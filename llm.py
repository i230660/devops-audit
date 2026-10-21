
import os
import re
import time

from google import genai
from google.genai import errors, types


class LLMError(Exception):
    pass


def _schema(s):
    """JSON-schema (as used by our tool specs) -> Gemini Schema dict."""
    if not isinstance(s, dict):
        return s
    out = {}
    t = s.get("type")
    if isinstance(t, list):
        non_null = [x for x in t if x != "null"]
        out["type"] = non_null[0] if non_null else "string"
        if "null" in t:
            out["nullable"] = True
    elif t:
        out["type"] = t
    for k, v in s.items():
        if k == "properties":
            out[k] = {n: _schema(p) for n, p in v.items()}
        elif k == "items":
            out[k] = _schema(v)
        elif k in ("description", "enum", "required"):
            out[k] = v
    return out


def _to_gemini_tools(specs):
    decls = [types.FunctionDeclaration(name=s["name"], description=s["description"],
                                       parameters=_schema(s["input_schema"])) for s in specs]
    return [types.Tool(function_declarations=decls)]


def _to_contents(messages):
    contents, id2name = [], {}
    for m in messages:
        role = "model" if m["role"] == "assistant" else "user"
        if isinstance(m["content"], str):
            parts = [types.Part(text=m["content"])]
        else:
            parts = []
            for b in m["content"]:
                t = b["type"]
                if t == "text":
                    if b["text"].strip():
                        parts.append(b.get("_part") or types.Part(text=b["text"]))
                elif t == "tool_use":
                    id2name[b["id"]] = b["name"]
                    # reuse the raw part: Gemini 3 needs its thought signature echoed back
                    parts.append(b.get("_part") or types.Part(
                        function_call=types.FunctionCall(name=b["name"], args=b["input"])))
                elif t == "tool_result":
                    parts.append(types.Part(function_response=types.FunctionResponse(
                        name=id2name.get(b["tool_use_id"], "unknown"),
                        response={"result": b["content"]})))
        if parts:
            contents.append(types.Content(role=role, parts=parts))
    return contents


def _retry_delay(err) -> float:
    text = str(err)
    m = re.search(r"retry in ([\d.]+)s", text) or re.search(r"retryDelay'?\"?: ?'?\"?([\d.]+)s", text)
    return float(m.group(1)) + 1 if m else 0.0


class GeminiLLM:
    def __init__(self, model=None, api_key=None, client=None, min_interval=None):
        key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if client is None and not key:
            raise LLMError("GEMINI_API_KEY is not set (get a free key at https://aistudio.google.com/apikey "
                           "and put it in .env)")
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
        self.client = client or genai.Client(
            api_key=key, http_options=types.HttpOptions(timeout=120_000))
        self.min_interval = float(os.getenv("GEMINI_MIN_INTERVAL", "5")) if min_interval is None else min_interval
        self._last = 0.0
        self._n = 0

    def _throttle(self):
        wait = self.min_interval - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def create(self, system, messages, tools):
        """Returns (blocks, stop_reason); blocks are dicts (text / tool_use)."""
        config = types.GenerateContentConfig(
            system_instruction=system, tools=_to_gemini_tools(tools), max_output_tokens=8192,
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True))
        contents = _to_contents(messages)
        resp = None
        for attempt in range(6):
            self._throttle()
            try:
                resp = self.client.models.generate_content(
                    model=self.model, contents=contents, config=config)
                break
            except errors.APIError as e:
                code = getattr(e, "code", None)
                if code == 429 and "PerDay" in str(e):
                    raise LLMError("Gemini free-tier DAILY quota exhausted for this model; try again "
                                   "tomorrow or set GEMINI_MODEL to another free model") from e
                if code in (429, 500, 503, 504) and attempt < 5:
                    time.sleep(min(max(_retry_delay(e), 5 * 2 ** attempt), 90))
                    continue
                if code == 404:
                    raise LLMError(f"Gemini model '{self.model}' not found; run `python llm.py` to list "
                                   "available models and set GEMINI_MODEL") from e
                raise LLMError(f"Gemini API error {code}: {getattr(e, 'message', e)}") from e
            except Exception as e:  # network errors, timeouts
                if attempt < 5:
                    time.sleep(5 * 2 ** attempt)
                    continue
                raise LLMError(f"Gemini request failed: {type(e).__name__}: {e}") from e
        blocks = []
        cand = resp.candidates[0] if resp and resp.candidates else None
        if cand and cand.content and cand.content.parts:
            for part in cand.content.parts:
                if part.function_call:
                    self._n += 1
                    blocks.append({"type": "tool_use", "id": f"call_{self._n}", "_part": part,
                                   "name": part.function_call.name,
                                   "input": dict(part.function_call.args or {})})
                elif part.text and not part.thought:
                    blocks.append({"type": "text", "text": part.text, "_part": part})
        if not blocks:
            blocks.append({"type": "text", "text": "(no output)"})
        return blocks, str(cand.finish_reason) if cand else "none"


if __name__ == "__main__":  # helper: list models available to your key
    from dotenv import load_dotenv
    load_dotenv()
    c = genai.Client(api_key=os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
    for m in c.models.list():
        if "generateContent" in (m.supported_actions or []):
            print(m.name.removeprefix("models/"))