from google.genai import types

from audit_agent import ALL_TOOL_SPECS
from llm import GeminiLLM, _schema, _to_contents, _to_gemini_tools


class FakeModels:
    def __init__(self, parts):
        self.parts, self.calls = parts, []

    def generate_content(self, model, contents, config):
        self.calls.append(contents)
        return types.GenerateContentResponse(candidates=[types.Candidate(
            content=types.Content(role="model", parts=self.parts))])


class FakeClient:
    def __init__(self, parts):
        self.models = FakeModels(parts)


def test_schema_converts_nullable_types():
    s = _schema({"type": "object", "properties": {"file": {"type": ["string", "null"]},
                                                   "line": {"type": ["integer", "null"]}}})
    assert s["properties"]["file"] == {"type": "string", "nullable": True}


def test_all_tool_specs_build_valid_gemini_tools():
    tool = _to_gemini_tools(ALL_TOOL_SPECS)[0]
    names = [d.name for d in tool.function_declarations]
    assert names == ["list_files", "read_file", "search_code", "git_log", "report_violation", "finish_audit"]


def test_messages_convert_with_function_response_names():
    msgs = [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": [{"type": "text", "text": "hm"},
                                          {"type": "tool_use", "id": "call_1", "name": "list_files", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call_1", "content": "a.py"}]},
    ]
    c = _to_contents(msgs)
    assert [x.role for x in c] == ["user", "model", "user"]
    fr = c[2].parts[0].function_response
    assert fr.name == "list_files" and fr.response == {"result": "a.py"}


def test_create_parses_function_call_and_text():
    parts = [types.Part(text="plan"),
             types.Part(function_call=types.FunctionCall(name="read_file", args={"path": "x.py"}))]
    llm = GeminiLLM(client=FakeClient(parts), min_interval=0)
    blocks, _ = llm.create("sys", [{"role": "user", "content": "hi"}], ALL_TOOL_SPECS)
    assert blocks[0]["type"] == "text"
    assert blocks[1]["type"] == "tool_use" and blocks[1]["input"] == {"path": "x.py"}
    # round-trip: the raw part is reused when the block is sent back
    again = _to_contents([{"role": "assistant", "content": blocks}])
    assert again[0].parts[1].function_call.name == "read_file"


def test_empty_response_becomes_placeholder():
    llm = GeminiLLM(client=FakeClient([]), min_interval=0)
    blocks, _ = llm.create("s", [{"role": "user", "content": "hi"}], ALL_TOOL_SPECS)
    assert blocks == [{"type": "text", "text": "(no output)"}]
