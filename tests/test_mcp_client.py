import io
import json
import unittest
from unittest import mock

from memwall.mcp_client import MiniClient, successful_tool_result


class MiniClientTests(unittest.TestCase):
    def test_supported_tool_success_and_malformed_content(self):
        blocks = [{"type": "text", "text": "ok"}, {"type": "image", "data": "", "mimeType": "image/png"},
                  {"type": "audio", "data": "", "mimeType": "audio/wav"},
                  {"type": "resource_link", "uri": "file:///synthetic", "name": "synthetic"},
                  {"type": "resource", "resource": {"uri": "file:///synthetic", "text": "ok"}}]
        self.assertTrue(successful_tool_result({"content": blocks, "isError": False}))
        for block in (None, {}, {"type": "text", "text": 1}, {"type": "image", "data": ""},
                      {"type": "resource", "resource": {}}, {"type": "unknown"},
                      {"type": "text", "text": "ok", "annotations": []}):
            with self.subTest(block=block):
                self.assertFalse(successful_tool_result({"content": [block]}))
        for result in ({"content": [], "structuredContent": None}, {"content": [], "isError": 0},
                       {"content": [], "_meta": []}, {"content": [], "isError": True}):
            self.assertFalse(successful_tool_result(result))

    def test_invalid_json_and_response_envelopes_are_not_success(self):
        for raw in (b'{"id":1,"result":{"content":[]}}\n',
                    b'{"jsonrpc":"2.0","id":1,"id":1,"result":{}}\n',
                    b'{"jsonrpc":"2.0","id":1,"method":"progress","result":{}}\n',
                    b'{"jsonrpc":"2.0","id":1,"result":{},"error":{}}\n',
                    b'{"jsonrpc":"2.0","id":1,"result":NaN}\n', b'not-json\n'):
            with self.subTest(raw=raw), mock.patch("memwall.mcp_client.subprocess.Popen") as popen:
                popen.return_value.stdin = io.BytesIO()
                popen.return_value.stdout = io.BytesIO(raw)
                client = MiniClient(["unused"])
                with self.assertRaises(RuntimeError):
                    client.call_tool("add_observations", {})

    def test_partial_pipe_writes_preserve_entire_request(self):
        captured = bytearray()

        def partial(data):
            count = min(7, len(data))
            captured.extend(data[:count])
            return count

        with mock.patch("memwall.mcp_client.subprocess.Popen") as popen:
            popen.return_value.stdin.write.side_effect = partial
            client = MiniClient(["unused"])
            request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "add_observations", "arguments": {"text": "café"}}}
            client._send(request)
        self.assertEqual(json.loads(captured), request)

    def test_boolean_response_id_cannot_match_integer_request(self):
        with mock.patch("memwall.mcp_client.subprocess.Popen") as popen:
            popen.return_value.stdin = io.BytesIO()
            popen.return_value.stdout = io.BytesIO(b'{"jsonrpc":"2.0","id":true,"result":{"content":[]}}\n')
            client = MiniClient(["unused"])
            with self.assertRaises(RuntimeError):
                client.call_tool("add_observations", {})

    def test_invalid_handshake_never_sends_tool_call(self):
        with mock.patch("memwall.mcp_client.subprocess.Popen") as popen:
            popen.return_value.stdin = io.BytesIO()
            popen.return_value.stdout = io.BytesIO(b'{"jsonrpc":"2.0","id":1,"result":{}}\n')
            client = MiniClient(["unused"])
            with self.assertRaisesRegex(RuntimeError, "initialize"):
                client.initialize()
            sent = [json.loads(raw) for raw in popen.return_value.stdin.getvalue().splitlines()]
            self.assertEqual([msg["method"] for msg in sent], ["initialize"])
