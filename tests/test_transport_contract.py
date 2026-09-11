"""Regression tests for the structured SSH execution boundary."""

import importlib.util
import inspect
import json
import asyncio
import io
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "ssh_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("ssh_mcp_server", MODULE_PATH)
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


class _FakeChannel:
    def __init__(self):
        self.closed_for_write = False

    def shutdown_write(self):
        self.closed_for_write = True

    def recv_exit_status(self):
        return 0


class _FakeStdin:
    def __init__(self):
        self.channel = _FakeChannel()
        self.writes = []
        self.flushed = False

    def write(self, text):
        self.writes.append(text)

    def flush(self):
        self.flushed = True


class _FakeStream:
    def __init__(self, text, channel):
        self._text = text
        self.channel = channel

    def read(self):
        return self._text.encode()


class _FakeClient:
    def __init__(self):
        self.stdin = _FakeStdin()
        self.command = None
        self.closed = False

    def exec_command(self, command, timeout):
        self.command = command
        channel = self.stdin.channel
        return self.stdin, _FakeStream("ok", channel), _FakeStream("", channel)

    def open_sftp(self):
        return _FakeSFTP()

    def close(self):
        self.closed = True


class _FakeSFTP:
    def file(self, path, mode):
        return io.StringIO()

    def chmod(self, path, mode):
        return None

    def close(self):
        return None


class TransportContractTests(TestCase):
    def test_v2_tools_expose_native_fields_not_a_params_wrapper(self):
        execute_fields = inspect.signature(server.ssh_execute_v2).parameters
        script_fields = inspect.signature(server.ssh_script_v2).parameters

        self.assertIn("command", execute_fields)
        self.assertIn("stdin_text", execute_fields)
        self.assertNotIn("params", execute_fields)
        self.assertIn("script", script_fields)
        self.assertNotIn("params", script_fields)

    def test_mcp_schema_publishes_native_v2_fields(self):
        tools = asyncio.run(server.mcp.list_tools())
        schemas = {tool.name: tool.inputSchema["properties"] for tool in tools}

        self.assertEqual(set(schemas["ssh_execute"]), {"params"})
        self.assertIn("command", schemas["ssh_execute_v2"])
        self.assertIn("stdin_text", schemas["ssh_execute_v2"])
        self.assertNotIn("params", schemas["ssh_execute_v2"])
        self.assertIn("script", schemas["ssh_script_v2"])
        self.assertIn("stdin_text", schemas["ssh_script_v2"])

    def test_exec_sends_sudo_password_and_input_over_stdin(self):
        client = _FakeClient()
        with patch.object(server, "_ssh_connect", return_value=client):
            result = server._ssh_exec_command(
                host="example.test",
                port=22,
                username="operator",
                password="p'ass",
                command="printf %s \"quoted value\"",
                use_sudo=True,
                stdin_text="payload\\n",
            )

        self.assertTrue(result["success"])
        self.assertNotIn("echo", client.command)
        self.assertTrue(client.command.startswith("sudo -S -p '' /bin/sh -c "))
        self.assertEqual(client.stdin.writes, ["p'ass\npayload\\n"])
        self.assertTrue(client.stdin.flushed)
        self.assertTrue(client.stdin.channel.closed_for_write)
        self.assertTrue(client.closed)

    def test_blocked_command_has_a_stable_policy_id(self):
        self.assertEqual(
            server._check_blocked("rm -rf /"),
            {"policy_id": "filesystem-root-delete", "pattern": r"\brm\s+-rf\s+/\s*$"},
        )

    def test_script_sends_sudo_password_and_input_over_stdin(self):
        client = _FakeClient()
        with patch.object(server, "_ssh_connect", return_value=client):
            result = server._ssh_sftp_upload_and_run(
                host="example.test",
                port=22,
                username="operator",
                password="p'ass",
                script_content="printf %s script",
                use_sudo=True,
                stdin_text="payload\\n",
            )

        self.assertTrue(result["success"])
        self.assertTrue(client.command.startswith("sudo -S -p '' /bin/bash "))
        self.assertEqual(client.stdin.writes, ["p'ass\npayload\\n"])
        self.assertTrue(client.stdin.channel.closed_for_write)

    def test_legacy_invalid_json_is_a_structured_validation_failure(self):
        response = server.ssh_execute("not json")
        if inspect.isawaitable(response):
            import asyncio
            response = asyncio.run(response)
        body = json.loads(response)
        self.assertFalse(body["success"])
        self.assertEqual(body["error_type"], "validation")
