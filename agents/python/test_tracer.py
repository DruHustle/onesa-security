import unittest
from unittest.mock import Mock
from uuid import uuid4
from onesa_security_tracer import AgentTracer

URL = "https://security-api.onesa.eu/v1/collector/ai/agent-traces"
TEST_TOKEN = "-".join(("synthetic", "test", "collector", "token"))


class TelemetryTests(unittest.TestCase):
    def make(self, sender=None, **kw):
        return AgentTracer(endpoint=URL, collector_token=TEST_TOKEN,
                           sender=sender or Mock(), **kw)

    def test_validated_https_mtls_default(self):
        for u in ("http://security-api.onesa.eu/v1/collector/ai/agent-traces",
                  "https://security-api.onesa.eu/v1/collector/ai/agent-traces?token=x",
                  ("https://" + "user:" + "dummy" + "@security-api.onesa.eu/v1/collector/ai/agent-traces"),
                  "https://security-api.onesa.eu:8000/v1/collector/ai/agent-traces"):
            with self.assertRaises(ValueError):
                AgentTracer(endpoint=u, collector_token=TEST_TOKEN,
                            sender=Mock())
        with self.assertRaises(ValueError):
            AgentTracer(endpoint=URL, collector_token=TEST_TOKEN)

    def test_agent_span_metadata_only(self):
        out=[]
        t=self.make(sender=out.append)
        trace=str(uuid4())
        with t.span(agent_ref="agent-01", phase="planning", trace_id=trace) as ctx:
            self.assertEqual(ctx["trace_id"], trace)
            private_text = "never exported into telemetry"
        self.assertTrue(t.flush())
        self.assertEqual(len(out), 1)
        event=out[0]
        self.assertEqual(event["outcome"], "success")
        self.assertEqual(event["agent_ref"], "agent-01")
        self.assertEqual(event["trace_id"], trace)
        self.assertEqual(event["span_id"], ctx["span_id"])
        self.assertNotIn("content", event)
        self.assertNotIn(private_text, str(event))
        self.assertEqual(len(event), 8)
        t.close()

    def test_errors_are_reported_without_mutating_host_exceptions(self):
        out=[]
        t=self.make(sender=out.append)
        with self.assertRaises(PermissionError):
            with t.span(agent_ref="agent-02", phase="tool_review"):
                raise PermissionError("Denied by local host policy")
        self.assertTrue(t.flush())
        self.assertEqual(out[0]["outcome"], "denied")
        self.assertNotIn("Denied by local host policy", str(out[0]))
        t.close()

    def test_network_failures_dont_bubble_into_agent_path(self):
        t=self.make(sender=Mock(side_effect=OSError("Synthetic network failure")))
        with t.span(agent_ref="agent-03", phase="inference"):
            pass
        self.assertTrue(t.flush())
        self.assertEqual(t.dropped, 1)
        t.close()

    def test_validation_and_close(self):
        t=self.make()
        for kw in (
            dict(agent_ref="bad name", phase="policy", outcome="success"),
            dict(agent_ref="agent-01", phase="invalid", outcome="success"),
            dict(agent_ref="agent-01", phase="policy", outcome="not-ok"),
        ):
            with self.assertRaises(ValueError):
                t.record(trace_id=str(uuid4()), span_id=str(uuid4()), elapsed_us=1,
                         **kw)
        t.close()
        self.assertFalse(t.record(trace_id=str(uuid4()), span_id=str(uuid4()), agent_ref="agent-01",
                                  phase="policy", outcome="success", elapsed_us=1))


if __name__ == "__main__":
    unittest.main()
