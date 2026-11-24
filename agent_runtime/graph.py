from control_plane.identity import tokens
from agent_runtime.pep_client import PEPClient

def run_scripted(pep: PEPClient, token: str) -> list[tuple]:
    """Exercises the v0.1 demo paths through the v0.2 token layer."""
    out = []

    d = pep.authorize(token, "read_file", {"path": "/tmp/hello.txt"})
    out.append(("read_file", d.allowed, d.reason, d.receipt["hash"]))
    if d.allowed:
        out.append(("read_file_result", True, open("/tmp/hello.txt").read().strip(), None))

    d = pep.authorize(token, "send_email", {"to": "ceo@example.com", "body": "..."})
    out.append(("send_email", d.allowed, d.reason, d.receipt["hash"]))

    return out


def mint_demo_token() -> str:
    """Helper for the demo — in v0.3 the agent fetches this over HTTP."""
    return tokens.mint("agent-demo-1", ["fs.read"])