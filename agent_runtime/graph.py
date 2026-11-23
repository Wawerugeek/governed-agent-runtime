from agent_runtime.pep_client import PEPClient

# v0.1: static capability manifest. v0.2 swaps this for a JWT-verified identity.
AGENT = {"id": "agent-demo-1", "capabilities": ["fs.read"]}  # NOT email.send

def run_scripted(pep: PEPClient) -> list[tuple]:
    out = []
    d = pep.authorize(AGENT, "read_file", {"path": "/tmp/hello.txt"})
    out.append(("read_file", d.allowed, d.reason, d.receipt["hash"]))
    if d.allowed:
        out.append(("read_file_result", True, open("/tmp/hello.txt").read().strip(), None))

    d = pep.authorize(AGENT, "send_email", {"to": "ceo@example.com", "body": "..."})
    out.append(("send_email", d.allowed, d.reason, d.receipt["hash"]))

    d = pep.authorize(AGENT, "read_file", {"path": "/tmp/hello.txt"})
    out.append(("read_file", d.allowed, d.reason, d.receipt["hash"]))
    return out
