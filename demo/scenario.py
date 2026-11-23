from control_plane.policy.engine import PolicyEngine
from control_plane.audit.log import AuditLog
from agent_runtime.pep_client import PEPClient
from agent_runtime.graph import run_scripted

def main() -> None:
    open("/tmp/hello.txt", "w").write("hello from governed agent\n")
    pep = PEPClient(PolicyEngine(), AuditLog("audit.jsonl"))
    for r in run_scripted(pep):
        print(r)
    print(f"\naudit chain valid: {pep.audit.verify('audit.jsonl')}")

if __name__ == "__main__":
    main()
