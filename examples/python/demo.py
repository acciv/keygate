import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from keygate import KeyGateClient

client = KeyGateClient(client_id="demo-python")

print("health:", client.health())
result = client.resolve("telegram", scope="send", ttl=60)
print("lease:", result["lease"])
print("masked:", result["masked_key"])
print("providers:", client.providers()["providers"])
print("audit events:", len(client.audit()["events"]))
