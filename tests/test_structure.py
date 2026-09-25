import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class StructureTests(unittest.TestCase):
    def test_pipeline(self):
        model = json.loads((ROOT / "build/flowlet.json").read_text())
        tables = {table["name"] for pipeline in model["pipelines"] for table in pipeline["tables"]}
        self.assertIn("IngressPipe.ipv4_route", tables)
        actions = {action["name"]: action for action in model["actions"]}
        self.assertIn("IngressPipe.drop", actions)
        forwarding = actions["IngressPipe.set_nhop"]
        self.assertTrue(any("ttl" in str(p) for p in forwarding["primitives"]))
        self.assertTrue(model["checksums"])
        self.assertTrue(any(c.get("verify") for c in model["checksums"]))
        self.assertTrue(any(c.get("update") for c in model["checksums"]))
