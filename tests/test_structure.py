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

    def test_flowlet_state(self):
        model = json.loads((ROOT / "build/flowlet.json").read_text())
        expected = {"flow_valid": 1, "flow_fingerprint": 32, "flow_last_seen": 48,
                    "flowlet_id": 32, "flow_path": 1}
        registers = {register["name"]: (register["size"], register["bitwidth"])
                     for register in model["register_arrays"]}
        self.assertEqual(registers, {f"IngressPipe.{name}": (4096, width)
                                     for name, width in expected.items()})
        state_actions = [action for action in model["actions"] if any(
            primitive["op"] in ("register_read", "register_write")
            for primitive in action["primitives"])]
        self.assertEqual([action["name"] for action in state_actions], ["IngressPipe.update_flowlet"])
        primitives = state_actions[0]["primitives"]
        for operation in ("register_read", "register_write"):
            arrays = {param["value"] for primitive in primitives if primitive["op"] == operation
                      for param in primitive["parameters"] if param["type"] == "register_array"}
            self.assertEqual(arrays, set(registers))
        self.assertIn("ingress_global_timestamp", json.dumps(primitives))
        hashes = [calc for calc in model["calculations"] if calc["algo"] == "crc32"]
        self.assertEqual(len(hashes), 3)
        self.assertEqual(len({json.dumps(calc["input"], sort_keys=True) for calc in hashes}), 3)
        self.assertEqual(sum(p["op"] == "modify_field_with_hash_based_offset" for p in primitives), 3)
        tables = {table["name"] for pipe in model["pipelines"] for table in pipe["tables"]}
        self.assertTrue({"IngressPipe.flowlet_config", "IngressPipe.flowlet_path"} <= tables)
