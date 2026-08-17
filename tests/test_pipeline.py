import json
import re
import sys
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def fields(header):
    return {name: width for name, width, _ in header["fields"]}


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_pipeline.py BMV2_JSON P4INFO")

    json_path = Path(sys.argv[1])
    p4info_path = Path(sys.argv[2])
    data = json.loads(json_path.read_text())

    header_types = {item["name"]: item for item in data["header_types"]}
    require(
        fields(header_types["ethernet_t"])
        == {"dst_addr": 48, "src_addr": 48, "ether_type": 16},
        "unexpected Ethernet header layout",
    )
    require(
        fields(header_types["mpls_t"])
        == {
            "label": 20,
            "traffic_class": 3,
            "bottom_of_stack": 1,
            "ttl": 8,
        },
        "unexpected MPLS header layout",
    )
    require(
        fields(header_types["ipv4_t"])
        == {
            "version": 4,
            "ihl": 4,
            "diffserv": 8,
            "total_len": 16,
            "identification": 16,
            "flags": 3,
            "frag_offset": 13,
            "ttl": 8,
            "protocol": 8,
            "hdr_checksum": 16,
            "src_addr": 32,
            "dst_addr": 32,
        },
        "unexpected IPv4 header layout",
    )

    parser = data["parsers"][0]
    states = {item["name"]: item for item in parser["parse_states"]}
    transitions = {
        item["value"]: item["next_state"]
        for item in states["start"]["transitions"]
        if item["type"] == "hexstr"
    }
    require(transitions.get("0x0800") == "parse_ipv4", "IPv4 parser path missing")
    require(transitions.get("0x8847") == "parse_mpls", "MPLS parser path missing")
    require(
        [item["op"] for item in states["parse_mpls"]["parser_ops"]].count("verify")
        == 1,
        "MPLS BoS verification missing",
    )
    require(
        [item["op"] for item in states["parse_ipv4"]["parser_ops"]].count("verify")
        == 3,
        "IPv4 parser verification incomplete",
    )

    require(
        data["deparsers"][0]["order"] == ["ethernet", "mpls", "ipv4"],
        "unexpected deparser order",
    )
    checksums = data["checksums"]
    require(sum(item["verify"] for item in checksums) == 1, "IPv4 checksum verifier missing")
    require(sum(item["update"] for item in checksums) == 1, "IPv4 checksum update missing")

    tables = {
        table["name"]: table
        for pipeline in data["pipelines"]
        for table in pipeline["tables"]
        if table["name"].startswith("IngressImpl.")
    }
    expected_tables = {
        "IngressImpl.ipv4_lpm": {
            "match_type": "lpm",
            "name": "hdr.ipv4.dst_addr",
            "target": ["ipv4", "dst_addr"],
        },
        "IngressImpl.mpls_forward": {
            "match_type": "exact",
            "name": "hdr.mpls.label",
            "target": ["mpls", "label"],
        },
    }
    require(set(tables) == set(expected_tables), "unexpected control-plane tables")
    for name, expected_key in expected_tables.items():
        table = tables[name]
        require(table["max_size"] == 32, f"unexpected size for {name}")
        require(len(table["key"]) == 1, f"unexpected key count for {name}")
        key = table["key"][0]
        for attribute, expected in expected_key.items():
            require(key[attribute] == expected, f"unexpected {attribute} for {name}")
        require(table["default_entry"]["action_const"], f"mutable default for {name}")
        require(table["default_entry"]["action_entry_const"], f"mutable entry for {name}")

    actions = {
        item["name"]: item
        for item in data["actions"]
        if item["name"] != "IngressImpl.drop"
    }
    expected_params = {
        "IngressImpl.ipv4_forward": [("dst_mac", 48), ("src_mac", 48), ("port", 9)],
        "IngressImpl.push_mpls": [
            ("label", 20),
            ("dst_mac", 48),
            ("src_mac", 48),
            ("port", 9),
        ],
        "IngressImpl.swap_mpls": [
            ("label", 20),
            ("dst_mac", 48),
            ("src_mac", 48),
            ("port", 9),
        ],
        "IngressImpl.pop_mpls": [("dst_mac", 48), ("src_mac", 48), ("port", 9)],
    }
    require(set(actions) == set(expected_params), "unexpected forwarding actions")
    for name, params in expected_params.items():
        actual = [(item["name"], item["bitwidth"]) for item in actions[name]["runtime_data"]]
        require(actual == params, f"unexpected parameters for {name}")

    push_ops = {item["op"] for item in actions["IngressImpl.push_mpls"]["primitives"]}
    pop_ops = {item["op"] for item in actions["IngressImpl.pop_mpls"]["primitives"]}
    require("add_header" in push_ops, "PUSH does not add an MPLS header")
    require("remove_header" in pop_ops, "POP does not remove the MPLS header")

    p4info = p4info_path.read_text()
    aliases = set(re.findall(r'^\s*alias: "([^"]+)"$', p4info, re.MULTILINE))
    require(
        aliases
        == {
            "ipv4_lpm",
            "mpls_forward",
            "drop",
            "ipv4_forward",
            "push_mpls",
            "swap_mpls",
            "pop_mpls",
        },
        "unexpected P4Info aliases",
    )
    require(p4info.count("const_default_action_id:") == 2, "P4Info defaults are not constant")

    print("pipeline structure: PASS")


if __name__ == "__main__":
    main()
