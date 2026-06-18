from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


KIND_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_]+$")


class OpenIPAHoundValidationError(RuntimeError):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise OpenIPAHoundValidationError(f"Could not read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise OpenIPAHoundValidationError(f"{path} is not valid JSON: {exc}") from exc


def load_extension_schema(path: Path) -> dict[str, Any]:
    schema = load_json(path)
    if not isinstance(schema, dict):
        raise OpenIPAHoundValidationError(f"Extension schema {path} must be a JSON object.")
    validate_extension_schema(schema)
    return schema


def validate_extension_schema(schema: dict[str, Any]) -> None:
    required_top_keys = ("schema", "node_kinds", "relationship_kinds", "environments", "relationship_findings")
    missing = [key for key in required_top_keys if key not in schema]
    if missing:
        raise OpenIPAHoundValidationError(f"Extension schema is missing required keys: {', '.join(missing)}")

    schema_data = require_mapping(schema["schema"], "schema")
    for key in ("name", "display_name", "version", "namespace"):
        if not schema_data.get(key):
            raise OpenIPAHoundValidationError(f"Extension schema metadata is missing required field: schema.{key}")

    namespace = str(schema_data["namespace"])
    if namespace.lower() == "tag":
        raise OpenIPAHoundValidationError("Extension schema namespace 'tag' is reserved by BloodHound.")

    node_kinds = require_list(schema["node_kinds"], "node_kinds")
    relationship_kinds = require_list(schema["relationship_kinds"], "relationship_kinds")
    environments = require_list(schema["environments"], "environments")
    relationship_findings = require_list(schema["relationship_findings"], "relationship_findings")

    node_names = validate_named_entries(node_kinds, "node_kinds", namespace)
    relationship_names = validate_named_entries(relationship_kinds, "relationship_kinds", namespace)
    finding_names = validate_named_entries(relationship_findings, "relationship_findings", namespace)
    duplicate_names = duplicate_values([*node_names, *relationship_names, *finding_names])
    if duplicate_names:
        raise OpenIPAHoundValidationError(
            f"Extension schema has duplicate kind/finding names: {', '.join(duplicate_names)}"
        )

    node_name_set = set(node_names)
    relationship_name_set = set(relationship_names)
    for index, entry in enumerate(environments):
        environment = require_mapping(entry, f"environments[{index}]")
        environment_kind = environment.get("environment_kind")
        if environment_kind not in node_name_set:
            raise OpenIPAHoundValidationError(
                f"environments[{index}].environment_kind must match a node kind defined in node_kinds."
            )
        if not environment.get("source_kind"):
            raise OpenIPAHoundValidationError(f"environments[{index}].source_kind is required.")
        principal_kinds = require_list(environment.get("principal_kinds"), f"environments[{index}].principal_kinds")
        unknown_principals = [kind for kind in principal_kinds if kind not in node_name_set]
        if unknown_principals:
            raise OpenIPAHoundValidationError(
                f"environments[{index}].principal_kinds contains unknown node kinds: "
                f"{', '.join(unknown_principals)}"
            )

    for index, entry in enumerate(relationship_findings):
        finding = require_mapping(entry, f"relationship_findings[{index}]")
        if finding.get("environment_kind") not in node_name_set:
            raise OpenIPAHoundValidationError(
                f"relationship_findings[{index}].environment_kind must match a node kind defined in node_kinds."
            )
        if finding.get("relationship_kind") not in relationship_name_set:
            raise OpenIPAHoundValidationError(
                f"relationship_findings[{index}].relationship_kind must match a relationship kind."
            )


def validate_payload_file(path: Path, schema: dict[str, Any]) -> tuple[int, int]:
    payload = load_json(path)
    return validate_payload(payload, schema, label=str(path))


def validate_payload(payload: Any, schema: dict[str, Any], label: str = "payload") -> tuple[int, int]:
    if not isinstance(payload, dict):
        raise OpenIPAHoundValidationError(f"{label} must be a JSON object.")

    metadata = require_mapping(payload.get("metadata"), f"{label}.metadata")
    source_kind = metadata.get("source_kind")
    if source_kind != "OpenIPAHound":
        raise OpenIPAHoundValidationError(f"{label}.metadata.source_kind must be OpenIPAHound.")

    graph = require_mapping(payload.get("graph"), f"{label}.graph")
    nodes = require_list(graph.get("nodes"), f"{label}.graph.nodes")
    edges = require_list(graph.get("edges"), f"{label}.graph.edges")
    node_kind_names = {entry["name"] for entry in schema["node_kinds"]}
    relationship_kind_names = {entry["name"] for entry in schema["relationship_kinds"]}

    for index, raw_node in enumerate(nodes):
        node = require_mapping(raw_node, f"{label}.graph.nodes[{index}]")
        if not isinstance(node.get("id"), str) or not node["id"]:
            raise OpenIPAHoundValidationError(f"{label}.graph.nodes[{index}].id must be a non-empty string.")
        kinds = require_list(node.get("kinds"), f"{label}.graph.nodes[{index}].kinds")
        if not kinds:
            raise OpenIPAHoundValidationError(f"{label}.graph.nodes[{index}].kinds must not be empty.")
        unknown_kinds = [kind for kind in kinds if kind not in node_kind_names]
        if unknown_kinds:
            raise OpenIPAHoundValidationError(
                f"{label}.graph.nodes[{index}].kinds contains unknown kinds: {', '.join(unknown_kinds)}"
            )
        if "properties" in node:
            require_mapping(node["properties"], f"{label}.graph.nodes[{index}].properties")

    for index, raw_edge in enumerate(edges):
        edge = require_mapping(raw_edge, f"{label}.graph.edges[{index}]")
        kind = edge.get("kind")
        if kind not in relationship_kind_names:
            raise OpenIPAHoundValidationError(f"{label}.graph.edges[{index}].kind is not in schema: {kind}")
        validate_match(edge.get("start"), f"{label}.graph.edges[{index}].start")
        validate_match(edge.get("end"), f"{label}.graph.edges[{index}].end")
        if "properties" in edge:
            require_mapping(edge["properties"], f"{label}.graph.edges[{index}].properties")

    return len(nodes), len(edges)


def payload_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.exists():
        raise OpenIPAHoundValidationError(f"Payload path does not exist: {path}")
    if not path.is_dir():
        raise OpenIPAHoundValidationError(f"Payload path must be a JSON file or directory: {path}")
    return sorted(candidate for candidate in path.glob("*.json") if candidate.name != "manifest.json")


def validate_match(value: Any, label: str) -> None:
    match = require_mapping(value, label)
    if match.get("match_by") != "id":
        raise OpenIPAHoundValidationError(f"{label}.match_by must be id.")
    if not isinstance(match.get("value"), str) or not match["value"]:
        raise OpenIPAHoundValidationError(f"{label}.value must be a non-empty string.")


def validate_named_entries(entries: list[Any], label: str, namespace: str) -> list[str]:
    names: list[str] = []
    namespace_prefix = f"{namespace}_"
    for index, raw_entry in enumerate(entries):
        entry = require_mapping(raw_entry, f"{label}[{index}]")
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise OpenIPAHoundValidationError(f"{label}[{index}].name is required.")
        if name.lower().startswith("tag_"):
            raise OpenIPAHoundValidationError(f"{label}[{index}].name uses reserved tag_ prefix: {name}")
        if not KIND_NAME_PATTERN.fullmatch(name):
            raise OpenIPAHoundValidationError(f"{label}[{index}].name contains invalid characters: {name}")
        if not name.startswith(namespace_prefix) or name == namespace_prefix:
            raise OpenIPAHoundValidationError(f"{label}[{index}].name must be prefixed with {namespace_prefix}: {name}")
        names.append(name)
    return names


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OpenIPAHoundValidationError(f"{label} must be an object.")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise OpenIPAHoundValidationError(f"{label} must be an array.")
    return value


def duplicate_values(values: list[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: list[str] = []
    for value in values:
        if value in seen and value not in duplicates:
            duplicates.append(value)
        seen.add(value)
    return duplicates
