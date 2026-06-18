from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ldap3.core.exceptions import LDAPException

from openipahound.ldap import (
    FreeIPACollector,
    build_add_member_edges,
    build_add_rbcd_edges,
    build_allowed_to_delegate_edges,
    build_can_hbac_service_edges,
    build_can_ssh_edges,
    build_can_sudo_edges,
    build_dcsync_edges,
    build_enroll_edges,
    build_force_change_password_edges,
    build_hostgroup_memberof_edges,
    build_memberof_edges,
    build_owns_edges,
    build_permission_memberof_edges,
    build_privilege_memberof_edges,
    build_read_kerberos_key_edges,
    build_role_memberof_edges,
    build_trusted_by_edges,
    domain_to_base_dn,
)
from openipahound.opengraph import (
    CANHBACSERVICE_KIND,
    CANSSH_KIND,
    CANSUDO_KIND,
    build_allowed_to_delegate_payload,
    build_certificate_payload,
    build_computer_payload,
    build_dcsync_payload,
    build_hostgroup_payload,
    build_membership_payload,
    build_payload,
    build_service_payload,
    build_trust_payload,
    build_user_payload,
)
from openipahound.validation import (
    OpenIPAHoundValidationError,
    load_extension_schema,
    payload_files,
    validate_payload,
    validate_payload_file,
)


DEFAULT_EXTENSION_SCHEMA = Path(__file__).resolve().parent / "schemas" / "openipahound-extension.json"
PASSWORD_PROMPT = "__OPENIPAHOUND_PROMPT_PASSWORD__"


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    file_name: str
    summary: str
    maturity: str
    collect: Callable[["CollectionContext"], dict[str, Any]]
    default: bool = False


class CollectionContext:
    def __init__(self, collector: FreeIPACollector) -> None:
        self.collector = collector
        self.cache: dict[str, Any] = {}

    def environment(self):
        return self._get("environment", self.collector.collect_environment)

    def users(self):
        return self._get("users", self.collector.collect_users)

    def groups(self):
        return self._get("groups", self.collector.collect_groups)

    def roles(self):
        return self._get("roles", self.collector.collect_roles)

    def privileges(self):
        return self._get("privileges", self.collector.collect_privileges)

    def permissions(self):
        return self._get("permissions", self.collector.collect_permissions)

    def cas(self):
        return self._get("cas", self.collector.collect_cas)

    def certificate_templates(self):
        return self._get("certificate_templates", self.collector.collect_certificate_templates)

    def ca_acls(self):
        return self._get("ca_acls", self.collector.collect_ca_acls)

    def selinux_user_maps(self):
        return self._get("selinux_user_maps", self.collector.collect_selinux_user_maps)

    def trusted_domains(self):
        return self._get("trusted_domains", self.collector.collect_trusted_domains)

    def computers(self):
        return self._get("computers", self.collector.collect_computers)

    def services(self):
        return self._get("services", self.collector.collect_services)

    def delegation_rules(self):
        return self._get("delegation_rules", self.collector.collect_service_delegation_rules)

    def delegation_targets(self):
        return self._get("delegation_targets", self.collector.collect_service_delegation_targets)

    def hostgroups(self):
        return self._get("hostgroups", self.collector.collect_hostgroups)

    def hbac_rules(self):
        return self._get("hbac_rules", self.collector.collect_hbac_rules)

    def hbac_services(self):
        return self._get("hbac_services", self.collector.collect_hbac_services)

    def sudo_rules(self):
        return self._get("sudo_rules", self.collector.collect_sudo_rules)

    def sudo_commands(self):
        return self._get("sudo_commands", self.collector.collect_sudo_commands)

    def _get(self, key: str, loader: Callable[[], Any]) -> Any:
        if key not in self.cache:
            self.cache[key] = loader()
        return self.cache[key]


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "collect":
        return collect_command(args, parser)
    if args.command == "validate":
        return validate_command(args)
    if args.command == "schema" and args.schema_command == "export":
        return schema_export_command(args)

    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openipahound",
        description="Collect FreeIPA objects and emit BloodHound OpenGraph JSON.",
    )
    subparsers = parser.add_subparsers(dest="command")

    collect = subparsers.add_parser("collect", help="Collect FreeIPA data into OpenGraph payload files.")
    collect.add_argument("server_arg", nargs="?", metavar="server", help="FreeIPA LDAP server hostname or IP address.")
    add_ldap_options(collect)
    collect.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        metavar="DIR",
        help="Directory for generated OpenGraph JSON payload files.",
    )
    collect.add_argument(
        "-c",
        "--only",
        dest="only",
        metavar="MODULES",
        help="Comma-separated modules to collect instead of the default module set.",
    )
    collect.add_argument("--exclude", metavar="MODULES", help="Comma-separated modules to remove from the selected set.")
    collect.add_argument("--list-modules", action="store_true", help="Print available collection modules and exit.")
    collect.add_argument("--compact", action="store_true", help="Write compact JSON payload files.")

    validate = subparsers.add_parser("validate", help="Validate OpenGraph payload files without BloodHound access.")
    validate.add_argument("path", type=Path, help="Payload JSON file or output directory to validate.")
    validate.add_argument(
        "--schema-file",
        type=Path,
        default=DEFAULT_EXTENSION_SCHEMA,
        help="OpenIPAHound extension schema. Defaults to the packaged schema.",
    )

    schema = subparsers.add_parser("schema", help="Work with the packaged OpenGraph extension schema.")
    schema_subparsers = schema.add_subparsers(dest="schema_command")
    export = schema_subparsers.add_parser("export", help="Write the packaged OpenGraph extension schema to stdout.")
    export.add_argument(
        "--schema-file",
        type=Path,
        default=DEFAULT_EXTENSION_SCHEMA,
        help="Schema file to export. Defaults to the packaged schema.",
    )
    return parser


def add_ldap_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--env-file", type=Path, metavar="PATH", help="Optional shell-style env file to load.")
    parser.add_argument("--server", metavar="HOST", help="FreeIPA LDAP server hostname or IP address. Usually provided as the collect target.")
    parser.add_argument("-d", "--domain", metavar="DOMAIN", help="FreeIPA domain, used to derive base DN.")
    parser.add_argument("--base-dn", metavar="DN", help="LDAP base DN. Defaults from --domain or IPA_DOMAIN.")
    parser.add_argument(
        "--auth",
        choices=("password", "kerberos"),
        help="LDAP auth mode. Defaults to password unless IPA_AUTH=kerberos or --kerberos is used.",
    )
    parser.add_argument(
        "--credential-profile",
        choices=("admin", "collector"),
        help="Env-file credential profile. Defaults to IPA_CREDENTIAL_PROFILE or collector.",
    )
    parser.add_argument("-u", "--user", "--username", dest="user", metavar="USER", help="LDAP username or bind DN.")
    parser.add_argument(
        "-p",
        "--password",
        nargs="?",
        const=PASSWORD_PROMPT,
        metavar="PASSWORD",
        help="LDAP password. Omit the value to prompt interactively.",
    )
    parser.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        help="Use the current Kerberos ticket cache for LDAP SASL/GSSAPI auth instead of username/password.",
    )
    parser.add_argument("--no-ssl", action="store_true", help="Use ldap:// instead of ldaps://.")


def collect_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.list_modules:
        print_module_list()
        return 0
    if args.output_dir is None:
        parser.error("collect requires -o/--output-dir unless --list-modules is used")

    try:
        modules = selected_modules(args.only, args.exclude)
        settings = collect_settings(args)
        schema = load_extension_schema(DEFAULT_EXTENSION_SCHEMA)
    except (OpenIPAHoundValidationError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 2

    args.output_dir.mkdir(parents=True, exist_ok=True)
    try:
        with FreeIPACollector(**settings) as collector:
            context = CollectionContext(collector)
            for module_name in modules:
                spec = MODULES[module_name]
                payload = spec.collect(context)
                validate_payload(payload, schema, label=spec.file_name)
                write_json(args.output_dir / spec.file_name, payload, compact=args.compact)
    except (LDAPException, OSError, ValueError) as exc:
        print(f"OpenIPAHound collection failed: {exc}", file=sys.stderr)
        return 1

    print(f"Wrote {len(modules)} OpenGraph payload file(s) to {args.output_dir}")
    print("Modules: " + ", ".join(modules))
    return 0


def validate_command(args: argparse.Namespace) -> int:
    try:
        schema = load_extension_schema(args.schema_file)
        files = payload_files(args.path)
        if not files:
            raise OpenIPAHoundValidationError(f"No JSON payload files found in {args.path}.")
        node_total = 0
        edge_total = 0
        for path in files:
            nodes, edges = validate_payload_file(path, schema)
            node_total += nodes
            edge_total += edges
    except OpenIPAHoundValidationError as exc:
        print(f"Validation failed: {exc}", file=sys.stderr)
        return 1

    print(f"Validated {len(files)} payload file(s): {node_total} node(s), {edge_total} edge(s).")
    return 0


def schema_export_command(args: argparse.Namespace) -> int:
    try:
        schema = load_extension_schema(args.schema_file)
    except OpenIPAHoundValidationError as exc:
        print(f"Schema export failed: {exc}", file=sys.stderr)
        return 1

    json.dump(schema, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def collect_settings(args: argparse.Namespace) -> dict[str, Any]:
    if args.env_file:
        load_env_file(args.env_file)

    server = args.server_arg or args.server or os.getenv("IPA_SERVER")
    domain = args.domain or os.getenv("IPA_DOMAIN")
    base_dn = args.base_dn or os.getenv("IPA_BASE_DN")
    auth_mode = args.auth or os.getenv("IPA_AUTH", "").lower() or "password"
    if args.kerberos:
        if auth_mode == "password" and args.auth == "password":
            raise ValueError("--kerberos conflicts with --auth password")
        auth_mode = "kerberos"
    if auth_mode not in {"password", "kerberos"}:
        raise ValueError("IPA_AUTH must be password or kerberos")
    use_kerberos = auth_mode == "kerberos"
    credential_profile = args.credential_profile or os.getenv("IPA_CREDENTIAL_PROFILE") or "collector"
    if credential_profile == "collector":
        env_user_key = "IPA_COLLECTOR_USER"
        env_password_key = "IPA_COLLECTOR_PASSWORD"
    else:
        env_user_key = "IPA_ADMIN_USER"
        env_password_key = "IPA_ADMIN_PASSWORD"
    user = None if use_kerberos else args.user or os.getenv(env_user_key)
    password = None
    if not use_kerberos:
        if args.password == PASSWORD_PROMPT:
            password = getpass.getpass("LDAP password: ")
        else:
            password = args.password or os.getenv(env_password_key)

    if not base_dn and domain:
        base_dn = domain_to_base_dn(domain)

    required = {"server": server, "base_dn": base_dn}
    if not use_kerberos:
        required.update({"user": user, "password": password})
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ValueError(f"Missing required LDAP settings: {', '.join(missing)}")
    if not use_kerberos and args.no_ssl:
        print("Warning: password auth over ldap:// is not encrypted by TLS.", file=sys.stderr)

    return {
        "server": server,
        "base_dn": base_dn,
        "user": user,
        "password": password,
        "use_ssl": not args.no_ssl,
        "use_kerberos": use_kerberos,
    }


def selected_modules(only: str | None, exclude: str | None) -> list[str]:
    selected = expand_modules(only) if only else [name for name, spec in MODULES.items() if spec.default]
    excluded = set(expand_modules(exclude)) if exclude else set()
    return [name for name in MODULES if name in selected and name not in excluded]


def expand_modules(raw: str | None) -> list[str]:
    if not raw:
        return []
    modules: list[str] = []
    for token in raw.split(","):
        name = normalize_module_name(token)
        if not name:
            continue
        if name in MODULE_ALIASES:
            modules.extend(MODULE_ALIASES[name])
        elif name in MODULES:
            modules.append(name)
        else:
            valid = ", ".join([*MODULE_ALIASES.keys(), *MODULES.keys()])
            raise ValueError(f"Unknown module '{name}'. Valid modules and aliases: {valid}")
    return dedupe_modules(modules)


def normalize_module_name(value: str) -> str:
    return value.strip().lower().replace("_", "-")


def dedupe_modules(modules: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for module in modules:
        if module in seen:
            continue
        seen.add(module)
        result.append(module)
    return result


def print_module_list() -> None:
    for name, spec in MODULES.items():
        default_marker = "default" if spec.default else "optional"
        print(f"{name:14} {default_marker:8} {spec.maturity:9} {spec.summary}")


def load_env_file(path: Path) -> None:
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = shlex.split(raw_value, comments=False, posix=True)
        os.environ[key] = value[0] if value else ""


def write_json(path: Path, payload: dict[str, Any], compact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        if compact:
            json.dump(payload, handle, separators=(",", ":"))
        else:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")


def warn_empty_collection(items: list[Any], item_name: str, impact: str) -> None:
    if items:
        return
    print(
        f"Warning: no {item_name} objects collected; {impact} output may be incomplete. "
        "Try again with more privileges for full coverage.",
        file=sys.stderr,
    )


def warn_no_service_ticket_flags(services: list[Any]) -> None:
    if not services or any(service.ticket_flags is not None for service in services):
        return
    print(
        "Warning: no krbTicketFlags values collected from service accounts; delegation flags may be incomplete. "
        "Try again with more privileges for full coverage.",
        file=sys.stderr,
    )


def warn_no_service_attribute(services: list[Any], attribute: str, ldap_attribute: str, relationship: str) -> None:
    if not services or any(getattr(service, attribute) for service in services):
        return
    print(
        f"Warning: no {ldap_attribute} values collected from service accounts; {relationship} edges may be incomplete. "
        "Try again with more privileges for full coverage.",
        file=sys.stderr,
    )


def collect_users(context: CollectionContext) -> dict[str, Any]:
    return build_user_payload(context.users())


def collect_groups(context: CollectionContext) -> dict[str, Any]:
    return build_payload(groups=context.groups())


def collect_membership(context: CollectionContext) -> dict[str, Any]:
    users = context.users()
    groups = context.groups()
    return build_membership_payload(users, groups, build_memberof_edges(users, groups))


def collect_computers(context: CollectionContext) -> dict[str, Any]:
    return build_computer_payload(context.computers())


def collect_hostgroups(context: CollectionContext) -> dict[str, Any]:
    computers = context.computers()
    hostgroups = context.hostgroups()
    return build_hostgroup_payload(computers, hostgroups, build_hostgroup_memberof_edges(computers, hostgroups))


def collect_services(context: CollectionContext) -> dict[str, Any]:
    services = context.services()
    warn_no_service_ticket_flags(services)
    return build_service_payload(services)


def collect_add_member(context: CollectionContext) -> dict[str, Any]:
    users = context.users()
    groups = context.groups()
    return build_payload(users=users, groups=groups, add_member_edges=build_add_member_edges(users, groups))


def collect_host_access(context: CollectionContext) -> dict[str, Any]:
    users = context.users()
    groups = context.groups()
    computers = context.computers()
    hostgroups = context.hostgroups()
    hbac_rules = context.hbac_rules()
    sudo_rules = context.sudo_rules()
    sudo_commands = context.sudo_commands()
    memberof_edges = [*build_memberof_edges(users, groups), *build_hostgroup_memberof_edges(computers, hostgroups)]
    can_ssh_edges = build_can_ssh_edges(users, groups, computers, hostgroups, hbac_rules)
    can_sudo_edges = build_can_sudo_edges(users, groups, computers, hostgroups, hbac_rules, sudo_rules, sudo_commands)
    return build_payload(
        users=users,
        groups=groups,
        computers=computers,
        hostgroups=hostgroups,
        memberof_edges=memberof_edges,
        can_ssh_edges=can_ssh_edges,
        can_sudo_edges=can_sudo_edges,
    )


def collect_key_control(context: CollectionContext) -> dict[str, Any]:
    users = context.users()
    groups = context.groups()
    computers = context.computers()
    services = context.services()
    warn_no_service_ticket_flags(services)
    warn_no_service_attribute(services, "write_key_dns", "ipaAllowedToPerform;write_keys", "ForceChangePassword")
    warn_no_service_attribute(services, "read_key_dns", "ipaAllowedToPerform;read_keys", "ReadKerberosKey")
    return build_payload(
        users=users,
        groups=groups,
        computers=computers,
        services=services,
        force_change_password_edges=build_force_change_password_edges(users, groups, computers, services),
        read_kerberos_key_edges=build_read_kerberos_key_edges(users, groups, computers, services),
    )


def collect_rbac(context: CollectionContext) -> dict[str, Any]:
    users = context.users()
    groups = context.groups()
    roles = context.roles()
    services = context.services()
    hostgroups = context.hostgroups()
    privileges = context.privileges()
    permissions = context.permissions()
    warn_empty_collection(roles, "IPA_Role", "role membership")
    warn_empty_collection(privileges, "IPA_Privilege", "privilege membership")
    warn_empty_collection(permissions, "IPA_Permission", "permission membership")
    return build_payload(
        users=users,
        groups=groups,
        roles=roles,
        services=services,
        hostgroups=hostgroups,
        privileges=privileges,
        permissions=permissions,
        has_role_edges=build_role_memberof_edges(users, groups, roles),
        has_privilege_edges=build_privilege_memberof_edges(users, groups, roles, services, hostgroups, privileges),
        contains_permission_edges=build_permission_memberof_edges(privileges, permissions),
    )


def collect_hbac_services(context: CollectionContext) -> dict[str, Any]:
    users = context.users()
    groups = context.groups()
    computers = context.computers()
    hostgroups = context.hostgroups()
    hbac_rules = context.hbac_rules()
    hbac_services = context.hbac_services()
    return build_payload(
        users=users,
        groups=groups,
        computers=computers,
        memberof_edges=build_memberof_edges(users, groups),
        can_hbac_service_edges=build_can_hbac_service_edges(
            users,
            groups,
            computers,
            hostgroups,
            hbac_rules,
            hbac_services,
        ),
    )


def collect_managed_by(context: CollectionContext) -> dict[str, Any]:
    computers = context.computers()
    services = context.services()
    warn_no_service_ticket_flags(services)
    return build_payload(computers=computers, services=services, owns_edges=build_owns_edges(computers, services))


def collect_delegation(context: CollectionContext) -> dict[str, Any]:
    services = context.services()
    warn_no_service_ticket_flags(services)
    return build_allowed_to_delegate_payload(
        services,
        build_allowed_to_delegate_edges(services, context.delegation_rules(), context.delegation_targets()),
    )


def collect_rbcd(context: CollectionContext) -> dict[str, Any]:
    users = context.users()
    groups = context.groups()
    computers = context.computers()
    services = context.services()
    warn_no_service_ticket_flags(services)
    warn_no_service_attribute(services, "write_delegation_dns", "ipaAllowedToPerform;write_delegation", "AddRBCD")
    return build_payload(
        users=users,
        groups=groups,
        computers=computers,
        services=services,
        add_rbcd_edges=build_add_rbcd_edges(users, groups, computers, services),
    )


def collect_certificates(context: CollectionContext) -> dict[str, Any]:
    users = context.users()
    groups = context.groups()
    computers = context.computers()
    services = context.services()
    hostgroups = context.hostgroups()
    cas = context.cas()
    certificate_templates = context.certificate_templates()
    ca_acls = context.ca_acls()
    return build_certificate_payload(
        users,
        groups,
        computers,
        services,
        hostgroups,
        cas,
        certificate_templates,
        build_enroll_edges(users, groups, computers, services, hostgroups, cas, certificate_templates, ca_acls),
    )


def collect_trusts(context: CollectionContext) -> dict[str, Any]:
    environment = context.environment()
    trusted_domains = context.trusted_domains()
    return build_trust_payload(environment, trusted_domains, build_trusted_by_edges(environment, trusted_domains))


def collect_replication(context: CollectionContext) -> dict[str, Any]:
    environment = context.environment()
    privileges = context.privileges()
    permissions = context.permissions()
    dcsync_edges = build_dcsync_edges(environment, privileges, permissions)
    dcsync_start_ids = {edge.start_id for edge in dcsync_edges}
    dcsync_privileges = [privilege for privilege in privileges if privilege.object_id in dcsync_start_ids]
    dcsync_permissions = [permission for permission in permissions if permission.object_id in dcsync_start_ids]
    return build_dcsync_payload(environment, dcsync_privileges, dcsync_permissions, dcsync_edges)


def collect_selinux(context: CollectionContext) -> dict[str, Any]:
    return build_payload(selinux_user_maps=context.selinux_user_maps())


MODULES: dict[str, ModuleSpec] = {
    "users": ModuleSpec("users", "users.json", "FreeIPA user nodes", "core", collect_users, default=True),
    "groups": ModuleSpec("groups", "groups.json", "FreeIPA group nodes", "core", collect_groups, default=True),
    "membership": ModuleSpec(
        "membership",
        "membership.json",
        "direct user and group membership edges",
        "core",
        collect_membership,
        default=True,
    ),
    "computers": ModuleSpec(
        "computers",
        "computers.json",
        "FreeIPA enrolled host nodes",
        "core",
        collect_computers,
        default=True,
    ),
    "hostgroups": ModuleSpec(
        "hostgroups",
        "hostgroups.json",
        "hostgroup nodes and hostgroup membership",
        "core",
        collect_hostgroups,
        default=True,
    ),
    "services": ModuleSpec(
        "services",
        "services.json",
        "FreeIPA service principal nodes",
        "core",
        collect_services,
        default=True,
    ),
    "add-member": ModuleSpec(
        "add-member",
        "add_member.json",
        "group member-manager AddMember control",
        "core",
        collect_add_member,
        default=True,
    ),
    "host-access": ModuleSpec(
        "host-access",
        "host_access.json",
        f"{CANSSH_KIND} and {CANSUDO_KIND} host-access edges",
        "core",
        collect_host_access,
        default=True,
    ),
    "key-control": ModuleSpec(
        "key-control",
        "key_control.json",
        "service read-key and rotate-key control edges",
        "core",
        collect_key_control,
        default=True,
    ),
    "rbac": ModuleSpec(
        "rbac",
        "rbac.json",
        "role, privilege, and permission graph",
        "support",
        collect_rbac,
    ),
    "hbac-services": ModuleSpec(
        "hbac-services",
        "hbac_services.json",
        f"non-traversable {CANHBACSERVICE_KIND} service detail",
        "research",
        collect_hbac_services,
    ),
    "managed-by": ModuleSpec(
        "managed-by",
        "managed_by.json",
        "managedBy ownership research edges",
        "research",
        collect_managed_by,
    ),
    "delegation": ModuleSpec(
        "delegation",
        "delegation.json",
        "S4U delegation research edges",
        "research",
        collect_delegation,
    ),
    "rbcd": ModuleSpec(
        "rbcd",
        "rbcd.json",
        "target-side resource delegation write-control edges",
        "research",
        collect_rbcd,
    ),
    "certificates": ModuleSpec(
        "certificates",
        "certificates.json",
        "certificate authority and enrollment research edges",
        "research",
        collect_certificates,
    ),
    "trusts": ModuleSpec(
        "trusts",
        "trusts.json",
        "FreeIPA AD trust research graph",
        "research",
        collect_trusts,
    ),
    "replication": ModuleSpec(
        "replication",
        "replication.json",
        "replication-control and DCSync research edges",
        "research",
        collect_replication,
    ),
    "selinux": ModuleSpec(
        "selinux",
        "selinux.json",
        "SELinux user-map inventory",
        "support",
        collect_selinux,
    ),
}

MODULE_ALIASES: dict[str, tuple[str, ...]] = {
    "all": tuple(MODULES.keys()),
    "core": tuple(name for name, spec in MODULES.items() if spec.default),
    "default": tuple(name for name, spec in MODULES.items() if spec.default),
    "identity": ("users", "groups", "membership"),
    "hosts": ("computers", "hostgroups"),
    "ssh": ("host-access",),
    "sudo": ("host-access",),
    "service-identity": ("services", "key-control"),
}
