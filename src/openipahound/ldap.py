from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterator

from ldap3 import ALL, BASE, GSSAPI, SASL, SUBTREE, Connection, Server


USER_ATTRIBUTES = [
    "uid",
    "krbPrincipalName",
    "krbCanonicalName",
    "ipaUniqueID",
    "displayName",
    "givenName",
    "sn",
    "mail",
    "nsAccountLock",
    "ipaUserAuthType",
    "uidNumber",
    "gidNumber",
    "homeDirectory",
    "loginShell",
    "ipaNTSecurityIdentifier",
]

GROUP_ATTRIBUTES = [
    "cn",
    "ipaUniqueID",
    "description",
    "member",
    "memberManager",
    "gidNumber",
    "ipaNTSecurityIdentifier",
]

ROLE_ATTRIBUTES = [
    "cn",
    "ipaUniqueID",
    "description",
    "member",
]

PRIVILEGE_ATTRIBUTES = [
    "cn",
    "ipaUniqueID",
    "description",
    "member",
]

PERMISSION_ATTRIBUTES = [
    "cn",
    "ipaUniqueID",
    "description",
    "member",
    "ipaPermRight",
    "ipaPermTarget",
    "ipaPermTargetFilter",
]

CA_ATTRIBUTES = [
    "cn",
    "description",
    "ipaCaId",
    "ipaCaSubjectDN",
    "ipaCaIssuerDN",
]

CERTIFICATE_TEMPLATE_ATTRIBUTES = [
    "cn",
    "description",
    "ipaCertProfileStoreIssued",
]

CA_ACL_ATTRIBUTES = [
    "cn",
    "description",
    "ipaUniqueID",
    "ipaEnabledFlag",
    "userCategory",
    "hostCategory",
    "serviceCategory",
    "ipaCaCategory",
    "memberUser",
    "memberHost",
    "memberService",
    "ipaMemberCa",
    "ipaMemberCertProfile",
    "ipaCertProfileCategory",
]

SELINUX_USER_MAP_ATTRIBUTES = [
    "cn",
    "description",
    "ipaUniqueID",
    "ipaEnabledFlag",
    "ipaSELinuxUser",
    "userCategory",
    "hostCategory",
    "memberUser",
    "memberHost",
    "seeAlso",
]

TRUSTED_DOMAIN_ATTRIBUTES = [
    "cn",
    "ipaNTFlatName",
    "ipaNTTrustedDomainSID",
    "ipaNTSecurityIdentifier",
    "ipaNTSIDBlacklistIncoming",
    "ipaNTSIDBlacklistOutgoing",
    "ipaNTTrustPartner",
    "ipaNTTrustDirection",
    "ipaNTTrustType",
    "ipaNTTrustAttributes",
    "ipaNTSupportedEncryptionTypes",
    "ipaNTTrustPosixOffset",
    "gidNumber",
    "uidNumber",
]

DCSYNC_SOURCE_NAMES = {
    "REPLICATION MANAGERS",
    "REPLICATION ADMINISTRATORS",
    "ADD REPLICATION AGREEMENTS",
    "MODIFY REPLICATION AGREEMENTS",
}

COMPUTER_ATTRIBUTES = [
    "fqdn",
    "cn",
    "ipaUniqueID",
    "description",
    "krbPrincipalName",
    "krbCanonicalName",
    "ipaNTSecurityIdentifier",
    "managedBy",
]

SERVICE_ATTRIBUTES = [
    "krbPrincipalName",
    "krbCanonicalName",
    "ipaKrbPrincipalAlias",
    "ipaUniqueID",
    "krbTicketFlags",
    "managedBy",
    "memberPrincipal",
    "ipaAllowedToPerform;write_delegation",
    "ipaAllowedToPerform;write_keys",
    "ipaAllowedToPerform;read_keys",
]

SERVICE_DELEGATION_RULE_ATTRIBUTES = [
    "cn",
    "memberPrincipal",
    "ipaAllowedTarget",
]

SERVICE_DELEGATION_TARGET_ATTRIBUTES = [
    "cn",
    "memberPrincipal",
]

HOSTGROUP_ATTRIBUTES = [
    "cn",
    "ipaUniqueID",
    "description",
    "member",
]

HBAC_RULE_ATTRIBUTES = [
    "cn",
    "ipaEnabledFlag",
    "description",
    "userCategory",
    "hostCategory",
    "serviceCategory",
    "memberUser",
    "memberHost",
    "memberService",
]

HBAC_SERVICE_ATTRIBUTES = [
    "cn",
    "description",
]

ENVIRONMENT_CONFIG_ATTRIBUTES = [
    "cn",
    "ipaKrbAuthzData",
    "ipaConfigString",
]

KDC_CONFIG_ATTRIBUTES = [
    "cn",
    "ipaConfigString",
]

SUDO_RULE_ATTRIBUTES = [
    "cn",
    "ipaEnabledFlag",
    "description",
    "userCategory",
    "hostCategory",
    "cmdCategory",
    "ipaSudoRunAsUserCategory",
    "ipaSudoRunAsGroupCategory",
    "memberUser",
    "memberHost",
    "memberAllowCmd",
    "ipaSudoOpt",
]

SUDO_COMMAND_ATTRIBUTES = [
    "sudoCmd",
    "description",
]

KRB_TICKET_FLAG_OK_AS_DELEGATE = 0x100000
KRB_TICKET_FLAG_OK_TO_AUTH_AS_DELEGATE = 0x200000


@dataclass(frozen=True)
class IPAUser:
    uid: str
    dn: str
    object_id: str
    name: str
    principal: str | None = None
    canonical_principal: str | None = None
    sid: str | None = None
    display_name: str | None = None
    given_name: str | None = None
    surname: str | None = None
    email: str | None = None
    disabled: bool = False
    password_auth_allow: bool = True
    uid_number: int | None = None
    gid_number: int | None = None
    home_directory: str | None = None
    login_shell: str | None = None


@dataclass(frozen=True)
class IPAGroup:
    cn: str
    dn: str
    object_id: str
    name: str
    description: str | None = None
    gid_number: int | None = None
    sid: str | None = None
    member_dns: tuple[str, ...] = ()
    member_manager_dns: tuple[str, ...] = ()


@dataclass(frozen=True)
class IPARole:
    cn: str
    dn: str
    object_id: str
    name: str
    description: str | None = None
    member_dns: tuple[str, ...] = ()


@dataclass(frozen=True)
class IPAPrivilege:
    cn: str
    dn: str
    object_id: str
    name: str
    description: str | None = None
    member_dns: tuple[str, ...] = ()


@dataclass(frozen=True)
class IPAPermission:
    cn: str
    dn: str
    object_id: str
    name: str
    description: str | None = None
    member_dns: tuple[str, ...] = ()
    rights: tuple[str, ...] = ()
    target: str | None = None
    target_filters: tuple[str, ...] = ()


@dataclass(frozen=True)
class IPACA:
    cn: str
    dn: str
    object_id: str
    name: str
    description: str | None = None
    authority_id: str | None = None
    subject_dn: str | None = None
    issuer_dn: str | None = None


@dataclass(frozen=True)
class IPACertificateTemplate:
    cn: str
    dn: str
    object_id: str
    name: str
    description: str | None = None
    store_issued: bool = False


@dataclass(frozen=True)
class CAACL:
    cn: str
    dn: str
    enabled: bool
    description: str | None = None
    user_category: str | None = None
    host_category: str | None = None
    service_category: str | None = None
    ca_category: str | None = None
    cert_profile_category: str | None = None
    member_user_dns: tuple[str, ...] = ()
    member_host_dns: tuple[str, ...] = ()
    member_service_dns: tuple[str, ...] = ()
    member_ca_dns: tuple[str, ...] = ()
    member_profile_dns: tuple[str, ...] = ()


@dataclass(frozen=True)
class IPASELinux:
    cn: str
    dn: str
    object_id: str
    name: str
    enabled: bool
    selinux_user: str | None = None
    description: str | None = None
    user_category: str | None = None
    host_category: str | None = None
    member_user_dns: tuple[str, ...] = ()
    member_host_dns: tuple[str, ...] = ()
    hbac_rule_dns: tuple[str, ...] = ()


@dataclass(frozen=True)
class FreeIPAEnvironment:
    domain: str
    base_dn: str
    object_id: str
    name: str
    krb_authz_data: tuple[str, ...] = ()
    config_strings: tuple[str, ...] = ()
    kdc_config_strings: tuple[str, ...] = ()
    pac_ticket_signing_supported: bool = False


@dataclass(frozen=True)
class IPATrustedDomain:
    domain: str
    dn: str
    object_id: str
    name: str
    flat_name: str | None = None
    trusted_domain_sid: str | None = None
    trust_account_sid: str | None = None
    sid_blacklist_incoming: tuple[str, ...] = ()
    sid_blacklist_outgoing: tuple[str, ...] = ()
    trust_partner: str | None = None
    trust_direction: int | None = None
    trust_type: int | None = None
    trust_attributes: int | None = None
    supported_encryption_types: int | None = None
    posix_offset: int | None = None
    gid_number: int | None = None
    uid_number: int | None = None


@dataclass(frozen=True)
class MemberOf:
    start_id: str
    end_id: str


@dataclass(frozen=True)
class HasRole:
    start_id: str
    end_id: str


@dataclass(frozen=True)
class HasPrivilege:
    start_id: str
    end_id: str


@dataclass(frozen=True)
class ContainsPermission:
    start_id: str
    end_id: str


@dataclass(frozen=True)
class AddMember:
    start_id: str
    end_id: str
    source_attribute: str = "memberManager"


@dataclass(frozen=True)
class Enroll:
    start_id: str
    end_id: str
    ca_acl: str
    user_category: str | None = None
    host_category: str | None = None
    service_category: str | None = None
    ca_category: str | None = None
    cert_profile_category: str | None = None
    ca_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class TrustedBy:
    start_id: str
    end_id: str
    trust_direction: int | None = None
    trust_direction_label: str | None = None
    trust_type: int | None = None
    trust_type_label: str | None = None
    trust_attributes: int | None = None


@dataclass(frozen=True)
class DCSync:
    start_id: str
    end_id: str
    source_name: str
    source_type: str


@dataclass(frozen=True)
class CanSSH:
    start_id: str
    end_id: str
    rule: str


@dataclass(frozen=True)
class CanHBACService:
    start_id: str
    end_id: str
    services: tuple[str, ...]
    hbac_rules: tuple[str, ...]
    grant_details: tuple[str, ...] = ()


@dataclass(frozen=True)
class CanSUDO:
    start_id: str
    end_id: str
    sudo_rule: str
    hbac_rules: tuple[str, ...]
    commands: tuple[str, ...] = ()
    command_category: str | None = None
    runas_user_category: str | None = None
    runas_group_category: str | None = None
    no_password: bool = False


@dataclass(frozen=True)
class Owns:
    start_id: str
    end_id: str
    source_attribute: str = "managedBy"


@dataclass(frozen=True)
class AllowedToDelegate:
    start_id: str
    end_id: str
    rule: str
    target: str


@dataclass(frozen=True)
class AddRBCD:
    start_id: str
    end_id: str
    source_attribute: str = "ipaAllowedToPerform;write_delegation"


@dataclass(frozen=True)
class ForceChangePassword:
    start_id: str
    end_id: str
    source_attribute: str = "ipaAllowedToPerform;write_keys"


@dataclass(frozen=True)
class ReadKerberosKey:
    start_id: str
    end_id: str
    source_attribute: str = "ipaAllowedToPerform;read_keys"


@dataclass(frozen=True)
class IPAComputer:
    fqdn: str
    dn: str
    object_id: str
    name: str
    principal: str | None = None
    canonical_principal: str | None = None
    sid: str | None = None
    description: str | None = None
    managed_by_dns: tuple[str, ...] = ()


@dataclass(frozen=True)
class IPAService:
    principal: str
    dn: str
    object_id: str
    name: str
    canonical_principal: str | None = None
    service_type: str | None = None
    host_fqdn: str | None = None
    aliases: tuple[str, ...] = ()
    managed_by_dns: tuple[str, ...] = ()
    member_principals: tuple[str, ...] = ()
    write_delegation_dns: tuple[str, ...] = ()
    write_key_dns: tuple[str, ...] = ()
    read_key_dns: tuple[str, ...] = ()
    ticket_flags: int | None = None
    unconstrained_delegation: bool = False
    ok_to_auth_as_delegate: bool = False


@dataclass(frozen=True)
class IPAHostGroup:
    cn: str
    dn: str
    object_id: str
    name: str
    description: str | None = None
    member_dns: tuple[str, ...] = ()


@dataclass(frozen=True)
class HBACRule:
    cn: str
    dn: str
    enabled: bool
    description: str | None = None
    user_category: str | None = None
    host_category: str | None = None
    service_category: str | None = None
    member_user_dns: tuple[str, ...] = ()
    member_host_dns: tuple[str, ...] = ()
    member_service_dns: tuple[str, ...] = ()


@dataclass(frozen=True)
class HBACService:
    cn: str
    dn: str
    description: str | None = None


@dataclass(frozen=True)
class SudoRule:
    cn: str
    dn: str
    enabled: bool
    description: str | None = None
    user_category: str | None = None
    host_category: str | None = None
    command_category: str | None = None
    runas_user_category: str | None = None
    runas_group_category: str | None = None
    member_user_dns: tuple[str, ...] = ()
    member_host_dns: tuple[str, ...] = ()
    member_allow_command_dns: tuple[str, ...] = ()
    sudo_options: tuple[str, ...] = ()


@dataclass(frozen=True)
class SudoCommand:
    dn: str
    command: str
    description: str | None = None


@dataclass(frozen=True)
class ServiceDelegationRule:
    cn: str
    dn: str
    member_principals: tuple[str, ...] = ()
    target_dns: tuple[str, ...] = ()


@dataclass(frozen=True)
class ServiceDelegationTarget:
    cn: str
    dn: str
    member_principals: tuple[str, ...] = ()


class FreeIPACollector:
    def __init__(
        self,
        server: str,
        base_dn: str,
        user: str | None,
        password: str | None,
        use_ssl: bool = True,
        use_kerberos: bool = False,
    ) -> None:
        self.server_name = server
        self.base_dn = base_dn
        self.user = user
        self.password = password
        self.use_ssl = use_ssl
        self.use_kerberos = use_kerberos
        self.connection: Connection | None = None

    def __enter__(self) -> "FreeIPACollector":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.connection is not None:
            self.connection.unbind()

    def connect(self) -> None:
        server = Server(self.server_name, use_ssl=self.use_ssl, get_info=ALL)
        if self.use_kerberos:
            connection_options = {
                "authentication": SASL,
                "sasl_mechanism": GSSAPI,
                "auto_bind": True,
            }
            self.connection = Connection(server, **connection_options)
            return

        if not self.user or not self.password:
            raise ValueError("simple LDAP bind requires user and password")
        self.connection = Connection(
            server,
            user=bind_dn(self.user, self.base_dn),
            password=self.password,
            auto_bind=True,
        )

    def collect_environment(self) -> FreeIPAEnvironment:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        config_entry: dict[str, Any] | None = None
        config_results = self.connection.extend.standard.paged_search(
            search_base=f"cn=ipaConfig,cn=etc,{self.base_dn}",
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=ENVIRONMENT_CONFIG_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )
        for item in config_results:
            if item.get("type") == "searchResEntry":
                config_entry = item
                break

        kdc_entries: list[dict[str, Any]] = []
        kdc_results = self.connection.extend.standard.paged_search(
            search_base=f"cn=masters,cn=ipa,cn=etc,{self.base_dn}",
            search_filter="(cn=KDC)",
            search_scope=SUBTREE,
            attributes=KDC_CONFIG_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )
        for item in kdc_results:
            if item.get("type") == "searchResEntry":
                kdc_entries.append(item)

        return environment_from_ldap_entries(self.base_dn, config_entry, kdc_entries)

    def collect_users(self, limit: int | None = None) -> list[IPAUser]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=users,cn=accounts,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(&(objectClass=person)(uid=*))",
            search_scope=SUBTREE,
            attributes=USER_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        users: list[IPAUser] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            users.append(user_from_ldap_entry(item, self.base_dn))
            if limit is not None and len(users) >= limit:
                break
        return users

    def collect_groups(self, limit: int | None = None) -> list[IPAGroup]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=groups,cn=accounts,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=groupOfNames)",
            search_scope=SUBTREE,
            attributes=GROUP_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        groups: list[IPAGroup] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            groups.append(group_from_ldap_entry(item, self.base_dn))
            if limit is not None and len(groups) >= limit:
                break
        return groups

    def collect_roles(self, limit: int | None = None) -> list[IPARole]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=roles,cn=accounts,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=groupOfNames)",
            search_scope=SUBTREE,
            attributes=ROLE_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        roles: list[IPARole] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            roles.append(role_from_ldap_entry(item, self.base_dn))
            if limit is not None and len(roles) >= limit:
                break
        return roles

    def collect_privileges(self, limit: int | None = None) -> list[IPAPrivilege]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=privileges,cn=pbac,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=groupOfNames)",
            search_scope=SUBTREE,
            attributes=PRIVILEGE_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        privileges: list[IPAPrivilege] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            privileges.append(privilege_from_ldap_entry(item, self.base_dn))
            if limit is not None and len(privileges) >= limit:
                break
        return privileges

    def collect_permissions(self, limit: int | None = None) -> list[IPAPermission]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=permissions,cn=pbac,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=ipaPermission)",
            search_scope=SUBTREE,
            attributes=PERMISSION_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        permissions: list[IPAPermission] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            permissions.append(permission_from_ldap_entry(item, self.base_dn))
            if limit is not None and len(permissions) >= limit:
                break
        return permissions

    def collect_cas(self, limit: int | None = None) -> list[IPACA]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=cas,cn=ca,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=ipaCA)",
            search_scope=SUBTREE,
            attributes=CA_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        cas: list[IPACA] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            cas.append(ca_from_ldap_entry(item, self.base_dn))
            if limit is not None and len(cas) >= limit:
                break
        return cas

    def collect_certificate_templates(self, limit: int | None = None) -> list[IPACertificateTemplate]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=certprofiles,cn=ca,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=ipaCertProfile)",
            search_scope=SUBTREE,
            attributes=CERTIFICATE_TEMPLATE_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        templates: list[IPACertificateTemplate] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            templates.append(certificate_template_from_ldap_entry(item, self.base_dn))
            if limit is not None and len(templates) >= limit:
                break
        return templates

    def collect_ca_acls(self, limit: int | None = None) -> list[CAACL]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=caacls,cn=ca,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=ipaCAACL)",
            search_scope=SUBTREE,
            attributes=CA_ACL_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        ca_acls: list[CAACL] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            ca_acls.append(ca_acl_from_ldap_entry(item))
            if limit is not None and len(ca_acls) >= limit:
                break
        return ca_acls

    def collect_selinux_user_maps(self, limit: int | None = None) -> list[IPASELinux]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=usermap,cn=selinux,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=ipaSELinuxUserMap)",
            search_scope=SUBTREE,
            attributes=SELINUX_USER_MAP_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        maps: list[IPASELinux] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            maps.append(selinux_user_map_from_ldap_entry(item, self.base_dn))
            if limit is not None and len(maps) >= limit:
                break
        return maps

    def collect_trusted_domains(self, limit: int | None = None) -> list[IPATrustedDomain]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=ad,cn=trusts,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=ipaNTTrustedDomain)",
            search_scope=SUBTREE,
            attributes=TRUSTED_DOMAIN_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        domains: list[IPATrustedDomain] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            domains.append(trusted_domain_from_ldap_entry(item))
            if limit is not None and len(domains) >= limit:
                break
        return domains

    def collect_computers(self, limit: int | None = None) -> list[IPAComputer]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=computers,cn=accounts,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=ipahost)",
            search_scope=SUBTREE,
            attributes=COMPUTER_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        computers: list[IPAComputer] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            computers.append(computer_from_ldap_entry(item, self.base_dn))
            if limit is not None and len(computers) >= limit:
                break
        return computers

    def collect_services(self, limit: int | None = None) -> list[IPAService]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=services,cn=accounts,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=ipaService)",
            search_scope=SUBTREE,
            attributes=SERVICE_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        services: list[IPAService] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            services.append(service_from_ldap_entry(item))
            if limit is not None and len(services) >= limit:
                break
        return services

    def collect_service_delegation_rules(self, limit: int | None = None) -> list[ServiceDelegationRule]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=s4u2proxy,cn=etc,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=ipaKrb5DelegationACL)",
            search_scope=SUBTREE,
            attributes=SERVICE_DELEGATION_RULE_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        rules: list[ServiceDelegationRule] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            rules.append(service_delegation_rule_from_ldap_entry(item))
            if limit is not None and len(rules) >= limit:
                break
        return rules

    def collect_service_delegation_targets(self, limit: int | None = None) -> list[ServiceDelegationTarget]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=s4u2proxy,cn=etc,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=groupOfPrincipals)",
            search_scope=SUBTREE,
            attributes=SERVICE_DELEGATION_TARGET_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        targets: list[ServiceDelegationTarget] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            targets.append(service_delegation_target_from_ldap_entry(item))
            if limit is not None and len(targets) >= limit:
                break
        return targets

    def collect_hostgroups(self, limit: int | None = None) -> list[IPAHostGroup]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=hostgroups,cn=accounts,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=ipaHostGroup)",
            search_scope=SUBTREE,
            attributes=HOSTGROUP_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        hostgroups: list[IPAHostGroup] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            hostgroups.append(hostgroup_from_ldap_entry(item, self.base_dn))
            if limit is not None and len(hostgroups) >= limit:
                break
        return hostgroups

    def collect_hbac_rules(self, limit: int | None = None) -> list[HBACRule]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=hbac,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=ipaHBACRule)",
            search_scope=SUBTREE,
            attributes=HBAC_RULE_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        rules: list[HBACRule] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            rules.append(hbac_rule_from_ldap_entry(item))
            if limit is not None and len(rules) >= limit:
                break
        return rules

    def collect_hbac_services(self, limit: int | None = None) -> list[HBACService]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=hbacservices,cn=hbac,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=ipaHBACService)",
            search_scope=SUBTREE,
            attributes=HBAC_SERVICE_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        services: list[HBACService] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            services.append(hbac_service_from_ldap_entry(item))
            if limit is not None and len(services) >= limit:
                break
        return services

    def collect_sudo_rules(self, limit: int | None = None) -> list[SudoRule]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=sudorules,cn=sudo,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=ipaSudoRule)",
            search_scope=SUBTREE,
            attributes=SUDO_RULE_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        rules: list[SudoRule] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            rules.append(sudo_rule_from_ldap_entry(item))
            if limit is not None and len(rules) >= limit:
                break
        return rules

    def collect_sudo_commands(self, limit: int | None = None) -> list[SudoCommand]:
        if self.connection is None:
            raise RuntimeError("collector is not connected")

        search_base = f"cn=sudocmds,cn=sudo,{self.base_dn}"
        results = self.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=ipaSudoCmd)",
            search_scope=SUBTREE,
            attributes=SUDO_COMMAND_ATTRIBUTES,
            paged_size=500,
            generator=True,
        )

        commands: list[SudoCommand] = []
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            commands.append(sudo_command_from_ldap_entry(item))
            if limit is not None and len(commands) >= limit:
                break
        return commands


def domain_to_base_dn(domain: str) -> str:
    parts = [part.strip() for part in domain.split(".") if part.strip()]
    return ",".join(f"dc={part}" for part in parts)


def bind_dn(user: str, base_dn: str) -> str:
    if "=" in user and "," in user:
        return user
    return f"uid={user},cn=users,cn=accounts,{base_dn}"


def user_from_ldap_entry(entry: dict[str, Any], base_dn: str) -> IPAUser:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    uid = first(attrs.get("uid")) or dn
    principal = first(attrs.get("krbprincipalname"))
    unique_id = first(attrs.get("ipauniqueid"))
    realm = base_dn_to_realm(base_dn)
    name = (principal or f"{uid}@{realm}").upper()
    disabled = parse_bool(first(attrs.get("nsaccountlock")))
    auth_types = [str(value).lower() for value in values(attrs.get("ipauserauthtype"))]

    return IPAUser(
        uid=uid,
        dn=dn,
        object_id=stable_user_id(unique_id, dn),
        name=name,
        principal=principal,
        canonical_principal=first(attrs.get("krbcanonicalname")),
        sid=first(attrs.get("ipantsecurityidentifier")),
        display_name=first(attrs.get("displayname")),
        given_name=first(attrs.get("givenname")),
        surname=first(attrs.get("sn")),
        email=first(attrs.get("mail")),
        disabled=disabled,
        password_auth_allow=not auth_types or "password" in auth_types,
        uid_number=parse_int(first(attrs.get("uidnumber"))),
        gid_number=parse_int(first(attrs.get("gidnumber"))),
        home_directory=first(attrs.get("homedirectory")),
        login_shell=first(attrs.get("loginshell")),
    )


def group_from_ldap_entry(entry: dict[str, Any], base_dn: str) -> IPAGroup:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    cn = first(attrs.get("cn")) or dn
    unique_id = first(attrs.get("ipauniqueid"))
    realm = base_dn_to_realm(base_dn)

    return IPAGroup(
        cn=cn,
        dn=dn,
        object_id=stable_group_id(unique_id, dn),
        name=f"{cn}@{realm}".upper(),
        description=first(attrs.get("description")),
        gid_number=parse_int(first(attrs.get("gidnumber"))),
        sid=first(attrs.get("ipantsecurityidentifier")),
        member_dns=tuple(str(value) for value in values(attrs.get("member"))),
        member_manager_dns=tuple(str(value) for value in values(attrs.get("membermanager"))),
    )


def role_from_ldap_entry(entry: dict[str, Any], base_dn: str) -> IPARole:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    cn = first(attrs.get("cn")) or dn
    unique_id = first(attrs.get("ipauniqueid"))
    realm = base_dn_to_realm(base_dn)

    return IPARole(
        cn=cn,
        dn=dn,
        object_id=stable_role_id(unique_id, dn),
        name=f"{cn}@{realm}".upper(),
        description=first(attrs.get("description")),
        member_dns=tuple(str(value) for value in values(attrs.get("member"))),
    )


def privilege_from_ldap_entry(entry: dict[str, Any], base_dn: str) -> IPAPrivilege:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    cn = first(attrs.get("cn")) or dn
    unique_id = first(attrs.get("ipauniqueid"))
    realm = base_dn_to_realm(base_dn)

    return IPAPrivilege(
        cn=cn,
        dn=dn,
        object_id=stable_privilege_id(unique_id, dn),
        name=f"{cn}@{realm}".upper(),
        description=first(attrs.get("description")),
        member_dns=tuple(str(value) for value in values(attrs.get("member"))),
    )


def permission_from_ldap_entry(entry: dict[str, Any], base_dn: str) -> IPAPermission:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    cn = first(attrs.get("cn")) or dn
    unique_id = first(attrs.get("ipauniqueid"))
    realm = base_dn_to_realm(base_dn)

    return IPAPermission(
        cn=cn,
        dn=dn,
        object_id=stable_permission_id(unique_id, dn),
        name=f"{cn}@{realm}".upper(),
        description=first(attrs.get("description")),
        member_dns=tuple(str(value) for value in values(attrs.get("member"))),
        rights=tuple(str(value) for value in values(attrs.get("ipapermright"))),
        target=first(attrs.get("ipapermtarget")),
        target_filters=tuple(str(value) for value in values(attrs.get("ipapermtargetfilter"))),
    )


def ca_from_ldap_entry(entry: dict[str, Any], base_dn: str) -> IPACA:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    cn = first(attrs.get("cn")) or dn
    authority_id = first(attrs.get("ipacaid"))
    realm = base_dn_to_realm(base_dn)

    return IPACA(
        cn=cn,
        dn=dn,
        object_id=stable_ca_id(authority_id, dn),
        name=f"{cn}@{realm}".upper(),
        description=first(attrs.get("description")),
        authority_id=authority_id,
        subject_dn=first(attrs.get("ipacasubjectdn")),
        issuer_dn=first(attrs.get("ipacaissuerdn")),
    )


def certificate_template_from_ldap_entry(entry: dict[str, Any], base_dn: str) -> IPACertificateTemplate:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    cn = first(attrs.get("cn")) or dn
    realm = base_dn_to_realm(base_dn)

    return IPACertificateTemplate(
        cn=cn,
        dn=dn,
        object_id=stable_certificate_template_id(cn, dn),
        name=f"{cn}@{realm}".upper(),
        description=first(attrs.get("description")),
        store_issued=parse_bool(first(attrs.get("ipacertprofilestoreissued"))),
    )


def ca_acl_from_ldap_entry(entry: dict[str, Any]) -> CAACL:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    cn = first(attrs.get("cn")) or dn

    return CAACL(
        cn=cn,
        dn=dn,
        enabled=parse_bool(first(attrs.get("ipaenabledflag"))),
        description=first(attrs.get("description")),
        user_category=lower_optional(first(attrs.get("usercategory"))),
        host_category=lower_optional(first(attrs.get("hostcategory"))),
        service_category=lower_optional(first(attrs.get("servicecategory"))),
        ca_category=lower_optional(first(attrs.get("ipacacategory"))),
        cert_profile_category=lower_optional(first(attrs.get("ipacertprofilecategory"))),
        member_user_dns=tuple(str(value) for value in values(attrs.get("memberuser"))),
        member_host_dns=tuple(str(value) for value in values(attrs.get("memberhost"))),
        member_service_dns=tuple(str(value) for value in values(attrs.get("memberservice"))),
        member_ca_dns=tuple(str(value) for value in values(attrs.get("ipamemberca"))),
        member_profile_dns=tuple(str(value) for value in values(attrs.get("ipamembercertprofile"))),
    )


def selinux_user_map_from_ldap_entry(entry: dict[str, Any], base_dn: str) -> IPASELinux:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    cn = first(attrs.get("cn")) or dn
    realm = base_dn_to_realm(base_dn)

    return IPASELinux(
        cn=cn,
        dn=dn,
        object_id=stable_selinux_user_map_id(first(attrs.get("ipauniqueid")), dn),
        name=f"{cn}@{realm}".upper(),
        enabled=parse_bool(first(attrs.get("ipaenabledflag"))),
        selinux_user=first(attrs.get("ipaselinuxuser")),
        description=first(attrs.get("description")),
        user_category=lower_optional(first(attrs.get("usercategory"))),
        host_category=lower_optional(first(attrs.get("hostcategory"))),
        member_user_dns=tuple(str(value) for value in values(attrs.get("memberuser"))),
        member_host_dns=tuple(str(value) for value in values(attrs.get("memberhost"))),
        hbac_rule_dns=tuple(str(value) for value in values(attrs.get("seealso"))),
    )


def environment_from_base_dn(
    base_dn: str,
    krb_authz_data: tuple[str, ...] = (),
    config_strings: tuple[str, ...] = (),
    kdc_config_strings: tuple[str, ...] = (),
) -> FreeIPAEnvironment:
    domain = ".".join(part[3:] for part in base_dn.split(",") if part.lower().startswith("dc="))
    realm = base_dn_to_realm(base_dn)
    pac_ticket_signing_supported = any(
        str(value).lower() == "pactktsignsupported" for value in kdc_config_strings
    )
    return FreeIPAEnvironment(
        domain=domain,
        base_dn=base_dn,
        object_id=stable_environment_id(domain or realm),
        name=realm,
        krb_authz_data=krb_authz_data,
        config_strings=config_strings,
        kdc_config_strings=kdc_config_strings,
        pac_ticket_signing_supported=pac_ticket_signing_supported,
    )


def environment_from_ldap_entries(
    base_dn: str,
    config_entry: dict[str, Any] | None,
    kdc_entries: list[dict[str, Any]],
) -> FreeIPAEnvironment:
    config_attrs = lower_keys(config_entry.get("attributes", {})) if config_entry else {}
    kdc_config_strings: list[str] = []
    for entry in kdc_entries:
        attrs = lower_keys(entry.get("attributes", {}))
        kdc_config_strings.extend(str(value) for value in values(attrs.get("ipaconfigstring")))

    return environment_from_base_dn(
        base_dn,
        krb_authz_data=tuple(str(value) for value in values(config_attrs.get("ipakrbauthzdata"))),
        config_strings=tuple(str(value) for value in values(config_attrs.get("ipaconfigstring"))),
        kdc_config_strings=tuple(dedupe(kdc_config_strings)),
    )


def trusted_domain_from_ldap_entry(entry: dict[str, Any]) -> IPATrustedDomain:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    domain = first(attrs.get("ipanttrustpartner")) or first(attrs.get("cn")) or dn

    return IPATrustedDomain(
        domain=domain,
        dn=dn,
        object_id=stable_trusted_domain_id(first(attrs.get("ipanttrusteddomainsid")), domain, dn),
        name=domain.upper(),
        flat_name=first(attrs.get("ipantflatname")),
        trusted_domain_sid=first(attrs.get("ipanttrusteddomainsid")),
        trust_account_sid=first(attrs.get("ipantsecurityidentifier")),
        sid_blacklist_incoming=tuple(str(value) for value in values(attrs.get("ipantsidblacklistincoming"))),
        sid_blacklist_outgoing=tuple(str(value) for value in values(attrs.get("ipantsidblacklistoutgoing"))),
        trust_partner=first(attrs.get("ipanttrustpartner")),
        trust_direction=parse_int(first(attrs.get("ipanttrustdirection"))),
        trust_type=parse_int(first(attrs.get("ipanttrusttype"))),
        trust_attributes=parse_int(first(attrs.get("ipanttrustattributes"))),
        supported_encryption_types=parse_int(first(attrs.get("ipantsupportedencryptiontypes"))),
        posix_offset=parse_int(first(attrs.get("ipanttrustposixoffset"))),
        gid_number=parse_int(first(attrs.get("gidnumber"))),
        uid_number=parse_int(first(attrs.get("uidnumber"))),
    )


def computer_from_ldap_entry(entry: dict[str, Any], base_dn: str) -> IPAComputer:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    fqdn = first(attrs.get("fqdn")) or first(attrs.get("cn")) or dn
    unique_id = first(attrs.get("ipauniqueid"))

    return IPAComputer(
        fqdn=fqdn,
        dn=dn,
        object_id=stable_computer_id(unique_id, dn),
        name=fqdn.upper(),
        principal=first(attrs.get("krbprincipalname")),
        canonical_principal=first(attrs.get("krbcanonicalname")),
        sid=first(attrs.get("ipantsecurityidentifier")),
        description=first(attrs.get("description")),
        managed_by_dns=tuple(str(value) for value in values(attrs.get("managedby"))),
    )


def service_from_ldap_entry(entry: dict[str, Any]) -> IPAService:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    principal = first(attrs.get("krbprincipalname")) or first(attrs.get("krbcanonicalname")) or dn
    unique_id = first(attrs.get("ipauniqueid"))
    ticket_flags = parse_int(first(attrs.get("krbticketflags")))
    service_type, host_fqdn = split_service_principal(principal)

    return IPAService(
        principal=principal,
        dn=dn,
        object_id=stable_service_id(unique_id, dn),
        name=principal.upper(),
        canonical_principal=first(attrs.get("krbcanonicalname")),
        service_type=service_type,
        host_fqdn=host_fqdn,
        aliases=tuple(str(value) for value in values(attrs.get("ipakrbprincipalalias"))),
        managed_by_dns=tuple(str(value) for value in values(attrs.get("managedby"))),
        member_principals=tuple(str(value) for value in values(attrs.get("memberprincipal"))),
        write_delegation_dns=tuple(str(value) for value in values(attrs.get("ipaallowedtoperform;write_delegation"))),
        write_key_dns=tuple(str(value) for value in values(attrs.get("ipaallowedtoperform;write_keys"))),
        read_key_dns=tuple(str(value) for value in values(attrs.get("ipaallowedtoperform;read_keys"))),
        ticket_flags=ticket_flags,
        unconstrained_delegation=has_ticket_flag(ticket_flags, KRB_TICKET_FLAG_OK_AS_DELEGATE),
        ok_to_auth_as_delegate=has_ticket_flag(ticket_flags, KRB_TICKET_FLAG_OK_TO_AUTH_AS_DELEGATE),
    )


def service_delegation_rule_from_ldap_entry(entry: dict[str, Any]) -> ServiceDelegationRule:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    cn = first(attrs.get("cn")) or dn

    return ServiceDelegationRule(
        cn=cn,
        dn=dn,
        member_principals=tuple(str(value) for value in values(attrs.get("memberprincipal"))),
        target_dns=tuple(str(value) for value in values(attrs.get("ipaallowedtarget"))),
    )


def service_delegation_target_from_ldap_entry(entry: dict[str, Any]) -> ServiceDelegationTarget:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    cn = first(attrs.get("cn")) or dn

    return ServiceDelegationTarget(
        cn=cn,
        dn=dn,
        member_principals=tuple(str(value) for value in values(attrs.get("memberprincipal"))),
    )


def hostgroup_from_ldap_entry(entry: dict[str, Any], base_dn: str) -> IPAHostGroup:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    cn = first(attrs.get("cn")) or dn
    unique_id = first(attrs.get("ipauniqueid"))
    realm = base_dn_to_realm(base_dn)

    return IPAHostGroup(
        cn=cn,
        dn=dn,
        object_id=stable_hostgroup_id(unique_id, dn),
        name=f"{cn}@{realm}".upper(),
        description=first(attrs.get("description")),
        member_dns=tuple(str(value) for value in values(attrs.get("member"))),
    )


def hbac_rule_from_ldap_entry(entry: dict[str, Any]) -> HBACRule:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    cn = first(attrs.get("cn")) or dn

    return HBACRule(
        cn=cn,
        dn=dn,
        enabled=parse_bool(first(attrs.get("ipaenabledflag"))),
        description=first(attrs.get("description")),
        user_category=lower_optional(first(attrs.get("usercategory"))),
        host_category=lower_optional(first(attrs.get("hostcategory"))),
        service_category=lower_optional(first(attrs.get("servicecategory"))),
        member_user_dns=tuple(str(value) for value in values(attrs.get("memberuser"))),
        member_host_dns=tuple(str(value) for value in values(attrs.get("memberhost"))),
        member_service_dns=tuple(str(value) for value in values(attrs.get("memberservice"))),
    )


def hbac_service_from_ldap_entry(entry: dict[str, Any]) -> HBACService:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    cn = first(attrs.get("cn")) or first_rdn_value(dn) or dn

    return HBACService(
        cn=cn,
        dn=dn,
        description=first(attrs.get("description")),
    )


def sudo_rule_from_ldap_entry(entry: dict[str, Any]) -> SudoRule:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    cn = first(attrs.get("cn")) or dn

    return SudoRule(
        cn=cn,
        dn=dn,
        enabled=parse_bool(first(attrs.get("ipaenabledflag"))),
        description=first(attrs.get("description")),
        user_category=lower_optional(first(attrs.get("usercategory"))),
        host_category=lower_optional(first(attrs.get("hostcategory"))),
        command_category=lower_optional(first(attrs.get("cmdcategory"))),
        runas_user_category=lower_optional(first(attrs.get("ipasudorunasusercategory"))),
        runas_group_category=lower_optional(first(attrs.get("ipasudorunasgroupcategory"))),
        member_user_dns=tuple(str(value) for value in values(attrs.get("memberuser"))),
        member_host_dns=tuple(str(value) for value in values(attrs.get("memberhost"))),
        member_allow_command_dns=tuple(str(value) for value in values(attrs.get("memberallowcmd"))),
        sudo_options=tuple(str(value) for value in values(attrs.get("ipasudoopt"))),
    )


def sudo_command_from_ldap_entry(entry: dict[str, Any]) -> SudoCommand:
    attrs = lower_keys(entry.get("attributes", {}))
    dn = str(entry["dn"])
    command = first(attrs.get("sudocmd")) or dn

    return SudoCommand(
        dn=dn,
        command=command,
        description=first(attrs.get("description")),
    )


def build_memberof_edges(users: list[IPAUser], groups: list[IPAGroup]) -> list[MemberOf]:
    objects_by_dn = {user.dn: user.object_id for user in users}
    objects_by_dn.update({group.dn: group.object_id for group in groups})

    edges: list[MemberOf] = []
    seen: set[tuple[str, str]] = set()
    for group in groups:
        for member_dn in group.member_dns:
            start_id = objects_by_dn.get(member_dn)
            if not start_id:
                continue
            key = (start_id, group.object_id)
            if key in seen:
                continue
            seen.add(key)
            edges.append(MemberOf(start_id=start_id, end_id=group.object_id))
    return edges


def build_add_member_edges(users: list[IPAUser], groups: list[IPAGroup]) -> list[AddMember]:
    objects_by_dn = {user.dn: user.object_id for user in users}
    objects_by_dn.update({group.dn: group.object_id for group in groups})

    edges: list[AddMember] = []
    seen: set[tuple[str, str]] = set()
    for group in groups:
        for manager_dn in group.member_manager_dns:
            manager_id = objects_by_dn.get(manager_dn)
            if manager_id is None:
                continue
            key = (manager_id, group.object_id)
            if key in seen:
                continue
            seen.add(key)
            edges.append(AddMember(start_id=manager_id, end_id=group.object_id))
    return edges


def build_role_memberof_edges(
    users: list[IPAUser],
    groups: list[IPAGroup],
    roles: list[IPARole],
) -> list[HasRole]:
    objects_by_dn = {user.dn: user.object_id for user in users}
    objects_by_dn.update({group.dn: group.object_id for group in groups})
    objects_by_dn.update({role.dn: role.object_id for role in roles})

    edges: list[HasRole] = []
    seen: set[tuple[str, str]] = set()
    for role in roles:
        for member_dn in role.member_dns:
            start_id = objects_by_dn.get(member_dn)
            if start_id is None:
                continue
            key = (start_id, role.object_id)
            if key in seen:
                continue
            seen.add(key)
            edges.append(HasRole(start_id=start_id, end_id=role.object_id))
    return edges


def build_privilege_memberof_edges(
    users: list[IPAUser],
    groups: list[IPAGroup],
    roles: list[IPARole],
    services: list[IPAService],
    hostgroups: list[IPAHostGroup],
    privileges: list[IPAPrivilege],
) -> list[HasPrivilege]:
    objects_by_dn = {user.dn: user.object_id for user in users}
    objects_by_dn.update({group.dn: group.object_id for group in groups})
    objects_by_dn.update({role.dn: role.object_id for role in roles})
    objects_by_dn.update({service.dn: service.object_id for service in services})
    objects_by_dn.update({hostgroup.dn: hostgroup.object_id for hostgroup in hostgroups})
    objects_by_dn.update({privilege.dn: privilege.object_id for privilege in privileges})

    edges: list[HasPrivilege] = []
    seen: set[tuple[str, str]] = set()
    for privilege in privileges:
        for member_dn in privilege.member_dns:
            start_id = objects_by_dn.get(member_dn)
            if start_id is None:
                continue
            key = (start_id, privilege.object_id)
            if key in seen:
                continue
            seen.add(key)
            edges.append(HasPrivilege(start_id=start_id, end_id=privilege.object_id))
    return edges


def build_permission_memberof_edges(
    privileges: list[IPAPrivilege],
    permissions: list[IPAPermission],
) -> list[ContainsPermission]:
    privileges_by_dn = {privilege.dn: privilege.object_id for privilege in privileges}

    edges: list[ContainsPermission] = []
    seen: set[tuple[str, str]] = set()
    for permission in permissions:
        for member_dn in permission.member_dns:
            privilege_id = privileges_by_dn.get(member_dn)
            if privilege_id is None:
                continue
            key = (privilege_id, permission.object_id)
            if key in seen:
                continue
            seen.add(key)
            edges.append(ContainsPermission(start_id=privilege_id, end_id=permission.object_id))
    return edges


def build_enroll_edges(
    users: list[IPAUser],
    groups: list[IPAGroup],
    computers: list[IPAComputer],
    services: list[IPAService],
    hostgroups: list[IPAHostGroup],
    cas: list[IPACA],
    templates: list[IPACertificateTemplate],
    ca_acls: list[CAACL],
) -> list[Enroll]:
    users_by_dn = {user.dn: user.object_id for user in users}
    groups_by_dn = {group.dn: group.object_id for group in groups}
    computers_by_dn = {computer.dn: computer.object_id for computer in computers}
    services_by_dn = {service.dn: service.object_id for service in services}
    hostgroups_by_dn = {hostgroup.dn: hostgroup.object_id for hostgroup in hostgroups}
    templates_by_dn = {template.dn: template for template in templates}
    cas_by_dn = {ca.dn: ca for ca in cas}

    edges: list[Enroll] = []
    seen: set[tuple[str, str, str]] = set()
    for ca_acl in ca_acls:
        if not ca_acl.enabled:
            continue

        target_templates = acl_certificate_templates(ca_acl, templates, templates_by_dn)
        source_ids = acl_source_ids(
            ca_acl,
            users_by_dn,
            groups_by_dn,
            computers_by_dn,
            services_by_dn,
            hostgroups_by_dn,
            users,
            computers,
            services,
        )
        ca_names = acl_ca_names(ca_acl, cas, cas_by_dn)

        for source_id in source_ids:
            for template in target_templates:
                key = (source_id, template.object_id, ca_acl.cn)
                if key in seen:
                    continue
                seen.add(key)
                edges.append(
                    Enroll(
                        start_id=source_id,
                        end_id=template.object_id,
                        ca_acl=ca_acl.cn,
                        user_category=ca_acl.user_category,
                        host_category=ca_acl.host_category,
                        service_category=ca_acl.service_category,
                        ca_category=ca_acl.ca_category,
                        cert_profile_category=ca_acl.cert_profile_category,
                        ca_names=ca_names,
                    )
                )
    return edges


def build_trusted_by_edges(
    environment: FreeIPAEnvironment,
    trusted_domains: list[IPATrustedDomain],
) -> list[TrustedBy]:
    return [
        TrustedBy(
            start_id=trusted_domain.object_id,
            end_id=environment.object_id,
            trust_direction=trusted_domain.trust_direction,
            trust_direction_label=trust_direction_label(trusted_domain.trust_direction),
            trust_type=trusted_domain.trust_type,
            trust_type_label=trust_type_label(trusted_domain.trust_type),
            trust_attributes=trusted_domain.trust_attributes,
        )
        for trusted_domain in trusted_domains
    ]


def build_dcsync_edges(
    environment: FreeIPAEnvironment,
    privileges: list[IPAPrivilege],
    permissions: list[IPAPermission],
) -> list[DCSync]:
    edges: list[DCSync] = []
    for privilege in privileges:
        if dcsync_source_name(privilege.cn):
            edges.append(
                DCSync(
                    start_id=privilege.object_id,
                    end_id=environment.object_id,
                    source_name=privilege.cn,
                    source_type="IPAPrivilege",
                )
            )
    for permission in permissions:
        if dcsync_source_name(permission.cn):
            edges.append(
                DCSync(
                    start_id=permission.object_id,
                    end_id=environment.object_id,
                    source_name=permission.cn,
                    source_type="IPAPermission",
                )
            )
    return edges


def dcsync_source_name(name: str) -> bool:
    return name.upper() in DCSYNC_SOURCE_NAMES


def acl_certificate_templates(
    ca_acl: CAACL,
    templates: list[IPACertificateTemplate],
    templates_by_dn: dict[str, IPACertificateTemplate],
) -> list[IPACertificateTemplate]:
    if ca_acl.member_profile_dns:
        return [
            template
            for template_dn in ca_acl.member_profile_dns
            for template in [templates_by_dn.get(template_dn)]
            if template is not None
        ]
    if ca_acl.cert_profile_category == "all":
        return templates
    return []


def acl_source_ids(
    ca_acl: CAACL,
    users_by_dn: dict[str, str],
    groups_by_dn: dict[str, str],
    computers_by_dn: dict[str, str],
    services_by_dn: dict[str, str],
    hostgroups_by_dn: dict[str, str],
    users: list[IPAUser],
    computers: list[IPAComputer],
    services: list[IPAService],
) -> list[str]:
    source_ids: list[str] = []
    source_ids.extend(resolve_dns(ca_acl.member_user_dns, users_by_dn, groups_by_dn))
    source_ids.extend(resolve_dns(ca_acl.member_host_dns, computers_by_dn, hostgroups_by_dn))
    source_ids.extend(resolve_dns(ca_acl.member_service_dns, services_by_dn))

    has_explicit_sources = bool(ca_acl.member_user_dns or ca_acl.member_host_dns or ca_acl.member_service_dns)
    if has_explicit_sources:
        return dedupe(source_ids)

    if ca_acl.user_category == "all":
        source_ids.extend(user.object_id for user in users)
    if ca_acl.host_category == "all":
        source_ids.extend(computer.object_id for computer in computers)
    if ca_acl.service_category == "all":
        source_ids.extend(service.object_id for service in services)

    return dedupe(source_ids)


def resolve_dns(dns: tuple[str, ...], *maps: dict[str, str]) -> list[str]:
    ids: list[str] = []
    for dn in dns:
        for mapping in maps:
            object_id = mapping.get(dn)
            if object_id is not None:
                ids.append(object_id)
                break
    return ids


def acl_ca_names(ca_acl: CAACL, cas: list[IPACA], cas_by_dn: dict[str, IPACA]) -> tuple[str, ...]:
    if ca_acl.member_ca_dns:
        return tuple(
            ca.name
            for ca_dn in ca_acl.member_ca_dns
            for ca in [cas_by_dn.get(ca_dn)]
            if ca is not None
        )
    if ca_acl.ca_category == "all" or not ca_acl.member_ca_dns:
        return tuple(ca.name for ca in cas)
    return ()


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def trust_direction_label(value: int | None) -> str | None:
    labels = {
        1: "Trusting forest",
        2: "Trusted forest",
        3: "Two-way trust",
    }
    return labels.get(value)


def trust_type_label(value: int | None) -> str | None:
    labels = {
        1: "Downlevel domain",
        2: "Active Directory domain",
        3: "MIT Kerberos realm",
    }
    return labels.get(value)


def build_hostgroup_memberof_edges(
    computers: list[IPAComputer],
    hostgroups: list[IPAHostGroup],
) -> list[MemberOf]:
    objects_by_dn = {computer.dn: computer.object_id for computer in computers}
    objects_by_dn.update({hostgroup.dn: hostgroup.object_id for hostgroup in hostgroups})

    edges: list[MemberOf] = []
    seen: set[tuple[str, str]] = set()
    for hostgroup in hostgroups:
        for member_dn in hostgroup.member_dns:
            start_id = objects_by_dn.get(member_dn)
            if not start_id:
                continue
            key = (start_id, hostgroup.object_id)
            if key in seen:
                continue
            seen.add(key)
            edges.append(MemberOf(start_id=start_id, end_id=hostgroup.object_id))
    return edges


def build_owns_edges(
    computers: list[IPAComputer],
    services: list[IPAService],
) -> list[Owns]:
    objects_by_dn = {computer.dn: computer.object_id for computer in computers}
    objects_by_dn.update({service.dn: service.object_id for service in services})

    edges: list[Owns] = []
    seen: set[tuple[str, str]] = set()
    for computer in computers:
        add_owns_edges(computer.managed_by_dns, computer.object_id, objects_by_dn, edges, seen)
    for service in services:
        add_owns_edges(service.managed_by_dns, service.object_id, objects_by_dn, edges, seen)
    return edges


def add_owns_edges(
    manager_dns: tuple[str, ...],
    managed_id: str,
    objects_by_dn: dict[str, str],
    edges: list[Owns],
    seen: set[tuple[str, str]],
) -> None:
    for manager_dn in manager_dns:
        manager_id = objects_by_dn.get(manager_dn)
        if not manager_id:
            continue
        if manager_id == managed_id:
            continue
        key = (manager_id, managed_id)
        if key in seen:
            continue
        seen.add(key)
        edges.append(Owns(start_id=manager_id, end_id=managed_id))


def build_allowed_to_delegate_edges(
    services: list[IPAService],
    delegation_rules: list[ServiceDelegationRule],
    delegation_targets: list[ServiceDelegationTarget],
) -> list[AllowedToDelegate]:
    services_by_principal = {service.principal.lower(): service for service in services}
    targets_by_dn = {target.dn: target for target in delegation_targets}

    edges: list[AllowedToDelegate] = []
    seen: set[tuple[str, str, str, str]] = set()

    for target_service in services:
        for source_principal in target_service.member_principals:
            source_service = services_by_principal.get(source_principal.lower())
            if source_service is None:
                continue
            key = (
                source_service.object_id,
                target_service.object_id,
                "resource-delegation",
                target_service.principal,
            )
            if key in seen:
                continue
            seen.add(key)
            edges.append(
                AllowedToDelegate(
                    start_id=source_service.object_id,
                    end_id=target_service.object_id,
                    rule="resource-delegation",
                    target=target_service.principal,
                )
            )

    for rule in delegation_rules:
        source_services = [
            service
            for principal in rule.member_principals
            for service in [services_by_principal.get(principal.lower())]
            if service is not None
        ]
        for target_dn in rule.target_dns:
            target = targets_by_dn.get(target_dn)
            if target is None:
                continue
            for source in source_services:
                for target_principal in target.member_principals:
                    target_service = services_by_principal.get(target_principal.lower())
                    if target_service is None:
                        continue
                    key = (source.object_id, target_service.object_id, rule.cn, target.cn)
                    if key in seen:
                        continue
                    seen.add(key)
                    edges.append(
                        AllowedToDelegate(
                            start_id=source.object_id,
                            end_id=target_service.object_id,
                            rule=rule.cn,
                            target=target.cn,
                        )
                    )
    return edges


def build_add_rbcd_edges(
    users: list[IPAUser],
    groups: list[IPAGroup],
    computers: list[IPAComputer],
    services: list[IPAService],
) -> list[AddRBCD]:
    objects_by_dn = {user.dn: user.object_id for user in users}
    objects_by_dn.update({group.dn: group.object_id for group in groups})
    objects_by_dn.update({computer.dn: computer.object_id for computer in computers})
    objects_by_dn.update({service.dn: service.object_id for service in services})

    edges: list[AddRBCD] = []
    seen: set[tuple[str, str]] = set()
    for service in services:
        for source_dn in service.write_delegation_dns:
            source_id = objects_by_dn.get(source_dn)
            if source_id is None:
                continue
            key = (source_id, service.object_id)
            if key in seen:
                continue
            seen.add(key)
            edges.append(AddRBCD(start_id=source_id, end_id=service.object_id))
    return edges


def build_force_change_password_edges(
    users: list[IPAUser],
    groups: list[IPAGroup],
    computers: list[IPAComputer],
    services: list[IPAService],
) -> list[ForceChangePassword]:
    objects_by_dn = {user.dn: user.object_id for user in users}
    objects_by_dn.update({group.dn: group.object_id for group in groups})
    objects_by_dn.update({computer.dn: computer.object_id for computer in computers})
    objects_by_dn.update({service.dn: service.object_id for service in services})

    edges: list[ForceChangePassword] = []
    seen: set[tuple[str, str]] = set()
    for service in services:
        for source_dn in service.write_key_dns:
            source_id = objects_by_dn.get(source_dn)
            if source_id is None:
                continue
            key = (source_id, service.object_id)
            if key in seen:
                continue
            seen.add(key)
            edges.append(ForceChangePassword(start_id=source_id, end_id=service.object_id))
    return edges


def build_read_kerberos_key_edges(
    users: list[IPAUser],
    groups: list[IPAGroup],
    computers: list[IPAComputer],
    services: list[IPAService],
) -> list[ReadKerberosKey]:
    objects_by_dn = {user.dn: user.object_id for user in users}
    objects_by_dn.update({group.dn: group.object_id for group in groups})
    objects_by_dn.update({computer.dn: computer.object_id for computer in computers})
    objects_by_dn.update({service.dn: service.object_id for service in services})

    edges: list[ReadKerberosKey] = []
    seen: set[tuple[str, str]] = set()
    for service in services:
        for source_dn in service.read_key_dns:
            source_id = objects_by_dn.get(source_dn)
            if source_id is None:
                continue
            key = (source_id, service.object_id)
            if key in seen:
                continue
            seen.add(key)
            edges.append(ReadKerberosKey(start_id=source_id, end_id=service.object_id))
    return edges


def build_can_ssh_edges(
    users: list[IPAUser],
    groups: list[IPAGroup],
    computers: list[IPAComputer],
    hostgroups: list[IPAHostGroup],
    hbac_rules: list[HBACRule],
) -> list[CanSSH]:
    users_by_dn = {user.dn: user for user in users}
    groups_by_dn = {group.dn: group for group in groups}
    computers_by_dn = {computer.dn: computer for computer in computers}
    hostgroups_by_dn = {hostgroup.dn: hostgroup for hostgroup in hostgroups}

    edges: list[CanSSH] = []
    seen: set[tuple[str, str, str]] = set()
    for rule in hbac_rules:
        if not rule.enabled or not hbac_rule_allows_service(rule, "sshd"):
            continue

        start_ids = hbac_principal_ids(rule, users, groups, users_by_dn, groups_by_dn)
        end_ids = hbac_host_ids(rule, computers, computers_by_dn, hostgroups_by_dn)
        for start_id in start_ids:
            for end_id in end_ids:
                key = (start_id, end_id, rule.cn)
                if key in seen:
                    continue
                seen.add(key)
                edges.append(CanSSH(start_id=start_id, end_id=end_id, rule=rule.cn))
    return edges


def build_can_hbac_service_edges(
    users: list[IPAUser],
    groups: list[IPAGroup],
    computers: list[IPAComputer],
    hostgroups: list[IPAHostGroup],
    hbac_rules: list[HBACRule],
    hbac_services: list[HBACService],
) -> list[CanHBACService]:
    users_by_dn = {user.dn: user for user in users}
    groups_by_dn = {group.dn: group for group in groups}
    computers_by_dn = {computer.dn: computer for computer in computers}
    hostgroups_by_dn = {hostgroup.dn: hostgroup for hostgroup in hostgroups}

    aggregated: dict[tuple[str, str], dict[str, set[str]]] = {}
    for rule in hbac_rules:
        if not rule.enabled:
            continue

        service_names = hbac_service_names_for_rule(rule, hbac_services)
        if not service_names:
            continue

        start_ids = hbac_principal_ids(rule, users, groups, users_by_dn, groups_by_dn)
        end_ids = hbac_host_ids(rule, computers, computers_by_dn, hostgroups_by_dn)
        for start_id in start_ids:
            for end_id in end_ids:
                edge_data = aggregated.setdefault(
                    (start_id, end_id),
                    {"services": set(), "hbac_rules": set(), "grant_details": set()},
                )
                for service in service_names:
                    edge_data["services"].add(service)
                    edge_data["hbac_rules"].add(rule.cn)
                    edge_data["grant_details"].add(f"{rule.cn}:{service}")

    return [
        CanHBACService(
            start_id=start_id,
            end_id=end_id,
            services=tuple(sorted(edge_data["services"], key=str.casefold)),
            hbac_rules=tuple(sorted(edge_data["hbac_rules"], key=str.casefold)),
            grant_details=tuple(sorted(edge_data["grant_details"], key=str.casefold)),
        )
        for (start_id, end_id), edge_data in sorted(aggregated.items())
    ]


def build_can_sudo_edges(
    users: list[IPAUser],
    groups: list[IPAGroup],
    computers: list[IPAComputer],
    hostgroups: list[IPAHostGroup],
    hbac_rules: list[HBACRule],
    sudo_rules: list[SudoRule],
    sudo_commands: list[SudoCommand],
) -> list[CanSUDO]:
    users_by_dn = {user.dn: user for user in users}
    groups_by_dn = {group.dn: group for group in groups}
    computers_by_dn = {computer.dn: computer for computer in computers}
    hostgroups_by_dn = {hostgroup.dn: hostgroup for hostgroup in hostgroups}
    commands_by_dn = {command.dn: command.command for command in sudo_commands}
    hbac_pairs = build_hbac_access_pairs(
        hbac_rules,
        users,
        groups,
        computers,
        hostgroups,
        services=("sudo", "sudo-i"),
    )

    edges: list[CanSUDO] = []
    seen: set[tuple[str, str, str]] = set()
    for rule in sudo_rules:
        if not rule.enabled:
            continue

        start_ids = hbac_principal_ids(rule, users, groups, users_by_dn, groups_by_dn)
        end_ids = hbac_host_ids(rule, computers, computers_by_dn, hostgroups_by_dn)
        commands = tuple(commands_by_dn[dn] for dn in rule.member_allow_command_dns if dn in commands_by_dn)
        no_password = any(option.lower() == "!authenticate" for option in rule.sudo_options)

        for start_id in start_ids:
            for end_id in end_ids:
                hbac_rule_names = hbac_pairs.get((start_id, end_id))
                if not hbac_rule_names:
                    continue
                key = (start_id, end_id, rule.cn)
                if key in seen:
                    continue
                seen.add(key)
                edges.append(
                    CanSUDO(
                        start_id=start_id,
                        end_id=end_id,
                        sudo_rule=rule.cn,
                        hbac_rules=tuple(sorted(hbac_rule_names)),
                        commands=commands,
                        command_category=rule.command_category,
                        runas_user_category=rule.runas_user_category,
                        runas_group_category=rule.runas_group_category,
                        no_password=no_password,
                    )
                )
    return edges


def build_hbac_access_pairs(
    hbac_rules: list[HBACRule],
    users: list[IPAUser],
    groups: list[IPAGroup],
    computers: list[IPAComputer],
    hostgroups: list[IPAHostGroup],
    services: tuple[str, ...],
) -> dict[tuple[str, str], set[str]]:
    users_by_dn = {user.dn: user for user in users}
    groups_by_dn = {group.dn: group for group in groups}
    computers_by_dn = {computer.dn: computer for computer in computers}
    hostgroups_by_dn = {hostgroup.dn: hostgroup for hostgroup in hostgroups}

    pairs: dict[tuple[str, str], set[str]] = {}
    for rule in hbac_rules:
        if not rule.enabled or not any(hbac_rule_allows_service(rule, service) for service in services):
            continue
        start_ids = hbac_principal_ids(rule, users, groups, users_by_dn, groups_by_dn)
        end_ids = hbac_host_ids(rule, computers, computers_by_dn, hostgroups_by_dn)
        for start_id in start_ids:
            for end_id in end_ids:
                pairs.setdefault((start_id, end_id), set()).add(rule.cn)
    return pairs


def hbac_rule_allows_service(rule: HBACRule, service_name: str) -> bool:
    if rule.service_category == "all":
        return True
    service_names = {first_rdn_value(dn).lower() for dn in rule.member_service_dns}
    return service_name.lower() in service_names


def hbac_service_names_for_rule(rule: HBACRule, hbac_services: list[HBACService]) -> tuple[str, ...]:
    names_by_key: dict[str, str] = {}
    if rule.service_category == "all":
        for service in hbac_services:
            if service.cn:
                names_by_key.setdefault(service.cn.casefold(), service.cn)
        if not names_by_key:
            names_by_key["all"] = "ALL"
    else:
        for dn in rule.member_service_dns:
            service = first_rdn_value(dn)
            if service:
                names_by_key.setdefault(service.casefold(), service)
    return tuple(names_by_key[key] for key in sorted(names_by_key))


def hbac_principal_ids(
    rule: HBACRule,
    users: list[IPAUser],
    groups: list[IPAGroup],
    users_by_dn: dict[str, IPAUser],
    groups_by_dn: dict[str, IPAGroup],
) -> list[str]:
    if rule.user_category == "all":
        return [user.object_id for user in users]

    principal_ids: list[str] = []
    for dn in rule.member_user_dns:
        user = users_by_dn.get(dn)
        if user is not None:
            principal_ids.append(user.object_id)
            continue
        group = groups_by_dn.get(dn)
        if group is not None:
            principal_ids.append(group.object_id)
    return principal_ids


def hbac_host_ids(
    rule: HBACRule,
    computers: list[IPAComputer],
    computers_by_dn: dict[str, IPAComputer],
    hostgroups_by_dn: dict[str, IPAHostGroup],
) -> list[str]:
    if rule.host_category == "all":
        return [computer.object_id for computer in computers]

    host_ids: list[str] = []
    for dn in rule.member_host_dns:
        host_ids.extend(expand_host_dn(dn, computers_by_dn, hostgroups_by_dn, seen=set()))
    return host_ids


def expand_host_dn(
    dn: str,
    computers_by_dn: dict[str, IPAComputer],
    hostgroups_by_dn: dict[str, IPAHostGroup],
    seen: set[str],
) -> list[str]:
    computer = computers_by_dn.get(dn)
    if computer is not None:
        return [computer.object_id]

    hostgroup = hostgroups_by_dn.get(dn)
    if hostgroup is None or hostgroup.dn in seen:
        return []

    seen.add(hostgroup.dn)
    host_ids: list[str] = []
    for member_dn in hostgroup.member_dns:
        host_ids.extend(expand_host_dn(member_dn, computers_by_dn, hostgroups_by_dn, seen))
    return host_ids


def stable_user_id(unique_id: str | None, dn: str) -> str:
    if unique_id:
        return f"freeipa:user:{unique_id}"
    digest = sha256(dn.encode("utf-8")).hexdigest()
    return f"freeipa:userdn:{digest}"


def stable_group_id(unique_id: str | None, dn: str) -> str:
    if unique_id:
        return f"freeipa:group:{unique_id}"
    digest = sha256(dn.encode("utf-8")).hexdigest()
    return f"freeipa:groupdn:{digest}"


def stable_role_id(unique_id: str | None, dn: str) -> str:
    if unique_id:
        return f"freeipa:role:{unique_id}"
    digest = sha256(dn.encode("utf-8")).hexdigest()
    return f"freeipa:roledn:{digest}"


def stable_privilege_id(unique_id: str | None, dn: str) -> str:
    if unique_id:
        return f"freeipa:privilege:{unique_id}"
    digest = sha256(dn.encode("utf-8")).hexdigest()
    return f"freeipa:privilegedn:{digest}"


def stable_permission_id(unique_id: str | None, dn: str) -> str:
    if unique_id:
        return f"freeipa:permission:{unique_id}"
    digest = sha256(dn.encode("utf-8")).hexdigest()
    return f"freeipa:permissiondn:{digest}"


def stable_ca_id(authority_id: str | None, dn: str) -> str:
    if authority_id:
        return f"freeipa:ca:{authority_id}"
    digest = sha256(dn.encode("utf-8")).hexdigest()
    return f"freeipa:cadn:{digest}"


def stable_certificate_template_id(cn: str | None, dn: str) -> str:
    if cn:
        return f"freeipa:certtemplate:{cn.lower()}"
    digest = sha256(dn.encode("utf-8")).hexdigest()
    return f"freeipa:certtemplatedn:{digest}"


def stable_selinux_user_map_id(unique_id: str | None, dn: str) -> str:
    if unique_id:
        return f"freeipa:selinux:{unique_id}"
    digest = sha256(dn.encode("utf-8")).hexdigest()
    return f"freeipa:selinuxdn:{digest}"


def stable_environment_id(domain: str) -> str:
    return f"freeipa:environment:{domain.lower()}"


def stable_trusted_domain_id(sid: str | None, domain: str | None, dn: str) -> str:
    if sid:
        return f"freeipa:trusteddomain:{sid}"
    if domain:
        return f"freeipa:trusteddomain:{domain.lower()}"
    digest = sha256(dn.encode("utf-8")).hexdigest()
    return f"freeipa:trusteddomaindn:{digest}"


def stable_computer_id(unique_id: str | None, dn: str) -> str:
    if unique_id:
        return f"freeipa:computer:{unique_id}"
    digest = sha256(dn.encode("utf-8")).hexdigest()
    return f"freeipa:computerdn:{digest}"


def stable_service_id(unique_id: str | None, dn: str) -> str:
    if unique_id:
        return f"freeipa:service:{unique_id}"
    digest = sha256(dn.encode("utf-8")).hexdigest()
    return f"freeipa:servicedn:{digest}"


def stable_hostgroup_id(unique_id: str | None, dn: str) -> str:
    if unique_id:
        return f"freeipa:hostgroup:{unique_id}"
    digest = sha256(dn.encode("utf-8")).hexdigest()
    return f"freeipa:hostgroupdn:{digest}"


def base_dn_to_realm(base_dn: str) -> str:
    labels = []
    for part in base_dn.split(","):
        key, _, value = part.partition("=")
        if key.strip().lower() == "dc" and value.strip():
            labels.append(value.strip())
    return ".".join(labels).upper()


def lower_keys(mapping: dict[str, Any]) -> dict[str, Any]:
    return {key.lower(): value for key, value in mapping.items()}


def lower_optional(value: str | None) -> str | None:
    if value is None:
        return None
    return value.lower()


def first_rdn_value(dn: str) -> str:
    first_part = dn.split(",", 1)[0]
    _, _, value = first_part.partition("=")
    return value


def split_service_principal(principal: str) -> tuple[str | None, str | None]:
    service_type, sep, remainder = principal.partition("/")
    if not sep:
        return None, None
    host_fqdn, _, _realm = remainder.partition("@")
    return service_type or None, host_fqdn.lower() if host_fqdn else None


def has_ticket_flag(ticket_flags: int | None, flag: int) -> bool:
    return bool(ticket_flags is not None and ticket_flags & flag)


def first(value: Any) -> str | None:
    vals = list(values(value))
    if not vals:
        return None
    return str(vals[0])


def values(value: Any) -> Iterator[Any]:
    if value is None:
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield item
    else:
        yield value


def parse_bool(value: str | None) -> bool:
    return bool(value and value.upper() == "TRUE")


def parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
