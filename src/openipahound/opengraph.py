from __future__ import annotations

from typing import Iterable

from openipahound.ldap import (
    AddMember,
    AddRBCD,
    CanHBACService,
    AllowedToDelegate,
    CanSSH,
    CanSUDO,
    ContainsPermission,
    DCSync,
    Enroll,
    ForceChangePassword,
    FreeIPAEnvironment,
    HasPrivilege,
    HasRole,
    IPACA,
    IPACertificateTemplate,
    IPAComputer,
    IPAGroup,
    IPAHostGroup,
    IPAPermission,
    IPAPrivilege,
    IPARole,
    IPASELinux,
    IPAService,
    IPATrustedDomain,
    IPAUser,
    MemberOf,
    Owns,
    ReadKerberosKey,
    TrustedBy,
)

SOURCE_KIND = "OpenIPAHound"
FREEIPAENVIRONMENT_KIND = "IPA_Environment"
IPAUSER_KIND = "IPA_User"
IPAGROUP_KIND = "IPA_Group"
IPAROLE_KIND = "IPA_Role"
IPAPRIVILEGE_KIND = "IPA_Privilege"
IPAPERMISSION_KIND = "IPA_Permission"
IPACA_KIND = "IPA_CA"
IPACERTIFICATETEMPLATE_KIND = "IPA_CertificateTemplate"
IPASELINUX_KIND = "IPA_SELinux"
IPATRUSTEDDOMAIN_KIND = "IPA_TrustedDomain"
IPACOMPUTER_KIND = "IPA_Computer"
IPASERVICE_KIND = "IPA_Service"
IPAHOSTGROUP_KIND = "IPA_HostGroup"
MEMBEROF_KIND = "IPA_MemberOf"
HASROLE_KIND = "IPA_HasRole"
HASPRIVILEGE_KIND = "IPA_HasPrivilege"
CONTAINSPERMISSION_KIND = "IPA_ContainsPermission"
ADDMEMBER_KIND = "IPA_AddMember"
OWNS_KIND = "IPA_Owns"
ALLOWEDTODELEGATE_KIND = "IPA_AllowedToDelegate"
ADDRBCD_KIND = "IPA_AddRBCD"
FORCECHANGEPASSWORD_KIND = "IPA_ForceChangePassword"
READKERBEROSKEY_KIND = "IPA_ReadKerberosKey"
ENROLL_KIND = "IPA_Enroll"
TRUSTEDBY_KIND = "IPA_TrustedBy"
DCSYNC_KIND = "IPA_DCSync"
CANSSH_KIND = "IPA_CanSSH"
CANHBACSERVICE_KIND = "IPA_CanHBACService"
CANSUDO_KIND = "IPA_CanSUDO"


def build_user_payload(users: Iterable[IPAUser]) -> dict:
    return build_payload(users=users)


def build_membership_payload(
    users: Iterable[IPAUser],
    groups: Iterable[IPAGroup],
    memberof_edges: Iterable[MemberOf],
) -> dict:
    return build_payload(users=users, groups=groups, memberof_edges=memberof_edges)


def build_add_member_payload(
    users: Iterable[IPAUser],
    groups: Iterable[IPAGroup],
    add_member_edges: Iterable[AddMember],
) -> dict:
    return build_payload(users=users, groups=groups, add_member_edges=add_member_edges)


def build_role_payload(
    users: Iterable[IPAUser],
    groups: Iterable[IPAGroup],
    roles: Iterable[IPARole],
    has_role_edges: Iterable[HasRole],
) -> dict:
    return build_payload(users=users, groups=groups, roles=roles, has_role_edges=has_role_edges)


def build_permission_payload(
    users: Iterable[IPAUser],
    groups: Iterable[IPAGroup],
    roles: Iterable[IPARole],
    services: Iterable[IPAService],
    hostgroups: Iterable[IPAHostGroup],
    privileges: Iterable[IPAPrivilege],
    permissions: Iterable[IPAPermission],
    has_privilege_edges: Iterable[HasPrivilege],
    contains_permission_edges: Iterable[ContainsPermission],
) -> dict:
    return build_payload(
        users=users,
        groups=groups,
        roles=roles,
        services=services,
        hostgroups=hostgroups,
        privileges=privileges,
        permissions=permissions,
        has_privilege_edges=has_privilege_edges,
        contains_permission_edges=contains_permission_edges,
    )


def build_certificate_payload(
    users: Iterable[IPAUser],
    groups: Iterable[IPAGroup],
    computers: Iterable[IPAComputer],
    services: Iterable[IPAService],
    hostgroups: Iterable[IPAHostGroup],
    cas: Iterable[IPACA],
    certificate_templates: Iterable[IPACertificateTemplate],
    enroll_edges: Iterable[Enroll],
) -> dict:
    return build_payload(
        users=users,
        groups=groups,
        computers=computers,
        services=services,
        hostgroups=hostgroups,
        cas=cas,
        certificate_templates=certificate_templates,
        enroll_edges=enroll_edges,
    )


def build_selinux_payload(selinux_user_maps: Iterable[IPASELinux]) -> dict:
    return build_payload(selinux_user_maps=selinux_user_maps)


def build_trust_payload(
    environment: FreeIPAEnvironment,
    trusted_domains: Iterable[IPATrustedDomain],
    trusted_by_edges: Iterable[TrustedBy],
) -> dict:
    return build_payload(
        environments=[environment],
        trusted_domains=trusted_domains,
        trusted_by_edges=trusted_by_edges,
    )


def build_dcsync_payload(
    environment: FreeIPAEnvironment,
    privileges: Iterable[IPAPrivilege],
    permissions: Iterable[IPAPermission],
    dcsync_edges: Iterable[DCSync],
) -> dict:
    return build_payload(
        environments=[environment],
        privileges=privileges,
        permissions=permissions,
        dcsync_edges=dcsync_edges,
    )


def build_computer_payload(computers: Iterable[IPAComputer]) -> dict:
    return build_payload(computers=computers)


def build_service_payload(services: Iterable[IPAService]) -> dict:
    return build_payload(services=services)


def build_owns_payload(
    computers: Iterable[IPAComputer],
    services: Iterable[IPAService],
    owns_edges: Iterable[Owns],
) -> dict:
    return build_payload(computers=computers, services=services, owns_edges=owns_edges)


def build_allowed_to_delegate_payload(
    services: Iterable[IPAService],
    allowed_to_delegate_edges: Iterable[AllowedToDelegate],
) -> dict:
    return build_payload(services=services, allowed_to_delegate_edges=allowed_to_delegate_edges)


def build_add_rbcd_payload(
    users: Iterable[IPAUser],
    groups: Iterable[IPAGroup],
    computers: Iterable[IPAComputer],
    services: Iterable[IPAService],
    add_rbcd_edges: Iterable[AddRBCD],
) -> dict:
    return build_payload(
        users=users,
        groups=groups,
        computers=computers,
        services=services,
        add_rbcd_edges=add_rbcd_edges,
    )


def build_force_change_password_payload(
    users: Iterable[IPAUser],
    groups: Iterable[IPAGroup],
    computers: Iterable[IPAComputer],
    services: Iterable[IPAService],
    force_change_password_edges: Iterable[ForceChangePassword],
) -> dict:
    return build_payload(
        users=users,
        groups=groups,
        computers=computers,
        services=services,
        force_change_password_edges=force_change_password_edges,
    )


def build_read_kerberos_key_payload(
    users: Iterable[IPAUser],
    groups: Iterable[IPAGroup],
    computers: Iterable[IPAComputer],
    services: Iterable[IPAService],
    read_kerberos_key_edges: Iterable[ReadKerberosKey],
) -> dict:
    return build_payload(
        users=users,
        groups=groups,
        computers=computers,
        services=services,
        read_kerberos_key_edges=read_kerberos_key_edges,
    )


def build_hostgroup_payload(
    computers: Iterable[IPAComputer],
    hostgroups: Iterable[IPAHostGroup],
    memberof_edges: Iterable[MemberOf],
) -> dict:
    return build_payload(computers=computers, hostgroups=hostgroups, memberof_edges=memberof_edges)


def build_can_ssh_payload(
    users: Iterable[IPAUser],
    groups: Iterable[IPAGroup],
    computers: Iterable[IPAComputer],
    memberof_edges: Iterable[MemberOf],
    can_ssh_edges: Iterable[CanSSH],
) -> dict:
    return build_payload(
        users=users,
        groups=groups,
        computers=computers,
        memberof_edges=memberof_edges,
        can_ssh_edges=can_ssh_edges,
    )


def build_can_hbac_service_payload(
    users: Iterable[IPAUser],
    groups: Iterable[IPAGroup],
    computers: Iterable[IPAComputer],
    memberof_edges: Iterable[MemberOf],
    can_hbac_service_edges: Iterable[CanHBACService],
) -> dict:
    return build_payload(
        users=users,
        groups=groups,
        computers=computers,
        memberof_edges=memberof_edges,
        can_hbac_service_edges=can_hbac_service_edges,
    )


def build_can_sudo_payload(
    users: Iterable[IPAUser],
    groups: Iterable[IPAGroup],
    computers: Iterable[IPAComputer],
    hostgroups: Iterable[IPAHostGroup],
    memberof_edges: Iterable[MemberOf],
    can_sudo_edges: Iterable[CanSUDO],
) -> dict:
    return build_payload(
        users=users,
        groups=groups,
        computers=computers,
        hostgroups=hostgroups,
        memberof_edges=memberof_edges,
        can_sudo_edges=can_sudo_edges,
    )


def build_payload(
    environments: Iterable[FreeIPAEnvironment] = (),
    users: Iterable[IPAUser] = (),
    groups: Iterable[IPAGroup] = (),
    roles: Iterable[IPARole] = (),
    privileges: Iterable[IPAPrivilege] = (),
    permissions: Iterable[IPAPermission] = (),
    cas: Iterable[IPACA] = (),
    certificate_templates: Iterable[IPACertificateTemplate] = (),
    selinux_user_maps: Iterable[IPASELinux] = (),
    trusted_domains: Iterable[IPATrustedDomain] = (),
    computers: Iterable[IPAComputer] = (),
    services: Iterable[IPAService] = (),
    hostgroups: Iterable[IPAHostGroup] = (),
    memberof_edges: Iterable[MemberOf] = (),
    has_role_edges: Iterable[HasRole] = (),
    has_privilege_edges: Iterable[HasPrivilege] = (),
    contains_permission_edges: Iterable[ContainsPermission] = (),
    add_member_edges: Iterable[AddMember] = (),
    owns_edges: Iterable[Owns] = (),
    allowed_to_delegate_edges: Iterable[AllowedToDelegate] = (),
    add_rbcd_edges: Iterable[AddRBCD] = (),
    force_change_password_edges: Iterable[ForceChangePassword] = (),
    read_kerberos_key_edges: Iterable[ReadKerberosKey] = (),
    enroll_edges: Iterable[Enroll] = (),
    trusted_by_edges: Iterable[TrustedBy] = (),
    dcsync_edges: Iterable[DCSync] = (),
    can_ssh_edges: Iterable[CanSSH] = (),
    can_hbac_service_edges: Iterable[CanHBACService] = (),
    can_sudo_edges: Iterable[CanSUDO] = (),
) -> dict:
    return {
        "metadata": {
            "source_kind": SOURCE_KIND,
        },
        "graph": {
            "nodes": [
                *[environment_to_node(environment) for environment in environments],
                *[user_to_node(user) for user in users],
                *[group_to_node(group) for group in groups],
                *[role_to_node(role) for role in roles],
                *[privilege_to_node(privilege) for privilege in privileges],
                *[permission_to_node(permission) for permission in permissions],
                *[ca_to_node(ca) for ca in cas],
                *[certificate_template_to_node(template) for template in certificate_templates],
                *[selinux_user_map_to_node(selinux_user_map) for selinux_user_map in selinux_user_maps],
                *[trusted_domain_to_node(trusted_domain) for trusted_domain in trusted_domains],
                *[computer_to_node(computer) for computer in computers],
                *[service_to_node(service) for service in services],
                *[hostgroup_to_node(hostgroup) for hostgroup in hostgroups],
            ],
            "edges": [
                *[member_of_to_edge(edge) for edge in memberof_edges],
                *[has_role_to_edge(edge) for edge in has_role_edges],
                *[has_privilege_to_edge(edge) for edge in has_privilege_edges],
                *[contains_permission_to_edge(edge) for edge in contains_permission_edges],
                *[add_member_to_edge(edge) for edge in add_member_edges],
                *[owns_to_edge(edge) for edge in owns_edges],
                *[allowed_to_delegate_to_edge(edge) for edge in allowed_to_delegate_edges],
                *[add_rbcd_to_edge(edge) for edge in add_rbcd_edges],
                *[force_change_password_to_edge(edge) for edge in force_change_password_edges],
                *[read_kerberos_key_to_edge(edge) for edge in read_kerberos_key_edges],
                *[enroll_to_edge(edge) for edge in enroll_edges],
                *[trusted_by_to_edge(edge) for edge in trusted_by_edges],
                *[dcsync_to_edge(edge) for edge in dcsync_edges],
                *[can_ssh_to_edge(edge) for edge in can_ssh_edges],
                *[can_hbac_service_to_edge(edge) for edge in can_hbac_service_edges],
                *[can_sudo_to_edge(edge) for edge in can_sudo_edges],
            ],
        },
    }


def environment_to_node(environment: FreeIPAEnvironment) -> dict:
    properties = compact_properties(
        {
            "name": environment.name,
            "displayname": environment.domain,
            "domain": environment.domain,
            "basedn": environment.base_dn,
            "krbauthzdata": list(environment.krb_authz_data) if environment.krb_authz_data else None,
            "configstrings": list(environment.config_strings) if environment.config_strings else None,
            "kdcconfigstrings": list(environment.kdc_config_strings) if environment.kdc_config_strings else None,
            "pacticketsigningsupported": environment.pac_ticket_signing_supported,
        }
    )
    return {
        "id": environment.object_id,
        "kinds": [FREEIPAENVIRONMENT_KIND],
        "properties": properties,
    }


def user_to_node(user: IPAUser) -> dict:
    properties = compact_properties(
        {
            "name": user.name,
            "displayname": user.display_name or user.uid,
            "uid": user.uid,
            "principal": user.principal,
            "canonicalprincipal": user.canonical_principal,
            "sid": user.sid,
            "distinguishedname": user.dn,
            "email": user.email,
            "givenname": user.given_name,
            "surname": user.surname,
            "disabled": user.disabled,
            "passwordauthallow": user.password_auth_allow,
            "uidnumber": user.uid_number,
            "gidnumber": user.gid_number,
            "homedirectory": user.home_directory,
            "loginshell": user.login_shell,
        }
    )
    return {
        "id": user.object_id,
        "kinds": [IPAUSER_KIND],
        "properties": properties,
    }


def group_to_node(group: IPAGroup) -> dict:
    properties = compact_properties(
        {
            "name": group.name,
            "displayname": group.cn,
            "cn": group.cn,
            "distinguishedname": group.dn,
            "description": group.description,
            "gidnumber": group.gid_number,
            "sid": group.sid,
        }
    )
    return {
        "id": group.object_id,
        "kinds": [IPAGROUP_KIND],
        "properties": properties,
    }


def role_to_node(role: IPARole) -> dict:
    properties = compact_properties(
        {
            "name": role.name,
            "displayname": role.cn,
            "cn": role.cn,
            "distinguishedname": role.dn,
            "description": role.description,
        }
    )
    return {
        "id": role.object_id,
        "kinds": [IPAROLE_KIND],
        "properties": properties,
    }


def privilege_to_node(privilege: IPAPrivilege) -> dict:
    properties = compact_properties(
        {
            "name": privilege.name,
            "displayname": privilege.cn,
            "cn": privilege.cn,
            "distinguishedname": privilege.dn,
            "description": privilege.description,
        }
    )
    return {
        "id": privilege.object_id,
        "kinds": [IPAPRIVILEGE_KIND],
        "properties": properties,
    }


def permission_to_node(permission: IPAPermission) -> dict:
    properties = compact_properties(
        {
            "name": permission.name,
            "displayname": permission.cn,
            "cn": permission.cn,
            "distinguishedname": permission.dn,
            "description": permission.description,
            "rights": list(permission.rights) if permission.rights else None,
            "target": permission.target,
            "targetfilters": list(permission.target_filters) if permission.target_filters else None,
        }
    )
    return {
        "id": permission.object_id,
        "kinds": [IPAPERMISSION_KIND],
        "properties": properties,
    }


def ca_to_node(ca: IPACA) -> dict:
    properties = compact_properties(
        {
            "name": ca.name,
            "displayname": ca.cn,
            "cn": ca.cn,
            "distinguishedname": ca.dn,
            "description": ca.description,
            "authorityid": ca.authority_id,
            "subjectdn": ca.subject_dn,
            "issuerdn": ca.issuer_dn,
        }
    )
    return {
        "id": ca.object_id,
        "kinds": [IPACA_KIND],
        "properties": properties,
    }


def certificate_template_to_node(template: IPACertificateTemplate) -> dict:
    properties = compact_properties(
        {
            "name": template.name,
            "displayname": template.cn,
            "cn": template.cn,
            "distinguishedname": template.dn,
            "description": template.description,
            "storeissued": template.store_issued,
        }
    )
    return {
        "id": template.object_id,
        "kinds": [IPACERTIFICATETEMPLATE_KIND],
        "properties": properties,
    }


def selinux_user_map_to_node(selinux_user_map: IPASELinux) -> dict:
    properties = compact_properties(
        {
            "name": selinux_user_map.name,
            "displayname": selinux_user_map.cn,
            "cn": selinux_user_map.cn,
            "distinguishedname": selinux_user_map.dn,
            "description": selinux_user_map.description,
            "enabled": selinux_user_map.enabled,
            "selinuxuser": selinux_user_map.selinux_user,
            "usercategory": selinux_user_map.user_category,
            "hostcategory": selinux_user_map.host_category,
            "memberusers": list(selinux_user_map.member_user_dns) if selinux_user_map.member_user_dns else None,
            "memberhosts": list(selinux_user_map.member_host_dns) if selinux_user_map.member_host_dns else None,
            "hbacrules": list(selinux_user_map.hbac_rule_dns) if selinux_user_map.hbac_rule_dns else None,
        }
    )
    return {
        "id": selinux_user_map.object_id,
        "kinds": [IPASELINUX_KIND],
        "properties": properties,
    }


def trusted_domain_to_node(trusted_domain: IPATrustedDomain) -> dict:
    properties = compact_properties(
        {
            "name": trusted_domain.name,
            "displayname": trusted_domain.domain,
            "domain": trusted_domain.domain,
            "flatname": trusted_domain.flat_name,
            "distinguishedname": trusted_domain.dn,
            "trusteddomainsid": trusted_domain.trusted_domain_sid,
            "trustaccountsid": trusted_domain.trust_account_sid,
            "sidblacklistincoming": list(trusted_domain.sid_blacklist_incoming)
            if trusted_domain.sid_blacklist_incoming
            else None,
            "sidblacklistoutgoing": list(trusted_domain.sid_blacklist_outgoing)
            if trusted_domain.sid_blacklist_outgoing
            else None,
            "trustpartner": trusted_domain.trust_partner,
            "trustdirection": trusted_domain.trust_direction,
            "trusttype": trusted_domain.trust_type,
            "trustattributes": trusted_domain.trust_attributes,
            "supportedencryptiontypes": trusted_domain.supported_encryption_types,
            "posixoffset": trusted_domain.posix_offset,
            "gidnumber": trusted_domain.gid_number,
            "uidnumber": trusted_domain.uid_number,
        }
    )
    return {
        "id": trusted_domain.object_id,
        "kinds": [IPATRUSTEDDOMAIN_KIND],
        "properties": properties,
    }


def computer_to_node(computer: IPAComputer) -> dict:
    properties = compact_properties(
        {
            "name": computer.name,
            "displayname": computer.fqdn,
            "fqdn": computer.fqdn,
            "principal": computer.principal,
            "canonicalprincipal": computer.canonical_principal,
            "sid": computer.sid,
            "distinguishedname": computer.dn,
            "description": computer.description,
        }
    )
    return {
        "id": computer.object_id,
        "kinds": [IPACOMPUTER_KIND],
        "properties": properties,
    }


def service_to_node(service: IPAService) -> dict:
    properties = compact_properties(
        {
            "name": service.name,
            "displayname": service.principal,
            "principal": service.principal,
            "canonicalprincipal": service.canonical_principal,
            "servicetype": service.service_type,
            "hostfqdn": service.host_fqdn,
            "distinguishedname": service.dn,
            "aliases": list(service.aliases) if service.aliases else None,
            "managedby": list(service.managed_by_dns) if service.managed_by_dns else None,
            "delegationprincipals": list(service.member_principals) if service.member_principals else None,
            "krbticketflags": service.ticket_flags,
            "unconstraineddelegation": service.unconstrained_delegation,
            "oktoauthasdelegate": service.ok_to_auth_as_delegate,
        }
    )
    return {
        "id": service.object_id,
        "kinds": [IPASERVICE_KIND],
        "properties": properties,
    }


def hostgroup_to_node(hostgroup: IPAHostGroup) -> dict:
    properties = compact_properties(
        {
            "name": hostgroup.name,
            "displayname": hostgroup.cn,
            "cn": hostgroup.cn,
            "distinguishedname": hostgroup.dn,
            "description": hostgroup.description,
        }
    )
    return {
        "id": hostgroup.object_id,
        "kinds": [IPAHOSTGROUP_KIND],
        "properties": properties,
    }


def member_of_to_edge(edge: MemberOf) -> dict:
    return {
        "kind": MEMBEROF_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": {
            "relationship": "MemberOf",
        },
    }


def has_role_to_edge(edge: HasRole) -> dict:
    return {
        "kind": HASROLE_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": {
            "relationship": "HasRole",
            "sourceattribute": "member",
            "derivedfrom": "FreeIPA role membership/memberOf",
        },
    }


def has_privilege_to_edge(edge: HasPrivilege) -> dict:
    return {
        "kind": HASPRIVILEGE_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": {
            "relationship": "HasPrivilege",
            "sourceattribute": "member",
            "derivedfrom": "FreeIPA privilege membership/memberOf",
        },
    }


def contains_permission_to_edge(edge: ContainsPermission) -> dict:
    return {
        "kind": CONTAINSPERMISSION_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": {
            "relationship": "ContainsPermission",
            "sourceattribute": "member",
            "derivedfrom": "FreeIPA permission membership/memberOf",
        },
    }


def add_member_to_edge(edge: AddMember) -> dict:
    return {
        "kind": ADDMEMBER_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": {
            "relationship": "AddMember",
            "sourceattribute": edge.source_attribute,
        },
    }


def owns_to_edge(edge: Owns) -> dict:
    return {
        "kind": OWNS_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": {
            "relationship": "Owns",
            "sourceattribute": edge.source_attribute,
        },
    }


def allowed_to_delegate_to_edge(edge: AllowedToDelegate) -> dict:
    return {
        "kind": ALLOWEDTODELEGATE_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": {
            "relationship": "AllowedToDelegate",
            "delegationrule": edge.rule,
            "delegationtarget": edge.target,
        },
    }


def add_rbcd_to_edge(edge: AddRBCD) -> dict:
    return {
        "kind": ADDRBCD_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": {
            "relationship": "AddRBCD",
            "sourceattribute": edge.source_attribute,
        },
    }


def force_change_password_to_edge(edge: ForceChangePassword) -> dict:
    return {
        "kind": FORCECHANGEPASSWORD_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": {
            "relationship": "ForceChangePassword",
            "sourceattribute": edge.source_attribute,
        },
    }


def read_kerberos_key_to_edge(edge: ReadKerberosKey) -> dict:
    return {
        "kind": READKERBEROSKEY_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": {
            "relationship": "ReadKerberosKey",
            "sourceattribute": edge.source_attribute,
        },
    }


def enroll_to_edge(edge: Enroll) -> dict:
    properties = compact_properties(
        {
            "relationship": "Enroll",
            "caacl": edge.ca_acl,
            "usercategory": edge.user_category,
            "hostcategory": edge.host_category,
            "servicecategory": edge.service_category,
            "cacategory": edge.ca_category,
            "certprofilecategory": edge.cert_profile_category,
            "cas": list(edge.ca_names) if edge.ca_names else None,
        }
    )
    return {
        "kind": ENROLL_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": properties,
    }


def trusted_by_to_edge(edge: TrustedBy) -> dict:
    properties = compact_properties(
        {
            "relationship": "TrustedBy",
            "trustdirection": edge.trust_direction,
            "trustdirectionlabel": edge.trust_direction_label,
            "trusttype": edge.trust_type,
            "trusttypelabel": edge.trust_type_label,
            "trustattributes": edge.trust_attributes,
        }
    )
    return {
        "kind": TRUSTEDBY_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": properties,
    }


def dcsync_to_edge(edge: DCSync) -> dict:
    properties = compact_properties(
        {
            "relationship": "DCSync",
            "sourcename": edge.source_name,
            "sourcetype": edge.source_type,
            "inferredfrom": "default replication permissions",
        }
    )
    return {
        "kind": DCSYNC_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": properties,
    }


def can_ssh_to_edge(edge: CanSSH) -> dict:
    return {
        "kind": CANSSH_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": {
            "relationship": "CanSSH",
            "hbacrule": edge.rule,
            "service": "sshd",
        },
    }


def can_hbac_service_to_edge(edge: CanHBACService) -> dict:
    return {
        "kind": CANHBACSERVICE_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": {
            "relationship": "CanHBACService",
            "relationships": [hbac_service_relationship(service) for service in edge.services],
            "services": list(edge.services),
            "hbacrules": list(edge.hbac_rules),
            "grants": list(edge.grant_details),
            "servicecount": len(edge.services),
            "rulecount": len(edge.hbac_rules),
        },
    }


def can_sudo_to_edge(edge: CanSUDO) -> dict:
    properties = compact_properties(
        {
            "relationship": "CanSUDO",
            "sudorule": edge.sudo_rule,
            "hbacrules": list(edge.hbac_rules),
            "commands": list(edge.commands) if edge.commands else None,
            "cmdcategory": edge.command_category,
            "runasusercategory": edge.runas_user_category,
            "runasgroupcategory": edge.runas_group_category,
            "nopassword": edge.no_password,
        }
    )
    return {
        "kind": CANSUDO_KIND,
        "start": {
            "match_by": "id",
            "value": edge.start_id,
        },
        "end": {
            "match_by": "id",
            "value": edge.end_id,
        },
        "properties": properties,
    }


def compact_properties(properties: dict) -> dict:
    return {key: value for key, value in properties.items() if value is not None}


def hbac_service_relationship(service: str) -> str:
    raw = service.strip()
    normalized = "".join(character for character in raw if character.isalnum())
    if not normalized:
        return "CanHBACService"
    known = {
        "all": "ALL",
        "crond": "Crond",
        "ftp": "FTP",
        "gdm": "GDM",
        "gdm-password": "GDMPassword",
        "gssftp": "GSSFTP",
        "kdm": "KDM",
        "login": "Login",
        "proftpd": "ProFTPD",
        "pure-ftpd": "PureFTPD",
        "ssh": "SSH",
        "sshd": "SSH",
        "su": "SU",
        "su-l": "SUL",
        "sudo": "SUDO",
        "sudo-i": "SUDOI",
        "systemd-user": "SystemdUser",
        "vsftpd": "VSFTPD",
        "dns": "DNS",
        "http": "HTTP",
        "https": "HTTPS",
        "imap": "IMAP",
        "ldap": "LDAP",
        "ldaps": "LDAPS",
        "nfs": "NFS",
        "ntp": "NTP",
        "smtp": "SMTP",
    }
    known_name = known.get(raw.casefold())
    if known_name is not None:
        return f"Can{known_name}"

    chunks: list[str] = []
    current = ""
    for character in raw:
        if character.isalnum():
            current += character
        elif current:
            chunks.append(current)
            current = ""
    if current:
        chunks.append(current)

    if not chunks:
        chunks = [normalized]

    label_parts = []
    for chunk in chunks:
        known_chunk = known.get(chunk.casefold())
        if known_chunk is not None:
            label_parts.append(known_chunk)
        else:
            label_parts.append(chunk[:1].upper() + chunk[1:].lower())
    return f"Can{''.join(label_parts)}"
