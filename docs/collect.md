# Collect

The default command writes OpenGraph JSON payload files to a directory you
choose:

```bash
openipahound collect ipa.example.test -d example.test -u openipahound-reader -p -o ./out
```

The collect target can be a hostname or an IP address:

```bash
openipahound collect 10.0.0.10 -d example.test -u openipahound-reader -p -o ./out
```

`-d` is the FreeIPA domain used to derive the LDAP base DN. If you do not want
to provide a domain, pass the base DN directly:

```bash
openipahound collect 10.0.0.10 --base-dn dc=example,dc=test -u openipahound-reader -p -o ./out
```

Use a hostname for Kerberos/GSSAPI collection. Kerberos service tickets are
normally issued for the LDAP service name on the FreeIPA host, not for a raw IP
address. The hostname must resolve from the collector machine through DNS or
`/etc/hosts`. Hostnames are also the cleanest path when your LDAPS setup
enforces certificate name checks. See [authentication.md](authentication.md) for
auth behavior and collector visibility.

`-p` without a value prompts for the password, which avoids putting the password
in shell history. To pass all settings non-interactively, use an env file:

```bash
openipahound collect --env-file ./freeipa.env -p -o ./out
```

If you add `IPA_COLLECTOR_PASSWORD` or `IPA_ADMIN_PASSWORD` to the env file, omit
`-p` for non-interactive collection.

Use modules when you want less data:

```bash
openipahound collect --env-file ./freeipa.env -p -c all -o ./out
openipahound collect ipa.example.test -d example.test -u openipahound-reader -p --only users,groups,computers -o ./out
openipahound collect --env-file ./freeipa.env -p --only identity,hosts,host-access -o ./out
openipahound collect --env-file ./freeipa.env -p --exclude hbac-services,replication -o ./out
openipahound collect --list-modules
```

Default modules collect the core graph: graph foundation, host access,
AddMember, and Kerberos key/service identity control.

`-c all` collects every product module, including additional research modules.

Research modules are available for deeper inspection, but their relationships
are not default pathfinding edges: RBCD/S4U delegation, certificates/PKINIT,
managedBy, replication/DCSync, AD trust, HBAC service detail, SELinux maps, and
broad RBAC triage. The saved-query pack includes research views for the main
non-traversable graph areas.

Validate output before upload:

```bash
openipahound validate ./out
```

## Common Flags

| Option | Purpose |
| --- | --- |
| `collect ipa.example.test` | FreeIPA LDAP server target, as a hostname or IP address. |
| `-d`, `--domain` | FreeIPA domain; used to derive the base DN. |
| `-u`, `--user`, `--username` | LDAP username or bind DN. |
| `-p`, `--password` | LDAP password; omit the value to prompt. |
| `-k`, `--kerberos` | Use the current Kerberos ticket cache. |
| `-o`, `--output-dir` | Output directory for OpenGraph JSON files. |
| `-c`, `--only` | Collect only selected modules or aliases. |

## Advanced Flags

| Option | Purpose |
| --- | --- |
| `--env-file` | Load repeatable settings from a shell-style env file. |
| `--server` | FreeIPA LDAP server hostname or IP, for scripts that cannot use the positional target. |
| `--base-dn` | Explicit LDAP base DN. |
| `--auth` | Choose `password` or `kerberos` auth explicitly. |
| `--credential-profile` | Choose the `collector` or `admin` env-file credential profile. |
| `--exclude` | Exclude selected modules or aliases. |
| `--list-modules` | Show available modules. |
| `--compact` | Write compact JSON payload files. |
| `--schema-file` | Use a non-packaged schema for validation or schema export. |
