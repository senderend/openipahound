# Authentication

OpenIPAHound can bind with a simple LDAP account or use an existing Kerberos
ticket cache. The account you use determines which FreeIPA objects and
attributes the collector can see.

## Password Auth

Password auth is the most direct first run:

```bash
openipahound collect ipa.example.test -d example.test -u openipahound-reader -p -o ./out
```

`-p` with no value prompts for the password. You can pass a value with
`-p 'password'`, but that can expose the secret in shell history or process
logs. Password auth uses LDAPS by default. Avoid `--no-ssl` unless you are in a
trusted test environment and understand that the bind is not protected by TLS.

The password-auth target can be a hostname or IP address. Hostnames are still
the cleanest choice when your LDAPS setup enforces certificate name checks.

## Kerberos Auth

If you already have a Kerberos ticket cache:

```bash
kinit openipahound-reader
openipahound collect ipa.example.test -d example.test -k -o ./out
```

Use a hostname for Kerberos/GSSAPI collection. Kerberos service tickets are
normally issued for the LDAP service name on the FreeIPA host, not for a raw IP
address. The hostname must resolve from the collector machine through DNS or
`/etc/hosts`.

## Env Files

The env file is optional. It exists for repeatable runs, scheduled collection,
and operators who do not want to paste the same target settings every time.
Direct CLI flags override env-file values.

```bash
openipahound collect --env-file ./freeipa.env -p -o ./out
```

If the env file includes `IPA_COLLECTOR_PASSWORD` or `IPA_ADMIN_PASSWORD`, omit
`-p` to run non-interactively.

## Collection Visibility

The most complete collection requires an admin or read-capable identity that can
read FreeIPA users, groups, hosts, hostgroups, services, HBAC rules, sudo rules,
and service key-control attributes.

A lower-privilege collector may still produce useful nodes and membership, but
some edges can be incomplete. In particular, service key-control, delegation
flags, and privileged service attributes may require more visibility.

Use `examples/env.example` as a starting point for repeatable runs and keep real
secrets out of git.
