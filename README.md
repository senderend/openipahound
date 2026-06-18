# OpenIPAHound

OpenIPAHound is a FreeIPA collector and structured BloodHound OpenGraph
extension. It collects FreeIPA identity, host, group, HBAC, sudo, RBAC, service
principal, and policy relationships, then writes OpenGraph JSON payloads for
upload into BloodHound.

## Overview

OpenIPAHound models FreeIPA as a structured graph so FreeIPA objects can be
searched, queried with Cypher, and included in BloodHound Pathfinding where the
relationship is configured as traversable. The included schema defines FreeIPA
node kinds, relationship kinds, display metadata, and traversal behavior.

Traversable relationships cover the primary FreeIPA control and access paths:

- group and hostgroup membership
- role, privilege, and permission expansion
- group `memberManager` AddMember control
- SSH host access
- sudo host administration
- service identity control through key retrieval
- service identity control through key creation or rotation

OpenIPAHound also collects non-traversable research relationships for delegation,
certificates, managedBy, trust and replication context, HBAC service detail,
SELinux maps, and RBAC permission triage. These relationships are visible for
review and Cypher analysis, and are backed by LDAP-readable FreeIPA directory
objects and attributes, but they are not default pathfinding edges. See
[Research Areas](#research-areas) for the follow-up edge families.

## Requirements

- Python 3.10 or newer
- Network access from the collector host to FreeIPA LDAP or LDAPS
- A FreeIPA account with enough read visibility for the modules you run
- BloodHound with OpenGraph support for schema installation and JSON upload

Kerberos collection also requires local GSSAPI/Kerberos support and a resolvable
FreeIPA hostname.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install .
```

Install Kerberos extras when you want to collect with an existing ticket cache:

```bash
python -m pip install '.[kerberos]'
```

## Collect Data

Password authentication:

```bash
openipahound collect ipa.example.test -d example.test -u openipahound-reader -p -o ./out
```

`-p` without a value prompts for the LDAP password.

Kerberos authentication:

```bash
kinit openipahound-reader@EXAMPLE.TEST
openipahound collect ipa.example.test -d example.test -k -o ./out
```

Repeatable env-file collection:

```bash
openipahound collect --env-file ./freeipa.env -p -o ./out
```

Collect all modules:

```bash
openipahound collect ipa.example.test -d example.test -u openipahound-reader -p -c all -o ./out
```

Collect selected modules:

```bash
openipahound collect ipa.example.test -d example.test -u openipahound-reader -p --only users,groups,computers -o ./out
```

Exclude selected modules:

```bash
openipahound collect ipa.example.test -d example.test -u openipahound-reader -p --exclude hbac-services,replication -o ./out
```

List available modules:

```bash
openipahound collect --list-modules
```

`-c` is an alias for `--only`; `-c all` collects every module.

Validate the output once collection finishes:

```bash
openipahound validate ./out
```

See [collect.md](docs/collect.md) for the complete command reference.

## Authentication

OpenIPAHound supports LDAP password authentication and Kerberos/GSSAPI
authentication.

Password authentication can target either a FreeIPA hostname or an IP address:

```bash
openipahound collect 10.0.0.10 -d example.test -u openipahound-reader -p -o ./out
```

Kerberos authentication should use a hostname because service tickets are issued
for the LDAP service principal on the FreeIPA host:

```bash
openipahound collect ipa.example.test -d example.test -k -o ./out
```

The account used for collection controls what OpenIPAHound can see. Lower
privilege collection can still produce useful identity and membership data, but
missing service-key, delegation, or privileged attribute edges should be treated
as unknown rather than absent.

See [authentication.md](docs/authentication.md) for target, credential, and
visibility details.

## BloodHound Upload

Install `openipahound-extension.json` as an OpenGraph extension schema, then
upload the JSON payload files from your output directory with the BloodHound file
upload UI.

The schema is included as a file at the package root. You can also regenerate it
from the installed package:

```bash
openipahound schema export > openipahound-extension.json
```

Suggested workflow:

1. Install OpenIPAHound.
2. Run `openipahound collect`.
3. Run `openipahound validate ./out`.
4. Install or update `openipahound-extension.json` in BloodHound.
5. Upload the generated JSON files.
6. Import the saved-query pack from `queries/saved/` if you want the bundled
   Cypher views.

Saved queries are separate from graph data. If you remove OpenIPAHound data or
uninstall the schema, remove OpenIPAHound saved queries separately from the
Saved Queries UI. See [upload-to-bloodhound.md](docs/upload-to-bloodhound.md).

## Saved Queries

The saved-query pack provides starting points for:

- host access and server administration paths
- AddMember paths into useful groups
- service key-control review
- node inventory and object browsing
- non-traversable research relationship review

Use saved queries to identify interesting principals, groups, services, and
hosts. Use BloodHound Pathfinding for the source-to-target path question.

See [saved-queries.md](docs/saved-queries.md) for the full list.

## Edge Documentation

[nodes-and-edges.md](docs/nodes-and-edges.md) documents the FreeIPA node and
relationship model, including source data, pathfinding rationale, known limits,
and abuse info for validated edge families:

- SSH plus sudo host administration
- AddMember into inherited host access
- service identity control through key retrieval
- service identity control through key creation or rotation
- RBAC chain inspection

Graph data is a map of policy and directory state. Validate important paths in
your own environment, especially when host reachability, SSSD cache state, sudo
password prompts, service key state, or protocol-specific behavior can change
the result.

## Research Areas

OpenIPAHound includes non-traversable research edges for:

- RBCD/S4U delegation
- PKINIT and service certificates
- managedBy object control
- DCSync/IPASync and key-material reuse
- AD trust paths
- non-SSH/non-sudo HBAC services
- FreeIPA permission-specific LDAP write behavior

These areas are not placeholders, they're backed by LDAP-readable FreeIPA
directory objects and attributes. Several have promising tradecraft
paths; future research will flesh these out with tradecraft discovery, attacker validation, and abuse info.

## License

OpenIPAHound is licensed under the Apache License, Version 2.0. See
[LICENSE](LICENSE).

## Credits

A big shoutout to PT SWARM for their FreeIPA attack-path research and the
original [IPAHound](https://github.com/IPAHound/IPAHound) implementation. While their
work served as an inspiration, reference, and guide to bring FreeIPA support to OpenGraph, no code was reused or ported from their project. Check out their excellent blog [here](https://swarm.ptsecurity.com/thinking-in-graphs-with-ipahound/)
