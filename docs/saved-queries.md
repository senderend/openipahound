# Saved Queries

The starter pack keeps the first BloodHound workflow focused:

- host-admin path discovery
- AddMember-to-host-admin path discovery
- service key-control review
- FreeIPA server-admin path discovery
- host-access support views
- node inventory
- object-browser utilities for custom OpenGraph nodes
- research views over non-traversable relationships

Research views cover:

- RBCD/S4U delegation signals
- certificate/PKINIT enrollment signals
- managedBy object-control context
- AD trust and replication/DCSync context
- HBAC service/rule detail, excluding only `systemd-user`-only session-policy noise
- broad RBAC permission triage

Saved queries help find interesting principals, groups, services, and hosts.
For a specific source-to-target question, select the returned objects in
BloodHound's Pathfinding tab and let BloodHound calculate paths over traversable
OpenIPAHound edges. These saved queries are based on lab testing and may require adjustment to render the best results in your environment. Let them serve as a starting point.

Research queries can return graph paths that contain non-traversable edges.
That is deliberate: the data is useful to inspect, but the relationship still
needs service-specific validation before it should become a normal pathfinding
edge.

## Query List

Path discovery:

- `freeipa-host-admin-paths.json`: principals with both SSH and sudo access to a host.
- `freeipa-addmember-host-admin-paths.json`: AddMember control that can lead to SSH and sudo host access.
- `freeipa-service-key-control.json`: service key-control through read or rotate rights.
- `freeipa-server-admin-paths.json`: principals with SSH and sudo access to hosts that expose a collected LDAP service principal.

Support views:

- `freeipa-host-access-overview.json`: direct SSH and sudo access into hosts.
- `freeipa-ssh-and-sudo-same-principal.json`: principals that have both SSH and sudo on the same host.
- `freeipa-user-group-host-admin-paths.json`: users reaching host administration through group membership.
- `freeipa-node-kind-inventory.json`: imported OpenIPAHound node kinds for quick UI inspection.

Research views:

- `freeipa-research-delegation-signals.json`: non-traversable RBCD/S4U delegation signals.
- `freeipa-research-certificate-enrollment.json`: non-traversable certificate enrollment signals.
- `freeipa-research-managedby-control.json`: non-traversable managedBy control context.
- `freeipa-research-trust-replication.json`: non-traversable AD trust and replication context.
- `freeipa-research-hbac-service-detail.json`: non-traversable HBAC service/rule detail, excluding only `systemd-user`-only noise.
- `freeipa-research-rbac-permission-triage.json`: structural RBAC permission triage.

Object-browser utilities:

- `freeipa-utility-group-direct-members.json`: direct user and group members for FreeIPA groups.
- `freeipa-utility-group-nested-members.json`: nested user and group membership up to three hops.
- `freeipa-utility-hostgroup-direct-members.json`: direct host and hostgroup members for FreeIPA hostgroups.
- `freeipa-utility-hostgroup-nested-members.json`: nested host and hostgroup membership up to three hops.
- `freeipa-utility-principal-outbound-control.json`: direct outbound access and control edges from principals.
- `freeipa-utility-principal-effective-expansion.json`: membership and RBAC inheritance from principals.
- `freeipa-utility-object-inbound-control.json`: direct modeled control or access edges into FreeIPA objects.
