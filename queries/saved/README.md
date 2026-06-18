# OpenIPAHound Saved Queries

This starter pack includes path discovery queries, host-access support, research
views, node inventory, and object-browser utilities.

Use these queries to find interesting principals, groups, services, and hosts.
For a specific source-to-target question, select the returned objects in
BloodHound's Pathfinding tab and let BloodHound calculate paths over traversable
OpenIPAHound edges.

Research queries can return non-traversable edges. That is intentional: the data
is useful to inspect, but the relationship still needs service-specific
validation before it should become a normal pathfinding edge.

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

- `freeipa-utility-group-direct-members.json`
- `freeipa-utility-group-nested-members.json`
- `freeipa-utility-hostgroup-direct-members.json`
- `freeipa-utility-hostgroup-nested-members.json`
- `freeipa-utility-principal-outbound-control.json`
- `freeipa-utility-principal-effective-expansion.json`
- `freeipa-utility-object-inbound-control.json`
