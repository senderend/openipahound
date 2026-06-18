# Research Areas

OpenIPAHound collects several FreeIPA relationship families from LDAP-readable
FreeIPA directory objects and attributes. They are useful for review today, but
are intentionally non-traversable in the default schema. These areas have enough
directory evidence to preserve in the graph and enough operator value to include
in saved-query views. Future releases can promote narrower relationships after
the source data, path composition, and tradecraft are stable.

## Current Review Data

The collector and saved-query pack expose review surfaces for:

- RBCD and S4U delegation signals
- certificate enrollment and PKINIT-related context
- `managedBy` ownership context
- replication-control and DCSync/IPASync context
- FreeIPA-to-AD trust context
- HBAC service and rule detail beyond SSH and sudo
- RBAC role, privilege, and permission triage

These relationships are available for Cypher, saved queries, and object review.
They are not included in normal pathfinding unless the schema marks the
relationship as traversable.

That boundary matters: OpenIPAHound records the relevant directory fact, not the
entire target-use workflow. For example, a delegation edge preserves delegation
directory state, a certificate edge preserves CA ACL/profile scope, and a
replication edge preserves replication-control context. Future pathfinding
promotion should happen only after the operator workflow is narrow and
reproducible.

## Why They Stay Non-Traversable

The advanced FreeIPA areas do not all collapse into a single "control" edge.
For example, target-side delegation writes are different from source service
identity control, certificate enrollment is different from a working PKINIT
login, and a permission name is not always enough to prove the affected object,
right, target, filter, or exclusion.

OpenIPAHound keeps this data visible without turning it into default pathfinding
until each promoted relationship can answer:

- What exact FreeIPA source object or attribute produced the edge?
- What action does the relationship actually allow?
- What additional identity, service, key, certificate, or host state is needed?
- What command path demonstrates the result?
- What cleanup or side effect exists?
- Does the relationship compose cleanly with the rest of the graph?

## Follow-Up Lanes

Delegation and S4U: preserve `IPA_AllowedToDelegate` and `IPA_AddRBCD` as review
signals while future work separates general constrained delegation, target-side
resource delegation, source service identity control, and real target use.

Certificates and PKINIT: preserve CA and certificate enrollment context while
future work ties CA ACLs, request-certificate rights, service ownership, and
certificate authentication into narrower path shapes.

managedBy: preserve ownership context while future work separates host ownership
from service ownership and proves which managed objects yield usable identity
material.

Replication and key material: preserve DCSync/IPASync context as high-impact
review data while future work hardens the tradecraft around replicated key
material, keytab conversion, redaction, and repeatable operator handling.

AD trust: preserve trust context while future work joins FreeIPA trust data with
native AD collection and verifies which cross-realm identities produce host or
service impact.

HBAC services: preserve aggregate service/rule detail while future work decides
which non-SSH/non-sudo services deserve their own action-specific paths.

RBAC action modeling: preserve the role to privilege to permission chain while
future work classifies specific permission families such as user lifecycle,
password, SSH key, Kerberos principal, certificate, host, and service control.

## Promotion Criteria

A research relationship should become a default pathfinding edge only when it is
narrow enough to be useful and reproducible. The preferred promotion path is:

1. Collect the relevant FreeIPA source facts.
2. Add saved-query or object-review coverage.
3. Prove a concrete operator workflow.
4. Capture cleanup and side effects.
5. Update the schema, docs, and validation tests together.

Until then, these relationships remain review data: visible, queryable, and
useful, but not treated as default attack-path traversal.
