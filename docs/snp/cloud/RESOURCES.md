# Cloud resources created by this work

Running note so nothing is orphaned. Project nsf-2348130-428843, zone us-east1-b unless stated.
Update on every create, stop and delete.

| created | name | type | purpose | state |
|---|---|---|---|---|
| 2026-08-28 01:17Z | probe-a, probe-b | n2d-standard-2 SEV-SNP, us-central1-a | the three probes | deleted 01:20Z |
| 2026-08-28T01:23Z | listener | n2d-standard-2 SEV-SNP, us-central1-a | the attested peer in the cloud (~$0.08/h) | created |
| 2026-08-28T01:23Z | relay | e2-small, us-central1-a, public IP | the on-path attacker and the non-confidential peer (~$0.02/h) | created |
| 2026-08-28T01:23Z | attested-tunnel-udp-4433 | firewall rule, default network | udp:4433 to the relay from 128.239.2.78/32 only | created |
