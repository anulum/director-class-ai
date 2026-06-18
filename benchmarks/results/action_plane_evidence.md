# Action-Plane Benchmark Evidence

Evidence grade: local-regression-non-isolated: functional benchmark evidence only; not a public performance or comparative claim

## Run Context

- command: `/home/anulum/.local/bin/python -m benchmarks.action_evidence --heavy-jobs not reserved; workstation may have background activity`
- git SHA: `db49f04ea16de7cba834ddbe09123036ad584489`
- isolation method: `none`
- CPU affinity: `none`
- host load before: `9.31, 9.12, 8.66`
- host load after: `9.31, 9.12, 8.66`
- CPU governor: `powersave`
- Python: `3.12.3`
- platform: `Linux-6.17.0-35-generic-x86_64-with-glibc2.39`
- heavy jobs: `not reserved; workstation may have background activity`

## Metrics

- authored n: 356
- external n: 0
- catastrophic recall: 1.000
- false hard-block rate: 0.000
- false escalation rate: 0.018
- safe route conformance: 1.000
- elapsed: 278.882 ms

## External Sources

- AgentDojo-style: loaded=False, licence=Not vendored; verify upstream licence before local import, status=absent
- SkillInject-style: loaded=False, licence=Not vendored; verify upstream licence before local import, status=absent
- MCP-security: loaded=False, licence=Not vendored; verify upstream licence before local import, status=absent

## Claim Boundary

These results are benchmark evidence for the recorded checkout and run context only. Public comparative claims require isolated execution, loaded external artefacts, and licence/provenance review.
