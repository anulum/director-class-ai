# Action-Plane Benchmark Evidence

Evidence grade: local-regression-non-isolated: functional benchmark evidence only; not a public performance or comparative claim

## Run Context

- command: `/home/anulum/.local/bin/python -m benchmarks.action_evidence --heavy-jobs not reserved; workstation may have background activity`
- git SHA: `9e7072aa7102f1fdcfd3c9f3c54b873a72b7ac97`
- isolation method: `none`
- CPU affinity: `none`
- host load before: `3.78, 4.61, 22.63`
- host load after: `3.78, 4.61, 22.63`
- CPU governor: `powersave`
- Python: `3.12.3`
- platform: `Linux-6.17.0-35-generic-x86_64-with-glibc2.39`
- heavy jobs: `not reserved; workstation may have background activity`

## Metrics

- authored n: 356
- external n: 0
- customer/private n: 0
- catastrophic recall: 1.000
- false hard-block rate: 0.000
- false escalation rate: 0.018
- safe route conformance: 1.000
- elapsed: 191.931 ms

## External Sources

- AgentDojo-style: loaded=False, licence=MIT, licence_status=allow, import_allowed=True, status=absent
- MSB MCP Security Bench-style: loaded=False, licence=MIT, licence_status=allow, import_allowed=True, status=absent
- MCPSecBench-style: loaded=False, licence=MIT, licence_status=allow, import_allowed=True, status=absent
- MCP-SafetyBench-style: loaded=False, licence=not verified for repository artefacts, licence_status=requires_review, import_allowed=False, status=absent
- SkillInject-style: loaded=False, licence=not verified for benchmark artefacts, licence_status=requires_review, import_allowed=False, status=absent
- InjecAgent-style: loaded=False, licence=not verified for repository artefacts, licence_status=requires_review, import_allowed=False, status=absent
- Agent Security Bench-style: loaded=False, licence=MIT, licence_status=allow, import_allowed=True, status=absent
- Browser-computer-use injection-style: loaded=False, licence=not verified for benchmark artefacts, licence_status=requires_review, import_allowed=False, status=absent

## Claim Boundary

These results are benchmark evidence for the recorded checkout and run context only. Public comparative claims require isolated execution, loaded external artefacts, and licence/provenance review.
