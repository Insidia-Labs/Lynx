# Skills

First-party skills live here, one folder per skill, each with a `SKILL.md`.
A skill is loaded on demand with the `load_skill` tool; nothing about it sits in
the default prompt.

`SKILL.md` frontmatter:

```yaml
name: authorization
description: One line on what the skill covers and when it applies
triggers: [idor, tenant isolation, access control]
applies_to: [web, api, source]
tools: []        # optional tool pack; built-in skills only
verify: {}       # optional fix-verification steps; built-in skills only
```
