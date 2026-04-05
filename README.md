# CTF Compass

CTF Compass is a safe, extensible assistant for lawful CTF practice. It helps users classify challenges, review common solving paths, and launch local analysis helpers for challenge categories such as crypto, web, pwn, reverse, forensic, and misc.

## Scope

This project is intentionally limited to legitimate CTF training workflows:

- classify challenge types from metadata and notes
- surface solving checklists and methodology guides
- provide local plugin hooks for challenge-specific analysis
- help organize evidence, observations, and likely next steps

This project does **not** target real-world systems and should not be used for unauthorized activity.

## Planned Capability Areas

- `crypto`: encoding detection, cipher family hints, known workflow checklists
- `web`: structured methodology guidance, route discovery notes, auth/session debugging hints, common vulnerability test checklists for CTF labs
- `reverse`: binary triage notes, strings/imports/function map workflow
- `pwn`: binary hardening checklist, libc/ELF metadata, exploit-planning notes for sandboxed challenge binaries
- `forensic`: file metadata, archive carving workflow, timeline hints
- `misc`: stego, encoding, logic puzzle triage

## Repository Layout

- `src/ctf_compass/`: application package
- `docs/`: architecture and challenge methodology guides
- `plugins/`: future plugin definitions for category-specific helpers

## Quick Start

```powershell
python -m ctf_compass.cli analyze --title "RSA warmup" --description "n and e are given, recover the flag" --tags crypto rsa
```

## Next Steps

1. Add richer challenge classifiers.
2. Add plugin loaders for category modules.
3. Add local file/binary/pcap ingestion flows.
4. Add a desktop or web UI for guided solving.

