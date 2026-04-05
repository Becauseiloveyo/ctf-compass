# Challenge Methods

## Crypto

- Identify whether the problem is encoding, classical cipher, block cipher, stream cipher, hash misuse, RSA, ECC, or custom math.
- Check for repeated structure, fixed alphabets, padding artifacts, modulus leaks, or nonce reuse.
- Separate "decode" tasks from actual cryptanalysis before choosing a path.

## Web

- Map endpoints, parameters, sessions, roles, and file upload surfaces.
- Check auth logic, input validation, template rendering, deserialization, SSRF-like pivots inside the challenge boundary, and common CTF misconfigurations.
- Use the guide to narrow the vulnerability class before attempting any challenge-specific exploit path.

## Reverse

- Start with file type, architecture, symbols, strings, imports, and anti-debug clues.
- Reconstruct high-level logic before patching or tracing.
- Record all constants, comparisons, and encoded data paths.

## Pwn

- Identify architecture, protections, I/O model, memory corruption surface, and intended primitive.
- Confirm NX, PIE, RELRO, stack canaries, and libc assumptions.
- Build exploit hypotheses only inside the provided challenge runtime.

## Forensic

- Confirm container/file types first.
- Build a timeline from metadata, archives, and embedded artifacts.
- Check for hidden layers such as nested archives, slack space, stego, or packet exfiltration traces.

## Misc

- Treat it as classification first, not brute force.
- Check whether it reduces to encoding, stego, logic, scripting, or protocol analysis.

