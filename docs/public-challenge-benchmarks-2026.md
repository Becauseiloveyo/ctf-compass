# Public Challenge Benchmarks 2026

This document records validation against recently released public CTF challenges. Challenge assets are not redistributed by CTF Compass; clone the linked upstream repositories to reproduce the checks.

## Sources

- [UofTCTF 2026 public challenges](https://github.com/UofTCTF/uoftctf-2026-chals-public)
- [Jeanne d'Hack CTF 2026](https://github.com/JeanneD-Hack-CTF/JeanneD-Hack-CTF-2026)

## Results

| Challenge | Category | CTF Compass result | Automated output |
| --- | --- | --- | --- |
| Jeanne d'Hack: Goofy Fantasy | Misc / GIF stego | Solved | Reads packed two-bit values from GIF image descriptors and recovers the published flag. |
| Jeanne d'Hack: Navi's Mania | Misc / MP4 repair | Partial, repair completed | Detects a suspicious trailing `free` box after `moov`, rewrites it to `trak`, and exports a repaired MP4. |
| Jeanne d'Hack: Blind Distribution | Misc / MP4 repair | Partial, repair completed | Detects unsorted `stco`/`co64` chunk offsets, sorts them, and exports a repaired MP4. |
| UofTCTF: babybof | Pwn | Partial static triage | Unpacks the challenge, identifies ELF64 x86-64, partial RELRO, NX, no PIE, no canary, risky `gets`/`printf`/`system`, and prioritizes ret2win/stack-overflow paths. |
| UofTCTF: baby-exfil | Forensic / pcapng | Partial | Extracts HTTP, DNS, TLS SNI, session, and object clues. Full challenge-specific exfil reconstruction remains a manual gap. |

## Improvements Driven By These Challenges

- Added GIF image-descriptor bitstream extraction.
- Added bounded large-file MP4 analysis and Misc classification.
- Added MP4 top-level box reports, hidden-track repair, and chunk-offset sorting.
- Stopped treating coincidental media/packet magic bytes as appended archives.
- Filtered obvious fake, placeholder, UUID, and transformed-placeholder flag candidates.
- Stopped reporting routine "no decodable text found" outcomes as failed tasks.

## Reproduction Notes

Run the app against each upstream `dist` attachment or challenge artifact. Generated reports and repaired files are written inside the CTF Compass sandbox. A `partial` result means deterministic local processing completed but the final challenge flag still requires challenge-specific reasoning, exploitation, or interaction.
