# CTF Compass

CTF Compass is a safe, extensible desktop app for lawful CTF practice. It is now designed around a file-first workflow: challenge statements, images, text files, archives, binaries, and traffic captures are treated as first-class inputs instead of optional notes.

## Scope

This project is intentionally limited to legitimate CTF training workflows:

- classify challenge types from metadata, notes, and attached artifacts
- extract likely flag candidates from text, ASCII / UTF-16 strings, and recursive encoded content
- automatically unpack ZIP and GZIP content and continue recursive analysis
- automatically decode base64, hex, base32, ascii85, URL-encoded, single-byte XOR, and compressed text layers when they produce useful local results
- automatically extract solvable image clues such as appended payloads, PNG text chunks, low-bit-plane candidates, and JPEG COM / XMP / APP segment payloads
- automatically decode QR and 1D barcode payloads from local images and export RGB / luminance / edge / JPEG-block visualization views for image-based challenges
- automatically summarize local traffic captures, extracting HTTP requests, DNS names, TLS SNI, cookies/tokens, and exported HTTP objects
- automatically extract PDF metadata, XMP packets, readable Flate streams, and OOXML/Office package contents for recursive local analysis
- automatically inspect WAV metadata, PCM LSB candidates, and waveform views for audio-based local challenges
- automatically persist the current workspace locally, restoring challenge fields, artifact paths, final flag selection, and evidence notes on the next launch
- export Markdown investigation reports that include classification, pipeline output, final flag, and artifact-level notebook entries
- surface solving checklists and methodology guides
- help organize evidence, observations, and likely next steps in one desktop workspace

This project does **not** target real-world systems and should not be used for unauthorized activity.

## Current Capability Areas

- `crypto`: simple encoded content discovery, category hints, and workflow guidance
- `web`: challenge metadata and traffic-based session/auth clue routing
- `reverse`: binary strings/import-oriented triage and flow hints
- `pwn`: binary-family routing with protection-oriented next steps
- `forensic`: pcap/pcapng session extraction, archive recursion, document extraction, and hidden-artifact oriented workflow hints
- `misc`: image/stego and mixed-artifact triage with local auto-processing where deterministic

## Repository Layout

- `src/ctf_compass/`: application package
- `desktop/`: Electron desktop shell and UI
- `docs/`: architecture and challenge methodology guides
- `plugins/`: future plugin definitions for category-specific helpers

## Desktop App

```powershell
npm install
npm run dev
```

Create a Windows desktop build:

```powershell
npm run dist:dir
```

The unpacked Windows app will be written to `release/win-unpacked/`.

A downloadable zip can be created from the unpacked build. The current local package name is `release/CTF-Compass-0.3.8-win-x64.zip`.

## Next Steps

1. Add deeper audio analyzers such as spectrogram views, tone/morse detection, and chunk anomaly summaries.
2. Add deeper executable analyzers for ELF/PE/APK to strengthen reverse and pwn routing.
3. Split PDF / Office / image / traffic into dedicated work panes instead of a shared generic evidence list.
4. Add category-specific plugin modules and release automation for GitHub Releases / installers.
