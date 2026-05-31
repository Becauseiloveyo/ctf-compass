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
- automatically inspect WAV metadata, PCM LSB candidates, tone / morse hints, and waveform / spectrogram views for audio-based local challenges
- automatically inspect ELF / PE / APK attachments, extracting headers, sections, imports / exports, symbol / relocation summaries, interpreter / shared-library hints, manifest strings, DEX method indexes, Android string-pool resources, and unpacked package contents for recursive local analysis
- detect local professional CTF tools on PATH and expose real executable actions instead of placeholder guidance
- run installed tool adapters for ExifTool, binwalk, zsteg, TShark, Ciphey, rabin2, jadx, and apktool, then import generated output back into the workspace
- show missing tool status and installation hints per artifact so the user knows exactly why a deeper action is unavailable
- automatically persist the current workspace locally, restoring challenge fields, artifact paths, final flag selection, and evidence notes on the next launch
- export Markdown investigation reports that include classification, pipeline output, final flag, and artifact-level notebook entries
- provide dedicated desktop workbench panes for binary / traffic / image / audio families instead of showing everything in one generic result list
- surface solving checklists and methodology guides
- help organize evidence, observations, and likely next steps in one desktop workspace

This project does **not** target real-world systems and should not be used for unauthorized activity.

## Current Capability Areas

- `crypto`: simple encoded content discovery, category hints, and workflow guidance
- `web`: challenge metadata and traffic-based session/auth clue routing
- `reverse`: ELF / PE / APK structure extraction, strings/import/export/symbol triage, and flow hints
- `pwn`: ELF-oriented routing with loader/shared-library clues and protection-oriented next steps
- `forensic`: pcap/pcapng session extraction, archive recursion, document extraction, and hidden-artifact oriented workflow hints
- `misc`: image/stego and mixed-artifact triage with local auto-processing where deterministic

## Tool-Backed Workflow

CTF Compass now uses a two-layer workflow:

- Built-in analyzers handle deterministic local tasks such as recursive ZIP/GZIP extraction, strings, encoded text layers, PNG text chunks, PNG LSB candidates, QR/barcode detection, basic pcap triage, PDF/Office unpacking, WAV clues, and ELF/PE/APK structure summaries.
- External tool adapters run mature local tools when they are installed. The app detects each command on PATH and only shows executable buttons for tools that can actually run.

Supported adapters:

- `ExifTool`: metadata extraction for images, documents, audio, archives, and binaries
- `binwalk`: signature scan and embedded-file extraction
- `zsteg`: PNG/BMP LSB steganography scan
- `TShark`: HTTP/DNS extraction and HTTP object export from traffic captures
- `Ciphey`: automatic decode/decrypt attempts for text-like artifacts
- `rabin2`: ELF/PE/Mach-O header, section, import, and string triage
- `jadx`: APK/DEX Java decompilation
- `apktool`: APK resource and smali unpacking

If a tool is missing, the artifact card shows it as `未安装` with the install direction. After installing and reopening/rerunning analysis, the matching action button becomes available.

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

A downloadable zip can be created from the unpacked build. The current local package name is `release/CTF-Compass-0.4.1-win-x64.zip`.

## Next Steps

1. Add dedicated workbench panes for PDF / Office so document-style attachments stop falling back to the generic results grid.
2. Add an optional tool installer/bootstrap page that can generate Windows/WSL setup commands without silently changing the host.
3. Deepen local binary routes with APK resource-id mapping, fuller DEX proto/method views, PE protection/export grouping, and ELF relocation detail views.
4. Add category-specific plugin modules and release automation for GitHub Releases / installers.
