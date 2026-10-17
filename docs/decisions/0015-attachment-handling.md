# ADR-0015: Attachment upload, storage and download

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V5.1.1, V5.2.1–V5.2.3, V5.3.1, V5.3.2, V5.4.1–V5.4.3, V1.3.4, V3.2.1; threats T-060..T-064

## Decision
- **Allowed types** (extension **and** detected content must agree, detection by magic bytes via `filetype`/`python-magic`): images PNG, JPEG, GIF, WebP; PDF; plain text (`.txt`, `.log`, `.csv`, `.md` — UTF-8 validated); office documents `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`; archives `.zip`. Everything else is rejected. SVG and HTML are **not accepted** (they are scriptable; V1.3.4). Content checks per type (V5.2.2 L2 applies them to every file): images are decoded and re-encoded with Pillow (pixel limit enforced); PDFs must start with `%PDF-` and parse their trailer; text must decode as UTF-8 without NUL bytes; Office Open XML files must be valid zip archives whose central directory contains `[Content_Types].xml`, and OpenDocument files must have a first entry named `mimetype` with the matching media type. These zip checks read only the central directory and the small `mimetype` entry, with entry-count (≤ 10,000) and size limits; they never extract the archive. `.zip` uploads must have a valid central directory within the same limits.
- **Size:** max 25 MB per file (`MAX_UPLOAD_MB`), enforced by Nginx and the app with streaming; per-project quota 2 GB; per-user upload rate limit (ADR-0024).
- **Antivirus scanning (V5.4.3):** every upload is written to a quarantine directory first and streamed to ClamAV (`clamd`, running inside the app container under supervisord, reached over a local Unix socket via `INSTREAM`). Only files with a clean result are moved to permanent storage and recorded; infected files are deleted and logged as `security.upload_rejected` (reason `malware`, signature name). **Fail closed:** if `clamd` is unavailable or times out (30 s), the upload is rejected with 503. `freshclam` updates signatures (ClamAV verifies their digital signatures) from the official mirror; this is the app container's only routine outbound connection (security-requirements §11). Operators without egress can supply signature files offline. Existing attachments are re-scanned weekly with fresh signatures, and newly detected files are quarantined and reported to project admins.
- **Archives (V5.2.3):** the application itself never decompresses or parses archives or office files. ClamAV does unpack them for scanning, with limits set in `clamd.conf`: `MaxScanSize 100M`, `MaxFileSize 25M`, `MaxRecursion 10`, `MaxFiles 1000`, `AlertExceedsMax yes` (files that exceed a limit are treated as infected and rejected). If preview or extraction is added later, the same limits apply in the application.
- **Storage:** `/data/attachments/<project_uuid>/<uuidv7>` with no extension; the original filename is stored only as metadata (sanitized for display; stripped of control characters, path separators and bidi overrides). The volume is mounted `noexec`; Nginx never serves it directly (`internal` location only).
- **Download:** the API authorizes, then responds with `X-Accel-Redirect`; headers are `Content-Type` from the detected type (or `application/octet-stream`), `Content-Disposition: attachment; filename*=UTF-8''<encoded>`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox; default-src 'none'`, `Cache-Control: private, no-store`. Raster images may be shown inline in the UI only through `<img>` tags from the same authorized endpoint with `?inline=1`, which is allowed only for PNG, JPEG, GIF and WebP.
- A SHA-256 checksum is recorded on upload and verified on download (integrity, A08).
- Avatars: same pipeline, raster images only, max 2 MB, re-encoded server-side with Pillow to strip metadata and payloads.
- ClamAV adds about 1–1.5 GB of memory to the app container; `mem_limit` is raised accordingly (PLAN §8.3). Signature-based scanning doesn't catch novel malware, so the residual risk for T-064 is reduced, not eliminated.

## Security impact
Mitigates stored XSS via files, path traversal, executable upload, MIME confusion, and resource exhaustion.

## Consequences
Users can't upload SVG diagrams; they can upload PNG exports instead. Uploads take slightly longer because of scanning. The app image is larger and needs more memory.
