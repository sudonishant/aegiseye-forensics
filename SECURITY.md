# Security Policy: AegisEye Forensics

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅ Yes    |

## Reporting a Vulnerability

If you find a bypass where the secure shredder fails to fully sanitize filename metadata, or if an EXIF reader fails to parse coordinates safely (buffer overflows), please report it responsibly:
1. Email your findings directly to the repository maintainers.
2. Provide the sample corrupted image or target file used in the audit.
3. We will patch the parser logic in the next revision.
