# Security Notes

- Never execute attachments directly.
- Sandbox URLs in isolated Docker networks only.
- Rate-limit OSINT APIs.
- Do not upload customer evidence to third-party services without consent.
- Keep API keys in `.env`, never in Git.
- Add authentication before public deployment.
- Add file size limits and MIME sniffing before production.
