<!--
Copy this file to .github/release-notes/v<tag>.md and fill it in. release.yml
refuses a tag whose notes file is missing or empty.

Rules:
- One change per bullet, one line, about 20 words. If a bullet needs three
  clauses it is three bullets.
- No commit hashes, file paths, function names or PR numbers in user-facing
  lines. Those belong in CHANGELOG.md.
- Delete empty sections. "Action required" always stays.
- Whole file under about 600 words. Longer than that means the extra detail
  belongs in CHANGELOG.md, which is where the full record lives.
- Links must be absolute URLs - relative links do not resolve in a release body.
- Do not add the image-digest or recommended-stack sections; release.yml
  appends those itself after this file.
- Keep the three closing paragraphs verbatim.
-->

<One sentence: which release this is, and who it is for.>

### Action required

<The one thing the reader must do. If nothing: None - routine update. No manual steps.>

### Security

- <one line per security change: what was closed or hardened, and the effect>

### Changed

- <one line per behaviour, dependency or coverage change>

### Fixed

- <one line per user-visible bug fix>

### Upgrade

Copy and paste the complete command:

```bash
wget -qO setup-npmplus.sh https://github.com/mangyan1/NPMplus/releases/download/<TAG>/setup-npmplus.sh &&
wget -qO setup-npmplus.sh.sha256 https://github.com/mangyan1/NPMplus/releases/download/<TAG>/setup-npmplus.sh.sha256 &&
sha256sum -c setup-npmplus.sh.sha256 &&
sudo bash setup-npmplus.sh
```

<One line: Install NPMplus for a fresh VM, Safe update for an existing one, and what Safe update does for you.>

Please report problems through [GitHub issues](https://github.com/mangyan1/NPMplus/issues). Report security vulnerabilities privately through the repository Security page.

This fork is based on NPMplus by ZoeyVid and the original Nginx Proxy Manager project by JC21 and contributors. It remains licensed under AGPL-3.0-or-later, with the original MIT-licensed work retained as documented in the repository.
