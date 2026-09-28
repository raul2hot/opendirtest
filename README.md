# opendirtest

A planned ultra-fast scanner and indexer for **public, legal open directories**. These are
web servers that publish auto-generated file listings, such as software mirrors, public
datasets and academic archives.

It indexes file metadata only (name, size, mtime), follows robots.txt, stays polite per
host, and puts every host through a safety gate before it gets published.

- **Safety flags:** [`src/safety.rs`](src/safety.rs). Every crawl-safety behaviour is a
  constant boolean, and all of them default to `true`.
- **Design guide (start here):** [`docs/GUIDE.md`](docs/GUIDE.md). It covers the 2026
  tech stack, discovery sources, crawler architecture, the legality pipeline, and storage
  and search.
