# Preprint manuscript

`paper.tex` — IEEEtran (conference option) manuscript for TechRxiv.
Self-contained: BibTeX is embedded in a `filecontents*` block, so it builds from
one file.

```bash
pdflatex paper && bibtex paper && pdflatex paper && pdflatex paper
# or:
latexmk -pdf paper.tex
# or, without a local TeX install:
docker run --rm -v "$PWD":/w -w /w texlive/texlive:latest \
  sh -c "pdflatex -interaction=nonstopmode paper && bibtex paper && pdflatex -interaction=nonstopmode paper"
```

## Citation integrity (verified)

| Check | Result |
|---|---|
| BibTeX entries | 25 |
| `\cite` commands / distinct keys | 30 / 25 |
| Undefined citations | **0** |
| Unused entries | **0** |
| Published 2021–2026 | **88%** (22/25) |

All entries were retrieved from CrossRef or DataCite; none were written from
memory. See the compliance note in the repository documentation for the one
entry whose DOI still requires author confirmation.
