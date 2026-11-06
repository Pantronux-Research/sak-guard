#!/bin/sh
# Build the preprint from paper.tex alone.
#
# filecontents* does NOT overwrite an existing references.bib: a stale copy shadows
# the embedded block and bibtex then drops whatever changed in it with no warning.
# Clearing the generated files first removes that failure mode entirely.
set -e
cd "$(dirname "$0")"
rm -f references.bib paper.aux paper.bbl paper.blg paper.log paper.out paper.pdf

ENGINE=pdflatex
if ! command -v "$ENGINE" >/dev/null 2>&1; then
  if command -v docker >/dev/null 2>&1; then
    exec docker run --rm -v "$PWD":/w -w /w texlive/texlive:latest sh build.sh
  fi
  echo "no pdflatex and no docker" >&2; exit 1
fi

pdflatex -interaction=nonstopmode -halt-on-error paper.tex
bibtex paper
pdflatex -interaction=nonstopmode paper.tex
pdflatex -interaction=nonstopmode paper.tex

echo "--- checks ---"
printf 'undefined citations: '; grep -ci 'citation.*undefined' paper.log || true
printf 'undefined refs     : '; grep -ci 'reference.*undefined' paper.log || true
printf 'bibtex entries     : '; grep -c bibitem paper.bbl
echo "built: paper.pdf"
