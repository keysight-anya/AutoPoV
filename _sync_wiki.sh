#!/bin/bash
set -e

WIKI_SRC="/home/user/AutoPoV/.qoder/repowiki/en/content"
WIKI_DEST="/home/user/autopov-wiki"

# Copy all .md files, flattening subdirectories with unique names
find "$WIKI_SRC" -name "*.md" | while read f; do
  rel="${f#$WIKI_SRC/}"
  dir=$(dirname "$rel")
  base=$(basename "$rel")

  if [ "$dir" = "." ]; then
    dest_name="$base"
  else
    # Use the immediate parent folder name as prefix to avoid collisions
    parent=$(basename "$dir")
    # If the file name already equals the parent name (e.g. "Agent System/Agent System.md"), skip prefix
    if [ "$base" = "${parent}.md" ]; then
      dest_name="$base"
    else
      dest_name="${parent} - ${base}"
    fi
  fi

  cp "$f" "$WIKI_DEST/$dest_name"
done

echo "Copy done. Total .md files in wiki repo:"
find "$WIKI_DEST" -maxdepth 1 -name "*.md" | wc -l
