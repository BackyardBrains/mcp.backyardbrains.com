#!/usr/bin/env bash
echo "Script started."

#
# describe.sh
# -----------
# Combines .ts, .tsx, .js, .mjs, .cjs, .json, .md, .yaml/.yml, .sh, and .env files
# from '.' (including subdirs) into ONE FILE, excluding .DS_Store, node_modules,
# .git, *.lock, venv, dist, build, coverage, out, .next, .turbo, .cache.
# Also includes a tree output (no summary), then code excerpts, overwriting output file each run.

OUTPUT_FILE="current_project.txt"

echo "Generating $OUTPUT_FILE..."

###
# (1) Print the 'tree' view.
#     --noreport kills the "29 directories, 37 files" summary line
###
{
  echo "===== Project Tree ====="
  if command -v tree >/dev/null 2>&1; then
    tree . \
      -I 'node_modules|\\.git|\\.DS_Store|.*\\.lock|venv|dist|build|coverage|out|\\.next|\\.turbo|\\.cache' \
      -P '*.ts|*.tsx|*.js|*.mjs|*.cjs|*.json|*.md|*.yaml|*.yml|*.sh|.env|tsconfig.json|jest.config.*|*.config.*' \
      --prune \
      --noreport
  else
    echo "(tree not installed; using find fallback)"
    find . \
      -path './node_modules' -prune -o \
      -path './.git' -prune -o \
      -path './venv' -prune -o \
      -path './dist' -prune -o \
      -path './build' -prune -o \
      -path './coverage' -prune -o \
      -path './out' -prune -o \
      -path './.next' -prune -o \
      -path './.turbo' -prune -o \
      -path './.cache' -prune -o \
      -type f \
      \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o \
          -name '*.json' -o -name '*.md' -o -name '*.yaml' -o -name '*.yml' -o -name '*.sh' -o \
          -name '.env' -o -name 'tsconfig.json' -o -name 'jest.config.*' -o -name '*.config.*' \) \
      -print
  fi
  echo -e "\n===== Begin Code Excerpts =====\n"
} > "$OUTPUT_FILE"  # Overwrite the file here

echo "Collected tree output."

###
# (2) Collect paths in the same order 'tree' uses.
#     - -fi => full path, no indentation
#     - --noreport => no summary line
#     - Exclude directories more carefully:
#         - Remove lines ending in '/' (the majority of directories).
#         - Remove lines that are just '.' 
#         - Possibly remove lines that are just './static'
###
if command -v tree >/dev/null 2>&1; then
  tree_files=$(
    tree -fi -F . \
      -I 'node_modules|\\.git|\\.DS_Store|.*\\.lock|venv|dist|build|coverage|out|\\.next|\\.turbo|\\.cache' \
      -P '*.ts|*.tsx|*.js|*.mjs|*.cjs|*.json|*.md|*.yaml|*.yml|*.sh|.env|tsconfig.json|jest.config.*|*.config.*' \
      --prune \
      --noreport \
    | sed -e '/\/$/d' \
    | sed -e '/^\.$/d' \
    | sed -e '/^\.\/static$/d' \
    | awk '!seen[$0]++'    # remove duplicates if any
  )
else
  tree_files=$(
    find . \
      -path './node_modules' -prune -o \
      -path './.git' -prune -o \
      -path './venv' -prune -o \
      -path './dist' -prune -o \
      -path './build' -prune -o \
      -path './coverage' -prune -o \
      -path './out' -prune -o \
      -path './.next' -prune -o \
      -path './.turbo' -prune -o \
      -path './.cache' -prune -o \
      -type f \
      \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o \
          -name '*.json' -o -name '*.md' -o -name '*.yaml' -o -name '*.yml' -o -name '*.sh' -o \
          -name '.env' -o -name 'tsconfig.json' -o -name 'jest.config.*' -o -name '*.config.*' \) \
      -print | awk '!seen[$0]++'
  )
fi

echo "Files collected: $tree_files"

###
# (3) Loop over each file and append to the output in the same order
###
while IFS= read -r file; do
  if [ -f "$file" ]; then
    echo "Processing file: $file"
    echo "----- BEGIN $file -----" >> "$OUTPUT_FILE"
    cat "$file" >> "$OUTPUT_FILE"
    echo -e "\n----- END $file -----\n" >> "$OUTPUT_FILE"
  fi
done <<< "$tree_files"

echo "Done. See '$OUTPUT_FILE' for the combined codebase."