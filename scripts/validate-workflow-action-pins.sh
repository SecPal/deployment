#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [ "$#" -eq 0 ]; then
  printf 'ERROR: expected at least one workflow path.\n' >&2
  exit 1
fi

failures=0
utf8_bom=$'\uFEFF'
document_start_pattern='^---[[:space:]]+(.*)$'
noncanonical_key_pattern="^[[:space:]]*(-[[:space:]]+)?([\"'].*[\"'][[:space:]]*:|[!&*?].*:)"
spaced_uses_key_pattern="^[[:space:]]*(-[[:space:]]+)?uses[[:space:]]+:"
explicit_key_pattern="^[[:space:]]*(-[[:space:]]+)?\\?([[:space:]]|$)"
multiline_quoted_scalar_pattern="^[[:space:]]*(-[[:space:]]+)?(\"[^\"]*|'[^']*)$"
flow_sequence_pattern="^[[:space:]]*-[[:space:]]*([!&][^[:space:]]+[[:space:]]+)*[\\[{]"
flow_mapping_pattern="^[[:space:]]*[^#[:space:]][^:]*:[[:space:]]*([!&][^[:space:]]+[[:space:]]+)*[\\[{]"
flow_bare_pattern="^[[:space:]]*([!&][^[:space:]]+[[:space:]]+)*[\\[{]"
flow_uses_key_pattern="(^|[,{[:space:]]|\\[)(uses|\"uses\"|'uses')[[:space:]]*:"
flow_noncanonical_key_pattern="(^|[,{[:space:]]|\\[)([\"'][^\"']*[\"'][[:space:]]*:|[!&*?][^,:}]*:)"
block_scalar_pattern="^[[:space:]]*[^#[:space:]][^:]*:[[:space:]]*[>|][-+0-9]*[[:space:]]*(#.*)?$"

fail() {
  local line_number="$1"
  local message="$2"

  printf 'FAIL: %s:%s %s\n' "$current_workflow" "$line_number" "$message" >&2
  failures=$((failures + 1))
}

trim_whitespace() {
  local value="$1"

  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

for workflow in "$@"; do
  current_workflow="$workflow"
  if [ ! -f "$workflow" ]; then
    fail 0 "workflow is missing or not a regular file"
    continue
  fi

  line_number=0
  block_scalar_indent=-1
  while IFS= read -r -u 3 line || [ -n "$line" ]; do
    line_number=$((line_number + 1))
    syntax_line="$line"
    if [ "$line_number" -eq 1 ] && [[ "$syntax_line" == "$utf8_bom"* ]]; then
      syntax_line="${syntax_line#"$utf8_bom"}"
    fi

    leading_whitespace="${syntax_line%%[![:space:]]*}"
    line_indent=${#leading_whitespace}
    trimmed_line="$(trim_whitespace "$syntax_line")"

    if [ "$block_scalar_indent" -ge 0 ]; then
      if [ -z "$trimmed_line" ] || [ "$line_indent" -gt "$block_scalar_indent" ]; then
        continue
      fi
      block_scalar_indent=-1
    fi

    if [[ "$syntax_line" =~ $document_start_pattern ]]; then
      syntax_line="${BASH_REMATCH[1]}"
      leading_whitespace="${syntax_line%%[![:space:]]*}"
      line_indent=${#leading_whitespace}
      trimmed_line="$(trim_whitespace "$syntax_line")"
    fi

    if [[ "$syntax_line" =~ $block_scalar_pattern ]]; then
      block_scalar_indent=$line_indent
      continue
    fi

    if [[ "$syntax_line" =~ $noncanonical_key_pattern ]] ||
      [[ "$syntax_line" =~ $spaced_uses_key_pattern ]] ||
      [[ "$syntax_line" =~ $explicit_key_pattern ]] ||
      [[ "$syntax_line" =~ $multiline_quoted_scalar_pattern ]]; then
      fail "$line_number" \
        "mapping keys must use the canonical plain syntax"
      continue
    fi

    if { [[ "$syntax_line" =~ $flow_sequence_pattern ]] ||
      [[ "$syntax_line" =~ $flow_mapping_pattern ]] ||
      [[ "$syntax_line" =~ $flow_bare_pattern ]]; } && {
      [[ "$syntax_line" =~ $flow_uses_key_pattern ]] ||
        [[ "$syntax_line" =~ $flow_noncanonical_key_pattern ]]
    }; then
      fail "$line_number" \
        "uses declarations must use the canonical block mapping syntax"
      continue
    fi

    if [[ ! "$syntax_line" =~ ^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*(.*)$ ]]; then
      continue
    fi

    uses_field="${BASH_REMATCH[2]}"
    value_part="$uses_field"
    source_comment=""
    has_source_comment=false

    if [[ "$uses_field" == *'#'* ]]; then
      value_part="${uses_field%%#*}"
      if [[ "$value_part" =~ [[:space:]]$ ]]; then
        source_comment="${uses_field#*#}"
        has_source_comment=true
      else
        value_part="$uses_field"
      fi
    fi

    action_reference="$(trim_whitespace "$value_part")"
    source_comment="$(trim_whitespace "$source_comment")"

    if [[ "$action_reference" == \"*\" ]] || [[ "$action_reference" == \'*\' ]]; then
      action_reference="${action_reference:1:${#action_reference}-2}"
    fi

    if [[ "$action_reference" == ./* ]]; then
      continue
    fi

    if [[ ! "$action_reference" =~ ^[^@#[:space:]]+@[0-9a-f]{40}$ ]]; then
      fail "$line_number" \
        "external uses reference must end with a full lowercase commit SHA"
      continue
    fi

    if [ "$has_source_comment" != true ] ||
      [[ ! "$source_comment" =~ ^[^#[:space:]]+([[:space:]].*)?$ ]]; then
      fail "$line_number" \
        "external uses reference must include a source tag or branch comment"
    fi
  done 3< "$workflow"
done

if [ "$failures" -ne 0 ]; then
  printf 'Workflow action pin validation failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Workflow action pin validation passed.\n'
