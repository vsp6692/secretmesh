# Shared helpers for the git hooks. Sourced, not executed.

if [ -t 1 ]; then
  red=$(printf '\033[31m'); green=$(printf '\033[32m'); dim=$(printf '\033[2m'); off=$(printf '\033[0m')
else
  red=; green=; dim=; off=
fi

# makevar NAME prints the value of "NAME := value" from the Makefile, so tool
# versions are defined in one place.
makevar() { sed -n "s/^$1 := //p" Makefile; }

# step "description" command... runs a command, printing its output only on failure.
step() {
  desc=$1; shift
  out=$(mktemp)
  printf '%s…%s ' "$dim" "$off"; printf '%s ' "$desc"
  if "$@" >"$out" 2>&1; then
    printf '%sok%s\n' "$green" "$off"
    rm -f "$out"
  else
    printf '%sFAILED%s\n' "$red" "$off"
    sed 's/^/    /' "$out"
    rm -f "$out"
    failed=1
  fi
}

finish() {
  if [ "${failed:-0}" -ne 0 ]; then
    printf '\n%s%s blocked.%s Fix the problems above and try again.\n' "$red" "$1" "$off" >&2
    printf 'CI runs the same checks and cannot be skipped, so bypassing this hook with --no-verify only delays the failure.\n' >&2
    exit 1
  fi
}
