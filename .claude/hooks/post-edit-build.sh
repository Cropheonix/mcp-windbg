#!/usr/bin/env bash
# Post-edit build verification hook for VideoPro26
# Runs qmake + cmake builds after source code changes.
# Exits non-zero on failure so Claude will see errors and continue fixing.

set -euo pipefail

# Read hook input from stdin to get the edited file path
INPUT=$(cat)
CHANGED_FILE=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null || echo "")

# Only build when relevant source files are changed
if [[ -n "$CHANGED_FILE" ]]; then
  case "$CHANGED_FILE" in
    *.cpp|*.h|*.c|*.ui|*.qrc|*.pro|*.cmake|CMakeLists.txt|*.rc|*.qss)
      ;; # relevant source file — continue
    *)
      exit 0  # not a build-relevant file, skip
      ;;
  esac
fi

REPO_ROOT="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
BUILD_BAT="$REPO_ROOT/build.bat"

if [[ ! -f "$BUILD_BAT" ]]; then
  echo "[HOOK] build.bat not found at $BUILD_BAT"
  exit 1
fi

echo "[HOOK] Verifying build after editing: ${CHANGED_FILE:-unknown}"
echo "[HOOK] Running build.bat (qmake + cmake) ..."

# Run the full build via cmd; build.bat handles VS2019 env, qmake, nmake, cmake, ninja
cmd //c "$BUILD_BAT"
exit_code=$?

if [[ $exit_code -ne 0 ]]; then
  echo ""
  echo "[HOOK] BUILD FAILED (exit code $exit_code)."
  echo "[HOOK] Fix the compilation errors above. Both qmake and CMake builds must pass."
  exit 2
fi

echo "[HOOK] Build passed successfully."
exit 0
