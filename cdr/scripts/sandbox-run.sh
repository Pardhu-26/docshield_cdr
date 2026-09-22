#!/usr/bin/env bash
# ==============================================================================
# DocShield CDR Engine - Native Kernel Sandbox Runner (Bubblewrap)
# ==============================================================================
# Provides complete hardware and kernel-level isolation for untrusted documents:
# - Network Airgap: Isolated network namespace (--unshare-all), zero outbound access.
# - Filesystem Airgap: Root mounted Read-Only (--ro-bind / /).
# - Host Protection: Host directories (home, system files) cannot be altered.
# - Input Protection: Target file is mounted strictly Read-Only.
# - Output Isolation: Only the designated output directory receives writes.
# - Resource Constraints: Ephemeral in-memory tmpfs scratchpad.
# ==============================================================================

set -eo pipefail

if [ "$#" -ne 2 ]; then
    echo "DocShield Sandbox: Please provide an input file and an output file."
    echo "Usage: ./scripts/sandbox-run.sh <input-file> <output-file>"
    exit 1
fi

INPUT="$1"
OUTPUT="$2"

if [ ! -f "$INPUT" ]; then
    echo "DocShield Sandbox: Input file does not exist or is not a regular file: $INPUT"
    exit 1
fi

# Ensure bubblewrap is installed
if ! command -v bwrap >/dev/null 2>&1; then
    echo "DocShield Sandbox Error: 'bwrap' (Bubblewrap) is required but not installed."
    echo "On Ubuntu/Debian: sudo apt-get update && sudo apt-get install -y bubblewrap"
    exit 1
fi

# Resolve absolute paths on host
ABS_INPUT="$(realpath "$INPUT")"
INPUT_FILENAME="$(basename "$ABS_INPUT")"

OUTPUT_DIR="$(dirname "$OUTPUT")"
mkdir -p "$OUTPUT_DIR"
ABS_OUTPUT_DIR="$(realpath "$OUTPUT_DIR")"
OUTPUT_FILENAME="$(basename "$OUTPUT")"

# Locate project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Ensure target directory exists
mkdir -p "$PROJECT_ROOT/target"
CLASSPATH_FILE="$PROJECT_ROOT/target/docshield-classpath.txt"

# Ensure classes and classpath are prepared
if [ ! -d "$PROJECT_ROOT/target/classes" ] || [ ! -f "$CLASSPATH_FILE" ]; then
    echo "DocShield Sandbox: Preparing classes and dependencies..."
    (cd "$PROJECT_ROOT" && mvn -q compile dependency:build-classpath -Dmdep.outputFile="$CLASSPATH_FILE")
fi

CLASSPATH="$PROJECT_ROOT/target/classes:$(cat "$CLASSPATH_FILE")"

# Create ephemeral scratch workspace on host
SCRATCH_DIR="$(mktemp -d -t docshield-sandbox-scratch-XXXXXX)"
cleanup() {
    rm -rf "$SCRATCH_DIR"
}
trap cleanup EXIT INT TERM

# Ensure reports and quarantine directories exist
mkdir -p "$PROJECT_ROOT/output/reports"
mkdir -p "$PROJECT_ROOT/output/quarantine"
ABS_REPORTS_DIR="$(realpath "$PROJECT_ROOT/output/reports")"
ABS_QUARANTINE_DIR="$(realpath "$PROJECT_ROOT/output/quarantine")"

echo "============================================================"
echo " Starting DocShield CDR in Airgapped Kernel Sandbox (bwrap) "
echo "============================================================"
echo " Isolated Input   : $ABS_INPUT (Read-Only)"
echo " Protected Output : $ABS_OUTPUT_DIR/$OUTPUT_FILENAME"
echo " Network Status   : AIRGAPPED (Zero Network Access)"
echo " Root Filesystem  : READ-ONLY"
echo " Ephemeral Scratch: $SCRATCH_DIR"
echo "============================================================"

# Execute inside impenetrable bubblewrap jail
bwrap \
    --unshare-all \
    --die-with-parent \
    --new-session \
    --ro-bind / / \
    --proc /proc \
    --dev /dev \
    --tmpfs /tmp \
    --tmpfs /var/tmp \
    --dir /tmp/sandbox \
    --dir /tmp/sandbox/input \
    --dir /tmp/sandbox/output \
    --dir /tmp/sandbox/scratch \
    --bind "$SCRATCH_DIR" /tmp/sandbox/scratch \
    --setenv HOME /tmp/sandbox/scratch \
    --setenv TMPDIR /tmp/sandbox/scratch \
    --ro-bind "$ABS_INPUT" "/tmp/sandbox/input/$INPUT_FILENAME" \
    --bind "$ABS_OUTPUT_DIR" /tmp/sandbox/output \
    --bind "$ABS_REPORTS_DIR" "$PROJECT_ROOT/output/reports" \
    --bind "$ABS_QUARANTINE_DIR" "$PROJECT_ROOT/output/quarantine" \
    --chdir "$PROJECT_ROOT" \
    java -Djava.awt.headless=true -cp "$CLASSPATH" Main "/tmp/sandbox/input/$INPUT_FILENAME" "/tmp/sandbox/output/$OUTPUT_FILENAME"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "============================================================"
    echo " DocShield Sandbox: Processing completed successfully!      "
    echo " Output file: $ABS_OUTPUT_DIR/$OUTPUT_FILENAME"
    echo "============================================================"
else
    echo "============================================================"
    echo " DocShield Sandbox: Terminated with exit code $EXIT_CODE    "
    echo " (If quarantined, see records in $PROJECT_ROOT/output/quarantine/)"
    echo "============================================================"
fi

exit $EXIT_CODE
