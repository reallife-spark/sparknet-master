#!/usr/bin/env bash
# Host-side launcher for the LoRA trainer + GGUF export.
#
# `sparknet-distill.py run` sets SPARKNET_DISTILL_RUN and
# SPARKNET_DISTILL_DATASET and runs this script from the run directory. The
# training image sees the distill state as /work, so the dataset and run paths
# line up; the HF cache is bind-mounted so a second run does not re-download
# the student. The export leg merges the adapter, converts to GGUF, quantizes
# Q4_K_M and signs the artifact when SPARKNET_DISTILL_SIGN_KEY is set.
set -euo pipefail
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  cat <<'HELP'
usage: SPARKNET_DISTILL_RUN=<id> SPARKNET_DISTILL_DATASET=<dir> sparknet-distill-trainer.sh

Runs the LoRA trainer and the GGUF export for one distillation run. The caller
is sparknet-distill.py run --execute, which sets the two environment variables
and runs this from the run directory. It holds no signer socket.
HELP
  exit 0
fi
RUN="${SPARKNET_DISTILL_RUN:?missing SPARKNET_DISTILL_RUN}"
DATASET="${SPARKNET_DISTILL_DATASET:?missing SPARKNET_DISTILL_DATASET}"
STATE="${SPARKNET_DISTILL_STATE:-/mnt/ai/distill}"
STUDENT="${SPARKNET_DISTILL_STUDENT:-Qwen/Qwen3-4B-Instruct-2507}"
MAX_LEN="${SPARKNET_DISTILL_MAX_LEN:-16384}"
IMAGE="${SPARKNET_DISTILL_IMAGE:-sparknet-distill:dev}"
HF_CACHE="${SPARKNET_HF_CACHE:-/mnt/ai/hf-cache}"
RUN_DIR="$STATE/runs/$RUN"
WORK_RUN="/work/runs/$RUN"
DATASET_IN_CONTAINER="/work/datasets/$(basename "$DATASET")"
mkdir -p "$HF_CACHE" "$RUN_DIR"

echo "[distill-trainer] training $STUDENT (max_len=$MAX_LEN) in $RUN_DIR"
docker run --rm --gpus all --network host \
  -v "$STATE:/work" \
  -v "$HF_CACHE:/root/.cache/huggingface" \
  -e SPARKNET_DISTILL_RUN="$RUN" \
  -e SPARKNET_DISTILL_DATASET="$DATASET_IN_CONTAINER" \
  -e SPARKNET_DISTILL_STUDENT="$STUDENT" \
  -e SPARKNET_DISTILL_MAX_LEN="$MAX_LEN" \
  -w "$WORK_RUN" \
  "$IMAGE"

echo "[distill-trainer] exporting GGUF"
docker run --rm --network host \
  -v "$STATE:/work" \
  -v "$HF_CACHE:/root/.cache/huggingface" \
  -e SPARKNET_DISTILL_RUN="$RUN" \
  -w "$WORK_RUN" \
  --entrypoint /usr/bin/python3 \
  "$IMAGE" /opt/sparknet/sparknet-distill-export.py \
    --adapter "$WORK_RUN/adapter" \
    --base "$STUDENT" \
    --out-dir "$WORK_RUN/export" \
    --quant Q4_K_M

ARTIFACT="$RUN_DIR/export/student-q4_k_m.gguf"
[ -s "$ARTIFACT" ] || { echo "[distill-trainer] export produced no artifact" >&2; exit 1; }
cp -f "$ARTIFACT" "$RUN_DIR/artifact"
if [ -n "${SPARKNET_DISTILL_SIGN_KEY:-}" ]; then
  python3 "$(dirname "$0")/../../scripts/sparknet-sign-artifact.py" sign \
    --file "$RUN_DIR/artifact" \
    --key "$SPARKNET_DISTILL_SIGN_KEY" \
    --out "$RUN_DIR/artifact.sig"
fi
echo "[distill-trainer] artifact: $RUN_DIR/artifact"
