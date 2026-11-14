#!/usr/bin/env bash
# Train a Qwen3-4B LoRA and export a servable Q4_K_M GGUF on an external GPU.
#
# The bundle that contains this script is training data, not knowledge. It has
# no peer key, no signer socket and no vault. Return the GGUF to agx32; the peer
# signs and uploads it to the Master's 8091 intake.
set -euo pipefail
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  cat <<'HELP'
usage: docker run --rm --gpus all -v "$PWD:/work" sparknet-distill-external

Environment:
  SPARKNET_DISTILL_DATASET  dataset directory (default /work/dataset)
  SPARKNET_DISTILL_STUDENT  base model (default Qwen/Qwen3-4B-Instruct-2507)
  SPARKNET_DISTILL_MAX_LEN  training sequence length (default 16384)
  SPARKNET_DISTILL_DTYPE    bf16 (default) or fp16
  SPARKNET_DISTILL_4BIT     1 (default) QLoRA, 0 for full-precision LoRA
  SPARKNET_DISTILL_OUT      output directory (default /work/out)

Writes out/student-q4_k_m.gguf; it does not sign or upload.
HELP
  exit 0
fi
DATASET="${SPARKNET_DISTILL_DATASET:-/work/dataset}"
STUDENT="${SPARKNET_DISTILL_STUDENT:-Qwen/Qwen3-4B-Instruct-2507}"
MAX_LEN="${SPARKNET_DISTILL_MAX_LEN:-16384}"
OUT="${SPARKNET_DISTILL_OUT:-/work/out}"
[ -s "$DATASET/train.jsonl" ] || { echo "[distill-external] dataset missing: $DATASET/train.jsonl" >&2; exit 1; }
mkdir -p "$OUT"
echo "[distill-external] training $STUDENT max_len=$MAX_LEN"
SPARKNET_DISTILL_STUDENT="$STUDENT" SPARKNET_DISTILL_MAX_LEN="$MAX_LEN" \
  python3 /opt/sparknet/train_lora.py
echo "[distill-external] exporting Q4_K_M"
python3 /opt/sparknet/sparknet-distill-export.py \
  --adapter "$PWD/adapter" \
  --base "$STUDENT" \
  --out-dir "$OUT" \
  --quant Q4_K_M \
  --llama-cpp /opt/llama.cpp
test -s "$OUT/student-q4_k_m.gguf" || { echo "[distill-external] no artifact" >&2; exit 1; }
sha256sum "$OUT/student-q4_k_m.gguf"
