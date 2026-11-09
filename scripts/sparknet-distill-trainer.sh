#!/usr/bin/env bash
# Host-side launcher for the LoRA trainer container.
#
# `sparknet-distill.py run` sets SPARKNET_DISTILL_RUN and
# SPARKNET_DISTILL_DATASET and runs this script from the run directory. The
# container sees /srv/sparknet/distill as /work, so the dataset path and the
# run directory line up; the HF cache is bind-mounted so a second run does not
# re-download the student.
set -euo pipefail
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  cat <<'EOF'
usage: SPARKNET_DISTILL_RUN=<id> SPARKNET_DISTILL_DATASET=<dir> sparknet-distill-trainer.sh

Runs the LoRA trainer container for one Master distillation run. The caller is
master-node/services/sparknet-distill.py run --execute, which sets the two
environment variables and runs this from the run directory. It holds no signer.
EOF
  exit 0
fi
RUN="${SPARKNET_DISTILL_RUN:?missing SPARKNET_DISTILL_RUN}"
DATASET="${SPARKNET_DISTILL_DATASET:?missing SPARKNET_DISTILL_DATASET}"
mkdir -p /mnt/ai/hf-cache
docker run --rm --gpus all --network host \
  -v /srv/sparknet/distill:/work \
  -v /mnt/ai/hf-cache:/root/.cache/huggingface \
  -e SPARKNET_DISTILL_RUN="$RUN" \
  -e SPARKNET_DISTILL_DATASET="/work/datasets/$(basename "$DATASET")" \
  -e SPARKNET_DISTILL_STUDENT="${SPARKNET_DISTILL_STUDENT:-Qwen/Qwen2.5-1.5B-Instruct}" \
  -w "/work/runs/$RUN" \
  sparknet-distill:dev
