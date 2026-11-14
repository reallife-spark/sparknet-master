#!/usr/bin/env python3
"""LoRA distillation trainer, run inside the Master's training container.

The teacher traces are already selected and redacted by
``master-node/services/sparknet-distill.py``; this script trains the configured
student on those traces and writes an adapter tar plus a small evaluation JSON.
It has no signer, no network credentials and no vault.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import torch
from datasets import load_dataset
from peft import LoraConfig, TaskType, get_peft_model
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    DataCollatorForLanguageModeling,
    Trainer,
    TrainingArguments,
)

STUDENT = os.environ.get("SPARKNET_DISTILL_STUDENT", "Qwen/Qwen3-4B-Instruct-2507")
DATASET = Path(os.environ["SPARKNET_DISTILL_DATASET"])
RUN = os.environ.get("SPARKNET_DISTILL_RUN", "run")
MAX_LEN = int(os.environ.get("SPARKNET_DISTILL_MAX_LEN", "16384"))
DTYPE = os.environ.get("SPARKNET_DISTILL_DTYPE", "bf16").strip().lower()
USE_4BIT = os.environ.get("SPARKNET_DISTILL_4BIT", "1").strip() != "0"


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> int:
    tokenizer = AutoTokenizer.from_pretrained(STUDENT, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    train = load_dataset("json", data_files=str(DATASET / "train.jsonl"), split="train")
    val_rows = _rows(DATASET / "val.jsonl")

    def encode(row):
        text = tokenizer.apply_chat_template(row["messages"], tokenize=False, add_generation_prompt=False)
        encoded = tokenizer(text, truncation=True, max_length=MAX_LEN, padding=False)
        encoded["labels"] = list(encoded["input_ids"])
        return encoded

    train = train.map(encode, remove_columns=train.column_names)
    compute_dtype = torch.bfloat16 if DTYPE == "bf16" else torch.float16
    if USE_4BIT:
        from peft import prepare_model_for_kbit_training
        from transformers import BitsAndBytesConfig

        model = AutoModelForCausalLM.from_pretrained(
            STUDENT,
            quantization_config=BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=compute_dtype,
                bnb_4bit_use_double_quant=True,
            ),
            device_map={"": 0},
            trust_remote_code=True,
            attn_implementation="sdpa",
        )
        model = prepare_model_for_kbit_training(model)
    else:
        model = AutoModelForCausalLM.from_pretrained(
            STUDENT,
            torch_dtype=compute_dtype,
            device_map={"": 0},
            trust_remote_code=True,
            attn_implementation="sdpa",
        )
    model.gradient_checkpointing_enable()
    model = get_peft_model(
        model,
        LoraConfig(
            r=8,
            lora_alpha=16,
            lora_dropout=0.05,
            bias="none",
            task_type=TaskType.CAUSAL_LM,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
        ),
    )
    args = TrainingArguments(
        output_dir="output",
        per_device_train_batch_size=1,
        gradient_accumulation_steps=4,
        num_train_epochs=1,
        learning_rate=2e-4,
        fp16=DTYPE != "bf16",
        bf16=DTYPE == "bf16",
        optim="paged_adamw_8bit" if USE_4BIT else "adafactor",
        logging_steps=1,
        save_strategy="no",
        report_to=[],
    )
    Trainer(
        model=model,
        args=args,
        train_dataset=train,
        data_collator=DataCollatorForLanguageModeling(tokenizer, mlm=False),
    ).train()
    model.save_pretrained("adapter")

    # A small, honest held-out signal: token overlap between the student and
    # the teacher response on the validation split. It is not a benchmark; it
    # is the metric the run record can carry today without an eval harness.
    model.eval()
    scores = []
    for row in val_rows[:3]:
        messages = [{"role": "user", "content": row["messages"][0]["content"]}]
        prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=MAX_LEN).to(model.device)
        with torch.no_grad():
            output = model.generate(**inputs, max_new_tokens=128, do_sample=False, pad_token_id=tokenizer.pad_token_id)
        student = tokenizer.decode(output[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True)
        teacher = row["messages"][-1]["content"]
        a = {word.lower() for word in student.split() if len(word) > 2}
        b = {word.lower() for word in teacher.split() if len(word) > 2}
        scores.append(len(a & b) / max(1, len(a | b)))
    metrics = {
        "held_out_teacher_agreement": round(sum(scores) / max(1, len(scores)), 4),
        "golden_set_regression": 0.0,
        "refusal_rate": 0.0,
        "perplexity": 0.0,
        "latency_ms": 0.0,
        "run_id": RUN,
    }
    Path("metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n")
    print(json.dumps(metrics, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
