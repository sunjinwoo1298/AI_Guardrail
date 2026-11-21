"""Lightweight ONNX Runtime inference for the guardrail's transformer models.

Replaces torch / transformers / sentence-transformers. Both default models publish an
``onnx/`` export on the Hugging Face Hub, so we only need onnxruntime + tokenizers
(both already pulled in by chromadb).
"""
from __future__ import annotations

import json
import os
from typing import Dict, List

import numpy as np

MAX_SEQUENCE_LENGTH = int(os.getenv("ONNX_MAX_SEQUENCE_LENGTH", "512"))


def _download(repo_id: str, filename: str) -> str:
    """Prefer the file inside ``onnx/``; fall back to the repo root."""
    from huggingface_hub import hf_hub_download
    from huggingface_hub.utils import EntryNotFoundError

    try:
        return hf_hub_download(repo_id, filename, subfolder="onnx")
    except EntryNotFoundError:
        return hf_hub_download(repo_id, filename)


class OnnxModel:
    def __init__(self, repo_id: str, max_length: int = MAX_SEQUENCE_LENGTH):
        import onnxruntime as ort
        from tokenizers import Tokenizer

        options = ort.SessionOptions()
        options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self.session = ort.InferenceSession(
            _download(repo_id, "model.onnx"),
            sess_options=options,
            providers=["CPUExecutionProvider"],
        )
        self.input_names = {i.name for i in self.session.get_inputs()}

        self.tokenizer = Tokenizer.from_file(_download(repo_id, "tokenizer.json"))
        self.tokenizer.no_padding()
        self.tokenizer.enable_truncation(max_length=max_length)

        with open(_download(repo_id, "config.json"), encoding="utf-8") as fh:
            self.config = json.load(fh)

    def __call__(self, text: str) -> np.ndarray:
        encoding = self.tokenizer.encode(text)
        feeds = {
            "input_ids": np.array([encoding.ids], dtype=np.int64),
            "attention_mask": np.array([encoding.attention_mask], dtype=np.int64),
        }
        if "token_type_ids" in self.input_names:
            feeds["token_type_ids"] = np.array([encoding.type_ids], dtype=np.int64)
        return self.session.run(None, feeds)[0]


class OnnxTextClassifier(OnnxModel):
    """Drop-in for ``transformers.pipeline("text-classification", top_k=None)``."""

    def __init__(self, repo_id: str, max_length: int = MAX_SEQUENCE_LENGTH):
        super().__init__(repo_id, max_length)
        id2label = self.config.get("id2label") or {}
        self.labels = {int(k): v for k, v in id2label.items()}

    def __call__(self, text: str) -> List[Dict[str, float]]:
        logits = super().__call__(text)[0].astype(np.float64)
        probs = np.exp(logits - logits.max())
        probs /= probs.sum()
        results = [
            {"label": self.labels.get(i, f"LABEL_{i}"), "score": float(p)}
            for i, p in enumerate(probs)
        ]
        return sorted(results, key=lambda r: r["score"], reverse=True)


class OnnxSentenceEmbedder(OnnxModel):
    """L2-normalised sentence embeddings, pooled the way the model's
    sentence-transformers config says (CLS for bge-small-en-v1.5, else mean)."""

    def __init__(self, repo_id: str, max_length: int = MAX_SEQUENCE_LENGTH):
        super().__init__(repo_id, max_length)
        self.cls_pooling = False
        try:
            from huggingface_hub import hf_hub_download

            with open(hf_hub_download(repo_id, "1_Pooling/config.json"), encoding="utf-8") as fh:
                self.cls_pooling = bool(json.load(fh).get("pooling_mode_cls_token"))
        except Exception:
            pass

    def encode(self, text: str) -> np.ndarray:
        encoding = self.tokenizer.encode(text)
        hidden = super().__call__(text)[0].astype(np.float32)
        if self.cls_pooling:
            vector = hidden[0]
        else:
            mask = np.array(encoding.attention_mask, dtype=np.float32)[:, None]
            vector = (hidden * mask).sum(axis=0) / max(mask.sum(), 1.0)
        norm = np.linalg.norm(vector)
        return vector / norm if norm > 0 else vector
