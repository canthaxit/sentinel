"""Sentinel - llama-cpp-python LLM Provider (direct in-process GGUF inference)."""

import os

from sentinel.llm_judge import LLMJudge

# ============================================================================
# Provider: llama-cpp-python (direct in-process GGUF inference)
# ============================================================================


class LlamaCppJudge(LLMJudge):
    """Direct in-process GGUF inference via llama-cpp-python.

    No server required -- loads the model directly into the Python process.
    Uses GBNF grammar to constrain output to exactly "SAFE" or "UNSAFE".
    Requires: pip install llama-cpp-python>=0.2.0

    Config env vars:
        SHIELD_GGUF_PATH: Path to .gguf model file (required)
        SHIELD_GPU_LAYERS: Number of layers to offload to GPU (default: 0)
    """

    _GBNF_GRAMMAR = 'root ::= "SAFE" | "UNSAFE"'

    def __init__(self, model=None, gguf_path=None, gpu_layers=None, **kwargs):
        super().__init__(model=model or "gguf-local", **kwargs)
        self.gguf_path = gguf_path or os.getenv("SHIELD_GGUF_PATH", "")
        if not self.gguf_path:
            raise ValueError(
                "GGUF model path required. Set SHIELD_GGUF_PATH env var "
                "or pass gguf_path= parameter."
            )
        self.gpu_layers = int(
            gpu_layers if gpu_layers is not None else os.getenv("SHIELD_GPU_LAYERS", "0")
        )
        self._llm = None

    def _get_llm(self):
        if self._llm is None:
            try:
                from llama_cpp import Llama
            except ImportError:
                raise ImportError(
                    "llama-cpp-python required. Install with: pip install llama-cpp-python>=0.2.0"
                )
            self._llm = Llama(
                model_path=self.gguf_path,
                n_gpu_layers=self.gpu_layers,
                n_ctx=512,
                verbose=False,
            )
        return self._llm

    def _call_llm(self, user_input):
        from llama_cpp import LlamaGrammar

        llm = self._get_llm()
        grammar = LlamaGrammar.from_string(self._GBNF_GRAMMAR)
        prompt = f"<|system|>\n{self.system_prompt}\n<|user|>\n{user_input}\n<|assistant|>\n"
        output = llm(
            prompt,
            max_tokens=8,
            temperature=0.0,
            grammar=grammar,
        )
        return output["choices"][0]["text"].strip()
