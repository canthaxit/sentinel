"""Sentinel - Chat Completion Helper (for decoy/assistant responses)."""

import logging
import os

log = logging.getLogger(__name__)


# ============================================================================
# Chat Completion Helper (for decoy/assistant responses)
# ============================================================================

def chat_completion(messages, system=None, options=None, **kwargs):
    """
    Provider-agnostic chat completion for general conversation.

    Uses the configured SHIELD_LLM_PROVIDER to generate responses.
    This replaces direct ollama.chat() calls in sentinel_app.py.

    Args:
        messages: List of {"role": ..., "content": ...} dicts
        system: Optional system prompt (prepended to messages)
        options: Provider-specific options (Ollama options dict, etc.)
        **kwargs: Additional provider-specific arguments

    Returns:
        str: The assistant's response text
    """
    provider = os.getenv("SHIELD_LLM_PROVIDER", "ollama").lower().strip()
    model = os.getenv("SHIELD_LLM_MODEL", "llama3")

    # Build full message list with system prompt
    full_messages = []
    if system and provider in ("ollama", "ollama_structured", "openai", "openai_compat", "azure", "llamacpp"):
        full_messages.append({"role": "system", "content": system})
    full_messages.extend(messages)

    if provider in ("ollama", "ollama_structured"):
        return _chat_ollama(full_messages, model, options)
    elif provider == "openai":
        return _chat_openai(full_messages, model, kwargs.get("api_key"))
    elif provider == "openai_compat":
        return _chat_openai_compat(full_messages, model, kwargs)
    elif provider == "anthropic":
        return _chat_anthropic(full_messages, model, system, kwargs.get("api_key"))
    elif provider == "azure":
        return _chat_azure(full_messages, kwargs)
    elif provider == "bedrock":
        return _chat_bedrock(full_messages, model, system, kwargs)
    elif provider in ("vertex", "gemini"):
        return _chat_gemini(full_messages, model, system, provider, kwargs)
    elif provider == "llamacpp":
        return _chat_llamacpp(full_messages, kwargs)
    else:
        # Fallback to Ollama
        return _chat_ollama(full_messages, model, options)


def _chat_ollama(messages, model, options=None):
    """Ollama chat completion."""
    import ollama
    default_options = {
        "num_ctx": 1024,
        "num_predict": 200,
        "temperature": 0.7,
        "top_k": 40,
        "top_p": 0.9,
    }
    if options:
        default_options.update(options)
    response = ollama.chat(model=model, messages=messages, options=default_options)
    return response["message"]["content"]


def _chat_openai(messages, model, api_key=None):
    """OpenAI chat completion."""
    try:
        import openai
    except ImportError:
        raise ImportError("openai package required. Install with: pip install openai>=1.0.0")
    client = openai.OpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY", ""))
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=200,
        temperature=0.7,
    )
    return response.choices[0].message.content


def _chat_anthropic(messages, model, system=None, api_key=None):
    """Anthropic chat completion."""
    try:
        import anthropic
    except ImportError:
        raise ImportError("anthropic package required. Install with: pip install anthropic>=0.40.0")
    client = anthropic.Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY", ""))
    # Filter out system messages (Anthropic uses separate system param)
    user_messages = [m for m in messages if m["role"] != "system"]
    sys_prompt = system or ""
    if not sys_prompt:
        for m in messages:
            if m["role"] == "system":
                sys_prompt = m["content"]
                break
    response = client.messages.create(
        model=model,
        max_tokens=200,
        system=sys_prompt,
        messages=user_messages,
    )
    return response.content[0].text


def _chat_azure(messages, kwargs):
    """Azure OpenAI chat completion."""
    try:
        import openai
    except ImportError:
        raise ImportError("openai package required. Install with: pip install openai>=1.0.0")
    client = openai.AzureOpenAI(
        azure_endpoint=kwargs.get("endpoint") or os.getenv("AZURE_OPENAI_ENDPOINT", ""),
        api_key=kwargs.get("api_key") or os.getenv("AZURE_OPENAI_KEY", ""),
        api_version=kwargs.get("api_version") or os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01"),
    )
    deployment = kwargs.get("deployment") or os.getenv("AZURE_OPENAI_DEPLOYMENT", "")
    response = client.chat.completions.create(
        model=deployment,
        messages=messages,
        max_tokens=200,
        temperature=0.7,
    )
    return response.choices[0].message.content


def _chat_bedrock(messages, model, system=None, kwargs=None):
    """AWS Bedrock chat completion."""
    import json
    try:
        import boto3
    except ImportError:
        raise ImportError("boto3 package required. Install with: pip install boto3>=1.34.0")
    kwargs = kwargs or {}
    region = kwargs.get("region") or os.getenv("AWS_REGION", "us-east-1")
    client = boto3.client("bedrock-runtime", region_name=region)
    user_messages = [m for m in messages if m["role"] != "system"]
    sys_prompt = system or ""
    if not sys_prompt:
        for m in messages:
            if m["role"] == "system":
                sys_prompt = m["content"]
                break
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 200,
        "system": sys_prompt,
        "messages": user_messages,
    })
    response = client.invoke_model(
        modelId=model, body=body,
        contentType="application/json", accept="application/json",
    )
    result = json.loads(response["body"].read())
    return result["content"][0]["text"]


def _chat_gemini(messages, model, system=None, provider="gemini", kwargs=None):
    """Google Gemini/Vertex chat completion."""
    kwargs = kwargs or {}
    if provider == "vertex":
        try:
            import vertexai
            from vertexai.generative_models import GenerativeModel
        except ImportError:
            raise ImportError("google-cloud-aiplatform required.")
        project = kwargs.get("project") or os.getenv("GOOGLE_CLOUD_PROJECT", "")
        location = kwargs.get("location") or os.getenv("GOOGLE_CLOUD_REGION", "us-central1")
        vertexai.init(project=project, location=location)
        gen_model = GenerativeModel(model, system_instruction=system or "")
    else:
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError("google-generativeai required.")
        genai.configure(api_key=kwargs.get("api_key") or os.getenv("GOOGLE_API_KEY", ""))
        gen_model = genai.GenerativeModel(model, system_instruction=system or "")

    # Combine user messages into a single prompt for Gemini
    user_text = "\n".join(m["content"] for m in messages if m["role"] != "system")
    response = gen_model.generate_content(
        user_text,
        generation_config={"max_output_tokens": 200, "temperature": 0.7},
    )
    return response.text


def _chat_openai_compat(messages, model, kwargs=None):
    """OpenAI-compatible server chat completion (vLLM, LocalAI, etc.)."""
    try:
        import openai
    except ImportError:
        raise ImportError("openai package required. Install with: pip install openai>=1.0.0")
    kwargs = kwargs or {}
    base_url = kwargs.get("base_url") or os.getenv(
        "SHIELD_OPENAI_COMPAT_BASE_URL", "http://localhost:8000/v1"
    )
    api_key = kwargs.get("api_key") or os.getenv("SHIELD_OPENAI_COMPAT_API_KEY", "not-needed")
    client = openai.OpenAI(base_url=base_url, api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=200,
        temperature=0.7,
    )
    return response.choices[0].message.content


def _chat_llamacpp(messages, kwargs=None):
    """llama-cpp-python chat completion."""
    try:
        from llama_cpp import Llama
    except ImportError:
        raise ImportError(
            "llama-cpp-python required. Install with: pip install llama-cpp-python>=0.2.0"
        )
    kwargs = kwargs or {}
    gguf_path = kwargs.get("gguf_path") or os.getenv("SHIELD_GGUF_PATH", "")
    if not gguf_path:
        raise ValueError("GGUF model path required. Set SHIELD_GGUF_PATH env var.")
    gpu_layers = int(kwargs.get("gpu_layers", os.getenv("SHIELD_GPU_LAYERS", "0")))
    llm = Llama(model_path=gguf_path, n_gpu_layers=gpu_layers, n_ctx=1024, verbose=False)
    # Build prompt from messages
    prompt_parts = []
    for m in messages:
        role = m["role"]
        prompt_parts.append(f"<|{role}|>\n{m['content']}")
    prompt_parts.append("<|assistant|>\n")
    prompt = "\n".join(prompt_parts)
    output = llm(prompt, max_tokens=200, temperature=0.7)
    return output["choices"][0]["text"].strip()
