"""
OpenRouter chat-completions helper with reasoning enabled.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

import time

import requests
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage


class OpenRouterError(Exception):
    """Raised when an OpenRouter request fails."""


@dataclass
class OpenRouterResponse:
    content: str
    reasoning_details: List[Dict[str, Any]]
    usage_metadata: Dict[str, int]
    response_metadata: Dict[str, Any]
    raw: Dict[str, Any]
    generation_id: Optional[str] = None
    exact_usage: Dict[str, Any] = field(default_factory=dict)


def extract_usage_details(response: Any, agent_role: Optional[str] = None) -> Dict[str, Any]:
    token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    openrouter_usage: Dict[str, Any] = {}

    try:
        if hasattr(response, 'usage_metadata') and response.usage_metadata:
            um = response.usage_metadata
            token_usage = {
                "prompt_tokens": int(um.get('input_tokens', 0) or um.get('prompt_tokens', 0) or 0),
                "completion_tokens": int(um.get('output_tokens', 0) or um.get('completion_tokens', 0) or 0),
                "total_tokens": int(um.get('total_tokens', 0) or 0),
            }

        if hasattr(response, 'response_metadata') and response.response_metadata:
            rm = response.response_metadata or {}
            generation = rm.get('openrouter_generation') or {}
            if isinstance(generation, dict):
                openrouter_usage = dict(generation)
            elif 'usage' in rm:
                usage = rm['usage'] or {}
                token_usage = {
                    "prompt_tokens": int(usage.get('prompt_tokens', 0) or usage.get('input_tokens', 0) or 0),
                    "completion_tokens": int(usage.get('completion_tokens', 0) or usage.get('output_tokens', 0) or 0),
                    "total_tokens": int(usage.get('total_tokens', 0) or 0),
                }
    except Exception:
        pass

    if openrouter_usage:
        openrouter_usage.setdefault('tokens_prompt', token_usage['prompt_tokens'])
        openrouter_usage.setdefault('tokens_completion', token_usage['completion_tokens'])
        openrouter_usage.setdefault('total_tokens', token_usage['total_tokens'])
        if agent_role:
            openrouter_usage['agent_role'] = agent_role

    exact_cost = 0.0
    try:
        exact_cost = float(openrouter_usage.get('cost_usd', 0.0) or 0.0)
    except Exception:
        exact_cost = 0.0

    return {
        'token_usage': token_usage,
        'cost_usd': exact_cost,
        'openrouter_usage': openrouter_usage,
    }


def rehydrate_openrouter_usage(usage: Any, api_key: str, base_url: str = "https://openrouter.ai/api/v1", timeout: int = 30) -> Dict[str, Any]:
    if not isinstance(usage, dict) or not usage or not api_key:
        return dict(usage) if isinstance(usage, dict) else {}

    generation_id = usage.get("generation_id") or usage.get("id")
    if not generation_id:
        return dict(usage)

    needs_refresh = (
        not usage.get("provider_name")
        or not usage.get("model")
        or not usage.get("exact")
        or float(usage.get("cost_usd", 0.0) or 0.0) <= 0.0
    )
    if not needs_refresh:
        return dict(usage)

    try:
        client = OpenRouterReasoningChat(
            model=str(usage.get("model") or usage.get("model_permaslug") or "openai/gpt-5.2"),
            api_key=api_key,
            base_url=base_url,
            temperature=0.0,
            timeout=timeout,
        )
        generation_data = client._fetch_generation_stats(str(generation_id))
        if not generation_data:
            return dict(usage)
        refreshed = client._normalize_generation_usage(
            {"id": generation_id, "model": usage.get("model") or usage.get("model_permaslug") or client.model, "usage": {}},
            generation_data,
        )
        merged = dict(usage)
        merged.update({
            k: v for k, v in refreshed.items()
            if v not in (None, '', [], {}) or k in {"cost_usd", "native_tokens_reasoning", "tokens_prompt", "tokens_completion", "total_tokens"}
        })
        return merged
    except Exception:
        return dict(usage)


class OpenRouterReasoningChat:
    def __init__(
        self,
        *,
        model: str,
        api_key: str,
        base_url: str,
        temperature: float,
        timeout: int,
        default_headers: Dict[str, str] | None = None,
        reasoning_enabled: bool = True,
    ) -> None:
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.temperature = temperature
        self.timeout = timeout
        self.default_headers = default_headers or {}
        self.reasoning_enabled = reasoning_enabled
        self._autopov_model_name = model

    def _serialize_content(self, content: Any) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: List[str] = []
            for item in content:
                if isinstance(item, dict):
                    if item.get('type') == 'text' and item.get('text'):
                        parts.append(str(item['text']))
                    elif 'content' in item and item['content']:
                        parts.append(str(item['content']))
                elif item is not None:
                    parts.append(str(item))
            return ''.join(parts)
        if content is None:
            return ''
        return str(content)

    def _serialize_message(self, message: BaseMessage) -> Dict[str, Any]:
        if isinstance(message, SystemMessage):
            role = 'system'
        elif isinstance(message, HumanMessage):
            role = 'user'
        elif isinstance(message, AIMessage):
            role = 'assistant'
        else:
            role = 'user'

        payload: Dict[str, Any] = {
            'role': role,
            'content': self._serialize_content(message.content),
        }
        additional_kwargs = getattr(message, 'additional_kwargs', {}) or {}
        if role == 'assistant' and additional_kwargs.get('reasoning_details'):
            payload['reasoning_details'] = additional_kwargs['reasoning_details']
        return payload

    def _headers(self) -> Dict[str, str]:
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
        }
        headers.update(self.default_headers)
        return headers

    def _fetch_generation_stats(self, generation_id: Optional[str]) -> Dict[str, Any]:
        if not generation_id:
            return {}

        last_payload: Dict[str, Any] = {}
        for delay_s in (0.0, 0.5, 1.0, 2.0, 4.0):
            if delay_s:
                time.sleep(delay_s)
            try:
                response = requests.get(
                    f'{self.base_url}/generation',
                    headers=self._headers(),
                    params={'id': generation_id},
                    timeout=self.timeout,
                )
            except requests.RequestException:
                continue
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict) and isinstance(data.get('data'), dict):
                    return data['data']
                if isinstance(data, dict):
                    return data
                return {}
            if response.status_code in {401, 403}:
                return {}
            try:
                payload = response.json()
                if isinstance(payload, dict):
                    last_payload = payload
            except Exception:
                last_payload = {}
        if isinstance(last_payload, dict) and isinstance(last_payload.get('data'), dict):
            return last_payload['data']
        return last_payload if isinstance(last_payload, dict) else {}

    def _normalize_generation_usage(self, chat_data: Dict[str, Any], generation_data: Dict[str, Any]) -> Dict[str, Any]:
        usage = chat_data.get('usage') or {}
        prompt_tokens = generation_data.get('tokens_prompt')
        completion_tokens = generation_data.get('tokens_completion')
        total_tokens = usage.get('total_tokens')

        if prompt_tokens is None:
            prompt_tokens = usage.get('prompt_tokens', 0) or usage.get('input_tokens', 0) or 0
        if completion_tokens is None:
            completion_tokens = usage.get('completion_tokens', 0) or usage.get('output_tokens', 0) or 0
        if total_tokens is None:
            total_tokens = int(prompt_tokens or 0) + int(completion_tokens or 0)

        normalized = {
            'generation_id': generation_data.get('generation_id') or generation_data.get('id') or chat_data.get('id'),
            'provider_name': generation_data.get('provider_name') or ((generation_data.get('provider_responses') or [{}])[0] or {}).get('provider_name') or '',
            'model': generation_data.get('model') or chat_data.get('model') or self.model,
            'model_permaslug': generation_data.get('model_permaslug') or generation_data.get('model') or chat_data.get('model') or self.model,
            'cost_usd': float(generation_data.get('total_cost', generation_data.get('usage', 0.0)) or 0.0),
            'cost_upstream_usd': float(generation_data.get('usage_upstream', generation_data.get('upstream_inference_cost', 0.0)) or 0.0),
            'tokens_prompt': int(prompt_tokens or 0),
            'tokens_completion': int(completion_tokens or 0),
            'total_tokens': int(total_tokens or 0),
            'native_tokens_prompt': int(generation_data.get('native_tokens_prompt', 0) or 0),
            'native_tokens_completion': int(generation_data.get('native_tokens_completion', 0) or 0),
            'native_tokens_reasoning': int(generation_data.get('native_tokens_reasoning', 0) or 0),
            'native_tokens_cached': int(generation_data.get('native_tokens_cached', 0) or 0),
            'latency_ms': generation_data.get('latency'),
            'generation_time_ms': generation_data.get('generation_time'),
            'finish_reason': generation_data.get('finish_reason') or '',
            'native_finish_reason': generation_data.get('native_finish_reason') or '',
            'provider_responses': generation_data.get('provider_responses') or [],
            'created_at': generation_data.get('created_at'),
            'exact': bool(generation_data),
        }
        return normalized

    def invoke(self, messages: Iterable[BaseMessage]) -> OpenRouterResponse:
        payload: Dict[str, Any] = {
            'model': self.model,
            'messages': [self._serialize_message(message) for message in messages],
            'temperature': self.temperature,
        }
        if self.reasoning_enabled:
            payload['reasoning'] = {'enabled': True}

        response = requests.post(
            f'{self.base_url}/chat/completions',
            headers=self._headers(),
            json=payload,
            timeout=self.timeout,
        )
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise OpenRouterError(f'OpenRouter request failed: {response.text}') from exc

        data = response.json()
        message = ((data.get('choices') or [{}])[0] or {}).get('message') or {}
        generation_id = data.get('id')
        generation_data = {}
        try:
            generation_data = self._fetch_generation_stats(generation_id)
        except Exception:
            generation_data = {}

        normalized_usage = self._normalize_generation_usage(data, generation_data)
        usage_metadata = {
            'input_tokens': normalized_usage.get('tokens_prompt', 0),
            'output_tokens': normalized_usage.get('tokens_completion', 0),
            'total_tokens': normalized_usage.get('total_tokens', 0),
        }
        reasoning_details = message.get('reasoning_details') or []

        return OpenRouterResponse(
            content=self._serialize_content(message.get('content', '')),
            reasoning_details=reasoning_details,
            usage_metadata=usage_metadata,
            response_metadata={
                'usage': data.get('usage') or {},
                'reasoning_details': reasoning_details,
                'raw': data,
                'openrouter_generation': normalized_usage,
            },
            raw=data,
            generation_id=normalized_usage.get('generation_id'),
            exact_usage=normalized_usage,
        )
