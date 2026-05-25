import os
import requests
import json
import logging
from typing import Optional
import asyncio

logger = logging.getLogger(__name__)


class LMStudioClient:
    """Cliente HTTP para LM Studio local"""
    
    def __init__(self):
        self.base_url = os.getenv("LM_STUDIO_URL", "http://127.0.0.1:1234")
        self.model = os.getenv("LM_STUDIO_MODEL", "mistral-7b-instruct-v0.3")
        self.timeout = 120  # segundos
        self.max_retries = 3
        self.retry_delay = 1  # segundos
    
    async def health_check(self) -> bool:
        """
        Verificar disponibilidad de LM Studio.
        """
        try:
            response = requests.get(
                f"{self.base_url}/models",
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"LM Studio health check failed: {e}")
            return False
    
    async def parse_logs(
        self,
        logs_chunk: str,
        temperature: float = 0.3,
        max_tokens: int = 2048
    ) -> Optional[list]:
        """
        Enviar chunk de logs sin parsear a IA para parsing.
        
        Devuelve lista de dicts parseados.
        """
        system_prompt = """You are a Linux log parser. Extract structured information from syslog entries.
Return ONLY a valid JSON array. Each element should have these fields:
- timestamp (ISO format or null)
- hostname (string or null)
- service (string or null)
- pid (integer or null)
- user (string or null)
- action (string or null)
- target (string or null)
- raw_line (string)

If any field cannot be extracted, use null. Return ONLY the JSON array, no other text."""

        user_prompt = f"""Parse these log lines and return JSON array:\n\n{logs_chunk}"""
        
        response = await self._send_request(
            system_prompt,
            user_prompt,
            temperature,
            max_tokens
        )
        
        if response:
            return await self.validate_json_response(response)
        return None
    
    async def analyze_logs(
        self,
        parsed_logs: str,
        temperature: float = 0.3,
        max_tokens: int = 2048
    ) -> Optional[list]:
        """
        Enviar logs parseados a IA para análisis de amenazas.
        
        Devuelve lista de dicts con análisis.
        """
        system_prompt = """You are a security analyst specialized in Linux forensics.
Analyze log entries for suspicious activity. For each entry, return JSON with:
- severity (low/medium/high/critical)
- threat_type (brute_force, privilege_escalation, exfiltration, suspicious_command, etc)
- indicators (list of suspicious elements)
- explanation (why this is suspicious)
- confidence (0.0 to 1.0)

Return ONLY a valid JSON array, no other text. If no threat detected, use severity "low"."""

        user_prompt = f"""Analyze these parsed log entries for threats:\n\n{parsed_logs}

Return JSON array with threat analysis for each entry."""
        
        response = await self._send_request(
            system_prompt,
            user_prompt,
            temperature,
            max_tokens
        )
        
        if response:
            return await self.validate_json_response(response)
        return None
    
    async def _send_request(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.3,
        max_tokens: int = 2048
    ) -> Optional[str]:
        """
        Enviar request a LM Studio con reintentos.
        
        Nota: El modelo solo soporta roles 'user' y 'assistant',
        así que combinamos system_prompt + user_prompt en un único mensaje.
        """
        url = f"{self.base_url}/v1/chat/completions"
        
        # Combinar system prompt y user prompt en un único mensaje
        combined_prompt = f"{system_prompt}\n\n{user_prompt}"
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": combined_prompt}
            ],
            "temperature": temperature,
            "top_p": 0.8,
            "max_tokens": max_tokens,
            "stream": False
        }
        
        for attempt in range(self.max_retries):
            try:
                logger.debug(f"Sending request to LM Studio (attempt {attempt + 1}/{self.max_retries})")
                
                # Usar to_thread para evitar bloquear el event loop
                response = await asyncio.to_thread(
                    requests.post,
                    url,
                    json=payload,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extraer contenido de la respuesta
                    if "choices" in data and len(data["choices"]) > 0:
                        content = data["choices"][0]["message"]["content"]
                        logger.debug("LM Studio response received successfully")
                        return content
                    else:
                        logger.error("Unexpected response format from LM Studio")
                        return None
                
                else:
                    logger.warning(f"LM Studio error: {response.status_code}")
                    logger.debug(f"Response: {response.text}")
                
            except requests.exceptions.Timeout:
                logger.warning(f"LM Studio timeout on attempt {attempt + 1}/{self.max_retries}")
            
            except requests.exceptions.ConnectionError:
                logger.warning(f"LM Studio connection error on attempt {attempt + 1}/{self.max_retries}")
            
            except Exception as e:
                logger.error(f"Unexpected error in LM Studio request: {e}")
            
            # Esperar antes de reintentar
            if attempt < self.max_retries - 1:
                await asyncio.sleep(self.retry_delay * (2 ** attempt))  # Backoff exponencial
        
        logger.error("LM Studio request failed after all retries")
        return None
    
    async def validate_json_response(self, response: str) -> Optional[list]:
        """
        Validar que la respuesta sea JSON válido.
        """
        try:
            data = json.loads(response)
            if isinstance(data, list):
                return data
            else:
                logger.error("LM Studio response is not a JSON array")
                return None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in LM Studio response: {e}")
            logger.debug(f"Response was: {response[:200]}...")
            return None
