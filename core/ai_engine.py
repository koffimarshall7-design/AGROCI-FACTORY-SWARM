"""Moteur IA unique - robuste aux coupures reseau mobiles."""
import os
import re
import json
import time
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GROQ_API_KEY", "").strip()
URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL_MAIN = os.getenv("GROQ_MODEL_MAIN", "openai/gpt-oss-120b")
MODEL_FAST = os.getenv("GROQ_MODEL_FAST", "openai/gpt-oss-20b")

_session = requests.Session()
_session.headers.update({
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
    "Connection": "keep-alive",
})


def _post(payload, retries=5):
    last_err = None
    for attempt in range(retries):
        try:
            r = _session.post(URL, json=payload, timeout=90)
            if r.status_code == 429:
                wait = 3 + attempt * 2
                print(f"[AI] rate limit, pause {wait}s...")
                time.sleep(wait)
                continue
            if r.status_code >= 500:
                wait = 2 ** attempt
                print(f"[AI] erreur serveur {r.status_code}, retry dans {wait}s...")
                time.sleep(wait)
                continue
            if r.status_code == 400:
                raise requests.HTTPError(f"400 Bad Request: {r.text[:300]}")
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except requests.HTTPError:
            raise
        except (requests.ConnectionError, requests.Timeout) as e:
            last_err = e
            wait = 2 ** attempt
            print(f"[AI] connexion coupee, retry {attempt+1}/{retries} dans {wait}s...")
            time.sleep(wait)
        except Exception as e:
            last_err = e
            time.sleep(2 ** attempt)
    raise RuntimeError(f"Echec LLM apres {retries} tentatives: {last_err}")


def ask_ai(prompt, system="Tu es un assistant utile.", model=None,
           json_mode=False, temperature=0.6):
    if not API_KEY:
        raise ValueError("GROQ_API_KEY manquante dans .env")
    if json_mode and "json" not in system.lower():
        system = system + " Reponds imperativement en JSON valide."
    payload = {
        "model": model or MODEL_MAIN,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    try:
        return _post(payload)
    except requests.HTTPError as e:
        if json_mode and "400" in str(e):
            payload.pop("response_format", None)
            return _post(payload)
        raise


def _extract_json(text):
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        return json.loads(m.group(1))
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        return json.loads(m.group(0))
    raise ValueError(f"Aucun JSON trouve dans: {text[:300]}")


def ask_ai_json(prompt, system="Tu reponds en JSON strict.", model=None):
    raw = ask_ai(prompt, system=system, model=model, json_mode=True)
    return _extract_json(raw)
