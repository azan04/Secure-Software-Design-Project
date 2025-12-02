"""Profile loader and validator for anonymization profiles"""
import json
from typing import Dict, Any

def load_profile(path: str) -> Dict[str, Any]:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)
