"""Core transformation utilities for anonymization/masking"""
from typing import Optional, List, Any
import hashlib
import hmac
import base64
import random
from faker import Faker

# Initialize Faker for substitution
fake = Faker()

def mask_value(val: Optional[str], keep_last: int = 4, mask_char: str = '*') -> Optional[str]:
    """Character masking - replaces characters with mask character"""
    if val is None:
        return val
    s = str(val)
    if len(s) <= keep_last:
        return mask_char * len(s)
    return mask_char * (len(s) - keep_last) + s[-keep_last:]

def null_value(val: Optional[Any]) -> None:
    """Nulling - replaces value with None/NULL"""
    return None

def substitute_value(val: Optional[str], data_type: str = 'name') -> Optional[str]:
    """Substitution - replaces with fake but realistic data"""
    if val is None:
        return val
    
    # Map data types to Faker methods
    substitution_map = {
        'name': fake.name,
        'email': fake.email,
        'phone': fake.phone_number,
        'address': fake.address,
        'company': fake.company,
        'ssn': fake.ssn,
        'credit_card': fake.credit_card_number,
        'date': lambda: fake.date_of_birth().strftime('%Y-%m-%d'),
        'city': fake.city,
        'country': fake.country,
        'zipcode': fake.zipcode,
        'url': fake.url,
        'ip': fake.ipv4,
        'text': fake.text
    }
    
    generator = substitution_map.get(data_type.lower(), fake.word)
    return generator()

def shuffle_column(values: List[Any]) -> List[Any]:
    """Shuffling - randomly reorders values within a column"""
    if not values:
        return values
    shuffled = values.copy()
    random.shuffle(shuffled)
    return shuffled

def salted_hash(val: Optional[str], salt: str) -> Optional[str]:
    """Hashing with salt for one-way anonymization"""
    if val is None:
        return val
    h = hashlib.sha256()
    h.update((salt + str(val)).encode('utf-8'))
    return h.hexdigest()

def hmac_pseudonymize(val: Optional[str], key: bytes, out_len: int = 12) -> Optional[str]:
    """HMAC-based pseudonymization for deterministic anonymization"""
    if val is None:
        return val
    tag = hmac.new(key, str(val).encode('utf-8'), digestmod=hashlib.sha256).digest()
    b64 = base64.urlsafe_b64encode(tag).decode('utf-8').rstrip('=')
    return b64[:out_len]

def generalize_age(age_val: Optional[int], bins=None) -> Optional[str]:
    """Generalization - converts precise ages to age ranges"""
    if age_val is None:
        return None
    try:
        age = int(age_val)
    except Exception:
        return str(age_val)
    if bins is None:
        bins = [0, 18, 30, 45, 65, 120]
    for i in range(len(bins)-1):
        if bins[i] <= age < bins[i+1]:
            return f"{bins[i]}-{bins[i+1]-1}"
    return f">={bins[-1]}"

def generalize_numeric(val: Optional[float], precision: int = 0) -> Optional[float]:
    """Generalize numeric values by reducing precision"""
    if val is None:
        return None
    try:
        num = float(val)
        if precision == 0:
            return float(int(num))
        return round(num, precision)
    except Exception:
        return val

def add_laplace_noise(val: Optional[float], epsilon: float = 1.0, sensitivity: float = 1.0) -> Optional[float]:
    """Add Laplace noise for differential privacy"""
    if val is None:
        return None
    try:
        num = float(val)
        scale = sensitivity / epsilon
        noise = random.laplace(0, scale)
        return num + noise
    except Exception:
        return val
