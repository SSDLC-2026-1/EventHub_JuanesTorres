"""
payment_validation.py

Skeleton file for input validation exercise.
You must implement each validation function according to the
specification provided in the docstrings.

All validation functions must return:

    (clean_value, error_message)

Where:
    clean_value: normalized/validated value (or empty string if invalid)
    error_message: empty string if valid, otherwise error description
"""

import re
import unicodedata
from datetime import datetime
from typing import Tuple, Dict


# =============================
# Regular Patterns
# =============================



CARD_DIGITS_RE = re.compile(r"^[0-9]{13,19}$")     # digits only
CVV_RE = re.compile(r"^[0-9]{3,4}$")             # 3 or 4 digits
EXP_RE = re.compile(r"^(0[1-9]|1[0-2])/([0-9]{2})$")             # MM/YY format
EMAIL_BASIC_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,254}$")     # basic email structure
NAME_ALLOWED_RE = re.compile(r"^[a-zA-ZÀ-ÖØ-öø-ÿ\s'\-]+$")    # allowed name characters



# =============================
# Utility Functions
# =============================

def normalize_basic(value: str) -> str:
    value = unicodedata.normalize("NFKC", (value or "")).strip()
    return value


def luhn_is_valid(number: str) -> bool:
    """
    ****BONUS IMPLEMENTATION****

    Validate credit card number using Luhn algorithm.

    Input:
        number (str) -> digits only

    Returns:
        True if valid according to Luhn algorithm
        False otherwise
    """
    if not number.isdigit():
        return False
        
    total = 0
    reversed_digits = number[::-1]
    
    for i, char in enumerate(reversed_digits):
        digit = int(char)
        if (i+1) % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
        
    return total % 10 == 0


# =============================
# Field Validations
# =============================

def validate_card_number(card_number: str) -> Tuple[str, str]:
    """
    Validate credit card number.

    Requirements:
    - Normalize input
    - Remove spaces and hyphens before validation
    - Must contain digits only
    - Length between 13 and 19 digits
    - BONUS: Must pass Luhn algorithm

    Input:
        card_number (str)

    Returns:
        (card, error_message)

    Notes:
        - If invalid → return ("", "Error message")
        - If valid → return (all credit card digits, "")
    """
    card_number = normalize_basic(card_number)
    card_number = card_number.replace(" ", "").replace("-", "")

    if not CARD_DIGITS_RE.match(card_number):
        return "", "Card number must contain only digits beetween 13 and 19"
    
    if not luhn_is_valid(card_number):
        return "", "Card number failed Luhn validation"
    
    return card_number, ""

def validate_exp_date(exp_date: str) -> Tuple[str, str]:
    """
    Validate expiration date.

    Requirements:
    - Format must be MM/YY
    - Month must be between 01 and 12
    - Must not be expired compared to current UTC date
    - Optional: limit to reasonable future (e.g., +15 years)

    Input:
        exp_date (str)

    Returns:
        (normalized_exp_date, error_message)
    """
    exp_date = normalize_basic(exp_date)
    exp_month = int(exp_date[:2])
    exp_year = int(exp_date[-2:])

    today = datetime.utcnow()
    year = today.year % 100
    month = today.month

    if not EXP_RE.match(exp_date):
        return "", "Expiration date must be in MM/YY format with valid month"
    elif exp_year < year or (exp_year == year and exp_month < month):
        return "", "Card is expired, check again :D"
    elif exp_year > (year + 7):
        return "", "Expiration date is unreal D:, are u sure this is correct?"
    
    # TODO: Implement validation
    return exp_date, ""


def validate_cvv(cvv: str) -> Tuple[str, str]:
    
    cvv_clean = normalize_basic(cvv)
    
    if not cvv_clean.isdigit():
        return "", "CVV must contain only digits"
    
    if len(cvv_clean) not in (3, 4):
        return "", "CVV must be exactly 3 or 4 digits"
    
    return "cvv_clean", ""


def validate_billing_email(billing_email: str) -> Tuple[str, str]:
    """
    Validate billing email.

    Requirements:
    - Normalize (strip + lowercase)
    - Max length 254
    - Must match basic email pattern

    Input:
        billing_email (str)

    Returns:
        (normalized_email, error_message)
    """
    email_clean = normalize_basic(billing_email).lower()
    
    if len(email_clean) > 254:
        return "", "Email must not exceed 254 characters"
    
    if not email_clean:
        return "", "Email cannot be empty"
    
    if not EMAIL_BASIC_RE.match(email_clean):
        return "", "Email must match basic email"
    
    return email_clean, ""


def validate_name_on_card(name_on_card: str) -> Tuple[str, str]:
    value = normalize_basic(name_on_card)
    value = re.sub(r"\s+", " ", value)
    if not (2 <= len(value) <= 60):
        return "", "Name must be between 2 and 60 characters"
    if not NAME_ALLOWED_RE.fullmatch(value):
        return "", "Name contains invalid characters"
    if not re.search(r"[A-Za-zÀ-ÖØ-öø-ÿ]", value):
        return "", "Name must contain letters"
    return value, ""
 #se supone que esto funciona

# =============================
# Orchestrator Function
# =============================

def validate_payment_form(
    card_number: str,
    exp_date: str,
    cvv: str,
    name_on_card: str,
    billing_email: str
) -> Tuple[Dict, Dict]:
    """
    Orchestrates all field validations.

    Returns:
        clean (dict)  -> sanitized values safe for storage/use
        errors (dict) -> field_name -> error_message
    """

    clean = {}
    errors = {}

    card, err = validate_card_number(card_number)
    if err:
        errors["card_number"] = err
    clean["card"] = card

    exp_clean, err = validate_exp_date(exp_date)
    if err:
        errors["exp_date"] = err
    clean["exp_date"] = exp_clean

    _, err = validate_cvv(cvv)
    if err:
        errors["cvv"] = err

    name_clean, err = validate_name_on_card(name_on_card)
    if err:
        errors["name_on_card"] = err
    clean["name_on_card"] = name_clean

    email_clean, err = validate_billing_email(billing_email)
    if err:
        errors["billing_email"] = err
    clean["billing_email"] = email_clean

    return clean, errors
