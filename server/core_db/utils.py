import uuid
import string
import secrets


def generate_random_username():
    """Generates a random 12-character alphanumeric string."""
    random_string = uuid.uuid4().hex

    return f"user_{random_string[:12]}"  # 281 trillion unique combinations


def generate_random_password(length=16):
    """
    Generate a cryptographically secure random password of the given length.
    Ensures at least one uppercase letter, one lowercase letter, one digit,
    and one special character are included in the password.
    """
    if length < 4:
        raise ValueError(
            "Password length must be at least 4 characters to meet the requirements"
        )

    # Define the character sets
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    punctuation = string.punctuation

    # Ensure at least one of each character type
    password = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(punctuation),
    ]

    # Fill the rest of the password length with random characters from all sets
    alphabet = lower + upper + digits + punctuation
    password += [secrets.choice(alphabet) for _ in range(length - 4)]

    # Shuffle the password to mix the characters
    secrets.SystemRandom().shuffle(password)

    return "".join(password)
