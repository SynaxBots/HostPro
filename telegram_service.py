import os
import secrets
import logging
import requests
from datetime import datetime, timedelta
from database import get_db, get_setting
import config

logger = logging.getLogger("vesper.telegram")

def is_valid_bot_token(token: str) -> bool:
    """Validate that the token matches Telegram's standard format (<digits>:<string>)."""
    if not token or not isinstance(token, str):
        return False
    clean = token.strip()
    if ":" not in clean or len(clean) < 15:
        return False
    prefix, _, suffix = clean.partition(":")
    return prefix.isdigit() and len(suffix) >= 10

def get_telegram_bot_token():
    """Retrieve Telegram bot token from environment or database settings."""
    env_token = os.environ.get("TELEGRAM_BOT_TOKEN", "8802958782:AAExyZMIRYWxM6M0uCI88cPvou7v1YIrVno").strip()
    if is_valid_bot_token(env_token):
        return env_token
    db_token = get_setting("telegram_bot_token", "8802958782:AAExyZMIRYWxM6M0uCI88cPvou7v1YIrVno")
    if is_valid_bot_token(db_token):
        return db_token.strip()
    return ""

def get_telegram_bot_username():
    """Retrieve Telegram bot username from environment or database settings."""
    env_user = os.environ.get("TELEGRAM_BOT_USERNAME", "").strip()
    if env_user:
        return env_user.lstrip("@")
    db_user = get_setting("telegram_bot_username", "BotStatusProBot)
    return db_user.strip().lstrip("@") if db_user else "BotStatusProBot"

def send_telegram_otp(telegram_id: str) -> dict:
    """
    Generates a 6-digit OTP and sends it to the user's Telegram ID via the Telegram Bot API.
    Handles rate limiting, invalidation of previous codes, and clear error messaging.
    """
    cleaned_id = str(telegram_id).strip()
    if not cleaned_id or not cleaned_id.isdigit():
        return {
            "success": False,
            "message": "Invalid Telegram User ID. Please enter numbers only (e.g. 123456789)."
        }

    if len(cleaned_id) < 5 or len(cleaned_id) > 15:
        return {
            "success": False,
            "message": "Telegram User ID must be between 5 and 15 digits."
        }

    db = get_db()
    cursor = db.cursor()

    # Rate limiting: check recent OTP requests for this telegram_id (within 15 seconds)
    recent_cutoff = (datetime.utcnow() - timedelta(seconds=15)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "SELECT created_at FROM telegram_otps WHERE telegram_id = ? AND created_at > ? ORDER BY id DESC LIMIT 1;",
        (cleaned_id, recent_cutoff)
    )
    recent = cursor.fetchone()
    if recent:
        return {
            "success": False,
            "message": "Please wait 15 seconds before requesting a new OTP."
        }

    # Generate cryptographically secure 6-digit OTP
    otp_code = f"{secrets.randbelow(900000) + 100000}"
    expires_at = (datetime.utcnow() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")

    # Invalidate previous unverified OTPs for this telegram_id
    cursor.execute(
        "UPDATE telegram_otps SET verified = 2 WHERE telegram_id = ? AND verified = 0;",
        (cleaned_id,)
    )

    # Insert new OTP record
    cursor.execute(
        """
        INSERT INTO telegram_otps (telegram_id, otp_code, expires_at, verified, attempts)
        VALUES (?, ?, ?, 0, 0);
        """,
        (cleaned_id, otp_code, expires_at)
    )
    db.commit()

    bot_token = get_telegram_bot_token()
    bot_username = get_telegram_bot_username()

    if not bot_token:
        # Development / Fallback mode when bot token has not been configured in env or settings yet
        logger.warning(f"[Telegram OTP] No TELEGRAM_BOT_TOKEN set. Dev OTP generated for {cleaned_id}: {otp_code}")
        return {
            "success": True,
            "message": f"Demo Mode (Bot token not yet configured): Your test OTP is {otp_code}. Enter this code below to proceed.",
            "dev_otp": otp_code,
            "is_demo": True
        }

    # Dispatch to Telegram Bot API
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    message_text = (
        f"🔐 <b>{config.PLATFORM_NAME} Verification Code</b>\n\n"
        f"Your one-time authentication code is:\n"
        f"👉 <code>{otp_code}</code> 👈\n\n"
        f"⏱ <i>This code expires in 10 minutes. Never share this code with anyone.</i>"
    )

    try:
        resp = requests.post(
            url,
            json={
                "chat_id": cleaned_id,
                "text": message_text,
                "parse_mode": "HTML"
            },
            timeout=8
        )
        res_data = resp.json()

        if resp.status_code == 200 and res_data.get("ok"):
            logger.info(f"[Telegram OTP] Successfully sent OTP to Telegram ID {cleaned_id}")
            return {
                "success": True,
                "message": f"6-digit verification code sent to Telegram ID {cleaned_id}."
            }

        # Handle common Telegram API errors with friendly, actionable instructions
        description = res_data.get("description", "Unknown error")
        error_code = res_data.get("error_code")

        logger.error(f"[Telegram OTP Error] Code {error_code}: {description}")

        if "chat not found" in description.lower():
            bot_link = f"https://t.me/{bot_username}" if bot_username else "our Telegram bot"
            return {
                "success": False,
                "message": (
                    f"Telegram could not deliver the message. Please open {bot_link}, "
                    f"click 'START', and then click 'Send OTP' again."
                )
            }
        elif "blocked" in description.lower():
            return {
                "success": False,
                "message": "It looks like you blocked our Telegram bot. Please unblock it to receive your verification OTP."
            }
        elif "not found" in description.lower():
            return {
                "success": False,
                "message": "Telegram Bot Token is invalid or expired. Please check your Bot Token from @BotFather in Admin Settings."
            }
        else:
            return {
                "success": False,
                "message": f"Telegram Bot response: {description}"
            }

    except requests.exceptions.RequestException as e:
        logger.exception(f"[Telegram OTP Exception] Network error connecting to Telegram: {e}")
        return {
            "success": False,
            "message": "Could not connect to Telegram Bot API. Please check network or try again shortly."
        }

def verify_telegram_otp(telegram_id: str, otp_code: str) -> tuple[bool, str]:
    """
    Verifies a user-submitted 6-digit OTP against the active record for their Telegram ID.
    Returns (is_valid: bool, message: str).
    """
    cleaned_id = str(telegram_id).strip()
    cleaned_code = str(otp_code).strip()

    if not cleaned_id or not cleaned_code:
        return False, "Both Telegram User ID and 6-digit OTP are required."

    if len(cleaned_code) != 6 or not cleaned_code.isdigit():
        return False, "OTP must be a 6-digit number."

    db = get_db()
    cursor = db.cursor()

    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        """
        SELECT id, otp_code, attempts, expires_at 
        FROM telegram_otps 
        WHERE telegram_id = ? AND verified = 0 AND expires_at > ?
        ORDER BY id DESC LIMIT 1;
        """,
        (cleaned_id, now_str)
    )
    record = cursor.fetchone()

    if not record:
        return False, "Verification code has expired or was not requested. Please click 'Send OTP' to request a new code."

    # Check maximum failed attempts
    if record["attempts"] >= 5:
        cursor.execute("UPDATE telegram_otps SET verified = 2 WHERE id = ?;", (record["id"],))
        db.commit()
        return False, "Too many incorrect attempts. Please request a new OTP code."

    if record["otp_code"] != cleaned_code:
        cursor.execute("UPDATE telegram_otps SET attempts = attempts + 1 WHERE id = ?;", (record["id"],))
        db.commit()
        remaining = 4 - record["attempts"]
        return False, f"Incorrect verification code. {remaining} attempt(s) remaining."

    # Mark OTP as successfully verified
    cursor.execute("UPDATE telegram_otps SET verified = 1 WHERE id = ?;", (record["id"],))
    db.commit()

    return True, "Verification successful."
