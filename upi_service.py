import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
import ssl
import math

from database import get_db
from security import log_activity


# ============================================================
# UPI CONFIGURATION
# ============================================================

UPI_VPA = "AbhishekXsynax@fam"
UPI_PAYEE_NAME = "Python Hosting Platform"


# ============================================================
# PAYMENT VERIFICATION API
# ============================================================
#
# The API is called ONLY with purpose.
#
# Example:
#
# https://paypapi.vercel.app?purpose=AddFunds583729164205
#
# IMPORTANT:
#
# The local payment reference is:
#
#     583729164205
#
# But the API purpose is:
#
#     AddFunds583729164205
#
# NO merchant ID.
# NO UTR parameter.
# NO txn_id parameter.
#
# ============================================================

VERIFY_API_BASE = "https://payzapi.vercel.app"

# API can normally take around 20 seconds.
VERIFY_TIMEOUT = 35


# ============================================================
# PURPOSE PREFIX
# ============================================================
#
# This prefix is used ONLY when communicating with the
# verification API.
#
# Example:
#
# Local reference:
#     583729164205
#
# API purpose:
#     AddFunds583729164205
#
# ============================================================

VERIFY_PURPOSE_PREFIX = "ADDFUNDS"


# ============================================================
# ANTI-SPAM VERIFICATION LOCK
# ============================================================
#
# {
#     purpose: last_checked_timestamp
# }
#
# The local 12-digit purpose is used as the lock key.
#
# ============================================================

_verification_locks = {}


# ============================================================
# GENERATE PURPOSE
# ============================================================

def generate_purpose():
    """
    Generate an exactly 12-digit random numeric payment
    reference.

    Example:

        583729164205

    This value is stored in the database and used as the
    local payment reference.

    When communicating with the verification API, the
    AddFunds prefix is added:

        AddFunds583729164205
    """

    return str(
        random.randint(
            100000000000,
            999999999999
        )
    )


# ============================================================
# CREATE UPI ORDER
# ============================================================

def create_upi_order(user_id, amount_inr):
    """
    Create a pending UPI payment order.

    PAYMENT FLOW:

        1. Generate exactly 12 random numeric digits.
        2. Store those digits as the local payment reference.
        3. Put the 12 digits into UPI `tn`.
        4. User makes the payment.
        5. User clicks Paid.
        6. Verification API is called with:

               ?purpose=AddFunds<12-digit-reference>

        7. API must return:
               status = verified

        8. API returned purpose must equal:
               AddFunds<12-digit-reference>

        9. ONLY API `amount` is credited.

    The API's UTR and txn_id are never used for verification.
    """

    # ========================================================
    # VALIDATE AMOUNT
    # ========================================================

    try:
        amount_inr = float(amount_inr)

    except (TypeError, ValueError):
        return None, "Invalid deposit amount."

    # Reject NaN and infinity.

    if not math.isfinite(amount_inr):
        return None, "Invalid deposit amount."

    if amount_inr <= 0:
        return None, "Deposit amount must be greater than ₹0."

    # Round amount for payment creation.

    amount_inr = round(amount_inr, 2)

    if amount_inr <= 0:
        return None, "Deposit amount must be greater than ₹0."

    db = get_db()

    # ========================================================
    # GENERATE UNIQUE 12-DIGIT PURPOSE
    # ========================================================

    purpose = None

    for _ in range(20):

        candidate = generate_purpose()

        # The existing database column is named `utr`.
        #
        # For compatibility, this column stores the generated
        # 12-digit payment reference.
        #
        # It does NOT store the bank UTR.

        exists = db.execute(
            """
            SELECT id
            FROM upi_orders
            WHERE utr = ?
            """,
            (candidate,)
        ).fetchone()

        if not exists:
            purpose = candidate
            break

    if purpose is None:

        return None, (
            "Unable to generate a unique payment reference. "
            "Please try again."
        )

    # ========================================================
    # GENERATE UPI PAYMENT LINK
    # ========================================================
    #
    # Example:
    #
    # upi://pay?
    # pa=paytm.s2znl0o@pty
    # &pn=Python%20Hosting%20Platform
    # &am=2.00
    # &cu=INR
    # &tn=583729164205
    #
    # IMPORTANT:
    #
    # UPI `tn` contains ONLY the 12-digit reference.
    #
    # It does NOT contain:
    #
    #     AddFunds
    #
    # Therefore:
    #
    #     tn=583729164205
    #
    # Verification API later receives:
    #
    #     purpose=AddFunds583729164205
    #
    # ========================================================

    upi_uri = (
        "upi://pay"
        f"?pa={urllib.parse.quote(UPI_VPA, safe='@')}"
        f"&pn={urllib.parse.quote(UPI_PAYEE_NAME)}"
        f"&am={amount_inr:.2f}"
        "&cu=INR"
        f"&tn={purpose}"
    )

    # ========================================================
    # SAVE ORDER
    # ========================================================

    try:

        cursor = db.execute(
            """
            INSERT INTO upi_orders
                (
                    user_id,
                    utr,
                    expected_amount,
                    status
                )
            VALUES
                (
                    ?,
                    ?,
                    ?,
                    'pending'
                )
            """,
            (
                user_id,
                purpose,
                amount_inr
            )
        )

        db.commit()

        order_id = cursor.lastrowid

        return {
            "order_id": order_id,

            # ------------------------------------------------
            # Compatibility
            # ------------------------------------------------
            #
            # Old callers may expect "utr".
            #
            # This is NOT a bank UTR.
            # It is the generated 12-digit purpose/reference.
            #
            "utr": purpose,

            # ------------------------------------------------
            # New/reference names
            # ------------------------------------------------

            "purpose": purpose,
            "tn": purpose,

            # ------------------------------------------------
            # Payment information
            # ------------------------------------------------

            "amount": amount_inr,
            "vpa": UPI_VPA,
            "payee_name": UPI_PAYEE_NAME,
            "upi_uri": upi_uri
        }, None

    except Exception as e:

        db.rollback()

        return None, str(e)


# ============================================================
# GET UPI ORDER
# ============================================================

def get_upi_order(user_id, purpose):
    """
    Retrieve a UPI order using:

        user_id + local 12-digit purpose

    The database column `utr` is retained for compatibility.

    Its value is the generated 12-digit purpose, NOT the
    bank transaction UTR.
    """

    if purpose is None:
        return None

    purpose = str(purpose).strip()

    # ========================================================
    # VALIDATE LOCAL PURPOSE
    # ========================================================

    if (
        len(purpose) != 12
        or not purpose.isdigit()
    ):
        return None

    db = get_db()

    return db.execute(
        """
        SELECT *
        FROM upi_orders
        WHERE user_id = ?
          AND utr = ?
        """,
        (
            user_id,
            purpose
        )
    ).fetchone()


# ============================================================
# VERIFY AND CREDIT UPI PAYMENT
# ============================================================

def verify_and_credit_upi_payment(user_id, purpose):
    """
    Verify and credit a UPI payment.

    ========================================================
    LOCAL PAYMENT REFERENCE
    ========================================================

    Example:

        583729164205

    ========================================================
    API PURPOSE
    ========================================================

    The API receives:

        AddFunds583729164205

    Therefore the request is:

        https://paypapi.vercel.app?purpose=AddFunds583729164205

    ========================================================
    VERIFICATION RULE
    ========================================================

    The payment is matched ONLY using:

        API response `purpose`

    Expected:

        AddFunds + local 12-digit purpose

    The returned:

        utr
        txn_id

    are NEVER used to verify or match the order.

    ========================================================
    AMOUNT RULE
    ========================================================

    The wallet receives ONLY:

        API response -> amount

    Example:

        QR amount = ₹10
        API amount = ₹7

        Wallet receives ₹7.

    Example:

        QR amount = ₹10
        API amount = ₹15

        Wallet receives ₹15.

    The expected QR amount is NOT used to determine the
    credited amount.
    """

    # ========================================================
    # VALIDATE PURPOSE
    # ========================================================

    if purpose is None:

        return {
            "success": False,
            "message": "Invalid payment reference."
        }

    purpose = str(purpose).strip()

    # ========================================================
    # LOCAL PURPOSE MUST BE EXACTLY 12 DIGITS
    # ========================================================

    if (
        len(purpose) != 12
        or not purpose.isdigit()
    ):

        return {
            "success": False,
            "message": "Invalid payment reference."
        }

    # ========================================================
    # BUILD API PURPOSE
    # ========================================================
    #
    # Local:
    #
    #     583729164205
    #
    # API:
    #
    #     AddFunds583729164205
    #
    # ========================================================

    api_purpose = (
        f"{VERIFY_PURPOSE_PREFIX}{purpose}"
    )

    # ========================================================
    # ANTI-SPAM LOCK
    # ========================================================

    now = time.time()

    last_check = _verification_locks.get(
        purpose,
        0
    )

    if now - last_check < 3:

        return {
            "success": False,
            "message": (
                "Verification is already in progress. "
                "Please wait a moment."
            )
        }

    _verification_locks[purpose] = now

    db = get_db()

    try:

        # ====================================================
        # FIND ORDER USING LOCAL PURPOSE
        # ====================================================
        #
        # The API prefix is NOT stored in the database.
        #
        # Database:
        #
        #     583729164205
        #
        # API:
        #
        #     AddFunds583729164205
        #
        # ====================================================

        order = db.execute(
            """
            SELECT *
            FROM upi_orders
            WHERE utr = ?
            """,
            (purpose,)
        ).fetchone()

        if not order:

            return {
                "success": False,
                "message": (
                    "Payment order not found."
                )
            }

        # ====================================================
        # CHECK USER
        # ====================================================

        if order["user_id"] != user_id:

            return {
                "success": False,
                "message": (
                    "Unauthorized access to this payment."
                )
            }

        # ====================================================
        # CHECK ALREADY CREDITED
        # ====================================================

        if order["status"] == "success":

            actual_amount = float(
                order["actual_amount"] or 0
            )

            return {
                "success": True,
                "already_credited": True,
                "message": (
                    "This payment has already been credited "
                    f"(₹{actual_amount:,.2f})."
                ),
                "amount_added": actual_amount
            }

        # ====================================================
        # CALL PAYMENT VERIFICATION API
        # ====================================================
        #
        # ONLY:
        #
        #     ?purpose=AddFunds<12-digit-reference>
        #
        # is sent.
        #
        # NEVER:
        #
        #     ?utr=
        #
        #     ?txn_id=
        #
        #     ?mid=
        #
        # ====================================================

        api_url = (
            f"{VERIFY_API_BASE}"
            f"?purpose={urllib.parse.quote(api_purpose)}"
        )

        try:

            request = urllib.request.Request(
                api_url,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 "
                        "(Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36"
                    ),
                    "Accept": "application/json"
                },
                method="GET"
            )

            # =================================================
            # SSL CONTEXT
            # =================================================
            #
            # This keeps the original behavior.
            #
            # NOTE:
            # Disabling certificate verification is less secure
            # than normal TLS verification.
            #
            # =================================================

            ssl_context = ssl.create_default_context()

            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            # =================================================
            # API REQUEST
            # =================================================

            with urllib.request.urlopen(
                request,
                context=ssl_context,
                timeout=VERIFY_TIMEOUT
            ) as response:

                raw_body = response.read().decode(
                    "utf-8",
                    errors="replace"
                )

                data = json.loads(raw_body)

        # ====================================================
        # HTTP ERROR
        # ====================================================

        except urllib.error.HTTPError as e:

            return {
                "success": False,
                "message": (
                    f"Payment API returned HTTP {e.code}. "
                    "Please try again."
                )
            }

        # ====================================================
        # CONNECTION ERROR
        # ====================================================

        except urllib.error.URLError:

            return {
                "success": False,
                "message": (
                    "Unable to reach payment verification server. "
                    "Please try again."
                )
            }

        # ====================================================
        # TIMEOUT
        # ====================================================

        except TimeoutError:

            return {
                "success": False,
                "message": (
                    "Verification timed out. "
                    "Please click Paid again."
                )
            }

        # ====================================================
        # INVALID JSON
        # ====================================================

        except json.JSONDecodeError:

            return {
                "success": False,
                "message": (
                    "Payment API returned an invalid response."
                )
            }

        # ====================================================
        # OTHER API ERROR
        # ====================================================

        except Exception:

            return {
                "success": False,
                "message": (
                    "Unable to verify payment right now. "
                    "Please try again."
                )
            }

        # ====================================================
        # VALIDATE API RESPONSE
        # ====================================================

        if not isinstance(data, dict):

            return {
                "success": False,
                "message": (
                    "Invalid response from payment server."
                )
            }

        # ====================================================
        # STATUS MUST BE VERIFIED
        # ====================================================

        status = str(
            data.get("status", "")
        ).strip().lower()

        if status != "verified":

            return {
                "success": False,
                "message": (
                    "Payment not received yet. "
                    "Please wait and click Paid again."
                )
            }

        # ====================================================
        # PURPOSE MUST MATCH
        # ====================================================
        #
        # THIS IS THE ONLY PAYMENT MATCHING CHECK.
        #
        # Expected API purpose:
        #
        #     AddFunds583729164205
        #
        # Returned API purpose must be exactly the same.
        #
        # IMPORTANT:
        #
        # We DO NOT check:
        #
        #     data["utr"]
        #
        # or:
        #
        #     data["txn_id"]
        #
        # ====================================================

        returned_purpose = str(
            data.get("purpose", "")
        ).strip()

        if returned_purpose != api_purpose:

            return {
                "success": False,
                "message": (
                    "Payment purpose does not match "
                    "this payment order."
                )
            }

        # ====================================================
        # GET ACTUAL PAID AMOUNT
        # ====================================================

        try:

            paid_amount = float(
                data.get("amount", 0)
            )

        except (TypeError, ValueError):

            paid_amount = 0.0

        # ====================================================
        # VALIDATE AMOUNT
        # ====================================================

        if not math.isfinite(paid_amount):

            return {
                "success": False,
                "message": (
                    "Payment API returned an invalid amount."
                )
            }

        if paid_amount <= 0:

            return {
                "success": False,
                "message": (
                    "Payment API returned an invalid amount."
                )
            }

        paid_amount = round(
            paid_amount,
            2
        )

        if paid_amount <= 0:

            return {
                "success": False,
                "message": (
                    "Payment API returned an invalid amount."
                )
            }

        # ====================================================
        # API UTR / TXN ID
        # ====================================================
        #
        # These are stored only as payment information for
        # history/reference.
        #
        # They are NEVER used for verification.
        #
        # ====================================================

        api_utr = str(
            data.get("utr", "")
        ).strip()

        api_txn_id = str(
            data.get("txn_id", "")
        ).strip()

        # ====================================================
        # CREDIT PAYMENT
        # ====================================================

        try:

            # =================================================
            # CREDIT ONLY API AMOUNT
            # =================================================
            #
            # No comparison with expected_amount.
            #
            # No comparison with QR amount.
            #
            # API amount is authoritative.
            #
            # =================================================

            cursor = db.execute(
                """
                UPDATE users
                SET wallet_balance =
                    wallet_balance + ?
                WHERE id = ?
                """,
                (
                    paid_amount,
                    user_id
                )
            )

            # =================================================
            # MAKE SURE USER EXISTS
            # =================================================

            if cursor.rowcount == 0:

                db.rollback()

                return {
                    "success": False,
                    "message": (
                        "User account was not found."
                    )
                }

            # =================================================
            # UPDATE UPI ORDER
            # =================================================

            now_str = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.gmtime()
            )

            order_cursor = db.execute(
                """
                UPDATE upi_orders
                SET
                    status = 'success',
                    actual_amount = ?,
                    response_json = ?,
                    updated_at = ?
                WHERE user_id = ?
                  AND utr = ?
                  AND status = 'pending'
                """,
                (
                    paid_amount,
                    json.dumps(
                        data,
                        ensure_ascii=False
                    ),
                    now_str,
                    user_id,
                    purpose
                )
            )

            # =================================================
            # IMPORTANT:
            #
            # If another request already changed the order
            # from pending to success, do not create another
            # transaction or credit again.
            # =================================================

            if order_cursor.rowcount == 0:

                db.rollback()

                # Re-check whether the order was already
                # credited.

                existing_order = db.execute(
                    """
                    SELECT *
                    FROM upi_orders
                    WHERE user_id = ?
                      AND utr = ?
                    """,
                    (
                        user_id,
                        purpose
                    )
                ).fetchone()

                if (
                    existing_order
                    and existing_order["status"] == "success"
                ):

                    existing_amount = float(
                        existing_order["actual_amount"] or 0
                    )

                    return {
                        "success": True,
                        "already_credited": True,
                        "message": (
                            "This payment has already been "
                            "credited "
                            f"(₹{existing_amount:,.2f})."
                        ),
                        "amount_added": existing_amount
                    }

                return {
                    "success": False,
                    "message": (
                        "Payment could not be finalized. "
                        "Please try again."
                    )
                }

            # =================================================
            # TRANSACTION HISTORY
            # =================================================
            #
            # API txn_id / UTR is used ONLY as a history
            # reference.
            #
            # It is NOT used for payment verification.
            #
            # =================================================

            transaction_ref = (
                api_txn_id
                or api_utr
                or purpose
            )

            description = (
                f"UPI Deposit "
                f"(Purpose: {purpose})"
            )

            db.execute(
                """
                INSERT INTO transactions
                    (
                        user_id,
                        transaction_ref,
                        type,
                        amount_inr,
                        status,
                        description,
                        metadata_json
                    )
                VALUES
                    (
                        ?,
                        ?,
                        'deposit',
                        ?,
                        'success',
                        ?,
                        ?
                    )
                """,
                (
                    user_id,
                    transaction_ref,
                    paid_amount,
                    description,
                    json.dumps(
                        data,
                        ensure_ascii=False
                    )
                )
            )

            # =================================================
            # NOTIFICATION
            # =================================================

            notification_message = (
                f"₹{paid_amount:,.2f} "
                "added to wallet via UPI."
            )

            db.execute(
                """
                INSERT INTO notifications
                    (
                        user_id,
                        title,
                        message,
                        type
                    )
                VALUES
                    (
                        ?,
                        ?,
                        ?,
                        ?
                    )
                """,
                (
                    user_id,
                    "Wallet Top-Up Credited",
                    notification_message,
                    "success"
                )
            )

            # =================================================
            # ACTIVITY LOG
            # =================================================

            log_activity(
                user_id,
                "upi_deposit",
                (
                    f"Credited ₹{paid_amount:.2f} "
                    f"(Purpose: {purpose})"
                )
            )

            # =================================================
            # COMMIT
            # =================================================

            db.commit()

        except Exception as e:

            db.rollback()

            return {
                "success": False,
                "message": (
                    "Database error while crediting payment: "
                    f"{str(e)}"
                )
            }

        # ====================================================
        # GET UPDATED BALANCE
        # ====================================================

        user_row = db.execute(
            """
            SELECT wallet_balance
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if user_row:

            new_balance = round(
                float(
                    user_row["wallet_balance"]
                ),
                2
            )

        else:

            new_balance = paid_amount

        # ====================================================
        # SUCCESS RESPONSE
        # ====================================================

        return {
            "success": True,

            "message": (
                f"Payment Successful! "
                f"₹{paid_amount:,.2f} "
                "has been added to your wallet balance."
            ),

            "amount_added": paid_amount,
            "new_balance": new_balance,

            # ------------------------------------------------
            # LOCAL PAYMENT REFERENCE
            # ------------------------------------------------

            "purpose": purpose,
            "tn": purpose,

            # ------------------------------------------------
            # API PURPOSE
            # ------------------------------------------------
            #
            # This is what was actually sent to paypapi.
            #
            "api_purpose": api_purpose,

            # ------------------------------------------------
            # API UTR / TXN ID
            # ------------------------------------------------
            #
            # Returned for display/history only.
            #
            # NEVER used for verification.
            #
            "utr": api_utr,
            "txn_id": api_txn_id
        }

    finally:

        # ====================================================
        # REMOVE TEMPORARY LOCK
        # ====================================================

        _verification_locks.pop(
            purpose,
            None
        )