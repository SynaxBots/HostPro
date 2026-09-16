import secrets
from datetime import datetime, timedelta
from database import get_db
from security import log_activity, log_audit
import config

def get_user_balance(user_id):
    """Returns the current wallet balance in INR."""
    db = get_db()
    row = db.execute("SELECT wallet_balance FROM users WHERE id = ?", (user_id,)).fetchone()
    return round(row["wallet_balance"] if row else 0.0, 2)

def deposit_funds(user_id, amount_inr, description="Wallet Balance Top-Up", method="UPI / NetBanking"):
    """
    Adds funds to user wallet and creates an immutable transaction record.
    """
    if amount_inr <= 0:
        return False, "Deposit amount must be greater than ₹0"
        
    db = get_db()
    tx_ref = f"DEP-{secrets.token_hex(6).upper()}"
    
    try:
        # Atomic balance update
        db.execute("UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?", (amount_inr, user_id))
        db.execute("""
        INSERT INTO transactions (user_id, transaction_ref, type, amount_inr, status, description, metadata_json)
        VALUES (?, ?, 'deposit', ?, 'success', ?, ?)
        """, (user_id, tx_ref, amount_inr, description, f'{{"method": "{method}"}}'))
        
        # Notification
        db.execute("""
        INSERT INTO notifications (user_id, title, message, type)
        VALUES (?, ?, ?, ?)
        """, (user_id, "Wallet Credited", f"₹{amount_inr:,.2f} has been added to your wallet balance.", "success"))
        
        log_activity(user_id, "wallet_deposit", f"Deposited ₹{amount_inr:,.2f} via {method}")
        db.commit()
        return True, tx_ref
    except Exception as e:
        db.rollback()
        return False, str(e)

def purchase_plan(user_id, plan_id):
    """
    Purchases a hosting plan using wallet balance.
    Creates subscription and records immutable transaction.
    """
    db = get_db()
    user = db.execute("SELECT id, wallet_balance, status FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or user["status"] != "active":
        return False, "User account is inactive or not found"
        
    plan = db.execute("SELECT * FROM plans WHERE id = ? AND is_active = 1", (plan_id,)).fetchone()
    if not plan:
        return False, "Selected plan is unavailable or disabled"
        
    price = plan["price_inr"]
    if user["wallet_balance"] < price:
        needed = price - user["wallet_balance"]
        return False, f"Insufficient wallet balance. Please add at least ₹{needed:,.2f} to proceed."
        
    tx_ref = f"SUB-{secrets.token_hex(6).upper()}"
    now = datetime.utcnow()
    expiry = now + timedelta(days=plan["billing_days"])
    
    try:
        # Deduct wallet
        db.execute("UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?", (price, user_id))
        
        # Create transaction record
        db.execute("""
        INSERT INTO transactions (user_id, transaction_ref, type, amount_inr, status, description, metadata_json)
        VALUES (?, ?, 'plan_purchase', ?, 'success', ?, ?)
        """, (user_id, tx_ref, price, f"Subscription to {plan['name']}", f'{{"plan_id": {plan_id}, "billing_days": {plan["billing_days"]}}}'))
        
        # Create subscription
        cursor = db.execute("""
        INSERT INTO subscriptions (user_id, plan_id, status, start_date, expiry_date, is_admin_granted)
        VALUES (?, ?, 'active', ?, ?, 0)
        """, (user_id, plan_id, now.strftime("%Y-%m-%d %H:%M:%S"), expiry.strftime("%Y-%m-%d %H:%M:%S")))
        sub_id = cursor.lastrowid
        
        # Notification
        db.execute("""
        INSERT INTO notifications (user_id, title, message, type)
        VALUES (?, ?, ?, ?)
        """, (user_id, "Plan Activated", f"Successfully subscribed to {plan['name']}. Valid for {plan['billing_days']} days.", "success"))
        
        log_activity(user_id, "plan_purchase", f"Purchased {plan['name']} for ₹{price:,.2f}")
        db.commit()
        return True, sub_id
    except Exception as e:
        db.rollback()
        return False, f"Purchase error: {str(e)}"

def admin_grant_subscription(admin_id, user_id, plan_id, days=30, custom_ram=None, custom_storage=None, custom_bandwidth=None, custom_cpu=None):
    """
    Allows admin to grant or override a subscription for any user with custom resources.
    """
    db = get_db()
    plan = db.execute("SELECT name FROM plans WHERE id = ?", (plan_id,)).fetchone()
    if not plan:
        return False, "Plan not found"
        
    now = datetime.utcnow()
    expiry = now + timedelta(days=int(days))
    
    try:
        cursor = db.execute("""
        INSERT INTO subscriptions (
            user_id, plan_id, status, start_date, expiry_date, is_admin_granted,
            custom_ram_mb, custom_storage_mb, custom_bandwidth_mb, custom_cpu_cores
        ) VALUES (?, ?, 'active', ?, ?, 1, ?, ?, ?, ?)
        """, (
            user_id, plan_id, now.strftime("%Y-%m-%d %H:%M:%S"), expiry.strftime("%Y-%m-%d %H:%M:%S"),
            custom_ram, custom_storage, custom_bandwidth, custom_cpu
        ))
        sub_id = cursor.lastrowid
        
        # Notification to user
        db.execute("""
        INSERT INTO notifications (user_id, title, message, type)
        VALUES (?, ?, ?, ?)
        """, (user_id, "Admin Granted Subscription", f"An administrator has granted you an active '{plan['name']}' subscription valid for {days} days.", "info"))
        
        log_audit(admin_id, "grant_subscription", f"Granted {plan['name']} subscription for {days} days (Sub ID: {sub_id})", target_user_id=user_id)
        db.commit()
        return True, sub_id
    except Exception as e:
        db.rollback()
        return False, str(e)

def admin_adjust_wallet(admin_id, user_id, amount_inr, action="add", reason="Admin adjustment"):
    """
    Allows admin to manually add or deduct funds from a user's wallet with audit logging.
    """
    if amount_inr <= 0:
        return False, "Amount must be positive"
        
    db = get_db()
    user = db.execute("SELECT wallet_balance, username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return False, "User not found"
        
    tx_ref = f"ADM-{secrets.token_hex(6).upper()}"
    
    if action == "deduct":
        if user["wallet_balance"] < amount_inr:
            return False, f"User only has ₹{user['wallet_balance']:,.2f} in wallet"
        delta = -amount_inr
        tx_type = "admin_deduct"
        desc = f"Admin deduction: {reason}"
    else:
        delta = amount_inr
        tx_type = "admin_grant"
        desc = f"Admin credit: {reason}"
        
    try:
        db.execute("UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?", (delta, user_id))
        db.execute("""
        INSERT INTO transactions (user_id, transaction_ref, type, amount_inr, status, description, metadata_json)
        VALUES (?, ?, ?, ?, 'success', ?, ?)
        """, (user_id, tx_ref, tx_type, amount_inr, desc, f'{{"admin_id": {admin_id}, "reason": "{reason}"}}'))
        
        log_audit(admin_id, f"wallet_{action}", f"{action.capitalize()}ed ₹{amount_inr:,.2f} to {user['username']}'s wallet ({reason})", target_user_id=user_id)
        db.commit()
        return True, "Wallet updated successfully"
    except Exception as e:
        db.rollback()
        return False, str(e)

def add_wallet_funds(user_id, amount_inr, description="Wallet Balance Top-Up", method="UPI / NetBanking"):
    success, res = deposit_funds(user_id, amount_inr, description, method)
    return res if success else None

def purchase_subscription(user_id, plan_id):
    success, res = purchase_plan(user_id, plan_id)
    if success:
        return True, "Subscription activated successfully!"
    return False, str(res)

def get_user_subscriptions(user_id):
    """Returns active subscriptions for user with plan metadata and used server counts."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
    SELECT s.*, p.name as plan_name, p.price_inr, p.billing_days,
           p.ram_mb, p.cpu_cores, p.storage_mb, p.bandwidth_mb, p.max_servers,
           (SELECT COUNT(*) FROM servers srv WHERE srv.subscription_id = s.id) as used_servers
    FROM subscriptions s
    JOIN plans p ON s.plan_id = p.id
    WHERE s.user_id = ? AND s.status = 'active' AND datetime(s.expiry_date) > datetime('now')
    ORDER BY s.created_at DESC;
    """, (user_id,))
    return cursor.fetchall()
