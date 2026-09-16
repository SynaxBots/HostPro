from database import get_db

def create_notification(user_id, title, message, notif_type="info", server_id=None):
    """Creates a user notification."""
    try:
        db = get_db()
        db.execute("""
        INSERT INTO notifications (user_id, server_id, title, message, type)
        VALUES (?, ?, ?, ?, ?)
        """, (user_id, server_id, title, message, notif_type))
        db.commit()
        return True
    except Exception as e:
        print(f"[Notification Error] {e}")
        return False

def get_user_notifications(user_id, limit=20):
    """Retrieves notifications for user."""
    db = get_db()
    cursor = db.execute("""
    SELECT n.*, s.name as server_name 
    FROM notifications n
    LEFT JOIN servers s ON n.server_id = s.id
    WHERE n.user_id = ?
    ORDER BY n.created_at DESC
    LIMIT ?
    """, (user_id, limit))
    return cursor.fetchall()

def get_unread_count(user_id):
    """Returns unread notifications count."""
    db = get_db()
    row = db.execute("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0", (user_id,)).fetchone()
    return row[0] if row else 0

def mark_all_read(user_id):
    """Marks all notifications as read for user."""
    db = get_db()
    db.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (user_id,))
    db.commit()

def mark_all_notifications_read(user_id):
    """Alias for mark_all_read."""
    return mark_all_read(user_id)
