import os
import shutil
import time
import zipfile
import io
from datetime import datetime
from security import resolve_safe_path, is_safe_path, safe_extract_zip
from resource_manager import check_storage_quota, update_server_storage
from process_manager import get_server_paths
from ai_inspector import inspect_code, inspect_file_on_disk, inspect_server_app_directory
import config

def format_size(size_bytes):
    """Converts bytes to human readable format (e.g. KB, MB, GB)."""
    if size_bytes is None or size_bytes <= 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}" if unit != 'B' else f"{int(size_bytes)} B"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"

def is_protected_sandbox_path(path_str):
    """
    Checks whether a relative or absolute path targets or is inside .sandbox_hook.
    Files and directories inside .sandbox_hook are protected system security components
    and CANNOT be edited, renamed, deleted, moved, or overwritten.
    """
    if not path_str:
        return False
    clean = str(path_str).replace("\\", "/").strip()
    norm = os.path.normpath(clean).replace("\\", "/").strip("/")
    parts = [p for p in norm.split("/") if p and p != "."]
    return ".sandbox_hook" in parts

def get_app_dir(user_id, server_id):
    """Returns the validated app directory path for a server."""
    paths = get_server_paths(user_id, server_id)
    return paths["app"]

def list_files(user_id, server_id, relative_path=""):
    """
    Returns files and directories inside relative_path for a server.
    """
    app_dir = get_app_dir(user_id, server_id)
    target_dir = resolve_safe_path(app_dir, relative_path) if relative_path else app_dir
    
    if not target_dir or not os.path.exists(target_dir) or not os.path.isdir(target_dir):
        return None, "Directory not found or invalid path"
        
    items = []
    try:
        entries = sorted(os.scandir(target_dir), key=lambda e: (not e.is_dir(), e.name.lower()))
        for entry in entries:
            is_dir = entry.is_dir()
            stat = entry.stat()
            size = stat.st_size if not is_dir else 0
            mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            
            # Compute relative path from app_dir
            rel = os.path.relpath(entry.path, app_dir).replace("\\", "/")
            ext = os.path.splitext(entry.name)[1].lower().lstrip(".")
            is_protected = is_protected_sandbox_path(rel) or entry.name == ".sandbox_hook"
            
            items.append({
                "name": entry.name,
                "relative_path": rel,
                "is_dir": is_dir,
                "size_bytes": size,
                "size_human": format_size(size) if not is_dir else "--",
                "modified": mtime,
                "extension": ext,
                "is_protected": is_protected
            })
            
        rel_current = os.path.relpath(target_dir, app_dir).replace("\\", "/")
        if rel_current == ".":
            rel_current = ""
            
        return {
            "current_path": rel_current,
            "items": items
        }, None
    except Exception as e:
        return None, str(e)

def read_file(user_id, server_id, relative_path):
    """Reads file text content safely."""
    app_dir = get_app_dir(user_id, server_id)
    file_path = resolve_safe_path(app_dir, relative_path)
    
    if not file_path or not os.path.exists(file_path) or os.path.isdir(file_path):
        return None, "File does not exist or path is invalid."
        
    # Prevent opening huge binary files into text editor
    size = os.path.getsize(file_path)
    if size > 5 * 1024 * 1024:
        return None, f"File is too large ({format_size(size)}) to view in browser editor (Max 5MB)."
        
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return {
            "name": os.path.basename(file_path),
            "relative_path": relative_path.replace("\\", "/"),
            "content": content,
            "size_bytes": size,
            "size_human": format_size(size),
            "is_protected": is_protected_sandbox_path(relative_path)
        }, None
    except Exception as e:
        return None, f"Error reading file: {str(e)}"

def save_file(user_id, server_id, relative_path, content):
    """Saves text content to a file with AI security inspection and sandbox protection."""
    if is_protected_sandbox_path(relative_path):
        return False, "Access Denied: Files inside '.sandbox_hook' are protected system security components and cannot be edited or modified."

    app_dir = get_app_dir(user_id, server_id)
    file_path = resolve_safe_path(app_dir, relative_path)
    
    if not file_path:
        return False, "Invalid target path (path traversal forbidden)."

    # AI Security Inspection before saving
    filename = os.path.basename(file_path)
    inspection = inspect_code(content, filename)
    if not inspection["allowed"]:
        return False, f"AI Security Inspection Blocked Save: {inspection['reason']} [{inspection['violation_rule']}]"
        
    content_bytes = content.encode("utf-8")
    additional = len(content_bytes) - (os.path.getsize(file_path) if os.path.exists(file_path) else 0)
    
    allowed, cur_mb, lim_mb = check_storage_quota(user_id, server_id, max(0, additional))
    if not allowed:
        return False, f"Storage quota exceeded! ({cur_mb} MB / {lim_mb} MB)"
        
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        update_server_storage(user_id, server_id)
        return True, "File saved successfully."
    except Exception as e:
        return False, f"Error saving file: {str(e)}"

def create_item(*args, **kwargs):
    """
    Creates a new empty file or folder.
    Supports signatures:
      create_item(server_id, relative_path, is_dir=False)
      create_item(user_id, server_id, relative_path, is_dir=False)
    """
    if len(args) == 2:
        server_id, relative_path = args[0], args[1]
        user_id = _get_server_user_id(server_id)
        is_dir = kwargs.get('is_dir', False)
    elif len(args) == 3:
        if isinstance(args[2], bool):
            server_id, relative_path, is_dir = args[0], args[1], args[2]
            user_id = _get_server_user_id(server_id)
        else:
            user_id, server_id, relative_path = args[0], args[1], args[2]
            is_dir = kwargs.get('is_dir', False)
    elif len(args) >= 4:
        user_id, server_id, relative_path, is_dir = args[0], args[1], args[2], args[3]
    else:
        return False, "Invalid arguments provided for item creation"

    app_dir = get_app_dir(user_id, server_id)
    if is_protected_sandbox_path(relative_path):
        return False, "Access Denied: Cannot create files or directories inside '.sandbox_hook'."
        
    target = resolve_safe_path(app_dir, relative_path)
    
    if not target:
        return False, "Invalid path (traversal forbidden)"
        
    if os.path.exists(target):
        return False, "An item with this name already exists"
        
    try:
        if is_dir:
            os.makedirs(target, exist_ok=True)
            return True, "Folder created successfully"
        else:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w", encoding="utf-8") as f:
                f.write("")
            update_server_storage(user_id, server_id)
            return True, "File created successfully"
    except Exception as e:
        return False, f"Creation failed: {str(e)}"

def rename_item(*args, **kwargs):
    """
    Renames a file or folder safely.
    Supports signatures:
      rename_item(server_id, old_rel_path, new_name)
      rename_item(user_id, server_id, old_rel_path, new_name)
    """
    if len(args) == 3:
        server_id, old_rel_path, new_name = args[0], args[1], args[2]
        user_id = _get_server_user_id(server_id)
    elif len(args) >= 4:
        user_id, server_id, old_rel_path, new_name = args[0], args[1], args[2], args[3]
    else:
        return False, "Invalid arguments provided for renaming"

    if is_protected_sandbox_path(old_rel_path) or is_protected_sandbox_path(new_name):
        return False, "Access Denied: '.sandbox_hook' and its contents are protected system components and cannot be renamed."

    app_dir = get_app_dir(user_id, server_id)
    old_path = resolve_safe_path(app_dir, old_rel_path)
    
    if not old_path or not os.path.exists(old_path):
        return False, "Item not found"
        
    clean_name = os.path.basename(new_name.strip())
    if not clean_name or "/" in clean_name or "\\" in clean_name or ".." in clean_name:
        return False, "Invalid file or folder name"
        
    parent_dir = os.path.dirname(old_path)
    new_path = os.path.join(parent_dir, clean_name)
    
    if os.path.exists(new_path):
        return False, f"An item named '{clean_name}' already exists in this folder"
        
    try:
        os.rename(old_path, new_path)
        # Check renamed file with AI security inspector
        if os.path.isfile(new_path):
            inspection = inspect_file_on_disk(new_path)
            if not inspection["allowed"]:
                # Revert rename
                os.rename(new_path, old_path)
                return False, f"Rename blocked by AI Security Inspector: {inspection['reason']} [{inspection['violation_rule']}]"
        update_server_storage(user_id, server_id)
        return True, "Item renamed successfully"
    except Exception as e:
        return False, str(e)

def delete_item(*args, **kwargs):
    """
    Deletes a file or directory safely.
    Supports signatures:
      delete_item(server_id, relative_path)
      delete_item(user_id, server_id, relative_path)
    """
    if len(args) == 2:
        server_id, relative_path = args[0], args[1]
        user_id = _get_server_user_id(server_id)
    elif len(args) >= 3:
        user_id, server_id, relative_path = args[0], args[1], args[2]
    else:
        return False, "Invalid arguments provided for deletion"

    if is_protected_sandbox_path(relative_path):
        return False, "Access Denied: '.sandbox_hook' and its contents are protected system components and cannot be deleted."

    app_dir = get_app_dir(user_id, server_id)
    target = resolve_safe_path(app_dir, relative_path)
    
    if not target or not os.path.exists(target):
        return False, "Item not found"
        
    # Prevent deleting the root app directory itself
    if target == app_dir:
        return False, "Cannot delete application root directory"
        
    try:
        if os.path.isdir(target):
            shutil.rmtree(target)
        else:
            os.remove(target)
        update_server_storage(user_id, server_id)
        return True, "Deleted successfully"
    except Exception as e:
        return False, str(e)

def handle_file_upload(user_id, server_id, relative_folder, file_storage):
    """Saves an uploaded file into the server application directory with AI inspection."""
    if is_protected_sandbox_path(relative_folder) or (file_storage and is_protected_sandbox_path(file_storage.filename)):
        return False, "Access Denied: Uploading into or modifying '.sandbox_hook' is strictly prohibited."

    app_dir = get_app_dir(user_id, server_id)
    target_folder = resolve_safe_path(app_dir, relative_folder) if relative_folder else app_dir
    
    if not target_folder or not os.path.isdir(target_folder):
        return False, "Invalid upload destination directory"
        
    filename = os.path.basename(file_storage.filename)
    if not filename or filename in (".", ".."):
        return False, "Invalid filename"
        
    file_path = os.path.join(target_folder, filename)
    if not is_safe_path(app_dir, file_path):
        return False, "Security error: invalid target path"
        
    # Read chunk and inspect content
    file_storage.seek(0, os.SEEK_END)
    file_size = file_storage.tell()
    file_storage.seek(0)
    
    allowed, cur_mb, lim_mb = check_storage_quota(user_id, server_id, file_size)
    if not allowed:
        return False, f"Storage quota exceeded! ({cur_mb} MB / {lim_mb} MB)"
        
    # Perform AI inspection on uploaded script
    try:
        preview_data = file_storage.read(150000)
        file_storage.seek(0)
        try:
            text_snippet = preview_data.decode("utf-8")
            inspection = inspect_code(text_snippet, filename)
            if not inspection["allowed"]:
                return False, f"AI Security Inspection Blocked Upload: {inspection['reason']} [{inspection['violation_rule']}]"
        except UnicodeDecodeError:
            # Binary file check
            ext = os.path.splitext(filename)[1].lower()
            if ext in (".exe", ".dll", ".so", ".bin", ".elf", ".pyarmor"):
                return False, f"AI Security Policy: Executable binary '{filename}' is not permitted."
    except Exception as e:
        pass
        
    try:
        file_storage.save(file_path)
        update_server_storage(user_id, server_id)
        return True, f"File '{filename}' uploaded successfully (Passed AI Inspection)"
    except Exception as e:
        return False, f"Upload error: {str(e)}"

def handle_zip_upload_and_extract(user_id, server_id, relative_folder, zip_storage):
    """Saves, inspects, and safely unpacks a ZIP archive into the destination directory."""
    if is_protected_sandbox_path(relative_folder):
        return False, "Access Denied: Cannot extract into '.sandbox_hook'."

    app_dir = get_app_dir(user_id, server_id)
    target_folder = resolve_safe_path(app_dir, relative_folder) if relative_folder else app_dir
    
    if not target_folder or not os.path.isdir(target_folder):
        return False, "Invalid upload destination directory"
        
    temp_zip = os.path.join(get_server_paths(user_id, server_id)["logs"], f"temp_{int(time.time())}.zip")
    try:
        zip_storage.save(temp_zip)
        file_count, total_unpacked = safe_extract_zip(temp_zip, target_folder)
        os.remove(temp_zip)
        
        # Post-extraction AI Security Scan of all extracted files
        scan_ok, scan_msg = inspect_server_app_directory(target_folder)
        if not scan_ok:
            # Security scan detected violation in extracted archive
            return False, f"ZIP Security Scan Failed: {scan_msg}"
            
        update_server_storage(user_id, server_id)
        return True, f"Extracted {file_count} files ({format_size(total_unpacked)}) successfully [AI Inspected & Clean]"
    except ValueError as ve:
        if os.path.exists(temp_zip):
            os.remove(temp_zip)
        return False, f"ZIP Security Validation Failed: {str(ve)}"
    except Exception as e:
        if os.path.exists(temp_zip):
            os.remove(temp_zip)
        return False, f"ZIP Extraction Error: {str(e)}"

def export_server_as_zip(user_id, server_id):
    """Creates an in-memory ZIP archive of the entire user app directory."""
    app_dir = get_app_dir(user_id, server_id)
    memory_file = io.BytesIO()
    
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(app_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, app_dir)
                zf.write(file_path, arcname)
                
    memory_file.seek(0)
    return memory_file

def _get_server_user_id(server_id):
    from database import get_db
    db = get_db()
    row = db.execute("SELECT user_id FROM servers WHERE id = ?", (server_id,)).fetchone()
    return row["user_id"] if row else 1

def list_directory_contents(server_id, relative_path=""):
    user_id = _get_server_user_id(server_id)
    res, err = list_files(user_id, server_id, relative_path)
    if err:
        return False, [], err
    return True, res.get("items", []), None

def read_file_content(server_id, relative_path):
    user_id = _get_server_user_id(server_id)
    res, err = read_file(user_id, server_id, relative_path)
    if err:
        return False, "", {}, err
    return True, res.get("content", ""), res, None

def write_file_content(server_id, relative_path, content):
    user_id = _get_server_user_id(server_id)
    success, msg = save_file(user_id, server_id, relative_path, content)
    return success, (None if success else msg)

def save_uploaded_file(server_id, file_storage, relative_folder=""):
    user_id = _get_server_user_id(server_id)
    success, msg = handle_file_upload(user_id, server_id, relative_folder, file_storage)
    return success, (None if success else msg)

def extract_zip_file(server_id, zip_bytes, relative_folder=""):
    if is_protected_sandbox_path(relative_folder):
        return False, 0, "Access Denied: Cannot extract into '.sandbox_hook'."

    user_id = _get_server_user_id(server_id)
    app_dir = get_app_dir(user_id, server_id)
    target_folder = resolve_safe_path(app_dir, relative_folder) if relative_folder else app_dir
    
    if not target_folder:
        return False, 0, "Invalid target folder"
        
    temp_zip = os.path.join(get_server_paths(user_id, server_id)["logs"], f"temp_{int(time.time())}.zip")
    try:
        with open(temp_zip, "wb") as f:
            f.write(zip_bytes)
        count, total = safe_extract_zip(temp_zip, target_folder)
        os.remove(temp_zip)
        
        # Post-extraction AI Security Scan
        scan_ok, scan_msg = inspect_server_app_directory(target_folder)
        if not scan_ok:
            return False, 0, f"ZIP Security Scan Failed: {scan_msg}"
            
        update_server_storage(user_id, server_id)
        return True, count, None
    except Exception as e:
        if os.path.exists(temp_zip):
            os.remove(temp_zip)
        return False, 0, str(e)

def create_zip_archive(server_id):
    user_id = _get_server_user_id(server_id)
    try:
        buf = export_server_as_zip(user_id, server_id)
        return True, buf, None
    except Exception as e:
        return False, None, str(e)

def copy_item(server_id, src_rel_path, dest_rel_folder):
    """Copies a file or folder from src_rel_path to dest_rel_folder."""
    if is_protected_sandbox_path(dest_rel_folder):
        return False, "Access Denied: Cannot copy items into '.sandbox_hook'."

    user_id = _get_server_user_id(server_id)
    app_dir = get_app_dir(user_id, server_id)
    src = resolve_safe_path(app_dir, src_rel_path)
    
    if not src or not os.path.exists(src):
        return False, "Source item not found"
        
    dest_dir = resolve_safe_path(app_dir, dest_rel_folder) if dest_rel_folder else app_dir
    if not dest_dir or not os.path.isdir(dest_dir):
        return False, "Destination directory invalid"
        
    base_name = os.path.basename(src)
    dest_target = os.path.join(dest_dir, base_name)
    
    # If already exists in destination, append suffix
    if os.path.exists(dest_target):
        name_no_ext, ext = os.path.splitext(base_name)
        counter = 1
        while os.path.exists(dest_target):
            dest_target = os.path.join(dest_dir, f"{name_no_ext}_copy{counter}{ext}")
            counter += 1
            
    if not is_safe_path(app_dir, dest_target):
        return False, "Invalid destination path"
        
    try:
        if os.path.isdir(src):
            shutil.copytree(src, dest_target)
        else:
            shutil.copy2(src, dest_target)
        update_server_storage(user_id, server_id)
        return True, f"Copied successfully to {os.path.relpath(dest_target, app_dir)}"
    except Exception as e:
        return False, f"Copy error: {str(e)}"

def move_item(server_id, src_rel_path, dest_rel_folder):
    """Moves a file or folder from src_rel_path to dest_rel_folder."""
    if is_protected_sandbox_path(src_rel_path) or is_protected_sandbox_path(dest_rel_folder):
        return False, "Access Denied: '.sandbox_hook' and its contents are protected system components and cannot be moved."

    user_id = _get_server_user_id(server_id)
    app_dir = get_app_dir(user_id, server_id)
    src = resolve_safe_path(app_dir, src_rel_path)
    
    if not src or not os.path.exists(src):
        return False, "Source item not found"
        
    dest_dir = resolve_safe_path(app_dir, dest_rel_folder) if dest_rel_folder else app_dir
    if not dest_dir or not os.path.isdir(dest_dir):
        return False, "Destination directory invalid"
        
    base_name = os.path.basename(src)
    dest_target = os.path.join(dest_dir, base_name)
    
    if os.path.abspath(src) == os.path.abspath(dest_target):
        return False, "Source and destination are identical"
        
    if os.path.exists(dest_target):
        return False, f"An item named '{base_name}' already exists in the target folder"
        
    if not is_safe_path(app_dir, dest_target):
        return False, "Invalid destination path"
        
    try:
        shutil.move(src, dest_target)
        update_server_storage(user_id, server_id)
        return True, f"Moved successfully to {os.path.relpath(dest_target, app_dir)}"
    except Exception as e:
        return False, f"Move error: {str(e)}"

def zip_selected_items(server_id, rel_paths, zip_name="archive.zip", dest_folder=""):
    """Creates a ZIP archive containing only the selected files and folders."""
    user_id = _get_server_user_id(server_id)
    app_dir = get_app_dir(user_id, server_id)
    
    if not rel_paths:
        return False, "No files or folders selected"
        
    dest_dir = resolve_safe_path(app_dir, dest_folder) if dest_folder else app_dir
    if not dest_dir or not os.path.isdir(dest_dir):
        dest_dir = app_dir
        
    clean_zip_name = os.path.basename(zip_name.strip())
    if not clean_zip_name.lower().endswith(".zip"):
        clean_zip_name += ".zip"
        
    target_zip_path = os.path.join(dest_dir, clean_zip_name)
    if os.path.exists(target_zip_path):
        name_no_ext, ext = os.path.splitext(clean_zip_name)
        counter = 1
        while os.path.exists(target_zip_path):
            target_zip_path = os.path.join(dest_dir, f"{name_no_ext}_{counter}{ext}")
            counter += 1
            
    if not is_safe_path(app_dir, target_zip_path):
        return False, "Invalid target archive path"
        
    try:
        with zipfile.ZipFile(target_zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for rel in rel_paths:
                item_path = resolve_safe_path(app_dir, rel)
                if not item_path or not os.path.exists(item_path):
                    continue
                if os.path.isdir(item_path):
                    for root, dirs, files in os.walk(item_path):
                        for f in files:
                            full_f = os.path.join(root, f)
                            arc = os.path.relpath(full_f, os.path.dirname(item_path))
                            zf.write(full_f, arc)
                else:
                    zf.write(item_path, os.path.basename(item_path))
                    
        update_server_storage(user_id, server_id)
        return True, f"Created ZIP archive '{os.path.basename(target_zip_path)}'"
    except Exception as e:
        return False, f"Failed to create ZIP: {str(e)}"

def export_selected_items_as_zip(server_id, rel_paths):
    """Exports selected files/folders as a streaming in-memory ZIP BytesIO for download."""
    user_id = _get_server_user_id(server_id)
    app_dir = get_app_dir(user_id, server_id)
    memory_file = io.BytesIO()
    
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for rel in rel_paths:
            item_path = resolve_safe_path(app_dir, rel)
            if not item_path or not os.path.exists(item_path):
                continue
            if os.path.isdir(item_path):
                for root, dirs, files in os.walk(item_path):
                    for f in files:
                        full_f = os.path.join(root, f)
                        arc = os.path.relpath(full_f, os.path.dirname(item_path))
                        zf.write(full_f, arc)
            else:
                zf.write(item_path, os.path.basename(item_path))
                
    memory_file.seek(0)
    return memory_file
