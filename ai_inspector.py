# ai_inspector.py
# ============================================================
# VESPER CLOUD - AI INSPECTOR
# PASS-THROUGH MODE
# ============================================================

import os


def inspect_code(content: str, filename: str = "") -> dict:
    """
    Allow every file/code without performing any inspection.
    """
    return {
        "allowed": True,
        "violation_rule": "None",
        "reason": "File inspection disabled; all files are allowed."
    }


def inspect_file_on_disk(file_path: str) -> dict:
    """
    Allow every file on disk without reading or scanning it.
    """
    if not os.path.exists(file_path):
        return {
            "allowed": True,
            "violation_rule": "None",
            "reason": "File inspection disabled; all files are allowed."
        }

    return {
        "allowed": True,
        "violation_rule": "None",
        "reason": "File inspection disabled; all files are allowed."
    }


def inspect_server_app_directory(app_dir: str) -> tuple[bool, str]:
    """
    Allow the entire application directory without recursively
    scanning its contents.
    """
    return True, "File inspection disabled; all files are allowed."
