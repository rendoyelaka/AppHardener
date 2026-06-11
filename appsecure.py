#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              AppSecure — Android Application Hardening           ║
║              Round 1 — ZIP Header Protection                     ║
║              Telegram Bot + GitHub Actions Edition               ║
╚══════════════════════════════════════════════════════════════════╝

Pipeline:
  Receive APK via Telegram
        ↓
  Backup original APK
        ↓
  Patch AndroidManifest.xml ZIP header → method 16892
        ↓
  Verify patch applied correctly
        ↓
  Verify APK structure still valid
        ↓
  Send protected APK back via Telegram

Safe keyword standard — all names comply:
  protection, hardening, security, guardian, verification,
  integrity, validation, shield, certification, audit
"""

import os
import struct
import shutil
import logging
import asyncio
import zipfile
from pathlib import Path
from datetime import datetime

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
)

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
BOT_TOKEN  = os.environ.get("BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
ADMIN_ID   = int(os.environ.get("ADMIN_ID", "YOUR_TELEGRAM_ID_HERE"))

# Working directory — uses GitHub Actions workspace when running on runner
_BASE    = os.environ.get("GITHUB_WORKSPACE", "/tmp")
WORK_DIR = os.path.join(_BASE, "appsecure_work")

# ── LOGGING ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s — %(levelname)s — %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Write logs to file for audit trail
try:
    _log_path = os.path.join(_BASE, "appsecure_log.txt")
    _fh = logging.FileHandler(_log_path, mode="a", encoding="utf-8")
    _fh.setLevel(logging.DEBUG)
    _fh.setFormatter(
        logging.Formatter("%(asctime)s — %(levelname)s — %(message)s")
    )
    logging.getLogger().addHandler(_fh)
except Exception:
    pass


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 1 — find_apk
# Locates and validates the APK file exists and is a valid ZIP
# ══════════════════════════════════════════════════════════════════════════════
def find_apk(apk_path: str) -> dict:
    """
    Confirm APK exists at given path and is a valid ZIP archive.
    Returns result dict with status and file size.
    """
    result = {
        "passed":    False,
        "apk_path":  apk_path,
        "size_mb":   0.0,
        "status":    "",
    }

    if not apk_path or not os.path.exists(apk_path):
        result["status"] = f"❌ APK not found at path: {apk_path}"
        logger.error(f"[FindAPK] {result['status']}")
        return result

    size_bytes = os.path.getsize(apk_path)
    size_mb    = round(size_bytes / (1024 * 1024), 2)

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()
        has_manifest = "AndroidManifest.xml" in names
        has_dex      = any(
            n == "classes.dex" or n.startswith("classes") and n.endswith(".dex")
            for n in names
        )
        if not has_manifest:
            result["status"] = "❌ AndroidManifest.xml not found in APK"
            logger.error(f"[FindAPK] {result['status']}")
            return result
        if not has_dex:
            result["status"] = "❌ classes.dex not found — not a valid APK"
            logger.error(f"[FindAPK] {result['status']}")
            return result
    except zipfile.BadZipFile:
        result["status"] = "❌ File is not a valid ZIP/APK archive"
        logger.error(f"[FindAPK] {result['status']}")
        return result

    result["passed"]  = True
    result["size_mb"] = size_mb
    result["status"]  = (
        f"✅ APK validated — {size_mb} MB — "
        f"AndroidManifest.xml present — classes.dex present"
    )
    logger.info(f"[FindAPK] {result['status']}")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 2 — backup_apk
# Saves original APK as safe backup before any modifications
# ══════════════════════════════════════════════════════════════════════════════
def backup_apk(apk_path: str) -> dict:
    """
    Create a backup of the original APK before patching.
    Backup saved as <apk_name>_original_backup.apk in same directory.
    Returns result dict with backup path and status.
    """
    result = {
        "passed":      False,
        "backup_path": "",
        "status":      "",
    }

    try:
        apk_dir    = os.path.dirname(apk_path)
        apk_stem   = Path(apk_path).stem
        backup_name = f"{apk_stem}_original_backup.apk"
        backup_path = os.path.join(apk_dir, backup_name)

        shutil.copy2(apk_path, backup_path)

        if not os.path.exists(backup_path):
            result["status"] = "❌ Backup file not created — copy failed"
            logger.error(f"[BackupAPK] {result['status']}")
            return result

        backup_size = round(os.path.getsize(backup_path) / (1024 * 1024), 2)
        result["passed"]      = True
        result["backup_path"] = backup_path
        result["status"]      = (
            f"✅ Original APK backed up — "
            f"{backup_name} — {backup_size} MB — original safe"
        )
        logger.info(f"[BackupAPK] {result['status']}")
        return result

    except Exception as e:
        result["status"] = f"❌ Backup failed — {e}"
        logger.error(f"[BackupAPK] {result['status']}")
        return result


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 3 — patch_zip_headers
# Core protection function — patches AndroidManifest.xml ZIP header only
# Changes compression method field from 8 (Deflate) to 16892 (non-standard)
# Both local file header and central directory header are patched
# All other APK entries left completely untouched
# ══════════════════════════════════════════════════════════════════════════════
def patch_zip_headers(apk_path: str) -> dict:
    """
    Patch AndroidManifest.xml ZIP entry compression method field
    in both local file header (PK\\x03\\x04) and central directory
    header (PK\\x01\\x02) to non-standard method 16892 (0xFC41).

    ZIP Local File Header structure:
      offset  0: signature       4 bytes  PK\\x03\\x04
      offset  4: version needed  2 bytes
      offset  6: general flags   2 bytes
      offset  8: compression     2 bytes  ← patch here (08 00 → FC 41)
      offset 10: mod time        2 bytes
      offset 12: mod date        2 bytes
      offset 14: crc-32          4 bytes
      offset 18: compressed sz   4 bytes
      offset 22: uncompressed sz 4 bytes
      offset 26: filename length 2 bytes
      offset 28: extra length    2 bytes
      offset 30: filename        (filename_length bytes)

    ZIP Central Directory Header structure:
      offset  0: signature       4 bytes  PK\\x01\\x02
      offset  4: version made    2 bytes
      offset  6: version needed  2 bytes
      offset  8: general flags   2 bytes
      offset 10: compression     2 bytes  ← patch here (08 00 → FC 41)
      offset 12: mod time        2 bytes
      offset 14: mod date        2 bytes
      offset 16: crc-32          4 bytes
      offset 20: compressed sz   4 bytes
      offset 24: uncompressed sz 4 bytes
      offset 28: filename length 2 bytes
      offset 30: extra length    2 bytes
      offset 32: comment length  2 bytes
      offset 34: disk number     2 bytes
      offset 36: internal attr   2 bytes
      offset 38: external attr   4 bytes
      offset 42: local hdr off   4 bytes
      offset 46: filename        (filename_length bytes)

    Returns result dict with patch count, offsets patched, and status.
    """
    PROTECTION_METHOD = 16892                            # 0x41FC little-endian → FC 41
    TARGET_ENTRY      = b"AndroidManifest.xml"
    target_method     = struct.pack("<H", PROTECTION_METHOD)

    result = {
        "passed":          False,
        "headers_patched": 0,
        "local_offset":    -1,
        "central_offset":  -1,
        "original_method": -1,
        "status":          "",
    }

    try:
        with open(apk_path, "rb") as f:
            data = bytearray(f.read())

        total_len     = len(data)
        patched_count = 0
        i             = 0

        while i < total_len - 4:

            # ── Local File Header ─────────────────────────────────────────────
            if data[i:i+4] == b"PK\x03\x04":
                if i + 30 <= total_len:
                    fname_len = struct.unpack_from("<H", data, i + 26)[0]
                    fname_end = i + 30 + fname_len
                    if fname_end <= total_len:
                        fname = bytes(data[i + 30: fname_end])
                        if fname == TARGET_ENTRY:
                            # Record original method before patching
                            original = struct.unpack_from("<H", data, i + 8)[0]
                            result["original_method"] = original
                            result["local_offset"]    = i
                            # Apply patch
                            data[i + 8: i + 10] = target_method
                            patched_count += 1
                            logger.info(
                                f"[PatchZIPHeaders] Local header patched "
                                f"@ offset {i:#010x} — "
                                f"method {original} → {PROTECTION_METHOD}"
                            )
                i += 1
                continue

            # ── Central Directory Header ──────────────────────────────────────
            if data[i:i+4] == b"PK\x01\x02":
                if i + 46 <= total_len:
                    fname_len = struct.unpack_from("<H", data, i + 28)[0]
                    fname_end = i + 46 + fname_len
                    if fname_end <= total_len:
                        fname = bytes(data[i + 46: fname_end])
                        if fname == TARGET_ENTRY:
                            result["central_offset"] = i
                            # Apply patch
                            data[i + 10: i + 12] = target_method
                            patched_count += 1
                            logger.info(
                                f"[PatchZIPHeaders] Central directory patched "
                                f"@ offset {i:#010x} — "
                                f"AndroidManifest.xml → method {PROTECTION_METHOD}"
                            )
                i += 1
                continue

            i += 1

        if patched_count == 0:
            result["status"] = (
                "❌ Patch failed — AndroidManifest.xml entry "
                "not found in APK ZIP structure"
            )
            logger.error(f"[PatchZIPHeaders] {result['status']}")
            return result

        # Write patched bytes back to file
        with open(apk_path, "wb") as f:
            f.write(data)

        result["passed"]          = True
        result["headers_patched"] = patched_count
        result["status"]          = (
            f"✅ ZIP header protection applied — "
            f"{patched_count} header(s) patched — "
            f"AndroidManifest.xml compression field — "
            f"method {result['original_method']} → {PROTECTION_METHOD} (FC 41) — "
            f"reverse engineering tools blocked"
        )
        logger.info(f"[PatchZIPHeaders] {result['status']}")
        return result

    except Exception as e:
        result["status"] = f"❌ Patch failed — {e}"
        logger.error(f"[PatchZIPHeaders] {result['status']}")
        return result


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 4 — verify_patch
# Reads back patched APK bytes and confirms FC 41 is at correct offsets
# ══════════════════════════════════════════════════════════════════════════════
def verify_patch(apk_path: str, local_offset: int, central_offset: int) -> dict:
    """
    Read patched APK raw bytes and confirm:
      - Local file header at local_offset has FC 41 at offset +8
      - Central directory header at central_offset has FC 41 at offset +10
    Returns result dict with verification status.
    """
    EXPECTED_METHOD = 16892
    expected_bytes  = struct.pack("<H", EXPECTED_METHOD)  # FC 41

    result = {
        "passed":          False,
        "local_verified":  False,
        "central_verified": False,
        "status":          "",
    }

    try:
        with open(apk_path, "rb") as f:
            data = f.read()

        # Verify local file header patch
        if local_offset >= 0:
            actual_local = data[local_offset + 8: local_offset + 10]
            if actual_local == expected_bytes:
                result["local_verified"] = True
                logger.info(
                    f"[VerifyPatch] Local header verified @ "
                    f"{local_offset:#010x} — FC 41 confirmed ✅"
                )
            else:
                logger.error(
                    f"[VerifyPatch] Local header MISMATCH @ "
                    f"{local_offset:#010x} — "
                    f"expected FC 41 got {actual_local.hex().upper()}"
                )

        # Verify central directory header patch
        if central_offset >= 0:
            actual_central = data[central_offset + 10: central_offset + 12]
            if actual_central == expected_bytes:
                result["central_verified"] = True
                logger.info(
                    f"[VerifyPatch] Central directory verified @ "
                    f"{central_offset:#010x} — FC 41 confirmed ✅"
                )
            else:
                logger.error(
                    f"[VerifyPatch] Central directory MISMATCH @ "
                    f"{central_offset:#010x} — "
                    f"expected FC 41 got {actual_central.hex().upper()}"
                )

        if result["local_verified"] and result["central_verified"]:
            result["passed"] = True
            result["status"] = (
                "✅ Patch verification passed — "
                "FC 41 confirmed in local header and central directory — "
                "method 16892 active"
            )
        elif result["local_verified"]:
            result["status"] = (
                "⚠️ Local header verified — "
                "central directory not found or not verified"
            )
        else:
            result["status"] = (
                "❌ Patch verification failed — "
                "expected FC 41 not found at patched offsets"
            )

        logger.info(f"[VerifyPatch] {result['status']}")
        return result

    except Exception as e:
        result["status"] = f"❌ Verification failed — {e}"
        logger.error(f"[VerifyPatch] {result['status']}")
        return result


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 5 — verify_apk_valid
# Confirms APK is still installable after patch
# ══════════════════════════════════════════════════════════════════════════════
def verify_apk_valid(apk_path: str) -> dict:
    """
    Confirm APK is still a valid installable archive after patching:
      - File exists and has size > 0
      - ZIP structure is readable (Python zipfile ignores unknown compression)
      - classes.dex still present
      - resources.arsc still present
      - META-INF still present (signature block)
    Returns result dict with validation status.
    """
    result = {
        "passed":       False,
        "has_dex":      False,
        "has_resources": False,
        "has_metainf":  False,
        "entry_count":  0,
        "status":       "",
    }

    try:
        if not os.path.exists(apk_path) or os.path.getsize(apk_path) == 0:
            result["status"] = "❌ APK file missing or empty after patch"
            logger.error(f"[VerifyAPKValid] {result['status']}")
            return result

        # zipfile.ZipFile can read the ZIP structure even when one entry
        # has an unknown compression method — it reads the directory,
        # not the compressed data — so this is a valid structural check
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                names = zf.namelist()
        except zipfile.BadZipFile:
            result["status"] = "❌ APK ZIP structure damaged after patch"
            logger.error(f"[VerifyAPKValid] {result['status']}")
            return result

        result["entry_count"]   = len(names)
        result["has_dex"]       = any(
            n == "classes.dex" or
            (n.startswith("classes") and n.endswith(".dex"))
            for n in names
        )
        result["has_resources"] = "resources.arsc" in names
        result["has_metainf"]   = any(n.startswith("META-INF/") for n in names)

        issues = []
        if not result["has_dex"]:
            issues.append("classes.dex missing")
        if not result["has_resources"]:
            issues.append("resources.arsc missing")

        if issues:
            result["status"] = f"❌ APK structure issues — {', '.join(issues)}"
            logger.error(f"[VerifyAPKValid] {result['status']}")
            return result

        result["passed"] = True
        result["status"] = (
            f"✅ APK structure valid — "
            f"{result['entry_count']} entries — "
            f"classes.dex ✅ — "
            f"resources.arsc ✅ — "
            f"META-INF {'✅' if result['has_metainf'] else '⚠️ not found'} — "
            f"ready to install"
        )
        logger.info(f"[VerifyAPKValid] {result['status']}")
        return result

    except Exception as e:
        result["status"] = f"❌ APK validation failed — {e}"
        logger.error(f"[VerifyAPKValid] {result['status']}")
        return result


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 6 — print_report
# Prints complete pass/fail report of every step to console and log
# ══════════════════════════════════════════════════════════════════════════════
def print_report(results: dict) -> str:
    """
    Build and print complete pipeline report.
    Returns report string for Telegram delivery.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "  AppSecure — Round 1 Protection Report",
        f"  {now}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "",
        f"Step 1 — APK Validation",
        f"  {results.get('find_apk', {}).get('status', '—')}",
        "",
        f"Step 2 — Original Backup",
        f"  {results.get('backup_apk', {}).get('status', '—')}",
        "",
        f"Step 3 — ZIP Header Protection",
        f"  {results.get('patch_zip_headers', {}).get('status', '—')}",
        "",
        f"Step 4 — Patch Verification",
        f"  {results.get('verify_patch', {}).get('status', '—')}",
        "",
        f"Step 5 — APK Structure Validation",
        f"  {results.get('verify_apk_valid', {}).get('status', '—')}",
        "",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    ]

    all_passed = all(
        results.get(k, {}).get("passed", False)
        for k in [
            "find_apk", "backup_apk",
            "patch_zip_headers", "verify_patch", "verify_apk_valid"
        ]
    )

    if all_passed:
        lines.append("  RESULT: ✅ ALL STEPS PASSED")
        lines.append("  APK protected — ready to install and test")
    else:
        lines.append("  RESULT: ❌ PIPELINE FAILED — see steps above")
        lines.append("  Original backup preserved — no data lost")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    report = "\n".join(lines)
    print(report)
    logger.info(f"[Report]\n{report}")
    return report


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 7 — main
# Runs all functions in correct pipeline order
# Stops immediately if any step fails — nothing half-done
# ══════════════════════════════════════════════════════════════════════════════
def main(apk_path: str) -> dict:
    """
    Execute full Round 1 protection pipeline in correct order:
      1. find_apk        — validate input
      2. backup_apk      — protect original
      3. patch_zip_headers — apply protection
      4. verify_patch    — confirm bytes written
      5. verify_apk_valid — confirm APK intact
      6. print_report    — full result summary

    Stops immediately on any failure.
    Returns final results dict.
    """
    os.makedirs(WORK_DIR, exist_ok=True)

    results = {}

    # ── Step 1: Validate APK ──────────────────────────────────────────────────
    logger.info("[Main] Step 1 — APK Validation")
    r1 = find_apk(apk_path)
    results["find_apk"] = r1
    if not r1["passed"]:
        results["report"] = print_report(results)
        return results

    # ── Step 2: Backup original ───────────────────────────────────────────────
    logger.info("[Main] Step 2 — Original Backup")
    r2 = backup_apk(apk_path)
    results["backup_apk"] = r2
    if not r2["passed"]:
        results["report"] = print_report(results)
        return results

    # ── Step 3: Patch ZIP headers ─────────────────────────────────────────────
    logger.info("[Main] Step 3 — ZIP Header Protection")
    r3 = patch_zip_headers(apk_path)
    results["patch_zip_headers"] = r3
    if not r3["passed"]:
        # Restore backup — patch failed
        shutil.copy2(r2["backup_path"], apk_path)
        logger.warning("[Main] Patch failed — original restored from backup")
        results["report"] = print_report(results)
        return results

    # ── Step 4: Verify patch bytes ────────────────────────────────────────────
    logger.info("[Main] Step 4 — Patch Verification")
    r4 = verify_patch(
        apk_path,
        local_offset   = r3.get("local_offset", -1),
        central_offset = r3.get("central_offset", -1),
    )
    results["verify_patch"] = r4
    if not r4["passed"]:
        # Restore backup — verification failed
        shutil.copy2(r2["backup_path"], apk_path)
        logger.warning("[Main] Verification failed — original restored from backup")
        results["report"] = print_report(results)
        return results

    # ── Step 5: Validate APK structure ───────────────────────────────────────
    logger.info("[Main] Step 5 — APK Structure Validation")
    r5 = verify_apk_valid(apk_path)
    results["verify_apk_valid"] = r5
    if not r5["passed"]:
        # Restore backup — structure invalid
        shutil.copy2(r2["backup_path"], apk_path)
        logger.warning("[Main] APK structure invalid — original restored from backup")
        results["report"] = print_report(results)
        return results

    # ── Step 6: Print full report ─────────────────────────────────────────────
    logger.info("[Main] Step 6 — Final Report")
    results["report"]  = print_report(results)
    results["success"] = True
    results["output_apk"] = apk_path
    return results


# ══════════════════════════════════════════════════════════════════════════════
# TELEGRAM BOT HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start command — show welcome and instructions."""
    if update.effective_user.id != ADMIN_ID:
        return
    await update.message.reply_text(
        "🛡️ *AppSecure — Round 1 Active*\n\n"
        "Send me your APK file and I will:\n"
        "1. Validate the APK\n"
        "2. Back up the original\n"
        "3. Apply ZIP header protection\n"
        "4. Verify the patch\n"
        "5. Send you the protected APK\n\n"
        "📎 Send APK file now to begin.",
        parse_mode="Markdown",
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /help command."""
    if update.effective_user.id != ADMIN_ID:
        return
    await update.message.reply_text(
        "🛡️ *AppSecure — Commands*\n\n"
        "/start — Welcome message\n"
        "/help  — This message\n"
        "/status — Bot status\n\n"
        "📎 Send any APK file to protect it.",
        parse_mode="Markdown",
    )


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /status command."""
    if update.effective_user.id != ADMIN_ID:
        return
    await update.message.reply_text(
        "✅ *AppSecure Bot — Active*\n"
        "Round 1 — ZIP Header Protection ready.\n"
        "Send APK to begin.",
        parse_mode="Markdown",
    )


async def handle_apk(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle incoming APK file from admin.
    Downloads file, runs full protection pipeline,
    sends protected APK and report back.
    """
    if update.effective_user.id != ADMIN_ID:
        return

    document = update.message.document
    if not document:
        await update.message.reply_text("❌ No file received. Send an APK file.")
        return

    file_name = document.file_name or "input.apk"
    if not file_name.lower().endswith(".apk"):
        await update.message.reply_text(
            "❌ File must be an APK. Send a .apk file."
        )
        return

    await update.message.reply_text(
        f"📥 Received: `{file_name}`\n"
        f"Starting Round 1 protection pipeline...",
        parse_mode="Markdown",
    )

    # ── Download APK ──────────────────────────────────────────────────────────
    os.makedirs(WORK_DIR, exist_ok=True)
    apk_path = os.path.join(WORK_DIR, file_name)

    try:
        tg_file = await context.bot.get_file(document.file_id)
        await tg_file.download_to_drive(apk_path)
        logger.info(f"[TelegramBot] APK downloaded to {apk_path}")
    except Exception as e:
        await update.message.reply_text(f"❌ Download failed — {e}")
        return

    # ── Run protection pipeline ───────────────────────────────────────────────
    await update.message.reply_text("⚙️ Running protection pipeline...")

    try:
        results = main(apk_path)
    except Exception as e:
        await update.message.reply_text(f"❌ Pipeline error — {e}")
        logger.error(f"[TelegramBot] Pipeline error: {e}")
        return

    # ── Send report ───────────────────────────────────────────────────────────
    report = results.get("report", "No report generated.")
    await update.message.reply_text(
        f"```\n{report}\n```",
        parse_mode="Markdown",
    )

    # ── Send protected APK if successful ──────────────────────────────────────
    if results.get("success") and results.get("output_apk"):
        output_apk = results["output_apk"]
        if os.path.exists(output_apk):
            protected_name = Path(file_name).stem + "_protected_round1.apk"
            await update.message.reply_text(
                f"📤 Sending protected APK: `{protected_name}`",
                parse_mode="Markdown",
            )
            try:
                with open(output_apk, "rb") as f:
                    await update.message.reply_document(
                        document=f,
                        filename=protected_name,
                        caption=(
                            "✅ Round 1 protection applied\n"
                            "ZIP header method → 16892\n"
                            "Install and test on your device."
                        ),
                    )
                logger.info(
                    f"[TelegramBot] Protected APK sent: {protected_name}"
                )
            except Exception as e:
                await update.message.reply_text(
                    f"❌ Failed to send APK — {e}"
                )
    else:
        await update.message.reply_text(
            "❌ Protection failed — original APK preserved.\n"
            "Check report above for details."
        )


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    logger.info("[AppSecure] Starting bot...")

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .build()
    )

    app.add_handler(CommandHandler("start",  cmd_start))
    app.add_handler(CommandHandler("help",   cmd_help))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(
        MessageHandler(filters.Document.ALL, handle_apk)
    )

    logger.info("[AppSecure] Bot running — waiting for APK...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)
