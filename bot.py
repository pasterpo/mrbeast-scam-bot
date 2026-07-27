"""
MrBeast Crypto Scam Image Detector — Discord Bot
--------------------------------------------------
Detects and auto-deletes fake "MrBeast crypto giveaway" scam screenshots
(fake casino UI, fake withdrawal confirmations, fake tweet screenshots, etc.)

Detection is 100% local / free — no paid APIs:
  1. Perceptual hashing (pHash/aHash/dHash) — catches exact reposts & lightly
     edited/cropped/recompressed copies of known scam images.
  2. OCR keyword matching (Tesseract, local) — catches NEW/unseen variations
     by reading the text baked into the screenshot and matching scam patterns.

Requirements:
  pip install discord.py imagehash pillow pytesseract
  apt install tesseract-ocr   (Tesseract binary must be installed on the host)

Setup:
  1. Set your bot token in config.json (or the DISCORD_BOT_TOKEN env var)
  2. Set MOD_LOG_CHANNEL_ID in config.json to a channel where deletions get logged
  3. Run: python bot.py

Mod commands:
  !flagscam        (reply to a message with an image) -> adds that image's
                    hash to the known-bad database, permanently.
  !scamstats        -> shows how many hashes/keywords are loaded, deletions so far
  !testscam         (reply to a message with an image) -> runs detection WITHOUT
                    deleting, tells you why it would/wouldn't be flagged (debug tool)
"""

import discord
from discord.ext import commands
import imagehash
from PIL import Image
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
import io
import json
import os
import re
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
HASH_DB_PATH = os.path.join(os.path.dirname(__file__), "data", "hash_db.json")
SEED_HASH_PATH = os.path.join(os.path.dirname(__file__), "data", "seed_hashes.json")
LOG_PATH = os.path.join(os.path.dirname(__file__), "data", "deletion_log.json")

DEFAULT_CONFIG = {
    "token": "PUT_YOUR_BOT_TOKEN_HERE",
    "mod_log_channel_id": None,
    "hamming_threshold": 10,      # lower = stricter match required (0-64 scale for pHash)
    "min_keyword_score": 2,       # how many distinct scam signals must match via OCR
    "delete_on_match": True,
    "command_prefix": "!"
}

if not os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "w") as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

TOKEN = os.environ.get("DISCORD_BOT_TOKEN", CONFIG.get("token"))
MOD_LOG_CHANNEL_ID = CONFIG.get("mod_log_channel_id")
HAMMING_THRESHOLD = CONFIG.get("hamming_threshold", 10)
MIN_KEYWORD_SCORE = CONFIG.get("min_keyword_score", 2)
DELETE_ON_MATCH = CONFIG.get("delete_on_match", True)
PREFIX = CONFIG.get("command_prefix", "!")

# ---------------------------------------------------------------------------
# Scam signal keyword groups.
# A message is flagged if OCR text matches keywords from MIN_KEYWORD_SCORE
# distinct groups below (default 2). This avoids false positives from any
# single common word while still catching new/unseen scam screenshots.
# ---------------------------------------------------------------------------
KEYWORD_GROUPS = {
    "celebrity_bait": [
        r"mrbeast", r"mr beast", r"elon musk", r"followed by elon"
    ],
    "crypto_casino_bait": [
        r"cryptocurrency casino", r"crypto casino", r"giving away",
        r"withdraw the bonus", r"registers"
    ],
    "withdrawal_success": [
        r"withdrawal success", r"withdraw.{0,15}success", r"successful withdrawal",
        r"was successfully", r"reward received", r"congratulations",
        r"your reward has been", r"receive usdt", r"withdrawal of \$"
    ],
    "bonus_activation": [
        r"activate code", r"bonus.{0,10}code", r"redeem code", r"promo code",
        r"rakeback", r"vip.?club"
    ],
    "scam_domains": [
        r"\.cc\b", r"zzgamb", r"busewin", r"merwex", r"resogamb", r"gamb\.cc"
    ],
    "fake_amounts": [
        r"\+\s?\d{3,5}\s?usdt", r"\$\d{3,5}(\.\d{2})?\b.{0,10}(success|received|withdraw)"
    ],
}

COMPILED_GROUPS = {
    name: [re.compile(p, re.IGNORECASE) for p in patterns]
    for name, patterns in KEYWORD_GROUPS.items()
}


def ocr_score(text: str):
    """Return (score, matched_groups) — number of distinct keyword groups hit."""
    text_lower = text.lower()
    matched = []
    for group_name, patterns in COMPILED_GROUPS.items():
        if any(p.search(text_lower) for p in patterns):
            matched.append(group_name)
    return len(matched), matched


def preprocess_for_ocr(pil_img):
    """Upscale small/blurry screenshots and boost contrast before OCR.
    Screenshots-of-screenshots (a Discord message containing a shrunk collage,
    or a phone photo of a monitor) are low-res/low-contrast; this helps a lot."""
    from PIL import ImageOps, ImageFilter
    gray = pil_img.convert("L")
    w, h = gray.size
    longer = max(w, h)
    if longer < 1200:
        scale = min(4, max(1, 1200 // max(longer, 1)))
        gray = gray.resize((w * scale, h * scale), Image.LANCZOS)
    gray = ImageOps.autocontrast(gray)
    gray = gray.filter(ImageFilter.SHARPEN)
    return gray


def ocr_multi_pass(pil_img) -> str:
    """Run OCR on raw + preprocessed versions and combine results (still free/local)."""
    texts = []
    try:
        texts.append(pytesseract.image_to_string(pil_img.convert("L")))
    except Exception:
        pass
    try:
        texts.append(pytesseract.image_to_string(preprocess_for_ocr(pil_img)))
    except Exception:
        pass
    return "\n".join(texts)


# ---------------------------------------------------------------------------
# Hash database (persisted to disk, mods can grow it with !flagscam)
# ---------------------------------------------------------------------------
def load_hash_db():
    db = {}
    if os.path.exists(SEED_HASH_PATH):
        with open(SEED_HASH_PATH) as f:
            db.update(json.load(f))
    if os.path.exists(HASH_DB_PATH):
        with open(HASH_DB_PATH) as f:
            db.update(json.load(f))
    return db


def save_hash_db(db):
    with open(HASH_DB_PATH, "w") as f:
        json.dump(db, f, indent=2)


HASH_DB = load_hash_db()


def compute_hashes(pil_img: Image.Image):
    return {
        "phash": str(imagehash.phash(pil_img)),
        "ahash": str(imagehash.average_hash(pil_img)),
        "dhash": str(imagehash.dhash(pil_img)),
    }


def hamming(hash_a: str, hash_b: str) -> int:
    return imagehash.hex_to_hash(hash_a) - imagehash.hex_to_hash(hash_b)


def check_phash_match(new_hashes: dict):
    """Return (matched: bool, best_distance: int, matched_filename: str|None)."""
    best_distance = 999
    best_file = None
    for fname, stored in HASH_DB.items():
        for htype in ("phash", "ahash", "dhash"):
            if htype in stored and htype in new_hashes:
                d = hamming(new_hashes[htype], stored[htype])
                if d < best_distance:
                    best_distance = d
                    best_file = fname
    matched = best_distance <= HAMMING_THRESHOLD
    return matched, best_distance, best_file


def log_deletion(entry: dict):
    log = []
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH) as f:
            log = json.load(f)
    log.append(entry)
    with open(LOG_PATH, "w") as f:
        json.dump(log, f, indent=2)


# ---------------------------------------------------------------------------
# Bot
# ---------------------------------------------------------------------------
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True

bot = commands.Bot(command_prefix=PREFIX, intents=intents)


async def analyze_attachment(attachment: discord.Attachment):
    """
    Download an attachment and run both detection layers.
    Returns a dict with the verdict and reasoning.
    """
    if not any(attachment.filename.lower().endswith(ext)
               for ext in (".png", ".jpg", ".jpeg", ".webp", ".gif")):
        return None

    raw = await attachment.read()
    try:
        pil_img = Image.open(io.BytesIO(raw)).convert("RGB")
    except Exception:
        return None

    new_hashes = compute_hashes(pil_img)
    phash_matched, distance, matched_file = check_phash_match(new_hashes)

    ocr_text = ""
    try:
        ocr_text = ocr_multi_pass(pil_img)
    except Exception:
        pass
    score, matched_groups = ocr_score(ocr_text)
    keyword_matched = score >= MIN_KEYWORD_SCORE

    flagged = phash_matched or keyword_matched
    reasons = []
    if phash_matched:
        reasons.append(f"perceptual hash match (distance={distance} vs `{matched_file}`)")
    if keyword_matched:
        reasons.append(f"OCR keyword match ({score} signal groups: {', '.join(matched_groups)})")

    return {
        "flagged": flagged,
        "reasons": reasons,
        "hashes": new_hashes,
        "ocr_text": ocr_text.strip()[:500],
        "phash_distance": distance,
    }


@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} — watching for scam images.")
    print(f"Loaded {len(HASH_DB)} known scam-image hashes.")


@bot.event
async def on_message(message: discord.Message):
    # let commands still process
    await bot.process_commands(message)

    if message.author.bot:
        return
    if not message.attachments:
        return

    for attachment in message.attachments:
        result = await analyze_attachment(attachment)
        if result is None:
            continue

        if result["flagged"]:
            reason_str = "; ".join(result["reasons"])

            mod_log_channel = None
            if MOD_LOG_CHANNEL_ID:
                mod_log_channel = bot.get_channel(int(MOD_LOG_CHANNEL_ID))

            log_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "guild": message.guild.name if message.guild else None,
                "channel": str(message.channel),
                "author": str(message.author),
                "author_id": message.author.id,
                "filename": attachment.filename,
                "reasons": result["reasons"],
                "ocr_snippet": result["ocr_text"],
            }
            log_deletion(log_entry)

            if DELETE_ON_MATCH:
                try:
                    await message.delete()
                except discord.Forbidden:
                    print("Missing permission to delete message.")
                except discord.NotFound:
                    pass

            if mod_log_channel:
                embed = discord.Embed(
                    title="🚨 Scam image auto-deleted" if DELETE_ON_MATCH else "🚨 Scam image flagged",
                    description=(
                        f"**Author:** {message.author.mention} (`{message.author}`)\n"
                        f"**Channel:** {message.channel.mention}\n"
                        f"**Reason:** {reason_str}\n"
                    ),
                    color=discord.Color.red(),
                    timestamp=datetime.now(timezone.utc),
                )
                if result["ocr_text"]:
                    embed.add_field(name="OCR snippet", value=f"```{result['ocr_text'][:300]}```", inline=False)
                embed.set_footer(text=f"Filename: {attachment.filename}")
                try:
                    file_bytes = await attachment.read()
                    file = discord.File(io.BytesIO(file_bytes), filename=attachment.filename)
                    embed.set_image(url=f"attachment://{attachment.filename}")
                    await mod_log_channel.send(embed=embed, file=file)
                except Exception as e:
                    await mod_log_channel.send(embed=embed)
                    print(f"Could not attach original image to log: {e}")
            break  # one flag is enough to act on the message


@bot.command(name="flagscam")
@commands.has_permissions(manage_messages=True)
async def flagscam(ctx: commands.Context):
    """Reply to a message containing an image with !flagscam to add it to the known-bad hash DB."""
    ref = ctx.message.reference
    if not ref:
        await ctx.send("Reply to a message that has the scam image attached, then run `!flagscam`.")
        return
    target = await ctx.channel.fetch_message(ref.message_id)
    if not target.attachments:
        await ctx.send("That message has no image attachment.")
        return

    added = 0
    for attachment in target.attachments:
        raw = await attachment.read()
        try:
            pil_img = Image.open(io.BytesIO(raw)).convert("RGB")
        except Exception:
            continue
        hashes = compute_hashes(pil_img)
        key = f"manual_{attachment.filename}_{int(datetime.now().timestamp())}"
        HASH_DB[key] = hashes
        added += 1

    save_hash_db(HASH_DB)
    await ctx.send(f"✅ Added {added} image hash(es) to the scam database. Total known hashes: {len(HASH_DB)}")


@bot.command(name="testscam")
@commands.has_permissions(manage_messages=True)
async def testscam(ctx: commands.Context):
    """Debug: reply to a message with an image to see the detection verdict WITHOUT deleting."""
    ref = ctx.message.reference
    if not ref:
        await ctx.send("Reply to a message that has an image attached, then run `!testscam`.")
        return
    target = await ctx.channel.fetch_message(ref.message_id)
    if not target.attachments:
        await ctx.send("That message has no image attachment.")
        return

    for attachment in target.attachments:
        result = await analyze_attachment(attachment)
        if result is None:
            continue
        verdict = "🚨 WOULD BE FLAGGED" if result["flagged"] else "✅ clean"
        reason_str = "; ".join(result["reasons"]) if result["reasons"] else "no matches"
        await ctx.send(
            f"**{verdict}**\n"
            f"Reasons: {reason_str}\n"
            f"pHash distance to closest known: {result['phash_distance']}\n"
            f"OCR snippet: ```{result['ocr_text'][:300]}```"
        )


@bot.command(name="scamstats")
async def scamstats(ctx: commands.Context):
    log = []
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH) as f:
            log = json.load(f)
    await ctx.send(
        f"📊 **Scam detector stats**\n"
        f"Known scam-image hashes: {len(HASH_DB)}\n"
        f"Keyword signal groups: {len(KEYWORD_GROUPS)}\n"
        f"Messages deleted so far: {len(log)}\n"
        f"Hamming threshold: {HAMMING_THRESHOLD} | Min keyword score: {MIN_KEYWORD_SCORE}"
    )


if __name__ == "__main__":
    if TOKEN == "PUT_YOUR_BOT_TOKEN_HERE":
        print("!! Set your bot token in config.json or the DISCORD_BOT_TOKEN env var before running.")
    else:
        bot.run(TOKEN)
