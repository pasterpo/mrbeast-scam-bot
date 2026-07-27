# MrBeast Crypto Scam Image Detector — Discord Bot

Auto-detects and deletes the fake "MrBeast crypto giveaway" scam screenshots
(fake casino sites, fake withdrawal confirmations, fake tweet screenshots)
that are circulating in your server. **100% free — no paid APIs, runs locally.**

## How detection works (two layers, both free)

1. **Perceptual hashing (pHash/aHash/dHash)** — catches exact reposts and
   lightly edited/cropped/recompressed copies of images your mods have
   already flagged once via `!flagscam`.
2. **OCR keyword matching (Tesseract, local)** — reads the text baked into
   screenshots and flags combinations of scam-pattern phrases ("withdrawal
   success", "MrBeast" + "crypto casino", known scam domains like `.cc`
   sites, `zzgamb`, `busewin`, `merwex`, etc.) This catches **brand new**
   variations the bot has never seen, as long as the screenshot is
   reasonably legible.

## ⚠️ Honest limitation — please read this

I tested this against the 9 images from your server. Results:

- **New, high-resolution, legible scam screenshots** (a fresh fake tweet, a
  fresh casino "withdrawal success" popup) → OCR catches these well, no
  training needed.
- **Reposts of a collage/photo your mods have already seen once** → after
  running `!flagscam` on it one time, pHash will catch every future repost
  of that exact image near-instantly, even if slightly cropped or
  recompressed.
- **Brand-new, low-resolution, multi-panel collages or video-call
  screenshots of a scam your mods haven't seen yet** → this is the gap.
  Neither pHash nor OCR reliably catches these on first sight, because the
  text is too small/blurry for OCR and the pixels don't match anything in
  the hash database yet.

That last gap is exactly where an AI vision model would help (it can tell
"this is a casino withdrawal screenshot" from layout alone, without clean
text) — but since you wanted a zero-cost solution, this bot doesn't include
that layer.

**Practical workflow to close the gap over time:** when a mod manually
deletes something the bot missed, have them reply to it with `!flagscam`.
That teaches the pHash layer permanently, so that specific scam template
(and all its future reposts) gets caught automatically from then on. The
database only grows — it never needs paid infrastructure to keep improving.

## Setup

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install Tesseract OCR** (the actual OCR engine, separate from the
   Python wrapper):
   - Ubuntu/Debian: `sudo apt install tesseract-ocr`
   - Mac: `brew install tesseract`
   - Windows: install from https://github.com/UB-Mannheim/tesseract/wiki

3. **Create a Discord bot:**
   - Go to https://discord.com/developers/applications → New Application
   - Bot tab → Add Bot → copy the token
   - Under "Privileged Gateway Intents", enable **Message Content Intent**
   - Invite it to your server with permissions: `Manage Messages`,
     `Read Message History`, `View Channels`, `Send Messages`,
     `Attach Files`, `Embed Links`

4. **Configure:**
   Edit `config.json`:
   ```json
   {
     "token": "YOUR_BOT_TOKEN",
     "mod_log_channel_id": "123456789012345678",
     "hamming_threshold": 10,
     "min_keyword_score": 2,
     "delete_on_match": true
   }
   ```
   - `mod_log_channel_id`: the channel ID where deleted-image logs get posted
     (right-click a channel → Copy Channel ID; you need Developer Mode on)
   - `hamming_threshold`: lower = stricter pHash match required (0-64 scale).
     10 is a reasonable default; raise it if legit images get falsely caught,
     lower it if obvious reposts slip through.
   - `min_keyword_score`: how many distinct scam-signal categories must
     match in the OCR text before flagging. 2 is a reasonable default.

   Alternatively, set the token via environment variable instead of the file:
   ```bash
   export DISCORD_BOT_TOKEN="your_token_here"
   ```

5. **Run:**
   ```bash
   python bot.py
   ```

## Mod commands

- **`!flagscam`** — reply to a message containing a scam image, run this
  command, and that image's hash gets added to the permanent database.
  Do this for every scam variant your mods manually catch.
- **`!testscam`** — reply to any image with this to see the detection
  verdict (flagged or not, and why) **without deleting anything**. Good for
  tuning thresholds or checking edge cases.
- **`!scamstats`** — shows how many hashes/keywords are loaded and how many
  messages have been auto-deleted so far.

## Files

- `bot.py` — the bot
- `config.json` — your settings (token, thresholds, log channel)
- `data/seed_hashes.json` — hashes pre-generated from your 9 example images
  (ships with the bot, read-only reference set)
- `data/hash_db.json` — grows automatically as mods use `!flagscam`
- `data/deletion_log.json` — audit trail of every auto-deletion

## Tuning tips

- If **legitimate images get falsely deleted**: raise `hamming_threshold`
  down (stricter) or raise `min_keyword_score` up (require more signals).
- If **obvious scam reposts slip through**: lower `min_keyword_score`, or
  just make sure mods are using `!flagscam` consistently — the hash
  database is the main thing that improves over time.
- Consider setting `delete_on_match: false` for the first day or two and
  watching the mod-log channel, to sanity check there are no false
  positives before letting it auto-delete for real.
