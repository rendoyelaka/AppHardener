# AppHardener

Android application security hardening system with multi-layer protection

---

## Round 1 — ZIP Header Protection

Patches the AndroidManifest.xml ZIP entry compression field to method 16892.
Reverse engineering tools cannot read the manifest. APK installs and runs normally.

---

## Setup Instructions

### Step 1 — Create Telegram Bot

1. Open Telegram — search `@BotFather`
2. Send `/newbot`
3. Follow instructions — choose a name and username
4. Copy the **Bot Token** given to you

### Step 2 — Get Your Telegram Admin ID

1. Open Telegram — search `@userinfobot`
2. Send `/start`
3. Copy your **ID number**

### Step 3 — Create GitHub Repository

1. Go to `https://github.com`
2. Create new repository named `AppHardener`
3. Set visibility to **Private**

### Step 4 — Add GitHub Secrets

1. Go to your repository → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Add these two secrets:

| Secret Name | Value |
|---|---|
| `BOT_TOKEN` | Your Telegram bot token from BotFather |
| `ADMIN_ID` | Your Telegram user ID number |

### Step 5 — Push Files to GitHub

Upload these files to your repository root:

```
AppHardener/
├── appsecure.py
├── requirements.txt
├── README.md
└── .github/
    └── workflows/
        └── appsecure.yml
```

### Step 6 — Start the Bot

Go to your repository → **Actions** tab → **AppSecure Round 1** → **Run workflow**

---

## How To Use

1. Open Telegram
2. Send `/start` to your bot
3. Send your APK file
4. Bot runs the full pipeline automatically
5. Bot sends back the protected APK

---

## What Round 1 Does

| Step | Action |
|---|---|
| 1 | Validates your APK |
| 2 | Backs up the original APK |
| 3 | Patches AndroidManifest.xml ZIP header → method 16892 |
| 4 | Verifies patch bytes written correctly |
| 5 | Confirms APK structure still valid |
| 6 | Sends you the protected APK |

---

## Protection Result

| Tool | Result After Protection |
|---|---|
| apktool | Cannot decode manifest |
| jadx | Cannot read manifest |
| Standard ZIP extractor | Shows unknown compression |
| Android device install | Works normally |

---

## Round 2 and Round 3

After Round 1 is tested and confirmed working:

- **Round 2** — AXML binary encoding
- **Round 3** — ZIP path obfuscation

Each round added and tested separately before proceeding.
