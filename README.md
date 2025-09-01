# Deno-Email-Hunter

A **100% free and open-source** Telegram bot for email-based OSINT—no paid keys or services required.

Send an email address to the bot, and it will:

-  Check for a public **Gravatar** profile and linked accounts  
-  Detect if the email is registered across numerous sites (via **Holehe**) :contentReference[oaicite:0]{index=0}  
-  Generate username candidates and search for them on 500+ platforms using **Maigret** :contentReference[oaicite:1]{index=1}  
-  Optionally retrieve public mentions via **DuckDuckGo** (free)  
-  Provide a clean summary and a downloadable **JSON report** of raw outputs  
-  Be used strictly for educational purposes and **with consent only**

---

##  Key Features

- Completely **free stack** (no paid APIs)  
- Easy-to-use **Telegram bot interface**—ideal for demos or capstone projects  
- Gravatar discovery (profile & avatar)  
- Email registrability across sites via Holehe  
- Username-based OSINT across 500+ platforms via Maigret  
- Optional DuckDuckGo lookup for public mentions  
- Downloadable JSON of full results

---

##  Tech Stack

- **Python 3.10+**  
- `python-telegram-bot`, `httpx`, `aiohttp`, `trio`, `httpx`  
- **Holehe** (CLI) — Email presence checker :contentReference[oaicite:2]{index=2}  
- **Maigret** (CLI/Python) — Username-based OSINT across many platforms :contentReference[oaicite:3]{index=3}  
- **duckduckgo-search** — Optional public mention scraping

---

##  How It Works

1. Send an email (e.g., `user@example.com`) to the bot.  
2. It validates the email and runs these steps:

   - Gravatar lookup  
   - Holehe scan for account presence across platforms  
   - Username generation (from email and Gravatar)  
   - Maigret search across 500+ sites  
   - Optional DuckDuckGo mention search  

3. Bot sends:

   - A **formatted summary** in chat  
   - A **JSON file** containing raw outputs of each tool

---

##  Project Structure

├── bot_free.py # Main Telegram bot.
├── requirements.txt # Python dependencies.
├── .env # Environment variables (user-provided).
└── README.md # This document.


---

##  Quick Start

### Prerequisites

- Python 3.10+  
- Telegram bot token (via @BotFather)

### Setup

# Clone and activate virtual environment
```
python3 -m venv .venv
source .venv/bin/activate
```

# Install dependencies
```bash
pip install -r requirements.txt
pip install holehe maigret duckduckgo-search
```
Create a .env file with:
```bash 
TELEGRAM_TOKEN=1234567890YOUR_TELEGRAM_BOT_TOKEN
# Optional tuning (all free)
HOLEHE_PATH=holehe
MAIGRET_PATH=maigret
ENABLE_DDG=1
MAX_USERNAMES=3
MAIGRET_TIMEOUT=240
# Optional Have I been pownd (HIBP) email breach lookup (requires API key)
ENABLE_HIBP=0
HIBP_API_KEY=your_hibp_api_key_here
HIBP_UA=EmailOSINTBot/0.1 (+https://github.com/your/repo)
```
Run the Bot
```bash
python bot_free.py
```

