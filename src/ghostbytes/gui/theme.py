"""Visual theme constants used by the Ghostbytes GUI."""

from pathlib import Path
from ghostbytes import __version__, __license__, __link__

ACCENT = "#1FB6A6"
ACCENT_HOVER = "#189485"
ACCENT_ON = "#03211D"
ACCENT_TINT = "#11302C"
ACCENT_BORDER = "#20463F"
DANGER = "#E5484D"
WARNING = "#F2A93B"
SUCCESS = "#3FC97F"

MONO_FONT = "Consolas"

SIDEBAR_LABELS = {
    "ENCRYPTION": "Encryption",
    "KEY MANAGEMENT": "Key management",
    "CRYPTO TOOLS": "Crypto tools",
    "SECURE STORAGE": "Secure storage",
}

TABS = {
    "HEADER": [("house", "Home")],
    "ENCRYPTION": [
        ("lock", "Encrypt / Decrypt"),
    ],
    "KEY MANAGEMENT": [
        ("key", "Generate Key Pair"),
        ("key", "Verify Key Pair"),
        ("key", "Key Information"),
    ],
    "CRYPTO TOOLS": [
        ("hashtag", "Hash File(s) (Checksum)"),
        ("dice", "Random"),
        ("dice", "Password Generator"),
        ("gauge-high", "Benchmark"),
    ],
    "SECURE STORAGE": [
        ("trash", "Secure Delete"),
        ("hard-drive", "Wipe Free Space"),
    ],
    "FOOTER": [("circle-info", "About")],
}

ACTIONS = [
    ("lock", "Encrypt File", "Secure a single file with strong encryption", "Encrypt / Decrypt"),
    ("lock-open", "Decrypt File", "Restore a file from its encrypted state", "Encrypt / Decrypt"),
    ("key", "Generate Key Pair", "Create an RSA or ML-KEM key pair", "Generate Key Pair"),
    ("circle-check", "Verify Key Pair", "Check if a key pair is matching", "Verify Key Pair"),
    ("hashtag", "Hash File", "Calculate a file's cryptographic hash", "Hash File(s) (Checksum)"),
    ("trash", "Secure Delete", "Permanently remove files, no traces left", "Secure Delete"),
    ("broom", "Wipe Free Space", "Remove traces from unused disk space", "Wipe Free Space"),
    ("dice", "Random", "Generate cryptographically random data", "Random"),
    ("gauge-high", "Benchmark", "Measure your machine's crypto performance", "Benchmark"),
]

ABOUT_BOX_CONTENT = [
    ("tag", "Version", __version__),
    ("scale-balanced", "License", __license__),
    ("github", "Source", __link__),
]

CAPABILITIES = [
    "AES-256-GCM",
    "Argon2id KDF",
    "Hybrid RSA-OAEP",
    "ML-KEM (PQC)",
    "Multi-pass secure erase",
]

CARD_WIDTH = 240
CARD_HEIGHT = 100
IMG_DIR = Path(__file__).resolve().parent.parent / "img"
ICON_PNG = IMG_DIR / "icon.png"
ICON_ICO = IMG_DIR / "icon.ico"

THEME = {
    "sidebar_bg": "#00000a",
    "content_bg": "#0f0f0f",
    "text_fg": "#9191C4",
    "font": "Roboto",
    "button_hover": "#1b67ca",
    "selected_tab": "#11518D",
    "corner_rad": 5,
    "content_text": "#d4e2ff",
    "slight_gray": "#cccccc",

    "box_color": "#181a1f",
    "box_border": "#252a35",
    "box_border_width": 1,

    "gray_text": "#3d3d3d"
}
