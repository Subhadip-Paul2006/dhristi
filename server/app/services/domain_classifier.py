"""Drishti Domain Classification & VPN Heuristics Engine.

Pure display-label lookup.
HARD INVARIANT: Never asserts an application is running. Only classifies
observed network traffic destinations into human-readable categories.
"""

from typing import TypedDict


class ClassificationResult(TypedDict):
    resolved_service_label: str | None
    category: str
    possible_vpn: bool
    confidence: str


STATIC_DOMAIN_SERVICES: dict[str, tuple[str, str]] = {
    "instagram.com": ("Instagram", "social"),
    "cdninstagram.com": ("Instagram", "social"),
    "facebook.com": ("Facebook", "social"),
    "fbcdn.net": ("Facebook", "social"),
    "twitter.com": ("Twitter / X", "social"),
    "x.com": ("Twitter / X", "social"),
    "tiktok.com": ("TikTok", "social"),
    "reddit.com": ("Reddit", "social"),
    "whatsapp.net": ("WhatsApp", "messaging"),
    "whatsapp.com": ("WhatsApp", "messaging"),
    "discord.com": ("Discord", "messaging"),
    "discord.gg": ("Discord", "messaging"),
    "discordapp.com": ("Discord", "messaging"),
    "telegram.org": ("Telegram", "messaging"),
    "slack.com": ("Slack", "messaging"),
    "youtube.com": ("YouTube", "streaming"),
    "googlevideo.com": ("YouTube", "streaming"),
    "netflix.com": ("Netflix", "streaming"),
    "nflxvideo.net": ("Netflix", "streaming"),
    "spotify.com": ("Spotify", "streaming"),
    "twitch.tv": ("Twitch", "streaming"),
    "primevideo.com": ("Prime Video", "streaming"),
    "steampowered.com": ("Steam", "gaming"),
    "steamcontent.com": ("Steam", "gaming"),
    "steamcommunity.com": ("Steam", "gaming"),
    "epicgames.com": ("Epic Games", "gaming"),
    "roblox.com": ("Roblox", "gaming"),
    "openai.com": ("ChatGPT", "ai"),
    "chatgpt.com": ("ChatGPT", "ai"),
    "claude.ai": ("Claude", "ai"),
    "anthropic.com": ("Claude", "ai"),
    "perplexity.ai": ("Perplexity AI", "ai"),
    "github.com": ("GitHub", "developer"),
    "substack.com": ("Substack", "news"),
}

STATIC_VPN_DOMAINS: set[str] = {
    "expressvpn.com",
    "protonvpn.com",
    "protonvpn.net",
    "nordvpn.com",
    "mullvad.net",
    "surfshark.com",
}


def classify_domain(
    domain: str,
    dest_port: int | None = None,
    is_udp_tunnel: bool = False,
) -> ClassificationResult:
    domain_clean = (domain or "").lower().strip()
    if domain_clean.startswith("www."):
        domain_clean = domain_clean[4:]

    if domain_clean in STATIC_DOMAIN_SERVICES:
        label, cat = STATIC_DOMAIN_SERVICES[domain_clean]
        return {
            "resolved_service_label": label,
            "category": cat,
            "possible_vpn": False,
            "confidence": "high",
        }

    for k, (label, cat) in STATIC_DOMAIN_SERVICES.items():
        if domain_clean.endswith("." + k):
            return {
                "resolved_service_label": label,
                "category": cat,
                "possible_vpn": False,
                "confidence": "high",
            }

    if domain_clean == "riotgames.com" or domain_clean.endswith(".riotgames.com"):
        return {
            "resolved_service_label": "Riot Games (Valorant/LoL)",
            "category": "gaming",
            "possible_vpn": False,
            "confidence": "high",
        }

    for vpn in STATIC_VPN_DOMAINS:
        if domain_clean == vpn or domain_clean.endswith("." + vpn):
            return {
                "resolved_service_label": "Unknown VPN?",
                "category": "vpn",
                "possible_vpn": True,
                "confidence": "medium",
            }

    if (dest_port in (51820, 1194) or is_udp_tunnel) and domain_clean:
        if "." not in domain_clean or domain_clean.replace(".", "").isdigit():
            return {
                "resolved_service_label": "Possible VPN/Tunnel",
                "category": "vpn",
                "possible_vpn": True,
                "confidence": "low",
            }

    return {
        "resolved_service_label": None,
        "category": "unclassified",
        "possible_vpn": False,
        "confidence": "medium",
    }
