import logging
import random
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class AdaptiveEngine:
    """
    Powers the 'Self-Improving' aspect of the hunting engine.
    Analyzes failed probes and mutates them for higher success rates.
    """

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
    ]

    def __init__(self):
        self.mutation_history = {}

    def get_adaptive_headers(self) -> Dict[str, str]:
        """Provides rotated and randomized headers to bypass basic WAFs."""
        return {
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }

    def mutate_path(self, original_path: str, response_code: int) -> List[str]:
        """
        Suggests mutated paths if the original one failed (404/403).
        Example: /.env -> /.env.bak, /.env.old, /_env
        """
        mutations = []
        if response_code in [404, 403]:
            # common backup/alias patterns
            mutations.append(f"{original_path}.bak")
            mutations.append(f"{original_path}.old")
            mutations.append(f"{original_path}~")
            
            if original_path.startswith("/."):
                mutations.append(f"/{original_path[2:]}") # /.env -> /env
            
        return mutations

    def analyze_block(self, url: str, response_code: int, response_text: str) -> str:
        """Determines if we are being blocked by a WAF or a 429 rate limit."""
        if response_code == 429:
            return "RATE_LIMIT"
        if response_code == 403:
            # Common WAF signatures
            waf_hints = ["Cloudflare", "Akamai", "ModSecurity", "Imperva", "Sucuri"]
            for hint in waf_hints:
                if hint.lower() in response_text.lower():
                    return f"WAF_DETECTED_{hint.upper()}"
            return "ACCESS_FORBIDDEN"
        return "STABLE"
