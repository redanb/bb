"""
Bug Bounty Co-Pilot -- Subscription Tier Engine
=================================================
Manages the 4-tier subscription model with psychological pricing.

Tiers (v4.0 Pricing Architecture):
  Free:   0/mo   -- 3 reports/mo, basic recon, community
  Growth: 499/mo -- 15 reports/mo, smart routing, dup prediction
  Pro:    1999/mo -- 50 reports/mo, full AI, acceptance graph, priority
  Elite:  4999/mo -- Unlimited, 1-on-1 coaching, custom models, SLA

Pricing Psychology (v4.0 Part 3):
  - Anchoring: Elite shown first to anchor against
  - Decoy: Growth positioned as decoy to push Pro
  - Odd pricing: 499/1999/4999 (below round numbers)
  - Income Guarantee: "Earn more than your subscription or money back"
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

logger = logging.getLogger(__name__)


class SubscriptionTier(Enum):
    """Available subscription tiers."""
    FREE = "free"
    GROWTH = "growth"
    PRO = "pro"
    ELITE = "elite"


@dataclass(frozen=True)
class TierConfig:
    """Configuration for a subscription tier."""
    tier: SubscriptionTier
    price_inr_monthly: int
    price_inr_annual: int        # Annual price (discounted)
    reports_per_month: int       # -1 for unlimited
    has_smart_routing: bool
    has_dup_prediction: bool
    has_acceptance_graph: bool
    has_report_linter: bool
    has_income_guarantee: bool
    has_priority_support: bool
    has_custom_models: bool
    revenue_share_pct: float     # Platform's cut of bounties
    display_name: str
    tagline: str


# v4.0 Tier Configuration with psychological pricing
TIER_CONFIGS: dict[SubscriptionTier, TierConfig] = {
    SubscriptionTier.FREE: TierConfig(
        tier=SubscriptionTier.FREE,
        price_inr_monthly=0,
        price_inr_annual=0,
        reports_per_month=3,
        has_smart_routing=False,
        has_dup_prediction=False,
        has_acceptance_graph=False,
        has_report_linter=True,    # Give enough value to hook
        has_income_guarantee=False,
        has_priority_support=False,
        has_custom_models=False,
        revenue_share_pct=20.0,    # Higher rev share on free tier
        display_name="Starter",
        tagline="Get started with AI-powered bug hunting",
    ),
    SubscriptionTier.GROWTH: TierConfig(
        tier=SubscriptionTier.GROWTH,
        price_inr_monthly=499,
        price_inr_annual=4990,     # ~17% discount
        reports_per_month=15,
        has_smart_routing=True,
        has_dup_prediction=True,
        has_acceptance_graph=False,  # Decoy: missing key feature
        has_report_linter=True,
        has_income_guarantee=False,
        has_priority_support=False,
        has_custom_models=False,
        revenue_share_pct=15.0,
        display_name="Growth",
        tagline="Scale your bug hunting output",
    ),
    SubscriptionTier.PRO: TierConfig(
        tier=SubscriptionTier.PRO,
        price_inr_monthly=1999,
        price_inr_annual=19990,    # ~17% discount
        reports_per_month=50,
        has_smart_routing=True,
        has_dup_prediction=True,
        has_acceptance_graph=True,   # The key differentiator
        has_report_linter=True,
        has_income_guarantee=True,
        has_priority_support=True,
        has_custom_models=False,
        revenue_share_pct=10.0,
        display_name="Pro",
        tagline="Maximize your Bounty/Hour with full AI power",
    ),
    SubscriptionTier.ELITE: TierConfig(
        tier=SubscriptionTier.ELITE,
        price_inr_monthly=4999,
        price_inr_annual=49990,    # ~17% discount
        reports_per_month=-1,      # Unlimited
        has_smart_routing=True,
        has_dup_prediction=True,
        has_acceptance_graph=True,
        has_report_linter=True,
        has_income_guarantee=True,
        has_priority_support=True,
        has_custom_models=True,
        revenue_share_pct=10.0,
        display_name="Elite",
        tagline="Enterprise-grade AI co-pilot with 1-on-1 coaching",
    ),
}


@dataclass
class UserSubscription:
    """A user's active subscription."""
    user_id: str
    tier: SubscriptionTier
    started_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    is_annual: bool = False
    reports_used_this_month: int = 0
    total_bounty_earned_usd: float = 0.0

    @property
    def config(self) -> TierConfig:
        return TIER_CONFIGS[self.tier]

    @property
    def is_active(self) -> bool:
        if self.tier == SubscriptionTier.FREE:
            return True
        return time.time() < self.expires_at

    @property
    def reports_remaining(self) -> int:
        limit = self.config.reports_per_month
        if limit == -1:
            return 999  # Unlimited
        return max(0, limit - self.reports_used_this_month)

    @property
    def can_submit_report(self) -> bool:
        return self.is_active and self.reports_remaining > 0


class SubscriptionEngine:
    """
    Manages user subscriptions and feature gating.

    Usage:
        engine = SubscriptionEngine()
        sub = engine.create_subscription("user_1", SubscriptionTier.PRO)
        if sub.can_submit_report:
            engine.use_report(sub)
        features = engine.get_available_features(sub)
    """

    def __init__(self):
        self._subscriptions: dict[str, UserSubscription] = {}
        logger.info("SubscriptionEngine initialized.")

    def create_subscription(
        self,
        user_id: str,
        tier: SubscriptionTier,
        is_annual: bool = False,
    ) -> UserSubscription:
        """Create or upgrade a user's subscription."""
        config = TIER_CONFIGS[tier]
        now = time.time()

        if is_annual:
            expires = now + (365 * 24 * 3600)
        elif tier == SubscriptionTier.FREE:
            expires = now + (100 * 365 * 24 * 3600)  # Effectively never
        else:
            expires = now + (30 * 24 * 3600)  # 30 days

        sub = UserSubscription(
            user_id=user_id,
            tier=tier,
            started_at=now,
            expires_at=expires,
            is_annual=is_annual,
        )
        self._subscriptions[user_id] = sub
        logger.info(
            "Subscription created: user=%s tier=%s annual=%s price=INR %d",
            user_id, tier.value, is_annual,
            config.price_inr_annual if is_annual else config.price_inr_monthly,
        )
        return sub

    def get_subscription(self, user_id: str) -> UserSubscription | None:
        return self._subscriptions.get(user_id)

    def use_report(self, sub: UserSubscription) -> bool:
        """Consume one report credit. Returns True if allowed."""
        if not sub.can_submit_report:
            logger.warning("Report denied: user=%s (remaining=%d)", sub.user_id, sub.reports_remaining)
            return False
        sub.reports_used_this_month += 1
        return True

    def reset_monthly_reports(self) -> None:
        """Reset all users' monthly report counts (call on billing cycle)."""
        for sub in self._subscriptions.values():
            sub.reports_used_this_month = 0
        logger.info("Monthly report counts reset for %d users.", len(self._subscriptions))

    def get_available_features(self, sub: UserSubscription) -> dict[str, bool]:
        """Get the feature flags for a user's subscription."""
        config = sub.config
        return {
            "smart_routing": config.has_smart_routing,
            "dup_prediction": config.has_dup_prediction,
            "acceptance_graph": config.has_acceptance_graph,
            "report_linter": config.has_report_linter,
            "income_guarantee": config.has_income_guarantee,
            "priority_support": config.has_priority_support,
            "custom_models": config.has_custom_models,
            "reports_remaining": sub.reports_remaining,
        }

    def calculate_upgrade_value(self, user_id: str) -> dict[str, Any]:
        """
        Calculate the value proposition for upgrading.
        Used for upsell prompts (behavioral economics - anchoring).
        """
        sub = self._subscriptions.get(user_id)
        if not sub:
            return {"recommendation": "Start with Free tier"}

        current = sub.config
        tiers_ordered = [SubscriptionTier.FREE, SubscriptionTier.GROWTH, SubscriptionTier.PRO, SubscriptionTier.ELITE]
        current_idx = tiers_ordered.index(sub.tier)

        if current_idx >= len(tiers_ordered) - 1:
            return {"recommendation": "You're on the highest tier!"}

        next_tier = tiers_ordered[current_idx + 1]
        next_config = TIER_CONFIGS[next_tier]

        # Calculate value delta
        new_features = []
        if next_config.has_acceptance_graph and not current.has_acceptance_graph:
            new_features.append("Acceptance Intelligence Graph (2.3x acceptance rate boost)")
        if next_config.has_income_guarantee and not current.has_income_guarantee:
            new_features.append("Income Guarantee (earn your subscription back or refund)")
        if next_config.has_dup_prediction and not current.has_dup_prediction:
            new_features.append("Duplicate Prediction (save hours on avoided duplicates)")
        if next_config.reports_per_month > current.reports_per_month or next_config.reports_per_month == -1:
            new_features.append(f"More reports: {current.reports_per_month} -> {'Unlimited' if next_config.reports_per_month == -1 else next_config.reports_per_month}")
        if next_config.revenue_share_pct < current.revenue_share_pct:
            new_features.append(f"Lower revenue share: {current.revenue_share_pct}% -> {next_config.revenue_share_pct}%")

        return {
            "current_tier": current.display_name,
            "recommended_tier": next_config.display_name,
            "price_increase_inr": next_config.price_inr_monthly - current.price_inr_monthly,
            "new_features": new_features,
            "recommendation": f"Upgrade to {next_config.display_name}: {next_config.tagline}",
        }

    def get_pricing_display(self) -> list[dict[str, Any]]:
        """
        Generate pricing page data with psychological anchoring.
        Returns tiers in REVERSE order (Elite first) for anchoring effect.
        """
        display = []
        for tier in reversed([SubscriptionTier.FREE, SubscriptionTier.GROWTH, SubscriptionTier.PRO, SubscriptionTier.ELITE]):
            config = TIER_CONFIGS[tier]
            entry: dict[str, Any] = {
                "tier": config.display_name,
                "price_monthly": config.price_inr_monthly,
                "price_annual": config.price_inr_annual,
                "tagline": config.tagline,
                "reports": "Unlimited" if config.reports_per_month == -1 else config.reports_per_month,
                "revenue_share": f"{config.revenue_share_pct}%",
                "is_popular": tier == SubscriptionTier.PRO,  # Badge for decoy effect
            }
            display.append(entry)
        return display
