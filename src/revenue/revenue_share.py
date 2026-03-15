"""
Bug Bounty Co-Pilot -- Revenue Share Calculator
=================================================
Calculates the platform's revenue share from bounties earned by users.

Revenue Share Tiers (v4.0):
  Free:   20% -- Higher share offsets zero subscription fee
  Growth: 15% -- Moderate share with subscription revenue
  Pro:    10% -- Lower share, users pay premium subscription
  Elite:  10% -- Same as Pro, volume makes up the difference

This is Revenue Stream #2 -- most scalable as users earn more bounties.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from src.revenue.subscription_engine import SubscriptionTier, TIER_CONFIGS

logger = logging.getLogger(__name__)


# Revenue share percentages per tier
REVENUE_SHARE_PCT: dict[SubscriptionTier, float] = {
    tier: config.revenue_share_pct
    for tier, config in TIER_CONFIGS.items()
}


@dataclass
class BountyTransaction:
    """A single bounty transaction record."""
    transaction_id: str
    user_id: str
    program_id: str
    platform: str
    bounty_amount_usd: float
    user_tier: SubscriptionTier
    revenue_share_pct: float = 0.0
    platform_cut_usd: float = 0.0
    user_payout_usd: float = 0.0
    timestamp: float = field(default_factory=time.time)

    @property
    def platform_cut_inr(self) -> float:
        """Convert to INR (approximate, for display)."""
        return self.platform_cut_usd * 83.0  # Approximate USD/INR


@dataclass
class PayoutSummary:
    """Payout summary for a user over a period."""
    user_id: str
    period_start: float
    period_end: float
    total_bounty_usd: float = 0.0
    total_platform_cut_usd: float = 0.0
    total_user_payout_usd: float = 0.0
    transaction_count: int = 0
    user_tier: SubscriptionTier = SubscriptionTier.FREE


class RevenueShareCalculator:
    """
    Calculates and tracks revenue share from user bounties.

    Usage:
        calc = RevenueShareCalculator()
        tx = calc.process_bounty(
            user_id="hunter_1",
            bounty_usd=500.0,
            user_tier=SubscriptionTier.PRO,
            program_id="prog_1",
            platform="hackerone",
        )
        # tx.platform_cut_usd = $50 (10% of $500)
        # tx.user_payout_usd = $450
    """

    def __init__(self):
        self._transactions: list[BountyTransaction] = []
        self._user_totals: dict[str, float] = {}
        self._total_platform_revenue: float = 0.0
        logger.info("RevenueShareCalculator initialized.")

    def process_bounty(
        self,
        user_id: str,
        bounty_usd: float,
        user_tier: SubscriptionTier,
        program_id: str = "",
        platform: str = "",
        transaction_id: str = "",
    ) -> BountyTransaction:
        """
        Process a bounty payment and calculate revenue share.

        Returns:
            BountyTransaction with platform cut and user payout calculated.
        """
        import uuid
        tx_id = transaction_id or uuid.uuid4().hex

        share_pct = REVENUE_SHARE_PCT.get(user_tier, 20.0)
        platform_cut = bounty_usd * (share_pct / 100.0)
        user_payout = bounty_usd - platform_cut

        tx = BountyTransaction(
            transaction_id=tx_id,
            user_id=user_id,
            program_id=program_id,
            platform=platform,
            bounty_amount_usd=bounty_usd,
            user_tier=user_tier,
            revenue_share_pct=share_pct,
            platform_cut_usd=platform_cut,
            user_payout_usd=user_payout,
        )
        self._transactions.append(tx)
        self._total_platform_revenue += platform_cut
        self._user_totals[user_id] = self._user_totals.get(user_id, 0.0) + platform_cut

        logger.info(
            "Bounty processed: user=%s amount=$%.2f share=%.0f%% platform_cut=$%.2f user_payout=$%.2f",
            user_id, bounty_usd, share_pct, platform_cut, user_payout,
        )

        return tx

    def get_user_payout_summary(self, user_id: str) -> PayoutSummary:
        """Get payout summary for a specific user."""
        user_txs = [t for t in self._transactions if t.user_id == user_id]
        if not user_txs:
            return PayoutSummary(user_id=user_id, period_start=0, period_end=0)

        return PayoutSummary(
            user_id=user_id,
            period_start=min(t.timestamp for t in user_txs),
            period_end=max(t.timestamp for t in user_txs),
            total_bounty_usd=sum(t.bounty_amount_usd for t in user_txs),
            total_platform_cut_usd=sum(t.platform_cut_usd for t in user_txs),
            total_user_payout_usd=sum(t.user_payout_usd for t in user_txs),
            transaction_count=len(user_txs),
            user_tier=user_txs[-1].user_tier,
        )

    def get_platform_revenue_report(self) -> dict[str, Any]:
        """Generate platform-level revenue report."""
        monthly_rev = {}
        for tx in self._transactions:
            month_key = time.strftime("%Y-%m", time.localtime(tx.timestamp))
            monthly_rev[month_key] = monthly_rev.get(month_key, 0.0) + tx.platform_cut_usd

        by_tier = {}
        for tier in SubscriptionTier:
            tier_txs = [t for t in self._transactions if t.user_tier == tier]
            by_tier[tier.value] = {
                "transaction_count": len(tier_txs),
                "total_bounty": sum(t.bounty_amount_usd for t in tier_txs),
                "total_platform_cut": sum(t.platform_cut_usd for t in tier_txs),
            }

        return {
            "total_platform_revenue_usd": round(self._total_platform_revenue, 2),
            "total_platform_revenue_inr": round(self._total_platform_revenue * 83, 2),
            "total_transactions": len(self._transactions),
            "unique_users": len(self._user_totals),
            "revenue_by_tier": by_tier,
            "monthly_revenue": monthly_rev,
        }

    @property
    def total_revenue(self) -> float:
        return self._total_platform_revenue
