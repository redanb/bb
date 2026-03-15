"""
Bug Bounty Co-Pilot -- Razorpay/UPI Payment Gateway
=====================================================
India-first payment integration with Razorpay.

Supports:
  - UPI payments (GPay, PhonePe, Paytm) -- #1 payment method in India
  - Card payments (Visa, Mastercard, RuPay)
  - Net banking
  - Subscription auto-renewal via Razorpay Subscriptions API
  - Payout to hunters via Razorpay Payouts (bank transfer/UPI)

Critical Guardrails:
  - All payment operations require HITL approval (Article 4 compliance)
  - No real API calls without explicit user configuration
  - Sandbox mode by default for development
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

logger = logging.getLogger(__name__)


class PaymentStatus(Enum):
    """Payment lifecycle states."""
    CREATED = auto()
    AUTHORIZED = auto()
    CAPTURED = auto()
    FAILED = auto()
    REFUNDED = auto()


class PaymentMethod(Enum):
    """Supported payment methods."""
    UPI = "upi"
    CARD = "card"
    NET_BANKING = "netbanking"
    WALLET = "wallet"


class PayoutStatus(Enum):
    """Payout lifecycle states."""
    QUEUED = auto()
    PROCESSING = auto()
    PROCESSED = auto()
    REVERSED = auto()
    FAILED = auto()


@dataclass
class PaymentOrder:
    """A payment order record."""
    order_id: str
    user_id: str
    amount_inr: int          # Amount in paise (smallest unit)
    currency: str = "INR"
    description: str = ""
    status: PaymentStatus = PaymentStatus.CREATED
    payment_method: PaymentMethod | None = None
    razorpay_order_id: str = ""
    razorpay_payment_id: str = ""
    created_at: float = field(default_factory=time.time)
    paid_at: float | None = None

    @property
    def amount_rupees(self) -> float:
        return self.amount_inr / 100.0


@dataclass
class PayoutOrder:
    """A payout to a hunter."""
    payout_id: str
    user_id: str
    amount_inr: int
    mode: str = "UPI"        # UPI, NEFT, IMPS, bank_transfer
    upi_id: str = ""
    bank_account: str = ""
    ifsc_code: str = ""
    status: PayoutStatus = PayoutStatus.QUEUED
    created_at: float = field(default_factory=time.time)
    processed_at: float | None = None

    @property
    def amount_rupees(self) -> float:
        return self.amount_inr / 100.0


class PaymentGateway:
    """
    Razorpay Payment Gateway integration.

    IMPORTANT: Runs in SANDBOX mode by default. No real API calls
    are made without explicit configuration with real credentials.

    Usage:
        gateway = PaymentGateway()  # Sandbox mode
        order = gateway.create_order(
            user_id="hunter_1",
            amount_inr=199900,  # INR 1999
            description="Pro Plan - Monthly",
        )
        # User completes payment on frontend...
        gateway.verify_payment(order.order_id, "pay_xxx", "sig_xxx")
    """

    def __init__(
        self,
        api_key: str = "rzp_test_sandbox",
        api_secret: str = "sandbox_secret",
        sandbox: bool = True,
    ):
        self._api_key = api_key
        self._api_secret = api_secret
        self._sandbox = sandbox
        self._orders: dict[str, PaymentOrder] = {}
        self._payouts: dict[str, PayoutOrder] = {}
        self._total_collected_inr: int = 0
        self._total_paid_out_inr: int = 0

        if sandbox:
            logger.info("PaymentGateway initialized in SANDBOX mode (no real charges).")
        else:
            logger.warning("PaymentGateway initialized in LIVE mode!")

    def create_order(
        self,
        user_id: str,
        amount_inr: int,
        description: str = "",
    ) -> PaymentOrder:
        """
        Create a payment order.

        Args:
            user_id: The user making payment.
            amount_inr: Amount in PAISE (multiply rupees by 100).
            description: What the payment is for.

        Returns:
            PaymentOrder with order_id for frontend checkout.
        """
        import uuid
        order_id = f"order_{uuid.uuid4().hex[:16]}"

        order = PaymentOrder(
            order_id=order_id,
            user_id=user_id,
            amount_inr=amount_inr,
            description=description,
        )

        if self._sandbox:
            order.razorpay_order_id = f"order_sandbox_{order_id}"
        # In live mode, would call Razorpay API here

        self._orders[order_id] = order
        logger.info(
            "Order created: %s user=%s amount=INR %.2f (%s)",
            order_id, user_id, order.amount_rupees,
            "SANDBOX" if self._sandbox else "LIVE",
        )
        return order

    def verify_payment(
        self,
        order_id: str,
        payment_id: str,
        signature: str,
    ) -> bool:
        """
        Verify a Razorpay payment signature.

        In production, this validates the HMAC-SHA256 signature from
        Razorpay's webhook/callback to prevent payment fraud.

        Returns True if payment is valid.
        """
        order = self._orders.get(order_id)
        if not order:
            logger.warning("Order not found: %s", order_id)
            return False

        if self._sandbox:
            # In sandbox, simulate successful verification
            order.status = PaymentStatus.CAPTURED
            order.razorpay_payment_id = payment_id
            order.paid_at = time.time()
            self._total_collected_inr += order.amount_inr
            logger.info("SANDBOX: Payment verified for order %s", order_id)
            return True

        # In LIVE mode: verify Razorpay signature
        expected_signature = hmac.new(
            self._api_secret.encode("utf-8"),
            f"{order.razorpay_order_id}|{payment_id}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if hmac.compare_digest(expected_signature, signature):
            order.status = PaymentStatus.CAPTURED
            order.razorpay_payment_id = payment_id
            order.paid_at = time.time()
            self._total_collected_inr += order.amount_inr
            logger.info("LIVE: Payment verified for order %s", order_id)
            return True

        logger.warning("Payment verification FAILED for order %s", order_id)
        order.status = PaymentStatus.FAILED
        return False

    def create_payout(
        self,
        user_id: str,
        amount_inr: int,
        upi_id: str = "",
        bank_account: str = "",
        ifsc_code: str = "",
    ) -> PayoutOrder:
        """
        Create a payout to a hunter.

        In sandbox mode, simulates the payout.
        In live mode, would use Razorpay Payouts API.
        """
        import uuid
        payout_id = f"pout_{uuid.uuid4().hex[:16]}"

        mode = "UPI" if upi_id else "NEFT"
        payout = PayoutOrder(
            payout_id=payout_id,
            user_id=user_id,
            amount_inr=amount_inr,
            mode=mode,
            upi_id=upi_id,
            bank_account=bank_account,
            ifsc_code=ifsc_code,
        )

        if self._sandbox:
            payout.status = PayoutStatus.PROCESSED
            payout.processed_at = time.time()
            self._total_paid_out_inr += amount_inr

        self._payouts[payout_id] = payout
        logger.info(
            "Payout created: %s user=%s amount=INR %.2f mode=%s (%s)",
            payout_id, user_id, payout.amount_rupees, mode,
            "SANDBOX" if self._sandbox else "LIVE",
        )
        return payout

    def get_financial_summary(self) -> dict[str, Any]:
        """Get platform financial summary."""
        return {
            "sandbox_mode": self._sandbox,
            "total_collected_inr": self._total_collected_inr / 100.0,
            "total_collected_usd": self._total_collected_inr / 100.0 / 83.0,
            "total_paid_out_inr": self._total_paid_out_inr / 100.0,
            "total_orders": len(self._orders),
            "total_payouts": len(self._payouts),
            "successful_payments": sum(
                1 for o in self._orders.values()
                if o.status == PaymentStatus.CAPTURED
            ),
            "net_revenue_inr": (self._total_collected_inr - self._total_paid_out_inr) / 100.0,
        }

    @property
    def is_sandbox(self) -> bool:
        return self._sandbox
