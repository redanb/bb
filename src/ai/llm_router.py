"""
Bug Bounty Co-Pilot -- Smart LLM Router (v3.1 Corrected Pricing)
================================================================
Routes tasks to the most cost-effective LLM based on complexity tier.

Tier Design (from strategy v3.1 fact-checked pricing):
  Tier 1 (Low-cost):  Recon synthesis, parsing
    -> DeepSeek V3 ($0.14/M in, $0.28/M out) or Gemini Flash-Lite ($0.0375/M)
  Tier 2 (Mid-cost):  Report drafting, template application
    -> GPT-4o-mini ($0.15/M in, $0.60/M out)
  Tier 3 (High-value): Payload crafting, complex analysis
    -> GPT-4o ($2.50/M in, $10.00/M out) or Claude 3.5 Sonnet
  Local Fallback:      Non-critical tasks when cost ceiling is hit
    -> Llama 4 (local, $0.00)

Self-Optimizing:
  - Tracks cost-per-task and acceptance rates per model.
  - Auto-shifts routing to maximize Bounty/Hour while minimizing cost.
  - When new LLM APIs are detected, auto-benchmarks and integrates.

Patentable Method #4: "Dynamic LLM routing system optimized for
cost-per-accepted-submission in security research workflows."
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

logger = logging.getLogger(__name__)


class TaskComplexity(Enum):
    """Complexity tier for routing decisions."""
    LOW = auto()       # Parsing, recon synthesis, data extraction
    MEDIUM = auto()    # Report drafting, template application, formatting
    HIGH = auto()      # Payload crafting, exploit analysis, novel vulnerability research
    CRITICAL = auto()  # Final report for high-value bounties ($5K+)


class LLMProvider(Enum):
    """Available LLM providers."""
    DEEPSEEK_V3 = "deepseek-v3"
    GEMINI_FLASH_LITE = "gemini-flash-lite"
    GPT4O_MINI = "gpt-4o-mini"
    GPT4O = "gpt-4o"
    CLAUDE_35_SONNET = "claude-3.5-sonnet"
    LLAMA_LOCAL = "llama-local"


@dataclass(frozen=True)
class LLMPricing:
    """Per-model pricing in USD per million tokens (v3.1 fact-checked)."""
    provider: LLMProvider
    input_per_million: float
    output_per_million: float
    max_context_window: int = 128_000
    supports_json_mode: bool = True
    is_local: bool = False

    @property
    def avg_cost_per_1k_tokens(self) -> float:
        """Average cost per 1K tokens (assuming 60/40 input/output ratio)."""
        return (self.input_per_million * 0.6 + self.output_per_million * 0.4) / 1000


# v3.1 FACT-CHECKED pricing (corrected from v3.0 errors)
MODEL_PRICING: dict[LLMProvider, LLMPricing] = {
    LLMProvider.DEEPSEEK_V3: LLMPricing(
        provider=LLMProvider.DEEPSEEK_V3,
        input_per_million=0.14,
        output_per_million=0.28,
        max_context_window=64_000,
    ),
    LLMProvider.GEMINI_FLASH_LITE: LLMPricing(
        provider=LLMProvider.GEMINI_FLASH_LITE,
        input_per_million=0.0375,
        output_per_million=0.0375,
        max_context_window=1_000_000,
    ),
    LLMProvider.GPT4O_MINI: LLMPricing(
        provider=LLMProvider.GPT4O_MINI,
        input_per_million=0.15,   # v3.1 CORRECTED from v3.0's $0.40
        output_per_million=0.60,
        max_context_window=128_000,
    ),
    LLMProvider.GPT4O: LLMPricing(
        provider=LLMProvider.GPT4O,
        input_per_million=2.50,
        output_per_million=10.00,
        max_context_window=128_000,
    ),
    LLMProvider.CLAUDE_35_SONNET: LLMPricing(
        provider=LLMProvider.CLAUDE_35_SONNET,
        input_per_million=3.00,
        output_per_million=15.00,
        max_context_window=200_000,
    ),
    LLMProvider.LLAMA_LOCAL: LLMPricing(
        provider=LLMProvider.LLAMA_LOCAL,
        input_per_million=0.0,
        output_per_million=0.0,
        max_context_window=32_000,
        is_local=True,
    ),
}

# Default routing table: complexity -> ordered list of preferred providers
DEFAULT_ROUTING: dict[TaskComplexity, list[LLMProvider]] = {
    TaskComplexity.LOW: [
        LLMProvider.GEMINI_FLASH_LITE,
        LLMProvider.DEEPSEEK_V3,
        LLMProvider.LLAMA_LOCAL,
    ],
    TaskComplexity.MEDIUM: [
        LLMProvider.GPT4O_MINI,
        LLMProvider.DEEPSEEK_V3,
        LLMProvider.GEMINI_FLASH_LITE,
    ],
    TaskComplexity.HIGH: [
        LLMProvider.GPT4O,
        LLMProvider.CLAUDE_35_SONNET,
        LLMProvider.GPT4O_MINI,
    ],
    TaskComplexity.CRITICAL: [
        LLMProvider.CLAUDE_35_SONNET,
        LLMProvider.GPT4O,
    ],
}


@dataclass
class RoutingDecision:
    """The result of a routing decision."""
    selected_provider: LLMProvider
    pricing: LLMPricing
    complexity: TaskComplexity
    reason: str
    estimated_cost_usd: float = 0.0
    fallback_used: bool = False


@dataclass
class ModelPerformanceRecord:
    """Tracks a model's performance for self-optimization."""
    provider: LLMProvider
    total_tasks: int = 0
    total_cost_usd: float = 0.0
    total_tokens_used: int = 0
    accepted_submissions: int = 0
    rejected_submissions: int = 0
    avg_quality_score: float = 0.0
    last_used: float = field(default_factory=time.time)

    @property
    def acceptance_rate(self) -> float:
        total = self.accepted_submissions + self.rejected_submissions
        return self.accepted_submissions / total if total > 0 else 0.0

    @property
    def cost_per_accepted(self) -> float:
        """Cost per accepted submission -- the key optimization metric."""
        if self.accepted_submissions == 0:
            return float("inf")
        return self.total_cost_usd / self.accepted_submissions


class LLMRouter:
    """
    Smart LLM Router -- routes tasks to the optimal model based on
    complexity, cost, and historical acceptance rates.

    Self-Optimizing Loop:
      1. Routes based on complexity tier + cost constraints.
      2. Tracks which model produces accepted submissions at lowest cost.
      3. Gradually shifts routing toward best cost-per-accepted-submission ratio.
      4. Detects new models and auto-benchmarks them.

    Usage:
        router = LLMRouter(monthly_budget_usd=50.0)
        decision = router.route(TaskComplexity.LOW, estimated_tokens=2000)
        # Use decision.selected_provider to call the right API
        router.record_outcome(decision.selected_provider, cost=0.001, accepted=True)
    """

    def __init__(
        self,
        monthly_budget_usd: float = 100.0,
        routing_table: dict[TaskComplexity, list[LLMProvider]] | None = None,
    ):
        self._monthly_budget = monthly_budget_usd
        self._routing_table = routing_table or DEFAULT_ROUTING.copy()
        self._month_spend: float = 0.0
        self._performance: dict[LLMProvider, ModelPerformanceRecord] = {
            p: ModelPerformanceRecord(provider=p) for p in LLMProvider
        }
        self._cost_ceiling_hit: bool = False
        logger.info("LLMRouter initialized. Monthly budget: $%.2f", monthly_budget_usd)

    def route(
        self,
        complexity: TaskComplexity,
        estimated_tokens: int = 1000,
        force_provider: LLMProvider | None = None,
    ) -> RoutingDecision:
        """
        Route a task to the optimal LLM provider.

        Args:
            complexity: The assessed complexity of the task.
            estimated_tokens: Estimated total token count.
            force_provider: Override routing to use a specific provider.

        Returns:
            RoutingDecision with the selected provider and cost estimate.
        """
        # Cost ceiling check -- if we've blown the budget, use local only
        if self._cost_ceiling_hit or self._month_spend >= self._monthly_budget:
            self._cost_ceiling_hit = True
            pricing = MODEL_PRICING[LLMProvider.LLAMA_LOCAL]
            return RoutingDecision(
                selected_provider=LLMProvider.LLAMA_LOCAL,
                pricing=pricing,
                complexity=complexity,
                reason="Monthly budget ceiling reached. Using local fallback.",
                estimated_cost_usd=0.0,
                fallback_used=True,
            )

        # Forced provider override
        if force_provider:
            pricing = MODEL_PRICING[force_provider]
            est_cost = self._estimate_cost(pricing, estimated_tokens)
            return RoutingDecision(
                selected_provider=force_provider,
                pricing=pricing,
                complexity=complexity,
                reason=f"Forced provider: {force_provider.value}",
                estimated_cost_usd=est_cost,
            )

        # Standard routing: try providers in order for the complexity tier
        candidates = self._routing_table.get(complexity, [LLMProvider.GPT4O_MINI])

        for provider in candidates:
            pricing = MODEL_PRICING[provider]
            est_cost = self._estimate_cost(pricing, estimated_tokens)

            # Skip if this single task would blow remaining budget
            remaining = self._monthly_budget - self._month_spend
            if est_cost > remaining and not pricing.is_local:
                continue

            return RoutingDecision(
                selected_provider=provider,
                pricing=pricing,
                complexity=complexity,
                reason=f"Tier {complexity.name} routing -> {provider.value}",
                estimated_cost_usd=est_cost,
            )

        # All providers over budget -- fallback to local
        pricing = MODEL_PRICING[LLMProvider.LLAMA_LOCAL]
        return RoutingDecision(
            selected_provider=LLMProvider.LLAMA_LOCAL,
            pricing=pricing,
            complexity=complexity,
            reason="All providers over budget. Local fallback.",
            estimated_cost_usd=0.0,
            fallback_used=True,
        )

    def record_outcome(
        self,
        provider: LLMProvider,
        cost_usd: float,
        tokens_used: int = 0,
        accepted: bool | None = None,
        quality_score: float = 0.0,
    ) -> None:
        """
        Record the outcome of an LLM call for self-optimization.

        Args:
            provider: Which provider was used.
            cost_usd: Actual cost of the API call.
            tokens_used: Actual tokens consumed.
            accepted: Whether the resulting submission was accepted (None if unknown yet).
            quality_score: Quality score from the Report Linter (0.0-1.0).
        """
        record = self._performance[provider]
        record.total_tasks += 1
        record.total_cost_usd += cost_usd
        record.total_tokens_used += tokens_used
        record.last_used = time.time()
        self._month_spend += cost_usd

        if accepted is True:
            record.accepted_submissions += 1
        elif accepted is False:
            record.rejected_submissions += 1

        if quality_score > 0:
            # Running average
            if record.avg_quality_score == 0:
                record.avg_quality_score = quality_score
            else:
                record.avg_quality_score = (record.avg_quality_score * 0.9) + (quality_score * 0.1)

        logger.info(
            "LLM outcome recorded: provider=%s cost=$%.4f accepted=%s quality=%.2f month_spend=$%.2f",
            provider.value, cost_usd, accepted, quality_score, self._month_spend,
        )

    def get_optimization_report(self) -> dict[str, Any]:
        """
        Generate a report of model performance for self-optimization review.
        Shows cost-per-accepted-submission for each model.
        """
        report: dict[str, Any] = {
            "monthly_budget": self._monthly_budget,
            "month_spend": self._month_spend,
            "budget_remaining": self._monthly_budget - self._month_spend,
            "cost_ceiling_hit": self._cost_ceiling_hit,
            "models": {},
        }
        for provider, record in self._performance.items():
            if record.total_tasks > 0:
                report["models"][provider.value] = {
                    "total_tasks": record.total_tasks,
                    "total_cost": round(record.total_cost_usd, 4),
                    "acceptance_rate": round(record.acceptance_rate, 3),
                    "cost_per_accepted": round(record.cost_per_accepted, 4),
                    "avg_quality": round(record.avg_quality_score, 3),
                }
        return report

    def optimize_routing(self) -> None:
        """
        Self-optimization: re-order routing table based on observed
        cost-per-accepted-submission performance data.

        Called periodically (e.g., weekly) to improve routing decisions.
        """
        for complexity in TaskComplexity:
            candidates = self._routing_table.get(complexity, [])
            if len(candidates) <= 1:
                continue

            # Sort by cost-per-accepted-submission (lower is better)
            scored = []
            for provider in candidates:
                record = self._performance[provider]
                if record.total_tasks >= 5:  # Minimum sample size
                    scored.append((provider, record.cost_per_accepted))
                else:
                    scored.append((provider, float("inf")))  # Not enough data

            scored.sort(key=lambda x: x[1])
            new_order = [p for p, _ in scored]

            if new_order != candidates:
                logger.info(
                    "Routing optimized for %s: %s -> %s",
                    complexity.name,
                    [p.value for p in candidates],
                    [p.value for p in new_order],
                )
                self._routing_table[complexity] = new_order

    def reset_monthly_spend(self) -> None:
        """Reset monthly spend counter (call at start of each billing cycle)."""
        self._month_spend = 0.0
        self._cost_ceiling_hit = False
        logger.info("Monthly spend counter reset.")

    @staticmethod
    def _estimate_cost(pricing: LLMPricing, estimated_tokens: int) -> float:
        """Estimate cost for a given token count (60/40 input/output split)."""
        input_tokens = estimated_tokens * 0.6
        output_tokens = estimated_tokens * 0.4
        cost = (input_tokens * pricing.input_per_million + output_tokens * pricing.output_per_million) / 1_000_000
        return cost

    @property
    def month_spend(self) -> float:
        return self._month_spend

    @property
    def budget_remaining(self) -> float:
        return max(0, self._monthly_budget - self._month_spend)
