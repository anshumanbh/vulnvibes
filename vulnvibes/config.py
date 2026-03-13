"""Configuration management for vuln-triage-agent."""

import os
from dataclasses import dataclass
from typing import Optional


# Model alias mapping
MODEL_ALIASES = {
    "sonnet": "claude-sonnet-4-5-20250929",
    "opus": "claude-opus-4-5-20251101",
    "haiku": "claude-haiku-4-5-20251001",
}


class AgentConfig:
    """Configuration for agent model selection with CLI override support.
    
    Priority hierarchy:
    1. Per-agent env vars (VULNTRIAGE_<AGENT>_MODEL) - highest priority
    2. cli_model parameter (from CLI --model flag) - medium priority
    3. Default "sonnet" - lowest priority
    """
    
    DEFAULTS = {
        "model": "sonnet",
        "max_tool_calls": 30,
    }
    
    def get_agent_model(
        self,
        agent_name: str,
        cli_override: Optional[str] = None
    ) -> str:
        """
        Get model for agent with priority cascade.
        
        Args:
            agent_name: Agent identifier (e.g., "pr_analyzer", "vuln_investigator")
            cli_override: Optional model from CLI --model flag
        
        Returns:
            Model alias (sonnet, opus, haiku) or full model ID
        """
        env_key = f"VULNTRIAGE_{agent_name.upper().replace('-', '_')}_MODEL"
        
        # Priority 1: Per-agent env var
        if env_val := os.environ.get(env_key):
            return self._resolve_model(env_val)
        
        # Priority 2: CLI override
        if cli_override:
            return self._resolve_model(cli_override)
        
        # Priority 3: Default
        return self.DEFAULTS["model"]
    
    def _resolve_model(self, model: str) -> str:
        """Resolve model alias to full model ID if needed."""
        return MODEL_ALIASES.get(model.lower(), model)


# Global agent config instance
agent_config = AgentConfig()


@dataclass
class Config:
    """Configuration for the vulnerability triage agent."""
    
    github_token: str
    anthropic_api_key: str
    model_id: str = "claude-sonnet-4-5-20250929"
    max_tool_calls: int = 30
    github_base_url: str = "https://api.github.com"
    
    @classmethod
    def from_env(cls) -> "Config":
        """
        Load configuration from environment variables.
        
        Returns:
            Config instance
        
        Raises:
            ValueError: If required environment variables are not set
        """
        github_token = os.getenv("GITHUB_TOKEN")
        if not github_token:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        
        anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", "")
        
        return cls(
            github_token=github_token,
            anthropic_api_key=anthropic_api_key,
            model_id=os.getenv("MODEL_ID", "claude-sonnet-4-5-20250929"),
            max_tool_calls=int(os.getenv("MAX_TOOL_CALLS", "30")),
            github_base_url=os.getenv("GITHUB_BASE_URL", "https://api.github.com"),
        )

