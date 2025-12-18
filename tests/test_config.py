"""Tests for configuration module."""

import os
import pytest

from vulnvibes.config import AgentConfig, Config, MODEL_ALIASES, agent_config


class TestModelAliases:
    """Tests for MODEL_ALIASES mapping."""
    
    def test_sonnet_alias(self):
        """Test sonnet alias maps to correct model ID."""
        assert "sonnet" in MODEL_ALIASES
        assert "claude-sonnet" in MODEL_ALIASES["sonnet"]
    
    def test_opus_alias(self):
        """Test opus alias maps to correct model ID."""
        assert "opus" in MODEL_ALIASES
        assert "claude-opus" in MODEL_ALIASES["opus"]
    
    def test_haiku_alias(self):
        """Test haiku alias maps to correct model ID."""
        assert "haiku" in MODEL_ALIASES
        assert "claude-haiku" in MODEL_ALIASES["haiku"]
    
    def test_all_aliases_are_strings(self):
        """Test all alias values are strings."""
        for alias, model_id in MODEL_ALIASES.items():
            assert isinstance(alias, str)
            assert isinstance(model_id, str)


class TestAgentConfig:
    """Tests for AgentConfig class."""
    
    def test_default_model(self):
        """Test default model is sonnet."""
        config = AgentConfig()
        assert config.DEFAULTS["model"] == "sonnet"
    
    def test_resolve_model_with_alias(self):
        """Test _resolve_model converts alias to full model ID."""
        config = AgentConfig()
        resolved = config._resolve_model("sonnet")
        assert resolved == MODEL_ALIASES["sonnet"]
    
    def test_resolve_model_case_insensitive(self):
        """Test _resolve_model is case insensitive."""
        config = AgentConfig()
        assert config._resolve_model("SONNET") == MODEL_ALIASES["sonnet"]
        assert config._resolve_model("Opus") == MODEL_ALIASES["opus"]
    
    def test_resolve_model_passthrough(self):
        """Test _resolve_model passes through unknown models."""
        config = AgentConfig()
        custom_model = "claude-3-custom-20240101"
        assert config._resolve_model(custom_model) == custom_model
    
    def test_get_agent_model_default(self):
        """Test get_agent_model returns default when no override."""
        config = AgentConfig()
        # Clear any env vars that might interfere
        env_key = "VULNTRIAGE_PR_ANALYZER_MODEL"
        original = os.environ.pop(env_key, None)
        try:
            model = config.get_agent_model("pr_analyzer")
            assert model == "sonnet"
        finally:
            if original:
                os.environ[env_key] = original
    
    def test_get_agent_model_cli_override(self):
        """Test get_agent_model respects CLI override."""
        config = AgentConfig()
        env_key = "VULNTRIAGE_PR_ANALYZER_MODEL"
        original = os.environ.pop(env_key, None)
        try:
            model = config.get_agent_model("pr_analyzer", cli_override="opus")
            assert model == MODEL_ALIASES["opus"]
        finally:
            if original:
                os.environ[env_key] = original
    
    def test_get_agent_model_env_override(self):
        """Test get_agent_model respects env var (highest priority)."""
        config = AgentConfig()
        env_key = "VULNTRIAGE_PR_ANALYZER_MODEL"
        original = os.environ.get(env_key)
        try:
            os.environ[env_key] = "haiku"
            model = config.get_agent_model("pr_analyzer", cli_override="opus")
            # Env var should win over CLI
            assert model == MODEL_ALIASES["haiku"]
        finally:
            if original:
                os.environ[env_key] = original
            else:
                os.environ.pop(env_key, None)
    
    def test_get_agent_model_env_key_format(self):
        """Test env key is correctly formatted for different agent names."""
        config = AgentConfig()
        # Test with hyphenated name
        env_key = "VULNTRIAGE_VULN_INVESTIGATOR_MODEL"
        original = os.environ.get(env_key)
        try:
            os.environ[env_key] = "opus"
            model = config.get_agent_model("vuln_investigator")
            assert model == MODEL_ALIASES["opus"]
        finally:
            if original:
                os.environ[env_key] = original
            else:
                os.environ.pop(env_key, None)


class TestGlobalAgentConfig:
    """Tests for global agent_config instance."""
    
    def test_global_instance_exists(self):
        """Test that global agent_config is available."""
        assert agent_config is not None
        assert isinstance(agent_config, AgentConfig)


class TestConfig:
    """Tests for Config dataclass."""
    
    def test_creation(self):
        """Test Config creation with required fields."""
        config = Config(
            github_token="test-github-token",
            anthropic_api_key="test-anthropic-key"
        )
        assert config.github_token == "test-github-token"
        assert config.anthropic_api_key == "test-anthropic-key"
    
    def test_defaults(self):
        """Test Config default values."""
        config = Config(
            github_token="token",
            anthropic_api_key="key"
        )
        assert config.max_tool_calls == 30
        assert config.github_base_url == "https://api.github.com"
        assert "claude-sonnet" in config.model_id
    
    def test_from_env_missing_github_token(self):
        """Test from_env raises when GITHUB_TOKEN missing."""
        original_github = os.environ.pop("GITHUB_TOKEN", None)
        original_anthropic = os.environ.get("ANTHROPIC_API_KEY")
        try:
            os.environ["ANTHROPIC_API_KEY"] = "test-key"
            with pytest.raises(ValueError, match="GITHUB_TOKEN"):
                Config.from_env()
        finally:
            if original_github:
                os.environ["GITHUB_TOKEN"] = original_github
            if original_anthropic:
                os.environ["ANTHROPIC_API_KEY"] = original_anthropic
    
    def test_from_env_missing_anthropic_key(self):
        """Test from_env raises when ANTHROPIC_API_KEY missing."""
        original_github = os.environ.get("GITHUB_TOKEN")
        original_anthropic = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            os.environ["GITHUB_TOKEN"] = "test-token"
            with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
                Config.from_env()
        finally:
            if original_github:
                os.environ["GITHUB_TOKEN"] = original_github
            else:
                os.environ.pop("GITHUB_TOKEN", None)
            if original_anthropic:
                os.environ["ANTHROPIC_API_KEY"] = original_anthropic
    
    def test_from_env_success(self):
        """Test from_env succeeds with required env vars."""
        original_github = os.environ.get("GITHUB_TOKEN")
        original_anthropic = os.environ.get("ANTHROPIC_API_KEY")
        try:
            os.environ["GITHUB_TOKEN"] = "test-token-value"
            os.environ["ANTHROPIC_API_KEY"] = "test-key-value"
            config = Config.from_env()
            assert config.github_token == "test-token-value"
            assert config.anthropic_api_key == "test-key-value"
        finally:
            if original_github:
                os.environ["GITHUB_TOKEN"] = original_github
            else:
                os.environ.pop("GITHUB_TOKEN", None)
            if original_anthropic:
                os.environ["ANTHROPIC_API_KEY"] = original_anthropic
            else:
                os.environ.pop("ANTHROPIC_API_KEY", None)
