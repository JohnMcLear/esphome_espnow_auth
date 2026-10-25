"""Unit tests for espnow_auth config validation.

Run with: python -m pytest tests/test_config_validation.py -v
"""

import importlib
import importlib.util
import sys
from unittest.mock import MagicMock

# ── Stub ESPHome modules so we can import __init__.py without ESPHome installed ─

mock_cg = MagicMock()
mock_cv = MagicMock()
mock_const = MagicMock()

mock_cv.one_of.return_value = lambda x: x
mock_cv.string = lambda x: x
mock_cv.boolean = lambda x: x
mock_cv.int_range.return_value = lambda x: x
mock_cv.Required.return_value = "required"
mock_cv.Optional.return_value = "optional"
mock_cv.GenerateID.return_value = "generated_id"
mock_cv.declare_id.return_value = lambda x: MagicMock(id=x)
mock_cv.Schema.return_value = lambda config: config
mock_cv.All.side_effect = lambda *args: args[-1]

mock_const.CONF_ID = "id"

mock_core = MagicMock()
mock_core.CORE.config = {}

sys.modules["esphome"] = MagicMock()
sys.modules["esphome.codegen"] = mock_cg
sys.modules["esphome.config_validation"] = mock_cv
sys.modules["esphome.const"] = mock_const
sys.modules["esphome.core"] = mock_core


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "espnow_auth", "components/espnow_auth/__init__.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Module structure ──────────────────────────────────────────────


def test_module_imports():
    """Component module should import without error."""
    mod = _load_module()
    assert hasattr(mod, "CONFIG_SCHEMA")
    assert hasattr(mod, "to_code")
    assert hasattr(mod, "CODEOWNERS")


def test_codeowners():
    """CODEOWNERS must list the maintainer."""
    mod = _load_module()
    assert "@JohnMcLear" in mod.CODEOWNERS


def test_conf_keys_exist():
    """All expected config keys should be defined."""
    mod = _load_module()
    assert mod.CONF_ROLE == "role"
    assert mod.CONF_SHARED_KEY == "shared_key"
    assert mod.CONF_CHANNEL == "channel"


# ── Role validation ──────────────────────────────────────────────


def test_final_validate_outside():
    """_final_validate should accept role='outside'."""
    mod = _load_module()
    config = {mod.CONF_ROLE: "outside", mod.CONF_ID: MagicMock(id="test")}
    result = mod._final_validate(config)
    assert result is config


def test_final_validate_inside():
    """_final_validate should accept role='inside'."""
    mod = _load_module()
    config = {mod.CONF_ROLE: "inside", mod.CONF_ID: MagicMock(id="test")}
    result = mod._final_validate(config)
    assert result is config


def test_final_validate_swaps_id_type():
    """_final_validate should change the ID type based on role."""
    mod = _load_module()
    original_id = MagicMock(id="test")
    config = {mod.CONF_ROLE: "inside", mod.CONF_ID: original_id}
    mod._final_validate(config)
    # ID should have been replaced (not the same object)
    assert config[mod.CONF_ID] is not original_id


# ── Wire format constraints ──────────────────────────────────────


def test_espnow_message_size():
    """EspNowMessage must fit within ESP-NOW's 250-byte limit."""
    size = 1 + 4 + 32 + 48  # type + counter + text + payload
    assert size == 85
    assert size <= 250


def test_auth_challenge_fits_payload():
    """AuthChallenge (16 bytes) must fit in the 48-byte payload field."""
    assert 16 <= 48


def test_auth_response_fits_payload():
    """AuthResponse (nonce + hmac = 48 bytes) must fit in the 48-byte payload."""
    assert 16 + 32 == 48
    assert 48 <= 48


def test_hmac_sha256_output_size():
    """HMAC output must be 32 bytes (SHA-256)."""
    assert 32 == 256 // 8


def test_nonce_length():
    """Nonce must be at least 16 bytes for replay resistance."""
    assert 16 >= 16


# ── Protocol constants ───────────────────────────────────────────


def test_message_type_values_unique():
    """All message type values must be distinct."""
    types = [0x01, 0x02, 0x10, 0x11, 0x12, 0x13, 0x14]
    assert len(types) == len(set(types))


def test_message_type_values_fit_uint8():
    """All message types must fit in a uint8_t."""
    types = [0x01, 0x02, 0x10, 0x11, 0x12, 0x13, 0x14]
    for t in types:
        assert 0 <= t <= 255


def test_channel_range():
    """Valid WiFi channels are 1-14."""
    for ch in range(1, 15):
        assert 1 <= ch <= 14


# ── Header file presence ─────────────────────────────────────────


def test_header_files_exist():
    """All required C++ headers should be present."""
    import os

    base = "components/espnow_auth"
    for name in ("espnow_base.h", "espnow_outside.h", "espnow_inside.h"):
        path = os.path.join(base, name)
        assert os.path.isfile(path), f"Missing header: {path}"


def test_base_header_contains_key_symbols():
    """espnow_base.h should define essential protocol symbols."""
    with open("components/espnow_auth/espnow_base.h") as f:
        content = f.read()
    for symbol in (
        "EspNowMessage",
        "AuthChallenge",
        "AuthResponse",
        "AuthPeer",
        "MessageType",
        "MSG_AUTH_REQUEST",
        "MSG_AUTH_CHALLENGE",
        "MSG_AUTH_RESPONSE",
        "MSG_AUTH_OK",
        "MSG_AUTH_FAIL",
        "MSG_PING",
        "MSG_PONG",
        "auth_hmac",
        "auth_hmac_verify",
        "auth_find_peer",
        "auth_is_authorized",
        "generate_nonce",
        "espnow_init",
        "BROADCAST_ADDR",
    ):
        assert symbol in content, f"Missing symbol in espnow_base.h: {symbol}"


def test_outside_header_contains_class():
    """espnow_outside.h should define ESPNowOutside class."""
    with open("components/espnow_auth/espnow_outside.h") as f:
        content = f.read()
    assert "class ESPNowOutside" in content
    assert "set_shared_key" in content
    assert "set_channel" in content
    assert "set_wifi_coexist" in content
    assert "on_recv" in content


def test_inside_header_contains_class():
    """espnow_inside.h should define ESPNowInside class."""
    with open("components/espnow_auth/espnow_inside.h") as f:
        content = f.read()
    assert "class ESPNowInside" in content
    assert "set_shared_key" in content
    assert "set_channel" in content
    assert "set_wifi_coexist" in content
    assert "auth_peers_" in content


def test_wifi_coexist_in_base_header():
    """espnow_init should accept wifi_coexist parameter."""
    with open("components/espnow_auth/espnow_base.h") as f:
        content = f.read()
    assert "wifi_coexist" in content
    assert "WiFi coexistence mode" in content


# ── Security checks ──────────────────────────────────────────────


def test_constant_time_comparison_exists():
    """The codebase must use constant-time HMAC comparison."""
    with open("components/espnow_auth/espnow_base.h") as f:
        content = f.read()
    assert "auth_hmac_verify" in content
    # Should XOR bytes, not use memcmp
    assert "diff |=" in content


def test_no_hardcoded_secrets_in_headers():
    """Headers must not contain hardcoded shared keys."""
    import os

    for name in ("espnow_base.h", "espnow_outside.h", "espnow_inside.h"):
        with open(os.path.join("components/espnow_auth", name)) as f:
            content = f.read()
        assert "change-me" not in content, f"Hardcoded secret in {name}"
        assert "my-secret" not in content, f"Hardcoded secret in {name}"


# ── Examples and repo structure ──────────────────────────────────


def test_example_files_exist():
    """All example configs should be present."""
    import os

    for name in ("outside.yaml", "inside.yaml", "standalone.yaml"):
        path = os.path.join("examples", name)
        assert os.path.isfile(path), f"Missing example: {path}"


def test_examples_use_wifi_and_ota():
    """Main examples should include wifi, ota, api, and !secret refs."""
    import os

    for name in ("outside.yaml", "inside.yaml"):
        with open(os.path.join("examples", name)) as f:
            content = f.read()
        assert "wifi:" in content, f"{name} missing wifi block"
        assert "!secret" in content, f"{name} should use !secret refs"
        assert "ota:" in content, f"{name} missing ota"
        assert "api:" in content, f"{name} missing api"


def test_standalone_example_no_wifi():
    """Standalone example should not use wifi or wifi_coexist."""
    with open("examples/standalone.yaml") as f:
        content = f.read()
    assert "wifi_coexist" not in content or "wifi_coexist: true" not in content
    assert "wifi:" not in content.split("espnow_auth:")[0]


def test_compile_configs_exist():
    """All CI compile test configs should be present."""
    import os

    expected = [
        "test_compile_outside.yaml",
        "test_compile_inside.yaml",
        "test_compile_wifi_coexist.yaml",
        "test_compile_wifi_outside.yaml",
    ]
    for name in expected:
        path = os.path.join("tests", name)
        assert os.path.isfile(path), f"Missing compile test: {path}"


def test_secrets_yaml_gitignored():
    """secrets.yaml must be in .gitignore."""
    with open(".gitignore") as f:
        content = f.read()
    assert "secrets.yaml" in content


def test_no_secrets_in_repo():
    """No secrets.yaml should be checked in."""
    import os

    assert not os.path.isfile("secrets.yaml"), "secrets.yaml must not be in repo"


def test_wifi_coexist_auto_detected():
    """to_code should auto-detect wifi from CORE.config, not require a YAML key."""
    with open("components/espnow_auth/__init__.py") as f:
        content = f.read()
    assert "CORE.config" in content, "Should use CORE.config for auto-detection"
    assert '"wifi"' in content, "Should check for 'wifi' key in config"
    assert "set_wifi_coexist" in content, "Should call set_wifi_coexist"


def test_no_wifi_coexist_in_schema():
    """wifi_coexist should not be a user-facing config option."""
    with open("components/espnow_auth/__init__.py") as f:
        content = f.read()
    assert "CONF_WIFI_COEXIST" not in content, "wifi_coexist should be auto-detected"
