"""ESPHome ESP-NOW authentication component."""

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.const import CONF_ID
from esphome.core import CORE

CODEOWNERS = ["@JohnMcLear"]

espnow_auth_ns = cg.esphome_ns.namespace("espnow_auth")
ESPNowOutside = espnow_auth_ns.class_("ESPNowOutside", cg.Component)
ESPNowInside = espnow_auth_ns.class_("ESPNowInside", cg.Component)

CONF_ROLE = "role"
CONF_SHARED_KEY = "shared_key"
CONF_CHANNEL = "channel"


def _final_validate(config):
    """Swap the component ID type to match the selected role."""
    role = config[CONF_ROLE]
    cls = ESPNowOutside if role == "outside" else ESPNowInside
    config[CONF_ID] = cv.declare_id(cls)(config[CONF_ID].id)
    return config


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(ESPNowOutside),
            cv.Required(CONF_ROLE): cv.one_of("outside", "inside", lower=True),
            cv.Required(CONF_SHARED_KEY): cv.string,
            cv.Optional(CONF_CHANNEL, default=1): cv.int_range(min=1, max=14),
        }
    ),
    _final_validate,
)


async def to_code(config):
    """Generate C++ code for the selected role."""
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    cg.add(var.set_shared_key(config[CONF_SHARED_KEY]))
    cg.add(var.set_channel(config[CONF_CHANNEL]))

    if CORE.is_esp32:
        # ESPHome 2026.10+ leaves esp_wifi out of builds that do not ask for it.
        from esphome.components.esp32 import include_builtin_idf_component

        include_builtin_idf_component("esp_wifi")

    # Auto-detect: if ESPHome's wifi component is configured, use coexist mode.
    wifi_configured = "wifi" in CORE.config
    cg.add(var.set_wifi_coexist(wifi_configured))
