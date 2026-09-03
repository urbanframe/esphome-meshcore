import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import sx126x, sx127x
from esphome.const import CONF_ID, CONF_NAME
from esphome import automation

CODEOWNERS = ["@davidwilliams"]  # replace with your GitHub handle before publishing
DEPENDENCIES = []
MULTI_CONF = True

meshcore_ns = cg.esphome_ns.namespace("meshcore")
MeshCoreComponent = meshcore_ns.class_("MeshCoreComponent", cg.Component)

SendChannelTextAction = meshcore_ns.class_(
    "SendChannelTextAction", automation.Action, cg.Parented.template(MeshCoreComponent)
)
SendAdvertAction = meshcore_ns.class_(
    "SendAdvertAction", automation.Action, cg.Parented.template(MeshCoreComponent)
)
SendMessageAction = meshcore_ns.class_(
    "SendMessageAction", automation.Action, cg.Parented.template(MeshCoreComponent)
)

CONF_MESHCORE_ID = "meshcore_id"
CONF_LORA = "lora"
CONF_PUBLIC_KEY = "public_key"
CONF_PRIVATE_KEY = "private_key"
CONF_PEER_PUBLIC_KEY = "peer_public_key"
CONF_NODE_NAME = "node_name"
CONF_REPEATER = "repeater"
CONF_ADVERTISE_INTERVAL = "advertise_interval"
CONF_CHANNELS = "channels"
CONF_PSK = "psk"
CONF_ON_CHANNEL_MESSAGE = "on_channel_message"
CONF_ON_MESSAGE = "on_message"
CONF_ON_ADVERT = "on_advert"
CONF_CHANNEL = "channel"
CONF_TEXT = "text"


def _hex_bytes(expected_len):
    def validator(value):
        value = cv.string_strict(value)
        try:
            raw = bytes.fromhex(value)
        except ValueError as err:
            raise cv.Invalid("Must be a hex string") from err
        if len(raw) != expected_len:
            raise cv.Invalid(f"Must be exactly {expected_len} bytes ({expected_len * 2} hex chars), got {len(raw)}")
        return value

    return validator


CHANNEL_SCHEMA = cv.Schema(
    {
        cv.Required(CONF_NAME): cv.string_strict,
        cv.Required(CONF_PSK): _hex_bytes(16),
    }
)

CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(MeshCoreComponent),
            cv.Required(CONF_LORA): cv.use_id(cg.Component),
            cv.Optional(CONF_PUBLIC_KEY): _hex_bytes(32),
            cv.Optional(CONF_PRIVATE_KEY): _hex_bytes(64),
            cv.Optional(CONF_PEER_PUBLIC_KEY): _hex_bytes(32),
            cv.Optional(CONF_NODE_NAME): cv.string_strict,
            cv.Optional(CONF_REPEATER, default=False): cv.boolean,
            cv.Optional(CONF_ADVERTISE_INTERVAL): cv.positive_time_period_milliseconds,
            cv.Optional(CONF_CHANNELS, default=[]): cv.ensure_list(CHANNEL_SCHEMA),
            cv.Optional(CONF_ON_CHANNEL_MESSAGE): automation.validate_automation(single=True),
            cv.Optional(CONF_ON_MESSAGE): automation.validate_automation(single=True),
            cv.Optional(CONF_ON_ADVERT): automation.validate_automation(single=True),
        }
    ).extend(cv.COMPONENT_SCHEMA),
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    lora = await cg.get_variable(config[CONF_LORA])
    cg.add(var.set_lora(lora))

    if CONF_PUBLIC_KEY in config and CONF_PRIVATE_KEY in config:
        pub_bytes = ", ".join(f"0x{b:02X}" for b in bytes.fromhex(config[CONF_PUBLIC_KEY]))
        prv_bytes = ", ".join(f"0x{b:02X}" for b in bytes.fromhex(config[CONF_PRIVATE_KEY]))
        cg.add(
            cg.RawExpression(
                f"{var}->set_identity((const uint8_t[]){{{pub_bytes}}}, (const uint8_t[]){{{prv_bytes}}})"
            )
        )
    elif CONF_PUBLIC_KEY in config or CONF_PRIVATE_KEY in config:
        raise cv.Invalid("public_key and private_key must both be set, or both omitted")

    if CONF_PEER_PUBLIC_KEY in config:
        peer_bytes = ", ".join(f"0x{b:02X}" for b in bytes.fromhex(config[CONF_PEER_PUBLIC_KEY]))
        cg.add(cg.RawExpression(f"{var}->set_peer((const uint8_t[]){{{peer_bytes}}})"))

    if CONF_NODE_NAME in config:
        cg.add(var.set_node_name(config[CONF_NODE_NAME]))
    cg.add(var.set_is_repeater(config[CONF_REPEATER]))
    if CONF_ADVERTISE_INTERVAL in config:
        cg.add(var.set_advertise_interval(config[CONF_ADVERTISE_INTERVAL].total_milliseconds))

    for ch in config[CONF_CHANNELS]:
        psk_bytes = ", ".join(f"0x{b:02X}" for b in bytes.fromhex(ch[CONF_PSK]))
        cg.add(cg.RawExpression(f'{var}->add_channel("{ch[CONF_NAME]}", (const uint8_t[]){{{psk_bytes}}})'))

    if channel_conf := config.get(CONF_ON_CHANNEL_MESSAGE):
        await automation.build_automation(
            var.get_on_channel_message_trigger(), [(cg.std_string, "channel"), (cg.std_string, "text")], channel_conf
        )
    if message_conf := config.get(CONF_ON_MESSAGE):
        await automation.build_automation(var.get_on_message_trigger(), [(cg.std_string, "text")], message_conf)
    if advert_conf := config.get(CONF_ON_ADVERT):
        await automation.build_automation(
            var.get_on_advert_trigger(), [(cg.std_string, "pubkey"), (cg.std_string, "name")], advert_conf
        )


MESHCORE_ACTION_SCHEMA = cv.Schema({cv.GenerateID(): cv.use_id(MeshCoreComponent)})


@automation.register_action(
    "meshcore.send_channel_text",
    SendChannelTextAction,
    MESHCORE_ACTION_SCHEMA.extend(
        {
            cv.Required(CONF_CHANNEL): cv.templatable(cv.string_strict),
            cv.Required(CONF_TEXT): cv.templatable(cv.string_strict),
        }
    ),
    synchronous=True,
)
async def send_channel_text_action_to_code(config, action_id, template_arg, args):
    var = cg.new_Pvariable(action_id, template_arg)
    await cg.register_parented(var, config[CONF_ID])
    cg.add(var.set_channel(await cg.templatable(config[CONF_CHANNEL], args, cg.std_string)))
    cg.add(var.set_text(await cg.templatable(config[CONF_TEXT], args, cg.std_string)))
    return var


@automation.register_action(
    "meshcore.send_advert", SendAdvertAction, MESHCORE_ACTION_SCHEMA, synchronous=True
)
async def send_advert_action_to_code(config, action_id, template_arg, args):
    var = cg.new_Pvariable(action_id, template_arg)
    await cg.register_parented(var, config[CONF_ID])
    return var


@automation.register_action(
    "meshcore.send_message",
    SendMessageAction,
    MESHCORE_ACTION_SCHEMA.extend({cv.Required(CONF_TEXT): cv.templatable(cv.string_strict)}),
    synchronous=True,
)
async def send_message_action_to_code(config, action_id, template_arg, args):
    var = cg.new_Pvariable(action_id, template_arg)
    await cg.register_parented(var, config[CONF_ID])
    cg.add(var.set_text(await cg.templatable(config[CONF_TEXT], args, cg.std_string)))
    return var
