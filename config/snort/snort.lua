-- =============================================================================
-- Cerberus Pi — Snort 3 configuration (Phase 3.2)
-- Install to /opt/cerberus/snort/snort.lua. Monitors eth0 passively and emits
-- JSON alerts that the threat parser tails at /opt/cerberus/logs/snort/.
--
-- HOME_NET is substituted by cerberus_start.sh (replaces __HOME_NET__).
-- =============================================================================

HOME_NET = '__HOME_NET__'        -- e.g. '192.168.1.0/24', filled at start
EXTERNAL_NET = '!' .. HOME_NET

-- Rule paths: community ruleset + Cerberus local rules.
RULE_PATH = '/opt/cerberus/snort/rules'

---------------------------------------------------------------------
-- Network / decoding
---------------------------------------------------------------------
network = {
    homenet = HOME_NET,
}

---------------------------------------------------------------------
-- Inspection: standard stream + service inspectors
---------------------------------------------------------------------
stream = { }
stream_tcp = { }
stream_udp = { }
stream_ip = { }

http_inspect = { }
ssh = { }
dns = { }
ssl = { }

---------------------------------------------------------------------
-- Detection rules
---------------------------------------------------------------------
ips = {
    -- Cerberus ships passive: action_override makes 'drop' behave as 'alert'
    -- unless the operator arms IPS mode via cerberus_start.sh --ips.
    mode = 'tap',
    variables = default_variables,
    rules = [[
        include $RULE_PATH/snort3-community.rules
        include $RULE_PATH/local.rules
    ]],
}

references = default_references
classifications = default_classifications

---------------------------------------------------------------------
-- Output: JSON alerts for the Cerberus parser
---------------------------------------------------------------------
alert_json = {
    file = true,
    limit = 100,                  -- MB before rotation
    fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_addr src_port ' ..
             'dst_addr dst_port service rule priority class action msg sig_id',
}

-- Also keep a unified2 log for offline tooling (Phase 3.2 requirement).
unified2 = {
    limit = 128,
    nostamp = true,
}
