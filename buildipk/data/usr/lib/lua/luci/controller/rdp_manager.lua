module("luci.controller.rdp_manager", package.seeall)

function index()
    entry({"admin", "network", "rdp_manager"}, call("action_index"), _("RDP 端口管理"), 99)
    entry({"admin", "network", "rdp_manager", "delete"}, call("action_delete")).leaf = true
    entry({"admin", "network", "rdp_manager", "set_dhcp"}, call("action_set_dhcp")).leaf = true
    entry({"admin", "network", "rdp_manager", "set_fw"}, call("action_set_fw")).leaf = true
    entry({"admin", "network", "rdp_manager", "apply"}, call("action_apply")).leaf = true
end

function action_index()
    local uci = require "luci.model.uci".cursor()
    local mac_map, host_map, static_ips = {}, {}, {}

    uci:foreach("dhcp", "host", function(s)
        local ip = type(s.ip) == "table" and s.ip[1] or s.ip
        if ip then
            if s.mac then
                local mac = type(s.mac) == "table" and s.mac[1] or s.mac
                mac_map[ip] = string.upper(tostring(mac))
            end
            if s.name then host_map[ip] = tostring(s.name) end
            static_ips[ip] = s['.name']
        end
    end)

    local f = io.open("/tmp/dhcp.leases", "r")
    if f then
        for line in f:lines() do
            local p = {}
            for v in line:gmatch("%S+") do table.insert(p, v) end
            if #p >= 3 then
                local mac, ip, name = string.upper(p[2]), p[3], p[4]
                if not mac_map[ip] then mac_map[ip] = mac end
                if name and name ~= "*" and not host_map[ip] then host_map[ip] = name end
            end
        end
        f:close()
    end

    local rdp_rules, other_rules = {}, {}

    uci:foreach("firewall", "redirect", function(s)
        local dest_ip = type(s.dest_ip) == "table" and s.dest_ip[1] or s.dest_ip
        local src_dport = type(s.src_dport) == "table" and s.src_dport[1] or s.src_dport
        local dest_port = type(s.dest_port) == "table" and s.dest_port[1] or s.dest_port
        local src_ip = type(s.src_ip) == "table" and s.src_ip[1] or s.src_ip

        if dest_ip then
            local rule = {
                index = s['.name'] or "",
                name = s.name or "未命名规则",
                src_dport = src_dport or "未知",
                dest_ip = dest_ip,
                dest_port = dest_port or "3389",
                src_ip_display = src_ip or "不限",
                mac = mac_map[dest_ip] or "未知",
                hostname = host_map[dest_ip] or "无解析",
                mac_id = static_ips[dest_ip] or "",
                ip_type = static_ips[dest_ip] and "静态绑定" or "DHCP分配"
            }
            local port_str = tostring(src_dport or "")
            if port_str == "6666" or port_str == "6667" or port_str == "6668" then 
                table.insert(rdp_rules, rule)
            else 
                table.insert(other_rules, rule) 
            end
        end
    end)

    luci.template.render("rdp_manager/index", {
        rdp_rules = rdp_rules, 
        other_rules = other_rules
    })
end

local function reply(status, msg)
    luci.http.prepare_content("application/json")
    luci.http.write('{"status":"'..status..'", "msg":"'..msg..'"}')
end

function action_delete()
    local uci = require "luci.model.uci".cursor()
    local fid = luci.http.formvalue("fw_idx")
    local mid = luci.http.formvalue("mac_id")
    if fid and fid ~= "" then uci:delete("firewall", fid) end
    if mid and mid ~= "" then uci:delete("dhcp", mid) end
    uci:commit("firewall"); uci:commit("dhcp")
    os.execute("/etc/init.d/firewall restart >/dev/null 2>&1")
    os.execute("/etc/init.d/dnsmasq restart >/dev/null 2>&1")
    reply("success", "删除成功")
end

function action_set_dhcp()
    local uci = require "luci.model.uci".cursor()
    local mac = luci.http.formvalue("mac")
    local ip = luci.http.formvalue("int_ip")
    local name = luci.http.formvalue("hostname") or "device"
    if mac and mac ~= "" and ip and ip ~= "" then
        local id = string.gsub(string.lower(mac), "[%-:]", "")
        uci:delete("dhcp", id)
        uci:section("dhcp", "host", id, { name = name, mac = mac, ip = ip })
        uci:commit("dhcp"); os.execute("/etc/init.d/dnsmasq restart >/dev/null 2>&1")
        reply("success", "静态 DHCP 已设置")
    else
        reply("error", "MAC或IP为空")
    end
end

function action_set_fw()
    local uci = require "luci.model.uci".cursor()
    local name = luci.http.formvalue("name")
    local port = luci.http.formvalue("ext_port")
    local ip = luci.http.formvalue("int_ip")
    local wan = luci.http.formvalue("wan_ip")
    local dest_port = luci.http.formvalue("int_port")
    if not dest_port or dest_port == "" then dest_port = "3389" end -- 增加内网端口容错

    if name and name ~= "" and port and ip then
        uci:foreach("firewall", "redirect", function(s)
            if s.name == name then uci:delete("firewall", s['.name']) end
        end)
        local r = { name=name, src="wan", dest="lan", src_dport=port, dest_ip=ip, dest_port=dest_port, target="DNAT" }
        if wan and wan ~= "" then r.src_ip = wan end
        uci:section("firewall", "redirect", nil, r)
        uci:commit("firewall"); os.execute("/etc/init.d/firewall restart >/dev/null 2>&1")
        reply("success", "转发规则已设置")
    end
end

function action_apply()
    local uci = require "luci.model.uci".cursor()
    local mac = luci.http.formvalue("mac")
    local ip = luci.http.formvalue("int_ip")
    local hostname = luci.http.formvalue("hostname") or "device"
    local fw_name = luci.http.formvalue("name")
    local port = luci.http.formvalue("ext_port")
    local wan = luci.http.formvalue("wan_ip")
    local dest_port = luci.http.formvalue("int_port")
    if not dest_port or dest_port == "" then dest_port = "3389" end -- 增加内网端口容错
    
    if mac and mac ~= "" and ip and ip ~= "" then
        local id = string.gsub(string.lower(mac), "[%-:]", "")
        uci:delete("dhcp", id)
        uci:section("dhcp", "host", id, { name = hostname, mac = mac, ip = ip })
        uci:commit("dhcp")
    end
    
    if fw_name and fw_name ~= "" and port and ip then
        uci:foreach("firewall", "redirect", function(s)
            if s.name == fw_name then uci:delete("firewall", s['.name']) end
        end)
        local r = { name=fw_name, src="wan", dest="lan", src_dport=port, dest_ip=ip, dest_port=dest_port, target="DNAT" }
        if wan and wan ~= "" then r.src_ip = wan end
        uci:section("firewall", "redirect", nil, r)
        uci:commit("firewall")
    end
    
    os.execute("/etc/init.d/dnsmasq restart >/dev/null 2>&1")
    os.execute("/etc/init.d/firewall restart >/dev/null 2>&1")
    reply("success", "全量应用成功")
end