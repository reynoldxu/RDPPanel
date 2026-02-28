import webbrowser
from threading import Timer
import sys
import os
import re
import json
import paramiko
from flask import Flask, render_template, request, jsonify
from waitress import serve


def get_resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


app = Flask(__name__, template_folder=get_resource_path('templates'))
CONFIG_FILE = 'config.json'


def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            try:
                return json.load(f)
            except:
                pass
    return {"host": "", "port": "", "user": "", "pass": ""}


def save_config(data):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f)


def ssh_exec(commands=""):
    cfg = load_config()
    if not cfg.get("host") or not cfg.get("port"): return "", "未配置连接信息"
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=cfg["host"], port=int(cfg["port"]), username=cfg["user"], password=cfg["pass"], timeout=5)
        combined_cmd = "uci show firewall; echo '===DHCP_START==='; uci show dhcp; echo '===LEASES_START==='; cat /tmp/dhcp.leases"
        if commands: combined_cmd = commands
        stdin, stdout, stderr = ssh.exec_command(combined_cmd)
        output = stdout.read().decode()
        error = stderr.read().decode()
        ssh.close()
        return output, error
    except Exception as e:
        return "", str(e)


def parse_full_data(fw_raw, dhcp_raw, leases_raw):
    mac_map, host_map, static_ips = {}, {}, {}
    dhcp_pattern = re.compile(r"dhcp\.([\w]+)\.(\w+)='(.*?)'")
    temp_dhcp = {}
    for line in dhcp_raw.splitlines():
        match = dhcp_pattern.match(line)
        if match:
            section, key, value = match.groups()
            if section not in temp_dhcp: temp_dhcp[section] = {}
            temp_dhcp[section][key] = value
    for sid, sec in temp_dhcp.items():
        if 'ip' in sec:
            ip = sec['ip']
            if 'mac' in sec: mac_map[ip] = sec['mac'].upper()
            if 'name' in sec: host_map[ip] = sec['name']
            static_ips[ip] = sid

    for line in leases_raw.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            m_addr, i_addr = parts[1].upper(), parts[2]
            if i_addr not in mac_map: mac_map[i_addr] = m_addr
            if len(parts) >= 4 and i_addr not in host_map and parts[3] != '*':
                host_map[i_addr] = parts[3]

    # === [新增代码] 提取所有已知的主机信息并按 IP 排序 ===
    all_hosts = []
    for ip, mac in mac_map.items():
        all_hosts.append({
            'ip': ip,
            'mac': mac,
            'hostname': host_map.get(ip, '')
        })
    # 按照 IP 地址进行逻辑排序
    all_hosts.sort(key=lambda x: [int(p) if p.isdigit() else p for p in x['ip'].split('.')])
    # ====================================================

    rules_dict = {}
    fw_pattern = re.compile(r"firewall\.@redirect\[(\d+)\]\.(\w+)='(.*?)'")
    for line in fw_raw.splitlines():
        match = fw_pattern.match(line)
        if match:
            idx, key, value = match.groups()
            if idx not in rules_dict: rules_dict[idx] = {}
            rules_dict[idx][key] = value

    rdp_rules, other_rules = [], []
    target_ports = ['6666', '6667', '6668']
    for idx in sorted(rules_dict.keys(), key=int):
        rule = rules_dict[idx]
        if 'src_dport' in rule and 'dest_ip' in rule:
            ip = rule['dest_ip']
            rule['index'] = idx
            rule['hostname'] = host_map.get(ip, "")
            rule['mac'] = mac_map.get(ip, "未知")
            rule['mac_id'] = static_ips.get(ip, "")
            rule['src_ip_display'] = rule.get('src_ip', '不限')
            rule['dest_port'] = rule.get('dest_port', '3389')
            rule['ip_type'] = "静态" if ip in static_ips else "DHCP"
            if rule['src_dport'] in target_ports:
                rdp_rules.append(rule)
            else:
                other_rules.append(rule)
    
    # === [修改] 将 all_hosts 也返回 ===
    return rdp_rules, other_rules, all_hosts


@app.route('/')
def index():
    cfg = load_config()
    display_cfg = {"host": "???.???.???.???" if cfg.get("host") else "", "port": "******" if cfg.get("port") else "",
                   "user": "******" if cfg.get("user") else "", "pass": "******" if cfg.get("pass") else "",
                   "has_config": bool(cfg.get("host"))}
    raw_out, _ = ssh_exec()
    # === [修改] 接收 all_hosts 变量 ===
    rdp, other, all_hosts = [], [], []
    if raw_out:
        parts = raw_out.split('===DHCP_START===')
        fw_segment = parts[0]
        dhcp_segment = leases_segment = ""
        if len(parts) > 1:
            sub_parts = parts[1].split('===LEASES_START===')
            dhcp_segment = sub_parts[0]
            if len(sub_parts) > 1: leases_segment = sub_parts[1]
        rdp, other, all_hosts = parse_full_data(fw_segment, dhcp_segment, leases_segment)
    # === [修改] 将 all_hosts 渲染到模板 ===
    return render_template('index.html', rdp_rules=rdp, other_rules=other, config=display_cfg, all_hosts=all_hosts)


@app.route('/update_config', methods=['POST'])
def update_config():
    new_cfg = request.form.to_dict()
    old_cfg = load_config()
    for k in ["host", "port", "user", "pass"]:
        if new_cfg.get(k) in ["???.???.???.???", "******"]: new_cfg[k] = old_cfg.get(k, "")
    save_config(new_cfg)
    return jsonify({"status": "success", "msg": "配置已同步"})


@app.route('/delete', methods=['POST'])
def delete_rule():
    data = request.json
    cmds = [f"uci delete firewall.@redirect[{data['fw_idx']}]", "uci commit firewall"]
    if data.get('mac_id'): cmds.extend([f"uci delete dhcp.{data['mac_id']}", "uci commit dhcp"])
    cmds.extend(["/etc/init.d/dnsmasq restart", "/etc/init.d/firewall restart"])
    ssh_exec("\n".join(cmds))
    return jsonify({"status": "success", "msg": "删除成功"})


@app.route('/set_dhcp', methods=['POST'])
def set_dhcp():
    f = request.form
    mac_id = f['mac'].replace(':', '').replace('-', '').lower()
    cmds = f"uci delete dhcp.{mac_id} >/dev/null 2>&1 || true\nuci set dhcp.{mac_id}=host\nuci set dhcp.{mac_id}.name='{f.get('hostname', '')}'\nuci set dhcp.{mac_id}.mac='{f['mac']}'\nuci set dhcp.{mac_id}.ip='{f['int_ip']}'\nuci commit dhcp\n/etc/init.d/dnsmasq restart"
    ssh_exec(cmds)
    return jsonify({"status": "success", "msg": "静态 DHCP 设置成功"})


@app.route('/set_fw', methods=['POST'])
def set_fw():
    f = request.form
    name = f['name']
    dest_port = f.get('int_port', '3389')
    if not dest_port.strip(): dest_port = '3389'

    raw_fw, _ = ssh_exec("uci show firewall")
    delete_cmds = []
    if raw_fw:
        pattern = re.compile(rf"firewall\.@redirect\[(\d+)\]\.name='{name}'")
        for m in pattern.finditer(raw_fw): delete_cmds.append(f"uci delete firewall.@redirect[{m.group(1)}]")

    add_cmds = [
        "uci add firewall redirect",
        f"uci set firewall.@redirect[-1].name='{name}'",
        f"uci set firewall.@redirect[-1].src_dport='{f['ext_port']}'",
        f"uci set firewall.@redirect[-1].dest_ip='{f['int_ip']}'",
        f"uci set firewall.@redirect[-1].dest_port='{dest_port}'",
        "uci set firewall.@redirect[-1].target='DNAT'",
        "uci set firewall.@redirect[-1].src='wan'",
        "uci set firewall.@redirect[-1].dest='lan'"
    ]
    if f.get('wan_ip'): add_cmds.append(f"uci set firewall.@redirect[-1].src_ip='{f['wan_ip'].strip()}'")
    add_cmds.extend(["uci commit firewall", "/etc/init.d/firewall restart"])
    ssh_exec("\n".join(delete_cmds[::-1] + add_cmds))
    return jsonify({"status": "success", "msg": "转发规则设置成功"})


@app.route('/apply', methods=['POST'])
def apply():
    f = request.form
    mac_id = f['mac'].replace(':', '').replace('-', '').lower()
    name = f['name']
    dest_port = f.get('int_port', '3389')
    if not dest_port.strip(): dest_port = '3389'

    raw_fw, _ = ssh_exec("uci show firewall")
    cmds_list = []
    if raw_fw:
        pattern = re.compile(rf"firewall\.@redirect\[(\d+)\]\.name='{name}'")
        for m in pattern.finditer(raw_fw): cmds_list.append(f"uci delete firewall.@redirect[{m.group(1)}]")

    cmds_list.extend([
        f"uci delete dhcp.{mac_id} >/dev/null 2>&1 || true",
        f"uci set dhcp.{mac_id}=host",
        f"uci set dhcp.{mac_id}.name='{f.get('hostname', '')}'",
        f"uci set dhcp.{mac_id}.mac='{f['mac']}'",
        f"uci set dhcp.{mac_id}.ip='{f['int_ip']}'",
        "uci commit dhcp",
        "uci add firewall redirect",
        f"uci set firewall.@redirect[-1].name='{name}'",
        f"uci set firewall.@redirect[-1].src_dport='{f['ext_port']}'",
        f"uci set firewall.@redirect[-1].dest_ip='{f['int_ip']}'",
        f"uci set firewall.@redirect[-1].dest_port='{dest_port}'",
        "uci set firewall.@redirect[-1].target='DNAT'",
        "uci set firewall.@redirect[-1].src='wan'",
        "uci set firewall.@redirect[-1].dest='lan'"
    ])
    if f.get('wan_ip'): cmds_list.append(f"uci set firewall.@redirect[-1].src_ip='{f['wan_ip'].strip()}'")
    cmds_list.extend(["uci commit firewall", "/etc/init.d/dnsmasq restart", "/etc/init.d/firewall restart"])
    ssh_exec("\n".join(cmds_list))
    return jsonify({"status": "success", "msg": "全量配置已应用"})

def open_browser():
    """自动打开默认浏览器"""
    webbrowser.open_new("http://127.0.0.1:30000")

if __name__ == '__main__':
    # 使用 Timer 延迟 1.5 秒打开网页，确保 Waitress 服务已经完全就绪
    Timer(1.5, open_browser).start()

    print(">>> 服务已启动，请访问: http://127.0.0.1:30000")
    serve(app, host='127.0.0.1', port=30000)