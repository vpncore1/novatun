import paramiko
import sys

def run_ssh(host, user, password, cmd):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=22, username=user, password=password, timeout=12)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        ssh.close()
        return out, err
    except Exception as e:
        return "", str(e)

print("=== CHECKING KHAREJ (65.108.213.175) ===")
cmd_kharej = "systemctl is-active novatun-kharej; ss -tulpn | grep -E '443|x-ui|8443|2053'"
out, err = run_ssh("65.108.213.175", "root", "Da05600560*#@", cmd_kharej)
print(out)
if err:
    print("ERR:", err)

print("=== CHECKING IRAN (37.32.12.16) ===")
cmd_iran = "systemctl is-active novatun-iran; curl -s --max-time 6 -x socks5h://127.0.0.1:1080 https://api.ipify.org; echo ''"
out, err = run_ssh("37.32.12.16", "root", "Da05600560", cmd_iran)
print(out)
if err:
    print("ERR:", err)
