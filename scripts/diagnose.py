import paramiko

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

print("--- IRAN DETAILED LOG ---")
out, err = run_ssh("37.32.12.16", "root", "Da05600560", "journalctl -u novatun-iran -n 20 --no-pager; curl -v -x socks5h://127.0.0.1:1080 http://65.108.213.175:8443 2>&1 | head -n 30")
print(out)
if err: print("ERR:", err)
