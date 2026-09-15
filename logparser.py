from collections import deque


def event_ssh_detection(log_line: str) -> str:

    event = ""

    if "Accepted password" in log_line or "Accepted passkey" in log_line:
        event = "SUCCESS_LOGIN"
    elif "session opened" in log_line:
        event = "SESSION_OPENED"
    elif "Failed password" in log_line:
        event = "FAILED_LOGIN"
    elif "authentication failure" in log_line:
        event = "FAILED_AUTHENTICATION"
    elif "Invalid user" in log_line:
        event = "INVALID_USER"
    elif "Connection closed" in log_line:
        event = "PREAUTH_CONNECTION_CLOSED"
    elif "session closed" in log_line:
        event = "SESSION_CLOSED"

    return event

def parse_ssh_fields(splitline: list[str], event: str) -> tuple[str, str]:

    user = "NO_USER"
    ip = "NO_IP"

    if event == "SUCCESS_LOGIN":
        user = splitline[splitline.index("for") + 1]
        ip = splitline[splitline.index("from") + 1]
    elif event == "SESSION_OPENED":
        user = splitline[splitline.index("user") + 1].split(")", 1)[0]
    elif event == "FAILED_LOGIN":
        user = splitline[splitline.index("for") + 1]
        ip = splitline[splitline.index("from") + 1]
    elif event == "FAILED_AUTHENTICATION":
        for word in splitline:
            if word.startswith("rhost="):
                ip = word.split("=", 1)[1]
            elif word.startswith("user="):
                user = word.split("=", 1)[1]
    elif event == "INVALID_USER":
        user = splitline[splitline.index("user") + 1]
        ip = splitline[splitline.index("from") + 1]
    elif event == "SESSION_CLOSED":
        user = splitline[splitline.index("user") + 1]
    
    return user, ip

def parse_ssh_log(log_line: str) -> dict:
    splitline = log_line.split()
    timestamp = splitline[0] + " " + splitline[1] + " " + splitline[2]
    host = splitline[3]

    event = event_ssh_detection(log_line)
    user, ip = parse_ssh_fields(splitline, event)

    #So that unimportant logs arn't being checked
    if event == "":
        return {}

    log_entry = {
        "timestamp": timestamp,
        "host": host,
        "source": "ssh",
        "event": event, 
        "user": user, 
        "ip": ip
    }

    return log_entry

def event_sudo_detection(log_line: str) -> str:
    event = ""
    
    if "authentication failure" in log_line:
        event = "FAILED_AUTHENTICATION"
    elif "COMMAND=" in log_line:
        event = "SUDO_COMMAND"
    
    return event

def parse_sudo_fields(splitline: list[str], event: str) -> tuple[str, str]:
    user = ""
    tty = ""
    
    if event == "FAILED_AUTHENTICATION":
        for word in splitline:
            if word.startswith("user="):
                user = word.split("=", 1)[1]
            if word.startswith("tty="):
                tty = word.split("=", 1)[1]
    
    if event == "SUDO_COMMAND":
        for index, word in enumerate(splitline):
            if word == "sudo:":
                user = splitline[index + 1]
            if word.startswith("TTY="):
                tty = word.split("=", 1)[1]
    
    return  user, tty

def parse_sudo_log(log_line: str) -> dict:
    splitline = log_line.split()
    date_and_time = splitline[0].split("T")
    timestamp = date_and_time[0].replace("-", " ") + " " + date_and_time[1].split(".")[0]
    host = splitline[1]

    event = event_sudo_detection(log_line)
    user, tty = parse_sudo_fields(splitline, event)

    #So that unimportant logs arn't being checked
    if event == "":
        return {}
    
    log_entry = {
        "timestamp": timestamp,
        "host": host,
        "source": "sudo",
        "event": event, 
        "user": user, 
        "tty": tty,
        "ip": "NO_IP"
    }

    if event == "SUDO_COMMAND":
        for word in splitline:
            if word.startswith("COMMAND="):
                log_entry["command"] = word.split("=", 1)[1]

    return log_entry

def parse_line(log_line: str) -> dict:
    if "sshd" in log_line:
        return parse_ssh_log(log_line)
    elif "sudo" in log_line:
        return parse_sudo_log(log_line)
    else:
        return {}

def parse_log(log_file: str) -> list[dict]:

    parsed_log = []

    with open(log_file, "r") as file:
        for line in file:
            parsed_line = parse_line(line)
            if parsed_line == {}:
                continue
            else:
                parsed_log.append(parsed_line)
    
    return parsed_log

def get_log_mins(log: dict) -> int:

    timestamp = log["timestamp"]
    
    if log['source'] == "ssh":
        time = timestamp.split(" ")[2]
        hours = int(time.split(":")[0])
        minutes = int(time.split(":")[1])
    
        return (hours * 60) + minutes
    elif log['source'] == "sudo":
        time = timestamp.split(" ")[2]
        hours = int(time.split(":")[0])
        minutes = int(time.split(":")[1])
    
        return (hours * 60) + minutes
    
    return 0

def ssh_brute_force_detect(logs: list[dict]) -> list[dict]:
    failed_login = {}
    alerts = []
    danger_ips = []
    for log in logs:
        if log["event"] == "FAILED_LOGIN":
            ip = log["ip"]
            if ip not in failed_login:
                failed_login[ip] = deque()
            failed_login[ip].append(log)
            
            if len(failed_login[ip]) >= 5:
                if get_log_mins(log) - get_log_mins(failed_login[ip][0]) < 5:
                    alerts.append({
                        "alert": "SSH_BRUTE_FORCE_ATTEMPT",
                        "ip": ip,
                        "attempts": len(failed_login[ip]),
                        "start_time": failed_login[ip][0]["timestamp"],
                        "end_time": failed_login[ip][-1]["timestamp"]
                    })
                    if ip not in danger_ips:
                        danger_ips.append(ip)
                    failed_login[ip].clear()

                else:
                    while get_log_mins(log) - get_log_mins(failed_login[ip][0]) >= 5:
                        failed_login[ip].popleft()

    return alerts

def ssh_user_enumeration_detect(logs: list[dict]) -> list[dict]:
    failed_user = {}
    alerts = []
    danger_ips = []
    for log in logs:
        if log["event"] == "INVALID_USER":
            ip = log["ip"]
            if ip not in failed_user:
                failed_user[ip] = deque()
            failed_user[ip].append(log)
            
            if len(failed_user[ip]) >= 5:
                if get_log_mins(log) - get_log_mins(failed_user[ip][0]) < 5:
                    alerts.append({
                        "alert": "SSH_USER_ENUMERATION",
                        "ip": ip,
                        "attempts": len(failed_user[ip]),
                        "start_time": failed_user[ip][0]["timestamp"],
                        "end_time": failed_user[ip][-1]["timestamp"]
                    })
                    if ip not in danger_ips:
                        danger_ips.append(ip)
                    failed_user[ip].clear()

                else:
                    while get_log_mins(log) - get_log_mins(failed_user[ip][0]) >= 5:
                        failed_user[ip].popleft()

    return alerts


def ssh_brute_force_success(logs: list[dict], brute_force_alerts: list[dict]) -> list[dict]:
    # Checks for sucessful login after many failed attempts

    if not brute_force_alerts:
        return []

    brute_force_success = []

    for log in logs:
        if log["event"] == "SUCCESS_LOGIN":
            for alert in brute_force_alerts:
                if log["ip"] == alert["ip"] and (get_log_mins(log) - get_log_mins({"timestamp": alert["end_time"]}) < 5):
                    brute_force_success.append({
                        "alert": "SSH_BRUTE_FORCE_SUCCESS",
                        "ip": log["ip"],
                        "time": log["timestamp"],
                    })
                    break
        
    return brute_force_success

def sudo_auth_brute_force(logs: list[dict]) -> list[dict]:
    failed_auth = {}
    alerts = []
    danger_user = []
    for log in logs:
        if log["event"] == "FAILED_AUTHENTICATION":
            user = log["user"]
            if user not in failed_auth:
                failed_auth[user] = deque()
            failed_auth[user].append(log)
            
            if len(failed_auth[user]) >= 5:
                if get_log_mins(log) - get_log_mins(failed_auth[user][0]) < 5:
                    alerts.append({
                        "alert": "SUDO_BRUTE_FORCE_ATTEMPT",
                        "user": user,
                        "tty" : log['tty'],
                        "attempts": len(failed_auth[user]),
                        "start_time": failed_auth[user][0]["timestamp"],
                        "end_time": failed_auth[user][-1]["timestamp"]
                    })
                    if user not in danger_user:
                        danger_user.append(user)
                    failed_auth[user].clear()

                else:
                    while get_log_mins(log) - get_log_mins(failed_auth[user][0]) >= 5:
                        failed_auth[user].popleft()

    return alerts

def sudo_sus_command_detection(logs: list[dict]) -> list[dict]:
    alerts = []
    suspicious_commands = [
        "useradd",
        "adduser",
        "usermod",
        "userdel",
        "passwd",
        "chmod",
        "chown",
        "visudo",
        "iptables",
        "ufw",
        "systemctl",
        "service"
    ]

    for log in logs:
        for commands in suspicious_commands:
            if commands in log["command"]:
                alerts.append({
                    "alert": "SUDO_SENSITIVE_COMMAND",
                    "user": log['user'],
                    "tty" : log['tty'],
                    "command": log["command"],
                    "time": log["timestamp"]
                })
                break
    
    return alerts

    

def ssh_alert_detection(logs: list[dict]) -> dict:
    
    brute_force_alerts = ssh_brute_force_detect(logs)
    user_enumeration_alerts = ssh_user_enumeration_detect(logs)
    brute_force_successes = ssh_brute_force_success(logs, brute_force_alerts)

    alerts = {
        "brute_force_alerts": brute_force_alerts,
        "user_enumeration_alerts": user_enumeration_alerts,
        "brute_force_successes": brute_force_successes,
    }

    return alerts

def sudo_alert_detection(logs: list[dict]) -> dict:

    sudo_brute_force_alerts = sudo_auth_brute_force(logs)
    sudo_command_alert = sudo_sus_command_detection(logs)


def alert_detection(logs: list[dict]) -> dict:
    
    alert = {}

    if not logs:
        return {}
    
    if logs[0]["source"] == "ssh":
        alert = ssh_alert_detection(logs)
    elif logs[0]["source"] == "sudo":
        alert = sudo_alert_detection(logs)
    

    return alert

def ssh_alert_output(alerts: dict) -> None:
    output = ""
    for alert_list in alerts.values():
        for log in alert_list:
            if log["alert"] == "SSH_BRUTE_FORCE_SUCCESS":
                output = f"ALERT: {log['alert']}\nIP: {log['ip']}\nTime: {log['start_time']} - {log['end_time']}"
            else:
                output = f"ALERT: {log['alert']}\nIP: {log['ip']}\nAttempts: {log['attempts']}\nTime: {log['start_time']} - {log['end_time']}"
        
            print(output)

def alert_output(alerts: dict) -> None:
    
def main() -> None:
    ssh_alert_output(alert_detection(parse_log("test.log")))
main()

