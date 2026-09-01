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
    user, ip = parse_ssh_feilds(splitline, event)

    log_entry = {
        "timestamp": timestamp,
        "host": host,
        "source": "ssh",
        "event": event, 
        "user": user, 
        "ip": ip
    }

    return log_entry

def parse_line(log_line: str) -> dict:
    if "sshd" in log_line:
        return parse_ssh_log(log_line)
    elif "sudo" in log_line:
        #Put sudo function here
        return {}
    else:
        return {}

def parse_log(log_file: str) -> list[dict]:

    parsed_log = []

    with open(log_file, "r") as file:
        for line in file:
            parsed_log.append(parse_line(line))
    
    return parsed_log

def get_log_mins(log: dict) -> int:

    timestamp = log["timestamp"]

    time = timestamp.split(" ")[2]
    hours = int(time.split(":")[0])
    minutes = int(time.split(":")[1])
    
    return (hours * 60) + minutes

def ssh_brute_force_detect(logs: list[dict]) -> list[dict]:
    failed_login = {}
    alerts = []
    danger_ips = set()
    for log in logs:
        if log["event"] == "FAILED_LOGIN":
            ip = log["ip"]
            if ip not in failed_login:
                failed_login[ip] = deque()
            failed_login[ip].append(log)
            
            if len(failed_login[ip]) >= 5:
                if get_log_mins(log) - get_log_mins(failed_login[ip][0]) < 5:
                    if ip not in danger_ips:
                        danger_ips.add(ip)

                        alerts.append({
                            "alert": "SSH_BRUTE_FORCE",
                            "ip": ip,
                            "attempts": len(failed_login[ip]),
                            "start_time": failed_login[ip][0]["timestamp"],
                            "end_time": failed_login[ip][-1]["timestamp"]
                        })

                else:
                    while get_log_mins(log) - get_log_mins(failed_login[ip][0]) >= 5:
                        failed_login[ip].popleft()

    return alerts

#def ssh_user_enumeration_detect(logs: list[dict]) -> list[dict]:


#def ssh_alert_detection(logs: list[dict]) -> dict:

                



def alert_detection(logs: list[dict]) -> str:
    
    alert = ""
    
    if logs[0]["source"] == "ssh":
        alert = ssh_alert_detection(logs)
    

    return alert




def main() -> None:
    print(ssh_brute_force_detect(parse_log("test.log")))
    
main()

