

def parse_ssh_log(log_line: str) -> dict:
    splitline = log_line.split()
    timestamp = splitline[0] + " " + splitline[1] + " " + splitline[2]
    host = splitline[3]

    # Make event detection function later on
    if "Accepted" in log_line or "session opened" in log_line:
        event = "SUCCESS_LOGIN"
    elif "Failed password" in log_line or "Invalid user" in log_line:
        event = "FAILED_LOGIN"
    
    user = ""
    
    count = 0
    for word in splitline:
        if word == "user":
            user = splitline[count + 1]
            break
        elif word == "for":
            user = splitline[count + 1]
            break
        count += 1

    if user == "":
        user = "NO_USER"

    ip = "NO_IP"
    count = 0
    for word in splitline:
        if word == "from":
            ip = splitline[count + 1]
        count += 1


    log_entry = {
        "timestamp": timestamp,
        "host": host,
        "event": event, 
        "user": user, 
        "ip": ip
    }

    return log_entry

def parse_line(log_line: str) -> dict:

    splitline = log_line.split()
    timestamp = splitline[0] + " " + splitline[1] + " " + splitline[2]
    event = splitline[3]
    user = splitline[4].replace("user=", "")
    ip = splitline[5].replace("ip=", "")

    log_entry = {
        "timestamp": timestamp,
        "event": event, 
        "user": user, 
        "ip": ip
    }

    return log_entry



def parse_log(log_file: str) -> list[dict]:

    parsed_log = []

    with open(log_file, "r") as file:
        for line in file:
            parsed_log.append(parse_line(line))
    
    return parsed_log

