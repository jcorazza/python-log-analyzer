import re
from datetime import datetime
from http.cookiejar import user_domain_match


def read_logs(log_file):
    with open(log_file, "r") as file:
        return file.readlines()

def extract_time(log):
    time_match = re.search(r"\b(\d{2}:\d{2}:\d{2})\b", log)

    if time_match:
        return time_match.group(1)
    return None

def analyze_log(logs):
    events = []
    failed_logins = 0
    successful_logins = 0

    for log in logs:
        if "Failed password" in log:
            failed_logins += 1

            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", log)
            user_match = re.search(r"Failed password for invalid user (\S+)", log)

            if user_match:
                username = user_match.group(1)
            else:
                user_match = re.search(r"Failed password for (\S+)", log)

                if user_match:
                    username = user_match.group(1)
                else:
                    username = None

            if ip_match and username:
                ip = ip_match.group(1)
                event_time = extract_time(log)

                events.append({
                    "type": "failed_login",
                    "ip": ip,
                    "username": username,
                    "time": event_time
                })

            if ip_match:
                ip = ip_match.group(1)
                event_time = extract_time(log)

        elif "Accepted password" in log:
            successful_logins += 1

            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", log)
            user_match = re.search(r"Accepted password for (\S+)", log)

            if ip_match and user_match:
                ip = ip_match.group(1)
                username = user_match.group(1)
                event_time = extract_time(log)

                events.append({
                    "type": "successful_login",
                    "ip": ip,
                    "username": username,
                    "time": event_time
                })
    return {
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "events": events
    }

def detect_bruteforce(events):
    alerts = []

    failed_events = [
        event for event in events
        if event["type"] == 'failed_login'
    ]

    for i in range(len(failed_events) -4):
        first_event = failed_events[i]

        for j in range(i + 4, len(failed_events)):
            fifth_event = failed_events[j]

            if first_event["ip"] != fifth_event["ip"]:
                continue

            first_time = datetime.strptime(
                first_event["time"],
                "%H:%M:%S"
            )

            fifth_time = datetime.strptime(
                fifth_event["time"],
                "%H:%M:%S"
            )

            duration = (fifth_time - first_time).total_seconds()

            if duration <=60:
                alerts.append({
                    "id": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "type": "brute_force",
                    "source_ip": first_event["ip"],
                    "username": first_event["username"],
                    "attempts": 5,
                    "time_window": int(duration)
                })

                break
    return alerts

def detect_success_after_failures(events):
    alerts = []

    for i, event in enumerate(events):

        if event["type"] != "successful_login":
            continue

        failed_count = 0

        for previous_event in events[:i]:
            if (
                previous_event["type"] == "failed_login"
                and previous_event["ip"] == event["ip"]
                and previous_event["username"] == event["username"]
            ):
                failed_count += 1

        if failed_count >= 3:
            alerts.append({
                "id": "SUCCESS_AFTER_FAILURES",
                "severity": "HIGH",
                "type": "successful_login_after_failures",
                "source_ip": event["ip"],
                "username": event["username"],
                "failed_attempts": failed_count,
                "time": event["time"]
            })
    return alerts

def detect_multiple_users(events):
    alerts = []

    users_by_ip = {}

    for event in events:
        if event["type"] != "failed_login":
            continue

        ip = event["ip"]
        username = event["username"]

        if ip not in users_by_ip:
            users_by_ip[ip] = set()

        users_by_ip[ip].add(username)

    for ip, users in users_by_ip.items():
        if len(users) >= 3:
            alerts.append({
                "id": "MULTIPLE_USERS",
                "severity": "MEDIUM",
                "type": "multiple_users_targeted",
                "source_ip" : ip,
                "user_count" : len(users),
                "users" : sorted(users)
            })
    return alerts

def detect_bruteforce_success(events):
    alerts =[]

    for i, event in enumerate(events):
        if event["type"] != "successful_login":
            continue

        failed_events = []

        for previous_event in events[:i]:
            if (
                previous_event["type"] == "failed_login"
                and previous_event["ip"] == event["ip"]
                and previous_event["username"] == event["username"]
            ):
                failed_events.append(previous_event)

        if len(failed_events) < 5:
            continue

        first_time = datetime.strptime(
            failed_events[-5]["time"], "%H:%M:%S"
        )

        last_failed_time = datetime.strptime(
            failed_events[-1]["time"], "%H:%M:%S"
        )

        duration = (
            last_failed_time - first_time
        ).total_seconds()

        if duration <= 60:
            alerts.append({
                "id": "BRUTE_FORCE_SUCCESS",
                "severity": "CRITICAL",
                "type": "brute_force_success",
                "source_ip": event["ip"],
                "username": event["username"],
                "failed_attempts": 5,
                "time_window": int(duration),
                "successful_login": event["time"]
            })
        return  alerts

def detect_threats(events):
    alerts = []

    brute_force_success_alerts = detect_bruteforce_success(events)
    alerts.extend(brute_force_success_alerts)

    correlated_incidents = {
        (alert["source_ip"], alert["username"])
        for alert in brute_force_success_alerts
    }

    brute_force_alerts = detect_bruteforce(events)

    for alert in brute_force_alerts:
        incident = (alert["source_ip"], alert["username"])

        if incident not in correlated_incidents:
            alerts.append(alert)

    success_alerts = detect_success_after_failures(events)

    for alert in success_alerts:
        incident = (alert["source_ip"], alert["username"])

        if incident not in correlated_incidents:
            alerts.append(alert)

    alerts.extend(detect_multiple_users(events))

    return alerts

def generate_report(logs, results, alerts):
    user_attempts = {}
    ip_attempts = {}

    print("\n========================================")
    print("        SSH LOG SECURITY ANALYZER")
    print("========================================")

    print(f"\nTotal events       : {len(logs)}")
    print(f"Successful logins  : {results['successful_logins']}")
    print(f"Failed logins      : {results['failed_logins']}")

    print("\n----------------------------------------")
    print("TOP SOURCE IPs")
    print("----------------------------------------")

    for event in results["events"]:
        if event["type"] == "failed_login":
           ip = event["ip"]

        if ip in ip_attempts:
            ip_attempts[ip] += 1
        else:
            ip_attempts[ip] = 1

    for ip, attempts in ip_attempts.items():
        print(f"{ip:<16} {attempts} failed attempts")

    print("\n----------------------------------------")
    print("TARGETED USERS")
    print("----------------------------------------")
    for event in results["events"]:
        if event["type"] == "failed_login":
           username = event["username"]

        if username in user_attempts:
            user_attempts[username] += 1
        else:
            user_attempts[username] = 1

    for username, attempts in user_attempts.items():
        print(f"{username:<16} {attempts} failed attempts")

    print("\n----------------------------------------")
    print("SECURITY ALERTS")
    print("----------------------------------------")

    if not alerts:
        print("[OK] No suspicious activity detected.")

    for alert in alerts:
        print(f"[{alert['severity']}] {alert['id']}")

        if alert["type"] == "brute_force":
            print(f"       Source IP: {alert['source_ip']}")
            print(f"       Target user: {alert['username']}")
            print(f"       Attempts: {alert['attempts']}")
            print(f"       Time window: {alert['time_window']} seconds")

        elif alert["type"] == "successful_login_after_failures":
            print(f"       Source IP: {alert['source_ip']}")
            print(f"       Target user: {alert['username']}")
            print(f"       Failed attempts: {alert['failed_attempts']}")
            print(f"       Time: {alert['time']}")

        elif alert["type"] == "multiple_users_targeted":
            print(f"        Source IP: {alert['source_ip']}")
            print(f"        User count: {alert['user_count']}")
            print(f"        Users: {', '.join(alert['users'])}")

        elif alert["type"] == "brute_force_success":
            print(f"       Source IP: {alert['source_ip']}")
            print(f"       Target user: {alert['username']}")
            print(f"       Failed attempts: {alert['failed_attempts']}")
            print(f"       Time window: {alert['time_window']} seconds")
            print(f"       Successful login: {alert['successful_login']}")

    print("\n========================================")


if __name__ == "__main__":
    log_file = "sample_auth.log"
    logs = read_logs(log_file)
    results = analyze_log(logs)

    alerts = detect_threats(results["events"])
    generate_report(logs, results, alerts)



