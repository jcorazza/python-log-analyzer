from log_analyzer import (
    read_logs,
    detect_bruteforce,
    detect_success_after_failures,
    detect_multiple_users,
    detect_bruteforce_success
)

def test_detect_bruteforce():
    events = [
        {
            "type": "failed_login",
            "ip": "192.168.1.50",
            "username": "admin",
            "time": "18:01:12"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.50",
            "username": "admin",
            "time": "18:01:15"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.50",
            "username": "admin",
            "time": "18:01:18"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.50",
            "username": "admin",
            "time": "18:01:21"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.50",
            "username": "admin",
            "time": "18:01:24"
        }
    ]

    alerts = detect_bruteforce(events)

    assert len(alerts) == 1
    assert alerts[0]["id"] == "BRUTE_FORCE"
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[0]["username"] == "admin"
    assert alerts[0]["attempts"] == 5

def test_no_bruteforce_with_four_attempts():
    events = [
        {
            "type": "failed_login",
            "ip": "192.168.1.50",
            "username": "admin",
            "time": "18:01:12"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.50",
            "username": "admin",
            "time": "18:01:15"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.50",
            "username": "admin",
            "time": "18:01:18"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.50",
            "username": "admin",
            "time": "18:01:21"
        }
    ]

    alerts = detect_bruteforce(events)

    assert len(alerts) == 0

def test_detect_success_after_failures():
    events = [
        {
            "type": "failed_login",
            "ip": "192.168.1.30",
            "username": "john",
            "time": "18:05:10"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.30",
            "username": "john",
            "time": "18:05:13"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.30",
            "username": "john",
            "time": "18:05:16"
        },
        {
            "type": "successful_login",
            "ip": "192.168.1.30",
            "username": "john",
            "time": "18:05:20"
        }
    ]

    alerts = detect_success_after_failures(events)

    assert len(alerts) == 1
    assert alerts[0]["id"] == "SUCCESS_AFTER_FAILURES"
    assert alerts[0]["source_ip"] == "192.168.1.30"
    assert alerts[0]["username"] == "john"
    assert alerts[0]["failed_attempts"] == 3


def test_no_success_after_failures_with_two_attempts():
    events = [
        {
            "type": "failed_login",
            "ip": "192.168.1.30",
            "username": "john",
            "time": "18:05:10"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.30",
            "username": "john",
            "time": "18:05:13"
        },
        {
            "type": "successful_login",
            "ip": "192.168.1.30",
            "username": "john",
            "time": "18:05:20"
        }
    ]

    alerts = detect_success_after_failures(events)

    assert len(alerts) == 0

def test_detect_multiple_users():
    events = [
        {
            "type": "failed_login",
            "ip": "192.168.1.40",
            "username": "admin",
            "time": "18:10:01"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.40",
            "username": "guest",
            "time": "18:10:03"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.40",
            "username": "root",
            "time": "18:10:05"
        }
    ]

    alerts = detect_multiple_users(events)

    assert len(alerts) == 1
    assert alerts[0]["id"] == "MULTIPLE_USERS"
    assert alerts[0]["source_ip"] == "192.168.1.40"
    assert alerts[0]["user_count"] == 3
    assert alerts[0]["users"] == ["admin", "guest", "root"]

def test_no_multiple_users_with_two_users():
    events = [
        {
            "type": "failed_login",
            "ip": "192.168.1.40",
            "username": "admin",
            "time": "18:10:01"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.40",
            "username": "guest",
            "time": "18:10:03"
        }
    ]

    alerts = detect_multiple_users(events)

    assert len(alerts) == 0

def test_detect_bruteforce_success():
    events = [
        {
            "type": "failed_login",
            "ip": "192.168.1.70",
            "username": "admin",
            "time": "18:11:01"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.70",
            "username": "admin",
            "time": "18:11:03"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.70",
            "username": "admin",
            "time": "18:11:05"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.70",
            "username": "admin",
            "time": "18:11:07"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.70",
            "username": "admin",
            "time": "18:11:09"
        },
        {
            "type": "successful_login",
            "ip": "192.168.1.70",
            "username": "admin",
            "time": "18:11:15"
        }
    ]

    alerts = detect_bruteforce_success(events)

    assert len(alerts) == 1
    assert alerts[0]["id"] == "BRUTE_FORCE_SUCCESS"
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["source_ip"] == "192.168.1.70"
    assert alerts[0]["username"] == "admin"
    assert alerts[0]["failed_attempts"] == 5
    assert alerts[0]["time_window"] == 8
    assert alerts[0]["successful_login"] == "18:11:15"

def test_no_bruteforce_success_when_attempts_are_too_slow():
    events = [
        {
            "type": "failed_login",
            "ip": "192.168.1.70",
            "username": "admin",
            "time": "18:11:01"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.70",
            "username": "admin",
            "time": "18:12:03"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.70",
            "username": "admin",
            "time": "18:13:05"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.70",
            "username": "admin",
            "time": "18:14:07"
        },
        {
            "type": "failed_login",
            "ip": "192.168.1.70",
            "username": "admin",
            "time": "18:15:09"
        },
        {
            "type": "successful_login",
            "ip": "192.168.1.70",
            "username": "admin",
            "time": "18:15:15"
        }
    ]

    alerts = detect_bruteforce_success(events)

    assert len(alerts) == 0

def test_read_logs(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "Failed password for admin from 192.168.1.50\n"
        "Accepted password for admin from 192.168.1.50\n"
    )

    logs = read_logs(log_file)

    assert len(logs) == 2
    assert "Failed password" in logs[0]
    assert "Accepted password" in logs[1]

def test_read_logs_file_not_found():
    logs = read_logs("file_that_does_not_exist.log")

    assert logs == []