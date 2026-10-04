import pytest
from datetime import datetime
from app.parsers.linux_auth import LinuxAuthParser
from app.parsers.apache_nginx import ApacheNginxParser
from app.parsers.generic import GenericParser
from app.parsers.manager import LogParserManager

def test_linux_auth_parser_ssh_failed():
    parser = LinuxAuthParser()
    raw = "Oct  4 14:02:15 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 45212 ssh2"
    event = parser.parse_line(raw, line_number=1)
    
    assert event is not None
    assert event.event_type == "AUTH_FAILURE"
    assert event.source_ip == "192.168.1.100"
    assert event.source_port == 45212
    assert event.username == "admin"
    assert event.process == "sshd"
    assert event.severity == "MEDIUM"
    assert isinstance(event.timestamp, datetime)

def test_linux_auth_parser_ssh_accepted():
    parser = LinuxAuthParser()
    raw = "Oct  4 14:02:20 server sshd[12350]: Accepted password for lokesh from 192.168.1.50 port 51234 ssh2"
    event = parser.parse_line(raw, line_number=2)
    
    assert event is not None
    assert event.event_type == "AUTH_SUCCESS"
    assert event.source_ip == "192.168.1.50"
    assert event.username == "lokesh"
    assert event.severity == "INFORMATIONAL"

def test_linux_auth_parser_sudo():
    parser = LinuxAuthParser()
    raw = "Oct  4 14:03:10 server sudo[12356]:  lokesh : 3 incorrect password attempts ; TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    event = parser.parse_line(raw, line_number=3)
    
    assert event is not None
    assert event.event_type == "PRIVILEGE_EVENT"
    assert event.username == "lokesh"
    assert event.severity == "HIGH"

def test_apache_nginx_parser_clf():
    parser = ApacheNginxParser()
    raw = '192.168.1.100 - frank [10/Oct/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 403 2326 "http://example.com" "Mozilla/5.0"'
    event = parser.parse_line(raw, line_number=1)
    
    assert event is not None
    assert event.source_ip == "192.168.1.100"
    assert event.username == "frank"
    assert event.method == "GET"
    assert event.endpoint == "/admin"
    assert event.status_code == 403
    assert event.event_type == "ACCESS_DENIED"

def test_generic_parser():
    parser = GenericParser()
    raw = "2026-10-04 14:02:15 [ERROR] auth_gateway: Failed password for user admin from 10.0.0.45"
    event = parser.parse_line(raw, line_number=1)
    
    assert event is not None
    assert event.source_ip == "10.0.0.45"
    assert event.username == "admin"
    assert event.event_type == "AUTH_FAILURE"

def test_parser_manager_detection():
    manager = LogParserManager()
    linux_lines = [
        "Oct  4 14:02:15 server sshd[12345]: Failed password for root from 1.2.3.4 port 22",
        "Oct  4 14:02:16 server sudo[123]:  bob : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls"
    ]
    web_lines = [
        '1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 500',
        '1.2.3.4 - - [10/Oct/2026:13:55:37 +0000] "POST /login HTTP/1.1" 401 200'
    ]
    assert manager.detect_format(linux_lines) == "LINUX_AUTH"
    assert manager.detect_format(web_lines) == "APACHE_NGINX"
