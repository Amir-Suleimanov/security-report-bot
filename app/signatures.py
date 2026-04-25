from __future__ import annotations

import re


SUSPICIOUS_PATH_FRAGMENT = (
    r"(?:"
    r"\.env(?:\..*)?|\.git(?:/.*)?|\.svn(?:/.*)?|\.hg(?:/.*)?|\.bzr(?:/.*)?|CVS(?:/.*)?|_darcs(?:/.*)?|"
    r"\.DS_Store|\.idea(?:/.*)?|\.vscode(?:/.*)?|\.htaccess|\.htpasswd|\.bash_history|\.zsh_history|\.mysql_history|"
    r"\.ssh(?:/.*)?|id_rsa|known_hosts|wp-admin/install\.php|wp-admin/setup-config\.php|wordpress/wp-admin/setup-config\.php|"
    r"wp-config(?:\.php)?(?:[\.\-_~].*)?|wp-content/debug\.log|phpinfo\.php|info\.php|server-status|server-info|"
    r"cgi-bin(?:/.*)?|vendor/phpunit(?:/.*)?|phpunit(?:/.*)?|webstat/.*|druid/index\.html|manager/text(?:/list)?|"
    r"actuator(?:/.*)?|GponForm/diag_Form|cliente/login\.php|login\.cgi|(?:stfilein/)?operator/servetest|"
    r"\+CSCOE\+/logon\.html|manage/account/login|admin/index\.html|backup(?:s)?(?:/.*)?|backup-db(?:/.*)?|"
    r".*\.(?:sql|sqlite3?|db|bak|old|orig|save|swp|tmp|zip|tar|tgz|7z|rar)"
    r")"
)
BACKUP_LEAK_FRAGMENT = (
    r"(?:.*(?:config|database|db|dump|backup|bak|passwd|secret|credentials|cred|env|settings|local|prod|dev)"
    r".*\.(?:php|asp|aspx|jsp|conf|config|ini|json|yaml|yml|xml|sql|txt|log|zip|gz|tar|tgz|7z|rar|bak|old|orig|save|swp|tmp))"
)
SCANNER_UA_FRAGMENT = (
    r"(?:sqlmap|wpscan|feroxbuster|gobuster|ffuf|fuzz faster u fool|masscan|masscan-ng|l9explore|l9tcpid|nessus|acunetix)"
)
TRUSTED_UA_FRAGMENT = r"Google-Read-Aloud"

SUSPICIOUS_PATH_RE = re.compile(r"/" + SUSPICIOUS_PATH_FRAGMENT)
SUSPICIOUS_QUERY_RE = re.compile(r"\?XDEBUG_SESSION_START=", re.IGNORECASE)
SCANNER_UA_RE = re.compile(SCANNER_UA_FRAGMENT, re.IGNORECASE)
TRUSTED_UA_RE = re.compile(TRUSTED_UA_FRAGMENT, re.IGNORECASE)


def render_fail2ban_filter() -> str:
    return f"""[Definition]

# Generated from app/signatures.py. Keep the report logic and fail2ban filter in sync.
failregex = ^<HOST> .* "(?:GET|POST|HEAD|OPTIONS|PROPFIND|PUT) /{SUSPICIOUS_PATH_FRAGMENT}[^\\"]*"
            ^<HOST> .* "PROPFIND /[^\\"]*"
            ^<HOST> .* "(?:GET|POST|HEAD|OPTIONS) /{BACKUP_LEAK_FRAGMENT}[^\\"]*"
            ^<HOST> .* "(?:GET|POST|HEAD) /\\?XDEBUG_SESSION_START=[^\\"]*"
            ^<HOST> .*"[^\\"]*" \\d+ \\d+ "[^\\"]*" "[^\\"]*{SCANNER_UA_FRAGMENT}[^\\"]*"

ignoreregex = ^<HOST> .*"[^\\"]*" \\d+ \\d+ "[^\\"]*" "[^\\"]*{TRUSTED_UA_FRAGMENT}[^\\"]*"
"""
