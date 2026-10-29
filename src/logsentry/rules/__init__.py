"""Detection rules. Add each new rule class to RULES."""

from logsentry.rules.base import Rule
from logsentry.rules.password_spray import PasswordSpray
from logsentry.rules.ssh_bruteforce import SshBruteforce
from logsentry.rules.success_after_failures import SuccessAfterFailures
from logsentry.rules.web_attack import WebAttack
from logsentry.rules.web_login_bruteforce import WebLoginBruteforce
from logsentry.rules.web_scan import WebScan

RULES: dict[str, type[Rule]] = {
    r.id: r
    for r in (
        SshBruteforce,
        PasswordSpray,
        SuccessAfterFailures,
        WebScan,
        WebAttack,
        WebLoginBruteforce,
    )
}
