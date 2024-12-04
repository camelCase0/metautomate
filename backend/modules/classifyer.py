
class ScriptRiskLevels:
    """
    Stores and manages predefined script risk levels for Nmap scripts.
    """
    LEVELS = {
        "INFO": [
            "default", "safe", "banner", "http-title", "smtp-commands", "imap-capabilities",
            "dns-service-discovery", "http-server-header", "asn-query", "whois-domain",
            "http-headers", "ip-geolocation-ipinfodb", "ssl-cert", "ssl-date",
            "ssl-google-cert-catalog", "smtp-capabilities"
        ],
        "LOW": [
            "http-methods", "mysql-info", "rdp-enum-encryption", "imap-ntlm-info",
            "targets-ipv6-multicast-mld", "targets-ipv6-multicast-slaac", "ntp-info",
            "smtp-strangeport", "pop3-brute", "smtp-open-relay", "http-cors", "http-enum",
            "http-cookie-flags", "http-robots.txt"
        ],
        "MEDIUM": [
            "ftp-anon", "nbstat", "snmp-info", "rpc-grind", "http-sql-injection",
            "mysql-users", "mongodb-info", "redis-info", "oracle-enum-users",
            "mysql-dump-hashes", "drda-info", "mongodb-databases", "smb-os-discovery",
            "ftp-brute", "http-brute", "mysql-brute", "smtp-brute", "imap-capabilities",
            "smtp-enum-users", "http-form-brute", "http-errors", "http-iis-short-name-brute",
            "dns-brute", "dns-srv-enum", "ssl-enum-ciphers"
        ],
        "HIGH": [
            "ssh-hostkey", "ssl-known-key", "smb-vuln-cve-2017-7494", "ssl-dh-params",
            "http-backdoor", "ftp-proftpd-backdoor", "smtp-vuln-cve2011-1720",
            "mysql-vuln-cve2012-2122", "rdp-brute", "redis-brute", "oracle-brute",
            "ssh-brute", "sip-brute", "snmp-brute", "http-xssed", "http-vuln-cve2015-1427",
            "ssl-poodle", "http-malware-host"
        ],
        "CRITICAL": [
            "vulners", "ftp-vsftpd-backdoor", "ssl-heartbleed", "http-shellshock",
            "smb-vuln-ms17-010", "http-vuln-cve2017-5638", "http-vuln-cve2021-26855",
            "ssl-v2", "tls-ticketbleed", "sip-vuln-cve2011-2536", "smb-vuln-cve-2012-1182",
            "http-majordomo2-dir-traversal", "http-huawei-hg5xx-vuln", "http-vuln-cve2013-7091",
            "http-vuln-cve2010-0738"
        ]
    }

    @classmethod
    def get_base_level(cls, script_name):
        """
        Returns the base risk level of the script.
        """
        for level, scripts in cls.LEVELS.items():
            if script_name in scripts:
                return level
        return "INFO"


class ScriptClassifier:
    """
    Classifies Nmap script outputs based on risk levels and dynamic context.
    """

    @staticmethod
    def classify(script_name, script_output=None, context=None):
        """
        Classifies an Nmap script based on its risk level and dynamic context.
        """
        base_level = ScriptRiskLevels.get_base_level(script_name)
        if context:
            return ScriptClassifier._adjust_classification(script_name, script_output, base_level, context)
        return base_level

    @staticmethod
    def _adjust_classification(script_name, script_output, base_level, context):
        if script_name == "ftp-anon" and context.get("public_ftp"):
            return "CRITICAL" if context.get("sensitive_data_found") else "HIGH"
        if script_name.startswith("http-") and context.get("sensitive_endpoint"):
            return "CRITICAL" if "exploit" in script_output.lower() else "HIGH"
        if context.get("sensitive_data_found") and base_level in ["LOW", "MEDIUM"]:
            return "HIGH"
        return base_level

