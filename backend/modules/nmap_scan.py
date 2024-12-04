import nmap
from .classifyer import ScriptClassifier


class NmapScanner:
    """
    Manages the configuration, execution, and results parsing of Nmap scans.
    """

    def __init__(self):
        self.scanner = nmap.PortScanner()

    def run_scan(self, ip_range, options):
        """
        Runs an Nmap scan on the specified IP range with the provided options.
        """
        arguments = self._build_arguments(options)
        self.scanner.scan(ip_range, arguments=arguments)
        return self._parse_results()

    def _build_arguments(self, options):
        """
        Constructs Nmap command-line arguments from the given options.
        """
        print(options)
        args = []
        args_map = {
            "service_version": "-sV",
            "os_detection": "-O",
            "aggressive": "-A",
            "tcp_scan": "-sT",
            "udp_scan": "-sU",
            "ping_scan": "-sn",
            "fast_scan": "-F",
        }
        for opt, arg in args_map.items():
            if options.get(opt):
                args.append(arg)
        if options.get("port_range"):
            args.append(f"-p {options['port_range']}")
        if options.get("scripts") and options["scripts"] != [""]:
            args.append(f"--script {','.join(options['scripts'])}")
        if options.get("max_rtt_timeout"):
            args.append(f"--max-rtt-timeout {options['max_rtt_timeout']}")
        if options.get("host_timeout"):
            args.append(f"--host-timeout {options['host_timeout']}")
        if options.get("retries"):
            args.append(f"--max-retries {options['retries']}")
        if options.get("scan_delay"):
            args.append(f"--scan-delay {options['scan_delay']}")

        return " ".join(args)

    def _parse_results(self):
        """
        Parses the results of the Nmap scan and classifies the scripts.
        """
        scan_results = []
        for host in self.scanner.all_hosts():
            for proto in self.scanner[host].all_protocols():
                for port in self.scanner[host][proto].keys():
                    service_info = self.scanner[host][proto][port]
                    context = self._build_context(service_info)
                    classified_scripts = self._classify_scripts(
                        service_info.get("script", {}), context
                    )
                    scan_results.append(
                        self._format_result(
                            host, proto, port, service_info, classified_scripts
                        )
                    )
        return scan_results

    @staticmethod
    def _build_context(service_info):
        """
        Builds the context for dynamic classification.
        """
        return {
            "public_ftp": "ftp" in service_info.get("name", "").lower(),
            "sensitive_data_found": any(
                "password" in str(output).lower()
                for output in service_info.get("script", {}).values()
            ),
        }

    @staticmethod
    def _classify_scripts(script_output, context):
        """
        Classifies each script in the script output.
        """
        return {
            script: {
                "output": output,
                "risk": ScriptClassifier.classify(script, output, context),
            }
            for script, output in script_output.items()
        }

    @staticmethod
    def _format_result(host, proto, port, service_info, classified_scripts):
        """
        Formats a single scan result into a structured dictionary.
        """
        return {
            "ip": host,
            "port": port,
            "protocol": proto,
            "service": service_info.get("name", ""),
            "product": service_info.get("product", ""),
            "version": service_info.get("version", ""),
            "state": service_info["state"],
            "script_output": classified_scripts,
        }
