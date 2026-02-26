package ipban

// defaultRuleFile is the built-in rule set used when no rule file/URL is configured.
var defaultRuleFile = RuleFile{
	Version: 1,
	Rules: []Rule{
		{
			Path: []string{
				"/.env", "/.env.bak", "/.env.local", "/.env.production",
				"/.git/config", "/.git/HEAD",
				"/.svn/entries",
				"/.htaccess", "/.htpasswd", "/.DS_Store",
				"/wp-login.php", "/xmlrpc.php", "/wp-config.php",
				"/adminer.php", "/admin.php",
				"/config.php", "/config.yml", "/config.json", "/config.bak",
				"/web.config",
				"/backup.sql", "/dump.sql", "/database.sql", "/db.sql",
				"/backup.zip", "/backup.tar.gz",
				"/shell.php", "/cmd.php", "/c99.php", "/r57.php",
				"/webshell.php", "/eval-stdin.php",
				"/server-status", "/server-info",
			},
			PathPrefix: []string{
				"/.env.", "/.git/", "/.svn/",
				"/wp-admin/", "/wp-content/uploads/", "/wp-includes/",
				"/phpmyadmin", "/pma/", "/myadmin/",
				"/cgi-bin/",
				"/actuator/", "/jmx-console/",
				"/manager/html", "/manager/status",
				"/solr/", "/jenkins/", "/hudson/",
				"/debug/pprof", "/debug/vars",
				"/telescope/", "/vendor/phpunit",
				"/etc/passwd", "/etc/shadow", "/proc/self/",
			},
			PathKeyword: []string{
				"wp-config", "phpinfo",
			},
			UserAgentKeyword: []string{
				"sqlmap", "nikto", "nmap", "masscan", "zgrab",
				"gobuster", "dirbuster", "dirb", "wfuzz", "ffuf",
				"nuclei", "acunetix", "nessus", "openvas", "qualys",
				"burpsuite", "owasp", "w3af", "arachni", "skipfish",
				"whatweb", "wpscan", "joomscan", "droopescan",
				"xray", "crawlergo", "httpx", "subfinder",
				"censys", "shodan", "netcraft",
				"scanner", "exploit",
			},
		},
	},
}
