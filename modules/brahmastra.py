def run(domain, techs=None):
    dorks = [
        # Credential & secret leaks
        f'site:github.com "{domain}" password OR secret OR api_key',
        f'site:pastebin.com "{domain}"',
        f'site:trello.com "{domain}"',

        # Exposed sensitive files
        f'site:{domain} filetype:env OR filetype:sql OR filetype:bak OR filetype:log',
        f'site:{domain} filetype:xml inurl:config',
        f'site:{domain} filetype:json inurl:api',

        # Admin & login panels
        f'site:{domain} inurl:admin OR inurl:login OR inurl:dashboard',
        f'site:{domain} inurl:wp-admin OR inurl:phpmyadmin',

        # Error pages (leak stack traces, paths, versions)
        f'site:{domain} "Warning: mysql_" OR "ORA-" OR "syntax error"',
        f'site:{domain} "Index of /" intitle:"Index of"',

        # Dev/staging assets
        f'site:{domain} inurl:dev OR inurl:staging OR inurl:test',

        # API documentation exposure
        f'site:{domain} inurl:swagger OR inurl:api-docs',
    ]

    # Tech-specific dorks
    if techs:
        tech_lower = str(techs).lower()
        if 'wordpress' in tech_lower:
            dorks.append(f'site:{domain} inurl:wp-content/uploads filetype:php')
        if 'jenkins' in tech_lower:
            dorks.append(f'site:{domain} inurl:jenkins inurl:script')
        if 'jira' in tech_lower:
            dorks.append(f'site:{domain} inurl:jira inurl:ViewUserHover.jspa')

    return {"msg": "Deploy these in Google / DorkSearch / Shodan:", "dorks": dorks}
