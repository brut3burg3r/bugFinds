## Step by step list to bug hunt

# Phase 1: Recon & Scoping

Primary objective:

- Enumerate all assets related/linked to the target
- Identify accessible endpoints, directories and technologies
- Build a target map before touching Burp or sending payloads

1. Target Identification

    Tools:

    - `Whois, crt.sh, dnsdumpster, shodan`
    - `RapidDNS, SecurityTrails`
    - Bug bounty platform scope (read clearly: *.example.com vs specific subdomains)

    Goals:

    - Know what's in-scope
    - Record the root domain, IPs, and DNS records
    - scope domain  Acquisitiond ASN enum Reverse whois       subdom enum port analysis
    
    Commands:
    ```bash
    whois example.com
    nslookup example.com
    curl https://crt.sh/?q=%.example.com&output=json
    ```
    
    What to do:

    - seed or root domain
    - Acquisitions(Crunchbase.com) also google on these acquisitions
    - ASN Enumeration (bgp.he.net)- Autonomous System Numbers help track down IT infrastructure (cmd tools: asnlookup, amass)

    `amass intel -asn 46489`

    - Reverse Whois (whoxy.com, DOMLink)
    - ad/analytics relationships(buildwith.com)

        checking related domains and subdomains

2. Subdomain Enumeration

    Tools:
    ` assetfinder, amass, subfinder, findomain, dnsx, httpx `

    Commands:
    ```bash
    subfinder -d example.com -o subdomains.txt
    assetfinder --subs-only example.com >> subdomains.txt
    amass enum -passive -d example.com -o amass.txt
    sort -u *.txt > all-subs.txt
    ```
    Look for:

    - Anything suspicious like `admin. dev. staging. uat. dashboard.`
    - Old apps, forgotten systems.

    Outcome:
    
    - All-subs.txt ready for next step

3. Alive checking

    Tools:
    `httpx, httprobe, curl`

    command:
    
    ` cat all-subs.txt | httpx -status-code -title -tech-detect -o alive.txt`

    look for:

    - 200/403/302/401 codes
    - weird titles like “Test Page”, “Apache2 Ubuntu Default Page”, or “Forbidden”

    Outcomes:

    List of live targets with stack&status code

4. URL Harvesting & JS enumeration

    Tools:

    `gau, waybackurls, hakrawler, katana, jsfiles, linkfinder, JSParser`

    commands:

    ```
    cat all-subs.txt | gau > urls.txt
    cat all-subs.txt | waybackurls > wayback.txt
    sort -u urls.txt wayback.txt > all-urls.txt
    ```
    JS Discovery:

    `cat all-urls.txt | grep "\.js" | uniq > jsfiles.txt`

    Outcomes:
    JavaScript files list for dynamic endpoint and API discovery





