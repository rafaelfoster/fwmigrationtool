import requests
import sys
import os

xgconf = ''
xgip = ''
user = ''
password = ''
xgip = ''


for param in sys.argv :
    if '--xgconf' in param:
        xgconf = param.replace("--xgconf=","")
        
    if '--user' in param:
        user = param.replace("--user=","")
    
    if '--password' in param:
        password = param.replace("--password=","")
        
    if '--xgip' in param:
        xgip = param.replace("--xgip=","")
        
        
getconfigstr = """<?xml version=\"1.0\" encoding=\"UTF-8\"?> 
<Request>
<Login>
<UserName>"""+user+"""</UserName>
<Password>"""+password+"""</Password>
</Login>\n"""


def api_call(api_ip, xml_file):
    api_url = r'https://{}:4444/webconsole/APIController?'.format(api_ip)
    data = {'reqxml' : (None,xml_file)}
    r = requests.post(api_url, files=data, verify=False)   
    print(r.text)

def main():
    print("""Utilize:
          
XGAPIpush --xgconf=<Entities.xml> --user=<XG user> --password=<XG password> --xgip=<XG ip>\n""")
    
    if xgconf == '':
        print("--> Faltou a configuracao do Sophos XG <Entities.xml>")
        
    elif user == '':
        print("--> Faltou o usuario do Sophos XG")
        
    elif password == '':
        print("--> Faltou a senha do Sophos XG")
        
    elif xgip == '':
        print("--> Faltou o Ip do Sophos XG")
    
    else:
        xgpath = os.path.abspath(xgconf)
        f = open(xgpath, 'r' )
        
        data_file = f.read()
        data_file = getconfigstr + data_file + "</Request>"
        
        ipaddress = xgip
        
        api_call(ipaddress, data_file)

if __name__ == "__main__":
    main() 
