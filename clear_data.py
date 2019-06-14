from html import unescape
from urllib.parse import unquote
import os
import io
import nltk
import re
import json
from html import unescape
from urllib.parse import unquote
from urllib.parse import parse_qs
from base64 import b64decode, b64encode
# from libinjection import is_sql_injection
# pip install  phpserialize
import phpserialize



DATA_DIR = "/Users/tme/myobject/ml/iwaf_demo_cnn/CNN_SQL/data"

def decode_files():
    """
    URL  解码 DATA_DIR下所有名称不包含decode的txt文件
    """
    for file_path in os.listdir(DATA_DIR):
        if "decode" in file_path:
            continue
        if ".txt" not in file_path:
            continue
        full_path = DATA_DIR + '/' + file_path
        decode_datas = []
        print(full_path)
        with open(full_path, encoding="utf-8") as f:
            for line in f.readlines():
                # decode_data = ",".join(unescape(line))
                line = unquote(line)
                decode_datas.append(unescape(line))
        with open(full_path + ".urldecode", 'w') as f:
            f.writelines(decode_datas)


## sql
# %26[\w.]+%3d([\w-/:\.]|%3A|%20|%2B|%40)*

re_split = """
(.*\.(ascx|cfm|ashx|aspx|php|asp|jsp|&)\?\w+=|&)
^[\w,=,-,.]+\' => '
^[a-zA-Z]+%20 => %20
^[a-zA-Z]+%22 => %22
^[a-zA-Z]+%27 => %27
^[a-zA-Z]+%29 => %29
--.* => --
^[a-zA-Z]+%25 => %25
%26([\w]|%5B|%5D)*%3D([\w\-/:\.]|%3A|%20|%2B|%40)*
%26[\w.]+%3d([\w+/:\.]|%3A|%20|%2B|%40)*
^\w+%3D([\w\-/:\.]|%3A|%20|%2B|%40)*--%3E => --%3E
^(\w|-|\.|%5B|%5D)+%3D([\w\-/:\.]|%3A|%20|%2B|%40|%2C)*
alert%28%27.*?%27%29 => alert%28%27xss%27%29
alert%28\d+?%29 => alert%28%27xss%27%29
alert%28/.*?%29 => alert%28%27xss%27%29
alert%28%22.*?%22%29 => alert%28%27xss%27%29
%3Cmarquee%3E.*?%3C/marquee%3E
%3Cmarquee.*?marquee%3E
%3Ch1%3E%3Cmarquee%3Exss%2Bby%2Bdeath\-angel
/.*(php|aspx)?\?.*?\w+=\w*(&\w+=[\w\-]*)*
^(\w|-)+?(%22|%27) => "
^(\w|-)+?%3C => %3C
"""

xss_re_split = """
<script>.*</script>
<SCRIPT>.*</SCRIPT>
"""

DATA_DIR = "/Users/tme/myobject/ML/dev/data"


def url_str(payload):
    #     payload = url_re(payload)
    payloads = []
    for i in payload:
        if isinstance(i, str):
            for i in is_sql_injection(i)["fingerprint"]:
                payloads.append(i)
        else:
            # int float bools --> str
            payloads.append(str(i))
    return payloads


def url_str(payload):
    #     payload = url_re(payload)
    return [str(x) for x in payload]

def url_decode(payloads, exec_count=0):
    """
    payload: str --> "/index.php?a=1"
    return list  --> ["/index.php", "a", "1"]
    """
    exec_count += 1
    if exec_count > 1000:
        print("max call")
        return payloads
    new_payloads = []
    if not isinstance(payloads, list):
        payloads = [payloads]
    for _index, payload in enumerate(payloads):
        if payload in [False, True, None]:
            new_payloads.append(payload)
            continue
        if isinstance(payload, int):
            new_payloads.append(payload)
            continue
        if isinstance(payload, float):
            new_payloads.append(payload)
            continue
        if isinstance(payload, dict):
            for k, v in payload.items():
                new_payloads.append(k)
                new_payloads.append(v)
            continue
        if isinstance(payload, list):
            for i in payload:
                new_payloads.append(i)
            continue
        if isinstance(payload, bytes):
            payload = payload.decode()
        # URL decode & unicode decode & hex
        payload = unquote(payload)
        # HTML decode
        payload = unescape(payload)

        # base64
        if len(payload) % 4 == 0:
            try:
                bpayload = b64decode(payload.encode("utf-8")).decode("utf-8")
            except Exception:

                pass
            else:
                if b64encode(bpayload.encode()).decode() == payload:
                    payload = bpayload

        dict_data = {}
        dict_qs = {}
        dict_php_serialize = {}

        # query string
        if "?" in payload or "&" in payload:
            dict_qs = parse_qs(payload)
        # json
        if "{" in payload and "}" in payload:
            try:
                dict_data = json.loads(payload)
            except Exception:
                pass
        # php serialize
        if ":" in payload and "}" in payload:
            try:
                dict_php_serialize = phpserialize.loads(payload.encode())
            except Exception:
                pass

        if dict_data:
            new_payloads.append(dict_data)
        elif dict_php_serialize:
            new_payloads.append(dict_php_serialize)
        elif dict_qs:
            new_payloads.append(dict_qs)
        else:
            new_payloads.append(payload)

    if str(new_payloads) != str(payloads):
        return url_decode(new_payloads, exec_count)

    # lower
    for _index, i in enumerate(new_payloads):
        if isinstance(i, str):
            new_payloads[_index] = i.lower()
    return new_payloads

def split_one(payload):
    """
    过正则, 用正则剔除非攻击体
    """
    for _re in re_split.split("\n"):
                    if _re:
                        _re_after = ""
                        _re_befor = _re
                        if "=>" in _re:
                            _re_befor, _re_after = _re.split("=>")
                            _re_befor = _re_befor.strip()
                            _re_after = _re_after.strip()
                        payload, _ = re.subn(_re_befor, _re_after, payload)
    return payload
    

def split_two(payload):
    """
    过正则, 用正则留下攻击体
    """
    for _re in xss_re_split.split("\n"):
        pass


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def url_split():
    # for file_path in os.listdir(DATA_DIR):
    #     black_file_name = ['git', 'split', 'dvc', 'DS_Store']:

    #     if "git" in file_path:
    #         continue
    #     if "split" in file_path:
    #         continue
    #     if "dvc" in file_path:
    #         continue
        file_path = 'train_xss.txt'
        full_path = DATA_DIR + '/' + file_path
        decode_datas = []
        ex_decode_datas = []
        print(full_path)
        with open(full_path, encoding="utf-8") as f:
            for payload in f.readlines():
                # decode_data = ",".join(unescape(line))
                ex_payload = payload
                payload = split_one(payload)
                ex_decode_datas.append(ex_payload + "\n" + payload+"\n")
                payload = url_decode(payload)
                payload = url_str(payload)
                payload = ",".join(payload)
                if payload != "\n":
                    decode_datas.append(payload + "\n")

        # full_path = DATA_DIR + "/clear_data/" + file_path
        full_path = os.path.join('data', 'clear_data', file_path)
        mkdir_p(os.path.join('data', 'clear_data'))
        print(full_path)
        with io.open(full_path + ".urlsplit", 'w', encoding='utf8') as f:
            for p in decode_datas:
                f.write(p)

        # with open(full_path + ".urlsplit", 'w') as f:
        #     f.writelines(decode_datas)
        # with open(full_path + ".urlsplitindex", 'w') as f:
        #     f.writelines(ex_decode_datas)


url = """
m%3Df423c594bde1b752f76d363ef2351d4f%26sv%3D8.2.1.348%26dv%3D1.1.0.3200%26r%3D104
callback%3DjQuery11240451821715105325_1498609670544%26itemspaceid%3D15609%26sf%3D1%26pgid%3Df1543b65-3133-c76b-7e44-70bd9072d2c9%26newschn%3D1000000000%26_smuid%3D27033E38ED88C6EDF98B184EDB4974A8%26SUV%3D1312111033048255%26yyid%3D%26adsrc%3D13%26adps%3D90001%26turn%3D1%26maxreads%3D1%26multichn%3D1000000000%26_%3D1498609670545
callback%3DjQuery19103811657843180001_1415179255373%26dst%3Dflash%26msgtype%3D165%26tablist%3D22%26id%3Db00247vu24c%26playright%3D2%26host%3Dhttp%3A//sports.qq.com/nba/%3Fpgv_ref%3Daio2015%26ptlang%3D2052%26pidx%3D0%26size%3D24
rdid%3D2974481%26dc%3D3%26di%3Du2974481%26dri%3D0%26dis%3D0%26dai%3D1%26ps%3D2722x292%26dcb%3D___adblockplus%26dtm%3DHTML_POST%26dvi%3D0.0%26dci%3D-1%26dpt%3Dnone%26tsr%3D0%26tpr%3D1498611951636%26ti%3D%E5%A4%8D%E5%85%B4%E5%8F%B7%E4%B8%BA%E4%BD%95%E8%BF%90%E8%90%A5%E6%AC%A1%E6%97%A5%E5%B0%B1%E6%99%9A%E7%82%B949%E5%88%86%E9%92%9F%EF%BC%9F%E5%AE%98%E6%96%B9%E5%9B%9E%E5%BA%94_%E5%87%A4%E5%87%B0%E8%B5%84%E8%AE%AF%26ari%3D2%26dbv%3D2%26drs%3D1%26pcs%3D1583x741%26pss%3D1583x2907%26cfv%3D0%26cpl%3D27%26chi%3D1%26cce%3Dtrue%26cec%3DUTF-8%26tlm%3D1498611951%26rw%3D741%26ltu%3Dhttp%3A/%3E%3E
vuin%3D943015753%26term%3D1%26srvver%3D26517%26rf%3Dnaio
"""

if __name__ == '__main__':
    url_split()
    # decode_files()

    # for l in url.split('\n'):
    #     print(l)
    #     # print(url_decode(l))
    #     line = unquote(l)
    #     print("*"*2)
    #     print(unescape(line))
    #     print("*"*2)
    #     print(url_decode(l))
    #     print("*"*8)
