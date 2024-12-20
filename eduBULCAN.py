import requests
import json
import base64
import uuid
import hashlib
import re
import urllib
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.backends import default_backend
from bs4 import BeautifulSoup
from OpenSSL import crypto

session = requests.Session()

login = input("Login ")
password = input("\nPassword ")

# Start of signer functions

def get_encoded_path(full_url):
    path = re.search(r"(api/mobile/.+)", full_url)
    if path is None:
        raise ValueError(
            "The URL does not seem correct (does not match `(api/mobile/.+)` regex)"
        )
    return urllib.parse.quote(path[1], safe="").lower()

def get_digest(body):
    if not body:
        return None

    m = hashlib.sha256()
    m.update(bytes(body, "utf-8"))
    return base64.b64encode(m.digest()).decode("utf-8")

def get_headers_list(body, digest, canonical_url, timestamp):
    sign_data = [
        ["vCanonicalUrl", canonical_url],
        ["Digest", digest] if body else None,
        ["vDate", timestamp.strftime("%a, %d %b %Y %H:%M:%S GMT")],
    ]

    return (
        " ".join(item[0] for item in sign_data if item),
        "".join(item[1] for item in sign_data if item),
    )

def get_signature(data, private_key):
    # Convert data to a string representatio
    data_str = (
        json.dumps(data)
        if isinstance(data, (dict, list))
        else str(data)
    )
    
    # Decode the base64 private key and load it
    private_key_bytes = base64.b64decode(private_key)
    pkcs8_key = load_der_private_key(private_key_bytes, password=None, backend=default_backend())
    
    # Sign the data
    signature = pkcs8_key.sign(
        bytes(data_str, "utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    # Encode the signature in base64 and return
    return base64.b64encode(signature).decode("utf-8")

def get_signature_values(fingerprint, private_key, body, full_url, timestamp):
    canonical_url = get_encoded_path(full_url)
    digest = get_digest(body)
    headers, values = get_headers_list(body, digest, canonical_url, timestamp)
    signature = get_signature(values, private_key)

    return (
        "SHA-256={}".format(digest) if digest else None,
        canonical_url,
        'keyId="{}",headers="{}",algorithm="sha256withrsa",signature=Base64(SHA256withRSA({}))'.format(
            fingerprint, headers, signature
        ),
    )

def pem_getraw(pem):
    return pem.decode("utf-8").replace("\n", "").split("-----")[2]

def generate_key_pair():
    pkcs8 = crypto.PKey()
    pkcs8.generate_key(crypto.TYPE_RSA, 2048)

    x509 = crypto.X509()
    x509.set_version(2)
    x509.set_serial_number(1)
    subject = x509.get_subject()
    subject.CN = "APP_CERTIFICATE CA Certificate"
    x509.set_issuer(subject)
    x509.set_pubkey(pkcs8)
    x509.sign(pkcs8, "sha256")
    x509.gmtime_adj_notBefore(0)
    x509.gmtime_adj_notAfter(20 * 365 * 24 * 60 * 60)

    certificate = pem_getraw(crypto.dump_certificate(crypto.FILETYPE_PEM, x509))
    fingerprint = x509.digest("sha1").decode("utf-8").replace(":", "").lower()
    private_key = pem_getraw(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkcs8))

    return certificate, fingerprint, private_key

# End of signer functions

certificate, fingerprint, private_key = generate_key_pair()

def APILogin(login, password):
    
    url = "https://eduvulcan.pl/"
    response1 = session.get(url)

    url = "https://eduvulcan.pl/logowanie"
    response2 = session.get(url)

    soup = BeautifulSoup(response2.text, 'html.parser')
    token_input = soup.find('input', {'name': '__RequestVerificationToken'})
    token = {"__RequestVerificationToken": token_input['value']}

    # Combine all cookies into a single string format for the Cookie header
    cookies = {**response1.cookies.get_dict(), **response2.cookies.get_dict()}
    cookies_str = "; ".join([f"{key}={value}" for key, value in cookies.items()])
    cookies_str += f"; __RequestVerificationToken={token_input['value']}"

    # Prometheus
    url = "https://eduvulcan.pl/logowanie?ReturnUrl=%2fapi%2fap"
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": cookies_str,  # Use the formatted cookies string here
        "Host": "eduvulcan.pl",
        "Origin": "https://eduvulcan.pl",
        "Referer": "https://eduvulcan.pl/logowanie?ReturnUrl=%2fapi%2fap",
        "sec-ch-ua": "\"Chromium\";v=\"130\", \"Android WebView\";v=\"130\", \"Not?A_Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": "\"Android\"",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; SM-G935F Build/TQ3A.230901.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.6723.107 Mobile Safari/537.36",
        "X-Requested-With": "pl.edu.vulcan.hebe.ce",
    }

    data = {
        "Alias": login,
        "Password": password,
        "captchaUser": "",
        "__RequestVerificationToken": token_input['value'],  # Use the actual token value here
    }

    response = session.post(url, headers=headers, data=data)
    content = response.text
    cookie_jar = response.cookies.get_dict()

    soup = BeautifulSoup(content, "html.parser")
    input_element = soup.find("input", {"id": "ap"})
    value = input_element["value"]
    parsed_json = json.loads(value)

    tokens = parsed_json.get("Tokens", [])
    token = " ".join(tokens)

    return token

def get_tenant_from_jwt(token):
    try:
        # Split the JWT into parts
        header, payload, signature = token.split('.')

        # Decode the payload from Base64
        # Add padding 
        payload += '=' * (-len(payload) % 4)
        decoded_payload = base64.urlsafe_b64decode(payload).decode('utf-8')

        # Parse the payload as JSON
        payload_json = json.loads(decoded_payload)

        # Return the tenant
        return payload_json.get('tenant')
    except (ValueError, json.JSONDecodeError, KeyError) as e:
        print(f"Error decoding JWT: {e}")
        return None

def getCurrentTimestamp():
    now = datetime.now()
    Timestamp = int(now.timestamp())

    return Timestamp

def getRandomIdentifier():
    ruuid = str(uuid.uuid4())

    return ruuid

def JWTLogin(token): 
    
    timestamp = datetime.now()
    date = timestamp.strftime("%a, %d %b %Y %H:%M:%S GMT") 
    tenant = get_tenant_from_jwt(token)

    url = f"https://lekcjaplus.vulcan.net.pl/{tenant}/api/mobile/register/jwt"
    
    NotificationToken = None
    RequestId = getRandomIdentifier()  # Ensure this is a value (not a function)
    
    OS = "Android"
    Certificate = certificate
    CertificateThumbprint = fingerprint
    SelfIdentifier = getRandomIdentifier()  # Ensure this is a value (not a function)
    Tokens = token
    DeviceModel = "SM-G935F"

    signerurl = url
    signerbody = None
    digest, canonical_url, signature = get_signature_values(fingerprint, private_key, signerbody, signerurl, timestamp)

    headers = {
        "accept-encoding": "gzip",
        "content-type": "application/json",
        "host": "lekcjaplus.vulcan.net.pl",
        "signature": signature,
        "user-agent": "Dart/3.3 (dart:io)",
        "vapi": "1",
        "vcanonicalurl": "api%2fmobile%2fregister%2fjwt",
        "vdate": date,
        "vos": "Android",
        "vversioncode": "640",
    }


    bodytimestamp = getCurrentTimestamp()

    body = {
        "AppName": "DzienniczekPlus 3.0",
        "AppVersion": "24.11.07 (G)",
        "NotificationToken": str(NotificationToken) if NotificationToken else None,
        "API": 1,
        "RequestId": str(RequestId),  # Ensure RequestId is serializable
        "Timestamp": bodytimestamp,
        "TimestampFormatted": date,
        "Envelope": {
            "OS": OS,
            "Certificate": Certificate,
            "CertificateType": "X509",
            "DeviceModel": DeviceModel,
            "SelfIdentifier": str(SelfIdentifier),  # Ensure serializability
            "CertificateThumbprint": CertificateThumbprint,
            "Tokens": [Tokens]
        }
    }

    body_json = json.dumps(body, indent=4)

    response1 = session.post(url, headers=headers, data=body_json)
    content1 = response1.text

    return content1

def HEBELogin(tenant):
    url = f"https://lekcjaplus.vulcan.net.pl/{tenant}/api/mobile/register/hebe?mode=2&lastSyncDate=1970-01-01%2001%3A00%3A00"
    signerurl = f"https://lekcjaplus.vulcan.net.pl/{tenant}/api/mobile/register/hebe?mode=2&lastSyncDate=1970-01-01%2001%3A00%3A00"
    body = None
    timestamp1 = datetime.now()
    date1 = timestamp1.strftime("%a, %d %b %Y %H:%M:%S GMT")
    digest, canonical_url, signature = get_signature_values(fingerprint, private_key, body, signerurl, timestamp=timestamp1)

    headers = {
        "accept-encoding": "gzip",
        "content-type": "application/json",
        "host": "lekcjaplus.vulcan.net.pl",
        "signature": signature,
        "user-agent": "Dart/3.3 (dart:io)",
        "vapi": "1",
        "vcanonicalurl": canonical_url,
        "vdate": date1,
        "vos": "Android",
        "vversioncode": "640",
    }

    response = requests.get(url, headers=headers)
    content = response.text
    return response, content

def getUserInfo(tenant):
    response, content = HEBELogin(tenant)

    data = json.loads(content)
    envelope = data.get("Envelope", [])[0]

    pupil = envelope.get("Pupil", {})
    unit = envelope.get("Unit", {})
    links = envelope.get("Links", {})
    ConstituentUnit = envelope.get("ConstituentUnit", {})

    Name = pupil.get("FirstName", {})
    SecondName = pupil.get("SecondName", {})
    Surname = pupil.get("Surname", {})
    Class = envelope.get("ClassDisplay", {})
    PupilID = pupil.get("Id", {})
    SchoolID = links.get("Symbol", {})
    ConstituentID = ConstituentUnit.get("Id", {})

    return Name, SecondName, Surname, Class, PupilID, SchoolID, ConstituentID

def getLuckyNumber(tenant, schoolid, pupilid, constituentid):
    timestamp = datetime.now()
    date = timestamp.strftime("%Y-%m-%d") 
    url = f"https://lekcjaplus.vulcan.net.pl/{tenant}/{schoolid}/api/mobile/school/lucky?pupilId={pupilid}&constituentId={constituentid}&day={date}"
    
    signerurl = url
    body = None
    date1 = timestamp.strftime("%a, %d %b %Y %H:%M:%S GMT")
    digest, canonical_url, signature = get_signature_values(fingerprint, private_key, body, signerurl, timestamp=timestamp)

    headers = {
        "accept-encoding": "gzip",
        "content-type": "application/json",
        "host": "lekcjaplus.vulcan.net.pl",
        "signature": signature,
        "user-agent": "Dart/3.3 (dart:io)",
        "vapi": "1",
        "vcanonicalurl": canonical_url,
        "vdate": date1,
        "vos": "Android",
        "vversioncode": "640",
    }

    response = requests.get(url, headers=headers)
    content = response.text

    data = json.loads(content)
    Envelope = data.get("Envelope", {})
    
    LuckyNumberDay = Envelope.get("Day", {})
    LuckyNumber = Envelope.get("Number", {})

    return LuckyNumber, LuckyNumberDay



token = APILogin(login, password)
tenant = get_tenant_from_jwt(token)
response2 = JWTLogin(token)
#response3 = HEBELogin(tenant)

#print(response1)
#print(response2)
#print(response3)
Name, SecondName, Surname, Class, PupilID, SchoolID, ConstituentID = getUserInfo(tenant)
print(Name, Surname, Class, PupilID, SchoolID, ConstituentID)
LuckyNumber, LuckyNumberDay = getLuckyNumber(tenant=tenant, schoolid=SchoolID, pupilid=PupilID, constituentid=ConstituentID)
print(f"Lucky number: {LuckyNumber}")

