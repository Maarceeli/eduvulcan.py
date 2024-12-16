import requests
import json
import base64
import uuid
from datetime import datetime
from bs4 import BeautifulSoup
from uonet_request_signer_hebe import get_signature_values
from uonet_request_signer_hebe import generate_key_pair

login = " "
password = " "

def APILogin(login, password):
    session = requests.Session()
    
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

    return content

def get_tenant_from_jwt(jwt_token):
    try:
        # Split the JWT into parts
        header, payload, signature = jwt_token.split('.')

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

def Login(): 
    session = requests.Session()
    
    timestamp = datetime.now()
    formatted_date = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    date = timestamp.strftime("%a, %d %b %Y %H:%M:%S GMT") 
    
    
    response = APILogin(login, password)
    
    soup = BeautifulSoup(response, "html.parser")
    input_element = soup.find("input", {"id": "ap"})
    value = input_element["value"]
    parsed_json = json.loads(value)

    tokens = parsed_json.get("Tokens", [])
    tokens_string = " ".join(tokens)
    alias = parsed_json.get("Alias")
    email = parsed_json.get("Email")
    error_message = parsed_json.get("ErrorMessage")

    tenant = get_tenant_from_jwt(tokens_string)

    url = f"https://lekcjaplus.vulcan.net.pl/{tenant}/api/mobile/register/jwt"
    
    NotificationToken = None
    RequestId = getRandomIdentifier()  # Ensure this is a value (not a function)
    
    OS = "Android"
    certificate, fingerprint, private_key = generate_key_pair()
    Certificate = certificate
    CertificateThumbprint = fingerprint
    SelfIdentifier = getRandomIdentifier()  # Ensure this is a value (not a function)
    Tokens = tokens_string
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
    return response1, content1, response, content



response1 = APILogin(login, password)
response2 = Login()

#print(response1)
print(response2)

