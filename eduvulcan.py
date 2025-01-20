import requests
import json
import base64
import uuid
import hashlib
import re
import urllib
import sqlite3
import os
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.backends import default_backend
from bs4 import BeautifulSoup
from OpenSSL import crypto

session = requests.Session()

if __name__ == '__main__':
    debug = True
else:    
    debug = False

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

def savecredentials(filename, credentials):
    with open(filename, 'w') as file:
        json.dump(credentials, file, indent=4)

def encodebase64(data):
    return base64.b64encode(data.encode("utf-8")).decode("utf-8")

def decodebase64(data):
    return base64.b64decode(data.encode("utf-8")).decode("utf-8")

def load_credentials_from_file(filename):
    if not os.path.exists(filename):
        print(f"{filename} does not exist.")
        return None
    
    with open(filename, 'r') as file:
        credentials = json.load(file)
    
    decodeduser = decodebase64(credentials['login'])
    decodedpass = decodebase64(credentials['password'])
    return {"login": decodeduser, "password": decodedpass}

def getDebugInfo(data):
    data = json.loads(data)
    status = data.get("Status", {})
    code = status.get("Code")
    message = status.get("Message")
    return code, message

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

def JWTLogin(token, debug=False): 
    
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

    response = session.post(url, headers=headers, data=body_json)
    content = response.text

    if debug:
        dinfo = getDebugInfo(content)
        return content, dinfo
    
    return content

def HEBELogin(tenant, debug=False):
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

    if debug:
        dinfo = getDebugInfo(content)
        return content, dinfo
    
    return content

def getUserInfo(tenant):
    content = HEBELogin(tenant)

    data = json.loads(content)
    envelope = data.get("Envelope", [])[0]

    pupil = envelope.get("Pupil", {})
    unit = envelope.get("Unit", {})
    links = envelope.get("Links", {})
    ConstituentUnit = envelope.get("ConstituentUnit", {})
    periods = envelope.get("Periods", [])


    Name = pupil.get("FirstName", {})
    SecondName = pupil.get("SecondName", {})
    Surname = pupil.get("Surname", {})
    Class = envelope.get("ClassDisplay", {})
    PupilID = pupil.get("Id", {})
    SchoolID = links.get("Symbol", {})
    ConstituentID = ConstituentUnit.get("Id", {})
    UnitID = unit.get("Id", {})
    PeriodID = next((period.get('Id') for period in periods if period.get('Current')), None)

    return Name, SecondName, Surname, Class, PupilID, SchoolID, ConstituentID, UnitID, PeriodID

def getLuckyNumber(tenant, schoolid, pupilid, constituentid, debug=False):
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

    if debug:
        dinfo = getDebugInfo(content)
        return LuckyNumber, LuckyNumberDay, dinfo
    
    return LuckyNumber, LuckyNumberDay

def getGrades(tenant, schoolid, pupilid, unitid, periodid, debug=False):
    timestamp = datetime.now()
    date = timestamp.strftime("%Y-%m-%d") 
    url = f"https://lekcjaplus.vulcan.net.pl/{tenant}/{schoolid}/api/mobile/grade/byPupil?unitId={unitid}&pupilId={pupilid}&periodId={periodid}&lastSyncDate=1970-01-01%2001%3A00%3A00&lastId=-2147483648&pageSize=500"

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


    if debug:
        dinfo = getDebugInfo(content)
        return content, dinfo

    return content

def ImportGradesToSQLite(content):
    data = json.loads(content)

    conn = sqlite3.connect('grades.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS grades (
        id INTEGER PRIMARY KEY,
        pupil_id INTEGER,
        content_raw TEXT,
        content TEXT,
        value INTEGER,
        description TEXT,
        date_created TEXT,
        date_modified TEXT,
        creator_name TEXT,
        creator_surname TEXT,
        lesson_name TEXT,
        lesson_code TEXT,
        category_name TEXT,
        category_code TEXT
    )
    ''')

    for entry in data['Envelope']:
        column = entry.get('Column') or {} 
        subject = column.get('Subject') or {}
        category = column.get('Category') or {}
        creator = entry.get('Creator') or {}
        
        cursor.execute('''
        INSERT or IGNORE INTO grades (
            id, pupil_id, content_raw, content, value, description,
            date_created, date_modified, creator_name, creator_surname,
            lesson_name, lesson_code, category_name, category_code
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry.get('Id'),
            entry.get('PupilId'),
            entry.get('ContentRaw'),
            entry.get('Content'),
            entry.get('Value'),
            entry.get('Comment'),
            entry.get('DateCreated', {}).get('DateDisplay'),
            entry.get('DateModify', {}).get('DateDisplay'),
            creator.get('Name'),
            creator.get('Surname'),
            subject.get('Name'),
            subject.get('Kod'),
            category.get('Name'),
            category.get('Code')
        ))

    conn.commit()
    conn.close()

def get_current_week():
    # Get today's date
    today = datetime.today()
    # Calculate the start of the week (Monday)
    start_of_week = today - timedelta(days=today.weekday())
    # Calculate the end of the week (Sunday)
    end_of_week = start_of_week + timedelta(days=6)

    # Return the dates as formatted strings
    return start_of_week.strftime('%Y-%m-%d'), end_of_week.strftime('%Y-%m-%d')

def getTimetable(tenant, schoolid, pupilid, start_date, end_date, debug=False):
    url = f"https://lekcjaplus.vulcan.net.pl/{tenant}/{schoolid}/api/mobile/schedule/withchanges/byPupil?pupilId={pupilid}&dateFrom={start_date}&dateTo={end_date}&lastId=-2147483648&pageSize=500&lastSyncDate=1970-01-01%2001%3A00%3A00"
    signerurl = url
    body = None
    date1 = datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
    digest, canonical_url, signature = get_signature_values(fingerprint, private_key, body, signerurl, timestamp=datetime.now())

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

    if debug:
        dinfo = getDebugInfo(content)
        return content, dinfo

    return content

def ImportTimetableToSQLite(content):
    data = json.loads(content)

    conn = sqlite3.connect('timetable.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS timetable (
        id INTEGER PRIMARY KEY,
        date TEXT,
        start_time TEXT,
        end_time TEXT,
        subject_name TEXT,
        teacher_name TEXT,
        teacher_surname TEXT,
        room_code TEXT,
        class_display TEXT,
        position INTEGER
    )
    ''')

    for entry in data['Envelope']:
        cursor.execute('''
        INSERT OR IGNORE INTO timetable (
            id, date, start_time, end_time, subject_name, teacher_name, 
            teacher_surname, room_code, class_display, position
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry.get('Id'),
            entry.get('Date', {}).get('DateDisplay'),
            entry.get('TimeSlot', {}).get('Start'),
            entry.get('TimeSlot', {}).get('End'),
            entry.get('Subject', {}).get('Name'),
            entry.get('TeacherPrimary', {}).get('Name'),
            entry.get('TeacherPrimary', {}).get('Surname'),
            entry.get('Room', {}).get('Code'),
            entry.get('Clazz', {}).get('DisplayName'),
            entry.get('TimeSlot', {}).get('Position') or 0
        ))

    conn.commit()
    conn.close()

def getTimetableForDay(day):
    conn = sqlite3.connect('timetable.db')
    cursor = conn.cursor()

    def get_lessons_for_day_sorted(date):
        cursor.execute('SELECT * FROM timetable WHERE date = ? ORDER BY position ASC', (date,))
        lessons = cursor.fetchall()
        return lessons


    day_to_check = day
    lessons_for_day_sorted = get_lessons_for_day_sorted(day_to_check)


#    print(f"\nLessons for {day_to_check}:")
#    for lesson in lessons_for_day_sorted:
#        print(lesson)

    conn.close()

    return lessons_for_day_sorted

def getExams(tenant, schoolid, pupilid, start_date, end_date, debug=False):
    url = f"https://lekcjaplus.vulcan.net.pl/{tenant}/{schoolid}/api/mobile/exam/byPupil?pupilId={pupilid}&dateFrom={start_date}&dateTo={end_date}&lastId=-2147483648&pageSize=500&lastSyncDate=1970-01-01%2001%3A00%3A00"
    signerurl = url
    body = None
    date1 = datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
    digest, canonical_url, signature = get_signature_values(fingerprint, private_key, body, signerurl, timestamp=datetime.now())

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

    if debug:
        dinfo = getDebugInfo(content)
        return content, dinfo

    return content

def ImportExamsToSQLite(content):
    data = json.loads(content)
    
    conn = sqlite3.connect("exams.db")
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS exams (
        id INTEGER PRIMARY KEY,
        type TEXT,
        content TEXT,
        date_created TEXT,
        date_modified TEXT,
        deadline TEXT,
        creator_name TEXT,
        creator_surname TEXT,
        subject_name TEXT,
        pupil_id INTEGER
    )
    ''')

    for entry in data['Envelope']:
        cursor.execute('''
        INSERT OR IGNORE INTO exams (
            id, type, content, date_created, date_modified, deadline, 
            creator_name, creator_surname, subject_name, pupil_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry.get('Id'),
            entry.get('Type'),
            entry.get('Content'),
            entry.get('DateCreated', {}).get('DateDisplay'),
            entry.get('DateModify', {}).get('DateDisplay'),
            entry.get('Deadline', {}).get('DateDisplay'),
            entry.get('Creator', {}).get('Name'),
            entry.get('Creator', {}).get('Surname'),
            entry.get('Subject', {}).get('Name'),
            entry.get('PupilId')
        ))
    
    conn.commit()
    conn.close()

def getExamsForWeek(start_date, end_date):
    conn = sqlite3.connect("exams.db")
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT * FROM exams 
    WHERE deadline BETWEEN ? AND ?
    ORDER BY deadline ASC
    ''', (start_date, end_date))
    exams = cursor.fetchall()
    conn.close()
    return exams

if __name__ == '__main__':
    today = datetime.today().strftime('%d-%m-%y')
    start_date, end_date = get_current_week()

    filename = "credentials.json"

    print("Welcome to eduVulcan CLI")
    print("Github: https://github.com/Maarceeli/eduvulcan.py")
    print("Use at your own responsibility\n")
    
    
    if os.path.exists(filename):
        credentials = load_credentials_from_file(filename)

        login = credentials['login']
        password = credentials['password']

    if not os.path.exists(filename):
        print("Please provide your login and password")
        login = input("Login ")
        password = input("\nPassword ")
        
        q = int(input("Do you want to save your credentials for future use? 1 = Yes, 2 = No "))
        
        if q == 1:
            epass = encodebase64(password)
            euser = encodebase64(login)
            savecredentials("credentials.json", {"login": euser, "password": epass})

            print("Credentials saved")
        if q == 2:
            print("Credentials not saved")
        elif q != 1 and q != 2:
            print("Invalid input, not saving credentials")
    
    token = APILogin(login, password)
    tenant = get_tenant_from_jwt(token)
    content, dinfoJWT = JWTLogin(token, debug=debug)
    content, dinfoHEBE = HEBELogin(tenant, debug=debug)

    Name, SecondName, Surname, Class, PupilID, SchoolID, ConstituentID, UnitID, PeriodID = getUserInfo(tenant)
    print(Name, Surname, Class, PupilID, SchoolID, ConstituentID)

    LuckyNumber, LuckyNumberDay, dinfoLUCK = getLuckyNumber(tenant=tenant, schoolid=SchoolID, pupilid=PupilID, constituentid=ConstituentID, debug=debug)
    print(f"Lucky number: {LuckyNumber}")

    content, dinfoGRADE = getGrades(tenant=tenant, schoolid=SchoolID, pupilid=PupilID, unitid=UnitID, periodid=PeriodID, debug=debug)
    ImportGradesToSQLite(content)
    print("Grades imported to SQLite database")

    response, dinfoTIME = getTimetable(tenant=tenant, schoolid=SchoolID, pupilid=PupilID, start_date=start_date, end_date=end_date, debug=debug)
    
    ImportTimetableToSQLite(response)
    print("Timetable imported to SQLite database")

    r = getTimetableForDay(day=today)
    print(f"\nLessons for {today}:")
    
    if r == []:
        print("No lessons for today")
    else:
        for lesson in r:
            print(*lesson)

    content, dinfoEXAM = getExams(tenant=tenant, schoolid=SchoolID, pupilid=PupilID, start_date=start_date, end_date=end_date, debug=debug)

    ImportExamsToSQLite(content)
    print("Exams imported to SQLite database")

    exams = getExamsForWeek(start_date, end_date)
    for exam in exams:
        print(*exam)
    
    print(f"\nJWT Status: {dinfoJWT[0]} {dinfoJWT[1]}")
    print(f"HEBE Status: {dinfoHEBE[0]} {dinfoHEBE[1]}")
    print(f"Lucky Number Status: {dinfoLUCK[0]} {dinfoLUCK[1]}")
    print(f"Grades Status: {dinfoGRADE[0]} {dinfoGRADE[1]}")
    print(f"Timetable Status: {dinfoTIME[0]} {dinfoTIME[1]}")
    print(f"Exams Status: {dinfoEXAM[0]} {dinfoEXAM[1]}")