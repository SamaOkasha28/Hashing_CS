#!/usr/bin/env python3

import re
import os
import requests
import concurrent.futures
from flask import Flask, request, jsonify

app = Flask(__name__)

# Colors and logging
end = '\033[0m'
red = '\033[91m'
green = '\033[92m'
white = '\033[97m'
dgreen = '\033[32m'
yellow = '\033[93m'
back = '\033[7;91m'
run = '\033[97m[~]\033[0m'
que = '\033[94m[?]\033[0m'
bad = '\033[91m[-]\033[0m'
info = '\033[93m[!]\033[0m'
good = '\033[92m[+]\033[0m'

thread_count = 4
result = {}

def alpha(hashvalue, hashtype):
    return False

def beta(hashvalue, hashtype):
    response = requests.get('https://hashtoolkit.com/reverse-hash/?hash=' + hashvalue).text
    match = re.search(r'/generate-hash/\?text=(.*?)"', response)
    if match:
        return match.group(1)
    else:
        return False

def gamma(hashvalue, hashtype):
    response = requests.get('https://www.nitrxgen.net/md5db/' + hashvalue, verify=False).text
    if response:
        return response
    else:
        return False

def delta(hashvalue, hashtype):
    return False

def theta(hashvalue, hashtype):
    response = requests.get('https://md5decrypt.net/Api/api.php?hash=%s&hash_type=%s&email=deanna_abshire@proxymail.eu&code=1152464b80a61728' % (hashvalue, hashtype)).text
    if len(response) != 0:
        return response
    else:
        return False

md5 = [gamma, alpha, beta, theta, delta]
sha1 = [alpha, beta, theta, delta]
sha256 = [alpha, beta, theta]
sha384 = [alpha, beta, theta]
sha512 = [alpha, beta, theta]

def identify_hash(hashvalue):
    """Identify the type of the given hash based on its length."""
    hash_length = len(hashvalue)
    if hash_length == 32:
        return 'md5', md5
    elif hash_length == 40:
        return 'sha1', sha1
    elif hash_length == 64:
        return 'sha256', sha256
    elif hash_length == 96:
        return 'sha384', sha384
    elif hash_length == 128:
        return 'sha512', sha512
    else:
        return None, None

def crack(hashvalue):
    hashtype, apis = identify_hash(hashvalue)
    if not hashtype:
        return None, 'Unsupported hash length'

    for api in apis:
        try:
            result = api(hashvalue, hashtype)
            if result:
                return result, None
        except Exception as e:
            return None, f'Error executing API: {str(e)}'
    return None, 'Hash not found in any database'

def threaded(hashvalue):
    resp, error = crack(hashvalue)
    if resp:
        result[hashvalue] = resp

def grepper(directory):
    hash_pattern = re.compile(r'[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{96}|[a-f0-9]{128}')
    found_hashes = set()
    for root, dirs, files in os.walk(directory):
        for file in files:
            if not file.endswith(('.png', '.jpg', '.jpeg', '.mp3', '.mp4', '.zip', '.gz')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        contents = f.read()
                        matches = hash_pattern.findall(contents)
                        if matches:
                            found_hashes.update(matches)
                except Exception as e:
                    print(f'{bad} Error reading file {file_path}: {e}')
    
    result_file = os.path.join(os.getcwd(), f'{os.path.basename(directory)}.txt')
    with open(result_file, 'w') as f:
        for hash_value in found_hashes:
            f.write(f'{hash_value}\n')
    
    return f'Results saved in {result_file}'

def miner(file, thread_count):
    lines = []
    found = set()
    with open(file, 'r') as f:
        for line in f:
            lines.append(line.strip('\n'))
    for line in lines:
        matches = re.findall(r'[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}', line)
        if matches:
            for match in matches:
                found.add(match)
    threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=thread_count)
    futures = (threadpool.submit(threaded, hashvalue) for hashvalue in found)
    for _ in concurrent.futures.as_completed(futures):
        pass
    return {hashvalue: result[hashvalue] for hashvalue in found if hashvalue in result}

@app.route('/crack_single', methods=['POST'])
@app.route('/crack_single', methods=['POST'])
def crack_single():
    data = request.json
    hashvalue = data.get('hash')
    if not hashvalue:
        return jsonify({'error': 'No hash provided'}), 400
    
    hashtype, _ = identify_hash(hashvalue)
    if not hashtype:
        return jsonify({'error': 'Unsupported hash length'}), 400
    
    result, error = crack(hashvalue)
    if result:
        return jsonify({'hash': hashvalue, 'hash_type': hashtype, 'result': result})
    else:
        return jsonify({'error': error}), 404


@app.route('/crack_file', methods=['POST'])
def crack_file():
    data = request.json
    file_path = data.get('file_path')
    thread_count = data.get('thread_count', 4)
    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'Invalid file path'}), 400
    results = miner(file_path, thread_count)
    return jsonify(results)

@app.route('/crack_directory', methods=['POST'])
def crack_directory():
    data = request.json
    directory = data.get('directory')
    if not directory or not os.path.exists(directory):
        return jsonify({'error': 'Invalid directory path'}), 400
    result_message = grepper(directory)
    return jsonify({'message': result_message})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)