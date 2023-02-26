import os

class Conf(object):
    # remote server address where server.py is running, used only by client_builder.py
    SERVER_ADDR = '127.0.0.1'
    BUFF_SIZE = 0x200
    SERVER_DIR_PATH = os.path.dirname(os.path.realpath(__file__))
    CERT_DIR_PATH = SERVER_DIR_PATH
    CERT_NAME = 'server'

    # host/port to listen for client connections
    CLIENT_HOST = '0.0.0.0'
    CLIENT_PORT = 28115

    # host/port for main server process IPC
    MANAGER_HOST = '127.0.0.1'
    MANAGER_PORT = 21377

    # host and port range for child server process IPC
    MAPPER_HOST = '127.0.0.1'
    MAPPER_PORT_MIN = 30000
    MAPPER_PORT_MAX = 60000

    CLIENT_VERSION = 2
    CLIENT_TIMEOUT = 120 # in seconds

    LOG_DIR_PATH = os.path.join(SERVER_DIR_PATH, 'logs')
    DOWNLOADS_DIR_PATH = os.path.join(SERVER_DIR_PATH, 'downloads')

    LOG_PATH_SERVER = os.path.join(SERVER_DIR_PATH, 'server.log')
    LOG_PATH_ACCESS = os.path.join(SERVER_DIR_PATH, 'access.log')

    PGID_FILE_PATH = os.path.join(SERVER_DIR_PATH, 'server.pgid')

    TIME_FORMAT = '%m/%d/%y %I:%M:%S %p'
    VERBOSE = False