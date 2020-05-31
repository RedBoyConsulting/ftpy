import os, sys, socket
from socket import _GLOBAL_DEFAULT_TIMEOUT
#Listado de respuestas server/cliente
#'USER' : [331]
#'PASS' : [230]
#'CONN' : [220]
#'PWD'  : [257]
#'CWD'  : [250]
#'RMD'  : [250]
#'MKD'  : [257]
#'LIST' : [150,226]
#'RETR' : [150,226]
#'STOR' : [150,226]
#'PASV' : [227]
#'QUIT' : [221]
#'DELE' : [250]
              

'''Pasa errores de cosas que hayamos programado.'''
class Error(Exception): pass

'''Pasa errores de servidor a cliente (serverresponseuesta)'''
class error_reply(Error): pass

'''Pasa errores de servidor a cliente y cliente a servidor (Tiempo)'''
class error_temp(Error): pass

'''Pasa errores de teclado "Capa 8, entre el teclado y el usuario XD¡¡" '''
all_errors = (Error, IOError, EOFError)

class SEAK:
    def ip_searching(host_ip):
        try:
            print('Escribe la dirección de la cual deseas saber la ip ')
            adress = input('>>')
            host_ip = socket.gethostbyname(adress)
            print(host_ip)
        except socket.gaierror:
            print('No se pudo comunicar con el host...\n')
            pass

class clienteftp:
    '''Funciones predefinidas'''
    #Comienza en cero por que se conecta "execute lvl:0" siempre.
    debugging = 0
    #Comienza en cero por que se conecta "execute lvl:1" siempre.
    passiveserver = 1
    #Yo tengo un teclado latino, pero si tu no, cambialo a UTF-8.
    encoding = "latin-1"
    #Definelo con la cantidad de byts que quieras.
    buffer_size = 1502
    #Creación de instancias para conectar y registrar entrada.
    def __init__(roadrunner, host='', user='', passwd='', timeout=9999, source_address=None):
        roadrunner.source_address = source_address
        roadrunner.timeout = timeout
        if host:
            roadrunner.connect(host)
            if user:
                roadrunner.login(user, passwd)
    #Imprime el directorio de la máquina local.
    def acp(roadrunner):
        return roadrunner.sendusrcomand('!LIST')
    #Imprime el directorio actual.
    def pwd(roadrunner):
        return roadrunner.sendusrcomand('PWD')
    #Comando de cambio de directorio.
    def cd(roadrunner, path):
        return roadrunner.sendusrcomand('CWD ' + path)
        print ('Ok')
    #Función que permite navegar en los 3 niveles de debuggeo.
    def set_debuglevel(roadrunner, level):
        roadrunner.debugging = level
        debug = set_debuglevel
    #Función que interactua con cliente y servidor (Envío de comandos)
    def voidusrcomand(roadrunner, usrcomand):
        roadrunner.putusrcomand(usrcomand)
        return roadrunner.voidserverresponse()
    #Función que envía todos los comandos del programa.
    def sendusrcomand(roadrunner, usrcomand):
        roadrunner.putusrcomand(usrcomand)
        return roadrunner.getserverresponse()
    #Intercambio de comando cliente servidor.
    def transferusrcomand(roadrunner, usrcomand, rest=None):
        return roadrunner.ntransferusrcomand(usrcomand, rest)[0]
    #Envía lin@@@@ qeas de cliente a servidor.
    def putline(roadrunner, line):
        line = line + '\r\n'
        if roadrunner.debugging > 1: print('*put*', roadrunner.pasarerrores(line))
        roadrunner.sock.sendall(line.encode(roadrunner.encoding))
    #Envía comandos de cliente a servidor.
    def putusrcomand(roadrunner, line):
        if roadrunner.debugging: print('*usrcomand*', roadrunner.pasarerrores(line))
        roadrunner.putline(line)
    #Lee archivos y mensajes de servidor a cliente.
    def getline(roadrunner):
        line = roadrunner.file.readline(roadrunner.buffer_size + 1)
        if len(line) > roadrunner.buffer_size:
            raise Error("got more than %d bytes" % roadrunner.buffer_size)
        if roadrunner.debugging > 1:
            print('*get*', roadrunner.pasarerrores(line))
        if not line: raise EOFError
        if line[-2:] == '\r\n': line = line[:-2]
        elif line[-1:] in '\r\n': line = line[:-1]
        return line
    #Crear directorio
    def mkd(roadrunner, dirname):
        serverresponse = roadrunner.voidusrcomand('MKD ' + dirname)
        if not serverresponse.startswith('257'):
                if serverresponse[:3] != '257':
                    raise error_reply(serverresponse)
                if serverresponse[3:5] != ' "':
                    return '' 
                    dirname = ''
                    i = 5
                    n = len(serverresponse)
                    while i < n:
                        c = serverresponse[i]
                        i = i+1
                        dirname = dirname + c
                        return dirname
    #Remover directorio.
    def rmd(roadrunner, dirname):
        return roadrunner.voidusrcomand('RMD ' + dirname)
    '''Funciones predefinidas'''
    
    '''Conexión, desconexión, registro de entrada, bienvenida'''
    #Genera la conexión.
    def connect(roadrunner, host='', port=21, timeout=-999, source_address=None):
        if host:
            roadrunner.host = host
        if port:
            roadrunner.port = port
        if timeout != -999:
            roadrunner.timeout = timeout
        if source_address:
            roadrunner.source_address = source_address
        roadrunner.sock = socket.create_connection((roadrunner.host, roadrunner.port), roadrunner.timeout,
                                             source_address=roadrunner.source_address)
        roadrunner.af = roadrunner.sock.family
        roadrunner.file = roadrunner.sock.makefile('r', encoding=roadrunner.encoding)
        roadrunner.welcome = roadrunner.getserverresponse()
        return roadrunner.welcome
    #Cierra la conexión.
    def quit(roadrunner):
        serverresponse = roadrunner.voidusrcomand('QUIT')
        roadrunner.file.close()
        roadrunner.sock.close()
        roadrunner.file = roadrunner.sock = None
        return serverresponse
    #Manda el usuario y la contraseña.
    def login(roadrunner, user = '', passwd = ''):
        serverresponse = roadrunner.sendusrcomand('USER ' + user)
        if serverresponse[0] == '3': serverresponse = roadrunner.sendusrcomand('PASS ' + passwd)
        if serverresponse[0] != '2':
             raise error_reply(serverresponse)
        return serverresponse
    #Recibe el permiso de entrada al servidor.
    def getwelcome(roadrunner):
        if roadrunner.debugging:
            print('*welcome*', roadrunner.pasarerrores(roadrunner.welcome))
        return roadrunner.welcome
    '''Conexión, desconexión, registro de entrada, bienvenida'''

    '''Comunicación de teclado cliente a servidor.'''
    #Obtiene objetos del servidor al cliente, siempre y cuando sean binarios, NO ADMITE IMAGENES
    def retrbinary(roadrunner, usrcomand, callback, bufferf_size=8192, rest=None):
        roadrunner.voidusrcomand('TYPE I')
        with roadrunner.transferusrcomand(usrcomand, rest) as conn:
            while 1:
                data = conn.recv(bufferf_size)
                if not data:
                    break
                callback(data)
        return roadrunner.voidserverresponse() 
    #Recuperar texto del servidor al cliente.
    def recoil(roadrunner, usrcomand, callback = None):
        if callback is None: callback = print_line
        serverresponse = roadrunner.sendusrcomand('TYPE A')
        with roadrunner.transferusrcomand(usrcomand) as conn, \
                 conn.makefile('r', encoding=roadrunner.encoding) as fp:
            while 1:
                line = fp.readline(roadrunner.buffer_size + 1)
                if len(line) > roadrunner.buffer_size:
                    raise Error("got more than %d bytes" % roadrunner.buffer_size)
                if roadrunner.debugging > 2: print('*retr*', repr(line))
                if not line:
                    break
                if line[-2:] == '\r\n':
                    line = line[:-2]
                elif line[-1:] == '\n':
                    line = line[:-1]
                callback(line)
        return roadrunner.voidserverresponse()
    #Subir archivos del cliente al servidor.
    def storbinary(roadrunner, usrcomand, fp, bufferf_size=8192, callback=None, rest=None):
        roadrunner.voidusrcomand('TYPE I')
        with roadrunner.transferusrcomand(usrcomand, rest) as conn:
            while 1:
                buf = fp.read(bufferf_size)
                if not buf: break
                conn.sendall(buf)
                if callback: callback(buf)
        return roadrunner.voidserverresponse()
    '''Comunicación de teclado cliente a servidor.'''
    
    '''Cambiar conexión, pasar errores'''
    #Llama al modo pasivo.
    def set_pasv(roadrunner, val):
        roadrunner.passiveserver = val
    #Función predefinida para pasar errores.
    def voidserverresponse(roadrunner):
        serverresponse = roadrunner.getserverresponse()
        if serverresponse[:1] != '2':
            raise error_reply(serverresponse)
        return serverresponse
    #Llama la serverresponseuesta para pasar errores.
    def pasarerrores(roadrunner, s):
        if s[:5] in {'pass ', 'PASS '}:
            i = len(s.rstrip('\r\n'))
            s = s[:5] + '*'*(i-5) + s[i:]
        return repr(s)
    #serverresponseonde con pasar por alto errores.
    def getserverresponse(roadrunner):
        serverresponse = roadrunner.getmultiline()
        if roadrunner.debugging: print('*serverresponse*', roadrunner.pasarerrores(serverresponse))
        roadrunner.lastserverresponse = serverresponse[:3]
        c = serverresponse[:1]
        if c in {'1', '2', '3'}:
            return serverresponse
        if c == '4':
            raise error_temp(serverresponse)
        if c == '5':
            raise error_perm(serverresponse)
        raise error_proto(serverresponse)
    '''Cambiar conexión, pasar errores'''

    '''Manejo de archivos'''
    #renombrar archivos.
    def rename(roadrunner, fromname, toname):
        serverresponse = roadrunner.sendusrcomand('RNFR ' + fromname)
        if serverresponse[0] != '3':
            raise error_reply(serverresponse)
        return roadrunner.voidusrcomand('RNTO ' + toname)
    #Borrar archivos.
    def delete(roadrunner, filename):
        serverresponse = roadrunner.sendusrcomand('DELE ' + filename)
        if serverresponse[:3] in {'250', '200'}:
            return serverresponse
        else:
            raise error_reply(serverresponse)
    #Define la talla de archivos
    def size(roadrunner, filename):
        serverresponse = roadrunner.sendusrcomand('SIZE ' + filename)
        if serverresponse[:3] == '213':
            s = serverresponse[3:].strip()
            return int(s)
    '''Manejo de archivos'''

    '''Manejo de instancia automáticas de respuesta cliente/servidor'''
    #Obtiene las lineas del servidor al cliente.
    def getmultiline(roadrunner):
        line = roadrunner.getline()
        if line[3:4] == '-':
            code = line[:3]
            while 1:
                nextline = roadrunner.getline()
                line = line + ('\n' + nextline)
                if nextline[:3] == code and \
                        nextline[3:4] != '-':
                    break
        return line
    #Envía el puerto.
    def sendport(roadrunner, host, port):
        hbytes = host.split('.')
        pbytes = [repr(port//256), repr(port%256)]
        bytes = hbytes + pbytes
        usrcomand = 'PORT ' + ','.join(bytes)
        return roadrunner.voidusrcomand(usrcomand)
    #Decide la conexión del puerto.
    def sendeprt(roadrunner, host, port):
        err = None
        sock = None
        for res in socket.getaddrinfo(None, 0, roadrunner.af, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
            af, socktype, proto, canonname, sa = res
            try:
                sock = socket.socket(af, socktype, proto)
                sock.bind(sa)
            except socket.error as _:
                err = _
                if sock:
                    sock.close()
                sock = None
                continue
            break
        if sock is None:
            if err is not None:
                raise err
            else:
                raise socket.error("getaddrinfo returns an empty list")
            raise socket.error(msg)
        sock.listen(1)
        port = sock.getsockname()[1]
        host = roadrunner.sock.getsockname()[0]
        if roadrunner.af == socket.AF_INET:
            serverresponse = roadrunner.sendport(host, port)
        else:
            serverresponse = roadrunner.sendeprt(host, port)
        if roadrunner.timeout is not _GLOBAL_DEFAULT_TIMEOUT:
            sock.settimeout(roadrunner.timeout)
        af = 0
        if roadrunner.af == socket.AF_INET:
            af = 1
        if roadrunner.af == socket.AF_INET6:
            af = 2
        if af == 0:
            raise error_proto('unsupported address family')
        fields = ['', repr(af), host, repr(port), '']
        usrcomand = 'EPRT ' + '|'.join(fields)
        return roadrunner.voidusrcomand(usrcomand)
    #Crea una conexión pasiva si la conexión normal esta saturada.
    def makepasv(roadrunner):
        if roadrunner.af == socket.AF_INET:
            host, port = parse227(roadrunner.sendusrcomand('PASV'))
        else:
            host, port = parse229(roadrunner.sendusrcomand('EPSV'), roadrunner.sock.getpeername())
        return host, port
    #Hace switch de los puertos al enviar los comandos del cliente en base a la saturación de los puerto.
    def ntransferusrcomand(roadrunner, usrcomand, rest=None):
        size = None
        if roadrunner.passiveserver:
            host, port = roadrunner.makepasv()
            conn = socket.create_connection((host, port), roadrunner.timeout,
                                            source_address=roadrunner.source_address)
            try:
                if rest is not None:
                    roadrunner.sendusrcomand("REST %s" % rest)
                serverresponse = roadrunner.sendusrcomand(usrcomand)
                if serverresponse[0] == '2':
                    serverresponse = roadrunner.getserverresponse()
                if serverresponse[0] != '1':
                    raise error_reply(serverresponse)
            except:
                conn.close()
                raise
        else:
            with roadrunner.makeport() as sock:
                if rest is not None:
                    roadrunner.sendusrcomand("REST %s" % rest)
                serverresponse = roadrunner.sendusrcomand(usrcomand)
                if serverresponse[0] == '2':
                    serverresponse = roadrunner.getserverresponse()
                if serverresponse[0] != '1':
                    raise error_reply(serverresponse)
                conn, sockaddr = sock.accept()
                if roadrunner.timeout is not _GLOBAL_DEFAULT_TIMEOUT:
                    conn.settimeout(roadrunner.timeout)
        if serverresponse[:3] == '150':
            size = parse150(serverresponse)
        return conn, size
    #Cacha las lineas ingresadas por el tecladod el usuario.
    def storlines(roadrunner, usrcomand, fp, callback=None):
        roadrunner.voidusrcomand('TYPE A')
        with roadrunner.transferusrcomand(usrcomand) as conn:
            while 1:
                buf = fp.readline(roadrunner.buffer_size + 1)
                if len(buf) > roadrunner.buffer_size:
                    raise Error("got more than %d bytes" % roadrunner.buffer_size)
                if not buf: break
                if buf[-2:] != b'\r\n':
                    if buf[-1] in b'\r\n': buf = buf[:-1]
                    buf = buf +b'\r\n'
                conn.sendall(buf)
                if callback: callback(buf)
        return roadrunner.voidserverresponse()
    '''Manejo de instancia automáticas de respuesta cliente/servidor'''
    
'''Supresión de errores conocidos en el sistema.'''
_150_re = None
def parse150(serverresponse):
    if serverresponse[:3] != '150':
        raise error_reply(serverresponse)
    global _150_re
    if _150_re is None:
        import re
        _150_re = re.compile(
            "150 .* \((\d+) bytes\)", re.IGNORECASE | re.ASCII)
    m = _150_re.match(serverresponse)
    if not m:
        return None
    return int(m.group(1))
_227_re = None
def parse227(serverresponse):
    if serverresponse[:3] != '227':
        raise error_reply(serverresponse)
    global _227_re
    if _227_re is None:
        import re
        _227_re = re.compile(r'(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)', re.ASCII)
    m = _227_re.search(serverresponse)
    if not m:
        raise error_proto(serverresponse)
    numbers = m.groups()
    host = '.'.join(numbers[:4])
    port = (int(numbers[4]) << 8) + int(numbers[5])
    return host, port
'''Supresión de errores conocidos en el sistema.'''
    #Función que imprime todo de servidor a cliente.
def print_line(line):
    print(line)
    '''SSL
try:
    import ssl
except ImportError:
    pass
else:
    class clienteftps(clienteftp):
        ssl_version = ssl.PROTOCOL_TLSv1

def __init__(roadrunner, host='', user='', passwd='', keyfile=None, certfile=None, context=None, timeout=999, source_address=None):
    if context is not None and keyfile is not None:
        raise ValueError("context and keyfile arguments are mutually exclusive")
    if context is not None and certfile is not None:
        raise ValueError("context and certfile arguments are mutually exclusive")
        roadrunner.keyfile = keyfile
        roadrunner.certfile = certfile
        roadrunner.context = context
        roadrunner._prot_p = False
        FTP.__init__(self, host, user, passwd, timeout, source_address)

def login(roadrunner, user='', passwd='', secure=True):
    if secure and not isinstance(roadrunner.sock, ssl.SSLSocket):
        roadrunner.auth()
        return clienteftp.login(roadrunner, user, passwd)

def auth(roadrunner):
    if isinstance(roadrunner.sock, ssl.SSLSocket):
        raise ValueError("Already using TLS")
    if roadrunner.ssl_version == ssl.PROTOCOL_TLSv1:
        serverresponse = roadrunner.voidusrcomand('AUTH TLS')
    else:
        serverresponse = roadrunner.voidusrcomand('AUTH SSL')
    if roadrunner.context is not None:
        roadrunner.sock = roadrunner.context.wrap_socket(roadrunner.sock)
    else:
        roadrunner.sock = ssl.wrap_socket(roadrunner.sock, roadrunner.keyfile, roadrunner.certfile, ssl_version=self.ssl_version)
        roadrunner.file = roadrunner.sock.makefile(mode='r', encoding=roadrunner.encoding)
        return serverresponse
    SSL'''
if __name__ == '__main__':
        search = SEAK()
        option = int(1)
        while option == 1:
            print('\n---------------------\nCliente FTP\n---------------------\n')
            print('<---Elija un módulo--->')
            print('1.- Buscar IP')
            print('2.- Utilizar clienteftp')
            print('3.- Quick test')
            print('4.- Documentación')
            print('5.- Conecta SSL')
            print('6.- Salir')
            option = int(input('>>'))
            if option == 1:
                search.ip_searching()
            if option == 2:
                clienteftp = clienteftp(input('Host>>'))
                clienteftp.login(input('User>>'),input('Password>>'))
            if option == 3:
                clienteftp = clienteftp(input('Host>>'))
                clienteftp.login(input('User>>'),input('Password>>'))
                print('Para subir un archivo utiliza el comando STOR test_drive.txt, presiona enter y enseguida vuelve a escribir test_drive.txt')
                clienteftp.storbinary(input('\n>>'), open(input('\n>>'), 'rb'))
                print('Para renombrar el archivo escribe lo siguiente.')             
                clienteftp.rename(input('Escribe el nombre del archivo a renombrar>>'),input('Escribe el nombre que quieres que tenga el archivo>>'))
                print('Para bajar un archivo del directorio utiliza el comando RETR test_drive.txt, presiona enter y vuelve a escribir test_drive.txt')
                clienteftp.retrbinary(input('\n>>'), open(input('\n>>'), 'wb').write)
                print('Para listar el archivo escribe el comando LIST')
                clienteftp.recoil(input('>>'))
                print('Para crear un directorio escribe el nombre del directorio')
                clienteftp.mkd(input('>>'))
                print('Para renombrar el directorio escribe el nombre del directorio')
                clienteftp.rename(input('Escribe el nombre del directorio a renombrar>>'),input('Escribe el nombre que quieres que tenga el diretorio>>'))
                print('Para remover ese directorio escribe el nombre del directorio')              
                clienteftp.rmd(input('>>'))
                print('Para eliminar el archivo test_drive.txt, escribe el nombre del archivo')
                clienteftp.delete(input('>>'))
                print('Ahora se cerrará la conexión')
                clienteftp.quit()
            if option == 4:
                docop = int(1)
                while docop != 0:
                    print('\n<---Elige la documentación que desees.--->')
                    print('1.- Buscar IP')
                    print('2.- Utilizar clienteftp')
                    print('3.- Quick Test')
                    print('4.- Regresa al menú principal')
                    docop = int(input('>>'))
                    if docop == 1:
                        print('\nSolo elige la primera opción y se presentará un letrero que dirá:\n\n"Escribe la dirección de la cual deseas saber la ip."\n\nAhora escribe la dirección de internet a la cual deseas conocer su ip.\n\n Enseguida se mostrará la ip de la página que solicitaste.')
                    if docop == 2:
                        print('<-------------------Bienvenido a el cliente clienteftp------------------->')
                        print('Elige la opción conectar vía clienteftp, enseguida, saldrá lo siguiente:')
                        print('Host>>')
                        print('Para llenar el campo incluye la IP del host a conectar, en el caso de que')
                        print('no conozcas la ip del servidor al que te quieres conectar tan solo elige la')
                        print('opción Buscar IP, así te dará la ip del servidor al que te quieres conectar,')
                        print('ahora entonces, suponiendo que sabes la IP introducela, una vez que la hayas')
                        print('Ahora que ya hiciste la petición, te mandará la siguiente petición:')
                        print('User>>')
                        print('Aquí solo tienes que introducir el usuario que esta asignado a alguna cuenta')
                        print('del sistema, enseguida te enviará la siguiente petición:')
                        print('Password>>')
                        print('También introduce la password asignada al usuario del sistema, si éstos datos')
                        print('son correctos, entonces te enviará la entrada del sistema.')
                        print('Para poder hacer uso de los comandos clienteftp, debes seguir la siguiente sintaxis')
                        print('>>clienteftp.[El comando que deseas ejecutar]()')
                        print('Y da enter, cabe aclarar que los "[]" no deben ser incluidos.')
                        print('Los comandos que puedes ejecutar son los siguientes:')
                        print('Mostrar los archivos del directorio actual')
                        print('>>clienteftp.recoil(LIST entre paréntesis simples)')        
                        print('Subir un archivo')
                        print('>>clienteftp.storbinary(STOR elnombredelarchivo.suextensión entre comillas simples,')
                        print('elnombredelarchivo.suextensión entre paréntesis simples, rb entre comillas simples)')             
                        print('Renombrar un archivo')
                        print('>>clienteftp.rename(elnombredelarchivo.suextensión entre comillas simples),')
                        print('elnuevonombredelarchivo.suextensión entre comillas simples')
                        print('Para bajar un archivo')
                        print('>>clienteftp.retrbinary( RETR elnombredelarchivo.suextensión entre comillas simples,')
                        print('open(elnombredelarchivo.suextensión entre comillas simples), wb entre comillas simples).write')
                        print('Crear un directorio')
                        print('>>clienteftp.mkd(el nombre del directorio entre comillas simples.)')
                        print('Renombrar el directorio')
                        print('>>clienteftp.rename(el nombre del directorio entre comillas simples,')
                        print('el nuevo nombre del directorio entre comillas simples')
                        print('Remover directorios')
                        print('>>clienteftp.rmd(el nombre del directorio entre comillas simples)')              
                        print('Eliminar archivos')
                        print('>>clienteftp.delete(el nombre del archivo entre comillas simples)')
                        print('Cerrar la conexión')
                        print('>>clienteftp.quit()')
                    if docop == 3:
                        print('Es un test rápido de la capacidad de la herramienta, se recomienta ir a éste paso primero.')
                    if docop == 4:
                        break
            if option == 5:
                print('Todavía esta en construcción')
                #clienteftp = clienteftp(input('Host>>'))
                #clienteftps.login(input('User>>'),input('Password>>'))
            if option == 6:
                print('Googbye')
                break

