import sys, select

def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    
    return reduce(lambda x,y:x+y, lst)

def ListToString(l):
    rt = ''
    for item in l:
        rt += item;
    return rt

def formatMAC(mac):
    rt = ""
    for i in range(0,c_macSize):
        rt += "%s%s"%(mac[i:i+2],":")
    return rt

def GetChar(Block=True):
  if Block or select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], []):
    return sys.stdin.read(1)