#!/usr/bin/env python

import os
import re
import subprocess
import sys


#
#    Dependencies: 
#        ike-scan - scanning
#

ENC_COMMON = ["1", "5", "7/128", "7/192", "7/256"] # DES, 3DES, AES
ENC_ALL = ["1", "2", "3", "4", "5", "6", "7/128", "7/192", "7/256", "8"]
HASH_COMMON = ["1", "2"] # MD5, SHA1
HASH_ALL = ["1", "2", "3", "4", "5", "6"]
AUTH_COMMON = ["1", "3", "64221", "65001"] # PSK, RSA, Hybrid, Xauth
AUTH_ALL = ["1", "2", "3", "4", "5", "6", "7", "64221", "65001"]
DH_COMMON = ["1", "2", "5"] # MODP 768, MODP 1024, MODP 1536
DH_ALL = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18"]
TRANS = "--trans="
ITERATIONS = 8
CMD = "ike-scan"
HELP = "Usage: {0} <discover, fingerprint> <common, all> <target>".format(sys.argv[0])

iterations = ITERATIONS

class IKE:
    VID = None
    ENC = None
    HASH = None
    AUTH = None
    MODE = None
    IP = None
    
    def __init__(self, vid, enc, hsh, auth, mode, ip):
        self.VID = vid
        self.ENC = enc
        self.HASH = hsh
        self.AUTH = auth
        self.MODE = mode
        self.IP = ip
    
   

# Iterate through all common transforms
def getCommon():
    trans = []
    for enc in ENC_COMMON:
        for hsh in HASH_COMMON:
            for auth in AUTH_COMMON:
                for dh in DH_COMMON:
                    trans.append("{0}{1},{2},{3},{4}".format(TRANS, enc, hsh, auth, dh))
    return trans

def getAll():
    trans = []
    for enc in ENC_ALL:
        for hsh in HASH_ALL:
            for auth in AUTH_ALL:
                for dh in DH_ALL:
                    trans.append("{0}{1},{2},{3},{4}".format(TRANS, enc, hsh, auth, dh))
    return trans
                
def getTransLine(trans):
    transLine = []
    if len(trans) > iterations:
        for i in range(iterations):
            transLine.append(trans.pop())
    else:
        while trans:
            transLine.append(trans.pop())
    return transLine

def whereIs(program):
    for path in os.environ.get('PATH', '').split(':'):
        if os.path.exists(os.path.join(path, program)) and \
           not os.path.isdir(os.path.join(path, program)):
            return os.path.join(path, program)
    return None

def checkIke():
    if whereIs('ike-scan') is None:
        print HELP
        print "Error: ike-scan not found in PATH."
        sys.exit(-1)

def checkArgs():
    if len(sys.argv) < 3:
        print HELP
        print "Error: Invalid number of arguments."
        sys.exit(-1)
    else:
        if not (sys.argv[1] != "discover" or sys.argv[1] != "fingerprint"):
            print HELP
            print "Error: Choose 'discover' or 'fingerprint'"
            sys.exit(-1)
        if not (sys.argv[2] != "common" or sys.argv[2] != "all"):
            print HELP
            print "Error: Choose 'common' or 'all'"
            sys.exit(-1)
        # put code to check target
        
def cleanOutput(output):
    output = output.split("\n")
    output = [x for x in output if x != ''] # remove empty strings 
    del output[0] # remove ike-scan banner
    del output[-1] # remove time completed

    lines = []
    for i in output:
        lines.append(i.replace("\t", "").strip())
    
    return lines

def parseData(data):
    ip = re.compile('(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}'
               +'(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9]))')
    mode = re.compile('(Main|Aggressive)')
    auth = re.compile('Auth=[0-9a-zA-Z/]+')
    dh = re.compile('Group=[:0-9a-zA-Z]+')
    enc = re.compile('Enc=[0-9a-zA-Z]+')
    vid = data[3]
    hsh = re.compile('Hash=[0-9a-zA-Z/]+')
    
    ips = ip.search(data[0]).group()
    modes = mode.search(data[0]).group()
    encs = enc.search(data[2]).group()
    auths = auth.search(data[2]).group()
    dhs = dh.search(data[2]).group()
    hshs = hsh.search(data[2]).group()
    
    return vid, encs, hshs, auths, modes, ips

def createIke(data):
    cleanedOutput = cleanOutput(data)
    vid, enc, hsh, auth, mode, ip = parseData(cleanedOutput)
    
    ike = IKE(vid, enc, hsh, auth, mode, ip)
    return ike
        
if __name__ == "__main__":
    checkArgs()
    checkIke()
    
    target = sys.argv[3]
    method = sys.argv[2]
    action = sys.argv[1]
    
    if action == "discover":
        if method == "all":
            transList = getAll()
        else:
            transList = getCommon()
        discovered = []
        
        while transList:
            cmd = [CMD, '-M']
            cmd.extend(getTransLine(transList))
            cmd.append(target)
    
            output = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
            if "1 returned handshake" in output:
                ike = createIke(output)
                discovered.append(ike)
                print "IP:", ike.IP,
                print "Mode:", ike.MODE,
                print "HASH:", ike.HASH,
                print "VID:", ike.VID + "\n"
