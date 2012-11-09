#!/usr/bin/env python
import os
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
ITERATIONS = 7
CMD = "ike-scan"

iterations = ITERATIONS
target = sys.argv[0]


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
    if whereIs('ike-scan') is not None:
        return True
    else:
        return False

if checkIke() == False:
        print "ike-scan not found in PATH."
        sys.exit(1)

trans1 = getCommon()
      
while trans1:
    transLine = getTransLine(trans1)
    transLine.insert(0, CMD)
    transLine.insert(1, '-M')
    transLine.append(target)
    test = ["ike-scan"]
    #print transLine
    
    subprocess.Popen(transLine).communicate()[0]

