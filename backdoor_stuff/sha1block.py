#!/usr/bin/env python

import hashlib
import itertools
import struct
import time
import multiprocessing
from ctypes import cdll


nbits = 19
mask = (1<<nbits)-1 #0x7ffff
tot_values = pow(2,nbits)

def process_killer():
    cdll['libc.so.6'].prctl(1,9)


def _left_rotate(n, b):
    """Left rotate a 32-bit integer n by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


def process_chunk(chunk, h0, h1, h2, h3, h4):
    """Process a chunk of data and return the new digest variables."""
    assert len(chunk) == 64

    w = [0] * 80

    # Break chunk into sixteen 4-byte big-endian words w[i]
    for i in range(16):
        w[i] = struct.unpack(b'>I', chunk[i*4:i*4 + 4])[0]
        #print hex(i),hex(w[i])

    # Extend the sixteen 4-byte words into eighty 4-byte words
    for i in range(16, 80):
        w[i] = _left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
        #print hex(i),hex(w[i])#,":",hex(w[i-3]),hex(w[i-8]),hex(w[i-14]),hex(w[i-16])
    
    # Initialize hash value for this chunk
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4
    
    for i in range(80):
        if 0 <= i <= 19:
            # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d) 
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xCA62C1D6
        
        #print map(hex,[a,f,e,k,w[i]])
        a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, 
                        a, _left_rotate(b, 30), c, d)
    
        #print hex(a)
    # Add this chunk's hash to result so far
    h0 = (h0 + a) & 0xffffffff
    return h0


def sha1block(tinput):
    tinput = tinput.ljust(64,'\x00')

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    res = process_chunk(tinput,h0,h2,h1,h3,h4) #intentionally switched

    return res

    if (res & mask) == res:
        return res
    else:
        return None

#import IPython; IPython.embed()

'''
tl = list(xrange(256))
ss = {}
for i,t in enumerate(itertools.product(tl,repeat=5)):
    if i % 0x100000 == 0:
        if i == 0: continue
        print hex(i), hex(len(ss))
        break
    tinput = "".join(map(chr,t))
    r = sha1block(tinput)
    if r != None:
        # print "tinput: %s, res: %08x" % (tinput.encode("hex"),r)
        ss[r] = tinput

for k in sorted(ss.keys()):
    v = ss[k]
    print  "%08x <-- %s" % (k,v.encode('hex'))
'''


def bruteforce_process(tid,nproc,result_queue):
    process_killer()
    slen = pow(2,8*5)
    tl = list(xrange(256))
    it = itertools.product(tl,repeat=5)
    step = (slen/nproc)*tid

    for x in itertools.islice(it,tid,slen):
        #print x
        tinput = "".join(map(chr,x))
        r = sha1block(tinput)
        if r != None:
            result_queue.put((r,tinput))




res = sha1block("\x01\x09\x54\x7f\x6b")
res = sha1block("\x01\x09\x54\x7f\x6b")
print hex(res)
res = sha1block("\x28\x71\x3a\xbc")
print hex(res)
res = sha1block("\xff\xff\xff\xff")
print hex(res)
res = sha1block("\x00\x00\x00\x00")
print hex(res)
res = sha1block("\x80\x00\x00\x00")
print hex(res)
res = sha1block("\x00\x00\x00\x01")
print hex(res)
