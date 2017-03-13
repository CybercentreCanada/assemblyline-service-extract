#!/usr/bin/env python2.7
# see https://msdn.microsoft.com/en-us/library/cc313071(v=office.12).aspx
import sys
import struct
import hashlib

from Crypto.Cipher import AES

from olefile import olefile2


def get_bit(i, n, mask = 1):
    return (i >> n) & mask

ALGID_ENUM = {
    0x00006801: "RC4",
    0x0000660E: "128-bit AES",
    0x0000660F: "192-bit AES",
    0x00006610: "256-bit AES"
}

ALGIDHASH_ENUM = {
    0x00000000: 'SHA-1',
    0x00008004: 'SHA-1'
}


def derive_key(hash_val, key_size):
    tmp_buffer = ['\x36'] * 64
    for i, c in enumerate(hash_val):
        tmp_buffer[i] = chr(ord(tmp_buffer[i]) ^ ord(hash_val[i]))

    x1 = hashlib.sha1("".join(tmp_buffer)).digest()
    derived_key = x1

    if key_size >= len(derived_key):
        tmp_buffer = ['\x5C'] * 64
        for i, c in enumerate(hash_val):
            tmp_buffer[i] = chr(ord(tmp_buffer[i]) ^ ord(hash_val[i]))

        x2 = hashlib.sha1("".join(tmp_buffer)).digest()

        derived_key += x2

    return derived_key[:key_size]


def generate_enc_key(password, salt, key_size):
    password = password.encode("utf-16")[2:]
    plain_text = salt + password
    h_step = hashlib.sha1(plain_text).digest()
    for i in xrange(50000):
        h_step = hashlib.sha1(struct.pack("I", i) + h_step).digest()

    block = 0
    h_final = hashlib.sha1(h_step + struct.pack("I", block)).digest()

    key = derive_key(h_final, key_size)
    return key


def check_password(password, metadata):
    key = generate_enc_key(password, metadata['salt'], metadata['enc_header']['KeySize'])

    aes = AES.new(key, mode=AES.MODE_ECB)
    vhash = aes.decrypt(metadata['verifier_hash'])[:metadata['verifier_len']]
    vdata = aes.decrypt(metadata['verifier_data'])
    hash = hashlib.sha1(vdata).digest()
    return vhash == hash


def decode_flags(flags):
    out = {}
    out['fCryptoAPI'] = get_bit(flags, 2) == 1
    out['fExternal'] = get_bit(flags, 4) == 1
    out['fAES'] = get_bit(flags, 5) == 1
    return out


def parse_enc_info(doc):
    header = {}
    flags = {}
    enc_header = {}

    fixed = struct.unpack("HHII", doc.read(12))
    header["ver_maj"] = fixed[0]
    header["ver_min"] = fixed[1]
    header["flags"] = fixed[2]
    header["size"] = fixed[3]
    fixed = struct.unpack("IIIIIIII", doc.read(8*4))
    enc_header['flags'] = fixed[0]
    enc_header['SizeExtra'] = fixed[1]
    enc_header['AlgID'] = ALGID_ENUM.get(fixed[2], fixed[2])
    enc_header['AlgIDHash'] = ALGIDHASH_ENUM.get(fixed[3], fixed[3])
    enc_header['KeySize'] = fixed[4]/8
    enc_header['ProviderType'] = fixed[5]
    enc_header['Reserved1'] = fixed[6]
    enc_header['Reserved2'] = fixed[7]
    enc_header['CSPName'] = doc.read(header["size"]-(8*4)).decode("utf-16")
    enc_header["flags"] = decode_flags(enc_header["flags"])
    header["enc_header"] = enc_header
    header["flags"] = decode_flags(header["flags"])

    saltsize = repr(doc.read(4))
    header['salt'] = doc.read(16)
    header['verifier_data'] = doc.read(16)
    header['verifier_len'] = struct.unpack("I", doc.read(4))[0]
    header['verifier_hash'] = doc.read(32)
    print header
    print check_password("password", header)
    return header

if __name__ == "__main__":
    if not olefile2.isOleFile(sys.argv[1]):
        print "not ole"
        sys.exit(7)
    of = olefile2.OleFileIO(sys.argv[1])
    print of.listdir()
    if of.exists("WordDocument"):
        print "Word Document"
    elif of.exists("EncryptionInfo"):
        metadata = parse_enc_info(of.openstream("EncryptionInfo"))

