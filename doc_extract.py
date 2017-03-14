#!/usr/bin/env python2.7
# Note:
# All algorithms, constants, etc taken from:
#  https://msdn.microsoft.com/en-us/library/cc313071(v=office.12).aspx

import struct
import hashlib
import math

from Crypto.Cipher import AES
from oletools.thirdparty.olefile import olefile2

# constants from MS-OFFCRYPTO 2.3.4.5
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


def get_bit(i, n, mask = 1):
    """Helper function, extract bits from a bitmask"""
    return (i >> n) & mask


def derive_key(hash_val, key_size):
    """Algorithm from MS-OFFCRYPTO 2.3.4.7"""
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
    """Algorithm from MS-OFFCRYPTO 2.3.4.7"""
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
    """Method described in MS-OFFCRYPTO 2.3.4.9"""
    key = generate_enc_key(password, metadata['salt'], metadata['enc_header']['KeySize'])

    aes = AES.new(key, mode=AES.MODE_ECB)
    vhash = aes.decrypt(metadata['verifier_hash'])[:metadata['verifier_len']]
    vdata = aes.decrypt(metadata['verifier_data'])
    hash = hashlib.sha1(vdata).digest()
    return vhash == hash


def decode_flags(flags):
    """Flags laid out in MS-OFFCRPYTO 2.3.1"""
    out = {
        'fCryptoAPI': get_bit(flags, 2) == 1,
        'fExternal': get_bit(flags, 4) == 1,
        'fAES': get_bit(flags, 5) == 1
    }

    return out

def decode_stream(password, metadata, package, out_file):
    """Structure laid out in MS-OFFCRYPTO 2.3.4.4"""
    decoded_len = struct.unpack("I", package.read(4))[0]
    useless_trash = package.read(4)
    print decoded_len

    key = generate_enc_key(password, metadata['salt'], metadata['enc_header']['KeySize'])

    aes = AES.new(key, mode=AES.MODE_ECB)
    ks = metadata['metadata']
    block_count = int(math.ceil(decoded_len/float(ks)))
    remainder = int(ks - (decoded_len % float(ks)))
    for i in xrange(block_count):
        cipher_t = package.read(float(ks))

        plain_t = aes.decrypt(cipher_t)
        if i == block_count-1:
            plain_t = plain_t[:remainder]

        out_file.write(plain_t)


def parse_enc_info(doc):
    """Structures laid out in MS-OFFCRYPTO 2.3.2 and 2.3.3"""
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
    return header


class PasswordError(Exception):
    pass


class ExtractionError(Exception):
    pass


def extract_docx(filename, password_list, output_folder):
    """
    Exceptions:
     - ValueError: Document is an unsupported format.
     - PasswordError: Document is a supported format, but the password is unknown.
     - ExtractionError: Document is encrypted but not in a supported format.

    :param filename: Name of the potential docx file
    :param password_list: a list of password strings, ascii or unicode
    :param output_folder: a path to a directory where we can write to
    :return: The filename we wrote. Else, an exception is thrown.
    """
    if not olefile2.isOleFile(filename):
        raise ValueError("Not OLE")

    of = olefile2.OleFileIO(filename)
    print of.listdir()
    if of.exists("WordDocument"):
        # Cannot parse these files yet
        raise ValueError("Legacy Word Document")

    elif of.exists("EncryptionInfo") and of.exists("EncryptedPackage"):
        metadata = parse_enc_info(of.openstream("EncryptionInfo"))
        if metadata["enc_header"]['AlgID'] == "RC4":
            raise ExtractionError("Error, cannot handle RC4")

        password = None
        for pass_try in password_list:
            if check_password(password, metadata) is True:
                password = pass_try
                break

        if password is None:
            PasswordError("Could not find correct password")

        import tempfile
        tf = tempfile.NamedTemporaryFile(dir=output_folder, delete=False)
        decode_stream(password, metadata, of.openstream("EncryptedPackage"), tf)
        name = tf.name
        tf.close()
        return name

