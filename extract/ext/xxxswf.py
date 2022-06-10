"""
Name:
    xxxswf.py
Version:
    2.0.0
Date:
    2017/02/02
Author:
    alexander<dot>hanel<at>gmail<dot>com


Reads, influences or borrowed code...
    http://www.the-labs.com/MacromediaFlash/SWF-Spec/SWFfileformat.html
    http://room32.dyndns.org/forums/showthread.php?766-SWFCompression
    http://pydoc.net/Python/tomato/0.0.2/tomato.swf_image_dumper/
    http://codeazur.com.br/fitc/HackingSWF.pdf
    https://gist.github.com/moriyoshi/1736477

License:
xxxswf.py is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see
<http://www.gnu.org/licenses/>.

"""

__author__ = "Alexander Hanel"
__version__ = "2.0.0"
__contact__ = "alexander<dot>hanel<at>gmail<dot>com"

import hashlib
import math
import os
import re
import struct
import sys
import zlib
from io import BytesIO
from optparse import OptionParser

import pylzma


class BitStream(object):
    # Source https://gist.github.com/moriyoshi/1736477
    def __init__(self, buf):
        self.buf = buf
        self.i = 0
        self.rem = 0
        self.n = 0

    def fetch(self, nbits):
        while self.n < nbits:
            self.rem = (self.rem << 8) | ord(self.buf[self.i])
            self.n += 8
            self.i += 1
        retval = (self.rem >> (self.n - nbits)) & ((1 << nbits) - 1)
        self.n -= nbits
        self.rem &= (1 << self.n) - 1
        return retval


# noinspection PyBroadException
class SwfHeader(object):
    def __init__(self, swf, logger):
        self.header = self.header_info(swf)
        self.log = logger
        self.print_header()

    @staticmethod
    def read_ui8(c):
        return struct.unpack('<B', c)[0]

    @staticmethod
    def read_ui16(c):
        return struct.unpack('<H', c)[0]

    @staticmethod
    def read_ui32(c):
        return struct.unpack('<I', c)[0]

    @staticmethod
    def check_type(swf):
        if type(swf) is bytes:
            swf = BytesIO(swf)
        return swf

    def header_info(self, swf):
        try:
            swf = self.check_type(swf)
            header = {'signature': swf.read(3)}
            if header['signature'] == b"FWS":
                header['compression'] = None
            elif header['signature'] == b"CWS":
                header['compression'] = "zlib"
            elif header['signature'] == b"ZWS":
                header['compression'] = "lzma"
            header['version'] = self.read_ui8(swf.read(1))
            header['file_length'] = self.read_ui32(swf.read(4))
            if header['compression'] == 'lzma':
                header['compressed_len'] = self.read_ui32(swf.read(4))
                swf.seek(3)
                vfl = swf.read(5)
                swf.read(4)
                swf = b"FWS" + vfl + pylzma.decompress(swf.read())
                swf = self.check_type(swf)
                swf.seek(8)
            elif header['compression'] == 'zlib':
                swf.seek(3)
                vfl = swf.read(5)
                swf = b"FWS" + vfl + zlib.decompress(swf.read())
                swf = self.check_type(swf)
                swf.seek(8)
            tmp = swf.tell()
            header['nbits'] = self.read_ui8(swf.read(1)) >> 3
            swf.seek(tmp)
            rect_size = int(math.ceil(((int(header['nbits']) * 4) + 5) / 8.0))
            bs = BitStream(swf.read(rect_size))
            bs.fetch(5)
            header['xmin'] = bs.fetch(int(header['nbits'])) / 20
            header['xmax'] = bs.fetch(int(header['nbits'])) / 20
            header['ymin'] = bs.fetch(int(header['nbits'])) / 20
            header['ymax'] = bs.fetch(int(header['nbits'])) / 20
            header['frame_rate'] = self.read_ui16(swf.read(2)) >> 8
            header['frame_count'] = self.read_ui16(swf.read(2))
            header['header_end'] = int(swf.tell())
        except Exception:
            return None
        return header

    def print_header(self):
        header = self.header
        if header is None:
            self.log.error('\t[HEADER] Error could not read header')
            return
        self.log.info('\t[HEADER] File Header: %s' % header['signature'])
        if header['compression'] is not None:
            self.log.info('\t[HEADER] Compression Type: %s' % header['compression'])
        if header['compression'] == 'lzma':
            self.log.info('\t[HEADER] Compressed Data Length: %s' % header['compressed_len'])
        self.log.info('\t[HEADER] File Veader: %i' % header['version'])
        self.log.info('\t[HEADER] File Size: %i' % header['file_length'])
        self.log.info('\t[HEADER] Rect Nbit: %i' % header['nbits'])
        self.log.info('\t[HEADER] Rect Xmin: %i' % header['xmin'])
        self.log.info('\t[HEADER] Rect Xmax: %i' % header['xmax'])
        self.log.info('\t[HEADER] Rect Ymin: %i' % header['ymin'])
        self.log.info('\t[HEADER] Rect Ymax: %i' % header['ymax'])
        self.log.info('\t[HEADER] Frame Rate: %i' % header['frame_rate'])
        self.log.info('\t[HEADER] Frace Count: %i' % header['frame_count'])


# noinspection PyBroadException,PyPep8Naming
class xxxswf:
    def __init__(self, logger):
        self.log = logger
        self.show_errors = True
        self.valid_version = 40
        self.debug = True
        self.cmd_run = False
        self.stream_func = []
        self.stream_swf = []
        self.lzma_install = False
        self.lzma_installed()
        # user defined options
        self.opt_extract = None
        self.opt_yara = None
        self.opt_md5_scan = None
        self.opt_header = None
        self.opt_decompress = None
        self.opt_path = None
        self.opt_compress = None
        self.opt_zcompress = None

    def lzma_installed(self):
        try:
            import pylzma
        except ImportError:
            self.lzma_install = False

    @staticmethod
    def find_swf(data_stream):
        """searches a data stream for the headers of SWF files"""
        data = data_stream.read()
        return [tmp.start() for tmp in re.finditer(b'CWS|FWS|ZWS', data)]

    def walk_path_find_swf(self, file_path):
        """returns a [path, [address, address]]"""
        path_addr = ['', []]
        r = path_addr * 0
        if not os.path.isdir(file_path) and file_path != '':
            if self.show_errors:
                self.log.error("\t[ERROR] File path must be a directory")
        for root, dirs, files, in os.walk(file_path):
            for name in files:
                try:
                    with open(os.path.join(root, name), "rb") as fh:
                        swf_addr = self.find_swf(fh)
                        if len(swf_addr) != 0:
                            path_addr[0] = os.path.join(root, name)
                            path_addr[1] = swf_addr
                            r.append(path_addr)
                            path_addr = ['', []]
                except Exception:
                    if self.show_errors:
                        self.log.error("\t[ERROR] Could not open file %s " % os.path.join(root, name))
        return r

    '''
    | 4 bytes       | 4 bytes   | 4 bytes       | 5 bytes    | n bytes   | 6 bytes         |
    | 'ZWS'+version | scriptLen | compressedLen | LZMA props | LZMA data | LZMA end marker |
    '''

    def uncompress_lzma(self, data):
        """uncompress lzma compressed stream"""
        if not self.lzma_install:
            if self.show_errors:
                self.log.error("\t[ERROR] pylzma module not installed - aborting validation/decompression")
            return None
        else:
            data = data[4:]
            try:
                return pylzma.decompress(data)
            except Exception:
                return None

    @staticmethod
    def uncompress_zlib(data):
        """uncompress zlib compressed stream"""
        try:
            return zlib.decompress(data)
        except Exception:
            return None

    def verify_swf(self, stream, addr):
        """carve and verify embedded SWF"""
        if type(stream) is bytes:
            stream = BytesIO(stream)
        # set index to address of the header
        stream.seek(addr)
        # read the header. index is address of version
        header = stream.read(3)
        # verify header. Should never happen but will test anyway
        if header not in [b"FWS", b"CWS", b"ZWS"]:
            if self.debug:
                self.log.debug('\t\t[DEBUG] Header not found', )
            return None
        # read version. index is file length
        version = struct.unpack("<b", stream.read(1))[0]
        # verify version
        if version > self.valid_version:
            if self.debug:
                self.log.debug('\n\t\t[DEBUG] Invalid Version', )
            return None
        # read size
        size = struct.unpack("<i", stream.read(4))[0]
        # len(header) =  3, len(version) = 1, len(size) = 4, Total 8
        if header == b"FWS":
            if self.cmd_run:
                self.log.info("- FWS Header")
            if size < 10:
                if self.debug:
                    self.log.debug('\t\t[DEBUG] FWS Size Invalid', )
                return None
            stream.seek(addr)
            try:
                return stream.read(size)
            except Exception:
                if self.debug:
                    self.log.debug('\t\t[DEBUG] FWS Size Invalid', )
                return None
        elif header == b"CWS":
            if self.cmd_run:
                self.log.info("- CWS Header")
            uncompress_data = self.uncompress_zlib(stream.read())
            if uncompress_data is None:
                if self.debug:
                    self.log.debug('\t\t[DEBUG] Zlib decompession failed', )
                return None
            # set index to version, skipping over the header
            stream.seek(addr + 3)
            return b"FWS" + stream.read(5) + uncompress_data[:size - 8]
        elif header == b"ZWS":
            if self.cmd_run:
                self.log.info("- ZWS Header")
            uncompress_lzma = self.uncompress_lzma(stream.read())
            if uncompress_lzma is None:
                if self.debug:
                    self.log.debug('\t\t[DEBUG] lzma decompession failed', )
                return None
            stream.seek(addr + 3)
            return b"FWS" + stream.read(5) + uncompress_lzma[:size - 8]
        return None

    def yara_scan(self, _data):
        """scan uncompressed SWF with Yara"""
        try:
            import yara
        except ImportError:
            if self.show_errors:
                self.log.error("\t[ERROR] Yara module not installed - aborting scan")
            return None
        try:
            rule = yara.compile(r'rules.yara')
        except Exception:
            if self.show_errors:
                self.log.error("\t[ERROR] Yara compile error - aborting scan")
            return None
        matches = rule.match(data=_data)
        for each in matches:
            self.log.info('\t[BAD] Yara Signature Hit:', each)

    def yara_md5_scan(self, _data):
        hashed = self.md5_hash_buffer(_data)
        try:
            import yara
        except ImportError:
            if self.show_errors:
                self.log.error("\t[ERROR] Yara module not installed - aborting scan")
            return None
        try:
            rule = yara.compile(r'md5.yara')
        except Exception:
            if self.show_errors:
                self.log.error("\t[ERROR] Yara compile error - aborting scan")
            return None
        matches = rule.match(data=hashed)
        for each in matches:
            self.log.info('\t[BAD] Yara MD5 Hit:', each)

    def pre_file_scan(self, data, file_scan):
        """executes a user defined function"""
        for func in file_scan:
            modified = None
            try:
                modified = func(data)
            except Exception:
                if self.show_errors:
                    self.log.error("\t[ERROR] Could not call pre-file-scan function")
                    return None
            if modified is None:
                continue
            else:
                return modified
        return None

    def swf_scan(self, data, swf_scan):
        """executes a user defined function"""
        if type(swf_scan) is not list:
            if self.show_errors:
                self.log.error("\t[ERROR] SWF-scan functions not a list")
            return None
        for func in data:
            try:
                modified = func(data)
            except Exception:
                if self.show_errors:
                    self.log.error("\t[ERROR] Could not call SWF-scan function")
                return None
            if modified is None:
                continue
            else:
                return modified
        return None

    def compress_lzma(self, swf):
        """compress a SWF with LZMA"""
        if type(swf) is bytes:
            swf = BytesIO(swf)
        if not self.lzma_install:
            if self.show_errors:
                self.log.error("\t[ERROR] pylzma module not installed - aborting validation/decompression")
            return None
        try:
            signature = swf.read(3)
            if signature != 'FWS':
                if self.show_errors:
                    self.log.error("\t[ERROR] FWS Header not found, aborting lzma compression")
                return None
            else:
                vfl = swf.read(5)
                # "ZWS" | version | len | compressed len | lzma compressed data
                # TEST
                lzma_data = pylzma.compress(swf.read())
                return b"ZWS" + vfl + struct.pack("<I", len(lzma_data) - 5) + lzma_data
        except Exception:
            return None

    def compress_zlib(self, swf):
        if type(swf) is bytes:
            swf = BytesIO(swf)
        self.show_errors = True
        try:
            signature = swf.read(3)
            if signature != 'FWS':
                if self.show_errors:
                    self.log.error("\t[ERROR] FWS Header not found, aborting zlib compression")
                return None
            vfl = swf.read(5)
            return b'CWS' + vfl + zlib.compress(swf.read())
        except Exception:
            if self.show_errors:
                self.log.error("\t[ERROR] Zlib compression failed")
            return None

    def get_arguments(self):
        usage = 'usage: %prog [options] <file.bad>'
        parser = OptionParser(usage=usage)
        parser.add_option('-x', '--extract', action='store_true', dest='extract',
                          help='Extracts the embedded SWF(s), names it MD5HASH.swf & saves '
                               'it in the working dir. No addition args needed')
        parser.add_option('-y', '--yara', action='store_true', dest='yara',
                          help='Scans the SWF(s) with yara. If the SWF(s) is compressed it '
                               'will be deflated. No addition args needed')
        parser.add_option('-s', '--md5scan', action='store_true', dest='md5scan',
                          help='Scans the SWF(s) for MD5 signatures. Please see func check '
                               'MD5 to define hashes. No addition args needed')
        parser.add_option('-H', '--header', action='store_true', dest='header',
                          help='Displays the SWFs file header. No addition args needed')
        parser.add_option('-d', '--decompress', action='store_true', dest='decompress',
                          help='Deflates compressed SWFS(s)')
        parser.add_option('-r', '--recdir', dest='PATH', type='string',
                          help='Will scan a directory for files that contain SWFs. Must provide path in quotes')
        parser.add_option('-c', '--compress', action='store_true', dest='compress', help='Compress SWF using Zlib')
        parser.add_option('-z', '--zcompress', action='store_true', dest='zcompress', help='Compress SWF using LZMA')
        (options, args) = parser.parse_args()
        if len(sys.argv) < 2:
            parser.print_help()
            return None
        if '-' in sys.argv[len(sys.argv) - 1][0] and options.PATH is None:
            parser.print_help()
            return None
        self.opt_extract = options.extract
        self.opt_yara = options.yara
        self.opt_md5_scan = options.md5scan
        self.opt_header = options.header
        self.opt_decompress = options.decompress
        self.opt_path = options.PATH
        self.opt_compress = options.compress
        self.opt_zcompress = options.zcompress
        return True

    def cmd(self):
        if self.get_arguments():
            self.cmd_run = True
        else:
            return None
        self.run()
        return

    def run(self):
        if self.opt_path is not None:
            paths = self.walk_path_find_swf(self.opt_path)
            for path in paths:
                try:
                    f = open(path[0], 'rb')
                    self.process(f, path[0])
                    f.close()
                except IOError:
                    pass
            return
        if self.opt_path is None:
            try:
                f = open(sys.argv[len(sys.argv) - 1], 'rb+')
                file_name = sys.argv[len(sys.argv) - 1]
            except Exception:
                self.log.error('[ERROR] File can not be opened/accessed')
                return
            self.process(f, file_name)
            f.close()

    def create_unique_name(self, name, ext):
        """if file already exists it will create a unique one"""
        count = None
        if os.path.exists(name + '.' + ext):
            count = 1
            while os.path.exists(name + '.' + str(count) + '.' + ext):
                if count == 50:
                    if self.show_errors:
                        self.log.error('\t[ERROR] Skipped 50 Matching MD5 SWFs')
                        return None
                count += 1
        if count is None:
            return name + '.' + ext
        else:
            return name + '.' + str(count) + '.' + ext

    def md5_hash_buffer(self, data):
        """MD5 hashes a buffer"""
        if type(data) is bytes:
            data = BytesIO(data)
        if data is None or data == '':
            if self.show_errors:
                self.log.error('\t[ERROR] Empty buffer, hashing exiting')
            return None
        md5 = hashlib.md5()
        while True:
            hasher = data.read(128)
            if not hasher:
                break
            md5.update(hasher)
        return md5.hexdigest()

    def write_swf(self, swf, output_path=None):
        name = self.create_unique_name(self.md5_hash_buffer(swf), "swf")
        if name is None:
            return
        if self.cmd_run:
            self.log.info('\t\t[FILE] Carved SWF MD5: %s' % name)
        try:
            if output_path:
                o = open(output_path + '/' + name, 'wb+')
            else:
                o = open(name, 'wb+')
            o.write(swf)
            o.close()
        except IOError as e:
            if self.cmd_run:
                self.log.error('\t[ERROR] Could Not Create %s ' % e)
        return name

    def extract(self, file_path, output_path):
        try:
            file = open(file_path, 'rb+')
        except Exception:
            self.log.error('[ERROR] File can not be opened/accessed')
            return

        # search for SWF file headers in the stream
        swf_data = self.find_swf(file)

        swf_found = []

        # print the number of found SWF Headers, FPs included
        for index, swf_addr in enumerate(swf_data):
            # set read to the address of the SWF header found
            file.seek(swf_addr)
            # verify and extract SWF.
            swf = self.verify_swf(file, swf_addr)
            if swf is None:
                continue
            name = self.write_swf(swf, output_path)
            if name:
                swf_found.append(name)
        return swf_found

    def process(self, stream, file_name=None):
        # compress first
        if self.opt_compress is not None:
            temp_swf = self.compress_zlib(stream)
            if temp_swf is not None:
                self.write_swf(temp_swf)
            else:
                self.log.error("\t[ERROR] Zlib compression failed")
            return
        if self.opt_zcompress is not None:
            temp_swf = self.compress_lzma(stream)
            if temp_swf is not None:
                self.write_swf(temp_swf)
            else:
                self.log.error("\t[ERROR] lzma compression failed")
            return
        # execute pre-parsing functions
        for func in self.stream_func:
            temp_stream = func(stream)
            if temp_stream is not None:
                stream = temp_stream
                break
        # search for SWF file headers in the stream
        swf_data = self.find_swf(stream)
        stream.seek(0)
        # print the number of found SWF Headers, FPs included
        if self.cmd_run:
            self.log.info("\n[SUMMARY] Potentially %d SWF(s) in MD5 %s:%s" % (
                len(swf_data), self.md5_hash_buffer(stream), file_name))
        # for each SWF in the file
        for index, swf_addr in enumerate(swf_data):
            if self.cmd_run:
                self.log.info("\t[ADDR] SWF %d at %s" % (index + 1, hex(swf_addr)), )
            # set read to the address of the SWF header found
            stream.seek(swf_addr)
            # verify and extract SWF.
            swf = self.verify_swf(stream, swf_addr)
            if swf is None:
                continue
            for func in self.stream_swf:
                temp_swf = func(swf)
                if temp_swf is not None:
                    stream = temp_swf
                    break
            if self.opt_extract is not None:
                self.write_swf(swf)
            if self.opt_yara is not None:
                self.yara_scan(swf)
            if self.opt_md5_scan is not None:
                self.yara_md5_scan(swf)
            if self.opt_decompress is not None:
                self.write_swf(swf)
            if self.opt_header is not None:
                SwfHeader(swf, self.log)
