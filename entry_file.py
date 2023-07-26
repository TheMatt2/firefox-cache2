import gzip
import struct
from dataclasses import dataclass, field
from datetime import datetime
from io import BytesIO
from pathlib import Path
from urllib.parse import unquote

from constants import META_HEADER_SIZE, kAlignSize, kChunkSize, kMinMetadataRead

# https://blog.packetfrenzy.com/ignoring-gzip-trailing-garbage-data-in-python/
# To ignore garbage following gzip data
class AltGzipFile(gzip.GzipFile):
    def read(self, size=-1):
        chunks = []
        try:
            if size < 0:
                while True:
                    chunk = self.read1()
                    if not chunk:
                        break
                    chunks.append(chunk)
            else:
                while size > 0:
                    chunk = self.read1(size)
                    if not chunk:
                        break
                    size -= len(chunk)
                    chunks.append(chunk)
        except OSError:
            if isinstance(self.fileobj, BytesIO):
                value = self.fileobj.getvalue()
                pos = self.fileobj.tell()
                preview = value[pos: pos + 10]
                print(f"{self.filename!r} ignored gzip trailing garbage "
                      f"(pos: {pos}; remaining: {len(value) - pos}; size: {len(value)}; preview {preview!r})")
            else:
                print(f"{self.filename!r} ignored gzip trailing garbage")

        return b''.join(chunks)

def decompress(data, filename = None):
    if data[0:2] != b'\x1F\x8B':
        # Not gzip, skip
        return data

    f = BytesIO(data)

    decompressor = AltGzipFile(fileobj = f, filename = filename)
    try:
        return decompressor.read()
    except IOError:
        # Error decompressing data
        # Assume not gzip
        return data


class EntryParseError(RuntimeError):
    """
    Parsing the entry has failed. This typically indicates
    the file is not a firefox cache file.
    """
    pass


"""
Refs:
https://searchfox.org/mozilla-central/source/netwerk/cache2/CacheFile.cpp

"""
@dataclass
class MetaDataHeader:
    version: int
    fetch_count: int
    last_fetched: datetime
    last_modified: datetime
    frecency: int
    expire_time: datetime
    key_size: int
    flags: int

    def __post_init__(self):
        self.last_fetched = datetime.fromtimestamp(self.last_fetched)
        self.last_modified = datetime.fromtimestamp(self.last_modified)
        self.expire_time = datetime.fromtimestamp(self.expire_time)


"""
https://searchfox.org/mozilla-central/source/__GENERATED__/__win64__/dist/include/mozilla/dom/ChromeUtilsBinding.h#706
"""
@dataclass
class KeyOriginAttributes:
    deprecatedAppId: int = 0
    firstPartyDomain: str = ""
    geckoViewSessionContextId: str = ""
    inIsolatedMozBrowser: bool = False
    partitionKey: str = ""
    privateBrowsingId: int = 0
    userContextId: int = 0


"""
https://searchfox.org/mozilla-central/source/netwerk/cache2/CacheFileUtils.cpp#56
"""
@dataclass
class KeyTags:
    originAttribs: KeyOriginAttributes = field(
        default_factory = KeyOriginAttributes)
    isAnonymous: bool = False
    idEnhance: str = ""
    cacheKey: str = ""


class EntryFile:
    def __init__(self):
        self.filename = None
        self.key = None
        self.key_tags = None
        self.hash_expected = 0
        self.hash_buf = None
        self.hash_codes = []
        self.elements = []
        self.data = None
        self.metadata_header = None

    def parse_entry_file(self, file_path):
        self.filename = Path(file_path).name
        with open(file_path, 'rb') as fd:
            data = fd.read()
        self.parse_entry(data)

    def parse_entry(self, data):
        size = len(data)

        # Calculate offset to metadata
        offset = min(size - kMinMetadataRead, 0)

        # Align to boundary
        offset -= offset % kAlignSize
        buf_size = size - offset
        metadata_buf = data[offset:offset + buf_size]

        # Parse metadata
        data_size = self.parse_metadata(metadata_buf, data, size)
        data_buf = data[:data_size]

        # gunzip
        self.data = decompress(data_buf, self.filename)

    def parse_key(self, key):
        """
        https://searchfox.org/mozilla-central/source/caps/OriginAttributes.cpp#297
        https://searchfox.org/mozilla-central/source/toolkit/components/extensions/parent/ext-cookies.js#71

        :     cacheKey        all rest
        O     originSuffix    next until ,
                  PopulateFromSuffix
                      Must start with "^"
                      inBrowser (same as isolatedBrowser)
                      addonId / appId (ignored)
                      userContextId (uint32)
                      privateBrowsingId (uint32)
                      firstPartyDomain (string replaces + with :)
                      geckoViewUserContextId (string)
                      partitionKey (string replaces + with :)
                          (scheme, domain, port)
                          If not "(", then https://${partitionKey}
                          port is omitted if ""

        p     privateBrowsing none
        b     isolatedBrowser none
        a     isAnonymous     none
        i     appId           integer
        ~     idEnhance       next until ,
        (assumes unknown tags consume until , and ignores)
        """
        key_tags = KeyTags()

        # ":" marks the final portion
        cache_key_index = key.find(b":")
        if cache_key_index != -1:
            key_tags.cacheKey = key[cache_key_index + 1:].decode()
            key = key[:cache_key_index]

        for key_part in key.split(b","):
            # Skip blank partitions
            if not key_part:
                continue

            if key_part.startswith(b"O"):
                assert key_part[1] == ord(b"^")

                name, value = key_part[2:].split(b"=", 1)

                if name == b"inBrowser":
                    assert value == b"1"
                    key_tags.originAttribs.inIsolatedMozBrowser = True

                elif name == b"addonId" or name == b"appId":
                    key_tags.originAttribs.deprecatedAppId = value

                elif name == b"userContextId":
                    key_tags.originAttribs.userContextId = value

                elif name == b"privateBrowsingId":
                    key_tags.originAttribs.privateBrowsingId = value

                elif name == b"firstPartyDomain":
                    key_tags.originAttribs.firstPartyDomain = value.replace(b"+", b":")

                elif name == b"geckoViewUserContextId":
                    key_tags.originAttribs.geckoViewSessionContextId = value

                elif name == b"partitionKey":
                    key_tags.originAttribs.partitionKey = unquote(value.decode())

            elif key_part == b"p":
                key_tags.originAttribs.privateBrowsingId = 1

            elif key_part == b"b":
                key_tags.originAttribs.inIsolatedMozBrowser = True

            elif key_part == b"a":
                key_tags.isAnonymous = True

            elif key_part.startswith(b"i"):
                key_tags.originAttribs.deprecatedAppId = int(key_part[1:])

            elif key_part.startswith(b"~"):
                key_tags.idEnhance = key_part[1:]
            else:
                # Ignore other tags
                print(f"Ignoring tags: {key_part}")

        self.key_tags = key_tags

    def parse_metadata(self, metadata_buf, data, size):
        buf_size = len(metadata_buf)
        real_offset, = struct.unpack('>I', metadata_buf[-4:])

        if not 0 <= real_offset < size:
            raise EntryParseError("metadata offset points to past end of file")

        used_offset = size - buf_size
        if real_offset < used_offset:
            missing = used_offset - real_offset
            buf_size = buf_size + missing
            metadata_buf = data[real_offset:real_offset + buf_size]
            used_offset = size - buf_size

        meta_offset = real_offset
        buf_offset = real_offset - used_offset
        meta_pos_offset = buf_size - 4
        hashes_offset = buf_offset + 4
        hash_count = meta_offset // kChunkSize

        if meta_offset % kChunkSize != 0:
            hash_count += 1

        hashes_len = hash_count * 2
        hdr_offset = hashes_offset + hashes_len
        key_offset = hdr_offset + META_HEADER_SIZE
        header_buf = metadata_buf[hdr_offset:key_offset]
        meta_header = MetaDataHeader(
            *struct.unpack('>IIIIIIII', header_buf[0:META_HEADER_SIZE]))

        self.metadata_header = meta_header
        key_size = meta_header.key_size

        # key should be null terminated
        assert metadata_buf[key_offset + key_size] == 0
        self.key = metadata_buf[key_offset: key_offset + key_size]
        self.parse_key(self.key)

        elements_offset = meta_header.key_size + key_offset + 1
        if elements_offset > meta_pos_offset:
            print(f"error: elements offset {elements_offset} exceeds {meta_pos_offset}")
        else:
            element_buf_size = meta_pos_offset - elements_offset
            element_buf = metadata_buf[elements_offset:elements_offset + element_buf_size]
            self.parse_elements(element_buf, element_buf_size)

        hash_buf_size = meta_pos_offset - hashes_offset
        hash_buf = metadata_buf[hashes_offset:hashes_offset + hash_buf_size]
        self.hash_expected, = struct.unpack('>I', metadata_buf[:4])
        hash_buf = metadata_buf[hashes_offset:hashes_offset+hashes_len]
        self.parse_hashes(hash_buf, hash_count)
        return meta_offset

    def parse_elements(self, buf, buf_size):
        start = 0
        for i in range(buf_size):
            if buf[i] == 0:
                key = buf[start:i]
                self.elements.append(key)
                start = i + 1

    def parse_hashes(self, hash_buf, count):
        for i in range(count):
            pos = i * 2
            hash_value, = struct.unpack('>H', hash_buf[pos:pos + 2])
            self.hash_codes.append(hash_value)
