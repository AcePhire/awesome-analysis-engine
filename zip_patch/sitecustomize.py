# malicious APKs often carry deliberately malformed ZIP metadata that Android ignores but Python's zipfile rejects. Make zipfile read them the way Android does, so analysis tools can open the original, untouched APK:
#   - malformed "extra field" blocks are skipped instead of raising BadZipFile
#   - the "encrypted" flag is ignored (APKs are never encrypted)
#   - an unknown compression method is read as stored (what Android does)
#   - CRC-32 mismatches are ignored (Android never checks them)
import zipfile

_KNOWN_METHODS = (
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
    zipfile.ZIP_BZIP2,
    zipfile.ZIP_LZMA,
)

_decode_extra = zipfile.ZipInfo._decodeExtra
_read_contents = zipfile.ZipFile._RealGetContents


def _tolerant_decode_extra(self, *args, **kwargs):
    try:
        _decode_extra(self, *args, **kwargs)
    except zipfile.BadZipFile:
        pass


def _tolerant_read_contents(self):
    _read_contents(self)
    for info in self.filelist:
        info.flag_bits &= ~0x1
        if info.compress_type not in _KNOWN_METHODS:
            info.compress_type = zipfile.ZIP_STORED
            info.compress_size = info.file_size


zipfile.ZipExtFile._update_crc = lambda self, newdata: None
zipfile.ZipInfo._decodeExtra = _tolerant_decode_extra
zipfile.ZipFile._RealGetContents = _tolerant_read_contents
