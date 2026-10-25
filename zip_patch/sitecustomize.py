import zipfile

_KNOWN_METHODS = (
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
    zipfile.ZIP_BZIP2,
    zipfile.ZIP_LZMA,
)

_decode_extra = zipfile.ZipInfo._decodeExtra
_read_contents = zipfile.ZipFile._RealGetContents


# Parse a ZIP entry's extra field, skipping it when malformed
def _tolerant_decode_extra(self, *args, **kwargs):
    try:
        _decode_extra(self, *args, **kwargs)
    except zipfile.BadZipFile:
        pass


# Read the ZIP directory, then clear the encryption flag and treat unknown compression as stored
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
