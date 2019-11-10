# License for stat-archiver, originally found here:
# https://github.com/parkerhoyes/stat-archiver
#
# Copyright (C) 2019 Parker Hoyes <contact@parkerhoyes.com>
#
# This software is provided "as-is", without any express or implied warranty. In
# no event will the authors be held liable for any damages arising from the use of
# this software.
#
# Permission is granted to anyone to use this software for any purpose, including
# commercial applications, and to alter it and redistribute it freely, subject to
# the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not claim
#    that you wrote the original software. If you use this software in a product,
#    an acknowledgment in the product documentation would be appreciated but is
#    not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.

"""This module contains various utilities used throughout the codebase."""

import collections
import fractions
import os
import threading
from typing import *

from . import _core

class SortableDict(collections.abc.MutableMapping):
    def __init__(self, *args, backing_factory=dict, key=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.__backing_factory = backing_factory
        self.__key = key if key is not None else lambda key, value: key
        self.__entries = []
        self.__lookup = self.__backing_factory()
        self.__sorted = True
    def __getitem__(self, key):
        lookup = self.__get_lookup()
        i = lookup[key] # Possible KeyError intentional
        k, v = self.__entries[i]
        return v
    def __setitem__(self, key, value):
        lookup = self.__get_lookup()
        i = lookup.get(key)
        if i is None:
            lookup[key] = len(self.__entries)
            self.__entries.append((key, value))
            self.__sorted = False
        else:
            k, v = self.__entries[i]
            self.__entries[i] = (k, value)
    def __delitem__(self, key):
        lookup = self.__get_lookup()
        i = lookup.pop(key) # Possible KeyError intentional
        k, v = self.__entries.pop(i)
        if i != len(self.__entries):
            self.__lookup = None
        return v
    def __iter__(self):
        for k, v in self.__entries:
            yield k
    def __len__(self):
        return len(self.__entries)
    def getitem_by_index(self, index: int) -> Tuple[Any, Any]:
        return self.__entries[index] # Possible IndexError intentional
    def popitem(self, last: bool = True) -> Tuple[Any, Any]:
        if len(self.__entries) == 0:
            raise KeyError()
        if last:
            k, v = self.__entries.pop(-1)
            if self.__lookup is not None:
                del self.__lookup[k]
        else:
            k, v = self.__entries.pop(0)
            self.__lookup = None
        return k, v
    def clear(self):
        self.__entries.clear()
        self.__lookup = self.__backing_factory()
        self.__sorted = True
    def sort(self, key=None):
        if not self.__sorted:
            if key is None:
                key = self.__key
            self.__entries.sort(key=(lambda entry: key(*entry)))
            self.__lookup = None
            self.__sorted = True
    def __get_lookup(self):
        if self.__lookup is None:
            self.__lookup = self.__backing_factory()
            for i, (key, value) in enumerate(self.__entries):
                self.__lookup[key] = i
        return self.__lookup

class OSPathMask:
    """This class implements a mask of OS paths.

    Paths may be masked recursively and non-recursively.
    """
    @property
    def masked(self) -> frozenset:
        return self.__masked
    @property
    def rmasked(self) -> frozenset:
        return self.__rmasked
    def __init__(self, masked: Iterable[str] = (), rmasked: Iterable[str] = (), *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__rmasked = set()
        for path in rmasked:
            path = os.path.abspath(str(path))
            if any(issubpath(path, p) for p in self.__rmasked):
                continue
            self.__rmasked.add(path)
        self.__rmasked = frozenset(self.__rmasked)
        self.__masked = frozenset(
            os.path.abspath(str(path)) for path in masked
            if not any(issubpath(path, p) for p in self.__rmasked)
        )
    def __contains__(self, path: str) -> bool:
        if not isinstance(path, str):
            raise TypeError()
        path = os.path.abspath(str(path))
        return path in self.__masked or any(issubpath(path, p) for p in self.__rmasked)

def issubpath(sub: str, parent: str, *, strict: bool = False) -> bool:
    sub = os.path.normpath(str(sub))
    parent = os.path.normpath(str(parent))
    return os.path.commonpath((sub, parent)) == parent and (not strict or sub != parent)

class FileInfo:
    @property
    def mode(self) -> int:
        return self.__mode
    @property
    def uid(self) -> int:
        return self.__uid
    @property
    def gid(self) -> int:
        return self.__gid
    @property
    def size(self) -> int:
        return self.__size
    @property
    def atime(self) -> fractions.Fraction:
        return self.__atime
    @property
    def mtime(self) -> fractions.Fraction:
        return self.__mtime
    @property
    def ctime(self) -> fractions.Fraction:
        return self.__ctime
    @property
    def __data(self):
        return (self.__mode, self.__uid, self.__gid, self.__size, self.__atime, self.__mtime, self.__ctime)
    def __init__(self, init=None, *args, mode=None, uid=None, gid=None, size=None, atime=None, mtime=None, ctime=None,
            **kwargs):
        super().__init__(*args, **kwargs)
        if init is not None:
            if isinstance(init, FileInfo):
                mode = init.mode
                uid = init.uid
                gid = init.gid
                size = init.size
                atime = init.atime
                mtime = init.mtime
                ctime = init.ctime
            elif isinstance(init, os.stat_result):
                mode = init.st_mode
                uid = init.st_uid
                gid = init.st_gid
                size = init.st_size
                atime = fractions.Fraction(init.st_atime_ns, 10 ** 9)
                mtime = fractions.Fraction(init.st_mtime_ns, 10 ** 9)
                ctime = fractions.Fraction(init.st_mtime_ns, 10 ** 9)
            else:
                raise ValueError()
        elif None in (mode, uid, gid, size, atime, mtime, ctime):
            raise ValueError()
        self.__mode = int(mode)
        if self.__mode < 0:
            raise ValueError()
        self.__uid = int(uid)
        if self.__uid < 0:
            raise ValueError()
        self.__gid = int(gid)
        if self.__gid < 0:
            raise ValueError()
        self.__size = int(size)
        if self.__size < 0:
            raise ValueError()
        self.__atime = atime if not isinstance(atime, fractions.Fraction) else fractions.Fraction(atime)
        assert fraction_is_decimal(atime)
        self.__mtime = mtime if not isinstance(mtime, fractions.Fraction) else fractions.Fraction(mtime)
        assert fraction_is_decimal(mtime)
        self.__ctime = ctime if not isinstance(ctime, fractions.Fraction) else fractions.Fraction(ctime)
        assert fraction_is_decimal(ctime)
    def __eq__(self, other):
        if not isinstance(other, __class__):
            return NotImplemented
        return self.__data == other.__data
    def __hash__(self):
        return hash((__class__.__qualname__, self.__data))
    def replace(self, mode=None, uid=None, gid=None, size=None, atime=None, mtime=None, ctime=None):
        return __class__(
            mode=(mode if mode is not None else self.__mode),
            uid=(uid if uid is not None else self.__uid),
            gid=(gid if gid is not None else self.__gid),
            size=(size if size is not None else self.__size),
            atime=(atime if atime is not None else self.__atime),
            mtime=(mtime if mtime is not None else self.__mtime),
            ctime=(ctime if ctime is not None else self.__ctime),
        )
    def same_mode(self, *infos: 'FileInfo') -> bool:
        return all(info.__mode == self.__mode for info in infos)
    def same_owners(self, *infos: 'FileInfo') -> bool:
        return all(info.__uid == self.__uid and info.__gid == self.__gid for info in infos)
    def same_size(self, *infos: 'FileInfo') -> bool:
        return all(info.__size == self.__size for info in infos)
    def same_times(self, *infos: 'FileInfo') -> bool:
        return all(
            info.__atime == self.__atime and info.__mtime == self.__mtime and info.__ctime == self.__ctime
            for info in infos
        )

def fraction_is_decimal(value: fractions.Fraction) -> bool:
    if not isinstance(value, fractions.Fraction):
        raise TypeError()
    den = int(value.denominator)
    while den & 1 == 0:
        den >>= 1
    while den % 5 == 0:
        den //= 5
    return den == 1

def fraction_as_decimal(value) -> str:
    if not isinstance(value, fractions.Fraction):
        raise TypeError()
    den = int(value.denominator)
    if den == 1:
        return str(int(value))
    n = 0
    while den & 1 == 0:
        den >>= 1
        n += 1
    m = 0
    while den % 5 == 0:
        den //= 5
        m += 1
    if den != 1:
        raise ValueError()
    del den
    places = max(n, m) # Always > 0
    del n, m
    value *= 2 ** places
    value *= 5 ** places
    value = str(int(value)).zfill(places)
    value = value[:-places] + '.' + value[-places:]
    return value

_UMASK_LOCK = threading.Lock()
_CACHED_UMASK = None
def get_umask(*, clear_cache: bool = False):
    """
    Raises:
        OSError
    """
    # This implementation is thread-safe because variable access is atomic
    if clear_cache:
        clear_umask_cache()
    umask = _CACHED_UMASK
    if umask is None:
        with _UMASK_LOCK:
            umask = os.umask(0o077)
            os.umask(umask)
            _CACHED_UMASK = umask
    return umask
def clear_umask_cache():
    with _UMASK_LOCK:
        _CACHED_UMASK = None

def iter_from_file(file, *, close: bool = False):
    try:
        while True:
            block = file.read(_core.IO_BLOCK_SIZE)
            if block is None:
                raise OSError('read blocking')
            if len(block) == 0:
                break
            yield block
    finally:
        if close:
            file.close()

def buffered_iter(source, *, buff_size: int = _core.IO_BLOCK_SIZE, source_bytes: bool = False):
    buff = bytearray()
    for block in source:
        (buff.append if source_bytes else buff.extend)(block)
        if len(buff) > buff_size:
            yield buff
            buff = bytearray()
    if len(buff) != 0:
        yield buff

def writer_from_file(file):
    def write(block):
        if len(block) == 0:
            return 0
        size = file.write(block)
        if size is None:
            raise OSError('write blocking')
        size = int(size)
        if size == 0:
            raise OSError('end of file while writing')
        return size
    return write
