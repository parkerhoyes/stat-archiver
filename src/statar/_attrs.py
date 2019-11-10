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

"""This module implements the functionality of the various attributes supported by stat-archiver."""

from abc import ABCMeta, abstractmethod
import fractions
import hashlib
import os
import re
import stat
import time
import types
from typing import *

from . import _core
from . import _format
from . import _util

class AttributeFormatError(_core.ArchiveParsingError):
    pass

class AttributeNotApplicableError(_core.StatArchiverError):
    pass

class Attribute(metaclass=ABCMeta):
    @property
    def key(self) -> str:
        return self.__key
    @property
    def aliases(self) -> Tuple[str, ...]:
        return self.__aliases
    @property
    def names(self) -> Tuple[str, ...]:
        return self.__names
    @property
    def may_use_fs(self) -> bool:
        return self.__may_use_fs
    @property
    def priority(self) -> int:
        return self.__priority
    @property
    def small(self) -> bool:
        return self.__small
    def __init__(self, key: str, *args, aliases: Iterable[str] = (), may_use_fs: bool, priority: int = 0, small: bool,
            **kwargs):
        super().__init__(*args, **kwargs)
        self.__key = str(key)
        if isinstance(aliases, str):
            raise TypeError()
        self.__aliases = tuple(sorted(str(alias) for alias in aliases))
        self.__names = tuple(sorted((self.__key, *self.__aliases)))
        if '' in self.__names or len(self.__names) != len(frozenset(name.lower() for name in self.__names)):
            raise ValueError()
        self.__may_use_fs = bool(may_use_fs)
        self.__priority = int(priority)
        self.__small = bool(small)
    @abstractmethod
    def serialize(self, value: Any) -> bytes:
        """This method is the inverse of :meth:`deserialize`.

        The value provided must be an acceptable value which would be returned by :meth:`deserialize`.
        """
        raise NotImplementedError()
    @abstractmethod
    def deserialize(self, value: bytes) -> Any:
        """Deserialize a value of this attribute.

        Returns:
            The parsed result of ``value`` as a suitable Python object (an ``int``, ``bytes``, etc.) which is hashable
            and supports equality comparison
        Raises:
            AttributeFormatError
        """
        raise NotImplementedError()
    @abstractmethod
    def get(self, path: str, info: Union[os.stat_result, _util.FileInfo]) -> Any:
        """Get the value of this attribute for the file at the path ``path`` given some information about the file.

        If :attr:`may_use_fs` is true, ``info`` must be a ``os.stat_result`` object; otherwise, it must be a
        :class:`_util.FileInfo` object.

        This method never follows symlinks for the last path component.

        Returns:
            A value suitable for passing to :meth:`serialize`
        Raises:
            AttributeNotApplicableError: If the value of this attribute is not defined for the specified file
            _core.ArchivingError: If there's an error getting the value of this attribute
            OSError: If there's an error interacting with the filesystem
        """
        raise NotImplementedError()
    @abstractmethod
    def set(self, path: str, info: Union[os.stat_result, _util.FileInfo],
            value: Any) -> Tuple[Optional[_util.FileInfo], bool]:
        """Set the value of this attribute for the file at the path ``path`` to the value ``value`` given some
        information about the file.

        A :class:`_util.FileInfo` object may be returned with new values for some file attributes. The file's attributes
        must be updated to these values (excluding ``ctime``) by the caller (unless ``new_info`` is ``None``).

        If :attr:`may_use_fs` is true, ``info`` must be a ``os.stat_result`` object; otherwise, it must be a
        ``FileInfo`` object.

        This method never follows symlinks for the last path component.

        The value provided must be an acceptable value which would be returned by :meth:`deserialize`.

        Returns:
            A tuple of the form ``(new_info, modified)`` where:

            * ``new_info`` is ``None`` or a ``FileInfo`` object (see above).
            * ``modified`` is a boolean which is false if and only if the file on the filesystem was not modified in any
               way; this is always false if :attr:`may_use_fs` is false.
        Raises:
            AttributeNotApplicableError: If this attribute cannot be set for the specified file
            _core.ArchivingError: If there's an error setting the value of this attribute
            OSError: If there's an error interacting with the filesystem
        """
        raise NotImplementedError()
    def get_and_serialize(self, path: str, info: Union[os.stat_result, _util.FileInfo]) -> Iterator[bytes]:
        """
        The returned iterator may raise the same exceptions as this method except for
        :exc:`AttributeNotApplicableError`.

        Raises:
            AttributeNotApplicableError
            _core.ArchivingError
            OSError
        """
        return iter((self.serialize(self.get(path, info)),))
    def deserialize_and_set(self, path: str, info: Union[os.stat_result, _util.FileInfo],
            value: Iterator[bytes]) -> Tuple[Optional[_util.FileInfo], bool]:
        """
        Raises:
            AttributeFormatError
            AttributeNotApplicableError
            _core.ArchivingError
            OSError
        """
        return self.set(path, info, self.deserialize(b''.join(value)))

class PrettyableAttribute(Attribute):
    @abstractmethod
    def pretty(self, value: Any) -> str:
        """Create a "pretty" representation of ``value``.

        The "pretty" representation is lossless, deterministic, and easily human-readable.

        The value provided must be an acceptable value which would be returned by :meth:`Attribute.deserialize`.

        Returns:
            The pretty representation
        """
        raise NotImplementedError()

class AttributeSet:
    @property
    def attrs(self) -> Iterable['Attribute']:
        return self.__attrs
    @property
    def attr_keys(self) -> Iterable[str]:
        return self.__attr_keys
    @property
    def attr_names(self) -> Iterable[str]:
        return self.__attr_names
    @property
    def attrs_by_key(self) -> Mapping[str, 'Attribute']:
        return self.__attrs_by_key
    @property
    def attrs_by_name(self) -> Mapping[str, 'Attribute']:
        return self.__attrs_by_name
    def __init__(self, attrs, *args, **kwargs):
        super().__init__(*args, **kwargs)
        attrs = tuple(attrs)
        if not all(isinstance(attr, Attribute) for attr in attrs):
            raise TypeError()
        self.__attrs = []
        self.__attr_keys = []
        self.__attr_names = []
        self.__attrs_by_key = {}
        self.__attrs_by_name = {}
        for attr in attrs:
            self.__attrs.append(attr)
            self.__attr_keys.append(attr.key)
            self.__attr_names.extend(attr.names)
            self.__attrs_by_key[attr.key] = attr
            for name in attr.names:
                self.__attrs_by_name[name] = attr
        if len(self.__attr_names) != len(frozenset(name.lower() for name in self.__attr_names)):
            raise ValueError('attribute name conflict')
        self.__attrs.sort(key=lambda attr: attr.key)
        self.__attrs = tuple(self.__attrs)
        self.__attr_keys.sort()
        self.__attr_keys = tuple(self.__attr_keys)
        self.__attr_names.sort()
        self.__attr_names = tuple(self.__attr_names)
        self.__attrs_by_key = types.MappingProxyType(self.__attrs_by_key)
        self.__attrs_by_name = types.MappingProxyType(self.__attrs_by_name)
        self.__attrs_by_lower_name = {name.lower(): attr for name, attr in self.__attrs_by_name.items()}
    def __getitem__(self, key: Union[str, 'Attribute']) -> 'Attribute':
        """
        Raises:
            KeyError
        """
        if isinstance(key, Attribute):
            if key not in self:
                raise KeyError()
            return key
        elif isinstance(key, str):
            return self.__attrs_by_lower_name[str(key).lower()] # Possible KeyError intentional
        else:
            raise TypeError()
    def __len__(self) -> int:
        return len(self.__attrs)
    def __iter__(self) -> Iterator['Attribute']:
        return iter(self.__attrs)
    def __contains__(self, item: 'Attribute'):
        return item in self.__attrs
    def sort_attrs(self, attrs: List[Union[str, 'Attribute']]):
        attrs.sort(key=self.sort_attr_key)
    def sort_attr_key(self, attr: Union[str, 'Attribute']) -> Any:
        name = attr if isinstance(attr, Attribute) else str(attr)
        attr = self[name]
        name = attr.key if isinstance(name, Attribute) else name
        return -attr.priority, attr.key, name

STANDARD_ATTRS = []

def _standard_attribute(attr):
    if not isinstance(attr, Attribute):
        attr = attr()
    if not isinstance(attr, Attribute):
        raise TypeError()
    STANDARD_ATTRS.append(attr)
    return attr

class NaturalNumberAttribute(Attribute):
    def serialize(self, value: int) -> bytes:
        value = int(value)
        if value < 0:
            raise ValueError()
        return str(value).encode()
    def deserialize(self, value: bytes) -> int:
        value = bytes(value)
        if not re.fullmatch(br'[0-9]+', value):
            raise AttributeFormatError(f'invalid format for value of attribute {self.name!r}')
        return int(value.decode())

class DecimalAttribute(Attribute):
    def serialize(self, value: fractions.Fraction) -> bytes:
        return _util.fraction_as_decimal(value).encode()
    def deserialize(self, value: bytes) -> fractions.Fraction:
        value = bytes(value)
        if not re.fullmatch(br'-?[0-9]+(\.[0-9]+)?', value):
            raise AttributeFormatError(f'invalid format for value of attribute {self.name!r}')
        return fractions.Fraction(value.decode())

class BytesAttribute(Attribute):
    def __init__(self, *args, size: int, **kwargs):
        self.__size = int(size)
        if self.__size < 0:
            raise ValueError()
        super().__init__(*args, small=(size <= 2 ** 10), **kwargs)
    def serialize(self, value: bytes) -> bytes:
        return bytes(value).hex().lower().encode()
    def deserialize(self, value: bytes) -> bytes:
        value = bytes(value)
        if not re.fullmatch(br'([0-9a-f]{2})*', value):
            raise AttributeFormatError(f'invalid format for value of attribute {self.name!r}')
        return bytes.fromhex(value.decode())

class OctalAttribute(Attribute):
    def __init__(self, *args, mask: int, zfill: int = 0, **kwargs):
        super().__init__(*args, **kwargs)
        self.__mask = int(mask)
        if self.__mask < 0:
            raise ValueError()
        self.__zfill = int(zfill)
        if self.__zfill < 0:
            raise ValueError()
    def serialize(self, value: int) -> bytes:
        value = int(value)
        if value < 0 or value & self.__mask != value:
            raise ValueError()
        return ('0o' + oct(value)[2:].zfill(self.__zfill)).encode()
    def deserialize(self, value: bytes) -> int:
        value = bytes(value)
        if not re.fullmatch(br'0o[0-7]+', value):
            raise AttributeFormatError(f'invalid format for value of attribute {self.name!r}')
        value = int(value[2:].decode(), base=8)
        if value & self.__mask != value:
            raise AttributeFormatError(f'invalid value of attribute {self.name!r}: out of range')
        return value

class BoolAttribute(Attribute):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, small=True, **kwargs)
    def serialize(self, value: bool) -> bytes:
        return b'true' if value else b'false'
    def deserialize(self, value: bytes) -> bool:
        if value == b'true':
            return True
        elif value == b'false':
            return False
        else:
            raise AttributeFormatError(f'invalid value of attribute {self.name!r}: expected true or false')

@_standard_attribute
class ATTR_TARGET(Attribute):
    def __init__(self):
        super().__init__('target', may_use_fs=True, priority=100, small=True)
    def serialize(self, value: str) -> bytes:
        return str(value).encode('utf-8')
    def deserialize(self, value: bytes) -> str:
        value = bytes(value)
        try:
            return value.decode('utf-8')
        except ValueError as e:
            raise AttributeFormatError('unicode error') from e
    def get(self, path: str, info: os.stat_result) -> str:
        path = str(path)
        if ATTR_TYPE.type_from_mode(info.st_mode) != ATTR_TYPE.TYPE_SYMLINK:
            raise AttributeNotApplicableError()
        return str(os.readlink(path))
    def set(self, path: str, info: os.stat_result, value: str) -> Tuple[Optional[_util.FileInfo], bool]:
        path = str(path)
        value = str(value)
        if ATTR_TYPE.type_from_mode(info.st_mode) != ATTR_TYPE.TYPE_SYMLINK:
            raise AttributeNotApplicableError()
        target = str(os.readlink(path))
        if target != value:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            os.symlink(value, path)
        return None, True

@_standard_attribute
class ATTR_TYPE(Attribute):
    MASK = 0o170000
    TYPES = []
    TYPE_SOCKET = 'socket'
    TYPES.append(TYPE_SOCKET)
    TYPE_SYMLINK = 'symbolic link'
    TYPES.append(TYPE_SYMLINK)
    TYPE_REGULAR = 'regular file'
    TYPES.append(TYPE_REGULAR)
    TYPE_BLOCKDEV = 'block device'
    TYPES.append(TYPE_BLOCKDEV)
    TYPE_DIRECTORY = 'directory'
    TYPES.append(TYPE_DIRECTORY)
    TYPE_CHARDEV = 'character device'
    TYPES.append(TYPE_CHARDEV)
    TYPE_PIPE = 'pipe' # AKA named pipe or FIFO
    TYPES.append(TYPE_PIPE)
    TYPE_DOOR = 'door'
    TYPES.append(TYPE_DOOR)
    TYPE_EVENTPORT = 'event port'
    TYPES.append(TYPE_EVENTPORT)
    TYPE_WHITEOUT = 'whiteout'
    TYPES.append(TYPE_WHITEOUT)
    TYPES = tuple(TYPES)
    TYPES_BY_MODE = {
        0o140000: TYPE_SOCKET,
        0o120000: TYPE_SYMLINK,
        0o100000: TYPE_REGULAR,
        0o060000: TYPE_BLOCKDEV,
        0o040000: TYPE_DIRECTORY,
        0o020000: TYPE_CHARDEV,
        0o010000: TYPE_PIPE,
    }
    assert len(frozenset(TYPES_BY_MODE.values())) == len(TYPES_BY_MODE)
    MODES_BY_TYPE = {typ: mode for mode, typ in TYPES_BY_MODE.items()}
    assert MODES_BY_TYPE[TYPE_SOCKET] ==    stat.S_IFSOCK
    assert MODES_BY_TYPE[TYPE_SYMLINK] ==   stat.S_IFLNK
    assert MODES_BY_TYPE[TYPE_REGULAR] ==   stat.S_IFREG
    assert MODES_BY_TYPE[TYPE_BLOCKDEV] ==  stat.S_IFBLK
    assert MODES_BY_TYPE[TYPE_DIRECTORY] == stat.S_IFDIR
    assert MODES_BY_TYPE[TYPE_CHARDEV] ==   stat.S_IFCHR
    assert MODES_BY_TYPE[TYPE_PIPE] ==      stat.S_IFIFO
    TYPECHARS_BY_TYPE = {
        TYPE_SOCKET:    's',
        TYPE_SYMLINK:   'l',
        TYPE_REGULAR:   '-',
        TYPE_BLOCKDEV:  'b',
        TYPE_DIRECTORY: 'd',
        TYPE_CHARDEV:   'c',
        TYPE_PIPE:      'p',
        TYPE_DOOR:      'D',
        TYPE_EVENTPORT: 'P',
    }
    @staticmethod
    def type_from_mode(mode: int) -> str:
        mode = int(mode)
        if mode < 0:
            raise ValueError()
        ftype = __class__.TYPES_BY_MODE.get(mode & __class__.MASK)
        if ftype is None:
            raise OSError(f'unrecognized file type: 0o{oct(mode)[2:].zfill(6)}')
        return ftype
    @staticmethod
    def mode_from_type(ftype: str) -> int:
        ftype = str(ftype)
        mode = __class__.MODES_BY_TYPE.get(ftype)
        if mode is None:
            if ftype not in __class__.TYPES:
                raise ValueError()
            raise OSError(f'this platform does not support the file type {ftype!r}')
        return mode
    def __init__(self):
        super().__init__('type', may_use_fs=False, priority=95, small=True)
    def serialize(self, value: str) -> bytes:
        value = str(value)
        if value not in __class__.TYPES:
            raise ValueError()
        return value.encode('ascii')
    def deserialize(self, value: bytes) -> str:
        value = bytes(value)
        try:
            value = value.decode('ascii')
        except ValueError:
            raise AttributeFormatError('unrecognized file type') from None
        if value not in __class__.TYPES:
            raise AttributeFormatError(f'unrecognized file type: {value!r}')
        return value
    def get(self, path: str, info: _util.FileInfo) -> str:
        return __class__.type_from_mode(info.mode)
    def set(self, path: str, info: _util.FileInfo, value: str) -> Tuple[Optional[_util.FileInfo], bool]:
        value = __class__.mode_from_type(value)
        return info.replace(mode=(info.mode ^ (info.mode & __class__.MASK) ^ value)), False

@_standard_attribute
class ATTR_MODE(OctalAttribute, PrettyableAttribute):
    MASK = 0o177777
    __RWX_LOOKUP = tuple(
        bytes(cp if (bits & (4 >> i)) != 0 else ord('-') for i, cp in enumerate(b'rwx'))
        for bits in range(0o10)
    )
    __EXTRA_BIT_CHARS = ('SlT', 'sst')
    def __init__(self):
        super().__init__('mode', may_use_fs=False, priority=90, small=True, mask=__class__.MASK, zfill=6)
    def get(self, path: str, info: _util.FileInfo) -> int:
        mode = info.mode
        if mode != mode & __class__.MASK:
            raise OSError(f'unrecognized file mode bits: 0o{oct(mode)[2:].zfill(6)}')
        ftype = mode & ATTR_TYPE.MASK
        if ftype not in ATTR_TYPE.TYPES_BY_MODE:
            raise OSError(f'unrecognized file type: 0o{oct(ftype)[2:].zfill(6)}')
        return mode
    def set(self, path: str, info: _util.FileInfo, value: int) -> Tuple[Optional[_util.FileInfo], bool]:
        return info.replace(mode=value), False
    def pretty(self, value: int) -> str:
        value = int(value)
        if value < 0:
            raise ValueError()
        result = ATTR_TYPE.TYPECHARS_BY_TYPE.get(ATTR_TYPE.TYPES_BY_MODE[value & ATTR_TYPE.MASK], '?')
        perms = value & 0o777
        result += ATTR_PERMISSIONS.pretty(perms)
        extra = value & 0o007000
        result = list(result)
        for i in range(3):
            if (extra & 0o004000) != 0:
                result[(i + 1) * 3] = __class__.__EXTRA_BIT_CHARS[(perms & 0o100) >> 6]
            extra <<= 1
            perms <<= 3
        return ''.join(result)

class _PermissionsFlagAttribute(BoolAttribute):
    def __init__(self, *args, mask: int, **kwargs):
        super().__init__(*args, may_use_fs=False, **kwargs)
        self.__mask = int(mask)
    def get(self, path: str, info: _util.FileInfo) -> bool:
        return info.mode & self.__mask != 0
    def set(self, path: str, info: _util.FileInfo, value: bool) -> Tuple[Optional[_util.FileInfo], bool]:
        value = self.__mask ^ (_util.get_umask() & self.__mask) if value else 0
        return info.replace(mode=(info.mode ^ (info.mode & self.__mask) ^ value)), False

@_standard_attribute
class ATTR_SUID(_PermissionsFlagAttribute):
    MASK = 0o004000
    def __init__(self):
        super().__init__('suid', priority=87, mask=__class__.MASK)

@_standard_attribute
class ATTR_SGID(_PermissionsFlagAttribute):
    MASK = 0o002000
    def __init__(self):
        super().__init__('sgid', priority=85, mask=__class__.MASK)

@_standard_attribute
class ATTR_STICKY(_PermissionsFlagAttribute):
    MASK = 0o001000
    def __init__(self):
        super().__init__('sticky', priority=83, mask=__class__.MASK)

@_standard_attribute
class ATTR_PERMISSIONS(OctalAttribute, PrettyableAttribute):
    MASK = 0o000777
    __RWX_LOOKUP = tuple(
        ''.join(ch if (bits & (4 >> i)) != 0 else '-' for i, ch in enumerate('rwx'))
        for bits in range(0o10)
    )
    def __init__(self):
        super().__init__('permissions', aliases=('perms',), may_use_fs=False, priority=80, small=True,
                mask=__class__.MASK, zfill=3)
    def get(self, path: str, info: _util.FileInfo) -> int:
        return info.mode & __class__.MASK
    def set(self, path: str, info: _util.FileInfo, value: int) -> Tuple[Optional[_util.FileInfo], bool]:
        return info.replace(mode=(info.mode ^ (info.mode & __class__.MASK) ^ int(value))), False
    def pretty(self, value: int) -> str:
        value = int(value)
        result = []
        for i in range(3):
            result.append(__class__.__RWX_LOOKUP[(value & 0o700) >> 6])
            value <<= 3
        return ''.join(result)
    def unpretty(self, text: str) -> int:
        text = str(text)
        try:
            result = int()
            for i in range(0, 9, 3):
                result <<= 3
                result |= __class__.__RWX_LOOKUP.index(text[i:i + 3])
        except ValueError:
            raise AttributeFormatError(f'invalid format for pretty-format value of attribute {self.name!r}') from None

@_standard_attribute
class ATTR_READABLE(_PermissionsFlagAttribute):
    MASK = 0o000444
    def __init__(self):
        super().__init__('readable', aliases=('read',), priority=77, mask=__class__.MASK)

@_standard_attribute
class ATTR_WRITABLE(_PermissionsFlagAttribute):
    MASK = 0o000222
    def __init__(self):
        super().__init__('writable', aliases=('write',), priority=75, mask=__class__.MASK)

@_standard_attribute
class ATTR_EXECUTABLE(_PermissionsFlagAttribute):
    MASK = 0o000111
    def __init__(self):
        super().__init__('executable', aliases=('exec',), priority=73, mask=__class__.MASK)
    def get(self, path: str, info: _util.FileInfo) -> int:
        if ATTR_TYPE.type_from_mode(info.mode) != ATTR_TYPE.TYPE_REGULAR:
            raise AttributeNotApplicableError()
        return super().get(path, info)
    def set(self, path: str, info: _util.FileInfo, value: int) -> Tuple[Optional[_util.FileInfo], bool]:
        if ATTR_TYPE.type_from_mode(info.mode) != ATTR_TYPE.TYPE_REGULAR:
            raise AttributeNotApplicableError()
        return super().set(path, info, value)

@_standard_attribute
class ATTR_UID(NaturalNumberAttribute):
    def __init__(self):
        super().__init__('uid', may_use_fs=False, priority=60, small=True)
    def get(self, path: str, info: _util.FileInfo) -> int:
        return info.uid
    def set(self, path: str, info: _util.FileInfo, value: int) -> Tuple[Optional[_util.FileInfo], bool]:
        return info.replace(uid=value), False

@_standard_attribute
class ATTR_GID(NaturalNumberAttribute):
    def __init__(self):
        super().__init__('gid', may_use_fs=False, priority=50, small=True)
    def get(self, path: str, info: _util.FileInfo) -> int:
        return info.gid
    def set(self, path: str, info: _util.FileInfo, value: int) -> Tuple[Optional[_util.FileInfo], bool]:
        return info.replace(gid=value), False

class _TimeAttribute(DecimalAttribute, PrettyableAttribute):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, small=True, **kwargs)
    def pretty(self, value: fractions.Fraction) -> str:
        value = int(value * 10 ** 9)
        result = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(value // 10 ** 9))
        sub = 10 ** 9 + (value % 10 ** 9)
        while sub % 10 == 0:
            sub //= 10
        sub = str(sub)[1:]
        if sub != '':
            result += '.' + sub
        result += 'Z'
        return result

STANDARD_TIME_ATTRS = []

@_standard_attribute
class ATTR_ATIME(_TimeAttribute):
    def __init__(self):
        super().__init__('atime', may_use_fs=False, priority=37)
    def get(self, path: str, info: _util.FileInfo) -> fractions.Fraction:
        return info.atime
    def set(self, path: str, info: _util.FileInfo, value: fractions.Fraction,) -> Tuple[Optional[_util.FileInfo], bool]:
        return info.replace(atime=value), False
STANDARD_TIME_ATTRS.append(ATTR_ATIME)

@_standard_attribute
class ATTR_MTIME(_TimeAttribute):
    def __init__(self):
        super().__init__('mtime', may_use_fs=False, priority=35)
    def get(self, path: str, info: _util.FileInfo) -> fractions.Fraction:
        return info.mtime
    def set(self, path: str, info: _util.FileInfo, value: fractions.Fraction) -> Tuple[Optional[_util.FileInfo], bool]:
        return info.replace(mtime=value), False
STANDARD_TIME_ATTRS.append(ATTR_MTIME)

@_standard_attribute
class ATTR_CTIME(_TimeAttribute):
    def __init__(self):
        super().__init__('ctime', may_use_fs=False, priority=33)
    def get(self, path: str, info: _util.FileInfo) -> fractions.Fraction:
        return info.ctime
    def set(self, path: str, info: _util.FileInfo, value: fractions.Fraction) -> Tuple[Optional[_util.FileInfo], bool]:
        return info.replace(ctime=value), False
STANDARD_TIME_ATTRS.append(ATTR_CTIME)

@_standard_attribute
class ATTR_SIZE(NaturalNumberAttribute, PrettyableAttribute):
    __UNITS = ('bytes', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB')
    def __init__(self):
        super().__init__('size', may_use_fs=False, priority=10, small=True)
    def get(self, path: str, info: _util.FileInfo) -> int:
        if ATTR_TYPE.type_from_mode(info.mode) not in (ATTR_TYPE.TYPE_SYMLINK, ATTR_TYPE.TYPE_REGULAR):
            raise AttributeNotApplicableError()
        return info.size
    def set(self, path: str, info: _util.FileInfo, value: int) -> Tuple[Optional[_util.FileInfo], bool]:
        if ATTR_TYPE.type_from_mode(info.mode) not in (ATTR_TYPE.TYPE_SYMLINK, ATTR_TYPE.TYPE_REGULAR):
            raise AttributeNotApplicableError()
        return info.replace(size=value), False
    def pretty(self, value: int) -> str:
        value = fractions.Fraction(value)
        steps = 0
        while value / 1024 >= 1 and value.numerator % 2 == 0 and steps + 1 < len(__class__.__UNITS):
            value /= 1024
            steps += 1
        return _util.fraction_as_decimal(value) + ' ' + __class__.__UNITS[steps]

@_standard_attribute
class ATTR_CONTENTS(Attribute):
    def __init__(self):
        super().__init__('contents', may_use_fs=True, priority=-30, small=False)
    def serialize(self, value: bytes) -> bytes:
        return bytes(value)
    def deserialize(self, value: bytes) -> bytes:
        return bytes(value)
    def get(self, path: str, info: os.stat_result) -> bytes:
        return b''.join(self.get_and_serialize(path, info))
    def set(self, path: str, info: os.stat_result, value: bytes) -> Tuple[Optional[_util.FileInfo], bool]:
        return self.deserialize_and_set(path, info, iter((value,)))
    def get_and_serialize(self, path: str, info: os.stat_result) -> Iterator[bytes]:
        if ATTR_TYPE.type_from_mode(info.st_mode) != ATTR_TYPE.TYPE_REGULAR:
            raise AttributeNotApplicableError()
        path = str(path)
        return _util.iter_from_file(open(path, 'rb'), close=True)
    def deserialize_and_set(self, path: str, info: os.stat_result,
            value: Iterator[bytes]) -> Tuple[Optional[_util.FileInfo], bool]:
        if ATTR_TYPE.type_from_mode(info.st_mode) != ATTR_TYPE.TYPE_REGULAR:
            raise AttributeNotApplicableError()
        path = str(path)
        size = 0
        with open(path, 'wb') as f:
            writer = _util.writer_from_file(f)
            for block in value:
                block = memoryview(block)
                while len(block) != 0:
                    s = writer(block)
                    size += s
                    block = block[s:]
        return _util.FileInfo(info).replace(size=size), True

class _HashlibHashAttribute(BytesAttribute):
    def __init__(self, *args, factory, **kwargs):
        self.__factory = factory
        self.__size = int(self.__factory().digest_size)
        super().__init__(*args, may_use_fs=True, size=self.__size, **kwargs)
    def get(self, path: str, info: os.stat_result) -> bytes:
        path = str(path)
        if ATTR_TYPE.type_from_mode(info.st_mode) != ATTR_TYPE.TYPE_REGULAR:
            raise AttributeNotApplicableError()
        h = self.__factory()
        with open(path, 'rb') as f:
            for block in _util.iter_from_file(f):
                h.update(block)
        return h.digest()
    def set(self, path: str, info: os.stat_result, value: bytes) -> Tuple[Optional[_util.FileInfo], bool]:
        value = bytes(value)
        if len(value) != self.__size:
            raise ValueError()
        if self.get(path, info) != value:
            raise _core.ArchivingError('hash does not match')
        return _util.FileInfo(info), True
    def calc_hash(self, data: bytes) -> bytes:
        return self.__factory(data).digest()

STANDARD_HASH_ATTRS = []

@_standard_attribute
class ATTR_SHA2_256(_HashlibHashAttribute):
    def __init__(self):
        super().__init__('SHA2-256', aliases=('SHA-256', 'SHA256'), priority=-60, factory=hashlib.sha256)
STANDARD_HASH_ATTRS.append(ATTR_SHA2_256)

@_standard_attribute
class ATTR_BLAKE2b_512(_HashlibHashAttribute):
    def __init__(self):
        super().__init__('BLAKE2b-512', aliases=('BLAKE2b',), priority=-70, factory=hashlib.blake2b)
STANDARD_HASH_ATTRS.append(ATTR_BLAKE2b_512)

STANDARD_ATTRS = AttributeSet(STANDARD_ATTRS)
