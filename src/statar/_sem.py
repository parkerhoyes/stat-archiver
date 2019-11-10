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

"""This module implements the semantics of the stat-archiver archive format."""

from abc import ABCMeta, abstractmethod
import functools
import itertools
from typing import *

from . import _attrs
from . import _core
from . import _format
from . import _util

class ArchiveSemanticsError(_core.ArchiveParsingError):
    pass

class ArchiveSemantics:
    @property
    def syntax(self) -> _format.ArchiveSyntax:
        return self.__syntax
    @property
    def attrs(self) -> _attrs.AttributeSet:
        return self.__attrs
    def __init__(self, syntax: _format.ArchiveSyntax, attrs: _attrs.AttributeSet, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not isinstance(syntax, _format.ArchiveSyntax):
            raise TypeError()
        self.__syntax = syntax
        if not isinstance(attrs, _attrs.AttributeSet):
            raise TypeError()
        self.__attrs = attrs
STANDARD_SEMANTICS = ArchiveSemantics(_format.STANDARD_SYNTAX, _attrs.STANDARD_ATTRS)

class Archive(metaclass=ABCMeta): # abstract
    @property
    def semantics(self) -> 'ArchiveSemantics':
        return self.__semantics
    @property
    def syntax(self) -> _format.ArchiveSyntax:
        return self.__semantics.syntax
    @property
    def attrs(self) -> _attrs.AttributeSet:
        return self.__semantics.attrs
    def __init__(self, *args, semantics: 'ArchiveSemantics' = STANDARD_SEMANTICS, **kwargs):
        super().__init__(*args, **kwargs)
        if not isinstance(semantics, ArchiveSemantics):
            raise TypeError()
        self.__semantics = semantics

class ArchiveSource(Archive): # abstract
    @abstractmethod
    def read_record(self) -> Optional[Iterator]:
        """Read a record from this source.

        The returned iterator may raise the same exceptions as this method.

        Returns:
            ``None`` if there are no records remaining, or an iterator which yields the record's path, the attribute,
            then zero or more ``bytes`` objects which, when concatenated together, are the serialized attribute value
            (which may be improperly formatted)
        Raises:
            Exception
        """
        raise NotImplementedError()
    def read_records(self) -> Iterator[Iterator]:
        """Return and iterator which yields the result of :meth:`read_record` until it is ``None``.

        Raises:
            Exception: If raised by the call to ``read_record``
        """
        return iter(self.read_record, None)

class ArchiveSink(Archive): # abstract
    @abstractmethod
    def write_record(self, record: Iterator):
        """Write a record to this sink.

        The provided iterator is completely iterated over before this method returns.

        Args:
            record: An iterable which yields the record's path, then the attribute or attribute name, then zero or more
                    ``bytes`` objects which, when concatenated together, are the serialized attribute value (which MUST
                    be properly formatted)
        Raises:
            Exception
        """
        raise NotImplementedError()

class ArchiveParser(ArchiveSource): # concrete
    def __init__(self, source: Iterator[bytes], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__parser = _format.RawArchiveParser(source, syntax=self.syntax)
    def read_record(self) -> Optional[Iterator]:
        """
        Raises:
            ArchiveFormatError: If the format of the archive is invalid or raised by source iterator
            ArchiveSemanticsError: If the semantics of the archive is invalid or raised by source iterator
            Exception: If raised by source iterator
        """
        record = self.__parser.read_record()
        if record is None:
            return None
        try:
            path = next(record)
            name = str(next(record))
        except StopIteration:
            raise ValueError() from None
        try:
            attr = self.attrs[name]
        except KeyError:
            raise ArchiveSemanticsError(f'unrecognized attribute name {name!r}') from None
        return itertools.chain((path, attr), record)

class ArchiveComposer(ArchiveSink): # concrete
    def __init__(self, sink: Callable[[bytes], int], *args, annotate: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.__annotate = bool(annotate)
        self.__composer = _format.RawArchiveComposer(sink, syntax=self.syntax)
    def write_record(self, record: Iterator):
        """
        The write may be buffered.

        Raises:
            Exception: If raised by call to sink
        """
        try:
            path = next(record)
            attr = next(record)
        except StopIteration:
            raise ValueError()
        attr = self.attrs[attr]
        name = attr.key
        if self.__annotate and isinstance(attr, _attrs.PrettyableAttribute):
            value = b''.join(record)
            record = iter((value,))
            try:
                value = attr.deserialize(value)
            except _attrs.AttributeFormatError as e:
                raise ValueError() from e
            comment = self.syntax.escape_string(attr.pretty(value).encode('utf-8'), self.syntax.sep_char +
                    self.syntax.path_sep_char)
            del value
        else:
            comment = None
        self.__composer.write_record(itertools.chain((path, name), record), comment=comment)
    def flush(self):
        """Flush all :meth:`written records <write_record>` to the underlying sink.

        Raises:
            Exception: If raised by call to sink
        """
        self.__composer.flush()

class MemoryArchive(ArchiveSource, ArchiveSink): # concrete
    """An archive that is buffered entirely in memory.

    Reading from the archive always produces records in the sorted (normalized) order. Writing multiple values for the
    same path and attribute will result in the previous value being overwritten.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__entries = _format.PathMap(syntax=self.syntax)
        self.__entry_sort_key = lambda key, value: self.attrs.sort_attr_key(key)
        self.__entries_iter = None
    def __new_entry(self):
        return _util.SortableDict(key=self.__entry_sort_key)
    def read_record(self) -> Optional[Iterator]:
        """
        Raises:
        """
        if len(self.__entries) == 0:
            return None
        path, entry = self.__entries.firstitem()
        entry.sort()
        attr, record = entry.popitem(last=False)
        if len(entry) == 0:
            del self.__entries[path]
        return iter((path, attr, attr.serialize(record.value)))
    def write_record(self, record: Iterator):
        """
        Raises:
            _attrs.AttributeFormatError: If the attribute value is improperly formatted
        """
        try:
            path = next(record)
            attr = next(record)
        except StopIteration:
            raise ValueError() from None
        path = bytes(path)
        attr = self.attrs[attr]
        value = attr.deserialize(b''.join(record))
        try:
            entry = self.__entries[path]
        except KeyError:
            entry = self.__new_entry()
            self.__entries[path] = entry
        entry[attr] = Record(path, attr, value, semantics=self.semantics)
    def get_record(self, path: bytes, attr: Union[str, _attrs.Attribute]) -> 'Record':
        """
        Raises:
            KeyError
        """
        path = bytes(path)
        attr = self.attrs[attr]
        return self.__records[path][attr] # Possible KeyError x2 intentional
    def set_record(self, path: bytes, attr: Union[str, _attrs.Attribute], value: Any):
        path = bytes(path)
        attr = self.attrs[attr]
        try:
            entry = self.__entries[path]
        except KeyError:
            entry = self.__new_entry()
            self.__entries[path] = entry
        entry[attr] = Record(path, attr, value)
    def iter_records_by_path(self, path: bytes) -> Iterator['Record']:
        try:
            entry = self.__records[path]
        except KeyError:
            return
        yield from entry.values()

@functools.total_ordering
class Record:
    __slots__ = (
        '__semantics',
        '__path',
        '__attr',
        '__value',
        '__hash',
    )
    @property
    def semantics(self) -> 'ArchiveSemantics':
        return self.__semantics
    @property
    def path(self) -> bytes:
        return self.__path
    @property
    def attr(self) -> _attrs.Attribute:
        return self.__attr
    @property
    def value(self) -> Any:
        return self.__value
    def __init__(self, path: bytes, attr: _attrs.Attribute, value: Any, *args,
            semantics: 'ArchiveSemantics' = STANDARD_SEMANTICS, **kwargs):
        super().__init__(*args, **kwargs)
        if not isinstance(semantics, ArchiveSemantics):
            raise TypeError()
        self.__semantics = semantics
        self.__path = bytes(path)
        if not isinstance(attr, _attrs.Attribute):
            raise TypeError()
        if attr not in self.semantics.attrs:
            raise ValueError()
        self.__attr = attr
        self.__value = value
        self.__hash = None
    def __eq__(self, other):
        if not isinstance(other, __class__):
            return False
        if other.__path != self.__path:
            return False
        if other.__attr != self.__attr:
            return False
        if other.__value != self.__value:
            return False
        return True
    def __hash__(self):
        if self.__hash is None:
            self.__hash = hash((__class__.__qualname__, self.__path, self.__attr.key, self.__value))
        return self.__hash
    def __lt__(self, other):
        if not isinstance(other, __class__):
            return NotImplemented
        if self.__path != other.__path:
            self_path = self.__semantics.syntax.sort_path_key(self.__path)
            other_path = self.__semantics.syntax.sort_path_key(other.__path)
            return self_path < other_path
        if self.__attr != other.__attr:
            self_attr = self.__semantics.attrs.sort_attr_key(self.__attr)
            other_attr = self.__semantics.attrs.sort_attr_key(other.__attr)
            return self_attr < other_attr
        if self.__value != other.__value:
            self_value = self.__attr.serialize(self.__value)
            other_value = other.__attr.serialize(other.__value)
            return self_value < other_value
        return False
    def __getitem__(self, key):
        if key == 0:
            return self.__path
        elif key == 1:
            return self.__attr
        elif key == 2:
            return self.__value
        else:
            raise IndexError()
    def __iter__(self):
        yield self.__path
        yield self.__attr
        yield self.__value
