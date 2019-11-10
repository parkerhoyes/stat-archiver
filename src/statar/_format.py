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

"""This module implements syntax parsing of the stat-archiver file format."""

from abc import ABCMeta, abstractmethod
import collections
import functools
import os
import re
from typing import *

from . import _core
from . import _util

_OS_PATH_SEP_CHAR = str(os.path.sep)
assert len(_OS_PATH_SEP_CHAR) == 1

class ArchiveFormatError(_core.ArchiveParsingError):
    def __init__(self, *args, line: Optional[int] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.__line = int(line) if line is not None else None
    def __str__(self):
        s = super().__str__()
        if self.__line is not None:
            s += f' (line {self.__line})'
        return s

class ArchiveSyntax:
    TEXT_CHARS = bytes(range(0x20, 0x7f))
    @property
    def sep_char(self) -> bytes:
        return self.__sep_char
    @property
    def comment_char(self) -> bytes:
        return self.__comment_char
    @property
    def path_sep_char(self) -> bytes:
        return self.__path_sep_char
    @property
    def escape_char(self) -> bytes:
        return self.__escape_char
    @property
    def special_chars(self) -> bytes:
        return self.__special_chars
    @property
    def escape_sequences(self) -> Mapping[int, bytes]:
        return self.__escape_sequences
    @property
    def escape_sequences_lookup_tree(self) -> Mapping[int, Union[Mapping, int]]:
        return self.__escape_sequences_lookup_tree
    def __init__(self, *args, sep_char: bytes = b':', comment_char: bytes = b'#', path_sep_char: bytes = b'/',
            escape_char: bytes = b'\\', special_chars: bytes = b'', **kwargs):
        super().__init__(*args, **kwargs)
        self.__sep_char = bytes(sep_char)
        if len(self.__sep_char) != 1:
            raise ValueError()
        self.__comment_char = bytes(comment_char)
        if len(self.__comment_char) != 1:
            raise ValueError()
        self.__path_sep_char = bytes(path_sep_char)
        if len(self.__path_sep_char) != 1:
            raise ValueError()
        self.__escape_char = bytes(escape_char)
        if len(self.__escape_char) != 1:
            raise ValueError()
        special_chars = bytes(special_chars)
        self.__special_chars = bytes(sorted(frozenset(
            self.__sep_char + self.__comment_char + self.__path_sep_char + self.__escape_char + special_chars
        )))
        if len(self.__special_chars) != 4 + len(special_chars):
            raise ValueError('duplicate special character')
        for cp in self.__special_chars:
            if cp not in __class__.TEXT_CHARS:
                raise ValueError(f'invalid special character: 0x{hex(cp)[2:].zfill(2)}')
        self.__hash = hash((__class__.__qualname__, self.__sep_char, self.__comment_char, self.__path_sep_char,
                self.__escape_char, self.__special_chars))
        self.__escape_sequences = {
            **{cp: b'x' + hex(cp)[2:].lower().zfill(2).encode() for cp in range(0x00, 0x100)},
            0x00: b'0',
            0x07: b'a',
            0x08: b'b',
            0x09: b't',
            0x0a: b'n',
            0x0b: b'v',
            0x0c: b'f',
            0x0d: b'r',
            ord('\\'): b'\\',
        }
        self.__escape_sequences_lookup_tree = {}
        for cp, seq in self.__escape_sequences.items():
            branch = self.__escape_sequences_lookup_tree
            for seq_cp, next_seq_cp in zip(seq, (*seq[1:], None)):
                if next_seq_cp is None:
                    branch[seq_cp] = cp
                    break
                else:
                    if seq_cp not in branch:
                        branch[seq_cp] = {}
                    branch = branch[seq_cp]
        self.__path_regex = (b'(' + self.__string_regex() + b')(' + re.escape(self.__path_sep_char) + b'(' +
                self.__string_regex() + b'))*')
    def __eq__(self, other):
        if other is self:
            return True
        if not isinstance(other, ArchiveSyntax):
            return False
        if other.__hash != self.__hash:
            return False
        if other.__sep_char != self.__sep_char:
            return False
        if other.__comment_char != self.__comment_char:
            return False
        if other.__path_sep_char != self.__path_sep_char:
            return False
        if other.__escape_char != self.__escape_char:
            return False
        if other.__special_chars != self.__special_chars:
            return False
        return True
    def __hash__(self):
        return self.__hash
    def __string_regex(self, permitted_special_chars: bytes = b'') -> bytes:
        return (b'((' + self.string_char_regex(permitted_special_chars) + b')|(' + re.escape(self.__escape_char) +
                b'([0abtnvfr\\]|x[0-9a-f]{2})))*')
    @functools.lru_cache()
    def string_char_regex(self, permitted_special_chars: bytes = b'') -> bytes:
        return b'[' + re.escape(self.string_chars(permitted_special_chars)) + b']'
    @functools.lru_cache()
    def string_chars_pattern(self, permitted_special_chars: bytes = b'') -> 're.Pattern':
        return re.compile(b'(' + self.string_char_regex(permitted_special_chars) + b')*')
    @functools.lru_cache()
    def is_string_codepoint_lookup_table(self, permitted_special_chars: bytes = b''):
        string_chars = self.string_chars(permitted_special_chars)
        return tuple(cp in string_chars for cp in range(0x00, 0x100))
    @functools.lru_cache()
    def string_chars(self, permitted_special_chars: bytes = b'') -> bytes:
        permitted_special_chars = bytes(permitted_special_chars)
        if self.__escape_char[0] in permitted_special_chars:
            raise ValueError()
        if any(cp not in self.__special_chars for cp in permitted_special_chars):
            raise ValueError()
        return bytes(sorted(
            cp for cp in __class__.TEXT_CHARS
            if cp not in self.__special_chars or cp in permitted_special_chars
        ))
    def escape_string(self, string: bytes, permitted_special_chars: bytes = b'') -> bytes:
        """Eescape characters in ``string`` as necessary."""
        result = bytearray()
        lookup = self.is_string_codepoint_lookup_table(permitted_special_chars)
        for cp in string:
            if lookup[cp]:
                result.append(cp)
            else:
                result.extend(self.escape_char)
                result.extend(self.escape_sequences[cp])
        return bytes(result)
    def unescape_string(self, string: bytes, permitted_special_chars: bytes = b'') -> bytes:
        """Unescape characters in ``string`` as necessary.

        Raises:
            ArchiveFormatError
        """
        string = memoryview(string)
        result = bytearray()
        pos = 0
        while pos < len(string):
            sub = self.string_chars_pattern(permitted_special_chars).match(string, pos).group()
            if len(sub) != 0:
                result.extend(sub)
                pos += len(sub)
                continue
            cp = string[pos]
            if cp == self.escape_char[0]:
                branch = self.escape_sequences_lookup_tree
                for pos in range(pos, len(string)):
                    cp = string[pos]
                    try:
                        branch = branch[cp]
                    except KeyError:
                        raise ArchiveFormatError('invalid escape sequence')
                    if isinstance(branch, int):
                        break
                else:
                    raise ArchiveFormatError('invalid escape sequence')
                result.append(branch)
            else:
                raise ArchiveFormatError(f'invalid character in string: 0x{hex(cp)[2:].zfill(2)}')
            pos += 1
        return bytes(result)
    def validate_path(self, path: bytes) -> bool:
        """Validate a serialized path."""
        path = bytes(path)
        if not re.fullmatch(self.__path_regex, path):
            return False
        if path in (b'', b'.'):
            return True
        for comp in path.split(self.__path_sep_char):
            try:
                comp = self.unescape_string(comp)
            except ArchiveFormatError:
                return False
            try:
                comp = comp.decode('utf-8')
            except UnicodeDecodeError:
                return False
            if comp in (b'', b'.', b'..'):
                return False
        return True
    def serialize_path(self, path: str) -> bytes:
        """Serialize an OS path.

        Raises:
            ValueError: If the path is invalid
        """
        path = str(path)
        if path in ('', '.'):
            return path.encode('utf-8')
        path = self.__path_sep_char.join(
            self.escape_string(comp.encode('utf-8')) for comp in path.split(_OS_PATH_SEP_CHAR)
        )
        if not self.validate_path(path):
            raise ValueError('invalid path')
        return path
    def deserialize_path(self, path: bytes) -> str:
        """Deserialize a path into an OS path.

        Raises:
            ArchiveFormatError
            OSError: If the path was valid but cannot be used on this platform
        """
        path = bytes(path)
        if path in (b'', b'.'):
            return path.decode('utf-8')
        if not self.validate_path(path):
            raise ArchiveFormatError('invalid path')
        try:
            comps = tuple(self.unescape_string(comp).decode('utf-8') for comp in path.split(self.__path_sep_char))
        except UnicodeError:
            raise ArchiveFormatError('invalid path: unicode error') from None
        if any('\x00' in comp or _OS_PATH_SEP_CHAR in comp for comp in comps):
            raise OSError('invalid path for this platform')
        return _OS_PATH_SEP_CHAR.join(comps)
    def join_paths(self, *paths: bytes) -> bytes:
        """Join serialized paths."""
        if all(path == b'.' for path in paths):
            return b'.'
        paths = tuple(bytes(path) for path in paths)
        assert all(self.validate_path(path) for path in paths)
        if len(paths) == 1:
            return paths[0]
        if b'' in paths:
            raise ValueError()
        return self.__path_sep_char.join(path for path in paths if path != b'.')
    def split_path(self, path: bytes) -> List[bytes]:
        if path == b'.':
            return []
        return path.split(self.__path_sep_char)
    def sort_paths(self, paths: List[bytes]):
        """Sort serialized paths in-place."""
        paths.sort(key=self.sort_path_key)
    def sort_path_key(self, path: bytes):
        path = bytes(path)
        return tuple(self.unescape_string(comp).decode('utf-8') for comp in path.split(self.__path_sep_char))
STANDARD_SYNTAX = ArchiveSyntax()

class RawArchive(metaclass=ABCMeta): # abstract
    @property
    def syntax(self) -> 'ArchiveSyntax':
        return self.__syntax
    def __init__(self, *args, syntax: 'ArchiveSyntax' = STANDARD_SYNTAX, **kwargs):
        super().__init__(*args, **kwargs)
        if not isinstance(syntax, ArchiveSyntax):
            raise TypeError()
        self.__syntax = syntax

class RawArchiveSource(RawArchive): # abstract
    @abstractmethod
    def read_record(self) -> Optional[Iterator]:
        """Read a raw record from this source.

        The returned iterator may raise the same exceptions as this method.

        Returns:
            ``None`` if there are no records remaining, or an iterator which yields the record's path, the attribute
            name, then zero or more ``bytes`` objects which, when concatenated together, are the serialized attribute
            value (which may be improperly formatted)
        Raises:
            Exception
        """
        raise NotImplementedError()
    def read_records(self) -> Iterator[Iterator]:
        return iter(self.read_record, None)

class RawArchiveSink(RawArchive): # abstract
    @abstractmethod
    def write_record(self, record: Iterator):
        """Write a raw record to this sink.

        The provided iterator will be completely iterated over before this method returns.

        Args:
            record: An iterator which yields the record's path, then the attribute name, then zero or more ``bytes``
                    objects which, when concatenated together, are the serialized attribute value (which may be
                    improperly formatted)
        Raises:
            Exception
        """
        raise NotImplementedError()

class RawArchiveParser(RawArchiveSource): # concrete
    def __init__(self, source: Iterator[bytes], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__source = source
        self.__buff = bytearray()
        self.__buff_pos = 0
        self.__concurrent_reads = []
        self.__seen_comments = False
        self.__line = 1
    def __enbuffer(self, size: int = 1) -> bool:
        """Read data from the source into the buffer.

        Returns:
            ``True`` if the requested data could be read, ``False`` otherwise
        Raises:
            Exception: If raised by the source
        """
        size = int(size)
        while size > 0:
            for block in self.__source:
                break
            else:
                return False
            if block is None:
                raise ValueError()
            block = bytes(block)
            size -= len(block)
            del self.__buff[:self.__buff_pos]
            self.__buff_pos = 0
            self.__buff.extend(block)
        return True
    def __ensure(self, size: int = 1) -> bool:
        return self.__enbuffer(int(size) - (len(self.__buff) - self.__buff_pos))
    def __finish_concurrent_reads(self):
        for it in self.__concurrent_reads:
            for _ in it:
                pass
        self.__concurrent_reads.clear()
    def __at_end(self) -> bool:
        """
        Returns:
            ``True`` if at the end of the file, ``False`` otherwise
        Raises:
            Exception: If raised by source
        """
        return not self.__ensure()
    def __read_codepoint(self) -> int:
        """
        Raises:
            ArchiveFormatError: If at EOF or raised by source
            Exception: If raised by source
        """
        if not self.__ensure():
            raise ArchiveFormatError('unexpected EOF')
        cp = self.__buff[self.__buff_pos]
        self.__buff_pos += 1
        return cp
    def __peek_codepoint(self) -> int:
        """
        Raises:
            ArchiveFormatError: If at EOF or raised by source
            Exception: If raised by source
        """
        if not self.__ensure():
            raise ArchiveFormatError('unexpected EOF')
        return self.__buff[self.__buff_pos]
    def __read_codepoints(self) -> Iterator[int]:
        while self.__ensure():
            yield self.__read_codepoint()
    def __peek_codepoints(self) -> Iterator[int]:
        while self.__ensure():
            yield self.__peek_codepoint()
    def __read_string(self, permitted_special_chars: bytes = b'') -> bytes:
        return bytes(self.__read_string_codepoints(permitted_special_chars))
    def __read_string_codepoints(self, permitted_special_chars: bytes = b'') -> Iterator[int]:
        lookup = self.syntax.is_string_codepoint_lookup_table(permitted_special_chars)
        while True:
            l = len(self.__buff)
            while self.__buff_pos != l:
                cp = self.__buff[self.__buff_pos]
                if not lookup[cp]:
                    break
                self.__buff_pos += 1
                yield cp
            else:
                if self.__ensure():
                    continue
                else:
                    break
            if cp == self.syntax.escape_char[0]:
                self.__buff_pos += 1
                yield self.__read_escape_sequence()
            else:
                break
    def __read_escape_sequence(self) -> int:
        branch = self.syntax.escape_sequences_lookup_tree
        for cp in self.__read_codepoints():
            try:
                branch = branch[cp]
            except KeyError:
                raise ArchiveFormatError('invalid escape sequence', line=self.__line)
            if isinstance(branch, int):
                return branch
        raise ArchiveFormatError('unexpected EOF')
    def __read_path(self) -> bytes:
        path = self.syntax.escape_string(self.__read_string(self.syntax.path_sep_char), self.syntax.path_sep_char)
        if not self.syntax.validate_path(path):
            raise ArchiveFormatError('invalid path', line=self.__line)
        if self.__read_codepoint() != self.syntax.sep_char[0]:
            raise ArchiveFormatError('invalid path syntax', line=self.__line)
        return path
    def __read_name(self) -> str:
        name = self.__read_string(self.syntax.path_sep_char)
        if self.__read_codepoint() != self.syntax.sep_char[0]:
            raise ArchiveFormatError('invalid attribute name syntax', line=self.__line)
        return name.decode('utf-8')
    def __read_comment(self):
        if not self.__at_end() and self.__peek_codepoint() == self.syntax.comment_char[0]:
            self.__seen_comments = True
            while not self.__at_end() and self.__peek_codepoint() != ord('\n'):
                if self.__read_codepoint() not in ArchiveSyntax.TEXT_CHARS:
                    raise ArchiveFormatError('invalid character in comment', line=self.__line)
    def read_record(self) -> Optional[Iterator]:
        """
        Raises:
            ArchiveFormatError: If the format of the archive is invalid or raised by source iterator
            Exception: If raised by source iterator
        """
        self.__finish_concurrent_reads()
        self.__read_record_prefix()
        if self.__at_end():
            return None
        it = self.__read_record_blocks()
        self.__concurrent_reads.append(it)
        return it
    def __read_record_blocks(self) -> Iterator:
        yield self.__read_path()
        yield self.__read_name()
        yield from _util.buffered_iter(self.__read_string_codepoints(self.syntax.sep_char + self.syntax.path_sep_char),
                source_bytes=True)
        self.__read_comment()
        if self.__read_codepoint() != ord('\n'):
            raise ArchiveFormatError('expected LF at end of record', line=self.__line)
        self.__line += 1
    def __read_record_prefix(self):
        while not self.__at_end():
            cp = self.__peek_codepoint()
            if cp == ord('\n'):
                self.__read_codepoint()
                self.__line += 1
            elif cp == self.syntax.comment_char[0]:
                self.__read_comment()
            else:
                break
    def seen_comments(self) -> bool:
        return self.__seen_comments

class RawArchiveComposer(RawArchiveSink): # concrete
    def __init__(self, sink: Callable[[bytes], int], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__sink = sink
        self.__buff = bytearray()
    def __debuffer(self, size: int = _core.IO_BLOCK_SIZE - 1):
        """Flush data to sink until the size of the buffer is no greater than ``size``.

        Raises:
            Exception: If raised by sink
        """
        size = int(size)
        while len(self.__buff) > size:
            del self.__buff[:int(self.__sink(memoryview(self.__buff)))]
    def __write(self, data: bytes):
        self.__buff.extend(data)
        self.__debuffer()
    def write_record(self, record: Iterator, comment: Optional[bytes] = None):
        """
        The write may be buffered.

        Raises:
            Exception: If raised by call to sink
        """
        try:
            path = next(record)
            name = next(record)
        except StopIteration:
            raise ValueError()
        self.__write(path)
        self.__write(self.syntax.sep_char)
        self.__write(self.syntax.escape_string(name.encode('utf-8'), self.syntax.path_sep_char))
        self.__write(self.syntax.sep_char)
        for block in record:
            self.__write(self.syntax.escape_string(block, self.syntax.sep_char + self.syntax.path_sep_char))
        self.write_empty(comment)
    def write_empty(self, comment: Optional[bytes] = None):
        if comment is not None:
            comment = bytes(comment)
            if not all(cp in ArchiveSyntax.TEXT_CHARS for cp in comment):
                raise ValueError()
            self.__write(b'#')
            self.__write(comment)
        self.__write(b'\n')
    def flush(self):
        """Flush all :meth:`written records <write_record>` to the underlying sink.

        Raises:
            Exception: If raised by call to sink
        """
        self.__debuffer(0)

class PathMap(collections.abc.MutableMapping):
    """This class implements a sorted mutable mapping where the keys are serialized paths for a specified syntax."""
    __slots__ = (
        '__syntax',
        '__sort_key',
        '__children',
        '__len',
        '__isset',
        '__value',
    )
    def __init__(self, init=(), *args, syntax: 'ArchiveSyntax' = STANDARD_SYNTAX, _sort_key=None, **kwargs):
        super().__init__(*args, **kwargs)
        if not isinstance(syntax, ArchiveSyntax):
            raise TypeError()
        self.__syntax = syntax
        self.__sort_key = _sort_key if _sort_key is not None else lambda key, value: self.__syntax.sort_path_key(key)
        self.__children = _util.SortableDict(key=self.__sort_key)
        self.__len = 0
        self.__isset = False
        for key, value in collections.OrderedDict(init).items():
            self[key] = value
    def __getitem__(self, path: bytes) -> Any:
        for node in self.__walk(path, allow_create=False):
            pass
        if not node.__isset:
            raise KeyError()
        return node.__value
    def __setitem__(self, path: bytes, value: Any) -> bool:
        nodes = tuple(self.__walk(path, allow_create=True))
        final = nodes[-1]
        final.__value = value
        if not final.__isset:
            final.__isset = True
            for node in nodes:
                node.__len += 1
            return True
        else:
            return False
    def __delitem__(self, path: bytes):
        nodes = tuple(self.__walk(path, allow_create=False, comps=True))
        final, comp = nodes[-1]
        if not final.__isset:
            raise KeyError()
        del final.__value
        final.__isset = False
        for node, comp in nodes:
            node.__len -= 1
        if len(nodes) > 1 and final.__len == 0:
            node, _ = nodes[-2]
            del node.__children[comp]
    def __contains__(self, path: bytes):
        try:
            self[path]
        except KeyError:
            return False
        else:
            return True
    def __iter__(self) -> Iterator[bytes]:
        for comps in self.__iter_key_comps():
            yield self.__syntax.join_paths(*comps)
    def __len__(self):
        return self.__len
    def set_and_parents(self, path: bytes, value: Any, parents: Any) -> Tuple[bool, int]:
        count = 0
        prev_nodes = []
        for node in self.__walk(path, allow_create=True):
            prev_nodes.append(node)
            if not node.__isset:
                unset = True
                count += 1
                node.__isset = True
                node.__value = parents
                for n in prev_nodes:
                    n.__len += 1
            else:
                unset = False
        node.__value = value
        if unset:
            count -= 1
        return unset, count
    def setdefault_and_parents(self, path: bytes, default: Any, parents: Any) -> Tuple[bool, Any, int]:
        count = 0
        prev_nodes = []
        for node in self.__walk(path, allow_create=True):
            prev_nodes.append(node)
            if not node.__isset:
                unset = True
                count += 1
                node.__isset = True
                node.__value = parents
                for n in prev_nodes:
                    n.__len += 1
            else:
                unset = False
        if unset:
            node.__value = default
            count -= 1
        else:
            default = node.__value
        return unset, default, count
    def clear(self, path: bytes = b'.'):
        try:
            for node in self.__walk(path, allow_create=False):
                pass
        except KeyError:
            return
        # TODO Memory leak: empty nodes are not pruned
        node.__children.clear()
        node.__len = 0
        if node.__isset:
            node.__isset = False
            del node.__value
    def clear_children(self, path: bytes = b'.'):
        try:
            for node in self.__walk(path, allow_create=False):
                pass
        except KeyError:
            return
        # TODO Memory leak: empty nodes are not pruned
        node.__children.clear()
        node.__len = 1 if node.__isset else 0
    def contains_parent(self, path: bytes) -> bool:
        try:
            for node in self.__walk(path, allow_create=False):
                if node.__isset:
                    return True
        except KeyError:
            pass
        return False
    def contains_child(self, path: bytes) -> bool:
        try:
            for node in self.__walk(path, allow_create=False):
                if len(node) == 0:
                    return False
        except KeyError:
            return False
        return len(node) > 1 or (len(node) == 1 and not node.__isset)
    def firstitem(self) -> Tuple[bytes, Any]:
        item = self.__firstitem()
        if item is None:
            raise KeyError()
        comps, value = item
        return self.__syntax.join_paths(*comps), value
    def __firstitem(self) -> Optional[Tuple[List[bytes], Any]]:
        if self.__isset:
            return [], self.__value
        self.__children.sort()
        for comp, node in self.__children.items():
            item = node.__firstitem()
            if item is None:
                continue
            sub_comps, value = item
            sub_comps.insert(0, comp)
            return sub_comps, value
        return None
    def setdefault(self, path: bytes, default: Any = None):
        nodes = tuple(self.__walk(path, allow_create=True))
        final = nodes[-1]
        if final.__isset:
            return final.__value
        else:
            final.__isset = True
            final.__value = default
            for node in nodes:
                node.__len += 1
            return default
    def __iter_key_comps(self) -> Iterator[List[bytes]]:
        if self.__isset:
            yield []
        self.__children.sort()
        for comp, node in self.__children.items():
            for sub_comps in node.__iter_key_comps():
                sub_comps.insert(0, comp)
                yield sub_comps
    def __walk(self, path: bytes, *, allow_create: bool, comps: bool = False):
        node = self
        yield node if not comps else (node, None)
        for comp in self.__syntax.split_path(path):
            child = node.__children.get(comp)
            if child is None:
                if allow_create:
                    child = __class__(syntax=self.__syntax, _sort_key=self.__sort_key)
                    node.__children[comp] = child
                else:
                    raise KeyError()
            node = child
            yield node if not comps else (node, comp)

class PathSet(collections.abc.MutableSet):
    """This class implements a mutable set of serialized paths for a specified syntax."""
    @property
    def proxy(self) -> collections.abc.Set:
        return self.__elems.keys()
    def __init__(self, init=(), *args, syntax: 'ArchiveSyntax' = STANDARD_SYNTAX, **kwargs):
        super().__init__(*args, **kwargs)
        self.__elems = PathMap(syntax=syntax)
        self |= init
    def __contains__(self, path: bytes) -> bool:
        return path in self.__elems
    def __iter__(self) -> Iterator[bytes]:
        return iter(self.__elems)
    def __len__(self) -> int:
        return len(self.__elems)
    def add_and_parents(self, path: bytes) -> Tuple[bool, int]:
        return self.__elems.set_and_parents(path, None, None)
    def clear(self, *args, **kwargs):
        return self.__elems.clear(*args, **kwargs)
    def clear_children(self, *args, **kwargs):
        return self.__elems.clear_children(*args, **kwargs)
    def contains_parent(self, *args, **kwargs):
        return self.__elems.contains_parent(*args, **kwargs)
    def contains_child(self, *args, **kwargs):
        return self.__elems.contains_child(*args, **kwargs)
    def add(self, path: bytes) -> bool:
        return self.__elems.__setitem__(path, None)
    def discard(self, path: bytes):
        try:
            del self.__elems[path]
        except KeyError:
            pass
    def remove(self, path: bytes):
        del self.__elems[path] # Possible KeyError intentional

class PathMask:
    """This class implements a mask of serialized paths for a specified syntax.

    Paths may be masked recursively and non-recursively.
    """
    @property
    def masked(self) -> collections.abc.Set:
        return self.__masked.proxy
    @property
    def rmasked(self) -> collections.abc.Set:
        return self.__rmasked.proxy
    def __init__(self, masked: Iterable[bytes] = (), rmasked: Iterable[bytes] = (), *args,
            syntax: 'ArchiveSyntax' = STANDARD_SYNTAX, **kwargs):
        super().__init__(*args, **kwargs)
        if not isinstance(syntax, ArchiveSyntax):
            raise TypeError()
        self.__syntax = syntax
        self.__rmasked = PathSet()
        for path in rmasked:
            path = bytes(path)
            assert self.__syntax.validate_path(path)
            if self.__rmasked.contains_parent(path):
                continue
            self.__rmasked.add(path)
        self.__masked = PathSet()
        for path in masked:
            path = bytes(path)
            assert self.__syntax.validate_path(path)
            if self.__rmasked.contains_parent(path):
                continue
            self.__masked.add(path)
    def __contains__(self, path: bytes) -> bool:
        path = bytes(path)
        assert self.__syntax.validate_path(path)
        return path in self.__masked or self.__rmasked.contains_parent(path)
