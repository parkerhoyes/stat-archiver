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

"""This module implements stat-archiver's various operations."""

import itertools
import os
import stat
import types
from typing import *

from . import _attrs
from . import _core
from . import _format
from . import _sem
from . import _util

# This is intended to avoid infinite recursion from following symlinks.
# TODO This limit is currently rather pointless as the Python recursion limit is reached first.
_MAX_RECURSION_DEPTH = 2 ** 13

class ArchiveInfo:
    TYPE_UNKNOWN = object()
    TYPE_UNRECOGNIZED = object()
    @property
    def semantics(self) -> _sem.ArchiveSemantics:
        return self.__semantics
    @property
    def n_records(self) -> int:
        return self.__n_records
    @property
    def n_paths(self) -> int:
        return self.__n_paths
    @property
    def n_implicit_dirs(self) -> int:
        return self.__n_implicit_dirs
    @property
    def n_records_by_attr(self) -> Mapping[_attrs.Attribute, int]:
        return self.__n_records_by_attr
    @property
    def n_paths_by_ftype(self) -> Mapping[Any, int]:
        """A mapping from file types to the number of unique paths with that file type.

        The key may also be ``TYPE_UNKNOWN`` for unknown file type, or ``TYPE_UNRECOGNIZED`` for unrecognized file type.
        """
        return self.__n_paths_by_ftype
    @property
    def contains_comments(self) -> bool:
        return self.__contains_comments
    @property
    def normalized(self) -> bool:
        return self.__normalized
    @property
    def n_files(self) -> int:
        return self.__n_paths + self.__n_implicit_dirs
    @property
    def attrs(self) -> Tuple[_attrs.Attribute, ...]:
        return self.__attrs
    def __init__(self, semantics: _sem.ArchiveSemantics, *args, n_records, n_paths, n_implicit_dirs,
            n_records_by_attr, n_paths_by_ftype, contains_comments, normalized, **kwargs):
        super().__init__(*args, **kwargs)
        if not isinstance(semantics, _sem.ArchiveSemantics):
            raise TypeError()
        self.__semantics = semantics
        self.__n_records = int(n_records)
        self.__n_paths = int(n_paths)
        self.__n_implicit_dirs = int(n_implicit_dirs)
        self.__n_records_by_attr = dict(n_records_by_attr)
        self.__n_records_by_attr = types.MappingProxyType({
            attr: self.__n_records_by_attr[attr] for attr in semantics.attrs
        })
        self.__n_paths_by_ftype = types.MappingProxyType(dict(n_paths_by_ftype))
        self.__contains_comments = bool(contains_comments)
        self.__normalized = bool(normalized)
        self.__attrs = tuple(sorted(attr for attr, value in self.__n_records_by_attr.items() if value != 0))
    def pretty(self) -> str:
        indent = ' ' * 4
        return '\n'.join((
            f'Records: {self.n_records}',
            f'Paths: {self.n_paths}',
            f'Implicit Directories: {self.n_implicit_dirs}',
            f'Total Files: {self.n_files}',
            'Records by Attribute:',
            *(
                f'{indent}{attr.key}: {self.n_records_by_attr[attr]}' for attr in self.attrs
            ),
            'Paths by File Type:',
            *(
                f'{indent}{ftype}: {self.n_paths_by_ftype[ftype]}'
                for ftype in _attrs.ATTR_TYPE.TYPES
                if self.n_paths_by_ftype[ftype] != 0
            ),
            *(
                (f'{indent}unknown: {self.n_paths_by_ftype[__class__.TYPE_UNKNOWN]}',)
                if self.n_paths_by_ftype[__class__.TYPE_UNKNOWN] != 0 else ()
            ),
            *(
                (f'{indent}unrecognized: {self.n_paths_by_ftype[__class__.TYPE_UNRECOGNIZED]}',)
                if self.n_paths_by_ftype[__class__.TYPE_UNRECOGNIZED] != 0 else ()
            ),
            f'Contains Comments: {"true" if self.contains_comments else "false"}',
            f'Normalized: {"true" if self.normalized else "false"}',
            '',
        ))

def getattrs(archive: _sem.ArchiveSink, path: str, attrs: Iterable[Union[str, _attrs.Attribute]],
        dest_path: _format.Path, *, recursive: bool, missing: str, exclude: Optional[_util.OSPathMask] = None,
        exclude_topmost: bool = False, follow_symlinks: bool = False, max_depth: int = _MAX_RECURSION_DEPTH):
    """Recursively get the attributes ``attrs`` of all files in the directory at path ``path`` and store them in
    ``archive`` under the path ``dest_path``.

    Args:
        archive: The destination archive
        path: The target path on the filesystem
        attrs: The attributes to get, in order
        dest_path: The destination path in this archive under which to store the attribute values
        recursive: Indicates if directories should be walked recursively
        missing: The action to take if a target file does not exist
        exclude: If not ``None`` and a target file's path is in this mask, it is skipped (this applies recursively)
        exclude_topmost: If ``True`` and ``path`` is a directory, its attributes are not retrieved (but it may still
                be traversed recursively)
        follow_symlinks: Indicates if symlinks at or under ``path`` should be followed
        max_depth: The maximum recursion depth (zero to only permit getting the attributes of the file at ``path``)
    Raises:
        _core.ArchivingError
        OSError:
        Exception: If raised by call to ``archive.write_record``
    """
    if not isinstance(archive, _sem.ArchiveSink):
        raise TypeError()
    path = str(path)
    try:
        attrs = [archive.attrs[attr] for attr in attrs]
    except KeyError as e:
        raise ValueError() from e
    attrs.sort()
    if not isinstance(dest_path, _format.Path):
        raise TypeError()
    dest_path = dest_path
    recursive = bool(recursive)
    max_depth = int(max_depth)
    if max_depth < 0:
        raise _core.ArchivingError('Maximum recursion depth exceeded' +
                (' (infinite symlink cycle?)' if follow_symlinks else ''))
    if exclude is not None and path in exclude:
        return
    try:
        info = os.lstat(path)
        if follow_symlinks and stat.S_ISLNK(info.st_mode):
            path = str(os.path.realpath(path)) # Note that this may still be a symlink
            if exclude is not None and path in exclude:
                return
            info = os.lstat(path)
    except FileNotFoundError:
        if missing == 'fail':
            raise _core.ArchivingError(f'target file does not exist: {path!r}') from None
        elif missing == 'ignore':
            return
        else:
            raise ValueError()
    is_dir = stat.S_ISDIR(info.st_mode) != 0
    if not is_dir or not exclude_topmost:
        for attr in attrs:
            try:
                value = attr.get_and_serialize(path, (info if attr.may_use_fs else _util.FileInfo(info)))
            except _attrs.AttributeNotApplicableError:
                continue
            archive.write_record(itertools.chain((dest_path, attr), value))
    if is_dir and recursive:
        with os.scandir(path) as dirents:
            dirents = list(dirents)
        dirents.sort(key=lambda dirent: str(dirent.name))
        for dirent in dirents:
            name = str(dirent.name)
            if name in ('', '.', '..'):
                raise OSError(f'invalid file name: {name!r}')
            entry_path = dest_path / name
            getattrs(archive, dirent.path, attrs, entry_path, recursive=recursive, missing=missing, exclude=exclude,
                    follow_symlinks=follow_symlinks, max_depth=(max_depth - 1))

def setattrs(archive: _sem.ArchiveSource, path: str, *, missing: str, create_missing_parents: bool,
        exclude: Optional[_util.OSPathMask] = None, follow_symlinks: bool = False):
    """Set all attribute values in ``archive`` to the files at or under ``path`` on the filesystem.

    Args:
        archive: The source archive
        path: The target path on the filesystem
        missing: The action to take if a target file does not exist
        create_missing_parents: Indicates if missing parent directories should be created
        exclude: If not ``None`` and a target file's path is in this mask, it is skipped (this applies recursively)
        follow_symlinks: Indicates if symlinks at or under ``path`` should be followed
    Raises:
        _core.ArchivingError
        _attrs.AttributeFormatError
        OSError
        Exception: If raised by call to ``archive.read_record``
    """
    if not isinstance(archive, _sem.ArchiveSource):
        raise TypeError()
    rootpath = str(path)
    del path
    prev_path = None
    dirty = False
    for record in archive.read_records():
        try:
            source_path = next(record)
            attr = next(record)
        except StopIteration:
            raise ValueError() from None
        attr = archive.attrs[attr]
        path = str(os.path.join(rootpath, source_path.to_ospath()))
        if attr.small:
            value = b''.join(record)
            record = iter((value,))
            value = attr.deserialize(value)
        else:
            value = None
        if path != prev_path:
            prev_path = None
            if exclude is not None and path in exclude:
                continue
            try:
                info = os.lstat(path)
                if follow_symlinks and stat.S_ISLNK(info.st_mode):
                    path = str(os.path.realpath(path)) # Note that this may still be a symlink
                    if exclude is not None and path in exclude:
                        continue
                    info = os.lstat(path)
            except FileNotFoundError as e:
                if missing == 'fail':
                    raise _core.ArchivingError(f'target file does not exist: {path!r}') from e
                elif missing == 'ignore':
                    continue
                elif missing == 'create':
                    _create_missing(archive, path, attr, value, parents=create_missing_parents)
                    info = os.lstat(path)
                else:
                    raise ValueError()
        prev_path = path
        if attr.may_use_fs and (dirty or not isinstance(info, os.stat_result)):
            info = os.lstat(path)
        try:
            new_info, dirty = attr.deserialize_and_set(path, (info if attr.may_use_fs else _util.FileInfo(info)),
                    record)
        except _attrs.AttributeNotApplicableError as e:
            raise ArchivingError(f'attribute {attr.key!r} not applicable to file {path!r}') from e
        if dirty:
            info = os.lstat(path)
        if new_info is not None:
            dirty = _set_common_attrs(path, _util.FileInfo(info), new_info)
            info = new_info

def _create_missing(path: str, attr: _attrs.Attribute, value: Any, *, parents: bool):
    if attr == _attrs.ATTR_TYPE:
        assert _attrs.ATTR_TYPE.small
        ftype = value
    elif attr == _attrs.ATTR_MODE:
        assert _attrs.ATTR_MODE.small
        ftype = _attrs.ATTR_TYPE.type_from_mode(value)
    elif attr == _attrs.ATTR_EXECUTABLE:
        ftype = _attrs.ATTR_TYPE.TYPE_REGULAR
    elif attr == _attrs.ATTR_TARGET:
        ftype = _attrs.ATTR_TYPE.TYPE_SYMLINK
    elif attr == _attrs.ATTR_CONTENTS:
        ftype = _attrs.ATTR_TYPE.TYPE_REGULAR
    elif attr in _attrs.STANDARD_HASH_ATTRS:
        ftype = _attrs.ATTR_TYPE.TYPE_REGULAR
    else:
        raise _core.ArchivingError("unable to create missing file: the file's type is not known")
    assert _attrs.ATTR_MODE.small
    mode = value if attr == _attrs.ATTR_MODE else None
    if ftype == _attrs.ATTR_TYPE.TYPE_SYMLINK:
        if attr != _attrs.ATTR_TARGET:
            raise _core.ArchivingError('unable to create missing symlink: target is not known')
        assert _attrs.ATTR_TARGET.small
        os.symlink(value, path)
    elif ftype == _attrs.ATTR_TYPE.TYPE_REGULAR:
        os.mknod(path, mode=((mode if mode is not None else 0o666) | stat.S_IFREG)) # obeys umask
    elif ftype == _attrs.ATTR_TYPE.TYPE_DIRECTORY:
        os.mkdir(path, mode=(mode if mode is not None else 0o777)) # obeys umask
    elif ftype == _attrs.ATTR_TYPE.TYPE_PIPE:
        os.mkfifo(path, mode=(mode if mode is not None else 0o666)) # obeys umask
    else:
        raise _core.ArchivingError(f'unable to create missing file: file type not supported: {ftype!r}')

def _set_common_attrs(path: str, info: _util.FileInfo, new_info: _util.FileInfo) -> bool:
    changed = False
    if new_info.mode != info.mode:
        if new_info.mode & _attrs.ATTR_TYPE.MASK != info.mode & _attrs.ATTR_TYPE.MASK:
            raise _core.ArchivingError('changing file type not permitted')
        os.lchmod(path, new_info.mode)
        changed = True
    if new_info.uid != info.uid or new_info.gid != info.gid:
        os.lchown(path, new_info.uid, new_info.gid)
        changed = True
    if new_info.size != info.size:
        raise _core.ArchivingError('changing file size not permitted')
    if new_info.atime != info.atime or new_info.mtime != info.mtime:
        os.utime(path, ns=(int(new_info.atime * 10 ** 9), int(new_info.mtime * 10 ** 9)), follow_symlinks=False)
        changed = True
    return changed

def process(sources: Iterable[_sem.ArchiveSource], sink: _sem.ArchiveSink, *, sort: bool = False,
        filter_attrs: Optional[Iterable[Union[str, _attrs.Attribute]]] = None,
        exclude: Optional[_format.PathMask] = None):
    """
    Raises:
        _attrs.AttributeFormatError
        Exception: If raised by call to ``read_record`` on any of ``sources`` or call to ``sink.write_record``
    """
    syntax = sink.syntax
    buff = _sem.MemoryArchive(semantics=sink.semantics) if sort else sink
    filter_attrs = set(buff.attrs[attr] for attr in filter_attrs) if filter_attrs is not None else None
    for source in sources:
        if source.syntax != syntax:
            raise ValueError()
        for record in source.read_records():
            try:
                path = next(record)
                attr = next(record)
            except StopIteration:
                raise ValueError()
            if exclude is not None and path in exclude:
                continue
            if filter_attrs is not None and attr in filter_attrs:
                continue
            if attr not in buff.attrs:
                raise ValueError()
            buff.write_record(itertools.chain((path, attr), record))
    if sort:
        for record in buff.read_records():
            sink.write_record(record)

def inspect(parser: _format.RawArchiveParser,
        semantics: _sem.ArchiveSemantics = _sem.STANDARD_SEMANTICS) -> 'ArchiveInfo':
    """
    Raises:
        _attrs.AttributeFormatError
        Exception: If raised by call to ``parser.read_record``
    """
    if not isinstance(parser, _format.RawArchiveParser):
        raise TypeError()
    if not isinstance(semantics, _sem.ArchiveSemantics):
        raise TypeError()
    if parser.syntax != semantics.syntax:
        raise ValueError()
    n_records = 0
    n_paths = 0
    n_implicit_dirs = 0
    n_records_by_attr = {attr: 0 for attr in semantics.attrs}
    normalized = True
    files = _format.PathMap()
    prev_path = None
    prev_attr = None
    for record in parser.read_records():
        try:
            path = next(record)
            name = str(next(record))
        except StopIteration:
            raise ValueError()
        try:
            attr = semantics.attrs[name]
        except KeyError:
            raise _sem.ArchiveSemanticsError(f'unrecognized attribute name {name!r}') from None
        n_records += 1
        new_path, ftype, implicit_parents = files.setdefault_and_parents(path, ArchiveInfo.TYPE_UNKNOWN, None)
        if new_path:
            n_paths += 1
        n_implicit_dirs += implicit_parents
        if ftype == ArchiveInfo.TYPE_UNKNOWN:
            if attr == _attrs.ATTR_TYPE:
                ftype = _attrs.ATTR_TYPE.deserialize(b''.join(record))
            elif attr == _attrs.ATTR_MODE:
                try:
                    ftype = _attrs.ATTR_TYPE.type_from_mode(_attrs.ATTR_MODE.deserialize(b''.join(record)))
                except OSError:
                    ftype = ArchiveInfo.TYPE_UNRECOGNIZED
            elif attr == _attrs.ATTR_EXECUTABLE:
                ftype = _attrs.ATTR_TYPE.TYPE_REGULAR
            elif attr == _attrs.ATTR_TARGET:
                ftype = _attrs.ATTR_TYPE.TYPE_SYMLINK
            elif attr == _attrs.ATTR_CONTENTS:
                ftype = _attrs.ATTR_TYPE.TYPE_REGULAR
            elif attr in _attrs.STANDARD_HASH_ATTRS:
                ftype = _attrs.ATTR_TYPE.TYPE_REGULAR
            if ftype != ArchiveInfo.TYPE_UNKNOWN:
                files[path] = ftype
        n_records_by_attr[attr] += 1
        if normalized and (
            attr.key != name or
            parser.seen_comments() or (
                prev_path is not None and (
                    prev_path > path or (
                        prev_path == path and
                        prev_attr >= attr
                    )
                )
            )
        ): normalized = False
        prev_path = path
        prev_attr = attr
    n_paths_by_ftype = {
        ftype: 0 for ftype in (*_attrs.ATTR_TYPE.TYPES, ArchiveInfo.TYPE_UNKNOWN, ArchiveInfo.TYPE_UNRECOGNIZED)
    }
    for ftype in files.values():
        if ftype is not None:
            n_paths_by_ftype[ftype] += 1
    return ArchiveInfo(
        semantics,
        n_records=n_records,
        n_paths=n_paths,
        n_implicit_dirs=n_implicit_dirs,
        n_records_by_attr=n_records_by_attr,
        n_paths_by_ftype=n_paths_by_ftype,
        contains_comments=parser.seen_comments(),
        normalized=normalized,
    )
