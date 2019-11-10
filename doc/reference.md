<!--
License for stat-archiver, originally found here:
https://github.com/parkerhoyes/stat-archiver

Copyright (C) 2019 Parker Hoyes <contact@parkerhoyes.com>

This software is provided "as-is", without any express or implied warranty. In
no event will the authors be held liable for any damages arising from the use of
this software.

Permission is granted to anyone to use this software for any purpose, including
commercial applications, and to alter it and redistribute it freely, subject to
the following restrictions:

1. The origin of this software must not be misrepresented; you must not claim
   that you wrote the original software. If you use this software in a product,
   an acknowledgment in the product documentation would be appreciated but is
   not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
-->

# stat-archiver Reference Manual

Also see [`documentation.md`](documentation.md) for more details.

The help text of the `statar` command is included here for convenience.

`statar --help`

```
usage: statar [-h] [--version] [-v {silent,critical,error,warning,info,debug}]
              [-C path] [--profile path]
              {get,set,process,inspect} ...

This utility provides tools for getting, setting, and serializing the
attributes of files or of directory trees recursively.

optional arguments:
  -h, --help            Print usage information and exit
  --version             Print version information and exit
  -v {silent,critical,error,warning,info,debug}, --verbosity {silent,critical,error,warning,info,debug}
                        Set logging verbosity
  -C path, --root path  Change to this directory before performing any
                        operations; this option is NOT order-sensitive, all
                        relative paths provided will be relative to this path
  --profile path        Profile the tool using cProfile and save the
                        statistics to the specified path (use an empty string
                        for stderr); this option is not part of the public API
                        and may be removed or changed at any time

subcommands:
  {get,set,process,inspect}
    get                 get attributes
    set                 set attributes
    process             process archive(s)
    inspect             inspect archive
```

`statar get --help`

```
usage: statar ... get [-h] [-o path] [-r] [-a attrs] [-n attrs]
                      [-m {fail,ignore}] [-x path] [-X path]
                      [--exclude-topmost] [-L] [-p path] [-t]
                      [target [target ...]]

Get attributes from the specified files and write them to an archive. The
resulting archive will be normalized (unless --annotate is used). If neither
--attrs nor --not-attrs is used, the default attributes (mode, uid, gid,
mtime) are assumed.

positional arguments:
  target                Target paths

optional arguments:
  -h, --help            Print usage information and exit
  -o path, --output path
                        Write archive to this file; use an empty string for
                        stdout (default)
  -r, --recursive       Walk target paths which are directories recursively
  -a attrs, --attrs attrs
                        A comma-separated list of attributes to get
                        (subsequent usages add attributes, order sensitive
                        with --not-attrs)
  -n attrs, --not-attrs attrs
                        A comma-separated list of attributes NOT to get
                        (subsequent usages remove attributes, order sensitive
                        with --attrs)
  -m {fail,ignore}, --missing {fail,ignore}
                        The action to take for target paths which do not exist
  -x path, --exclude path
                        Don't get the attributes of the file at the specified
                        path
  -X path, --exclude-recursive path
                        Don't get the attributes of the children of the
                        directory (or symlink) at the specified path
  --exclude-topmost     Don't get the attributes of the topmost directory when
                        recursively descending a directory
  -L, --follow-symlinks
                        Follow symbolic links (default is to not follow
                        symlinks)
  -p path, --prefix path
                        A path to prefix the results with in the archive
  -t, --annotate        Add comments to some records with more human-readable
                        descriptions of the attribute values
```

`statar set --help`

```
usage: statar ... set [-h] [-m {fail,ignore,create}] [-p] [-x path] [-X path]
                      [-L]
                      [input [input ...]]

Read the specified archives, in order, one record at a time, and write each
record to the filesystem by setting attributes (and creating missing files if
--missing=create) as necessary.

positional arguments:
  input                 Read archives from these files; use an empty string
                        for stdin

optional arguments:
  -h, --help            Print usage information and exit
  -m {fail,ignore,create}, --missing {fail,ignore,create}
                        The action to take for target paths which do not exist
  -p, --parents         Create missing parent directories (their permissions
                        will be 0o777 ^ umask); this only has an effect if
                        --missing=create
  -x path, --exclude path
                        Don't get the attributes of the file at the specified
                        path
  -X path, --exclude-recursive path
                        Don't get the attributes of the children of the
                        directory (or symlink) at the specified path
  -L, --follow-symlinks
                        Follow symbolic links (default is to not follow
                        symlinks)
```

`statar process --help`

```
usage: statar ... process [-h] [-o path] [-s] [-a attrs] [-x path] [-X path]
                          [-t]
                          [input [input ...]]

Read the specified archives, perform the specified transformations on them,
then output the resulting archive. Comments and empty lines are removed. If
--sort is specified, the resulting archive is guaranteed to be normalized;
otherwise, the ordering of records in the result is the same as in the input.
When using --sort, care should be taken when passing very large archives as
input as they have to be entirely buffered in memory (although, the in-memory
representation is usually much more space efficient than the archive file
format). This shouldn't be a problem unless you're dealing with a very large
number of files, or you have low memory available, or the archive contains
file contents.

positional arguments:
  input                 Read archives from these files; use an empty string
                        for stdin

optional arguments:
  -h, --help            Print usage information and exit
  -o path, --output path
                        Write archive to this file; use an empty string for
                        stdout (default)
  -s, --sort            Sort the records in the archive and remove records for
                        the same path and attribute (the value of the last
                        occuring record in the input is used); if specified,
                        the result is guaranteed to be normalized
  -a attrs, --attrs attrs
                        A comma-separated list of attributes; if specified,
                        only the records which specify these attributes will
                        be included in the result
  -x path, --exclude path
                        Filter out records with this path
  -X path, --exclude-recursive path
                        Filter out records whose path is a (non-strict)
                        subpath of this path
  -t, --annotate        Add comments to some records with more human-readable
                        descriptions of the attribute values
```

`statar inspect --help`

```
usage: statar ... inspect [-h] [input [input ...]]

Read the specified archives, then print statistics about them to stdout.

positional arguments:
  input       Read archives from these files; use an empty string for stdin

optional arguments:
  -h, --help  Print usage information and exit
```

## Supported Attributes

Attribute names are not case-sensitive. Attributes will always be stored in the
archive in the order they're listed below.

### `target`

When **getting**, this reads the target of symbolic links and stores it UTF-8
encoded (note that non-ASCII characters, control characters, and the `#`
character will be escaped). For files that are not symbolic links, the file is
skipped (no record is stored).

When **setting**, this replaces the symlink with a new symlink with the new
target, or leaves the existing symlink if the target is the same. File
attributes are preserved (by resetting them afterwards). If the target is not a
symbolic link, this fails.

### `type`

When **getting**, this gets the file type and stores it as one of the following
values: `socket`, `symbolic link`, `regular file`, `block device`, `directory`,
`character device`, `pipe`, `door`, `event port`, or `whiteout`.

When **setting**, this will fail if the file type does not match.

### `mode`

When **getting**, this gets the file mode and stores it as an octal number. This
encodes the file type, SUID bit, SGID bit, sticky bit, and file permissions.

When **setting**, this fails if the file type does not match, but otherwise sets
all other mode bits (using `chmod`).

### `suid`

When **getting**, this gets the set-user-ID bit and stores it as `true` or
`false`.

When **setting**, this sets the set-user-ID bit (using `chmod`).

### `sgid`

When **getting**, this gets the set-group-ID bit and stores it as `true` or
`false`.

When **setting**, this sets the set-group-ID bit (using `chmod`).

### `sticky`

When **getting**, this gets the sticky bit and stores it as `true` or `false`.

When **setting**, this sets the sticky bit (using `chmod`).

### `permissions` (aliases: `perms`)

When **getting**, this gets all nine permission bits and stores them as an octal
number.

When **setting**, this sets the permission bits (using `chmod`).

### `readable` (aliases: `read`)

When **getting**, this gets all three readable permission bits and stores `true`
if any of them are set, or `false` otherwise.

When **setting**, this sets all three readable permission bits *masked by the
current umask* if `true`, or unsets all three bits if `false` (using `chmod`).

### `writable` (aliases: `write`)

When **getting**, this gets all three writable permission bits  and stores
`true` if any of them are set, or `false` otherwise.

When **setting**, this sets all three writable permission bits *masked by the
current umask* if `true`, or unsets all three bits if `false` (using `chmod`).

### `executable` (aliases: `exec`)

When **getting**, this gets all three executable permission bits  and stores
`true` if any of them are set, or `false` otherwise.

When **setting**, this sets all three executable permission bits *masked by the
current umask* if `true`, or unsets all three bits if `false` (using `chmod`).

### `uid`

When **getting**, this gets the user owner ID and stores it as a number.

When **setting**, this sets the user owner ID (using `chown`).

### `gid`

When **getting**, this gets the group owner ID and stores it as a number.

When **setting**, this sets the group owner ID (using `chown`).

### `atime`

When **getting**, this gets the time of most recent access, possibly accurate
down to the nanosecond, and stores it as a decimal number in seconds.

When **setting**, this sets the time of most recent access (using `utime`).

### `mtime`

When **getting**, this gets the time of most recent content modification,
possibly accurate down to the nanosecond, and stores it as a decimal number in
seconds.

When **setting**, this sets the time of most recent content modification.

### `ctime`

When **getting**, this gets:

- the time of most recent metadata change on Unix (using `stat`), or
- the time of creation on Windows,

possibly accurate down to the nanosecond, and stores it as a decimal number in
seconds.

When **setting**, this attribute does nothing.

### `size`

When **getting**, this gets:

- the size of the file in bytes for regular files, or
- the size of the target in bytes for symbolic links,

or, for targets that are not regular files or symbolic links, the target is
skipped (no record is stored).

When **setting**, this fails if the file's size does not match or if the target
is not a regular file or a symbolic link.

### `contents`

When **getting**, this reads the entire contents of the file and stores it as-is
(note that non-ASCII characters, non-printable characters, and the `#` character
will be escaped). For targets that are not regular files, the target is skipped
(no record is stored).

When **setting**, this writes the contents to the file, replacing any existing
contents completely. File attributes are preserved (by resetting them
afterwards). If the target is not a regular file, this fails.

### `SHA2-256` (aliases: `SHA-256`, `SHA256`)

When **getting**, this reads the entire contents of the file, hashes it using
SHA-256, and stores the hash hex-encoded. For targets that are not regular
files, the target is skipped (no record is stored).

When **setting**, this reads the entire contents of the target file, hashes it
using SHA-256, and fails if the hashes do not match. If the target is not a
regular file, this fails.

### `BLAKE2b-512` (aliases: `BLAKE2b`)

Same as `SHA2-256`, but uses BLAKE2b-512.
