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

# stat-archiver Documentation

stat-archiver (or `statar`) is a command-line utility for archiving file
attributes in a deterministic, text-based, human-readable, and easy to
manipulate file format.

stat-archiver is not intended to store the contents of files like most archiving
tools, but you can if you really want to (see [Storing File Contents]).

See [`reference.md`][Reference] for command-line usage information and a list of
supported attributes.

It is strongly recommended to run this tool with Python optimization enabled
(specify `python -O` or set `PYTHONOPTIMIZE`) as this significantly improves
performance (the implementation uses a lot of performance-heavy assertions to
assist with debugging). The `statar` command you get when installing this
package (at `src/scripts/statar`) does this.

[Storing File Contents]: #storing-file-contents
[Reference]: reference.md

## Operations

stat-archiver currently supports four operations (which each have their own
subcommand):

- `get`: Get attributes from filesystem, write to archive
- `set`: Read attributes from zero or more archives, set them on the filesystem
- `process`: Process archives (merge, sort, filter, etc.)
- `inspect`: Get statistics on zero or more archives

Getting and setting are not necessarily perfect inverses of each other. See
[`reference.md`][Reference] for the exact behavior of each attribute for `get`
and `set`.

### `get`

When getting attributes, `statar` will try to minimize the number of syscalls
necessary. It will also attempt to handle concurrent modification gracefully.
The result of the `get` command is always deterministic, and the returned
archive is always [normalized][Normalization], except comments are added if you
used `--annotate`.

The `get` operation is implemented with an [online algorithm][Wikipedia: Online
Algorithm], meaning it does not need to buffer the archive data (except for
listing the files in each directory it traverses). Therefore, this operation has
roughly constant auxiliary space complexity (memory usage). Worst-case time
complexity varies between _O(n)_ and _O(n log n)_ depending on various factors.
Resource usage generally shouldn't be a problem unless you have a very flat
directory structure (on the order of hundreds of thousands of entries in a
single directory, not including files in subdirectories).

[Normalization]: #normalization
[Wikipedia: Online Algorithm]: https://en.wikipedia.org/wiki/Online_algorithm

### `set`

When setting attributes, `statar` simply reads the archive and processes one
record (one line) at a time, in order. It will minimize the number of syscalls
necessary by processing records for the same path that appear next to each other
in the archive together. A `statar` archive is sort of like a sequence of
instructions telling `statar` what attributes to change on the filesystem. If a
file named in the archive is missing and `--missing=create`, it will attempt to
create the file _using only information in the first record it encounters with
the file's path_. This means that if the first record referencing a missing file
is, for example, `permissions`, then `statar` will not be able to create the
file because the `permissions` attribute does not contain information about the
file type, so the command will fail. It also means that when recreating
symlinks, the first record for the symlink must be `target`, because you can't
usually create a symlink without knowing the target path. This limitation
shouldn't usually be a problem, because [normalized][Normalization] archives are
always sorted in such a way to make sure that the records containing information
necessary to recreate the file appear before any other records for a specific
path (this is why the `target` attribute always appears first).

The `set` operation scans the archive from start to finish and does not buffer
its input, and therefore has constant auxiliary space complexity (memory usage)
and linear time complexity.

If you use the `contents` attribute as well as a hash attribute (eg. `sha256`),
`statar` will write the file then read it back to check the hash when using the
`set` subcommand.

### `process`

Read the input archives, filter records by attribute or path as specified, sort
and merge records if `--sort` is specified, then output the resulting archive.
Comments and empty lines are removed. If `--sort` is specified, the resulting
archive is guaranteed to be normalized; otherwise, the ordering of records in
the resulting archive is the same as in the input.

The resource utilization of the `process` operation depends on whether or not
`--sort` is specified.

When sorting, the current implementation of the `process` operation buffers the
input archives in memory. Care should therefore be taken when passing very large
archives as input as they have to be entirely buffered in memory. This shouldn't
be a problem unless you're dealing with a very large number of files, or you
have low memory available, or the archive contains file contents. `process` with
`--sort` has linear auxiliary space complexity (memory usage) and the worst-case
time complexity varies between _O(n)_ and _O(n log n)_ depending on various
factors.

When `--sort` is not specified, `process` is implemented with an [online
algorithm][Wikipedia: Online Algorithm] and does not buffer its input. It
therefore has constant memory usage and linear time complexity.

### `inspect`

Get statistics about the input archives, including whether or not they are
normalized.

The `inspect` operation has linear auxiliary space complexity w.r.t. the number
of unique paths in the archive, and linear time complexity. This operation
buffers the paths it encounters in the archive, but not any attributes or
attribute values. The paths are stored in a prefix tree which is particularly
memory efficient for deep directory trees.

## Archive File Format

stat-archiver archives are simply text files with one record per line. Archives
do not contain headers, version numbers, or any other kind of metadata.

Here are a few details about the file format:

- Absolute paths, or paths that end with `/`, are not permitted.
- Paths which contain the components `.` or `..` are not permitted, unless the
  entire path is `.`.
- Archives are always ASCII-only. Control characters (excluding linefeed) are
  not permitted, even in comments.
- If paths or attribute values contain non-ASCII characters, control characters,
  or special characters (`:`, `/`, `\`, or `#`), they will be escaped as
  necessary (like so: `\xff`).
- Paths are stored UTF-8 encoded and using `/` as the path separator, regardless
  of platform.
- Empty lines in the archive will be ignored. The archive must end in an empty
  line.
- All text after a `#` character on a line is ignored.
- Trailing whitespace on a line is not stripped, nor is whitespace before
  comments. You should therefore be careful if you include comments that the
  `#` character is the first character on the line or that it follows
  immediately after the attribute value.
- If the `:` character appears in a path, it is escaped as `\x3a`, and if the
  `#` character appears in a path or an attribute value, it is escaped as
  `\x23`, which means you can always get the path, attribute name, and value of
  a record using the regex `(.*?):(.*?):(.*?)(#.*)?\n`.
- If the `/` character appears in a file name, it is escaped as `\x2f`, which
  means you can get the components of a path by splitting it by the `/`
  character.

## Normalization

The result of the `get` operation is always deterministic. This means the
resulting archive will always be the same as long as the attributes, contents,
and directory structures of the target files no not change for a given command.
This is because the resulting archive is "normalized" - no irrelevant
information is included in the archive. This means, for example, records in the
output archive must be sorted, or else it would depend on the order in which
directory entries were returned to `statar` by the operating system (which is
not deterministic). The comments generated if `--annotate` is used are also
deterministic.

An archive is considered "normalized" if it could have been the output of the
`get` command without `--annotate` specified. If you concatenate multiple
archives together, or reorder records in an archive, the result may not be
normalized.

An archive in non-normal form can be normalized using the `process --sort`
command. The `inspect` command will tell you whether or not an existing archive
is normalized.

## Storing File Contents

Theoretically, if you use the `contents` attribute, stat-archiver behaves more
or less like a regular file archiving utility. The `get` subcommand corresponds
to creating an archive, and the `set` subcommand corresponds to extracting an
archive. Additionally, `statar`'s handling of file attributes makes it more
configurable than most other archiving utilities because you can pick and choose
which file attributes you'd like to store in the archive.

However, **storing the contents of large files is not stat-archiver's intended
use case**.

The file format was designed to be text-based, human-readable, and easy to
manipulate. Hence, stat-archiver is not well optimized for storing large files
(especially non-text files). The current implementation was designed to handle
large files gracefully, so you shouldn't encounter any instability, you will
simply notice slow read / write speed compared to, for example, `tar`.

The main reason the stat-archiver file format is less efficient for storing
large binary files is that the file format is ASCII-only, so non-ASCII or
control characters will be escaped (like so: `\xff`). This means if you have
large files that contain mostly non-ASCII or control characters, the size of the
archive could be multiplied by a factor of four. Escaping characters also slows
down read / write speed and increases CPU usage compared to `tar`.

Adding support for a binary-optimized file format would solve all of the above
problems, but since stat-archiver isn't intended for this use case, adding that
feature is not currently planned.
