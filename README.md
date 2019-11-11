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

# stat-archiver 0.8.0

[![PyPI](https://img.shields.io/pypi/v/statar?color=blue)](https://pypi.org/project/statar/)
[![documentation](https://img.shields.io/badge/docs-read%20now-blue)](doc/documentation.md)
[![develop branch ahead by](https://img.shields.io/github/commits-since/parkerhoyes/stat-archiver/latest/develop?color=red&label=develop%20branch%20ahead%20by)](https://github.com/parkerhoyes/stat-archiver/tree/develop)

stat-archiver (or `statar`) is a command-line utility which can:

- read the file attributes (timestamps, permissions, owner, etc.) of each file
  in a directory tree recursively and output them in a deterministic text-based
  format, and
- read the previous output of the utility and write the attributes back to the
  filesystem, changing the files' attributes or creating missing files as
  necessary.

The file format used by `statar` is text-based, human-readable, and easy to
manipulate (one line per attribute per file).

To summarize, this tool is sort of like `tar`, except it has a text-based file
format and it's intended to only archive the attributes of files, not their
contents (though it can actually [store file contents][Documentation: Storing
File Contents] if you really want to).

stat-archiver is written in Python and has a CLI and a Python API (it can be
used from the command-line, or imported as a Python library).

This tool's only dependency is Python 3.6+.

[Documentation: Storing File Contents]: doc/documentation.md#storing-file-contents

## Features

- Supported file attributes: file type, mode, owners, timestamps, permissions,
  size, etc.
- Write a `statar` archive back to the filesystem, updating file attributes and
  creating missing files as necessary
- Deterministic output (records in the archive are sorted)
- Text-based, human-readable, easy to manipulate file format (one line per
  attribute per file)
- Support for Unix and Windows
- Extensive Python API which allows you to use the tool or customize it (eg. add
  your own attributes or customize the file format syntax)
- Optimized for processing very large numbers of files

stat-archiver also has a number of other useful features for more specific use
cases, for example:

- Attributes which only store sub-fields of the `mode` bit field when less
  detail is required (`perms`, `executable`, `suid`, etc.)
- Store hashes of file contents in a `statar` archive, and later check them
  against the contents of the files on the filesystem (like `sha256sum`, but
  supports recursively traversing directories)
- Archives can be merged by simply concatenating them together (if you want to
  sort them so the ordering is deterministic, use the `process` subcommand)
- Filter records in an archive by attribute or path using the `process`
  subcommand
- Store the contents of files using the `contents` attribute (however, use of
  this is discouraged unless you have a really good reason not to simply use
  `tar` or something similar, see
  [here][Documentation: Storing File Contents] for details)

## Planned Features

The following features are currently planned to be added before version 1.0:

- Reading from `tar` archives
- Getting attributes from a file descriptor
- Multithreading

If you have any feature suggestions, feel free to contact me or open an issue
[on GitHub](https://github.com/parkerhoyes/stat-archiver).

## Limitations

- No support for extended attributes (yet!)
- stat-archiver is not intended to be used to store the contents of files, so if
  you need to do that too you should probably use one of the many other archive
  tools (like `tar`). You can always use `statar` in addition to `tar` if you
  want to make use of `statar`'s better handling of file attributes. (You can
  actually store file contents using the `contents` attribute, but there are
  some performance drawbacks, see
  [here][Documentation: Storing File Contents] for details.)
- This project is still in beta. The CLI and Python APIs are likely to change
  frequently.

## Alternatives

Err, `find -exec stat {} \;`?

There are lots of ways to get file attributes. However, stat-archiver's main
selling point is that it reports attributes in an easy to manipulate text-based
format and can parse this format and write attributes back to the filesystem. To
my knowledge, there is no other tool which works quite like this (if you're
aware of any, please let me know).

## Documentation

See [`doc/documentation.md`](doc/documentation.md) for a big-picture description
of how the tool works and [`doc/reference.md`](doc/reference.md) for
command-line options and a list of supported attributes.

## Example

### Getting Attributes

```
$ mkdir -p hello/world
$ ln -s /home/ hello/home
$ echo -e '#!/usr/bin/env bash\necho bar' > hello/world/foo
$ chmod +x hello/world/foo
$ echo 'Interesting stuff' > notes.txt
$ statar get -r --attrs type,exec,target,mtime,contents,sha256 hello notes.txt
hello:type:directory
hello:mtime:1442224245
hello/home:target:/home/
hello/home:type:symbolic link
hello/home:mtime:1442224245
hello/world:type:directory
hello/world:mtime:1442224245
hello/world/foo:type:regular file
hello/world/foo:executable:true
hello/world/foo:mtime:1442224245
hello/world/foo:contents:\x23!/usr/bin/env bash\necho bar\n
hello/world/foo:SHA2-256:3cecf5f65c15fa8f9481dce708e0b99a92f40642dd1464e01a4bee87db808f35
notes.txt:type:regular file
notes.txt:executable:false
notes.txt:mtime:1442224245
notes.txt:contents:Interesting stuff\n
notes.txt:SHA2-256:2c79a79f9bd3880984320d220b002a17acd1998081eff661b32fc16ee3b24431
```

### Setting Attributes

If the output of a `statar get ...` command were saved to the file
`archive.statar`, you could recreate the files like so:

```
statar set archive.statar
```

## Installation

stat-archiver requires you have Python 3.6+ installed.

You can install this package from PyPI like so:

```
pip3 install statar
```

The `statar` command will then be available on your PATH.

You can also install it from source like so:

```
git clone https://github.com/parkerhoyes/stat-archiver
cd stat-archiver/
pip3 install .
```

The `./install-here` script will install this package in a new Python [virtual
environment](https://docs.python.org/3/tutorial/venv.html) in the repository
root which is useful for portable installations or for testing during
development.

## Release Cycle and Changelog

This project's versioning scheme will adhere to [Semantic Versioning
2.0.0](http://semver.org/). Command-line options, the archive file format, and
the Python API will be considered part of stat-archiver's public API.

The release notes and changelog for this project is maintained [on
GitHub](https://github.com/parkerhoyes/stat-archiver/releases).

## Contributing

Contributions are welcome. See [`doc/development.md`](doc/development.md).

## License

This software is licensed under the terms of the very permissive [Zlib
License](https://opensource.org/licenses/Zlib). The exact text of this license
is reproduced in the [`LICENSE.txt`](LICENSE.txt) file.

## Some Neat Use Cases

### Checksum an Entire Directory Tree

stat-archiver has special attributes for computing hashes of the contents of
files.

Here's an example of using `statar` to get the hashes of the files in a
directory at `path/` which contains the files `file1.txt` and `file2.txt` whose
contents are `Hello, world!` and `Goodbye, world!`, respectively:

```
$ statar get -r --attrs sha256 path/
path/file1.txt:SHA2-256:315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3
path/file2.txt:SHA2-256:a6ab91893bbd50903679eb6f0d5364dba7ec12cd3ccc6b06dfb04c044e43d300
```

By also adding other attributes to the above command (such as `type`, `perms`,
`mtime`, etc.) we can create an archive of the file data that we'd like to hash.
Then, we can pass that `statar` archive to the `sha256sum` command or something
similar to get a hash of the entire directory. This works because the archive
format is deterministic.

For example, to create a checksum:

```
statar get -r --attrs type,perms,sha256 path/ | sha256sum - > sha256sum.txt
```

And to validate the checksum:

```
statar get -r --attrs type,perms,sha256 path/ | sha256sum -c sha256sum.txt
```

`statar` will also let you validate checksums of individual files by using the
`set` subcommand. For example, if we run `statar set ''` (the empty string tells
`statar` to read from stdin) and we give it the following input:

```
path/file1.txt:SHA2-256:315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3
path/file2.txt:SHA2-256:a6ab91893bbd50903679eb6f0d5364dba7ec12cd3ccc6b06dfb04c044e43d300
```

then `statar` will calculate the hashes of `path/file1.txt` and `path/file2.txt`
and it will exit with a non-zero status code if any of the hashes didn't match.
`statar` has similar behavior for the `type` and `size` attributes: it will fail
if the destination file's type or size doesn't match what's stored in the
archive. This can be useful for speeding up verifying a checksum: if you include
`size` and `sha256` attributes in an archive, the command will check the `size`
first, which is faster than having to compute the entire SHA256 hash (however,
it will still have to compute the hash if the size matches).

### Diff Directory Trees

The `statar` archive format is text-based, so other utilities which operate on
text input can be used to analyze `statar` archives. This makes it easy to use
`statar` to compare two directory trees.

For example, to compare the contents of the directories `a/` and `b/` in the
current working directory and see differences in structure only, you can do the
following:

```
statar -C a/ get -r --attrs type . > a.statar
statar -C b/ get -r --attrs type . > b.statar
diff a.statar b.statar
```

This works because the statar archive format is deterministic, so the order of
records in the archive will always be the same.

Of course, you can also compare differences in whatever file attributes you
want, or by contents using hashes as described in the previous section.

### Track File Attributes in a Git Repository

`git` only tracks the names, contents, and executability of files in a
repository. Additionally, empty directories are ignored completely. By including
a `statar` archive in a git repository, extra information about the files in the
repository that git would otherwise ignore can also be tracked. Changes to the
file attributes will appear as changes in the statar archive in git diffs. Since
the `statar` archive format is text-based, diffs of these archives will be
human-readable, and git should be able to merge changes to `statar` archives
automatically in most cases.

The downside is that the `statar` archive in the repository must be updated
before each commit, and it must be read back and applied to the files in the
repository after a checkout. However, this can be easily automated using [git
hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks).

To create a `statar` archive in the root of your repository which includes file
attributes of all files in the repository:

```
# Execute from the root of the repository
statar get -r --exclude-topmost -o .fileattrs.statar .
```

To read the attributes from the archive and set them on all files in the
repository (after doing a `git checkout`, for example), use the following
command. **This will also create empty directories which were saved in the
archive but git did not create.**

```
# Execute from the root of the repository
statar set --missing=create .fileattrs.statar
```

Note that you'll probably want to use the `--attrs` option when creating the
archive to customize which attributes will be saved for your use case rather
than using the defaults. For example, you probably won't want to save `uid` or
`gid`.

Setting up a git hook to perform these commands automatically is relatively
easy. Simply create the following scripts in your local git repository and
remember to make them executable with `chmod +x`.

`.git/hooks/pre-commit`

```
#!/usr/bin/env bash
statar get -r --exclude-topmost -o .fileattrs.statar .
```

`.git/hooks/post-checkout`

```
#!/usr/bin/env bash
statar set --missing=create .fileattrs.statar
```

Note that **git hooks are not checked into the repository**, so everyone who
clones your repository will have to add the same hooks if they want to
automatically track changes to file attributes.
