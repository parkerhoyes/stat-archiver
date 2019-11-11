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

"""This module contains the implementation of the front-end command-line utility for stat-archiver."""

import argparse
import logging
import os
import sys

from . import _attrs
from . import _core
from . import _format
from . import _ops
from . import _sem
from . import _util
from . import version

LOGGER = logging.getLogger(__name__)

PROG = 'statar'

def main():
    sys.exit(run(*sys.argv[1:]))

def run(*args):
    return Application().run(args)

class ApplicationExit(Exception):
    def __init__(self, *args, status: int, **kwargs):
        super().__init__(*args, **kwargs)
        self.status = int(status)

class ApplicationSuccess(ApplicationExit):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, status=0, **kwargs)

class ApplicationError(ApplicationExit):
    def __init__(self, *args, status: int = 1, **kwargs):
        super().__init__(*args, status=status, **kwargs)

class ApplicationUsageError(ApplicationError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, status=2, **kwargs)

class ApplicationArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ApplicationUsageError(str(message))

class _HelpAction(argparse.Action):
    def __init__(self, option_strings, *, dest, help=None):
        super().__init__(option_strings, dest=dest, nargs=0, help=help)
    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_help()
        raise ApplicationSuccess()

class _VersionAction(argparse.Action):
    def __init__(self, option_strings, *, dest, help=None):
        super().__init__(option_strings, dest=dest, nargs=0, help=help)
    def __call__(self, parser, namespace, values, option_string=None):
        print(f'{PROG} {version.VERSION_STR}')
        raise ApplicationSuccess()

ARGPARSER = ApplicationArgumentParser(prog=PROG, allow_abbrev=False, add_help=False, description='''
This utility provides tools for getting, setting, and serializing the attributes of files or of directory trees
recursively.
''')
ARGPARSER.add_argument('-h', '--help', action=_HelpAction, help='Print usage information and exit')
ARGPARSER.add_argument('--version', action=_VersionAction, help='Print version information and exit')
ARGPARSER.add_argument('-v', '--verbosity', choices=('silent', 'critical', 'error', 'warning', 'info', 'debug'),
        default='info', help='Set logging verbosity')
ARGPARSER.add_argument('-C', '--root', default=None, metavar='path',
        help='Change to this directory before performing any operations; this option is NOT order-sensitive, all \
relative paths provided will be relative to this path')
ARGPARSER.add_argument('--profile', default=None, metavar='path',
        help='Profile the tool using cProfile and save the statistics to the specified path (use an empty string for \
stderr); this option is not part of the public API and may be removed or changed at any time')
SUBARGPARSERS = ARGPARSER.add_subparsers(dest='subcommand', title='subcommands')

class _AttrsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if not hasattr(namespace, 'attrs') or namespace.attrs is None:
            namespace.attrs = []
        namespace.attrs.append((True, values))

class _NotAttrsAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if not hasattr(namespace, 'attrs') or namespace.attrs is None:
            namespace.attrs = []
        namespace.attrs.append((False, values))

ARGPARSER_GET = SUBARGPARSERS.add_parser('get', prog=f'{PROG} ... get', allow_abbrev=False, add_help=False,
        help='get attributes', description='''
Get attributes from the specified files and write them to an archive. The resulting archive will be normalized (unless
--annotate is used). If neither --attrs nor --not-attrs is used, the default attributes (mode, uid, gid, mtime) are
assumed.
''')
ARGPARSER_GET.add_argument('-h', '--help', action=_HelpAction, help='Print usage information and exit')
ARGPARSER_GET.add_argument('-o', '--output', default='', metavar='path',
        help='Write archive to this file; use an empty string for stdout (default)')
ARGPARSER_GET.add_argument('-r', '--recursive', action='store_true',
        help='Walk target paths which are directories recursively')
ARGPARSER_GET.add_argument('-a', '--attrs', action=_AttrsAction, metavar='attrs',
        help='A comma-separated list of attributes to get (subsequent usages add attributes, order sensitive with \
--not-attrs)')
ARGPARSER_GET.add_argument('-n', '--not-attrs', action=_NotAttrsAction, metavar='attrs',
        help='A comma-separated list of attributes NOT to get (subsequent usages remove attributes, order sensitive \
with --attrs)')
ARGPARSER_GET.add_argument('-m', '--missing', choices=('fail', 'ignore'), default='fail',
        help='The action to take for target paths which do not exist')
ARGPARSER_GET.add_argument('-x', '--exclude', action='append', metavar='path',
        help="Don't get the attributes of the file at the specified path")
ARGPARSER_GET.add_argument('-X', '--exclude-recursive', action='append', metavar='path',
        help="Don't get the attributes of the children of the directory (or symlink) at the specified path")
ARGPARSER_GET.add_argument('--exclude-topmost', action='store_true',
        help="Don't get the attributes of the topmost directory when recursively descending a directory")
ARGPARSER_GET.add_argument('-L', '--follow-symlinks', action='store_true',
        help='Follow symbolic links (default is to not follow symlinks)')
ARGPARSER_GET.add_argument('-p', '--prefix', metavar='path', default=None,
        help='A path to prefix the results with in the archive')
ARGPARSER_GET.add_argument('-t', '--annotate', action='store_true',
        help='Add comments to some records with more human-readable descriptions of the attribute values')
ARGPARSER_GET.add_argument('targets', nargs='*', metavar='target', help='Target paths')

ARGPARSER_SET = SUBARGPARSERS.add_parser('set', prog=f'{PROG} ... set', allow_abbrev=False, add_help=False,
        help='set attributes', description='''
Read the specified archives, in order, one record at a time, and write each record to the filesystem by setting
attributes (and creating missing files if --missing=create) as necessary.
''')
ARGPARSER_SET.add_argument('-h', '--help', action=_HelpAction, help='Print usage information and exit')
ARGPARSER_SET.add_argument('-m', '--missing', choices=('fail', 'ignore', 'create'), default='fail',
        help='The action to take for target paths which do not exist')
ARGPARSER_SET.add_argument('-p', '--parents', action='store_true',
        help='Create missing parent directories (their permissions will be 0o777 ^ umask); this only has an effect if \
--missing=create')
ARGPARSER_SET.add_argument('-x', '--exclude', action='append', metavar='path',
        help="Don't get the attributes of the file at the specified path")
ARGPARSER_SET.add_argument('-X', '--exclude-recursive', action='append', metavar='path',
        help="Don't get the attributes of the children of the directory (or symlink) at the specified path")
ARGPARSER_SET.add_argument('-L', '--follow-symlinks', action='store_true',
        help='Follow symbolic links (default is to not follow symlinks)')
ARGPARSER_SET.add_argument('inputs', nargs='*', metavar='input',
        help='Read archives from these files; use an empty string for stdin')

ARGPARSER_PROCESS = SUBARGPARSERS.add_parser('process', prog=f'{PROG} ... process', allow_abbrev=False, add_help=False,
        help='process archive(s)', description='''
Read the specified archives, perform the specified transformations on them, then output the resulting archive. Comments
and empty lines are removed. If --sort is specified, the resulting archive is guaranteed to be normalized; otherwise,
the ordering of records in the result is the same as in the input. When using --sort, care should be taken when passing
very large archives as input as they have to be entirely buffered in memory (although, the in-memory representation is
usually much more space efficient than the archive file format). This shouldn't be a problem unless you're dealing with
a very large number of files, or you have low memory available, or the archive contains file contents.
''')
ARGPARSER_PROCESS.add_argument('-h', '--help', action=_HelpAction, help='Print usage information and exit')
ARGPARSER_PROCESS.add_argument('-o', '--output', default='', metavar='path',
        help='Write archive to this file; use an empty string for stdout (default)')
ARGPARSER_PROCESS.add_argument('-s', '--sort', action='store_true',
        help='Sort the records in the archive and remove records for the same path and attribute (the value of the \
last occuring record in the input is used); if specified, the result is guaranteed to be normalized')
ARGPARSER_PROCESS.add_argument('-a', '--attrs', metavar='attrs', default=None,
        help='A comma-separated list of attributes; if specified, only the records which specify these attributes will \
be included in the result')
ARGPARSER_PROCESS.add_argument('-x', '--exclude', action='append', metavar='path',
        help='Filter out records with this path')
ARGPARSER_PROCESS.add_argument('-X', '--exclude-recursive', action='append', metavar='path',
        help='Filter out records whose path is a (non-strict) subpath of this path')
ARGPARSER_PROCESS.add_argument('-t', '--annotate', action='store_true',
        help='Add comments to some records with more human-readable descriptions of the attribute values')
ARGPARSER_PROCESS.add_argument('inputs', nargs='*', metavar='input',
        help='Read archives from these files; use an empty string for stdin')

ARGPARSER_INSPECT = SUBARGPARSERS.add_parser('inspect', prog=f'{PROG} ... inspect', allow_abbrev=False, add_help=False,
        help='inspect archive', description='''
Read the specified archives, then print statistics about them to stdout.
''')
ARGPARSER_INSPECT.add_argument('-h', '--help', action=_HelpAction, help='Print usage information and exit')
ARGPARSER_INSPECT.add_argument('inputs', nargs='*', metavar='input',
        help='Read archives from these files; use an empty string for stdin')

class Application:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    def run(self, args):
        parser = ARGPARSER
        profiler = None
        try:
            logging.captureWarnings(True)
            root_logger = logging.getLogger()
            root_logger.setLevel(logging.INFO)
            logging_stream_handler = logging.StreamHandler()
            logging_stream_handler.setFormatter(ApplicationLoggingFormatter())
            root_logger.addHandler(logging_stream_handler)
            del logging_stream_handler
            args = ARGPARSER.parse_args(tuple(str(arg) for arg in args))
            if args.verbosity == 'silent':
                logging.disable(logging.CRITICAL)
            else:
                root_logger.setLevel({
                    'critical': logging.CRITICAL,
                    'error': logging.ERROR,
                    'warning': logging.WARNING,
                    'info': logging.INFO,
                    'debug': logging.DEBUG,
                }[args.verbosity])
            del root_logger
            if __debug__:
                LOGGER.warning('debug enabled: reduced performance')
            if args.root is not None:
                try:
                    os.chdir(str(args.root))
                except OSError as e:
                    raise ApplicationError(str(e))
            if args.profile is not None:
                try:
                    import cProfile
                except ImportError as e:
                    raise ApplicationError('cannot import cProfile') from e
                if __debug__:
                    LOGGER.warning('profiling with debug enabled')
                pstats_dest = None if args.profile == '' else os.path.abspath(str(args.profile))
                profiler = cProfile.Profile()
                profiler.enable()
            else:
                profiler = None
            if args.subcommand is None:
                raise ApplicationUsageError('no subcommand specified')
            elif args.subcommand == 'get':
                parser = ARGPARSER_GET
                self.__run_get(args)
            elif args.subcommand == 'set':
                parser = ARGPARSER_SET
                self.__run_set(args)
            elif args.subcommand == 'process':
                parser = ARGPARSER_PROCESS
                self.__run_process(args)
            elif args.subcommand == 'inspect':
                parser = ARGPARSER_INSPECT
                self.__run_inspect(args)
            else:
                raise ApplicationUsageError('invalid subcommand')
        except KeyboardInterrupt as e:
            return 3
        except ApplicationError as e:
            LOGGER.critical(str(e))
            LOGGER.debug('fatal error traceback:', exc_info=e)
            status = e.status
        except ApplicationExit as e:
            status = e.status
        else:
            status = 0
        if profiler is not None:
            profiler.disable()
            import io
            import pstats
            s = io.StringIO()
            ps = pstats.Stats(profiler, stream=s)
            del profiler
            ps.strip_dirs()
            ps.sort_stats('tottime')
            ps.print_stats()
            s = s.getvalue()
            del ps
            if pstats_dest is None:
                sys.stderr.write(s)
            else:
                with open(pstats_dest, 'w') as f:
                    f.write(s)
        return status
    def __run_get(self, args):
        if args.output is None:
            raise ValueError()
        output = str(args.output)
        output = None if output == '' else os.path.abspath(output)
        if args.recursive is None:
            raise ValueError()
        recursive = bool(args.recursive)
        arg_attrs = args.attrs if args.attrs is not None else ()
        if len(arg_attrs) == 0:
            arg_attrs = ((True, 'mode,uid,gid,mtime'),)
        attrs = set()
        for add, lst in arg_attrs:
            for attr in lst.split(','):
                attr = attr.strip()
                if attr == '':
                    continue
                try:
                    attr = _attrs.STANDARD_ATTRS[attr]
                except KeyError:
                    raise ApplicationError(f'unrecognized attribute name: {attr!r}')
                if add:
                    attrs.add(attr)
                else:
                    attrs.discard(attr)
        if args.missing is None:
            raise ValueError()
        missing = str(args.missing)
        if missing not in ('fail', 'ignore'):
            raise ValueError()
        exclude = _util.OSPathMask(
            (os.path.abspath(path) for path in args.exclude) if args.exclude is not None else (),
            (os.path.abspath(path) for path in args.exclude_recursive) if args.exclude_recursive is not None else (),
        )
        if args.exclude_topmost is None:
            raise ValueError()
        exclude_topmost = bool(args.exclude_topmost)
        if args.follow_symlinks is None:
            raise ValueError()
        follow_symlinks = bool(args.follow_symlinks)
        prefix = str(args.prefix) if args.prefix is not None else '.'
        try:
            prefix = _format.Path.from_ospath(prefix)
        except ValueError:
            raise ApplicationError('invalid value for --prefix: invalid path') from None
        if args.annotate is None:
            raise ValueError()
        annotate = bool(args.annotate)
        if args.targets is None:
            raise ValueError()
        if '' in args.targets:
            raise ApplicationError("invalid target path: ''")
        targets = _util.OSPathMask(args.targets) if not recursive else _util.OSPathMask((), args.targets)
        targets = targets.masked if not recursive else targets.rmasked
        if len(targets) == 0:
            LOGGER.warning('no targets')
        target_paths = _format.PathMap()
        try:
            cwd = os.path.abspath(os.getcwd())
        except OSError as e:
            raise ApplicationError(str(e))
        for target in targets:
            dest_path = os.path.relpath(target, cwd)
            if not _util.issubpath(target, cwd):
                raise ApplicationError(f'target outside CWD: {dest_path!r}')
            try:
                dest_path = _format.Path.from_ospath(dest_path)
            except ValueError:
                raise ApplicationError(f'invalid target path: {dest_path!r}') from None
            dest_path = prefix / dest_path
            if not (dest_path in target_paths or (recursive and target_paths.contains_parent(dest_path))):
                target_paths[dest_path] = target
        target_paths.sort()
        try:
            with _get_raw_stdout() if output is None else open(output, 'wb') as output:
                archive = _sem.ArchiveComposer(_util.writer_from_file(output), annotate=annotate)
                for dest_path, target in target_paths.items():
                    _ops.getattrs(archive, target, attrs, dest_path, recursive=recursive, missing=missing,
                            exclude=exclude, exclude_topmost=exclude_topmost, follow_symlinks=follow_symlinks)
                archive.flush()
        except (OSError, _core.StatArchiverError) as e:
            raise ApplicationError(str(e)) from e
    def __run_set(self, args):
        if args.missing is None:
            raise ValueError()
        missing = str(args.missing)
        if missing not in ('fail', 'ignore', 'create'):
            raise ValueError()
        if args.parents is None:
            raise ValueError()
        parents = bool(args.parents)
        exclude = _util.OSPathMask(
            (os.path.abspath(path) for path in args.exclude) if args.exclude is not None else (),
            (os.path.abspath(path) for path in args.exclude_recursive) if args.exclude_recursive is not None else (),
        )
        if args.follow_symlinks is None:
            raise ValueError()
        follow_symlinks = bool(args.follow_symlinks)
        inputs = tuple(os.path.abspath(path) if path != '' else None for path in (str(path) for path in args.inputs))
        if len(inputs) == 0:
            LOGGER.warning('no inputs (use empty string for stdin)')
        if sum(1 for inpt in inputs if inpt is None) > 1:
            raise ApplicationError('cannot use stdin as input multiple times')
        try:
            cwd = os.path.abspath(os.getcwd())
            for inpt in inputs:
                with open(inpt, 'rb') if inpt is not None else _get_raw_stdin() as inpt:
                    archive = _sem.ArchiveParser(_util.iter_from_file(inpt))
                    _ops.setattrs(archive, cwd, missing=missing, create_missing_parents=parents, exclude=exclude,
                            follow_symlinks=follow_symlinks)
        except (OSError, _core.StatArchiverError) as e:
            raise ApplicationError(str(e)) from e
    def __run_process(self, args):
        if args.output is None:
            raise ValueError()
        output = str(args.output)
        output = None if output == '' else os.path.abspath(output)
        if args.sort is None:
            raise ValueError()
        sort = bool(args.sort)
        attrs = args.attrs if args.attrs is not None else ()
        if len(attrs) == 0:
            attrs = None
        else:
            attrs_set = set()
            for add, lst in attrs:
                for attr in lst.split(','):
                    attr = attr.strip()
                    if attr == '':
                        continue
                    try:
                        attr = _attrs.STANDARD_ATTRS[attr]
                    except KeyError:
                        raise ApplicationError(f'unrecognized attribute name: {attr!r}')
                    if add:
                        attrs_set.add(attr)
                    else:
                        attrs_set.discard(attr)
            attrs = attrs_set
            del attrs_set
        exclude = _format.PathSet()
        for path in args.exclude if args.exclude is not None else ():
            try:
                path  = _format.Path.from_ospath(path)
            except ValueError as e:
                raise ApplicationError(f'invalid path: {path!r}') from e
            exclude.add(path)
        rexclude = _format.PathSet()
        for path in args.exclude_recursive if args.exclude_recursive is not None else ():
            try:
                path  = _format.Path.from_ospath(path)
            except ValueError as e:
                raise ApplicationError(f'invalid path: {path!r}') from e
            rexclude.add(path)
        exclude = _format.PathMask(exclude, rexclude)
        del rexclude
        if args.annotate is None:
            raise ValueError()
        annotate = bool(args.annotate)
        inputs = tuple(os.path.abspath(path) if path != '' else None for path in (str(path) for path in args.inputs))
        if len(inputs) == 0:
            LOGGER.warning('no inputs (use empty string for stdin)')
        if sum(1 for inpt in inputs if inpt is None) > 1:
            raise ApplicationError('cannot use stdin as input multiple times')
        try:
            cwd = os.path.abspath(os.getcwd())
            with _get_raw_stdout() if output is None else open(output, 'wb') as output:
                output = _sem.ArchiveComposer(_util.writer_from_file(output), annotate=annotate)
                def inpts():
                    for inpt in inputs:
                        with _get_raw_stdin() if inpt is None else open(inpt, 'rb') as inpt:
                            yield _sem.ArchiveParser(_util.iter_from_file(inpt))
                _ops.process(inpts(), output, sort=sort, filter_attrs=attrs, exclude=exclude)
                output.flush()
        except (OSError, _core.StatArchiverError) as e:
            raise ApplicationError(str(e)) from e
    def __run_inspect(self, args):
        inputs = tuple(os.path.abspath(path) if path != '' else None for path in (str(path) for path in args.inputs))
        if len(inputs) == 0:
            LOGGER.warning('no inputs (use empty string for stdin)')
        if sum(1 for inpt in inputs if inpt is None) > 1:
            raise ApplicationError('cannot use stdin as input multiple times')
        try:
            cwd = os.path.abspath(os.getcwd())
            for i, inpt in enumerate(inputs):
                if len(inputs) != 1:
                    sys.stdout.write(('\n' if i != 0 else '') + (inpt if inpt is not None else '/dev/stdin') + '\n')
                with _get_raw_stdin() if inpt is None else open(os.path.abspath(inpt), 'rb') as f:
                    info = _ops.inspect(_format.RawArchiveParser(_util.iter_from_file(f)))
                sys.stdout.write(info.pretty())
                sys.stdout.flush()
        except (OSError, _core.StatArchiverError) as e:
            raise ApplicationError(str(e)) from e

class ApplicationLoggingFormatter(logging.Formatter):
    def format(self, record):
        message = super().format(record)
        level_name = {
            logging.CRITICAL: 'fatal error',
            logging.ERROR: 'error',
            logging.WARNING: 'warning',
            logging.INFO: 'info',
            logging.DEBUG: 'debug',
        }[record.levelno]
        return f'{PROG}: {level_name}: {message}'

def _get_raw_stdin():
    stdin = sys.__stdin__
    if stdin is None:
        raise ApplicationError('no stdin')
    try:
        return stdin.buffer
    except AttributeError:
        raise ApplicationError('no binary stdin') from None

def _get_raw_stdout():
    stdout = sys.__stdout__
    if stdout is None:
        raise ApplicationError('no stdout')
    try:
        return stdout.buffer
    except AttributeError:
        raise ApplicationError('no binary stdout') from None
