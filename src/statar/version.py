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

MAJOR = 0
MINOR = 8
PATCH = 0
PRERELEASE_STR = None

IS_PRERELEASE = PRERELEASE_STR is not None
VERSION = (MAJOR, MINOR, PATCH, *((PRERELEASE_STR,) if IS_PRERELEASE else ()))
VERSION_STR = f'{MAJOR}.{MINOR}.{PATCH}' + (f'-{PRERELEASE_STR}' if IS_PRERELEASE else '')
