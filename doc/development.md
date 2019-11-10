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

# stat-archiver Development Workflows

This document contains information about the workflow processes used during
development of this project.

The [stat-archiver repository](https://github.com/parkerhoyes/stat-archiver)
will follow a Git branching model similar to that described in [Vincent
Driessen's *A successful Git branching
model*](http://nvie.com/posts/a-successful-git-branching-model/) and
stat-archiver's versioning scheme will adhere to [Semantic Versioning
2.0.0](http://semver.org/).

## Contributing

Pull requests are welcome.

Unless the contribution you'd like to make is fairly small, it is recommended
that you open an issue on GitHub to discuss your proposed changes first.

## Before Commit Checklist

1. All new source files (including docs) with non-trivial contents should have
   the license boilerplate added at the top.
2. Add current year and your own name to copyright statement at the top of
   source files (including docs) to which non-trivial modifications have been
   made.
3. TEST!

## Before Release Checklist

1. Update `README.md`, everything in `doc/`, and command-line help text.
2. Start a new release branch.
3. Update version number in `README.md` and `src/statar/version.py`.
4. Merge into `master` branch and tag the merge commit with the version string
   prefixed with `v`.
5. Create a [release on the GitHub
   repo](https://github.com/parkerhoyes/stat-archiver/releases) with appropriate
   release notes.
