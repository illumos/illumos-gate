This is the OpenZFS source code repository.
===========================================

OpenZFS is an outstanding storage platform that encompasses the
functionality of traditional filesystems, volume managers, and more.
OpenZFS provides consistent reliability, functionality and performance
across all distributions, including illumos, FreeBSD, Linux, and OSX.

See http://open-zfs.org for more details.

This repo closely tracks illumos, and is the upstream for the
above-mentioned distributions.


Directories of interest for ZFS:
================================

* usr/src/uts/common/fs/zfs
  * code for the ZFS kernel module

* usr/src/common/zfs
  * code for both the kernel module and userland (libzfs)

* usr/src/cmd/{zfs,zpool}
  * code for administrative commands

* usr/src/cmd/{zdb,ztest,zstreamdump,zhack}
  * code for test/development commands

* usr/src/lib/{libzfs,libzfs_core}
  * code for libraies used by administrative commands

* usr/src/lib/libzpool
  * compiles kernel code into a userland module for testing
    (used by zdb, ztest)

* usr/src/cmd/mdb/common/modules/zfs
  * zfs mdb module, provides ZFS-specific debugging commands

* usr/src/test/zfs-tests
  * ZFS test suite


Relation to illumos, and integration requirements
=================================================

This is a clone of [illumos-gate](https://github.com/illumos/illumos-gate),
(see also http://illumos.org).  All commits meet the requirements for
integrating into illumos[*], including:
* each commit fixes one or more illumos bugs
* commit message format is one line for each bug fixed, plus one line
  for each reviewer
* code has been reviewed by someone familiar with illumos code and
  practices

[*] An exception is made for changes that should never be ported to
other platforms (including illumos).  For example, changes to this
README.

Code review requirements
------------------------
Code changes must be reviewed by someone with experience in the area of
code being changed (besides the change's author).  Note that the
reviewers need not be absolute experts, the review need not be
conducted on github (or any public forum), and you need not make every
change requested by reviewers.  The thoroughness of the review will be
evaluated by a committer.

Testing requirements
--------------------

Most changes can be tested on any platform's port of OpenZFS (e.g.
illumos, FreeBSD, Linux, OSX), and then be tested on OpenZFS/illumos
simply by running the regression tests:
* /usr/bin/ztest (typically for at least 2 hours)
* the zfs test suite, /opt/zfs-tests/bin/zfstest
  * Note that there are some known failures on master. Therefore your
    results should be compared with results from master to determine if
    they are new failures.

Licensing requirements
----------------------

Modifications to existing files must be licensed under that file's
original licence terms (typically CDDL).  New files may be licensed
under more permissive licenses if desired.

How to contribute changes
-------------------------

Simply open a pull request.  This will begin the code review and
regression testing process.

Typically when bringing changes from a different platform, your workflow
will include:
* check out openzfs/master
* apply patch, potentially changing file paths as appropriate
* open an [illumos bug](https://www.illumos.org/projects/illumos-gate/issues/new)
  * the description of the bug should include an analysis of problem and
    solution (similar to what might be included in the commit message in
    other repositories)
* commit the change, using the illumos-style commit message
  * Optionally, for ease of reviewing, you may include freeform text
    following the illumos-style commit message.  This text will be
    removed by the commiter when it is committed (and the Approved-by
    line will be added).
* open a pull request against openzfs/master
* respond to any code review feedback
  * Note that responding does not necessarily mean doing what the
    reviewer suggested.  Often it means explaining your reasoning or
    answering a question.
* look for automated regression test results and address and unexpected
  failures

Committers
==========

Committers are experts in OpenZFS and illumos who can directly make
changes to this repository.  They are listed on the
[github account](https://github.com/orgs/openzfs/people).  If you are
interested in becoming a committer, contact Matt Ahrens (@ahrens).


Further Discussion
==================

The best way to reach the relevant members of this community is the
developer@open-zfs.org
[mailing list](http://open-zfs.org/wiki/Mailing_list).  You may also
find folks on IRC in #openzfs on irc.freenode.net.
