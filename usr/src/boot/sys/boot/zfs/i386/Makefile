#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2016 Toomas Soome <tsoome@me.com>
#

include ../Makefile.com

CFLAGS +=	-march=i386 -m32 -fno-reorder-functions
CFLAGS +=	-mpreferred-stack-boundary=2

[/opt/os-tests/tests/sigqueue]
tests = ['sigqueue_queue_size']

[/opt/os-tests/tests/tmpfs]
user = root
tests = ['tmpfs_badmount', 'tmpfs_enospc']

[/opt/os-tests/tests/file-locking]
tests = ['runtests.32', 'runtests.64']
MACHINE=	$(MACH)
