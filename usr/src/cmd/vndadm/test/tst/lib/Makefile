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
# Copyright (c) 2014 Joyent, Inc.  All rights reserved.
#

TSTDIR =	lib
EXETESTS = \
	create.basic.exe \
	create.badlink.exe \
	create.badpropid.exe \
	create.badpropsize.exe \
	create.badzone.exe \
	create.enomem.exe \
	create.frameioeagain.exe \
	create.open.exe \
	create.propiter.exe \
	create.proprdonly.exe \
	err.badclose.exe \
	tst.badopen.exe \
	tst.strerror.exe \
	tst.strsyserror.exe
OUTFILES = tst.strerror.exe.out
SHTESTS =
SUPBOBJS =

CLOBBERFILES =	$(EXETESTS)

include ../../Makefile.com

LDLIBS += -lvnd

install: $(ROOTTESTS)

include ../../Makefile.targ
