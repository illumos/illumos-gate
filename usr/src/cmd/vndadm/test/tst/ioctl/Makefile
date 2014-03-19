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

TSTDIR =	ioctl
EXETESTS = \
	create.attach.exe \
	create.attachnolink.exe \
	create.badlinkname.exe \
	create.doublelink.exe \
	create.gioctlattach.exe \
	create.link.exe \
	create.linkexists.exe \
	create.ngioctlfault.exe \
	create.nopriv1.exe \
	create.nopriv2.exe \
	create.nopriv3.exe \
	create.nopriv4.exe \
	create.olink.exe \
	create.olinknopriv.exe \
	create.rmenolink.exe \
	tst.attachrdonly.exe \
	tst.basicopenctl.exe \
	tst.badioctl.exe \
	tst.gioctlfault.exe \
	tst.gioctlnattach.exe \
	tst.openctlbadflags.exe
SHTESTS = \
	tst.iocsize.ksh
SUPBOBJS =

CLOBBERFILES =	$(EXETESTS)

include ../../Makefile.com

install: $(ROOTTESTS)

include ../../Makefile.targ
