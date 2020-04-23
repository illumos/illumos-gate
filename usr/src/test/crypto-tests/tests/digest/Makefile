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
# Copyright 2019 Joyent, Inc.
# Copyright 2020 Oxide Computer Company
#

ALGS	= sha1 sha256 sha384 sha512 sha512_224 sha512_256 md5
SUBDIRS	= data

all	:=	TARGET = all
install	:=	TARGET = install
clean	:=	TARGET = clean
clobber	:=	TARGET = clobber

.KEEP_STATE:

all clean clobber install: $(ALGS) $(SUBDIRS)

$(ALGS): FRC
	$(MAKE) -e -f Makefile.digest BASEPROG=$@ $(TARGET)

$(SUBDIRS): FRC
	cd $@; pwd; $(MAKE) $(TARGET)

FRC:
