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
# Copyright 2020 Oxide Computer Company
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/crypto-tests
SHAREDIR = $(ROOTOPTPKG)/share

DIGEST_FILES = \
    README \
    MD5Msg.rsp \
    SHA1LongMsg.rsp \
    SHA1ShortMsg.rsp \
    SHA224LongMsg.rsp \
    SHA224ShortMsg.rsp \
    SHA256LongMsg.rsp \
    SHA256ShortMsg.rsp \
    SHA384LongMsg.rsp \
    SHA384ShortMsg.rsp \
    SHA512_224LongMsg.rsp \
    SHA512_224ShortMsg.rsp \
    SHA512_256LongMsg.rsp \
    SHA512_256ShortMsg.rsp \
    SHA512LongMsg.rsp \
    SHA512ShortMsg.rsp

FILES = $(DIGEST_FILES:%=$(SHAREDIR)/%)
$(FILES) := FILEMODE = 0444

all clean lint clobber:

install: $(SHAREDIR) $(FILES)

$(SHAREDIR):
	$(INS.dir)

$(SHAREDIR)/%: %
	$(INS.file)
