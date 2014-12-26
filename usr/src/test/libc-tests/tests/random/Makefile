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
# Copyright (c) 2015 Joyent, Inc.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/libc-tests
TESTDIR = $(ROOTOPTPKG)/tests/random
ROOTBINDIR = $(ROOTOPTPKG)/bin

PROGS = arc4random 		\
	arc4random_prefork 	\
	arc4random_fork 	\
	arc4random_preforkall 	\
	arc4random_forkall 	\
	arc4random_preforksig	\
	arc4random_forksig	\
	arc4random_rekey 	\
	chacha 			\
	getentropy 		\
	getrandom 		\
	inz_child		\
	inz_inval		\
	inz_mlock		\
	inz_region 		\
	inz_split		\
	inz_split_vpp		\
	inz_vpp

SCRIPTS = arc4key.ksh

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

CMDS = $(PROGS:%=$(TESTDIR)/%) $(SCRIPTS:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

all: $(PROGS)

install: all $(CMDS)

lint:

clobber: clean
	-$(RM) $(PROGS)

clean:
	-$(RM) *.o

$(CMDS): $(TESTDIR) $(PROGS)

arc4random_prefork: arc4random_fork.c
	$(LINK.c) -o $@ -DARC4_PREINIT=1 arc4random_fork.c $(LDLIBS)
	$(POST_PROCESS)

arc4random_preforkall: arc4random_forkall.c
	$(LINK.c) -o $@ -DARC4_PREINIT=1 arc4random_forkall.c $(LDLIBS)
	$(POST_PROCESS)

arc4random_preforksig: arc4random_forksig.c
	$(LINK.c) -o $@ -DARC4_PREINIT=1 arc4random_forksig.c $(LDLIBS)
	$(POST_PROCESS)

chacha: chacha_tv.c
	$(COMPILE.c) -DKEYSTREAM_ONLY -I$(SRC)/common/crypto/chacha -o chacha.o -c $(SRC)/common/crypto/chacha/chacha.c
	$(COMPILE.c) -I$(SRC)/common/crypto/chacha -o chacha_tv.o -c chacha_tv.c
	$(LINK.c) -o $@ chacha_tv.o chacha.o $(LDLIBS)
	$(POST_PROCESS)

$(ROOTBINDIR):
	$(INS.dir)

$(ROOTBINDIR)/%: %
	$(INS.file)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

$(TESTDIR)/%: %
	$(INS.file)
