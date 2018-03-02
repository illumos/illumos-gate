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
# Copyright 2018, Joyent, Inc.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com
include $(SRC)/cmd/Makefile.ctf

ALGS = sha1 sha256 sha384 sha512
CRYPTO = pkcs kcf

PROGS_pkcs = $(ALGS:%=%_pkcs)
PROGS_kcf = $(ALGS:%=%_kcf)
PROGS = $(PROGS_pkcs) $(PROGS_kcf)

ROOTOPTPKG = $(ROOT)/opt/crypto-tests
TESTROOT = $(ROOTOPTPKG)/tests/digest
TESTDIR_pkcs = $(TESTROOT)/pkcs
TESTDIR_kcf = $(TESTROOT)/kcf

COMMONDIR = ../common

$(CRYPTO:%=sha1_%)	:= OBJS = sha1.o
$(CRYPTO:%=sha256_%)	:= OBJS = sha256.o
$(CRYPTO:%=sha384_%)	:= OBJS = sha384.o
$(CRYPTO:%=sha512_%)	:= OBJS = sha512.o

OBJS_COMMON	= $(COMMONDIR)/testfuncs.o
$(PROGS_pkcs)	:= OBJS_COMMON += $(COMMONDIR)/cryptotest_pkcs.o
$(PROGS_kcf)	:= OBJS_COMMON += $(COMMONDIR)/cryptotest_kcf.o
$(PROGS)	:= OBJS += main.o

CSTD = $(CSTD_GNU99)

CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
CPPFLAGS += -I$(COMMONDIR) -I$(SRC)/common/crypto

LINTFLAGS += -xerroff=E_NAME_USED_NOT_DEF2
LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2

$(PROGS_pkcs) := LDLIBS += -lpkcs11 -lcryptoutil

CMDS_pkcs = $(ALGS:%=$(TESTDIR_pkcs)/%)
CMDS_kcf = $(ALGS:%=$(TESTDIR_kcf)/%)
CMDS = $(CMDS_pkcs) $(CMDS_kcf)

$(CMDS) := FILEMODE = 0555

all: $(PROGS)

$(COMMONDIR)/%.o:
$(PROGS): main.o

%_pkcs: %.o
	$(LINK.c) -o $@ $(OBJS) $(OBJS_COMMON) $(LDLIBS)
	$(POST_PROCESS)

%_kcf: %.o
	$(LINK.c) -o $@ $(OBJS) $(OBJS_COMMON) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

install: all $(CMDS)

lint: $(CRYPTO:%=lint_%)
lint_pkcs: $(ALGS:%=lint_pkcs_%)
lint_kcf: $(ALGS_kcf:%=lint_kcf_%)

lint_pkcs_%:
	$(LINT.c) main.c $(@:lint_pkcs_%=%.c) $(OBJS_COMMON:%.o=%.c) $(LDLIBS)

lint_pcf_%:
	$(LINT.c) main.c $(@:lint_kcf_%=%.c) $(OBJS_COMMON:%.o=%.c) $(LDLIBS)

clobber: clean
	-$(RM) $(PROGS)

clean:
	-$(RM) $(ALGS:%=%.o) main.o

$(CMDS): $(TESTDIR_pkcs) $(TESTDIR_kcf) $(PROGS)

$(TESTDIR_pkcs) $(TESTDIR_kcf):
	$(INS.dir)
	@echo Cmds: $(CMDS)

$(TESTROOT)/pkcs/%: %_pkcs
	$(INS.rename)

$(TESTROOT)/kcf/%: %_kcf
	$(INS.rename)
