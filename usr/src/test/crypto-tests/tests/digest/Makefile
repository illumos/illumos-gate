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

ALGS = sha1 sha256 sha384 sha512 sha512_224 sha512_256 md5
CRYPTO = pkcs kcf

PROGS_pkcs_32 = $(ALGS:%=%_32_pkcs)
PROGS_pkcs_64 = $(ALGS:%=%_64_pkcs)
PROGS_kcf_32 = $(ALGS:%=%_32_kcf)
PROGS_kcf_64 = $(ALGS:%=%_64_kcf)
PROGS_pkcs = $(PROGS_pkcs_32) $(PROGS_pkcs_64)
PROGS_kcf = $(PROGS_kcf_32) $(PROGS_kcf_64)
PROGS_32 = $(PROGS_pkcs_32) $(PROGS_kcf_32)
PROGS_64 = $(PROGS_pkcs_64) $(PROGS_kcf_64)
PROGS = $(PROGS_32) $(PROGS_64)

ROOTOPTPKG = $(ROOT)/opt/crypto-tests
TESTROOT = $(ROOTOPTPKG)/tests/digest
TESTDIR_pkcs = $(TESTROOT)/pkcs
TESTDIR_kcf = $(TESTROOT)/kcf

COMMONDIR = ../common

$(CRYPTO:%=sha1_32_%)	:= OBJS = sha1.32.o
$(CRYPTO:%=sha256_32_%)	:= OBJS = sha256.32.o
$(CRYPTO:%=sha384_32_%)	:= OBJS = sha384.32.o
$(CRYPTO:%=sha512_32_%)	:= OBJS = sha512.32.o
$(CRYPTO:%=sha512_224_32_%) := OBJS = sha512_224.32.o
$(CRYPTO:%=sha512_256_32_%) := OBJS = sha512_256.32.o
$(CRYPTO:%=md5_32_%)	:= OBJS = md5.32.o

$(CRYPTO:%=sha1_64_%)	:= OBJS = sha1.64.o
$(CRYPTO:%=sha256_64_%)	:= OBJS = sha256.64.o
$(CRYPTO:%=sha384_64_%)	:= OBJS = sha384.64.o
$(CRYPTO:%=sha512_64_%)	:= OBJS = sha512.64.o
$(CRYPTO:%=sha512_224_64_%) := OBJS = sha512_224.64.o
$(CRYPTO:%=sha512_256_64_%) := OBJS = sha512_256.64.o
$(CRYPTO:%=md5_64_%)	:= OBJS = md5.64.o

$(PROGS_32)		:= OBJS_COMMON = main.32.o $(COMMONDIR)/testfuncs.32.o
$(PROGS_64)		:= OBJS_COMMON = main.64.o $(COMMONDIR)/testfuncs.64.o
$(PROGS_pkcs_32)	:= OBJS_COMMON += $(COMMONDIR)/cryptotest_pkcs.32.o
$(PROGS_pkcs_64)	:= OBJS_COMMON += $(COMMONDIR)/cryptotest_pkcs.64.o
$(PROGS_kcf_32)		:= OBJS_COMMON += $(COMMONDIR)/cryptotest_kcf.32.o
$(PROGS_kcf_64)		:= OBJS_COMMON += $(COMMONDIR)/cryptotest_kcf.64.o

CSTD = $(CSTD_GNU99)

CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
CPPFLAGS += -I$(COMMONDIR) -I$(SRC)/common/crypto

LINTFLAGS += -xerroff=E_NAME_USED_NOT_DEF2
LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2

$(PROGS_pkcs) := LDLIBS += -lpkcs11 -lcryptoutil

CMDS_pkcs = $(PROGS_pkcs:%_pkcs=$(TESTDIR_pkcs)/%)
CMDS_kcf = $(PROGS_kcf:%_kcf=$(TESTDIR_kcf)/%)
CMDS = $(CMDS_pkcs) $(CMDS_kcf)

$(CMDS) := FILEMODE = 0555

all: $(PROGS)

$(PROGS): main.32.o main.64.o

%_32_pkcs: %.32.o
	$(LINK.c) -o $@ $(OBJS) $(OBJS_COMMON) $(LDLIBS)
	$(POST_PROCESS)

%_64_pkcs: %.64.o
	$(LINK64.c) -o $@ $(OBJS) $(OBJS_COMMON) $(LDLIBS)
	$(POST_PROCESS)

%_32_kcf: %.32.o
	$(LINK.c) -o $@ $(OBJS) $(OBJS_COMMON) $(LDLIBS)
	$(POST_PROCESS)

%_64_kcf: %.64.o
	$(LINK64.c) -o $@ $(OBJS) $(OBJS_COMMON) $(LDLIBS)
	$(POST_PROCESS)

%.32.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.64.o: %.c
	$(COMPILE64.c) -o $@ $<
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
	-$(RM) $(ALGS:%=%.32.o) $(ALGS:%=%.64.o) main.32.o main.64.o

$(CMDS): $(TESTDIR_pkcs) $(TESTDIR_kcf) $(PROGS)

$(TESTDIR_pkcs) $(TESTDIR_kcf):
	$(INS.dir)

$(TESTDIR_pkcs)/%_32: %_32_pkcs
	$(INS.rename)

$(TESTDIR_pkcs)/%_64: %_64_pkcs
	$(INS.rename)

$(TESTDIR_kcf)/%_32: %_32_kcf
	$(INS.rename)

$(TESTDIR_kcf)/%_64: %_64_kcf
	$(INS.rename)
