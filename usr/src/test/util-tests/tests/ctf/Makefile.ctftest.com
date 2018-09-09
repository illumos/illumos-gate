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
#

#
# This Makefile is installed onto the target system and is used as part
# of the running tests. It is not used as part of the build.
#
# This makefile could be simplified substantially. However, it does
# everything explicitly to try and work with a wide variety of different
# makes.
#
# The following values should be passed in by the invoker of the
# Makefile:
#
#	CC		C Compiler to use
#	CFLAGS32	32-bit CFLAGS
#	CFLAGS64	64-bit CFLAGS
#	CTFCONVERT	Path to ctfconvert
#	CTFMERGE	Path to ctfmerge
#	DEBUGFLAGS	The set of debug flags to use
#	BUILDDIR	Directory things should be built in
#	CHECK32		Program to check 32-bit output
#	CHECK64		Program to check 64-bit output
#
# The following values should be set before building this:
#
#	TEST		The name of the test program
#	OBJS_C_32	32-bit convert objects
#	OBJS_C_64	64-bit convert objects
#	OBJS_M_32	32-bit merge objects
#	OBJS_M_64	64-bit merge objects
#

CONV32 =	$(BUILDDIR)/$(TEST)-32c
CONV64 =	$(BUILDDIR)/$(TEST)-64c
MERGE32 =	$(BUILDDIR)/$(TEST)-32m
MERGE64 =	$(BUILDDIR)/$(TEST)-64m

BINS =		$(CONV32) \
		$(CONV64) \
		$(MERGE32) \
		$(MERGE64)

build: $(BINS)

$(BUILDDIR)/%.32.c.o: %.c
	$(CC) $(CFLAGS32) $(DEBUGFLAGS) -o $@ -c $<

$(BUILDDIR)/%.64.c.o: %.c
	$(CC) $(CFLAGS64) $(DEBUGFLAGS) -o $@ -c $<

$(BUILDDIR)/%.32.m.o: %.c
	$(CC) $(CFLAGS32) $(DEBUGFLAGS) -o $@ -c $<
	$(CTFCONVERT) $@

$(BUILDDIR)/%.64.m.o: %.c
	$(CC) $(CFLAGS64) $(DEBUGFLAGS) -o $@ -c $<
	$(CTFCONVERT) $@

$(CONV32): $(OBJS_C_32)
	$(CC) $(CFLAGS32) $(DEBUGFLAGS) -o $@ $(OBJS_C_32)
	$(CTFCONVERT) $@

$(CONV64): $(OBJS_C_64)
	$(CC) $(CFLAGS64) $(DEBUGFLAGS) -o $@ $(OBJS_C_64)
	$(CTFCONVERT) $@

$(MERGE32): $(OBJS_M_32)
	$(CC) $(CFLAGS32) $(DEBUGFLAGS) -o $@ $(OBJS_M_32)
	$(CTFMERGE) -t -o $@ $(OBJS_M_32)

$(MERGE64): $(OBJS_M_64)
	$(CC) $(CFLAGS64) $(DEBUGFLAGS) -o $@ $(OBJS_M_64)
	$(CTFMERGE) -t -o $@ $(OBJS_M_64)

run-test:
	$(CHECK32) $(CONV32)
	$(CHECK64) $(CONV64)
	$(CHECK32) $(MERGE32)
	$(CHECK64) $(MERGE64)
