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

# Copyright 2015, Richard Lowe.

LIBRARY =	libvroot.a
VERS =		.1
OBJECTS =	access.o	\
		args.o		\
		chdir.o		\
		chmod.o		\
		chown.o		\
		chroot.o	\
		creat.o		\
		execve.o	\
		lock.o		\
		lstat.o		\
		mkdir.o		\
		mount.o		\
		open.o		\
		readlink.o	\
		report.o	\
		rmdir.o		\
		stat.o		\
		truncate.o	\
		unlink.o	\
		utimes.o	\
		vroot.o		\
		setenv.o

include $(SRC)/lib/Makefile.lib
include ../../Makefile.com

LIBS = $(LIBRARY)
SRCDIR = $(SRC)/cmd/make/lib/vroot
MAPFILES=
CPPFLAGS += -D_FILE_OFFSET_BITS=64

all: $(LIBS)

install: all

lint:

include $(SRC)/lib/Makefile.targ
