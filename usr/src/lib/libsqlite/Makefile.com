#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2015 Igor Kozhukhov <ikozhukhov@gmail.com>
# Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
# Copyright (c) 2019, Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

# Make the SO name unlikely to conflict with any other
# libsqlite that might also be found on the system.
LIBRARY = libsqlite-sys.a

VERS = .2.8.15
OBJECTS = \
	attach.o	\
	auth.o		\
	btree.o		\
	btree_rb.o	\
	build.o		\
	copy.o		\
	date.o		\
	delete.o	\
	encode.o	\
	expr.o		\
	func.o		\
	hash.o		\
	insert.o	\
	main.o		\
	opcodes.o	\
	os.o		\
	pager.o		\
	parse.o		\
	pragma.o	\
	printf.o	\
	random.o	\
	select.o	\
	table.o		\
	tokenize.o	\
	trigger.o	\
	update.o	\
	util.o		\
	vacuum.o	\
	vdbe.o		\
	vdbeaux.o	\
	where.o

include $(SRC)/lib/Makefile.lib

# install this library in the root filesystem
include $(SRC)/lib/Makefile.rootfs

SRCDIR = ../src
TOOLDIR = ../tool
$(DYNLIB) := LDLIBS += -lc

LIBS = $(DYNLIB)

# generated sources
GENSRC = opcodes.c parse.c

# all sources
SRCS = \
	$(GENSRC) \
	$(SRCDIR)/attach.c	\
	$(SRCDIR)/auth.c	\
	$(SRCDIR)/btree.c	\
	$(SRCDIR)/btree_rb.c	\
	$(SRCDIR)/build.c	\
	$(SRCDIR)/copy.c	\
	$(SRCDIR)/date.c	\
	$(SRCDIR)/delete.c	\
	$(SRCDIR)/encode.c	\
	$(SRCDIR)/expr.c	\
	$(SRCDIR)/func.c	\
	$(SRCDIR)/hash.c	\
	$(SRCDIR)/insert.c	\
	$(SRCDIR)/main.c	\
	$(SRCDIR)/os.c		\
	$(SRCDIR)/pager.c	\
	$(SRCDIR)/pragma.c	\
	$(SRCDIR)/printf.c	\
	$(SRCDIR)/random.c	\
	$(SRCDIR)/select.c	\
	$(SRCDIR)/table.c	\
	$(SRCDIR)/tokenize.c	\
	$(SRCDIR)/update.c	\
	$(SRCDIR)/util.c	\
	$(SRCDIR)/vacuum.c	\
	$(SRCDIR)/vdbe.c	\
	$(SRCDIR)/vdbeaux.c	\
	$(SRCDIR)/where.c	\
	$(SRCDIR)/trigger.c

MYCPPFLAGS = -D_REENTRANT -DTHREADSAFE=1 -DHAVE_USLEEP=1 -I. -I.. -I$(SRCDIR)
CPPFLAGS += $(MYCPPFLAGS)

CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-unused-function

# not linted
SMATCH=off

MAPFILES = $(SRC)/lib/libsqlite/mapfile-sqlite

# headers generated here
GENHDR = opcodes.h parse.h

# Header files used by all library source files.
#
HDR = \
	$(GENHDR) \
	$(SRCDIR)/btree.h	\
	$(SRCDIR)/config.h	\
	$(SRCDIR)/hash.h	\
	$(SRCDIR)/os.h		\
	../sqlite.h		\
	$(SRCDIR)/sqliteInt.h	\
	$(SRCDIR)/vdbe.h	\
	$(SRCDIR)/vdbeInt.h

#
# Sources used for test harness
#
TESTSRC = \
	$(SRCDIR)/tclsqlite.c	\
	$(SRCDIR)/btree.c	\
	$(SRCDIR)/func.c	\
	$(SRCDIR)/os.c		\
	$(SRCDIR)/pager.c	\
	$(SRCDIR)/test1.c	\
	$(SRCDIR)/test2.c	\
	$(SRCDIR)/test3.c	\
	$(SRCDIR)/md5.c

TESTOBJS = $(TESTSRC:$(SRCDIR)/%.c=%.o)

TESTCLEAN = $(TESTOBJS) test.db test.tcl test1.bt test2.db testdb

TCLBASE = /usr/sfw
TCLVERS = tcl8.3

testfixture := MYCPPFLAGS += -I$(TCLBASE)/include -DTCLSH -DSQLITE_TEST=1

testfixture := LDLIBS += -R$(TCLBASE)/lib -L$(TCLBASE)/lib -l$(TCLVERS) -lm -ldl

CLEANFILES += \
	$(TESTCLEAN)	\
	lemon		\
	lemon.o		\
	lempar.c	\
	opcodes.c	\
	opcodes.h	\
	parse_tmp.c	\
	parse_tmp.h	\
	parse_tmp.out	\
	parse_tmp.y	\
	parse.c		\
	parse.h

ENCODING  = ISO8859

.PARALLEL: $(OBJS) $(PICS)
.KEEP_STATE:

# This is the default Makefile target.  The objects listed here
# are what get build when you type just "make" with no arguments.
#
all:		$(LIBS)
install:	all

all_h: $(GENHDR)

$(ROOTLINK): $(ROOTLIBDIR) $(ROOTLIBDIR)/$(DYNLIB)
	$(INS.liblink)
