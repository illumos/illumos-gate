#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2015 Igor Kozhukhov <ikozhukhov@gmail.com>
# Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
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
LIBS = $(DYNLIB) $(LINTLIB) $(NATIVERELOC)

$(LINTLIB) :=	SRCS = ../$(LINTSRC)

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
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused-function
CERRWARN += -_gcc=-Wno-unused-label

MAPFILES = ../mapfile-sqlite

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

#
# Native variant (needed by cmd/configd)
#
NATIVERELOC = libsqlite-native.o
NATIVEPROGS = testfixture
NATIVEOBJS = $(OBJS:%.o=%-native.o)

NATIVETARGETS = $(NATIVEPROGS) $(NATIVEOBJS) $(NATIVERELOC)

$(NATIVETARGETS) :=	CC = $(NATIVECC)
$(NATIVETARGETS) :=	LD = $(NATIVELD)
$(NATIVETARGETS) :=	CFLAGS = $(NATIVE_CFLAGS)
$(NATIVETARGETS) :=	CPPFLAGS = $(MYCPPFLAGS)
$(NATIVETARGETS) :=	LDFLAGS =
$(NATIVETARGETS) :=	LDLIBS = -lc

$(OBJS) :=		CFLAGS += $(CTF_FLAGS)
$(OBJS) :=		CTFCONVERT_POST = $(CTFCONVERT_O)

TCLBASE = /usr/sfw
TCLVERS = tcl8.3

testfixture := MYCPPFLAGS += -I$(TCLBASE)/include -DTCLSH -DSQLITE_TEST=1
#
# work around compiler issues
#
testfixture := CFLAGS += \
	-erroff=E_ARRAY_OF_INCOMPLETE \
	-erroff=E_ARG_INCOMPATIBLE_WITH_ARG

testfixture := LDLIBS += -R$(TCLBASE)/lib -L$(TCLBASE)/lib -l$(TCLVERS) -lm -ldl

CLEANFILES += \
	$(NATIVETARGETS) \
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


.PARALLEL: $(OBJS) $(OBJS:%.o=%-native.o)
.KEEP_STATE:

# This is the default Makefile target.  The objects listed here
# are what get build when you type just "make" with no arguments.
#
all:		$(LIBS)
install:	all \
		$(ROOTLIBDIR)/$(DYNLIB) \
		$(ROOTLIBDIR)/$(LINTLIB) \
		$(ROOTLIBDIR)/$(NATIVERELOC)

lint:

all_h: $(GENHDR)

$(ROOTLIBDIR)/$(NATIVERELOC)	:= FILEMODE= 644
$(ROOTLINTDIR)/$(LINTLIB)	:= FILEMODE= 644

$(ROOTLINK): $(ROOTLIBDIR) $(ROOTLIBDIR)/$(DYNLIB)
	$(INS.liblink)

$(ROOTLINTDIR)/%: ../%
	$(INS.file)

native: $(NATIVERELOC)

$(NATIVERELOC):	objs .WAIT $(OBJS:%.o=%-native.o)
	$(LD) -r -o $(NATIVERELOC) $(OBJS:%.o=%-native.o)

opcodes.h: $(SRCDIR)/vdbe.c
	@echo "Generating $@"; \
	 $(RM) -f $@ ; \
	 echo '/* Automatically generated file.  Do not edit */' > $@ ; \
	 grep '^case OP_' $(SRCDIR)/vdbe.c | \
	    sed -e 's/://' | \
	    $(AWK) '{printf "#define %-30s %3d\n", $$2, ++cnt}' >> $@

opcodes.c: $(SRCDIR)/vdbe.c
	@echo "Generating $@"; \
	 $(RM) -f $@ ; \
	 echo '/* Automatically generated file.  Do not edit */' > $@ ; \
	 echo 'char *sqliteOpcodeNames[] = { "???", ' >> $@ ; \
	 grep '^case OP_' $(SRCDIR)/vdbe.c | \
	    sed -e 's/^.*OP_/  "/' -e 's/:.*$$/", /' >> $@ ; \
	 echo '};' >> $@

testfixture: FRC
	@if [ -f $(TCLBASE)/include/tcl.h ]; then \
		unset SUNPRO_DEPENDENCIES; \
		echo $(LINK.c) -o testfixture $(TESTSRC) $(LIBRARY) $(LDLIBS) ;\
		exec $(LINK.c) -o testfixture $(TESTSRC) $(LIBRARY) $(LDLIBS) ;\
	else \
		echo "$(TCLBASE)/include/tcl.h: not found."; \
		exit 1; \
	fi

# Prevent Makefile.lib $(PICS) := from adding PICFLAGS
# by building lemon in a recursive make invocation.
# Otherwise, this target causes a rebuild every time after
# the PICS target builds this one way, then lint the other.
parse.h parse.c : $(SRCDIR)/parse.y $(TOOLDIR)/lemon.c $(TOOLDIR)/lempar.c
	-$(RM) parse_tmp.y lempar.c
	$(CP) $(SRCDIR)/parse.y parse_tmp.y
	$(CP) $(TOOLDIR)/lempar.c lempar.c
	$(MAKE) lemon
	./lemon parse_tmp.y
	-$(RM) parse.c parse.h
	$(CP) parse_tmp.h parse.h
	$(CP) parse_tmp.c parse.c

lemon: $(TOOLDIR)/lemon.c
	$(NATIVECC) $(NATIVE_CFLAGS) -o $@ $(TOOLDIR)/lemon.c

objs/%-native.o: $(SRCDIR)/%.c $(GENHDR)
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs/%-native.o: %.c $(GENHDR)
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs/parse-native.o: parse.c $(GENHDR)
	$(COMPILE.c) -o $@ parse.c
	$(POST_PROCESS_O)

objs/%.o pics/%.o: $(SRCDIR)/%.c $(GENHDR)
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs/%.o pics/%.o: %.c $(GENHDR)
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

# need direct rules for generated files
objs/opcodes.o pics/opcodes.o: opcodes.c $(GENHDR)
	$(COMPILE.c) -o $@ opcodes.c
	$(POST_PROCESS_O)

objs/parse.o pics/parse.o: parse.c $(GENHDR)
	$(COMPILE.c) -o $@ parse.c
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ

FRC:
