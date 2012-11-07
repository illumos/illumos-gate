#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

SQLITE_VERSION = 2.8.15-repcached

LIBRARY = libsqlite.a
RELOC = $(LIBRARY:%.a=%.o)

VERS = .1
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

# The shared object install target directory is usr/lib/smbsrv.
SMBSRVLIBDIR=   $(ROOTLIBDIR)/smbsrv
SMBSRVLINK=     $(SMBSRVLIBDIR)/$(LIBLINKS)

SRCDIR = ../src
TOOLDIR = ../tool
$(DYNLIB) := LDLIBS += -lc
LIBS = $(RELOC) $(LINTLIB) $(DYNLIB)

$(LINTLIB) :=	SRCS = $(LINTSRC)

SRCS = \
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
	opcodes.c		\
	$(SRCDIR)/os.c		\
	$(SRCDIR)/pager.c	\
	parse.c			\
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

# Header files used by all library source files.
#
HDR = \
	$(SRCDIR)/btree.h	\
	$(SRCDIR)/config.h	\
	$(SRCDIR)/hash.h	\
	opcodes.h		\
	$(SRCDIR)/os.h		\
	parse.h			\
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
# Native variants
#
NATIVERELOC = $(RELOC:%.o=%-native.o)
NATIVEPROGS = lemon-build testfixture
NATIVEOBJS = lemon.o $(OBJS:%.o=%-native.o)

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
	$(RELOC)	\
	$(LINTLIB)	\
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

LINTSRC=    ../llib-lsqlite


.PARALLEL: $(OBJS) $(OBJS:%.o=%-native.o)
.KEEP_STATE:

# This is the default Makefile target.  The objects listed here
# are what get build when you type just "make" with no arguments.
#
all:		$(LIBS)
install:	all $(ROOTLIBDIR)/$(RELOC) $(ROOTLIBDIR)/$(NATIVERELOC) \
		$(ROOTLIBDIR)/llib-lsqlite.ln $(SMBSRVLIBDIR)/$(DYNLIB)

$(ROOTLIBDIR)/$(RELOC)		:= FILEMODE= 644
$(ROOTLIBDIR)/$(NATIVERELOC)	:= FILEMODE= 644
$(ROOTLIBDIR)/llib-lsqlite.ln	:= FILEMODE= 644
$(SMBSRVLIBDIR)/$(DYNLIB)	:= FILEMODE= 755

$(ROOTLIBDIR)/%: %
	$(INS.file)

$(SMBSRVLIBDIR): $(ROOTLIBDIR)
	$(INS.dir)

$(SMBSRVLIBDIR)/%: % $(SMBSRVLIBDIR)
	$(INS.file)

$(SMBSRVLINK): $(SMBSRVLIBDIR) $(SMBSRVLIBDIR)/$(DYNLIB)
	$(INS.liblink)

$(OBJS) $(OBJS:%.o=%-native.o): $(HDR)

native: $(NATIVERELOC)

$(RELOC): objs .WAIT $(OBJS)
	$(LD) -r $(MAPFILES:%=-M%) -o $(RELOC) $(OBJS)
	$(CTFMERGE) -t -f -L VERSION -o $(RELOC) $(OBJS)

$(NATIVERELOC):	objs .WAIT $(OBJS:%.o=%-native.o)
	$(LD) -r $(MAPFILES:%=-M%) -o $(NATIVERELOC) $(OBJS:%.o=%-native.o)

opcodes.h: $(SRCDIR)/vdbe.c
	@echo "Generating $@"; \
	 $(RM) -f $@ ; \
	 echo '/* Automatically generated file.  Do not edit */' > $@ ; \
	 grep '^case OP_' $(SRCDIR)/vdbe.c | \
	    sed -e 's/://' | \
	    awk '{printf "#define %-30s %3d\n", $$2, ++cnt}' >> $@

opcodes.c: $(SRCDIR)/vdbe.c
	@echo "Generating $@"; \
	 $(RM) -f $@ ; \
	 echo '/* Automatically generated file.  Do not edit */' > $@ ; \
	 echo 'char *sqliteOpcodeNames[] = { "???", ' >> $@ ; \
	 grep '^case OP_' $(SRCDIR)/vdbe.c | \
	    sed -e 's/^.*OP_/  "/' -e 's/:.*$$/", /' >> $@ ; \
	 echo '};' >> $@

#
# We use a recursive invocation because otherwise pmake always rebuilds
# everything, due to multiple expansions of "foo := A += B".
#
lemon:	FRC
	$(MAKE) lemon-build

lemon-build:	lemon.o $(TOOLDIR)/lempar.c
	$(LINK.c) -o lemon lemon.o
	$(RM) lempar.c
	$(LN) -s $(TOOLDIR)/lempar.c lempar.c
	$(RM) lemon-build
	$(CP) lemon lemon-build

testfixture: FRC
	@if [ -f $(TCLBASE)/include/tcl.h ]; then \
		unset SUNPRO_DEPENDENCIES; \
		echo $(LINK.c) -o testfixture $(TESTSRC) $(LIBRARY) $(LDLIBS) ;\
		exec $(LINK.c) -o testfixture $(TESTSRC) $(LIBRARY) $(LDLIBS) ;\
	else \
		echo "$(TCLBASE)/include/tcl.h: not found."; \
		exit 1; \
	fi

parse_tmp.out: $(SRCDIR)/parse.y lemon
	$(RM) parse_tmp.y
	$(CP) $(SRCDIR)/parse.y parse_tmp.y
	./lemon parse_tmp.y

parse.h: parse_tmp.out
	$(CP) parse_tmp.h parse.h

parse.c: parse_tmp.out
	$(CP) parse_tmp.c parse.c

objs/%-native.o: $(SRCDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs/%-native.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs/parse-native.o: parse.c
	$(COMPILE.c) -o $@ parse.c
	$(POST_PROCESS_O)

objs/%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.o: $(SRCDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.o: $(TOOLDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ

FRC:
