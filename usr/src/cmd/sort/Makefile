#

# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

#
# Debugging targets
#   sort provides a number of debugging options to simplify failure analysis.
#
#   debug		provides symbol information and sets DEBUG; includes
#			convert, invoke
#   stats		builds binaries with statistics reporting enabled
#   convert		builds convert binaries (converts input to collation
#			vectors)
#   invoke		builds invoke binaries (allows inspection of options
#			parser outcome)
#
# Debugging #defines
#   DEBUG		activate assertions; allow wider range of memory
#			settings (-S)
#   DEBUG_FORCE_WIDE	force all i/o through wide streams
#   DEBUG_DISALLOW_MMAP	force all i/o through stdio or wide streams
#   DEBUG_NO_CACHE_TEMP	do not cache last sorted portion in memory; write all
#			data to temporary files before merge
#

PROG = sort
XPG4PROG = sort

BASE_OBJS =		\
	check.o		\
	fields.o	\
	initialize.o	\
	internal.o	\
	merge.o		\
	options.o	\
	streams.o	\
	streams_array.o \
	streams_mmap.o	\
	streams_stdio.o \
	streams_wide.o	\
	utility.o

OBJS =	main.o $(BASE_OBJS)
INVOKE_OBJS = invoke.o $(BASE_OBJS)
CONVERT_OBJS = convert.o $(BASE_OBJS)
STATS_OBJS = main.o statistics.o $(BASE_OBJS)

XPG4OBJS = $(OBJS:%.o=xpg4_%.o)
CLEANFILES = $(OBJS) $(XPG4OBJS)

include ../Makefile.cmd
include ../Makefile.cmd.64

DCFILE =	$(PROG).dc

CFLAGS +=	$(SORT_DEBUG)

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-unused-function

# not linted
SMATCH=off

$(XPG4)	:=	CFLAGS += -DXPG4

debug :=	SORT_DEBUG = $(CCGDEBUG) -DDEBUG
debug :=	COPTFLAG =
debug :=	COPTFLAG64 =
stats	:=	SORT_DEBUG = $(CCGDEBUG) -DSTATS -DDEBUG
stats	:=	COPTFLAG =
stats	:=	COPTFLAG64 =

.KEEP_STATE :

.PARALLEL : $(OBJS) $(XPG4OBJS) $(LNTS)

all : $(PROG) $(XPG4)

debug : $(PROG) convert invoke

clean :
	$(RM) $(CLEANFILES)

$(PROG) : $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(XPG4) : $(XPG4OBJS)
	$(LINK.c) -o $@ $(XPG4OBJS) $(LDLIBS)
	$(POST_PROCESS)

invoke: $(INVOKE_OBJS)
	$(LINK.c) -o $@ $(INVOKE_OBJS) $(LDLIBS)

convert: $(CONVERT_OBJS)
	$(LINK.c) -o $@ $(CONVERT_OBJS) $(LDLIBS)

stats: $(STATS_OBJS)
	$(LINK.c) -o $@ $(STATS_OBJS) $(LDLIBS)

%.o : %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

xpg4_%.o : %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

SRCS =	check.c fields.c initialize.c internal.c \
	main.c merge.c options.c streams.c \
	streams_array.c streams_mmap.c streams_stdio.c \
	streams_wide.c utility.c

POFILES = $(SRCS:.c=.po)
XGETFLAGS += -a -x sort.xcl
CLOBBERFILES = $(DCFILE) $(POFILE) $(POFILES)

ROOTLINK = $(PROG:%=$(ROOTBIN64)/%)

.KEEP_STATE:

install : $(ROOTPROG) $(ROOTXPG4PROG) $(ROOTLINK)

$(ROOTLINK):
	$(RM) $@; $(SYMLINK) ../../bin/$(@F) $@

$(POFILE) : $(POFILES)
	echo $(SRCS)
	echo $(POFILES)
	-$(RM) $@
	$(CAT) $(POFILES) > $@

%.po : %.c
	$(RM) messages.po
	$(XGETTEXT) -c TRANSLATION_NOTE $<
	$(SED) -e '/^domain/d' messages.po > $@
	$(RM) messages.po

include ../Makefile.targ
