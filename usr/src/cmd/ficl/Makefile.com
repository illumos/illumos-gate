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
# Copyright 2016 Toomas Soome <tsoome@me.com>
#

PROG= ficl-sys
OBJS= main.o
SRCS= main.c

include ../../Makefile.cmd
include ../../Makefile.ctf

LDLIBS += -lficl-sys -ltecla -lumem
CPPFLAGS += -D_FILE_OFFSET_BITS=64 -I$(SRC)/common/ficl

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS)

include ../../Makefile.targ

%.o:	$(SRC)/common/ficl/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $< $(CTFCONVERT_HOOK)
	$(POST_PROCESS_O)
