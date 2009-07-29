#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/pcmciad/Makefile
#

include ../Makefile.cmd

PROG= 	pcmciad

# srcs
SRCS = $(PROG:%=%.c)
DEVS=	

SOFILES= ${DEVS}

# objects
OBJECTS = $(SRCS:%.c=%.o)

LDLIBS += -lvolmgt
CFLAGS += $(CCVERBOSE)
$(SOFILES) :=	LDLIBS += -lc
# to get the correct DSO flags used for compilation/linking
$(SOFILES) :=	CFLAGS += $(C_PICFLAGS)
$(SOFILES) :=	LDFLAGS += $(ZTEXT)

ROOTLIBPROG=	$(PROG:%=$(ROOTLIB)/%)

FILEMODE= 555

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint

.KEEP_STATE:

all: $(PROG) $(DEVLINK) $(SOFILES)

$(PROG): $(COMMONOBJ) $(LIBS)

# build rule
%: %.c $(COMMONOBJ)
	$(LINK.c) -o $@ $< $(COMMONOBJ) $(LIBS) $(LDLIBS)
	$(POST_PROCESS)

.SUFFIXES: .so.1 ${SUFFIXES}

.c.so.1:
	${CC} ${CPPFLAGS} ${CFLAGS} $(GSHARED) -o $@ $< $(LDLIBS) $(LDFLAGS)
	$(POST_PROCESS_SO)

install: all $(ROOTLIBPROG) $(ROOTDEVLINK)

$(ROOTLIB)/%:	%
		$(INS.file)

clean:	$(LIBSUBDIRS)
	$(RM) $(OBJECTS) $(DEVLINK)

lint:	lint_SRCS 

FRC:

include ../Makefile.targ

# additional dependency for clobber which is defined in ../Makefile.targ
clobber:
