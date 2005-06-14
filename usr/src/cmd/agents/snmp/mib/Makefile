#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# snmp/mib/Makefile
#

include ../../Makefile.vars

# OPTIONAL_INCLUDE_FILE:sh = /bin/sh ../../misc.sh ../../../cmd/Makefile.cmd
# include $(OPTIONAL_INCLUDE_FILE)

include $(SRC)/cmd/Makefile.cmd

#
# In order to conform with the Solaris 2.6 way of packaging things,
# we now need to put any deliverable that is specified in the
# prototype file into a common "proto" area, so that their
# packaging scheme knows where to obtain the input binaries.
#
 
AGENT =	snmpdx.mib
BINPROG = $(AGENT)
OPTMIB = $(ROOT)/var/snmp/mib
OPTPROG = $(BINPROG:%=$(OPTMIB)/%)
 
$(OPTMIB)/%: $(OPTMIB) %
	$(INS.file)

SOURCES.c=

SOURCES.h= snmpdx.mib

OBJECTS= $(SOURCES.c:%.c=$(BIN)/%.o)

CFLAGS += -c

LDFLAGS +=

LINT=	lint

.KEEP_STATE:
 
#######################################################
 
#
# all
#
 
FILEMODE = 0644
GROUP = sys
 
CLOBBERFILES=
 
all: $(SOURCES.h) $(BINPROG)
 
install: all $(OPTPROG)

$(BINPROG): $(BIN) $(OBJECTS)

$(BIN)/%.o: %.c


#
# lint
#

lint:
	@echo "nothing to lint"


#
# purify
#

purify:
	$(PURIFY) $(CC) -o $(BINPROG) $(LDFLAGS) $(OBJECTS)


#
# directories
#

$(BIN):
	@$(TEST) -d $@ || mkdir $@


#
# clean
#

clean:
	$(RM) $(OBJECTS)

realclobber: clean
	sccs clean

# OPTIONAL_INCLUDE_FILE:sh = /bin/sh ../../misc.sh ../../../cmd/Makefile.targ
# include $(OPTIONAL_INCLUDE_FILE)

include $(SRC)/cmd/Makefile.targ
