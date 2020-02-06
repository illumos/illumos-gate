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

STABS_SRC = ..

#
#       Define the module and object file sets.
#
STABS_PROG	= stabs	  # name doesn't conflict with Makefile.master STABS
PROG		= stabs	  # name doesn't conflict with Makefile.master STABS
STABS_SRCS	= $(STABS_SRC)/main.c $(STABS_SRC)/stabs.c \
		  $(STABS_SRC)/forth.c $(STABS_SRC)/genassym.c \
		  $(STABS_SRC)/squander.c
STABS_OBJS	= $(STABS_SRCS:$(STABS_SRC)/%.c=%.o)

SRCS		= $(STABS_SRCS)
OBJECTS		= $(STABS_OBJS)

#
#       Include common rules.
#
CLEANFILES	= $(OBJECTS)

include ../../Makefile.tools

FILEMODE        = 555

CFLAGS		+= $(CCVERBOSE)

INC_PATH	= -I$(STABS_SRC)

LDLIBS		+= -lm
NATIVE_LIBS	+= libm.so

#
#       Default build targets.
#
.KEEP_STATE:

.PARALLEL: $(STABS_OBJS)

all: $(STABS_PROG)

install: all .WAIT $(ROOTONBLDMACHPROG)

clean:
	$(RM) $(CLEANFILES)

$(STABS_PROG): $(STABS_OBJS)
	$(LINK.c) -o $@ $(STABS_OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: $(STABS_SRC)/%.c
	$(COMPILE.c) $(INC_PATH) -o $@ -c $<

include ../../Makefile.targ
