#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#  Copyright (c) 1988, 1989, 1990, 1991, 1992, 1995, 1996, 1997
#	The Regents of the University of California.  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that: (1) source code distributions
#  retain the above copyright notice and this paragraph in its entirety, (2)
#  distributions including binary code include the above copyright notice and
#  this paragraph in its entirety in the documentation or other materials
#  provided with the distribution, and (3) all advertising materials mentioning
#  features or use of this software display the following acknowledgement:
#  ``This product includes software developed by the University of California,
#  Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
#  the University nor the names of its contributors may be used to endorse
#  or promote products derived from this software without specific prior
#  written permission.
#  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
#  WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
#

PROG=		traceroute
OBJS=		traceroute.o traceroute_aux.o traceroute_aux6.o
SRCS=		$(OBJS:.o=.c)

include	../../../Makefile.cmd

$(ROOTUSRSBIN)/traceroute	:=	FILEMODE= 04555

# Traceroute uses the ancillary data feature which is available only through
# UNIX 98 standards version of Socket interface. This interface is supposed to
# be accessed by -lxnet. In addition -lsocket is used to
# capture new not-yet-standard interfaces. Someday -lxnet alone should be enough
# when IPv6 inspired new interfaces are part of standards.
LDLIBS +=	-lxnet -lsocket -linetutil

# These #defines are required to use UNIX 98 interfaces
CPPFLAGS += -D_XOPEN_SOURCE=500 -D__EXTENSIONS__

#
# Setting the above defines to use the UNIX98 ancillary data feature
# causes lint to output warnings about lint library declarations
# conflicting with those in the header files. Since we need these
# features, the best course of action is to switch the types of the
# resulting warnings off when running lint.
#
LINTFLAGS +=	-erroff=E_FUNC_DECL_VAR_ARG2 -erroff=E_INCONS_ARG_DECL2 \
		-erroff=E_INCONS_ARG_USED2 -erroff=E_INCONS_VAL_TYPE_DECL2

CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-clobbered

.KEEP_STATE:

all:	$(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include ../../../Makefile.targ
