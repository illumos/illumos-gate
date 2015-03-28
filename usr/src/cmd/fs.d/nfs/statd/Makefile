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
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
#

#
# Copyright 1990-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

FSTYPE=		nfs
TYPEPROG=	statd
ATTMK=		$(TYPEPROG)

include		../../Makefile.fstype
CPPFLAGS +=     -D_REENTRANT -DSUN_THREADS

CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized

LOCAL=		sm_svc.o sm_proc.o sm_statd.o
OBJS= 		$(LOCAL) selfcheck.o daemon.o

SRCS=		$(LOCAL:%.o=%.c) ../lib/selfcheck.c ../lib/daemon.c

LDLIBS +=	-lsocket -lrpcsvc -lnsl

$(TYPEPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)
		$(LOCK_LINT)

selfcheck.o:	../lib/selfcheck.c
		$(COMPILE.c) ../lib/selfcheck.c

daemon.o:	../lib/daemon.c
		$(COMPILE.c) ../lib/daemon.c

lint:		lint_SRCS

clean:
		$(RM) $(OBJS) $(TYPEPROG)
