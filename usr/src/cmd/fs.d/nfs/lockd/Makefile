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
# Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2012 by Delphix. All rights reserved.
#

FSTYPE	  =	nfs
TYPEPROG  =	lockd
ATTMK	  =	$(TYPEPROG)

include		../../Makefile.fstype

LOCAL	  =	lockd.o
OBJS	  =	$(LOCAL) daemon.o nfs_tbind.o smfcfg.o thrpool.o

POFILE	  =	lockd.po

SRCS	  =	$(LOCAL:%.o=%.c) ../lib/daemon.c ../lib/nfs_tbind.c \
		../lib/smfcfg.c ../lib/thrpool.c
LDLIBS	 +=	-lnsl -lscf
CPPFLAGS +=	-I../lib
C99MODE	  =	$(C99_ENABLE)

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-uninitialized

$(TYPEPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

lockd.o:	lockd.c
		$(COMPILE.c) lockd.c

nfs_tbind.o:	../lib/nfs_tbind.c
		$(COMPILE.c) ../lib/nfs_tbind.c

thrpool.o:	../lib/thrpool.c
		$(COMPILE.c) ../lib/thrpool.c

daemon.o:	../lib/daemon.c
		$(COMPILE.c) ../lib/daemon.c

smfcfg.o:	../lib/smfcfg.c
		$(COMPILE.c) ../lib/smfcfg.c

#
# message catalog
#
catalog: $(POFILE)

$(POFILE): $(SRCS)
	$(RM) $@
	$(COMPILE.cpp) $(SRCS)   > $(POFILE).i
	$(XGETTEXT)     $(XGETFLAGS) $(POFILE).i
	sed "/^domain/d"        messages.po     > $@
	$(RM) $(POFILE).i messages.po

lint:
	$(LINT.c) $(SRCS) $(LDLIBS)

clean:
	$(RM) $(OBJS) $(DOBJ)
