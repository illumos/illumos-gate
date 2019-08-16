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
# Copyright (c) 2018, Joyent, Inc.

PROG= listen nlps_server

DBGOBJ	= doprnt.o
DBGSRC	= doprnt.c

LSOBJS  =	listen.o lslog.o lsdbf.o lsdata.o nstoa.o nlsaddr.o

NLPSOBJS =	nlps_serv.o lsdbf.o lssmb.o nstoa.o lslog.o lsdata.o

OBJS= $(LSOBJS) $(NLPSOBJS)
LSSRC= $(LSOBJS:%.o=%.c)
NLPSSRC= $(NLPSOBJS:%.o=%.c)
SRCS= $(LSSRC) $(NLPSSRC)

include ../Makefile.cmd

LIBSAFD = $(ROOTLIB)/saf
NETD = $(ROOT)/usr/net
NETNLSD = $(NETD)/nls

# Don"t re-install /usr/lib/saf/ and /usr/net, Targetdirs installs them
#DIRS= $(LIBSAFD) $(NETD) $(NETNLSD)
DIRS=  $(NETNLSD)
ROOTSAFPROG= $(PROG:%=$(LIBSAFD)/%) 

# If machine name and /etc/issue file need to be printed
# before the service prompt is printed, then:  CPPFLAGS += -DSYS_NAME
# If debug is needed, then:  CPPFLAGS += -DDEBUG

LDLIBS += -lnsl
LDFLAGS += $(MAPFILE.NGB:%=-M%)
LINTFLAGS = -b -x
FILEMODE= 0755

CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-empty-body
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)

# not linted
SMATCH=off

$(LIBSAFD)/% : %
	$(INS.file)

.KEEP_STATE:

all: $(PROG)

listen:	$(LSOBJS) $(MAPFILE.NGB)
	$(LINK.c) $(LSOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

nlps_server:	$(NLPSOBJS) $(MAPFILE.NGB)
	$(LINK.c) $(NLPSOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(DIRS) $(ROOTSAFPROG)
	$(RM) $(ROOT)/usr/net/nls/listen
	-$(SYMLINK) ../../lib/saf/listen $(ROOT)/usr/net/nls/listen
	$(RM) $(ROOT)/usr/net/nls/nlps_server
	-$(SYMLINK) ../../lib/saf/nlps_server $(ROOT)/usr/net/nls/nlps_server

$(DIRS):
	$(INS.dir)

clean:
	$(RM) $(OBJS)

lint:
	$(LINT.c) $(LSSRC)
	$(LINT.c) $(NLPSSRC)

include ../Makefile.targ
