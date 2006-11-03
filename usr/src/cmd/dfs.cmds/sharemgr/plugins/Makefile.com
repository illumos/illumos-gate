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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include ../../../../Makefile.cmd

COMMON = ..

NFS_MOD		= libshare_nfs.so
NFS_SRC		= $(NFS_MOD:%.so=$(COMMON)/%.c)
NFSLIB_DIR	= $(SRC)/cmd/fs.d/nfs/lib

SHAREDSRC1	= nfs_sec.c
SHAREDSRC2	= nfslog_config.c
SHAREDSRC3	= nfslogtab.c
NFS_SRCS	= $(COMMON)/$(SHAREDSRC1) \
		$(COMMON)/$(SHAREDSRC2) $(COMMON)/$(SHAREDSRC3) $(NFS_SRC)
NFS_OBJS	= libshare_nfs.o nfs_sec.o nfslog_config.o nfslogtab.o

LINK_SRCS	= $(NFS_SRC)

LINT_MODULES 	= $(LINK_SRCS:.c=.ln)
# -u to eliminate XML warnings.
LINTFLAGS	+= -u

LINK_OBJS	= $(NFS_OBJS)

LINK_MODS	= $(NFS_MOD)

SRCS	= $(LINK_SRCS)
OBJS	= $(LINK_OBJS)
MODS	= $(LINK_MODS)

NFS_DIR		= fs/nfs
ROOTLIB_NFS_LINKMOD = $(ROOTLIB)/$(NFS_DIR)
ROOTLIB_NFS_LINK_MODS	= $(LINK_MODS:%=$(ROOTLIB_NFS_LINKMOD)/%)

CLOBBERFILES = $(MODS) $(SHAREDSRC)

MYCPPFLAGS = -I$(SRC)/lib/libshare/common -I$(SRC)/lib/libfsmgt/common \
		-I/usr/include/libxml2 -I.. -I../.. \
		-I../../../../fs.d/nfs/lib
CPPFLAGS += $(MYCPPFLAGS)
LDLIBS += -lshare -lnsl -lscf -lumem -lc
all install := LDLIBS += -lxml2
LDFLAGS += -zdefs -zcombreloc
CFLAGS += -Kpic

POFILES	= $(LINK_SRCS:.c=.po)
POFILE	= libshare_nfs.po

OWNER= root
GROUP= sys
FILEMODE= 555

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint


.KEEP_STATE:

all: $(MODS)

install: all \
	$(ROOTLIB_NFS_LINKMOD) \
	$(ROOTLIB_NFS_LINK_MODS)

%.so: %.o
	$(LINK.c) -o $@ $(GSHARED) -h $@ $<

%.o: $(COMMON)/%.c
	$(COMPILE.c) -o $@ $<

$(NFS_MOD): $(NFS_OBJS)
	$(LINK.c) -o $@ $(GSHARED) $(LDLIBS) -h $@ $(NFS_OBJS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS) 

lint: $(LINT_MODULES)

%.ln: FRC
	$(LINT.c) $(@:.ln=.c) $(LDLIBS)

FRC:

include ../../../../Makefile.targ

$(POFILE):      $(POFILES)
	$(RM) $@; cat $(POFILES) > $@

$(ROOTLIB_NFS):
	$(INS.dir)

$(ROOTLIB_NFS_LINKMOD):
	$(INS.dir)

$(ROOTLIB_NFS_LINKMOD)/%.so: %.so
	$(INS.file)

%.o:	$(NFSLIB_DIR)/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $< $(CTFCONVERT_HOOK)
	$(POST_PROCESS_O)
