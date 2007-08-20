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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG= iscsitgtd
OBJS	= main.o mgmt.o mgmt_create.o mgmt_list.o mgmt_modify.o mgmt_remove.o
OBJS	+= iscsi_authclient.o iscsi_authglue.o iscsi_cmd.o iscsi_conn.o
OBJS	+= iscsi_crc.o iscsi_ffp.o iscsi_login.o iscsi_sess.o radius.o
OBJS	+= t10_sam.o t10_spc.o t10_sbc.o t10_raw_if.o t10_ssc.o t10_osd.o
OBJS	+= t10_spc_pr.o util.o util_err.o util_ifname.o util_port.o util_queue.o
OBJS	+= isns_client.o isns.o
POFILE= iscsitgtd.po
POFILES	= $(OBJS:%.o=%.po)

include ../../Makefile.cmd
include $(SRC)/cmd/iscsi/Makefile.iscsi

$(64ONLY)SUBDIRS= $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

MANIFEST	= iscsi_target.xml
SVCMETHOD	= svc-iscsitgt

ROOTMANIFESTDIR	= $(ROOTSVCSYSTEM)
$(ROOTSVCSYSTEM)/iscsi_target.xml	:= OWNER = root
$(ROOTSVCSYSTEM)/iscsi_target.xml	:= GROUP = bin
$(ROOTSVCSYSTEM)/iscsi_target.xml	:= FILEMODE = 0444

DLIBSRCS = iscsi.d

ROOTDLIBDIR = $(ROOT)/usr/lib/dtrace
ROOTDLIBS = $(DLIBSRCS:%=$(ROOTDLIBDIR)/%)
$(ROOTDLIBS) := FILEMODE = 0644

CPPFLAGS += -D_FILE_OFFSET_BITS=64 -I${ISCSICOMMONDIR}

all	:=	TARGET = all
install	:=	TARGET = install
clean	:=	TARGET = clean
clobber	:=	TARGET = clobber
lint	:=	TARGET = lint

.KEEP_STATE:

all:	$(SUBDIRS)

clean clobber lint:	$(SUBDIRS)

install: $(SUBDIRS) $(ROOTMANIFEST) $(ROOTDLIBS) $(ROOTSVCMETHOD)
	-$(RM) $(ROOTUSRSBINPROG)
	-$(LN) $(ISAEXEC) $(ROOTUSRSBINPROG)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

catalog:	$(POFILE)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

check:	$(CHKMANIFEST)

$(ROOTDLIBDIR):
	$(INS.dir)

$(ROOTDLIBDIR)/%.d: %.d
	$(INS.file)

$(ROOTDLIBS): $(ROOTDLIBDIR)

FRC:

include ../../Makefile.targ
