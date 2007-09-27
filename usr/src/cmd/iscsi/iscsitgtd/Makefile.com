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

PROG = iscsitgtd

DSRC = iscsi_provider.d
DTRACE_HEADER = $(DSRC:%.d=%.h)

COBJS	= main.o mgmt.o mgmt_create.o mgmt_list.o mgmt_modify.o mgmt_remove.o
COBJS	+= iscsi_authclient.o iscsi_authglue.o iscsi_cmd.o iscsi_conn.o
COBJS	+= iscsi_crc.o iscsi_ffp.o iscsi_login.o iscsi_sess.o radius.o
COBJS	+= t10_sam.o t10_spc.o t10_sbc.o t10_raw_if.o t10_ssc.o t10_osd.o
COBJS	+= t10_spc_pr.o util.o util_err.o util_ifname.o util_port.o util_queue.o
COBJS	+= isns_client.o isns.o mgmt_scf.o
OBJS=	$(COBJS) $(DSRC:%.d=%.o)
SRCS=	$(COBJS:%.o=../%.c) $(COMMON_SRCS)

include ../../../Makefile.cmd
include $(SRC)/cmd/iscsi/Makefile.iscsi

CTFMERGE_HOOK = && $(CTFMERGE) -L VERSION -o $@ $(OBJS)
CTFCONVERT_HOOK = && $(CTFCONVERT_O)
CFLAGS += $(CTF_FLAGS)
CFLAGS64 += $(CTF_FLAGS)
NATIVE_CFLAGS += $(CTF_FLAGS)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_LARGEFILE64_SOURCE=1 -I/usr/include/libxml2
CFLAGS64 +=	$(CCVERBOSE)

SUFFIX_LINT = .ln

GROUP = sys

CLEANFILES += $(OBJS) ../$(DTRACE_HEADER)

.KEEP_STATE:

all: $(PROG)

LDLIBS	+= -lumem -luuid -lxml2 -lsocket -lnsl -ldoor -lavl -lmd5 -ladm -lefi
LDLIBS  += -liscsitgt -lzfs -ldlpi -lsecdb -lscf -lsasl

$(PROG): $(OBJS) $(COMMON_OBJS)
	$(LINK.c) $(OBJS) $(COMMON_OBJS) -o $@ $(LDLIBS) $(CTFMERGE_HOOK)
	$(POST_PROCESS)

lint := LINTFLAGS += -u
lint := LINTFLAGS64 += -u

lint: $(SRCS:../%=%$(SUFFIX_LINT))

%$(SUFFIX_LINT): ../%
	${LINT.c} -I.. ${INCLUDES} -y -c $< && touch $@

../%.h:	../%.d
	$(DTRACE) -xnolibs -h -s $< -o $@

%.o:	$(ISCSICOMMONDIR)/%.c ../$(DTRACE_HEADER)
	$(COMPILE.c) $< $(CTFCONVERT_HOOK)
	$(POST_PROCESS_O)

%.o:	../%.c ../$(DTRACE_HEADER)
	$(COMPILE.c) $< $(CTFCONVERT_HOOK)
	$(POST_PROCESS_O)

%.o:	../%.d $(COBJS)
	$(COMPILE.d) -xnolibs -s $< $(COBJS)

clean:
	$(RM) $(CLEANFILES) $(COMMON_OBJS) *$(SUFFIX_LINT)

include ../../../Makefile.targ
