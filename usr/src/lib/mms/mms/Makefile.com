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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#

LIBRARY =	libmms.a
VERS =		.1

NOLINTSRC =	cfg_yacc.c mmsp_yacc.c cfg_lex.c mmsp_lex.c cfg_parse.c

LIBSRCS = 	mms_list.c mmsp_common.c connect.c mms_mgmt.c msg_sub.c \
		host_ident.c mms_par_util.c net_cfg.c mms_api.c mms_rw.c \
		net_cfg_service.c mms_cat.c mms_scsi.c strapp.c mms_cfg.c \
		mms_sock.c trace.c mms_client.c mms_ssl.c mms_cores.c mms_sym.c

OBJECTS =	cfg_yacc.o mmsp_yacc.o cfg_lex.o mmsp_lex.o cfg_parse.o \
		mms_list.o mmsp_common.o connect.o mms_mgmt.o msg_sub.o \
		host_ident.o mms_par_util.o net_cfg.o mms_api.o mms_rw.o \
		net_cfg_service.o mms_cat.o mms_scsi.o strapp.o mms_cfg.o \
		mms_sock.o trace.o mms_client.o mms_ssl.o mms_cores.o mms_sym.o

include $(SRC)/lib/Makefile.lib

YACC		 = bison
YACCFLAGS	+= -vd

SRCS = 		$(LIBSRCS:%.c=../common/%.c)
LIBS =		$(DYNLIB) $(LINTLIB)

SRCDIR =	../common

LDLIBS +=	-lc -lsocket -lnsl -lscf
LDLIBS +=	-lssl -lcrypto

CFLAGS +=	$(CTF_FLAGS) $(CCVERBOSE)
CFLAGS += 	$(C_BIGPICFLAGS)

CPPFLAGS +=	-DMMS_OPENSSL
CPPFLAGS +=	-I$(SRCDIR) -I$(SRC)/common/mms/mms

C99MODE=	$(C99_ENABLE)

LOGMMS = $(ROOT)/var/log/mms

FILES += $(LOGMMS)/mms_logadm.conf

.KEEP_STATE:

all:  $(SRCDIR)/cfg_yacc.c $(SRCDIR)/mmsp_yacc.c .WAIT \
	$(SRCDIR)/cfg_lex.c $(SRCDIR)/mmsp_lex.c .WAIT \
	$(LIBS) $(LIBLINKS)

install: $(FILES)

lint:  $(LINTLIB) lintcheck

CLEANFILES += \
	$(SRCDIR)/cfg_yacc.c	\
	$(SRCDIR)/cfg_yacc.h	\
	$(SRCDIR)/mmsp_yacc.c	\
	$(SRCDIR)/mmsp_yacc.h	\
	$(SRCDIR)/cfg_lex.c	\
	$(SRCDIR)/mmsp_lex.c

$(LOGMMS):
	$(INS.dir)

$(LOGMMS)/%: $(LOGMMS) ../common/%
	$(INS.file)

$(SRCDIR)/cfg_yacc.c: $(SRCDIR)/cfg_yacc.y
	$(YACC) $(YACCFLAGS) $(SRCDIR)/cfg_yacc.y -o $(SRCDIR)/cfg_yacc.c
	rm -f $(SRCDIR)/cfg_yacc.output

$(SRCDIR)/mmsp_yacc.c: $(SRCDIR)/mmsp_yacc.y
	$(YACC) $(YACCFLAGS) $(SRCDIR)/mmsp_yacc.y -o $(SRCDIR)/mmsp_yacc.c
	rm -f $(SRCDIR)/mmsp_yacc.output

$(SRCDIR)/cfg_lex.c:	$(SRCDIR)/cfg_lex.l
	$(FLEX) -t $(SRCDIR)/cfg_lex.l > $(SRCDIR)/cfg_lex.c

$(SRCDIR)/mmsp_lex.c:	$(SRCDIR)/mmsp_lex.l
	$(FLEX) -t $(SRCDIR)/mmsp_lex.l > $(SRCDIR)/mmsp_lex.c

$(LIBLINKS):    FRC
	$(RM) $@; $(SYMLINK) $(DYNLIB) $@

$(ROOTLIBDIR):
	$(INS.dir)

$(ROOTLIBDIR64):
	$(INS.dir)

FRC: 

include $(SRC)/lib/Makefile.targ
