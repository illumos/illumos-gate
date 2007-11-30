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
# cmd/ssh/sshd/Makefile

PROG= sshd

DIRS= $(ROOTLIBSSH)

OBJS	= sshd.o \
	  altprivsep.o \
	  auth.o \
	  auth1.o \
	  auth2.o \
	  auth-options.o \
	  auth2-chall.o \
	  auth2-gss.o \
	  auth2-hostbased.o \
	  auth2-kbdint.o \
	  auth2-none.o \
	  auth2-passwd.o \
	  auth2-pam.o \
	  auth2-pubkey.o \
	  auth-bsdauth.o \
	  auth-chall.o \
	  auth-rhosts.o \
	  auth-krb4.o \
	  auth-krb5.o \
	  auth-pam.o \
	  auth-passwd.o \
	  auth-rsa.o \
	  auth-rh-rsa.o \
	  auth-sia.o \
	  auth-skey.o \
	  bsmaudit.o \
	  groupaccess.o \
	  gss-serv.o \
	  loginrec.o \
	  md5crypt.o \
	  servconf.o \
	  serverloop.o \
	  session.o \
	  sshlogin.o \
	  sshpty.o
SRCS	= $(OBJS:.o=.c)

include ../../Makefile.cmd
include ../Makefile.ssh-common

LDLIBS += $(SSH_COMMON_LDLIBS) -lsocket \
	-lnsl \
	-lz \
	-lpam \
	-lbsm \
	-L$(ROOTSFWLIB) -lwrap \
	$(OPENSSL_LDFLAGS) -lcrypto \
	-lgss \
	-lcontract
MAPFILES = $(MAPFILE.INT) $(MAPFILE.NGB)
LDFLAGS += $(MAPFILES:%=-M%)

DYNFLAGS += $(OPENSSL_DYNFLAGS) $(C99_DISABLE)

POFILE_DIR= ..

CPPFLAGS += -I$(ROOTSFWINCLUDE)

.KEEP_STATE:

.PARALLEL: $(OBJS)

all: $(PROG)

$(PROG): $(OBJS) $(MAPFILES) ../libssh/$(MACH)/libssh.a \
	../libopenbsd-compat/$(MACH)/libopenbsd-compat.a
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS) $(DYNFLAGS)
	$(POST_PROCESS)

install: all $(DIRS) $(ROOTLIBSSHPROG) $(ROOTLIBSSH)


$(ROOTLIBSSHPROG)/%: %
	$(INS.file)

$(DIRS):
	$(INS.dir)

clean:
	$(RM) -f $(OBJS) $(PROG)

lint:	lint_SRCS

include ../Makefile.msg.targ
include ../../Makefile.targ
