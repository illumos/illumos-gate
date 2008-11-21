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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

PROG =	openssl

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/lib/openssl/Makefile.openssl

OBJS =	\
	app_rand.o \
	apps.o \
	asn1pars.o \
	ca.o \
	ciphers.o \
	crl.o \
	crl2p7.o \
	dgst.o \
	dh.o \
	dhparam.o \
	dsa.o \
	dsaparam.o \
	enc.o \
	engine.o \
	errstr.o \
	gendh.o \
	gendsa.o \
	genrsa.o \
	nseq.o \
	ocsp.o \
	openssl.o \
	passwd.o \
	pkcs12.o \
	pkcs7.o \
	pkcs8.o \
	prime.o \
	rand.o \
	req.o \
	rsa.o \
	rsautl.o \
	s_cb.o \
	s_client.o \
	s_server.o \
	s_socket.o \
	s_time.o \
	sess_id.o \
	smime.o \
	speed.o \
	spkac.o \
	verify.o \
	version.o \
	x509.o

SRCDIR =	$(OPENSSL_SRC)/apps

ROOTCMDDIR =	$(ROOTBIN)

CFLAGS +=	$(CCVERBOSE) \
	-erroff=E_END_OF_LOOP_CODE_NOT_REACHED,E_CONST_PROMOTED_UNSIGNED_LONG

CFLAGS64 +=	-erroff=E_END_OF_LOOP_CODE_NOT_REACHED

CPPFLAGS =	\
	$(OPENSSL_BUILD_CPPFLAGS) -I$(SRCDIR) -DMONOLITH $(CPPFLAGS.master)

LDLIBS +=	-lcrypto -lssl -lnsl -lsocket -lc 

.KEEP_STATE:

.PARALLEL: $(OBJS)

all:	$(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS) $(DYNFLAGS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS)

include $(SRC)/cmd/Makefile.targ

%.o: $(SRCDIR)/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

# Rule to install CA.pl
$(ROOTCMDDIR)/%: $(SRCDIR)/% $(ROOTCMDDIR)
	$(INS.file)
