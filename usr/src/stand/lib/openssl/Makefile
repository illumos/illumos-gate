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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/lib/Makefile.lib

HDRS= \
	aes.h \
	asn1.h \
	asn1_mac.h \
	asn1t.h \
	bio.h \
	bio_lcl.h \
	blowfish.h \
	bn.h \
	buffer.h \
	cast.h \
	comp.h \
	conf.h \
	conf_api.h \
	crypto.h \
	des.h \
	des_old.h \
	dh.h \
	dsa.h \
	dso.h \
	ebcdic.h \
	ec.h \
	ecdh.h \
	ecdsa.h \
	ech_locl.h \
	ecs_locl.h \
	engine.h \
	err.h \
	evp.h \
	hmac.h \
	idea.h \
	krb5_asn.h \
	lhash.h \
	md2.h \
	md4.h \
	md5.h \
	mdc2.h \
	o_dir.h \
	o_str.h \
	obj_mac.h \
	objects.h \
	ocsp.h \
	opensslconf.h \
	opensslv.h \
	ossl_typ.h \
	pcy_int.h \
	pem.h \
	pem2.h \
	pkcs12.h \
	pkcs7.h \
	pq_compat.h \
	pqueue.h \
	rand.h \
	rc2.h \
	rc4.h \
	rc5.h \
	ripemd.h \
	rsa.h \
	safestack.h \
	sha.h \
	stack.h \
	store.h \
	str_locl.h \
	symhacks.h \
	tmdiff.h \
	txt_db.h \
	ui.h \
	ui_compat.h \
	x509.h \
	x509_vfy.h \
	x509v3.h \
	kssl.h \
	ssl.h \
	ssl2.h \
	ssl3.h \
	ssl23.h \
	tls1.h \
	dtls1.h \
	e_os2.h


OPENSSL_SRC =	../../../common/openssl
HDRCRYPTODIR =	$(OPENSSL_SRC)/crypto
HDRSSLDIR =	$(OPENSSL_SRC)/ssl
HDRDIR = $(OPENSSL_SRC)

ROOTHDRDIR = ../openssl

all clobber lint:

CLOBBERFILES += $(HDRS)

install: $(ROOTHDRS)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRSSLDIR)/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/aes/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/asn1/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/bf/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/bio/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/bn/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/buffer/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/cast/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/comp/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/conf/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/des/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/dh/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/dsa/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/dso/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/ec/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/ecdh/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/ecdsa/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/engine/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/err/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/evp/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/hmac/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/idea/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/krb5/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/lhash/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/md2/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/md4/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/md5/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/mdc2/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/objects/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/ocsp/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/pem/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/pkcs12/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/pkcs7/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/pqueue/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/rand/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/rc2/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/rc4/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/rc5/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/ripemd/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/rsa/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/sha/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/stack/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/store/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/txt_db/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/ui/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/x509/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRCRYPTODIR)/x509v3/%
	 $(INS.file)


include $(SRC)/lib/Makefile.targ
