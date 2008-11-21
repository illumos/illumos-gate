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
#

include $(SRC)/lib/Makefile.lib
include ../Makefile.com

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
	x509v3.h


HDRDIR =	$(OPENSSL_SRC)/crypto
ROOTHDRDIR =	$(ROOT)/usr/include/openssl

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint

.KEEP_STATE:
.PARALLEL:

all clean clobber install lint: $(SUBDIRS)

install_h:	$(ROOTHDRS)

_msg:

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

$(ROOTHDRDIR)/%: $(HDRDIR)/aes/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/asn1/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/bf/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/bio/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/bn/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/buffer/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/cast/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/comp/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/conf/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/des/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/dh/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/dsa/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/dso/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/ec/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/ecdh/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/ecdsa/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/engine/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/err/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/evp/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/hmac/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/idea/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/krb5/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/lhash/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/md2/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/md4/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/md5/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/mdc2/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/objects/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/ocsp/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/pem/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/pkcs12/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/pkcs7/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/pqueue/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/rand/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/rc2/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/rc4/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/rc5/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/ripemd/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/rsa/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/sha/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/stack/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/store/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/txt_db/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/ui/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/x509/%
	 $(INS.file)

$(ROOTHDRDIR)/%: $(HDRDIR)/x509v3/%
	 $(INS.file)


include $(SRC)/lib/Makefile.targ
