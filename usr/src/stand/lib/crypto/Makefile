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
# See the README file in this directory for a description of how to cull
# objects unused by the standalone boot applications from the OBJECTS list.
#

LIBRARY = libcrypto.a

OBJECTS = cryptlib.o	mem.o		mem_dbg.o	ex_data.o	\
	cpt_err.o	o_time.o	mem_clr.o	o_dir.o		\
	\
	a_object.o	a_bitstr.o	a_utctm.o	a_gentm.o	\
	a_time.o	a_int.o		a_octet.o	a_print.o	\
	a_type.o	a_set.o		a_dup.o		a_d2i_fp.o	\
	a_i2d_fp.o	a_enum.o	a_utf8.o	a_sign.o	\
	a_digest.o	a_verify.o	a_mbstr.o	a_strex.o	\
	x_algor.o	x_val.o		x_pubkey.o	x_sig.o		\
	x_req.o		x_attrib.o	x_bignum.o	x_long.o	\
	x_name.o	x_x509.o	x_x509a.o	x_crl.o		\
	x_info.o	x_spki.o	nsseq.o		d2i_pu.o	\
	d2i_pr.o	i2d_pu.o	i2d_pr.o	t_x509.o	\
	t_x509a.o	t_pkey.o	tasn_new.o	tasn_fre.o	\
	tasn_enc.o	tasn_dec.o	tasn_utl.o	tasn_typ.o	\
	f_int.o		f_string.o	x_pkey.o	a_bool.o	\
	x_exten.o	asn1_par.o	asn1_lib.o	asn1_err.o	\
	a_bytes.o	a_strnid.o	evp_asn1.o	asn_pack.o	\
	p5_pbe.o	p5_pbev2.o	p8_pkey.o	asn1_gen.o	\
	\
	bf_skey.o	bf_ecb.o	bf_cfb64.o	bf_ofb64.o	\
	bf_enc.o							\
	\
	bio_lib.o	bio_err.o	bss_file.o	bss_sock.o	\
	bf_buff.o	b_print.o	b_dump.o			\
	\
	bn_add.o	bn_div.o	bn_exp.o	bn_lib.o	\
	bn_ctx.o	bn_mul.o	bn_mod.o	bn_print.o	\
	bn_rand.o	bn_shift.o	bn_word.o	bn_blind.o	\
	bn_gcd.o	bn_prime.o	bn_asm.o	bn_mont.o	\
	bn_err.o	bn_sqr.o	bn_recp.o	bn_exp2.o	\
	\
	buffer.o	buf_err.o					\
	\
	comp_lib.o							\
	\
	conf_err.o	conf_lib.o	conf_api.o	conf_def.o	\
	conf_mod.o							\
	\
	set_key.o	ecb_enc.o	ecb3_enc.o	ofb64enc.o	\
	cfb64enc.o	cfb64ede.o	cfb_enc.o	ofb64ede.o	\
	\
	xcbc_enc.o	des_enc.o					\
	\
	dh_asn1.o	dh_key.o	dh_lib.o	dh_check.o	\
	dh_err.o							\
	\
	dsa_vrf.o	dsa_sign.o	dsa_err.o	dsa_ossl.o	\
	dsa_lib.o	dsa_asn1.o					\
	\
	dso_lib.o	dso_null.o	dso_openssl.o			\
	\
	err.o		err_all.o	err_prn.o			\
	\
	c_all.o		c_allc.o	c_alld.o	digest.o	\
	e_des3.o	e_null.o	e_rc2.o		e_xcbc_d.o	\
	e_bf.o		e_des.o		encode.o	evp_enc.o	\
	evp_err.o	evp_key.o	evp_lib.o	evp_pbe.o	\
	evp_pkey.o	m_dss.o		m_dss1.o	m_md5.o		\
	m_sha.o		m_sha1.o	names.o		p5_crpt.o	\
	p5_crpt2.o	p_lib.o		p_sign.o	p_verify.o	\
	\
	eng_list.o	eng_ctrl.o	eng_table.o	tb_cipher.o	\
	eng_err.o	tb_dh.o		tb_digest.o	eng_init.o	\
	tb_dsa.o	eng_lib.o	tb_rand.o	tb_rsa.o	\
	\
	hmac.o								\
	\
	lhash.o								\
	\
	md5_dgst.o	md5-sparcv9.o					\
	\
	o_names.o	obj_dat.o	obj_err.o	obj_lib.o	\
	\
	ocsp_asn.o	ocsp_err.o					\
	\
	pem_info.o	pem_lib.o	pem_all.o	pem_err.o	\
	pem_x509.o	pem_xaux.o	pem_oth.o	pem_pkey.o	\
	\
	p12_add.o	p12_asn.o	p12_crpt.o	p12_key.o	\
	p12_mutl.o	p12_utl.o	pk12err.o	p12_p8d.o	\
	p12_attr.o	p12_decr.o	p12_p8e.o			\
	\
	pk7_asn1.o	pk7_lib.o	pkcs7err.o			\
	\
	md_rand.o	randfile.o	rand_lib.o	rand_err.o	\
	rand_unix.o							\
	\
	rc2_cbc.o	rc2_ecb.o	rc2_skey.o	rc2cfb64.o	\
	rc2ofb64.o							\
	\
	rsa_eay.o	rsa_lib.o	rsa_sign.o	rsa_err.o	\
	rsa_pk1.o	rsa_ssl.o	rsa_none.o	rsa_oaep.o	\
	rsa_asn1.o	rsa_x931.o					\
	\
	sha_dgst.o	sha1dgst.o	sha256.o	sha512.o	\
	\
	stack.o								\
	\
	ui_err.o							\
	\
	x509_def.o	x509_d2.o 	x509_cmp.o	x509_obj.o	\
	x509_req.o 	x509_vfy.o	x509rset.o	x509_err.o	\
	x509name.o	x509_v3.o	x509_ext.o	x509_att.o	\
	x509type.o	x509_lu.o	x_all.o		x509_txt.o	\
	x509_trs.o	by_file.o	by_dir.o	x509_vpm.o	\
	\
	v3_ia5.o	v3_lib.o	v3_prn.o	v3_utl.o	\
	v3_pku.o	v3_int.o	v3_enum.o	v3err.o		\
	v3_alt.o	v3_genn.o	v3_pci.o	v3_pcia.o	\
	v3_purp.o	v3_info.o	v3_ocsp.o	v3_bitst.o	\
	v3_conf.o	v3_extku.o	v3_cpols.o	v3_crld.o	\
	v3_akey.o	v3_akeya.o	v3_skey.o	v3_sxnet.o	\
	v3_ncons.o	v3_bcons.o	v3_pcons.o	v3_pmaps.o	\
	\
	pcy_cache.o	pcy_tree.o	pcy_data.o	pcy_lib.o	\
	pcy_map.o	pcy_node.o					\
	\
	$($(MACH)_OBJECTS)


include ../Makefile.com

SRCDIR = $(TOPDIR)/common/openssl/crypto

SRCS =	$(OBJECTS:%.o= \
	$(SRCDIR)/asn1/%.c           $(SRCDIR)/rc2/%.c            \
        $(SRCDIR)/bf/%.c             $(SRCDIR)/dsa/%.c            \
        $(SRCDIR)/bio/%.c            $(SRCDIR)/bn/%.c             \
        $(SRCDIR)/buffer/%.c                                      \
        $(SRCDIR)/comp/%.c           $(SRCDIR)/conf/%.c           \
        $(SRCDIR)/des/%.c            $(SRCDIR)/dh/%.c             \
        $(SRCDIR)/err/%.c            $(SRCDIR)/evp/%.c            \
        $(SRCDIR)/engine/%.c         $(SRCDIR)/hmac/%.c           \
        $(SRCDIR)/lhash/%.c          $(SRCDIR)/ocsp/%.c           \
        $(SRCDIR)/objects/%.c        $(SRCDIR)/pem/%.c            \
        $(SRCDIR)/pkcs12/%.c         $(SRCDIR)/pkcs7/%.c          \
        $(SRCDIR)/rand/%.c           $(SRCDIR)/rsa/%.c            \
        $(SRCDIR)/sha/%.c            $(SRCDIR)/stack/%.c          \
        $(SRCDIR)/txt_db/%.c         $(SRCDIR)/ui/%.c             \
        $(SRCDIR)/x509/%.c           $(SRCDIR)/x509v3/%.c	  \
	$(SRCDIR)/md5/%.c)

#
# We don't have chmod() in the standalone environment.
# We also need to prepend the OpenSSL CPPFLAGS.
#
CPPFLAGS += $(OPENSSL_BUILD_CPPFLAGS) -DNO_CHMOD -I../sock

# The following blocks work around code in the OpenSSL open source distribution
# that fail to follow Sun coding standards and fail to compile without warnings.
# Instead of changing the shared openssl code, we supress compiler warnings for
# them.
CRYPTO_OBS = \
	a_strex.o  asn1_par.o bf_enc.o   x_algor.o  x_val.o    x_pubkey.o \
        x_sig.o    x_req.o    x_attrib.o x_name.o   x_x509.o   x_x509a.o  \
        x_crl.o    x_spki.o   nsseq.o    x_exten.o  p5_pbe.o   \
        p5_pbev2.o p8_pkey.o  dsa_asn1.o dh_asn1.o  p12_asn.o  pk7_asn1.o \
        rsa_asn1.o v3_bcons.o v3_extku.o v3_genn.o  v3_pku.o   v3_sxnet.o \
        v3_cpols.o v3_crld.o  v3_info.o  v3_akeya.o ocsp_asn.o 

$(CRYPTO_OBS:%.o=objs/%.o) := CPPFLAGS += \
	-erroff=E_TYP_STORAGE_CLASS_OBSOLESCENT

# Rather than change the shared openssl code, we permit incomplete
# type-based arguments
CRYPTO_INCOM = \
	err_all.o

$(CRYPTO_INCOM:%.o=objs/%.o) := CPPFLAGS += \
	-erroff=E_ARRAY_OF_INCOMPLETE_NONAME

# M_ASN1_I2D_finish(), M_ASN1_D2I_Finish() macros confuse compiler
CRYPTO_FIN_OBJ = \
	p8_key.o   x_cinf.o   x_pkey.o   x509_vfy.o

$(CRYPTO_FIN_OBJ:%.o=objs/%.o) := CPPFLAGS += \
	-erroff=E_STATEMENT_NOT_REACHED

CRYPTO_ULONG_OBJ = \
	a_int.o		a_enum.o	a_strex.o	a_strnid.o	\
	bf_skey.o	bf_enc.o	bss_sock.o	bn_add.o	\
	bn_div.o	bn_lib.o	bn_shift.o	bn_word.o	\
	bn_mul.o	bn_asm.o	bn_mont.o	bn_sqr.o	\
	set_key.o	ecb_enc.o	des_enc.o	lhash.o		\
	sha1dgst.o	sha_dgst.o	x509_cmp.o

$(CRYPTO_ULONG_OBJ:%.o=objs/%.o) := CPPFLAGS += \
	-erroff=E_CONST_PROMOTED_UNSIGNED_LONG

CERRWARN += -_gcc=-Wno-unused-value
CERRWARN += -_gcc=-Wno-address
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused-variable

objs/md5_dgst.o := CPPFLAGS += -DMD5_ASM
objs/md5-sparcv9.o := CPPFLAGS += -DMD5_BLOCK_DATA_ORDER

objs/%.o: $(SRCDIR)/asn1/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/bf/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/dsa/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/dso/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/bio/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/bn/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/buffer/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/comp/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/conf/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/des/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/dh/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/err/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/engine/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/evp/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/hmac/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/lhash/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/objects/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/ocsp/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/pem/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/pkcs12/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/pkcs7/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/rand/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/rc2/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/rsa/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/md5/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/md5/asm/%.S
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/sha/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/stack/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/txt_db/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/ui/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/x509/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
objs/%.o: $(SRCDIR)/x509v3/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../Makefile.targ
