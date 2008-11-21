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

LIBRARY = libcrypto.a

OBJECTS = \
	cryptlib.o	mem.o		mem_dbg.o	cversion.o	\
	ex_data.o	tmdiff.o	cpt_err.o	o_time.o	\
	uid.o		mem_clr.o	o_str.o		o_dir.o		\
	\
	aes/aes_cbc.o	aes/aes_cfb.o	aes/aes_core.o	aes/aes_ctr.o	\
	aes/aes_ecb.o	aes/aes_misc.o	aes/aes_ofb.o			\
	\
	asn1/a_object.o	asn1/a_bitstr.o	asn1/a_utctm.o	asn1/a_gentm.o	\
	asn1/a_time.o	asn1/a_int.o	asn1/a_octet.o	asn1/a_print.o	\
	asn1/a_type.o	asn1/a_set.o	asn1/a_dup.o	asn1/a_d2i_fp.o	\
	asn1/a_i2d_fp.o	asn1/a_enum.o	asn1/a_utf8.o	asn1/a_sign.o	\
	asn1/a_digest.o	asn1/a_verify.o	asn1/a_mbstr.o	asn1/a_strex.o	\
	asn1/x_algor.o	asn1/x_val.o	asn1/x_pubkey.o	asn1/x_sig.o	\
	asn1/x_req.o	asn1/x_attrib.o	asn1/x_bignum.o	asn1/x_long.o	\
	asn1/x_name.o	asn1/x_x509.o	asn1/x_x509a.o	asn1/x_crl.o	\
	asn1/x_info.o	asn1/x_spki.o	asn1/nsseq.o	asn1/d2i_pu.o	\
	asn1/d2i_pr.o	asn1/i2d_pu.o	asn1/i2d_pr.o	asn1/t_req.o	\
	asn1/t_x509.o	asn1/t_x509a.o	asn1/t_crl.o	asn1/t_pkey.o	\
	asn1/t_spki.o	asn1/t_bitst.o	asn1/tasn_new.o	asn1/tasn_fre.o	\
	asn1/tasn_enc.o	asn1/tasn_dec.o	asn1/tasn_utl.o	asn1/tasn_typ.o	\
	asn1/f_int.o	asn1/f_string.o	asn1/n_pkey.o	asn1/f_enum.o	\
	asn1/a_hdr.o	asn1/x_pkey.o	asn1/a_bool.o	asn1/x_exten.o	\
	asn1/asn1_par.o	asn1/asn1_lib.o	asn1/asn1_err.o	asn1/a_meth.o	\
	asn1/a_bytes.o	asn1/a_strnid.o	asn1/evp_asn1.o	asn1/asn_pack.o	\
	asn1/p5_pbe.o	asn1/p5_pbev2.o	asn1/p8_pkey.o	asn1/asn_moid.o	\
	asn1/asn1_gen.o							\
	\
	bf/bf_skey.o	bf/bf_ecb.o	bf/bf_cfb64.o	bf/bf_ofb64.o	\
	bf/bf_enc.o							\
	\
	bio/bio_lib.o	bio/bio_cb.o	bio/bio_err.o	bio/bss_mem.o	\
	bio/bss_null.o	bio/bss_fd.o	bio/bss_file.o	bio/bss_sock.o	\
	bio/bss_conn.o	bio/bf_null.o	bio/bf_buff.o	bio/b_print.o	\
	bio/b_dump.o	bio/b_sock.o	bio/bss_acpt.o	bio/bf_nbio.o	\
	bio/bss_log.o	bio/bss_bio.o	bio/bss_dgram.o			\
	\
	bn/bn_add.o	bn/bn_div.o	bn/bn_exp.o	bn/bn_lib.o	\
	bn/bn_ctx.o	bn/bn_mul.o	bn/bn_mod.o	bn/bn_print.o	\
	bn/bn_rand.o	bn/bn_shift.o	bn/bn_word.o	bn/bn_blind.o	\
	bn/bn_kron.o	bn/bn_sqrt.o	bn/bn_gcd.o	bn/bn_prime.o	\
	bn/bn_err.o	bn/bn_sqr.o	bn/bn_recp.o	bn/bn_mont.o	\
	bn/bn_const.o	bn/bn_depr.o	bn/bn_gf2m.o	bn/bn_nist.o	\
	bn/bn_mpi.o	bn/bn_exp2.o					\
	\
	buffer/buffer.o	buffer/buf_err.o				\
	\
	cast/c_enc.o	cast/c_ecb.o	cast/c_cfb64.o	cast/c_ofb64.o	\
	cast/c_skey.o							\
	\
	comp/comp_lib.o	comp/c_rle.o	comp/c_zlib.o			\
	\
	conf/conf_err.o	conf/conf_lib.o	conf/conf_api.o	conf/conf_sap.o	\
	conf/conf_def.o	conf/conf_mod.o	conf/conf_mall.o		\
	\
	des/set_key.o	des/ecb_enc.o	des/cbc_enc.o	des/ecb3_enc.o	\
	des/cfb64enc.o	des/cfb64ede.o	des/cfb_enc.o	des/ofb64ede.o	\
	des/enc_read.o	des/enc_writ.o	des/ofb64enc.o	des/ofb_enc.o	\
	des/str2key.o	des/pcbc_enc.o	des/qud_cksm.o	des/rand_key.o	\
	des/fcrypt.o	des/xcbc_enc.o	des/rpc_enc.o	des/cbc_cksm.o	\
	des/des_old.o	des/des_old2.o	des/read2pwd.o	des/des_enc.o	\
	des/fcrypt_b.o	des/ede_cbcm_enc.o				\
	\
	dh/dh_asn1.o	dh/dh_gen.o	dh/dh_key.o	dh/dh_lib.o	\
	dh/dh_check.o	dh/dh_err.o	dh/dh_depr.o			\
	\
	dsa/dsa_gen.o	dsa/dsa_key.o	dsa/dsa_lib.o	dsa/dsa_asn1.o	\
	dsa/dsa_vrf.o	dsa/dsa_sign.o	dsa/dsa_err.o	dsa/dsa_ossl.o	\
	dsa/dsa_depr.o							\
	\
	dso/dso_dl.o	dso/dso_dlfcn.o	dso/dso_err.o	dso/dso_lib.o	\
	dso/dso_null.o	dso/dso_openssl.o				\
	\
	err/err.o	err/err_all.o	err/err_prn.o			\
	\
	evp/bio_b64.o	evp/bio_enc.o	evp/bio_md.o	evp/bio_ok.o	\
	evp/c_all.o	evp/c_allc.o	evp/c_alld.o	evp/digest.o	\
	evp/e_aes.o	evp/e_bf.o	evp/e_cast.o	evp/e_des.o	\
	evp/e_des3.o	evp/e_idea.o	evp/e_null.o	evp/e_rc2.o	\
	evp/e_rc4.o	evp/e_rc5.o	evp/e_xcbc_d.o	evp/encode.o	\
	evp/evp_acnf.o	evp/evp_enc.o	evp/evp_err.o	evp/evp_key.o	\
	evp/evp_lib.o	evp/evp_pbe.o	evp/evp_pkey.o	evp/m_dss.o	\
	evp/m_dss1.o	evp/m_md2.o	evp/m_md4.o	evp/m_md5.o	\
	evp/m_mdc2.o	evp/m_null.o	evp/m_ripemd.o	evp/m_sha.o	\
	evp/m_sha1.o	evp/names.o	evp/p5_crpt.o	evp/p5_crpt2.o	\
	evp/p_dec.o	evp/p_enc.o	evp/p_lib.o	evp/p_open.o	\
	evp/p_seal.o	evp/p_sign.o	evp/p_verify.o	evp/e_old.o	\
	evp/m_ecdsa.o							\
	\
	engine/eng_all.o		engine/eng_list.o		\
	engine/eng_cnf.o		engine/eng_pkey.o		\
	engine/eng_ctrl.o		engine/eng_table.o		\
	engine/eng_dyn.o		engine/tb_cipher.o		\
	engine/eng_err.o		engine/tb_dh.o			\
	engine/eng_fat.o		engine/tb_digest.o		\
	engine/eng_init.o		engine/tb_dsa.o			\
	engine/eng_lib.o		engine/tb_rand.o		\
	engine/tb_rsa.o			engine/tb_store.o		\
	engine/tb_ecdh.o		engine/tb_ecdsa.o		\
	engine/eng_cryptodev.o						\
	\
	engine/hw_pk11.o		engine/hw_pk11_pub.o		\
	\
	hmac/hmac.o							\
	\
	lhash/lhash.o	lhash/lh_stats.o				\
	\
	md2/md2_dgst.o	md2/md2_one.o					\
	\
	md4/md4_dgst.o	md4/md4_one.o					\
	\
	md5/md5_dgst.o	md5/md5_one.o					\
	\
	objects/o_names.o		objects/obj_dat.o		\
	objects/obj_err.o		objects/obj_lib.o		\
	\
	ocsp/ocsp_asn.o	ocsp/ocsp_err.o	ocsp/ocsp_prn.o			\
	ocsp/ocsp_vfy.o	ocsp/ocsp_cl.o	ocsp/ocsp_ext.o	ocsp/ocsp_lib.o	\
	ocsp/ocsp_srv.o	ocsp/ocsp_ht.o					\
	\
	pem/pem_sign.o	pem/pem_seal.o	pem/pem_info.o	pem/pem_lib.o	\
	pem/pem_all.o	pem/pem_err.o	pem/pem_x509.o	pem/pem_xaux.o	\
	pem/pem_oth.o	pem/pem_pk8.o	pem/pem_pkey.o			\
	\
	pkcs12/p12_add.o		pkcs12/p12_asn.o		\
	pkcs12/p12_crpt.o		pkcs12/p12_crt.o		\
	pkcs12/p12_init.o		pkcs12/p12_key.o		\
	pkcs12/p12_mutl.o		pkcs12/p12_utl.o		\
	pkcs12/pk12err.o		pkcs12/p12_p8d.o		\
	pkcs12/p12_attr.o		pkcs12/p12_decr.o		\
	pkcs12/p12_kiss.o		pkcs12/p12_npas.o		\
	pkcs12/p12_p8e.o						\
	\
	pkcs7/pk7_asn1.o		pkcs7/pk7_lib.o			\
	pkcs7/pkcs7err.o		pkcs7/pk7_doit.o		\
	pkcs7/pk7_smime.o		pkcs7/pk7_attr.o		\
	pkcs7/pk7_mime.o						\
	\
	pqueue/pqueue.o							\
	\
	rand/md_rand.o	rand/randfile.o	rand/rand_lib.o	rand/rand_err.o	\
	rand/rand_unix.o		rand/rand_egd.o	rand/rand_nw.o	\
	\
	rc2/rc2_cbc.o	rc2/rc2_ecb.o	rc2/rc2_skey.o	rc2/rc2cfb64.o	\
	rc2/rc2ofb64.o							\
	\
	rc4/rc4_enc.o	rc4/rc4_skey.o					\
	\
	ripemd/rmd_dgst.o		ripemd/rmd_one.o		\
	\
	rsa/rsa_eay.o	rsa/rsa_gen.o	rsa/rsa_lib.o	rsa/rsa_sign.o	\
	rsa/rsa_saos.o	rsa/rsa_err.o	rsa/rsa_pk1.o	rsa/rsa_ssl.o	\
	rsa/rsa_none.o	rsa/rsa_oaep.o	rsa/rsa_chk.o	rsa/rsa_null.o	\
	rsa/rsa_asn1.o	rsa/rsa_depr.o	rsa/rsa_pss.o	rsa/rsa_x931.o	\
	\
	sha/sha_dgst.o	sha/sha1dgst.o	sha/sha_one.o	sha/sha1_one.o	\
	sha/sha256.o	sha/sha512.o					\
	\
	stack/stack.o							\
	\
	store/str_err.o	store/str_lib.o	store/str_mem.o			\
	store/str_meth.o						\
	\
	txt_db/txt_db.o							\
	\
	ui/ui_err.o	ui/ui_compat.o	ui/ui_lib.o	ui/ui_openssl.o	\
	ui/ui_util.o							\
	\
	x509/x509_def.o	x509/x509_d2.o	x509/x509_r2x.o x509/x509_cmp.o	\
	x509/x509_obj.o	x509/x509_req.o x509/x509spki.o	x509/x509_vfy.o	\
	x509/x509_set.o x509/x509cset.o	x509/x509rset.o	x509/x509_err.o	\
	x509/x509name.o	x509/x509_v3.o	x509/x509_ext.o x509/x509_att.o	\
	x509/x509type.o	x509/x509_lu.o	x509/x_all.o	x509/x509_txt.o	\
	x509/x509_trs.o x509/by_file.o	x509/by_dir.o	x509/x509_vpm.o	\
	\
	x509v3/v3_ia5.o	x509v3/v3_lib.o	x509v3/v3_prn.o x509v3/v3_utl.o	\
	x509v3/v3_pku.o	x509v3/v3_int.o	x509v3/v3_enum.o		\
	x509v3/v3err.o	x509v3/v3_alt.o x509v3/v3_genn.o		\
	x509v3/v3_pci.o			x509v3/v3_pcia.o		\
	x509v3/v3_purp.o		x509v3/v3_info.o		\
	x509v3/v3_ocsp.o		x509v3/v3_bitst.o		\
	x509v3/v3_conf.o		x509v3/v3_extku.o		\
	x509v3/v3_cpols.o		x509v3/v3_crld.o		\
	x509v3/v3_akey.o		x509v3/v3_akeya.o		\
	x509v3/v3_skey.o		x509v3/v3_sxnet.o		\
	x509v3/v3_ncons.o		x509v3/v3_bcons.o		\
	x509v3/v3_pcons.o		x509v3/v3_pmaps.o		\
	\
	x509v3/pcy_cache.o		x509v3/pcy_tree.o		\
	x509v3/pcy_data.o		x509v3/pcy_lib.o		\
	x509v3/pcy_map.o		x509v3/pcy_node.o		\
	\
	$(MD5_OBJ_ASM)							\
	$(BN_ASM)

# MD5_OBJ_ASM and BN_ASM may be overriden by <arch>/Makefile.
MD5_OBJ_ASM =
BN_ASM = 	bn/bn_asm.o

include ../../Makefile.com

CFLAGS +=	-K PIC
CFLAGS64 +=	-K PIC
LDLIBS +=	-lc -lsocket -lnsl

MAPFILES =

LIBS =		$(DYNLIB) $(LINTLIB)
SRCDIR =	$(OPENSSL_SRC)/crypto

$(LINTLIB) := 	SRCS = $(SRCDIR)/$(LINTSRC)

# We do not want to give the CFLAGS and build date information
# so we define the magic NO_WINDOWS_BRAINDEATH to suppress this
pics/cversion.o :=	CPPFLAGS += -DNO_WINDOWS_BRAINDEATH
lint :=			CPPFLAGS += -DNO_WINDOWS_BRAINDEATH

.KEEP_STATE:

all:		subdirs $(LIBS)

lint:		lintcheck

lintcheck := SRCS = $(SRCDIR)/engine/hw_pk11.c $(SRCDIR)/engine/hw_pk11_pub.c

subdirs:	FRC
	@mkdir -p \
		pics/aes \
		pics/asn1  \
		pics/bf \
		pics/bio \
		pics/bn \
		pics/bn/asm \
		pics/buffer \
		pics/cast \
		pics/comp \
		pics/conf \
		pics/des \
		pics/dh \
		pics/dsa \
		pics/dso \
		pics/ec \
		pics/engine \
		pics/err \
		pics/evp \
		pics/hmac \
		pics/lhash \
		pics/md2 \
		pics/md4 \
		pics/md5 \
		pics/md5/asm \
		pics/mdc2 \
		pics/objects \
		pics/ocsp \
		pics/pem \
		pics/pkcs12 \
		pics/pkcs7 \
		pics/pqueue \
		pics/store \
		pics/rand \
		pics/rc2 \
		pics/rc4 \
		pics/ripemd \
		pics/rsa \
		pics/sha \
		pics/stack \
		pics/txt_db \
		pics/ui \
		pics/x509 \
		pics/x509v3

FRC:

pics/%.o: $(SRCDIR)/%.S
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
