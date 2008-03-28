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
# ident	"%Z%%M%	%I%	%E% SMI"
#

# we need this for OPENSSL_SRC (src/common directory location)
include $(SRC)/lib/openssl/Makefile.openssl
# we need this for VERS (OpenSSL version)
include $(SRC)/lib/openssl/Makefile.com

SUBDIRS =		$(MACH)
$(BUILD64) SUBDIRS +=	$(MACH64)

ROOTOPENSSL =		$(ROOT)/etc/sfw/openssl
MANDIRS =		man1 man3 man5 man7
ROOTSFWMANDIRS =	$(MANDIRS:%=$(ROOTSFWMAN)/%)

POD2MAN =		/usr/perl5/bin/pod2man
OPENSSL_VERSION =	$(VERS:.%=%)
# official release date of OpenSSL 0.9.8a
DATE =			"Oct 11 2005"
EXTRACT_NAMES=		$(OPENSSL_SRC)/doc/extract-names.pl

# we need to explicitly specify these 3 manual pages since their sections
# cannot be read from their location in common/openssl/doc. All other manual
# pages follow this rule according to the directory they reside in: apps=1,
# crypto=3, ssl=3
SPECMANPAGES =		man7/des_modes.7
CONFIGMANPAGES =	man5/x509v3_config.5 man5/config.5

CRYPTOMANPAGES =	man3/ASN1_OBJECT_new.3 \
			man3/ASN1_STRING_length.3 \
			man3/ASN1_STRING_new.3 \
			man3/ASN1_STRING_print_ex.3 \
			man3/ASN1_generate_nconf.3 \
			man3/BIO_ctrl.3 \
			man3/BIO_f_base64.3 \
			man3/BIO_f_buffer.3 \
			man3/BIO_f_cipher.3 \
			man3/BIO_f_md.3 \
			man3/BIO_f_null.3 \
			man3/BIO_f_ssl.3 \
			man3/BIO_find_type.3 \
			man3/BIO_new.3 \
			man3/BIO_push.3 \
			man3/BIO_read.3 \
			man3/BIO_s_accept.3 \
			man3/BIO_s_bio.3 \
			man3/BIO_s_connect.3 \
			man3/BIO_s_fd.3 \
			man3/BIO_s_file.3 \
			man3/BIO_s_mem.3 \
			man3/BIO_s_null.3 \
			man3/BIO_s_socket.3 \
			man3/BIO_set_callback.3 \
			man3/BIO_should_retry.3 \
			man3/BN_BLINDING_new.3 \
			man3/BN_CTX_new.3 \
			man3/BN_CTX_start.3 \
			man3/BN_add.3 \
			man3/BN_add_word.3 \
			man3/BN_bn2bin.3 \
			man3/BN_cmp.3 \
			man3/BN_copy.3 \
			man3/BN_generate_prime.3 \
			man3/BN_mod_inverse.3 \
			man3/BN_mod_mul_montgomery.3 \
			man3/BN_mod_mul_reciprocal.3 \
			man3/BN_new.3 \
			man3/BN_num_bytes.3 \
			man3/BN_rand.3 \
			man3/BN_set_bit.3 \
			man3/BN_swap.3 \
			man3/BN_zero.3 \
			man3/CONF_modules_free.3 \
			man3/CONF_modules_load_file.3 \
			man3/CRYPTO_set_ex_data.3 \
			man3/DH_generate_key.3 \
			man3/DH_generate_parameters.3 \
			man3/DH_get_ex_new_index.3 \
			man3/DH_new.3 \
			man3/DH_set_method.3 \
			man3/DH_size.3 \
			man3/DSA_SIG_new.3 \
			man3/DSA_do_sign.3 \
			man3/DSA_dup_DH.3 \
			man3/DSA_generate_key.3 \
			man3/DSA_generate_parameters.3 \
			man3/DSA_get_ex_new_index.3 \
			man3/DSA_new.3 \
			man3/DSA_set_method.3 \
			man3/DSA_sign.3 \
			man3/DSA_size.3 \
			man3/ERR_GET_LIB.3 \
			man3/ERR_clear_error.3 \
			man3/ERR_error_string.3 \
			man3/ERR_get_error.3 \
			man3/ERR_load_crypto_strings.3 \
			man3/ERR_load_strings.3 \
			man3/ERR_print_errors.3 \
			man3/ERR_put_error.3 \
			man3/ERR_remove_state.3 \
			man3/ERR_set_mark.3 \
			man3/EVP_BytesToKey.3 \
			man3/EVP_DigestInit.3 \
			man3/EVP_EncryptInit.3 \
			man3/EVP_OpenInit.3 \
			man3/EVP_PKEY_new.3 \
			man3/EVP_PKEY_set1_RSA.3 \
			man3/EVP_SealInit.3 \
			man3/EVP_SignInit.3 \
			man3/EVP_VerifyInit.3 \
			man3/OBJ_nid2obj.3 \
			man3/OPENSSL_Applink.3 \
			man3/OPENSSL_VERSION_NUMBER.3 \
			man3/OPENSSL_config.3 \
			man3/OPENSSL_ia32cap.3 \
			man3/OPENSSL_load_builtin_modules.3 \
			man3/OpenSSL_add_all_algorithms.3 \
			man3/PKCS12_create.3 \
			man3/PKCS12_parse.3 \
			man3/PKCS7_decrypt.3 \
			man3/PKCS7_encrypt.3 \
			man3/PKCS7_sign.3 \
			man3/PKCS7_verify.3 \
			man3/RAND_add.3 \
			man3/RAND_bytes.3 \
			man3/RAND_cleanup.3 \
			man3/RAND_egd.3 \
			man3/RAND_load_file.3 \
			man3/RAND_set_rand_method.3 \
			man3/RSA_blinding_on.3 \
			man3/RSA_check_key.3 \
			man3/RSA_generate_key.3 \
			man3/RSA_get_ex_new_index.3 \
			man3/RSA_new.3 \
			man3/RSA_padding_add_PKCS1_type_1.3 \
			man3/RSA_print.3 \
			man3/RSA_private_encrypt.3 \
			man3/RSA_public_encrypt.3 \
			man3/RSA_set_method.3 \
			man3/RSA_sign.3 \
			man3/RSA_sign_ASN1_OCTET_STRING.3 \
			man3/RSA_size.3 \
			man3/SMIME_read_PKCS7.3 \
			man3/SMIME_write_PKCS7.3 \
			man3/X509_NAME_ENTRY_get_object.3 \
			man3/X509_NAME_add_entry_by_txt.3 \
			man3/X509_NAME_get_index_by_NID.3 \
			man3/X509_NAME_print_ex.3 \
			man3/X509_new.3 \
			man3/bio.3 \
			man3/blowfish.3 \
			man3/bn.3 \
			man3/bn_internal.3 \
			man3/buffer.3 \
			man3/crypto.3 \
			man3/d2i_ASN1_OBJECT.3 \
			man3/d2i_DHparams.3 \
			man3/d2i_DSAPublicKey.3 \
			man3/d2i_PKCS8PrivateKey.3 \
			man3/d2i_RSAPublicKey.3 \
			man3/d2i_X509.3 \
			man3/d2i_X509_ALGOR.3 \
			man3/d2i_X509_CRL.3 \
			man3/d2i_X509_NAME.3 \
			man3/d2i_X509_REQ.3 \
			man3/d2i_X509_SIG.3 \
			man3/des.3 \
			man3/dh.3 \
			man3/dsa.3 \
			man3/ecdsa.3 \
			man3/engine.3 \
			man3/err.3 \
			man3/evp.3 \
			man3/hmac.3 \
			man3/lh_stats.3 \
			man3/lhash.3 \
			man3/md5.3 \
			man3/mdc2.3 \
			man3/pem.3 \
			man3/rand.3 \
			man3/rc4.3 \
			man3/ripemd.3 \
			man3/rsa.3 \
			man3/sha.3 \
			man3/threads.3 \
			man3/ui.3 \
			man3/ui_compat.3 \
			man3/x509.3

APPSMANPAGES =		man1/CA.pl.1 \
			man1/asn1parse.1 \
			man1/ca.1 \
			man1/ciphers.1 \
			man1/crl.1 \
			man1/crl2pkcs7.1 \
			man1/dgst.1 \
			man1/dhparam.1 \
			man1/dsa.1 \
			man1/dsaparam.1 \
			man1/ec.1 \
			man1/ecparam.1 \
			man1/enc.1 \
			man1/errstr.1 \
			man1/gendsa.1 \
			man1/genrsa.1 \
			man1/nseq.1 \
			man1/ocsp.1 \
			man1/openssl.1 \
			man1/passwd.1 \
			man1/pkcs12.1 \
			man1/pkcs7.1 \
			man1/pkcs8.1 \
			man1/rand.1 \
			man1/req.1 \
			man1/rsa.1 \
			man1/rsautl.1 \
			man1/s_client.1 \
			man1/s_server.1 \
			man1/s_time.1 \
			man1/sess_id.1 \
			man1/smime.1 \
			man1/speed.1 \
			man1/spkac.1 \
			man1/verify.1 \
			man1/version.1 \
			man1/x509.1

SSLMANPAGES =		man3/SSL_CIPHER_get_name.3 \
			man3/SSL_COMP_add_compression_method.3 \
			man3/SSL_CTX_add_extra_chain_cert.3 \
			man3/SSL_CTX_add_session.3 \
			man3/SSL_CTX_ctrl.3 \
			man3/SSL_CTX_flush_sessions.3 \
			man3/SSL_CTX_free.3 \
			man3/SSL_CTX_get_ex_new_index.3 \
			man3/SSL_CTX_get_verify_mode.3 \
			man3/SSL_CTX_load_verify_locations.3 \
			man3/SSL_CTX_new.3 \
			man3/SSL_CTX_sess_number.3 \
			man3/SSL_CTX_sess_set_cache_size.3 \
			man3/SSL_CTX_sess_set_get_cb.3 \
			man3/SSL_CTX_sessions.3 \
			man3/SSL_CTX_set_cert_store.3 \
			man3/SSL_CTX_set_cert_verify_callback.3 \
			man3/SSL_CTX_set_cipher_list.3 \
			man3/SSL_CTX_set_client_CA_list.3 \
			man3/SSL_CTX_set_client_cert_cb.3 \
			man3/SSL_CTX_set_default_passwd_cb.3 \
			man3/SSL_CTX_set_generate_session_id.3 \
			man3/SSL_CTX_set_info_callback.3 \
			man3/SSL_CTX_set_max_cert_list.3 \
			man3/SSL_CTX_set_mode.3 \
			man3/SSL_CTX_set_msg_callback.3 \
			man3/SSL_CTX_set_options.3 \
			man3/SSL_CTX_set_quiet_shutdown.3 \
			man3/SSL_CTX_set_session_cache_mode.3 \
			man3/SSL_CTX_set_session_id_context.3 \
			man3/SSL_CTX_set_ssl_version.3 \
			man3/SSL_CTX_set_timeout.3 \
			man3/SSL_CTX_set_tmp_dh_callback.3 \
			man3/SSL_CTX_set_tmp_rsa_callback.3 \
			man3/SSL_CTX_set_verify.3 \
			man3/SSL_CTX_use_certificate.3 \
			man3/SSL_SESSION_free.3 \
			man3/SSL_SESSION_get_ex_new_index.3 \
			man3/SSL_SESSION_get_time.3 \
			man3/SSL_accept.3 \
			man3/SSL_alert_type_string.3 \
			man3/SSL_clear.3 \
			man3/SSL_connect.3 \
			man3/SSL_do_handshake.3 \
			man3/SSL_free.3 \
			man3/SSL_get_SSL_CTX.3 \
			man3/SSL_get_ciphers.3 \
			man3/SSL_get_client_CA_list.3 \
			man3/SSL_get_current_cipher.3 \
			man3/SSL_get_default_timeout.3 \
			man3/SSL_get_error.3 \
			man3/SSL_get_ex_data_X509_STORE_CTX_idx.3 \
			man3/SSL_get_ex_new_index.3 \
			man3/SSL_get_fd.3 \
			man3/SSL_get_peer_cert_chain.3 \
			man3/SSL_get_peer_certificate.3 \
			man3/SSL_get_rbio.3 \
			man3/SSL_get_session.3 \
			man3/SSL_get_verify_result.3 \
			man3/SSL_get_version.3 \
			man3/SSL_library_init.3 \
			man3/SSL_load_client_CA_file.3 \
			man3/SSL_new.3 \
			man3/SSL_pending.3 \
			man3/SSL_read.3 \
			man3/SSL_rstate_string.3 \
			man3/SSL_session_reused.3 \
			man3/SSL_set_bio.3 \
			man3/SSL_set_connect_state.3 \
			man3/SSL_set_fd.3 \
			man3/SSL_set_session.3 \
			man3/SSL_set_shutdown.3 \
			man3/SSL_set_verify_result.3 \
			man3/SSL_shutdown.3 \
			man3/SSL_state_string.3 \
			man3/SSL_want.3 \
			man3/SSL_write.3 \
			man3/d2i_SSL_SESSION.3 \
			man3/ssl.3

ROOTSFWSPECMANPAGES =	$(SPECMANPAGES:%=$(ROOTSFWMAN)/%)
ROOTSFWCONFIGMANPAGES =	$(CONFIGMANPAGES:%=$(ROOTSFWMAN)/%)
ROOTSFWAPPSMANPAGES =	$(APPSMANPAGES:%=$(ROOTSFWMAN)/%)
ROOTSFWCRYPTOMANPAGES = $(CRYPTOMANPAGES:%=$(ROOTSFWMAN)/%)
ROOTSFWSSLMANPAGES =	$(SSLMANPAGES:%=$(ROOTSFWMAN)/%)

ROOTSFWMANPAGES =	$(ROOTSFWSPECMANPAGES) \
			$(ROOTSFWCONFIGMANPAGES) \
			$(ROOTSFWAPPSMANPAGES) \
			$(ROOTSFWCRYPTOMANPAGES) \
			$(ROOTSFWSSLMANPAGES)

CONFIGSUNPAGES =	$(CONFIGMANPAGES:man5%.5=sunman%.5)
SPECSUNPAGES =		$(SPECMANPAGES:man7%.7=sunman%.7)
APPSSUNPAGES =		$(APPSMANPAGES:man1%.1=sunman%.1)
CRYPTOSUNPAGES =	$(CRYPTOMANPAGES:man3%.3=sunman%.3)
SSLSUNPAGES =		$(SSLMANPAGES:man3%.3=sunman%.3)

# we don't want to explicitly define what symlinks to existing man pages to
# create. This can be easily extracted from manual pages in POD format.
# However, for each manual page we need information about its section and
# actual location in common/openssl/doc. Note that we don't use ':' as a
# separator for the section/dir/pod_page triplet because ':' generally denotes
# "noise" in the nightly build log.
CONFIGPODPAGES =	$(CONFIGMANPAGES:man5/%.5=5,apps,%)
SPECPODPAGES =		$(SPECMANPAGES:man7/%.7=7,crypto,%)
APPSPODPAGES =		$(APPSMANPAGES:man1/%.1=1,apps,%)
CRYPTOPODPAGES =	$(CRYPTOMANPAGES:man3/%.3=3,crypto,%)
SSLPODPAGES =		$(SSLMANPAGES:man3/%.3=3,ssl,%)

ALLPODPAGES =		$(CONFIGPODPAGES) \
			$(SPECPODPAGES) \
			$(APPSPODPAGES) \
			$(CRYPTOPODPAGES) \
			$(SSLPODPAGES)

include ../Makefile.cmd

all 	:=		TARGET = all
clean 	:=		TARGET = clean
clobber	:=		TARGET = clobber
install :=		TARGET = install

.PARALLEL: $(SUBDIRS)

all clobber: $(SUBDIRS)

clean clobber: $(SUBDIRS)
	$(RM) -r sunman

install: $(SUBDIRS) $(ROOTOPENSSL)/openssl.cnf man

# (1) convert man pages in POD format into NROFF format and store them in
# ./sunman directory
# (2) install them into their respective manX directories in the proto area
# (3) create symlinks according to NAME section of each manual page
man:			mansymlinks
mansymlinks:		$(ROOTSFWMANPAGES)
$(ROOTSFWMANPAGES):	sunman

# We do NOT attempt to place 3rd Party code under the ON gate lint rules.
lint:

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

$(ROOTOPENSSL)/openssl.cnf := FILEMODE = 644

$(ROOTOPENSSL)/%: % $(ROOTOPENSSL)
	$(INS.file)

$(ROOTOPENSSL):
	$(INS.dir)
	$(INS.dir) $(ROOTOPENSSL)/certs
	$(INS.dir) $(ROOTOPENSSL)/private

$(ROOTSFWMANPAGES) := FILEMODE = 0444
$(ROOTSFWMANPAGES): $(ROOTSFWMANDIRS)

$(ROOTSFWMANDIRS): $(ROOTSFWMAN) $(ROOTSFW)/man
	$(INS.dir)

$(ROOTSFWMAN): $(ROOTSFW)/share
	$(INS.dir)

$(ROOTSFW)/man: $(ROOTSFW)
	$(RM) $@
	$(SYMLINK) share/man $@

$(ROOTSFW)/share: $(ROOTSFW)
	$(INS.dir)

$(ROOTSFW):
	$(INS.dir)

$(ROOTSFWMAN)/man1/% $(ROOTSFWMAN)/man3/% $(ROOTSFWMAN)/man5/% $(ROOTSFWMAN)/man7/%: sunman/%
	$(INS.file)

$(SPECSUNPAGES):
	@$(POD2MAN) --date=$(DATE) --center=OpenSSL --section=7 \
	    --quotes=none --release "OpenSSL-$(OPENSSL_VERSION)" \
	    --name=`basename $@ .7` $(OPENSSL_SRC)/doc/crypto/`basename $@ .7`.pod $@

$(CONFIGSUNPAGES):
	@$(POD2MAN) --date=$(DATE) --center=OpenSSL --section=5 \
	    --quotes=none --release "OpenSSL-$(OPENSSL_VERSION)" \
	    --name=`basename $@ .5` $(OPENSSL_SRC)/doc/apps/`basename $@ .5`.pod $@

$(APPSSUNPAGES):
	@$(POD2MAN) --date=$(DATE) --center=OpenSSL --section=1 \
	    --quotes=none --release "OpenSSL-$(OPENSSL_VERSION)" \
	    --name=`basename $@ .1` $(OPENSSL_SRC)/doc/apps/`basename $@ .1`.pod $@

$(SSLSUNPAGES):
	@$(POD2MAN) --date=$(DATE) --center=OpenSSL --section=3 \
	    --quotes=none --release "OpenSSL-$(OPENSSL_VERSION)" \
	    --name=`basename $@ .3` $(OPENSSL_SRC)/doc/ssl/`basename $@ .3`.pod $@

$(CRYPTOSUNPAGES):
	@$(POD2MAN) --date=$(DATE) --center=OpenSSL --section=3 \
	    --quotes=none --release "OpenSSL-$(OPENSSL_VERSION)" \
	    --name=`basename $@ .3` $(OPENSSL_SRC)/doc/crypto/`basename $@ .3`.pod $@

mansymlinks:
	@for i in $(ALLPODPAGES); do \
		section=`echo $$i | cut -f1 -d,`; \
		dir=`echo $$i | cut -f2 -d,`; \
		base=`echo $$i | cut -f3 -d,`; \
		$(EXTRACT_NAMES) <$(OPENSSL_SRC)/doc/$$dir/$$base.pod | \
		    grep -v "^$$base$$" | \
		    while read j; do \
			    $(RM) -f $(ROOTSFWMAN)/man$$section/$$j.$$section; \
			    $(SYMLINK) $$base.$$section $(ROOTSFWMAN)/man$$section/$$j.$$section ; \
		    done; \
	done

sunman:
	mkdir sunman
