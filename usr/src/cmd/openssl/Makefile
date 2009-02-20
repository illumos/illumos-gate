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

# we need this for OPENSSL_VERSION, OPENSSL_DATE
include $(SRC)/lib/openssl/Makefile.openssl

SUBDIRS =		$(MACH)
$(BUILD64) SUBDIRS +=	$(MACH64)

ROOTOPENSSL =		$(ROOT)/etc/openssl
MS1 =			1openssl
MS3 =			3openssl
MS5 =			5openssl
MS7 =			7openssl
MANDIRS =		man$(MS1) man$(MS3) man$(MS5) man$(MS7)
ROOTMANDIRS =		$(MANDIRS:%=$(ROOTMAN)/%)

POD2MAN =		/usr/perl5/bin/pod2man
OPENSSL_SRC =		../../common/openssl
EXTRACT_NAMES=		$(OPENSSL_SRC)/doc/extract-names.pl

# we need to explicitly specify these 3 manual pages since their sections
# cannot be read from their location in common/openssl/doc. All other manual
# pages follow this rule according to the directory they reside in: apps=1,
# crypto=3, ssl=3
SPECMANPAGES =		man$(MS7)/des_modes.$(MS7)
CONFIGMANPAGES =	man$(MS5)/x509v3_config.$(MS5) man$(MS5)/config.$(MS5)

CRYPTOMANPAGES =	man$(MS3)/ASN1_OBJECT_new.$(MS3) \
			man$(MS3)/ASN1_STRING_length.$(MS3) \
			man$(MS3)/ASN1_STRING_new.$(MS3) \
			man$(MS3)/ASN1_STRING_print_ex.$(MS3) \
			man$(MS3)/ASN1_generate_nconf.$(MS3) \
			man$(MS3)/BIO_ctrl.$(MS3) \
			man$(MS3)/BIO_f_base64.$(MS3) \
			man$(MS3)/BIO_f_buffer.$(MS3) \
			man$(MS3)/BIO_f_cipher.$(MS3) \
			man$(MS3)/BIO_f_md.$(MS3) \
			man$(MS3)/BIO_f_null.$(MS3) \
			man$(MS3)/BIO_f_ssl.$(MS3) \
			man$(MS3)/BIO_find_type.$(MS3) \
			man$(MS3)/BIO_new.$(MS3) \
			man$(MS3)/BIO_push.$(MS3) \
			man$(MS3)/BIO_read.$(MS3) \
			man$(MS3)/BIO_s_accept.$(MS3) \
			man$(MS3)/BIO_s_bio.$(MS3) \
			man$(MS3)/BIO_s_connect.$(MS3) \
			man$(MS3)/BIO_s_fd.$(MS3) \
			man$(MS3)/BIO_s_file.$(MS3) \
			man$(MS3)/BIO_s_mem.$(MS3) \
			man$(MS3)/BIO_s_null.$(MS3) \
			man$(MS3)/BIO_s_socket.$(MS3) \
			man$(MS3)/BIO_set_callback.$(MS3) \
			man$(MS3)/BIO_should_retry.$(MS3) \
			man$(MS3)/BN_BLINDING_new.$(MS3) \
			man$(MS3)/BN_CTX_new.$(MS3) \
			man$(MS3)/BN_CTX_start.$(MS3) \
			man$(MS3)/BN_add.$(MS3) \
			man$(MS3)/BN_add_word.$(MS3) \
			man$(MS3)/BN_bn2bin.$(MS3) \
			man$(MS3)/BN_cmp.$(MS3) \
			man$(MS3)/BN_copy.$(MS3) \
			man$(MS3)/BN_generate_prime.$(MS3) \
			man$(MS3)/BN_mod_inverse.$(MS3) \
			man$(MS3)/BN_mod_mul_montgomery.$(MS3) \
			man$(MS3)/BN_mod_mul_reciprocal.$(MS3) \
			man$(MS3)/BN_new.$(MS3) \
			man$(MS3)/BN_num_bytes.$(MS3) \
			man$(MS3)/BN_rand.$(MS3) \
			man$(MS3)/BN_set_bit.$(MS3) \
			man$(MS3)/BN_swap.$(MS3) \
			man$(MS3)/BN_zero.$(MS3) \
			man$(MS3)/CONF_modules_free.$(MS3) \
			man$(MS3)/CONF_modules_load_file.$(MS3) \
			man$(MS3)/CRYPTO_set_ex_data.$(MS3) \
			man$(MS3)/DH_generate_key.$(MS3) \
			man$(MS3)/DH_generate_parameters.$(MS3) \
			man$(MS3)/DH_get_ex_new_index.$(MS3) \
			man$(MS3)/DH_new.$(MS3) \
			man$(MS3)/DH_set_method.$(MS3) \
			man$(MS3)/DH_size.$(MS3) \
			man$(MS3)/DSA_SIG_new.$(MS3) \
			man$(MS3)/DSA_do_sign.$(MS3) \
			man$(MS3)/DSA_dup_DH.$(MS3) \
			man$(MS3)/DSA_generate_key.$(MS3) \
			man$(MS3)/DSA_generate_parameters.$(MS3) \
			man$(MS3)/DSA_get_ex_new_index.$(MS3) \
			man$(MS3)/DSA_new.$(MS3) \
			man$(MS3)/DSA_set_method.$(MS3) \
			man$(MS3)/DSA_sign.$(MS3) \
			man$(MS3)/DSA_size.$(MS3) \
			man$(MS3)/ERR_GET_LIB.$(MS3) \
			man$(MS3)/ERR_clear_error.$(MS3) \
			man$(MS3)/ERR_error_string.$(MS3) \
			man$(MS3)/ERR_get_error.$(MS3) \
			man$(MS3)/ERR_load_crypto_strings.$(MS3) \
			man$(MS3)/ERR_load_strings.$(MS3) \
			man$(MS3)/ERR_print_errors.$(MS3) \
			man$(MS3)/ERR_put_error.$(MS3) \
			man$(MS3)/ERR_remove_state.$(MS3) \
			man$(MS3)/ERR_set_mark.$(MS3) \
			man$(MS3)/EVP_BytesToKey.$(MS3) \
			man$(MS3)/EVP_DigestInit.$(MS3) \
			man$(MS3)/EVP_EncryptInit.$(MS3) \
			man$(MS3)/EVP_OpenInit.$(MS3) \
			man$(MS3)/EVP_PKEY_new.$(MS3) \
			man$(MS3)/EVP_PKEY_set1_RSA.$(MS3) \
			man$(MS3)/EVP_SealInit.$(MS3) \
			man$(MS3)/EVP_SignInit.$(MS3) \
			man$(MS3)/EVP_VerifyInit.$(MS3) \
			man$(MS3)/OBJ_nid2obj.$(MS3) \
			man$(MS3)/OPENSSL_Applink.$(MS3) \
			man$(MS3)/OPENSSL_VERSION_NUMBER.$(MS3) \
			man$(MS3)/OPENSSL_config.$(MS3) \
			man$(MS3)/OPENSSL_ia32cap.$(MS3) \
			man$(MS3)/OPENSSL_load_builtin_modules.$(MS3) \
			man$(MS3)/OpenSSL_add_all_algorithms.$(MS3) \
			man$(MS3)/PKCS12_create.$(MS3) \
			man$(MS3)/PKCS12_parse.$(MS3) \
			man$(MS3)/PKCS7_decrypt.$(MS3) \
			man$(MS3)/PKCS7_encrypt.$(MS3) \
			man$(MS3)/PKCS7_sign.$(MS3) \
			man$(MS3)/PKCS7_verify.$(MS3) \
			man$(MS3)/RAND_add.$(MS3) \
			man$(MS3)/RAND_bytes.$(MS3) \
			man$(MS3)/RAND_cleanup.$(MS3) \
			man$(MS3)/RAND_egd.$(MS3) \
			man$(MS3)/RAND_load_file.$(MS3) \
			man$(MS3)/RAND_set_rand_method.$(MS3) \
			man$(MS3)/RSA_blinding_on.$(MS3) \
			man$(MS3)/RSA_check_key.$(MS3) \
			man$(MS3)/RSA_generate_key.$(MS3) \
			man$(MS3)/RSA_get_ex_new_index.$(MS3) \
			man$(MS3)/RSA_new.$(MS3) \
			man$(MS3)/RSA_padding_add_PKCS1_type_1.$(MS3) \
			man$(MS3)/RSA_print.$(MS3) \
			man$(MS3)/RSA_private_encrypt.$(MS3) \
			man$(MS3)/RSA_public_encrypt.$(MS3) \
			man$(MS3)/RSA_set_method.$(MS3) \
			man$(MS3)/RSA_sign.$(MS3) \
			man$(MS3)/RSA_sign_ASN1_OCTET_STRING.$(MS3) \
			man$(MS3)/RSA_size.$(MS3) \
			man$(MS3)/SMIME_read_PKCS7.$(MS3) \
			man$(MS3)/SMIME_write_PKCS7.$(MS3) \
			man$(MS3)/X509_NAME_ENTRY_get_object.$(MS3) \
			man$(MS3)/X509_NAME_add_entry_by_txt.$(MS3) \
			man$(MS3)/X509_NAME_get_index_by_NID.$(MS3) \
			man$(MS3)/X509_NAME_print_ex.$(MS3) \
			man$(MS3)/X509_new.$(MS3) \
			man$(MS3)/bio.$(MS3) \
			man$(MS3)/blowfish.$(MS3) \
			man$(MS3)/bn.$(MS3) \
			man$(MS3)/bn_internal.$(MS3) \
			man$(MS3)/buffer.$(MS3) \
			man$(MS3)/crypto.$(MS3) \
			man$(MS3)/d2i_ASN1_OBJECT.$(MS3) \
			man$(MS3)/d2i_DHparams.$(MS3) \
			man$(MS3)/d2i_DSAPublicKey.$(MS3) \
			man$(MS3)/d2i_PKCS8PrivateKey.$(MS3) \
			man$(MS3)/d2i_RSAPublicKey.$(MS3) \
			man$(MS3)/d2i_X509.$(MS3) \
			man$(MS3)/d2i_X509_ALGOR.$(MS3) \
			man$(MS3)/d2i_X509_CRL.$(MS3) \
			man$(MS3)/d2i_X509_NAME.$(MS3) \
			man$(MS3)/d2i_X509_REQ.$(MS3) \
			man$(MS3)/d2i_X509_SIG.$(MS3) \
			man$(MS3)/des.$(MS3) \
			man$(MS3)/dh.$(MS3) \
			man$(MS3)/dsa.$(MS3) \
			man$(MS3)/ecdsa.$(MS3) \
			man$(MS3)/engine.$(MS3) \
			man$(MS3)/err.$(MS3) \
			man$(MS3)/evp.$(MS3) \
			man$(MS3)/hmac.$(MS3) \
			man$(MS3)/lh_stats.$(MS3) \
			man$(MS3)/lhash.$(MS3) \
			man$(MS3)/md5.$(MS3) \
			man$(MS3)/mdc2.$(MS3) \
			man$(MS3)/pem.$(MS3) \
			man$(MS3)/rand.$(MS3) \
			man$(MS3)/rc4.$(MS3) \
			man$(MS3)/ripemd.$(MS3) \
			man$(MS3)/rsa.$(MS3) \
			man$(MS3)/sha.$(MS3) \
			man$(MS3)/threads.$(MS3) \
			man$(MS3)/ui.$(MS3) \
			man$(MS3)/ui_compat.$(MS3) \
			man$(MS3)/x509.$(MS3)

APPSMANPAGES =		man$(MS1)/CA.pl.$(MS1) \
			man$(MS1)/asn1parse.$(MS1) \
			man$(MS1)/ca.$(MS1) \
			man$(MS1)/ciphers.$(MS1) \
			man$(MS1)/crl.$(MS1) \
			man$(MS1)/crl2pkcs7.$(MS1) \
			man$(MS1)/dgst.$(MS1) \
			man$(MS1)/dhparam.$(MS1) \
			man$(MS1)/dsa.$(MS1) \
			man$(MS1)/dsaparam.$(MS1) \
			man$(MS1)/ec.$(MS1) \
			man$(MS1)/ecparam.$(MS1) \
			man$(MS1)/enc.$(MS1) \
			man$(MS1)/errstr.$(MS1) \
			man$(MS1)/gendsa.$(MS1) \
			man$(MS1)/genrsa.$(MS1) \
			man$(MS1)/nseq.$(MS1) \
			man$(MS1)/ocsp.$(MS1) \
			man$(MS1)/openssl.$(MS1) \
			man$(MS1)/passwd.$(MS1) \
			man$(MS1)/pkcs12.$(MS1) \
			man$(MS1)/pkcs7.$(MS1) \
			man$(MS1)/pkcs8.$(MS1) \
			man$(MS1)/rand.$(MS1) \
			man$(MS1)/req.$(MS1) \
			man$(MS1)/rsa.$(MS1) \
			man$(MS1)/rsautl.$(MS1) \
			man$(MS1)/s_client.$(MS1) \
			man$(MS1)/s_server.$(MS1) \
			man$(MS1)/s_time.$(MS1) \
			man$(MS1)/sess_id.$(MS1) \
			man$(MS1)/smime.$(MS1) \
			man$(MS1)/speed.$(MS1) \
			man$(MS1)/spkac.$(MS1) \
			man$(MS1)/verify.$(MS1) \
			man$(MS1)/version.$(MS1) \
			man$(MS1)/x509.$(MS1)

SSLMANPAGES =		man$(MS3)/SSL_CIPHER_get_name.$(MS3) \
			man$(MS3)/SSL_COMP_add_compression_method.$(MS3) \
			man$(MS3)/SSL_CTX_add_extra_chain_cert.$(MS3) \
			man$(MS3)/SSL_CTX_add_session.$(MS3) \
			man$(MS3)/SSL_CTX_ctrl.$(MS3) \
			man$(MS3)/SSL_CTX_flush_sessions.$(MS3) \
			man$(MS3)/SSL_CTX_free.$(MS3) \
			man$(MS3)/SSL_CTX_get_ex_new_index.$(MS3) \
			man$(MS3)/SSL_CTX_get_verify_mode.$(MS3) \
			man$(MS3)/SSL_CTX_load_verify_locations.$(MS3) \
			man$(MS3)/SSL_CTX_new.$(MS3) \
			man$(MS3)/SSL_CTX_sess_number.$(MS3) \
			man$(MS3)/SSL_CTX_sess_set_cache_size.$(MS3) \
			man$(MS3)/SSL_CTX_sess_set_get_cb.$(MS3) \
			man$(MS3)/SSL_CTX_sessions.$(MS3) \
			man$(MS3)/SSL_CTX_set_cert_store.$(MS3) \
			man$(MS3)/SSL_CTX_set_cert_verify_callback.$(MS3) \
			man$(MS3)/SSL_CTX_set_cipher_list.$(MS3) \
			man$(MS3)/SSL_CTX_set_client_CA_list.$(MS3) \
			man$(MS3)/SSL_CTX_set_client_cert_cb.$(MS3) \
			man$(MS3)/SSL_CTX_set_default_passwd_cb.$(MS3) \
			man$(MS3)/SSL_CTX_set_generate_session_id.$(MS3) \
			man$(MS3)/SSL_CTX_set_info_callback.$(MS3) \
			man$(MS3)/SSL_CTX_set_max_cert_list.$(MS3) \
			man$(MS3)/SSL_CTX_set_mode.$(MS3) \
			man$(MS3)/SSL_CTX_set_msg_callback.$(MS3) \
			man$(MS3)/SSL_CTX_set_options.$(MS3) \
			man$(MS3)/SSL_CTX_set_quiet_shutdown.$(MS3) \
			man$(MS3)/SSL_CTX_set_session_cache_mode.$(MS3) \
			man$(MS3)/SSL_CTX_set_session_id_context.$(MS3) \
			man$(MS3)/SSL_CTX_set_ssl_version.$(MS3) \
			man$(MS3)/SSL_CTX_set_timeout.$(MS3) \
			man$(MS3)/SSL_CTX_set_tmp_dh_callback.$(MS3) \
			man$(MS3)/SSL_CTX_set_tmp_rsa_callback.$(MS3) \
			man$(MS3)/SSL_CTX_set_verify.$(MS3) \
			man$(MS3)/SSL_CTX_use_certificate.$(MS3) \
			man$(MS3)/SSL_SESSION_free.$(MS3) \
			man$(MS3)/SSL_SESSION_get_ex_new_index.$(MS3) \
			man$(MS3)/SSL_SESSION_get_time.$(MS3) \
			man$(MS3)/SSL_accept.$(MS3) \
			man$(MS3)/SSL_alert_type_string.$(MS3) \
			man$(MS3)/SSL_clear.$(MS3) \
			man$(MS3)/SSL_connect.$(MS3) \
			man$(MS3)/SSL_do_handshake.$(MS3) \
			man$(MS3)/SSL_free.$(MS3) \
			man$(MS3)/SSL_get_SSL_CTX.$(MS3) \
			man$(MS3)/SSL_get_ciphers.$(MS3) \
			man$(MS3)/SSL_get_client_CA_list.$(MS3) \
			man$(MS3)/SSL_get_current_cipher.$(MS3) \
			man$(MS3)/SSL_get_default_timeout.$(MS3) \
			man$(MS3)/SSL_get_error.$(MS3) \
			man$(MS3)/SSL_get_ex_data_X509_STORE_CTX_idx.$(MS3) \
			man$(MS3)/SSL_get_ex_new_index.$(MS3) \
			man$(MS3)/SSL_get_fd.$(MS3) \
			man$(MS3)/SSL_get_peer_cert_chain.$(MS3) \
			man$(MS3)/SSL_get_peer_certificate.$(MS3) \
			man$(MS3)/SSL_get_rbio.$(MS3) \
			man$(MS3)/SSL_get_session.$(MS3) \
			man$(MS3)/SSL_get_verify_result.$(MS3) \
			man$(MS3)/SSL_get_version.$(MS3) \
			man$(MS3)/SSL_library_init.$(MS3) \
			man$(MS3)/SSL_load_client_CA_file.$(MS3) \
			man$(MS3)/SSL_new.$(MS3) \
			man$(MS3)/SSL_pending.$(MS3) \
			man$(MS3)/SSL_read.$(MS3) \
			man$(MS3)/SSL_rstate_string.$(MS3) \
			man$(MS3)/SSL_session_reused.$(MS3) \
			man$(MS3)/SSL_set_bio.$(MS3) \
			man$(MS3)/SSL_set_connect_state.$(MS3) \
			man$(MS3)/SSL_set_fd.$(MS3) \
			man$(MS3)/SSL_set_session.$(MS3) \
			man$(MS3)/SSL_set_shutdown.$(MS3) \
			man$(MS3)/SSL_set_verify_result.$(MS3) \
			man$(MS3)/SSL_shutdown.$(MS3) \
			man$(MS3)/SSL_state_string.$(MS3) \
			man$(MS3)/SSL_want.$(MS3) \
			man$(MS3)/SSL_write.$(MS3) \
			man$(MS3)/d2i_SSL_SESSION.$(MS3) \
			man$(MS3)/ssl.$(MS3)

ROOTSPECMANPAGES =	$(SPECMANPAGES:%=$(ROOTMAN)/%)
ROOTCONFIGMANPAGES =	$(CONFIGMANPAGES:%=$(ROOTMAN)/%)
ROOTAPPSMANPAGES =	$(APPSMANPAGES:%=$(ROOTMAN)/%)
ROOTCRYPTOMANPAGES =	$(CRYPTOMANPAGES:%=$(ROOTMAN)/%)
ROOTSSLMANPAGES =	$(SSLMANPAGES:%=$(ROOTMAN)/%)

ROOTMANPAGES =		$(ROOTSPECMANPAGES) \
			$(ROOTCONFIGMANPAGES) \
			$(ROOTAPPSMANPAGES) \
			$(ROOTCRYPTOMANPAGES) \
			$(ROOTSSLMANPAGES)

CONFIGSUNPAGES =	$(CONFIGMANPAGES:man$(MS5)%.$(MS5)=sunman%.$(MS5))
SPECSUNPAGES =		$(SPECMANPAGES:man$(MS7)%.$(MS7)=sunman%.$(MS7))
APPSSUNPAGES =		$(APPSMANPAGES:man$(MS1)%.$(MS1)=sunman%.$(MS1))
CRYPTOSUNPAGES =	$(CRYPTOMANPAGES:man$(MS3)%.$(MS3)=sunman%.$(MS3))
SSLSUNPAGES =		$(SSLMANPAGES:man$(MS3)%.$(MS3)=sunman%.$(MS3))

# we don't want to explicitly define what symlinks to existing man pages to
# create. This can be easily extracted from manual pages in POD format.
# However, for each manual page we need information about its section and
# actual location in common/openssl/doc. Note that we don't use ':' as a
# separator for the section/dir/pod_page triplet because ':' generally denotes
# "noise" in the nightly build log.
CONFIGPODPAGES =	$(CONFIGMANPAGES:man$(MS5)/%.$(MS5)=$(MS5),apps,%)
SPECPODPAGES =		$(SPECMANPAGES:man$(MS7)/%.$(MS7)=$(MS7),crypto,%)
APPSPODPAGES =		$(APPSMANPAGES:man$(MS1)/%.$(MS1)=$(MS1),apps,%)
CRYPTOPODPAGES =	$(CRYPTOMANPAGES:man$(MS3)/%.$(MS3)=$(MS3),crypto,%)
SSLPODPAGES =		$(SSLMANPAGES:man$(MS3)/%.$(MS3)=$(MS3),ssl,%)

ALLPODPAGES =		$(CONFIGPODPAGES) \
			$(SPECPODPAGES) \
			$(APPSPODPAGES) \
			$(CRYPTOPODPAGES) \
			$(SSLPODPAGES)

ROOTUSRSFWBIN =		$(ROOT)/usr/sfw/bin
SFWBINLINKS =		openssl $(BUILD64) $(MACH64)/openssl
ROOTUSRSFWBINLINKS =	$(SFWBINLINKS:%=$(ROOTUSRSFWBIN)/%)

include ../Makefile.cmd

all 	:=		TARGET = all
clean 	:=		TARGET = clean
clobber	:=		TARGET = clobber
install :=		TARGET = install

.KEEP_STATE:

.PARALLEL: $(SUBDIRS)

all clobber: $(SUBDIRS)

clean clobber: $(SUBDIRS)
	$(RM) -r sunman

install: $(SUBDIRS) $(ROOTOPENSSL)/openssl.cnf man binsymlinks

# (1) convert man pages in POD format into NROFF format and store them in
# ./sunman directory
# (2) install them into their respective manX directories in the proto area
# (3) create symlinks according to NAME section of each manual page
man:			mansymlinks
mansymlinks:		$(ROOTMANPAGES)
$(ROOTMANPAGES):	sunman

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

$(ROOTMANPAGES) := FILEMODE = 0444
$(ROOTMANPAGES): $(ROOTMANDIRS)

$(ROOTMANDIRS): $(ROOTMAN)
	$(INS.dir)

$(ROOTMAN)/man$(MS1)/% \
$(ROOTMAN)/man$(MS3)/% \
$(ROOTMAN)/man$(MS5)/% \
$(ROOTMAN)/man$(MS7)/% \
	:	sunman/%
	$(INS.file)

$(SPECSUNPAGES):
	@$(POD2MAN) --date=$(OPENSSL_DATE) --center=OpenSSL --section=$(MS7) \
	    --quotes=none --release "OpenSSL-$(OPENSSL_VERSION)" \
	    --name=`basename $@ .$(MS7)` \
	    $(OPENSSL_SRC)/doc/crypto/`basename $@ .$(MS7)`.pod $@

$(CONFIGSUNPAGES):
	@$(POD2MAN) --date=$(OPENSSL_DATE) --center=OpenSSL --section=$(MS5) \
	    --quotes=none --release "OpenSSL-$(OPENSSL_VERSION)" \
	    --name=`basename $@ .$(MS5)` \
	    $(OPENSSL_SRC)/doc/apps/`basename $@ .$(MS5)`.pod $@

$(APPSSUNPAGES):
	@$(POD2MAN) --date=$(OPENSSL_DATE) --center=OpenSSL --section=$(MS1) \
	    --quotes=none --release "OpenSSL-$(OPENSSL_VERSION)" \
	    --name=`basename $@ .$(MS1)` \
	    $(OPENSSL_SRC)/doc/apps/`basename $@ .$(MS1)`.pod $@

$(SSLSUNPAGES):
	@$(POD2MAN) --date=$(OPENSSL_DATE) --center=OpenSSL --section=$(MS3) \
	    --quotes=none --release "OpenSSL-$(OPENSSL_VERSION)" \
	    --name=`basename $@ .$(MS3)` \
	    $(OPENSSL_SRC)/doc/ssl/`basename $@ .$(MS3)`.pod $@

$(CRYPTOSUNPAGES):
	@$(POD2MAN) --date=$(OPENSSL_DATE) --center=OpenSSL --section=$(MS3) \
	    --quotes=none --release "OpenSSL-$(OPENSSL_VERSION)" \
	    --name=`basename $@ .$(MS3)` \
	    $(OPENSSL_SRC)/doc/crypto/`basename $@ .$(MS3)`.pod $@

mansymlinks:
	@for i in $(ALLPODPAGES); do \
		section=`echo $$i | cut -f1 -d,`; \
		dir=`echo $$i | cut -f2 -d,`; \
		base=`echo $$i | cut -f3 -d,`; \
		$(EXTRACT_NAMES) <$(OPENSSL_SRC)/doc/$$dir/$$base.pod | \
		    grep -v "^$$base$$" | \
		    while read j; do \
			    $(RM) -f $(ROOTMAN)/man$$section/$$j.$$section; \
			    $(SYMLINK) $$base.$$section \
				$(ROOTMAN)/man$$section/$$j.$$section; \
		    done; \
	done

sunman:
	$(MKDIR) -p sunman

binsymlinks:	$(ROOTUSRSFWBIN) .WAIT $(ROOTUSRSFWBINLINKS)

$(ROOTUSRSFWBIN):
	$(INS.dir)
	$(INS.dir) $@/$(MACH64)

$(ROOTUSRSFWBIN)/openssl:= \
		REALPATH=../../bin/openssl
$(ROOTUSRSFWBIN)/$(MACH64)/openssl:= \
		REALPATH=../../../bin/$(MACH64)/openssl

$(ROOTUSRSFWBINLINKS):
	$(RM) $@
	$(SYMLINK) $(REALPATH) $@
