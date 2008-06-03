/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The kernel SSL module ioctls.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/ksynch.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/task.h>
#include <sys/mkdev.h>
#include <sys/model.h>
#include <sys/sysmacros.h>
#include <sys/policy.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>

#include "ksslimpl.h"
#include "kssl.h"
#include "ksslproto.h"

kssl_entry_t **kssl_entry_tab;
int kssl_entry_tab_size;
int kssl_entry_tab_nentries;
kmutex_t kssl_tab_mutex;

static void
certificate_free(Certificate_t *cert)
{
	kmem_free(cert->msg, cert->len);
	kmem_free(cert, sizeof (struct Certificate));
}

static void
privateKey_free(crypto_key_t *privkey)
{
	int i;
	size_t attrs_size;
	crypto_object_attribute_t *attrs;

	attrs = privkey->ck_attrs;
	attrs_size = privkey->ck_count * sizeof (crypto_object_attribute_t);
	for (i = 0; i < privkey->ck_count; i++) {
		bzero(attrs[i].oa_value, attrs[i].oa_value_len);
		kmem_free(attrs[i].oa_value, attrs[i].oa_value_len);
	}
	kmem_free(attrs, attrs_size);
	kmem_free(privkey, sizeof (crypto_key_t));
}

static void
sess_free(kssl_session_info_t *s)
{
	if (s->is_valid_handle) {
		(void) crypto_session_logout(s->prov, s->sid, NULL);
		(void) crypto_session_close(s->prov, s->sid, NULL);
		crypto_release_provider(s->prov);
		s->is_valid_handle = B_FALSE;
	}

	if (s->evnt_handle != NULL) {
		crypto_unnotify_events(s->evnt_handle);
		s->evnt_handle = NULL;
	}

	bzero(s->tokpin, s->pinlen);
	kmem_free(s, sizeof (kssl_session_info_t) + s->pinlen);
}

/*
 * Frees the space for the entry and the keys and certs
 * it carries.
 */
void
kssl_free_entry(kssl_entry_t *kssl_entry)
{
	int i;
	Certificate_t *cert;
	crypto_key_t *privkey;
	kssl_session_info_t *s;

	if (kssl_entry->ke_no_freeall) {
		kmem_free(kssl_entry, sizeof (kssl_entry_t));
		return;
	}

	if ((cert = kssl_entry->ke_server_certificate) != NULL) {
		certificate_free(cert);
	}

	if ((privkey = kssl_entry->ke_private_key) != NULL) {
		privateKey_free(privkey);
	}

	for (i = 0; i < kssl_entry->sid_cache_nentries; i++)
		mutex_destroy(&(kssl_entry->sid_cache[i].se_lock));

	kmem_free(kssl_entry->sid_cache,
	    kssl_entry->sid_cache_nentries * sizeof (kssl_sid_ent_t));

	ASSERT(kssl_entry->ke_proxy_head == NULL);
	ASSERT(kssl_entry->ke_fallback_head == NULL);

	if ((s = kssl_entry->ke_sessinfo) != NULL) {
		ASSERT(kssl_entry->ke_is_nxkey);
		sess_free(s);
	}

	kmem_free(kssl_entry, sizeof (kssl_entry_t));
}

/*
 * Returns the index of the entry in kssl_entry_tab[] that matches
 * the address and port.  Returns -1 if no match is found.
 */
static int
kssl_find_entry(ipaddr_t laddr, in_port_t port, int type,
    boolean_t wild_card_match)
{
	int i;
	kssl_entry_t *ep;

	ASSERT(MUTEX_HELD(&kssl_tab_mutex));

	for (i = 0; i < kssl_entry_tab_size; i++) {
		ep = kssl_entry_tab[i];
		if (ep == NULL)
			continue;

		if (!((type == IS_SSL_PORT && ep->ke_ssl_port == port) ||
		    (type == IS_PROXY_PORT && ep->ke_proxy_port == port)))
			continue;

		if ((ep->ke_laddr == laddr) || (wild_card_match &&
		    ((laddr == INADDR_ANY) || (ep->ke_laddr == INADDR_ANY))))
			break;
	}

	if (i == kssl_entry_tab_size)
		return (-1);

	return (i);
}

static void
copy_int_to_bytearray(int x, uchar_t *buf)
{
	buf[0] = (x >> 16) & 0xff;
	buf[1] = (x >> 8) & 0xff;
	buf[2] = (x) & 0xff;
}

static int
extract_certificate(kssl_params_t *kssl_params, Certificate_t **certpp)
{
	int i, len;
	uint64_t in_size;
	uchar_t *end_pos;
	uint32_t ncert;
	uint32_t *cert_sizes;
	Certificate_t *cert;
	char *begin = (char *)kssl_params;
	uchar_t *cert_buf;
	int cert_buf_len;
	uchar_t *cert_from, *cert_to;

	ASSERT(kssl_params);

	in_size = kssl_params->kssl_params_size;
	end_pos = (uchar_t *)kssl_params + in_size;

	/*
	 * Get the certs array. First the array of sizes, then the actual
	 * certs.
	 */
	ncert = kssl_params->kssl_certs.sc_count;

	if (ncert == 0) {
		/* no certs in here! why did ya call? */
		return (EINVAL);
	}
	if (in_size < (sizeof (kssl_params_t) + ncert * sizeof (uint32_t))) {
		return (EINVAL);
	}

	/* Trusting that the system call preserved the 4-byte alignment */
	cert_sizes = (uint32_t *)(begin +
	    kssl_params->kssl_certs.sc_sizes_offset);

	/* should this be an ASSERT()? */
	if (!IS_P2ALIGNED(cert_sizes, sizeof (uint32_t))) {
		return (EINVAL);
	}

	len = 0;
	for (i = 0; i < ncert; i++) {
		if (cert_sizes[i] < 1) {
			return (EINVAL);
		}
		len += cert_sizes[i] + 3;
	}

	len += 3;	/* length of certificate message without msg header */

	cert_buf_len = len + 4 + 4;	/* add space for msg headers */

	cert_buf = kmem_alloc(cert_buf_len, KM_SLEEP);

	cert_buf[0] = (uchar_t)certificate;
	copy_int_to_bytearray(len, & cert_buf[1]);
	copy_int_to_bytearray(len - 3, & cert_buf[4]);

	cert_from = (uchar_t *)(begin +
	    kssl_params->kssl_certs.sc_certs_offset);
	cert_to = &cert_buf[7];

	for (i = 0; i < ncert; i++) {
		copy_int_to_bytearray(cert_sizes[i], cert_to);
		cert_to += 3;

		if (cert_from + cert_sizes[i] > end_pos) {
			kmem_free(cert_buf, cert_buf_len);
			return (EINVAL);
		}

		bcopy(cert_from, cert_to, cert_sizes[i]);
		cert_from += cert_sizes[i];
		cert_to += cert_sizes[i];
	}

	len += 4;
	cert_buf[len] = (uchar_t)server_hello_done;
	copy_int_to_bytearray(0, & cert_buf[len + 1]);

	cert = kmem_alloc(sizeof (Certificate_t), KM_SLEEP);
	cert->msg = cert_buf;
	cert->len = cert_buf_len;

	*certpp = cert;

	return (0);
}

static int
extract_private_key(kssl_params_t *kssl_params, crypto_key_t **privkey)
{
	char *begin = (char *)kssl_params;
	char *end_pos;
	int i, j, rv;
	size_t attrs_size;
	crypto_object_attribute_t *newattrs = NULL;
	char *mp_attrs;
	kssl_object_attribute_t att;
	char *attval;
	uint32_t attlen;
	crypto_key_t *kssl_privkey;

	end_pos = (char *)kssl_params + kssl_params->kssl_params_size;

	kssl_privkey = kmem_alloc(sizeof (crypto_key_t), KM_SLEEP);

	kssl_privkey->ck_format = kssl_params->kssl_privkey.ks_format;
	kssl_privkey->ck_count = kssl_params->kssl_privkey.ks_count;

	switch (kssl_privkey->ck_format) {
		case CRYPTO_KEY_ATTR_LIST:
			break;
		case CRYPTO_KEY_RAW:
		case CRYPTO_KEY_REFERENCE:
		default:
			rv = EINVAL;
			goto err1;
	}

	/* allocate the attributes */
	attrs_size = kssl_privkey->ck_count *
	    sizeof (crypto_object_attribute_t);

	mp_attrs = begin + kssl_params->kssl_privkey.ks_attrs_offset;
	if (mp_attrs + attrs_size > end_pos) {
		rv = EINVAL;
		goto err1;
	}

	newattrs = kmem_alloc(attrs_size, KM_SLEEP);

	/* Now the individual attributes */
	for (i = 0; i < kssl_privkey->ck_count; i++) {
		bcopy(mp_attrs, &att, sizeof (kssl_object_attribute_t));

		mp_attrs += sizeof (kssl_object_attribute_t);

		attval = begin + att.ka_value_offset;
		attlen = att.ka_value_len;

		if (attval + attlen > end_pos) {
			rv = EINVAL;
			goto err2;
		}

		newattrs[i].oa_type = att.ka_type;
		newattrs[i].oa_value_len = attlen;
		newattrs[i].oa_value = kmem_alloc(attlen, KM_SLEEP);

		bcopy(attval, newattrs[i].oa_value, attlen);
	}

	kssl_privkey->ck_attrs = newattrs;

	*privkey = kssl_privkey;

	return (0);

err2:
	for (j = 0; j < i; j++) {
		bzero(newattrs[j].oa_value, newattrs[j].oa_value_len);
		kmem_free(newattrs[j].oa_value, newattrs[j].oa_value_len);
	}
	kmem_free(newattrs, attrs_size);
err1:
	kmem_free(kssl_privkey, sizeof (crypto_key_t));
	return (rv);
}

static int
create_sessinfo(kssl_params_t *kssl_params, kssl_entry_t *kssl_entry)
{
	int rv;
	char *p;
	kssl_session_info_t *s;
	kssl_tokinfo_t *t;

	t =  &kssl_params->kssl_token;
	/* Do a sanity check */
	if (t->pinlen > MAX_PIN_LENGTH) {
		return (EINVAL);
	}

	s = kmem_zalloc(sizeof (kssl_session_info_t) + t->pinlen, KM_SLEEP);
	s->pinlen = t->pinlen;
	bcopy(t->toklabel, s->toklabel, CRYPTO_EXT_SIZE_LABEL);
	p = (char *)kssl_params + t->tokpin_offset;
	bcopy(p, s->tokpin, s->pinlen);
	ASSERT(kssl_entry->ke_sessinfo == NULL);
	kssl_entry->ke_sessinfo = s;

	/* Get the handle to the non extractable key */
	rv = kssl_get_obj_handle(kssl_entry);
	kssl_params->kssl_token.ck_rv = rv;
	if (rv != CRYPTO_SUCCESS) {
		sess_free(s);
		kssl_entry->ke_sessinfo = NULL;
		return (EINVAL);
	}

	kssl_entry->ke_sessinfo->is_valid_handle = B_TRUE;
	kssl_entry->ke_sessinfo->do_reauth = B_FALSE;
	kssl_entry->ke_sessinfo->evnt_handle =
	    crypto_notify_events(kssl_prov_evnt,
	    CRYPTO_EVENT_PROVIDER_REGISTERED |
	    CRYPTO_EVENT_PROVIDER_UNREGISTERED);

	return (0);
}

static kssl_entry_t *
create_kssl_entry(kssl_params_t *kssl_params, Certificate_t *cert,
    crypto_key_t *privkey)
{
	int i;
	uint16_t s;
	kssl_entry_t *kssl_entry, *ep;
	uint_t cnt, mech_count;
	crypto_mech_name_t *mechs;
	boolean_t got_rsa, got_md5, got_sha1, got_rc4, got_des, got_3des;
	boolean_t got_aes;

	kssl_entry = kmem_zalloc(sizeof (kssl_entry_t), KM_SLEEP);

	kssl_entry->ke_laddr = kssl_params->kssl_addr.sin_addr.s_addr;
	kssl_entry->ke_ssl_port = kssl_params->kssl_addr.sin_port;
	kssl_entry->ke_proxy_port = kssl_params->kssl_proxy_port;
	if (kssl_params->kssl_session_cache_timeout == 0)
		kssl_entry->sid_cache_timeout = DEFAULT_SID_TIMEOUT;
	else
		kssl_entry->sid_cache_timeout =
		    kssl_params->kssl_session_cache_timeout;
	if (kssl_params->kssl_session_cache_size == 0)
		kssl_entry->sid_cache_nentries = DEFAULT_SID_CACHE_NENTRIES;
	else
		kssl_entry->sid_cache_nentries =
		    kssl_params->kssl_session_cache_size;
	kssl_entry->ke_private_key = privkey;
	kssl_entry->ke_server_certificate = cert;

	kssl_entry->ke_is_nxkey = kssl_params->kssl_is_nxkey;
	if (kssl_entry->ke_is_nxkey) {
		if (create_sessinfo(kssl_params, kssl_entry) != 0) {
			kmem_free(kssl_entry, sizeof (kssl_entry_t));
			return (NULL);
		}
	}

	mechs = crypto_get_mech_list(&mech_count, KM_SLEEP);
	if (mechs != NULL) {
		got_rsa = got_md5 = got_sha1 = got_rc4 =
		    got_des = got_3des = got_aes = B_FALSE;
		for (i = 0; i < mech_count; i++) {
			if (strncmp(SUN_CKM_RSA_X_509, mechs[i],
			    CRYPTO_MAX_MECH_NAME) == 0)
				got_rsa = B_TRUE;
			else if (strncmp(SUN_CKM_MD5_HMAC, mechs[i],
			    CRYPTO_MAX_MECH_NAME) == 0)
				got_md5 = B_TRUE;
			else if (strncmp(SUN_CKM_SHA1_HMAC, mechs[i],
			    CRYPTO_MAX_MECH_NAME) == 0)
				got_sha1 = B_TRUE;
			else if (strncmp(SUN_CKM_RC4, mechs[i],
			    CRYPTO_MAX_MECH_NAME) == 0)
				got_rc4 = B_TRUE;
			else if (strncmp(SUN_CKM_DES_CBC, mechs[i],
			    CRYPTO_MAX_MECH_NAME) == 0)
				got_des = B_TRUE;
			else if (strncmp(SUN_CKM_DES3_CBC, mechs[i],
			    CRYPTO_MAX_MECH_NAME) == 0)
				got_3des = B_TRUE;
			else if (strncmp(SUN_CKM_AES_CBC, mechs[i],
			    CRYPTO_MAX_MECH_NAME) == 0)
				got_aes = B_TRUE;
		}

		cnt = 0;
		ep = kssl_entry;
		for (i = 0; i < CIPHER_SUITE_COUNT - 1; i++) {
			switch (s = kssl_params->kssl_suites[i]) {
			case SSL_RSA_WITH_RC4_128_MD5:
				if (got_rsa && got_rc4 && got_md5)
					ep->kssl_cipherSuites[cnt++] = s;
				break;
			case SSL_RSA_WITH_RC4_128_SHA:
				if (got_rsa && got_rc4 && got_sha1)
					ep->kssl_cipherSuites[cnt++] = s;
				break;
			case SSL_RSA_WITH_DES_CBC_SHA:
				if (got_rsa && got_des && got_sha1)
					ep->kssl_cipherSuites[cnt++] = s;
				break;
			case SSL_RSA_WITH_3DES_EDE_CBC_SHA:
				if (got_rsa && got_3des && got_sha1)
					ep->kssl_cipherSuites[cnt++] = s;
				break;
			case TLS_RSA_WITH_AES_128_CBC_SHA:
				if (got_rsa && got_aes && got_sha1)
					ep->kssl_cipherSuites[cnt++] = s;
				break;
			case TLS_RSA_WITH_AES_256_CBC_SHA:
				if (got_rsa && got_aes && got_sha1)
					ep->kssl_cipherSuites[cnt++] = s;
				break;
			case CIPHER_NOTSET:
			default:
				break;
			}
		}

		crypto_free_mech_list(mechs, mech_count);
	}

	/* Add the no encryption suite to the end */
	kssl_entry->kssl_cipherSuites[cnt++] = SSL_RSA_WITH_NULL_SHA;
	kssl_entry->kssl_cipherSuites_nentries = cnt;
	for (i = 0; i < cnt; i++)
		kssl_entry->kssl_saved_Suites[i] =
		    kssl_entry->kssl_cipherSuites[i];

	kssl_entry->sid_cache = kmem_alloc(
	    kssl_entry->sid_cache_nentries * sizeof (kssl_sid_ent_t), KM_SLEEP);

	for (i = 0; i < kssl_entry->sid_cache_nentries; i++) {
		mutex_init(&(kssl_entry->sid_cache[i].se_lock), NULL,
		    MUTEX_DEFAULT, NULL);
		kssl_entry->sid_cache[i].se_used = 0;
		kssl_entry->sid_cache[i].se_sid.cached = B_FALSE;
	}

	KSSL_ENTRY_REFHOLD(kssl_entry);

	return (kssl_entry);
}

int
kssl_add_entry(kssl_params_t *kssl_params)
{
	int rv, index, i;
	Certificate_t *cert;
	crypto_key_t *privkey;
	kssl_entry_t *kssl_entry;
	ipaddr_t laddr;

	if ((rv = extract_certificate(kssl_params, &cert)) != 0) {
		return (rv);
	}

	if ((rv = extract_private_key(kssl_params, &privkey)) != 0) {
		certificate_free(cert);
		return (rv);
	}

	kssl_entry = create_kssl_entry(kssl_params, cert, privkey);
	if (kssl_entry == NULL) {
		certificate_free(cert);
		privateKey_free(privkey);
		return (EINVAL);
	}

	/* Revisit here for IPv6 support */
	laddr = kssl_params->kssl_addr.sin_addr.s_addr;

retry:
	mutex_enter(&kssl_tab_mutex);
	/* Allocate the array first time here */
	if (kssl_entry_tab == NULL) {
		size_t allocsize;
		kssl_entry_t **tmp_tab;
		int tmp_size;

		tmp_size = KSSL_TAB_INITSIZE;
		allocsize = tmp_size * sizeof (kssl_entry_t *);
		mutex_exit(&kssl_tab_mutex);
		tmp_tab = kmem_zalloc(allocsize, KM_SLEEP);
		mutex_enter(&kssl_tab_mutex);
		if (kssl_entry_tab != NULL) {
			mutex_exit(&kssl_tab_mutex);
			kmem_free(tmp_tab, allocsize);
			goto retry;
		}
		kssl_entry_tab_size = tmp_size;
		kssl_entry_tab = tmp_tab;
		index = 0;
	} else {
		/* Check if a matching entry exists already */
		index = kssl_find_entry(laddr,
		    kssl_params->kssl_addr.sin_port, IS_SSL_PORT, B_TRUE);

		if (index == -1) {
			/* Check if an entry with the same proxy port exists */
			if (kssl_find_entry(laddr, kssl_params->kssl_proxy_port,
			    IS_PROXY_PORT, B_TRUE) != -1) {
				mutex_exit(&kssl_tab_mutex);
				kssl_free_entry(kssl_entry);
				return (EADDRINUSE);
			}

			/* No matching entry, find an empty spot */
			for (i = 0; i < kssl_entry_tab_size; i++) {
				if (kssl_entry_tab[i] == NULL)
					break;
			}
			/* Table full. Gotta grow it */
			if (i == kssl_entry_tab_size) {
				kssl_entry_t **new_tab, **old_tab;
				size_t allocsize;
				size_t oldtabsize = kssl_entry_tab_size *
				    sizeof (kssl_entry_t *);
				int tmp_size, old_size;

				tmp_size = old_size = kssl_entry_tab_size;
				tmp_size += KSSL_TAB_INITSIZE;
				allocsize = tmp_size * sizeof (kssl_entry_t *);
				mutex_exit(&kssl_tab_mutex);
				new_tab = kmem_zalloc(allocsize, KM_SLEEP);
				mutex_enter(&kssl_tab_mutex);
				if (kssl_entry_tab_size > old_size) {
					mutex_exit(&kssl_tab_mutex);
					kmem_free(new_tab, allocsize);
					goto retry;
				}

				kssl_entry_tab_size = tmp_size;
				bcopy(kssl_entry_tab, new_tab, oldtabsize);

				old_tab = kssl_entry_tab;
				kssl_entry_tab = new_tab;

				kmem_free(old_tab, oldtabsize);
			}
			index = i;
		} else {
			/*
			 * We do not want an entry with a specific address and
			 * an entry with IN_ADDR_ANY to coexist. We could
			 * replace the existing entry. But, most likely this
			 * is misconfiguration. Better bail out with an error.
			 */
			if ((laddr == INADDR_ANY &&
			    (kssl_entry_tab[index]->ke_laddr != INADDR_ANY)) ||
			    (laddr != INADDR_ANY &&
			    (kssl_entry_tab[index]->ke_laddr == INADDR_ANY))) {
				mutex_exit(&kssl_tab_mutex);
				kssl_free_entry(kssl_entry);
				return (EEXIST);
			}

			/* Replace the existing entry */
			KSSL_ENTRY_REFRELE(kssl_entry_tab[index]);
			kssl_entry_tab[index] = NULL;
			kssl_entry_tab_nentries--;
		}
	}

	kssl_entry_tab[index] = kssl_entry;
	kssl_entry_tab_nentries++;
	mutex_exit(&kssl_tab_mutex);

	return (0);
}

int
kssl_delete_entry(struct sockaddr_in *kssl_addr)
{
	ipaddr_t laddr;
	int index;

	/* Revisit here for IPv6 support */
	laddr = kssl_addr->sin_addr.s_addr;

	mutex_enter(&kssl_tab_mutex);
	index = kssl_find_entry(laddr, kssl_addr->sin_port,
	    IS_SSL_PORT, B_FALSE);

	if (index == -1) {
		mutex_exit(&kssl_tab_mutex);
		return (ENOENT);
	}

	KSSL_ENTRY_REFRELE(kssl_entry_tab[index]);
	kssl_entry_tab[index] = NULL;
	kssl_entry_tab_nentries--;

	mutex_exit(&kssl_tab_mutex);

	return (0);
}

/*
 * We care about only one private key object.
 * So, set the max count to only 1.
 */
#define	MAX_OBJECT_COUNT	1

/*
 * Open a session to the provider specified by the label and
 * authenticate to it. Find the private key object with the
 * specified  attributes and save the handle. The userland component
 * must set all the attributes in the template so as to uniquely
 * identify the object.
 *
 * Note that the handle will be invalid if we logout or close
 * the session to the provider.
 */
int
kssl_get_obj_handle(kssl_entry_t *kp)
{
	int rv;
	unsigned int count;
	void *cookie = NULL;
	crypto_provider_t prov;
	kssl_session_info_t *s;
	crypto_session_id_t sid;
	crypto_object_attribute_t *attrs;
	crypto_object_id_t ohndl[MAX_OBJECT_COUNT];
	char label[CRYPTO_EXT_SIZE_LABEL + 1];

	ASSERT(kp->ke_is_nxkey);
	s = kp->ke_sessinfo;

	bcopy(s->toklabel, label, CRYPTO_EXT_SIZE_LABEL);
	label[CRYPTO_EXT_SIZE_LABEL] = '\0';
	prov = crypto_get_provider(label, NULL, NULL);
	if (prov == NULL)
		return (CRYPTO_UNKNOWN_PROVIDER);

	rv = crypto_session_open(prov, &sid, NULL);
	if (rv != CRYPTO_SUCCESS) {
		goto err1;
	}

	rv = crypto_session_login(prov, sid, CRYPTO_USER,
	    s->tokpin, s->pinlen, NULL);
	if (rv != CRYPTO_SUCCESS) {
		goto err2;
	}

	count = kp->ke_private_key->ck_count;
	attrs = kp->ke_private_key->ck_attrs;

	rv = crypto_object_find_init(prov, sid, attrs, count, &cookie, NULL);
	if (rv != CRYPTO_SUCCESS) {
		goto err3;
	}

	rv = crypto_object_find(prov, cookie, ohndl, &count,
	    MAX_OBJECT_COUNT, NULL);
	if (rv != CRYPTO_SUCCESS || count == 0) {
		if (count == 0)
			rv = CRYPTO_FAILED;
		goto err3;
	}

	(void) crypto_object_find_final(prov, cookie, NULL);

	s->sid = sid;
	s->prov = prov;
	s->key.ck_format = CRYPTO_KEY_REFERENCE;
	/* Keep the handle around for later use */
	s->key.ck_obj_id = ohndl[0];

	return (CRYPTO_SUCCESS);

err3:
	(void) crypto_session_logout(prov, sid, NULL);
err2:
	(void) crypto_session_close(prov, sid, NULL);
err1:
	crypto_release_provider(prov);
	return (rv);
}
