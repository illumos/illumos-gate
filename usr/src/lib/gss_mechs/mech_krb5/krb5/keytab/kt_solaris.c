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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <krb5.h>
#include <errno.h>
#include <netdb.h>
#include <strings.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include "kt_solaris.h"

#define	AES128		ENCTYPE_AES128_CTS_HMAC_SHA1_96
#define	AES256		ENCTYPE_AES256_CTS_HMAC_SHA1_96
#define	DES3		ENCTYPE_DES3_CBC_SHA1
#define	AES_ENTRIES	2
#define	HOST_TRUNC	15
#define	SVC_ENTRIES	4

static krb5_error_code
kt_open(krb5_context ctx, krb5_keytab *kt)
{
	krb5_error_code code;
	char		buf[MAX_KEYTAB_NAME_LEN], ktstr[MAX_KEYTAB_NAME_LEN];

	memset(buf, 0, sizeof (buf));
	memset(ktstr, 0, sizeof (ktstr));

	if ((code = krb5_kt_default_name(ctx, buf, sizeof (buf))) != 0)
		return (code);

	/*
	 * The default is file type w/o the write.  If it's anything besides
	 * FILE or WRFILE then we bail as quickly as possible.
	 */
	if (strncmp(buf, "FILE:", strlen("FILE:")) == 0)
		(void) snprintf(ktstr, sizeof (ktstr), "WR%s", buf);
	else if (strncmp(buf, "WRFILE:", strlen("WRFILE:")) == 0)
		(void) snprintf(ktstr, sizeof (ktstr), "%s", buf);
	else
		return (EINVAL);

	return (krb5_kt_resolve(ctx, ktstr, kt));
}

static krb5_error_code
kt_add_entry(krb5_context ctx, krb5_keytab kt, const krb5_principal princ,
    const krb5_principal svc_princ, krb5_enctype enctype, krb5_kvno kvno,
    const char *pw)
{
	krb5_keytab_entry entry;
	krb5_data password, salt;
	krb5_keyblock key;
	krb5_error_code code;

	memset(&entry, 0, sizeof (entry));
	memset(&key, 0, sizeof (krb5_keyblock));

	password.length = strlen(pw);
	password.data = (char *)pw;

	if ((code = krb5_principal2salt(ctx, svc_princ, &salt)) != 0) {
		return (code);
	}

	if ((krb5_c_string_to_key(ctx, enctype, &password, &salt, &key)) != 0)
		goto cleanup;

	entry.key = key;
	entry.vno = kvno;
	entry.principal = princ;

	code = krb5_kt_add_entry(ctx, kt, &entry);

cleanup:

	krb5_xfree(salt.data);
	krb5_free_keyblock_contents(ctx, &key);

	return (code);
}

/*
 * krb5_error_code krb5_kt_add_ad_entries(krb5_context ctx, char **sprincs_str,
 * krb5_kvno kvno, uint_t flags, char *password)
 *
 * Adds keys to the keytab file for a default set of service principals in an
 * Active Directory environment.
 *
 * where ctx is the pointer passed back from krb5_init_context
 * where sprincs_str is an array of service principal names to be added
 * to the keytab file, terminated by a NULL pointer
 * where domain is the domain used to fully qualify the hostname for
 * constructing the salt in the string-to-key function.
 * where kvno is the key version number of the set of service principal
 * keys to be added
 * where flags is the set of conditions that affects the key table entries
 * current set of defined flags:
 *
 * 	encryption type
 * 	---------------
 *  	0x00000001  KRB5_KT_FLAG_AES_SUPPORT (core set + AES-256-128 keys added)
 *
 * where password is the password that will be used to derive the key for
 * the associated service principals in the keytab file
 *
 * Note: this function is used for adding service principals to the
 * local /etc/krb5/krb5.keytab (unless KRB5_KTNAME has been set to something
 * different, see krb5envvar(5)) file when the client belongs to an AD domain.
 * The keytab file is populated differently for an AD domain as the various
 * service principals share the same key material, unlike MIT based
 * implementations.
 *
 * Note: For encryption types; the union of the enc type flag and the
 * capabilities of the client is used to determine the enc type set to
 * populate the keytab file.
 *
 * Note: The keys are not created for any AES enctypes UNLESS the
 * KRB5_KT_FLAG_AES_SUPPORT flag is set and permitted_enctypes has the AES
 * enctypes enabled.
 *
 * Note: In Active Directory environments the salt is constructed by truncating
 * the host name to 15 characters and only use the host svc princ as the salt,
 * e.g. host/<str15>.<domain>@<realm>.  The realm name is determined by parsing
 * sprincs_str.  The local host name to construct is determined by calling
 * gethostname(3C).  If AD environments construct salts differently in the
 * future or this function is expanded outside of AD environments one could
 * derive the salt by sending an initial authentication exchange.
 *
 * Note: The kvno was previously determined by performing an LDAP query of the
 * computer account's msDS-KeyVersionNumber attribute.  If the schema changes
 * in the future or this function is expanded outside of AD environments then
 * one could derive the principal's kvno by requesting a service ticket.
 */
krb5_error_code
krb5_kt_add_ad_entries(krb5_context ctx, char **sprincs_str, char *domain,
    krb5_kvno kvno, uint_t flags, char *password)
{
	krb5_principal	princ = NULL, salt = NULL, f_princ = NULL;
	krb5_keytab	kt = NULL;
	krb5_enctype	*enctypes = NULL, *tenctype, penctype = 0;
	char		**tprinc, *ptr, *token, *t_host = NULL, *realm;
	char		localname[MAXHOSTNAMELEN];
	krb5_error_code	code;
	krb5_boolean	similar;
	uint_t		t_len;

	assert(ctx != NULL && sprincs_str != NULL && *sprincs_str != NULL);
	assert(password != NULL && domain != NULL);

	if ((code = krb5_parse_name(ctx, *sprincs_str, &f_princ)) != 0)
		return (code);
	if (krb5_princ_realm(ctx, f_princ)->length == 0) {
		code = EINVAL;
		goto cleanup;
	}
	realm = krb5_princ_realm(ctx, f_princ)->data;

	if (gethostname(localname, MAXHOSTNAMELEN) != 0) {
		code = errno;
		goto cleanup;
	}
	token = localname;

	/*
	 * Local host name could be fully qualified and/or in upper case, but
	 * usually and appropriately not.
	 */
	if ((ptr = strchr(token, '.')) != NULL)
		ptr = '\0';
	for (ptr = token; *ptr; ptr++)
		*ptr = tolower(*ptr);
	/*
	 * Windows servers currently truncate the host name to 15 characters
	 * and only use the host svc princ as the salt, e.g.
	 * host/str15.domain@realm
	 */
	t_len = snprintf(NULL, 0, "host/%.*s.%s@%s", HOST_TRUNC, token, domain,
	    realm) + 1;
	if ((t_host = malloc(t_len)) == NULL) {
		code = ENOMEM;
		goto cleanup;
	}
	(void) snprintf(t_host, t_len, "host/%.*s.%s@%s", HOST_TRUNC, token,
	    domain, realm);

	if ((code = krb5_parse_name(ctx, t_host, &salt)) != 0)
		goto cleanup;

	if ((code = kt_open(ctx, &kt)) != 0)
		goto cleanup;

	code = krb5_get_permitted_enctypes(ctx, &enctypes);
	if (code != 0 || *enctypes == 0)
		goto cleanup;

	for (tprinc = sprincs_str; *tprinc; tprinc++) {

		if ((code = krb5_parse_name(ctx, *tprinc, &princ)) != 0)
			goto cleanup;

		for (tenctype = enctypes; *tenctype; tenctype++) {
			if ((!(flags & KRB5_KT_FLAG_AES_SUPPORT) &&
			    (*tenctype == AES128 || *tenctype == AES256)) ||
			    (*tenctype == DES3)) {
				continue;
			}

			if (penctype) {
				code = krb5_c_enctype_compare(ctx, *tenctype,
				    penctype, &similar);
				if (code != 0)
					goto cleanup;
				else if (similar)
					continue;
			}

			code = kt_add_entry(ctx, kt, princ, salt, *tenctype,
			    kvno, password);
			if (code != 0)
				goto cleanup;

			penctype = *tenctype;
		}

		krb5_free_principal(ctx, princ);
		princ = NULL;
	}

cleanup:

	if (f_princ != NULL)
		krb5_free_principal(ctx, f_princ);
	if (salt != NULL)
		krb5_free_principal(ctx, salt);
	if (t_host != NULL)
		free(t_host);
	if (kt != NULL)
		(void) krb5_kt_close(ctx, kt);
	if (enctypes != NULL)
		krb5_free_ktypes(ctx, enctypes);
	if (princ != NULL)
		krb5_free_principal(ctx, princ);

	return (code);
}

#define	PRINCIPAL	0
#define	REALM		1

static krb5_error_code
kt_remove_by_key(krb5_context ctx, char *key, uint_t type)
{
	krb5_error_code		code;
	krb5_kt_cursor		cursor;
	krb5_keytab_entry	entry;
	krb5_keytab		kt = NULL;
	krb5_principal		svc_princ = NULL;
	krb5_principal_data	realm_data;
	boolean_t		found = FALSE;

	assert(ctx != NULL && key != NULL);

	if (type == REALM) {
		krb5_princ_realm(ctx, &realm_data)->length = strlen(key);
		krb5_princ_realm(ctx, &realm_data)->data = key;
	} else if (type == PRINCIPAL) {
		if ((code = krb5_parse_name(ctx, key, &svc_princ)) != 0)
			goto cleanup;
	} else
		return (EINVAL);

	if ((code = kt_open(ctx, &kt)) != 0)
		goto cleanup;

	if ((code = krb5_kt_start_seq_get(ctx, kt, &cursor)) != 0)
		goto cleanup;

	while ((code = krb5_kt_next_entry(ctx, kt, &entry, &cursor)) == 0) {
		if (type == PRINCIPAL && krb5_principal_compare(ctx, svc_princ,
		    entry.principal)) {
			found = TRUE;
		} else if (type == REALM && krb5_realm_compare(ctx, &realm_data,
		    entry.principal)) {
			found = TRUE;
		}

		if (found == TRUE) {
			code = krb5_kt_end_seq_get(ctx, kt, &cursor);
			if (code != 0) {
				krb5_kt_free_entry(ctx, &entry);
				goto cleanup;
			}

			code = krb5_kt_remove_entry(ctx, kt, &entry);
			if (code != 0) {
				krb5_kt_free_entry(ctx, &entry);
				goto cleanup;
			}

			code = krb5_kt_start_seq_get(ctx, kt, &cursor);
			if (code != 0) {
				krb5_kt_free_entry(ctx, &entry);
				goto cleanup;
			}

			found = FALSE;
		}

		krb5_kt_free_entry(ctx, &entry);
	}

	if (code && code != KRB5_KT_END)
		goto cleanup;

	code = krb5_kt_end_seq_get(ctx, kt, &cursor);

cleanup:

	if (svc_princ != NULL)
		krb5_free_principal(ctx, svc_princ);
	if (kt != NULL)
		(void) krb5_kt_close(ctx, kt);

	return (code);
}

/*
 * krb5_error_code krb5_kt_remove_by_realm(krb5_context ctx, char *realm)
 *
 * Removes all key entries in the keytab file that match the exact realm name
 * specified.
 *
 * where ctx is the pointer passed back from krb5_init_context
 * where realm is the realm name that is matched for any keytab entries
 * to be removed
 *
 * Note: if there are no entries matching realm then 0 (success) is returned
 */
krb5_error_code
krb5_kt_remove_by_realm(krb5_context ctx, char *realm)
{

	return (kt_remove_by_key(ctx, realm, REALM));
}

/*
 * krb5_error_code krb5_kt_remove_by_svcprinc(krb5_context ctx,
 *	char *sprinc_str)
 *
 * Removes all key entries in the keytab file that match the exact service
 * principal name specified.
 *
 * where ctx is the pointer passed back from krb5_init_context
 * where sprinc_str is the service principal name that is matched for any
 * keytab entries to be removed
 *
 * Note: if there are no entries matching sprinc_str then 0 (success) is
 * returned
 */
krb5_error_code
krb5_kt_remove_by_svcprinc(krb5_context ctx, char *sprinc_str)
{

	return (kt_remove_by_key(ctx, sprinc_str, PRINCIPAL));
}

/*
 * krb5_error_code krb5_kt_validate(krb5_context ctx, char *sprinc_str,
 * uint_t flags, boolean_t *valid)
 *
 * The validate function determines that the service principal exists and that
 * it has a valid set of encryption types for said principal.
 *
 * where ctx is the pointer passed back from krb5_init_context
 * where sprinc_str is the principal to be validated in the keytab file
 * where flags is the set of conditions that affects the key table entries
 * that the function considers valid
 * 	current set of defined flags:
 *
 *	encryption type
 *	---------------
 *	0x00000001 KRB5_KT_FLAG_AES_SUPPORT (core set + AES-256-128 keys are
 *		valid)
 *
 * where valid is a boolean that is set if the sprinc_str is correctly
 * populated in the keytab file based on the flags set else valid is unset.
 *
 * Note: The validate function assumes that only one set of keys exists for
 * a corresponding service principal, of key version number (kvno) n.  It would
 * consider more than one kvno set as invalid.  This is from the fact that AD
 * clients will attempt to refresh credential caches if KRB5KRB_AP_ERR_MODIFIED
 * is returned by the acceptor when the requested kvno is not found within the
 * keytab file.
 */
krb5_error_code
krb5_kt_ad_validate(krb5_context ctx, char *sprinc_str, uint_t flags,
    boolean_t *valid)
{
	krb5_error_code		code;
	krb5_kt_cursor		cursor;
	krb5_keytab_entry	entry;
	krb5_keytab		kt = NULL;
	krb5_principal		svc_princ = NULL;
	krb5_enctype		*enctypes, *tenctype, penctype = 0;
	boolean_t		ck_aes = FALSE;
	uint_t			aes_count = 0, kt_entries = 0;
	krb5_boolean		similar;

	assert(ctx != NULL && sprinc_str != NULL && valid != NULL);

	*valid = FALSE;
	ck_aes = flags & KRB5_KT_FLAG_AES_SUPPORT;

	if ((code = krb5_parse_name(ctx, sprinc_str, &svc_princ)) != 0)
		goto cleanup;

	if ((code = kt_open(ctx, &kt)) != 0)
		goto cleanup;

	code = krb5_get_permitted_enctypes(ctx, &enctypes);
	if (code != 0 || *enctypes == 0)
		goto cleanup;

	if ((code = krb5_kt_start_seq_get(ctx, kt, &cursor)) != 0)
		goto cleanup;

	while ((code = krb5_kt_next_entry(ctx, kt, &entry, &cursor)) == 0) {
		if (krb5_principal_compare(ctx, svc_princ, entry.principal)) {

			for (tenctype = enctypes; *tenctype; tenctype++) {
				if (penctype) {
					code = krb5_c_enctype_compare(ctx,
					    *tenctype, penctype, &similar);
					if (code != 0) {
						krb5_kt_free_entry(ctx, &entry);
						goto cleanup;
					} else if (similar)
						continue;
				}

				if ((*tenctype != DES3) &&
				    (entry.key.enctype == *tenctype)) {
					kt_entries++;
				}

				penctype = *tenctype;
			}

			if ((entry.key.enctype == AES128) ||
			    (entry.key.enctype == AES256)) {
				aes_count++;
			}
		}

		krb5_kt_free_entry(ctx, &entry);
	}

	if (code && code != KRB5_KT_END)
		goto cleanup;

	if ((code = krb5_kt_end_seq_get(ctx, kt, &cursor)))
		goto cleanup;

	if (ck_aes == TRUE) {
		if ((kt_entries != SVC_ENTRIES) || (aes_count != AES_ENTRIES))
			goto cleanup;
	} else if (kt_entries != (SVC_ENTRIES - AES_ENTRIES))
		goto cleanup;

	*valid = TRUE;

cleanup:

	if (svc_princ != NULL)
		krb5_free_principal(ctx, svc_princ);
	if (kt != NULL)
		(void) krb5_kt_close(ctx, kt);
	if (enctypes != NULL)
		krb5_free_ktypes(ctx, enctypes);

	return (code);
}
