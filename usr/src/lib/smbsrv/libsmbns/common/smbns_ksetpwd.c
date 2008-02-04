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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <kerberosv5/krb5.h>
#include <kerberosv5/com_err.h>
#include <smbns_krb.h>

static int smb_krb5_open_wrfile(krb5_context ctx, char *fname,
    krb5_keytab *kt);
static int smb_krb5_ktadd(krb5_context ctx, krb5_keytab kt,
    const krb5_principal princ, krb5_enctype enctype, krb5_kvno kvno,
    const char *pw);
static krb5_error_code smb_krb5_ktremove(krb5_context ctx, krb5_keytab kt,
    const krb5_principal princ);


/*
 * smb_krb5_ctx_init
 *
 * Initialize the kerberos context.
 * Return 0 on success. Otherwise, return -1.
 */
int
smb_krb5_ctx_init(krb5_context *ctx)
{
	if (krb5_init_context(ctx) != 0)
		return (-1);

	return (0);
}

/*
 * smb_krb5_get_principal
 *
 * Setup the krb5_principal given the host principal in string format.
 * Return 0 on success. Otherwise, return -1.
 */
int
smb_krb5_get_principal(krb5_context ctx, char *princ_str, krb5_principal *princ)
{
	if (krb5_parse_name(ctx, princ_str, princ) != 0)
		return (-1);

	return (0);
}

/*
 * smb_krb5_ctx_fini
 *
 * Free the kerberos context.
 */
void
smb_krb5_ctx_fini(krb5_context ctx)
{
	krb5_free_context(ctx);
}

/*
 * smb_ksetpw
 *
 * Set the workstation trust account password.
 * Returns 0 on success.  Otherwise, returns non-zero value.
 */
int
smb_krb5_setpwd(krb5_context ctx, krb5_principal princ, char *passwd)
{
	krb5_error_code code;
	krb5_ccache cc = NULL;
	int result_code;
	krb5_data result_code_string, result_string;

	(void) memset(&result_code_string, 0, sizeof (result_code_string));
	(void) memset(&result_string, 0, sizeof (result_string));

	if ((code = krb5_cc_default(ctx, &cc)) != 0) {
		syslog(LOG_ERR, "smb_krb5_setpwd: failed to find a ccache\n");
		return (-1);
	}

	code = krb5_set_password_using_ccache(ctx, cc, passwd, princ,
	    &result_code, &result_code_string, &result_string);

	krb5_cc_close(ctx, cc);

	if (code != 0)
		(void) syslog(LOG_ERR,
		    "smb_krb5_setpwd: Result: %.*s (%d) %.*s\n",
		    result_code == 0 ?
		    strlen("success") : result_code_string.length,
		    result_code == 0 ? "success" : result_code_string.data,
		    result_code, result_string.length, result_string.data);

	free(result_code_string.data);
	free(result_string.data);
	return (code);
}

/*
 * smb_krb5_open_wrfile
 *
 * Open the keytab file for writing.
 * The keytab should be closed by calling krb5_kt_close().
 */
static int
smb_krb5_open_wrfile(krb5_context ctx, char *fname, krb5_keytab *kt)
{
	char *ktname;
	int len;

	*kt = NULL;
	len = snprintf(NULL, 0, "WRFILE:%s", fname) + 1;
	if ((ktname = malloc(len)) == NULL) {
		syslog(LOG_ERR, "smb_krb5_write_keytab: resource shortage");
		return (-1);
	}

	(void) snprintf(ktname, len, "WRFILE:%s", fname);

	if (krb5_kt_resolve(ctx, ktname, kt) != 0) {
		syslog(LOG_ERR, "smb_krb5_write_keytab: failed to open/create "
		    "keytab %s\n", fname);
		free(ktname);
		return (-1);
	}

	free(ktname);
	return (0);
}

/*
 * smb_krb5_remove_keytab_entries
 *
 * Remove the keys from the keytab for the specified principal.
 */
int
smb_krb5_remove_keytab_entries(krb5_context ctx, krb5_principal princ,
    char *fname)
{
	krb5_keytab kt = NULL;
	int rc = 0;
	krb5_error_code code;

	if (smb_krb5_open_wrfile(ctx, fname, &kt) != 0)
		return (-1);

	if ((code = smb_krb5_ktremove(ctx, kt, princ)) != 0) {
		syslog(LOG_ERR, "smb_krb5_remove_keytab_entries: %s",
		    error_message(code));
		rc = -1;
	}

	krb5_kt_close(ctx, kt);
	return (rc);
}

/*
 * smb_krb5_update_keytab_entries
 *
 * Update the keys for the specified principal in the keytab.
 * Returns 0 on success.  Otherwise, returns -1.
 */
int
smb_krb5_update_keytab_entries(krb5_context ctx, krb5_principal princ,
    char *fname, krb5_kvno kvno, char *passwd, krb5_enctype *enctypes,
    int enctype_count)
{
	krb5_keytab kt = NULL;
	int rc = 0, i;
	krb5_error_code code;

	if (smb_krb5_open_wrfile(ctx, fname, &kt) != 0)
		return (-1);

	if ((code = smb_krb5_ktremove(ctx, kt, princ)) != 0) {
		syslog(LOG_ERR, "smb_krb5_update_keytab_entries: %s",
		    error_message(code));
		krb5_kt_close(ctx, kt);
		return (-1);
	}

	for (i = 0; i < enctype_count; i++) {
		if (smb_krb5_ktadd(ctx, kt, princ, enctypes[i], kvno, passwd)
		    != 0) {
			rc = -1;
			break;
		}

	}

	krb5_kt_close(ctx, kt);
	return (rc);
}

/*
 * smb_krb5_ktremove
 *
 * Removes the old entries for the specified principal from the keytab.
 *
 * Returns 0 upon success. Otherwise, returns KRB5 error code.
 */
static krb5_error_code
smb_krb5_ktremove(krb5_context ctx, krb5_keytab kt, const krb5_principal princ)
{
	krb5_keytab_entry entry;
	krb5_kt_cursor cursor;
	int code;

	code = krb5_kt_get_entry(ctx, kt, princ, 0, 0, &entry);
	if (code != 0) {
		if (code == ENOENT || code == KRB5_KT_NOTFOUND)
			return (0);

		return (code);
	}

	krb5_kt_free_entry(ctx, &entry);

	if ((code = krb5_kt_start_seq_get(ctx, kt, &cursor)) != 0)
		return (code);

	while ((code = krb5_kt_next_entry(ctx, kt, &entry, &cursor)) == 0) {
		if (krb5_principal_compare(ctx, princ, entry.principal)) {

			code = krb5_kt_end_seq_get(ctx, kt, &cursor);
			if (code != 0) {
				krb5_kt_free_entry(ctx, &entry);
				return (code);
			}

			code = krb5_kt_remove_entry(ctx, kt, &entry);
			if (code != 0) {
				krb5_kt_free_entry(ctx, &entry);
				return (code);
			}

			code = krb5_kt_start_seq_get(ctx, kt, &cursor);
			if (code != 0) {
				krb5_kt_free_entry(ctx, &entry);
				return (code);
			}

		}
		krb5_kt_free_entry(ctx, &entry);
	}

	if (code && code != KRB5_KT_END) {
		(void) krb5_kt_end_seq_get(ctx, kt, &cursor);
		return (code);
	}

	if ((code = krb5_kt_end_seq_get(ctx, kt, &cursor)))
		return (code);

	return (0);
}

/*
 * smb_krb5_ktadd
 *
 * Add a Keberos key to the keytab file.
 * Returns 0 on success. Otherwise, returns -1.
 */
static int
smb_krb5_ktadd(krb5_context ctx, krb5_keytab kt, const krb5_principal princ,
	krb5_enctype enctype, krb5_kvno kvno, const char *pw)
{
	krb5_keytab_entry *entry;
	krb5_data password, salt;
	krb5_keyblock key;
	krb5_error_code code;
	char buf[100];
	int rc = 0;

	if ((code = krb5_enctype_to_string(enctype, buf, sizeof (buf)))) {
		syslog(LOG_ERR, "smb_krb5_ktadd[%d]: unknown enctype",
		    enctype);
		return (-1);
	}

	if ((entry = (krb5_keytab_entry *) malloc(sizeof (*entry))) == NULL) {
		syslog(LOG_ERR, "smb_krb5_ktadd[%d]: resource shortage",
		    enctype);
		return (-1);
	}

	(void) memset((char *)entry, 0, sizeof (*entry));

	password.length = strlen(pw);
	password.data = (char *)pw;

	if ((code = krb5_principal2salt(ctx, princ, &salt)) != 0) {
		syslog(LOG_ERR, "smb_krb5_ktadd[%d]: failed to compute salt",
		    enctype);
		free(entry);
		return (-1);
	}

	code = krb5_c_string_to_key(ctx, enctype, &password, &salt, &key);
	krb5_xfree(salt.data);
	if (code != 0) {
		syslog(LOG_ERR, "smb_krb5_ktadd[%d]: failed to generate key",
		    enctype);
		free(entry);
		return (-1);
	}

	(void) memcpy(&entry->key, &key, sizeof (krb5_keyblock));
	entry->vno = kvno;
	entry->principal = princ;

	if ((code = krb5_kt_add_entry(ctx, kt, entry)) != 0) {
		syslog(LOG_ERR, "smb_krb5_ktadd[%d] failed to add entry to "
		    "keytab (%d)", enctype, code);
		rc = -1;
	}

	free(entry);
	if (key.length)
		krb5_free_keyblock_contents(ctx, &key);
	return (rc);
}
