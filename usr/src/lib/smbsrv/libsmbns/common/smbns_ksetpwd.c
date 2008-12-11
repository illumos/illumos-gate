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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/param.h>
#include <kerberosv5/krb5.h>
#include <kerberosv5/com_err.h>

#include <smbsrv/libsmb.h>
#include <smbns_krb.h>

static char *spn_prefix[] = {"host/", "nfs/", "HTTP/", "root/"};

static int smb_krb5_open_wrfile(krb5_context ctx, char *fname,
    krb5_keytab *kt);
static int smb_krb5_ktadd(krb5_context ctx, krb5_keytab kt,
    const krb5_principal princ, krb5_enctype enctype, krb5_kvno kvno,
    const char *pw);

/*
 * smb_krb5_get_spn
 *
 * Gets Service Principal Name.
 * Caller must free the memory allocated for the spn.
 */
char *
smb_krb5_get_spn(smb_krb5_spn_idx_t idx, char *fqhost)
{
	int len;
	char *princ;
	char *spn;

	if (!fqhost)
		return (NULL);

	if ((idx < 0) || (idx >= SMBKRB5_SPN_IDX_MAX))
		return (NULL);

	spn = spn_prefix[idx];
	len = strlen(spn) + strlen(fqhost) + 1;
	princ = (char *)malloc(len);

	if (!princ)
		return (NULL);

	(void) snprintf(princ, len, "%s%s", spn, fqhost);
	return (princ);
}

/*
 * smb_krb5_get_upn
 *
 * Gets User Principal Name.
 * Caller must free the memory allocated for the upn.
 */
char *
smb_krb5_get_upn(char *spn, char *domain)
{
	int len;
	char *realm;
	char *upn;

	if (!spn || !domain)
		return (NULL);

	realm = strdup(domain);
	if (!realm)
		return (NULL);

	(void) utf8_strupr(realm);

	len = strlen(spn) + 1 + strlen(realm) + 1;
	upn = (char *)malloc(len);
	if (!upn) {
		free(realm);
		return (NULL);
	}

	(void) snprintf(upn, len, "%s@%s", spn, realm);
	free(realm);

	return (upn);
}

/*
 * smb_krb5_get_host_upn
 *
 * Derives UPN by the given fully-qualified hostname.
 * Caller must free the memory allocated for the upn.
 */
static char *
smb_krb5_get_host_upn(const char *fqhn)
{
	char *upn;
	char *realm;
	char *dom;
	int len;

	if ((dom = strchr(fqhn, '.')) == NULL)
		return (NULL);

	if ((realm = strdup(++dom)) == NULL)
		return (NULL);

	(void) utf8_strupr(realm);

	len = strlen(spn_prefix[SMBKRB5_SPN_IDX_HOST]) + strlen(fqhn) +
	    + 1 + strlen(realm) + 1;
	if ((upn = malloc(len)) == NULL) {
		free(realm);
		return (NULL);
	}

	(void) snprintf(upn, len, "%s%s@%s", spn_prefix[SMBKRB5_SPN_IDX_HOST],
	    fqhn, realm);

	free(realm);
	return (upn);
}

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
 * smb_krb5_get_principals
 *
 * Setup the krb5_principal array given the principals in string format.
 * Return 0 on success. Otherwise, return -1.
 */
int
smb_krb5_get_principals(char *domain, krb5_context ctx,
    krb5_principal *krb5princs)
{
	char fqhn[MAXHOSTNAMELEN];
	int i;
	char *spn, *upn;

	if (smb_gethostname(fqhn, MAXHOSTNAMELEN, 0) != 0)
			return (-1);

	(void) snprintf(fqhn, MAXHOSTNAMELEN, "%s.%s", fqhn,
	    domain);

	for (i = 0; i < SMBKRB5_SPN_IDX_MAX; i++) {

		if ((spn = smb_krb5_get_spn(i, fqhn)) == NULL) {
			return (-1);
		}

		upn = smb_krb5_get_upn(spn, domain);
		free(spn);

		if (krb5_parse_name(ctx, upn, &krb5princs[i]) != 0) {
			smb_krb5_free_principals(ctx, krb5princs, i - 1);
			free(upn);
			return (-1);
		}
		free(upn);
	}
	return (0);
}

void
smb_krb5_free_principals(krb5_context ctx, krb5_principal *krb5princs,
    size_t num)
{
	int i;

	for (i = 0; i < num; i++)
		krb5_free_principal(ctx, krb5princs[i]);
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
 * smb_krb5_add_keytab_entries
 *
 * Update the keys for the specified principal in the keytab.
 * Returns 0 on success.  Otherwise, returns -1.
 */
int
smb_krb5_add_keytab_entries(krb5_context ctx, krb5_principal *princs,
    char *fname, krb5_kvno kvno, char *passwd, krb5_enctype *enctypes,
    int enctype_count)
{
	krb5_keytab kt = NULL;
	int i, j;

	if (smb_krb5_open_wrfile(ctx, fname, &kt) != 0)
		return (-1);

	for (j = 0; j < SMBKRB5_SPN_IDX_MAX; j++) {
		for (i = 0; i < enctype_count; i++) {
			if (smb_krb5_ktadd(ctx, kt, princs[j], enctypes[i],
			    kvno, passwd) != 0) {
				krb5_kt_close(ctx, kt);
				return (-1);
			}
		}

	}
	krb5_kt_close(ctx, kt);
	return (0);
}

boolean_t
smb_krb5_find_keytab_entries(const char *fqhn, char *fname)
{
	krb5_context ctx;
	krb5_keytab kt;
	krb5_keytab_entry entry;
	krb5_principal princ;
	char ktname[MAXPATHLEN];
	char *upn;
	boolean_t found = B_FALSE;

	if (!fqhn || !fname)
		return (found);

	if ((upn = smb_krb5_get_host_upn((char *)fqhn)) == NULL)
		return (found);

	if (smb_krb5_ctx_init(&ctx) != 0) {
		free(upn);
		return (found);
	}

	if (krb5_parse_name(ctx, upn, &princ) != 0) {
		free(upn);
		smb_krb5_ctx_fini(ctx);
		return (found);
	}

	free(upn);
	(void) snprintf(ktname, MAXPATHLEN, "FILE:%s", fname);
	if (krb5_kt_resolve(ctx, ktname, &kt) == 0) {
		if (krb5_kt_get_entry(ctx, kt, princ, 0, 0, &entry) == 0) {
			found = B_TRUE;
			krb5_kt_free_entry(ctx, &entry);
		}

		krb5_kt_close(ctx, kt);
	}

	krb5_free_principal(ctx, princ);
	smb_krb5_ctx_fini(ctx);
	return (found);
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
