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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
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

/*
 * Kerberized services available on the system.
 */
static smb_krb5_pn_t smb_krb5_pn_tab[] = {
	/*
	 * Service keys are salted with the SMB_KRB_PN_ID_ID_SALT prinipal
	 * name.
	 */
	{SMB_KRB5_PN_ID_SALT,		SMB_PN_SVC_HOST,	SMB_PN_SALT},

	/* CIFS SPNs. (HOST, CIFS, ...) */
	{SMB_KRB5_PN_ID_HOST_FQHN,	SMB_PN_SVC_HOST,
	    SMB_PN_KEYTAB_ENTRY | SMB_PN_SPN_ATTR | SMB_PN_UPN_ATTR},
	{SMB_KRB5_PN_ID_HOST_SHORT,	SMB_PN_SVC_HOST,
	    SMB_PN_KEYTAB_ENTRY | SMB_PN_SPN_ATTR},
	{SMB_KRB5_PN_ID_CIFS_FQHN,	SMB_PN_SVC_CIFS,
	    SMB_PN_KEYTAB_ENTRY | SMB_PN_SPN_ATTR},
	{SMB_KRB5_PN_ID_CIFS_SHORT,	SMB_PN_SVC_CIFS,
	    SMB_PN_KEYTAB_ENTRY | SMB_PN_SPN_ATTR},
	{SMB_KRB5_PN_ID_MACHINE,	NULL,
	    SMB_PN_KEYTAB_ENTRY},

	/* NFS */
	{SMB_KRB5_PN_ID_NFS_FQHN,	SMB_PN_SVC_NFS,
	    SMB_PN_KEYTAB_ENTRY | SMB_PN_SPN_ATTR},

	/* HTTP */
	{SMB_KRB5_PN_ID_HTTP_FQHN,	SMB_PN_SVC_HTTP,
	    SMB_PN_KEYTAB_ENTRY | SMB_PN_SPN_ATTR},

	/* ROOT */
	{SMB_KRB5_PN_ID_ROOT_FQHN,	SMB_PN_SVC_ROOT,
	    SMB_PN_KEYTAB_ENTRY | SMB_PN_SPN_ATTR},
};

#define	SMB_KRB5_SPN_TAB_SZ \
	(sizeof (smb_krb5_pn_tab) / sizeof (smb_krb5_pn_tab[0]))

#define	SMB_KRB5_MAX_BUFLEN	128

static int smb_krb5_kt_open(krb5_context, char *, krb5_keytab *);
static int smb_krb5_kt_addkey(krb5_context, krb5_keytab, const krb5_principal,
    krb5_enctype, krb5_kvno, const krb5_data *, const char *);
static int smb_krb5_spn_count(uint32_t);
static smb_krb5_pn_t *smb_krb5_lookup_pn(smb_krb5_pn_id_t);
static char *smb_krb5_get_pn_by_id(smb_krb5_pn_id_t, uint32_t,
    const char *);
static int smb_krb5_get_kprinc(krb5_context, smb_krb5_pn_id_t, uint32_t,
    const char *, krb5_principal *);


/*
 * Generates a null-terminated array of principal names that
 * represents the list of the available Kerberized services
 * of the specified type (SPN attribute, UPN attribute, or
 * keytab entry).
 *
 * Returns the number of principal names returned via the 1st
 * output parameter (i.e. vals).
 *
 * Caller must invoke smb_krb5_free_spns to free the allocated
 * memory when finished.
 */
uint32_t
smb_krb5_get_pn_set(smb_krb5_pn_set_t *set, uint32_t type, char *fqdn)
{
	int cnt, i;
	smb_krb5_pn_t *tabent;

	if (!set || !fqdn)
		return (0);

	bzero(set, sizeof (smb_krb5_pn_set_t));
	cnt = smb_krb5_spn_count(type);
	set->s_pns = (char **)calloc(cnt + 1, sizeof (char *));

	if (set->s_pns == NULL)
		return (0);

	for (i = 0, set->s_cnt = 0; i < SMB_KRB5_SPN_TAB_SZ; i++) {
		tabent = &smb_krb5_pn_tab[i];

		if (set->s_cnt == cnt)
			break;

		if ((tabent->p_flags & type) != type)
			continue;

		set->s_pns[set->s_cnt] = smb_krb5_get_pn_by_id(tabent->p_id,
		    type, fqdn);
		if (set->s_pns[set->s_cnt] == NULL) {
			syslog(LOG_ERR, "smbns_ksetpwd: failed to obtain "
			    "principal names: possible transient memory "
			    "shortage");
			smb_krb5_free_pn_set(set);
			return (0);
		}

		set->s_cnt++;
	}

	if (set->s_cnt == 0)
		smb_krb5_free_pn_set(set);

	return (set->s_cnt);
}

void
smb_krb5_free_pn_set(smb_krb5_pn_set_t *set)
{
	int i;

	if (set == NULL || set->s_pns == NULL)
		return;

	for (i = 0; i < set->s_cnt; i++)
		free(set->s_pns[i]);

	free(set->s_pns);
	set->s_pns = NULL;
}

/*
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
 * Free the kerberos context.
 */
void
smb_krb5_ctx_fini(krb5_context ctx)
{
	krb5_free_context(ctx);
}

/*
 * Create an array of Kerberos Princiapls given an array of principal names.
 * Caller must free the allocated memory using smb_krb5_free_kprincs()
 * upon success.
 *
 * Returns 0 on success. Otherwise, returns -1.
 */
int
smb_krb5_get_kprincs(krb5_context ctx, char **names, size_t num,
    krb5_principal **krb5princs)
{
	int i;

	if ((*krb5princs = calloc(num, sizeof (krb5_principal *))) == NULL) {
		return (-1);
	}

	for (i = 0; i < num; i++) {
		if (krb5_parse_name(ctx, names[i], &(*krb5princs)[i]) != 0) {
			smb_krb5_free_kprincs(ctx, *krb5princs, i);
			return (-1);
		}
	}

	return (0);
}

void
smb_krb5_free_kprincs(krb5_context ctx, krb5_principal *krb5princs,
    size_t num)
{
	int i;

	for (i = 0; i < num; i++)
		krb5_free_principal(ctx, krb5princs[i]);

	free(krb5princs);
}

/*
 * Set the workstation trust account password.
 * Returns 0 on success.  Otherwise, returns non-zero value.
 */
int
smb_krb5_setpwd(krb5_context ctx, const char *fqdn, char *passwd)
{
	krb5_error_code code;
	krb5_ccache cc = NULL;
	int result_code = 0;
	krb5_data result_code_string, result_string;
	krb5_principal princ;
	char msg[SMB_KRB5_MAX_BUFLEN];

	if (smb_krb5_get_kprinc(ctx, SMB_KRB5_PN_ID_HOST_FQHN,
	    SMB_PN_UPN_ATTR, fqdn, &princ) != 0)
		return (-1);

	(void) memset(&result_code_string, 0, sizeof (result_code_string));
	(void) memset(&result_string, 0, sizeof (result_string));

	if ((code = krb5_cc_default(ctx, &cc)) != 0) {
		(void) snprintf(msg, sizeof (msg), "smbns_ksetpwd: failed to "
		    "find %s", SMB_CCACHE_PATH);
		smb_krb5_log_errmsg(ctx, msg, code);
		krb5_free_principal(ctx, princ);
		return (-1);
	}

	code = krb5_set_password_using_ccache(ctx, cc, passwd, princ,
	    &result_code, &result_code_string, &result_string);

	if (code != 0)
		smb_krb5_log_errmsg(ctx, "smbns_ksetpwd: KPASSWD protocol "
		    "exchange failed", code);

	(void) krb5_cc_close(ctx, cc);

	if (result_code != 0)
		syslog(LOG_ERR, "smbns_ksetpwd: KPASSWD failed: %s",
		    result_code_string.data);

	krb5_free_principal(ctx, princ);
	free(result_code_string.data);
	free(result_string.data);
	return (code);
}

/*
 * Open the keytab file for writing.
 * The keytab should be closed by calling krb5_kt_close().
 */
static int
smb_krb5_kt_open(krb5_context ctx, char *fname, krb5_keytab *kt)
{
	char *ktname;
	krb5_error_code code;
	int len;
	char msg[SMB_KRB5_MAX_BUFLEN];

	*kt = NULL;
	len = snprintf(NULL, 0, "WRFILE:%s", fname) + 1;
	if ((ktname = malloc(len)) == NULL) {
		syslog(LOG_ERR, "smbns_ksetpwd: unable to open keytab %s: "
		    "possible transient memory shortage", fname);
		return (-1);
	}

	(void) snprintf(ktname, len, "WRFILE:%s", fname);

	if ((code = krb5_kt_resolve(ctx, ktname, kt)) != 0) {
		(void) snprintf(msg, sizeof (msg), "smbns_ksetpwd: %s", fname);
		smb_krb5_log_errmsg(ctx, msg, code);
		free(ktname);
		return (-1);
	}

	free(ktname);
	return (0);
}

/*
 * Populate the keytab with keys of the specified key version for the
 * specified set of krb5 principals.  All service keys will be salted by:
 * host/<truncated@15_lower_case_hostname>.<fqdn>@<REALM>
 */
int
smb_krb5_kt_populate(krb5_context ctx, const char *fqdn,
    krb5_principal *princs, int count, char *fname, krb5_kvno kvno,
    char *passwd, krb5_enctype *enctypes, int enctype_count)
{
	krb5_keytab kt = NULL;
	krb5_data salt;
	krb5_error_code code;
	krb5_principal salt_princ;
	int i, j;

	if (smb_krb5_kt_open(ctx, fname, &kt) != 0)
		return (-1);

	if (smb_krb5_get_kprinc(ctx, SMB_KRB5_PN_ID_SALT, SMB_PN_SALT,
	    fqdn, &salt_princ) != 0) {
		(void) krb5_kt_close(ctx, kt);
		return (-1);
	}

	code = krb5_principal2salt(ctx, salt_princ, &salt);
	if (code != 0) {
		smb_krb5_log_errmsg(ctx, "smbns_ksetpwd: salt computation "
		    "failed", code);
		krb5_free_principal(ctx, salt_princ);
		(void) krb5_kt_close(ctx, kt);
		return (-1);
	}

	for (j = 0; j < count; j++) {
		for (i = 0; i < enctype_count; i++) {
			if (smb_krb5_kt_addkey(ctx, kt, princs[j], enctypes[i],
			    kvno, &salt, passwd) != 0) {
				krb5_free_principal(ctx, salt_princ);
				krb5_xfree(salt.data);
				(void) krb5_kt_close(ctx, kt);
				return (-1);
			}
		}

	}
	krb5_free_principal(ctx, salt_princ);
	krb5_xfree(salt.data);
	(void) krb5_kt_close(ctx, kt);
	return (0);
}

boolean_t
smb_krb5_kt_find(smb_krb5_pn_id_t id, const char *fqdn, char *fname)
{
	krb5_context ctx;
	krb5_keytab kt;
	krb5_keytab_entry entry;
	krb5_principal princ;
	char ktname[MAXPATHLEN];
	boolean_t found = B_FALSE;

	if (!fqdn || !fname)
		return (found);

	if (smb_krb5_ctx_init(&ctx) != 0)
		return (found);

	if (smb_krb5_get_kprinc(ctx, id, SMB_PN_KEYTAB_ENTRY, fqdn,
	    &princ) != 0) {
		smb_krb5_ctx_fini(ctx);
		return (found);
	}

	(void) snprintf(ktname, MAXPATHLEN, "FILE:%s", fname);
	if (krb5_kt_resolve(ctx, ktname, &kt) == 0) {
		if (krb5_kt_get_entry(ctx, kt, princ, 0, 0, &entry) == 0) {
			found = B_TRUE;
			(void) krb5_kt_free_entry(ctx, &entry);
		}

		(void) krb5_kt_close(ctx, kt);
	}

	krb5_free_principal(ctx, princ);
	smb_krb5_ctx_fini(ctx);
	return (found);
}

/*
 * Add a key of the specified encryption type for the specified principal
 * to the keytab file.
 * Returns 0 on success. Otherwise, returns -1.
 */
static int
smb_krb5_kt_addkey(krb5_context ctx, krb5_keytab kt, const krb5_principal princ,
    krb5_enctype enctype, krb5_kvno kvno, const krb5_data *salt,
    const char *pw)
{
	krb5_keytab_entry *entry;
	krb5_data password;
	krb5_keyblock key;
	krb5_error_code code;
	char buf[SMB_KRB5_MAX_BUFLEN], msg[SMB_KRB5_MAX_BUFLEN];
	int rc = 0;

	if ((code = krb5_enctype_to_string(enctype, buf, sizeof (buf)))) {
		(void) snprintf(msg, sizeof (msg), "smbns_ksetpwd: unknown "
		    "encryption type (%d)", enctype);
		smb_krb5_log_errmsg(ctx, msg, code);
		return (-1);
	}

	if ((entry = (krb5_keytab_entry *) malloc(sizeof (*entry))) == NULL) {
		syslog(LOG_ERR, "smbns_ksetpwd: possible transient "
		    "memory shortage");
		return (-1);
	}

	(void) memset((char *)entry, 0, sizeof (*entry));

	password.length = strlen(pw);
	password.data = (char *)pw;

	code = krb5_c_string_to_key(ctx, enctype, &password, salt, &key);
	if (code != 0) {
		(void) snprintf(msg, sizeof (msg), "smbns_ksetpwd: failed to "
		    "generate key (%d)", enctype);
		smb_krb5_log_errmsg(ctx, msg, code);
		free(entry);
		return (-1);
	}

	(void) memcpy(&entry->key, &key, sizeof (krb5_keyblock));
	entry->vno = kvno;
	entry->principal = princ;

	if ((code = krb5_kt_add_entry(ctx, kt, entry)) != 0) {
		(void) snprintf(msg, sizeof (msg), "smbns_ksetpwd: failed to "
		    "add key (%d)", enctype);
		smb_krb5_log_errmsg(ctx, msg, code);
		rc = -1;
	}

	free(entry);
	if (key.length)
		krb5_free_keyblock_contents(ctx, &key);
	return (rc);
}

static int
smb_krb5_spn_count(uint32_t type)
{
	int i, cnt;

	for (i = 0, cnt = 0; i < SMB_KRB5_SPN_TAB_SZ; i++) {
		if (smb_krb5_pn_tab[i].p_flags & type)
			cnt++;
	}

	return (cnt);
}

/*
 * Generate the Kerberos Principal given a principal name format and the
 * fully qualified domain name. On success, caller must free the allocated
 * memory by calling krb5_free_principal().
 */
static int
smb_krb5_get_kprinc(krb5_context ctx, smb_krb5_pn_id_t id, uint32_t type,
    const char *fqdn, krb5_principal *princ)
{
	char *buf;

	if ((buf = smb_krb5_get_pn_by_id(id, type, fqdn)) == NULL)
		return (-1);

	if (krb5_parse_name(ctx, buf, princ) != 0) {
		free(buf);
		return (-1);
	}

	free(buf);
	return (0);
}

/*
 * Looks up an entry in the principal name table given the ID.
 */
static smb_krb5_pn_t *
smb_krb5_lookup_pn(smb_krb5_pn_id_t id)
{
	int i;
	smb_krb5_pn_t *tabent;

	for (i = 0; i < SMB_KRB5_SPN_TAB_SZ; i++) {
		tabent = &smb_krb5_pn_tab[i];
		if (id == tabent->p_id)
			return (tabent);
	}

	return (NULL);
}

/*
 * Construct the principal name given an ID, the requested type, and the
 * fully-qualified name of the domain of which the principal is a member.
 */
static char *
smb_krb5_get_pn_by_id(smb_krb5_pn_id_t id, uint32_t type,
    const char *fqdn)
{
	char nbname[NETBIOS_NAME_SZ];
	char hostname[MAXHOSTNAMELEN];
	char *realm = NULL;
	smb_krb5_pn_t *pn;
	char *buf;

	(void) smb_getnetbiosname(nbname, NETBIOS_NAME_SZ);
	(void) smb_gethostname(hostname, MAXHOSTNAMELEN, SMB_CASE_LOWER);

	pn = smb_krb5_lookup_pn(id);

	/* detect inconsistent requested format and type */
	if ((type & pn->p_flags) != type)
		return (NULL);

	switch (id) {
	case SMB_KRB5_PN_ID_SALT:
		(void) asprintf(&buf, "%s/%s.%s",
		    pn->p_svc, smb_strlwr(nbname), fqdn);
		break;

	case SMB_KRB5_PN_ID_HOST_FQHN:
	case SMB_KRB5_PN_ID_CIFS_FQHN:
	case SMB_KRB5_PN_ID_NFS_FQHN:
	case SMB_KRB5_PN_ID_HTTP_FQHN:
	case SMB_KRB5_PN_ID_ROOT_FQHN:
		(void) asprintf(&buf, "%s/%s.%s",
		    pn->p_svc, hostname, fqdn);
		break;

	case SMB_KRB5_PN_ID_HOST_SHORT:
	case SMB_KRB5_PN_ID_CIFS_SHORT:
		(void) asprintf(&buf, "%s/%s",
		    pn->p_svc, nbname);
		break;

	/*
	 * SPN for the machine account, which is simply the
	 * (short) machine name with a dollar sign appended.
	 */
	case SMB_KRB5_PN_ID_MACHINE:
		(void) asprintf(&buf, "%s$", nbname);
		break;

	default:
		return (NULL);
	}

	/*
	 * If the requested principal is either added to keytab / the machine
	 * account as the UPN attribute or used for key salt generation,
	 * the principal name must have the @<REALM> portion.
	 */
	if (type & (SMB_PN_KEYTAB_ENTRY | SMB_PN_UPN_ATTR | SMB_PN_SALT)) {
		if ((realm = strdup(fqdn)) == NULL) {
			free(buf);
			return (NULL);
		}

		(void) smb_strupr(realm);
		if (buf != NULL) {
			char *tmp;

			(void) asprintf(&tmp, "%s@%s", buf,
			    realm);
			free(buf);
			buf = tmp;
		}

		free(realm);
	}

	return (buf);
}
