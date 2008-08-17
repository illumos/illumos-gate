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

#pragma ident	"@(#)smb_auth.c	1.5	08/07/08 SMI"

#include <strings.h>
#include <stdlib.h>
#include <smbsrv/codepage.h>
#include <smbsrv/oem.h>
#include <smbsrv/ctype.h>
#include <smbsrv/crypt.h>
#include <smbsrv/libsmb.h>

extern void randomize(char *data, unsigned len);
static uint64_t unix_micro_to_nt_time(struct timeval *unix_time);

/*
 * smb_auth_qnd_unicode
 *
 * Quick and dirty unicode conversion!
 * Returns the length of dst in bytes.
 */
int
smb_auth_qnd_unicode(mts_wchar_t *dst, char *src, int length)
{
	int i;

	unsigned int cpid = oem_get_telnet_cpid();
	unsigned int count;
	mts_wchar_t new_char;

	if ((count = oemstounicodes(dst, src, length, cpid)) == 0) {
		for (i = 0; i < length; ++i) {
			new_char = (mts_wchar_t)src[i] & 0xff;
			dst[i] = LE_IN16(&new_char);
		}
		dst[i] = 0;
		count = length;
	}

	return (count * sizeof (mts_wchar_t));
}

/*
 * smb_auth_lmupr
 *
 * Converts the given LM password to all uppercase.
 * The standard strupr cannot
 * be used here because lm_pwd doesn't have to be
 * nul terminated.
 */
static void
smb_auth_lmupr(unsigned char *lm_pwd)
{
	unsigned char *p = lm_pwd;
	int i;

	for (i = 0; (*p) && (i < SMBAUTH_LM_PWD_SZ); i++) {
		if (mts_isascii(*p)) {
			*p = codepage_toupper(*p);
			p++;
		}
	}
}

/*
 * smb_auth_lm_hash
 *
 * Source: Implementing CIFS (Chris Hertel)
 *
 * 1. The password, as entered by user, is either padded with nulls
 *	  or trimmed to 14 bytes.
 *    . Note that the 14-byte result string is not handled as a
 *	    nul-terminated string.
 *	  . The given password is OEM not Unicode
 *
 * 2. The 14-byte password is converted to all uppercase
 *
 * 3. The result is used as key to encrypt the KGS magic string to
 *    make a 16-byte hash.
 */
int
smb_auth_lm_hash(char *password, unsigned char *lm_hash)
{
	unsigned char lm_pwd[SMBAUTH_LM_PWD_SZ];

	bzero((void *)lm_pwd, SMBAUTH_LM_PWD_SZ);
	(void) strncpy((char *)lm_pwd, password, SMBAUTH_LM_PWD_SZ);
	smb_auth_lmupr(lm_pwd);

	return (smb_auth_DES(lm_hash, SMBAUTH_HASH_SZ, lm_pwd,
	    SMBAUTH_LM_PWD_SZ, (unsigned char *)SMBAUTH_LM_MAGIC_STR,
	    sizeof (SMBAUTH_LM_MAGIC_STR)));
}

/*
 * smb_auth_lm_response
 *
 * Create a LM response from the given LM hash and challenge.
 *
 * Returns SMBAUTH_FAILURE if any problems occur, SMBAUTH_SUCCESS if
 * all goes well.
 */
static int
smb_auth_lm_response(unsigned char *hash,
    unsigned char *challenge, int clen,
    unsigned char *lm_rsp)
{
	unsigned char S21[21];

	/*
	 * 14-byte LM Hash should be padded with 5 nul bytes to create
	 * a 21-byte string to be used in producing LM response
	 */
	bzero(&S21[SMBAUTH_HASH_SZ], 5);
	bcopy(hash, S21, SMBAUTH_HASH_SZ);

	/* padded LM Hash -> LM Response */
	return (smb_auth_DES(lm_rsp, SMBAUTH_LM_RESP_SZ, S21, 21,
	    challenge, clen));
}

/*
 * smb_auth_ntlm_hash
 *
 * Make NTLM Hash (using MD4) from the given password.
 * The result will contain a 16-byte NTLM hash.
 */
int
smb_auth_ntlm_hash(char *password, unsigned char *hash)
{
	mts_wchar_t *unicode_password;
	int length;
	int rc;

	if (password == NULL || hash == NULL)
		return (SMBAUTH_FAILURE);

	length = strlen(password);
	unicode_password = (mts_wchar_t *)
	    malloc((length + 1) * sizeof (mts_wchar_t));

	if (unicode_password == NULL)
		return (SMBAUTH_FAILURE);

	length = smb_auth_qnd_unicode(unicode_password, password, length);
	rc = smb_auth_md4(hash, (unsigned char *)unicode_password, length);

	free(unicode_password);
	return (rc);
}

/*
 * smb_auth_ntlm_response
 *
 * Make LM/NTLM response from the given LM/NTLM Hash and given
 * challenge.
 */
static int
smb_auth_ntlm_response(unsigned char *hash,
    unsigned char *challenge, int clen,
    unsigned char *ntlm_rsp)
{
	unsigned char S21[21];

	bcopy(hash, S21, SMBAUTH_HASH_SZ);
	bzero(&S21[SMBAUTH_HASH_SZ], 5);
	if (smb_auth_DES((unsigned char *)ntlm_rsp, SMBAUTH_LM_RESP_SZ,
	    S21, 21, challenge, clen) == SMBAUTH_FAILURE)
		return (0);
	return (SMBAUTH_LM_RESP_SZ);
}

/*
 * smb_auth_gen_data_blob
 *
 * Fill the NTLMv2 data blob structure with information as described in
 * "Implementing CIFS, The Common Internet File System". (pg. 282)
 */
static void
smb_auth_gen_data_blob(smb_auth_data_blob_t *blob, char *ntdomain)
{
	struct timeval now;

	(void) memset(blob->ndb_signature, 1, 2);
	(void) memset(&blob->ndb_signature[2], 0, 2);
	(void) memset(blob->ndb_reserved, 0, sizeof (blob->ndb_reserved));

	(void) gettimeofday(&now, 0);
	blob->ndb_timestamp = unix_micro_to_nt_time(&now);
	randomize((char *)blob->ndb_clnt_challenge,
	    SMBAUTH_V2_CLNT_CHALLENGE_SZ);
	(void) memset(blob->ndb_unknown, 0, sizeof (blob->ndb_unknown));
	blob->ndb_names[0].nne_len = smb_auth_qnd_unicode(
	    blob->ndb_names[0].nne_name, ntdomain, strlen(ntdomain));
	blob->ndb_names[0].nne_type = SMBAUTH_NAME_TYPE_DOMAIN_NETBIOS;
	blob->ndb_names[1].nne_len = 0;
	blob->ndb_names[1].nne_type = SMBAUTH_NAME_TYPE_LIST_END;
	*blob->ndb_names[1].nne_name = 0;
	(void) memset(blob->ndb_unknown2, 0, sizeof (blob->ndb_unknown2));
}

/*
 * smb_auth_memcpy
 *
 * It increments the pointer to the destination buffer for the easy of
 * concatenation.
 */
static void
smb_auth_memcpy(unsigned char **dstbuf,
	unsigned char *srcbuf,
	int srcbuf_len)
{
	(void) memcpy(*dstbuf, srcbuf, srcbuf_len);
	*dstbuf += srcbuf_len;
}

/*
 * smb_auth_blob_to_string
 *
 * Prepare the data blob string which will be used in NTLMv2 response
 * generation.
 *
 * Assumption: Caller must allocate big enough buffer to prevent buffer
 * overrun.
 *
 * Returns the len of the data blob string.
 */
static int
smb_auth_blob_to_string(smb_auth_data_blob_t *blob, unsigned char *data_blob)
{
	unsigned char *bufp = data_blob;

	smb_auth_memcpy(&bufp, blob->ndb_signature,
	    sizeof (blob->ndb_signature));
	smb_auth_memcpy(&bufp, blob->ndb_reserved,
	    sizeof (blob->ndb_reserved));
	smb_auth_memcpy(&bufp, (unsigned char *)&blob->ndb_timestamp,
	    sizeof (blob->ndb_timestamp));
	smb_auth_memcpy(&bufp, blob->ndb_clnt_challenge,
	    SMBAUTH_V2_CLNT_CHALLENGE_SZ);
	smb_auth_memcpy(&bufp, blob->ndb_unknown, sizeof (blob->ndb_unknown));
	smb_auth_memcpy(&bufp, (unsigned char *)&blob->ndb_names[0].nne_type,
	    sizeof (blob->ndb_names[0].nne_type));
	smb_auth_memcpy(&bufp, (unsigned char *)&blob->ndb_names[0].nne_len,
	    sizeof (blob->ndb_names[0].nne_len));
	smb_auth_memcpy(&bufp, (unsigned char *)blob->ndb_names[0].nne_name,
	    blob->ndb_names[0].nne_len);
	smb_auth_memcpy(&bufp, (unsigned char *)&blob->ndb_names[1].nne_type,
	    sizeof (blob->ndb_names[1].nne_type));
	smb_auth_memcpy(&bufp, (unsigned char *)&blob->ndb_names[1].nne_len,
	    sizeof (blob->ndb_names[1].nne_len));
	smb_auth_memcpy(&bufp, blob->ndb_unknown2, sizeof (blob->ndb_unknown2));

	/*LINTED E_PTRDIFF_OVERFLOW*/
	return (bufp - data_blob);
}

/*
 * smb_auth_ntlmv2_hash
 *
 * The NTLM v2 hash will be created from the given NTLM hash, username,
 * and the NETBIOS name of the domain.
 *
 * The NTLMv2 hash will be returned via the ntlmv2_hash parameter which
 * will be used in the calculation of the NTLMv2 and LMv2 responses.
 */
int
smb_auth_ntlmv2_hash(unsigned char *ntlm_hash,
    char *username,
    char *ntdomain,
    unsigned char *ntlmv2_hash)
{
	mts_wchar_t *data;
	int data_len;
	unsigned char *buf;
	int rc;

	if (username == NULL || ntdomain == NULL)
		return (SMBAUTH_FAILURE);

	(void) utf8_strupr(username);

	data_len = strlen(username) + strlen(ntdomain);
	buf = (unsigned char *)malloc((data_len + 1) * sizeof (char));
	if (buf == NULL)
		return (SMBAUTH_FAILURE);

	(void) snprintf((char *)buf, data_len + 1, "%s%s", username, ntdomain);
	data = (mts_wchar_t *)malloc((data_len + 1) * sizeof (mts_wchar_t));
	if (data == NULL) {
		free(buf);
		return (SMBAUTH_FAILURE);
	}

	data_len = smb_auth_qnd_unicode(data, (char *)buf, data_len);
	rc = SMBAUTH_HMACT64((unsigned char *)data, data_len, ntlm_hash,
	    SMBAUTH_HASH_SZ, ntlmv2_hash);

	free(buf);
	free(data);
	return (rc);
}

/*
 * smb_auth_v2_response
 *
 * Caculates either the LMv2 or NTLMv2 response.
 *
 * Same algorithm is used for calculating both LMv2 or NTLMv2 responses.
 * This routine will return NTLMv2 response if the data blob information
 * is passed in as the clnt_data. Otherwise, it will return LMv2 response
 * with the 8-byte client challenge(a.k.a blip) as the clnt_data.
 *
 * (LM/NTLM)v2 response is the hmac-md5 hash of the specified data
 * (server challenge + NTLMv2 data blob or LMv2 client challenge)
 * using the NTLMv2 hash as the key.
 *
 * Returns the size of the corresponding v2 response upon success.
 * Otherwise, returns -1 on error.
 */
static int
smb_auth_v2_response(
	unsigned char *hash,
	unsigned char *srv_challenge, int slen,
	unsigned char *clnt_data, int clen,
	unsigned char *v2_rsp)
{
	unsigned char *hmac_data;

	hmac_data = (unsigned char *)malloc((slen + clen) * sizeof (char));
	if (!hmac_data) {
		return (-1);
	}

	(void) memcpy(hmac_data, srv_challenge, slen);
	(void) memcpy(&hmac_data[slen], clnt_data, clen);
	if (SMBAUTH_HMACT64(hmac_data, slen + clen, (unsigned char *)hash,
	    SMBAUTH_HASH_SZ, (unsigned char *)v2_rsp) != SMBAUTH_SUCCESS)
		return (-1);
	(void) memcpy(&v2_rsp[SMBAUTH_HASH_SZ], clnt_data, clen);

	free(hmac_data);
	return (SMBAUTH_HASH_SZ + clen);
}

/*
 * smb_auth_set_info
 *
 * Fill the smb_auth_info instance with either NTLM or NTLMv2 related
 * authentication information based on the LMCompatibilityLevel.
 *
 * If the LMCompatibilityLevel equals 2, the SMB Redirector will perform
 * NTLM challenge/response authentication which requires the NTLM hash and
 * NTLM response.
 *
 * If the LMCompatibilityLevel is 3 or above, the SMB Redirector will
 * perfrom NTLMv2 challenge/response authenticatoin which requires the
 * NTLM hash, NTLMv2 hash, NTLMv2 response and LMv2 response.
 *
 * Returns -1 on error. Otherwise, returns 0 upon success.
 */
int
smb_auth_set_info(char *username,
	char *password,
	unsigned char *ntlm_hash,
	char *domain,
	unsigned char *srv_challenge_key,
	int srv_challenge_len,
	int lmcomp_lvl,
	smb_auth_info_t *auth)
{
	unsigned short blob_len;
	unsigned char blob_buf[SMBAUTH_BLOB_MAXLEN];
	int rc;
	char *uppercase_dom;

	auth->lmcompatibility_lvl = lmcomp_lvl;
	if (lmcomp_lvl == 2) {
		auth->ci_len = 0;
		*auth->ci = 0;
		if (!ntlm_hash) {
			if (smb_auth_ntlm_hash(password, auth->hash) !=
			    SMBAUTH_SUCCESS)
				return (-1);
		} else {
			(void) memcpy(auth->hash, ntlm_hash, SMBAUTH_HASH_SZ);
		}

		auth->cs_len = smb_auth_ntlm_response(auth->hash,
		    srv_challenge_key, srv_challenge_len, auth->cs);
	} else {
		if (!ntlm_hash) {
			if (smb_auth_ntlm_hash(password, auth->hash) !=
			    SMBAUTH_SUCCESS)
				return (-1);
		} else {
			(void) memcpy(auth->hash, ntlm_hash, SMBAUTH_HASH_SZ);
		}

		if (!domain)
			return (-1);

		if ((uppercase_dom = strdup(domain)) == NULL)
			return (-1);

		(void) utf8_strupr(uppercase_dom);

		if (smb_auth_ntlmv2_hash(auth->hash, username,
		    uppercase_dom, auth->hash_v2) != SMBAUTH_SUCCESS) {
			free(uppercase_dom);
			return (-1);
		}

		/* generate data blob */
		smb_auth_gen_data_blob(&auth->data_blob, uppercase_dom);
		free(uppercase_dom);
		blob_len = smb_auth_blob_to_string(&auth->data_blob, blob_buf);

		/* generate NTLMv2 response */
		rc = smb_auth_v2_response(auth->hash_v2, srv_challenge_key,
		    srv_challenge_len, blob_buf, blob_len, auth->cs);

		if (rc < 0)
			return (-1);

		auth->cs_len = rc;

		/* generate LMv2 response */
		rc = smb_auth_v2_response(auth->hash_v2, srv_challenge_key,
		    srv_challenge_len, auth->data_blob.ndb_clnt_challenge,
		    SMBAUTH_V2_CLNT_CHALLENGE_SZ, auth->ci);

		if (rc < 0)
			return (-1);

		auth->ci_len = rc;
	}

	return (0);
}

/*
 * smb_auth_gen_session_key
 *
 * Generate the NTLM user session key if LMCompatibilityLevel is 2 or
 * NTLMv2 user session key if LMCompatibilityLevel is 3 or above.
 *
 * NTLM_Session_Key = MD4(NTLM_Hash);
 *
 * NTLMv2_Session_Key = HMAC_MD5(NTLMv2Hash, 16, NTLMv2_HMAC, 16)
 *
 * Prior to calling this function, the auth instance should be set
 * via smb_auth_set_info().
 *
 * Returns the appropriate session key.
 */
int
smb_auth_gen_session_key(smb_auth_info_t *auth, unsigned char *session_key)
{
	int rc;

	if (auth->lmcompatibility_lvl == 2)
		rc = smb_auth_md4(session_key, auth->hash, SMBAUTH_HASH_SZ);
	else
		rc = SMBAUTH_HMACT64((unsigned char *)auth->cs,
		    SMBAUTH_HASH_SZ, (unsigned char *)auth->hash_v2,
		    SMBAUTH_SESSION_KEY_SZ, session_key);

	return (rc);
}

/* 100's of ns between 1/1/1970 and 1/1/1601 */
#define	NT_TIME_BIAS    (134774LL * 24LL * 60LL * 60LL * 10000000LL)

static uint64_t
unix_micro_to_nt_time(struct timeval *unix_time)
{
	uint64_t nt_time;

	nt_time = unix_time->tv_sec;
	nt_time *= 10000000;  /* seconds to 100ns */
	nt_time += unix_time->tv_usec * 10;
	return (nt_time + NT_TIME_BIAS);
}

static boolean_t
smb_lm_password_ok(
    unsigned char *challenge,
    uint32_t clen,
    unsigned char *lm_hash,
    unsigned char *passwd)
{
	unsigned char lm_resp[SMBAUTH_LM_RESP_SZ];
	int rc;

	rc = smb_auth_lm_response(lm_hash, challenge, clen, lm_resp);
	if (rc != SMBAUTH_SUCCESS)
		return (B_FALSE);

	return (bcmp(lm_resp, passwd, SMBAUTH_LM_RESP_SZ) == 0);
}

static boolean_t
smb_ntlm_password_ok(
    unsigned char *challenge,
    uint32_t clen,
    unsigned char *ntlm_hash,
    unsigned char *passwd,
    unsigned char *session_key)
{
	unsigned char ntlm_resp[SMBAUTH_LM_RESP_SZ];
	int rc;
	boolean_t ok;

	rc = smb_auth_ntlm_response(ntlm_hash, challenge, clen, ntlm_resp);
	if (rc != SMBAUTH_LM_RESP_SZ)
		return (B_FALSE);

	ok = (bcmp(ntlm_resp, passwd, SMBAUTH_LM_RESP_SZ) == 0);
	if (ok && (session_key)) {
		rc = smb_auth_md4(session_key, ntlm_hash, SMBAUTH_HASH_SZ);
		if (rc != SMBAUTH_SUCCESS)
			ok = B_FALSE;
	}
	return (ok);
}

static boolean_t
smb_ntlmv2_password_ok(
    unsigned char *challenge,
    uint32_t clen,
    unsigned char *ntlm_hash,
    unsigned char *passwd,
    int pwdlen,
    char *domain,
    char *username,
    uchar_t *session_key)
{
	unsigned char *clnt_blob;
	int clnt_blob_len;
	unsigned char ntlmv2_hash[SMBAUTH_HASH_SZ];
	unsigned char *ntlmv2_resp;
	boolean_t ok = B_FALSE;
	char *dest[3];
	int i;
	int rc;

	clnt_blob_len = pwdlen - SMBAUTH_HASH_SZ;
	clnt_blob = &passwd[SMBAUTH_HASH_SZ];
	dest[0] = domain;
	if ((dest[1] = strdup(domain)) == NULL)
		return (B_FALSE);
	(void) utf8_strupr(dest[1]);
	dest[2] = "";

	/*
	 * 15.5.2 The NTLMv2 Password Hash, pg. 279, of the "Implementing CIFS"
	 *
	 * The NTLMv2 Hash is created from:
	 * - NTLM hash
	 * - user's username, and
	 * - the name of the logon destination(i.e. the NetBIOS name of either
	 *   the SMB server or NT Domain against which the user is trying to
	 *   authenticate.
	 *
	 * Experiments show this is not exactly the case.
	 * For Windows Server 2003, the domain name needs to be included and
	 * converted to uppercase. For Vista, the domain name needs to be
	 * included also, but leave the case alone.  And in some cases it needs
	 * to be empty. All three variants are tried here.
	 */

	ntlmv2_resp = (unsigned char *)malloc(SMBAUTH_HASH_SZ + clnt_blob_len);
	if (ntlmv2_resp == NULL) {
		free(dest[1]);
		return (B_FALSE);
	}

	for (i = 0; i < (sizeof (dest) / sizeof (char *)); i++) {
		if (smb_auth_ntlmv2_hash(ntlm_hash, username, dest[i],
		    ntlmv2_hash) != SMBAUTH_SUCCESS)
			break;

		if (smb_auth_v2_response(ntlmv2_hash, challenge,
		    clen, clnt_blob, clnt_blob_len, ntlmv2_resp) < 0)
			break;

		ok = (bcmp(passwd, ntlmv2_resp, pwdlen) == 0);
		if (ok && session_key) {
			rc = SMBAUTH_HMACT64(ntlmv2_resp,
			    SMBAUTH_HASH_SZ, ntlmv2_hash,
			    SMBAUTH_SESSION_KEY_SZ, session_key);
			if (rc != SMBAUTH_SUCCESS) {
				ok = B_FALSE;
			}
			break;
		}
	}

	free(dest[1]);
	free(ntlmv2_resp);
	return (ok);
}

static boolean_t
smb_lmv2_password_ok(
    unsigned char *challenge,
    uint32_t clen,
    unsigned char *ntlm_hash,
    unsigned char *passwd,
    char *domain,
    char *username)
{
	unsigned char *clnt_challenge;
	unsigned char ntlmv2_hash[SMBAUTH_HASH_SZ];
	unsigned char lmv2_resp[SMBAUTH_LM_RESP_SZ];
	boolean_t ok = B_FALSE;
	char *dest[3];
	int i;

	clnt_challenge = &passwd[SMBAUTH_HASH_SZ];
	dest[0] = domain;
	if ((dest[1] = strdup(domain)) == NULL)
		return (B_FALSE);
	(void) utf8_strupr(dest[1]);
	dest[2] = "";

	/*
	 * 15.5.2 The NTLMv2 Password Hash, pg. 279, of the "Implementing CIFS"
	 *
	 * The NTLMv2 Hash is created from:
	 * - NTLM hash
	 * - user's username, and
	 * - the name of the logon destination(i.e. the NetBIOS name of either
	 *   the SMB server or NT Domain against which the suer is trying to
	 *   authenticate.
	 *
	 * Experiments show this is not exactly the case.
	 * For Windows Server 2003, the domain name needs to be included and
	 * converted to uppercase. For Vista, the domain name needs to be
	 * included also, but leave the case alone.  And in some cases it needs
	 * to be empty. All three variants are tried here.
	 */

	for (i = 0; i < (sizeof (dest) / sizeof (char *)); i++) {
		if (smb_auth_ntlmv2_hash(ntlm_hash, username, dest[i],
		    ntlmv2_hash) != SMBAUTH_SUCCESS)
			break;

		if (smb_auth_v2_response(ntlmv2_hash, challenge,
		    clen, clnt_challenge, SMBAUTH_V2_CLNT_CHALLENGE_SZ,
		    lmv2_resp) < 0)
			break;

		ok = (bcmp(passwd, lmv2_resp, SMBAUTH_LM_RESP_SZ) == 0);
		if (ok)
			break;
	}

	free(dest[1]);
	return (ok);
}

/*
 * smb_auth_validate_lm
 *
 * Validates given LM/LMv2 client response, passed in passwd arg, against
 * stored user's password, passed in smbpw
 *
 * If LM level <=3 server accepts LM responses, otherwise LMv2
 */
boolean_t
smb_auth_validate_lm(
    unsigned char *challenge,
    uint32_t clen,
    smb_passwd_t *smbpw,
    unsigned char *passwd,
    int pwdlen,
    char *domain,
    char *username)
{
	boolean_t ok = B_FALSE;
	int64_t lmlevel;

	if (pwdlen != SMBAUTH_LM_RESP_SZ)
		return (B_FALSE);

	if (smb_config_getnum(SMB_CI_LM_LEVEL, &lmlevel) != SMBD_SMF_OK)
		return (B_FALSE);

	if (lmlevel <= 3) {
		ok = smb_lm_password_ok(challenge, clen, smbpw->pw_lmhash,
		    passwd);
	}

	if (!ok)
		ok = smb_lmv2_password_ok(challenge, clen, smbpw->pw_nthash,
		    passwd, domain, username);

	return (ok);
}

/*
 * smb_auth_validate_nt
 *
 * Validates given NTLM/NTLMv2 client response, passed in passwd arg, against
 * stored user's password, passed in smbpw
 *
 * If LM level <=4 server accepts NTLM/NTLMv2 responses, otherwise only NTLMv2
 */
boolean_t
smb_auth_validate_nt(
    unsigned char *challenge,
    uint32_t clen,
    smb_passwd_t *smbpw,
    unsigned char *passwd,
    int pwdlen,
    char *domain,
    char *username,
    uchar_t *session_key)
{
	int64_t lmlevel;
	boolean_t ok;

	if (smb_config_getnum(SMB_CI_LM_LEVEL, &lmlevel) != SMBD_SMF_OK)
		return (B_FALSE);

	if ((lmlevel == 5) && (pwdlen <= SMBAUTH_LM_RESP_SZ))
		return (B_FALSE);

	if (pwdlen > SMBAUTH_LM_RESP_SZ)
		ok = smb_ntlmv2_password_ok(challenge, clen,
		    smbpw->pw_nthash, passwd, pwdlen,
		    domain, username, session_key);
	else
		ok = smb_ntlm_password_ok(challenge, clen,
		    smbpw->pw_nthash, passwd, session_key);

	return (ok);
}
