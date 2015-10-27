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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <strings.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/md5.h>
#include <smbsrv/string.h>
#include <smbsrv/libsmb.h>
#include <netsmb/spnego.h>	/* libsmbfs */
#include <assert.h>

#define	NTLM_CHAL_SZ	SMBAUTH_CHAL_SZ	/* challenge size */

/*
 * Compute the combined (server+client) challenge per. [MS-NLMP 3.3.1]
 * MD5(concat(ServerChallenge,ClientChallenge))
 */
void
smb_auth_ntlm2_mkchallenge(char *result,
	const char *srv_chal, const char *clnt_chal)
{
	MD5_CTX context;
	uchar_t challenges[2 * NTLM_CHAL_SZ];
	uchar_t digest[SMBAUTH_HASH_SZ];

	/*
	 * challenges = ConcatenationOf(ServerChallenge, ClientChallenge)
	 */
	(void) memcpy(challenges, srv_chal, NTLM_CHAL_SZ);
	(void) memcpy(challenges + NTLM_CHAL_SZ, clnt_chal, NTLM_CHAL_SZ);

	/*
	 * digest = MD5(challenges)
	 */
	MD5Init(&context);
	MD5Update(&context, challenges, sizeof (challenges));
	MD5Final(digest, &context);

	/*
	 * result = digest[0..7]
	 */
	(void) memcpy(result, digest, NTLM_CHAL_SZ);
}

void
smb_auth_ntlm2_kxkey(unsigned char *result, const char *srv_chal,
	const char *clnt_chal, unsigned char *ssn_base_key)
{
	uchar_t challenges[2 * NTLM_CHAL_SZ];

	/*
	 * challenges = ConcatenationOf(ServerChallenge, ClientChallenge)
	 */
	(void) memcpy(challenges, srv_chal, NTLM_CHAL_SZ);
	(void) memcpy(challenges + NTLM_CHAL_SZ, clnt_chal, NTLM_CHAL_SZ);

	/* HMAC_MD5(SessionBaseKey, concat(...)) */
	/* SMBAUTH_HMACT64 args: D, Dsz, K, Ksz, digest */
	(void) SMBAUTH_HMACT64(challenges, sizeof (challenges),
	    ssn_base_key, SMBAUTH_HASH_SZ, result);
}

/*
 * smb_auth_qnd_unicode
 *
 * Quick and dirty unicode conversion!
 * Returns the length of dst in bytes.
 */
int
smb_auth_qnd_unicode(smb_wchar_t *dst, const char *src, int length)
{
	int i;
	unsigned int count;
	smb_wchar_t new_char;

	if ((count = oemtoucs(dst, src, length, OEM_CPG_1252)) == 0) {
		for (i = 0; i < length; ++i) {
			new_char = (smb_wchar_t)src[i] & 0xff;
			dst[i] = LE_IN16(&new_char);
		}
		dst[i] = 0;
		count = length;
	}

	return (count * sizeof (smb_wchar_t));
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
		if (smb_isascii(*p)) {
			*p = smb_toupper(*p);
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
smb_auth_lm_hash(const char *password, unsigned char *lm_hash)
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
    unsigned char *challenge, /* NTLM_CHAL_SZ */
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
	    challenge, NTLM_CHAL_SZ));
}

/*
 * smb_auth_ntlm_hash
 *
 * Make NTLM Hash (using MD4) from the given password.
 * The result will contain a 16-byte NTLM hash.
 */
int
smb_auth_ntlm_hash(const char *password, unsigned char *hash)
{
	smb_wchar_t *unicode_password;
	int length, unicode_len;
	int rc;

	if (password == NULL || hash == NULL)
		return (SMBAUTH_FAILURE);

	length = strlen(password);
	unicode_len = (length + 1) * sizeof (smb_wchar_t);
	unicode_password = malloc(unicode_len);

	if (unicode_password == NULL)
		return (SMBAUTH_FAILURE);

	length = smb_auth_qnd_unicode(unicode_password, password, length);
	rc = smb_auth_md4(hash, (unsigned char *)unicode_password, length);

	(void) memset(unicode_password, 0, unicode_len);
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
    unsigned char *challenge, /* NTLM_CHAL_SZ */
    unsigned char *ntlm_rsp)
{
	unsigned char S21[21];

	bcopy(hash, S21, SMBAUTH_HASH_SZ);
	bzero(&S21[SMBAUTH_HASH_SZ], 5);
	if (smb_auth_DES((unsigned char *)ntlm_rsp, SMBAUTH_LM_RESP_SZ,
	    S21, 21, challenge, NTLM_CHAL_SZ) == SMBAUTH_FAILURE)
		return (0);
	return (SMBAUTH_LM_RESP_SZ);
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
	smb_wchar_t *data;
	int data_len;
	unsigned char *buf;
	int rc;

	if (username == NULL || ntdomain == NULL)
		return (SMBAUTH_FAILURE);

	(void) smb_strupr(username);

	data_len = strlen(username) + strlen(ntdomain);
	buf = (unsigned char *)malloc((data_len + 1) * sizeof (char));
	if (buf == NULL)
		return (SMBAUTH_FAILURE);

	(void) snprintf((char *)buf, data_len + 1, "%s%s", username, ntdomain);
	data = (smb_wchar_t *)malloc((data_len + 1) * sizeof (smb_wchar_t));
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
	unsigned char *srv_challenge, /* NTLM_CHAL_SZ */
	unsigned char *clnt_data, int clen,
	unsigned char *v2_rsp)
{
	unsigned char *hmac_data;
	int slen = NTLM_CHAL_SZ;

	hmac_data = malloc(NTLM_CHAL_SZ + clen);
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


static boolean_t
smb_lm_password_ok(
    unsigned char *challenge,
    unsigned char *lm_hash,
    unsigned char *lm_resp)
{
	unsigned char ok_resp[SMBAUTH_LM_RESP_SZ];
	int rc;

	rc = smb_auth_lm_response(lm_hash, challenge, ok_resp);
	if (rc != SMBAUTH_SUCCESS)
		return (B_FALSE);

	return (bcmp(ok_resp, lm_resp, SMBAUTH_LM_RESP_SZ) == 0);
}

static boolean_t
smb_ntlm_password_ok(
    unsigned char *challenge,
    unsigned char *ntlm_hash,
    unsigned char *nt_resp,
    unsigned char *session_key)
{
	unsigned char ok_resp[SMBAUTH_LM_RESP_SZ];
	int rc;
	boolean_t ok;

	rc = smb_auth_ntlm_response(ntlm_hash, challenge, ok_resp);
	if (rc != SMBAUTH_LM_RESP_SZ)
		return (B_FALSE);

	ok = (bcmp(ok_resp, nt_resp, SMBAUTH_LM_RESP_SZ) == 0);
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
	(void) smb_strupr(dest[1]);
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
		    clnt_blob, clnt_blob_len, ntlmv2_resp) < 0)
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
    unsigned char *srv_challenge,
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
	(void) smb_strupr(dest[1]);
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

		if (smb_auth_v2_response(ntlmv2_hash, srv_challenge,
		    clnt_challenge, SMBAUTH_CHAL_SZ,
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
 * smb_auth_validate
 *
 * Validates given NTLMv2 (or NTLM, LMv2, LM) client responses against
 * the stored user's password, passed in smbpw.  Try those in the order
 * strongest to weakest, stopping at a point determined by the configured
 * lmauth_level (LM Compatibility Level).
 */
boolean_t
smb_auth_validate(
    smb_passwd_t *smbpw,
    char *domain,
    char *username,
    unsigned char *challenge,
    uint_t clen,
    unsigned char *nt_resp,
    uint_t nt_len,
    unsigned char *lm_resp,
    uint_t lm_len,
    uchar_t *session_key)
{
	int64_t lmlevel;
	boolean_t ok = B_FALSE;

	if (smb_config_getnum(SMB_CI_LM_LEVEL, &lmlevel) != SMBD_SMF_OK)
		return (B_FALSE);

	if (lmlevel > 5)
		return (B_FALSE);

	if (clen != NTLM_CHAL_SZ)
		return (B_FALSE);

	/*
	 * Accept NTLMv2 at any LM level (0-5).
	 */
	if (nt_len > SMBAUTH_LM_RESP_SZ) {
		ok = smb_ntlmv2_password_ok(challenge,
		    smbpw->pw_nthash, nt_resp, nt_len,
		    domain, username, session_key);
		if (ok)
			return (ok);
	}

	if (lmlevel == 5)
		return (B_FALSE);

	/*
	 * Accept NTLM at levels 0-4
	 */
	if (nt_len == SMBAUTH_LM_RESP_SZ) {
		ok = smb_ntlm_password_ok(challenge, smbpw->pw_nthash,
		    nt_resp, session_key);
		if (ok)
			return (ok);
	}

	if (lmlevel == 4)
		return (B_FALSE);


	/*
	 * Accept LM/LMv2 auth at levels 0-3
	 */
	if (lm_len != SMBAUTH_LM_RESP_SZ)
		return (B_FALSE);
	if (session_key)
		(void) smb_auth_md4(session_key, smbpw->pw_nthash,
		    SMBAUTH_HASH_SZ);
	ok = smb_lmv2_password_ok(challenge, smbpw->pw_nthash,
	    lm_resp, domain, username);
	if (ok)
		return (ok);
	ok = smb_lm_password_ok(challenge, smbpw->pw_lmhash, lm_resp);
	if (ok)
		return (ok);

	return (B_FALSE);
}

/*
 * smb_gen_random_passwd(buf, len)
 * Generate a random password of length len-1, and store it in buf,
 * null terminated.  This is used as a machine account password,
 * which we set when we join a domain.
 *
 * [MS-DISO] A machine password is an ASCII string of randomly chosen
 * characters. Each character's ASCII code is between 32 and 122 inclusive.
 * That's space through 'z'.
 */

int
smb_gen_random_passwd(char *buf, size_t len)
{
	const uchar_t start = ' ';
	const uchar_t modulus = 'z' - ' ' + 1;
	uchar_t t;
	int i;

	/* Last byte is the null. */
	len--;

	/* Temporarily put random data in the caller's buffer. */
	randomize(buf, len);

	/* Convert the random data to printable characters. */
	for (i = 0; i < len; i++) {
		/* need unsigned math */
		t = (uchar_t)buf[i];
		t = (t % modulus) + start;
		assert(' ' <= t && t <= 'z');
		buf[i] = (char)t;
	}

	buf[len] = '\0';

	return (0);
}
