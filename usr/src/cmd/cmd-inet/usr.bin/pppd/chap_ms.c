/*
 * chap_ms.c - Microsoft MS-CHAP compatible implementation.
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1995 Eric Rosenquist, Strata Software Limited.
 * http://www.strataware.com/
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Eric Rosenquist.  The name of the author may not be used to
 * endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * This module implements MS-CHAPv1 (RFC 2433) and MS-CHAPv2 (RFC 2759).
 *
 * Modifications by Lauri Pesonen / lpesonen@clinet.fi, april 1997
 *
 *   Implemented LANManager type password response to MS-CHAP challenges.
 *   Now pppd provides both NT style and LANMan style blocks, and the
 *   prefered is set by option "ms-lanman". Default is to use NT.
 *   The hash text (StdText) was taken from Win95 RASAPI32.DLL.
 *
 *   You should also use DOMAIN\\USERNAME as described in README.MSCHAP80
 *
 * Modifications by James Carlson / james.d.carlson@sun.com, June 1st, 2000.
 *
 *	Added MS-CHAPv2 support.
 */

#if defined(CHAPMS) || defined(CHAPMSV2)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#ifdef CHAPMSV2
#include "sha1.h"
#endif

#ifndef USE_CRYPT
#include <des.h>
#endif

#include "pppd.h"
#include "chap.h"
#include "chap_ms.h"
#include "md4.h"

typedef struct {
    u_char LANManResp[24];
    u_char NTResp[24];
    u_char UseNT;		/* If 1, ignore the LANMan response field */
} MS_ChapResponse;
/* We use MS_CHAP_RESPONSE_LEN, rather than sizeof(MS_ChapResponse),
   in case this struct gets padded. */

typedef struct {
	u_char PeerChallenge[16];
	u_char MustBeZero[8];
	u_char NTResp[24];
	u_char Flags;		/* Should be zero (Win98 sends 04) */
} MS_Chapv2Response;
/* We use MS_CHAPV2_RESPONSE_LEN, rather than sizeof(MS_Chapv2Response),
   in case this struct gets padded. */

static void	ChallengeResponse __P((u_char *, u_char *, u_char *));
static void	DesEncrypt __P((u_char *, u_char *, u_char *));
static void	MakeKey __P((u_char *, u_char *));
static u_char	Get7Bits __P((u_char *, int));
#ifdef CHAPMS
static void	ChapMS_NT __P((u_char *, char *, int, MS_ChapResponse *));
#ifdef MSLANMAN
static void	ChapMS_LANMan __P((u_char *, char *, int, MS_ChapResponse *));
#endif
#endif
#ifdef CHAPMSV2
static void	ChapMSv2_NT __P((char *, u_char *, char *, int,
    MS_Chapv2Response *));
#endif

#ifdef USE_CRYPT
static void	Expand __P((u_char *, char *));
static void	Collapse __P((char *, u_char *));
#endif

#if defined(MSLANMAN) && defined(CHAPMS)
bool	ms_lanman = 0;    	/* Use LanMan password instead of NT */
			  	/* Has meaning only with MS-CHAP challenges */
#endif

#ifdef CHAPMSV2
/* Specially-formatted Microsoft CHAP response message. */
static char status_message[256];
#endif

static void
ChallengeResponse(challenge, pwHash, response)
    u_char *challenge;	/* IN   8 octets */
    u_char *pwHash;	/* IN  16 octets */
    u_char *response;	/* OUT 24 octets */
{
    u_char    ZPasswordHash[21];

    BZERO(ZPasswordHash, sizeof(ZPasswordHash));
    BCOPY(pwHash, ZPasswordHash, MD4_SIGNATURE_SIZE);

#if 0
    dbglog("ChallengeResponse - ZPasswordHash %.*B",
	   sizeof(ZPasswordHash), ZPasswordHash);
#endif

    DesEncrypt(challenge, ZPasswordHash +  0, response + 0);
    DesEncrypt(challenge, ZPasswordHash +  7, response + 8);
    DesEncrypt(challenge, ZPasswordHash + 14, response + 16);

#if 0
    dbglog("ChallengeResponse - response %.24B", response);
#endif
}


#ifdef USE_CRYPT
static void
DesEncrypt(clear, key, cipher)
    u_char *clear;	/* IN  8 octets */
    u_char *key;	/* IN  7 octets */
    u_char *cipher;	/* OUT 8 octets */
{
    u_char des_key[8];
    char crypt_key[66];
    char des_input[66];

    MakeKey(key, des_key);

    Expand(des_key, crypt_key);
    setkey(crypt_key);

#if 0
    CHAPDEBUG((LOG_INFO, "DesEncrypt: 8 octet input : %.8B", clear));
#endif

    Expand(clear, des_input);
    encrypt(des_input, 0);
    Collapse(des_input, cipher);

#if 0
    CHAPDEBUG((LOG_INFO, "DesEncrypt: 8 octet output: %.8B", cipher));
#endif
}

#else /* USE_CRYPT */

static void
DesEncrypt(clear, key, cipher)
    u_char *clear;	/* IN  8 octets */
    u_char *key;	/* IN  7 octets */
    u_char *cipher;	/* OUT 8 octets */
{
    des_cblock		des_key;
    des_key_schedule	key_schedule;

    MakeKey(key, des_key);

    des_set_key(&des_key, key_schedule);

#if 0
    CHAPDEBUG((LOG_INFO, "DesEncrypt: 8 octet input : %.8B", clear));
#endif

    des_ecb_encrypt((des_cblock *)clear, (des_cblock *)cipher, key_schedule, 1);

#if 0
    CHAPDEBUG((LOG_INFO, "DesEncrypt: 8 octet output: %.8B", cipher));
#endif
}

#endif /* USE_CRYPT */


static u_char Get7Bits(input, startBit)
    u_char *input;
    int startBit;
{
    register unsigned int	word;

    word  = (unsigned)input[startBit / 8] << 8;
    word |= (unsigned)input[startBit / 8 + 1];

    word >>= 15 - (startBit % 8 + 7);

    return word & 0xFE;
}

#ifdef USE_CRYPT

/* in == 8-byte string (expanded version of the 56-bit key)
 * out == 64-byte string where each byte is either 1 or 0
 * Note that the low-order "bit" is always ignored by by setkey()
 */
static void Expand(in, out)
    u_char *in;
    char *out;
{
        int j, c;
        int i;

        for(i = 0; i < 64; in++){
		c = *in;
                for(j = 7; j >= 0; j--)
                        *out++ = (c >> j) & 01;
                i += 8;
        }
}

/* The inverse of Expand
 */
static void Collapse(in, out)
    char *in;
    u_char *out;
{
        int j;
        int i;
	unsigned int c;

	for (i = 0; i < 64; i += 8, out++) {
	    c = 0;
	    for (j = 7; j >= 0; j--, in++)
		c |= *(u_char *)in << j;
	    *out = c & 0xff;
	}
}
#endif

static void MakeKey(key, des_key)
    u_char *key;	/* IN  56 bit DES key missing parity bits */
    u_char *des_key;	/* OUT 64 bit DES key with parity bits added */
{
    des_key[0] = Get7Bits(key,  0);
    des_key[1] = Get7Bits(key,  7);
    des_key[2] = Get7Bits(key, 14);
    des_key[3] = Get7Bits(key, 21);
    des_key[4] = Get7Bits(key, 28);
    des_key[5] = Get7Bits(key, 35);
    des_key[6] = Get7Bits(key, 42);
    des_key[7] = Get7Bits(key, 49);

#ifndef USE_CRYPT
    des_set_odd_parity((des_cblock *)des_key);
#endif

#if 0
    CHAPDEBUG((LOG_INFO, "MakeKey: 56-bit input : %.7B", key));
    CHAPDEBUG((LOG_INFO, "MakeKey: 64-bit output: %.8B", des_key));
#endif
}

#ifdef CHAPMS
static void
ChapMS_NT(rchallenge, secret, secret_len, response)
    u_char *rchallenge;
    char *secret;
    int secret_len;
    MS_ChapResponse    *response;
{
    int			i;
#if defined(__NetBSD__) || defined(HAVE_LIBMD)
    /* NetBSD uses the libc md4 routines which take bytes instead of bits */
    int			mdlen = secret_len * 2;
#else
    int			mdlen = secret_len * 2 * 8;
#endif
    MD4_CTX		md4Context;
    u_char		hash[MD4_SIGNATURE_SIZE];
    u_char		unicodePassword[MAX_NT_PASSWORD * 2];

    /* Initialize the Unicode version of the secret (== password). */
    /* This implicitly supports 8-bit ISO8859/1 characters. */
    BZERO(unicodePassword, sizeof(unicodePassword));
    for (i = 0; i < secret_len; i++)
	unicodePassword[i * 2] = (u_char)secret[i];

    MD4Init(&md4Context);
    MD4Update(&md4Context, unicodePassword, mdlen);

    MD4Final(hash, &md4Context); 	/* Tell MD4 we're done */

    ChallengeResponse(rchallenge, hash, response->NTResp);
}

#ifdef MSLANMAN
static u_char *StdText = (u_char *)"KGS!@#$%"; /* key from rasapi32.dll */

static void
ChapMS_LANMan(rchallenge, secret, secret_len, response)
    u_char *rchallenge;
    char *secret;
    int secret_len;
    MS_ChapResponse	*response;
{
    int			i;
    u_char		UcasePassword[MAX_NT_PASSWORD]; /* max is actually 14 */
    u_char		PasswordHash[MD4_SIGNATURE_SIZE];

    /* LANMan password is case insensitive */
    BZERO(UcasePassword, sizeof(UcasePassword));
    for (i = 0; i < secret_len; i++)
	UcasePassword[i] = (u_char)(
	    islower(secret[i]) ? toupper(secret[i]) : secret[i]);
    DesEncrypt( StdText, UcasePassword + 0, PasswordHash + 0 );
    DesEncrypt( StdText, UcasePassword + 7, PasswordHash + 8 );
    ChallengeResponse(rchallenge, PasswordHash, response->LANManResp);
}
#endif

void
ChapMS(cstate, rchallenge, rchallenge_len, secret, secret_len)
    chap_state *cstate;
    u_char *rchallenge;
    int rchallenge_len;
    char *secret;
    int secret_len;
{
    MS_ChapResponse	response;

    if (rchallenge_len < 8) {
	    cstate->resp_length = 0;
	    return;
    }

#if 0
    CHAPDEBUG((LOG_INFO, "ChapMS: secret is '%.*s'", secret_len, secret));
#endif
    BZERO(&response, sizeof(response));

    /* Calculate both always */
    ChapMS_NT(rchallenge, secret, secret_len, &response);

#ifdef MSLANMAN
    ChapMS_LANMan(rchallenge, secret, secret_len, &response);

    /* prefered method is set by option  */
    response.UseNT = !ms_lanman;
#else
    response.UseNT = 1;
#endif

    BCOPY(&response, cstate->response, MS_CHAP_RESPONSE_LEN);
    cstate->resp_length = MS_CHAP_RESPONSE_LEN;
}

static int
ChapMSStatus(cstate, flag)
    chap_state *cstate;
    int flag;
{
    if (flag != 0) {
	cstate->stat_message = NULL;
	cstate->stat_length = 0;
    } else {
	cstate->stat_message = "E=691 R=0 M=\"Authentication failed\"";
	cstate->stat_length = strlen(cstate->stat_message);
    }
    return (flag);
}

int
ChapMSValidate(cstate, response, response_len, secret, secret_len)
    chap_state *cstate;
    u_char *response;
    int response_len;
    char *secret;
    int secret_len;
{
    MS_ChapResponse ckresp;

    if (response_len < MS_CHAP_RESPONSE_LEN || cstate->chal_len < 8)
	return (0);

    BZERO(&ckresp, sizeof(ckresp));

    if (response[MS_CHAP_RESPONSE_LEN-1]) {
	ChapMS_NT(cstate->challenge, secret, secret_len, &ckresp);
	return (ChapMSStatus(cstate, memcmp(ckresp.NTResp, response+24,
	    24) == 0));
    }

#ifdef MSLANMAN
    ChapMS_LANMan(cstate->challenge, secret, secret_len, &ckresp);
    return (ChapMSStatus(cstate,
	memcmp(ckresp.LANManResp, response, 24) == 0));
#else
    return (ChapMSStatus(cstate, 0));
#endif
}
#endif /* CHAPMS */

#ifdef CHAPMSV2
static void
ChallengeHash(peerchallenge, authenticatorchallenge, username, challenge)
u_char *peerchallenge, *authenticatorchallenge, *challenge;
char *username;
{
    uint8_t digest[20];
    SHA1_CTX sha1Context;
    char *cp;

    SHA1Init(&sha1Context);
    SHA1Update(&sha1Context, peerchallenge, 16);
    SHA1Update(&sha1Context, authenticatorchallenge, 16);

    /*
     * Only the user name (as presented by the peer and
     * excluding any prepended domain name)
     * is used as input to SHAUpdate().
     */
    if ((cp = strchr(username,'\\')) != NULL)
	username = cp;

    SHA1Update(&sha1Context, (uint8_t *)username, strlen(username));
    SHA1Final(digest, &sha1Context);
    BCOPY(digest, challenge, 8);
}

static void
ChapMSv2_NT(username, rchallenge, secret, secret_len, response)
    char *username;
    u_char *rchallenge;
    char *secret;
    int secret_len;
    MS_Chapv2Response    *response;
{
    int			i;
#if defined(__NetBSD__) || defined(HAVE_LIBMD)
    /* NetBSD uses the libc md4 routines that take bytes instead of bits */
    int			mdlen = secret_len * 2;
#else
    int			mdlen = secret_len * 2 * 8;
#endif
    MD4_CTX		md4Context;
    u_char		hash[MD4_SIGNATURE_SIZE];
    u_char		challenge[8];
    u_char		unicodePassword[MAX_NT_PASSWORD * 2];

    /* Initialize the Unicode version of the secret (== password). */
    /* This implicitly supports 8-bit ISO8859/1 characters. */
    BZERO(unicodePassword, sizeof(unicodePassword));
    for (i = 0; i < secret_len && i < MAX_NT_PASSWORD; i++)
	if ((unicodePassword[i * 2] = (u_char)secret[i]) == '\0')
	    break;

    ChallengeHash(response->PeerChallenge, rchallenge, username, challenge);

    MD4Init(&md4Context);
    MD4Update(&md4Context, unicodePassword, mdlen);

    MD4Final(hash, &md4Context); 	/* Tell MD4 we're done */

    ChallengeResponse(challenge, hash, response->NTResp);
}

void
ChapMSv2(cstate, rchallenge, rchallenge_len, secret, secret_len)
    chap_state *cstate;
    u_char *rchallenge;
    int rchallenge_len;
    char *secret;
    int secret_len;
{
    MS_Chapv2Response	response;
    u_char *ptr;
    int i;

    if (rchallenge_len < 8) {
	cstate->resp_length = 0;
	return;
    }

    BZERO(&response, sizeof(response));

    ptr = response.PeerChallenge;
    for (i = 0; i < 16; i++)
	*ptr++ = (u_char) (drand48() * 0xff);

    ChapMSv2_NT(cstate->resp_name, rchallenge, secret, secret_len, &response);

    BCOPY(&response, cstate->response, MS_CHAPV2_RESPONSE_LEN);
    cstate->resp_length = MS_CHAPV2_RESPONSE_LEN;
}

static void
ChapMSv2Success(cstate, msresp, authchall, rhostname, secret, secret_len)
    chap_state *cstate;
    MS_Chapv2Response *msresp;
    u_char *authchall;
    char *rhostname, *secret;
    int secret_len;
{
    static const u_char Magic1[39] = "Magic server to client signing constant";
    static const u_char Magic2[41] =
	"Pad to make it do more than one iteration";
#if defined(__NetBSD__) || defined(HAVE_LIBMD)
    /* NetBSD uses the libc md4 routines that take bytes instead of bits */
    int mdlen = 1;
#else
    int mdlen = 8;
#endif
    u_char unicodePassword[MAX_NT_PASSWORD * 2];
    MD4_CTX md4Context;
    u_char hash[MD4_SIGNATURE_SIZE];
    u_char hashhash[MD4_SIGNATURE_SIZE];
    SHA1_CTX sha1Context;
    uint8_t digest[20];
    u_char challenge[8];
    char *cp;
    static const char hexdig[] = "0123456789ABCDEF";
    int i;

    /* Initialize the Unicode version of the secret (== password). */
    /* This implicitly supports 8-bit ISO8859/1 characters. */
    BZERO(unicodePassword, sizeof(unicodePassword));
    for (i = 0; i < secret_len && i < MAX_NT_PASSWORD; i++)
	if ((unicodePassword[i * 2] = (u_char)secret[i]) == '\0')
	    break;

    /* Hash the password with MD4 */
    MD4Init(&md4Context);
    MD4Update(&md4Context, unicodePassword, secret_len * 2 * mdlen);
    MD4Final(hash, &md4Context);

    /* Now hash the hash */
    MD4Init(&md4Context);
    MD4Update(&md4Context, hash, MD4_SIGNATURE_SIZE * mdlen);
    MD4Final(hashhash, &md4Context);

    SHA1Init(&sha1Context);
    SHA1Update(&sha1Context, hashhash, MD4_SIGNATURE_SIZE);
    SHA1Update(&sha1Context, msresp->NTResp, sizeof (msresp->NTResp));
    SHA1Update(&sha1Context, Magic1, 39);
    SHA1Final(digest, &sha1Context);

    ChallengeHash(msresp->PeerChallenge, authchall, rhostname, challenge);

    SHA1Init(&sha1Context);
    SHA1Update(&sha1Context, digest, 20);
    SHA1Update(&sha1Context, challenge, 8);
    SHA1Update(&sha1Context, Magic2, 41);
    SHA1Final(digest, &sha1Context);

    cp = status_message;
    *cp++ = 'S';
    *cp++ = '=';
    for (i = 0; i < 20; i++) {
	*cp++ = hexdig[digest[i]>>4];
	*cp++ = hexdig[digest[i]&15];
    }
    /*
     * RFC 2759 says that a M=<string> greeting message is possible
     * here.  It lies.  Any such greeting causes Windoze-98 to give
     * error number 742, "Dial-Up Networking was unable to complete
     * the connection.  The computer you're dialing in to does not
     * support the data encryption requirements specified.  Please
     * check your encryption settings in the properties of the
     * connection.  If this problem persists, contact your network
     * administrator."
     */
    *cp = '\0';
#if 0
    slprintf(cp, sizeof (status_message) - (cp-status_message),
	"M=\"Welcome to %s.\"", hostname);
#endif
    cstate->stat_message = status_message;
    cstate->stat_length = strlen(status_message);
}

int
ChapMSv2Validate(cstate, rhostname, response, response_len, secret, secret_len)
    chap_state *cstate;
    char *rhostname;
    u_char *response;
    int response_len;
    char *secret;
    int secret_len;
{
    MS_Chapv2Response ckresp;

    if (response_len < MS_CHAPV2_RESPONSE_LEN ||
	/* response[MS_CHAPV2_RESPONSE_LEN-1] != 0 || */cstate->chal_len < 8) {
	cstate->stat_message = NULL;
	cstate->stat_length = 0;
	return 0;
    }

    BZERO(&ckresp, sizeof(ckresp));

    BCOPY(response, ckresp.PeerChallenge, 16);

    ChapMSv2_NT(rhostname, cstate->challenge, secret, secret_len, &ckresp);
    if (memcmp(ckresp.NTResp, response+24, 24) != 0) {
	cstate->stat_message = "E=691 R=0 C=11111111111111111111111111111111 V=3 M=\"Authentication failed\"";
	cstate->stat_length = strlen(cstate->stat_message);
	return (0);
    }
    ChapMSv2Success(cstate, (MS_Chapv2Response *)response, cstate->challenge,
	rhostname, secret, secret_len);
    return (1);
}
#endif /* CHAPMSV2 */

#endif /* CHAPMS or CHAPMSV2 */
