/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/* DIGEST-MD5 SASL plugin
 * Rob Siemborski
 * Tim Martin
 * Alexey Melnikov
 * $Id: digestmd5.c,v 1.153 2003/03/30 22:17:06 leg Exp $
 */
/*
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef macintosh
#include <sys/types.h>
#include <sys/stat.h>
#endif
#include <fcntl.h>
#include <ctype.h>

/* DES support */
#ifdef WITH_DES
# ifdef WITH_SSL_DES
#  include <openssl/des.h>
# else /* system DES library */
#  include <des.h>
# endif
#endif /* WITH_DES */

#ifdef WIN32
# include <winsock.h>
#else /* Unix */
# include <netinet/in.h>
#endif /* WIN32 */

#ifdef _SUN_SDK_
#include <unistd.h>
#endif /* _SUN_SDK_ */

#include <sasl.h>
#include <saslplug.h>

#include "plugin_common.h"

#if defined _SUN_SDK_  && defined USE_UEF
#include <security/cryptoki.h>
static int uef_init(const sasl_utils_t *utils);
#endif /* _SUN_SDK_ && USE_UEF */

#ifndef WIN32
extern int strcasecmp(const char *s1, const char *s2);
#endif /* end WIN32 */

#ifdef macintosh
#include <sasl_md5_plugin_decl.h>
#endif

/* external definitions */

#ifndef _SUN_SDK_
#ifdef sun
/* gotta define gethostname ourselves on suns */
extern int      gethostname(char *, int);
#endif
#endif /* !_SUN_SDK_ */

#define bool int

#ifndef TRUE
#define TRUE  (1)
#define FALSE (0)
#endif

#define DEFAULT_BUFSIZE 0xFFFF

/*****************************  Common Section  *****************************/

#ifndef _SUN_SDK_
static const char plugin_id[] = "$Id: digestmd5.c,v 1.153 2003/03/30 22:17:06 leg Exp $";
#endif /* !_SUN_SDK_ */

/* Definitions */
#define NONCE_SIZE (32)		/* arbitrary */

/* Layer Flags */
#define DIGEST_NOLAYER    (1)
#define DIGEST_INTEGRITY  (2)
#define DIGEST_PRIVACY    (4)

/* defines */
#define HASHLEN 16
typedef unsigned char HASH[HASHLEN + 1];
#define HASHHEXLEN 32
typedef unsigned char HASHHEX[HASHHEXLEN + 1];

#define MAC_SIZE 10
#define MAC_OFFS 2

const char *SEALING_CLIENT_SERVER="Digest H(A1) to client-to-server sealing key magic constant";
const char *SEALING_SERVER_CLIENT="Digest H(A1) to server-to-client sealing key magic constant";

const char *SIGNING_CLIENT_SERVER="Digest session key to client-to-server signing key magic constant";
const char *SIGNING_SERVER_CLIENT="Digest session key to server-to-client signing key magic constant";

#define HT	(9)
#define CR	(13)
#define LF	(10)
#define SP	(32)
#define DEL	(127)

struct context;

/* function definitions for cipher encode/decode */
typedef int cipher_function_t(struct context *,
			      const char *,
			      unsigned,
			      unsigned char[],
			      char *,
			      unsigned *);

#ifdef _SUN_SDK_
typedef int cipher_init_t(struct context *, char [16],
                                            char [16]);
#else
typedef int cipher_init_t(struct context *, unsigned char [16],
                                            unsigned char [16]);
#endif /* _SUN_SDK_ */

typedef void cipher_free_t(struct context *);

enum Context_type { SERVER = 0, CLIENT = 1 };

typedef struct cipher_context cipher_context_t;

/* cached auth info used for fast reauth */
typedef struct reauth_entry {
    char *authid;
    char *realm;
    unsigned char *nonce;
    unsigned int nonce_count;
    unsigned char *cnonce;

    union {
	struct {
	    time_t timestamp;
	} s; /* server stuff */

	struct {
	    char *serverFQDN;
	    int protection;
	    struct digest_cipher *cipher;
	    unsigned int server_maxbuf;
	} c; /* client stuff */
    } u;
} reauth_entry_t;

typedef struct reauth_cache {
    /* static stuff */
    enum Context_type i_am;	/* are we the client or server? */
    time_t timeout;
    void *mutex;
    size_t size;

    reauth_entry_t *e;		/* fixed-size hash table of entries */
} reauth_cache_t;

/* context that stores info */
typedef struct context {
    int state;			/* state in the authentication we are in */
    enum Context_type i_am;	/* are we the client or server? */

    reauth_cache_t *reauth;

    char *authid;
    char *realm;
    unsigned char *nonce;
    unsigned int nonce_count;
    unsigned char *cnonce;

    char *response_value;

    unsigned int seqnum;
    unsigned int rec_seqnum;	/* for checking integrity */

    HASH Ki_send;
    HASH Ki_receive;

    HASH HA1;		/* Kcc or Kcs */

    /* copy of utils from the params structures */
    const sasl_utils_t *utils;

    /* For general use */
    char *out_buf;
    unsigned out_buf_len;

    /* for encoding/decoding */
    buffer_info_t *enc_in_buf;
    char *encode_buf, *decode_buf, *decode_once_buf;
    unsigned encode_buf_len, decode_buf_len, decode_once_buf_len;
    char *decode_tmp_buf;
    unsigned decode_tmp_buf_len;
    char *MAC_buf;
    unsigned MAC_buf_len;

    char *buffer;
    char sizebuf[4];
    int cursize;

    /* Layer info */
    unsigned int size; /* Absolute size of buffer */
    unsigned int needsize; /* How much of the size of the buffer is left */

    /* Server MaxBuf for Client or Client MaxBuf For Server */
    /* INCOMING */
    unsigned int in_maxbuf;

    /* if privacy mode is used use these functions for encode and decode */
    cipher_function_t *cipher_enc;
    cipher_function_t *cipher_dec;
    cipher_init_t *cipher_init;
    cipher_free_t *cipher_free;
    struct cipher_context *cipher_enc_context;
    struct cipher_context *cipher_dec_context;
} context_t;

struct digest_cipher {
    char *name;
    sasl_ssf_t ssf;
    int n; /* bits to make privacy key */
    int flag; /* a bitmask to make things easier for us */

    cipher_function_t *cipher_enc;
    cipher_function_t *cipher_dec;
    cipher_init_t *cipher_init;
    cipher_free_t *cipher_free;
};

#ifdef _SUN_SDK_
static const unsigned char *COLON = (unsigned char *)":";
#else
static const unsigned char *COLON = ":";
#endif /* _SUN_SDK_ */

/* Hashes a string to produce an unsigned short */
static unsigned hash(const char *str)
{
    unsigned val = 0;
    int i;

    while (str && *str) {
	i = (int) *str;
	val ^= i;
	val <<= 1;
	str++;
    }

    return val;
}

static void CvtHex(HASH Bin, HASHHEX Hex)
{
    unsigned short  i;
    unsigned char   j;

    for (i = 0; i < HASHLEN; i++) {
	j = (Bin[i] >> 4) & 0xf;
	if (j <= 9)
	    Hex[i * 2] = (j + '0');
	else
	    Hex[i * 2] = (j + 'a' - 10);
	j = Bin[i] & 0xf;
	if (j <= 9)
	    Hex[i * 2 + 1] = (j + '0');
	else
	    Hex[i * 2 + 1] = (j + 'a' - 10);
    }
    Hex[HASHHEXLEN] = '\0';
}

/*
 * calculate request-digest/response-digest as per HTTP Digest spec
 */
void
DigestCalcResponse(const sasl_utils_t * utils,
		   HASHHEX HA1,	/* H(A1) */
		   unsigned char *pszNonce,	/* nonce from server */
		   unsigned int pszNonceCount,	/* 8 hex digits */
		   unsigned char *pszCNonce,	/* client nonce */
		   unsigned char *pszQop,	/* qop-value: "", "auth",
						 * "auth-int" */
		   unsigned char *pszDigestUri,	/* requested URL */
		   unsigned char *pszMethod,
		   HASHHEX HEntity,	/* H(entity body) if qop="auth-int" */
		   HASHHEX Response	/* request-digest or response-digest */
    )
{
    MD5_CTX         Md5Ctx;
    HASH            HA2;
    HASH            RespHash;
    HASHHEX         HA2Hex;
    char ncvalue[10];

    /* calculate H(A2) */
    utils->MD5Init(&Md5Ctx);

    if (pszMethod != NULL) {
	utils->MD5Update(&Md5Ctx, pszMethod, strlen((char *) pszMethod));
    }
    utils->MD5Update(&Md5Ctx, (unsigned char *) COLON, 1);

    /* utils->MD5Update(&Md5Ctx, (unsigned char *) "AUTHENTICATE:", 13); */
    utils->MD5Update(&Md5Ctx, pszDigestUri, strlen((char *) pszDigestUri));
    if (strcasecmp((char *) pszQop, "auth") != 0) {
	/* append ":00000000000000000000000000000000" */
	utils->MD5Update(&Md5Ctx, COLON, 1);
	utils->MD5Update(&Md5Ctx, HEntity, HASHHEXLEN);
    }
    utils->MD5Final(HA2, &Md5Ctx);
    CvtHex(HA2, HA2Hex);

    /* calculate response */
    utils->MD5Init(&Md5Ctx);
    utils->MD5Update(&Md5Ctx, HA1, HASHHEXLEN);
    utils->MD5Update(&Md5Ctx, COLON, 1);
    utils->MD5Update(&Md5Ctx, pszNonce, strlen((char *) pszNonce));
    utils->MD5Update(&Md5Ctx, COLON, 1);
    if (*pszQop) {
	sprintf(ncvalue, "%08x", pszNonceCount);
#ifdef _SUN_SDK_
	utils->MD5Update(&Md5Ctx, (unsigned char *)ncvalue, strlen(ncvalue));
#else
	utils->MD5Update(&Md5Ctx, ncvalue, strlen(ncvalue));
#endif /* _SUN_SDK_ */
	utils->MD5Update(&Md5Ctx, COLON, 1);
	utils->MD5Update(&Md5Ctx, pszCNonce, strlen((char *) pszCNonce));
	utils->MD5Update(&Md5Ctx, COLON, 1);
	utils->MD5Update(&Md5Ctx, pszQop, strlen((char *) pszQop));
	utils->MD5Update(&Md5Ctx, COLON, 1);
    }
    utils->MD5Update(&Md5Ctx, HA2Hex, HASHHEXLEN);
    utils->MD5Final(RespHash, &Md5Ctx);
    CvtHex(RespHash, Response);
}

static bool UTF8_In_8859_1(const unsigned char *base, int len)
{
    const unsigned char *scan, *end;

    end = base + len;
    for (scan = base; scan < end; ++scan) {
	if (*scan > 0xC3)
	    break;			/* abort if outside 8859-1 */
	if (*scan >= 0xC0 && *scan <= 0xC3) {
	    if (++scan == end || *scan < 0x80 || *scan > 0xBF)
		break;
	}
    }

    /* if scan >= end, then this is a 8859-1 string. */
    return (scan >= end);
}

/*
 * if the string is entirely in the 8859-1 subset of UTF-8, then translate to
 * 8859-1 prior to MD5
 */
void MD5_UTF8_8859_1(const sasl_utils_t * utils,
		     MD5_CTX * ctx,
		     bool In_ISO_8859_1,
		     const unsigned char *base,
		     int len)
{
    const unsigned char *scan, *end;
    unsigned char   cbuf;

    end = base + len;

    /* if we found a character outside 8859-1, don't alter string */
    if (!In_ISO_8859_1) {
	utils->MD5Update(ctx, base, len);
	return;
    }
    /* convert to 8859-1 prior to applying hash */
    do {
	for (scan = base; scan < end && *scan < 0xC0; ++scan);
	if (scan != base)
	    utils->MD5Update(ctx, base, scan - base);
	if (scan + 1 >= end)
	    break;
	cbuf = ((scan[0] & 0x3) << 6) | (scan[1] & 0x3f);
	utils->MD5Update(ctx, &cbuf, 1);
	base = scan + 2;
    }
    while (base < end);
}

static void DigestCalcSecret(const sasl_utils_t * utils,
			     unsigned char *pszUserName,
			     unsigned char *pszRealm,
			     unsigned char *Password,
			     int PasswordLen,
			     HASH HA1)
{
    bool            In_8859_1;

    MD5_CTX         Md5Ctx;

    /* Chris Newman clarified that the following text in DIGEST-MD5 spec
       is bogus: "if name and password are both in ISO 8859-1 charset"
       We shoud use code example instead */

    utils->MD5Init(&Md5Ctx);

    /* We have to convert UTF-8 to ISO-8859-1 if possible */
    In_8859_1 = UTF8_In_8859_1(pszUserName, strlen((char *) pszUserName));
    MD5_UTF8_8859_1(utils, &Md5Ctx, In_8859_1,
		    pszUserName, strlen((char *) pszUserName));

    utils->MD5Update(&Md5Ctx, COLON, 1);

    if (pszRealm != NULL && pszRealm[0] != '\0') {
	/* a NULL realm is equivalent to the empty string */
	utils->MD5Update(&Md5Ctx, pszRealm, strlen((char *) pszRealm));
    }

    utils->MD5Update(&Md5Ctx, COLON, 1);

    /* We have to convert UTF-8 to ISO-8859-1 if possible */
    In_8859_1 = UTF8_In_8859_1(Password, PasswordLen);
    MD5_UTF8_8859_1(utils, &Md5Ctx, In_8859_1,
		    Password, PasswordLen);

    utils->MD5Final(HA1, &Md5Ctx);
}

static unsigned char *create_nonce(const sasl_utils_t * utils)
{
    unsigned char  *base64buf;
    int             base64len;

    char           *ret = (char *) utils->malloc(NONCE_SIZE);
    if (ret == NULL)
	return NULL;

#if defined _DEV_URANDOM && defined _SUN_SDK_
    {
	int fd = open(_DEV_URANDOM, O_RDONLY);
	int nread = 0;

	if (fd != -1) {
		nread = read(fd, ret, NONCE_SIZE);
		close(fd);
	}
	if (nread != NONCE_SIZE)
	    utils->rand(utils->rpool, (char *) ret, NONCE_SIZE);
    }
#else
    utils->rand(utils->rpool, (char *) ret, NONCE_SIZE);
#endif /* _DEV_URANDOM && _SUN_SDK_ */

    /* base 64 encode it so it has valid chars */
    base64len = (NONCE_SIZE * 4 / 3) + (NONCE_SIZE % 3 ? 4 : 0);

    base64buf = (unsigned char *) utils->malloc(base64len + 1);
    if (base64buf == NULL) {
#ifdef _SUN_SDK_
	utils->log(utils->conn, SASL_LOG_ERR,
		   "Unable to allocate final buffer");
#else
	utils->seterror(utils->conn, 0, "Unable to allocate final buffer");
#endif /* _SUN_SDK_ */
	return NULL;
    }

    /*
     * Returns SASL_OK on success, SASL_BUFOVER if result won't fit
     */
    if (utils->encode64(ret, NONCE_SIZE,
			(char *) base64buf, base64len, NULL) != SASL_OK) {
	utils->free(ret);
	return NULL;
    }
    utils->free(ret);

    return base64buf;
}

static int add_to_challenge(const sasl_utils_t *utils,
			    char **str, unsigned *buflen, unsigned *curlen,
			    char *name,
			    unsigned char *value,
			    bool need_quotes)
{
    int             namesize = strlen(name);
    int             valuesize = strlen((char *) value);
    int             ret;

    ret = _plug_buf_alloc(utils, str, buflen,
			  *curlen + 1 + namesize + 2 + valuesize + 2);
    if(ret != SASL_OK) return ret;

    *curlen = *curlen + 1 + namesize + 2 + valuesize + 2;

    strcat(*str, ",");
    strcat(*str, name);

    if (need_quotes) {
	strcat(*str, "=\"");
	strcat(*str, (char *) value);	/* XXX. What about quoting??? */
	strcat(*str, "\"");
    } else {
	strcat(*str, "=");
	strcat(*str, (char *) value);
    }

    return SASL_OK;
}

static char *skip_lws (char *s)
{
    if(!s) return NULL;

    /* skipping spaces: */
    while (s[0] == ' ' || s[0] == HT || s[0] == CR || s[0] == LF) {
	if (s[0]=='\0') break;
	s++;
    }

    return s;
}

#ifdef __SUN_SDK_
static char *skip_token (char *s, int caseinsensitive  __attribute__((unused)))
#else
static char *skip_token (char *s, int caseinsensitive)
#endif /* _SUN_SDK_ */
{
    if(!s) return NULL;

#ifdef __SUN_SDK_
    while (((unsigned char *)s)[0]>SP) {
#else
    while (s[0]>SP) {
#endif /* _SUN_SDK_ */
	if (s[0]==DEL || s[0]=='(' || s[0]==')' || s[0]=='<' || s[0]=='>' ||
	    s[0]=='@' || s[0]==',' || s[0]==';' || s[0]==':' || s[0]=='\\' ||
	    s[0]=='\'' || s[0]=='/' || s[0]=='[' || s[0]==']' || s[0]== '?' ||
	    s[0]=='=' || s[0]== '{' || s[0]== '}') {
#ifdef __SUN_SDK_
	    /* the above chars are never uppercase */
	    break;
#else
	    if (caseinsensitive == 1) {
		if (!isupper((unsigned char) s[0]))
		    break;
	    } else {
		break;
	    }
#endif /* _SUN_SDK_ */
	}
	s++;
    }
    return s;
}

/* NULL - error (unbalanced quotes),
   otherwise pointer to the first character after value */
static char *unquote (char *qstr)
{
    char *endvalue;
    int   escaped = 0;
    char *outptr;

    if(!qstr) return NULL;

    if (qstr[0] == '"') {
	qstr++;
	outptr = qstr;

	for (endvalue = qstr; endvalue[0] != '\0'; endvalue++, outptr++) {
	    if (escaped) {
		outptr[0] = endvalue[0];
		escaped = 0;
	    }
	    else if (endvalue[0] == '\\') {
		escaped = 1;
		outptr--; /* Will be incremented at the end of the loop */
	    }
	    else if (endvalue[0] == '"') {
		break;
	    }
	    else {
		outptr[0] = endvalue[0];
	    }
	}

	if (endvalue[0] != '"') {
	    return NULL;
	}

	while (outptr <= endvalue) {
	    outptr[0] = '\0';
	    outptr++;
	}
	endvalue++;
    }
    else { /* not qouted value (token) */
	endvalue = skip_token(qstr,0);
    };

    return endvalue;
}

static void get_pair(char **in, char **name, char **value)
{
    char  *endpair;
    /* int    inQuotes; */
    char  *curp = *in;
    *name = NULL;
    *value = NULL;

    if (curp == NULL) return;
    if (curp[0] == '\0') return;

    /* skipping spaces: */
    curp = skip_lws(curp);

    *name = curp;

    curp = skip_token(curp,1);

    /* strip wierd chars */
    if (curp[0] != '=' && curp[0] != '\0') {
	*curp++ = '\0';
    };

    curp = skip_lws(curp);

    if (curp[0] != '=') { /* No '=' sign */
	*name = NULL;
	return;
    }

    curp[0] = '\0';
    curp++;

    curp = skip_lws(curp);

    *value = (curp[0] == '"') ? curp+1 : curp;

    endpair = unquote (curp);
    if (endpair == NULL) { /* Unbalanced quotes */
	*name = NULL;
	return;
    }
    if (endpair[0] != ',') {
	if (endpair[0]!='\0') {
	    *endpair++ = '\0';
	}
    }

    endpair = skip_lws(endpair);

    /* syntax check: MUST be '\0' or ',' */
    if (endpair[0] == ',') {
	endpair[0] = '\0';
	endpair++; /* skipping <,> */
    } else if (endpair[0] != '\0') {
	*name = NULL;
	return;
    }

    *in = endpair;
}

#ifdef WITH_DES
struct des_context_s {
    des_key_schedule keysched;  /* key schedule for des initialization */
    des_cblock ivec;            /* initial vector for encoding */
    des_key_schedule keysched2; /* key schedule for 3des initialization */
};

typedef struct des_context_s des_context_t;

/* slide the first 7 bytes of 'inbuf' into the high seven bits of the
   first 8 bytes of 'keybuf'. 'keybuf' better be 8 bytes long or longer. */
static void slidebits(unsigned char *keybuf, unsigned char *inbuf)
{
    keybuf[0] = inbuf[0];
    keybuf[1] = (inbuf[0]<<7) | (inbuf[1]>>1);
    keybuf[2] = (inbuf[1]<<6) | (inbuf[2]>>2);
    keybuf[3] = (inbuf[2]<<5) | (inbuf[3]>>3);
    keybuf[4] = (inbuf[3]<<4) | (inbuf[4]>>4);
    keybuf[5] = (inbuf[4]<<3) | (inbuf[5]>>5);
    keybuf[6] = (inbuf[5]<<2) | (inbuf[6]>>6);
    keybuf[7] = (inbuf[6]<<1);
}

/******************************
 *
 * 3DES functions
 *
 *****************************/

static int dec_3des(context_t *text,
		    const char *input,
		    unsigned inputlen,
		    unsigned char digest[16],
		    char *output,
		    unsigned *outputlen)
{
    des_context_t *c = (des_context_t *) text->cipher_dec_context;
    int padding, p;

    des_ede2_cbc_encrypt((void *) input,
			 (void *) output,
			 inputlen,
			 c->keysched,
			 c->keysched2,
			 &c->ivec,
			 DES_DECRYPT);

    /* now chop off the padding */
    padding = output[inputlen - 11];
    if (padding < 1 || padding > 8) {
	/* invalid padding length */
	return SASL_FAIL;
    }
    /* verify all padding is correct */
    for (p = 1; p <= padding; p++) {
	if (output[inputlen - 10 - p] != padding) {
	    return SASL_FAIL;
	}
    }

    /* chop off the padding */
    *outputlen = inputlen - padding - 10;

    /* copy in the HMAC to digest */
    memcpy(digest, output + inputlen - 10, 10);

    return SASL_OK;
}

static int enc_3des(context_t *text,
		    const char *input,
		    unsigned inputlen,
		    unsigned char digest[16],
		    char *output,
		    unsigned *outputlen)
{
    des_context_t *c = (des_context_t *) text->cipher_enc_context;
    int len;
    int paddinglen;

    /* determine padding length */
    paddinglen = 8 - ((inputlen + 10) % 8);

    /* now construct the full stuff to be ciphered */
    memcpy(output, input, inputlen);                /* text */
    memset(output+inputlen, paddinglen, paddinglen);/* pad  */
    memcpy(output+inputlen+paddinglen, digest, 10); /* hmac */

    len=inputlen+paddinglen+10;

    des_ede2_cbc_encrypt((void *) output,
			 (void *) output,
			 len,
			 c->keysched,
			 c->keysched2,
			 &c->ivec,
			 DES_ENCRYPT);

    *outputlen=len;

    return SASL_OK;
}

static int init_3des(context_t *text,
		     unsigned char enckey[16],
		     unsigned char deckey[16])
{
    des_context_t *c;
    unsigned char keybuf[8];

    /* allocate enc & dec context */
    c = (des_context_t *) text->utils->malloc(2 * sizeof(des_context_t));
    if (c == NULL) return SASL_NOMEM;

    /* setup enc context */
    slidebits(keybuf, enckey);
    if (des_key_sched((des_cblock *) keybuf, c->keysched) < 0)
	return SASL_FAIL;

    slidebits(keybuf, enckey + 7);
    if (des_key_sched((des_cblock *) keybuf, c->keysched2) < 0)
	return SASL_FAIL;
    memcpy(c->ivec, ((char *) enckey) + 8, 8);

    text->cipher_enc_context = (cipher_context_t *) c;

    /* setup dec context */
    c++;
    slidebits(keybuf, deckey);
    if (des_key_sched((des_cblock *) keybuf, c->keysched) < 0)
	return SASL_FAIL;

    slidebits(keybuf, deckey + 7);
    if (des_key_sched((des_cblock *) keybuf, c->keysched2) < 0)
	return SASL_FAIL;

    memcpy(c->ivec, ((char *) deckey) + 8, 8);

    text->cipher_dec_context = (cipher_context_t *) c;

    return SASL_OK;
}


/******************************
 *
 * DES functions
 *
 *****************************/

static int dec_des(context_t *text,
		   const char *input,
		   unsigned inputlen,
		   unsigned char digest[16],
		   char *output,
		   unsigned *outputlen)
{
    des_context_t *c = (des_context_t *) text->cipher_dec_context;
    int p, padding = 0;

    des_cbc_encrypt((void *) input,
		    (void *) output,
		    inputlen,
		    c->keysched,
		    &c->ivec,
		    DES_DECRYPT);

    /* Update the ivec (des_cbc_encrypt implementations tend to be broken in
       this way) */
    memcpy(c->ivec, input + (inputlen - 8), 8);

    /* now chop off the padding */
    padding = output[inputlen - 11];
    if (padding < 1 || padding > 8) {
	/* invalid padding length */
	return SASL_FAIL;
    }
    /* verify all padding is correct */
    for (p = 1; p <= padding; p++) {
	if (output[inputlen - 10 - p] != padding) {
	    return SASL_FAIL;
	}
    }

    /* chop off the padding */
    *outputlen = inputlen - padding - 10;

    /* copy in the HMAC to digest */
    memcpy(digest, output + inputlen - 10, 10);

    return SASL_OK;
}

static int enc_des(context_t *text,
		   const char *input,
		   unsigned inputlen,
		   unsigned char digest[16],
		   char *output,
		   unsigned *outputlen)
{
    des_context_t *c = (des_context_t *) text->cipher_enc_context;
    int len;
    int paddinglen;

    /* determine padding length */
    paddinglen = 8 - ((inputlen+10) % 8);

    /* now construct the full stuff to be ciphered */
    memcpy(output, input, inputlen);                /* text */
    memset(output+inputlen, paddinglen, paddinglen);/* pad  */
    memcpy(output+inputlen+paddinglen, digest, 10); /* hmac */

    len = inputlen + paddinglen + 10;

    des_cbc_encrypt((void *) output,
                    (void *) output,
                    len,
                    c->keysched,
                    &c->ivec,
                    DES_ENCRYPT);

    /* Update the ivec (des_cbc_encrypt implementations tend to be broken in
       this way) */
    memcpy(c->ivec, output + (len - 8), 8);

    *outputlen = len;

    return SASL_OK;
}

static int init_des(context_t *text,
		    unsigned char enckey[16],
		    unsigned char deckey[16])
{
    des_context_t *c;
    unsigned char keybuf[8];

    /* allocate enc context */
    c = (des_context_t *) text->utils->malloc(2 * sizeof(des_context_t));
    if (c == NULL) return SASL_NOMEM;

    /* setup enc context */
    slidebits(keybuf, enckey);
    des_key_sched((des_cblock *) keybuf, c->keysched);

    memcpy(c->ivec, ((char *) enckey) + 8, 8);

    text->cipher_enc_context = (cipher_context_t *) c;

    /* setup dec context */
    c++;
    slidebits(keybuf, deckey);
    des_key_sched((des_cblock *) keybuf, c->keysched);

    memcpy(c->ivec, ((char *) deckey) + 8, 8);

    text->cipher_dec_context = (cipher_context_t *) c;

    return SASL_OK;
}

static void free_des(context_t *text)
{
    /* free des contextss. only cipher_enc_context needs to be free'd,
       since cipher_dec_context was allocated at the same time. */
    if (text->cipher_enc_context) text->utils->free(text->cipher_enc_context);
}

#endif /* WITH_DES */

#ifdef WITH_RC4
/* quick generic implementation of RC4 */
struct rc4_context_s {
    unsigned char sbox[256];
    int i, j;
};

typedef struct rc4_context_s rc4_context_t;

static void rc4_init(rc4_context_t *text,
		     const unsigned char *key,
		     unsigned keylen)
{
    int i, j;

    /* fill in linearly s0=0 s1=1... */
    for (i=0;i<256;i++)
	text->sbox[i]=i;

    j=0;
    for (i = 0; i < 256; i++) {
	unsigned char tmp;
	/* j = (j + Si + Ki) mod 256 */
	j = (j + text->sbox[i] + key[i % keylen]) % 256;

	/* swap Si and Sj */
	tmp = text->sbox[i];
	text->sbox[i] = text->sbox[j];
	text->sbox[j] = tmp;
    }

    /* counters initialized to 0 */
    text->i = 0;
    text->j = 0;
}

static void rc4_encrypt(rc4_context_t *text,
			const char *input,
			char *output,
			unsigned len)
{
    int tmp;
    int i = text->i;
    int j = text->j;
    int t;
    int K;
    const char *input_end = input + len;

    while (input < input_end) {
	i = (i + 1) % 256;

	j = (j + text->sbox[i]) % 256;

	/* swap Si and Sj */
	tmp = text->sbox[i];
	text->sbox[i] = text->sbox[j];
	text->sbox[j] = tmp;

	t = (text->sbox[i] + text->sbox[j]) % 256;

	K = text->sbox[t];

	/* byte K is Xor'ed with plaintext */
	*output++ = *input++ ^ K;
    }

    text->i = i;
    text->j = j;
}

static void rc4_decrypt(rc4_context_t *text,
			const char *input,
			char *output,
			unsigned len)
{
    int tmp;
    int i = text->i;
    int j = text->j;
    int t;
    int K;
    const char *input_end = input + len;

    while (input < input_end) {
	i = (i + 1) % 256;

	j = (j + text->sbox[i]) % 256;

	/* swap Si and Sj */
	tmp = text->sbox[i];
	text->sbox[i] = text->sbox[j];
	text->sbox[j] = tmp;

	t = (text->sbox[i] + text->sbox[j]) % 256;

	K = text->sbox[t];

	/* byte K is Xor'ed with plaintext */
	*output++ = *input++ ^ K;
    }

    text->i = i;
    text->j = j;
}

static void free_rc4(context_t *text)
{
    /* free rc4 context structures */

    if(text->cipher_enc_context) text->utils->free(text->cipher_enc_context);
    if(text->cipher_dec_context) text->utils->free(text->cipher_dec_context);
#ifdef _SUN_SDK_
    text->cipher_enc_context = NULL;
    text->cipher_dec_context = NULL;
#endif /* _SUN_SDK_ */
}

static int init_rc4(context_t *text,
#ifdef _SUN_SDK_
		    char enckey[16],
		    char deckey[16])
#else
		    unsigned char enckey[16],
		    unsigned char deckey[16])
#endif /* _SUN_SDK_ */
{
    /* allocate rc4 context structures */
    text->cipher_enc_context=
	(cipher_context_t *) text->utils->malloc(sizeof(rc4_context_t));
    if (text->cipher_enc_context == NULL) return SASL_NOMEM;

    text->cipher_dec_context=
	(cipher_context_t *) text->utils->malloc(sizeof(rc4_context_t));
#ifdef _SUN_SDK_
    if (text->cipher_dec_context == NULL) {
	text->utils->free(text->cipher_enc_context);
	text->cipher_enc_context = NULL;
	return SASL_NOMEM;
    }
#else
    if (text->cipher_dec_context == NULL) return SASL_NOMEM;
#endif /* _SUN_SDK_ */

    /* initialize them */
    rc4_init((rc4_context_t *) text->cipher_enc_context,
             (const unsigned char *) enckey, 16);
    rc4_init((rc4_context_t *) text->cipher_dec_context,
             (const unsigned char *) deckey, 16);

    return SASL_OK;
}

static int dec_rc4(context_t *text,
		   const char *input,
		   unsigned inputlen,
		   unsigned char digest[16],
		   char *output,
		   unsigned *outputlen)
{
    /* decrypt the text part */
    rc4_decrypt((rc4_context_t *) text->cipher_dec_context,
                input, output, inputlen-10);

    /* decrypt the HMAC part */
    rc4_decrypt((rc4_context_t *) text->cipher_dec_context,
		input+(inputlen-10), (char *) digest, 10);

    /* no padding so we just subtract the HMAC to get the text length */
    *outputlen = inputlen - 10;

    return SASL_OK;
}

static int enc_rc4(context_t *text,
		   const char *input,
		   unsigned inputlen,
		   unsigned char digest[16],
		   char *output,
		   unsigned *outputlen)
{
    /* pad is zero */
    *outputlen = inputlen+10;

    /* encrypt the text part */
    rc4_encrypt((rc4_context_t *) text->cipher_enc_context,
                input,
                output,
                inputlen);

    /* encrypt the HMAC part */
    rc4_encrypt((rc4_context_t *) text->cipher_enc_context,
                (const char *) digest,
		(output)+inputlen, 10);

    return SASL_OK;
}

#endif /* WITH_RC4 */

struct digest_cipher available_ciphers[] =
{
#ifdef WITH_RC4
    { "rc4-40", 40, 5, 0x01, &enc_rc4, &dec_rc4, &init_rc4, &free_rc4 },
    { "rc4-56", 56, 7, 0x02, &enc_rc4, &dec_rc4, &init_rc4, &free_rc4 },
    { "rc4", 128, 16, 0x04, &enc_rc4, &dec_rc4, &init_rc4, &free_rc4 },
#endif
#ifdef WITH_DES
    { "des", 55, 16, 0x08, &enc_des, &dec_des, &init_des, &free_des },
    { "3des", 112, 16, 0x10, &enc_3des, &dec_3des, &init_3des, &free_des },
#endif
    { NULL, 0, 0, 0, NULL, NULL, NULL, NULL }
};


#ifdef USE_UEF
DEFINE_STATIC_MUTEX(uef_init_mutex);
#define DES_CIPHER_INDEX	3
#define DES3_CIPHER_INDEX	4

static int got_uef_slot = FALSE;
static sasl_ssf_t uef_max_ssf = 0;
static CK_SLOT_ID rc4_slot_id;
static CK_SLOT_ID des_slot_id;
static CK_SLOT_ID des3_slot_id;

struct uef_context_s {
    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
};

typedef struct uef_context_s uef_context_t;

/*
 * slide the first 7 bytes of 'inbuf' into the high seven bits of the
 * first 8 bytes of 'keybuf'. 'inbuf' better be 8 bytes long or longer.
 *
 * This is used to compute the IV for "des" and "3des" as described in
 * draft-ietf-sasl-rfc2831bis-00.txt - The IV for "des"
 *  and "3des" is the last 8 bytes of Kcc or Kcs - the encryption keys.
 */

static void slidebits(unsigned char *keybuf, unsigned char *inbuf)
{
    keybuf[0] = inbuf[0];
    keybuf[1] = (inbuf[0]<<7) | (inbuf[1]>>1);
    keybuf[2] = (inbuf[1]<<6) | (inbuf[2]>>2);
    keybuf[3] = (inbuf[2]<<5) | (inbuf[3]>>3);
    keybuf[4] = (inbuf[3]<<4) | (inbuf[4]>>4);
    keybuf[5] = (inbuf[4]<<3) | (inbuf[5]>>5);
    keybuf[6] = (inbuf[5]<<2) | (inbuf[6]>>6);
    keybuf[7] = (inbuf[6]<<1);
}

/*
 * Create encryption and decryption session handle handles for later use.
 * Returns SASL_OK on success - any other return indicates failure.
 *
 * free_uef is called to release associated resources by
 *	digestmd5_common_mech_dispose
 */

static int init_uef(context_t *text,
		    CK_KEY_TYPE keyType,
		    CK_MECHANISM_TYPE mech_type,
		    CK_SLOT_ID slot_id,
		    char enckey[16],
		    char deckey[16])
{
    CK_RV		rv;
    uef_context_t	*enc_context;
    uef_context_t	*dec_context;
    CK_OBJECT_CLASS	class = CKO_SECRET_KEY;
    CK_BBOOL		true = TRUE;
    static CK_MECHANISM	mechanism = {CKM_RC4, NULL, 0};
    unsigned char 	keybuf[24];
    CK_ATTRIBUTE	template[] = {
				{CKA_CLASS, NULL, sizeof (class)},
				{CKA_KEY_TYPE, NULL, sizeof (keyType)},
				{CKA_ENCRYPT, NULL, sizeof (true)},
				{CKA_VALUE, NULL, 16}};

    template[0].pValue = &class;
    template[1].pValue = &keyType;
    template[2].pValue = &true;
    if (keyType == CKK_DES || keyType == CKK_DES3) {
	slidebits(keybuf, (unsigned char *)enckey);
	if (keyType == CKK_DES3) {
	    slidebits(keybuf + 8, (unsigned char *)enckey + 7);
	    (void) memcpy(keybuf + 16, keybuf, 8);
	    template[3].ulValueLen = 24;
	} else {
	    template[3].ulValueLen = 8;
	}
	template[3].pValue = keybuf;
	mechanism.pParameter = enckey + 8;
	mechanism.ulParameterLen = 8;
    } else {
	template[3].pValue = enckey;
    }
    mechanism.mechanism = mech_type;

    /* allocate rc4 context structures */
    enc_context = text->utils->malloc(sizeof (uef_context_t));
    if (enc_context == NULL)
	return SASL_NOMEM;

    rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
		&enc_context->hSession);
    if (rv != CKR_OK) {
	text->utils->free(enc_context);
#ifdef DEBUG
	text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
		"enc C_OpenSession Failed:0x%.8X\n", rv);
#endif
	return SASL_FAIL;
    }

    rv = C_CreateObject(enc_context->hSession, template,
		sizeof (template)/sizeof (template[0]), &enc_context->hKey);
    if (rv != CKR_OK) {
	text->utils->free(enc_context);
	(void) C_CloseSession(enc_context->hSession);
#ifdef DEBUG
	text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			 "enc C_CreateObject: rv = 0x%.8X\n", rv);
#endif
	return SASL_FAIL;
    }

    text->cipher_enc_context = (cipher_context_t *)enc_context;

    /* Initialize the encryption operation in the session */
    rv = C_EncryptInit(enc_context->hSession, &mechanism, enc_context->hKey);
    if (rv != CKR_OK) {
#ifdef DEBUG
	text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			 "C_EncryptInit: rv = 0x%.8X\n", rv);
#endif
	return SASL_FAIL;
    }

    dec_context = text->utils->malloc(sizeof(uef_context_t));
    if (dec_context == NULL)
	return SASL_NOMEM;

    rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
		&dec_context->hSession);
    if (rv != CKR_OK) {
#ifdef DEBUG
	text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
		"dec C_OpenSession Failed:0x%.8X\n", rv);
#endif
	text->utils->free(dec_context);
	return SASL_FAIL;
    }

    template[2].type = CKA_DECRYPT;
    if (keyType == CKK_DES || keyType == CKK_DES3) {
	slidebits(keybuf, (unsigned char *)deckey);
	if (keyType == CKK_DES3) {
	    slidebits(keybuf + 8, (unsigned char *)deckey + 7);
	    (void) memcpy(keybuf + 16, keybuf, 8);
	}
	mechanism.pParameter = deckey + 8;
    } else {
	template[3].pValue = deckey;
    }

    rv = C_CreateObject(dec_context->hSession, template,
		sizeof (template)/sizeof (template[0]), &dec_context->hKey);
    if (rv != CKR_OK) {
#ifdef DEBUG
	text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
		"dec C_CreateObject: rv = 0x%.8X\n", rv);
#endif
	(void) C_CloseSession(dec_context->hSession);
	text->utils->free(dec_context);
	return SASL_FAIL;
    }
    text->cipher_dec_context = (cipher_context_t *)dec_context;

    /* Initialize the decryption operation in the session */
    rv = C_DecryptInit(dec_context->hSession, &mechanism, dec_context->hKey);
    if (rv != CKR_OK) {
#ifdef DEBUG
	text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			 "C_DecryptInit: rv = 0x%.8X\n", rv);
#endif
	return SASL_FAIL;
    }

    return SASL_OK;
}

static int init_rc4_uef(context_t *text,
		    char enckey[16],
		    char deckey[16])
{
    return init_uef(text, CKK_RC4, CKM_RC4, rc4_slot_id, enckey, deckey);
}

static int init_des_uef(context_t *text,
		    char enckey[16],
		    char deckey[16])
{
    return init_uef(text, CKK_DES, CKM_DES_CBC, des_slot_id, enckey, deckey);
}

static int init_3des_uef(context_t *text,
		    char enckey[16],
		    char deckey[16])
{
    return init_uef(text, CKK_DES3, CKM_DES3_CBC, des3_slot_id, enckey, deckey);
}

static void
free_uef(context_t *text)
{
    uef_context_t	*enc_context =
		(uef_context_t *)text->cipher_enc_context;
    uef_context_t	*dec_context =
		(uef_context_t *)text->cipher_dec_context;
    CK_RV		rv;
    unsigned char 	buf[1];
    CK_ULONG		ulLen = 0;


    if (enc_context != NULL) {
	rv = C_EncryptFinal(enc_context->hSession, buf, &ulLen);
	if (rv != CKR_OK) {
#ifdef DEBUG
	    text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
	    		     "C_EncryptFinal failed:0x%.8X\n", rv);
#endif
	}
	rv = C_DestroyObject(enc_context->hSession, enc_context->hKey);
	if (rv != CKR_OK) {
#ifdef DEBUG
	    text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			     "C_DestroyObject failed:0x%.8X\n", rv);
#endif
	}
	rv = C_CloseSession(enc_context->hSession);
	if (rv != CKR_OK) {
#ifdef DEBUG
	    text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			     "C_CloseSession failed:0x%.8X\n", rv);
#endif
	}
	text->utils->free(enc_context);
    }
    if (dec_context != NULL) {
	rv = C_DecryptFinal(dec_context->hSession, buf, &ulLen);
	if (rv != CKR_OK) {
#ifdef DEBUG
	    text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			     "C_DecryptFinal failed:0x%.8X\n", rv);
#endif
	}
	rv = C_DestroyObject(dec_context->hSession, dec_context->hKey);
	if (rv != CKR_OK) {
#ifdef DEBUG
	    text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			     "C_DestroyObject failed:0x%.8X\n", rv);
#endif
	}

	rv = C_CloseSession(dec_context->hSession);
	if (rv != CKR_OK) {
#ifdef DEBUG
	    text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			     "C_CloseSession failed:0x%.8X\n", rv);
#endif
	}
	text->utils->free(dec_context);
    }
    text->cipher_enc_context = NULL;
    text->cipher_dec_context = NULL;
}

static int
dec_rc4_uef(context_t *text,
	    const char *input,
	    unsigned inputlen,
	    unsigned char digest[16],
	    char *output,
	    unsigned *outputlen)
{
    CK_RV		rv;
    uef_context_t	*dec_context =
		(uef_context_t *)text->cipher_dec_context;
    CK_ULONG		ulDataLen = *outputlen - MAC_SIZE;
    CK_ULONG		ulDigestLen = MAC_SIZE;

    rv = C_DecryptUpdate(dec_context->hSession, (CK_BYTE_PTR)input,
	inputlen - MAC_SIZE, (CK_BYTE_PTR)output, &ulDataLen);
    if (rv != CKR_OK) {
#ifdef DEBUG
	text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			 "C_DecryptUpdate failed:0x%.8X\n", rv);
#endif
	return SASL_FAIL;
    }
    *outputlen = (unsigned)ulDataLen;

    rv = C_DecryptUpdate(dec_context->hSession,
	(CK_BYTE_PTR)input+(inputlen-MAC_SIZE), MAC_SIZE, (CK_BYTE_PTR)digest,
	&ulDigestLen);
    if (rv != CKR_OK || ulDigestLen != MAC_SIZE) {
#ifdef DEBUG
	text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			 "C_DecryptUpdate:0x%.8X, digestLen:%d\n",
			 rv, ulDigestLen);
#endif
	return SASL_FAIL;
    }

    return SASL_OK;
}

static int
enc_rc4_uef(context_t *text,
	    const char *input,
	    unsigned inputlen,
	    unsigned char digest[16],
	    char *output,
	    unsigned *outputlen)
{
    CK_RV		rv;
    uef_context_t	*enc_context =
		(uef_context_t *)text->cipher_enc_context;
    CK_ULONG		ulDataLen = inputlen;
    CK_ULONG		ulDigestLen = MAC_SIZE;

    rv = C_EncryptUpdate(enc_context->hSession, (CK_BYTE_PTR)input, inputlen,
	(CK_BYTE_PTR)output, &ulDataLen);
    if (rv != CKR_OK) {
#ifdef DEBUG
	text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			 "C_EncryptUpdate failed: 0x%.8X "
			  "inputlen:%d outputlen:%d\n",
			  rv, inputlen, ulDataLen);
#endif
	return SASL_FAIL;
    }
    rv = C_EncryptUpdate(enc_context->hSession, (CK_BYTE_PTR)digest, MAC_SIZE,
	(CK_BYTE_PTR)output + inputlen, &ulDigestLen);
    if (rv != CKR_OK) {
#ifdef DEBUG
	text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			 "C_EncryptUpdate failed: 0x%.8X ulDigestLen:%d\n",
			 rv, ulDigestLen);
#endif
	return SASL_FAIL;
    }

    *outputlen = ulDataLen + ulDigestLen;

    return SASL_OK;
}

static int
dec_des_uef(context_t *text,
	    const char *input,
	    unsigned inputlen,
	    unsigned char digest[16],
	    char *output,
	    unsigned *outputlen)
{
    CK_RV		rv;
    uef_context_t	*dec_context =
		(uef_context_t *)text->cipher_dec_context;
    CK_ULONG		ulDataLen = inputlen;
    int			padding, p;

    rv = C_DecryptUpdate(dec_context->hSession, (CK_BYTE_PTR)input,
	inputlen, (CK_BYTE_PTR)output, &ulDataLen);
    if (rv != CKR_OK) {
#ifdef DEBUG
	text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			 "C_DecryptUpdate failed:0x%.8X\n", rv);
#endif
	return SASL_FAIL;
    }
    if (ulDataLen != inputlen) {
#ifdef DEBUG
	text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			 "C_DecryptUpdate unexpected data len:%d !=%d\n",
			 inputlen, ulDataLen);
#endif
	return SASL_BUFOVER;
    }

    /* now chop off the padding */
    padding = output[inputlen - 11];
    if (padding < 1 || padding > 8) {
	/* invalid padding length */
	return SASL_BADMAC;
    }
    /* verify all padding is correct */
    for (p = 1; p <= padding; p++) {
	if (output[inputlen - MAC_SIZE - p] != padding) {
	    return SASL_BADMAC;
	}
    }

    /* chop off the padding */
    *outputlen = inputlen - padding - MAC_SIZE;

    /* copy in the HMAC to digest */
    memcpy(digest, output + inputlen - MAC_SIZE, MAC_SIZE);

    return SASL_OK;
}

static int
enc_des_uef(context_t *text,
	    const char *input,
	    unsigned inputlen,
	    unsigned char digest[16],
	    char *output,
	    unsigned *outputlen)
{
    CK_RV		rv;
    uef_context_t	*enc_context =
		(uef_context_t *)text->cipher_enc_context;
    CK_ULONG		ulDataLen;
    int paddinglen;

    /* determine padding length */
    paddinglen = 8 - ((inputlen + MAC_SIZE) % 8);

    /* now construct the full stuff to be ciphered */
    memcpy(output, input, inputlen);                /* text */
    memset(output+inputlen, paddinglen, paddinglen);/* pad  */
    memcpy(output+inputlen+paddinglen, digest, MAC_SIZE); /* hmac */

    ulDataLen=inputlen+paddinglen+MAC_SIZE;

    rv = C_EncryptUpdate(enc_context->hSession, (CK_BYTE_PTR)output, ulDataLen,
	(CK_BYTE_PTR)output, &ulDataLen);
    if (rv != CKR_OK) {
#ifdef DEBUG
	text->utils->log(text->utils->conn, SASL_LOG_DEBUG,
			 "C_EncryptUpdate failed: 0x%.8X "
			 "inputlen:%d outputlen:%d\n",
			 rv, ulDataLen, ulDataLen);
#endif
	return SASL_FAIL;
    }
    *outputlen = (unsigned)ulDataLen;

    return SASL_OK;
}

struct digest_cipher uef_ciphers[] =
{
    { "rc4-40", 40, 5, 0x01, &enc_rc4_uef, &dec_rc4_uef, &init_rc4_uef,
	&free_uef },
    { "rc4-56", 56, 7, 0x02, &enc_rc4_uef, &dec_rc4_uef, &init_rc4_uef,
	&free_uef },
    { "rc4", 128, 16, 0x04, &enc_rc4_uef, &dec_rc4_uef, &init_rc4_uef,
	&free_uef },
    { "des", 55, 16, 0x08, &enc_des_uef, &dec_des_uef, &init_des_uef,
	&free_uef },
    { "3des", 112, 16, 0x10, &enc_des_uef, &dec_des_uef, &init_3des_uef,
	&free_uef },
    { NULL, 0, 0, 0, NULL, NULL, NULL, NULL }
};

struct digest_cipher *available_ciphers1 = uef_ciphers;
#endif /* USE_UEF */

static int create_layer_keys(context_t *text,
			     const sasl_utils_t *utils,
			     HASH key, int keylen,
			     char enckey[16], char deckey[16])
{
    MD5_CTX Md5Ctx;

    utils->MD5Init(&Md5Ctx);
    utils->MD5Update(&Md5Ctx, key, keylen);
    if (text->i_am == SERVER) {
	utils->MD5Update(&Md5Ctx, (const unsigned char *) SEALING_SERVER_CLIENT,
			 strlen(SEALING_SERVER_CLIENT));
    } else {
	utils->MD5Update(&Md5Ctx, (const unsigned char *) SEALING_CLIENT_SERVER,
			 strlen(SEALING_CLIENT_SERVER));
    }
    utils->MD5Final((unsigned char *) enckey, &Md5Ctx);

    utils->MD5Init(&Md5Ctx);
    utils->MD5Update(&Md5Ctx, key, keylen);
    if (text->i_am != SERVER) {
	utils->MD5Update(&Md5Ctx, (const unsigned char *)SEALING_SERVER_CLIENT,
			 strlen(SEALING_SERVER_CLIENT));
    } else {
	utils->MD5Update(&Md5Ctx, (const unsigned char *)SEALING_CLIENT_SERVER,
			 strlen(SEALING_CLIENT_SERVER));
    }
    utils->MD5Final((unsigned char *) deckey, &Md5Ctx);

    /* create integrity keys */
    /* sending */
    utils->MD5Init(&Md5Ctx);
    utils->MD5Update(&Md5Ctx, text->HA1, HASHLEN);
    if (text->i_am == SERVER) {
	utils->MD5Update(&Md5Ctx, (const unsigned char *)SIGNING_SERVER_CLIENT,
			 strlen(SIGNING_SERVER_CLIENT));
    } else {
	utils->MD5Update(&Md5Ctx, (const unsigned char *)SIGNING_CLIENT_SERVER,
			 strlen(SIGNING_CLIENT_SERVER));
    }
    utils->MD5Final(text->Ki_send, &Md5Ctx);

    /* receiving */
    utils->MD5Init(&Md5Ctx);
    utils->MD5Update(&Md5Ctx, text->HA1, HASHLEN);
    if (text->i_am != SERVER) {
	utils->MD5Update(&Md5Ctx, (const unsigned char *)SIGNING_SERVER_CLIENT,
			 strlen(SIGNING_SERVER_CLIENT));
    } else {
	utils->MD5Update(&Md5Ctx, (const unsigned char *)SIGNING_CLIENT_SERVER,
			 strlen(SIGNING_CLIENT_SERVER));
    }
    utils->MD5Final(text->Ki_receive, &Md5Ctx);

    return SASL_OK;
}

static const unsigned short version = 1;

/* len, CIPHER(Kc, {msg, pag, HMAC(ki, {SeqNum, msg})[0..9]}), x0001, SeqNum */

static int
digestmd5_privacy_encode(void *context,
			 const struct iovec *invec,
			 unsigned numiov,
			 const char **output,
			 unsigned *outputlen)
{
    context_t *text = (context_t *) context;
    int tmp;
    unsigned int tmpnum;
    unsigned short int tmpshort;
    int ret;
    char *out;
    unsigned char digest[16];
    struct buffer_info *inblob, bufinfo;

    if(!context || !invec || !numiov || !output || !outputlen) {
	PARAMERROR(text->utils);
	return SASL_BADPARAM;
    }

    if (numiov > 1) {
	ret = _plug_iovec_to_buf(text->utils, invec, numiov, &text->enc_in_buf);
	if (ret != SASL_OK) return ret;
	inblob = text->enc_in_buf;
    } else {
	/* avoid the data copy */
	bufinfo.data = invec[0].iov_base;
	bufinfo.curlen = invec[0].iov_len;
	inblob = &bufinfo;
    }

    /* make sure the output buffer is big enough for this blob */
    ret = _plug_buf_alloc(text->utils, &(text->encode_buf),
			  &(text->encode_buf_len),
			  (4 +                        /* for length */
			   inblob->curlen + /* for content */
			   10 +                       /* for MAC */
			   8 +                        /* maximum pad */
			   6 +                        /* for padding */
			   1));                       /* trailing null */
    if(ret != SASL_OK) return ret;

    /* skip by the length for now */
    out = (text->encode_buf)+4;

    /* construct (seqnum, msg) */
    /* We can just use the output buffer because it's big enough */
    tmpnum = htonl(text->seqnum);
    memcpy(text->encode_buf, &tmpnum, 4);
    memcpy(text->encode_buf + 4, inblob->data, inblob->curlen);

    /* HMAC(ki, (seqnum, msg) ) */
    text->utils->hmac_md5((const unsigned char *) text->encode_buf,
			  inblob->curlen + 4,
			  text->Ki_send, HASHLEN, digest);

    /* calculate the encrypted part */
    text->cipher_enc(text, inblob->data, inblob->curlen,
		     digest, out, outputlen);
    out+=(*outputlen);

    /* copy in version */
    tmpshort = htons(version);
    memcpy(out, &tmpshort, 2);	/* 2 bytes = version */

    out+=2;
    (*outputlen)+=2; /* for version */

    /* put in seqnum */
    tmpnum = htonl(text->seqnum);
    memcpy(out, &tmpnum, 4);	/* 4 bytes = seq # */

    (*outputlen)+=4; /* for seqnum */

    /* put the 1st 4 bytes in */
    tmp=htonl(*outputlen);
    memcpy(text->encode_buf, &tmp, 4);

    (*outputlen)+=4;

    *output = text->encode_buf;
    text->seqnum++;

    return SASL_OK;
}

static int
digestmd5_privacy_decode_once(void *context,
			      const char **input,
			      unsigned *inputlen,
			      char **output,
			      unsigned *outputlen)
{
    context_t *text = (context_t *) context;
    unsigned int tocopy;
    unsigned diff;
    int result;
    unsigned char digest[16];
    int tmpnum;
    int lup;

    if (text->needsize>0) /* 4 bytes for how long message is */
	{
	    /* if less than 4 bytes just copy those we have into text->size */
	    if (*inputlen<4)
		tocopy=*inputlen;
	    else
		tocopy=4;

	    if (tocopy>text->needsize)
		tocopy=text->needsize;

	    memcpy(text->sizebuf+4-text->needsize, *input, tocopy);
	    text->needsize-=tocopy;

	    *input+=tocopy;
	    *inputlen-=tocopy;

	    if (text->needsize==0) /* got all of size */
	    {
		memcpy(&(text->size), text->sizebuf, 4);
		text->cursize=0;
		text->size=ntohl(text->size);

		if (text->size > text->in_maxbuf) {
		    return SASL_FAIL; /* too big probably error */
		}

		if(!text->buffer)
		    text->buffer=text->utils->malloc(text->size+5);
		else
		    text->buffer=text->utils->realloc(text->buffer,
						      text->size+5);
		if (text->buffer == NULL) return SASL_NOMEM;
	    }

	    *outputlen=0;
	    *output=NULL;
	    if (*inputlen==0) /* have to wait until next time for data */
		return SASL_OK;

	    if (text->size==0)  /* should never happen */
		return SASL_FAIL;
	}

    diff=text->size - text->cursize; /* bytes need for full message */

    if (! text->buffer)
	return SASL_FAIL;

    if (*inputlen < diff) /* not enough for a decode */
    {
	memcpy(text->buffer+text->cursize, *input, *inputlen);
	text->cursize+=*inputlen;
	*inputlen=0;
	*outputlen=0;
	*output=NULL;
	return SASL_OK;
    } else {
	memcpy(text->buffer+text->cursize, *input, diff);
	*input+=diff;
	*inputlen-=diff;
    }

    {
	unsigned short ver;
	unsigned int seqnum;
	unsigned char checkdigest[16];

	result = _plug_buf_alloc(text->utils, &text->decode_once_buf,
				 &text->decode_once_buf_len,
				 text->size-6);
	if (result != SASL_OK)
	    return result;

	*output = text->decode_once_buf;
	*outputlen = *inputlen;

	result=text->cipher_dec(text,text->buffer,text->size-6,digest,
				*output, outputlen);

	if (result!=SASL_OK)
	    return result;

	{
	    int i;
	    for(i=10; i; i--) {
		memcpy(&ver, text->buffer+text->size-i,2);
		ver=ntohs(ver);
	    }
	}

	/* check the version number */
	memcpy(&ver, text->buffer+text->size-6, 2);
	ver=ntohs(ver);
	if (ver != version)
	{
#ifdef _INTEGRATED_SOLARIS_
	    text->utils->seterror(text->utils->conn, 0,
		gettext("Wrong Version"));
#else
	    text->utils->seterror(text->utils->conn, 0, "Wrong Version");
#endif /* _INTEGRATED_SOLARIS_ */
	    return SASL_FAIL;
	}

	/* check the CMAC */

	/* construct (seqnum, msg) */
	result = _plug_buf_alloc(text->utils, &text->decode_tmp_buf,
				 &text->decode_tmp_buf_len, *outputlen + 4);
	if(result != SASL_OK) return result;

	tmpnum = htonl(text->rec_seqnum);
	memcpy(text->decode_tmp_buf, &tmpnum, 4);
	memcpy(text->decode_tmp_buf + 4, *output, *outputlen);

	/* HMAC(ki, (seqnum, msg) ) */
	text->utils->hmac_md5((const unsigned char *) text->decode_tmp_buf,
			      (*outputlen) + 4,
			      text->Ki_receive, HASHLEN, checkdigest);

	/* now check it */
	for (lup=0;lup<10;lup++)
	    if (checkdigest[lup]!=digest[lup])
		{
#ifdef _SUN_SDK_
		    text->utils->log(text->utils->conn, SASL_LOG_ERR,
			"CMAC doesn't match at byte %d!", lup);
		    return SASL_BADMAC;
#else
		    text->utils->seterror(text->utils->conn, 0,
					  "CMAC doesn't match at byte %d!", lup);
		    return SASL_FAIL;
#endif /* _SUN_SDK_ */
		}

	/* check the sequence number */
	memcpy(&seqnum, text->buffer+text->size-4,4);
	seqnum=ntohl(seqnum);

	if (seqnum!=text->rec_seqnum)
	    {
#ifdef _SUN_SDK_
		text->utils->log(text->utils->conn, SASL_LOG_ERR,
				 "Incorrect Sequence Number");
#else
		text->utils->seterror(text->utils->conn, 0,
				      "Incorrect Sequence Number");
#endif /* _SUN_SDK_ */
		return SASL_FAIL;
	    }

	text->rec_seqnum++; /* now increment it */
    }

    text->needsize=4;

    return SASL_OK;
}

static int digestmd5_privacy_decode(void *context,
				    const char *input, unsigned inputlen,
				    const char **output, unsigned *outputlen)
{
    context_t *text = (context_t *) context;
    int ret;

    ret = _plug_decode(text->utils, context, input, inputlen,
		       &text->decode_buf, &text->decode_buf_len, outputlen,
		       digestmd5_privacy_decode_once);

    *output = text->decode_buf;

    return ret;
}

static int
digestmd5_integrity_encode(void *context,
			   const struct iovec *invec,
			   unsigned numiov,
			   const char **output,
			   unsigned *outputlen)
{
    context_t      *text = (context_t *) context;
    unsigned char   MAC[16];
    unsigned int    tmpnum;
    unsigned short int tmpshort;
    struct buffer_info *inblob, bufinfo;
    int ret;

    if(!context || !invec || !numiov || !output || !outputlen) {
	PARAMERROR( text->utils );
	return SASL_BADPARAM;
    }

    if (numiov > 1) {
	ret = _plug_iovec_to_buf(text->utils, invec, numiov,
				 &text->enc_in_buf);
	if (ret != SASL_OK) return ret;
	inblob = text->enc_in_buf;
    } else {
	/* avoid the data copy */
	bufinfo.data = invec[0].iov_base;
	bufinfo.curlen = invec[0].iov_len;
	inblob = &bufinfo;
    }

    /* construct output */
    *outputlen = 4 + inblob->curlen + 16;

    ret = _plug_buf_alloc(text->utils, &(text->encode_buf),
			  &(text->encode_buf_len), *outputlen);
    if(ret != SASL_OK) return ret;

    /* construct (seqnum, msg) */
    /* we can just use the output buffer */
    tmpnum = htonl(text->seqnum);
    memcpy(text->encode_buf, &tmpnum, 4);
    memcpy(text->encode_buf + 4, inblob->data, inblob->curlen);

    /* HMAC(ki, (seqnum, msg) ) */
#ifdef _SUN_SDK_
    text->utils->hmac_md5((unsigned char *)text->encode_buf,
			  inblob->curlen + 4,
			  text->Ki_send, HASHLEN, MAC);
#else
    text->utils->hmac_md5(text->encode_buf, inblob->curlen + 4,
			  text->Ki_send, HASHLEN, MAC);
#endif /* _SUN_SDK_ */

    /* create MAC */
    tmpshort = htons(version);
    memcpy(MAC + 10, &tmpshort, MAC_OFFS);	/* 2 bytes = version */

    tmpnum = htonl(text->seqnum);
    memcpy(MAC + 12, &tmpnum, 4);	/* 4 bytes = sequence number */

    /* copy into output */
    tmpnum = htonl((*outputlen) - 4);

    /* length of message in network byte order */
    memcpy(text->encode_buf, &tmpnum, 4);
    /* the message text */
    memcpy(text->encode_buf + 4, inblob->data, inblob->curlen);
    /* the MAC */
    memcpy(text->encode_buf + 4 + inblob->curlen, MAC, 16);

    text->seqnum++;		/* add one to sequence number */

    *output = text->encode_buf;

    return SASL_OK;
}

static int
create_MAC(context_t * text,
	   char *input,
	   int inputlen,
	   int seqnum,
	   unsigned char MAC[16])
{
    unsigned int    tmpnum;
    unsigned short int tmpshort;
    int ret;

    if (inputlen < 0)
	return SASL_FAIL;

    ret = _plug_buf_alloc(text->utils, &(text->MAC_buf),
			  &(text->MAC_buf_len), inputlen + 4);
    if(ret != SASL_OK) return ret;

    /* construct (seqnum, msg) */
    tmpnum = htonl(seqnum);
    memcpy(text->MAC_buf, &tmpnum, 4);
    memcpy(text->MAC_buf + 4, input, inputlen);

    /* HMAC(ki, (seqnum, msg) ) */
#ifdef _SUN_SDK_
    text->utils->hmac_md5((unsigned char *)text->MAC_buf, inputlen + 4,
			  text->Ki_receive, HASHLEN,
			  MAC);
#else
    text->utils->hmac_md5(text->MAC_buf, inputlen + 4,
			  text->Ki_receive, HASHLEN,
			  MAC);
#endif /* _SUN_SDK_ */

    /* create MAC */
    tmpshort = htons(version);
    memcpy(MAC + 10, &tmpshort, 2);	/* 2 bytes = version */

    tmpnum = htonl(seqnum);
    memcpy(MAC + 12, &tmpnum, 4);	/* 4 bytes = sequence number */

    return SASL_OK;
}

static int
check_integrity(context_t * text,
		char *buf, int bufsize,
		char **output, unsigned *outputlen)
{
    unsigned char MAC[16];
    int result;

    result = create_MAC(text, buf, bufsize - 16, text->rec_seqnum, MAC);
    if (result != SASL_OK)
	return result;

    /* make sure the MAC is right */
    if (strncmp((char *) MAC, buf + bufsize - 16, 16) != 0)
    {
#ifdef _SUN_SDK_
	text->utils->log(text->utils->conn, SASL_LOG_ERR,
			 "MAC doesn't match");
	return SASL_BADMAC;
#else
	text->utils->seterror(text->utils->conn, 0, "MAC doesn't match");
	return SASL_FAIL;
#endif /* _SUN_SDK_ */
    }

    text->rec_seqnum++;

    /* ok make output message */
    result = _plug_buf_alloc(text->utils, &text->decode_once_buf,
			     &text->decode_once_buf_len,
			     bufsize - 15);
    if (result != SASL_OK)
	return result;

    *output = text->decode_once_buf;
    memcpy(*output, buf, bufsize - 16);
    *outputlen = bufsize - 16;
    (*output)[*outputlen] = 0;

    return SASL_OK;
}

static int
digestmd5_integrity_decode_once(void *context,
				const char **input,
				unsigned *inputlen,
				char **output,
				unsigned *outputlen)
{
    context_t      *text = (context_t *) context;
    unsigned int    tocopy;
    unsigned        diff;
    int             result;

    if (text->needsize > 0) {	/* 4 bytes for how long message is */
	/*
	 * if less than 4 bytes just copy those we have into text->size
	 */
	if (*inputlen < 4)
	    tocopy = *inputlen;
	else
	    tocopy = 4;

	if (tocopy > text->needsize)
	    tocopy = text->needsize;

	memcpy(text->sizebuf + 4 - text->needsize, *input, tocopy);
	text->needsize -= tocopy;

	*input += tocopy;
	*inputlen -= tocopy;

	if (text->needsize == 0) {	/* got all of size */
	    memcpy(&(text->size), text->sizebuf, 4);
	    text->cursize = 0;
	    text->size = ntohl(text->size);

	    if (text->size > text->in_maxbuf)
		return SASL_FAIL;	/* too big probably error */

	    if(!text->buffer)
		text->buffer=text->utils->malloc(text->size+5);
	    else
		text->buffer=text->utils->realloc(text->buffer,text->size+5);
	    if (text->buffer == NULL) return SASL_NOMEM;
	}
	*outputlen = 0;
	*output = NULL;
	if (*inputlen == 0)		/* have to wait until next time for data */
	    return SASL_OK;

	if (text->size == 0)	/* should never happen */
	    return SASL_FAIL;
    }
    diff = text->size - text->cursize;	/* bytes need for full message */

    if(! text->buffer)
	return SASL_FAIL;

    if (*inputlen < diff) {	/* not enough for a decode */
	memcpy(text->buffer + text->cursize, *input, *inputlen);
	text->cursize += *inputlen;
	*inputlen = 0;
	*outputlen = 0;
	*output = NULL;
	return SASL_OK;
    } else {
	memcpy(text->buffer + text->cursize, *input, diff);
	*input += diff;
	*inputlen -= diff;
    }

    result = check_integrity(text, text->buffer, text->size,
			     output, outputlen);
    if (result != SASL_OK)
	return result;

    /* Reset State */
    text->needsize = 4;

    return SASL_OK;
}

static int digestmd5_integrity_decode(void *context,
				      const char *input, unsigned inputlen,
				      const char **output, unsigned *outputlen)
{
    context_t *text = (context_t *) context;
    int ret;

    ret = _plug_decode(text->utils, context, input, inputlen,
		       &text->decode_buf, &text->decode_buf_len, outputlen,
		       digestmd5_integrity_decode_once);

    *output = text->decode_buf;

    return ret;
}

static void
digestmd5_common_mech_dispose(void *conn_context, const sasl_utils_t *utils)
{
    context_t *text = (context_t *) conn_context;

    if (!text || !utils) return;

    if (text->authid) utils->free(text->authid);
    if (text->realm) utils->free(text->realm);
    if (text->nonce) utils->free(text->nonce);
    if (text->cnonce) utils->free(text->cnonce);

    if (text->cipher_free) text->cipher_free(text);

    /* free the stuff in the context */
    if (text->response_value) utils->free(text->response_value);

    if (text->buffer) utils->free(text->buffer);
    if (text->encode_buf) utils->free(text->encode_buf);
    if (text->decode_buf) utils->free(text->decode_buf);
    if (text->decode_once_buf) utils->free(text->decode_once_buf);
    if (text->decode_tmp_buf) utils->free(text->decode_tmp_buf);
    if (text->out_buf) utils->free(text->out_buf);
    if (text->MAC_buf) utils->free(text->MAC_buf);

    if (text->enc_in_buf) {
	if (text->enc_in_buf->data) utils->free(text->enc_in_buf->data);
	utils->free(text->enc_in_buf);
    }

    utils->free(conn_context);
}

static void
clear_reauth_entry(reauth_entry_t *reauth, enum Context_type type,
		   const sasl_utils_t *utils)
{
    if (!reauth) return;

    if (reauth->authid) utils->free(reauth->authid);
    if (reauth->realm) utils->free(reauth->realm);
    if (reauth->nonce) utils->free(reauth->nonce);
    if (reauth->cnonce) utils->free(reauth->cnonce);

    if (type == CLIENT) {
	if (reauth->u.c.serverFQDN) utils->free(reauth->u.c.serverFQDN);
    }

    memset(reauth, 0, sizeof(reauth_entry_t));
}

static void
digestmd5_common_mech_free(void *glob_context, const sasl_utils_t *utils)
{
    reauth_cache_t *reauth_cache = (reauth_cache_t *) glob_context;
    size_t n;

    if (!reauth_cache) return;

    for (n = 0; n < reauth_cache->size; n++)
	clear_reauth_entry(&reauth_cache->e[n], reauth_cache->i_am, utils);
    if (reauth_cache->e) utils->free(reauth_cache->e);

    if (reauth_cache->mutex) utils->mutex_free(reauth_cache->mutex);

    utils->free(reauth_cache);
}

/*****************************  Server Section  *****************************/

typedef struct server_context {
    context_t common;

    time_t timestamp;
    int stale;				/* last nonce is stale */
    sasl_ssf_t limitssf, requiressf;	/* application defined bounds */
} server_context_t;

static void
DigestCalcHA1FromSecret(context_t * text,
			const sasl_utils_t * utils,
			HASH HA1,
			unsigned char *authorization_id,
			unsigned char *pszNonce,
			unsigned char *pszCNonce,
			HASHHEX SessionKey)
{
    MD5_CTX Md5Ctx;

    /* calculate session key */
    utils->MD5Init(&Md5Ctx);
    utils->MD5Update(&Md5Ctx, HA1, HASHLEN);
    utils->MD5Update(&Md5Ctx, COLON, 1);
    utils->MD5Update(&Md5Ctx, pszNonce, strlen((char *) pszNonce));
    utils->MD5Update(&Md5Ctx, COLON, 1);
    utils->MD5Update(&Md5Ctx, pszCNonce, strlen((char *) pszCNonce));
    if (authorization_id != NULL) {
	utils->MD5Update(&Md5Ctx, COLON, 1);
	utils->MD5Update(&Md5Ctx, authorization_id, strlen((char *) authorization_id));
    }
    utils->MD5Final(HA1, &Md5Ctx);

    CvtHex(HA1, SessionKey);


    /* save HA1 because we need it to make the privacy and integrity keys */
    memcpy(text->HA1, HA1, sizeof(HASH));
}

static char *create_response(context_t * text,
			     const sasl_utils_t * utils,
			     unsigned char *nonce,
			     unsigned int ncvalue,
			     unsigned char *cnonce,
			     char *qop,
			     char *digesturi,
			     HASH Secret,
			     char *authorization_id,
			     char **response_value)
{
    HASHHEX         SessionKey;
    HASHHEX         HEntity = "00000000000000000000000000000000";
    HASHHEX         Response;
    char           *result;

    if (qop == NULL)
	qop = "auth";

    DigestCalcHA1FromSecret(text,
			    utils,
			    Secret,
			    (unsigned char *) authorization_id,
			    nonce,
			    cnonce,
			    SessionKey);

    DigestCalcResponse(utils,
		       SessionKey,/* H(A1) */
		       nonce,	/* nonce from server */
		       ncvalue,	/* 8 hex digits */
		       cnonce,	/* client nonce */
		       (unsigned char *) qop,	/* qop-value: "", "auth",
						 * "auth-int" */
		       (unsigned char *) digesturi,	/* requested URL */
		       (unsigned char *) "AUTHENTICATE",
		       HEntity,	/* H(entity body) if qop="auth-int" */
		       Response	/* request-digest or response-digest */
	);

    result = utils->malloc(HASHHEXLEN + 1);
#ifdef _SUN_SDK_
    if (result == NULL)
	return NULL;
#endif /* _SUN_SDK_ */
/* TODO */
    memcpy(result, Response, HASHHEXLEN);
    result[HASHHEXLEN] = 0;

    /* response_value (used for reauth i think */
    if (response_value != NULL) {
	DigestCalcResponse(utils,
			   SessionKey,	/* H(A1) */
			   nonce,	/* nonce from server */
			   ncvalue,	/* 8 hex digits */
			   cnonce,	/* client nonce */
			   (unsigned char *) qop,	/* qop-value: "", "auth",
							 * "auth-int" */
			   (unsigned char *) digesturi,	/* requested URL */
			   NULL,
			   HEntity,	/* H(entity body) if qop="auth-int" */
			   Response	/* request-digest or response-digest */
	    );

	*response_value = utils->malloc(HASHHEXLEN + 1);
	if (*response_value == NULL)
	    return NULL;
	memcpy(*response_value, Response, HASHHEXLEN);
	(*response_value)[HASHHEXLEN] = 0;
    }
    return result;
}

static int
get_server_realm(sasl_server_params_t * params,
		 char **realm)
{
    /* look at user realm first */
    if (params->user_realm != NULL) {
	if(params->user_realm[0] != '\0') {
	    *realm = (char *) params->user_realm;
	} else {
	    /* Catch improperly converted apps */
#ifdef _SUN_SDK_
	    params->utils->log(params->utils->conn, SASL_LOG_ERR,
			       "user_realm is an empty string!");
#else
	    params->utils->seterror(params->utils->conn, 0,
				    "user_realm is an empty string!");
#endif /* _SUN_SDK_ */
	    return SASL_BADPARAM;
	}
    } else if (params->serverFQDN != NULL) {
	*realm = (char *) params->serverFQDN;
    } else {
#ifdef _SUN_SDK_
	params->utils->log(params->utils->conn, SASL_LOG_ERR,
			   "no way to obtain domain");
#else
	params->utils->seterror(params->utils->conn, 0,
				"no way to obtain domain");
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }

    return SASL_OK;
}

/*
 * Convert hex string to int
 */
static int htoi(unsigned char *hexin, unsigned int *res)
{
    int             lup, inlen;
    inlen = strlen((char *) hexin);

    *res = 0;
    for (lup = 0; lup < inlen; lup++) {
	switch (hexin[lup]) {
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	    *res = (*res << 4) + (hexin[lup] - '0');
	    break;

	case 'a':
	case 'b':
	case 'c':
	case 'd':
	case 'e':
	case 'f':
	    *res = (*res << 4) + (hexin[lup] - 'a' + 10);
	    break;

	case 'A':
	case 'B':
	case 'C':
	case 'D':
	case 'E':
	case 'F':
	    *res = (*res << 4) + (hexin[lup] - 'A' + 10);
	    break;

	default:
	    return SASL_BADPARAM;
	}

    }

    return SASL_OK;
}

static int digestmd5_server_mech_new(void *glob_context,
				     sasl_server_params_t * sparams,
				     const char *challenge __attribute__((unused)),
				     unsigned challen __attribute__((unused)),
				     void **conn_context)
{
    context_t *text;

    /* holds state are in -- allocate server size */
    text = sparams->utils->malloc(sizeof(server_context_t));
    if (text == NULL)
	return SASL_NOMEM;
    memset(text, 0, sizeof(server_context_t));

    text->state = 1;
    text->i_am = SERVER;
    text->reauth = glob_context;

    *conn_context = text;
    return SASL_OK;
}

static int
digestmd5_server_mech_step1(server_context_t *stext,
			    sasl_server_params_t *sparams,
			    const char *clientin __attribute__((unused)),
			    unsigned clientinlen __attribute__((unused)),
			    const char **serverout,
			    unsigned *serveroutlen,
			    sasl_out_params_t * oparams __attribute__((unused)))
{
    context_t *text = (context_t *) stext;
    int             result;
    char           *realm;
    unsigned char  *nonce;
    char           *charset = "utf-8";
    char qop[1024], cipheropts[1024];
    struct digest_cipher *cipher;
    unsigned       resplen;
    int added_conf = 0;
    char maxbufstr[64];

    sparams->utils->log(sparams->utils->conn, SASL_LOG_DEBUG,
			"DIGEST-MD5 server step 1");

    /* get realm */
    result = get_server_realm(sparams, &realm);
    if(result != SASL_OK) return result;

    /* what options should we offer the client? */
    qop[0] = '\0';
    cipheropts[0] = '\0';
    if (stext->requiressf == 0) {
	if (*qop) strcat(qop, ",");
	strcat(qop, "auth");
    }
    if (stext->requiressf <= 1 && stext->limitssf >= 1) {
	if (*qop) strcat(qop, ",");
	strcat(qop, "auth-int");
    }

#ifdef USE_UEF_SERVER
    cipher = available_ciphers1;
#else
    cipher = available_ciphers;
#endif
    while (cipher->name) {
	/* do we allow this particular cipher? */
	if (stext->requiressf <= cipher->ssf &&
	    stext->limitssf >= cipher->ssf) {
	    if (!added_conf) {
		if (*qop) strcat(qop, ",");
		strcat(qop, "auth-conf");
		added_conf = 1;
	    }
#ifdef _SUN_SDK_
	    if(strlen(cipheropts) + strlen(cipher->name) + 1 >=
			sizeof (cipheropts)) {
		sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
		    "internal error: cipheropts too big");
		return SASL_FAIL;
	    }
#endif /* _SUN_SDK_ */
	    if (*cipheropts) strcat(cipheropts, ",");
	    strcat(cipheropts, cipher->name);
	}
	cipher++;
    }

    if (*qop == '\0') {
	/* we didn't allow anything?!? we'll return SASL_TOOWEAK, since
	   that's close enough */
	return SASL_TOOWEAK;
    }

    /*
     * digest-challenge  = 1#( realm | nonce | qop-options | stale | maxbuf |
     * charset | cipher-opts | auth-param )
     */

#ifndef _SUN_SDK_
    /* FIXME: get nonce XXX have to clean up after self if fail */
#endif /* !_SUN_SDK_ */
    nonce = create_nonce(sparams->utils);
    if (nonce == NULL) {
#ifdef _SUN_SDK_
	/* Note typo below */
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "internal error: failed creating a nonce");
#else
	SETERROR(sparams->utils, "internal erorr: failed creating a nonce");
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }

#ifdef _SUN_SDK_
    resplen = strlen((char *)nonce) + strlen("nonce") + 5;
#else
    resplen = strlen(nonce) + strlen("nonce") + 5;
#endif /* _SUN_SDK_ */
    result = _plug_buf_alloc(sparams->utils, &(text->out_buf),
			     &(text->out_buf_len), resplen);
#ifdef _SUN_SDK_
    if(result != SASL_OK) {
	sparams->utils->free(nonce);
	return result;
    }
#else
    if(result != SASL_OK) return result;
#endif /* _SUN_SDK_ */

    sprintf(text->out_buf, "nonce=\"%s\"", nonce);

    /* add to challenge; if we chose not to specify a realm, we won't
     * send one to the client */
    if (realm && add_to_challenge(sparams->utils,
				  &text->out_buf, &text->out_buf_len, &resplen,
				  "realm", (unsigned char *) realm,
				  TRUE) != SASL_OK) {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "internal error: add_to_challenge failed");
	sparams->utils->free(nonce);
#else
	SETERROR(sparams->utils, "internal error: add_to_challenge failed");
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }
    /*
     * qop-options A quoted string of one or more tokens indicating the
     * "quality of protection" values supported by the server.  The value
     * "auth" indicates authentication; the value "auth-int" indicates
     * authentication with integrity protection; the value "auth-conf"
     * indicates authentication with integrity protection and encryption.
     */

    /* add qop to challenge */
    if (add_to_challenge(sparams->utils,
			 &text->out_buf, &text->out_buf_len, &resplen,
			 "qop",
			 (unsigned char *) qop, TRUE) != SASL_OK) {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
		 "internal error: add_to_challenge 3 failed");
	sparams->utils->free(nonce);
#else
	SETERROR(sparams->utils, "internal error: add_to_challenge 3 failed");
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }

    /*
     *  Cipheropts - list of ciphers server supports
     */
    /* add cipher-opts to challenge; only add if there are some */
    if (strcmp(cipheropts,"")!=0)
	{
	    if (add_to_challenge(sparams->utils,
				 &text->out_buf, &text->out_buf_len, &resplen,
				 "cipher", (unsigned char *) cipheropts,
				 TRUE) != SASL_OK) {
#ifdef _SUN_SDK_
		sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			"internal error: add_to_challenge 4 failed");
		sparams->utils->free(nonce);
#else
		SETERROR(sparams->utils,
			 "internal error: add_to_challenge 4 failed");
#endif /* _SUN_SDK_ */
		return SASL_FAIL;
	    }
	}

    /* "stale" is true if a reauth failed because of a nonce timeout */
    if (stext->stale &&
	add_to_challenge(sparams->utils,
			 &text->out_buf, &text->out_buf_len, &resplen,
#ifdef _SUN_SDK_
			 "stale", (unsigned char *)"true", FALSE) != SASL_OK) {
	sparams->utils->free(nonce);
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "internal error: add_to_challenge failed");
#else
			 "stale", "true", FALSE) != SASL_OK) {
	SETERROR(sparams->utils, "internal error: add_to_challenge failed");
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }

    /*
     * maxbuf A number indicating the size of the largest buffer the server
     * is able to receive when using "auth-int". If this directive is
     * missing, the default value is 65536. This directive may appear at most
     * once; if multiple instances are present, the client should abort the
     * authentication exchange.
     */
    if(sparams->props.maxbufsize) {
	snprintf(maxbufstr, sizeof(maxbufstr), "%d",
		 sparams->props.maxbufsize);
	if (add_to_challenge(sparams->utils,
			     &text->out_buf, &text->out_buf_len, &resplen,
			     "maxbuf",
			     (unsigned char *) maxbufstr, FALSE) != SASL_OK) {
#ifdef _SUN_SDK_
	    sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
				"internal error: add_to_challenge 5 failed");
#else
	    SETERROR(sparams->utils,
		     "internal error: add_to_challenge 5 failed");
#endif /* _SUN_SDK_ */
	    return SASL_FAIL;
	}
    }


    if (add_to_challenge(sparams->utils,
			 &text->out_buf, &text->out_buf_len, &resplen,
			 "charset",
			 (unsigned char *) charset, FALSE) != SASL_OK) {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "internal error: add_to_challenge 6 failed");
	sparams->utils->free(nonce);
#else
	SETERROR(sparams->utils, "internal error: add_to_challenge 6 failed");
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }


    /*
     * algorithm
     *  This directive is required for backwards compatibility with HTTP
     *  Digest., which supports other algorithms. . This directive is
     *  required and MUST appear exactly once; if not present, or if multiple
     *  instances are present, the client should abort the authentication
     *  exchange.
     *
     * algorithm         = "algorithm" "=" "md5-sess"
     */

    if (add_to_challenge(sparams->utils,
			 &text->out_buf, &text->out_buf_len, &resplen,
			 "algorithm",
			 (unsigned char *) "md5-sess", FALSE)!=SASL_OK) {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "internal error: add_to_challenge 7 failed");
	sparams->utils->free(nonce);
#else
	SETERROR(sparams->utils, "internal error: add_to_challenge 7 failed");
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }

    /*
     * The size of a digest-challenge MUST be less than 2048 bytes!!!
     */
    if (*serveroutlen > 2048) {
#ifdef _SUN_SDK_
	sparams->utils->free(nonce);
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "internal error: challenge larger than 2048 bytes");
#else
	SETERROR(sparams->utils,
		 "internal error: challenge larger than 2048 bytes");
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }

    text->authid = NULL;
    _plug_strdup(sparams->utils, realm, &text->realm, NULL);
    text->nonce = nonce;
    text->nonce_count = 1;
    text->cnonce = NULL;
    stext->timestamp = time(0);

    *serveroutlen = strlen(text->out_buf);
    *serverout = text->out_buf;

    text->state = 2;

    return SASL_CONTINUE;
}

static int
digestmd5_server_mech_step2(server_context_t *stext,
			    sasl_server_params_t *sparams,
			    const char *clientin,
			    unsigned clientinlen,
			    const char **serverout,
			    unsigned *serveroutlen,
			    sasl_out_params_t * oparams)
{
    context_t *text = (context_t *) stext;
    /* verify digest */
    sasl_secret_t  *sec = NULL;
    int             result;
    char           *serverresponse = NULL;
    char           *username = NULL;
    char           *authorization_id = NULL;
    char           *realm = NULL;
    unsigned char  *nonce = NULL, *cnonce = NULL;
    unsigned int   noncecount = 0;
    char           *qop = NULL;
    char           *digesturi = NULL;
    char           *response = NULL;

    /* setting the default value (65536) */
    unsigned int    client_maxbuf = 65536;
    int             maxbuf_count = 0;  /* How many maxbuf instaces was found */

    char           *charset = NULL;
    char           *cipher = NULL;
    unsigned int   n=0;

    HASH            A1;

    /* password prop_request */
    const char *password_request[] = { SASL_AUX_PASSWORD,
				       "*cmusaslsecretDIGEST-MD5",
				       NULL };
    unsigned len;
    struct propval auxprop_values[2];

    /* can we mess with clientin? copy it to be safe */
    char           *in_start = NULL;
    char           *in = NULL;

    sparams->utils->log(sparams->utils->conn, SASL_LOG_DEBUG,
			"DIGEST-MD5 server step 2");

    in = sparams->utils->malloc(clientinlen + 1);
#ifdef _SUN_SDK_
    if (!in) return SASL_NOMEM;
#endif /* _SUN_SDK_ */

    memcpy(in, clientin, clientinlen);
    in[clientinlen] = 0;

    in_start = in;


    /* parse what we got */
    while (in[0] != '\0') {
	char           *name = NULL, *value = NULL;
	get_pair(&in, &name, &value);

	if (name == NULL)
	    break;

	/* Extracting parameters */

	/*
	 * digest-response  = 1#( username | realm | nonce | cnonce |
	 * nonce-count | qop | digest-uri | response | maxbuf | charset |
	 * cipher | auth-param )
	 */

	if (strcasecmp(name, "username") == 0) {
	    _plug_strdup(sparams->utils, value, &username, NULL);
	} else if (strcasecmp(name, "authzid") == 0) {
	    _plug_strdup(sparams->utils, value, &authorization_id, NULL);
	} else if (strcasecmp(name, "cnonce") == 0) {
	    _plug_strdup(sparams->utils, value, (char **) &cnonce, NULL);
	} else if (strcasecmp(name, "nc") == 0) {
	    if (htoi((unsigned char *) value, &noncecount) != SASL_OK) {
#ifdef _SUN_SDK_
		sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			 "error converting hex to int");
#else
		SETERROR(sparams->utils,
			 "error converting hex to int");
#endif /* _SUN_SDK_ */
		result = SASL_BADAUTH;
		goto FreeAllMem;
	    }
	} else if (strcasecmp(name, "realm") == 0) {
	    if (realm) {
#ifdef _SUN_SDK_
		sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
				    "duplicate realm: authentication aborted");
#else
		SETERROR(sparams->utils,
			 "duplicate realm: authentication aborted");
#endif /* _SUN_SDK_ */
		result = SASL_FAIL;
		goto FreeAllMem;
	    }
	    _plug_strdup(sparams->utils, value, &realm, NULL);
	} else if (strcasecmp(name, "nonce") == 0) {
	    _plug_strdup(sparams->utils, value, (char **) &nonce, NULL);
	} else if (strcasecmp(name, "qop") == 0) {
	    _plug_strdup(sparams->utils, value, &qop, NULL);
	} else if (strcasecmp(name, "digest-uri") == 0) {
            size_t service_len;

	    /*
	     * digest-uri-value  = serv-type "/" host [ "/" serv-name ]
	     */

	    _plug_strdup(sparams->utils, value, &digesturi, NULL);

	    /* verify digest-uri format */

            /* make sure it's the service that we're expecting */
            service_len = strlen(sparams->service);
            if (strncasecmp(digesturi, sparams->service, service_len) ||
                digesturi[service_len] != '/') {
                result = SASL_BADAUTH;
#ifdef _SUN_SDK_
		sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
				    "bad digest-uri: doesn't match service");
#else
                SETERROR(sparams->utils,
                         "bad digest-uri: doesn't match service");
#endif /* _SUN_SDK_ */
                goto FreeAllMem;
            }

            /* xxx we don't verify the hostname component */

	} else if (strcasecmp(name, "response") == 0) {
	    _plug_strdup(sparams->utils, value, &response, NULL);
	} else if (strcasecmp(name, "cipher") == 0) {
	    _plug_strdup(sparams->utils, value, &cipher, NULL);
	} else if (strcasecmp(name, "maxbuf") == 0) {
	    maxbuf_count++;
	    if (maxbuf_count != 1) {
		result = SASL_BADAUTH;
#ifdef _SUN_SDK_
		sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
				    "duplicate maxbuf: authentication aborted");
#else
		SETERROR(sparams->utils,
			 "duplicate maxbuf: authentication aborted");
#endif /* _SUN_SDK_ */
		goto FreeAllMem;
	    } else if (sscanf(value, "%u", &client_maxbuf) != 1) {
		result = SASL_BADAUTH;
#ifdef _SUN_SDK_
		sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			"invalid maxbuf parameter");
#else
		SETERROR(sparams->utils, "invalid maxbuf parameter");
#endif /* _SUN_SDK_ */
		goto FreeAllMem;
	    } else {
		if (client_maxbuf <= 16) {
		    result = SASL_BADAUTH;
#ifdef _SUN_SDK_
		    sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
					"maxbuf parameter too small");
#else
		    SETERROR(sparams->utils,
			     "maxbuf parameter too small");
#endif /* _SUN_SDK_ */
		    goto FreeAllMem;
		}
	    }
	} else if (strcasecmp(name, "charset") == 0) {
	    if (strcasecmp(value, "utf-8") != 0) {
#ifdef _SUN_SDK_
		sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
				    "client doesn't support UTF-8");
#else
		SETERROR(sparams->utils, "client doesn't support UTF-8");
#endif /* _SUN_SDK_ */
		result = SASL_FAIL;
		goto FreeAllMem;
	    }
	    _plug_strdup(sparams->utils, value, &charset, NULL);
	} else {
	    sparams->utils->log(sparams->utils->conn, SASL_LOG_DEBUG,
				"DIGEST-MD5 unrecognized pair %s/%s: ignoring",
				name, value);
	}
    }

    /*
     * username         = "username" "=" <"> username-value <">
     * username-value   = qdstr-val cnonce           = "cnonce" "=" <">
     * cnonce-value <"> cnonce-value     = qdstr-val nonce-count      = "nc"
     * "=" nc-value nc-value         = 8LHEX qop              = "qop" "="
     * qop-value digest-uri = "digest-uri" "=" digest-uri-value
     * digest-uri-value  = serv-type "/" host [ "/" serv-name ] serv-type
     * = 1*ALPHA host             = 1*( ALPHA | DIGIT | "-" | "." ) service
     * = host response         = "response" "=" <"> response-value <">
     * response-value   = 32LHEX LHEX = "0" | "1" | "2" | "3" | "4" | "5" |
     * "6" | "7" | "8" | "9" | "a" | "b" | "c" | "d" | "e" | "f" cipher =
     * "cipher" "=" cipher-value
     */
    /* Verifing that all parameters was defined */
    if ((username == NULL) ||
	(nonce == NULL) ||
	(noncecount == 0) ||
	(cnonce == NULL) ||
	(digesturi == NULL) ||
	(response == NULL)) {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
		"required parameters missing");
#else
	SETERROR(sparams->utils, "required parameters missing");
#endif /* _SUN_SDK_ */
	result = SASL_BADAUTH;
	goto FreeAllMem;
    }

    if (text->state == 1) {
	unsigned val = hash(username) % text->reauth->size;

	/* reauth attempt, see if we have any info for this user */
	if (sparams->utils->mutex_lock(text->reauth->mutex) == SASL_OK) { /* LOCK */
	    if (text->reauth->e[val].authid &&
		!strcmp(username, text->reauth->e[val].authid)) {

		_plug_strdup(sparams->utils, text->reauth->e[val].realm,
			     &text->realm, NULL);
#ifdef _SUN_SDK_
		_plug_strdup(sparams->utils, (char *)text->reauth->e[val].nonce,
			     (char **) &text->nonce, NULL);
#else
		_plug_strdup(sparams->utils, text->reauth->e[val].nonce,
			     (char **) &text->nonce, NULL);
#endif /* _SUN_SDK_ */
		text->nonce_count = ++text->reauth->e[val].nonce_count;
#ifdef _SUN_SDK_
		_plug_strdup(sparams->utils, (char *)text->reauth->e[val].cnonce,
			     (char **) &text->cnonce, NULL);
#else
		_plug_strdup(sparams->utils, text->reauth->e[val].cnonce,
			     (char **) &text->cnonce, NULL);
#endif /* _SUN_SDK_ */
		stext->timestamp = text->reauth->e[val].u.s.timestamp;
	    }
	    sparams->utils->mutex_unlock(text->reauth->mutex); /* UNLOCK */
	}

	if (!text->nonce) {
	    /* we don't have any reauth info, so bail */
	    result = SASL_FAIL;
	    goto FreeAllMem;
	}
    }

    /* Sanity check the parameters */
#ifdef _SUN_SDK_
    if ((realm != NULL && text->realm != NULL &&
		strcmp(realm, text->realm) != 0) ||
	    (realm == NULL && text->realm != NULL) ||
	    (realm != NULL && text->realm == NULL)) {
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "realm changed: authentication aborted");
#else
    if (strcmp(realm, text->realm) != 0) {
	SETERROR(sparams->utils,
		 "realm changed: authentication aborted");
#endif /* _SUN_SDK_ */
	result = SASL_BADAUTH;
	goto FreeAllMem;
    }
#ifdef _SUN_SDK_
    if (strcmp((char *)nonce, (char *) text->nonce) != 0) {
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "nonce changed: authentication aborted");
#else
    if (strcmp(nonce, (char *) text->nonce) != 0) {
	SETERROR(sparams->utils,
		 "nonce changed: authentication aborted");
#endif /* _SUN_SKD_ */
	result = SASL_BADAUTH;
	goto FreeAllMem;
    }
    if (noncecount != text->nonce_count) {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "incorrect nonce-count: authentication aborted");
#else
	SETERROR(sparams->utils,
		 "incorrect nonce-count: authentication aborted");
#endif /* _SUN_SDK_ */
	result = SASL_BADAUTH;
	goto FreeAllMem;
    }
#ifdef _SUN_SDK_
    if (text->cnonce && strcmp((char *)cnonce, (char *)text->cnonce) != 0) {
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "cnonce changed: authentication aborted");
#else
    if (text->cnonce && strcmp(cnonce, text->cnonce) != 0) {
	SETERROR(sparams->utils,
		 "cnonce changed: authentication aborted");
#endif /* _SUN_SDK_ */
	result = SASL_BADAUTH;
	goto FreeAllMem;
    }

    result = sparams->utils->prop_request(sparams->propctx, password_request);
    if(result != SASL_OK) {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "unable to request user password");
#else
	SETERROR(sparams->utils, "unable to resquest user password");
#endif /* _SUN_SDK_ */
	goto FreeAllMem;
    }

    /* this will trigger the getting of the aux properties */
    /* Note that if we don't have an authorization id, we don't use it... */
    result = sparams->canon_user(sparams->utils->conn,
				 username, 0, SASL_CU_AUTHID, oparams);
    if (result != SASL_OK) {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "unable canonify user and get auxprops");
#else
	SETERROR(sparams->utils, "unable canonify user and get auxprops");
#endif /* _SUN_SDK_ */
	goto FreeAllMem;
    }

    if (!authorization_id || !*authorization_id) {
	result = sparams->canon_user(sparams->utils->conn,
				     username, 0, SASL_CU_AUTHZID, oparams);
    } else {
	result = sparams->canon_user(sparams->utils->conn,
				     authorization_id, 0, SASL_CU_AUTHZID,
				     oparams);
    }

    if (result != SASL_OK) {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "unable to canonicalize authorization ID");
#else
	SETERROR(sparams->utils, "unable authorization ID");
#endif /* _SUN_SDK_ */
	goto FreeAllMem;
    }

    result = sparams->utils->prop_getnames(sparams->propctx, password_request,
					   auxprop_values);
    if (result < 0 ||
       ((!auxprop_values[0].name || !auxprop_values[0].values) &&
	(!auxprop_values[1].name || !auxprop_values[1].values))) {
	/* We didn't find this username */
#ifdef _INTEGRATED_SOLARIS_
	sparams->utils->seterror(sparams->utils->conn, 0,
			gettext("no secret in database"));
#else
	sparams->utils->seterror(sparams->utils->conn, 0,
				 "no secret in database");
#endif /* _INTEGRATED_SOLARIS_ */
	result = SASL_NOUSER;
	goto FreeAllMem;
    }

    if (auxprop_values[0].name && auxprop_values[0].values) {
	len = strlen(auxprop_values[0].values[0]);
	if (len == 0) {
#ifdef _INTEGRATED_SOLARIS_
	    sparams->utils->seterror(sparams->utils->conn,0,
			gettext("empty secret"));
#else
	    sparams->utils->seterror(sparams->utils->conn,0,
				     "empty secret");
#endif /* _INTEGRATED_SOLARIS_ */
	    result = SASL_FAIL;
	    goto FreeAllMem;
	}

	sec = sparams->utils->malloc(sizeof(sasl_secret_t) + len);
	if (!sec) {
#ifdef _SUN_SDK_
	    sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
				"unable to allocate secret");
#else
	    SETERROR(sparams->utils, "unable to allocate secret");
#endif /* _SUN_SDK_ */
	    result = SASL_FAIL;
	    goto FreeAllMem;
	}

	sec->len = len;
#ifdef _SUN_SDK_
	strncpy((char *)sec->data, auxprop_values[0].values[0], len + 1);
#else
	strncpy(sec->data, auxprop_values[0].values[0], len + 1);
#endif /* _SUN_SDK_ */

	/*
	 * Verifying response obtained from client
	 *
	 * H_URP = H({ username-value,":",realm-value,":",passwd}) sec->data
	 * contains H_URP
	 */

	/* Calculate the secret from the plaintext password */
	{
	    HASH HA1;

#ifdef _SUN_SDK_
	    DigestCalcSecret(sparams->utils, (unsigned char *)username,
			     (unsigned char *)text->realm, sec->data,
			     sec->len, HA1);
#else
	    DigestCalcSecret(sparams->utils, username,
			     text->realm, sec->data, sec->len, HA1);
#endif /* _SUN_SDK_ */

	    /*
	     * A1 = { H( { username-value, ":", realm-value, ":", passwd } ),
	     * ":", nonce-value, ":", cnonce-value }
	     */

	    memcpy(A1, HA1, HASHLEN);
	    A1[HASHLEN] = '\0';
	}

	/* We're done with sec now. Let's get rid of it */
	_plug_free_secret(sparams->utils, &sec);
    } else if (auxprop_values[1].name && auxprop_values[1].values) {
	memcpy(A1, auxprop_values[1].values[0], HASHLEN);
	A1[HASHLEN] = '\0';
    } else {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "Have neither type of secret");
#else
	sparams->utils->seterror(sparams->utils->conn, 0,
				 "Have neither type of secret");
#endif /* _SUN_SDK_ */
#ifdef _SUN_SDK_
	result = SASL_FAIL;
	goto FreeAllMem;
#else
	return SASL_FAIL;
#endif /* _SUN_SDK_ */
    }

    /* defaulting qop to "auth" if not specified */
    if (qop == NULL) {
	_plug_strdup(sparams->utils, "auth", &qop, NULL);
    }

    /* check which layer/cipher to use */
    if ((!strcasecmp(qop, "auth-conf")) && (cipher != NULL)) {
	/* see what cipher was requested */
	struct digest_cipher *cptr;

#ifdef USE_UEF_SERVER
	cptr = available_ciphers1;
#else
	cptr = available_ciphers;
#endif
	while (cptr->name) {
	    /* find the cipher requested & make sure it's one we're happy
	       with by policy */
	    if (!strcasecmp(cipher, cptr->name) &&
		stext->requiressf <= cptr->ssf &&
		stext->limitssf >= cptr->ssf) {
		/* found it! */
		break;
	    }
	    cptr++;
	}

	if (cptr->name) {
	    text->cipher_enc = cptr->cipher_enc;
	    text->cipher_dec = cptr->cipher_dec;
	    text->cipher_init = cptr->cipher_init;
	    text->cipher_free = cptr->cipher_free;
	    oparams->mech_ssf = cptr->ssf;
	    n = cptr->n;
	} else {
	    /* erg? client requested something we didn't advertise! */
	    sparams->utils->log(sparams->utils->conn, SASL_LOG_WARN,
				"protocol violation: client requested invalid cipher");
#ifndef _SUN_SDK_
	    SETERROR(sparams->utils, "client requested invalid cipher");
#endif /* !_SUN_SDK_ */
	    /* Mark that we attempted security layer negotiation */
	    oparams->mech_ssf = 2;
	    result = SASL_FAIL;
	    goto FreeAllMem;
	}

	oparams->encode=&digestmd5_privacy_encode;
	oparams->decode=&digestmd5_privacy_decode;
    } else if (!strcasecmp(qop, "auth-int") &&
	       stext->requiressf <= 1 && stext->limitssf >= 1) {
	oparams->encode = &digestmd5_integrity_encode;
	oparams->decode = &digestmd5_integrity_decode;
	oparams->mech_ssf = 1;
    } else if (!strcasecmp(qop, "auth") && stext->requiressf == 0) {
	oparams->encode = NULL;
	oparams->decode = NULL;
	oparams->mech_ssf = 0;
    } else {
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "protocol violation: client requested invalid qop");
#else
	SETERROR(sparams->utils,
		 "protocol violation: client requested invalid qop");
#endif /* _SUN_SDK_ */
	result = SASL_FAIL;
	goto FreeAllMem;
    }

    serverresponse = create_response(text,
				     sparams->utils,
				     text->nonce,
				     text->nonce_count,
				     cnonce,
				     qop,
				     digesturi,
				     A1,
				     authorization_id,
				     &text->response_value);

    if (serverresponse == NULL) {
#ifndef _SUN_SDK_
	SETERROR(sparams->utils, "internal error: unable to create response");
#endif /* !_SUN_SDK_ */
	result = SASL_NOMEM;
	goto FreeAllMem;
    }

    /* if ok verified */
    if (strcmp(serverresponse, response) != 0) {
#ifdef _INTEGRATED_SOLARIS_
	SETERROR(sparams->utils,
		 gettext("client response doesn't match what we generated"));
#else
	SETERROR(sparams->utils,
		 "client response doesn't match what we generated");
#endif /* _INTEGRATED_SOLARIS_ */
	result = SASL_BADAUTH;

	goto FreeAllMem;
    }

    /* see if our nonce expired */
    if (text->reauth->timeout &&
	time(0) - stext->timestamp > text->reauth->timeout) {
#ifdef _INTEGRATED_SOLARIS_
	SETERROR(sparams->utils, gettext("server nonce expired"));
#else
	SETERROR(sparams->utils, "server nonce expired");
#endif /* _INTEGRATED_SOLARIS_ */
	stext->stale = 1;
	result = SASL_BADAUTH;

	goto FreeAllMem;
     }

    /*
     * nothing more to do; authenticated set oparams information
     */
    oparams->doneflag = 1;
    oparams->maxoutbuf = client_maxbuf - 4;
    if (oparams->mech_ssf > 1) {
#ifdef _SUN_SDK_
	if (oparams->maxoutbuf <= 25) {
	     result = SASL_BADPARAM;
	     goto FreeAllMem;
	}
#endif
	/* MAC block (privacy) */
	oparams->maxoutbuf -= 25;
    } else if(oparams->mech_ssf == 1) {
#ifdef _SUN_SDK_
	if (oparams->maxoutbuf <= 16) {
	     result = SASL_BADPARAM;
	     goto FreeAllMem;
	}
#endif
	/* MAC block (integrity) */
	oparams->maxoutbuf -= 16;
    }

    oparams->param_version = 0;

    text->seqnum = 0;		/* for integrity/privacy */
    text->rec_seqnum = 0;	/* for integrity/privacy */
    text->in_maxbuf =
       sparams->props.maxbufsize ? sparams->props.maxbufsize : DEFAULT_BUFSIZE;
    text->utils = sparams->utils;

    /* used by layers */
    text->needsize = 4;
    text->buffer = NULL;

    if (oparams->mech_ssf > 0) {
	char enckey[16];
	char deckey[16];

	create_layer_keys(text, sparams->utils,text->HA1,n,enckey,deckey);

	/* initialize cipher if need be */
#ifdef _SUN_SDK_
	if (text->cipher_init) {
	    if (text->cipher_free)
		text->cipher_free(text);
	    if ((result = text->cipher_init(text, enckey, deckey)) != SASL_OK) {
		sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
				"couldn't init cipher");
		goto FreeAllMem;
	    }
	}
#else
	if (text->cipher_init)
	    if (text->cipher_init(text, enckey, deckey) != SASL_OK) {
		sparams->utils->seterror(sparams->utils->conn, 0,
					 "couldn't init cipher");
	    }
#endif /* _SUN_SDK_ */
    }

    /*
     * The server receives and validates the "digest-response". The server
     * checks that the nonce-count is "00000001". If it supports subsequent
     * authentication, it saves the value of the nonce and the nonce-count.
     */

    /*
     * The "username-value", "realm-value" and "passwd" are encoded according
     * to the value of the "charset" directive. If "charset=UTF-8" is
     * present, and all the characters of either "username-value" or "passwd"
     * are in the ISO 8859-1 character set, then it must be converted to
     * UTF-8 before being hashed. A sample implementation of this conversion
     * is in section 8.
     */

    /* add to challenge */
    {
	unsigned resplen =
	    strlen(text->response_value) + strlen("rspauth") + 3;

	result = _plug_buf_alloc(sparams->utils, &(text->out_buf),
				 &(text->out_buf_len), resplen);
	if(result != SASL_OK) {
	    goto FreeAllMem;
	}

	sprintf(text->out_buf, "rspauth=%s", text->response_value);

	/* self check */
	if (strlen(text->out_buf) > 2048) {
	    result = SASL_FAIL;
	    goto FreeAllMem;
	}
    }

    *serveroutlen = strlen(text->out_buf);
    *serverout = text->out_buf;

    result = SASL_OK;

  FreeAllMem:
    if (text->reauth->timeout &&
	sparams->utils->mutex_lock(text->reauth->mutex) == SASL_OK) { /* LOCK */
	unsigned val = hash(username) % text->reauth->size;

	switch (result) {
	case SASL_OK:
	    /* successful auth, setup for future reauth */
	    if (text->nonce_count == 1) {
		/* successful initial auth, create new entry */
		clear_reauth_entry(&text->reauth->e[val], SERVER, sparams->utils);
		text->reauth->e[val].authid = username; username = NULL;
		text->reauth->e[val].realm = text->realm; text->realm = NULL;
		text->reauth->e[val].nonce = text->nonce; text->nonce = NULL;
		text->reauth->e[val].cnonce = cnonce; cnonce = NULL;
	    }
	    if (text->nonce_count <= text->reauth->e[val].nonce_count) {
		/* paranoia.  prevent replay attacks */
		clear_reauth_entry(&text->reauth->e[val], SERVER, sparams->utils);
	    }
	    else {
		text->reauth->e[val].nonce_count = text->nonce_count;
		text->reauth->e[val].u.s.timestamp = time(0);
	    }
	    break;
	default:
	    if (text->nonce_count > 1) {
		/* failed reauth, clear entry */
		clear_reauth_entry(&text->reauth->e[val], SERVER, sparams->utils);
	    }
	    else {
		/* failed initial auth, leave existing cache */
	    }
	}
	sparams->utils->mutex_unlock(text->reauth->mutex); /* UNLOCK */
    }

    /* free everything */
    if (in_start) sparams->utils->free (in_start);

    if (username != NULL)
	sparams->utils->free (username);
#ifdef _SUN_SDK_
    if (authorization_id != NULL)
	sparams->utils->free (authorization_id);
#endif /* _SUN_SDK_ */
    if (realm != NULL)
	sparams->utils->free (realm);
    if (nonce != NULL)
	sparams->utils->free (nonce);
    if (cnonce != NULL)
	sparams->utils->free (cnonce);
    if (response != NULL)
	sparams->utils->free (response);
    if (cipher != NULL)
	sparams->utils->free (cipher);
    if (serverresponse != NULL)
	sparams->utils->free(serverresponse);
    if (charset != NULL)
	sparams->utils->free (charset);
    if (digesturi != NULL)
	sparams->utils->free (digesturi);
    if (qop!=NULL)
	sparams->utils->free (qop);
    if (sec)
	_plug_free_secret(sparams->utils, &sec);

    return result;
}

static int
digestmd5_server_mech_step(void *conn_context,
			   sasl_server_params_t *sparams,
			   const char *clientin,
			   unsigned clientinlen,
			   const char **serverout,
			   unsigned *serveroutlen,
			   sasl_out_params_t *oparams)
{
    context_t *text = (context_t *) conn_context;
    server_context_t *stext = (server_context_t *) conn_context;

    if (clientinlen > 4096) return SASL_BADPROT;

    *serverout = NULL;
    *serveroutlen = 0;

    switch (text->state) {

    case 1:
	/* setup SSF limits */
	if (!sparams->props.maxbufsize) {
	    stext->limitssf = 0;
	    stext->requiressf = 0;
	} else {
	    if (sparams->props.max_ssf < sparams->external_ssf) {
		stext->limitssf = 0;
	    } else {
		stext->limitssf =
		    sparams->props.max_ssf - sparams->external_ssf;
	    }
	    if (sparams->props.min_ssf < sparams->external_ssf) {
		stext->requiressf = 0;
	    } else {
		stext->requiressf =
		    sparams->props.min_ssf - sparams->external_ssf;
	    }
	}

        if (clientin && text->reauth->timeout) {
	    /* here's where we attempt fast reauth if possible */
	    if (digestmd5_server_mech_step2(stext, sparams,
					    clientin, clientinlen,
					    serverout, serveroutlen,
					    oparams) == SASL_OK) {
		return SASL_OK;
	    }

#ifdef _SUN_SDK_
	    sparams->utils->log(sparams->utils->conn, SASL_LOG_WARN,
				"DIGEST-MD5 reauth failed");
#else
	    sparams->utils->log(NULL, SASL_LOG_WARN,
				"DIGEST-MD5 reauth failed\n");
#endif /* _SUN_SDK_ */

	    /* re-initialize everything for a fresh start */
	    memset(oparams, 0, sizeof(sasl_out_params_t));

	    /* fall through and issue challenge */
	}

	return digestmd5_server_mech_step1(stext, sparams,
					   clientin, clientinlen,
					   serverout, serveroutlen, oparams);

    case 2:
	return digestmd5_server_mech_step2(stext, sparams,
					   clientin, clientinlen,
					   serverout, serveroutlen, oparams);

    default:
#ifdef _SUN_SDK_
	sparams->utils->log(sparams->utils->conn, SASL_LOG_ERR,
			    "Invalid DIGEST-MD5 server step %d", text->state);
#else
	sparams->utils->log(NULL, SASL_LOG_ERR,
			    "Invalid DIGEST-MD5 server step %d\n", text->state);
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }

#ifndef _SUN_SDK_
    return SASL_FAIL; /* should never get here */
#endif /* !_SUN_SDK_ */
}

static void
digestmd5_server_mech_dispose(void *conn_context, const sasl_utils_t *utils)
{
    server_context_t *stext = (server_context_t *) conn_context;

    if (!stext || !utils) return;

    digestmd5_common_mech_dispose(conn_context, utils);
}

static sasl_server_plug_t digestmd5_server_plugins[] =
{
    {
	"DIGEST-MD5",			/* mech_name */
#ifdef WITH_RC4
	128,				/* max_ssf */
#elif WITH_DES
	112,
#else
	0,
#endif
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOANONYMOUS
	| SASL_SEC_MUTUAL_AUTH,		/* security_flags */
	SASL_FEAT_ALLOWS_PROXY,		/* features */
	NULL,				/* glob_context */
	&digestmd5_server_mech_new,	/* mech_new */
	&digestmd5_server_mech_step,	/* mech_step */
	&digestmd5_server_mech_dispose,	/* mech_dispose */
	&digestmd5_common_mech_free,	/* mech_free */
	NULL,				/* setpass */
	NULL,				/* user_query */
	NULL,				/* idle */
	NULL,				/* mech avail */
	NULL				/* spare */
    }
};

int digestmd5_server_plug_init(sasl_utils_t *utils,
			       int maxversion,
			       int *out_version,
			       sasl_server_plug_t **pluglist,
			       int *plugcount)
{
    reauth_cache_t *reauth_cache;
    const char *timeout = NULL;
    unsigned int len;
#if defined _SUN_SDK_  && defined USE_UEF
    int ret;
#endif /* _SUN_SDK_ && USE_UEF */

    if (maxversion < SASL_SERVER_PLUG_VERSION)
	return SASL_BADVERS;

#if defined _SUN_SDK_  && defined USE_UEF
    if ((ret = uef_init(utils)) != SASL_OK)
	return ret;
#endif /* _SUN_SDK_ && USE_UEF */

    /* reauth cache */
    reauth_cache = utils->malloc(sizeof(reauth_cache_t));
    if (reauth_cache == NULL)
	return SASL_NOMEM;
    memset(reauth_cache, 0, sizeof(reauth_cache_t));
    reauth_cache->i_am = SERVER;

    /* fetch and canonify the reauth_timeout */
    utils->getopt(utils->getopt_context, "DIGEST-MD5", "reauth_timeout",
		  &timeout, &len);
    if (timeout)
	reauth_cache->timeout = (time_t) 60 * strtol(timeout, NULL, 10);
#ifdef _SUN_SDK_
    else
	reauth_cache->timeout = 0;
#endif /* _SUN_SDK_ */
    if (reauth_cache->timeout < 0)
	reauth_cache->timeout = 0;

    if (reauth_cache->timeout) {
	/* mutex */
	reauth_cache->mutex = utils->mutex_alloc();
	if (!reauth_cache->mutex)
	    return SASL_FAIL;

	/* entries */
	reauth_cache->size = 100;
	reauth_cache->e = utils->malloc(reauth_cache->size *
					sizeof(reauth_entry_t));
	if (reauth_cache->e == NULL)
	    return SASL_NOMEM;
	memset(reauth_cache->e, 0, reauth_cache->size * sizeof(reauth_entry_t));
    }

    digestmd5_server_plugins[0].glob_context = reauth_cache;

#ifdef _SUN_SDK_
#ifdef USE_UEF_CLIENT
    digestmd5_server_plugins[0].max_ssf = uef_max_ssf;
#endif /* USE_UEF_CLIENT */
#endif /* _SUN_SDK_ */

#ifdef _INTEGRATED_SOLARIS_
    /*
     * Let libsasl know that we are a "Sun" plugin so that privacy
     * and integrity will be allowed.
     */
    REG_PLUG("DIGEST-MD5", digestmd5_server_plugins);
#endif /* _INTEGRATED_SOLARIS_ */

    *out_version = SASL_SERVER_PLUG_VERSION;
    *pluglist = digestmd5_server_plugins;
    *plugcount = 1;

    return SASL_OK;
}

/*****************************  Client Section  *****************************/

typedef struct client_context {
    context_t common;

    sasl_secret_t *password;	/* user password */
    unsigned int free_password; /* set if we need to free password */

    int protection;
    struct digest_cipher *cipher;
    unsigned int server_maxbuf;
#ifdef _INTEGRATED_SOLARIS_
    void *h;
#endif /* _INTEGRATED_SOLARIS_ */
} client_context_t;

/* calculate H(A1) as per spec */
static void
DigestCalcHA1(context_t * text,
	      const sasl_utils_t * utils,
	      unsigned char *pszUserName,
	      unsigned char *pszRealm,
	      sasl_secret_t * pszPassword,
	      unsigned char *pszAuthorization_id,
	      unsigned char *pszNonce,
	      unsigned char *pszCNonce,
	      HASHHEX SessionKey)
{
    MD5_CTX         Md5Ctx;
    HASH            HA1;

    DigestCalcSecret(utils,
		     pszUserName,
		     pszRealm,
		     (unsigned char *) pszPassword->data,
		     pszPassword->len,
		     HA1);

    /* calculate the session key */
    utils->MD5Init(&Md5Ctx);
    utils->MD5Update(&Md5Ctx, HA1, HASHLEN);
    utils->MD5Update(&Md5Ctx, COLON, 1);
    utils->MD5Update(&Md5Ctx, pszNonce, strlen((char *) pszNonce));
    utils->MD5Update(&Md5Ctx, COLON, 1);
    utils->MD5Update(&Md5Ctx, pszCNonce, strlen((char *) pszCNonce));
    if (pszAuthorization_id != NULL) {
	utils->MD5Update(&Md5Ctx, COLON, 1);
	utils->MD5Update(&Md5Ctx, pszAuthorization_id,
			 strlen((char *) pszAuthorization_id));
    }
    utils->MD5Final(HA1, &Md5Ctx);

    CvtHex(HA1, SessionKey);

    /* xxx rc-* use different n */

    /* save HA1 because we'll need it for the privacy and integrity keys */
    memcpy(text->HA1, HA1, sizeof(HASH));

}

static char *calculate_response(context_t * text,
				const sasl_utils_t * utils,
				unsigned char *username,
				unsigned char *realm,
				unsigned char *nonce,
				unsigned int ncvalue,
				unsigned char *cnonce,
				char *qop,
				unsigned char *digesturi,
				sasl_secret_t * passwd,
				unsigned char *authorization_id,
				char **response_value)
{
    HASHHEX         SessionKey;
    HASHHEX         HEntity = "00000000000000000000000000000000";
    HASHHEX         Response;
    char           *result;

    /* Verifing that all parameters was defined */
    if(!username || !cnonce || !nonce || !ncvalue || !digesturi || !passwd) {
	PARAMERROR( utils );
	return NULL;
    }

    if (realm == NULL) {
	/* a NULL realm is equivalent to the empty string */
	realm = (unsigned char *) "";
    }

    if (qop == NULL) {
	/* default to a qop of just authentication */
	qop = "auth";
    }

    DigestCalcHA1(text,
		  utils,
		  username,
		  realm,
		  passwd,
		  authorization_id,
		  nonce,
		  cnonce,
		  SessionKey);

    DigestCalcResponse(utils,
		       SessionKey,/* H(A1) */
		       nonce,	/* nonce from server */
		       ncvalue,	/* 8 hex digits */
		       cnonce,	/* client nonce */
		       (unsigned char *) qop,	/* qop-value: "", "auth",
						 * "auth-int" */
		       digesturi,	/* requested URL */
		       (unsigned char *) "AUTHENTICATE",
		       HEntity,	/* H(entity body) if qop="auth-int" */
		       Response	/* request-digest or response-digest */
	);

    result = utils->malloc(HASHHEXLEN + 1);
#ifdef _SUN_SDK_
    if (result == NULL)
	return NULL;
#endif /* _SUN_SDK_ */
    memcpy(result, Response, HASHHEXLEN);
    result[HASHHEXLEN] = 0;

    if (response_value != NULL) {
	DigestCalcResponse(utils,
			   SessionKey,	/* H(A1) */
			   nonce,	/* nonce from server */
			   ncvalue,	/* 8 hex digits */
			   cnonce,	/* client nonce */
			   (unsigned char *) qop,	/* qop-value: "", "auth",
							 * "auth-int" */
			   (unsigned char *) digesturi,	/* requested URL */
			   NULL,
			   HEntity,	/* H(entity body) if qop="auth-int" */
			   Response	/* request-digest or response-digest */
	    );

#ifdef _SUN_SDK_
	if (*response_value != NULL)
	    utils->free(*response_value);
#endif /* _SUN_SDK_ */
	*response_value = utils->malloc(HASHHEXLEN + 1);
	if (*response_value == NULL)
	    return NULL;

	memcpy(*response_value, Response, HASHHEXLEN);
	(*response_value)[HASHHEXLEN] = 0;

    }

    return result;
}

static int
make_client_response(context_t *text,
		     sasl_client_params_t *params,
		     sasl_out_params_t *oparams)
{
    client_context_t *ctext = (client_context_t *) text;
    char *qop = NULL;
    unsigned nbits = 0;
    unsigned char  *digesturi = NULL;
    bool            IsUTF8 = FALSE;
    char           ncvalue[10];
    char           maxbufstr[64];
    char           *response = NULL;
    unsigned        resplen = 0;
    int result;

    switch (ctext->protection) {
    case DIGEST_PRIVACY:
	qop = "auth-conf";
	oparams->encode = &digestmd5_privacy_encode;
	oparams->decode = &digestmd5_privacy_decode;
	oparams->mech_ssf = ctext->cipher->ssf;

	nbits = ctext->cipher->n;
	text->cipher_enc = ctext->cipher->cipher_enc;
	text->cipher_dec = ctext->cipher->cipher_dec;
	text->cipher_free = ctext->cipher->cipher_free;
	text->cipher_init = ctext->cipher->cipher_init;
	break;
    case DIGEST_INTEGRITY:
	qop = "auth-int";
	oparams->encode = &digestmd5_integrity_encode;
	oparams->decode = &digestmd5_integrity_decode;
	oparams->mech_ssf = 1;
	break;
    case DIGEST_NOLAYER:
    default:
	qop = "auth";
	oparams->encode = NULL;
	oparams->decode = NULL;
	oparams->mech_ssf = 0;
    }

    digesturi = params->utils->malloc(strlen(params->service) + 1 +
				      strlen(params->serverFQDN) + 1 +
				      1);
    if (digesturi == NULL) {
	result = SASL_NOMEM;
	goto FreeAllocatedMem;
    };

    /* allocated exactly this. safe */
    strcpy((char *) digesturi, params->service);
    strcat((char *) digesturi, "/");
    strcat((char *) digesturi, params->serverFQDN);
    /*
     * strcat (digesturi, "/"); strcat (digesturi, params->serverFQDN);
     */

    /* response */
    response =
	calculate_response(text,
			   params->utils,
#ifdef _SUN_SDK_
			   (unsigned char *) oparams->authid,
#else
			   (char *) oparams->authid,
#endif /* _SUN_SDK_ */
			   (unsigned char *) text->realm,
			   text->nonce,
			   text->nonce_count,
			   text->cnonce,
			   qop,
			   digesturi,
			   ctext->password,
			   strcmp(oparams->user, oparams->authid) ?
#ifdef _SUN_SDK_
			   (unsigned char *) oparams->user : NULL,
#else
			   (char *) oparams->user : NULL,
#endif /* _SUN_SDK_ */
			   &text->response_value);

#ifdef _SUN_SDK_
    if (response == NULL) {
	result = SASL_NOMEM;
	goto FreeAllocatedMem;
    }
#endif /* _SUN_SDK_ */

    resplen = strlen(oparams->authid) + strlen("username") + 5;
    result =_plug_buf_alloc(params->utils, &(text->out_buf),
			    &(text->out_buf_len),
			    resplen);
    if (result != SASL_OK) goto FreeAllocatedMem;

    sprintf(text->out_buf, "username=\"%s\"", oparams->authid);

    if (add_to_challenge(params->utils,
			 &text->out_buf, &text->out_buf_len, &resplen,
			 "realm", (unsigned char *) text->realm,
			 TRUE) != SASL_OK) {
	result = SASL_FAIL;
	goto FreeAllocatedMem;
    }
    if (strcmp(oparams->user, oparams->authid)) {
	if (add_to_challenge(params->utils,
			     &text->out_buf, &text->out_buf_len, &resplen,
#ifdef _SUN_SDK_
			     "authzid", (unsigned char *) oparams->user,
			     TRUE) != SASL_OK) {
#else
			     "authzid", (char *) oparams->user, TRUE) != SASL_OK) {
#endif /* _SUN_SDK_ */
	    result = SASL_FAIL;
	    goto FreeAllocatedMem;
	}
    }
    if (add_to_challenge(params->utils,
			 &text->out_buf, &text->out_buf_len, &resplen,
			 "nonce", text->nonce, TRUE) != SASL_OK) {
	result = SASL_FAIL;
	goto FreeAllocatedMem;
    }
    if (add_to_challenge(params->utils,
			 &text->out_buf, &text->out_buf_len, &resplen,
			 "cnonce", text->cnonce, TRUE) != SASL_OK) {
	result = SASL_FAIL;
	goto FreeAllocatedMem;
    }
    snprintf(ncvalue, sizeof(ncvalue), "%08x", text->nonce_count);
    if (add_to_challenge(params->utils,
			 &text->out_buf, &text->out_buf_len, &resplen,
			 "nc", (unsigned char *) ncvalue, FALSE) != SASL_OK) {
	result = SASL_FAIL;
	goto FreeAllocatedMem;
    }
    if (add_to_challenge(params->utils,
			 &text->out_buf, &text->out_buf_len, &resplen,
			 "qop", (unsigned char *) qop, FALSE) != SASL_OK) {
	result = SASL_FAIL;
	goto FreeAllocatedMem;
    }
    if (ctext->cipher != NULL) {
	if (add_to_challenge(params->utils,
			     &text->out_buf, &text->out_buf_len, &resplen,
			     "cipher",
			     (unsigned char *) ctext->cipher->name,
			     TRUE) != SASL_OK) {
	    result = SASL_FAIL;
	    goto FreeAllocatedMem;
	}
    }

    if (params->props.maxbufsize) {
	snprintf(maxbufstr, sizeof(maxbufstr), "%d", params->props.maxbufsize);
	if (add_to_challenge(params->utils,
			     &text->out_buf, &text->out_buf_len, &resplen,
			     "maxbuf", (unsigned char *) maxbufstr,
			     FALSE) != SASL_OK) {
#ifdef _SUN_SDK_
	    params->utils->log(params->utils->conn, SASL_LOG_ERR,
		     "internal error: add_to_challenge maxbuf failed");
#else
	    SETERROR(params->utils,
		     "internal error: add_to_challenge maxbuf failed");
#endif /* _SUN_SDK_ */
	    goto FreeAllocatedMem;
	}
    }

    if (IsUTF8) {
	if (add_to_challenge(params->utils,
			     &text->out_buf, &text->out_buf_len, &resplen,
			     "charset", (unsigned char *) "utf-8",
			     FALSE) != SASL_OK) {
	    result = SASL_FAIL;
	    goto FreeAllocatedMem;
	}
    }
    if (add_to_challenge(params->utils,
			 &text->out_buf, &text->out_buf_len, &resplen,
			 "digest-uri", digesturi, TRUE) != SASL_OK) {
	result = SASL_FAIL;
	goto FreeAllocatedMem;
    }
    if (add_to_challenge(params->utils,
			 &text->out_buf, &text->out_buf_len, &resplen,
			 "response", (unsigned char *) response,
			 FALSE) != SASL_OK) {

	result = SASL_FAIL;
	goto FreeAllocatedMem;
    }

    /* self check */
    if (strlen(text->out_buf) > 2048) {
	result = SASL_FAIL;
	goto FreeAllocatedMem;
    }

    /* set oparams */
#ifdef _SUN_SDK_
    oparams->maxoutbuf = ctext->server_maxbuf - 4;
#else
    oparams->maxoutbuf = ctext->server_maxbuf;
#endif /* _SUN_SDK_ */
    if(oparams->mech_ssf > 1) {
#ifdef _SUN_SDK_
	if (oparams->maxoutbuf <= 25)
	     return (SASL_BADPARAM);
#endif
	/* MAC block (privacy) */
	oparams->maxoutbuf -= 25;
    } else if(oparams->mech_ssf == 1) {
#ifdef _SUN_SDK_
	if (oparams->maxoutbuf <= 16)
	     return (SASL_BADPARAM);
#endif
	/* MAC block (integrity) */
	oparams->maxoutbuf -= 16;
    }

    text->seqnum = 0;	/* for integrity/privacy */
    text->rec_seqnum = 0;	/* for integrity/privacy */
    text->utils = params->utils;

    text->in_maxbuf =
	params->props.maxbufsize ? params->props.maxbufsize : DEFAULT_BUFSIZE;

    /* used by layers */
    text->needsize = 4;
    text->buffer = NULL;

    if (oparams->mech_ssf > 0) {
	char enckey[16];
	char deckey[16];

	create_layer_keys(text, params->utils, text->HA1, nbits,
			  enckey, deckey);

	/* initialize cipher if need be */
#ifdef _SUN_SDK_
	if (text->cipher_init) {
	    if (text->cipher_free)
		text->cipher_free(text);
	    if((result = text->cipher_init(text, enckey, deckey)) != SASL_OK) {
		params->utils->log(params->utils->conn, SASL_LOG_ERR,
					"couldn't init cipher");
		goto FreeAllocatedMem;
	    }
	}
#else
	if (text->cipher_init)
	    text->cipher_init(text, enckey, deckey);
#endif /* _SUN_SDK_ */
    }

    result = SASL_OK;

  FreeAllocatedMem:
    if (digesturi) params->utils->free(digesturi);
    if (response) params->utils->free(response);

    return result;
}

static int parse_server_challenge(client_context_t *ctext,
				  sasl_client_params_t *params,
				  const char *serverin, unsigned serverinlen,
				  char ***outrealms, int *noutrealm)
{
    context_t *text = (context_t *) ctext;
    int result = SASL_OK;
    char *in_start = NULL;
    char *in = NULL;
    char **realms = NULL;
    int nrealm = 0;
    sasl_ssf_t limit, musthave = 0;
    sasl_ssf_t external;
    int protection = 0;
    int ciphers = 0;
    int maxbuf_count = 0;
#ifndef _SUN_SDK_
    bool IsUTF8 = FALSE;
#endif /* !_SUN_SDK_ */
    int algorithm_count = 0;

    if (!serverin || !serverinlen) {
#ifndef _SUN_SDK_
	params->utils->log(params->utils->conn, SASL_LOG_ERR,
				"no server challenge");
#else
	params->utils->seterror(params->utils->conn, 0,
				"no server challenge");
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }

    in_start = in = params->utils->malloc(serverinlen + 1);
    if (in == NULL) return SASL_NOMEM;

    memcpy(in, serverin, serverinlen);
    in[serverinlen] = 0;

    ctext->server_maxbuf = 65536; /* Default value for maxbuf */

    /* create a new cnonce */
    text->cnonce = create_nonce(params->utils);
    if (text->cnonce == NULL) {
#ifdef _SUN_SDK_
	params->utils->log(params->utils->conn, SASL_LOG_ERR,
			   "failed to create cnonce");
#else
	params->utils->seterror(params->utils->conn, 0,
				"failed to create cnonce");
#endif /* _SUN_SDK_ */
	result = SASL_FAIL;
	goto FreeAllocatedMem;
    }

    /* parse the challenge */
    while (in[0] != '\0') {
	char *name, *value;

	get_pair(&in, &name, &value);

	/* if parse error */
	if (name == NULL) {
#ifdef _SUN_SDK_
	    params->utils->log(params->utils->conn, SASL_LOG_ERR,
			       "Parse error");
#else
	    params->utils->seterror(params->utils->conn, 0, "Parse error");
#endif /* _SUN_SDK_ */
	    result = SASL_FAIL;
	    goto FreeAllocatedMem;
	}

	if (strcasecmp(name, "realm") == 0) {
	    nrealm++;

	    if(!realms)
		realms = params->utils->malloc(sizeof(char *) * (nrealm + 1));
	    else
		realms = params->utils->realloc(realms,
						sizeof(char *) * (nrealm + 1));

	    if (realms == NULL) {
		result = SASL_NOMEM;
		goto FreeAllocatedMem;
	    }

	    _plug_strdup(params->utils, value, &realms[nrealm-1], NULL);
	    realms[nrealm] = NULL;
	} else if (strcasecmp(name, "nonce") == 0) {
	    _plug_strdup(params->utils, value, (char **) &text->nonce,
			 NULL);
	    text->nonce_count = 1;
	} else if (strcasecmp(name, "qop") == 0) {
	    while (value && *value) {
		char *comma = strchr(value, ',');
		if (comma != NULL) {
		    *comma++ = '\0';
		}

		if (strcasecmp(value, "auth-conf") == 0) {
		    protection |= DIGEST_PRIVACY;
		} else if (strcasecmp(value, "auth-int") == 0) {
		    protection |= DIGEST_INTEGRITY;
		} else if (strcasecmp(value, "auth") == 0) {
		    protection |= DIGEST_NOLAYER;
		} else {
		    params->utils->log(params->utils->conn, SASL_LOG_DEBUG,
				       "Server supports unknown layer: %s\n",
				       value);
		}

		value = comma;
	    }

	    if (protection == 0) {
		result = SASL_BADAUTH;
#ifdef _INTEGRATED_SOLARIS_
		params->utils->seterror(params->utils->conn, 0,
			gettext("Server doesn't support known qop level"));
#else
		params->utils->seterror(params->utils->conn, 0,
					"Server doesn't support known qop level");
#endif /* _INTEGRATED_SOLARIS_ */
		goto FreeAllocatedMem;
	    }
	} else if (strcasecmp(name, "cipher") == 0) {
	    while (value && *value) {
		char *comma = strchr(value, ',');
#ifdef USE_UEF_CLIENT
		struct digest_cipher *cipher = available_ciphers1;
#else
		struct digest_cipher *cipher = available_ciphers;
#endif

		if (comma != NULL) {
		    *comma++ = '\0';
		}

		/* do we support this cipher? */
		while (cipher->name) {
		    if (!strcasecmp(value, cipher->name)) break;
		    cipher++;
		}
		if (cipher->name) {
		    ciphers |= cipher->flag;
		} else {
		    params->utils->log(params->utils->conn, SASL_LOG_DEBUG,
				       "Server supports unknown cipher: %s\n",
				       value);
		}

		value = comma;
	    }
	} else if (strcasecmp(name, "stale") == 0 && ctext->password) {
	    /* clear any cached password */
	    if (ctext->free_password)
		_plug_free_secret(params->utils, &ctext->password);
	    ctext->password = NULL;
	} else if (strcasecmp(name, "maxbuf") == 0) {
	    /* maxbuf A number indicating the size of the largest
	     * buffer the server is able to receive when using
	     * "auth-int". If this directive is missing, the default
	     * value is 65536. This directive may appear at most once;
	     * if multiple instances are present, the client should
	     * abort the authentication exchange.
	     */
	    maxbuf_count++;

	    if (maxbuf_count != 1) {
		result = SASL_BADAUTH;
#ifdef _SUN_SDK_
		params->utils->log(params->utils->conn, SASL_LOG_ERR,
				   "At least two maxbuf directives found."
				   " Authentication aborted");
#else
		params->utils->seterror(params->utils->conn, 0,
					"At least two maxbuf directives found. Authentication aborted");
#endif /* _SUN_SDK_ */
		goto FreeAllocatedMem;
	    } else if (sscanf(value, "%u", &ctext->server_maxbuf) != 1) {
		result = SASL_BADAUTH;
#ifdef _SUN_SDK_
		params->utils->log(params->utils->conn, SASL_LOG_ERR,
			"Invalid maxbuf parameter received from server");
#else
		params->utils->seterror(params->utils->conn, 0,
					"Invalid maxbuf parameter received from server");
#endif /* _SUN_SDK_ */
		goto FreeAllocatedMem;
	    } else {
		if (ctext->server_maxbuf<=16) {
		    result = SASL_BADAUTH;
#ifdef _SUN_SDK_
		    params->utils->log(params->utils->conn, SASL_LOG_ERR,
			"Invalid maxbuf parameter received from server"
			" (too small: %s)", value);
#else
		    params->utils->seterror(params->utils->conn, 0,
					    "Invalid maxbuf parameter received from server (too small: %s)", value);
#endif /* _SUN_SDK_ */
		    goto FreeAllocatedMem;
		}
	    }
	} else if (strcasecmp(name, "charset") == 0) {
	    if (strcasecmp(value, "utf-8") != 0) {
		result = SASL_BADAUTH;
#ifdef _SUN_SDK_
		params->utils->log(params->utils->conn, SASL_LOG_ERR,
				   "Charset must be UTF-8");
#else
		params->utils->seterror(params->utils->conn, 0,
					"Charset must be UTF-8");
#endif /* _SUN_SDK_ */
		goto FreeAllocatedMem;
	    } else {
#ifndef _SUN_SDK_
		IsUTF8 = TRUE;
#endif /* !_SUN_SDK_ */
	    }
	} else if (strcasecmp(name,"algorithm")==0) {
	    if (strcasecmp(value, "md5-sess") != 0)
		{
#ifdef _SUN_SDK_
		    params->utils->log(params->utils->conn, SASL_LOG_ERR,
				"'algorithm' isn't 'md5-sess'");
#else
		    params->utils->seterror(params->utils->conn, 0,
					    "'algorithm' isn't 'md5-sess'");
#endif /* _SUN_SDK_ */
		    result = SASL_FAIL;
		    goto FreeAllocatedMem;
		}

	    algorithm_count++;
	    if (algorithm_count > 1)
		{
#ifdef _SUN_SDK_
		    params->utils->log(params->utils->conn, SASL_LOG_ERR,
				       "Must see 'algorithm' only once");
#else
		    params->utils->seterror(params->utils->conn, 0,
					    "Must see 'algorithm' only once");
#endif /* _SUN_SDK_ */
		    result = SASL_FAIL;
		    goto FreeAllocatedMem;
		}
	} else {
	    params->utils->log(params->utils->conn, SASL_LOG_DEBUG,
			       "DIGEST-MD5 unrecognized pair %s/%s: ignoring",
			       name, value);
	}
    }

    if (algorithm_count != 1) {
#ifdef _SUN_SDK_
	params->utils->log(params->utils->conn, SASL_LOG_ERR,
		"Must see 'algorithm' once. Didn't see at all");
#else
	params->utils->seterror(params->utils->conn, 0,
				"Must see 'algorithm' once. Didn't see at all");
#endif /* _SUN_SDK_ */
	result = SASL_FAIL;
	goto FreeAllocatedMem;
    }

    /* make sure we have everything we require */
    if (text->nonce == NULL) {
#ifdef _SUN_SDK_
	params->utils->log(params->utils->conn, SASL_LOG_ERR,
			   "Don't have nonce.");
#else
	params->utils->seterror(params->utils->conn, 0,
				"Don't have nonce.");
#endif /* _SUN_SDK_ */
	result = SASL_FAIL;
	goto FreeAllocatedMem;
    }

    /* get requested ssf */
    external = params->external_ssf;

    /* what do we _need_?  how much is too much? */
    if (params->props.maxbufsize == 0) {
	musthave = 0;
	limit = 0;
    } else {
	if (params->props.max_ssf > external) {
	    limit = params->props.max_ssf - external;
	} else {
	    limit = 0;
	}
	if (params->props.min_ssf > external) {
	    musthave = params->props.min_ssf - external;
	} else {
	    musthave = 0;
	}
    }

    /* we now go searching for an option that gives us at least "musthave"
       and at most "limit" bits of ssf. */
    if ((limit > 1) && (protection & DIGEST_PRIVACY)) {
	struct digest_cipher *cipher;

	/* let's find an encryption scheme that we like */
#ifdef USE_UEF_CLIENT
	cipher = available_ciphers1;
#else
	cipher = available_ciphers;
#endif
	while (cipher->name) {
	    /* examine each cipher we support, see if it meets our security
	       requirements, and see if the server supports it.
	       choose the best one of these */
	    if ((limit >= cipher->ssf) && (musthave <= cipher->ssf) &&
		(ciphers & cipher->flag) &&
		(!ctext->cipher || (cipher->ssf > ctext->cipher->ssf))) {
		ctext->cipher = cipher;
	    }
	    cipher++;
	}

	if (ctext->cipher) {
	    /* we found a cipher we like */
	    ctext->protection = DIGEST_PRIVACY;
	} else {
	    /* we didn't find any ciphers we like */
#ifdef _INTEGRATED_SOLARIS_
	    params->utils->seterror(params->utils->conn, 0,
				    gettext("No good privacy layers"));
#else
	    params->utils->seterror(params->utils->conn, 0,
				    "No good privacy layers");
#endif /* _INTEGRATED_SOLARIS_ */
	}
    }

    if (ctext->cipher == NULL) {
	/* we failed to find an encryption layer we liked;
	   can we use integrity or nothing? */

	if ((limit >= 1) && (musthave <= 1)
	    && (protection & DIGEST_INTEGRITY)) {
	    /* integrity */
	    ctext->protection = DIGEST_INTEGRITY;
#ifdef _SUN_SDK_
	} else if (musthave == 0) {
#else
	} else if (musthave <= 0) {
#endif /* _SUN_SDK_ */
	    /* no layer */
	    ctext->protection = DIGEST_NOLAYER;

	    /* See if server supports not having a layer */
	    if ((protection & DIGEST_NOLAYER) != DIGEST_NOLAYER) {
#ifdef _INTEGRATED_SOLARIS_
		params->utils->seterror(params->utils->conn, 0,
			gettext("Server doesn't support \"no layer\""));
#else
		params->utils->seterror(params->utils->conn, 0,
					"Server doesn't support \"no layer\"");
#endif /* _INTEGRATED_SOLARIS_ */
		result = SASL_FAIL;
		goto FreeAllocatedMem;
	    }
	} else {
#ifdef _INTEGRATED_SOLARIS_
	    params->utils->seterror(params->utils->conn, 0,
				    gettext("Can't find an acceptable layer"));
#else
	    params->utils->seterror(params->utils->conn, 0,
				    "Can't find an acceptable layer");
#endif /* _INTEGRATED_SOLARIS_ */
	    result = SASL_TOOWEAK;
	    goto FreeAllocatedMem;
	}
    }

    *outrealms = realms;
    *noutrealm = nrealm;

  FreeAllocatedMem:
    if (in_start) params->utils->free(in_start);

    if (result != SASL_OK && realms) {
	int lup;

	/* need to free all the realms */
	for (lup = 0;lup < nrealm; lup++)
	    params->utils->free(realms[lup]);

	params->utils->free(realms);
    }

    return result;
}

static int ask_user_info(client_context_t *ctext,
			 sasl_client_params_t *params,
			 char **realms, int nrealm,
			 sasl_interact_t **prompt_need,
			 sasl_out_params_t *oparams)
{
    context_t *text = (context_t *) ctext;
    int result = SASL_OK;
    const char *authid = NULL, *userid = NULL, *realm = NULL;
    char *realm_chal = NULL;
    int user_result = SASL_OK;
    int auth_result = SASL_OK;
    int pass_result = SASL_OK;
    int realm_result = SASL_FAIL;

    /* try to get the authid */
    if (oparams->authid == NULL) {
	auth_result = _plug_get_authid(params->utils, &authid, prompt_need);

	if ((auth_result != SASL_OK) && (auth_result != SASL_INTERACT)) {
	    return auth_result;
	}
    }

    /* try to get the userid */
    if (oparams->user == NULL) {
	user_result = _plug_get_userid(params->utils, &userid, prompt_need);

	if ((user_result != SASL_OK) && (user_result != SASL_INTERACT)) {
	    return user_result;
	}
    }

    /* try to get the password */
    if (ctext->password == NULL) {
	pass_result = _plug_get_password(params->utils, &ctext->password,
					 &ctext->free_password, prompt_need);
	if ((pass_result != SASL_OK) && (pass_result != SASL_INTERACT)) {
	    return pass_result;
	}
    }

    /* try to get the realm */
    if (text->realm == NULL) {
	if (realms) {
	    if(nrealm == 1) {
		/* only one choice */
		realm = realms[0];
		realm_result = SASL_OK;
	    } else {
		/* ask the user */
		realm_result = _plug_get_realm(params->utils,
					       (const char **) realms,
					       (const char **) &realm,
					       prompt_need);
	    }
	}

	/* fake the realm if we must */
	if ((realm_result != SASL_OK) && (realm_result != SASL_INTERACT)) {
	    if (params->serverFQDN) {
		realm = params->serverFQDN;
	    } else {
		return realm_result;
	    }
	}
    }

    /* free prompts we got */
    if (prompt_need && *prompt_need) {
	params->utils->free(*prompt_need);
	*prompt_need = NULL;
    }

    /* if there are prompts not filled in */
    if ((user_result == SASL_INTERACT) || (auth_result == SASL_INTERACT) ||
	(pass_result == SASL_INTERACT) || (realm_result == SASL_INTERACT)) {

	/* make our default realm */
	if ((realm_result == SASL_INTERACT) && params->serverFQDN) {
	    realm_chal = params->utils->malloc(3+strlen(params->serverFQDN));
	    if (realm_chal) {
		sprintf(realm_chal, "{%s}", params->serverFQDN);
	    } else {
		return SASL_NOMEM;
	    }
	}

	/* make the prompt list */
	result =
#if defined _INTEGRATED_SOLARIS_
	    _plug_make_prompts(params->utils, &ctext->h, prompt_need,
			       user_result == SASL_INTERACT ?
			       convert_prompt(params->utils, &ctext->h,
			       gettext("Please enter your authorization name"))
					: NULL,
			       NULL,
			       auth_result == SASL_INTERACT ?
			       convert_prompt(params->utils, &ctext->h,
			gettext("Please enter your authentication name"))
					: NULL,
			       NULL,
			       pass_result == SASL_INTERACT ?
			       convert_prompt(params->utils, &ctext->h,
					gettext("Please enter your password"))
					: NULL, NULL,
			       NULL, NULL, NULL,
			       realm_chal ? realm_chal : "{}",
			       realm_result == SASL_INTERACT ?
			       convert_prompt(params->utils, &ctext->h,
				    gettext("Please enter your realm")) : NULL,
			       params->serverFQDN ? params->serverFQDN : NULL);
#else
	    _plug_make_prompts(params->utils, prompt_need,
			       user_result == SASL_INTERACT ?
			       "Please enter your authorization name" : NULL,
			       NULL,
			       auth_result == SASL_INTERACT ?
			       "Please enter your authentication name" : NULL,
			       NULL,
			       pass_result == SASL_INTERACT ?
			       "Please enter your password" : NULL, NULL,
			       NULL, NULL, NULL,
			       realm_chal ? realm_chal : "{}",
			       realm_result == SASL_INTERACT ?
			       "Please enter your realm" : NULL,
			       params->serverFQDN ? params->serverFQDN : NULL);
#endif /* _INTEGRATED_SOLARIS_ */

	if (result == SASL_OK) return SASL_INTERACT;

	return result;
    }

    if (oparams->authid == NULL) {
	if (!userid || !*userid) {
	    result = params->canon_user(params->utils->conn, authid, 0,
					SASL_CU_AUTHID | SASL_CU_AUTHZID,
					oparams);
	}
	else {
	    result = params->canon_user(params->utils->conn,
					authid, 0, SASL_CU_AUTHID, oparams);
	    if (result != SASL_OK) return result;

	    result = params->canon_user(params->utils->conn,
					userid, 0, SASL_CU_AUTHZID, oparams);
	}
	if (result != SASL_OK) return result;
    }

    /* Get an allocated version of the realm into the structure */
    if (realm && text->realm == NULL) {
	_plug_strdup(params->utils, realm, (char **) &text->realm, NULL);
    }

    return result;
}

static int
digestmd5_client_mech_new(void *glob_context,
			  sasl_client_params_t * params,
			  void **conn_context)
{
    context_t *text;

    /* holds state are in -- allocate client size */
    text = params->utils->malloc(sizeof(client_context_t));
    if (text == NULL)
	return SASL_NOMEM;
    memset(text, 0, sizeof(client_context_t));

    text->state = 1;
    text->i_am = CLIENT;
    text->reauth = glob_context;

    *conn_context = text;

    return SASL_OK;
}

static int
digestmd5_client_mech_step1(client_context_t *ctext,
			    sasl_client_params_t *params,
			    const char *serverin __attribute__((unused)),
			    unsigned serverinlen __attribute__((unused)),
			    sasl_interact_t **prompt_need,
			    const char **clientout,
			    unsigned *clientoutlen,
			    sasl_out_params_t *oparams)
{
    context_t *text = (context_t *) ctext;
    int result = SASL_FAIL;
    unsigned val;

    params->utils->log(params->utils->conn, SASL_LOG_DEBUG,
		       "DIGEST-MD5 client step 1");

    result = ask_user_info(ctext, params, NULL, 0, prompt_need, oparams);
    if (result != SASL_OK) return result;

    /* check if we have cached info for this user on this server */
    val = hash(params->serverFQDN) % text->reauth->size;
    if (params->utils->mutex_lock(text->reauth->mutex) == SASL_OK) { /* LOCK */
	if (text->reauth->e[val].u.c.serverFQDN &&
	    !strcasecmp(text->reauth->e[val].u.c.serverFQDN,
			params->serverFQDN) &&
	    !strcmp(text->reauth->e[val].authid, oparams->authid)) {

#ifdef _SUN_SDK_
	    if (text->realm) params->utils->free(text->realm);
	    if (text->nonce) params->utils->free(text->nonce);
	    if (text->cnonce) params->utils->free(text->cnonce);
#endif /* _SUN_SDK_ */
	    /* we have info, so use it */
	    _plug_strdup(params->utils, text->reauth->e[val].realm,
			 &text->realm, NULL);
#ifdef _SUN_SDK_
	    _plug_strdup(params->utils, (char *)text->reauth->e[val].nonce,
			 (char **) &text->nonce, NULL);
#else
	    _plug_strdup(params->utils, text->reauth->e[val].nonce,
			 (char **) &text->nonce, NULL);
#endif /* _SUN_SDK_ */
	    text->nonce_count = ++text->reauth->e[val].nonce_count;
#ifdef _SUN_SDK_
	    _plug_strdup(params->utils, (char *)text->reauth->e[val].cnonce,
			 (char **) &text->cnonce, NULL);
#else
	    _plug_strdup(params->utils, text->reauth->e[val].cnonce,
			 (char **) &text->cnonce, NULL);
#endif /* _SUN_SDK_ */
	    ctext->protection = text->reauth->e[val].u.c.protection;
	    ctext->cipher = text->reauth->e[val].u.c.cipher;
	    ctext->server_maxbuf = text->reauth->e[val].u.c.server_maxbuf;
	}
	params->utils->mutex_unlock(text->reauth->mutex); /* UNLOCK */
    }

    if (!text->nonce) {
	/* we don't have any reauth info, so just return
	 * that there is no initial client send */
	text->state = 2;
	return SASL_CONTINUE;
    }

    /*
     * (username | realm | nonce | cnonce | nonce-count | qop digest-uri |
     * response | maxbuf | charset | auth-param )
     */

    result = make_client_response(text, params, oparams);
    if (result != SASL_OK) return result;

    *clientoutlen = strlen(text->out_buf);
    *clientout = text->out_buf;

    text->state = 3;
    return SASL_CONTINUE;
}

static int
digestmd5_client_mech_step2(client_context_t *ctext,
			    sasl_client_params_t *params,
			    const char *serverin,
			    unsigned serverinlen,
			    sasl_interact_t **prompt_need,
			    const char **clientout,
			    unsigned *clientoutlen,
			    sasl_out_params_t *oparams)
{
    context_t *text = (context_t *) ctext;
    int result = SASL_FAIL;
    char **realms = NULL;
    int nrealm = 0;

    params->utils->log(params->utils->conn, SASL_LOG_DEBUG,
		       "DIGEST-MD5 client step 2");

    if (params->props.min_ssf > params->props.max_ssf) {
	return SASL_BADPARAM;
    }

    /* don't bother parsing the challenge more than once */
    if (text->nonce == NULL) {
	result = parse_server_challenge(ctext, params, serverin, serverinlen,
					&realms, &nrealm);
	if (result != SASL_OK) goto FreeAllocatedMem;

	if (nrealm == 1) {
	    /* only one choice! */
	    text->realm = realms[0];

	    /* free realms */
	    params->utils->free(realms);
	    realms = NULL;
	}
    }

    result = ask_user_info(ctext, params, realms, nrealm,
			   prompt_need, oparams);
    if (result != SASL_OK) goto FreeAllocatedMem;

    /*
     * (username | realm | nonce | cnonce | nonce-count | qop digest-uri |
     * response | maxbuf | charset | auth-param )
     */

    result = make_client_response(text, params, oparams);
    if (result != SASL_OK) goto FreeAllocatedMem;

    *clientoutlen = strlen(text->out_buf);
    *clientout = text->out_buf;

    text->state = 3;

    result = SASL_CONTINUE;

  FreeAllocatedMem:
    if (realms) {
	int lup;

	/* need to free all the realms */
	for (lup = 0;lup < nrealm; lup++)
	    params->utils->free(realms[lup]);

	params->utils->free(realms);
    }

    return result;
}

static int
digestmd5_client_mech_step3(client_context_t *ctext,
			    sasl_client_params_t *params,
			    const char *serverin,
			    unsigned serverinlen,
			    sasl_interact_t **prompt_need __attribute__((unused)),
			    const char **clientout __attribute__((unused)),
			    unsigned *clientoutlen __attribute__((unused)),
			    sasl_out_params_t *oparams)
{
    context_t *text = (context_t *) ctext;
    char           *in = NULL;
    char           *in_start;
    int result = SASL_FAIL;

    params->utils->log(params->utils->conn, SASL_LOG_DEBUG,
		       "DIGEST-MD5 client step 3");

    /* Verify that server is really what they claim to be */
    in_start = in = params->utils->malloc(serverinlen + 1);
    if (in == NULL) return SASL_NOMEM;

    memcpy(in, serverin, serverinlen);
    in[serverinlen] = 0;

    /* parse the response */
    while (in[0] != '\0') {
	char *name, *value;
	get_pair(&in, &name, &value);

	if (name == NULL) {
#ifdef _SUN_SDK_
	    params->utils->log(params->utils->conn, SASL_LOG_ERR,
			       "DIGEST-MD5 Received Garbage");
#else
	    params->utils->seterror(params->utils->conn, 0,
				    "DIGEST-MD5 Received Garbage");
#endif /* _SUN_SDK_ */
	    break;
	}

	if (strcasecmp(name, "rspauth") == 0) {

	    if (strcmp(text->response_value, value) != 0) {
#ifdef _INTEGRATED_SOLARIS_
		params->utils->seterror(params->utils->conn, 0,
			gettext("Server authentication failed"));
#else
		params->utils->seterror(params->utils->conn, 0,
					"DIGEST-MD5: This server wants us to believe that he knows shared secret");
#endif /* _INTEGRATED_SOLARIS_ */
		result = SASL_FAIL;
	    } else {
		oparams->doneflag = 1;
		oparams->param_version = 0;

		result = SASL_OK;
	    }
	    break;
	} else {
	    params->utils->log(params->utils->conn, SASL_LOG_DEBUG,
			       "DIGEST-MD5 unrecognized pair %s/%s: ignoring",
			       name, value);
	}
    }

    params->utils->free(in_start);

    if (params->utils->mutex_lock(text->reauth->mutex) == SASL_OK) { /* LOCK */
	unsigned val = hash(params->serverFQDN) % text->reauth->size;
	switch (result) {
	case SASL_OK:
	    if (text->nonce_count == 1) {
		/* successful initial auth, setup for future reauth */
		clear_reauth_entry(&text->reauth->e[val], CLIENT, params->utils);
		_plug_strdup(params->utils, oparams->authid,
			     &text->reauth->e[val].authid, NULL);
		text->reauth->e[val].realm = text->realm; text->realm = NULL;
		text->reauth->e[val].nonce = text->nonce; text->nonce = NULL;
		text->reauth->e[val].nonce_count = text->nonce_count;
		text->reauth->e[val].cnonce = text->cnonce; text->cnonce = NULL;
		_plug_strdup(params->utils, params->serverFQDN,
			     &text->reauth->e[val].u.c.serverFQDN, NULL);
		text->reauth->e[val].u.c.protection = ctext->protection;
		text->reauth->e[val].u.c.cipher = ctext->cipher;
		text->reauth->e[val].u.c.server_maxbuf = ctext->server_maxbuf;
	    }
#ifndef _SUN_SDK_
	    else {
		/* reauth, we already incremented nonce_count */
	    }
#endif /* !_SUN_SDK_ */
	    break;
	default:
	    if (text->nonce_count > 1) {
		/* failed reauth, clear cache */
		clear_reauth_entry(&text->reauth->e[val], CLIENT, params->utils);
	    }
	    else {
		/* failed initial auth, leave existing cache */
	    }
	}
	params->utils->mutex_unlock(text->reauth->mutex); /* UNLOCK */
    }

    return result;
}

static int
digestmd5_client_mech_step(void *conn_context,
			   sasl_client_params_t *params,
			   const char *serverin,
			   unsigned serverinlen,
			   sasl_interact_t **prompt_need,
			   const char **clientout,
			   unsigned *clientoutlen,
			   sasl_out_params_t *oparams)
{
    context_t *text = (context_t *) conn_context;
    client_context_t *ctext = (client_context_t *) conn_context;
    unsigned val = hash(params->serverFQDN) % text->reauth->size;

    if (serverinlen > 2048) return SASL_BADPROT;

    *clientout = NULL;
    *clientoutlen = 0;

    switch (text->state) {

    case 1:
	if (!serverin) {
	    /* here's where we attempt fast reauth if possible */
	    int reauth = 0;

	    /* check if we have saved info for this server */
	    if (params->utils->mutex_lock(text->reauth->mutex) == SASL_OK) { /* LOCK */
		reauth = text->reauth->e[val].u.c.serverFQDN &&
		    !strcasecmp(text->reauth->e[val].u.c.serverFQDN,
				params->serverFQDN);
		params->utils->mutex_unlock(text->reauth->mutex); /* UNLOCK */
	    }
	    if (reauth) {
		return digestmd5_client_mech_step1(ctext, params,
						   serverin, serverinlen,
						   prompt_need,
						   clientout, clientoutlen,
						   oparams);
	    }
	    else {
		/* we don't have any reauth info, so just return
		 * that there is no initial client send */
		text->state = 2;
		return SASL_CONTINUE;
	    }
	}

	/* fall through and respond to challenge */

    case 3:
	if (serverin && !strncasecmp(serverin, "rspauth=", 8)) {
	    return digestmd5_client_mech_step3(ctext, params,
					       serverin, serverinlen,
					       prompt_need,
					       clientout, clientoutlen,
					       oparams);
	}

	/* fall through and respond to challenge */
	text->state = 2;

	/* cleanup after a failed reauth attempt */
	if (params->utils->mutex_lock(text->reauth->mutex) == SASL_OK) { /* LOCK */
	    clear_reauth_entry(&text->reauth->e[val], CLIENT, params->utils);

	    params->utils->mutex_unlock(text->reauth->mutex); /* UNLOCK */
	}

	if (text->realm) params->utils->free(text->realm);
	if (text->nonce) params->utils->free(text->nonce);
	if (text->cnonce) params->utils->free(text->cnonce);
#ifdef _SUN_SDK_
	text->realm = NULL;
	text->nonce = text->cnonce = NULL;
#else
	text->realm = text->nonce = text->cnonce = NULL;
#endif /* _SUN_SDK_ */
	ctext->cipher = NULL;

    case 2:
	return digestmd5_client_mech_step2(ctext, params,
					   serverin, serverinlen,
					   prompt_need,
					   clientout, clientoutlen,
					   oparams);

    default:
#ifdef _SUN_SDK_
	params->utils->log(params->utils->conn, SASL_LOG_ERR,
			   "Invalid DIGEST-MD5 client step %d", text->state);
#else
	params->utils->log(NULL, SASL_LOG_ERR,
			   "Invalid DIGEST-MD5 client step %d\n", text->state);
#endif /* _SUN_SDK_ */
	return SASL_FAIL;
    }

    return SASL_FAIL; /* should never get here */
}

static void
digestmd5_client_mech_dispose(void *conn_context, const sasl_utils_t *utils)
{
    client_context_t *ctext = (client_context_t *) conn_context;

    if (!ctext || !utils) return;

#ifdef _INTEGRATED_SOLARIS_
    convert_prompt(utils, &ctext->h, NULL);
#endif /* _INTEGRATED_SOLARIS_ */

    if (ctext->free_password) _plug_free_secret(utils, &ctext->password);

    digestmd5_common_mech_dispose(conn_context, utils);
}

static sasl_client_plug_t digestmd5_client_plugins[] =
{
    {
	"DIGEST-MD5",
#ifdef WITH_RC4				/* mech_name */
	128,				/* max ssf */
#elif WITH_DES
	112,
#else
	0,
#endif
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOANONYMOUS
	| SASL_SEC_MUTUAL_AUTH,		/* security_flags */
	SASL_FEAT_ALLOWS_PROXY, 	/* features */
	NULL,				/* required_prompts */
	NULL,				/* glob_context */
	&digestmd5_client_mech_new,	/* mech_new */
	&digestmd5_client_mech_step,	/* mech_step */
	&digestmd5_client_mech_dispose,	/* mech_dispose */
	&digestmd5_common_mech_free,	/* mech_free */
	NULL,				/* idle */
	NULL,				/* spare1 */
	NULL				/* spare2 */
    }
};

int digestmd5_client_plug_init(sasl_utils_t *utils,
			       int maxversion,
			       int *out_version,
			       sasl_client_plug_t **pluglist,
			       int *plugcount)
{
    reauth_cache_t *reauth_cache;
#if defined _SUN_SDK_  && defined USE_UEF
    int ret;
#endif /* _SUN_SDK_ && USE_UEF */

    if (maxversion < SASL_CLIENT_PLUG_VERSION)
	return SASL_BADVERS;

#if defined _SUN_SDK_  && defined USE_UEF
    if ((ret = uef_init(utils)) != SASL_OK)
	return ret;
#endif /* _SUN_SDK_ && USE_UEF */

    /* reauth cache */
    reauth_cache = utils->malloc(sizeof(reauth_cache_t));
    if (reauth_cache == NULL)
	return SASL_NOMEM;
    memset(reauth_cache, 0, sizeof(reauth_cache_t));
    reauth_cache->i_am = CLIENT;

    /* mutex */
    reauth_cache->mutex = utils->mutex_alloc();
    if (!reauth_cache->mutex)
	return SASL_FAIL;

    /* entries */
    reauth_cache->size = 10;
    reauth_cache->e = utils->malloc(reauth_cache->size *
				    sizeof(reauth_entry_t));
    if (reauth_cache->e == NULL)
	return SASL_NOMEM;
    memset(reauth_cache->e, 0, reauth_cache->size * sizeof(reauth_entry_t));

    digestmd5_client_plugins[0].glob_context = reauth_cache;
#ifdef _SUN_SDK_
#ifdef USE_UEF_CLIENT
    digestmd5_client_plugins[0].max_ssf = uef_max_ssf;
#endif /* USE_UEF_CLIENT */
#endif /* _SUN_SDK_ */

#ifdef _INTEGRATED_SOLARIS_
    /*
     * Let libsasl know that we are a "Sun" plugin so that privacy
     * and integrity will be allowed.
     */
    REG_PLUG("DIGEST-MD5", digestmd5_client_plugins);
#endif /* _INTEGRATED_SOLARIS_ */

    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = digestmd5_client_plugins;
    *plugcount = 1;

    return SASL_OK;
}

#ifdef _SUN_SDK_
#ifdef USE_UEF
/* If we fail here - we should just not offer privacy or integrity */
static int
getSlotID(const sasl_utils_t *utils, CK_MECHANISM_TYPE mech_type,
	  CK_SLOT_ID *slot_id)
{
    CK_RV rv;
    CK_ULONG ulSlotCount;
    CK_ULONG ulMechTypeCount;
    CK_SLOT_ID *pSlotList = NULL;
    CK_SLOT_ID slotID;
    CK_MECHANISM_TYPE_PTR pMechTypeList = NULL;
    int i, m;

    rv = C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
    if (rv != CKR_OK || ulSlotCount == 0) {
#ifdef DEBUG
	utils->log(utils->conn, SASL_LOG_DEBUG,
		   "C_GetSlotList: 0x%.8X count:%d\n", rv, ulSlotCount);
#endif
	return SASL_FAIL;
    }

    pSlotList = utils->calloc(sizeof (CK_SLOT_ID), ulSlotCount);
    if (pSlotList == NULL)
	return SASL_NOMEM;

    rv = C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
    if (rv != CKR_OK) {
#ifdef DEBUG
	utils->log(utils->conn, SASL_LOG_DEBUG,
		   "C_GetSlotList: 0x%.8X count:%d\n", rv, ulSlotCount);
#endif
	return SASL_FAIL;
    }

    for (i = 0; i < ulSlotCount; i++) {
	slotID = pSlotList[i];
	rv = C_GetMechanismList(slotID, NULL_PTR, &ulMechTypeCount);
	if (rv != CKR_OK) {
#ifdef DEBUG
	    utils->log(utils->conn, SASL_LOG_DEBUG,
		      "C_GetMechanismList returned 0x%.8X count:%d\n", rv,
		       ulMechTypeCount);
#endif
	    utils->free(pSlotList);
	    return SASL_FAIL;
	}
	pMechTypeList =
		utils->calloc(sizeof (CK_MECHANISM_TYPE), ulMechTypeCount);
	if (pMechTypeList == NULL_PTR) {
	    utils->free(pSlotList);
	    return SASL_NOMEM;
	}
	rv = C_GetMechanismList(slotID, pMechTypeList, &ulMechTypeCount);
	if (rv != CKR_OK) {
#ifdef DEBUG
	    utils->log(utils->conn, SASL_LOG_DEBUG,
	    	       "C_GetMechanismList returned 0x%.8X count:%d\n", rv,
		       ulMechTypeCount);
#endif
	    utils->free(pMechTypeList);
	    utils->free(pSlotList);
	    return SASL_FAIL;
	}

	for (m = 0; m < ulMechTypeCount; m++) {
	    if (pMechTypeList[m] == mech_type)
		break;
	}
	utils->free(pMechTypeList);
	pMechTypeList = NULL;
	if (m < ulMechTypeCount)
	    break;
    }
    utils->free(pSlotList);
    if (i < ulSlotCount) {
	*slot_id = slotID;
	return SASL_OK;
    }
    return SASL_FAIL;
}

static int
uef_init(const sasl_utils_t *utils)
{
    int got_rc4;
    int got_des;
    int got_3des;
    int next_c;
    CK_RV rv;

    if (got_uef_slot)
	return (SASL_OK);

    if (LOCK_MUTEX(&uef_init_mutex) < 0)
	return (SASL_FAIL);

    rv = C_Initialize(NULL_PTR);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
#ifdef DEBUG
	utils->log(utils->conn, SASL_LOG_DEBUG,
		   "C_Initialize returned 0x%.8X\n", rv);
#endif
	return SASL_FAIL;
    }

    got_rc4 = getSlotID(utils, CKM_RC4, &rc4_slot_id) == SASL_OK;
    if (!got_rc4)
	utils->log(utils->conn, SASL_LOG_WARN, "Could not get rc4");

    got_des = getSlotID(utils, CKM_DES_CBC, &des_slot_id) == SASL_OK;
    if (!got_des)
	utils->log(utils->conn, SASL_LOG_WARN, "Could not get des");

    got_3des = getSlotID(utils, CKM_DES3_CBC, &des3_slot_id) == SASL_OK;
    if (!got_3des)
	utils->log(utils->conn, SASL_LOG_WARN, "Could not get 3des");

    uef_max_ssf = got_rc4 ? 128 : got_3des ? 112 : got_des ? 55 : 0;

    /* adjust the available ciphers */
    next_c = (got_rc4) ? 3 : 0;

    if (got_des) {
        uef_ciphers[next_c].name = uef_ciphers[DES_CIPHER_INDEX].name;
        uef_ciphers[next_c].ssf = uef_ciphers[DES_CIPHER_INDEX].ssf;
        uef_ciphers[next_c].n = uef_ciphers[DES_CIPHER_INDEX].n;
        uef_ciphers[next_c].flag = uef_ciphers[DES_CIPHER_INDEX].flag;
        uef_ciphers[next_c].cipher_enc =
		uef_ciphers[DES_CIPHER_INDEX].cipher_enc;
        uef_ciphers[next_c].cipher_dec =
		uef_ciphers[DES_CIPHER_INDEX].cipher_dec;
        uef_ciphers[next_c].cipher_init =
		uef_ciphers[DES_CIPHER_INDEX].cipher_init;
	next_c++;
    }

    if (got_3des) {
        uef_ciphers[next_c].name = uef_ciphers[DES3_CIPHER_INDEX].name;
        uef_ciphers[next_c].ssf = uef_ciphers[DES3_CIPHER_INDEX].ssf;
        uef_ciphers[next_c].n = uef_ciphers[DES3_CIPHER_INDEX].n;
        uef_ciphers[next_c].flag = uef_ciphers[DES3_CIPHER_INDEX].flag;
        uef_ciphers[next_c].cipher_enc =
		uef_ciphers[DES3_CIPHER_INDEX].cipher_enc;
        uef_ciphers[next_c].cipher_dec =
		uef_ciphers[DES3_CIPHER_INDEX].cipher_dec;
        uef_ciphers[next_c].cipher_init =
		uef_ciphers[DES3_CIPHER_INDEX].cipher_init;
	next_c++;
    }
    uef_ciphers[next_c].name = NULL;

    got_uef_slot = TRUE;
    UNLOCK_MUTEX(&uef_init_mutex);

    return (SASL_OK);
}
#endif /* USE_UEF */
#endif /* _SUN_SDK_ */
