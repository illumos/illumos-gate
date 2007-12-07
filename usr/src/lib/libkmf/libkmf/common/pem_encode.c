/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* pem_encode.c - PEM encoding routines */

#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <kmfapi.h>
#include <pem_encode.h>

static unsigned char data_bin2ascii[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ\
abcdefghijklmnopqrstuvwxyz0123456789+/";

static unsigned char data_ascii2bin[128] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xE0, 0xF0, 0xFF, 0xFF, 0xF1, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xE0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xF2, 0xFF, 0x3F,
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
	0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF,
	0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
	0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

#define	conv_bin2ascii(a)	(data_bin2ascii[(a)&0x3f])
#define	conv_ascii2bin(a)	(data_ascii2bin[(a)&0x7f])


void
PEM_EncodeInit(PEM_ENCODE_CTX *ctx)
{
	ctx->length = 48;
	ctx->num = 0;
	ctx->line_num = 0;
}

int
PEM_EncodeBlock(unsigned char *t, const unsigned char *f, int dlen)
{
	int i, ret = 0;
	unsigned long l;

	for (i = dlen; i > 0; i -= 3) {
		if (i >= 3) {
			l = (((unsigned long)f[0])<<16L)|
			    (((unsigned long)f[1])<< 8L)|f[2];
			*(t++) = conv_bin2ascii(l>>18L);
			*(t++) = conv_bin2ascii(l>>12L);
			*(t++) = conv_bin2ascii(l>> 6L);
			*(t++) = conv_bin2ascii(l);
		} else {
			l = ((unsigned long)f[0])<<16L;
			if (i == 2)
				l |= ((unsigned long)f[1]<<8L);

			*(t++) = conv_bin2ascii(l>>18L);
			*(t++) = conv_bin2ascii(l>>12L);
			*(t++) = (i == 1)?'=':conv_bin2ascii(l>> 6L);
			*(t++) = '=';
		}
		ret += 4;
		f += 3;
	}

	*t = '\0';
	return (ret);
}

void
PEM_EncodeUpdate(PEM_ENCODE_CTX *ctx, unsigned char *out, int *outl,
	unsigned char *in, int inl)
{
	int i, j;
	unsigned int total = 0;

	*outl = 0;
	if (inl == 0)
		return;
	if ((ctx->num+inl) < ctx->length) {
		(void) memcpy(&(ctx->enc_data[ctx->num]), in, inl);
		ctx->num += inl;
		return;
	}
	if (ctx->num != 0) {
		i = ctx->length-ctx->num;
		(void) memcpy(&(ctx->enc_data[ctx->num]), in, i);
		in += i;
		inl -= i;
		j = PEM_EncodeBlock(out, ctx->enc_data, ctx->length);
		ctx->num = 0;
		out += j;
		*(out++) = '\n';
		*out = '\0';
		total = j+1;
	}

	while (inl >= ctx->length) {
		j = PEM_EncodeBlock(out, in, ctx->length);
		in += ctx->length;
		inl -= ctx->length;
		out += j;
		*(out++) = '\n';
		*out = '\0';
		total += j+1;
	}

	if (inl != 0)
		(void) memcpy(&(ctx->enc_data[0]), in, inl);
	ctx->num = inl;
	*outl = total;
}

void
PEM_EncodeFinal(PEM_ENCODE_CTX *ctx, unsigned char *out, int *outl)
{
	unsigned int ret = 0;

	if (ctx->num != 0) {
		ret = PEM_EncodeBlock(out, ctx->enc_data, ctx->num);
		out[ret++] = '\n';
		out[ret] = '\0';
		ctx->num = 0;
	}
	*outl = ret;
}

KMF_RETURN
Der2Pem(KMF_OBJECT_TYPE type, unsigned char *data,
	int len, unsigned char **out, int *outlen)
{


	int nlen, n, i, j, outl;
	unsigned char *buf = NULL, *p = NULL;
	PEM_ENCODE_CTX ctx;
	char *name = NULL;

	if (data == NULL || len == 0 || out == NULL || outlen == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (type == KMF_CERT)
		name = PEM_STRING_X509;
	else if (type == KMF_CSR)
		name = PEM_STRING_X509_REQ;
	else if (type == KMF_CRL)
		name = PEM_STRING_X509_CRL;
	else
		return (KMF_ERR_BAD_OBJECT_TYPE);


	PEM_EncodeInit(&ctx);
	nlen = strlen(name);

	buf = malloc(PEM_BUFSIZE*8);
	if (buf == NULL) {
		return (KMF_ERR_MEMORY);
	}

	p = buf;
	(void) memcpy(p, "-----BEGIN ", 11);
	p += 11;
	(void) memcpy(p, name, nlen);
	p += nlen;
	(void) memcpy(p, "-----\n", 6);
	p += 6;

	i = j = 0;
	while (len > 0) {
		n = (int)((len > (PEM_BUFSIZE*5))?(PEM_BUFSIZE*5):len);
		PEM_EncodeUpdate(&ctx, p, &outl, &(data[j]), n);
		i += outl;
		len -= n;
		j += n;
		p += outl;
	}

	PEM_EncodeFinal(&ctx, p, &outl);

	if (outl > 0)
		p += outl;

	(void) memcpy(p, "-----END ", 9);
	p += 9;
	(void) memcpy(p, name, nlen);
	p += nlen;
	(void) memcpy(p, "-----\n", 6);
	p += 6;

	*out = buf;
	*outlen = i+outl+nlen*2+11+6+9+6;

	return (KMF_OK);

}

int
PEM_DecodeBlock(unsigned char *t, const unsigned char *f, int n)
{
	int i, ret = 0, a, b, c, d;
	unsigned long l;

	/* trim white space from the start of the line. */
	while ((conv_ascii2bin(*f) == B64_WS) && (n > 0)) {
		f++;
		n--;
	}

	/*
	 * strip off stuff at the end of the line
	 * ascii2bin values B64_WS, B64_EOLN, B64_EOLN and B64_EOF
	 */
	while ((n > 3) && (B64_NOT_BASE64(conv_ascii2bin(f[n-1]))))
		n--;

	if (n%4 != 0) {
		return (-1);
	}

	for (i = 0; i < n; i += 4) {
		a = conv_ascii2bin(*(f++));
		b = conv_ascii2bin(*(f++));
		c = conv_ascii2bin(*(f++));
		d = conv_ascii2bin(*(f++));
		if ((a & 0x80) || (b & 0x80) ||	(c & 0x80) || (d & 0x80))
			return (-1);
		l = ((((unsigned long)a)<<18L) | (((unsigned long)b)<<12L) |
		    (((unsigned long)c)<< 6L) | (((unsigned long)d)));
		*(t++) = (unsigned char)(l>>16L)&0xff;
		*(t++) = (unsigned char)(l>> 8L)&0xff;
		*(t++) = (unsigned char)(l)&0xff;
		ret += 3;
	}
	return (ret);
}

void
PEM_DecodeInit(PEM_ENCODE_CTX *ctx)
{
	ctx->length = 30;
	ctx->num = 0;
	ctx->line_num = 0;
	ctx->expect_nl = 0;
}

/*
 * -1 for error
 *  0 for last line
 *  1 for full line
 */
int
PEM_DecodeUpdate(PEM_ENCODE_CTX *ctx, unsigned char *out, int *outl,
    unsigned char *in, int inl)
{
	int seof = -1, eof = 0, rv = -1, ret = 0;
	int i, v, tmp, n, ln, exp_nl;
	unsigned char *d;

	n = ctx->num;
	d = ctx->enc_data;
	ln = ctx->line_num;
	exp_nl = ctx->expect_nl;

	/* last line of input. */
	if ((inl == 0) || ((n == 0) && (conv_ascii2bin(in[0]) == B64_EOF))) {
		rv = 0;
		goto end;
	}

	/* We parse the input data */
	for (i = 0; i < inl; i++) {
		/* If the current line is > 80 characters, scream alot */
		if (ln >= 80) {
			rv = -1;
			goto end;
		}

		/* Get char and put it into the buffer */
		tmp = *(in++);
		v = conv_ascii2bin(tmp);
		/* only save the good data :-) */
		if (!B64_NOT_BASE64(v)) {
			d[n++] = tmp;
			ln++;
		} else if (v == B64_ERROR) {
			rv = -1;
			goto end;
		}

		/*
		 * have we seen a '=' which is 'definitly' the last
		 * input line.  seof will point to the character that
		 * holds it. and eof will hold how many characters to
		 * chop off.
		 */
		if (tmp == '=') {
			if (seof == -1) seof = n;
			eof++;
		}

		if (v == B64_CR) {
			ln = 0;
			if (exp_nl)
				continue;
		}

		/* eoln */
		if (v == B64_EOLN) {
			ln = 0;
			if (exp_nl) {
				exp_nl = 0;
				continue;
			}
		}
		exp_nl = 0;

		/*
		 * If we are at the end of input and it looks like a
		 * line, process it.
		 */
		if (((i+1) == inl) && (((n&3) == 0) || eof)) {
			v = B64_EOF;
			/*
			 * In case things were given us in really small
			 * records (so two '=' were given in separate
			 * updates), eof may contain the incorrect number
			 * of ending bytes to skip, so let's redo the count
			 */
			eof = 0;
			if (d[n-1] == '=') eof++;
			if (d[n-2] == '=') eof++;
			/* There will never be more than two '=' */
		}

		if ((v == B64_EOF) || (n >= 64)) {
			/*
			 * This is needed to work correctly on 64 byte input
			 * lines.  We process the line and then need to
			 * accept the '\n'
			 */
			if ((v != B64_EOF) && (n >= 64))
				exp_nl = 1;
			if (n > 0) {
				v = PEM_DecodeBlock(out, d, n);
				if (v < 0) {
					rv = 0;
					goto end;
				}
				n = 0;
				ret += (v-eof);
			} else {
				eof = 1;
				v = 0;
			}

			/*
			 * This is the case where we have had a short
			 * but valid input line
			 */
			if ((v < ctx->length) && eof) {
				rv = 0;
				goto end;
			} else
				ctx->length = v;

			if (seof >= 0) {
				rv = 0;
				goto end;
			}
			out += v;
		}
	}
	rv = 1;
end:
	*outl = ret;
	ctx->num = n;
	ctx->line_num = ln;
	ctx->expect_nl = exp_nl;
	return (rv);
}

int
PEM_DecodeFinal(PEM_ENCODE_CTX *ctx, unsigned char *out, int *outl)
{
	int i;

	*outl = 0;
	if (ctx->num != 0) {
		i = PEM_DecodeBlock(out, ctx->enc_data, ctx->num);
		if (i < 0)
			return (-1);
		ctx->num = 0;
		*outl = i;
		return (1);
	} else
		return (1);
}

static int
get_line(unsigned char *in, char *buf)
{

	int i = 0;
	int len = 0;

	while ((in[i] != '\n')) {
		buf[i] = in[i];
		i++;
		len++;
	}

	return (len);
}

KMF_RETURN
Pem2Der(unsigned char *in, int inlen,
    unsigned char **out, int *outlen)
{
	int kmf_rv = 0;
	PEM_ENCODE_CTX ctx;
	int i, j, k, bl = 0;
	char buf[2048];
	char *nameB = NULL;
	unsigned char *dataB = NULL;
	int total = 0;

	if (in == NULL || inlen == 0 || out == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(buf, 0, sizeof (buf));

	for (;;) {
		/*
		 * get a line (ended at '\n'), which returns
		 * number of bytes in the line
		 */
		i = get_line(in + total, buf);
		if (i <= 0) {
			kmf_rv = KMF_ERR_ENCODING;
			goto err;
		}

		j = i;
		while ((j >= 0) && (buf[j] <= ' ')) j--;
		buf[++j] = '\n';
		buf[++j] = '\0';

		total += i + 1;

		if (strncmp(buf, "-----BEGIN ", 11) == 0) {
			i = strlen(&(buf[11]));
			if (strncmp(&(buf[11+i-6]), "-----\n", 6) != 0) {
				continue;
			}

			if ((nameB = malloc(i+9)) == NULL) {
				kmf_rv = KMF_ERR_MEMORY;
				goto err;
			}

			(void) memcpy(nameB, &(buf[11]), i-6);
			nameB[i-6] = '\0';
			break;
		}
	}

	bl = 0;
	if ((dataB = malloc(2048)) == NULL) {
		kmf_rv = KMF_ERR_MEMORY;
		goto err;
	}

	dataB[0] = '\0';

	for (;;) {
		(void) memset(buf, 0, 1024);
		i = get_line(in+total, buf);

		if (i <= 0) break;

		j = i;
		while ((j >= 0) && (buf[j] <= ' '))
			j--;

		buf[++j] = '\n';
		buf[++j] = '\0';
		total += i + 1;

		if (buf[0] == '\n') break;
		if ((dataB = realloc(dataB, bl+j+9)) == NULL) {
			kmf_rv = KMF_ERR_MEMORY;
			goto err;
		}

		if (strncmp(buf, "-----END ", 9) == 0) {
			break;
		}

		(void) memcpy(&(dataB[bl]), buf, j);
		dataB[bl+j] = '\0';
		bl += j;
	}

	i = strlen(nameB);
	if ((strncmp(buf, "-----END ", 9) != 0) ||
	    (strncmp(nameB, &(buf[9]), i) != 0) ||
	    (strncmp(&(buf[9+i]), "-----", 5) != 0)) {
		kmf_rv = KMF_ERR_ENCODING;
		goto err;
	}

	PEM_DecodeInit(&ctx);
	i = PEM_DecodeUpdate(&ctx,
	    (unsigned char *)dataB, &bl, (unsigned char *)dataB, bl);

	if (i < 0) {
		kmf_rv = KMF_ERR_ENCODING;
		goto err;
	}

	i = PEM_DecodeFinal(&ctx, (unsigned char *)&(dataB[bl]), &k);
	if (i < 0) {
		kmf_rv = KMF_ERR_ENCODING;
		goto err;
	}
	bl += k;

	if (bl == 0) goto err;
	*out = (unsigned char *)dataB;
	*outlen = bl;

err:
	if (nameB != NULL)
		free(nameB);
	if (kmf_rv != KMF_OK && dataB != NULL)
		free(dataB);

	return (kmf_rv);
}
