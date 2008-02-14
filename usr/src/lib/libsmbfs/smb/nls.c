/*
 * Copyright (c) 2000-2001, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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
 * $Id: nls.c,v 1.10 2004/12/13 00:25:22 lindak Exp $
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <locale.h>
#include <errno.h>

#include <netsmb/smb_lib.h>

/*
 * prototype iconv* functions
 */
typedef void *iconv_t;

static size_t(*my_iconv)(iconv_t, const char **, size_t *, char **, size_t *);

u_char nls_lower[256];
u_char nls_upper[256];

static iconv_t nls_toext, nls_toloc;
static int iconv_loaded;

int
nls_setlocale(const char *name)
{
	int i;

	if (setlocale(LC_CTYPE, name) == NULL) {
		fprintf(stdout, dgettext(TEXT_DOMAIN,
		    "can't set locale '%s'\n"), name);
	}
	for (i = 0; i < 256; i++) {
		nls_lower[i] = tolower(i);
		nls_upper[i] = toupper(i);
	}
	return 0;
}

int
nls_setrecode(const char *local, const char *external)
{
	return ENOENT;
}

char *
nls_str_toloc(char *dst, const char *src)
{
	char *p = dst;
	size_t inlen, outlen;

	if (!iconv_loaded)
		return strcpy(dst, src);

	if (nls_toloc == (iconv_t)0)
		return strcpy(dst, src);
	inlen = outlen = strlen(src);
	my_iconv(nls_toloc, NULL, NULL, &p, &outlen);
	my_iconv(nls_toloc, &src, &inlen, &p, &outlen);
	*p = 0;
	return dst;
}

char *
nls_str_toext(char *dst, const char *src)
{
	char *p = dst;
	size_t inlen, outlen;

	if (!iconv_loaded)
		return strcpy(dst, src);

	if (nls_toext == (iconv_t)0)
		return strcpy(dst, src);
	inlen = outlen = strlen(src);
	my_iconv(nls_toext, NULL, NULL, &p, &outlen);
	my_iconv(nls_toext, &src, &inlen, &p, &outlen);
	*p = 0;
	return dst;
}

void *
nls_mem_toloc(void *dst, const void *src, int size)
{
	char *p = dst;
	const char *s = src;
	size_t inlen, outlen;

	if (!iconv_loaded)
		return memcpy(dst, src, size);

	if (size == 0)
		return NULL;

	if (nls_toloc == (iconv_t)0)
		return memcpy(dst, src, size);
	inlen = outlen = size;
	my_iconv(nls_toloc, NULL, NULL, &p, &outlen);
	my_iconv(nls_toloc, &s, &inlen, &p, &outlen);
	return dst;
}

void *
nls_mem_toext(void *dst, const void *src, int size)
{
	char *p = dst;
	const char *s = src;
	size_t inlen, outlen;

	if (size == 0)
		return NULL;

	if (!iconv_loaded || nls_toext == (iconv_t)0)
		return memcpy(dst, src, size);

	inlen = outlen = size;
	my_iconv(nls_toext, NULL, NULL, &p, &outlen);
	my_iconv(nls_toext, &s, &inlen, &p, &outlen);
	return dst;
}

char *
nls_str_upper(char *dst, const char *src)
{
	char *p = dst;

	while (*src)
		*dst++ = toupper(*src++);
	*dst = 0;
	return p;
}

char *
nls_str_lower(char *dst, const char *src)
{
	char *p = dst;

	while (*src)
		*dst++ = tolower(*src++);
	*dst = 0;
	return p;
}
