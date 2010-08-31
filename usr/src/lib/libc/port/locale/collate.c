/*
 * Copyright (c) 1995 Alex Tatmanjants <alex@elvisti.kiev.ua>
 *		at Electronni Visti IA, Kiev, Ukraine.
 *			All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

#include "lint.h"
#include "file64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sysexits.h>
#include <netinet/in.h>

#include "collate.h"
#include "setlocale.h"
#include "ldpart.h"

int __collate_load_error = 1;
int __collate_substitute_nontrivial;

char __collate_substitute_table[UCHAR_MAX + 1][STR_LEN];
struct __collate_st_char_pri __collate_char_pri_table[UCHAR_MAX + 1];
struct __collate_st_chain_pri *__collate_chain_pri_table;

int
__collate_load_tables(const char *encoding)
{
	FILE *fp;
	int i, saverr, chains;
	uint32_t u32;
	char strbuf[STR_LEN], buf[PATH_MAX];
	void *TMP_substitute_table, *TMP_char_pri_table, *TMP_chain_pri_table;
	static char collate_encoding[ENCODING_LEN + 1];

	/* 'encoding' must be already checked. */
	if (strcmp(encoding, "C") == 0 || strcmp(encoding, "POSIX") == 0) {
		__collate_load_error = 1;
		return (_LDP_CACHE);
	}

	/*
	 * If the locale name is the same as our cache, use the cache.
	 */
	if (strcmp(encoding, collate_encoding) == 0) {
		__collate_load_error = 0;
		return (_LDP_CACHE);
	}

	/*
	 * Slurp the locale file into the cache.
	 */

	(void) snprintf(buf, sizeof (buf), "%s/%s/LC_COLLATE/LCL_DATA",
	    _PathLocale, encoding);

	if ((fp = fopen(buf, "r")) == NULL)
		return (_LDP_ERROR);

	if (fread(strbuf, sizeof (strbuf), 1, fp) != 1) {
		saverr = errno;
		(void) fclose(fp);
		errno = saverr;
		return (_LDP_ERROR);
	}
	chains = -1;
	if (strcmp(strbuf, COLLATE_VERSION) == 0)
		chains = 0;
	else if (strcmp(strbuf, COLLATE_VERSION1_2) == 0)
		chains = 1;
	if (chains < 0) {
		(void) fclose(fp);
		errno = EINVAL;
		return (_LDP_ERROR);
	}
	if (chains) {
		if (fread(&u32, sizeof (u32), 1, fp) != 1) {
			saverr = errno;
			(void) fclose(fp);
			errno = saverr;
			return (_LDP_ERROR);
		}
		if ((chains = (int)ntohl(u32)) < 1) {
			(void) fclose(fp);
			errno = EINVAL;
			return (_LDP_ERROR);
		}
	} else
		chains = TABLE_SIZE;

	if ((TMP_substitute_table =
	    malloc(sizeof (__collate_substitute_table))) == NULL) {
		saverr = errno;
		(void) fclose(fp);
		errno = saverr;
		return (_LDP_ERROR);
	}
	if ((TMP_char_pri_table =
	    malloc(sizeof (__collate_char_pri_table))) == NULL) {
		saverr = errno;
		free(TMP_substitute_table);
		(void) fclose(fp);
		errno = saverr;
		return (_LDP_ERROR);
	}
	if ((TMP_chain_pri_table =
	    malloc(sizeof (*__collate_chain_pri_table) * chains)) == NULL) {
		saverr = errno;
		free(TMP_substitute_table);
		free(TMP_char_pri_table);
		(void) fclose(fp);
		errno = saverr;
		return (_LDP_ERROR);
	}

#define	FREAD(a, b, c, d) \
{ \
	if (fread(a, b, c, d) != c) { \
		saverr = errno; \
		free(TMP_substitute_table); \
		free(TMP_char_pri_table); \
		free(TMP_chain_pri_table); \
		(void) fclose(d); \
		errno = saverr; \
		return (_LDP_ERROR); \
	} \
}

	FREAD(TMP_substitute_table, sizeof (__collate_substitute_table), 1, fp);
	FREAD(TMP_char_pri_table, sizeof (__collate_char_pri_table), 1, fp);
	FREAD(TMP_chain_pri_table,
	    sizeof (*__collate_chain_pri_table), chains, fp);
	(void) fclose(fp);

	(void) strcpy(collate_encoding, encoding);
	if (__collate_substitute_table_ptr != NULL)
		free(__collate_substitute_table_ptr);
	__collate_substitute_table_ptr = TMP_substitute_table;
	if (__collate_char_pri_table_ptr != NULL)
		free(__collate_char_pri_table_ptr);
	__collate_char_pri_table_ptr = TMP_char_pri_table;
	for (i = 0; i < UCHAR_MAX + 1; i++) {
		__collate_char_pri_table[i].prim =
		    ntohl(__collate_char_pri_table[i].prim);
		__collate_char_pri_table[i].sec =
		    ntohl(__collate_char_pri_table[i].sec);
	}
	if (__collate_chain_pri_table != NULL)
		free(__collate_chain_pri_table);
	__collate_chain_pri_table = TMP_chain_pri_table;
	for (i = 0; i < chains; i++) {
		__collate_chain_pri_table[i].prim =
		    ntohl(__collate_chain_pri_table[i].prim);
		__collate_chain_pri_table[i].sec =
		    ntohl(__collate_chain_pri_table[i].sec);
	}
	__collate_substitute_nontrivial = 0;
	for (i = 0; i < UCHAR_MAX + 1; i++) {
		if (__collate_substitute_table[i][0] != i ||
		    __collate_substitute_table[i][1] != 0) {
			__collate_substitute_nontrivial = 1;
			break;
		}
	}
	__collate_load_error = 0;

	return (_LDP_LOADED);
}

char *
__collate_substitute(const char *str)
{
	int dest_len, len, nlen;
	int delta;
	char *dest_str = NULL;
	uchar_t *s = (uchar_t *)str;

	if (s == NULL || *s == '\0') {
		return (strdup(""));
	}

	delta = strlen(str);
	delta += delta / 8;
	dest_str = malloc(dest_len = delta);
	if (dest_str == NULL)
		return (NULL);
	len = 0;
	while (*s) {
		nlen = len + strlen(__collate_substitute_table[*s]);
		if (dest_len <= nlen) {
			char *new_str;
			new_str = realloc(dest_str, dest_len = nlen + delta);
			if (new_str == NULL) {
				free(dest_str);
				return (NULL);
			}
			dest_str = new_str;
		}
		(void) strcpy(dest_str + len,
		    (char *)__collate_substitute_table[*s++]);
		len = nlen;
	}
	return (dest_str);
}

void
__collate_lookup(const char *t, int *len, int *prim, int *sec)
{
	struct __collate_st_chain_pri *p2;

	*len = 1;
	*prim = *sec = 0;
	for (p2 = __collate_chain_pri_table; p2->str[0] != '\0'; p2++) {
		if (*t == p2->str[0] &&
		    strncmp(t, (char *)p2->str, strlen((char *)p2->str)) == 0) {
			*len = strlen((char *)p2->str);
			*prim = p2->prim;
			*sec = p2->sec;
			return;
		}
	}
	*prim = __collate_char_pri_table[(uchar_t)*t].prim;
	*sec = __collate_char_pri_table[(uchar_t)*t].sec;
}
