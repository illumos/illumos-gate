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
#include <strings.h>
#include <secdb.h>
#include <ctype.h>

/* From libnsl */
extern char *_strdup_null(char *);
extern char *_strtok_escape(char *, char *, char **);
extern char *_strpbrk_escape(char *, char *);
extern char *_unescape(char *, char *);

char *_do_unescape(char *);


/*
 * kva_match(): Given a key-value array and a key, return a pointer to the
 * value that matches the key.
 */
char *
kva_match(kva_t *kva, char *key)
{
	int	i;
	kv_t	*data;

	if (kva == NULL || key == NULL) {
		return ((char *)NULL);
	}
	data = kva->data;
	for (i = 0; i < kva->length; i++) {
		if (strcmp(data[i].key, key) == 0) {
			return (data[i].value);
		}
	}

	return ((char *)NULL);
}

/*
 * _kva_free(): Free up memory.
 */
void
_kva_free(kva_t *kva)
{
	int	i;
	kv_t	*data;

	if (kva == NULL) {
		return;
	}
	data = kva->data;
	for (i = 0; i < kva->length; i++) {
		if (data[i].key != NULL) {
			free(data[i].key);
			data[i].key = NULL;
		}
		if (data[i].value != NULL) {
			free(data[i].value);
			data[i].value = NULL;
		}
	}
	free(kva->data);
	free(kva);
}

/*
 * new_kva(): Allocate a key-value array.
 */
kva_t  *
_new_kva(int size)
{
	kva_t	*new_kva;

	if ((new_kva = (kva_t *)calloc(1, sizeof (kva_t))) == NULL) {
		return ((kva_t *)NULL);
	}
	if ((new_kva->data = (kv_t *)calloc(1, (size*sizeof (kv_t)))) == NULL) {
		free(new_kva);
		return ((kva_t *)NULL);
	}

	return (new_kva);
}

/*
 * _str2kva(): Given a string (s) of key-value pairs, separated by delimeter
 * (del), place the values into the key value array (nkva).
 */
kva_t  *
_str2kva(char *s, char *ass, char *del)
{
	int	n = 0;
	int	m;
	int	size = KV_ADD_KEYS;
	char	*buf;
	char	*p;
	char	*pair;
	char	*key;
	char	*last_pair;
	char	*last_key;
	kv_t	*data;
	kva_t	*nkva;

	if (s == NULL ||
	    ass == NULL ||
	    del == NULL ||
	    *s == '\0' ||
	    *s == '\n' ||
	    (strlen(s) <= 1)) {
		return ((kva_t *)NULL);
	}
	p = s;
	while ((p = _strpbrk_escape(p, ass)) != NULL) {
		n++;
		p++;
	}
	if (n > size) {
		m = n/size;
		if (n%size) {
			++m;
		}
		size = m * KV_ADD_KEYS;
	}
	if ((nkva = _new_kva(size)) == NULL) {
		return ((kva_t *)NULL);
	}
	data = nkva->data;
	nkva->length = 0;
	if ((buf = strdup(s)) == NULL) {
		return ((kva_t *)NULL);
	}
	pair = _strtok_escape(buf, del, &last_pair);
	do {
		key = _strtok_escape(pair, ass, &last_key);
		if (key != NULL) {
			data[nkva->length].key = _do_unescape(key);
			data[nkva->length].value = _do_unescape(last_key);
			nkva->length++;
		}
	} while ((pair = _strtok_escape(NULL, del, &last_pair)) != NULL);
	free(buf);
	return (nkva);
}

/*
 * _kva2str(): Given an array of key-value pairs, place them into a string
 * (buf). Use delimeter (del) to separate pairs.  Use assignment character
 * (ass) to separate keys and values.
 *
 * Return Values: 0  Success 1  Buffer too small 2  Out of memory
 */
int
_kva2str(kva_t *kva, char *buf, int buflen, char *ass, char *del)
{
	int	i;
	int	length = 0;
	char	*tmp;
	kv_t	*data;

	if (kva == NULL) {
		return (0);
	}
	data = kva->data;
	for (i = 0; i < kva->length; i++) {
		if (data[i].value != NULL) {
			length += 2 + strlen(data[i].value);
		}
	}
	if (length > buflen) {
		return (1);
	}
	(void) memset(buf, 0, buflen);
	if ((tmp = (char *)malloc(buflen)) == NULL) {
		return (2);
	}
	for (i = 0; i < kva->length; i++) {
		if (data[i].value != NULL) {
			if (snprintf(tmp, buflen, "%s%s%s%s",
			    data[i].key, ass, data[i].value, del) >= buflen) {
				return (0);
			}
			(void) strcat(buf, tmp);
		}
	}
	return (0);
}

int
_insert2kva(kva_t *kva, char *key, char *value)
{
	int	i;
	kv_t	*data;

	if (kva == NULL) {
		return (0);
	}
	data = kva->data;
	for (i = 0; i < kva->length; i++) {
		if (strcmp(data[i].key, key) == 0) {
			if (data[i].value != NULL)
				free(data[i].value);
			data[i].value = _strdup_null(value);
			return (0);
		}
	}
	return (1);
}

kva_t  *
_kva_dup(kva_t *old_kva)
{
	int	i;
	int	size;
	kv_t	*old_data;
	kv_t	*new_data;
	kva_t 	*nkva = (kva_t *)NULL;

	if (old_kva == NULL) {
		return ((kva_t *)NULL);
	}
	old_data = old_kva->data;
	size = old_kva->length;
	if ((nkva = _new_kva(size)) == NULL) {
		return ((kva_t *)NULL);
	}
	new_data = nkva->data;
	nkva->length = old_kva->length;
	for (i = 0; i < nkva->length; i++) {
		new_data[i].key = _strdup_null(old_data[i].key);
		new_data[i].value = _strdup_null(old_data[i].value);
	}

	return (nkva);
}

static void
strip_spaces(char **valuep)
{
	char *p, *start;

	/* Find first non-white space character and return pointer to it */
	for (p = *valuep; *p != '\0' && isspace((unsigned char)*p); p++)
		;

	*valuep = start = p;

	if (*p == '\0')
		return;

	p = p + strlen(p) - 1;

	/* Remove trailing spaces */
	while (p > start && isspace((unsigned char)*p))
		p--;

	p[1] = '\0';
}

char *
_do_unescape(char *src)
{
	char *tmp = NULL;
	char *dst = NULL;

	if (src == NULL) {
		dst = _strdup_null(src);
	} else {
		strip_spaces(&src);
		tmp = _unescape(src, "=;:,\\");
		dst = (tmp == NULL) ? _strdup_null(src) : tmp;
	}

	return (dst);
}


/*
 * Some utilities for handling comma-separated lists.
 */
char *
_argv_to_csl(char **strings)
{
	int len = 0;
	int i = 0;
	char *newstr = (char *)NULL;

	if (strings == NULL)
		return ((char *)NULL);
	for (i = 0; strings[i] != NULL; i++) {
		len += strlen(strings[i]) + 1;
	}
	if ((len > 0) && ((newstr = (char *)malloc(len + 1)) != NULL)) {
		(void) memset(newstr, 0, len);
		for (i = 0; strings[i] != NULL; i++) {
			(void) strcat(newstr, strings[i]);
			(void) strcat(newstr, ",");
		}
		newstr[len-1] = NULL;
		return (newstr);
	} else
		return ((char *)NULL);
}


char **
_csl_to_argv(char *csl)
{
	int len = 0;
	int ncommas = 0;
	int i = 0;
	char **spc = (char **)NULL;
	char *copy = (char *)NULL;
	char *pc;
	char *lasts = (char *)NULL;

	len = strlen(csl);
	for (i = 0; i < len; i++) {
		if (csl[i] == ',')
			ncommas++;
	}
	if ((spc = (char **)malloc((ncommas + 2) * sizeof (char *))) == NULL) {
		return ((char **)NULL);
	}
	copy = strdup(csl);
	for (pc = strtok_r(copy, ",", &lasts), i = 0; pc != NULL;
	    pc = strtok_r(NULL, ",", &lasts), i++) {
		spc[i] = strdup(pc);
	}
	spc[i] = NULL;
	free(copy);
	return (spc);
}


void
_free_argv(char **p_argv)
{
	char **p_a;

	for (p_a = p_argv; *p_a != NULL; p_a++)
		free(*p_a);
	free(p_argv);
}


#ifdef DEBUG
void
print_kva(kva_t *kva)
{
	int	i;
	kv_t	*data;

	if (kva == NULL) {
		printf("  (empty)\n");
		return;
	}
	data = kva->data;
	for (i = 0; i < kva->length; i++) {
		printf("  %s = %s\n", data[i].key, data[i].value);
	}
}
#endif  /* DEBUG */
