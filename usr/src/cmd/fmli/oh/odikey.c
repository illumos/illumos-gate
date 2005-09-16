/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>		/* EFT abs k16 */
#include "wish.h"
#include "typetab.h"
#include "var_arrays.h"
#include "moremacros.h"
#include "sizes.h"

#define ODISIZ (2*PATHSIZ)
#define NULLSTR	""

static char *copy_to_key();
static char *skip_to_key();

int
odi_putkey(entry, key, value)
struct ott_entry *entry;
char *key, *value;
{
	int length;
	register char *p, *q;
	char valbuf[PATHSIZ], odibuf[ODISIZ];
	char *copy_to_key(), *skip_to_key();

	if (key == NULL)
		key = NULLSTR;
	if (value == NULL)
		value = NULLSTR;

	if ((length = strlen(value) + strlen(key)) >= sizeof(valbuf))
		return(O_FAIL);
	if (entry->odi && (strlen(entry->odi) + length >= ODISIZ))
		return(O_FAIL);

	strcpy(valbuf, key);
	strcat(valbuf, "=");
	q = value;
	for (p=valbuf+strlen(valbuf); (*q!='\0') && (p < valbuf+PATHSIZ); p++,q++) {
		switch (*q) {
		case ';':
		case '=':
		case '\\':
			*p++ = '\\';
			/* no break */
		default:
			*p = *q;
		}
	}
	*p = '\0';

	if (entry->odi == NULL) {		/* no odi, just add it */
		entry->odi = strsave(valbuf);
		return(O_OK);
	}

	/* copy the new value onto beginning of odibuf, then copy all of
	 * the old odibuf onto the end, leaving out the original key if
	 * it exists.
	 */
	strcpy(odibuf, valbuf);

	strcpy(valbuf, key);
	strcat(valbuf, "=");
	length = strlen(valbuf);
	q = entry->odi;
	for (p = &odibuf[strlen(odibuf)]; *q; ) {
		if (strncmp(q, valbuf, length) == 0)
			q = skip_to_key(q);
		else {
			*p++ = ';';
			q = copy_to_key(p, q, sizeof(odibuf) - (p-odibuf), FALSE);
			p = p + strlen(p);
		}
	}
	*p = '\0';

	free(entry->odi);
	entry->odi = strsave(odibuf);
	return(O_OK);
}

char *
odi_getkey(entry, key)
struct ott_entry *entry;
char *key;
{
	register int length;
	register char *p;
	static char keybuf[PATHSIZ];

	char *copy_to_key(), *skip_to_key();

	strcpy(keybuf, key);
	strcat(keybuf, "=");
	length = strlen(keybuf);

	for (p = entry->odi; p && *p; p = skip_to_key(p)) {
		if (strncmp(keybuf, p, length) == 0) {
			copy_to_key(keybuf, p+length, sizeof(keybuf), TRUE);
			break;
		}
	}
	if (p && *p)
		return(keybuf);
	else
		return(NULL);
}

/* copy from src to dst one keyword's value, of maximum size sizedst.
 * If unquote is TRUE, then the copy should also remove a level of backslashes.
 */

static char *
copy_to_key(dst, src, sizedst, unquote)
char *dst, *src;
int sizedst;
bool unquote;
{
	register char *p = dst;
	register bool done = FALSE;

	while (!done && src && *src && dst-p < sizedst-1 ) {
		switch (*src) {
		case ';':
			done = TRUE;
			break;
		case '\\':
			if (src[1]) {
				if (unquote == FALSE)
					*dst++ = *src;
				src++;
			}
			/* no break! continue with next case */
		default:
			*dst++ = *src++;
			break;
		}
	}
	*dst = '\0';
	return(done?++src:src);		/* skip the ";" */
}

static char *
skip_to_key(src)
char *src;
{
	char dst[PATHSIZ];

	return(copy_to_key(dst, src, sizeof(dst), TRUE));
}

/* return the first entry in the current ott which has key set to
 * value.
 */

struct ott_entry *
key_to_odi(key, value)
char *key, *value;
{
	extern struct ott_entry *Cur_entry;

	register int i;
	register int size = array_len(Cur_entry);
	register char *p;


	for (i = 0; i < size; i++)
		if ((p = odi_getkey(Cur_entry[i].dname, key)) && strcmp(p, value) == 0)
			return(Cur_entry + i);

	return(NULL);
}
