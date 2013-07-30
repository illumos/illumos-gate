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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/time.h>
#include "ns_sldap.h"
#include "ns_internal.h"
#include <crypt.h>

static	char		t1[ROTORSIZE];
static	char		t2[ROTORSIZE];
static	char		t3[ROTORSIZE];
static	char		hexdig[] = "0123456789abcdef";

static mutex_t		ns_crypt_lock = DEFAULTMUTEX;
static boolean_t	crypt_inited = B_FALSE;

static int
is_cleartext(const char *pwd)
{
	if (0 == strncmp(pwd, CRYPTMARK, strlen(CRYPTMARK)))
		return (FALSE);
	return (TRUE);
}


static char *
hex2ascii(char *aString, int aLen)
{
	char *res;
	int i = 0;

	if ((res = (char *)calloc(aLen*2 + 1, 1)) == NULL) {
		return (NULL);
	}
	for (;;) {
		if (aLen < 1)
			break;
		res[i] = hexdig[(*aString & 0xf0) >> 4];
		res[i + 1] = hexdig[*aString & 0x0f];
		i += 2;
		aLen--;
		aString++;
	}
	return (res);
}


static int
unhex(char c)
{
	return (c >= '0' && c <= '9' ? c - '0'
		: c >= 'A' && c <= 'F' ? c - 'A' + 10
		: c - 'a' + 10);
}


static char *
ascii2hex(char *anHexaStr, int *aResLen)
{
	int theLen = 0;
	char *theRes = malloc(strlen(anHexaStr) /2 + 1);

	if (theRes == NULL)
		return (NULL);
	while (isxdigit(*anHexaStr)) {
		theRes[theLen] = unhex(*anHexaStr) << 4;
		if (++anHexaStr != '\0') {
			theRes[theLen] += unhex(*anHexaStr);
			anHexaStr++;
		}
		theLen++;
	}
	theRes[theLen] = '\0';
	*aResLen = theLen;
	return (theRes);
}


static void
c_setup()
{
	int ic, i, k, temp;
	unsigned random;
	char buf[13];
	int seed;

	(void) mutex_lock(&ns_crypt_lock);
	if (crypt_inited) {
		(void) mutex_unlock(&ns_crypt_lock);
		return;
	}
	(void) strcpy(buf, "Homer J");
	buf[8] = buf[0];
	buf[9] = buf[1];
	(void) strncpy(buf, (char *)crypt(buf, &buf[8]), 13);
	seed = 123;
	for (i = 0; i < 13; i++)
		seed = seed*buf[i] + i;
	for (i = 0; i < ROTORSIZE; i++) {
		t1[i] = i;
		t3[i] = 0;
	}
	for (i = 0; i < ROTORSIZE; i++) {
		seed = 5*seed + buf[i%13];
		random = seed % 65521;
		k = ROTORSIZE-1 - i;
		ic = (random&MASK)%(k+1);
		random >>= 8;
		temp = t1[k];
		t1[k] = t1[ic];
		t1[ic] = temp;
		if (t3[k] != 0) continue;
		ic = (random&MASK) % k;
		while (t3[ic] != 0) ic = (ic + 1) % k;
		t3[k] = ic;
		t3[ic] = k;
	}
	for (i = 0; i < ROTORSIZE; i++)
		t2[t1[i]&MASK] = i;
	crypt_inited = B_TRUE;
	(void) mutex_unlock(&ns_crypt_lock);
}


static char *
modvalue(char *str, int len, int *mod_len)
{
	int i, n1, n2;
	char *s;

	if (!crypt_inited)
		c_setup();
	i = 0;
	n1 = 0;
	n2 = 0;
	if ((s = (char *)malloc(2 * len + 1)) != NULL) {
		while (i < len) {
		    s[i] = t2[(t3[(t1[(str[i]+n1)&MASK]+n2)&MASK]-n2)&MASK]-n1;
		    i++;
		    n1++;
		    if (n1 == ROTORSIZE) {
			n1 = 0;
			n2++;
			if (n2 == ROTORSIZE) n2 = 0;
		    }
		}
		s[i] = '\0';
		if (mod_len != NULL)
		    *mod_len = i;
	}
	return (s);
}


char *
evalue(char *ptr)
{
	char *modv, *str, *ev;
	int modv_len;
	size_t len;

	/*
	 * if not cleartext, return a copy of what ptr
	 * points to as that is what evalue does below.
	 */
	if (FALSE == is_cleartext(ptr)) {
		str = strdup(ptr);
		return (str);
	}

	modv = modvalue(ptr, strlen(ptr), &modv_len);
	str = hex2ascii(modv, modv_len);
	free(modv);
	modv = NULL;
	len = strlen(str) + strlen(CRYPTMARK) + 1;
	ev = malloc(len);
	if (ev == NULL) {
		free(str);
		return (NULL);
	}
	(void) snprintf(ev, len, CRYPTMARK "%s", str);
	free(str);
	str = NULL;
	return (ev);
}


char *
dvalue(char *ptr)
{
	char *modv, *str, *sb;
	int len;

	/* if cleartext return NULL (error!) */
	if (TRUE == is_cleartext(ptr))
		return (NULL);

	sb = strchr(ptr, '}');
	sb++;
	len = strlen(sb);
	str = ascii2hex(sb, &len);
	modv = modvalue(str, len, NULL);
	free(str);
	str = NULL;
	return (modv);
}
