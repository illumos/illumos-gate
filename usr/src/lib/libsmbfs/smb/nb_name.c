/*
 * Copyright (c) 2000, Boris Popov
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
 * $Id: nb_name.c,v 1.11 2004/12/11 05:23:59 lindak Exp $
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <libintl.h>
#include <assert.h>

#include <netsmb/netbios.h>
#include <netsmb/smb_lib.h>
#include <netsmb/nb_lib.h>
#include <netsmb/mchain.h>
#include "private.h"

int
nb_snballoc(struct sockaddr_nb **dst)
{
	struct sockaddr_nb *snb;
	int slen;

	slen = sizeof (struct sockaddr_nb);
	snb = malloc(slen);
	if (snb == NULL)
		return (ENOMEM);
	bzero(snb, slen);
	snb->snb_family = AF_NETBIOS;
	*dst = snb;
	return (0);
}

void
nb_snbfree(struct sockaddr *snb)
{
	free(snb);
}

/*
 * Create a full NETBIOS address
 * Passed names should already be upper case.
 * Stores the names truncated or blank padded.
 * NetBIOS name encoding happens later.
 */
int
nb_sockaddr(struct sockaddr *peer, struct nb_name *np,
	struct sockaddr_nb **dst)

{
	struct sockaddr_nb *snb;
	struct sockaddr_in *sin;
	int error;

	if (peer && (peer->sa_family != AF_INET))
		return (EPROTONOSUPPORT);
	error = nb_snballoc(&snb);
	if (error)
		return (error);

	if (strcmp(np->nn_name, "*") == 0) {
		/* Star is special: No blanks, type, etc. */
		snb->snb_name[0] = '*';
	} else {
		/* Normal name: pad with blanks, add type. */
		snprintf(snb->snb_name, NB_NAMELEN,
		    "%-15.15s", np->nn_name);
		snb->snb_name[15] = (char)np->nn_type;
	}

	if (peer) {
		/*LINTED*/
		sin = (struct sockaddr_in *)peer;
		snb->snb_ipaddr = sin->sin_addr.s_addr;
	}
	*dst = snb;
	return (0);
}

int
nb_name_len(struct nb_name *np)
{
	char *name;
	int len, sclen;

	len = 1 + NB_ENCNAMELEN;
	if (np->nn_scope == NULL)
		return (len + 1);
	sclen = 0;
	for (name = np->nn_scope; *name; name++) {
		if (*name == '.') {
			sclen = 0;
		} else {
			if (sclen < NB_MAXLABLEN) {
				sclen++;
				len++;
			}
		}
	}
	return (len + 1);
}

int
nb_encname_len(const uchar_t *str)
{
	const uchar_t *cp = str;
	int len, blen;

	if ((cp[0] & 0xc0) == 0xc0)
		return (-1);	/* first two bytes are offset to name */

	len = 1;
	for (;;) {
		blen = *cp;
		if (blen++ == 0)
			break;
		len += blen;
		cp += blen;
	}
	return (len);
}

int
nb_name_encode(struct mbdata *mbp, struct nb_name *nn)
{
	char *plen;
	uchar_t ch;
	char *p, namebuf[NB_NAMELEN+1];
	int i, lblen;

	bcopy(nn->nn_name, namebuf, NB_NAMELEN);
	namebuf[NB_NAMELEN-1] = (char)nn->nn_type;
	namebuf[NB_NAMELEN] = '\0'; /* for debug */

	/*
	 * Do the NetBIOS "first-level encoding" here.
	 * (RFC1002 explains this weirdness...)
	 *
	 * Here is what we marshall:
	 *   uint8_t NAME_LENGTH (always 32)
	 *   uint8_t ENCODED_NAME[32]
	 *   uint8_t SCOPE_LENGTH
	 *   Scope follows here, then another null.
	 */

	/* NAME_LENGTH */
	mb_put_uint8(mbp, (2 * NB_NAMELEN));

	/* ENCODED_NAME */
	for (i = 0; i < NB_NAMELEN; i++) {
		ch = namebuf[i];
		mb_put_uint8(mbp, 'A' + ((ch >> 4) & 0xF));
		mb_put_uint8(mbp, 'A' + ((ch) & 0xF));
	}

	/*
	 * NetBIOS "scope" sting encoding,
	 * a.k.a second-level encoding.
	 * See RFC1002 for the details.
	 *
	 * Note: plen points to the length byte at the
	 * start of each string.  This keeps a pointer
	 * to the location and fills it in after the
	 * length of the string is determined.
	 *
	 * One string of length zero terminates.
	 * With no scope string, the zero-length
	 * string is the only thing there.
	 */
	if (nn->nn_scope == NULL) {
		mb_put_uint8(mbp, 0);
		return (0);
	}

	(void) mb_fit(mbp, 1, &plen);
	*plen = 0; /* will update below */
	lblen = 0;
	for (p = nn->nn_scope; ; p++) {
		if (*p == '\0') {
			*plen = lblen;
			if (lblen)
				mb_put_uint8(mbp, 0);
			break;
		}
		if (*p == '.') {
			*plen = lblen;
			(void) mb_fit(mbp, 1, &plen);
			*plen = 0;
			lblen = 0;
		} else {
			if (lblen < NB_MAXLABLEN) {
				mb_put_uint8(mbp, *p);
				lblen++;
			}
		}
	}

	return (0);
}
