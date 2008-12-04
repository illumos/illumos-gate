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
nb_snballoc(int namelen, struct sockaddr_nb **dst)
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
 */
int
nb_sockaddr(struct sockaddr *peer, struct nb_name *np,
	struct sockaddr_nb **dst)

{
	struct sockaddr_nb *snb;
	struct sockaddr_in *sin;
	struct hostent *hst;
	int nmlen, error;

	if (peer && (peer->sa_family != AF_INET))
		return (EPROTONOSUPPORT);
#if NOT_DEFINED /* moved encoding into kernel */
	nmlen = nb_name_len(np);
	if (nmlen < NB_ENCNAMELEN)
		return (EINVAL);
#else
	nmlen = NB_NAMELEN;
#endif
	error = nb_snballoc(nmlen, &snb);
	if (error)
		return (error);

	/*
	 * Moved toupper() work to callers.
	 *
	 * Moved NetBIOS name encoding into the driver
	 * so we have readable names right up until the
	 * point where we marshall them in to a message.
	 * Just makes debugging easier.
	 */
#if NOT_DEFINED
	if (nmlen != nb_name_encode(np, snb->snb_name))
		printf(dgettext(TEXT_DOMAIN,
			"a bug somewhere in the nb_name* code\n"));
		/* XXX */
#else
	/*
	 * OK, nb_snballoc() did bzero, set snb_family.
	 * Hacks for "*" moved here from nb_name_encode(),
	 * but belongs where nn_name is filled in...
	 * XXX fix later
	 */
	if (strcmp(np->nn_name, "*") == 0) {
		/* Star is special: No blanks, type, etc. */
		snb->snb_name[0] = '*';
	} else {
		/* Normal name: pad with blanks, add type. */
		assert(NB_NAMELEN == 16);
		snprintf(snb->snb_name, NB_NAMELEN,
		    "%-15.15s", np->nn_name);
		snb->snb_name[15] = (char)np->nn_type;
	}
#endif

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
nb_name_encode(struct nb_name *np, uchar_t *dst)
{
	char *name;
	uchar_t *plen;
	uchar_t ch, *cp = dst;
	char *p, buf1[NB_NAMELEN+1];
	int i, lblen;

	/*
	 * XXX: I'd rather see this part moved into
	 * callers of this function, leaving just
	 * the pure NB encoding here. -GWR
	 */
	name = np->nn_name;
	if (name[0] == '*') {
		/* Star is special: No blanks, type, etc. */
		bzero(buf1, NB_NAMELEN);
		buf1[0] = '*';
	} else {
		/* Normal name: pad with blanks, add type. */
		assert(NB_NAMELEN == 16);
		snprintf(buf1, NB_NAMELEN,
		    "%-15.15s", name);
		buf1[15] = (char)np->nn_type;
	}
	name = buf1;

	/*
	 * Do the NetBIOS "first-level encoding" here.
	 * (RFC1002 explains this wierdness...)
	 * See similar code in kernel nsmb module:
	 *   uts/common/fs/smbclnt/netsmb/smb_trantcp.c
	 *
	 * Here is what we marshall:
	 *   uint8_t NAME_LENGTH (always 32)
	 *   uint8_t ENCODED_NAME[32]
	 *   uint8_t SCOPE_LENGTH
	 *   Scope follows here, then another null.
	 */

	/* NAME_LENGTH */
	*cp++ = (2 * NB_NAMELEN);

	/* ENCODED_NAME */
	for (i = 0; i < NB_NAMELEN; i++) {
		ch = name[i];
		*cp++ = 'A' + ((ch >> 4) & 0xF);
		*cp++ = 'A' + ((ch) & 0xF);
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
	 */
#if NOT_DEFINED /* XXX: not yet */
	if (np->nn_scope) {
		plen = cp++;
		*plen = 0; /* fill in later */
		lblen = 0;
		for (p = np->nn_scope; ; p++) {
			if (*p == '.' || *p == 0) {
				*plen = lblen;
				if (*p == 0)
					break;
				plen = cp++;
				*plen = 0;
				lblen = 0;
			} else {
				if (lblen < NB_MAXLABLEN) {
					*cp++ = *p;
					lblen++;
				}
			}
		}
	} else
#endif /* XXX: not yet */
	{
		*cp++ = 0;
	}

	return (cp - dst);
}
