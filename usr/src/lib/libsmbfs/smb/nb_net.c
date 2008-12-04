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
 * $Id: nb_net.c,v 1.8 2004/03/19 01:49:47 lindak Exp $
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <unistd.h>

#include <err.h>

#include <netsmb/netbios.h>
#include <netsmb/smb_lib.h>
#include <netsmb/nb_lib.h>
#include "private.h"

/*
 * General networking stuff, in spite of the names
 * that imply they're specific to NetBIOS.
 */

int
nb_getlocalname(char *name, size_t maxlen)
{
	char buf[1024], *cp;

	if (gethostname(buf, sizeof (buf)) != 0)
		return (errno);
	cp = strchr(buf, '.');
	if (cp)
		*cp = 0;
	strlcpy(name, buf, maxlen);
	return (0);
}

int
nb_resolvehost_in(const char *name, struct sockaddr **dest)
{
	struct hostent *h;
	struct sockaddr_in *sinp;
	in_addr_t	addr;
	struct in_addr in;
	int len;
	char **p;


	h = gethostbyname(name);
	if (!h) {
#ifdef DEBUG
		warnx("can't get server address `%s': ", name);
#endif
		return (ENETDOWN);
	}
	if (h->h_addrtype != AF_INET) {
#ifdef DEBUG
		warnx("address for `%s' is not in the AF_INET family", name);
#endif
		return (EAFNOSUPPORT);
	}
	if (h->h_length != 4) {
#ifdef DEBUG
		warnx("address for `%s' has invalid length", name);
#endif
		return (EAFNOSUPPORT);
	}
	len = sizeof (struct sockaddr_in);
	sinp = malloc(len);
	if (sinp == NULL)
		return (ENOMEM);
	bzero(sinp, len);
	/*
	 * There is no sin_len in sockaddr_in structure on Solaris.
	 * sinp->sin_len = len;
	 */
	sinp->sin_family = h->h_addrtype;
	memcpy(&sinp->sin_addr.s_addr, *h->h_addr_list,\
	    sizeof (sinp->sin_addr.s_addr));
	sinp->sin_port = htons(SMB_TCP_PORT);
	*dest = (struct sockaddr *)sinp;
	return (0);
}
