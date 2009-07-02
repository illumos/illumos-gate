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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <nss_dbdefs.h>

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
nb_resolvehost_in(const char *name, struct in_addr *ia)
{
	char  he_buf[NSS_BUFLEN_HOSTS];
	struct hostent he, *h;
	int err;

	h = gethostbyname_r(name, &he, he_buf, sizeof (he_buf), &err);
	if (h == NULL) {
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

	memcpy(ia, h->h_addr, sizeof (*ia));
	return (0);
}
