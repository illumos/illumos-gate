/*
 * Copyright 1993-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef	_NET_IF_DL_H
#define	_NET_IF_DL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* from UCB 8.1 (Berkeley) 6/10/93 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * A Link-Level Sockaddr may specify the interface in one of two
 * ways: either by means of a system-provided index number (computed
 * anew and possibly differently on every reboot), or by a human-readable
 * string such as "il0" (for managerial convenience).
 *
 * Census taking actions, such as something akin to SIOCGCONF would return
 * both the index and the human name.
 *
 * High volume transactions (such as giving a link-level ``from'' address
 * in a recvfrom or recvmsg call) may be likely only to provide the indexed
 * form, (which requires fewer copy operations and less space).
 *
 * The form and interpretation  of the link-level address is purely a matter
 * of convention between the device driver and its consumers; however, it is
 * expected that all drivers for an interface of a given if_type will agree.
 */

/*
 * Structure of a Link-Level sockaddr:
 */
struct sockaddr_dl {
	ushort_t sdl_family;	/* AF_LINK */
	ushort_t sdl_index;	/* if != 0, system given index for interface */
	uchar_t	sdl_type;	/* interface type */
	uchar_t	sdl_nlen;	/* interface name length, no trailing 0 reqd. */
	uchar_t	sdl_alen;	/* link level address length */
	uchar_t	sdl_slen;	/* link layer selector length */
	char	sdl_data[244];	/* contains both if name and ll address */
};

#define	LLADDR(s) ((caddr_t)((s)->sdl_data + (s)->sdl_nlen))

#ifdef	__STDC__
extern char *_link_ntoa(const unsigned char *, char *, int, int);
extern unsigned char *_link_aton(const char *, int *);
#else	/* __STDC__ */
extern char *_link_ntoa();
extern unsigned char *_link_aton();
#endif	/* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _NET_IF_DL_H */
