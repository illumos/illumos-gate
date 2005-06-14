/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1991, 1993
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
 *
 *	@(#)auth.h	8.1 (Berkeley) 6/4/93
 */

/*
 * Copyright (C) 1990 by the Massachusetts Institute of Technology
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#ifndef	_AUTH_H
#define	_AUTH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct XauthP {
	int	type;
	int	way;
	int	(*init)(struct XauthP *);
	int	(*send)(struct XauthP *);
	void	(*reply)(struct XauthP *, unsigned char *, int);
	int	(*status)(struct XauthP *, char *, int);
	void	(*printsub)(unsigned char *, int, unsigned char *, int);
} Authenticator;

#define	AUTH_NAME_BUFSIZ	256
#define	AUTH_LBUF_BUFSIZ	32	/* short temporary buffer */

extern	char *UserNameRequested;
/* extern	char *RemoteHostName; */

void	auth_init(const char *);
void	auth_request(void);
void	auth_send(unsigned char *, int);
int	auth_sendname(uchar_t *, int);
void	auth_send_retry(void);
void	auth_reply(unsigned char *, int);
void	auth_finished(Authenticator *, int);
int	auth_must_encrypt(void);
void	auth_printsub(uchar_t *, uint_t, uchar_t *, uint_t);

void	auth_disable_name(const char *);

void	set_krb5_realm(char *);
int	kerberos5_init(Authenticator *);
int	kerberos5_send(Authenticator *);
void	kerberos5_reply(Authenticator *, unsigned char *, int);
int	kerberos5_status(Authenticator *, char *, int);
void	kerberos5_printsub(unsigned char *, int, unsigned char *, int);

#include <profile/prof_int.h>
extern	errcode_t profile_get_options_boolean(profile_t,
	char **, profile_options_boolean *);

#define	OPTS_FORWARD_CREDS	0x00000002
#define	OPTS_FORWARDABLE_CREDS	0x00000001

extern	boolean_t auth_debug_mode;

#ifdef	__cplusplus
}
#endif

#endif	/* _AUTH_H */
