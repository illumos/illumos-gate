/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * usr/src/cmd/cmd-inet/usr.bin/telnet/auth.c
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
 */

/* based on @(#)auth.c	8.1 (Berkeley) 6/4/93 */

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


#include <stdio.h>
#include <sys/types.h>
#include <signal.h>

#define	AUTHTYPE_NAMES		/* this is needed for arpa/telnet.h */
#include <arpa/telnet.h>

#ifdef	__STDC__
#include <stdlib.h>
#endif

#include <string.h>

#include "externs.h"
#include "encrypt.h"
#include "auth.h"

#define	typemask(x)	((x) > 0 ? 1 << ((x)-1) : 0)

static int auth_onoff(const char *type, boolean_t on);
static void auth_gen_printsub(uchar_t *, uint_t, uchar_t *, uint_t);

boolean_t	auth_debug_mode = B_FALSE;
boolean_t	auth_has_failed = B_FALSE;
boolean_t	auth_enable_encrypt = B_FALSE;

static 	char		*Name = "Noname";
static	Authenticator	*authenticated = NULL;
static	uchar_t		_auth_send_data[BUFSIZ];
static	uchar_t		*auth_send_data;
static	int		auth_send_cnt = 0;

/*
 * Authentication types supported.  Note that these are stored
 * in priority order, i.e. try the first one first.
 */
static	Authenticator authenticators[] = {
	{ AUTHTYPE_KERBEROS_V5,
		AUTH_WHO_CLIENT|AUTH_HOW_MUTUAL|AUTH_ENCRYPT_ON,
				kerberos5_init,
				kerberos5_send,
				kerberos5_reply,
				kerberos5_status,
				kerberos5_printsub },
	{ AUTHTYPE_KERBEROS_V5, AUTH_WHO_CLIENT|AUTH_HOW_MUTUAL,
				kerberos5_init,
				kerberos5_send,
				kerberos5_reply,
				kerberos5_status,
				kerberos5_printsub },
	{ AUTHTYPE_KERBEROS_V5, AUTH_WHO_CLIENT|AUTH_HOW_ONE_WAY,
				kerberos5_init,
				kerberos5_send,
				kerberos5_reply,
				kerberos5_status,
				kerberos5_printsub },
	{ 0, },
};

static Authenticator NoAuth = { 0 };

static uint_t	i_support = 0;
static uint_t	i_wont_support = 0;

/*
 * Traverse the Authenticator array until we find the authentication type
 * and matching direction we are looking for.  Return a pointer into the
 * Authenticator type array.
 *
 * Returns:	0 - type not found (error)
 * 		nonzero - pointer to authenticator
 */
static Authenticator *
findauthenticator(int type, int way)
{
	Authenticator *ap = authenticators;

	while (ap->type && (ap->type != type || ap->way != way))
		++ap;
	return (ap->type ? ap : NULL);
}

/*
 * For each authentication type in the Authenticator array,
 * call the associated init routine, and update the i_support bitfield.
 */
void
auth_init(const char *name)
{
	Authenticator *ap = authenticators;

	Name = name ? strdup(name) : "Noname";

	i_support = 0;
	authenticated = NULL;
	while (ap->type) {
		if (!ap->init || (*ap->init)(ap)) {
			i_support |= typemask(ap->type);
			if (auth_debug_mode)
			    (void) printf(gettext
				(">>>%s: I support auth type %d %d\r\n"),
				Name, ap->type, ap->way);
		}
		++ap;
	}
}

/*
 * Search the Authenticator array for the authentication type 'name',
 * and disable this type by updating the i_wont_support bitfield.
 */
void
auth_disable_name(const char *name)
{
	uint_t x;
	for (x = 0; x < AUTHTYPE_CNT; ++x) {
		if (!strcasecmp(name, AUTHTYPE_NAME(x))) {
			i_wont_support |= typemask(x);
			break;
		}
	}

	if (!i_wont_support)
		(void) printf(
			gettext("%s : invalid authentication type\n"),
			name);
}

/*
 * Search the Authenticator array for the authentication type given
 * by the character string 'type', and return its integer bitmask
 * in maskp.
 *
 * Returns:	1 - no error
 *		0 - type not found (error)
 */
static int
getauthmask(const char *type, uint_t *maskp)
{
	uint_t x;

	if (!strcasecmp(type, AUTHTYPE_NAME(0))) {
		*maskp = (uint_t)-1;
		return (1);
	}

	for (x = 1; x < AUTHTYPE_CNT; ++x) {
		if (!strcasecmp(type, AUTHTYPE_NAME(x))) {
			*maskp = typemask(x);
			return (1);
		}
	}
	return (0);
}

int
auth_enable(char *type)
{
	return (auth_onoff(type, B_TRUE));
}

int
auth_disable(char *type)
{
	return (auth_onoff(type, B_FALSE));
}

/*
 * Responds to the 'auth enable <option>' and 'auth disable <option>' commands.
 *
 * If <option> is:
 *	- a valid authentication type, turns support on / off
 *	- "?" or "help", print a usage message
 *	- not recognized, print an error message.
 *
 * Returns:	1 - no error, authentication is enabled or disabled
 *		0 - error, or help requested
 */
static int
auth_onoff(const char *type, boolean_t on)
{
	uint_t i, mask = 0;
	Authenticator *ap;

	if (!strcasecmp(type, "?") || !strcasecmp(type, "help")) {
		(void) printf(on ?
			gettext("auth enable 'type'\n") :
			gettext("auth disable 'type'\n"));
		(void) printf(
			gettext("Where 'type' is one of:\n"));
		(void) printf("\t%s\n", AUTHTYPE_NAME(0));
		for (ap = authenticators; ap->type; ap++) {
			if ((mask & (i = typemask(ap->type))) != 0)
				continue;
			mask |= i;
			(void) printf("\t%s\n", AUTHTYPE_NAME(ap->type));
		}
		return (0);
	}

	if (!getauthmask(type, &mask)) {
		(void) printf(
			gettext("%s: invalid authentication type\n"), type);
		return (0);
	}
	if (on)
		i_wont_support &= ~mask;
	else
		i_wont_support |= mask;
	return (1);
}

/*
 * Responds to the 'toggle authdebug' command.
 *
 * Returns:	1 - always
 */
int
auth_togdebug(int on)
{
	if (on < 0)
		auth_debug_mode = !auth_debug_mode;
	else
		auth_debug_mode = on > 0 ? B_TRUE : B_FALSE;
	(void) printf(auth_debug_mode ?
		gettext("auth debugging enabled\n") :
		gettext("auth debugging disabled\n"));
	return (1);
}

/*
 * Responds to the 'auth status' command.
 * Traverses the authenticator array and prints enabled or disabled for
 * each authentication type, depencing on the i_wont_support bitfield.
 *
 * Returns:	1 - always
 */
int
auth_status(void)
{
	Authenticator *ap;
	uint_t i, mask;

	if (i_wont_support == (uint_t)-1)
		(void) printf(gettext("Authentication disabled\n"));
	else
		(void) printf(gettext("Authentication enabled\n"));

	mask = 0;
	for (ap = authenticators; ap->type; ap++) {
		if ((mask & (i = typemask(ap->type))) != 0)
			continue;
		mask |= i;
		(void) printf("%s: %s\n", AUTHTYPE_NAME(ap->type),
			(i_wont_support & typemask(ap->type)) ?
			gettext("disabled") : gettext("enabled"));
	}
	return (1);
}

/*
 * This is called when an AUTH SEND is received.
 * data is a list of authentication mechanisms we support
 */
void
auth_send(uchar_t *data, int cnt)
{

	if (auth_debug_mode) {
		(void) printf(gettext(">>>%s: auth_send got:"), Name);
		printd(data, cnt);
		(void) printf("\r\n");
	}

	/*
	 * Save the list of authentication mechanisms
	 */
	auth_send_cnt = cnt;
	if (auth_send_cnt > sizeof (_auth_send_data))
	    auth_send_cnt = sizeof (_auth_send_data);
	(void) memcpy((void *)_auth_send_data, (void *)data, auth_send_cnt);
	auth_send_data = _auth_send_data;

	auth_send_retry();
}

/*
 * Try the next authentication mechanism on the list, and see if it
 * works.
 */
void
auth_send_retry(void)
{
	Authenticator *ap;
	static uchar_t str_none[] = { IAC, SB, TELOPT_AUTHENTICATION,
		TELQUAL_IS, AUTHTYPE_NULL, 0, IAC, SE };

	for (; (auth_send_cnt -= 2) >= 0; auth_send_data += 2) {
	    if (auth_debug_mode)
		(void) printf(
			gettext(">>>%s: Remote host supports %d\r\n"),
			Name, *auth_send_data);
	    if (!(i_support & typemask(*auth_send_data)))
		continue;
	    if (i_wont_support & typemask(*auth_send_data))
		continue;
	    ap = findauthenticator(auth_send_data[0], auth_send_data[1]);
	    if (!ap || !ap->send)
		continue;
	    if ((ap->way & AUTH_ENCRYPT_MASK) && !auth_enable_encrypt)
		continue;

	    if (auth_debug_mode)
		(void) printf(
			gettext(">>>%s: Trying %d %d\r\n"), Name,
			auth_send_data[0], auth_send_data[1]);
	    if ((*ap->send)(ap)) {
		/*
		 * Okay, we found one we like and did it.  we can go
		 * home now.
		 */
		if (auth_debug_mode)
		    (void) printf(gettext(">>>%s: Using type %d\r\n"),
			Name, *auth_send_data);
		auth_send_data += 2;
		return;
	    }
	}
	(void) net_write(str_none, sizeof (str_none));
	printsub('>', &str_none[2], sizeof (str_none) - 2);
	if (auth_debug_mode)
		(void) printf(
			gettext(">>>%s: Sent failure message\r\n"), Name);
	auth_finished(0, AUTH_REJECT);
	auth_has_failed = B_TRUE;
}

void
auth_reply(uchar_t *data, int cnt)
{
	Authenticator *ap;

	if (cnt < 2)
		return;

	if (ap = findauthenticator(data[0], data[1])) {
		if (ap->reply)
			(*ap->reply)(ap, data+2, cnt-2);
	} else if (auth_debug_mode)
		(void) printf(gettext
			(">>>%s: Invalid authentication in SEND: %d\r\n"),
			Name, *data);
}

int
auth_sendname(uchar_t *cp, int len)
{
	static uchar_t str_request[AUTH_NAME_BUFSIZ + 6] = { IAC, SB,
		TELOPT_AUTHENTICATION, TELQUAL_NAME, };
	register uchar_t *e = str_request + 4;
	register uchar_t *ee = &str_request[sizeof (str_request) - 2];

	while (--len >= 0) {
		if ((*e++ = *cp++) == IAC)
			*e++ = IAC;
		if (e >= ee)
			return (0);
	}
	*e++ = IAC;
	*e++ = SE;
	(void) net_write(str_request, e - str_request);
	printsub('>', &str_request[2], e - &str_request[2]);
	return (1);
}

/* ARGSUSED */
void
auth_finished(Authenticator *ap, int result)
{
	authenticated = ap;
	if (authenticated == NULL)
		authenticated = &NoAuth;
}

void
auth_printsub(uchar_t *data, uint_t cnt, uchar_t *buf, uint_t buflen)
{
	Authenticator *ap;

	ap = findauthenticator(data[1], data[2]);
	if (ap && ap->printsub)
		(*ap->printsub)(data, cnt, buf, buflen);
	else
		auth_gen_printsub(data, cnt, buf, buflen);
}

static void
auth_gen_printsub(uchar_t *data, uint_t cnt, uchar_t *buf, uint_t buflen)
{
	register uchar_t *cp;
	uchar_t lbuf[AUTH_LBUF_BUFSIZ];

	if (buflen < 2)
		return;
	cnt = (cnt > 3) ? cnt - 3 : 0;
	data += 3;
	buf[buflen - 1] = '\0';
	buf[buflen - 2] = '*';
	buflen -= 2;
	for (; cnt > 0; cnt--, data++) {
		(void) snprintf((char *)lbuf, AUTH_LBUF_BUFSIZ, " %d", *data);
		for (cp = lbuf; (*cp != '\0') && (buflen > 0); --buflen)
			*buf++ = *cp++;
		if (buflen == 0)
			return;
	}
	*buf = '\0';
}
