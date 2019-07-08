/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * usr/src/cmd/cmd-inet/usr.bin/telnet/kerberos5.c
 *
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *	must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *	may be used to endorse or promote products derived from this software
 *	without specific prior written permission.
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

/* based on @(#)kerberos5.c	8.1 (Berkeley) 6/4/93 */

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


#include <arpa/telnet.h>
#include <stdio.h>
#include <ctype.h>
#include <syslog.h>
#include <stdlib.h>

/* the following are from the kerberos tree */
#include <k5-int.h>
#include <com_err.h>
#include <netdb.h>
#include <profile/prof_int.h>
#include <sys/param.h>
#include "externs.h"

extern	char *RemoteHostName;
extern	boolean_t auth_debug_mode;
extern	int net;

#define	ACCEPTED_ENCTYPE(a) \
	(a == ENCTYPE_DES_CBC_CRC || a == ENCTYPE_DES_CBC_MD5)
/* for comapatibility with non-Solaris KDC's, this has to be big enough */
#define	KERBEROS_BUFSIZ	8192

int	forward_flags = 0;  /* Flags get set in telnet/main.c on -f and -F */
static	void kerberos5_forward(Authenticator *);

static	unsigned char str_data[KERBEROS_BUFSIZ] = { IAC, SB,
		TELOPT_AUTHENTICATION, 0, AUTHTYPE_KERBEROS_V5, };
static	char *appdef[] = { "appdefaults", "telnet", NULL };
static	char *realmdef[] = { "realms", NULL, "telnet", NULL };

static	krb5_auth_context auth_context = 0;

static	krb5_data auth;	/* telnetd gets session key from here */
static	krb5_ticket *ticket = NULL;
	/* telnet matches the AP_REQ and AP_REP with this */

static	krb5_keyblock	*session_key = 0;
char	*telnet_krb5_realm = NULL;

/*
 * Change the kerberos realm
 */
void
set_krb5_realm(char *name)
{
	if (name == NULL) {
		(void) fprintf(stderr, gettext("Could not set Kerberos realm, "
			"no realm provided.\n"));
		return;
	}

	if (telnet_krb5_realm)
		free(telnet_krb5_realm);

	telnet_krb5_realm = (char *)strdup(name);

	if (telnet_krb5_realm == NULL)
		(void) fprintf(stderr, gettext(
			"Could not set Kerberos realm, malloc failed\n"));
}

#define	RETURN_NOMEM	{ errno = ENOMEM; return (-1); }

static int
krb5_send_data(Authenticator *ap, int type, krb5_pointer d, int c)
{
	/* the first 3 bytes are control chars */
	unsigned char *p = str_data + 4;
	unsigned char *cd = (unsigned char *)d;
	/* spaceleft is incremented whenever p is decremented */
	size_t spaceleft = sizeof (str_data) - 4;

	if (c == -1)
		c = strlen((char *)cd);

	if (auth_debug_mode) {
		(void) printf("%s:%d: [%d] (%d)",
			str_data[3] == TELQUAL_IS ? ">>>IS" : ">>>REPLY",
			str_data[3], type, c);
		printd(d, c);
		(void) printf("\r\n");
	}

	if (spaceleft < 3)
		RETURN_NOMEM;
	*p++ = ap->type;
	*p++ = ap->way;
	*p++ = type;
	spaceleft -= 3;

	while (c-- > 0) {
		if (spaceleft < 2)
			RETURN_NOMEM;
		if ((*p++ = *cd++) == IAC) {
			*p++ = IAC;
			spaceleft -= 2;
		}
	}

	if (spaceleft < 2)
		RETURN_NOMEM;
	*p++ = IAC;
	*p++ = SE;
	if (str_data[3] == TELQUAL_IS)
		printsub('>', &str_data[2], p - &str_data[2]);
	return (net_write(str_data, p - str_data));
}

krb5_context telnet_context = 0;

/* ARGSUSED */
int
kerberos5_init(Authenticator *ap)
{
	krb5_error_code retval;

	str_data[3] = TELQUAL_IS;
	if (krb5auth_flag && (telnet_context == 0)) {
		retval = krb5_init_context(&telnet_context);
		if (retval)
			return (0);
	}
	return (1);
}

int
kerberos5_send(Authenticator *ap)
{
	krb5_error_code retval;
	krb5_ccache ccache;
	krb5_creds creds;		/* telnet gets session key from here */
	krb5_creds *new_creds = 0;
	int ap_opts;
	char type_check[2];
	krb5_data check_data;

	krb5_keyblock *newkey = 0;

	int i;
	krb5_enctype *ktypes;

	if (!UserNameRequested) {
		if (auth_debug_mode)
			(void) printf(gettext("telnet: Kerberos V5: "
				"no user name supplied\r\n"));
		return (0);
	}

	if ((retval = krb5_cc_default(telnet_context, &ccache))) {
		if (auth_debug_mode)
		    (void) printf(gettext("telnet: Kerberos V5: "
			"could not get default ccache\r\n"));
		return (0);
	}

	(void) memset((char *)&creds, 0, sizeof (creds));
	if (auth_debug_mode)
		printf("telnet: calling krb5_sname_to_principal\n");
	if ((retval = krb5_sname_to_principal(telnet_context, RemoteHostName,
		"host", KRB5_NT_SRV_HST, &creds.server))) {
		if (auth_debug_mode)
		    (void) printf(gettext("telnet: Kerberos V5: error "
			"while constructing service name: %s\r\n"),
			error_message(retval));
		return (0);
	}
	if (auth_debug_mode)
		printf("telnet: done calling krb5_sname_to_principal\n");

	if (telnet_krb5_realm != NULL) {
		krb5_data rdata;

		rdata.magic = 0;
		rdata.length = strlen(telnet_krb5_realm);
		rdata.data = (char *)malloc(rdata.length + 1);
		if (rdata.data == NULL) {
			(void) fprintf(stderr, gettext("malloc failed\n"));
			return (0);
		}
		(void) strcpy(rdata.data, telnet_krb5_realm);
		krb5_princ_set_realm(telnet_context, creds.server, &rdata);
		if (auth_debug_mode)
		    (void) printf(gettext(
			"telnet: Kerberos V5: set kerberos realm to %s\r\n"),
			telnet_krb5_realm);
	}

	if ((retval = krb5_cc_get_principal(telnet_context, ccache,
		&creds.client)) != 0) {
		if (auth_debug_mode) {
			(void) printf(gettext(
			    "telnet: Kerberos V5: failure on principal "
			    "(%s)\r\n"), error_message(retval));
		}
		krb5_free_cred_contents(telnet_context, &creds);
		return (0);
	}
/*
 * Check to to confirm that at least one of the supported
 * encryption types (des-cbc-md5, des-cbc-crc is available. If
 * one is available then use it to obtain credentials.
 */

	if ((retval = krb5_get_tgs_ktypes(telnet_context, creds.server,
		&ktypes))) {
		if (auth_debug_mode) {
			(void) printf(gettext(
			    "telnet: Kerberos V5: could not determine "
				"TGS encryption types "
				"(see default_tgs_enctypes in krb5.conf) "
			    "(%s)\r\n"), error_message(retval));
		}
		krb5_free_cred_contents(telnet_context, &creds);
		return (0);
	}

	for (i = 0; ktypes[i]; i++) {
		if (ACCEPTED_ENCTYPE(ktypes[i]))
			break;
	}

	if (ktypes[i] == 0) {
		if (auth_debug_mode) {
			(void) printf(gettext(
				"telnet: Kerberos V5: "
				"failure on encryption types. "
				"Cannot find des-cbc-md5 or des-cbc-crc "
				"in list of TGS encryption types "
				"(see default_tgs_enctypes in krb5.conf)\n"));
		}
		krb5_free_cred_contents(telnet_context, &creds);
		return (0);
	}

	creds.keyblock.enctype = ktypes[i];
	if ((retval = krb5_get_credentials(telnet_context, 0,
		ccache, &creds, &new_creds))) {
		if (auth_debug_mode) {
			(void) printf(gettext(
			    "telnet: Kerberos V5: failure on credentials "
			    "(%s)\r\n"), error_message(retval));
		}
		krb5_free_cred_contents(telnet_context, &creds);
		return (0);
	}

	ap_opts = ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) ?
			AP_OPTS_MUTUAL_REQUIRED : 0;

	ap_opts |= AP_OPTS_USE_SUBKEY;

	if (auth_context) {
		krb5_auth_con_free(telnet_context, auth_context);
		auth_context = 0;
	}
	if ((retval = krb5_auth_con_init(telnet_context, &auth_context))) {
		if (auth_debug_mode) {
			(void) printf(gettext(
				"Kerberos V5: failed to init auth_context "
				"(%s)\r\n"), error_message(retval));
		}
		return (0);
	}

	krb5_auth_con_setflags(telnet_context, auth_context,
		KRB5_AUTH_CONTEXT_RET_TIME);

	type_check[0] = ap->type;
	type_check[1] = ap->way;
	check_data.magic = KV5M_DATA;
	check_data.length = 2;
	check_data.data = (char *)&type_check;

	retval = krb5_mk_req_extended(telnet_context, &auth_context, ap_opts,
		&check_data, new_creds, &auth);

	krb5_auth_con_getlocalsubkey(telnet_context, auth_context, &newkey);
	if (session_key) {
		krb5_free_keyblock(telnet_context, session_key);
		session_key = 0;
	}

	if (newkey) {
		/*
		 * keep the key in our private storage, but don't use it
		 * yet---see kerberos5_reply() below
		 */
		if (!(ACCEPTED_ENCTYPE(newkey->enctype))) {
		    if (!(ACCEPTED_ENCTYPE(new_creds->keyblock.enctype)))
			/* use the session key in credentials instead */
			krb5_copy_keyblock(telnet_context,
				&new_creds->keyblock, &session_key);
		} else
			krb5_copy_keyblock(telnet_context,
				newkey, &session_key);

		krb5_free_keyblock(telnet_context, newkey);
	}

	krb5_free_cred_contents(telnet_context, &creds);
	krb5_free_creds(telnet_context, new_creds);

	if (retval) {
		if (auth_debug_mode)
			(void) printf(gettext(
			    "telnet: Kerberos V5: mk_req failed (%s)\r\n"),
			    error_message(retval));
		return (0);
	}

	if ((auth_sendname((uchar_t *)UserNameRequested,
		strlen(UserNameRequested))) == 0) {
		if (auth_debug_mode)
			(void) printf(gettext(
				"telnet: Not enough room for user name\r\n"));
		return (0);
	}
	retval = krb5_send_data(ap, KRB_AUTH, auth.data, auth.length);
	if (auth_debug_mode && retval) {
		(void) printf(gettext(
		    "telnet: Sent Kerberos V5 credentials to server\r\n"));
	} else if (auth_debug_mode) {
		(void) printf(gettext(
		    "telnet: Not enough room for authentication data\r\n"));
		return (0);
	}
	return (1);
}

void
kerberos5_reply(Authenticator *ap, unsigned char *data, int cnt)
{
	Session_Key skey;
	static boolean_t mutual_complete = B_FALSE;

	if (cnt-- < 1)
		return;
	switch (*data++) {
	case KRB_REJECT:
		if (cnt > 0)
		    (void) printf(gettext(
			"[ Kerberos V5 refuses authentication because "
			"%.*s ]\r\n"), cnt, data);
		else
		    (void) printf(gettext(
			"[ Kerberos V5 refuses authentication ]\r\n"));
		auth_send_retry();
		return;
	case KRB_ACCEPT:
		if (!mutual_complete) {
			if ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) {
			    (void) printf(gettext(
				"[ Kerberos V5 accepted you, but didn't "
				"provide mutual authentication! ]\r\n"));
			    auth_send_retry();
			    return;
			}

			if (session_key) {
			    skey.type = SK_DES;
			    skey.length = 8;
			    skey.data = session_key->contents;
			    encrypt_session_key(&skey);
			}
		}
		if (cnt)
			(void) printf(gettext(
			    "[ Kerberos V5 accepts you as ``%.*s'' ]\r\n"),
			    cnt, data);
		else
			(void) printf(gettext(
			    "[ Kerberos V5 accepts you ]\r\n"));
		auth_finished(ap, AUTH_USER);

		if (forward_flags & OPTS_FORWARD_CREDS)
			kerberos5_forward(ap);

		break;
	case KRB_RESPONSE:
		if ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) {
			/* the rest of the reply should contain a krb_ap_rep */
			krb5_ap_rep_enc_part *reply;
			krb5_data inbuf;
			krb5_error_code retval;

			inbuf.length = cnt;
			inbuf.data = (char *)data;

			retval = krb5_rd_rep(telnet_context, auth_context,
				&inbuf, &reply);
			if (retval) {
				(void) printf(gettext(
					"[ Mutual authentication failed: "
					"%s ]\r\n"), error_message(retval));
				auth_send_retry();
				return;
			}
			krb5_free_ap_rep_enc_part(telnet_context, reply);

			if (session_key) {
				skey.type = SK_DES;
				skey.length = 8;
				skey.data = session_key->contents;
				encrypt_session_key(&skey);
			}
			mutual_complete = B_TRUE;
		}
		return;
	case KRB_FORWARD_ACCEPT:
		(void) printf(gettext(
			"[ Kerberos V5 accepted forwarded credentials ]\r\n"));
		return;
	case KRB_FORWARD_REJECT:
		(void) printf(gettext(
			"[ Kerberos V5 refuses forwarded credentials because "
			"%.*s ]\r\n"), cnt, data);
		return;
	default:
		if (auth_debug_mode)
			(void) printf(gettext(
				"Unknown Kerberos option %d\r\n"), data[-1]);
		return;
	}
}

/* ARGSUSED */
int
kerberos5_status(Authenticator *ap, char *name, int level)
{
	if (level < AUTH_USER)
		return (level);

	if (UserNameRequested && krb5_kuserok(telnet_context,
		ticket->enc_part2->client, UserNameRequested)) {

		/* the name buffer comes from telnetd/telnetd{-ktd}.c */
		(void) strncpy(name, UserNameRequested, MAXNAMELEN);
		name[MAXNAMELEN-1] = '\0';
		return (AUTH_VALID);
	} else
		return (AUTH_USER);
}

#define	BUMP(buf, len)		while (*(buf)) {++(buf), --(len); }
#define	ADDC(buf, len, c)	if ((len) > 0) {*(buf)++ = (c); --(len); }

/*
 * Used with the set opt command to print suboptions
 */
void
kerberos5_printsub(unsigned char *data, int cnt, unsigned char *buf, int buflen)
{
	char lbuf[AUTH_LBUF_BUFSIZ];
	register int i;

	buf[buflen-1] = '\0';		/* make sure its NULL terminated */
	buflen -= 1;

	switch (data[3]) {
	case KRB_REJECT:		/* Rejected (reason might follow) */
		(void) strncpy((char *)buf, " REJECT ", buflen);
		goto common;

	case KRB_ACCEPT:		/* Accepted (name might follow) */
		(void) strncpy((char *)buf, " ACCEPT ", buflen);
	common:
		BUMP(buf, buflen);
		if (cnt <= 4)
			break;
		ADDC(buf, buflen, '"');
		for (i = 4; i < cnt; i++)
			ADDC(buf, buflen, data[i]);
		ADDC(buf, buflen, '"');
		ADDC(buf, buflen, '\0');
		break;

	case KRB_AUTH:			/* Authentication data follows */
		(void) strncpy((char *)buf, " AUTH", buflen);
		goto common2;

	case KRB_RESPONSE:
		(void) strncpy((char *)buf, " RESPONSE", buflen);
		goto common2;

	case KRB_FORWARD:		/* Forwarded credentials follow */
		(void) strncpy((char *)buf, " FORWARD", buflen);
		goto common2;

	case KRB_FORWARD_ACCEPT:	/* Forwarded credentials accepted */
		(void) strncpy((char *)buf, " FORWARD_ACCEPT", buflen);
		goto common2;

	case KRB_FORWARD_REJECT:	/* Forwarded credentials rejected */
					/* (reason might follow) */
		(void) strncpy((char *)buf, " FORWARD_REJECT", buflen);
		goto common2;

	default:
		(void) snprintf(lbuf, AUTH_LBUF_BUFSIZ,
			gettext(" %d (unknown)"),
			data[3]);
		(void) strncpy((char *)buf, lbuf, buflen);
	common2:
		BUMP(buf, buflen);
		for (i = 4; i < cnt; i++) {
			(void) snprintf(lbuf, AUTH_LBUF_BUFSIZ, " %d", data[i]);
			(void) strncpy((char *)buf, lbuf, buflen);
			BUMP(buf, buflen);
		}
		break;
	}
}

void
krb5_profile_get_options(char *host, char *realm,
	profile_options_boolean *optionsp)
{
	char	**realms = NULL;
	krb5_error_code err = 0;

	if (!telnet_context) {
	    err = krb5_init_context(&telnet_context);
	    if (err) {
		(void) fprintf(stderr, gettext(
			"Error initializing Kerberos 5 library: %s\n"),
			error_message(err));
		return;
	    }
	}

	if ((realmdef[1] = realm) == NULL) {
		err = krb5_get_host_realm(telnet_context, host, &realms);
		if (err) {
		    (void) fprintf(stderr, gettext(
			"Error getting Kerberos 5 realms for: %s (%s)\n"),
			host, error_message(err));
		    return;
		}
		realmdef[1] = realms[0];
	}

	profile_get_options_boolean(telnet_context->profile,
		realmdef, optionsp);
	profile_get_options_boolean(telnet_context->profile,
		appdef, optionsp);
}

static void
kerberos5_forward(Authenticator *ap)
{
	krb5_error_code retval;
	krb5_ccache ccache;
	krb5_principal client = 0;
	krb5_principal server = 0;
	krb5_data forw_creds;

	forw_creds.data = 0;

	if ((retval = krb5_cc_default(telnet_context, &ccache))) {
	    if (auth_debug_mode)
		(void) printf(gettext(
			"Kerberos V5: could not get default ccache - %s\r\n"),
			error_message(retval));
	    return;
	}

	retval = krb5_cc_get_principal(telnet_context, ccache, &client);
	if (retval) {
		if (auth_debug_mode)
			(void) printf(gettext(
				"Kerberos V5: could not get default "
				"principal - %s\r\n"), error_message(retval));
		goto cleanup;
	}

	retval = krb5_sname_to_principal(telnet_context, RemoteHostName,
		"host", KRB5_NT_SRV_HST, &server);
	if (retval) {
		if (auth_debug_mode)
			(void) printf(gettext(
				"Kerberos V5: could not make server "
				"principal - %s\r\n"), error_message(retval));
		goto cleanup;
	}

	retval = krb5_auth_con_genaddrs(telnet_context, auth_context, net,
				KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR);
	if (retval) {
		if (auth_debug_mode)
			(void) printf(gettext(
				"Kerberos V5: could not gen local full "
				"address - %s\r\n"), error_message(retval));
		goto cleanup;
	}

	retval = krb5_fwd_tgt_creds(telnet_context, auth_context, 0, client,
		server, ccache, forward_flags & OPTS_FORWARDABLE_CREDS,
		&forw_creds);
	if (retval) {
		if (auth_debug_mode)
			(void) printf(gettext(
				"Kerberos V5: error getting forwarded "
				"creds - %s\r\n"), error_message(retval));
		goto cleanup;
	}

	/* Send forwarded credentials */
	if (!krb5_send_data(ap, KRB_FORWARD, forw_creds.data,
		forw_creds.length)) {
		    if (auth_debug_mode)
			(void) printf(gettext(
			    "Not enough room for authentication data\r\n"));
	} else if (auth_debug_mode)
		(void) printf(gettext(
		    "Forwarded local Kerberos V5 credentials to server\r\n"));
cleanup:
	if (client)
		krb5_free_principal(telnet_context, client);
	if (server)
		krb5_free_principal(telnet_context, server);
	if (forw_creds.data)
		free(forw_creds.data);
	/* LINTED */
	krb5_cc_close(telnet_context, ccache);
}
