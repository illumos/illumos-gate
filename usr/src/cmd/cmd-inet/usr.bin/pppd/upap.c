/*
 * upap.c - User/Password Authentication Protocol.
 *
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.
 *
 * SUN MAKES NO REPRESENTATION OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  SUN SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <string.h>

#include "pppd.h"
#include "upap.h"

static bool hide_password = 1;

/*
 * Command-line options.
 */
static option_t pap_option_list[] = {
    { "hide-password", o_bool, &hide_password,
      "Don't output passwords to log", 1 },
    { "show-password", o_bool, &hide_password,
      "Show password string in debug log messages", 0 },
    { "pap-restart", o_int, &upap[0].us_timeouttime,
      "Set retransmit timeout for PAP" },
    { "pap-max-authreq", o_int, &upap[0].us_maxtransmits,
      "Max number of PAP Authenticate-Request sent" },
    { "pap-max-receive", o_int, &upap[0].us_maxreceives,
      "Max allowable PAP Authenticate-Request received" },
    { "pap-timeout", o_int, &upap[0].us_reqtimeout,
      "Set time limit for peer PAP authentication" },
    { NULL }
};

/*
 * Protocol entry points.
 */
static void upap_init __P((int));
static void upap_lowerup __P((int));
static void upap_lowerdown __P((int));
static void upap_input __P((int, u_char *, int));
static void upap_protrej __P((int));
static int  upap_printpkt __P((u_char *, int,
    void (*) __P((void *, const char *, ...)), void *));

struct protent pap_protent = {
    PPP_PAP,
    upap_init,
    upap_input,
    upap_protrej,
    upap_lowerup,
    upap_lowerdown,
    NULL,
    NULL,
    upap_printpkt,
    NULL,
    1,
    "PAP",
    NULL,
    pap_option_list,
    NULL,
    NULL,
    NULL
};

upap_state upap[NUM_PPP];		/* UPAP state; one for each unit */

static void upap_timeout __P((void *));
static void upap_reqtimeout __P((void *));
static void upap_rauthreq __P((upap_state *, u_char *, int, int));
static void upap_rauthack __P((upap_state *, u_char *, int, int));
static void upap_rauthnak __P((upap_state *, u_char *, int, int));
static void upap_sauthreq __P((upap_state *));
static void upap_sresp __P((upap_state *, int, int, char *, int));

static const char *
pap_cstate(clientstate)
    int clientstate;
{
    static const char *cstate[] = { UPAPCS__NAMES };
    static char buf[32];

    if (clientstate < 0 || clientstate >= Dim(cstate)) {
	(void) slprintf(buf, sizeof (buf), "Cli#%d", clientstate);
	return ((const char *)buf);
    }
    return (cstate[clientstate]);
}

static const char *
pap_sstate(serverstate)
    int serverstate;
{
    static const char *sstate[] = { UPAPSS__NAMES };
    static char buf[32];

    if (serverstate < 0 || serverstate >= Dim(sstate)) {
	(void) slprintf(buf, sizeof (buf), "Srv#%d", serverstate);
	return ((const char *)buf);
    }
    return (sstate[serverstate]);
}

/*
 * upap_init - Initialize a UPAP unit.
 */
static void
upap_init(unit)
    int unit;
{
    upap_state *u = &upap[unit];

    u->us_unit = unit;
    u->us_user = NULL;
    u->us_userlen = 0;
    u->us_passwd = NULL;
    u->us_clientstate = UPAPCS_INITIAL;
    u->us_serverstate = UPAPSS_INITIAL;
    u->us_id = 0;
    u->us_timeouttime = UPAP_DEFTIMEOUT;
    u->us_maxtransmits = 10;
    u->us_reqtimeout = UPAP_DEFREQTIME;
    u->us_maxreceives = 3;
    u->us_msg = "";
    u->us_msglen = 0;
}


/*
 * upap_authwithpeer - Authenticate us with our peer (start client).
 *
 * Set new state and send authenticate's.
 */
void
upap_authwithpeer(unit, user, password)
    int unit;
    char *user, *password;
{
    upap_state *u = &upap[unit];

    /* Save the username and password we're given */
    u->us_user = user;
    u->us_userlen = strlen(user);
    u->us_passwd = password;
    u->us_transmits = 0;

    /* Lower layer up yet? */
    if (u->us_clientstate == UPAPCS_INITIAL ||
	u->us_clientstate == UPAPCS_PENDING) {
	u->us_clientstate = UPAPCS_PENDING;
	return;
    }

    upap_sauthreq(u);			/* Start protocol */
}


/*
 * upap_authpeer - Authenticate our peer (start server).
 *
 * Set new state.
 */
void
upap_authpeer(unit)
    int unit;
{
    upap_state *u = &upap[unit];

    /* Lower layer up yet? */
    if (u->us_serverstate == UPAPSS_INITIAL ||
	u->us_serverstate == UPAPSS_PENDING) {
	u->us_serverstate = UPAPSS_PENDING;
	return;
    }

    u->us_serverstate = UPAPSS_LISTEN;
    u->us_receives = 0;
    if (u->us_reqtimeout > 0)
	TIMEOUT(upap_reqtimeout, u, u->us_reqtimeout);
}


/*
 * upap_timeout - Retransmission timer for sending auth-reqs expired.
 */
static void
upap_timeout(arg)
    void *arg;
{
    upap_state *u = (upap_state *) arg;

    if (u->us_clientstate != UPAPCS_AUTHREQ)
	return;

    if (u->us_transmits >= u->us_maxtransmits) {
	/* give up in disgust */
	error("No response to %d PAP Authenticate-Requests", u->us_transmits);
	u->us_clientstate = UPAPCS_BADAUTH;
	auth_withpeer_fail(u->us_unit, PPP_PAP);
	return;
    }

    upap_sauthreq(u);		/* Send Authenticate-Request */
}


/*
 * upap_reqtimeout - Give up waiting for the peer to send a valid auth-req.
 */
static void
upap_reqtimeout(arg)
    void *arg;
{
    upap_state *u = (upap_state *) arg;

    if (u->us_serverstate != UPAPSS_LISTEN)
	return;			/* huh?? */

    auth_peer_fail(u->us_unit, PPP_PAP);
    u->us_serverstate = UPAPSS_BADAUTH;
}


/*
 * upap_lowerup - The lower layer is up.
 *
 * Start authenticating if pending.
 */
static void
upap_lowerup(unit)
    int unit;
{
    upap_state *u = &upap[unit];

    if (u->us_clientstate == UPAPCS_INITIAL)
	u->us_clientstate = UPAPCS_CLOSED;
    else if (u->us_clientstate == UPAPCS_PENDING) {
	upap_sauthreq(u);	/* send an auth-request */
    }

    if (u->us_serverstate == UPAPSS_INITIAL)
	u->us_serverstate = UPAPSS_CLOSED;
    else if (u->us_serverstate == UPAPSS_PENDING) {
	u->us_serverstate = UPAPSS_LISTEN;
	if (u->us_reqtimeout > 0)
	    TIMEOUT(upap_reqtimeout, u, u->us_reqtimeout);
    }
}


/*
 * upap_lowerdown - The lower layer is down.
 *
 * Cancel all timeouts.
 */
static void
upap_lowerdown(unit)
    int unit;
{
    upap_state *u = &upap[unit];

    /* Cancel timeouts */
    if (u->us_clientstate == UPAPCS_AUTHREQ && u->us_timeouttime > 0)
	UNTIMEOUT(upap_timeout, u);
    if (u->us_serverstate == UPAPSS_LISTEN && u->us_reqtimeout > 0)
	UNTIMEOUT(upap_reqtimeout, u);

    u->us_clientstate = UPAPCS_INITIAL;
    u->us_serverstate = UPAPSS_INITIAL;
}


/*
 * upap_protrej - Peer doesn't speak this protocol.
 *
 * This shouldn't happen.  In any case, pretend lower layer went down.
 */
static void
upap_protrej(unit)
    int unit;
{
    upap_state *u = &upap[unit];

    if (u->us_clientstate == UPAPCS_AUTHREQ) {
	error("PAP authentication failed due to protocol-reject");
	auth_withpeer_fail(unit, PPP_PAP);
    }
    if (u->us_serverstate == UPAPSS_LISTEN) {
	error("PAP authentication of peer failed (protocol-reject)");
	auth_peer_fail(unit, PPP_PAP);
    }
    upap_lowerdown(unit);
}


/*
 * upap_input - Input UPAP packet.
 */
static void
upap_input(unit, inpacket, l)
    int unit;
    u_char *inpacket;
    int l;
{
    upap_state *u = &upap[unit];
    u_char *inp;
    u_char code, id;
    int len;

    /*
     * Parse header (code, id and length).
     * If packet too short, drop it.
     */
    inp = inpacket;
    if (l < UPAP_HEADERLEN) {
	error("PAP: packet is too small (%d < %d)", l, UPAP_HEADERLEN);
	return;
    }
    GETCHAR(code, inp);
    GETCHAR(id, inp);
    GETSHORT(len, inp);
    if ((len < UPAP_HEADERLEN) || (len > l)) {
	error("PAP: packet has illegal length %d (%d..%d)", len,
	    UPAP_HEADERLEN, l);
	return;
    }
    len -= UPAP_HEADERLEN;

    /*
     * Action depends on code.
     */
    switch (code) {
    case UPAP_AUTHREQ:
	upap_rauthreq(u, inp, id, len);
	break;

    case UPAP_AUTHACK:
	upap_rauthack(u, inp, id, len);
	break;

    case UPAP_AUTHNAK:
	upap_rauthnak(u, inp, id, len);
	break;

    default:
	warn("Unknown PAP code (%d) received.", code);
	break;
    }
}


/*
 * upap_rauth - Receive Authenticate.
 */
static void
upap_rauthreq(u, inp, id, len)
    upap_state *u;
    u_char *inp;
    int id;
    int len;
{
    u_char ruserlen, rpasswdlen;
    char *ruser, *rpasswd;
    int retcode;
    char *msg;
    int msglen;

    if (u->us_serverstate < UPAPSS_LISTEN) {
	info("PAP: discarded Authenticate-Request in state %s",
	    pap_sstate(u->us_serverstate));
	return;
    }

    /*
     * If we receive a duplicate authenticate-request, we are
     * supposed to return the same status as for the first request.
     */
    if (u->us_serverstate == UPAPSS_OPEN) {
	/* return auth-ack */
	upap_sresp(u, UPAP_AUTHACK, id, u->us_msg, u->us_msglen);
	return;
    }
    if (u->us_serverstate == UPAPSS_BADAUTH) {
	/* return auth-nak */
	upap_sresp(u, UPAP_AUTHNAK, id, u->us_msg, u->us_msglen);
	return;
    }

    /*
     * Parse user/passwd.
     */
    if (len < 1) {
	error("PAP: rcvd short packet; no data");
	return;
    }
    GETCHAR(ruserlen, inp);
    len -= sizeof (u_char) + ruserlen + sizeof (u_char);
    if (len < 0) {
	error("PAP: rcvd short packet; peer name missing");
	return;
    }
    ruser = (char *) inp;
    INCPTR(ruserlen, inp);
    GETCHAR(rpasswdlen, inp);
    if (len < rpasswdlen) {
	error("PAP: rcvd short packet; pass len %d < %d", len, rpasswdlen);
	return;
    }
    rpasswd = (char *) inp;

    /*
     * Check the username and password given.
     */
    retcode = check_passwd(u->us_unit, ruser, ruserlen, rpasswd,
			   rpasswdlen, &msg);
    BZERO(rpasswd, rpasswdlen);
    msglen = strlen(msg);
    if (msglen > 255)
	msglen = 255;

    u->us_msg = msg;
    u->us_msglen = msglen;
    upap_sresp(u, retcode, id, u->us_msg, u->us_msglen);

    if (retcode == UPAP_AUTHACK) {
	u->us_serverstate = UPAPSS_OPEN;
	auth_peer_success(u->us_unit, PPP_PAP, ruser, ruserlen);
    } else if (++u->us_receives >= u->us_maxreceives) {
	u->us_serverstate = UPAPSS_BADAUTH;
	auth_peer_fail(u->us_unit, PPP_PAP);
    } else {
	/* Just wait for a good one to arrive, or for time-out. */
	return;
    }

    if (u->us_reqtimeout > 0)
	UNTIMEOUT(upap_reqtimeout, u);
}


/*
 * upap_rauthack - Receive Authenticate-Ack.
 */
/*ARGSUSED*/
static void
upap_rauthack(u, inp, id, len)
    upap_state *u;
    u_char *inp;
    int id;
    int len;
{
    u_char msglen;
    char *msg;

    if (u->us_clientstate != UPAPCS_AUTHREQ) {
	info("PAP: discarded Authenticate-Ack in state %s",
	    pap_cstate(u->us_clientstate));
	return;
    }

    if (id != u->us_id) {
	dbglog("PAP: discard Authenticate-Ack; ID %d != %d",
	    id, u->us_id);
	return;
    }

    if (u->us_timeouttime > 0)
	UNTIMEOUT(upap_timeout, u);

    /*
     * Parse message.
     */
    if (len < 1) {
	info("PAP:  Ignoring missing ack msg-length octet");
    } else {
	GETCHAR(msglen, inp);
	if (msglen > 0) {
	    len -= sizeof (u_char);
	    if (len < msglen) {
		error("PAP:  Discarding short packet (%d < %d)", len, msglen);
		return;
	    }
	    msg = (char *) inp;
	    PRINTMSG(msg, msglen);
	}
    }

    u->us_clientstate = UPAPCS_OPEN;

    auth_withpeer_success(u->us_unit, PPP_PAP);
}


/*
 * upap_rauthnak - Receive Authenticate-Nakk.
 */
/*ARGSUSED*/
static void
upap_rauthnak(u, inp, id, len)
    upap_state *u;
    u_char *inp;
    int id;
    int len;
{
    u_char msglen;
    char *msg;

    if (u->us_clientstate != UPAPCS_AUTHREQ) {
	info("PAP: discarded Authenticate-Nak in state %s",
	    pap_cstate(u->us_clientstate));
	return;
    }

    if (id != u->us_id) {
	dbglog("PAP: discard Authenticate-Ack; ID %d != %d",
	    id, u->us_id);
	return;
    }

    if (u->us_timeouttime > 0)
	UNTIMEOUT(upap_timeout, u);

    /*
     * Parse message.
     */
    if (len < 1) {
	error("PAP: ignoring missing nak msg-length octet");
    } else {
	GETCHAR(msglen, inp);
	if (msglen > 0) {
	    len -= sizeof (u_char);
	    if (len < msglen) {
		error("PAP: Discarding short packet (%d < %d)", len, msglen);
		return;
	    }
	    msg = (char *) inp;
	    PRINTMSG(msg, msglen);
	}
    }

    /* Try to get a new password from the plugin. */
    if (pap_passwd_hook != NULL) {
	if (u->us_transmits < u->us_maxtransmits) {
	    if ((*pap_passwd_hook)(user, passwd) >= 0) {
		upap_sauthreq(u);
		return;
	    }
	} else {
	    /* Tell plug-in that we're giving up. */
	    (void) (*pap_passwd_hook)(NULL, NULL);
	}
    }

    u->us_clientstate = UPAPCS_BADAUTH;

    error("PAP authentication failed");
    auth_withpeer_fail(u->us_unit, PPP_PAP);
}


/*
 * upap_sauthreq - Send an Authenticate-Request.
 */
static void
upap_sauthreq(u)
    upap_state *u;
{
    u_char *outp;
    int pwlen;
    int outlen;

    pwlen = strllen(passwd, MAXSECRETLEN);
    if (pwlen > 0xFF)
	pwlen = 0xFF;
    outlen = UPAP_HEADERLEN + 2 * sizeof (u_char) + u->us_userlen + pwlen;
    outp = outpacket_buf;

    MAKEHEADER(outp, PPP_PAP);

    PUTCHAR(UPAP_AUTHREQ, outp);
    PUTCHAR(++u->us_id, outp);
    PUTSHORT(outlen, outp);
    PUTCHAR(u->us_userlen, outp);
    BCOPY(u->us_user, outp, u->us_userlen);
    INCPTR(u->us_userlen, outp);
    PUTCHAR(pwlen, outp);
    BCOPY(u->us_passwd, outp, pwlen);

    output(u->us_unit, outpacket_buf, outlen + PPP_HDRLEN);

    if (u->us_timeouttime > 0)
	TIMEOUT(upap_timeout, u, u->us_timeouttime);
    ++u->us_transmits;
    u->us_clientstate = UPAPCS_AUTHREQ;
}


/*
 * upap_sresp - Send a response (ack or nak).
 */
static void
upap_sresp(u, code, id, msg, msglen)
    upap_state *u;
    u_char code, id;
    char *msg;
    int msglen;
{
    u_char *outp;
    int outlen;

    outlen = UPAP_HEADERLEN + sizeof (u_char) + msglen;
    outp = outpacket_buf;
    MAKEHEADER(outp, PPP_PAP);

    PUTCHAR(code, outp);
    PUTCHAR(id, outp);
    PUTSHORT(outlen, outp);
    PUTCHAR(msglen, outp);
    BCOPY(msg, outp, msglen);
    output(u->us_unit, outpacket_buf, outlen + PPP_HDRLEN);
}

/*
 * upap_printpkt - print the contents of a PAP packet.
 */
static char *upap_codenames[] = {
    "AuthReq", "AuthAck", "AuthNak"
};

static int
upap_printpkt(p, plen, printer, arg)
    u_char *p;
    int plen;
    void (*printer) __P((void *, const char *, ...));
    void *arg;
{
    int code, id, len;
    int mlen, ulen, wlen;
    char *user, *pwd, *msg;
    u_char *pstart;

    if (plen < UPAP_HEADERLEN)
	return (0);
    pstart = p;
    GETCHAR(code, p);
    GETCHAR(id, p);
    GETSHORT(len, p);
    if (len < UPAP_HEADERLEN || len > plen)
	return (0);

    if (code >= 1 && code <= Dim(upap_codenames))
	printer(arg, " %s", upap_codenames[code-1]);
    else
	printer(arg, " code=0x%x", code);
    printer(arg, " id=0x%x", id);
    len -= UPAP_HEADERLEN;
    switch (code) {
    case UPAP_AUTHREQ:
	if (len < 1)
	    break;
	ulen = p[0];
	if (len < ulen + 2)
	    break;
	wlen = p[ulen + 1];
	if (len < ulen + wlen + 2)
	    break;
	user = (char *) (p + 1);
	pwd = (char *) (p + ulen + 2);
	p += ulen + wlen + 2;
	len -= ulen + wlen + 2;
	printer(arg, " user=");
	print_string(user, ulen, printer, arg);
	printer(arg, " password=");
	if (!hide_password)
	    print_string(pwd, wlen, printer, arg);
	else
	    printer(arg, "<hidden>");
	break;
    case UPAP_AUTHACK:
    case UPAP_AUTHNAK:
	if (len < 1)
	    break;
	mlen = p[0];
	if (len < mlen + 1)
	    break;
	msg = (char *) (p + 1);
	p += mlen + 1;
	len -= mlen + 1;
	printer(arg, " ");
	print_string(msg, mlen, printer, arg);
	break;
    }

    /* print the rest of the bytes in the packet */
    for (; len > 0; --len) {
	GETCHAR(code, p);
	printer(arg, " %.2x", code);
    }

    return (p - pstart);
}
