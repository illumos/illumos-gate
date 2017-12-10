/*
 * fsm.c - {Link, IP} Control Protocol Finite State Machine.
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

/*
 * TODO:
 * Randomize fsm id on link/init.
 * Deal with variable outgoing MTU.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#ifndef NO_DRAND48
#include <stdlib.h>
#endif /* NO_DRAND48 */

#include "pppd.h"
#include "fsm.h"

static void fsm_timeout __P((void *));
static void fsm_rconfreq __P((fsm *, int, u_char *, int));
static void fsm_rconfack __P((fsm *, int, u_char *, int));
static void fsm_rconfnakrej __P((fsm *, int, int, u_char *, int));
static void fsm_rtermreq __P((fsm *, int, u_char *, int));
static void fsm_rtermack __P((fsm *));
static void fsm_rcoderej __P((fsm *, u_char *, int));
static void fsm_sconfreq __P((fsm *, int));

#define PROTO_NAME(f)	((f)->callbacks->proto_name)

static int peer_mru[NUM_PPP];

const char *
fsm_state(int statenum)
{
    static const char *fsm_states[] = { FSM__STATES };
    static char buf[32];

    if (statenum < 0 || statenum >= Dim(fsm_states)) {
	(void) slprintf(buf, sizeof (buf), "unknown#%d", statenum);
	return buf;
    }
    return fsm_states[statenum];
}

/*
 * fsm_init - Initialize fsm.
 *
 * Initialize fsm state.
 */
void
fsm_init(f)
    fsm *f;
{
    f->state = INITIAL;
    f->flags = 0;
    f->id = (uchar_t)(drand48() * 0xFF);	/* Start with random id */
    f->timeouttime = DEFTIMEOUT;
    f->maxconfreqtransmits = DEFMAXCONFREQS;
    f->maxtermtransmits = DEFMAXTERMREQS;
    f->maxnakloops = DEFMAXNAKLOOPS;
    f->term_reason_len = 0;
}


/*
 * fsm_lowerup - The lower layer is up.
 */
void
fsm_lowerup(f)
    fsm *f;
{
    switch( f->state ){
    case INITIAL:
	f->state = CLOSED;
	break;

    case STARTING:
	if( f->flags & OPT_SILENT )
	    f->state = STOPPED;
	else {
	    /* Send an initial configure-request */
	    fsm_sconfreq(f, 0);
	    f->state = REQSENT;
	}
	break;

    default:
	error("%s: Up event in state %s", PROTO_NAME(f), fsm_state(f->state));
    }
}


/*
 * fsm_lowerdown - The lower layer is down.
 *
 * Cancel all timeouts and inform upper layers.
 */
void
fsm_lowerdown(f)
    fsm *f;
{
    switch( f->state ){
    case CLOSED:
	f->state = INITIAL;
	break;

    case STOPPED:
	f->state = STARTING;
	if (f->callbacks->starting != NULL)
	    (*f->callbacks->starting)(f);
	break;

    case CLOSING:
	f->state = INITIAL;
	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	break;

    case STOPPING:
    case REQSENT:
    case ACKRCVD:
    case ACKSENT:
	f->state = STARTING;
	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	break;

    case OPENED:
	f->state = STARTING;
	if (f->callbacks->down != NULL)
	    (*f->callbacks->down)(f);
	break;

    default:
	dbglog("%s: Down event in state %s", PROTO_NAME(f),
	    fsm_state(f->state));
    }
}


/*
 * fsm_open - Link is allowed to come up.
 */
void
fsm_open(f)
    fsm *f;
{
    switch( f->state ){
    case INITIAL:
	f->state = STARTING;
	if (f->callbacks->starting != NULL)
	    (*f->callbacks->starting)(f);
	break;

    case CLOSED:
	if( f->flags & OPT_SILENT )
	    f->state = STOPPED;
	else {
	    /* Send an initial configure-request */
	    fsm_sconfreq(f, 0);
	    f->state = REQSENT;
	}
	break;

    case CLOSING:
	f->state = STOPPING;
	/*FALLTHROUGH*/
    case STOPPING:
    case STOPPED:
    case OPENED:
	if( f->flags & OPT_RESTART ){
	    fsm_lowerdown(f);
	    fsm_lowerup(f);
	}
	break;

    case STARTING:
    case REQSENT:
    case ACKRCVD:
    case ACKSENT:
	/* explicitly do nothing here. */
	break;
    }
}


/*
 * fsm_close - Start closing connection.
 *
 * Cancel timeouts and either initiate close or possibly go directly to
 * the CLOSED state.
 */
void
fsm_close(f, reason)
    fsm *f;
    char *reason;
{
    int prevstate = f->state;

    f->term_reason = reason;
    f->term_reason_len = (reason == NULL? 0: strlen(reason));
    switch( f->state ){
    case STARTING:
	f->state = INITIAL;
	if (f->callbacks->finished != NULL)
	    (*f->callbacks->finished)(f);
	break;

    case STOPPED:
	f->state = CLOSED;
	break;

    case STOPPING:
	f->state = CLOSING;
	break;

    case REQSENT:
    case ACKRCVD:
    case ACKSENT:
    case OPENED:
	f->state = CLOSING;
	if (prevstate != OPENED )
	    UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	else if (f->callbacks->down != NULL)
	    (*f->callbacks->down)(f);	/* Inform upper layers we're down */
	/*
	 * Note that this-layer-down means "stop transmitting."
	 * This-layer-finished means "stop everything."
	 */

	/* Init restart counter, send Terminate-Request */
	f->retransmits = f->maxtermtransmits;
	fsm_sdata(f, CODE_TERMREQ, f->reqid = ++f->id,
		  (u_char *) f->term_reason, f->term_reason_len);
	TIMEOUT(fsm_timeout, f, f->timeouttime);
	--f->retransmits;
	break;

    case INITIAL:
    case CLOSED:
    case CLOSING:
	/* explicitly do nothing here. */
	break;
    }
}


/*
 * fsm_timeout - Timeout expired.
 */
static void
fsm_timeout(arg)
    void *arg;
{
    fsm *f = (fsm *) arg;

    switch (f->state) {
    case CLOSING:
    case STOPPING:
	if( f->retransmits <= 0 ){
	    /*
	     * We've waited for an ack long enough.  Peer probably heard us.
	     */
	    f->state = (f->state == CLOSING)? CLOSED: STOPPED;
	    if (f->callbacks->finished != NULL)
		(*f->callbacks->finished)(f);
	} else {
	    /* Send Terminate-Request */
	    fsm_sdata(f, CODE_TERMREQ, f->reqid = ++f->id,
		      (u_char *) f->term_reason, f->term_reason_len);
	    TIMEOUT(fsm_timeout, f, f->timeouttime);
	    --f->retransmits;
	}
	break;

    case REQSENT:
    case ACKRCVD:
    case ACKSENT:
	if (f->retransmits <= 0) {
	    warn("%s: timeout sending Config-Requests\n", PROTO_NAME(f));
	    f->state = STOPPED;
	    if (!(f->flags & OPT_PASSIVE) && f->callbacks->finished != NULL)
		(*f->callbacks->finished)(f);

	} else {
	    /* Retransmit the configure-request */
	    if (f->callbacks->retransmit != NULL)
		(*f->callbacks->retransmit)(f);
	    fsm_sconfreq(f, 1);		/* Re-send Configure-Request */
	    if( f->state == ACKRCVD )
		f->state = REQSENT;
	}
	break;

    default:
	fatal("%s: Timeout event in state %s!", PROTO_NAME(f),
	    fsm_state(f->state));
    }
}


/*
 * fsm_input - Input packet.
 */
void
fsm_input(f, inpacket, l)
    fsm *f;
    u_char *inpacket;
    int l;
{
    u_char *inp;
    u_char code, id;
    int len;

    /*
     * Parse header (code, id and length).
     * If packet too short, drop it.
     */
    inp = inpacket;
    if (l < HEADERLEN) {
	error("%s packet: discard; too small (%d < %d)", PROTO_NAME(f), l,
	    HEADERLEN);
	return;
    }
    GETCHAR(code, inp);
    GETCHAR(id, inp);
    GETSHORT(len, inp);
    if (len < HEADERLEN) {
	error("%s packet: discard; invalid length (%d < %d)", PROTO_NAME(f),
	    len, HEADERLEN);
	return;
    }
    if (len > l) {
	error("%s packet: discard; truncated (%d > %d)", PROTO_NAME(f), len,
	    l);
	return;
    }
    len -= HEADERLEN;		/* subtract header length */

    if (f->state == INITIAL || f->state == STARTING) {
	dbglog("%s: discarded packet in state %s", PROTO_NAME(f),
	    fsm_state(f->state));
	return;
    }

    /*
     * Action depends on code.
     */
    switch (code) {
    case CODE_CONFREQ:
	fsm_rconfreq(f, id, inp, len);
	break;
    
    case CODE_CONFACK:
	fsm_rconfack(f, id, inp, len);
	break;
    
    case CODE_CONFNAK:
    case CODE_CONFREJ:
	fsm_rconfnakrej(f, code, id, inp, len);
	break;
    
    case CODE_TERMREQ:
	fsm_rtermreq(f, id, inp, len);
	break;
    
    case CODE_TERMACK:
	fsm_rtermack(f);
	break;
    
    case CODE_CODEREJ:
	fsm_rcoderej(f, inp, len);
	break;
    
    default:
	if (f->callbacks->extcode == NULL ||
	    !(*f->callbacks->extcode)(f, code, id, inp, len))
	    fsm_sdata(f, CODE_CODEREJ, ++f->id, inpacket, len + HEADERLEN);
	break;
    }
}


/*
 * fsm_rconfreq - Receive Configure-Request.
 */
static void
fsm_rconfreq(f, id, inp, len)
    fsm *f;
    u_char id;
    u_char *inp;
    int len;
{
    int code, reject_if_disagree;

    switch( f->state ){
    case CLOSED:
	/* Go away, we're closed */
	fsm_sdata(f, CODE_TERMACK, id, NULL, 0);
	return;

    case CLOSING:
    case STOPPING:
	dbglog("%s: discarded Configure-Request in state %s", PROTO_NAME(f),
	    fsm_state(f->state));
	return;

    case OPENED:
	/* Go down and restart negotiation */
	if (f->callbacks->down != NULL)
	    (*f->callbacks->down)(f);	/* Inform upper layers */
	break;
    }

#ifdef DEBUG
    if (inp >= outpacket_buf && inp < outpacket_buf+PPP_MRU+PPP_HDRLEN)
	fatal("bad pointer");
#endif

    /*
     * Pass the requested configuration options
     * to protocol-specific code for checking.
     */
    if (f->callbacks->reqci != NULL) {		/* Check CI */
	reject_if_disagree = (f->nakloops >= f->maxnakloops);
	code = (*f->callbacks->reqci)(f, inp, &len, reject_if_disagree);
    } else if (len > 0)
	code = CODE_CONFREJ;			/* Reject all CI */
    else
	code = CODE_CONFACK;

    /* Allow NCP to do fancy footwork, such as reinitializing. */
    if (code <= 0)
	return;

    if (f->state == OPENED || f->state == STOPPED)
	fsm_sconfreq(f, 0);		/* Send initial Configure-Request */

    /* send the Ack, Nak or Rej to the peer */
    fsm_sdata(f, code, id, inp, len);

    if (code == CODE_CONFACK) {
	/* RFC 1661 event RCR+ */
	if (f->state == ACKRCVD) {
	    UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	    f->state = OPENED;
	    if (f->callbacks->up != NULL)
		(*f->callbacks->up)(f);	/* Inform upper layers */
	} else
	    f->state = ACKSENT;
	f->nakloops = 0;

    } else {
	/* RFC 1661 event RCR- */
	/* (we sent CODE_CONFNAK or CODE_CONFREJ) */
	if (f->state != ACKRCVD)
	    f->state = REQSENT;
	if( code == CODE_CONFNAK )
	    ++f->nakloops;
    }
}


/*
 * fsm_rconfack - Receive Configure-Ack.
 */
static void
fsm_rconfack(f, id, inp, len)
    fsm *f;
    int id;
    u_char *inp;
    int len;
{
    if (id != f->reqid || f->seen_ack)		/* Expected id? */
	return;					/* Nope, toss... */
    if( !(f->callbacks->ackci != NULL ? (*f->callbacks->ackci)(f, inp, len):
	  (len == 0)) ){
	/* Ack is bad - ignore it */
	error("Received bad configure-ack: %P", inp, len);
	return;
    }
    f->seen_ack = 1;

    switch (f->state) {
    case CLOSED:
    case STOPPED:
	fsm_sdata(f, CODE_TERMACK, id, NULL, 0);
	break;

    case REQSENT:
	f->state = ACKRCVD;
	f->retransmits = f->maxconfreqtransmits;
	break;

    case ACKRCVD:
	/* Huh? an extra valid Ack? oh well... */
	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	fsm_sconfreq(f, 0);
	f->state = REQSENT;
	break;

    case ACKSENT:
	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	f->state = OPENED;
	f->retransmits = f->maxconfreqtransmits;
	if (f->callbacks->up != NULL)
	    (*f->callbacks->up)(f);	/* Inform upper layers */
	break;

    case OPENED:
	/* Go down and restart negotiation */
	fsm_sconfreq(f, 0);		/* Send initial Configure-Request */
	f->state = REQSENT;
	if (f->callbacks->down != NULL)
	    (*f->callbacks->down)(f);	/* Inform upper layers */
	break;
    }
}


/*
 * fsm_rconfnakrej - Receive Configure-Nak or Configure-Reject.
 */
static void
fsm_rconfnakrej(f, code, id, inp, len)
    fsm *f;
    int code, id;
    u_char *inp;
    int len;
{
    int (*proc) __P((fsm *, u_char *, int));
    int ret;

    if (id != f->reqid || f->seen_ack)	/* Expected id? */
	return;				/* Nope, toss... */
    proc = (code == CODE_CONFNAK)? f->callbacks->nakci: f->callbacks->rejci;
    if (proc == NULL || !(ret = proc(f, inp, len))) {
	/* Nak/reject is bad - ignore it */
	error("Received bad configure-nak/rej: %P", inp, len);
	return;
    }
    f->seen_ack = 1;

    switch (f->state) {
    case CLOSED:
    case STOPPED:
	fsm_sdata(f, CODE_TERMACK, id, NULL, 0);
	break;

    case REQSENT:
    case ACKSENT:
	/* They didn't agree to what we wanted - try another request */
	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	if (ret < 0)
	    f->state = STOPPED;		/* kludge for stopping CCP */
	else
	    fsm_sconfreq(f, 0);		/* Send Configure-Request */
	break;

    case ACKRCVD:
	/* Got a Nak/reject when we had already had an Ack?? oh well... */
	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	fsm_sconfreq(f, 0);
	f->state = REQSENT;
	break;

    case OPENED:
	/* Go down and restart negotiation */
	fsm_sconfreq(f, 0);		/* Send initial Configure-Request */
	f->state = REQSENT;
	if (f->callbacks->down != NULL)
	    (*f->callbacks->down)(f);	/* Inform upper layers */
	break;
    }
}


/*
 * fsm_rtermreq - Receive Terminate-Req.
 */
static void
fsm_rtermreq(f, id, p, len)
    fsm *f;
    int id;
    u_char *p;
    int len;
{
    switch (f->state) {
    case ACKRCVD:
    case ACKSENT:
	f->state = REQSENT;		/* Start over but keep trying */
	break;

    case OPENED:
	if (len > 0) {
	    info("%s terminated by peer (%0.*v)", PROTO_NAME(f), len, p);
	} else {
	    info("%s terminated by peer", PROTO_NAME(f));
	}
	f->state = STOPPING;
	if (f->callbacks->down != NULL)
	    (*f->callbacks->down)(f);	/* Inform upper layers */
	f->retransmits = 0;
	TIMEOUT(fsm_timeout, f, f->timeouttime);
	break;
    }

    fsm_sdata(f, CODE_TERMACK, id, NULL, 0);
}


/*
 * fsm_rtermack - Receive Terminate-Ack.
 */
static void
fsm_rtermack(f)
    fsm *f;
{
    switch (f->state) {
    case CLOSING:
	UNTIMEOUT(fsm_timeout, f);
	f->state = CLOSED;
	if (f->callbacks->finished != NULL)
	    (*f->callbacks->finished)(f);
	break;
    case STOPPING:
	UNTIMEOUT(fsm_timeout, f);
	f->state = STOPPED;
	if (f->callbacks->finished != NULL)
	    (*f->callbacks->finished)(f);
	break;

    case ACKRCVD:
	f->state = REQSENT;
	break;

    case OPENED:
	fsm_sconfreq(f, 0);
	f->state = REQSENT;
	if (f->callbacks->down != NULL)
	    (*f->callbacks->down)(f);	/* Inform upper layers */
	break;
    }
}


/*
 * fsm_rcoderej - Receive a Code-Reject.
 */
static void
fsm_rcoderej(f, inp, len)
    fsm *f;
    u_char *inp;
    int len;
{
    u_char code, id;
    int seriouserr;

    if (len < HEADERLEN) {
	error("%s: Code-Reject too short (%d < %d)", PROTO_NAME(f), len,
	    HEADERLEN);
	return;
    }
    GETCHAR(code, inp);
    GETCHAR(id, inp);
    len -= 2;
    warn("%s: Rcvd Code-Reject for %s id %d", PROTO_NAME(f),
	code_name(code,0), id);

    setbit(f->codemask, code);

    /* Let the protocol know what happened. */
    if (f->callbacks->codereject != NULL) {
	seriouserr = (*f->callbacks->codereject)(f,code,id,inp,len);
    } else {
	    /*
	     * By default, it's RXJ- for well-known codes and RXJ+ for
	     * unknown ones.
	     */
	seriouserr = (code >= CODE_CONFREQ && code <= CODE_CODEREJ);
    }

    if (seriouserr) {
	/* RXJ- -- shut down the protocol. */
	switch (f->state) {
	case CLOSING:
	    UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	    /*FALLTHROUGH*/
	case CLOSED:
	    f->state = CLOSED;
	    if (f->callbacks->finished != NULL)
		(*f->callbacks->finished)(f);
	    break;

	case STOPPING:
	case REQSENT:
	case ACKRCVD:
	case ACKSENT:
	    UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	    f->state = STOPPED;
	    /*FALLTHROUGH*/
	case STOPPED:
	    if (f->callbacks->finished != NULL)
		(*f->callbacks->finished)(f);
	    break;

	case OPENED:
	    f->state = STOPPING;
	    if (f->callbacks->down != NULL)
		(*f->callbacks->down)(f);

	    if (f->term_reason == NULL) {
		f->term_reason = "unacceptable Code-Reject received";
		f->term_reason_len = strlen(f->term_reason);
	    }

	    /* Init restart counter, send Terminate-Request */
	    f->retransmits = f->maxtermtransmits;
	    fsm_sdata(f, CODE_TERMREQ, f->reqid = ++f->id,
		(u_char *) f->term_reason, f->term_reason_len);
	    TIMEOUT(fsm_timeout, f, f->timeouttime);
	    --f->retransmits;
	    break;

	default:
	    fatal("state error");
	}
    } else {
	/* RXJ+ -- just back up from Ack-Rcvd to Req-Sent. */
	if (f->state == ACKRCVD)
	    f->state = REQSENT;
    }
}


/*
 * fsm_protreject - Peer doesn't speak this protocol.
 *
 * Treat this as a catastrophic error (RXJ-).
 */
void
fsm_protreject(f)
    fsm *f;
{
    switch( f->state ){
    case CLOSING:
	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	/*FALLTHROUGH*/
    case CLOSED:
	f->state = CLOSED;
	if (f->callbacks->finished != NULL)
	    (*f->callbacks->finished)(f);
	break;

    case STOPPING:
    case REQSENT:
    case ACKRCVD:
    case ACKSENT:
	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	/*FALLTHROUGH*/
    case STOPPED:
	f->state = STOPPED;
	if (f->callbacks->finished != NULL)
	    (*f->callbacks->finished)(f);
	break;

    case OPENED:
	f->state = STOPPING;
	if (f->callbacks->down != NULL)
	    (*f->callbacks->down)(f);

	/* Init restart counter, send Terminate-Request */
	f->retransmits = f->maxtermtransmits;
	fsm_sdata(f, CODE_TERMREQ, f->reqid = ++f->id,
		  (u_char *) f->term_reason, f->term_reason_len);
	TIMEOUT(fsm_timeout, f, f->timeouttime);
	--f->retransmits;
	break;

    default:
	dbglog("%s: Protocol-Reject in state %s", PROTO_NAME(f),
	    fsm_state(f->state));
    }
}


/*
 * fsm_sconfreq - Send a Configure-Request.
 */
static void
fsm_sconfreq(f, retransmit)
    fsm *f;
    int retransmit;
{
    u_char *outp;
    int cilen;

    if( f->state != REQSENT && f->state != ACKRCVD && f->state != ACKSENT ){
	/* Not currently negotiating - reset options */
	if (f->callbacks->resetci != NULL)
	    (*f->callbacks->resetci)(f);
	f->nakloops = 0;
    }

    if( !retransmit ){
	/* New request - reset retransmission counter, use new ID */
	f->retransmits = f->maxconfreqtransmits;
	f->reqid = ++f->id;
    }

    f->seen_ack = 0;

    /*
     * Make up the request packet
     */
    outp = outpacket_buf + PPP_HDRLEN + HEADERLEN;
    if (f->callbacks->cilen != NULL) {
	cilen = (*f->callbacks->cilen)(f);
	if (cilen > peer_mru[f->unit] - HEADERLEN)
	    cilen = peer_mru[f->unit] - HEADERLEN;
    } else {
	cilen = peer_mru[f->unit] - HEADERLEN;
    }

    if (f->callbacks->addci != NULL)
	(*f->callbacks->addci)(f, outp, &cilen);
    else
	cilen = 0;

    /* send the request to our peer */
    fsm_sdata(f, CODE_CONFREQ, f->reqid, outp, cilen);

    /* start the retransmit timer */
    --f->retransmits;
    TIMEOUT(fsm_timeout, f, f->timeouttime);
}


/*
 * fsm_sdata - Send some data.
 *
 * Used for all packets sent to our peer by this module.
 */
void
fsm_sdata(f, code, id, data, datalen)
    fsm *f;
    u_char code, id;
    u_char *data;
    int datalen;
{
    u_char *outp;
    int outlen;

    if (isset(f->codemask,code)) {
	dbglog("%s: Peer has rejected %s; not sending another",
	    PROTO_NAME(f), code_name(code,0));
	return;
    }

    /* Adjust length to be smaller than MTU */
    outp = outpacket_buf;
    if (datalen > peer_mru[f->unit] - HEADERLEN)
	datalen = peer_mru[f->unit] - HEADERLEN;
    if (datalen && data != outp + PPP_HDRLEN + HEADERLEN)
	BCOPY(data, outp + PPP_HDRLEN + HEADERLEN, datalen);
    outlen = datalen + HEADERLEN;
    MAKEHEADER(outp, f->protocol);
    PUTCHAR(code, outp);
    PUTCHAR(id, outp);
    PUTSHORT(outlen, outp);
    output(f->unit, outpacket_buf, outlen + PPP_HDRLEN);
}

/*
 * fsm_setpeermru - Set our idea of the peer's mru
 *
 * Used by routines in lcp.c which negotiate this value.
 */
void
fsm_setpeermru(unit, mru)
    int unit;
    int mru;
{
    if (unit >= NUM_PPP) {
	dbglog("fsm_setpeermru: unit out of bounds");
    } else {
	peer_mru[unit] = mru;
    }
}
