/*
 * cbcp - Call Back Configuration Protocol.
 *
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Copyright (c) 1995 Pedro Roque Marques
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Pedro Roque Marques.  The name of the author may not be used to
 * endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>

#include "pppd.h"
#include "cbcp.h"
#include "fsm.h"
#include "lcp.h"

/*
 * Options.
 */
static int setcbcp __P((char **, option_t *));

static option_t cbcp_option_list[] = {
    { "callback", o_special, (void *)setcbcp,
      "Ask for callback" },
    { NULL }
};

/*
 * Protocol entry points.
 */
static void cbcp_init      __P((int unit));
static void cbcp_lowerup   __P((int unit));
static void cbcp_input     __P((int unit, u_char *pkt, int len));
static void cbcp_protrej   __P((int unit));
static int  cbcp_printpkt  __P((u_char *pkt, int len,
    void (*printer) __P((void *, const char *, ...)),
    void *arg));

struct protent cbcp_protent = {
    PPP_CBCP,			/* PPP protocol number */
    cbcp_init,			/* Initialization procedure */
    cbcp_input,			/* Process a received packet */
    cbcp_protrej,		/* Process a received protocol-reject */
    cbcp_lowerup,		/* Lower layer has come up */
    NULL,			/* Lower layer has gone down */
    NULL,			/* Open the protocol */
    NULL,			/* Close the protocol */
    cbcp_printpkt,		/* Print a packet in readable form */
    NULL,			/* Process a received data packet */
    0,				/* 0 iff protocol is disabled */
    "CBCP",			/* Text name of protocol */
    NULL,			/* Text name of corresponding data protocol */
    cbcp_option_list,		/* List of command-line options */
    NULL,			/* Check requested options, assign defaults */
    NULL,			/* Configure interface for demand-dial */
    NULL			/* Say whether to bring up link for this pkt */
};

/* Not static'd for plug-ins */
cbcp_state cbcp[NUM_PPP];	

/* internal prototypes */

static void cbcp_recvreq __P((cbcp_state *us, u_char *pckt, int len));
static void cbcp_recvack __P((cbcp_state *us, u_char *pckt, int len));
static void cbcp_send __P((cbcp_state *us, int code, u_char *buf, int len));

/* option processing */
/*ARGSUSED*/
static int
setcbcp(argv, opt)
    char **argv;
    option_t *opt;
{
    lcp_wantoptions[0].neg_cbcp = 1;
    cbcp_protent.enabled_flag = 1;
    cbcp[0].us_number = strdup(*argv);
    if (cbcp[0].us_number == NULL)
	novm("callback number");
    cbcp[0].us_type |= (1 << CB_CONF_USER);
    cbcp[0].us_type |= (1 << CB_CONF_ADMIN);
    return (1);
}

/* init state */
static void
cbcp_init(unit)
    int unit;
{
    cbcp_state *us;

    us = &cbcp[unit];
    BZERO(us, sizeof(cbcp_state));
    us->us_unit = unit;
    us->us_type |= (1 << CB_CONF_NO);
}

/* lower layer is up */
static void
cbcp_lowerup(unit)
    int unit;
{
    cbcp_state *us = &cbcp[unit];

    if (debug) {
	dbglog("cbcp_lowerup: want: %d", us->us_type);

	if (us->us_type == CB_CONF_USER)
	    dbglog("phone no: %s", us->us_number);
    }
}

/* process an incoming packet */
static void
cbcp_input(unit, inpacket, pktlen)
    int unit;
    u_char *inpacket;
    int pktlen;
{
    u_char *inp;
    u_char code, id;
    u_short len;

    cbcp_state *us = &cbcp[unit];

    inp = inpacket;

    if (pktlen < CBCP_MINLEN) {
        error("CBCP packet is too small (%d < %d)", pktlen, CBCP_MINLEN);
	return;
    }

    GETCHAR(code, inp);
    GETCHAR(id, inp);
    GETSHORT(len, inp);

    if (len > pktlen) {
        error("CBCP packet: invalid length (%d > %d)", len, pktlen);
        return;
    }

    len -= CBCP_MINLEN;
 
    switch (code) {
    case CBCP_REQ:
        us->us_id = id;
	cbcp_recvreq(us, inp, len);
	break;

    case CBCP_RESP:
	if (debug)
	    dbglog("CBCP Response received; no request sent");
	break;

    case CBCP_ACK:
	if (id != us->us_id) {
	    if (debug)
		dbglog("CBCP Ack ID %d doesn't match expected %d", id,
		    us->us_id);
	    break;
	}

	cbcp_recvack(us, inp, len);
	break;

    default:
	if (debug)
	    dbglog("Unknown CBCP code number %d", code);
	break;
    }
}

/* protocol was rejected by foe */
/*ARGSUSED*/
static void
cbcp_protrej(int unit)
{
    start_networks();
}

static char *cbcp_codenames[] = {
    "Request", "Response", "Ack"
};

static char *cbcp_optionnames[] = {
    "NoCallback",
    "UserDefined",
    "AdminDefined",
    "List"
};

/*
 * Pretty print a packet.  Return value is number of bytes parsed out
 * of the packet and printed in some way.  Caller (in util.c) will
 * print the remainder of the packet.
 */
static int
cbcp_printpkt(p, plen, printer, arg)
    u_char *p;
    int plen;
    void (*printer) __P((void *, const char *, ...));
    void *arg;
{
    int code, id, len, olen, alen;
    u_char *pstart, cichar;

    if (plen < HEADERLEN) {
	printer(arg, "too short (%d<%d)", plen, HEADERLEN);
	return (0);
    }
    pstart = p;
    GETCHAR(code, p);
    GETCHAR(id, p);
    GETSHORT(len, p);

    if (code >= 1 && code <= Dim(cbcp_codenames))
	printer(arg, " %s", cbcp_codenames[code-1]);
    else
	printer(arg, " code=0x%x", code); 

    printer(arg, " id=0x%x", id);

    if (len < HEADERLEN) {
	printer(arg, " header length %d<%d", len, HEADERLEN);
	return (HEADERLEN);
    }
    if (len > plen) {
	printer(arg, " truncated (%d>%d)", len, plen);
	len = plen;
    }
    len -= HEADERLEN;

    switch (code) {
    case CBCP_REQ:
    case CBCP_RESP:
    case CBCP_ACK:
        while (len >= 2) {
	    GETCHAR(cichar, p);
	    GETCHAR(olen, p);

	    if (olen < 2)
		break;

	    printer(arg, " <");

	    if (olen > len) {
		printer(arg, "trunc[%d>%d] ", olen, len);
	        olen = len;
	    }
	    len -= olen;
	    olen -= 2;

	    if (cichar >= 1 && cichar <= Dim(cbcp_optionnames))
	    	printer(arg, " %s", cbcp_optionnames[cichar-1]);
	    else
	        printer(arg, " option=0x%x", cichar); 

	    if (olen > 0) {
	        GETCHAR(cichar, p);
		olen--;
		printer(arg, " delay=%d", cichar);
	    }

	    while (olen > 0) {
		GETCHAR(cichar, p);
		olen--;
		if (cichar != 1)
		    printer(arg, " (type %d?)", cichar);
		alen = strllen((const char *)p, olen);
		if (olen > 0 && alen > 0)
		    printer(arg, " '%.*s'", alen, p);
		else
		    printer(arg, " null");
		p += alen + 1;
		olen -= alen + 1;
	    }
	    printer(arg, ">");
	}

    default:
	break;
    }

    if (len > 0) {
	if (len > 8)
	    printer(arg, "%8B ...", p);
	else
	    printer(arg, "%.*B", len, p);
    }
    p += len;

    return p - pstart;
}

/*
 * received CBCP request.
 * No reason to print packet contents in detail here, since enabling
 * debug mode will cause the print routine above to be invoked.
 */
static void
cbcp_recvreq(us, pckt, pcktlen)
    cbcp_state *us;
    u_char *pckt;
    int pcktlen;
{
    u_char type, opt_len;
    int len = pcktlen;
    u_char cb_type;
    u_char buf[256];
    u_char *bufp = buf;

    us->us_allowed = 0;
    while (len > 0) {
	GETCHAR(type, pckt);
	GETCHAR(opt_len, pckt);

	if (opt_len > 2) {
	    pckt++;	/* ignore the delay time */
	}

	len -= opt_len;

	/*
	 * Careful; don't use left-shift operator on numbers that are
	 * too big.
	 */
	if (type > CB_CONF_LIST) {
	    if (debug)
		dbglog("CBCP: ignoring unknown type %d", type);
	    continue;
	}

	us->us_allowed |= (1 << type);

	switch (type) {
	case CB_CONF_NO:
	    if (debug)
		dbglog("CBCP: operation without callback allowed");
	    break;

	case CB_CONF_USER:
	    if (debug)
		dbglog("callback to user-specified number allowed");
	    break;

	case CB_CONF_ADMIN:
	    if (debug)
		dbglog("CBCP: callback to admin-defined address allowed");
	    break;

	case CB_CONF_LIST:
	    if (debug)
		dbglog("CBCP: callback to one out of list allowed");
	    break;
	}
    }

    /* Now generate the response */
    len = 0;
    cb_type = us->us_allowed & us->us_type;

    if (cb_type & ( 1 << CB_CONF_USER ) ) {
	if (debug)
	    dbglog("CBCP Response: selecting user-specified number");
	PUTCHAR(CB_CONF_USER, bufp);
	len = 3 + 1 + strlen(us->us_number) + 1;
	PUTCHAR(len , bufp);
	PUTCHAR(5, bufp); /* delay */
	PUTCHAR(1, bufp);
	BCOPY(us->us_number, bufp, strlen(us->us_number) + 1);
	cbcp_send(us, CBCP_RESP, buf, len);
	return;
    }

    if (cb_type & ( 1 << CB_CONF_ADMIN ) ) {
	if (debug)
	    dbglog("CBCP Response: selecting admin-specified number");
        PUTCHAR(CB_CONF_ADMIN, bufp);
	len = 3;
	PUTCHAR(len, bufp);
	PUTCHAR(5, bufp); /* delay */
	cbcp_send(us, CBCP_RESP, buf, len);
	return;
    }

    if (cb_type & ( 1 << CB_CONF_NO ) ) {
	if (debug)
	    dbglog("CBCP Response: selecting no-callback mode");
	PUTCHAR(CB_CONF_NO, bufp);
	len = 3;
	PUTCHAR(len , bufp);
	PUTCHAR(0, bufp);
	cbcp_send(us, CBCP_RESP, buf, len);
	start_networks();
	return;
    }

    if (debug)
	dbglog("CBCP:  no callback types in common");
    lcp_close(us->us_unit, "No CBCP callback options available");
}

static void
cbcp_send(us, code, buf, len)
    cbcp_state *us;
    int code;
    u_char *buf;
    int len;
{
    u_char *outp;
    int outlen;

    outp = outpacket_buf;

    outlen = 4 + len;
    
    MAKEHEADER(outp, PPP_CBCP);

    PUTCHAR(code, outp);
    PUTCHAR(us->us_id, outp);
    PUTSHORT(outlen, outp);
    
    if (len > 0)
        BCOPY(buf, outp, len);

    output(us->us_unit, outpacket_buf, outlen + PPP_HDRLEN);
}

/*
 * Received CBCP Acknowledgment message.
 */
static void
cbcp_recvack(us, pckt, len)
    cbcp_state *us;
    u_char *pckt;
    int len;
{
    u_char type, addr_type;
    int opt_len;

    if (len > 0) {
        GETCHAR(type, pckt);
	GETCHAR(opt_len, pckt);

	if (type == CB_CONF_NO) {
	    if (debug)
		dbglog("CBCP: proceeding without callback");
	    return;
	}
     
	/* just ignore the delay time */
	pckt++;

	if (opt_len > 4) {
	    GETCHAR(addr_type, pckt);
	    if (addr_type != 1)
		warn("CBCP: unknown callback address type %d", addr_type);
	}
	if (debug && opt_len > 5)
	    dbglog("CBCP: peer will call %.*s", pckt, opt_len - 4);
    }

    persist = 0;
    lcp_close(us->us_unit, "Call me back, please");
    status = EXIT_CALLBACK;
}
