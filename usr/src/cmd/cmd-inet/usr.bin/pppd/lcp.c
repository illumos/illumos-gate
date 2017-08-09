/*
 * lcp.c - PPP Link Control Protocol.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Copyright (c) 2016 by Delphix. All rights reserved.
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
#include <stdlib.h>
#include <ctype.h>
#if defined(CHAPMS) || defined(CHAPMSV2)
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#ifndef USE_CRYPT
#include <des.h>
#endif
#ifdef SOL2
#include <errno.h>
#endif
#endif

#include "pppd.h"
#include "fsm.h"
#include "lcp.h"
#include "chap.h"
#include "magic.h"
#include "patchlevel.h"

/*
 * Special failure codes for logging link failure reasons.
 */
bool peer_nak_auth;		/* Peer sent nak for our auth request */
u_short nak_auth_orig;		/* Auth proto peer naked */
u_short nak_auth_proto;		/* Auth proto peer suggested instead */
bool unsolicited_nak_auth;	/* Peer asked us to authenticate */
u_short unsolicit_auth_proto;	/* Auth proto peer wants */
bool peer_reject_auth;		/* Peer sent reject for auth */
u_short reject_auth_proto;	/* Protocol that peer rejected */
bool rejected_peers_auth;	/* We sent a reject to the peer */
u_short rejected_auth_proto;	/* Protocol that peer wanted to use */
bool naked_peers_auth;		/* We sent a nak to the peer */
u_short naked_auth_orig;	/* Protocol that we wanted to use */
u_short naked_auth_proto;	/* Protocol that peer wants us to use */

/*
 * LCP-related command-line options.
 */
int	lcp_echo_interval = 0; 	/* Interval between LCP echo-requests */
int	lcp_echo_fails = 0;	/* Tolerance to unanswered echo-requests */
bool	lax_recv = 0;		/* accept control chars in asyncmap */
static int use_accm_test = 2;	/* use big echo-requests to check ACCM */
#define	ACCM_TEST_FAILS	5

#define _tostr2(x)	#x
#define _tostr(x)	_tostr2(x)
static char identstr[256] =	/* Identification string */
	"ppp-" VERSION "." _tostr(PATCHLEVEL) IMPLEMENTATION;
static int noident = 0;		/* 1 to disable; 2 to reject */
static int sentident = 0;	/* counts the # of ident codes sent */

/* set if we're allowed to send an unsolicited Configure-Nak for MRU. */
static bool unsolicit_mru;

static int setescape __P((char **, option_t *));

static bool do_msft_workaround = 1;
static int setasyncmap __P((char **, option_t *));

bool	noendpoint = 0;		/* don't send/accept endpoint discriminator */
static int setendpoint __P((char **, option_t *));

static char *callback_strings[] = {
	"auth", "dialstring", "location", "E.164", "X.500", "", "CBCP", NULL
};

/* This is used in packet printing even if NEGOTIATE_FCS isn't enabled */
static char *fcsalt_strings[] = {
	"null", "crc16", "crc32", NULL
};

#ifdef NEGOTIATE_FCS
static int setfcsallow __P((char **, option_t *));
static int setfcswant __P((char **, option_t *));
#endif

/* Backward compatibility for Linux */
#ifndef PPP_MAXMRU
#define	PPP_MTU		1500	/* Default MTU (size of Info field) */
#define	PPP_MAXMTU	65535 - (PPP_HDRLEN + PPP_FCSLEN)
#define	PPP_MINMTU	64
#define	PPP_MAXMRU	65000	/* Largest MRU we allow */
#define	PPP_MINMRU	128
#endif

static option_t lcp_option_list[] = {
    /* LCP options */
    { "noaccomp", o_bool, &lcp_wantoptions[0].neg_accompression,
      "Disable address/control compression",
      OPT_A2COPY, &lcp_allowoptions[0].neg_accompression },
    { "-ac", o_bool, &lcp_wantoptions[0].neg_accompression,
      "Disable address/control compression",
      OPT_A2COPY, &lcp_allowoptions[0].neg_accompression },
    { "default-asyncmap", o_bool, &lcp_wantoptions[0].neg_asyncmap,
      "Disable asyncmap negotiation",
      OPT_A2COPY, &lcp_allowoptions[0].neg_asyncmap },
    { "-am", o_bool, &lcp_wantoptions[0].neg_asyncmap,
      "Disable asyncmap negotiation",
      OPT_A2COPY, &lcp_allowoptions[0].neg_asyncmap },
    { "asyncmap", o_special, (void *)setasyncmap,
      "Set asyncmap (for received packets)" },
    { "-as", o_special, (void *)setasyncmap,
      "Set asyncmap (for received packets)" },
    { "nomagic", o_bool, &lcp_wantoptions[0].neg_magicnumber,
      "Disable magic number option (looped-back line detect)",
      OPT_A2COPY, &lcp_allowoptions[0].neg_magicnumber },
    { "-mn", o_bool, &lcp_wantoptions[0].neg_magicnumber,
      "Disable magic number option (looped-back line detect)",
      OPT_A2COPY, &lcp_allowoptions[0].neg_magicnumber },
    { "default-mru", o_bool, &lcp_wantoptions[0].neg_mru,
      "Disable MRU negotiation (use default 1500)",
      OPT_A2COPY, &lcp_allowoptions[0].neg_mru },
    { "-mru", o_bool, &lcp_wantoptions[0].neg_mru,
      "Disable MRU negotiation (use default 1500)",
      OPT_A2COPY, &lcp_allowoptions[0].neg_mru },
    { "mru", o_int, &lcp_wantoptions[0].mru,
      "Set MRU (maximum received packet size) for negotiation",
      OPT_LIMITS, &lcp_wantoptions[0].neg_mru, PPP_MAXMRU, PPP_MINMRU },
    { "mtu", o_int, &lcp_allowoptions[0].mru,
      "Set our MTU", OPT_LIMITS|OPT_A2COPY, &lcp_allowoptions[0].mrru,
      PPP_MAXMTU, PPP_MINMTU },
    { "nopcomp", o_bool, &lcp_wantoptions[0].neg_pcompression,
      "Disable protocol field compression",
      OPT_A2COPY, &lcp_allowoptions[0].neg_pcompression },
    { "-pc", o_bool, &lcp_wantoptions[0].neg_pcompression,
      "Disable protocol field compression",
      OPT_A2COPY, &lcp_allowoptions[0].neg_pcompression },
    { "-p", o_bool, &lcp_wantoptions[0].passive,
      "Set passive mode", 1 },
    { "passive", o_bool, &lcp_wantoptions[0].passive,
      "Set passive mode", 1 },
    { "silent", o_bool, &lcp_wantoptions[0].silent,
      "Set silent mode", 1 },
    { "escape", o_special, (void *)setescape,
      "List of character codes to escape on transmission" },
    { "lcp-echo-failure", o_int, &lcp_echo_fails,
      "Number of consecutive echo failures for link failure" },
    { "lcp-echo-interval", o_int, &lcp_echo_interval,
      "Set time in seconds between LCP echo requests" },
    { "no-accm-test", o_int, &use_accm_test,
      "Disable use of LCP Echo-Request asyncmap checking",
      OPT_NOARG|OPT_VAL(0) },
    { "small-accm-test", o_int, &use_accm_test,
      "Use only small Echo-Requests for asyncmap checking",
      OPT_NOARG|OPT_VAL(1) },
    { "lcp-restart", o_int, &lcp_fsm[0].timeouttime,
      "Set time in seconds between LCP retransmissions" },
    { "lcp-max-terminate", o_int, &lcp_fsm[0].maxtermtransmits,
      "Maximum number of LCP terminate-request transmissions" },
    { "lcp-max-configure", o_int, &lcp_fsm[0].maxconfreqtransmits,
      "Maximum number of LCP configure-request transmissions" },
    { "lcp-max-failure", o_int, &lcp_fsm[0].maxnakloops,
      "Set limit on number of LCP configure-naks" },
    { "receive-all", o_bool, &lax_recv,
      "Accept all received control characters", 1 },
#ifdef HAVE_MULTILINK
    { "mrru", o_int, &lcp_wantoptions[0].mrru,
      "Maximum received packet size for multilink bundle",
      OPT_LIMITS, &lcp_wantoptions[0].neg_mrru, PPP_MAXMRU, PPP_MINMRU },
    { "mpshortseq", o_bool, &lcp_wantoptions[0].neg_ssnhf,
      "Use short sequence numbers in multilink headers",
      OPT_A2COPY | 1, &lcp_allowoptions[0].neg_ssnhf },
    { "nompshortseq", o_bool, &lcp_wantoptions[0].neg_ssnhf,
      "Don't use short sequence numbers in multilink headers",
      OPT_A2COPY, &lcp_allowoptions[0].neg_ssnhf },
#endif /* HAVE_MULTILINK */
    { "endpoint", o_special, (void *)setendpoint,
      "Endpoint discriminator for multilink", },
    { "noendpoint", o_bool, &noendpoint,
      "Don't send or accept multilink endpoint discriminator", 1 },
    { "ident", o_string, identstr,
      "LCP Identification string", OPT_STATIC, NULL, sizeof(identstr) },
    { "noident", o_int, &noident,
      "Disable use of LCP Identification", OPT_INC|OPT_NOARG|1 },
#ifdef NEGOTIATE_FCS
    { "default-fcs", o_bool, &lcp_wantoptions[0].neg_fcs,
      "Disable FCS Alternatives option (use default CRC-16)",
      OPT_A2COPY, &lcp_allowoptions[0].neg_fcs },
    { "allow-fcs", o_special, (void *)setfcsallow,
      "Set allowable FCS types; crc16, crc32, null, or number" },
    { "fcs", o_special, (void *)setfcswant,
      "Set FCS type(s) desired; crc16, crc32, null, or number" },
#endif
#ifdef MUX_FRAME
    /*
     * if pppmux option is turned on, then the parameter to this
     * is time value in microseconds
     */
    { "pppmux", o_int, &lcp_wantoptions[0].pppmux,
      "Set PPP Multiplexing option timer", OPT_LLIMIT | OPT_A2COPY,
	&lcp_allowoptions[0].pppmux, 0, 0 },
#endif
    {NULL}
};

/* global vars */
fsm lcp_fsm[NUM_PPP];			/* LCP fsm structure (global)*/
lcp_options lcp_wantoptions[NUM_PPP];	/* Options that we want to request */
lcp_options lcp_gotoptions[NUM_PPP];	/* Options that peer ack'd */
lcp_options lcp_allowoptions[NUM_PPP];	/* Options we allow peer to request */
lcp_options lcp_hisoptions[NUM_PPP];	/* Options that we ack'd */
u_int32_t xmit_accm[NUM_PPP][8];	/* extended transmit ACCM */

/*
 * These variables allow a plugin to assert limits on the maximum
 * MRU/MTU values that can be negotiated.
 */
int absmax_mru = PPP_MAXMRU;
int absmax_mtu = PPP_MAXMTU;

static int lcp_echos_pending = 0;	/* Number of outstanding echo msgs */
static int lcp_echo_number   = 0;	/* ID number of next echo frame */
static int lcp_echo_timer_running = 0;  /* set if a timer is running */
static bool lcp_echo_accm_test = 0;	/* flag if still testing ACCM */
static int lcp_echo_badreplies = 0;	/* number of bad replies from peer */
/*
 * The maximum number of bad replies we tolerate before bringing the
 * link down.
 */
#define LCP_ECHO_MAX_BADREPLIES	10

/*
 * Callbacks for fsm code.  (CI = Configuration Information)
 */
static void lcp_resetci __P((fsm *));	/* Reset our CI */
static int  lcp_cilen __P((fsm *));		/* Return length of our CI */
static void lcp_addci __P((fsm *, u_char *, int *)); /* Add our CI to pkt */
static int  lcp_ackci __P((fsm *, u_char *, int)); /* Peer ack'd our CI */
static int  lcp_nakci __P((fsm *, u_char *, int)); /* Peer nak'd our CI */
static int  lcp_rejci __P((fsm *, u_char *, int)); /* Peer rej'd our CI */
static int  lcp_reqci __P((fsm *, u_char *, int *, int)); /* Rcv peer CI */
static void lcp_up __P((fsm *));		/* We're UP */
static void lcp_down __P((fsm *));		/* We're DOWN */
static void lcp_starting __P((fsm *));	/* We need lower layer up */
static void lcp_finished __P((fsm *));	/* We need lower layer down */
static int  lcp_extcode __P((fsm *, int, int, u_char *, int));
static void lcp_rprotrej __P((fsm *, u_char *, int));
static int lcp_coderej __P((fsm *f, int code, int id, u_char *inp, int len));

/*
 * routines to send LCP echos to peer
 */

static void lcp_echo_lowerup __P((int));
static void lcp_echo_lowerdown __P((int));
static void LcpEchoTimeout __P((void *));
static int lcp_received_echo_reply __P((fsm *, int, u_char *, int));
static void LcpSendEchoRequest __P((fsm *));
static void LcpLinkFailure __P((fsm *));
static void LcpEchoCheck __P((fsm *));

/*
 * routines to send and receive additional LCP packets described in
 * section 1 of rfc1570.
 */
static void LcpSendIdentification __P((fsm *));
static void lcp_received_identification __P((fsm *, int, u_char *, int));
static void LcpSendTimeRemaining __P((fsm *, u_int32_t));
static void lcp_timeremaining __P((void *));
static void lcp_received_timeremain __P((fsm *, int, u_char *, int));


static fsm_callbacks lcp_callbacks = {	/* LCP callback routines */
    lcp_resetci,		/* Reset our Configuration Information */
    lcp_cilen,			/* Length of our Configuration Information */
    lcp_addci,			/* Add our Configuration Information */
    lcp_ackci,			/* ACK our Configuration Information */
    lcp_nakci,			/* NAK our Configuration Information */
    lcp_rejci,			/* Reject our Configuration Information */
    lcp_reqci,			/* Request peer's Configuration Information */
    lcp_up,			/* Called when fsm reaches OPENED state */
    lcp_down,			/* Called when fsm leaves OPENED state */
    lcp_starting,		/* Called when we want the lower layer up */
    lcp_finished,		/* Called when we want the lower layer down */
    NULL,			/* Retransmission is necessary */
    lcp_extcode,		/* Called to handle LCP-specific codes */
    "LCP",			/* String name of protocol */
    lcp_coderej,		/* Peer rejected a code number */
};

/*
 * Protocol entry points.
 * Some of these are called directly.
 */

static void lcp_init __P((int));
static void lcp_input __P((int, u_char *, int));
static void lcp_protrej __P((int));
static int  lcp_printpkt __P((u_char *, int,
    void (*) __P((void *, const char *, ...)), void *));


struct protent lcp_protent = {
    PPP_LCP,		/* Protocol Number for LCP */
    lcp_init,		/* Initializes LCP */
    lcp_input,		/* Processes a received LCP packet */
    lcp_protrej,	/* Process a received Protocol-reject */
    lcp_lowerup,	/* Called after the serial device has been set up */
    lcp_lowerdown,	/* Called when the link is brought down */
    lcp_open,		/* Called after lcp_lowerup when bringing up the link */
    lcp_close,		/* Called when the link goes down */
    lcp_printpkt,	/* Print a packet in human readable form */
    NULL,		/* Process a received data packet */
    1,			/* LCP is enabled by default */
    "LCP",		/* Name of the protocol */
    NULL,		/* Name of the corresponding data protocol */
    lcp_option_list,	/* List of LCP command-line options */
    NULL,		/* Assigns default values for options */
    NULL,		/* Configures demand-dial */
    NULL		/* Bring up the link for this packet? */
};

int lcp_loopbackfail = DEFLOOPBACKFAIL;

/*
 * Length of each type of configuration option (in octets)
 */
#define CILEN_VOID	2
#define CILEN_CHAR	3
#define CILEN_SHORT	4	/* CILEN_VOID + 2 */
#define CILEN_CHAP	5	/* CILEN_VOID + 2 + 1 */
#define CILEN_LONG	6	/* CILEN_VOID + 4 */
#define CILEN_LQR	8	/* CILEN_VOID + 2 + 4 */
#define CILEN_CBCP	3


/*
 * setescape - add chars to the set we escape on transmission.
 */
/*ARGSUSED*/
static int
setescape(argv, opt)
    char **argv;
    option_t *opt;
{
    int n, ret;
    char *p, *endp;

    p = *argv;
    ret = 1;
    while (*p != '\0') {
	n = strtol(p, &endp, 16);
	if (p == endp) {
	    option_error("escape parameter contains invalid hex number '%s'",
			 p);
	    return 0;
	}
	p = endp;
	if (n < 0 || n == 0x5E || n > 0xFF) {
	    option_error("can't escape character 0x%x", n);
	    ret = 0;
	} else
	    xmit_accm[0][n >> 5] |= 1 << (n & 0x1F);
	while (*p == ',' || *p == ' ')
	    ++p;
    }
    return ret;
}

/*
 * setasyncmap - set async map negotiated
 */
/*ARGSUSED*/
static int
setasyncmap(argv, opt)
    char **argv;
    option_t *opt;
{
    u_int32_t val;
    char *endp;

    val = strtoul(*argv, &endp, 16);
    if (*argv == endp) {
	option_error("invalid numeric parameter '%s' for 'asyncmap' option",
	    *argv);
	return 0;
    }
    lcp_wantoptions[0].asyncmap |= val;
    lcp_wantoptions[0].neg_asyncmap = (~lcp_wantoptions[0].asyncmap != 0);
    do_msft_workaround = 0;
    return 1;
}

/*ARGSUSED*/
static int
setendpoint(argv, opt)
    char **argv;
    option_t *opt;
{
    if (str_to_epdisc(&lcp_wantoptions[0].endpoint, *argv)) {
	lcp_wantoptions[0].neg_endpoint = 1;
	return 1;
    }
    option_error("Can't parse '%s' as an endpoint discriminator", *argv);
    return 0;
}

#ifdef NEGOTIATE_FCS
static int
str_to_fcstype(opt,arg)
    lcp_options *opt;
    char *arg;
{
    char **cpp, *cp;
    int val, len;

    if (*arg != '\0') {
	val = 0;
	while (*arg != '\0') {
	    len = 0;
	    if (isdigit(*arg)) {
		len = strtol(arg, &cp, 0);
		if (len < 0 || len > 255 || arg == cp ||
		    (*cp != '\0' && *cp != ','))
		    break;
		val |= len;
		len = cp - arg;
	    } else {
		for (cpp = fcsalt_strings; *cpp != NULL; cpp++) {
		    len = strlen(*cpp);
		    if (strncasecmp(arg, *cpp, len) == 0 &&
		        (arg[len] == '\0' || arg[len] == ','))
			break;
		}
		if (*cpp == NULL)
		    break;
		val |= 1<<(cpp-fcsalt_strings);
	    }
	    if (arg[len] == '\0') {
		opt->neg_fcs = 1;
		opt->fcs_type = val;
		return (1);
	    }
	    arg += len+1;
	}
    }
    option_error("Can't parse '%s' as an FCS type", arg);
    return (0);
}

/*ARGSUSED*/
static int
setfcsallow(argv, opt)
    char **argv;
    option_t *opt;
{
    return str_to_fcstype(&lcp_allowoptions[0], *argv);
}

/*ARGSUSED*/
static int
setfcswant(argv, opt)
    char **argv;
    option_t *opt;
{
    return str_to_fcstype(&lcp_wantoptions[0], *argv);
}
#endif

/*
 * lcp_init - Initialize LCP.
 */
static void
lcp_init(unit)
    int unit;
{
    fsm *f = &lcp_fsm[unit];
    lcp_options *wo = &lcp_wantoptions[unit];
    lcp_options *ao = &lcp_allowoptions[unit];

    f->unit = unit;
    f->protocol = PPP_LCP;
    f->callbacks = &lcp_callbacks;

    fsm_init(f);

    BZERO(wo, sizeof(*wo));
    wo->neg_mru = 1;
    wo->mru = PPP_MRU;
    wo->neg_asyncmap = 1;
    wo->chap_mdtype = CHAP_DIGEST_MD5;
    wo->neg_magicnumber = 1;
    wo->neg_pcompression = 1;
    wo->neg_accompression = 1;

    /*
     * Leave allowed MRU (MTU) at zero; configuration option sets it
     * non-zero if we should nak for something else.
     */
    BZERO(ao, sizeof(*ao));
    ao->neg_mru = 1;
    ao->neg_asyncmap = 1;
    ao->neg_chap = 1;
#if defined(CHAPMS) || defined(CHAPMSV2)
#ifdef SOL2
    /* Check if DES wasn't exported */
    errno = 0;
    setkey("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    if (errno == 0)
#endif
    {
#ifdef CHAPMS
    ao->neg_mschap = 1;
#endif
#ifdef CHAPMSV2
    ao->neg_mschapv2 = 1;
#endif
    }
#endif
    ao->chap_mdtype = CHAP_DIGEST_MD5;
    ao->neg_upap = 1;
    ao->neg_magicnumber = 1;
    ao->neg_pcompression = 1;
    ao->neg_accompression = 1;
#ifdef CBCP_SUPPORT
    ao->neg_cbcp = 1;
#endif
    ao->neg_endpoint = 1;
#ifdef NEGOTIATE_FCS
    ao->neg_fcs = 1;
    ao->fcs_type = FCSALT_NULL|FCSALT_16|FCSALT_32;
#endif

    BZERO(xmit_accm[unit], sizeof(xmit_accm[0]));
    xmit_accm[unit][3] = 0x60000000;
}


/*
 * lcp_open - LCP is allowed to come up.
 */
void
lcp_open(unit)
    int unit;
{
    fsm *f = &lcp_fsm[unit];
    lcp_options *wo = &lcp_wantoptions[unit];

    f->flags = 0;
    if (wo->passive)
	f->flags |= OPT_PASSIVE;
    if (wo->silent)
	f->flags |= OPT_SILENT;
    fsm_open(f);
}


/*
 * lcp_close - Take LCP down.
 */
void
lcp_close(unit, reason)
    int unit;
    char *reason;
{
    fsm *f = &lcp_fsm[unit];

    if (phase != PHASE_DEAD)
	new_phase(PHASE_TERMINATE);
    if (f->state == STOPPED && (f->flags & (OPT_PASSIVE|OPT_SILENT))) {
	/*
	 * This action is not strictly according to the FSM in RFC1548,
	 * but it does mean that the program terminates if you do a
	 * lcp_close() in passive/silent mode when a connection hasn't
	 * been established.
	 */
	f->state = CLOSED;
	lcp_finished(f);

    } else
	fsm_close(&lcp_fsm[unit], reason);
}


/*
 * lcp_lowerup - The lower layer is up.
 */
void
lcp_lowerup(unit)
    int unit;
{
    lcp_options *wo = &lcp_wantoptions[unit];
    int mru, mtu;

    mru = PPP_MRU > absmax_mru ? absmax_mru : PPP_MRU;
    mtu = PPP_MTU > absmax_mtu ? absmax_mtu : PPP_MTU;

    /*
     * Don't use A/C or protocol compression on transmission,
     * but accept A/C and protocol compressed packets
     * if we are going to ask for A/C and protocol compression.
     */
    ppp_set_xaccm(unit, xmit_accm[unit]);
    ppp_send_config(unit, mtu, 0xffffffff, 0, 0);
    ppp_recv_config(unit, mru, (lax_recv? 0: 0xffffffff),
		    wo->neg_pcompression, wo->neg_accompression);
#ifdef NEGOTIATE_FCS
    ppp_send_fcs(unit, FCSALT_16);
    ppp_recv_fcs(unit, FCSALT_16);
#endif

    fsm_setpeermru(unit, mtu);
    lcp_allowoptions[unit].asyncmap = xmit_accm[unit][0];

    fsm_lowerup(&lcp_fsm[unit]);
}


/*
 * lcp_lowerdown - The lower layer is down.
 */
void
lcp_lowerdown(unit)
    int unit;
{
    fsm_lowerdown(&lcp_fsm[unit]);
}


/*
 * lcp_input - Input LCP packet.
 */
static void
lcp_input(unit, p, len)
    int unit;
    u_char *p;
    int len;
{
    fsm *f = &lcp_fsm[unit];

    fsm_input(f, p, len);
}


/*
 * lcp_extcode - Handle a LCP-specific code.
 */
static int
lcp_extcode(f, code, id, inp, len)
    fsm *f;
    int code, id;
    u_char *inp;
    int len;
{
    u_char *magp;

    switch( code ){
    case CODE_PROTREJ:
	lcp_rprotrej(f, inp, len);
	break;

    case CODE_ECHOREQ:
	if (f->state != OPENED)
	    break;
	magp = inp;
	PUTLONG(lcp_gotoptions[f->unit].magicnumber, magp);
	fsm_sdata(f, CODE_ECHOREP, id, inp, len);
	break;

    case CODE_ECHOREP:
	if (!lcp_received_echo_reply(f, id, inp, len)) {
	    lcp_echo_badreplies++;
	    if (lcp_echo_badreplies > LCP_ECHO_MAX_BADREPLIES) {
		LcpLinkFailure(f);
		lcp_echos_pending = 0;
		lcp_echo_badreplies = 0;
	    }
	}
	break;

    case CODE_DISCREQ:
	break;

    case CODE_IDENT:
	/* More than one 'noident' tells us to reject the code number. */
	if (noident > 1)
	    return 0;
	lcp_received_identification(f, id, inp, len);
	break;

    case CODE_TIMEREMAIN:
	lcp_received_timeremain(f, id, inp, len);
	break;

    default:
	return 0;
    }
    return 1;
}

/*
 * lcp_rprotrej - Receive an Protocol-Reject.
 *
 * Figure out which protocol is rejected and inform it.
 */
static void
lcp_rprotrej(f, inp, len)
    fsm *f;
    u_char *inp;
    int len;
{
    int i;
    struct protent *protp;
    u_short prot;

    if (len < 2) {
	dbglog("lcp_rprotrej: Rcvd short Protocol-Reject packet!");
	return;
    }

    GETSHORT(prot, inp);

    /*
     * Protocol-Reject packets received in any state other than the LCP
     * OPENED state SHOULD be silently discarded.
     */
    if( f->state != OPENED ){
	dbglog("Protocol-Reject discarded: LCP in state %s",
	    fsm_state(f->state));
	return;
    }

    /*
     * Upcall the proper Protocol-Reject routine.
     */
    for (i = 0; (protp = protocols[i]) != NULL; ++i)
	if (protp->protocol == prot && protp->enabled_flag) {
	    (*protp->protrej)(f->unit);
	    return;
	}

    warn("Protocol-Reject for unsupported protocol 0x%x", prot);
}


/*
 * lcp_protrej - A Protocol-Reject was received.
 */
/*ARGSUSED*/
static void
lcp_protrej(unit)
    int unit;
{
    /*
     * Can't reject LCP!
     */
    error("Received Protocol-Reject for LCP!");
}

/*
 * lcp_coderej - A Code-Reject was received.
 */
/*ARGSUSED*/
static int
lcp_coderej(f, code, id, inp, len)
	fsm *f;
	int code;
	int id;
	u_char *inp;
	int len;
{
	/* The peer cannot reject these code numbers. */
	if (code >= CODE_CONFREQ && code <= CODE_PROTREJ)
		return 1;
	switch (code) {
	case CODE_ECHOREQ:
	    /*
	     * If the peer rejects an Echo-Request, then stop doing that.
	     */
	    if (lcp_echo_timer_running != 0) {
		UNTIMEOUT (LcpEchoTimeout, f);
		lcp_echo_timer_running = 0;
		lcp_echo_interval = 0;
	    }
	    break;
	}
	return 0;
}

/*
 * lcp_sprotrej - Send a Protocol-Reject for some protocol.
 */
void
lcp_sprotrej(unit, p, len)
    int unit;
    u_char *p;
    int len;
{
    /*
     * Send back the protocol and the information field of the
     * rejected packet.  We only get here if LCP is in the OPENED state.
     */
    p += 2;
    len -= 2;

    fsm_sdata(&lcp_fsm[unit], CODE_PROTREJ, ++lcp_fsm[unit].id,
	      p, len);
}


/*
 * lcp_resetci - Reset our CI.
 */
static void
lcp_resetci(f)
    fsm *f;
{
    lcp_options *wo = &lcp_wantoptions[f->unit];
    lcp_options *go = &lcp_gotoptions[f->unit];
    lcp_options *ao = &lcp_allowoptions[f->unit];

    wo->magicnumber = magic();
    wo->numloops = 0;
    sentident = 0;
    *go = *wo;
    if (!multilink) {
	go->neg_mrru = 0;
	go->neg_ssnhf = 0;
    }
    if (noendpoint)
	ao->neg_endpoint = 0;
    if (go->mru > absmax_mru)
	go->mru = absmax_mru;
    if (ao->mru > absmax_mtu)
	ao->mru = absmax_mtu;
    unsolicit_mru = 1;
    fsm_setpeermru(f->unit, PPP_MTU > absmax_mtu ? absmax_mtu : PPP_MTU);
    auth_reset(f->unit);
}


/*
 * lcp_cilen - Return length of our CI.
 */
static int
lcp_cilen(f)
    fsm *f;
{
    lcp_options *go = &lcp_gotoptions[f->unit];

#define LENCIVOID(neg)	((neg) ? CILEN_VOID : 0)
#define LENCICHAP(neg)	((neg) ? CILEN_CHAP : 0)
#define LENCICHAR(neg)	((neg) ? CILEN_CHAR : 0)
#define LENCISHORT(neg)	((neg) ? CILEN_SHORT : 0)
#define LENCILONG(neg)	((neg) ? CILEN_LONG : 0)
#define LENCILQR(neg)	((neg) ? CILEN_LQR: 0)
#define LENCICBCP(neg)	((neg) ? CILEN_CBCP: 0)
    /*
     * NB: we only ask for one of CHAP and UPAP, even if we will
     * accept either.
     */
    return (LENCISHORT(go->neg_mru && go->mru != PPP_MRU) +
	    LENCILONG(go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF) +
	    LENCICHAP(go->neg_chap || go->neg_mschap || go->neg_mschapv2) +
	    LENCISHORT(!go->neg_chap && go->neg_upap && !go->neg_mschap &&
		!go->neg_mschapv2) +
	    LENCILQR(go->neg_lqr) +
	    LENCICBCP(go->neg_cbcp) +
	    LENCILONG(go->neg_magicnumber) +
	    LENCIVOID(go->neg_pcompression) +
	    LENCIVOID(go->neg_accompression) +
	    LENCICHAR(go->neg_fcs) +
	    LENCISHORT(go->neg_mrru) +
	    LENCIVOID(go->neg_ssnhf) +
#ifdef MUX_FRAME
            LENCIVOID(go->pppmux) +
#endif
	    (go->neg_endpoint? CILEN_CHAR + go->endpoint.length: 0));
}


/*
 * lcp_addci - Add our desired CIs to a packet.
 */
static void
lcp_addci(f, ucp, lenp)
    fsm *f;
    u_char *ucp;
    int *lenp;
{
    lcp_options *go = &lcp_gotoptions[f->unit];
    lcp_options *ho = &lcp_hisoptions[f->unit];
    u_char *start_ucp = ucp;

#define ADDCIVOID(opt, neg) \
    if (neg) { \
	PUTCHAR(opt, ucp); \
	PUTCHAR(CILEN_VOID, ucp); \
    }
#define ADDCISHORT(opt, neg, val) \
    if (neg) { \
	PUTCHAR(opt, ucp); \
	PUTCHAR(CILEN_SHORT, ucp); \
	PUTSHORT(val, ucp); \
    }
#define ADDCICHAP(opt, neg, val, digest) \
    if (neg) { \
	PUTCHAR(opt, ucp); \
	PUTCHAR(CILEN_CHAP, ucp); \
	PUTSHORT(val, ucp); \
	PUTCHAR(digest, ucp); \
    }
#define ADDCILONG(opt, neg, val) \
    if (neg) { \
	PUTCHAR(opt, ucp); \
	PUTCHAR(CILEN_LONG, ucp); \
	PUTLONG(val, ucp); \
    }
#define ADDCILQR(opt, neg, val) \
    if (neg) { \
	PUTCHAR(opt, ucp); \
	PUTCHAR(CILEN_LQR, ucp); \
	PUTSHORT(PPP_LQR, ucp); \
	PUTLONG(val, ucp); \
    }
#define ADDCICHAR(opt, neg, val) \
    if (neg) { \
	PUTCHAR(opt, ucp); \
	PUTCHAR(CILEN_CHAR, ucp); \
	PUTCHAR(val, ucp); \
    }
#define ADDCIENDP(opt, neg, class, val, len) \
    if (neg) { \
	int i; \
	PUTCHAR(opt, ucp); \
	PUTCHAR(CILEN_CHAR + len, ucp); \
	PUTCHAR(class, ucp); \
	for (i = 0; i < len; ++i) \
	    PUTCHAR(val[i], ucp); \
    }

    ADDCISHORT(CI_MRU, go->neg_mru && go->mru != PPP_MRU, go->mru);
    ADDCILONG(CI_ASYNCMAP, go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF,
	      go->asyncmap);
    /* go->chap_mdtype always points to a useful value */
    ADDCICHAP(CI_AUTHTYPE, go->neg_chap || go->neg_mschap || go->neg_mschapv2,
	PPP_CHAP, go->chap_mdtype);
    ADDCISHORT(CI_AUTHTYPE, !(go->neg_chap || go->neg_mschap ||
	go->neg_mschapv2) && go->neg_upap, PPP_PAP);
    /* We can't both say zero for LQR period. */
    if (f->state == ACKSENT && go->neg_lqr && go->lqr_period == 0 &&
	ho->neg_lqr && ho->lqr_period == 0)
	go->lqr_period = 500;
    ADDCILQR(CI_QUALITY, go->neg_lqr, go->lqr_period);
    ADDCICHAR(CI_CALLBACK, go->neg_cbcp, CBOP_CBCP);
    ADDCILONG(CI_MAGICNUMBER, go->neg_magicnumber, go->magicnumber);
    ADDCIVOID(CI_PCOMPRESSION, go->neg_pcompression);
    ADDCIVOID(CI_ACCOMPRESSION, go->neg_accompression);
    ADDCICHAR(CI_FCSALTERN, (go->neg_fcs && go->fcs_type != 0), go->fcs_type);
    ADDCIENDP(CI_EPDISC, go->neg_endpoint, go->endpoint.class,
	      go->endpoint.value, go->endpoint.length);
#ifdef MUX_FRAME
    ADDCIVOID(CI_MUXING, go->pppmux);
#endif
    ADDCISHORT(CI_MRRU, go->neg_mrru, go->mrru);
    ADDCIVOID(CI_SSNHF, go->neg_ssnhf);

    if (ucp - start_ucp != *lenp) {
	/* this should never happen, because peer_mtu should be 1500 */
	error("Bug in lcp_addci: wrong length");
    }
}


/*
 * lcp_ackci - Ack our CIs.
 * This should not modify any state if the Ack is bad.
 *
 * Returns:
 *	0 - Ack was bad.
 *	1 - Ack was good.
 */
static int
lcp_ackci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    lcp_options *go = &lcp_gotoptions[f->unit];
#ifdef MUX_FRAME
    lcp_options *ao = &lcp_allowoptions[f->unit];
#endif
    u_char cilen, citype, cichar;
    u_short cishort;
    u_int32_t cilong;

    /*
     * CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define ACKCIVOID(opt, neg) \
    if (neg) { \
	if ((len -= CILEN_VOID) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_VOID || \
	    citype != opt) \
	    goto bad; \
    }
#define ACKCISHORT(opt, neg, val) \
    if (neg) { \
	if ((len -= CILEN_SHORT) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_SHORT || \
	    citype != opt) \
	    goto bad; \
	GETSHORT(cishort, p); \
	if (cishort != val) \
	    goto bad; \
    }
#define ACKCIAUTH(opt, neg, val) \
    if (neg) { \
	if ((len -= CILEN_SHORT) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_SHORT || \
	    citype != opt) \
	    goto bad; \
	GETSHORT(cishort, p); \
	if (cishort != val) \
	    goto bad; \
	peer_nak_auth = 0; \
	peer_reject_auth = 0; \
    }
#define ACKCICHAR(opt, neg, val) \
    if (neg) { \
	if ((len -= CILEN_CHAR) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_CHAR || \
	    citype != opt) \
	    goto bad; \
	GETCHAR(cichar, p); \
	if (cichar != val) \
	    goto bad; \
    }
#define ACKCICHAP(opt, neg, val, digest) \
    if (neg) { \
	if ((len -= CILEN_CHAP) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_CHAP || \
	    citype != opt) \
	    goto bad; \
	GETSHORT(cishort, p); \
	if (cishort != val) \
	    goto bad; \
	GETCHAR(cichar, p); \
	if (cichar != digest) \
	  goto bad; \
	peer_nak_auth = 0; \
	peer_reject_auth = 0; \
    }
#define ACKCILONG(opt, neg, val) \
    if (neg) { \
	if ((len -= CILEN_LONG) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_LONG || \
	    citype != opt) \
	    goto bad; \
	GETLONG(cilong, p); \
	if (cilong != val) \
	    goto bad; \
    }
#define ACKCILQR(opt, neg, val) \
    if (neg) { \
	if ((len -= CILEN_LQR) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_LQR || \
	    citype != opt) \
	    goto bad; \
	GETSHORT(cishort, p); \
	if (cishort != PPP_LQR) \
	    goto bad; \
	GETLONG(cilong, p); \
	if (cilong != val) \
	  goto bad; \
    }
#define ACKCIENDP(opt, neg, class, val, vlen) \
    if (neg) { \
	int i; \
	if ((len -= CILEN_CHAR + vlen) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != CILEN_CHAR + vlen || \
	    citype != opt) \
	    goto bad; \
	GETCHAR(cichar, p); \
	if (cichar != class) \
	    goto bad; \
	for (i = 0; i < vlen; ++i) { \
	    GETCHAR(cichar, p); \
	    if (cichar != val[i]) \
		goto bad; \
	} \
    }

    ACKCISHORT(CI_MRU, go->neg_mru && go->mru != PPP_MRU, go->mru);
    ACKCILONG(CI_ASYNCMAP, go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF,
	      go->asyncmap);
    /* go->chap_mdtype always points to a useful value */
    ACKCICHAP(CI_AUTHTYPE, go->neg_chap || go->neg_mschap || go->neg_mschapv2,
	PPP_CHAP, go->chap_mdtype);
    ACKCIAUTH(CI_AUTHTYPE, !(go->neg_chap || go->neg_mschap ||
	go->neg_mschapv2) && go->neg_upap, PPP_PAP);
    ACKCILQR(CI_QUALITY, go->neg_lqr, go->lqr_period);
    ACKCICHAR(CI_CALLBACK, go->neg_cbcp, CBOP_CBCP);
    ACKCILONG(CI_MAGICNUMBER, go->neg_magicnumber, go->magicnumber);
    ACKCIVOID(CI_PCOMPRESSION, go->neg_pcompression);
    ACKCIVOID(CI_ACCOMPRESSION, go->neg_accompression);
    ACKCICHAR(CI_FCSALTERN, go->neg_fcs, go->fcs_type);
    ACKCIENDP(CI_EPDISC, go->neg_endpoint, go->endpoint.class,
	      go->endpoint.value, go->endpoint.length);
#ifdef MUX_FRAME
    ACKCIVOID(CI_MUXING, go->pppmux);
    if (go->pppmux)
    	go->pppmux = ao->pppmux;
#endif
    ACKCISHORT(CI_MRRU, go->neg_mrru, go->mrru);
    ACKCIVOID(CI_SSNHF, go->neg_ssnhf);

    /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
	goto bad;
    return (1);
bad:
    dbglog("lcp_acki: received bad Ack!");
    return (0);
}


/*
 * lcp_nakci - Peer has sent a NAK for some of our CIs.
 * This should not modify any state if the Nak is bad
 * or if LCP is in the OPENED state.
 *
 * Returns:
 *	0 - Nak was bad.
 *	1 - Nak was good.
 */
static int
lcp_nakci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    lcp_options *go = &lcp_gotoptions[f->unit];
    lcp_options *wo = &lcp_wantoptions[f->unit];
    u_char citype, cichar, *next;
    u_short cishort;
    u_int32_t cilong;
    lcp_options no;		/* options we've seen Naks for */
    lcp_options try;		/* options to request next time */
    int looped_back = 0;
    int cilen;

    BZERO(&no, sizeof(no));
    try = *go;

    /*
     * Any Nak'd CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define NAKCIVOID(opt, neg) \
    if (go->neg && \
	len >= CILEN_VOID && \
	p[1] == CILEN_VOID && \
	p[0] == opt) { \
	len -= CILEN_VOID; \
	INCPTR(CILEN_VOID, p); \
	no.neg = 1; \
	try.neg = 0; \
    }
#define NAKCICHAR(opt, neg, code) \
    if (go->neg && \
	len >= CILEN_CHAR && \
	p[1] == CILEN_CHAR && \
	p[0] == opt) { \
	len -= CILEN_CHAR; \
	INCPTR(2, p); \
	GETCHAR(cichar, p); \
	no.neg = 1; \
	code \
    }
#define NAKCISHORT(opt, neg, code) \
    if (go->neg && \
	len >= CILEN_SHORT && \
	p[1] == CILEN_SHORT && \
	p[0] == opt) { \
	len -= CILEN_SHORT; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	no.neg = 1; \
	code \
    }
#define NAKCILONG(opt, neg, code) \
    if (go->neg && \
	len >= CILEN_LONG && \
	p[1] == CILEN_LONG && \
	p[0] == opt) { \
	len -= CILEN_LONG; \
	INCPTR(2, p); \
	GETLONG(cilong, p); \
	no.neg = 1; \
	code \
    }
#define NAKCILQR(opt, neg, code) \
    if (go->neg && \
	len >= CILEN_LQR && \
	p[1] == CILEN_LQR && \
	p[0] == opt) { \
	len -= CILEN_LQR; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	GETLONG(cilong, p); \
	no.neg = 1; \
	code \
    }
#define NAKCIENDP(opt, neg) \
    if (go->neg && \
	len >= CILEN_CHAR && \
	p[0] == opt && \
	p[1] >= CILEN_CHAR && \
	p[1] <= len) { \
	len -= p[1]; \
	INCPTR(p[1], p); \
	no.neg = 1; \
	try.neg = 0; \
    }

    /*
     * We don't care if they want to send us smaller packets than
     * we want.  Therefore, accept any MRU less than what we asked for,
     * but then ignore the new value when setting the MRU in the kernel.
     * If they send us a bigger MRU than what we asked, accept it, up to
     * the limit of the default MRU we'd get if we didn't negotiate.
     */
    if (go->neg_mru && go->mru != PPP_MRU) {
	NAKCISHORT(CI_MRU, neg_mru,
		   if (cishort <= wo->mru ||
		       (cishort <= PPP_MRU && cishort <= absmax_mru))
		       try.mru = cishort;
		   );
    }

    /*
     * Add any characters they want to our (receive-side) asyncmap.
     */
    if (go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF) {
	NAKCILONG(CI_ASYNCMAP, neg_asyncmap,
		  try.asyncmap = go->asyncmap | cilong;
		  );
    }

    /*
     * If they've nak'd our authentication-protocol, check whether
     * they are proposing a different protocol, or a different
     * hash algorithm for CHAP.
     */
    if ((go->neg_chap || go->neg_mschap || go->neg_mschapv2 || go->neg_upap) &&
	len >= CILEN_SHORT && p[0] == CI_AUTHTYPE && p[1] >= CILEN_SHORT &&
	p[1] <= len) {
	cilen = p[1];
	len -= cilen;
	INCPTR(2, p);
        GETSHORT(cishort, p);
	peer_nak_auth = 1;
	nak_auth_orig = (go->neg_chap || go->neg_mschap || go->neg_mschapv2) ?
	    PPP_CHAP : PPP_PAP;
	nak_auth_proto = cishort;
	if (cishort == PPP_PAP && cilen == CILEN_SHORT) {
	    no.neg_upap = go->neg_upap;
	    /*
	     * If we were asking for CHAP, they obviously don't want to do it.
	     * If we weren't asking for CHAP, then we were asking for PAP,
	     * in which case this Nak is bad.
	     */
	    if (!go->neg_chap && !go->neg_mschap && !go->neg_mschapv2)
		goto bad;
	    try.neg_chap = 0;
	    try.neg_mschap = 0;
	    try.neg_mschapv2 = 0;

	} else if (cishort == PPP_CHAP && cilen >= CILEN_CHAP) {
	    /* stop asking for that type */
	    switch (go->chap_mdtype) {
	    case CHAP_DIGEST_MD5:
		no.neg_chap = go->neg_chap;
		try.neg_chap = 0;
		break;
	    case CHAP_MICROSOFT:
		no.neg_mschap = go->neg_mschap;
		try.neg_mschap = 0;
		break;
	    case CHAP_MICROSOFT_V2:
		no.neg_mschapv2 = go->neg_mschapv2;
		try.neg_mschapv2 = 0;
		break;
	    }
	    GETCHAR(cichar, p);
	    /* Allow >= on length here for broken and silly peers. */
	    p += cilen - CILEN_CHAP;
	    try.neg_upap = 0;
	    if ((cichar == CHAP_DIGEST_MD5 && wo->neg_chap) ||
		(cichar == CHAP_MICROSOFT && wo->neg_mschap) ||
		(cichar == CHAP_MICROSOFT_V2 && wo->neg_mschapv2)) {
		/* Try its requested algorithm. */
		try.chap_mdtype = cichar;
	    } else {
		goto try_another;
	    }

	} else {
	    /*
	     * We don't recognize what they're suggesting.
	     * Stop asking for what we were asking for.
	     */
	try_another:
	    if (go->neg_chap || go->neg_mschap || go->neg_mschapv2) {
		switch (go->chap_mdtype) {
		case CHAP_DIGEST_MD5:
		    try.neg_chap = 0;
		    if (wo->neg_mschap) {
			try.chap_mdtype = CHAP_MICROSOFT;
			break;
		    }
			/*FALLTHROUGH*/
		case CHAP_MICROSOFT:
		    try.neg_mschap = 0;
		    if (wo->neg_mschapv2) {
			try.chap_mdtype = CHAP_MICROSOFT_V2;
			break;
		    }
			/*FALLTHROUGH*/
		case CHAP_MICROSOFT_V2:
		    try.neg_mschapv2 = 0;
		    break;
		}
	    } else
		try.neg_upap = 0;
	    p += cilen - CILEN_SHORT;
	}
    }

    /*
     * If they can't cope with our link quality protocol, we'll have
     * to stop asking for LQR.  We haven't got any other protocol.  If
     * they Nak the reporting period, then the following logic
     * applies:
     * If it suggests zero and go->neg_fcs is true and
     * ao->lqr_period isn't zero, then take its suggestion.  If it
     * suggests zero otherwise, ignore it.  If it suggests a nonzero
     * value and wo->lqr_period is zero, then take its suggestion.  If
     * it suggests a nonzero value otherwise that's less than
     * wo->lqr_period, then ignore it.
     */
    NAKCILQR(CI_QUALITY, neg_lqr,
	     if (cishort != PPP_LQR)
		 try.neg_lqr = 0;
	     else if (cilong == 0 && go->neg_fcs && wo->lqr_period != 0)
		 try.lqr_period = cilong;
	     else if (cilong != 0 &&
		 (wo->lqr_period == 0 || cilong > wo->lqr_period))
		 try.lqr_period = cilong;
	     );

    /*
     * Only implementing CBCP...not the rest of the callback options
     */
    NAKCICHAR(CI_CALLBACK, neg_cbcp,
              try.neg_cbcp = 0;
              );

    /*
     * Check for a looped-back line.
     */
    NAKCILONG(CI_MAGICNUMBER, neg_magicnumber,
	      try.magicnumber = magic();
	      looped_back = 1;
	      );

    /*
     * Peer shouldn't send Nak for protocol compression or
     * address/control compression requests; they should send
     * a Reject instead.  If they send a Nak, treat it as a Reject.
     */
    NAKCIVOID(CI_PCOMPRESSION, neg_pcompression);
    NAKCIVOID(CI_ACCOMPRESSION, neg_accompression);

    /*
     * Remove any FCS types it doesn't like from our (receive-side)
     * FCS list.
     */
    NAKCICHAR(CI_FCSALTERN, neg_fcs, try.fcs_type = go->fcs_type & cichar;);

#ifdef MUX_FRAME
    /* Nacked MUX option */
    NAKCIVOID(CI_MUXING, pppmux);
#endif

    /*
     * Nak of the endpoint discriminator option is not permitted,
     * treat it like a reject.
     */
    NAKCIENDP(CI_EPDISC, neg_endpoint);

    /*
     * Nak for MRRU option - accept their value if it is smaller
     * than the one we want.
     */
    if (go->neg_mrru) {
	NAKCISHORT(CI_MRRU, neg_mrru,
		   if (cishort <= wo->mrru)
		       try.mrru = cishort;
		   );
    }

    /*
     * Nak for short sequence numbers shouldn't be sent, treat it
     * like a reject.
     */
    NAKCIVOID(CI_SSNHF, neg_ssnhf);

    /*
     * There may be remaining CIs, if the peer is requesting negotiation
     * on an option that we didn't include in our request packet.
     * If we see an option that we requested, or one we've already seen
     * in this packet, then this packet is bad.
     * If we wanted to respond by starting to negotiate on the requested
     * option(s), we could, but we don't, because except for the
     * authentication type and quality protocol, if we are not negotiating
     * an option, it is because we were told not to.
     * For the authentication type, the Nak from the peer means
     * `let me authenticate myself with you' which is a bit pointless.
     * For the quality protocol, the Nak means `ask me to send you quality
     * reports', but if we didn't ask for them, we don't want them.
     * An option we don't recognize represents the peer asking to
     * negotiate some option we don't support, so ignore it.
     */
    while (len > CILEN_VOID) {
	GETCHAR(citype, p);
	GETCHAR(cilen, p);
	if (cilen < CILEN_VOID || (len -= cilen) < 0)
	    goto bad;
	next = p + cilen - 2;

	switch (citype) {
	case CI_MRU:
	    if ((go->neg_mru && go->mru != PPP_MRU)
		|| no.neg_mru || cilen != CILEN_SHORT)
		goto bad;
	    GETSHORT(cishort, p);
	    if (cishort < PPP_MRU && cishort < absmax_mru) {
		try.neg_mru = 1;
		try.mru = cishort;
		notice("Peer sent unsolicited Nak for MRU less than default.");
	    }
	    break;
	case CI_ASYNCMAP:
	    if ((go->neg_asyncmap && go->asyncmap != 0xFFFFFFFF)
		|| no.neg_asyncmap || cilen != CILEN_LONG)
		goto bad;
	    break;
	case CI_AUTHTYPE:
	    unsolicited_nak_auth = 1;
	    if (cilen >= CILEN_SHORT) {
		GETSHORT(unsolicit_auth_proto, p);
	    } else {
		unsolicit_auth_proto = 0;
	    }
	    if (go->neg_chap || no.neg_chap ||
		go->neg_mschap || no.neg_mschap ||
		go->neg_mschapv2 || no.neg_mschapv2 ||
		go->neg_upap || no.neg_upap)
		goto bad;
	    break;
	case CI_MAGICNUMBER:
	    if (go->neg_magicnumber || no.neg_magicnumber ||
		cilen != CILEN_LONG)
		goto bad;
	    break;
	case CI_PCOMPRESSION:
	    if (go->neg_pcompression || no.neg_pcompression
		|| cilen != CILEN_VOID)
		goto bad;
	    break;
	case CI_ACCOMPRESSION:
	    if (go->neg_accompression || no.neg_accompression
		|| cilen != CILEN_VOID)
		goto bad;
	    break;
	case CI_QUALITY:
	    if (go->neg_lqr || no.neg_lqr || cilen != CILEN_LQR)
		goto bad;
	    break;
	case CI_MRRU:
	    if (go->neg_mrru || no.neg_mrru || cilen != CILEN_SHORT)
		goto bad;
	    break;
	case CI_SSNHF:
	    if (go->neg_ssnhf || no.neg_ssnhf || cilen != CILEN_VOID)
		goto bad;
	    try.neg_ssnhf = 1;
	    break;
	case CI_EPDISC:
	    if (go->neg_endpoint || no.neg_endpoint || cilen < CILEN_CHAR)
		goto bad;
	    break;
	case CI_FCSALTERN:
	    if (go->neg_fcs || no.neg_fcs || cilen < CILEN_CHAR)
		goto bad;
	    break;
#ifdef MUX_FRAME
        case CI_MUXING:
            if (go->pppmux || no.pppmux || cilen < CILEN_VOID)
                goto bad;
            break;
#endif
	}
	p = next;
    }

    /*
     * OK, the Nak is good.  Now we can update state.
     * If there are any options left we ignore them.
     */
    if (f->state != OPENED) {
	/*
	 * Note:  the code once reset try.numloops to zero here if
	 * looped_back wasn't set.  This is wrong because a mixture of
	 * looped-back and peer data (possible if half-duplex is used)
	 * will allow the link to come up, and it shouldn't.
	 */
	if (looped_back) {
	    if (++try.numloops >= lcp_loopbackfail) {
		notice("Serial line is looped back.");
		lcp_close(f->unit, "Loopback detected");
		status = EXIT_LOOPBACK;
	    }
	}
	*go = try;
    }

    return 1;

bad:
    dbglog("lcp_nakci: received bad Nak!");
    return 0;
}


/*
 * lcp_rejci - Peer has Rejected some of our CIs.
 * This should not modify any state if the Reject is bad
 * or if LCP is in the OPENED state.
 *
 * Returns:
 *	0 - Reject was bad.
 *	1 - Reject was good.
 */
static int
lcp_rejci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    lcp_options *go = &lcp_gotoptions[f->unit];
    u_char cichar;
    u_short cishort;
    u_int32_t cilong;
    lcp_options try;		/* options to request next time */

    try = *go;

    /*
     * Any Rejected CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define REJCIVOID(opt, neg) \
    if (go->neg && \
	len >= CILEN_VOID && \
	p[1] == CILEN_VOID && \
	p[0] == opt) { \
	len -= CILEN_VOID; \
	INCPTR(CILEN_VOID, p); \
	try.neg = 0; \
    }
#define REJCICHAR(opt, neg, val) \
    if (go->neg && \
	len >= CILEN_CHAR && \
	p[1] == CILEN_CHAR && \
	p[0] == opt) { \
	len -= CILEN_CHAR; \
	INCPTR(2, p); \
	GETCHAR(cichar, p); \
	/* Check rejected value. */ \
	if (cichar != val) \
	    goto bad; \
	try.neg = 0; \
    }
#define REJCISHORT(opt, neg, val) \
    if (go->neg && \
	len >= CILEN_SHORT && \
	p[1] == CILEN_SHORT && \
	p[0] == opt) { \
	len -= CILEN_SHORT; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	/* Check rejected value. */ \
	if (cishort != val) \
	    goto bad; \
	try.neg = 0; \
    }
#define REJCIAUTH(opt, neg, val) \
    if (go->neg && \
	len >= CILEN_SHORT && \
	p[1] == CILEN_SHORT && \
	p[0] == opt) { \
	len -= CILEN_SHORT; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	/* Check rejected value. */ \
	peer_reject_auth = 1; \
	reject_auth_proto = cishort; \
	if (cishort != val) \
	    goto bad; \
	try.neg = 0; \
    }
#define REJCILONG(opt, neg, val) \
    if (go->neg && \
	len >= CILEN_LONG && \
	p[1] == CILEN_LONG && \
	p[0] == opt) { \
	len -= CILEN_LONG; \
	INCPTR(2, p); \
	GETLONG(cilong, p); \
	/* Check rejected value. */ \
	if (cilong != val) \
	    goto bad; \
	try.neg = 0; \
    }
#define REJCILQR(opt, neg, val) \
    if (go->neg && \
	len >= CILEN_LQR && \
	p[1] == CILEN_LQR && \
	p[0] == opt) { \
	len -= CILEN_LQR; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	GETLONG(cilong, p); \
	/* Check rejected value. */ \
	if (cishort != PPP_LQR || cilong != val) \
	    goto bad; \
	try.neg = 0; \
    }
#define REJCICBCP(opt, neg, val) \
    if (go->neg && \
	len >= CILEN_CBCP && \
	p[1] == CILEN_CBCP && \
	p[0] == opt) { \
	len -= CILEN_CBCP; \
	INCPTR(2, p); \
	GETCHAR(cichar, p); \
	/* Check rejected value. */ \
	if (cichar != val) \
	    goto bad; \
	try.neg = 0; \
    }
#define REJCIENDP(opt, neg, class, val, vlen) \
    if (go->neg && \
	len >= CILEN_CHAR + vlen && \
	p[0] == opt && \
	p[1] == CILEN_CHAR + vlen) { \
	int i; \
	len -= CILEN_CHAR + vlen; \
	INCPTR(2, p); \
	GETCHAR(cichar, p); \
	if (cichar != class) \
	    goto bad; \
	for (i = 0; i < vlen; ++i) { \
	    GETCHAR(cichar, p); \
	    if (cichar != val[i]) \
		goto bad; \
	} \
	try.neg = 0; \
    }

    /* Received a Configure-Reject, try to send Identification now. */
    if (!noident && sentident < 3) {
	LcpSendIdentification(f);
	sentident++;
    }

    REJCISHORT(CI_MRU, neg_mru, go->mru);
    REJCILONG(CI_ASYNCMAP, neg_asyncmap, go->asyncmap);

    /*
     * There are broken peers (such as unbundled Solaris PPP) that
     * send Configure-Reject for authentication when they really
     * intend Configure-Nak.  This code works around this problem.
     */
    if ((go->neg_chap || go->neg_mschap || go->neg_mschapv2) &&
	len >= CILEN_CHAP && p[1] == CILEN_CHAP && p[0] == CI_AUTHTYPE) {
	len -= CILEN_CHAP;
	INCPTR(2, p);
	GETSHORT(cishort, p);
	GETCHAR(cichar, p);
	peer_reject_auth = 1;
	reject_auth_proto = cishort;
	/* Check rejected value. */
	if (cishort != PPP_CHAP || cichar != go->chap_mdtype)
	    goto bad;
	/* Disable the one that it rejected */
	switch (cichar) {
	case CHAP_DIGEST_MD5:
	    try.neg_chap = 0;
	    break;
	case CHAP_MICROSOFT:
	    try.neg_mschap = 0;
	    break;
	case CHAP_MICROSOFT_V2:
	    try.neg_mschapv2 = 0;
	    break;
	}
	/* Try another, if we can. */
	if (try.neg_chap)
	    try.chap_mdtype = CHAP_DIGEST_MD5;
	else if (try.neg_mschap)
	    try.chap_mdtype = CHAP_MICROSOFT;
	else
	    try.chap_mdtype = CHAP_MICROSOFT_V2;
    }

    if (!go->neg_chap && !go->neg_mschap && !go->neg_mschapv2) {
	REJCIAUTH(CI_AUTHTYPE, neg_upap, PPP_PAP);
    }
    REJCILQR(CI_QUALITY, neg_lqr, go->lqr_period);
    REJCICBCP(CI_CALLBACK, neg_cbcp, CBOP_CBCP);
    REJCILONG(CI_MAGICNUMBER, neg_magicnumber, go->magicnumber);
    REJCIVOID(CI_PCOMPRESSION, neg_pcompression);
    REJCIVOID(CI_ACCOMPRESSION, neg_accompression);
    REJCICHAR(CI_FCSALTERN, neg_fcs, go->fcs_type);
#ifdef MUX_FRAME
    REJCIVOID(CI_MUXING,pppmux);
#endif
    REJCIENDP(CI_EPDISC, neg_endpoint, go->endpoint.class,
	      go->endpoint.value, go->endpoint.length);
    REJCISHORT(CI_MRRU, neg_mrru, go->mrru);
    REJCIVOID(CI_SSNHF, neg_ssnhf);

    /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
	goto bad;
    /*
     * Now we can update state.
     */
    if (f->state != OPENED)
	*go = try;
    return 1;

bad:
    dbglog("lcp_rejci: received bad Reject!");
    return 0;
}


/*
 * lcp_reqci - Check the peer's requested CIs and send appropriate response.
 *
 * Returns: CODE_CONFACK, CODE_CONFNAK or CODE_CONFREJ and input
 * packet modified appropriately.  If reject_if_disagree is non-zero,
 * doesn't return CODE_CONFNAK; returns CODE_CONFREJ if it can't
 * return CODE_CONFACK.
 */
static int
lcp_reqci(f, p, lenp, dont_nak)
    fsm *f;
    u_char *p;		/* Requested CIs */
    int *lenp;		/* Length of requested CIs */
    int dont_nak;
{
    lcp_options *wo = &lcp_wantoptions[f->unit];
    lcp_options *go = &lcp_gotoptions[f->unit];
    lcp_options *ho = &lcp_hisoptions[f->unit];
    lcp_options *ao = &lcp_allowoptions[f->unit];
    int cilen, citype, cichar;	/* Parsed len, type, char value */
    u_short cishort;		/* Parsed short value */
    u_int32_t cilong;		/* Parse long value */
    int ret, newret;
    u_char *p0, *nakp, *rejp, *prev;
    int len;

    /*
     * Loop through options once to find out if peer is offering
     * Multilink, and repair values as needed.
     */
    ao->mru = ao->mrru;
    p0 = p;
    for (len = *lenp; len > 0; len -= cilen, p = prev + cilen) {
	if (len < 2 || p[1] > len) {
	    /*
	     * RFC 1661 page 40 -- if the option extends beyond the
	     * packet, then discard the entire packet.
	     */
	    dbglog("discarding LCP Configure-Request due to truncated option");
	    return (0);
	}
	prev = p;
	GETCHAR(citype, p);
	GETCHAR(cilen, p);
	if (citype == CI_MRRU) {
	    if (ao->mrru != 0) {
		if (ao->mrru+6 > PPP_MTU)
		    ao->mru = PPP_MTU;
		else
		    ao->mru = ao->mrru + 6;
	    }
	}
	if (cilen < 2)
	    cilen = 2;
    }
    if (ao->mru > absmax_mtu)
	ao->mru = absmax_mtu;

    ret = CODE_CONFACK;
    rejp = p = p0;
    nakp = nak_buffer;

    /*
     * Reset all its options.
     */
    BZERO(ho, sizeof(*ho));

    /*
     * Process all its options.
     */
    for (len = *lenp; len > 0; len -= cilen, p = prev + cilen) {
	newret = CODE_CONFACK;			/* Assume success */

	prev = p;
	GETCHAR(citype, p);
	GETCHAR(cilen, p);

	switch (citype) {		/* Check CI type */
	case CI_MRU:
	    if (!ao->neg_mru) {
		newret = CODE_CONFREJ;
		break;
	    }

	    if (cilen != CILEN_SHORT) {	/* Check CI length */
		newret = CODE_CONFNAK;
		cishort = ao->mru;
	    } else {
		/* extract the MRU from the option */
		GETSHORT(cishort, p);

		/*
		 * If the offered MRU is less than our desired MTU, we
		 * should nak.  This is especially helpful if we're
		 * doing demand-dial, since those queued up packets
		 * might be discarded otherwise.
		 */
		if (cishort < ao->mru) {
		    newret = CODE_CONFNAK;
		    cishort = ao->mru;
		}
	    }

	    /*
	     * If we're going to send a nak with something less than
	     * or equal to the default PPP MTU, then just reject instead.
	     */
	    if (newret == CODE_CONFNAK && cishort <= PPP_MTU)
		newret = CODE_CONFREJ;

	    if (newret == CODE_CONFNAK) {
		PUTCHAR(CI_MRU, nakp);
		PUTCHAR(CILEN_SHORT, nakp);
		PUTSHORT(cishort, nakp);	/* Give it a hint */
	    }

	    ho->neg_mru = 1;		/* Remember that it sent MRU */
	    ho->mru = cishort;		/* And remember value */
	    break;

	case CI_ASYNCMAP:
	    if (!ao->neg_asyncmap) {
		newret = CODE_CONFREJ;
		break;
	    }

	    if (cilen != CILEN_LONG) {
		newret = CODE_CONFNAK;
		cilong = 0;
	    } else {
		GETLONG(cilong, p);

		/*
		 * Asyncmap must have set at least the bits
		 * which are set in lcp_allowoptions[unit].asyncmap.
		 */
		if ((ao->asyncmap & ~cilong) != 0)
		    newret = CODE_CONFNAK;
	    }

	    /*
	     * Workaround for common broken Microsoft software -- if
	     * the peer is sending us a nonzero ACCM, then it *needs*
	     * us to send the same to it.  Adjust our Configure-
	     * Request message and restart LCP.
	     */
	    if (do_msft_workaround && (cilong & ~wo->asyncmap)) {
		dbglog("adjusted requested asyncmap from %X to %X",
		    wo->asyncmap, wo->asyncmap | cilong);
		do_msft_workaround = 0;
		wo->neg_asyncmap = 1;
		wo->asyncmap |= cilong;
		f->flags &= ~OPT_SILENT;
		info("possibly broken peer detected; restarting LCP");
		fsm_lowerdown(f);
		fsm_lowerup(f);
		return (0);
	    }

	    if (newret == CODE_CONFNAK) {
		PUTCHAR(CI_ASYNCMAP, nakp);
		PUTCHAR(CILEN_LONG, nakp);
		PUTLONG(ao->asyncmap | cilong, nakp);
	    }
	    ho->neg_asyncmap = 1;
	    ho->asyncmap = cilong;
	    break;

	case CI_AUTHTYPE:
	    if (!(ao->neg_upap || ao->neg_chap || ao->neg_mschap ||
	        ao->neg_mschapv2)) {
		rejected_peers_auth = 1;
		if (cilen >= CILEN_SHORT) {
		    GETSHORT(rejected_auth_proto, p);
		} else {
		    rejected_auth_proto = 0;
		}
		/*
		 * Reject the option if we're not willing to authenticate.
		 */
		newret = CODE_CONFREJ;
		break;
	    }
	    rejected_peers_auth = 0;
	    naked_peers_auth = 0;

	    if (cilen >= CILEN_SHORT) {
		/* Extract the authentication protocol from the option */
		GETSHORT(cishort, p);

		if (ho->neg_upap || ho->neg_chap || ho->neg_mschap ||
		    ho->neg_mschapv2) {
		    dbglog("Rejecting extra authentication protocol option");
		    newret = CODE_CONFREJ;
		    break;
		}

		/*
		 * Authtype must be PAP or CHAP.
		 *
		 * Note: if both ao->neg_upap and ao->neg_*chap* are
		 * set, and the peer sends a Configure-Request with
		 * two authenticate-protocol requests, one for CHAP
		 * and one for UPAP, then we will reject the second
		 * request.  Whether we end up doing CHAP or UPAP
		 * depends then on the ordering of the CIs in the
		 * peer's Configure-Request.
		 *
		 * We're supposed to list all of the protocols we can
		 * possibly use in the returned Configure-Nak.  This
		 * part of RFC 1661 (section 5.3) is in conflict with
		 * the section that says the options shouldn't be
		 * reordered, so it's often ignored.
		 */

		if (cishort == PPP_PAP) {
		    if (ao->neg_upap) {
			if (cilen != CILEN_SHORT)
			    goto try_pap_anyway;
			ho->neg_upap = 1;
			break;
		    }
		} else if (cishort == PPP_CHAP) {
		    /* Test >= here to allow for broken peers. */
		    if (cilen >= CILEN_CHAP &&
			(ao->neg_chap || ao->neg_mschap || ao->neg_mschapv2)) {
			GETCHAR(cichar, p);
			if (cichar == CHAP_DIGEST_MD5 && ao->neg_chap)
			    ho->neg_chap = 1;
			else if (cichar == CHAP_MICROSOFT && ao->neg_mschap)
			    ho->neg_mschap = 1;
			else if (cichar == CHAP_MICROSOFT_V2 &&
			    ao->neg_mschapv2)
			    ho->neg_mschap = 1;
			if (ho->neg_chap || ho->neg_mschap ||
			    ho->neg_mschapv2) {
			    ho->chap_mdtype = cichar; /* save md type */
			    break;
			}
		    }
		}
	    }

	    /*
	     * We don't recognize the protocol they're asking for.
	     * Nak it with something we're willing to do.
	     * (At this point we know ao->neg_upap || ao->neg_chap.)
	     */
	    PUTCHAR(CI_AUTHTYPE, nakp);
	    if (ao->neg_chap || ao->neg_mschap || ao->neg_mschapv2) {
		PUTCHAR(CILEN_CHAP, nakp);
		PUTSHORT(PPP_CHAP, nakp);
		PUTCHAR(ao->chap_mdtype, nakp);
		naked_auth_proto = PPP_CHAP;
	    } else {
	    try_pap_anyway:
		PUTCHAR(CILEN_SHORT, nakp);
		PUTSHORT(PPP_PAP, nakp);
		naked_auth_proto = PPP_PAP;
	    }
	    naked_peers_auth = 1;
	    naked_auth_orig = cishort;
	    newret = CODE_CONFNAK;
	    break;

	case CI_QUALITY:
	    if (!ao->neg_lqr) {
		newret = CODE_CONFREJ;
		break;
	    }

	    if (cilen != CILEN_LQR) {
		newret = CODE_CONFNAK;
		cilong = ao->lqr_period;
	    } else {

		GETSHORT(cishort, p);
		GETLONG(cilong, p);

		/* Check the LQM protocol */
		if (cishort != PPP_LQR) {
		    newret = CODE_CONFNAK;
		}

		/* Check the reporting period; we can't both send zero */
		if ((cilong == 0 && go->lqr_period == 0) ||
		    cilong < ao->lqr_period) {
		    newret = CODE_CONFNAK;
		    if ((cilong = ao->lqr_period) == 0)
			cilong = 500;
		}
	    }

	    if (newret == CODE_CONFNAK) {
		PUTCHAR(CI_QUALITY, nakp);
		PUTCHAR(CILEN_LQR, nakp);
		PUTSHORT(PPP_LQR, nakp);
		PUTLONG(cilong, nakp);
	    }

	    ho->neg_lqr = 1;
	    ho->lqr_period = cilong;
	    break;

	case CI_MAGICNUMBER:
	    if (!(ao->neg_magicnumber || go->neg_magicnumber)) {
		newret = CODE_CONFREJ;
		break;
	    }

	    ho->neg_magicnumber = 1;
	    if (cilen < CILEN_LONG) {
		/*
		 * If we send Magic-Number, then we must not reject it
		 * when the peer sends it to us, even if its version
		 * looks odd to us.  Ack if the cilent is wrong in this
		 * case.  If we're not sending Magic-Number, then we don't
		 * much care what its value is anyway.
		 */
		break;
	    }

	    GETLONG(cilong, p);
	    ho->magicnumber = cilong;
	    if (cilen > CILEN_LONG)
		break;

	    /*
	     * It must have a different magic number.  Make sure we
	     * give it a good one to use.
	     */
	    while (go->neg_magicnumber && cilong == go->magicnumber) {
		newret = CODE_CONFNAK;
		cilong = magic();
	    }

	    if (newret == CODE_CONFNAK) {
		PUTCHAR(CI_MAGICNUMBER, nakp);
		PUTCHAR(CILEN_LONG, nakp);
		PUTLONG(cilong, nakp);
		/*
		 * We don't need to bump the numloops counter here
		 * since it's already done upon reception of a nak.
		 */
	    }
	    break;

	case CI_PCOMPRESSION:
	    if (!ao->neg_pcompression) {
		newret = CODE_CONFREJ;
		break;
	    }
	    if (cilen != CILEN_VOID) {
		newret = CODE_CONFNAK;
		PUTCHAR(CI_PCOMPRESSION, nakp);
		PUTCHAR(CILEN_VOID, nakp);
	    }
	    ho->neg_pcompression = 1;
	    break;

	case CI_ACCOMPRESSION:
	    if (!ao->neg_accompression) {
		newret = CODE_CONFREJ;
		break;
	    }
	    if (cilen != CILEN_VOID) {
		newret = CODE_CONFNAK;
		PUTCHAR(CI_ACCOMPRESSION, nakp);
		PUTCHAR(CILEN_VOID, nakp);
	    }
	    ho->neg_accompression = 1;
	    break;

	case CI_FCSALTERN:
	    if (!ao->neg_fcs) {
		newret = CODE_CONFREJ;
		break;
	    }

	    if (cilen != CILEN_CHAR) {
		newret = CODE_CONFNAK;
		cichar = ao->fcs_type;
	    } else {

		GETCHAR(cichar, p);
		/* If it has bits we don't like, tell it to stop. */
		if (cichar & ~ao->fcs_type) {
		    if ((cichar &= ao->fcs_type) == 0) {
			newret = CODE_CONFREJ;
			break;
		    }
		    newret = CODE_CONFNAK;
		}
	    }
	    if (newret == CODE_CONFNAK) {
		PUTCHAR(CI_FCSALTERN, nakp);
		PUTCHAR(CILEN_CHAR, nakp);
		PUTCHAR(cichar, nakp);
	    }
	    ho->neg_fcs = 1;
	    ho->fcs_type = cichar;
	    break;

	case CI_MRRU:
	    if (!ao->neg_mrru || !multilink) {
		newret = CODE_CONFREJ;
		break;
	    }
	    if (cilen != CILEN_SHORT) {
		newret = CODE_CONFNAK;
		cishort = ao->mrru;
	    } else {
		GETSHORT(cishort, p);
		if (cishort < ao->mrru) {
		    newret = CODE_CONFNAK;
		    cishort = ao->mrru;
		}
	    }

	    if (cishort < PPP_MINMTU) {
		newret = CODE_CONFNAK;
		cishort = PPP_MINMTU;
	    }

	    if (newret == CODE_CONFNAK) {
		PUTCHAR(CI_MRRU, nakp);
		PUTCHAR(CILEN_SHORT, nakp);
		PUTSHORT(cishort, nakp);
	    }

	    ho->neg_mrru = 1;
	    ho->mrru = cishort;
	    break;

	case CI_SSNHF:
	    if (!ao->neg_ssnhf || !multilink) {
		newret = CODE_CONFREJ;
		break;
	    }
	    if (cilen != CILEN_VOID) {
		newret = CODE_CONFNAK;
		PUTCHAR(CI_SSNHF, nakp);
		PUTCHAR(CILEN_VOID, nakp);
	    }
	    ho->neg_ssnhf = 1;
	    break;

	case CI_EPDISC:
	    if (!ao->neg_endpoint) {
		newret = CODE_CONFREJ;
		break;
	    }
	    if (cilen < CILEN_CHAR || cilen > CILEN_CHAR + MAX_ENDP_LEN) {
		int i;

		newret = CODE_CONFNAK;
		PUTCHAR(CI_EPDISC, nakp);
		PUTCHAR(CILEN_CHAR + ao->endpoint.length, nakp);
		PUTCHAR(ao->endpoint.class, nakp);
		for (i = 0; i < ao->endpoint.length; i++)
		    PUTCHAR(ao->endpoint.value[i], nakp);
		break;
	    }
	    GETCHAR(cichar, p);
	    ho->neg_endpoint = 1;
	    ho->endpoint.class = cichar;
	    ho->endpoint.length = cilen - 3;
	    BCOPY(p, ho->endpoint.value, cilen - 3);
	    break;

#ifdef MUX_FRAME
        case CI_MUXING:
            if (ao->pppmux == 0 || cilen != CILEN_VOID) {
                newret = CODE_CONFREJ;
                break;
            }
            /* remember its option */
            ho->pppmux = ao->pppmux;
            break;
#endif

	default:
	    dbglog("LCP: rejecting unknown option %d", citype);
	    newret = CODE_CONFREJ;
	    break;
	}

	/* Cope with confused peers. */
	if (cilen < 2)
	    cilen = 2;

	/*
	 * If this is an Ack'able CI, but we're sending back a Nak,
	 * don't include this CI.
	 */
	if (newret == CODE_CONFACK && ret != CODE_CONFACK)
	    continue;

	if (newret == CODE_CONFNAK) {
	    /*
	     * Continue naking the Magic Number option until the cows come
	     * home -- rejecting it is wrong.
	     */
	    if (dont_nak && citype != CI_MAGICNUMBER) {
		newret = CODE_CONFREJ;
	    } else {
		/* Ignore subsequent Nak'able things if rejecting. */
		if (ret == CODE_CONFREJ)
		    continue;
		ret = CODE_CONFNAK;
	    }
	}

	if (newret == CODE_CONFREJ) {
	    ret = CODE_CONFREJ;
	    if (prev != rejp)
		BCOPY(prev, rejp, cilen);
	    rejp += cilen;
	}
    }

    /*
     * If the peer hasn't negotiated its MRU, and we'd like an MTU
     * that's larger than the default, try sending an unsolicited
     * Nak for what we want.
     */
    if (ret != CODE_CONFREJ && !ho->neg_mru && ao->mru > PPP_MTU &&
	!dont_nak && unsolicit_mru) {
	unsolicit_mru = 0;	/* don't ask again */
	ret = CODE_CONFNAK;
	PUTCHAR(CI_MRU, nakp);
	PUTCHAR(CILEN_SHORT, nakp);
	PUTSHORT(ao->mru, nakp);
    }

    switch (ret) {
    case CODE_CONFACK:
	*lenp = p - p0;
	break;
    case CODE_CONFNAK:
	/*
	 * Copy the Nak'd options from the nak_buffer to the caller's buffer.
	 */
	*lenp = nakp - nak_buffer;
	BCOPY(nak_buffer, p0, *lenp);
	break;
    case CODE_CONFREJ:
	*lenp = rejp - p0;

	/* We're about to send Configure-Reject; send Identification */
	if (!noident && sentident < 3) {
	    LcpSendIdentification(f);
	    sentident++;
	}
	break;
    }

    LCPDEBUG(("lcp_reqci: returning %s.", code_name(ret, 1)));
    return (ret);			/* Return final code */
}


/*
 * lcp_up - LCP has come UP.
 */
static void
lcp_up(f)
    fsm *f;
{
    lcp_options *wo = &lcp_wantoptions[f->unit];
    lcp_options *ho = &lcp_hisoptions[f->unit];
    lcp_options *go = &lcp_gotoptions[f->unit];
    lcp_options *ao = &lcp_allowoptions[f->unit];
    int mru, mtu;

    if (!go->neg_magicnumber)
	go->magicnumber = 0;
    if (!ho->neg_magicnumber)
	ho->magicnumber = 0;

    /*
     * Set our MTU to the smaller of the MTU we wanted and
     * the MRU our peer wanted.  If we negotiated an MRU,
     * set our MRU to the larger of value we wanted and
     * the value we got in the negotiation.
     */
    if (ao->mru != 0 && ho->mru > ao->mru)
	ho->mru = ao->mru;
    mtu = (ho->neg_mru ? ho->mru: PPP_MRU);
    if (mtu > absmax_mtu)
	mtu = absmax_mtu;
    ppp_send_config(f->unit, mtu,
		    (ho->neg_asyncmap? ho->asyncmap: 0xffffffff),
		    ho->neg_pcompression, ho->neg_accompression);
    fsm_setpeermru(f->unit, mtu);
    mru = (go->neg_mru? MAX(wo->mru, go->mru): PPP_MRU);
    if (mru > absmax_mru)
	mru = absmax_mru;
    ppp_recv_config(f->unit, mru,
		    (lax_recv? 0: go->neg_asyncmap? go->asyncmap: 0xffffffff),
		    go->neg_pcompression, go->neg_accompression);
#ifdef NEGOTIATE_FCS
    ppp_send_fcs(f->unit, ho->neg_fcs ? ho->fcs_type : FCSALT_16);
    ppp_recv_fcs(f->unit, go->neg_fcs ? go->fcs_type : FCSALT_16);
#endif
#ifdef MUX_FRAME
    ppp_send_muxoption(f->unit, ho->pppmux);
    ppp_recv_muxoption(f->unit, go->pppmux);
#endif

    lcp_echo_lowerup(f->unit);  /* Enable echo messages */

    /* LCP is Up; send Identification */
    if (!noident) {
	LcpSendIdentification(f);
	sentident++;
    }

    link_established(f->unit);
}


/*
 * lcp_down - LCP has gone DOWN.
 *
 * Alert other protocols.
 */
static void
lcp_down(f)
    fsm *f;
{
    int mtu;
    lcp_options *go = &lcp_gotoptions[f->unit];

    lcp_echo_lowerdown(f->unit);

    link_down(f->unit);

    mtu = PPP_MTU > absmax_mtu ? absmax_mtu : PPP_MTU;
    ppp_send_config(f->unit, mtu, 0xffffffff, 0, 0);
    ppp_recv_config(f->unit, (PPP_MRU > absmax_mru ? absmax_mru : PPP_MRU),
		    (go->neg_asyncmap? go->asyncmap: 0xffffffff),
		    go->neg_pcompression, go->neg_accompression);
#ifdef NEGOTIATE_FCS
    ppp_send_fcs(f->unit, FCSALT_16);
    ppp_recv_fcs(f->unit, FCSALT_16);
#endif
    fsm_setpeermru(f->unit, mtu);
}


/*
 * lcp_starting - LCP needs the lower layer up.
 */
static void
lcp_starting(f)
    fsm *f;
{
    link_required(f->unit);
}


/*
 * lcp_finished - LCP has finished with the lower layer.
 */
static void
lcp_finished(f)
    fsm *f;
{
    link_terminated(f->unit);
}


/*
 * lcp_printpkt - print the contents of an LCP packet.
 */

static int
lcp_printpkt(p, plen, printer, arg)
    u_char *p;
    int plen;
    void (*printer) __P((void *, const char *, ...));
    void *arg;
{
    int code, id, len, olen, i;
    u_char *pstart, *optend, cichar;
    u_short cishort;
    u_int32_t cilong;

    if (plen < HEADERLEN)
	return 0;
    pstart = p;
    GETCHAR(code, p);
    GETCHAR(id, p);
    GETSHORT(len, p);
    if (len < HEADERLEN || len > plen)
	return 0;

    printer(arg, " %s id=0x%x", code_name(code,1), id);
    len -= HEADERLEN;
    switch (code) {
    case CODE_CONFREQ:
    case CODE_CONFACK:
    case CODE_CONFNAK:
    case CODE_CONFREJ:
	/* print option list */
	while (len >= 2) {
	    GETCHAR(code, p);
	    GETCHAR(olen, p);
	    p -= 2;
	    if (olen < 2 || olen > len) {
		break;
	    }
	    printer(arg, " <");
	    len -= olen;
	    optend = p + olen;
	    switch (code) {
	    case CI_MRU:
		if (olen >= CILEN_SHORT) {
		    p += 2;
		    GETSHORT(cishort, p);
		    printer(arg, "mru %d", cishort);
		}
		break;
	    case CI_ASYNCMAP:
		if (olen >= CILEN_LONG) {
		    p += 2;
		    GETLONG(cilong, p);
		    printer(arg, "asyncmap 0x%x", cilong);
		}
		break;
	    case CI_AUTHTYPE:
		if (olen >= CILEN_SHORT) {
		    p += 2;
		    printer(arg, "auth ");
		    GETSHORT(cishort, p);
		    switch (cishort) {
		    case PPP_PAP:
			printer(arg, "pap");
			break;
		    case PPP_CHAP:
			printer(arg, "chap");
			if (p < optend) {
			    switch (*p) {
			    case CHAP_DIGEST_MD5:
				printer(arg, " MD5");
				++p;
				break;
			    case CHAP_MICROSOFT:
				printer(arg, " m$oft");
				++p;
				break;
			    case CHAP_MICROSOFT_V2:
				printer(arg, " m$oft-v2");
				++p;
				break;
			    }
			}
			break;
#ifdef PPP_EAP
		    case PPP_EAP:
			printer(arg, "eap");
			break;
#endif
		    case 0xC027:
			printer(arg, "spap");
			break;
		    case 0xC123:
			printer(arg, "old-spap");
			break;
		    default:
			printer(arg, "0x%x", cishort);
		    }
		}
		break;
	    case CI_QUALITY:
		if (olen >= CILEN_SHORT) {
		    p += 2;
		    printer(arg, "quality ");
		    GETSHORT(cishort, p);
		    switch (cishort) {
		    case PPP_LQR:
			printer(arg, "lqr");
			break;
		    default:
			printer(arg, "0x%x", cishort);
		    }
		}
		break;
	    case CI_CALLBACK:
		if (olen >= CILEN_CHAR) {
		    p += 2;
		    printer(arg, "callback ");
		    GETCHAR(cichar, p);
		    if (cichar <= 6 &&
			*callback_strings[(int)cichar] != '\0') {
			printer(arg, "%s", callback_strings[(int)cichar]);
		    } else {
			printer(arg, "0x%x", cichar);
		    }
		}
		break;
	    case CI_MAGICNUMBER:
		if (olen >= CILEN_LONG) {
		    p += 2;
		    GETLONG(cilong, p);
		    printer(arg, "magic 0x%x", cilong);
		}
		break;
	    case CI_PCOMPRESSION:
		if (olen >= CILEN_VOID) {
		    p += 2;
		    printer(arg, "pcomp");
		}
		break;
	    case CI_ACCOMPRESSION:
		if (olen >= CILEN_VOID) {
		    p += 2;
		    printer(arg, "accomp");
		}
		break;
	    case CI_FCSALTERN:
		if (olen >= CILEN_CHAR) {
		    char **cpp;
		    int needcomma = 0;

		    p += 2;
		    GETCHAR(cichar, p);
		    for (cpp = fcsalt_strings; *cpp != NULL; cpp++)
			if (cichar & 1<<(cpp-fcsalt_strings)) {
			    cichar &= ~(1<<(cpp-fcsalt_strings));
			    printer(arg, (needcomma ? ",%s" : "fcs %s"), *cpp);
			    needcomma = 1;
			}
		    if (cichar != 0 || !needcomma)
			printer(arg, (needcomma ? ",0x%x" : "fcs 0x%x"),
			    cichar);
		}
		break;
	    case CI_NUMBERED:
		if (olen >= CILEN_SHORT) {
		    p += 2;
		    GETCHAR(cichar, p);
		    printer(arg, "numb win %d", cichar);
		    GETCHAR(cichar, p);
		    printer(arg, " addr %d", cichar);
		}
		break;
	    case CI_MRRU:
		if (olen >= CILEN_SHORT) {
		    p += 2;
		    GETSHORT(cishort, p);
		    printer(arg, "mrru %d", cishort);
		}
		break;
	    case CI_SSNHF:
		if (olen >= CILEN_VOID) {
		    p += 2;
		    printer(arg, "ssnhf");
		}
		break;
	    case CI_EPDISC:
		if (olen >= CILEN_CHAR) {
		    struct epdisc epd;
		    p += 2;
		    GETCHAR(epd.class, p);
		    epd.length = olen - CILEN_CHAR;
		    if (epd.length > MAX_ENDP_LEN)
			epd.length = MAX_ENDP_LEN;
		    if (epd.length > 0) {
			BCOPY(p, epd.value, epd.length);
			p += epd.length;
		    }
		    printer(arg, "endpoint [%s]", epdisc_to_str(&epd));
		}
		break;
	    case CI_LINKDISC:
		if (olen >= CILEN_SHORT) {
		    p += 2;
		    GETSHORT(cishort, p);
		    printer(arg, "linkdisc %d", cishort);
		}
		break;
	    case CI_COBS:
		if (olen >= CILEN_CHAR) {
		    p += 2;
		    GETCHAR(cichar, p);
		    printer(arg, "cobs 0x%x", cichar);
		}
		break;
	    case CI_PFXELISION:
		if (olen >= CILEN_CHAR) {
		    p += 2;
		    printer(arg, "pfx");
		}
		break;
	    case CI_MPHDRFMT:
		if (olen >= CILEN_SHORT) {
		    p += 2;
		    printer(arg, "mphdr ");
		    GETCHAR(cichar, p);
		    switch (cichar) {
		    case 2:
			    printer(arg, "long");
			    break;
		    case 6:
			    printer(arg, "short");
			    break;
		    default:
			    printer(arg, "0x%x", cichar);
			    break;
		    }
		    GETCHAR(cichar, p);
		    printer(arg, " #cl %d", cichar);
		}
		break;
	    case CI_I18N:
		if (olen >= CILEN_LONG) {
		    p += 2;
		    GETLONG(cilong, p);
		    printer(arg, "i18n charset 0x%x", cilong);
		    if (olen > CILEN_LONG) {
			printer(arg, " lang ");
			print_string((char *)p, olen-CILEN_LONG, printer, arg);
			p = optend;
		    }
		}
		break;
	    case CI_SDL:
		if (olen >= CILEN_VOID) {
		    p += 2;
		    printer(arg, "sdl");
		}
		break;
	    case CI_MUXING:
		if (olen >= CILEN_VOID) {
		    p += 2;
		    printer(arg, "mux");
		}
		break;
	    }
	    while (p < optend) {
		GETCHAR(code, p);
		printer(arg, " %.2x", code);
	    }
	    printer(arg, ">");
	}
	break;

    case CODE_TERMACK:
    case CODE_TERMREQ:
	if (len > 0 && *p >= ' ' && *p < 0x7f) {
	    printer(arg, " ");
	    print_string((char *)p, len, printer, arg);
	    p += len;
	    len = 0;
	}
	break;

    case CODE_ECHOREQ:
    case CODE_ECHOREP:
    case CODE_DISCREQ:
	if (len >= 4) {
	    GETLONG(cilong, p);
	    printer(arg, " magic=0x%x", cilong);
	    len -= 4;
	}
	break;

    case CODE_IDENT:
	if (len >= 4) {
	    GETLONG(cilong, p);
	    printer(arg, " magic=0x%x", cilong);
	    len -= 4;
	} else
	    break;
	if (len > 0 && (len > 1 || *p != '\0')) {
	    printer(arg, " ");
	    print_string((char *)p, len, printer, arg);
	    p += len;
	    len = 0;
	}
	break;

    case CODE_TIMEREMAIN:
	if (len >= 4) {
	    GETLONG(cilong, p);
	    printer(arg, " magic=0x%x", cilong);
	    len -= 4;
	} else
	    break;
	if (len >= 4) {
	    GETLONG(cilong, p);
	    printer(arg, " seconds=%d", cilong);
	    len -= 4;
	} else
	    break;
	if (len > 0 && (len > 1 || *p != '\0')) {
	    printer(arg, " ");
	    print_string((char *)p, len, printer, arg);
	    p += len;
	    len = 0;
	}
	break;
    }

    /* print the rest of the bytes in the packet */
    for (i = 0; i < len && i < 32; ++i) {
	GETCHAR(code, p);
	printer(arg, " %.2x", code);
    }
    if (i < len) {
	printer(arg, " ...");
	p += len - i;
    }

    return p - pstart;
}

/*
 * Time to shut down the link because there is nothing out there.
 */

static void
LcpLinkFailure (f)
    fsm *f;
{
    char *close_message;

    if (f->state == OPENED) {
	if (lcp_echo_badreplies > LCP_ECHO_MAX_BADREPLIES) {
	    info("Received %d bad echo-replies", lcp_echo_badreplies);
	    close_message = "Receiving malformed Echo-Replies";
	} else if (lcp_echo_accm_test) {
	    /*
	     * If this is an asynchronous line and we've missed all of
	     * the initial echo requests, then this is probably due to
	     * a bad ACCM.
	     */
	    notice("Peer not responding to initial Echo-Requests.");
	    notice("Negotiated asyncmap may be incorrect for this link.");
	    close_message = "Peer not responding; perhaps bad asyncmap";
	} else {
	    info("No response to %d echo-requests", lcp_echos_pending);
	    notice("Serial link appears to be disconnected.");
	    close_message = "Peer not responding";
	}

	lcp_close(f->unit, close_message);
	status = EXIT_PEER_DEAD;
    }
}

/*
 * Timer expired for the LCP echo requests from this process.
 */

static void
LcpEchoCheck (f)
    fsm *f;
{
    if (f->state != OPENED || lcp_echo_interval == 0)
	return;

    LcpSendEchoRequest (f);

    /*
     * Start the timer for the next interval.
     */
    if (lcp_echo_timer_running)
	warn("assertion lcp_echo_timer_running==0 failed");
    TIMEOUT (LcpEchoTimeout, f, lcp_echo_interval);
    lcp_echo_timer_running = 1;
}

/*
 * LcpEchoTimeout - Timer expired on the LCP echo
 */

static void
LcpEchoTimeout (arg)
    void *arg;
{
    if (lcp_echo_timer_running != 0) {
        lcp_echo_timer_running = 0;
	LcpEchoCheck ((fsm *) arg);
    }
}

/*
 * LcpEchoReply - LCP has received a reply to the echo
 */
/*ARGSUSED*/
static int
lcp_received_echo_reply (f, id, inp, len)
    fsm *f;
    int id;
    u_char *inp;
    int len;
{
    u_int32_t magic;

    /* Check the magic number - don't count replies from ourselves. */
    if (len < 4) {
	dbglog("lcp: received short Echo-Reply, length %d", len);
	return (0);
    }
    GETLONG(magic, inp);
    if (lcp_gotoptions[f->unit].neg_magicnumber &&
	magic == lcp_gotoptions[f->unit].magicnumber) {
	warn("appear to have received our own echo-reply!");
	return (0);
    }

    /* Reset the number of outstanding echo frames */
    lcp_echos_pending = 0;

    if (lcp_echo_accm_test) {
	dbglog("lcp: validated asyncmap setting");
	lcp_echo_accm_test = 0;
	if (lcp_echo_fails == 0)
	    lcp_echo_interval = 0;
    }
    return (1);
}

/*
 * LcpSendEchoRequest - Send an echo request frame to the peer
 */

static void
LcpSendEchoRequest (f)
    fsm *f;
{
    u_int32_t lcp_magic;
    u_char pkt[4+256], *pktp;
    int i;

    /*
     * Detect the failure of the peer at this point.  If we're not currently
     * performing the ACCM test, then we just check for the user's echo-failure
     * point.  If we are performing the ACCM test, then use ACCM_TEST_FAILS if
     * the user hasn't specified a different failure point.
     */
    i = lcp_echo_fails;
    if (i == 0)
	i = ACCM_TEST_FAILS;
    if ((!lcp_echo_accm_test && lcp_echo_fails != 0 &&
	lcp_echos_pending >= lcp_echo_fails) ||
	(lcp_echo_accm_test && lcp_echos_pending >= i)) {
	LcpLinkFailure(f);
	lcp_echos_pending = 0;
	lcp_echo_badreplies = 0;
    }

    /*
     * Make and send the echo request frame.
     */
    if (f->state == OPENED) {
        lcp_magic = lcp_gotoptions[f->unit].magicnumber;
	pktp = pkt;
	PUTLONG(lcp_magic, pktp);
	/* Send some test packets so we can fail the link early. */
	if (lcp_echo_accm_test) {
	    switch (use_accm_test) {
	    case 1:
		/* Only the characters covered by negotiated ACCM */
		for (i = 0; i < 32; i++)
		    *pktp++ = i;
		break;
	    case 2:
		/* All characters */
		for (i = 0; i < 256; i++)
		    *pktp++ = i;
		break;
	    }
	}
        fsm_sdata(f, CODE_ECHOREQ, lcp_echo_number++ & 0xFF, pkt, pktp - pkt);
	++lcp_echos_pending;
    }
}

/*
 * lcp_echo_lowerup - Start the timer for the LCP frame
 */

static void
lcp_echo_lowerup (unit)
    int unit;
{
    fsm *f = &lcp_fsm[unit];

    /* Clear the parameters for generating echo frames */
    lcp_echos_pending      = 0;
    lcp_echo_number        = 0;
    lcp_echo_timer_running = 0;
    lcp_echo_accm_test     = !sync_serial && use_accm_test;

    /* If a timeout interval is specified then start the timer */
    LcpEchoCheck(f);
}

/*
 * lcp_echo_lowerdown - Stop the timer for the LCP frame
 */

static void
lcp_echo_lowerdown (unit)
    int unit;
{
    fsm *f = &lcp_fsm[unit];

    if (lcp_echo_timer_running != 0) {
        UNTIMEOUT (LcpEchoTimeout, f);
        lcp_echo_timer_running = 0;
    }
}

/*
 * LcpSendIdentification - Send LCP Identification string to peer.
 */

static void
LcpSendIdentification (f)
    fsm *f;
{
    u_int32_t lcp_magic;
    u_char pkt[4 + sizeof(identstr)], *pktp;
    int idlen;

    /*
     * Make and send the Identification frame.
     */
    if (f->state == OPENED)
        lcp_magic = lcp_gotoptions[f->unit].magicnumber;
    else
	lcp_magic = 0;

    pktp = pkt;
    PUTLONG(lcp_magic, pktp);
    idlen = strlen(identstr);
    BCOPY(identstr, pktp, idlen);
    INCPTR(idlen, pktp);
    fsm_sdata(f, CODE_IDENT, ++f->id, pkt, pktp - pkt);
}

/*ARGSUSED*/
static void
lcp_received_identification (f, id, inp, len)
    fsm *f;
    int id;
    u_char *inp;
    int len;
{
    u_int32_t magic;

    /* Check the magic number - don't count replies from ourselves. */
    if (len < 4) {
	dbglog("%s: received short Identification; %d < 4", len);
	return;
    }
    GETLONG(magic, inp);
    len -= 4;
    if (lcp_gotoptions[f->unit].neg_magicnumber && f->state == OPENED &&
	magic == lcp_gotoptions[f->unit].magicnumber) {
	warn("appear to have received our own Identification!");
	return;
    }
    if (len > 0 && (len > 1 || *inp != '\0'))
	notice("Peer Identification: %0.*v", len, inp);
}

/*
 * Send a Time-Remaining LCP packet.  We don't include a message.
 */
static void
LcpSendTimeRemaining(f, time_remaining)
    fsm *f;
    u_int32_t time_remaining;
{
    u_int32_t lcp_magic;
    u_char pkt[8];
    u_char *pktp;

    if (f->state != OPENED)
	return;

    lcp_magic = lcp_gotoptions[f->unit].magicnumber;
    pktp = pkt;
    PUTLONG(lcp_magic, pktp);
    PUTLONG(time_remaining, pktp);
    fsm_sdata(f, CODE_TIMEREMAIN, ++f->id, pkt, pktp - pkt);
}

/*ARGSUSED*/
static void
lcp_received_timeremain(f, id, inp, len)
    fsm *f;
    int id;
    u_char *inp;
    int len;
{
    u_int32_t magic;
    u_int32_t time_remaining;

    /* Check the magic number - don't count replies from ourselves. */
    if (len < 8) {
	dbglog("%s: received short Time-Remain; %d < 8", len);
	return;
    }
    GETLONG(magic, inp);
    if (lcp_gotoptions[f->unit].neg_magicnumber && f->state == OPENED &&
	magic == lcp_gotoptions[f->unit].magicnumber) {
	warn("appear to have received our own Time-Remain!");
	return;
    }
    GETLONG(time_remaining, inp);
    if (len > 8) {
	notice("%d seconds remain: \"%.*s\"", time_remaining,
	    len-8, inp);
    } else {
	notice("Time Remaining: %d seconds", time_remaining);
    }
}

/*
 * lcp_timeremaining - timeout handler which sends LCP Time-Remaining
 * packet.
 */
static void
lcp_timeremaining(arg)
    void *arg;
{
    struct lcp_timer *lt = (struct lcp_timer *)arg;
    u_int32_t time_remaining;
    int unit;

    unit = lt->unit;
    time_remaining = lt->tr;
    LcpSendTimeRemaining(&lcp_fsm[unit], time_remaining);
    free(lt);
}

/*
 * lcp_settimeremaining - set a timeout to send an LCP Time-Remaining
 * packet.  The first argument, connecttime, is the time remaining
 * at the time this function is called.  The second argument is the
 * desired time remaining when the packet should be sent out.
 */
void
lcp_settimeremaining(unit, connecttime, time_remaining)
    int unit;
    u_int32_t connecttime;
    u_int32_t time_remaining;
{
    struct lcp_timer *lt;

    if (connecttime == time_remaining) {
	LcpSendTimeRemaining(&lcp_fsm[unit], time_remaining);
    } else {
	lt = (struct lcp_timer *)malloc(sizeof (struct lcp_timer));
	lt->unit = unit;
	lt->tr = time_remaining;
	TIMEOUT(lcp_timeremaining, (void *)lt, connecttime - time_remaining);
    }
}
