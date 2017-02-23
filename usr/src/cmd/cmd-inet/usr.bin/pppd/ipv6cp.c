/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 *
 *
    ipv6cp.c - PPP IPV6 Control Protocol.
    Copyright (C) 1999  Tommi Komulainen <Tommi.Komulainen@iki.fi>

    Redistribution and use in source and binary forms are permitted
    provided that the above copyright notice and this paragraph are
    duplicated in all such forms.  The name of the author may not be
    used to endorse or promote products derived from this software
    without specific prior written permission.
    THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
    IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
    WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
*/

/*  Original version, based on RFC2023 :

    Copyright (c) 1995, 1996, 1997 Francis.Dupont@inria.fr, INRIA Rocquencourt,
    Alain.Durand@imag.fr, IMAG,
    Jean-Luc.Richier@imag.fr, IMAG-LSR.

    Copyright (c) 1998, 1999 Francis.Dupont@inria.fr, GIE DYADE,
    Alain.Durand@imag.fr, IMAG,
    Jean-Luc.Richier@imag.fr, IMAG-LSR.

    Ce travail a été fait au sein du GIE DYADE (Groupement d'Intérêt
    Économique ayant pour membres BULL S.A. et l'INRIA).

    Ce logiciel informatique est disponible aux conditions
    usuelles dans la recherche, c'est-à-dire qu'il peut
    être utilisé, copié, modifié, distribué à l'unique
    condition que ce texte soit conservé afin que
    l'origine de ce logiciel soit reconnue.

    Le nom de l'Institut National de Recherche en Informatique
    et en Automatique (INRIA), de l'IMAG, ou d'une personne morale
    ou physique ayant participé à l'élaboration de ce logiciel ne peut
    être utilisé sans son accord préalable explicite.

    Ce logiciel est fourni tel quel sans aucune garantie,
    support ou responsabilité d'aucune sorte.
    Ce logiciel est dérivé de sources d'origine
    "University of California at Berkeley" et
    "Digital Equipment Corporation" couvertes par des copyrights.

    L'Institut d'Informatique et de Mathématiques Appliquées de Grenoble (IMAG)
    est une fédération d'unités mixtes de recherche du CNRS, de l'Institut National
    Polytechnique de Grenoble et de l'Université Joseph Fourier regroupant
    sept laboratoires dont le laboratoire Logiciels, Systèmes, Réseaux (LSR).

    This work has been done in the context of GIE DYADE (joint R & D venture
    between BULL S.A. and INRIA).

    This software is available with usual "research" terms
    with the aim of retain credits of the software.
    Permission to use, copy, modify and distribute this software for any
    purpose and without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies,
    and the name of INRIA, IMAG, or any contributor not be used in advertising
    or publicity pertaining to this material without the prior explicit
    permission. The software is provided "as is" without any
    warranties, support or liabilities of any kind.
    This software is derived from source code from
    "University of California at Berkeley" and
    "Digital Equipment Corporation" protected by copyrights.

    Grenoble's Institute of Computer Science and Applied Mathematics (IMAG)
    is a federation of seven research units funded by the CNRS, National
    Polytechnic Institute of Grenoble and University Joseph Fourier.
    The research unit in Software, Systems, Networks (LSR) is member of IMAG.
*/

/*
 * Derived from :
 *
 *
 * ipcp.c - PPP IP Control Protocol.
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
 *
 * $Id: ipv6cp.c,v 1.9 2000/04/15 01:27:11 masputra Exp $
 */

#define RCSID	"$Id: ipv6cp.c,v 1.9 2000/04/15 01:27:11 masputra Exp $"

/*
 * TODO:
 *
 * Proxy Neighbour Discovery.
 *
 * Better defines for selecting the ordering of
 *   interface up / set address. (currently checks for __linux__,
 *   since SVR4 && (SNI || __USLC__) didn't work properly)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pppd.h"
#include "eui64.h"
#include "fsm.h"
#include "ipcp.h"
#include "ipv6cp.h"
#include "magic.h"
#include "pathnames.h"

#if !defined(lint) && !defined(_lint)
static const char rcsid[] = RCSID;
#endif

/* global vars */
ipv6cp_options ipv6cp_wantoptions[NUM_PPP];     /* Options that we want to request */
ipv6cp_options ipv6cp_gotoptions[NUM_PPP];	/* Options that peer ack'd */
ipv6cp_options ipv6cp_allowoptions[NUM_PPP];	/* Options we allow peer to request */
ipv6cp_options ipv6cp_hisoptions[NUM_PPP];	/* Options that we ack'd */
int no_ifaceid_neg = 0;

/* local vars */
static bool ipv6cp_is_up;

/*
 * Callbacks for fsm code.  (CI = Configuration Information)
 */
static void ipv6cp_resetci __P((fsm *));	/* Reset our CI */
static int  ipv6cp_cilen __P((fsm *));	        /* Return length of our CI */
static void ipv6cp_addci __P((fsm *, u_char *, int *)); /* Add our CI */
static int  ipv6cp_ackci __P((fsm *, u_char *, int));	/* Peer ack'd our CI */
static int  ipv6cp_nakci __P((fsm *, u_char *, int));	/* Peer nak'd our CI */
static int  ipv6cp_rejci __P((fsm *, u_char *, int));	/* Peer rej'd our CI */
static int  ipv6cp_reqci __P((fsm *, u_char *, int *, int)); /* Rcv CI */
static void ipv6cp_up __P((fsm *));		/* We're UP */
static void ipv6cp_down __P((fsm *));		/* We're DOWN */
static void ipv6cp_finished __P((fsm *));	/* Don't need lower layer */

fsm ipv6cp_fsm[NUM_PPP];		/* IPV6CP fsm structure */

static fsm_callbacks ipv6cp_callbacks = { /* IPV6CP callback routines */
    ipv6cp_resetci,		/* Reset our Configuration Information */
    ipv6cp_cilen,		/* Length of our Configuration Information */
    ipv6cp_addci,		/* Add our Configuration Information */
    ipv6cp_ackci,		/* ACK our Configuration Information */
    ipv6cp_nakci,		/* NAK our Configuration Information */
    ipv6cp_rejci,		/* Reject our Configuration Information */
    ipv6cp_reqci,		/* Request peer's Configuration Information */
    ipv6cp_up,			/* Called when fsm reaches OPENED state */
    ipv6cp_down,		/* Called when fsm leaves OPENED state */
    NULL,			/* Called when we want the lower layer up */
    ipv6cp_finished,		/* Called when we want the lower layer down */
    NULL,			/* Retransmission is necessary */
    NULL,			/* Called to handle protocol-specific codes */
    "IPV6CP",			/* String name of protocol */
    NULL			/* Peer rejected a code number */
};

static int setifaceid __P((char **arg, option_t *));

/*
 * Command-line options.
 */
static option_t ipv6cp_option_list[] = {
    { "ipv6", o_special, (void *)setifaceid,
      "Set interface identifiers for IPV6" },
    { "noipv6", o_bool, &ipv6cp_protent.enabled_flag,
      "Disable IPv6 and IPv6CP" },
    { "-ipv6", o_bool, &ipv6cp_protent.enabled_flag,
      "Disable IPv6 and IPv6CP" },
    { "+ipv6", o_bool, &ipv6cp_protent.enabled_flag,
      "Enable IPv6 and IPv6CP", 1 },
    { "ipv6cp-accept-local", o_bool, &ipv6cp_wantoptions[0].accept_local,
      "Accept peer's interface identifier for us", 1 },
    { "ipv6cp-use-ipaddr", o_bool, &ipv6cp_wantoptions[0].use_ip,
      "Use (default) IPv4 address as interface identifier", 1 },
#if defined(SOL2)
    { "ipv6cp-use-persistent", o_bool, &ipv6cp_wantoptions[0].use_persistent,
      "Use unique persistent value for link local address", 1 },
#endif /* defined(SOL2) */
    { "ipv6cp-restart", o_int, &ipv6cp_fsm[0].timeouttime,
      "Set timeout for IPv6CP" },
    { "ipv6cp-max-terminate", o_int, &ipv6cp_fsm[0].maxtermtransmits,
      "Maximum number of IPV6CP Terminate-Request" },
    { "ipv6cp-max-configure", o_int, &ipv6cp_fsm[0].maxconfreqtransmits,
      "Maximum number of IPV6CP Configure-Request" },
    { "ipv6cp-max-failure", o_int, &ipv6cp_fsm[0].maxnakloops,
      "Maximum number of IPV6CP Configure-Nak" },
    { NULL }
};


/*
 * Protocol entry points from main code.
 */
static void ipv6cp_init __P((int));
static void ipv6cp_open __P((int));
static void ipv6cp_close __P((int, char *));
static void ipv6cp_lowerup __P((int));
static void ipv6cp_lowerdown __P((int));
static void ipv6cp_input __P((int, u_char *, int));
static void ipv6cp_protrej __P((int));
static int  ipv6cp_printpkt __P((u_char *, int,
    void (*) __P((void *, const char *, ...)), void *));
static void ipv6_check_options __P((void));
static int  ipv6_demand_conf __P((int));
static int  ipv6_active_pkt __P((u_char *, int));

struct protent ipv6cp_protent = {
    PPP_IPV6CP,			/* Protocol Number for IPV6CP */
    ipv6cp_init,		/* Initializes IPV6CP */
    ipv6cp_input,		/* Processes a received IPV6CP packet */
    ipv6cp_protrej,		/* Process a received Protocol-reject */
    ipv6cp_lowerup,		/* Called when LCP is brought up */
    ipv6cp_lowerdown,		/* Called when LCP has gone down */
    ipv6cp_open,		/* Called when link is established */
    ipv6cp_close,		/* Called when link has gone down */
    ipv6cp_printpkt,		/* Print a packet in human readable form */
    NULL,			/* Process a received data packet */
    0,				/* IPV6CP is disabled by default */
    "IPV6CP",			/* Name of the protocol */
    "IPV6",			/* Name of the corresponding data protocol */
    ipv6cp_option_list,		/* List of IPV6CP command-line options */
    ipv6_check_options,		/* Assigns default values for options */
    ipv6_demand_conf,		/* Configures demand-dial */
    ipv6_active_pkt		/* Bring up the link for this packet? */
};

/*
 * Local forward function declarations.
 */
static void ipv6cp_clear_addrs __P((int, eui64_t, eui64_t));
static void ipv6cp_script __P((char *));
static void ipv6cp_script_done __P((void *, int));

/*
 * Lengths of configuration options.
 */
#define CILEN_VOID	2
#define CILEN_COMPRESS	4	/* length for RFC2023 compress opt. */
#define CILEN_IFACEID   10	/* RFC2472, interface identifier    */

#define CODENAME(x)	((x) == CODE_CONFACK ? "ACK" : \
			 (x) == CODE_CONFNAK ? "NAK" : "REJ")

/*
 * This state variable is used to ensure that we don't
 * run an ipcp-up/down script while one is already running.
 */
static enum script_state {
    s_down,
    s_up
} ipv6cp_script_state;
static pid_t ipv6cp_script_pid;

/*
 * setifaceid - set the interface identifiers manually
 */
/*ARGSUSED*/
static int
setifaceid(argv, opt)
    char **argv;
    option_t *opt;
{
    char *comma, *arg;
    ipv6cp_options *wo = &ipv6cp_wantoptions[0];
    struct in6_addr addr;

#define VALIDID(a) ( (((a).s6_addr32[0] == 0) && ((a).s6_addr32[1] == 0)) && \
			(((a).s6_addr32[2] != 0) || ((a).s6_addr32[3] != 0)) )


    arg = *argv;

    comma = strchr(arg, ',');

    /*
     * If comma first character, then no local identifier
     */
    if (comma != arg) {
	if (comma != NULL)
	    *comma = '\0';

	if (inet_pton(AF_INET6, arg, &addr) != 1 || !VALIDID(addr)) {
	    option_error("Illegal interface identifier (local): %s", arg);
	    return 0;
	}

	eui64_copy(addr.s6_addr32[2], wo->ourid);
	wo->opt_local = 1;
    }

    /*
     * If comma last character, then no remote identifier
     */
    if (comma != NULL && *++comma != '\0') {
	if (inet_pton(AF_INET6, comma, &addr) != 1 || !VALIDID(addr)) {
	    option_error("Illegal interface identifier (remote): %s", comma);
	    return 0;
	}
	eui64_copy(addr.s6_addr32[2], wo->hisid);
	wo->opt_remote = 1;
    }

    ipv6cp_protent.enabled_flag = 1;
    return 1;
}

/*
 * Given an interface identifier, return a string representation of the
 * link local address associated with that identifier.
 * string will be at most 26 characters (including null terminator).
 */
static char *
llv6_ntoa(ifaceid)
    eui64_t ifaceid;
{
    struct in6_addr addr;
    static char addrstr[26];

    BZERO(&addr, sizeof (addr));
    addr.s6_addr[0] = 0xfe;
    addr.s6_addr[1] = 0x80;
    eui64_copy(ifaceid, addr.s6_addr[8]);

    (void) inet_ntop(AF_INET6, &addr, addrstr, 26);

    return addrstr;
}


/*
 * ipv6cp_init - Initialize IPV6CP.
 */
static void
ipv6cp_init(unit)
    int unit;
{
    fsm *f = &ipv6cp_fsm[unit];
    ipv6cp_options *wo = &ipv6cp_wantoptions[unit];
    ipv6cp_options *ao = &ipv6cp_allowoptions[unit];

    f->unit = unit;
    f->protocol = PPP_IPV6CP;
    f->callbacks = &ipv6cp_callbacks;
    fsm_init(&ipv6cp_fsm[unit]);

    BZERO(wo, sizeof(*wo));
    BZERO(ao, sizeof(*ao));

    wo->neg_ifaceid = 1;
    ao->neg_ifaceid = 1;

#ifdef IPV6CP_COMP
    wo->neg_vj = 1;
    ao->neg_vj = 1;
    wo->vj_protocol = IPV6CP_COMP;
#endif

}


/*
 * ipv6cp_open - IPV6CP is allowed to come up.
 */
static void
ipv6cp_open(unit)
    int unit;
{
    fsm_open(&ipv6cp_fsm[unit]);
}


/*
 * ipv6cp_close - Take IPV6CP down.
 */
static void
ipv6cp_close(unit, reason)
    int unit;
    char *reason;
{
    fsm_close(&ipv6cp_fsm[unit], reason);
}


/*
 * ipv6cp_lowerup - The lower layer is up.
 */
static void
ipv6cp_lowerup(unit)
    int unit;
{
    fsm_lowerup(&ipv6cp_fsm[unit]);
}


/*
 * ipv6cp_lowerdown - The lower layer is down.
 */
static void
ipv6cp_lowerdown(unit)
    int unit;
{
    fsm_lowerdown(&ipv6cp_fsm[unit]);
}


/*
 * ipv6cp_input - Input IPV6CP packet.
 */
static void
ipv6cp_input(unit, p, len)
    int unit;
    u_char *p;
    int len;
{
    fsm_input(&ipv6cp_fsm[unit], p, len);
}


/*
 * ipv6cp_protrej - A Protocol-Reject was received for IPV6CP.
 */
static void
ipv6cp_protrej(unit)
    int unit;
{
    fsm_protreject(&ipv6cp_fsm[unit]);
}


/*
 * ipv6cp_resetci - Reset our CI.
 */
static void
ipv6cp_resetci(f)
    fsm *f;
{
    ipv6cp_options *wo = &ipv6cp_wantoptions[f->unit];
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];

    wo->req_ifaceid = wo->neg_ifaceid && ipv6cp_allowoptions[f->unit].neg_ifaceid;

    if (!wo->opt_local) {
	eui64_magic_nz(wo->ourid);
    }

    *go = *wo;
    eui64_zero(go->hisid);	/* last proposed interface identifier */
}


/*
 * ipv6cp_cilen - Return length of our CI.
 */
static int
ipv6cp_cilen(f)
    fsm *f;
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];

#define LENCIVJ(neg)		(neg ? CILEN_COMPRESS : 0)
#define LENCIIFACEID(neg)	(neg ? CILEN_IFACEID : 0)

    return (LENCIIFACEID(go->neg_ifaceid) +
	    LENCIVJ(go->neg_vj));
}


/*
 * ipv6cp_addci - Add our desired CIs to a packet.
 */
static void
ipv6cp_addci(f, ucp, lenp)
    fsm *f;
    u_char *ucp;
    int *lenp;
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    int len = *lenp;

#define ADDCIVJ(opt, neg, val) \
    if (neg) { \
	int vjlen = CILEN_COMPRESS; \
	if (len >= vjlen) { \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(vjlen, ucp); \
	    PUTSHORT(val, ucp); \
	    len -= vjlen; \
	} else \
	    neg = 0; \
    }

#define ADDCIIFACEID(opt, neg, val1) \
    if (neg) { \
	int idlen = CILEN_IFACEID; \
	if (len >= idlen) { \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(idlen, ucp); \
	    eui64_put(val1, ucp); \
	    len -= idlen; \
	} else \
	    neg = 0; \
    }

    ADDCIIFACEID(CI_IFACEID, go->neg_ifaceid, go->ourid);

    ADDCIVJ(CI_COMPRESSTYPE, go->neg_vj, go->vj_protocol);

    *lenp -= len;
}


/*
 * ipv6cp_ackci - Ack our CIs.
 *
 * Returns:
 *	0 - Ack was bad.
 *	1 - Ack was good.
 */
static int
ipv6cp_ackci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    u_short cilen, citype, cishort;
    eui64_t ifaceid;

    /*
     * CIs must be in exactly the same order that we sent...
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */

#define ACKCIVJ(opt, neg, val) \
    if (neg) { \
	int vjlen = CILEN_COMPRESS; \
	if ((len -= vjlen) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != vjlen || \
	    citype != opt)  \
	    goto bad; \
	GETSHORT(cishort, p); \
	if (cishort != val) \
	    goto bad; \
    }

#define ACKCIIFACEID(opt, neg, val1) \
    if (neg) { \
	int idlen = CILEN_IFACEID; \
	if ((len -= idlen) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != idlen || \
	    citype != opt) \
	    goto bad; \
	eui64_get(ifaceid, p); \
	if (! eui64_equals(val1, ifaceid)) \
	    goto bad; \
    }

    ACKCIIFACEID(CI_IFACEID, go->neg_ifaceid, go->ourid);

    ACKCIVJ(CI_COMPRESSTYPE, go->neg_vj, go->vj_protocol);

    /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
	goto bad;
    return (1);

bad:
    IPV6CPDEBUG(("ipv6cp_ackci: received bad Ack!"));
    return (0);
}

/*
 * ipv6cp_nakci - Peer has sent a NAK for some of our CIs.
 * This should not modify any state if the Nak is bad
 * or if IPV6CP is in the OPENED state.
 *
 * Returns:
 *	0 - Nak was bad.
 *	1 - Nak was good.
 */
static int
ipv6cp_nakci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    u_char citype, cilen, *next;
    u_short cishort;
    eui64_t ifaceid;
    ipv6cp_options no;		/* options we've seen Naks for */
    ipv6cp_options try;		/* options to request next time */

    BZERO(&no, sizeof(no));
    try = *go;

    /*
     * Any Nak'd CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define NAKCIIFACEID(opt, neg, code) \
    if (go->neg && \
	len >= (cilen = CILEN_IFACEID) && \
	p[1] == cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	eui64_get(ifaceid, p); \
	no.neg = 1; \
	code \
    }

#define NAKCIVJ(opt, neg, code) \
    if (go->neg && \
	((cilen = p[1]) == CILEN_COMPRESS) && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	no.neg = 1; \
        code \
    }

    /*
     * Accept the peer's idea of {our,its} interface identifier, if different
     * from our idea, only if the accept_{local,remote} flag is set.
     */
    NAKCIIFACEID(CI_IFACEID, neg_ifaceid,
	      if (go->accept_local) {
		  while (eui64_iszero(ifaceid) ||
			 eui64_equals(ifaceid, go->hisid)) /* bad luck */
		      eui64_magic(ifaceid);
		  try.ourid = ifaceid;
		  IPV6CPDEBUG(("local LL address %s", llv6_ntoa(ifaceid)));
	      }
	      );

#ifdef IPV6CP_COMP
    NAKCIVJ(CI_COMPRESSTYPE, neg_vj,
	    {
		if (cishort == IPV6CP_COMP) {
		    try.vj_protocol = cishort;
		} else {
		    try.neg_vj = 0;
		}
	    }
	    );
#else
    NAKCIVJ(CI_COMPRESSTYPE, neg_vj,
	    {
		try.neg_vj = 0;
	    }
	    );
#endif

    /*
     * There may be remaining CIs, if the peer is requesting negotiation
     * on an option that we didn't include in our request packet.
     * If they want to negotiate about interface identifier, we comply.
     * If they want us to ask for compression, we refuse.
     */
    while (len > CILEN_VOID) {
	GETCHAR(citype, p);
	GETCHAR(cilen, p);
	if( (len -= cilen) < 0 )
	    goto bad;
	next = p + cilen - 2;

	switch (citype) {
	case CI_COMPRESSTYPE:
	    if (go->neg_vj || no.neg_vj ||
		(cilen != CILEN_COMPRESS))
		goto bad;
	    no.neg_vj = 1;
	    break;
	case CI_IFACEID:
	    if (go->neg_ifaceid || no.neg_ifaceid || cilen != CILEN_IFACEID)
		goto bad;
	    try.neg_ifaceid = 1;
	    eui64_get(ifaceid, p);
	    if (go->accept_local) {
		while (eui64_iszero(ifaceid) ||
		       eui64_equals(ifaceid, go->hisid)) /* bad luck */
		    eui64_magic(ifaceid);
		try.ourid = ifaceid;
	    }
	    no.neg_ifaceid = 1;
	    break;
	}
	p = next;
    }

    /* If there is still anything left, this packet is bad. */
    if (len != 0)
	goto bad;

    /*
     * OK, the Nak is good.  Now we can update state.
     */
    if (f->state != OPENED)
	*go = try;

    return 1;

bad:
    IPV6CPDEBUG(("ipv6cp_nakci: received bad Nak!"));
    return 0;
}


/*
 * ipv6cp_rejci - Reject some of our CIs.
 */
static int
ipv6cp_rejci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    u_char cilen;
    u_short cishort;
    eui64_t ifaceid;
    ipv6cp_options try;		/* options to request next time */

    try = *go;
    /*
     * Any Rejected CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define REJCIIFACEID(opt, neg, val1) \
    if (go->neg && \
	len >= (cilen = CILEN_IFACEID) && \
	p[1] == cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	eui64_get(ifaceid, p); \
	/* Check rejected value. */ \
	if (! eui64_equals(ifaceid, val1)) \
	    goto bad; \
	try.neg = 0; \
    }

#define REJCIVJ(opt, neg, val) \
    if (go->neg && \
	p[1] == CILEN_COMPRESS && \
	len >= p[1] && \
	p[0] == opt) { \
	len -= p[1]; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	/* Check rejected value. */  \
	if (cishort != val) \
	    goto bad; \
	try.neg = 0; \
     }

    REJCIIFACEID(CI_IFACEID, neg_ifaceid, go->ourid);

    REJCIVJ(CI_COMPRESSTYPE, neg_vj, go->vj_protocol);

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
    IPV6CPDEBUG(("ipv6cp_rejci: received bad Reject!"));
    return 0;
}


/*
 * ipv6cp_reqci - Check the peer's requested CIs and send appropriate response.
 *
 * Returns: CODE_CONFACK, CODE_CONFNAK or CODE_CONFREJ and input packet modified
 * appropriately.  If reject_if_disagree is non-zero, doesn't return
 * CODE_CONFNAK; returns CODE_CONFREJ if it can't return CODE_CONFACK.
 */
static int
ipv6cp_reqci(f, p, lenp, dont_nak)
    fsm *f;
    u_char *p;		/* Requested CIs */
    int *lenp;			/* Length of requested CIs */
    int dont_nak;
{
    ipv6cp_options *wo = &ipv6cp_wantoptions[f->unit];
    ipv6cp_options *ho = &ipv6cp_hisoptions[f->unit];
    ipv6cp_options *ao = &ipv6cp_allowoptions[f->unit];
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    u_char *p0, *nakp, *rejp, *prev;
    int ret, newret;
    int len, cilen, type;
    eui64_t ifaceid;
    u_short cishort;

    ret = CODE_CONFACK;
    rejp = p0 = p;
    nakp = nak_buffer;

    /*
     * Reset all its options.
     */
    BZERO(ho, sizeof(*ho));

    /*
     * Process all its options.
     */
    for (len = *lenp; len > 0; len -= cilen, p = prev + cilen) {
	newret = CODE_CONFACK;

	if ((len < 2) || p[1] > len) {
	    /*
	     * RFC 1661 page 40 -- if the option extends beyond the
	     * packet, then discard the entire packet.
	     */
	    return (0);
	}

	prev = p;
	GETCHAR(type, p);
	GETCHAR(cilen, p);

	switch (type) {		/* Check CI type */
	case CI_IFACEID:
	    IPV6CPDEBUG(("ipv6cp: received interface identifier "));

	    if (!ao->neg_ifaceid) {
		newret = CODE_CONFREJ;
		break;
	    }

	    if (cilen != CILEN_IFACEID) {
		/*
		 * rfc1661, page 40 -- a recongnized option with an
		 * invalid length should be Nak'ed.
		 */
		newret = CODE_CONFNAK;
		eui64_copy(wo->hisid, ifaceid);
	    } else {

		/*
		 * If it has no interface identifier, or if we both
		 * have same identifier then NAK it with new idea.  In
		 * particular, if we don't know his identifier, but it
		 * does, then accept that identifier.
		 */
		eui64_get(ifaceid, p);
		IPV6CPDEBUG(("(%s)", llv6_ntoa(ifaceid)));
		if (eui64_iszero(ifaceid) && eui64_iszero(go->ourid)) {
		    newret = CODE_CONFREJ;		/* Reject CI */
		    break;
		}
		/* If we don't like its ID, then nak that ID. */
		if (!eui64_iszero(wo->hisid) &&
		    !eui64_equals(ifaceid, wo->hisid) &&
		    eui64_iszero(go->hisid)) {
		    newret = CODE_CONFNAK;
		    eui64_copy(wo->hisid, ifaceid);
		} else if (eui64_iszero(ifaceid) ||
		    eui64_equals(ifaceid, go->ourid)) {
		    newret = CODE_CONFNAK;
		    /* first time, try option */
		    if (eui64_iszero(go->hisid))
			eui64_copy(wo->hisid, ifaceid);
		    while (eui64_iszero(ifaceid) ||
			eui64_equals(ifaceid, go->ourid)) /* bad luck */
			eui64_magic(ifaceid);
		}
	    }
	    if (newret == CODE_CONFNAK) {
		PUTCHAR(type, nakp);
		PUTCHAR(CILEN_IFACEID, nakp);
		eui64_put(ifaceid, nakp);
	    }

	    ho->neg_ifaceid = 1;
	    eui64_copy(ifaceid, ho->hisid);
	    break;

	case CI_COMPRESSTYPE:
	    IPV6CPDEBUG(("ipv6cp: received COMPRESSTYPE "));

	    if (!ao->neg_vj) {
		newret = CODE_CONFREJ;
		break;
	    }

	    if (cilen != CILEN_COMPRESS) {
		newret = CODE_CONFNAK;
		cishort = ao->vj_protocol;
	    } else {
		GETSHORT(cishort, p);
		IPV6CPDEBUG(("(%d)", cishort));

#ifdef IPV6CP_COMP
		if (cishort != IPV6CP_COMP) {
		    newret = CODE_CONFNAK;
		    cishort = IPV6CP_COMP;
		}
#else
		newret = CODE_CONFREJ;
		break;
#endif
	    }

	    ho->neg_vj = 1;
	    ho->vj_protocol = cishort;
	    break;

	default:
	    newret = CODE_CONFREJ;
	    break;
	}

	IPV6CPDEBUG((" (%s)\n", CODENAME(newret)));

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
	    if (dont_nak) {
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
		(void) BCOPY(prev, rejp, cilen);
	    rejp += cilen;
	}
    }

    /*
     * If we aren't rejecting this packet, and we want to negotiate
     * their identifier and they didn't send their identifier, then we
     * send a NAK with a CI_IFACEID option appended.  We assume the
     * input buffer is long enough that we can append the extra
     * option safely.
     */
    if (ret != CODE_CONFREJ && !ho->neg_ifaceid &&
	wo->req_ifaceid && !dont_nak) {
	if (ret == CODE_CONFACK)
	    wo->req_ifaceid = 0;
	ret = CODE_CONFNAK;
	PUTCHAR(CI_IFACEID, nakp);
	PUTCHAR(CILEN_IFACEID, nakp);
	eui64_put(wo->hisid, nakp);
    }

    switch (ret) {
    case CODE_CONFACK:
	*lenp = p - p0;
	sys_block_proto(PPP_IPV6);
	break;
    case CODE_CONFNAK:
	*lenp = nakp - nak_buffer;
	(void) BCOPY(nak_buffer, p0, *lenp);
	break;
    case CODE_CONFREJ:
	*lenp = rejp - p0;
	break;
    }

    IPV6CPDEBUG(("ipv6cp: returning Configure-%s", CODENAME(ret)));
    return (ret);			/* Return final code */
}


/*
 * ipv6_check_options - check that any IP-related options are OK,
 * and assign appropriate defaults.
 */
static void
ipv6_check_options()
{
    ipv6cp_options *wo = &ipv6cp_wantoptions[0];

#if defined(SOL2)
    /*
     * Persistent link-local id is only used when user has not explicitly
     * configure/hard-code the id
     */
    if ((wo->use_persistent) && (!wo->opt_local) && (!wo->opt_remote)) {

	/*
	 * On systems where there are no Ethernet interfaces used, there
	 * may be other ways to obtain a persistent id. Right now, it
	 * will fall back to using magic [see eui64_magic] below when
	 * an EUI-48 from MAC address can't be obtained. Other possibilities
	 * include obtaining EEPROM serial numbers, or some other unique
	 * yet persistent number. On Sparc platforms, this is possible,
	 * but too bad there's no standards yet for x86 machines.
	 */
	if (ether_to_eui64(&wo->ourid)) {
	    wo->opt_local = 1;
	}
    }
#endif

    /*
     * If ipv6cp-use-ipaddr is used, then both local and remote IPv4
     * addresses should be specified as options.  Otherwise, since
     * ipcp has yet to negotiate the IPv4 addresses, the interface
     * identifiers will be based on meaningless values.
     */
    if (wo->use_ip) {
	if ((ipcp_wantoptions[0].accept_local ||
	    ipcp_wantoptions[0].ouraddr == 0) && eui64_iszero(wo->ourid)) {
	    warn("either IPv4 or IPv6 local address should be non-zero for ipv6cp-use-ipaddr");
	}
	if ((ipcp_wantoptions[0].accept_remote ||
	    ipcp_wantoptions[0].hisaddr == 0) && eui64_iszero(wo->hisid)) {
	    warn("either IPv4 or IPv6 remote address should be non-zero for ipv6cp-use-ipaddr");
	}
    }

    if (!wo->opt_local) {	/* init interface identifier */
	if (wo->use_ip && eui64_iszero(wo->ourid)) {
	    eui64_setlo32(wo->ourid, ntohl(ipcp_wantoptions[0].ouraddr));
	    if (!eui64_iszero(wo->ourid))
		wo->opt_local = 1;
	}

	while (eui64_iszero(wo->ourid))
	    eui64_magic(wo->ourid);
    }

    if (!wo->opt_remote) {
	if (wo->use_ip && eui64_iszero(wo->hisid)) {
	    eui64_setlo32(wo->hisid, ntohl(ipcp_wantoptions[0].hisaddr));
	    if (!eui64_iszero(wo->hisid))
		wo->opt_remote = 1;
	}
    }

    if (demand && (eui64_iszero(wo->ourid) || eui64_iszero(wo->hisid))) {
	fatal("local/remote LL address required for demand-dialling\n");
    }
}


/*
 * ipv6_demand_conf - configure the interface as though
 * IPV6CP were up, for use with dial-on-demand.
 */
static int
ipv6_demand_conf(u)
    int u;
{
    ipv6cp_options *wo = &ipv6cp_wantoptions[u];

#if SIF6UPFIRST
    if (!sif6up(u))
	return 0;
#endif
    if (!sif6addr(u, wo->ourid, wo->hisid))
	return 0;
#if !SIF6UPFIRST
    if (!sif6up(u))
	return 0;
#endif
    if (!sifnpmode(u, PPP_IPV6, NPMODE_QUEUE))
	return 0;

    notice("local  LL address %s", llv6_ntoa(wo->ourid));
    notice("remote LL address %s", llv6_ntoa(wo->hisid));

    return 1;
}


/*
 * ipv6cp_up - IPV6CP has come UP.
 *
 * Configure the IPv6 network interface appropriately and bring it up.
 */
static void
ipv6cp_up(f)
    fsm *f;
{
    ipv6cp_options *ho = &ipv6cp_hisoptions[f->unit];
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    ipv6cp_options *wo = &ipv6cp_wantoptions[f->unit];

    IPV6CPDEBUG(("ipv6cp: up"));

    /*
     * We must have a non-zero LL address for both ends of the link.
     */
    if (!ho->neg_ifaceid)
	ho->hisid = wo->hisid;

    if(!no_ifaceid_neg) {
	if (eui64_iszero(ho->hisid)) {
	    error("Could not determine remote LL address");
	    ipv6cp_close(f->unit, "Could not determine remote LL address");
	    return;
	}
	if (eui64_iszero(go->ourid)) {
	    error("Could not determine local LL address");
	    ipv6cp_close(f->unit, "Could not determine local LL address");
	    return;
	}
	if (eui64_equals(go->ourid, ho->hisid)) {
	    error("local and remote LL addresses are equal");
	    ipv6cp_close(f->unit, "local and remote LL addresses are equal");
	    return;
	}
    }

#ifdef IPV6CP_COMP
    /* set tcp compression */
    if (sif6comp(f->unit, ho->neg_vj) != 1) {
	ipv6cp_close(f->unit, "Could not enable TCP compression");
	return;
    }
#endif

    /*
     * If we are doing dial-on-demand, the interface is already
     * configured, so we put out any saved-up packets, then set the
     * interface to pass IPv6 packets.
     */
    if (demand) {
	if (! eui64_equals(go->ourid, wo->ourid) ||
	    ! eui64_equals(ho->hisid, wo->hisid)) {
	    if (! eui64_equals(go->ourid, wo->ourid))
		warn("Local LL address changed to %s",
		     llv6_ntoa(go->ourid));
	    if (! eui64_equals(ho->hisid, wo->hisid))
		warn("Remote LL address changed to %s",
		     llv6_ntoa(ho->hisid));
	    ipv6cp_clear_addrs(f->unit, go->ourid, ho->hisid);

	    /* Set the interface to the new addresses */
	    if (!sif6addr(f->unit, go->ourid, ho->hisid)) {
		if (debug)
		    warn("sif6addr failed");
		ipv6cp_close(f->unit, "Interface configuration failed");
		return;
	    }

	}
	demand_rexmit(PPP_IPV6);
	if (sifnpmode(f->unit, PPP_IPV6, NPMODE_PASS) != 1) {
	    ipv6cp_close(f->unit, "Interface configuration failed");
	    return;
	}

    } else {
	/*
	 * Set LL addresses
	 */
#if !SIF6UPFIRST
	if (!sif6addr(f->unit, go->ourid, ho->hisid)) {
	    if (debug)
		warn("sif6addr failed");
	    ipv6cp_close(f->unit, "Interface configuration failed");
	    return;
	}
#endif
#if defined(SOL2)
	/* bring the interface up for IPv6 */
	if (!sif6up(f->unit)) {
	    if (debug)
		warn("sifup failed (IPV6)");
	    ipv6cp_close(f->unit, "Interface configuration failed");
	    return;
	}
#else
	if (!sifup(f->unit)) {
	    if (debug)
		warn("sifup failed (IPV6)");
	    ipv6cp_close(f->unit, "Interface configuration failed");
	    return;
	}
#endif
#if SIF6UPFIRST
	if (!sif6addr(f->unit, go->ourid, ho->hisid)) {
	    if (debug)
		warn("sif6addr failed");
	    ipv6cp_close(f->unit, "Interface configuration failed");
	    return;
	}
#endif
	if (sifnpmode(f->unit, PPP_IPV6, NPMODE_PASS) != 1) {
	    ipv6cp_close(f->unit, "Interface configuration failed");
	    return;
	}

	notice("local  LL address %s", llv6_ntoa(go->ourid));
	notice("remote LL address %s", llv6_ntoa(ho->hisid));
    }

    np_up(f->unit, PPP_IPV6);
    ipv6cp_is_up = 1;

    /*
     * Execute the ipv6-up script, like this:
     *	/etc/ppp/ipv6-up interface tty speed local-LL remote-LL
     */
    script_setenv("LLLOCAL", llv6_ntoa(go->ourid), 0);
    script_setenv("LLREMOTE", llv6_ntoa(ho->hisid), 0);
    if (ipv6cp_script_state == s_down && ipv6cp_script_pid == 0) {
	ipv6cp_script_state = s_up;
	ipv6cp_script(_PATH_IPV6UP);
    }
    sys_unblock_proto(PPP_IPV6);
}


/*
 * ipv6cp_down - IPV6CP has gone DOWN.
 *
 * Take the IPv6 network interface down, clear its addresses
 * and delete routes through it.
 */
static void
ipv6cp_down(f)
    fsm *f;
{
    IPV6CPDEBUG(("ipv6cp: down"));
    update_link_stats(f->unit);
    if (ipv6cp_is_up) {
	ipv6cp_is_up = 0;
	np_down(f->unit, PPP_IPV6);
    }
#ifdef IPV6CP_COMP
    if (sif6comp(f->unit, 0) != 1) {
	if (debug)
	    warn("Failed to disable TCP compression.");
    }
#endif

    /*
     * If we are doing dial-on-demand, set the interface
     * to queue up outgoing packets (for now).
     */
    if (demand) {
	if (sifnpmode(f->unit, PPP_IPV6, NPMODE_QUEUE) != 1) {
	    if (debug)
		warn("Failed to enable queueing on outgoing packets.");
	}
    } else {
	if (sifnpmode(f->unit, PPP_IPV6, NPMODE_ERROR) != 1) {
	    if (debug)
		warn("Could not set interface to drop packets.");
	}
#if !defined(__linux__) && !(defined(SVR4) && (defined(SNI) || defined(__USLC)))
#if defined(SOL2)
	if (sif6down(f->unit) != 1)
	    warn("Couldn not bring interface down.");
#else
	if (sifdown(f->unit) != 1)
	    warn("Could not bring interface down.");
#endif /* defined(SOL2) */
#endif
	ipv6cp_clear_addrs(f->unit,
			   ipv6cp_gotoptions[f->unit].ourid,
			   ipv6cp_hisoptions[f->unit].hisid);
#if defined(__linux__) || (defined(SVR4) && (defined(SNI) || defined(__USLC)))
	if (sifdown(f->unit) != 1)
	    warn("Could not bring interface down.");
#endif
    }

    /* Execute the ipv6-down script */
    if (ipv6cp_script_state == s_up && ipv6cp_script_pid == 0) {
	ipv6cp_script_state = s_down;
	ipv6cp_script(_PATH_IPV6DOWN);
    }
}


/*
 * ipv6cp_clear_addrs() - clear the interface addresses, routes,
 * proxy neighbour discovery entries, etc.
 */
static void
ipv6cp_clear_addrs(unit, ourid, hisid)
    int unit;
    eui64_t ourid;
    eui64_t hisid;
{
    if (cif6addr(unit, ourid, hisid) != 1)
	warn("Could not clear addresses");
}


/*
 * ipv6cp_finished - possibly shut down the lower layers.
 */
static void
ipv6cp_finished(f)
    fsm *f;
{
    np_finished(f->unit, PPP_IPV6);
}


/*
 * ipv6cp_script_done - called when the ipv6-up or ipv6-down script
 * has finished.
 */
/*ARGSUSED*/
static void
ipv6cp_script_done(arg, status)
    void *arg;
    int status;
{
    ipv6cp_script_pid = 0;
    switch (ipv6cp_script_state) {
    case s_up:
	if (ipv6cp_fsm[0].state != OPENED) {
	    ipv6cp_script_state = s_down;
	    ipv6cp_script(_PATH_IPV6DOWN);
	}
	break;
    case s_down:
	if (ipv6cp_fsm[0].state == OPENED) {
	    ipv6cp_script_state = s_up;
	    ipv6cp_script(_PATH_IPV6UP);
	}
	break;
    }
}


/*
 * ipv6cp_script - Execute a script with arguments
 * interface-name tty-name speed local-LL remote-LL.
 */
static void
ipv6cp_script(script)
    char *script;
{
    char strspeed[32], strlocal[26], strremote[26];
    char *argv[8];

    (void) slprintf(strspeed, sizeof (strspeed), "%d", baud_rate);
    (void) strlcpy(strlocal, llv6_ntoa(ipv6cp_gotoptions[0].ourid),
	sizeof (strlocal));
    (void) strlcpy(strremote, llv6_ntoa(ipv6cp_hisoptions[0].hisid),
	sizeof (strremote));

    argv[0] = script;
    argv[1] = ifname;
    argv[2] = devnam;
    argv[3] = strspeed;
    argv[4] = strlocal;
    argv[5] = strremote;
    argv[6] = ipparam;
    argv[7] = NULL;

    ipv6cp_script_pid = run_program(script, argv, 0, ipv6cp_script_done, NULL);
}

static int
ipv6cp_printpkt(p, plen, printer, arg)
    u_char *p;
    int plen;
    void (*printer) __P((void *, const char *, ...));
    void *arg;
{
    int code, id, len, olen;
    u_char *pstart, *optend;
    u_short cishort;
    eui64_t ifaceid;

    if (plen < HEADERLEN)
	return 0;
    pstart = p;
    GETCHAR(code, p);
    GETCHAR(id, p);
    GETSHORT(len, p);
    if (len < HEADERLEN || len > plen)
	return 0;


    printer(arg, " %s id=0x%x", code_name(code, 1), id);
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
	    case CI_COMPRESSTYPE:
		if (olen >= CILEN_COMPRESS) {
		    p += 2;
		    GETSHORT(cishort, p);
		    printer(arg, "compress 0x%x", cishort);
		}
		break;
	    case CI_IFACEID:
		if (olen == CILEN_IFACEID) {
		    p += 2;
		    eui64_get(ifaceid, p);
		    printer(arg, "addr %s", llv6_ntoa(ifaceid));
		}
		break;
	    }
	    printer(arg, "%8.*B>", optend-p, p);
	    p = optend;
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
    }

    /* print the rest of the bytes in the packet */
    printer(arg, " %32.*B", len, p);

    return p - pstart;
}

/*
 * ipv6_active_pkt - see if this IP packet is worth bringing the link up for.
 * We don't bring the link up for IP fragments or for TCP FIN packets
 * with no data.
 */
#define TCP_HDRLEN	20
#define TH_FIN		0x01

static int
ipv6_active_pkt(pkt, len)
    u_char *pkt;
    int len;
{
    u_char *tcp;
    struct in6_addr addr;
    char fromstr[26];
    char tostr[26];

    len -= PPP_HDRLEN;
    pkt += PPP_HDRLEN;
    if (len < IP6_HDRLEN) {
	dbglog("IPv6 packet of length %d is not activity", len);
	return 0;
    }
    (void) BCOPY(get_ip6src(pkt), &addr, sizeof (addr));
    (void) inet_ntop(AF_INET6, &addr, fromstr, 26);
    (void) BCOPY(get_ip6dst(pkt), &addr, sizeof (addr));
    (void) inet_ntop(AF_INET6, &addr, tostr, 26);
    if (get_ip6nh(pkt) == IPPROTO_FRAGMENT) {
	dbglog("IPv6 fragment from %s->%s is not activity", fromstr, tostr);
	return 0;
    }
    if (get_ip6nh(pkt) != IPPROTO_TCP) {
	info("IPv6 proto %d from %s->%s is activity", get_ip6nh(pkt), fromstr,
	    tostr);
	return 1;
    }
    if (len < IP6_HDRLEN + TCP_HDRLEN) {
	dbglog("Bad TCP length %d<%d+%d %s->%s is not activity", len,
	    IP6_HDRLEN, TCP_HDRLEN, fromstr, tostr);
	return 0;
    }
    tcp = pkt + IP6_HDRLEN;
    if ((get_tcpflags(tcp) & TH_FIN) != 0 &&
	len == IP6_HDRLEN + get_tcpoff(tcp) * 4) {
	dbglog("Empty TCP FIN %s->%s is not activity", fromstr, tostr);
	return 0;
    }
    info("TCP %d data %s%s->%s is activity", len - IP6_HDRLEN - TCP_HDRLEN,
	tcp_flag_decode(get_tcpflags(tcp)), fromstr, tostr);
    return 1;
}
