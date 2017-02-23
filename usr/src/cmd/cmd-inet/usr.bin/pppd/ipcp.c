/*
 * ipcp.c - PPP IP Control Protocol.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#define RCSID	"$Id: ipcp.c,v 1.54 2000/04/15 01:27:11 masputra Exp $"

/*
 * TODO:
 */

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#if defined(_linux_) || defined(__linux__)
#define	__FAVOR_BSD
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "pppd.h"
#include "fsm.h"
#include "ipcp.h"
#include "pathnames.h"

#if !defined(lint) && !defined(_lint)
static const char rcsid[] = RCSID;
#endif

/* global vars */
ipcp_options ipcp_wantoptions[NUM_PPP];	/* Options that we want to request */
ipcp_options ipcp_gotoptions[NUM_PPP];	/* Options that peer ack'd */
ipcp_options ipcp_allowoptions[NUM_PPP]; /* Options we allow peer to request */
ipcp_options ipcp_hisoptions[NUM_PPP];	/* Options that we ack'd */

bool	ipcp_from_hostname = 0;	/* Local IP address is from hostname lookup */

/* Hook for a plugin to know when IP protocol has come up */
void (*ip_up_hook) __P((void)) = NULL;

/* Hook for a plugin to know when IP protocol has come down */
void (*ip_down_hook) __P((void)) = NULL;

/* local vars */
static bool default_route_set[NUM_PPP];	/* Have set up a default route */
static bool proxy_arp_set[NUM_PPP];	/* Have created proxy arp entry */
static bool ipcp_is_up[NUM_PPP];	/* have called np_up() */
static bool proxy_arp_quiet[NUM_PPP];	/* We should be quiet on error */
static bool disable_defaultip = 0;	/* Don't use hostname for IP addr */

/*
 * Callbacks for fsm code.  (CI = Configuration Information)
 */
static void ipcp_resetci __P((fsm *));	/* Reset our CI */
static int  ipcp_cilen __P((fsm *));	        /* Return length of our CI */
static void ipcp_addci __P((fsm *, u_char *, int *)); /* Add our CI */
static int  ipcp_ackci __P((fsm *, u_char *, int));	/* Peer ack'd our CI */
static int  ipcp_nakci __P((fsm *, u_char *, int));	/* Peer nak'd our CI */
static int  ipcp_rejci __P((fsm *, u_char *, int));	/* Peer rej'd our CI */
static int  ipcp_reqci __P((fsm *, u_char *, int *, int)); /* Rcv CI */
static void ipcp_up __P((fsm *));		/* We're UP */
static void ipcp_down __P((fsm *));		/* We're DOWN */
static void ipcp_finished __P((fsm *));	/* Don't need lower layer */
static int  setmsservaddr __P((char *, u_int32_t *));

fsm ipcp_fsm[NUM_PPP];		/* IPCP fsm structure */

static fsm_callbacks ipcp_callbacks = { /* IPCP callback routines */
    ipcp_resetci,		/* Reset our Configuration Information */
    ipcp_cilen,			/* Length of our Configuration Information */
    ipcp_addci,			/* Add our Configuration Information */
    ipcp_ackci,			/* ACK our Configuration Information */
    ipcp_nakci,			/* NAK our Configuration Information */
    ipcp_rejci,			/* Reject our Configuration Information */
    ipcp_reqci,			/* Request peer's Configuration Information */
    ipcp_up,			/* Called when fsm reaches OPENED state */
    ipcp_down,			/* Called when fsm leaves OPENED state */
    NULL,			/* Called when we want the lower layer up */
    ipcp_finished,		/* Called when we want the lower layer down */
    NULL,			/* Retransmission is necessary */
    NULL,			/* Called to handle protocol-specific codes */
    "IPCP",			/* String name of protocol */
    NULL			/* Peer rejected a code number */
};

/*
 * Command-line options.
 */
static int setvjslots __P((char **));
static int setdnsaddr __P((char **));
static int setwinsaddr __P((char **));
static int autoproxyarp __P((char **));

static option_t ipcp_option_list[] = {
    { "noip", o_bool, &ipcp_protent.enabled_flag,
      "Disable IP and IPCP" },
    { "-ip", o_bool, &ipcp_protent.enabled_flag,
      "Disable IP and IPCP" },
    { "novj", o_bool, &ipcp_wantoptions[0].neg_vj,
      "Disable VJ compression", OPT_A2COPY, &ipcp_allowoptions[0].neg_vj },
    { "-vj", o_bool, &ipcp_wantoptions[0].neg_vj,
      "Disable VJ compression", OPT_A2COPY, &ipcp_allowoptions[0].neg_vj },
    { "novjccomp", o_bool, &ipcp_wantoptions[0].cflag,
      "Disable VJ connection-ID compression", OPT_A2COPY,
      &ipcp_allowoptions[0].cflag },
    { "-vjccomp", o_bool, &ipcp_wantoptions[0].cflag,
      "Disable VJ connection-ID compression", OPT_A2COPY,
      &ipcp_allowoptions[0].cflag },
    { "vj-max-slots", o_special, (void *)setvjslots,
      "Set maximum VJ header slots" },
    { "ipcp-accept-local", o_bool, &ipcp_wantoptions[0].accept_local,
      "Accept peer's address for us", 1 },
    { "ipcp-accept-remote", o_bool, &ipcp_wantoptions[0].accept_remote,
      "Accept peer's address for it", 1 },
    { "ipparam", o_string, &ipparam,
      "Set ip script parameter" },
    { "noipdefault", o_bool, &disable_defaultip,
      "Don't use name for default IP adrs", 1 },
    { "ms-dns", o_special, (void *)setdnsaddr,
      "DNS address for the peer's use" },
    { "ms-wins", o_special, (void *)setwinsaddr,
      "Nameserver for SMB over TCP/IP for peer" },
    { "ipcp-restart", o_int, &ipcp_fsm[0].timeouttime,
      "Set timeout for IPCP" },
    { "ipcp-max-terminate", o_int, &ipcp_fsm[0].maxtermtransmits,
      "Set max #xmits for term-reqs" },
    { "ipcp-max-configure", o_int, &ipcp_fsm[0].maxconfreqtransmits,
      "Set max #xmits for conf-reqs" },
    { "ipcp-max-failure", o_int, &ipcp_fsm[0].maxnakloops,
      "Set max #conf-naks for IPCP" },
    { "defaultroute", o_bool, &ipcp_wantoptions[0].default_route,
      "Add default route", OPT_ENABLE|1, &ipcp_allowoptions[0].default_route },
    { "nodefaultroute", o_bool, &ipcp_allowoptions[0].default_route,
      "disable defaultroute option", OPT_A2COPY,
      &ipcp_wantoptions[0].default_route },
    { "-defaultroute", o_bool, &ipcp_allowoptions[0].default_route,
      "disable defaultroute option", OPT_A2COPY,
      &ipcp_wantoptions[0].default_route },
    { "proxyarp", o_bool, &ipcp_wantoptions[0].proxy_arp,
      "Add proxy ARP entry", OPT_ENABLE|1, &ipcp_allowoptions[0].proxy_arp },
    { "autoproxyarp", o_special_noarg, (void *)autoproxyarp,
      "Add proxy ARP entry if needed", OPT_ENABLE,
      &ipcp_allowoptions[0].proxy_arp },
    { "noproxyarp", o_bool, &ipcp_allowoptions[0].proxy_arp,
      "disable proxyarp option", OPT_A2COPY, &ipcp_wantoptions[0].proxy_arp },
    { "-proxyarp", o_bool, &ipcp_allowoptions[0].proxy_arp,
      "disable proxyarp option", OPT_A2COPY, &ipcp_wantoptions[0].proxy_arp },
    { "usepeerdns", o_bool, &ipcp_wantoptions[0].req_dns1,
      "Ask peer for DNS address(es)", OPT_A2COPY|1,
      &ipcp_wantoptions[0].req_dns2 },
    { NULL }
};

/*
 * Protocol entry points from main code.
 */
static void ipcp_init __P((int));
static void ipcp_open __P((int));
static void ipcp_close __P((int, char *));
static void ipcp_lowerup __P((int));
static void ipcp_lowerdown __P((int));
static void ipcp_input __P((int, u_char *, int));
static void ipcp_protrej __P((int));
static int  ipcp_printpkt __P((u_char *, int,
    void (*) __P((void *, const char *, ...)), void *));
static void ip_check_options __P((void));
static int  ip_demand_conf __P((int));
static int  ip_active_pkt __P((u_char *, int));
static void ipcp_print_stat __P((int, FILE *));

static void create_resolv __P((u_int32_t, u_int32_t));

struct protent ipcp_protent = {
    PPP_IPCP,
    ipcp_init,
    ipcp_input,
    ipcp_protrej,
    ipcp_lowerup,
    ipcp_lowerdown,
    ipcp_open,
    ipcp_close,
    ipcp_printpkt,
    NULL,
    1,
    "IPCP",
    "IP",
    ipcp_option_list,
    ip_check_options,
    ip_demand_conf,
    ip_active_pkt,
    ipcp_print_stat
};

static void ipcp_clear_addrs __P((int, u_int32_t, u_int32_t));
static void ipcp_script __P((char *));		/* Run an up/down script */
static void ipcp_script_done __P((void *, int));

/*
 * Lengths of configuration options.
 */
#define CILEN_VOID	2
#define CILEN_COMPRESS	4	/* min length for compression protocol opt. */
#define CILEN_VJ	6	/* length for RFC1332 Van-Jacobson opt. */
#define CILEN_ADDR	6	/* new-style single address option */
#define CILEN_ADDRS	10	/* old-style dual address option */


/*
 * This state variable is used to ensure that we don't
 * run an ipcp-up/down script while one is already running.
 */
static enum script_state {
    s_down,
    s_up
} ipcp_script_state;
static pid_t ipcp_script_pid;

/*
 * Make a string representation of a network IP address.
 */
char *
ip_ntoa(ipaddr)
u_int32_t ipaddr;
{
    static char b[64];

    (void) slprintf(b, sizeof(b), "%I", ipaddr);
    return b;
}

/*
 * Option parsing.
 */

/*
 * setvjslots - set maximum number of connection slots for VJ compression
 */
static int
setvjslots(argv)
    char **argv;
{
    int value;

    if (!int_option(*argv, &value))
	return 0;
    if (value < 2 || value > 16) {
	option_error("vj-max-slots value must be between 2 and 16");
	return 0;
    }
    ipcp_wantoptions [0].maxslotindex =
        ipcp_allowoptions[0].maxslotindex = value - 1;
    return 1;
}

/*
 * setmsservaddr - Set the primary and secondary server addresses in the
 * array.  setdnsaddr() and setwinsaddr() call this function with either
 * dnsaddr[] or winsaddr[] as the serverarray argument.
 */
static int
setmsservaddr(servname, serverarray)
    char *servname;
    u_int32_t *serverarray;
{
    u_int32_t addr;
    struct hostent *hp = NULL;

    addr = inet_addr(servname);
    if (addr == (u_int32_t) -1) {
	if ((hp = gethostbyname(servname)) == NULL)
	    return 0;
	BCOPY(hp->h_addr, &addr, sizeof (u_int32_t));
    }

    /*
     * If there is no primary then this is the first instance of the
     * option, we must set the primary.  In that case, try to set the
     * secondary to h_addr_list[1].  If the primary is already set, then
     * this is the second instance of the option, and we must set
     * the secondary.
     */
    if (serverarray[0] == 0) {
	serverarray[0] = addr;
	if (hp != NULL && hp->h_addr_list[1] != NULL)
	    BCOPY(hp->h_addr_list[1], &serverarray[1], sizeof (u_int32_t));
	else
	    serverarray[1] = addr;
    } else {
	serverarray[1] = addr;
    }

    return (1);
}

/*
 * setdnsaddr - set the dns address(es)
 */
static int
setdnsaddr(argv)
    char **argv;
{
    if (setmsservaddr(*argv, &(ipcp_allowoptions[0].dnsaddr[0])) == 0) {
	option_error("invalid address parameter '%s' for ms-dns option", *argv);
	return (0);
    }

    return (1);
}

/*
 * setwinsaddr - set the wins address(es)
 * This is primrarly used with the Samba package under UNIX or for pointing
 * the caller to the existing WINS server on a Windows NT platform.
 */
static int
setwinsaddr(argv)
    char **argv;
{
    if (setmsservaddr(*argv, &(ipcp_allowoptions[0].winsaddr[0])) == 0) {
	option_error("invalid address parameter '%s' for ms-wins option",
	    *argv);
	return (0);
    }

    return (1);
}

/*
 * autoproxyarp -- enable proxy ARP but don't emit error messages if
 * it's not actually needed.
 */
/*ARGSUSED*/
static int
autoproxyarp(argv)
    char **argv;
{
    ipcp_wantoptions[0].proxy_arp = 1;
    proxy_arp_quiet[0] = 1;

    return (1);
}


/*
 * ipcp_init - Initialize IPCP.
 */
static void
ipcp_init(unit)
    int unit;
{
    fsm *f = &ipcp_fsm[unit];
    ipcp_options *wo = &ipcp_wantoptions[unit];
    ipcp_options *ao = &ipcp_allowoptions[unit];

    f->unit = unit;
    f->protocol = PPP_IPCP;
    f->callbacks = &ipcp_callbacks;
    fsm_init(&ipcp_fsm[unit]);

    BZERO(wo, sizeof(*wo));
    BZERO(ao, sizeof(*ao));

    wo->neg_addr = wo->old_addrs = 1;
    wo->neg_vj = 1;
    wo->vj_protocol = IPCP_VJ_COMP;
    wo->maxslotindex = MAX_STATES - 1; /* really max index */
    wo->cflag = 1;

    ao->neg_addr = ao->old_addrs = 1;
    ao->neg_vj = 1;
    ao->maxslotindex = MAX_STATES - 1;
    ao->cflag = 1;

    /*
     * These aren't actually negotiated.  Instead, they control
     * whether the user may use the proxyarp and defaultroute options.
     */
    ao->proxy_arp = 1;
    ao->default_route = 1;
    proxy_arp_quiet[unit] = 0;
}


/*
 * ipcp_open - IPCP is allowed to come up.
 */
static void
ipcp_open(unit)
    int unit;
{
    fsm_open(&ipcp_fsm[unit]);
}


/*
 * ipcp_close - Take IPCP down.
 */
static void
ipcp_close(unit, reason)
    int unit;
    char *reason;
{
    fsm_close(&ipcp_fsm[unit], reason);
}


/*
 * ipcp_lowerup - The lower layer is up.
 */
static void
ipcp_lowerup(unit)
    int unit;
{
    fsm_lowerup(&ipcp_fsm[unit]);
}


/*
 * ipcp_lowerdown - The lower layer is down.
 */
static void
ipcp_lowerdown(unit)
    int unit;
{
    fsm_lowerdown(&ipcp_fsm[unit]);
}


/*
 * ipcp_input - Input IPCP packet.
 */
static void
ipcp_input(unit, p, len)
    int unit;
    u_char *p;
    int len;
{
    fsm_input(&ipcp_fsm[unit], p, len);
}


/*
 * ipcp_protrej - A Protocol-Reject was received for IPCP.
 */
static void
ipcp_protrej(unit)
    int unit;
{
    fsm_protreject(&ipcp_fsm[unit]);
}


/*
 * ipcp_resetci - Reset our CI.
 * Called by fsm_sconfreq, Send Configure Request.
 */
static void
ipcp_resetci(f)
    fsm *f;
{
    ipcp_options *wo = &ipcp_wantoptions[f->unit];
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    ipcp_options *ao = &ipcp_allowoptions[f->unit];

    wo->req_addr = (wo->neg_addr || wo->old_addrs) &&
	(ao->neg_addr || ao->old_addrs);
    if (wo->ouraddr == 0 || disable_defaultip)
	wo->accept_local = 1;
    if (wo->hisaddr == 0)
	wo->accept_remote = 1;
    *go = *wo;
    if (disable_defaultip)
	go->ouraddr = 0;
}


/*
 * ipcp_cilen - Return length of our CI.
 * Called by fsm_sconfreq, Send Configure Request.
 */
static int
ipcp_cilen(f)
    fsm *f;
{
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    ipcp_options *wo = &ipcp_wantoptions[f->unit];
    ipcp_options *ho = &ipcp_hisoptions[f->unit];

#define LENCIADDRS(neg)		(neg ? CILEN_ADDRS : 0)
#define LENCIVJ(neg, old)	(neg ? (old? CILEN_COMPRESS : CILEN_VJ) : 0)
#define LENCIADDR(neg)		(neg ? (CILEN_ADDR) : 0)

    /*
     * First see if we want to change our options to the old
     * forms because we have received old forms from the peer.
     */
    if (go->neg_addr && go->old_addrs && !ho->neg_addr && ho->old_addrs)
	/* use the old style of address negotiation */
	go->neg_addr = 0;
    if (wo->neg_vj && !go->neg_vj && !go->old_vj) {
	/* try an older style of VJ negotiation */
	/* use the old style only if the peer did */
	if (ho->neg_vj && ho->old_vj) {
	    go->neg_vj = 1;
	    go->old_vj = 1;
	    go->vj_protocol = ho->vj_protocol;
	}
    }

    return (LENCIADDRS(!go->neg_addr && go->old_addrs) +
	    LENCIVJ(go->neg_vj, go->old_vj) +
	    LENCIADDR(go->neg_addr) +
	    LENCIADDR(go->req_dns1) +
	    LENCIADDR(go->req_dns2)) ;
}


/*
 * ipcp_addci - Add our desired CIs to a packet.
 * Called by fsm_sconfreq, Send Configure Request.
 */
static void
ipcp_addci(f, ucp, lenp)
    fsm *f;
    u_char *ucp;
    int *lenp;
{
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    int len = *lenp;

#define ADDCIADDRS(opt, neg, val1, val2) \
    if (neg) { \
	if (len >= CILEN_ADDRS) { \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(CILEN_ADDRS, ucp); \
	    PUTNLONG(val1, ucp); \
	    PUTNLONG(val2, ucp); \
	    len -= CILEN_ADDRS; \
	} else \
	    go->old_addrs = 0; \
    }

#define ADDCIVJ(opt, neg, val, old, maxslotindex, cflag) \
    if (neg) { \
	int vjlen = old? CILEN_COMPRESS : CILEN_VJ; \
	if (len >= vjlen) { \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(vjlen, ucp); \
	    PUTSHORT(val, ucp); \
	    if (!old) { \
		PUTCHAR(maxslotindex, ucp); \
		PUTCHAR(cflag, ucp); \
	    } \
	    len -= vjlen; \
	} else \
	    neg = 0; \
    }

#define ADDCIADDR(opt, neg, val) \
    if (neg) { \
	if (len >= CILEN_ADDR) { \
	    PUTCHAR(opt, ucp); \
	    PUTCHAR(CILEN_ADDR, ucp); \
	    PUTNLONG(val, ucp); \
	    len -= CILEN_ADDR; \
	} else \
	    neg = 0; \
    }

    ADDCIADDRS(CI_ADDRS, !go->neg_addr && go->old_addrs, go->ouraddr,
	       go->hisaddr);

    ADDCIVJ(CI_COMPRESSTYPE, go->neg_vj, go->vj_protocol, go->old_vj,
	    go->maxslotindex, go->cflag);

    ADDCIADDR(CI_ADDR, go->neg_addr, go->ouraddr);

    ADDCIADDR(CI_MS_DNS1, go->req_dns1, go->dnsaddr[0]);

    ADDCIADDR(CI_MS_DNS2, go->req_dns2, go->dnsaddr[1]);

    *lenp -= len;
}


/*
 * ipcp_ackci - Ack our CIs.
 * Called by fsm_rconfack, Receive Configure ACK.
 *
 * Returns:
 *	0 - Ack was bad.
 *	1 - Ack was good.
 */
static int
ipcp_ackci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    u_short cilen, citype, cishort;
    u_int32_t cilong;
    u_char cimaxslotindex, cicflag;

    /*
     * CIs must be in exactly the same order that we sent...
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */

#define	ACKCHECK(opt, olen) \
	if ((len -= olen) < 0) \
	    goto bad; \
	GETCHAR(citype, p); \
	GETCHAR(cilen, p); \
	if (cilen != olen || \
	    citype != opt) \
	    goto bad;

#define ACKCIADDRS(opt, neg, val1, val2) \
    if (neg) { \
	ACKCHECK(opt, CILEN_ADDRS) \
	GETNLONG(cilong, p); \
	if (val1 != cilong) \
	    goto bad; \
	GETNLONG(cilong, p); \
	if (val2 != cilong) \
	    goto bad; \
    }

#define ACKCIVJ(opt, neg, val, old, maxslotindex, cflag) \
    if (neg) { \
	int vjlen = old? CILEN_COMPRESS : CILEN_VJ; \
	ACKCHECK(opt, vjlen) \
	GETSHORT(cishort, p); \
	if (cishort != val) \
	    goto bad; \
	if (!old) { \
	    GETCHAR(cimaxslotindex, p); \
	    if (cimaxslotindex != maxslotindex) \
		goto bad; \
	    GETCHAR(cicflag, p); \
	    if (cicflag != cflag) \
		goto bad; \
	} \
    }

#define ACKCIADDR(opt, neg, val) \
    if (neg) { \
	ACKCHECK(opt, CILEN_ADDR) \
	GETNLONG(cilong, p); \
	if (val != cilong) \
	    goto bad; \
    }

    ACKCIADDRS(CI_ADDRS, !go->neg_addr && go->old_addrs, go->ouraddr,
	       go->hisaddr);

    ACKCIVJ(CI_COMPRESSTYPE, go->neg_vj, go->vj_protocol, go->old_vj,
	    go->maxslotindex, go->cflag);

    ACKCIADDR(CI_ADDR, go->neg_addr, go->ouraddr);

    ACKCIADDR(CI_MS_DNS1, go->req_dns1, go->dnsaddr[0]);

    ACKCIADDR(CI_MS_DNS2, go->req_dns2, go->dnsaddr[1]);

    /*
     * If there are any remaining CIs, then this packet is bad.
     */
    if (len != 0)
	goto bad;
    return (1);

bad:
    IPCPDEBUG(("ipcp_ackci: received bad Ack!"));
    return (0);
}

/*
 * ipcp_nakci - Peer has sent a NAK for some of our CIs.
 * This should not modify any state if the Nak is bad
 * or if IPCP is in the OPENED state.
 * Calback from fsm_rconfnakrej - Receive Configure-Nak or Configure-Reject.
 *
 * Returns:
 *	0 - Nak was bad.
 *	1 - Nak was good.
 */
static int
ipcp_nakci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    u_char cimaxslotindex, cicflag;
    u_char citype, cilen, *next;
    u_short cishort;
    u_int32_t ciaddr1, ciaddr2;
    ipcp_options no;		/* options we've seen Naks for */
    ipcp_options try;		/* options to request next time */

    BZERO(&no, sizeof(no));
    try = *go;

    /*
     * Any Nak'd CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define NAKCIADDRS(opt, neg, code) \
    if ((neg) && \
	(cilen = p[1]) == CILEN_ADDRS && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETNLONG(ciaddr1, p); \
	GETNLONG(ciaddr2, p); \
	no.old_addrs = 1; \
	code \
    }

#define NAKCIVJ(opt, neg, code) \
    if (go->neg && \
	((cilen = p[1]) == CILEN_COMPRESS || cilen == CILEN_VJ) && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	no.neg = 1; \
        code \
    }

#define NAKCIADDR(opt, neg, code) \
    if (go->neg && \
	(cilen = p[1]) == CILEN_ADDR && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETNLONG(ciaddr1, p); \
	no.neg = 1; \
	code \
    }

    /*
     * Accept the peer's idea of {our,its} address, if different
     * from our idea, only if the accept_{local,remote} flag is set.
     */
    NAKCIADDRS(CI_ADDRS, !go->neg_addr && go->old_addrs,
	      if (go->accept_local && ciaddr1) { /* Do we know our address? */
		  try.ouraddr = ciaddr1;
	      }
	      if (go->accept_remote && ciaddr2) { /* Does it know its? */
		  try.hisaddr = ciaddr2;
	      }
	      );

    /*
     * Accept the peer's value of maxslotindex provided that it
     * is less than what we asked for.  Turn off slot-ID compression
     * if the peer wants.  Send old-style compress-type option if
     * the peer wants.
     */
    NAKCIVJ(CI_COMPRESSTYPE, neg_vj,
	    if (cilen == CILEN_VJ) {
		GETCHAR(cimaxslotindex, p);
		GETCHAR(cicflag, p);
		if (cishort == IPCP_VJ_COMP) {
		    try.old_vj = 0;
		    if (cimaxslotindex < go->maxslotindex)
			try.maxslotindex = cimaxslotindex;
		    if (!cicflag)
			try.cflag = 0;
		} else {
		    try.neg_vj = 0;
		}
	    } else {
		if (cishort == IPCP_VJ_COMP || cishort == IPCP_VJ_COMP_OLD) {
		    try.old_vj = 1;
		    try.vj_protocol = cishort;
		} else {
		    try.neg_vj = 0;
		}
	    }
	    );

    NAKCIADDR(CI_ADDR, neg_addr,
	      if (go->accept_local && ciaddr1) { /* Do we know our address? */
		  try.ouraddr = ciaddr1;
	      }
	      );

    NAKCIADDR(CI_MS_DNS1, req_dns1,
	      try.dnsaddr[0] = ciaddr1;
	      );

    NAKCIADDR(CI_MS_DNS2, req_dns2,
	      try.dnsaddr[1] = ciaddr1;
	      );

    /*
     * There may be remaining CIs, if the peer is requesting negotiation
     * on an option that we didn't include in our request packet.
     * If they want to negotiate about IP addresses, we comply.
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
		(cilen != CILEN_VJ && cilen != CILEN_COMPRESS))
		goto bad;
	    no.neg_vj = 1;
	    break;
	case CI_ADDRS:
	    if ((!go->neg_addr && go->old_addrs) || no.old_addrs
		|| cilen != CILEN_ADDRS)
		goto bad;
	    try.neg_addr = 1;
	    try.old_addrs = 1;
	    GETNLONG(ciaddr1, p);
	    if (ciaddr1 && go->accept_local)
		try.ouraddr = ciaddr1;
	    GETNLONG(ciaddr2, p);
	    if (ciaddr2 && go->accept_remote)
		try.hisaddr = ciaddr2;
	    no.old_addrs = 1;
	    break;
	case CI_ADDR:
	    if (go->neg_addr || no.neg_addr || cilen != CILEN_ADDR)
		goto bad;
	    try.old_addrs = 0;
	    GETNLONG(ciaddr1, p);
	    if (ciaddr1 && go->accept_local)
		try.ouraddr = ciaddr1;
	    if (try.ouraddr != 0)
		try.neg_addr = 1;
	    no.neg_addr = 1;
	    break;
	}
	p = next;
    }

    /*
     * OK, the Nak is good.  Now we can update state.
     * If there are any remaining options, we ignore them.
     */
    if (f->state != OPENED)
	*go = try;

    return 1;

bad:
    IPCPDEBUG(("ipcp_nakci: received bad Nak!"));
    return 0;
}


/*
 * ipcp_rejci - Reject some of our CIs.
 * Callback from fsm_rconfnakrej.
 */
static int
ipcp_rejci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    u_char cimaxslotindex, ciflag, cilen;
    u_short cishort;
    u_int32_t cilong;
    ipcp_options try;		/* options to request next time */

    try = *go;
    /*
     * Any Rejected CIs must be in exactly the same order that we sent.
     * Check packet length and CI length at each step.
     * If we find any deviations, then this packet is bad.
     */
#define REJCIADDRS(opt, neg, val1, val2) \
    if ((neg) && \
	(cilen = p[1]) == CILEN_ADDRS && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETNLONG(cilong, p); \
	/* Check rejected value. */ \
	if (cilong != val1) \
	    goto bad; \
	GETNLONG(cilong, p); \
	/* Check rejected value. */ \
	if (cilong != val2) \
	    goto bad; \
	try.old_addrs = 0; \
    }

#define REJCIVJ(opt, neg, val, old, maxslot, cflag) \
    if (go->neg && \
	p[1] == (old? CILEN_COMPRESS : CILEN_VJ) && \
	len >= p[1] && \
	p[0] == opt) { \
	len -= p[1]; \
	INCPTR(2, p); \
	GETSHORT(cishort, p); \
	/* Check rejected value. */  \
	if (cishort != val) \
	    goto bad; \
	if (!old) { \
	   GETCHAR(cimaxslotindex, p); \
	   if (cimaxslotindex != maxslot) \
	     goto bad; \
	   GETCHAR(ciflag, p); \
	   if (ciflag != cflag) \
	     goto bad; \
        } \
	try.neg = 0; \
     }

#define REJCIADDR(opt, neg, addr) \
    if (go->neg && \
	((cilen = p[1]) == CILEN_ADDR) && \
	len >= cilen && \
	p[0] == opt) { \
	len -= cilen; \
	INCPTR(2, p); \
	GETNLONG(cilong, p); \
	/* Check rejected value. */ \
	if (cilong != addr) \
	    goto bad; \
	try.neg = 0; \
    }

    REJCIADDRS(CI_ADDRS, !go->neg_addr && go->old_addrs,
	       go->ouraddr, go->hisaddr);

    REJCIVJ(CI_COMPRESSTYPE, neg_vj, go->vj_protocol, go->old_vj,
	    go->maxslotindex, go->cflag);

    REJCIADDR(CI_ADDR, neg_addr, go->ouraddr);

    REJCIADDR(CI_MS_DNS1, req_dns1, go->dnsaddr[0]);

    REJCIADDR(CI_MS_DNS2, req_dns2, go->dnsaddr[1]);

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
    IPCPDEBUG(("ipcp_rejci: received bad Reject!"));
    return 0;
}


/*
 * ipcp_reqci - Check the peer's requested CIs and send appropriate response.
 * Callback from fsm_rconfreq, Receive Configure Request
 *
 * Returns: CODE_CONFACK, CODE_CONFNAK or CODE_CONFREJ and input
 * packet modified appropriately.  If reject_if_disagree is non-zero,
 * doesn't return CODE_CONFNAK; returns CODE_CONFREJ if it can't
 * return CODE_CONFACK.
 */
static int
ipcp_reqci(f, p, lenp, dont_nak)
    fsm *f;
    u_char *p;		/* Requested CIs */
    int *lenp;			/* Length of requested CIs */
    bool dont_nak;
{
    ipcp_options *wo = &ipcp_wantoptions[f->unit];
    ipcp_options *ho = &ipcp_hisoptions[f->unit];
    ipcp_options *ao = &ipcp_allowoptions[f->unit];
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    int ret, newret;
    u_char *p0, *nakp, *rejp, *prev;
    u_short cishort;
    int len, cilen, type;
    u_int32_t tl, ciaddr1, ciaddr2;	/* Parsed address values */
    u_char maxslotindex, cflag;
    int d;

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
	if ((len < 2) || p[1] > len) {
	    /*
	     * RFC 1661 page 40 -- if the option extends beyond the
	     * packet, then discard the entire packet.
	     */
	    return (0);
	}

	newret = CODE_CONFACK;
	prev = p;
	GETCHAR(type, p);
	GETCHAR(cilen, p);

	switch (type) {		/* Check CI type */
	case CI_ADDRS:
	    if (!ao->old_addrs || ho->neg_addr) {
		newret = CODE_CONFREJ;
		break;
	    }

	    if (cilen != CILEN_ADDRS) {
		/*
		 * rfc1661, page 40 -- a recongnized option with an
		 * invalid length should be Nak'ed.
		 */
		newret = CODE_CONFNAK;
		ciaddr1 = wo->hisaddr;
		ciaddr2 = wo->ouraddr;
	    } else {

		/*
		 * If it has no address, or if we both have its
		 * address but disagree about it, then NAK it with our
		 * idea. In particular, if we don't know its address,
		 * but it does, then accept it.
		 */
		GETNLONG(ciaddr1, p);
		if (ciaddr1 != wo->hisaddr &&
		    (ciaddr1 == 0 || !wo->accept_remote)) {
		    newret = CODE_CONFNAK;
		    ciaddr1 = wo->hisaddr;
		} else if (ciaddr1 == 0 && wo->hisaddr == 0) {
		    /*
		     * If neither we nor he knows his address, reject
		     * the option.
		     */
		    newret = CODE_CONFREJ;
		    wo->req_addr = 0;	/* don't NAK with 0.0.0.0 later */
		    break;
		} else if (ciaddr1 != 0) {
		    go->hisaddr = ciaddr1;
		}

		/*
		 * If he doesn't know our address, or if we both have
		 * our address * but disagree about it, then NAK it
		 * with our idea.
		 */
		GETNLONG(ciaddr2, p);
		if (ciaddr2 != wo->ouraddr) {
		    if (ciaddr2 == 0 || !wo->accept_local) {
			newret = CODE_CONFNAK;
			ciaddr2 = wo->ouraddr;
		    } else {
			go->ouraddr = ciaddr2;	/* accept peer's idea */
		    }
		}
	    }

	    if (newret == CODE_CONFNAK) {
		PUTCHAR(type, nakp);
		PUTCHAR(CILEN_ADDRS, nakp);
		PUTNLONG(ciaddr1, nakp);
		PUTNLONG(ciaddr2, nakp);
	    }

	    ho->old_addrs = 1;
	    ho->hisaddr = ciaddr1;
	    ho->ouraddr = ciaddr2;
	    break;

	case CI_ADDR:
	    if (!ao->neg_addr || ho->old_addrs) {
		newret = CODE_CONFREJ;
		break;
	    }

	    if (cilen != CILEN_ADDR) {
		/*
		 * rfc1661, page 40 -- a recongnized option with an
		 * invalid length should be Nak'ed.
		 */
		newret = CODE_CONFNAK;
		ciaddr1 = wo->hisaddr;
	    } else {

		/*
		 * If he has no address, or if we both have his
		 * address but disagree about it, then NAK it with our
		 * idea.  In particular, if we don't know his address,
		 * but he does, then accept it.
		 */
		GETNLONG(ciaddr1, p);
		if (ciaddr1 != wo->hisaddr &&
		    (ciaddr1 == 0 || !wo->accept_remote)) {
		    newret = CODE_CONFNAK;
		    ciaddr1 = wo->hisaddr;
		} else if (ciaddr1 == 0 && wo->hisaddr == 0 &&
		    wo->default_route != 0) {
		    newret = CODE_CONFNAK;
		    /*
		     * If this is a dialup line (default_route is
		     * set), and neither side knows about its address,
		     * suggest an arbitrary rfc1918 address.
		     */
		    ciaddr1 = htonl(0xc0a80101 + ifunit);
		    dbglog("Peer address unknown; suggesting %I", ciaddr1);
		} else if (ciaddr1 == 0 && wo->hisaddr == 0) {
		    /*
		     * If this is not a dialup line, don't ACK an
		     * address of 0.0.0.0 - reject it instead.
		     */
		    newret = CODE_CONFREJ;
		    wo->req_addr = 0;	/* don't NAK with 0.0.0.0 later */
		    break;
		}
	    }

	    if (newret == CODE_CONFNAK) {
		PUTCHAR(type, nakp);
		PUTCHAR(CILEN_ADDR, nakp);
		PUTNLONG(ciaddr1, nakp);
	    }

	    ho->neg_addr = 1;
	    ho->hisaddr = ciaddr1;
	    break;

	case CI_MS_DNS1:
	case CI_MS_DNS2:
	    /* Warning -- these options work backwards. */
	    /* Microsoft primary or secondary DNS request */
	    d = (type == CI_MS_DNS2 ? 1 : 0);

	    if (ao->dnsaddr[d] == 0) {
		newret = CODE_CONFREJ;
		break;
	    }

	    if (cilen != CILEN_ADDR) {
		newret = CODE_CONFNAK;
	    } else {
		GETNLONG(tl, p);
		if (tl != ao->dnsaddr[d]) {
		    newret = CODE_CONFNAK;
		}
	    }

	    if (newret == CODE_CONFNAK) {
		PUTCHAR(type, nakp);
		PUTCHAR(CILEN_ADDR, nakp);
		PUTNLONG(ao->dnsaddr[d], nakp);
	    }
            break;

	case CI_MS_WINS1:
	case CI_MS_WINS2:
	    /* Warning -- these options work backwards. */
	    /* Microsoft primary or secondary WINS request */
	    d = (type == CI_MS_WINS2 ? 1 : 0);

	    if (ao->winsaddr[d] == 0) {
		newret = CODE_CONFREJ;
		break;
	    }

	    if (cilen != CILEN_ADDR) {
		newret = CODE_CONFNAK;
	    } else {
		GETNLONG(tl, p);
		if (tl != ao->winsaddr[d]) {
		    newret = CODE_CONFNAK;
		}
	    }

	    if (newret == CODE_CONFNAK) {
		PUTCHAR(type, nakp);
		PUTCHAR(CILEN_ADDR, nakp);
		PUTNLONG(ao->winsaddr[d], nakp);
	    }
            break;

	case CI_COMPRESSTYPE:
	    if (!ao->neg_vj) {
		newret = CODE_CONFREJ;
		break;
	    }

	    maxslotindex = ao->maxslotindex;
	    cflag = ao->cflag;
	    if (cilen != CILEN_VJ && cilen != CILEN_COMPRESS) {
		newret = CODE_CONFNAK;
		cishort = IPCP_VJ_COMP;
	    } else {
		GETSHORT(cishort, p);
		if (cishort != IPCP_VJ_COMP &&
		    (cishort != IPCP_VJ_COMP_OLD || cilen != CILEN_COMPRESS)) {
		    newret = CODE_CONFNAK;
		    cishort = IPCP_VJ_COMP;
		} else if (cilen == CILEN_VJ) {
		    GETCHAR(maxslotindex, p);
		    if (maxslotindex > ao->maxslotindex) {
			newret = CODE_CONFNAK;
			maxslotindex = ao->maxslotindex;
		    }
		    GETCHAR(cflag, p);
		    if (cflag != 0 && ao->cflag == 0) {
			newret = CODE_CONFNAK;
			cflag = 0;
		    }
		} else {
		    ho->old_vj = 1;
		    maxslotindex = MAX_STATES - 1;
		    cflag = 1;
		}
	    }

	    if (newret == CODE_CONFNAK) {
		PUTCHAR(type, nakp);
		if (cishort == IPCP_VJ_COMP) {
		    PUTCHAR(CILEN_VJ, nakp);
		    PUTSHORT(cishort, nakp);
		    PUTCHAR(maxslotindex, nakp);
		    PUTCHAR(cflag, nakp);
		} else {
		    PUTCHAR(CILEN_COMPRESS, nakp);
		    PUTSHORT(cishort, nakp);
		}
	    }
	    ho->neg_vj = 1;
	    ho->vj_protocol = cishort;
	    ho->maxslotindex = maxslotindex;
	    ho->cflag = cflag;
	    break;

	default:
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
		BCOPY(prev, rejp, cilen);
	    rejp += cilen;
	}
    }

    /*
     * If we aren't rejecting this packet, and we want to negotiate
     * their address, and they didn't send their address, then we
     * send a NAK with a CI_ADDR option appended.  We assume the
     * input buffer is long enough that we can append the extra
     * option safely.
     */
    if (ret != CODE_CONFREJ && !ho->neg_addr && !ho->old_addrs &&
	wo->req_addr && !dont_nak) {
	if (ret == CODE_CONFACK)
	    wo->req_addr = 0;		/* don't ask again */
	ret = CODE_CONFNAK;
	PUTCHAR(CI_ADDR, nakp);
	PUTCHAR(CILEN_ADDR, nakp);
	PUTNLONG(wo->hisaddr, nakp);
    }

    switch (ret) {
    case CODE_CONFACK:
	*lenp = p - p0;
	sys_block_proto(PPP_IP);
	break;
    case CODE_CONFNAK:
	*lenp = nakp - nak_buffer;
	BCOPY(nak_buffer, p0, *lenp);
	break;
    case CODE_CONFREJ:
	*lenp = rejp - p0;
	break;
    }

    return (ret);			/* Return final code */
}


/*
 * ip_check_options - check that any IP-related options are OK,
 * and assign appropriate defaults.
 */
static void
ip_check_options()
{
    struct hostent *hp;
    u_int32_t local;
    ipcp_options *wo = &ipcp_wantoptions[0];

    /*
     * Default our local IP address based on our hostname.
     * If local IP address already given, don't bother.
     */
    if (wo->ouraddr == 0) {
	/*
	 * Look up our hostname (possibly with domain name appended)
	 * and take the first IP address as our local IP address.
	 * If there isn't an IP address for our hostname, too bad.
	 */
	wo->accept_local = 1;	/* don't insist on this default value */
	if ((hp = gethostbyname(hostname)) != NULL) {
	    BCOPY(hp->h_addr, &local, sizeof (hp->h_addr));
	    if (local != 0 && !bad_ip_adrs(local)) {
		wo->ouraddr = local;
		ipcp_from_hostname = 1;
	    }
	}
    }
}


/*
 * ip_demand_conf - configure the interface as though
 * IPCP were up, for use with dial-on-demand.
 */
static int
ip_demand_conf(u)
    int u;
{
    ipcp_options *wo = &ipcp_wantoptions[u];

    if (wo->hisaddr == 0) {
	/* make up an arbitrary address for the peer */
	wo->hisaddr = htonl(0x0a707070 + ifunit);
	wo->accept_remote = 1;
    }
    if (wo->ouraddr == 0) {
	/* make up an arbitrary address for us */
	wo->ouraddr = htonl(0x0a404040 + ifunit);
	wo->accept_local = 1;
	disable_defaultip = 1;	/* don't tell the peer this address */
    }
    if (!sifaddr(u, wo->ouraddr, wo->hisaddr, GetMask(wo->ouraddr)))
	return 0;
    if (!sifup(u))
	return 0;
    if (!sifnpmode(u, PPP_IP, NPMODE_QUEUE))
	return 0;
    if (wo->default_route && sifdefaultroute(u, wo->ouraddr, wo->hisaddr))
	default_route_set[u] = 1;
    if (wo->proxy_arp && sifproxyarp(u, wo->hisaddr, proxy_arp_quiet[u]))
	proxy_arp_set[u] = 1;

    notice("local  IP address %I", wo->ouraddr);
    notice("remote IP address %I", wo->hisaddr);

    return 1;
}


/*
 * ipcp_up - IPCP has come UP.
 *
 * Configure the IP network interface appropriately and bring it up.
 */
static void
ipcp_up(f)
    fsm *f;
{
    u_int32_t mask;
    ipcp_options *ho = &ipcp_hisoptions[f->unit];
    ipcp_options *go = &ipcp_gotoptions[f->unit];
    ipcp_options *wo = &ipcp_wantoptions[f->unit];

    IPCPDEBUG(("ipcp: up"));

    /*
     * We must have a non-zero IP address for both ends of the link.
     */
    if (ho->hisaddr == 0)
	ho->hisaddr = wo->hisaddr;

    if (ho->hisaddr == 0) {
	if (wo->accept_remote) {
	    /* Pick some rfc1918 address. */
	    ho->hisaddr = htonl(0xc0a80101 + ifunit);
	    dbglog("Peer refused to provide his address; assuming %I",
		ho->hisaddr);
	} else {
	    error("Could not determine remote IP address");
	    ipcp_close(f->unit, "Could not determine remote IP address");
	    return;
	}
    }
    if (go->ouraddr == 0) {
	error("Could not determine local IP address");
	ipcp_close(f->unit, "Could not determine local IP address");
	return;
    }
    script_setenv("IPLOCAL", ip_ntoa(go->ouraddr), 0);
    script_setenv("IPREMOTE", ip_ntoa(ho->hisaddr), 1);

    /*
     * Check that the peer is allowed to use the IP address it wants.
     */
    if (!auth_ip_addr(f->unit, ho->hisaddr)) {
	error("Peer is not authorized to use remote address %I", ho->hisaddr);
	ipcp_close(f->unit, "Unauthorized remote IP address");
	return;
    }

    if ((go->req_dns1 && go->dnsaddr[0] != 0) ||
	(go->req_dns2 && go->dnsaddr[1] != 0)) {
	script_setenv("USEPEERDNS", "1", 0);
	if (go->dnsaddr[0] != 0)
	    script_setenv("DNS1", ip_ntoa(go->dnsaddr[0]), 0);
	if (go->dnsaddr[1] != 0)
	    script_setenv("DNS2", ip_ntoa(go->dnsaddr[1]), 0);
	create_resolv(go->dnsaddr[0], go->dnsaddr[1]);
    }

    /* set tcp compression */
    if (sifvjcomp(f->unit, ho->neg_vj, ho->cflag, ho->maxslotindex) != 1) {
	ipcp_close(f->unit, "Could not enable VJ TCP header compression");
	return;
    }

    /*
     * If we are doing dial-on-demand, the interface is already
     * configured, so we put out any saved-up packets, then set the
     * interface to pass IP packets.
     */
    if (demand) {
	if (go->ouraddr != wo->ouraddr || ho->hisaddr != wo->hisaddr) {
	    ipcp_clear_addrs(f->unit, wo->ouraddr, wo->hisaddr);
	    if (go->ouraddr != wo->ouraddr) {
		warn("Local IP address changed to %I", go->ouraddr);
		script_setenv("OLDIPLOCAL", ip_ntoa(wo->ouraddr), 0);
		wo->ouraddr = go->ouraddr;
	    } else
		script_unsetenv("OLDIPLOCAL");
	    if (ho->hisaddr != wo->hisaddr) {
		warn("Remote IP address changed to %I", ho->hisaddr);
		script_setenv("OLDIPREMOTE", ip_ntoa(wo->hisaddr), 0);
		wo->hisaddr = ho->hisaddr;
	    } else
		script_unsetenv("OLDIPREMOTE");

	    /* Set the interface to the new addresses */
	    mask = GetMask(go->ouraddr);
	    if (!sifaddr(f->unit, go->ouraddr, ho->hisaddr, mask)) {
		warn("Interface configuration failed");
		ipcp_close(f->unit, "Interface configuration failed");
		return;
	    }

	    /* assign a default route through the interface if required */
	    if (wo->default_route)
		if (sifdefaultroute(f->unit, go->ouraddr, ho->hisaddr))
		    default_route_set[f->unit] = 1;

	    /* Make a proxy ARP entry if requested. */
	    if (wo->proxy_arp &&
		sifproxyarp(f->unit, ho->hisaddr, proxy_arp_quiet[f->unit]))
		proxy_arp_set[f->unit] = 1;

	}
	demand_rexmit(PPP_IP);
	if (sifnpmode(f->unit, PPP_IP, NPMODE_PASS) != 1) {
	    ipcp_close(f->unit, "Interface configuration failed.");
	    return;
	}

    } else {
	/*
	 * Set IP addresses and (if specified) netmask.
	 */
	mask = GetMask(go->ouraddr);

#if SIFUPFIRST
	/* bring the interface up for IP */
	if (!sifup(f->unit)) {
	    warn("Interface failed to come up");
	    ipcp_close(f->unit, "Interface configuration failed");
	    return;
	}
#endif

	if (!sifaddr(f->unit, go->ouraddr, ho->hisaddr, mask)) {
	    warn("Interface configuration failed");
	    ipcp_close(f->unit, "Interface configuration failed");
	    return;
	}

#if !SIFUPFIRST
	/* bring the interface up for IP */
	if (!sifup(f->unit)) {
	    warn("Interface failed to come up");
	    ipcp_close(f->unit, "Interface configuration failed");
	    return;
	}
#endif

	if (sifnpmode(f->unit, PPP_IP, NPMODE_PASS) != 1) {
	    ipcp_close(f->unit, "Interface configuration failed.");
	    return;
	}

	/* assign a default route through the interface if required */
	if (wo->default_route)
	    if (sifdefaultroute(f->unit, go->ouraddr, ho->hisaddr))
		default_route_set[f->unit] = 1;

	/* Make a proxy ARP entry if requested. */
	if (wo->proxy_arp &&
	    sifproxyarp(f->unit, ho->hisaddr, proxy_arp_quiet[f->unit]))
	    proxy_arp_set[f->unit] = 1;

	wo->ouraddr = go->ouraddr;

	notice("local  IP address %I", go->ouraddr);
	notice("remote IP address %I", ho->hisaddr);
	if (go->dnsaddr[0] != 0)
	    notice("primary   DNS address %I", go->dnsaddr[0]);
	if (go->dnsaddr[1] != 0)
	    notice("secondary DNS address %I", go->dnsaddr[1]);
    }

    np_up(f->unit, PPP_IP);
    ipcp_is_up[f->unit] = 1;

    if (ip_up_hook != NULL)
	(*ip_up_hook)();

    /*
     * Execute the ip-up script, like this:
     *	/etc/ppp/ip-up interface tty speed local-IP remote-IP
     */
    if (ipcp_script_state == s_down && ipcp_script_pid == 0) {
	ipcp_script_state = s_up;
	ipcp_script(_PATH_IPUP);
    }
    sys_unblock_proto(PPP_IP);
}


/*
 * ipcp_down - IPCP has gone DOWN.
 *
 * Take the IP network interface down, clear its addresses
 * and delete routes through it.
 */
static void
ipcp_down(f)
    fsm *f;
{
    IPCPDEBUG(("ipcp: down"));
    /* XXX a bit IPv4-centric here, we only need to get the stats
     * before the interface is marked down. */
    update_link_stats(f->unit);
    if (ip_down_hook != NULL)
	(*ip_down_hook)();
    if (ipcp_is_up[f->unit]) {
	ipcp_is_up[f->unit] = 0;
	np_down(f->unit, PPP_IP);
    }
    if (sifvjcomp(f->unit, 0, 0, 0) != 1) {
	if (debug)
	    warn("Failed to disable VJ TCP header compression.");
    }

    /*
     * If we are doing dial-on-demand, set the interface
     * to queue up outgoing packets (for now).
     */
    if (demand) {
	if (sifnpmode(f->unit, PPP_IP, NPMODE_QUEUE) != 1) {
	    if (debug)
		warn("Failed to enable Queueing on outgoing packets.");
	}
    } else {
	if (sifnpmode(f->unit, PPP_IP, NPMODE_ERROR) != 1) {
	    if (debug)
		warn("Could not set interface to drop packets.");
	}
	if (sifdown(f->unit) != 1)
	    warn("Could not bring interface down.");
	ipcp_clear_addrs(f->unit, ipcp_gotoptions[f->unit].ouraddr,
			 ipcp_hisoptions[f->unit].hisaddr);
    }

    /* Execute the ip-down script */
    if (ipcp_script_state == s_up && ipcp_script_pid == 0) {
	ipcp_script_state = s_down;
	ipcp_script(_PATH_IPDOWN);
    }
}


/*
 * ipcp_clear_addrs() - clear the interface addresses, routes,
 * proxy arp entries, etc.
 */
static void
ipcp_clear_addrs(unit, ouraddr, hisaddr)
    int unit;
    u_int32_t ouraddr;  /* local address */
    u_int32_t hisaddr;  /* remote address */
{
    if (proxy_arp_set[unit]) {
	(void) cifproxyarp(unit, hisaddr);
	proxy_arp_set[unit] = 0;
    }
    if (default_route_set[unit]) {
	(void) cifdefaultroute(unit, ouraddr, hisaddr);
	default_route_set[unit] = 0;
    }
    if (cifaddr(unit, ouraddr, hisaddr) != 1)
	warn("Could not clear addresses");
}


/*
 * ipcp_finished - possibly shut down the lower layers.
 */
static void
ipcp_finished(f)
    fsm *f;
{
    np_finished(f->unit, PPP_IP);
}


/*
 * ipcp_script_done - called when the ip-up or ip-down script
 * has finished.
 */
/*ARGSUSED*/
static void
ipcp_script_done(arg, status)
    void *arg;
    int status;
{
    ipcp_script_pid = 0;
    switch (ipcp_script_state) {
    case s_up:
	if (ipcp_fsm[0].state != OPENED) {
	    ipcp_script_state = s_down;
	    ipcp_script(_PATH_IPDOWN);
	}
	break;
    case s_down:
	if (ipcp_fsm[0].state == OPENED) {
	    ipcp_script_state = s_up;
	    ipcp_script(_PATH_IPUP);
	}
	break;
    }
}


/*
 * ipcp_script - Execute a script with arguments
 * interface-name tty-name speed local-IP remote-IP.
 */
static void
ipcp_script(script)
    char *script;
{
    char strspeed[32], strlocal[32], strremote[32];
    char *argv[8];

    (void) slprintf(strspeed, sizeof(strspeed), "%d", baud_rate);
    (void) slprintf(strlocal, sizeof(strlocal), "%I",
	ipcp_gotoptions[0].ouraddr);
    (void) slprintf(strremote, sizeof(strremote), "%I",
	ipcp_hisoptions[0].hisaddr);

    argv[0] = script;
    argv[1] = ifname;
    argv[2] = devnam;
    argv[3] = strspeed;
    argv[4] = strlocal;
    argv[5] = strremote;
    argv[6] = ipparam;
    argv[7] = NULL;
    ipcp_script_pid = run_program(script, argv, 0, ipcp_script_done, NULL);
}

/*
 * create_resolv - create the replacement resolv.conf file
 */
static void
create_resolv(peerdns1, peerdns2)
    u_int32_t peerdns1, peerdns2;
{
    FILE *f;

    f = fopen(_PATH_RESOLV, "w");
    if (f == NULL) {
	error("Failed to create %s: %m", _PATH_RESOLV);
	return;
    }

    if (peerdns1)
	if (fprintf(f, "nameserver %s\n", ip_ntoa(peerdns1)) <= 0)
	    error("Write failed to %s: %m", _PATH_RESOLV);

    if (peerdns2)
	if (fprintf(f, "nameserver %s\n", ip_ntoa(peerdns2)) <= 0)
	    error("Write failed to %s: %m", _PATH_RESOLV);

    if (fclose(f) != 0)
	error("Failed to close %s: %m", _PATH_RESOLV);
}

/*
 * ipcp_printpkt - print the contents of an IPCP packet.
 */
static int
ipcp_printpkt(p, plen, printer, arg)
    u_char *p;
    int plen;
    void (*printer) __P((void *, const char *, ...));
    void *arg;
{
    int code, id, len, olen;
    u_char *pstart, *optend;
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
	    case CI_ADDRS:
		if (olen == CILEN_ADDRS) {
		    p += 2;
		    GETNLONG(cilong, p);
		    printer(arg, "addrs %I", cilong);
		    GETNLONG(cilong, p);
		    printer(arg, " %I", cilong);
		}
		break;
	    case CI_COMPRESSTYPE:
		if (olen >= CILEN_COMPRESS) {
		    p += 2;
		    GETSHORT(cishort, p);
		    printer(arg, "compress ");
		    switch (cishort) {
		    case IPCP_VJ_COMP:
			printer(arg, "VJ");
			break;
		    case IPCP_VJ_COMP_OLD:
			printer(arg, "old-VJ");
			break;
		    default:
			printer(arg, "0x%x", cishort);
		    }
		}
		break;
	    case CI_ADDR:
		if (olen == CILEN_ADDR) {
		    p += 2;
		    GETNLONG(cilong, p);
		    printer(arg, "addr %I", cilong);
		}
		break;
	    case CI_MS_DNS1:
	    case CI_MS_DNS2:
	        p += 2;
		GETNLONG(cilong, p);
		printer(arg, "ms-dns%d %I", (code == CI_MS_DNS1 ? 1 : 2),
		    cilong);
		break;
	    case CI_MS_WINS1:
	    case CI_MS_WINS2:
	        p += 2;
		GETNLONG(cilong, p);
		printer(arg, "ms-wins%d %I", (code == CI_MS_WINS1 ? 1 : 2),
		    cilong);
		break;
	    case CI_SUBNET:
		p += 2;
		GETNLONG(cilong, p);
		printer(arg, "subnet %I", cilong);
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
    }

    /* print the rest of the bytes in the packet */
    for (; len > 0; --len) {
	GETCHAR(code, p);
	printer(arg, " %.2x", code);
    }

    return p - pstart;
}

char *
tcp_flag_decode(val)
    int val;
{
    static char buf[32];
    char *cp = buf;

    if (val & TH_URG)
	*cp++ = 'U';
    if (val & TH_ACK)
	*cp++ = 'A';
    if (val & TH_PUSH)
	*cp++ = 'P';
    if (val & TH_RST)
	*cp++ = 'R';
    if (val & TH_SYN)
	*cp++ = 'S';
    if (val & TH_FIN)
	*cp++ = 'F';
    if (cp != buf)
	*cp++ = ' ';
    *cp = '\0';
    return buf;
}

/*
 * ip_active_pkt - see if this IP packet is worth bringing the link up for.
 * We don't bring the link up for IP fragments or for TCP FIN packets
 * with no data.
 */

static int
ip_active_pkt(pkt, len)
    u_char *pkt;
    int len;
{
    u_char *tcp;
    struct protoent *pep;
    int val;
    int hlen;
    char buf[32], *cp;
    u_int32_t src, dst;

    len -= PPP_HDRLEN;
    pkt += PPP_HDRLEN;
    if (len < IP_HDRLEN) {
	dbglog("IP packet of length %d is not activity", len);
	return 0;
    }
    src = get_ipsrc(pkt);
    dst = get_ipdst(pkt);
    if ((get_ipoff(pkt) & IP_OFFMASK) != 0) {
	dbglog("IP fragment from %I->%I is not activity", src, dst);
	return 0;
    }
    val = get_ipproto(pkt);
    if (val != IPPROTO_TCP) {
	if (debug) {
	    if ((pep = getprotobynumber(val)) != NULL) {
		cp = pep->p_name;
	    } else {
		(void) slprintf(buf, sizeof (buf), "IP proto %d", val);
		cp = buf;
	    }
	    info("%s from %I->%I is activity", cp, src, dst);
	}
	return 1;
    }
    hlen = get_iphl(pkt) * 4;
    if (len < hlen + TCP_HDRLEN) {
	dbglog("Bad TCP length %d<%d+%d %I->%I is not activity", len, hlen,
	    TCP_HDRLEN, src, dst);
	return 0;
    }
    tcp = pkt + hlen;
    val = get_tcpflags(tcp);
    hlen += get_tcpoff(tcp) * 4;
    if ((val & TH_FIN) != 0 && len == hlen) {
	dbglog("Empty TCP FIN %I->%I is not activity", src, dst);
	return 0;
    }
    info("TCP %d data %s%I->%I is activity", len - hlen,
	tcp_flag_decode(get_tcpflags(tcp)), src, dst);
    return 1;
}

static void
ipcp_print_stat(unit, strptr)
    int unit;
    FILE *strptr;
{
    ipcp_options *go = &ipcp_gotoptions[unit];
    ipcp_options *ho = &ipcp_hisoptions[unit];
    char *proto_name = ipcp_protent.name;

    if (!ipcp_protent.enabled_flag) {
	(void) flprintf(strptr, "%s disabled\n", proto_name);
	return;
    }

    (void) flprintf(strptr, "%s state: %s", proto_name,
	fsm_state(ipcp_fsm[unit].state));
    (void) flprintf(strptr, "%s local %I  remote %I", proto_name, go->ouraddr,
	ho->ouraddr);
}
