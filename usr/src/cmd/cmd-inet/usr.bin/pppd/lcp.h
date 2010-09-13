/*
 * lcp.h - Link Control Protocol definitions.
 *
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
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
 * $Id: lcp.h,v 1.15 2000/04/04 07:06:51 paulus Exp $
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef __LCP_H_
#define __LCP_H_

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Options.
 */
#define CI_MRU		1	/* Maximum Receive Unit */
#define CI_ASYNCMAP	2	/* Async Control Character Map */
#define CI_AUTHTYPE	3	/* Authentication Type */
#define CI_QUALITY	4	/* Quality Protocol */
#define CI_MAGICNUMBER	5	/* Magic Number */
#define CI_PCOMPRESSION	7	/* Protocol Field Compression */
#define CI_ACCOMPRESSION 8	/* Address/Control Field Compression */
#define CI_FCSALTERN	9	/* FCS Alternatives */
#define CI_NUMBERED	11	/* Numbered Mode */
#define CI_CALLBACK	13	/* callback */
#define CI_MRRU		17	/* max reconstructed receive unit; multilink */
#define CI_SSNHF	18	/* short sequence numbers for multilink */
#define CI_EPDISC	19	/* endpoint discriminator */
#define CI_LINKDISC	23	/* Link Discriminator (BACP) */
#define CI_COBS		25	/* Consistent Overhead Byte Stuffing */
#define CI_PFXELISION	26	/* Prefix Elision */
#define CI_MPHDRFMT	27	/* Multilink Header Format */
#define CI_I18N		28	/* Internationalization */
#define CI_SDL		29	/* Simple Data Link */
#define CI_MUXING	30	/* PPP Muxing */

/*
 * LCP-specific packet types.
 */
#define CODE_PROTREJ		8	/* Protocol Reject */
#define CODE_ECHOREQ		9	/* Echo Request */
#define CODE_ECHOREP		10	/* Echo Reply */
#define CODE_DISCREQ		11	/* Discard Request */
#define CODE_IDENT		12	/* Identification */
#define CODE_TIMEREMAIN		13	/* Time Remaining */

/*
 * Callback operation field values
 */
#define CBOP_AUTH	0	/* Location determined by user auth */
#define CBOP_DIALSTR	1	/* Dialing string */
#define CBOP_LOCATION	2	/* Location identifier */
#define CBOP_E164	3	/* E.164 number */
#define CBOP_X500	4	/* X.500 distinguished name */
#define CBOP_CBCP	6	/* Use callback control protocol */

/* FCS-Alternatives bits (RFC 1570) */
#define	FCSALT_NULL	1	/* None for network data; default otherwise */
#define	FCSALT_16	2	/* CRC-16 */
#define	FCSALT_32	4	/* CRC-32 */

/* An endpoint discriminator, used with multilink. */
#define MAX_ENDP_LEN    20      /* maximum length of discriminator value */
struct epdisc {
    unsigned char       class;
    unsigned char       length;
    unsigned char       value[MAX_ENDP_LEN];
};

/* values for epdisc.class */
#define EPD_NULL	0	/* null discriminator, no data */
#define EPD_LOCAL	1
#define EPD_IP		2
#define EPD_MAC		3
#define EPD_MAGIC	4
#define EPD_PHONENUM	5

/*
 * The state of options is described by an lcp_options structure.
 *
 * We encode CHAP/MS-CHAP/MS-CHAPv2 options as Booleans.  This is done
 * so that we can represent the choices of requiring or refusing each
 * separately.  The chap_mdtype value can't do that.
 */
typedef struct lcp_options {
    bool passive;		/* Don't die if we don't get a response */
    bool silent;		/* Wait for the other end to start first */
    bool restart;		/* Restart vs. exit after close */
    bool neg_mru;		/* Negotiate the MRU? */
    bool neg_asyncmap;		/* Negotiate the async map? */
    bool neg_upap;		/* Ask for UPAP authentication? */
    bool neg_chap;		/* Ask for CHAP authentication? */
    bool neg_mschap;		/* Ask for MS-CHAPv1 authentication? */
    bool neg_mschapv2;		/* Ask for MS-CHAPv2 authentication? */
    bool neg_magicnumber;	/* Ask for magic number? */
    bool neg_pcompression;	/* HDLC Protocol Field Compression? */
    bool neg_accompression;	/* HDLC Address/Control Field Compression? */
    bool neg_lqr;		/* Negotiate use of Link Quality Reports */
    bool neg_cbcp;		/* Negotiate use of CBCP */
    bool neg_mrru;		/* negotiate multilink MRRU */
#ifdef MUX_FRAME
    u_int32_t pppmux;           /* Negotiate for PPP Multiplexing option */
#endif
    bool neg_ssnhf;		/* negotiate short sequence numbers */
    bool neg_endpoint;		/* negotiate endpoint discriminator */
    bool neg_fcs;		/* negotiate FCS alternatives */
    int  mru;			/* Value of MRU */
    int	 mrru;			/* Value of MRRU, and multilink enable */
    u_char chap_mdtype;		/* which MD type (hashing algorithm) */
    u_char fcs_type;		/* selected FCS type(s) */
    u_int32_t asyncmap;		/* Value of async map */
    u_int32_t magicnumber;
    int  numloops;		/* Number of loops during magic number neg. */
    u_int32_t lqr_period;	/* Reporting period for LQR 1/100ths second */
    struct epdisc endpoint;	/* endpoint discriminator */
} lcp_options;

/*
 * The structure passed to lcp_settimeremaining(), holds the unit
 * number of the link being timed, and the time remaining for that
 * connection.
 */
struct lcp_timer {
    int unit;
    u_int32_t tr;
};

extern fsm lcp_fsm[];
extern lcp_options lcp_wantoptions[];
extern lcp_options lcp_gotoptions[];
extern lcp_options lcp_allowoptions[];
extern lcp_options lcp_hisoptions[];
extern u_int32_t xmit_accm[][8];

void lcp_open __P((int));
void lcp_close __P((int, char *));
void lcp_lowerup __P((int));
void lcp_lowerdown __P((int));
void lcp_sprotrej __P((int, u_char *, int));	/* send protocol reject */
void lcp_settimeremaining __P((int, u_int32_t, u_int32_t));

/*
 * Procedures exported from multilink.c
 */
extern char *epdisc_to_str __P((struct epdisc *));
				/* string from endpoint discriminator */
extern int  str_to_epdisc __P((struct epdisc *, char *));
				/* endpt discriminator from str */

extern struct protent lcp_protent;

/* Default number of times we receive our magic number from the peer
   before deciding the link is looped-back. */
#define DEFLOOPBACKFAIL	10

#ifdef	__cplusplus
}
#endif

#endif /* __LCP_H_ */
