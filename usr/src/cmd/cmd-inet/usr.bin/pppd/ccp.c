/*
 * ccp.c - PPP Compression Control Protocol.
 *
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAVE BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 */
/*
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <stdlib.h>
#include <string.h>

#include "pppd.h"
#include "fsm.h"
#include "ccp.h"
#include <net/ppp-comp.h>

/*
 * Command-line options.
 */
static int setbsdcomp __P((char **, option_t *));
static int setdeflate __P((char **, option_t *));

static option_t ccp_option_list[] = {
    { "noccp", o_bool, &ccp_protent.enabled_flag,
      "Disable CCP negotiation" },
    { "-ccp", o_bool, &ccp_protent.enabled_flag,
      "Disable CCP negotiation" },
    { "bsdcomp", o_special, (void *)setbsdcomp,
      "Request BSD-Compress packet compression" },
    { "nobsdcomp", o_bool, &ccp_wantoptions[0].bsd_compress,
      "don't allow BSD-Compress", OPT_A2COPY,
      &ccp_allowoptions[0].bsd_compress },
    { "-bsdcomp", o_bool, &ccp_wantoptions[0].bsd_compress,
      "don't allow BSD-Compress", OPT_A2COPY,
      &ccp_allowoptions[0].bsd_compress },
    { "deflate", o_special, (void *)setdeflate,
      "request Deflate compression" },
    { "nodeflate", o_bool, &ccp_wantoptions[0].deflate,
      "don't allow Deflate compression", OPT_A2COPY,
      &ccp_allowoptions[0].deflate },
    { "-deflate", o_bool, &ccp_wantoptions[0].deflate,
      "don't allow Deflate compression", OPT_A2COPY,
      &ccp_allowoptions[0].deflate },
    { "nodeflatedraft", o_bool, &ccp_wantoptions[0].deflate_draft,
      "don't use draft deflate #", OPT_A2COPY,
      &ccp_allowoptions[0].deflate_draft },
    { "predictor1", o_bool, &ccp_wantoptions[0].predictor_1,
      "request Predictor-1", 1, &ccp_allowoptions[0].predictor_1 },
    { "nopredictor1", o_bool, &ccp_wantoptions[0].predictor_1,
      "don't allow Predictor-1", OPT_A2COPY,
      &ccp_allowoptions[0].predictor_1 },
    { "-predictor1", o_bool, &ccp_wantoptions[0].predictor_1,
      "don't allow Predictor-1", OPT_A2COPY,
      &ccp_allowoptions[0].predictor_1 },

    { NULL }
};

/*
 * Protocol entry points from main code.
 */
static void ccp_init __P((int unit));
static void ccp_open __P((int unit));
static void ccp_close __P((int unit, char *));
static void ccp_lowerup __P((int unit));
static void ccp_lowerdown __P((int));
static void ccp_input __P((int unit, u_char *pkt, int len));
static void ccp_protrej __P((int unit));
static int  ccp_printpkt __P((u_char *pkt, int len,
			      void (*printer) __P((void *, const char *, ...)),
			      void *arg));
static void ccp_datainput __P((int unit, u_char *pkt, int len));

struct protent ccp_protent = {
    PPP_CCP,
    ccp_init,
    ccp_input,
    ccp_protrej,
    ccp_lowerup,
    ccp_lowerdown,
    ccp_open,
    ccp_close,
    ccp_printpkt,
    ccp_datainput,
    1,
    "CCP",
    "Compressed",
    ccp_option_list,
    NULL,
    NULL,
    NULL
};

fsm ccp_fsm[NUM_PPP];
ccp_options ccp_wantoptions[NUM_PPP];	/* what to request the peer to use */
ccp_options ccp_gotoptions[NUM_PPP];	/* what the peer agreed to do */
ccp_options ccp_allowoptions[NUM_PPP];	/* what we'll agree to do */
ccp_options ccp_hisoptions[NUM_PPP];	/* what we agreed to do */

/*
 * Callbacks for fsm code.
 */
static void ccp_resetci __P((fsm *));
static int  ccp_cilen __P((fsm *));
static void ccp_addci __P((fsm *, u_char *, int *));
static int  ccp_ackci __P((fsm *, u_char *, int));
static int  ccp_nakci __P((fsm *, u_char *, int));
static int  ccp_rejci __P((fsm *, u_char *, int));
static int  ccp_reqci __P((fsm *, u_char *, int *, int));
static void ccp_up __P((fsm *));
static void ccp_down __P((fsm *));
static int  ccp_extcode __P((fsm *, int, int, u_char *, int));
static int  ccp_codereject __P((fsm *p, int code, int id, u_char *inp,
    int len));

static fsm_callbacks ccp_callbacks = {
    ccp_resetci,		/* Reset our Configuration Information */
    ccp_cilen,                  /* Length of our Configuration Information */
    ccp_addci,                  /* Add our Configuration Information */
    ccp_ackci,                  /* ACK our Configuration Information */
    ccp_nakci,                  /* NAK our Configuration Information */
    ccp_rejci,                  /* Reject our Configuration Information */
    ccp_reqci,                  /* Request peer's Configuration Information */
    ccp_up,                     /* Called when fsm reaches OPENED state */
    ccp_down,                   /* Called when fsm leaves OPENED state */
    NULL,                       /* Called when we want the lower layer up */
    NULL,                       /* Called when we want the lower layer down */
    NULL,			/* Retransmission is necessary */
    ccp_extcode,                /* Called to handle LCP-specific codes */
    "CCP",			/* String name of protocol */
    ccp_codereject,             /* Peer rejected a code number */
};

/*
 * Local statics.
 */
static void ccp_rack_timeout __P((void *));
static char * method_name __P((ccp_options *, ccp_options *));

/*
 * Do we want / did we get any compression?
 */
#define ANY_COMPRESS(opt)	((opt).deflate || (opt).bsd_compress \
				 || (opt).predictor_1 || (opt).predictor_2)

/*
 * Local state (mainly for handling reset-reqs and reset-acks).
 */
static int ccp_localstate[NUM_PPP];
#define RACK_PENDING	0x0001	/* waiting for reset-ack */
#define RREQ_REPEAT	0x0002	/* send another reset-req if no reset-ack */
#define RREQ_REJECTED	0x0004	/* peer code-rejected reset-request */
#define RACK_REJECTED	0x0008	/* peer code-rejected reset-ack */
#define RREQ_IGNORED	0x0010	/* peer just ignored reset-request */

#define RACKTIMEOUT	1	/* time in seconds between Reset-Requests */

static int all_rejected[NUM_PPP];	/* we rejected all peer's options */

#ifdef COMP_TUNE
static int deflate_tune = -1;	/* compression effort level for deflate */
#endif
static int deflate_rmax = DEFLATE_MAX_SIZE;	/* max rbits */
static int deflate_amax = DEFLATE_MAX_SIZE;	/* max abits */

/*
 * Option parsing.
 */
/*ARGSUSED*/
static int
setbsdcomp(argv, opt)
    char **argv;
    option_t *opt;
{
    int rbits, abits;
    char *str, *endp;

    str = *argv;
    abits = rbits = strtol(str, &endp, 0);
    if (endp != str && *endp == ',') {
	str = endp + 1;
	abits = strtol(str, &endp, 0);
    }
    if (*endp != '\0' || endp == str) {
	option_error("invalid parameter '%s' for bsdcomp option", *argv);
	return 0;
    }
    if ((rbits != 0 && (rbits < BSD_MIN_BITS || rbits > BSD_MAX_BITS))
	|| (abits != 0 && (abits < BSD_MIN_BITS || abits > BSD_MAX_BITS))) {
	option_error("bsdcomp option values must be 0 or %d .. %d",
		     BSD_MIN_BITS, BSD_MAX_BITS);
	return 0;
    }
    if (rbits > 0) {
	ccp_wantoptions[0].bsd_compress = 1;
	ccp_wantoptions[0].bsd_bits = rbits;
    } else
	ccp_wantoptions[0].bsd_compress = 0;
    if (abits > 0) {
	ccp_allowoptions[0].bsd_compress = 1;
	ccp_allowoptions[0].bsd_bits = abits;
    } else
	ccp_allowoptions[0].bsd_compress = 0;
    return 1;
}

/*ARGSUSED*/
static int
setdeflate(argv, opt)
    char **argv;
    option_t *opt;
{
    int rbits, abits, def_rmax, def_amax;
    char *str, *endp;

    str = endp = *argv;
    if (*str == ',')
	abits = rbits = -1;
    else
	abits = rbits = strtol(str, &endp, 0);
    if (*endp == ',') {
	str = ++endp;
	if (*str == ',')
	    abits = rbits;
	else
	    abits = strtol(str, &endp, 0);
    }
#ifdef COMP_TUNE
    if (*endp == ',' && privileged_option) {
	str = ++endp;
	deflate_tune = strtol(str, &endp, 0);
    }
#endif
    if (*endp != '\0' || endp == str) {
	option_error("invalid parameter '%s' for deflate option", *argv);
	return 0;
    }
    if (privileged_option) {
	def_rmax = def_amax = DEFLATE_MAX_SIZE;
    } else {
	def_rmax = deflate_rmax;
	def_amax = deflate_amax;
    }
    if (rbits < 0)
	rbits = def_rmax;
    if (abits < 0)
	abits = def_amax;
    if ((rbits != 0 && (rbits <= DEFLATE_MIN_SIZE || rbits > def_rmax))
	|| (abits != 0 && (abits <= DEFLATE_MIN_SIZE || abits > def_amax))) {
	option_error("deflate option values must be 0 or {%d,%d} .. {%d,%d}",
		     DEFLATE_MIN_SIZE+1, DEFLATE_MIN_SIZE+1,
		     def_rmax, def_amax);
	return 0;
    }
    if (privileged_option) {
	deflate_rmax = rbits;
	deflate_amax = abits;
    }
    if (rbits > 0) {
	ccp_wantoptions[0].deflate = 1;
	ccp_wantoptions[0].deflate_size = rbits;
    } else
	ccp_wantoptions[0].deflate = 0;
    if (abits > 0) {
	ccp_allowoptions[0].deflate = 1;
	ccp_allowoptions[0].deflate_size = abits;
    } else
	ccp_allowoptions[0].deflate = 0;
    return 1;
}


/*
 * ccp_init - initialize CCP.
 */
static void
ccp_init(unit)
    int unit;
{
    fsm *f = &ccp_fsm[unit];

    f->unit = unit;
    f->protocol = PPP_CCP;
    f->callbacks = &ccp_callbacks;
    fsm_init(f);
    f->flags |= OPT_RESTART;

    BZERO(&ccp_wantoptions[unit],  sizeof(ccp_options));
    BZERO(&ccp_gotoptions[unit],   sizeof(ccp_options));
    BZERO(&ccp_allowoptions[unit], sizeof(ccp_options));
    BZERO(&ccp_hisoptions[unit],   sizeof(ccp_options));

    ccp_wantoptions[0].deflate = 1;
    ccp_wantoptions[0].deflate_size = DEFLATE_MAX_SIZE;
    ccp_wantoptions[0].deflate_correct = 1;
    ccp_wantoptions[0].deflate_draft = 1;
    ccp_allowoptions[0].deflate = 1;
    ccp_allowoptions[0].deflate_size = DEFLATE_MAX_SIZE;
    ccp_allowoptions[0].deflate_correct = 1;
    ccp_allowoptions[0].deflate_draft = 1;

    ccp_wantoptions[0].bsd_compress = 1;
    ccp_wantoptions[0].bsd_bits = BSD_MAX_BITS;
    ccp_allowoptions[0].bsd_compress = 1;
    ccp_allowoptions[0].bsd_bits = BSD_MAX_BITS;

    ccp_allowoptions[0].predictor_1 = 1;
}

/*
 * ccp_open - CCP is allowed to come up.
 */
static void
ccp_open(unit)
    int unit;
{
    fsm *f = &ccp_fsm[unit];

    /*
     * If we haven't gone open yet (first time through), then go open
     * but not up.  Otherwise, skip this to allow reopen to reset the
     * compressor.
     */
    if (f->state != OPENED)
	ccp_flags_set(unit, 1, 0);

    /*
     * Find out which compressors the kernel supports before
     * deciding whether to open in silent mode.
     */
    ccp_resetci(f);
    if (!ANY_COMPRESS(ccp_gotoptions[unit]))
	f->flags |= OPT_SILENT;

    fsm_open(f);
}

/*
 * ccp_close - Terminate CCP.
 */
static void
ccp_close(unit, reason)
    int unit;
    char *reason;
{
    ccp_flags_set(unit, 0, 0);
    fsm_close(&ccp_fsm[unit], reason);
}

/*
 * ccp_lowerup - we may now transmit CCP packets.
 */
static void
ccp_lowerup(unit)
    int unit;
{
    fsm_lowerup(&ccp_fsm[unit]);
}

/*
 * ccp_lowerdown - we may not transmit CCP packets.
 */
static void
ccp_lowerdown(unit)
    int unit;
{
    fsm_lowerdown(&ccp_fsm[unit]);
}

/*
 * ccp_input - process a received CCP packet.
 */
static void
ccp_input(unit, p, len)
    int unit;
    u_char *p;
    int len;
{
    fsm *f = &ccp_fsm[unit];
    int oldstate;

    /*
     * Check for a terminate-request so we can print a message.
     */
    oldstate = f->state;
    fsm_input(f, p, len);
    if (oldstate == OPENED && p[0] == CODE_TERMREQ && f->state != OPENED)
	notice("Compression disabled by peer.");

    /*
     * If we get a terminate-ack and we're not asking for compression,
     * close CCP.  (Terminate-Request is handled by fsm_input() above.)
     */
    if (oldstate == REQSENT && p[0] == CODE_TERMACK
	&& !ANY_COMPRESS(ccp_gotoptions[unit]))
	ccp_close(unit, "No compression negotiated");
}

/*
 * Handle a CCP-specific code.
 */
static int
ccp_extcode(f, code, id, p, len)
    fsm *f;
    int code, id;
    u_char *p;
    int len;
{
    switch (code) {
    case CCP_RESETREQ:
	/* If not open, then silently ignore. */
	if (f->state != OPENED)
	    break;
	/* send a reset-ack, which our transmitter module will see and
	   reset its compression state. */
	fsm_sdata(f, CCP_RESETACK, id, p, len);
	break;

    case CCP_RESETACK:
	/*
	 * Note that the compression module isn't picky about ID
	 * numbers and such.
	 */
	ccp_localstate[f->unit] &= ~RREQ_IGNORED & ~RREQ_REJECTED;
	if ((ccp_localstate[f->unit] & RACK_PENDING) && id == f->reqid) {
	    ccp_localstate[f->unit] &= ~RACK_PENDING & ~RREQ_REPEAT;
	    UNTIMEOUT(ccp_rack_timeout, f);
	}
	break;

    default:
	/* Tell fsm to send code reject */
	return (0);
    }

    return (1);
}

/*
 * Handle Code-Reject for one of our extended codes by dropping back to
 * reopen as mechanism to restart compression.
 */
/*ARGSUSED*/
static int
ccp_codereject(f, code, id, inp, len)
    fsm *f;
    int code, id;
    u_char *inp;
    int len;
{
    switch (code) {
    case CCP_RESETREQ:
	if (!(ccp_localstate[f->unit] & RREQ_REJECTED)) {
	    info("peer has rejected CCP Reset-Request; falling back on Open");
	    if (f->state == OPENED)
		ccp_open(f->unit);
	}
	ccp_localstate[f->unit] |= RREQ_REJECTED;
	return (0);

    case CCP_RESETACK:
	/*
	 * Peer must have sent us CCP Reset-Request but then code-rejected when
	 * we sent CCP Reset-Ack.  It seems to have changed its mind, and we
	 * have to obey its wishes.
	 */
	ccp_localstate[f->unit] |= RACK_REJECTED;
	notice("peer has erroneously rejected CCP Reset-Ack");
	f->term_reason = "peer sent Code-Reject for CCP Reset-Ack";
	f->term_reason_len = strlen(f->term_reason);
	break;

    default:
	f->term_reason = "peer sent invalid Code-Reject";
	break;
    }

    f->term_reason_len = strlen(f->term_reason);
    return (1);
}

/*
 * ccp_protrej - peer doesn't talk CCP.
 */
static void
ccp_protrej(unit)
    int unit;
{
    /* Neither open nor up. */
    ccp_flags_set(unit, 0, 0);
    fsm_lowerdown(&ccp_fsm[unit]);
}

/*
 * ccp_resetci - initialize at start of negotiation.
 */
static void
ccp_resetci(f)
    fsm *f;
{
    ccp_options *go = &ccp_gotoptions[f->unit];
    u_char opt_buf[16];

    *go = ccp_wantoptions[f->unit];
    all_rejected[f->unit] = 0;

    /*
     * Check whether the kernel knows about the various
     * decompression methods we might request.
     */
    if (go->bsd_compress) {
	opt_buf[0] = CI_BSD_COMPRESS;
	opt_buf[1] = CILEN_BSD_COMPRESS;
	opt_buf[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION, BSD_MIN_BITS);
	if (ccp_test(f->unit, opt_buf, CILEN_BSD_COMPRESS, 0) <= 0)
	    go->bsd_compress = 0;
    }
    if (go->deflate) {
	if (go->deflate_correct) {
	    opt_buf[0] = CI_DEFLATE;
	    opt_buf[1] = CILEN_DEFLATE;
	    opt_buf[2] = DEFLATE_MAKE_OPT(DEFLATE_MIN_SIZE+1);
	    opt_buf[3] = DEFLATE_CHK_SEQUENCE;
	    if (ccp_test(f->unit, opt_buf, CILEN_DEFLATE, 0) <= 0)
		go->deflate_correct = 0;
	}
	if (go->deflate_draft) {
	    opt_buf[0] = CI_DEFLATE_DRAFT;
	    opt_buf[1] = CILEN_DEFLATE;
	    opt_buf[2] = DEFLATE_MAKE_OPT(DEFLATE_MIN_SIZE+1);
	    opt_buf[3] = DEFLATE_CHK_SEQUENCE;
	    if (ccp_test(f->unit, opt_buf, CILEN_DEFLATE, 0) <= 0)
		go->deflate_draft = 0;
	}
	if (!go->deflate_correct && !go->deflate_draft)
	    go->deflate = 0;
    }
    if (go->predictor_1) {
	opt_buf[0] = CI_PREDICTOR_1;
	opt_buf[1] = CILEN_PREDICTOR_1;
	if (ccp_test(f->unit, opt_buf, CILEN_PREDICTOR_1, 0) <= 0)
	    go->predictor_1 = 0;
    }
    if (go->predictor_2) {
	opt_buf[0] = CI_PREDICTOR_2;
	opt_buf[1] = CILEN_PREDICTOR_2;
	if (ccp_test(f->unit, opt_buf, CILEN_PREDICTOR_2, 0) <= 0)
	    go->predictor_2 = 0;
    }
}

/*
 * ccp_cilen - Return total length of our configuration info.
 */
static int
ccp_cilen(f)
    fsm *f;
{
    ccp_options *go = &ccp_gotoptions[f->unit];

    return (go->bsd_compress? CILEN_BSD_COMPRESS: 0)
	+ (go->deflate && go->deflate_correct ? CILEN_DEFLATE : 0)
	+ (go->deflate && go->deflate_draft ? CILEN_DEFLATE : 0)
	+ (go->predictor_1? CILEN_PREDICTOR_1: 0)
	+ (go->predictor_2? CILEN_PREDICTOR_2: 0);
}

/*
 * ccp_addci - put our requests in a packet.
 */
static void
ccp_addci(f, p, lenp)
    fsm *f;
    u_char *p;
    int *lenp;
{
    int res;
    ccp_options *go = &ccp_gotoptions[f->unit];
    u_char *p0 = p;

    /*
     * Add the compression types that we can receive, in decreasing
     * preference order.  Get the kernel to allocate the first one
     * in case it gets Acked.
     */
    if (go->deflate) {
	p[0] = go->deflate_correct? CI_DEFLATE: CI_DEFLATE_DRAFT;
	p[1] = CILEN_DEFLATE;
	p[2] = DEFLATE_MAKE_OPT(go->deflate_size);
	p[3] = DEFLATE_CHK_SEQUENCE;
	for (;;) {
	    res = ccp_test(f->unit, p, CILEN_DEFLATE, 0);
	    if (res > 0) {
		p += CILEN_DEFLATE;
		break;
	    }
	    if (res < 0 || go->deflate_size <= DEFLATE_MIN_SIZE+1) {
		go->deflate = 0;
		break;
	    }
	    --go->deflate_size;
	    p[2] = DEFLATE_MAKE_OPT(go->deflate_size);
	}
	/* If we're offering both, then this is second. */
	if (p != p0 && go->deflate_correct && go->deflate_draft) {
	    p[0] = CI_DEFLATE_DRAFT;
	    p[1] = CILEN_DEFLATE;
	    p[2] = p[2 - CILEN_DEFLATE];
	    p[3] = DEFLATE_CHK_SEQUENCE;
	    p += CILEN_DEFLATE;
	}
    }
    if (go->bsd_compress) {
	p[0] = CI_BSD_COMPRESS;
	p[1] = CILEN_BSD_COMPRESS;
	p[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION, go->bsd_bits);
	if (p != p0) {
	    p += CILEN_BSD_COMPRESS;	/* not the first option */
	} else {
	    for (;;) {
		res = ccp_test(f->unit, p, CILEN_BSD_COMPRESS, 0);
		if (res > 0) {
		    p += CILEN_BSD_COMPRESS;
		    break;
		}
		if (res < 0 || go->bsd_bits <= BSD_MIN_BITS) {
		    go->bsd_compress = 0;
		    break;
		}
		--go->bsd_bits;
		p[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION, go->bsd_bits);
	    }
	}
    }
    /*
     * Prefer Predictor-1 over Predictor-2.  (The latter requires the use
     * of LAP-B and has no known implementations.)
     */
    if (go->predictor_1) {
	p[0] = CI_PREDICTOR_1;
	p[1] = CILEN_PREDICTOR_1;
	if (p == p0 && ccp_test(f->unit, p, CILEN_PREDICTOR_1, 0) <= 0) {
	    go->predictor_1 = 0;
	} else {
	    p += CILEN_PREDICTOR_1;
	}
    }
    if (go->predictor_2) {
	p[0] = CI_PREDICTOR_2;
	p[1] = CILEN_PREDICTOR_2;
	if (p == p0 && ccp_test(f->unit, p, CILEN_PREDICTOR_2, 0) <= 0) {
	    go->predictor_2 = 0;
	} else {
	    p += CILEN_PREDICTOR_2;
	}
    }

    go->method = (p > p0)? p0[0]: -1;

    *lenp = p - p0;
}

/*
 * ccp_ackci - process a received configure-ack, and return
 * 1 iff the packet was OK.
 */
static int
ccp_ackci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    ccp_options *go = &ccp_gotoptions[f->unit];
    u_char *p0 = p;

    if (go->deflate && go->deflate_correct) {
	if (len < CILEN_DEFLATE
	    || p[0] != CI_DEFLATE || p[1] != CILEN_DEFLATE
	    || p[2] != DEFLATE_MAKE_OPT(go->deflate_size)
	    || p[3] != DEFLATE_CHK_SEQUENCE)
	    return 0;
	/* Cope with non-standard first/fast ack */
	if (p == p0 && len == 0)
	    return 1;
	p += CILEN_DEFLATE;
	len -= CILEN_DEFLATE;
    }
    if (go->deflate && go->deflate_draft) {
	if (len < CILEN_DEFLATE
	    || p[0] != CI_DEFLATE_DRAFT || p[1] != CILEN_DEFLATE
	    || p[2] != DEFLATE_MAKE_OPT(go->deflate_size)
	    || p[3] != DEFLATE_CHK_SEQUENCE)
	    return 0;
	/* Cope with non-standard first/fast ack */
	if (p == p0 && len == 0)
	    return 1;
	p += CILEN_DEFLATE;
	len -= CILEN_DEFLATE;
    }
    if (go->bsd_compress) {
	if (len < CILEN_BSD_COMPRESS
	    || p[0] != CI_BSD_COMPRESS || p[1] != CILEN_BSD_COMPRESS
	    || p[2] != BSD_MAKE_OPT(BSD_CURRENT_VERSION, go->bsd_bits))
	    return 0;
	/* Cope with non-standard first/fast ack */
	if (p == p0 && len == 0)
	    return 1;
	p += CILEN_BSD_COMPRESS;
	len -= CILEN_BSD_COMPRESS;
    }
    if (go->predictor_1) {
	if (len < CILEN_PREDICTOR_1
	    || p[0] != CI_PREDICTOR_1 || p[1] != CILEN_PREDICTOR_1)
	    return 0;
	/* Cope with non-standard first/fast ack */
	if (p == p0 && len == 0)
	    return 1;
	p += CILEN_PREDICTOR_1;
	len -= CILEN_PREDICTOR_1;
    }
    if (go->predictor_2) {
	if (len < CILEN_PREDICTOR_2
	    || p[0] != CI_PREDICTOR_2 || p[1] != CILEN_PREDICTOR_2)
	    return 0;
	/* Cope with non-standard first/fast ack */
	if (p == p0 && len == 0)
	    return 1;
	p += CILEN_PREDICTOR_2;
	len -= CILEN_PREDICTOR_2;
    }

    /* Peer cannot ack something that wasn't sent. */
    if (len != 0)
	return 0;
    return 1;
}

/*
 * ccp_nakci - process received configure-nak.
 * Returns 1 iff the nak was OK.
 */
static int
ccp_nakci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    ccp_options *go = &ccp_gotoptions[f->unit];
    ccp_options no;		/* options we've seen already */
    ccp_options try;		/* options to ask for next time */

    BZERO(&no, sizeof(no));
    try = *go;

    if (go->deflate && go->deflate_correct && len >= CILEN_DEFLATE &&
	p[0] == CI_DEFLATE) {
	no.deflate = 1;
	/*
	 * Peer wants us to use a different code size or something.
	 * Stop asking for Deflate if we don't understand its suggestion.
	 */
	if (p[1] != CILEN_DEFLATE
	    || DEFLATE_METHOD(p[2]) != DEFLATE_METHOD_VAL
	    || DEFLATE_SIZE(p[2]) <= DEFLATE_MIN_SIZE
	    || p[3] != DEFLATE_CHK_SEQUENCE)
	    try.deflate_correct = 0;
	else if (DEFLATE_SIZE(p[2]) < go->deflate_size)
	    try.deflate_size = DEFLATE_SIZE(p[2]);
	len -= p[1];
	p += p[1];
    }

    if (go->deflate && go->deflate_draft && len >= CILEN_DEFLATE &&
	p[0] == CI_DEFLATE_DRAFT) {
	no.deflate = 1;
	/*
	 * Peer wants us to use a different code size or something.
	 * Stop asking for Deflate using the old algorithm number if
	 * we don't understand its suggestion.  (Note that this will
	 * happen if the peer is running Magnalink instead of
	 * old-style Deflate.)
	 */
	if (p[1] != CILEN_DEFLATE
	    || DEFLATE_METHOD(p[2]) != DEFLATE_METHOD_VAL
	    || DEFLATE_SIZE(p[2]) <= DEFLATE_MIN_SIZE
	    || p[3] != DEFLATE_CHK_SEQUENCE)
	    try.deflate_draft = 0;
	else if (DEFLATE_SIZE(p[2]) < go->deflate_size)
	    try.deflate_size = DEFLATE_SIZE(p[2]);
	len -= p[1];
	p += p[1];
    }

    if (!try.deflate_correct && !try.deflate_draft)
	try.deflate = 0;

    if (go->bsd_compress && len >= CILEN_BSD_COMPRESS &&
	p[0] == CI_BSD_COMPRESS) {
	no.bsd_compress = 1;
	/*
	 * Peer wants us to use a different number of bits
	 * or a different version.
	 */
	if (p[1] != CILEN_BSD_COMPRESS ||
	    BSD_VERSION(p[2]) != BSD_CURRENT_VERSION)
	    try.bsd_compress = 0;
	else if (BSD_NBITS(p[2]) < go->bsd_bits)
	    try.bsd_bits = BSD_NBITS(p[2]);
	len -= p[1];
	p += p[1];
    }

    /*
     * Predictor-1 and 2 have no options, so they can't be Naked.
     *
     * There may be remaining options but we ignore them.
     */

    if (f->state != OPENED)
	*go = try;
    return 1;
}

/*
 * ccp_rejci - peer rejects some of our suggested compression methods.
 */
static int
ccp_rejci(f, p, len)
    fsm *f;
    u_char *p;
    int len;
{
    ccp_options *go = &ccp_gotoptions[f->unit];
    ccp_options try;		/* options to request next time */

    try = *go;

    /*
     * Cope with empty configure-rejects by ceasing to send
     * configure-requests.
     */
    if (len == 0 && all_rejected[f->unit])
	return -1;

    if (go->deflate && go->deflate_correct && len >= CILEN_DEFLATE &&
	p[0] == CI_DEFLATE && p[1] == CILEN_DEFLATE) {
	if (p[2] != DEFLATE_MAKE_OPT(go->deflate_size)
	    || p[3] != DEFLATE_CHK_SEQUENCE)
	    return 0;		/* Rej is bad */
	try.deflate_correct = 0;
	p += CILEN_DEFLATE;
	len -= CILEN_DEFLATE;
    }
    if (go->deflate && go->deflate_draft && len >= CILEN_DEFLATE &&
	p[0] == CI_DEFLATE_DRAFT && p[1] == CILEN_DEFLATE) {
	if (p[2] != DEFLATE_MAKE_OPT(go->deflate_size)
	    || p[3] != DEFLATE_CHK_SEQUENCE)
	    return 0;		/* Rej is bad */
	try.deflate_draft = 0;
	p += CILEN_DEFLATE;
	len -= CILEN_DEFLATE;
    }
    if (!try.deflate_correct && !try.deflate_draft)
	try.deflate = 0;
    if (go->bsd_compress && len >= CILEN_BSD_COMPRESS
	&& p[0] == CI_BSD_COMPRESS && p[1] == CILEN_BSD_COMPRESS) {
	if (p[2] != BSD_MAKE_OPT(BSD_CURRENT_VERSION, go->bsd_bits))
	    return 0;
	try.bsd_compress = 0;
	p += CILEN_BSD_COMPRESS;
	len -= CILEN_BSD_COMPRESS;
    }
    if (go->predictor_1 && len >= CILEN_PREDICTOR_1
	&& p[0] == CI_PREDICTOR_1 && p[1] == CILEN_PREDICTOR_1) {
	try.predictor_1 = 0;
	p += CILEN_PREDICTOR_1;
	len -= CILEN_PREDICTOR_1;
    }
    if (go->predictor_2 && len >= CILEN_PREDICTOR_2
	&& p[0] == CI_PREDICTOR_2 && p[1] == CILEN_PREDICTOR_2) {
	try.predictor_2 = 0;
	p += CILEN_PREDICTOR_2;
	len -= CILEN_PREDICTOR_2;
    }

    if (len != 0)
	return 0;

    if (f->state != OPENED)
	*go = try;

    return 1;
}

/*
 * ccp_reqci - process a received configure-request.
 *
 * Returns CODE_CONFACK, CODE_CONFNAK or CODE_CONFREJ and the packet
 * is modified appropriately.
 */
static int
ccp_reqci(f, p, lenp, dont_nak)
    fsm *f;
    u_char *p;
    int *lenp;
    int dont_nak;
{
    int ret, newret, res;
    u_char *p0, *nakp, *rejp, *pv;
    int len, clen, type, nb;
    ccp_options *ho = &ccp_hisoptions[f->unit];
    ccp_options *ao = &ccp_allowoptions[f->unit];

    ret = CODE_CONFACK;
    rejp = p0 = p;
    nakp = nak_buffer;
    len = *lenp;

    BZERO(ho, sizeof(ccp_options));
    ho->method = (len > 0)? p[0]: -1;

    for (; len > 0; len -= clen, p += clen) {
	newret = CODE_CONFACK;
	if (len < 2 || p[1] > len) {
	    /*
	     * RFC 1661 page 40 -- if the option extends beyond the
	     * packet, then discard the entire packet.
	     */
	    return (0);
	}

	type = p[0];
	clen = p[1];

	pv = p;
	switch (type) {
	case CI_DEFLATE:
	case CI_DEFLATE_DRAFT:
	    if (!ao->deflate ||
		(!ao->deflate_correct && type == CI_DEFLATE) ||
		(!ao->deflate_draft && type == CI_DEFLATE_DRAFT)) {
		newret = CODE_CONFREJ;
		break;
	    }

	    ho->deflate = 1;
	    nb = clen < CILEN_DEFLATE ? ao->deflate_size : DEFLATE_SIZE(p[2]);
	    ho->deflate_size = nb;
	    if (clen != CILEN_DEFLATE ||
		DEFLATE_METHOD(p[2]) != DEFLATE_METHOD_VAL ||
		p[3] != DEFLATE_CHK_SEQUENCE || nb > ao->deflate_size ||
		nb <= DEFLATE_MIN_SIZE) {
		newret = CODE_CONFNAK;
		if (dont_nak)
		    break;
		if (nb > ao->deflate_size)
		    nb = ao->deflate_size;
		else if (nb <= DEFLATE_MIN_SIZE)
		    nb = DEFLATE_MIN_SIZE+1;
		pv = nakp;
		PUTCHAR(type, nakp);
		PUTCHAR(CILEN_DEFLATE, nakp);
		PUTCHAR(DEFLATE_MAKE_OPT(nb), nakp);
		PUTCHAR(DEFLATE_CHK_SEQUENCE, nakp);
	    }

	    /*
	     * Check whether we can do Deflate with the window
	     * size they want.  If the window is too big, reduce
	     * it until the kernel can cope and nak with that.
	     * We only check this for the first option.
	     */
	    if (p == p0) {
		for (;;) {
		    res = ccp_test(f->unit, pv, CILEN_DEFLATE, 1);
		    if (res > 0)
			break;		/* it's OK now */
		    if (res < 0 || nb <= DEFLATE_MIN_SIZE+1 || dont_nak) {
			newret = CODE_CONFREJ;
			break;
		    }
		    if (newret == CODE_CONFACK) {
			BCOPY(pv, nakp, CILEN_DEFLATE);
			pv = nakp;
			nakp += CILEN_DEFLATE;
			newret = CODE_CONFNAK;
		    }
		    --nb;
		    pv[2] = DEFLATE_MAKE_OPT(nb);
		}
#ifdef COMP_TUNE
		/* Tune Deflate compression effort. */
		if (newret == CODE_CONFACK)
		    ccp_tune(f->unit, deflate_tune);
#endif
	    }
	    break;

	case CI_BSD_COMPRESS:
	    if (!ao->bsd_compress) {
		newret = CODE_CONFREJ;
		break;
	    }

	    ho->bsd_compress = 1;
	    nb = clen < CILEN_BSD_COMPRESS ? ao->bsd_bits : BSD_NBITS(p[2]);
	    ho->bsd_bits = nb;
	    if (clen != CILEN_BSD_COMPRESS ||
		BSD_VERSION(p[2]) != BSD_CURRENT_VERSION ||
		nb > ao->bsd_bits || nb < BSD_MIN_BITS) {
		newret = CODE_CONFNAK;
		if (dont_nak)
		    break;
		if (nb > ao->bsd_bits)
		    nb = ao->bsd_bits;
		else if (nb < BSD_MIN_BITS)
		    nb = BSD_MIN_BITS;
		pv = nakp;
		PUTCHAR(type, nakp);
		PUTCHAR(CILEN_BSD_COMPRESS, nakp);
		PUTCHAR(BSD_MAKE_OPT(BSD_CURRENT_VERSION, nb), nakp);
	    }

	    /*
	     * Check whether we can do BSD-Compress with the code
	     * size they want.  If the code size is too big, reduce
	     * it until the kernel can cope and nak with that.
	     * We only check this for the first option.
	     */
	    if (p == p0) {
		for (;;) {
		    res = ccp_test(f->unit, pv, CILEN_BSD_COMPRESS, 1);
		    if (res > 0)
			break;
		    if (res < 0 || nb == BSD_MIN_BITS || dont_nak) {
			newret = CODE_CONFREJ;
			break;
		    }
		    if (newret == CODE_CONFACK) {
			BCOPY(pv, nakp, CILEN_BSD_COMPRESS);
			pv = nakp;
			nakp += CILEN_BSD_COMPRESS;
			newret = CODE_CONFNAK;
		    }
		    --nb;
		    pv[2] = BSD_MAKE_OPT(BSD_CURRENT_VERSION, nb);
		}
	    }
	    break;

	case CI_PREDICTOR_1:
	    if (!ao->predictor_1) {
		newret = CODE_CONFREJ;
		break;
	    }

	    ho->predictor_1 = 1;
	    if (clen != CILEN_PREDICTOR_1) {
		newret = CODE_CONFNAK;
		if (dont_nak)
		    break;
		pv = nakp;
		PUTCHAR(type, nakp);
		PUTCHAR(CILEN_PREDICTOR_1, nakp);
	    }
	    if (p == p0 &&
		ccp_test(f->unit, pv, CILEN_PREDICTOR_1, 1) <= 0) {
		newret = CODE_CONFREJ;
	    }
	    break;

	case CI_PREDICTOR_2:
	    if (!ao->predictor_2) {
		newret = CODE_CONFREJ;
		break;
	    }

	    ho->predictor_2 = 1;
	    if (clen != CILEN_PREDICTOR_2) {
		newret = CODE_CONFNAK;
		if (dont_nak)
		    break;
		pv = nakp;
		PUTCHAR(type, nakp);
		PUTCHAR(CILEN_PREDICTOR_2, nakp);
	    }
	    if (p == p0 &&
		ccp_test(f->unit, p, CILEN_PREDICTOR_2, 1) <= 0) {
		newret = CODE_CONFREJ;
	    }
	    break;

	default:
	    newret = CODE_CONFREJ;
	    break;
	}

	/* Cope with confused peers. */
	if (clen < 2)
	    clen = 2;

	if (newret == CODE_CONFACK && ret != CODE_CONFACK)
	    continue;
	if (newret == CODE_CONFNAK) {
	    if (dont_nak) {
		newret = CODE_CONFREJ;
	    } else {
		/* Ignore subsequent nakable things if rejecting. */
		if (ret == CODE_CONFREJ)
		    continue;
		ret = CODE_CONFNAK;
	    }
	}
	if (newret == CODE_CONFREJ) {
	    ret = CODE_CONFREJ;
	    if (p != rejp)
		BCOPY(p, rejp, clen);
	    rejp += clen;
	}
    }

    switch (ret) {
    case CODE_CONFACK:
	*lenp = p - p0;
	break;
    case CODE_CONFNAK:
	*lenp = nakp - nak_buffer;
	BCOPY(nak_buffer, p0, *lenp);
	break;
    case CODE_CONFREJ:
	*lenp = rejp - p0;
	break;
    }
    return ret;
}

/*
 * Make a string name for a compression method (or 2).
 */
static char *
method_name(opt, opt2)
    ccp_options *opt, *opt2;
{
    static char result[64];

    if (!ANY_COMPRESS(*opt))
	return "(none)";
    switch (opt->method) {
    case CI_DEFLATE:
    case CI_DEFLATE_DRAFT:
	if (opt2 != NULL && opt2->deflate_size != opt->deflate_size)
	    (void) slprintf(result, sizeof(result), "Deflate%s (%d/%d)",
		     (opt->method == CI_DEFLATE_DRAFT? "(old#)": ""),
		     opt->deflate_size, opt2->deflate_size);
	else
	    (void) slprintf(result, sizeof(result), "Deflate%s (%d)",
		     (opt->method == CI_DEFLATE_DRAFT? "(old#)": ""),
		     opt->deflate_size);
	break;
    case CI_BSD_COMPRESS:
	if (opt2 != NULL && opt2->bsd_bits != opt->bsd_bits)
	    (void) slprintf(result, sizeof(result), "BSD-Compress (%d/%d)",
		     opt->bsd_bits, opt2->bsd_bits);
	else
	    (void) slprintf(result, sizeof(result), "BSD-Compress (%d)",
		     opt->bsd_bits);
	break;
    case CI_PREDICTOR_1:
	return "Predictor 1";
    case CI_PREDICTOR_2:
	return "Predictor 2";
#ifdef CI_STAC
    case CI_STAC:
	return "Stac";
#endif
#ifdef CI_MPPC
    case CI_MPPC:
	return "MS-PPC";
#endif
    default:
	(void) slprintf(result, sizeof(result), "Method %d", opt->method);
    }
    return result;
}

/*
 * CCP has come up - inform the kernel driver and log a message.
 */
static void
ccp_up(f)
    fsm *f;
{
    ccp_options *go = &ccp_gotoptions[f->unit];
    ccp_options *ho = &ccp_hisoptions[f->unit];
    char method1[64];

    /*
     * We're now open and up (running).
     */
    ccp_flags_set(f->unit, 1, 1);
    if (ANY_COMPRESS(*go)) {
	if (ANY_COMPRESS(*ho)) {
	    if (go->method == ho->method) {
		notice("%s compression enabled", method_name(go, ho));
	    } else {
		(void) strlcpy(method1, method_name(go, NULL), sizeof(method1));
		notice("%s / %s compression enabled",
		       method1, method_name(ho, NULL));
	    }
	} else
	    notice("%s receive decompression enabled", method_name(go, NULL));
    } else if (ANY_COMPRESS(*ho))
	notice("%s transmit compression enabled", method_name(ho, NULL));
}

/*
 * CCP has gone down - inform the kernel driver.
 */
static void
ccp_down(f)
    fsm *f;
{
    if (ccp_localstate[f->unit] & RACK_PENDING)
	UNTIMEOUT(ccp_rack_timeout, f);
    /* Don't forget about peer's code rejects or ignoring of requests. */
    ccp_localstate[f->unit] &= ~RACK_PENDING & ~RREQ_REPEAT;
    /* We're still open, but no longer up. */
    ccp_flags_set(f->unit, 1, 0);
}

static int
ccp_printpkt(p, plen, printer, arg)
    u_char *p;
    int plen;
    void (*printer) __P((void *, const char *, ...));
    void *arg;
{
    u_char *p0, *optend, cichar;
    int code, id, len;
    int optlen, clen;
    u_short cishort;
#ifdef CI_MPPC
    u_int32_t cilong;
#endif

    p0 = p;
    if (plen < HEADERLEN) {
	printer(arg, "too short (%d<%d)", plen, HEADERLEN);
	return (0);
    }
    GETCHAR(code, p);
    GETCHAR(id, p);
    GETSHORT(len, p);

    printer(arg, " %s id=0x%x", code_name(code, 1), id);

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
    case CODE_CONFREQ:
    case CODE_CONFACK:
    case CODE_CONFNAK:
    case CODE_CONFREJ:
	/* print list of possible compression methods */
	while (len >= 2) {
	    GETCHAR(code, p);
	    GETCHAR(clen, p);
	    optlen = clen;
	    printer(arg, " <");
	    if (optlen > len)
		optlen = len;
	    if (optlen < 2)
		optlen = 2;
	    len -= optlen;
	    optend = p + optlen - 2;
	    switch (code) {
	    case CI_DEFLATE:
	    case CI_DEFLATE_DRAFT:
		printer(arg, "deflate%s",
		    (code == CI_DEFLATE_DRAFT? "(old#)": ""));
		if (clen != CILEN_DEFLATE)
		    printer(arg, " length %d", clen);
		if (optlen >= CILEN_DEFLATE) {
		    GETCHAR(cichar, p);
		    printer(arg, " %d", DEFLATE_SIZE(cichar));
		    if (DEFLATE_METHOD(cichar) != DEFLATE_METHOD_VAL)
			printer(arg, " method %d", DEFLATE_METHOD(cichar));
		    GETCHAR(cichar, p);
		    if (cichar != DEFLATE_CHK_SEQUENCE)
			printer(arg, " check %d", cichar);
		}
		break;
	    case CI_BSD_COMPRESS:
		printer(arg, "bsd");
		if (clen != CILEN_BSD_COMPRESS)
		    printer(arg, " length %d", clen);
		if (optlen >= CILEN_BSD_COMPRESS) {
		    GETCHAR(cichar, p);
		    printer(arg, " v%d %d", BSD_VERSION(cichar),
			BSD_NBITS(cichar));
		}
		break;
	    case CI_PREDICTOR_1:
		printer(arg, "predictor-1");
		if (clen != CILEN_PREDICTOR_1)
		    printer(arg, " length %d", clen);
		break;
	    case CI_PREDICTOR_2:
		printer(arg, "predictor-2");
		if (clen != CILEN_PREDICTOR_2)
		    printer(arg, " length %d", clen);
		break;
#ifdef CI_STAC
	    case CI_STAC:
		printer(arg, "Stac");
		if (clen != CILEN_STAC)
		    printer(arg, " length %d", clen);
		if (optlen >= CILEN_STAC) {
		    GETSHORT(cishort, p);
		    GETCHAR(cichar, p);
		    printer(arg, " h%d/m%d", cishort, cichar);
		}
		break;
#endif
#ifdef CI_MPPC
	    case CI_MPPC:
		/* There appears to be no good generic name for this one. */
		if (optlen >= CILEN_MPPC) {
		    GETLONG(cilong, p);
		    if (!(cilong & MPPC_COMP)) {
			if (cilong & MPPC_MPPE)
			    printer(arg, "MPPE");
			else
			    printer(arg, "MS-PPC?");
		    } else {
			if (cilong & MPPC_MPPE)
			    printer(arg, "MPPC+MPPE");
			else
			    printer(arg, "MPPC");
		    }
		} else {
		    printer(arg, "MS-?");
		}
		if (clen != CILEN_STAC)
		    printer(arg, " length %d", clen);
		break;
#endif
	    default:
		printer(arg, "typ%d len%d ", code, clen);
		break;
	    }
	    if (p < optend) {
		if (p+8 < optend)
		    printer(arg, " %.8B ...", p);
		else
		    printer(arg, " %.*B", optend-p, p);
		p = optend;
	    }
	    printer(arg, ">");
	}
	break;

    case CODE_TERMACK:
    case CODE_TERMREQ:
	if (len > 0) {
	    if (len == 2) {
		GETSHORT(cishort, p);
		printer(arg, " history %d", cishort);
		len = 0;
	    } else if (*p >= ' ' && *p < 0x7f) {
		printer(arg, " ");
		print_string((char *)p, len, printer, arg);
		p += len;
		len = 0;
	    }
	}
	break;
    }

    /* dump out the rest of the packet in hex */
    if (len > 0) {
	if (len > 8)
	    printer(arg, " %.8B ...", p);
	else
	    printer(arg, " %.*B", len, p);
	p += len;
    }

    return p - p0;
}

/*
 * We have received a packet that the decompressor failed to
 * decompress.  Here we would expect to issue a reset-request, but
 * Motorola has a patent on resetting the compressor as a result of
 * detecting an error in the decompressed data after decompression.
 * (See US patent 5,130,993; international patent publication number
 * WO 91/10289; Australian patent 73296/91.)
 *
 * So we ask the kernel whether the error was detected after
 * decompression; if it was, we take CCP down, thus disabling
 * compression :-(, otherwise we issue the reset-request.
 */
/*ARGSUSED*/
static void
ccp_datainput(unit, pkt, len)
    int unit;
    u_char *pkt;
    int len;
{
    fsm *f;

    f = &ccp_fsm[unit];
    if (f->state == OPENED) {
	if (ccp_fatal_error(unit)) {
	    /*
	     * Disable compression by taking CCP down.
	     */
	    error("Lost compression sync: disabling compression");
	    ccp_close(unit, "Lost compression sync");
	} else {
	    /*
	     * Send a reset-request to reset the peer's compressor, if
	     * possible.  We don't do anything if we are still waiting
	     * for an acknowledgement to a previous reset-request (to
	     * avoid flooding the peer).  We reopen CCP if the peer
	     * doesn't like hearing about CCP Reset-Request (Cisco
	     * sends CCP Code-Reject for Reset-Request).  (Reopen
	     * automatically clears the flags and cancels the
	     * timeout.)
	     */
	    if (ccp_localstate[f->unit] & RREQ_REJECTED) {
		dbglog("reopening CCP to reset peer's compressor");
		ccp_open(f->unit);
	    } else if (ccp_localstate[f->unit] & RACK_PENDING) {
		/* Send another reset request; we're out of sequence. */
		ccp_localstate[f->unit] |= RREQ_REPEAT;
	    } else {
		dbglog("sending CCP Reset-Request to reset peer's compressor");
		fsm_sdata(f, CCP_RESETREQ, f->reqid = ++f->id, NULL, 0);
		TIMEOUT(ccp_rack_timeout, f, RACKTIMEOUT);
		ccp_localstate[f->unit] |= RACK_PENDING;
	    }
	}
    }
}

/*
 * Timeout waiting for reset-ack.
 */
static void
ccp_rack_timeout(arg)
    void *arg;
{
    fsm *f = arg;

    /* Timeout; no longer pending. */
    ccp_localstate[f->unit] &= ~RACK_PENDING;

    /* Frankly, it's a coding flaw if this occurs. */
    if (f->state != OPENED)
	return;

    if (ccp_localstate[f->unit] & RREQ_IGNORED) {
	info("peer ignored our CCP Reset-Request twice; reopen instead");
	ccp_localstate[f->unit] =
	    (ccp_localstate[f->unit] & ~RREQ_IGNORED) | RREQ_REJECTED;
	ccp_open(f->unit);
    } else if (ccp_localstate[f->unit] & RREQ_REPEAT) {
	dbglog("sending another CCP Reset-Request on timeout");
	fsm_sdata(f, CCP_RESETREQ, f->reqid, NULL, 0);
	TIMEOUT(ccp_rack_timeout, f, RACKTIMEOUT);
	ccp_localstate[f->unit] =
	    (ccp_localstate[f->unit] & ~RREQ_REPEAT) | RREQ_IGNORED |
	    RACK_PENDING;
    } else {
	dbglog("timeout waiting for CCP Reset-Ack; hope for the best");
	ccp_localstate[f->unit] |= RREQ_IGNORED;
    }
}
