/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr3.2H 	*/

/*
 * Dump STREAMS module.  Could be used anywhere on a stream to
 * print all message headers and data on to the console.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/strsun.h>

#include <sys/conf.h>
#include <sys/modctl.h>

static char	hdr[100];	/* current message header */
static char  	hdrpad[100];	/* pad of same length as hdr[] */

/*
 * Raw buffer dumping routine.  Displays the contents of the first message in
 * message chain `mp', using the "traditional" dump format.
 *
 * For instance, "Hello STREAMS, panicked lately?" would be displayed as:
 *
 * RD 30001dbb240 M_DATA 48656C6C 6F205354 5245414D 532C2070  Hello STREAMS, p
 *                       616E6963 6B656420 6C617465 6C793F    anicked lately?
 *
 * If the character being displayed is not printable, a '.' is shown.
 */

#define	DEDUMP_HEXPERBLK	4
#define	DEDUMP_HEXLEN		(sizeof ("11223344") * 4)
#define	DEDUMP_ASCLEN		(sizeof ("0123456789ABCDEF") - 1)

static void
dedump_raw(mblk_t *mp)
{
	char	hex[DEDUMP_HEXLEN + 1], asc[DEDUMP_ASCLEN + 1];
	int	hexi = 0, asci = 0, i = 0;
	uchar_t	c;
	char	*hdrp = hdr;

	hex[DEDUMP_HEXLEN] = '\0';

	for (;;) {
		if (i == MBLKL(mp) || (i != 0 && (i % DEDUMP_ASCLEN) == 0)) {
			/*
			 * We're either out of data or we've filled a complete
			 * line.  In either case, print out what we've got --
			 * but first NUL-terminate asc[] and pad out hex[]
			 * with spaces.
			 */
			asc[asci] = '\0';
			(void) memset(hex + hexi, ' ', DEDUMP_HEXLEN - hexi);
			(void) printf("%s %s %s\n", hdrp, hex, asc);

			/*
			 * If we're out of data, bail.  Otherwise, reset asci
			 * and hexi for another lap around.  Also, set hdrp to
			 * the pad since we only want to show the header once.
			 */
			if (i == MBLKL(mp))
				break;
			asci = 0;
			hexi = 0;
			hdrp = hdrpad;
		}

		c = mp->b_rptr[i++];

		hexi += snprintf(hex + hexi, 3, "%02X", c);
		if ((i % DEDUMP_HEXPERBLK) == 0)
			hex[hexi++] = ' ';
		asc[asci++] = (c >= 32 && c <= 126) ? c : '.';
	}
}

static void
dedump_char(mblk_t *mp)
{
	(void) printf("%s 0x%x\n", hdr, *(uchar_t *)mp->b_rptr);
}

static void
dedump_int(mblk_t *mp)
{
	(void) printf("%s %d\n", hdr, *(int *)mp->b_rptr);
}

static void
dedump_ssize(mblk_t *mp)
{
	(void) printf("%s %ld\n", hdr, *(ssize_t *)mp->b_rptr);
}

static void
dedump_cmdblk(mblk_t *mp)
{
	struct cmdblk *cbp = (struct cmdblk *)mp->b_rptr;

	(void) printf("%s cmd %x cred %p len %u error %d\n", hdr, cbp->cb_cmd,
	    (void *)cbp->cb_cr, cbp->cb_len, cbp->cb_error);
}

static void
dedump_iocblk(mblk_t *mp)
{
	struct iocblk *ic = (struct iocblk *)mp->b_rptr;

	(void) printf("%s cmd %x cred %p id %u flag %x count %ld rval %d "
	    "err %d\n", hdr, ic->ioc_cmd, (void *)ic->ioc_cr, ic->ioc_id,
	    ic->ioc_flag, ic->ioc_count, ic->ioc_rval, ic->ioc_error);
}

static void
dedump_stroptions(mblk_t *mp)
{
	struct stroptions *so = (struct stroptions *)mp->b_rptr;

	(void) printf("%s flag %x readopt %d wroff %u\n", hdr,
	    so->so_flags, so->so_readopt, so->so_wroff);

	(void) printf("%s minpsz %ld maxpsz %ld hiwat %lu lowat %lu\n", hdrpad,
	    so->so_minpsz, so->so_maxpsz, so->so_hiwat, so->so_lowat);

	(void) printf("%s band %u erropt %u maxblk %ld copyopt %u\n", hdrpad,
	    so->so_band, so->so_erropt, so->so_maxblk, so->so_copyopt);
}

static void
dedump_copyreq(mblk_t *mp)
{
	struct copyreq *cq = (struct copyreq *)mp->b_rptr;

	(void) printf("%s cmd %x cred %p id %u flag %x priv %p addr %p size "
	    "%lu\n", hdr, cq->cq_cmd, (void *)cq->cq_cr, cq->cq_id, cq->cq_flag,
	    (void *)cq->cq_private, (void *)cq->cq_addr, cq->cq_size);
}

static void
dedump_copyresp(mblk_t *mp)
{
	struct copyresp *cp = (struct copyresp *)mp->b_rptr;

	(void) printf("%s cmd %x cred %p id %u flag %x priv %p rval %p\n", hdr,
	    cp->cp_cmd, (void *)cp->cp_cr, cp->cp_id, cp->cp_flag,
	    (void *)cp->cp_private, (void *)cp->cp_rval);
}

typedef struct msgfmt {
	uchar_t	m_type;
	char	m_desc[15];
	void	(*m_print)(mblk_t *);
} msgfmt_t;

static msgfmt_t msgfmt[256] = {
	{	M_DATA,		"M_DATA    ", 	dedump_raw		},
	{	M_PROTO,	"M_PROTO   ", 	dedump_raw		},
	{	M_BREAK,	"M_BREAK   ", 	dedump_raw		},
	{	M_PASSFP,	"M_PASSFP  ", 	dedump_raw		},
	{	M_EVENT,	"M_EVENT   ", 	dedump_raw		},
	{	M_SIG,		"M_SIG     ", 	dedump_char		},
	{	M_DELAY,	"M_DELAY   ", 	dedump_int		},
	{	M_CTL,		"M_CTL     ", 	dedump_raw		},
	{	M_IOCTL,	"M_IOCTL   ", 	dedump_iocblk		},
	{	M_SETOPTS,	"M_SETOPTS ", 	dedump_stroptions	},
	{	M_RSE,		"M_RSE     ", 	dedump_raw		},
	{	M_IOCACK,	"M_IOCACK  ", 	dedump_iocblk		},
	{	M_IOCNAK,	"M_IOCNAK  ", 	dedump_iocblk		},
	{	M_PCPROTO,	"M_PCPROTO ", 	dedump_raw		},
	{	M_PCSIG,	"M_PCSIG   ", 	dedump_char		},
	{	M_READ,		"M_READ    ", 	dedump_ssize		},
	{	M_FLUSH,	"M_FLUSH   ", 	dedump_char		},
	{	M_STOP,		"M_STOP    ", 	dedump_raw		},
	{	M_START,	"M_START   ", 	dedump_raw		},
	{	M_HANGUP,	"M_HANGUP  ", 	dedump_raw		},
	{	M_ERROR,	"M_ERROR   ", 	dedump_char		},
	{	M_COPYIN,	"M_COPYIN  ", 	dedump_copyreq		},
	{	M_COPYOUT,	"M_COPYOUT ", 	dedump_copyreq		},
	{	M_IOCDATA,	"M_IOCDATA ", 	dedump_copyresp		},
	{	M_PCRSE,	"M_PCRSE   ", 	dedump_raw		},
	{	M_STOPI,	"M_STOPI   ", 	dedump_raw		},
	{	M_STARTI,	"M_STARTI  ", 	dedump_raw		},
	{	M_PCEVENT,	"M_PCEVENT ", 	dedump_raw		},
	{	M_UNHANGUP,	"M_UNHANGUP", 	dedump_raw		},
	{	M_CMD,		"M_CMD     ", 	dedump_cmdblk		},
};

/*ARGSUSED1*/
static int
dedumpopen(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *crp)
{
	if (!sflag)
		return (ENXIO);

	if (q->q_ptr)
		return (0);		/* already attached */

	qprocson(q);
	return (0);
}

/*ARGSUSED1*/
static int
dedumpclose(queue_t *q, int flag, cred_t *crp)
{
	qprocsoff(q);
	return (0);
}

/*
 * Common put procedure for upstream and downstream.
 */
static int
dedumpput(queue_t *q, mblk_t *mp)
{
	unsigned char type = DB_TYPE(mp);
	ssize_t hdrlen;

	hdrlen = snprintf(hdr, sizeof (hdr), "%s %p %10s ",
	    (q->q_flag & QREADR) ? "RD" : "WR", (void *)q, msgfmt[type].m_desc);

	hdrpad[hdrlen] = '\0';
	msgfmt[type].m_print(mp);
	hdrpad[hdrlen] = ' ';

	putnext(q, mp);
	return (0);
}

struct module_info dedump_minfo = {
	0xaaa, "dedump", 0, INFPSZ, 0, 0
};

struct qinit dedumprinit = {
	dedumpput, NULL, dedumpopen, dedumpclose, NULL, &dedump_minfo, NULL
};

struct qinit dedumpwinit = {
	dedumpput, NULL, NULL, NULL, NULL, &dedump_minfo, NULL
};

struct streamtab dedumpinfo = {
	&dedumprinit, &dedumpwinit, NULL, NULL,
};

static struct fmodsw fsw = {
	"dedump",
	&dedumpinfo,
	D_MP | D_MTPERMOD	/* just to serialize printfs */
};

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "dump streams module", &fsw
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlstrmod, NULL
};

int
_init(void)
{
	int i;
	msgfmt_t mf;

	/*
	 * Sort msgfmt[] so that msgfmt[n] describes message type n.
	 */
	for (i = 255; i != 0; i--) {
		mf = msgfmt[i];
		msgfmt[i].m_type = i;
		(void) sprintf(msgfmt[i].m_desc, "M_BOGUS_0x%x", i);
		msgfmt[i].m_print = dedump_raw;
		if (mf.m_desc[0] != 0)
			msgfmt[mf.m_type] = mf;
	}

	/*
	 * Fill hdrpad[] with as many spaces as will fit.
	 */
	(void) memset(hdrpad, ' ', sizeof (hdrpad) - 1);
	hdrpad[sizeof (hdrpad) - 1] = '\0';

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
