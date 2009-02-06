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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/note.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/adapters/blk2scsa.h>

/*
 * We implement the following SCSI-2 commands on behalf of targets:
 *
 * SCMD_DOORLOCK
 * SCMD_FORMAT
 * SCMD_INQUIRY
 * SCMD_MODE_SENSE
 * SCMD_READ
 * SCMD_READ_G1
 * SCMD_READ_CAPACITY
 * SCMD_RELEASE
 * SCMD_REQUEST_SENSE
 * SCMD_RESERVE
 * SCMD_SDIAG
 * SCMD_START_STOP
 * SCMD_TEST_UNIT_READY
 * SCMD_WRITE
 * SCMD_WRITE_G1
 *
 * We really should, at some point in the future, investigate offering
 * more complete SCSI-3 commands, including the G4 and G5 variants of
 * READ and WRITE, MODE_SELECT, PERSISTENT_RESERVE_IN,
 * PERSISTENT_RESERVE_OUT, SYNCHRONIZE_CACHE, READ_MEDIAL_SERIAL,
 * REPORT_LUNS, etc.
 */

typedef struct b2s_request_impl b2s_request_impl_t;

struct b2s_request_impl {
	b2s_request_t		ri_public;
	struct scsi_pkt		*ri_pkt;
	struct scsi_arq_status	*ri_sts;
	buf_t			*ri_bp;

	size_t			ri_resid;
	b2s_nexus_t		*ri_nexus;
	b2s_leaf_t		*ri_leaf;
	void			(*ri_done)(struct b2s_request_impl *);
};

#define	ri_lun		ri_public.br_lun
#define	ri_target	ri_public.br_target
#define	ri_cmd		ri_public.br_cmd
#define	ri_errno	ri_public.br_errno
#define	ri_count	ri_public.br_count
#define	ri_xfered	ri_public.br_xfered

#define	ri_flags	ri_public.br_flags
#define	ri_media	ri_public.br_media
#define	ri_inquiry	ri_public.br_inquiry
#define	ri_lba		ri_public.br_lba
#define	ri_nblks	ri_public.br_nblks

struct b2s_nexus {
	dev_info_t		*n_dip;
	struct scsi_hba_tran	*n_tran;
	void			*n_private;
	ddi_dma_attr_t		*n_dma;
	boolean_t		(*n_request)(void *, b2s_request_t *);

	kmutex_t		n_lock;
	kcondvar_t		n_cv;
	boolean_t		n_attached;
	list_t			n_leaves;
};
#define	B2S_NEXUS_ATTACHED	(1U << 0)

_NOTE(MUTEX_PROTECTS_DATA(b2s_nexus::n_lock, b2s_nexus::n_leaves))
_NOTE(SCHEME_PROTECTS_DATA("stable data", b2s_nexus::n_dip))
_NOTE(SCHEME_PROTECTS_DATA("stable data", b2s_nexus::n_private))
_NOTE(SCHEME_PROTECTS_DATA("stable data", b2s_nexus::n_request))
_NOTE(SCHEME_PROTECTS_DATA("stable data", b2s_nexus::n_dma))
_NOTE(SCHEME_PROTECTS_DATA("stable data", b2s_nexus::n_tran))
_NOTE(SCHEME_PROTECTS_DATA("client synchronized", b2s_nexus::n_attached))

struct b2s_leaf {
	b2s_nexus_t		*l_nexus;
	uint_t			l_target;
	uint_t			l_lun;
	uint32_t		l_flags;
	char			*l_uuid;
	uint32_t		l_refcnt;
	list_node_t		l_node;
	struct scsi_inquiry	l_inq;
};

_NOTE(MUTEX_PROTECTS_DATA(b2s_nexus::n_lock, b2s_leaf::l_node))
_NOTE(MUTEX_PROTECTS_DATA(b2s_nexus::n_lock, b2s_leaf::l_refcnt))
_NOTE(MUTEX_PROTECTS_DATA(b2s_nexus::n_lock, b2s_leaf::l_uuid))
_NOTE(MUTEX_PROTECTS_DATA(b2s_nexus::n_lock, b2s_leaf::l_lun))
_NOTE(MUTEX_PROTECTS_DATA(b2s_nexus::n_lock, b2s_leaf::l_target))
_NOTE(MUTEX_PROTECTS_DATA(b2s_nexus::n_lock, b2s_leaf::l_nexus))
_NOTE(DATA_READABLE_WITHOUT_LOCK(b2s_leaf::l_uuid))
_NOTE(DATA_READABLE_WITHOUT_LOCK(b2s_leaf::l_lun))
_NOTE(DATA_READABLE_WITHOUT_LOCK(b2s_leaf::l_target))
_NOTE(DATA_READABLE_WITHOUT_LOCK(b2s_leaf::l_nexus))

_NOTE(SCHEME_PROTECTS_DATA("stable data", scsi_hba_tran))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", b2s_request_impl))
_NOTE(SCHEME_PROTECTS_DATA("unique per packet", scsi_arq_status))
_NOTE(SCHEME_PROTECTS_DATA("unique per packet", scsi_pkt))
_NOTE(SCHEME_PROTECTS_DATA("unique per packet", scsi_inquiry))
_NOTE(SCHEME_PROTECTS_DATA("client synchronized", b2s_leaf::l_flags))

/*
 * This copies a string into a target buf, obeying the size limits
 * of the target.  It does not null terminate, ever.
 */
#define	COPYSTR(src, dst)	bcopy(src, dst, min(strlen(src), sizeof (dst)))

/*
 * Thank you SCSA, for making it a PITA to deal with a single byte
 * value by turning it into a bitfield!
 */
#define	PUTSTAT(dst, val)	(*((uint8_t *)(void *)&dst) = val)

struct b2s_error {
	uint8_t			e_reason;	/* scsi CMD_xxx reason */
	uint8_t			e_status;	/* scsi STATUS_xxx code */
	uint8_t			e_skey;		/* sense key */
	uint8_t			e_asc;		/* additional sense code */
	uint8_t			e_ascq;		/* sense code qualifier */
	uint8_t			e_sksv[3];	/* sense key specific-value */
};

static struct b2s_error b2s_errs[B2S_NERRS];

static struct modlmisc modlmisc = {
	&mod_miscops,
	"SCSA Block Device Emulation",
};

static struct modlinkage modlinkage = {
	MODREV_1, { &modlmisc, NULL }
};

/*
 * For layers that don't provide a DMA attribute, we offer a default
 * one.  Such devices probably just want to do mapin, all of the time,
 * but since SCSI doesn't give us a way to indicate that, we have to
 * provide a fake attribute.  Slightly wasteful, but PIO-only disk
 * devices are going to have some performance issues anyway.
 *
 * For such devices, we only want to commit to transferring 64K at a time,
 * and let the SCSA layer break it up for us.
 */
static struct ddi_dma_attr b2s_default_dma_attr =  {
	DMA_ATTR_V0,
	0,			/* lo address */
	0xffffffffffffffffULL,	/* high address */
	0xffffU,		/* DMA counter max */
	1,			/* alignment */
	0x0c,			/* burst sizes */
	1,			/* minimum transfer size */
	0xffffU,		/* maximum transfer size */
	0xffffU,		/* maximum segment size */
	1,			/* scatter/gather list length */
	1,			/* granularity */
	0			/* DMA flags */
};


/*
 * Private prototypes.
 */

static int b2s_tran_tgt_init(dev_info_t *, dev_info_t *,
    scsi_hba_tran_t *, struct scsi_device *);
static void b2s_tran_tgt_free(dev_info_t *, dev_info_t *,
    scsi_hba_tran_t *, struct scsi_device *);
static int b2s_tran_getcap(struct scsi_address *, char *, int);
static int b2s_tran_setcap(struct scsi_address *, char *, int, int);
static void b2s_tran_destroy_pkt(struct scsi_address *, struct scsi_pkt *);
static struct scsi_pkt *b2s_tran_init_pkt(struct scsi_address *,
    struct scsi_pkt *, struct buf *, int, int, int, int,
    int (*)(caddr_t), caddr_t);
static int b2s_tran_start(struct scsi_address *, struct scsi_pkt *);
static int b2s_tran_abort(struct scsi_address *, struct scsi_pkt *);
static int b2s_tran_reset(struct scsi_address *, int);
static int b2s_bus_config(dev_info_t *, uint_t, ddi_bus_config_op_t, void *,
    dev_info_t **);
static b2s_leaf_t *b2s_hold_leaf(b2s_nexus_t *, uint_t, uint_t);
static dev_info_t *b2s_find_node(b2s_nexus_t *, b2s_leaf_t *);
static int b2s_create_node(b2s_nexus_t *, b2s_leaf_t *, dev_info_t **);
static int b2s_update_props(dev_info_t *, b2s_leaf_t *, char **, int);
static void b2s_inquiry_done(b2s_request_impl_t *);
static int b2s_inquiry(b2s_leaf_t *);
static void b2s_init_err_table(void);
static int b2s_scmd_inq(b2s_request_impl_t *);
static int b2s_scmd_tur(b2s_request_impl_t *);
static int b2s_scmd_doorlock(b2s_request_impl_t *);
static int b2s_scmd_format(b2s_request_impl_t *);
static int b2s_scmd_readcap(b2s_request_impl_t *);
static int b2s_scmd_rw(b2s_request_impl_t *);
static int b2s_scmd_rqs(b2s_request_impl_t *);
static int b2s_scmd_sdiag(b2s_request_impl_t *);
static int b2s_scmd_start_stop(b2s_request_impl_t *);
static int b2s_scmd_mode_sense(b2s_request_impl_t *);
static int b2s_scmd_reserve_release(b2s_request_impl_t *);
static void b2s_scmd_readcap_done(b2s_request_impl_t *);
static void b2s_scmd_mode_sense_done(b2s_request_impl_t *);
static void b2s_warn(b2s_leaf_t *, const char *, ...);

int
_init(void)
{
	int	rv;

	b2s_init_err_table();
	rv = mod_install(&modlinkage);
	return (rv);
}

int
_fini(void)
{
	int	rv;

	rv = mod_remove(&modlinkage);
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
b2s_mod_init(struct modlinkage *modlp)
{
	return (scsi_hba_init(modlp));
}

void
b2s_mod_fini(struct modlinkage *modlp)
{
	scsi_hba_fini(modlp);
}

void
b2s_init_err_table(void)
{
	int	i;

	/* fill up most of them with defaults */
	for (i = 0; i < B2S_NERRS; i++) {
		b2s_errs[i].e_reason = CMD_CMPLT;
		b2s_errs[i].e_status = STATUS_CHECK;
		b2s_errs[i].e_skey = KEY_NO_SENSE;
		b2s_errs[i].e_asc = 0;
		b2s_errs[i].e_ascq = 0;
		b2s_errs[i].e_sksv[0] = 0;
		b2s_errs[i].e_sksv[1] = 0;
		b2s_errs[i].e_sksv[2] = 0;
	}

	/* now flesh out real values */
	b2s_errs[B2S_EOK].e_status = STATUS_GOOD;

	b2s_errs[B2S_ENOTSUP].e_skey = KEY_ILLEGAL_REQUEST;
	b2s_errs[B2S_ENOTSUP].e_asc = 0x20;

	b2s_errs[B2S_EFORMATTING].e_skey = KEY_NOT_READY;
	b2s_errs[B2S_EFORMATTING].e_asc = 0x04;
	b2s_errs[B2S_EFORMATTING].e_ascq = 0x04;
	b2s_errs[B2S_EFORMATTING].e_sksv[0] = 0x80;

	b2s_errs[B2S_ENOMEDIA].e_skey = KEY_NOT_READY;
	b2s_errs[B2S_ENOMEDIA].e_asc = 0x3A;

	b2s_errs[B2S_EMEDIACHG].e_skey = KEY_UNIT_ATTENTION;
	b2s_errs[B2S_EMEDIACHG].e_asc = 0x28;

	b2s_errs[B2S_ESTOPPED].e_skey = KEY_NOT_READY;
	b2s_errs[B2S_ESTOPPED].e_asc = 0x04;
	b2s_errs[B2S_ESTOPPED].e_ascq = 0x02;

	b2s_errs[B2S_EBLKADDR].e_skey = KEY_ILLEGAL_REQUEST;
	b2s_errs[B2S_EBLKADDR].e_asc = 0x21;

	b2s_errs[B2S_EIO].e_skey = KEY_HARDWARE_ERROR;
	b2s_errs[B2S_EIO].e_asc = 0x08;
	b2s_errs[B2S_EIO].e_ascq = 0x00;

	b2s_errs[B2S_EHARDWARE].e_skey = KEY_HARDWARE_ERROR;
	b2s_errs[B2S_EHARDWARE].e_asc = 0x44;

	b2s_errs[B2S_ENODEV].e_reason = CMD_DEV_GONE;

	b2s_errs[B2S_EMEDIA].e_skey = KEY_MEDIUM_ERROR;

	b2s_errs[B2S_EDOORLOCK].e_skey = KEY_NOT_READY;
	b2s_errs[B2S_EDOORLOCK].e_asc = 0x53;
	b2s_errs[B2S_EDOORLOCK].e_ascq = 0x02;

	b2s_errs[B2S_EWPROTECT].e_skey = KEY_DATA_PROTECT;
	b2s_errs[B2S_EWPROTECT].e_asc = 0x27;

	b2s_errs[B2S_ESTARTING].e_skey = KEY_NOT_READY;
	b2s_errs[B2S_ESTARTING].e_asc = 0x04;
	b2s_errs[B2S_ESTARTING].e_ascq = 0x01;

	b2s_errs[B2S_ETIMEDOUT].e_skey = KEY_ABORTED_COMMAND;
	b2s_errs[B2S_ETIMEDOUT].e_asc = 0x08;
	b2s_errs[B2S_ETIMEDOUT].e_ascq = 0x01;

	/*
	 * This one, SYSTEM_RESOURCE_FAILURE, is not really legal for
	 * DTYPE_DIRECT in SCSI-2, but sd doesn't care, and reporting
	 * it this way may help diagnosis.  sd will retry it in any
	 * case.
	 */
	b2s_errs[B2S_ENOMEM].e_skey = KEY_ABORTED_COMMAND;
	b2s_errs[B2S_ENOMEM].e_asc = 0x55;

	b2s_errs[B2S_ERESET].e_reason = CMD_RESET;

	b2s_errs[B2S_EABORT].e_reason = CMD_ABORTED;

	b2s_errs[B2S_ERSVD].e_status = STATUS_RESERVATION_CONFLICT;

	b2s_errs[B2S_EINVAL].e_skey = KEY_ILLEGAL_REQUEST;
	b2s_errs[B2S_EINVAL].e_asc = 0x24;

	b2s_errs[B2S_EPARAM].e_skey = KEY_ILLEGAL_REQUEST;
	b2s_errs[B2S_EPARAM].e_asc = 0x26;

	b2s_errs[B2S_EBADMSG].e_reason = CMD_BADMSG;
}

/*
 * Locate the the leaf node for the given target/lun.  This must be
 * called with the nexus lock held.
 */
b2s_leaf_t *
b2s_get_leaf(b2s_nexus_t *n, uint_t target, uint_t lun)
{
	b2s_leaf_t *l;

	ASSERT(mutex_owned(&n->n_lock));

	l = list_head(&n->n_leaves);
	while (l != NULL) {
		ASSERT(l->l_nexus == n);
		if ((l->l_target == target) && (l->l_lun == lun)) {
			break;
		}
		l = list_next(&n->n_leaves, l);
	}

	return (l);
}

/*
 * Locate the the leaf node for the given target/lun, and hold it.  The
 * nexus lock must *NOT* be held.
 */
b2s_leaf_t *
b2s_hold_leaf(b2s_nexus_t *n, uint_t target, uint_t lun)
{
	b2s_leaf_t	*l;

	mutex_enter(&n->n_lock);
	l = b2s_get_leaf(n, target, lun);
	if (l != NULL) {
		l->l_refcnt++;
	}
	mutex_exit(&n->n_lock);
	return (l);
}

/*
 * Drop the hold on the leaf.
 */
void
b2s_rele_leaf(b2s_leaf_t *l)
{
	b2s_nexus_t *n = l->l_nexus;
	mutex_enter(&n->n_lock);
	l->l_refcnt--;
	if (l->l_refcnt == 0) {
		list_remove(&n->n_leaves, l);
		kmem_free(l->l_uuid, strlen(l->l_uuid) + 1);
		kmem_free(l, sizeof (*l));
	}
	mutex_exit(&n->n_lock);
}

/*
 * This is used to walk the list of leaves safely, without requiring the
 * nexus lock to be held.  The returned leaf is held.  (If the passed in
 * lastl is not NULL, then it is released as well.)
 *
 * Pass NULL for lastl to start the walk.
 */
b2s_leaf_t *
b2s_next_leaf(b2s_nexus_t *n, b2s_leaf_t *lastl)
{
	b2s_leaf_t *l;

	mutex_enter(&n->n_lock);
	if (lastl == NULL) {
		l = list_head(&n->n_leaves);
	} else {
		l = list_next(&n->n_leaves, lastl);
	}
	if (l != NULL) {
		l->l_refcnt++;
	}
	mutex_exit(&n->n_lock);

	if (lastl != NULL) {
		b2s_rele_leaf(lastl);
	}

	return (l);
}

void
b2s_request_mapin(b2s_request_t *req, caddr_t *addrp, size_t *lenp)
{
	b2s_request_impl_t	 *ri = (void *)req;
	buf_t			*bp;

	if (((bp = ri->ri_bp) != NULL) && (bp->b_bcount != 0)) {
		*addrp = bp->b_un.b_addr;
		*lenp = bp->b_bcount;
	} else {
		*addrp = 0;
		*lenp = 0;
	}
}

void
b2s_request_dma(b2s_request_t *req, uint_t *ndmacp, ddi_dma_cookie_t **dmacsp)
{
	/*
	 * We don't support direct DMA right now... there are no
	 * clients that need it.  Frankly, bcopy is safer right now.
	 */
	_NOTE(ARGUNUSED(req));

	*ndmacp = 0;
	*dmacsp = NULL;
}

void
b2s_request_done_pkt(b2s_request_impl_t *ri)
{
	struct scsi_pkt		*pkt;
	uint8_t			status;
	struct scsi_arq_status	*sts = ri->ri_sts;
	b2s_err_t		err;

	err = ri->ri_errno;

	pkt = ri->ri_pkt;
	pkt->pkt_resid = ri->ri_resid;

	bzero(sts, sizeof (*sts));

	/*
	 * Make sure that the status is in range of our known errs.  If we
	 * don't know it, then just cobble up a bogus one.
	 */
	if ((err < 0) || (err >= B2S_NERRS)) {
		pkt->pkt_reason = CMD_TRAN_ERR;
	} else {
		pkt->pkt_reason = b2s_errs[err].e_reason;
		status = b2s_errs[err].e_status;
	}

	if (pkt->pkt_reason == CMD_CMPLT) {

		pkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS;

		PUTSTAT(sts->sts_status, status);

		if (status == STATUS_CHECK) {
			/*
			 * Contingent allegiance.  We need to do the
			 * ARQ thing.
			 */
			PUTSTAT(sts->sts_rqpkt_status, STATUS_GOOD);

			sts->sts_rqpkt_reason = CMD_CMPLT;
			sts->sts_rqpkt_resid = 0;
			sts->sts_rqpkt_state = STATE_XFERRED_DATA |
			    STATE_GOT_BUS | STATE_GOT_STATUS;

			sts->sts_sensedata.es_valid = 1;
			sts->sts_sensedata.es_class = CLASS_EXTENDED_SENSE;
			sts->sts_sensedata.es_key = b2s_errs[err].e_skey;
			sts->sts_sensedata.es_add_code = b2s_errs[err].e_asc;
			sts->sts_sensedata.es_qual_code = b2s_errs[err].e_ascq;
			bcopy(sts->sts_sensedata.es_skey_specific,
			    b2s_errs[err].e_sksv, 3);
			/*
			 * Stash any residue information.
			 */
			sts->sts_sensedata.es_info_1 =
			    (ri->ri_resid >> 24) & 0xff;
			sts->sts_sensedata.es_info_2 =
			    (ri->ri_resid >> 16) & 0xff;
			sts->sts_sensedata.es_info_3 =
			    (ri->ri_resid >> 8) & 0xff;
			sts->sts_sensedata.es_info_4 =
			    (ri->ri_resid) & 0xff;

			pkt->pkt_state |= STATE_ARQ_DONE;
		}

	} else if (pkt->pkt_reason == CMD_ABORTED) {
		pkt->pkt_statistics |= STAT_ABORTED;
	} else if (pkt->pkt_reason == CMD_RESET) {
		pkt->pkt_statistics |= STAT_DEV_RESET;
	} else {
		pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD;
	}

	/*
	 * N.B.: Obviously not all commands actually have a SCSI
	 * DATA-IN or DATA-OUT phase.  But it doesn't matter, since
	 * sd.c only bothers to look at this flag for request sense
	 * traffic, which is always correct within our emulation.
	 *
	 * We go ahead and set it on all good packets however, since
	 * there may in the future be some additional checks to make
	 * sure a data transfer occurred.  This seems safer (since
	 * then sd should examine pkt_resid) rather than leaving it
	 * off by default.
	 */
	if (ri->ri_errno == 0) {
		pkt->pkt_state |= STATE_XFERRED_DATA;
	}

	/*
	 * Finally, execute the callback (unless running POLLED)
	 */
	if ((pkt->pkt_flags & FLAG_NOINTR) == 0) {
		scsi_hba_pkt_comp(pkt);
	}

}

void
b2s_request_done(b2s_request_t *req, b2s_err_t err, size_t resid)
{
	b2s_request_impl_t	*ri = (void *)req;

	ri->ri_errno = err;
	ri->ri_resid = (ssize_t)resid;

	/*
	 * Post process...  this is used for massaging results into
	 * what SCSI wants.
	 */
	if (ri->ri_done != NULL)
		ri->ri_done(ri);

	/*
	 * Undo the effect of any specific mapin that may have been done to
	 * process the request.
	 */
	if (ri->ri_flags & B2S_REQUEST_FLAG_MAPIN) {
		bp_mapout(ri->ri_bp);
		ri->ri_flags &= ~B2S_REQUEST_FLAG_MAPIN;
	}

	/*
	 * For SCSI packets, we have special completion handling.  For
	 * internal requests, we just mark the request done so the caller
	 * can free it.
	 */
	if (ri->ri_pkt == NULL) {
		b2s_nexus_t	*n = ri->ri_nexus;

		mutex_enter(&n->n_lock);
		ri->ri_flags |= B2S_REQUEST_FLAG_DONE;
		cv_broadcast(&n->n_cv);
		mutex_exit(&n->n_lock);
	} else {
		b2s_request_done_pkt(ri);
	}
}

int
b2s_tran_tgt_init(dev_info_t *hbadip, dev_info_t *tgtdip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	uint_t		tgt, lun;
	b2s_nexus_t	*n;
	b2s_leaf_t	*l;

	_NOTE(ARGUNUSED(hbadip));
	_NOTE(ARGUNUSED(sd));

	/*
	 * Lookup the target and lun.
	 */
	tgt = (uint_t)ddi_prop_get_int(DDI_DEV_T_ANY, tgtdip,
	    DDI_PROP_DONTPASS, "target", -1);

	lun = (uint_t)ddi_prop_get_int(DDI_DEV_T_ANY, tgtdip,
	    DDI_PROP_DONTPASS, "lun", -1);

	n = tran->tran_hba_private;

	/*
	 * Hold the leaf node as long as the devinfo node is using it.
	 */
	l = b2s_hold_leaf(n, tgt, lun);
	if (l == NULL) {
		/*
		 * Target node not found on bus.
		 */
		return (DDI_FAILURE);
	}
	tran->tran_tgt_private = l;

	return (DDI_SUCCESS);
}

void
b2s_tran_tgt_free(dev_info_t *hbadip, dev_info_t *tgtdip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	b2s_leaf_t	*l;

	_NOTE(ARGUNUSED(hbadip));
	_NOTE(ARGUNUSED(tgtdip));
	_NOTE(ARGUNUSED(sd));

	l = tran->tran_tgt_private;
	ASSERT(l != NULL);
	b2s_rele_leaf(l);
}

struct scsi_pkt *
b2s_tran_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
    struct buf *bp, int cmdlen, int statuslen, int tgtlen, int flags,
    int (*cb)(caddr_t), caddr_t cbarg)
{
	int			(*func)(caddr_t);
	dev_info_t		*dip;
	scsi_hba_tran_t		*tran;
	b2s_request_impl_t	*ri;

	_NOTE(ARGUNUSED(flags));
	_NOTE(ARGUNUSED(cbarg));

	tran = ap->a_hba_tran;
	dip = tran->tran_hba_dip;

	/*
	 * We just unconditionally map this in for now.  This makes
	 * sure that we will always have kernel virtual addresses for
	 * copying with.
	 */
	if (bp && (bp->b_bcount)) {
		bp_mapin(bp);
	}

	if (pkt == NULL) {
		func = (cb == SLEEP_FUNC) ? SLEEP_FUNC : NULL_FUNC;
		pkt = scsi_hba_pkt_alloc(dip, ap, cmdlen, statuslen,
		    tgtlen, sizeof (b2s_request_impl_t), func, NULL);
		if (pkt == NULL)
			return (NULL);

		ri = pkt->pkt_ha_private;
		ri->ri_pkt = pkt;
		ri->ri_sts = (struct scsi_arq_status *)(void *)pkt->pkt_scbp;
		ri->ri_bp = bp;

		/*
		 * NB: This would be the time to do DMA allocation.
		 */
	}

	return (pkt);
}

void
b2s_tran_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	scsi_hba_pkt_free(ap, pkt);
}

int
b2s_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	int	capid;

	_NOTE(ARGUNUSED(ap));
	_NOTE(ARGUNUSED(whom));

	capid = scsi_hba_lookup_capstr(cap);

	switch (capid) {
	case SCSI_CAP_ARQ:
	case SCSI_CAP_UNTAGGED_QING:
		return (1);
	case SCSI_CAP_DMA_MAX:
		return (65536);

	default:
		return (-1);
	}
}

int
b2s_tran_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	b2s_request_impl_t	*ri;
	b2s_nexus_t		*n = ap->a_hba_tran->tran_hba_private;
	b2s_leaf_t		*l = ap->a_hba_tran->tran_tgt_private;
	int			err;

	/*
	 * We can only do the blind abort of all packets.  We have
	 * no way to request an individual packet be aborted.
	 */
	if (pkt != NULL) {
		return (B_FALSE);
	}

	ri = kmem_zalloc(sizeof (*ri), KM_NOSLEEP);
	if (ri == NULL) {
		return (B_FALSE);
	}
	ri->ri_cmd = B2S_CMD_ABORT;
	ri->ri_target = l->l_target;
	ri->ri_lun = l->l_lun;
	ri->ri_flags = B2S_REQUEST_FLAG_HEAD;
	ri->ri_leaf = l;
	ri->ri_nexus = n;
	/* leave all else null */

	/*
	 * Submit request to device driver.
	 */
	if (!n->n_request(n->n_private, &ri->ri_public)) {
		/* this shouldn't happen, since we are just starting out */
		b2s_warn(l, "Busy trying to abort");
		kmem_free(ri, sizeof (*ri));
		return (B_FALSE);
	}

	/*
	 * Wait for command completion.
	 */
	mutex_enter(&n->n_lock);
	while ((ri->ri_flags & B2S_REQUEST_FLAG_DONE) == 0)
		cv_wait(&n->n_cv, &n->n_lock);
	mutex_exit(&n->n_lock);

	err = ri->ri_errno;
	kmem_free(ri, sizeof (*ri));

	if (err != 0) {
		b2s_warn(l, "Failed during abort (error %d)", err);
		return (B_FALSE);
	}

	return (B_TRUE);
}

int
b2s_tran_reset(struct scsi_address *ap, int level)
{
	b2s_request_impl_t	*ri;
	b2s_nexus_t		*n = ap->a_hba_tran->tran_hba_private;
	b2s_leaf_t		*l = ap->a_hba_tran->tran_tgt_private;
	int			err;

	if (level == RESET_LUN) {
		return (B_FALSE);
	}

	ri = kmem_zalloc(sizeof (*ri), KM_NOSLEEP);
	if (ri == NULL) {
		return (B_FALSE);
	}
	ri->ri_cmd = B2S_CMD_RESET;
	ri->ri_target = l->l_target;
	ri->ri_lun = l->l_lun;
	ri->ri_flags = B2S_REQUEST_FLAG_HEAD;
	ri->ri_leaf = l;
	ri->ri_nexus = n;
	/* leave all else null */

	/*
	 * Submit request to device driver.
	 */
	if (!n->n_request(n->n_private, &ri->ri_public)) {
		/* this shouldn't happen, since we are just starting out */
		b2s_warn(l, "Busy trying to reset");
		kmem_free(ri, sizeof (*ri));
		return (B_FALSE);
	}

	/*
	 * Wait for command completion.
	 */
	mutex_enter(&n->n_lock);
	while ((ri->ri_flags & B2S_REQUEST_FLAG_DONE) == 0)
		cv_wait(&n->n_cv, &n->n_lock);
	mutex_exit(&n->n_lock);

	err = ri->ri_errno;
	kmem_free(ri, sizeof (*ri));

	if (err != 0) {
		b2s_warn(l, "Failed during reset (error %d)", err);
		return (B_FALSE);
	}

	return (B_TRUE);
}

int
b2s_tran_setcap(struct scsi_address *ap, char *cap, int val, int whom)
{
	int	capid;

	_NOTE(ARGUNUSED(ap));
	_NOTE(ARGUNUSED(val));
	_NOTE(ARGUNUSED(whom));

	capid = scsi_hba_lookup_capstr(cap);

	switch (capid) {
	case SCSI_CAP_ARQ:
		if (val == 0) {
			return (0);
		} else {
			return (1);
		}

	default:
		return (-1);
	}
}

int
b2s_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	b2s_request_impl_t	*ri = pkt->pkt_ha_private;
	b2s_nexus_t		*n = ap->a_hba_tran->tran_hba_private;
	b2s_leaf_t		*l = ap->a_hba_tran->tran_tgt_private;

	ri->ri_errno = B2S_EOK;
	ri->ri_resid = 0;
	bzero(&ri->ri_public.br_args, sizeof (ri->ri_public.br_args));
	ri->ri_flags = 0;
	ri->ri_done = NULL;

	if ((n == NULL) || (l == NULL) ||
	    ((l->l_flags & B2S_LEAF_DETACHED) != 0)) {
		/*
		 * Leaf is not on the bus!
		 *
		 * We should add support for inquiry when lun != 0,
		 * even if when the lun does not exist, but lun 0 is
		 * present.  But, it turns out this is not strictly
		 * required by sd(7d).
		 */
		b2s_request_done(&ri->ri_public, B2S_ENODEV, 0);
		return (TRAN_ACCEPT);
	}

	ri->ri_nexus = n;
	ri->ri_leaf = l;
	ri->ri_target = l->l_target;
	ri->ri_lun = l->l_lun;

	if (pkt->pkt_flags & FLAG_NOINTR)
		ri->ri_flags |= B2S_REQUEST_FLAG_POLL;
	if (pkt->pkt_flags & FLAG_HEAD)
		ri->ri_flags |= B2S_REQUEST_FLAG_HEAD;

	switch (pkt->pkt_cdbp[0]) {
	case SCMD_DOORLOCK:
		return (b2s_scmd_doorlock(ri));

	case SCMD_FORMAT:
		return (b2s_scmd_format(ri));

	case SCMD_INQUIRY:
		return (b2s_scmd_inq(ri));

	case SCMD_REQUEST_SENSE:
		return (b2s_scmd_rqs(ri));

	case SCMD_SDIAG:
		return (b2s_scmd_sdiag(ri));

	case SCMD_TEST_UNIT_READY:
		return (b2s_scmd_tur(ri));

	case SCMD_READ_CAPACITY:
		return (b2s_scmd_readcap(ri));

	case SCMD_RELEASE:
	case SCMD_RESERVE:
		return (b2s_scmd_reserve_release(ri));

	case SCMD_START_STOP:
		return (b2s_scmd_start_stop(ri));

	case SCMD_MODE_SENSE:
		return (b2s_scmd_mode_sense(ri));

	case SCMD_READ:
	case SCMD_READ_G1:
	case SCMD_WRITE:
	case SCMD_WRITE_G1:
		return (b2s_scmd_rw(ri));

	default:
		b2s_request_done(&ri->ri_public, B2S_ENOTSUP, 0);
		return (TRAN_ACCEPT);
	}
}

/*
 * Publish standard properties on a newly created devinfo node.
 */
int
b2s_update_props(dev_info_t *dip, b2s_leaf_t *l, char **compat, int ncompat)
{
	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip, "target", l->l_target) !=
	    DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip, "lun", l->l_lun) !=
	    DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip, "pm-capable", 1) !=
	    DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, dip, "compatible",
	    compat, ncompat) != DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (ndi_prop_update_string(DDI_DEV_T_NONE, dip, "unique-id",
	    l->l_uuid) != DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (l->l_flags & B2S_LEAF_HOTPLUGGABLE) {
		if (ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
		    "hotpluggable") != DDI_PROP_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * Find the devinfo node associated with the leaf, looking up by target and
 * lun.  (Alternatively in the future we could use a full address)
 *
 * This must be called with the tree lock held.
 */
dev_info_t *
b2s_find_node(b2s_nexus_t *n, b2s_leaf_t *l)
{
	dev_info_t	*dip;
	int		tgt, lun;

	dip = ddi_get_child(n->n_dip);
	while (dip != NULL) {

		tgt = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "target", -1);

		lun = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "lun", -1);

		/* is this the right target */
		if ((lun == l->l_lun) && (tgt == l->l_target)) {
			return (dip);
		}

		dip = ddi_get_next_sibling(dip);
	}

	return (NULL);

}

/*
 * Create and attach a devinfo node for the supplied nexus/leaf
 * combination.
 */
int
b2s_create_node(b2s_nexus_t *n, b2s_leaf_t *l, dev_info_t **dipp)
{
	dev_info_t	*dip;
	char		*name;
	char		**compat;
	int		ncompat;
	int		rv;

	/*
	 * If the node was already created, then we're done.
	 */
	if ((dip = b2s_find_node(n, l)) != NULL) {
		if (dipp)
			*dipp = dip;
		return (DDI_SUCCESS);
	}

	ASSERT(l != NULL);

	/*
	 * Perform an inquiry to collect key information.
	 */
	if (b2s_inquiry(l) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	scsi_hba_nodename_compatible_get(&l->l_inq, NULL, l->l_inq.inq_dtype,
	    NULL, &name, &compat, &ncompat);

	if (ndi_devi_alloc(n->n_dip, name, DEVI_SID_NODEID, &dip) !=
	    NDI_SUCCESS) {
		scsi_hba_nodename_compatible_free(name, compat);
		b2s_warn(l, "Unable to create devinfo node");
		return (DDI_FAILURE);
	}

	if (b2s_update_props(dip, l, compat, ncompat) != DDI_SUCCESS) {
		scsi_hba_nodename_compatible_free(name, compat);
		ndi_prop_remove_all(dip);
		(void) ndi_devi_free(dip);
		b2s_warn(l, "Unable to create properties");
		return (DDI_FAILURE);
	}
	scsi_hba_nodename_compatible_free(name, compat);

	if (dipp) {
		/*
		 * We were called by bus_config BUS_CONFIG_ONE,
		 * and therefore must be done synchronously.
		 */
		rv = ndi_devi_online(dip, NDI_ONLINE_ATTACH);
		if (rv == NDI_SUCCESS)
			*dipp = dip;
	} else {
		/*
		 * The rest of the time, asynchronous is easier and
		 * safer (nexus could call us from interrupt context).
		 */
		rv = ndi_devi_online_async(dip,
		    NDI_ONLINE_ATTACH | NDI_NOSLEEP);
	}
	if (rv != NDI_SUCCESS) {
		b2s_warn(l, "Failed to online device");
		ndi_prop_remove_all(dip);
		(void) ndi_devi_free(dip);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
b2s_bus_config(dev_info_t *ndip, uint_t flag, ddi_bus_config_op_t op,
    void *arg, dev_info_t **ldip)
{
	long			val;
	char			*ptr;
	int			rv;
	scsi_hba_tran_t		*tran;
	b2s_leaf_t		*l;
	b2s_nexus_t		*n;
	int			circ;
	uint_t			target, lun;

	tran = ddi_get_driver_private(ndip);
	n = tran->tran_hba_private;

	ndi_devi_enter(ndip, &circ);

	switch (op) {
	case BUS_CONFIG_ONE:

		/*
		 * First parse out the target and lun from the
		 * address.
		 */
		if ((ptr = strchr((char *)arg, '@')) == NULL) {
			rv = NDI_FAILURE;
			break;
		}
		ptr++;
		if ((ddi_strtol(ptr, &ptr, 16, &val) != 0) ||
		    (val < 0) || (*ptr != ',')) {
			rv = NDI_FAILURE;
			break;
		}
		ptr++;
		target = (uint_t)val;
		if ((ddi_strtol(ptr, &ptr, 16, &val) != 0) ||
		    (val < 0) || (*ptr != 0)) {
			rv = NDI_FAILURE;
			break;
		}
		lun = (uint_t)val;

		/*
		 * Now lookup the leaf, and if we have it, attempt to create
		 * the devinfo node for it.
		 */
		rv = NDI_SUCCESS;
		if ((l = b2s_hold_leaf(n, target, lun)) != NULL) {
			if (b2s_create_node(n, l, ldip) != DDI_SUCCESS) {
				rv = NDI_FAILURE;
			}
			b2s_rele_leaf(l);
			break;
		}
		break;

	case BUS_CONFIG_DRIVER:
	case BUS_CONFIG_ALL:

		l = b2s_next_leaf(n, NULL);
		while (l != NULL) {
			(void) b2s_create_node(n, l, NULL);
			l = b2s_next_leaf(n, l);
		}

		rv = NDI_SUCCESS;
		break;

	default:
		rv = NDI_FAILURE;
		break;
	}

	if (rv == NDI_SUCCESS) {
		rv = ndi_busop_bus_config(ndip, flag, op, arg, ldip, 0);
	}

	ndi_devi_exit(ndip, circ);
	return (rv);
}

void
b2s_inquiry_done(b2s_request_impl_t *ri)
{
	struct scsi_inquiry	*inqp = &ri->ri_leaf->l_inq;

	/*
	 * The only post processing we have to do is to massage the
	 * strings into the inquiry structure.
	 */
	COPYSTR(ri->ri_inquiry.inq_vendor, inqp->inq_vid);
	COPYSTR(ri->ri_inquiry.inq_product, inqp->inq_pid);
	COPYSTR(ri->ri_inquiry.inq_revision, inqp->inq_revision);
	COPYSTR(ri->ri_inquiry.inq_serial, inqp->inq_serial);
}

int
b2s_inquiry(b2s_leaf_t *l)
{
	b2s_nexus_t		*n;
	b2s_request_impl_t	*ri;
	struct scsi_inquiry	*inqp;
	int			err;

	inqp = &l->l_inq;
	n = l->l_nexus;

	/*
	 * Set up basic structure, including space padding for ASCII strings.
	 */
	bzero(inqp, sizeof (*inqp));
	(void) memset(inqp->inq_vid, ' ', sizeof (inqp->inq_vid));
	(void) memset(inqp->inq_pid, ' ', sizeof (inqp->inq_pid));
	(void) memset(inqp->inq_revision, ' ', sizeof (inqp->inq_revision));
	(void) memset(inqp->inq_serial, ' ', sizeof (inqp->inq_serial));
	inqp->inq_len = sizeof (*inqp) - 4;
	inqp->inq_ansi = 2;
	inqp->inq_rdf = RDF_SCSI2;
	inqp->inq_dtype = DTYPE_DIRECT;
	if (l->l_flags & B2S_LEAF_REMOVABLE)
		inqp->inq_rmb = 1;

	/*
	 * To get product strings, we have to issue a query to the driver.
	 */
	ri = kmem_zalloc(sizeof (*ri), KM_NOSLEEP);
	if (ri == NULL) {
		return (DDI_FAILURE);
	}
	ri->ri_cmd = B2S_CMD_INQUIRY;
	ri->ri_target = l->l_target;
	ri->ri_lun = l->l_lun;
	ri->ri_flags = B2S_REQUEST_FLAG_HEAD;
	ri->ri_leaf = l;
	ri->ri_nexus = n;
	ri->ri_done = b2s_inquiry_done;
	/* leave all else null */

	/*
	 * Submit inquiry request to device driver.
	 */
	if (!n->n_request(n->n_private, &ri->ri_public)) {
		/* this shouldn't happen, since we are just starting out */
		b2s_warn(l, "Busy trying to collect inquiry data");
		kmem_free(ri, sizeof (*ri));
		return (DDI_FAILURE);
	}

	/*
	 * Wait for inquiry completion.
	 */
	mutex_enter(&n->n_lock);
	while ((ri->ri_flags & B2S_REQUEST_FLAG_DONE) == 0)
		cv_wait(&n->n_cv, &n->n_lock);
	mutex_exit(&n->n_lock);

	err = ri->ri_errno;
	kmem_free(ri, sizeof (*ri));

	if (err != 0) {
		b2s_warn(l, "Failed during inquiry (error %d)", err);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
b2s_scmd_inq(b2s_request_impl_t *ri)
{
	b2s_leaf_t		*l = ri->ri_leaf;
	union scsi_cdb		*cdb = (void *)ri->ri_pkt->pkt_cdbp;
	caddr_t			ptr;
	size_t			resid, len;
	uint8_t			hdr[4];
	const uint8_t		*data;
	/*
	 * Suppport inquiry pages: 0 is the list itself, and 80 is the
	 * unit serial number (in ASCII).
	 */
	const uint8_t		supp[2] = { 0, 0x80 };

	b2s_request_mapin(&ri->ri_public, &ptr, &len);

	hdr[2] = 0;

	/*
	 * We don't support the EVP data bit, and hence neither a page code.
	 * This corresponds to the entire G0 address field (which includes
	 * a few reserved bits).
	 */
	switch (GETG0ADDR(cdb)) {
	case 0x00000:		/* standard SCSI inquiry */
		resid = min(sizeof (l->l_inq), GETG0COUNT(cdb));
		len = min(resid, len);
		bcopy(&l->l_inq, ptr, len);
		ri->ri_resid = resid - len;
		bcopy(&l->l_inq, ptr, len);
		ri->ri_resid = resid - len;
		b2s_request_done(&ri->ri_public, B2S_EOK, 0);
		return (TRAN_ACCEPT);

	case 0x10000:		/* page 0 supported VPD pages */
		data = supp;
		hdr[0] = DTYPE_DIRECT;
		hdr[1] = 0;	/* page code */
		hdr[2] = 0;
		hdr[3] = 2;	/* page length */
		break;

	case 0x18000:		/* page 80 unit serial number */
		data = (uint8_t *)l->l_uuid;
		hdr[0] = DTYPE_DIRECT;
		hdr[1] = 0x80;	/* page code */
		hdr[2] = 0;
		hdr[3] = l->l_uuid ? strlen(l->l_uuid) : 0; 	/* page len */
		break;

	default:
		b2s_request_done(&ri->ri_public, B2S_EINVAL, 0);
		return (TRAN_ACCEPT);
	}

	resid = min(hdr[3] + 4, GETG0COUNT(cdb));
	len = min(resid, len);
	ri->ri_resid = resid - len;

	/* now copy the header */
	len = min(resid, 4);
	bcopy(hdr, ptr, len);
	resid -= len;

	/* now copy the actual page data */
	bcopy(data, ptr + len, resid);

	b2s_request_done(&ri->ri_public, B2S_EOK, 0);
	return (TRAN_ACCEPT);
}

int
b2s_scmd_rqs(b2s_request_impl_t *ri)
{
	union scsi_cdb	*cdb = (void *)ri->ri_pkt->pkt_cdbp;
	size_t		len, resid;
	caddr_t		ptr;
	int		rv;

	/* Like inquiry, the entire G0 address field must be zero. */
	if (GETG0ADDR(cdb) != 0) {
		rv = B2S_EINVAL;
		len = 0;
		resid = 0;
	} else {
		struct scsi_extended_sense es;

		/*
		 * We always use ARQ, unconditionally, so this command
		 * can always return success.
		 */
		bzero(&es, sizeof (es));
		es.es_valid = 1;
		es.es_class = CLASS_EXTENDED_SENSE;
		es.es_key = KEY_NO_SENSE;

		resid = sizeof (es);

		b2s_request_mapin(&ri->ri_public, &ptr, &len);

		len = min(resid, len);
		bcopy(&es, ptr, len);
		resid -= len;

		rv = B2S_EOK;
	}
	b2s_request_done(&ri->ri_public, rv, resid);
	return (TRAN_ACCEPT);
}

int
b2s_scmd_sdiag(b2s_request_impl_t *ri)
{
	union scsi_cdb	*cdb = (void *)ri->ri_pkt->pkt_cdbp;
	int		rv;

	/* we only support the SELFTEST bit */
	if ((GETG0TAG(cdb) & 0x4) == 0) {
		rv = B2S_EINVAL;
	} else {
		rv = B2S_EOK;
	}
	b2s_request_done(&ri->ri_public, rv, 0);
	return (TRAN_ACCEPT);
}

int
b2s_scmd_tur(b2s_request_impl_t *ri)
{
	b2s_nexus_t 	*n = ri->ri_nexus;

	ri->ri_cmd = B2S_CMD_GETMEDIA;
	if (!n->n_request(n->n_private, &ri->ri_public)) {
		return (TRAN_BUSY);
	}
	return (TRAN_ACCEPT);
}

int
b2s_scmd_doorlock(b2s_request_impl_t *ri)
{
	b2s_nexus_t	*n = ri->ri_nexus;
	union scsi_cdb	*cdb = (void *)ri->ri_pkt->pkt_cdbp;

	/*
	 * Bit 0 of the count indicates the "Prevent" mode.  All other address
	 * and count bits are reserved.
	 */
	if ((GETG0ADDR(cdb) != 0) || ((GETG0COUNT(cdb) & 0xFE) != 0)) {
		b2s_request_done(&ri->ri_public, B2S_EINVAL, 0);
		return (TRAN_ACCEPT);
	}

	ri->ri_cmd = (GETG0COUNT(cdb) != 0) ? B2S_CMD_LOCK : B2S_CMD_UNLOCK;
	if (!n->n_request(n->n_private, &ri->ri_public)) {
		return (TRAN_BUSY);
	}
	return (TRAN_ACCEPT);
}

int
b2s_scmd_format(b2s_request_impl_t *ri)
{
	b2s_nexus_t	*n = ri->ri_nexus;
	union scsi_cdb	*cdb = (void *)ri->ri_pkt->pkt_cdbp;
	size_t		len;
	caddr_t		ptr;

	if (GETG0TAG(cdb) & 0x7) {
		b2s_request_done(&ri->ri_public, B2S_EINVAL, 0);
		return (TRAN_ACCEPT);
	}

	if (GETG0TAG(cdb) & FPB_DATA) {
		/*
		 * FmtData set.  A defect list is attached.
		 *
		 * This is an awful lot of work just to support a command
		 * option we don't ever care about.  SCSI-2 says we have
		 * to do it.
		 *
		 * The alternative would just be to ignore the defect list
		 * and format options altogether.  That would be a lot easier.
		 */

		b2s_request_mapin(&ri->ri_public, &ptr, &len);

		if (len < 4) {
			b2s_request_done(&ri->ri_public, B2S_EBADMSG, 0);
			return (TRAN_ACCEPT);
		}

		if ((ptr[0] != 0) || (ptr[2] != 0) || (ptr[3] != 0) ||
		    ((ptr[1] & 0xF9) != 0)) {
			b2s_request_done(&ri->ri_public, B2S_EPARAM, 0);
			return (TRAN_ACCEPT);
		}

		if (ptr[1] & 0x2) {
			ri->ri_flags |= B2S_REQUEST_FLAG_IMMED;
		}

	} else if (GETG0TAG(cdb) & FPB_CMPLT) {
		/*
		 * No defect list, so this bit (CmpLst) should have been zero!
		 */
		b2s_request_done(&ri->ri_public, B2S_EINVAL, 0);
		return (TRAN_ACCEPT);
	}

	ri->ri_cmd = B2S_CMD_FORMAT;
	if (!n->n_request(n->n_private, &ri->ri_public)) {
		return (TRAN_BUSY);
	}

	return (TRAN_ACCEPT);
}

void
b2s_scmd_readcap_done(b2s_request_impl_t *ri)
{
	uint32_t		lba;
	union scsi_cdb		*cdb = (void *)ri->ri_pkt->pkt_cdbp;
	struct scsi_capacity	cap;
	caddr_t			ptr;
	size_t			resid, len;

	/*
	 * Lower layer resid is meaningless here.
	 */
	if (ri->ri_errno != B2S_EOK) {
		return;
	}

	lba = GETG1ADDR(cdb);

	switch (GETG1COUNT(cdb)) {
	case 0:	/* PMI == 0 */
		if (lba != 0) {
			ri->ri_errno = B2S_EINVAL;
			return;
		}
		break;
	case 1:	/* PMI == 1 */
		if (lba >= ri->ri_media.media_nblks) {
			ri->ri_errno = B2S_EBLKADDR;
			return;
		}
		break;
	default:
		ri->ri_errno = B2S_EINVAL;
		return;
	}

	/*
	 * Note that the capacity is the LBA of the last block, not the
	 * number of blocks.  A little surprising if you don't pay close
	 * enough attention to the spec.
	 */
	SCSI_WRITE32(&cap.capacity, ri->ri_media.media_nblks - 1);
	SCSI_WRITE32(&cap.lbasize, ri->ri_media.media_blksz);

	b2s_request_mapin(&ri->ri_public, &ptr, &len);

	if (len != 0) {
		resid = sizeof (cap);
		len = min(resid, len);
		bcopy(&cap, ptr, len);
		ri->ri_resid = resid - len;
	}
}

int
b2s_scmd_readcap(b2s_request_impl_t *ri)
{
	b2s_nexus_t	*n = ri->ri_nexus;
	union scsi_cdb	*cdb = (void *)ri->ri_pkt->pkt_cdbp;

	/*
	 * No transfer by real target.
	 */
	ri->ri_done = b2s_scmd_readcap_done;

	if ((GETG1TAG(cdb)) != 0) {
		b2s_request_done(&ri->ri_public, B2S_EINVAL, 0);
		return (TRAN_ACCEPT);
	}

	ri->ri_cmd = B2S_CMD_GETMEDIA;
	if (!n->n_request(n->n_private, &ri->ri_public)) {
		return (TRAN_BUSY);
	}

	return (TRAN_ACCEPT);
}

int
b2s_scmd_reserve_release(b2s_request_impl_t *ri)
{
	union scsi_cdb	*cdb = (void *)ri->ri_pkt->pkt_cdbp;

	/* we aren't checking fields we don't care about */
	if ((GETG0TAG(cdb) & 0x1) != 0)  {
		/* extent reservations not supported */
		b2s_request_done(&ri->ri_public, B2S_EINVAL, 0);
		return (TRAN_ACCEPT);
	}

	/*
	 * We don't support multi-initiator access, so we always
	 * return success.
	 */

	b2s_request_done(&ri->ri_public, B2S_EOK, 0);
	return (TRAN_ACCEPT);
}

int
b2s_scmd_start_stop(b2s_request_impl_t *ri)
{
	b2s_nexus_t	*n = ri->ri_nexus;
	union scsi_cdb	*cdb = (void *)ri->ri_pkt->pkt_cdbp;
	uint8_t		count;

	switch (GETG0ADDR(cdb)) {
	case 0:
		break;
	case 0x10000:	/* immed set */
		ri->ri_flags |= B2S_REQUEST_FLAG_IMMED;
		break;
	default:
		b2s_request_done(&ri->ri_public, B2S_EINVAL, 0);
		return (TRAN_ACCEPT);
	}
	count = GETG0COUNT(cdb);
	if (count > 3) {
		b2s_request_done(&ri->ri_public, B2S_EINVAL, 0);
		return (TRAN_ACCEPT);
	}
	if (count & 0x2)
		ri->ri_flags |= B2S_REQUEST_FLAG_LOAD_EJECT;
	if (count & 0x1) {
		ri->ri_cmd = B2S_CMD_START;
	} else {
		ri->ri_cmd = B2S_CMD_STOP;
	}

	if (!n->n_request(n->n_private, &ri->ri_public)) {
		return (TRAN_BUSY);
	}
	return (TRAN_ACCEPT);
}

void
b2s_scmd_mode_sense_done(b2s_request_impl_t *ri)
{
	uchar_t			*cdb = ri->ri_pkt->pkt_cdbp;
	uint8_t			pc, page, devspec;
	caddr_t			ptr;
	size_t			len, resid;
	uint8_t			data[16];

	if ((ri->ri_errno == 0) &&
	    ((ri->ri_media.media_flags & B2S_MEDIA_FLAG_READ_ONLY) == 0))  {
		devspec = 0;
	} else {
		/* this marks the media read-only */
		devspec = 0x80;
	}

	pc = page = cdb[2];
	pc &= 0xc0;
	page &= 0x3f;

	/* we do not support savable parameters, at all */
	if ((pc & 0xc0) == 0x3) {
		ri->ri_errno = B2S_ENOSAV;
		ri->ri_resid = 0;
		return;
	}

	b2s_request_mapin(&ri->ri_public, &ptr, &resid);

	if ((page == 0x9) || (page == 0x3f)) {
		/* Peripheral device page */

		/* header */
		data[0] = 9 + 3;	/* length following */
		data[1] = 0;		/* medium type */
		data[2] = devspec;	/* mostly r/w flag */
		data[3] = 0;		/* block descriptor len */
		len = min(4, resid);

		bcopy(data, ptr, len);
		resid -= len;
		ptr += len;

		/* page data - 9 bytes long */
		bzero(data, 9);
		data[0] = 0x9;		/* page code */
		data[1] = 0x8;		/* following data */
		len = min(resid, 9);
		bcopy(data, ptr, len);
		resid -= len;
		ptr += len;
	}

	if ((page == 0xa) || (page == 0x3f)) {
		/* Control mode page */

		/* header */
		data[0] = 8 + 3;	/* length following */
		data[1] = 0;		/* medium type */
		data[2] = devspec;	/* mostly r/w flag */
		data[3] = 0;		/* block descriptor len */
		len = min(4, resid);

		bcopy(data, ptr, len);
		resid -= len;
		ptr += len;

		/* page data - 9 bytes long */
		bzero(data, 8);
		data[0] = 0xa;		/* page code */
		data[1] = 0x7;		/* following data */
		len = min(resid, 9);
		bcopy(data, ptr, len);
		resid -= len;
		ptr += len;
	}

	ri->ri_resid = 0;
	ri->ri_errno = B2S_EOK;
}

int
b2s_scmd_mode_sense(b2s_request_impl_t *ri)
{
	b2s_nexus_t	*n = ri->ri_nexus;

	ri->ri_done = b2s_scmd_mode_sense_done;
	ri->ri_cmd = B2S_CMD_GETMEDIA;
	if (!n->n_request(n->n_private, &ri->ri_public)) {
		return (TRAN_BUSY);
	}
	return (TRAN_ACCEPT);
}

int
b2s_scmd_rw(b2s_request_impl_t *ri)
{
	b2s_nexus_t	*n = ri->ri_nexus;
	uint32_t	lba;
	uint32_t	nblks;
	union scsi_cdb	*cdb = (void *)ri->ri_pkt->pkt_cdbp;

	switch (GETGROUP(cdb)) {
	case CDB_GROUPID_0:
		nblks = GETG0COUNT(cdb);
		nblks = nblks ? nblks : 256;
		lba = GETG0ADDR(cdb);
		break;
	case CDB_GROUPID_1:
		if (GETG1TAG(cdb)) {
			/* we don't support relative addresses */
			b2s_request_done(&ri->ri_public, B2S_EINVAL, 0);
			return (TRAN_ACCEPT);
		}
		lba = GETG1ADDR(cdb);
		nblks = GETG1COUNT(cdb);
		break;
	default:
		b2s_request_done(&ri->ri_public, B2S_ENOTSUP, 0);
		return (TRAN_ACCEPT);
	}

	if (nblks == 0) {
		b2s_request_done(&ri->ri_public, 0, 0);
		return (TRAN_ACCEPT);
	}

	ri->ri_nblks = nblks;
	ri->ri_lba = lba;
	ri->ri_flags |= B2S_REQUEST_FLAG_BLKS;
	ri->ri_cmd = (GETCMD(cdb)) == SCMD_READ ?
	    B2S_CMD_READ : B2S_CMD_WRITE;

	if (!n->n_request(n->n_private, &ri->ri_public)) {
		return (TRAN_BUSY);
	}
	return (TRAN_ACCEPT);
}

void
b2s_warn(b2s_leaf_t *l, const char *fmt, ...)
{
	va_list		ap;
	b2s_nexus_t	*n;
	char		msg[256];

	n = l->l_nexus;

	(void) snprintf(msg, sizeof (msg), "%s%d target %d lun %d: %s",
	    ddi_driver_name(n->n_dip), ddi_get_instance(n->n_dip),
	    l->l_target, l->l_lun, fmt);

	va_start(ap, fmt);
	vcmn_err(CE_WARN, msg, ap);
	va_end(ap);
}

b2s_nexus_t *
b2s_alloc_nexus(b2s_nexus_info_t *info)
{
	b2s_nexus_t		*n;
	struct scsi_hba_tran	*tran;

	if (info->nexus_version != B2S_VERSION_0)
		return (NULL);

	n = kmem_zalloc(sizeof (*n), KM_SLEEP);
	mutex_init(&n->n_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&n->n_cv, NULL, CV_DRIVER, NULL);
	list_create(&n->n_leaves, sizeof (struct b2s_leaf),
	    offsetof(struct b2s_leaf, l_node));

	n->n_dip = info->nexus_dip;
	n->n_private = info->nexus_private;
	n->n_request = info->nexus_request;
	if (info->nexus_dma_attr != NULL) {
		n->n_dma = info->nexus_dma_attr;
	} else {
		n->n_dma = &b2s_default_dma_attr;
	}

	tran = scsi_hba_tran_alloc(n->n_dip, SCSI_HBA_CANSLEEP);
	if (tran == NULL) {
		list_destroy(&n->n_leaves);
		mutex_destroy(&n->n_lock);
		cv_destroy(&n->n_cv);
		kmem_free(n, sizeof (*n));
		return (NULL);
	}
	n->n_tran =  tran;

	tran->tran_hba_dip =		n->n_dip;
	tran->tran_hba_private =	n;
	tran->tran_tgt_private =	NULL;
	tran->tran_tgt_init =		b2s_tran_tgt_init;
	tran->tran_tgt_free =		b2s_tran_tgt_free;
	tran->tran_tgt_probe =		scsi_hba_probe;
	tran->tran_tgt_free =		NULL;
	tran->tran_start =		b2s_tran_start;
	tran->tran_reset = 		b2s_tran_reset;
	tran->tran_abort = 		b2s_tran_abort;
	tran->tran_getcap = 		b2s_tran_getcap;
	tran->tran_setcap = 		b2s_tran_setcap;
	tran->tran_init_pkt = 		b2s_tran_init_pkt;
	tran->tran_destroy_pkt = 	b2s_tran_destroy_pkt;
	tran->tran_setup_pkt =		NULL;
	tran->tran_teardown_pkt =	NULL;
	tran->tran_hba_len =		sizeof (b2s_request_impl_t);
	tran->tran_bus_config =		b2s_bus_config;

	return (n);
}

void
b2s_free_nexus(b2s_nexus_t *n)
{
	b2s_leaf_t *l;

	/*
	 * Toss any registered leaves, if we haven't already done so.
	 * At this point we don't care about upper layers, because the
	 * DDI should not have allowed us to detach if there were busy
	 * targets.
	 */
	while ((l = list_head(&n->n_leaves)) != NULL) {
		list_remove(&n->n_leaves, l);
		kmem_free(l, sizeof (struct b2s_leaf));
	}
	list_destroy(&n->n_leaves);
	mutex_destroy(&n->n_lock);
	cv_destroy(&n->n_cv);
	kmem_free(n, sizeof (struct b2s_nexus));
}

int
b2s_attach_nexus(b2s_nexus_t *n)
{
	int	rv;

	rv = scsi_hba_attach_setup(n->n_dip, n->n_dma, n->n_tran,
	    SCSI_HBA_TRAN_SCB | SCSI_HBA_TRAN_CDB | SCSI_HBA_TRAN_CLONE);
	if (rv == 0) {
		n->n_attached = B_TRUE;
	}
	return (rv);
}

int
b2s_detach_nexus(b2s_nexus_t *n)
{
	int	rv;

	if (n->n_attached) {
		rv = scsi_hba_detach(n->n_dip);
		if (rv == 0) {
			n->n_attached = B_FALSE;
		}
	} else {
		rv = 0;
	}
	return ((rv == 0) ? DDI_SUCCESS : DDI_FAILURE);
}

b2s_leaf_t *
b2s_attach_leaf(b2s_nexus_t *n, b2s_leaf_info_t *info)
{
	b2s_leaf_t	*l;
	uint_t		target	= info->leaf_target;
	uint_t		lun	= info->leaf_lun;
	const char	*uuid	= info->leaf_unique_id;
	uint32_t	flags	= info->leaf_flags;

	if (uuid == NULL) {
		uuid = "";
	}

	mutex_enter(&n->n_lock);

	/*
	 * If the leaf already exists, it is a sign that the device
	 * was kept around because it was still in use.  In that case,
	 * we attempt to detect the situation where the node is the same
	 * as the previous one, and reconnect it.
	 */
	if ((l = b2s_get_leaf(n, target, lun)) != NULL) {
		if (strcmp(l->l_uuid, uuid) != 0) {
			/*
			 * Leaf already exists, but is not the same!  This
			 * would be a good time to issue a warning.
			 */
			mutex_exit(&n->n_lock);
			b2s_warn(l, "Target disconnected while still in use.");
			b2s_warn(l, "Reconnect the previous target device.");
			return (NULL);
		}
		l->l_flags &= ~B2S_LEAF_DETACHED;
	} else {
		if ((l = kmem_zalloc(sizeof (*l), KM_NOSLEEP)) == NULL) {
			mutex_exit(&n->n_lock);
			b2s_warn(l, "Unable to allocate target state.");
			return (NULL);
		}
		l->l_nexus = n;
		l->l_target = target;
		l->l_lun = lun;
		l->l_flags = flags;

		/* strdup would be nice here */
		l->l_uuid = kmem_alloc(strlen(uuid) + 1, KM_NOSLEEP);
		if (l->l_uuid == NULL) {
			mutex_exit(&n->n_lock);
			kmem_free(l, sizeof (*l));
			b2s_warn(l, "Unable to allocate target UUID storage.");
			return (NULL);
		}
		(void) strcpy(l->l_uuid, uuid);

		list_insert_tail(&n->n_leaves, l);
	}

	/*
	 * Make sure we hold it, so that it won't be freed out from
	 * underneath us.
	 */
	l->l_refcnt++;
	mutex_exit(&n->n_lock);

	/*
	 * If the HBA is currently attached, then we need to attach
	 * the node right now.  This supports "hotplug".  Note that
	 * if the node is a reinsert, then this should degenerate into
	 * a NOP.
	 */
	if (n->n_attached) {
		int	circ;
		ndi_devi_enter(n->n_dip, &circ);
		(void) b2s_create_node(n, l, NULL);
		ndi_devi_exit(n->n_dip, circ);
	}

	return (l);
}

void
b2s_detach_leaf(b2s_leaf_t *l)
{
	b2s_nexus_t	*n = l->l_nexus;
	dev_info_t	*dip;
	int		circ;

	l->l_flags |= B2S_LEAF_DETACHED;

	/*
	 * Search for an appropriate child devinfo.
	 */
	ndi_devi_enter(n->n_dip, &circ);
	dip = b2s_find_node(n, l);
	if (dip != NULL) {
		(void) ndi_devi_offline(dip, NDI_DEVI_REMOVE);
	}
	ndi_devi_exit(n->n_dip, circ);

	b2s_rele_leaf(l);
}
