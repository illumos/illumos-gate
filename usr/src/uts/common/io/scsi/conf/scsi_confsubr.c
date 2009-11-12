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

/*
 * Utility SCSI configuration routines
 */
/*
 * Many routines in this file have built in parallel bus assumption
 * which might need to change as other interconnect evolve.
 */

#include <sys/scsi/scsi.h>
#include <sys/modctl.h>
#include <sys/bitmap.h>

/*
 * macro for filling in lun value for scsi-1 support
 */

#define	FILL_SCSI1_LUN(sd, pkt) \
	if ((sd->sd_address.a_lun > 0) && \
	    (sd->sd_inq->inq_ansi == 0x1)) { \
		((union scsi_cdb *)(pkt)->pkt_cdbp)->scc_lun = \
		    sd->sd_address.a_lun; \
	}

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,	/* Type of module */
	"SCSI Bus Utility Routines"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

static void create_inquiry_props(struct scsi_device *);

static int scsi_check_ss2_LUN_limit(struct scsi_device *);
static void scsi_establish_LUN_limit(struct scsi_device *);
static void scsi_update_parent_ss2_prop(dev_info_t *, int, int);

static int check_vpd_page_support8083(struct scsi_device *sd,
		int (*callback)(), int *, int *);
static int send_scsi_INQUIRY(struct scsi_device *sd,
		int (*callback)(), uchar_t *bufaddr, size_t buflen,
		uchar_t evpd, uchar_t page_code, size_t *lenp);

/*
 * this int-array HBA-node property keeps track of strictly SCSI-2
 * target IDs
 */
#define	SS2_LUN0_TGT_LIST_PROP	"ss2-targets"

/*
 * for keeping track of nodes for which we do *NOT* want to probe above LUN 7
 * (i.e. strict SCSI-2 targets)
 *
 * note that we could also keep track of dtype (SCSI device type) and
 * ANSI (SCSI standard conformance level), but all currently-known cases of
 * this problem are on SCSI-2 PROCESSOR device types
 */
typedef struct ss2_lun0_info {
	const char	*sli_vid;	/* SCSI inquiry VID */
	const char	*sli_pid;	/* SCSI inquiry PID */
	const char	*sli_rev;	/* SCSI inquiry REV */
} ss2_lun0_info_t;

/*
 * these two workarounds are for the SCSI-2 GEM2* chips used in the
 * D1000 and D240
 */
#define	SES_D1000_VID		"SYMBIOS"
#define	SES_D1000_PID		"D1000"		/* the D1000 */
#define	SES_D1000_REV		"2"

#define	SES_D240_VID		"SUN"
#define	SES_D240_PID		"D240"		/* the D240 */
#define	SES_D240_REV		"2"

/*
 * a static list of targets where we do *not* want to probe above LUN 7
 */
static const ss2_lun0_info_t	scsi_probe_strict_s2_list[] = {
	{SES_D1000_VID, SES_D1000_PID, SES_D1000_REV},
	{SES_D240_VID, SES_D240_PID, SES_D240_REV},
};

static const int		scsi_probe_strict_s2_size =
	sizeof (scsi_probe_strict_s2_list) / sizeof (struct ss2_lun0_info);


#ifdef	DEBUG

int	scsi_probe_debug = 0;

#define	SCSI_PROBE_DEBUG0(l, s)		\
		if (scsi_probe_debug >= (l)) printf(s)
#define	SCSI_PROBE_DEBUG1(l, s, a1)	\
		if (scsi_probe_debug >= (l)) printf(s, a1)
#define	SCSI_PROBE_DEBUG2(l, s, a1, a2)	\
		if (scsi_probe_debug >= (l)) printf(s, a1, a2)
#define	SCSI_PROBE_DEBUG3(l, s, a1, a2, a3)	\
		if (scsi_probe_debug >= (l)) printf(s, a1, a2, a3)

#else	/* DEBUG */

#define	SCSI_PROBE_DEBUG0(l, s)
#define	SCSI_PROBE_DEBUG1(l, s, a1)
#define	SCSI_PROBE_DEBUG2(l, s, a1, a2)
#define	SCSI_PROBE_DEBUG3(l, s, a1, a2, a3)

#endif	/* DEBUG */

int	scsi_test_busy_timeout = SCSI_POLL_TIMEOUT;	/* in seconds */
int	scsi_test_busy_delay = 10000;			/* 10msec in usec */

/*
 * architecture dependent allocation restrictions. For x86, we'll set
 * dma_attr_addr_hi to scsi_max_phys_addr and dma_attr_sgllen to
 * scsi_sgl_size during _init().
 */
#if defined(__sparc)
ddi_dma_attr_t scsi_alloc_attr = {
	DMA_ATTR_V0,	/* version number */
	0x0,		/* lowest usable address */
	0xFFFFFFFFull,	/* high DMA address range */
	0xFFFFFFFFull,	/* DMA counter register */
	1,		/* DMA address alignment */
	1,		/* DMA burstsizes */
	1,		/* min effective DMA size */
	0xFFFFFFFFull,	/* max DMA xfer size */
	0xFFFFFFFFull,	/* segment boundary */
	1,		/* s/g list length */
	512,		/* granularity of device */
	0		/* DMA transfer flags */
};
#elif defined(__x86)
ddi_dma_attr_t scsi_alloc_attr = {
	DMA_ATTR_V0,	/* version number */
	0x0,		/* lowest usable address */
	0x0,		/* high DMA address range [set in _init()] */
	0xFFFFull,	/* DMA counter register */
	1,		/* DMA address alignment */
	1,		/* DMA burstsizes */
	1,		/* min effective DMA size */
	0xFFFFFFFFull,	/* max DMA xfer size */
	0xFFFFFFFFull,  /* segment boundary */
	0,		/* s/g list length */
	512,		/* granularity of device [set in _init()] */
	0		/* DMA transfer flags */
};
uint64_t scsi_max_phys_addr = 0xFFFFFFFFull;
int scsi_sgl_size = 0xFF;
#endif

ulong_t	*scsi_pkt_bad_alloc_bitmap;

int
_init()
{
	scsi_initialize_hba_interface();
	scsi_watch_init();

#if defined(__x86)
	/* set the max physical address for iob allocs on x86 */
	scsi_alloc_attr.dma_attr_addr_hi = scsi_max_phys_addr;

	/*
	 * set the sgllen for iob allocs on x86. If this is set less than
	 * the number of pages the buffer will take (taking into account
	 * alignment), it would force the allocator to try and allocate
	 * contiguous pages.
	 */
	scsi_alloc_attr.dma_attr_sgllen = scsi_sgl_size;
#endif

	/* bitmap to limit scsi_pkt allocation violation messages */
	scsi_pkt_bad_alloc_bitmap = kmem_zalloc(BT_SIZEOFMAP(devcnt), KM_SLEEP);

	return (mod_install(&modlinkage));
}

/*
 * there is no _fini() routine because this module is never unloaded
 */

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

#define	ROUTE	(&sd->sd_address)

static int
scsi_slave_do_rqsense(struct scsi_device *sd, int (*callback)())
{
	struct scsi_pkt *rq_pkt = NULL;
	struct buf *rq_bp = NULL;
	int rval = SCSIPROBE_EXISTS;

	/*
	 * prepare rqsense packet
	 */
	rq_bp = scsi_alloc_consistent_buf(ROUTE, (struct buf *)NULL,
	    (uint_t)SENSE_LENGTH, B_READ, callback, NULL);
	if (rq_bp == NULL) {
		rval = SCSIPROBE_NOMEM;
		goto out;
	}

	rq_pkt = scsi_init_pkt(ROUTE, (struct scsi_pkt *)NULL,
	    rq_bp, CDB_GROUP0, 1, 0, PKT_CONSISTENT,
	    callback, NULL);

	if (rq_pkt == NULL) {
		if (rq_bp->b_error == 0)
			rval = SCSIPROBE_NOMEM_CB;
		else
			rval = SCSIPROBE_NOMEM;
		goto out;
	}
	ASSERT(rq_bp->b_error == 0);

	(void) scsi_setup_cdb((union scsi_cdb *)rq_pkt->
	    pkt_cdbp, SCMD_REQUEST_SENSE, 0, SENSE_LENGTH, 0);
	FILL_SCSI1_LUN(sd, rq_pkt);
	rq_pkt->pkt_flags = FLAG_NOINTR|FLAG_NOPARITY|FLAG_SENSING;

	/*
	 * The controller type is as yet unknown, so we
	 * have to do a throwaway non-extended request sense,
	 * and hope that that clears the check condition
	 * for that unit until we can find out what kind
	 * of drive it is. A non-extended request sense
	 * is specified by stating that the sense block
	 * has 0 length, which is taken to mean that it
	 * is four bytes in length.
	 */
	if (scsi_poll(rq_pkt) < 0) {
		rval = SCSIPROBE_FAILURE;
	}

out:
	if (rq_pkt) {
		scsi_destroy_pkt(rq_pkt);
	}
	if (rq_bp) {
		scsi_free_consistent_buf(rq_bp);
	}

	return (rval);
}

/*
 *
 * SCSI slave probe routine - provided as a service to target drivers
 *
 * Mostly attempts to allocate and fill sd inquiry data..
 */

int
scsi_slave(struct scsi_device *sd, int (*callback)())
{
	struct scsi_pkt	*pkt;
	int		rval = SCSIPROBE_EXISTS;

	/*
	 * the first test unit ready will tell us whether a target
	 * responded and if there was one, it will clear the unit attention
	 * condition
	 */
	pkt = scsi_init_pkt(ROUTE, (struct scsi_pkt *)NULL, NULL,
	    CDB_GROUP0, sizeof (struct scsi_arq_status), 0, 0, callback, NULL);

	if (pkt == NULL) {
		return (SCSIPROBE_NOMEM_CB);
	}

	(void) scsi_setup_cdb((union scsi_cdb *)pkt->pkt_cdbp,
	    SCMD_TEST_UNIT_READY, 0, 0, 0);
	FILL_SCSI1_LUN(sd, pkt);
	pkt->pkt_flags = FLAG_NOINTR|FLAG_NOPARITY;

	if (scsi_poll(pkt) < 0) {
		if (pkt->pkt_reason == CMD_INCOMPLETE)
			rval = SCSIPROBE_NORESP;
		else
			rval = SCSIPROBE_FAILURE;

		if ((pkt->pkt_state & STATE_ARQ_DONE) == 0) {
			if (((struct scsi_status *)pkt->pkt_scbp)->sts_chk)
				/*
				 * scanner and processor devices can return a
				 * check condition here
				 */
				rval = scsi_slave_do_rqsense(sd, callback);
		}

		if (rval != SCSIPROBE_EXISTS) {
			scsi_destroy_pkt(pkt);
			return (rval);
		}
	}

	/*
	 * the second test unit ready, allows the host adapter to negotiate
	 * synchronous transfer period and offset
	 */
	if (scsi_poll(pkt) < 0) {
		if (pkt->pkt_reason == CMD_INCOMPLETE)
			rval = SCSIPROBE_NORESP;
		else
			rval = SCSIPROBE_FAILURE;
	}

	/*
	 * do a rqsense if there was a check condition and ARQ was not done
	 */
	if ((pkt->pkt_state & STATE_ARQ_DONE) == 0) {
		if (((struct scsi_status *)pkt->pkt_scbp)->sts_chk) {
			rval = scsi_slave_do_rqsense(sd, callback);
		}
	}

	/*
	 * call scsi_probe to do the inquiry
	 *
	 * NOTE: there is minor difference with the old scsi_slave
	 * implementation: busy conditions are not handled in scsi_probe.
	 */
	scsi_destroy_pkt(pkt);
	if (rval == SCSIPROBE_EXISTS) {
		return (scsi_probe(sd, callback));
	} else {
		return (rval);
	}
}

/*
 * Undo scsi_slave - older interface, but still supported
 *
 * NOTE: The 'sd_inq' inquiry data is now freed by scsi_hba/scsi_vhci code
 * as part of free of scsi_device(9S).
 */
/*ARGSUSED*/
void
scsi_unslave(struct scsi_device *sd)
{
}

/*
 * Undo scsi_probe
 *
 * NOTE: The 'sd_inq' inquiry data is now freed by scsi_hba/scsi_vhci code
 * as part of free of scsi_device(9S).
 */
/*ARGSUSED*/
void
scsi_unprobe(struct scsi_device *sd)
{
}

/*
 * This is like scsi_poll, but only does retry for TRAN_BUSY.
 */
static int
scsi_test(struct scsi_pkt *pkt)
{
	int		rval = -1;
	int		wait_usec;
	int		rc;
	extern int	do_polled_io;

	pkt->pkt_flags |= FLAG_NOINTR;
	pkt->pkt_time = SCSI_POLL_TIMEOUT;	/* in seconds */

	if (scsi_ifgetcap(&pkt->pkt_address, "tagged-qing", 1) == 1) {
		pkt->pkt_flags |= FLAG_STAG;
	}

	/*
	 * Each TRAN_BUSY response waits scsi_test_busy_delay usec up to a
	 * maximum of scsi_test_busy_timeout.
	 */
	for (wait_usec = 0; (wait_usec / 1000000) <= scsi_test_busy_timeout;
	    wait_usec += scsi_test_busy_delay) {

		/* Initialize pkt status variables */
		*pkt->pkt_scbp = pkt->pkt_reason = pkt->pkt_state = 0;

		rc = scsi_transport(pkt);
		if ((rc != TRAN_BUSY) || (scsi_test_busy_delay == 0) ||
		    (scsi_test_busy_timeout == 0))
			break;

		/* transport busy, wait */
		if ((curthread->t_flag & T_INTR_THREAD) == 0 && !do_polled_io) {
			delay(drv_usectohz(scsi_test_busy_delay));
		} else {
			/* we busy wait during cpr_dump or interrupt threads */
			drv_usecwait(scsi_test_busy_delay);
		}
	}

	if (rc != TRAN_ACCEPT) {
		goto exit;
	} else if (pkt->pkt_reason == CMD_INCOMPLETE && pkt->pkt_state == 0) {
		goto exit;
	} else if (pkt->pkt_reason != CMD_CMPLT) {
		goto exit;
	} else if (((*pkt->pkt_scbp) & STATUS_MASK) == STATUS_BUSY) {
		rval = 0;
	} else {
		rval = 0;
	}

exit:
	return (rval);
}

/*
 * The implementation of scsi_probe now allows a particular
 * HBA to intercept the call, for any post- or pre-processing
 * it may need.  The default, if the HBA does not override it,
 * is to call scsi_hba_probe(), which retains the old functionality
 * intact.
 */
int
scsi_probe(struct scsi_device *sd, int (*callback)())
{
	int			ret;
	scsi_hba_tran_t		*tran = sd->sd_address.a_hba_tran;

	if (scsi_check_ss2_LUN_limit(sd) != 0) {
		/*
		 * caller is trying to probe a strictly-SCSI-2 device
		 * with a LUN that is too large, so do not allow it
		 */
		return (SCSIPROBE_NORESP);	/* skip probing this one */
	}

	if (tran->tran_tgt_probe != NULL) {
		ret = (*tran->tran_tgt_probe)(sd, callback);
	} else {
		ret = scsi_hba_probe(sd, callback);
	}

	if (ret == SCSIPROBE_EXISTS) {
		create_inquiry_props(sd);
		/* is this a strictly-SCSI-2 node ?? */
		scsi_establish_LUN_limit(sd);
	}

	return (ret);
}
/*
 * probe scsi device using any available path
 *
 */
int
scsi_hba_probe(struct scsi_device *sd, int (*callback)())
{
	return (scsi_hba_probe_pi(sd, callback, 0));
}

/*
 * probe scsi device using specific path
 *
 * scsi_hba_probe_pi does not do any test unit ready's which access the medium
 * and could cause busy or not ready conditions.
 * scsi_hba_probe_pi does 2 inquiries and a rqsense to clear unit attention
 * and to allow sync negotiation to take place
 * finally, scsi_hba_probe_pi does one more inquiry which should
 * reliably tell us what kind of target we have.
 * A scsi-2 compliant target should be able to	return inquiry with 250ms
 * and we actually wait more than a second after reset.
 */
int
scsi_hba_probe_pi(struct scsi_device *sd, int (*callback)(), int pi)
{
	struct scsi_pkt		*inq_pkt = NULL;
	struct scsi_pkt		*rq_pkt = NULL;
	int			rval = SCSIPROBE_NOMEM;
	struct buf		*inq_bp = NULL;
	struct buf		*rq_bp = NULL;
	int			(*cb_flag)();
	int			pass = 1;

	if (sd->sd_inq == NULL) {
		sd->sd_inq = (struct scsi_inquiry *)
		    kmem_alloc(SUN_INQSIZE, ((callback == SLEEP_FUNC) ?
		    KM_SLEEP : KM_NOSLEEP));
		if (sd->sd_inq == NULL) {
			goto out;
		}
	}

	if (callback != SLEEP_FUNC && callback != NULL_FUNC) {
		cb_flag = NULL_FUNC;
	} else {
		cb_flag = callback;
	}
	inq_bp = scsi_alloc_consistent_buf(ROUTE,
	    (struct buf *)NULL, SUN_INQSIZE, B_READ, cb_flag, NULL);
	if (inq_bp == NULL) {
		goto out;
	}

	inq_pkt = scsi_init_pkt(ROUTE, (struct scsi_pkt *)NULL,
	    inq_bp, CDB_GROUP0, sizeof (struct scsi_arq_status),
	    0, PKT_CONSISTENT, callback, NULL);
	if (inq_pkt == NULL) {
		if (inq_bp->b_error == 0)
			rval = SCSIPROBE_NOMEM_CB;
		goto out;
	}
	ASSERT(inq_bp->b_error == 0);

	(void) scsi_setup_cdb((union scsi_cdb *)inq_pkt->pkt_cdbp,
	    SCMD_INQUIRY, 0, SUN_INQSIZE, 0);
	inq_pkt->pkt_flags = FLAG_NOINTR|FLAG_NOPARITY;

	/*
	 * set transport path
	 */
	if (pi && scsi_pkt_allocated_correctly(inq_pkt)) {
		inq_pkt->pkt_path_instance = pi;
		inq_pkt->pkt_flags |= FLAG_PKT_PATH_INSTANCE;
	}

	/*
	 * the first inquiry will tell us whether a target
	 * responded
	 *
	 * The FILL_SCSI1_LUN below will find "ansi_ver != 1" on first pass
	 * because of bzero initilization. If this assumption turns out to be
	 * incorrect after we have real sd_inq data (for lun0) we will do a
	 * second pass during which FILL_SCSI1_LUN will place lun in CDB.
	 */
	bzero((caddr_t)sd->sd_inq, SUN_INQSIZE);
again:	FILL_SCSI1_LUN(sd, inq_pkt);

	if (scsi_test(inq_pkt) < 0) {
		if (inq_pkt->pkt_reason == CMD_INCOMPLETE) {
			rval = SCSIPROBE_NORESP;
			goto out;
		} else {
			/*
			 * retry one more time
			 */
			if (scsi_test(inq_pkt) < 0) {
				rval = SCSIPROBE_FAILURE;
				goto out;
			}
		}
	}

	/*
	 * if we are lucky, this inquiry succeeded
	 */
	if ((inq_pkt->pkt_reason == CMD_CMPLT) &&
	    (((*inq_pkt->pkt_scbp) & STATUS_MASK) == 0)) {
		goto done;
	}

	/*
	 * the second inquiry, allows the host adapter to negotiate
	 * synchronous transfer period and offset
	 */
	if (scsi_test(inq_pkt) < 0) {
		if (inq_pkt->pkt_reason == CMD_INCOMPLETE)
			rval = SCSIPROBE_NORESP;
		else
			rval = SCSIPROBE_FAILURE;
		goto out;
	}

	/*
	 * if target is still busy, give up now
	 */
	if (((struct scsi_status *)inq_pkt->pkt_scbp)->sts_busy) {
		rval = SCSIPROBE_BUSY;
		goto out;
	}

	/*
	 * do a rqsense if there was a check condition and ARQ was not done
	 */
	if ((inq_pkt->pkt_state & STATE_ARQ_DONE) == 0) {
		if (((struct scsi_status *)inq_pkt->pkt_scbp)->sts_chk) {

			/*
			 * prepare rqsense packet
			 * there is no real need for this because the
			 * check condition should have been cleared by now.
			 */
			rq_bp = scsi_alloc_consistent_buf(ROUTE,
			    (struct buf *)NULL,
			    (uint_t)SENSE_LENGTH, B_READ, cb_flag, NULL);
			if (rq_bp == NULL) {
				goto out;
			}

			rq_pkt = scsi_init_pkt(ROUTE, (struct scsi_pkt *)NULL,
			    rq_bp, CDB_GROUP0, 1, 0, PKT_CONSISTENT, callback,
			    NULL);

			if (rq_pkt == NULL) {
				if (rq_bp->b_error == 0)
					rval = SCSIPROBE_NOMEM_CB;
				goto out;
			}
			ASSERT(rq_bp->b_error == 0);

			(void) scsi_setup_cdb((union scsi_cdb *)rq_pkt->
			    pkt_cdbp, SCMD_REQUEST_SENSE, 0, SENSE_LENGTH, 0);
			FILL_SCSI1_LUN(sd, rq_pkt);
			rq_pkt->pkt_flags = FLAG_NOINTR|FLAG_NOPARITY;

			/*
			 * set transport path
			 */
			if (pi && scsi_pkt_allocated_correctly(rq_pkt)) {
				rq_pkt->pkt_path_instance = pi;
				rq_pkt->pkt_flags |= FLAG_PKT_PATH_INSTANCE;
			}

			/*
			 * The FILL_SCSI1_LUN above will find "inq_ansi != 1"
			 * on first pass, see "again" comment above.
			 *
			 * The controller type is as yet unknown, so we
			 * have to do a throwaway non-extended request sense,
			 * and hope that that clears the check condition for
			 * that unit until we can find out what kind of drive
			 * it is. A non-extended request sense is specified
			 * by stating that the sense block has 0 length,
			 * which is taken to mean that it is four bytes in
			 * length.
			 */
			if (scsi_test(rq_pkt) < 0) {
				rval = SCSIPROBE_FAILURE;
				goto out;
			}
		}
	}

	/*
	 * At this point, we are guaranteed that something responded
	 * to this scsi bus target id. We don't know yet what
	 * kind of device it is, or even whether there really is
	 * a logical unit attached (as some SCSI target controllers
	 * lie about a unit being ready, e.g., the Emulex MD21).
	 */

	if (scsi_test(inq_pkt) < 0) {
		rval = SCSIPROBE_FAILURE;
		goto out;
	}

	if (((struct scsi_status *)inq_pkt->pkt_scbp)->sts_busy) {
		rval = SCSIPROBE_BUSY;
		goto out;
	}

	/*
	 * Okay we sent the INQUIRY command.
	 *
	 * If enough data was transferred, we count that the
	 * Inquiry command succeeded, else we have to assume
	 * that this is a non-CCS scsi target (or a nonexistent
	 * target/lun).
	 */

	if (((struct scsi_status *)inq_pkt->pkt_scbp)->sts_chk) {
		/*
		 * try a request sense if we have a pkt, otherwise
		 * just retry the inquiry one more time
		 */
		if (rq_pkt) {
			(void) scsi_test(rq_pkt);
		}

		/*
		 * retry inquiry
		 */
		if (scsi_test(inq_pkt) < 0) {
			rval = SCSIPROBE_FAILURE;
			goto out;
		}
		if (((struct scsi_status *)inq_pkt->pkt_scbp)->sts_chk) {
			rval = SCSIPROBE_FAILURE;
			goto out;
		}
	}

done:
	/*
	 * If we got a parity error on receive of inquiry data,
	 * we're just plain out of luck because we told the host
	 * adapter to not watch for parity errors.
	 */
	if ((inq_pkt->pkt_state & STATE_XFERRED_DATA) == 0 ||
	    ((SUN_INQSIZE - inq_pkt->pkt_resid) < SUN_MIN_INQLEN)) {
		rval = SCSIPROBE_NONCCS;
	} else {
		ASSERT(inq_pkt->pkt_resid >= 0);
		bcopy((caddr_t)inq_bp->b_un.b_addr,
		    (caddr_t)sd->sd_inq, (SUN_INQSIZE - inq_pkt->pkt_resid));
		rval = SCSIPROBE_EXISTS;
	}

out:
	/*
	 * If lun > 0 we need to figure out if this is a scsi-1 device where
	 * the "real" lun needs to be embedded into the cdb.
	 */
	if ((rval == SCSIPROBE_EXISTS) && (pass == 1) &&
	    (sd->sd_address.a_lun > 0) && (sd->sd_inq->inq_ansi == 0x1)) {
		pass++;
		if (sd->sd_address.a_lun <= 7)
			goto again;

		/*
		 * invalid lun for scsi-1,
		 * return probe failure.
		 */
		rval = SCSIPROBE_FAILURE;
	}

	if (rq_pkt) {
		scsi_destroy_pkt(rq_pkt);
	}
	if (inq_pkt) {
		scsi_destroy_pkt(inq_pkt);
	}
	if (rq_bp) {
		scsi_free_consistent_buf(rq_bp);
	}
	if (inq_bp) {
		scsi_free_consistent_buf(inq_bp);
	}
	return (rval);
}

/*
 * Convert from a scsi_device structure pointer to a scsi_hba_tran structure
 * pointer. The correct way to do this is
 *
 *	#define	DEVP_TO_TRAN(sd)	((sd)->sd_address.a_hba_tran)
 *
 * however we have some consumers that place their own vector in a_hba_tran. To
 * avoid problems, we implement this using the sd_tran_safe. See
 * scsi_hba_initchild for more details.
 */
#define	DEVP_TO_TRAN(sd)	((sd)->sd_tran_safe)

/*
 * Function, callable from SCSA framework, to get 'human' readable REPORTDEV
 * addressing information from scsi_device properties.
 */
int
scsi_ua_get_reportdev(struct scsi_device *sd, char *ra, int len)
{
	/* use deprecated tran_get_bus_addr interface if it is defined */
	/* NOTE: tran_get_bus_addr is a poor name choice for interface */
	if (DEVP_TO_TRAN(sd)->tran_get_bus_addr)
		return ((*DEVP_TO_TRAN(sd)->tran_get_bus_addr)(sd, ra, len));
	return (scsi_hba_ua_get_reportdev(sd, ra, len));
}

/*
 * Function, callable from HBA driver's tran_get_bus_addr(9E) implementation,
 * to get standard form of human readable REPORTDEV addressing information
 * from scsi_device properties.
 */
int
scsi_hba_ua_get_reportdev(struct scsi_device *sd, char *ra, int len)
{
	int		tgt, lun, sfunc;
	char		*tgt_port;
	scsi_lun64_t	lun64;

	/* get device unit-address properties */
	tgt = scsi_device_prop_get_int(sd, SCSI_DEVICE_PROP_PATH,
	    SCSI_ADDR_PROP_TARGET, -1);
	if (scsi_device_prop_lookup_string(sd, SCSI_DEVICE_PROP_PATH,
	    SCSI_ADDR_PROP_TARGET_PORT, &tgt_port) != DDI_PROP_SUCCESS)
		tgt_port = NULL;
	if ((tgt == -1) && (tgt_port == NULL))
		return (0);		/* no target */

	lun = scsi_device_prop_get_int(sd, SCSI_DEVICE_PROP_PATH,
	    SCSI_ADDR_PROP_LUN, 0);
	lun64 = scsi_device_prop_get_int64(sd, SCSI_DEVICE_PROP_PATH,
	    SCSI_ADDR_PROP_LUN64, lun);
	sfunc = scsi_device_prop_get_int(sd, SCSI_DEVICE_PROP_PATH,
	    SCSI_ADDR_PROP_SFUNC, -1);

	/*
	 * XXX should the default be to print this in decimal for
	 * "human readable" form, so it matches conf files?
	 */
	if (tgt_port) {
		if (sfunc == -1)
			(void) snprintf(ra, len,
			    "%s %s lun %" PRIx64,
			    SCSI_ADDR_PROP_TARGET_PORT, tgt_port, lun64);
		else
			(void) snprintf(ra, len,
			    "%s %s lun %" PRIx64 " sfunc %x",
			    SCSI_ADDR_PROP_TARGET_PORT, tgt_port, lun64, sfunc);
		scsi_device_prop_free(sd, SCSI_DEVICE_PROP_PATH, tgt_port);
	} else {
		if (sfunc == -1)
			(void) snprintf(ra, len,
			    "%s %x lun %" PRIx64,
			    SCSI_ADDR_PROP_TARGET, tgt, lun64);
		else
			(void) snprintf(ra, len,
			    "%s %x lun %" PRIx64 " sfunc %x",
			    SCSI_ADDR_PROP_TARGET, tgt, lun64, sfunc);
	}

	return (1);
}

/*
 * scsi_ua_get: using properties, return "unit-address" string.
 * Called by SCSA framework, may call HBAs tran function.
 */
int
scsi_ua_get(struct scsi_device *sd, char *ua, int len)
{
	char		*eua;

	/* See if we already have established the unit-address. */
	if ((eua = scsi_device_unit_address(sd)) != NULL) {
		(void) strlcpy(ua, eua, len);
		return (1);
	}

	/* Use deprecated tran_get_name interface if it is defined. */
	/* NOTE: tran_get_name is a poor name choice for interface */
	if (DEVP_TO_TRAN(sd)->tran_get_name)
		return ((*DEVP_TO_TRAN(sd)->tran_get_name)(sd, ua, len));

	/* Use generic property implementation */
	return (scsi_hba_ua_get(sd, ua, len));
}

/*
 * scsi_hba_ua_get: using properties, return "unit-address" string.
 * This function may be called from an HBAs tran function.
 *
 * Function to get "unit-address" in "name@unit-address" /devices path
 * component form from the scsi_device unit-address properties on a node.
 *
 * NOTE: This function works in conjunction with scsi_hba_ua_set().
 */
int
scsi_hba_ua_get(struct scsi_device *sd, char *ua, int len)
{
	int		tgt, lun, sfunc;
	char		*tgt_port;
	scsi_lun64_t	lun64;

	/* get device unit-address properties */
	tgt = scsi_device_prop_get_int(sd, SCSI_DEVICE_PROP_PATH,
	    SCSI_ADDR_PROP_TARGET, -1);
	if (scsi_device_prop_lookup_string(sd, SCSI_DEVICE_PROP_PATH,
	    SCSI_ADDR_PROP_TARGET_PORT, &tgt_port) != DDI_PROP_SUCCESS)
		tgt_port = NULL;
	if ((tgt == -1) && (tgt_port == NULL))
		return (0);		/* no target */

	lun = scsi_device_prop_get_int(sd, SCSI_DEVICE_PROP_PATH,
	    SCSI_ADDR_PROP_LUN, 0);
	lun64 = scsi_device_prop_get_int64(sd, SCSI_DEVICE_PROP_PATH,
	    SCSI_ADDR_PROP_LUN64, lun);
	sfunc = scsi_device_prop_get_int(sd, SCSI_DEVICE_PROP_PATH,
	    SCSI_ADDR_PROP_SFUNC, -1);
	if (tgt_port) {
		if (sfunc == -1)
			(void) snprintf(ua, len, "%s,%" PRIx64,
			    tgt_port, lun64);
		else
			(void) snprintf(ua, len, "%s,%" PRIx64 ",%x",
			    tgt_port, lun64, sfunc);
		scsi_device_prop_free(sd, SCSI_DEVICE_PROP_PATH, tgt_port);
	} else {
		if (sfunc == -1)
			(void) snprintf(ua, len, "%x,%" PRIx64, tgt, lun64);
		else
			(void) snprintf(ua, len, "%x,%" PRIx64 ",%x",
			    tgt, lun64, sfunc);
	}
	return (1);
}

static void
create_inquiry_props(struct scsi_device *sd)
{
	struct scsi_inquiry *inq = sd->sd_inq;

	(void) ndi_prop_update_int(DDI_DEV_T_NONE, sd->sd_dev,
	    INQUIRY_DEVICE_TYPE, (int)inq->inq_dtype);

	/*
	 * Create the following properties:
	 *
	 * inquiry-vendor-id	Vendor id (INQUIRY data bytes 8-15)
	 * inquiry-product-id	Product id (INQUIRY data bytes 16-31)
	 * inquiry-revision-id	Product Rev level (INQUIRY data bytes 32-35)
	 *
	 * NOTE: We don't support creation of these properties for scsi-1
	 * devices (as the vid, pid and revision were not defined) and we
	 * don't create the property if they are of zero length when
	 * stripped of Nulls and spaces.
	 *
	 * NOTE: The first definition of these properties sticks. This gives
	 * a transport the ability to provide a higher-quality definition
	 * than the standard SCSI INQUIRY data.
	 */
	if (inq->inq_ansi != 1) {
		if (ddi_prop_exists(DDI_DEV_T_NONE, sd->sd_dev,
		    DDI_PROP_TYPE_STRING, INQUIRY_VENDOR_ID) == 0)
			(void) scsi_device_prop_update_inqstring(sd,
			    INQUIRY_VENDOR_ID,
			    inq->inq_vid, sizeof (inq->inq_vid));

		if (ddi_prop_exists(DDI_DEV_T_NONE, sd->sd_dev,
		    DDI_PROP_TYPE_STRING, INQUIRY_PRODUCT_ID) == 0)
			(void) scsi_device_prop_update_inqstring(sd,
			    INQUIRY_PRODUCT_ID,
			    inq->inq_pid, sizeof (inq->inq_pid));

		if (ddi_prop_exists(DDI_DEV_T_NONE, sd->sd_dev,
		    DDI_PROP_TYPE_STRING, INQUIRY_REVISION_ID) == 0)
			(void) scsi_device_prop_update_inqstring(sd,
			    INQUIRY_REVISION_ID,
			    inq->inq_revision, sizeof (inq->inq_revision));
	}
}

/*
 * Create 'inquiry' string properties.  An 'inquiry' string gets special
 * treatment to trim trailing blanks (etc) and ensure null termination.
 */
int
scsi_device_prop_update_inqstring(struct scsi_device *sd,
    char *name, char *data, size_t len)
{
	int	ilen;
	char	*data_string;
	int	rv;

	ilen = scsi_ascii_inquiry_len(data, len);
	ASSERT(ilen <= (int)len);
	if (ilen <= 0)
		return (DDI_PROP_INVAL_ARG);

	/* ensure null termination */
	data_string = kmem_zalloc(ilen + 1, KM_SLEEP);
	bcopy(data, data_string, ilen);
	rv = ndi_prop_update_string(DDI_DEV_T_NONE,
	    sd->sd_dev, name, data_string);
	kmem_free(data_string, ilen + 1);
	return (rv);
}

/*
 * Interfaces associated with SCSI_HBA_ADDR_COMPLEX
 * per-scsi_device HBA private data support.
 */
struct scsi_device *
scsi_address_device(struct scsi_address *sa)
{
	ASSERT(sa->a_hba_tran->tran_hba_flags & SCSI_HBA_ADDR_COMPLEX);
	return (sa->a.a_sd);
}

void
scsi_device_hba_private_set(struct scsi_device *sd, void *data)
{
	ASSERT(sd->sd_address.a_hba_tran->tran_hba_flags &
	    SCSI_HBA_ADDR_COMPLEX);
	sd->sd_hba_private = data;
}

void *
scsi_device_hba_private_get(struct scsi_device *sd)
{
	ASSERT(sd->sd_address.a_hba_tran->tran_hba_flags &
	    SCSI_HBA_ADDR_COMPLEX);
	return (sd->sd_hba_private);
}

/*
 * This routine is called from the start of scsi_probe() if a tgt/LUN to be
 * probed *may* be a request to probe a strictly SCSI-2 target (with respect
 * to LUNs) -- and this probe may be for a LUN number greater than 7,
 * which can cause a hardware hang
 *
 * return 0 if the probe can proceed,
 * else return 1, meaning do *NOT* probe this target/LUN
 */
static int
scsi_check_ss2_LUN_limit(struct scsi_device *sd)
{
	struct scsi_address	*ap = &(sd->sd_address);
	dev_info_t		*pdevi =
	    (dev_info_t *)DEVI(sd->sd_dev)->devi_parent;
	int			ret_val = 0;	/* default return value */
	uchar_t			*tgt_list;
	uint_t			tgt_nelements;
	int			i;


	/*
	 * check for what *might* be a problem probe, only we don't
	 * know yet what's really at the destination target/LUN
	 */
	if ((ap->a_target >= NTARGETS_WIDE) ||
	    (ap->a_lun < NLUNS_PER_TARGET)) {
		return (0);		/* okay to probe this target */
	}

	/*
	 * this *might* be a problematic probe, so look to see
	 * if the inquiry data matches
	 */
	SCSI_PROBE_DEBUG2(1, "SCSA pre-probe: checking tgt.LUN=%d.%d\n",
	    ap->a_target, ap->a_lun);
	SCSI_PROBE_DEBUG1(2,
	    "SCSA pre-probe: scanning parent node name: %s ...\n",
	    ddi_node_name(pdevi));

	/*
	 * look for a special property of our parent node that lists
	 * the targets under it for which we do *NOT* want to probe
	 * if LUN>7 -- if the property is found, look to see if our
	 * target ID is on that list
	 */
	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, pdevi,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, SS2_LUN0_TGT_LIST_PROP,
	    &tgt_list, &tgt_nelements) != DDI_PROP_SUCCESS) {
		/*
		 * no list, so it must be okay to probe this target.LUN
		 */
		SCSI_PROBE_DEBUG0(3,
		    "SCSA pre-probe: NO parent prop found\n");
	} else {
		for (i = 0; i < tgt_nelements; i++) {
			if (tgt_list[i] == ap->a_target) {
				/*
				 * we found a match, which means we do *NOT*
				 * want to probe the specified target.LUN
				 */
				ret_val = 1;
				break;
			}
		}
		ddi_prop_free(tgt_list);
#ifdef	DEBUG
		if (ret_val == 1) {
			SCSI_PROBE_DEBUG2(1,
			    "SCSA pre-probe: marker node FOUND for "
			    "tgt.LUN=%d.%d, so SKIPPING it\n",
			    ap->a_target, ap->a_lun);
		} else {
			SCSI_PROBE_DEBUG0(2,
			    "SCSA pre-probe: NO marker node found"
			    " -- OK to probe\n");
		}
#endif
	}
	return (ret_val);
}


/*
 * this routine is called from near the end of scsi_probe(),
 * to see if the just-probed node is on our list of strictly-SCSI-2 nodes,
 * and if it is we mark our parent node with this information
 */
static void
scsi_establish_LUN_limit(struct scsi_device *sd)
{
	struct scsi_address	*ap = &(sd->sd_address);
	struct scsi_inquiry	*inq = sd->sd_inq;
	dev_info_t		*devi = sd->sd_dev;
	char			*vid = NULL;
	char			*pid = NULL;
	char			*rev = NULL;
	int			i;
	const ss2_lun0_info_t	*p;
	int			bad_target_found = 0;


	/*
	 * if this inquiry data shows that we have a strictly-SCSI-2 device
	 * at LUN 0, then add it to our list of strictly-SCSI-2 devices,
	 * so that we can avoid probes where LUN>7 on this device later
	 */
	if ((ap->a_lun != 0) ||
	    (ap->a_target >= NTARGETS_WIDE) ||
	    (inq->inq_dtype != DTYPE_PROCESSOR) ||
	    (inq->inq_ansi != 2)) {
		/*
		 * this can't possibly be a node we want to look at, since
		 * either LUN is greater than 0, target is greater than or
		 * equal to 16, device type
		 * is not processor, or SCSI level is not SCSI-2,
		 * so don't bother checking for a strictly SCSI-2
		 * (only 8 LUN) target
		 */
		return;				/* don't care */
	}

	SCSI_PROBE_DEBUG2(1, "SCSA post-probe: LUN limit on tgt.LUN=%d.%d, "
	    "SCSI-2 PROCESSOR?\n", ap->a_target, ap->a_lun);

	ASSERT(devi != NULL);

	/*
	 * we have a node that has been probed that is: LUN=0, target<16,
	 * PROCESSOR-type SCSI target, and at the SCSI-2 level, so
	 * check INQ properties to see if it's in our list of strictly
	 * SCSI-2 targets
	 *
	 * first we have to get the VID/PID/REV INQUIRY properties for
	 * comparison
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    INQUIRY_VENDOR_ID, &vid) != DDI_PROP_SUCCESS) {
		SCSI_PROBE_DEBUG1(2, "SCSA post-probe: prop \"%s\" missing\n",
		    INQUIRY_VENDOR_ID);
		goto dun;
	}
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    INQUIRY_PRODUCT_ID, &pid) != DDI_PROP_SUCCESS) {
		SCSI_PROBE_DEBUG1(2, "SCSA post-probe: prop \"%s\" missing\n",
		    INQUIRY_PRODUCT_ID);
		goto dun;
	}
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    INQUIRY_REVISION_ID, &rev) != DDI_PROP_SUCCESS) {
		SCSI_PROBE_DEBUG1(2, "SCSA post-probe: prop \"%s\" missing\n",
		    INQUIRY_REVISION_ID);
		goto dun;
	}

	SCSI_PROBE_DEBUG3(3, "SCSA post-probe: looking for vid/pid/rev = "
	    "\"%s\"/\"%s\"/\"%s\"\n", vid, pid, rev);

	/*
	 * now that we have the INQUIRY properties from the device node,
	 * compare them with our known offenders
	 *
	 * Note: comparison is *CASE* *SENSITIVE*
	 */
	for (i = 0; i < scsi_probe_strict_s2_size; i++) {
		p = &scsi_probe_strict_s2_list[i];

		if ((strcmp(p->sli_vid, vid) == 0) &&
		    (strcmp(p->sli_pid, pid) == 0) &&
		    (strcmp(p->sli_rev, rev) == 0)) {
			/*
			 * we found a match -- do NOT want to probe this one
			 */
			SCSI_PROBE_DEBUG3(1,
			    "SCSA post-probe: recording strict SCSI-2 node "
			    "vid/pid/rev = \"%s\"/\"%s\"/\"%s\"\n",
			    vid, pid, rev);

			/*
			 * set/update private parent-node property,
			 * so we can find out about this node later
			 */
			bad_target_found = 1;
			break;
		}
	}

	/*
	 * either add remove target number from parent property
	 */
	scsi_update_parent_ss2_prop(devi, ap->a_target, bad_target_found);

dun:
	if (vid != NULL) {
		ddi_prop_free(vid);
	}
	if (pid != NULL) {
		ddi_prop_free(pid);
	}
	if (rev != NULL) {
		ddi_prop_free(rev);
	}
}


/*
 * update the parent node to add in the supplied tgt number to the target
 * list property already present (if any)
 *
 * since the target list can never be longer than 16, and each target
 * number is also small, we can save having to alloc memory by putting
 * a 16-byte array on the stack and using it for property memory
 *
 * if "add_tgt" is set then add the target to the parent's property, else
 * remove it (if present)
 */
static void
scsi_update_parent_ss2_prop(dev_info_t *devi, int tgt, int add_tgt)
{
	dev_info_t	*pdevi = (dev_info_t *)DEVI(devi)->devi_parent;
	uchar_t		*tgt_list;
	uint_t		nelements;
	uint_t		new_nelements;
	int		i;
	int		update_result;
	uchar_t		new_tgt_list[NTARGETS_WIDE];


	ASSERT(pdevi != NULL);

	SCSI_PROBE_DEBUG3(3,
	    "SCSA post-probe: updating parent=%s property to %s tgt=%d\n",
	    ddi_node_name(pdevi), add_tgt ? "add" : "remove", tgt);

	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, pdevi,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    SS2_LUN0_TGT_LIST_PROP, &tgt_list, &nelements) ==
	    DDI_PROP_SUCCESS) {

		if (add_tgt) {
			/*
			 * we found an existing property -- we might need
			 *	to add to it
			 */
			for (i = 0; i < nelements; i++) {
				if (tgt_list[i] == tgt) {
					/* target already in list */
					SCSI_PROBE_DEBUG1(2, "SCSA post-probe:"
					    " tgt %d already listed\n", tgt);
					ddi_prop_free(tgt_list);
					return;
				}
			}

			/*
			 * need to append our target number to end of list
			 *	(no need sorting list, as it's so short)
			 */

			/*
			 * will this new entry fit ?? -- it should, since
			 *	the array is 16-wide and only keep track of
			 *	16 targets, but check just in case
			 */
			new_nelements = nelements + 1;
			if (new_nelements >= NTARGETS_WIDE) {
				SCSI_PROBE_DEBUG0(1, "SCSA post-probe: "
				    "internal error: no room "
				    "for more targets?\n");
				ddi_prop_free(tgt_list);
				return;
			}

			/* copy existing list then add our tgt number to end */
			bcopy((void *)tgt_list, (void *)new_tgt_list,
			    sizeof (uchar_t) * nelements);
			new_tgt_list[new_nelements - 1] = (uchar_t)tgt;
		} else {
			/*
			 * we need to remove our target number from the list,
			 *	so copy all of the other target numbers,
			 *	skipping ours
			 */
			int	tgt_removed = 0;

			new_nelements = 0;
			for (i = 0; i < nelements; i++) {
				if (tgt_list[i] != tgt) {
					new_tgt_list[new_nelements++] =
					    tgt_list[i];
				} else {
					/* skip this target */
					tgt_removed++;
				}
			}

			if (!tgt_removed) {
				SCSI_PROBE_DEBUG1(2, "SCSA post-probe:"
				    " no need to remove tgt %d\n", tgt);
				ddi_prop_free(tgt_list);
				return;
			}
		}

		update_result = ddi_prop_update_byte_array(DDI_DEV_T_NONE,
		    pdevi, SS2_LUN0_TGT_LIST_PROP, new_tgt_list,
		    new_nelements);

		ddi_prop_free(tgt_list);
	} else {
		/*
		 * no property yet
		 */
		if (add_tgt) {
			/*
			 * create a property with just our tgt
			 */
			new_tgt_list[0] = (uchar_t)tgt;
			new_nelements = 1;	/* just one element */

			update_result = ddi_prop_update_byte_array(
			    DDI_DEV_T_NONE, pdevi, SS2_LUN0_TGT_LIST_PROP,
			    new_tgt_list, new_nelements);
		} else {
			/*
			 * no list so no need to remove tgt from that list
			 */
			return;
		}
	}

#ifdef	DEBUG
	/*
	 * if we get here we have tried to add/update properties
	 */
	if (update_result != DDI_PROP_SUCCESS) {
		SCSI_PROBE_DEBUG2(1, "SCSA post-probe: can't update parent "
		    "property with tgt=%d (%d)\n", tgt, update_result);
	} else {
		if (add_tgt) {
			SCSI_PROBE_DEBUG3(2,
			    "SCSA post-probe: added tgt=%d to parent "
			    "prop=\"%s\" (now %d entries)\n",
			    tgt, SS2_LUN0_TGT_LIST_PROP, new_nelements);
		} else {
			SCSI_PROBE_DEBUG3(2,
			    "SCSA post-probe: removed tgt=%d from parent "
			    "prop=\"%s\" (now %d entries)\n",
			    tgt, SS2_LUN0_TGT_LIST_PROP, new_nelements);
		}
	}
#endif
}


/* XXX BEGIN: find a better place for this: inquiry.h? */
/*
 * Definitions used by device id registration routines
 */
#define	VPD_HEAD_OFFSET		3	/* size of head for vpd page */
#define	VPD_PAGE_LENGTH		3	/* offset for pge length data */
#define	VPD_MODE_PAGE		1	/* offset into vpd pg for "page code" */

/* size for devid inquiries */
#define	MAX_INQUIRY_SIZE	0xF0
#define	MAX_INQUIRY_SIZE_EVPD	0xFF	/* XXX why is this longer */
/* XXX END: find a better place for these */


/*
 * Decorate devinfo node with identity properties using information obtained
 * from device. These properties are used by device enumeration code to derive
 * the devid, and guid for the device. These properties are also used to
 * determine if a device should be enumerated under the physical HBA (PHCI) or
 * the virtual HBA (VHCI, for mpxio support).
 *
 * Return zero on success. If commands that should succeed fail or allocations
 * fail then return failure (non-zero). It is possible for this function to
 * return success and not have decorated the node with any additional identity
 * information if the device correctly responds indicating that they are not
 * supported.  When failure occurs the caller should consider not making the
 * device accessible.
 */
int
scsi_device_identity(struct scsi_device *sd, int (*callback)())
{
	dev_info_t	*devi		= sd->sd_dev;
	uchar_t		*inq80		= NULL;
	uchar_t		*inq83		= NULL;
	int		rval;
	size_t		len;
	int		pg80, pg83;

	/* find out what pages are supported by device */
	if (check_vpd_page_support8083(sd, callback, &pg80, &pg83) == -1)
		return (-1);

	/* if available, collect page 80 data and add as property */
	if (pg80) {
		inq80 = kmem_zalloc(MAX_INQUIRY_SIZE,
		    ((callback == SLEEP_FUNC) ? KM_SLEEP : KM_NOSLEEP));
		if (inq80 == NULL) {
			rval = -1;
			goto out;
		}

		rval = send_scsi_INQUIRY(sd, callback, inq80,
		    MAX_INQUIRY_SIZE, 0x01, 0x80, &len);
		if (rval)
			goto out;		/* should have worked */

		if (len && (ndi_prop_update_byte_array(DDI_DEV_T_NONE, devi,
		    "inquiry-page-80", inq80, len) != DDI_PROP_SUCCESS)) {
			cmn_err(CE_WARN, "scsi_device_identity: "
			    "failed to add page80 prop");
			rval = -1;
			goto out;
		}
	}

	/* if available, collect page 83 data and add as property */
	if (pg83) {
		inq83 = kmem_zalloc(MAX_INQUIRY_SIZE,
		    ((callback == SLEEP_FUNC) ? KM_SLEEP : KM_NOSLEEP));
		if (inq83 == NULL) {
			rval = -1;
			goto out;
		}

		rval = send_scsi_INQUIRY(sd, callback, inq83,
		    MAX_INQUIRY_SIZE, 0x01, 0x83, &len);
		if (rval)
			goto out;		/* should have worked */

		if (len && (ndi_prop_update_byte_array(DDI_DEV_T_NONE, devi,
		    "inquiry-page-83", inq83, len) != DDI_PROP_SUCCESS)) {
			cmn_err(CE_WARN, "scsi_device_identity: "
			    "failed to add page83 prop");
			rval = -1;
			goto out;
		}
	}

	/* Commands worked, identity information that exists has been added. */
	rval = 0;

	/* clean up resources */
out:	if (inq80 != NULL)
		kmem_free(inq80, MAX_INQUIRY_SIZE);
	if (inq83 != NULL)
		kmem_free(inq83, MAX_INQUIRY_SIZE);

	return (rval);
}

/*
 * Send an INQUIRY command with the EVPD bit set and a page code of 0x00 to
 * the device, returning zero on success. Returned INQUIRY data is used to
 * determine which vital product pages are supported. The device idenity
 * information we are looking for is in pages 0x83 and/or 0x80. If the device
 * fails the EVPD inquiry then no pages are supported but the call succeeds.
 * Return -1 (failure) if there were memory allocation failures or if a
 * command faild that should have worked.
 */
static int
check_vpd_page_support8083(struct scsi_device *sd, int (*callback)(),
	int *ppg80, int *ppg83)
{
	uchar_t *page_list;
	int	counter;
	int	rval;

	/* pages are not supported */
	*ppg80 = 0;
	*ppg83 = 0;

	/*
	 * We'll set the page length to the maximum to save figuring it out
	 * with an additional call.
	 */
	page_list =  kmem_zalloc(MAX_INQUIRY_SIZE_EVPD,
	    ((callback == SLEEP_FUNC) ? KM_SLEEP : KM_NOSLEEP));
	if (page_list == NULL)
		return (-1);		/* memory allocation problem */

	/* issue page 0 (Supported VPD Pages) INQUIRY with evpd set */
	rval = send_scsi_INQUIRY(sd, callback,
	    page_list, MAX_INQUIRY_SIZE_EVPD, 1, 0, NULL);

	/*
	 * Now we must validate that the device accepted the command (some
	 * devices do not support it) and if the idenity pages we are
	 * interested in are supported.
	 */
	if ((rval == 0) &&
	    (page_list[VPD_MODE_PAGE] == 0x00)) {
		/* Loop to find one of the 2 pages we need */
		counter = 4;  /* Supported pages start at byte 4, with 0x00 */

		/*
		 * Pages are returned in ascending order, and 0x83 is the
		 * last page we are hoping to find.
		 */
		while ((page_list[counter] <= 0x83) &&
		    (counter <= (page_list[VPD_PAGE_LENGTH] +
		    VPD_HEAD_OFFSET))) {
			/*
			 * Add 3 because page_list[3] is the number of
			 * pages minus 3
			 */

			switch (page_list[counter]) {
			case 0x80:
				*ppg80 = 1;
				break;
			case 0x83:
				*ppg83 = 1;
				break;
			}
			counter++;
		}
	}

	kmem_free(page_list, MAX_INQUIRY_SIZE_EVPD);
	return (0);
}

/*
 * Send INQUIRY command with specified EVPD and page code.  Return
 * zero on success.  On success, the amount of data transferred
 * is returned in *lenp.
 */
static int
send_scsi_INQUIRY(struct scsi_device *sd, int (*callback)(),
    uchar_t *bufaddr, size_t buflen,
    uchar_t evpd, uchar_t page_code, size_t *lenp)
{
	int		(*cb_flag)();
	struct buf	*inq_bp;
	struct scsi_pkt *inq_pkt = NULL;
	int		rval = -1;

	if (lenp)
		*lenp = 0;
	if (callback != SLEEP_FUNC && callback != NULL_FUNC)
		cb_flag = NULL_FUNC;
	else
		cb_flag = callback;
	inq_bp = scsi_alloc_consistent_buf(ROUTE,
	    (struct buf *)NULL, buflen, B_READ, cb_flag, NULL);
	if (inq_bp == NULL)
		goto out;		/* memory allocation problem */

	inq_pkt = scsi_init_pkt(ROUTE, (struct scsi_pkt *)NULL,
	    inq_bp, CDB_GROUP0, sizeof (struct scsi_arq_status),
	    0, PKT_CONSISTENT, callback, NULL);
	if (inq_pkt == NULL)
		goto out;		/* memory allocation problem */

	ASSERT(inq_bp->b_error == 0);

	/* form INQUIRY cdb with specified EVPD and page code */
	(void) scsi_setup_cdb((union scsi_cdb *)inq_pkt->pkt_cdbp,
	    SCMD_INQUIRY, 0, buflen, 0);
	inq_pkt->pkt_cdbp[1] = evpd;
	inq_pkt->pkt_cdbp[2] = page_code;

	inq_pkt->pkt_time = SCSI_POLL_TIMEOUT;	/* in seconds */
	inq_pkt->pkt_flags = FLAG_NOINTR|FLAG_NOPARITY;

	/*
	 * Issue inquiry command thru scsi_test
	 *
	 * NOTE: This is important data about device identity, not sure why
	 * NOPARITY is used. Also seems like we should check pkt_stat for
	 * STATE_XFERRED_DATA.
	 */
	if ((scsi_test(inq_pkt) == 0) &&
	    (inq_pkt->pkt_reason == CMD_CMPLT) &&
	    (((*inq_pkt->pkt_scbp) & STATUS_MASK) == 0)) {
		ASSERT(inq_pkt->pkt_resid >= 0);
		ASSERT(inq_pkt->pkt_resid <= buflen);

		bcopy(inq_bp->b_un.b_addr,
		    bufaddr, buflen - inq_pkt->pkt_resid);
		if (lenp)
			*lenp = (buflen - inq_pkt->pkt_resid);
		rval = 0;
	}

out:	if (inq_pkt)
		scsi_destroy_pkt(inq_pkt);
	if (inq_bp)
		scsi_free_consistent_buf(inq_bp);
	return (rval);
}
