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

#define	FILL_SCSI1_LUN(devp, pkt) \
	if ((devp->sd_address.a_lun > 0) && \
	    (devp->sd_inq->inq_ansi == 0x1)) { \
		((union scsi_cdb *)(pkt)->pkt_cdbp)->scc_lun = \
		    devp->sd_address.a_lun; \
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
static int get_inquiry_prop_len(char *, size_t);

static int scsi_check_ss2_LUN_limit(struct scsi_device *);
static void scsi_establish_LUN_limit(struct scsi_device *);
static void scsi_update_parent_ss2_prop(dev_info_t *, int, int);

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

#define	ROUTE	(&devp->sd_address)

static int
scsi_slave_do_rqsense(struct scsi_device *devp, int (*callback)())
{
	struct scsi_pkt *rq_pkt = NULL;
	struct buf *rq_bp = NULL;
	int rval = SCSIPROBE_EXISTS;

	/*
	 * prepare rqsense packet
	 */
	rq_bp = scsi_alloc_consistent_buf(ROUTE,
	    (struct buf *)NULL,
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
	FILL_SCSI1_LUN(devp, rq_pkt);
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
 * Mostly attempts to allocate and fill devp inquiry data..
 */

int
scsi_slave(struct scsi_device *devp, int (*callback)())
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
	FILL_SCSI1_LUN(devp, pkt);
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
				rval = scsi_slave_do_rqsense(devp, callback);
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
			rval = scsi_slave_do_rqsense(devp, callback);
		}
	}

	/*
	 * call scsi_probe to do the inquiry
	 * XXX there is minor difference with the old scsi_slave implementation:
	 * busy conditions are not handled in scsi_probe.
	 */
	scsi_destroy_pkt(pkt);
	if (rval == SCSIPROBE_EXISTS) {
		return (scsi_probe(devp, callback));
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
scsi_unslave(struct scsi_device *devp)
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
scsi_unprobe(struct scsi_device *devp)
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
scsi_probe(struct scsi_device *devp, int (*callback)())
{
	int ret;
	scsi_hba_tran_t		*hba_tran = devp->sd_address.a_hba_tran;


	if (scsi_check_ss2_LUN_limit(devp) != 0) {
		/*
		 * caller is trying to probe a strictly-SCSI-2 device
		 * with a LUN that is too large, so do not allow it
		 */
		return (SCSIPROBE_NORESP);	/* skip probing this one */
	}

	if (hba_tran->tran_tgt_probe != NULL) {
		ret = (*hba_tran->tran_tgt_probe)(devp, callback);
	} else {
		ret = scsi_hba_probe(devp, callback);
	}

	if (ret == SCSIPROBE_EXISTS) {
		create_inquiry_props(devp);
		/* is this a strictly-SCSI-2 node ?? */
		scsi_establish_LUN_limit(devp);
	}

	return (ret);
}

/*
 * scsi_hba_probe does not do any test unit ready's which access the medium
 * and could cause busy or not ready conditions.
 * scsi_hba_probe does 2 inquiries and a rqsense to clear unit attention
 * and to allow sync negotiation to take place
 * finally, scsi_hba_probe does one more inquiry which should
 * reliably tell us what kind of target we have.
 * A scsi-2 compliant target should be able to	return inquiry with 250ms
 * and we actually wait more than a second after reset.
 */
int
scsi_hba_probe(struct scsi_device *devp, int (*callback)())
{
	struct scsi_pkt		*inq_pkt = NULL;
	struct scsi_pkt		*rq_pkt = NULL;
	int			rval = SCSIPROBE_NOMEM;
	struct buf		*inq_bp = NULL;
	struct buf		*rq_bp = NULL;
	int			(*cb_flag)();
	int			pass = 1;

	if (devp->sd_inq == NULL) {
		devp->sd_inq = (struct scsi_inquiry *)
		    kmem_alloc(SUN_INQSIZE, ((callback == SLEEP_FUNC) ?
		    KM_SLEEP : KM_NOSLEEP));
		if (devp->sd_inq == NULL) {
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
	 * the first inquiry will tell us whether a target
	 * responded
	 *
	 * The FILL_SCSI1_LUN below will find "ansi_ver != 1" on first pass
	 * because of bzero initilization. If this assumption turns out to be
	 * incorrect after we have real sd_inq data (for lun0) we will do a
	 * second pass during which FILL_SCSI1_LUN will place lun in CDB.
	 */
	bzero((caddr_t)devp->sd_inq, SUN_INQSIZE);
again:	FILL_SCSI1_LUN(devp, inq_pkt);

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
			FILL_SCSI1_LUN(devp, rq_pkt);
			rq_pkt->pkt_flags = FLAG_NOINTR|FLAG_NOPARITY;

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
		    (caddr_t)devp->sd_inq, (SUN_INQSIZE - inq_pkt->pkt_resid));
		rval = SCSIPROBE_EXISTS;
	}

out:
	/*
	 * If lun > 0 we need to figure out if this is a scsi-1 device where
	 * the "real" lun needs to be embedded into the cdb.
	 */
	if ((rval == SCSIPROBE_EXISTS) && (pass == 1) &&
	    (devp->sd_address.a_lun > 0) && (devp->sd_inq->inq_ansi == 0x1)) {
		pass++;
		if (devp->sd_address.a_lun <= 7)
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


#define	A_TO_TRAN(ap)	(ap->a_hba_tran)

/*
 * Function to get target and lun identifiers from HBA driver.
 */
int
scsi_get_bus_addr(struct scsi_device *devp, char *name, int len)
{
	struct scsi_address *ap = &devp->sd_address;

	if ((A_TO_TRAN(ap)->tran_get_bus_addr) == NULL) {
		(void) sprintf(name, "%x,%x", ap->a_target, ap->a_lun);
		return (1);
	}
	return (*A_TO_TRAN(ap)->tran_get_bus_addr)(devp, name, len);
}

/*
 * Function to get name from HBA driver.
 */
int
scsi_get_name(struct scsi_device *devp, char *name, int len)
{
	struct scsi_address *ap = &devp->sd_address;

	if ((A_TO_TRAN(ap)->tran_get_name) == NULL) {
		(void) sprintf(name, "%x,%x", ap->a_target, ap->a_lun);
		return (1);
	}
	return (*A_TO_TRAN(ap)->tran_get_name)(devp, name, len);
}

void
create_inquiry_props(struct scsi_device *devp)
{
	struct scsi_inquiry *inq = devp->sd_inq;

	(void) ndi_prop_update_int(DDI_DEV_T_NONE, devp->sd_dev,
	    INQUIRY_DEVICE_TYPE, (int)inq->inq_dtype);

	/*
	 * Create the following properties:
	 *
	 * inquiry-vendor-id 	Vendor id (INQUIRY data bytes 8-15)
	 * inquiry-product-id 	Product id (INQUIRY data bytes 16-31)
	 * inquiry-revision-id 	Product Rev level (INQUIRY data bytes 32-35)
	 *
	 * Note we don't support creation of these properties for scsi-1
	 * devices (as the vid, pid and revision were not defined) and we
	 * don't create the property if they are of zero length when
	 * stripped of Nulls and spaces.
	 */
	if (inq->inq_ansi != 1) {
		if (ddi_prop_exists(DDI_DEV_T_NONE, devp->sd_dev,
		    DDI_PROP_TYPE_STRING, INQUIRY_VENDOR_ID) == 0)
			(void) scsi_hba_prop_update_inqstring(devp,
			    INQUIRY_VENDOR_ID,
			    inq->inq_vid, sizeof (inq->inq_vid));

		if (ddi_prop_exists(DDI_DEV_T_NONE, devp->sd_dev,
		    DDI_PROP_TYPE_STRING, INQUIRY_PRODUCT_ID) == 0)
			(void) scsi_hba_prop_update_inqstring(devp,
			    INQUIRY_PRODUCT_ID,
			    inq->inq_pid, sizeof (inq->inq_pid));

		if (ddi_prop_exists(DDI_DEV_T_NONE, devp->sd_dev,
		    DDI_PROP_TYPE_STRING, INQUIRY_REVISION_ID) == 0)
			(void) scsi_hba_prop_update_inqstring(devp,
			    INQUIRY_REVISION_ID,
			    inq->inq_revision, sizeof (inq->inq_revision));
	}
}

/*
 * Create 'inquiry' string properties.  An 'inquiry' string gets special
 * treatment to trim trailing blanks (etc) and ensure null termination.
 */
int
scsi_hba_prop_update_inqstring(struct scsi_device *devp,
    char *name, char *data, size_t len)
{
	int	ilen;
	char	*data_string;
	int	rv;

	ilen = get_inquiry_prop_len(data, len);
	ASSERT(ilen <= (int)len);
	if (ilen <= 0)
		return (DDI_PROP_INVAL_ARG);

	/* ensure null termination */
	data_string = kmem_zalloc(ilen + 1, KM_SLEEP);
	bcopy(data, data_string, ilen);
	rv = ndi_prop_update_string(DDI_DEV_T_NONE,
	    devp->sd_dev, name, data_string);
	kmem_free(data_string, ilen + 1);
	return (rv);
}

/*
 * This routine returns the true length of the inquiry properties that are to
 * be created by removing the padded spaces at the end of the inquiry data.
 * This routine was designed for trimming spaces from the vid, pid and revision
 * which are defined as being left aligned.  In addition, we return 0 length
 * if the property is full of all 0's or spaces, indicating to the caller that
 * the device was not ready to return the proper inquiry data as per note 65 in
 * the scsi-2 spec.
 */
static int
get_inquiry_prop_len(char *property, size_t length)
{
	int retval;
	int trailer;
	char *p;

	retval = length;

	/*
	 * The vid, pid and revision are left-aligned ascii fields within the
	 * inquiry data.  Here we trim the end of these fields by discounting
	 * length associated with trailing spaces or NULL bytes.  The remaining
	 * bytes shall be only graphics codes - 0x20 through 0x7e as per the
	 * scsi spec definition.  If we have all 0's or spaces, we return 0
	 * length.  For devices that store inquiry data on the device, they
	 * can return 0's or spaces in these fields until the data is avail-
	 * able from the device (See NOTE 65 in the scsi-2 specification
	 * around the inquiry command.)  We don't want to create a property in
	 * the case of a device not able to return valid data.
	 */
	trailer = 1;
	for (p = property + length - 1; p >= property; p--) {
		if (trailer) {
			if ((*p == ' ') || (*p == '\0')) {
				retval--;
				continue;
			}
			trailer = 0;
		}

		/* each char must be within 0x20 - 0x7e */
		if (*p < 0x20 || *p > 0x7e) {
			retval = -1;
			break;
		}

	}

	return (retval);
}


/*
 * this routine is called from the start of scsi_probe() if a tgt/LUN to be
 * probed *may* be a request to probe a strictly SCSI-2 target (with respect
 * to LUNs) -- and this probe may be for a LUN number greater than 7,
 * which can cause a hardware hang
 *
 * return 0 if the probe can proceed,
 * else return 1, meaning do *NOT* probe this target/LUN
 */
static int
scsi_check_ss2_LUN_limit(struct scsi_device *devp)
{
	struct scsi_address	*ap = &(devp->sd_address);
	dev_info_t		*pdevi =
	    (dev_info_t *)DEVI(devp->sd_dev)->devi_parent;
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
	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY,
	    pdevi, DDI_PROP_DONTPASS, SS2_LUN0_TGT_LIST_PROP,
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
scsi_establish_LUN_limit(struct scsi_device *devp)
{
	struct scsi_address	*ap = &(devp->sd_address);
	struct scsi_inquiry	*inq = devp->sd_inq;
	dev_info_t		*devi = devp->sd_dev;
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
		 * eqaual to 16, device type
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
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    INQUIRY_VENDOR_ID, &vid) != DDI_PROP_SUCCESS) {
		SCSI_PROBE_DEBUG1(2, "SCSA post-probe: prop \"%s\" missing\n",
		    INQUIRY_VENDOR_ID);
		goto dun;
	}
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    INQUIRY_PRODUCT_ID, &pid) != DDI_PROP_SUCCESS) {
		SCSI_PROBE_DEBUG1(2, "SCSA post-probe: prop \"%s\" missing\n",
		    INQUIRY_PRODUCT_ID);
		goto dun;
	}
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
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

	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, pdevi, DDI_PROP_DONTPASS,
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
