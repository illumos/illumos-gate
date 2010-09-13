/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Utility DCD configuration routines.
 */

#include	<sys/dada/dada.h>
#include 	<sys/modctl.h>

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops, 	/* Type of module */
	" ATA Bus Utility Routines"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};



static int dcd_test(struct dcd_pkt *);
void makecommand(struct dcd_pkt *, int, uchar_t, uint32_t,
				uchar_t, uint32_t, uchar_t, uchar_t);

int
_init()
{

	(void) dcd_initialize_hba_interface();

	return (mod_install(&modlinkage));
}


/*
 * There is no _fini() routine because this module is never unloaded.
 */
int
_info(modinfop)
struct modinfo *modinfop;
{

	return (mod_info(&modlinkage, modinfop));
}

/*
 * The implementation of dcd_probe allows a particular HBA to intercept the call
 * for any post or pre-processing it may need. The default, if the HBA does not
 * override it, is to call dcd_hba_probe.
 */
int
dcd_probe(struct dcd_device *devp, int (*callback)())
{
	dcd_hba_tran_t	*hba_tran = devp->dcd_address->a_hba_tran;

	if (hba_tran->tran_tgt_probe != NULL) {
		return ((*hba_tran->tran_tgt_probe)(devp, callback));
	} else {
		return (dcd_hba_probe(devp, callback));
	}
}

/*
 * Undo the dcd_probe
 */
void
dcd_unprobe(struct dcd_device *devp)
{
	if (devp->dcd_ident) {
		kmem_free((caddr_t)devp->dcd_ident, SUN_IDENTSIZE);
		devp->dcd_ident = (struct dcd_identify *)NULL;
	}
}

#define	ROUTE   (devp->dcd_address)

int
dcd_hba_probe(struct dcd_device *devp, int (*callback)())
{

	struct dcd_pkt *ident_pkt = NULL;
	int rval = DCDPROBE_NOMEM;
	struct buf *ident_bp = NULL;
	int  (*cb_flag)();

	if (devp->dcd_ident == NULL) {
#ifdef DEBUG1
		printf("Dcd_ident is NULL\n");
#endif

		devp->dcd_ident = (struct dcd_identify *)
			kmem_alloc(SUN_IDENTSIZE, ((callback == SLEEP_FUNC)?
						KM_SLEEP : KM_NOSLEEP));
		if (devp->dcd_ident == NULL) {
				goto out;
		}
	}

	if (callback != SLEEP_FUNC && callback != NULL_FUNC) {
		cb_flag = NULL_FUNC;
	} else {
		cb_flag = callback;
	}

	ident_bp = dcd_alloc_consistent_buf(ROUTE, (struct buf *)NULL,
			(uint_t)SUN_IDENTSIZE, B_READ, cb_flag, NULL);
	if (ident_bp == NULL) {
		goto out;
	}

	ident_pkt = dcd_init_pkt(ROUTE, (struct dcd_pkt *)NULL,
			ident_bp, sizeof (struct dcd_cmd), 2, 0,
			PKT_CONSISTENT,
			callback, NULL);

	if (ident_pkt == NULL) {
		if (ident_bp->b_error == 0)
			rval = DCDPROBE_NOMEM_CB;
		goto out;
	}

	bp_mapin(ident_bp);

	bzero((caddr_t)devp->dcd_ident, SUN_IDENTSIZE);

	makecommand(ident_pkt, FLAG_NOINTR, IDENTIFY, 0, ADD_LBA_MODE,
		SUN_IDENTSIZE, DATA_READ, 0);

	/*
	 * The first identify will tell us whether the target responded
	 * or not.
	 */

	if (dcd_test(ident_pkt) < 0) {
#ifdef DEBUG1
	printf("dcd_test: failed\n");
#endif
		if (ident_pkt->pkt_reason == CMD_INCOMPLETE) {
			rval = DCDPROBE_NORESP;
			goto out;
		} else {
			/*
			 * retry one more time
			 */
			if (dcd_test(ident_pkt) < 0) {
				rval = DCDPROBE_FAILURE;
				goto out;
			}
		}
	}

#ifdef DEBUG1
	printf("Pkt reason %x, scsbp %x\n", ident_pkt->pkt_reason,
		*ident_pkt->pkt_scbp);
#endif
	/*
	 * If we are lucky, this identify succeeded
	 */
	if ((ident_pkt->pkt_reason == CMD_CMPLT) &&
		(((*ident_pkt->pkt_scbp) & STATUS_ATA_MASK) == 0)) {
		goto done;
	}

	/*
	 * the second inquiry, allows the host adapters to try again.
	 */
	if (dcd_test(ident_pkt) < 0) {
		if (ident_pkt->pkt_reason == CMD_INCOMPLETE)
			rval = DCDPROBE_NORESP;
		else
			rval = DCDPROBE_FAILURE;
		goto out;
	}

	/*
	 * At this point we are guarenteed that something responded
	 * to this target. We don't know yest what kind of device it is.
	 */

	if (dcd_test(ident_pkt) < 0) {
		rval = DCDPROBE_FAILURE;
		goto out;
	}

done:
	/*
	 * If we got no error then receive the indentify data,
	 */
	if ((ident_pkt->pkt_state & STATE_XFERRED_DATA) == 0 &&
		ident_pkt->pkt_resid > 0) {
		rval = DCDPROBE_NONCCS;
	} else {
		bcopy((caddr_t)ident_bp->b_un.b_addr,
			(caddr_t)devp->dcd_ident, SUN_IDENTSIZE);
		rval = DCDPROBE_EXISTS;
	}

out:
	if (ident_pkt) {
		dcd_destroy_pkt(ident_pkt);
	}
	if (ident_bp) {
		dcd_free_consistent_buf(ident_bp);
	}
	return (rval);
}


static int
dcd_test(struct dcd_pkt *pkt)
{

	int rval = -1;

	pkt->pkt_flags |= FLAG_NOINTR;
	pkt->pkt_time = DCD_POLL_TIMEOUT;

#ifdef DEBUG1
	printf("flags %x: timeout %x\n", pkt->pkt_flags, pkt->pkt_time);
#endif

	if (dcd_transport(pkt) != TRAN_ACCEPT) {
		goto error;
	} else if (pkt->pkt_reason == CMD_INCOMPLETE &&
			pkt->pkt_state == 0) {
		goto error;
	} else if (pkt->pkt_reason != CMD_CMPLT) {
		goto error;
	} else if (((*pkt->pkt_scbp) & STATUS_ATA_MASK) == STATUS_ATA_BUSY) {
		rval = 0;
	} else {
		rval = 0;
	}
error:
#ifdef DEBUG1
	printf("dcd_test: rval is %x\n", rval);
#endif

	return (rval);
}

void
makecommand(struct dcd_pkt *pkt,
		int	flags,
		uchar_t	command,
		uint32_t block,
		uchar_t	address_mode,
		uint32_t size,
		uchar_t	direction,
		uchar_t	features)
{

	struct	dcd_cmd *cdbp = (struct dcd_cmd *)pkt->pkt_cdbp;

	cdbp->cmd = command;
	cdbp->sector_num.lba_num = block;
	cdbp->address_mode = address_mode;
	cdbp->direction = direction;
	cdbp->size = size;	/* Size in bytes */
	cdbp->features = features;

	pkt->pkt_flags = flags;
#ifdef DEBUG1
	printf("pkt flags set in dada %x\n", pkt->pkt_flags);

	printf("command %x, flags %x, block %x, address_mode %x, size %x\n",
		command, flags, block, address_mode, size);
#endif


}
