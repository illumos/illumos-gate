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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/adapters/scsi_vhci.h>
#include <sys/scsi/adapters/scsi_vhci_tpgs.h>

/*
 * External function definitions
 */
extern void vhci_mpapi_update_tpg_data(struct scsi_address *, char *);



static int vhci_tpgs_inquiry(struct scsi_address *ap, struct buf *bp,
    int *mode);
static int vhci_tpgs_page83(struct scsi_address *ap, struct buf *bp,
    int *rel_tgt_port, int *tgt_port, int *lu);
static void print_buf(char *buf, int buf_size);
static int vhci_tpgs_report_target_groups(struct scsi_address *ap,
    struct buf *bp, int rel_tgt_port, int tgt_port, int *pstate,
    int *preferred);

int
vhci_tpgs_set_target_groups(struct scsi_address *ap, int set_state,
    int tpg_id)
{
	struct scsi_pkt			*pkt;
	struct buf			*bp;
	int				len, rval, ss = SCSI_SENSE_UNKNOWN;
	char				*bufp;
	struct scsi_extended_sense	*sns;

	len = 8;

	bp = getrbuf(KM_NOSLEEP);
	if (bp == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_tpgs_set_target_groups: "
		    " failed getrbuf"));
		return (1);
	}

	bufp = kmem_zalloc(len, KM_NOSLEEP);
	if (bufp == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_tpgs_set_target_groups: "
		    "request packet allocation for %d failed....", len));
		freerbuf(bp);
		return (1);
	}

	bp->b_un.b_addr = bufp;
	bp->b_flags = B_READ;
	bp->b_bcount = len;
	bp->b_resid = 0;

	bufp[4] = (0x0f & set_state);
	bufp[6] = (0xff00 & tpg_id) >> 8;
	bufp[7] = (0x00ff & tpg_id);

	pkt = scsi_init_pkt(ap, NULL, bp, CDB_GROUP5,
	    sizeof (struct scsi_arq_status), 0, 0, NULL, NULL);

	if (pkt == NULL) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!vhci_tpgs_set_target_groups: scsi_init_pkt error\n"));
		freerbuf(bp);
		kmem_free((void *)bufp, len);
		return (1);
	}

	/*
	 * Sends 1 TPG descriptor only. Hence Parameter list length pkt_cdbp[9]
	 * is set to 8 bytes - Refer SPC3 for details.
	 */
	pkt->pkt_cdbp[0] = SCMD_MAINTENANCE_OUT;
	pkt->pkt_cdbp[1] = SSVC_ACTION_SET_TARGET_PORT_GROUPS;
	pkt->pkt_cdbp[9] = 8;
	pkt->pkt_time = 90;

	VHCI_DEBUG(1, (CE_NOTE, NULL,
	    "!vhci_tpgs_set_target_groups: sending set target port group:"
	    " cdb[0/1/6/7/8/9]: %x/%x/%x/%x/%x/%x\n", pkt->pkt_cdbp[0],
	    pkt->pkt_cdbp[1], pkt->pkt_cdbp[6], pkt->pkt_cdbp[7],
	    pkt->pkt_cdbp[8], pkt->pkt_cdbp[9]));

#ifdef DEBUG
	print_buf(bufp, len);
#endif
	rval = vhci_do_scsi_cmd(pkt);

	if (rval == 0) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_tpgs_set_target_groups:"
		    " vhci_do_scsi_cmd failed\n"));
		freerbuf(bp);
		kmem_free((void *)bufp, len);
		scsi_destroy_pkt(pkt);
		return (-1);
	} else if ((pkt->pkt_reason == CMD_CMPLT) &&
	    (SCBP_C(pkt) == STATUS_CHECK) &&
	    (pkt->pkt_state & STATE_ARQ_DONE)) {
		sns = &(((struct scsi_arq_status *)(uintptr_t)
		    (pkt->pkt_scbp))->sts_sensedata);

		if ((sns->es_key == KEY_UNIT_ATTENTION) &&
		    (sns->es_add_code == STD_SCSI_ASC_STATE_CHG) &&
		    (sns->es_qual_code == STD_SCSI_ASCQ_STATE_CHG_SUCC)) {
			ss = SCSI_SENSE_STATE_CHANGED;
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "!vhci_tpgs_set_target_groups:"
			    " sense:%x, add_code: %x, qual_code:%x"
			    " sense:%x\n", sns->es_key, sns->es_add_code,
			    sns->es_qual_code, ss));
		} else if ((sns->es_key == KEY_ILLEGAL_REQUEST) &&
		    (sns->es_add_code == STD_SCSI_ASC_INVAL_PARAM_LIST)) {
			ss = SCSI_SENSE_NOFAILOVER;
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!vhci_tpgs_set_target_groups:"
			    " sense:%x, add_code: %x, qual_code:%x"
			    " sense:%x\n", sns->es_key, sns->es_add_code,
			    sns->es_qual_code, ss));
		} else if ((sns->es_key == KEY_ILLEGAL_REQUEST) &&
		    (sns->es_add_code == STD_SCSI_ASC_INVAL_CMD_OPCODE)) {
			ss = SCSI_SENSE_NOFAILOVER;
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!vhci_tpgs_set_target_groups:"
			    " sense_key:%x, add_code: %x, qual_code:%x"
			    " sense:%x\n", sns->es_key, sns->es_add_code,
			    sns->es_qual_code, rval));
		} else {
			/*
			 * At this point sns data may be for power-on-reset
			 * UNIT ATTN hardware errors, vendor unqiue sense etc.
			 * For all these cases, sense is unknown.
			 */
			ss = SCSI_SENSE_NOFAILOVER;
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!vhci_tpgs_set_target_groups: "
			    " sense UNKNOWN: sense key:%x, ASC:%x, ASCQ:%x\n",
			    sns->es_key, sns->es_add_code, sns->es_qual_code));
		}

		if (ss == SCSI_SENSE_STATE_CHANGED) {
			freerbuf(bp);
			kmem_free((void *)bufp, len);
			scsi_destroy_pkt(pkt);
			return (0);
		}
	}

	freerbuf(bp);
	kmem_free((void *)bufp, len);
	scsi_destroy_pkt(pkt);
	return (1);
}

/*
 * get the failover mode, ownership and if it has extended failover
 * capability. The mode(bits5-4/byte5) is defined as implicit, explicit, or
 * both.  The state is defined as online-optimized(0h),
 * online-nonoptimized(1h), standby(2h), offline(3h),
 * and transitioning(fh). Currently, there is online,
 * standby, and offline(defined in sunmdi.h).
 * Online-nonoptimized will be a mode of secondary
 * and an ownership of online. Thought about using a different mode but
 * it appears the states are really for the states for secondary mode.
 * We currently have IS_ONLINING, IS_OFFLINING - should we have TRANSITIONING
 * to mean from online-optimized to online-nonoptimized or does onlining
 * cover this?
 */
/* ARGSUSED */
int
vhci_tpgs_get_target_fo_mode(struct scsi_device *sd, int *mode,
    int *state, int *xlf_capable, int *preferred)
{
	int			retval = 0;
	struct buf		*bp;
	struct scsi_address	*ap;
	int			lu = 0, rel_tgt_port = 0, tgt_port = 0x0;

	VHCI_DEBUG(6, (CE_NOTE, NULL,
	    "!vhci_tpgs_get_target_fo_mode: enter\n"));
	*mode = *state = *xlf_capable = 0;
	bp = getrbuf(KM_NOSLEEP);
	if (bp == NULL) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_tpgs_get_target_fo_mode: "
		    " failed getrbuf\n"));
		return (1);
	}

	ap = &sd->sd_address;
	if (vhci_tpgs_inquiry(ap, bp, mode)) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_tpgs_get_target_fo_mode: "
		    " failed vhci_tpgs_inquiry\n"));
		retval = 1;
	} else if (vhci_tpgs_page83(ap, bp, &rel_tgt_port, &tgt_port, &lu)) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_tpgs_get_target_fo_mode: "
		    " failed vhci_tpgs_page83\n"));
		retval = 1;
	} else if (vhci_tpgs_report_target_groups(ap, bp, rel_tgt_port,
	    tgt_port, state, preferred)) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_tpgs_get_target_fo_mode: "
		    " failed vhci_tpgs_report_target_groups\n"));
		retval = 1;
	}

	freerbuf(bp);
	if (retval == 0) {
		VHCI_DEBUG(6, (CE_NOTE, NULL, "!vhci_tpgs_get_target_fo_mode: "
		    "SUCCESS\n"));
	}
	return (retval);
}

static int
vhci_tpgs_inquiry(struct scsi_address *ap, struct buf *bp, int *mode)
{
	struct scsi_pkt		*pkt;
	struct scsi_inquiry	inq;
	int			retval;

	*mode = 0;
	bp->b_un.b_addr = (caddr_t)&inq;
	bp->b_flags = B_READ;
	bp->b_bcount = sizeof (inq);
	bp->b_resid = 0;

	pkt = scsi_init_pkt(ap, NULL, bp, CDB_GROUP0,
	    sizeof (struct scsi_arq_status), 0, 0, SLEEP_FUNC, NULL);
	pkt->pkt_cdbp[0] = SCMD_INQUIRY;
	pkt->pkt_cdbp[4] = sizeof (inq);
	pkt->pkt_time = 60;

	retval = vhci_do_scsi_cmd(pkt);
	scsi_destroy_pkt(pkt);
	if (retval == 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_tpgs_inquiry: Failure"
		    " returned from vhci_do_scsi_cmd"));
		return (1);
	}

	if (inq.inq_tpgs == 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL,
		    "!vhci_tpgs_inquiry: zero tpgs_bits"));
		return (1);
	}
	retval = 0;
	if (inq.inq_tpgs == SCSI_IMPLICIT_FAILOVER) {
		*mode = SCSI_IMPLICIT_FAILOVER;
	} else if (inq.inq_tpgs == SCSI_EXPLICIT_FAILOVER) {
		*mode = SCSI_EXPLICIT_FAILOVER;
	} else if (inq.inq_tpgs == SCSI_BOTH_FAILOVER) {
		*mode = SCSI_BOTH_FAILOVER;
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL,
		    "!vhci_tpgs_inquiry: Illegal mode returned: %x mode: %x",
		    inq.inq_tpgs, *mode));
		retval = 1;
	}

	return (retval);
}

static int
vhci_tpgs_page83(struct scsi_address *ap, struct buf *bp,
	int *rel_tgt_port, int *tgt_port, int *lu)
{
	char			*ptr, *end;
	struct scsi_pkt		*pkt;
	char			*bufp;
	unsigned int		buf_len, rx_bsize;

	/*
	 * lets start the buf size with 512 bytes. If this
	 * if found to be insufficient, we can allocate
	 * appropriate size in the next iteration.
	 */
	buf_len = 512;

once_again:
	bufp = kmem_zalloc(buf_len, KM_NOSLEEP);
	if (bufp == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_tpgs_page83: "
		    "request packet allocation for %d failed....",
		    buf_len));
		return (1);
	}


	bp->b_un.b_addr = bufp;
	bp->b_flags = B_READ;
	bp->b_bcount = buf_len;
	bp->b_resid = 0;

	pkt = scsi_init_pkt(ap, NULL, bp, CDB_GROUP0,
	    sizeof (struct scsi_arq_status), 0, 0, NULL, NULL);
	if (pkt == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL,
		    "!vhci_tpgs_page83: Failure returned from scsi_init_pkt"));
		kmem_free((void *)bufp, buf_len);
		return (1);
	}

	pkt->pkt_cdbp[0] = SCMD_INQUIRY;
	pkt->pkt_cdbp[1] = 0x1;
	pkt->pkt_cdbp[2] = 0x83;
	pkt->pkt_cdbp[3] = (unsigned char)((buf_len >> 8) & 0xff);
	pkt->pkt_cdbp[4] = (unsigned char)(buf_len & 0xff);
	pkt->pkt_time = 90;

	if (vhci_do_scsi_cmd(pkt) == 0) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!vhci_tpgs_page83: vhci_do_scsi_cmd failed\n"));
		kmem_free((void *)bufp, buf_len);
		scsi_destroy_pkt(pkt);
		return (1);
	}

	/*
	 * Now lets check if the size that was provided was
	 * sufficient. If not, allocate the appropriate size
	 * and retry the command again.
	 */
	rx_bsize = (((bufp[2] & 0xff) << 8) | (bufp[3] & 0xff));
	rx_bsize += 4;
	if (rx_bsize > buf_len) {
		/*
		 * Need to allocate more buf and retry again
		 */
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_tpgs_page83: "
		    "bufsize: %d greater than allocated buf: %d\n",
		    rx_bsize, buf_len));
		VHCI_DEBUG(1, (CE_NOTE, NULL, "Retrying for size %d\n",
		    rx_bsize));
		kmem_free((void *)bufp, buf_len);
		buf_len = (unsigned int)(rx_bsize);
		goto once_again;
	}

	ptr = bufp;
	ptr += 4; /* identification descriptor 0 */
	end = bufp + rx_bsize;
	while (ptr < end) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "vhci_tpgs_page83: "
		    "desc[1/4/5/6/7]:%x %x %x %x %x\n",
		    ptr[1], ptr[4], ptr[5], ptr[6], ptr[7]));
		if ((ptr[1] & 0x0f) == 0x04) {
			*rel_tgt_port = 0;
			*rel_tgt_port |= ((ptr[6] & 0xff) << 8);
			*rel_tgt_port |= (ptr[7] & 0xff);
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!vhci_tpgs_page83: relative target port: %x\n",
			    *rel_tgt_port));
		} else if ((ptr[1] & 0x0f) == 0x05) {
			*tgt_port = 0;
			*tgt_port = ((ptr[6] & 0xff) << 8);
			*tgt_port |= (ptr[7] & 0xff);
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!vhci_tpgs_page83: target port: %x\n", *tgt_port));
		} else if ((ptr[1] & 0x0f) == 0x06) {
			*lu = 0;
			*lu |= ((ptr[6] & 0xff)<< 8);
			*lu |= (ptr[7] & 0xff);
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!vhci_tpgs_page83: logical unit: %x\n", *lu));
		}
		ptr += ptr[3] + 4;  /* next identification descriptor */
	}
	kmem_free((void *)bufp, buf_len);
	scsi_destroy_pkt(pkt);
	return (0);
}

#ifdef DEBUG
static void
print_buf(char *buf, int buf_size)
{
	int		i = 0, j;
	int		loop, left;

	loop = buf_size / 8;
	left = buf_size % 8;

	VHCI_DEBUG(4, (CE_NOTE, NULL, "!buf_size: %x loop: %x left: %x",
	    buf_size, loop, left));

	for (j = 0; j < loop; j++) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "!buf[%d-%d]: %x %x %x %x %x %x %x %x",
		    i, i + 7, buf[i], buf[i+1], buf[i+2], buf[i+3],
		    buf[i+4], buf[i+5], buf[i+6], buf[i+7]));
		i += 8;
	}

	if (left) {
		VHCI_DEBUG(4, (CE_CONT, NULL,
		    "NOTICE: buf[%d-%d]:", i, i + left));
		for (j = 0; j < left; j++) {
			VHCI_DEBUG(4, (CE_CONT, NULL, " %x", buf[i + j]));
		}
		VHCI_DEBUG(4, (CE_CONT, NULL, "\n"));
	}
}
#endif

static int
vhci_tpgs_report_target_groups(struct scsi_address *ap, struct buf *bp,
	int rel_tgt_port, int tgt_port, int *pstate, int *preferred)
{
	struct scsi_pkt		*pkt;
	char			*ptr, *end, *bufp, *mpapi_ptr;
	unsigned int		rtpg_len = 0;
	unsigned int		l_tgt_port = 0, tpgs_state = 0;
	unsigned int		tgt_port_cnt = 0, lr_tgt_port = 0;
	int			i, len;

	/*
	 * Start with buffer size of 512.
	 * If this is found to be insufficient, required size
	 * will be allocated and the command will be retried.
	 */
	len = 512;

try_again:
	bufp = kmem_zalloc(len, KM_NOSLEEP);
	if (bufp == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_tpgs_report_target_groups:"
		    " request packet allocation for %d failed....", len));
		return (1);
	}

	bp->b_un.b_addr = bufp;
	bp->b_flags = B_READ;
	bp->b_bcount = len;
	bp->b_resid = 0;

	pkt = scsi_init_pkt(ap, NULL, bp, CDB_GROUP5,
	    sizeof (struct scsi_arq_status), 0, 0, NULL, NULL);

	if (pkt == NULL) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!vhci_tpgs_report_target_groups: scsi_init_pkt error\n"));
		kmem_free((void *)bufp, len);
		return (1);
	}

	pkt->pkt_cdbp[0] = SCMD_MAINTENANCE_IN;
	pkt->pkt_cdbp[1] = SSVC_ACTION_GET_TARGET_PORT_GROUPS;
	pkt->pkt_cdbp[6] = ((len >>  24) & 0xff);
	pkt->pkt_cdbp[7] = ((len >> 16) & 0xff);
	pkt->pkt_cdbp[8] = ((len >> 8) & 0xff);
	pkt->pkt_cdbp[9] = len & 0xff;
	pkt->pkt_time = 90;

	VHCI_DEBUG(6, (CE_NOTE, NULL,
	    "!vhci_tpgs_report_target_groups: sending target port group:"
	    " cdb[6/7/8/9]: %x/%x/%x/%x\n", pkt->pkt_cdbp[6],
	    pkt->pkt_cdbp[7], pkt->pkt_cdbp[8], pkt->pkt_cdbp[9]));
	if (vhci_do_scsi_cmd(pkt) == 0) {
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!vhci_tpgs_report_target_groups:"
		    " vhci_do_scsi_cmd failed\n"));
		kmem_free((void *)bufp, len);
		scsi_destroy_pkt(pkt);
		return (1);
	}
	ptr = bufp;
	VHCI_DEBUG(6, (CE_NOTE, NULL, "!vhci_tpgs_report_target_groups:"
	    " returned from target"
	    " port group: buf[0/1/2/3]: %x/%x/%x/%x\n",
	    ptr[0], ptr[1], ptr[2], ptr[3]));
	rtpg_len = (unsigned int)((0xff & ptr[0]) << 24);
	rtpg_len |= (unsigned int)((0xff & ptr[1]) << 16);
	rtpg_len |= (unsigned int)((0xff & ptr[2]) << 8);
	rtpg_len |= (unsigned int)(0xff & ptr[3]);
	rtpg_len += 4;
	if (rtpg_len > len) {
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!vhci_tpgs_report_target_groups:"
		    " bufsize: %d greater than allocated buf: %d\n",
		    rtpg_len, len));
		VHCI_DEBUG(4, (CE_NOTE, NULL, "Retrying for size %d\n",
		    rtpg_len));
		kmem_free((void *)bufp, len);
		len = (unsigned int)(rtpg_len + 1);
		goto try_again;
	}
#ifdef DEBUG
	print_buf(bufp, rtpg_len);
#endif
	end = ptr + rtpg_len;
	ptr += 4;
	while (ptr < end) {
		mpapi_ptr = ptr;
		l_tgt_port = ((ptr[2] & 0xff) << 8) + (ptr[3] & 0xff);
		tpgs_state = ptr[0] & 0x0f;
		tgt_port_cnt = (ptr[7] & 0xff);
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!vhci_tpgs_report_tgt_groups:"
		    " tpgs state: %x"
		    " tgt_group: %x count: %x\n", tpgs_state,
		    l_tgt_port, tgt_port_cnt));
		ptr += 8;
		for (i = 0; i < tgt_port_cnt; i++) {
			lr_tgt_port = 0;
			lr_tgt_port |= ((ptr[2] & 0Xff) << 8);
			lr_tgt_port |= (ptr[3] & 0xff);

			if ((lr_tgt_port == rel_tgt_port) &&
			    (l_tgt_port == tgt_port)) {
				VHCI_DEBUG(4, (CE_NOTE, NULL,
				    "!vhci_tpgs_report_tgt_groups:"
				    " found tgt_port: %x rel_tgt_port:%x"
				    " tpgs_state: %x\n", tgt_port, rel_tgt_port,
				    tpgs_state));
				/*
				 * once we have the preferred flag
				 * and a non-optimized state flag
				 * we will get preferred flag  from the
				 * report target groups
				 */
				if (tpgs_state == STD_ACTIVE_OPTIMIZED) {
					*pstate = STD_ACTIVE_OPTIMIZED;
					*preferred = PCLASS_PREFERRED;
				} else if (tpgs_state ==
				    STD_ACTIVE_NONOPTIMIZED) {
					*pstate = STD_ACTIVE_NONOPTIMIZED;
					*preferred = PCLASS_NONPREFERRED;
				} else if (tpgs_state == STD_STANDBY) {
					*pstate = STD_STANDBY;
					*preferred = PCLASS_NONPREFERRED;
				} else {
					*pstate = STD_UNAVAILABLE;
					*preferred = PCLASS_NONPREFERRED;
				}
				vhci_mpapi_update_tpg_data(ap, mpapi_ptr);
				kmem_free((void *)bufp, len);
				scsi_destroy_pkt(pkt);
				return (0);
			}
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "!vhci_tpgs_report_tgt_groups:"
			    " tgt_port: %x rel_tgt_port:%x\n", tgt_port,
			    rel_tgt_port));
			ptr += 4;
		}
	}
	*pstate = SCSI_PATH_INACTIVE;
	*preferred = PCLASS_NONPREFERRED;
	VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_tpgs_report_tgt_groups: "
	    "NO rel_TGTPRT MATCH!!! Assigning Default: state: %x "
	    "preferred: %d\n", *pstate, *preferred));
	kmem_free((void *)bufp, len);
	scsi_destroy_pkt(pkt);
	return (1);
}
