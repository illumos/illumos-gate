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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implementation of "scsi_vhci_f_tpgs" T10 standard based failover_ops.
 *
 * NOTE: for non-sequential devices only.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/adapters/scsi_vhci.h>

/* Supported device table entries.  */
char	*std_dev_table[] = { NULL };

/* Failover module plumbing. */
SCSI_FAILOVER_OP(SFO_NAME_TPGS, std, "%I%");

#define	STD_SCSI_CMD_LEN 0xff

#define	STD_FO_CMD_RETRY_DELAY	1000000 /* 1 seconds */
#define	STD_FO_RETRY_DELAY	2000000 /* 2 seconds */
/*
 * max time for failover to complete is 3 minutes.  Compute
 * number of retries accordingly, to ensure we wait for at least
 * 3 minutes
 */
#define	STD_FO_MAX_RETRIES	(3*60*1000000)/STD_FO_RETRY_DELAY

/*
 * max number of retries for std failover to complete where the ping
 * command is failing due to transport errors or commands being rejected by
 * std.
 * STD_FO_MAX_RETRIES takes into account the case where CMD_CMPLTs but
 * std takes time to complete the failover.
 */
#define	STD_FO_MAX_CMD_RETRIES	3

#define	STD_ACTIVE_OPTIMIZED    0x0
#define	STD_ACTIVE_NONOPTIMIZED 0x1
#define	STD_STANDBY		0x2
#define	STD_UNAVAILABLE		0x3
#define	STD_TRANSITIONING	0xf

#define	STD_SCSI_ASC_STATE_TRANS	0x04
#define	STD_SCSI_ASCQ_STATE_TRANS_FAIL  0x0A
#define	STD_SCSI_ASC_STATE_CHG		0x2A
#define	STD_SCSI_ASCQ_STATE_CHG_SUCC	0x06
#define	STD_SCSI_ASCQ_STATE_CHG_FAILED	0x07
#define	STD_SCSI_ASC_INVAL_PARAM_LIST	0x26
#define	STD_SCSI_ASC_INVAL_CMD_OPCODE	0x20
#define	STD_LOGICAL_UNIT_NOT_ACCESSIBLE	0x04
#define	STD_TGT_PORT_UNAVAILABLE	0x0C


/* Special exported for direct use by MP-API */
int std_set_target_groups(struct scsi_address *, int, int);

/*
 * External function definitions
 */
extern void vhci_mpapi_update_tpg_data(struct scsi_address *, char *);

static int std_get_fo_mode(struct scsi_device *,
		int *, int *, int *, int *);
static int std_report_target_groups(struct scsi_address *, struct buf *,
		int, int, int *, int *);

/* ARGSUSED */
static int
std_device_probe(struct scsi_device *sd, struct scsi_inquiry *inq,
void **ctpriv)
{
	unsigned int	tpgs_bits;
	unsigned char	*inqbuf = (unsigned char *)inq;
	unsigned char	dtype = (inq->inq_dtype & DTYPE_MASK);

	int		mode, state, xlf, preferred = 0;

	VHCI_DEBUG(6, (CE_NOTE, NULL, "std_device_probe: vidpid %s\n",
	    inq->inq_vid));

	tpgs_bits = ((inqbuf[5] & 0x30) >> 4);

	if (tpgs_bits == 0) {
		VHCI_DEBUG(4, (CE_WARN, NULL,
		    "!std_device_probe: not a standard tpgs device"));
		return (SFO_DEVICE_PROBE_PHCI);
	}

	if (dtype == DTYPE_SEQUENTIAL) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "!std_device_probe: Detected a "
		    "Standard Asymmetric device "
		    "not yet supported\n"));
		return (SFO_DEVICE_PROBE_PHCI);
	}

	if (std_get_fo_mode(sd, &mode, &state, &xlf, &preferred)) {
		VHCI_DEBUG(4, (CE_WARN, NULL, "!unable to fetch fo "
		    "mode: sd(%p)", (void *) sd));
		return (SFO_DEVICE_PROBE_PHCI);
	}

	if (tpgs_bits == SCSI_IMPLICIT_FAILOVER) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!std_device_probe: Detected a "
		    "Standard Asymmetric device "
		    "with implicit failover\n"));
		return (SFO_DEVICE_PROBE_VHCI);
	}
	if (tpgs_bits == SCSI_EXPLICIT_FAILOVER) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!std_device_probe: Detected a "
		    "Standard Asymmetric device "
		    "with explicit failover\n"));
		return (SFO_DEVICE_PROBE_VHCI);
	}
	if (tpgs_bits == SCSI_BOTH_FAILOVER) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!std_device_probe: Detected a "
		    "Standard Asymmetric device "
		    "which supports both implicit and explicit failover\n"));
		return (SFO_DEVICE_PROBE_VHCI);
	}
	VHCI_DEBUG(1, (CE_WARN, NULL,
	    "!std_device_probe: "
	    "Unknown tpgs_bits: %x", tpgs_bits));
	return (SFO_DEVICE_PROBE_PHCI);
}

/* ARGSUSED */
static void
std_device_unprobe(struct scsi_device *sd, void *ctpriv)
{
	/*
	 * For future use
	 */
}

static int
std_inquiry(struct scsi_address *ap, struct buf *bp, int *mode)
{
	struct scsi_pkt		*pkt;
	char			buf[STD_SCSI_CMD_LEN];
	int			buf_size = sizeof (buf);
	unsigned int		tpgs_bits;
	int			retval;

	*mode = 0;
	bp->b_un.b_addr = (caddr_t)&buf;
	bp->b_flags = B_READ;
	bp->b_bcount = buf_size;
	bp->b_resid = 0;

	pkt = scsi_init_pkt(ap, NULL, bp, CDB_GROUP0,
	    sizeof (struct scsi_arq_status), 0, 0, SLEEP_FUNC, NULL);
	pkt->pkt_cdbp[0] = SCMD_INQUIRY;
	pkt->pkt_cdbp[4] = (unsigned char)buf_size;
	pkt->pkt_time = 60;

	retval = vhci_do_scsi_cmd(pkt);
	scsi_destroy_pkt(pkt);
	if (retval == 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL,
		    "!std_inquiry: Failure returned from vhci_do_scsi_cmd"));
		return (1);
	}

	tpgs_bits = ((buf[5] & 0x30) >> 4);
	if (tpgs_bits == 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL,
		    "!std_inquiry: zero tpgs_bits"));
		return (1);
	}
	retval = 0;
	if (tpgs_bits == SCSI_IMPLICIT_FAILOVER) {
		*mode = SCSI_IMPLICIT_FAILOVER;
	} else if (tpgs_bits == SCSI_EXPLICIT_FAILOVER) {
		*mode = SCSI_EXPLICIT_FAILOVER;
	} else if (tpgs_bits == SCSI_BOTH_FAILOVER) {
		*mode = SCSI_BOTH_FAILOVER;
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL,
		    "!std_inquiry: Illegal mode returned: %x mode: %x",
		    tpgs_bits, *mode));
		retval = 1;
	}

	return (retval);
}

static int
std_page83(struct scsi_address *ap, struct buf *bp,
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
		VHCI_DEBUG(1, (CE_WARN, NULL, "!std_page83: "
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
		    "!std_page83: Failure returned from scsi_init_pkt"));
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
		    "!std_page83: vhci_do_scsi_cmd failed\n"));
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
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_page83: "
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
		VHCI_DEBUG(1, (CE_NOTE, NULL, "std_page83: desc[1/4/5/6/7]:"
		    "%x %x %x %x %x\n",
		    ptr[1], ptr[4], ptr[5], ptr[6], ptr[7]));
		if ((ptr[1] & 0x0f) == 0x04) {
			*rel_tgt_port = 0;
			*rel_tgt_port |= ((ptr[6] & 0xff) << 8);
			*rel_tgt_port |= (ptr[7] & 0xff);
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!std_page83: relative target port: %x\n",
			    *rel_tgt_port));
		} else if ((ptr[1] & 0x0f) == 0x05) {
			*tgt_port = 0;
			*tgt_port = ((ptr[6] & 0xff) << 8);
			*tgt_port |= (ptr[7] & 0xff);
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!std_page83: target port: %x\n", *tgt_port));
		} else if ((ptr[1] & 0x0f) == 0x06) {
			*lu = 0;
			*lu |= ((ptr[6] & 0xff)<< 8);
			*lu |= (ptr[7] & 0xff);
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!std_page83: logical unit: %x\n", *lu));
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
std_report_target_groups(struct scsi_address *ap, struct buf *bp,
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
		VHCI_DEBUG(1, (CE_WARN, NULL, "!std_report_target_groups: "
		    "request packet allocation for %d failed....",
		    len));
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
		    "!std_report_target_groups: scsi_init_pkt error\n"));
		kmem_free((void *)bufp, len);
		return (1);
	}

	pkt->pkt_cdbp[0] = SCMD_MAINTENANCE_IN;
	pkt->pkt_cdbp[1] = SCMD_SET_TARGET_PORT_GROUPS;
	pkt->pkt_cdbp[6] = ((len >>  24) & 0xff);
	pkt->pkt_cdbp[7] = ((len >> 16) & 0xff);
	pkt->pkt_cdbp[8] = ((len >> 8) & 0xff);
	pkt->pkt_cdbp[9] = len & 0xff;
	pkt->pkt_time = 90;

	VHCI_DEBUG(6, (CE_NOTE, NULL,
	    "!std_report_target_groups: sending target port group:"
	    " cdb[6/7/8/9]: %x/%x/%x/%x\n", pkt->pkt_cdbp[6],
	    pkt->pkt_cdbp[7], pkt->pkt_cdbp[8], pkt->pkt_cdbp[9]));
	if (vhci_do_scsi_cmd(pkt) == 0) {
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!std_report_target_groups:"
		    " vhci_do_scsi_cmd failed\n"));
		kmem_free((void *)bufp, len);
		scsi_destroy_pkt(pkt);
		return (1);
	}
	ptr = bufp;
	VHCI_DEBUG(6, (CE_NOTE, NULL, "!std_report_target_groups:"
	    " returned from target"
	    " port group: buf[0/1/2/3]: %x/%x/%x/%x\n",
	    ptr[0], ptr[1], ptr[2], ptr[3]));
	rtpg_len = (unsigned int)((0xff & ptr[0]) << 24);
	rtpg_len |= (unsigned int)((0xff & ptr[1]) << 16);
	rtpg_len |= (unsigned int)((0xff & ptr[2]) << 8);
	rtpg_len |= (unsigned int)(0xff & ptr[3]);
	rtpg_len += 4;
	if (rtpg_len > len) {
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!std_report_target_groups: "
		    "bufsize: %d greater than allocated buf: %d\n",
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
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!std_report_tgt_groups:"
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
				    "!std_report_tgt_groups:"
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
			VHCI_DEBUG(4, (CE_NOTE, NULL, "!std_report_tgt_groups:"
			    " tgt_port: %x rel_tgt_port:%x\n", tgt_port,
			    rel_tgt_port));
			ptr += 4;
		}
	}
	*pstate = SCSI_PATH_INACTIVE;
	*preferred = PCLASS_NONPREFERRED;
	VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_report_tgt_groups: "
	    "NO rel_TGTPRT MATCH!!! Assigning Default: state: %x "
	    "preferred: %d\n", *pstate, *preferred));
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
static int
std_get_fo_mode(struct scsi_device *sd, int *mode,
    int *state, int *xlf_capable, int *preferred)
{
	int			retval = 0;
	struct buf		*bp;
	struct scsi_address	*ap;
	int			lu = 0, rel_tgt_port = 0, tgt_port = 0x0;

	VHCI_DEBUG(6, (CE_NOTE, NULL, "!std_get_fo_mode: enter\n"));
	*mode = *state = *xlf_capable = 0;
	bp = getrbuf(KM_NOSLEEP);
	if (bp == NULL) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_get_fo_mode: "
		    " failed getrbuf\n"));
		return (1);
	}

	ap = &sd->sd_address;
	if (std_inquiry(ap, bp, mode)) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_get_fo_mode: "
		    " failed std_inquiry\n"));
		retval = 1;
	} else if (std_page83(ap, bp, &rel_tgt_port, &tgt_port, &lu)) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_get_fo_mode: "
		    " failed std_page83\n"));
		retval = 1;
	} else if (std_report_target_groups(ap, bp, rel_tgt_port, tgt_port,
	    state, preferred)) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_get_fo_mode: "
		    " failed std_report_target_groups\n"));
		retval = 1;
	}

	freerbuf(bp);
	if (retval == 0) {
		VHCI_DEBUG(6, (CE_NOTE, NULL, "!std_get_fo_mode: "
		    "SUCCESS\n"));
	}
	return (retval);
}

/* ARGSUSED */
static int
std_activate_explicit(struct scsi_device *sd, int xlf_capable)
{
	cmn_err(CE_NOTE, "Explicit Activation is done by "
	    "std_set_target_groups() call from MPAPI");
	return (1);
}

/*
 * Process the packet reason of CMD_PKT_CMPLT - return 0 if no
 * retry and 1 if a retry should be done
 */
static int
std_process_cmplt_pkt(struct scsi_device *sd, struct scsi_pkt *pkt,
	int *retry_cnt)
{
	struct scsi_extended_sense	*sns;

	/*
	 * Re-initialize retry_cmd_cnt. Allow transport and
	 * cmd errors to go through a full retry count when
	 * these are encountered.  This way TRAN/CMD errors
	 * retry count is not exhausted due to CMD_CMPLTs
	 * delay. This allows the system
	 * to brave a hick-up on the link at any given time,
	 * while waiting for the fo to complete.
	 */
	if (pkt->pkt_state & STATE_ARQ_DONE) {
		sns = &(((struct scsi_arq_status *)(uintptr_t)
		    (pkt->pkt_scbp))->sts_sensedata);
		if (sns->es_key == KEY_UNIT_ATTENTION) {
			/*
			 * tpgs access state changed
			 */
			if (sns->es_add_code == STD_SCSI_ASC_STATE_CHG &&
			    sns->es_qual_code == STD_SCSI_ASCQ_STATE_CHG_SUCC) {
				/* XXX: update path info? */
				cmn_err(CE_WARN, "!Device failover"
				    " state change");
			}
			return (1);
		} else if (sns->es_key == KEY_NOT_READY) {
			if ((*retry_cnt)++ >=
			    STD_FO_MAX_RETRIES) {
				cmn_err(CE_WARN, "!Device failover"
				    " failed: timed out waiting "
				    "for path to become active");
				return (0);
			}
			VHCI_DEBUG(6, (CE_NOTE, NULL,
			    "!(sd:%p)lun "
			    "becoming active...\n", (void *)sd));
			drv_usecwait(STD_FO_RETRY_DELAY);
			return (1);
		}
		cmn_err(CE_NOTE, "!Failover failed;"
		    " sense key:%x, ASC: %x, "
		    "ASCQ:%x", sns->es_key,
		    sns->es_add_code, sns->es_qual_code);
		return (0);
	}
	switch (SCBP_C(pkt)) {
		case STATUS_GOOD:
			break;
		case STATUS_CHECK:
			VHCI_DEBUG(4, (CE_WARN, NULL,
			    "!(sd:%p):"
			    " status returned CHECK during std"
			    " path activation", (void *)sd));
			return (0);
		case STATUS_QFULL:
			VHCI_DEBUG(6, (CE_NOTE, NULL, "QFULL "
			    "status returned QFULL during std "
			    "path activation for %p\n", (void *)sd));
			drv_usecwait(5000);
			return (1);
		case STATUS_BUSY:
			VHCI_DEBUG(6, (CE_NOTE, NULL, "BUSY "
			    "status returned BUSY during std "
			    "path activation for %p\n", (void *)sd));
			drv_usecwait(5000);
			return (1);
		default:
			VHCI_DEBUG(4, (CE_WARN, NULL,
			    "!(sd:%p) Bad status returned during std "
			    "activation (pkt %p, status %x)",
			    (void *)sd, (void *)pkt, SCBP_C(pkt)));
			return (0);
	}
	return (0);
}

/*
 * For now we are going to use primary/online and secondary/online.
 * There is no standby path returned by the dsp and we may have
 * to do something different for other devices that use standby
 */
/* ARGSUSED */
static int
std_path_activate(struct scsi_device *sd, char *pathclass,
void *ctpriv)
{
	struct buf			*bp;
	struct scsi_pkt			*pkt;
	struct scsi_address		*ap;
	int				err, retry_cnt, retry_cmd_cnt;
	int				mode, state, retval, xlf, preferred;

	ap = &sd->sd_address;

	mode = state = 0;

	if (std_get_fo_mode(sd, &mode, &state, &xlf, &preferred)) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_path_activate:"
		    " failed std_get_fo_mode\n"));
		return (1);
	}
	if ((state == STD_ACTIVE_OPTIMIZED) ||
	    (state == STD_ACTIVE_NONOPTIMIZED)) {
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!path already active for %p\n",
		    (void *)sd));
		return (0);
	}

	if (mode != SCSI_IMPLICIT_FAILOVER) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "!mode is EXPLICIT for %p xlf %x\n",
		    (void *)sd, xlf));
		retval = std_activate_explicit(sd, xlf);
		if (retval != 0) {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "!(sd:%p)std_path_activate failed(1)\n",
			    (void *)sd));
			return (1);
		}
	} else {
		VHCI_DEBUG(4, (CE_NOTE, NULL, "STD mode is IMPLICIT for %p\n",
		    (void *)sd));
	}

	bp = scsi_alloc_consistent_buf(ap, (struct buf *)NULL, DEV_BSIZE,
	    B_READ, NULL, NULL);
	if (!bp) {
		VHCI_DEBUG(4, (CE_WARN, NULL,
		    "!(sd:%p)std_path_activate failed to alloc buffer",
		    (void *)sd));
		return (1);
	}

	pkt = scsi_init_pkt(ap, NULL, bp, CDB_GROUP1,
	    sizeof (struct scsi_arq_status), 0, PKT_CONSISTENT, NULL, NULL);
	if (!pkt) {
		VHCI_DEBUG(4, (CE_WARN, NULL,
		    "!(sd:%p)std_path_activate failed to initialize packet",
		    (void *)sd));
		scsi_free_consistent_buf(bp);
		return (1);
	}

	(void) scsi_setup_cdb((union scsi_cdb *)(uintptr_t)pkt->pkt_cdbp,
	    SCMD_READ, 1, 1, 0);
	pkt->pkt_time = 3*30;
	pkt->pkt_flags |= FLAG_NOINTR;

	retry_cnt = 0;
	retry_cmd_cnt = 0;
retry:
	err = scsi_transport(pkt);
	if (err != TRAN_ACCEPT) {
		/*
		 * Retry TRAN_BUSY till STD_FO_MAX_RETRIES is exhausted.
		 * All other errors are fatal and should not be retried.
		 */
		if ((err == TRAN_BUSY) &&
		    (retry_cnt++ < STD_FO_MAX_RETRIES)) {
			drv_usecwait(STD_FO_RETRY_DELAY);
			goto retry;
		}
		cmn_err(CE_WARN, "Failover failed, "
		    "couldn't transport packet");
		scsi_destroy_pkt(pkt);
		scsi_free_consistent_buf(bp);
		return (1);
	}
	switch (pkt->pkt_reason) {
		case CMD_CMPLT:
			retry_cmd_cnt = 0;
			retval = std_process_cmplt_pkt(sd, pkt, &retry_cnt);
			if (retval != 0) {
				goto retry;
			}
			break;
		case CMD_TIMEOUT:
			cmn_err(CE_WARN, "!Failover failed: timed out ");
			retval = 1;
			break;
		case CMD_INCOMPLETE:
		case CMD_RESET:
		case CMD_ABORTED:
		case CMD_TRAN_ERR:
			/*
			 * Increased the number of retries when these error
			 * cases are encountered.  Also added a 1 sec wait
			 * before retrying.
			 */
			if (retry_cmd_cnt++ < STD_FO_MAX_CMD_RETRIES) {
				drv_usecwait(STD_FO_CMD_RETRY_DELAY);
				VHCI_DEBUG(4, (CE_WARN, NULL,
				    "!Retrying path activation due to "
				    "pkt reason:%x, retry cnt:%d",
				    pkt->pkt_reason, retry_cmd_cnt));
				goto retry;
			}
			/* FALLTHROUGH */
		default:
			cmn_err(CE_WARN, "!Path activation did not "
			    "complete successfully,"
			    "(pkt reason %x)", pkt->pkt_reason);
			retval = 1;
			break;
	}


	VHCI_DEBUG(4, (CE_NOTE, NULL, "!Path activation success\n"));
	scsi_destroy_pkt(pkt);
	scsi_free_consistent_buf(bp);
	return (retval);
}

/* ARGSUSED */
static int std_path_deactivate(struct scsi_device *sd, char *pathclass,
void *ctpriv)
{
	return (0);
}

/* ARGSUSED */
static int
std_path_get_opinfo(struct scsi_device *sd, struct scsi_path_opinfo
*opinfo, void *ctpriv)
{
	int			mode, preferred, state, xlf;

	opinfo->opinfo_rev = OPINFO_REV;

	if (std_get_fo_mode(sd, &mode, &state, &xlf, &preferred)) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_path_getopinfo:"
		    " failed std_get_fo_mode\n"));
		return (1);
	}

	if (state == STD_ACTIVE_OPTIMIZED) {
		opinfo->opinfo_path_state = SCSI_PATH_ACTIVE;
	} else if (state == STD_ACTIVE_NONOPTIMIZED) {
		opinfo->opinfo_path_state = SCSI_PATH_ACTIVE_NONOPT;
	} else if (state == STD_STANDBY) {
		opinfo->opinfo_path_state = SCSI_PATH_INACTIVE;
	} else if (state == STD_UNAVAILABLE) {
		opinfo->opinfo_path_state = SCSI_PATH_INACTIVE;
	}
	if (preferred) {
		(void) strcpy(opinfo->opinfo_path_attr, PCLASS_PRIMARY);
	} else {
		(void) strcpy(opinfo->opinfo_path_attr, PCLASS_SECONDARY);
	}
	VHCI_DEBUG(4, (CE_NOTE, NULL, "std_path_get_opinfo: "
	    "class: %s state: %s\n", opinfo->opinfo_path_attr,
	    opinfo->opinfo_path_state == SCSI_PATH_ACTIVE ?
	    "ACTIVE" : "INACTIVE"));
	opinfo->opinfo_xlf_capable = 0;
	opinfo->opinfo_pswtch_best = 30;
	opinfo->opinfo_pswtch_worst = 3*30;
	opinfo->opinfo_preferred = (uint16_t)preferred;
	opinfo->opinfo_mode = (uint16_t)mode;

	return (0);
}

/* ARGSUSED */
static int std_path_ping(struct scsi_device *sd, void *ctpriv)
{
	/*
	 * For future use
	 */
	return (1);
}

/*
 * Analyze the sense code to determine whether failover process
 */
/* ARGSUSED */
static int
std_analyze_sense(struct scsi_device *sd, struct scsi_extended_sense
*sense, void *ctpriv)
{
	int rval = SCSI_SENSE_UNKNOWN;

	if ((sense->es_key == KEY_UNIT_ATTENTION) &&
	    (sense->es_add_code == STD_SCSI_ASC_STATE_CHG) &&
	    (sense->es_qual_code == STD_SCSI_ASCQ_STATE_CHG_SUCC)) {
		rval = SCSI_SENSE_STATE_CHANGED;
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!std_analyze_sense:"
		    " sense_key:%x, add_code: %x, qual_code:%x"
		    " sense:%x\n", sense->es_key, sense->es_add_code,
		    sense->es_qual_code, rval));
	} else if ((sense->es_key == KEY_NOT_READY) &&
	    (sense->es_add_code == STD_LOGICAL_UNIT_NOT_ACCESSIBLE) &&
	    (sense->es_qual_code == STD_TGT_PORT_UNAVAILABLE)) {
		rval = SCSI_SENSE_INACTIVE;
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!std_analyze_sense:"
		    " sense_key:%x, add_code: %x, qual_code:%x"
		    " sense:%x\n", sense->es_key, sense->es_add_code,
		    sense->es_qual_code, rval));
	} else if ((sense->es_key == KEY_ILLEGAL_REQUEST) &&
	    (sense->es_add_code == STD_SCSI_ASC_INVAL_PARAM_LIST)) {
		rval = SCSI_SENSE_NOFAILOVER;
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_analyze_sense:"
		    " sense_key:%x, add_code: %x, qual_code:%x"
		    " sense:%x\n", sense->es_key, sense->es_add_code,
		    sense->es_qual_code, rval));
	} else if ((sense->es_key == KEY_ILLEGAL_REQUEST) &&
	    (sense->es_add_code == STD_SCSI_ASC_INVAL_CMD_OPCODE)) {
		rval = SCSI_SENSE_NOFAILOVER;
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_analyze_sense:"
		    " sense_key:%x, add_code: %x, qual_code:%x"
		    " sense:%x\n", sense->es_key, sense->es_add_code,
		    sense->es_qual_code, rval));
	} else {
		/*
		 * At this point sense data may be for power-on-reset
		 * UNIT ATTN hardware errors, vendor unqiue sense data etc.
		 * For all these cases, return SCSI_SENSE_UNKNOWN.
		 */
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!Analyze sense UNKNOWN:"
		    " sense key:%x, ASC:%x, ASCQ:%x\n", sense->es_key,
		    sense->es_add_code, sense->es_qual_code));
	}

	return (rval);
}

/* ARGSUSED */
static int
std_pathclass_next(char *cur, char **nxt, void *ctpriv)
{
	/*
	 * The first phase does not have a standby path so
	 * there will be no explicit failover - when standard tpgs.
	 * standard defines preferred flag then we should start
	 * using this as the selection mechanism - there can be
	 * preferred primary standby that we should fail to first and then
	 * nonpreferred secondary standby.
	 */
	if (cur == NULL) {
		*nxt = PCLASS_PRIMARY;
		return (0);
	} else if (strcmp(cur, PCLASS_PRIMARY) == 0) {
		*nxt = PCLASS_SECONDARY;
		return (0);
	} else if (strcmp(cur, PCLASS_SECONDARY) == 0) {
		return (ENOENT);
	} else {
		return (EINVAL);
	}
}

int
std_set_target_groups(struct scsi_address *ap, int set_state, int tpg_id)
{
	struct scsi_pkt			*pkt;
	struct buf			*bp;
	int				len, rval, ss = SCSI_SENSE_UNKNOWN;
	char				*bufp;
	struct scsi_extended_sense	*sns;

	len = 8;

	bp = getrbuf(KM_NOSLEEP);
	if (bp == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "!std_set_target_groups: "
		    " failed getrbuf"));
		return (1);
	}

	bufp = kmem_zalloc(len, KM_NOSLEEP);
	if (bufp == NULL) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "!std_set_target_groups: "
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
		    "!std_set_target_groups: scsi_init_pkt error\n"));
		freerbuf(bp);
		kmem_free((void *)bufp, len);
		return (1);
	}

	/*
	 * Sends 1 TPG descriptor only. Hence Parameter list length pkt_cdbp[9]
	 * is set to 8 bytes - Refer SPC3 for details.
	 */
	pkt->pkt_cdbp[0] = SCMD_MAINTENANCE_OUT;
	pkt->pkt_cdbp[1] = SCMD_SET_TARGET_PORT_GROUPS;
	pkt->pkt_cdbp[9] = 8;
	pkt->pkt_time = 90;

	VHCI_DEBUG(1, (CE_NOTE, NULL,
	    "!std_set_target_groups: sending set target port group:"
	    " cdb[0/1/6/7/8/9]: %x/%x/%x/%x/%x/%x\n", pkt->pkt_cdbp[0],
	    pkt->pkt_cdbp[1], pkt->pkt_cdbp[6], pkt->pkt_cdbp[7],
	    pkt->pkt_cdbp[8], pkt->pkt_cdbp[9]));

#ifdef DEBUG
	print_buf(bufp, len);
#endif
	rval = vhci_do_scsi_cmd(pkt);

	if (rval == 0) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_set_target_groups:"
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
			VHCI_DEBUG(4, (CE_NOTE, NULL, "!std_set_target_groups:"
			    " sense:%x, add_code: %x, qual_code:%x"
			    " sense:%x\n", sns->es_key, sns->es_add_code,
			    sns->es_qual_code, ss));
		} else if ((sns->es_key == KEY_ILLEGAL_REQUEST) &&
		    (sns->es_add_code == STD_SCSI_ASC_INVAL_PARAM_LIST)) {
			ss = SCSI_SENSE_NOFAILOVER;
			VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_set_target_groups:"
			    " sense:%x, add_code: %x, qual_code:%x"
			    " sense:%x\n", sns->es_key, sns->es_add_code,
			    sns->es_qual_code, ss));
		} else if ((sns->es_key == KEY_ILLEGAL_REQUEST) &&
		    (sns->es_add_code == STD_SCSI_ASC_INVAL_CMD_OPCODE)) {
			ss = SCSI_SENSE_NOFAILOVER;
			VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_set_target_groups:"
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
			VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_set_target_groups: "
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
