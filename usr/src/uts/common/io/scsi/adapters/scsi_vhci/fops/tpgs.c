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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2024 RackTop Systems, Inc.
 */

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
#include <sys/scsi/adapters/scsi_vhci_tpgs.h>

/* Supported device table entries.  */
char	*std_dev_table[] = { NULL };

/* Failover module plumbing. */
SCSI_FAILOVER_OP(SFO_NAME_TPGS, std);

#define	STD_FO_CMD_RETRY_DELAY	1000000 /* 1 seconds */
#define	STD_FO_RETRY_DELAY	2000000 /* 2 seconds */
/*
 * max time for failover to complete is 3 minutes.  Compute
 * number of retries accordingly, to ensure we wait for at least
 * 3 minutes
 */
#define	STD_FO_MAX_RETRIES	(3*60*1000000)/STD_FO_RETRY_DELAY


/* ARGSUSED */
static int
std_device_probe(struct scsi_device *sd, struct scsi_inquiry *inq,
    void **ctpriv)
{
	int		mode, state, xlf, preferred = 0;

	VHCI_DEBUG(6, (CE_NOTE, NULL, "std_device_probe: vidpid %s\n",
	    inq->inq_vid));

	if (inq->inq_tpgs == TPGS_FAILOVER_NONE) {
		VHCI_DEBUG(4, (CE_WARN, NULL,
		    "!std_device_probe: not a standard tpgs device"));
		return (SFO_DEVICE_PROBE_PHCI);
	}

	if (inq->inq_dtype == DTYPE_SEQUENTIAL) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "!std_device_probe: Detected a "
		    "Standard Asymmetric device "
		    "not yet supported\n"));
		return (SFO_DEVICE_PROBE_PHCI);
	}

	if (vhci_tpgs_get_target_fo_mode(sd, &mode, &state, &xlf, &preferred)) {
		VHCI_DEBUG(4, (CE_WARN, NULL, "!unable to fetch fo "
		    "mode: sd(%p)", (void *) sd));
		return (SFO_DEVICE_PROBE_PHCI);
	}

	if (inq->inq_tpgs == TPGS_FAILOVER_IMPLICIT) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!std_device_probe: Detected a "
		    "Standard Asymmetric device "
		    "with implicit failover\n"));
		return (SFO_DEVICE_PROBE_VHCI);
	}
	if (inq->inq_tpgs == TPGS_FAILOVER_EXPLICIT) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!std_device_probe: Detected a "
		    "Standard Asymmetric device "
		    "with explicit failover\n"));
		return (SFO_DEVICE_PROBE_VHCI);
	}
	if (inq->inq_tpgs == TPGS_FAILOVER_BOTH) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!std_device_probe: Detected a "
		    "Standard Asymmetric device "
		    "which supports both implicit and explicit failover\n"));
		return (SFO_DEVICE_PROBE_VHCI);
	}
	VHCI_DEBUG(1, (CE_WARN, NULL,
	    "!std_device_probe: "
	    "Unknown tpgs_bits: %x", inq->inq_tpgs));
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

/* ARGSUSED */
static int
std_activate_explicit(struct scsi_device *sd, int xlf_capable)
{
	cmn_err(CE_NOTE, "Explicit Activation is done by "
	    "vhci_tpgs_set_target_groups() call from MPAPI");
	return (1);
}

/*
 * Process the packet reason of CMD_PKT_CMPLT - return 0 if no
 * retry and 1 if a retry should be done
 */
static int
std_process_cmplt_pkt(struct scsi_device *sd, struct scsi_pkt *pkt,
    int *retry_cnt, int *retval)
{
	*retval = 1; /* fail */

	switch (SCBP_C(pkt)) {
		case STATUS_GOOD:
			*retval = 0;
			break;
		case STATUS_CHECK:
			if (pkt->pkt_state & STATE_ARQ_DONE) {
				uint8_t *sns, skey, asc, ascq;
				sns = (uint8_t *)
				    &(((struct scsi_arq_status *)(uintptr_t)
				    (pkt->pkt_scbp))->sts_sensedata);
				skey = scsi_sense_key(sns);
				asc = scsi_sense_asc(sns);
				ascq = scsi_sense_ascq(sns);
				if (skey == KEY_UNIT_ATTENTION) {
					/*
					 * tpgs access state changed
					 */
					if (asc == STD_SCSI_ASC_STATE_CHG &&
					    ascq ==
					    STD_SCSI_ASCQ_STATE_CHG_SUCC) {
						/* XXX: update path info? */
						cmn_err(CE_WARN,
						    "!Device failover"
						    " state change");
					}
					return (1);
				} else if (skey == KEY_NOT_READY) {
					if (asc ==
					    STD_LOGICAL_UNIT_NOT_ACCESSIBLE &&
					    ascq == STD_TGT_PORT_STANDBY) {
						/*
						 * Don't retry on the path
						 * which is indicated as
						 * standby, return failure.
						 */
						return (0);
					} else if ((*retry_cnt)++ >=
					    STD_FO_MAX_RETRIES) {
						cmn_err(CE_WARN,
						    "!Device failover failed: "
						    "timed out waiting for "
						    "path to become active");
						return (0);
					}
					VHCI_DEBUG(6, (CE_NOTE, NULL,
					    "!(sd:%p)lun becoming active...\n",
					    (void *)sd));
					drv_usecwait(STD_FO_RETRY_DELAY);
					return (1);
				}
				cmn_err(CE_NOTE, "!Failover failed;"
				    " sense key:%x, ASC: %x, "
				    "ASCQ:%x", skey, asc, ascq);
				return (0);
			}
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
	size_t				blksize;

	ap = &sd->sd_address;

	mode = state = 0;

	blksize = vhci_get_blocksize(sd->sd_dev);

	if (vhci_tpgs_get_target_fo_mode(sd, &mode, &state, &xlf, &preferred)) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_path_activate:"
		    " failed vhci_tpgs_get_target_fo_mode\n"));
		return (1);
	}
	if ((state == STD_ACTIVE_OPTIMIZED) ||
	    (state == STD_ACTIVE_NONOPTIMIZED)) {
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!path already active for %p\n",
		    (void *)sd));
		return (0);
	}

	if (mode == SCSI_EXPLICIT_FAILOVER) {
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

	bp = scsi_alloc_consistent_buf(ap, (struct buf *)NULL, blksize, B_READ,
	    NULL, NULL);
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
	    SCMD_READ_G1, 1, 1, 0);
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
			/*
			 * Re-initialize retry_cmd_cnt. Allow transport and
			 * cmd errors to go through a full retry count when
			 * these are encountered.  This way TRAN/CMD errors
			 * retry count is not exhausted due to CMD_CMPLTs
			 * delay. This allows the system
			 * to brave a hick-up on the link at any given time,
			 * while waiting for the fo to complete.
			 */
			retry_cmd_cnt = 0;
			if (std_process_cmplt_pkt(sd, pkt, &retry_cnt,
			    &retval) != 0) {
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
std_path_get_opinfo(struct scsi_device *sd, struct scsi_path_opinfo *opinfo,
    void *ctpriv)
{
	int			mode, preferred, state, xlf;

	opinfo->opinfo_rev = OPINFO_REV;

	if (vhci_tpgs_get_target_fo_mode(sd, &mode, &state, &xlf, &preferred)) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_path_getopinfo:"
		    " failed vhci_tpgs_get_target_fo_mode\n"));
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
std_analyze_sense(struct scsi_device *sd, uint8_t *sense,
    void *ctpriv)
{
	int rval = SCSI_SENSE_UNKNOWN;

	uint8_t skey, asc, ascq;

	skey = scsi_sense_key(sense);
	asc = scsi_sense_asc(sense);
	ascq = scsi_sense_ascq(sense);

	if ((skey == KEY_UNIT_ATTENTION) &&
	    (asc == STD_SCSI_ASC_STATE_CHG) &&
	    (ascq == STD_SCSI_ASCQ_STATE_CHG_SUCC)) {
		rval = SCSI_SENSE_STATE_CHANGED;
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!std_analyze_sense:"
		    " sense_key:%x, add_code: %x, qual_code:%x"
		    " sense:%x\n", skey, asc, ascq, rval));
	} else if ((skey == KEY_NOT_READY) &&
	    (asc == STD_LOGICAL_UNIT_NOT_ACCESSIBLE) &&
	    ((ascq == STD_TGT_PORT_UNAVAILABLE) ||
	    (ascq == STD_TGT_PORT_STANDBY))) {
		rval = SCSI_SENSE_INACTIVE;
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!std_analyze_sense:"
		    " sense_key:%x, add_code: %x, qual_code:%x"
		    " sense:%x\n", skey, asc, ascq, rval));
	} else if ((skey == KEY_ILLEGAL_REQUEST) &&
	    (asc == STD_SCSI_ASC_INVAL_PARAM_LIST)) {
		rval = SCSI_SENSE_NOFAILOVER;
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_analyze_sense:"
		    " sense_key:%x, add_code: %x, qual_code:%x"
		    " sense:%x\n", skey, asc, ascq, rval));
	} else if ((skey == KEY_ILLEGAL_REQUEST) &&
	    (asc == STD_SCSI_ASC_INVAL_CMD_OPCODE)) {
		rval = SCSI_SENSE_NOFAILOVER;
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!std_analyze_sense:"
		    " sense_key:%x, add_code: %x, qual_code:%x"
		    " sense:%x\n", skey, asc, ascq, rval));
	} else {
		/*
		 * At this point sense data may be for power-on-reset
		 * UNIT ATTN hardware errors, vendor unqiue sense data etc.
		 * For all these cases, return SCSI_SENSE_UNKNOWN.
		 */
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!Analyze sense UNKNOWN:"
		    " sense key:%x, ASC:%x, ASCQ:%x\n", skey, asc, ascq));
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
