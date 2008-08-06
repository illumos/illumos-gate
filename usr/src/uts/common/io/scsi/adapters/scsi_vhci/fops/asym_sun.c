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

/*
 * Implementation of "scsi_vhci_f_asym_sun" asymmetric failover_ops.
 *
 * Note : f_asym_sun method is the same as the one originally used by SUN's
 * T3 (Purple) device.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/adapters/scsi_vhci.h>

/* Supported device table entries.  */
char	*purple_dev_table[] = {
/*	"                  111111" */
/*	"012345670123456789012345" */
/*	"|-VID--||-----PID------|" */

	"SUN     T300            ",
	"SUN     T4              ",
	NULL,
};

/* Failover module plumbing. */
SCSI_FAILOVER_OP("f_asym_sun", purple);

#define	PURPLE_FO_CMD_RETRY_DELAY	1000000 /* 1 seconds */
#define	PURPLE_FO_RETRY_DELAY		2000000 /* 2 seconds */
/*
 * max time for failover to complete is 3 minutes.  Compute
 * number of retries accordingly, to ensure we wait for at least
 * 3 minutes
 */
#define	PURPLE_FO_MAX_RETRIES	(3*60*1000000)/PURPLE_FO_RETRY_DELAY

/*
 * max number of retries for purple failover to complete where the ping
 * command is failing due to transport errors or commands being rejected by
 * purple.
 * PURPLE_FO_MAX_RETRIES takes into account the case where CMD_CMPLTs but
 * purple takes time to complete the failover.
 */
#define	PURPLE_FO_MAX_CMD_RETRIES	3

#define	T3_SCSI_ASC_FO_IN_PROGRESS	0x90
#define	T3_SCSI_ASCQ_PATH_ACT2INACT	0x00
#define	T3_SCSI_ASCQ_PATH_INACT2ACT	0x01
#define	T3_SCSI_ASC_PATH_INACTIVE	0x04
#define	T3_SCSI_ASCQ_PATH_INACTIVE	0x88

static void purple_get_fo_mode(struct scsi_device *sd,
		int *mode, int *ownership, int *xlf_capable);

/* ARGSUSED */
static int
purple_device_probe(struct scsi_device *sd, struct scsi_inquiry *stdinq,
void **ctpriv)
{
	char	**dt;
	int	xlf = 0, mode = 0, ownership = 0;

	VHCI_DEBUG(6, (CE_NOTE, NULL, "purple_device_probe: vidpid %s\n",
	    stdinq->inq_vid));

	for (dt = purple_dev_table; *dt; dt++) {
		if (strncmp(stdinq->inq_vid, *dt, strlen(*dt)))
			continue;

		/* match */
		purple_get_fo_mode(sd, &mode, &ownership, &xlf);
		if (mode == SCSI_EXPLICIT_FAILOVER)
			return (SFO_DEVICE_PROBE_VHCI);
		else
			return (SFO_DEVICE_PROBE_PHCI);
	}
	return (SFO_DEVICE_PROBE_PHCI);
}

/* ARGSUSED */
static void
purple_device_unprobe(struct scsi_device *sd, void *ctpriv)
{
	/*
	 * For future use
	 */
}

/* ARGSUSED */
static void
purple_get_fo_mode(struct scsi_device *sd, int *mode,
int *ownership, int *xlf_capable)
{
	char		inqbuf[0xff], *ptr, *end;
	int		retval = 0;
	struct buf	*bp;
	struct scsi_pkt	*pkt;
	struct scsi_address	*ap;

	*mode = *ownership = *xlf_capable = 0;
	bp = getrbuf(KM_NOSLEEP);
	if (bp == NULL)
		return;
	bp->b_un.b_addr = inqbuf;
	bp->b_flags = B_READ;
	bp->b_bcount = 0xff;
	bp->b_resid = 0;

	ap = &sd->sd_address;
	pkt = scsi_init_pkt(ap, NULL, bp, CDB_GROUP0,
	    sizeof (struct scsi_arq_status), 0, 0, NULL, NULL);
	if (pkt == NULL) {
		freerbuf(bp);
		return;
	}

	pkt->pkt_cdbp[0] = SCMD_INQUIRY;
	pkt->pkt_cdbp[1] = 0x1;
	pkt->pkt_cdbp[2] = 0x83;
	pkt->pkt_cdbp[4] = 0xff;
	pkt->pkt_time = 90;

	retval = vhci_do_scsi_cmd(pkt);
	scsi_destroy_pkt(pkt);
	freerbuf(bp);
	if (retval == 0) {
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!(sd:%p)failed to get mode"
		    " and ownership info\n", (void *)sd));
		return;
	}

	ptr = inqbuf;
	ptr += 4; /* identification descriptor 0 */
	end = inqbuf + 4 + inqbuf[3];
	while (((ptr[1] & 0x0f) != 0xf) && (ptr < end))
		ptr += ptr[3] + 4;  /* next identification descriptor */
	if (ptr >= end) {
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!(sd:%p)p_g_m_a_o:assuming"
		    " implicit mode\n", (void *)sd));
		*mode = SCSI_IMPLICIT_FAILOVER;
		*ownership = 0;
		return;
	}
	ptr += 4; /* Port Failover Identifier */
	*mode = ptr[0];
	if ((ptr[1] & 0x3) == 0x01)
		*ownership = 0;
	else if ((ptr[1] & 0x3) == 0x00)
		*ownership = 1;
	if (ptr[1] & 0x4) {
		*xlf_capable = 1;
	} else {
		*xlf_capable = 0;
	}
}

static int
purple_activate_explicit(struct scsi_device *sd, int xlf_capable)
{
	char			cdb[CDB_GROUP1];
	struct scsi_address	*ap;
	struct scsi_pkt		*pkt;
	int			retval;

	bzero(cdb, CDB_GROUP1);

	ap = &sd->sd_address;
	pkt = scsi_init_pkt(ap, NULL, NULL, CDB_GROUP1,
	    sizeof (struct scsi_arq_status), 0, 0, NULL, NULL);
	if (pkt == NULL)
		return (0);

	pkt->pkt_cdbp[0] = 0xD0;
	if (xlf_capable) {
		/*
		 * Bit 2/1: 1/0: implicitly drop any reservation
		 * Bit 0: Grab bit - 1 means an explicit failover will be
		 * triggered
		 */
		pkt->pkt_cdbp[1] = 0x05;
	} else {
		pkt->pkt_cdbp[1] = 0x01; /* no reservation check, "grab" lun */
	}

	retval = vhci_do_scsi_cmd(pkt);
	scsi_destroy_pkt(pkt);

	return (retval);
}

/* ARGSUSED */
static int
purple_path_activate(struct scsi_device *sd, char *pathclass,
void *ctpriv)
{
	struct buf		*bp;
	struct scsi_pkt		*pkt;
	struct scsi_address	*ap;
	int			err, retry_cnt, retry_cmd_cnt;
	int			mode, ownership, retval, xlf;
	struct scsi_extended_sense	*sns;

	ap = &sd->sd_address;

	mode = ownership = 0;

	purple_get_fo_mode(sd, &mode, &ownership, &xlf);
	if (ownership == 1) {
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!path already active for 0x%p\n",
		    (void *)sd));
		return (0);
	}

	if (mode != SCSI_IMPLICIT_FAILOVER) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "!mode is EXPLICIT for 0x%p xlf %x\n",
		    (void *)sd, xlf));
		retval = purple_activate_explicit(sd, xlf);
		if (retval == 0) {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "!(sd:%p)purple_path_activate failed(1)\n",
			    (void *)sd));
			return (1);
		}
	} else {
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!mode is IMPLICIT for 0x%p\n",
		    (void *)sd));
	}

	bp = scsi_alloc_consistent_buf(ap, (struct buf *)NULL, DEV_BSIZE,
	    B_READ, NULL, NULL);
	if (!bp) {
		cmn_err(CE_WARN, "!No resources (buf) to initiate T3 path "
		    "activation");
		return (1);
	}

	pkt = scsi_init_pkt(ap, NULL, bp, CDB_GROUP1,
	    sizeof (struct scsi_arq_status), 0, PKT_CONSISTENT, NULL, NULL);
	if (!pkt) {
		cmn_err(CE_WARN, "!Packet alloc failure during T3 "
		    "path activation");
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
		 * Retry TRAN_BUSY till PURPLE_FO_MAX_RETRIES is exhausted.
		 * All other errors are fatal and should not be retried.
		 */
		if ((err == TRAN_BUSY) &&
		    (retry_cnt++ < PURPLE_FO_MAX_RETRIES)) {
			drv_usecwait(PURPLE_FO_RETRY_DELAY);
			goto retry;
		}
		cmn_err(CE_WARN, "T3 failover failed, "
		    "couldn't transport packet");
		scsi_destroy_pkt(pkt);
		scsi_free_consistent_buf(bp);
		return (1);
	}

	switch (pkt->pkt_reason) {
		case CMD_TIMEOUT:
			cmn_err(CE_WARN, "!T3 failover failed: timed out ");
			scsi_destroy_pkt(pkt);
			scsi_free_consistent_buf(bp);
			return (1);
		case CMD_CMPLT:
			/*
			 * Re-initialize retry_cmd_cnt. Allow transport and
			 * cmd errors to go through a full retry count when
			 * these are encountered.  This way TRAN/CMD errors
			 * retry count is not exhausted due to CMD_CMPLTs
			 * delay for a T3 fo to finish. This allows the system
			 * to brave a hick-up on the link at any given time,
			 * while waiting for the fo to complete.
			 */
			retry_cmd_cnt = 0;
			if (pkt->pkt_state & STATE_ARQ_DONE) {
				sns = &(((struct scsi_arq_status *)(uintptr_t)
				    (pkt->pkt_scbp))->sts_sensedata);
				if (sns->es_key == KEY_UNIT_ATTENTION) {
					/*
					 * swallow unit attention
					 */
					goto retry;
				} else if ((sns->es_key == KEY_NOT_READY) &&
				    (sns->es_add_code ==
				    T3_SCSI_ASC_FO_IN_PROGRESS) &&
				    (sns->es_qual_code ==
				    T3_SCSI_ASCQ_PATH_INACT2ACT)) {
					if (retry_cnt++ >=
					    PURPLE_FO_MAX_RETRIES) {
						cmn_err(CE_WARN, "!T3 failover"
						    " failed: timed out "
						    "waiting for path to "
						    "become active");
						scsi_destroy_pkt(pkt);
						scsi_free_consistent_buf(bp);
						return (1);
					}
					VHCI_DEBUG(6, (CE_NOTE, NULL,
					    "!(sd:%p)lun becoming active...\n",
					    (void *)sd));
					drv_usecwait(PURPLE_FO_RETRY_DELAY);
					goto retry;
				}
				cmn_err(CE_NOTE, "!T3 failover failed;"
				    " sense key:%x, ASC: %x, "
				    "ASCQ:%x", sns->es_key,
				    sns->es_add_code, sns->es_qual_code);
				scsi_destroy_pkt(pkt);
				scsi_free_consistent_buf(bp);
				return (1);
			}
			switch (SCBP_C(pkt)) {
				case STATUS_GOOD:
					break;
				case STATUS_CHECK:
					VHCI_DEBUG(4, (CE_WARN, NULL,
					    "!(sd:%p)T3:"
					    " cont allegiance during purple "
					    "activation", (void *)sd));
					scsi_destroy_pkt(pkt);
					scsi_free_consistent_buf(bp);
					return (1);
				case STATUS_QFULL:
					VHCI_DEBUG(6, (CE_NOTE, NULL, "QFULL "
					    "status returned during purple "
					    "path activation for 0x%p\n",
					    (void *)sd));
					drv_usecwait(5000);
					goto retry;
				case STATUS_BUSY:
					VHCI_DEBUG(6, (CE_NOTE, NULL, "BUSY "
					    "status returned during purple "
					    "path activation for 0x%p\n",
					    (void *)sd));
					drv_usecwait(5000);
					goto retry;
				default:
					VHCI_DEBUG(4, (CE_WARN, NULL,
					    "!(sd:%p) Bad status "
					    "returned during purple "
					    "activation (pkt 0x%p, "
					    "status %x)",
					    (void *)sd, (void *)pkt,
					    SCBP_C(pkt)));
					scsi_destroy_pkt(pkt);
					scsi_free_consistent_buf(bp);
					return (1);
			}
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
			if (retry_cmd_cnt++ < PURPLE_FO_MAX_CMD_RETRIES) {
				drv_usecwait(PURPLE_FO_CMD_RETRY_DELAY);
				VHCI_DEBUG(4, (CE_WARN, NULL,
				    "!Retrying T3 path activation due to "
				    "pkt reason:%x, retry cnt:%d",
				    pkt->pkt_reason, retry_cmd_cnt));
				goto retry;
			}
			/* FALLTHROUGH */
		default:
			cmn_err(CE_WARN, "!T3 path activation did not "
			    "complete successfully,"
			    "(pkt reason %x)", pkt->pkt_reason);
			scsi_destroy_pkt(pkt);
			scsi_free_consistent_buf(bp);
			return (1);
	}

	VHCI_DEBUG(4, (CE_NOTE, NULL, "!T3 path activation success\n"));
	scsi_destroy_pkt(pkt);
	scsi_free_consistent_buf(bp);
	return (0);
}

/* ARGSUSED */
static int purple_path_deactivate(struct scsi_device *sd, char *pathclass,
void *ctpriv)
{
	return (0);
}

/* ARGSUSED */
static int
purple_path_get_opinfo(struct scsi_device *sd, struct scsi_path_opinfo
*opinfo, void *ctpriv)
{
	struct scsi_inquiry	*inq;
	struct buf		*bp;
	struct scsi_pkt		*pkt;
	struct scsi_address	*ap;
	int			retval, mode, ownership, xlf;

	ap = &sd->sd_address;

	bp = scsi_alloc_consistent_buf(ap, (struct buf *)NULL, SUN_INQSIZE,
	    B_READ, NULL, NULL);
	if (!bp)
		return (1);
	pkt = scsi_init_pkt(ap, NULL, bp, CDB_GROUP0,
	    sizeof (struct scsi_arq_status), 0, PKT_CONSISTENT, NULL, NULL);
	if (!pkt) {
		scsi_free_consistent_buf(bp);
		return (1);
	}
	(void) scsi_setup_cdb((union scsi_cdb *)(uintptr_t)pkt->pkt_cdbp,
	    SCMD_INQUIRY, 0, SUN_INQSIZE, 0);
	pkt->pkt_time = 60;

	retval = vhci_do_scsi_cmd(pkt);
	if (retval == 0) {
		scsi_destroy_pkt(pkt);
		scsi_free_consistent_buf(bp);
		return (1);
	}

	inq = (struct scsi_inquiry *)bp->b_un.b_addr;

	opinfo->opinfo_rev = OPINFO_REV;

	/*
	 * Ignore to check inquiry dual port bit.
	 * T3 can return this bit as 0 when one of its controller goes down.
	 * Instead relying on inquiry port bit only.
	 */
	if (inq->inq_port == 0) {
		(void) strcpy(opinfo->opinfo_path_attr, "primary");
	} else {
		(void) strcpy(opinfo->opinfo_path_attr, "secondary");
	}

	scsi_destroy_pkt(pkt);
	scsi_free_consistent_buf(bp);

	purple_get_fo_mode(sd, &mode, &ownership, &xlf);

	if (ownership == 1)
		opinfo->opinfo_path_state = SCSI_PATH_ACTIVE;
	else
		opinfo->opinfo_path_state = SCSI_PATH_INACTIVE;
	opinfo->opinfo_xlf_capable = xlf;
	opinfo->opinfo_pswtch_best = 30;
	opinfo->opinfo_pswtch_worst = 3*30;
	opinfo->opinfo_mode = (uint16_t)mode;
	opinfo->opinfo_preferred = 1;

	return (0);
}

/* ARGSUSED */
static int purple_path_ping(struct scsi_device *sd, void *ctpriv)
{
	/*
	 * For future use
	 */
	return (1);
}

/* ARGSUSED */
static int
purple_analyze_sense(struct scsi_device *sd, struct scsi_extended_sense
*sense, void *ctpriv)
{
	if (sense->es_key == KEY_NOT_READY) {
		if (sense->es_add_code == T3_SCSI_ASC_FO_IN_PROGRESS) {
			if (sense->es_qual_code == T3_SCSI_ASCQ_PATH_INACT2ACT)
				return (SCSI_SENSE_INACT2ACT);
			else if (sense->es_qual_code ==
			    T3_SCSI_ASCQ_PATH_ACT2INACT)
				return (SCSI_SENSE_ACT2INACT);
		} else if ((sense->es_add_code == T3_SCSI_ASC_PATH_INACTIVE) &&
		    (sense->es_qual_code == T3_SCSI_ASCQ_PATH_INACTIVE)) {
			return (SCSI_SENSE_INACTIVE);
		}
	}

	/*
	 * At this point sense data may be for power-on-reset UNIT ATTN or
	 * hardware errors, vendor unique sense data etc.  For all these cases
	 * return SCSI_SENSE_UNKNOWN.
	 */
	VHCI_DEBUG(6, (CE_NOTE, NULL, "!T3 analyze sense UNKNOWN:"
	    " sense key:%x, ASC: %x, ASCQ:%x\n", sense->es_key,
	    sense->es_add_code, sense->es_qual_code));
	return (SCSI_SENSE_UNKNOWN);
}

/* ARGSUSED */
static int
purple_pathclass_next(char *cur, char **nxt, void *ctpriv)
{
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
