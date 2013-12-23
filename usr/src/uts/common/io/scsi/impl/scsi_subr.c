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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/scsi/scsi.h>
#include <sys/file.h>

/*
 * Utility SCSI routines
 */

/*
 * Polling support routines
 */

int		scsi_pkt_allow_naca = 0;
extern uintptr_t scsi_callback_id;

extern uchar_t scsi_cdb_size[];

/*
 * Common buffer for scsi_log
 */

extern kmutex_t scsi_log_mutex;
static char scsi_log_buffer[MAXPATHLEN + 1];


#define	A_TO_TRAN(ap)	(ap->a_hba_tran)
#define	P_TO_TRAN(pkt)	((pkt)->pkt_address.a_hba_tran)
#define	P_TO_ADDR(pkt)	(&((pkt)->pkt_address))

#define	CSEC		10000			/* usecs */
#define	SEC_TO_CSEC	(1000000/CSEC)

extern ddi_dma_attr_t scsi_alloc_attr;

/*PRINTFLIKE4*/
static void impl_scsi_log(dev_info_t *dev, char *label, uint_t level,
    const char *fmt, ...) __KPRINTFLIKE(4);
/*PRINTFLIKE4*/
static void v_scsi_log(dev_info_t *dev, char *label, uint_t level,
    const char *fmt, va_list ap) __KVPRINTFLIKE(4);

static int
scsi_get_next_descr(uint8_t *sdsp,
    int sense_buf_len, struct scsi_descr_template **descrpp);

#define	DESCR_GOOD	0
#define	DESCR_PARTIAL	1
#define	DESCR_END	2

static int
scsi_validate_descr(struct scsi_descr_sense_hdr *sdsp,
    int valid_sense_length, struct scsi_descr_template *descrp);

int
scsi_poll(struct scsi_pkt *pkt)
{
	int			rval = -1;
	int			savef;
	long			savet;
	void			(*savec)();
	int			timeout;
	int			busy_count;
	int			poll_delay;
	int			rc;
	uint8_t			*sensep;
	struct scsi_arq_status	*arqstat;
	extern int		do_polled_io;

	ASSERT(pkt->pkt_scbp);

	/*
	 * save old flags..
	 */
	savef = pkt->pkt_flags;
	savec = pkt->pkt_comp;
	savet = pkt->pkt_time;

	pkt->pkt_flags |= FLAG_NOINTR;

	/*
	 * XXX there is nothing in the SCSA spec that states that we should not
	 * do a callback for polled cmds; however, removing this will break sd
	 * and probably other target drivers
	 */
	pkt->pkt_comp = NULL;

	/*
	 * we don't like a polled command without timeout.
	 * 60 seconds seems long enough.
	 */
	if (pkt->pkt_time == 0)
		pkt->pkt_time = SCSI_POLL_TIMEOUT;

	/*
	 * Send polled cmd.
	 *
	 * We do some error recovery for various errors.  Tran_busy,
	 * queue full, and non-dispatched commands are retried every 10 msec.
	 * as they are typically transient failures.  Busy status and Not
	 * Ready are retried every second as this status takes a while to
	 * change.
	 */
	timeout = pkt->pkt_time * SEC_TO_CSEC;

	for (busy_count = 0; busy_count < timeout; busy_count++) {
		/*
		 * Initialize pkt status variables.
		 */
		*pkt->pkt_scbp = pkt->pkt_reason = pkt->pkt_state = 0;

		if ((rc = scsi_transport(pkt)) != TRAN_ACCEPT) {
			if (rc != TRAN_BUSY) {
				/* Transport failed - give up. */
				break;
			} else {
				/* Transport busy - try again. */
				poll_delay = 1 * CSEC;		/* 10 msec. */
			}
		} else {
			/*
			 * Transport accepted - check pkt status.
			 */
			rc = (*pkt->pkt_scbp) & STATUS_MASK;
			if ((pkt->pkt_reason == CMD_CMPLT) &&
			    (rc == STATUS_CHECK) &&
			    (pkt->pkt_state & STATE_ARQ_DONE)) {
				arqstat =
				    (struct scsi_arq_status *)(pkt->pkt_scbp);
				sensep = (uint8_t *)&arqstat->sts_sensedata;
			} else {
				sensep = NULL;
			}

			if ((pkt->pkt_reason == CMD_CMPLT) &&
			    (rc == STATUS_GOOD)) {
				/* No error - we're done */
				rval = 0;
				break;

			} else if (pkt->pkt_reason == CMD_DEV_GONE) {
				/* Lost connection - give up */
				break;

			} else if ((pkt->pkt_reason == CMD_INCOMPLETE) &&
			    (pkt->pkt_state == 0)) {
				/* Pkt not dispatched - try again. */
				poll_delay = 1 * CSEC;		/* 10 msec. */

			} else if ((pkt->pkt_reason == CMD_CMPLT) &&
			    (rc == STATUS_QFULL)) {
				/* Queue full - try again. */
				poll_delay = 1 * CSEC;		/* 10 msec. */

			} else if ((pkt->pkt_reason == CMD_CMPLT) &&
			    (rc == STATUS_BUSY)) {
				/* Busy - try again. */
				poll_delay = 100 * CSEC;	/* 1 sec. */
				busy_count += (SEC_TO_CSEC - 1);

			} else if ((sensep != NULL) &&
			    (scsi_sense_key(sensep) == KEY_NOT_READY) &&
			    (scsi_sense_asc(sensep) == 0x04) &&
			    (scsi_sense_ascq(sensep) == 0x01)) {
				/*
				 * Not ready -> ready - try again.
				 * 04h/01h: LUN IS IN PROCESS OF BECOMING READY
				 * ...same as STATUS_BUSY
				 */
				poll_delay = 100 * CSEC;	/* 1 sec. */
				busy_count += (SEC_TO_CSEC - 1);

			} else {
				/* BAD status - give up. */
				break;
			}
		}

		if (((curthread->t_flag & T_INTR_THREAD) == 0) &&
		    !do_polled_io) {
			delay(drv_usectohz(poll_delay));
		} else {
			/* we busy wait during cpr_dump or interrupt threads */
			drv_usecwait(poll_delay);
		}
	}

	pkt->pkt_flags = savef;
	pkt->pkt_comp = savec;
	pkt->pkt_time = savet;

	/* return on error */
	if (rval)
		return (rval);

	/*
	 * This is not a performance critical code path.
	 *
	 * As an accommodation for scsi_poll callers, to avoid ddi_dma_sync()
	 * issues associated with looking at DMA memory prior to
	 * scsi_pkt_destroy(), we scsi_sync_pkt() prior to return.
	 */
	scsi_sync_pkt(pkt);
	return (0);
}

/*
 * Command packaging routines.
 *
 * makecom_g*() are original routines and scsi_setup_cdb()
 * is the new and preferred routine.
 */

/*
 * These routines put LUN information in CDB byte 1 bits 7-5.
 * This was required in SCSI-1. SCSI-2 allowed it but it preferred
 * sending LUN information as part of IDENTIFY message.
 * This is not allowed in SCSI-3.
 */

void
makecom_g0(struct scsi_pkt *pkt, struct scsi_device *devp,
    int flag, int cmd, int addr, int cnt)
{
	MAKECOM_G0(pkt, devp, flag, cmd, addr, (uchar_t)cnt);
}

void
makecom_g0_s(struct scsi_pkt *pkt, struct scsi_device *devp,
    int flag, int cmd, int cnt, int fixbit)
{
	MAKECOM_G0_S(pkt, devp, flag, cmd, cnt, (uchar_t)fixbit);
}

void
makecom_g1(struct scsi_pkt *pkt, struct scsi_device *devp,
    int flag, int cmd, int addr, int cnt)
{
	MAKECOM_G1(pkt, devp, flag, cmd, addr, cnt);
}

void
makecom_g5(struct scsi_pkt *pkt, struct scsi_device *devp,
    int flag, int cmd, int addr, int cnt)
{
	MAKECOM_G5(pkt, devp, flag, cmd, addr, cnt);
}

/*
 * Following routine does not put LUN information in CDB.
 * This interface must be used for SCSI-2 targets having
 * more than 8 LUNs or a SCSI-3 target.
 */
int
scsi_setup_cdb(union scsi_cdb *cdbp, uchar_t cmd, uint_t addr, uint_t cnt,
    uint_t addtl_cdb_data)
{
	uint_t	addr_cnt;

	cdbp->scc_cmd = cmd;

	switch (CDB_GROUPID(cmd)) {
		case CDB_GROUPID_0:
			/*
			 * The following calculation is to take care of
			 * the fact that format of some 6 bytes tape
			 * command is different (compare 6 bytes disk and
			 * tape read commands).
			 */
			addr_cnt = (addr << 8) + cnt;
			addr = (addr_cnt & 0x1fffff00) >> 8;
			cnt = addr_cnt & 0xff;
			FORMG0ADDR(cdbp, addr);
			FORMG0COUNT(cdbp, cnt);
			break;

		case CDB_GROUPID_1:
		case CDB_GROUPID_2:
			FORMG1ADDR(cdbp, addr);
			FORMG1COUNT(cdbp, cnt);
			break;

		case CDB_GROUPID_4:
			FORMG4ADDR(cdbp, addr);
			FORMG4COUNT(cdbp, cnt);
			FORMG4ADDTL(cdbp, addtl_cdb_data);
			break;

		case CDB_GROUPID_5:
			FORMG5ADDR(cdbp, addr);
			FORMG5COUNT(cdbp, cnt);
			break;

		default:
			return (0);
	}

	return (1);
}


/*
 * Common iopbmap data area packet allocation routines
 */

struct scsi_pkt *
get_pktiopb(struct scsi_address *ap, caddr_t *datap, int cdblen, int statuslen,
    int datalen, int readflag, int (*func)())
{
	scsi_hba_tran_t	*tran = A_TO_TRAN(ap);
	dev_info_t	*pdip = tran->tran_hba_dip;
	struct scsi_pkt	*pkt = NULL;
	struct buf	local;
	size_t		rlen;

	if (!datap)
		return (pkt);
	*datap = (caddr_t)0;
	bzero((caddr_t)&local, sizeof (struct buf));

	/*
	 * use i_ddi_mem_alloc() for now until we have an interface to allocate
	 * memory for DMA which doesn't require a DMA handle. ddi_iopb_alloc()
	 * is obsolete and we want more flexibility in controlling the DMA
	 * address constraints.
	 */
	if (i_ddi_mem_alloc(pdip, &scsi_alloc_attr, datalen,
	    ((func == SLEEP_FUNC) ? 1 : 0), 0, NULL, &local.b_un.b_addr, &rlen,
	    NULL) != DDI_SUCCESS) {
		return (pkt);
	}
	if (readflag)
		local.b_flags = B_READ;
	local.b_bcount = datalen;
	pkt = (*tran->tran_init_pkt) (ap, NULL, &local,
	    cdblen, statuslen, 0, PKT_CONSISTENT,
	    (func == SLEEP_FUNC) ? SLEEP_FUNC : NULL_FUNC, NULL);
	if (!pkt) {
		i_ddi_mem_free(local.b_un.b_addr, NULL);
		if (func != NULL_FUNC) {
			ddi_set_callback(func, NULL, &scsi_callback_id);
		}
	} else {
		*datap = local.b_un.b_addr;
	}
	return (pkt);
}

/*
 *  Equivalent deallocation wrapper
 */

void
free_pktiopb(struct scsi_pkt *pkt, caddr_t datap, int datalen)
{
	register struct scsi_address	*ap = P_TO_ADDR(pkt);
	register scsi_hba_tran_t	*tran = A_TO_TRAN(ap);

	(*tran->tran_destroy_pkt)(ap, pkt);
	if (datap && datalen) {
		i_ddi_mem_free(datap, NULL);
	}
	if (scsi_callback_id != 0) {
		ddi_run_callback(&scsi_callback_id);
	}
}

/*
 * Common naming functions
 */

static char scsi_tmpname[64];

char *
scsi_dname(int dtyp)
{
	static char	*dnames[] = DTYPE_ASCII;
	char		*dname = NULL;

	if ((dtyp & DTYPE_MASK) < (sizeof (dnames) / sizeof (*dnames)))
		dname = dnames[dtyp&DTYPE_MASK];
	else if (dtyp == DTYPE_NOTPRESENT)
		dname = "Not Present";
	if ((dname == NULL) || (*dname == '\0'))
		dname = "<unknown device type>";
	return (dname);
}

char *
scsi_rname(uchar_t reason)
{
	static char	*rnames[] = CMD_REASON_ASCII;
	char		*rname = NULL;

	if (reason < (sizeof (rnames) / sizeof (*rnames)))
		rname = rnames[reason];
	if ((rname == NULL) || (*rname == '\0'))
		rname = "<unknown reason>";
	return (rname);
}

char *
scsi_mname(uchar_t msg)
{
	static char *imsgs[23] = {
		"COMMAND COMPLETE",
		"EXTENDED",
		"SAVE DATA POINTER",
		"RESTORE POINTERS",
		"DISCONNECT",
		"INITIATOR DETECTED ERROR",
		"ABORT",
		"REJECT",
		"NO-OP",
		"MESSAGE PARITY",
		"LINKED COMMAND COMPLETE",
		"LINKED COMMAND COMPLETE (W/FLAG)",
		"BUS DEVICE RESET",
		"ABORT TAG",
		"CLEAR QUEUE",
		"INITIATE RECOVERY",
		"RELEASE RECOVERY",
		"TERMINATE PROCESS",
		"CONTINUE TASK",
		"TARGET TRANSFER DISABLE",
		"RESERVED (0x14)",
		"RESERVED (0x15)",
		"CLEAR ACA"
	};
	static char *imsgs_2[6] = {
		"SIMPLE QUEUE TAG",
		"HEAD OF QUEUE TAG",
		"ORDERED QUEUE TAG",
		"IGNORE WIDE RESIDUE",
		"ACA",
		"LOGICAL UNIT RESET"
	};

	if (msg < 23) {
		return (imsgs[msg]);
	} else if (IS_IDENTIFY_MSG(msg)) {
		return ("IDENTIFY");
	} else if (IS_2BYTE_MSG(msg) &&
	    (int)((msg) & 0xF) < (sizeof (imsgs_2) / sizeof (char *))) {
		return (imsgs_2[msg & 0xF]);
	} else {
		return ("<unknown msg>");
	}

}

char *
scsi_cname(uchar_t cmd, register char **cmdvec)
{
	while (*cmdvec != (char *)0) {
		if (cmd == **cmdvec) {
			return ((char *)((long)(*cmdvec)+1));
		}
		cmdvec++;
	}
	return (sprintf(scsi_tmpname, "<undecoded cmd 0x%x>", cmd));
}

char *
scsi_cmd_name(uchar_t cmd, struct scsi_key_strings *cmdlist, char *tmpstr)
{
	int i = 0;

	while (cmdlist[i].key !=  -1) {
		if (cmd == cmdlist[i].key) {
			return ((char *)cmdlist[i].message);
		}
		i++;
	}
	return (sprintf(tmpstr, "<undecoded cmd 0x%x>", cmd));
}

static struct scsi_asq_key_strings extended_sense_list[] = {
	0x00, 0x00, "no additional sense info",
	0x00, 0x01, "filemark detected",
	0x00, 0x02, "end of partition/medium detected",
	0x00, 0x03, "setmark detected",
	0x00, 0x04, "beginning of partition/medium detected",
	0x00, 0x05, "end of data detected",
	0x00, 0x06, "i/o process terminated",
	0x00, 0x11, "audio play operation in progress",
	0x00, 0x12, "audio play operation paused",
	0x00, 0x13, "audio play operation successfully completed",
	0x00, 0x14, "audio play operation stopped due to error",
	0x00, 0x15, "no current audio status to return",
	0x00, 0x16, "operation in progress",
	0x00, 0x17, "cleaning requested",
	0x00, 0x18, "erase operation in progress",
	0x00, 0x19, "locate operation in progress",
	0x00, 0x1A, "rewind operation in progress",
	0x00, 0x1B, "set capacity operation in progress",
	0x00, 0x1C, "verify operation in progress",
	0x00, 0x1D, "ATA passthrough information available",
	0x01, 0x00, "no index/sector signal",
	0x02, 0x00, "no seek complete",
	0x03, 0x00, "peripheral device write fault",
	0x03, 0x01, "no write current",
	0x03, 0x02, "excessive write errors",
	0x04, 0x00, "LUN not ready",
	0x04, 0x01, "LUN is becoming ready",
	0x04, 0x02, "LUN initializing command required",
	0x04, 0x03, "LUN not ready intervention required",
	0x04, 0x04, "LUN not ready format in progress",
	0x04, 0x05, "LUN not ready, rebuild in progress",
	0x04, 0x06, "LUN not ready, recalculation in progress",
	0x04, 0x07, "LUN not ready, operation in progress",
	0x04, 0x08, "LUN not ready, long write in progress",
	0x04, 0x09, "LUN not ready, self-test in progress",
	0x04, 0x0A, "LUN not accessible, asymmetric access state transition",
	0x04, 0x0B, "LUN not accessible, target port in standby state",
	0x04, 0x0C, "LUN not accessible, target port in unavailable state",
	0x04, 0x10, "LUN not ready, auxiliary memory not accessible",
	0x05, 0x00, "LUN does not respond to selection",
	0x06, 0x00, "reference position found",
	0x07, 0x00, "multiple peripheral devices selected",
	0x08, 0x00, "LUN communication failure",
	0x08, 0x01, "LUN communication time-out",
	0x08, 0x02, "LUN communication parity error",
	0x08, 0x03, "LUN communication crc error (ultra-DMA/32)",
	0x08, 0x04, "unreachable copy target",
	0x09, 0x00, "track following error",
	0x09, 0x01, "tracking servo failure",
	0x09, 0x02, "focus servo failure",
	0x09, 0x03, "spindle servo failure",
	0x09, 0x04, "head select fault",
	0x0a, 0x00, "error log overflow",
	0x0b, 0x00, "warning",
	0x0b, 0x01, "warning - specified temperature exceeded",
	0x0b, 0x02, "warning - enclosure degraded",
	0x0c, 0x00, "write error",
	0x0c, 0x01, "write error - recovered with auto reallocation",
	0x0c, 0x02, "write error - auto reallocation failed",
	0x0c, 0x03, "write error - recommend reassignment",
	0x0c, 0x04, "compression check miscompare error",
	0x0c, 0x05, "data expansion occurred during compression",
	0x0c, 0x06, "block not compressible",
	0x0c, 0x07, "write error - recovery needed",
	0x0c, 0x08, "write error - recovery failed",
	0x0c, 0x09, "write error - loss of streaming",
	0x0c, 0x0a, "write error - padding blocks added",
	0x0c, 0x0b, "auxiliary memory write error",
	0x0c, 0x0c, "write error - unexpected unsolicited data",
	0x0c, 0x0d, "write error - not enough unsolicited data",
	0x0d, 0x00, "error detected by third party temporary initiator",
	0x0d, 0x01, "third party device failure",
	0x0d, 0x02, "copy target device not reachable",
	0x0d, 0x03, "incorrect copy target device type",
	0x0d, 0x04, "copy target device data underrun",
	0x0d, 0x05, "copy target device data overrun",
	0x0e, 0x00, "invalid information unit",
	0x0e, 0x01, "information unit too short",
	0x0e, 0x02, "information unit too long",
	0x10, 0x00, "ID CRC or ECC error",
	0x11, 0x00, "unrecovered read error",
	0x11, 0x01, "read retries exhausted",
	0x11, 0x02, "error too long to correct",
	0x11, 0x03, "multiple read errors",
	0x11, 0x04, "unrecovered read error - auto reallocate failed",
	0x11, 0x05, "L-EC uncorrectable error",
	0x11, 0x06, "CIRC unrecovered error",
	0x11, 0x07, "data re-synchronization error",
	0x11, 0x08, "incomplete block read",
	0x11, 0x09, "no gap found",
	0x11, 0x0a, "miscorrected error",
	0x11, 0x0b, "unrecovered read error - recommend reassignment",
	0x11, 0x0c, "unrecovered read error - recommend rewrite the data",
	0x11, 0x0d, "de-compression crc error",
	0x11, 0x0e, "cannot decompress using declared algorithm",
	0x11, 0x0f, "error reading UPC/EAN number",
	0x11, 0x10, "error reading ISRC number",
	0x11, 0x11, "read error - loss of streaming",
	0x11, 0x12, "auxiliary memory read error",
	0x11, 0x13, "read error - failed retransmission request",
	0x12, 0x00, "address mark not found for ID field",
	0x13, 0x00, "address mark not found for data field",
	0x14, 0x00, "recorded entity not found",
	0x14, 0x01, "record not found",
	0x14, 0x02, "filemark or setmark not found",
	0x14, 0x03, "end-of-data not found",
	0x14, 0x04, "block sequence error",
	0x14, 0x05, "record not found - recommend reassignment",
	0x14, 0x06, "record not found - data auto-reallocated",
	0x14, 0x07, "locate operation failure",
	0x15, 0x00, "random positioning error",
	0x15, 0x01, "mechanical positioning error",
	0x15, 0x02, "positioning error detected by read of medium",
	0x16, 0x00, "data sync mark error",
	0x16, 0x01, "data sync error - data rewritten",
	0x16, 0x02, "data sync error - recommend rewrite",
	0x16, 0x03, "data sync error - data auto-reallocated",
	0x16, 0x04, "data sync error - recommend reassignment",
	0x17, 0x00, "recovered data with no error correction",
	0x17, 0x01, "recovered data with retries",
	0x17, 0x02, "recovered data with positive head offset",
	0x17, 0x03, "recovered data with negative head offset",
	0x17, 0x04, "recovered data with retries and/or CIRC applied",
	0x17, 0x05, "recovered data using previous sector id",
	0x17, 0x06, "recovered data without ECC - data auto-reallocated",
	0x17, 0x07, "recovered data without ECC - recommend reassignment",
	0x17, 0x08, "recovered data without ECC - recommend rewrite",
	0x17, 0x09, "recovered data without ECC - data rewritten",
	0x18, 0x00, "recovered data with error correction",
	0x18, 0x01, "recovered data with error corr. & retries applied",
	0x18, 0x02, "recovered data - data auto-reallocated",
	0x18, 0x03, "recovered data with CIRC",
	0x18, 0x04, "recovered data with L-EC",
	0x18, 0x05, "recovered data - recommend reassignment",
	0x18, 0x06, "recovered data - recommend rewrite",
	0x18, 0x07, "recovered data with ECC - data rewritten",
	0x18, 0x08, "recovered data with linking",
	0x19, 0x00, "defect list error",
	0x1a, 0x00, "parameter list length error",
	0x1b, 0x00, "synchronous data xfer error",
	0x1c, 0x00, "defect list not found",
	0x1c, 0x01, "primary defect list not found",
	0x1c, 0x02, "grown defect list not found",
	0x1d, 0x00, "miscompare during verify",
	0x1e, 0x00, "recovered ID with ECC",
	0x1f, 0x00, "partial defect list transfer",
	0x20, 0x00, "invalid command operation code",
	0x20, 0x01, "access denied - initiator pending-enrolled",
	0x20, 0x02, "access denied - no access rights",
	0x20, 0x03, "access denied - invalid mgmt id key",
	0x20, 0x04, "illegal command while in write capable state",
	0x20, 0x06, "illegal command while in explicit address mode",
	0x20, 0x07, "illegal command while in implicit address mode",
	0x20, 0x08, "access denied - enrollment conflict",
	0x20, 0x09, "access denied - invalid lu identifier",
	0x20, 0x0a, "access denied - invalid proxy token",
	0x20, 0x0b, "access denied - ACL LUN conflict",
	0x21, 0x00, "logical block address out of range",
	0x21, 0x01, "invalid element address",
	0x21, 0x02, "invalid address for write",
	0x22, 0x00, "illegal function",
	0x24, 0x00, "invalid field in cdb",
	0x24, 0x01, "cdb decryption error",
	0x25, 0x00, "LUN not supported",
	0x26, 0x00, "invalid field in param list",
	0x26, 0x01, "parameter not supported",
	0x26, 0x02, "parameter value invalid",
	0x26, 0x03, "threshold parameters not supported",
	0x26, 0x04, "invalid release of persistent reservation",
	0x26, 0x05, "data decryption error",
	0x26, 0x06, "too many target descriptors",
	0x26, 0x07, "unsupported target descriptor type code",
	0x26, 0x08, "too many segment descriptors",
	0x26, 0x09, "unsupported segment descriptor type code",
	0x26, 0x0a, "unexpected inexact segment",
	0x26, 0x0b, "inline data length exceeded",
	0x26, 0x0c, "invalid operation for copy source or destination",
	0x26, 0x0d, "copy segment granularity violation",
	0x27, 0x00, "write protected",
	0x27, 0x01, "hardware write protected",
	0x27, 0x02, "LUN software write protected",
	0x27, 0x03, "associated write protect",
	0x27, 0x04, "persistent write protect",
	0x27, 0x05, "permanent write protect",
	0x27, 0x06, "conditional write protect",
	0x27, 0x80, "unable to overwrite data",
	0x28, 0x00, "medium may have changed",
	0x28, 0x01, "import or export element accessed",
	0x29, 0x00, "power on, reset, or bus reset occurred",
	0x29, 0x01, "power on occurred",
	0x29, 0x02, "scsi bus reset occurred",
	0x29, 0x03, "bus device reset message occurred",
	0x29, 0x04, "device internal reset",
	0x29, 0x05, "transceiver mode changed to single-ended",
	0x29, 0x06, "transceiver mode changed to LVD",
	0x29, 0x07, "i_t nexus loss occurred",
	0x2a, 0x00, "parameters changed",
	0x2a, 0x01, "mode parameters changed",
	0x2a, 0x02, "log parameters changed",
	0x2a, 0x03, "reservations preempted",
	0x2a, 0x04, "reservations released",
	0x2a, 0x05, "registrations preempted",
	0x2a, 0x06, "asymmetric access state changed",
	0x2a, 0x07, "implicit asymmetric access state transition failed",
	0x2b, 0x00, "copy cannot execute since host cannot disconnect",
	0x2c, 0x00, "command sequence error",
	0x2c, 0x03, "current program area is not empty",
	0x2c, 0x04, "current program area is empty",
	0x2c, 0x06, "persistent prevent conflict",
	0x2c, 0x07, "previous busy status",
	0x2c, 0x08, "previous task set full status",
	0x2c, 0x09, "previous reservation conflict status",
	0x2d, 0x00, "overwrite error on update in place",
	0x2e, 0x00, "insufficient time for operation",
	0x2f, 0x00, "commands cleared by another initiator",
	0x30, 0x00, "incompatible medium installed",
	0x30, 0x01, "cannot read medium - unknown format",
	0x30, 0x02, "cannot read medium - incompatible format",
	0x30, 0x03, "cleaning cartridge installed",
	0x30, 0x04, "cannot write medium - unknown format",
	0x30, 0x05, "cannot write medium - incompatible format",
	0x30, 0x06, "cannot format medium - incompatible medium",
	0x30, 0x07, "cleaning failure",
	0x30, 0x08, "cannot write - application code mismatch",
	0x30, 0x09, "current session not fixated for append",
	0x30, 0x0b, "WORM medium - Overwrite attempted",
	0x30, 0x0c, "WORM medium - Cannot Erase",
	0x30, 0x0d, "WORM medium - Integrity Check",
	0x30, 0x10, "medium not formatted",
	0x31, 0x00, "medium format corrupted",
	0x31, 0x01, "format command failed",
	0x31, 0x02, "zoned formatting failed due to spare linking",
	0x31, 0x94, "WORM media corrupted",
	0x32, 0x00, "no defect spare location available",
	0x32, 0x01, "defect list update failure",
	0x33, 0x00, "tape length error",
	0x34, 0x00, "enclosure failure",
	0x35, 0x00, "enclosure services failure",
	0x35, 0x01, "unsupported enclosure function",
	0x35, 0x02, "enclosure services unavailable",
	0x35, 0x03, "enclosure services transfer failure",
	0x35, 0x04, "enclosure services transfer refused",
	0x36, 0x00, "ribbon, ink, or toner failure",
	0x37, 0x00, "rounded parameter",
	0x39, 0x00, "saving parameters not supported",
	0x3a, 0x00, "medium not present",
	0x3a, 0x01, "medium not present - tray closed",
	0x3a, 0x02, "medium not present - tray open",
	0x3a, 0x03, "medium not present - loadable",
	0x3a, 0x04, "medium not present - medium auxiliary memory accessible",
	0x3b, 0x00, "sequential positioning error",
	0x3b, 0x01, "tape position error at beginning-of-medium",
	0x3b, 0x02, "tape position error at end-of-medium",
	0x3b, 0x08, "reposition error",
	0x3b, 0x0c, "position past beginning of medium",
	0x3b, 0x0d, "medium destination element full",
	0x3b, 0x0e, "medium source element empty",
	0x3b, 0x0f, "end of medium reached",
	0x3b, 0x11, "medium magazine not accessible",
	0x3b, 0x12, "medium magazine removed",
	0x3b, 0x13, "medium magazine inserted",
	0x3b, 0x14, "medium magazine locked",
	0x3b, 0x15, "medium magazine unlocked",
	0x3b, 0x16, "mechanical positioning or changer error",
	0x3d, 0x00, "invalid bits in indentify message",
	0x3e, 0x00, "LUN has not self-configured yet",
	0x3e, 0x01, "LUN failure",
	0x3e, 0x02, "timeout on LUN",
	0x3e, 0x03, "LUN failed self-test",
	0x3e, 0x04, "LUN unable to update self-test log",
	0x3f, 0x00, "target operating conditions have changed",
	0x3f, 0x01, "microcode has been changed",
	0x3f, 0x02, "changed operating definition",
	0x3f, 0x03, "inquiry data has changed",
	0x3f, 0x04, "component device attached",
	0x3f, 0x05, "device identifier changed",
	0x3f, 0x06, "redundancy group created or modified",
	0x3f, 0x07, "redundancy group deleted",
	0x3f, 0x08, "spare created or modified",
	0x3f, 0x09, "spare deleted",
	0x3f, 0x0a, "volume set created or modified",
	0x3f, 0x0b, "volume set deleted",
	0x3f, 0x0c, "volume set deassigned",
	0x3f, 0x0d, "volume set reassigned",
	0x3f, 0x0e, "reported LUNs data has changed",
	0x3f, 0x0f, "echo buffer overwritten",
	0x3f, 0x10, "medium loadable",
	0x3f, 0x11, "medium auxiliary memory accessible",
	0x40, 0x00, "ram failure",
	0x41, 0x00, "data path failure",
	0x42, 0x00, "power-on or self-test failure",
	0x43, 0x00, "message error",
	0x44, 0x00, "internal target failure",
	0x45, 0x00, "select or reselect failure",
	0x46, 0x00, "unsuccessful soft reset",
	0x47, 0x00, "scsi parity error",
	0x47, 0x01, "data phase crc error detected",
	0x47, 0x02, "scsi parity error detected during st data phase",
	0x47, 0x03, "information unit iucrc error detected",
	0x47, 0x04, "asynchronous information protection error detected",
	0x47, 0x05, "protocol service crc error",
	0x47, 0x7f, "some commands cleared by iscsi protocol event",
	0x48, 0x00, "initiator detected error message received",
	0x49, 0x00, "invalid message error",
	0x4a, 0x00, "command phase error",
	0x4b, 0x00, "data phase error",
	0x4b, 0x01, "invalid target port transfer tag received",
	0x4b, 0x02, "too much write data",
	0x4b, 0x03, "ack/nak timeout",
	0x4b, 0x04, "nak received",
	0x4b, 0x05, "data offset error",
	0x4c, 0x00, "logical unit failed self-configuration",
	0x4d, 0x00, "tagged overlapped commands (ASCQ = queue tag)",
	0x4e, 0x00, "overlapped commands attempted",
	0x50, 0x00, "write append error",
	0x50, 0x01, "data protect write append error",
	0x50, 0x95, "data protect write append error",
	0x51, 0x00, "erase failure",
	0x52, 0x00, "cartridge fault",
	0x53, 0x00, "media load or eject failed",
	0x53, 0x01, "unload tape failure",
	0x53, 0x02, "medium removal prevented",
	0x54, 0x00, "scsi to host system interface failure",
	0x55, 0x00, "system resource failure",
	0x55, 0x01, "system buffer full",
	0x55, 0x02, "insufficient reservation resources",
	0x55, 0x03, "insufficient resources",
	0x55, 0x04, "insufficient registration resources",
	0x55, 0x05, "insufficient access control resources",
	0x55, 0x06, "auxiliary memory out of space",
	0x57, 0x00, "unable to recover TOC",
	0x58, 0x00, "generation does not exist",
	0x59, 0x00, "updated block read",
	0x5a, 0x00, "operator request or state change input",
	0x5a, 0x01, "operator medium removal request",
	0x5a, 0x02, "operator selected write protect",
	0x5a, 0x03, "operator selected write permit",
	0x5b, 0x00, "log exception",
	0x5b, 0x01, "threshold condition met",
	0x5b, 0x02, "log counter at maximum",
	0x5b, 0x03, "log list codes exhausted",
	0x5c, 0x00, "RPL status change",
	0x5c, 0x01, "spindles synchronized",
	0x5c, 0x02, "spindles not synchronized",
	0x5d, 0x00, "drive operation marginal, service immediately"
		    " (failure prediction threshold exceeded)",
	0x5d, 0x01, "media failure prediction threshold exceeded",
	0x5d, 0x02, "LUN failure prediction threshold exceeded",
	0x5d, 0x03, "spare area exhaustion prediction threshold exceeded",
	0x5d, 0x10, "hardware impending failure general hard drive failure",
	0x5d, 0x11, "hardware impending failure drive error rate too high",
	0x5d, 0x12, "hardware impending failure data error rate too high",
	0x5d, 0x13, "hardware impending failure seek error rate too high",
	0x5d, 0x14, "hardware impending failure too many block reassigns",
	0x5d, 0x15, "hardware impending failure access times too high",
	0x5d, 0x16, "hardware impending failure start unit times too high",
	0x5d, 0x17, "hardware impending failure channel parametrics",
	0x5d, 0x18, "hardware impending failure controller detected",
	0x5d, 0x19, "hardware impending failure throughput performance",
	0x5d, 0x1a, "hardware impending failure seek time performance",
	0x5d, 0x1b, "hardware impending failure spin-up retry count",
	0x5d, 0x1c, "hardware impending failure drive calibration retry count",
	0x5d, 0x20, "controller impending failure general hard drive failure",
	0x5d, 0x21, "controller impending failure drive error rate too high",
	0x5d, 0x22, "controller impending failure data error rate too high",
	0x5d, 0x23, "controller impending failure seek error rate too high",
	0x5d, 0x24, "controller impending failure too many block reassigns",
	0x5d, 0x25, "controller impending failure access times too high",
	0x5d, 0x26, "controller impending failure start unit times too high",
	0x5d, 0x27, "controller impending failure channel parametrics",
	0x5d, 0x28, "controller impending failure controller detected",
	0x5d, 0x29, "controller impending failure throughput performance",
	0x5d, 0x2a, "controller impending failure seek time performance",
	0x5d, 0x2b, "controller impending failure spin-up retry count",
	0x5d, 0x2c, "controller impending failure drive calibration retry cnt",
	0x5d, 0x30, "data channel impending failure general hard drive failure",
	0x5d, 0x31, "data channel impending failure drive error rate too high",
	0x5d, 0x32, "data channel impending failure data error rate too high",
	0x5d, 0x33, "data channel impending failure seek error rate too high",
	0x5d, 0x34, "data channel impending failure too many block reassigns",
	0x5d, 0x35, "data channel impending failure access times too high",
	0x5d, 0x36, "data channel impending failure start unit times too high",
	0x5d, 0x37, "data channel impending failure channel parametrics",
	0x5d, 0x38, "data channel impending failure controller detected",
	0x5d, 0x39, "data channel impending failure throughput performance",
	0x5d, 0x3a, "data channel impending failure seek time performance",
	0x5d, 0x3b, "data channel impending failure spin-up retry count",
	0x5d, 0x3c, "data channel impending failure drive calibrate retry cnt",
	0x5d, 0x40, "servo impending failure general hard drive failure",
	0x5d, 0x41, "servo impending failure drive error rate too high",
	0x5d, 0x42, "servo impending failure data error rate too high",
	0x5d, 0x43, "servo impending failure seek error rate too high",
	0x5d, 0x44, "servo impending failure too many block reassigns",
	0x5d, 0x45, "servo impending failure access times too high",
	0x5d, 0x46, "servo impending failure start unit times too high",
	0x5d, 0x47, "servo impending failure channel parametrics",
	0x5d, 0x48, "servo impending failure controller detected",
	0x5d, 0x49, "servo impending failure throughput performance",
	0x5d, 0x4a, "servo impending failure seek time performance",
	0x5d, 0x4b, "servo impending failure spin-up retry count",
	0x5d, 0x4c, "servo impending failure drive calibration retry count",
	0x5d, 0x50, "spindle impending failure general hard drive failure",
	0x5d, 0x51, "spindle impending failure drive error rate too high",
	0x5d, 0x52, "spindle impending failure data error rate too high",
	0x5d, 0x53, "spindle impending failure seek error rate too high",
	0x5d, 0x54, "spindle impending failure too many block reassigns",
	0x5d, 0x55, "spindle impending failure access times too high",
	0x5d, 0x56, "spindle impending failure start unit times too high",
	0x5d, 0x57, "spindle impending failure channel parametrics",
	0x5d, 0x58, "spindle impending failure controller detected",
	0x5d, 0x59, "spindle impending failure throughput performance",
	0x5d, 0x5a, "spindle impending failure seek time performance",
	0x5d, 0x5b, "spindle impending failure spin-up retry count",
	0x5d, 0x5c, "spindle impending failure drive calibration retry count",
	0x5d, 0x60, "firmware impending failure general hard drive failure",
	0x5d, 0x61, "firmware impending failure drive error rate too high",
	0x5d, 0x62, "firmware impending failure data error rate too high",
	0x5d, 0x63, "firmware impending failure seek error rate too high",
	0x5d, 0x64, "firmware impending failure too many block reassigns",
	0x5d, 0x65, "firmware impending failure access times too high",
	0x5d, 0x66, "firmware impending failure start unit times too high",
	0x5d, 0x67, "firmware impending failure channel parametrics",
	0x5d, 0x68, "firmware impending failure controller detected",
	0x5d, 0x69, "firmware impending failure throughput performance",
	0x5d, 0x6a, "firmware impending failure seek time performance",
	0x5d, 0x6b, "firmware impending failure spin-up retry count",
	0x5d, 0x6c, "firmware impending failure drive calibration retry count",
	0x5d, 0xff, "failure prediction threshold exceeded (false)",
	0x5e, 0x00, "low power condition active",
	0x5e, 0x01, "idle condition activated by timer",
	0x5e, 0x02, "standby condition activated by timer",
	0x5e, 0x03, "idle condition activated by command",
	0x5e, 0x04, "standby condition activated by command",
	0x60, 0x00, "lamp failure",
	0x61, 0x00, "video acquisition error",
	0x62, 0x00, "scan head positioning error",
	0x63, 0x00, "end of user area encountered on this track",
	0x63, 0x01, "packet does not fit in available space",
	0x64, 0x00, "illegal mode for this track",
	0x64, 0x01, "invalid packet size",
	0x65, 0x00, "voltage fault",
	0x66, 0x00, "automatic document feeder cover up",
	0x67, 0x00, "configuration failure",
	0x67, 0x01, "configuration of incapable LUNs failed",
	0x67, 0x02, "add LUN failed",
	0x67, 0x03, "modification of LUN failed",
	0x67, 0x04, "exchange of LUN failed",
	0x67, 0x05, "remove of LUN failed",
	0x67, 0x06, "attachment of LUN failed",
	0x67, 0x07, "creation of LUN failed",
	0x67, 0x08, "assign failure occurred",
	0x67, 0x09, "multiply assigned LUN",
	0x67, 0x0a, "set target port groups command failed",
	0x68, 0x00, "logical unit not configured",
	0x69, 0x00, "data loss on logical unit",
	0x69, 0x01, "multiple LUN failures",
	0x69, 0x02, "parity/data mismatch",
	0x6a, 0x00, "informational, refer to log",
	0x6b, 0x00, "state change has occurred",
	0x6b, 0x01, "redundancy level got better",
	0x6b, 0x02, "redundancy level got worse",
	0x6c, 0x00, "rebuild failure occurred",
	0x6d, 0x00, "recalculate failure occurred",
	0x6e, 0x00, "command to logical unit failed",
	0x6f, 0x00, "copy protect key exchange failure authentication failure",
	0x6f, 0x01, "copy protect key exchange failure key not present",
	0x6f, 0x02, "copy protect key exchange failure key not established",
	0x6f, 0x03, "read of scrambled sector without authentication",
	0x6f, 0x04, "media region code is mismatched to LUN region",
	0x6f, 0x05, "drive region must be permanent/region reset count error",
	0x70, 0xffff, "decompression exception short algorithm id of ASCQ",
	0x71, 0x00, "decompression exception long algorithm id",
	0x72, 0x00, "session fixation error",
	0x72, 0x01, "session fixation error writing lead-in",
	0x72, 0x02, "session fixation error writing lead-out",
	0x72, 0x03, "session fixation error - incomplete track in session",
	0x72, 0x04, "empty or partially written reserved track",
	0x72, 0x05, "no more track reservations allowed",
	0x73, 0x00, "cd control error",
	0x73, 0x01, "power calibration area almost full",
	0x73, 0x02, "power calibration area is full",
	0x73, 0x03, "power calibration area error",
	0x73, 0x04, "program memory area update failure",
	0x73, 0x05, "program memory area is full",
	0x73, 0x06, "rma/pma is almost full",
	0xffff, 0xffff, NULL
};

char *
scsi_esname(uint_t key, char *tmpstr)
{
	int i = 0;

	while (extended_sense_list[i].asc != 0xffff) {
		if (key == extended_sense_list[i].asc) {
			return ((char *)extended_sense_list[i].message);
		}
		i++;
	}
	return (sprintf(tmpstr, "<vendor unique code 0x%x>", key));
}

char *
scsi_asc_name(uint_t asc, uint_t ascq, char *tmpstr)
{
	int i = 0;

	while (extended_sense_list[i].asc != 0xffff) {
		if ((asc == extended_sense_list[i].asc) &&
		    ((ascq == extended_sense_list[i].ascq) ||
		    (extended_sense_list[i].ascq == 0xffff))) {
			return ((char *)extended_sense_list[i].message);
		}
		i++;
	}
	return (sprintf(tmpstr, "<vendor unique code 0x%x>", asc));
}

char *
scsi_sname(uchar_t sense_key)
{
	if (sense_key >= (uchar_t)(NUM_SENSE_KEYS+NUM_IMPL_SENSE_KEYS)) {
		return ("<unknown sense key>");
	} else {
		return (sense_keys[sense_key]);
	}
}


/*
 * Print a piece of inquiry data- cleaned up for non-printable characters.
 */
static void
inq_fill(char *p, int l, char *s)
{
	register unsigned i = 0;
	char c;

	if (!p)
		return;

	while (i++ < l) {
		/* clean string of non-printing chars */
		if ((c = *p++) < ' ' || c >= 0177) {
			c = ' ';
		}
		*s++ = c;
	}
	*s++ = 0;
}

static char *
scsi_asc_search(uint_t asc, uint_t ascq,
    struct scsi_asq_key_strings *list)
{
	int i = 0;

	while (list[i].asc != 0xffff) {
		if ((asc == list[i].asc) &&
		    ((ascq == list[i].ascq) ||
		    (list[i].ascq == 0xffff))) {
			return ((char *)list[i].message);
		}
		i++;
	}
	return (NULL);
}

static char *
scsi_asc_ascq_name(uint_t asc, uint_t ascq, char *tmpstr,
	struct scsi_asq_key_strings *list)
{
	char *message;

	if (list) {
		if (message = scsi_asc_search(asc, ascq, list)) {
			return (message);
		}
	}
	if (message = scsi_asc_search(asc, ascq, extended_sense_list)) {
		return (message);
	}

	return (sprintf(tmpstr, "<vendor unique code 0x%x>", asc));
}

/*
 * The first part/column of the error message will be at least this length.
 * This number has been calculated so that each line fits in 80 chars.
 */
#define	SCSI_ERRMSG_COLUMN_LEN	42
#define	SCSI_ERRMSG_BUF_LEN	256

void
scsi_generic_errmsg(struct scsi_device *devp, char *label, int severity,
    daddr_t blkno, daddr_t err_blkno,
    uchar_t cmd_name, struct scsi_key_strings *cmdlist,
    uint8_t *sensep, struct scsi_asq_key_strings *asc_list,
    char *(*decode_fru)(struct scsi_device *, char *, int, uchar_t))
{
	uchar_t com;
	static char buf[SCSI_ERRMSG_BUF_LEN];
	static char buf1[SCSI_ERRMSG_BUF_LEN];
	static char tmpbuf[64];
	static char pad[SCSI_ERRMSG_COLUMN_LEN];
	dev_info_t *dev = devp->sd_dev;
	static char *error_classes[] = {
		"All", "Unknown", "Informational",
		"Recovered", "Retryable", "Fatal"
	};
	uchar_t sense_key, asc, ascq, fru_code;
	uchar_t *fru_code_ptr;
	int i, buflen;

	mutex_enter(&scsi_log_mutex);

	/*
	 * We need to put our space padding code because kernel version
	 * of sprintf(9F) doesn't support %-<number>s type of left alignment.
	 */
	for (i = 0; i < SCSI_ERRMSG_COLUMN_LEN; i++) {
		pad[i] = ' ';
	}

	bzero(buf, SCSI_ERRMSG_BUF_LEN);
	com = cmd_name;
	(void) sprintf(buf, "Error for Command: %s",
	    scsi_cmd_name(com, cmdlist, tmpbuf));
	buflen = strlen(buf);
	if (buflen < SCSI_ERRMSG_COLUMN_LEN) {
		pad[SCSI_ERRMSG_COLUMN_LEN - buflen] = '\0';
		(void) sprintf(&buf[buflen], "%s Error Level: %s",
		    pad, error_classes[severity]);
		pad[SCSI_ERRMSG_COLUMN_LEN - buflen] = ' ';
	} else {
		(void) sprintf(&buf[buflen], " Error Level: %s",
		    error_classes[severity]);
	}
	impl_scsi_log(dev, label, CE_WARN, buf);

	if (blkno != -1 || err_blkno != -1 &&
	    ((com & 0xf) == SCMD_READ) || ((com & 0xf) == SCMD_WRITE)) {
		bzero(buf, SCSI_ERRMSG_BUF_LEN);
		(void) sprintf(buf, "Requested Block: %ld", blkno);
		buflen = strlen(buf);
		if (buflen < SCSI_ERRMSG_COLUMN_LEN) {
			pad[SCSI_ERRMSG_COLUMN_LEN - buflen] = '\0';
			(void) sprintf(&buf[buflen], "%s Error Block: %ld\n",
			    pad, err_blkno);
			pad[SCSI_ERRMSG_COLUMN_LEN - buflen] = ' ';
		} else {
			(void) sprintf(&buf[buflen], " Error Block: %ld\n",
			    err_blkno);
		}
		impl_scsi_log(dev, label, CE_CONT, buf);
	}

	bzero(buf, SCSI_ERRMSG_BUF_LEN);
	(void) strcpy(buf, "Vendor: ");
	inq_fill(devp->sd_inq->inq_vid, 8, &buf[strlen(buf)]);
	buflen = strlen(buf);
	if (buflen < SCSI_ERRMSG_COLUMN_LEN) {
		pad[SCSI_ERRMSG_COLUMN_LEN - buflen] = '\0';
		(void) sprintf(&buf[strlen(buf)], "%s Serial Number: ", pad);
		pad[SCSI_ERRMSG_COLUMN_LEN - buflen] = ' ';
	} else {
		(void) sprintf(&buf[strlen(buf)], " Serial Number: ");
	}
	inq_fill(devp->sd_inq->inq_serial, 12, &buf[strlen(buf)]);
	impl_scsi_log(dev, label, CE_CONT, "%s\n", buf);

	if (sensep) {
		sense_key = scsi_sense_key(sensep);
		asc = scsi_sense_asc(sensep);
		ascq = scsi_sense_ascq(sensep);
		scsi_ext_sense_fields(sensep, SENSE_LENGTH,
		    NULL, NULL, &fru_code_ptr, NULL, NULL);
		fru_code = (fru_code_ptr ? *fru_code_ptr : 0);

		bzero(buf, SCSI_ERRMSG_BUF_LEN);
		(void) sprintf(buf, "Sense Key: %s\n",
		    sense_keys[sense_key]);
		impl_scsi_log(dev, label, CE_CONT, buf);

		bzero(buf, SCSI_ERRMSG_BUF_LEN);
		if ((fru_code != 0) &&
		    (decode_fru != NULL)) {
			(*decode_fru)(devp, buf, SCSI_ERRMSG_BUF_LEN,
			    fru_code);
			if (buf[0] != NULL) {
				bzero(buf1, SCSI_ERRMSG_BUF_LEN);
				(void) sprintf(&buf1[strlen(buf1)],
				    "ASC: 0x%x (%s)", asc,
				    scsi_asc_ascq_name(asc, ascq,
				    tmpbuf, asc_list));
				buflen = strlen(buf1);
				if (buflen < SCSI_ERRMSG_COLUMN_LEN) {
					pad[SCSI_ERRMSG_COLUMN_LEN - buflen] =
					    '\0';
					(void) sprintf(&buf1[buflen],
					    "%s ASCQ: 0x%x", pad, ascq);
				} else {
					(void) sprintf(&buf1[buflen],
					    " ASCQ: 0x%x", ascq);
				}
				impl_scsi_log(dev,
				    label, CE_CONT, "%s\n", buf1);
				impl_scsi_log(dev,
				    label, CE_CONT, "FRU: 0x%x (%s)\n",
				    fru_code, buf);
				mutex_exit(&scsi_log_mutex);
				return;
			}
		}
		(void) sprintf(&buf[strlen(buf)],
		    "ASC: 0x%x (%s), ASCQ: 0x%x, FRU: 0x%x",
		    asc, scsi_asc_ascq_name(asc, ascq, tmpbuf, asc_list),
		    ascq, fru_code);
		impl_scsi_log(dev, label, CE_CONT, "%s\n", buf);
	}
	mutex_exit(&scsi_log_mutex);
}

void
scsi_vu_errmsg(struct scsi_device *devp, struct scsi_pkt *pkt, char *label,
    int severity, daddr_t blkno, daddr_t err_blkno,
    struct scsi_key_strings *cmdlist, struct scsi_extended_sense *sensep,
    struct scsi_asq_key_strings *asc_list,
    char *(*decode_fru)(struct scsi_device *, char *, int, uchar_t))
{
	uchar_t com;

	com = ((union scsi_cdb *)pkt->pkt_cdbp)->scc_cmd;

	scsi_generic_errmsg(devp, label, severity, blkno, err_blkno,
	    com, cmdlist, (uint8_t *)sensep, asc_list, decode_fru);


}

void
scsi_errmsg(struct scsi_device *devp, struct scsi_pkt *pkt, char *label,
    int severity, daddr_t blkno, daddr_t err_blkno,
    struct scsi_key_strings *cmdlist, struct scsi_extended_sense *sensep)
{
	scsi_vu_errmsg(devp, pkt, label, severity, blkno,
	    err_blkno, cmdlist, sensep, NULL, NULL);
}

/*PRINTFLIKE4*/
void
scsi_log(dev_info_t *dev, char *label, uint_t level,
    const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	mutex_enter(&scsi_log_mutex);
	v_scsi_log(dev, label, level, fmt, ap);
	mutex_exit(&scsi_log_mutex);
	va_end(ap);
}

/*PRINTFLIKE4*/
static void
impl_scsi_log(dev_info_t *dev, char *label, uint_t level,
    const char *fmt, ...)
{
	va_list ap;

	ASSERT(mutex_owned(&scsi_log_mutex));

	va_start(ap, fmt);
	v_scsi_log(dev, label, level, fmt, ap);
	va_end(ap);
}


char *ddi_pathname(dev_info_t *dip, char *path);

/*PRINTFLIKE4*/
static void
v_scsi_log(dev_info_t *dev, char *label, uint_t level,
    const char *fmt, va_list ap)
{
	static char name[256];
	int log_only = 0;
	int boot_only = 0;
	int console_only = 0;

	ASSERT(mutex_owned(&scsi_log_mutex));

	if (dev) {
		if (level == CE_PANIC || level == CE_WARN ||
		    level == CE_NOTE) {
			(void) sprintf(name, "%s (%s%d):\n",
			    ddi_pathname(dev, scsi_log_buffer),
			    label, ddi_get_instance(dev));
		} else if (level >= (uint_t)SCSI_DEBUG) {
			(void) sprintf(name,
			    "%s%d:", label, ddi_get_instance(dev));
		} else {
			name[0] = '\0';
		}
	} else {
		(void) sprintf(name, "%s:", label);
	}

	(void) vsprintf(scsi_log_buffer, fmt, ap);

	switch (scsi_log_buffer[0]) {
	case '!':
		log_only = 1;
		break;
	case '?':
		boot_only = 1;
		break;
	case '^':
		console_only = 1;
		break;
	}

	switch (level) {
	case CE_NOTE:
		level = CE_CONT;
		/* FALLTHROUGH */
	case CE_CONT:
	case CE_WARN:
	case CE_PANIC:
		if (boot_only) {
			cmn_err(level, "?%s\t%s", name, &scsi_log_buffer[1]);
		} else if (console_only) {
			cmn_err(level, "^%s\t%s", name, &scsi_log_buffer[1]);
		} else if (log_only) {
			cmn_err(level, "!%s\t%s", name, &scsi_log_buffer[1]);
		} else {
			cmn_err(level, "%s\t%s", name, scsi_log_buffer);
		}
		break;
	case (uint_t)SCSI_DEBUG:
	default:
		cmn_err(CE_CONT, "^DEBUG: %s\t%s", name, scsi_log_buffer);
		break;
	}
}

/*
 * Lookup the 'prop_name' string array property and walk thru its list of
 * tuple values looking for a tuple who's VID/PID string (first part of tuple)
 * matches the inquiry VID/PID information for the scsi_device.  On a match,
 * return a duplicate of the second part of the tuple.  If no match is found,
 * return NULL. On non-NULL return, caller is responsible for freeing return
 * result via:
 *	kmem_free(string, strlen(string) + 1);
 *
 * This interface can either be used directly, or indirectly by
 * scsi_get_device_type_scsi_options.
 */
char	*
scsi_get_device_type_string(char *prop_name,
    dev_info_t *dip, struct scsi_device *devp)
{
	struct scsi_inquiry	*inq = devp->sd_inq;
	char			**tuples;
	uint_t			ntuples;
	int			i;
	char			*tvp;		/* tuple vid/pid */
	char			*trs;		/* tuple return string */
	int			tvp_len;

	/* if we have no inquiry data then we can't do this */
	if (inq == NULL)
		return (NULL);

	/*
	 * So that we can establish a 'prop_name' for all instances of a
	 * device in the system in a single place if needed (via options.conf),
	 * we loop going up to the root ourself. This way root lookup does
	 * *not* specify DDI_PROP_DONTPASS, and the code will look on the
	 * options node.
	 */
	do {
		if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip,
		    (ddi_get_parent(dip) ? DDI_PROP_DONTPASS : 0) |
		    DDI_PROP_NOTPROM, prop_name, &tuples, &ntuples) ==
		    DDI_PROP_SUCCESS) {

			/* loop over tuples */
			for (i = 0;  i < (ntuples/2); i++) {
				/* split into vid/pid and return-string */
				tvp = tuples[i * 2];
				trs = tuples[(i * 2) + 1];
				tvp_len = strlen(tvp);

				/* check for vid/pid match */
				if ((tvp_len == 0) ||
				    bcmp(tvp, inq->inq_vid, tvp_len))
					continue;	/* no match */

				/* match, dup return-string */
				trs = i_ddi_strdup(trs, KM_SLEEP);
				ddi_prop_free(tuples);
				return (trs);
			}
			ddi_prop_free(tuples);
		}

		/* climb up to root one step at a time */
		dip = ddi_get_parent(dip);
	} while (dip);

	return (NULL);
}

/*
 * The 'device-type-scsi-options' mechanism can be used to establish a device
 * specific scsi_options value for a particular device. This mechanism uses
 * paired strings ("vendor_info", "options_property_name") from the string
 * array "device-type-scsi-options" definition. A bcmp of the vendor info is
 * done against the inquiry data (inq_vid). Here is an example of use:
 *
 * device-type-scsi-options-list =
 *	"FOOLCO  Special x1000", "foolco-scsi-options",
 *	"FOOLCO  Special y1000", "foolco-scsi-options";
 * foolco-scsi-options = 0xXXXXXXXX;
 */
int
scsi_get_device_type_scsi_options(dev_info_t *dip,
    struct scsi_device *devp, int options)
{
	char	*string;

	if ((string = scsi_get_device_type_string(
	    "device-type-scsi-options-list", dip, devp)) != NULL) {
		options = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
		    string, options);
		kmem_free(string, strlen(string) + 1);
	}
	return (options);
}

/*
 * Find the scsi_options for a scsi_device. The precedence is:
 *
 *	target<%d>-scsi-options		highest
 *	device-type-scsi-options
 *	per bus scsi-options (parent)
 *	global scsi-options
 *	default_scsi_options argument	lowest
 *
 * If the global is used then it has already been established
 * on the parent scsi_hba_attach_setup.
 */
int
scsi_get_scsi_options(struct scsi_device *sd, int default_scsi_options)
{
	dev_info_t	*parent;
	int		options = -1;
	int		tgt;
	char		topt[32];

	if ((sd == NULL) || (sd->sd_dev == NULL))
		return (default_scsi_options);

	parent = ddi_get_parent(sd->sd_dev);

	if ((tgt = ddi_prop_get_int(DDI_DEV_T_ANY, sd->sd_dev,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "target", -1)) != -1) {
		(void) sprintf(topt, "target%d-scsi-options", tgt);
		options = ddi_prop_get_int(DDI_DEV_T_ANY, parent,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, topt, -1);
	}

	if (options == -1)
		options = scsi_get_device_type_scsi_options(parent, sd, -1);

	if (options == -1)
		options = ddi_prop_get_int(DDI_DEV_T_ANY, parent,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "scsi-options", -1);

	if (options == -1)
		options = default_scsi_options;

	return (options);
}

/*
 * Use scsi-options to return the maximum number of LUNs.
 */
int
scsi_get_scsi_maxluns(struct scsi_device *sd)
{
	int	options;
	int	maxluns;

	ASSERT(sd && sd->sd_inq);
	options = scsi_get_scsi_options(sd, SCSI_OPTIONS_NLUNS_DEFAULT);

	switch (SCSI_OPTIONS_NLUNS(options)) {
	default:
	case SCSI_OPTIONS_NLUNS_DEFAULT:
		/* based on scsi version of target */
		if (sd->sd_inq->inq_ansi < SCSI_VERSION_3)
			maxluns = SCSI_8LUN_PER_TARGET;		/* 8 */
		else
			maxluns = SCSI_16LUNS_PER_TARGET;	/* 16 */
		break;
	case SCSI_OPTIONS_NLUNS_1:
		maxluns = SCSI_1LUN_PER_TARGET;		/* 1 */
		break;
	case SCSI_OPTIONS_NLUNS_8:
		maxluns = SCSI_8LUN_PER_TARGET;		/* 8 */
		break;
	case SCSI_OPTIONS_NLUNS_16:
		maxluns = SCSI_16LUNS_PER_TARGET;	/* 16 */
		break;
	case SCSI_OPTIONS_NLUNS_32:
		maxluns = SCSI_32LUNS_PER_TARGET;	/* 32 */
		break;
	}

	/* For SCSI-1 we never support > 8 LUNs */
	if ((sd->sd_inq->inq_ansi <= SCSI_VERSION_1) &&
	    (maxluns > SCSI_8LUN_PER_TARGET))
		maxluns = SCSI_8LUN_PER_TARGET;

	return (maxluns);
}

/*
 * Functions for format-neutral sense data functions
 */
int
scsi_validate_sense(uint8_t *sense_buffer, int sense_buf_len, int *flags)
{
	int result;
	struct scsi_extended_sense *es =
	    (struct scsi_extended_sense *)sense_buffer;

	/*
	 * Init flags if present
	 */
	if (flags != NULL) {
		*flags = 0;
	}

	/*
	 * Check response code (Solaris breaks this into a 3-bit class
	 * and 4-bit code field.
	 */
	if ((es->es_class != CLASS_EXTENDED_SENSE) ||
	    ((es->es_code != CODE_FMT_FIXED_CURRENT) &&
	    (es->es_code != CODE_FMT_FIXED_DEFERRED) &&
	    (es->es_code != CODE_FMT_DESCR_CURRENT) &&
	    (es->es_code != CODE_FMT_DESCR_DEFERRED))) {
		/*
		 * Sense data (if there's actually anything here) is not
		 * in a format we can handle).
		 */
		return (SENSE_UNUSABLE);
	}

	/*
	 * Check if this is deferred sense
	 */
	if ((flags != NULL) &&
	    ((es->es_code == CODE_FMT_FIXED_DEFERRED) ||
	    (es->es_code == CODE_FMT_DESCR_DEFERRED))) {
		*flags |= SNS_BUF_DEFERRED;
	}

	/*
	 * Make sure length is OK
	 */
	if (es->es_code == CODE_FMT_FIXED_CURRENT ||
	    es->es_code == CODE_FMT_FIXED_DEFERRED) {
		/*
		 * We can get by with a buffer that only includes the key,
		 * asc, and ascq.  In reality the minimum length we should
		 * ever see is 18 bytes.
		 */
		if ((sense_buf_len < MIN_FIXED_SENSE_LEN) ||
		    ((es->es_add_len + ADDL_SENSE_ADJUST) <
		    MIN_FIXED_SENSE_LEN)) {
			result = SENSE_UNUSABLE;
		} else {
			/*
			 * The es_add_len field contains the number of sense
			 * data bytes that follow the es_add_len field.
			 */
			if ((flags != NULL) &&
			    (sense_buf_len <
			    (es->es_add_len + ADDL_SENSE_ADJUST))) {
				*flags |= SNS_BUF_OVERFLOW;
			}

			result = SENSE_FIXED_FORMAT;
		}
	} else {
		struct scsi_descr_sense_hdr *ds =
		    (struct scsi_descr_sense_hdr *)sense_buffer;

		/*
		 * For descriptor format we need at least the descriptor
		 * header
		 */
		if (sense_buf_len < sizeof (struct scsi_descr_sense_hdr)) {
			result = SENSE_UNUSABLE;
		} else {
			/*
			 * Check for overflow
			 */
			if ((flags != NULL) &&
			    (sense_buf_len <
			    (ds->ds_addl_sense_length + sizeof (*ds)))) {
				*flags |= SNS_BUF_OVERFLOW;
			}

			result = SENSE_DESCR_FORMAT;
		}
	}

	return (result);
}


uint8_t
scsi_sense_key(uint8_t *sense_buffer)
{
	uint8_t skey;
	if (SCSI_IS_DESCR_SENSE(sense_buffer)) {
		struct scsi_descr_sense_hdr *sdsp =
		    (struct scsi_descr_sense_hdr *)sense_buffer;
		skey = sdsp->ds_key;
	} else {
		struct scsi_extended_sense *ext_sensep =
		    (struct scsi_extended_sense *)sense_buffer;
		skey = ext_sensep->es_key;
	}
	return (skey);
}

uint8_t
scsi_sense_asc(uint8_t *sense_buffer)
{
	uint8_t asc;
	if (SCSI_IS_DESCR_SENSE(sense_buffer)) {
		struct scsi_descr_sense_hdr *sdsp =
		    (struct scsi_descr_sense_hdr *)sense_buffer;
		asc = sdsp->ds_add_code;
	} else {
		struct scsi_extended_sense *ext_sensep =
		    (struct scsi_extended_sense *)sense_buffer;
		asc = ext_sensep->es_add_code;
	}
	return (asc);
}

uint8_t
scsi_sense_ascq(uint8_t *sense_buffer)
{
	uint8_t ascq;
	if (SCSI_IS_DESCR_SENSE(sense_buffer)) {
		struct scsi_descr_sense_hdr *sdsp =
		    (struct scsi_descr_sense_hdr *)sense_buffer;
		ascq = sdsp->ds_qual_code;
	} else {
		struct scsi_extended_sense *ext_sensep =
		    (struct scsi_extended_sense *)sense_buffer;
		ascq = ext_sensep->es_qual_code;
	}
	return (ascq);
}

void scsi_ext_sense_fields(uint8_t *sense_buffer, int sense_buf_len,
    uint8_t **information, uint8_t **cmd_spec_info, uint8_t **fru_code,
    uint8_t **sk_specific, uint8_t **stream_flags)
{
	int sense_fmt;

	/*
	 * Sanity check sense data and determine the format
	 */
	sense_fmt = scsi_validate_sense(sense_buffer, sense_buf_len, NULL);

	/*
	 * Initialize any requested data to 0
	 */
	if (information) {
		*information = NULL;
	}
	if (cmd_spec_info) {
		*cmd_spec_info = NULL;
	}
	if (fru_code) {
		*fru_code = NULL;
	}
	if (sk_specific) {
		*sk_specific = NULL;
	}
	if (stream_flags) {
		*stream_flags = NULL;
	}

	if (sense_fmt == SENSE_DESCR_FORMAT) {
		struct scsi_descr_template *sdt = NULL;

		while (scsi_get_next_descr(sense_buffer,
		    sense_buf_len, &sdt) != -1) {
			switch (sdt->sdt_descr_type) {
			case DESCR_INFORMATION: {
				struct scsi_information_sense_descr *isd =
				    (struct scsi_information_sense_descr *)
				    sdt;
				if (information) {
					*information =
					    &isd->isd_information[0];
				}
				break;
			}
			case DESCR_COMMAND_SPECIFIC: {
				struct scsi_cmd_specific_sense_descr *csd =
				    (struct scsi_cmd_specific_sense_descr *)
				    sdt;
				if (cmd_spec_info) {
					*cmd_spec_info =
					    &csd->css_cmd_specific_info[0];
				}
				break;
			}
			case DESCR_SENSE_KEY_SPECIFIC: {
				struct scsi_sk_specific_sense_descr *ssd =
				    (struct scsi_sk_specific_sense_descr *)
				    sdt;
				if (sk_specific) {
					*sk_specific =
					    (uint8_t *)&ssd->sss_data;
				}
				break;
			}
			case DESCR_FRU: {
				struct scsi_fru_sense_descr *fsd =
				    (struct scsi_fru_sense_descr *)
				    sdt;
				if (fru_code) {
					*fru_code = &fsd->fs_fru_code;
				}
				break;
			}
			case DESCR_STREAM_COMMANDS: {
				struct scsi_stream_cmd_sense_descr *strsd =
				    (struct scsi_stream_cmd_sense_descr *)
				    sdt;
				if (stream_flags) {
					*stream_flags =
					    (uint8_t *)&strsd->scs_data;
				}
				break;
			}
			case DESCR_BLOCK_COMMANDS: {
				struct scsi_block_cmd_sense_descr *bsd =
				    (struct scsi_block_cmd_sense_descr *)
				    sdt;
				/*
				 * The "Block Command" sense descriptor
				 * contains an ili bit that we can store
				 * in the stream specific data if it is
				 * available.  We shouldn't see both
				 * a block command and a stream command
				 * descriptor in the same collection
				 * of sense data.
				 */
				if (stream_flags) {
					/*
					 * Can't take an address of a bitfield,
					 * but the flags are just after the
					 * bcs_reserved field.
					 */
					*stream_flags =
					    (uint8_t *)&bsd->bcs_reserved + 1;
				}
				break;
			}
			}
		}
	} else {
		struct scsi_extended_sense *es =
		    (struct scsi_extended_sense *)sense_buffer;

		/* Get data from fixed sense buffer */
		if (information && es->es_valid) {
			*information = &es->es_info_1;
		}
		if (cmd_spec_info && es->es_valid) {
			*cmd_spec_info = &es->es_cmd_info[0];
		}
		if (fru_code) {
			*fru_code = &es->es_fru_code;
		}
		if (sk_specific) {
			*sk_specific = &es->es_skey_specific[0];
		}
		if (stream_flags) {
			/*
			 * Can't take the address of a bit field,
			 * but the stream flags are located just after
			 * the es_segnum field;
			 */
			*stream_flags = &es->es_segnum + 1;
		}
	}
}

boolean_t
scsi_sense_info_uint64(uint8_t *sense_buffer, int sense_buf_len,
    uint64_t *information)
{
	boolean_t valid;
	int sense_fmt;

	ASSERT(sense_buffer != NULL);
	ASSERT(information != NULL);

	/* Validate sense data and get format */
	sense_fmt = scsi_validate_sense(sense_buffer, sense_buf_len, NULL);

	if (sense_fmt == SENSE_UNUSABLE) {
		/* Information is not valid */
		valid = 0;
	} else if (sense_fmt == SENSE_FIXED_FORMAT) {
		struct scsi_extended_sense *es =
		    (struct scsi_extended_sense *)sense_buffer;

		*information = (uint64_t)SCSI_READ32(&es->es_info_1);

		valid = es->es_valid;
	} else {
		/* Sense data is descriptor format */
		struct scsi_information_sense_descr *isd;

		isd = (struct scsi_information_sense_descr *)
		    scsi_find_sense_descr(sense_buffer, sense_buf_len,
		    DESCR_INFORMATION);

		if (isd) {
			*information = SCSI_READ64(isd->isd_information);
			valid = 1;
		} else {
			valid = 0;
		}
	}

	return (valid);
}

boolean_t
scsi_sense_cmdspecific_uint64(uint8_t *sense_buffer, int sense_buf_len,
    uint64_t *cmd_specific_info)
{
	boolean_t valid;
	int sense_fmt;

	ASSERT(sense_buffer != NULL);
	ASSERT(cmd_specific_info != NULL);

	/* Validate sense data and get format */
	sense_fmt = scsi_validate_sense(sense_buffer, sense_buf_len, NULL);

	if (sense_fmt == SENSE_UNUSABLE) {
		/* Command specific info is not valid */
		valid = 0;
	} else if (sense_fmt == SENSE_FIXED_FORMAT) {
		struct scsi_extended_sense *es =
		    (struct scsi_extended_sense *)sense_buffer;

		*cmd_specific_info = (uint64_t)SCSI_READ32(es->es_cmd_info);

		valid = es->es_valid;
	} else {
		/* Sense data is descriptor format */
		struct scsi_cmd_specific_sense_descr *c;

		c = (struct scsi_cmd_specific_sense_descr *)
		    scsi_find_sense_descr(sense_buffer, sense_buf_len,
		    DESCR_COMMAND_SPECIFIC);

		if (c) {
			valid = 1;
			*cmd_specific_info =
			    SCSI_READ64(c->css_cmd_specific_info);
		} else {
			valid = 0;
		}
	}

	return (valid);
}

uint8_t *
scsi_find_sense_descr(uint8_t *sdsp, int sense_buf_len, int req_descr_type)
{
	struct scsi_descr_template *sdt = NULL;

	while (scsi_get_next_descr(sdsp, sense_buf_len, &sdt) != -1) {
		ASSERT(sdt != NULL);
		if (sdt->sdt_descr_type == req_descr_type) {
			/* Found requested descriptor type */
			break;
		}
	}

	return ((uint8_t *)sdt);
}

/*
 * Sense Descriptor format is:
 *
 * <Descriptor type> <Descriptor length> <Descriptor data> ...
 *
 * 2 must be added to the descriptor length value to get the
 * total descriptor length sense the stored length does not
 * include the "type" and "additional length" fields.
 */

#define	NEXT_DESCR_PTR(ndp_descr) \
	((struct scsi_descr_template *)(((uint8_t *)(ndp_descr)) + \
	    ((ndp_descr)->sdt_addl_length + \
	    sizeof (struct scsi_descr_template))))

static int
scsi_get_next_descr(uint8_t *sense_buffer,
    int sense_buf_len, struct scsi_descr_template **descrpp)
{
	struct scsi_descr_sense_hdr *sdsp =
	    (struct scsi_descr_sense_hdr *)sense_buffer;
	struct scsi_descr_template *cur_descr;
	boolean_t find_first;
	int valid_sense_length;

	ASSERT(descrpp != NULL);
	find_first = (*descrpp == NULL);

	/*
	 * If no descriptor is passed in then return the first
	 * descriptor
	 */
	if (find_first) {
		/*
		 * The first descriptor will immediately follow the header
		 * (Pointer arithmetic)
		 */
		cur_descr = (struct scsi_descr_template *)(sdsp+1);
	} else {
		cur_descr = *descrpp;
		ASSERT(cur_descr > (struct scsi_descr_template *)sdsp);
	}

	/* Assume no more descriptors are available */
	*descrpp = NULL;

	/*
	 * Calculate the amount of valid sense data -- make sure the length
	 * byte in this descriptor lies within the valid sense data.
	 */
	valid_sense_length =
	    min((sizeof (struct scsi_descr_sense_hdr) +
	    sdsp->ds_addl_sense_length),
	    sense_buf_len);

	/*
	 * Make sure this descriptor is complete (either the first
	 * descriptor or the descriptor passed in)
	 */
	if (scsi_validate_descr(sdsp, valid_sense_length, cur_descr) !=
	    DESCR_GOOD) {
		return (-1);
	}

	/*
	 * If we were looking for the first descriptor go ahead and return it
	 */
	if (find_first) {
		*descrpp = cur_descr;
		return ((*descrpp)->sdt_descr_type);
	}

	/*
	 * Get pointer to next descriptor
	 */
	cur_descr = NEXT_DESCR_PTR(cur_descr);

	/*
	 * Make sure this descriptor is also complete.
	 */
	if (scsi_validate_descr(sdsp, valid_sense_length, cur_descr) !=
	    DESCR_GOOD) {
		return (-1);
	}

	*descrpp = (struct scsi_descr_template *)cur_descr;
	return ((*descrpp)->sdt_descr_type);
}

static int
scsi_validate_descr(struct scsi_descr_sense_hdr *sdsp,
    int valid_sense_length, struct scsi_descr_template *descrp)
{
	int descr_offset, next_descr_offset;

	/*
	 * Make sure length is present
	 */
	descr_offset = (uint8_t *)descrp - (uint8_t *)sdsp;
	if (descr_offset + sizeof (struct scsi_descr_template) >
	    valid_sense_length) {
		return (DESCR_PARTIAL);
	}

	/*
	 * Check if length is 0 (no more descriptors)
	 */
	if (descrp->sdt_addl_length == 0) {
		return (DESCR_END);
	}

	/*
	 * Make sure the rest of the descriptor is present
	 */
	next_descr_offset =
	    (uint8_t *)NEXT_DESCR_PTR(descrp) - (uint8_t *)sdsp;
	if (next_descr_offset > valid_sense_length) {
		return (DESCR_PARTIAL);
	}

	return (DESCR_GOOD);
}

/*
 * Internal data structure for handling uscsi command.
 */
typedef	struct	uscsi_i_cmd {
	struct uscsi_cmd	uic_cmd;
	caddr_t			uic_rqbuf;
	uchar_t			uic_rqlen;
	caddr_t			uic_cdb;
	int			uic_flag;
	struct scsi_address	*uic_ap;
} uscsi_i_cmd_t;

#if !defined(lint)
_NOTE(SCHEME_PROTECTS_DATA("unshared data", uscsi_i_cmd))
#endif

/*ARGSUSED*/
static void
scsi_uscsi_mincnt(struct buf *bp)
{
	/*
	 * Do not break up because the CDB count would then be
	 * incorrect and create spurious data underrun errors.
	 */
}

/*
 * Function: scsi_uscsi_alloc_and_copyin
 *
 * Description: Target drivers call this function to allocate memeory,
 *	copy in, and convert ILP32/LP64 to make preparations for handling
 *	uscsi commands.
 *
 * Arguments:
 *	arg	- pointer to the caller's uscsi command struct
 *	flag	- mode, corresponds to ioctl(9e) 'mode'
 *	ap	- SCSI address structure
 *	uscmdp	- pointer to the converted uscsi command
 *
 * Return code: 0
 *	EFAULT
 *	EINVAL
 *
 * Context: Never called at interrupt context.
 */

int
scsi_uscsi_alloc_and_copyin(intptr_t arg, int flag, struct scsi_address *ap,
    struct uscsi_cmd **uscmdp)
{
	int	rval = 0;
	struct uscsi_cmd *uscmd;

	/*
	 * In order to not worry about where the uscsi structure came
	 * from (or where the cdb it points to came from) we're going
	 * to make kmem_alloc'd copies of them here. This will also
	 * allow reference to the data they contain long after this
	 * process has gone to sleep and its kernel stack has been
	 * unmapped, etc. First get some memory for the uscsi_cmd
	 * struct and copy the contents of the given uscsi_cmd struct
	 * into it. We also save infos of the uscsi command by using
	 * uicmd to supply referrence for the copyout operation.
	 */
	uscmd = scsi_uscsi_alloc();

	if ((rval = scsi_uscsi_copyin(arg, flag, ap, &uscmd)) != 0) {
		scsi_uscsi_free(uscmd);
		*uscmdp = NULL;
		rval = EFAULT;
	} else {
		*uscmdp = uscmd;
	}

	return (rval);
}

struct uscsi_cmd *
scsi_uscsi_alloc()
{
	struct uscsi_i_cmd	*uicmd;

	uicmd = (struct uscsi_i_cmd *)
	    kmem_zalloc(sizeof (struct uscsi_i_cmd), KM_SLEEP);

	/*
	 * It is supposed that the uscsi_cmd has been alloced correctly,
	 * we need to check is it NULL or mis-created.
	 */
	ASSERT(uicmd && (offsetof(struct uscsi_i_cmd, uic_cmd) == 0));

	return (&uicmd->uic_cmd);
}

int
scsi_uscsi_copyin(intptr_t arg, int flag, struct scsi_address *ap,
    struct uscsi_cmd **uscmdp)
{
#ifdef _MULTI_DATAMODEL
	/*
	 * For use when a 32 bit app makes a call into a
	 * 64 bit ioctl
	 */
	struct uscsi_cmd32	uscsi_cmd_32_for_64;
	struct uscsi_cmd32	*ucmd32 = &uscsi_cmd_32_for_64;
#endif /* _MULTI_DATAMODEL */
	struct uscsi_cmd	*uscmd = *uscmdp;
	struct uscsi_i_cmd	*uicmd = (struct uscsi_i_cmd *)(uscmd);
	int			max_hba_cdb;
	int			rval;
	extern dev_info_t	*scsi_vhci_dip;

	ASSERT(uscmd != NULL);
	ASSERT(uicmd != NULL);

	/*
	 * To be able to issue multiple commands off a single uscmdp
	 * We need to free the original cdb, rqbuf and bzero the uscmdp
	 * if the cdb, rqbuf and uscmdp is not NULL
	 */
	if (uscmd->uscsi_rqbuf != NULL)
		kmem_free(uscmd->uscsi_rqbuf, uscmd->uscsi_rqlen);
	if (uscmd->uscsi_cdb != NULL)
		kmem_free(uscmd->uscsi_cdb, uscmd->uscsi_cdblen);
	bzero(uscmd, sizeof (struct uscsi_cmd));


#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)arg, ucmd32, sizeof (*ucmd32), flag)) {
			rval = EFAULT;
			goto scsi_uscsi_copyin_failed;
		}
		/*
		 * Convert the ILP32 uscsi data from the
		 * application to LP64 for internal use.
		 */
		uscsi_cmd32touscsi_cmd(ucmd32, uscmd);
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, uscmd, sizeof (*uscmd), flag)) {
			rval = EFAULT;
			goto scsi_uscsi_copyin_failed;
		}
		break;
	default:
		rval = EFAULT;
		goto scsi_uscsi_copyin_failed;
	}
#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, uscmd, sizeof (*uscmd), flag)) {
		rval = EFAULT;
		goto scsi_uscsi_copyin_failed;
	}
#endif /* _MULTI_DATAMODEL */

	/*
	 * We are going to allocate kernel virtual addresses for
	 * uscsi_rqbuf and uscsi_cdb pointers, so save off the
	 * original, possibly user virtual, uscsi_addresses
	 * in uic_fields
	 */
	uicmd->uic_rqbuf = uscmd->uscsi_rqbuf;
	uicmd->uic_rqlen = uscmd->uscsi_rqlen;
	uicmd->uic_cdb   = uscmd->uscsi_cdb;
	uicmd->uic_flag  = flag;
	uicmd->uic_ap    = ap;

	/*
	 * Skip the following steps if we meet RESET commands.
	 */
	if (uscmd->uscsi_flags &
	    (USCSI_RESET_LUN | USCSI_RESET_TARGET | USCSI_RESET_ALL)) {
		uscmd->uscsi_rqbuf = NULL;
		uscmd->uscsi_cdb = NULL;
		return (0);
	}

	/*
	 * Currently, USCSI_PATH_INSTANCE is only valid when directed
	 * to scsi_vhci.
	 */
	if ((uscmd->uscsi_flags & USCSI_PATH_INSTANCE) &&
	    (A_TO_TRAN(ap)->tran_hba_dip != scsi_vhci_dip)) {
		rval = EFAULT;
		goto scsi_uscsi_copyin_failed;
	}

	/*
	 * Perfunctory sanity checks. Get the maximum hba supported
	 * cdb length first.
	 */
	max_hba_cdb = scsi_ifgetcap(ap, "max-cdb-length", 1);
	if (max_hba_cdb < CDB_GROUP0) {
		max_hba_cdb = CDB_GROUP4;
	}
	if (uscmd->uscsi_cdblen < CDB_GROUP0 ||
	    uscmd->uscsi_cdblen > max_hba_cdb) {
		rval = EINVAL;
		goto scsi_uscsi_copyin_failed;
	}
	if ((uscmd->uscsi_flags & USCSI_RQENABLE) &&
	    (uscmd->uscsi_rqlen == 0 || uscmd->uscsi_rqbuf == NULL)) {
		rval = EINVAL;
		goto scsi_uscsi_copyin_failed;
	}

	/*
	 * To extend uscsi_cmd in the future, we need to ensure current
	 * reserved bits remain unused (zero).
	 */
	if (uscmd->uscsi_flags & USCSI_RESERVED) {
		rval = EINVAL;
		goto scsi_uscsi_copyin_failed;
	}

	/*
	 * Now we get some space for the CDB, and copy the given CDB into
	 * it. Use ddi_copyin() in case the data is in user space.
	 */
	uscmd->uscsi_cdb = kmem_zalloc((size_t)uscmd->uscsi_cdblen, KM_SLEEP);
	if (ddi_copyin(uicmd->uic_cdb, uscmd->uscsi_cdb,
	    (uint_t)uscmd->uscsi_cdblen, flag) != 0) {
		kmem_free(uscmd->uscsi_cdb, (size_t)uscmd->uscsi_cdblen);
		rval = EFAULT;
		goto scsi_uscsi_copyin_failed;
	}

	if (uscmd->uscsi_cdb[0] != SCMD_VAR_LEN) {
		if (uscmd->uscsi_cdblen > SCSI_CDB_SIZE ||
		    scsi_cdb_size[CDB_GROUPID(uscmd->uscsi_cdb[0])] >
		    uscmd->uscsi_cdblen) {
			kmem_free(uscmd->uscsi_cdb,
			    (size_t)uscmd->uscsi_cdblen);
			rval = EINVAL;
			goto scsi_uscsi_copyin_failed;
		}
	} else {
		if ((uscmd->uscsi_cdblen % 4) != 0) {
			kmem_free(uscmd->uscsi_cdb,
			    (size_t)uscmd->uscsi_cdblen);
			rval = EINVAL;
			goto scsi_uscsi_copyin_failed;
		}
	}

	/*
	 * Initialize Request Sense buffering, if requested.
	 */
	if (uscmd->uscsi_flags & USCSI_RQENABLE) {
		/*
		 * Here uscmd->uscsi_rqbuf currently points to the caller's
		 * buffer, but we replace this with a kernel buffer that
		 * we allocate to use with the sense data. The sense data
		 * (if present) gets copied into this new buffer before the
		 * command is completed.  Then we copy the sense data from
		 * our allocated buf into the caller's buffer below. Note
		 * that uscmd->uscsi_rqbuf and uscmd->uscsi_rqlen are used
		 * below to perform the copy back to the caller's buf.
		 */
		if (uicmd->uic_rqlen <= SENSE_LENGTH) {
			uscmd->uscsi_rqlen = SENSE_LENGTH;
			uscmd->uscsi_rqbuf = kmem_zalloc(SENSE_LENGTH,
			    KM_SLEEP);
		} else {
			uscmd->uscsi_rqlen = MAX_SENSE_LENGTH;
			uscmd->uscsi_rqbuf = kmem_zalloc(MAX_SENSE_LENGTH,
			    KM_SLEEP);
		}
		uscmd->uscsi_rqresid = uscmd->uscsi_rqlen;
	} else {
		uscmd->uscsi_rqbuf = NULL;
		uscmd->uscsi_rqlen = 0;
		uscmd->uscsi_rqresid = 0;
	}
	return (0);

scsi_uscsi_copyin_failed:
	/*
	 * The uscsi_rqbuf and uscsi_cdb is refering to user-land
	 * address now, no need to free them.
	 */
	uscmd->uscsi_rqbuf = NULL;
	uscmd->uscsi_cdb = NULL;

	return (rval);
}

/*
 * Function: scsi_uscsi_handle_cmd
 *
 * Description: Target drivers call this function to handle uscsi commands.
 *
 * Arguments:
 *	dev		- device number
 *	dataspace	- UIO_USERSPACE or UIO_SYSSPACE
 *	uscmd		- pointer to the converted uscsi command
 *	strat		- pointer to the driver's strategy routine
 *	bp		- buf struct ptr
 *	private_data	- pointer to bp->b_private
 *
 * Return code: 0
 *    EIO	- scsi_reset() failed, or see biowait()/physio() codes.
 *    EINVAL
 *    return code of biowait(9F) or physio(9F):
 *      EIO	- IO error
 *      ENXIO
 *      EACCES	- reservation conflict
 *
 * Context: Never called at interrupt context.
 */

int
scsi_uscsi_handle_cmd(dev_t dev, enum uio_seg dataspace,
    struct uscsi_cmd *uscmd, int (*strat)(struct buf *),
    struct buf *bp, void *private_data)
{
	struct uscsi_i_cmd	*uicmd = (struct uscsi_i_cmd *)uscmd;
	int	bp_alloc_flag = 0;
	int	rval;

	/*
	 * Perform resets directly; no need to generate a command to do it.
	 */
	if (uscmd->uscsi_flags &
	    (USCSI_RESET_LUN | USCSI_RESET_TARGET | USCSI_RESET_ALL)) {
		int flags = (uscmd->uscsi_flags & USCSI_RESET_ALL) ?
		    RESET_ALL : ((uscmd->uscsi_flags & USCSI_RESET_TARGET) ?
		    RESET_TARGET : RESET_LUN);
		if (scsi_reset(uicmd->uic_ap, flags) == 0) {
			/* Reset attempt was unsuccessful */
			return (EIO);
		}
		return (0);
	}

	/*
	 * Force asynchronous mode, if necessary.  Doing this here
	 * has the unfortunate effect of running other queued
	 * commands async also, but since the main purpose of this
	 * capability is downloading new drive firmware, we can
	 * probably live with it.
	 */
	if (uscmd->uscsi_flags & USCSI_ASYNC) {
		if (scsi_ifgetcap(uicmd->uic_ap, "synchronous", 1) == 1) {
			if (scsi_ifsetcap(uicmd->uic_ap, "synchronous",
			    0, 1) != 1) {
				return (EINVAL);
			}
		}
	}

	/*
	 * Re-enable synchronous mode, if requested.
	 */
	if (uscmd->uscsi_flags & USCSI_SYNC) {
		if (scsi_ifgetcap(uicmd->uic_ap, "synchronous", 1) == 0) {
			rval = scsi_ifsetcap(uicmd->uic_ap, "synchronous",
			    1, 1);
		}
	}

	/*
	 * If bp is NULL, allocate space here.
	 */
	if (bp == NULL) {
		bp = getrbuf(KM_SLEEP);
		bp->b_private = private_data;
		bp_alloc_flag = 1;
	}

	/*
	 * If we're going to do actual I/O, let physio do all the right things.
	 */
	if (uscmd->uscsi_buflen != 0) {
		struct iovec	aiov;
		struct uio	auio;
		struct uio	*uio = &auio;

		bzero(&auio, sizeof (struct uio));
		bzero(&aiov, sizeof (struct iovec));
		aiov.iov_base = uscmd->uscsi_bufaddr;
		aiov.iov_len  = uscmd->uscsi_buflen;
		uio->uio_iov  = &aiov;

		uio->uio_iovcnt  = 1;
		uio->uio_resid   = uscmd->uscsi_buflen;
		uio->uio_segflg  = dataspace;

		/*
		 * physio() will block here until the command completes....
		 */
		rval = physio(strat, bp, dev,
		    ((uscmd->uscsi_flags & USCSI_READ) ? B_READ : B_WRITE),
		    scsi_uscsi_mincnt, uio);
	} else {
		/*
		 * We have to mimic that physio would do here! Argh!
		 */
		bp->b_flags  = B_BUSY |
		    ((uscmd->uscsi_flags & USCSI_READ) ? B_READ : B_WRITE);
		bp->b_edev   = dev;
		bp->b_dev    = cmpdev(dev);	/* maybe unnecessary? */
		bp->b_bcount = 0;
		bp->b_blkno  = 0;
		bp->b_resid  = 0;

		(void) (*strat)(bp);
		rval = biowait(bp);
	}
	uscmd->uscsi_resid = bp->b_resid;

	if (bp_alloc_flag == 1) {
		bp_mapout(bp);
		freerbuf(bp);
	}

	return (rval);
}

/*
 * Function: scsi_uscsi_pktinit
 *
 * Description: Target drivers call this function to transfer uscsi_cmd
 *	information into a scsi_pkt before sending the scsi_pkt.
 *
 *	NB: At this point the implementation is limited to path_instance.
 *	At some point more code could be removed from the target driver by
 *	enhancing this function - with the added benifit of making the uscsi
 *	implementation more consistent accross all drivers.
 *
 * Arguments:
 *    uscmd     - pointer to the uscsi command
 *    pkt	- pointer to the scsi_pkt
 *
 * Return code: 1 on successfull transfer, 0 on failure.
 */
int
scsi_uscsi_pktinit(struct uscsi_cmd *uscmd, struct scsi_pkt *pkt)
{

	/*
	 * Check if the NACA flag is set. If one initiator sets it
	 * but does not clear it, other initiators would end up
	 * waiting indefinitely for the first to clear NACA. If the
	 * the system allows NACA to be set, then warn the user but
	 * still pass the command down, otherwise, clear the flag.
	 */
	if (uscmd->uscsi_cdb[uscmd->uscsi_cdblen - 1] & CDB_FLAG_NACA) {
		if (scsi_pkt_allow_naca) {
			cmn_err(CE_WARN, "scsi_uscsi_pktinit: "
			    "NACA flag is set");
		} else {
			uscmd->uscsi_cdb[uscmd->uscsi_cdblen - 1] &=
			    ~CDB_FLAG_NACA;
			cmn_err(CE_WARN, "scsi_uscsi_pktinit: "
			    "NACA flag is cleared");
		}
	}

	/*
	 * See if path_instance was requested in uscsi_cmd.
	 */
	if ((uscmd->uscsi_flags & USCSI_PATH_INSTANCE) &&
	    (uscmd->uscsi_path_instance != 0)) {
		/*
		 * Check to make sure the scsi_pkt was allocated correctly
		 * before transferring uscsi(7i) path_instance to scsi_pkt(9S).
		 */
		if (scsi_pkt_allocated_correctly(pkt)) {
			/* set pkt_path_instance and flag. */
			pkt->pkt_flags |= FLAG_PKT_PATH_INSTANCE;
			pkt->pkt_path_instance = uscmd->uscsi_path_instance;
		} else {
			return (0);	/* failure */
		}
	} else {
		/*
		 * Can only use pkt_path_instance if the packet
		 * was correctly allocated.
		 */
		if (scsi_pkt_allocated_correctly(pkt)) {
			pkt->pkt_path_instance = 0;
		}
		pkt->pkt_flags &= ~FLAG_PKT_PATH_INSTANCE;
	}

	return (1);			/* success */
}

/*
 * Function: scsi_uscsi_pktfini
 *
 * Description: Target drivers call this function to transfer completed
 * 	scsi_pkt information back into uscsi_cmd.
 *
 *	NB: At this point the implementation is limited to path_instance.
 *	At some point more code could be removed from the target driver by
 *	enhancing this function - with the added benifit of making the uscsi
 *	implementation more consistent accross all drivers.
 *
 * Arguments:
 *    pkt	- pointer to the scsi_pkt
 *    uscmd     - pointer to the uscsi command
 *
 * Return code: 1 on successfull transfer, 0 on failure.
 */
int
scsi_uscsi_pktfini(struct scsi_pkt *pkt, struct uscsi_cmd *uscmd)
{
	/*
	 * Check to make sure the scsi_pkt was allocated correctly before
	 * transferring scsi_pkt(9S) path_instance to uscsi(7i).
	 */
	if (!scsi_pkt_allocated_correctly(pkt)) {
		uscmd->uscsi_path_instance = 0;
		return (0);		/* failure */
	}

	uscmd->uscsi_path_instance = pkt->pkt_path_instance;
	/* reset path_instance */
	pkt->pkt_flags &= ~FLAG_PKT_PATH_INSTANCE;
	pkt->pkt_path_instance = 0;
	return (1);			/* success */
}

/*
 *    Function: scsi_uscsi_copyout_and_free
 *
 * Description: Target drivers call this function to undo what was done by
 *    scsi_uscsi_alloc_and_copyin.
 *
 *   Arguments: arg - pointer to the uscsi command to be returned
 *    uscmd     - pointer to the converted uscsi command
 *
 * Return code: 0
 *    EFAULT
 *
 *     Context: Never called at interrupt context.
 */
int
scsi_uscsi_copyout_and_free(intptr_t arg, struct uscsi_cmd *uscmd)
{
	int	rval = 0;

	rval = scsi_uscsi_copyout(arg, uscmd);

	scsi_uscsi_free(uscmd);

	return (rval);
}

int
scsi_uscsi_copyout(intptr_t arg, struct uscsi_cmd *uscmd)
{
#ifdef _MULTI_DATAMODEL
	/*
	 * For use when a 32 bit app makes a call into a
	 * 64 bit ioctl.
	 */
	struct uscsi_cmd32	uscsi_cmd_32_for_64;
	struct uscsi_cmd32	*ucmd32 = &uscsi_cmd_32_for_64;
#endif /* _MULTI_DATAMODEL */
	struct uscsi_i_cmd	*uicmd = (struct uscsi_i_cmd *)uscmd;
	caddr_t	k_rqbuf;
	int	k_rqlen;
	caddr_t	k_cdb;
	int	rval = 0;

	/*
	 * If the caller wants sense data, copy back whatever sense data
	 * we may have gotten, and update the relevant rqsense info.
	 */
	if ((uscmd->uscsi_flags & USCSI_RQENABLE) &&
	    (uscmd->uscsi_rqbuf != NULL)) {
		int rqlen = uscmd->uscsi_rqlen - uscmd->uscsi_rqresid;
		rqlen = min(((int)uicmd->uic_rqlen), rqlen);
		uscmd->uscsi_rqresid = uicmd->uic_rqlen - rqlen;
		/*
		 * Copy out the sense data for user process.
		 */
		if ((uicmd->uic_rqbuf != NULL) && (rqlen != 0)) {
			if (ddi_copyout(uscmd->uscsi_rqbuf,
			    uicmd->uic_rqbuf, rqlen, uicmd->uic_flag) != 0) {
				rval = EFAULT;
			}
		}
	}

	/*
	 * Restore original uscsi_values, saved in uic_fields for
	 * copyout (so caller does not experience a change in these
	 * fields)
	 */
	k_rqbuf = uscmd->uscsi_rqbuf;
	k_rqlen = uscmd->uscsi_rqlen;
	k_cdb   = uscmd->uscsi_cdb;
	uscmd->uscsi_rqbuf = uicmd->uic_rqbuf;
	uscmd->uscsi_rqlen = uicmd->uic_rqlen;
	uscmd->uscsi_cdb   = uicmd->uic_cdb;

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(uicmd->uic_flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		/*
		 * Convert back to ILP32 before copyout to the
		 * application
		 */
		uscsi_cmdtouscsi_cmd32(uscmd, ucmd32);
		if (ddi_copyout(ucmd32, (void *)arg, sizeof (*ucmd32),
		    uicmd->uic_flag)) {
			rval = EFAULT;
		}
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyout(uscmd, (void *)arg, sizeof (*uscmd),
		    uicmd->uic_flag)) {
			rval = EFAULT;
		}
		break;
	default:
		rval = EFAULT;
	}
#else /* _MULTI_DATAMODE */
	if (ddi_copyout(uscmd, (void *)arg, sizeof (*uscmd), uicmd->uic_flag)) {
		rval = EFAULT;
	}
#endif /* _MULTI_DATAMODE */

	/*
	 * Copyout done, restore kernel virtual addresses for further
	 * scsi_uscsi_free().
	 */
	uscmd->uscsi_rqbuf = k_rqbuf;
	uscmd->uscsi_rqlen = k_rqlen;
	uscmd->uscsi_cdb = k_cdb;

	return (rval);
}

void
scsi_uscsi_free(struct uscsi_cmd *uscmd)
{
	struct uscsi_i_cmd	*uicmd = (struct uscsi_i_cmd *)uscmd;

	ASSERT(uicmd != NULL);

	if ((uscmd->uscsi_rqbuf != NULL) && (uscmd->uscsi_rqlen != 0)) {
		kmem_free(uscmd->uscsi_rqbuf, (size_t)uscmd->uscsi_rqlen);
		uscmd->uscsi_rqbuf = NULL;
	}

	if ((uscmd->uscsi_cdb != NULL) && (uscmd->uscsi_cdblen != 0)) {
		kmem_free(uscmd->uscsi_cdb, (size_t)uscmd->uscsi_cdblen);
		uscmd->uscsi_cdb = NULL;
	}

	kmem_free(uicmd, sizeof (struct uscsi_i_cmd));
}
