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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * t1394_errmsg.c
 *    Utility function that targets can use to convert an error code into a
 *    printable string.
 */

#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/cmd1394.h>
#include <sys/1394/ixl1394.h>

static const char *error_string[] = {
	"CMD1394_CMDSUCCESS:  Command Success",			/* 0 */
	"",							/* -1 */
	"",							/* -2 */
	"",							/* -3 */
	"",							/* -4 */
	"",							/* -5 */
	"",							/* -6 */
	"",							/* -7 */
	"",							/* -8 */
	"",							/* -9 */
	"CMD1394_ENULL_MBLK:  NULL mblk pointer",		/* -10 */
	"CMD1394_EMBLK_TOO_SMALL:  Mblk too small",		/* -11 */
	"CMD1394_ESTALE_GENERATION:  Stale generation",		/* -12 */
	"CMD1394_EDEVICE_REMOVED:  Device removed",		/* -13 */
	"CMD1394_EINVALID_CONTEXT:  Invalid context",		/* -14 */
	"CMD1394_EINVALID_COMMAND:  Invalid command",		/* -15 */
	"CMD1394_EUNKNOWN_ERROR:  Unknown error",		/* -16 */
	"CMD1394_NOSTATUS:  No status",				/* -17 */
	"CMD1394_EFATAL_ERROR:  Fatal error",			/* -18 */
	"CMD1394_ENO_ATREQ:  Unable to send ATREQ",		/* -19 */
	"CMD1394_EDEVICE_ERROR:  Device error",			/* -20 */
	"",							/* -21 */
	"",							/* -22 */
	"",							/* -23 */
	"",							/* -24 */
	"",							/* -25 */
	"",							/* -26 */
	"",							/* -27 */
	"",							/* -28 */
	"",							/* -29 */
	"CMD1394_EDEVICE_BUSY:  Device busy",			/* -30 */
	"CMD1394_ERETRIES_EXCEEDED:  Too many retries",		/* -31 */
	"CMD1394_ETYPE_ERROR:  Resp/ack type error",		/* -32 */
	"CMD1394_EDATA_ERROR:  Resp/ack data error",		/* -33 */
	"CMD1394_EBUSRESET:  Bus reset",			/* -34 */
	"CMD1394_EADDRESS_ERROR:  Address error",		/* -35 */
	"CMD1394_ETIMEOUT:  Command timed out",			/* -36 */
	"CMD1394_ERSRC_CONFLICT:  Resource conflict"		/* -37 */
};

static const char *ixl_compilation_error_string[] = {
	"IXL1394_EMEM_ALLOC_FAIL:  Memory allocation failed",	/* -301 */
	"IXL1394_EBAD_IXL_OPCODE:  Bad opcode",			/* -302 */
	"IXL1394_EFRAGMENT_OFLO:  Descriptor block overflow",	/* -303 */
	"IXL1394_ENO_DATA_PKTS:  No descriptor blocks",		/* -304 */
	"IXL1394_EMISPLACED_RECV:  Misplaced receive",		/* -305 */
	"IXL1394_EMISPLACED_SEND:  Misplaced send",		/* -306 */
	"IXL1394_EPKT_HDR_MISSING:  Packet header missing",	/* -307 */
	"IXL1394_ENULL_BUFFER_ADDR:  NULL buffer address",	/* -308 */
	"IXL1394_EPKTSIZE_MAX_OFLO:  Packet > 0xFFFF bytes",	/* -309 */
	"IXL1394_EPKTSIZE_RATIO:  Improper packet length/count", /* -310 */
	"IXL1394_EUNAPPLIED_SET_CMD:  Unused set command",	/* -311 */
	"IXL1394_EDUPLICATE_SET_CMD:  Multiple set commands",	/* -312 */
	"IXL1394_EJUMP_NOT_TO_LABEL:  Jump destination not a label", /* -313 */
	"IXL1394_EUPDATE_DISALLOWED:  Update not allowed ",	/* -314 */
	"IXL1394_EBAD_SKIPMODE:  Invalid skip mode",		/* -315 */
	"IXL1394_EWRONG_XR_CMD_MODE:  Inapproriate xmit/recv mode", /* -316 */
	"IXL1394_EINTERNAL_ERROR:  Internal error",		/* -317 */
	"IXL1394_ENOT_IMPLEMENTED:  Unimplemented error",	/* -318 */
	"IXL1394_EOPCODE_MISMATCH:  Opcode mismatch",		/* -319 */
	"IXL1394_EOPCODE_DISALLOWED:  Opcode disallowed for update", /* -320 */
	"IXL1394_EBAD_SKIP_LABEL:  Skip label destination not a label",
	"IXL1394_EXFER_BUF_MISSING:  Missing buffer in transfer command",
	"IXL1394_EXFER_BUF_CNT_DIFF:  Packet count differs in new buffer",
	"IXL1394_EORIG_IXL_CORRUPTED:  Original IXL program corrupted",
	"IXL1394_ECOUNT_MISMATCH:  IXL command count difference", /* -325 */
	"IXL1394_EPRE_UPD_DMALOST:  DMA path lost before update", /* -326 */
	"IXL1394_EPOST_UPD_DMALOST:  DMA path lost after update", /* -327 */
	"IXL1394_ERISK_PROHIBITS_UPD:  Risk prohibits update"	/* -328 */
};

static const char *addr_error_string[] = {
	"T1394_EALLOC_ADDR:  Unable to alloc 1394 address block", /* -400 */
};

static const char *cec_error_string[] = {
	"T1394_ENO_BANDWIDTH:  Bandwidth allocation failed",	/* -500	*/
	"T1394_ENO_CHANNEL:  Channel allocation failed",	/* -501	*/
	"T1394_ETARGET:  One or more callbacks failed in isoch setup" /* -502 */
};

static const char *idma_error_string[] = {
	"T1394_EIDMA_NO_RESRCS:  No DMA resources",		/* -600 */
	"T1394_EIDMA_CONFLICT:  Conflicting arguments"		/* -601 */
};

static const char *cfgrom_error_string[] = {
	"T1394_ECFGROM_FULL:  Config ROM is full",		/* -700	*/
	"T1394_EINVALID_PARAM:  Invalid parameter in call",	/* -701	*/
	"T1394_EINVALID_CONTEXT:  Invalid context for call",	/* -702 */
	"T1394_NOERROR:  No error"				/* -703 */
};

#define	T1394_ERRMSG_EMPTY_STRING		""

/*
 * Function:    t1394_errmsg()
 * Input(s):    result			Result code
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	const string; empty string if invalid result code is passed in
 *
 * Description:	t1394_errmsg() returns a string corresponding the error code
 */
/* ARGSUSED */
const char *
t1394_errmsg(int result, uint_t flags)
{
	int err;
	const char *msg = T1394_ERRMSG_EMPTY_STRING;

	if (result > 0) {
		return (T1394_ERRMSG_EMPTY_STRING);
	}

	result = -result;

	if ((result >= -CMD1394_ERR_FIRST) && (result <= -CMD1394_ERR_LAST)) {
		err = result - (-CMD1394_ERR_FIRST);
		msg = error_string[err];
	} else if ((result >= -IXL1394_COMP_ERR_FIRST) &&
	    (result <= -IXL1394_COMP_ERR_LAST)) {
		err = result - (-IXL1394_COMP_ERR_FIRST);
		msg = ixl_compilation_error_string[err];
	} else if ((result >= -T1394_EADDR_FIRST) &&
	    (result <= -T1394_EADDR_LAST)) {
		err = result - (-T1394_EADDR_FIRST);
		msg = addr_error_string[err];
	} else if ((result >= -T1394_CEC_ERR_FIRST) &&
	    (result <= -T1394_CEC_ERR_LAST)) {
		err = result - (-T1394_CEC_ERR_FIRST);
		msg = cec_error_string[err];
	} else if ((result >= -T1394_IDMA_ERR_FIRST) &&
	    (result <= -T1394_IDMA_ERR_LAST)) {
		err = result - (-T1394_IDMA_ERR_FIRST);
		msg = idma_error_string[err];
	} else if ((result >= -T1394_ECFG_FIRST) &&
	    (result <= -T1394_ECFG_LAST)) {
		err = result - (-T1394_ECFG_FIRST);
		msg = cfgrom_error_string[err];
	}

	return (msg);
}
