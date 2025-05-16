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
 * Copyright (c) 2019, Joyent, Inc.
 */

/*
 * This file contains routines for sending and receiving SCSI commands.  The
 * higher level logic is contained in ds_scsi.c.
 */

#include <assert.h>
#include <sys/types.h>
#include <sys/param.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <utility.h>
#include <unistd.h>
#include <stropts.h>
#include <alloca.h>

#include "ds_scsi.h"
#include "ds_scsi_uscsi.h"

#define	MSGBUFLEN 64
#define	USCSI_DEFAULT_TIMEOUT	45
#define	USCSI_TIMEOUT_MAX	INT_MAX

static diskaddr_t scsi_extract_sense_info_descr(
    struct scsi_descr_sense_hdr *sdsp, int rqlen);
static void scsi_print_extended_sense(struct scsi_extended_sense *rq,
    int rqlen);
static void scsi_print_descr_sense(struct scsi_descr_sense_hdr *rq, int rqlen);

typedef struct slist {
	char	*str;
	int	value;
} slist_t;

static char *
find_string(slist_t *slist, int match_value)
{
	for (; slist->str != NULL; slist++) {
		if (slist->value == match_value) {
			return (slist->str);
		}
	}

	return ((char *)NULL);
}

/*
 * Strings for printing mode sense page control values
 */
static slist_t page_control_strings[] = {
	{ "current",	PC_CURRENT },
	{ "changeable",	PC_CHANGEABLE },
	{ "default",	PC_DEFAULT },
	{ "saved",	PC_SAVED },
	{ NULL,		0 }
};

/*
 * Strings for printing the mode select options
 */
static slist_t mode_select_strings[] = {
	{ "",		0 },
	{ "(pf)",	MODE_SELECT_PF },
	{ "(sp)",	MODE_SELECT_SP },
	{ "(pf,sp)",	MODE_SELECT_PF|MODE_SELECT_SP },
	{ NULL,		0 }
};

static slist_t sensekey_strings[] = {
	{ "No sense error",	KEY_NO_SENSE		},
	{ "Recoverable error",	KEY_RECOVERABLE_ERROR	},
	{ "Not ready error",	KEY_NOT_READY		},
	{ "Medium error",	KEY_MEDIUM_ERROR	},
	{ "Hardware error",	KEY_HARDWARE_ERROR	},
	{ "Illegal request",	KEY_ILLEGAL_REQUEST	},
	{ "Unit attention error", KEY_UNIT_ATTENTION	},
	{ "Write protect error", KEY_WRITE_PROTECT	},
	{ "Blank check error",	KEY_BLANK_CHECK		},
	{ "Vendor unique error", KEY_VENDOR_UNIQUE	},
	{ "Copy aborted error",	KEY_COPY_ABORTED	},
	{ "Aborted command",	KEY_ABORTED_COMMAND	},
	{ "Equal error",	KEY_EQUAL		},
	{ "Volume overflow",	KEY_VOLUME_OVERFLOW	},
	{ "Miscompare error",	KEY_MISCOMPARE		},
	{ "Reserved error",	KEY_RESERVED		},
	{ NULL,			0			}
};

static slist_t scsi_cmdname_strings[] = {
	{ "mode select",	SCMD_MODE_SELECT	},
	{ "mode sense",		SCMD_MODE_SENSE		},
	{ "mode select(10)",	SCMD_MODE_SELECT_G1	},
	{ "mode sense(10)",	SCMD_MODE_SENSE_G1	},
	{ "log sense",		SCMD_LOG_SENSE_G1	},
	{ "request sense",	SCMD_REQUEST_SENSE	},
	{ NULL,			0			}
};

static struct _scsi_asq_key_strings {
	uint_t asc;
	uint_t ascq;
	const char *message;
} extended_sense_list[] = {
	{ 0x00, 0x00, "no additional sense info" },
	{ 0x00, 0x01, "filemark detected" },
	{ 0x00, 0x02, "end of partition/medium detected" },
	{ 0x00, 0x03, "setmark detected" },
	{ 0x00, 0x04, "begining of partition/medium detected" },
	{ 0x00, 0x05, "end of data detected" },
	{ 0x00, 0x06, "i/o process terminated" },
	{ 0x00, 0x11, "audio play operation in progress" },
	{ 0x00, 0x12, "audio play operation paused" },
	{ 0x00, 0x13, "audio play operation successfully completed" },
	{ 0x00, 0x14, "audio play operation stopped due to error" },
	{ 0x00, 0x15, "no current audio status to return" },
	{ 0x00, 0x16, "operation in progress" },
	{ 0x00, 0x17, "cleaning requested" },
	{ 0x00, 0x18, "erase operation in progress" },
	{ 0x00, 0x19, "locate operation in progress" },
	{ 0x00, 0x1A, "rewind operation in progress" },
	{ 0x00, 0x1B, "set capacity operation in progress" },
	{ 0x00, 0x1C, "verify operation in progress" },
	{ 0x01, 0x00, "no index/sector signal" },
	{ 0x02, 0x00, "no seek complete" },
	{ 0x03, 0x00, "peripheral device write fault" },
	{ 0x03, 0x01, "no write current" },
	{ 0x03, 0x02, "excessive write errors" },
	{ 0x04, 0x00, "LUN not ready" },
	{ 0x04, 0x01, "LUN is becoming ready" },
	{ 0x04, 0x02, "LUN initializing command required" },
	{ 0x04, 0x03, "LUN not ready intervention required" },
	{ 0x04, 0x04, "LUN not ready format in progress" },
	{ 0x04, 0x05, "LUN not ready, rebuild in progress" },
	{ 0x04, 0x06, "LUN not ready, recalculation in progress" },
	{ 0x04, 0x07, "LUN not ready, operation in progress" },
	{ 0x04, 0x08, "LUN not ready, long write in progress" },
	{ 0x04, 0x09, "LUN not ready, self-test in progress" },
	{ 0x04, 0x0A, "LUN not accessible, asymmetric access state "
		"transition" },
	{ 0x04, 0x0B, "LUN not accessible, target port in standby state" },
	{ 0x04, 0x0C, "LUN not accessible, target port in unavailable state" },
	{ 0x04, 0x10, "LUN not ready, auxiliary memory not accessible" },
	{ 0x05, 0x00, "LUN does not respond to selection" },
	{ 0x06, 0x00, "reference position found" },
	{ 0x07, 0x00, "multiple peripheral devices selected" },
	{ 0x08, 0x00, "LUN communication failure" },
	{ 0x08, 0x01, "LUN communication time-out" },
	{ 0x08, 0x02, "LUN communication parity error" },
	{ 0x08, 0x03, "LUN communication crc error (ultra-DMA/32)" },
	{ 0x08, 0x04, "unreachable copy target" },
	{ 0x09, 0x00, "track following error" },
	{ 0x09, 0x01, "tracking servo failure" },
	{ 0x09, 0x02, "focus servo failure" },
	{ 0x09, 0x03, "spindle servo failure" },
	{ 0x09, 0x04, "head select fault" },
	{ 0x0a, 0x00, "error log overflow" },
	{ 0x0b, 0x00, "warning" },
	{ 0x0b, 0x01, "warning - specified temperature exceeded" },
	{ 0x0b, 0x02, "warning - enclosure degraded" },
	{ 0x0c, 0x00, "write error" },
	{ 0x0c, 0x01, "write error - recovered with auto reallocation" },
	{ 0x0c, 0x02, "write error - auto reallocation failed" },
	{ 0x0c, 0x03, "write error - recommend reassignment" },
	{ 0x0c, 0x04, "compression check miscompare error" },
	{ 0x0c, 0x05, "data expansion occurred during compression" },
	{ 0x0c, 0x06, "block not compressible" },
	{ 0x0c, 0x07, "write error - recovery needed" },
	{ 0x0c, 0x08, "write error - recovery failed" },
	{ 0x0c, 0x09, "write error - loss of streaming" },
	{ 0x0c, 0x0a, "write error - padding blocks added" },
	{ 0x0c, 0x0b, "auxiliary memory write error" },
	{ 0x0c, 0x0c, "write error - unexpected unsolicited data" },
	{ 0x0c, 0x0d, "write error - not enough unsolicited data" },
	{ 0x0d, 0x00, "error detected by third party temporary initiator" },
	{ 0x0d, 0x01, "third party device failure" },
	{ 0x0d, 0x02, "copy target device not reachable" },
	{ 0x0d, 0x03, "incorrect copy target device type" },
	{ 0x0d, 0x04, "copy target device data underrun" },
	{ 0x0d, 0x05, "copy target device data overrun" },
	{ 0x0e, 0x00, "invalid information unit" },
	{ 0x0e, 0x01, "information unit too short" },
	{ 0x0e, 0x02, "information unit too long" },
	{ 0x10, 0x00, "ID CRC or ECC error" },
	{ 0x11, 0x00, "unrecovered read error" },
	{ 0x11, 0x01, "read retries exhausted" },
	{ 0x11, 0x02, "error too long to correct" },
	{ 0x11, 0x03, "multiple read errors" },
	{ 0x11, 0x04, "unrecovered read error - auto reallocate failed" },
	{ 0x11, 0x05, "L-EC uncorrectable error" },
	{ 0x11, 0x06, "CIRC unrecovered error" },
	{ 0x11, 0x07, "data re-synchronization error" },
	{ 0x11, 0x08, "incomplete block read" },
	{ 0x11, 0x09, "no gap found" },
	{ 0x11, 0x0a, "miscorrected error" },
	{ 0x11, 0x0b, "unrecovered read error - recommend reassignment" },
	{ 0x11, 0x0c, "unrecovered read error - recommend rewrite the data" },
	{ 0x11, 0x0d, "de-compression crc error" },
	{ 0x11, 0x0e, "cannot decompress using declared algorithm" },
	{ 0x11, 0x0f, "error reading UPC/EAN number" },
	{ 0x11, 0x10, "error reading ISRC number" },
	{ 0x11, 0x11, "read error - loss of streaming" },
	{ 0x11, 0x12, "auxiliary memory read error" },
	{ 0x11, 0x13, "read error - failed retransmission request" },
	{ 0x12, 0x00, "address mark not found for ID field" },
	{ 0x13, 0x00, "address mark not found for data field" },
	{ 0x14, 0x00, "recorded entity not found" },
	{ 0x14, 0x01, "record not found" },
	{ 0x14, 0x02, "filemark or setmark not found" },
	{ 0x14, 0x03, "end-of-data not found" },
	{ 0x14, 0x04, "block sequence error" },
	{ 0x14, 0x05, "record not found - recommend reassignment" },
	{ 0x14, 0x06, "record not found - data auto-reallocated" },
	{ 0x14, 0x07, "locate operation failure" },
	{ 0x15, 0x00, "random positioning error" },
	{ 0x15, 0x01, "mechanical positioning error" },
	{ 0x15, 0x02, "positioning error detected by read of medium" },
	{ 0x16, 0x00, "data sync mark error" },
	{ 0x16, 0x01, "data sync error - data rewritten" },
	{ 0x16, 0x02, "data sync error - recommend rewrite" },
	{ 0x16, 0x03, "data sync error - data auto-reallocated" },
	{ 0x16, 0x04, "data sync error - recommend reassignment" },
	{ 0x17, 0x00, "recovered data with no error correction" },
	{ 0x17, 0x01, "recovered data with retries" },
	{ 0x17, 0x02, "recovered data with positive head offset" },
	{ 0x17, 0x03, "recovered data with negative head offset" },
	{ 0x17, 0x04, "recovered data with retries and/or CIRC applied" },
	{ 0x17, 0x05, "recovered data using previous sector id" },
	{ 0x17, 0x06, "recovered data without ECC - data auto-reallocated" },
	{ 0x17, 0x07, "recovered data without ECC - recommend reassignment" },
	{ 0x17, 0x08, "recovered data without ECC - recommend rewrite" },
	{ 0x17, 0x09, "recovered data without ECC - data rewritten" },
	{ 0x18, 0x00, "recovered data with error correction" },
	{ 0x18, 0x01, "recovered data with error corr. & retries applied" },
	{ 0x18, 0x02, "recovered data - data auto-reallocated" },
	{ 0x18, 0x03, "recovered data with CIRC" },
	{ 0x18, 0x04, "recovered data with L-EC" },
	{ 0x18, 0x05, "recovered data - recommend reassignment" },
	{ 0x18, 0x06, "recovered data - recommend rewrite" },
	{ 0x18, 0x07, "recovered data with ECC - data rewritten" },
	{ 0x18, 0x08, "recovered data with linking" },
	{ 0x19, 0x00, "defect list error" },
	{ 0x1a, 0x00, "parameter list length error" },
	{ 0x1b, 0x00, "synchronous data xfer error" },
	{ 0x1c, 0x00, "defect list not found" },
	{ 0x1c, 0x01, "primary defect list not found" },
	{ 0x1c, 0x02, "grown defect list not found" },
	{ 0x1d, 0x00, "miscompare during verify" },
	{ 0x1e, 0x00, "recovered ID with ECC" },
	{ 0x1f, 0x00, "partial defect list transfer" },
	{ 0x20, 0x00, "invalid command operation code" },
	{ 0x20, 0x01, "access denied - initiator pending-enrolled" },
	{ 0x20, 0x02, "access denied - no access rights" },
	{ 0x20, 0x03, "access denied - invalid mgmt id key" },
	{ 0x20, 0x04, "illegal command while in write capable state" },
	{ 0x20, 0x06, "illegal command while in explicit address mode" },
	{ 0x20, 0x07, "illegal command while in implicit address mode" },
	{ 0x20, 0x08, "access denied - enrollment conflict" },
	{ 0x20, 0x09, "access denied - invalid lu identifier" },
	{ 0x20, 0x0a, "access denied - invalid proxy token" },
	{ 0x20, 0x0b, "access denied - ACL LUN conflict" },
	{ 0x21, 0x00, "logical block address out of range" },
	{ 0x21, 0x01, "invalid element address" },
	{ 0x21, 0x02, "invalid address for write" },
	{ 0x22, 0x00, "illegal function" },
	{ 0x24, 0x00, "invalid field in cdb" },
	{ 0x24, 0x01, "cdb decryption error" },
	{ 0x25, 0x00, "LUN not supported" },
	{ 0x26, 0x00, "invalid field in param list" },
	{ 0x26, 0x01, "parameter not supported" },
	{ 0x26, 0x02, "parameter value invalid" },
	{ 0x26, 0x03, "threshold parameters not supported" },
	{ 0x26, 0x04, "invalid release of persistent reservation" },
	{ 0x26, 0x05, "data decryption error" },
	{ 0x26, 0x06, "too many target descriptors" },
	{ 0x26, 0x07, "unsupported target descriptor type code" },
	{ 0x26, 0x08, "too many segment descriptors" },
	{ 0x26, 0x09, "unsupported segment descriptor type code" },
	{ 0x26, 0x0a, "unexpected inexact segment" },
	{ 0x26, 0x0b, "inline data length exceeded" },
	{ 0x26, 0x0c, "invalid operation for copy source or destination" },
	{ 0x26, 0x0d, "copy segment granularity violation" },
	{ 0x27, 0x00, "write protected" },
	{ 0x27, 0x01, "hardware write protected" },
	{ 0x27, 0x02, "LUN software write protected" },
	{ 0x27, 0x03, "associated write protect" },
	{ 0x27, 0x04, "persistent write protect" },
	{ 0x27, 0x05, "permanent write protect" },
	{ 0x27, 0x06, "conditional write protect" },
	{ 0x28, 0x00, "medium may have changed" },
	{ 0x28, 0x01, "import or export element accessed" },
	{ 0x29, 0x00, "power on, reset, or bus reset occurred" },
	{ 0x29, 0x01, "power on occurred" },
	{ 0x29, 0x02, "scsi bus reset occurred" },
	{ 0x29, 0x03, "bus device reset message occurred" },
	{ 0x29, 0x04, "device internal reset" },
	{ 0x29, 0x05, "transceiver mode changed to single-ended" },
	{ 0x29, 0x06, "transceiver mode changed to LVD" },
	{ 0x29, 0x07, "i_t nexus loss occurred" },
	{ 0x2a, 0x00, "parameters changed" },
	{ 0x2a, 0x01, "mode parameters changed" },
	{ 0x2a, 0x02, "log parameters changed" },
	{ 0x2a, 0x03, "reservations preempted" },
	{ 0x2a, 0x04, "reservations released" },
	{ 0x2a, 0x05, "registrations preempted" },
	{ 0x2a, 0x06, "asymmetric access state changed" },
	{ 0x2a, 0x07, "implicit asymmetric access state transition failed" },
	{ 0x2b, 0x00, "copy cannot execute since host cannot disconnect" },
	{ 0x2c, 0x00, "command sequence error" },
	{ 0x2c, 0x03, "current program area is not empty" },
	{ 0x2c, 0x04, "current program area is empty" },
	{ 0x2c, 0x06, "persistent prevent conflict" },
	{ 0x2c, 0x07, "previous busy status" },
	{ 0x2c, 0x08, "previous task set full status" },
	{ 0x2c, 0x09, "previous reservation conflict status" },
	{ 0x2d, 0x00, "overwrite error on update in place" },
	{ 0x2e, 0x00, "insufficient time for operation" },
	{ 0x2f, 0x00, "commands cleared by another initiator" },
	{ 0x30, 0x00, "incompatible medium installed" },
	{ 0x30, 0x01, "cannot read medium - unknown format" },
	{ 0x30, 0x02, "cannot read medium - incompatible format" },
	{ 0x30, 0x03, "cleaning cartridge installed" },
	{ 0x30, 0x04, "cannot write medium - unknown format" },
	{ 0x30, 0x05, "cannot write medium - incompatible format" },
	{ 0x30, 0x06, "cannot format medium - incompatible medium" },
	{ 0x30, 0x07, "cleaning failure" },
	{ 0x30, 0x08, "cannot write - application code mismatch" },
	{ 0x30, 0x09, "current session not fixated for append" },
	{ 0x30, 0x10, "medium not formatted" },
	{ 0x31, 0x00, "medium format corrupted" },
	{ 0x31, 0x01, "format command failed" },
	{ 0x31, 0x02, "zoned formatting failed due to spare linking" },
	{ 0x32, 0x00, "no defect spare location available" },
	{ 0x32, 0x01, "defect list update failure" },
	{ 0x33, 0x00, "tape length error" },
	{ 0x34, 0x00, "enclosure failure" },
	{ 0x35, 0x00, "enclosure services failure" },
	{ 0x35, 0x01, "unsupported enclosure function" },
	{ 0x35, 0x02, "enclosure services unavailable" },
	{ 0x35, 0x03, "enclosure services transfer failure" },
	{ 0x35, 0x04, "enclosure services transfer refused" },
	{ 0x36, 0x00, "ribbon, ink, or toner failure" },
	{ 0x37, 0x00, "rounded parameter" },
	{ 0x39, 0x00, "saving parameters not supported" },
	{ 0x3a, 0x00, "medium not present" },
	{ 0x3a, 0x01, "medium not present - tray closed" },
	{ 0x3a, 0x02, "medium not present - tray open" },
	{ 0x3a, 0x03, "medium not present - loadable" },
	{ 0x3a, 0x04, "medium not present - medium auxiliary memory "
		"accessible" },
	{ 0x3b, 0x00, "sequential positioning error" },
	{ 0x3b, 0x01, "tape position error at beginning-of-medium" },
	{ 0x3b, 0x02, "tape position error at end-of-medium" },
	{ 0x3b, 0x08, "reposition error" },
	{ 0x3b, 0x0c, "position past beginning of medium" },
	{ 0x3b, 0x0d, "medium destination element full" },
	{ 0x3b, 0x0e, "medium source element empty" },
	{ 0x3b, 0x0f, "end of medium reached" },
	{ 0x3b, 0x11, "medium magazine not accessible" },
	{ 0x3b, 0x12, "medium magazine removed" },
	{ 0x3b, 0x13, "medium magazine inserted" },
	{ 0x3b, 0x14, "medium magazine locked" },
	{ 0x3b, 0x15, "medium magazine unlocked" },
	{ 0x3b, 0x16, "mechanical positioning or changer error" },
	{ 0x3d, 0x00, "invalid bits in indentify message" },
	{ 0x3e, 0x00, "LUN has not self-configured yet" },
	{ 0x3e, 0x01, "LUN failure" },
	{ 0x3e, 0x02, "timeout on LUN" },
	{ 0x3e, 0x03, "LUN failed self-test" },
	{ 0x3e, 0x04, "LUN unable to update self-test log" },
	{ 0x3f, 0x00, "target operating conditions have changed" },
	{ 0x3f, 0x01, "microcode has been changed" },
	{ 0x3f, 0x02, "changed operating definition" },
	{ 0x3f, 0x03, "inquiry data has changed" },
	{ 0x3f, 0x04, "component device attached" },
	{ 0x3f, 0x05, "device identifier changed" },
	{ 0x3f, 0x06, "redundancy group created or modified" },
	{ 0x3f, 0x07, "redundancy group deleted" },
	{ 0x3f, 0x08, "spare created or modified" },
	{ 0x3f, 0x09, "spare deleted" },
	{ 0x3f, 0x0a, "volume set created or modified" },
	{ 0x3f, 0x0b, "volume set deleted" },
	{ 0x3f, 0x0c, "volume set deassigned" },
	{ 0x3f, 0x0d, "volume set reassigned" },
	{ 0x3f, 0x0e, "reported LUNs data has changed" },
	{ 0x3f, 0x0f, "echo buffer overwritten" },
	{ 0x3f, 0x10, "medium loadable" },
	{ 0x3f, 0x11, "medium auxiliary memory accessible" },
	{ 0x40, 0x00, "ram failure" },
	{ 0x41, 0x00, "data path failure" },
	{ 0x42, 0x00, "power-on or self-test failure" },
	{ 0x43, 0x00, "message error" },
	{ 0x44, 0x00, "internal target failure" },
	{ 0x45, 0x00, "select or reselect failure" },
	{ 0x46, 0x00, "unsuccessful soft reset" },
	{ 0x47, 0x00, "scsi parity error" },
	{ 0x47, 0x01, "data phase crc error detected" },
	{ 0x47, 0x02, "scsi parity error detected during st data phase" },
	{ 0x47, 0x03, "information unit iucrc error detected" },
	{ 0x47, 0x04, "asynchronous information protection error detected" },
	{ 0x47, 0x05, "protocol service crc error" },
	{ 0x47, 0x7f, "some commands cleared by iscsi protocol event" },
	{ 0x48, 0x00, "initiator detected error message received" },
	{ 0x49, 0x00, "invalid message error" },
	{ 0x4a, 0x00, "command phase error" },
	{ 0x4b, 0x00, "data phase error" },
	{ 0x4b, 0x01, "invalid target port transfer tag received" },
	{ 0x4b, 0x02, "too much write data" },
	{ 0x4b, 0x03, "ack/nak timeout" },
	{ 0x4b, 0x04, "nak received" },
	{ 0x4b, 0x05, "data offset error" },
	{ 0x4c, 0x00, "logical unit failed self-configuration" },
	{ 0x4d, 0x00, "tagged overlapped commands (ASCQ = queue tag)" },
	{ 0x4e, 0x00, "overlapped commands attempted" },
	{ 0x50, 0x00, "write append error" },
	{ 0x51, 0x00, "erase failure" },
	{ 0x52, 0x00, "cartridge fault" },
	{ 0x53, 0x00, "media load or eject failed" },
	{ 0x53, 0x01, "unload tape failure" },
	{ 0x53, 0x02, "medium removal prevented" },
	{ 0x54, 0x00, "scsi to host system interface failure" },
	{ 0x55, 0x00, "system resource failure" },
	{ 0x55, 0x01, "system buffer full" },
	{ 0x55, 0x02, "insufficient reservation resources" },
	{ 0x55, 0x03, "insufficient resources" },
	{ 0x55, 0x04, "insufficient registration resources" },
	{ 0x55, 0x05, "insufficient access control resources" },
	{ 0x55, 0x06, "auxiliary memory out of space" },
	{ 0x57, 0x00, "unable to recover TOC" },
	{ 0x58, 0x00, "generation does not exist" },
	{ 0x59, 0x00, "updated block read" },
	{ 0x5a, 0x00, "operator request or state change input" },
	{ 0x5a, 0x01, "operator medium removal request" },
	{ 0x5a, 0x02, "operator selected write protect" },
	{ 0x5a, 0x03, "operator selected write permit" },
	{ 0x5b, 0x00, "log exception" },
	{ 0x5b, 0x01, "threshold condition met" },
	{ 0x5b, 0x02, "log counter at maximum" },
	{ 0x5b, 0x03, "log list codes exhausted" },
	{ 0x5c, 0x00, "RPL status change" },
	{ 0x5c, 0x01, "spindles synchronized" },
	{ 0x5c, 0x02, "spindles not synchronized" },
	{ 0x5d, 0x00, "drive operation marginal, service immediately"
		    " (failure prediction threshold exceeded)" },
	{ 0x5d, 0x01, "media failure prediction threshold exceeded" },
	{ 0x5d, 0x02, "LUN failure prediction threshold exceeded" },
	{ 0x5d, 0x03, "spare area exhaustion prediction threshold exceeded" },
	{ 0x5d, 0x10, "hardware impending failure general hard drive failure" },
	{ 0x5d, 0x11, "hardware impending failure drive error rate too high" },
	{ 0x5d, 0x12, "hardware impending failure data error rate too high" },
	{ 0x5d, 0x13, "hardware impending failure seek error rate too high" },
	{ 0x5d, 0x14, "hardware impending failure too many block reassigns" },
	{ 0x5d, 0x15, "hardware impending failure access times too high" },
	{ 0x5d, 0x16, "hardware impending failure start unit times too high" },
	{ 0x5d, 0x17, "hardware impending failure channel parametrics" },
	{ 0x5d, 0x18, "hardware impending failure controller detected" },
	{ 0x5d, 0x19, "hardware impending failure throughput performance" },
	{ 0x5d, 0x1a, "hardware impending failure seek time performance" },
	{ 0x5d, 0x1b, "hardware impending failure spin-up retry count" },
	{ 0x5d, 0x1c, "hardware impending failure drive calibration retry "
		"count" },
	{ 0x5d, 0x20, "controller impending failure general hard drive "
		"failure" },
	{ 0x5d, 0x21, "controller impending failure drive error rate too "
		"high" },
	{ 0x5d, 0x22, "controller impending failure data error rate too high" },
	{ 0x5d, 0x23, "controller impending failure seek error rate too high" },
	{ 0x5d, 0x24, "controller impending failure too many block reassigns" },
	{ 0x5d, 0x25, "controller impending failure access times too high" },
	{ 0x5d, 0x26, "controller impending failure start unit times too "
		"high" },
	{ 0x5d, 0x27, "controller impending failure channel parametrics" },
	{ 0x5d, 0x28, "controller impending failure controller detected" },
	{ 0x5d, 0x29, "controller impending failure throughput performance" },
	{ 0x5d, 0x2a, "controller impending failure seek time performance" },
	{ 0x5d, 0x2b, "controller impending failure spin-up retry count" },
	{ 0x5d, 0x2c, "controller impending failure drive calibration retry "
		"cnt" },
	{ 0x5d, 0x30, "data channel impending failure general hard drive "
		"failure" },
	{ 0x5d, 0x31, "data channel impending failure drive error rate too "
		"high" },
	{ 0x5d, 0x32, "data channel impending failure data error rate too "
		"high" },
	{ 0x5d, 0x33, "data channel impending failure seek error rate too "
		"high" },
	{ 0x5d, 0x34, "data channel impending failure too many block "
		"reassigns" },
	{ 0x5d, 0x35, "data channel impending failure access times too high" },
	{ 0x5d, 0x36, "data channel impending failure start unit times too "
		"high" },
	{ 0x5d, 0x37, "data channel impending failure channel parametrics" },
	{ 0x5d, 0x38, "data channel impending failure controller detected" },
	{ 0x5d, 0x39, "data channel impending failure throughput performance" },
	{ 0x5d, 0x3a, "data channel impending failure seek time performance" },
	{ 0x5d, 0x3b, "data channel impending failure spin-up retry count" },
	{ 0x5d, 0x3c, "data channel impending failure drive calibrate retry "
		"cnt" },
	{ 0x5d, 0x40, "servo impending failure general hard drive failure" },
	{ 0x5d, 0x41, "servo impending failure drive error rate too high" },
	{ 0x5d, 0x42, "servo impending failure data error rate too high" },
	{ 0x5d, 0x43, "servo impending failure seek error rate too high" },
	{ 0x5d, 0x44, "servo impending failure too many block reassigns" },
	{ 0x5d, 0x45, "servo impending failure access times too high" },
	{ 0x5d, 0x46, "servo impending failure start unit times too high" },
	{ 0x5d, 0x47, "servo impending failure channel parametrics" },
	{ 0x5d, 0x48, "servo impending failure controller detected" },
	{ 0x5d, 0x49, "servo impending failure throughput performance" },
	{ 0x5d, 0x4a, "servo impending failure seek time performance" },
	{ 0x5d, 0x4b, "servo impending failure spin-up retry count" },
	{ 0x5d, 0x4c, "servo impending failure drive calibration retry count" },
	{ 0x5d, 0x50, "spindle impending failure general hard drive failure" },
	{ 0x5d, 0x51, "spindle impending failure drive error rate too high" },
	{ 0x5d, 0x52, "spindle impending failure data error rate too high" },
	{ 0x5d, 0x53, "spindle impending failure seek error rate too high" },
	{ 0x5d, 0x54, "spindle impending failure too many block reassigns" },
	{ 0x5d, 0x55, "spindle impending failure access times too high" },
	{ 0x5d, 0x56, "spindle impending failure start unit times too high" },
	{ 0x5d, 0x57, "spindle impending failure channel parametrics" },
	{ 0x5d, 0x58, "spindle impending failure controller detected" },
	{ 0x5d, 0x59, "spindle impending failure throughput performance" },
	{ 0x5d, 0x5a, "spindle impending failure seek time performance" },
	{ 0x5d, 0x5b, "spindle impending failure spin-up retry count" },
	{ 0x5d, 0x5c, "spindle impending failure drive calibration retry "
		"count" },
	{ 0x5d, 0x60, "firmware impending failure general hard drive failure" },
	{ 0x5d, 0x61, "firmware impending failure drive error rate too high" },
	{ 0x5d, 0x62, "firmware impending failure data error rate too high" },
	{ 0x5d, 0x63, "firmware impending failure seek error rate too high" },
	{ 0x5d, 0x64, "firmware impending failure too many block reassigns" },
	{ 0x5d, 0x65, "firmware impending failure access times too high" },
	{ 0x5d, 0x66, "firmware impending failure start unit times too high" },
	{ 0x5d, 0x67, "firmware impending failure channel parametrics" },
	{ 0x5d, 0x68, "firmware impending failure controller detected" },
	{ 0x5d, 0x69, "firmware impending failure throughput performance" },
	{ 0x5d, 0x6a, "firmware impending failure seek time performance" },
	{ 0x5d, 0x6b, "firmware impending failure spin-up retry count" },
	{ 0x5d, 0x6c, "firmware impending failure drive calibration retry "
		"count" },
	{ 0x5d, 0xff, "failure prediction threshold exceeded (false)" },
	{ 0x5e, 0x00, "low power condition active" },
	{ 0x5e, 0x01, "idle condition activated by timer" },
	{ 0x5e, 0x02, "standby condition activated by timer" },
	{ 0x5e, 0x03, "idle condition activated by command" },
	{ 0x5e, 0x04, "standby condition activated by command" },
	{ 0x60, 0x00, "lamp failure" },
	{ 0x61, 0x00, "video aquisition error" },
	{ 0x62, 0x00, "scan head positioning error" },
	{ 0x63, 0x00, "end of user area encountered on this track" },
	{ 0x63, 0x01, "packet does not fit in available space" },
	{ 0x64, 0x00, "illegal mode for this track" },
	{ 0x64, 0x01, "invalid packet size" },
	{ 0x65, 0x00, "voltage fault" },
	{ 0x66, 0x00, "automatic document feeder cover up" },
	{ 0x67, 0x00, "configuration failure" },
	{ 0x67, 0x01, "configuration of incapable LUNs failed" },
	{ 0x67, 0x02, "add LUN failed" },
	{ 0x67, 0x03, "modification of LUN failed" },
	{ 0x67, 0x04, "exchange of LUN failed" },
	{ 0x67, 0x05, "remove of LUN failed" },
	{ 0x67, 0x06, "attachment of LUN failed" },
	{ 0x67, 0x07, "creation of LUN failed" },
	{ 0x67, 0x08, "assign failure occurred" },
	{ 0x67, 0x09, "multiply assigned LUN" },
	{ 0x67, 0x0a, "set target port groups command failed" },
	{ 0x68, 0x00, "logical unit not configured" },
	{ 0x69, 0x00, "data loss on logical unit" },
	{ 0x69, 0x01, "multiple LUN failures" },
	{ 0x69, 0x02, "parity/data mismatch" },
	{ 0x6a, 0x00, "informational, refer to log" },
	{ 0x6b, 0x00, "state change has occured" },
	{ 0x6b, 0x01, "redundancy level got better" },
	{ 0x6b, 0x02, "redundancy level got worse" },
	{ 0x6c, 0x00, "rebuild failure occured" },
	{ 0x6d, 0x00, "recalculate failure occured" },
	{ 0x6e, 0x00, "command to logical unit failed" },
	{ 0x6f, 0x00, "copy protect key exchange failure authentication "
		"failure" },
	{ 0x6f, 0x01, "copy protect key exchange failure key not present" },
	{ 0x6f, 0x02, "copy protect key exchange failure key not established" },
	{ 0x6f, 0x03, "read of scrambled sector without authentication" },
	{ 0x6f, 0x04, "media region code is mismatched to LUN region" },
	{ 0x6f, 0x05, "drive region must be permanent/region reset count "
		"error" },
	{ 0x70, 0xffff, "decompression exception short algorithm id of ASCQ" },
	{ 0x71, 0x00, "decompression exception long algorithm id" },
	{ 0x72, 0x00, "session fixation error" },
	{ 0x72, 0x01, "session fixation error writing lead-in" },
	{ 0x72, 0x02, "session fixation error writing lead-out" },
	{ 0x72, 0x03, "session fixation error - incomplete track in session" },
	{ 0x72, 0x04, "empty or partially written reserved track" },
	{ 0x72, 0x05, "no more track reservations allowed" },
	{ 0x73, 0x00, "cd control error" },
	{ 0x73, 0x01, "power calibration area almost full" },
	{ 0x73, 0x02, "power calibration area is full" },
	{ 0x73, 0x03, "power calibration area error" },
	{ 0x73, 0x04, "program memory area update failure" },
	{ 0x73, 0x05, "program memory area is full" },
	{ 0x73, 0x06, "rma/pma is almost full" },
	{ 0xffff, 0xffff, NULL }
};

/*
 * Given an asc (Additional Sense Code) and ascq (Additional Sense Code
 * Qualifier), return a string describing the error information.
 */
static char *
scsi_util_asc_ascq_name(uint_t asc, uint_t ascq, char *buf, int buflen)
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
	(void) snprintf(buf, buflen, "<vendor unique code 0x%x>", asc);
	return (buf);
}

/*
 * Dumps detailed information about a particular SCSI error condition.
 */
static void
scsi_printerr(struct uscsi_cmd *ucmd, struct scsi_extended_sense *rq, int rqlen)
{
	diskaddr_t	blkno;
	struct scsi_descr_sense_hdr *sdsp = (struct scsi_descr_sense_hdr *)rq;
	char msgbuf[MSGBUFLEN];

	if (find_string(sensekey_strings, rq->es_key) == NULL)
		ds_dprintf("unknown error");

	ds_dprintf("during %s:",
	    find_string(scsi_cmdname_strings, ucmd->uscsi_cdb[0]));

	/*
	 * Get asc, ascq and info field from sense data.  There are two
	 * possible formats (fixed sense data and descriptor sense data)
	 * depending on the value of es_code.
	 */
	switch (rq->es_code) {
	case CODE_FMT_DESCR_CURRENT:
	case CODE_FMT_DESCR_DEFERRED:
		blkno = (diskaddr_t)scsi_extract_sense_info_descr(sdsp, rqlen);
		if (blkno != (diskaddr_t)-1)
			ds_dprintf(": block %lld (0x%llx)", blkno, blkno);
		ds_dprintf("\n");
		ds_dprintf("ASC: 0x%x   ASCQ: 0x%x    (%s)\n",
		    sdsp->ds_add_code, sdsp->ds_qual_code,
		    scsi_util_asc_ascq_name(sdsp->ds_add_code,
		    sdsp->ds_qual_code, msgbuf, MSGBUFLEN));

		break;

	case CODE_FMT_FIXED_CURRENT:
	case CODE_FMT_FIXED_DEFERRED:
	default:
		if (rq->es_valid) {
			blkno = (rq->es_info_1 << 24) |
			    (rq->es_info_2 << 16) |
			    (rq->es_info_3 << 8) | rq->es_info_4;
			ds_dprintf(": block %lld (0x%llx)", blkno, blkno);
		}
		ds_dprintf("\n");
		if (rq->es_add_len >= 6) {
			ds_dprintf("ASC: 0x%x   ASCQ: 0x%x    (%s)\n",
			    rq->es_add_code,
			    rq->es_qual_code,
			    scsi_util_asc_ascq_name(rq->es_add_code,
			    rq->es_qual_code, msgbuf, MSGBUFLEN));
		}
		break;
	}

	if (rq->es_key == KEY_ILLEGAL_REQUEST) {
		ddump("cmd:", (caddr_t)ucmd,
		    sizeof (struct uscsi_cmd));
		ddump("cdb:", (caddr_t)ucmd->uscsi_cdb,
		    ucmd->uscsi_cdblen);
	}
	ddump("sense:", (caddr_t)rq, rqlen);

	switch (rq->es_code) {
	case CODE_FMT_DESCR_CURRENT:
	case CODE_FMT_DESCR_DEFERRED:
		scsi_print_descr_sense(sdsp, rqlen);
		break;
	case CODE_FMT_FIXED_CURRENT:
	case CODE_FMT_FIXED_DEFERRED:
	default:
		scsi_print_extended_sense(rq, rqlen);
		break;
	}
}

/*
 * Retrieve "information" field from descriptor format sense data.  Iterates
 * through each sense descriptor looking for the information descriptor and
 * returns the information field from that descriptor.
 */
static diskaddr_t
scsi_extract_sense_info_descr(struct scsi_descr_sense_hdr *sdsp, int rqlen)
{
	diskaddr_t result;
	uint8_t *descr_offset;
	int valid_sense_length;
	struct scsi_information_sense_descr *isd;

	/*
	 * Initialize result to -1 indicating there is no information
	 * descriptor
	 */
	result = (diskaddr_t)-1;

	/*
	 * The first descriptor will immediately follow the header
	 */
	descr_offset = (uint8_t *)(sdsp+1);

	/*
	 * Calculate the amount of valid sense data
	 */
	valid_sense_length =
	    MIN((sizeof (struct scsi_descr_sense_hdr) +
	    sdsp->ds_addl_sense_length), rqlen);

	/*
	 * Iterate through the list of descriptors, stopping when we run out of
	 * sense data
	 */
	while ((descr_offset + sizeof (struct scsi_information_sense_descr)) <=
	    (uint8_t *)sdsp + valid_sense_length) {
		/*
		 * Check if this is an information descriptor.  We can use the
		 * scsi_information_sense_descr structure as a template since
		 * the first two fields are always the same
		 */
		isd = (struct scsi_information_sense_descr *)descr_offset;
		if (isd->isd_descr_type == DESCR_INFORMATION) {
			/*
			 * Found an information descriptor.  Copy the
			 * information field.  There will only be one
			 * information descriptor so we can stop looking.
			 */
			result =
			    (((diskaddr_t)isd->isd_information[0] << 56) |
			    ((diskaddr_t)isd->isd_information[1] << 48) |
			    ((diskaddr_t)isd->isd_information[2] << 40) |
			    ((diskaddr_t)isd->isd_information[3] << 32) |
			    ((diskaddr_t)isd->isd_information[4] << 24) |
			    ((diskaddr_t)isd->isd_information[5] << 16) |
			    ((diskaddr_t)isd->isd_information[6] << 8)  |
			    ((diskaddr_t)isd->isd_information[7]));
			break;
		}

		/*
		 * Get pointer to the next descriptor.  The "additional length"
		 * field holds the length of the descriptor except for the
		 * "type" and "additional length" fields, so we need to add 2 to
		 * get the total length.
		 */
		descr_offset += (isd->isd_addl_length + 2);
	}

	return (result);
}

/*
 * Display the full scsi_extended_sense as returned by the device
 */
static void
scsi_print_extended_sense(struct scsi_extended_sense *rq, int rqlen)
{
	static char *scsi_extended_sense_labels[] = {
	    "Request sense valid:             ",
	    "Error class and code:            ",
	    "Segment number:                  ",
	    "Filemark:                        ",
	    "End-of-medium:                   ",
	    "Incorrect length indicator:      ",
	    "Sense key:                       ",
	    "Information field:               ",
	    "Additional sense length:         ",
	    "Command-specific information:    ",
	    "Additional sense code:           ",
	    "Additional sense code qualifier: ",
	    "Field replaceable unit code:     ",
	    "Sense-key specific:              ",
	    "Additional sense bytes:          "
	};

	char **p = scsi_extended_sense_labels;

	if (rqlen < (sizeof (*rq) - 2) || !rq->es_valid) {
		/*
		 * target should be capable of returning at least 18
		 * bytes of data, i.e upto rq->es_skey_specific field.
		 * The additional sense bytes (2 or more ...) are optional.
		 */
		return;
	}

	ds_dprintf("\n%s%s\n", *p++, rq->es_valid ? "yes" : "no");
	ds_dprintf("%s0x%02x\n", *p++, (rq->es_class << 4) + rq->es_code);
	ds_dprintf("%s%d\n", *p++, rq->es_segnum);
	ds_dprintf("%s%s\n", *p++, rq->es_filmk ? "yes" : "no");
	ds_dprintf("%s%s\n", *p++, rq->es_eom ? "yes" : "no");
	ds_dprintf("%s%s\n", *p++, rq->es_ili ? "yes" : "no");
	ds_dprintf("%s%d\n", *p++, rq->es_key);

	ds_dprintf("%s0x%02x 0x%02x 0x%02x 0x%02x\n", *p++, rq->es_info_1,
	    rq->es_info_2, rq->es_info_3, rq->es_info_4);
	ds_dprintf("%s%d\n", *p++, rq->es_add_len);
	ds_dprintf("%s0x%02x 0x%02x 0x%02x 0x%02x\n", *p++,
	    rq->es_cmd_info[0], rq->es_cmd_info[1], rq->es_cmd_info[2],
	    rq->es_cmd_info[3]);
	ds_dprintf("%s0x%02x = %d\n", *p++, rq->es_add_code,
	    rq->es_add_code);
	ds_dprintf("%s0x%02x = %d\n", *p++, rq->es_qual_code,
	    rq->es_qual_code);
	ds_dprintf("%s%d\n", *p++, rq->es_fru_code);
	ds_dprintf("%s0x%02x 0x%02x 0x%02x\n", *p++,
	    rq->es_skey_specific[0], rq->es_skey_specific[1],
	    rq->es_skey_specific[2]);
	if (rqlen >= sizeof (*rq)) {
		ds_dprintf("%s0x%02x 0x%02x%s\n", *p, rq->es_add_info[0],
		    rq->es_add_info[1], (rqlen > sizeof (*rq)) ? " ..." : "");
	}

	ds_dprintf("\n");
}

/*
 * Display the full descriptor sense data as returned by the device
 */
static void
scsi_print_descr_sense(struct scsi_descr_sense_hdr *rq, int rqlen)
{
	/*
	 * Labels for the various fields of the scsi_descr_sense_hdr structure
	 */
	static char *scsi_descr_sense_labels[] = {
	    "Error class and code:            ",
	    "Sense key:                       ",
	    "Additional sense length:         ",
	    "Additional sense code:           ",
	    "Additional sense code qualifier: ",
	    "Additional sense bytes:          "
	};

	struct scsi_information_sense_descr *isd;
	uint8_t	*descr_offset;
	int valid_sense_length;
	char **p = scsi_descr_sense_labels;

	/* Target must return at least 8 bytes of data */
	if (rqlen < sizeof (struct scsi_descr_sense_hdr))
		return;

	/* Print descriptor sense header */
	ds_dprintf("%s0x%02x\n", *p++, (rq->ds_class << 4) + rq->ds_code);
	ds_dprintf("%s%d\n", *p++, rq->ds_key);

	ds_dprintf("%s%d\n", *p++, rq->ds_addl_sense_length);
	ds_dprintf("%s0x%02x = %d\n", *p++, rq->ds_add_code,
	    rq->ds_add_code);
	ds_dprintf("%s0x%02x = %d\n", *p++, rq->ds_qual_code,
	    rq->ds_qual_code);
	ds_dprintf("\n");

	/*
	 * Now print any sense descriptors.   The first descriptor will
	 * immediately follow the header
	 */
	descr_offset = (uint8_t *)(rq+1); /* Pointer arithmetic */

	/*
	 * Calculate the amount of valid sense data
	 */
	valid_sense_length =
	    MIN((sizeof (struct scsi_descr_sense_hdr) +
	    rq->ds_addl_sense_length), rqlen);

	/*
	 * Iterate through the list of descriptors, stopping when we
	 * run out of sense data.  Descriptor format is:
	 *
	 * <Descriptor type> <Descriptor length> <Descriptor data> ...
	 */
	while ((descr_offset + *(descr_offset + 1)) <=
	    (uint8_t *)rq + valid_sense_length) {
		/*
		 * Determine descriptor type.  We can use the
		 * scsi_information_sense_descr structure as a
		 * template since the first two fields are always the
		 * same.
		 */
		isd = (struct scsi_information_sense_descr *)descr_offset;
		switch (isd->isd_descr_type) {
		case DESCR_INFORMATION: {
			uint64_t information;

			information =
			    (((uint64_t)isd->isd_information[0] << 56) |
			    ((uint64_t)isd->isd_information[1] << 48) |
			    ((uint64_t)isd->isd_information[2] << 40) |
			    ((uint64_t)isd->isd_information[3] << 32) |
			    ((uint64_t)isd->isd_information[4] << 24) |
			    ((uint64_t)isd->isd_information[5] << 16) |
			    ((uint64_t)isd->isd_information[6] << 8)  |
			    ((uint64_t)isd->isd_information[7]));
			ds_dprintf("Information field:               "
			    "%0" PRIx64 "\n", information);
			break;
		}
		case DESCR_COMMAND_SPECIFIC: {
			struct scsi_cmd_specific_sense_descr *c =
			    (struct scsi_cmd_specific_sense_descr *)isd;
			uint64_t cmd_specific;

			cmd_specific =
			    (((uint64_t)c->css_cmd_specific_info[0] << 56) |
			    ((uint64_t)c->css_cmd_specific_info[1] << 48) |
			    ((uint64_t)c->css_cmd_specific_info[2] << 40) |
			    ((uint64_t)c->css_cmd_specific_info[3] << 32) |
			    ((uint64_t)c->css_cmd_specific_info[4] << 24) |
			    ((uint64_t)c->css_cmd_specific_info[5] << 16) |
			    ((uint64_t)c->css_cmd_specific_info[6] << 8)  |
			    ((uint64_t)c->css_cmd_specific_info[7]));
			ds_dprintf("Command-specific information:    "
			    "%0" PRIx64 "\n", cmd_specific);
			break;
		}
		case DESCR_SENSE_KEY_SPECIFIC: {
			struct scsi_sk_specific_sense_descr *ssd =
			    (struct scsi_sk_specific_sense_descr *)isd;
			uint8_t *sk_spec_ptr = (uint8_t *)&ssd->sss_data;
			ds_dprintf("Sense-key specific:              "
			    "0x%02x 0x%02x 0x%02x\n", sk_spec_ptr[0],
			    sk_spec_ptr[1], sk_spec_ptr[2]);
			break;
		}
		case DESCR_FRU: {
			struct scsi_fru_sense_descr *fsd =
			    (struct scsi_fru_sense_descr *)isd;
			ds_dprintf("Field replaceable unit code:     "
			    "%d\n", fsd->fs_fru_code);
			break;
		}
		case DESCR_BLOCK_COMMANDS: {
			struct scsi_block_cmd_sense_descr *bsd =
			    (struct scsi_block_cmd_sense_descr *)isd;
			ds_dprintf("Incorrect length indicator:      "
			    "%s\n", bsd->bcs_ili ? "yes" : "no");
			break;
		}
		default:
			/* Ignore */
			break;
		}

		/*
		 * Get pointer to the next descriptor.  The "additional
		 * length" field holds the length of the descriptor except
		 * for the "type" and "additional length" fields, so
		 * we need to add 2 to get the total length.
		 */
		descr_offset += (isd->isd_addl_length + 2);
	}

	ds_dprintf("\n");
}

static int
uscsi_timeout(void)
{
	const char *env = getenv("USCSI_TIMEOUT");
	static int timeo = -1;
	int i;

	if (timeo > 0)
		return (timeo);

	if (env != NULL) {
		i = atoi(env);
		if (i > USCSI_TIMEOUT_MAX)
			i = USCSI_TIMEOUT_MAX;
		else if (i < 0)
			i = USCSI_DEFAULT_TIMEOUT;
	} else
		i = USCSI_DEFAULT_TIMEOUT;

	timeo = i;
	return (i);
}

/*
 * Execute a command and determine the result.  Uses the "uscsi" ioctl
 * interface, which is fully supported.
 *
 * If the user wants request sense data to be returned in case of error then ,
 * the "uscsi_cmd" structure should have the request sense buffer allocated in
 * uscsi_rqbuf.
 */
static int
uscsi_cmd(int fd, struct uscsi_cmd *ucmd, void *rqbuf, int *rqlen)
{
	struct scsi_extended_sense *rq;
	int status;

	/*
	 * Set function flags for driver.
	 */
	ucmd->uscsi_flags = USCSI_ISOLATE;
	if (!ds_debug)
		ucmd->uscsi_flags |= USCSI_SILENT;

	/*
	 * If this command will perform a read, set the USCSI_READ flag
	 */
	if (ucmd->uscsi_buflen > 0) {
		/*
		 * uscsi_cdb is declared as a caddr_t, so any CDB
		 * command byte with the MSB set will result in a
		 * compiler error unless we cast to an unsigned value.
		 */
		switch ((uint8_t)ucmd->uscsi_cdb[0]) {
		case SCMD_MODE_SENSE:
		case SCMD_MODE_SENSE_G1:
		case SCMD_LOG_SENSE_G1:
		case SCMD_REQUEST_SENSE:
			ucmd->uscsi_flags |= USCSI_READ;
			break;

		case SCMD_MODE_SELECT:
		case SCMD_MODE_SELECT_G1:
			/* LINTED */
			ucmd->uscsi_flags |= USCSI_WRITE;
			break;
		default:
			assert(0);
			break;
		}
	}

	/* Set timeout */
	ucmd->uscsi_timeout = uscsi_timeout();

	/*
	 * Set up Request Sense buffer
	 */

	if (ucmd->uscsi_rqbuf == NULL)  {
		ucmd->uscsi_rqbuf = rqbuf;
		ucmd->uscsi_rqlen = *rqlen;
		ucmd->uscsi_rqresid = *rqlen;
	}
	if (ucmd->uscsi_rqbuf)
		ucmd->uscsi_flags |= USCSI_RQENABLE;
	ucmd->uscsi_rqstatus = IMPOSSIBLE_SCSI_STATUS;

	if (ucmd->uscsi_rqbuf != NULL && ucmd->uscsi_rqlen > 0)
		(void) memset(ucmd->uscsi_rqbuf, 0, ucmd->uscsi_rqlen);

	/*
	 * Execute the ioctl
	 */
	status = ioctl(fd, USCSICMD, ucmd);
	if (status == 0 && ucmd->uscsi_status == 0)
		return (status);

	/*
	 * If an automatic Request Sense gave us valid info about the error, we
	 * may be able to use that to print a reasonable error msg.
	 */
	if (ucmd->uscsi_rqstatus == IMPOSSIBLE_SCSI_STATUS) {
		ds_dprintf("No request sense for command %s\n",
		    find_string(scsi_cmdname_strings,
		    ucmd->uscsi_cdb[0]));
		return (-1);
	}
	if (ucmd->uscsi_rqstatus != STATUS_GOOD) {
		ds_dprintf("Request sense status for command %s: 0x%x\n",
		    find_string(scsi_cmdname_strings,
		    ucmd->uscsi_cdb[0]),
		    ucmd->uscsi_rqstatus);
		return (-1);
	}

	rq = (struct scsi_extended_sense *)ucmd->uscsi_rqbuf;
	*rqlen = ucmd->uscsi_rqlen - ucmd->uscsi_rqresid;

	if ((((int)rq->es_add_len) + 8) < MIN_REQUEST_SENSE_LEN ||
	    rq->es_class != CLASS_EXTENDED_SENSE ||
	    *rqlen < MIN_REQUEST_SENSE_LEN) {
		ds_dprintf("Request sense for command %s failed\n",
		    find_string(scsi_cmdname_strings,
		    ucmd->uscsi_cdb[0]));

		ds_dprintf("Sense data:\n");
		ddump(NULL, (caddr_t)rqbuf, *rqlen);

		return (-1);
	}

	/*
	 * If the failed command is a Mode Select, and the
	 * target is indicating that it has rounded one of
	 * the mode select parameters, as defined in the SCSI-2
	 * specification, then we should accept the command
	 * as successful.
	 */
	if (ucmd->uscsi_cdb[0] == SCMD_MODE_SELECT ||
	    ucmd->uscsi_cdb[0] == SCMD_MODE_SELECT_G1) {
		if (rq->es_key == KEY_RECOVERABLE_ERROR &&
		    rq->es_add_code == ROUNDED_PARAMETER &&
		    rq->es_qual_code == 0) {
			return (0);
		}
	}

	if (ds_debug)
		scsi_printerr(ucmd, rq, *rqlen);
	if (rq->es_key != KEY_RECOVERABLE_ERROR)
		return (-1);
	return (0);
}

int
uscsi_request_sense(int fd, caddr_t buf, int buflen, void *rqbuf, int *rqblen)
{
	struct uscsi_cmd ucmd;
	union scsi_cdb cdb;
	int status;

	(void) memset(buf, 0, buflen);
	(void) memset(&ucmd, 0, sizeof (ucmd));
	(void) memset(&cdb, 0, sizeof (union scsi_cdb));
	cdb.scc_cmd = SCMD_REQUEST_SENSE;
	FORMG0COUNT(&cdb, (uchar_t)buflen);
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = buf;
	ucmd.uscsi_buflen = buflen;
	status = uscsi_cmd(fd, &ucmd, rqbuf, rqblen);
	if (status)
		ds_dprintf("Request sense failed\n");
	if (status == 0)
		ddump("Request Sense data:", buf, buflen);

	return (status);
}

/*
 * Execute a uscsi mode sense command.  This can only be used to return one page
 * at a time.  Return the mode header/block descriptor and the actual page data
 * separately - this allows us to support devices which return either 0 or 1
 * block descriptors.  Whatever a device gives us in the mode header/block
 * descriptor will be returned to it upon subsequent mode selects.
 */
int
uscsi_mode_sense(int fd, int page_code, int page_control, caddr_t page_data,
    int page_size, struct scsi_ms_header *header, void *rqbuf, int *rqblen)
{
	caddr_t mode_sense_buf;
	struct mode_header *hdr;
	struct mode_page *pg;
	int nbytes;
	struct uscsi_cmd ucmd;
	union scsi_cdb cdb;
	int status;
	int maximum;
	char *pc;

	assert(page_size >= 0 && page_size < 256);
	assert(page_control == PC_CURRENT || page_control == PC_CHANGEABLE ||
	    page_control == PC_DEFAULT || page_control == PC_SAVED);

	nbytes = sizeof (struct scsi_ms_header) + page_size;
	mode_sense_buf = alloca((uint_t)nbytes);

	/*
	 * Build and execute the uscsi ioctl
	 */
	(void) memset(mode_sense_buf, 0, nbytes);
	(void) memset(&ucmd, 0, sizeof (ucmd));
	(void) memset(&cdb, 0, sizeof (union scsi_cdb));
	cdb.scc_cmd = SCMD_MODE_SENSE;
	FORMG0COUNT(&cdb, (uchar_t)nbytes);
	cdb.cdb_opaque[2] = page_control | page_code;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = mode_sense_buf;
	ucmd.uscsi_buflen = nbytes;
	status = uscsi_cmd(fd, &ucmd, rqbuf, rqblen);
	if (status) {
		ds_dprintf("Mode sense page 0x%x failed\n", page_code);
		return (-1);
	}

	ddump("RAW MODE SENSE BUFFER", mode_sense_buf, nbytes);

	/*
	 * Verify that the returned data looks reasonable, find the actual page
	 * data, and copy it into the user's buffer.  Copy the mode_header and
	 * block_descriptor into the header structure, which can then be used to
	 * return the same data to the drive when issuing a mode select.
	 */
	hdr = (struct mode_header *)mode_sense_buf;
	(void) memset((caddr_t)header, 0, sizeof (struct scsi_ms_header));

	/*
	 * Check to see if we have a valid header length. We've occasionally
	 * seen hardware return zero here, even though they filled in the media
	 * type.
	 */
	if (hdr->length == 0) {
		ds_dprintf("\nMode sense page 0x%x: has header length for "
		    "zero\n", page_code);
		ddump("Mode sense:", mode_sense_buf, nbytes);
		return (-1);
	}

	if (hdr->bdesc_length != sizeof (struct block_descriptor) &&
	    hdr->bdesc_length != 0) {
		ds_dprintf("\nMode sense page 0x%x: block descriptor "
		    "length %d incorrect\n", page_code, hdr->bdesc_length);
		ddump("Mode sense:", mode_sense_buf, nbytes);
		return (-1);
	}
	(void) memcpy((caddr_t)header, mode_sense_buf,
	    (int)(MODE_HEADER_LENGTH + hdr->bdesc_length));
	pg = (struct mode_page *)((ulong_t)mode_sense_buf +
	    MODE_HEADER_LENGTH + hdr->bdesc_length);

	if (page_code == MODEPAGE_ALLPAGES) {
		/* special case */

		if ((hdr->length + sizeof (header->ms_header.length)) <
		    (MODE_HEADER_LENGTH + hdr->bdesc_length)) {
			ds_dprintf("\nHeader length would spiral into a "
			    "negative bcopy\n");
			return (-1);
		}

		(void) memcpy(page_data, (caddr_t)pg,
		    (hdr->length + sizeof (header->ms_header.length)) -
		    (MODE_HEADER_LENGTH + hdr->bdesc_length));

		pc = find_string(page_control_strings, page_control);
		ds_dprintf("\nMode sense page 0x%x (%s):\n", page_code,
		    pc != NULL ? pc : "");
		ddump("header:", (caddr_t)header,
		    sizeof (struct scsi_ms_header));
		ddump("data:", page_data,
		    (hdr->length +
		    sizeof (header->ms_header.length)) -
		    (MODE_HEADER_LENGTH + hdr->bdesc_length));

		return (0);
	}

	if (pg->code != page_code) {
		ds_dprintf("\nMode sense page 0x%x: incorrect page code 0x%x\n",
		    page_code, pg->code);
		ddump("Mode sense:", mode_sense_buf, nbytes);
		return (-1);
	}

	/*
	 * Accept up to "page_size" bytes of mode sense data.  This allows us to
	 * accept both CCS and SCSI-2 structures, as long as we request the
	 * greater of the two.
	 */
	maximum = page_size - sizeof (struct mode_page);
	if (((int)pg->length) > maximum) {
		ds_dprintf("Mode sense page 0x%x: incorrect page "
		    "length %d - expected max %d\n",
		    page_code, pg->length, maximum);
		ddump("Mode sense:", mode_sense_buf, nbytes);
		return (-1);
	}

	(void) memcpy(page_data, (caddr_t)pg, MODESENSE_PAGE_LEN(pg));

	pc = find_string(page_control_strings, page_control);
	ds_dprintf("\nMode sense page 0x%x (%s):\n", page_code,
	    pc != NULL ? pc : "");
	ddump("header:", (caddr_t)header, sizeof (struct scsi_ms_header));
	ddump("data:", page_data, MODESENSE_PAGE_LEN(pg));

	return (0);
}

/*
 * Execute a uscsi MODE SENSE(10) command.  This can only be used to return one
 * page at a time.  Return the mode header/block descriptor and the actual page
 * data separately - this allows us to support devices which return either 0 or
 * 1 block descriptors.  Whatever a device gives us in the mode header/block
 * descriptor will be returned to it upon subsequent mode selects.
 */
int
uscsi_mode_sense_10(int fd, int page_code, int page_control,
    caddr_t page_data, int page_size, struct scsi_ms_header_g1 *header,
    void *rqbuf, int *rqblen)
{
	caddr_t mode_sense_buf;
	struct mode_header_g1 *hdr;
	struct mode_page *pg;
	int nbytes;
	struct uscsi_cmd ucmd;
	union scsi_cdb cdb;
	int status;
	int maximum;
	ushort_t length, bdesc_length;
	char *pc;

	assert(page_size >= 0 && page_size < UINT16_MAX);
	assert(page_control == PC_CURRENT || page_control == PC_CHANGEABLE ||
	    page_control == PC_DEFAULT || page_control == PC_SAVED);

	nbytes = sizeof (struct scsi_ms_header_g1) + page_size;
	mode_sense_buf = alloca((uint_t)nbytes);

	(void) memset(mode_sense_buf, 0, nbytes);
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	(void) memset((char *)&cdb, 0, sizeof (union scsi_cdb));
	cdb.scc_cmd = SCMD_MODE_SENSE_G1;
	FORMG1COUNT(&cdb, (uint16_t)nbytes);
	cdb.cdb_opaque[2] = page_control | page_code;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = mode_sense_buf;
	ucmd.uscsi_buflen = nbytes;

	status = uscsi_cmd(fd, &ucmd, rqbuf, rqblen);
	if (status) {
		ds_dprintf("Mode sense(10) page 0x%x failed\n",
		    page_code);
		return (-1);
	}

	ddump("RAW MODE SENSE(10) BUFFER", mode_sense_buf, nbytes);

	/*
	 * Verify that the returned data looks reasonable, find the actual page
	 * data, and copy it into the user's buffer.  Copy the mode_header and
	 * block_descriptor into the header structure, which can then be used to
	 * return the same data to the drive when issuing a mode select.
	 */
	/* LINTED */
	hdr = (struct mode_header_g1 *)mode_sense_buf;

	length = BE_16(hdr->length);
	bdesc_length = BE_16(hdr->bdesc_length);

	(void) memset((caddr_t)header, 0, sizeof (struct scsi_ms_header_g1));
	if (bdesc_length != sizeof (struct block_descriptor) &&
	    bdesc_length != 0) {
		ds_dprintf("\nMode sense(10) page 0x%x: block descriptor "
		    "length %d incorrect\n", page_code, bdesc_length);
		ddump("Mode sense(10):", mode_sense_buf, nbytes);
		return (-1);
	}
	(void) memcpy((caddr_t)header, mode_sense_buf,
	    (int)(MODE_HEADER_LENGTH_G1 + bdesc_length));
	pg = (struct mode_page *)((ulong_t)mode_sense_buf +
	    MODE_HEADER_LENGTH_G1 + bdesc_length);

	if (page_code == MODEPAGE_ALLPAGES) {
		/* special case */

		(void) memcpy(page_data, (caddr_t)pg,
		    (length + sizeof (header->ms_header.length)) -
		    (MODE_HEADER_LENGTH_G1 + bdesc_length));

		pc = find_string(page_control_strings, page_control);
		ds_dprintf("\nMode sense(10) page 0x%x (%s):\n",
		    page_code, pc != NULL ? pc : "");
		ddump("header:", (caddr_t)header,
		    MODE_HEADER_LENGTH_G1 + bdesc_length);

		ddump("data:", page_data,
		    (length + sizeof (header->ms_header.length)) -
		    (MODE_HEADER_LENGTH_G1 + bdesc_length));

		return (0);
	}

	if (pg->code != page_code) {
		ds_dprintf("\nMode sense(10) page 0x%x: incorrect page "
		    "code 0x%x\n", page_code, pg->code);
		ddump("Mode sense(10):", mode_sense_buf, nbytes);
		return (-1);
	}

	/*
	 * Accept up to "page_size" bytes of mode sense data.  This allows us to
	 * accept both CCS and SCSI-2 structures, as long as we request the
	 * greater of the two.
	 */
	maximum = page_size - sizeof (struct mode_page);
	if (((int)pg->length) > maximum) {
		ds_dprintf("Mode sense(10) page 0x%x: incorrect page "
		    "length %d - expected max %d\n",
		    page_code, pg->length, maximum);
		ddump("Mode sense(10):", mode_sense_buf,
		    nbytes);
		return (-1);
	}

	(void) memcpy(page_data, (caddr_t)pg, MODESENSE_PAGE_LEN(pg));

	pc = find_string(page_control_strings, page_control);
	ds_dprintf("\nMode sense(10) page 0x%x (%s):\n", page_code,
	    pc != NULL ? pc : "");
	ddump("header:", (caddr_t)header,
	    sizeof (struct scsi_ms_header_g1));
	ddump("data:", page_data, MODESENSE_PAGE_LEN(pg));

	return (0);
}

/*
 * Execute a uscsi mode select command.
 */
int
uscsi_mode_select(int fd, int page_code, int options, caddr_t page_data,
    int page_size, struct scsi_ms_header *header, void *rqbuf, int *rqblen)
{
	caddr_t mode_select_buf;
	int nbytes;
	struct uscsi_cmd ucmd;
	union scsi_cdb cdb;
	int status;
	char *s;

	assert(((struct mode_page *)page_data)->ps == 0);
	assert(header->ms_header.length == 0);
	assert(header->ms_header.device_specific == 0);
	assert((options & ~(MODE_SELECT_SP|MODE_SELECT_PF)) == 0);

	nbytes = sizeof (struct scsi_ms_header) + page_size;
	mode_select_buf = alloca((uint_t)nbytes);

	/*
	 * Build the mode select data out of the header and page data This
	 * allows us to support devices which return either 0 or 1 block
	 * descriptors.
	 */
	(void) memset(mode_select_buf, 0, nbytes);
	nbytes = MODE_HEADER_LENGTH;
	if (header->ms_header.bdesc_length ==
	    sizeof (struct block_descriptor)) {
		nbytes += sizeof (struct block_descriptor);
	}

	s = find_string(mode_select_strings,
	    options & (MODE_SELECT_SP|MODE_SELECT_PF));
	ds_dprintf("\nMode select page 0x%x%s:\n", page_code,
	    s != NULL ? s : "");
	ddump("header:", (caddr_t)header, nbytes);
	ddump("data:", (caddr_t)page_data, page_size);

	/*
	 * Put the header and data together
	 */
	(void) memcpy(mode_select_buf, (caddr_t)header, nbytes);
	(void) memcpy(mode_select_buf + nbytes, page_data, page_size);
	nbytes += page_size;

	/*
	 * Build and execute the uscsi ioctl
	 */
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	(void) memset((char *)&cdb, 0, sizeof (union scsi_cdb));
	cdb.scc_cmd = SCMD_MODE_SELECT;
	FORMG0COUNT(&cdb, (uchar_t)nbytes);
	cdb.cdb_opaque[1] = (uchar_t)options;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = mode_select_buf;
	ucmd.uscsi_buflen = nbytes;
	status = uscsi_cmd(fd, &ucmd, rqbuf, rqblen);

	if (status)
		ds_dprintf("Mode select page 0x%x failed\n", page_code);

	return (status);
}

/*
 * Execute a uscsi mode select(10) command.
 */
int
uscsi_mode_select_10(int fd, int page_code, int options,
    caddr_t page_data, int page_size, struct scsi_ms_header_g1 *header,
    void *rqbuf, int *rqblen)
{
	caddr_t				mode_select_buf;
	int				nbytes;
	struct uscsi_cmd		ucmd;
	union scsi_cdb			cdb;
	int				status;
	char				*s;

	assert(((struct mode_page *)page_data)->ps == 0);
	assert(header->ms_header.length == 0);
	assert(header->ms_header.device_specific == 0);
	assert((options & ~(MODE_SELECT_SP|MODE_SELECT_PF)) == 0);

	nbytes = sizeof (struct scsi_ms_header_g1) + page_size;
	mode_select_buf = alloca((uint_t)nbytes);

	/*
	 * Build the mode select data out of the header and page data
	 * This allows us to support devices which return either
	 * 0 or 1 block descriptors.
	 */
	(void) memset(mode_select_buf, 0, nbytes);
	nbytes = sizeof (struct mode_header_g1);
	if (BE_16(header->ms_header.bdesc_length) ==
	    sizeof (struct block_descriptor)) {
		nbytes += sizeof (struct block_descriptor);
	}

	/*
	 * Dump the structures
	 */
	s = find_string(mode_select_strings,
	    options & (MODE_SELECT_SP|MODE_SELECT_PF));
	ds_dprintf("\nMode select(10) page 0x%x%s:\n", page_code,
	    s != NULL ? s : "");
	ddump("header:", (caddr_t)header, nbytes);
	ddump("data:", (caddr_t)page_data, page_size);

	/*
	 * Put the header and data together
	 */
	(void) memcpy(mode_select_buf, (caddr_t)header, nbytes);
	(void) memcpy(mode_select_buf + nbytes, page_data, page_size);
	nbytes += page_size;

	/*
	 * Build and execute the uscsi ioctl
	 */
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	(void) memset((char *)&cdb, 0, sizeof (union scsi_cdb));
	cdb.scc_cmd = SCMD_MODE_SELECT_G1;
	FORMG1COUNT(&cdb, (uint16_t)nbytes);
	cdb.cdb_opaque[1] = (uchar_t)options;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = mode_select_buf;
	ucmd.uscsi_buflen = nbytes;
	status = uscsi_cmd(fd, &ucmd, rqbuf, rqblen);

	if (status)
		ds_dprintf("Mode select(10) page 0x%x failed\n", page_code);

	return (status);
}

int
uscsi_log_sense(int fd, int page_code, int page_control, caddr_t page_data,
    int page_size, void *rqbuf, int *rqblen)
{
	caddr_t log_sense_buf;
	scsi_log_header_t *hdr;
	struct uscsi_cmd ucmd;
	union scsi_cdb cdb;
	int status;
	ushort_t len;
	char *pc;

	assert(page_size >= 0 && page_size < UINT16_MAX);
	assert(page_control == PC_CURRENT || page_control == PC_CHANGEABLE ||
	    page_control == PC_DEFAULT || page_control == PC_SAVED);

	if (page_size < sizeof (scsi_log_header_t))
		return (-1);

	log_sense_buf = calloc(1, page_size);
	if (log_sense_buf == NULL)
		return (-1);

	/*
	 * Build and execute the uscsi ioctl
	 */
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	(void) memset((char *)&cdb, 0, sizeof (union scsi_cdb));
	cdb.scc_cmd = SCMD_LOG_SENSE_G1;
	FORMG1COUNT(&cdb, (uint16_t)page_size);
	cdb.cdb_opaque[2] = page_control | page_code;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = log_sense_buf;
	ucmd.uscsi_buflen = page_size;
	status = uscsi_cmd(fd, &ucmd, rqbuf, rqblen);
	if (status) {
		ds_dprintf("Log sense page 0x%x failed\n", page_code);
		free(log_sense_buf);
		return (-1);
	}

	/*
	 * Verify that the returned data looks reasonable, then copy it into the
	 * user's buffer.
	 */
	hdr = (scsi_log_header_t *)log_sense_buf;

	/*
	 * Ensure we have a host-understandable length field
	 */
	len = BE_16(hdr->lh_length);

	if (hdr->lh_code != page_code) {
		ds_dprintf("\nLog sense page 0x%x: incorrect page code 0x%x\n",
		    page_code, hdr->lh_code);
		ddump("Log sense:", log_sense_buf, page_size);
		free(log_sense_buf);
		return (-1);
	}

	ddump("LOG SENSE RAW OUTPUT", log_sense_buf,
	    sizeof (scsi_log_header_t) + len);

	/*
	 * Accept up to "page_size" bytes of mode sense data.  This allows us to
	 * accept both CCS and SCSI-2 structures, as long as we request the
	 * greater of the two.
	 */
	(void) memcpy(page_data, (caddr_t)hdr, len +
	    sizeof (scsi_log_header_t));

	pc = find_string(page_control_strings, page_control);
	ds_dprintf("\nLog sense page 0x%x (%s):\n", page_code,
	    pc != NULL ? pc : "");
	ddump("header:", (caddr_t)hdr,
	    sizeof (scsi_log_header_t));
	ddump("data:", (caddr_t)hdr +
	    sizeof (scsi_log_header_t), len);
	free(log_sense_buf);

	return (0);
}
