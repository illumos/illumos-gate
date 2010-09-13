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

#include <sys/types.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>

#include <stddef.h>
#include <stdio.h>

#include <scsi/libscsi.h>
#include "libscsi_impl.h"

typedef struct slist {
	char	*str;
	int	value;
} slist_t;

static slist_t sensekey_strings[] = {
	{ "No sense error", 	KEY_NO_SENSE		},
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

static struct asq_key_strings {
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

static const char *
find_string(slist_t *slist, int match_value)
{
	for (; slist->str != NULL; slist++) {
		if (slist->value == match_value) {
			return (slist->str);
		}
	}

	return (NULL);
}

const char *
libscsi_sense_key_name(uint64_t key)
{
	return (find_string(sensekey_strings, (int)key));
}

/*
 * Given an asc (Additional Sense Code) and ascq (Additional Sense Code
 * Qualifier), return a string describing the error information.
 */
const char *
libscsi_sense_code_name(uint64_t asc, uint64_t ascq)
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

	return (NULL);
}

/*
 * Retrieve "information" field from descriptor format sense data.  Iterates
 * through each sense descriptor looking for the information descriptor and
 * returns the information field from that descriptor.
 */
static diskaddr_t
scsi_extract_sense_info_descr(struct scsi_descr_sense_hdr *sdsp, size_t len)
{
	diskaddr_t result;
	uint8_t *descr_offset;
	size_t valid_sense_length;
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
	    sdsp->ds_addl_sense_length), len);

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

int
libscsi_action_parse_sense(const libscsi_action_t *ap, uint64_t *keyp,
    uint64_t *ascp, uint64_t *ascqp, diskaddr_t *blkp)
{
	struct scsi_extended_sense *xsp;
	struct scsi_descr_sense_hdr *sdsp;
	size_t len;

	if (libscsi_action_get_sense(ap, (uint8_t **)&xsp, NULL, &len) != 0)
		return (-1);

	sdsp = (struct scsi_descr_sense_hdr *)xsp;

	if (keyp != NULL)
		*keyp = (uint64_t)xsp->es_key;

	switch (xsp->es_code) {
	case CODE_FMT_DESCR_CURRENT:
	case CODE_FMT_DESCR_DEFERRED:
		if (blkp != NULL)
			*blkp = (diskaddr_t)
			    scsi_extract_sense_info_descr(sdsp, len);
		if (ascp != NULL)
			*ascp = (uint64_t)sdsp->ds_add_code;
		if (ascqp != NULL)
			*ascqp = (uint64_t)sdsp->ds_qual_code;
		break;
	case CODE_FMT_FIXED_CURRENT:
	case CODE_FMT_FIXED_DEFERRED:
	default:
		if (xsp->es_valid && blkp != NULL)
			*blkp = (diskaddr_t)
			    ((xsp->es_info_1 << 24) | (xsp->es_info_2 << 16) |
			    (xsp->es_info_3 << 8) | xsp->es_info_4);
		if (xsp->es_add_len >= 6) {
			if (ascp != NULL)
				*ascp = (uint64_t)xsp->es_add_code;
			if (ascqp != NULL)
				*ascqp = (uint64_t)xsp->es_qual_code;
		}
		break;
	}

	return (0);
}
