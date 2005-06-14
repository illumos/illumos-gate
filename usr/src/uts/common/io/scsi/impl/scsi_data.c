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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Global SCSI data
 */

#include <sys/scsi/scsi.h>

char *sense_keys[NUM_SENSE_KEYS + NUM_IMPL_SENSE_KEYS] = {
	"No Additional Sense",		/* 0x00 */
	"Soft Error",			/* 0x01 */
	"Not Ready",			/* 0x02 */
	"Media Error",			/* 0x03 */
	"Hardware Error",		/* 0x04 */
	"Illegal Request",		/* 0x05 */
	"Unit Attention",		/* 0x06 */
	"Write Protected",		/* 0x07 */
	"Blank Check",			/* 0x08 */
	"Vendor Unique",		/* 0x09 */
	"Copy Aborted",			/* 0x0a */
	"Aborted Command",		/* 0x0b */
	"Equal Error",			/* 0x0c */
	"Volume Overflow",		/* 0x0d */
	"Miscompare Error",		/* 0x0e */
	"Reserved",			/* 0x0f */
	"fatal",			/* 0x10 */
	"timeout",			/* 0x11 */
	"EOF",				/* 0x12 */
	"EOT",				/* 0x13 */
	"length error",			/* 0x14 */
	"BOT",				/* 0x15 */
	"wrong tape media"		/* 0x16 */
};


char *scsi_state_bits = "\20\05STS\04XFER\03CMD\02SEL\01ARB";


/*
 * This structure is used to allow you to quickly determine the size of the
 * cdb by examining the cmd code.  It is used in conjunction with the
 * CDB_GROUPID macro.  Lookup returns size of cdb.  If unknown, zero returned.
 */
uchar_t	scsi_cdb_size[] = {
	CDB_GROUP0,	/* Group 0, 6  byte cdb */
	CDB_GROUP1,	/* Group 1, 10 byte cdb */
	CDB_GROUP2,	/* Group 2, 10 byte cdb */
	CDB_GROUP3,	/* Group 3,  reserved */
	CDB_GROUP4,	/* Group 4, 16 byte cdb */
	CDB_GROUP5,	/* Group 5, 12 byte cdb */
	CDB_GROUP6,	/* Group 6,  ? byte cdb (vendor specific) */
	CDB_GROUP7	/* Group 7,  ? byte cdb (vendor specific) */
};

/*
 * Basic SCSI command description strings that can be used by drivers
 * to pass to scsi_errmsg().
 */
struct scsi_key_strings scsi_cmds[] = {
/* 0x00 */ SCMD_TEST_UNIT_READY,		"test unit ready",
/* 0x01 */ SCMD_REZERO_UNIT|SCMD_REWIND,	"rezero/rewind",
/* 0x02 */ SCMD_REQUEST_SENSE,			"request sense",
/* 0x04 */ SCMD_FORMAT,				"format",
/* 0x05 */ SCMD_READ_BLKLIM,			"read block limits",
/* 0x07 */ SCMD_REASSIGN_BLOCK,			"reassign",
/* 0x08 */ SCMD_READ,				"read",
/* 0x0a */ SCMD_WRITE,				"write",
/* 0x0b */ SCMD_SEEK,				"seek",
/* 0x0f */ SCMD_READ_REVERSE,			"read reverce",
/* 0x10 */ SCMD_WRITE_FILE_MARK,		"write file mark",
/* 0x11 */ SCMD_SPACE,				"space",
/* 0x12 */ SCMD_INQUIRY,			"inquiry",
/* 0x13 */ SCMD_VERIFY_G0,			"verify(8)",
/* 0x14 */ SCMD_RECOVER_BUF,			"recover buffer data",
/* 0x15 */ SCMD_MODE_SELECT,			"mode select",
/* 0x16 */ SCMD_RESERVE,			"reserve",
/* 0x17 */ SCMD_RELEASE,			"release",
/* 0x18 */ SCMD_COPY,				"copy",
/* 0x19 */ SCMD_ERASE,				"erase tape",
/* 0x1a */ SCMD_MODE_SENSE,			"mode sense",
/* 0x1b */ SCMD_START_STOP|SCMD_LOAD,		"load/start/stop",
/* 0x1c */ SCMD_GDIAG,				"get diagnostic results",
/* 0x1d */ SCMD_SDIAG,				"send diagnostic command",
/* 0x1e */ SCMD_DOORLOCK,			"door lock",
/* 0x23 */ SCMD_READ_FORMAT_CAP,		"read format capacity",
/* 0x25 */ SCMD_READ_CAPACITY,			"read capacity",
/* 0x28 */ SCMD_READ_G1,			"read(10)",
/* 0x2a */ SCMD_WRITE_G1,			"write(10)",
/* 0x2b */ SCMD_SEEK_G1|SCMD_LOCATE,		"locate/seek(10)",
/* 0x2f */ SCMD_VERIFY,				"verify",
/* 0x34 */ SCMD_READ_POSITION,			"read position",
/* 0x37 */ SCMD_READ_DEFECT_LIST,		"read defect data",
/* 0x3b */ SCMD_WRITE_BUFFER,			"write buffer",
/* 0x3c */ SCMD_READ_BUFFER,			"read buffer",
/* 0x44 */ SCMD_REPORT_DENSITIES,		"report densities",
/* 0x46 */ SCMD_GET_CONFIGURATION,		"get configuration",
/* 0x4c */ SCMD_LOG_SELECT_G1,			"log select(10)",
/* 0x4d */ SCMD_LOG_SENSE_G1,			"log sense(10)",
/* 0x5e */ SCMD_PRIN,				"persistent reservation in",
/* 0x5f */ SCMD_PROUT,				"persistent reservation out",
/* 0xa0 */ SCMD_REPORT_LUNS,			"report luns",
	-1,					NULL
};
