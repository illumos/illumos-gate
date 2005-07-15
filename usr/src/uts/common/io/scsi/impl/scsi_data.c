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
 * Global SCSI data
 */

#include <sys/scsi/scsi.h>
#include <sys/cdio.h>			/* CDROM SCMD_ commands */

char *sense_keys[NUM_SENSE_KEYS + NUM_IMPL_SENSE_KEYS] = {
					/* ==== SCSI Standard Keys */
	"No_Additional_Sense",		/* 0x00 KEY_NO_SENSE */
	"Soft_Error",			/* 0x01 KEY_RECOVERABLE_ERROR */
	"Not_Ready",			/* 0x02 KEY_NOT_READY */
	"Media_Error",			/* 0x03 KEY_MEDIUM_ERROR */
	"Hardware_Error",		/* 0x04 KEY_HARDWARE_ERROR */
	"Illegal_Request",		/* 0x05 KEY_ILLEGAL_REQUEST */
	"Unit_Attention",		/* 0x06 KEY_UNIT_ATTENTION */
	"Write_Protected",		/* 0x07 KEY_WRITE_PROTECT */
	"Blank_Check",			/* 0x08 KEY_BLANK_CHECK */
	"Vendor_Unique",		/* 0x09 KEY_VENDOR_UNIQUE */
	"Copy_Aborted",			/* 0x0a KEY_COPY_ABORTED */
	"Aborted_Command",		/* 0x0b KEY_ABORTED_COMMAND */
	"Equal_Error",			/* 0x0c KEY_EQUAL */
	"Volume_Overflow",		/* 0x0d KEY_VOLUME_OVERFLOW */
	"Miscompare_Error",		/* 0x0e KEY_MISCOMPARE */
	"Reserved",			/* 0x0f KEY_RESERVED */
					/* ==== SUN SCSA 'pseudo' keys */
	"fatal",			/* 0x10 SUN_KEY_FATAL */
	"timeout",			/* 0x11 SUN_KEY_TIMEOUT */
	"EOF",				/* 0x12 SUN_KEY_EOF */
	"EOT",				/* 0x13 SUN_KEY_EOT */
	"length_error",			/* 0x14 SUN_KEY_LENGTH */
	"BOT",				/* 0x15 SUN_KEY_BOT */
	"wrong_tape_media"		/* 0x16 SUN_KEY_WRONGMEDIA */
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
	SCSI_CMDS_KEY_STRINGS,
	SCSI_CMDS_KEY_STRINGS_CDIO,
	-1,			NULL
};
