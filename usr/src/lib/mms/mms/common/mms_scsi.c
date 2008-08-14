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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/generic/commands.h>
#include <mms_sym.h>
#include <mms_scsi.h>
#include <mms_strapp.h>

static	mms_sym_t	mms_scsi_cmd_tab[] = {
	"TEST_UNIT_READY",	SCMD_TEST_UNIT_READY,		/* 0x00 */
	"REZERO/REWIND",	SCMD_REWIND | SCMD_REZERO_UNIT,	/* 0x01 */
	"REQUEST_SENSE",	SCMD_REQUEST_SENSE,		/* 0x03 */
	"FORMAT",		SCMD_FORMAT,			/* 0x04 */
	"READ_BLOCK_LIMITS",	SCMD_READ_BLKLIM,		/* 0x05 */
	"REASSIGN",		SCMD_REASSIGN_BLOCK,		/* 0x07 */
	"READ",			SCMD_READ | SCMD_RECEIVE,	/* 0x08 */
	"WRITE",		SCMD_PRINT | SCMD_SEND | SCMD_WRITE, /* 0x0A */
	"SEEK",			SCMD_SEEK | SCMD_SLEW_PRINT | SCMD_TRK_SEL,
								/* 0x0B */
	"READ_REVERSE",		SCMD_READ_REVERSE,		/* 0x0F */
	"WRITE_FILE_MARK",	SCMD_WRITE_FILE_MARK | SCMD_FLUSH_PRINT_BUF,
								/* 0x10 */
	"SPACE",		SCMD_SPACE,			/* 0x11 */
	"INQUIRY",		SCMD_INQUIRY,			/* 0x12 */
	"VERIFY",		SCMD_VERIFY_G0,			/* 0x13 */
	"RECOVER_BUFFER_DATA",	SCMD_RECOVER_BUF,		/* 0x14 */
	"MODE_SELECT",		SCMD_MODE_SELECT,		/* 0x15 */
	"RESERVE",		SCMD_RESERVE,			/* 0x16 */
	"RELEASE",		SCMD_RELEASE,			/* 0x17 */
	"COPY",			SCMD_COPY,			/* 0x18 */
	"ERASE_TAPE",		SCMD_ERASE,			/* 0x19 */
	"MODE_SENSE",		SCMD_MODE_SENSE,		/* 0x1A */
	"LOAD/START/STOP",	SCMD_LOAD | SCMD_START_STOP | SCMD_STOP_PRINT,
								/* 0x1B */
	"GET_DIAGNOSTIC_RESULTS", SCMD_GDIAG,			/* 0x1C */
	"SEND_DIAGNOSTIC_COMMAND", SCMD_SDIAG,			/* 0x1D */
	"DOOR_LOCK",		SCMD_DOORLOCK,			/* 0x1E */
	"READ_FORMAT_CAPACITY",	SCMD_READ_FORMAT_CAP,		/* 0x23 */
	"READ_CAPACITY",	SCMD_READ_CAPACITY,		/* 0x25 */
	"READ(10)",		SCMD_READ_G1,			/* 0x28 */
	"WRITE(10)",		SCMD_WRITE_G1,			/* 0x2A */
	"SEEK(10)",		SCMD_SEEK_G1 | SCMD_LOCATE,	/* 0x2B */
	"WRITE_VERIFY",		SCMD_WRITE_VERIFY,		/* 0x2E */
	"VERIFY(10)",		SCMD_VERIFY,			/* 0x2F */
	"SEARCH_DATA_HIGH",	SCMD_SEARCH_HIGH,		/* 0x30 */
	"SEARCH_DATA_EQUAL",	SCMD_SEARCH_EQUAL,		/* 0x31 */
	"SEARCH_DATA_LOW",	SCMD_SEARCH_LOW,		/* 0x32 */
	"SET_LIMITS",		SCMD_SET_LIMITS,		/* 0x33 */
	"READ_POSITION",	SCMD_READ_POSITION,		/* 0x34 */
	"SYNCHRONIZE_CACHE",	SCMD_SYNCHRONIZE_CACHE,		/* 0x35 */
	"READ_DEFECT_DATA",	SCMD_READ_DEFECT_LIST,		/* 0x37 */
	"COMPARE",		SCMD_COMPARE,			/* 0x39 */
	"COPY_VERIFY",		SCMD_COPY_VERIFY,		/* 0x3A */
	"WRITE_BUFFER",		SCMD_WRITE_BUFFER,		/* 0x3B */
	"READ_BUFFER",		SCMD_READ_BUFFER,		/* 0x3C */
	"READ_LONG",		SCMD_READ_LONG,			/* 0x3E */
	"WRITE_LONG",		SCMD_WRITE_LONG,		/* 0x3F */
	"REPORT_DENSITIES/READ_HEADER",	SCMD_REPORT_DENSITIES,	/* 0x44 */
	"LOG_SELECT",		SCMD_LOG_SELECT_G1,		/* 0x4C */
	"LOG_SENSE",		SCMD_LOG_SENSE_G1,		/* 0x4D */
	"MODE_SELECT(10)",	SCMD_MODE_SELECT_G1,		/* 0x55 */
	"RESERVE(10)",		SCMD_RESERVE_G1,		/* 0x56 */
	"RELEASE(10)",		SCMD_RELEASE_G1,		/* 0x57 */
	"MODE_SENSE(10)",	SCMD_MODE_SENSE_G1,		/* 0x5A */
	"PERSISTENT_RESERVE_IN", SCMD_PERSISTENT_RESERVE_IN,	/* 0x5E */
	"PERSISTENT_RESERVE_OUT", SCMD_PERSISTENT_RESERVE_OUT,	/* 0x5F */
	"EXTENDED_COPY",	SCMD_EXTENDED_COPY,		/* 0x83 */
	"READ(16)",		SCMD_READ_G4,			/* 0x88 */
	"WRITE(16)",		SCMD_WRITE_G4,			/* 0x8A */
	"READ_ATTRIBUTE",	SCMD_READ_ATTRIBUTE,		/* 0x8C */
	"WRITE_ATTRIBUTE",	SCMD_WRITE_ATTRIBUTE,		/* 0x8D */
	"VERIFY(16)",		SCMD_VERIFY_G4,			/* 0x8F */
	"LOCATE(16)",		SCMD_LOCATE_G4,			/* 0x92 */
	"SERVICE_ACTION_IN(16)", SCMD_SVC_ACTION_IN_G4,		/* 0x9E */
	"SERVICE_ACTION_OUT(16)", SCMD_SVC_ACTION_OUT_G4,	/* 0x9F */
	"REPORT_LUNS",		SCMD_REPORT_LUNS,		/* 0xA0 */
	"READ(12)",		SCMD_READ_G5,			/* 0xA8 */
	"WRITE(12)",		SCMD_WRITE_G5,			/* 0xAA */
	"GET_PERFORMANCE",	SCMD_GET_PERFORMANCE,		/* 0xAC */
	"VERIFY(12)",		SCMD_VERIFY_G5,			/* 0xAF */

	NULL,			-1,
};

static	mms_sym_t mms_scsi_status_tab[] = {
	"GOOD",			STATUS_GOOD,
	"CHECK",		STATUS_CHECK,
	"CONDITION MET",	STATUS_MET,
	"BUSY",			STATUS_BUSY,
	"INTERMEDIATE",		STATUS_INTERMEDIATE,
	"INTERMEDIATE MET",	STATUS_INTERMEDIATE_MET,
	"RESERVATION CONFLICT",	STATUS_RESERVATION_CONFLICT,
	"TERMINATED",		STATUS_TERMINATED,
	NULL,			-1,
};


static	mms_sym_t mms_scsi_senkey_tab[] = {
	"NO SENSE",		KEY_NO_SENSE,
	"RECOVERABLE MMS_ERROR",	KEY_RECOVERABLE_ERROR,
	"NOT READY",		KEY_NOT_READY,
	"MEDIUM MMS_ERROR",		KEY_MEDIUM_ERROR,
	"HARDWARE MMS_ERROR",	KEY_HARDWARE_ERROR,
	"ILLEGAL REQUEST",	KEY_ILLEGAL_REQUEST,
	"UNIT ATTENTION",	KEY_UNIT_ATTENTION,
	"WRITE PROTECT",	KEY_WRITE_PROTECT,
	"DATA PROTECT",		KEY_DATA_PROTECT,
	"BLANK CHECK",		KEY_BLANK_CHECK,
	"VENDOR UNIQUE",	KEY_VENDOR_UNIQUE,
	"COPY ABORTED",		KEY_COPY_ABORTED,
	"ABORTED COMMAND",	KEY_ABORTED_COMMAND,
	"EQUAL",		KEY_EQUAL,
	"VOLUME OVERFLOW",	KEY_VOLUME_OVERFLOW,
	"MISCOMPARE",		KEY_MISCOMPARE,
	"RESERVED",		KEY_RESERVED,
	/*
	 * The following are SUN keys
	 */
	"SUN FATAL",		SUN_KEY_FATAL,
	"SUN TIMEOUT",		SUN_KEY_TIMEOUT,
	"SUN EOF",		SUN_KEY_EOF,
	"SUN EOT",		SUN_KEY_EOT,
	"SUN LENGTH MMS_ERROR",	SUN_KEY_LENGTH,
	"SUN BOT",		SUN_KEY_BOT,
	"SUN WRONG MEDIA",	SUN_KEY_WRONGMEDIA,

	NULL,			-1,
};

static char *
mms_scsi_lookup(mms_sym_t *tab, int code)
{
	mms_sym_t	*mms_sym;
	static char	hexcode[10];

	for (mms_sym = tab; mms_sym->sym_token != NULL; mms_sym++) {
		if (mms_sym->sym_code == code) {
			return (mms_sym->sym_token);
		}
	}
	(void) snprintf(hexcode, sizeof (hexcode), "0x%2.2x", code);
	return (hexcode);
}

char *
mms_scsi_cmd(int cmd)
{
	return (mms_scsi_lookup(mms_scsi_cmd_tab, cmd));
}

char *
mms_scsi_status(int stat)
{
	return (mms_scsi_lookup(mms_scsi_status_tab, stat));
}

char *
mms_scsi_sensekey(int senkey)
{
	return (mms_scsi_lookup(mms_scsi_senkey_tab, senkey));
}

char *
mms_scsi_asc(int asc)
{
	static	char	buf[10];

	(void) snprintf(buf, sizeof (buf), "0x%2.2x", asc);
	return (buf);
}

char *
mms_scsi_ascq(int ascq)
{
	static	char	buf[10];

	(void) snprintf(buf, sizeof (buf), "0x%2.2x", ascq);
	return (buf);
}

char *
mms_format_sense(struct scsi_extended_sense *sen)
{
	char	*buf;
	mms_skey_specific_t	*sks;

	sks = (mms_skey_specific_t *)sen->es_skey_specific;

	buf = mms_strapp(NULL,
	    "valid=%x, resp code=%2.2x, seg num=%2.2x, "
	    "filemark=%x, eom=%x, ili=%x, sen key=%x, "
	    "info=%8.8x, add len=%2.2x, cmd info=%8.8x, "
	    "asc=%2.2x, ascq=%2.2x, fruc=%2.2x, "
	    "SKSV=%x, C/D=%x, BPV=%x, bit ptr=%x, field ptr=%4.4x",

	    sen->es_valid, (sen->es_class << 4) | sen->es_code,
	    sen->es_segnum,
	    sen->es_filmk, sen->es_eom, sen->es_ili, sen->es_key,
	    (sen->es_info_1 << 24) | (sen->es_info_2 << 16) |
	    (sen->es_info_3 << 8) | sen->es_info_4,
	    sen->es_add_len,
	    (sen->es_cmd_info[0] << 24) | (sen->es_cmd_info[1] << 16) |
	    (sen->es_cmd_info[2] << 8) | sen->es_cmd_info[3],
	    sen->es_add_code, sen->es_qual_code, sen->es_fru_code,
	    sks->mms_sksv, sks->mms_cd, sks->mms_bpv,
	    sks->mms_bitptr,
	    (sks->mms_fp[0] << 8) | sks->mms_fp[1]);

	return (buf);
}
