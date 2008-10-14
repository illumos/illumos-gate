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


/*LINTLIBRARY*/

/*
 *
 *	This module is part of the photon Command Line
 *	Interface program.
 *
 */

/*
 * I18N message number ranges
 *  This file: 11500 - 11999
 *  Shared common messages: 1 - 1999
 */

/* #define		_POSIX_SOURCE 1 */

/*	Includes	*/
#include	<stdlib.h>
#include	<stdio.h>
#include	<string.h>
#include	<sys/file.h>
#include	<sys/types.h>
#include	<fcntl.h>
#include	<sys/sunddi.h>
#include	<sys/systm.h>
#include	<sys/scsi/scsi.h>
#include	<nl_types.h>
#include	<unistd.h>
#include	<l_common.h>
#include	<stgcom.h>
#include	<l_error.h>
#include	<g_state.h>
#include	<errno.h>
#include	<devid.h>
#include	<libdevinfo.h>


/*	Defines		*/
/* Because of a bug in Unisys Envsen card,  Bug ID:1266986. */
#define	SCSI_ESI_PCV	0x01		/* Page Code Valid */
#define	SCSI_ESI_PF	0x10		/* Page Format */
#define	ACTION_MASK	0x1f		/* Persistent Reserve In command */
#define	IMMED		1		/* make the stop immediate */
#define	DAK_PROD_STR	"SUNWGS INT FCBPL"
#define	DAK_BOXNAME_LEN	16		/* The length of the daktari boxname */
#define	DAK_BOXNAME_OFF	36		/* The offset of the daktari boxname */



/*	Global variables	*/
extern	nl_catd l_catd;


/*	Forward declarations	*/
static int scsi_read_capacity_16_cmd(int, struct scsi_capacity_16 *, int);


/*	External functions	*/


int
g_scsi_persistent_reserve_in_cmd(int fd, uchar_t *buf_ptr,
	int buf_len, uchar_t action)
{
struct uscsi_cmd	ucmd;
my_cdb_g1	cdb = {SCMD_PERS_RESERV_IN, 0, 0, 0, 0, 0, 0, 0, 0, 0};
struct	scsi_extended_sense	sense;

	if ((fd < 0) || (buf_ptr == NULL) || (buf_len < 0)) {
		return (L_INVALID_ARG);
	}

	(void) memset(buf_ptr, 0, buf_len);
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	cdb.byte1 = action & ACTION_MASK;
	cdb.byte7 = (buf_len>>8) & 0xff;
	cdb.byte8 = buf_len & 0xff;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)buf_ptr;
	ucmd.uscsi_buflen = buf_len;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 60;

	if (buf_len & 0x03) {
		return (L_PR_INVLD_TRNSFR_LEN);
	}
	/* Do in SILENT mode as cmd may not be supported. */
	return (cmd(fd, &ucmd, USCSI_READ | USCSI_SILENT));
}
/*
 *	Send Diagnostic command
 *
 *	NOTE: This function includes a delay.
 */
int
g_scsi_send_diag_cmd(int fd, uchar_t *buf_ptr, int buf_len)
{
struct uscsi_cmd	ucmd;
uchar_t	cdb[] = {SCMD_SDIAG, SCSI_ESI_PF, 0, 0, 0, 0};
struct	scsi_extended_sense	sense;
int		err;

	if ((fd < 0) || (buf_ptr == NULL) || (buf_len < 0)) {
		return (L_INVALID_ARG);
	}

	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	cdb[3] = (buf_len>>8) & 0xff;
	cdb[4] = buf_len & 0xff;
	ucmd.uscsi_cdb = (caddr_t)cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)buf_ptr;
	ucmd.uscsi_buflen = buf_len;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 60;

	if (err = cmd(fd, &ucmd, USCSI_WRITE)) {
		return (err);
	}
	/*
	 * Allow time for things to stabilize.
	 */
	sleep(5);
	return (0);
}

/*
 * Internal routine to allow manipulation of the cdb[1] byte
 * in receive diag.
 */
static int
rec_diag_cmd(int fd, uchar_t *buf_ptr, int buf_len, uchar_t page_code,
	uchar_t cdb_one)
{
struct uscsi_cmd	ucmd;
uchar_t	cdb[] = {SCMD_GDIAG, 0, 0, 0, 0, 0};
struct	scsi_extended_sense	sense;

	if ((fd < 0) || (buf_ptr == NULL) || (buf_len < 0)) {
		return (L_INVALID_ARG);
	}

	(void) memset(buf_ptr, 0, buf_len);
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	cdb[1] = cdb_one;
	cdb[2] = page_code;
	cdb[3] = (buf_len>>8) & 0xff;
	cdb[4] = buf_len & 0xff;
	ucmd.uscsi_cdb = (caddr_t)cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)buf_ptr;
	ucmd.uscsi_buflen = buf_len;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 60;
	return (cmd(fd, &ucmd, USCSI_READ));
}


/*
 *	Receive Diagnostic command
 */
int
g_scsi_rec_diag_cmd(int fd, uchar_t *buf_ptr, int buf_len, uchar_t page_code)
{
int	status;

	if ((fd < 0) || (buf_ptr == NULL) || (buf_len < 0)) {
		return (L_INVALID_ARG);
	}

	if (buf_len & 0x03) {
		return (L_RD_INVLD_TRNSFR_LEN);
	}

	/*
	 * The a5k and newer enclosures abide by the SCSI spec
	 * (SPC-2: 7.15) but the SSA does not.  It requires
	 * 0x10 to be present in cdb[1].
	 *
	 * For enclosures that abide by the spec, the first call
	 * will work.  For SSAs the first call will fail, at which
	 * point we try again with the SSA specific value.
	 */
	status = rec_diag_cmd(fd, buf_ptr, buf_len, page_code, SCSI_ESI_PCV);
	if (status != 0) {
	    status = rec_diag_cmd(fd, buf_ptr, buf_len, page_code, SCSI_ESI_PF);
	}
	return (status);
}

/*
 *		Write buffer command set up to download firmware
 */
int
g_scsi_writebuffer_cmd(int fd, int off, uchar_t *buf_ptr, int buf_len,
				int sp, int bid)
{
struct uscsi_cmd	ucmd;
my_cdb_g1	cdb = {SCMD_WRITE_BUFFER, 0x4, 0, 0, 0, 0, 0, 0, 0, 0};
struct	scsi_extended_sense	sense;

	if ((fd < 0) || (buf_ptr == NULL) || (buf_len < 0)) {
		return (L_INVALID_ARG);
	}

	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	cdb.byte1 |= sp;		/* set the save bit */
	cdb.byte2 = (char)(bid & 0xff);
	cdb.byte3 = off>>16;	/* bytes 3-5 contain file offset */
	cdb.byte4 = (off>>8) & 0xff;
	cdb.byte5 = off & 0xff;
	cdb.byte6 = buf_len>>16;	/* bytes 6-8 contain file length */
	cdb.byte7 = (buf_len>>8) & 0xff;
	cdb.byte8 = buf_len & 0xff;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)buf_ptr;
	ucmd.uscsi_buflen = buf_len;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 240;	/* long timeout required */

	return (cmd(fd, &ucmd, USCSI_WRITE));
}

/*
 *	Read buffer command set up to upload firmware
 *	Reads from code image starting at offset
 *	"code_off" for "buf_len" bytes.
 */
int
g_scsi_readbuffer_cmd(int fd, uchar_t *buf_ptr, int buf_len, int code_off)
{
struct uscsi_cmd	ucmd;
my_cdb_g1	cdb = {SCMD_READ_BUFFER, 0x5, 0, 0, 0, 0, 0, 0, 0, 0};
struct	scsi_extended_sense	sense;

	if ((fd < 0) || (buf_ptr == NULL) || (buf_len < 0)) {
		return (L_INVALID_ARG);
	}

	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	cdb.byte3 = (code_off >> 16) & 0xff;
	cdb.byte4 = (code_off >> 8) & 0xff;
	cdb.byte5 = code_off & 0xff;
	cdb.byte6 = buf_len>>16;	/* bytes 6-8 contain file length */
	cdb.byte7 = (buf_len>>8) & 0xff;
	cdb.byte8 = buf_len & 0xff;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)buf_ptr;
	ucmd.uscsi_buflen = buf_len;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 120;

	return (cmd(fd, &ucmd, USCSI_READ));
}

int
g_scsi_inquiry_cmd(int fd, uchar_t *buf_ptr, int buf_len)
{
struct uscsi_cmd	ucmd;
my_cdb_g0	cdb = {SCMD_INQUIRY, 0, 0, 0, 0, 0};
struct	scsi_extended_sense	sense;
int	myreturn;

	if ((fd < 0) || (buf_ptr == NULL) || (buf_len < 0)) {
		return (L_INVALID_ARG);
	}

	(void) memset(buf_ptr, 0, buf_len);
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	cdb.count = (uchar_t)buf_len;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)buf_ptr;
	ucmd.uscsi_buflen = buf_len;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 60;

	myreturn = cmd(fd, &ucmd, USCSI_READ | USCSI_SILENT);
	if (myreturn) {
	    return (myreturn);	    /* != 0, error just return */
	}

	/*
	 * This is a work around for the format of Daktari's
	 * SCSI inquiry page information.  The name of the enclosure
	 * is not in the same place that products like the a5000 place it
	 * so we have to copy the string to the expected location.
	 */
	if (strncmp((char *)&buf_ptr[16], DAK_PROD_STR,
			strlen(DAK_PROD_STR)) == 0) {
		strncpy((char *)&buf_ptr[96], (char *)&buf_ptr[DAK_BOXNAME_OFF],
		    DAK_BOXNAME_LEN);
	}

	return (myreturn);
}

int
g_scsi_log_sense_cmd(int fd, uchar_t *buf_ptr, int buf_len, uchar_t page_code)
{
struct uscsi_cmd	ucmd;
my_cdb_g1	cdb =  {SCMD_LOG_SENSE, 0, 0x40, 0, 0, 0, 0, 0, 0, 0};
struct	scsi_extended_sense	sense;

	if ((fd < 0) || (buf_ptr == NULL) || (buf_len < 0)) {
		return (L_INVALID_ARG);
	}

	/* clear buffers on cmds that read data */
	(void) memset(buf_ptr, 0, buf_len);
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	cdb.byte2 |= page_code;			/* requested page */
	cdb.byte7 = buf_len>>8;
	cdb.byte8 = buf_len & 0xff;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)buf_ptr;
	ucmd.uscsi_buflen = buf_len;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 120;
	return (cmd(fd, &ucmd, USCSI_READ));
}

/*
 *		MODE SELECT
 *
 *		MODE SELECT USCSI command
 *
 *		sp is the save pages bit  - Must be bit 0 -
 *
 */
int
g_scsi_mode_select_cmd(int fd, uchar_t *buf_ptr, int buf_len, uchar_t sp)
{
struct uscsi_cmd	ucmd;
/* 10 byte Mode Select cmd */
my_cdb_g1	cdb =  {SCMD_MODE_SELECT_G1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
struct	scsi_extended_sense	sense;

	if ((fd < 0) || (buf_ptr == NULL) || (buf_len < 0)) {
		return (L_INVALID_ARG);
	}

	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	cdb.byte1 = (sp & 1) | 0x10;		/* 0x10 is the PF bit  */
	cdb.byte7 = buf_len>>8;
	cdb.byte8 = buf_len & 0xff;

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)buf_ptr;
	ucmd.uscsi_buflen = buf_len;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 120;

	return (cmd(fd, &ucmd, USCSI_WRITE));
}


/*
 *		MODE SENSE USCSI command
 *
 *
 *		pc = page control field
 *		page_code = Pages to return
 */
int
g_scsi_mode_sense_cmd(int fd,
	uchar_t *buf_ptr,
	int buf_len,
	uchar_t pc,
	uchar_t page_code)
{
struct uscsi_cmd	ucmd;
/* 10 byte Mode Select cmd */
my_cdb_g1	cdb =  {SCMD_MODE_SENSE_G1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
struct	scsi_extended_sense	sense;
int		status;
static	int	uscsi_count;

	if ((fd < 0) || (buf_ptr == NULL) || (buf_len < 0)) {
		return (L_INVALID_ARG);
	}

	(void) memset(buf_ptr, 0, buf_len);
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	/* Just for me  - a sanity check */
	if ((page_code > MODEPAGE_ALLPAGES) || (pc > 3) ||
		(buf_len > MAX_MODE_SENSE_LEN)) {
		return (L_ILLEGAL_MODE_SENSE_PAGE);
	}
	cdb.byte2 = (pc << 6) + page_code;
	cdb.byte7 = buf_len>>8;
	cdb.byte8 = buf_len & 0xff;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)buf_ptr;
	ucmd.uscsi_buflen = buf_len;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 120;

	status = cmd(fd, &ucmd, USCSI_READ);
	/* Bytes actually transfered */
	if (status == 0) {
		uscsi_count = buf_len - ucmd.uscsi_resid;
		S_DPRINTF("  Number of bytes read on "
			"Mode Sense 0x%x\n", uscsi_count);
		if (getenv("_LUX_D_DEBUG") != NULL) {
			(void) g_dump("  Mode Sense data: ", buf_ptr,
			uscsi_count, HEX_ASCII);
		}
	}
	return (status);
}

int
g_scsi_read_capacity_cmd(int fd, uchar_t *buf_ptr, int buf_len)
{
struct uscsi_cmd	ucmd;
my_cdb_g1	cdb = {SCMD_READ_CAPACITY, 0, 0, 0, 0, 0, 0, 0, 0, 0};
struct	scsi_extended_sense	sense;

	if ((fd < 0) || (buf_ptr == NULL) || (buf_len < 0)) {
		return (L_INVALID_ARG);
	}

	/* clear buffers on on cmds that read data */
	(void) memset(buf_ptr, 0, buf_len);
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)buf_ptr;
	ucmd.uscsi_buflen = buf_len;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 60;
	return (cmd(fd, &ucmd, USCSI_READ));
}

int
g_scsi_read_capacity_1016_cmd(int fd,
		struct scsi_capacity_16 *cap_ptr, int buf_len)
{
struct uscsi_cmd	ucmd;
my_cdb_g1	cdb = {SCMD_READ_CAPACITY, 0, 0, 0, 0, 0, 0, 0, 0, 0};
struct scsi_extended_sense	sense;
struct scsi_capacity	cap_old;
int	ret;

	if ((fd < 0) || (cap_ptr == NULL) ||
		(buf_len < sizeof (struct scsi_capacity_16))) {
		return (L_INVALID_ARG);
	}

	/* clear buffers on on cmds that read data */
	(void) memset((char *)&cap_old, 0, sizeof (cap_old));
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)&cap_old;
	ucmd.uscsi_buflen = sizeof (cap_old);
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 60;

	ret = cmd(fd, &ucmd, USCSI_READ);
	if (cap_old.capacity == 0xffffffff) {
		/*
		 * A capacity of 0xffffffff in response to a
		 * READ CAPACITY 10 indicates that the lun
		 * is too large to report the size in a 32 bit
		 * value, and a READ CAPACITY 16 is required
		 * to get the correct size.
		 */
		ret = scsi_read_capacity_16_cmd(fd, cap_ptr, buf_len);
	} else {
		cap_ptr->sc_capacity = cap_old.capacity;
		cap_ptr->sc_lbasize = cap_old.lbasize;
	}
	return (ret);
}

static int
scsi_read_capacity_16_cmd(int fd,
		struct scsi_capacity_16 *cap_ptr, int buf_len)
{
struct uscsi_cmd	ucmd;
union scsi_cdb		cdb;
struct scsi_extended_sense	sense;

	if ((fd < 0) || (cap_ptr == NULL) ||
		(buf_len < sizeof (struct scsi_capacity_16))) {
		return (L_INVALID_ARG);
	}
	/* clear buffers on on cmds that read data */
	(void) memset((char *)cap_ptr, 0, buf_len);
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	(void) memset((char *)&cdb, 0, sizeof (union scsi_cdb));

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP4;
	ucmd.uscsi_bufaddr = (caddr_t)cap_ptr;
	ucmd.uscsi_buflen = buf_len;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 60;

	/*
	 * Read Capacity (16) is a Service Action In command.  One
	 * command byte (0x9E) is overloaded for multiple operations,
	 * with the second CDB byte specifying the desired operation
	 */
	cdb.scc_cmd = SCMD_SVC_ACTION_IN_G4;
	cdb.cdb_opaque[1] = SSVC_ACTION_READ_CAPACITY_G4;

	/*
	 * Fill in allocation length field
	 */
	cdb.cdb_opaque[10] =
		(uchar_t)((ucmd.uscsi_buflen & 0xff000000) >> 24);
	cdb.cdb_opaque[11] =
		(uchar_t)((ucmd.uscsi_buflen & 0x00ff0000) >> 16);
	cdb.cdb_opaque[12] =
		(uchar_t)((ucmd.uscsi_buflen & 0x0000ff00) >> 8);
	cdb.cdb_opaque[13] =
		(uchar_t)(ucmd.uscsi_buflen & 0x000000ff);

	return (cmd(fd, &ucmd, USCSI_READ));
}

int
g_scsi_release_cmd(int fd)
{
struct uscsi_cmd	ucmd;
const my_cdb_g0	cdb = {SCMD_RELEASE, 0, 0, 0, 0, 0};
struct	scsi_extended_sense	sense;

	if (fd < 0) {
		return (L_INVALID_ARG);
	}

	(void) memset((char *)&ucmd, 0, sizeof (ucmd));

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = NULL;
	ucmd.uscsi_buflen = 0;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 60;
	return (cmd(fd, &ucmd, 0));
}

int
g_scsi_reserve_cmd(int fd)
{
struct uscsi_cmd	ucmd;
const my_cdb_g0	cdb = {SCMD_RESERVE, 0, 0, 0, 0, 0};
struct	scsi_extended_sense	sense;

	if (fd < 0) {
		return (L_INVALID_ARG);
	}

	(void) memset((char *)&ucmd, 0, sizeof (ucmd));

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = NULL;
	ucmd.uscsi_buflen = 0;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 60;
	return (cmd(fd, &ucmd, 0));
}

int
g_scsi_start_cmd(int fd)
{
struct uscsi_cmd	ucmd;
/*
 * Use this to induce a SCSI error
 *	const my_cdb_g0	cdb = {SCMD_START_STOP, 0, 0xff, 0, 1, 0};
 */
const my_cdb_g0	cdb = {SCMD_START_STOP, 0, 0, 0, 1, 0};
struct	scsi_extended_sense	sense;

	if (fd < 0) {
		return (L_INVALID_ARG);
	}

	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = NULL;
	ucmd.uscsi_buflen = 0;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 240;	/* takes a while to start all */
	return (cmd(fd, &ucmd, 0));
}

int
g_scsi_stop_cmd(int fd, int immediate_flag)
{
struct uscsi_cmd	ucmd;
my_cdb_g0	cdb = {SCMD_START_STOP, 0, 0, 0, 0, 0};
struct	scsi_extended_sense	sense;

	if (fd < 0) {
		return (L_INVALID_ARG);
	}

	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	if (immediate_flag) {
		cdb.lba_msb = IMMED;
	}
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = NULL;
	ucmd.uscsi_buflen = 0;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 120;
	return (cmd(fd, &ucmd, 0));
}

int
g_scsi_tur(int fd)
{
struct uscsi_cmd	ucmd;
const my_cdb_g0	cdb = {SCMD_TEST_UNIT_READY, 0, 0, 0, 0, 0};
struct	scsi_extended_sense	sense;

	if (fd < 0) {
		return (L_INVALID_ARG);
	}

	(void) memset((char *)&ucmd, 0, sizeof (ucmd));

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = NULL;
	ucmd.uscsi_buflen = NULL;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 60;
	return (cmd(fd, &ucmd, 0));
}

/*
 * NOTE: This function includes a delay.
 */
int
g_scsi_reset(int fd)
{
struct uscsi_cmd	ucmd;
struct	scsi_extended_sense	sense;
int	err;

	if (fd < 0) {
		return (L_INVALID_ARG);
	}

	(void) memset((char *)&ucmd, 0, sizeof (ucmd));

	ucmd.uscsi_cdb = NULL;
	ucmd.uscsi_cdblen = NULL;
	ucmd.uscsi_bufaddr = NULL;
	ucmd.uscsi_buflen = NULL;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 60;
	if (err = cmd(fd, &ucmd, USCSI_RESET)) {
		return (err);
	}
	/*
	 * Allow time for things to stabilize.
	 */
	sleep(20);
	return (0);
}


/*
 * Description:
 *    Retrieves a devid from a device path.
 *
 * Input Values:
 *
 *    devpath: Valid block device path.
 *        Example:/devices/scsi_vhci/ssd@g280000602200416d6257333030303353:c,raw
 *
 *    devid: ptr to ddi_devid_t struct
 *    root: root handle to device tree snapshot
 *    drvr_name: driver name to start the node tree search
 * On success, devid points to device tree handle to devid
 * di_fini on root will invalidate devid pointer
 *
 * Return Value:
 *    0 on success
 *    non-zero on failure
 */
int
g_devid_get(char *devpath, ddi_devid_t *devid, di_node_t root,
		const char *drvr_name)
{
char *cptr;
char rootpath[MAXPATHLEN];
di_node_t node;
char *devfs_path = NULL;
hrtime_t	start_time, end_time;
char *env = NULL;

	if (devpath == NULL || devid == NULL || drvr_name == NULL) {
		return (L_INVALID_ARG);
	}

	if ((env = getenv("_LUX_T_DEBUG")) != NULL) {
		start_time = gethrtime();
	}

	*devid = NULL;
	rootpath[0] = '\0';

	/*
	 * Form a valid root path by stripping off the /devices/ mount point
	 * prefix and the minor name (:a[,raw]).
	 */
	if (strstr(devpath, DEV_PREFIX)) {
		strcat(rootpath, devpath + strlen(DEV_PREFIX) - 1);
		if (strchr(devpath, ':')) {
			cptr = strrchr(rootpath, ':');
			*cptr = '\0';
		} else {
			return (L_INVALID_PATH);
		}
	} else {
		return (L_INVALID_PATH);
	}

	/* point to first node which matches portdrvr */
	node = di_drv_first_node(drvr_name, root);
	if (node == DI_NODE_NIL) {
		/*
		 * Could not find driver node
		 */
		return (L_NO_DEVID);
	}

	while (node != DI_NODE_NIL) {
		if ((devfs_path = di_devfs_path(node)) != NULL) {
			if (strcmp(rootpath, devfs_path) == 0) {
				*devid = di_devid(node);
				di_devfs_path_free(devfs_path);
				break;
			}
			di_devfs_path_free(devfs_path);
		}
		node = di_drv_next_node(node);
	}

	if (env != NULL) {
		end_time = gethrtime();
		(void) fprintf(stdout,
		"      g_devid_get: "
		"\t\tTime = %lld millisec\n",
		(end_time - start_time)/1000000);
	}
	/* Did we get back a handle? */
	if (*devid != NULL) {
		return (0);
	} else { /* Couldn't get a devid. */
		return (L_NO_DEVID);
	}
}
