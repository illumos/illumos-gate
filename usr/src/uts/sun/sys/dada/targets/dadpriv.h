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

#ifndef _SYS_DADA_TARGET_DADPRIV_H
#define	_SYS_DADA_TARGET_DADPRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DIOCTL_RWCMD		5	/* read/write a disk 		*/

/*
 *  dadkio_rwcmd cmd
 */

#define	DADKIO_RWCMD_READ		1	/* read command */
#define	DADKIO_RWCMD_WRITE		2	/* write command */

/*
 * dadkio_rwcmd flags
 */
#define	DADKIO_FLAG_SILENT		0x01	/* driver should not */
						/* generate any warning */
						/* or error console msgs */
#define	DADKIO_FLAG_RESERVED		0x02	/* reserved/not used */


#define	DADKIO_ERROR_INFO_LEN	128

/*
 * dadkio_status status value.
 */
struct dadkio_status {
	int		status;
	ulong_t		resid;
	int		failed_blk_is_valid;
	daddr_t		failed_blk;
	int		fru_code_is_valid;
	int		fru_code;
	char		add_error_info[DADKIO_ERROR_INFO_LEN];
};

struct dadkio_status32 {
	int		status;
	uint32_t	resid;
	int		failed_blk_is_valid;
	daddr32_t	failed_blk;
	int		fru_code_is_valid;
	int		fru_code;
	char		add_error_info[DADKIO_ERROR_INFO_LEN];
};

/*
 * Used by read/write ioctl (DKIOCTL_RWCMD)
 */
struct dadkio_rwcmd {
	int			cmd;
	int			flags;
	daddr_t			blkaddr;
	uint_t			buflen;
	caddr_t			bufaddr;
	struct dadkio_status	status;
};

struct dadkio_rwcmd32 {
	int			cmd;
	int			flags;
	daddr32_t		blkaddr;
	uint_t			buflen;
	caddr32_t		bufaddr;
	struct dadkio_status32	status;
};


/*
 * dadkio_status status values
 */
#define	DADKIO_STAT_NO_ERROR		0	/* cmd was successful */
#define	DADKIO_STAT_NOT_READY		1	/* device not ready */
#define	DADKIO_STAT_MEDIUM_ERROR	2	/* error on medium */
#define	DADKIO_STAT_HARDWARE_ERROR	3	/* other hardware error */
#define	DADKIO_STAT_ILLEGAL_REQUEST	4	/* illegal request */
#define	DADKIO_STAT_ILLEGAL_ADDRESS	5	/* illegal block address */
#define	DADKIO_STAT_WRITE_PROTECTED	6	/* device write-protected */
#define	DADKIO_STAT_TIMED_OUT		7	/* no response from device */
#define	DADKIO_STAT_PARITY		8	/* parity error in data */
#define	DADKIO_STAT_BUS_ERROR		9	/* error on bus */
#define	DADKIO_STAT_SOFT_ERROR		10	/* data recovered via ECC */
#define	DADKIO_STAT_NO_RESOURCES	11	/* no resources for cmd */
#define	DADKIO_STAT_NOT_FORMATTED	12	/* device is not formatted */
#define	DADKIO_STAT_RESERVED		13	/* device is reserved */
#define	DADKIO_STAT_NOT_SUPPORTED	14	/* feature not supported */


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DADA_TARGET_DADPRIV_H */
