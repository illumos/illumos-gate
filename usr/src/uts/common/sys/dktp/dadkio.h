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

#ifndef _SYS_DKTP_DADKIO_H
#define	_SYS_DKTP_DADKIO_H

#ifdef	__cplusplus
extern "C" {
#endif

/*	direct coupled disk driver ioctl command			*/
#define	DIOCTL_GETGEOM		1	/* get logical disk geometry	*/
#define	DIOCTL_GETPHYGEOM	2	/* get physical disk geometry	*/
#define	DIOCTL_GETMODEL		3	/* get model number		*/
#define	DIOCTL_GETSERIAL	4	/* get serial number		*/
#define	DIOCTL_RWCMD		5	/* read/write a disk		*/
#define	DIOCTL_GETWCE		6	/* get write cache enabled state */

#if !defined(BLKADDR_TYPE)
#define	BLKADDR_TYPE
#if defined(_EXTVTOC)
typedef	unsigned long	blkaddr_t;
typedef	unsigned int	blkaddr32_t;
#else
typedef	daddr_t		blkaddr_t;
typedef	daddr32_t	blkaddr32_t;
#endif
#endif

/*
 * arg structure for DIOCTL_GETMODEL and DIOCTL_GETSERIAL
 * On input to the ioctl, is_size contains the size of the buffer
 * pointed to by is_buf;
 * On return, is_size contains the number of characters needed to
 * represent the string.  This may be more than the input value, in
 * which case the caller can choose to
 *  1. Use the truncated string as is
 *  2. Allocate a buffer of is_size+1 bytes to hold the string
 */
#ifdef _SYSCALL32
typedef struct dadk_ioc_string32
{
	caddr32_t	is_buf;		/* pointer to character array */
	int		is_size;	/* string length */
} dadk_ioc_string32_t;
#endif /* _SYSCALL32 */

typedef struct dadk_ioc_string
{
	caddr_t		is_buf;		/* pointer to character array */
	int 		is_size;	/* string length */
} dadk_ioc_string_t;

/*	direct coupled disk driver command				*/
#define	DCMD_READ	1	/* Read Sectors/Blocks 			*/
#define	DCMD_WRITE	2	/* Write Sectors/Blocks 		*/
#define	DCMD_FMTTRK	3	/* Format Tracks 			*/
#define	DCMD_FMTDRV	4	/* Format entire drive 			*/
#define	DCMD_RECAL	5	/* Recalibrate 				*/
#define	DCMD_SEEK	6	/* Seek to Cylinder 			*/
#define	DCMD_RDVER	7	/* Read Verify sectors on disk 		*/
#define	DCMD_GETDEF	8	/* Read manufacturers defect list	*/
/* cd-rom commands */
#define	DCMD_LOCK	9	/* Lock door				*/
#define	DCMD_UNLOCK	10	/* Unlock door				*/
#define	DCMD_START_MOTOR 11	/* Start motor				*/
#define	DCMD_STOP_MOTOR 12	/* Stop motor				*/
#define	DCMD_EJECT	13	/* Eject medium				*/
#define	DCMD_UPDATE_GEOM 14	/* Update geometry			*/
#define	DCMD_GET_STATE	15	/* Get removable disk status		*/
#define	DCMD_PAUSE	16	/* cdrom pause				*/
#define	DCMD_RESUME	17	/* cdrom resume				*/
#define	DCMD_PLAYTRKIND	18	/* cdrom play by track and index	*/
#define	DCMD_PLAYMSF	19	/* cdrom play msf			*/
#define	DCMD_SUBCHNL	20	/* cdrom sub channel			*/
#define	DCMD_READMODE1	21	/* cdrom read mode 1			*/
#define	DCMD_READTOCHDR	22	/* cdrom read table of contents header	*/
#define	DCMD_READTOCENT	23	/* cdrom read table of contents entry	*/
#define	DCMD_READOFFSET	24	/* cdrom read offset			*/
#define	DCMD_READMODE2	25	/* cdrom mode 2				*/
#define	DCMD_VOLCTRL	26	/* cdrom volume control			*/
/* additional disk commands */
#define	DCMD_FLUSH_CACHE 27	/* flush write cache to physical medium	*/

/*	driver error code						*/
#define	DERR_SUCCESS	0	/* success				*/
#define	DERR_AMNF	1	/* address mark not found		*/
#define	DERR_TKONF	2	/* track 0 not found			*/
#define	DERR_ABORT	3	/* aborted command			*/
#define	DERR_DWF	4	/* write fault				*/
#define	DERR_IDNF	5	/* ID not found				*/
#define	DERR_BUSY	6	/* drive busy				*/
#define	DERR_UNC	7	/* uncorrectable data error		*/
#define	DERR_BBK	8	/* bad block detected			*/
#define	DERR_INVCDB	9	/* invalid cdb				*/
#define	DERR_HARD	10	/* hard device error - no retry 	*/
/*
 * atapi additional error codes
 */
#define	DERR_ILI	11	/* Illegal length indication		*/
#define	DERR_EOM	12	/* End of media detected		*/
#define	DERR_MCR	13	/* Media change requested		*/
/*
 * atapi (SCSI) sense key errors
 */
#define	DERR_RECOVER	14	/* Recovered from error			*/
#define	DERR_NOTREADY	15	/* Device not ready			*/
#define	DERR_MEDIUM	16	/* Medium error				*/
#define	DERR_HW		17	/* Hardware error			*/
#define	DERR_ILL	18	/* Illegal request			*/
#define	DERR_UNIT_ATTN	19	/* Unit attention			*/
#define	DERR_DATA_PROT	20	/* Data protection			*/
#define	DERR_MISCOMP	21	/* Miscompare				*/
#define	DERR_ICRC	22	/* Interface CRC error -- new driver	*/
				/* error code in ATA-4 and newer	*/
#define	DERR_RESV	23	/* Reserved				*/

struct	dadkio_derr {
	int	d_action;
	int	d_severity;
};

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
	blkaddr_t	failed_blk;
	int		fru_code_is_valid;
	int		fru_code;
	char		add_error_info[DADKIO_ERROR_INFO_LEN];
};

#ifdef _SYSCALL32
struct dadkio_status32 {
	int		status;
	uint32_t	resid;
	int		failed_blk_is_valid;
	blkaddr32_t	failed_blk;
	int		fru_code_is_valid;
	int		fru_code;
	char		add_error_info[DADKIO_ERROR_INFO_LEN];
};
#endif /* _SYSCALL32 */

/*
 * Used by read/write ioctl (DKIOCTL_RWCMD)
 */
struct dadkio_rwcmd {
	int			cmd;
	int			flags;
	blkaddr_t		blkaddr;
	uint_t			buflen;
	caddr_t			bufaddr;
	struct dadkio_status	status;
};

#ifdef _SYSCALL32
struct dadkio_rwcmd32 {
	int			cmd;
	int			flags;
	blkaddr32_t		blkaddr;
	uint_t			buflen;
	caddr32_t		bufaddr;
	struct dadkio_status32	status;
};
#endif /* _SYSCALL32 */

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

#endif	/* _SYS_DKTP_DADKIO_H */
