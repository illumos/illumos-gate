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


#ifndef	__MMS_DMD_H__
#define	__MMS_DMD_H__

/* Begin: 32-bit align copyin() structs for amd64 only due to 32-bit x86 ABI */
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

#define	MMS_HDL_DIR	"/var/mms/handle"
#define	MMS_MAX_CMD	(32 * 1024)		/* Max cmd size to/from MMS */

#define	MMS_SER_NUM_LEN	64		/* max size of ser number */
#define	MMS_READ_SER_NUM_BUF_LEN (MMS_SER_NUM_LEN + 4)


/*
 * Struct to hold position
 */
typedef	struct	mms_pos {
	uint64_t	mms_pos;
}	mms_pos_t;

/*
 * Density request
 */
typedef	struct	mms_density {
	uint32_t	mms_den;
}	mms_density_t;

/*
 * Capacity request
 */
typedef	struct mms_capacity {
	/*
	 * Capacity is in megabytes (1048576)
	 */
	uint64_t	mms_max;		/* capacity of the cartridge */
	uint64_t	mms_avail;		/* amount available from EOD */
	uint32_t	mms_pc_avail;		/* percent available */
}	mms_capacity_t;

/*
 * Read block limit
 */
typedef	struct	mms_blk_limit {
	uint64_t	mms_max;		/* Max blocksize */
	uint32_t	mms_min;		/* Min blocksize */
	uint32_t	mms_gran;		/* granularity */
}	mms_blk_limit_t;

#define	MMS_SIDE(num)	"side " #num
#define	MMS_PART(num)	"Part" #num

/*
 * MMS ioctl's
 */
#define	MMS_IOC	(('S' << 24) | ('M' << 16) | ('M' << 8))

#define	MMS_BLK_LIMIT		(MMS_IOC | 1)	/* read block limit */
#define	MMS_GET_POS		(MMS_IOC | 2)	/* get position */
#define	MMS_LOCATE		(MMS_IOC | 3)	/* locate to position */
#define	MMS_FILE_OPT		(MMS_IOC | 4)	/* return file options */
#define	MMS_GET_CAPACITY	(MMS_IOC | 5)	/* return capacity */
#define	MMS_UPDATE_CAPACITY	(MMS_IOC | 6)	/* update cartridge capacity */
						/* in database */
#define	MMS_SET_DENSITY	(MMS_IOC | 7)	/* set density */
#define	MMS_GET_DENSITY	(MMS_IOC | 8)	/* get density */
#define	MMS_INQUIRY		(MMS_IOC | 9)	/* get inquiry data */

/*
 * MMS special pseudo sense key for beg of file and end of file.
 * They are returned in mt_erreg.
 */
#define	MMS_KEY_BOF		0xe0	/* At the beginning of file. */
#define	MMS_KEY_EOF		0xe1	/* At the end of file (not tapemark). */

/*
 * SCSI error
 */
typedef	struct	mms_scsi_err {
	uchar_t		mms_sk;		/* sense key */
	uchar_t		mms_asc;		/* additional sense code */
	uchar_t		mms_ascq;		/* additional sense code qual */
	char		mms_text[256];		/* error text */
}	mms_scsi_err_t;




/* End: 32-bit align copyin() structs for amd64 only due to 32-bit x86 ABI */
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#endif	/* __MMS_DMD_H__ */
