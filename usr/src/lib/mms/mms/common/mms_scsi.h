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

#ifndef	__MMS_SCSI_H
#define	__MMS_SCSI_H


#include <sys/list.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MMS_MAX_CDB_LEN	32		/* max cdb length (bytes) */
#define	MMS_SENSEKEY(sen)	((sen)[2] & 0x0f)
#define	MMS_ASC(sen)		((sen)[12])
#define	MMS_ASCQ(sen)		((sen)[13])

typedef	struct	mms_skey_specific {
#if defined(_BIT_FIELDS_HTOL)
	uchar_t	mms_sksv	: 1,		/* SKV */
		mms_cd		: 1,		/* cmd / data */
		mms_reserved	: 2,
		mms_bpv	: 1,
		mms_bitptr	: 3;		/* bit pointer */
#elif defined(_BIT_FIELDS_LTOH)
	uchar_t	mms_bitptr	: 3,		/* bit pointer */
		mms_bpv	: 1,
		mms_reserved	: 2,
		mms_cd		: 1,		/* cmd / data */
		mms_sksv	: 1;		/* SKV */
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
	uchar_t	mms_fp[2];			/* field pointer */
}	mms_skey_specific_t;

char *mms_scsi_cmd(int cmd);
char *mms_scsi_status(int stat);
char *mms_scsi_sensekey(int senkey);
char *mms_scsi_asc(int asc);
char *mms_scsi_ascq(int ascq);
char *mms_format_sense(struct scsi_extended_sense *sen);



#ifdef	__cplusplus
}
#endif

#endif	/* __MMS_SCSI_H */
