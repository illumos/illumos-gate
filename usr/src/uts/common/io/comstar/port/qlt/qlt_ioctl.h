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
 * Copyright 2009 QLogic Corporation.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_QLT_IOCTL_H
#define	_QLT_IOCTL_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * stmf error codes from qlt_ioctl
 */
typedef enum qlt_ioctl_err {
	QLTIO_NO_DUMP = 1,
	QLTIO_DUMP_INPROGRESS,
	QLTIO_NOT_ONLINE,
	QLTIO_INVALID_FW_SIZE,
	QLTIO_INVALID_FW_TYPE,
	QLTIO_ALREADY_FETCHED,
	QLTIO_MBOX_NOT_INITIALIZED,
	QLTIO_CANT_GET_MBOXES,
	QLTIO_MBOX_TIMED_OUT,
	QLTIO_MBOX_ABORTED,

	QLTIO_MAX_ERR
} qlt_ioctl_err_t;

#define	QLTIO_ERR_STRINGS	{ \
	"No additional information", \
	"No firmware dump available", \
	"Firmware dump in progress", \
	"Port is not online", \
	"Firmware size is invalid", \
	"Firmware type does not match this chip", \
	"Firmware dump already fetched by user", \
	"Mailboxes are not yet initialized", \
	"Mailboxes are not busy", \
	"Mailbox command timed out", \
	"Mailbox command got aborted", \
	"" \
	}

typedef struct qlt_fw_info {
	uint32_t	fwi_stay_offline:1,
			fwi_port_active:1,
			fwi_fw_uploaded:1,
			fwi_rsvd:29;
	uint16_t	fwi_active_major;
	uint16_t	fwi_active_minor;
	uint16_t	fwi_active_subminor;
	uint16_t	fwi_active_attr;
	uint16_t	fwi_loaded_major;
	uint16_t	fwi_loaded_minor;
	uint16_t	fwi_loaded_subminor;
	uint16_t	fwi_loaded_attr;
	uint16_t	fwi_default_major;
	uint16_t	fwi_default_minor;
	uint16_t	fwi_default_subminor;
	uint16_t	fwi_default_attr;
} qlt_fw_info_t;

typedef struct qlt_ioctl_mbox {
	uint16_t	to_fw[32];
	uint32_t	to_fw_mask;
	uint16_t	from_fw[32];
	uint32_t	from_fw_mask;
} qlt_ioctl_mbox_t;

#define	QLT_FWDUMP_BUFSIZE		(4 * 1024 * 1024)
/*
 * QLT IOCTLs
 */
#define	QLT_IOCTL_FETCH_FWDUMP		0x9001
#define	QLT_IOCTL_TRIGGER_FWDUMP	0x9002
#define	QLT_IOCTL_UPLOAD_FW		0x9003
#define	QLT_IOCTL_CLEAR_FW		0x9004
#define	QLT_IOCTL_GET_FW_INFO		0x9005
#define	QLT_IOCTL_STAY_OFFLINE		0x9006
#define	QLT_IOCTL_MBOX			0x9007
#define	QLT_IOCTL_ELOG			0x9008

#ifdef	__cplusplus
}
#endif

#endif /* _QLT_IOCTL_H */
