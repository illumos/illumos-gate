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

#ifndef	_FCP_UTIL_H
#define	_FCP_UTIL_H



#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>


#define	FCP_TGT_INQUIRY		0x01
#define	FCP_TGT_CREATE		0x02
#define	FCP_TGT_DELETE		0x04
#define	FCP_TGT_SEND_SCSI	0x08
#define	FCP_STATE_COUNT		0x10
#define	FCP_GET_TARGET_MAPPINGS	0x11

struct	fcp_ioctl {
	minor_t		fp_minor;
	uint32_t	listlen;
	caddr_t		list;
};

struct	device_data {
	la_wwn_t	dev_pwwn;
	int		dev_status;
	int		dev_lun_cnt;
	uchar_t		dev0_type;
};

struct fcp_scsi_cmd {
	uint32_t	scsi_fc_port_num;
	la_wwn_t	scsi_fc_pwwn;
	uint32_t	scsi_fc_status;
	uint32_t	scsi_fc_rspcode;
	uchar_t		scsi_pkt_state;
	uchar_t		scsi_pkt_action;
	uint32_t	scsi_pkt_reason;
	uint64_t	scsi_lun;
	uint32_t	scsi_flags;
	uint32_t	scsi_timeout;
	caddr_t		scsi_cdbbufaddr;
	uint32_t	scsi_cdblen;
	caddr_t		scsi_bufaddr;
	uint32_t	scsi_buflen;
	int32_t		scsi_bufresid;
	uint32_t	scsi_bufstatus;
	caddr_t		scsi_rqbufaddr;
	uint32_t	scsi_rqlen;
	int32_t		scsi_rqresid;
};

typedef struct fc_hba_mapping_entry {
    char			targetDriver[MAXPATHLEN];
    uint32_t			d_id;
    uint32_t			busNumber;
    uint32_t			targetNumber;
    uint32_t			osLUN;
    uint64_t			samLUN;
    la_wwn_t			NodeWWN;
    la_wwn_t			PortWWN;
    uint8_t			guid[256];
} fc_hba_mapping_entry_t;

#define	FC_HBA_TARGET_MAPPINGS_VERSION		1
typedef struct fc_hba_target_mappings {
    uint32_t			version;
    uint32_t			numLuns;
    uint64_t			reserved;
    fc_hba_mapping_entry_t	entries[1];
} fc_hba_target_mappings_t;

/*
 * flags for scsi_flags field of fcp_scsi_cmd structure
 */
#define	FCP_SCSI_READ	0x0001	/* get data from device */


#if defined(_SYSCALL32)
/*
 * 32 bit variant of fcp_ioctl and fcp_scsi_cmd
 * used only in the driver.
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

struct	fcp32_ioctl {
	minor_t		fp_minor;
	uint32_t	listlen;
	caddr32_t	list;
};

struct fcp32_scsi_cmd {
	uint32_t	scsi_fc_port_num;
	la_wwn_t	scsi_fc_pwwn;
	uint32_t	scsi_fc_status;
	uint32_t	scsi_fc_rspcode;
	uchar_t		scsi_pkt_state;
	uchar_t		scsi_pkt_action;
	uint32_t	scsi_pkt_reason;
	uint64_t	scsi_lun;
	uint32_t	scsi_flags;
	uint32_t	scsi_timeout;
	caddr32_t	scsi_cdbbufaddr;
	uint32_t	scsi_cdblen;
	caddr32_t	scsi_bufaddr;
	uint32_t	scsi_buflen;
	int32_t		scsi_bufresid;
	uint32_t	scsi_bufstatus;
	caddr32_t	scsi_rqbufaddr;
	uint32_t	scsi_rqlen;
	int32_t		scsi_rqresid;
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#define	FCP32_SCSI_CMD_TO_FCP_SCSI_CMD(cmd32, cmd)			\
	(cmd)->scsi_fc_port_num	= (cmd32)->scsi_fc_port_num;		\
	bcopy(&((cmd32)->scsi_fc_pwwn), &((cmd)->scsi_fc_pwwn),		\
			sizeof ((cmd)->scsi_fc_pwwn));			\
	(cmd)->scsi_fc_status	= (cmd32)->scsi_fc_status;		\
	(cmd)->scsi_fc_rspcode	= (cmd32)->scsi_fc_rspcode;		\
	(cmd)->scsi_pkt_state	= (cmd32)->scsi_pkt_state;		\
	(cmd)->scsi_pkt_action	= (cmd32)->scsi_pkt_action;		\
	(cmd)->scsi_pkt_reason	= (cmd32)->scsi_pkt_reason;		\
	(cmd)->scsi_lun		= (cmd32)->scsi_lun;			\
	(cmd)->scsi_flags	= (cmd32)->scsi_flags;			\
	(cmd)->scsi_timeout	= (cmd32)->scsi_timeout;		\
	(cmd)->scsi_cdbbufaddr	= (caddr_t)(long)(cmd32)->scsi_cdbbufaddr; \
	(cmd)->scsi_cdblen	= (cmd32)->scsi_cdblen;			\
	(cmd)->scsi_bufaddr	= (caddr_t)(long)(cmd32)->scsi_bufaddr;	\
	(cmd)->scsi_buflen	= (cmd32)->scsi_buflen;			\
	(cmd)->scsi_bufresid	= (cmd32)->scsi_bufresid;		\
	(cmd)->scsi_bufstatus	= (cmd32)->scsi_bufstatus;		\
	(cmd)->scsi_rqbufaddr	= (caddr_t)(long)(cmd32)->scsi_rqbufaddr; \
	(cmd)->scsi_rqlen	= (cmd32)->scsi_rqlen;			\
	(cmd)->scsi_rqresid	= (cmd32)->scsi_rqresid;

#define	FCP_SCSI_CMD_TO_FCP32_SCSI_CMD(cmd, cmd32)			\
	(cmd32)->scsi_fc_port_num = (cmd)->scsi_fc_port_num;		\
	bcopy(&((cmd)->scsi_fc_pwwn), &((cmd32)->scsi_fc_pwwn),		\
			sizeof ((cmd32)->scsi_fc_pwwn));		\
	(cmd32)->scsi_fc_status	= (cmd)->scsi_fc_status;		\
	(cmd32)->scsi_fc_rspcode = (cmd)->scsi_fc_rspcode;		\
	(cmd32)->scsi_pkt_state	= (cmd)->scsi_pkt_state;		\
	(cmd32)->scsi_pkt_action = (cmd)->scsi_pkt_action;		\
	(cmd32)->scsi_pkt_reason = (cmd)->scsi_pkt_reason;		\
	(cmd32)->scsi_lun	= (cmd)->scsi_lun;			\
	(cmd32)->scsi_flags	= (cmd)->scsi_flags;			\
	(cmd32)->scsi_timeout	= (cmd)->scsi_timeout;			\
	(cmd32)->scsi_cdbbufaddr = (caddr32_t)(long)(cmd)->scsi_cdbbufaddr; \
	(cmd32)->scsi_cdblen	= (cmd)->scsi_cdblen;			\
	(cmd32)->scsi_bufaddr	= (caddr32_t)(long)(cmd)->scsi_bufaddr;	\
	(cmd32)->scsi_buflen	= (cmd)->scsi_buflen;			\
	(cmd32)->scsi_bufresid	= (cmd)->scsi_bufresid;			\
	(cmd32)->scsi_bufstatus	= (cmd)->scsi_bufstatus;		\
	(cmd32)->scsi_rqbufaddr	= (caddr32_t)(long)(cmd)->scsi_rqbufaddr; \
	(cmd32)->scsi_rqlen	= (cmd)->scsi_rqlen;			\
	(cmd32)->scsi_rqresid	= (cmd)->scsi_rqresid;

#endif /* _SYSCALL32 */

#if !defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("Unshared Data", device_data))
_NOTE(SCHEME_PROTECTS_DATA("Unshared Data", fcp_scsi_cmd))
#endif /* __lint */

#ifdef	__cplusplus
}
#endif

#endif	/* _FCP_UTIL_H */
