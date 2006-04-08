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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#ifndef	_SCFSNAP_H
#define	_SCFSNAP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ioctl
 */
#define	SCFIOCSNAP		's'<<8

/*
 * ioctl
 */
#define	SCFIOCSNAPSHOTSIZE	(SCFIOCSNAP|1|0x80040000)
#define	SCFIOCSNAPSHOT		(SCFIOCSNAP|2|0x80040000)

/* SCFIOCSNAPSHOTSIZE */
typedef struct scfsnapsize {
	int		type;
	int		info;
	int		size;
} scfsnapsize_t;

/* SCFIOCSNAPSHOT */
typedef struct scfsnap_value {
	char		ss_name[32];
	int		ss_flag;
	int		ss_rsv1;
	int		ss_size;
	int		ss_nextoff;
} scfsnap_value_t;
/* for ss_name field */
#define	SNAP_SCF_DRIVER_VL	"scf_driver_vl"
#define	SNAP_SCF_COMTBL		"scf_comtbl"
#define	SNAP_SCF_STATE		"scf_state"
#define	SNAP_SCF_TIMER_TBL	"scf_timer"
#define	SNAP_SCF_DSCP_COMTBL	"scf_dscp_comtbl"
#define	SNAP_SCF_DSCP_TXDSC	"scf_dscp_txdsc"
#define	SNAP_SCF_DSCP_RXDSC	"scf_dscp_rxdsc"
#define	SNAP_SCF_DSCP_TXSRAM	"scf_dscp_txsram"
#define	SNAP_SCF_DSCP_EVENT	"scf_dscp_event"
#define	SNAP_SCF_DSCP_RDATA	"scf_dscp_rdata"
#define	SNAP_REGISTER		"REGISTER"
#define	SNAP_SRAM		"SRAM"

/* for ss_flag field */
#define	SCF_DRIVER_64BIT	64
#define	SCF_DRIVER_32BIT	32

typedef struct scfsnap {
	int		type;
	int		info;
	scfsnap_value_t	*ss_entries;
} scfsnap_t;
/* for 32bit */
typedef struct scfsnap32 {
	int		type;
	int		info;
	caddr32_t	ss_entries;
} scfsnap32_t;
/* for type field */
#define	SCFSNAPTYPE_ALL		1
#define	SCFSNAPTYPE_DRIVER	2
#define	SCFSNAPTYPE_REGISTER	3
#define	SCFSNAPTYPE_SRAM	4

/* for info field */
#define	SCFSNAPINFO_AUTO	(-1)

/*
 * External function
 */
extern int	scf_snapshotsize(intptr_t arg, int mode);
extern int	scf_get_snapize(int type, int info);
extern int	scf_snapshot(intptr_t arg, int mode);
extern int	scf_get_snap(int type, int info, scfsnap_value_t *snap_p,
			int snap_size);

#ifdef	__cplusplus
}
#endif

#endif /* _SCFSNAP_H */
