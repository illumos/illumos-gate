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
 * Copyright (c) 1991,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_DKMPIO_H
#define	_SYS_DKMPIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* from dualport: dkmpio.h 1.5 91/04/11 SMI	*/

/*
 * Structures and definitions for multi port disk io control commands
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Disk driver multi port state.
 * dk_gmpstate.dkg_mpstate and dk_smpstate.dks_mpstate values.
 */
enum dk_mpstate { DKS_INITIAL, DKS_OFFLINE, DKS_ONLINE, DKS_FREEZE};

/*
 * Disk drive protocol types
 * dk_mpinfo.dke_mptype values.
 */
enum dk_mptype { DKT_IPI, DKT_SCSI, DKT_UNKNOWN };

/*
 * Used for getting disk driver multi port state and status
 */
struct dk_gmpstate {
	enum dk_mpstate	dkg_mpstate;		/* output: current state */
	uint_t		dkg_fail_state;		/* output: fail state */
	uint_t		dkg_current_status; /* output: current drive status */
	int		dkg_pad[4];		/* Pads for future use */
};

/*
 * Used for setting driver multi port state and status
 */
struct dk_smpstate {
	enum dk_mpstate	dks_mpstate;		/* input: requested state */
	int		dks_pad[2];		/* Pads for future use */
};

/*
 * flags for current status, ro
 * dk_gmpstate.dkg_current_status definitions.
 */
#define	DKF_DRV_RESERVED	0x00000001	/* drive reserved */
#define	DKF_DRV_DUAL_ENABLED	0x00000002	/* both ports are enabled */
#define	DKF_DRV_RESET		0x00000004	/* drive was reset */
#define	DKF_DRV_WRTPROT		0x00000008	/* drive was write protect */
#define	DKF_DRV_BUSY		0x00000010	/* drive seems busy */
#define	DKF_DRV_TIMEOUT		0x00000020	/* drive timed out */
#define	DKF_DRV_DUALPORTED	0x00000040	/* drive is used dual ported */
#define	DKF_DRV_ALTRSVD		0x00000080	/* Alternate port reserved */
#define	DKF_ADAPT_RESERVED	0x00000100	/* host adaptor reserved */
#define	DKF_ADAPT_RESET		0x00000400	/* host adaptor was reset */
#define	DKF_ADAPT_BUSY		0x00001000	/* host adaptor seems busy */
#define	DKF_ADAPT_TIMEOUT	0x00002000	/* host adaptor timed out */
#define	DKF_CTLR_RESERVED	0x00010000	/* ctlr reserved */
#define	DKF_CTLR_RESET		0x00040000	/* ctlr was reset */
#define	DKF_CTLR_BUSY		0x00100000	/* host adaptor seems busy */
#define	DKF_CTLR_TIMEOUT	0x02000000	/* host adaptor timed out */

/*
 * Volatile disk drive fail state flags, ro
 * dk_gmpstate.dkg_fail_state flags definitions.
 */
#define	DKF_DRV_RSV_LOST	0x00000001	/* drive lost reservation */
#define	DKF_CTLR_RSV_LOST	0x00000002	/* ctlr lost reservation */
#define	DKF_DRV_DIAGNOSED	0x00000004	/* drive self diag. */
						/* reports error */
#define	DKF_CTLR_DIAGNOSED	0x00000008	/* ctlr self diag. */
						/* reports error */
#define	DKF_ADAPT_DIAGNOSED	0x00000010	/* host adapt. self diag. */
						/* reports error */
#define	DKF_DRV_FAILED		0x00001000	/* drive failure */
#define	DKF_CTLR_FAILED		0x00100000	/* controller failure */
#define	DKF_ADAPT_FAILED	0x10000000	/* host adaptor failure */

/*
 * Used for getting disk drive error counts
 */
struct dk_mpdrv_status {
	uint_t	dkd_cum_drv_soft_errors; /* cumulative drive soft errors */
	uint_t	dkd_cum_drv_hard_errors; /* cumulative drive media errors */
	uint_t	dkd_cum_drv_retries;	/* cumulative successful drive */
					/* retries on media errors */
	int	dkd_pad[4];		/* Pads for future use */
};

/*
 * Used to set/get the configuration and control/status flags
 */
struct dk_mpflags {
	uint_t	dkf_config_flags;		/* config flags, ro */
	uint_t	dkf_control_flags;		/* control flags, rw */
	int	dkf_pad[4];			/* Pads for future use */
};

/*
 * Volatile disk drive configuration status flags, ro
 * dk_mpflags.dkf_config_flags definitions.
 */
#define	DKF_DRV_NOEXIST		0x00000001	/* non-existent drive */
#define	DKF_CTLR_NOEXIST	0x00000002	/* non-existent controller */
#define	DKF_ADAPT_NOEXIST	0x00000004	/* non-existent host adaptor */

/*
 * Non-destructive configuration control flags, r/w
 * dk_mpflags.dkf_control_flags definitions.
 */
#define	DKF_ORDERED		0x00000001	/* write ordering of sectors */
#define	DKF_PANIC_ABORT		0x00000002	/* commands aborted at panic */
#define	DKF_RERUN_UNR_CMDS	0x00000004	/* rerun commands after reset */
						/* on unreserved unit occurs */
#define	DKF_RERUN_RSV_CMDS	0x00000008	/* rerun commands after reset */
						/* on reserved unit occurs */
#define	DKF_AUTOFAIL		0x00000010	/* make drive/ctlr/adapter */
						/* unavailable after a */
						/* failure */



/*
 * Extended info: used for getting all the multi port info
 */
struct dk_mpinfo {
	struct dk_gmpstate	dke_mpstate; /* current state & drive status */
	struct dk_mpflags	dke_mpflags;	/* config/control flags */
	struct dk_mpdrv_status	dke_mpdrv_status; /* cumulative for errors */
	enum dk_mptype		dke_mptype;	/* drive type */
	int			dke_qcapacity;	/* min freeze queue capacity */
	uint_t			dke_max_quiesce; /* maxtime to quiesce drive */
	int			dke_pad[4];	/* Pads for future use */
};

/*
 * Used for reserve, release, reset, abort, probe and reinitialization.
 * May use with the "common command list" flags.
 */
struct dk_mpcmd {
	uint_t		dkc_mpcmd;		/* command */
	uint_t		dkc_mpflags;		/* execution flags */
	caddr_t		dkc_bufaddr;		/* user's buffer address */
	uint_t 		dkc_buflen;		/* size of user's buffer */
	int		dkc_pad[4];		/* Pads for future use */
};

/*
 * Common command list, for all protocols.
 * dk_mpcmd.dkc_mpcmd definitions.
 */
#define	DKF_RESERVE	0x00000001		/* reserve drive */
#define	DKF_RELEASE	0x00000002		/* release drive */
#define	DKF_RESET	0x00000004		/* reset drive */
#define	DKF_ABORT	0x00000008		/* abort all cmds */
#define	DKF_PROBE	0x00000010		/* ping drive */
#define	DKF_REINIT	0x00000020		/* reinitialize drive */

/*
 * Execution flags.
 * dk_mpcmd.dkc_mpflags definitions.
 */
#define	DKF_DIAGNOSE	0x00000001	/* fail if any error occurs */
#define	DKF_ISOLATE	0x00000002	/* isolate from normal commands */
#define	DKF_READ	0x00000004	/* get data from device */
#define	DKF_WRITE	0x00000008	/* send data to device */
#define	DKF_DESTRUCTIVE	0x00000010	/* destructive action ok */

/*
 * Disk io control commands
 */
#define	DKIOCGMPINFO	(DIOC | 90) /* struct dk_mpinfo Get mp info */
#define	DKIOCGMPSTATE	(DIOC | 91) /* struct dk_gmpstate Get mp state */
#define	DKIOCSMPSTATE	(DIOC | 92) /* struct dk_smpstate Set mp state */
#define	DKIOCGSTATUS	(DIOC | 93) /* struct dk_mpdrv_status Get drv status */
#define	DKIOCGMPFLAGS	(DIOC | 94) /* struct dk_mpflags Get mp flags */
#define	DKIOCSMPFLAGS	(DIOC | 95) /* struct dk_mpflags Set mp flags */
#define	DKIOCSMPCMD	(DIOC | 96) /* struct dk_mpcmd Set generic mp cmd */

#ifdef __cplusplus
}
#endif

#endif	/* !_SYS_DKMPIO_H */
