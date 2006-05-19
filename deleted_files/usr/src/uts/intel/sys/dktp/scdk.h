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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_DKTP_SCDK_H
#define	_SYS_DKTP_SCDK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct	scdk {
	struct tgdk_ext	*scd_extp;	/* back pointer to ext data	*/
	struct scsi_device *scd_sd;	/* back pointer to SCSI_DEVICE 	*/

	short	scd_secshf;
	short	scd_blkshf;
	struct  tgdk_geom scd_logg;	/* logical disk geometry 	*/
	struct  tgdk_geom scd_phyg;	/* physical disk geometry 	*/

	unsigned scd_rmb : 1;		/* removable device		*/
	unsigned scd_rdonly : 1;	/* read only device		*/
	unsigned scd_arq : 1;		/* auto-request sense enable	*/
	unsigned scd_tagque : 1;	/* tagged queueing enable	*/
	unsigned scd_cdrom : 1;		/* cdrom device			*/
	unsigned scd_resv : 3;
	unsigned char scd_type;		/* device type			*/
	unsigned char scd_ctype;	/* controller type 		*/
	unsigned char scd_options;	/* drive options 		*/
	long	scd_pktflag;		/* scsi packet flag option 	*/

	opaque_t scd_flcobjp;		/* flow control object ptr	*/
	struct	tgcom_obj scd_com;	/* com object for flowctrl	*/
	opaque_t scd_cdobjp;		/* CDrom object pointer		*/
	char	scd_cdname[OBJNAMELEN];	/* CDrom object name		*/
	struct	tgpassthru_obj scd_passthru; /* passthru obj for CDrom	*/
	int	(*scd_cdioctl)();	/* indirect func for cdioctl	*/
	enum dkio_state scd_iostate;	/* ejected/inserted		*/
	kmutex_t	scd_mutex;	/* protect scd_state		*/
	kcondvar_t	scd_state_cv;	/* condition variable for state */

	int	scd_drvready;		/* drive has been started	*/
	ksema_t	scd_drvsema;		/* semaphore to protect status	*/
	void	(*scd_cbfunc)();	/* ptr to cmdk_devstatus()	*/
	void	*scd_cbarg;		/* ptr to (struct cmdk *)	*/
};

#define	SCD_SECSIZ	scd_phyg.g_secsiz

/*
 * Local definitions, for clarity of code
 */

/*
 * Parameters
 */
#define	SD_BSY_TIMEOUT	(drv_usectohz(5 * 1000000))
#define	SD_IO_TIME	60
#define	SD_RETRY_COUNT	5
#define	SD_OPEN_RETRY_COUNT	2

#define	SCDK_IOSTART	0
#define	SCDK_IOCONT	1
#define	SCDK_RTYCNT	3

#define	SCDK2ADDR(scdkp) ((struct scsi_address *)&((scdkp)->scd_sd->sd_address))
#define	PKT2SCDK(pktp)	((struct scdk *)SC_XPKTP((pktp))->x_sdevp)

#define	SCDK_GETGEOM_HEAD(X) (((X) >> 16) & 0xff)
#define	SCDK_GETGEOM_SEC(X)  ((X) & 0xff)

#define	SCDK_DRIVE_READY(scdkp)	((scdkp)->scd_drvready)

#define	SCDK_SET_DRIVE_READY(scdkp, state) { 			\
	sema_p(&(scdkp)->scd_drvsema);				\
	(scdkp)->scd_drvready = (state);			\
	sema_v(&(scdkp)->scd_drvsema);				\
	if ((scdkp)->scd_cbfunc != NULL)			\
		((scdkp)->scd_cbfunc)((scdkp)->scd_cbarg);	\
}

/* use 10 byte cdbs */
#define	SCDK_OPTION_CDB10_FLAG	1

#define	SCDK_OPTION_CDB10(scdkp)	\
		((scdkp)->scd_options & SCDK_OPTION_CDB10_FLAG)

#ifndef TRUE
#define	TRUE	1
#endif

#ifndef	FALSE
#define	FALSE	0
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_SCDK_H */
