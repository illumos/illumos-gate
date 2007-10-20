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

#ifndef _SYS_DKTP_DADK_H
#define	_SYS_DKTP_DADK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/dktp/tgcom.h>

struct	dadk {
	struct tgdk_ext	*dad_extp;	/* back pointer to ext data	*/
	struct scsi_device *dad_sd;	/* back pointer to SCSI_DEVICE 	*/

	struct  tgdk_geom dad_logg;	/* logical disk geometry 	*/
	struct  tgdk_geom dad_phyg;	/* physical disk geometry 	*/

	unsigned dad_rmb : 1;		/* removable device		*/
	unsigned dad_rdonly : 1;	/* read only device		*/
	unsigned dad_cdrom : 1;		/* cdrom device			*/
	unsigned dad_noflush : 1;	/* flush cmd unsupported	*/
	unsigned dad_wce : 1;		/* disk write cache enabled	*/
	unsigned dad_resv : 3;
	unsigned char dad_type;		/* device type			*/
	unsigned char dad_ctype;	/* controller type 		*/

	short	 dad_secshf;
	short	 dad_blkshf;

	opaque_t dad_bbhobjp;		/* bbh object ptr		*/
	opaque_t dad_flcobjp;		/* flow control object ptr	*/
	opaque_t dad_ctlobjp;		/* controller object ptr	*/
	struct	tgcom_obj dad_com;	/* com object for flowctrl	*/
	enum dkio_state dad_iostate;	/* ejected/inserted		*/
	kmutex_t	dad_mutex;	/* protect dad_state		*/
	kcondvar_t	dad_state_cv;	/* condition variable for state */
	uchar_t		dad_thread_cnt;	/* reference count on removable	*/
					/* - disk state watcher thread	*/
	kstat_t		*dad_errstats;	/* error stats			*/
	kmutex_t	dad_cmd_mutex;
	int		dad_cmd_count;
};

#define	DAD_SECSIZ	dad_phyg.g_secsiz

/*
 * Local definitions, for clarity of code
 */

/*
 * Parameters
 */
#define	DADK_BSY_TIMEOUT	(drv_usectohz(5 * 1000000))
#define	DADK_IO_TIME		35
#define	DADK_FLUSH_CACHE_TIME	60
#define	DADK_RETRY_COUNT	5
#define	DADK_SILENT		1

#define	PKT2DADK(pktp)	((struct dadk *)(pktp)->cp_dev_private)

/*
 * packet action codes
 */
#define	COMMAND_DONE		0
#define	COMMAND_DONE_ERROR	1
#define	QUE_COMMAND		2
#define	QUE_SENSE		3
#define	JUST_RETURN		4

typedef	struct	dadk_errstats {
	kstat_named_t dadk_softerrs;		/* Collecting Softerrs */
	kstat_named_t dadk_harderrs;		/* Collecting harderrs */
	kstat_named_t dadk_transerrs;		/* Collecting Transfer errs */
	kstat_named_t dadk_model;		/* model # of the disk */
	kstat_named_t dadk_revision;		/* The disk revision */
	kstat_named_t dadk_serial;		/* The disk serial number */
	kstat_named_t dadk_capacity;		/* Capacity of the disk */
	kstat_named_t dadk_rq_media_err;	/* Any media err seen */
	kstat_named_t dadk_rq_ntrdy_err;	/* Not ready errs */
	kstat_named_t dadk_rq_nodev_err;	/* No device errs */
	kstat_named_t dadk_rq_recov_err;	/* Recovered errs */
	kstat_named_t dadk_rq_illrq_err;	/* Illegal requests */
} dadk_errstats_t;

int dadk_init(opaque_t objp, opaque_t devp, opaque_t flcobjp,
    opaque_t queobjp, opaque_t bbhobjp, void *lkarg);
int dadk_free(struct tgdk_obj *dkobjp);
int dadk_probe(opaque_t objp, int kmsflg);
int dadk_attach(opaque_t objp);
int dadk_open(opaque_t objp, int flag);
int dadk_close(opaque_t objp);
int dadk_ioctl(opaque_t objp, dev_t dev, int cmd, intptr_t arg,
    int flag, cred_t *cred_p, int *rval_p);
int dadk_flushdone(struct buf *bp);
int dadk_strategy(opaque_t objp, struct buf *bp);
int dadk_setgeom(opaque_t objp, struct tgdk_geom *dkgeom_p);
int dadk_getgeom(opaque_t objp, struct tgdk_geom *dkgeom_p);
struct tgdk_iob *dadk_iob_alloc(opaque_t objp, daddr_t blkno,
    ssize_t xfer, int kmsflg);
int dadk_iob_free(opaque_t objp, struct tgdk_iob *iobp);
caddr_t dadk_iob_htoc(opaque_t objp, struct tgdk_iob *iobp);
caddr_t dadk_iob_xfer(opaque_t objp, struct tgdk_iob *iobp, int rw);
int dadk_dump(opaque_t objp, struct buf *bp);
int dadk_getphygeom(opaque_t objp, struct tgdk_geom *dkgeom_p);
int dadk_set_bbhobj(opaque_t objp, opaque_t bbhobjp);
int dadk_check_media(opaque_t objp, int *state);
static void dadk_watch_thread(struct dadk *dadkp);
int dadk_inquiry(opaque_t objp, opaque_t *inqpp);
void dadk_cleanup(struct tgdk_obj *dkobjp);

int dadk_getcmds(opaque_t objp);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_DADK_H */
