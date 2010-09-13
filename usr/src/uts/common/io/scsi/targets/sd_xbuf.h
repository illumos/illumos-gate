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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SCSI_TARGETS_SD_XBUF_H
#define	_SYS_SCSI_TARGETS_SD_XBUF_H

#ifdef	__cplusplus
extern "C" {
#endif

#if	defined(_KERNEL) || defined(_KMEMUSER)

#include <sys/note.h>
#include <sys/taskq.h>


#if (defined(__fibre))
/*
 * These #defines are to avoid namespace collisions that occur because this
 * code is currently used to compile two seperate driver modules: sd and ssd.
 * All function names need to be treated this way (even if declared static)
 * in order to allow the debugger to resolve the names properly.
 * It is anticipated that in the near future the ssd module will be obsoleted,
 * at which time this ugliness should go away.
 */
#define	ddi_xbuf_attr_create		ssd_ddi_xbuf_attr_create
#define	ddi_xbuf_attr_destroy		ssd_ddi_xbuf_attr_destroy
#define	ddi_xbuf_attr_register_devinfo	ssd_ddi_xbuf_attr_register_devinfo
#define	ddi_xbuf_attr_unregister_devinfo	\
					ssd_ddi_xbuf_attr_unregister_devinfo
#define	ddi_xbuf_qstrategy		ssd_ddi_xbuf_qstrategy
#define	ddi_xbuf_done			ssd_ddi_xbuf_done
#define	ddi_xbuf_get			ssd_ddi_xbuf_get
#define	xbuf_iostart			ssd_xbuf_iostart
#define	xbuf_dispatch			ssd_xbuf_dispatch
#define	xbuf_restart_callback		ssd_xbuf_restart_callback
#define	xbuf_tq				ssd_xbuf_tq
#define	xbuf_attr_tq_minalloc		ssd_xbuf_attr_tq_minalloc
#define	xbuf_attr_tq_maxalloc		ssd_xbuf_attr_tq_maxalloc
#define	xbuf_mutex			ssd_xbuf_mutex
#define	xbuf_refcount			ssd_xbuf_refcount

#define	ddi_xbuf_dispatch		ssd_ddi_xbuf_dispatch

#define	ddi_xbuf_flushq			ssd_ddi_xbuf_flushq
#define	ddi_xbuf_attr_setup_brk		ssd_ddi_xbuf_attr_setup_brk

#endif


typedef void *		ddi_xbuf_t;


/*
 * Primary attribute struct for buf extensions.
 */
struct __ddi_xbuf_attr {
	kmutex_t	xa_mutex;
	size_t		xa_allocsize;
	uint32_t	xa_pending;	/* call to xbuf_iostart() is iminent */
	uint32_t	xa_active_limit;
	uint32_t	xa_active_count;
	uint32_t	xa_active_lowater;
	struct buf	*xa_headp;	/* FIFO buf queue head ptr */
	struct buf	*xa_tailp;	/* FIFO buf queue tail ptr */
	kmutex_t	xa_reserve_mutex;
	uint32_t	xa_reserve_limit;
	uint32_t	xa_reserve_count;
	void		*xa_reserve_headp;
	void		(*xa_strategy)(struct buf *, ddi_xbuf_t, void *);
	void		*xa_attr_arg;
	timeout_id_t	xa_timeid;
	taskq_t		*xa_tq;
	struct buf	*xa_flush_headp;
	struct buf	*xa_flush_tailp;
	size_t		xa_brksize;
};


typedef struct __ddi_xbuf_attr	*ddi_xbuf_attr_t;

#define	DDII

DDII   ddi_xbuf_attr_t ddi_xbuf_attr_create(size_t xsize,
	void (*xa_strategy)(struct buf *bp, ddi_xbuf_t xp, void *attr_arg),
	void *attr_arg, uint32_t active_limit, uint32_t reserve_limit,
	major_t major, int flags);
DDII   void ddi_xbuf_attr_destroy(ddi_xbuf_attr_t xap);
DDII   void ddi_xbuf_attr_register_devinfo(ddi_xbuf_attr_t xbuf_attr,
	dev_info_t *dip);
DDII   void ddi_xbuf_attr_unregister_devinfo(ddi_xbuf_attr_t xbuf_attr,
	dev_info_t *dip);
DDII   int ddi_xbuf_qstrategy(struct buf *bp, ddi_xbuf_attr_t xap);
DDII   int ddi_xbuf_done(struct buf *bp, ddi_xbuf_attr_t xap);
DDII   ddi_xbuf_t ddi_xbuf_get(struct buf *bp, ddi_xbuf_attr_t xap);
DDII   void ddi_xbuf_dispatch(ddi_xbuf_attr_t xap);
DDII   void ddi_xbuf_flushq(ddi_xbuf_attr_t xap, int (*funcp)(struct buf *));
DDII   int ddi_xbuf_attr_setup_brk(ddi_xbuf_attr_t xap, size_t size);


/*
 * The buf extension facility utilizes an internal pool of threads to perform
 * callbacks into the given xa_strategy routines.  Clients of the facility
 * do not need to be concerned with the management of these threads as this is
 * handled by the framework.  However clients may recommend certain operational
 * parameters for the framework to consider in performing its thread mangement
 * by specifying one of the following flags to ddi_xbuf_attr_create():
 *
 * DDI_XBUF_QTHREAD_SYSTEM: This should be specified when the client driver
 * provides an xa_strategy routine that is "well behaved", ie, does not
 * block for memory, shared resources, or device states that may take a long
 * or indeterminate amount of time to satisfy. The 'major' argument to
 * ddi_xbuf_attr_create() may be zero if this flag is specified. (?)
 *
 * DDI_XBUF_QTHREAD_DRIVER: This should be specified when the client driver
 * performs blocking operations within its xa_strategy routine that would
 * make it unsuitable for being called from a shared system thread.  The
 * 'major' argument to ddi_xbuf_attr_create() must be the return value of
 * ddi_driver_major() when this flag is specified.
 *
 * DDI_XBUF_QTHREAD_PRIVATE: This should be specified when the client driver
 * would prefer to have a dedicated thread for a given ddi_xbuf_attr_t
 * instantiation. The 'major' argument to ddi_xbuf_attr_create() must be
 * the return value of ddi_driver_major() when this flag is specified. Note
 * that this option ought to be used judiciously in order to avoid excessive
 * consumption of system resources, especially if the client driver has a
 * large number of ddi_xbuf_attr_t instantiations.
 *
 * Note that the above flags are mutually exclusive.  Also note that the
 * behaviors specified by these flags are merely advisory to the framework,
 * and the framework is still free to implement its internal thread management
 * policies as necessary and that these policies are opaque to drivers.
 */

#define	DDI_XBUF_QTHREAD_SYSTEM		0x01
#define	DDI_XBUF_QTHREAD_DRIVER		0x02
#define	DDI_XBUF_QTHREAD_PRIVATE	0x04


#endif	/* defined(_KERNEL) || defined(_KMEMUSER) */


#ifdef	__cplusplus
}
#endif


#endif	/* _SYS_SCSI_TARGETS_SD_XBUF_H */
