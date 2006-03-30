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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _GHD_H
#define	_GHD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/scsi/scsi.h>

#include "ghd_queue.h"		/* linked list structures */
#include "ghd_scsi.h"
#include "ghd_waitq.h"
#include "ghd_debug.h"

#ifndef	TRUE
#define	TRUE	1
#endif

#ifndef	FALSE
#define	FALSE	0
#endif

/*
 * values for cmd_state:
 */

typedef enum {
	GCMD_STATE_IDLE = 0,
	GCMD_STATE_WAITQ,
	GCMD_STATE_ACTIVE,
	GCMD_STATE_DONEQ,
	GCMD_STATE_ABORTING_CMD,
	GCMD_STATE_ABORTING_DEV,
	GCMD_STATE_RESETTING_DEV,
	GCMD_STATE_RESETTING_BUS,
	GCMD_STATE_HUNG,
	GCMD_NSTATES
} cmdstate_t;

/*
 * action codes for the HBA timeout function
 */

typedef enum {
	GACTION_EARLY_TIMEOUT = 0,	/* timed-out before started */
	GACTION_EARLY_ABORT,		/* scsi_abort() before started */
	GACTION_ABORT_CMD,		/* abort a specific request */
	GACTION_ABORT_DEV,		/* abort everything on specifici dev */
	GACTION_RESET_TARGET,		/* reset a specific dev */
	GACTION_RESET_BUS,		/* reset the whole bus */
	GACTION_INCOMPLETE		/* giving up on incomplete request */
} gact_t;

/*
 * types of ghd_timer_poll() invocations
 */

typedef enum {
	GHD_TIMER_POLL_ALL = 0,		/* time out all expired commands */
	GHD_TIMER_POLL_ONE		/* time out one, let caller loop */
} gtimer_poll_t;

/*
 * the common portion of the Command Control Block
 */

typedef struct ghd_cmd {
	L2el_t		 cmd_q;		/* link for for done/active CCB Qs */
	cmdstate_t	 cmd_state;	/* request's current state */
	ulong_t		 cmd_waitq_level; /* which wait Q this request is on */
	int		 cmd_flags;	/* generic magic info */

	L2el_t		 cmd_timer_link; /* ccb timer doubly linked list */
	ulong_t		 cmd_start_time; /* lbolt at start of request */
	ulong_t		 cmd_timeout;	/* how long to wait */

	opaque_t	 cmd_private;	/* used by the HBA driver */
	void		*cmd_pktp;	/* request packet */
	gtgt_t		*cmd_gtgtp;	/* dev instance for this request */

	int		 cmd_dma_flags;
	ddi_dma_handle_t cmd_dma_handle;
	ddi_dma_win_t	 cmd_dmawin;
	ddi_dma_seg_t	 cmd_dmaseg;

	uint_t		 cmd_wcount;	/* ddi_dma_attr: window count */
	uint_t		 cmd_windex;	/* ddi_dma_attr: current window */
	uint_t		 cmd_ccount;	/* ddi_dma_attr: cookie count */
	uint_t		 cmd_cindex;	/* ddi_dma_attr: current cookie */

	long		 cmd_totxfer;	/* # bytes transferred so far */
	ddi_dma_cookie_t cmd_first_cookie;
	int		 use_first;
} gcmd_t;


/* definitions for cmd_flags */
#define	GCMDFLG_RESET_NOTIFY	1	/* command is a reset notification */

/*
 * Initialize the gcmd_t structure
 */

#define	GHD_GCMD_INIT(gcmdp, cmdp, gtgtp)	\
	(L2_INIT(&(gcmdp)->cmd_q),		\
	L2_INIT(&(gcmdp)->cmd_timer_link),	\
	(gcmdp)->cmd_private = (cmdp),		\
	(gcmdp)->cmd_gtgtp = (gtgtp)		\
)


/*
 * CMD/CCB timer config structure - one per HBA driver module
 */
typedef struct tmr_conf {
	kmutex_t	t_mutex;	/* mutex to protect t_ccc_listp */
	timeout_id_t	t_timeout_id;	/* handle for timeout() function */
	long		t_ticks;	/* periodic timeout in clock ticks */
	int		t_refs;		/* reference count */
	struct cmd_ctl	*t_ccc_listp;	/* control struct list, one per HBA */
} tmr_t;



/*
 * CMD/CCB timer control structure - one per HBA instance (per board)
 */
typedef struct cmd_ctl {
	struct cmd_ctl	*ccc_nextp;	/* list of control structs */
	struct tmr_conf	*ccc_tmrp;	/* back ptr to config struct */
	char		*ccc_label;	/* name of this HBA driver */

	kmutex_t ccc_activel_mutex;	/* mutex to protect list ... */
	L2el_t	 ccc_activel;		/* ... list of active CMD/CCBs */

	dev_info_t *ccc_hba_dip;
	ddi_iblock_cookie_t ccc_iblock;
	ddi_softintr_t  ccc_soft_id;	/* ID for timeout softintr */

	kmutex_t ccc_hba_mutex;		/* mutex for HBA soft-state */
	int	 ccc_hba_pollmode;	/* FLAG_NOINTR mode active? */

	L1_t	 ccc_devs;		/* unsorted list of attached devs */
	kmutex_t ccc_waitq_mutex;	/* mutex to protect device wait Qs */
	Q_t	 ccc_waitq;		/* the HBA's wait queue */
	clock_t	 ccc_waitq_freezetime;	/* time the waitq was frozen, ticks */
	uint_t	 ccc_waitq_freezedelay;	/* delta time until waitq thaws, ms */

	ddi_softintr_t  ccc_doneq_softid; /* ID for doneq softintr */
	kmutex_t ccc_doneq_mutex;	/* mutex to protect the doneq */
	L2el_t	 ccc_doneq; 		/* completed cmd_t's */

	void	*ccc_hba_handle;
	int	(*ccc_ccballoc)();	/* alloc/init gcmd and ccb */
	void	(*ccc_ccbfree)();
	void	(*ccc_sg_func)();
	int	(*ccc_hba_start)(void *handle, gcmd_t *);
	void    (*ccc_hba_complete)(void *handle, gcmd_t *, int);
	void	(*ccc_process_intr)(void *handle, void *intr_status);
	int	(*ccc_get_status)(void *handle, void *intr_status);
	int	(*ccc_timeout_func)(void *handle, gcmd_t *cmdp, gtgt_t *gtgtp,
			gact_t action, int calltype);
	void 	(*ccc_hba_reset_notify_callback)(gtgt_t *gtgtp,
			void (*callback)(caddr_t),
			caddr_t arg);
	L2el_t	 ccc_reset_notify_list;	/* list of reset notifications */
	kmutex_t ccc_reset_notify_mutex; /* and a mutex to protect it */
	char	 ccc_timeout_pending;	/* timeout Q's softintr is triggered */
	char	 ccc_waitq_frozen;	/* ccc_waitq_freezetime non-null */
	char	 ccc_waitq_held;	/* frozen, but no freezetime */
} ccc_t;

#define	GHBA_QHEAD(cccp)	((cccp)->ccc_waitq.Q_qhead)
#define	GHBA_MAXACTIVE(cccp)	((cccp)->ccc_waitq.Q_maxactive)
#define	GHBA_NACTIVE(cccp)	((cccp)->ccc_waitq.Q_nactive)

/* Initialize the HBA's list headers */
#define	CCCP_INIT(cccp)	{				\
		L1HEADER_INIT(&(cccp)->ccc_devs);	\
		L2_INIT(&(cccp)->ccc_doneq);		\
		L2_INIT(&(cccp)->ccc_reset_notify_list);	\
}


#define	CCCP2GDEVP(cccp)					\
	(L1_EMPTY(&(cccp)->ccc_devs)				\
	? (gdev_t *)NULL					\
	: (gdev_t *)((cccp)->ccc_devs.l1_headp->le_datap))


/*
 * reset_notify handling: these elements are on the ccc_t's
 * reset_notify_list, one for each notification requested.  The
 * gtgtp isn't needed except for debug.
 */

typedef struct ghd_reset_notify_list {
	gtgt_t *gtgtp;
	void (*callback)(caddr_t);
	caddr_t	arg;
	L2el_t l2_link;
} ghd_reset_notify_list_t;

/* ******************************************************************* */

#include "ghd_scsa.h"
#include "ghd_dma.h"

/*
 * GHD Entry Points
 */
void	 ghd_complete(ccc_t *cccp, gcmd_t *cmdp);
void	 ghd_doneq_put_head(ccc_t *cccp, gcmd_t *cmdp);
void	 ghd_doneq_put_tail(ccc_t *cccp, gcmd_t *cmdp);

int	 ghd_intr(ccc_t *cccp, void *status);
int	 ghd_register(char *, ccc_t *, dev_info_t *, int, void *hba_handle,
			int (*ccc_ccballoc)(gtgt_t *, gcmd_t *, int, int,
					    int, int),
			void (*ccc_ccbfree)(gcmd_t *),
			void (*ccc_sg_func)(gcmd_t *, ddi_dma_cookie_t *,
					    int, int),
			int  (*hba_start)(void *, gcmd_t *),
			void (*hba_complete)(void *, gcmd_t *, int),
			uint_t (*int_handler)(caddr_t),
			int  (*get_status)(void *, void *),
			void (*process_intr)(void *, void *),
			int  (*timeout_func)(void *, gcmd_t *, gtgt_t *,
				gact_t, int),
			tmr_t *tmrp,
			void (*hba_reset_notify_callback)(gtgt_t *,
				void (*)(caddr_t), caddr_t));
void	ghd_unregister(ccc_t *cccp);

int	ghd_transport(ccc_t *cccp, gcmd_t *cmdp, gtgt_t *gtgtp,
	    ulong_t timeout, int polled, void *intr_status);

int	ghd_tran_abort(ccc_t *cccp, gcmd_t *cmdp, gtgt_t *gtgtp,
	    void *intr_status);
int	ghd_tran_abort_lun(ccc_t *cccp, gtgt_t *gtgtp, void *intr_status);
int	ghd_tran_reset_target(ccc_t *cccp, gtgt_t *gtgtp, void *intr_status);
int	ghd_tran_reset_bus(ccc_t *cccp, gtgt_t *gtgtp, void *intr_status);
int	ghd_reset_notify(ccc_t *cccp, gtgt_t *gtgtp, int flag,
	    void (*callback)(caddr_t), caddr_t arg);
void	ghd_freeze_waitq(ccc_t *cccp, int delay);
void	ghd_trigger_reset_notify(ccc_t *cccp);

void	 ghd_queue_hold(ccc_t *cccp);
void	 ghd_queue_unhold(ccc_t *cccp);

/*
 * Allocate a gcmd_t wrapper and HBA private area
 */
gcmd_t	*ghd_gcmd_alloc(gtgt_t *gtgtp, int ccblen, int sleep);

/*
 * Free the gcmd_t wrapper and HBA private area
 */
void	ghd_gcmd_free(gcmd_t *gcmdp);


/*
 * GHD CMD/CCB timer Entry points
 */

int	ghd_timer_attach(ccc_t *cccp, tmr_t *tmrp,
	    int (*timeout_func)(void *handle, gcmd_t *, gtgt_t *,
	    gact_t, int));
void	ghd_timer_detach(ccc_t *cccp);
void	ghd_timer_fini(tmr_t *tmrp);
void	ghd_timer_init(tmr_t *tmrp, long ticks);
void	ghd_timer_newstate(ccc_t *cccp, gcmd_t *cmdp, gtgt_t *gtgtp,
	    gact_t action, int calltype);
void	ghd_timer_poll(ccc_t *cccp, gtimer_poll_t calltype);
void	ghd_timer_start(ccc_t *cccp, gcmd_t *cmdp, long cmd_timeout);
void	ghd_timer_stop(ccc_t *cccp, gcmd_t *cmdp);


/*
 * Wait queue utility routines
 */

gtgt_t	*ghd_target_init(dev_info_t *, dev_info_t *, ccc_t *, size_t,
	    void *, ushort_t, uchar_t);
void	 ghd_target_free(dev_info_t *, dev_info_t *, ccc_t *, gtgt_t *);
void	 ghd_waitq_shuffle_up(ccc_t *, gdev_t *);
void	 ghd_waitq_delete(ccc_t *, gcmd_t *);
int	 ghd_waitq_process_and_mutex_hold(ccc_t *);
void	 ghd_waitq_process_and_mutex_exit(ccc_t *);


/*
 * The values for the calltype arg for the ghd_timer_newstate() function,
 * and the HBA timeout-action function (ccc_timeout_func)
 */

#define	GHD_TGTREQ		0
#define	GHD_TIMEOUT		1

/* ******************************************************************* */

/*
 * specify GHD_INLINE to get optimized versions
 */
#define	GHD_INLINE	1
#if defined(GHD_DEBUG) || defined(DEBUG) || defined(__lint)
#undef	GHD_INLINE
#endif

#if defined(GHD_INLINE)
#define	GHD_COMPLETE(cccp, gcmpd)	GHD_COMPLETE_INLINE(cccp, gcmdp)
#define	GHD_TIMER_STOP(cccp, gcmdp)	GHD_TIMER_STOP_INLINE(cccp, gcmdp)
#define	GHD_DONEQ_PUT_HEAD(cccp, gcmdp)	GHD_DONEQ_PUT_HEAD_INLINE(cccp, gcmdp)
#define	GHD_DONEQ_PUT_TAIL(cccp, gcmdp)	GHD_DONEQ_PUT_TAIL_INLINE(cccp, gcmdp)
#else
#define	GHD_COMPLETE(cccp, gcmpd)	ghd_complete(cccp, gcmdp)
#define	GHD_TIMER_STOP(cccp, gcmdp)	ghd_timer_stop(cccp, gcmdp)
#define	GHD_DONEQ_PUT_HEAD(cccp, gcmdp)	ghd_doneq_put_head(cccp, gcmdp)
#define	GHD_DONEQ_PUT_TAIL(cccp, gcmdp)	ghd_doneq_put_tail(cccp, gcmdp)
#endif

/*
 * request is complete, stop the request timer and add to doneq
 */
#define	GHD_COMPLETE_INLINE(cccp, gcmdp)	\
{						\
	ghd_waitq_delete(cccp, gcmdp);		\
	(gcmdp)->cmd_state = GCMD_STATE_DONEQ;	\
	GHD_TIMER_STOP((cccp), (gcmdp));	\
	GHD_DONEQ_PUT_TAIL((cccp), (gcmdp));	\
}

#define	GHD_TIMER_STOP_INLINE(cccp, gcmdp)	\
{						\
	mutex_enter(&(cccp)->ccc_activel_mutex);\
	L2_delete(&(gcmdp)->cmd_timer_link);	\
	mutex_exit(&(cccp)->ccc_activel_mutex);	\
}

/*
 * mark the request done and append it to the head of the doneq
 */
#define	GHD_DONEQ_PUT_HEAD_INLINE(cccp, gcmdp)			\
{								\
	kmutex_t *doneq_mutexp = &(cccp)->ccc_doneq_mutex;	\
								\
	mutex_enter(doneq_mutexp);				\
	(gcmdp)->cmd_state = GCMD_STATE_DONEQ;			\
	L2_add_head(&(cccp)->ccc_doneq, &(gcmdp)->cmd_q, (gcmdp));	\
	if (!(cccp)->ccc_hba_pollmode)				\
		ddi_trigger_softintr((cccp)->ccc_doneq_softid);	\
	mutex_exit(doneq_mutexp);				\
}

/*
 * mark the request done and append it to the tail of the doneq
 */
#define	GHD_DONEQ_PUT_TAIL_INLINE(cccp, gcmdp)			\
{								\
	kmutex_t *doneq_mutexp = &(cccp)->ccc_doneq_mutex;	\
								\
	mutex_enter(doneq_mutexp);				\
	(gcmdp)->cmd_state = GCMD_STATE_DONEQ;			\
	L2_add(&(cccp)->ccc_doneq, &(gcmdp)->cmd_q, (gcmdp));	\
	if (!(cccp)->ccc_hba_pollmode)				\
		ddi_trigger_softintr((cccp)->ccc_doneq_softid);	\
	mutex_exit(doneq_mutexp);				\
}

/* ******************************************************************* */

/*
 * These are shortcut macros for linkages setup by GHD
 */

/*
 * (gcmd_t *) to (struct scsi_pkt *)
 */
#define	GCMDP2PKTP(gcmdp)	((gcmdp)->cmd_pktp)

/*
 * (gcmd_t *) to (gtgt_t *)
 */
#define	GCMDP2GTGTP(gcmdp)	((gcmdp)->cmd_gtgtp)

/*
 * (gcmd_t *) to (gdev_t *)
 */
#define	GCMDP2GDEVP(gcmdp)	((gcmdp)->cmd_gtgtp->gt_gdevp)

/*
 * (gcmd_t *) to (ccc_t *)
 */
#define	GCMDP2CCCP(gcmdp)	(GCMDP2GTGTP(gcmdp)->gt_ccc)

/*
 * (struct scsi_pkt *) to (gcmd_t *)
 */
#define	PKTP2GCMDP(pktp)	((gcmd_t *)(pktp)->pkt_ha_private)


/* These are shortcut macros for linkages setup by SCSA */

/*
 * (struct scsi_address *) to (scsi_hba_tran *)
 */
#define	ADDR2TRAN(ap)		((ap)->a_hba_tran)

/*
 * (struct scsi_device *) to (scsi_address *)
 */
#define	SDEV2ADDR(sdp)		(&(sdp)->sd_address)

/*
 * (struct scsi_device *) to (scsi_hba_tran *)
 */
#define	SDEV2TRAN(sdp)		ADDR2TRAN(SDEV2ADDR(sdp))

/*
 * (struct scsi_pkt *) to (scsi_hba_tran *)
 */
#define	PKTP2TRAN(pktp)		ADDR2TRAN(&(pktp)->pkt_address)

/*
 * (scsi_hba_tran_t *) to (per-target-soft-state *)
 */
#define	TRAN2GTGTP(tranp)	((gtgt_t *)((tranp)->tran_tgt_private))

/*
 * (struct scsi_device *) to (per-target-soft-state *)
 */
#define	SDEV2GTGTP(sd)  	TRAN2GTGTP(SDEV2TRAN(sd))

/*
 * (struct scsi_pkt *) to (per-target-soft-state *)
 */
#define	PKTP2GTGTP(pktp)	TRAN2GTGTP(PKTP2TRAN(pktp))


/*
 * (scsi_hba_tran_t *) to (per-HBA-soft-state *)
 */
#define	TRAN2HBA(tranp)		((tranp)->tran_hba_private)


/*
 * (struct scsi_device *) to (per-HBA-soft-state *)
 */
#define	SDEV2HBA(sd)		TRAN2HBA(SDEV2TRAN(sd))

/*
 * (struct scsi_address *) to (per-target-soft-state *)
 */
#define	ADDR2GTGTP(ap)  	TRAN2GTGTP(ADDR2TRAN(ap))

/* ******************************************************************* */


#ifdef __cplusplus
}
#endif

#endif /* _GHD_H */
