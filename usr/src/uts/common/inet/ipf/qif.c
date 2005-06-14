/*
 * Copyright (C) 2000, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/dditypes.h>
#include <sys/stream.h>
#include <sys/poll.h>
#include <sys/autoconf.h>
#include <sys/byteorder.h>
#include <sys/socket.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/sockio.h>
#include <net/if.h>
#if SOLARIS2 >= 6
# include <net/if_types.h>
# if SOLARIS2 >= 8
#  include <netinet/ip6.h>
# endif
# include <net/if_dl.h>
#endif
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>

#include "compat.h"
#include "qif.h"


#if SOLARIS2 >= 6
static	size_t	hdrsizes[57][2] = {
	{ 0, 0 },
	{ IFT_OTHER, 0 },
	{ IFT_1822, 0 },
	{ IFT_HDH1822, 0 },
	{ IFT_X25DDN, 0 },
	{ IFT_X25, 0 },
	{ IFT_ETHER, 14 },
	{ IFT_ISO88023, 0 },
	{ IFT_ISO88024, 0 },
	{ IFT_ISO88025, 0 },
	{ IFT_ISO88026, 0 },
	{ IFT_STARLAN, 0 },
	{ IFT_P10, 0 },
	{ IFT_P80, 0 },
	{ IFT_HY, 0 },
	{ IFT_FDDI, 24 },
	{ IFT_LAPB, 0 },
	{ IFT_SDLC, 0 },
	{ IFT_T1, 0 },
	{ IFT_CEPT, 0 },
	{ IFT_ISDNBASIC, 0 },
	{ IFT_ISDNPRIMARY, 0 },
	{ IFT_PTPSERIAL, 0 },
	{ IFT_PPP, 0 },
	{ IFT_LOOP, 0 },
	{ IFT_EON, 0 },
	{ IFT_XETHER, 0 },
	{ IFT_NSIP, 0 },
	{ IFT_SLIP, 0 },
	{ IFT_ULTRA, 0 },
	{ IFT_DS3, 0 },
	{ IFT_SIP, 0 },
	{ IFT_FRELAY, 0 },
	{ IFT_RS232, 0 },
	{ IFT_PARA, 0 },
	{ IFT_ARCNET, 0 },
	{ IFT_ARCNETPLUS, 0 },
	{ IFT_ATM, 0 },
	{ IFT_MIOX25, 0 },
	{ IFT_SONET, 0 },
	{ IFT_X25PLE, 0 },
	{ IFT_ISO88022LLC, 0 },
	{ IFT_LOCALTALK, 0 },
	{ IFT_SMDSDXI, 0 },
	{ IFT_FRELAYDCE, 0 },
	{ IFT_V35, 0 },
	{ IFT_HSSI, 0 },
	{ IFT_HIPPI, 0 },
	{ IFT_MODEM, 0 },
	{ IFT_AAL5, 0 },
	{ IFT_SONETPATH, 0 },
	{ IFT_SONETVT, 0 },
	{ IFT_SMDSICIP, 0 },
	{ IFT_PROPVIRTUAL, 0 },
	{ IFT_PROPMUX, 0 },
};
#endif /* SOLARIS2 >= 6 */


#define	SAPNAME(x)	((x)->qf_sap == 0x0800 ? "IPv4" : \
			 (x)->qf_sap == 0x86dd ? "IPv6" : "??")

static	int		qif_num = 0;
static	kmem_cache_t	*qif_cache = NULL;

qif_t	*qif_head;
int	qif_verbose = 0;


/* ------------------------------------------------------------------------ */
/* Function:    qif_startup                                                 */
/* Returns:     int - 0 == success, -1 == failure                           */
/* Parameters:  None.                                                       */
/*                                                                          */
/* Perform any initialisation of data structures related to managing qif's  */
/* that is deemed necessary.                                                */
/* ------------------------------------------------------------------------ */
int qif_startup()
{

	qif_head = NULL;
	qif_cache = kmem_cache_create("qif_head_cache", sizeof(qif_t), 8,
				      NULL, NULL, NULL, NULL, NULL, 0);
	if (qif_cache == NULL)
		return -1;
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    qif_stop                                                    */
/* Returns:     void                                                        */
/* Parameters:  None.                                                       */
/*                                                                          */
/* Deallocate all qif_t's allocated and clean up any other data structures  */
/* required in order to 'shut down' this part of the pfil module.           */
/* ------------------------------------------------------------------------ */
void qif_stop()
{
	kmem_cache_destroy(qif_cache);
	qif_cache = NULL;
}


/* ------------------------------------------------------------------------ */
/* Function:    q_to_ill                                                    */
/* Returns:     void * - NULL == failure, else pointer to ill               */
/* Parameters:  rq(I) - pointer to STREAMS read queue                       */
/* Locks:       pfil_rw                                                     */
/*                                                                          */
/* Given a pointer to a queue, try and find the ill which owns it.          */
/* ------------------------------------------------------------------------ */
void *q_to_ill(rq)
queue_t *rq;
{
#ifndef	IRE_ILL_CN
	ill_t *ill = NULL;
	queue_t *qu, *wq;

	wq = OTHERQ(rq);
	if (rq) {
#if SOLARIS2 >= 10
		ill_walk_context_t ctx;

		rw_enter(&ill_g_lock, RW_READER);
		for (ill = ILL_START_WALK_ALL(&ctx); ill != NULL;
		     ill = ill_next(&ctx, ill))
#else
		for (ill = ill_g_head; ill != NULL; ill = ill->ill_next)
#endif
		{
			if (ill->ill_rq == NULL || ill->ill_wq == NULL)
				continue;
			if (ill->ill_rq == RD(rq)->q_next)
				break;
			for (qu = WR(ill->ill_rq); qu; qu = qu->q_next)
				if ((qu->q_ptr == rq->q_ptr) || (qu == wq))
					break;
			if (qu != NULL)
				break;
			for (qu = ill->ill_rq; qu; qu = qu->q_next)
				if (qu->q_ptr == rq->q_ptr)
					break;
			if (qu != NULL)
				break;
		}
	}
#if SOLARIS2 >= 10
	rw_exit(&ill_g_lock);
#endif
	return ill;
#else /* IRE_ILL_CN */
	s_ill_t *ill = NULL;

	if (!rq)
		return 0;

	ASSERT(rq->q_flag & QREADR);

	mutex_enter(&s_ill_g_head_lock);
	for (ill = s_ill_g_head; ill; ill = ill->ill_next)
		if (ill->ill_rq == rq)
			break;
	mutex_exit(&s_ill_g_head_lock);

	return ill;
#endif
}


#ifndef	IRE_ILL_CN
/* ------------------------------------------------------------------------ */
/* Function:    qif_ire_walker                                              */
/* Returns:     void                                                        */
/* Parameters:  ire(I) - pointer to an ire_t                                */
/*              arg(I) - pointer to a qif                                   */
/*                                                                          */
/* This function gets called by the ire-walking function for each ire in    */
/* table.  We enumerate through the ire looking for cached fastpath headers */
/* on a given NIC (the qif) so we can update qf_hl from its size.           */
/* ------------------------------------------------------------------------ */
void
qif_ire_walker(ire, arg)
	ire_t *ire;
	void *arg;
{
	qif_t *qif = arg;

	if ((ire->ire_type == IRE_CACHE) &&
#if SOLARIS2 >= 6
	    (ire->ire_ipif != NULL) &&
	    (ire->ire_ipif->ipif_ill == qif->qf_ill)
#else
	    (ire_to_ill(ire) == qif->qf_ill)
#endif
	    ) {
#if SOLARIS2 >= 8
		mblk_t *m = ire->ire_fp_mp;
#else
		mblk_t *m = ire->ire_ll_hdr_mp;
#endif
		if (m != NULL)
			qif->qf_hl = m->b_wptr - m->b_rptr;
	}
}
#endif


/* ------------------------------------------------------------------------ */
/* Function:    qif_attach                                                  */
/* Returns:     int  - 0 == success, -1 == error in attaching qif_t to q    */
/* Parameters:  rq(I) - pointer to STREAMS read queue                       */
/* Write Lock:  pfil_rw                                                     */
/*                                                                          */
/* Attempt to bind a qif_t structure to a specific interface given the      */
/* queue pointer.  Assumes the queue already has a qif_t structure tagged   */
/* against it.                                                              */
/* ------------------------------------------------------------------------ */
int
qif_attach(rq)
	queue_t *rq;
{
	packet_filter_hook_t *pfh;
	qif_t *qif;
#ifdef IRE_ILL_CN
	s_ill_t *ill;
#else
	ill_t *ill;
#endif

	/*
	 * Can we map the queue to a specific ill?  If not, go no futher, we
	 * are only interested in being associated with queues that we can
	 * recognise as being used for IP communication of some sort.
	 */
	ill = q_to_ill(rq);
	if (ill == NULL) {
		if (qif_verbose > 0)
			cmn_err(CE_NOTE,
				"PFIL: cannot find interface for rq %p",
				(void *)rq);
		return -1;
	}

	qif = rq->q_ptr;
#ifndef IRE_ILL_CN
#if SOLARIS2 < 8
	qif->qf_hl = ill->ill_hdr_length;
#else
	if ((ill->ill_type > 0) && (ill->ill_type < 0x37) &&
	    (hdrsizes[ill->ill_type][0] == ill->ill_type))
		qif->qf_hl = hdrsizes[ill->ill_type][1];

	if (qif->qf_hl == 0) {
		cmn_err(CE_WARN,
			"!Unknown layer 2 header size for %s type %d sap %x\n",
			qif->qf_name, ill->ill_type, ill->ill_sap);
	}
#endif
#endif /* IRE_ILL_CN */

	/*
	 * Protect against the qif_t being bound against an interface, twice
	 * by getting a lock on setting qf_bound and don't release it until
	 * all the information has been set with qf_bound finally set to 1
	 * after that.
	 */
	if (qif->qf_bound == 1)
		return 0;

	qif->qf_sap = ill->ill_sap;
#ifndef IRE_ILL_CN
	qif->qf_ppa = ill->ill_ppa;
#endif
#ifdef icmp_nextmtu
	qif->qf_max_frag = ill->ill_max_frag;
#endif
	(void) strncpy(qif->qf_name, ill->ill_name, sizeof(qif->qf_name));
	qif->qf_name[sizeof(qif->qf_name) - 1] = '\0';
	qif->qf_ill = ill;
	qif->qf_bound = 1;

	READ_ENTER(&pfh_sync.ph_lock);

	pfh = pfil_hook_get(PFIL_IN, &pfh_sync);
	for (; pfh; pfh = pfh->pfil_next)
		if (pfh->pfil_func)
			(void) (*pfh->pfil_func)(NULL, 0, ill, 0, qif, NULL);

	RW_EXIT(&pfh_sync.ph_lock);

	if (qif_verbose > 0)
		cmn_err(CE_NOTE, "PFIL: attaching [%s] - %s", qif->qf_name,
			SAPNAME(qif));
#if SOLARIS2 <= 8
	ire_walk(qif_ire_walker, qif);
#else
# ifndef IRE_ILL_CN
	ire_walk(qif_ire_walker, (char *)qif);
# endif
#endif
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    qif_new                                                     */
/* Returns:     qif_t * - NULL == failure, else pointer to qif_t            */
/* Parameters:  q(I) - pointer to STREAMS queue                             */
/*                                                                          */
/* Allocate a new qif struct, give it a unique number and add it to the     */
/* list of registered qif_t's for the given queue.  Along the way, if we    */
/* find an existing qif_t for this queue, return that instead.              */
/* ------------------------------------------------------------------------ */
qif_t *
qif_new(q, mflags)
	queue_t *q;
	int mflags;
{
	qif_t *qif;

	qif = kmem_cache_alloc(qif_cache, mflags);
	if (qif == NULL) {
		cmn_err(CE_NOTE, "PFIL: malloc(%d) for qif_t failed",
			(int)sizeof(qif_t));
		return NULL;
	}

	bzero((char *)qif, sizeof(*qif));
	mutex_init(&qif->qf_ptl.pt_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&qif->qf_ptl.pt_cv, NULL, CV_DRIVER, NULL);
	qif->qf_q = q;
	qif->qf_oq = OTHERQ(q);
	WRITE_ENTER(&pfil_rw);
	qif->qf_num = qif_num++;
	qif->qf_next = qif_head;
	qif_head = qif;
	RW_EXIT(&pfil_rw);
	(void) sprintf(qif->qf_name, "QIF%x", qif->qf_num);
	return qif;
}

/* ------------------------------------------------------------------------ */
/* Function:    qif_delete                                                  */
/* Returns:     void                                                        */
/* Parameters:  None.                                                       */
/* Write Locks: pfil_rw                                                     */
/*                                                                          */
/* Remove a qif structure from the list of recognised qif's.                */
/*                                                                          */
/* NOTE: The locking structure used here on qif's is to protect their use   */
/* by the pkt.c functions for sending out a packet.  It is possible that a  */
/* packet will be processed on one queue and need to be output on another   */
/* and given we cannot hold a lock across putnext() we need to use a P-V    */
/* like algorithm for locking.  The PT_* macros come from the PTY code.     */
/* In the fullness of time, this function should be rewritten to make sure  */
/* that it is not posible to find the qif before we call the PT_* macros    */
/* and call qprocsoff().                                                    */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
void qif_delete(qif, q)
qif_t *qif;
queue_t *q;
{
	packet_filter_hook_t *pfh;
	qif_t **qp;
	int rm = 0;

	if (qif == NULL)
		return;

	PT_ENTER_WRITE(&qif->qf_ptl);

	if (qif->qf_bound == 1 && qif_verbose > 0)
		cmn_err(CE_NOTE, "PFIL: detaching [%s] - %s", qif->qf_name,
			SAPNAME(qif));

	for (qp = &qif_head; *qp; qp = &(*qp)->qf_next)
		if (*qp == qif) {
			*qp = qif->qf_next;
			rm = 1;
			break;
		}
	PT_EXIT_WRITE(&qif->qf_ptl);

	if (qif->qf_ill) {
		READ_ENTER(&pfh_sync.ph_lock);
		pfh = pfil_hook_get(PFIL_OUT, &pfh_sync);
		for (; pfh; pfh = pfh->pfil_next)
			if (pfh->pfil_func)
				(void) (*pfh->pfil_func)(NULL, 0, qif->qf_ill,
							 1, qif, NULL);
		RW_EXIT(&pfh_sync.ph_lock);
	}

	if (rm) {
		if (qif->qf_addrset != NULL)
			freeb(qif->qf_addrset);
		mutex_destroy(&qif->qf_ptl.pt_lock);
		cv_destroy(&qif->qf_ptl.pt_cv);
		kmem_cache_free(qif_cache, qif);
	}
	return;
}


/* ------------------------------------------------------------------------ */
/* Function:    qif_iflookup                                                */
/* Returns:     void *  - NULL == search failed, else pointer to qif_t      */
/* Parameters:  name(I) - pointer to the name                               */
/*              sap(I)  - SAP value                                         */
/* Locks:       pfil_rw                                                     */
/*                                                                          */
/* Search the list of registered qif_t's for a match based on the name and  */
/* the SAP and return a pointer to the matching entry.                      */
/* ------------------------------------------------------------------------ */
void *qif_iflookup(char *name, int sap)
{
	qif_t *qif;

	for (qif = qif_head; qif; qif = qif->qf_next)
		if ((!sap || (qif->qf_sap == sap)) &&
		    !strcmp(qif->qf_name, name))
			break;
	return qif;
}


/* ------------------------------------------------------------------------ */
/* Function:    qif_update                                                  */
/* Returns:     void                                                        */
/* Parameters:  qif(I) - pointer to qif_t structure                         */
/*              mp(I)  - pointer to STREAMS message                         */
/* Locks:       pfil_rw                                                     */
/*                                                                          */
/* This function attempts to force an update of the qf_sap and qf_hl fields */
/* using information that is in the STREAMS message and/or the ill_t.  This */
/* function should only be called if the mblk is a DL_IOC_HDR_INFO message. */
/* ------------------------------------------------------------------------ */
void qif_update(qif, mp)
qif_t *qif;
mblk_t *mp;
{
#ifdef IRE_ILL_CN
	s_ill_t *ill;
#else
	ill_t *ill;
#endif

	ill = qif->qf_ill;
	if (ill == NULL)
		return;

	if (mp->b_datap->db_type == M_IOCACK && mp->b_cont) {
		mp = mp->b_cont;
		if (mp->b_datap->db_type == M_PROTO && mp->b_cont) {
			mp = mp->b_cont;
			if (mp->b_datap->db_type == M_DATA) {
				qif->qf_hl = mp->b_wptr - mp->b_rptr;
			}
		}
	}

	/*
	 * If we still have a 0 size expected fasthpath header length, check
	 * the ill structure to see if we can use it to now make a better
	 * guess about what to use.
	 */
	qif->qf_sap = ill->ill_sap;
#ifndef IRE_ILL_CN
	if (qif->qf_hl == 0) {
#if SOLARIS2 < 8
		qif->qf_hl = ill->ill_hdr_length;
#else
		if ((ill->ill_type > 0) && (ill->ill_type < 0x37) &&
		    (hdrsizes[ill->ill_type][0] == ill->ill_type))
			qif->qf_hl = hdrsizes[ill->ill_type][1];
#endif
	}
#endif
}


/* ------------------------------------------------------------------------ */
/* Function:    qif_walk                                                    */
/* Returns:     qif_t *  - NULL == search failed, else pointer to qif_t     */
/* Parameters:  qfp(IO) - pointer to the name                               */
/*                                                                          */
/* NOTE: it is assumed the caller has a lock on pfil_rw                     */
/*                                                                          */
/* Provide a function to enable the caller to enumerate through all of the  */
/* qif_t's without being aware of the internal data structure used to store */
/* them in.                                                                 */
/* ------------------------------------------------------------------------ */
qif_t *qif_walk(qif_t **qfp)
{
	struct qif *qf, *qf2;

	if (qfp == NULL)
		return NULL;

	qf = *qfp;
	if (qf == NULL)
		*qfp = qif_head;
	else {
		/*
		 * Make sure the pointer being passed in exists as a current
		 * object before returning its next value.
		 */
		for (qf2 = qif_head; qf2 != NULL; qf2 = qf2->qf_next)
			if (qf2 == qf)
				break;
		if (qf2 == NULL)
			*qfp = NULL;
		else
			*qfp = qf->qf_next;
	}
	return *qfp;
}
