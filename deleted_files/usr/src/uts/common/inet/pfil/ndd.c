/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/stream.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include "compat.h"
#include "qif.h"
#include "pfil.h"

caddr_t	pfil_nd;

#if !defined(sun) || SOLARIS2 <= 8
static int qif_report(queue_t *, mblk_t *, caddr_t);
static int sill_report(queue_t *, mblk_t *, caddr_t);
static int qif_ipmp_report(queue_t *, mblk_t *, caddr_t);
static int qif_ipmp_set(queue_t *, mblk_t *, char *, caddr_t);
static int pfil_hl_set(queue_t *, mblk_t *, char *, caddr_t);

extern int pfil_report(queue_t *, mblk_t *, caddr_t);
#else
static int qif_report(queue_t *, mblk_t *, caddr_t, cred_t *);
static int sill_report(queue_t *, mblk_t *, caddr_t, cred_t *);
static int qif_ipmp_report(queue_t *, mblk_t *, caddr_t, cred_t *);
static int qif_ipmp_set(queue_t *, mblk_t *, char *, caddr_t , cred_t *);
static int pfil_hl_set(queue_t *, mblk_t *, char *, caddr_t , cred_t *);

extern int pfil_report(queue_t *, mblk_t *, caddr_t, cred_t *);
#endif


/* ------------------------------------------------------------------------ */
/* Function:    pfil_nd_get                                                 */
/* Returns:     int     - 0 == success                                      */
/* Parameters:  q(I)    - pointer to queue                                  */
/*              mp(I)   - pointer to mblk                                   */
/*              ptr(I)  - pointer to value to retrieve                      */
/*              cred(I) - pointer to credential information                 */
/*                                                                          */
/* Given a pointer "ptr" to some data to return, copy it into the mblk that */
/* has been provided.                                                       */
/* ------------------------------------------------------------------------ */
#if !defined(sun) || SOLARIS2 <= 8
/*ARGSUSED*/
int pfil_nd_get(queue_t *q, mblk_t *mp, caddr_t ptr)
#else
/*ARGSUSED*/
int pfil_nd_get(queue_t *q, mblk_t *mp, caddr_t ptr, cred_t *cred)
#endif
{
	int *ip;

	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(2,(CE_CONT, "pfil_nd_get(%p,%p,%p)\n",
		 (void *)q, (void *)mp, (void *)ptr));
	ip = (int *)ptr;
	(void) mi_mpprintf(mp, "%d", *ip);
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_nd_set                                                 */
/* Returns:     int     - 0 == success, > 0 error occurred                  */
/* Parameters:  q(I)    - pointer to queue                                  */
/*              mp(I)   - pointer to mblk                                   */
/*              str(I)  - pointer to new value as a string                  */
/*              ptr(I)  - pointer to value to be stored                     */
/*              cred(I) - pointer to credential information                 */
/*                                                                          */
/* Given a pointer "ptr" to a location to store the new value represented   */
/* by the string "str", check to see if we allow setting that variable and  */
/* if the new value is within the definable ranges understood for it.       */
/* ------------------------------------------------------------------------ */
#if !defined(sun) || SOLARIS2 <= 8
/*ARGSUSED*/
int pfil_nd_set(queue_t *q, mblk_t *mp, char *str, caddr_t ptr)
#else
/*ARGSUSED*/
int pfil_nd_set(queue_t *q, mblk_t *mp, char *str, caddr_t ptr, cred_t *cred)
#endif
{
	char *end;
	long i;

	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(2, (CE_CONT, "pfil_nd_set(%p,%p,%s[%p],%p)\n", 
		  (void *)q, (void *)mp, str, (void *)str, 
		  (void *)ptr));

#if (SOLARIS2 >= 10)
	if (ddi_strtol(str, &end, 10, &i) != 0)
		return (EINVAL);
#else
	i =  mi_strtol(str, &end, 10);
#endif

	if (ptr == (caddr_t)&pfildebug) {
#ifdef	PFILDEBUG
#if (SOLARIS2 >= 10)
		if ((end == str) || (i < 0) || (i > 100))
#else
		if (i < 0 || i > 1)
#endif
#endif
			return EINVAL;
	} else if (ptr == (caddr_t)&qif_verbose) {
		if ((end == str) || (i < 0) || (i > 1))
			return EINVAL;
	}
	*((int *)ptr) = i;
	return 0;
}




/* ------------------------------------------------------------------------ */
/* Function:    pfil_ioctl_nd                                               */
/* Returns:     int - B_TRUE == success, B_FALSE == getset error            */
/* Parameters:  q(I)    - pointer to queue                                  */
/*              mp(I)   - pointer to mblk                                   */
/*                                                                          */
/* Handle both incoming ndd set and get requests but only if they're not    */
/* destined for another STREAMS module (ie. there is no next queue for this */
/* message.)                                                                */
/* ------------------------------------------------------------------------ */
int pfil_ioctl_nd(queue_t *q, mblk_t *mp)
{
	return (nd_getset(q, pfil_nd, mp));
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_nd_init                                                */
/* Returns:     int   - 0 == success, -1 == error                           */
/* Parameters:  None.                                                       */
/*                                                                          */
/* Perform any initialisation required for processing ndd ioctl messages.   */
/* ------------------------------------------------------------------------ */
int pfil_nd_init()
{

#ifdef PFILDEBUG
	if (!nd_load(&pfil_nd, "pfildebug", pfil_nd_get, pfil_nd_set,
		      (caddr_t)&pfildebug)) {
		nd_free(&pfil_nd);
		return -1;
	}
#endif

	if (!nd_load(&pfil_nd, "pfil_delayed_copy", pfil_nd_get, pfil_nd_set,
		     (caddr_t)&pfil_delayed_copy)) {
		nd_free(&pfil_nd);
		return -1;
	}

	if (!nd_load(&pfil_nd, "pfil_interface", pfil_nd_get, NULL,
		     (caddr_t)&pfilinterface)) {
		nd_free(&pfil_nd);
		return -1;
	}

	if (!nd_load(&pfil_nd, "qif_status", qif_report, NULL, NULL)) {
		nd_free(&pfil_nd);
		return -1;
	}

	if (!nd_load(&pfil_nd, "sill_status", sill_report, NULL, NULL)) {
		nd_free(&pfil_nd);
		return -1;
	}

	if (!nd_load(&pfil_nd, "qif_ipmp_status", qif_ipmp_report, NULL,
		     NULL)) {
		nd_free(&pfil_nd);
		return -1;
	}

	if (!nd_load(&pfil_nd, "qif_ipmp_set", NULL, qif_ipmp_set, NULL)) {
		nd_free(&pfil_nd);
		return -1;
	}

	if (!nd_load(&pfil_nd, "qif_verbose", pfil_nd_get, pfil_nd_set,
		     (caddr_t)&qif_verbose)) {
		nd_free(&pfil_nd);
		return -1;
	}

	if (!nd_load(&pfil_nd, "pfil_inet4", pfil_report, NULL,
		     (void *)&pfh_inet4)) {
		nd_free(&pfil_nd);
		return -1;
	}

	if (!nd_load(&pfil_nd, "pfil_inet6", pfil_report, NULL,
		     (void *)&pfh_inet6)) {
		nd_free(&pfil_nd);
		return -1;
	}

	if (!nd_load(&pfil_nd, "pfil_sync", pfil_report, NULL,
		     (void *)&pfh_sync)) {
		nd_free(&pfil_nd);
		return -1;
	}

	if (!nd_load(&pfil_nd, "pfil_hl", NULL, pfil_hl_set, NULL)) {
		nd_free(&pfil_nd);
		return -1;
	}

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_nd_fini                                                */
/* Returns:     void                                                        */
/* Parameters:  None.                                                       */
/*                                                                          */
/* Clean up any data structures related to ndd processing in preparation    */
/* for the module being unloaded.                                           */
/* ------------------------------------------------------------------------ */
void pfil_nd_fini()
{

	nd_free(&pfil_nd);
}


/* ------------------------------------------------------------------------ */
/* Function:    qif_report                                                  */
/* Returns:     int                                                         */
/* Parameters:  q(I)    - pointer to queue                                  */
/*              mp(I)   - pointer to mblk                                   */
/*              ptr(I)  - pointer to value to retrieve                      */
/*              cred(I) - pointer to credential information                 */
/*                                                                          */
/* Fills the mblk with any qif data that happens to be currently available. */
/* ------------------------------------------------------------------------ */
#if !defined(sun) || SOLARIS2 <= 8
/*ARGSUSED*/
static int qif_report(queue_t *q, mblk_t *mp, caddr_t arg)
#else
/*ARGSUSED*/
static int qif_report(queue_t *q, mblk_t *mp, caddr_t arg, cred_t *cred)
#endif
{
	qif_t *qif;

	(void) mi_mpprintf(mp,
		   "ifname ill q OTHERQ ipmp num sap hl nr nw bad copy copyfail drop notip nodata notdata");
	READ_ENTER(&pfil_rw);
	for (qif = qif_head ; qif; qif = qif->qf_next)
		(void) mi_mpprintf(mp,
			"%s %p %p %p %p %d %x %d %lu %lu %lu %lu %lu %lu %lu %lu %lu",
				   qif->qf_name, (void *)qif->qf_ill,
				   (void *)qif->qf_q, (void *)qif->qf_oq,
				   (void *)qif->qf_ipmp, qif->qf_num,
				   qif->qf_sap, (int)qif->qf_hl,
				   qif->qf_nr, qif->qf_nw, qif->qf_bad,
				   qif->qf_copy, qif->qf_copyfail,
				   qif->qf_drop, qif->qf_notip,
				   qif->qf_nodata, qif->qf_notdata);
	RW_EXIT(&pfil_rw);
	return 0;
}



/* ------------------------------------------------------------------------ */
/* Function:    sill_report                                                 */
/* Returns:     int                                                         */
/* Parameters:  q(I)    - pointer to queue                                  */
/*              mp(I)   - pointer to mblk                                   */
/*              ptr(I)  - pointer to value to retrieve                      */
/*              cred(I) - pointer to credential information                 */
/*                                                                          */
/* Fills the mblk with any shadow ill (s_illt) data that happens to be      */
/* currently available.                                                     */
/* ------------------------------------------------------------------------ */
#if !defined(sun) || SOLARIS2 <= 8
/*ARGSUSED*/
static int sill_report(queue_t *q, mblk_t *mp, caddr_t arg)
#else
/*ARGSUSED*/
static int sill_report(queue_t *q, mblk_t *mp, caddr_t arg, cred_t *cred)
#endif
{
	s_ill_t *sill;

	(void) mi_mpprintf(mp,
		   "sill name sap mtu localaddr netmask broadaddr dstaddr");
	READ_ENTER(&pfil_rw);
	for (sill = s_ill_g_head ; sill; sill = sill->ill_next)
		(void) mi_mpprintf(mp, "%p %s %x %u %x %x %x %x",
				   (void *)sill, sill->ill_name, sill->ill_sap,
				   sill->mtu,
				   sill->localaddr.in.sin_addr.s_addr,
				   sill->netmask.in.sin_addr.s_addr,
				   sill->broadaddr.in.sin_addr.s_addr,
				   sill->dstaddr.in.sin_addr.s_addr);
	RW_EXIT(&pfil_rw);
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    qif_ipmp_report                                             */
/* Returns:     int                                                         */
/* Parameters:  q(I)    - pointer to queue                                  */
/*              mp(I)   - pointer to mblk                                   */
/*              ptr(I)  - pointer to value to retrieve                      */
/*              cred(I) - pointer to credential information                 */
/*                                                                          */
/* Fills the mblk with any qif data that happens to be currently available. */
/* ------------------------------------------------------------------------ */
#if !defined(sun) || SOLARIS2 <= 8
/*ARGSUSED*/
static int qif_ipmp_report(queue_t *q, mblk_t *mp, caddr_t arg)
#else
/*ARGSUSED*/
static int qif_ipmp_report(queue_t *q, mblk_t *mp, caddr_t arg, cred_t *cred)
#endif
{
	qif_t *qif;

	(void) mi_mpprintf(mp, "ifname members");
	READ_ENTER(&pfil_rw);
	for (qif = qif_head ; qif; qif = qif->qf_next) {
		if ((qif->qf_flags & QF_IPMP) == 0)
			continue;
		(void) mi_mpprintf(mp, "%s %s", qif->qf_name, qif->qf_members);
	}
	RW_EXIT(&pfil_rw);
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    qif_ipmp_set                                                */
/* Returns:     int     - 0 == success, > 0 error occurred                  */
/* Parameters:  q(I)    - pointer to queue                                  */
/*              mp(I)   - pointer to mblk                                   */
/*              str(I)  - pointer to new value as a string                  */
/*              ptr(I)  - pointer to value to be stored                     */
/*              cred(I) - pointer to credential information                 */
/*                                                                          */
/* This function is a wrapper for qif_ipmp_update(), providing a run-time   */
/* interactive way to configure the IPMP configuration for pfil without     */
/* needing to load/unload the module to reread the config file (or is there */
/* a way to do that once loaded, anyway?)                                   */
/* ------------------------------------------------------------------------ */
#if !defined(sun) || SOLARIS2 <= 8
/*ARGSUSED*/
static int qif_ipmp_set(queue_t *q, mblk_t *mp, char *str, caddr_t ptr)
#else
/*ARGSUSED*/
static int qif_ipmp_set(queue_t *q, mblk_t *mp, char *str, caddr_t ptr,
			cred_t *cred)
#endif
{
	char *s, *t;

	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(2, (CE_CONT, "qif_ipmp_set(0x%p,0x%p,0x%s[%p],0x%p)\n",
		  (void *)q, (void *)mp, str, (void *)str, (void *)ptr));

	t = NULL;
	s = str;
	do {
		if (t != NULL)
			s = t + 1;
		t = strchr(s, ';');
		if (t != NULL)
			*t = '\0';
		qif_ipmp_update(s);
	} while (t != NULL);

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_hl_set                                                 */
/* Returns:     int     - 0 == success, > 0 error occurred                  */
/* Parameters:  q(I)    - pointer to queue                                  */
/*              mp(I)   - pointer to mblk                                   */
/*              str(I)  - pointer to new value as a string                  */
/*              ptr(I)  - pointer to value to be stored                     */
/*              cred(I) - pointer to credential information                 */
/*                                                                          */
/* Explicitly set the header length (hl) field of the qif structure.  This  */
/* is used in situations where pfil cannot, for some reason, automatically  */
/* determine it via either ioctl snooping or looking at passing messages.   */
/* ndd -set /dev/pfil pfil_hl ipmp0=14  or v4:ipmp0=14                      */
/* ------------------------------------------------------------------------ */
#if !defined(sun) || SOLARIS2 <= 8
/*ARGSUSED*/
static int pfil_hl_set(queue_t *q, mblk_t *mp, char *str, caddr_t ptr)
#else
/*ARGSUSED*/
static int pfil_hl_set(queue_t *q, mblk_t *mp, char *str, caddr_t ptr,
			cred_t *cred)
#endif
{
	char *s, *t;

	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(2, (CE_CONT, "pfil_hl_set(0x%lx,0x%lx,0x%lx[%s],0x%lx)\n",
		  (u_long)q, (u_long)mp, (u_long)str, str, (u_long)ptr));

	t = NULL;
	s = str;
	do {
		if (t != NULL)
			s = t + 1;
		t = strchr(s, ';');
		if (t != NULL)
			*t = '\0';
		qif_hl_set(s);
	} while (t != NULL);

	return 0;
}
