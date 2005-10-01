/*
 * Copyright (C) 2000, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * ident "@(#)$Id: pfil.c,v 1.22 2003/08/18 22:13:59 darrenr Exp $"
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef __hpux
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#else
struct uio;
#endif

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/poll.h>
#include <sys/byteorder.h>
#include <sys/socket.h>
#ifdef sun
# include <sys/kmem.h>
#endif
#include <sys/dlpi.h>
#include <sys/lock.h>
#include <sys/stropts.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifdef sun
# include <inet/common.h>
# if SOLARIS2 >= 8
#  include <netinet/ip6.h>
# endif
# undef IPOPT_EOL
# undef IPOPT_NOP
# undef IPOPT_LSRR
# undef IPOPT_SSRR
# undef IPOPT_RR
# include <inet/ip.h>
#endif

#include "compat.h"
#include "qif.h"
#include "pfil.h"


int	pfil_delayed_copy = 1;
int	pfilinterface = PFIL_INTERFACE;
/*
** HPUX Port
** Align these structs to 16 bytes
** so that the embedded locks (first member)
** are 16 byte aligned
*/
#ifdef	__hpux
#pragma align 16
struct	pfil_head	pfh_inet4 = { 0, NULL, NULL, 0 };
#pragma align 16
struct	pfil_head	pfh_inet6 = { 0, NULL, NULL, 0 };
#pragma align 16
struct	pfil_head	pfh_sync = { 0, NULL, NULL, 0 };
#else
struct	pfil_head	pfh_inet4;
struct	pfil_head	pfh_inet6;
struct	pfil_head	pfh_sync;
#endif


static int pfil_list_add(pfil_list_t *,
			 int (*) __P((struct ip *, int, void *, int,
				      struct qif *, mblk_t **)),
			 int);
static int pfil_list_remove(pfil_list_t *,
			 int (*) __P((struct ip *, int, void *, int,
				      struct qif *, mblk_t **)));


/* ------------------------------------------------------------------------ */
/* Function:    pfil_report                                                 */
/* Returns:     int     - always returns 0                                  */
/* Parameters:  q(I)    - pointer to queue                                  */
/*              mp(I)   - pointer to mblk                                   */
/*              arg(I)  - pointer to value to retrieve                      */
/*              cred(I) - pointer to credential information                 */
/*                                                                          */
/* Returns a list of the registered callbacks for processing packets going  */
/* in and out on a particular filtering head structure                      */
/* ------------------------------------------------------------------------ */
#if !defined(sun) || (SOLARIS2 <= 8)
/*ARGSUSED*/
int pfil_report(queue_t *q, mblk_t *mp, caddr_t arg)
#else
/*ARGSUSED*/
int pfil_report(queue_t *q, mblk_t *mp, caddr_t arg, cred_t *cred)
#endif
{
	packet_filter_hook_t *p;
	pfil_head_t *ph;

	ph = (pfil_head_t *)arg;

	READ_ENTER(&ph->ph_lock);

	(void) mi_mpprintf(mp, "in");
	(void) mi_mpprintf(mp, "function\tflags");
	for (p = ph->ph_in.pfl_top; p; p = p->pfil_next)
		(void)mi_mpprintf(mp,"%p\t%x", 
				  (void *)p->pfil_func, p->pfil_flags);

	(void) mi_mpprintf(mp, "out");
	(void) mi_mpprintf(mp, "function\tflags");
	for (p = ph->ph_out.pfl_top; p; p = p->pfil_next)
		(void)mi_mpprintf(mp,"%p\t%x",
				  (void *)p->pfil_func, p->pfil_flags);

	RW_EXIT(&ph->ph_lock);

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_init                                                   */
/* Returns:     void                                                        */
/* Parameters:  ph(I) - pointer to pfil head structure                      */
/*                                                                          */
/* Initialise a pfil_head structure.                                        */
/* ------------------------------------------------------------------------ */
void
pfil_init(ph)
	 struct pfil_head *ph;
{
#ifdef sun
	rw_init(&ph->ph_lock, "pfil head", RW_DRIVER, NULL);
#endif
#ifdef __hpux
	initlock(&ph->ph_lock, PFIL_SMAJ, 1020, "pfil head");
#endif
	ph->ph_in.pfl_top = NULL;
	ph->ph_in.pfl_tail = &ph->ph_in.pfl_top;
	ph->ph_out.pfl_top = NULL;
	ph->ph_out.pfl_tail = &ph->ph_out.pfl_top;
	ph->ph_init = 1;
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_add_hook                                               */
/* Returns:     int      - 0 == success, else error.                        */
/* Parameters:  func(I)  - function pointer to add                          */
/*              flags(I) - flags describing for which events to call the    */
/*                         passed function                                  */
/*              ph(I)    - pointer to callback head structure               */
/*                                                                          */
/* This function is the public interface for adding a callback function to  */
/* a list of callbacks for a particular protocol head (ph).                 */
/*                                                                          */
/* pfil_add_hook() adds a function to the packet filter hook.  the          */
/* flags are:                                                               */
/*	PFIL_IN		call me on incoming packets                         */
/*	PFIL_OUT	call me on outgoing packets                         */
/*	PFIL_WAITOK	OK to call malloc and wait whilst adding this hook  */
/* ------------------------------------------------------------------------ */
int
pfil_add_hook(func, flags, ph)
	int	(*func) __P((struct ip *, int, void *, int,
			     struct qif *, mblk_t **));
	int	flags;
	struct	pfil_head	*ph;
{
	int err = 0;

	ASSERT((flags & ~(PFIL_IN|PFIL_OUT|PFIL_WAITOK)) == 0);

	if (ph->ph_init == 0)
		pfil_init(ph);

	WRITE_ENTER(&ph->ph_lock);

	if (flags & PFIL_IN)
		err = pfil_list_add(&ph->ph_in, func, flags);

	if ((err == 0) && (flags & PFIL_OUT))
		err = pfil_list_add(&ph->ph_out, func, flags);

	RW_EXIT(&ph->ph_lock);

	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_list_add                                               */
/* Returns:     int      - 0 == success, else error.                        */
/* Parameters:  list(I)  - pfil list pointer                                */
/*              func(I)  - function pointer to add                          */
/*              flags(I) - flags describing for which events to call the    */
/*                         passed function                                  */
/* Write Locks: list's owner                                                */
/*                                                                          */
/* Adds the function (func) to the end of the list of functions.            */
/* ------------------------------------------------------------------------ */
static int
pfil_list_add(list, func, flags)
	pfil_list_t *list;
	int	(*func) __P((struct ip *, int, void *, int,
			     struct qif *, mblk_t **));
	int flags;
{
	struct packet_filter_hook *pfh;
	int wait;

	for (pfh = list->pfl_top; pfh; pfh = pfh->pfil_next)
		if (pfh->pfil_func == func)
			return EEXIST;

	wait = flags & PFIL_WAITOK ? KM_SLEEP : KM_NOSLEEP;

	KMALLOC(pfh, struct packet_filter_hook *, sizeof(*pfh), wait);
	if (pfh == NULL)
		return ENOMEM;
	pfh->pfil_func = func;
	pfh->pfil_flags = flags;

	/*
	 * insert the input list in reverse order of the output list
	 * so that the hooks are called in the reverse order for each
	 * direction.  So if it was A,B,C for input, it is C,B,A for output.
	 */

	if (flags & PFIL_OUT) {
		pfh->pfil_pnext = list->pfl_tail;
		*list->pfl_tail = pfh;
		list->pfl_tail = &pfh->pfil_next;
	} else if (flags & PFIL_IN) {
		pfh->pfil_pnext = &list->pfl_top;
		pfh->pfil_next = list->pfl_top;
		list->pfl_top = pfh;
		if (pfh->pfil_next == NULL)
			list->pfl_tail = &pfh->pfil_next;
	}

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_remove_hook                                            */
/* Returns:     int      - 0 == success, else error.                        */
/* Parameters:  func(I)  - function pointer to remove                       */
/*              flags(I) - flags describing for which events to call the    */
/*                         passed function                                  */
/*              ph(I)    - pointer to callback head structure               */
/*                                                                          */
/* pfil_remove_hook removes a specific function from a particular           */
/* pfil_head's list of callbacks as given by which flags have been passed.  */
/* ------------------------------------------------------------------------ */
int
pfil_remove_hook(func, flags, ph)
	int	(*func) __P((struct ip *, int, void *, int,
			     struct qif *, mblk_t **));
	int	flags;
	struct	pfil_head	*ph;
{
	int err = 0;

	ASSERT((flags & ~(PFIL_IN|PFIL_OUT)) == 0);

	if (ph->ph_init == 0)
		pfil_init(ph);

	WRITE_ENTER(&ph->ph_lock);

	if (flags & PFIL_IN)
		err = pfil_list_remove(&ph->ph_in, func);

	if ((err == 0) && (flags & PFIL_OUT))
		err = pfil_list_remove(&ph->ph_out, func);

	RW_EXIT(&ph->ph_lock);

	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_list_remove                                            */
/* Returns:     int     - 0 == success, else error.                         */
/* Parameters:  list(I) - pfil list pointer                                 */
/*              func(I) - function pointer to remove                        */
/* Write Locks: list's owner                                                */
/*                                                                          */
/* pfil_list_remove is an internal function that takes a function off the   */
/* specified pfil list, providing that a match for func is found.           */
/* ------------------------------------------------------------------------ */
static int
pfil_list_remove(list, func)
	pfil_list_t *list;
	int	(*func) __P((struct ip *, int, void *, int,
			     struct qif *, mblk_t **));
{
	struct packet_filter_hook *pfh;

	for (pfh = list->pfl_top; pfh; pfh = pfh->pfil_next)
		if (pfh->pfil_func == func) {
			*pfh->pfil_pnext = pfh->pfil_next;
			if (list->pfl_tail == &pfh->pfil_next)
				list->pfl_tail = pfh->pfil_pnext;
			KMFREE(pfh, sizeof(*pfh));
			return 0;
		}

	return ESRCH;
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_hook_get                                               */
/* Returns:     struct packet_filter_hook * - pointer to first member in    */
/*                                            list of callbacks or NULL if  */
/*                                            if there are none.            */
/* Parameters:  flags(I) - indicates which callback list to return          */ 
/*              ph(I)    - pointer to callback head structure               */
/* Locks:       READ(ph->ph_lock)                                           */
/*                                                                          */
/* Returns the first pointer of the list associated with "flags" or NULL if */
/* flags is not a recognised value.                                         */
/* ------------------------------------------------------------------------ */
struct packet_filter_hook *
pfil_hook_get(flag, ph)
	int flag;
	struct	pfil_head	*ph;
{

	/* ASSERT(rw_read_locked(&ph->ph_lock) != 0); */

	if (ph->ph_init != 0) {
		switch (flag)
		{
		case PFIL_IN:
			return ph->ph_in.pfl_top;
		case PFIL_OUT:
			return ph->ph_out.pfl_top;
		}
	}
	return NULL;
}
