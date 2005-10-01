/*
 * Copyright (C) 2002-2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if defined(KERNEL) || defined(_KERNEL)
# undef KERNEL
# undef _KERNEL
# define        KERNEL	1
# define        _KERNEL	1
#endif
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#if __FreeBSD_version >= 220000 && defined(_KERNEL)
# include <sys/fcntl.h>
# include <sys/filio.h>
#else
# include <sys/ioctl.h>
#endif
#if !defined(_KERNEL)
# include <string.h>
# define _KERNEL
# ifdef __OpenBSD__
struct file;
# endif
# include <sys/uio.h>
# undef _KERNEL
#endif
#include <sys/socket.h>
#include <net/if.h>
#if defined(__FreeBSD__)
#  include <sys/cdefs.h>
#  include <sys/proc.h>
#endif
#if defined(_KERNEL)
# include <sys/systm.h>
# if !defined(__SVR4) && !defined(__svr4__)
#  include <sys/mbuf.h>
# endif
#endif
#include <netinet/in.h>

#if SOLARIS2 >= 10
#include "ip_compat.h"
#include "ip_fil.h"
#include "ip_pool.h"
#include "ip_htable.h"
#include "ip_lookup.h"
#else
#include "netinet/ip_compat.h"
#include "netinet/ip_fil.h"
#include "netinet/ip_pool.h"
#include "netinet/ip_htable.h"
#include "netinet/ip_lookup.h"
#endif

#if !defined(lint)
static const char rcsid[] = "@(#)$Id: ip_lookup.c,v 2.21 2003/06/28 17:01:57 darrenr Exp $";
#endif

#ifdef	IPFILTER_LOOKUP
static ip_pool_stat_t ippoolstate;
# ifdef USE_MUTEXES
ipfrwlock_t	ip_poolrw;
# endif
int	ip_lookup_inited = 0;

static int iplookup_addnode __P((caddr_t));
static int iplookup_delnode __P((caddr_t data));
static int iplookup_addtable __P((caddr_t));
static int iplookup_deltable __P((caddr_t));
static int iplookup_stats __P((caddr_t));
static int iplookup_flush __P((caddr_t));


int ip_lookup_init()
{
	if (ip_pool_init() == -1)
		return -1;

	RWLOCK_INIT(&ip_poolrw, "ip pool rwlock");
	bzero((char *)&ippoolstate, sizeof(ippoolstate));

	ip_lookup_inited = 1;

	return 0;
}


void ip_lookup_unload()
{
	ip_pool_fini();
	fr_htable_unload();

	if (ip_lookup_inited == 1) {
		RW_DESTROY(&ip_poolrw);
		ip_lookup_inited = 0;
	}
}


int ip_lookup_ioctl(data, cmd, mode)
caddr_t data;
# if defined(__NetBSD__) || defined(__OpenBSD__)
u_long cmd;
# else
int cmd;
# endif
int mode;
{
	int err;
# if defined(_KERNEL) && !defined(MENTAT) && defined(USE_SPL)
	int s;
# endif

	mode = mode;	/* LINT */

	SPL_NET(s);

	switch (cmd)
	{
	case SIOCLOOKUPADDNODE :
		WRITE_ENTER(&ip_poolrw);
		err = iplookup_addnode(data);
		if (err == 0)
			ippoolstate.ipls_nodes++;
		RWLOCK_EXIT(&ip_poolrw);
		break;

	case SIOCLOOKUPDELNODE :
		WRITE_ENTER(&ip_poolrw);
		err = iplookup_delnode(data);
		if (err == 0)
			ippoolstate.ipls_nodes--;
		RWLOCK_EXIT(&ip_poolrw);
		break;

	case SIOCLOOKUPADDTABLE :
		WRITE_ENTER(&ip_poolrw);
		err = iplookup_addtable(data);
		RWLOCK_EXIT(&ip_poolrw);
		break;

	case SIOCLOOKUPDELTABLE :
		WRITE_ENTER(&ip_poolrw);
		err = iplookup_deltable(data);
		RWLOCK_EXIT(&ip_poolrw);
		break;

	case SIOCLOOKUPSTAT :
		WRITE_ENTER(&ip_poolrw);
		err = iplookup_stats(data);
		RWLOCK_EXIT(&ip_poolrw);
		break;

	case SIOCLOOKUPFLUSH :
		WRITE_ENTER(&ip_poolrw);
		err = iplookup_flush(data);
		RWLOCK_EXIT(&ip_poolrw);
		break;

	default :
		err = EINVAL;
		break;
	}
	SPL_X(s);
	return err;
}


static int iplookup_addnode(data)
caddr_t data;
{
	ip_pool_node_t node, *m;
	iplookupop_t op;
	iphtable_t *iph;
	iphtent_t hte;
	ip_pool_t *p;
	int err;

	err = COPYIN(data, &op, sizeof(op));
	if (err != 0)
		return EFAULT;
	op.iplo_name[sizeof(op.iplo_name) - 1] = '\0';

	switch (op.iplo_type)
	{
	case IPLT_POOL :
# if defined(_KERNEL) && defined(__osf__)
		return ENOTSUP;
# else
		if (op.iplo_size != sizeof(node))
			return EINVAL;

		err = COPYIN(op.iplo_struct, &node, sizeof(node));
		if (err != 0)
			return EFAULT;

		p = ip_pool_find(op.iplo_unit, op.iplo_name);
		if (p == NULL)
			return ESRCH;

		/*
		 * add an entry to a pool - return an error if it already
		 * exists remove an entry from a pool - if it exists
		 * - in both cases, the pool *must* exist!
		 */
		m = ip_pool_findeq(p, &node.ipn_addr, &node.ipn_mask);
		if (m)
			return EEXIST;
		err = ip_pool_insert(p, &node.ipn_addr,
				     &node.ipn_mask, node.ipn_info);
# endif
		break;

	case IPLT_HASH :
		if (op.iplo_size != sizeof(hte))
			return EINVAL;

		err = COPYIN(op.iplo_struct, &hte, sizeof(hte));
		if (err != 0)
			return EFAULT;

		iph = fr_findhtable(op.iplo_unit, op.iplo_name);
		if (iph == NULL)
			return ESRCH;
		err = fr_addhtent(iph, &hte);
		break;

	default :
		err = EINVAL;
		break;
	}
	return err;
}


static int iplookup_delnode(data)
caddr_t data;
{
	ip_pool_node_t node, *m;
	iplookupop_t op;
	iphtable_t *iph;
	iphtent_t hte;
	ip_pool_t *p;
	int err;

	err = COPYIN(data, &op, sizeof(op));
	if (err != 0)
		return EFAULT;
	op.iplo_name[sizeof(op.iplo_name) - 1] = '\0';

	switch (op.iplo_type)
	{
	case IPLT_POOL :
# if defined(_KERNEL) && defined(__osf__)
		return ENOTSUP;
# else
		if (op.iplo_size != sizeof(node))
			return EINVAL;

		err = COPYIN(op.iplo_struct, &node, sizeof(node));
		if (err != 0)
			return EFAULT;

		p = ip_pool_find(op.iplo_unit, op.iplo_name);
		if (!p)
			return ESRCH;

		/*
		 * add an entry to a pool - return an error if it already
		 * exists remove an entry from a pool - if it exists
		 * - in both cases, the pool *must* exist!
		 */
		m = ip_pool_findeq(p, &node.ipn_addr, &node.ipn_mask);
		if (m == NULL)
			return ENOENT;
		err = ip_pool_remove(p, m);
		break;
# endif

	case IPLT_HASH :
		if (op.iplo_size != sizeof(hte))
			return EINVAL;

		err = COPYIN(op.iplo_struct, &hte, sizeof(hte));
		if (err != 0)
			return EFAULT;

		iph = fr_findhtable(op.iplo_unit, op.iplo_name);
		if (iph == NULL)
			return ESRCH;
		err = fr_delhtent(iph, &hte);
		break;

	default :
		err = EINVAL;
		break;
	}
	return err;
}


static int iplookup_addtable(data)
caddr_t data;
{
	iplookupop_t op;
	int err;

	err = COPYIN(data, &op, sizeof(op));
	if (err != 0)
		return EFAULT;
	op.iplo_name[sizeof(op.iplo_name) - 1] = '\0';

	/*
	 * create a new pool - fail if one already exists with
	 * the same #
	 */
	switch (op.iplo_type)
	{
	case IPLT_POOL :
# if defined(_KERNEL) && defined(__osf__)
		return ENOTSUP;
# else
		if (ip_pool_find(op.iplo_unit, op.iplo_name) != NULL)
			err = EEXIST;
		else
			err = ip_pool_create(&op);
		if (err == 0)
			ippoolstate.ipls_pools++;
		break;
# endif

	case IPLT_HASH :
		if (fr_findhtable(op.iplo_unit, op.iplo_name) != NULL)
			err = EEXIST;
		else
			err = fr_newhtable(&op);
		break;

	default :
		err = EINVAL;
		break;
	}
	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    iplookup_deltable                                           */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* Decodes ioctl request to remove a particular hash table or pool and      */
/* calls the relevant function to do the cleanup.                           */
/* ------------------------------------------------------------------------ */
static int iplookup_deltable(data)
caddr_t data;
{
	iplookupop_t op;
	int err;

	err = COPYIN(data, &op, sizeof(op));
	if (err != 0)
		return EFAULT;
	op.iplo_name[sizeof(op.iplo_name) - 1] = '\0';

	if (op.iplo_arg & IPLT_ANON)
		op.iplo_arg &= IPLT_ANON;

	/*
	 * create a new pool - fail if one already exists with
	 * the same #
	 */
	switch (op.iplo_type)
	{
	case IPLT_POOL :
# if defined(_KERNEL) && defined(__osf__)
		return ENOTSUP;
# else
		err = ip_pool_destroy(&op);
		break;
# endif

	case IPLT_HASH :
		err = fr_removehtable(&op);
		break;

	default :
		err = EINVAL;
		break;
	}
	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    iplookup_stats                                              */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* Copy statistical information from inside the kernel back to user space.  */
/* ------------------------------------------------------------------------ */
static int iplookup_stats(data)
caddr_t data;
{
	iplookupop_t op;
	int err;

	err = 0;
	(void)BCOPYIN(data, &op, sizeof(op));

	switch (op.iplo_type)
	{
	case IPLT_POOL :
		err = ip_pool_statistics(&op);
		break;

	case IPLT_HASH :
		err = fr_gethtablestat(&op);
		break;

	default :
		err = EINVAL;
		break;
	}
	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    iplookup_flush                                              */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* A flush is called when we want to flush all the nodes from a particular  */
/* entry in the hash table/pool or want to remove all groups from those.    */
/* ------------------------------------------------------------------------ */
static int iplookup_flush(data)
caddr_t data;
{
	iphtable_t *iph, *iphn;
	int err, unit, type, i;
	iplookupflush_t flush, opf;
	ip_pool_t *p, *q;
	iplookupop_t op;
	size_t num;

	err = COPYIN(data, &flush, sizeof(flush));
	if (err != 0)
		return EFAULT;

	flush.iplf_name[sizeof(flush.iplf_name) - 1] = '\0';

	unit = flush.iplf_unit;
	if ((unit < 0 || unit > IPL_LOGMAX) && (unit != IPLT_ALL))
		return EINVAL;

	/*
	 * Flush all ?
	 * Or flush n except where n == -1 (all pools)
	 */
	type = flush.iplf_type;
	err = EINVAL;
	num = 0;

	if (type == IPLT_POOL || type == IPLT_ALL) {
# if defined(_KERNEL) && defined(__osf__)
		err = ENOTSUP;
# else
		err = 0;
		if (flush.iplf_arg != IPLT_ALL) {
			op.iplo_unit = unit;
			(void)strncpy(op.iplo_name, flush.iplf_name,
				sizeof(op.iplo_name));
			err = ip_pool_destroy(&op);
			if (err == 0)
				num++;
		} else {
			for (i = 0; i <= IPL_LOGMAX; i++) {
				if (unit != IPLT_ALL && i != unit)
					continue;
				for (q = ip_pool_list[i]; (p = q) != NULL; ) {
					op.iplo_unit = i;
					(void)strncpy(op.iplo_name, p->ipo_name,
						sizeof(op.iplo_name));
					q = p->ipo_next;
					err = ip_pool_destroy(&op);
					if (err == 0)
						num++;
					else
						break;
				}
			}
		}
# endif
	}

	if (type == IPLT_HASH  || type == IPLT_ALL) {
		err = 0;
		if (flush.iplf_arg != IPLT_ALL) {
			opf.iplf_unit = unit;
			(void)strncpy(opf.iplf_name, flush.iplf_name,
				      sizeof(opf.iplf_name));
			num += fr_flushhtable(&opf);
		}
		else {
			for (i = 0; i <= IPL_LOGMAX; i++) {
				if (unit != IPLT_ALL && i != unit)
					continue;
				for (iphn = ipf_htables[i];
				     (iph = iphn) != NULL; ) {
					opf.iplf_unit = i;
					(void)strncpy(opf.iplf_name,
						      iph->iph_name,
						      sizeof(opf.iplf_name));
					iphn = iph->iph_next;
					num += fr_flushhtable(&opf);
				}
			}
		}
	}

	if (err == 0) {
		flush.iplf_count = num;
		err = COPYOUT(&flush, data, sizeof(flush));
	}
	return err;
}


void ip_lookup_deref(type, ptr)
int type;
void *ptr;
{
	if (ptr == NULL)
		return;

	WRITE_ENTER(&ip_poolrw);
	switch (type)
	{
	case IPLT_POOL :
		ip_pool_deref(ptr);
		break;
	case IPLT_HASH :
		fr_derefhtable(ptr);
		break;
	}
	RWLOCK_EXIT(&ip_poolrw);
}


#else /* IPFILTER_LOOKUP */

/*ARGSUSED*/
int ip_lookup_ioctl(data, cmd, mode)
caddr_t data;
# if defined(__NetBSD__) || defined(__OpenBSD__)
u_long cmd;
# else
int cmd;
# endif
int mode;
{
	return EIO;
}
#endif /* IPFILTER_LOOKUP */
