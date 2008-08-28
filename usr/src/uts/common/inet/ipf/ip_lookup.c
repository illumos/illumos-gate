/*
 * Copyright (C) 2002-2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if defined(KERNEL) || defined(_KERNEL)
# undef KERNEL
# undef _KERNEL
# define        KERNEL	1
# define        _KERNEL	1
#endif
#if defined(__osf__)
# define _PROTO_NET_H_
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
#if (defined(__osf__) || defined(AIX) || defined(__hpux) || defined(__sgi)) && defined(_KERNEL)
# ifdef __osf__
#  include <net/radix.h>
# endif
# include "radix_ipf_local.h"
# define _RADIX_H_
#endif
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

#include "netinet/ip_compat.h"
#include "netinet/ip_fil.h"
#include "netinet/ip_pool.h"
#include "netinet/ip_htable.h"
#include "netinet/ip_lookup.h"
#include "netinet/ipf_stack.h"
/* END OF INCLUDES */

#if !defined(lint)
static const char rcsid[] = "@(#)$Id: ip_lookup.c,v 2.35.2.7 2005/06/12 07:18:20 darrenr Exp $";
#endif

#ifdef	IPFILTER_LOOKUP
static int iplookup_addnode __P((caddr_t, ipf_stack_t *));
static int iplookup_delnode __P((caddr_t data, ipf_stack_t *));
static int iplookup_addtable __P((caddr_t, ipf_stack_t *));
static int iplookup_deltable __P((caddr_t, ipf_stack_t *));
static int iplookup_stats __P((caddr_t, ipf_stack_t *));
static int iplookup_flush __P((caddr_t, ipf_stack_t *));



/* ------------------------------------------------------------------------ */
/* Function:    iplookup_init                                               */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Initialise all of the subcomponents of the lookup infrstructure.         */
/* ------------------------------------------------------------------------ */
int ip_lookup_init(ifs)
ipf_stack_t *ifs;
{

	if (ip_pool_init(ifs) == -1)
		return -1;

	RWLOCK_INIT(&ifs->ifs_ip_poolrw, "ip pool rwlock");

	ifs->ifs_ip_lookup_inited = 1;
	ifs->ifs_ipftokenhead = NULL;
	ifs->ifs_ipftokentail = &ifs->ifs_ipftokenhead;
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    iplookup_unload                                             */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Free up all pool related memory that has been allocated whilst IPFilter  */
/* has been running.  Also, do any other deinitialisation required such     */
/* ip_lookup_init() can be called again, safely.                            */
/* ------------------------------------------------------------------------ */
void ip_lookup_unload(ifs)
ipf_stack_t *ifs;
{
	ip_pool_fini(ifs);
	fr_htable_unload(ifs);

	if (ifs->ifs_ip_lookup_inited == 1) {
		RW_DESTROY(&ifs->ifs_ip_poolrw);
		ifs->ifs_ip_lookup_inited = 0;
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    iplookup_ioctl                                              */
/* Returns:     int      - 0 = success, else error                          */
/* Parameters:  data(IO) - pointer to ioctl data to be copied to/from user  */
/*                         space.                                           */
/*              cmd(I)   - ioctl command number                             */
/*              mode(I)  - file mode bits used with open                    */
/*                                                                          */
/* Handle ioctl commands sent to the ioctl device.  For the most part, this */
/* involves just calling another function to handle the specifics of each   */
/* command.                                                                 */
/* ------------------------------------------------------------------------ */
int ip_lookup_ioctl(data, cmd, mode, uid, ctx, ifs)
caddr_t data;
ioctlcmd_t cmd;
int mode, uid;
void *ctx;
ipf_stack_t *ifs;
{
	int err;
	SPL_INT(s);

	mode = mode;	/* LINT */

	SPL_NET(s);

	switch (cmd)
	{
	case SIOCLOOKUPADDNODE :
	case SIOCLOOKUPADDNODEW :
		WRITE_ENTER(&ifs->ifs_ip_poolrw);
		err = iplookup_addnode(data, ifs);
		RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
		break;

	case SIOCLOOKUPDELNODE :
	case SIOCLOOKUPDELNODEW :
		WRITE_ENTER(&ifs->ifs_ip_poolrw);
		err = iplookup_delnode(data, ifs);
		RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
		break;

	case SIOCLOOKUPADDTABLE :
		WRITE_ENTER(&ifs->ifs_ip_poolrw);
		err = iplookup_addtable(data, ifs);
		RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
		break;

	case SIOCLOOKUPDELTABLE :
		WRITE_ENTER(&ifs->ifs_ip_poolrw);
		err = iplookup_deltable(data, ifs);
		RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
		break;

	case SIOCLOOKUPSTAT :
	case SIOCLOOKUPSTATW :
		WRITE_ENTER(&ifs->ifs_ip_poolrw);
		err = iplookup_stats(data, ifs);
		RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
		break;

	case SIOCLOOKUPFLUSH :
		WRITE_ENTER(&ifs->ifs_ip_poolrw);
		err = iplookup_flush(data, ifs);
		RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
		break;

	case SIOCLOOKUPITER :
		err = ip_lookup_iterate(data, uid, ctx, ifs);
		break;

	default :
		err = EINVAL;
		break;
	}
	SPL_X(s);
	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    iplookup_addnode                                            */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* Add a new data node to a lookup structure.  First, check to see if the   */
/* parent structure refered to by name exists and if it does, then go on to */
/* add a node to it.                                                        */
/* ------------------------------------------------------------------------ */
static int iplookup_addnode(data, ifs)
caddr_t data;
ipf_stack_t *ifs;
{
	ip_pool_node_t node, *m;
	iplookupop_t op;
	iphtable_t *iph;
	iphtent_t hte;
	ip_pool_t *p;
	int err;

	err = BCOPYIN(data, &op, sizeof(op));
	if (err != 0)
		return EFAULT;

	op.iplo_name[sizeof(op.iplo_name) - 1] = '\0';

	switch (op.iplo_type)
	{
	case IPLT_POOL :
		if (op.iplo_size != sizeof(node))
			return EINVAL;

		err = COPYIN(op.iplo_struct, &node, sizeof(node));
		if (err != 0)
			return EFAULT;

		p = ip_pool_find(op.iplo_unit, op.iplo_name, ifs);
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
				     &node.ipn_mask, node.ipn_info, ifs);
		break;

	case IPLT_HASH :
		if (op.iplo_size != sizeof(hte))
			return EINVAL;

		err = COPYIN(op.iplo_struct, &hte, sizeof(hte));
		if (err != 0)
			return EFAULT;

		iph = fr_findhtable(op.iplo_unit, op.iplo_name, ifs);
		if (iph == NULL)
			return ESRCH;
		err = fr_addhtent(iph, &hte, ifs);
		break;

	default :
		err = EINVAL;
		break;
	}
	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    iplookup_delnode                                            */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* Delete a node from a lookup table by first looking for the table it is   */
/* in and then deleting the entry that gets found.                          */
/* ------------------------------------------------------------------------ */
static int iplookup_delnode(data, ifs)
caddr_t data;
ipf_stack_t *ifs;
{
	ip_pool_node_t node, *m;
	iplookupop_t op;
	iphtable_t *iph;
	iphtent_t hte;
	ip_pool_t *p;
	int err;

	err = BCOPYIN(data, &op, sizeof(op));
	if (err != 0)
		return EFAULT;

	op.iplo_name[sizeof(op.iplo_name) - 1] = '\0';

	switch (op.iplo_type)
	{
	case IPLT_POOL :
		if (op.iplo_size != sizeof(node))
			return EINVAL;

		err = COPYIN(op.iplo_struct, &node, sizeof(node));
		if (err != 0)
			return EFAULT;

		p = ip_pool_find(op.iplo_unit, op.iplo_name, ifs);
		if (!p)
			return ESRCH;

		m = ip_pool_findeq(p, &node.ipn_addr, &node.ipn_mask);
		if (m == NULL)
			return ENOENT;
		err = ip_pool_remove(p, m, ifs);
		break;

	case IPLT_HASH :
		if (op.iplo_size != sizeof(hte))
			return EINVAL;

		err = COPYIN(op.iplo_struct, &hte, sizeof(hte));
		if (err != 0)
			return EFAULT;

		iph = fr_findhtable(op.iplo_unit, op.iplo_name, ifs);
		if (iph == NULL)
			return ESRCH;
		err = fr_delhtent(iph, &hte, ifs);
		break;

	default :
		err = EINVAL;
		break;
	}
	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    iplookup_addtable                                           */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* Create a new lookup table, if one doesn't already exist using the name   */
/* for this one.                                                            */
/* ------------------------------------------------------------------------ */
static int iplookup_addtable(data, ifs)
caddr_t data;
ipf_stack_t *ifs;
{
	iplookupop_t op;
	int err;

	err = BCOPYIN(data, &op, sizeof(op));
	if (err != 0)
		return EFAULT;

	op.iplo_name[sizeof(op.iplo_name) - 1] = '\0';

	switch (op.iplo_type)
	{
	case IPLT_POOL :
		if (ip_pool_find(op.iplo_unit, op.iplo_name, ifs) != NULL)
			err = EEXIST;
		else
			err = ip_pool_create(&op, ifs);
		break;

	case IPLT_HASH :
		if (fr_findhtable(op.iplo_unit, op.iplo_name, ifs) != NULL)
			err = EEXIST;
		else
			err = fr_newhtable(&op, ifs);
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
static int iplookup_deltable(data, ifs)
caddr_t data;
ipf_stack_t *ifs;
{
	iplookupop_t op;
	int err;

	err = BCOPYIN(data, &op, sizeof(op));
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
		err = ip_pool_destroy(&op, ifs);
		break;

	case IPLT_HASH :
		err = fr_removehtable(&op, ifs);
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
static int iplookup_stats(data, ifs)
caddr_t data;
ipf_stack_t *ifs;
{
	iplookupop_t op;
	int err;

	err = BCOPYIN(data, &op, sizeof(op));
	if (err != 0)
		return EFAULT;

	switch (op.iplo_type)
	{
	case IPLT_POOL :
		err = ip_pool_statistics(&op, ifs);
		break;

	case IPLT_HASH :
		err = fr_gethtablestat(&op, ifs);
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
static int iplookup_flush(data, ifs)
caddr_t data;
ipf_stack_t *ifs;
{
	int err, unit, num, type;
	iplookupflush_t flush;

	err = BCOPYIN(data, &flush, sizeof(flush));
	if (err != 0)
		return EFAULT;

	flush.iplf_name[sizeof(flush.iplf_name) - 1] = '\0';

	unit = flush.iplf_unit;
	if ((unit < 0 || unit > IPL_LOGMAX) && (unit != IPLT_ALL))
		return EINVAL;

	type = flush.iplf_type;
	err = EINVAL;
	num = 0;

	if (type == IPLT_POOL || type == IPLT_ALL) {
		err = 0;
		num = ip_pool_flush(&flush, ifs);
	}

	if (type == IPLT_HASH  || type == IPLT_ALL) {
		err = 0;
		num += fr_flushhtable(&flush, ifs);
	}

	if (err == 0) {
		flush.iplf_count = num;
		err = COPYOUT(&flush, data, sizeof(flush));
	}
	return err;
}



void ip_lookup_deref(type, ptr, ifs)
int type;
void *ptr;
ipf_stack_t *ifs;
{
	if (ptr == NULL)
		return;

	WRITE_ENTER(&ifs->ifs_ip_poolrw);
	switch (type)
	{
	case IPLT_POOL :
		ip_pool_deref(ptr, ifs);
		break;

	case IPLT_HASH :
		fr_derefhtable(ptr, ifs);
		break;
	}
	RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
}

	
int ip_lookup_iterate(data, uid, ctx, ifs)
void *data;
int uid;
void *ctx;
ipf_stack_t *ifs;
{
	ipflookupiter_t iter;
	ipftoken_t *token;
	int err;

	err = fr_inobj(data, &iter, IPFOBJ_LOOKUPITER);
	if (err != 0) {
#ifdef _KERNEL
		(void) printf("fr_inobj\n");
#endif
		return err;
	}

	if (iter.ili_unit < 0 || iter.ili_unit > IPL_LOGMAX) {
#ifdef _KERNEL
		(void) printf("unit=%d\n", iter.ili_unit);
#endif
		return EINVAL;
	}

	if (iter.ili_ival != IPFGENITER_LOOKUP) {
#ifdef _KERNEL
		(void) printf("ival=%d\n", iter.ili_ival);
#endif
		return EINVAL;
	}

	token = ipf_findtoken(iter.ili_key, uid, ctx, ifs);
	if (token == NULL) {
		RWLOCK_EXIT(&ifs->ifs_ipf_tokens);
		return ESRCH;
	}

	switch (iter.ili_type)
	{
	case IPLT_POOL :
		err = ip_pool_getnext(token, &iter, ifs);
		break;
	case IPLT_HASH :
		err = fr_htable_getnext(token, &iter, ifs);
		break;
	default :
#ifdef _KERNEL
		(void) printf("type=%d\n", iter.ili_type);
#endif
		err = EINVAL;
		break;
	}
	RWLOCK_EXIT(&ifs->ifs_ipf_tokens);

	return err;
}


void ip_lookup_iterderef(type, data, ifs)
u_32_t type;
void *data;
ipf_stack_t *ifs;
{
	iplookupiterkey_t	key;

	key.ilik_key = type;

	if (key.ilik_unstr.ilik_ival != IPFGENITER_LOOKUP)
		return;

	switch (key.ilik_unstr.ilik_type)
	{
	case IPLT_HASH :
		fr_htable_iterderef((u_int)key.ilik_unstr.ilik_otype,
				    (int)key.ilik_unstr.ilik_unit, data, ifs);
		break;
	case IPLT_POOL :
		ip_pool_iterderef((u_int)key.ilik_unstr.ilik_otype,
				  (int)key.ilik_unstr.ilik_unit, data, ifs);
		break;
	}
}


#else /* IPFILTER_LOOKUP */

/*ARGSUSED*/
int ip_lookup_ioctl(data, cmd, mode, uid, ifs)
caddr_t data;
ioctlcmd_t cmd;
int mode, uid;
ipf_stack_t *ifs;
{
	return EIO;
}
#endif /* IPFILTER_LOOKUP */
