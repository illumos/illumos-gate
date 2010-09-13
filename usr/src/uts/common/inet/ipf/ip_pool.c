/*
 * Copyright (C) 1993-2001, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#if !defined(_KERNEL) && !defined(__KERNEL__)
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# define _KERNEL
# ifdef __OpenBSD__
struct file;
# endif
# include <sys/uio.h>
# undef _KERNEL
#else
# include <sys/systm.h>
# if defined(NetBSD) && (__NetBSD_Version__ >= 104000000)
#  include <sys/proc.h>
# endif
#endif
#include <sys/time.h>
#if !defined(linux)
# include <sys/protosw.h>
#endif
#include <sys/socket.h>
#if defined(_KERNEL) && (!defined(__SVR4) && !defined(__svr4__))
# include <sys/mbuf.h>
#endif
#if defined(__SVR4) || defined(__svr4__)
# include <sys/filio.h>
# include <sys/byteorder.h>
# ifdef _KERNEL
#  include <sys/dditypes.h>
# endif
# include <sys/stream.h>
# include <sys/kmem.h>
#endif
#if defined(__FreeBSD_version) && (__FreeBSD_version >= 300000)
# include <sys/malloc.h>
#endif

#if defined(_KERNEL) && (defined(__osf__) || defined(AIX) || \
     defined(__hpux) || defined(__sgi))
# ifdef __osf__
#  include <net/radix.h>
# endif
# include "radix_ipf_local.h"
# define _RADIX_H_
#endif
#include <net/if.h>
#include <netinet/in.h>

#include "netinet/ipf_stack.h"
#include "netinet/ip_compat.h"
#include "netinet/ip_fil.h"
#include "netinet/ip_pool.h"

#if defined(IPFILTER_LOOKUP) && defined(_KERNEL) && \
      ((BSD >= 198911) && !defined(__osf__) && \
      !defined(__hpux) && !defined(__sgi))
static int rn_freenode __P((struct radix_node *, void *));
#endif

/* END OF INCLUDES */

#if !defined(lint)
static const char sccsid[] = "@(#)ip_fil.c	2.41 6/5/96 (C) 1993-2000 Darren Reed";
static const char rcsid[] = "@(#)$Id: ip_pool.c,v 2.55.2.14 2005/06/12 07:18:26 darrenr Exp $";
#endif

#ifdef IPFILTER_LOOKUP

/*
 * Binary tree routines from Sedgewick and enhanced to do ranges of addresses.
 * NOTE: Insertion *MUST* be from greatest range to least for it to work!
 * These should be replaced, eventually, by something else - most notably a
 * interval searching method.  The important feature is to be able to find
 * the best match.
 *
 * So why not use a radix tree for this?  As the first line implies, it
 * has been written to work with a _range_ of addresses.  A range is not
 * necessarily a match with any given netmask so what we end up dealing
 * with is an interval tree.  Implementations of these are hard to find
 * and the one herein is far from bug free.
 *
 * Sigh, in the end I became convinced that the bugs the code contained did
 * not make it worthwhile not using radix trees.  For now the radix tree from
 * 4.4 BSD is used, but this is not viewed as a long term solution.
 */

#ifdef TEST_POOL
void treeprint __P((ip_pool_t *));

int
main(argc, argv)
	int argc;
	char *argv[];
{
	addrfamily_t a, b;
	iplookupop_t op;
	ip_pool_t *ipo;
	i6addr_t ip;
	fr_info_t fin;

	RWLOCK_INIT(&ifs->ifs_ip_poolrw, "poolrw");
	ip_pool_init(ifs);

	bzero((char *)&a, sizeof(a));
	bzero((char *)&b, sizeof(b));
	bzero((char *)&ip, sizeof(ip));
	bzero((char *)&op, sizeof(op));
	strcpy(op.iplo_name, "0");

	if (ip_pool_create(&op, ifs) == 0)
		ipo = ip_pool_find(0, "0", ifs);

	a.adf_addr.in4.s_addr = 0x0a010203;
	b.adf_addr.in4.s_addr = 0xffffffff;
	ip_pool_insert(ipo, &a, &b, 1, ifs);
	ip_pool_insert(ipo, &a, &b, 1, ifs);

	a.adf_addr.in4.s_addr = 0x0a000000;
	b.adf_addr.in4.s_addr = 0xff000000;
	ip_pool_insert(ipo, &a, &b, 0, ifs);
	ip_pool_insert(ipo, &a, &b, 0, ifs);

	a.adf_addr.in4.s_addr = 0x0a010100;
	b.adf_addr.in4.s_addr = 0xffffff00;
	ip_pool_insert(ipo, &a, &b, 1, ifs);
	ip_pool_insert(ipo, &a, &b, 1, ifs);

	a.adf_addr.in4.s_addr = 0x0a010200;
	b.adf_addr.in4.s_addr = 0xffffff00;
	ip_pool_insert(ipo, &a, &b, 0, ifs);
	ip_pool_insert(ipo, &a, &b, 0, ifs);

	a.adf_addr.in4.s_addr = 0x0a010000;
	b.adf_addr.in4.s_addr = 0xffff0000;
	ip_pool_insert(ipo, &a, &b, 1, ifs);
	ip_pool_insert(ipo, &a, &b, 1, ifs);

	a.adf_addr.in4.s_addr = 0x0a01020f;
	b.adf_addr.in4.s_addr = 0xffffffff;
	ip_pool_insert(ipo, &a, &b, 1, ifs);
	ip_pool_insert(ipo, &a, &b, 1, ifs);
#ifdef	DEBUG_POOL
treeprint(ipo);
#endif
	fin.fin_plen = 20;
	ip.in4.s_addr = 0x0a00aabb;
	printf("search(%#x) = %d (0)\n", ip.in4.s_addr,
		ip_pool_search(ipo, 4, &ip, &fin, ifs));

	ip.in4.s_addr = 0x0a000001;
	printf("search(%#x) = %d (0)\n", ip.in4.s_addr,
		ip_pool_search(ipo, 4, &ip, &fin, ifs));

	ip.in4.s_addr = 0x0a000101;
	printf("search(%#x) = %d (0)\n", ip.in4.s_addr,
		ip_pool_search(ipo, 4, &ip, &fin, ifs));

	ip.in4.s_addr = 0x0a010001;
	printf("search(%#x) = %d (1)\n", ip.in4.s_addr,
		ip_pool_search(ipo, 4, &ip, &fin, ifs));

	ip.in4.s_addr = 0x0a010101;
	printf("search(%#x) = %d (1)\n", ip.in4.s_addr,
		ip_pool_search(ipo, 4, &ip, &fin, ifs));

	ip.in4.s_addr = 0x0a010201;
	printf("search(%#x) = %d (0)\n", ip.in4.s_addr,
		ip_pool_search(ipo, 4, &ip, &fin, ifs));

	ip.in4.s_addr = 0x0a010203;
	printf("search(%#x) = %d (1)\n", ip.in4.s_addr,
		ip_pool_search(ipo, 4, &ip, &fin, ifs));

	ip.in4.s_addr = 0x0a01020f;
	printf("search(%#x) = %d (1)\n", ip.in4.s_addr,
		ip_pool_search(ipo, 4, &ip, &fin, ifs));

	ip.in4.s_addr = 0x0b00aabb;
	printf("search(%#x) = %d (-1)\n", ip.in4.s_addr,
		ip_pool_search(ipo, 4, &ip, &fin, ifs));

#ifdef	DEBUG_POOL
treeprint(ipo);
#endif

	ip_pool_fini(ifs);

	return 0;
}


void
treeprint(ipo)
ip_pool_t *ipo;
{
	ip_pool_node_t *c;

	for (c = ipo->ipo_list; c != NULL; c = c->ipn_next)
		printf("Node %p(%s) (%#x/%#x) = %d hits %lu\n",
			c, c->ipn_name, c->ipn_addr.adf_addr.in4.s_addr,
			c->ipn_mask.adf_addr.in4.s_addr,
			c->ipn_info, c->ipn_hits);
}
#endif /* TEST_POOL */


/* ------------------------------------------------------------------------ */
/* Function:    ip_pool_init                                                */
/* Returns:     int     - 0 = success, else error                           */
/*                                                                          */
/* Initialise the routing table data structures where required.             */
/* ------------------------------------------------------------------------ */
int ip_pool_init(ifs)
ipf_stack_t *ifs;
{

	bzero(&ifs->ifs_ipoolstat, sizeof (ip_pool_stat_t));

#if !defined(_KERNEL) || ((BSD < 199306) && (SOLARIS2 < 10))
	rn_init();
#endif
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ip_pool_fini                                                */
/* Returns:     int     - 0 = success, else error                           */
/* Locks:       WRITE(ipf_global)                                           */
/*                                                                          */
/* Clean up all the pool data structures allocated and call the cleanup     */
/* function for the radix tree that supports the pools. ip_pool_destroy() is*/
/* used to delete the pools one by one to ensure they're properly freed up. */
/* ------------------------------------------------------------------------ */
void ip_pool_fini(ifs)
ipf_stack_t *ifs;
{
	ip_pool_t *p, *q;
	iplookupop_t op;
	int i;

	ASSERT(rw_read_locked(&ifs->ifs_ipf_global.ipf_lk) == 0);

	for (i = 0; i <= IPL_LOGMAX; i++) {
		for (q = ifs->ifs_ip_pool_list[i]; (p = q) != NULL; ) {
			op.iplo_unit = i;
			(void)strncpy(op.iplo_name, p->ipo_name,
				sizeof(op.iplo_name));
			q = p->ipo_next;
			(void) ip_pool_destroy(&op, ifs);
		}
	}

#if !defined(_KERNEL) || ((BSD < 199306) && (SOLARIS2 < 10))
	rn_fini();
#endif
}


/* ------------------------------------------------------------------------ */
/* Function:    ip_pool_statistics                                          */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  op(I)   - pointer to lookup operation arguments             */
/*                                                                          */
/* Copy the current statistics out into user space, collecting pool list    */
/* pointers as appropriate for later use.                                   */
/* ------------------------------------------------------------------------ */
int ip_pool_statistics(op, ifs)
iplookupop_t *op;
ipf_stack_t *ifs;
{
	ip_pool_stat_t stats;
	int unit, i, err = 0;

	if (op->iplo_size != sizeof(ip_pool_stat_t))
		return EINVAL;

	bcopy((char *)&ifs->ifs_ipoolstat, (char *)&stats, sizeof(stats));
	unit = op->iplo_unit;
	if (unit == IPL_LOGALL) {
		for (i = 0; i < IPL_LOGSIZE; i++)
			stats.ipls_list[i] = ifs->ifs_ip_pool_list[i];
	} else if (unit >= 0 && unit < IPL_LOGSIZE) {
		if (op->iplo_name[0] != '\0')
			stats.ipls_list[unit] = ip_pool_find(unit,
							     op->iplo_name, ifs);
		else
			stats.ipls_list[unit] = ifs->ifs_ip_pool_list[unit];
	} else
		err = EINVAL;
	if (err == 0)
		err = COPYOUT(&stats, op->iplo_struct, sizeof(stats));
	return err;
}



/* ------------------------------------------------------------------------ */
/* Function:    ip_pool_find                                                */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  ipo(I)  - pointer to the pool getting the new node.         */
/*                                                                          */
/* Find a matching pool inside the collection of pools for a particular     */
/* device, indicated by the unit number.                                    */
/* ------------------------------------------------------------------------ */
void *ip_pool_find(unit, name, ifs)
int unit;
char *name;
ipf_stack_t *ifs;
{
	ip_pool_t *p;

	for (p = ifs->ifs_ip_pool_list[unit]; p != NULL; p = p->ipo_next)
		if (strncmp(p->ipo_name, name, sizeof(p->ipo_name)) == 0)
			break;
	return p;
}


/* ------------------------------------------------------------------------ */
/* Function:    ip_pool_findeq                                              */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  ipo(I)  - pointer to the pool getting the new node.         */
/*              addr(I) - pointer to address information to delete          */
/*              mask(I) -                                                   */
/*                                                                          */
/* Searches for an exact match of an entry in the pool.                     */
/* ------------------------------------------------------------------------ */
ip_pool_node_t *ip_pool_findeq(ipo, addr, mask)
ip_pool_t *ipo;
addrfamily_t *addr, *mask;
{
	struct radix_node *n;
	SPL_INT(s);

	SPL_NET(s);
	n = ipo->ipo_head->rnh_lookup(addr, mask, ipo->ipo_head);
	SPL_X(s);
	return (ip_pool_node_t *)n;
}


/* ------------------------------------------------------------------------ */
/* Function:    ip_pool_search                                              */
/* Returns:     int     - 0 == +ve match, -1 == error, 1 == -ve/no match    */
/* Parameters:  tptr(I)    - pointer to the pool to search                  */
/*              version(I) - IP protocol version (4 or 6)                   */
/*              dptr(I)    - pointer to address information                 */
/*		fin	   - pointer to packet information		    */
/*		ifs	   - ipf stack instance				    */
/*                                                                          */
/* Search the pool for a given address and return a search result.          */
/* ------------------------------------------------------------------------ */
int ip_pool_search(tptr, version, dptr, fin, ifs)
void *tptr;
int version;
void *dptr;
fr_info_t *fin;
ipf_stack_t *ifs;
{
	struct radix_node *rn;
	ip_pool_node_t *m;
	i6addr_t *addr;
	addrfamily_t v;
	ip_pool_t *ipo;
	int rv;

	ipo = tptr;
	if (ipo == NULL)
		return -1;

	rv = 1;
	m = NULL;
	addr = (i6addr_t *)dptr;
	bzero(&v, sizeof(v));
	v.adf_len = offsetof(addrfamily_t, adf_addr);

	if (version == 4) {
		v.adf_len += sizeof(addr->in4);
		v.adf_addr.in4 = addr->in4;
#ifdef USE_INET6
	} else if (version == 6) {
		v.adf_len += sizeof(addr->in6);
		v.adf_addr.in6 = addr->in6;
#endif
	} else
		return -1;

	READ_ENTER(&ifs->ifs_ip_poolrw);

	rn = ipo->ipo_head->rnh_matchaddr(&v, ipo->ipo_head);

	if ((rn != NULL) && ((rn->rn_flags & RNF_ROOT) == 0)) {
		m = (ip_pool_node_t *)rn;
		ipo->ipo_hits++;
		m->ipn_hits++;
		m->ipn_bytes += fin->fin_plen;
		rv = m->ipn_info;
	}
	RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
	return rv;
}


/* ------------------------------------------------------------------------ */
/* Function:    ip_pool_insert                                              */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  ipo(I)  - pointer to the pool getting the new node.         */
/*              addr(I) - IPv4/6 address being added as a node              */
/*              mask(I) - IPv4/6 netmask to with the node being added       */
/*              info(I) - extra information to store in this node.          */
/* Locks:       WRITE(ip_poolrw)                                            */
/*                                                                          */
/* Add another node to the pool given by ipo.  The three parameters passed  */
/* in (addr, mask, info) shold all be stored in the node.                   */
/* ------------------------------------------------------------------------ */
int ip_pool_insert(ipo, addr, mask, info, ifs)
ip_pool_t *ipo;
addrfamily_t *addr, *mask;
int info;
ipf_stack_t *ifs;
{
	struct radix_node *rn;
	ip_pool_node_t *x;

	ASSERT(rw_read_locked(&ifs->ifs_ip_poolrw.ipf_lk) == 0);

	KMALLOC(x, ip_pool_node_t *);
	if (x == NULL) {
		return ENOMEM;
	}

	bzero(x, sizeof(*x));

	x->ipn_info = info;
	(void)strncpy(x->ipn_name, ipo->ipo_name, sizeof(x->ipn_name));

	bcopy(addr, &x->ipn_addr, sizeof(*addr));
	x->ipn_addr.adf_len = sizeof(x->ipn_addr);
	bcopy(mask, &x->ipn_mask, sizeof(*mask));
	x->ipn_mask.adf_len = sizeof(x->ipn_mask);

	rn = ipo->ipo_head->rnh_addaddr(&x->ipn_addr, &x->ipn_mask,
					ipo->ipo_head, x->ipn_nodes);
#ifdef	DEBUG_POOL
	printf("Added %p at %p\n", x, rn);
#endif

	if (rn == NULL) {
		KFREE(x);
		return ENOMEM;
	}

	x->ipn_ref = 1;
	x->ipn_next = ipo->ipo_list;
	x->ipn_pnext = &ipo->ipo_list;
	if (ipo->ipo_list != NULL)
		ipo->ipo_list->ipn_pnext = &x->ipn_next;
	ipo->ipo_list = x;

	ifs->ifs_ipoolstat.ipls_nodes++;

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ip_pool_create                                              */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  op(I) - pointer to iplookup struct with call details        */
/* Locks:       WRITE(ip_poolrw)                                            */
/*                                                                          */
/* Creates a new group according to the paramters passed in via the         */
/* iplookupop structure.  Does not check to see if the group already exists */
/* when being inserted - assume this has already been done.  If the pool is */
/* marked as being anonymous, give it a new, unique, identifier.  Call any  */
/* other functions required to initialise the structure.                    */
/* ------------------------------------------------------------------------ */
int ip_pool_create(op, ifs)
iplookupop_t *op;
ipf_stack_t *ifs;
{
	char name[FR_GROUPLEN];
	int poolnum, unit;
	ip_pool_t *h;

	ASSERT(rw_read_locked(&ifs->ifs_ip_poolrw.ipf_lk) == 0);

	KMALLOC(h, ip_pool_t *);
	if (h == NULL)
		return ENOMEM;
	bzero(h, sizeof(*h));

	if (rn_inithead((void **)&h->ipo_head,
			offsetof(addrfamily_t, adf_addr) << 3) == 0) {
		KFREE(h);
		return ENOMEM;
	}

	unit = op->iplo_unit;

	if ((op->iplo_arg & IPOOL_ANON) != 0) {
		ip_pool_t *p;

		poolnum = IPOOL_ANON;

#if defined(SNPRINTF) && defined(_KERNEL)
		(void)SNPRINTF(name, sizeof(name), "%x", poolnum);
#else
		(void)sprintf(name, "%x", poolnum);
#endif

		for (p = ifs->ifs_ip_pool_list[unit]; p != NULL; ) {
			if (strncmp(name, p->ipo_name,
				    sizeof(p->ipo_name)) == 0) {
				poolnum++;
#if defined(SNPRINTF) && defined(_KERNEL)
				(void)SNPRINTF(name, sizeof(name), "%x", poolnum);
#else
				(void)sprintf(name, "%x", poolnum);
#endif
				p = ifs->ifs_ip_pool_list[unit];
			} else
				p = p->ipo_next;
		}

		(void)strncpy(h->ipo_name, name, sizeof(h->ipo_name));
	} else {
		(void) strncpy(h->ipo_name, op->iplo_name, sizeof(h->ipo_name));
	}

	h->ipo_ref = 1;
	h->ipo_list = NULL;
	h->ipo_unit = unit;
	h->ipo_next = ifs->ifs_ip_pool_list[unit];
	if (ifs->ifs_ip_pool_list[unit] != NULL)
		ifs->ifs_ip_pool_list[unit]->ipo_pnext = &h->ipo_next;
	h->ipo_pnext = &ifs->ifs_ip_pool_list[unit];
	ifs->ifs_ip_pool_list[unit] = h;

	ifs->ifs_ipoolstat.ipls_pools++;

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ip_pool_remove                                              */
/* Returns:     int    - 0 = success, else error                            */
/* Parameters:  ipo(I) - pointer to the pool to remove the node from.       */
/*              ipe(I) - address being deleted as a node                    */
/* Locks:       WRITE(ip_poolrw)                                            */
/*                                                                          */
/* Add another node to the pool given by ipo.  The three parameters passed  */
/* in (addr, mask, info) shold all be stored in the node.                   */
/* ------------------------------------------------------------------------ */
int ip_pool_remove(ipo, ipe, ifs)
ip_pool_t *ipo;
ip_pool_node_t *ipe;
ipf_stack_t *ifs;
{
	ip_pool_node_t **ipp, *n;

	ASSERT(rw_read_locked(&ifs->ifs_ip_poolrw.ipf_lk) == 0);

	for (ipp = &ipo->ipo_list; (n = *ipp) != NULL; ipp = &n->ipn_next) {
		if (ipe == n) {
			*n->ipn_pnext = n->ipn_next;
			if (n->ipn_next)
				n->ipn_next->ipn_pnext = n->ipn_pnext;
			break;
		}
	}

	if (n == NULL)
		return ENOENT;

	ipo->ipo_head->rnh_deladdr(&n->ipn_addr, &n->ipn_mask,
				   ipo->ipo_head);
	KFREE(n);

	ifs->ifs_ipoolstat.ipls_nodes--;	

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ip_pool_destroy                                             */
/* Returns:     int    - 0 = success, else error                            */
/* Parameters:  op(I)  -  information about the pool to remove              */
/* Locks:       WRITE(ip_poolrw) or WRITE(ipf_global)                       */
/*                                                                          */
/* Search for a pool using paramters passed in and if it's not otherwise    */
/* busy, free it.                                                           */
/*                                                                          */
/* NOTE: Because this function is called out of ipldetach() where ip_poolrw */
/* may not be initialised, we can't use an ASSERT to enforce the locking    */
/* assertion that one of the two (ip_poolrw,ipf_global) is held.            */
/* ------------------------------------------------------------------------ */
int ip_pool_destroy(op, ifs)
iplookupop_t *op;
ipf_stack_t *ifs;
{
	ip_pool_t *ipo;

	ipo = ip_pool_find(op->iplo_unit, op->iplo_name, ifs);
	if (ipo == NULL)
		return ESRCH;

	if (ipo->ipo_ref != 1)
		return EBUSY;

	ip_pool_free(ipo, ifs);
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ip_pool_flush                                               */
/* Returns:     int    - number of pools deleted                            */
/* Parameters:  fp(I)  - which pool(s) to flush                             */
/* Locks:       WRITE(ip_poolrw) or WRITE(ipf_global)                       */
/*                                                                          */
/* Free all pools associated with the device that matches the unit number   */
/* passed in with operation.                                                */
/*                                                                          */
/* NOTE: Because this function is called out of ipldetach() where ip_poolrw */
/* may not be initialised, we can't use an ASSERT to enforce the locking    */
/* assertion that one of the two (ip_poolrw,ipf_global) is held.            */
/* ------------------------------------------------------------------------ */
int ip_pool_flush(fp, ifs)
iplookupflush_t *fp;
ipf_stack_t *ifs;
{
	int i, num = 0, unit, err;
	ip_pool_t *p, *q;
	iplookupop_t op;

	unit = fp->iplf_unit;

	for (i = 0; i <= IPL_LOGMAX; i++) {
		if (unit != IPLT_ALL && i != unit)
			continue;
		for (q = ifs->ifs_ip_pool_list[i]; (p = q) != NULL; ) {
			op.iplo_unit = i;
			(void)strncpy(op.iplo_name, p->ipo_name,
				sizeof(op.iplo_name));
			q = p->ipo_next;
			err = ip_pool_destroy(&op, ifs);
			if (err == 0)
				num++;
			else
				break;
		}
	}
	return num;
}


/* ------------------------------------------------------------------------ */
/* Function:    ip_pool_free                                                */
/* Returns:     void                                                        */
/* Parameters:  ipo(I) -  pointer to pool structure                         */
/* Locks:       WRITE(ip_poolrw) or WRITE(ipf_global)                       */
/*                                                                          */
/* Deletes the pool strucutre passed in from the list of pools and deletes  */
/* all of the address information stored in it, including any tree data     */
/* structures also allocated.                                               */
/*                                                                          */
/* NOTE: Because this function is called out of ipldetach() where ip_poolrw */
/* may not be initialised, we can't use an ASSERT to enforce the locking    */
/* assertion that one of the two (ip_poolrw,ipf_global) is held.            */
/* ------------------------------------------------------------------------ */
void ip_pool_free(ipo, ifs)
ip_pool_t *ipo;
ipf_stack_t *ifs;
{
	ip_pool_node_t *n;

	while ((n = ipo->ipo_list) != NULL) {
		ipo->ipo_head->rnh_deladdr(&n->ipn_addr, &n->ipn_mask,
					   ipo->ipo_head);

		*n->ipn_pnext = n->ipn_next;
		if (n->ipn_next)
			n->ipn_next->ipn_pnext = n->ipn_pnext;

		KFREE(n);

		ifs->ifs_ipoolstat.ipls_nodes--;
	}

	ipo->ipo_list = NULL;
	if (ipo->ipo_next != NULL)
		ipo->ipo_next->ipo_pnext = ipo->ipo_pnext;
	*ipo->ipo_pnext = ipo->ipo_next;
	rn_freehead(ipo->ipo_head);
	KFREE(ipo);

	ifs->ifs_ipoolstat.ipls_pools--;
}


/* ------------------------------------------------------------------------ */
/* Function:    ip_pool_deref                                               */
/* Returns:     void                                                        */
/* Parameters:  ipo(I) -  pointer to pool structure                         */
/* Locks:       WRITE(ip_poolrw)                                            */
/*                                                                          */
/* Drop the number of known references to this pool structure by one and if */
/* we arrive at zero known references, free it.                             */
/* ------------------------------------------------------------------------ */
void ip_pool_deref(ipo, ifs)
ip_pool_t *ipo;
ipf_stack_t *ifs;
{

	ASSERT(rw_read_locked(&ifs->ifs_ip_poolrw.ipf_lk) == 0);

	ipo->ipo_ref--;
	if (ipo->ipo_ref == 0)
		ip_pool_free(ipo, ifs);
}



void ip_pool_node_deref(ipn, ifs)
ip_pool_node_t *ipn;
ipf_stack_t *ifs;
{

	ipn->ipn_ref--;

	if (ipn->ipn_ref == 0) {
		KFREE(ipn);
		ifs->ifs_ipoolstat.ipls_nodes--;
	}
}


int ip_pool_getnext(token, ilp, ifs)
ipftoken_t *token;
ipflookupiter_t *ilp;
ipf_stack_t *ifs;
{
	ip_pool_node_t *node, zn, *nextnode;
	ip_pool_t *ipo, zp, *nextipo;
	int err;

	err = 0;
	node = NULL;
	nextnode = NULL;
	ipo = NULL;
	nextipo = NULL;

	READ_ENTER(&ifs->ifs_ip_poolrw);

	/*
	 * Get "previous" entry from the token and find the next entry.
	 *
	 * If we found an entry, add a reference to it and update the token.
	 * Otherwise, zero out data to be returned and NULL out token.
	 */
	switch (ilp->ili_otype)
	{
	case IPFLOOKUPITER_LIST :
		ipo = token->ipt_data;
		if (ipo == NULL) {
			nextipo = ifs->ifs_ip_pool_list[(int)ilp->ili_unit];
		} else {
			nextipo = ipo->ipo_next;
		}
		if (nextipo != NULL) {
			ATOMIC_INC(nextipo->ipo_ref);
			token->ipt_data = nextipo;
		} else {
			bzero((char *)&zp, sizeof(zp));
			nextipo = &zp;
			token->ipt_data = NULL;
		}
		break;

	case IPFLOOKUPITER_NODE :
		node = token->ipt_data;
		if (node == NULL) {
			ipo = ip_pool_find(ilp->ili_unit, ilp->ili_name, ifs);
			if (ipo == NULL)
				err = ESRCH;
			else {
				nextnode = ipo->ipo_list;
				ipo = NULL;
			}
		} else {
			nextnode = node->ipn_next;
		}
		if (nextnode != NULL) {
			ATOMIC_INC(nextnode->ipn_ref);
			token->ipt_data = nextnode;
		} else {
			bzero((char *)&zn, sizeof(zn));
			nextnode = &zn;
			token->ipt_data = NULL;
		}
		break;

	default :
		err = EINVAL;
		break;
	}

	/*
	 * Now that we have ref, it's save to give up lock.
	 */
	RWLOCK_EXIT(&ifs->ifs_ip_poolrw);

	if (err != 0)
		return err;

	/*
	 * Copy out the data and update the references and token as needed.
	 */
	switch (ilp->ili_otype)
	{
	case IPFLOOKUPITER_LIST :
		err = COPYOUT(nextipo, ilp->ili_data, sizeof(*nextipo));
		if (err != 0)
			err = EFAULT;
		if (token->ipt_data == NULL) {
			ipf_freetoken(token, ifs);
		} else {
			if (ipo != NULL) {
				WRITE_ENTER(&ifs->ifs_ip_poolrw);
				ip_pool_deref(ipo, ifs);
				RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
			}
			if (nextipo->ipo_next == NULL) 
				ipf_freetoken(token, ifs);
		}
		break;

	case IPFLOOKUPITER_NODE :
		err = COPYOUT(nextnode, ilp->ili_data, sizeof(*nextnode));
		if (err != 0)
			err = EFAULT;
		if (token->ipt_data == NULL) {
			ipf_freetoken(token, ifs);
		} else {
			if (node != NULL) {
				WRITE_ENTER(&ifs->ifs_ip_poolrw);
				ip_pool_node_deref(node, ifs);
				RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
			}
			if (nextnode->ipn_next == NULL) 
				ipf_freetoken(token, ifs);
		}
		break;
	}

	return err;
}


void ip_pool_iterderef(otype, unit, data, ifs)
u_int otype;
int unit;
void *data;
ipf_stack_t *ifs;
{

	if (data == NULL)
		return;

	if (unit < 0 || unit > IPL_LOGMAX)
		return;

	switch (otype)
	{
	case IPFLOOKUPITER_LIST :
		WRITE_ENTER(&ifs->ifs_ip_poolrw);
		ip_pool_deref((ip_pool_t *)data, ifs);
		RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
		break;

	case IPFLOOKUPITER_NODE :
		WRITE_ENTER(&ifs->ifs_ip_poolrw);
		ip_pool_node_deref((ip_pool_node_t *)data, ifs);
		RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
		break;
	default :
		break;
	}
}


# if defined(_KERNEL) && ((BSD >= 198911) && !defined(__osf__) && \
      !defined(__hpux) && !defined(__sgi))
static int
rn_freenode(struct radix_node *n, void *p, ipf_stack_t *ifs)
{
	struct radix_node_head *rnh = p;
	struct radix_node *d;

	d = rnh->rnh_deladdr(n->rn_key, NULL, rnh);
	if (d != NULL) {
		FreeS(d, ifs->ifs_max_keylen + 2 * sizeof (*d));
	}
	return 0;
}


void
rn_freehead(rnh)
      struct radix_node_head *rnh;
{

	(*rnh->rnh_walktree)(rnh, rn_freenode, rnh);

	rnh->rnh_addaddr = NULL;
	rnh->rnh_deladdr = NULL;
	rnh->rnh_matchaddr = NULL;
	rnh->rnh_lookup = NULL;
	rnh->rnh_walktree = NULL;

	Free(rnh);
}
# endif

#endif /* IPFILTER_LOOKUP */
