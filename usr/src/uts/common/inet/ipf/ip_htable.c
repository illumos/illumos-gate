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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/file.h>
#if !defined(_KERNEL)
# include <stdlib.h>
# include <string.h>
# define _KERNEL
# ifdef __OpenBSD__
struct file;
# endif
# include <sys/uio.h>
# undef _KERNEL
#endif
#include <sys/socket.h>
#if defined(__FreeBSD_version) && (__FreeBSD_version >= 300000)
# include <sys/malloc.h>
#endif
#if defined(__FreeBSD__)
#  include <sys/cdefs.h>
#  include <sys/proc.h>
#endif
#if !defined(__svr4__) && !defined(__SVR4) && !defined(__hpux) && \
    !defined(linux)
# include <sys/mbuf.h>
#endif
#if defined(_KERNEL)
# include <sys/systm.h>
#else
# include <stdio.h>
#endif
#include <netinet/in.h>
#include <net/if.h>

#include "netinet/ip_compat.h"
#include "netinet/ip_fil.h"
#include "netinet/ip_lookup.h"
#include "netinet/ip_htable.h"
#include "netinet/ipf_stack.h"
/* END OF INCLUDES */

#if !defined(lint)
static const char rcsid[] = "@(#)$Id: ip_htable.c,v 2.34.2.3 2005/05/14 05:11:38 darrenr Exp $";
#endif

#ifdef	IPFILTER_LOOKUP
static iphtent_t *fr_iphmfind __P((iphtable_t *, struct in_addr *));
#ifdef USE_INET6
static iphtent_t *fr_iphmfind6 __P((iphtable_t *, struct in6_addr *));
static uint32_t sum4(uint32_t *);
static void left_shift_ipv6 __P((char *));
#endif

void fr_htable_unload(ifs)
ipf_stack_t *ifs;
{
	iplookupflush_t fop;

	fop.iplf_unit = IPL_LOGALL;
	(void)fr_flushhtable(&fop, ifs);
}


int fr_gethtablestat(op, ifs)
iplookupop_t *op;
ipf_stack_t *ifs;
{
	iphtstat_t stats;

	if (op->iplo_size != sizeof(stats))
		return EINVAL;

	stats.iphs_tables = ifs->ifs_ipf_htables[op->iplo_unit];
	stats.iphs_numtables = ifs->ifs_ipf_nhtables[op->iplo_unit];
	stats.iphs_numnodes = ifs->ifs_ipf_nhtnodes[op->iplo_unit];
	stats.iphs_nomem = ifs->ifs_ipht_nomem[op->iplo_unit];

	return COPYOUT(&stats, op->iplo_struct, sizeof(stats));

}


/*
 * Create a new hash table using the template passed.
 */
int fr_newhtable(op, ifs)
iplookupop_t *op;
ipf_stack_t *ifs;
{
	iphtable_t *iph, *oiph;
	char name[FR_GROUPLEN];
	int err, i, unit;

	KMALLOC(iph, iphtable_t *);
	if (iph == NULL) {
		ifs->ifs_ipht_nomem[op->iplo_unit]++;
		return ENOMEM;
	}

	err = COPYIN(op->iplo_struct, iph, sizeof(*iph));
	if (err != 0) {
		KFREE(iph);
		return EFAULT;
	}

	unit = op->iplo_unit;
	if (iph->iph_unit != unit) {
		KFREE(iph);
		return EINVAL;
	}

	if ((op->iplo_arg & IPHASH_ANON) == 0) {
		if (fr_findhtable(op->iplo_unit, op->iplo_name, ifs) != NULL) {
			KFREE(iph);
			return EEXIST;
		}
	} else {
		i = IPHASH_ANON;
		do {
			i++;
#if defined(SNPRINTF) && defined(_KERNEL)
			(void)SNPRINTF(name, sizeof(name), "%u", i);
#else
			(void)sprintf(name, "%u", i);
#endif
			for (oiph = ifs->ifs_ipf_htables[unit]; oiph != NULL;
			     oiph = oiph->iph_next)
				if (strncmp(oiph->iph_name, name,
					    sizeof(oiph->iph_name)) == 0)
					break;
		} while (oiph != NULL);
		(void)strncpy(iph->iph_name, name, sizeof(iph->iph_name));
		err = COPYOUT(iph, op->iplo_struct, sizeof(*iph));
		if (err != 0) {
			KFREE(iph);
			return EFAULT;
		}
		iph->iph_type |= IPHASH_ANON;
	}

	KMALLOCS(iph->iph_table, iphtent_t **,
		 iph->iph_size * sizeof(*iph->iph_table));
	if (iph->iph_table == NULL) {
		KFREE(iph);
		ifs->ifs_ipht_nomem[unit]++;
		return ENOMEM;
	}

	bzero((char *)iph->iph_table, iph->iph_size * sizeof(*iph->iph_table));
	iph->iph_masks[0] = 0;
	iph->iph_masks[1] = 0;
	iph->iph_masks[2] = 0;
	iph->iph_masks[3] = 0;
	iph->iph_list = NULL;

	iph->iph_ref = 1;
	iph->iph_next = ifs->ifs_ipf_htables[unit];
	iph->iph_pnext = &ifs->ifs_ipf_htables[unit];
	if (ifs->ifs_ipf_htables[unit] != NULL)
		ifs->ifs_ipf_htables[unit]->iph_pnext = &iph->iph_next;
	ifs->ifs_ipf_htables[unit] = iph;

	ifs->ifs_ipf_nhtables[unit]++;

	return 0;
}


/*
 */
int fr_removehtable(op, ifs)
iplookupop_t *op;
ipf_stack_t *ifs;
{
	iphtable_t *iph;


	iph = fr_findhtable(op->iplo_unit, op->iplo_name, ifs);
	if (iph == NULL)
		return ESRCH;

	if (iph->iph_unit != op->iplo_unit) {
		return EINVAL;
	}
	
	if (iph->iph_ref != 1) {
		return EBUSY;
	}

	fr_delhtable(iph, ifs);

	return 0;
}


void fr_delhtable(iph, ifs)
iphtable_t *iph;
ipf_stack_t *ifs;
{
	iphtent_t *ipe;
	int i;

	for (i = 0; i < iph->iph_size; i++)
		while ((ipe = iph->iph_table[i]) != NULL)
			if (fr_delhtent(iph, ipe, ifs) != 0)
				return;

	*iph->iph_pnext = iph->iph_next;
	if (iph->iph_next != NULL)
		iph->iph_next->iph_pnext = iph->iph_pnext;

	ifs->ifs_ipf_nhtables[iph->iph_unit]--;

	if (iph->iph_ref == 1) {
		KFREES(iph->iph_table, iph->iph_size * sizeof(*iph->iph_table));
		KFREE(iph);
	}
}


void fr_derefhtable(iph, ifs)
iphtable_t *iph;
ipf_stack_t *ifs;
{
	iph->iph_ref--;
	if (iph->iph_ref == 0)
		fr_delhtable(iph, ifs);
}


void fr_derefhtent(ipe)
iphtent_t *ipe;
{
	ipe->ipe_ref--;
	if (ipe->ipe_ref == 0) {
		KFREE(ipe);
	}
}


iphtable_t *fr_findhtable(unit, name, ifs)
int unit;
char *name;
ipf_stack_t *ifs;
{
	iphtable_t *iph;

	for (iph = ifs->ifs_ipf_htables[unit]; iph != NULL; iph = iph->iph_next)
		if (strncmp(iph->iph_name, name, sizeof(iph->iph_name)) == 0)
			break;
	return iph;
}


size_t fr_flushhtable(op, ifs)
iplookupflush_t *op;
ipf_stack_t *ifs;
{
	iphtable_t *iph;
	size_t freed;
	int i;

	freed = 0;

	for (i = 0; i <= IPL_LOGMAX; i++) {
		if (op->iplf_unit == i || op->iplf_unit == IPL_LOGALL) {
			while ((iph = ifs->ifs_ipf_htables[i]) != NULL) {
				fr_delhtable(iph, ifs);
				freed++;
			}
		}
	}

	return freed;
}


/*
 * Add an entry to a hash table.
 */
int fr_addhtent(iph, ipeo, ifs)
iphtable_t *iph;
iphtent_t *ipeo;
ipf_stack_t *ifs;
{
	iphtent_t *ipe;
	u_int hv;
	int bits;

	KMALLOC(ipe, iphtent_t *);
	if (ipe == NULL)
		return -1;

	bcopy((char *)ipeo, (char *)ipe, sizeof(*ipe));
#ifdef USE_INET6
	if (ipe->ipe_family == AF_INET6) {
		bits = count6bits((u_32_t *)ipe->ipe_mask.in6_addr8);
		hv = IPE_HASH_FN(sum4((uint32_t *)ipe->ipe_addr.in6_addr8), 
				 sum4((uint32_t *)ipe->ipe_mask.in6_addr8),
				 iph->iph_size);
	} else
#endif
	if (ipe->ipe_family == AF_INET)
	{
		ipe->ipe_addr.in4_addr &= ipe->ipe_mask.in4_addr;
		ipe->ipe_addr.in4_addr = ntohl(ipe->ipe_addr.in4_addr);
		bits = count4bits(ipe->ipe_mask.in4_addr);
		ipe->ipe_mask.in4_addr = ntohl(ipe->ipe_mask.in4_addr);

		hv = IPE_HASH_FN(ipe->ipe_addr.in4_addr, ipe->ipe_mask.in4_addr,
				 iph->iph_size);
	} else
		return -1;

	ipe->ipe_ref = 1;
	ipe->ipe_next = iph->iph_table[hv];
	ipe->ipe_pnext = iph->iph_table + hv;

	if (iph->iph_table[hv] != NULL)
		iph->iph_table[hv]->ipe_pnext = &ipe->ipe_next;
	iph->iph_table[hv] = ipe;

	ipe->ipe_snext = iph->iph_list;
	ipe->ipe_psnext = &iph->iph_list;
	if (ipe->ipe_next != NULL)
		ipe->ipe_next->ipe_psnext = &ipe->ipe_snext;
	iph->iph_list = ipe;

#ifdef USE_INET6
	if (ipe->ipe_family == AF_INET6) {
		if ((bits >= 0) && (bits != 128))
			if (bits >= 96)
				iph->iph_masks[0] |= 1 << (bits - 96);
			else if (bits >= 64)
				iph->iph_masks[1] |= 1 << (bits - 64);
			else if (bits >= 32)
				iph->iph_masks[2] |= 1 << (bits - 32);
			else
				iph->iph_masks[3] |= 1 << bits;

	} else
#endif
	{
		if ((bits >= 0) && (bits != 32))
			iph->iph_masks[3] |= 1 << bits;
	}

	switch (iph->iph_type & ~IPHASH_ANON)
	{
	case IPHASH_GROUPMAP :
		ipe->ipe_ptr = fr_addgroup(ipe->ipe_group, NULL,
					   iph->iph_flags, IPL_LOGIPF,
					   ifs->ifs_fr_active, ifs);
		break;

	default :
		ipe->ipe_ptr = NULL;
		ipe->ipe_value = 0;
		break;
	}

	ifs->ifs_ipf_nhtnodes[iph->iph_unit]++;

	return 0;
}


/*
 * Delete an entry from a hash table.
 */
int fr_delhtent(iph, ipe, ifs)
iphtable_t *iph;
iphtent_t *ipe;
ipf_stack_t *ifs;
{
	if (ipe->ipe_ref != 1)
		return EBUSY;


	*ipe->ipe_pnext = ipe->ipe_next;
	if (ipe->ipe_next != NULL)
		ipe->ipe_next->ipe_pnext = ipe->ipe_pnext;

	switch (iph->iph_type & ~IPHASH_ANON)
	{
	case IPHASH_GROUPMAP :
		if (ipe->ipe_group != NULL)
			fr_delgroup(ipe->ipe_group, IPL_LOGIPF,
				    ifs->ifs_fr_active, ifs);
		break;

	default :
		ipe->ipe_ptr = NULL;
		ipe->ipe_value = 0;
		break;
	}

	KFREE(ipe);

	ifs->ifs_ipf_nhtnodes[iph->iph_unit]--;
	
	return 0;
}


void *fr_iphmfindgroup(tptr, version, aptr, ifs)
void *tptr;
int version;
void *aptr;
ipf_stack_t *ifs;
{
	i6addr_t *addr;
	iphtable_t *iph;
	iphtent_t *ipe;
	void *rval;

	if ((version != 4)
#ifdef USE_INET6
	    && (version != 6)
#endif
	    )
		return NULL;

	READ_ENTER(&ifs->ifs_ip_poolrw);
	iph = tptr;
	addr = aptr;

#ifdef USE_INET6
	if (version == 6)
		ipe = fr_iphmfind6(iph, &addr->in6);
	else
#endif
	if (version == 4)
		ipe = fr_iphmfind(iph, &addr->in4);
	else
		ipe = NULL;
	if (ipe != NULL)
		rval = ipe->ipe_ptr;
	else
		rval = NULL;
	RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
	return rval;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_iphmfindip                                               */
/* Returns:     int     - 0 == +ve match, -1 == error, 1 == -ve/no match    */
/* Parameters:  tptr(I)    - pointer to the pool to search                  */
/*              version(I) - IP protocol version (4 or 6)                   */
/*              aptr(I)    - pointer to address information                 */
/*		fin	   - pointer to packet information		    */
/*		ifs	   - ipf stack instance				    */
/*                                                                          */
/* Search the hash table for a given address and return a search result.    */
/* ------------------------------------------------------------------------ */
int fr_iphmfindip(tptr, version, aptr, fin, ifs)
void *tptr, *aptr;
int version;
fr_info_t *fin;
ipf_stack_t *ifs;
{
	i6addr_t *addr;
	iphtable_t *iph;
	iphtent_t *ipe;
	int rval;

	if ((version != 4)
#ifdef USE_INET6
	    && (version != 6)
#endif
	    )
		return -1;

	if (tptr == NULL || aptr == NULL)
		return -1;

	iph = tptr;
	addr = aptr;

	READ_ENTER(&ifs->ifs_ip_poolrw);
#ifdef USE_INET6
	if (version == 6)
		ipe = fr_iphmfind6(iph, &addr->in6);
	else
#endif
	if (version == 4)
		ipe = fr_iphmfind(iph, &addr->in4);
	else
		ipe = NULL;
	if (ipe != NULL) {
		ipe->ipe_hits++;
		ipe->ipe_bytes += fin->fin_plen;
		rval = 0;
	} else {
		rval = 1;
	}
	RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
	return rval;
}


/* Locks:  ip_poolrw */
static iphtent_t *fr_iphmfind(iph, addr)
iphtable_t *iph;
struct in_addr *addr;
{
	u_32_t hmsk, msk, ips;
	iphtent_t *ipe;
	u_int hv;

	hmsk = iph->iph_masks[3];
	msk = 0xffffffff;
maskloop:
	ips = ntohl(addr->s_addr) & msk;
	hv = IPE_HASH_FN(ips, msk, iph->iph_size);
	for (ipe = iph->iph_table[hv]; (ipe != NULL); ipe = ipe->ipe_next) {
		if (ipe->ipe_mask.in4_addr != msk ||
		    ipe->ipe_addr.in4_addr != ips) {
			continue;
		}
		break;
	}

	if ((ipe == NULL) && (hmsk != 0)) {
		while (hmsk != 0) {
			msk <<= 1;
			if (hmsk & 0x80000000)
				break;
			hmsk <<= 1;
		}
		if (hmsk != 0) {
			hmsk <<= 1;
			goto maskloop;
		}
	}
	return ipe;
}


#ifdef USE_INET6
/* Locks:  ip_poolrw */
static iphtent_t *fr_iphmfind6(iph, addr)
iphtable_t *iph;
struct in6_addr *addr;
{
	u_32_t hmsk[4], msk[4], ips[4], *and;
	iphtent_t *ipe;
	u_int hv;

	hmsk[0] = iph->iph_masks[0];
	hmsk[1] = iph->iph_masks[1];
	hmsk[2] = iph->iph_masks[2];
	hmsk[3] = iph->iph_masks[3];

	msk[0] = 0xffffffff;
	msk[1] = 0xffffffff;
	msk[2] = 0xffffffff;
	msk[3] = 0xffffffff;
maskloop:
	and = (u_32_t *)addr->s6_addr;
	ips[0] = *and & msk[0];
	ips[1] = *(and + 1) & msk[1];
	ips[2] = *(and + 2) & msk[2];
	ips[3] = *(and + 3) & msk[3];

	hv = IPE_HASH_FN(sum4((uint32_t *)addr), sum4((uint32_t *)msk),
			      iph->iph_size);
	for (ipe = iph->iph_table[hv]; (ipe != NULL); ipe = ipe->ipe_next) {
		if (bcmp((void *)&ipe->ipe_mask.in6, (void *)msk, 16) ||
		    bcmp((void *)&ipe->ipe_addr.in6, (void *)ips, 16))
			continue;
		break;
	}

	if ((ipe == NULL) && ((hmsk[0] != 0) ||
			      (hmsk[1] != 0) ||
			      (hmsk[2] != 0) ||
			      (hmsk[3] != 0) )) {
		while ((hmsk[0] != 0) && (hmsk[1] != 0) && 
		       (hmsk[2] != 0) && (hmsk[3] != 0)) {
			left_shift_ipv6((char *)msk);
			if (hmsk[0] & 0x80000000)
				break;
			left_shift_ipv6((char *)hmsk);
		}
		if ((hmsk[0] != 0) && (hmsk[1] != 0) && 
		    (hmsk[2] != 0) && (hmsk[3] != 0)) {
			left_shift_ipv6((char *)hmsk);
			goto maskloop;
		}
	}
	return ipe;
}


/*
 * sum4: ipv6 add -> 4 bytes values
 */
static uint32_t sum4(add)
uint32_t *add;
{
	return (*add + *(add + 1) + *(add + 2) + *(add + 3));
}

/*
 * left shift on 128 bits
 */
static void left_shift_ipv6(data)
char *data;
{
	u_32_t *sd;

	sd = (u_32_t *)data;
	sd[0] <<= 1;
	if (sd[1] >= 0x80000000)
		sd[0] += 1;

	sd[1] <<= 1;
	if (sd[2] >= 0x80000000)
		sd[1] += 1;

	sd[2] <<= 1;
	if (sd[3] >= 0x80000000)
		sd[2] += 1;

	sd[3] <<= 1;
}
#endif

int fr_htable_getnext(token, ilp, ifs)
ipftoken_t *token;
ipflookupiter_t *ilp;
ipf_stack_t *ifs;
{
	iphtent_t *node, zn, *nextnode;
	iphtable_t *iph, zp, *nextiph;
	int err;

	err = 0;
	iph = NULL;
	node = NULL;
	nextiph = NULL;
	nextnode = NULL;

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
		iph = token->ipt_data;
		if (iph == NULL) {
			nextiph = ifs->ifs_ipf_htables[(int)ilp->ili_unit];
		} else {
			nextiph = iph->iph_next;
		}
		if (nextiph != NULL) {
			ATOMIC_INC(nextiph->iph_ref);
			token->ipt_data = nextiph;
		} else {
			bzero((char *)&zp, sizeof(zp));
			nextiph = &zp;
			token->ipt_data = NULL;
		}
		break;

	case IPFLOOKUPITER_NODE :
		node = token->ipt_data;
		if (node == NULL) {
			iph = fr_findhtable(ilp->ili_unit, ilp->ili_name, ifs);
			if (iph == NULL)
				err = ESRCH;
			else {
				nextnode = iph->iph_list;
			}
		} else {
			nextnode = node->ipe_snext;
		}
		if (nextnode != NULL) {
			ATOMIC_INC(nextnode->ipe_ref);
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
	 * Copy out data and clean up references and token as needed.
	 */
	switch (ilp->ili_otype)
	{
	case IPFLOOKUPITER_LIST :
		err = COPYOUT(nextiph, ilp->ili_data, sizeof(*nextiph));
		if (err != 0)
			err = EFAULT;
		if (token->ipt_data == NULL) {
			ipf_freetoken(token, ifs);
		} else {
			if (iph != NULL) {
				WRITE_ENTER(&ifs->ifs_ip_poolrw);
				fr_derefhtable(iph, ifs);
				RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
			}
			if (nextiph->iph_next == NULL)
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
				fr_derefhtent(node);
				RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
			}
			if (nextnode->ipe_snext == NULL)
				ipf_freetoken(token, ifs);
		}
		break;
	}

	return err;
}


void fr_htable_iterderef(otype, unit, data, ifs)
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
		fr_derefhtable((iphtable_t *)data, ifs);
		RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
		break;

	case IPFLOOKUPITER_NODE :
		WRITE_ENTER(&ifs->ifs_ip_poolrw);
		fr_derefhtent((iphtent_t *)data);
		RWLOCK_EXIT(&ifs->ifs_ip_poolrw);
		break;
	default :
		break;
	}
}
#endif /* IPFILTER_LOOKUP */
