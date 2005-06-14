/*
 * Copyright (C) 1993-2001, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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
#if !defined(__svr4__) && !defined(__SVR4) && !defined(__hpux)
# include <sys/mbuf.h>
#endif
#if defined(_KERNEL)
# include <sys/systm.h>
#else
# include <stdio.h>
#endif
#include <netinet/in.h>
#include <net/if.h>

#if SOLARIS2 >= 10
#include "ip_compat.h"
#include "ip_fil.h"
#include "ip_lookup.h"
#include "ip_htable.h"
#else
#include "netinet/ip_compat.h"
#include "netinet/ip_fil.h"
#include "netinet/ip_lookup.h"
#include "netinet/ip_htable.h"
#endif

#if !defined(lint)
static const char rcsid[] = "@(#)$Id: ip_htable.c,v 2.24 2003/05/12 13:49:17 darrenr Exp $";
#endif

#ifdef	IPFILTER_LOOKUP
static iphtent_t *fr_iphmfind __P((iphtable_t *, struct in_addr *));

iphtable_t *ipf_htables[IPL_LOGSIZE] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };


void fr_htable_unload()
{
	iplookupflush_t fop;
	iphtable_t *iph;
	int unit;

	for (unit = 0; unit < IPL_LOGMAX; unit++) {
		fop.iplf_unit = unit;
		while ((iph = ipf_htables[unit]) != NULL) {
			(void)strncpy(fop.iplf_name, iph->iph_name,
				      sizeof(fop.iplf_name));
			(void)fr_flushhtable(&fop);
		}
	}
}


/*
 * Create a new hash table using the template passed.
 */
int fr_newhtable(op)
iplookupop_t *op;
{
	iphtable_t *iph, *oiph;
	char name[FR_GROUPLEN];
	int err, i, unit;

	KMALLOC(iph, iphtable_t *);
	if (iph == NULL)
		return ENOMEM; 

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
		if (fr_findhtable(op->iplo_unit, op->iplo_name) != NULL) {
			KFREE(iph);
			return EEXIST;
		}
	} else {
		i = IPHASH_ANON;
		do {
			i++;
			(void)sprintf(name, "%u", i);
			for (oiph = ipf_htables[unit]; oiph != NULL;
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
		return ENOMEM;
	}

	bzero((char *)iph->iph_table, iph->iph_size * sizeof(*iph->iph_table));
	iph->iph_masks = 0;

	iph->iph_next = ipf_htables[unit];
	iph->iph_pnext = &ipf_htables[unit];
	if (ipf_htables[unit] != NULL)
		ipf_htables[unit]->iph_pnext = &iph->iph_next;
	ipf_htables[unit] = iph;
	return 0;
}


/*
 */
int fr_removehtable(op)
iplookupop_t *op;
{
	iphtable_t *iph;


	iph = fr_findhtable(op->iplo_unit, op->iplo_name);
	if (iph == NULL)
		return ESRCH;

	if (iph->iph_unit != op->iplo_unit) {
		return EINVAL;
	}

	if (iph->iph_ref != 0) {
		return EBUSY;
	}

	fr_delhtable(iph);

	return 0;
}


void fr_delhtable(iph)
iphtable_t *iph;
{

	*iph->iph_pnext = iph->iph_next;
	if (iph->iph_next != NULL)
		iph->iph_next->iph_pnext = iph->iph_pnext;

	KFREES(iph->iph_table, iph->iph_size * sizeof(*iph->iph_table));
	KFREE(iph);
}


void fr_derefhtable(iph)
iphtable_t *iph;
{
	iph->iph_ref--;
	if (iph->iph_ref == 0)
		fr_delhtable(iph);
}


iphtable_t *fr_findhtable(unit, name)
int unit;
char *name;
{
	iphtable_t *iph;

	for (iph = ipf_htables[unit]; iph != NULL; iph = iph->iph_next)
		if (strncmp(iph->iph_name, name, sizeof(iph->iph_name)) == 0)
			break;
	return iph;
}


size_t fr_flushhtable(op)
iplookupflush_t *op;
{
	iphtable_t *iph;
	size_t i, freed;
	iphtent_t *ipe;

	iph = fr_findhtable(op->iplf_unit, op->iplf_name);
	if (iph == NULL) {
		return 0;
	}

	freed = 0;
	*iph->iph_pnext = iph->iph_next;
	if (iph->iph_next != NULL)
		iph->iph_next->iph_pnext = iph->iph_pnext;

	for (i = 0; i < iph->iph_size; i++)
		while ((ipe = iph->iph_table[i]) != NULL) {
			*ipe->ipe_pnext = ipe->ipe_next;
			if (ipe->ipe_next != NULL)
				ipe->ipe_next->ipe_pnext = ipe->ipe_pnext;

			switch (iph->iph_type & ~IPHASH_ANON)
			{
			case IPHASH_GROUPMAP :
				if (ipe->ipe_ptr != NULL)
					fr_delgroup(ipe->ipe_group, 
						    IPL_LOGIPF, fr_active);
				break;
			}
			/* ipe_ref */
			KFREE(ipe);
			freed++;
		}

	KFREES(iph->iph_table, iph->iph_size * sizeof(*iph->iph_table));
	KFREE(iph);

	return freed;
}


/*
 * Add an entry to a hash table.
 */
int fr_addhtent(iph, ipeo)
iphtable_t *iph;
iphtent_t *ipeo;
{
	iphtent_t *ipe;
	u_int hv;
	int bits;

	KMALLOC(ipe, iphtent_t *);
	if (ipe == NULL)
		return -1;

	bcopy((char *)ipeo, (char *)ipe, sizeof(*ipe));
	ipe->ipe_addr.in4_addr &= ipe->ipe_mask.in4_addr;
	ipe->ipe_addr.in4_addr = ntohl(ipe->ipe_addr.in4_addr);
	bits = count4bits(ipe->ipe_mask.in4_addr);
	ipe->ipe_mask.in4_addr = ntohl(ipe->ipe_mask.in4_addr);

	hv = IPE_HASH_FN(ipe->ipe_addr.in4_addr, ipe->ipe_mask.in4_addr,
			 iph->iph_size);
	ipe->ipe_ref = 0;
	ipe->ipe_next = iph->iph_table[hv];
	ipe->ipe_pnext = iph->iph_table + hv;

	if (iph->iph_table[hv] != NULL)
		iph->iph_table[hv]->ipe_pnext = &ipe->ipe_next;
	iph->iph_table[hv] = ipe;
	if ((bits >= 0) && (bits != 32))
		iph->iph_masks |= 1 << bits;

	switch (iph->iph_type & ~IPHASH_ANON)
	{
	case IPHASH_GROUPMAP :
		ipe->ipe_ptr = fr_addgroup(ipe->ipe_group, NULL,
					   iph->iph_flags, IPL_LOGIPF,
					   fr_active);
		break;

	default :
		ipe->ipe_ptr = NULL;
		ipe->ipe_value = 0;
		break;
	}

	return 0;
}


/*
 * Delete an entry from a hash table.
 */
int fr_delhtent(iph, ipe)
iphtable_t *iph;
iphtent_t *ipe;
{

	if (ipe->ipe_ref != 0)
		return EBUSY;


	*ipe->ipe_pnext = ipe->ipe_next;
	if (ipe->ipe_next != NULL)
		ipe->ipe_next->ipe_pnext = ipe->ipe_pnext;

	switch (iph->iph_type & ~IPHASH_ANON)
	{
	case IPHASH_GROUPMAP :
		if (ipe->ipe_group != NULL)
			fr_delgroup(ipe->ipe_group, IPL_LOGIPF, fr_active);
		break;

	default :
		ipe->ipe_ptr = NULL;
		ipe->ipe_value = 0;
		break;
	}

	KFREE(ipe);

	return 0;
}


void *fr_iphmfindgroup(tptr, aptr)
void *tptr, *aptr;
{
	struct in_addr *addr;
	iphtable_t *iph;
	iphtent_t *ipe;
	void *rval;

	READ_ENTER(&ip_poolrw);
	iph = tptr;
	addr = aptr;

	ipe = fr_iphmfind(iph, addr);
	if (ipe != NULL)
		rval = ipe->ipe_ptr;
	else
		rval = NULL;
	RWLOCK_EXIT(&ip_poolrw);
	return rval;
}


int fr_iphmfindip(tptr, version, aptr)
void *tptr, *aptr;
int version;
{
	struct in_addr *addr;
	iphtable_t *iph;
	iphtent_t *ipe;
	int rval;

	if (version != 4)
		return 1;

	if (tptr == NULL || aptr == NULL)
		return 1;

	iph = tptr;
	addr = aptr;

	READ_ENTER(&ip_poolrw);
	ipe = fr_iphmfind(iph, addr);
	if (ipe != NULL)
		rval = 0;
	else
		rval = 1;
	RWLOCK_EXIT(&ip_poolrw);
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

	hmsk = iph->iph_masks;
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

#endif /* IPFILTER_LOOKUP */
