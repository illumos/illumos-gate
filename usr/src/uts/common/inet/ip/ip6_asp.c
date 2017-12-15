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
 * Copyright 2017 Sebastian Wiedenroth
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/strsun.h>
#include <sys/zone.h>
#include <netinet/in.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip6_asp.h>
#include <inet/ip_ire.h>
#include <inet/ip_if.h>
#include <inet/ipclassifier.h>

#define	IN6ADDR_MASK128_INIT \
	{ 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU }
#define	IN6ADDR_MASK96_INIT	{ 0xffffffffU, 0xffffffffU, 0xffffffffU, 0 }
#define	IN6ADDR_MASK32_INIT	{ 0xffffffffU, 0, 0, 0 }
#ifdef _BIG_ENDIAN
#define	IN6ADDR_MASK16_INIT	{ 0xffff0000U, 0, 0, 0 }
#define	IN6ADDR_MASK10_INIT	{ 0xffc00000U, 0, 0, 0 }
#define	IN6ADDR_MASK7_INIT	{ 0xfe000000U, 0, 0, 0 }
#else
#define	IN6ADDR_MASK16_INIT	{ 0x0000ffffU, 0, 0, 0 }
#define	IN6ADDR_MASK10_INIT	{ 0x0000c0ffU, 0, 0, 0 }
#define	IN6ADDR_MASK7_INIT	{ 0x000000feU, 0, 0, 0 }
#endif

/*
 * This table is ordered such that longest prefix matches are hit first
 * (longer prefix lengths first).  The last entry must be the "default"
 * entry (::0/0).
 */
static ip6_asp_t default_ip6_asp_table[] = {
	{ IN6ADDR_LOOPBACK_INIT,	IN6ADDR_MASK128_INIT,
	    "Loopback", 50 },
	{ IN6ADDR_ANY_INIT,		IN6ADDR_MASK96_INIT,
	    "IPv4_Compatible", 1 },
#ifdef _BIG_ENDIAN
	{ { 0, 0, 0x0000ffffU, 0 },	IN6ADDR_MASK96_INIT,
	    "IPv4", 35 },
	{ { 0x20010000U, 0, 0, 0 },	IN6ADDR_MASK32_INIT,
	    "Teredo", 5 },
	{ { 0x20020000U, 0, 0, 0 },	IN6ADDR_MASK16_INIT,
	    "6to4", 30 },
	{ { 0x3ffe0000U, 0, 0, 0 },	IN6ADDR_MASK16_INIT,
	    "6bone", 1 },
	{ { 0xfec00000U, 0, 0, 0 },	IN6ADDR_MASK10_INIT,
	    "Site_Local", 1 },
	{ { 0xfc000000U, 0, 0, 0 },	IN6ADDR_MASK7_INIT,
	    "ULA", 3 },
#else
	{ { 0, 0, 0xffff0000U, 0 },	IN6ADDR_MASK96_INIT,
	    "IPv4", 35 },
	{ { 0x00000120U, 0, 0, 0 },	IN6ADDR_MASK32_INIT,
	    "Teredo", 5 },
	{ { 0x00000220U, 0, 0, 0 },	IN6ADDR_MASK16_INIT,
	    "6to4", 30 },
	{ { 0x0000fe3fU, 0, 0, 0 },	IN6ADDR_MASK16_INIT,
	    "6bone", 1 },
	{ { 0x0000c0feU, 0, 0, 0 },	IN6ADDR_MASK10_INIT,
	    "Site_Local", 1 },
	{ { 0x000000fcU, 0, 0, 0 },	IN6ADDR_MASK7_INIT,
	    "ULA", 3 },
#endif
	{ IN6ADDR_ANY_INIT,		IN6ADDR_ANY_INIT,
	    "Default", 40 }
};

/*
 * The IPv6 Default Address Selection policy table.
 * Until someone up above reconfigures the policy table, use the global
 * default.  The table needs no lock since the only way to alter it is
 * through the SIOCSIP6ADDRPOLICY which is exclusive in ip.
 */
static void ip6_asp_copy(ip6_asp_t *, ip6_asp_t *, uint_t);
static void ip6_asp_check_for_updates(ip_stack_t *);

void
ip6_asp_init(ip_stack_t *ipst)
{
	/* Initialize the table lock */
	mutex_init(&ipst->ips_ip6_asp_lock, NULL, MUTEX_DEFAULT, NULL);

	ipst->ips_ip6_asp_table = default_ip6_asp_table;

	ipst->ips_ip6_asp_table_count =
	    sizeof (default_ip6_asp_table) / sizeof (ip6_asp_t);
}

void
ip6_asp_free(ip_stack_t *ipst)
{
	if (ipst->ips_ip6_asp_table != default_ip6_asp_table) {
		kmem_free(ipst->ips_ip6_asp_table,
		    ipst->ips_ip6_asp_table_count * sizeof (ip6_asp_t));
		ipst->ips_ip6_asp_table = NULL;
	}
	mutex_destroy(&ipst->ips_ip6_asp_lock);
}

/*
 * Return false if the table is being updated. Else, increment the ref
 * count and return true.
 */
boolean_t
ip6_asp_can_lookup(ip_stack_t *ipst)
{
	mutex_enter(&ipst->ips_ip6_asp_lock);
	if (ipst->ips_ip6_asp_uip) {
		mutex_exit(&ipst->ips_ip6_asp_lock);
		return (B_FALSE);
	}
	IP6_ASP_TABLE_REFHOLD(ipst);
	mutex_exit(&ipst->ips_ip6_asp_lock);
	return (B_TRUE);

}

void
ip6_asp_pending_op(queue_t *q, mblk_t *mp, aspfunc_t func)
{
	conn_t	*connp = Q_TO_CONN(q);
	ip_stack_t *ipst = connp->conn_netstack->netstack_ip;

	ASSERT((mp->b_prev == NULL) && (mp->b_queue == NULL) &&
	    (mp->b_next == NULL));
	mp->b_queue = (void *)q;
	mp->b_prev = (void *)func;
	mp->b_next = NULL;

	mutex_enter(&ipst->ips_ip6_asp_lock);
	if (ipst->ips_ip6_asp_pending_ops == NULL) {
		ASSERT(ipst->ips_ip6_asp_pending_ops_tail == NULL);
		ipst->ips_ip6_asp_pending_ops =
		    ipst->ips_ip6_asp_pending_ops_tail = mp;
	} else {
		ipst->ips_ip6_asp_pending_ops_tail->b_next = mp;
		ipst->ips_ip6_asp_pending_ops_tail = mp;
	}
	mutex_exit(&ipst->ips_ip6_asp_lock);
}

static void
ip6_asp_complete_op(ip_stack_t *ipst)
{
	mblk_t		*mp;
	queue_t		*q;
	aspfunc_t	func;

	mutex_enter(&ipst->ips_ip6_asp_lock);
	while (ipst->ips_ip6_asp_pending_ops != NULL) {
		mp = ipst->ips_ip6_asp_pending_ops;
		ipst->ips_ip6_asp_pending_ops = mp->b_next;
		mp->b_next = NULL;
		if (ipst->ips_ip6_asp_pending_ops == NULL)
			ipst->ips_ip6_asp_pending_ops_tail = NULL;
		mutex_exit(&ipst->ips_ip6_asp_lock);

		q = (queue_t *)mp->b_queue;
		func = (aspfunc_t)mp->b_prev;

		mp->b_prev = NULL;
		mp->b_queue = NULL;


		(*func)(NULL, q, mp, NULL);
		mutex_enter(&ipst->ips_ip6_asp_lock);
	}
	mutex_exit(&ipst->ips_ip6_asp_lock);
}

/*
 * Decrement reference count. When it gets to 0, we check for (pending)
 * saved update to the table, if any.
 */
void
ip6_asp_table_refrele(ip_stack_t *ipst)
{
	IP6_ASP_TABLE_REFRELE(ipst);
}

/*
 * This function is guaranteed never to return a NULL pointer.  It
 * will always return information from one of the entries in the
 * asp_table (which will never be empty).  If a pointer is passed
 * in for the precedence, the precedence value will be set; a
 * pointer to the label will be returned by the function.
 *
 * Since the table is only anticipated to have about 10 entries
 * total, the lookup algorithm hasn't been optimized to anything
 * better than O(n).
 */
char *
ip6_asp_lookup(const in6_addr_t *addr, uint32_t *precedence, ip_stack_t *ipst)
{
	ip6_asp_t *aspp;
	ip6_asp_t *match = NULL;
	ip6_asp_t *default_policy;

	aspp = ipst->ips_ip6_asp_table;
	/* The default entry must always be the last one */
	default_policy = aspp + ipst->ips_ip6_asp_table_count - 1;

	while (match == NULL) {
		if (aspp == default_policy) {
			match = aspp;
		} else {
			if (V6_MASK_EQ(*addr, aspp->ip6_asp_mask,
			    aspp->ip6_asp_prefix))
				match = aspp;
			else
				aspp++;
		}
	}

	if (precedence != NULL)
		*precedence = match->ip6_asp_precedence;
	return (match->ip6_asp_label);
}

/*
 * If we had deferred updating the table because of outstanding references,
 * do it now. Note, we don't do error checking on the queued IOCTL mblk, since
 * ip_sioctl_ip6addrpolicy() has already done it for us.
 */
void
ip6_asp_check_for_updates(ip_stack_t *ipst)
{
	ip6_asp_t *table;
	size_t	table_size;
	mblk_t	*data_mp, *mp;
	struct iocblk *iocp;

	mutex_enter(&ipst->ips_ip6_asp_lock);
	if (ipst->ips_ip6_asp_pending_update == NULL ||
	    ipst->ips_ip6_asp_refcnt > 0) {
		mutex_exit(&ipst->ips_ip6_asp_lock);
		return;
	}

	mp = ipst->ips_ip6_asp_pending_update;
	ipst->ips_ip6_asp_pending_update = NULL;
	ASSERT(mp->b_prev != NULL);

	ipst->ips_ip6_asp_uip = B_TRUE;

	iocp = (struct iocblk *)mp->b_rptr;
	data_mp = mp->b_cont;
	if (data_mp == NULL) {
		table = NULL;
		table_size = iocp->ioc_count;
	} else {
		table = (ip6_asp_t *)data_mp->b_rptr;
		table_size = iocp->ioc_count;
	}

	ip6_asp_replace(mp, table, table_size, B_TRUE, ipst,
	    iocp->ioc_flag & IOC_MODELS);
}

/*
 * ip6_asp_replace replaces the contents of the IPv6 address selection
 * policy table with those specified in new_table.  If new_table is NULL,
 * this indicates that the caller wishes ip to use the default policy
 * table.  The caller is responsible for making sure that there are exactly
 * new_count policy entries in new_table.
 */
/*ARGSUSED5*/
void
ip6_asp_replace(mblk_t *mp, ip6_asp_t *new_table, size_t new_size,
    boolean_t locked, ip_stack_t *ipst, model_t datamodel)
{
	int			ret_val = 0;
	ip6_asp_t		*tmp_table;
	uint_t			count;
	queue_t			*q;
	struct iocblk		*iocp;
#if defined(_SYSCALL32_IMPL) && _LONG_LONG_ALIGNMENT_32 == 4
	size_t ip6_asp_size = SIZEOF_STRUCT(ip6_asp, datamodel);
#else
	const size_t ip6_asp_size = sizeof (ip6_asp_t);
#endif

	if (new_size % ip6_asp_size != 0) {
		ip1dbg(("ip6_asp_replace: invalid table size\n"));
		ret_val = EINVAL;
		if (locked)
			goto unlock_end;
		goto replace_end;
	} else {
		count = new_size / ip6_asp_size;
	}


	if (!locked)
		mutex_enter(&ipst->ips_ip6_asp_lock);
	/*
	 * Check if we are in the process of creating any IRE using the
	 * current information. If so, wait till that is done.
	 */
	if (!locked && ipst->ips_ip6_asp_refcnt > 0) {
		/* Save this request for later processing */
		if (ipst->ips_ip6_asp_pending_update == NULL) {
			ipst->ips_ip6_asp_pending_update = mp;
		} else {
			/* Let's not queue multiple requests for now */
			ip1dbg(("ip6_asp_replace: discarding request\n"));
			mutex_exit(&ipst->ips_ip6_asp_lock);
			ret_val =  EAGAIN;
			goto replace_end;
		}
		mutex_exit(&ipst->ips_ip6_asp_lock);
		return;
	}

	/* Prevent lookups till the table have been updated */
	if (!locked)
		ipst->ips_ip6_asp_uip = B_TRUE;

	ASSERT(ipst->ips_ip6_asp_refcnt == 0);

	if (new_table == NULL) {
		/*
		 * This is a special case.  The user wants to revert
		 * back to using the default table.
		 */
		if (ipst->ips_ip6_asp_table == default_ip6_asp_table)
			goto unlock_end;

		kmem_free(ipst->ips_ip6_asp_table,
		    ipst->ips_ip6_asp_table_count * sizeof (ip6_asp_t));
		ipst->ips_ip6_asp_table = default_ip6_asp_table;
		ipst->ips_ip6_asp_table_count =
		    sizeof (default_ip6_asp_table) / sizeof (ip6_asp_t);
		goto unlock_end;
	}

	if (count == 0) {
		ret_val = EINVAL;
		ip1dbg(("ip6_asp_replace: empty table\n"));
		goto unlock_end;
	}

	if ((tmp_table = kmem_alloc(count * sizeof (ip6_asp_t), KM_NOSLEEP)) ==
	    NULL) {
		ret_val = ENOMEM;
		goto unlock_end;
	}

#if defined(_SYSCALL32_IMPL) && _LONG_LONG_ALIGNMENT_32 == 4

	/*
	 * If 'new_table' -actually- originates from a 32-bit process
	 * then the nicely aligned ip6_asp_label array will be
	 * subtlely misaligned on this kernel, because the structure
	 * is 8 byte aligned in the kernel, but only 4 byte aligned in
	 * userland.  Fix it up here.
	 *
	 * XX64	See the notes in ip_sioctl_ip6addrpolicy.  Perhaps we could
	 *	do the datamodel transformation (below) there instead of here?
	 */
	if (datamodel == IOC_ILP32) {
		ip6_asp_t *dst;
		ip6_asp32_t *src;
		int i;

		if ((dst = kmem_zalloc(count * sizeof (*dst),
		    KM_NOSLEEP)) == NULL) {
			kmem_free(tmp_table, count * sizeof (ip6_asp_t));
			ret_val = ENOMEM;
			goto unlock_end;
		}

		/*
		 * Copy each element of the table from ip6_asp32_t
		 * format into ip6_asp_t format.  Fortunately, since
		 * we're just dealing with a trailing structure pad,
		 * we can do this straightforwardly with a flurry of
		 * bcopying.
		 */
		src = (void *)new_table;
		for (i = 0; i < count; i++)
			bcopy(src + i, dst + i, sizeof (*src));

		ip6_asp_copy(dst, tmp_table, count);
		kmem_free(dst, count * sizeof (*dst));
	} else
#endif
		ip6_asp_copy(new_table, tmp_table, count);

	/* Make sure the last entry is the default entry */
	if (!IN6_IS_ADDR_UNSPECIFIED(&tmp_table[count - 1].ip6_asp_prefix) ||
	    !IN6_IS_ADDR_UNSPECIFIED(&tmp_table[count - 1].ip6_asp_mask)) {
		ret_val = EINVAL;
		kmem_free(tmp_table, count * sizeof (ip6_asp_t));
		ip1dbg(("ip6_asp_replace: bad table: no default entry\n"));
		goto unlock_end;
	}
	if (ipst->ips_ip6_asp_table != default_ip6_asp_table) {
		kmem_free(ipst->ips_ip6_asp_table,
		    ipst->ips_ip6_asp_table_count * sizeof (ip6_asp_t));
	}
	ipst->ips_ip6_asp_table = tmp_table;
	ipst->ips_ip6_asp_table_count = count;

unlock_end:
	ipst->ips_ip6_asp_uip = B_FALSE;
	mutex_exit(&ipst->ips_ip6_asp_lock);

	/* Let conn_ixa caching know that source address selection changed */
	ip_update_source_selection(ipst);

replace_end:
	/* Reply to the ioctl */
	q = (queue_t *)mp->b_prev;
	mp->b_prev = NULL;
	if (q == NULL) {
		freemsg(mp);
		goto check_binds;
	}
	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_error = ret_val;
	iocp->ioc_count = 0;
	DB_TYPE(mp) = (iocp->ioc_error == 0) ? M_IOCACK : M_IOCNAK;
	qreply(q, mp);
check_binds:
	ip6_asp_complete_op(ipst);
}

/*
 * Copies the contents of src_table to dst_table, and sorts the
 * entries in decending order of prefix lengths.  It assumes that both
 * tables are appropriately sized to contain count entries.
 */
static void
ip6_asp_copy(ip6_asp_t *src_table, ip6_asp_t *dst_table, uint_t count)
{
	ip6_asp_t *src_ptr, *src_limit, *dst_ptr, *dst_limit, *dp;

	dst_table[0] = src_table[0];
	if (count == 1)
		return;

	/*
	 * Sort the entries in descending order of prefix lengths.
	 *
	 * Note: this should be a small table.  In 99% of cases, we
	 * expect the table to have 9 entries.  In the remaining 1%
	 * of cases, we expect the table to have one or two more
	 * entries.
	 */
	src_limit = src_table + count;
	dst_limit = dst_table + 1;
	for (src_ptr = src_table + 1; src_ptr != src_limit;
	    src_ptr++, dst_limit++) {
		for (dst_ptr = dst_table; dst_ptr < dst_limit; dst_ptr++) {
			if (ip_mask_to_plen_v6(&src_ptr->ip6_asp_mask) >
			    ip_mask_to_plen_v6(&dst_ptr->ip6_asp_mask)) {
				/*
				 * Make room to insert the source entry
				 * before dst_ptr by shifting entries to
				 * the right.
				 */
				for (dp = dst_limit - 1; dp >= dst_ptr; dp--)
					*(dp + 1) = *dp;
				break;
			}
		}
		*dst_ptr = *src_ptr;
	}
}

/*
 * This function copies as many entries from ip6_asp_table as will fit
 * into dtable.  The dtable_size parameter is the size of dtable
 * in bytes.  This function returns the number of entries in
 * ip6_asp_table, even if it's not able to fit all of the entries into
 * dtable.
 */
int
ip6_asp_get(ip6_asp_t *dtable, size_t dtable_size, ip_stack_t *ipst)
{
	uint_t dtable_count;

	if (dtable != NULL) {
		if (dtable_size < sizeof (ip6_asp_t))
			return (-1);

		dtable_count = dtable_size / sizeof (ip6_asp_t);
		bcopy(ipst->ips_ip6_asp_table, dtable,
		    MIN(ipst->ips_ip6_asp_table_count, dtable_count) *
		    sizeof (ip6_asp_t));
	}

	return (ipst->ips_ip6_asp_table_count);
}

/*
 * Compare two labels.  Return B_TRUE if they are equal, B_FALSE
 * otherwise.
 */
boolean_t
ip6_asp_labelcmp(const char *label1, const char *label2)
{
	int64_t *llptr1, *llptr2;

	/*
	 * The common case, the two labels are actually the same string
	 * from the policy table.
	 */
	if (label1 == label2)
		return (B_TRUE);

	/*
	 * Since we know the labels are at most 16 bytes long, compare
	 * the two strings as two 8-byte long integers.  The ip6_asp_t
	 * structure guarantees that the labels are 8 byte alligned.
	 */
	llptr1 = (int64_t *)label1;
	llptr2 = (int64_t *)label2;
	if (llptr1[0] == llptr2[0] && llptr1[1] == llptr2[1])
		return (B_TRUE);
	return (B_FALSE);
}
