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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/kmem.h>
#include <sys/strsubr.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/param.h>
#include <sys/model.h>
#include <sys/errno.h>
#include <sys/modhash.h>

#include <sys/policy.h>
#include <sys/tsol/label.h>
#include <sys/tsol/tsyscall.h>
#include <sys/tsol/tndb.h>
#include <sys/tsol/tnet.h>
#include <sys/disp.h>

#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/sdt.h>

static mod_hash_t *tpc_name_hash;	/* hash of cache entries by name */
static kmutex_t tpc_lock;

static tsol_tpc_t *tpc_unlab;

/*
 * tnrhc_table and tnrhc_table_v6 are similar to the IP forwarding tables
 * in organization and search. The tnrhc_table[_v6] is an array of 33/129
 * pointers to the 33/129 tnrhc tables indexed by the prefix length.
 * A largest prefix match search is done by find_rhc and it walks the
 * tables from the most specific to the least specific table. Table 0
 * corresponds to the single entry for 0.0.0.0/0 or ::0/0.
 */
tnrhc_hash_t *tnrhc_table[TSOL_MASK_TABLE_SIZE];
tnrhc_hash_t *tnrhc_table_v6[TSOL_MASK_TABLE_SIZE_V6];
kmutex_t tnrhc_g_lock;

static void tsol_create_i_tmpls(void);

static void tsol_create_i_tnrh(const tnaddr_t *);

/* List of MLPs on valid on shared addresses */
static tsol_mlp_list_t shared_mlps;

/*
 * Convert length for a mask to the mask.
 */
static ipaddr_t
tsol_plen_to_mask(uint_t masklen)
{
	return (masklen == 0 ? 0 : htonl(IP_HOST_MASK << (IP_ABITS - masklen)));
}

/*
 * Convert a prefix length to the mask for that prefix.
 * Returns the argument bitmask.
 */
static void
tsol_plen_to_mask_v6(uint_t plen, in6_addr_t *bitmask)
{
	uint32_t *ptr;

	ASSERT(plen <= IPV6_ABITS);

	ptr = (uint32_t *)bitmask;
	while (plen >= 32) {
		*ptr++ = 0xffffffffU;
		plen -= 32;
	}
	if (plen > 0)
		*ptr++ = htonl(0xffffffff << (32 - plen));
	while (ptr < (uint32_t *)(bitmask + 1))
		*ptr++ = 0;
}

boolean_t
tnrhc_init_table(tnrhc_hash_t *table[], short prefix_len, int kmflag)
{
	int	i;

	mutex_enter(&tnrhc_g_lock);

	if (table[prefix_len] == NULL) {
		table[prefix_len] = (tnrhc_hash_t *)
		    kmem_zalloc(TNRHC_SIZE * sizeof (tnrhc_hash_t), kmflag);
		if (table[prefix_len] == NULL) {
			mutex_exit(&tnrhc_g_lock);
			return (B_FALSE);
		}
		for (i = 0; i < TNRHC_SIZE; i++) {
			mutex_init(&table[prefix_len][i].tnrh_lock,
			    NULL, MUTEX_DEFAULT, 0);
		}
	}
	mutex_exit(&tnrhc_g_lock);
	return (B_TRUE);
}

void
tcache_init(void)
{
	tnaddr_t address;

	/*
	 * Note: unable to use mod_hash_create_strhash here, since it's
	 * assymetric.  It assumes that the user has allocated exactly
	 * strlen(key) + 1 bytes for the key when inserted, and attempts to
	 * kmem_free that memory on a delete.
	 */
	tpc_name_hash = mod_hash_create_extended("tnrhtpc_by_name", 256,
	    mod_hash_null_keydtor,  mod_hash_null_valdtor, mod_hash_bystr,
	    NULL, mod_hash_strkey_cmp, KM_SLEEP);
	mutex_init(&tpc_lock, NULL, MUTEX_DEFAULT, NULL);

	mutex_init(&tnrhc_g_lock, NULL, MUTEX_DEFAULT, NULL);

	/* label_init always called before tcache_init */
	ASSERT(l_admin_low != NULL && l_admin_high != NULL);

	/* Initialize the zeroth table prior to loading the 0.0.0.0 entry */
	(void) tnrhc_init_table(tnrhc_table, 0, KM_SLEEP);
	(void) tnrhc_init_table(tnrhc_table_v6, 0, KM_SLEEP);
	/*
	 * create an internal host template called "_unlab"
	 */
	tsol_create_i_tmpls();

	/*
	 * create a host entry, 0.0.0.0 = _unlab
	 */
	bzero(&address, sizeof (tnaddr_t));
	address.ta_family = AF_INET;
	tsol_create_i_tnrh(&address);

	/*
	 * create a host entry, ::0 = _unlab
	 */
	address.ta_family = AF_INET6;
	tsol_create_i_tnrh(&address);

	rw_init(&shared_mlps.mlpl_rwlock, NULL, RW_DEFAULT, NULL);
}

/* Called only by the TNRHC_RELE macro when the refcount goes to zero. */
void
tnrhc_free(tsol_tnrhc_t *tnrhc)
{
	/*
	 * We assert rhc_invalid here to make sure that no new thread could
	 * possibly end up finding this entry.  If it could, then the
	 * mutex_destroy would panic.
	 */
	DTRACE_PROBE1(tx__tndb__l3__tnrhcfree, tsol_tnrhc_t *, tnrhc);
	ASSERT(tnrhc->rhc_next == NULL && tnrhc->rhc_invalid);
	mutex_exit(&tnrhc->rhc_lock);
	mutex_destroy(&tnrhc->rhc_lock);
	if (tnrhc->rhc_tpc != NULL)
		TPC_RELE(tnrhc->rhc_tpc);
	kmem_free(tnrhc, sizeof (*tnrhc));
}

/* Called only by the TPC_RELE macro when the refcount goes to zero. */
void
tpc_free(tsol_tpc_t *tpc)
{
	DTRACE_PROBE1(tx__tndb__l3__tpcfree, tsol_tpc_t *, tpc);
	ASSERT(tpc->tpc_invalid);
	mutex_exit(&tpc->tpc_lock);
	mutex_destroy(&tpc->tpc_lock);
	kmem_free(tpc, sizeof (*tpc));
}

/*
 * Find and hold a reference to a template entry by name.  Ignores entries that
 * are being deleted.
 */
static tsol_tpc_t *
tnrhtp_find(const char *name, mod_hash_t *hash)
{
	mod_hash_val_t hv;
	tsol_tpc_t *tpc = NULL;

	mutex_enter(&tpc_lock);
	if (mod_hash_find(hash, (mod_hash_key_t)name, &hv) == 0) {
		tpc = (tsol_tpc_t *)hv;
		if (tpc->tpc_invalid)
			tpc = NULL;
		else
			TPC_HOLD(tpc);
	}
	mutex_exit(&tpc_lock);
	return (tpc);
}

static int
tnrh_delete(const tsol_rhent_t *rhent)
{
	tsol_tnrhc_t *current;
	tsol_tnrhc_t **prevp;
	ipaddr_t tmpmask;
	in6_addr_t tmpmask_v6;
	tnrhc_hash_t *tnrhc_hash;

	if (rhent->rh_address.ta_family == AF_INET) {
		if (rhent->rh_prefix < 0 || rhent->rh_prefix > IP_ABITS)
			return (EINVAL);
		if (tnrhc_table[rhent->rh_prefix] == NULL)
			return (ENOENT);
		tmpmask = tsol_plen_to_mask(rhent->rh_prefix);
		tnrhc_hash = &tnrhc_table[rhent->rh_prefix][
		    TSOL_ADDR_HASH(rhent->rh_address.ta_addr_v4.s_addr &
		    tmpmask, TNRHC_SIZE)];
	} else if (rhent->rh_address.ta_family == AF_INET6) {
		if (rhent->rh_prefix < 0 || rhent->rh_prefix > IPV6_ABITS)
			return (EINVAL);
		if (tnrhc_table_v6[rhent->rh_prefix] == NULL)
			return (ENOENT);
		tsol_plen_to_mask_v6(rhent->rh_prefix, &tmpmask_v6);
		tnrhc_hash = &tnrhc_table_v6[rhent->rh_prefix][
		    TSOL_ADDR_MASK_HASH_V6(rhent->rh_address.ta_addr_v6,
		    tmpmask_v6, TNRHC_SIZE)];
	} else {
		return (EAFNOSUPPORT);
	}

	/* search for existing entry */
	mutex_enter(&tnrhc_hash->tnrh_lock);
	prevp = &tnrhc_hash->tnrh_list;
	while ((current = *prevp) != NULL) {
		if (TNADDR_EQ(&rhent->rh_address, &current->rhc_host))
			break;
		prevp = &current->rhc_next;
	}

	if (current != NULL) {
		DTRACE_PROBE(tx__tndb__l2__tnrhdelete_existingrhentry);
		*prevp = current->rhc_next;
		mutex_enter(&current->rhc_lock);
		current->rhc_next = NULL;
		current->rhc_invalid = 1;
		mutex_exit(&current->rhc_lock);
		TNRHC_RELE(current);
	}
	mutex_exit(&tnrhc_hash->tnrh_lock);
	return (current == NULL ? ENOENT : 0);
}

/*
 * Flush all remote host entries from the database.
 *
 * Note that the htable arrays themselves do not have reference counters, so,
 * unlike the remote host entries, they cannot be freed.
 */
static void
flush_rh_table(tnrhc_hash_t **htable, int nbits)
{
	tnrhc_hash_t *hent, *hend;
	tsol_tnrhc_t *rhc, *rhnext;

	while (--nbits >= 0) {
		if ((hent = htable[nbits]) == NULL)
			continue;
		hend = hent + TNRHC_SIZE;
		while (hent < hend) {
			/*
			 * List walkers hold this lock during the walk.  It
			 * protects tnrh_list and rhc_next.
			 */
			mutex_enter(&hent->tnrh_lock);
			rhnext = hent->tnrh_list;
			hent->tnrh_list = NULL;
			mutex_exit(&hent->tnrh_lock);
			/*
			 * There may still be users of the rhcs at this point,
			 * but not of the list or its next pointer.  Thus, the
			 * only thing that would need to be done under a lock
			 * is setting the invalid bit, but that's atomic
			 * anyway, so no locks needed here.
			 */
			while ((rhc = rhnext) != NULL) {
				rhnext = rhc->rhc_next;
				rhc->rhc_next = NULL;
				rhc->rhc_invalid = 1;
				TNRHC_RELE(rhc);
			}
			hent++;
		}
	}
}

/*
 * Load a remote host entry into kernel cache.  Create a new one if a matching
 * entry isn't found, otherwise replace the contents of the previous one by
 * deleting it and recreating it.  (Delete and recreate is used to avoid
 * allowing other threads to see an unstable data structure.)
 *
 * A "matching" entry is the one whose address matches that of the one
 * being loaded.
 *
 * Return 0 for success, error code for failure.
 */
static int
tnrh_hash_add(tsol_tnrhc_t *new, short prefix)
{
	tsol_tnrhc_t **rhp;
	tsol_tnrhc_t *rh;
	ipaddr_t tmpmask;
	in6_addr_t tmpmask_v6;
	tnrhc_hash_t *tnrhc_hash;

	/* Find the existing entry, if any, leaving the hash locked */
	if (new->rhc_host.ta_family == AF_INET) {
		if (prefix < 0 || prefix > IP_ABITS)
			return (EINVAL);
		if (tnrhc_table[prefix] == NULL &&
		    !tnrhc_init_table(tnrhc_table, prefix,
		    KM_NOSLEEP))
			return (ENOMEM);
		tmpmask = tsol_plen_to_mask(prefix);
		tnrhc_hash = &tnrhc_table[prefix][
		    TSOL_ADDR_HASH(new->rhc_host.ta_addr_v4.s_addr &
		    tmpmask, TNRHC_SIZE)];
		mutex_enter(&tnrhc_hash->tnrh_lock);
		for (rhp = &tnrhc_hash->tnrh_list; (rh = *rhp) != NULL;
		    rhp = &rh->rhc_next) {
			ASSERT(rh->rhc_host.ta_family == AF_INET);
			if (((rh->rhc_host.ta_addr_v4.s_addr ^
			    new->rhc_host.ta_addr_v4.s_addr) & tmpmask) ==
			    0)
				break;
		}
	} else if (new->rhc_host.ta_family == AF_INET6) {
		if (prefix < 0 || prefix > IPV6_ABITS)
			return (EINVAL);
		if (tnrhc_table_v6[prefix] == NULL &&
		    !tnrhc_init_table(tnrhc_table_v6, prefix,
		    KM_NOSLEEP))
			return (ENOMEM);
		tsol_plen_to_mask_v6(prefix, &tmpmask_v6);
		tnrhc_hash = &tnrhc_table_v6[prefix][
		    TSOL_ADDR_MASK_HASH_V6(new->rhc_host.ta_addr_v6,
		    tmpmask_v6, TNRHC_SIZE)];
		mutex_enter(&tnrhc_hash->tnrh_lock);
		for (rhp = &tnrhc_hash->tnrh_list; (rh = *rhp) != NULL;
		    rhp = &rh->rhc_next) {
			ASSERT(rh->rhc_host.ta_family == AF_INET6);
			if (V6_MASK_EQ_2(rh->rhc_host.ta_addr_v6, tmpmask_v6,
			    new->rhc_host.ta_addr_v6))
				break;
		}
	} else {
		return (EAFNOSUPPORT);
	}

	/* Clobber the old remote host entry. */
	if (rh != NULL) {
		ASSERT(!rh->rhc_invalid);
		rh->rhc_invalid = 1;
		*rhp = rh->rhc_next;
		rh->rhc_next = NULL;
		DTRACE_PROBE1(tx__tndb__l2__tnrhhashadd__invalidaterh,
		    tsol_tnrhc_t *, rh);
		TNRHC_RELE(rh);
	}

	TNRHC_HOLD(new);
	new->rhc_next = tnrhc_hash->tnrh_list;
	tnrhc_hash->tnrh_list = new;
	DTRACE_PROBE1(tx__tndb__l2__tnrhhashadd__addedrh, tsol_tnrhc_t *, new);
	mutex_exit(&tnrhc_hash->tnrh_lock);

	return (0);
}

/*
 * Load a remote host entry into kernel cache.
 *
 * Return 0 for success, error code for failure.
 */
int
tnrh_load(const tsol_rhent_t *rhent)
{
	tsol_tnrhc_t *new;
	tsol_tpc_t *tpc;
	int status;

	/* Find and bump the reference count on the named template */
	if ((tpc = tnrhtp_find(rhent->rh_template, tpc_name_hash)) == NULL) {
		return (EINVAL);
	}
	ASSERT(tpc->tpc_tp.host_type == UNLABELED ||
	    tpc->tpc_tp.host_type == SUN_CIPSO);

	if ((new = kmem_zalloc(sizeof (*new), KM_NOSLEEP)) == NULL) {
		TPC_RELE(tpc);
		return (ENOMEM);
	}

	/* Initialize the new entry. */
	mutex_init(&new->rhc_lock, NULL, MUTEX_DEFAULT, NULL);
	new->rhc_host = rhent->rh_address;

	/* The rhc now owns this tpc reference, so no TPC_RELE past here */
	new->rhc_tpc = tpc;

	/*
	 * tnrh_hash_add handles the tnrh entry ref count for hash
	 * table inclusion. The ref count is incremented and decremented
	 * here to trigger deletion of the new hash table entry in the
	 * event that tnrh_hash_add fails.
	 */
	TNRHC_HOLD(new);
	status = tnrh_hash_add(new, rhent->rh_prefix);
	TNRHC_RELE(new);

	return (status);
}

static int
tnrh_get(tsol_rhent_t *rhent)
{
	tsol_tpc_t *tpc;

	switch (rhent->rh_address.ta_family) {
	case AF_INET:
		tpc = find_tpc(&rhent->rh_address.ta_addr_v4, IPV4_VERSION,
		    B_TRUE);
		break;

	case AF_INET6:
		tpc = find_tpc(&rhent->rh_address.ta_addr_v6, IPV6_VERSION,
		    B_TRUE);
		break;

	default:
		return (EINVAL);
	}
	if (tpc == NULL)
		return (ENOENT);

	DTRACE_PROBE2(tx__tndb__l4__tnrhget__foundtpc, tsol_rhent_t *,
	    rhent, tsol_tpc_t *, tpc);
	bcopy(tpc->tpc_tp.name, rhent->rh_template,
	    sizeof (rhent->rh_template));
	TPC_RELE(tpc);
	return (0);
}

static boolean_t
template_name_ok(const char *name)
{
	const char *name_end = name + TNTNAMSIZ;

	while (name < name_end) {
		if (*name == '\0')
			break;
		name++;
	}
	return (name < name_end);
}

static int
tnrh(int cmd, void *buf)
{
	int retv;
	tsol_rhent_t rhent;

	/* Make sure user has sufficient privilege */
	if (cmd != TNDB_GET &&
	    (retv = secpolicy_net_config(CRED(), B_FALSE)) != 0)
		return (set_errno(retv));

	/*
	 * Get arguments
	 */
	if (cmd != TNDB_FLUSH &&
	    copyin(buf, &rhent, sizeof (rhent)) != 0) {
		DTRACE_PROBE(tx__tndb__l0__tnrhdelete__copyin);
		return (set_errno(EFAULT));
	}

	switch (cmd) {
	case TNDB_LOAD:
		DTRACE_PROBE(tx__tndb__l2__tnrhdelete__tndbload);
		if (!template_name_ok(rhent.rh_template)) {
			retv = EINVAL;
		} else {
			retv = tnrh_load(&rhent);
		}
		break;

	case TNDB_DELETE:
		DTRACE_PROBE(tx__tndb__l2__tnrhdelete__tndbdelete);
		retv = tnrh_delete(&rhent);
		break;

	case TNDB_GET:
		DTRACE_PROBE(tx__tndb__l4__tnrhdelete__tndbget);
		if (!template_name_ok(rhent.rh_template)) {
			retv = EINVAL;
			break;
		}

		retv = tnrh_get(&rhent);
		if (retv != 0)
			break;

		/*
		 * Copy out result
		 */
		if (copyout(&rhent, buf, sizeof (rhent)) != 0) {
			DTRACE_PROBE(tx__tndb__l0__tnrhdelete__copyout);
			retv = EFAULT;
		}
		break;

	case TNDB_FLUSH:
		DTRACE_PROBE(tx__tndb__l2__tnrhdelete__flush);
		flush_rh_table(tnrhc_table, TSOL_MASK_TABLE_SIZE);
		flush_rh_table(tnrhc_table_v6, TSOL_MASK_TABLE_SIZE_V6);
		break;

	default:
		DTRACE_PROBE1(tx__tndb__l0__tnrhdelete__unknowncmd,
		    int, cmd);
		retv = EOPNOTSUPP;
		break;
	}

	if (retv != 0)
		return (set_errno(retv));
	else
		return (retv);
}

static tsol_tpc_t *
tnrhtp_create(const tsol_tpent_t *tpent, int kmflags)
{
	tsol_tpc_t *tpc;
	mod_hash_val_t hv;

	/*
	 * We intentionally allocate a new entry before taking the lock on the
	 * entire database.
	 */
	if ((tpc = kmem_zalloc(sizeof (*tpc), kmflags)) == NULL)
		return (NULL);

	mutex_enter(&tpc_lock);
	if (mod_hash_find(tpc_name_hash, (mod_hash_key_t)tpent->name,
	    &hv) == 0) {
		tsol_tpc_t *found_tpc = (tsol_tpc_t *)hv;

		found_tpc->tpc_invalid = 1;
		(void) mod_hash_destroy(tpc_name_hash,
		    (mod_hash_key_t)tpent->name);
		TPC_RELE(found_tpc);
	}

	mutex_init(&tpc->tpc_lock, NULL, MUTEX_DEFAULT, NULL);
	/* tsol_tpent_t is the same on LP64 and ILP32 */
	bcopy(tpent, &tpc->tpc_tp, sizeof (tpc->tpc_tp));
	(void) mod_hash_insert(tpc_name_hash, (mod_hash_key_t)tpc->tpc_tp.name,
	    (mod_hash_val_t)tpc);
	TPC_HOLD(tpc);
	mutex_exit(&tpc_lock);

	return (tpc);
}

static int
tnrhtp_delete(const char *tname)
{
	tsol_tpc_t *tpc;
	mod_hash_val_t hv;
	int retv = ENOENT;

	mutex_enter(&tpc_lock);
	if (mod_hash_find(tpc_name_hash, (mod_hash_key_t)tname, &hv) == 0) {
		tpc = (tsol_tpc_t *)hv;
		ASSERT(!tpc->tpc_invalid);
		tpc->tpc_invalid = 1;
		(void) mod_hash_destroy(tpc_name_hash,
		    (mod_hash_key_t)tpc->tpc_tp.name);
		TPC_RELE(tpc);
		retv = 0;
	}
	mutex_exit(&tpc_lock);
	return (retv);
}

/* ARGSUSED */
static uint_t
tpc_delete(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	tsol_tpc_t *tpc = (tsol_tpc_t *)val;

	ASSERT(!tpc->tpc_invalid);
	tpc->tpc_invalid = 1;
	TPC_RELE(tpc);
	return (MH_WALK_CONTINUE);
}

static void
tnrhtp_flush(void)
{
	mutex_enter(&tpc_lock);
	mod_hash_walk(tpc_name_hash, tpc_delete, NULL);
	mod_hash_clear(tpc_name_hash);
	mutex_exit(&tpc_lock);
}

static int
tnrhtp(int cmd, void *buf)
{
	int retv;
	int type;
	tsol_tpent_t rhtpent;
	tsol_tpc_t *tpc;

	/* Make sure user has sufficient privilege */
	if (cmd != TNDB_GET &&
	    (retv = secpolicy_net_config(CRED(), B_FALSE)) != 0)
		return (set_errno(retv));

	/*
	 * Get argument.  Note that tsol_tpent_t is the same on LP64 and ILP32,
	 * so no special handling is required.
	 */
	if (cmd != TNDB_FLUSH) {
		if (copyin(buf, &rhtpent, sizeof (rhtpent)) != 0) {
			DTRACE_PROBE(tx__tndb__l0__tnrhtp__copyin);
			return (set_errno(EFAULT));
		}

		/*
		 * Don't let the user give us a bogus (unterminated) template
		 * name.
		 */
		if (!template_name_ok(rhtpent.name))
			return (set_errno(EINVAL));
	}

	switch (cmd) {
	case TNDB_LOAD:
		DTRACE_PROBE1(tx__tndb__l2__tnrhtp__tndbload, char *,
			rhtpent.name);
		type = rhtpent.host_type;
		if (type != UNLABELED && type != SUN_CIPSO) {
			retv = EINVAL;
			break;
		}

		if (tnrhtp_create(&rhtpent, KM_NOSLEEP) == NULL)
			retv = ENOMEM;
		else
			retv = 0;
		break;

	case TNDB_GET:
		DTRACE_PROBE1(tx__tndb__l4__tnrhtp__tndbget, char *,
		    rhtpent.name);
		tpc = tnrhtp_find(rhtpent.name, tpc_name_hash);
		if (tpc == NULL) {
			retv = ENOENT;
			break;
		}

		/* Copy out result */
		if (copyout(&tpc->tpc_tp, buf, sizeof (tpc->tpc_tp)) != 0) {
			DTRACE_PROBE(tx__tndb__l0__tnrhtp__copyout);
			retv = EFAULT;
		} else {
			retv = 0;
		}
		TPC_RELE(tpc);
		break;

	case TNDB_DELETE:
		DTRACE_PROBE1(tx__tndb__l4__tnrhtp__tndbdelete, char *,
		    rhtpent.name);
		retv = tnrhtp_delete(rhtpent.name);
		break;

	case TNDB_FLUSH:
		DTRACE_PROBE(tx__tndb__l4__tnrhtp__flush);
		tnrhtp_flush();
		retv = 0;
		break;

	default:
		DTRACE_PROBE1(tx__tndb__l0__tnrhtp__unknowncmd, int,
		    cmd);
		retv = EOPNOTSUPP;
		break;
	}

	if (retv != 0)
		return (set_errno(retv));
	else
		return (retv);
}

/*
 * MLP entry ordering logic
 *
 * There are two loops in this routine.  The first loop finds the entry that
 * either logically follows the new entry to be inserted, or is the entry that
 * precedes and overlaps the new entry, or is NULL to mean end-of-list.  This
 * is 'tme.'  The second loop scans ahead from that point to find any overlap
 * on the front or back of this new entry.
 *
 * For the first loop, we can have the following cases in the list (note that
 * the port-portmax range is inclusive):
 *
 *	       port   portmax
 *		+--------+
 * 1: +------+ ................... precedes; skip to next
 * 2:	    +------+ ............. overlaps; stop here if same protocol
 * 3:		+------+ ......... overlaps; stop if same or higher protocol
 * 4:		    +-------+ .... overlaps or succeeds; stop here
 *
 * For the second loop, we can have the following cases (note that we need not
 * care about other protocol entries at this point, because we're only looking
 * for overlap, not an insertion point):
 *
 *	       port   portmax
 *		+--------+
 * 5:	    +------+ ............. overlaps; stop if same protocol
 * 6:		+------+ ......... overlaps; stop if same protocol
 * 7:		    +-------+ .... overlaps; stop if same protocol
 * 8:			   +---+ . follows; search is done
 *
 * In other words, this second search needs to consider only whether the entry
 * has a starting port number that's greater than the end point of the new
 * entry.  All others are overlaps.
 */
static int
mlp_add_del(tsol_mlp_list_t *mlpl, zoneid_t zoneid, uint8_t proto,
    uint16_t port, uint16_t portmax, boolean_t addflag)
{
	int retv;
	tsol_mlp_entry_t *tme, *tme2, *newent;

	if (addflag) {
		if ((newent = kmem_zalloc(sizeof (*newent), KM_NOSLEEP)) ==
		    NULL)
			return (ENOMEM);
	} else {
		newent = NULL;
	}
	rw_enter(&mlpl->mlpl_rwlock, RW_WRITER);

	/*
	 * First loop: find logical insertion point or overlap.  Table is kept
	 * in order of port number first, and then, within that, by protocol
	 * number.
	 */
	for (tme = mlpl->mlpl_first; tme != NULL; tme = tme->mlpe_next) {
		/* logically next (case 4) */
		if (tme->mlpe_mlp.mlp_port > port)
			break;
		/* if this is logically next or overlap, then stop (case 3) */
		if (tme->mlpe_mlp.mlp_port == port &&
		    tme->mlpe_mlp.mlp_ipp >= proto)
			break;
		/* earlier or same port sequence; check for overlap (case 2) */
		if (tme->mlpe_mlp.mlp_ipp == proto &&
		    tme->mlpe_mlp.mlp_port_upper >= port)
			break;
		/* otherwise, loop again (case 1) */
	}

	/* Second loop: scan ahead for overlap */
	for (tme2 = tme; tme2 != NULL; tme2 = tme2->mlpe_next) {
		/* check if entry follows; no overlap (case 8) */
		if (tme2->mlpe_mlp.mlp_port > portmax) {
			tme2 = NULL;
			break;
		}
		/* only exact protocol matches at this point (cases 5-7) */
		if (tme2->mlpe_mlp.mlp_ipp == proto)
			break;
	}

	retv = 0;
	if (addflag) {
		if (tme2 != NULL) {
			retv = EEXIST;
		} else {
			newent->mlpe_zoneid = zoneid;
			newent->mlpe_mlp.mlp_ipp = proto;
			newent->mlpe_mlp.mlp_port = port;
			newent->mlpe_mlp.mlp_port_upper = portmax;
			newent->mlpe_next = tme;
			if (tme == NULL) {
				tme2 = mlpl->mlpl_last;
				mlpl->mlpl_last = newent;
			} else {
				tme2 = tme->mlpe_prev;
				tme->mlpe_prev = newent;
			}
			newent->mlpe_prev = tme2;
			if (tme2 == NULL)
				mlpl->mlpl_first = newent;
			else
				tme2->mlpe_next = newent;
			newent = NULL;
		}
	} else {
		if (tme2 == NULL || tme2->mlpe_mlp.mlp_port != port ||
		    tme2->mlpe_mlp.mlp_port_upper != portmax) {
			retv = ENOENT;
		} else {
			if ((tme2 = tme->mlpe_prev) == NULL)
				mlpl->mlpl_first = tme->mlpe_next;
			else
				tme2->mlpe_next = tme->mlpe_next;
			if ((tme2 = tme->mlpe_next) == NULL)
				mlpl->mlpl_last = tme->mlpe_prev;
			else
				tme2->mlpe_prev = tme->mlpe_prev;
			newent = tme;
		}
	}
	rw_exit(&mlpl->mlpl_rwlock);

	if (newent != NULL)
		kmem_free(newent, sizeof (*newent));

	return (retv);
}

/*
 * Add or remove an MLP entry from the database so that the classifier can find
 * it.
 *
 * Note: port number is in host byte order.
 */
int
tsol_mlp_anon(zone_t *zone, mlp_type_t mlptype, uchar_t proto, uint16_t port,
    boolean_t addflag)
{
	int retv = 0;

	if (mlptype == mlptBoth || mlptype == mlptPrivate)
		retv = mlp_add_del(&zone->zone_mlps, zone->zone_id, proto,
		    port, port, addflag);
	if ((retv == 0 || !addflag) &&
	    (mlptype == mlptBoth || mlptype == mlptShared)) {
		retv = mlp_add_del(&shared_mlps, zone->zone_id, proto, port,
		    port, addflag);
		if (retv != 0 && addflag)
			(void) mlp_add_del(&zone->zone_mlps, zone->zone_id,
			    proto, port, port, B_FALSE);
	}
	return (retv);
}

static void
mlp_flush(tsol_mlp_list_t *mlpl, zoneid_t zoneid)
{
	tsol_mlp_entry_t *tme, *tme2, *tmnext;

	rw_enter(&mlpl->mlpl_rwlock, RW_WRITER);
	for (tme = mlpl->mlpl_first; tme != NULL; tme = tmnext) {
		tmnext = tme->mlpe_next;
		if (zoneid == ALL_ZONES || tme->mlpe_zoneid == zoneid) {
			if ((tme2 = tme->mlpe_prev) == NULL)
				mlpl->mlpl_first = tmnext;
			else
				tme2->mlpe_next = tmnext;
			if (tmnext == NULL)
				mlpl->mlpl_last = tme2;
			else
				tmnext->mlpe_prev = tme2;
			kmem_free(tme, sizeof (*tme));
		}
	}
	rw_exit(&mlpl->mlpl_rwlock);
}

/*
 * Note: user supplies port numbers in host byte order.
 */
static int
tnmlp(int cmd, void *buf)
{
	int retv;
	tsol_mlpent_t tsme;
	zone_t *zone;
	tsol_mlp_list_t *mlpl;
	tsol_mlp_entry_t *tme;

	/* Make sure user has sufficient privilege */
	if (cmd != TNDB_GET &&
	    (retv = secpolicy_net_config(CRED(), B_FALSE)) != 0)
		return (set_errno(retv));

	/*
	 * Get argument.  Note that tsol_mlpent_t is the same on LP64 and
	 * ILP32, so no special handling is required.
	 */
	if (copyin(buf, &tsme, sizeof (tsme)) != 0) {
		DTRACE_PROBE(tx__tndb__l0__tnmlp__copyin);
		return (set_errno(EFAULT));
	}

	/* MLPs on shared IP addresses */
	if (tsme.tsme_flags & TSOL_MEF_SHARED) {
		zone = NULL;
		mlpl = &shared_mlps;
	} else {
		zone = zone_find_by_id(tsme.tsme_zoneid);
		if (zone == NULL)
			return (set_errno(EINVAL));
		mlpl = &zone->zone_mlps;
	}
	if (tsme.tsme_mlp.mlp_port_upper == 0)
		tsme.tsme_mlp.mlp_port_upper = tsme.tsme_mlp.mlp_port;

	switch (cmd) {
	case TNDB_LOAD:
		DTRACE_PROBE1(tx__tndb__l2__tnmlp__tndbload,
		    tsol_mlpent_t *, &tsme);
		if (tsme.tsme_mlp.mlp_ipp == 0 || tsme.tsme_mlp.mlp_port == 0 ||
		    tsme.tsme_mlp.mlp_port > tsme.tsme_mlp.mlp_port_upper) {
			retv = EINVAL;
			break;
		}
		retv = mlp_add_del(mlpl, tsme.tsme_zoneid,
		    tsme.tsme_mlp.mlp_ipp, tsme.tsme_mlp.mlp_port,
		    tsme.tsme_mlp.mlp_port_upper, B_TRUE);
		break;

	case TNDB_GET:
		DTRACE_PROBE1(tx__tndb__l2__tnmlp__tndbget,
		    tsol_mlpent_t *, &tsme);

		/*
		 * Search for the requested element or, failing that, the one
		 * that's logically next in the sequence.
		 */
		rw_enter(&mlpl->mlpl_rwlock, RW_READER);
		for (tme = mlpl->mlpl_first; tme != NULL;
		    tme = tme->mlpe_next) {
			if (tsme.tsme_zoneid != ALL_ZONES &&
			    tme->mlpe_zoneid != tsme.tsme_zoneid)
				continue;
			if (tme->mlpe_mlp.mlp_ipp >= tsme.tsme_mlp.mlp_ipp &&
			    tme->mlpe_mlp.mlp_port == tsme.tsme_mlp.mlp_port)
				break;
			if (tme->mlpe_mlp.mlp_port > tsme.tsme_mlp.mlp_port)
				break;
		}
		if (tme == NULL) {
			retv = ENOENT;
		} else {
			tsme.tsme_zoneid = tme->mlpe_zoneid;
			tsme.tsme_mlp = tme->mlpe_mlp;
			retv = 0;
		}
		rw_exit(&mlpl->mlpl_rwlock);
		break;

	case TNDB_DELETE:
		DTRACE_PROBE1(tx__tndb__l4__tnmlp__tndbdelete,
		    tsol_mlpent_t *, &tsme);
		retv = mlp_add_del(mlpl, tsme.tsme_zoneid,
		    tsme.tsme_mlp.mlp_ipp, tsme.tsme_mlp.mlp_port,
		    tsme.tsme_mlp.mlp_port_upper, B_FALSE);
		break;

	case TNDB_FLUSH:
		DTRACE_PROBE1(tx__tndb__l4__tnmlp__tndbflush,
		    tsol_mlpent_t *, &tsme);
		mlp_flush(mlpl, ALL_ZONES);
		mlp_flush(&shared_mlps, tsme.tsme_zoneid);
		retv = 0;
		break;

	default:
		DTRACE_PROBE1(tx__tndb__l0__tnmlp__unknowncmd, int,
		    cmd);
		retv = EOPNOTSUPP;
		break;
	}

	if (zone != NULL)
		zone_rele(zone);

	if (cmd == TNDB_GET && retv == 0) {
		/* Copy out result */
		if (copyout(&tsme, buf, sizeof (tsme)) != 0) {
			DTRACE_PROBE(tx__tndb__l0__tnmlp__copyout);
			retv = EFAULT;
		}
	}

	if (retv != 0)
		return (set_errno(retv));
	else
		return (retv);
}

/*
 * Returns a tnrhc matching the addr address.
 * The returned rhc's refcnt is incremented.
 */
tsol_tnrhc_t *
find_rhc(const void *addr, uchar_t version, boolean_t staleok)
{
	tsol_tnrhc_t *rh = NULL;
	tsol_tnrhc_t *new;
	tsol_tpc_t *tpc;
	tnrhc_hash_t *tnrhc_hash;
	ipaddr_t tmpmask;
	in_addr_t *in4 = (in_addr_t *)addr;
	in6_addr_t *in6 = (in6_addr_t *)addr;
	in_addr_t tmpin4;
	in6_addr_t tmpmask6;
	int	i;
	int	prefix;

	/*
	 * An IPv4-mapped IPv6 address is really an IPv4 address
	 * in IPv6 format.
	 */
	if (version == IPV6_VERSION &&
	    IN6_IS_ADDR_V4MAPPED(in6)) {
		IN6_V4MAPPED_TO_IPADDR(in6, tmpin4);
		version = IPV4_VERSION;
		in4 = &tmpin4;
	}

	/*
	 * Search the tnrh hash table for each prefix length,
	 * starting at longest prefix length, until a matching
	 * rhc entry is found.
	 */
	if (version == IPV4_VERSION) {
		for (i = (TSOL_MASK_TABLE_SIZE - 1); i >= 0; i--) {

			if ((tnrhc_table[i]) == NULL)
				continue;

			tmpmask = tsol_plen_to_mask(i);
			tnrhc_hash = &tnrhc_table[i][
			    TSOL_ADDR_HASH(*in4 & tmpmask, TNRHC_SIZE)];

			mutex_enter(&tnrhc_hash->tnrh_lock);
			for (rh = tnrhc_hash->tnrh_list; rh != NULL;
			    rh = rh->rhc_next) {
				if ((rh->rhc_host.ta_family == AF_INET) &&
				    ((rh->rhc_host.ta_addr_v4.s_addr &
				    tmpmask) == (*in4 & tmpmask))) {
					prefix = i;
					TNRHC_HOLD(rh);
					break;
				}
			}
			mutex_exit(&tnrhc_hash->tnrh_lock);
			if (rh != NULL)
				break;
		}
		if (rh == NULL)
			DTRACE_PROBE1(tx__tndb__l1__findrhc__norhv4ent,
			    in_addr_t *, in4);
	} else {
		for (i = (TSOL_MASK_TABLE_SIZE_V6 - 1); i >= 0; i--) {
			if ((tnrhc_table_v6[i]) == NULL)
				continue;

			tsol_plen_to_mask_v6(i, &tmpmask6);
			tnrhc_hash = &tnrhc_table_v6[i][
			    TSOL_ADDR_MASK_HASH_V6(*in6, tmpmask6, TNRHC_SIZE)];

			mutex_enter(&tnrhc_hash->tnrh_lock);
			for (rh = tnrhc_hash->tnrh_list; rh != NULL;
			    rh = rh->rhc_next) {
				if ((rh->rhc_host.ta_family == AF_INET6) &&
				    V6_MASK_EQ_2(rh->rhc_host.ta_addr_v6,
				    tmpmask6, *in6)) {
					prefix = i;
					TNRHC_HOLD(rh);
					break;
				}
			}
			mutex_exit(&tnrhc_hash->tnrh_lock);
			if (rh != NULL)
				break;
		}
		if (rh == NULL)
			DTRACE_PROBE1(tx__tndb__l1__findrhc__norhv6ent,
			    in6_addr_t *, in6);
	}

	/*
	 * Does the tnrh entry point to a stale template?
	 * This can happen any time the user deletes or modifies
	 * a template that has existing tnrh entries pointing
	 * to it. Try to find a new version of the template.
	 * If there is no template, then just give up.
	 * If the template exists, reload the tnrh entry.
	 */
	if (rh != NULL && rh->rhc_tpc->tpc_invalid) {
		tpc = tnrhtp_find(rh->rhc_tpc->tpc_tp.name, tpc_name_hash);
		if (tpc == NULL) {
			if (!staleok) {
				DTRACE_PROBE2(tx__tndb__l1__findrhc__staletpc,
				    tsol_tnrhc_t *, rh, tsol_tpc_t *,
				    rh->rhc_tpc);
				TNRHC_RELE(rh);
				rh = NULL;
			}
		} else {
			ASSERT(tpc->tpc_tp.host_type == UNLABELED ||
			    tpc->tpc_tp.host_type == SUN_CIPSO);

			if ((new = kmem_zalloc(sizeof (*new),
			    KM_NOSLEEP)) == NULL) {
				DTRACE_PROBE(tx__tndb__l1__findrhc__nomem);
				TNRHC_RELE(rh);
				TPC_RELE(tpc);
				return (NULL);
			}

			mutex_init(&new->rhc_lock, NULL, MUTEX_DEFAULT, NULL);
			new->rhc_host = rh->rhc_host;
			new->rhc_tpc = tpc;
			new->rhc_isbcast = rh->rhc_isbcast;
			new->rhc_local = rh->rhc_local;
			TNRHC_RELE(rh);
			rh = new;

			/*
			 * This function increments the tnrh entry ref count
			 * for the pointer returned to the caller.
			 * tnrh_hash_add increments the tnrh entry ref count
			 * for the pointer in the hash table.
			 */
			TNRHC_HOLD(rh);
			if (tnrh_hash_add(new, prefix) != 0) {
				TNRHC_RELE(rh);
				rh = NULL;
			}
		}
	}
	return (rh);
}

tsol_tpc_t *
find_tpc(const void *addr, uchar_t version, boolean_t staleok)
{
	tsol_tpc_t *tpc;
	tsol_tnrhc_t *rhc;

	if ((rhc = find_rhc(addr, version, staleok)) == NULL)
		return (NULL);

	tpc = rhc->rhc_tpc;
	TPC_HOLD(tpc);
	TNRHC_RELE(rhc);
	return (tpc);
}

/*
 * create an internal template called "_unlab":
 *
 * _unlab;\
 *	host_type = unlabeled;\
 *	def_label = ADMIN_LOW[ADMIN_LOW];\
 *	min_sl = ADMIN_LOW;\
 *	max_sl = ADMIN_HIGH;
 */
static void
tsol_create_i_tmpls(void)
{
	tsol_tpent_t rhtpent;

	bzero(&rhtpent, sizeof (rhtpent));

	/* create _unlab */
	(void) strcpy(rhtpent.name, "_unlab");

	rhtpent.host_type = UNLABELED;
	rhtpent.tp_mask_unl = TSOL_MSK_DEF_LABEL | TSOL_MSK_DEF_CL |
	    TSOL_MSK_SL_RANGE_TSOL;

	rhtpent.tp_gw_sl_range.lower_bound = *label2bslabel(l_admin_low);
	rhtpent.tp_def_label = rhtpent.tp_gw_sl_range.lower_bound;
	rhtpent.tp_gw_sl_range.upper_bound = *label2bslabel(l_admin_high);
	rhtpent.tp_cipso_doi_unl = default_doi;
	tpc_unlab = tnrhtp_create(&rhtpent, KM_SLEEP);
}

/*
 * set up internal host template, called from kernel only.
 */
static void
tsol_create_i_tnrh(const tnaddr_t *sa)
{
	tsol_tnrhc_t *rh, *new;
	tnrhc_hash_t *tnrhc_hash;

	/* Allocate a new entry before taking the lock */
	new = kmem_zalloc(sizeof (*new), KM_SLEEP);

	tnrhc_hash = (sa->ta_family == AF_INET) ? &tnrhc_table[0][0] :
	    &tnrhc_table_v6[0][0];

	mutex_enter(&tnrhc_hash->tnrh_lock);
	rh = tnrhc_hash->tnrh_list;

	if (rh == NULL) {
		/* We're keeping the new entry. */
		rh = new;
		new = NULL;
		rh->rhc_host = *sa;
		mutex_init(&rh->rhc_lock, NULL, MUTEX_DEFAULT, NULL);
		TNRHC_HOLD(rh);
		tnrhc_hash->tnrh_list = rh;
	}

	/*
	 * Link the entry to internal_unlab
	 */
	if (rh->rhc_tpc != tpc_unlab) {
		if (rh->rhc_tpc != NULL)
			TPC_RELE(rh->rhc_tpc);
		rh->rhc_tpc = tpc_unlab;
		TPC_HOLD(tpc_unlab);
	}
	mutex_exit(&tnrhc_hash->tnrh_lock);
	if (new != NULL)
		kmem_free(new, sizeof (*new));
}

/*
 * Returns 0 if the port is known to be SLP.  Returns next possible port number
 * (wrapping through 1) if port is MLP on shared or global.  Administrator
 * should not make all ports MLP.  If that's done, then we'll just pretend
 * everything is SLP to avoid looping forever.
 *
 * Note: port is in host byte order.
 */
in_port_t
tsol_next_port(zone_t *zone, in_port_t port, int proto, boolean_t upward)
{
	boolean_t loop;
	tsol_mlp_entry_t *tme;
	int newport = port;

	loop = B_FALSE;
	for (;;) {
		if (zone != NULL && zone->zone_mlps.mlpl_first != NULL) {
			rw_enter(&zone->zone_mlps.mlpl_rwlock, RW_READER);
			for (tme = zone->zone_mlps.mlpl_first; tme != NULL;
			    tme = tme->mlpe_next) {
				if (proto == tme->mlpe_mlp.mlp_ipp &&
				    newport >= tme->mlpe_mlp.mlp_port &&
				    newport <= tme->mlpe_mlp.mlp_port_upper)
					newport = upward ?
					    tme->mlpe_mlp.mlp_port_upper + 1 :
					    tme->mlpe_mlp.mlp_port - 1;
			}
			rw_exit(&zone->zone_mlps.mlpl_rwlock);
		}
		if (shared_mlps.mlpl_first != NULL) {
			rw_enter(&shared_mlps.mlpl_rwlock, RW_READER);
			for (tme = shared_mlps.mlpl_first; tme != NULL;
			    tme = tme->mlpe_next) {
				if (proto == tme->mlpe_mlp.mlp_ipp &&
				    newport >= tme->mlpe_mlp.mlp_port &&
				    newport <= tme->mlpe_mlp.mlp_port_upper)
					newport = upward ?
					    tme->mlpe_mlp.mlp_port_upper + 1 :
					    tme->mlpe_mlp.mlp_port - 1;
			}
			rw_exit(&shared_mlps.mlpl_rwlock);
		}
		if (newport <= 65535 && newport > 0)
			break;
		if (loop)
			return (0);
		loop = B_TRUE;
		newport = upward ? 1 : 65535;
	}
	return (newport == port ? 0 : newport);
}

/*
 * tsol_mlp_port_type will check if the given (zone, proto, port) is a
 * multilevel port.  If it is, return the type (shared, private, or both), or
 * indicate that it's single-level.
 *
 * Note: port is given in host byte order, not network byte order.
 */
mlp_type_t
tsol_mlp_port_type(zone_t *zone, uchar_t proto, uint16_t port,
    mlp_type_t mlptype)
{
	tsol_mlp_entry_t *tme;

	if (mlptype == mlptBoth || mlptype == mlptPrivate) {
		tme = NULL;
		if (zone->zone_mlps.mlpl_first != NULL) {
			rw_enter(&zone->zone_mlps.mlpl_rwlock, RW_READER);
			for (tme = zone->zone_mlps.mlpl_first; tme != NULL;
			    tme = tme->mlpe_next) {
				if (proto == tme->mlpe_mlp.mlp_ipp &&
				    port >= tme->mlpe_mlp.mlp_port &&
				    port <= tme->mlpe_mlp.mlp_port_upper)
					break;
			}
			rw_exit(&zone->zone_mlps.mlpl_rwlock);
		}
		if (tme == NULL) {
			if (mlptype == mlptBoth)
				mlptype = mlptShared;
			else if (mlptype == mlptPrivate)
				mlptype = mlptSingle;
		}
	}
	if (mlptype == mlptBoth || mlptype == mlptShared) {
		tme = NULL;
		if (shared_mlps.mlpl_first != NULL) {
			rw_enter(&shared_mlps.mlpl_rwlock, RW_READER);
			for (tme = shared_mlps.mlpl_first; tme != NULL;
			    tme = tme->mlpe_next) {
				if (proto == tme->mlpe_mlp.mlp_ipp &&
				    port >= tme->mlpe_mlp.mlp_port &&
				    port <= tme->mlpe_mlp.mlp_port_upper)
					break;
			}
			rw_exit(&shared_mlps.mlpl_rwlock);
		}
		if (tme == NULL) {
			if (mlptype == mlptBoth)
				mlptype = mlptPrivate;
			else if (mlptype == mlptShared)
				mlptype = mlptSingle;
		}
	}
	return (mlptype);
}

/*
 * tsol_mlp_findzone will check if the given (proto, port) is a multilevel port
 * on a shared address.  If it is, return the owning zone.
 *
 * Note: lport is in network byte order, unlike the other MLP functions,
 * because the callers of this function are all dealing with packets off the
 * wire.
 */
zoneid_t
tsol_mlp_findzone(uchar_t proto, uint16_t lport)
{
	tsol_mlp_entry_t *tme;
	zoneid_t zoneid;
	uint16_t port;

	if (shared_mlps.mlpl_first == NULL)
		return (ALL_ZONES);
	port = ntohs(lport);
	rw_enter(&shared_mlps.mlpl_rwlock, RW_READER);
	for (tme = shared_mlps.mlpl_first; tme != NULL; tme = tme->mlpe_next) {
		if (proto == tme->mlpe_mlp.mlp_ipp &&
		    port >= tme->mlpe_mlp.mlp_port &&
		    port <= tme->mlpe_mlp.mlp_port_upper)
			break;
	}
	zoneid = tme == NULL ? ALL_ZONES : tme->mlpe_zoneid;
	rw_exit(&shared_mlps.mlpl_rwlock);
	return (zoneid);
}

/* Debug routine */
void
tsol_print_label(const blevel_t *blev, const char *name)
{
	const _blevel_impl_t *bli = (const _blevel_impl_t *)blev;

	/* We really support only sensitivity labels */
	cmn_err(CE_NOTE, "%s %x:%x:%08x%08x%08x%08x%08x%08x%08x%08x",
	    name, bli->id, LCLASS(bli), ntohl(bli->_comps.c1),
	    ntohl(bli->_comps.c2), ntohl(bli->_comps.c3), ntohl(bli->_comps.c4),
	    ntohl(bli->_comps.c5), ntohl(bli->_comps.c6), ntohl(bli->_comps.c7),
	    ntohl(bli->_comps.c8));
}

/*
 * Name:	labelsys()
 *
 * Normal:	Routes TSOL syscalls.
 *
 * Output:	As defined for each TSOL syscall.
 *		Returns ENOSYS for unrecognized calls.
 */
/* ARGSUSED */
int
labelsys(int op, void *a1, void *a2, void *a3, void *a4, void *a5)
{
	switch (op) {
	case TSOL_SYSLABELING:
		return (sys_labeling);
	case TSOL_TNRH:
		return (tnrh((int)(uintptr_t)a1, a2));
	case TSOL_TNRHTP:
		return (tnrhtp((int)(uintptr_t)a1, a2));
	case TSOL_TNMLP:
		return (tnmlp((int)(uintptr_t)a1, a2));
	case TSOL_GETLABEL:
		return (getlabel((char *)a1, (bslabel_t *)a2));
	case TSOL_FGETLABEL:
		return (fgetlabel((int)(uintptr_t)a1, (bslabel_t *)a2));
	default:
		return (set_errno(ENOSYS));
	}
	/* NOTREACHED */
}
