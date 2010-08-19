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
 *
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_multi.h>
#include <inet/ip_ndp.h>
#include <inet/ip_rts.h>
#include <inet/mi.h>
#include <net/if_types.h>
#include <sys/dlpi.h>
#include <sys/kmem.h>
#include <sys/modhash.h>
#include <sys/sdt.h>
#include <sys/strsun.h>
#include <sys/sunddi.h>
#include <sys/types.h>

/*
 * Convenience macros for getting the ip_stack_t associated with an
 * ipmp_illgrp_t or ipmp_grp_t.
 */
#define	IPMP_GRP_TO_IPST(grp)		PHYINT_TO_IPST((grp)->gr_phyint)
#define	IPMP_ILLGRP_TO_IPST(illg)	((illg)->ig_ipmp_ill->ill_ipst)

/*
 * Assorted constants that aren't important enough to be tunable.
 */
#define	IPMP_GRP_HASH_SIZE		64
#define	IPMP_ILL_REFRESH_TIMEOUT	120	/* seconds */

/*
 * IPMP meta-interface kstats (based on those in PSARC/1997/198).
 */
static const kstat_named_t ipmp_kstats[IPMP_KSTAT_MAX] = {
	{ "obytes",	KSTAT_DATA_UINT32 },
	{ "obytes64",	KSTAT_DATA_UINT64 },
	{ "rbytes",	KSTAT_DATA_UINT32 },
	{ "rbytes64",	KSTAT_DATA_UINT64 },
	{ "opackets",	KSTAT_DATA_UINT32 },
	{ "opackets64",	KSTAT_DATA_UINT64 },
	{ "oerrors",	KSTAT_DATA_UINT32 },
	{ "ipackets",	KSTAT_DATA_UINT32 },
	{ "ipackets64",	KSTAT_DATA_UINT64 },
	{ "ierrors",	KSTAT_DATA_UINT32 },
	{ "multircv",	KSTAT_DATA_UINT32 },
	{ "multixmt",	KSTAT_DATA_UINT32 },
	{ "brdcstrcv",	KSTAT_DATA_UINT32 },
	{ "brdcstxmt",	KSTAT_DATA_UINT32 },
	{ "link_up",	KSTAT_DATA_UINT32 }
};

static void	ipmp_grp_insert(ipmp_grp_t *, mod_hash_hndl_t);
static int	ipmp_grp_create_kstats(ipmp_grp_t *);
static int	ipmp_grp_update_kstats(kstat_t *, int);
static void	ipmp_grp_destroy_kstats(ipmp_grp_t *);
static ill_t	*ipmp_illgrp_min_ill(ipmp_illgrp_t *);
static ill_t	*ipmp_illgrp_max_ill(ipmp_illgrp_t *);
static void	ipmp_illgrp_set_cast(ipmp_illgrp_t *, ill_t *);
static void	ipmp_illgrp_set_mtu(ipmp_illgrp_t *, uint_t, uint_t);
static boolean_t ipmp_ill_activate(ill_t *);
static void	ipmp_ill_deactivate(ill_t *);
static void	ipmp_ill_ire_mark_testhidden(ire_t *, char *);
static void	ipmp_ill_ire_clear_testhidden(ire_t *, char *);
static void	ipmp_ill_refresh_active_timer_start(ill_t *);
static void	ipmp_ill_rtsaddrmsg(ill_t *, int);
static void	ipmp_ill_bind_ipif(ill_t *, ipif_t *, enum ip_resolver_action);
static ipif_t	*ipmp_ill_unbind_ipif(ill_t *, ipif_t *, boolean_t);
static void	ipmp_phyint_get_kstats(phyint_t *, uint64_t *);
static boolean_t ipmp_ipif_is_up_dataaddr(const ipif_t *);
static void	ipmp_ncec_delete_nonlocal(ncec_t *, uchar_t *);

/*
 * Initialize IPMP state for IP stack `ipst'; called from ip_stack_init().
 */
void
ipmp_init(ip_stack_t *ipst)
{
	ipst->ips_ipmp_grp_hash = mod_hash_create_extended("ipmp_grp_hash",
	    IPMP_GRP_HASH_SIZE, mod_hash_null_keydtor, mod_hash_null_valdtor,
	    mod_hash_bystr, NULL, mod_hash_strkey_cmp, KM_SLEEP);
	rw_init(&ipst->ips_ipmp_lock, NULL, RW_DEFAULT, 0);
}

/*
 * Destroy IPMP state for IP stack `ipst'; called from ip_stack_fini().
 */
void
ipmp_destroy(ip_stack_t *ipst)
{
	mod_hash_destroy_hash(ipst->ips_ipmp_grp_hash);
	rw_destroy(&ipst->ips_ipmp_lock);
}

/*
 * Create an IPMP group named `grname', associate it with IPMP phyint `phyi',
 * and add it to the hash.  On success, return a pointer to the created group.
 * Caller must ensure `grname' is not yet in the hash.  Assumes that the IPMP
 * meta-interface associated with the group also has the same name (but they
 * may differ later via ipmp_grp_rename()).
 */
ipmp_grp_t *
ipmp_grp_create(const char *grname, phyint_t *phyi)
{
	ipmp_grp_t *grp;
	ip_stack_t *ipst = PHYINT_TO_IPST(phyi);
	mod_hash_hndl_t mh;

	ASSERT(RW_WRITE_HELD(&ipst->ips_ipmp_lock));

	if ((grp = kmem_zalloc(sizeof (ipmp_grp_t), KM_NOSLEEP)) == NULL)
		return (NULL);

	(void) strlcpy(grp->gr_name, grname, sizeof (grp->gr_name));
	(void) strlcpy(grp->gr_ifname, grname, sizeof (grp->gr_ifname));

	/*
	 * Cache the group's phyint.  This is safe since a phyint_t will
	 * outlive its ipmp_grp_t.
	 */
	grp->gr_phyint = phyi;

	/*
	 * Create IPMP group kstats.
	 */
	if (ipmp_grp_create_kstats(grp) != 0) {
		kmem_free(grp, sizeof (ipmp_grp_t));
		return (NULL);
	}

	/*
	 * Insert the group into the hash.
	 */
	if (mod_hash_reserve_nosleep(ipst->ips_ipmp_grp_hash, &mh) != 0) {
		ipmp_grp_destroy_kstats(grp);
		kmem_free(grp, sizeof (ipmp_grp_t));
		return (NULL);
	}
	ipmp_grp_insert(grp, mh);

	return (grp);
}

/*
 * Create IPMP kstat structures for `grp'.  Return an errno upon failure.
 */
static int
ipmp_grp_create_kstats(ipmp_grp_t *grp)
{
	kstat_t *ksp;
	netstackid_t id = IPMP_GRP_TO_IPST(grp)->ips_netstack->netstack_stackid;

	ksp = kstat_create_netstack("ipmp", 0, grp->gr_ifname, "net",
	    KSTAT_TYPE_NAMED, IPMP_KSTAT_MAX, 0, id);
	if (ksp == NULL)
		return (ENOMEM);

	ksp->ks_update = ipmp_grp_update_kstats;
	ksp->ks_private = grp;
	bcopy(ipmp_kstats, ksp->ks_data, sizeof (ipmp_kstats));

	kstat_install(ksp);
	grp->gr_ksp = ksp;
	return (0);
}

/*
 * Update the IPMP kstats tracked by `ksp'; called by the kstats framework.
 */
static int
ipmp_grp_update_kstats(kstat_t *ksp, int rw)
{
	uint_t		i;
	kstat_named_t	*kn = KSTAT_NAMED_PTR(ksp);
	ipmp_grp_t	*grp = ksp->ks_private;
	ip_stack_t	*ipst = IPMP_GRP_TO_IPST(grp);
	ipsq_t		*ipsq, *grp_ipsq = grp->gr_phyint->phyint_ipsq;
	phyint_t	*phyi;
	uint64_t	phyi_kstats[IPMP_KSTAT_MAX];

	if (rw == KSTAT_WRITE)
		return (EACCES);

	/*
	 * Start with the group's baseline values.
	 */
	for (i = 0; i < IPMP_KSTAT_MAX; i++) {
		if (kn[i].data_type == KSTAT_DATA_UINT32) {
			kn[i].value.ui32 = grp->gr_kstats0[i];
		} else {
			ASSERT(kn[i].data_type == KSTAT_DATA_UINT64);
			kn[i].value.ui64 = grp->gr_kstats0[i];
		}
	}

	/*
	 * Add in the stats of each phyint currently in the group.  Since we
	 * don't directly track the phyints in a group, we cheat by walking
	 * the IPSQ set under ill_g_lock.  (The IPSQ list cannot change while
	 * ill_g_lock is held.)
	 */
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ipsq = grp_ipsq->ipsq_next;
	for (; ipsq != grp_ipsq; ipsq = ipsq->ipsq_next) {
		phyi = ipsq->ipsq_phyint;

		/*
		 * If a phyint in a group is being unplumbed, it's possible
		 * that ill_glist_delete() -> phyint_free() already freed the
		 * phyint (and set ipsq_phyint to NULL), but the unplumb
		 * operation has yet to complete (and thus ipsq_dq() has yet
		 * to remove the phyint's IPSQ from the group IPSQ's phyint
		 * list).  We skip those phyints here (note that their kstats
		 * have already been added to gr_kstats0[]).
		 */
		if (phyi == NULL)
			continue;

		ipmp_phyint_get_kstats(phyi, phyi_kstats);

		for (i = 0; i < IPMP_KSTAT_MAX; i++) {
			phyi_kstats[i] -= phyi->phyint_kstats0[i];
			if (kn[i].data_type == KSTAT_DATA_UINT32)
				kn[i].value.ui32 += phyi_kstats[i];
			else
				kn[i].value.ui64 += phyi_kstats[i];
		}
	}

	kn[IPMP_KSTAT_LINK_UP].value.ui32 =
	    (grp->gr_phyint->phyint_flags & PHYI_RUNNING) != 0;

	rw_exit(&ipst->ips_ill_g_lock);
	return (0);
}

/*
 * Destroy IPMP kstat structures for `grp'.
 */
static void
ipmp_grp_destroy_kstats(ipmp_grp_t *grp)
{
	netstackid_t id = IPMP_GRP_TO_IPST(grp)->ips_netstack->netstack_stackid;

	kstat_delete_netstack(grp->gr_ksp, id);
	bzero(grp->gr_kstats0, sizeof (grp->gr_kstats0));
	grp->gr_ksp = NULL;
}

/*
 * Look up an IPMP group named `grname' on IP stack `ipst'.  Return NULL if it
 * does not exist.
 */
ipmp_grp_t *
ipmp_grp_lookup(const char *grname, ip_stack_t *ipst)
{
	ipmp_grp_t *grp;

	ASSERT(RW_LOCK_HELD(&ipst->ips_ipmp_lock));

	if (mod_hash_find(ipst->ips_ipmp_grp_hash, (mod_hash_key_t)grname,
	    (mod_hash_val_t *)&grp) == 0)
		return (grp);

	return (NULL);
}

/*
 * Place information about group `grp' into `lifgr'.
 */
void
ipmp_grp_info(const ipmp_grp_t *grp, lifgroupinfo_t *lifgr)
{
	ill_t *ill;
	ip_stack_t *ipst = IPMP_GRP_TO_IPST(grp);

	ASSERT(RW_LOCK_HELD(&ipst->ips_ipmp_lock));

	lifgr->gi_v4 = (grp->gr_v4 != NULL);
	lifgr->gi_v6 = (grp->gr_v6 != NULL);
	lifgr->gi_nv4 = grp->gr_nv4 + grp->gr_pendv4;
	lifgr->gi_nv6 = grp->gr_nv6 + grp->gr_pendv6;
	lifgr->gi_mactype = grp->gr_nif > 0 ? grp->gr_mactype : SUNW_DL_IPMP;
	(void) strlcpy(lifgr->gi_grifname, grp->gr_ifname, LIFNAMSIZ);
	lifgr->gi_m4ifname[0] = '\0';
	lifgr->gi_m6ifname[0] = '\0';
	lifgr->gi_bcifname[0] = '\0';

	if (grp->gr_v4 != NULL && (ill = grp->gr_v4->ig_cast_ill) != NULL) {
		(void) strlcpy(lifgr->gi_m4ifname, ill->ill_name, LIFNAMSIZ);
		(void) strlcpy(lifgr->gi_bcifname, ill->ill_name, LIFNAMSIZ);
	}

	if (grp->gr_v6 != NULL && (ill = grp->gr_v6->ig_cast_ill) != NULL)
		(void) strlcpy(lifgr->gi_m6ifname, ill->ill_name, LIFNAMSIZ);
}

/*
 * Insert `grp' into the hash using the reserved hash entry `mh'.
 * Caller must ensure `grp' is not yet in the hash.
 */
static void
ipmp_grp_insert(ipmp_grp_t *grp, mod_hash_hndl_t mh)
{
	int err;
	ip_stack_t *ipst = IPMP_GRP_TO_IPST(grp);

	ASSERT(RW_WRITE_HELD(&ipst->ips_ipmp_lock));

	/*
	 * Since grp->gr_name will exist at least as long as `grp' is in the
	 * hash, we use it directly as the key.
	 */
	err = mod_hash_insert_reserve(ipst->ips_ipmp_grp_hash,
	    (mod_hash_key_t)grp->gr_name, (mod_hash_val_t)grp, mh);
	if (err != 0) {
		/*
		 * This should never happen since `mh' was preallocated.
		 */
		panic("cannot insert IPMP group \"%s\" (err %d)",
		    grp->gr_name, err);
	}
}

/*
 * Remove `grp' from the hash.  Caller must ensure `grp' is in it.
 */
static void
ipmp_grp_remove(ipmp_grp_t *grp)
{
	int err;
	mod_hash_val_t val;
	mod_hash_key_t key = (mod_hash_key_t)grp->gr_name;
	ip_stack_t *ipst = IPMP_GRP_TO_IPST(grp);

	ASSERT(RW_WRITE_HELD(&ipst->ips_ipmp_lock));

	err = mod_hash_remove(ipst->ips_ipmp_grp_hash, key, &val);
	if (err != 0 || val != grp) {
		panic("cannot remove IPMP group \"%s\" (err %d)",
		    grp->gr_name, err);
	}
}

/*
 * Attempt to rename `grp' to new name `grname'.  Return an errno if the new
 * group name already exists or is invalid, or if there isn't enough memory.
 */
int
ipmp_grp_rename(ipmp_grp_t *grp, const char *grname)
{
	mod_hash_hndl_t mh;
	ip_stack_t *ipst = IPMP_GRP_TO_IPST(grp);

	ASSERT(RW_WRITE_HELD(&ipst->ips_ipmp_lock));

	if (grname[0] == '\0')
		return (EINVAL);

	if (mod_hash_find(ipst->ips_ipmp_grp_hash, (mod_hash_key_t)grname,
	    (mod_hash_val_t *)&grp) != MH_ERR_NOTFOUND)
		return (EEXIST);

	/*
	 * Before we remove the group from the hash, ensure we'll be able to
	 * re-insert it by reserving space.
	 */
	if (mod_hash_reserve_nosleep(ipst->ips_ipmp_grp_hash, &mh) != 0)
		return (ENOMEM);

	ipmp_grp_remove(grp);
	(void) strlcpy(grp->gr_name, grname, sizeof (grp->gr_name));
	ipmp_grp_insert(grp, mh);

	return (0);
}

/*
 * Destroy `grp' and remove it from the hash.  Caller must ensure `grp' is in
 * the hash, and that there are no interfaces on it.
 */
void
ipmp_grp_destroy(ipmp_grp_t *grp)
{
	ip_stack_t *ipst = IPMP_GRP_TO_IPST(grp);

	ASSERT(RW_WRITE_HELD(&ipst->ips_ipmp_lock));

	/*
	 * If there are still interfaces using this group, panic before things
	 * go really off the rails.
	 */
	if (grp->gr_nif != 0)
		panic("cannot destroy IPMP group \"%s\": in use", grp->gr_name);

	ipmp_grp_remove(grp);
	ipmp_grp_destroy_kstats(grp);

	ASSERT(grp->gr_v4 == NULL);
	ASSERT(grp->gr_v6 == NULL);
	ASSERT(grp->gr_nv4 == 0);
	ASSERT(grp->gr_nv6 == 0);
	ASSERT(grp->gr_nactif == 0);
	ASSERT(grp->gr_linkdownmp == NULL);
	grp->gr_phyint = NULL;

	kmem_free(grp, sizeof (ipmp_grp_t));
}

/*
 * Check whether `ill' is suitable for inclusion into `grp', and return an
 * errno describing the problem (if any).  NOTE: many of these errno values
 * are interpreted by ifconfig, which will take corrective action and retry
 * the SIOCSLIFGROUPNAME, so please exercise care when changing them.
 */
static int
ipmp_grp_vet_ill(ipmp_grp_t *grp, ill_t *ill)
{
	ip_stack_t *ipst = IPMP_GRP_TO_IPST(grp);

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(RW_LOCK_HELD(&ipst->ips_ipmp_lock));

	/*
	 * To sidestep complicated address migration logic in the kernel and
	 * to force the kernel's all-hosts multicast memberships to be blown
	 * away, all addresses that had been brought up must be brought back
	 * down prior to adding an interface to a group.  (This includes
	 * addresses currently down due to DAD.)  Once the interface has been
	 * added to the group, its addresses can then be brought back up, at
	 * which point they will be moved to the IPMP meta-interface.
	 * NOTE: we do this before ill_appaddr_cnt() since bringing down the
	 * link-local causes in.ndpd to remove its ADDRCONF'd addresses.
	 */
	if (ill->ill_ipif_up_count + ill->ill_ipif_dup_count > 0)
		return (EADDRINUSE);

	/*
	 * To avoid confusing applications by changing addresses that are
	 * under their control, all such control must be removed prior to
	 * adding an interface into a group.
	 */
	if (ill_appaddr_cnt(ill) != 0)
		return (EADDRNOTAVAIL);

	/*
	 * Since PTP addresses do not share the same broadcast domain, they
	 * are not allowed to be in an IPMP group.
	 */
	if (ill_ptpaddr_cnt(ill) != 0)
		return (EINVAL);

	/*
	 * An ill must support multicast to be allowed into a group.
	 */
	if (!(ill->ill_flags & ILLF_MULTICAST))
		return (ENOTSUP);

	/*
	 * An ill must strictly be using ARP and/or ND for address
	 * resolution for it to be allowed into a group.
	 */
	if (ill->ill_flags & (ILLF_NONUD | ILLF_NOARP))
		return (ENOTSUP);

	/*
	 * An ill cannot also be using usesrc groups.  (Although usesrc uses
	 * ill_g_usesrc_lock, we don't need to grab it since usesrc also does
	 * all its modifications as writer.)
	 */
	if (IS_USESRC_ILL(ill) || IS_USESRC_CLI_ILL(ill))
		return (ENOTSUP);

	/*
	 * All ills in a group must be the same mactype.
	 */
	if (grp->gr_nif > 0 && grp->gr_mactype != ill->ill_mactype)
		return (EINVAL);

	return (0);
}

/*
 * Check whether `phyi' is suitable for inclusion into `grp', and return an
 * errno describing the problem (if any).  See comment above ipmp_grp_vet_ill()
 * regarding errno values.
 */
int
ipmp_grp_vet_phyint(ipmp_grp_t *grp, phyint_t *phyi)
{
	int err = 0;
	ip_stack_t *ipst = IPMP_GRP_TO_IPST(grp);

	ASSERT(IAM_WRITER_IPSQ(phyi->phyint_ipsq));
	ASSERT(RW_LOCK_HELD(&ipst->ips_ipmp_lock));

	/*
	 * An interface cannot have address families plumbed that are not
	 * configured in the group.
	 */
	if (phyi->phyint_illv4 != NULL && grp->gr_v4 == NULL ||
	    phyi->phyint_illv6 != NULL && grp->gr_v6 == NULL)
		return (EAFNOSUPPORT);

	if (phyi->phyint_illv4 != NULL)
		err = ipmp_grp_vet_ill(grp, phyi->phyint_illv4);
	if (err == 0 && phyi->phyint_illv6 != NULL)
		err = ipmp_grp_vet_ill(grp, phyi->phyint_illv6);

	return (err);
}

/*
 * Create a new illgrp on IPMP meta-interface `ill'.
 */
ipmp_illgrp_t *
ipmp_illgrp_create(ill_t *ill)
{
	uint_t mtu = ill->ill_isv6 ? IPV6_MIN_MTU : IP_MIN_MTU;
	ipmp_illgrp_t *illg;

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(IS_IPMP(ill));
	ASSERT(ill->ill_grp == NULL);

	if ((illg = kmem_zalloc(sizeof (ipmp_illgrp_t), KM_NOSLEEP)) == NULL)
		return (NULL);

	list_create(&illg->ig_if, sizeof (ill_t), offsetof(ill_t, ill_grpnode));
	list_create(&illg->ig_actif, sizeof (ill_t),
	    offsetof(ill_t, ill_actnode));
	list_create(&illg->ig_arpent, sizeof (ipmp_arpent_t),
	    offsetof(ipmp_arpent_t, ia_node));

	illg->ig_ipmp_ill = ill;
	ill->ill_grp = illg;
	ipmp_illgrp_set_mtu(illg, mtu, mtu);

	return (illg);
}

/*
 * Destroy illgrp `illg', and disconnect it from its IPMP meta-interface.
 */
void
ipmp_illgrp_destroy(ipmp_illgrp_t *illg)
{
	ASSERT(IAM_WRITER_ILL(illg->ig_ipmp_ill));
	ASSERT(IS_IPMP(illg->ig_ipmp_ill));

	/*
	 * Verify `illg' is empty.
	 */
	ASSERT(illg->ig_next_ill == NULL);
	ASSERT(illg->ig_cast_ill == NULL);
	ASSERT(list_is_empty(&illg->ig_arpent));
	ASSERT(list_is_empty(&illg->ig_if));
	ASSERT(list_is_empty(&illg->ig_actif));
	ASSERT(illg->ig_nactif == 0);

	/*
	 * Destroy `illg'.
	 */
	illg->ig_ipmp_ill->ill_grp = NULL;
	illg->ig_ipmp_ill = NULL;
	list_destroy(&illg->ig_if);
	list_destroy(&illg->ig_actif);
	list_destroy(&illg->ig_arpent);
	kmem_free(illg, sizeof (ipmp_illgrp_t));
}

/*
 * Add `ipif' to the pool of usable data addresses on `illg' and attempt to
 * bind it to an underlying ill, while keeping an even address distribution.
 * If the bind is successful, return a pointer to the bound ill.
 */
ill_t *
ipmp_illgrp_add_ipif(ipmp_illgrp_t *illg, ipif_t *ipif)
{
	ill_t *minill;
	ipmp_arpent_t *entp;

	ASSERT(IAM_WRITER_IPIF(ipif));
	ASSERT(ipmp_ipif_is_dataaddr(ipif));

	/*
	 * IPMP data address mappings are internally managed by IP itself, so
	 * delete any existing ARP entries associated with the address.
	 */
	if (!ipif->ipif_isv6) {
		entp = ipmp_illgrp_lookup_arpent(illg, &ipif->ipif_lcl_addr);
		if (entp != NULL)
			ipmp_illgrp_destroy_arpent(illg, entp);
	}

	if ((minill = ipmp_illgrp_min_ill(illg)) != NULL)
		ipmp_ill_bind_ipif(minill, ipif, Res_act_none);

	return (ipif->ipif_bound ? ipif->ipif_bound_ill : NULL);
}

/*
 * Delete `ipif' from the pool of usable data addresses on `illg'.  If it's
 * bound, unbind it from the underlying ill while keeping an even address
 * distribution.
 */
void
ipmp_illgrp_del_ipif(ipmp_illgrp_t *illg, ipif_t *ipif)
{
	ill_t *maxill, *boundill = ipif->ipif_bound_ill;

	ASSERT(IAM_WRITER_IPIF(ipif));

	if (boundill != NULL) {
		(void) ipmp_ill_unbind_ipif(boundill, ipif, B_FALSE);

		maxill = ipmp_illgrp_max_ill(illg);
		if (maxill->ill_bound_cnt > boundill->ill_bound_cnt + 1) {
			ipif = ipmp_ill_unbind_ipif(maxill, NULL, B_TRUE);
			ipmp_ill_bind_ipif(boundill, ipif, Res_act_rebind);
		}
	}
}

/*
 * Return the active ill with the greatest number of data addresses in `illg'.
 */
static ill_t *
ipmp_illgrp_max_ill(ipmp_illgrp_t *illg)
{
	ill_t *ill, *bestill = NULL;

	ASSERT(IAM_WRITER_ILL(illg->ig_ipmp_ill));

	ill = list_head(&illg->ig_actif);
	for (; ill != NULL; ill = list_next(&illg->ig_actif, ill)) {
		if (bestill == NULL ||
		    ill->ill_bound_cnt > bestill->ill_bound_cnt) {
			bestill = ill;
		}
	}
	return (bestill);
}

/*
 * Return the active ill with the fewest number of data addresses in `illg'.
 */
static ill_t *
ipmp_illgrp_min_ill(ipmp_illgrp_t *illg)
{
	ill_t *ill, *bestill = NULL;

	ASSERT(IAM_WRITER_ILL(illg->ig_ipmp_ill));

	ill = list_head(&illg->ig_actif);
	for (; ill != NULL; ill = list_next(&illg->ig_actif, ill)) {
		if (bestill == NULL ||
		    ill->ill_bound_cnt < bestill->ill_bound_cnt) {
			if (ill->ill_bound_cnt == 0)
				return (ill);	 /* can't get better */
			bestill = ill;
		}
	}
	return (bestill);
}

/*
 * Return a pointer to IPMP meta-interface for `illg' (which must exist).
 * Since ig_ipmp_ill never changes for a given illg, no locks are needed.
 */
ill_t *
ipmp_illgrp_ipmp_ill(ipmp_illgrp_t *illg)
{
	return (illg->ig_ipmp_ill);
}

/*
 * Return a pointer to the next available underlying ill in `illg', or NULL if
 * one doesn't exist.  Caller must be inside the IPSQ.
 */
ill_t *
ipmp_illgrp_next_ill(ipmp_illgrp_t *illg)
{
	ill_t *ill;
	ip_stack_t *ipst = IPMP_ILLGRP_TO_IPST(illg);

	ASSERT(IAM_WRITER_ILL(illg->ig_ipmp_ill));

	rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
	if ((ill = illg->ig_next_ill) != NULL) {
		illg->ig_next_ill = list_next(&illg->ig_actif, ill);
		if (illg->ig_next_ill == NULL)
			illg->ig_next_ill = list_head(&illg->ig_actif);
	}
	rw_exit(&ipst->ips_ipmp_lock);

	return (ill);
}

/*
 * Return a held pointer to the next available underlying ill in `illg', or
 * NULL if one doesn't exist.  Caller need not be inside the IPSQ.
 */
ill_t *
ipmp_illgrp_hold_next_ill(ipmp_illgrp_t *illg)
{
	ill_t *ill;
	uint_t i;
	ip_stack_t *ipst = IPMP_ILLGRP_TO_IPST(illg);

	rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
	for (i = 0; i < illg->ig_nactif; i++) {
		ill = illg->ig_next_ill;
		illg->ig_next_ill = list_next(&illg->ig_actif, ill);
		if (illg->ig_next_ill == NULL)
			illg->ig_next_ill = list_head(&illg->ig_actif);

		if (ill_check_and_refhold(ill)) {
			rw_exit(&ipst->ips_ipmp_lock);
			return (ill);
		}
	}
	rw_exit(&ipst->ips_ipmp_lock);

	return (NULL);
}

/*
 * Return a held pointer to the nominated multicast ill in `illg', or NULL if
 * one doesn't exist.  Caller need not be inside the IPSQ.
 */
ill_t *
ipmp_illgrp_hold_cast_ill(ipmp_illgrp_t *illg)
{
	ill_t *castill;
	ip_stack_t *ipst = IPMP_ILLGRP_TO_IPST(illg);

	rw_enter(&ipst->ips_ipmp_lock, RW_READER);
	castill = illg->ig_cast_ill;
	if (castill != NULL && ill_check_and_refhold(castill)) {
		rw_exit(&ipst->ips_ipmp_lock);
		return (castill);
	}
	rw_exit(&ipst->ips_ipmp_lock);
	return (NULL);
}

/*
 * Set the nominated cast ill on `illg' to `castill'.  If `castill' is NULL,
 * any existing nomination is removed.  Caller must be inside the IPSQ.
 */
static void
ipmp_illgrp_set_cast(ipmp_illgrp_t *illg, ill_t *castill)
{
	ill_t *ocastill = illg->ig_cast_ill;
	ill_t *ipmp_ill = illg->ig_ipmp_ill;
	ip_stack_t *ipst = IPMP_ILLGRP_TO_IPST(illg);

	ASSERT(IAM_WRITER_ILL(ipmp_ill));

	/*
	 * Disable old nominated ill (if any).
	 */
	if (ocastill != NULL) {
		DTRACE_PROBE2(ipmp__illgrp__cast__disable, ipmp_illgrp_t *,
		    illg, ill_t *, ocastill);
		ASSERT(ocastill->ill_nom_cast);
		ocastill->ill_nom_cast = B_FALSE;
		/*
		 * If the IPMP meta-interface is down, we never did the join,
		 * so we must not try to leave.
		 */
		if (ipmp_ill->ill_dl_up)
			ill_leave_multicast(ipmp_ill);

		/*
		 * Delete any NCEs tied to the old nomination.  We must do this
		 * last since ill_leave_multicast() may trigger IREs to be
		 * built using ig_cast_ill.
		 */
		ncec_walk(ocastill, (pfi_t)ipmp_ncec_delete_nonlocal, ocastill,
		    ocastill->ill_ipst);
	}

	/*
	 * Set new nomination.
	 */
	rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
	illg->ig_cast_ill = castill;
	rw_exit(&ipst->ips_ipmp_lock);

	/*
	 * Enable new nominated ill (if any).
	 */
	if (castill != NULL) {
		DTRACE_PROBE2(ipmp__illgrp__cast__enable, ipmp_illgrp_t *,
		    illg, ill_t *, castill);
		ASSERT(!castill->ill_nom_cast);
		castill->ill_nom_cast = B_TRUE;
		/*
		 * If the IPMP meta-interface is down, the attempt to recover
		 * will silently fail but ill_need_recover_multicast will be
		 * erroneously cleared -- so check first.
		 */
		if (ipmp_ill->ill_dl_up)
			ill_recover_multicast(ipmp_ill);
	}
}

/*
 * Create an IPMP ARP entry and add it to the set tracked on `illg'.  If an
 * entry for the same IP address already exists, destroy it first.  Return the
 * created IPMP ARP entry, or NULL on failure.
 */
ipmp_arpent_t *
ipmp_illgrp_create_arpent(ipmp_illgrp_t *illg, boolean_t proxyarp,
    ipaddr_t ipaddr, uchar_t *lladdr, size_t lladdr_len, uint16_t flags)
{
	ipmp_arpent_t *entp, *oentp;

	ASSERT(IAM_WRITER_ILL(illg->ig_ipmp_ill));

	if ((entp = kmem_alloc(sizeof (ipmp_arpent_t) + lladdr_len,
	    KM_NOSLEEP)) == NULL)
		return (NULL);

	/*
	 * Delete any existing ARP entry for this address.
	 */
	if ((oentp = ipmp_illgrp_lookup_arpent(illg, &entp->ia_ipaddr)) != NULL)
		ipmp_illgrp_destroy_arpent(illg, oentp);

	/*
	 * Prepend the new entry.
	 */
	entp->ia_ipaddr = ipaddr;
	entp->ia_flags = flags;
	entp->ia_lladdr_len = lladdr_len;
	entp->ia_lladdr = (uchar_t *)&entp[1];
	bcopy(lladdr, entp->ia_lladdr, lladdr_len);
	entp->ia_proxyarp = proxyarp;
	entp->ia_notified = B_TRUE;
	list_insert_head(&illg->ig_arpent, entp);
	return (entp);
}

/*
 * Remove IPMP ARP entry `entp' from the set tracked on `illg' and destroy it.
 */
void
ipmp_illgrp_destroy_arpent(ipmp_illgrp_t *illg, ipmp_arpent_t *entp)
{
	ASSERT(IAM_WRITER_ILL(illg->ig_ipmp_ill));

	list_remove(&illg->ig_arpent, entp);
	kmem_free(entp, sizeof (ipmp_arpent_t) + entp->ia_lladdr_len);
}

/*
 * Mark that ARP has been notified about the IP address on `entp'; `illg' is
 * taken as a debugging aid for DTrace FBT probes.
 */
/* ARGSUSED */
void
ipmp_illgrp_mark_arpent(ipmp_illgrp_t *illg, ipmp_arpent_t *entp)
{
	entp->ia_notified = B_TRUE;
}

/*
 * Look up the IPMP ARP entry for IP address `addrp' on `illg'; if `addrp' is
 * NULL, any IPMP ARP entry is requested.  Return NULL if it does not exist.
 */
ipmp_arpent_t *
ipmp_illgrp_lookup_arpent(ipmp_illgrp_t *illg, ipaddr_t *addrp)
{
	ipmp_arpent_t *entp = list_head(&illg->ig_arpent);

	ASSERT(IAM_WRITER_ILL(illg->ig_ipmp_ill));

	if (addrp == NULL)
		return (entp);

	for (; entp != NULL; entp = list_next(&illg->ig_arpent, entp))
		if (entp->ia_ipaddr == *addrp)
			break;
	return (entp);
}

/*
 * Refresh ARP entries on `illg' to be distributed across its active
 * interfaces.  Entries that cannot be refreshed (e.g., because there are no
 * active interfaces) are marked so that subsequent calls can try again.
 */
void
ipmp_illgrp_refresh_arpent(ipmp_illgrp_t *illg)
{
	ill_t *ill, *ipmp_ill = illg->ig_ipmp_ill;
	uint_t paddrlen = ipmp_ill->ill_phys_addr_length;
	ipmp_arpent_t *entp;
	ncec_t *ncec;
	nce_t  *nce;

	ASSERT(IAM_WRITER_ILL(ipmp_ill));
	ASSERT(!ipmp_ill->ill_isv6);

	ill = list_head(&illg->ig_actif);
	entp = list_head(&illg->ig_arpent);
	for (; entp != NULL; entp = list_next(&illg->ig_arpent, entp)) {
		if (ill == NULL || ipmp_ill->ill_ipif_up_count == 0) {
			entp->ia_notified = B_FALSE;
			continue;
		}

		ASSERT(paddrlen == ill->ill_phys_addr_length);

		/*
		 * If this is a proxy ARP entry, we can skip notifying ARP if
		 * the entry is already up-to-date.  If it has changed, we
		 * update the entry's hardware address before notifying ARP.
		 */
		if (entp->ia_proxyarp) {
			if (bcmp(ill->ill_phys_addr, entp->ia_lladdr,
			    paddrlen) == 0 && entp->ia_notified)
				continue;
			bcopy(ill->ill_phys_addr, entp->ia_lladdr, paddrlen);
		}

		(void) nce_lookup_then_add_v4(ipmp_ill, entp->ia_lladdr,
		    paddrlen, &entp->ia_ipaddr, entp->ia_flags, ND_UNCHANGED,
		    &nce);
		if (nce == NULL || !entp->ia_proxyarp) {
			if (nce != NULL)
				nce_refrele(nce);
			continue;
		}
		ncec = nce->nce_common;
		mutex_enter(&ncec->ncec_lock);
		nce_update(ncec, ND_UNCHANGED, ill->ill_phys_addr);
		mutex_exit(&ncec->ncec_lock);
		nce_refrele(nce);
		ipmp_illgrp_mark_arpent(illg, entp);

		if ((ill = list_next(&illg->ig_actif, ill)) == NULL)
			ill = list_head(&illg->ig_actif);
	}
}

/*
 * Return an interface in `illg' with the specified `physaddr', or NULL if one
 * doesn't exist.  Caller must hold ill_g_lock if it's not inside the IPSQ.
 */
ill_t *
ipmp_illgrp_find_ill(ipmp_illgrp_t *illg, uchar_t *physaddr, uint_t paddrlen)
{
	ill_t *ill;
	ill_t *ipmp_ill = illg->ig_ipmp_ill;
	ip_stack_t *ipst = IPMP_ILLGRP_TO_IPST(illg);

	ASSERT(IAM_WRITER_ILL(ipmp_ill) || RW_LOCK_HELD(&ipst->ips_ill_g_lock));

	ill = list_head(&illg->ig_if);
	for (; ill != NULL; ill = list_next(&illg->ig_if, ill)) {
		if (ill->ill_phys_addr_length == paddrlen &&
		    bcmp(ill->ill_phys_addr, physaddr, paddrlen) == 0)
			return (ill);
	}
	return (NULL);
}

/*
 * Asynchronously update the MTU for an IPMP ill by injecting a DL_NOTIFY_IND.
 * Caller must be inside the IPSQ unless this is initialization.
 */
static void
ipmp_illgrp_set_mtu(ipmp_illgrp_t *illg, uint_t mtu, uint_t mc_mtu)
{
	ill_t *ill = illg->ig_ipmp_ill;
	mblk_t *mp;

	ASSERT(illg->ig_mtu == 0 || IAM_WRITER_ILL(ill));

	/*
	 * If allocation fails, we have bigger problems than MTU.
	 */
	if ((mp = ip_dlnotify_alloc2(DL_NOTE_SDU_SIZE2, mtu, mc_mtu)) != NULL) {
		illg->ig_mtu = mtu;
		illg->ig_mc_mtu = mc_mtu;
		put(ill->ill_rq, mp);
	}
}

/*
 * Recalculate the IPMP group MTU for `illg', and update its associated IPMP
 * ill MTU if necessary.
 */
void
ipmp_illgrp_refresh_mtu(ipmp_illgrp_t *illg)
{
	ill_t *ill;
	ill_t *ipmp_ill = illg->ig_ipmp_ill;
	uint_t mtu = 0;
	uint_t mc_mtu = 0;

	ASSERT(IAM_WRITER_ILL(ipmp_ill));

	/*
	 * Since ill_mtu can only change under ill_lock, we hold ill_lock
	 * for each ill as we iterate through the list.  Any changes to the
	 * ill_mtu will also trigger an update, so even if we missed it
	 * this time around, the update will catch it.
	 */
	ill = list_head(&illg->ig_if);
	for (; ill != NULL; ill = list_next(&illg->ig_if, ill)) {
		mutex_enter(&ill->ill_lock);
		if (mtu == 0 || ill->ill_mtu < mtu)
			mtu = ill->ill_mtu;
		if (mc_mtu == 0 || ill->ill_mc_mtu < mc_mtu)
			mc_mtu = ill->ill_mc_mtu;
		mutex_exit(&ill->ill_lock);
	}

	/*
	 * MTU must be at least the minimum MTU.
	 */
	mtu = MAX(mtu, ipmp_ill->ill_isv6 ? IPV6_MIN_MTU : IP_MIN_MTU);
	mc_mtu = MAX(mc_mtu, ipmp_ill->ill_isv6 ? IPV6_MIN_MTU : IP_MIN_MTU);
	if (illg->ig_mtu != mtu || illg->ig_mc_mtu != mc_mtu)
		ipmp_illgrp_set_mtu(illg, mtu, mc_mtu);
}

/*
 * Link illgrp `illg' to IPMP group `grp'.  To simplify the caller, silently
 * allow the same link to be established more than once.
 */
void
ipmp_illgrp_link_grp(ipmp_illgrp_t *illg, ipmp_grp_t *grp)
{
	ip_stack_t *ipst = IPMP_ILLGRP_TO_IPST(illg);

	ASSERT(RW_WRITE_HELD(&ipst->ips_ipmp_lock));

	if (illg->ig_ipmp_ill->ill_isv6) {
		ASSERT(grp->gr_v6 == NULL || grp->gr_v6 == illg);
		grp->gr_v6 = illg;
	} else {
		ASSERT(grp->gr_v4 == NULL || grp->gr_v4 == illg);
		grp->gr_v4 = illg;
	}
}

/*
 * Unlink illgrp `illg' from its IPMP group.  Return an errno if the illgrp
 * cannot be unlinked (e.g., because there are still interfaces using it).
 */
int
ipmp_illgrp_unlink_grp(ipmp_illgrp_t *illg)
{
	ipmp_grp_t *grp = illg->ig_ipmp_ill->ill_phyint->phyint_grp;
	ip_stack_t *ipst = IPMP_ILLGRP_TO_IPST(illg);

	ASSERT(RW_WRITE_HELD(&ipst->ips_ipmp_lock));

	if (illg->ig_ipmp_ill->ill_isv6) {
		if (grp->gr_nv6 + grp->gr_pendv6 != 0)
			return (EBUSY);
		grp->gr_v6 = NULL;
	} else {
		if (grp->gr_nv4 + grp->gr_pendv4 != 0)
			return (EBUSY);
		grp->gr_v4 = NULL;
	}
	return (0);
}

/*
 * Place `ill' into `illg', and rebalance the data addresses on `illg'
 * to be spread evenly across the ills now in it.  Also, adjust the IPMP
 * ill as necessary to account for `ill' (e.g., MTU).
 */
void
ipmp_ill_join_illgrp(ill_t *ill, ipmp_illgrp_t *illg)
{
	ill_t *ipmp_ill;
	ipif_t *ipif;
	ip_stack_t *ipst = ill->ill_ipst;

	/* IS_UNDER_IPMP() requires ill_grp to be non-NULL */
	ASSERT(!IS_IPMP(ill) && ill->ill_phyint->phyint_grp != NULL);
	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(ill->ill_grp == NULL);

	ipmp_ill = illg->ig_ipmp_ill;

	/*
	 * Account for `ill' joining the illgrp.
	 */
	rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
	if (ill->ill_isv6)
		ill->ill_phyint->phyint_grp->gr_nv6++;
	else
		ill->ill_phyint->phyint_grp->gr_nv4++;
	rw_exit(&ipst->ips_ipmp_lock);

	/*
	 * Ensure the ILLF_ROUTER flag remains consistent across the group.
	 */
	mutex_enter(&ill->ill_lock);
	if (ipmp_ill->ill_flags & ILLF_ROUTER)
		ill->ill_flags |= ILLF_ROUTER;
	else
		ill->ill_flags &= ~ILLF_ROUTER;
	mutex_exit(&ill->ill_lock);

	/*
	 * Blow away all multicast memberships that currently exist on `ill'.
	 * This may seem odd, but it's consistent with the application view
	 * that `ill' no longer exists (e.g., due to ipmp_ill_rtsaddrmsg()).
	 * The ill_grp_pending bit prevents multicast group joins after
	 * update_conn_ill() and before ill_grp assignment.
	 */
	mutex_enter(&ill->ill_mcast_serializer);
	ill->ill_grp_pending = 1;
	mutex_exit(&ill->ill_mcast_serializer);
	update_conn_ill(ill, ill->ill_ipst);
	if (ill->ill_isv6) {
		reset_mrt_ill(ill);
	} else {
		ipif = ill->ill_ipif;
		for (; ipif != NULL; ipif = ipif->ipif_next) {
			reset_mrt_vif_ipif(ipif);
		}
	}
	ip_purge_allmulti(ill);

	/*
	 * Borrow the first ill's ill_phys_addr_length value for the illgrp's
	 * physical address length.  All other ills must have the same value,
	 * since they are required to all be the same mactype.  Also update
	 * the IPMP ill's MTU and CoS marking, if necessary.
	 */
	if (list_is_empty(&illg->ig_if)) {
		ASSERT(ipmp_ill->ill_phys_addr_length == 0);
		/*
		 * NOTE: we leave ill_phys_addr NULL since the IPMP group
		 * doesn't have a physical address.  This means that code must
		 * not assume that ill_phys_addr is non-NULL just because
		 * ill_phys_addr_length is non-zero.  Likewise for ill_nd_lla.
		 */
		ipmp_ill->ill_phys_addr_length = ill->ill_phys_addr_length;
		ipmp_ill->ill_nd_lla_len = ill->ill_phys_addr_length;
		ipmp_ill->ill_type = ill->ill_type;

		if (ill->ill_flags & ILLF_COS_ENABLED) {
			mutex_enter(&ipmp_ill->ill_lock);
			ipmp_ill->ill_flags |= ILLF_COS_ENABLED;
			mutex_exit(&ipmp_ill->ill_lock);
		}
		ipmp_illgrp_set_mtu(illg, ill->ill_mtu, ill->ill_mc_mtu);
	} else {
		ASSERT(ipmp_ill->ill_phys_addr_length ==
		    ill->ill_phys_addr_length);
		ASSERT(ipmp_ill->ill_type == ill->ill_type);

		if (!(ill->ill_flags & ILLF_COS_ENABLED)) {
			mutex_enter(&ipmp_ill->ill_lock);
			ipmp_ill->ill_flags &= ~ILLF_COS_ENABLED;
			mutex_exit(&ipmp_ill->ill_lock);
		}
		if (illg->ig_mtu > ill->ill_mtu ||
		    illg->ig_mc_mtu > ill->ill_mc_mtu) {
			ipmp_illgrp_set_mtu(illg, ill->ill_mtu,
			    ill->ill_mc_mtu);
		}
	}

	rw_enter(&ipst->ips_ill_g_lock, RW_WRITER);
	list_insert_tail(&illg->ig_if, ill);
	ill->ill_grp = illg;
	rw_exit(&ipst->ips_ill_g_lock);

	mutex_enter(&ill->ill_mcast_serializer);
	ill->ill_grp_pending = 0;
	mutex_exit(&ill->ill_mcast_serializer);

	/*
	 * Hide the IREs on `ill' so that we don't accidentally find them when
	 * sending data traffic.
	 */
	ire_walk_ill(MATCH_IRE_ILL, 0, ipmp_ill_ire_mark_testhidden, ill, ill);

	ipmp_ill_refresh_active(ill);
}

/*
 * Remove `ill' from its illgrp, and rebalance the data addresses in that
 * illgrp to be spread evenly across the remaining ills.  Also, adjust the
 * IPMP ill as necessary now that `ill' is removed (e.g., MTU).
 */
void
ipmp_ill_leave_illgrp(ill_t *ill)
{
	ill_t *ipmp_ill;
	ipif_t *ipif;
	ipmp_arpent_t *entp;
	ipmp_illgrp_t *illg = ill->ill_grp;
	ip_stack_t *ipst = IPMP_ILLGRP_TO_IPST(illg);

	ASSERT(IS_UNDER_IPMP(ill));
	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(illg != NULL);

	ipmp_ill = illg->ig_ipmp_ill;

	/*
	 * Cancel IPMP-specific ill timeouts.
	 */
	(void) untimeout(ill->ill_refresh_tid);

	/*
	 * Expose any previously-hidden IREs on `ill'.
	 */
	ire_walk_ill(MATCH_IRE_ILL, 0, ipmp_ill_ire_clear_testhidden, ill, ill);

	/*
	 * Ensure the multicast state for each ipif on `ill' is down so that
	 * our ipif_multicast_up() (once `ill' leaves the group) will rejoin
	 * all eligible groups.
	 */
	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next)
		if (ipif->ipif_flags & IPIF_UP)
			ipif_multicast_down(ipif);

	/*
	 * Account for `ill' leaving the illgrp.
	 */
	rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
	if (ill->ill_isv6)
		ill->ill_phyint->phyint_grp->gr_nv6--;
	else
		ill->ill_phyint->phyint_grp->gr_nv4--;
	rw_exit(&ipst->ips_ipmp_lock);

	/*
	 * Pull `ill' out of the interface lists.
	 */
	if (list_link_active(&ill->ill_actnode))
		ipmp_ill_deactivate(ill);
	rw_enter(&ipst->ips_ill_g_lock, RW_WRITER);
	list_remove(&illg->ig_if, ill);
	ill->ill_grp = NULL;
	rw_exit(&ipst->ips_ill_g_lock);

	/*
	 * Re-establish multicast memberships that were previously being
	 * handled by the IPMP meta-interface.
	 */
	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next)
		if (ipif->ipif_flags & IPIF_UP)
			ipif_multicast_up(ipif);

	/*
	 * Refresh the group MTU based on the new interface list.
	 */
	ipmp_illgrp_refresh_mtu(illg);

	if (list_is_empty(&illg->ig_if)) {
		/*
		 * No ills left in the illgrp; we no longer have a physical
		 * address length, nor can we support ARP, CoS, or anything
		 * else that depends on knowing the link layer type.
		 */
		while ((entp = ipmp_illgrp_lookup_arpent(illg, NULL)) != NULL)
			ipmp_illgrp_destroy_arpent(illg, entp);

		ipmp_ill->ill_phys_addr_length = 0;
		ipmp_ill->ill_nd_lla_len = 0;
		ipmp_ill->ill_type = IFT_OTHER;
		mutex_enter(&ipmp_ill->ill_lock);
		ipmp_ill->ill_flags &= ~ILLF_COS_ENABLED;
		mutex_exit(&ipmp_ill->ill_lock);
	} else {
		/*
		 * If `ill' didn't support CoS, see if it can now be enabled.
		 */
		if (!(ill->ill_flags & ILLF_COS_ENABLED)) {
			ASSERT(!(ipmp_ill->ill_flags & ILLF_COS_ENABLED));

			ill = list_head(&illg->ig_if);
			do {
				if (!(ill->ill_flags & ILLF_COS_ENABLED))
					break;
			} while ((ill = list_next(&illg->ig_if, ill)) != NULL);

			if (ill == NULL) {
				mutex_enter(&ipmp_ill->ill_lock);
				ipmp_ill->ill_flags |= ILLF_COS_ENABLED;
				mutex_exit(&ipmp_ill->ill_lock);
			}
		}
	}
}

/*
 * Check if `ill' should be active, and activate or deactivate if need be.
 * Return B_FALSE if a refresh was necessary but could not be performed.
 */
static boolean_t
ipmp_ill_try_refresh_active(ill_t *ill)
{
	boolean_t refreshed = B_TRUE;

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(IS_UNDER_IPMP(ill));

	if (ipmp_ill_is_active(ill)) {
		if (!list_link_active(&ill->ill_actnode))
			refreshed = ipmp_ill_activate(ill);
	} else {
		if (list_link_active(&ill->ill_actnode))
			ipmp_ill_deactivate(ill);
	}

	return (refreshed);
}

/*
 * Check if `ill' should be active, and activate or deactivate if need be.
 * If the refresh fails, schedule a timer to try again later.
 */
void
ipmp_ill_refresh_active(ill_t *ill)
{
	if (!ipmp_ill_try_refresh_active(ill))
		ipmp_ill_refresh_active_timer_start(ill);
}

/*
 * Retry ipmp_ill_try_refresh_active() on the ill named by `ill_arg'.
 */
static void
ipmp_ill_refresh_active_timer(void *ill_arg)
{
	ill_t *ill = ill_arg;
	boolean_t refreshed = B_FALSE;

	/*
	 * Clear ill_refresh_tid to indicate that no timeout is pending
	 * (another thread could schedule a new timeout while we're still
	 * running, but that's harmless).  If the ill is going away, bail.
	 */
	mutex_enter(&ill->ill_lock);
	ill->ill_refresh_tid = 0;
	if (ill->ill_state_flags & ILL_CONDEMNED) {
		mutex_exit(&ill->ill_lock);
		return;
	}
	mutex_exit(&ill->ill_lock);

	if (ipsq_try_enter(NULL, ill, NULL, NULL, NULL, NEW_OP, B_FALSE)) {
		refreshed = ipmp_ill_try_refresh_active(ill);
		ipsq_exit(ill->ill_phyint->phyint_ipsq);
	}

	/*
	 * If the refresh failed, schedule another attempt.
	 */
	if (!refreshed)
		ipmp_ill_refresh_active_timer_start(ill);
}

/*
 * Retry an ipmp_ill_try_refresh_active() on the ill named by `arg'.
 */
static void
ipmp_ill_refresh_active_timer_start(ill_t *ill)
{
	mutex_enter(&ill->ill_lock);

	/*
	 * If the ill is going away or a refresh is already scheduled, bail.
	 */
	if (ill->ill_refresh_tid != 0 ||
	    (ill->ill_state_flags & ILL_CONDEMNED)) {
		mutex_exit(&ill->ill_lock);
		return;
	}

	ill->ill_refresh_tid = timeout(ipmp_ill_refresh_active_timer, ill,
	    SEC_TO_TICK(IPMP_ILL_REFRESH_TIMEOUT));

	mutex_exit(&ill->ill_lock);
}

/*
 * Activate `ill' so it will be used to send and receive data traffic.  Return
 * B_FALSE if `ill' cannot be activated.  Note that we allocate any messages
 * needed to deactivate `ill' here as well so that deactivation cannot fail.
 */
static boolean_t
ipmp_ill_activate(ill_t *ill)
{
	ipif_t		*ipif;
	mblk_t		*linkupmp = NULL, *linkdownmp = NULL;
	ipmp_grp_t	*grp = ill->ill_phyint->phyint_grp;
	ipmp_illgrp_t	*illg = ill->ill_grp;
	ill_t		*maxill;
	ip_stack_t	*ipst = IPMP_ILLGRP_TO_IPST(illg);

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(IS_UNDER_IPMP(ill));

	/*
	 * If this will be the first active interface in the group, allocate
	 * the link-up and link-down messages.
	 */
	if (grp->gr_nactif == 0) {
		linkupmp = ip_dlnotify_alloc(DL_NOTE_LINK_UP, 0);
		linkdownmp = ip_dlnotify_alloc(DL_NOTE_LINK_DOWN, 0);
		if (linkupmp == NULL || linkdownmp == NULL)
			goto fail;
	}

	if (list_is_empty(&illg->ig_actif)) {
		/*
		 * Now that we have an active ill, nominate it for multicast
		 * and broadcast duties.  Do this before ipmp_ill_bind_ipif()
		 * since that may need to send multicast packets (e.g., IPv6
		 * neighbor discovery probes).
		 */
		ipmp_illgrp_set_cast(illg, ill);

		/*
		 * This is the first active ill in the illgrp -- add 'em all.
		 * We can access/walk ig_ipmp_ill's ipif list since we're
		 * writer on its IPSQ as well.
		 */
		ipif = illg->ig_ipmp_ill->ill_ipif;
		for (; ipif != NULL; ipif = ipif->ipif_next)
			if (ipmp_ipif_is_up_dataaddr(ipif))
				ipmp_ill_bind_ipif(ill, ipif, Res_act_initial);
	} else {
		/*
		 * Redistribute the addresses by moving them from the ill with
		 * the most addresses until the ill being activated is at the
		 * same level as the rest of the ills.
		 */
		for (;;) {
			maxill = ipmp_illgrp_max_ill(illg);
			ASSERT(maxill != NULL);
			if (ill->ill_bound_cnt + 1 >= maxill->ill_bound_cnt)
				break;
			ipif = ipmp_ill_unbind_ipif(maxill, NULL, B_TRUE);
			ipmp_ill_bind_ipif(ill, ipif, Res_act_rebind);
		}
	}

	/*
	 * Put the interface in the active list.
	 */
	rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
	list_insert_tail(&illg->ig_actif, ill);
	illg->ig_nactif++;
	illg->ig_next_ill = ill;
	rw_exit(&ipst->ips_ipmp_lock);

	/*
	 * Refresh static/proxy ARP entries to use `ill', if need be.
	 */
	if (!ill->ill_isv6)
		ipmp_illgrp_refresh_arpent(illg);

	/*
	 * Finally, mark the group link up, if necessary.
	 */
	if (grp->gr_nactif++ == 0) {
		ASSERT(grp->gr_linkdownmp == NULL);
		grp->gr_linkdownmp = linkdownmp;
		put(illg->ig_ipmp_ill->ill_rq, linkupmp);
	}
	return (B_TRUE);
fail:
	freemsg(linkupmp);
	freemsg(linkdownmp);
	return (B_FALSE);
}

/*
 * Deactivate `ill' so it will not be used to send or receive data traffic.
 */
static void
ipmp_ill_deactivate(ill_t *ill)
{
	ill_t		*minill, *ipmp_ill;
	ipif_t		*ipif, *ubnextipif, *ubheadipif = NULL;
	mblk_t		*mp;
	ipmp_grp_t	*grp = ill->ill_phyint->phyint_grp;
	ipmp_illgrp_t	*illg = ill->ill_grp;
	ip_stack_t	*ipst = IPMP_ILLGRP_TO_IPST(illg);

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(IS_UNDER_IPMP(ill));

	ipmp_ill = illg->ig_ipmp_ill;

	/*
	 * Pull the interface out of the active list.
	 */
	rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
	list_remove(&illg->ig_actif, ill);
	illg->ig_nactif--;
	illg->ig_next_ill = list_head(&illg->ig_actif);
	rw_exit(&ipst->ips_ipmp_lock);

	/*
	 * If the ill that's being deactivated had been nominated for
	 * multicast/broadcast, nominate a new one.
	 */
	if (ill == illg->ig_cast_ill)
		ipmp_illgrp_set_cast(illg, list_head(&illg->ig_actif));

	/*
	 * Delete all nce_t entries using this ill, so that the next attempt
	 * to send data traffic will revalidate cached nce's.
	 */
	nce_flush(ill, B_TRUE);

	/*
	 * Unbind all of the ipifs bound to this ill, and save 'em in a list;
	 * we'll rebind them after we tell the resolver the ill is no longer
	 * active.  We must do things in this order or the resolver could
	 * accidentally rebind to the ill we're trying to remove if multiple
	 * ills in the group have the same hardware address (which is
	 * unsupported, but shouldn't lead to a wedged machine).
	 */
	while ((ipif = ipmp_ill_unbind_ipif(ill, NULL, B_TRUE)) != NULL) {
		ipif->ipif_bound_next = ubheadipif;
		ubheadipif = ipif;
	}

	if (!ill->ill_isv6) {
		/*
		 * Refresh static/proxy ARP entries that had been using `ill'.
		 */
		ipmp_illgrp_refresh_arpent(illg);
	}

	/*
	 * Rebind each ipif from the deactivated ill to the active ill with
	 * the fewest ipifs.  If there are no active ills, the ipifs will
	 * remain unbound.
	 */
	for (ipif = ubheadipif; ipif != NULL; ipif = ubnextipif) {
		ubnextipif = ipif->ipif_bound_next;
		ipif->ipif_bound_next = NULL;

		if ((minill = ipmp_illgrp_min_ill(illg)) != NULL)
			ipmp_ill_bind_ipif(minill, ipif, Res_act_rebind);
	}

	/*
	 * Remove any IRE_IF_CLONEs for this ill since they might have an
	 * ire_nce_cache/nce_common which refers to another ill in the group.
	 */
	ire_walk_ill(MATCH_IRE_TYPE, IRE_IF_CLONE, ill_downi_if_clone, ill,
	    ill);

	/*
	 * Finally, if there are no longer any active interfaces, then delete
	 * any NCECs associated with the group and mark the group link down.
	 */
	if (--grp->gr_nactif == 0) {
		ncec_walk(ipmp_ill, (pfi_t)ncec_delete_per_ill, ipmp_ill, ipst);
		mp = grp->gr_linkdownmp;
		grp->gr_linkdownmp = NULL;
		ASSERT(mp != NULL);
		put(ipmp_ill->ill_rq, mp);
	}
}

/*
 * Send the routing socket messages needed to make `ill' "appear" (RTM_ADD)
 * or "disappear" (RTM_DELETE) to non-IPMP-aware routing socket listeners.
 */
static void
ipmp_ill_rtsaddrmsg(ill_t *ill, int cmd)
{
	ipif_t *ipif;

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(cmd == RTM_ADD || cmd == RTM_DELETE);

	/*
	 * If `ill' is truly down, there are no messages to generate since:
	 *
	 * 1. If cmd == RTM_DELETE, then we're supposed to hide the interface
	 *    and its addresses by bringing them down.  But that's already
	 *    true, so there's nothing to hide.
	 *
	 * 2. If cmd == RTM_ADD, then we're supposed to generate messages
	 *    indicating that any previously-hidden up addresses are again
	 *    back up (along with the interface).  But they aren't, so
	 *    there's nothing to expose.
	 */
	if (ill->ill_ipif_up_count == 0)
		return;

	if (cmd == RTM_ADD)
		ip_rts_xifmsg(ill->ill_ipif, IPIF_UP, 0, RTSQ_NORMAL);

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next)
		if (ipif->ipif_flags & IPIF_UP)
			ip_rts_newaddrmsg(cmd, 0, ipif, RTSQ_NORMAL);

	if (cmd == RTM_DELETE)
		ip_rts_xifmsg(ill->ill_ipif, 0, IPIF_UP, RTSQ_NORMAL);
}

/*
 * Bind the address named by `ipif' to the underlying ill named by `ill'.
 * If `act' is Res_act_none, don't notify the resolver.  Otherwise, `act'
 * will indicate to the resolver whether this is an initial bringup of
 * `ipif', or just a rebind to another ill.
 */
static void
ipmp_ill_bind_ipif(ill_t *ill, ipif_t *ipif, enum ip_resolver_action act)
{
	int err = 0;
	ip_stack_t *ipst = ill->ill_ipst;

	ASSERT(IAM_WRITER_ILL(ill) && IAM_WRITER_IPIF(ipif));
	ASSERT(IS_UNDER_IPMP(ill) && IS_IPMP(ipif->ipif_ill));
	ASSERT(act == Res_act_none || ipmp_ipif_is_up_dataaddr(ipif));
	ASSERT(ipif->ipif_bound_ill == NULL);
	ASSERT(ipif->ipif_bound_next == NULL);

	ipif->ipif_bound_next = ill->ill_bound_ipif;
	ill->ill_bound_ipif = ipif;
	ill->ill_bound_cnt++;
	rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
	ipif->ipif_bound_ill = ill;
	rw_exit(&ipst->ips_ipmp_lock);

	/*
	 * If necessary, tell ARP/NDP about the new mapping.  Note that
	 * ipif_resolver_up() cannot fail for IPv6 ills.
	 */
	if (act != Res_act_none) {
		if (ill->ill_isv6) {
			VERIFY(ipif_resolver_up(ipif, act) == 0);
			err = ipif_ndp_up(ipif, act == Res_act_initial);
		} else {
			err = ipif_resolver_up(ipif, act);
		}

		/*
		 * Since ipif_ndp_up() never returns EINPROGRESS and
		 * ipif_resolver_up() only returns EINPROGRESS when the
		 * associated ill is not up, we should never be here with
		 * EINPROGRESS.  We rely on this to simplify the design.
		 */
		ASSERT(err != EINPROGRESS);
	}
	/* TODO: retry binding on failure? when? */
	ipif->ipif_bound = (err == 0);
}

/*
 * Unbind the address named by `ipif' from the underlying ill named by `ill'.
 * If `ipif' is NULL, then an arbitrary ipif on `ill' is unbound and returned.
 * If no ipifs are bound to `ill', NULL is returned.  If `notifyres' is
 * B_TRUE, notify the resolver about the change.
 */
static ipif_t *
ipmp_ill_unbind_ipif(ill_t *ill, ipif_t *ipif, boolean_t notifyres)
{
	ipif_t *previpif;
	ip_stack_t *ipst = ill->ill_ipst;

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(IS_UNDER_IPMP(ill));

	/*
	 * If necessary, find an ipif to unbind.
	 */
	if (ipif == NULL) {
		if ((ipif = ill->ill_bound_ipif) == NULL) {
			ASSERT(ill->ill_bound_cnt == 0);
			return (NULL);
		}
	}

	ASSERT(IAM_WRITER_IPIF(ipif));
	ASSERT(IS_IPMP(ipif->ipif_ill));
	ASSERT(ipif->ipif_bound_ill == ill);
	ASSERT(ill->ill_bound_cnt > 0);

	/*
	 * Unbind it.
	 */
	rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
	ipif->ipif_bound_ill = NULL;
	rw_exit(&ipst->ips_ipmp_lock);
	ill->ill_bound_cnt--;

	if (ill->ill_bound_ipif == ipif) {
		ill->ill_bound_ipif = ipif->ipif_bound_next;
	} else {
		previpif = ill->ill_bound_ipif;
		while (previpif->ipif_bound_next != ipif)
			previpif = previpif->ipif_bound_next;

		previpif->ipif_bound_next = ipif->ipif_bound_next;
	}
	ipif->ipif_bound_next = NULL;

	/*
	 * If requested, notify the resolvers (provided we're bound).
	 */
	if (notifyres && ipif->ipif_bound) {
		if (ill->ill_isv6)
			ipif_ndp_down(ipif);
		else
			(void) ipif_arp_down(ipif);
	}
	ipif->ipif_bound = B_FALSE;

	return (ipif);
}

/*
 * Check if `ill' is active.  Caller must hold ill_lock and phyint_lock if
 * it's not inside the IPSQ.  Since ipmp_ill_try_refresh_active() calls this
 * to determine whether an ill should be considered active, other consumers
 * may race and learn about an ill that should be deactivated/activated before
 * IPMP has performed the activation/deactivation.  This should be safe though
 * since at worst e.g. ire_atomic_start() will prematurely delete an IRE that
 * would've been cleaned up by ipmp_ill_deactivate().
 */
boolean_t
ipmp_ill_is_active(ill_t *ill)
{
	phyint_t *phyi = ill->ill_phyint;

	ASSERT(IS_UNDER_IPMP(ill));
	ASSERT(IAM_WRITER_ILL(ill) ||
	    (MUTEX_HELD(&ill->ill_lock) && MUTEX_HELD(&phyi->phyint_lock)));

	/*
	 * Note that PHYI_RUNNING isn't checked since we rely on in.mpathd to
	 * set PHYI_FAILED whenever PHYI_RUNNING is cleared.  This allows the
	 * link flapping logic to be just in in.mpathd and allows us to ignore
	 * changes to PHYI_RUNNING.
	 */
	return (!(ill->ill_ipif_up_count == 0 ||
	    (phyi->phyint_flags & (PHYI_OFFLINE|PHYI_INACTIVE|PHYI_FAILED))));
}

/*
 * IRE walker callback: set ire_testhidden on IRE_HIDDEN_TYPE IREs associated
 * with `ill_arg'.
 */
static void
ipmp_ill_ire_mark_testhidden(ire_t *ire, char *ill_arg)
{
	ill_t *ill = (ill_t *)ill_arg;

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(!IS_IPMP(ill));

	if (ire->ire_ill != ill)
		return;

	if (IRE_HIDDEN_TYPE(ire->ire_type)) {
		DTRACE_PROBE1(ipmp__mark__testhidden, ire_t *, ire);
		ire->ire_testhidden = B_TRUE;
	}
}

/*
 * IRE walker callback: clear ire_testhidden if the IRE has a source address
 * on `ill_arg'.
 */
static void
ipmp_ill_ire_clear_testhidden(ire_t *ire, char *ill_arg)
{
	ill_t *ill = (ill_t *)ill_arg;

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(!IS_IPMP(ill));

	if (ire->ire_ill == ill) {
		DTRACE_PROBE1(ipmp__clear__testhidden, ire_t *, ire);
		ire->ire_testhidden = B_FALSE;
	}
}

/*
 * Return a held pointer to the IPMP ill for underlying interface `ill', or
 * NULL if one doesn't exist.  (Unfortunately, this function needs to take an
 * underlying ill rather than an ipmp_illgrp_t because an underlying ill's
 * ill_grp pointer may become stale when not inside an IPSQ and not holding
 * ipmp_lock.)  Caller need not be inside the IPSQ.
 */
ill_t *
ipmp_ill_hold_ipmp_ill(ill_t *ill)
{
	ip_stack_t *ipst = ill->ill_ipst;
	ipmp_illgrp_t *illg;

	ASSERT(!IS_IPMP(ill));

	rw_enter(&ipst->ips_ipmp_lock, RW_READER);
	illg = ill->ill_grp;
	if (illg != NULL && ill_check_and_refhold(illg->ig_ipmp_ill)) {
		rw_exit(&ipst->ips_ipmp_lock);
		return (illg->ig_ipmp_ill);
	}
	/*
	 * Assume `ill' was removed from the illgrp in the meantime.
	 */
	rw_exit(&ill->ill_ipst->ips_ipmp_lock);
	return (NULL);
}

/*
 * Return a held pointer to the appropriate underlying ill for sending the
 * specified type of packet.  (Unfortunately, this function needs to take an
 * underlying ill rather than an ipmp_illgrp_t because an underlying ill's
 * ill_grp pointer may become stale when not inside an IPSQ and not holding
 * ipmp_lock.)  Caller need not be inside the IPSQ.
 */
ill_t *
ipmp_ill_hold_xmit_ill(ill_t *ill, boolean_t is_unicast)
{
	ill_t *xmit_ill;
	ip_stack_t *ipst = ill->ill_ipst;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	if (ill->ill_grp == NULL) {
		/*
		 * The ill was taken out of the group, so just send on it.
		 */
		rw_exit(&ipst->ips_ill_g_lock);
		ill_refhold(ill);
		return (ill);
	}
	if (is_unicast)
		xmit_ill = ipmp_illgrp_hold_next_ill(ill->ill_grp);
	else
		xmit_ill = ipmp_illgrp_hold_cast_ill(ill->ill_grp);
	rw_exit(&ipst->ips_ill_g_lock);

	return (xmit_ill);
}

/*
 * Return the interface index for the IPMP ill tied to underlying interface
 * `ill', or zero if one doesn't exist.  Caller need not be inside the IPSQ.
 */
uint_t
ipmp_ill_get_ipmp_ifindex(const ill_t *ill)
{
	uint_t ifindex = 0;
	ip_stack_t *ipst = ill->ill_ipst;
	ipmp_grp_t *grp;

	ASSERT(!IS_IPMP(ill));

	rw_enter(&ipst->ips_ipmp_lock, RW_READER);
	if ((grp = ill->ill_phyint->phyint_grp) != NULL)
		ifindex = grp->gr_phyint->phyint_ifindex;
	rw_exit(&ipst->ips_ipmp_lock);
	return (ifindex);
}

/*
 * Place phyint `phyi' into IPMP group `grp'.
 */
void
ipmp_phyint_join_grp(phyint_t *phyi, ipmp_grp_t *grp)
{
	ill_t *ill;
	ipsq_t *ipsq = phyi->phyint_ipsq;
	ipsq_t *grp_ipsq = grp->gr_phyint->phyint_ipsq;
	ip_stack_t *ipst = PHYINT_TO_IPST(phyi);

	ASSERT(IAM_WRITER_IPSQ(ipsq));
	ASSERT(phyi->phyint_illv4 != NULL || phyi->phyint_illv6 != NULL);

	/*
	 * Send routing socket messages indicating that the phyint's ills
	 * and ipifs vanished.
	 */
	if (phyi->phyint_illv4 != NULL) {
		ill = phyi->phyint_illv4;
		ipmp_ill_rtsaddrmsg(ill, RTM_DELETE);
	}

	if (phyi->phyint_illv6 != NULL) {
		ill = phyi->phyint_illv6;
		ipmp_ill_rtsaddrmsg(ill, RTM_DELETE);
	}

	/*
	 * Snapshot the phyint's initial kstats as a baseline.
	 */
	ipmp_phyint_get_kstats(phyi, phyi->phyint_kstats0);

	rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);

	phyi->phyint_grp = grp;
	if (++grp->gr_nif == 1)
		grp->gr_mactype = ill->ill_mactype;
	else
		ASSERT(grp->gr_mactype == ill->ill_mactype);

	/*
	 * Now that we're in the group, request a switch to the group's xop
	 * when we ipsq_exit().  All future operations will be exclusive on
	 * the group xop until ipmp_phyint_leave_grp() is called.
	 */
	ASSERT(ipsq->ipsq_swxop == NULL);
	ASSERT(grp_ipsq->ipsq_xop == &grp_ipsq->ipsq_ownxop);
	ipsq->ipsq_swxop = &grp_ipsq->ipsq_ownxop;

	rw_exit(&ipst->ips_ipmp_lock);
}

/*
 * Remove phyint `phyi' from its current IPMP group.
 */
void
ipmp_phyint_leave_grp(phyint_t *phyi)
{
	uint_t i;
	ipsq_t *ipsq = phyi->phyint_ipsq;
	ip_stack_t *ipst = PHYINT_TO_IPST(phyi);
	uint64_t phyi_kstats[IPMP_KSTAT_MAX];

	ASSERT(IAM_WRITER_IPSQ(ipsq));

	/*
	 * If any of the phyint's ills are still in an illgrp, kick 'em out.
	 */
	if (phyi->phyint_illv4 != NULL && IS_UNDER_IPMP(phyi->phyint_illv4))
		ipmp_ill_leave_illgrp(phyi->phyint_illv4);
	if (phyi->phyint_illv6 != NULL && IS_UNDER_IPMP(phyi->phyint_illv6))
		ipmp_ill_leave_illgrp(phyi->phyint_illv6);

	/*
	 * Send routing socket messages indicating that the phyint's ills
	 * and ipifs have reappeared.
	 */
	if (phyi->phyint_illv4 != NULL)
		ipmp_ill_rtsaddrmsg(phyi->phyint_illv4, RTM_ADD);
	if (phyi->phyint_illv6 != NULL)
		ipmp_ill_rtsaddrmsg(phyi->phyint_illv6, RTM_ADD);

	/*
	 * Calculate the phyint's cumulative kstats while it was in the group,
	 * and add that to the group's baseline.
	 */
	ipmp_phyint_get_kstats(phyi, phyi_kstats);
	for (i = 0; i < IPMP_KSTAT_MAX; i++) {
		phyi_kstats[i] -= phyi->phyint_kstats0[i];
		atomic_add_64(&phyi->phyint_grp->gr_kstats0[i], phyi_kstats[i]);
	}

	rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);

	phyi->phyint_grp->gr_nif--;
	phyi->phyint_grp = NULL;

	/*
	 * As our final act in leaving the group, request a switch back to our
	 * IPSQ's own xop when we ipsq_exit().
	 */
	ASSERT(ipsq->ipsq_swxop == NULL);
	ipsq->ipsq_swxop = &ipsq->ipsq_ownxop;

	rw_exit(&ipst->ips_ipmp_lock);
}

/*
 * Store the IPMP-related kstats for `phyi' into the array named by `kstats'.
 * Assumes that `kstats' has at least IPMP_KSTAT_MAX elements.
 */
static void
ipmp_phyint_get_kstats(phyint_t *phyi, uint64_t kstats[])
{
	uint_t		i, j;
	const char	*name;
	kstat_t		*ksp;
	kstat_named_t	*kn;
	ip_stack_t	*ipst = PHYINT_TO_IPST(phyi);
	zoneid_t	zoneid;

	bzero(kstats, sizeof (kstats[0]) * IPMP_KSTAT_MAX);
	zoneid = netstackid_to_zoneid(ipst->ips_netstack->netstack_stackid);
	ksp = kstat_hold_byname("link", 0, phyi->phyint_name, zoneid);
	if (ksp == NULL)
		return;

	KSTAT_ENTER(ksp);

	if (ksp->ks_data != NULL && ksp->ks_type == KSTAT_TYPE_NAMED) {
		/*
		 * Bring kstats up-to-date before recording.
		 */
		(void) KSTAT_UPDATE(ksp, KSTAT_READ);

		kn = KSTAT_NAMED_PTR(ksp);
		for (i = 0; i < IPMP_KSTAT_MAX; i++) {
			name = ipmp_kstats[i].name;
			kstats[i] = 0;
			for (j = 0; j < ksp->ks_ndata; j++) {
				if (strcmp(kn[j].name, name) != 0)
					continue;

				switch (kn[j].data_type) {
				case KSTAT_DATA_INT32:
				case KSTAT_DATA_UINT32:
					kstats[i] = kn[j].value.ui32;
					break;
#ifdef	_LP64
				case KSTAT_DATA_LONG:
				case KSTAT_DATA_ULONG:
					kstats[i] = kn[j].value.ul;
					break;
#endif
				case KSTAT_DATA_INT64:
				case KSTAT_DATA_UINT64:
					kstats[i] = kn[j].value.ui64;
					break;
				}
				break;
			}
		}
	}

	KSTAT_EXIT(ksp);
	kstat_rele(ksp);
}

/*
 * Refresh the active state of all ills on `phyi'.
 */
void
ipmp_phyint_refresh_active(phyint_t *phyi)
{
	if (phyi->phyint_illv4 != NULL)
		ipmp_ill_refresh_active(phyi->phyint_illv4);
	if (phyi->phyint_illv6 != NULL)
		ipmp_ill_refresh_active(phyi->phyint_illv6);
}

/*
 * Return a held pointer to the underlying ill bound to `ipif', or NULL if one
 * doesn't exist.  Caller need not be inside the IPSQ.
 */
ill_t *
ipmp_ipif_hold_bound_ill(const ipif_t *ipif)
{
	ill_t *boundill;
	ip_stack_t *ipst = ipif->ipif_ill->ill_ipst;

	ASSERT(IS_IPMP(ipif->ipif_ill));

	rw_enter(&ipst->ips_ipmp_lock, RW_READER);
	boundill = ipif->ipif_bound_ill;
	if (boundill != NULL && ill_check_and_refhold(boundill)) {
		rw_exit(&ipst->ips_ipmp_lock);
		return (boundill);
	}
	rw_exit(&ipst->ips_ipmp_lock);
	return (NULL);
}

/*
 * Return a pointer to the underlying ill bound to `ipif', or NULL if one
 * doesn't exist.  Caller must be inside the IPSQ.
 */
ill_t *
ipmp_ipif_bound_ill(const ipif_t *ipif)
{
	ASSERT(IAM_WRITER_ILL(ipif->ipif_ill));
	ASSERT(IS_IPMP(ipif->ipif_ill));

	return (ipif->ipif_bound_ill);
}

/*
 * Check if `ipif' is a "stub" (placeholder address not being used).
 */
boolean_t
ipmp_ipif_is_stubaddr(const ipif_t *ipif)
{
	if (ipif->ipif_flags & IPIF_UP)
		return (B_FALSE);
	if (ipif->ipif_ill->ill_isv6)
		return (IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr));
	else
		return (ipif->ipif_lcl_addr == INADDR_ANY);
}

/*
 * Check if `ipif' is an IPMP data address.
 */
boolean_t
ipmp_ipif_is_dataaddr(const ipif_t *ipif)
{
	if (ipif->ipif_flags & IPIF_NOFAILOVER)
		return (B_FALSE);
	if (ipif->ipif_ill->ill_isv6)
		return (!IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr));
	else
		return (ipif->ipif_lcl_addr != INADDR_ANY);
}

/*
 * Check if `ipif' is an IPIF_UP IPMP data address.
 */
static boolean_t
ipmp_ipif_is_up_dataaddr(const ipif_t *ipif)
{
	return (ipmp_ipif_is_dataaddr(ipif) && (ipif->ipif_flags & IPIF_UP));
}

/*
 * Check if `mp' contains a probe packet by checking if the IP source address
 * is a test address on underlying interface `ill'.  Caller need not be inside
 * the IPSQ.
 */
boolean_t
ipmp_packet_is_probe(mblk_t *mp, ill_t *ill)
{
	ip6_t *ip6h = (ip6_t *)mp->b_rptr;
	ipha_t *ipha = (ipha_t *)mp->b_rptr;

	ASSERT(DB_TYPE(mp) != M_CTL);

	if (!IS_UNDER_IPMP(ill))
		return (B_FALSE);

	if (ill->ill_isv6) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src) &&
		    ipif_lookup_testaddr_v6(ill, &ip6h->ip6_src, NULL))
			return (B_TRUE);
	} else {
		if (ipha->ipha_src != INADDR_ANY &&
		    ipif_lookup_testaddr_v4(ill, &ipha->ipha_src, NULL))
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * NCEC walker callback: delete `ncec' if it is associated with `ill_arg' and
 * is not one of our local addresses.  Caller must be inside the IPSQ.
 */
static void
ipmp_ncec_delete_nonlocal(ncec_t *ncec, uchar_t *ill_arg)
{
	if (!NCE_MYADDR(ncec) && ncec->ncec_ill == (ill_t *)ill_arg)
		ncec_delete(ncec);
}

/*
 * Delete any NCEs tied to the illgrp associated with `ncec'.  Caller need not
 * be inside the IPSQ.
 */
void
ipmp_ncec_delete_nce(ncec_t *ncec)
{
	ipmp_illgrp_t	*illg = ncec->ncec_ill->ill_grp;
	ip_stack_t	*ipst = ncec->ncec_ipst;
	ill_t		*ill;
	nce_t		*nce;
	list_t		dead;

	ASSERT(IS_IPMP(ncec->ncec_ill));

	/*
	 * For each underlying interface, delete `ncec' from its ill_nce list
	 * via nce_fastpath_list_delete().  Defer the actual nce_refrele()
	 * until we've dropped ill_g_lock.
	 */
	list_create(&dead, sizeof (nce_t), offsetof(nce_t, nce_node));

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = list_head(&illg->ig_if);
	for (; ill != NULL; ill = list_next(&illg->ig_if, ill))
		nce_fastpath_list_delete(ill, ncec, &dead);
	rw_exit(&ipst->ips_ill_g_lock);

	while ((nce = list_remove_head(&dead)) != NULL)
		nce_refrele(nce);

	list_destroy(&dead);
}

/*
 * Refresh any NCE entries tied to the illgrp associated with `ncec' to
 * use the information in `ncec'.  Caller need not be inside the IPSQ.
 */
void
ipmp_ncec_refresh_nce(ncec_t *ncec)
{
	ipmp_illgrp_t	*illg = ncec->ncec_ill->ill_grp;
	ip_stack_t	*ipst = ncec->ncec_ipst;
	ill_t		*ill;
	nce_t		*nce, *nce_next;
	list_t		replace;

	ASSERT(IS_IPMP(ncec->ncec_ill));

	/*
	 * If `ncec' is not reachable, there is no use in refreshing NCEs.
	 */
	if (!NCE_ISREACHABLE(ncec))
		return;

	/*
	 * Find all the NCEs matching ncec->ncec_addr.  We cannot update them
	 * in-situ because we're holding ipmp_lock to prevent changes to IPMP
	 * group membership and updating indirectly calls nce_fastpath_probe()
	 * -> putnext() which cannot hold locks.  Thus, move the NCEs to a
	 * separate list and process that list after dropping ipmp_lock.
	 */
	list_create(&replace, sizeof (nce_t), offsetof(nce_t, nce_node));
	rw_enter(&ipst->ips_ipmp_lock, RW_READER);
	ill = list_head(&illg->ig_actif);
	for (; ill != NULL; ill = list_next(&illg->ig_actif, ill)) {
		mutex_enter(&ill->ill_lock);
		nce = list_head(&ill->ill_nce);
		for (; nce != NULL; nce = nce_next) {
			nce_next = list_next(&ill->ill_nce, nce);
			if (IN6_ARE_ADDR_EQUAL(&nce->nce_addr,
			    &ncec->ncec_addr)) {
				nce_refhold(nce);
				nce_delete(nce);
				list_insert_tail(&replace, nce);
			}
		}
		mutex_exit(&ill->ill_lock);
	}
	rw_exit(&ipst->ips_ipmp_lock);

	/*
	 * Process the list; nce_lookup_then_add_v* ensures that nce->nce_ill
	 * is still in the group for ncec->ncec_ill.
	 */
	while ((nce = list_remove_head(&replace)) != NULL) {
		if (ncec->ncec_ill->ill_isv6) {
			(void) nce_lookup_then_add_v6(nce->nce_ill,
			    ncec->ncec_lladdr, ncec->ncec_lladdr_length,
			    &nce->nce_addr, ncec->ncec_flags, ND_UNCHANGED,
			    NULL);
		} else {
			ipaddr_t ipaddr;

			IN6_V4MAPPED_TO_IPADDR(&ncec->ncec_addr, ipaddr);
			(void) nce_lookup_then_add_v4(nce->nce_ill,
			    ncec->ncec_lladdr, ncec->ncec_lladdr_length,
			    &ipaddr, ncec->ncec_flags, ND_UNCHANGED, NULL);
		}
		nce_refrele(nce);
	}

	list_destroy(&replace);
}
