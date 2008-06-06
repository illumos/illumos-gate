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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/t_lock.h>
#include <sys/stat.h>

#define	MDDB
#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_names.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

extern md_set_t	md_set[];
extern int	*md_nm_snarfed;
void		*lookup_entry(struct nm_next_hdr *, set_t,
			side_t, mdkey_t, md_dev64_t, int);
void		*lookup_shared_entry(struct nm_next_hdr *,
			mdkey_t, char *, mddb_recid_t *, int);
static void	add_to_devid_list(ddi_devid_t did);
static int	devid_is_unique(ddi_devid_t did);
static size_t	free_devid_list(int *count);
void		md_devid_cleanup(set_t, uint_t);
extern md_krwlock_t	nm_lock;

typedef enum lookup_dev_result {
	LOOKUP_DEV_FOUND,	/* Found a good record. */
	LOOKUP_DEV_NOMATCH,	/* No matching record in DB. */
	LOOKUP_DEV_CONFLICT	/* Name conflicts with existing record. */
} lookup_dev_result_t;

/* List of SVM module names. */
static char *meta_names[] = {
	"md",
	MD_STRIPE,
	MD_MIRROR,
	MD_TRANS,
	MD_HOTSPARES,
	MD_RAID,
	MD_VERIFY,
	MD_SP,
	MD_NOTIFY
};

#define	META_NAME_COUNT	(sizeof (meta_names) / sizeof (char *))

/*
 * Used in translating from the md major name on miniroot to
 * md major name on target system.  This is only needed during
 * upgrade.
 */

extern major_t md_major, md_major_targ;

/*
 * During upgrade, SVM basically runs with the devt from the target
 * being upgraded.  Translations are made from the miniroot devt to/from the
 * target devt when the devt is to be stored in the SVM metadriver's
 * unit structures.
 *
 * The following routines return a translated (aka miniroot) devt:
 *	- md_getdevnum
 *	- the metadriver's get_devs routines (stripe_getdevs, etc.)
 *
 * By the same token, the major number and major name conversion operations
 * need to use the name_to_major file from the target system instead
 * of the name_to_major file on the miniroot.  So, calls to
 * ddi_name_to_major must be replaced with calls to md_targ_name_to_major
 * when running on an upgrade.  Same is true with calls to
 * ddi_major_to_name.
 */

static mdkey_t
create_key(struct nm_next_hdr *nh)
{
	mdkey_t	retval;
	struct nm_rec_hdr	*rh = (struct nm_rec_hdr *)nh->nmn_record;

	retval = rh->r_next_key;
	/* increment the next_key, keeps them unique */
	rh->r_next_key++;

	return (retval);
}

static int
unused_key(struct nm_next_hdr *nh, int shared, mdkey_t key)
{
	mdkey_t	min_value;
	int	nmspace;

	if (shared & NM_DEVID) {
		min_value = 1;
		nmspace = NM_DEVID;
	} else {
		min_value = ((shared & NM_SHARED) ? MDDB_FIRST_MODID : 1);
		nmspace = 0;
	}

	/* Just say no if the key passed in is less than the initial */
	if (key < min_value)
		return (0);

	if ((shared & NM_SHARED) && (lookup_shared_entry(nh, key, (char *)0,
		NULL, nmspace) != NULL))
		return (0);

	/*
	 * The set num in lookup_entry is not used in this case
	 * we dont keep track of the nonshared in the devid nmspace
	 */
	if (!(shared & NM_NOTSHARED) &&
		(lookup_entry(nh, 0, -1, key, NODEV64, 0L) != NULL))
		return (0);

	return (1);
}

static void
destroy_key(struct nm_next_hdr *nh, int shared, mdkey_t key)
{
	struct nm_rec_hdr *rh = (struct nm_rec_hdr *)nh->nmn_record;

	if ((key + 1) != rh->r_next_key)
		return;

	while (unused_key(nh, shared, key))
		key--;
	rh->r_next_key = key + 1;
}

static void
cleanup_unused_rec(set_t setno, int devid_nm)
{
	mddb_recid_t	recid;
	mddb_type_t	hdr, shr, notshr;

	hdr = ((devid_nm & NM_DEVID) ? MDDB_DID_NM_HDR : MDDB_NM_HDR);
	notshr = ((devid_nm & NM_DEVID) ? MDDB_DID_NM : MDDB_NM);
	shr = ((devid_nm & NM_DEVID) ? MDDB_DID_SHR_NM : MDDB_SHR_NM);

	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, hdr, 0)) > 0)
		if (! (mddb_getrecprivate(recid) & MD_PRV_GOTIT))
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);

	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, notshr, 0)) > 0)
		if (! (mddb_getrecprivate(recid) & MD_PRV_GOTIT))
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);

	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, shr, 0)) > 0)
		if (! (mddb_getrecprivate(recid) & MD_PRV_GOTIT))
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);
}

static int
create_hdr(set_t setno, int shared)
{
	struct nm_header_hdr	*hhdr;
	mddb_recid_t		nmid;


	if (shared & NM_DEVID) {
		/*
		 * Deal with the device id name space
		 */
		nmid = md_set[setno].s_did_nmid =
			mddb_createrec(sizeof (struct nm_header),
				MDDB_DID_NM_HDR, 1, MD_CRO_32BIT, setno);
		/*
		 * Out of space
		 */
		if (nmid < 0)
			return (nmid);
	} else {
		nmid = md_set[setno].s_nmid =
			mddb_createrec(sizeof (struct nm_header),
				MDDB_NM_HDR, 1, MD_CRO_32BIT, setno);
		/*
		 * Out of space
		 */
		if (nmid < 0)
			return (nmid);
	}

	hhdr = kmem_zalloc(sizeof (*hhdr), KM_SLEEP);

	if (shared & NM_DEVID) {
		md_set[setno].s_did_nm = hhdr;
	} else {
		md_set[setno].s_nm = hhdr;
	}

	hhdr->hh_header = (struct nm_header *)mddb_getrecaddr(nmid);
	hhdr->hh_names.nmn_record = &(hhdr->hh_header->h_names);
	hhdr->hh_shared.nmn_record = &(hhdr->hh_header->h_shared);

	/*
	 * h_names.r_next_key is set to zero in devid nmspace
	 * since we dont keep track of it
	 */
	if (shared & NM_DEVID) {
		hhdr->hh_header->h_names.r_next_key = 0;
		hhdr->hh_header->h_shared.r_next_key = 1;
	} else {
		hhdr->hh_header->h_names.r_next_key = 1;
		hhdr->hh_header->h_shared.r_next_key = MDDB_FIRST_MODID;
	}

	mddb_commitrec_wrapper(nmid);
	return (0);
}

static int
create_record(
	mddb_recid_t		p_recid,	/* parent recid */
	struct nm_next_hdr	*nh,		/* parent record header */
	int			shared,
	size_t			needed_space)
{
	struct nm_rec_hdr	*rh = (struct nm_rec_hdr *)nh->nmn_record;
	struct nm_next_hdr	*new_nh;
	mddb_type_t		rec_type;
	size_t			used_size;
	size_t			alloc_size;
	mddb_recid_t		recids[3];
	set_t			setno;
	mddb_recid_t		new_id;

	setno = mddb_getsetnum(p_recid);

	if (shared & NM_DEVID) {
		/*
		 * Device id name space
		 */
		rec_type = ((shared & NM_SHARED) ?
			MDDB_DID_SHR_NM : MDDB_DID_NM);
		used_size = ((shared & NM_SHARED) ?
			(sizeof (struct devid_shr_rec) -
				sizeof (struct did_shr_name)) :
			(sizeof (struct devid_min_rec) -
				sizeof (struct did_min_name)));
		alloc_size = ((shared & NM_SHARED) ?
			NM_DID_ALLOC_SIZE : NM_ALLOC_SIZE);
	} else {
		rec_type = ((shared & NM_SHARED) ?
			MDDB_SHR_NM : MDDB_NM);
		used_size = ((shared & NM_SHARED) ?
			(sizeof (struct nm_shr_rec) -
				sizeof (struct nm_shared_name)) :
			(sizeof (struct nm_rec) - sizeof (struct nm_name)));
		alloc_size = NM_ALLOC_SIZE;
	}

	used_size += needed_space;

	new_id = mddb_createrec((size_t)alloc_size, rec_type, 1,
		MD_CRO_32BIT, setno);
	if (new_id < 0)
		return (new_id);

	recids[0] = rh->r_next_recid = new_id;
	recids[1] = p_recid;
	recids[2] = 0;

	new_nh = (struct nm_next_hdr *)kmem_zalloc(sizeof (*new_nh), KM_SLEEP);
	nh->nmn_nextp = new_nh;
	new_nh->nmn_record = mddb_getrecaddr(rh->r_next_recid);

	((struct nm_rec_hdr *)new_nh->nmn_record)->r_alloc_size = alloc_size;
	((struct nm_rec_hdr *)new_nh->nmn_record)->r_used_size =
		(uint_t)used_size;

	mddb_commitrecs_wrapper(recids);
	return (0);
}

static int
expand_record(
	struct nm_next_hdr	*parent_nh,	/* parent record header */
	mddb_recid_t		parent_recid,	/* parent record id */
	struct nm_next_hdr	*nh,		/* record hdr to be expanded */
	int			shared)		/* boolean - shared or not */
{
	struct nm_rec_hdr	*rh = (struct nm_rec_hdr *)nh->nmn_record;
	struct nm_rec_hdr	*parent_rh = (struct nm_rec_hdr *)
						parent_nh->nmn_record;
	struct nm_rec_hdr	*new_rh;
	void			*new_rec;
	mddb_recid_t		new_id;
	mddb_recid_t		old_id;
	mddb_recid_t		recids[3];
	set_t			setno;
	mddb_type_t		rec_type;
	size_t			alloc_size;

	setno = mddb_getsetnum(parent_recid);

	if (shared & NM_DEVID) {
		/*
		 * Device id name space
		 */
		rec_type = ((shared & NM_SHARED) ?
			MDDB_DID_SHR_NM : MDDB_DID_NM);
		alloc_size = ((shared & NM_SHARED) ?
			NM_DID_ALLOC_SIZE : NM_ALLOC_SIZE);
	} else {
		rec_type = ((shared & NM_SHARED) ? MDDB_SHR_NM : MDDB_NM);
		alloc_size = NM_ALLOC_SIZE;
	}

	new_id = mddb_createrec((size_t)rh->r_alloc_size + alloc_size, rec_type,
			1, MD_CRO_32BIT, setno);
	/*
	 * No space
	 */
	if (new_id < 0)
		return (new_id);

	new_rec = mddb_getrecaddr(new_id);
	(void) bcopy(rh, new_rec, rh->r_alloc_size);

	recids[0] = parent_recid;
	recids[1] = new_id;
	recids[2] = 0;

	/* Fix up rec hdr to point at this new record */
	nh->nmn_record = new_rec;
	old_id = parent_rh->r_next_recid;
	parent_rh->r_next_recid = new_id;

	if (shared & NM_DEVID)
		/*
		 * Device id name space
		 */
		new_rh = ((shared & NM_SHARED) ?
		    &((struct devid_shr_rec *)new_rec)->did_rec_hdr :
		    &((struct devid_min_rec *)new_rec)->min_rec_hdr);
	else
		new_rh = ((shared & NM_SHARED) ?
		    &((struct nm_shr_rec *)new_rec)->sr_rec_hdr :
		    &((struct nm_rec *)new_rec)->r_rec_hdr);

	new_rh->r_alloc_size += alloc_size;
	if (!(shared & NM_NOCOMMIT))
		mddb_commitrecs_wrapper(recids);

	/* delete the old record */
	mddb_deleterec_wrapper(old_id);

	return (0);
}

struct nm_next_hdr *
get_first_record(set_t setno, int alloc, int shared)
{
	struct nm_next_hdr	*nh;
	mddb_recid_t		nmid;

	ASSERT(md_get_setstatus(setno) & MD_SET_NM_LOADED);

	if (shared & NM_DEVID) {
		/*
		 * We are dealing with the device id name space.
		 * If set is a MN diskset, just return 0 since
		 * devids aren't yet supported in MN disksets.
		 */
		if (MD_MNSET_SETNO(setno))
			return ((struct nm_next_hdr *)0);
		if (md_set[setno].s_did_nm == NULL)
			if (create_hdr(setno, shared) < 0)
				return ((struct nm_next_hdr *)0);

		nh = ((shared & NM_SHARED) ?
		    &((struct nm_header_hdr *)md_set[setno].s_did_nm)->hh_shared
		    :
		    &((struct nm_header_hdr *)
		    md_set[setno].s_did_nm)->hh_names);

		nmid = md_set[setno].s_did_nmid;
	} else {
		/*
		 * We are dealing with the regular one (non-devid)
		 */
		if (md_set[setno].s_nm == NULL)
			if (create_hdr(setno, shared) < 0)
				return ((struct nm_next_hdr *)0);

		nh = ((shared & NM_SHARED) ?
		    &((struct nm_header_hdr *)md_set[setno].s_nm)->hh_shared
		    :
		    &((struct nm_header_hdr *)md_set[setno].s_nm)->hh_names);

		nmid = md_set[setno].s_nmid;
	}

	/*
	 * Name space exists
	 */
	if (nh->nmn_nextp != NULL)
		return (nh);

	/*
	 * If name space is expected and is empty
	 */
	if (! alloc)
		return ((struct nm_next_hdr *)0);

	/*
	 * Empty is okay alloc it
	 */
	if (create_record(nmid, nh, shared, 0L) < 0)
		return ((struct nm_next_hdr *)0);

	return (nh);
}


void *
alloc_entry(
	struct nm_next_hdr *nh,		/* parent name header */
	mddb_recid_t recid,		/* parent record id */
	size_t len,			/* length of entry */
	int shared,			/* shared boolean */
	mddb_recid_t *id)		/* return of new record id */
{
	struct nm_rec_hdr	*rh;		/* parent */
	mddb_recid_t		this_recid;
	struct nm_next_hdr	*this_nh;
	struct nm_rec_hdr	*this_rh;
	void			*this_rec;
	size_t			needed_space;
	char			*name;

	if (shared & NM_DEVID)
		/*
		 * Device id name space
		 */
		needed_space = ((shared & NM_SHARED) ?
			sizeof (struct did_shr_name) :
			sizeof (struct did_min_name)) + len - 1;
	else
		needed_space = ((shared & NM_SHARED) ?
			sizeof (struct nm_shared_name) :
			sizeof (struct nm_name)) + len - 1;

	needed_space = roundup(needed_space, sizeof (uint_t));

	/* check the next record to see if it has space */
	/*CONSTCOND*/
	while (1) {
		while ((this_nh = nh->nmn_nextp) != NULL) {

			rh = (struct nm_rec_hdr *)nh->nmn_record;
			this_recid = rh->r_next_recid;
			this_rec = this_nh->nmn_record;

			if (shared & NM_DEVID)
			    this_rh = ((shared & NM_SHARED) ?
			    &((struct devid_shr_rec *)this_rec)->did_rec_hdr :
			    &((struct devid_min_rec *)this_rec)->min_rec_hdr);
			else
			    this_rh = ((shared & NM_SHARED) ?
			    &((struct nm_shr_rec *)this_rec)->sr_rec_hdr :
			    &((struct nm_rec *)this_rec)->r_rec_hdr);

			/* check for space in this record */
			if ((this_rh->r_alloc_size - this_rh->r_used_size) >=
			    needed_space) {
				/* allocate space in this record */
				name = (char *)this_rec + this_rh->r_used_size;
				this_rh->r_used_size += (uint_t)needed_space;
				if (!(shared & NM_NOCOMMIT))
					mddb_commitrec_wrapper(this_recid);
				*id = this_recid;
				return ((caddr_t)name);
			}

			/* if we can expand the record we look again */
			if (expand_record(nh, recid, this_nh, shared) == 0)
				continue;

			/* advance parent to this record, and go try next */
			recid = this_recid;
			nh = this_nh;
		}

		/* no space, try creating a new record after parent */
		if (create_record(recid, nh, shared, 0L) < 0)
			return ((caddr_t)0);
	} /* go check the new record */
	/* can't get here, but lint seems to think so */
	/* NOTREACHED */
}

static void *
get_next_entry(
	struct nm_next_hdr *nh,
	caddr_t ent,
	size_t ent_size,
	size_t *off)
{

	if (((struct nm_rec_hdr *)nh->nmn_record)->r_used_size <=
			(*off + ent_size)) {
		if (nh->nmn_nextp == NULL)
			return ((caddr_t)0);

		/* offset == 0, means go to next record */
		*off = 0;
		return ((caddr_t)0);
	}

	*off += ent_size;
	return ((caddr_t)((char *)ent + ent_size));
}

static int
rem_entry(
	struct nm_next_hdr *nh,	/* record header for entry being removed */
	mddb_recid_t id,	/* record id for entry being removed */
	void *ent,		/* address of entry to be removed */
	size_t ent_size,	/* size of entry to be removed */
	size_t offset,		/* offset of entry within record */
	int devid_nm)		/* which name space? 0 - primary */
{
	struct nm_next_hdr	*first_nh;
	mddb_recid_t		recids[3];
	size_t			c = ((struct nm_rec_hdr *)
				    nh->nmn_record)->r_used_size - offset -
				    ent_size;
	set_t			setno;
	mdkey_t			ent_key;


	setno = mddb_getsetnum(id);
	first_nh = get_first_record(setno, 0, devid_nm | NM_NOTSHARED);
	ASSERT(first_nh != NULL);

	recids[0] = id;
	recids[1] = ((devid_nm & NM_DEVID) ? md_set[setno].s_did_nmid :
		md_set[setno].s_nmid);
	recids[2] = 0;
	ent_key = ((devid_nm & NM_DEVID) ?
		((struct did_min_name *)ent)->min_key :
		((struct nm_name *)ent)->n_key);

	if (c == 0)
		(void) bzero(ent, ent_size);	/* last entry */
	else {
		(void) ovbcopy((caddr_t)ent+ent_size, ent, c);
		(void) bzero((caddr_t)ent+c, ent_size);
	}

	((struct nm_rec_hdr *)nh->nmn_record)->r_used_size -= (uint_t)ent_size;

	/*
	 * We don't keep track of keys in the device id nonshared namespace
	 */
	if (!devid_nm)
		destroy_key(first_nh, NM_NOTSHARED, ent_key);

	mddb_commitrecs_wrapper(recids);
	return (0);
}

static int
rem_shr_entry(
	struct nm_next_hdr *nh,	/* record header for entry being removed */
	mddb_recid_t id,	/* record id for entry being removed */
	void *ent,		/* address of entry to be removed */
	size_t ent_size,	/* size of entry to be removed */
	size_t offset,		/* offset of entry within record */
	int devid_nm)		/* which name space? 0 - primary */
{
	struct nm_next_hdr	*first_nh;
	mddb_recid_t		recids[3];
	size_t			c = ((struct nm_rec_hdr *)
				    nh->nmn_record)->r_used_size - offset -
				    ent_size;
	set_t			setno;
	uint_t			count;

	setno = mddb_getsetnum(id);
	first_nh = get_first_record(setno, 0, devid_nm | NM_SHARED);
	ASSERT(first_nh != NULL);

	recids[0] = id;
	recids[1] = ((devid_nm & NM_DEVID) ? md_set[setno].s_did_nmid :
		md_set[setno].s_nmid);
	recids[2] = 0;

	if (devid_nm & NM_DEVID) {
		count = --((struct did_shr_name *)ent)->did_count;
	} else {
		count = --((struct nm_shared_name *)ent)->sn_count;
	}

	if (count == 0 || devid_nm & NM_IMP_SHARED) {
		mdkey_t	ent_key;

		ent_key = ((devid_nm & NM_DEVID) ?
			((struct did_shr_name *)ent)->did_key :
			((struct nm_shared_name *)ent)->sn_key);

		if (c == 0)
			(void) bzero(ent, ent_size);	/* last entry */
		else {
			(void) ovbcopy((caddr_t)ent+ent_size, ent, c);
			(void) bzero((caddr_t)ent+c, ent_size);
		}

		((struct nm_rec_hdr *)nh->nmn_record)->r_used_size -=
			(uint_t)ent_size;
		destroy_key(first_nh, devid_nm | NM_SHARED, ent_key);
	}

	if (!(devid_nm & NM_NOCOMMIT))
		mddb_commitrecs_wrapper(recids);
	return (0);
}

static mdkey_t
setshared_name(set_t setno, char *shrname, mdkey_t shrkey, int devid_nm)
{
	struct nm_next_hdr	*nh;
	struct nm_shared_name	*shn;
	struct did_shr_name	*did_shn = (struct did_shr_name *)NULL;
	mddb_recid_t		recid;
	mddb_recid_t		recids[3];
	size_t			len;
	mdkey_t			key;
	int			shared = NM_SHARED;


	if (shrkey == MD_KEYWILD) {
		len = ((devid_nm & NM_DEVID) ?
		    ddi_devid_sizeof((ddi_devid_t)shrname) :
		    (strlen(shrname) + 1));
	}
	/*
	 * If devid_nm is not NULL, nh will point to the did name space
	 */
	if (devid_nm & NM_NOCOMMIT) {
		if ((nh = get_first_record(setno, 0, devid_nm | NM_SHARED))
		    == NULL)
			return (MD_KEYBAD);
	} else {
		if ((nh = get_first_record(setno, 1, devid_nm | NM_SHARED))
		    == NULL)
			return (MD_KEYBAD);
	}
	if (devid_nm & NM_NOCOMMIT)
		shared = NM_NOCOMMIT  | shared;
	if (devid_nm & NM_DEVID) {
		/*
		 * A key has been supplied so find the corresponding entry
		 * which must exist.
		 */
		if (shrkey != MD_KEYWILD) {
			did_shn = (struct did_shr_name *)lookup_shared_entry(nh,
			    shrkey, NULL, &recid, devid_nm);
			if (did_shn == (struct did_shr_name *)NULL)
				return (MD_KEYBAD);
		} else {
			did_shn = (struct did_shr_name *)lookup_shared_entry(nh,
			    0, shrname, &recid, devid_nm);
		}
		if (did_shn != (struct did_shr_name *)NULL) {
			did_shn->did_count++;
			if (!(devid_nm & NM_NOCOMMIT))
				mddb_commitrec_wrapper(recid);
			return (did_shn->did_key);
		}


		/* allocate an entry and fill it in */
		if ((did_shn = (struct did_shr_name *)alloc_entry(nh,
			md_set[setno].s_did_nmid, len, shared | NM_DEVID,
			&recid)) == NULL)
			return (MD_KEYBAD);
		did_shn->did_key = create_key(nh);
		did_shn->did_count = 1;
		did_shn->did_size = (ushort_t)len;
		/*
		 * Let the whole world know it is valid devid
		 */
		did_shn->did_data = NM_DEVID_VALID;
		bcopy((void *)shrname, (void *)did_shn->did_devid, len);
		key = did_shn->did_key;
	} else {
		if ((shn = (struct nm_shared_name *)lookup_shared_entry(nh,
			0, shrname, &recid, 0L)) != NULL) {
			/* Increment reference count */
			shn->sn_count++;
			if (!(devid_nm & NM_NOCOMMIT))
				mddb_commitrec_wrapper(recid);
			return (shn->sn_key);
		}

		/* allocate an entry and fill it in */
		if ((shn = (struct nm_shared_name *)alloc_entry(nh,
		    md_set[setno].s_nmid, len, shared, &recid)) == NULL)
			return (MD_KEYBAD);
		shn->sn_key = create_key(nh);
		shn->sn_count = 1;
		shn->sn_namlen = (ushort_t)len;
		(void) strcpy(shn->sn_name, shrname);
		key = shn->sn_key;
	}

	recids[0] = recid;
	recids[1] = ((devid_nm & NM_DEVID) ? md_set[setno].s_did_nmid :
			md_set[setno].s_nmid);
	recids[2] = 0;

	if (!(devid_nm & NM_NOCOMMIT))
		mddb_commitrecs_wrapper(recids);
	return (key);
}

void *
getshared_name(set_t setno, mdkey_t shrkey, int devid_nm)
{
	char			*shn;
	struct nm_next_hdr	*nh;
	mddb_recid_t		recid;

	if ((nh = get_first_record(setno, 0, devid_nm | NM_SHARED)) == NULL)
		return ((void *)0);

	shn = (char *)((devid_nm & NM_DEVID) ?
		lookup_shared_entry(nh, shrkey, (char *)0, &recid, devid_nm) :
		lookup_shared_entry(nh, shrkey, (char *)0, &recid, 0L));

	if (shn == NULL)
		return ((void *)0);

	return ((void *)((devid_nm & NM_DEVID) ?
		((struct did_shr_name *)shn)->did_devid :
		((struct nm_shared_name *)shn)->sn_name));
}

static mdkey_t
getshared_key(set_t setno, char *shrname, int devid_nm)
{
	struct nm_next_hdr	*nh;
	char			*shn;
	mddb_recid_t		recid;

	if ((nh = get_first_record(setno, 1, devid_nm |  NM_SHARED)) == NULL)
		return (MD_KEYBAD);

	shn = (char *)lookup_shared_entry(nh, 0, shrname, &recid, devid_nm);

	if (shn == NULL)
		return (MD_KEYBAD);

	return (((devid_nm & NM_DEVID) ?
		((struct did_shr_name *)shn)->did_key :
		((struct nm_shared_name *)shn)->sn_key));
}

static int
setshared_data(set_t setno, mdkey_t shrkey, caddr_t data)
{
	struct nm_shared_name	*shn;
	struct nm_next_hdr	*nh;
	mddb_recid_t		recid;

	if ((nh = get_first_record(setno, 0, NM_SHARED)) == NULL)
		return (ENOENT);

	shn = (struct nm_shared_name *)lookup_shared_entry(nh, shrkey,
		(char *)0, &recid, 0L);
	if (shn == NULL)
		return (ENOENT);
	shn->sn_data = (uint32_t)(uintptr_t)data;
	return (0);
}

int
update_entry(
	struct nm_next_hdr	*nh,		/* head record header */
	side_t			side,		/* (key 1) side number */
	mdkey_t			key,		/* (key 2) via md_setdevname */
	int			devid_nm)	/* Which name space? */
{
	struct nm_rec_hdr	*rh = (struct nm_rec_hdr *)nh->nmn_record;
	struct nm_next_hdr	*this_nh = nh->nmn_nextp;
	void			*record = this_nh->nmn_record;
	mddb_recid_t		recid = rh->r_next_recid;
	struct nm_rec_hdr	*this_rh;
	caddr_t			n;
	size_t			offset, n_offset, n_size;
	mdkey_t			n_key;
	side_t			n_side;

	n_offset = offset = ((devid_nm & NM_DEVID) ?
		(sizeof (struct devid_min_rec) - sizeof (struct did_min_name))
				:
		(sizeof (struct nm_rec) - sizeof (struct nm_name)));

	this_rh = ((devid_nm & NM_DEVID) ?
		&((struct devid_min_rec *)record)->min_rec_hdr :
		&((struct nm_rec *)record)->r_rec_hdr);

	n = ((devid_nm & NM_DEVID) ?
		((caddr_t)&((struct devid_min_rec *)record)->minor_name[0]) :
		((caddr_t)&((struct nm_rec *)record)->r_name[0]));

	/*CONSTCOND*/
	while (1) {

		if (devid_nm & NM_DEVID) {
			n_side = ((struct did_min_name *)n)->min_side;
			n_key = ((struct did_min_name *)n)->min_key;
			n_size = DID_NAMSIZ((struct did_min_name *)n);

		} else {
			n_side = ((struct nm_name *)n)->n_side;
			n_key = ((struct nm_name *)n)->n_key;
			n_size = NAMSIZ((struct nm_name *)n);
		}

		if ((side == n_side) && (key == n_key)) {
			mddb_commitrec_wrapper(recid);
			return (0);
		}

		n = (caddr_t)get_next_entry(this_nh, n, n_size, &offset);

		if (n == NULL) {
			if (offset)
				return (ENOENT);

			/* Go to next record */
			offset = n_offset;
			this_nh = this_nh->nmn_nextp;
			record = this_nh->nmn_record;
			recid = this_rh->r_next_recid;
			this_rh = ((devid_nm & NM_DEVID) ?
			    &((struct devid_min_rec *)record)->min_rec_hdr
			    :
			    &((struct nm_rec *)record)->r_rec_hdr);
			n = ((devid_nm & NM_DEVID) ?
				((caddr_t)&((struct devid_min_rec *)
					record)->minor_name[0]) :
				((caddr_t)&((struct nm_rec *)
					record)->r_name[0]));
		}
	}
	/*NOTREACHED*/
}

int
remove_entry(
	struct nm_next_hdr	*nh,		/* head record header */
	side_t			side,		/* (key 1) side number */
	mdkey_t			key,		/* (key 2) via md_setdevname */
	int			devid_nm)	/* which name space? */
{
	struct nm_rec_hdr	*rh = (struct nm_rec_hdr *)nh->nmn_record;
	struct nm_next_hdr	*this_nh = nh->nmn_nextp;
	void			*record = this_nh->nmn_record;
	mddb_recid_t		recid = rh->r_next_recid;
	struct nm_rec_hdr	*this_rh;
	caddr_t			n;
	size_t			offset, n_offset, n_size;
	mdkey_t			n_key;
	side_t			n_side;

	n_offset = offset = ((devid_nm & NM_DEVID) ?
		(sizeof (struct devid_min_rec) - sizeof (struct did_min_name))
				:
		(sizeof (struct nm_rec) - sizeof (struct nm_name)));

	this_rh = ((devid_nm & NM_DEVID) ?
		&((struct devid_min_rec *)record)->min_rec_hdr :
		&((struct nm_rec *)record)->r_rec_hdr);

	n = ((devid_nm & NM_DEVID) ?
		((caddr_t)&((struct devid_min_rec *)record)->minor_name[0]) :
		((caddr_t)&((struct nm_rec *)record)->r_name[0]));

	/*CONSTCOND*/
	while (1) {

		if (devid_nm & NM_DEVID) {
			n_side = ((struct did_min_name *)n)->min_side;
			n_key = ((struct did_min_name *)n)->min_key;
			n_size = DID_NAMSIZ((struct did_min_name *)n);
		} else {
			n_side = ((struct nm_name *)n)->n_side;
			n_key = ((struct nm_name *)n)->n_key;
			n_size = NAMSIZ((struct nm_name *)n);
		}

		if ((side == n_side) && (key == n_key))
			return (rem_entry(this_nh, recid, (char *)n, n_size,
				offset, devid_nm));

		n = (caddr_t)get_next_entry(this_nh, n, n_size, &offset);

		if (n == NULL) {
			if (offset)
				return (ENOENT);

			/* Go to next record */
			offset = n_offset;
			this_nh = this_nh->nmn_nextp;
			record = this_nh->nmn_record;
			recid = this_rh->r_next_recid;
			this_rh = ((devid_nm & NM_DEVID) ?
				&((struct devid_min_rec *)record)->min_rec_hdr
					:
				&((struct nm_rec *)record)->r_rec_hdr);
			n = ((devid_nm & NM_DEVID) ?
				((caddr_t)&((struct devid_min_rec *)
					record)->minor_name[0]) :
				((caddr_t)&((struct nm_rec *)
					record)->r_name[0]));
		}
	}
	/*NOTREACHED*/
}

int
remove_shared_entry(
	struct nm_next_hdr *nh,	/* First record header to start lookup */
	mdkey_t key,		/* Shared key, used as key if nm is NULL */
	char *nm,		/* Shared name, used as key if non-NULL */
	int devid_nm)		/* which name space? */
{
	struct nm_rec_hdr	*rh = (struct nm_rec_hdr *)nh->nmn_record;
	struct nm_next_hdr	*this_nh = nh->nmn_nextp;
	void			*record = this_nh->nmn_record;
	struct nm_rec_hdr	*this_rh;
	caddr_t			shn;
	mddb_recid_t		recid = rh->r_next_recid;
	size_t			offset, shn_offset;
	size_t			nm_len = 0, shn_size;
	mdkey_t			shn_key;
	ushort_t		shn_namlen;

	if (nm == (char *)0) {
		/* No name.  Search by key only. */
		if (key == MD_KEYBAD) {
			/* No key either.  Nothing to remove. */
			return (0);
		}
	} else {
		/* How long is the name? */
		nm_len = ((devid_nm & NM_DEVID) ?
			ddi_devid_sizeof((ddi_devid_t)nm) :
			(strlen(nm) + 1));
	}

	this_rh = ((devid_nm & NM_DEVID) ?
		&((struct devid_shr_rec *)record)->did_rec_hdr :
		&((struct nm_shr_rec *)record)->sr_rec_hdr);

	shn_offset = offset = ((devid_nm & NM_DEVID) ?
		(sizeof (struct devid_shr_rec) - sizeof (struct did_shr_name))
			:
		(sizeof (struct nm_shr_rec) - sizeof (struct nm_shared_name)));

	shn = ((devid_nm & NM_DEVID) ?
		((caddr_t)&((struct devid_shr_rec *)record)->device_id[0]) :
		((caddr_t)&((struct nm_shr_rec *)record)->sr_name[0]));

	/*CONSTCOND*/
	while (1) {

		if (devid_nm & NM_DEVID) {
			shn_key = ((struct did_shr_name *)shn)->did_key;
			shn_namlen = ((struct did_shr_name *)shn)->did_size;
			shn_size = DID_SHR_NAMSIZ((struct did_shr_name *)shn);
		} else {
			shn_key = ((struct nm_shared_name *)shn)->sn_key;
			shn_namlen = ((struct nm_shared_name *)shn)->sn_namlen;
			shn_size = SHR_NAMSIZ((struct nm_shared_name *)shn);
		}

		if ((key != 0) && (key == shn_key))
			return (rem_shr_entry(this_nh, recid, (char *)shn,
				shn_size, offset, devid_nm));

		if (nm_len == shn_namlen) {
			if (!devid_nm) {
			    if (strcmp(nm, ((struct nm_shared_name *)
					shn)->sn_name) == 0)
				return (rem_shr_entry(this_nh, recid,
					(char *)shn, shn_size, offset,
					devid_nm));
			} else {

				if (nm == NULL ||
				    ((struct did_shr_name *)shn)->did_devid
				    == NULL) {
					return (0);
				}
			    if (ddi_devid_compare((ddi_devid_t)nm,
				(ddi_devid_t)(((struct did_shr_name *)shn)->
					did_devid)) == 0)
				return (rem_shr_entry(this_nh, recid,
					(char *)shn, shn_size, offset,
					devid_nm));
			}
		}

		shn = (caddr_t)get_next_entry(this_nh,
			(caddr_t)shn, shn_size, &offset);

		if (shn == (caddr_t)0) {
			if (offset)
				return (ENOENT);

			/* Go to next record */
			offset = shn_offset;
			this_nh = this_nh->nmn_nextp;
			record = this_nh->nmn_record;
			recid = this_rh->r_next_recid;
			this_rh = ((devid_nm & NM_DEVID) ?
				&((struct devid_shr_rec *)record)->did_rec_hdr :
				&((struct nm_shr_rec *)record)->sr_rec_hdr);
			shn = ((devid_nm & NM_DEVID) ?
				((caddr_t)&((struct devid_shr_rec *)
					record)->device_id[0]) :
				((caddr_t)&((struct nm_shr_rec *)
					record)->sr_name[0]));
		}
	}
	/*NOTREACHED*/
}

static md_dev64_t
build_device_number(set_t setno, struct nm_name *n)
{
	major_t	maj;
	char	*shn;
	md_dev64_t dev;

	/*
	 * Can't determine the driver name
	 */
	if ((shn = (char *)getshared_name(setno, n->n_drv_key, 0L)) == NULL)
		return (NODEV64);

	if (MD_UPGRADE)
		maj = md_targ_name_to_major(shn);
	else
		maj = ddi_name_to_major(shn);

	if (maj == (major_t)-1)
		return (NODEV64);
	dev = md_makedevice(maj, n->n_minor);

	return (dev);
}

void *
lookup_entry(
	struct nm_next_hdr	*nh,	/* head record header */
	set_t			setno,	/* set to lookup in */
	side_t			side,	/* (key 1) side number */
	mdkey_t			key,	/* (key 2) from md_setdevname */
	md_dev64_t		dev,	/* (alt. key 2) use if key == KEYWILD */
	int			devid_nm /* Which name space? */
)
{
	struct nm_next_hdr	*this_nh = nh->nmn_nextp;
	void			*record;
	struct nm_rec_hdr	*this_rh;
	caddr_t			n;
	size_t			offset, n_offset, n_size;
	side_t			n_side;
	mdkey_t			n_key;

	if ((key == MD_KEYWILD) && (dev == NODEV64))
		return ((void *)0);

	if (this_nh == NULL)
		return ((void *)0);

	record = this_nh->nmn_record;

	this_rh = ((devid_nm & NM_DEVID) ?
		&((struct devid_min_rec *)record)->min_rec_hdr :
		&((struct nm_rec *)record)->r_rec_hdr);

	/* code to see if EMPTY record */
	while (this_nh && this_rh->r_used_size == sizeof (struct nm_rec_hdr)) {
		/* Go to next record */
		this_nh = this_nh->nmn_nextp;
		if (this_nh == NULL)
			return ((void *)0);
		record = this_nh->nmn_record;
		this_rh = ((devid_nm & NM_DEVID) ?
			&((struct devid_min_rec *)record)->min_rec_hdr :
			&((struct nm_rec *)record)->r_rec_hdr);
	}

	/*
	 * n_offset will be used to reset offset
	 */
	n_offset = offset = ((devid_nm & NM_DEVID) ?
		(sizeof (struct devid_min_rec) - sizeof (struct did_min_name)) :
		(sizeof (struct nm_rec) - sizeof (struct nm_name)));

	n = ((devid_nm & NM_DEVID) ?
		((caddr_t)&((struct devid_min_rec *)record)->minor_name[0]) :
		((caddr_t)&((struct nm_rec *)record)->r_name[0]));

	/*CONSTCOND*/
	while (1) {

		if (devid_nm & NM_DEVID) {
			n_side = ((struct did_min_name *)n)->min_side;
			n_key = ((struct did_min_name *)n)->min_key;
			n_size = DID_NAMSIZ((struct did_min_name *)n);
		} else {
			n_side = ((struct nm_name *)n)->n_side;
			n_key = ((struct nm_name *)n)->n_key;
			n_size = NAMSIZ((struct nm_name *)n);
		}

		if ((side == n_side) || (side == MD_SIDEWILD)) {

			if ((key != MD_KEYWILD) && (key == n_key))
				return ((void *)n);

			if ((key == MD_KEYWILD) && !devid_nm &&
			    (dev == build_device_number(setno,
			    (struct nm_name *)n)))
				return ((void *)n);
		}

		n = (caddr_t)get_next_entry(this_nh, n, n_size, &offset);

		if (n == NULL) {
			/*
			 * No next record, return
			 */
			if (offset)
				return ((void *)n);

			/* Go to next record */
			offset = n_offset;
			this_nh = this_nh->nmn_nextp;
			record = this_nh->nmn_record;
			this_rh = ((devid_nm & NM_DEVID) ?
			    &((struct devid_min_rec *)record)->min_rec_hdr :
			    &((struct nm_rec *)record)->r_rec_hdr);
			n = ((devid_nm & NM_DEVID) ?
				((caddr_t)&((struct devid_min_rec *)
					record)->minor_name[0]) :
				((caddr_t)&((struct nm_rec *)
					record)->r_name[0]));
		}
	}
	/*NOTREACHED*/
}

static int
is_meta_drive(set_t setno, mdkey_t key)
{
	int				i;
	struct nm_next_hdr		*nh;
	struct nm_shared_name		*shn;

	if ((nh = get_first_record(setno, 0, NM_SHARED)) == NULL)
		return (FALSE);
	if ((shn = (struct nm_shared_name *)lookup_shared_entry(nh,
		key, NULL, NULL, NM_SHARED)) == NULL) {
		return (FALSE);
	}

	/* See if the name is a metadevice. */
	for (i = 0; i < META_NAME_COUNT; i++) {
		if (strcmp(meta_names[i], shn->sn_name) == 0)
			return (TRUE);
	}
	return (FALSE);
}

static lookup_dev_result_t
lookup_deventry(
	struct nm_next_hdr	*nh,	/* head record header */
	set_t			setno,	/* set to lookup in */
	side_t			side,	/* (key 1) side number */
	mdkey_t			key,	/* (key 2) from md_setdevname */
	char			*drvnm,	/* drvnm to be stored */
	minor_t			mnum,	/* minor number to be stored */
	char			*dirnm,	/* directory name to be stored */
	char			*filenm, /* device filename to be stored */
	struct nm_name		**ret_rec /* place return found rec. */
)
{
	struct nm_next_hdr	*this_nh = nh->nmn_nextp;
	struct nm_rec		*record;
	struct nm_rec_hdr	*this_rh;
	struct nm_name		*n;
	size_t			offset;
	mdkey_t			dirkey, drvkey;

	*ret_rec = NULL;
	if (this_nh == NULL)
		return (LOOKUP_DEV_NOMATCH);

	record = (struct nm_rec *)this_nh->nmn_record;
	this_rh = &record->r_rec_hdr;
	n = &record->r_name[0];

	offset = sizeof (struct nm_rec) - sizeof (struct nm_name);

	if ((drvkey = getshared_key(setno, drvnm, 0L)) == MD_KEYBAD)
		return (LOOKUP_DEV_NOMATCH);

	if (dirnm == NULL) {
		/* No directory name to look up. */
		dirkey = MD_KEYBAD;
	} else {
		/* Look up the directory name */
		if ((dirkey = getshared_key(setno, dirnm, 0L)) == MD_KEYBAD)
			return (LOOKUP_DEV_NOMATCH);
	}
	ASSERT(side != MD_SIDEWILD);

	/* code to see if EMPTY record */
	while (this_nh && this_rh->r_used_size == sizeof (struct nm_rec_hdr)) {
		/* Go to next record */
		this_nh = this_nh->nmn_nextp;
		if (this_nh == NULL)
			return (LOOKUP_DEV_NOMATCH);
		record = (struct nm_rec *)this_nh->nmn_record;
		this_rh = &record->r_rec_hdr;
		n = &record->r_name[0];
	}

	/*CONSTCOND*/
	while (1) {
		if ((side == n->n_side) &&
		    ((key == MD_KEYWILD) || (key == n->n_key)) &&
		    (mnum == n->n_minor) &&
		    (drvkey == n->n_drv_key) &&
		    (dirkey == n->n_dir_key) &&
		    (strcmp(filenm, n->n_name) == 0)) {
			*ret_rec = n;
			return (LOOKUP_DEV_FOUND);
		}

		/*
		 * Now check for a name conflict.  If the filenm of the
		 * current record matches filename passed in we have a
		 * potential conflict.  If all the other parameters match
		 * except for the side number, then this is not a
		 * conflict.  The reason is that there are cases where name
		 * record is added to each side of a set.
		 *
		 * There is one additional complication.  It is only a
		 * conflict if the drvkeys both represent metadevices.  It
		 * is legal for a metadevice and a physical device to have
		 * the same name.
		 */
		if (strcmp(filenm, n->n_name) == 0) {
			int	both_meta;

			/*
			 * It is hsp and we are trying to add it twice
			 */
			if (strcmp(getshared_name(setno, n->n_drv_key, 0L),
			    MD_HOTSPARES) == 0 && (side == n->n_side) &&
			    find_hot_spare_pool(setno,
				KEY_TO_HSP_ID(setno, n->n_key)) == NULL) {
				/*
				 * All entries removed
				 */
				rw_exit(&nm_lock.lock);
				(void) md_rem_hspname(setno, n->n_key);
				rw_enter(&nm_lock.lock, RW_WRITER);
				return (LOOKUP_DEV_NOMATCH);
			}

			/*
			 * It is metadevice and we are trying to add it twice
			 */
			if (md_set[setno].s_un[MD_MIN2UNIT(n->n_minor)]
				== NULL && (side == n->n_side) &&
			    ddi_name_to_major(getshared_name(setno,
				n->n_drv_key, 0L)) == md_major) {
				/*
				 * Apparently it is invalid so
				 * clean it up
				 */
				md_remove_minor_node(n->n_minor);
				rw_exit(&nm_lock.lock);
				(void) md_rem_selfname(n->n_minor);
				rw_enter(&nm_lock.lock, RW_WRITER);
				return (LOOKUP_DEV_NOMATCH);
			}

			/* First see if the two drives are metadevices. */
			if (is_meta_drive(setno, drvkey) &&
				is_meta_drive(setno, n->n_drv_key)) {
				both_meta = TRUE;
			} else {
				both_meta = FALSE;
			}
			/* Check rest of the parameters. */
			if ((both_meta == TRUE) &&
				((key != n->n_key) ||
				(mnum != n->n_minor) ||
				(drvkey != n->n_drv_key) ||
				(dirkey != n->n_dir_key))) {
				return (LOOKUP_DEV_CONFLICT);
			}
		}
		n = (struct nm_name *)get_next_entry(this_nh, (caddr_t)n,
		    NAMSIZ(n), &offset);

		if (n == (struct nm_name *)0) {
			if (offset)
				return (LOOKUP_DEV_NOMATCH);

			/* Go to next record */
			offset = sizeof (struct nm_rec) -
			    sizeof (struct nm_name);
			this_nh = this_nh->nmn_nextp;
			record = (struct nm_rec *)this_nh->nmn_record;
			this_rh = &record->r_rec_hdr;
			n = &record->r_name[0];
		}
	}
	/*NOTREACHED*/
}

void *
lookup_shared_entry(
	struct nm_next_hdr *nh,	/* First record header to start lookup */
	mdkey_t key,		/* Shared key, used as key if nm is NULL */
	char *nm,		/* Shared name, used as key if non-NULL */
	mddb_recid_t *id,	/* mddb record id of record entry is found in */
	int	devid_nm)	/* which name space? */
{
	struct nm_rec_hdr	*rh = (struct nm_rec_hdr *)nh->nmn_record;
	struct nm_next_hdr	*this_nh = nh->nmn_nextp;
	void			*record;
	struct nm_rec_hdr	*this_rh;
	caddr_t			shn;
	size_t			offset, shn_offset;
	size_t			nm_len = 0, shn_size;
	mdkey_t			shn_key;
	ushort_t		shn_namlen;

	if (this_nh == NULL)
		return ((void *)0);

	record = this_nh->nmn_record;

	if (nm != (char *)0)
		nm_len = ((devid_nm & NM_DEVID) ?
			ddi_devid_sizeof((ddi_devid_t)nm) :
			(strlen(nm) + 1));

	if (id != NULL)
		*id = rh->r_next_recid;

	this_rh = ((devid_nm & NM_DEVID) ?
		&((struct devid_shr_rec *)record)->did_rec_hdr :
		&((struct nm_shr_rec *)record)->sr_rec_hdr);

	/* code to see if EMPTY record */
	while (this_nh && this_rh->r_used_size == sizeof (struct nm_rec_hdr)) {
		/* Go to next record */
		this_nh = this_nh->nmn_nextp;
		if (this_nh == NULL)
			return ((void *)0);
		record = this_nh->nmn_record;
		if (id != NULL)
			*id = this_rh->r_next_recid;

		this_rh = ((devid_nm & NM_DEVID) ?
			&((struct devid_shr_rec *)record)->did_rec_hdr :
			&((struct nm_shr_rec *)record)->sr_rec_hdr);
	}

	/*
	 * shn_offset will be used to reset offset
	 */
	shn_offset = offset = ((devid_nm & NM_DEVID) ?
		(sizeof (struct devid_shr_rec) - sizeof (struct did_shr_name)) :
		(sizeof (struct nm_shr_rec) - sizeof (struct nm_shared_name)));

	shn = ((devid_nm & NM_DEVID) ?
		((caddr_t)&((struct devid_shr_rec *)record)->device_id[0]) :
		((caddr_t)&((struct nm_shr_rec *)record)->sr_name[0]));

	/*CONSTCOND*/
	while (1) {

		if (devid_nm & NM_DEVID) {
			shn_key = ((struct did_shr_name *)shn)->did_key;
			shn_namlen = ((struct did_shr_name *)shn)->did_size;
			shn_size = DID_SHR_NAMSIZ((struct did_shr_name *)shn);
		} else {
			shn_key = ((struct nm_shared_name *)shn)->sn_key;
			shn_namlen = ((struct nm_shared_name *)shn)->sn_namlen;
			shn_size = SHR_NAMSIZ((struct nm_shared_name *)shn);
		}

		if ((key != 0) && (key == shn_key))
			return ((void *)shn);

		/* Lookup by name */
		if (nm != NULL) {
		    if (devid_nm & NM_IMP_SHARED) {
			/*
			 * the nm passed in is "/dev/md" in the import case
			 * and we want to do a partial match on that.
			 */
			if (strncmp(nm, ((struct nm_shared_name *)shn)->sn_name,
			    strlen(nm)) == 0)
			    return ((void *)shn);
		    } else if (nm_len == shn_namlen) {
			if (devid_nm & NM_DEVID) {
			    if (ddi_devid_compare((ddi_devid_t)nm,
				(ddi_devid_t)(((struct did_shr_name *)shn)->
					did_devid)) == 0)
				return ((void *)shn);
			} else {
			    if (strcmp(nm, ((struct nm_shared_name *)
					shn)->sn_name) == 0)
				return ((void *)shn);
			}
		    }
		}

		shn = (caddr_t)get_next_entry(this_nh,
		    (caddr_t)shn, shn_size, &offset);

		if (shn == (caddr_t)0) {
			/*
			 * No next record, return
			 */
			if (offset)
				return ((void *)shn);

			/* Go to next record */
			offset = shn_offset;
			this_nh = this_nh->nmn_nextp;
			record = this_nh->nmn_record;
			if (id != NULL)
				*id = this_rh->r_next_recid;
			this_rh = ((devid_nm & NM_DEVID) ?
				&((struct devid_shr_rec *)record)->did_rec_hdr :
				&((struct nm_shr_rec *)record)->sr_rec_hdr);
			shn = ((devid_nm & NM_DEVID) ?
				((caddr_t)&((struct devid_shr_rec *)
					record)->device_id[0]) :
				((caddr_t)&((struct nm_shr_rec *)
					record)->sr_name[0]));
		}
	}
	/*NOTREACHED*/
}


/*
 * lookup_hspentry - Getting a hotspare pool entry from the namespace.
 *		     Use either the NM key or the hotspare name to find
 *		     a matching record in the namespace of the set.
 */
void *
lookup_hspentry(
	struct nm_next_hdr	*nh,	/* head record header */
	set_t			setno,	/* set to lookup in */
	side_t			side,	/* (key 1) side number */
	mdkey_t			key,	/* (key 2) from md_setdevname */
	char			*name	/* (alt. key 2), if key == MD_KEYWILD */
)
{
	struct nm_next_hdr	*this_nh = nh->nmn_nextp;
	struct nm_rec		*record;
	struct nm_rec_hdr	*this_rh;
	struct nm_name		*n;
	size_t			offset, n_offset, n_size;
	side_t			n_side;
	mdkey_t			n_key;
	char			*drv_name;
	char			*tmpname;
	char			*setname = NULL;

	if ((key == MD_KEYWILD) && (name == '\0'))
		return ((void *)0);

	if (this_nh == NULL)
		return ((void *)0);

	record = (struct nm_rec *)this_nh->nmn_record;

	this_rh = &record->r_rec_hdr;

	if (setno != MD_LOCAL_SET) {
		setname = mddb_getsetname(setno);
		if (setname == NULL)
			return ((void *)0);
	}

	/* code to see if EMPTY record */
	while (this_nh && this_rh->r_used_size == sizeof (struct nm_rec_hdr)) {
		/* Go to next record */
		this_nh = this_nh->nmn_nextp;
		if (this_nh == NULL)
			return ((void *)0);
		record = this_nh->nmn_record;
		this_rh = &record->r_rec_hdr;
	}

	/*
	 * n_offset will be used to reset offset
	 */
	n_offset = offset = (sizeof (struct nm_rec) - sizeof (struct nm_name));

	n = ((struct nm_name *)&record->r_name[0]);

	tmpname = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	/*CONSTCOND*/
	while (1) {
		n_side = n->n_side;
		n_size = NAMSIZ(n);
		if ((drv_name = (char *)getshared_name(setno,
		    n->n_drv_key, 0L)) != NULL) {

			/* We're only interested in hsp NM records */
			if ((strcmp(drv_name, "md_hotspares") == 0) &&
			    ((side == n_side) || (side == MD_SIDEWILD))) {
				n_key = n->n_key;

				if ((key != MD_KEYWILD) && (key == n_key))
					goto done;

				/*
				 * Searching by a hotspare pool name.
				 * Since the input name is of the form
				 * setname/hsp_name, we need to attach
				 * the string 'setname/' in front of the
				 * n->n_name.
				 */
				if (key == MD_KEYWILD) {
					if (setname != NULL)
					    (void) snprintf(tmpname, MAXPATHLEN,
						"%s/%s", setname,
						((struct nm_name *)n)->n_name);
					else
					    (void) snprintf(tmpname, MAXPATHLEN,
						"%s",
						((struct nm_name *)n)->n_name);

					if ((strcmp(name, tmpname)) == 0)
						goto done;
				}
			}
		}

		n = (struct nm_name *)get_next_entry(this_nh, (caddr_t)n,
		    n_size, &offset);

		if (n == NULL) {
			/*
			 * No next record, return
			 */
			if (offset)
				goto done;

			/* Go to next record */
			offset = n_offset;
			this_nh = this_nh->nmn_nextp;
			record = (struct nm_rec *)this_nh->nmn_record;
			this_rh = &record->r_rec_hdr;
			n = ((struct nm_name *)&record->r_name[0]);
		}
	}

done:
	kmem_free(tmpname, MAXPATHLEN);
	return ((void *)n);
}

static int
md_make_devname(struct nm_name *n, set_t setno, char *string, size_t max_size)
{

	char	*dir_name;
	size_t	dir_len;

	/*
	 * Can't determine the path
	 */
	if ((dir_name =
	    (char *)getshared_name(setno, n->n_dir_key, 0L)) == NULL)
		return ((int)NODEV64);

	dir_len = strlen(dir_name);
	if ((dir_len + n->n_namlen) > max_size)
		return (EFAULT);

	/* Tack the directory and device strings together */
	(void) strcpy(strcpy(string, dir_name) + dir_len, n->n_name);
	return (0);
}

static void
build_rec_hdr_list(struct nm_next_hdr *nh, mddb_recid_t recid, int shared)
{
	size_t			overhead_size;
	struct nm_rec_hdr	*this_rh;
	uint_t			private;
	struct nm_rec_hdr	*rh = (struct nm_rec_hdr *)nh->nmn_record;
	struct nm_next_hdr	*this_nh;
	set_t			setno;
	int			multi_node = 0;

	/* If given record is for a multi_node set, set flag */
	setno = DBSET(recid);
	if (MD_MNSET_SETNO(setno))
		multi_node = 1;

	if (shared & NM_DEVID)
		overhead_size = ((shared & NM_SHARED) ?
		(sizeof (struct devid_shr_rec) - sizeof (struct did_shr_name))
				:
		(sizeof (struct devid_min_rec) - sizeof (struct did_min_name)));
	else
		overhead_size = ((shared & NM_SHARED) ?
		(sizeof (struct nm_shr_rec) - sizeof (struct nm_shared_name)) :
		(sizeof (struct nm_rec) - sizeof (struct nm_name)));

	while (rh->r_next_recid > 0) {
		this_nh = kmem_zalloc(sizeof (*this_nh), KM_SLEEP);
		nh->nmn_nextp = this_nh;
		this_nh->nmn_record = mddb_getrecaddr(rh->r_next_recid);

		ASSERT(this_nh->nmn_record != NULL);

		if (shared & NM_DEVID)
		    this_rh = ((shared & NM_SHARED) ?
		    &((struct devid_shr_rec *)this_nh->nmn_record)->did_rec_hdr
			:
		    &((struct devid_min_rec *)
		    this_nh->nmn_record)->min_rec_hdr);
		else
		    this_rh = ((shared & NM_SHARED) ?
		    &((struct nm_shr_rec *)this_nh->nmn_record)->sr_rec_hdr :
		    &((struct nm_rec *)this_nh->nmn_record)->r_rec_hdr);

		/*
		 * Check for empty records and clean them up.
		 * For a MN diskset, only do this if master.
		 */
		if ((!multi_node) ||
		    (multi_node && md_set[setno].s_am_i_master)) {
			if (this_rh->r_used_size == overhead_size) {
				mddb_setrecprivate(rh->r_next_recid,
					MD_PRV_PENDDEL);
				rh->r_next_recid = this_rh->r_next_recid;
				kmem_free(this_nh, sizeof (*this_nh));
				nh->nmn_nextp = NULL;
				mddb_setrecprivate(recid, MD_PRV_PENDCOM);
				continue;
			}
		}

		private = mddb_getrecprivate(rh->r_next_recid);
		mddb_setrecprivate(rh->r_next_recid, (private | MD_PRV_GOTIT));
		recid = rh->r_next_recid;
		rh = this_rh;
		nh = this_nh;
	}
}

static void
zero_data_ptrs(struct nm_next_hdr *nh, set_t setno)
{
	mdkey_t	i;
	struct nm_rec_hdr	*rh = (struct nm_rec_hdr *)nh->nmn_record;

	if (rh->r_next_recid == 0)
		return;

	for (i = MDDB_FIRST_MODID; i < rh->r_next_key; i++)
		(void) setshared_data(setno, i, (caddr_t)-1);
}

/*
 * md_setdevname - Allows putting a device name into the database
 */
mdkey_t
md_setdevname(
	set_t		setno,	/* specify which namespace to put in */
	side_t		side,	/* (key 1) side # */
	mdkey_t		key,	/* (key 2) KEYWILD - alloc key, else use key */
	char		*drvnm,	/* store this driver name with devicename */
	minor_t		mnum,	/* store this minor number as well */
	char		*devname,	/* device name to be stored */
	int		imp_flag,	/* used exclusively by import */
	ddi_devid_t	imp_devid,	/* used exclusively by import */
	char		*imp_mname,	/* used exclusively by import */
	set_t		imp_setno,	/* used exclusively by import */
	md_error_t	*ep		/* place to return error info */
)
{
	struct nm_next_hdr	*nh, *did_nh = NULL;
	struct nm_name		*n;
	struct did_min_name	*did_n;
	struct did_min_name	*new_did_n;
	mddb_recid_t		recids[3];
	char			*cp, *dname = NULL, *fname;
	char			c;
	mdkey_t			retval = MD_KEYBAD;
	int			shared = -1, new = 0;
	ddi_devid_t		devid = NULL;
	dev_t			devt;
	char			*mname = NULL;
	side_t			thisside = MD_SIDEWILD;
	lookup_dev_result_t	lookup_res;
	mdkey_t			min_devid_key = MD_KEYWILD;
	size_t			min_len;
	int			use_devid = 0;
	side_t			temp_side;

	/*
	 * Don't allow addition of new names to namespace during upgrade.
	 */
	if (MD_UPGRADE)  {
		return (MD_KEYBAD);
	}

	/*
	 * Make sure devname is not empty
	 */
	if (devname == (char *)NULL || strncmp(devname, "", 1) == 0) {
		cmn_err(CE_WARN, "Unknown device with minor number of %d",
		    mnum);
		return (MD_KEYBAD);
	}

	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (MD_KEYBAD);
	}

	/*
	 * Go looking for an existing devid namespace record for this
	 * key. We need to do this here as md_devid_found() also
	 * requires the nm_lock.lock.
	 */
	if ((!imp_flag) && (setno == MD_LOCAL_SET) && (side > 0) &&
	    (key != MD_KEYWILD)) {
		/*
		 * We must be adding a namespace record for a disk in a
		 * shared metaset of some description. As we already have a
		 * key, walk all the valid sides for the set and see if we
		 * have a devid record present. This will be used to help
		 * determine which namespace we add this new record into.
		 */
		for (temp_side = 1; temp_side < MD_MAXSIDES; temp_side++) {
			if (md_devid_found(setno, temp_side, key) == 0) {
				/*
				 * We have a devid record for this key.
				 * Assume it's safe to use devid's for the
				 * other side records as well.
				 */
				use_devid = 1;
				break;
			}
		}
	}

	rw_enter(&nm_lock.lock, RW_WRITER);

	/*
	 * Find out what namespace/set/side combination that is
	 * being dealt with. If this is not done then we stand a
	 * chance of adding in incorrect devid details to match
	 * the remote side's disk information. For example:
	 * disk c2t0d0s0 may have devt of 32,256 on this side
	 * but 32,567 on the remote side and if this is the case
	 * we do not want to add the devid for disk 32,567 on
	 * this side into the namespace.
	 */
	if (setno == MD_LOCAL_SET && side == 0)
		/* local set/local side */
		thisside = side;
	else if (setno == MD_LOCAL_SET && side > 0) {
		/*
		 * local set/non-local side information ie a set record
		 *
		 * if the key is not set then this is the first time
		 * through this code which means this is the first record
		 * which then means the record to be added is for this node
		 */
		if (key == MD_KEYWILD) {
			thisside = side;
		} else {
			/*
			 * This is not the first time through this code,
			 * so we have already got a record in the namespace.
			 * Check if the earlier search for this record found
			 * a devid record or not, and set the namespace
			 * accordingly.
			 */
			if (use_devid == 1) {
				/* A devid record exists */
				shared = NM_DEVID | NM_NOTSHARED;
			} else {
				/* No devid record exists for this key */
				shared = NM_NOTSHARED;
			}
		}
	} else if (setno != MD_LOCAL_SET) {
		/* set record */
		thisside = mddb_getsidenum(setno);
	}

	/*
	 * Check to see if it has a device id associated with
	 * and if the MDDB_DEVID_STYLE flag is set. If the device
	 * is a metadevice the get_minor_name will fail. No account
	 * of the side information is taken here because it is dealt
	 * with later on.
	 */
	if (!imp_flag) {
		/*
		 * Only do this if we have not already set the namespace type,
		 * otherwise we run the risk of adding a record for an invalid
		 * minor number from a remote node.
		 */
		if (shared == -1) {
			devt = makedevice(ddi_name_to_major(drvnm), mnum);
			if ((ddi_lyr_get_devid(devt, &devid) == DDI_SUCCESS) &&
			    (ddi_lyr_get_minor_name(devt, S_IFBLK, &mname) ==
			    DDI_SUCCESS) &&
			    (((mddb_set_t *)md_set[setno].s_db)->s_lbp->lb_flags
			    & MDDB_DEVID_STYLE))
				/*
				 * Reference the device id namespace
				 */
				shared = NM_DEVID | NM_NOTSHARED;
			else
				shared = NM_NOTSHARED;
		}
	} else {
		/* Importing diskset has devids so store in namespace */
		devid = kmem_alloc(ddi_devid_sizeof(imp_devid), KM_SLEEP);
		bcopy(imp_devid, devid, ddi_devid_sizeof(imp_devid));
		mname = md_strdup(imp_mname);
		shared = NM_DEVID | NM_NOTSHARED;
	}

	/*
	 * Always lookup the primary name space
	 */
	if ((nh = get_first_record(setno, 1, NM_NOTSHARED)) == NULL) {
		retval = MD_KEYBAD;
		goto out;
	}

	/*
	 * If it has a device id then get the header for the devid namespace
	 */
	if (shared & NM_DEVID) {
		if ((did_nh = get_first_record(setno, 1, shared)) == NULL) {
			retval = MD_KEYBAD;
			goto out;
		}
	}

	/* find boundary between filename and directory */
	cp = strrchr(devname, '/');

	if (cp == NULL) {
		/* No directory part to the name. */
		fname = devname;
		dname = NULL;
	} else {
		/* Isolate the directory name only; save character after '/' */
		c = *(cp + 1);
		*(cp + 1) = '\0';
		dname = md_strdup(devname);

		/* Restore character after '/' */
		*(cp + 1) = c;
		fname = cp+1;
	}

	/*
	 * If it already there in the name space
	 */
	lookup_res = lookup_deventry(nh, setno, side, key, drvnm, mnum, dname,
		fname, &n);

	/* If we are importing the set */
	if (imp_flag && (lookup_res == LOOKUP_DEV_FOUND)) {
		ushort_t	did_sz;
		ddi_devid_t	did;

		/*
		 * We need to check for the case where there is a disk
		 * already in the namespace with a different ID from
		 * the one we want to add, but the same name. This is
		 * possible in the case of an unavailable disk.
		 */
		rw_exit(&nm_lock.lock);
		if (md_getdevid(setno, side, n->n_key, NULL, &did_sz) != 0)
			did_sz = 0;
		rw_enter(&nm_lock.lock, RW_WRITER);
		if (did_sz > 0) {
			did = kmem_zalloc(did_sz, KM_SLEEP);
			rw_exit(&nm_lock.lock);
			(void) md_getdevid(setno, side, n->n_key, did, &did_sz);
			rw_enter(&nm_lock.lock, RW_WRITER);
			if (ddi_devid_compare(did, devid) == 0) {
				kmem_free(did, did_sz);
				retval = 0;
				goto out;
			}
			kmem_free(did, did_sz);
		}
		/*
		 * This is not the same disk so we haven't really found it.
		 * Thus, we need to say it's "NOMATCH" and create a new
		 * entry.
		 */
		lookup_res = LOOKUP_DEV_NOMATCH;
	}
	switch (lookup_res) {
	case LOOKUP_DEV_FOUND:
		/* If we are importing the set */
		if (md_get_setstatus(imp_setno) & MD_SET_IMPORT) {
			retval = 0;
			goto out;
		}

		/* Increment reference count */
		retval = n->n_key;
		n->n_count++;
		(void) update_entry(nh, n->n_side, n->n_key, 0L);

		/* Also in the device id name space if there is one */
		if (did_nh) {
			/*
			 * Use thisside for the sideno as this is the
			 * side this is running on.
			 */
			if ((did_n = (struct did_min_name *)
			    lookup_entry(did_nh, setno, side, n->n_key,
				NODEV64, NM_DEVID)) != NULL) {

				did_n->min_count++;
				(void) update_entry(did_nh, did_n->min_side,
						did_n->min_key, NM_DEVID);
			} else {
				/*
				 * If a disk device does not support
				 * devid then we would fail to find the
				 * device and then try and add it, bit
				 * silly.
				 */
				goto add_devid;
			}
		}
		goto out;

	case LOOKUP_DEV_CONFLICT:
		(void) mderror(ep, MDE_NAME_IN_USE);
		retval = MD_KEYBAD;
		goto out;

	case LOOKUP_DEV_NOMATCH:
		/* Create a new name entry */
		new = 1;
		n = (struct nm_name *)alloc_entry(nh, md_set[setno].s_nmid,
		    strlen(fname)+1, NM_NOTSHARED, &recids[0]);

		if (n == NULL)
			goto out;

		n->n_minor = mnum;
		n->n_side = side;
		n->n_key = ((key == MD_KEYWILD) ? create_key(nh) : key);
		n->n_count = 1;

		/* fill-in filename */
		(void) strcpy(n->n_name, fname);
		n->n_namlen = (ushort_t)(strlen(fname) + 1);

		/*
		 * If MDE_DB_NOSPACE occurs
		 */
		if (((n->n_drv_key =
			setshared_name(setno, drvnm, MD_KEYWILD, 0L)) ==
			MD_KEYBAD)) {
			/*
			 * Remove entry allocated by alloc_entry
			 * and return MD_KEYBAD
			 */
			(void) remove_entry(nh, n->n_side, n->n_key, 0L);
			goto out;
		}
		if (dname == NULL) {
			/* No directory name implies no key. */
			n->n_dir_key = MD_KEYBAD;
		} else {
			/* We have a directory name to save. */
			if ((n->n_dir_key =
				setshared_name(setno, dname, MD_KEYWILD, 0L)) ==
				MD_KEYBAD) {
				/*
				 * Remove entry allocated by alloc_entry
				 * and return MD_KEYBAD
				 */
				(void) remove_entry(nh, n->n_side, n->n_key,
					0L);
				goto out;
			}
		}

		recids[1] = md_set[setno].s_nmid;
		recids[2] = 0;
		mddb_commitrecs_wrapper(recids);
		retval = n->n_key;

		/*
		 * Now to find out if devid's were used for thisside and if
		 * so what is the devid_key for the entry so that the correct
		 * minor name entry (did_n) has the correct devid key.
		 * Also get the minor name of the device, use the minor name
		 * on this side because the assumption is that the slices are
		 * going to be consistant across the nodes.
		 */
		if (key != MD_KEYWILD && (shared & NM_DEVID)) {
			if ((did_n = (struct did_min_name *)
			    lookup_entry(did_nh, setno, thisside, n->n_key,
			    NODEV64, NM_DEVID)) == NULL) {
				shared &= ~NM_DEVID;
			} else {
				min_devid_key = did_n->min_devid_key;
				min_len = (size_t)did_n->min_namlen;
				/*
				 * Need to save the min_name as well because
				 * if the alloc_entry() needs to expand the
				 * record then it will free the existing
				 * record (which will free any references
				 * to information within it ie did_n->min_name)
				 */
				if (mname != NULL) {
					kmem_free(mname, strlen(mname) + 1);
				}
				mname = kmem_alloc(min_len, KM_SLEEP);
				(void) strcpy(mname, did_n->min_name);
			}
		} else {

			/*
			 * It is possible for the minor name to be null, for
			 * example a metadevice which means the minor name is
			 * not initialised.
			 */
			if (mname == NULL)
				goto out;

			min_len = strlen(mname) + 1;
		}
		break;
	}

	/*
	 * We have the key and if the NM_DEVID bit is on
	 * use the key to add the device id into the device id name space
	 */

add_devid:

	if (shared & NM_DEVID) {
		new_did_n = (struct did_min_name *)alloc_entry(did_nh,
			md_set[setno].s_did_nmid, min_len,
			shared, &recids[0]);

		/*
		 * No space
		 */
		if (new_did_n == NULL) {
		    if (new) {
			(void) remove_entry(nh, n->n_side, n->n_key, 0L);
			retval = MD_KEYBAD;
		    }
		    goto out;
		}

		new_did_n->min_side = side;
		new_did_n->min_key = n->n_key;
		new_did_n->min_count = n->n_count;

		/*
		 * If the key is set then we know that there should
		 * be a corresponding devid entry because when the record
		 * associated with the key was created it would have created
		 * a corresponding devid entry, all we need to do is find
		 * that record and increment the count.
		 */
		if (key != MD_KEYWILD) {

			/*
			 * Need to copy the information from the original
			 * side (thisside).
			 */
			new_did_n->min_devid_key = min_devid_key;
			min_devid_key = setshared_name(setno,
			    (char *)NULL, min_devid_key, NM_DEVID);
			if (new_did_n->min_devid_key != min_devid_key) {
				cmn_err(CE_NOTE,
				    "addname: failed to add to record");
			}
			(void) strcpy(new_did_n->min_name, mname);
			new_did_n->min_namlen = (ushort_t)min_len;
		} else {

			/* use the did_n allocated above! */
			(void) strcpy(new_did_n->min_name, mname);
			new_did_n->min_namlen = (ushort_t)(strlen(mname) + 1);
			new_did_n->min_devid_key = setshared_name(setno,
			    (char *)devid, MD_KEYWILD, NM_DEVID);
		}
		/*
		 * If MDE_DB_NOSPACE occurs
		 */
		if (new_did_n->min_devid_key == MD_KEYBAD) {
			/*
			 * Remove entry allocated by alloc_entry
			 */
			(void) remove_entry(did_nh, new_did_n->min_side,
				new_did_n->min_key, NM_DEVID);
			if (new) {
			    (void) remove_entry(nh, n->n_side, n->n_key, 0L);
			    retval = MD_KEYBAD;
			}
		} else {
			recids[1] = md_set[setno].s_did_nmid;
			recids[2] = 0;
			mddb_commitrecs_wrapper(recids);
		}
	}
out:
	if (devid) {
		ddi_devid_free(devid);
	}
	if (dname)
		freestr(dname);
	if (mname)
		kmem_free(mname, strlen(mname) + 1);
	rw_exit(&nm_lock.lock);
	return (retval);
}

/*
 * md_get_invdid - return the invalid device id's
 */
int
md_get_invdid(
	set_t	setno,
	side_t	side,
	int	count,
	int	size,
	void	*ctdptr
)
{
	struct nm_next_hdr	*did_shr_nh, *did_nh = NULL, *nh = NULL;
	struct did_shr_name	*did_shr_n;
	struct did_min_name	*did_n;
	struct nm_name		*n;
	int			key = MD_KEYWILD;
	int			cnt = 0;
	char			*cptr = (char *)ctdptr;
	int			i, dont_add_it;
	char			*tmpctd;
	char			*diskname;
	char			*tmpname;

	/* first get the invalid devid's from the loc block */
	if ((cnt = mddb_getinvlb_devid(setno, count, size, &cptr)) == -1) {
		return (-1);
	}

	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (ENOENT);
	}

	rw_enter(&nm_lock.lock, RW_READER);

	did_nh = get_first_record(setno, 0, NM_DEVID | NM_NOTSHARED);
	if (did_nh == NULL) {
		rw_exit(&nm_lock.lock);
		return (0);
	}

	did_shr_nh = get_first_record(setno, 1, NM_DEVID | NM_SHARED);
	if (did_shr_nh == NULL) {
		rw_exit(&nm_lock.lock);
		return (0);
	}

	nh = get_first_record(setno, 0, NM_NOTSHARED);
	if (nh == NULL) {
		rw_exit(&nm_lock.lock);
		return (0);
	}
	while ((key = md_getnextkey(setno, side, key, NULL)) != MD_KEYWILD) {
		dev_t		devt;
		ddi_devid_t	rtn_devid = NULL;
		int		get_rc;
		int		compare_rc = 1;

		did_n = (struct did_min_name *)lookup_entry(
				did_nh, setno, side, key, NODEV64, NM_DEVID);
		if (did_n == NULL) {
			continue;
		}
		did_shr_n = (struct did_shr_name *)lookup_shared_entry(
				did_shr_nh, did_n->min_devid_key, (char *)0,
				NULL, NM_DEVID);
		if ((did_shr_n->did_data & NM_DEVID_VALID) != NULL) {
			continue;
		}
		/* found invalid device id. Add to list */
		devt = md_dev64_to_dev(
				md_getdevnum(setno, side, key, MD_TRUST_DEVT));
		get_rc = ddi_lyr_get_devid(devt, &rtn_devid);
		if (get_rc == DDI_SUCCESS) {
			compare_rc = ddi_devid_compare(rtn_devid,
			    (ddi_devid_t)did_shr_n-> did_devid);
			ddi_devid_free(rtn_devid);
		}

		if ((get_rc == DDI_SUCCESS) && (compare_rc == 0)) {
			did_shr_n->did_data |= NM_DEVID_VALID;
		} else {
			if (cnt++ > count) {
				rw_exit(&nm_lock.lock);
				return (-1);
			}
			n = (struct nm_name *)lookup_entry(
					nh, setno, side, key, NODEV64, 0L);
			if (n == NULL) {
				rw_exit(&nm_lock.lock);
				return ((int)NODEV64);
			}
			tmpctd = ctdptr;
			diskname = md_strdup(n->n_name);
			if (strlen(diskname) > size) {
				kmem_free(diskname, strlen(diskname) + 1);
				rw_exit(&nm_lock.lock);
				return (-1);
			}
			if ((tmpname = strrchr(diskname, 's')) != NULL)
			    *tmpname = '\0';
			dont_add_it = 0;
			for (i = 0; i < (cnt - 1); i++) {
				if (strcmp(diskname, tmpctd) == 0) {
					dont_add_it = 1;
					break;
				}
				tmpctd += size;
			}
			if (dont_add_it == 0) {
				(void) strcpy(cptr, diskname);
				cptr += size;
			}
			kmem_free(diskname, strlen(n->n_name) + 1);
		}
	}
	*cptr = '\0';
	rw_exit(&nm_lock.lock);
	return (0);
}
/*
 * md_validate_devid - Checks the device id's to see if they're valid.
 *			Returns a count of the number of invalid device id's
 */
int
md_validate_devid(
	set_t	setno,
	side_t	side,
	int	*rmaxsz
)
{
	struct nm_next_hdr	*did_shr_nh, *did_nh = NULL;
	struct did_shr_name	*did_shr_n;
	struct did_min_name	*did_n;
	struct nm_name		*n;
	struct nm_next_hdr	*nh = NULL;
	int			cnt = 0;
	int			key = MD_KEYWILD;
	int			maxsz = 0;
	int			len;

	/*
	 * do the locator blocks first...
	 */

	if ((cnt = mddb_validate_lb(setno, &maxsz)) == -1) {
		return (-1);
	}

	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (-1);
	}

	rw_enter(&nm_lock.lock, RW_READER);

	did_nh = get_first_record(setno, 0, NM_DEVID | NM_NOTSHARED);
	if (did_nh == NULL) {
		rw_exit(&nm_lock.lock);
		*rmaxsz = maxsz;
		return (cnt);
	}

	did_shr_nh = get_first_record(setno, 0, NM_DEVID | NM_SHARED);
	if (did_shr_nh == NULL) {
		rw_exit(&nm_lock.lock);
		*rmaxsz = maxsz;
		return (cnt);
	}

	nh = get_first_record(setno, 0, NM_NOTSHARED);
	if (nh == NULL) {
		rw_exit(&nm_lock.lock);
		*rmaxsz = maxsz;
		return (cnt);
	}
	while ((key = md_getnextkey(setno, side, key, NULL)) != MD_KEYWILD) {
		dev_t		devt;
		ddi_devid_t	rtn_devid = NULL;
		int		get_rc;
		int		compare_rc = 1;

		did_n = (struct did_min_name *)lookup_entry(
				did_nh, setno, side, key, NODEV64, NM_DEVID);
		if (did_n == NULL) {
			continue;
		}
		did_shr_n = (struct did_shr_name *)lookup_shared_entry(
				did_shr_nh, did_n->min_devid_key, (char *)0,
				NULL, NM_DEVID);
		if ((did_shr_n->did_data & NM_DEVID_VALID) != 0) {
			continue;
		}

		devt = md_dev64_to_dev(
				md_getdevnum(setno, side, key, MD_TRUST_DEVT));
		get_rc = ddi_lyr_get_devid(devt, &rtn_devid);
		if (get_rc == DDI_SUCCESS) {
			compare_rc = ddi_devid_compare(rtn_devid,
			    (ddi_devid_t)did_shr_n->did_devid);
			ddi_devid_free(rtn_devid);
		}

		if ((get_rc == DDI_SUCCESS) && (compare_rc == 0)) {
			did_shr_n->did_data |= NM_DEVID_VALID;
		} else {
			/* device id is invalid */
			cnt++;
			n = (struct nm_name *)lookup_entry(
					nh, setno, side, key, NODEV64, 0L);
			if (n == NULL) {
				rw_exit(&nm_lock.lock);
				return ((int)NODEV64);
			}
			/* update max size if necessary */
			len = (int)strlen(n->n_name);
			if (maxsz < len)
				maxsz = len;
		}
	}
	rw_exit(&nm_lock.lock);
	*rmaxsz = maxsz;
	return (cnt);
}

/*
 * md_getdevname
 *
 * Wrapper for md_getdevname_common()
 */
int
md_getdevname(
	set_t	setno,		/* which set to get name from */
	side_t	side,		/* (key 1) side number */
	mdkey_t	key,		/* (key 2) key provided by md_setdevname() */
	md_dev64_t	dev,	/* (alt. key 2) use this if key == KEYWILD */
	char	*devname,	/* char array to put device name in */
	size_t	max_size	/* size of char array */
)
{
	return (md_getdevname_common(setno, side, key, dev, devname,
	    max_size, MD_WAIT_LOCK));
}

/*
 * md_getdevname_common
 *		   Allows getting a device name from the database.
 *		   A pointer to a character array is passed in for
 *		   the device name to be built in. Also the max_size
 *		   is the maximum number of characters which can be put
 *		   in the devname[].
 */
int
md_getdevname_common(
	set_t	setno,		/* which set to get name from */
	side_t	side,		/* (key 1) side number */
	mdkey_t	key,		/* (key 2) key provided by md_setdevname() */
	md_dev64_t	dev,	/* (alt. key 2) use this if key == KEYWILD */
	char	*devname,	/* char array to put device name in */
	size_t	max_size,	/* size of char array */
	int	try_lock	/* whether to spin on the namespace lock */
)
{
	struct nm_next_hdr	*nh;
	struct nm_name		*n;
	int			err;

	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (ENOENT);
	}

	if (try_lock) {
		if (rw_tryenter(&nm_lock.lock, RW_READER) == 0) {
			/* Cannot obtain the lock without blocking */
			return (EAGAIN);
		}
	} else {
		rw_enter(&nm_lock.lock, RW_READER);
	}

	if ((nh = get_first_record(setno, 0, NM_NOTSHARED)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	if ((n = (struct nm_name *)lookup_entry(nh, setno, side, key,
	    dev, 0L))
		== NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	err = md_make_devname(n, setno, devname, max_size);

	rw_exit(&nm_lock.lock);
	return (err);
}

/*
 * md_gethspinfo -  Getting a hsp name or id from the database.
 *		    A pointer to a character array is passed in for
 *		    the hsp name to be built in. If a match is found,
 *		    the corresponding hspid is stored in ret_hspid.
 */
int
md_gethspinfo(
	set_t	setno,		/* which set to get name from */
	side_t	side,		/* (key 1) side number */
	mdkey_t	key,		/* (key 2) key provided by md_setdevname() */
	char	*drvnm,		/* return driver name here */
	hsp_t	*ret_hspid,	/* returned key if key is MD_KEYWILD */
	char	*hspname	/* alternate key or returned device name */
)
{
	struct nm_next_hdr	*nh;
	struct nm_name		*n;
	char			*drv_name;
	int			err = 0;
	char			*setname = NULL;

	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (ENOENT);
	}

	rw_enter(&nm_lock.lock, RW_READER);

	if ((nh = get_first_record(setno, 0, NM_NOTSHARED)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	if ((n = (struct nm_name *)lookup_hspentry(nh, setno, side,
	    key, hspname)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	/* Copy the driver name, device name and key for return */
	drv_name = (char *)getshared_name(setno, n->n_drv_key, 0L);
	if (!drv_name || (strlen(drv_name) > MD_MAXDRVNM)) {
		rw_exit(&nm_lock.lock);
		return (EFAULT);
	}

	/*
	 * Pre-friendly hsp names are of the form hspxxx and we
	 * should not have an entry in the namespace for them.
	 * So make sure the NM entry we get is a hotspare pool.
	 */
	if ((strcmp(drv_name, "md_hotspares")) != 0) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}
	(void) strcpy(drvnm, drv_name);

	/*
	 * If the input key is not MD_KEYWILD, return the
	 * hspname we found.
	 */
	if (key != MD_KEYWILD) {
		setname = mddb_getsetname(setno);
		if (setname != NULL)
			(void) snprintf(hspname, MAXPATHLEN,
			    "%s/%s", setname, n->n_name);
		else
			(void) snprintf(hspname, MAXPATHLEN,
			    "%s", n->n_name);
	}

	*ret_hspid = KEY_TO_HSP_ID(setno, n->n_key);

	rw_exit(&nm_lock.lock);
	return (err);
}

/*
 * md_devid_found  - Check to see if this key has devid entry or not
 *		     Return 1 if there is one or 0 if none
 */
int
md_devid_found(
	set_t	setno,		/* which set to get name from */
	side_t	side,		/* (key 1) side number */
	mdkey_t	key		/* key used to find entry in namespace */
)
{
	struct nm_next_hdr	*nh;

	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (0);
	}

	rw_enter(&nm_lock.lock, RW_READER);

	if ((nh = get_first_record(setno, 0, NM_DEVID| NM_NOTSHARED)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (0);
	}

	/*
	 * Look up the key
	 */
	if (lookup_entry(nh, setno, side, key, NODEV64, NM_DEVID) == NULL) {
			/* This key not in database */
			rw_exit(&nm_lock.lock);
			return (0);
	}

	rw_exit(&nm_lock.lock);
	/* found a key */
	return (1);
}


/*
 * md_getkeyfromdev  - Allows getting a key from the database by using the dev.
 *                     Returns the first key found and the number of keys
 *                     found that match dev.
 */
int
md_getkeyfromdev(
	set_t	setno,		/* which set to get name from */
	side_t	side,		/* (key 1) side number */
	md_dev64_t	dev,	/* dev to match against */
	mdkey_t	*firstkey,	/* ptr for first key found */
	int	*numkeysmatch	/* ptr to number of keys matching dev */
)
{
	struct nm_next_hdr	*nh;
	struct nm_name		*n;
	int			keynum;

	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (ENOENT);
	}

	rw_enter(&nm_lock.lock, RW_READER);

	if ((nh = get_first_record(setno, 0, NM_NOTSHARED)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	/*
	 * Walk through all keys in the namespace looking for a match
	 * against the given dev.  Count the number of matches and
	 * set firstkey to be first matched key.
	 */
	*numkeysmatch = 0;
	for (keynum = 1; keynum <
	    ((struct nm_rec_hdr *)nh->nmn_record)->r_next_key; keynum++) {
		if ((n = (struct nm_name *)lookup_entry(nh, setno, side,
		    keynum, dev, 0L)) == NULL) {
			/* This key not in database */
			continue;
		} else {
			/* found a key, look for the dev match */
			if (dev == build_device_number(setno,
			    (struct nm_name *)n)) {
				/* found a dev match */
				(*numkeysmatch)++;
				if (*numkeysmatch == 1) {
					*firstkey = n->n_key;
				}
			}
		}
	}

	rw_exit(&nm_lock.lock);
	return (0);
}

/*
 * md_getnment  - Allows getting a driver name and minor # from the database.
 */
int
md_getnment(
	set_t	setno,		/* which set to get name from */
	side_t	side,		/* (key 1) side number */
	mdkey_t	key,		/* (key 2) key provided by md_setdevname() */
	md_dev64_t dev,
	char	*drvnm,		/* char array to put driver name in */
	uint_t	max_size,	/* size of char array */
	major_t	*major,		/* address for major number */
	minor_t	*mnum,		/* address for minor number */
	mdkey_t	*retkey		/* address for returning key */
)
{
	struct nm_next_hdr	*nh;
	struct nm_name		*n;
	char			*drv_name;

	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (ENOENT);
	}

	rw_enter(&nm_lock.lock, RW_READER);

	if ((nh = get_first_record(setno, 0, NM_NOTSHARED)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	if ((n = (struct nm_name *)lookup_entry(nh, setno, side, key,
	    dev, 0L))
		== NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	drv_name = (char *)getshared_name(setno, n->n_drv_key, 0L);
	if (!drv_name || (strlen(drv_name) > max_size)) {
		rw_exit(&nm_lock.lock);
		return (EFAULT);
	}

	/* Copy the driver name, and fill in the minor number */
	(void) strcpy(drvnm, drv_name);
	if (MD_UPGRADE)
		*major = md_targ_name_to_major(drvnm);
	else
		*major = ddi_name_to_major(drvnm);
	*mnum = n->n_minor;
	*retkey = n->n_key;

	rw_exit(&nm_lock.lock);

	return (0);
}

/*
 * md_getdevnum  - Allows getting a device number from the database.
 * This routine returns a translated (aka miniroot) md_dev64_t.
 */
md_dev64_t
md_getdevnum(
	set_t	setno,		/* which set to get name from */
	side_t	side,		/* (key 1) side number */
	mdkey_t	key,		/* (key 2) key provided by md_setdevname() */
	int	flag)		/* If set then return devt from namespace */
{
	struct nm_next_hdr	*nh, *did_shr_nh, *did_nh = NULL;
	struct nm_name		*n;
	struct did_min_name	*did_n;
	struct did_shr_name	*did_shr_n;
	md_dev64_t		retval, retval_targ;
	int			did_found = 0;
	ddi_devid_t		devid = NULL;
	int			ndevs;
	dev_t			*devs;
	char			*drv, *drvnm, *mname = NULL;
	mddb_recid_t		recids[3];
	int			devid_nm = 0;

	/*
	 * If a MN diskset and this node is the master OR
	 * if a traditional diskset, then check to see if the
	 * did namespace should be cleaned up.
	 *
	 * Always set MD_SET_DIDCLUP bit in set's status field
	 * so that this check is only done once.
	 */
	if (!(md_get_setstatus(setno) & MD_SET_DIDCLUP)) {
	    if ((MD_MNSET_SETNO(setno) && (md_set[setno].s_am_i_master)) ||
		(!(MD_MNSET_SETNO(setno)))) {
		    if (!(((mddb_set_t *)md_set[setno].s_db)->s_lbp->lb_flags
			& MDDB_DEVID_STYLE) || md_devid_destroy) {
			    (void) md_load_namespace(setno, NULL, NM_DEVID);
			    (void) md_devid_cleanup(setno, 1);
		    }
	    }
	    md_set_setstatus(setno, MD_SET_DIDCLUP);
	}

	/*
	 * Test the MDDB_DEVID_STYLE bit
	 */
	if (((mddb_set_t *)md_set[setno].s_db)->s_lbp->lb_flags
		& MDDB_DEVID_STYLE) {
		(void) md_load_namespace(setno, NULL, NM_DEVID);
		devid_nm = 1;
	}

	/*
	 * Load the primary name space
	 */
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (NODEV64);
	}

	rw_enter(&nm_lock.lock, RW_READER);


	/*
	 * If not even in the primary name space, bail out
	 */
	if (((nh = get_first_record(setno, 0, NM_NOTSHARED)) == NULL) ||
		((n = (struct nm_name *)lookup_entry(nh, setno, side, key,
			NODEV64, 0L)) == NULL)) {
		rw_exit(&nm_lock.lock);
		return (NODEV64);
	}

	/*
	 * Entry corresponds to this key is referenced and snarfed so
	 * we set the value to 1.  During the name space cleanup we will check
	 * this value and if it is set then we know it is part of the
	 * current configuration.  For any 'key' whose value is not set
	 * then we know it is an 'orphan' entry and will be removed.
	 */
	if (md_nm_snarfed)
		md_nm_snarfed[key] = 1;

	/*
	 * Reference the device id namespace
	 */
	if (devid_nm) {
	    if (((did_nh = get_first_record(setno, 1, NM_DEVID | NM_NOTSHARED))
		== NULL) || ((did_shr_nh = get_first_record(setno, 1,
			NM_DEVID | NM_SHARED)) == NULL)) {
		devid_nm = 0;
	    }
	}

	/*
	 * If the key is in the device id name space then
	 * this device has disk tracking info stored
	 */
	if (devid_nm && ((did_n = (struct did_min_name *)lookup_entry(did_nh,
		setno, side, key, NODEV64, NM_DEVID)) != NULL)) {
		/*
		 * Get the minor name and the device id
		 */
		devid = (ddi_devid_t)getshared_name(setno,
						did_n->min_devid_key, NM_DEVID);

		did_shr_n = (struct did_shr_name *)lookup_shared_entry(
					did_shr_nh, did_n->min_devid_key,
					(char *)0, NULL, NM_DEVID);

		if ((devid == NULL) || (did_shr_n == NULL)) {
			rw_exit(&nm_lock.lock);
			return (NODEV64);
		}


		if (ddi_lyr_devid_to_devlist(devid, did_n->min_name, &ndevs,
			&devs) == DDI_SUCCESS) {

			md_dev64_t tdev;
			int cnt;

			did_found = 1;

			/*
			 * Save the first available devt
			 * During upgrade, this is a miniroot devt.
			 */

			retval = md_expldev(devs[0]);

			/*
			 * For a multipath device more than 1 md_dev64_t will
			 * occur. In this case retval will be set to
			 * the md_dev64_t that was previously set.
			 */

			if (ndevs > 1) {

				/* get the stored md_dev64_t */
				tdev = build_device_number(setno, n);
				for (cnt = 0; cnt < ndevs; cnt++) {
					if (tdev == md_expldev(devs[cnt])) {
						retval = tdev;
						break;
					}
				}
			}

			/*
			 * If during upgrade, switch drvnm to be target
			 * device's name, not miniroot's name.
			 */
			if (MD_UPGRADE)
				drvnm = md_targ_major_to_name(md_getmajor
					(md_xlate_mini_2_targ(retval)));
			else
				drvnm = ddi_major_to_name(
						md_getmajor(retval));

			/*
			 * It is a valid device id
			 */
			did_shr_n->did_data = NM_DEVID_VALID;

			/*
			 * Free the memory
			 */
			(void) ddi_lyr_free_devlist(devs, ndevs);
		} else {
			/*
			 * Invalid device id, say so
			 * and check flag to see if we can return
			 * devt stored in the namespace
			 */
			did_shr_n->did_data = NM_DEVID_INVALID;
			rw_exit(&nm_lock.lock);

			/*
			 * If flag does not have MD_TRUST_DEVT bit on
			 * then with the invalid device id we simply cant
			 * trust the devt in the namespace at all
			 *
			 * Bit MD_TRUST_DEVT is set by metadevadm or
			 * when a diskset is taken and it does not have
			 * any associated devid records for the drive
			 * records in the set.
			 *
			 * When this bit is set that means devt can be
			 * trusted and we just go ahead do whatever user
			 * ask for
			 */
			if (!(flag & MD_TRUST_DEVT))
				return (NODEV64);

			/* build_device_number returns a target devt */
			retval_targ = build_device_number(setno, n);
			/* translate devt to miniroot devt */
			if ((retval = md_xlate_targ_2_mini(retval_targ))
			    == NODEV64) {
				return (NODEV64);
			}
			return (retval);
		}
	}


	/*
	 * If no entry is found in the device id name space
	 * It can be one of:
	 *	underlying meta device
	 *	No device id associated
	 *	Has a device id but mddb is in the old fromat
	 */
	if (did_found) {
		/*
		 * Update the name entry if necessary
		 */
		if ((retval_targ = md_xlate_mini_2_targ(retval)) == NODEV64) {
			rw_exit(&nm_lock.lock);
			return (NODEV64);
		}

		if (n->n_minor != md_getminor(retval_targ))
			n->n_minor = md_getminor(retval_targ);

		if ((drv =
		    (char *)getshared_name(setno, n->n_drv_key, 0L)) == NULL) {
			rw_exit(&nm_lock.lock);
			return (NODEV64);
		}

		if (strcmp(drv, drvnm) != 0)
			n->n_drv_key = setshared_name(setno, drvnm,
			    MD_KEYWILD, 0L);

		if (!(md_get_setstatus(setno) & MD_SET_STALE))
			(void) update_entry(nh, side, key, 0L);
	} else {
		/*
		 * Has a device id associated with it?
		 * If yes, then we will try to add them into the device id nm
		 * build_device_number returns a target devt.
		 */
		if ((retval_targ = build_device_number(setno, n)) == NODEV64) {
			rw_exit(&nm_lock.lock);
			return (NODEV64);
		}

		/*
		 * We don't translate the devt of the meta device
		 * and currently no device id associated with metadevice
		 */
		if (md_getmajor(retval_targ) != md_major_targ) {

			if ((retval = md_xlate_targ_2_mini(retval_targ))
			    == NODEV64) {
				rw_exit(&nm_lock.lock);
				return (NODEV64);
			}

			/*
			 * Add the device id info only if
			 * MDDB_DEVID_STYLE bit is set
			 *
			 */
			if (!devid_nm) {
				rw_exit(&nm_lock.lock);
				return (retval);
			}

			/*
			 * We can continue if we are here
			 * If retval has a device id, add them
			 */
			if ((ddi_lyr_get_devid(md_dev64_to_dev(retval), &devid)
							== DDI_SUCCESS) &&
			    (ddi_lyr_get_minor_name(md_dev64_to_dev(retval),
							S_IFBLK, &mname)
							== DDI_SUCCESS)) {
				/*
				 * Add them into the devid name space
				 */
				did_n = (struct did_min_name *)alloc_entry(
					did_nh, md_set[setno].s_did_nmid,
					strlen(mname)+1, NM_DEVID|NM_NOTSHARED,
					&recids[0]);

				if (did_n) {
					did_n->min_side = side;
					did_n->min_key = key;
					did_n->min_count = 1;
					(void) strcpy(did_n->min_name, mname);
					did_n->min_namlen =
					    (ushort_t)(strlen(mname)+1);
					did_n->min_devid_key =
					    setshared_name(setno,
						(char *)devid, MD_KEYWILD,
						NM_DEVID);
					/*
					 * Commit the change to the record
					 */
					if (did_n->min_devid_key == MD_KEYBAD) {
						(void) remove_entry(did_nh,
							did_n->min_side,
							did_n->min_key,
							NM_DEVID);
					} else {
						recids[1] =
						    md_set[setno].s_did_nmid;
						recids[2] = 0;
						mddb_commitrecs_wrapper(recids);
					}
				}
			}
			/*
			 * Free all the memory
			 */
			if (devid)
				ddi_devid_free(devid);
			if (mname)
				kmem_free(mname, strlen(mname) + 1);
		} else {
			retval = md_makedevice(md_major,
						md_getminor(retval_targ));
		}
	}

	rw_exit(&nm_lock.lock);
	return (retval);
}

/*
 * md_getnextkey  - Allows running thru the list of defined device names.
 */
mdkey_t
md_getnextkey(
	set_t	setno,		/* which set to get name from */
	side_t	side,		/* (key 1) side number */
	mdkey_t	key,		/* (key 2) wildcarded or from md_getnextkey() */
	uint_t	*cnt)		/* n_count returns here */
{
	struct nm_next_hdr	*nh;
	struct nm_name		*n = NULL;
	mdkey_t			retval = MD_KEYWILD;


	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (MD_KEYWILD);
	}

	rw_enter(&nm_lock.lock, RW_READER);

	if ((nh = get_first_record(setno, 0, NM_NOTSHARED)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (MD_KEYWILD);
	}

	for (key++; key < ((struct nm_rec_hdr *)nh->nmn_record)->r_next_key;
			key++) {
		if ((n = (struct nm_name *)lookup_entry(nh, setno, side, key,
			NODEV64, 0L)) != NULL)
			break;
	}

	if (n != NULL) {
		if (cnt != NULL)
		    *cnt = n->n_count;

		retval = n->n_key;
	}

	rw_exit(&nm_lock.lock);
	return (retval);
}

/*
 * md_update_namespace_did - update the devid portion of the namespace
 */
int
md_update_namespace_did(
	set_t		setno,
	side_t		side,
	mdkey_t		key,
	md_error_t	*ep
)
{
	dev_t			devt;
	ddi_devid_t		rtn_devid = NULL;
	ddi_devid_t		devid = NULL;
	struct nm_next_hdr	*did_shr_nh;
	mdkey_t			ent_did_key;
	uint32_t		ent_did_count;
	uint32_t		ent_did_data;
	struct nm_next_hdr	*this_did_shr_nh;
	void			*record;
	size_t			offset;
	struct did_shr_name	*shn;
	mddb_recid_t		recids[3];
	struct nm_next_hdr	*nh;
	struct nm_next_hdr	*this_did_nh;
	struct did_min_name	*n;
	struct did_shr_name	*shr_n;
	mdkey_t			o_key, devid_key;
	size_t			ent_size, size;

	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (!md_load_namespace(setno, NULL, 0L)) {
		(void) md_unload_namespace(setno, NM_DEVID);
		return ((int)NODEV64);
	}
	rw_enter(&nm_lock.lock, RW_WRITER);

	offset = (sizeof (struct devid_shr_rec) - sizeof (struct did_shr_name));
	if ((nh = get_first_record(setno, 0, NM_DEVID | NM_NOTSHARED)) ==
									NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	this_did_nh = nh->nmn_nextp;
	if (this_did_nh  == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}
	record = this_did_nh->nmn_record;
	if (record == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}
	if ((n = (struct did_min_name *)lookup_entry(nh, setno, side, key,
	    NODEV64, NM_DEVID)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}
	devid_key = n->min_devid_key;

	rw_exit(&nm_lock.lock);
	devt = md_dev64_to_dev(
			md_getdevnum(setno, side, key, MD_TRUST_DEVT));
	rw_enter(&nm_lock.lock, RW_WRITER);
	if (ddi_lyr_get_devid(devt, &rtn_devid) == DDI_SUCCESS) {
		did_shr_nh = get_first_record(setno, 0, NM_DEVID | NM_SHARED);
		if (did_shr_nh == NULL) {
			ddi_devid_free(rtn_devid);
			rw_exit(&nm_lock.lock);
			return ((int)NODEV64);
		}
		this_did_shr_nh = did_shr_nh->nmn_nextp;
		record = this_did_shr_nh->nmn_record;
		shn = &((struct devid_shr_rec *)record)->device_id[0];
		shr_n = (struct did_shr_name *)lookup_shared_entry(
				did_shr_nh, n->min_devid_key, (char *)0,
				&recids[0], NM_DEVID);
		if (shr_n == NULL) {
			ddi_devid_free(rtn_devid);
			rw_exit(&nm_lock.lock);
			return (ENOENT);
		}
		o_key = shn->did_key;
		while (devid_key != o_key) {
			shn = (struct did_shr_name *)get_next_entry(
					this_did_shr_nh, (caddr_t)shn,
					DID_SHR_NAMSIZ(shn), &offset);
			if (shn == NULL) {
				if (offset) {
					ddi_devid_free(rtn_devid);
					rw_exit(&nm_lock.lock);
					return (ENOENT);
				}
			}
			o_key = shn->did_key;
		}
		devid = (ddi_devid_t)shr_n->did_devid;
		if (ddi_devid_compare(rtn_devid, devid) != 0) {
			/* remove old devid info */
			ent_did_key = shr_n->did_key;
			ent_did_count = shr_n->did_count;
			ent_did_data = shr_n->did_data;
			ent_size = DID_SHR_NAMSIZ(shr_n);
			size = ((struct nm_rec_hdr *)this_did_shr_nh->
			    nmn_record)->r_used_size - offset - ent_size;
			if (size == 0) {
				(void) bzero(shr_n, ent_size);
			} else {
				(void) ovbcopy((caddr_t)shr_n + ent_size, shr_n,
				    size);
				(void) bzero((caddr_t)shr_n + size, ent_size);
			}
			((struct nm_rec_hdr *)this_did_shr_nh->nmn_record)->
			    r_used_size -= ent_size;
			/* add in new devid info */
			if ((shn = (struct did_shr_name *)alloc_entry(
			    did_shr_nh, md_set[setno].s_did_nmid,
			    ddi_devid_sizeof(rtn_devid),
			    NM_DEVID | NM_SHARED | NM_NOCOMMIT,
			    &recids[0])) == NULL) {
				ddi_devid_free(rtn_devid);
				rw_exit(&nm_lock.lock);
				return (ENOMEM);
			}
			shn->did_key = ent_did_key;
			shn->did_count = ent_did_count;
			ent_did_data |= NM_DEVID_VALID;
			shn->did_data = ent_did_data;
			shn->did_size = ddi_devid_sizeof(rtn_devid);
			bcopy((void *)rtn_devid, (void *)shn->did_devid,
			    shn->did_size);
			recids[1] = md_set[setno].s_nmid;
			recids[2] = 0;

			mddb_commitrecs_wrapper(recids);
		}
		ddi_devid_free(rtn_devid);
	} else {
		rw_exit(&nm_lock.lock);
		(void) mderror(ep, MDE_NODEVID);
		return (ENOENT);
	}
	rw_exit(&nm_lock.lock);
	return (0);
}

/*
 * md_update_namespace - update namespace device name and pathname
 *
 */

int
md_update_namespace(
	set_t	setno,		/* which set to get name from */
	side_t	side,		/* (key 1) side number */
	mdkey_t	key,		/* (key 2) key provided by md_setdevname() */
	char	*devname,	/* device name */
	char	*pathname,	/* pathname to device */
	minor_t	mnum		/* minor numer */
)
{
	struct nm_next_hdr	*nh;
	struct nm_name		*n;
	struct nm_name		*o_n;
	struct nm_next_hdr	*this_nh;
	struct nm_next_hdr	*snh;
	struct nm_shared_name	*shn;
	void			*record;
	mddb_recid_t		recids[3];
	size_t			size;
	mdkey_t			ent_key, ent_drv_key, ent_dir_key, new_dir_key;
	uint32_t		ent_count;
	side_t			ent_side;
	size_t			offset;
	mdkey_t			o_key = NULL;
	char			*old_pathname;
	int			ent_size;

	if (!md_load_namespace(setno, NULL, 0L)) {
		return (ENOENT);
	}

	rw_enter(&nm_lock.lock, RW_WRITER);

	offset = sizeof (struct nm_rec) - sizeof (struct nm_name);
	if ((nh = get_first_record(setno, 0, NM_NOTSHARED)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	this_nh = nh->nmn_nextp;
	record = this_nh->nmn_record;
	o_n = &((struct nm_rec *)record)->r_name[0];
	if ((n = (struct nm_name *)lookup_entry(nh, setno, side, key, NODEV64,
	    0L)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	o_key = o_n->n_key;
	while (key != o_key) {
		o_n = (struct nm_name *)get_next_entry(this_nh, (caddr_t)o_n,
		    NAMSIZ(o_n), &offset);
		if (o_n == NULL) {
			if (offset) {
				rw_exit(&nm_lock.lock);
				return (ENOENT);
			}
		}
		o_key = o_n->n_key;
	}
	/* save the values from the old record */
	ent_side = n->n_side;
	ent_key = n->n_key;
	ent_count = n->n_count;
	ent_drv_key = n->n_drv_key;
	ent_dir_key = n->n_dir_key;
	ent_size = NAMSIZ(n);
	size = ((struct nm_rec_hdr *)this_nh->nmn_record)->r_used_size - offset
	    - ent_size;

	if (size == 0) {
		(void) bzero(n, ent_size);    /* last entry */
	} else {
		(void) ovbcopy((caddr_t)n + ent_size, n, size);
		(void) bzero((caddr_t)n + size, ent_size);
	}
	((struct nm_rec_hdr *)this_nh->nmn_record)->r_used_size -= ent_size;

	rw_exit(&nm_lock.lock);
	/* check to see if we have a new pathname */
	old_pathname = md_getshared_name(setno, ent_dir_key);
	if (strcmp(old_pathname, pathname)) {
		/* now see if the new pathname actually exists in our nsp */
		if ((snh = get_first_record(setno, 0, NM_SHARED)) == NULL)
			return (ENOENT);
		shn = (struct nm_shared_name *)lookup_shared_entry(
		    snh, NULL, pathname, &recids[0], 0L);
		if (shn) {
			/* pathname exists so get it's key */
			new_dir_key = shn->sn_key;
		} else {
			/* pathname doesn't exist so create it */
			new_dir_key =
			    md_setshared_name(setno, pathname, NM_NOCOMMIT);
		}
		/* update dir key */
		ent_dir_key = new_dir_key;
	}

	rw_enter(&nm_lock.lock, RW_WRITER);
	/* Create a name entry */
	n = (struct nm_name *)alloc_entry(nh, md_set[setno].s_nmid,
	    strlen(devname)+1, NM_NOTSHARED | NM_NOCOMMIT, &recids[0]);

	if (n == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOMEM);
	}

	n->n_minor = mnum;
	n->n_side = ent_side;
	n->n_key = ent_key;
	n->n_count = ent_count;
	n->n_drv_key = ent_drv_key;

	/* fill-in filename */
	(void) strcpy(n->n_name, devname);
	n->n_namlen = (ushort_t)(strlen(devname) + 1);

	/* directory name */
	n->n_dir_key = ent_dir_key;

	recids[1] = md_set[setno].s_nmid;
	recids[2] = 0;

	mddb_commitrecs_wrapper(recids);

	rw_exit(&nm_lock.lock);
	return (0);
}

/*
 * md_getdevidminor - Get the minor name from the database. The minor
 *		      name and the devid id uniquely identify the disk
 *		      slice.
 */
int
md_getdevidminor(
	set_t	setno,
	side_t	side,
	mdkey_t	key,
	char	*minorname,
	size_t	max_size
)
{
	struct nm_next_hdr	*nh;
	struct did_min_name	*n;

	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (ENOENT);
	}

	rw_enter(&nm_lock.lock, RW_READER);

	/*
	 * The key we have is for the non-shared, regular namespace.  We
	 * have to lookup the min_key in the non-shared, devid namespace.
	 */
	if ((nh = get_first_record(setno, 0, NM_DEVID | NM_NOTSHARED))
	    == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	if ((n = (struct did_min_name *)lookup_entry(nh, setno, side, key,
	    NODEV64, NM_DEVID)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	if (n->min_namlen > max_size) {
		rw_exit(&nm_lock.lock);
		return (EFAULT);
	}

	bcopy(&((struct did_min_name *)n)->min_name[0], minorname,
	    n->min_namlen);

	rw_exit(&nm_lock.lock);
	return (0);
}

/*
 * md_getdevid -   Allows getting a device id from the database.
 *		   A pointer to a character array is passed in for
 *		   the device id to be copied to.  The size is returned
 *		   in *did_size.
 */
int
md_getdevid(
	set_t	setno,		/* which set to get name from */
	side_t	side,
	mdkey_t	key,		/* (key 2) key provided by md_setdevname() */
	ddi_devid_t	did,		/* pointer to did string */
	ushort_t	*did_size	/* pointer to size of did string */
)
{
	struct nm_next_hdr	*nh;
	void			*n;
	mddb_recid_t		recid;

	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (ENOENT);
	}

	rw_enter(&nm_lock.lock, RW_READER);

	/*
	 * The key we have is for the non-shared, regular namespace.  We
	 * have to lookup the min_key in the non-shared, devid namespace.
	 */
	if ((nh = get_first_record(setno, 0, NM_DEVID | NM_NOTSHARED))
	    == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	if ((n = (struct did_min_name *)lookup_entry(nh, setno, side, key,
	    NODEV64, NM_DEVID)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	/*
	 * Now go get the devid.
	 */
	if ((nh = get_first_record(setno, 0, NM_DEVID | NM_SHARED)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	if ((n = (struct did_shr_name *)lookup_shared_entry(nh,
	    ((struct did_min_name *)n)->min_devid_key, (char *)0, &recid,
	    NM_DEVID)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	/*
	 * If did is non-zero then copy devid to buffer, else return
	 * devid size to user.  These are exclusive operations.
	 */
	if (did != NULL) {
		bcopy(&((struct did_shr_name *)n)->did_devid[0], did,
		    *did_size);
	} else {
		*did_size = ((struct did_shr_name *)n)->did_size;
	}

	rw_exit(&nm_lock.lock);
	return (0);
}

/*
 * md_remdevname - Allows removing a device name from the database.
 */
int
md_remdevname(
	set_t			setno,
	side_t			side,
	mdkey_t			key
)
{
	struct nm_next_hdr	*nh, *did_nh;
	struct nm_next_hdr	*shared_nh, *did_shr_nh;
	struct nm_name		*n;
	struct did_min_name	*did_n = NULL;
	mdkey_t			drv_key, dir_key, did_key;
	int			err;


	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (ENOENT);
	}

	rw_enter(&nm_lock.lock, RW_WRITER);

	if (((nh = get_first_record(setno, 0, NM_NOTSHARED)) == NULL) ||
	    ((shared_nh = get_first_record(setno, 0, NM_SHARED)) == NULL)) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	/*
	 * If it is not in the primary name space, nothing to remove
	 */
	if ((n = (struct nm_name *)lookup_entry(nh, setno, side, key, NODEV64,
		0L)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	/*
	 * If there is non-empty device id name space
	 * Try to locate the entry
	 */
	if (md_set[setno].s_did_nm &&
	    ((did_nh = get_first_record(setno, 0, NM_DEVID | NM_NOTSHARED))
		!= NULL) &&
	    ((did_shr_nh = get_first_record(setno, 0, NM_DEVID | NM_SHARED))
		!= NULL)) {
		did_n = (struct did_min_name *)lookup_entry(did_nh, setno,
			side, key, NODEV64, NM_DEVID);
	}

	n->n_count--;
	if (n->n_count) {

		err = update_entry(nh, side, key, 0L);
		/*
		 * Update the device id namespace as well
		 */
		if (did_n) {
			did_n->min_count--;
			(void) update_entry(did_nh, side, key, NM_DEVID);
		}

		rw_exit(&nm_lock.lock);
		return (err);
	}

	/* reference count is zero, actually remove the name entry */
	drv_key = n->n_drv_key;
	dir_key = n->n_dir_key;
	did_key = (did_n ? did_n->min_devid_key : 0);

	if (remove_entry(nh, side, key, 0L)) {
		rw_exit(&nm_lock.lock);
		return (EINVAL);
	}

	if (remove_shared_entry(shared_nh, drv_key, (char *)0, 0L) ||
		remove_shared_entry(shared_nh, dir_key, (char *)0, 0L)) {
		rw_exit(&nm_lock.lock);
		return (EINVAL);
	}

	/*
	 * Remove from the device id name space
	 */
	if (did_n) {
		if (remove_entry(did_nh, side, key, NM_DEVID)) {
			rw_exit(&nm_lock.lock);
			return (EINVAL);
		}

		if (remove_shared_entry(did_shr_nh, did_key, (char *)0,
			NM_DEVID)) {
			rw_exit(&nm_lock.lock);
			return (EINVAL);
		}
	}

	rw_exit(&nm_lock.lock);
	return (0);
}

/*
 * md_setshared_name -  Puts a name into the shared namespace database, and
 *			returns a key (used to get the string back).
 *			If the name does not already exist in the namespace
 *			then it will be added and the reference count will
 *			be set to one;
 *			Otherwise the reference count is incremented.
 */
mdkey_t
md_setshared_name(set_t setno, char *shrname, int nocommit)
{
	mdkey_t	key;


	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (MD_KEYBAD);
	}

	rw_enter(&nm_lock.lock, RW_WRITER);

	key = setshared_name(setno, shrname, MD_KEYWILD, nocommit);

	rw_exit(&nm_lock.lock);
	return (key);
}


/*
 * md_getshared_name -	Allows converting a key, into the shared namespace
 *			database, to the string which it represents.
 */
char *
md_getshared_name(set_t setno, mdkey_t shrkey)
{
	char	*string;


	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return ((char *)0);
	}

	rw_enter(&nm_lock.lock, RW_READER);
	string = (char *)getshared_name(setno, shrkey, 0L);
	rw_exit(&nm_lock.lock);

	return (string);
}

/*
 * md_remshared_name - Allows removing of shared name by key.
 */
int
md_remshared_name(set_t setno, mdkey_t shrkey)
{
	struct nm_next_hdr	*nh;


	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (ENOENT);
	}

	rw_enter(&nm_lock.lock, RW_WRITER);

	if ((nh = get_first_record(setno, 0, NM_SHARED)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	if (remove_shared_entry(nh, shrkey, (char *)0, 0L)) {
		rw_exit(&nm_lock.lock);
		return (ENOENT);
	}

	rw_exit(&nm_lock.lock);
	return (0);
}

/*
 * md_getshared_key - get the key for the given string.
 */
mdkey_t
md_getshared_key(set_t setno, char *shrname)
{
	mdkey_t	retval;


	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (MD_KEYBAD);
	}

	rw_enter(&nm_lock.lock, RW_WRITER);
	retval = getshared_key(setno, shrname, 0L);
	rw_exit(&nm_lock.lock);
	return (retval);
}

/*
 * md_load_namespace - Get all the records associated with the namespace
 *			out of the database and setup all the incore
 *			structures (i.e., pointers).
 */
int
md_load_namespace(set_t setno, md_error_t *ep, int devid_nm)
{
	mddb_recid_t		hdr_recid;
	struct nm_header_hdr	*hdr = NULL;
	mddb_type_t		rec_type;

	if ((md_get_setstatus(setno) & MD_SET_NM_LOADED))
		return (1);

	if (devid_nm && (md_set[setno].s_did_nm != 0))
		return (1);

	rec_type = (devid_nm ? MDDB_DID_NM_HDR : MDDB_NM_HDR);

	hdr_recid = mddb_getnextrec(mddb_makerecid(setno, 0), rec_type, 0);

	if (hdr_recid < 0) {
		if (ep != NULL)
			return (mddbstatus2error(ep, hdr_recid, NODEV32,
							setno));
		return (0);
	}

	if (hdr_recid != 0) {
		mddb_recstatus_t status;

		status = mddb_getrecstatus(hdr_recid);
		if (status == MDDB_NODATA) {
			mddb_setrecprivate(hdr_recid, MD_PRV_PENDDEL);
			hdr_recid = 0;
		} else if (status == MDDB_STALE) {
			if (! (md_get_setstatus(setno) & MD_SET_STALE)) {
				md_set_setstatus(setno, MD_SET_STALE);
				cmn_err(CE_WARN, "md: state database is stale");
			}
		}
	}

	rw_enter(&nm_lock.lock, RW_WRITER);

	if (hdr_recid != 0) {

		hdr = kmem_zalloc(sizeof (*hdr), KM_SLEEP);
		ASSERT(hdr != NULL);

		if (devid_nm) {
			md_set[setno].s_did_nmid = hdr_recid;
			md_set[setno].s_did_nm = (void *)hdr;
		} else {
			md_set[setno].s_nmid = hdr_recid;
			md_set[setno].s_nm = (void *)hdr;
		}

		hdr->hh_header = (struct nm_header *)mddb_getrecaddr(hdr_recid);

		ASSERT(hdr->hh_header != NULL);

		hdr->hh_names.nmn_record = &(hdr->hh_header->h_names);
		hdr->hh_shared.nmn_record = &(hdr->hh_header->h_shared);

		mddb_setrecprivate(hdr_recid, MD_PRV_GOTIT);

		build_rec_hdr_list(&hdr->hh_names, hdr_recid,
				devid_nm | NM_NOTSHARED);
		build_rec_hdr_list(&hdr->hh_shared, hdr_recid,
				devid_nm | NM_SHARED);

		/*
		 * Only cleanup a MN diskset if this node is master.
		 * Always cleanup traditional diskset.
		 */
		if (!(MD_MNSET_SETNO(setno)) ||
		    (MD_MNSET_SETNO(setno) && md_set[setno].s_am_i_master)) {
			if (devid_nm) {
				cleanup_unused_rec(setno, NM_DEVID);
			} else {
				cleanup_unused_rec(setno, 0L);
			}
		}
	}

	if (!devid_nm)
		md_set_setstatus(setno, MD_SET_NM_LOADED);
	if (hdr && hdr->hh_header != NULL)
		zero_data_ptrs(&hdr->hh_shared, setno);
	rw_exit(&nm_lock.lock);
	return (1);
}

void
md_unload_namespace(set_t setno, int devid_nm)
{
	struct nm_header_hdr *hhdr;
	struct nm_next_hdr *nh, *nnh;

	if (!devid_nm && (md_set[setno].s_nmid == 0))
		return;

	if (devid_nm && (md_set[setno].s_did_nmid == 0))
		return;

	rw_enter(&nm_lock.lock, RW_WRITER);

	hhdr = ((devid_nm & NM_DEVID) ?
		(struct nm_header_hdr *)md_set[setno].s_did_nm :
		(struct nm_header_hdr *)md_set[setno].s_nm);

	if (devid_nm) {
		md_set[setno].s_did_nmid = 0;
		md_set[setno].s_did_nm = NULL;
	} else {
		md_set[setno].s_nmid = 0;
		md_set[setno].s_nm = NULL;
	}

	/*
	 * Clear MD_SET_NM_LOADED when the primary is unloaded
	 */
	if (!devid_nm)
		md_clr_setstatus(setno, MD_SET_NM_LOADED);

	rw_exit(&nm_lock.lock);

	/*
	 * Free the memory occupied by the namespace records if any has been
	 * allocated.  For the case of a namespace which contains drives not
	 * supporting device id's we must be careful.
	 */
	if (hhdr != NULL) {
		for (nh = hhdr->hh_names.nmn_nextp; nh; nh = nnh) {
			nnh = nh->nmn_nextp;
			kmem_free(nh, sizeof (*nh));
		}

		for (nh = hhdr->hh_shared.nmn_nextp; nh; nh = nnh) {
			nnh = nh->nmn_nextp;
			kmem_free(nh, sizeof (*nh));
		}
		kmem_free(hhdr, sizeof (*hhdr));
	}
}

/*
 * md_nm_did_chkspace - calculate the approximate DID namespace size based
 *			on the component disk devices defined in the primary
 *			non-shared namespace for this set.  This is done on
 *			the conservative side and may be a block or two too
 *			large.  These are MDDB blocks.
 *
 * This is intended to be called during a replica conversion from non-devid
 * format to devid format.  As such no special precautions were taken to
 * insure reentrancy.  In particular the code in free_devid_list() that
 * initializes the devid_list anchor linkages makes this function non-MT-safe.
 */

int
md_nm_did_chkspace(set_t setno)
{
	struct	nm_next_hdr	*nh;
	struct	nm_name		*n;
	side_t			side = MD_SIDEWILD;
	mdkey_t			key = MD_KEYWILD;
	int			total_size = 0;	/* Total required size */
	int			devid_size = 0;	/* Device id total size */
	int			mname_size = 0;	/* Minor name total size */
	int			namelen = 0;
	int			comp_count = 0;	/* Total number of components */
	int			devid_count = 0; /* Total number of devids */
	ddi_devid_t		devid = NULL;
	char			*mname = NULL;

	rw_enter(&nm_lock.lock, RW_READER);

	if ((nh = get_first_record(setno, 0, NM_NOTSHARED)) == NULL) {
		rw_exit(&nm_lock.lock);
		return (total_size);
	}

	/*
	 * For each key in the non-shared, primary namespace, lookup the
	 * minor name and any associated device id.  These will reside in
	 * the device id namespace of the upgraded system.
	 */
	while ((key = md_getnextkey(setno, side, key, NULL)) != MD_KEYWILD) {
		if ((n = (struct nm_name *)lookup_entry(nh, setno, side, key,
			NODEV64, 0L)) == NULL) {
			break;
		} else {
			md_dev64_t dev64 = build_device_number(setno, n);
			dev_t dev = md_dev64_to_dev(dev64);

			if (ddi_lyr_get_minor_name(dev, S_IFBLK, &mname)
						!= DDI_SUCCESS) {
				continue;
			} else {
				if (mname) {
					namelen = strlen(mname);
					mname_size += namelen;
					kmem_free(mname, (namelen + 1));
					comp_count++;
				}
			}
			if (ddi_lyr_get_devid(dev, &devid) != DDI_SUCCESS) {
				continue;
			} else {
				if (devid_is_unique(devid)) {
					add_to_devid_list(devid);
				} else {
					ddi_devid_free(devid);
				}
			}
		}
	}

	devid_size = free_devid_list(&devid_count);
	rw_exit(&nm_lock.lock);

	/*
	 * Sum things up in this order:
	 * 1) # blocks to hold devid non-shared record blocks
	 * 2) # blocks to hold devid shared record blocks
	 * 3) 1 block to hold devid non-shared nm_rec_hdr's
	 * 4) 1 block to hold mddb_de's for both of these spaces
	 */

	/*
	 * 1)
	 */
	total_size = roundup(sizeof (struct mddb_rb32) +
	    sizeof (struct nm_rec_hdr) + (sizeof (struct did_min_name) *
	    comp_count) + (mname_size + comp_count), MDDB_BSIZE);

	/*
	 * 2)
	 */
	total_size += roundup(sizeof (struct mddb_rb32) +
	    sizeof (struct nm_rec_hdr) + (sizeof (struct did_shr_name) *
	    devid_count) + devid_size, MDDB_BSIZE);

	/*
	 * 3) and 4)
	 */
	total_size += (2 * MDDB_BSIZE);

	return (total_size/MDDB_BSIZE);
}

/*
 * devid_list - forward list of devid_list structs.
 * Managed by routines add_to_devid_list() and free_devid_list() to keep
 * track of unique devids associated with components of metadevices.  Entries
 * are made at the beginning of the list.
 */
static	struct	devid_list {
	size_t	devid_size;
	struct	devid_list	*next;
	ddi_devid_t		devid;
} did_list = { 0, NULL, NULL};

static	struct	devid_list	*dlp = &did_list;

/*
 * add_to_devid_list - add a struct devid_list to the head of the devid_list
 * list.
 */
static void
add_to_devid_list(ddi_devid_t did)
{
	struct	devid_list	*curdlp;

	curdlp = kmem_zalloc(sizeof (struct devid_list), KM_SLEEP);
	curdlp->devid_size = ddi_devid_sizeof(did);
	curdlp->devid = did;
	curdlp->next = dlp->next;
	dlp->next = curdlp;
}

/*
 * free_devid_list - free storage allocated to dev_list list.  Return number
 * of entries on list at address supplied by argument count.  Return total
 * size of all device ids that were on the list.
 */
static size_t
free_devid_list(int *count)
{
	struct	devid_list	*curdlp;
	struct	devid_list	*nextlp;
	size_t	total_size = 0;
	int	n = 0;

	/*
	 * If there's nothing on the list.
	 */
	if ((curdlp = dlp->next) == NULL) {
		*count = 0;
		return (total_size);
	}

	while (curdlp) {
		nextlp = curdlp->next;
		total_size += curdlp->devid_size;
		(void) ddi_devid_free(curdlp->devid);
		kmem_free(curdlp, sizeof (struct devid_list));
		curdlp = nextlp;
		n++;
	}

	/*
	 * Insure that the devid_list anchor linkages are reinitialized in
	 * case of multiple calls (eg during testsuite execution).
	 */
	dlp->next = NULL;
	dlp->devid = NULL;

	*count = n;
	return (total_size);
}

/*
 * devid_is_unique - search for did on devid_list list.  Return "false" if
 * found.
 */
static int
devid_is_unique(ddi_devid_t did)
{
	struct	devid_list	*curdlp;
	int	unique = 1;	/* Default to true */

	/*
	 * If first call.
	 */
	if ((curdlp = dlp->next) == NULL) {
		return (1);
	}

	while (curdlp) {
		if (ddi_devid_compare(curdlp->devid, did) == 0) {
			unique = 0;
			break;
		}
		curdlp = curdlp->next;
	}
	return (unique);
}


/*
 * Called after the unit's snarf to cleanup the device id name space
 */
void
md_devid_cleanup(set_t setno, uint_t all)
{
	struct nm_next_hdr	*nh, *did_nh, *this_nh, *did_shr_nh;
	struct did_min_name	*did_n;
	size_t			offset, n_offset;
	struct devid_min_rec	*record;
	mdkey_t			did_key;
	size_t			n_size;
	int			doit;

	/*
	 * If it is an empty name space
	 */
	if (((nh = get_first_record(setno, 0, NM_NOTSHARED)) == NULL) ||
		((did_nh = get_first_record(setno, 1, NM_DEVID | NM_NOTSHARED))
			== NULL) ||
		((did_shr_nh = get_first_record(setno, 1, NM_DEVID |
			NM_SHARED)) == NULL)) {
		return;
	}

	/*
	 * Or the name space is empty
	 */
	this_nh = did_nh->nmn_nextp;
	record = this_nh->nmn_record;

	if (((struct nm_rec_hdr *)record)->r_used_size ==
		sizeof (struct nm_rec_hdr)) {
		return;
	}

	/*
	 * Not empty
	 */
	n_offset = offset = (sizeof (struct devid_min_rec) -
		sizeof (struct did_min_name));
	did_n = &(record->minor_name[0]);

	/*CONSTCOND*/
	while (1) {
		did_key = did_n->min_devid_key;
		n_size = DID_NAMSIZ((struct did_min_name *)did_n);

		/*
		 * It is not in the primary, remove it from the devid nmspace
		 */
		doit = (all ? 1 :
			(lookup_entry(nh, setno, MD_SIDEWILD, did_n->min_key,
				NODEV64, 0L) == NULL));
		if (doit) {
			(void) remove_entry(did_nh, did_n->min_side,
					did_n->min_key, NM_DEVID);
			(void) remove_shared_entry(did_shr_nh, did_key,
					(char *)0, NM_DEVID);
			/*
			 * We delete something so reset scan
			 */
			offset = n_offset;
			did_n = &(record->minor_name[0]);
			if (did_n->min_key != NULL) {
				continue;
			} else {
				return;
			}
		}

		did_n = (struct did_min_name *)get_next_entry(this_nh,
			(caddr_t)did_n, n_size, &offset);

		/*
		 * Next record?
		 */
		if (did_n == NULL) {
			if (offset)
				return;
			/*
			 * Goto next record
			 */
			offset = n_offset;
			this_nh = this_nh->nmn_nextp;
			record = this_nh->nmn_record;
			did_n = &(record->minor_name[0]);
		}
	}
	/*NOTREACHED*/
}


/*
 * Resolve md_dev64_t by device id when current configure changes.  This
 * can happen before the system reboot or between snarf
 * and the first use of metadevice.  The configure change can
 * mean poweroff before boot and poweron after boot or recable
 * disks between snarf and the first open of metadevice.
 */
md_dev64_t
md_resolve_bydevid(minor_t mnum, md_dev64_t device, mdkey_t key)
{

	struct nm_name		*n;
	struct nm_next_hdr	*nh, *did_nh;
	struct did_min_name	*did_n;
	ddi_devid_t		devid;
	dev_t			*devs; /* ddi returns dev_t not md_dev64_t */
	int			ndevs,
				cnt;
	set_t			setno;
	int			update = 0;
	md_dev64_t		targ_dev;

	/* assign here so that lint does not complain */
	targ_dev = NODEV64;

	if (device != NODEV64 && (md_getmajor(device) == md_major))
		return (device);

	setno = MD_MIN2SET(mnum);

	if (((nh = get_first_record(setno, 0, NM_NOTSHARED)) == NULL) ||
		((n = (struct nm_name *)lookup_entry(nh, setno, MD_SIDEWILD,
			key, NODEV64, 0L)) == NULL)) {
		return (NODEV64);
	}

	/*
	 * Something can be resolved by device id
	 * Resolve by the device id and if it can't be resolved
	 * then return whatever passed in
	 */
	if (((did_nh = get_first_record(setno, 0, NM_DEVID | NM_NOTSHARED))
		!= NULL) && ((did_n = (struct did_min_name *)lookup_entry
		(did_nh, setno, MD_SIDEWILD, key, NODEV64, NM_DEVID))
		!= NULL)) {
		/*
		 * Get the current devt and update mddb devt if necessary
		 */
		devid =	(ddi_devid_t)getshared_name(setno,
			did_n->min_devid_key, NM_DEVID);

		if (devid && (ddi_lyr_devid_to_devlist(devid, did_n->min_name,
			&ndevs, &devs) == DDI_SUCCESS)) {

			/*
			 * This device has been powered off
			 */
			if (device == NODEV64) {
				device = md_expldev(devs[0]);
				update = 1;
			} else {
				for (cnt = 0; cnt < ndevs; cnt++) {
					if (device == md_expldev(devs[cnt]))
						break;
				}
				if (cnt == ndevs) {
					device = md_expldev(devs[0]);
					update = 1;
				}
			}

			/*
			 * Have devt so update name space also
			 */
			targ_dev = md_xlate_mini_2_targ(device);
			if (targ_dev == NODEV64)
				return (NODEV64);

			if (update &&
				!(md_get_setstatus(setno) & MD_SET_STALE)) {
				n->n_minor = md_getminor(targ_dev);
				/*
				 * If we have the key for the driver get
				 * it and update the entry. If it's not there
				 * we need to create it.
				 */
				if ((n->n_drv_key = getshared_key(setno,
				    md_targ_major_to_name(
				    md_getmajor(targ_dev)), 0L)) == MD_KEYBAD) {
					n->n_drv_key = setshared_name(setno,
					    md_targ_major_to_name(
					    md_getmajor(targ_dev)),
					    MD_KEYWILD, 0L);
				}
				(void) update_entry(nh, MD_SIDEWILD,
				    n->n_key, 0L);
			}
			/*
			 * Free memory
			 */
			(void) ddi_lyr_free_devlist(devs, ndevs);
		} else {
			/*
			 * if input devid is null or ddi_devid_lyr_devlist
			 * does not return success then return NODEV64
			 */
			device = NODEV64;
		}
	}
	return (device);
}
