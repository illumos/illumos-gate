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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <ctype.h>
#include <libdevinfo.h>
#include <mdiox.h>
#include <meta.h>
#include "meta_repartition.h"
#include "meta_set_prv.h"
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/lvm/md_mddb.h>
#include <sys/lvm/md_names.h>
#include <sys/lvm/md_crc.h>
#include <sys/lvm/md_convert.h>

typedef struct did_list {
	void		*rdid;	/* real did if replicated set */
	void		*did;	/* did stored in lb */
	char		*devname;
	dev_t		dev;
	uint_t		did_index;
	char		*minor_name;
	char		*driver_name;
	int		available;
	struct did_list	*next;
} did_list_t;

typedef struct replicated_disk {
	void			*old_devid;
	void 			*new_devid;
	struct replicated_disk	*next;
} replicated_disk_t;

/*
 * The current implementation limits the max device id length to 256 bytes.
 * Should the max device id length be increased, this definition would have to
 * be bumped up accordingly
 */
#define	MAX_DEVID_LEN		256

/*
 * We store a global list of all the replicated disks in the system. In
 * order to prevent us from performing a linear search on this list, we
 * store the disks in a two dimensional sparse array. The disks are bucketed
 * based on the length of their device ids.
 */
static replicated_disk_t *replicated_disk_list[MAX_DEVID_LEN + 1] = {NULL};

/*
 * The list of replicated disks is built just once and this flag is set
 * once it's done
 */
int replicated_disk_list_built_pass1 = 0;
int replicated_disk_list_built_pass2 = 0;
int *replicated_disk_list_built;

static void free_did_list(did_list_t *did_listp);

/*
 * Map logical blk to physical
 *
 * This is based on the routine of the same name in the md kernel module (see
 * file md_mddb.c), with the following caveats:
 *
 * - The kernel routine works on in core master blocks, or mddb_mb_ic_t; this
 * routine works instead on the mddb_mb_t read directly from the disk
 */
daddr_t
getphysblk(
	mddb_block_t	blk,
	mddb_mb_t	*mbp
)
{
	/*
	 * Sanity check: is the block within range?  If so, we then assume
	 * that the block range map in the master block is valid and
	 * consistent with the block count.  Unfortunately, there is no
	 * reliable way to validate this assumption.
	 */
	if (blk >= mbp->mb_blkcnt || blk >= mbp->mb_blkmap.m_consecutive)
		return ((daddr_t)-1);

	return (mbp->mb_blkmap.m_firstblk + blk);
}



/*
 * drive_append()
 *
 * Append to tail of linked list of md_im_drive_info_t.
 *
 * Will allocate space for new node and copy args into new space.
 *
 * Returns pointer to new node.
 */
static md_im_drive_info_t *
drive_append(
	md_im_drive_info_t	**midpp,
	mddrivename_t		*dnp,
	did_list_t		*nonrep_did_listp,
	minor_t			mnum,
	md_timeval32_t		timestamp,
	md_im_replica_info_t	*mirp
)
{
	md_im_drive_info_t	*midp;
	int			o_devid_sz;
	int			devid_sz;

	for (; (*midpp != NULL); midpp = &((*midpp)->mid_next))
		;

	midp = *midpp = Zalloc(sizeof (md_im_drive_info_t));

	midp->mid_dnp = dnp;

	/*
	 * If rdid is not NULL then we know we are dealing with
	 * replicated diskset case. 'devid_sz' will always be the
	 * size of a valid devid which can be 'did' or 'rdid'
	 */

	if (nonrep_did_listp->rdid) {
		devid_sz = devid_sizeof(nonrep_did_listp->rdid);
		midp->mid_devid = (void *)Malloc(devid_sz);
		(void) memcpy(midp->mid_devid, nonrep_did_listp->rdid,
		    devid_sz);
		/*
		 * Also need to store the 'other' devid
		 */
		o_devid_sz = devid_sizeof((ddi_devid_t)(nonrep_did_listp->did));
		midp->mid_o_devid = (void *)Malloc(o_devid_sz);
		(void) memcpy(midp->mid_o_devid, nonrep_did_listp->did,
		    o_devid_sz);
		midp->mid_o_devid_sz = o_devid_sz;
	} else {
		devid_sz = devid_sizeof(nonrep_did_listp->did);
		midp->mid_devid = (void *)Malloc(devid_sz);
		/*
		 * In the case of regular diskset, midp->mid_o_devid
		 * will be a NULL pointer
		 */
		(void) memcpy(midp->mid_devid, nonrep_did_listp->did, devid_sz);
	}

	midp->mid_devid_sz = devid_sz;
	midp->mid_setcreatetimestamp = timestamp;
	midp->mid_available = nonrep_did_listp->available;
	if (nonrep_did_listp->minor_name) {
		(void) strlcpy(midp->mid_minor_name,
		    nonrep_did_listp->minor_name, MDDB_MINOR_NAME_MAX);
	}
	midp->mid_mnum = mnum;
	if (nonrep_did_listp->driver_name)
		midp->mid_driver_name = Strdup(nonrep_did_listp->driver_name);
	midp->mid_replicas = mirp;
	if (nonrep_did_listp->devname)
		midp->mid_devname = Strdup(nonrep_did_listp->devname);
	return (midp);
}



/*
 * drive_append_wrapper()
 *
 * Constant time append wrapper; the append function will always walk the list,
 * this will take a tail argument and use the append function on just the tail
 * node, doing the appropriate old-tail-next-pointer bookkeeping.
 */
static md_im_drive_info_t **
drive_append_wrapper(
	md_im_drive_info_t	**tailpp,
	mddrivename_t		*dnp,
	did_list_t		*nonrep_did_listp,
	minor_t			mnum,
	md_timeval32_t		timestamp,
	md_im_replica_info_t	*mirp
)
{
	(void) drive_append(tailpp, dnp, nonrep_did_listp, mnum, timestamp,
	    mirp);

	if ((*tailpp)->mid_next == NULL)
		return (tailpp);

	return (&((*tailpp)->mid_next));
}



/*
 * replica_append()
 *
 * Append to tail of linked list of md_im_replica_info_t.
 *
 * Will allocate space for new node and copy args into new space.
 *
 * Returns pointer to new node.
 */
static md_im_replica_info_t *
replica_append(
	md_im_replica_info_t	**mirpp,
	int			flags,
	daddr32_t		offset,
	daddr32_t		length,
	md_timeval32_t		timestamp
)
{
	md_im_replica_info_t	*mirp;

	for (; (*mirpp != NULL); mirpp = &((*mirpp)->mir_next))
		;

	mirp = *mirpp = Zalloc(sizeof (md_im_replica_info_t));

	mirp->mir_flags = flags;
	mirp->mir_offset = offset;
	mirp->mir_length = length;
	mirp->mir_timestamp = timestamp;

	return (mirp);

}



/*
 * replica_append_wrapper()
 *
 * Constant time append wrapper; the append function will always walk the list,
 * this will take a tail argument and use the append function on just the tail
 * node, doing the appropriate old-tail-next-pointer bookkeeping.
 */
static md_im_replica_info_t **
replica_append_wrapper(
	md_im_replica_info_t	**tailpp,
	int			flags,
	daddr32_t		offset,
	daddr32_t		length,
	md_timeval32_t		timestamp
)
{
	(void) replica_append(tailpp, flags, offset, length, timestamp);

	if ((*tailpp)->mir_next == NULL)
		return (tailpp);

	return (&(*tailpp)->mir_next);
}

/*
 * map_replica_disk()
 *
 * Searches the device id list for a specific
 * disk based on the locator block device id array index.
 *
 * Returns a pointer to the did_list node if a match was
 * found or NULL otherwise.
 */
static did_list_t *
map_replica_disk(
	did_list_t	*did_listp,
	int		did_index
)
{
	did_list_t	*tailp = did_listp;

	while (tailp != NULL) {
		if (tailp->did_index == did_index)
			return (tailp);
		tailp = tailp->next;
	}

	/* not found, return failure */
	return (NULL);
}

/*
 * replicated_list_lookup()
 *
 * looks up a replicated disk entry in the global replicated disk list
 * based upon the length of that disk's device id. returns the new device id
 * for the disk.
 * If you store the returned devid you must create a local copy.
 */
void *
replicated_list_lookup(
	uint_t	devid_len,
	void	*old_devid
)
{
	replicated_disk_t *head = NULL;

	assert(devid_len <= MAX_DEVID_LEN);
	head = replicated_disk_list[devid_len];

	if (head == NULL)
		return (NULL);

	do {
		if (devid_compare((ddi_devid_t)old_devid,
			(ddi_devid_t)head->old_devid) == 0)
			return (head->new_devid);
		head = head->next;
	} while (head != NULL);

	return (NULL);
}

/*
 * replicated_list_insert()
 *
 * inserts a replicated disk entry into the global replicated disk list
 */
static void
replicated_list_insert(
	size_t	old_devid_len,
	void	*old_devid,
	void	*new_devid
)
{
	replicated_disk_t	*repl_disk, **first_entry;
	void			*repl_old_devid = NULL;

	assert(old_devid_len <= MAX_DEVID_LEN);

	repl_disk = Zalloc(sizeof (replicated_disk_t));
	repl_old_devid = Zalloc(old_devid_len);
	(void) memcpy(repl_old_devid, (void *)old_devid, old_devid_len);

	repl_disk->old_devid = repl_old_devid;
	repl_disk->new_devid = new_devid;

	first_entry = &replicated_disk_list[old_devid_len];

	if (*first_entry == NULL) {
		*first_entry = repl_disk;
		return;
	}

	repl_disk->next = *first_entry;
	replicated_disk_list[old_devid_len] = repl_disk;
}

/*
 * get_replica_disks()
 *
 * Will step through the locator records in the supplied locator block, and add
 * each one with an active replica to a supplied list of md_im_drive_info_t, and
 * add the appropriate replicas to the md_im_replica_info_t contained therein.
 */
static void
get_replica_disks(
	md_im_set_desc_t	*misp,
	did_list_t		*did_listp,
	mddb_mb_t		*mb,
	mddb_lb_t		*lbp,
	md_error_t		*ep
)
{
	mddrivename_t		*dnp;
	int			indx, on_list;
	mdsetname_t		*sp = metasetname(MD_LOCAL_NAME, ep);
	int			flags;
	did_list_t		*replica_disk;
	daddr32_t		offset;
	daddr32_t		length;
	md_timeval32_t		timestamp;
	md_im_replica_info_t	**mirpp = NULL;
	md_im_drive_info_t	**midpp = &misp->mis_drives;
	md_im_drive_info_t	*midp;

	for (indx = 0; indx < lbp->lb_loccnt; indx++) {

		on_list = 0;
		if ((lbp->lb_locators[indx].l_flags == 0) ||
		    (lbp->lb_locators[indx].l_flags & MDDB_F_DELETED))
			continue;

		/*
		 * search the device id list for a
		 * specific ctds based on the locator
		 * block device id array index.
		 */
		replica_disk = map_replica_disk(did_listp, indx);

		assert(replica_disk != NULL);


		/*
		 * metadrivename() can fail for a slice name
		 * if there is not an existing mddrivename_t.
		 * So we use metadiskname() to strip the slice
		 * number.
		 */
		dnp = metadrivename(&sp, metadiskname(replica_disk->devname),
		    ep);

		for (midp = misp->mis_drives; midp != NULL;
			midp = midp->mid_next) {
			if (dnp == midp->mid_dnp) {
				/*
				 * You could get a dnp match, but if 1 disk
				 * is unavailable and the other isn't, they
				 * will have the same dnp due
				 * to the name being the same, but in fact
				 * are different disks.
				 */
				if (midp->mid_available ==
				    replica_disk->available) {
					on_list = 1;
					mirpp = &midp->mid_replicas;
					break;
				}
			}
		}

		/*
		 * New on the list so add it
		 */
		if (!on_list) {
			mddb_mb_t	*mbp;
			uint_t		sliceno;
			mdname_t	*rsp;
			int		fd = -1;

			mbp = Malloc(DEV_BSIZE);

			/*
			 * If the disk isn't available, we don't
			 * want to try to read from it.
			 */
			if (replica_disk->available == MD_IM_DISK_AVAILABLE) {
				/* determine the replica slice */
				if (meta_replicaslice(dnp, &sliceno,
				    ep) != 0) {
					Free(mbp);
					continue;
				}

				/*
				 * if the replica slice size is zero,
				 * don't bother opening
				 */
				if (dnp->vtoc.parts[sliceno].size == 0) {
					Free(mbp);
					continue;
				}

				if ((rsp = metaslicename(dnp, sliceno,
				    ep)) == NULL) {
					Free(mbp);
					continue;
				}

				if ((fd = open(rsp->rname,
				    O_RDONLY| O_NDELAY)) < 0) {
					Free(mbp);
					continue;
				}

				/*
				 * a drive may not have a master block
				 */
				if (read_master_block(ep, fd, mbp,
				    DEV_BSIZE) <= 0) {
					mdclrerror(ep);
					Free(mbp);
					(void) close(fd);
					continue;
				}

				(void) close(fd);
			}
			midpp = drive_append_wrapper(midpp, dnp,
			    replica_disk,
			    meta_getminor(replica_disk->dev),
			    mbp->mb_setcreatetime, NULL);
			mirpp = &((*midpp)->mid_replicas);
			Free(mbp);
		}

		/*
		 * For either of these assertions to fail, it implies
		 * a NULL return from metadrivename() above.  Since
		 * the args came from a presumed valid locator block,
		 * that's Bad.
		 */
		assert(midpp != NULL);
		assert(mirpp != NULL);

		/*
		 * Extract the parameters describing this replica.
		 *
		 * The magic "1" in the length calculation accounts
		 * for the length of the master block, in addition to
		 * the block count it describes.  (The master block
		 * will always take up one block on the disk, and
		 * there will always only be one master block per
		 * replica, even though much of the code is structured
		 * to handle noncontiguous replicas.)
		 */
		flags = lbp->lb_locators[indx].l_flags;
		offset = lbp->lb_locators[indx].l_blkno;
		length = mb->mb_blkcnt + 1;
		timestamp = mb->mb_setcreatetime;

		mirpp = replica_append_wrapper(mirpp, flags,
			offset, length, timestamp);

		/*
		 * If we're here it means -
		 *
		 * we've added the disk to the list of
		 *    disks.
		 */

		/*
		 * We need to bump up the number of active
		 * replica count for each such replica that is
		 * active so that it can be used later for replica
		 * quorum check.
		 */
		if (flags & MDDB_F_ACTIVE) {
			misp->mis_active_replicas++;
		}
	}
}


/*
 * append_pnm_rec()
 *
 * Append pnm_rec_t entry to list of physical devices in the diskset.  Entry
 * contains a mapping of n_key in NM namespace(or min_key in DID_NM namespace)
 * to name of the physical device.  This list will be used to ensure that the
 * correct names of the physical devices are printed in the metastat output--the
 * NM namespace might have stale information about where the physical devices
 * were previously located when the diskset was last active.
 */
static void
append_pnm_rec(
	pnm_rec_t	**pnm,
	mdkey_t		min_key,
	char		*n_name
)
{
	pnm_rec_t 	*tmp_pnm;
	char 		*p;
	int 		len;

	if ((p = strrchr(n_name, '/')) != NULL)
		p++;

	/*
	 * Allocates pnm_rec_t record for the physical
	 * device.
	 */
	len = strlen(p) + 1; /* Length of name plus Null term */
	tmp_pnm  = Malloc(sizeof (pnm_rec_t) + len);
	(void) strncpy(tmp_pnm->n_name, p, len);
	tmp_pnm->n_key = min_key;

	/*
	 * Adds new element to head of pnm_rec_t list.
	 */
	if (*pnm == NULL) {
		tmp_pnm->next = NULL;
		*pnm = tmp_pnm;
	} else {
		tmp_pnm->next = *pnm;
		*pnm = tmp_pnm;
	}
}

/*
 * free_pnm_rec_list()
 *
 * Freeing all pnm_rec_t entries on the list of physical devices in the
 * diskset.
 */
void
free_pnm_rec_list(pnm_rec_t **pnm)
{
	pnm_rec_t	*tmp_pnm, *rm_pnm;

	for (tmp_pnm = *pnm; tmp_pnm != NULL; ) {
		rm_pnm = tmp_pnm;
		tmp_pnm = tmp_pnm->next;
		Free(rm_pnm);
	}

	*pnm = NULL;
}


/*
 * get_disks_from_didnamespace()
 * This function was origionally called: get_nonreplica_disks()
 *
 * Extracts the disks without replicas from the locator name space and adds them
 * to the supplied list of md_im_drive_info_t.
 * If the print verbose option was given then this function will also
 * correct the nm namespace so that the n_name is the right ctd name
 */
static void
get_disks_from_didnamespace(
	md_im_set_desc_t	*misp,
	pnm_rec_t		**pnm,
	mddb_rb_t		*nm,
	mddb_rb_t		*shrnm,
	mddb_rb_t		*did_nm,
	mddb_rb_t		*did_shrnm,
	uint_t 			imp_flags,
	int			replicated,
	md_error_t		*ep
)
{
	char			*search_path = "/dev";
	devid_nmlist_t		*nmlist;
	md_im_drive_info_t	*midp, **midpp = &misp->mis_drives;
	mddrivename_t		*dnp;
	mdsetname_t		*sp = metasetname(MD_LOCAL_NAME, ep);
	mddb_rb_t		*rbp_did = did_nm;
	mddb_rb_t		*rbp_did_shr = did_shrnm;
	mddb_rb_t		*rbp_nm = nm;
	mddb_rb_t		*rbp_shr_nm = shrnm;
	int			on_list = 0;
	struct devid_min_rec	*did_rec;
	struct devid_shr_rec	*did_shr_rec;
	struct nm_rec		*namesp_rec;
	struct nm_shr_rec	*namesp_shr_rec;
	struct did_shr_name	*did;
	struct did_min_name	*min;
	void			*r_did;	/* NULL if not a replicated diskset */
	void			*valid_did;
	int			avail = 0;
	struct nm_name		*nmp;
	struct nm_shared_name	*snmp;
	mdkey_t			drv_key, key, dev_key;
	minor_t			mnum = 0;
	did_list_t		*nonrep_did_listp;
	size_t			used_size, offset;

	/*
	 * We got a pointer to an mddb record, which we expect to contain a
	 * name record; extract the pointer thereto.
	 */
	/* LINTED */
	did_rec = (struct devid_min_rec *)((caddr_t)(&rbp_did->rb_data));
	/* LINTED */
	did_shr_rec = (struct devid_shr_rec *)
	    ((caddr_t)(&rbp_did_shr->rb_data));
	/* LINTED */
	namesp_rec = (struct nm_rec *)((caddr_t)(&rbp_nm->rb_data));
	/* LINTED */
	namesp_shr_rec = (struct nm_shr_rec *)((caddr_t)(&rbp_shr_nm->rb_data));

	/*
	 * Skip the nm_rec_hdr and iterate on the array of struct minor_name
	 * at the end of the devid_min_rec
	 */
	for (min = &did_rec->minor_name[0]; min->min_devid_key != 0;
	    /* LINTED */
	    min = (struct did_min_name *)((char *)min + DID_NAMSIZ(min))) {

		on_list = 0;
		r_did = NULL;
		nonrep_did_listp = Zalloc(sizeof (struct did_list));

		/*
		 * For a given DID_NM key, locate the corresponding device
		 * id from DID_NM_SHR
		 */
		for (did = &did_shr_rec->device_id[0]; did->did_key != 0;
		    /* LINTED */
		    did = (struct did_shr_name *)
		    ((char *)did + DID_SHR_NAMSIZ(did))) {
			/*
			 * We got a match, this is the device id we're
			 * looking for
			 */
			if (min->min_devid_key == did->did_key)
				break;
		}

		if (did->did_key == 0) {
			/* we didn't find a match */
			assert(did->did_key != 0);
			md_exit(NULL, 1);
		}

		/*
		 * If replicated diskset
		 */
		if (replicated) {
			size_t		new_devid_len, old_devid_len;
			char		*temp;
			/*
			 * In this case, did->did_devid will
			 * be invalid so lookup the real one
			 */
			temp = replicated_list_lookup(did->did_size,
			    did->did_devid);
			if (temp == NULL) {
				/* we have a partial replicated set, fake it */
				new_devid_len = did->did_size;
				r_did = Zalloc(new_devid_len);
				(void) memcpy(r_did, did->did_devid,
				    new_devid_len);
			} else {
				new_devid_len = devid_sizeof((ddi_devid_t)temp);
				r_did = Zalloc(new_devid_len);
				(void) memcpy(r_did, temp, new_devid_len);
			}
			valid_did = r_did;
			nonrep_did_listp->rdid = Zalloc(new_devid_len);
			(void) memcpy(nonrep_did_listp->rdid, r_did,
			    new_devid_len);
			old_devid_len =
			    devid_sizeof((ddi_devid_t)did->did_devid);
			nonrep_did_listp->did = Zalloc(old_devid_len);
			(void) memcpy((void *)nonrep_did_listp->did,
			    (void *)did->did_devid, old_devid_len);
		} else {
			size_t		new_devid_len;

			valid_did = did->did_devid;
			new_devid_len =
			    devid_sizeof((ddi_devid_t)did->did_devid);
			nonrep_did_listp->did = Zalloc(new_devid_len);
			(void) memcpy((void *)nonrep_did_listp->did,
			    (void *)did->did_devid, new_devid_len);
		}

		/*
		 * Get a ctds mapping for that device id.
		 * Since disk is being imported into this system,
		 * just use the first ctds in list.
		 */
		if (meta_deviceid_to_nmlist(search_path,
		    (ddi_devid_t)valid_did,
		    &min->min_name[0], &nmlist) == 0) {
			/*
			 * We know the disk is available. Use the
			 * device information in nmlist.
			 */
			assert(nmlist[0].devname != NULL);
			nonrep_did_listp->devname = Strdup(nmlist[0].devname);
			nonrep_did_listp->available = MD_IM_DISK_AVAILABLE;
			avail = 0;
			mnum = meta_getminor(nmlist[0].dev);
			devid_free_nmlist(nmlist);
		} else {
			/*
			 * The disk is not available. That means we need to
			 * use the (old) device information stored in the
			 * namespace.
			 */
			/* search in nm space for a match */
			offset = sizeof (struct nm_rec) -
			    sizeof (struct nm_name);
			used_size =  namesp_rec->r_rec_hdr.r_used_size - offset;
			for (nmp = &namesp_rec->r_name[0]; nmp->n_key != 0;
			    /* LINTED */
			    nmp = (struct nm_name *)((char *)nmp +
			    NAMSIZ(nmp))) {
				if (nmp->n_key == min->min_key)
					break;
			    used_size -=  NAMSIZ(nmp);
			    if ((int)used_size <= 0) {
				md_exit(NULL, 1);
			    }
			}

			if (nmp->n_key == 0) {
				assert(nmp->n_key != 0);
				md_exit(NULL, 1);
			}
			dev_key = nmp->n_dir_key;
			snmp = &namesp_shr_rec->sr_name[0];
			key = snmp->sn_key;
			/*
			 * Use the namespace n_dir_key to look in the
			 * shared namespace. When we find the matching
			 * key, that is the devname and minor number we
			 * want.
			 */
			offset = sizeof (struct nm_shr_rec) -
			    sizeof (struct nm_shared_name);
			used_size = namesp_shr_rec->sr_rec_hdr.r_used_size -
			    offset;
			while (key != 0) {
				if (dev_key == key) {
					/*
					 * This complicated looking series
					 * of code creates a devname of the
					 * form  <sn_name>/<n_name> which
					 * will look like /dev/dsk/c1t4d0s0.
					 */
					nonrep_did_listp->devname =
					    Zalloc(strlen(nmp->n_name) +
					    strlen(snmp->sn_name) + 2);
					(void) strlcpy(
					    nonrep_did_listp->devname,
					    snmp->sn_name,
					    strlen(snmp->sn_name));
					(void) strlcat(
					    nonrep_did_listp->devname, "/",
					    strlen(nmp->n_name) +
					    strlen(snmp->sn_name) + 2);
					(void) strlcat(
					    nonrep_did_listp->devname,
					    nmp->n_name,
					    strlen(nmp->n_name) +
					    strlen(snmp->sn_name) + 2);
					mnum = nmp->n_minor;
					break;
				}
				/* LINTED */
				snmp = (struct nm_shared_name *)((char *)snmp +
				    SHR_NAMSIZ(snmp));
				key = snmp->sn_key;
				used_size -= SHR_NAMSIZ(snmp);
				if ((int)used_size <= 0) {
					md_exit(NULL, 1);
				}
			}
			if (key == 0) {
				nonrep_did_listp->devname = NULL;
				mnum = 0;
			}

			nonrep_did_listp->available = MD_IM_DISK_NOT_AVAILABLE;
			nonrep_did_listp->minor_name = Strdup(min->min_name);
			avail = 1;
			drv_key = nmp->n_drv_key;
			snmp = &namesp_shr_rec->sr_name[0];
			key = snmp->sn_key;
			/*
			 * Use the namespace n_drv_key to look in the
			 * shared namespace. When we find the matching
			 * key, that is the driver name for the disk.
			 */
			offset = sizeof (struct nm_shr_rec) -
			    sizeof (struct nm_shared_name);
			used_size = namesp_shr_rec->sr_rec_hdr.r_used_size -
			    offset;
			while (key != 0) {
				if (drv_key == key) {
					nonrep_did_listp->driver_name =
					    Strdup(snmp->sn_name);
					break;
				}
				/* LINTED */
				snmp = (struct nm_shared_name *)((char *)snmp +
				    SHR_NAMSIZ(snmp));
				key = snmp->sn_key;
				used_size -= SHR_NAMSIZ(snmp);
				if ((int)used_size <= 0) {
					md_exit(NULL, 1);
				}
			}
			if (key == 0)
				nonrep_did_listp->driver_name = NULL;
		}
		dnp = metadrivename(&sp,
		    metadiskname(nonrep_did_listp->devname), ep);
		/*
		 * Add drive to pnm_rec_t list of physical devices for
		 * metastat output.
		 */
		if (imp_flags & META_IMP_VERBOSE) {
			append_pnm_rec(pnm, min->min_key,
			    nonrep_did_listp->devname);
		}

		assert(dnp != NULL);
		/* Is it already on the list? */
		for (midp = misp->mis_drives; midp != NULL;
		    midp = midp->mid_next) {
			if (midp->mid_dnp == dnp) {
				if (midp->mid_available ==
				    nonrep_did_listp->available) {
					on_list = 1;
					break;
				}
			}
		}

		if (!on_list) {
			mddb_mb_t	*mbp;
			uint_t		sliceno;
			mdname_t	*rsp;
			int		fd = -1;

			mbp = Malloc(DEV_BSIZE);

			if (!avail) {
				/* determine the replica slice */
				if (meta_replicaslice(dnp, &sliceno,
				    ep) != 0) {
					Free(mbp);
					free_did_list(nonrep_did_listp);
					continue;
				}

				/*
				 * if the replica slice size is zero,
				 * don't bother opening
				 */
				if (dnp->vtoc.parts[sliceno].size
				    == 0) {
					Free(mbp);
					free_did_list(nonrep_did_listp);
					continue;
				}

				if ((rsp = metaslicename(dnp, sliceno,
				    ep)) == NULL) {
					Free(mbp);
					free_did_list(nonrep_did_listp);
					continue;
				}

				if ((fd = open(rsp->rname,
				    O_RDONLY| O_NDELAY)) < 0) {
					Free(mbp);
					free_did_list(nonrep_did_listp);
					continue;
				}

				/*
				 * a drive may not have a master block
				 */
				if (read_master_block(ep, fd, mbp,
				    DEV_BSIZE) <= 0) {
					mdclrerror(ep);
					Free(mbp);
					free_did_list(nonrep_did_listp);
					(void) close(fd);
					continue;
				}

				(void) close(fd);
			}
			/*
			 * If it is replicated diskset,
			 * r_did will be non-NULL.
			 * Passing the devname as NULL because field
			 * is not currently used for a non-replica disk.
			 */
			midpp = drive_append_wrapper(midpp,
			    dnp, nonrep_did_listp,
			    mnum, mbp->mb_setcreatetime, NULL);
			Free(mbp);
			free_did_list(nonrep_did_listp);
		}
	free_did_list(nonrep_did_listp);
	}
}

/*
 * set_append()
 *
 * Append to tail of linked list of md_im_set_desc_t.
 *
 * Will allocate space for new node AND populate it by extracting disks with
 * and without replicas from the locator blocks and locator namespace.
 *
 * Returns pointer to new node.
 */
static md_im_set_desc_t *
set_append(
	md_im_set_desc_t	**mispp,
	did_list_t		*did_listp,
	mddb_mb_t		*mb,
	mddb_lb_t		*lbp,
	mddb_rb_t		*nm,
	mddb_rb_t		*shrnm,
	pnm_rec_t		**pnm,
	mddb_rb_t		*did_nm,
	mddb_rb_t		*did_shrnm,
	uint_t 			imp_flags,
	md_error_t		*ep
)
{

	md_im_set_desc_t	*misp;
	set_t			setno = mb->mb_setno;
	int			partial = imp_flags & MD_IM_PARTIAL_DISKSET;
	int			replicated = imp_flags & MD_IM_SET_REPLICATED;

	/* run to end of list */
	for (; (*mispp != NULL); mispp = &((*mispp)->mis_next))
		;

	/* allocate new list element */
	misp = *mispp = Zalloc(sizeof (md_im_set_desc_t));

	if (replicated)
		misp->mis_flags = MD_IM_SET_REPLICATED;

	misp->mis_oldsetno = setno;
	misp->mis_partial = partial;

	/* Get the disks with and without replicas */
	get_replica_disks(misp, did_listp, mb, lbp, ep);

	if (nm != NULL && did_nm != NULL && did_shrnm != NULL) {
		get_disks_from_didnamespace(misp, pnm, nm, shrnm, did_nm,
		    did_shrnm, imp_flags, replicated, ep);
	}

	/*
	 * An error in this struct could come from either of
	 * the above routines;
	 * in both cases, we want to pass it back on up.
	 */

	return (misp);
}


/*
 * add_disk_names()
 *
 * Iterator to walk the minor node tree of the device snapshot, adding only the
 * first non-block instance of each non-cdrom minor node to a list of disks.
 */
static int
add_disk_names(di_node_t node, di_minor_t minor, void *args)
{
	char			*search_path = "/dev";
	ddi_devid_t		devid = di_devid(node);
	devid_nmlist_t		*nm;
	char			*min = di_minor_name(minor);
	md_im_names_t		*cnames = (md_im_names_t *)args;
	static di_node_t	save_node = NULL;

	/*
	 * skip CD devices
	 * If a device does not have a device id, we can't
	 * do anything with it so just exclude it from our
	 * list.
	 *
	 * This would also encompass CD devices and floppy
	 * devices that don't have a device id.
	 */
	if (devid == NULL) {
		return (DI_WALK_CONTINUE);
	}

	/* char disk devices (as opposed to block) */
	if (di_minor_spectype(minor) == S_IFCHR) {

		/* only first occurrence (slice 0) of each instance */
		if (save_node == NULL || node != save_node) {
			save_node = node;
			if (meta_deviceid_to_nmlist(search_path, devid,
			    min, &nm) == 0) {
				int	index = cnames->min_count++;

				assert(nm->devname != NULL);
				cnames->min_names =
					Realloc(cnames->min_names,
						cnames->min_count *
						sizeof (char *));

				assert(cnames->min_names != NULL);
				cnames->min_names[index] =
					metadiskname(nm->devname);
				devid_free_nmlist(nm);
			}
		}
	}
	return (DI_WALK_CONTINUE);
}



/*
 * meta_list_disks()
 *
 * Snapshots the device tree and extracts disk devices from the snapshot.
 */
int
meta_list_disks(md_error_t *ep, md_im_names_t *cnames)
{
	di_node_t root_node;

	assert(cnames != NULL);
	cnames->min_count = 0;
	cnames->min_names = NULL;

	if ((root_node = di_init("/", DINFOCPYALL|DINFOFORCE))
	    == DI_NODE_NIL) {
		return (mdsyserror(ep, errno, NULL));
	}

	(void) di_walk_minor(root_node, DDI_NT_BLOCK, 0, cnames,
	    add_disk_names);

	di_fini(root_node);
	return (0);
}

/*
 * meta_imp_drvused
 *
 * Checks if given drive is mounted, swapped, part of disk configuration
 * or in use by SVM.  ep also has error code set up if drive is in use.
 *
 * Returns 1 if drive is in use.
 * Returns 0 if drive is not in use.
 */
int
meta_imp_drvused(
	mdsetname_t		*sp,
	mddrivename_t		*dnp,
	md_error_t		*ep
)
{
	md_error_t		status = mdnullerror;
	md_error_t		*db_ep = &status;

	/*
	 * We pass in db_ep to meta_setup_db_locations
	 * and never ever use the error contained therein
	 * because all we're interested in is a check to
	 * see whether any local metadbs are present.
	 */
	if ((meta_check_drivemounted(sp, dnp, ep) != 0) ||
	    (meta_check_driveswapped(sp, dnp, ep) != 0) ||
	    (((meta_setup_db_locations(db_ep) == 0) &&
	    ((meta_check_drive_inuse(sp, dnp, 1, ep) != 0) ||
	    (meta_check_driveinset(sp, dnp, ep) != 0))))) {
		return (1);
	} else {
		return (0);
	}
}

/*
 * meta_prune_cnames()
 *
 * Removes in-use disks from the list prior to further processing.
 *
 * Return value depends on err_on_prune flag: if set, and one or more disks
 * are pruned, the return list will be the pruned disks.  If not set, or if no
 * disks are pruned, the return list will be the unpruned disks.
 */
mddrivenamelist_t *
meta_prune_cnames(
	md_error_t *ep,
	md_im_names_t *cnames,
	int err_on_prune
)
{
	int			d;
	int			fcount = 0;
	mddrivenamelist_t	*dnlp = NULL;
	mddrivenamelist_t	**dnlpp = &dnlp;
	mddrivenamelist_t	*fdnlp = NULL;
	mddrivenamelist_t	**fdnlpp = &fdnlp;
	mdsetname_t		*sp = metasetname(MD_LOCAL_NAME, ep);

	for (d = 0; d < cnames->min_count; ++d) {
		mddrivename_t	*dnp;

		dnp = metadrivename(&sp, cnames->min_names[d], ep);
		if (dnp == NULL) {
			/*
			 * Assuming we're interested in knowing about
			 * whatever error occurred, but not in stopping.
			 */
			mde_perror(ep, cnames->min_names[d]);
			mdclrerror(ep);

			continue;
		}

		/*
		 * Check if the drive is inuse.
		 */
		if (meta_imp_drvused(sp, dnp, ep)) {
			fdnlpp = meta_drivenamelist_append_wrapper(fdnlpp, dnp);
			fcount++;
			mdclrerror(ep);
		} else {
			dnlpp = meta_drivenamelist_append_wrapper(dnlpp, dnp);
		}
	}

	if (fcount) {
		if (err_on_prune) {
			(void) mddserror(ep, MDE_DS_DRIVEINUSE, 0,
			    NULL, fdnlp->drivenamep->cname, NULL);
			metafreedrivenamelist(dnlp);
			return (fdnlp);
		}
		metafreedrivenamelist(fdnlp);
	}

	return (dnlp);
}

/*
 * read_master_block()
 *
 * Returns:
 *	< 0 for failure
 *	  0 for no valid master block
 *	  1 for valid master block
 *
 * The supplied buffer will be filled in for EITHER 0 or 1.
 */
int
read_master_block(
	md_error_t	*ep,
	int		fd,
	void		*bp,
	int		bsize
)
{
	mddb_mb_t	*mbp = bp;
	int		rval = 1;

	assert(bp != NULL);

	if (lseek(fd, (off_t)dbtob(16), SEEK_SET) < 0)
		return (mdsyserror(ep, errno, NULL));

	if (read(fd, bp, bsize) != bsize)
		return (mdsyserror(ep, errno, NULL));

	/*
	 * The master block magic number can either be MDDB_MAGIC_MB in
	 * the case of a real master block, or, it can be MDDB_MAGIC_DU
	 * in the case of a dummy master block
	 */
	if ((mbp->mb_magic != MDDB_MAGIC_MB) &&
	    (mbp->mb_magic != MDDB_MAGIC_DU)) {
		rval = 0;
		(void) mdmddberror(ep, MDE_DB_MASTER, 0, 0, 0, NULL);
	}

	if (mbp->mb_revision != MDDB_REV_MB) {
		rval = 0;
	}

	return (rval);
}

/*
 * read_locator_block()
 *
 * Returns:
 *	< 0 for failure
 *	  0 for no valid locator block
 *	  1 for valid locator block
 */
int
read_locator_block(
	md_error_t	*ep,
	int		fd,
	mddb_mb_t	*mbp,
	void		*bp,
	int		bsize
)
{
	mddb_lb_t	*lbp = bp;

	assert(bp != NULL);

	if (lseek(fd, (off_t)dbtob(mbp->mb_blkmap.m_firstblk), SEEK_SET) < 0)
		return (mdsyserror(ep, errno, NULL));

	if (read(fd, bp, bsize) != bsize)
		return (mdsyserror(ep, errno, NULL));

	return ((lbp->lb_magic == MDDB_MAGIC_LB) ? 1 : 0);
}

int
phys_read(
	md_error_t	*ep,
	int		fd,
	mddb_mb_t	*mbp,
	daddr_t		blk,
	void		*bp,
	int		bcount
)
{
	daddr_t		pblk;

	if ((pblk = getphysblk(blk, mbp)) < 0)
		return (mdmddberror(ep, MDE_DB_BLKRANGE, NODEV32,
			MD_LOCAL_SET, blk, NULL));

	if (lseek(fd, (off_t)dbtob(pblk), SEEK_SET) < 0)
		return (mdsyserror(ep, errno, NULL));

	if (read(fd, bp, bcount) != bcount)
		return (mdsyserror(ep, errno, NULL));

	return (bcount);
}

/*
 * read_locator_block_did()
 *
 * Returns:
 * 	< 0 for failure
 *	  0 for no valid locator name struct
 *	  1 for valid locator name struct
 */
int
read_locator_block_did(
	md_error_t	*ep,
	int		fd,
	mddb_mb_t	*mbp,
	mddb_lb_t	*lbp,
	void		*bp,
	int		bsize
)
{
	int		lb_didfirstblk = lbp->lb_didfirstblk;
	mddb_did_blk_t	*lbdidp = bp;
	int		rval;

	assert(bp != NULL);

	if ((rval = phys_read(ep, fd, mbp, lb_didfirstblk, bp, bsize)) < 0)
		return (rval);

	return ((lbdidp->blk_magic == MDDB_MAGIC_DI) ? 1 : 0);
}

/*
 * read_locator_names()
 *
 * Returns:
 *	< 0 for failure
 *	  0 for no valid locator name struct
 *	  1 for valid locator name struct
 */
int
read_locator_names(
	md_error_t	*ep,
	int		fd,
	mddb_mb_t	*mbp,
	mddb_lb_t	*lbp,
	void		*bp,
	int		bsize
)
{
	int		lnfirstblk = lbp->lb_lnfirstblk;
	mddb_ln_t	*lnp = bp;
	int		rval;

	assert(bp != NULL);

	if ((rval = phys_read(ep, fd, mbp, lnfirstblk, bp, bsize)) < 0)
		return (rval);

	return ((lnp->ln_magic == MDDB_MAGIC_LN) ? 1 : 0);
}


int
read_database_block(
	md_error_t	*ep,
	int		fd,
	mddb_mb_t	*mbp,
	int		dbblk,
	void		*bp,
	int		bsize
)
{
	mddb_db_t	*dbp = bp;
	int		rval;

	assert(bp != NULL);

	if ((rval = phys_read(ep, fd, mbp, dbblk, bp, bsize)) < 0)
		return (rval);

	return ((dbp->db_magic == MDDB_MAGIC_DB) ? 1 : 0);
}

int
read_loc_didblks(
	md_error_t	*ep,
	int		fd,
	mddb_mb_t	*mbp,
	int		didblk,
	void		*bp,
	int		bsize
)
{
	mddb_did_blk_t	*didbp = bp;
	int		rval;

	assert(bp != NULL);

	if ((rval = phys_read(ep, fd, mbp, didblk, bp, bsize)) < 0)
		return (rval);

	return ((didbp->blk_magic == MDDB_MAGIC_DI) ? 1 : 0);
}


int
read_loc_didinfo(
	md_error_t	*ep,
	int		fd,
	mddb_mb_t	*mbp,
	int		infoblk,
	void		*bp,
	int		bsize
)
{
	int		rval = 1;
	mddb_did_info_t	*infop = bp;

	assert(bp != NULL);

	if ((rval = phys_read(ep, fd, mbp, infoblk, bp, bsize)) < 0)
		return (rval);

	return ((infop->info_flags & MDDB_DID_EXISTS) ? 1 : 0);
}

/*
 * meta_nm_rec()
 *
 * Return the DE corresponding to the requested namespace record type.
 * Modifies dbp to have a firstentry if one isn't there.
 */
static mddb_de_t *
meta_nm_rec(mddb_db_t *dbp, mddb_type_t rectype)
{
	mddb_de_t *dep;
	int	desize;

	if (dbp->db_firstentry != NULL) {
		/* LINTED */
		dep = (mddb_de_t *)((caddr_t)(&dbp->db_firstentry)
				    + sizeof (dbp->db_firstentry));
		dbp->db_firstentry = dep;
		while (dep && dep->de_next) {
			desize = sizeof (*dep) - sizeof (dep->de_blks) +
				sizeof (daddr_t) * dep->de_blkcount;
			/* LINTED */
			dep->de_next = (mddb_de_t *)
				((caddr_t)dep + desize);
			dep = dep->de_next;
		}
	}

	for (dep = dbp->db_firstentry; dep != NULL; dep = dep->de_next) {
		if (dep->de_type1 == rectype)
			break;
	}
	return (dep);
}

/*
 * read_nm_rec()
 *
 * Reads the NM, NM_DID or NM_DID_SHR record in the mddb and stores the
 * configuration data in the buffer 'nm'
 *
 * Returns:
 *	< 0 for failure
 *	  0 for no valid NM/DID_NM/DID_NM_SHR record
 *	  1 for valid NM/DID_NM/DID_NM_SHR record
 *
 */
static int
read_nm_rec(
	md_error_t 	*ep,
	int 		fd,
	mddb_mb_t	*mbp,
	mddb_lb_t	*lbp,
	char		**nm,
	mddb_type_t	rectype,
	char		*diskname
)
{
	int		cnt, dbblk, rval = 0;
	char		db[DEV_BSIZE];
	mddb_de_t	*dep;
	/*LINTED*/
	mddb_db_t	*dbp = (mddb_db_t *)&db;
	char 		*tmpnm = NULL;
	daddr_t		pblk;

	for (dbblk = lbp->lb_dbfirstblk;
	    dbblk != 0;
	    dbblk = dbp->db_nextblk) {

		if ((rval = read_database_block(ep, fd, mbp, dbblk, dbp,
		    sizeof (db))) <= 0)
			return (rval);

		/*
		 * Locate NM/DID_NM/DID_NM_SHR record. Normally there is
		 * only one record per mddb. There is a rare case when we
		 * can't expand the record. If this is the case then we
		 * will have multiple NM/DID_NM/DID_NM_SHR records linked
		 * with r_next_recid.
		 *
		 * For now assume the normal case and handle the extended
		 * namespace in Phase 2.
		 */
		if ((dep = meta_nm_rec(dbp, rectype)) != NULL)
			break;
	}

	/* If meta_nm_rec() never succeeded, bail out */
	if (dep == NULL)
		return (0);

	/* Read in the appropriate record and return configurations */
	tmpnm = (char *)Zalloc(dbtob(dep->de_blkcount));
	*nm = tmpnm;

	for (cnt = 0; cnt < dep->de_blkcount; cnt++) {
		if ((pblk = getphysblk(dep->de_blks[cnt], mbp)) < 0) {
			rval = mdmddberror(ep, MDE_DB_BLKRANGE,
			    NODEV32, MD_LOCAL_SET,
			    dep->de_blks[cnt], diskname);
			return (rval);
		}

		if (lseek(fd, (off_t)dbtob(pblk), SEEK_SET) < 0) {
			rval = mdsyserror(ep, errno, diskname);
			return (rval);
		}

		if (read(fd, tmpnm, DEV_BSIZE) != DEV_BSIZE) {
			rval = mdsyserror(ep, errno, diskname);
			return (rval);
		}

		tmpnm += DEV_BSIZE;
	}
	return (1);
}

/*
 * is_replicated
 *
 * Determines whether a disk has been replicated or not. It checks to see
 * if the device id stored in the master block is the same as the device id
 * registered for that disk on the current system. If the two device ids are
 * different, then we know that the disk has been replicated.
 *
 * If need_devid is set and the disk is replicated, fill in the new_devid.
 * Also, if need_devid is set, this routine allocates memory for the device
 * ids; the caller of this routine is responsible for free'ing up the memory.
 *
 * Returns:
 * 	MD_IM_SET_REPLICATED	if it's a replicated disk
 * 	0 			if it's not a replicated disk
 */
static int
is_replicated(
	int fd,
	mddb_mb_t *mbp,
	int need_devid,
	void **new_devid
)
{
	ddi_devid_t	current_devid;
	int		retval = 0;
	size_t		new_devid_len;

	if (mbp->mb_devid_magic != MDDB_MAGIC_DE)
		return (retval);

	if (devid_get(fd, &current_devid) != 0)
		return (retval);

	if (devid_compare((ddi_devid_t)mbp->mb_devid, current_devid) != 0)
		retval = MD_IM_SET_REPLICATED;

	if (retval && need_devid) {
		new_devid_len = devid_sizeof(current_devid);
		*new_devid = Zalloc(new_devid_len);
		(void) memcpy(*new_devid, (void *)current_devid, new_devid_len);
	}

	devid_free(current_devid);
	return (retval);
}

/*
 * free_replicated_disks_list()
 *
 * this frees up all the memory allocated by build_replicated_disks_list
 */
static void
free_replicated_disks_list()
{
	replicated_disk_t 	**repl_disk, *temp;
	int 			index;

	for (index = 0; index <= MAX_DEVID_LEN; index++) {
		repl_disk = &replicated_disk_list[index];

		while (*repl_disk != NULL) {
			temp = *repl_disk;
			*repl_disk = (*repl_disk)->next;

			Free(temp->old_devid);
			Free(temp->new_devid);
			Free(temp);
		}
	}
}

/*
 * build_replicated_disks_list()
 *
 * Builds a list of disks that have been replicated using either a
 * remote replication or a point-in-time replication software. The
 * list is stored as a two dimensional sparse array.
 *
 * Returns
 * 	1	on success
 * 	0 	on failure
 */
int
build_replicated_disks_list(
	md_error_t *ep,
	mddrivenamelist_t *dnlp
)
{
	uint_t			sliceno;
	int			fd = -1;
	mddrivenamelist_t	*dp;
	mdname_t		*rsp;
	mddb_mb_t		*mbp;

	mbp = Malloc(DEV_BSIZE);

	for (dp = dnlp; dp != NULL; dp = dp->next) {
		mddrivename_t *dnp;
		void *new_devid;

		dnp = dp->drivenamep;
		/* determine the replica slice */
		if (meta_replicaslice(dnp, &sliceno, ep) != 0)
			continue;

		/*
		 * if the replica slice size is zero, don't bother opening
		 */
		if (dnp->vtoc.parts[sliceno].size == 0)
			continue;

		if ((rsp = metaslicename(dnp, sliceno, ep)) == NULL)
			continue;

		if ((fd = open(rsp->rname, O_RDONLY| O_NDELAY)) < 0)
			return (mdsyserror(ep, errno, rsp->rname));

		/* a drive may not have a master block so we just continue */
		if (read_master_block(ep, fd, mbp, DEV_BSIZE) <= 0) {
			(void) close(fd);
			mdclrerror(ep);
			continue;
		}

		if (is_replicated(fd, mbp, 1, &new_devid)) {
			replicated_list_insert(mbp->mb_devid_len,
			    mbp->mb_devid, new_devid);
		}
		(void) close(fd);
	}
	*replicated_disk_list_built = 1;

	Free(mbp);
	return (1);
}

/*
 * free_did_list()
 *
 * Frees the did_list allocated as part of build_did_list
 */
static void
free_did_list(
	did_list_t	*did_listp
)
{
	did_list_t	*temp, *head;

	head = did_listp;

	while (head != NULL) {
		temp = head;
		head = head->next;
		if (temp->rdid)
			Free(temp->rdid);
		if (temp->did)
			Free(temp->did);
		if (temp->devname)
			Free(temp->devname);
		if (temp->minor_name)
			Free(temp->minor_name);
		if (temp->driver_name)
			Free(temp->driver_name);
		Free(temp);
	}
}

/*
 * meta_free_im_replica_info
 *
 * Frees the md_im_replica_info list
 */
static void
meta_free_im_replica_info(
	md_im_replica_info_t	*mirp
)
{
	md_im_replica_info_t	*r, *temp;

	r = mirp;

	while (r != NULL) {
		temp = r;
		r = r->mir_next;

		Free(temp);
	}
}

/*
 * meta_free_im_drive_info
 *
 * Frees the md_im_drive_info list
 */
static void
meta_free_im_drive_info(
	md_im_drive_info_t	*midp
)
{
	md_im_drive_info_t	*d, *temp;

	d = midp;

	while (d != NULL) {
		temp = d;
		d = d->mid_next;

		if (temp->mid_available & MD_IM_DISK_NOT_AVAILABLE)
			/*
			 * dnp is not on the drivenamelist and is a temp
			 * dnp for metaimport if the disk is unavailable.
			 * We need to specifically free it because of this.
			 * If the disk is available, standard drivelist freeing
			 * will kick in so we don't need to do it.
			 */
			metafreedrivename(temp->mid_dnp);
		if (temp->mid_devid)
			Free(temp->mid_devid);
		if (temp->mid_o_devid)
			Free(temp->mid_o_devid);
		if (temp->mid_driver_name)
			Free(temp->mid_driver_name);
		if (temp->mid_devname)
			Free(temp->mid_devname);
		if (temp->mid_replicas) {
			meta_free_im_replica_info(temp->mid_replicas);
			temp->mid_replicas = NULL;
		}
		if (temp->overlap) {
			meta_free_im_drive_info(temp->overlap);
			temp->overlap = NULL;
		}
		Free(temp);
	}
}

/*
 * meta_free_im_set_desc
 *
 * Frees the md_im_set_desc_t list
 */
void
meta_free_im_set_desc(
	md_im_set_desc_t	*misp
)
{
	md_im_set_desc_t	*s, *temp;

	s = misp;

	while (s != NULL) {
		temp = s;
		s = s->mis_next;
		if (temp->mis_drives) {
			meta_free_im_drive_info(temp->mis_drives);
			temp->mis_drives = NULL;
		}
		Free(temp);
	}
}

/*
 * build_did_list()
 *
 * Build a list of device ids corresponding to disks in the locator block.
 * Memory is allocated here for the nodes in the did_list. The callers of
 * this routine must also call free_did_list to free up the memory after
 * they're done.
 *
 * Returns:
 *	< 0 		for failure
 *	  0 		for no valid locator block device id array
 *	  1 		for valid locator block device id array
 *	  ENOTSUP	partial diskset, not all disks in a diskset on the
 *			system where import is being executed
 */
static int
build_did_list(
	md_error_t	*ep,
	int		fd,
	mddb_mb_t	*mb,
	mddb_lb_t	*lbp,
	mddb_did_blk_t	*lbdidp,
	mddb_ln_t	*lnp,
	did_list_t	**did_listp,
	int		replicated
)
{
	char 		*search_path = "/dev";
	char		*minor_name;
	int		rval, cnt;
	devid_nmlist_t	*nm;
	uint_t		did_info_length = 0;
	uint_t		did_info_firstblk = 0;
	did_list_t	*new, *head = NULL;
	char		*bp = NULL, *temp;
	mddb_did_info_t	*did_info = NULL;
	void		*did = NULL;
	size_t		new_devid_len;
	int		partial = 0;
	int		partial_replicated = 0;

	for (cnt = 0; cnt < MDDB_NLB; cnt++) {
		partial_replicated = 0;
		did_info = &lbdidp->blk_info[cnt];

		if (!(did_info->info_flags & MDDB_DID_EXISTS))
			continue;

		new = Zalloc(sizeof (did_list_t));
		new->did = Zalloc(did_info->info_length);

		/*
		 * If we can re-use the buffer that has already been
		 * read in then just use it.  Otherwise free
		 * the previous one and alloc a new one
		 */
		if (did_info->info_firstblk != did_info_firstblk) {

			did_info_length = dbtob(did_info->info_blkcnt);
			did_info_firstblk = did_info->info_firstblk;

			if (bp)
				Free(bp);
			bp = temp = Zalloc(did_info_length);

			if ((rval = phys_read(ep, fd, mb, did_info_firstblk,
			    (void *)bp, did_info_length)) < 0)
				return (rval);
		} else {
			temp = bp;
		}

		temp += did_info->info_offset;
		(void) memcpy(new->did, temp, did_info->info_length);
		new->did_index = cnt;
		minor_name = did_info->info_minor_name;

		/*
		 * If we are not able to find the ctd mapping corresponding
		 * to a given device id, it probably means the device id in
		 * question is not registered with the system.
		 *
		 * Highly likely that the only time this happens, we've hit
		 * a case where not all the disks that are a part of the
		 * diskset were moved before importing the diskset.
		 *
		 * If set is a replicated diskset, then the device id we get
		 * from 'lb' will be the 'other' did and we need to lookup
		 * the real one before we call this routine.
		 */
		if (replicated) {
		    temp = replicated_list_lookup(did_info->info_length,
			new->did);
		    if (temp == NULL) {
			/* we have a partial replicated set, fake it */
			new_devid_len = devid_sizeof((ddi_devid_t)new->did);
			new->rdid = Zalloc(new_devid_len);
			(void) memcpy(new->rdid, new->did, new_devid_len);
			did = new->rdid;
			partial_replicated = 1;
		    } else {
			new_devid_len = devid_sizeof((ddi_devid_t)temp);
			new->rdid = Zalloc(new_devid_len);
			(void) memcpy(new->rdid, temp, new_devid_len);
			did = new->rdid;
		    }
		} else {
		    did = new->did;
		}

		if (devid_valid((ddi_devid_t)(did)) == 0) {
			return (-1);
		}

		if (partial_replicated || meta_deviceid_to_nmlist(search_path,
		    (ddi_devid_t)did, minor_name, &nm) != 0) {
			int	len = 0;

			/*
			 * Partial diskset case. We'll need to get the
			 * device information from the metadb instead
			 * of the output (nm) of meta_deviceid_to_nmlist.
			 */
			len = strlen(lnp->ln_prefixes[0].pre_data) +
			    strlen(lnp->ln_suffixes[0][cnt].suf_data) + 2;
			new->devname = Zalloc(len);
			(void) strlcpy(new->devname,
			    lnp->ln_prefixes[0].pre_data,
			    strlen(lnp->ln_prefixes[0].pre_data) + 1);
			(void) strlcat(new->devname, "/", len);
			(void) strlcat(new->devname,
			    lnp->ln_suffixes[0][cnt].suf_data, len);
			new->minor_name = Strdup(minor_name);
			new->next = head;
			new->available = MD_IM_DISK_NOT_AVAILABLE;
			new->driver_name = Strdup(lbp->lb_drvnm[0].dn_data);
			new->dev = lbp->lb_locators[cnt].l_dev;
			head = new;
			partial = ENOTSUP;
			continue;
		}

		/*
		 * Disk is there. Grab device information from nm structure.
		 */
		assert(nm->devname != NULL);
		new->devname = Strdup(nm->devname);
		new->dev = nm->dev;
		new->minor_name = Strdup(minor_name);
		new->available = MD_IM_DISK_AVAILABLE;

		devid_free_nmlist(nm);

		new->next = head;
		head = new;
	}

	/* Free the last bp */
	if (bp)
		Free(bp);
	*did_listp = head;
	if (partial)
		return (partial);
	return (1);
}
/*
 * check_nm_disks
 *	Checks the disks listed in the shared did namespace to see if they
 *	are accessable on the system. If not, return ENOTSUP error to
 *	indicate we have a partial diskset.
 * Returns:
 *	< 0 		for failure
 *	  0		success
 *	  ENOTSUP	partial diskset, not all disks in a diskset on the
 *			system where import is being executed
 */
static int
check_nm_disks(
	struct devid_min_rec	*did_nmp,
	struct devid_shr_rec	*did_shrnmp
)
{
	char 		*search_path = "/dev";
	char		*minor_name = NULL;
	uint_t		used_size, min_used_size;
	ddi_devid_t	did;
	devid_nmlist_t	*nm;
	void		*did_min_namep;
	void		*did_shr_namep;
	size_t		did_nsize, did_shr_nsize;

	used_size = did_shrnmp->did_rec_hdr.r_used_size -
	    sizeof (struct nm_rec_hdr);
	min_used_size = did_nmp->min_rec_hdr.r_used_size -
	    sizeof (struct nm_rec_hdr);
	did_shr_namep = (void *)(&did_shrnmp->device_id[0]);
	while (used_size > (int)sizeof (struct did_shr_name)) {
		did_min_namep = (void *)(&did_nmp->minor_name[0]);
		/* grab device id and minor name from the shared spaces */
		did = (ddi_devid_t)(((struct did_shr_name *)
		    did_shr_namep)->did_devid);
		if (devid_valid(did) == 0) {
			return (-1);
		}

		/*
		 * We need to check that the DID_NM and DID_SHR_NM are in
		 * sync. It is possible that we took a panic between writing
		 * the two areas to disk. This would be cleaned up on the
		 * next snarf but we don't know for sure that snarf has even
		 * happened since we're reading from disk.
		 */
		while (((struct did_shr_name *)did_shr_namep)->did_key !=
		    ((struct did_min_name *)did_min_namep)->min_devid_key) {
			did_nsize = DID_NAMSIZ((struct did_min_name *)
			    did_min_namep);
			did_min_namep = ((void *)((char *)did_min_namep +
			    did_nsize));
			min_used_size -= did_nsize;
			if (min_used_size < (int)sizeof (struct did_min_name))
				continue;
		}
		minor_name = ((struct did_min_name *)did_min_namep)->min_name;

		/*
		 * Try to find disk in the system. If we can't find the
		 * disk, we have a partial diskset.
		 */
		if ((meta_deviceid_to_nmlist(search_path,
		    did, minor_name, &nm)) != 0) {
			/* Partial diskset detected */
			return (ENOTSUP);
		}
		devid_free_nmlist(nm);
		used_size -= DID_SHR_NAMSIZ((struct did_shr_name *)
		    did_shr_namep);
		/* increment to next item in the shared spaces */
		did_shr_nsize = DID_SHR_NAMSIZ((struct did_shr_name *)
		    did_shr_namep);
		did_shr_namep = ((void *)((char *)did_shr_namep +
		    did_shr_nsize));
	}
	return (0);
}


/*
 * report_metadb_info()
 *
 * Generates metadb output for the diskset.
 *
 */
static void
report_metadb_info(
	md_im_set_desc_t	*misp,
	char			*indent
)
{
	md_im_drive_info_t	*d;
	md_im_replica_info_t	*r;
	char			*unk_str = "";
	int			i;

	(void) printf("%s\t%5.5s\t\t%9.9s\t%11.11s\n", indent, gettext("flags"),
	    gettext("first blk"), gettext("block count"));

	unk_str = gettext("unknown");

	/*
	 * Looping through all drives in the diskset to print
	 * out information about the drive and if the verbose
	 * option is set print out replica data.
	 */
	for (d = misp->mis_drives; d != NULL; d = d->mid_next) {

		if (d->mid_replicas != NULL) {
			for (r = d->mid_replicas; r != NULL;
			    r = r->mir_next) {
				(void) printf("%s", indent);
				for (i = 0; i < MDDB_FLAGS_LEN; i++) {
					if (r->mir_flags & (1 << i)) {
						(void) putchar(
						    MDDB_FLAGS_STRING[i]);
					} else {
						(void) putchar(' ');
					}
				}
				if ((r->mir_offset == -1) && (r->mir_length
				    == -1)) {
					(void) printf("%7.7s\t\t%7.7s\t",
					    unk_str, unk_str);
				} else if (r->mir_length == -1) {
					(void) printf("%i\t\t%7.7s\t",
					    r->mir_offset, unk_str);
				} else {
					(void) printf("%i\t\t%i\t",
					    r->mir_offset, r->mir_length);
				}
				(void) printf("\t%s\n",
				    d->mid_devname);
			}
		}
	}
	(void) printf("\n");
}

/*
 * meta_replica_quorum will determine if the disks in the set to be
 * imported have enough valid replicas to have quorum.
 *
 * RETURN:
 *	-1	Set doesn't have quorum
 *	0	Set does have quorum
 */
int
meta_replica_quorum(
	md_im_set_desc_t *misp
)
{
	md_im_drive_info_t	*midp;
	md_im_replica_info_t    *midr;
	int			replica_count = 0;

	for (midp = misp->mis_drives; midp != NULL;
		midp = midp->mid_next) {

		if (midp->mid_available == MD_IM_DISK_NOT_AVAILABLE)
			continue;

		/*
		 * The drive is okay. Now count its replicas
		 */
		for (midr = midp->mid_replicas; midr != NULL;
			midr = midr->mir_next) {
			replica_count++;
		}
	}

	if (misp->mis_active_replicas & 1) {
		/* odd number of replicas */
		if (replica_count < (misp->mis_active_replicas + 1)/2)
			return (-1);
	} else {
		/* even number of replicas */
		if (replica_count <= ((misp->mis_active_replicas + 1)/2))
			return (-1);
	}

	return (0);
}


/*
 * Choose the best drive to use for the metaimport command.
 */
md_im_drive_info_t *
pick_good_disk(md_im_set_desc_t *misp)
{
	md_timeval32_t		*setcrtime; /* set creation time */
	md_im_drive_info_t	*good_disk = NULL;
	md_im_drive_info_t	*midp = NULL;
	md_im_replica_info_t	*mirp;

	setcrtime = &(misp->mis_drives->mid_replicas->mir_timestamp);
	for (midp = misp->mis_drives; (midp != NULL) && (good_disk == NULL);
	    midp = midp->mid_next) {
		/* drive must be available */
		if (midp->mid_available == MD_IM_DISK_NOT_AVAILABLE) {
			continue;
		}
		for (mirp = midp->mid_replicas; mirp != NULL;
		    mirp = mirp->mir_next) {
			/* replica must be active to be a good one */
			if (mirp->mir_flags & MDDB_F_ACTIVE) {
				if ((setcrtime->tv_sec ==
				    midp-> mid_setcreatetimestamp.tv_sec) &&
				    (setcrtime->tv_usec ==
				    midp->mid_setcreatetimestamp.tv_usec)) {
					good_disk = midp;
					break;
				}
			}
		}
	}
	return (good_disk);
}

/*
 * report_set_info()
 *
 * Returns:
 *	< 0 for failure
 *	  0 for success
 *
 */
static int
report_set_info(
	md_im_set_desc_t	*misp,
	mddb_mb_t		*mb,
	mddb_lb_t		*lbp,
	mddb_rb_t		*nm,
	pnm_rec_t		**pnm,
	mdname_t		*rsp,
	int			fd,
	uint_t			imp_flags,
	int			set_count,
	int			overlap,
	md_im_drive_info_t	*overlap_disks,
	md_error_t		*ep
)
{
	int 			rval = 0;
	md_im_drive_info_t	*d;
	md_im_drive_info_t	*good_disk = NULL;
	int			i;
	int			in = META_INDENT;
	char			indent[MAXPATHLEN];
	md_timeval32_t		lastaccess; /* stores last modified timestamp */
	int			has_overlap = 0;
	int			no_quorum = 0;
	int			partial = 0;

	/* Calculates the correct indentation. */
	indent[0] = 0;
	for (i = 0; i < in; i++)
		(void) strlcat(indent, " ", sizeof (indent));

	/*
	 * This will print before the information for the first diskset
	 * if the verbose option was set.
	 */
	if (set_count == 1) {
		if (imp_flags & META_IMP_REPORT) {
			(void) printf("\n%s:\n\n",
			    gettext("Disksets eligible for import"));
		}
	}

	partial = misp->mis_partial;
	good_disk = pick_good_disk(misp);
	if (good_disk == NULL) {
		return (rval);
	}

	/*
	 * Make the distinction between a regular diskset and
	 * a replicated diskset.  Also make the distinction
	 * between a partial vs. full diskset.
	 */
	if (partial == MD_IM_PARTIAL_DISKSET) {
		if (misp->mis_flags & MD_IM_SET_REPLICATED) {
			if (imp_flags & META_IMP_REPORT) {
				(void) printf("%i)  %s:\n", set_count, gettext(
				    "Found partial replicated diskset "
				    "containing disks"));
			} else {
				(void) printf("\n%s:\n", gettext(
				    "Importing partial replicated diskset "
				    "containing disks"));
			}
		} else {
			if (imp_flags & META_IMP_REPORT) {
				(void) printf("%i)  %s:\n", set_count, gettext(
				    "Found partial regular diskset containing "
				    "disks"));
			} else {
				(void) printf("\n%s:\n", gettext(
				    "Importing partial regular diskset "
				    "containing disks"));
			}
		}
	} else {
		if (misp->mis_flags & MD_IM_SET_REPLICATED) {
			if (imp_flags & META_IMP_REPORT) {
				(void) printf("%i)  %s:\n", set_count, gettext(
				    "Found replicated diskset containing "
				    "disks"));
			} else {
				(void) printf("\n%s:\n", gettext(
				    "Importing replicated diskset containing "
				    "disks"));
			}
		} else {
			if (imp_flags & META_IMP_REPORT) {
				(void) printf("%i)  %s:\n", set_count, gettext(
				    "Found regular diskset containing disks"));
			} else {
				(void) printf("\n%s:\n", gettext(
				    "Importing regular diskset containing "
				    "disks"));
			}
		}
	}

	/*
	 * Check each drive in the set. If it's unavailable or
	 * an overlap tell the user.
	 */
	for (d = misp->mis_drives; d != NULL; d = d->mid_next) {
		(void) fprintf(stdout, "  %s", d->mid_dnp->cname);
		if (d->mid_available == MD_IM_DISK_NOT_AVAILABLE) {
			(void) fprintf(stdout, " (UNAVAIL)");
		}
		if (overlap) {
			md_im_drive_info_t	**chain;
			/*
			 * There is the potential for an overlap, see if
			 * this disk is one of the overlapped disks.
			 */
			for (chain = &overlap_disks; *chain != NULL;
			    chain = &(*chain)->overlap) {
				if (strcmp(d->mid_dnp->cname,
				    (*chain)->mid_dnp->cname) == 0) {
					(void) fprintf(stdout, " (CONFLICT)");
					has_overlap = 1;
					break;
				}
			}
		}
		(void) fprintf(stdout, "\n");
	}

	/*
	 * This note explains the (UNAVAIL) that appears next to the
	 * disks in the diskset that are not available.
	 */
	if (partial) {
		(void) printf("%s%s\n%s%s\n\n", indent,
		    gettext("(UNAVAIL) WARNING: This disk is unavailable on"
		    " this system."), indent, gettext("Import may corrupt "
		    "data in the diskset."));
	}

	/*
	 * This note explains the (CONFLICT) that appears next to the
	 * disks whose lb_inittime timestamp does not
	 * match the rest of the diskset.
	 */
	if (has_overlap) {
		(void) printf("%s%s\n%s%s\n\n", indent,
		    gettext("(CONFLICT) WARNING: This disk has been reused in "
		    "another diskset or system configuration."), indent,
		    gettext("Import may corrupt data in the diskset."));
	}

	/*
	 * If the verbose flag was given on the command line,
	 * we will print out the metastat -c information , the
	 * creation time, and last modified time for the diskset.
	 */
	if (imp_flags & META_IMP_VERBOSE) {
		(void) printf("%s%s\n", indent,
		    gettext("Metadatabase information:"));
		report_metadb_info(misp, indent);

		/*
		 * Printing creation time and last modified time.
		 * Last modified: uses the global variable "lastaccess",
		 * which is set to the last updated timestamp from all of
		 * the database blocks(db_timestamp) or record blocks
		 * (rb_timestamp).
		 * Creation time is the locator block init time
		 * (lb_inittime).
		 */
		lastaccess = good_disk->mid_replicas->mir_timestamp;

		(void) printf("%s%s\n", indent,
		    gettext("Metadevice information:"));
		rval = report_metastat_info(mb, lbp, nm, pnm, rsp, fd,
		    &lastaccess, ep);
		if (rval < 0) {
			return (rval);
		}

		(void) printf("%s%s:\t%s\n", indent,
		    gettext("Creation time"),
		    meta_print_time(&good_disk->mid_replicas->mir_timestamp));
		(void) printf("%s%s:\t%s\n", indent,
		    gettext("Last modified time"),
		    meta_print_time(&lastaccess));
	} else {
		/*
		 * Even if the verbose option is not set, we will print the
		 * creation time for the diskset.
		 */
		(void) printf("%s%s:\t%s\n", indent, gettext("Creation time"),
		    meta_print_time(&good_disk->mid_replicas->mir_timestamp));
	}


	/*
	 * If the diskset is not actually being imported, then we
	 * print out extra information about how to import it.
	 * If the verbose flag was not set, then we will also
	 * print out information about how to obtain verbose output.
	 */
	if (imp_flags & META_IMP_REPORT) {
		/*
		 * TRANSLATION_NOTE
		 *
		 * The translation of the phrase "For more information
		 * about this set" will be followed by a ":" and a
		 * suggested command (untranslatable) that the user
		 * may use to request additional information.
		 */
		if (!(imp_flags & META_IMP_VERBOSE)) {
		(void) printf("%s%s:\n%s  %s -r -v %s\n", indent,
		    gettext("For more information about this diskset"),
		    indent, myname, good_disk->mid_dnp->cname);
		}

		if (meta_replica_quorum(misp) != 0)
			no_quorum = 1;

		/*
		 * TRANSLATION_NOTE
		 *
		 * The translation of the phrase "To import this set"
		 * will be followed by a ":" and a suggested command
		 * (untranslatable) that the user may use to import
		 * the specified diskset.
		 */
		if (partial || has_overlap || no_quorum) {
			(void) printf("%s%s:\n%s  %s -f -s <newsetname> %s\n",
			    indent, gettext("To import this diskset"), indent,
			    myname, good_disk->mid_dnp->cname);
		} else {
			(void) printf("%s%s:\n%s  %s -s <newsetname> %s\n",
			    indent, gettext("To import this diskset"), indent,
			    myname, good_disk->mid_dnp->cname);
		}
	}
	(void) printf("\n\n");

	return (rval);
}


/*
 * meta_get_and_report_set_info
 *
 * Scans a given drive for set specific information. If the given drive
 * has a shared metadb, scans the shared metadb for information pertaining
 * to the set.
 * If imp_flags has META_IMP_PASS1 set don't report.
 *
 * Returns:
 * 	<0 	for failure
 *	0	success but no replicas were found
 *	1	success and a replica was found
 */
int
meta_get_and_report_set_info(
	mddrivenamelist_t	*dp,
	md_im_set_desc_t	**mispp,
	int			local_mb_ok,
	uint_t			imp_flags,
	int			*set_count,
	int			overlap,
	md_im_drive_info_t	*overlap_disks,
	md_error_t 		*ep
)
{
	uint_t			s;
	mdname_t		*rsp;
	int			fd;
	char			mb[DEV_BSIZE];
				/*LINTED*/
	mddb_mb_t		*mbp = (mddb_mb_t *)mb;
	char			lb[dbtob(MDDB_LBCNT)];
				/*LINTED*/
	mddb_lb_t		*lbp = (mddb_lb_t *)lb;
	mddb_did_blk_t		*lbdidp = NULL;
	mddb_ln_t		*lnp = NULL;
	int			lnsize, lbdid_size;
	int			rval = 0;
	char			db[DEV_BSIZE];
				/*LINTED*/
	mddb_db_t		*dbp = (mddb_db_t *)db;
	did_list_t		*did_listp = NULL;
	mddrivenamelist_t	*dnlp;
	mddrivename_t 		*dnp;
	md_im_names_t		cnames = { 0, NULL};
	char			*nm = NULL, *shrnm = NULL;
	char			*did_nm = NULL, *did_shrnm = NULL;
	struct nm_rec		*nmp;
	struct nm_shr_rec	*snmp;
	struct devid_shr_rec	*did_shrnmp;
	struct devid_min_rec	*did_nmp;
	int			extended_namespace = 0;
	int			replicated = 0;
	int			partial = 0;
	pnm_rec_t		*pnm = NULL; /* list of physical devs in set */
	md_im_set_desc_t	*misp;

	dnp = dp->drivenamep;

	/*
	 * Determine and open the replica slice
	 */
	if (meta_replicaslice(dnp, &s, ep) != 0) {
		return (-1);
	}

	/*
	 * Test for the size of replica slice in question. If
	 * the size is zero, we know that this is not a disk that was
	 * part of a set and it should be silently ignored for import.
	 */
	if (dnp->vtoc.parts[s].size == 0)
		return (0);

	if ((rsp = metaslicename(dnp, s, ep)) == NULL) {
		return (-1);
	}

	if ((fd = open(rsp->rname, O_RDONLY|O_NDELAY)) < 0)
		return (mdsyserror(ep, errno, rsp->cname));

	/*
	 * After the open() succeeds, we should return via the "out"
	 * label to clean up after ourselves.  (Up 'til now, we can
	 * just return directly, because there are no resources to
	 * give back.)
	 */

	if ((rval = read_master_block(ep, fd, mbp, sizeof (mb))) <= 0)
		goto out;

	replicated = is_replicated(fd, mbp, 0, NULL);

	if (!local_mb_ok && mbp->mb_setno == 0) {
		rval = 0;
		goto out;
	}

	if ((rval = read_locator_block(ep, fd, mbp, lbp, sizeof (lb))) <= 0)
		goto out;

	/*
	 * Once the locator block has been read, we need to
	 * check if the locator block commit count is zero.
	 * If it is zero, we know that the replica we're dealing
	 * with is on a disk that was deleted from the disk set;
	 * and, it potentially has stale data. We need to quit
	 * in that case
	 */
	if (lbp->lb_commitcnt == 0) {
		rval = 0;
		goto out;
	}

	/*
	 * Make sure that the disk being imported has device id
	 * namespace present for disksets. If a disk doesn't have
	 * device id namespace, we skip reading the replica on that disk
	 */
	if (!(lbp->lb_flags & MDDB_DEVID_STYLE)) {
		rval = 0;
		goto out;
	}

	/*
	 * Grab the locator block device id array. Allocate memory for the
	 * array first.
	 */
	lbdid_size = dbtob(lbp->lb_didblkcnt);
	lbdidp = Zalloc(lbdid_size);

	if ((rval = read_locator_block_did(ep, fd, mbp, lbp, lbdidp,
	    lbdid_size)) <= 0)
		goto out;

	/*
	 * For a disk that has not been replicated, extract the device ids
	 * stored in the locator block device id array and store them in
	 * a list.
	 *
	 * If the disk has been replicated using replication software such
	 * as HDS Truecopy/ShadowImage or EMC SRDF/BCV, the device ids in
	 * the locator block are invalid and we need to build a list of
	 * replicated disks.
	 */
	if (imp_flags & META_IMP_PASS1) {
		/*
		 * We need to do this for both passes but
		 * replicated_disk_list_built is global so we need some way
		 * to determine which pass we're on. Set it to the appropriate
		 * pass's flag.
		 */
		replicated_disk_list_built = &replicated_disk_list_built_pass1;
	} else {
		replicated_disk_list_built = &replicated_disk_list_built_pass2;
	}
	if (replicated && !(*replicated_disk_list_built)) {
		/*
		 * if there's a replicated diskset involved, we need to
		 * scan the system one more time and build a list of all
		 * candidate disks that might be part of that replicated set
		 */
		if (meta_list_disks(ep, &cnames) != 0) {
			rval = 0;
			goto out;
		}
		dnlp = meta_prune_cnames(ep, &cnames, 0);
		rval = build_replicated_disks_list(ep, dnlp);
		if (rval == 0)
			goto out;
	}

	/*
	 * Until here, we've gotten away with fixed sizes for the
	 * master block and locator block.  The locator names,
	 * however, are sized (and therefore allocated) dynamically
	 * according to information in the locator block.
	 */
	lnsize = dbtob(lbp->lb_lnblkcnt);
	lnp = Zalloc(lnsize);

	if ((rval = read_locator_names(ep, fd, mbp, lbp, lnp, lnsize)) <= 0)
		goto out;

	rval = build_did_list(ep, fd, mbp, lbp, lbdidp, lnp, &did_listp,
	    replicated);

	/*
	 * An rval of ENOTSUP means we have a partial diskset. We'll want
	 * to set the partial variable so we can pass this information
	 * set_append_wrapper later for placing on the misp list.
	 */
	if (rval == ENOTSUP)
		partial = MD_IM_PARTIAL_DISKSET;

	if (rval < 0)
		goto out;

	/*
	 * Read in the NM record
	 * If no NM record was found, it still is a valid configuration
	 * but it also means that we won't find any corresponding DID_NM
	 * or DID_SHR_NM.
	 */
	if ((rval = read_nm_rec(ep, fd, mbp, lbp, &nm, MDDB_NM, rsp->cname))
	    < 0)
		goto out;
	else if (rval == 0)
		goto append;

	/*
	 * At this point, we have read in all of the blocks that form
	 * the nm_rec.  We should at least detect the corner case
	 * mentioned above, in which r_next_recid links to another
	 * nm_rec. Extended namespace handling is left for Phase 2.
	 *
	 * What this should really be is a loop, each iteration of
	 * which reads in a nm_rec and calls the set_append().
	 */
	/*LINTED*/
	nmp = (struct nm_rec *)(nm + sizeof (mddb_rb_t));
	if (nmp->r_rec_hdr.r_next_recid != (mddb_recid_t)0) {
		extended_namespace = 1;
		rval = 0;
		goto out;
	}

	if ((rval = read_nm_rec(ep, fd, mbp, lbp, &shrnm, MDDB_SHR_NM,
	    rsp->cname)) < 0)
		goto out;
	else if (rval == 0)
		goto append;

	/*LINTED*/
	snmp = (struct nm_shr_rec *)(shrnm + sizeof (mddb_rb_t));
	if (snmp->sr_rec_hdr.r_next_recid != (mddb_recid_t)0) {
		extended_namespace = 1;
		rval = 0;
		goto out;
	}

	if ((rval = read_nm_rec(ep, fd, mbp, lbp, &did_nm,
	    MDDB_DID_NM, rsp->cname)) < 0)
		goto out;
	else if (rval == 0)
		goto append;

	/*LINTED*/
	did_nmp = (struct devid_min_rec *)(did_nm + sizeof (mddb_rb_t) -
	    sizeof (int));
	if (did_nmp->min_rec_hdr.r_next_recid != (mddb_recid_t)0) {
		extended_namespace = 1;
		rval = 0;
		goto out;
	}

	if ((rval = read_nm_rec(ep, fd, mbp, lbp, &did_shrnm,
	    MDDB_DID_SHR_NM, rsp->cname)) < 0)
		goto out;
	else if (rval == 0)
		goto append;

	/*LINTED*/
	did_shrnmp = (struct devid_shr_rec *)(did_shrnm + sizeof (mddb_rb_t) -
	    sizeof (int));
	if (did_shrnmp->did_rec_hdr.r_next_recid != (mddb_recid_t)0) {
		extended_namespace = 1;
		rval = 0;
		goto out;
	}

	/*
	 * We need to check if all of the disks listed in the namespace
	 * are actually available. If they aren't we'll return with
	 * an ENOTSUP error which indicates a partial diskset.
	 */
	rval = check_nm_disks(did_nmp, did_shrnmp);

	/*
	 * An rval of ENOTSUP means we have a partial diskset. We'll want
	 * to set the partial variable so we can pass this information
	 * to set_append_wrapper later for placing on the misp list.
	 */
	if (rval == ENOTSUP)
		partial = MD_IM_PARTIAL_DISKSET;

	if (rval < 0)
		goto out;

append:
	/* Finally, we've got what we need to process this replica. */
	misp = set_append(mispp, did_listp, mbp, lbp,
	    /*LINTED*/
	    (mddb_rb_t *)nm, (mddb_rb_t *)shrnm, &pnm, (mddb_rb_t *)did_nm,
	    /*LINTED*/
	    (mddb_rb_t *)did_shrnm, (imp_flags | partial | replicated), ep);

	if (!(imp_flags & META_IMP_PASS1)) {
		*set_count += 1;
		rval = report_set_info(misp, mbp, lbp,
		    /*LINTED*/
		    (mddb_rb_t *)nm, &pnm, rsp, fd, imp_flags, *set_count,
		    overlap, overlap_disks, ep);
		if (rval < 0)
			goto out;
	}

	/* Return the fact that we found at least one set */
	rval = 1;

out:
	if (fd >= 0)
		(void) close(fd);
	if (did_listp != NULL)
		free_did_list(did_listp);
	if (lnp != NULL)
		Free(lnp);
	if (nm != NULL)
		Free(nm);
	if (did_nm != NULL)
		Free(did_nm);
	if (did_shrnm != NULL)
		Free(did_shrnm);
	if (pnm != NULL)
		free_pnm_rec_list(&pnm);

	/*
	 * If we are at the end of the list, we must free up
	 * the replicated list too
	 */
	if (dp->next == NULL)
		free_replicated_disks_list();

	if (extended_namespace)
		return (mddserror(ep, MDE_DS_EXTENDEDNM, MD_SET_BAD,
		    mynode(), NULL, NULL));

	return (rval);
}

/*
 * Return the minor name associated with a given disk slice
 */
static char *
meta_getminor_name(
	char *devname,
	md_error_t *ep
)
{
	int 	fd = -1;
	char 	*minor_name = NULL;
	char	*ret_minor_name = NULL;

	if (devname == NULL)
		return (NULL);

	if ((fd = open(devname, O_RDONLY|O_NDELAY, 0)) < 0) {
		(void) mdsyserror(ep, errno, devname);
		return (NULL);
	}

	if (devid_get_minor_name(fd, &minor_name) == 0) {
		ret_minor_name = Strdup(minor_name);
		devid_str_free(minor_name);
	}

	(void) close(fd);
	return (ret_minor_name);
}

/*
 * meta_update_mb_did
 *
 * Update or create the master block with the new set number.
 * If a non-null devid pointer is given, the devid in the
 * master block will also be changed.
 *
 * This routine is called during the import of a diskset
 * (meta_imp_update_mb) and during the take of a diskset that has
 * some unresolved replicated drives (meta_unrslv_replicated_mb).
 *
 * Returns : nothing (void)
 */
static void
meta_update_mb_did(
	mdsetname_t	*sp,
	mddrivename_t	*dnp,			/* raw name of drive with mb */
	void		*new_devid,		/* devid to be stored in mb */
	int		new_devid_len,
	void		*old_devid,		/* old devid stored in mb */
	int		replica_present,	/* does replica follow mb? */
	int		offset,
	md_error_t	*ep
)
{
	int			fd;
	struct mddb_mb		*mbp;
	uint_t			sliceno;
	mdname_t		*rsp;

	/* determine the replica slice */
	if (meta_replicaslice(dnp, &sliceno, ep) != 0) {
		return;
	}

	/*
	 * if the replica slice size is zero,
	 * don't bother opening
	 */
	if (dnp->vtoc.parts[sliceno].size == 0) {
		return;
	}

	if ((rsp = metaslicename(dnp, sliceno, ep)) == NULL) {
		return;
	}

	if ((fd = open(rsp->rname, O_RDWR | O_NDELAY)) < 0) {
		return;
	}

	if (lseek(fd, (off_t)dbtob(offset), SEEK_SET) < 0)
		return;

	mbp = Zalloc(DEV_BSIZE);
	if (read(fd, mbp, DEV_BSIZE) != DEV_BSIZE) {
		Free(mbp);
		return;
	}

	/* If no replica on disk, check for dummy mb */
	if (replica_present == NULL) {
		/*
		 * Check to see if there is a dummy there. If not
		 * create one. This would happen if the set was
		 * created before the master block dummy code was
		 * implemented.
		 */
		if ((mbp->mb_magic != MDDB_MAGIC_DU) ||
		    (mbp->mb_revision != MDDB_REV_MB)) {
			meta_mkdummymaster(sp, fd, offset);
			Free(mbp);
			return;
		}
	}

	mbp->mb_setno = sp->setno;
	if (meta_gettimeofday(&mbp->mb_timestamp) == -1) {
		Free(mbp);
		return;
	}

	/*
	 * If a old_devid is non-NULL then we're are dealing with a
	 * replicated diskset and the devid needs to be updated.
	 */
	if (old_devid) {
		if (mbp->mb_devid_magic == MDDB_MAGIC_DE) {
			if (mbp->mb_devid_len)
				(void) memset(mbp->mb_devid, 0,
				    mbp->mb_devid_len);
			(void) memcpy(mbp->mb_devid,
			    (char *)new_devid, new_devid_len);
			mbp->mb_devid_len = new_devid_len;
		}
	}

	crcgen((uchar_t *)mbp, (uint_t *)&mbp->mb_checksum,
	    (uint_t)DEV_BSIZE, (crc_skip_t *)NULL);

	/*
	 * Now write out the changes to disk.
	 * If an error occurs, just continue on.
	 * Next take of set will register this drive as
	 * an unresolved replicated drive and will attempt
	 * to fix the master block again.
	 */
	if (lseek(fd, (off_t)dbtob(offset), SEEK_SET) < 0) {
		Free(mbp);
		return;
	}
	if (write(fd, mbp, DEV_BSIZE) != DEV_BSIZE) {
		Free(mbp);
		return;
	}

	Free(mbp);
	(void) close(fd);
}


/*
 * meta_imp_update_mb
 *
 * Update the master block information during an import.
 * Takes an import set descriptor.
 *
 * Returns : nothing (void)
 */
void
meta_imp_update_mb(mdsetname_t *sp, md_im_set_desc_t *misp, md_error_t *ep)
{
	md_im_drive_info_t	*midp;
	mddrivename_t		*dnp;
	int			offset = 16; /* default mb offset is 16 */

	for (midp = misp->mis_drives; midp != NULL; midp = midp->mid_next) {
		/*
		 * If disk isn't available we can't update, so go to next
		 */
		if (midp->mid_available == MD_IM_DISK_NOT_AVAILABLE) {
			continue;
		}

		dnp = midp->mid_dnp;

		if (midp->mid_replicas) {
			md_im_replica_info_t	*mirp;

			/*
			 * If we have replicas on this disk we need to make
			 * sure that we update the master block on every
			 * replica on the disk.
			 */
			for (mirp = midp->mid_replicas; mirp != NULL;
			    mirp = mirp->mir_next) {
				offset = mirp->mir_offset;
				meta_update_mb_did(sp, dnp, midp->mid_devid,
				    midp->mid_devid_sz, midp->mid_o_devid,
				    1, offset, ep);
			}
		} else {
			/* No replicas, just update the one dummy mb */
			meta_update_mb_did(sp, dnp, midp->mid_devid,
			    midp->mid_devid_sz, midp->mid_o_devid,
			    0, offset, ep);
		}
		if (!mdisok(ep))
			return;
	}
}

/*
 * meta_unrslv_replicated_common
 *
 * Given a drive_desc and a drivenamelist pointer,
 * return the devidp associated with the drive_desc,
 * the replicated (new) devidp associated with the drive_desc
 * and the specific mddrivename in the drivenamelist that
 * matches the replicated (new) devidp.
 *
 * Typically the drivenamelist pointer would be setup by
 * the meta_prune_cnames function.
 *
 * Calling function must free devidp using devid_free.
 *
 * Returns 0 - success, found new_devidp and dnp_new.
 * Returns 1 - failure, didn't find new devid info
 */
static int
meta_unrslv_replicated_common(
	int			myside,
	md_drive_desc		*dd,	/* drive list for diskset */
	mddrivenamelist_t	*dnlp,	/* list of drives on current system */
	ddi_devid_t		*devidp,	/* old devid */
	ddi_devid_t		*new_devidp,	/* replicated (new) devid */
	mddrivename_t		**dnp_new,	/* replicated drive name */
	md_error_t		*ep
)
{
	mddrivename_t		*dnp;	/* drive name of old drive */
	mdsidenames_t		*sn = NULL;
	uint_t			rep_slice;
	mdname_t		*np;
	char			*minor_name = NULL;
	char			*devid_str = NULL;
	size_t			len;
	int			devid_sz;
	mddrivenamelist_t	*dp;
	ddi_devid_t		old_devid; /* devid of old drive */
	ddi_devid_t		new_devid; /* devid of new replicated drive */
	ddi_devid_t		dnp_new_devid; /* devid derived from drive */
						/* name of replicated drive */

	dnp = dd->dd_dnp;

	/* Get old devid from drive record */
	(void) devid_str_decode(dd->dd_dnp->devid,
	    &old_devid, NULL);

	/* Look up replicated (new) devid */
	new_devid = replicated_list_lookup(
	    devid_sizeof(old_devid), old_devid);

	devid_free(old_devid);

	if (new_devid == NULL)
		return (1);

	/*
	 * Using new_devid, find a drivename entry with a matching devid.
	 * Use the passed in dnlp since it has the new (replicated) disknames
	 * in it.
	 */
	for (dp = dnlp; dp != NULL; dp = dp->next) {
		(void) devid_str_decode(dp->drivenamep->devid,
		    &dnp_new_devid, NULL);

		if (dnp_new_devid == NULL)
			continue;

		if (devid_compare(new_devid, dnp_new_devid) == 0) {
			devid_free(dnp_new_devid);
			break;
		}
		devid_free(dnp_new_devid);
	}

	/* If can't find new name for drive - nothing to update */
	if (dp == NULL)
		return (1);

	/*
	 * Setup returned value to be the drivename structure associated
	 * with new (replicated) drive.
	 */
	*dnp_new = dp->drivenamep;

	/*
	 * Need to return the new devid including the minor name.
	 * Find the minor_name here using the sidename or by
	 * looking in the namespace.
	 */
	for (sn = dnp->side_names; sn != NULL; sn = sn->next) {
		if (sn->sideno == myside)
			break;
	}

	/*
	 * The disk has no side name information
	 */
	if (sn == NULL) {
		if ((meta_replicaslice(*dnp_new, &rep_slice, ep) != 0) ||
		    ((np = metaslicename(*dnp_new, rep_slice, ep))
			== NULL)) {
			mdclrerror(ep);
			return (1);
		}

		if (np->dev == NODEV64)
			return (1);

		/*
		 * minor_name will be NULL if dnp->devid == NULL
		 * - see metagetvtoc()
		 */
		if (np->minor_name == NULL)
			return (1);
		else
			minor_name = Strdup(np->minor_name);

	} else {
		minor_name = meta_getdidminorbykey(
			    MD_LOCAL_SET, sn->sideno + SKEW,
			    dnp->side_names_key, ep);
		if (!mdisok(ep))
			return (1);
	}
	/*
	 * Now, use the old devid with minor name to lookup
	 * the replicated (new) devid that will also contain
	 * a minor name.
	 */
	len = strlen(dnp->devid) + strlen(minor_name) + 2;
	devid_str = (char *)Malloc(len);
	(void) snprintf(devid_str, len, "%s/%s", dnp->devid,
	    minor_name);
	(void) devid_str_decode(devid_str, devidp, NULL);
	Free(devid_str);
	devid_sz = devid_sizeof((ddi_devid_t)*devidp);
	*new_devidp = replicated_list_lookup(devid_sz, *devidp);
	return (0);
}

/*
 * meta_unrslv_replicated_mb
 *
 * Update the master block information during a take.
 * Takes an md_drive_desc descriptor.
 *
 * Returns : nothing (void)
 */
void
meta_unrslv_replicated_mb(
	mdsetname_t		*sp,
	md_drive_desc		*dd,	/* drive list for diskset */
	mddrivenamelist_t	*dnlp,	/* list of drives on current system */
	md_error_t		*ep
)
{
	md_drive_desc		*d = NULL, *d_save;
	mddrivename_t		*dnp;	   /* dnp of old drive */
	mddrivename_t		*dnp_new;  /* dnp of new (replicated) drive */
	mddrivename_t		*dnp_save; /* saved copy needed to restore */
	ddi_devid_t		devidp, new_devidp;
	int			myside;

	if ((myside = getmyside(sp, ep)) == MD_SIDEWILD)
		return;

	for (d = dd; d != NULL; d = d->dd_next) {
		dnp = d->dd_dnp;
		if (dnp == NULL)
			continue;

		/* If don't need to update master block - skip it. */
		if (!(d->dd_flags & MD_DR_FIX_MB_DID))
			continue;

		/*
		 * Get old and replicated (new) devids associated with this
		 * drive.  Also, get the new (replicated) drivename structure.
		 */
		if (meta_unrslv_replicated_common(myside, d, dnlp, &devidp,
		    &new_devidp, &dnp_new, ep) != 0) {
			mdclrerror(ep);
			continue;
		}

		if (new_devidp) {
			int	offset = 16; /* default mb offset is 16 */
			int	dbcnt;

			if (d->dd_dbcnt) {
				/*
				 * Update each master block on the disk
				 */
				for (dbcnt = d->dd_dbcnt; dbcnt != 0; dbcnt--) {
					meta_update_mb_did(sp, dnp_new,
					    new_devidp,
					    devid_sizeof(new_devidp), devidp,
					    1, offset, ep);
					offset += d->dd_dbsize;
				}
			} else {
				/* update the one dummy mb */
				meta_update_mb_did(sp, dnp_new, new_devidp,
				    devid_sizeof(new_devidp), devidp,
				    0, offset, ep);
			}
			if (!mdisok(ep)) {
				devid_free(devidp);
				return;
			}

			/* Set drive record flags to ok */
			/* Just update this one drive record. */
			d_save = d->dd_next;
			dnp_save = d->dd_dnp;
			d->dd_next = NULL;
			d->dd_dnp = dnp_new;
			/* Ignore failure since no bad effect. */
			(void) clnt_upd_dr_flags(mynode(), sp, d,
			    MD_DR_OK, ep);
			d->dd_next = d_save;
			d->dd_dnp = dnp_save;
		}
		devid_free(devidp);
	}
}

/*
 * meta_update_nm_rr_did
 *
 * Change a devid stored in the diskset namespace and in the local set
 * namespace with the new devid.
 *
 * This routine is called during the import of a diskset
 * (meta_imp_update_nn) and during the take of a diskset that has
 * some unresolved replicated drives (meta_unrslv_replicated_nm).
 *
 * Returns : nothing (void)
 */
static void
meta_update_nm_rr_did(
	mdsetname_t	*sp,
	void		*old_devid,		/* old devid being replaced */
	int		old_devid_sz,
	void		*new_devid,		/* devid to be stored in nm */
	int		new_devid_sz,
	int		import_flag,		/* called during import? */
	md_error_t	*ep
)
{
	struct mddb_config	c;

	(void) memset(&c, 0, sizeof (c));
	c.c_setno = sp->setno;

	/* During import to NOT update the local namespace. */
	if (import_flag)
		c.c_flags = MDDB_C_IMPORT;

	c.c_locator.l_devid = (uintptr_t)Malloc(new_devid_sz);
	(void) memcpy((void *)(uintptr_t)c.c_locator.l_devid,
	    new_devid, new_devid_sz);
	c.c_locator.l_devid_sz = new_devid_sz;
	c.c_locator.l_devid_flags =
	    MDDB_DEVID_VALID | MDDB_DEVID_SPACE | MDDB_DEVID_SZ;
	c.c_locator.l_old_devid = (uint64_t)(uintptr_t)Malloc(old_devid_sz);
	(void) memcpy((void *)(uintptr_t)c.c_locator.l_old_devid,
	    old_devid, old_devid_sz);
	c.c_locator.l_old_devid_sz = old_devid_sz;
	if (metaioctl(MD_IOCUPDATE_NM_RR_DID, &c, &c.c_mde, NULL) != 0) {
		(void) mdstealerror(ep, &c.c_mde);
	}
	Free((void *)(uintptr_t)c.c_locator.l_devid);
	Free((void *)(uintptr_t)c.c_locator.l_old_devid);
}

/*
 * meta_imp_update_nm
 *
 * Change a devid stored in the diskset namespace with the new devid.
 * This routine is called during the import of a remotely replicated diskset.
 *
 * Returns : nothing (void)
 */
void
meta_imp_update_nm(mdsetname_t *sp, md_im_set_desc_t *misp, md_error_t *ep)
{
	md_im_drive_info_t	*midp;

	for (midp = misp->mis_drives; midp != NULL; midp = midp->mid_next) {
		/*
		 * If disk isn't available we can't update, so go to next
		 */
		if (midp->mid_available == MD_IM_DISK_NOT_AVAILABLE) {
			continue;
		}

		meta_update_nm_rr_did(sp, midp->mid_o_devid,
		    midp->mid_o_devid_sz, midp->mid_devid,
		    midp->mid_devid_sz, 1, ep);
		if (!mdisok(ep))
			return;
	}
}

/*
 * meta_unrslv_replicated_nm
 *
 * Change a devid stored in the diskset namespace and in the local set
 * namespace with the new devid.
 *
 * This routine is called during the take of a diskset that has
 * some unresolved replicated drives.
 *
 * Returns : nothing (void)
 */
void
meta_unrslv_replicated_nm(
	mdsetname_t		*sp,
	md_drive_desc		*dd,	/* drive list for diskset */
	mddrivenamelist_t	*dnlp,	/* list of drives on current system */
	md_error_t		*ep
)
{
	md_drive_desc		*d = NULL;
	mddrivename_t		*dnp;	/* drive name of old drive */
	mddrivename_t		*dnp_new; /* drive name of new (repl) drive */
	ddi_devid_t		devidp, new_devidp;
	ddi_devid_t		old_devid;
	char			*devid_old_save;
	mdsetname_t		*local_sp = NULL;
	int			myside;

	if ((myside = getmyside(sp, ep)) == MD_SIDEWILD)
		return;

	for (d = dd; d != NULL; d = d->dd_next) {
		dnp = d->dd_dnp;
		if (dnp == NULL)
			continue;

		/* If don't need to update namespace - skip it. */
		if (!(d->dd_flags & MD_DR_FIX_LB_NM_DID))
			continue;

		/* Get old devid from drive record */
		(void) devid_str_decode(d->dd_dnp->devid,
		    &old_devid, NULL);

		/*
		 * Get old and replicated (new) devids associated with this
		 * drive.  Also, get the new (replicated) drivename structure.
		 */
		if (meta_unrslv_replicated_common(myside, d, dnlp, &devidp,
		    &new_devidp, &dnp_new, ep) != 0) {
			mdclrerror(ep);
			continue;
		}

		if (new_devidp) {
			meta_update_nm_rr_did(sp, devidp,
			    devid_sizeof(devidp), new_devidp,
			    devid_sizeof(new_devidp), 0, ep);
			if (!mdisok(ep)) {
				devid_free(devidp);
				return;
			}
		}
		devid_free(devidp);

		/*
		 * Using the new devid, fix up the name.
		 * If meta_upd_ctdnames fails, the next take will re-resolve
		 * the name from the new devid.
		 */
		local_sp = metasetname(MD_LOCAL_NAME, ep);
		devid_old_save = dnp->devid;
		dnp->devid = dnp_new->devid;
		(void) meta_upd_ctdnames(&local_sp, 0, (myside + SKEW),
			dnp, NULL, ep);
		mdclrerror(ep);
		dnp->devid = devid_old_save;
	}
}

static set_t
meta_imp_setno(
	md_error_t *ep
)
{
	set_t	max_sets, setno;
	int	bool;

	if ((max_sets = get_max_sets(ep)) == 0) {
		return (MD_SET_BAD);
	}

	/*
	 * This code needs to be expanded when we run in SunCluster
	 * environment SunCluster obtains setno internally
	 */
	for (setno = 1; setno < max_sets; setno++) {
		if (clnt_setnumbusy(mynode(), setno,
			&bool, ep) == -1) {
			setno = MD_SET_BAD;
			break;
		}
		/*
		 * found one available
		 */
		if (bool == FALSE)
			break;
	}

	if (setno == max_sets) {
		setno = MD_SET_BAD;
	}

	return (setno);
}

int
meta_imp_set(
	md_im_set_desc_t *misp,
	char		*setname,
	int		force,
	bool_t		dry_run,
	md_error_t	*ep
)
{
	md_timeval32_t		tp;
	md_im_drive_info_t	*midp;
	uint_t			rep_slice;
	mddrivename_t		*dnp;
	struct mddb_config	c;
	mdname_t		*np;
	md_im_replica_info_t	*mirp;
	set_t			setno;
	mdcinfo_t		*cinfo;
	mdsetname_t		*sp;
	mddrivenamelist_t	*dnlp = NULL;
	mddrivenamelist_t	**dnlpp = &dnlp;
	char			*minor_name = NULL;
	int			stale_flag = 0;
	md_set_desc		*sd;
	int			partial_replicated_flag = 0;
	md_error_t		xep = mdnullerror;
	md_setkey_t		*cl_sk;

	(void) memset(&c, 0, sizeof (c));
	(void) strlcpy(c.c_setname, setname, sizeof (c.c_setname));
	c.c_sideno = 0;
	c.c_flags = MDDB_C_IMPORT;

	/*
	 * Check to see if the setname that the set is being imported into,
	 * already exists.
	 */
	if (getsetbyname(c.c_setname, ep) != NULL) {
		return (mddserror(ep, MDE_DS_SETNAMEBUSY, MD_SET_BAD,
		    mynode(), NULL, c.c_setname));
	}

	/*
	 * Find the next available set number
	 */
	if ((setno = meta_imp_setno(ep)) == MD_SET_BAD) {
		return (mddserror(ep, MDE_DS_SETNOTIMP, MD_SET_BAD,
		    mynode(), NULL, c.c_setname));
	}

	c.c_setno = setno;
	if (meta_gettimeofday(&tp) == -1) {
		return (mdsyserror(ep, errno, NULL));
	}
	c.c_timestamp = tp;

	/* Check to see if replica quorum requirement is fulfilled */
	if (meta_replica_quorum(misp) == -1) {
		if (!force) {
			return (mddserror(ep, MDE_DS_INSUFQUORUM, MD_SET_BAD,
			    mynode(), NULL, c.c_setname));
		} else {
			stale_flag = MD_IMP_STALE_SET;
			/*
			 * If we have a stale diskset, the kernel will
			 * delete the replicas on the unavailable disks.
			 * To be consistent, we'll zero out the mirp on those
			 * disks here.
			 */
			for (midp = misp->mis_drives; midp != NULL;
			    midp = midp->mid_next) {
				if (midp->mid_available ==
				    MD_IM_DISK_NOT_AVAILABLE) {
					midp->mid_replicas = NULL;
				}
			}
		}
	}

	for (midp = misp->mis_drives; midp != NULL;
		midp = midp->mid_next) {

		if ((misp->mis_flags & MD_IM_SET_REPLICATED) &&
		    (partial_replicated_flag == 0) &&
		    (midp->mid_available == MD_IM_DISK_NOT_AVAILABLE))
			partial_replicated_flag = MD_SR_UNRSLV_REPLICATED;

		/*
		 * We pass the list of the drives in the
		 * set with replicas on them down to the kernel.
		 */
		dnp = midp->mid_dnp;
		mirp = midp->mid_replicas;
		if (!mirp) {
			/*
			 * No replicas on this disk, go to next disk.
			 */
			continue;
		}

		if (midp->mid_available == MD_IM_DISK_NOT_AVAILABLE) {
			/*
			 * The disk isn't there. We'll need to get the
			 * disk information from the midp list instead
			 * of going and looking for it. This means it
			 * will be information relative to the old
			 * system.
			 */
			minor_name = Strdup(midp->mid_minor_name);
			(void) strncpy(c.c_locator.l_driver,
			    midp->mid_driver_name,
			    sizeof (c.c_locator.l_driver));
			(void) strcpy(c.c_locator.l_devname, midp->mid_devname);
			c.c_locator.l_mnum = midp->mid_mnum;

		} else {
			if ((meta_replicaslice(dnp, &rep_slice, ep) != 0) ||
			    ((np = metaslicename(dnp, rep_slice, ep))
			    == NULL)) {
				mdclrerror(ep);
				continue;
			}
			(void) strcpy(c.c_locator.l_devname, np->bname);
			c.c_locator.l_dev = meta_cmpldev(np->dev);
			c.c_locator.l_mnum = meta_getminor(np->dev);
			minor_name = meta_getminor_name(np->bname, ep);
			if ((cinfo = metagetcinfo(np, ep)) == NULL) {
				mdclrerror(ep);
				continue;
			}

			if (cinfo->dname) {
				(void) strncpy(c.c_locator.l_driver,
				    cinfo->dname,
				    sizeof (c.c_locator.l_driver));
			}
		}

		c.c_locator.l_devid = (uintptr_t)Malloc(midp->mid_devid_sz);
		(void) memcpy((void *)(uintptr_t)c.c_locator.l_devid,
		    midp->mid_devid, midp->mid_devid_sz);
		c.c_locator.l_devid_sz = midp->mid_devid_sz;
		c.c_locator.l_devid_flags =
		    MDDB_DEVID_VALID | MDDB_DEVID_SPACE | MDDB_DEVID_SZ;
		if (midp->mid_o_devid) {
			c.c_locator.l_old_devid =
			    (uint64_t)(uintptr_t)Malloc(midp->mid_o_devid_sz);
			(void) memcpy((void *)(uintptr_t)
			    c.c_locator.l_old_devid,
			    midp->mid_o_devid, midp->mid_o_devid_sz);
			c.c_locator.l_old_devid_sz = midp->mid_o_devid_sz;
		}
		if (minor_name) {
			(void) strncpy(c.c_locator.l_minor_name, minor_name,
			    sizeof (c.c_locator.l_minor_name));
		}

		do {
			c.c_locator.l_flags = 0;
			c.c_locator.l_blkno = mirp->mir_offset;
			if (metaioctl(MD_DB_USEDEV, &c, &c.c_mde, NULL) != 0) {
				Free((void *)(uintptr_t)c.c_locator.l_devid);
				if (c.c_locator.l_old_devid)
					Free((void *)(uintptr_t)
					    c.c_locator.l_old_devid);
				return (mdstealerror(ep, &c.c_mde));
			}
			mirp = mirp->mir_next;
		} while (mirp != NULL);
	}

	/*
	 * If the dry run option was specified, flag success
	 * and exit out
	 */
	if (dry_run == 1) {
		md_eprintf("%s\n", dgettext(TEXT_DOMAIN,
		    "import should be successful"));
		Free((void *)(uintptr_t)c.c_locator.l_devid);
		if (c.c_locator.l_old_devid)
			Free((void *)(uintptr_t)c.c_locator.l_old_devid);
		return (0);
	}

	/*
	 * Now the kernel should have all the information
	 * regarding the import diskset replica.
	 * Tell the kernel to load them up and import the set
	 */
	(void) memset(&c, 0, sizeof (c));
	c.c_flags = stale_flag;
	c.c_setno = setno;
	if (metaioctl(MD_IOCIMP_LOAD, &c, &c.c_mde, NULL) != 0) {
		Free((void *)(uintptr_t)c.c_locator.l_devid);
		if (c.c_locator.l_old_devid)
			Free((void *)(uintptr_t)c.c_locator.l_old_devid);
		return (mdstealerror(ep, &c.c_mde));
	}

	(void) meta_smf_enable(META_SMF_DISKSET, NULL);

	/*
	 * Create a set name for the set.
	 */
	sp = Zalloc(sizeof (*sp));
	sp->setname = Strdup(setname);
	sp->lockfd = MD_NO_LOCK;
	sp->setno = setno;
	sd = Zalloc(sizeof (*sd));
	(void) strcpy(sd->sd_nodes[0], mynode());
	sd->sd_ctime = tp;
	sd->sd_genid = 0;

	if (misp->mis_flags & MD_IM_SET_REPLICATED) {
		/* Update the diskset namespace */
		meta_imp_update_nm(sp, misp, ep);

		/* Release the diskset - even if update_nm failed */
		(void) memset(&c, 0, sizeof (c));
		c.c_setno = setno;
		/* Don't need device id information from this ioctl */
		c.c_locator.l_devid = (uint64_t)0;
		c.c_locator.l_devid_flags = 0;
		if (metaioctl(MD_RELEASE_SET, &c, &c.c_mde, NULL) != 0) {
			if (mdisok(ep))
				(void) mdstealerror(ep, &c.c_mde);
			Free(sd);
			Free(sp);
			return (-1);
		}

		/* If update_nm failed, then fail the import. */
		if (!mdisok(ep)) {
			Free(sd);
			Free(sp);
			return (-1);
		}
	}

	/*
	 * We'll need to update information in the master block due
	 * to the set number changing and if the case of a replicated
	 * diskset, the device id changing. May also need to create a
	 * dummy master block if it's not there.
	 */
	meta_imp_update_mb(sp, misp, ep);
	if (!mdisok(ep)) {
		Free(sd);
		Free(sp);
		return (-1);
	}

	/*
	 * Create set record for diskset, but record is left in
	 * MD_SR_ADD state until after drives are added to set.
	 */
	if (clnt_lock_set(mynode(), sp, ep)) {
		Free(sd);
		Free(sp);
		return (-1);
	}

	if (clnt_createset(mynode(), sp, sd->sd_nodes,
	    sd->sd_ctime, sd->sd_genid, ep)) {
		cl_sk = cl_get_setkey(sp->setno, sp->setname);
		(void) clnt_unlock_set(mynode(), cl_sk, &xep);
		Free(sd);
		Free(sp);
		return (-1);
	}

	Free(sd);

	/*
	 * Create drive records for the disks in the set.
	 */
	for (midp = misp->mis_drives; midp != NULL; midp = midp->mid_next) {
		dnp = midp->mid_dnp;
		if (midp->mid_available & MD_IM_DISK_NOT_AVAILABLE) {
			/*
			 * If the disk isn't available, the dnp->devid is
			 * no good. It is either blank for the case where
			 * there is no disk with that devname, or it
			 * contains the devid for the real disk in the system
			 * with that name. The problem is, if the disk is
			 * unavailable, then the devid should be the devid
			 * of the missing disk. So we're faking a dnp for
			 * the import. This is needed for creating drive
			 * records.
			 */
			dnp = Zalloc(sizeof (mddrivename_t));
			dnp->side_names_key = midp->mid_dnp->side_names_key;
			dnp->type = midp->mid_dnp->type;
			dnp->cname = Strdup(midp->mid_dnp->cname);
			dnp->rname = Strdup(midp->mid_dnp->rname);
			dnp->devid = devid_str_encode(midp->mid_devid,
			    NULL);
			midp->mid_dnp = dnp;
		}
		dnlpp = meta_drivenamelist_append_wrapper(dnlpp, dnp);
	}

	if (meta_imp_set_adddrives(sp, dnlp, misp, ep)) {
		Free(sp);
		return (mddserror(ep, MDE_DS_SETNOTIMP, MD_SET_BAD,
		    mynode(), NULL, c.c_setname));
	}

	/* If drives were added without error, set set_record to OK */
	if (clnt_upd_sr_flags(mynode(), sp,
	    (partial_replicated_flag | MD_SR_OK | MD_SR_MB_DEVID), ep)) {
		Free(sp);
		return (mddserror(ep, MDE_DS_SETNOTIMP, MD_SET_BAD,
		    mynode(), NULL, c.c_setname));
	}

	Free(sp);

	cl_sk = cl_get_setkey(sp->setno, sp->setname);
	if (clnt_unlock_set(mynode(), cl_sk, ep)) {
		return (-1);
	}
	cl_set_setkey(NULL);

	Free((void *)(uintptr_t)c.c_locator.l_devid);
	if (c.c_locator.l_old_devid)
		Free((void *)(uintptr_t)c.c_locator.l_old_devid);
	return (0);
}
