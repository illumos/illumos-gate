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

/*
 * mirror operations
 */

#include <meta.h>
#include <sys/lvm/md_mirror.h>
#include <thread.h>

extern	int	md_in_daemon;
extern md_mn_client_list_t *mdmn_clients;

/*
 * chain of mirrors
 */
typedef struct mm_unit_list {
	struct mm_unit_list	*next;	/* next in chain */
	mdname_t		*namep;	/* mirror name */
	mm_pass_num_t		pass;	/* pass number */
	uint_t			done;	/* resync done */
} mm_unit_list_t;

/*
 * resync mirror
 * meta_lock for this set should be held on entry.
 */
int
meta_mirror_resync(
	mdsetname_t		*sp,
	mdname_t		*mirnp,
	daddr_t			size,
	md_error_t		*ep,
	md_resync_cmd_t		cmd	/* Start/Block/Unblock/Kill */
)
{
	char			*miscname;
	md_resync_ioctl_t	ri;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(mirnp->dev)));

	/* make sure we have a mirror */
	if ((miscname = metagetmiscname(mirnp, ep)) == NULL)
		return (-1);
	if (strcmp(miscname, MD_MIRROR) != 0) {
		return (mdmderror(ep, MDE_NOT_MM, meta_getminor(mirnp->dev),
		    mirnp->cname));
	}

	/* start resync */
	(void) memset(&ri, 0, sizeof (ri));
	MD_SETDRIVERNAME(&ri, MD_MIRROR, sp->setno);
	ri.ri_mnum = meta_getminor(mirnp->dev);
	ri.ri_copysize = size;
	switch (cmd) {
	case MD_RESYNC_FORCE_MNSTART:
		ri.ri_flags |= MD_RI_RESYNC_FORCE_MNSTART;
		break;
	case MD_RESYNC_START:
		ri.ri_flags = 0;
		break;
	case MD_RESYNC_BLOCK:
		ri.ri_flags = MD_RI_BLOCK;
		break;
	case MD_RESYNC_UNBLOCK:
		ri.ri_flags = MD_RI_UNBLOCK;
		break;
	case MD_RESYNC_KILL:
		ri.ri_flags = MD_RI_KILL;
		break;
	case MD_RESYNC_KILL_NO_WAIT:
		ri.ri_flags = MD_RI_KILL | MD_RI_NO_WAIT;
		break;
	default:
		/* TODO: Add new error MDE_BAD_RESYNC_FLAGS */
		return (mderror(ep, MDE_BAD_RESYNC_OPT, mirnp->cname));
	}

	if (metaioctl(MD_IOCSETSYNC, &ri, &ri.mde, mirnp->cname) != 0)
		return (mdstealerror(ep, &ri.mde));

	/* return success */
	return (0);
}

/*
 * free units
 */
static void
free_units(
	mm_unit_list_t	*mirrors[MD_PASS_MAX + 1]
)
{
	uint_t		i;

	for (i = 0; (i < (MD_PASS_MAX + 1)); ++i) {
		mm_unit_list_t	*p, *n;

		for (p = mirrors[i], n = NULL; (p != NULL); p = n) {
			n = p->next;
			Free(p);
		}
		mirrors[i] = NULL;
	}
}

/*
 * setup_units:	build lists of units for each pass
 */
static int
setup_units(
	mdsetname_t	*sp,
	mm_unit_list_t	*mirrors[MD_PASS_MAX + 1],
	md_error_t	*ep
)
{
	mdnamelist_t	*mirrornlp = NULL;
	mdnamelist_t	*p;
	int		rval = 0;

	/* should have a set */
	assert(sp != NULL);

	/* for each mirror */
	if (meta_get_mirror_names(sp, &mirrornlp, 0, ep) < 0)
		return (-1);
	for (p = mirrornlp; (p != NULL); p = p->next) {
		md_mirror_t	*mirrorp;
		mm_unit_list_t	*lp;

		/* get unit structure */
		if ((mirrorp = meta_get_mirror(sp, p->namep, ep)) == NULL) {
			rval = -1;	/* record, but ignore errors */
			continue;
		}

		/* save info */
		lp = Zalloc(sizeof (*lp));
		lp->namep = p->namep;
		lp->pass = mirrorp->pass_num;
		if ((lp->pass < 0) || (lp->pass > MD_PASS_MAX))
			lp->pass = MD_PASS_MAX;

		/* put on list */
		lp->next = mirrors[lp->pass];
		mirrors[lp->pass] = lp;
	}

	/* cleanup, return error */
	metafreenamelist(mirrornlp);
	return (rval);
}

/*
 * resync all mirrors (in background)
 */
int
meta_mirror_resync_all(
	mdsetname_t	*sp,
	daddr_t		size,
	md_error_t	*ep
)
{
	mm_unit_list_t	*mirrors[MD_PASS_MAX + 1];
	mm_pass_num_t	pass, max_pass;
	int		rval = 0, fval;

	/* should have a set */
	assert(sp != NULL);

	/* get mirrors */
	(void) memset(mirrors, 0, sizeof (mirrors));
	if (setup_units(sp, mirrors, ep) != 0)
		return (-1);

	/* fork a process */
	if ((fval = md_daemonize(sp, ep)) != 0) {
		/*
		 * md_daemonize will fork off a process.  The is the
		 * parent or error.
		 */
		if (fval > 0) {
			free_units(mirrors);
			return (0);
		}
		mdclrerror(ep);
	}
	/*
	 * Closing stdin/out/err here.
	 * In case this was called thru rsh, the calling process on the other
	 * side will know, it doesn't have to wait until all the resyncs have
	 * finished.
	 * Also initialise the rpc client pool so that this process will use
	 * a unique pool of clients. If we don't do this, all of the forked
	 * clients will end up using the same pool of clients which can result
	 * in hung clients.
	 */
	if (meta_is_mn_set(sp, ep)) {
		(void) close(0);
		(void) close(1);
		(void) close(2);
		mdmn_clients = NULL;
	}
	assert((fval == 0) || (fval == -1));

	/*
	 * Determine which pass level is the highest that contains mirrors to
	 * resync. We only need to wait for completion of earlier levels below
	 * this high watermark. If all mirrors are at the same pass level
	 * there is no requirement to wait for completion.
	 */

	max_pass = 1;
	for (pass = MD_PASS_MAX; pass > 1; --pass) {
		if (mirrors[pass] != NULL) {
			max_pass = pass;
			break;
		}
	}

	/*
	 * max_pass now contains the highest pass-level with resyncable mirrors
	 */

	/* do passes */
	for (pass = 1; (pass <= MD_PASS_MAX); ++pass) {
		int			dispatched = 0;
		unsigned		howlong = 1;
		mm_unit_list_t		*lp;

		/* skip empty passes */
		if (mirrors[pass] == NULL)
			continue;

		/* dispatch all resyncs in pass */
		for (lp = mirrors[pass]; (lp != NULL); lp = lp->next) {
			if (meta_is_mn_set(sp, ep)) {
				if (meta_mn_send_setsync(sp, lp->namep,
				    size, ep) != 0) {
					rval = -1;
					lp->done = 1;
				} else {
					++dispatched;
				}
			} else {
				if (meta_mirror_resync(sp, lp->namep, size, ep,
				    MD_RESYNC_START) != 0) {
					rval = -1;
					lp->done = 1;
				} else {
					++dispatched;
				}
			}
		}

		/*
		 * Wait for them to finish iff we are at a level lower than
		 * max_pass. This orders the resyncs into distinct levels.
		 * I.e. level 2 resyncs won't start until all level 1 ones
		 * have completed.
		 */
		if (pass == max_pass)
			continue;

		howlong = 1;
		while (dispatched > 0) {

			/* wait a while */
			(void) sleep(howlong);

			/* see if any finished */
			for (lp = mirrors[pass]; lp != NULL; lp = lp->next) {
				md_resync_ioctl_t	ri;

				if (lp->done)
					continue;

				(void) memset(&ri, '\0', sizeof (ri));
				ri.ri_mnum = meta_getminor(lp->namep->dev);
				MD_SETDRIVERNAME(&ri, MD_MIRROR, sp->setno);
				if (metaioctl(MD_IOCGETSYNC, &ri, &ri.mde,
				    lp->namep->cname) != 0) {
					(void) mdstealerror(ep, &ri.mde);
					rval = -1;
					lp->done = 1;
					--dispatched;
				} else if (! (ri.ri_flags & MD_RI_INPROGRESS)) {
					lp->done = 1;
					--dispatched;
				}
			}

			/* wait a little longer next time */
			if (howlong < 10)
				++howlong;
		}
	}

	/* cleanup, return success */
	free_units(mirrors);
	if (fval == 0)  /* we are the child process so exit */
		exit(0);
	return (rval);
}

/*
 * meta_mn_mirror_resync_all:
 * -------------------------
 * Resync all mirrors associated with given set (arg). Called when master
 * node is adding a node to a diskset.  Only want to initiate the resync on
 * the current node.
 */
void *
meta_mn_mirror_resync_all(void *arg)
{
	set_t		setno = *((set_t *)arg);
	mdsetname_t	*sp;
	mm_unit_list_t	*mirrors[MD_PASS_MAX + 1];
	mm_pass_num_t	pass, max_pass;
	md_error_t	mde = mdnullerror;
	int		fval;


	/* should have a set */
	assert(setno != NULL);

	if ((sp = metasetnosetname(setno, &mde)) == NULL) {
		mde_perror(&mde, "");
		return (NULL);
	}

	if (!(meta_is_mn_set(sp, &mde))) {
		mde_perror(&mde, "");
		return (NULL);
	}

	/* fork a process */
	if ((fval = md_daemonize(sp, &mde)) != 0) {
		/*
		 * md_daemonize will fork off a process.  The is the
		 * parent or error.
		 */
		if (fval > 0) {
			return (NULL);
		}
		mde_perror(&mde, "");
		return (NULL);
	}
	/*
	 * Child process should never return back to rpc.metad, but
	 * should exit.
	 * Flush all internally cached data inherited from parent process
	 * since cached data will be cleared when parent process RPC request
	 * has completed (which is possibly before this child process
	 * can complete).
	 * Child process can retrieve and cache its own copy of data from
	 * rpc.metad that won't be changed by the parent process.
	 *
	 * Reset md_in_daemon since this child will be a client of rpc.metad
	 * not part of the rpc.metad daemon itself.
	 * md_in_daemon is used by rpc.metad so that libmeta can tell if
	 * this thread is rpc.metad or any other thread.  (If this thread
	 * was rpc.metad it could use some short circuit code to get data
	 * directly from rpc.metad instead of doing an RPC call to rpc.metad).
	 */
	md_in_daemon = 0;
	metaflushsetname(sp);
	sr_cache_flush_setno(setno);
	if ((sp = metasetnosetname(setno, &mde)) == NULL) {
		mde_perror(&mde, "");
		md_exit(sp, 1);
	}

	if (meta_lock(sp, TRUE, &mde) != 0) {
		mde_perror(&mde, "");
		md_exit(sp, 1);
	}

	/*
	 * Closing stdin/out/err here.
	 */
	(void) close(0);
	(void) close(1);
	(void) close(2);
	assert(fval == 0);

	/* get mirrors */
	(void) memset(mirrors, 0, sizeof (mirrors));
	if (setup_units(sp, mirrors, &mde) != 0) {
		(void) meta_unlock(sp, &mde);
		md_exit(sp, 1);
	}

	/*
	 * Determine which pass level is the highest that contains mirrors to
	 * resync. We only need to wait for completion of earlier levels below
	 * this high watermark. If all mirrors are at the same pass level
	 * there is no requirement to wait for completion.
	 */
	max_pass = 1;
	for (pass = MD_PASS_MAX; pass > 1; --pass) {
		if (mirrors[pass] != NULL) {
			max_pass = pass;
			break;
		}
	}

	/*
	 * max_pass now contains the highest pass-level with resyncable mirrors
	 */
	/* do passes */
	for (pass = 1; (pass <= MD_PASS_MAX); ++pass) {
		int			dispatched = 0;
		unsigned		howlong = 1;
		mm_unit_list_t		*lp;

		/* skip empty passes */
		if (mirrors[pass] == NULL)
			continue;

		/* dispatch all resyncs in pass */
		for (lp = mirrors[pass]; (lp != NULL); lp = lp->next) {
			if (meta_mirror_resync(sp, lp->namep, 0, &mde,
			    MD_RESYNC_FORCE_MNSTART) != 0) {
				mdclrerror(&mde);
				lp->done = 1;
			} else {
				++dispatched;
			}
		}

		/*
		 * Wait for them to finish iff we are at a level lower than
		 * max_pass. This orders the resyncs into distinct levels.
		 * I.e. level 2 resyncs won't start until all level 1 ones
		 * have completed.
		 */
		if (pass == max_pass)
			continue;

		howlong = 1;
		while (dispatched > 0) {

			/* wait a while */
			(void) sleep(howlong);

			/* see if any finished */
			for (lp = mirrors[pass]; lp != NULL; lp = lp->next) {
				md_resync_ioctl_t	ri;

				if (lp->done)
					continue;

				(void) memset(&ri, '\0', sizeof (ri));
				ri.ri_mnum = meta_getminor(lp->namep->dev);
				MD_SETDRIVERNAME(&ri, MD_MIRROR, sp->setno);
				if (metaioctl(MD_IOCGETSYNC, &ri, &ri.mde,
				    lp->namep->cname) != 0) {
					mdclrerror(&mde);
					lp->done = 1;
					--dispatched;
				} else if (! (ri.ri_flags & MD_RI_INPROGRESS)) {
					lp->done = 1;
					--dispatched;
				}
			}

			/* wait a little longer next time */
			if (howlong < 10)
				++howlong;
		}
	}

	/* cleanup, return success */
	free_units(mirrors);
	(void) meta_unlock(sp, &mde);
	md_exit(sp, 0);
	/*NOTREACHED*/
	return (NULL);
}

/*
 * meta_mirror_resync_process:
 * --------------------------
 * Modify any resync that is in progress on this node for the given set.
 *
 * Input Parameters:
 *	sp	setname to scan for mirrors
 *	cmd	action to take:
 *		MD_RESYNC_KILL	- kill all resync threads
 *		MD_RESYNC_BLOCK	- block all resync threads
 *		MD_RESYNC_UNBLOCK - resume all resync threads
 * Output Parameters
 *	ep	error return structure
 *
 * meta_lock for this set should be held on entry.
 */
static void
meta_mirror_resync_process(mdsetname_t *sp, md_error_t *ep, md_resync_cmd_t cmd)
{
	mm_unit_list_t	*mirrors[MD_PASS_MAX + 1];
	mm_pass_num_t	pass;

	/* Grab all the mirrors from the set (if any) */
	(void) memset(mirrors, 0, sizeof (mirrors));
	if (setup_units(sp, mirrors, ep) != 0)
		return;

	/* do passes */
	for (pass = 1; (pass <= MD_PASS_MAX); ++pass) {
		mm_unit_list_t		*lp;

		/* skip empty passes */
		if (mirrors[pass] == NULL)
			continue;

		/* Process all resyncs in pass */
		for (lp = mirrors[pass]; (lp != NULL); lp = lp->next) {
			(void) meta_mirror_resync(sp, lp->namep, 0, ep,
			    cmd);
		}
	}

	/* Clear up mirror units */
	free_units(mirrors);
}

/*
 * meta_mirror_resync_process_all:
 * ------------------------------
 * Issue the given resync command to all mirrors contained in all multi-node
 * sets.
 *
 * Input Parameters:
 *	cmd	- MD_RESYNC_KILL, MD_RESYNC_BLOCK, MD_RESYNC_UNBLOCK
 */
static void
meta_mirror_resync_process_all(md_resync_cmd_t cmd)
{
	set_t		setno, max_sets;
	md_error_t	mde = mdnullerror;
	mdsetname_t	*this_sp;
	md_set_desc	*sd;

	/*
	 * Traverse all sets looking for multi-node capable ones.
	 */
	max_sets = get_max_sets(&mde);
	for (setno = 1; setno < max_sets; setno++) {
		mde = mdnullerror;
		if (this_sp = metasetnosetname(setno, &mde)) {
			if ((sd = metaget_setdesc(this_sp, &mde)) == NULL)
				continue;
			if (!MD_MNSET_DESC(sd))
				continue;

			if (meta_lock(this_sp, TRUE, &mde)) {
				continue;
			}
			meta_mirror_resync_process(this_sp, &mde, cmd);
			(void) meta_unlock(this_sp, &mde);
		}
	}
}

/*
 * meta_mirror_resync_kill_all:
 * ---------------------------
 * Abort any resync that is in progress on this node. Scan all sets for all
 * mirrors.
 * Note: this routine is provided for future use. For example to kill all
 *	 resyncs on a node this could be used as long as the
 *	 mddoors / rpc.mdcommd tuple is running on all members of the cluster.
 */
void
meta_mirror_resync_kill_all(void)
{
	meta_mirror_resync_process_all(MD_RESYNC_KILL);
}

/*
 * meta_mirror_resync_block_all:
 * ----------------------------
 * Block all resyncs that are in progress. This causes the resync state to
 * freeze on this machine, and can be resumed by calling
 * meta_mirror_resync_unblock_all.
 */
void
meta_mirror_resync_block_all(void)
{
	meta_mirror_resync_process_all(MD_RESYNC_BLOCK);
}

/*
 * meta_mirror_resync_unblock_all:
 * ------------------------------
 * Unblock all previously blocked resync threads on this node.
 */
void
meta_mirror_resync_unblock_all(void)
{
	meta_mirror_resync_process_all(MD_RESYNC_UNBLOCK);
}

/*
 * meta_mirror_resync_unblock:
 * --------------------------
 * Unblock any previously blocked resync threads for the given set.
 * meta_lock for this set should be held on entry.
 */
void
meta_mirror_resync_unblock(mdsetname_t *sp)
{
	md_error_t	mde = mdnullerror;

	meta_mirror_resync_process(sp, &mde, MD_RESYNC_UNBLOCK);
}

/*
 * meta_mirror_resync_kill:
 * -----------------------
 * Kill any resync threads running on mirrors in the given set.
 * Called when releasing a set (meta_set_prv.c`halt_set)
 */
void
meta_mirror_resync_kill(mdsetname_t *sp)
{
	md_error_t	mde = mdnullerror;

	meta_mirror_resync_process(sp, &mde, MD_RESYNC_KILL);
}
