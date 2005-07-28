/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * change the identity of a metadevice
 * These are the "do it" functions for the metarename command.
 */

#include <string.h>
#include <meta.h>
#include <sys/lvm/md_rename.h>

/* private */
#define	FORCE	(0x00000001)
#define	NOISY	(0x00000010)
#define	NOFLIP	(0x00000020)
#define	DRYRUN	(0x00000040)

#define	OP_STR(op)						\
	((op) == MDRNOP_EXCHANGE?	"exchange":		\
	    (op) == MDRNOP_RENAME?	"rename":		\
	    (op) == MDRNOP_UNK?		"<unknown>": "garbage")


/*
 * Check if from_np is open
 * Return 0 if not open, -1 if open
 */
static int
check_open(
	mdsetname_t	*sp,
	mdname_t	*from_np,
	md_error_t	*ep)
{
	int		rc;

	if ((rc = meta_isopen(sp, from_np, ep, (mdcmdopts_t)0)) < 0) {
		assert(!mdisok(ep));
		return (-1);

	} else if (rc > 0) {
		if (mdisok(ep)) {
			(void) mdmderror(ep, MDE_RENAME_BUSY,
				meta_getminor(from_np->dev),
				from_np->cname);
		}
		return (-1);
	}
	return (0);
}

/*
 * meta_swap is the common code used by the
 * meta_rename() and meta_exchange() entry points
 */

static int
meta_swap(
	mdsetname_t	*sp,
	mdname_t	*from_np,
	md_common_t	*from_mdp,
	mdname_t	*to_np,
	md_common_t	*to_mdp,
	md_renop_t	op,
	int		flags,
	md_error_t	*ep)
{
	md_rename_t	txn;
	int		from_add_flag = 0;
	int		to_add_flag = 0;

	/*
	 * If the device exists a key may already exist so need to find it
	 * otherwise we'll end up adding the key in again which will lead
	 * to an inconsistent n_count for the namespace record.
	 */
	if (from_np->dev != NODEV) {
		(void) meta_getnmentbydev(sp->setno, MD_SIDEWILD, from_np->dev,
		    NULL, NULL, &from_np->key, ep);
	}

	if (to_np->dev != NODEV) {
		(void) meta_getnmentbydev(sp->setno, MD_SIDEWILD, to_np->dev,
		    NULL, NULL, &to_np->key, ep);
	}

	if ((from_np->key == MD_KEYWILD) || (from_np->key == MD_KEYBAD)) {
		/*
		 * If from does not have key and it is a component device
		 * then something really goes wrong
		 */
		assert(!MD_HAS_PARENT(from_mdp->parent));

		/*
		 * So only add the entry if from is a top device
		 */
		if (add_key_name(sp, from_np, NULL, ep) != 0) {
			assert(!mdisok(ep));
			return (-1);
		} else {
			from_add_flag = 1;
		}
	}

	(void) memset(&txn, 0, sizeof (txn));

	txn.op		= op;
	txn.revision	= MD_RENAME_VERSION;
	txn.flags	= 0;
	txn.from.mnum	= meta_getminor(from_np->dev);
	txn.from.key	= from_np->key;

	if ((to_np->key == MD_KEYWILD) || (to_np->key == MD_KEYBAD)) {
		/*
		 * If to does not have key and is not a top device
		 * then something really goes wrong
		 */
		assert(!MD_HAS_PARENT(to_mdp->parent));

		/*
		 * Add entry
		 */
		if (add_key_name(sp, to_np, NULL, ep) != 0) {
			assert(!mdisok(ep));
			if (from_add_flag)
				(void) del_key_name(sp, from_np, ep);
			return (-1);
		} else {
			to_add_flag = 1;
		}
	}

	txn.to.mnum	= meta_getminor(to_np->dev);
	txn.to.key	= to_np->key;

	if (flags & NOISY) {
		(void) fprintf(stderr, "\top: %s\n", OP_STR(txn.op));
		(void) fprintf(stderr, "\trevision: %d, flags: %d\n",
				txn.revision, txn.flags);
		(void) fprintf(stderr,
				"\tfrom(mnum,key): %ld, %d\tto: %ld, %d\n",
				txn.from.mnum, txn.from.key,
				txn.to.mnum, txn.to.key);
	}

	mdclrerror(ep);
	if (metaioctl(MD_IOCRENAME, &txn, &txn.mde, from_np->cname) != 0) {
		if (from_add_flag) {
			(void) del_key_name(sp, from_np, ep);
		}

		if (op == MDRNOP_RENAME || to_add_flag) {
			(void) del_key_name(sp, to_np, ep);
		}
		return (mdstealerror(ep, &txn.mde));
	}

	/*
	 * If top device
	 */
	if (op == MDRNOP_RENAME && !MD_HAS_PARENT(from_mdp->parent)) {
		(void) del_key_name(sp, to_np, ep);
	}

	/* force the name cache to re-read device state */
	meta_invalidate_name(from_np);
	meta_invalidate_name(to_np);

	return (0);
}

/*
 * rename a metadevice
 */
int
meta_rename(
	mdsetname_t	*sp,
	mdname_t	*from_np,
	mdname_t	*to_np,
	mdcmdopts_t	 options,
	md_error_t	*ep
)
{
	int		 flags		= (options & MDCMD_FORCE)? FORCE: 0;
	int		 rc		= 0;
	mdcinfo_t	*cinfop;
	char		*p;
	md_set_desc	*sd;
	mdkey_t		 side_key = MD_KEYWILD;
	md_error_t	 dummy_ep = mdnullerror;
	int		 i, j;
	md_mnnode_desc	*nd, *nd_del;
	md_common_t	*from_mdp;

	/* must have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(from_np->dev)));

	mdclrerror(ep);

	if (((p = getenv("MD_DEBUG")) != NULL) &&
	    (strstr(p, "RENAME") != NULL)) {
		flags |= NOISY;
	}
	/* if DOIT is not set, we are in dryrun mode */
	if ((options & MDCMD_DOIT) == 0) {
		flags |= DRYRUN;
	}


	if (metachkmeta(from_np, ep) != 0) {
		assert(!mdisok(ep));
		return (-1);
	}

	mdclrerror(ep);

	if ((from_mdp = meta_get_unit(sp, from_np, ep)) == NULL) {
		assert(!mdisok(ep));
		return (-1);
	}

	if (meta_get_unit(sp, to_np, ep) != NULL) {
		if (mdisok(ep)) {
			(void) mdmderror(ep, MDE_UNIT_ALREADY_SETUP,
					meta_getminor(to_np->dev),
					to_np->cname);
		}
		return (-1);
	}
	mdclrerror(ep);

	/* If FORCE is not set, check if metadevice is open */
	if (!(flags & FORCE)) {
		if (check_open(sp, from_np, ep) != 0) {
			return (-1);
		}
	}

	/*
	 * All checks are done, now we do the real work.
	 * If we are in dryrun mode, we're done.
	 */
	if (flags & DRYRUN) {
		return (0); /* success */
	}

	/*
	 * add key for new name to the namespace
	 */
	if ((cinfop = metagetcinfo(from_np, ep)) == NULL) {
		assert(!mdisok(ep));
		return (-1);
	}

	if (metaislocalset(sp)) {
		to_np->key = add_name(sp, MD_SIDEWILD, MD_KEYWILD,
		    cinfop->dname, meta_getminor(to_np->dev), to_np->bname, ep);
	} else {
		/*
		 * As this is not the local set we have to create a namespace
		 * record for each side (host) in the set. We cannot use
		 * add_key_names() because the destination device (to_np)
		 * should not exist and so the subsequent metagetcinfo()
		 * call will fail when it tries to open the device, so we
		 * have to use the information from the source device (from_np)
		 */
		if ((sd = metaget_setdesc(sp, ep)) == (md_set_desc *)NULL) {
			return (-1);
		}
		to_np->key = MD_KEYWILD;

		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			while (nd) {
				side_key = add_name(sp, (side_t)nd->nd_nodeid,
				    to_np->key, cinfop->dname,
				    meta_getminor(to_np->dev),
				    to_np->bname, ep);
				/*
				 * Break out if failed to add the key,
				 * but delete any name space records that
				 * were added.
				 */
				if (side_key == MD_KEYBAD ||
				    side_key == MD_KEYWILD) {
					/*
					 * If we have a valid to_np->key then
					 * a record was added correctly but
					 * we do not know for which side, so
					 * we need to try to delete all of them.
					 */

					if (to_np->key != MD_KEYBAD &&
					    to_np->key != MD_KEYWILD) {
						nd_del = sd->sd_nodelist;
						while ((nd_del != nd) &&
						(nd_del != NULL)) {
						    (void) del_name(sp,
						    (side_t)nd_del->nd_nodeid,
						    to_np->key, &dummy_ep);
						    nd_del = nd_del->nd_next;
						}
						/* preserve error key state */
						to_np->key = side_key;
					}
					break;
				}
				to_np->key = side_key;
				nd = nd->nd_next;
			}
		} else {
			for (i = 0; i < MD_MAXSIDES; i++) {
				if (sd->sd_nodes[i][0] != '\0') {
					side_key = add_name(sp, (side_t)i,
					    to_np->key, cinfop->dname,
					    meta_getminor(to_np->dev),
					    to_np->bname, ep);
					/*
					 * Break out if failed to add the key,
					 * but delete any name space records
					 * that were added.
					 */
					if (side_key == MD_KEYBAD ||
					    side_key == MD_KEYWILD) {
						/*
						 * If we have a valid
						 * to_np->key then a record was
						 * added correctly but we do
						 * not know for which side, so
						 * we need to try to delete
						 * all of them.
						 */
						if (to_np->key != MD_KEYBAD &&
						    to_np->key != MD_KEYWILD) {
							for (j = 0; j < i;
							    j++) {
							    (void) del_name(sp,
							    (side_t)j,
							    to_np->key,
							    &dummy_ep);
							}
							/*
							 * preserve err
							 * key state
							 */
							to_np->key = side_key;
						}
						break;
					}
					to_np->key = side_key;
				}
			}
		}
	}

	if (to_np->key == MD_KEYBAD || to_np->key == MD_KEYWILD) {
		assert(!mdisok(ep));
		return (-1);
	}

	rc = meta_swap(sp, from_np, from_mdp, to_np, NULL, MDRNOP_RENAME,
		flags, ep);

	if (rc == 0) {
		if (options & MDCMD_PRINT) {
			(void) fprintf(stdout, dgettext(TEXT_DOMAIN,
				"%s: has been renamed to %s\n"),
				from_np->cname, to_np->cname);
		}
	}

	return (rc);
}

/*
 * return TRUE if current <from>, <to> ordering would
 * prevent <from> from being in the role of <self>
 */
static bool_t
meta_exchange_need_to_flip(
	md_common_t	*from_mdp,
	md_common_t	*to_mdp
)
{
	assert(from_mdp);
	assert(to_mdp);

	/*
	 * ?
	 *  \
	 * <to>
	 *    \
	 *    <from>
	 */

	if (MD_HAS_PARENT(from_mdp->parent)) {
		if (MD_HAS_PARENT(to_mdp->parent)) {
			if (from_mdp->parent ==
				meta_getminor(to_mdp->namep->dev)) {
				return (TRUE);
			}
		}
	}

	/*
	 * <from>
	 *    \
	 *    <to>
	 *      \
	 *	 ?
	 */

	if (MD_HAS_PARENT(to_mdp->parent)) {
		if (to_mdp->capabilities & MD_CAN_META_CHILD) {
			return (TRUE);
		}
	}

	/*
	 * <to>
	 *   \
	 *  <from>
	 */

	if (MD_HAS_PARENT(from_mdp->parent)) {
		if (from_mdp->parent == meta_getminor(to_mdp->namep->dev)) {
			if (!(from_mdp->capabilities & MD_CAN_META_CHILD)) {
				return (TRUE);
			}
		}
	}

	/*
	 * <from>	or	<to>
	 *   \			  \
	 *  <to>		<from>
	 *			    \
	 *			    ?
	 */

	return (FALSE);
}

/*
 * exchange the names of two metadevices
 */
int
meta_exchange(
	mdsetname_t	*sp,
	mdname_t	*from_np,
	mdname_t	*to_np,
	mdcmdopts_t	 options,
	md_error_t	*ep
)
{
	int		 flags	= (options & MDCMD_FORCE)? FORCE: 0;
	md_common_t	*from_mdp, *to_mdp;
	int		 rc;
	char		*p, *p2;

	/* must have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(from_np->dev)));
	assert(sp->setno == MD_MIN2SET(meta_getminor(to_np->dev)));

	if (metachkmeta(from_np, ep) != 0) {
		assert(!mdisok(ep));
		return (-1);
	}

	if (metachkmeta(to_np, ep) != 0) {
		assert(!mdisok(ep));
		return (-1);
	}

	if ((options & MDCMD_DOIT) == 0) {
		flags |= DRYRUN;
	}

	if ((p = getenv("MD_DEBUG")) != NULL) {
		if ((p2 = strstr(p, "EXCHANGE=")) != NULL) {
			flags |= NOISY;
			if ((p2 = strchr(p2, '=')) != NULL) {
				if (strcmp((p2+1), "NOFLIP") == 0) {
					flags |= NOFLIP;
				}
			}
		} else if (strstr(p, "EXCHANGE") != NULL) {
			flags |= NOISY;
		}
	}

	if ((from_mdp = meta_get_unit(sp, from_np, ep)) == NULL) {
		assert(!mdisok(ep));
		return (-1);
	}

	if ((to_mdp = meta_get_unit(sp, to_np, ep)) == NULL) {
		assert(!mdisok(ep));
		return (-1);
	}
	assert(mdisok(ep));


	/* If FORCE is not set, check if metadevice is open */
	if (!(flags & FORCE)) {
		if (check_open(sp, from_np, ep) != 0) {
			return (-1);
		}
	}

	/*
	 * All checks are done, now we do the real work.
	 * If we are in dryrun mode, we're done.
	 */
	if (flags & DRYRUN) {
		return (0); /* success */
	}

	/*
	 * NOFLIP is used only for debugging; the driver
	 * will catch this and return MDE_RENAME_ORDER, if necessary
	 */
	if (((flags & NOFLIP) == 0) &&
	    meta_exchange_need_to_flip(from_mdp, to_mdp)) {
		rc = meta_swap(sp, to_np, to_mdp, from_np, from_mdp,
			MDRNOP_EXCHANGE, flags, ep);

	} else {
		rc = meta_swap(sp, from_np, from_mdp, to_np, to_mdp,
			MDRNOP_EXCHANGE, flags, ep);
	}

	if (rc == 0) {
		if (options & MDCMD_PRINT) {
			(void) fprintf(stdout, dgettext(TEXT_DOMAIN,
				"%s and %s have exchanged identities\n"),
				from_np->cname, to_np->cname);
		}
	}

	return (rc);
}
