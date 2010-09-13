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
	int		from_is_fn, to_is_fn;
	bool_t		from_has_parent, to_has_parent;

	/*
	 * What types of devices we have here?
	 * For MDRNOP_RENAME to_mdp is NULL
	 */
	from_is_fn = (from_mdp->revision & MD_FN_META_DEV);
	from_has_parent = MD_HAS_PARENT(from_mdp->parent);
	if (to_mdp) {
		to_is_fn = (to_mdp->revision & MD_FN_META_DEV);
		to_has_parent = MD_HAS_PARENT(to_mdp->parent);
	}

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
		 * If we are top and revision indicates that we
		 * should have key but we don't then something
		 * really goes wrong
		 */
		assert(!from_has_parent && !from_is_fn);

		if (from_has_parent || from_is_fn) {
			return (-1);
		}

		/*
		 * So only add the entry if necessary
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
		 * If we are top and revision indicates that we
		 * should have key but we don't then something
		 * really goes wrong
		 */
		assert(!to_has_parent && !to_is_fn);

		if (to_has_parent || to_is_fn) {
			return (-1);
		}

		/*
		 * So only add the entry if necessary
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
			/*
			 * Attempt removal of device node
			 */
			(void) metaioctl(MD_IOCREM_DEV, &txn.from.mnum,
				ep, NULL);
		}

		if (op == MDRNOP_RENAME || to_add_flag) {
			(void) del_key_name(sp, to_np, ep);
			/*
			 * Attempt removal of device node
			 */
			(void) metaioctl(MD_IOCREM_DEV, &txn.to.mnum,
				ep, NULL);
		}

		return (mdstealerror(ep, &txn.mde));
	}

	/*
	 * Since now the metadevice can be ref'd in the namespace
	 * by self and by the top device so upon the successful
	 * rename/xchange, we need to check the type and make
	 * necessary adjustment for the device's n_cnt in the namespace
	 * by calling add_key_name/del_key_name to do the tricks
	 */
	if (op == MDRNOP_RENAME && from_has_parent) {
		(void) add_key_name(sp, to_np, NULL, ep);
		if (from_is_fn)
			(void) del_self_name(sp, from_np->key, ep);
	}

	if (op == MDRNOP_EXCHANGE && from_is_fn) {
		(void) add_key_name(sp, from_np, NULL, ep);
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
	char		*p;
	md_common_t	*from_mdp;
	minor_t		to_minor = meta_getminor(to_np->dev);
	md_error_t	status = mdnullerror;
	md_error_t	*t_ep = &status;

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

	/*
	 * The dest device name has been added early on
	 * by meta_init_make_device call so get the entry from
	 * the namespace
	 */
	if (meta_getnmentbydev(sp->setno, MD_SIDEWILD, to_np->dev,
	    NULL, NULL, &to_np->key, ep) == NULL) {
		return (-1);
	}

	/* If FORCE is not set, check if metadevice is open */
	if (!(flags & FORCE)) {
	    if (check_open(sp, from_np, ep) != 0) {
		(void) del_key_name(sp, to_np, t_ep);
		(void) metaioctl(MD_IOCREM_DEV, &to_minor, t_ep, NULL);
		return (-1);
	    }
	}

	/*
	 * All checks are done, now we do the real work.
	 * If we are in dryrun mode, clear the deivce node
	 * and we are done.
	 */
	if (flags & DRYRUN) {
		(void) del_key_name(sp, to_np, t_ep);
		(void) metaioctl(MD_IOCREM_DEV, &to_minor, t_ep, NULL);
		return (0); /* success */
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
