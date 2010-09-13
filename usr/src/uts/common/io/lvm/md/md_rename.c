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
 * rename or exchange identities of virtual device nodes
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_rename.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

extern	major_t		md_major;
extern	unit_t		md_nunits;
extern	set_t		md_nsets;
extern	md_set_t	md_set[];

#define	ROLE(r)						\
	((r) == MDRR_PARENT?	"parent":		\
	(r) == MDRR_SELF?	"self":			\
	(r) == MDRR_CHILD?	"child":		\
	(r) == MDRR_UNK?	"<unknown>": "<garbage>")

#define	OP_STR(op)							\
		(((op) == MDRNOP_UNK)?		"<unknown>"	:	\
		    ((op) == MDRNOP_RENAME)?	"rename"	:	\
		    ((op) == MDRNOP_EXCHANGE)?	"exchange"	:	\
						"<garbage>")
int md_rename_debug = 0;

/* delta guard rails */
const unsigned long long	DELTA_BEG	= (0xDad08888a110beefull);
const unsigned long long	DELTA_END	= (0xa110Beef88880Dadull);

const unsigned long long	DELTA_BEG_FREED	= (0xBad0c0ed0fed0dadull);
const unsigned long long	DELTA_END_FREED	= (0x0Fed0dadbad0c0edull);

/* transaction guard rails */
const unsigned long long	TXN_BEG		= (0xDad01eadc0ed2badull);
const unsigned long long	TXN_END		= (0xc0ed2badDad01eadull);

const unsigned long long	TXNUN_BEG	= (0xcafe0fedbad0beefull);
const unsigned long long	TXNUN_END	= (0xbad0beefcafe0fedull);

const unsigned int		guard_shift	= (sizeof (u_longlong_t) - 3);
const md_stackcap_t		MD_CAN_DO_ANYTHING	= (md_stackcap_t)0;

typedef struct role_change_mapping_tab_t {
	const int			ord;
	const md_renrole_t		old_role;
	const md_renrole_t		new_role;
	const char			*svc_name;
	md_ren_roleswap_svc_t * const	default_svc;
} role_change_tab_t;

/*
 *  The actual table is at the end of the file, so we don't need
 *  many forward references
 */
static	role_change_tab_t	role_swap_tab[];

#define	ILLEGAL_ROLESWAP_SVC	((md_ren_roleswap_svc_t *)(0xA1100BAD))
#define	NO_DEFAULT_ROLESWAP_SVC	((md_ren_roleswap_svc_t *)(NULL))
#define	ILLEGAL_SVC_NAME	(NULL)

/*
 *
 * Role swap rule table:
 *
 *                                New Role
 *      +---------------------------------------------------------------|
 *      |        |    Parent       |       Self     |      Child        |
 *      +--------+-----------------+----------------+-------------------+
 *      | Parent | no default      | ...no default  | illegal	        |
 *      |        | 1 (update kids) | 2  (update to) | 3	                |
 * Old  +--------+-----------------+----------------+-------------------+
 * Role | Self   | ...self update  | ...rename self | no default (down  |
 *      |        | 4   update up | 5	            | 6    update from) |
 *      +--------+-----------------+----------------+-------------------+
 *      | Child  | illegal         | ...child       | ...update         |
 *      |        | 7	           | 8   update to  | 9	parent          |
 *      +---------------------------------------------------------------+
 *
 * and notes:
 *
 * - Boxes 1, 4 and 6 are the most interesting. They are responsible
 *   for updating the from unit's data structures. These may involve
 *   finding (former or future) children, resetting name keys and the like.
 *
 * - The "rename" operation is boxes 1, 5 and 9. Most of the work
 *   is done in box 5, since that contains both the "from" and "to"
 *   unit struct for rename.
 *
 *  (There's got to be an eigen function for this; that diagonal
 *   axis is a role identity operation searching for an expression.)
 *
 * - Almost every transaction will call more than one of these.
 *   (Only a rename of a unit with no relatives will only call
 *   a single box.)
 *
 * - Box 4 "...update from" is the generic self->parent modifier.
 * - Box 8 "...update to" is the generic child->self modifier.
 *   These can be generic because all of the information which
 *   needs to be updated is in the common portion of the unit
 *   structure when changing from their respective roles.
 *
 * - Boxes 1, 2 and 6 ("no default") indicate that per-metadevice
 *   information must be updated. For example, in box 1, children
 *   identities must be updated. Since different metadevice types
 *   detect and manipulate their children differently, there can
 *   be no generic "md_rename" function in this box.
 *
 * In addition to the named services in the table above, there
 * are other named services used by rename/exchange.
 * MDRNM_LIST_URFOLKS, MDRNM_LIST_URSELF, MDRNM_LIST_URKIDS
 * list a device's parents, self and children, respectively.
 * In most cases the default functions can be used for parents
 * and self. Top-level devices, are not required to have a
 * "list folks" named service. Likewise, devices which can
 * not have metadevice children, are not required to have the
 * "list kids" named service. The LIST_UR* functions call back into
 * the base driver (md_build_rendelta()) to package the changes to
 * a device for addition onto the tree. The LIST_UR* named service
 * then adds this "rename delta" onto the delta tree itself.
 * This keeps private knowledge appropriately encapsulated.
 * They return the number of devices which will need to be changed,
 * and hence the number of elements they've added to the delta list
 * or -1 for error.
 *
 * Other named services used by rename/exchange are:
 * "lock" (MDRNM_LOCK), "unlock" (MDRNM_UNLOCK) and "check" (MDRNM_CHECK).
 * These (un) write-lock all of the relevant in-core structs,
 * including the unit structs for the device and quiesce i/o as necessary.
 * The "check" named service verifies that this device
 * is in a state where rename could and may occur at this time.
 * Since the role_swap functions themselves cannot be undone
 * (at least in this implementation), it is check()'s job to
 * verify that the device is renamable (sic) or, if not, abort.
 * The check function for the device participating in the role
 * of "self" is usually where rename or exchange validity is verified.
 *
 * All of these functions take two arguments which may be thought
 * of as the collective state changes of the tree of devices
 * (md_rendelta_t *family) and the rename transaction state
 * (md_rentxn_t rtxn or rtxnp).
 *
 */


/*
 * rename unit lock
 * (default name service routine MDRNM_LOCK)
 */
static intptr_t
md_rename_lock(md_rendelta_t *delta, md_rentxn_t *rtxnp)
{
	minor_t		 mnum;
	md_renop_t	 op;

	ASSERT(delta);
	ASSERT(rtxnp);

	if (!delta || !rtxnp) {
		(void) mdsyserror(&rtxnp->mde, EINVAL);
		return (EINVAL);
	}
	mnum = md_getminor(delta->dev);
	op = rtxnp->op;

	/*
	 * target doesn't exist if renaming (by definition),
	 * so it need not be locked
	 */
	if (op == MDRNOP_RENAME && mnum == rtxnp->to.mnum) {
		return (0);
	}

	ASSERT(delta->uip);
	if (!delta->uip) {
		(void) mdmderror(&rtxnp->mde, MDE_UNIT_NOT_SETUP, mnum);
		return (ENODEV);
	}

	ASSERT(delta->unp);
	if (!delta->unp) {
		(void) mdmderror(&rtxnp->mde, MDE_UNIT_NOT_SETUP, mnum);
		return (ENODEV);
	}

	ASSERT(!UNIT_WRITER_HELD(delta->unp));

	(void) md_unit_writerlock(delta->uip);

	ASSERT(UNIT_WRITER_HELD(delta->unp));

	return (0);
}

/*
 * (default name service routine MDRNM_UNLOCK)
 */
/* ARGSUSED */
static void
md_rename_unlock(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	ASSERT(delta);
	ASSERT(delta->uip);
	ASSERT(delta->unp);

	ASSERT(UNIT_WRITER_HELD(delta->unp));

	(void) md_unit_writerexit(delta->uip);

	ASSERT(!UNIT_WRITER_HELD(delta->unp));
}

/*
 * This is used by the various MDRNM_LIST* named services.
 */
md_rendelta_t *
md_build_rendelta(
	md_renrole_t	 old_role,
	md_renrole_t	 new_role,
	md_dev64_t	 dev,
	md_rendelta_t	*prev,
	md_unit_t	*unp,
	mdi_unit_t	*uip,
	md_error_t	*ep)
{
	int		 err	= 0;
	md_rendelta_t	*new;

	new = (md_rendelta_t *)kmem_alloc(sizeof (md_rendelta_t), KM_SLEEP);

	new->beginning	= DELTA_BEG;
	new->dev	= dev;
	new->new_role	= new_role;
	new->old_role	= old_role;
	new->next	= NULL;
	new->prev	= prev;
	new->unp = unp;
	new->uip = uip;
	bzero((void *) &new->txn_stat, sizeof (md_rendstat_t));

	/*
	 * For non-meta devices that are being renamed (in the future,
	 * that is) we would need to pass in default functions to
	 * accommodate them, provided the default function is
	 * truly capable of performing the lock/check/unlock function
	 * on opaque devices.
	 */

	new->lock	= md_get_named_service(dev, /* modindex */ 0,
						MDRNM_LOCK, md_rename_lock);

	new->unlock	= (md_ren_void_svc_t *)md_get_named_service(dev,
					/* modindex */ 0, MDRNM_UNLOCK,
					(intptr_t (*)()) md_rename_unlock);

	new->check	= md_get_named_service(dev, /* modindex */ 0,
					    MDRNM_CHECK, /* Default */ NULL);

	new->role_swap	= NULL;	/* set this when the roles are determined */

	if (!new->lock || !new->unlock || !new->check) {
		(void) mdmderror(ep, MDE_RENAME_CONFIG_ERROR, md_getminor(dev));
		err = EINVAL;
		goto out;
	}

	new->end = DELTA_END;

out:
	if (err != 0) {
		if (new) {
			new->beginning	= DELTA_BEG_FREED;
			new->end	= DELTA_END_FREED;

			kmem_free(new, sizeof (md_rendelta_t));
			new = NULL;
		}
	}

	if (prev) {
		prev->next = new;
	}

	return (new);
}

/*
 * md_store_recid()
 * used by role swap functions
 */
void
md_store_recid(
	int		*prec_idx,
	mddb_recid_t	*recid_list,
	md_unit_t	*un)
{
	mddb_recid_t	*rp;
	bool_t		 add_recid;

	ASSERT(prec_idx);
	ASSERT(recid_list);
	ASSERT(recid_list[*prec_idx] == 0);
	ASSERT(*prec_idx >= 0);

	for (add_recid = TRUE, rp = recid_list; add_recid && rp && *rp; rp++) {
		if (MD_RECID(un) == *rp) {
			add_recid = FALSE;
		}
	}

	if (add_recid) {
		recid_list[(*prec_idx)++] = MD_RECID(un);
	}
}

/*
 * MDRNM_LIST_URFOLKS: generic named svc entry point
 * add all parents onto the list pointed to by dlpp
 * (only weird multi-parented devices need to have their
 * own named svc  to do this.)
 */
static int
md_rename_listfolks(md_rendelta_t **dlpp, md_rentxn_t *rtxnp)
{
	md_rendelta_t	*new;

	ASSERT(rtxnp);
	ASSERT(dlpp);
	ASSERT(*dlpp == NULL);
	ASSERT((rtxnp->op == MDRNOP_EXCHANGE) || (rtxnp->op == MDRNOP_RENAME));
	ASSERT(rtxnp->from.uip);
	ASSERT(rtxnp->from.unp);

	if ((!rtxnp->from.uip) || (!rtxnp->from.unp)) {
		(void) mdmderror(&rtxnp->mde, MDE_UNIT_NOT_SETUP,
							rtxnp->from.mnum);
		return (-1);
	}

	if (!MD_HAS_PARENT(MD_PARENT(rtxnp->from.unp))) {
		return (0);
	}

	/*
	 * If supporting log renaming (and other multiparented devices)
	 * callout to each misc module to claim this waif and return the
	 * md_dev64_t of its parents.
	 */
	if (MD_PARENT(rtxnp->from.unp) == MD_MULTI_PARENT) {
		(void) mdmderror(&rtxnp->mde, MDE_RENAME_SOURCE_BAD,
							rtxnp->from.mnum);
		return (2);
	}

	if ((rtxnp->op == MDRNOP_RENAME) ||
	    (MD_PARENT(rtxnp->from.unp) != MD_SID(rtxnp->to.unp))) {

		new = md_build_rendelta(
			    MDRR_PARENT,
			    MDRR_PARENT,
			    md_makedevice(md_major, MD_PARENT(rtxnp->from.unp)),
			    NULL,
			    MD_UNIT(MD_PARENT(rtxnp->from.unp)),
			    MDI_UNIT(MD_PARENT(rtxnp->from.unp)),
			    &rtxnp->mde);
	} else {
		/* parent is swapping roles with self */
		new = md_build_rendelta(
			    MDRR_PARENT,
			    MDRR_SELF,
			    md_makedevice(md_major, MD_SID(rtxnp->to.unp)),
			    NULL,
			    rtxnp->to.unp,
			    rtxnp->to.uip,
			    &rtxnp->mde);
	}

	if (!new) {
		if (mdisok(&rtxnp->mde)) {
			(void) mdsyserror(&rtxnp->mde, ENOMEM);
		}
		return (-1);
	}

	*dlpp = new;

	return (1);
}

/*
 * MDRNM_LIST_URSELF: named svc entry point
 * add all delta entries appropriate for ourselves onto the deltalist pointed
 * to by dlpp
 */
static int
md_rename_listself(md_rendelta_t **dlpp, md_rentxn_t *rtxnp)
{
	md_rendelta_t	*new, *p;
	bool_t		 exchange_up	= FALSE;

	ASSERT(rtxnp);
	ASSERT(dlpp);
	ASSERT((rtxnp->op == MDRNOP_EXCHANGE) || (rtxnp->op == MDRNOP_RENAME));
	ASSERT(rtxnp->from.unp);
	ASSERT(rtxnp->from.uip);

	if ((!rtxnp->from.uip) || (!rtxnp->from.unp)) {
		(void) mdmderror(&rtxnp->mde, MDE_UNIT_NOT_SETUP,
							rtxnp->from.mnum);
		return (-1);
	}

	for (p = *dlpp; p && p->next != NULL; p = p->next) {
		/* NULL */
	}

	/*
	 * renaming or
	 * from's parent is not to and to's parent is not from
	 */
	if (rtxnp->op == MDRNOP_RENAME) {
		new = md_build_rendelta(
				MDRR_SELF,
				MDRR_SELF,
				md_makedevice(md_major, rtxnp->from.mnum),
				p,
				rtxnp->from.unp,
				rtxnp->from.uip,
				&rtxnp->mde);
	} else {

		if (MD_PARENT(rtxnp->from.unp) == MD_SID(rtxnp->to.unp)) {
			exchange_up = TRUE;
		}

		/* self and parent are flipping */
		new = md_build_rendelta(
				MDRR_SELF,
				exchange_up? MDRR_PARENT: MDRR_CHILD,
				md_makedevice(md_major, rtxnp->from.mnum),
				p,
				rtxnp->from.unp,
				rtxnp->from.uip,
				&rtxnp->mde);
	}

	if (!new) {
		if (mdisok(&rtxnp->mde)) {
			(void) mdsyserror(&rtxnp->mde, ENOMEM);
		}
		return (-1);
	}

	if (!*dlpp) {
		*dlpp = new;
	}

	return (1);
}

/*
 * free the tree of all deltas to devices involved in the rename transaction
 */
static void
free_dtree(md_rendelta_t *family)
{
	md_rendelta_t	*next		= NULL;
	int		 i		= 0;
	md_rendelta_t	*r;

	for (r = family; (NULL != r); r = next, i++) {

		next		= r->next;

		/* shift << because it makes the resultant pattern readable */
		r->beginning	= DELTA_BEG_FREED ^ (i << guard_shift);
		r->end		= DELTA_END_FREED ^ (i << guard_shift);

		kmem_free(r, sizeof (md_rendelta_t));
	}
}

/*
 * walk down family tree, calling lock service function
 */
static int
lock_dtree(md_rendelta_t *family, md_rentxn_t *rtxnp)
{
	md_rendelta_t	*r;
	int		 rc;

	ASSERT(family);
	ASSERT(rtxnp);

	if (!family || !rtxnp) {
		return (EINVAL);
	}

	for (rc = 0, r = family; r; r = r->next) {

		ASSERT(r->unp);
		ASSERT(!UNIT_WRITER_HELD(r->unp));
		ASSERT(r->lock);

		if ((rc = (int)(*r->lock) (r, rtxnp)) != 0) {
			return (rc);
		}
		r->txn_stat.locked = TRUE;
	}

	return (0);
}

/*
 * We rely on check() (MDRNM_CHECK) to make exhaustive checks,
 * since we don't attempt to undo role_swap() failures.
 *
 * To implement an undo() function would require each role_swap()
 * to store a log of previous state of the structures it changes,
 * presumably anchored by the rendelta.
 *
 */
static int
check_dtree(md_rendelta_t *family, md_rentxn_t *rtxnp)
{
	md_rendelta_t	*r;
	int		 rc;

	ASSERT(family);
	ASSERT(rtxnp);

	if (!family || !rtxnp) {
		/* no error packet to set? */
		return (EINVAL);
	}

	for (r = family, rc = 0; r; r = r->next) {

		ASSERT(UNIT_WRITER_HELD(r->unp));
		ASSERT(r->txn_stat.locked);

		/*
		 * <to> doesn't exist for rename
		 */
		if (!(rtxnp->op == MDRNOP_RENAME &&
		    md_getminor(r->dev) == rtxnp->to.mnum)) {
			ASSERT(r->uip);
			r->txn_stat.is_open = md_unit_isopen(r->uip);
		}

		/*
		 * if only allowing offline rename/exchanges, check
		 * for top being trans because it opens its sub-devices
		 */

		switch (rtxnp->revision) {
		case MD_RENAME_VERSION_OFFLINE:
			if ((r->txn_stat.is_open) &&
				(!rtxnp->stat.trans_in_stack)) {
				(void) mdmderror(&rtxnp->mde, MDE_RENAME_BUSY,
							md_getminor(r->dev));
				return (EBUSY);
			}
			break;

		case MD_RENAME_VERSION_ONLINE:
			break;

		default:
			(void) mdmderror(&rtxnp->mde, MDE_RENAME_CONFIG_ERROR,
						md_getminor(r->dev));
			return (EINVAL);
		}

		/* MD_UN_MOD_INPROGRESS includes the MD_UN_RENAMING bit */

		if (MD_STATUS(r->unp) & MD_UN_MOD_INPROGRESS) {
			(void) mdmderror(&rtxnp->mde, MDE_RENAME_BUSY,
							md_getminor(r->dev));
			return (EBUSY);
		}

		MD_STATUS(r->unp) |= MD_UN_RENAMING;

		if ((rc = (int)(*r->check)(r, rtxnp)) != 0) {
			return (rc);
		}

		/* and be sure we can proceed */
		if (!(r->role_swap)) {
			(void) mdmderror(&rtxnp->mde, MDE_RENAME_CONFIG_ERROR,
							md_getminor(r->dev));
			return (EINVAL);
		}
		r->txn_stat.checked = TRUE;
	}

	return (0);
}


/*
 * rename role_swap() functions are responsible for updating their
 * own parent, self and children references in both on-disk
 * and in-core structures, as well as storing the changed
 * record ids into recids and incrementing rec_idx.
 */

static void
role_swap_dtree(md_rendelta_t *family, md_rentxn_t *rtxnp)
{
	md_rendelta_t	*r;

	ASSERT(family);
	ASSERT(rtxnp);

	for (r = family; r; r = r->next) {
		ASSERT(r->role_swap);
		ASSERT(r->txn_stat.locked);
		ASSERT(r->txn_stat.checked);

		(*r->role_swap)(r, rtxnp);

		r->txn_stat.role_swapped = TRUE;
	}

	/*
	 * there's some work to do, but not more than expected
	 */
	ASSERT(rtxnp->rec_idx > 0);
	ASSERT(rtxnp->rec_idx < rtxnp->n_recids);

	if (rtxnp->rec_idx >= rtxnp->n_recids || rtxnp->rec_idx <= 0) {
		/*
		 * There's no way to indicate error from here,
		 * and even if we could, there's no undo mechanism.
		 * We've already modified the in-core structs, so
		 * We can't continue w/o committing, but we
		 * don't appear to have anything to commit.
		 */
		cmn_err(CE_PANIC,
			"md_rename: role_swap_dtree(family:%p, rtxnp:%p)",
					(void *) family, (void *) rtxnp);
		return;
	}
	rtxnp->recids[rtxnp->rec_idx] = 0;

	mddb_commitrecs_wrapper(rtxnp->recids);
}

/*
 * walk down delta tree, calling the unlock service for each device,
 * provided any of the devices appear to have been locked
 */
static void
unlock_dtree(md_rendelta_t *family, md_rentxn_t *rtxnp)
{
	md_rendelta_t	*r;
	uint_t		 any_locked	= FALSE;

	ASSERT(family);
	ASSERT(rtxnp);

	for (r = family; r; r = r->next) {

		ASSERT(!(r->txn_stat.unlocked)); /* "has been unlocked" */
		any_locked |= r->txn_stat.locked;
	}

	if (any_locked) {

		/* unwind in reverse order */
		for (r = family; NULL != r->next; r = r->next) {
			/* NULL */
		}

		for (; NULL != r; r = r->prev) {
			MD_STATUS(r->unp) &= ~MD_UN_RENAMING;
			ASSERT(r->unlock);
			r->unlock(r, rtxnp);
			r->txn_stat.unlocked = TRUE;
		}
	}
}

/*
 * MDRNM_UPDATE_SELF
 * This role swap function is identical for all unit types,
 * so keep it here. It's also the best example because it
 * touches all the modified portions of the relevant
 * in-common structures.
 */
static void
md_rename_update_self(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	minor_t		from_min, to_min;
	sv_dev_t	sv;
	mddb_de_ic_t	*dep;
	mddb_rb32_t	*rbp;

	ASSERT(rtxnp);
	ASSERT(rtxnp->op == MDRNOP_RENAME);
	ASSERT(delta);
	ASSERT(delta->unp);
	ASSERT(delta->uip);
	ASSERT(rtxnp->rec_idx >= 0);
	ASSERT(rtxnp->recids);
	ASSERT(delta->old_role == MDRR_SELF);
	ASSERT(delta->new_role == MDRR_SELF);
	ASSERT(md_getminor(delta->dev) == rtxnp->from.mnum);

	from_min = rtxnp->from.mnum;
	to_min = rtxnp->to.mnum;

	/*
	 * self id changes in our own unit struct
	 */
	MD_SID(delta->unp) = to_min;

	/*
	 * make sure that dest always has correct un_revision
	 * and rb_revision
	 */
	delta->unp->c.un_revision |= MD_FN_META_DEV;
	dep = mddb_getrecdep(MD_RECID(delta->unp));
	ASSERT(dep);
	rbp = dep->de_rb;
	if (rbp->rb_revision & MDDB_REV_RB) {
		rbp->rb_revision = MDDB_REV_RBFN;
	} else if (rbp->rb_revision & MDDB_REV_RB64) {
		rbp->rb_revision = MDDB_REV_RB64FN;
	}

	/*
	 * clear old array pointers to unit in-core and unit
	 */

	MDI_VOIDUNIT(from_min) = NULL;
	MD_VOIDUNIT(from_min) = NULL;

	/*
	 * and point the new slots at the unit in-core and unit structs
	 */

	MDI_VOIDUNIT(to_min) = delta->uip;
	MD_VOIDUNIT(to_min) = delta->unp;

	/*
	 * recreate kstats
	 * - destroy the ones associated with our former identity
	 * - reallocate and associate them with our new identity
	 */
	md_kstat_destroy_ui(delta->uip);
	md_kstat_init_ui(to_min, delta->uip);

	/*
	 * the unit in-core reference to the get next link's id changes
	 */

	delta->uip->ui_link.ln_id = to_min;

	/*
	 * name space addition of new key was done from user-level
	 * remove the old name's key here
	 */

	sv.setno = MD_MIN2SET(from_min);
	sv.key = rtxnp->from.key;

	md_rem_names(&sv, 1);

	/*
	 * Remove associated device node as well
	 */
	md_remove_minor_node(from_min);

	/*
	 * and store the record id (from the unit struct) into recids
	 * for later commitment by md_rename()
	 */
	md_store_recid(&rtxnp->rec_idx, rtxnp->recids, delta->unp);
}

/*
 * Either one of our siblings and/or our parent changed identities.
 */
static void
md_renexch_update_parent(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	ASSERT(rtxnp);
	ASSERT((MDRNOP_RENAME == rtxnp->op) || (rtxnp->op == MDRNOP_EXCHANGE));
	ASSERT(rtxnp->rec_idx >= 0);
	ASSERT(rtxnp->recids);
	ASSERT(delta);
	ASSERT(delta->unp);
	ASSERT(delta->old_role == MDRR_CHILD);
	ASSERT(delta->new_role == MDRR_CHILD);
	ASSERT((MD_PARENT(delta->unp) == rtxnp->from.mnum) ||
		(MD_PARENT(delta->unp) == rtxnp->to.mnum));

	if (MD_PARENT(delta->unp) == rtxnp->from.mnum) {
		MD_PARENT(delta->unp) = rtxnp->to.mnum;
	}

	md_store_recid(&rtxnp->rec_idx, rtxnp->recids, delta->unp);
}

/*
 * exchange up (child->self)
 */
static void
md_exchange_child_update_to(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	minor_t from_min, to_min;

	ASSERT(rtxnp);
	ASSERT(rtxnp->op == MDRNOP_EXCHANGE);
	ASSERT(rtxnp->rec_idx >= 0);
	ASSERT(rtxnp->recids);
	ASSERT(delta);
	ASSERT(delta->unp);
	ASSERT(delta->uip);
	ASSERT(delta->old_role == MDRR_CHILD);
	ASSERT(delta->new_role == MDRR_SELF);
	ASSERT(md_getminor(delta->dev) == rtxnp->to.mnum);

	from_min = rtxnp->from.mnum;
	to_min = rtxnp->to.mnum;

	/*
	 * self id changes in our own unit struct
	 * Note:
	 * - Since we're assuming the identity of "from" we use its mnum even
	 *   though we're updating the "to" structures.
	 */

	MD_SID(delta->unp) = from_min;

	/*
	 * our parent identifier becomes the new self, who was "to"
	 */

	MD_PARENT(delta->unp) = to_min;

	/*
	 * point the set array pointers at the "new" unit and unit in-cores
	 * Note:
	 * - The other half of this transfer is done in the "update from"
	 *   rename/exchange named service.
	 */

	MD_VOIDUNIT(from_min) = delta->unp;
	MDI_VOIDUNIT(from_min) = delta->uip;

	/*
	 * transfer kstats
	 */

	delta->uip->ui_kstat = rtxnp->from.kstatp;

	/*
	 * the unit in-core reference to the get next link's id changes
	 */

	delta->uip->ui_link.ln_id = from_min;

	/*
	 * name space additions, if necessary, were done from user-level.
	 * name space deletions, if necessary, were done in "exchange_from"
	 */

	/*
	 * and store the record id (from the unit struct) into recids
	 * for later comitment by md_rename()
	 */

	md_store_recid(&rtxnp->rec_idx, rtxnp->recids, delta->unp);
}

/*
 * exchange up (self->parent)
 */
static void
md_exchange_self_update_from_up(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	minor_t from_min, to_min;

	ASSERT(rtxnp);
	ASSERT(rtxnp->op == MDRNOP_EXCHANGE);
	ASSERT(rtxnp->rec_idx >= 0);
	ASSERT(rtxnp->recids);
	ASSERT(delta);
	ASSERT(delta->unp);
	ASSERT(delta->uip);
	ASSERT(delta->old_role == MDRR_SELF);
	ASSERT(delta->new_role == MDRR_PARENT);
	ASSERT(md_getminor(delta->dev) == rtxnp->from.mnum);

	from_min = rtxnp->from.mnum;
	to_min = rtxnp->to.mnum;

	/*
	 * self id changes in our own unit struct
	 * Note:
	 * - Since we're assuming the identity of "to" we use its mnum
	 *   while we're updating the "to" structures.
	 */

	MD_SID(delta->unp) = to_min;

	/*
	 * our parent identifier becomes the new parent, who was "from"
	 */

	MD_PARENT(delta->unp) = from_min;

	/*
	 * point the set array pointers at the "new" unit and unit in-cores
	 * Note:
	 * - The other half of this transfer is done in the "update from"
	 *   rename/exchange named service.
	 */

	MD_VOIDUNIT(to_min) = delta->unp;
	MDI_VOIDUNIT(to_min) = delta->uip;

	/*
	 * transfer kstats
	 */

	delta->uip->ui_kstat = rtxnp->to.kstatp;

	/*
	 * the unit in-core reference to the get next link's id changes
	 */

	delta->uip->ui_link.ln_id = to_min;

	/*
	 * name space additions, if necessary, were done from user-level.
	 * name space deletions, if necessary, were done in "exchange_from"
	 */

	/*
	 * and store the record id (from the unit struct) into recids
	 * for later comitment by md_rename()
	 */

	md_store_recid(&rtxnp->rec_idx, rtxnp->recids, delta->unp);
}

/*
 * The order of the called role swap functions is critical.
 * If they're not ordered as "all parents", then "all self"
 * then "all child" transitions, we will almost certainly
 * corrupt the data base and the in-core linkages. So,
 * verify that the list built by the individual drivers is
 * ok here.
 *
 * We could have done fancy bit encodings of the roles so
 * it all fit into a single word and we wouldn't need the
 * prev_ord field. But, since cpu power is cheaper than
 * than people power, they're all separate for easier
 * debugging and maintaining. (In the unlikely event that
 * rename/exchange ever becomes cpu-limited, and this
 * algorithm is the bottleneck, we should revisit this.)
 */

static bool_t
role_swap_is_valid(
	int		 previous,
	int		 current,
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	bool_t	valid	= FALSE;

	/*
	 * we've backed up in processing the role table
	 */
	if ((previous > current) &&
	    (delta->prev && (delta->old_role != delta->prev->old_role))) {
		goto out;
	}

	/*
	 * we're repeating the same role transition
	 */
	if (previous == current) {
		switch (delta->old_role) {
		case MDRR_PARENT:
			/*
			 * require at least one of the devices to
			 * be multiparented for us to allow another
			 * parent transition
			 */
			if ((MD_MULTI_PARENT != MD_PARENT(rtxnp->from.unp)) &&
			    (MD_MULTI_PARENT != MD_PARENT(rtxnp->to.unp))) {
				goto out;
			}
			break;

		case MDRR_CHILD:
			/* it's ok to have multiple children */
			break;

		case MDRR_SELF:
			/* it's never ok to have multiple self transitions */
			/* FALLTHROUGH */
		default:
			goto out;
		}
	}

	valid = TRUE;
out:
	if (!valid) {
		if (md_rename_debug != 0) {
			cmn_err(CE_NOTE, "previous: %d, current: %d, role: %s",
					previous, current,
					ROLE(delta->old_role));
			delay(3*drv_usectohz(1000000));
			ASSERT(FALSE);
		}
	}

	return (valid);
}

static role_change_tab_t *
lookup_role(md_renrole_t old_role, md_renrole_t new_role)
{
	role_change_tab_t	*rp;
	role_change_tab_t	*found = NULL;

	for (rp = role_swap_tab; !found && (rp->old_role != MDRR_UNK); rp++) {

		if (rp->old_role == old_role && rp->new_role == new_role) {
			found = rp;
		}
	}
	/*
	 * we require a named svc if we've got two devices
	 * claiming to be changing roles in this manner
	 */
	ASSERT(found);
	ASSERT(found->default_svc != ILLEGAL_ROLESWAP_SVC);
	ASSERT(found->svc_name != ILLEGAL_SVC_NAME);

	if (!found ||
	    (found->default_svc == ILLEGAL_ROLESWAP_SVC) ||
	    (found->svc_name == ILLEGAL_SVC_NAME)) {
		return (NULL);
	}

	return (found);
}

/*
 * fill in the role swap named svc., now that we know each device
 * and its changing role
 */
static int
valid_roleswap_dtree(
	md_rendelta_t	*family,
	md_rentxn_t	*rtxnp
)
{
	md_rendelta_t		*r;
	role_change_tab_t	*rolep;
	minor_t			 from_min, to_min;
	int			 prev_ord	= -1;
	bool_t			found_self	= FALSE;
	int			 err		= 0;

	ASSERT(family);
	ASSERT(rtxnp);

	from_min = rtxnp->from.mnum;
	to_min = rtxnp->to.mnum;

	for (r = family; r; r = r->next, prev_ord = rolep->ord) {

		if (!(rolep = lookup_role(r->old_role, r->new_role))) {
			(void) mdmderror(&rtxnp->mde,
					MDE_RENAME_CONFIG_ERROR, from_min);
			err = EOPNOTSUPP;
			goto out;
		}
		r->role_swap = (md_ren_roleswap_svc_t *)md_get_named_service(
					r->dev, /* modindex */ 0,
					(char *)rolep->svc_name,
					(intptr_t (*)()) rolep->default_svc);

		/*
		 * someone probably called the ioctl directly and
		 * incorrectly, rather than via the libmeta wrappers
		 */
		if (!(r->role_swap)) {
			(void) mdmderror(&rtxnp->mde,
					MDE_RENAME_TARGET_UNRELATED, to_min);
			err = EOPNOTSUPP;
			goto out;
		}

		if (!role_swap_is_valid(prev_ord, rolep->ord, r, rtxnp)) {
			(void) mdmderror(&rtxnp->mde,
					MDE_RENAME_CONFIG_ERROR, from_min);
			err = EINVAL;
			goto out;
		}

		if (rolep->old_role == MDRR_SELF) {
			found_self = TRUE;
		}

		if (MD_PARENT(r->unp) == MD_MULTI_PARENT) {
			(void) mdmderror(&rtxnp->mde, MDE_RENAME_TARGET_BAD,
							md_getminor(r->dev));
			err = EINVAL;
			goto out;
		}
	}

	/*
	 * must be at least one selfish device
	 */
	ASSERT(found_self);
	if (!found_self) {
		(void) mdmderror(&rtxnp->mde,
					MDE_RENAME_CONFIG_ERROR, from_min);
		err = EINVAL;
		goto out;
	}

out:
	return (err);
}

/*
 * dump contents of rename transaction
 */
static void
dump_txn(md_rentxn_t *rtxnp) {

	if (md_rename_debug == 0) {
		return;
	}

	cmn_err(CE_NOTE, "rtxnp: %p", (void *) rtxnp);
	if (rtxnp) {
		cmn_err(CE_NOTE, "beginning: %llx, op: %s",
			rtxnp->beginning, OP_STR(rtxnp->op));

		cmn_err(CE_NOTE,
	"revision: %d, uflags: %d, rec_idx: %d, n_recids: %d, rec_ids: %p%s",
			rtxnp->revision, rtxnp->uflags,
			rtxnp->rec_idx, rtxnp->n_recids, (void *) rtxnp->recids,
			rtxnp->stat.trans_in_stack? " (trans in stack)": "");
		cmn_err(CE_NOTE, " from: beginning: %llx",
							rtxnp->from.beginning);
		cmn_err(CE_NOTE, "    minor: %lX, key: %lX",
			(ulong_t)rtxnp->from.mnum, (ulong_t)rtxnp->from.key);
		cmn_err(CE_NOTE, "    unp: %lX, uip: %lX",
			(ulong_t)rtxnp->from.unp, (ulong_t)rtxnp->from.uip);
		cmn_err(CE_NOTE, "    end: %llx", rtxnp->from.end);
		cmn_err(CE_NOTE, "  to: beginning: %llx", rtxnp->to.beginning);
		cmn_err(CE_NOTE, "    minor: %lX, key: %lX",
			(ulong_t)rtxnp->to.mnum, (ulong_t)rtxnp->to.key);
		cmn_err(CE_NOTE, "    unp: %lX, uip: %lX",
			(ulong_t)rtxnp->to.unp, (ulong_t)rtxnp->to.uip);
		cmn_err(CE_NOTE, "    end: %llx", rtxnp->to.end);
		cmn_err(CE_NOTE, "end: %llx\n", rtxnp->end);
	}
	delay(drv_usectohz(1000000));
}

/*
 * dump contents of all deltas
 */
static void
dump_dtree(md_rendelta_t *family)
{
	md_rendelta_t	*r;
	int		i;

	if (md_rename_debug == 0) {
		return;
	}

	for (r = family, i = 0; r; r = r->next, i++) {
		cmn_err(CE_NOTE, "%d.  beginning: %llx", i, r->beginning);
		cmn_err(CE_NOTE, "  r: %lX, dev: %lX, next: %lx, prev: %lx",
					(ulong_t)r, (ulong_t)r->dev,
					(ulong_t)r->next, (ulong_t)r->prev);

		cmn_err(CE_NOTE, "  role: %s -> %s, unp: %lx, uip: %lx",
			ROLE(r->old_role), ROLE(r->new_role),
			(ulong_t)r->unp, (ulong_t)r->uip);
		cmn_err(CE_NOTE,
		"  lock: %lx, unlock: %lx\n\t  check: %lx, role_swap: %lx",
			(ulong_t)r->lock, (ulong_t)r->unlock,
			(ulong_t)r->check, (ulong_t)r->role_swap);
		if (*((uint_t *)(&r->txn_stat)) != 0) {
			cmn_err(CE_NOTE, "status: (0x%x) %s%s%s%s%s",
			*((uint_t *)(&r->txn_stat)),
			r->txn_stat.is_open?		"is_open "	: "",
			r->txn_stat.locked?		"locked "	: "",
			r->txn_stat.checked?		"checked "	: "",
			r->txn_stat.role_swapped?	"role_swapped "	: "",
			r->txn_stat.unlocked?		"unlocked"	: "");
		}
		cmn_err(CE_NOTE, "end: %llx\n", r->end);
	}
	delay(drv_usectohz(1000000));
}

/*
 * validate the rename request parameters
 */
static int
validate_txn_parms(md_rentxn_t *rtxnp)
{
	minor_t	to_min, from_min;

	ASSERT(rtxnp);

	from_min = rtxnp->from.mnum;
	to_min = rtxnp->to.mnum;

	switch (rtxnp->revision) {
	case MD_RENAME_VERSION_OFFLINE:
		if (rtxnp->uflags != 0) {
			(void) mdmderror(&rtxnp->mde, MDE_RENAME_CONFIG_ERROR,
								from_min);
			return (ENOTSUP);
		}
		break;

	case MD_RENAME_VERSION_ONLINE:
		/* not supported until 5.0 */
		/* FALLTHROUGH */

	default:
		(void) mdmderror(&rtxnp->mde, MDE_RENAME_CONFIG_ERROR,
								from_min);
		return (EPROTONOSUPPORT);
	}

	if ((rtxnp->from.uip = MDI_UNIT(from_min)) == NULL) {
		(void) mdmderror(&rtxnp->mde, MDE_UNIT_NOT_SETUP, from_min);
		return (ENODEV);
	}

	if (!md_dev_exists(md_makedevice(md_major, from_min))) {
		(void) mdmderror(&rtxnp->mde, MDE_UNIT_NOT_SETUP, from_min);
		return (ENODEV);
	}

	if ((rtxnp->from.key == MD_KEYBAD) || (rtxnp->from.key == MD_KEYWILD)) {
		(void) mdmderror(&rtxnp->mde, MDE_INVAL_UNIT, from_min);
		return (EINVAL);
	}

	rtxnp->from.kstatp = rtxnp->from.uip->ui_kstat;
	rtxnp->from.unp = MD_UNIT(from_min);

	if (MD_MIN2SET(to_min) != MD_MIN2SET(from_min)) {
		(void) mdmderror(&rtxnp->mde, MDE_INVAL_UNIT, to_min);
		return (EINVAL);
	}

	switch (rtxnp->op) {
	case MDRNOP_EXCHANGE:
		rtxnp->to.unp = MD_UNIT(to_min);
		rtxnp->to.uip = MDI_UNIT(to_min);

		/*
		 * exchange requires target to exist
		 */

		if ((rtxnp->to.uip == NULL) ||
		    (md_dev_exists(md_makedevice(md_major, to_min)) == NULL)) {
			(void) mdmderror(&rtxnp->mde, MDE_UNIT_NOT_SETUP,
									to_min);
			return (ENODEV);
		}

		if ((rtxnp->to.key == MD_KEYBAD) ||
		    (rtxnp->to.key == MD_KEYWILD)) {
			(void) mdmderror(&rtxnp->mde, MDE_INVAL_UNIT, to_min);
			return (EINVAL);
		}

		/*
		 * <from> is not in the role of <self>,
		 * that is,
		 * <from> has a parent, which is <to> and <to> has a parent too
		 * or
		 * <to> has a parent, which is <from> and <to> can have a child
		 */
		if ((MD_HAS_PARENT(MD_PARENT(rtxnp->from.unp))) &&
		    (MD_PARENT(rtxnp->from.unp) == to_min) &&
		    MD_HAS_PARENT(MD_PARENT(rtxnp->to.unp))) {
			(void) mdmderror(&rtxnp->mde, MDE_RENAME_ORDER,
								from_min);
			return (EINVAL);
		}

		if ((MD_HAS_PARENT(MD_PARENT(rtxnp->to.unp))) &&
		    (MD_PARENT(rtxnp->to.unp) == from_min) &&
		    (MD_CAPAB(rtxnp->to.unp) & MD_CAN_META_CHILD)) {
			(void) mdmderror(&rtxnp->mde, MDE_RENAME_ORDER,
								from_min);
			return (EINVAL);
		}

		rtxnp->to.kstatp = rtxnp->to.uip->ui_kstat;
		break;

	case MDRNOP_RENAME:

		/*
		 * rename requires <to> not to exist
		 */

		if (MDI_UNIT(to_min) ||
		    md_dev_exists(md_makedevice(md_major, to_min))) {

			(void) mdmderror(&rtxnp->mde, MDE_UNIT_ALREADY_SETUP,
									to_min);
			return (EEXIST);
		}

		/*
		 * and to be within valid ranges for the current
		 * limits on number of sets and metadevices
		 */
		if ((MD_MIN2SET(to_min) >= md_nsets) ||
		    (MD_MIN2UNIT(to_min) >= md_nunits)) {
			(void) mdmderror(&rtxnp->mde, MDE_INVAL_UNIT, to_min);
			return (EINVAL);
		}

		rtxnp->to.unp = NULL;
		rtxnp->to.uip = NULL;
		rtxnp->to.kstatp = NULL;
		break;

	default:
		(void) mdmderror(&rtxnp->mde, MDE_RENAME_CONFIG_ERROR,
								from_min);
		return (EINVAL);
	}

	/*
	 * install guard rails
	 */
	rtxnp->beginning = TXN_BEG;

	rtxnp->from.beginning	= TXNUN_BEG;
	rtxnp->from.end		= TXNUN_END;

	rtxnp->to.beginning	= TXNUN_BEG;
	rtxnp->to.end		= TXNUN_END;

	rtxnp->end = TXN_END;

	return (0);
}

/*
 * If the device being changed exhibits this capability, set the list
 * relatives function pointer to the named service that lists the
 * appropriate relatives for this capability.
 */
static int
set_list_rels_funcp(
	md_rentxn_t		 *rtxnp,
	md_stackcap_t		 capability,
	char			 *svc_name,
	md_ren_list_svc_t	 default_svc_func,
	md_ren_list_svc_t	 **list_relatives_funcp
)
{
	int		 err;
	minor_t		 from_min;
	md_dev64_t	 from_dev;
	md_unit_t	*from_un;
	mdi_unit_t	*from_ui;

	ASSERT(rtxnp);
	ASSERT((rtxnp->op == MDRNOP_RENAME) || (rtxnp->op == MDRNOP_EXCHANGE));
	ASSERT(list_relatives_funcp);

	from_min	= rtxnp->from.mnum;
	from_dev	= md_makedevice(md_major, from_min);
	from_un		= MD_UNIT(from_min);
	from_ui		= MDI_UNIT(from_min);
	err		= 0;

	if (!from_ui || !from_un) {
		(void) mdmderror(&rtxnp->mde, MDE_UNIT_NOT_SETUP, from_min);
		err = EINVAL;
		goto out;
	}

	if ((capability == MD_CAN_DO_ANYTHING) ||
	    ((MD_CAPAB(from_un) & capability) == capability)) {

			*list_relatives_funcp = (md_ren_list_svc_t *)
					md_get_named_service(from_dev,
					/* modindex */ 0, svc_name,
					(intptr_t (*)()) default_svc_func);

			ASSERT(*list_relatives_funcp);
			if (!(*list_relatives_funcp)) {
				(void) mdmderror(&rtxnp->mde,
					MDE_RENAME_CONFIG_ERROR, from_min);
				err = EINVAL;
				goto out;
			}
	} else {
		*list_relatives_funcp = (md_ren_list_svc_t *)NULL;
	}

out:
	return (err);
}

/*
 * call list relations function, bump recid counter
 * by number of members added to the delta list.
 * Validate that the number of members added is within bounds.
 */
static int
list_relations(
		md_rendelta_t		**family,
		md_rentxn_t		 *rtxnp,
		md_ren_list_svc_t	 *add_relatives_funcp,
		int			  valid_min,
		int			  valid_max
)
{
	int	n_added;
	int	err = 0;

	ASSERT(family);
	ASSERT(rtxnp);

	if (!family || !rtxnp) {
		err = EINVAL;
		goto out;
	}

	n_added = 0;

	/* no relations of this type */
	if (!add_relatives_funcp) {
		goto out;
	}

	n_added = (*add_relatives_funcp) (family, rtxnp);

	if ((n_added < valid_min) || (n_added > valid_max)) {
		if (mdisok(&rtxnp->mde)) {
			(void) mdmderror(&rtxnp->mde, MDE_RENAME_CONFIG_ERROR,
							rtxnp->from.mnum);
		}
		err = EINVAL;
		goto out;
	}

	rtxnp->n_recids += n_added;

out:
	return (err);
}

/*
 * build recid array
 */
static int
alloc_recids(md_rendelta_t *family, md_rentxn_t *rtxnp)
{
	int	err	= 0;

	if (!family || !rtxnp) {
		err = ENOMEM;
		goto out;
	}

	rtxnp->rec_idx = 0;

	if (rtxnp->n_recids == 0) {
		err = EINVAL;
		goto out;
	}

	rtxnp->n_recids += 1;	/* terminator */

	rtxnp->recids = kmem_alloc(sizeof (mddb_recid_t) * rtxnp->n_recids,
	    KM_SLEEP);
	if (!(rtxnp->recids)) {
		err = ENOMEM;
		goto out;
	}

	bzero((void *) rtxnp->recids,
				(sizeof (mddb_recid_t) * rtxnp->n_recids));
out:
	if (err != 0) {
		(void) mdsyserror(&rtxnp->mde, err);
	}

	return (err);
}

/*
 * build family tree (parent(s), self, children)
 * The order of the resultant list is important, as it governs
 * the order of locking, checking and changing the unit structures.
 * Since we'll be changing them, we may not use the MD_UNIT, MDI_UNIT,
 * and other pointer which depend on the array being correct.
 * Use only the cached pointers (in rtxnp.)
 */
static md_rendelta_t *
build_dtree(md_rentxn_t *rtxnp)
{
	md_ren_list_svc_t	*add_folks, *add_self, *add_kids;
	int			 err;
	md_rendelta_t		*family	= NULL;

	ASSERT(rtxnp);
	ASSERT((rtxnp->op == MDRNOP_RENAME) || (rtxnp->op == MDRNOP_EXCHANGE));

	err = set_list_rels_funcp(rtxnp, MD_CAN_PARENT, MDRNM_LIST_URFOLKS,
					md_rename_listfolks, &add_folks);

	if (err) {
		goto out;
	}

	err = set_list_rels_funcp(rtxnp, MD_CAN_DO_ANYTHING, MDRNM_LIST_URSELF,
						md_rename_listself, &add_self);
	if (err) {
		goto out;
	}

	err = set_list_rels_funcp(rtxnp, MD_CAN_META_CHILD, MDRNM_LIST_URKIDS,
				/* no default list func */ ((int (*)()) NULL),
								&add_kids);
	if (err) {
		goto out;
	}

	rtxnp->n_recids = 0;	/* accumulated by list_relations() */

	if ((err = list_relations(&family, rtxnp, add_folks, 0, 1)) != 0) {
		goto out;
	}

	if ((err = list_relations(&family, rtxnp, add_self, 1, 1)) != 0) {
		goto out;
	}

	err = list_relations(&family, rtxnp, add_kids, 0, md_nunits);
	if (err != 0) {
		goto out;
	}

	/*
	 * delta tree is still empty?
	 */
	if ((!family) || (rtxnp->n_recids == 0)) {
		(void) mdmderror(&rtxnp->mde, MDE_RENAME_CONFIG_ERROR,
							rtxnp->from.mnum);
		err = EINVAL;
		goto out;
	}

	/*
	 * verify role change interactions
	 */
	if ((err = valid_roleswap_dtree(family, rtxnp)) != 0) {
		goto out;
	}

	if ((err = alloc_recids(family, rtxnp)) != 0) {
		goto out;
	}

out:
	if (err != 0) {
		free_dtree(family);
		dump_dtree(family);	/* yes, after freeing it */
		family = NULL;
	}

	return (family);
}


/*
 * (MD_IOCRENAME) rename/exchange ioctl entry point
 * calls individual driver named service entry points
 * to build a list of devices which need state changed,
 * to verify that they're in a state where renames may occur,
 * and to modify themselves into their new identities
 */

int
md_rename(
	md_rename_t	*mrp,
	IOLOCK		*iolockp)
{
	md_rendelta_t	*family		= NULL;
	md_rentxn_t	rtxn;
	int		err		= 0;
	set_t		setno;
	mdc_unit_t	*mdc;

	ASSERT(iolockp);
	if (mrp == NULL)
		return (EINVAL);

	setno = MD_MIN2SET(mrp->from.mnum);
	if (setno >= md_nsets) {
		return (EINVAL);
	}

	/*
	 * Early exit if top is eof trans
	 */
	mdc = (mdc_unit_t *)md_set[setno].s_un[MD_MIN2UNIT(mrp->from.mnum)];
	while (mdc != NULL) {
	    if (!MD_HAS_PARENT(mdc->un_parent)) {
		break;
	    } else {
		mdc = (mdc_unit_t *)md_set[setno].s_un[MD_MIN2UNIT
		    (mdc->un_parent)];
	    }
	}

	if (mdc && mdc->un_type == MD_METATRANS) {
		return (EINVAL);
	}


	mdclrerror(&mrp->mde);

	bzero((void *) &rtxn, sizeof (md_rentxn_t));
	mdclrerror(&rtxn.mde);

	/*
	 * encapsulate user parameters
	 */
	rtxn.from.key	= mrp->from.key;
	rtxn.to.key	= mrp->to.key;
	rtxn.from.mnum	= mrp->from.mnum;
	rtxn.to.mnum	= mrp->to.mnum;
	rtxn.op		= mrp->op;
	rtxn.uflags	= mrp->flags;
	rtxn.revision	= mrp->revision;

	if (MD_MIN2UNIT(mrp->to.mnum) >= md_nunits) {
		err = EINVAL;
		goto cleanup;
	}

	/*
	 * catch this early, before taking any locks
	 */
	if (md_get_setstatus(setno) & MD_SET_STALE) {
		(void) (mdmddberror(&rtxn.mde, MDE_DB_STALE, rtxn.from.mnum,
						MD_MIN2SET(rtxn.from.mnum)));
		err = EROFS;
		goto cleanup;
	}

	/*
	 * Locking and re-validation (of the per-unit state) is
	 * done by the rename lock/unlock service, for now only take
	 * the array lock.
	 */
	md_array_writer(iolockp);

	/*
	 * validate the rename/exchange parameters
	 * rtxn is filled in on succesful completion of validate_txn_parms()
	 */
	if ((err = validate_txn_parms(&rtxn)) != 0) {
		goto cleanup;
	}

	/*
	 * build list of work to do, the "delta tree" for related devices
	 */
	if (!(family = build_dtree(&rtxn))) {
		err = ENOMEM;
		goto cleanup;
	}
	dump_txn(&rtxn);
	dump_dtree(family);

	if ((err = lock_dtree(family, &rtxn)) != 0) {
		goto cleanup;
	}

	if ((err = check_dtree(family, &rtxn)) != 0) {
		goto cleanup;
	}
	dump_txn(&rtxn);

	role_swap_dtree(family, &rtxn);	/* commits the recids */

	/*
	 * let folks know
	 */
	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_RENAME_SRC, SVM_TAG_METADEVICE,
	    MD_MIN2SET(rtxn.from.mnum), rtxn.from.mnum);
	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_RENAME_DST, SVM_TAG_METADEVICE,
	    MD_MIN2SET(rtxn.from.mnum), rtxn.from.mnum);

cleanup:

	if (err != 0 && mdisok(&rtxn.mde)) {
		(void) mdsyserror(&rtxn.mde, EINVAL);
	}

	if (family) {
		unlock_dtree(family, &rtxn);
		free_dtree(family);
		dump_dtree(family);
		family = NULL;
	}

	if (rtxn.recids && (rtxn.n_recids > 0)) {
		kmem_free(rtxn.recids, sizeof (mddb_recid_t) * rtxn.n_recids);
	}

	if (!mdisok(&rtxn.mde)) {
		(void) mdstealerror(&mrp->mde, &rtxn.mde);
	}

	return (0);	/* success/failure will be communicated via rtxn.mde */
}

static role_change_tab_t
role_swap_tab[] =
{
	{
		1,			/* ordinal */
		MDRR_PARENT,		/* old role */
		MDRR_PARENT,		/* new role */
		MDRNM_UPDATE_KIDS,	/* named service */
		NO_DEFAULT_ROLESWAP_SVC	/* default role swap function */
	},
	{
		2,
		MDRR_PARENT,
		MDRR_SELF,
		MDRNM_PARENT_UPDATE_TO,
		NO_DEFAULT_ROLESWAP_SVC
	},
	{
		3,
		MDRR_PARENT,
		MDRR_CHILD,
		ILLEGAL_SVC_NAME,
		ILLEGAL_ROLESWAP_SVC
	},
	{
		4,
		MDRR_SELF,
		MDRR_PARENT,
		MDRNM_SELF_UPDATE_FROM_UP,
		md_exchange_self_update_from_up
	},
	{
		5,
		MDRR_SELF,
		MDRR_SELF,
		MDRNM_UPDATE_SELF,
		md_rename_update_self
	},
	{
		6,
		MDRR_SELF,
		MDRR_CHILD,
		MDRNM_SELF_UPDATE_FROM_DOWN,
		NO_DEFAULT_ROLESWAP_SVC
	},
	{
		7,
		MDRR_CHILD,
		MDRR_PARENT,
		ILLEGAL_SVC_NAME,
		ILLEGAL_ROLESWAP_SVC
	},
	{
		8,
		MDRR_CHILD,
		MDRR_SELF,
		MDRNM_CHILD_UPDATE_TO,
		md_exchange_child_update_to
	},
	{
		9,
		MDRR_CHILD,
		MDRR_CHILD,
		MDRNM_UPDATE_FOLKS,
		md_renexch_update_parent
	},

	/* terminator is old_role == MDRR_UNK */
	{
		0,
		MDRR_UNK,
		MDRR_UNK,
		ILLEGAL_SVC_NAME,
		NO_DEFAULT_ROLESWAP_SVC
	}
};
