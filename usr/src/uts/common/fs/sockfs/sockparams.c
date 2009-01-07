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
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/list.h>

#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <fs/sockfs/sockcommon.h>
#include <fs/sockfs/socktpi.h>

/*
 * Socket Parameters
 *
 * Socket parameter (struct sockparams) entries represent the socket types
 * available on the system.
 *
 * Flags (sp_flags):
 *
 * SOCKPARAMS_EPHEMERAL: A temporary sockparams entry that will be deleted
 * as soon as its' ref count drops to zero. In addition, ephemeral entries will
 * never be hooked onto the global sockparams list. Ephemeral entries are
 * created when application requests to create a socket using an application
 * supplied device path, or when a socket is falling back to TPI.
 *
 * Lock order:
 *   The lock order is splist_lock -> sp_lock.
 *   The lock order is sp_ephem_lock -> sp_lock.
 */
extern int 	kobj_path_exists(char *, int);
extern void	nl7c_init(void);
extern int	sockfs_defer_nl7c_init;

static int 	sockparams_sdev_init(struct sockparams *, char *, int);
static void 	sockparams_sdev_fini(struct sockparams *);

/*
 * Global sockparams list (populated via soconfig(1M)).
 */
static list_t sphead;
static krwlock_t splist_lock;

/*
 * List of ephemeral sockparams.
 */
static list_t sp_ephem_list;
static krwlock_t sp_ephem_lock;

void
sockparams_init(void)
{
	list_create(&sphead, sizeof (struct sockparams),
	    offsetof(struct sockparams, sp_node));
	list_create(&sp_ephem_list, sizeof (struct sockparams),
	    offsetof(struct sockparams, sp_node));

	rw_init(&splist_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&sp_ephem_lock, NULL, RW_DEFAULT, NULL);
}

/*
 * sockparams_create(int family, int type, int protocol, char *modname,
 *     char *devpath, int devpathlen, int flags, int kmflags, int *errorp)
 *
 * Create a new sockparams entry.
 *
 * Arguments:
 *   family, type, protocol: specifies the socket type
 *   modname: Name of the module associated with the socket type. The
 *            module can be NULL if a device path is given, in which
 *            case the TPI module is used.
 *   devpath: Path to the STREAMS device. May be NULL for non-STREAMS
 *            based transports, or those transports that do not provide
 *            the capability to fallback to STREAMS.
 *   devpathlen: Length of the devpath string. The argument can be 0,
 *            indicating that devpath was allocated statically, and should
 *            not be freed when the sockparams entry is destroyed.
 *
 *   flags  : SOCKPARAMS_EPHEMERAL is the only flag that is allowed.
 *   kmflags: KM_{NO,}SLEEP
 *   errorp : Value-return argument, set when an error occurs.
 *
 * Returns:
 *   On success a new sockparams entry is returned, and *errorp is set
 *   to 0. On failure NULL is returned and *errorp is set to indicate the
 *   type of error that occured.
 *
 * Notes:
 *   devpath and modname are freed upon failure.
 */
struct sockparams *
sockparams_create(int family, int type, int protocol, char *modname,
    char *devpath, int devpathlen, int flags, int kmflags, int *errorp)
{
	struct sockparams *sp = NULL;
	size_t size;

	ASSERT((flags & ~SOCKPARAMS_EPHEMERAL) == 0);
	if (flags & ~SOCKPARAMS_EPHEMERAL) {
		*errorp = EINVAL;
		goto error;
	}

	/* either a module or device must be given */
	if (modname == NULL && devpath == NULL) {
		*errorp = EINVAL;
		goto error;
	}

	sp = kmem_zalloc(sizeof (*sp), kmflags);
	if (sp == NULL) {
		*errorp = ENOMEM;
		goto error;
	}
	sp->sp_family = family;
	sp->sp_type = type;
	sp->sp_protocol = protocol;
	sp->sp_refcnt = 0;
	sp->sp_flags = flags;

	if (modname != NULL) {
		sp->sp_smod_name = modname;
	} else {
		size = strlen(SOTPI_SMOD_NAME) + 1;
		modname = kmem_zalloc(size, kmflags);
		if (modname == NULL) {
			*errorp = ENOMEM;
			goto error;
		}
		sp->sp_smod_name = modname;
		(void) sprintf(sp->sp_smod_name, "%s", SOTPI_SMOD_NAME);
	}

	if (devpath != NULL) {
		/* Set up the device entry. */
		*errorp = sockparams_sdev_init(sp, devpath, devpathlen);
		if (*errorp != 0)
			goto error;
	}

	mutex_init(&sp->sp_lock, NULL, MUTEX_DEFAULT, NULL);
	*errorp = 0;
	return (sp);
error:
	ASSERT(*errorp != 0);
	if (modname != NULL)
		kmem_free(modname, strlen(modname) + 1);
	if (devpathlen != 0)
		kmem_free(devpath, devpathlen);
	if (sp != NULL)
		kmem_free(sp, sizeof (*sp));
	return (NULL);
}

/*
 * Initialize the STREAMS device aspect of the sockparams entry.
 */
static int
sockparams_sdev_init(struct sockparams *sp, char *devpath, int devpathlen)
{
	vnode_t *vp = NULL;
	int error;

	ASSERT(devpath != NULL);

	if ((error = sogetvp(devpath, &vp, UIO_SYSSPACE)) != 0) {
		dprint(0, ("sockparams_sdev_init: vp %s failed with %d\n",
		    devpath, error));
		return (error);
	}

	ASSERT(vp != NULL);
	sp->sp_sdev_info.sd_vnode = vp;
	sp->sp_sdev_info.sd_devpath = devpath;
	sp->sp_sdev_info.sd_devpathlen = devpathlen;

	return (0);
}

/*
 * sockparams_destroy(struct sockparams *sp)
 *
 * Releases all the resources associated with the sockparams entry,
 * and frees the sockparams entry.
 *
 * Arguments:
 *   sp: the sockparams entry to destroy.
 *
 * Returns:
 *   Nothing.
 *
 * Locking:
 *   The sp_lock of the entry can not be held.
 */
void
sockparams_destroy(struct sockparams *sp)
{
	ASSERT(sp->sp_refcnt == 0);
	ASSERT(!list_link_active(&sp->sp_node));

	sockparams_sdev_fini(sp);

	if (sp->sp_smod_info != NULL)
		SMOD_DEC_REF(sp, sp->sp_smod_info);
	kmem_free(sp->sp_smod_name, strlen(sp->sp_smod_name) + 1);
	sp->sp_smod_name = NULL;
	sp->sp_smod_info = NULL;
	mutex_destroy(&sp->sp_lock);

	kmem_free(sp, sizeof (*sp));
}

/*
 * Clean up the STREAMS device part of the sockparams entry.
 */
static void
sockparams_sdev_fini(struct sockparams *sp)
{
	sdev_info_t sd;

	/*
	 * if the entry does not have a STREAMS device, then there
	 * is nothing to do.
	 */
	if (!SOCKPARAMS_HAS_DEVICE(sp))
		return;

	sd = sp->sp_sdev_info;
	if (sd.sd_vnode != NULL)
		VN_RELE(sd.sd_vnode);
	if (sd.sd_devpathlen != 0)
		kmem_free(sd.sd_devpath, sd.sd_devpathlen);

	sp->sp_sdev_info.sd_vnode = NULL;
	sp->sp_sdev_info.sd_devpath = NULL;
}

/*
 * Look for a matching sockparams entry on the given list.
 * The caller must hold the associated list lock.
 */
static struct sockparams *
sockparams_find(list_t *list, int family, int type, int protocol,
    boolean_t by_devpath, const char *name)
{
	struct sockparams *sp;

	for (sp = list_head(list); sp != NULL; sp = list_next(list, sp)) {
		if (sp->sp_family == family && sp->sp_type == type) {
			if (sp->sp_protocol == protocol) {
				if (name == NULL)
					break;
				else if (by_devpath &&
				    sp->sp_sdev_info.sd_devpath != NULL &&
				    strcmp(sp->sp_sdev_info.sd_devpath,
				    name) == 0)
					break;
				else if (strcmp(sp->sp_smod_name, name) == 0)
					break;
			}
		}
	}
	return (sp);
}

/*
 * sockparams_hold_ephemeral()
 *
 * Returns an ephemeral sockparams entry of the requested family, type and
 * protocol. The entry is returned held, and the caller is responsible for
 * dropping the reference using SOCKPARAMS_DEC_REF() once done.
 *
 * All ephemeral entries are on list (sp_ephem_list). If there is an
 * entry on the list that match the search criteria, then a reference is
 * placed on that entry. Otherwise, a new entry is created and inserted
 * in the list. The entry is removed from the list when the last reference
 * is dropped.
 *
 * The tpi flag is used to determine whether name refers to a device or
 * module name.
 */
static struct sockparams *
sockparams_hold_ephemeral(int family, int type, int protocol,
    const char *name, boolean_t by_devpath, int kmflag, int *errorp)
{
	struct sockparams *sp = NULL;
	*errorp = 0;

	/*
	 * First look for an existing entry
	 */
	rw_enter(&sp_ephem_lock, RW_READER);
	sp = sockparams_find(&sp_ephem_list, family, type, protocol,
	    by_devpath, name);
	if (sp != NULL) {
		SOCKPARAMS_INC_REF(sp);
		rw_exit(&sp_ephem_lock);

		return (sp);
	} else {
		struct sockparams *newsp = NULL;
		char *namebuf = NULL;
		int namelen = 0;

		rw_exit(&sp_ephem_lock);

		namelen = strlen(name) + 1;
		namebuf = kmem_alloc(namelen, kmflag);
		if (namebuf == NULL) {
			*errorp = ENOMEM;
			return (NULL);
		}

		(void *)strncpy(namebuf, name, namelen);
		if (by_devpath) {
			newsp = sockparams_create(family, type,
			    protocol, NULL, namebuf, namelen,
			    SOCKPARAMS_EPHEMERAL, kmflag, errorp);
		} else {
			newsp = sockparams_create(family, type,
			    protocol, namebuf, NULL, 0,
			    SOCKPARAMS_EPHEMERAL, kmflag, errorp);
		}

		if (newsp == NULL) {
			ASSERT(*errorp != 0);
			return (NULL);
		}

		/*
		 * Time to load the socket module.
		 */
		ASSERT(newsp->sp_smod_info == NULL);
		newsp->sp_smod_info =
		    smod_lookup_byname(newsp->sp_smod_name);
		if (newsp->sp_smod_info == NULL) {
			/* Failed to load */
			sockparams_destroy(newsp);
			*errorp = ENXIO;
			return (NULL);
		}

		/*
		 * The sockparams entry was created, now try to add it
		 * to the list. We need to hold the lock as a WRITER.
		 */
		rw_enter(&sp_ephem_lock, RW_WRITER);
		sp = sockparams_find(&sp_ephem_list, family, type, protocol,
		    by_devpath, name);
		if (sp != NULL) {
			/*
			 * Someone has requested a matching entry, so just
			 * place a hold on it and release the entry we alloc'ed.
			 */
			SOCKPARAMS_INC_REF(sp);
			rw_exit(&sp_ephem_lock);

			sockparams_destroy(newsp);
		} else {
			SOCKPARAMS_INC_REF(newsp);
			list_insert_tail(&sp_ephem_list, newsp);
			rw_exit(&sp_ephem_lock);

			sp = newsp;
		}
		ASSERT(*errorp == 0);

		return (sp);
	}
}

struct sockparams *
sockparams_hold_ephemeral_bydev(int family, int type, int protocol,
    const char *dev, int kmflag, int *errorp)
{
	return (sockparams_hold_ephemeral(family, type, protocol, dev, B_TRUE,
	    kmflag, errorp));
}

struct sockparams *
sockparams_hold_ephemeral_bymod(int family, int type, int protocol,
    const char *mod, int kmflag, int *errorp)
{
	return (sockparams_hold_ephemeral(family, type, protocol, mod, B_FALSE,
	    kmflag, errorp));
}

/*
 * Called when the last socket using the ephemeral entry is dropping
 * its' reference. To maintain lock order we must drop the sockparams
 * lock before calling this function. As a result, a new reference
 * might be placed on the entry, in which case there is nothing to
 * do. However, if ref count goes to zero, we delete the entry.
 */
void
sockparams_ephemeral_drop_last_ref(struct sockparams *sp)
{
	ASSERT(sp->sp_flags & SOCKPARAMS_EPHEMERAL);
	ASSERT(MUTEX_NOT_HELD(&sp->sp_lock));

	rw_enter(&sp_ephem_lock, RW_WRITER);
	mutex_enter(&sp->sp_lock);

	if (--sp->sp_refcnt == 0) {
		list_remove(&sp_ephem_list, sp);
		mutex_exit(&sp->sp_lock);
		rw_exit(&sp_ephem_lock);

		sockparams_destroy(sp);
	} else {
		mutex_exit(&sp->sp_lock);
		rw_exit(&sp_ephem_lock);
	}
}

/*
 * sockparams_add(struct sockparams *sp)
 *
 * Tries to add the given sockparams entry to the global list.
 *
 * Arguments:
 *   sp: the sockparms entry to add
 *
 * Returns:
 *   On success 0, but if an entry already exists, then EEXIST
 *   is returned.
 *
 * Locking:
 *   The caller can not be holding splist_lock.
 */
static int
sockparams_add(struct sockparams *sp)
{
	ASSERT(!(sp->sp_flags & SOCKPARAMS_EPHEMERAL));

	rw_enter(&splist_lock, RW_WRITER);
	if (sockparams_find(&sphead, sp->sp_family, sp->sp_type,
	    sp->sp_protocol, B_TRUE, NULL) != 0) {
		rw_exit(&splist_lock);
		return (EEXIST);
	} else {
		list_insert_tail(&sphead, sp);
		rw_exit(&splist_lock);
		return (0);
	}
}

/*
 * sockparams_delete(int family, int type, int protocol)
 *
 * Marks the sockparams entry for a specific family, type and protocol
 * for deletion. The entry is removed from the list and destroyed
 * if no one is holding a reference to it.
 *
 * Arguments:
 *   family, type, protocol: the socket type that should be removed.
 *
 * Returns:
 *   On success 0, otherwise ENXIO.
 *
 * Locking:
 *   Caller can not be holding splist_lock or the sp_lock of
 *   any sockparams entry.
 */
static int
sockparams_delete(int family, int type, int protocol)
{
	struct sockparams *sp;

	rw_enter(&splist_lock, RW_WRITER);
	sp = sockparams_find(&sphead, family, type, protocol, B_TRUE, NULL);

	if (sp != NULL) {
		/*
		 * If no one is holding a reference to the entry, then
		 * we go ahead and remove it from the list and then
		 * destroy it.
		 */
		mutex_enter(&sp->sp_lock);
		if (sp->sp_refcnt != 0) {
			mutex_exit(&sp->sp_lock);
			rw_exit(&splist_lock);
			return (EBUSY);
		}
		mutex_exit(&sp->sp_lock);
		/* Delete the sockparams entry. */
		list_remove(&sphead, sp);
		rw_exit(&splist_lock);

		sockparams_destroy(sp);
		return (0);
	} else {
		rw_exit(&splist_lock);
		return (ENXIO);
	}
}

/*
 * soconfig(int family, int type, int protocol,
 *     char *devpath, int devpathlen, char *module)
 *
 * Add or delete an entry to the sockparams table.
 * When devpath and module both are NULL, it will delete an entry.
 *
 * Arguments:
 *   family, type, protocol: the tuple in question
 *   devpath: STREAMS device path. Can be NULL for module based sockets.
 *   module : Name of the socket module. Can be NULL for STREAMS
 *            based sockets.
 *   devpathlen: length of the devpath string, or 0 if devpath
 *            was statically allocated.
 *
 * Note:
 *   This routine assumes that the caller has kmem_alloced
 *   devpath (if devpathlen > 0) and module for this routine to
 *   consume.
 */
int
soconfig(int family, int type, int protocol,
    char *devpath, int devpathlen, char *module)
{
	struct sockparams *sp;
	int error = 0;

	dprint(0, ("soconfig(%d,%d,%d,%s,%d,%s)\n",
	    family, type, protocol, devpath, devpathlen,
	    module == NULL ? "NULL" : module));

	if (sockfs_defer_nl7c_init) {
		nl7c_init();
		sockfs_defer_nl7c_init = 0;
	}

	if (devpath == NULL && module == NULL) {
		/*
		 * Delete existing entry,
		 * both socket module and STEAMS device.
		 */
		ASSERT(module == NULL);
		error = sockparams_delete(family, type, protocol);
	} else {
		/*
		 * Adding an entry
		 * sockparams_create frees mod name and devpath upon failure.
		 */
		sp = sockparams_create(family, type, protocol, module,
		    devpath, devpathlen, 0, KM_SLEEP, &error);

		if (sp != NULL) {
			error = sockparams_add(sp);
			if (error != 0)
				sockparams_destroy(sp);
		}
	}

	return (error);
}

/*
 * solookup(int family, int type, int protocol, struct sockparams **spp)
 *
 * Lookup an entry in the sockparams list based on the triple. The returned
 * entry either exactly match the given tuple, or it is the 'default' entry
 * for the given <family, type>. A default entry is on with a protocol
 * value of zero.
 *
 * Arguments:
 *   family, type, protocol: tuple to search for
 *   spp: Value-return argument
 *
 * Returns:
 *   If an entry is found, 0 is returned and *spp is set to point to the
 *   entry. In case an entry is not found, *spp is set to NULL, and an
 *   error code is returned. The errors are (in decreasing precedence):
 *	EAFNOSUPPORT - address family not in list
 *	EPROTONOSUPPORT - address family supported but not protocol.
 *	EPROTOTYPE - address family and protocol supported but not socket type.
 *
 * TODO: should use ddi_modopen()/ddi_modclose()
 */
int
solookup(int family, int type, int protocol, struct sockparams **spp)
{
	struct sockparams *sp = NULL;
	int error = 0;

	*spp = NULL;
	rw_enter(&splist_lock, RW_READER);

	/*
	 * Search the sockparams list for an appropiate entry.
	 * Hopefully we find an entry that match the exact family,
	 * type and protocol specified by the user, in which case
	 * we return that entry. However, we also keep track of
	 * the default entry for a specific family and type, the
	 * entry of which would have a protocol value of 0.
	 */
	sp = sockparams_find(&sphead, family, type, protocol, B_TRUE, NULL);

	if (sp == NULL) {
		int found = 0;

		/* Determine correct error code */
		for (sp = list_head(&sphead); sp != NULL;
		    sp = list_next(&sphead, sp)) {
			if (sp->sp_family == family && found < 1)
				found = 1;
			if (sp->sp_family == family &&
			    sp->sp_protocol == protocol && found < 2)
				found = 2;
		}
		rw_exit(&splist_lock);
		switch (found) {
		case 0:
			error = EAFNOSUPPORT;
			break;
		case 1:
			error = EPROTONOSUPPORT;
			break;
		case 2:
			error = EPROTOTYPE;
			break;
		}
		return (error);
	}

	/*
	 * An entry was found.
	 *
	 * We put a hold on the entry early on, so if the
	 * sockmod is not loaded, and we have to exit
	 * splist_lock to call modload(), we know that the
	 * sockparams entry wont go away. That way we don't
	 * have to look up the entry once we come back from
	 * modload().
	 */
	SOCKPARAMS_INC_REF(sp);
	rw_exit(&splist_lock);

	if (sp->sp_smod_info == NULL) {
		sp->sp_smod_info = smod_lookup_byname(sp->sp_smod_name);
		if (sp->sp_smod_info == NULL) {
			/*
			 * We put a hold on the sockparams entry
			 * earlier, hoping everything would work out.
			 * That obviously did not happen, so release
			 * the hold here.
			 */
			SOCKPARAMS_DEC_REF(sp);
			/*
			 * We should probably mark the sockparams as
			 * "bad", and redo the lookup skipping the
			 * "bad" entries. I.e., sp->sp_mod_state |= BAD,
			 * return (solookup(...))
			 */
			return (ENXIO);
		}
	}

	/*
	 * Alright, we have a valid sockparams entry.
	 */
	*spp = sp;
	return (0);
}
