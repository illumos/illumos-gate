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

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/prom_plat.h>
#include <sys/promif.h>
#include <sys/kmem.h>
#include <sys/hypervisor_api.h>
#include <sys/hsvc.h>

#ifdef DEBUG

int	hsvc_debug = 0;				/* HSVC debug flags */

/*
 * Flags to control HSVC debugging
 */
#define	DBG_HSVC_REGISTER	0x0001
#define	DBG_HSVC_UNREGISTER	0x0002
#define	DBG_HSVC_OBP_CIF	0x0004
#define	DBG_HSVC_ALLOC		0x0008
#define	DBG_HSVC_VERSION	0x0010
#define	DBG_HSVC_REFCNT		0x0020
#define	DBG_HSVC_SETUP		0x0040

#define	HSVC_CHK_REFCNT(hsvcp)	\
	if (hsvc_debug & DBG_HSVC_REFCNT) hsvc_chk_refcnt(hsvcp)

#define	HSVC_DEBUG(flag, ARGS)	\
	if (hsvc_debug & flag)  prom_printf ARGS

#define	HSVC_DUMP()	\
	if (hsvc_debug & DBG_HSVC_SETUP) hsvc_dump()

#else /* DEBUG */

#define	HSVC_CHK_REFCNT(hsvcp)
#define	HSVC_DEBUG(flag, args)
#define	HSVC_DUMP()

#endif /* DEBUG */

/*
 * Each hypervisor API group negotiation is tracked via a
 * hsvc structure. This structure contains the API group,
 * currently negotiated major/minor number, a singly linked
 * list of clients currently registered and a reference count.
 *
 * Since the number of API groups is fairly small, negotiated
 * API groups are maintained via a singly linked list. Also,
 * sufficient free space is reserved to allow for API group
 * registration before kmem_xxx interface can be used to
 * allocate memory dynamically.
 *
 * Note that all access to the API group lookup and negotiation
 * is serialized to support strict HV API interface.
 */

typedef struct hsvc {
	struct hsvc	*next;			/* next group/free entry */
	uint64_t	group;			/* hypervisor service group */
	uint64_t	major;			/* major number */
	uint64_t	minor;			/* minor number */
	uint64_t	refcnt;			/* reference count */
	hsvc_info_t	*clients;		/* linked list of clients */
} hsvc_t;


/*
 * Global variables
 */
hsvc_t		*hsvc_groups;		/* linked list of API groups in use */
hsvc_t		*hsvc_avail;		/* free reserved buffers */
kmutex_t	hsvc_lock;		/* protects linked list and globals */

/*
 * Preallocate some space for boot requirements (before kmem_xxx can be
 * used)
 */
#define	HSVC_RESV_BUFS_MAX		16
hsvc_t	hsvc_resv_bufs[HSVC_RESV_BUFS_MAX];

/*
 * Pre-versioning groups (not negotiated by Ontario/Erie FCS release)
 */
static uint64_t hsvc_pre_versioning_groups[] = {
	HSVC_GROUP_SUN4V,
	HSVC_GROUP_CORE,
	HSVC_GROUP_VPCI,
	HSVC_GROUP_VSC,
	HSVC_GROUP_NIAGARA_CPU,
	HSVC_GROUP_NCS,
	HSVC_GROUP_DIAG
};

#define	HSVC_PRE_VERSIONING_GROUP_CNT	\
	(sizeof (hsvc_pre_versioning_groups) / sizeof (uint64_t))

static boolean_t
pre_versioning_group(uint64_t api_group)
{
	int	i;

	for (i = 0; i < HSVC_PRE_VERSIONING_GROUP_CNT; i++)
		if (hsvc_pre_versioning_groups[i] == api_group)
			return (B_TRUE);
	return (B_FALSE);
}

static hsvc_t *
hsvc_lookup(hsvc_info_t *hsvcinfop)
{
	hsvc_t		*hsvcp;
	hsvc_info_t	*p;

	for (hsvcp = hsvc_groups; hsvcp != NULL; hsvcp = hsvcp->next) {
		for (p = hsvcp->clients; p != NULL;
		    p = (hsvc_info_t *)p->hsvc_private)
			if (p == hsvcinfop)
				break;
		if (p)
			break;
	}

	return (hsvcp);
}

#ifdef DEBUG

/*
 * Check client reference count
 */
static void
hsvc_chk_refcnt(hsvc_t *hsvcp)
{
	int		refcnt;
	hsvc_info_t	*p;

	for (refcnt = 0, p = hsvcp->clients; p != NULL;
	    p = (hsvc_info_t *)p->hsvc_private)
		refcnt++;

	ASSERT(hsvcp->refcnt == refcnt);
}

/*
 * Dump registered clients information
 */
static void
hsvc_dump(void)
{
	hsvc_t		*hsvcp;
	hsvc_info_t	*p;

	mutex_enter(&hsvc_lock);

	prom_printf("hsvc_dump: hsvc_groups: %p  hsvc_avail: %p\n",
	    (void *)hsvc_groups, (void *)hsvc_avail);

	for (hsvcp = hsvc_groups; hsvcp != NULL; hsvcp = hsvcp->next) {
		prom_printf(" hsvcp: %p (0x%lx 0x%lx 0x%lx) ref: %ld clients: "
		    "%p\n", (void *)hsvcp, hsvcp->group, hsvcp->major,
		    hsvcp->minor, hsvcp->refcnt, (void *)hsvcp->clients);

		for (p = hsvcp->clients; p != NULL;
		    p = (hsvc_info_t *)p->hsvc_private) {
			prom_printf("  client %p (0x%lx 0x%lx 0x%lx '%s') "
			    "private: %p\n", (void *)p, p->hsvc_group,
			    p->hsvc_major, p->hsvc_minor, p->hsvc_modname,
			    p->hsvc_private);
		}
	}

	mutex_exit(&hsvc_lock);
}

#endif /* DEBUG */

/*
 * Allocate a buffer to cache API group information. Note that we
 * allocate a buffer from reserved pool early on, before kmem_xxx
 * interface becomes available.
 */
static hsvc_t *
hsvc_alloc(void)
{
	hsvc_t	*hsvcp;

	ASSERT(MUTEX_HELD(&hsvc_lock));

	if (hsvc_avail != NULL) {
		hsvcp = hsvc_avail;
		hsvc_avail = hsvcp->next;
	} else if (kmem_ready) {
		hsvcp = kmem_zalloc(sizeof (hsvc_t), KM_SLEEP);
		HSVC_DEBUG(DBG_HSVC_ALLOC,
		    ("hsvc_alloc: hsvc_avail: %p  kmem_zalloc hsvcp: %p\n",
		    (void *)hsvc_avail, (void *)hsvcp));
	} else
		hsvcp = NULL;
	return (hsvcp);
}

static void
hsvc_free(hsvc_t *hsvcp)
{
	ASSERT(hsvcp != NULL);
	ASSERT(MUTEX_HELD(&hsvc_lock));

	if (hsvcp >= hsvc_resv_bufs &&
	    hsvcp < &hsvc_resv_bufs[HSVC_RESV_BUFS_MAX]) {
		hsvcp->next = hsvc_avail;
		hsvc_avail =  hsvcp;
	} else {
		HSVC_DEBUG(DBG_HSVC_ALLOC,
		    ("hsvc_free: hsvc_avail: %p  kmem_free hsvcp: %p\n",
		    (void *)hsvc_avail, (void *)hsvcp));
		(void) kmem_free(hsvcp, sizeof (hsvc_t));
	}
}

/*
 * Link client on the specified hsvc's client list and
 * bump the reference count.
 */
static void
hsvc_link_client(hsvc_t *hsvcp, hsvc_info_t *hsvcinfop)
{
	ASSERT(MUTEX_HELD(&hsvc_lock));
	HSVC_CHK_REFCNT(hsvcp);

	hsvcinfop->hsvc_private = hsvcp->clients;
	hsvcp->clients = hsvcinfop;
	hsvcp->refcnt++;
}

/*
 * Unlink a client from the specified hsvc's client list and
 * decrement the reference count, if found.
 *
 * Return 0 if client unlinked. Otherwise return -1.
 */
static int
hsvc_unlink_client(hsvc_t *hsvcp, hsvc_info_t *hsvcinfop)
{
	hsvc_info_t	*p, **pp;
	int	status = 0;

	ASSERT(MUTEX_HELD(&hsvc_lock));
	HSVC_CHK_REFCNT(hsvcp);

	for (pp = &hsvcp->clients; (p = *pp) != NULL;
	    pp = (hsvc_info_t **)&p->hsvc_private) {
		if (p != hsvcinfop)
			continue;

		ASSERT(hsvcp->refcnt > 0);
		hsvcp->refcnt--;
		*pp = (hsvc_info_t *)p->hsvc_private;
		p->hsvc_private = NULL;
		break;
	}

	if (p == NULL)
		status = -1;

	return (status);
}

/*
 * Negotiate/register an API group usage
 */
int
hsvc_register(hsvc_info_t *hsvcinfop, uint64_t *supported_minor)
{
	hsvc_t *hsvcp;
	uint64_t api_group = hsvcinfop->hsvc_group;
	uint64_t major = hsvcinfop->hsvc_major;
	uint64_t minor = hsvcinfop->hsvc_minor;
	int status = 0;

	HSVC_DEBUG(DBG_HSVC_REGISTER,
	    ("hsvc_register %p (0x%lx 0x%lx 0x%lx ID %s)\n", (void *)hsvcinfop,
	    api_group, major, minor, hsvcinfop->hsvc_modname));

	if (hsvcinfop->hsvc_rev != HSVC_REV_1)
		return (EINVAL);

	mutex_enter(&hsvc_lock);

	/*
	 * Make sure that the hsvcinfop is new (i.e. not already registered).
	 */
	if (hsvc_lookup(hsvcinfop) != NULL) {
		mutex_exit(&hsvc_lock);
		return (EINVAL);
	}

	/*
	 * Search for the specified api_group
	 */
	for (hsvcp = hsvc_groups; hsvcp != NULL; hsvcp = hsvcp->next)
		if (hsvcp->group == api_group)
			break;

	if (hsvcp) {
		/*
		 * If major number mismatch, then return ENOTSUP.
		 * Otherwise return currently negotiated minor
		 * and the following status:
		 *	ENOTSUP		requested minor < current minor
		 *	OK		requested minor >= current minor
		 */

		if (hsvcp->major != major) {
			status = ENOTSUP;
		} else if (hsvcp->minor > minor) {
			/*
			 * Client requested a lower minor number than
			 * currently in use.
			 */
			status = ENOTSUP;
			*supported_minor = hsvcp->minor;
		} else {
			/*
			 * Client requested a minor number same or higher
			 * than the one in use.  Set supported minor number
			 * and link the client on hsvc client linked list.
			 */
			*supported_minor = hsvcp->minor;
			hsvc_link_client(hsvcp, hsvcinfop);
		}
	} else {
		/*
		 * This service group has not been negotiated yet.
		 * Call OBP CIF interface to negotiate a major/minor
		 * number.
		 *
		 * If not enough memory to cache this information, then
		 * return EAGAIN so that the caller can try again later.
		 * Otherwise, process OBP CIF results as follows:
		 *
		 *	H_BADTRAP	OBP CIF interface is not supported.
		 *			If not a pre-versioning group, then
		 *			return EINVAL, indicating unsupported
		 *			API group. Otherwise, mimic default
		 *			behavior (i.e. support only major=1).
		 *
		 *	H_EOK		Negotiation was successful. Cache
		 *			and return supported major/minor,
		 *			limiting the minor number to the
		 *			requested value.
		 *
		 *	H_EINVAL	Invalid group. Return EINVAL
		 *
		 *	H_ENOTSUPPORTED	Unsupported major number. Return
		 *			ENOTSUP.
		 *
		 *	H_EBUSY		Return EAGAIN.
		 *
		 *	H_EWOULDBLOCK	Return EAGAIN.
		 */
		hsvcp = hsvc_alloc();
		if (hsvcp == NULL) {
			status = EAGAIN;
		} else {
			uint64_t hvstat;

			hvstat = prom_set_sun4v_api_version(api_group,
			    major, minor, supported_minor);

			HSVC_DEBUG(DBG_HSVC_OBP_CIF,
			    ("prom_set_sun4v_api_ver: 0x%lx 0x%lx, 0x%lx "
			    " hvstat: 0x%lx sup_minor: 0x%lx\n", api_group,
			    major, minor, hvstat, *supported_minor));

			switch (hvstat) {
			case H_EBADTRAP:
				/*
				 * Older firmware does not support OBP CIF
				 * interface. If it's a pre-versioning group,
				 * then assume that the firmware supports
				 * only major=1 and minor=0.
				 */
				if (!pre_versioning_group(api_group)) {
					status = EINVAL;
					break;
				} else if (major != 1) {
					status = ENOTSUP;
					break;
				}

				/*
				 * It's a preversioning group. Default minor
				 * value to 0.
				 */
				*supported_minor = 0;

				/*FALLTHROUGH*/
			case H_EOK:
				/*
				 * Limit supported minor number to the
				 * requested value and cache the new
				 * API group information.
				 */
				if (*supported_minor > minor)
					*supported_minor = minor;
				hsvcp->group = api_group;
				hsvcp->major = major;
				hsvcp->minor = *supported_minor;
				hsvcp->refcnt = 0;
				hsvcp->clients = NULL;
				hsvcp->next = hsvc_groups;
				hsvc_groups = hsvcp;

				/*
				 * Link the caller on the client linked list.
				 */
				hsvc_link_client(hsvcp, hsvcinfop);
				break;

			case H_ENOTSUPPORTED:
				status = ENOTSUP;
				break;

			case H_EBUSY:
			case H_EWOULDBLOCK:
				status = EAGAIN;
				break;

			case H_EINVAL:
			default:
				status = EINVAL;
				break;
			}
		}
		/*
		 * Deallocate entry if not used
		 */
		if (status != 0)
			hsvc_free(hsvcp);
	}
	mutex_exit(&hsvc_lock);

	HSVC_DEBUG(DBG_HSVC_REGISTER,
	    ("hsvc_register(%p) status; %d sup_minor: 0x%lx\n",
	    (void *)hsvcinfop, status, *supported_minor));

	return (status);
}

/*
 * Unregister an API group usage
 */
int
hsvc_unregister(hsvc_info_t *hsvcinfop)
{
	hsvc_t		**hsvcpp, *hsvcp;
	uint64_t	api_group;
	uint64_t	major, supported_minor;
	int		status = 0;

	if (hsvcinfop->hsvc_rev != HSVC_REV_1)
		return (EINVAL);

	major = hsvcinfop->hsvc_major;
	api_group = hsvcinfop->hsvc_group;

	HSVC_DEBUG(DBG_HSVC_UNREGISTER,
	    ("hsvc_unregister %p (0x%lx 0x%lx 0x%lx ID %s)\n",
	    (void *)hsvcinfop, api_group, major, hsvcinfop->hsvc_minor,
	    hsvcinfop->hsvc_modname));

	/*
	 * Search for the matching entry and return EINVAL if no match found.
	 * Otherwise, remove it from our list and unregister the API
	 * group if this was the last reference to that API group.
	 */
	mutex_enter(&hsvc_lock);

	for (hsvcpp = &hsvc_groups; (hsvcp = *hsvcpp) != NULL;
	    hsvcpp = &hsvcp->next) {
		if (hsvcp->group != api_group || hsvcp->major != major)
			continue;

		/*
		 * Search client list for a matching hsvcinfop entry
		 * and unlink it and decrement refcnt, if found.
		 */
		if (hsvc_unlink_client(hsvcp, hsvcinfop) < 0) {
			/* client not registered */
			status = EINVAL;
			break;
		}

		/*
		 * Client has been unlinked. If this was the last
		 * reference, unregister API group via OBP CIF
		 * interface.
		 */
		if (hsvcp->refcnt == 0) {
			uint64_t	hvstat;

			ASSERT(hsvcp->clients == NULL);
			hvstat = prom_set_sun4v_api_version(api_group, 0, 0,
			    &supported_minor);

			HSVC_DEBUG(DBG_HSVC_OBP_CIF,
			    (" prom unreg group: 0x%lx hvstat: 0x%lx\n",
			    api_group, hvstat));

			/*
			 * Note that the call to unnegotiate an API group
			 * may fail if anyone, including OBP, is using
			 * those services. However, the caller is done
			 * with this API group and should be allowed to
			 * unregister regardless of the outcome.
			 */
			*hsvcpp = hsvcp->next;
			hsvc_free(hsvcp);
		}
		break;
	}

	if (hsvcp == NULL)
		status = EINVAL;

	mutex_exit(&hsvc_lock);

	HSVC_DEBUG(DBG_HSVC_UNREGISTER,
	    ("hsvc_unregister %p status: %d\n", (void *)hsvcinfop, status));

	return (status);
}


/*
 * Get negotiated major/minor version number for an API group
 */
int
hsvc_version(uint64_t api_group, uint64_t *majorp, uint64_t *minorp)
{
	int status = 0;
	uint64_t hvstat;
	hsvc_t	*hsvcp;

	/*
	 * Check if the specified api_group is already in use.
	 * If so, return currently negotiated major/minor number.
	 * Otherwise, call OBP CIF interface to get the currently
	 * negotiated major/minor number.
	 */
	mutex_enter(&hsvc_lock);
	for (hsvcp = hsvc_groups; hsvcp != NULL; hsvcp = hsvcp->next)
		if (hsvcp->group == api_group)
			break;

	if (hsvcp) {
		*majorp = hsvcp->major;
		*minorp = hsvcp->minor;
	} else {
		hvstat = prom_get_sun4v_api_version(api_group, majorp, minorp);

		switch (hvstat) {
		case H_EBADTRAP:
			/*
			 * Older firmware does not support OBP CIF
			 * interface. If it's a pre-versioning group,
			 * then return default major/minor (i.e. 1/0).
			 * Otherwise, return EINVAL.
			 */
			if (pre_versioning_group(api_group)) {
				*majorp = 1;
				*minorp = 0;
			} else
				status = EINVAL;
			break;

		case H_EINVAL:
		default:
			status = EINVAL;
			break;

		}
	}
	mutex_exit(&hsvc_lock);

	HSVC_DEBUG(DBG_HSVC_VERSION,
	    ("hsvc_version(0x%lx) status: %d major: 0x%lx minor: 0x%lx\n",
	    api_group, status, *majorp, *minorp));

	return (status);
}

/*
 * Initialize framework data structures
 */
void
hsvc_init(void)
{
	int		i;
	hsvc_t		*hsvcp;

	/*
	 * Initialize global data structures
	 */
	mutex_init(&hsvc_lock, NULL, MUTEX_DEFAULT, NULL);
	hsvc_groups = NULL;
	hsvc_avail = NULL;

	/*
	 * Setup initial free list
	 */
	mutex_enter(&hsvc_lock);
	for (i = 0, hsvcp = &hsvc_resv_bufs[0];
	    i < HSVC_RESV_BUFS_MAX; i++, hsvcp++)
		hsvc_free(hsvcp);
	mutex_exit(&hsvc_lock);
}


/*
 * Hypervisor services to be negotiated at boot time.
 *
 * Note that the kernel needs to negotiate the HSVC_GROUP_SUN4V
 * API group first, before doing any other negotiation. Also, it
 * uses hypervisor services belonging to the HSVC_GROUP_CORE API
 * group only for itself.
 *
 * Note that the HSVC_GROUP_DIAG is negotiated on behalf of
 * any driver/module using DIAG services.
 */
typedef struct hsvc_info_unix_s {
	hsvc_info_t	hsvcinfo;
	int		required;
} hsvc_info_unix_t;

static hsvc_info_unix_t  hsvcinfo_unix[] = {
	{{HSVC_REV_1, NULL,	HSVC_GROUP_SUN4V,	1,	0, NULL}, 1},
	{{HSVC_REV_1, NULL,	HSVC_GROUP_CORE,	1,	1, NULL}, 1},
	{{HSVC_REV_1, NULL,	HSVC_GROUP_DIAG,	1,	0, NULL}, 1},
	{{HSVC_REV_1, NULL,	HSVC_GROUP_INTR,	1,	0, NULL}, 0},
};

#define	HSVCINFO_UNIX_CNT	(sizeof (hsvcinfo_unix) / sizeof (hsvc_info_t))
static char	*hsvcinfo_unix_modname = "unix";

/*
 * Initialize framework and register hypervisor services to be used
 * by the kernel.
 */
void
hsvc_setup()
{
	int			i, status;
	uint64_t		sup_minor;
	hsvc_info_unix_t	*hsvcinfop;

	/*
	 * Initialize framework
	 */
	hsvc_init();

	/*
	 * Negotiate versioning for required groups
	 */
	for (hsvcinfop = &hsvcinfo_unix[0], i = 0; i < HSVCINFO_UNIX_CNT;
	    i++, hsvcinfop++) {
		hsvcinfop->hsvcinfo.hsvc_private = NULL;
		hsvcinfop->hsvcinfo.hsvc_modname = hsvcinfo_unix_modname;
		status = hsvc_register(&(hsvcinfop->hsvcinfo), &sup_minor);

		if ((status != 0) && hsvcinfop->required) {
			cmn_err(CE_PANIC, "%s: cannot negotiate hypervisor "
			    "services - group: 0x%lx major: 0x%lx minor: 0x%lx"
			    " errno: %d\n", hsvcinfop->hsvcinfo.hsvc_modname,
			    hsvcinfop->hsvcinfo.hsvc_group,
			    hsvcinfop->hsvcinfo.hsvc_major,
			    hsvcinfop->hsvcinfo.hsvc_minor, status);
		}
	}
	HSVC_DUMP();
}
