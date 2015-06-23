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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/spl.h>
#include <sys/time.h>
#include <sys/varargs.h>
#include <ipp/ipp.h>
#include <ipp/ipp_impl.h>
#include <ipp/ipgpc/ipgpc.h>

/*
 * Debug switch.
 */

#if	defined(DEBUG)
#define	IPP_DBG
#endif

/*
 * Globals
 */

/*
 * ipp_action_count is not static because it is imported by inet/ipp_common.h
 */
uint32_t		ipp_action_count = 0;

static kmem_cache_t	*ipp_mod_cache = NULL;
static uint32_t		ipp_mod_count = 0;
static uint32_t		ipp_max_mod = IPP_NMOD;
static ipp_mod_t	**ipp_mod_byid;
static krwlock_t	ipp_mod_byid_lock[1];

static ipp_mod_id_t	ipp_next_mid = IPP_MOD_RESERVED + 1;
static ipp_mod_id_t	ipp_mid_limit;

static ipp_ref_t	*ipp_mod_byname[IPP_NBUCKET];
static krwlock_t	ipp_mod_byname_lock[1];

static kmem_cache_t	*ipp_action_cache = NULL;
static uint32_t		ipp_max_action = IPP_NACTION;
static ipp_action_t	**ipp_action_byid;
static krwlock_t	ipp_action_byid_lock[1];

static ipp_action_id_t	ipp_next_aid = IPP_ACTION_RESERVED + 1;
static ipp_action_id_t	ipp_aid_limit;

static ipp_ref_t	*ipp_action_byname[IPP_NBUCKET];
static krwlock_t	ipp_action_byname_lock[1];
static ipp_ref_t	*ipp_action_noname;

static kmem_cache_t	*ipp_packet_cache = NULL;
static uint_t		ipp_packet_classes = IPP_NCLASS;
static uint_t		ipp_packet_logging = 0;
static uint_t		ipp_packet_log_entries = IPP_NLOG;

/*
 * Prototypes
 */

void			ipp_init(void);

int			ipp_list_mods(ipp_mod_id_t **, int *);

ipp_mod_id_t		ipp_mod_lookup(const char *);
int			ipp_mod_name(ipp_mod_id_t, char **);
int			ipp_mod_register(const char *, ipp_ops_t *);
int			ipp_mod_unregister(ipp_mod_id_t);
int			ipp_mod_list_actions(ipp_mod_id_t, ipp_action_id_t **,
    int *);

ipp_action_id_t		ipp_action_lookup(const char *);
int			ipp_action_name(ipp_action_id_t, char **);
int			ipp_action_mod(ipp_action_id_t, ipp_mod_id_t *);
int			ipp_action_create(ipp_mod_id_t, const char *,
    nvlist_t **, ipp_flags_t, ipp_action_id_t *);
int			ipp_action_modify(ipp_action_id_t, nvlist_t **,
    ipp_flags_t);
int			ipp_action_destroy(ipp_action_id_t, ipp_flags_t);
int			ipp_action_info(ipp_action_id_t, int (*)(nvlist_t *,
    void *), void *, ipp_flags_t);
void			ipp_action_set_ptr(ipp_action_id_t, void *);
void			*ipp_action_get_ptr(ipp_action_id_t);
int			ipp_action_ref(ipp_action_id_t,	ipp_action_id_t,
    ipp_flags_t);
int			ipp_action_unref(ipp_action_id_t, ipp_action_id_t,
    ipp_flags_t);

int			ipp_packet_alloc(ipp_packet_t **, const char *,
    ipp_action_id_t);
void			ipp_packet_free(ipp_packet_t *);
int			ipp_packet_add_class(ipp_packet_t *, const char *,
    ipp_action_id_t);
int			ipp_packet_process(ipp_packet_t **);
int			ipp_packet_next(ipp_packet_t *, ipp_action_id_t);
void			ipp_packet_set_data(ipp_packet_t *, mblk_t *);
mblk_t			*ipp_packet_get_data(ipp_packet_t *);
void			ipp_packet_set_private(ipp_packet_t *, void *,
    void (*)(void *));
void			*ipp_packet_get_private(ipp_packet_t *);

int			ipp_stat_create(ipp_action_id_t, const char *, int,
    int (*)(ipp_stat_t *, void *, int), void *, ipp_stat_t **);
void			ipp_stat_install(ipp_stat_t *);
void			ipp_stat_destroy(ipp_stat_t *);
int			ipp_stat_named_init(ipp_stat_t *, const char *, uchar_t,
    ipp_named_t	*);
int			ipp_stat_named_op(ipp_named_t *, void *, int);

static int		ref_mod(ipp_action_t *, ipp_mod_t *);
static void		unref_mod(ipp_action_t *, ipp_mod_t *);
static int		is_mod_busy(ipp_mod_t *);
static int		get_mod_ref(ipp_mod_t *, ipp_action_id_t **, int *);
static int		get_mods(ipp_mod_id_t **bufp, int *);
static ipp_mod_id_t	find_mod(const char *);
static int		alloc_mod(const char *, ipp_mod_id_t *);
static void		free_mod(ipp_mod_t *);
static ipp_mod_t	*hold_mod(ipp_mod_id_t);
static void		rele_mod(ipp_mod_t *);
static ipp_mod_id_t	get_mid(void);

static int		condemn_action(ipp_ref_t **, ipp_action_t *);
static int		destroy_action(ipp_action_t *, ipp_flags_t);
static int		ref_action(ipp_action_t *, ipp_action_t *);
static int		unref_action(ipp_action_t *, ipp_action_t *);
static int		is_action_refd(ipp_action_t *);
static ipp_action_id_t	find_action(const char *);
static int		alloc_action(const char *, ipp_action_id_t *);
static void		free_action(ipp_action_t *);
static ipp_action_t	*hold_action(ipp_action_id_t);
static void		rele_action(ipp_action_t *);
static ipp_action_id_t	get_aid(void);

static int		alloc_packet(const char *, ipp_action_id_t,
    ipp_packet_t **);
static int		realloc_packet(ipp_packet_t *);
static void		free_packet(ipp_packet_t *);

static int		hash(const char *);
static int		update_stats(kstat_t *, int);
static void		init_mods(void);
static void		init_actions(void);
static void		init_packets(void);
static int		mod_constructor(void *, void *, int);
static void		mod_destructor(void *, void *);
static int		action_constructor(void *, void *, int);
static void		action_destructor(void *, void *);
static int		packet_constructor(void *, void *, int);
static void		packet_destructor(void *, void *);

/*
 * Debug message macros
 */

#ifdef	IPP_DBG

#define	DBG_MOD		0x00000001ull
#define	DBG_ACTION	0x00000002ull
#define	DBG_PACKET	0x00000004ull
#define	DBG_STATS	0x00000008ull
#define	DBG_LIST	0x00000010ull

static uint64_t		ipp_debug_flags =
/*
 * DBG_PACKET |
 * DBG_STATS |
 * DBG_LIST |
 * DBG_MOD |
 * DBG_ACTION |
 */
0;

static kmutex_t	debug_mutex[1];

/*PRINTFLIKE3*/
static void ipp_debug(uint64_t, const char *, char *, ...)
	__KPRINTFLIKE(3);

#define	DBG0(_type, _fmt)		    			\
	ipp_debug((_type), __FN__, (_fmt));

#define	DBG1(_type, _fmt, _a1) 					\
	ipp_debug((_type), __FN__, (_fmt), (_a1));

#define	DBG2(_type, _fmt, _a1, _a2)				\
	ipp_debug((_type), __FN__, (_fmt), (_a1), (_a2));

#define	DBG3(_type, _fmt, _a1, _a2, _a3)			\
	ipp_debug((_type), __FN__, (_fmt), (_a1), (_a2),	\
	    (_a3));

#define	DBG4(_type, _fmt, _a1, _a2, _a3, _a4)			\
	ipp_debug((_type), __FN__, (_fmt), (_a1), (_a2),	\
	    (_a3), (_a4));

#define	DBG5(_type, _fmt, _a1, _a2, _a3, _a4, _a5)		\
	ipp_debug((_type), __FN__, (_fmt), (_a1), (_a2),	\
	    (_a3), (_a4), (_a5));

#else	/* IPP_DBG */

#define	DBG0(_type, _fmt)
#define	DBG1(_type, _fmt, _a1)
#define	DBG2(_type, _fmt, _a1, _a2)
#define	DBG3(_type, _fmt, _a1, _a2, _a3)
#define	DBG4(_type, _fmt, _a1, _a2, _a3, _a4)
#define	DBG5(_type, _fmt, _a1, _a2, _a3, _a4, _a5)

#endif	/* IPP_DBG */

/*
 * Lock macros
 */

#define	LOCK_MOD(_imp, _rw)						\
	rw_enter((_imp)->ippm_lock, (_rw))
#define	UNLOCK_MOD(_imp)						\
	rw_exit((_imp)->ippm_lock)

#define	LOCK_ACTION(_ap, _rw)						\
	rw_enter((_ap)->ippa_lock, (_rw))
#define	UNLOCK_ACTION(_imp)						\
	rw_exit((_imp)->ippa_lock)

#define	CONFIG_WRITE_START(_ap)						\
	CONFIG_LOCK_ENTER((_ap)->ippa_config_lock, CL_WRITE)

#define	CONFIG_WRITE_END(_ap)						\
	CONFIG_LOCK_EXIT((_ap)->ippa_config_lock)

#define	CONFIG_READ_START(_ap)						\
	CONFIG_LOCK_ENTER((_ap)->ippa_config_lock, CL_READ)

#define	CONFIG_READ_END(_ap)						\
	CONFIG_LOCK_EXIT((_ap)->ippa_config_lock)

/*
 * Exported functions
 */

#define	__FN__	"ipp_init"
void
ipp_init(
	void)
{
#ifdef	IPP_DBG
	mutex_init(debug_mutex, NULL, MUTEX_ADAPTIVE,
	    (void *)ipltospl(LOCK_LEVEL));
#endif	/* IPP_DBG */

	/*
	 * Initialize module and action structure caches and associated locks.
	 */

	init_mods();
	init_actions();
	init_packets();
}
#undef	__FN__

#define	__FN__	"ipp_list_mods"
int
ipp_list_mods(
	ipp_mod_id_t	**bufp,
	int		*neltp)
{
	ASSERT(bufp != NULL);
	ASSERT(neltp != NULL);

	return (get_mods(bufp, neltp));
}
#undef	__FN__

/*
 * Module manipulation interface.
 */

#define	__FN__	"ipp_mod_lookup"
ipp_mod_id_t
ipp_mod_lookup(
	const char	*modname)
{
	ipp_mod_id_t	mid;
#define	FIRST_TIME	0
	int		try = FIRST_TIME;

	/*
	 * Sanity check the module name.
	 */

	if (modname == NULL || strlen(modname) > MAXNAMELEN - 1)
		return (IPP_MOD_INVAL);

try_again:
	if ((mid = find_mod(modname)) == IPP_MOD_INVAL) {

		/*
		 * Module not installed.
		 */

		if (try++ == FIRST_TIME) {

			/*
			 * This is the first attempt to find the module so
			 * try to 'demand load' it.
			 */

			DBG1(DBG_MOD, "loading module '%s'\n", modname);
			(void) modload("ipp", (char *)modname);
			goto try_again;
		}
	}

	return (mid);

#undef	FIRST_TIME
}
#undef	__FN__

#define	__FN__	"ipp_mod_name"
int
ipp_mod_name(
	ipp_mod_id_t	mid,
	char		**modnamep)
{
	ipp_mod_t	*imp;
	char		*modname;
	char		*buf;

	ASSERT(modnamep != NULL);

	/*
	 * Translate the module id into the module pointer.
	 */

	if ((imp = hold_mod(mid)) == NULL)
		return (ENOENT);

	LOCK_MOD(imp, RW_READER);
	modname = imp->ippm_name;

	/*
	 * Allocate a buffer to pass back to the caller.
	 */

	if ((buf = kmem_zalloc(strlen(modname) + 1, KM_NOSLEEP)) == NULL) {
		UNLOCK_MOD(imp);
		rele_mod(imp);
		return (ENOMEM);
	}

	/*
	 * Copy the module name into the buffer.
	 */

	(void) strcpy(buf, modname);
	UNLOCK_MOD(imp);

	*modnamep = buf;

	rele_mod(imp);
	return (0);
}
#undef	__FN__

#define	__FN__	"ipp_mod_register"
int
ipp_mod_register(
	const char	*modname,
	ipp_ops_t	*ipp_ops)
{
	ipp_mod_id_t	mid;
	ipp_mod_t	*imp;
	int		rc;

	ASSERT(ipp_ops != NULL);

	/*
	 * Sanity check the module name.
	 */

	if (modname == NULL || strlen(modname) > MAXNAMELEN - 1)
		return (EINVAL);

	/*
	 * Allocate a module structure.
	 */

	if ((rc = alloc_mod(modname, &mid)) != 0)
		return (rc);

	imp = hold_mod(mid);
	ASSERT(imp != NULL);

	/*
	 * Make module available for use.
	 */

	LOCK_MOD(imp, RW_WRITER);
	DBG1(DBG_MOD, "registering module '%s'\n", imp->ippm_name);
	imp->ippm_ops = ipp_ops;
	imp->ippm_state = IPP_MODSTATE_AVAILABLE;
	UNLOCK_MOD(imp);

	rele_mod(imp);
	return (0);
}
#undef	__FN__

#define	__FN__	"ipp_mod_unregister"
int
ipp_mod_unregister(
	ipp_mod_id_t	mid)
{
	ipp_mod_t	*imp;

	/*
	 * Translate the module id into the module pointer.
	 */

	if ((imp = hold_mod(mid)) == NULL)
		return (ENOENT);

	LOCK_MOD(imp, RW_WRITER);
	ASSERT(imp->ippm_state == IPP_MODSTATE_AVAILABLE);

	/*
	 * Check to see if there are any actions that reference the module.
	 */

	if (is_mod_busy(imp)) {
		UNLOCK_MOD(imp);
		rele_mod(imp);
		return (EBUSY);
	}

	/*
	 * Prevent further use of the module.
	 */

	DBG1(DBG_MOD, "unregistering module '%s'\n", imp->ippm_name);
	imp->ippm_state = IPP_MODSTATE_PROTO;
	imp->ippm_ops = NULL;
	UNLOCK_MOD(imp);

	/*
	 * Free the module structure.
	 */

	free_mod(imp);
	rele_mod(imp);

	return (0);
}
#undef	__FN__

#define	__FN__	"ipp_mod_list_actions"
int
ipp_mod_list_actions(
	ipp_mod_id_t	mid,
	ipp_action_id_t	**bufp,
	int		*neltp)
{
	ipp_mod_t	*imp;
	int		rc;

	ASSERT(bufp != NULL);
	ASSERT(neltp != NULL);

	/*
	 * Translate the module id into the module pointer.
	 */

	if ((imp = hold_mod(mid)) == NULL)
		return (ENOENT);

	/*
	 * Get the list of actions referencing the module.
	 */

	LOCK_MOD(imp, RW_READER);
	rc = get_mod_ref(imp, bufp, neltp);
	UNLOCK_MOD(imp);

	rele_mod(imp);
	return (rc);
}
#undef	__FN__

/*
 * Action manipulation interface.
 */

#define	__FN__	"ipp_action_lookup"
ipp_action_id_t
ipp_action_lookup(
	const char	*aname)
{
	if (aname == NULL)
		return (IPP_ACTION_INVAL);

	/*
	 * Check for special case 'virtual action' names.
	 */

	if (strcmp(aname, IPP_ANAME_CONT) == 0)
		return (IPP_ACTION_CONT);
	else if (strcmp(aname, IPP_ANAME_DEFER) == 0)
		return (IPP_ACTION_DEFER);
	else if (strcmp(aname, IPP_ANAME_DROP) == 0)
		return (IPP_ACTION_DROP);

	/*
	 * Now check real actions.
	 */

	return (find_action(aname));
}
#undef	__FN__

#define	__FN__	"ipp_action_name"
int
ipp_action_name(
	ipp_action_id_t	aid,
	char		**anamep)
{
	ipp_action_t	*ap;
	char		*aname;
	char		*buf;
	int		rc;

	ASSERT(anamep != NULL);

	/*
	 * Check for special case 'virtual action' ids.
	 */

	switch (aid) {
	case IPP_ACTION_CONT:
		ap = NULL;
		aname = IPP_ANAME_CONT;
		break;
	case IPP_ACTION_DEFER:
		ap = NULL;
		aname = IPP_ANAME_DEFER;
		break;
	case IPP_ACTION_DROP:
		ap = NULL;
		aname = IPP_ANAME_DROP;
		break;
	default:

		/*
		 * Not a special case. Check for a real action.
		 */

		if ((ap = hold_action(aid)) == NULL)
			return (ENOENT);

		LOCK_ACTION(ap, RW_READER);
		aname = ap->ippa_name;
		break;
	}

	/*
	 * Allocate a buffer to pass back to the caller.
	 */

	if ((buf = kmem_zalloc(strlen(aname) + 1, KM_NOSLEEP)) == NULL) {
		rc = ENOMEM;
		goto done;
	}

	/*
	 * Copy the action name into the buffer.
	 */

	(void) strcpy(buf, aname);
	*anamep = buf;
	rc = 0;
done:
	/*
	 * Unlock the action if necessary (i.e. it wasn't a virtual action).
	 */

	if (ap != NULL) {
		UNLOCK_ACTION(ap);
		rele_action(ap);
	}

	return (rc);
}
#undef	__FN__

#define	__FN__	"ipp_action_mod"
int
ipp_action_mod(
	ipp_action_id_t	aid,
	ipp_mod_id_t	*midp)
{
	ipp_action_t	*ap;
	ipp_mod_t	*imp;

	ASSERT(midp != NULL);

	/*
	 * Return an error for  'virtual action' ids.
	 */

	switch (aid) {
	case IPP_ACTION_CONT:
	/*FALLTHRU*/
	case IPP_ACTION_DEFER:
	/*FALLTHRU*/
	case IPP_ACTION_DROP:
		return (EINVAL);
	default:
		break;
	}

	/*
	 * This is a real action.
	 */

	if ((ap = hold_action(aid)) == NULL)
		return (ENOENT);

	/*
	 * Check that the action is not in prototype state.
	 */

	LOCK_ACTION(ap, RW_READER);
	if (ap->ippa_state == IPP_ASTATE_PROTO) {
		UNLOCK_ACTION(ap);
		rele_action(ap);
		return (ENOENT);
	}

	imp = ap->ippa_mod;
	ASSERT(imp != NULL);
	UNLOCK_ACTION(ap);

	*midp = imp->ippm_id;

	rele_action(ap);
	return (0);
}
#undef	__FN__

#define	__FN__	"ipp_action_create"
int
ipp_action_create(
	ipp_mod_id_t	mid,
	const char	*aname,
	nvlist_t	**nvlpp,
	ipp_flags_t	flags,
	ipp_action_id_t	*aidp)
{
	ipp_ops_t	*ippo;
	ipp_mod_t	*imp;
	ipp_action_id_t	aid;
	ipp_action_t	*ap;
	int		rc;

	ASSERT(nvlpp != NULL);
	ASSERT(*nvlpp != NULL);

	/*
	 * Sanity check the action name (NULL means the framework chooses the
	 * name).
	 */

	if (aname != NULL && strlen(aname) > MAXNAMELEN - 1)
		return (EINVAL);

	/*
	 * Translate the module id into the module pointer.
	 */

	if ((imp = hold_mod(mid)) == NULL)
		return (ENOENT);

	/*
	 * Allocate an action.
	 */

	if ((rc = alloc_action(aname, &aid)) != 0) {
		rele_mod(imp);
		return (rc);
	}

	ap = hold_action(aid);
	ASSERT(ap != NULL);

	/*
	 * Note that the action is in the process of creation/destruction.
	 */

	LOCK_ACTION(ap, RW_WRITER);
	ap->ippa_state = IPP_ASTATE_CONFIG_PENDING;

	/*
	 * Reference the module for which the action is being created.
	 */

	LOCK_MOD(imp, RW_WRITER);
	if ((rc = ref_mod(ap, imp)) != 0) {
		UNLOCK_MOD(imp);
		ap->ippa_state = IPP_ASTATE_PROTO;
		UNLOCK_ACTION(ap);

		free_action(ap);
		rele_action(ap);
		rele_mod(imp);
		return (rc);
	}

	UNLOCK_ACTION(ap);

	ippo = imp->ippm_ops;
	ASSERT(ippo != NULL);
	UNLOCK_MOD(imp);

	/*
	 * Call into the module to create the action context.
	 */

	CONFIG_WRITE_START(ap);
	DBG2(DBG_ACTION, "creating action '%s' in module '%s'\n",
	    ap->ippa_name, imp->ippm_name);
	if ((rc = ippo->ippo_action_create(ap->ippa_id, nvlpp, flags)) != 0) {
		LOCK_ACTION(ap, RW_WRITER);
		LOCK_MOD(imp, RW_WRITER);
		unref_mod(ap, imp);
		UNLOCK_MOD(imp);
		ap->ippa_state = IPP_ASTATE_PROTO;
		UNLOCK_ACTION(ap);

		CONFIG_WRITE_END(ap);

		free_action(ap);
		rele_action(ap);
		rele_mod(imp);
		return (rc);
	}
	CONFIG_WRITE_END(ap);

	/*
	 * Make the action available for use.
	 */

	LOCK_ACTION(ap, RW_WRITER);
	ap->ippa_state = IPP_ASTATE_AVAILABLE;
	if (aidp != NULL)
		*aidp = ap->ippa_id;
	UNLOCK_ACTION(ap);

	rele_action(ap);
	rele_mod(imp);
	return (0);
}
#undef	__FN__

#define	__FN__	"ipp_action_destroy"
int
ipp_action_destroy(
	ipp_action_id_t	aid,
	ipp_flags_t	flags)
{
	ipp_ref_t	*rp = NULL;
	ipp_ref_t	*tmp;
	ipp_action_t	*ap;
	int		rc;

	/*
	 * Translate the action id into the action pointer.
	 */

	if ((ap = hold_action(aid)) == NULL)
		return (ENOENT);

	/*
	 * Set the condemned action list pointer and destroy the action.
	 */

	ap->ippa_condemned = &rp;
	if ((rc = destroy_action(ap, flags)) == 0) {

		/*
		 * Destroy any other actions condemned by the destruction of
		 * the first action.
		 */

		for (tmp = rp; tmp != NULL; tmp = tmp->ippr_nextp) {
			ap = tmp->ippr_action;
			ap->ippa_condemned = &rp;
			(void) destroy_action(ap, flags);
		}
	} else {

		/*
		 * Unreference any condemned actions since the destruction of
		 * the first action failed.
		 */

		for (tmp = rp; tmp != NULL; tmp = tmp->ippr_nextp) {
			ap = tmp->ippr_action;
			rele_action(ap);
		}
	}

	/*
	 * Clean up the condemned list.
	 */

	while (rp != NULL) {
		tmp = rp;
		rp = rp->ippr_nextp;
		kmem_free(tmp, sizeof (ipp_ref_t));
	}

	return (rc);
}
#undef	__FN__

#define	__FN__	"ipp_action_modify"
int
ipp_action_modify(
	ipp_action_id_t	aid,
	nvlist_t	**nvlpp,
	ipp_flags_t	flags)
{
	ipp_action_t	*ap;
	ipp_ops_t	*ippo;
	ipp_mod_t	*imp;
	int		rc;

	ASSERT(nvlpp != NULL);
	ASSERT(*nvlpp != NULL);

	/*
	 * Translate the action id into the action pointer.
	 */

	if ((ap = hold_action(aid)) == NULL)
		return (ENOENT);

	/*
	 * Check that the action is either available for use or is in the
	 * process of creation/destruction.
	 *
	 * NOTE: It is up to the module to lock multiple configuration
	 *	 operations against each other if necessary.
	 */

	LOCK_ACTION(ap, RW_READER);
	if (ap->ippa_state != IPP_ASTATE_AVAILABLE &&
	    ap->ippa_state != IPP_ASTATE_CONFIG_PENDING) {
		UNLOCK_ACTION(ap);
		rele_action(ap);
		return (EPROTO);
	}

	imp = ap->ippa_mod;
	ASSERT(imp != NULL);
	UNLOCK_ACTION(ap);

	ippo = imp->ippm_ops;
	ASSERT(ippo != NULL);

	/*
	 * Call into the module to modify the action context.
	 */

	DBG1(DBG_ACTION, "modifying action '%s'\n", ap->ippa_name);
	CONFIG_WRITE_START(ap);
	rc = ippo->ippo_action_modify(aid, nvlpp, flags);
	CONFIG_WRITE_END(ap);

	rele_action(ap);
	return (rc);
}
#undef	__FN__

#define	__FN__	"ipp_action_info"
int
ipp_action_info(
	ipp_action_id_t	aid,
	int		(*fn)(nvlist_t *, void *),
	void		*arg,
	ipp_flags_t    	flags)
{
	ipp_action_t	*ap;
	ipp_mod_t	*imp;
	ipp_ops_t	*ippo;
	int		rc;

	/*
	 * Translate the action id into the action pointer.
	 */

	if ((ap = hold_action(aid)) == NULL)
		return (ENOENT);

	/*
	 * Check that the action is available for use. We don't want to
	 * read back parameters while the action is in the process of
	 * creation/destruction.
	 */

	LOCK_ACTION(ap, RW_READER);
	if (ap->ippa_state != IPP_ASTATE_AVAILABLE) {
		UNLOCK_ACTION(ap);
		rele_action(ap);
		return (EPROTO);
	}

	imp = ap->ippa_mod;
	ASSERT(imp != NULL);
	UNLOCK_ACTION(ap);

	ippo = imp->ippm_ops;
	ASSERT(ippo != NULL);

	/*
	 * Call into the module to get the action configuration information.
	 */

	DBG1(DBG_ACTION,
	    "getting configuration information from action '%s'\n",
	    ap->ippa_name);
	CONFIG_READ_START(ap);
	if ((rc = ippo->ippo_action_info(aid, fn, arg, flags)) != 0) {
		CONFIG_READ_END(ap);
		rele_action(ap);
		return (rc);
	}
	CONFIG_READ_END(ap);

	rele_action(ap);
	return (0);
}
#undef	__FN__

#define	__FN__	"ipp_action_set_ptr"
void
ipp_action_set_ptr(
	ipp_action_id_t	aid,
	void		*ptr)
{
	ipp_action_t	*ap;

	/*
	 * Translate the action id into the action pointer.
	 */

	ap = hold_action(aid);
	ASSERT(ap != NULL);

	/*
	 * Set the private data pointer.
	 */

	ap->ippa_ptr = ptr;
	rele_action(ap);
}
#undef	__FN__

#define	__FN__	"ipp_action_get_ptr"
void *
ipp_action_get_ptr(
	ipp_action_id_t	aid)
{
	ipp_action_t	*ap;
	void		*ptr;

	/*
	 * Translate the action id into the action pointer.
	 */

	ap = hold_action(aid);
	ASSERT(ap != NULL);

	/*
	 * Return the private data pointer.
	 */

	ptr = ap->ippa_ptr;
	rele_action(ap);

	return (ptr);
}
#undef	__FN__

#define	__FN__	"ipp_action_ref"
/*ARGSUSED*/
int
ipp_action_ref(
	ipp_action_id_t	aid,
	ipp_action_id_t	ref_aid,
	ipp_flags_t	flags)
{
	ipp_action_t	*ap;
	ipp_action_t	*ref_ap;
	int		rc;

	/*
	 * Actions are not allowed to reference themselves.
	 */

	if (aid == ref_aid)
		return (EINVAL);

	/*
	 * Check for a special case 'virtual action' id.
	 */

	switch (ref_aid) {
	case IPP_ACTION_CONT:
	/*FALLTHRU*/
	case IPP_ACTION_DEFER:
	/*FALLTHRU*/
	case IPP_ACTION_DROP:
		return (0);
	default:
		break;
	}

	/*
	 * Translate the action ids into action pointers.
	 */

	if ((ap = hold_action(aid)) == NULL)
		return (ENOENT);

	if ((ref_ap = hold_action(ref_aid)) == NULL) {
		rele_action(ap);
		return (ENOENT);
	}

	LOCK_ACTION(ap, RW_WRITER);
	LOCK_ACTION(ref_ap, RW_WRITER);

	if (ref_ap->ippa_state != IPP_ASTATE_AVAILABLE) {
		UNLOCK_ACTION(ref_ap);
		UNLOCK_ACTION(ap);

		rele_action(ref_ap);
		rele_action(ap);
		return (EPROTO);
	}

	/*
	 * Create references between the two actions.
	 */

	rc = ref_action(ap, ref_ap);
	UNLOCK_ACTION(ref_ap);
	UNLOCK_ACTION(ap);

	rele_action(ref_ap);
	rele_action(ap);
	return (rc);
}
#undef	__FN__

#define	__FN__	"ipp_action_unref"
int
ipp_action_unref(
	ipp_action_id_t	aid,
	ipp_action_id_t	ref_aid,
	ipp_flags_t	flags)
{
	ipp_action_t	*ap;
	ipp_action_t	*ref_ap;
	int		ref_is_busy;
	int		rc;

	if (aid == ref_aid)
		return (EINVAL);

	/*
	 * Check for a special case 'virtual action' id.
	 */

	switch (ref_aid) {
	case IPP_ACTION_CONT:
	/*FALLTHRU*/
	case IPP_ACTION_DEFER:
	/*FALLTHRU*/
	case IPP_ACTION_DROP:
		return (0);
	default:
		break;
	}

	/*
	 * Translate the action ids into action pointers.
	 */

	if ((ap = hold_action(aid)) == NULL)
		return (ENOENT);

	if ((ref_ap = hold_action(ref_aid)) == NULL) {
		rele_action(ap);
		return (ENOENT);
	}

	LOCK_ACTION(ap, RW_WRITER);
	LOCK_ACTION(ref_ap, RW_WRITER);

	/*
	 * Remove the reference between the actions.
	 */

	if ((rc = unref_action(ap, ref_ap)) != 0) {
		UNLOCK_ACTION(ref_ap);
		UNLOCK_ACTION(ap);
		rele_action(ref_ap);
		rele_action(ap);
		return (rc);
	}

	ref_is_busy = is_action_refd(ref_ap);

	UNLOCK_ACTION(ref_ap);
	UNLOCK_ACTION(ap);

	if (flags & IPP_DESTROY_REF) {
		if (!ref_is_busy) {

			/*
			 * Condemn the action so that it will be destroyed.
			 */

			(void) condemn_action(ap->ippa_condemned, ref_ap);
			return (0);
		}
	}

	rele_action(ref_ap);
	rele_action(ap);
	return (0);
}
#undef	__FN__

/*
 * Packet manipulation interface.
 */

#define	__FN__	"ipp_packet_alloc"
int
ipp_packet_alloc(
	ipp_packet_t	**ppp,
	const char	*name,
	ipp_action_id_t	aid)
{
	ipp_packet_t	*pp;
	int		rc;

	ASSERT(ppp != NULL);

	/*
	 * A name is required.
	 */

	if (name == NULL || strlen(name) > MAXNAMELEN - 1)
		return (EINVAL);

	/*
	 * Allocate a packet structure from the cache.
	 */

	if ((rc = alloc_packet(name, aid, &pp)) != 0)
		return (rc);

	if (ipp_packet_logging != 0 && pp->ippp_log == NULL) {

		/*
		 * Logging is turned on but there's no log buffer. We need
		 * to allocate one.
		 */
		if ((pp->ippp_log = kmem_alloc(
		    ipp_packet_log_entries * sizeof (ipp_log_t),
		    KM_NOSLEEP)) != NULL) {
			pp->ippp_log_limit = ipp_packet_log_entries - 1;
			pp->ippp_log_windex = 0;
		}
	} else if (ipp_packet_logging == 0 && pp->ippp_log != NULL) {

		/*
		 * A log buffer is present but logging has been turned off.
		 * Free the buffer now,
		 */

		kmem_free(pp->ippp_log,
		    (pp->ippp_log_limit + 1) * sizeof (ipp_log_t));
		pp->ippp_log = NULL;
		pp->ippp_log_limit = 0;
		pp->ippp_log_windex = 0;
	}

	*ppp = pp;
	return (0);
}
#undef	__FN__

#define	__FN__	"ipp_packet_free"
void
ipp_packet_free(
	ipp_packet_t	*pp)
{

	ASSERT(pp != NULL);

	/*
	 * If there is a private structure pointer set, call its free
	 * function.
	 */

	if (pp->ippp_private) {
		pp->ippp_private_free(pp->ippp_private);
		pp->ippp_private = NULL;
		pp->ippp_private_free = NULL;
	}

	/*
	 * Free the packet structure back to the cache.
	 */

	free_packet(pp);
}
#undef	__FN__

#define	__FN__	"ipp_packet_add_class"
int
ipp_packet_add_class(
	ipp_packet_t	*pp,
	const char	*name,
	ipp_action_id_t	aid)
{
	ipp_class_t	*cp;
	int		rc;

	ASSERT(pp != NULL);

	/*
	 * A name is required.
	 */

	if (name == NULL || strlen(name) > MAXNAMELEN - 1)
		return (EINVAL);

	/*
	 * Check if there is an available class structure.
	 */

	if (pp->ippp_class_windex == pp->ippp_class_limit) {

		/*
		 * No more structures. Re-allocate the array.
		 */

		if ((rc = realloc_packet(pp)) != 0)
			return (rc);
	}
	ASSERT(pp->ippp_class_windex < pp->ippp_class_limit);

	/*
	 * Set up a new class structure.
	 */

	cp = &(pp->ippp_class_array[pp->ippp_class_windex++]);
	(void) strcpy(cp->ippc_name, name);
	cp->ippc_aid = aid;

	return (0);
}
#undef	__FN__

#define	__FN__	"ipp_packet_process"
int
ipp_packet_process(
	ipp_packet_t	**ppp)
{
	ipp_packet_t	*pp;
	ipp_action_id_t	aid;
	ipp_class_t	*cp;
	ipp_log_t	*lp;
	ipp_action_t	*ap;
	ipp_mod_t	*imp;
	ipp_ops_t	*ippo;
	int		rc;

	ASSERT(ppp != NULL);
	pp = *ppp;
	ASSERT(pp != NULL);

	/*
	 * Walk the class list.
	 */

	while (pp->ippp_class_rindex < pp->ippp_class_windex) {
		cp = &(pp->ippp_class_array[pp->ippp_class_rindex]);

		/*
		 * While there is a real action to invoke...
		 */

		aid = cp->ippc_aid;
		while (aid != IPP_ACTION_CONT &&
		    aid != IPP_ACTION_DEFER &&
		    aid != IPP_ACTION_DROP) {

			ASSERT(aid != IPP_ACTION_INVAL);

			/*
			 * Translate the action id to the action pointer.
			 */

			if ((ap = hold_action(aid)) == NULL) {
				DBG1(DBG_PACKET,
				    "action id '%d' not found\n", aid);
				return (ENOENT);
			}

			/*
			 * Check that the action is available for use...
			 */
			LOCK_ACTION(ap, RW_READER);
			if (ap->ippa_state != IPP_ASTATE_AVAILABLE) {
				UNLOCK_ACTION(ap);
				rele_action(ap);
				return (EPROTO);
			}

			/*
			 * Increment the action's packet count to note that
			 * it's being used.
			 *
			 * NOTE: We only have a read lock, so we need to use
			 *	 atomic_add_32(). The read lock is still
			 *	 important though as it is crucial to block
			 *	 out a destroy operation between the action
			 *	 state being checked and the packet count
			 *	 being incremented.
			 */

			atomic_inc_32(&(ap->ippa_packets));

			imp = ap->ippa_mod;
			ASSERT(imp != NULL);
			UNLOCK_ACTION(ap);

			ippo = imp->ippm_ops;
			ASSERT(ippo != NULL);

			/*
			 * If there's a log, grab the next entry and fill it
			 * in.
			 */

			if (pp->ippp_log != NULL &&
			    pp->ippp_log_windex <= pp->ippp_log_limit) {
				lp = &(pp->ippp_log[pp->ippp_log_windex++]);
				lp->ippl_aid = aid;
				(void) strcpy(lp->ippl_name, cp->ippc_name);
				gethrestime(&lp->ippl_begin);
			} else {
				lp = NULL;
			}

			/*
			 * Invoke the action.
			 */

			rc = ippo->ippo_action_invoke(aid, pp);

			/*
			 * Also log the time that the action finished
			 * processing.
			 */

			if (lp != NULL)
				gethrestime(&lp->ippl_end);

			/*
			 * Decrement the packet count.
			 */

			atomic_dec_32(&(ap->ippa_packets));

			/*
			 * If the class' action id is the same now as it was
			 * before then clearly no 'next action' has been set.
			 * This is a protocol error.
			 */

			if (cp->ippc_aid == aid) {
				DBG1(DBG_PACKET,
				    "action '%s' did not set next action\n",
				    ap->ippa_name);
				rele_action(ap);
				return (EPROTO);
			}

			/*
			 * The action did not complete successfully. Terminate
			 * packet processing.
			 */

			if (rc != 0) {
				DBG2(DBG_PACKET,
				    "action error '%d' from action '%s'\n",
				    rc, ap->ippa_name);
				rele_action(ap);
				return (rc);
			}

			rele_action(ap);

			/*
			 * Look at the next action.
			 */

			aid = cp->ippc_aid;
		}

		/*
		 * No more real actions to invoke, check for 'virtual' ones.
		 */

		/*
		 * Packet deferred: module has held onto packet for processing
		 * later.
		 */

		if (cp->ippc_aid == IPP_ACTION_DEFER) {
			*ppp = NULL;
			return (0);
		}

		/*
		 * Packet dropped: free the packet and discontinue processing.
		 */

		if (cp->ippc_aid == IPP_ACTION_DROP) {
			freemsg(pp->ippp_data);
			ipp_packet_free(pp);
			*ppp = NULL;
			return (0);
		}

		/*
		 * Must be 'continue processing': move onto the next class.
		 */

		ASSERT(cp->ippc_aid == IPP_ACTION_CONT);
		pp->ippp_class_rindex++;
	}

	return (0);
}
#undef	__FN__

#define	__FN__	"ipp_packet_next"
int
ipp_packet_next(
	ipp_packet_t	*pp,
	ipp_action_id_t	aid)
{
	ipp_action_t	*ap;
	ipp_class_t	*cp;

	ASSERT(pp != NULL);

	cp = &(pp->ippp_class_array[pp->ippp_class_rindex]);
	ASSERT(cp != NULL);

	/*
	 * Check for a special case 'virtual action' id.
	 */

	switch (aid) {
	case IPP_ACTION_INVAL:
		return (EINVAL);
	case IPP_ACTION_DEFER:
	/*FALLTHRU*/
	case IPP_ACTION_CONT:
	/*FALLTHRU*/
	case IPP_ACTION_DROP:
		break;
	default:

		/*
		 * Not a virtual action so try to translate the action id
		 * into the action pointer to confirm the actions existence.
		 */

		if ((ap = hold_action(aid)) == NULL) {
			DBG0(DBG_PACKET, "invalid action\n");
			return (ENOENT);
		}
		rele_action(ap);

		break;
	}

	/*
	 * Set the class' new action id.
	 */

	cp->ippc_aid = aid;

	return (0);
}
#undef	__FN__

#define	__FN__	"ipp_packet_set_data"
void
ipp_packet_set_data(
	ipp_packet_t	*pp,
	mblk_t		*data)
{
	ASSERT(pp != NULL);
	pp->ippp_data = data;
}
#undef	__FN__

#define	__FN__	"ipp_packet_get_data"
mblk_t *
ipp_packet_get_data(
	ipp_packet_t	*pp)
{
	ASSERT(pp != NULL);
	return (pp->ippp_data);
}
#undef	__FN__

#define	__FN__	"ipp_packet_set_private"
void
ipp_packet_set_private(
	ipp_packet_t	*pp,
	void		*buf,
	void		(*free_func)(void *))
{
	ASSERT(pp != NULL);
	ASSERT(free_func != NULL);

	pp->ippp_private = buf;
	pp->ippp_private_free = free_func;
}
#undef	__FN__

#define	__FN__	"ipp_packet_get_private"
void *
ipp_packet_get_private(
	ipp_packet_t	*pp)
{
	ASSERT(pp != NULL);
	return (pp->ippp_private);
}
#undef	__FN__

/*
 * Statistics interface.
 */

#define	__FN__	"ipp_stat_create"
int
ipp_stat_create(
	ipp_action_id_t	aid,
	const char	*name,
	int		nstat,
	int		(*update)(ipp_stat_t *, void *, int),
	void		*arg,
	ipp_stat_t	**spp)
{
	ipp_action_t	*ap;
	ipp_mod_t	*imp;
	ipp_stat_impl_t	*sip;
	ipp_stat_t	*sp;
	kstat_t		*ksp;
	char		*class;
	char		*modname;
	int		instance;

	ASSERT(spp != NULL);

	/*
	 * Sanity check the arguments.
	 */

	if (name == NULL || nstat <= 0 || update == NULL)
		return (EINVAL);

	/*
	 * Translate the action id into the action pointer.
	 */

	if ((ap = hold_action(aid)) == NULL)
		return (ENOENT);

	/*
	 * Grab relevant action and module information.
	 */

	LOCK_ACTION(ap, RW_READER);
	class = ap->ippa_name;
	instance = (int)ap->ippa_id;

	imp = ap->ippa_mod;
	ASSERT(imp != NULL);

	LOCK_MOD(imp, RW_READER);
	modname = imp->ippm_name;

	/*
	 * Allocate a stats info structure.
	 */

	if ((sip = kmem_alloc(sizeof (ipp_stat_impl_t), KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	/*
	 * Create a set of kstats.
	 */

	DBG2(DBG_STATS, "creating stat set '%s' for action '%s'\n",
	    name, class);
	if ((ksp = kstat_create(modname, instance, name, class,
	    KSTAT_TYPE_NAMED, nstat, KSTAT_FLAG_WRITABLE)) == NULL) {
		kmem_free(sip, sizeof (ipp_stat_impl_t));
		UNLOCK_ACTION(ap);
		UNLOCK_MOD(imp);
		return (EINVAL);	/* Assume EINVAL was the cause */
	}

	UNLOCK_ACTION(ap);
	UNLOCK_MOD(imp);

	DBG1(DBG_STATS, "ks_data = %p\n", ksp->ks_data);

	/*
	 * Set up the kstats structure with a private data pointer and an
	 * 'update' function.
	 */

	ksp->ks_update = update_stats;
	ksp->ks_private = (void *)sip;

	/*
	 * Keep a reference to the kstats structure in our own stats info
	 * structure.
	 */

	sip->ippsi_ksp = ksp;
	sip->ippsi_data = ksp->ks_data;

	/*
	 * Fill in the rest of the stats info structure.
	 */

	(void) strcpy(sip->ippsi_name, name);
	sip->ippsi_arg = arg;
	sip->ippsi_update = update;
	sip->ippsi_limit = nstat;
	sip->ippsi_count = 0;
	mutex_init(sip->ippsi_lock, NULL, MUTEX_ADAPTIVE,
	    (void *)ipltospl(LOCK_LEVEL));

	/*
	 * Case the stats info structure to a semi-opaque structure that
	 * we pass back to the caller.
	 */

	sp = (ipp_stat_t *)sip;
	ASSERT(sp->ipps_data == sip->ippsi_data);
	*spp = sp;

	rele_action(ap);
	return (0);
}
#undef __FN__

#define	__FN__	"ipp_stat_install"
void
ipp_stat_install(
	ipp_stat_t	*sp)
{
	ipp_stat_impl_t	*sip = (ipp_stat_impl_t *)sp;

	ASSERT(sp != NULL);

	/*
	 * Install the set of kstats referenced by the stats info structure.
	 */

	DBG1(DBG_STATS, "installing stat set '%s'\n", sip->ippsi_name);
	kstat_install(sip->ippsi_ksp);
}
#undef	__FN__

#define	__FN__	"ipp_stat_destroy"
void
ipp_stat_destroy(
	ipp_stat_t	*sp)
{
	ipp_stat_impl_t	*sip = (ipp_stat_impl_t *)sp;

	ASSERT(sp != NULL);

	/*
	 * Destroy the set of kstats referenced by the stats info structure.
	 */

	DBG1(DBG_STATS, "destroying stat set '%s'\n", sip->ippsi_name);
	kstat_delete(sip->ippsi_ksp);

	/*
	 * Destroy the stats info structure itself.
	 */

	mutex_destroy(sip->ippsi_lock);
	kmem_free(sip, sizeof (ipp_stat_impl_t));
}
#undef	__FN__

#define	__FN__	"ipp_stat_named_init"
int
ipp_stat_named_init(
	ipp_stat_t	*sp,
	const char	*name,
	uchar_t		type,
	ipp_named_t	*np)
{
	ipp_stat_impl_t	*sip = (ipp_stat_impl_t *)sp;
	uchar_t		ktype;

	ASSERT(sp != NULL);
	ASSERT(np != NULL);

	if (name == NULL)
		return (EINVAL);

	if ((type & IPP_STAT_TAG) == 0)
		return (EINVAL);
	ktype = type & ~IPP_STAT_TAG;

	/*
	 * Check we will not exceed the maximum number of a stats that was
	 * indicated during set creation.
	 */

	mutex_enter(sip->ippsi_lock);
	if (sip->ippsi_count >= sip->ippsi_limit) {
		mutex_exit(sip->ippsi_lock);
		return (ENOSPC);
	}

	/*
	 * Bump the count.
	 */

	sip->ippsi_count++;

	/*
	 * Create a new named kstat.
	 */

	DBG3(DBG_STATS, "%s.%s: knp = %p\n", sip->ippsi_name, name, np);
	kstat_named_init(np, name, ktype);
	mutex_exit(sip->ippsi_lock);

	return (0);
}
#undef	__FN__

#define	__FN__	"ipp_stat_named_op"
int
ipp_stat_named_op(
	ipp_named_t	*np,
	void		*valp,
	int		rw)
{
	kstat_named_t	*knp;
	uchar_t		type;
	int		rc = 0;

	ASSERT(np != NULL);
	ASSERT(valp != NULL);

	knp = np;
	type = knp->data_type | IPP_STAT_TAG;

	/*
	 * Copy data to or from the named kstat, depending on the specified
	 * opcode.
	 */

	switch (rw) {
	case IPP_STAT_WRITE:
		switch (type) {
		case IPP_STAT_INT32:
			*(int32_t *)valp = knp->value.i32;
			break;
		case IPP_STAT_UINT32:
			*(uint32_t *)valp = knp->value.ui32;
			break;
		case IPP_STAT_INT64:
			*(int64_t *)valp = knp->value.i64;
			break;
		case IPP_STAT_UINT64:
			*(uint64_t *)valp = knp->value.ui64;
			break;
		case IPP_STAT_STRING:
			(void) strncpy(valp, knp->value.c, 16);
			break;
		default:
			ASSERT(0);	/* should not reach here */
			break;
		}

		break;
	case IPP_STAT_READ:
		switch (type) {
		case IPP_STAT_INT32:
			knp->value.i32 = *(int32_t *)valp;
			break;
		case IPP_STAT_UINT32:
			knp->value.ui32 = *(uint32_t *)valp;
			break;
		case IPP_STAT_INT64:
			knp->value.i64 = *(int64_t *)valp;
			break;
		case IPP_STAT_UINT64:
			knp->value.ui64 = *(uint64_t *)valp;
			break;
		case IPP_STAT_STRING:
			(void) strncpy(knp->value.c, valp, 16);
			break;
		default:
			ASSERT(0);	/* should not reach here */
			break;
		}

		break;
	default:
		rc = EINVAL;
	}

	return (rc);
}
#undef	__FN__

/*
 * Local functions (for local people. There's nothing for you here!)
 */

#define	__FN__	"ref_mod"
static int
ref_mod(
	ipp_action_t	*ap,
	ipp_mod_t	*imp)
{
	ipp_ref_t	**rpp;
	ipp_ref_t	*rp;

	ASSERT(rw_write_held(ap->ippa_lock));
	ASSERT(rw_write_held(imp->ippm_lock));

	/*
	 * Add the new reference at the end of the module's list.
	 */

	rpp = &(imp->ippm_action);
	while ((rp = *rpp) != NULL) {
		ASSERT(rp->ippr_action != ap);
		rpp = &(rp->ippr_nextp);
	}

	/*
	 * Allocate a reference structure.
	 */

	if ((rp = kmem_zalloc(sizeof (ipp_ref_t), KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	/*
	 * Set the reference to the action and link it onto the module's list.
	 */

	rp->ippr_action = ap;
	*rpp = rp;

	/*
	 * Keep a 'back pointer' from the action structure to the module
	 * structure.
	 */

	ap->ippa_mod = imp;

	return (0);
}
#undef	__FN__

#define	__FN__	"unref_mod"
static void
unref_mod(
	ipp_action_t	*ap,
	ipp_mod_t	*imp)
{
	ipp_ref_t	**rpp;
	ipp_ref_t	*rp;

	ASSERT(rw_write_held(ap->ippa_lock));
	ASSERT(rw_write_held(imp->ippm_lock));

	/*
	 * Scan the module's list for the reference to the action.
	 */

	rpp = &(imp->ippm_action);
	while ((rp = *rpp) != NULL) {
		if (rp->ippr_action == ap)
			break;
		rpp = &(rp->ippr_nextp);
	}
	ASSERT(rp != NULL);

	/*
	 * Unlink the reference structure and free it.
	 */

	*rpp = rp->ippr_nextp;
	kmem_free(rp, sizeof (ipp_ref_t));

	/*
	 * NULL the 'back pointer'.
	 */

	ap->ippa_mod = NULL;
}
#undef	__FN__

#define	__FN__	"is_mod_busy"
static int
is_mod_busy(
	ipp_mod_t	*imp)
{
	/*
	 * Return a value which is true (non-zero) iff the module refers
	 * to no actions.
	 */

	return (imp->ippm_action != NULL);
}
#undef	__FN__

#define	__FN__	"get_mod_ref"
static int
get_mod_ref(
	ipp_mod_t	*imp,
	ipp_action_id_t	**bufp,
	int		*neltp)
{
	ipp_ref_t	*rp;
	int		nelt;
	ipp_action_t	*ap;
	ipp_action_id_t	*buf;
	int		length;

	ASSERT(rw_lock_held(imp->ippm_lock));

	/*
	 * Count the number of actions referred to from the module structure.
	 */

	nelt = 0;
	for (rp = imp->ippm_action; rp != NULL; rp = rp->ippr_nextp) {
		nelt++;
	}
	DBG1(DBG_LIST, "%d actions found\n", nelt);

	/*
	 * If there are no actions referred to then there's nothing to do.
	 */

	if (nelt == 0) {
		*bufp = NULL;
		*neltp = 0;
		return (0);
	}

	/*
	 * Allocate a buffer to pass back to the caller.
	 */

	length = nelt * sizeof (ipp_action_id_t);
	if ((buf = kmem_alloc(length, KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	/*
	 * Fill the buffer with an array of action ids.
	 */

	*bufp = buf;
	*neltp = nelt;

	for (rp = imp->ippm_action; rp != NULL; rp = rp->ippr_nextp) {
		ap = rp->ippr_action;
		*buf++ = ap->ippa_id;
	}

	ASSERT((uintptr_t)buf == (uintptr_t)*bufp + length);
	return (0);
}
#undef	__FN__

#define	__FN__	"get_mods"
static int
get_mods(
	ipp_mod_id_t	**bufp,
	int		*neltp)
{
	ipp_mod_id_t	*buf;
	int		length;
	ipp_mod_id_t	mid;
	ipp_mod_t	*imp;


	rw_enter(ipp_mod_byname_lock, RW_READER);

	/*
	 * If there are no modules registered then there's nothing to do.
	 */

	if (ipp_mod_count == 0) {
		DBG0(DBG_LIST, "no modules registered\n");
		*bufp = NULL;
		*neltp = 0;
		rw_exit(ipp_mod_byname_lock);
		return (0);
	}

	/*
	 * Allocate a buffer to pass back to the caller.
	 */

	DBG1(DBG_LIST, "%d modules registered\n", ipp_mod_count);
	length = ipp_mod_count * sizeof (ipp_mod_id_t);
	if ((buf = kmem_alloc(length, KM_NOSLEEP)) == NULL) {
		rw_exit(ipp_mod_byname_lock);
		return (ENOMEM);
	}

	rw_enter(ipp_mod_byid_lock, RW_READER);

	/*
	 * Search the array of all modules.
	 */

	*bufp = buf;
	*neltp = ipp_mod_count;

	for (mid = IPP_MOD_RESERVED + 1; mid <= ipp_mid_limit; mid++) {
		if ((imp = ipp_mod_byid[mid]) == NULL)
			continue;

		/*
		 * If the module has 'destruct pending' set then it means it
		 * is either still in the cache (i.e not allocated) or in the
		 * process of being set up by alloc_mod().
		 */

		LOCK_MOD(imp, RW_READER);
		ASSERT(imp->ippm_id == mid);

		if (imp->ippm_destruct_pending) {
			UNLOCK_MOD(imp);
			continue;
		}
		UNLOCK_MOD(imp);

		*buf++ = mid;
	}

	rw_exit(ipp_mod_byid_lock);
	rw_exit(ipp_mod_byname_lock);

	ASSERT((uintptr_t)buf == (uintptr_t)*bufp + length);
	return (0);
}
#undef	__FN__

#define	__FN__	"find_mod"
static ipp_mod_id_t
find_mod(
	const char	*modname)
{
	ipp_mod_id_t	mid;
	ipp_mod_t	*imp;
	ipp_ref_t	*rp;
	int		hb;

	ASSERT(modname != NULL);

	rw_enter(ipp_mod_byname_lock, RW_READER);

	/*
	 * Quick return if no modules are registered.
	 */

	if (ipp_mod_count == 0) {
		rw_exit(ipp_mod_byname_lock);
		return (IPP_MOD_INVAL);
	}

	/*
	 * Find the hash bucket where the module structure should be.
	 */

	hb = hash(modname);
	rp = ipp_mod_byname[hb];

	/*
	 * Scan the bucket for a match.
	 */

	while (rp != NULL) {
		imp = rp->ippr_mod;
		if (strcmp(imp->ippm_name, modname) == 0)
			break;
		rp = rp->ippr_nextp;
	}

	if (rp == NULL) {
		rw_exit(ipp_mod_byname_lock);
		return (IPP_MOD_INVAL);
	}

	if (imp->ippm_state == IPP_MODSTATE_PROTO) {
		rw_exit(ipp_mod_byname_lock);
		return (IPP_MOD_INVAL);
	}

	mid = imp->ippm_id;
	rw_exit(ipp_mod_byname_lock);

	return (mid);
}
#undef __FN__

#define	__FN__	"alloc_mod"
static int
alloc_mod(
	const char	*modname,
	ipp_mod_id_t	*midp)
{
	ipp_mod_t	*imp;
	ipp_ref_t	**rpp;
	ipp_ref_t	*rp;
	int		hb;

	ASSERT(modname != NULL);
	ASSERT(midp != NULL);

	rw_enter(ipp_mod_byname_lock, RW_WRITER);

	/*
	 * Find the right hash bucket for a module of the given name.
	 */

	hb = hash(modname);
	rpp = &ipp_mod_byname[hb];

	/*
	 * Scan the bucket making sure the module isn't already
	 * registered.
	 */

	while ((rp = *rpp) != NULL) {
		imp = rp->ippr_mod;
		if (strcmp(imp->ippm_name, modname) == 0) {
			DBG1(DBG_MOD, "module '%s' already exists\n", modname);
			rw_exit(ipp_mod_byname_lock);
			return (EEXIST);
		}
		rpp = &(rp->ippr_nextp);
	}

	/*
	 * Allocate a new reference structure and a new module structure.
	 */

	if ((rp = kmem_zalloc(sizeof (ipp_ref_t), KM_NOSLEEP)) == NULL) {
		rw_exit(ipp_mod_byname_lock);
		return (ENOMEM);
	}

	if ((imp = kmem_cache_alloc(ipp_mod_cache, KM_NOSLEEP)) == NULL) {
		kmem_free(rp, sizeof (ipp_ref_t));
		rw_exit(ipp_mod_byname_lock);
		return (ENOMEM);
	}

	/*
	 * Set up the name of the new structure.
	 */

	(void) strcpy(imp->ippm_name, modname);

	/*
	 * Make sure the 'destruct pending' flag is clear. This indicates
	 * that the structure is no longer part of the cache.
	 */

	LOCK_MOD(imp, RW_WRITER);
	imp->ippm_destruct_pending = B_FALSE;
	UNLOCK_MOD(imp);

	/*
	 * Set the reference and link it into the hash bucket.
	 */

	rp->ippr_mod = imp;
	*rpp = rp;

	/*
	 * Increment the module count.
	 */

	ipp_mod_count++;

	*midp = imp->ippm_id;
	rw_exit(ipp_mod_byname_lock);
	return (0);
}
#undef	__FN__

#define	__FN__	"free_mod"
static void
free_mod(
	ipp_mod_t	*imp)
{
	ipp_ref_t	**rpp;
	ipp_ref_t	*rp;
	int		hb;

	rw_enter(ipp_mod_byname_lock, RW_WRITER);

	/*
	 * Find the hash bucket where the module structure should be.
	 */

	hb = hash(imp->ippm_name);
	rpp = &ipp_mod_byname[hb];

	/*
	 * Scan the bucket for a match.
	 */

	while ((rp = *rpp) != NULL) {
		if (rp->ippr_mod == imp)
			break;
		rpp = &(rp->ippr_nextp);
	}
	ASSERT(rp != NULL);

	/*
	 * Unlink the reference structure and free it.
	 */

	*rpp = rp->ippr_nextp;
	kmem_free(rp, sizeof (ipp_ref_t));

	/*
	 * Decrement the module count.
	 */

	ipp_mod_count--;

	/*
	 * Empty the name.
	 */

	*imp->ippm_name = '\0';

	/*
	 * If the hold count is zero then we can free the structure
	 * immediately, otherwise we defer to rele_mod().
	 */

	LOCK_MOD(imp, RW_WRITER);
	imp->ippm_destruct_pending = B_TRUE;
	if (imp->ippm_hold_count == 0) {
		UNLOCK_MOD(imp);
		kmem_cache_free(ipp_mod_cache, imp);
		rw_exit(ipp_mod_byname_lock);
		return;
	}
	UNLOCK_MOD(imp);

	rw_exit(ipp_mod_byname_lock);
}
#undef __FN__

#define	__FN__	"hold_mod"
static ipp_mod_t *
hold_mod(
	ipp_mod_id_t	mid)
{
	ipp_mod_t	*imp;

	if (mid < 0)
		return (NULL);

	/*
	 * Use the module id as an index into the array of all module
	 * structures.
	 */

	rw_enter(ipp_mod_byid_lock, RW_READER);
	if ((imp = ipp_mod_byid[mid]) == NULL) {
		rw_exit(ipp_mod_byid_lock);
		return (NULL);
	}

	ASSERT(imp->ippm_id == mid);

	/*
	 * If the modul has 'destruct pending' set then it means it is either
	 * still in the cache (i.e not allocated) or in the process of
	 * being set up by alloc_mod().
	 */

	LOCK_MOD(imp, RW_READER);
	if (imp->ippm_destruct_pending) {
		UNLOCK_MOD(imp);
		rw_exit(ipp_mod_byid_lock);
		return (NULL);
	}
	UNLOCK_MOD(imp);

	/*
	 * Increment the hold count to prevent the structure from being
	 * freed.
	 */

	atomic_inc_32(&(imp->ippm_hold_count));
	rw_exit(ipp_mod_byid_lock);

	return (imp);
}
#undef	__FN__

#define	__FN__	"rele_mod"
static void
rele_mod(
	ipp_mod_t	*imp)
{
	/*
	 * This call means we're done with the pointer so we can drop the
	 * hold count.
	 */

	ASSERT(imp->ippm_hold_count != 0);
	atomic_dec_32(&(imp->ippm_hold_count));

	/*
	 * If the structure has 'destruct pending' set then we tried to free
	 * it but couldn't, so do it now.
	 */

	LOCK_MOD(imp, RW_READER);
	if (imp->ippm_destruct_pending && imp->ippm_hold_count == 0) {
		UNLOCK_MOD(imp);
		kmem_cache_free(ipp_mod_cache, imp);
		return;
	}

	UNLOCK_MOD(imp);
}
#undef	__FN__

#define	__FN__	"get_mid"
static ipp_mod_id_t
get_mid(
	void)
{
	int	index;
	int	start;
	int	limit;

	ASSERT(rw_write_held(ipp_mod_byid_lock));

	/*
	 * Start searching after the last module id we allocated.
	 */

	start = (int)ipp_next_mid;
	limit = (int)ipp_mid_limit;

	/*
	 * Look for a spare slot in the array.
	 */

	index = start;
	while (ipp_mod_byid[index] != NULL) {
		index++;
		if (index > limit)
			index = IPP_MOD_RESERVED + 1;
		if (index == start)
			return (IPP_MOD_INVAL);
	}

	/*
	 * Note that we've just allocated a new module id so that we can
	 * start our search there next time.
	 */

	index++;
	if (index > limit) {
		ipp_next_mid = IPP_MOD_RESERVED + 1;
	} else
		ipp_next_mid = (ipp_mod_id_t)index;

	return ((ipp_mod_id_t)(--index));
}
#undef	__FN__

#define	__FN__	"condemn_action"
static int
condemn_action(
	ipp_ref_t	**rpp,
	ipp_action_t	*ap)
{
	ipp_ref_t	*rp;

	DBG1(DBG_ACTION, "condemning action '%s'\n", ap->ippa_name);

	/*
	 * Check to see if the action is already condemned.
	 */

	while ((rp = *rpp) != NULL) {
		if (rp->ippr_action == ap)
			break;
		rpp = &(rp->ippr_nextp);
	}

	/*
	 * Create a new entry for the action.
	 */

	if (rp == NULL) {
		if ((rp = kmem_zalloc(sizeof (ipp_ref_t), KM_NOSLEEP)) == NULL)
			return (ENOMEM);

		rp->ippr_action = ap;
		*rpp = rp;
	}

	return (0);
}
#undef	__FN__

#define	__FN__	"destroy_action"
static int
destroy_action(
	ipp_action_t	*ap,
	ipp_flags_t	flags)
{
	ipp_ops_t	*ippo;
	ipp_mod_t	*imp;
#define	MAXWAIT		10
	uint32_t	wait;
	int		rc;

	/*
	 * Check that the action is available.
	 */

	LOCK_ACTION(ap, RW_WRITER);
	if (ap->ippa_state != IPP_ASTATE_AVAILABLE) {
		UNLOCK_ACTION(ap);
		rele_action(ap);
		return (EPROTO);
	}

	/*
	 * Note that the action is in the process of creation/destruction.
	 */

	ap->ippa_state = IPP_ASTATE_CONFIG_PENDING;

	/*
	 * Wait for the in-transit packet count for this action to fall to
	 * zero (checking at millisecond intervals).
	 *
	 * NOTE: no new packets will enter the action now that the
	 *	 state has been changed.
	 */

	for (wait = 0; ap->ippa_packets > 0 && wait < (MAXWAIT * 1000000);
	    wait += 1000) {

		/*
		 * NOTE: We can hang onto the lock because the packet count is
		 *	 decremented without needing to take the lock.
		 */

		drv_usecwait(1000);
	}

	/*
	 * The packet count did not fall to zero.
	 */
	if (ap->ippa_packets > 0) {
		ap->ippa_state = IPP_ASTATE_AVAILABLE;
		UNLOCK_ACTION(ap);
		rele_action(ap);
		return (EAGAIN);
	}

	/*
	 * Check to see if any other action has a dependency on this one.
	 */

	if (is_action_refd(ap)) {
		ap->ippa_state = IPP_ASTATE_AVAILABLE;
		UNLOCK_ACTION(ap);
		rele_action(ap);
		return (EBUSY);
	}

	imp = ap->ippa_mod;
	ASSERT(imp != NULL);
	UNLOCK_ACTION(ap);

	ippo = imp->ippm_ops;
	ASSERT(ippo != NULL);

	/*
	 * Call into the module to destroy the action context.
	 */

	CONFIG_WRITE_START(ap);
	DBG1(DBG_ACTION, "destroying action '%s'\n", ap->ippa_name);
	if ((rc = ippo->ippo_action_destroy(ap->ippa_id, flags)) != 0) {
		LOCK_ACTION(ap, RW_WRITER);
		ap->ippa_state = IPP_ASTATE_AVAILABLE;
		UNLOCK_ACTION(ap);

		CONFIG_WRITE_END(ap);

		rele_action(ap);
		return (rc);
	}
	CONFIG_WRITE_END(ap);

	LOCK_ACTION(ap, RW_WRITER);
	LOCK_MOD(imp, RW_WRITER);
	unref_mod(ap, imp);
	UNLOCK_MOD(imp);
	ap->ippa_state = IPP_ASTATE_PROTO;
	UNLOCK_ACTION(ap);

	/*
	 * Free the action structure.
	 */

	ASSERT(ap->ippa_ref == NULL);
	free_action(ap);
	rele_action(ap);
	return (0);
#undef	MAXWAIT
}
#undef	__FN__

#define	__FN__	"ref_action"
static int
ref_action(
	ipp_action_t	*refby_ap,
	ipp_action_t	*ref_ap)
{
	ipp_ref_t	**rpp;
	ipp_ref_t	**save_rpp;
	ipp_ref_t	*rp;

	ASSERT(rw_write_held(refby_ap->ippa_lock));
	ASSERT(rw_write_held(ref_ap->ippa_lock));

	/*
	 * We want to add the new reference at the end of the refering
	 * action's list.
	 */

	rpp = &(refby_ap->ippa_ref);
	while ((rp = *rpp) != NULL) {
		if (rp->ippr_action == ref_ap)
			break;
		rpp = &(rp->ippr_nextp);
	}

	if ((rp = *rpp) != NULL) {

		/*
		 * There is an existing reference so increment its counter.
		 */

		rp->ippr_count++;

		/*
		 * Find the 'back pointer' and increment its counter too.
		 */

		rp = ref_ap->ippa_refby;
		while (rp != NULL) {
			if (rp->ippr_action == refby_ap)
				break;
			rp = rp->ippr_nextp;
		}
		ASSERT(rp != NULL);

		rp->ippr_count++;
	} else {

		/*
		 * Allocate, fill in and link a new reference structure.
		 */

		if ((rp = kmem_zalloc(sizeof (ipp_ref_t), KM_NOSLEEP)) == NULL)
			return (ENOMEM);

		rp->ippr_action = ref_ap;
		rp->ippr_count = 1;
		*rpp = rp;
		save_rpp = rpp;

		/*
		 * We keep a 'back pointer' which we want to add at the end of
		 * a list in the referred action's structure.
		 */

		rpp = &(ref_ap->ippa_refby);
		while ((rp = *rpp) != NULL) {
			ASSERT(rp->ippr_action != refby_ap);
			rpp = &(rp->ippr_nextp);
		}

		/*
		 * Allocate another reference structure and, if this fails,
		 * remember to clean up the first reference structure we
		 * allocated.
		 */

		if ((rp = kmem_zalloc(sizeof (ipp_ref_t),
		    KM_NOSLEEP)) == NULL) {
			rpp = save_rpp;
			rp = *rpp;
			*rpp = NULL;
			kmem_free(rp, sizeof (ipp_ref_t));

			return (ENOMEM);
		}

		/*
		 * Fill in the reference structure with the 'back pointer' and
		 * link it into the list.
		 */

		rp->ippr_action = refby_ap;
		rp->ippr_count = 1;
		*rpp = rp;
	}

	return (0);
}
#undef	__FN__

#define	__FN__	"unref_action"
static int
unref_action(
	ipp_action_t	*refby_ap,
	ipp_action_t	*ref_ap)
{
	ipp_ref_t	**rpp;
	ipp_ref_t	*rp;

	ASSERT(rw_write_held(refby_ap->ippa_lock));
	ASSERT(rw_write_held(ref_ap->ippa_lock));

	/*
	 * Scan for the reference in the referring action's list.
	 */

	rpp = &(refby_ap->ippa_ref);
	while ((rp = *rpp) != NULL) {
		if (rp->ippr_action == ref_ap)
			break;
		rpp = &(rp->ippr_nextp);
	}

	if (rp == NULL)
		return (ENOENT);

	if (rp->ippr_count > 1) {

		/*
		 * There are currently multiple references so decrement the
		 * count.
		 */

		rp->ippr_count--;

		/*
		 * Find the 'back pointer' and decrement its counter too.
		 */

		rp = ref_ap->ippa_refby;
		while (rp != NULL) {
			if (rp->ippr_action == refby_ap)
				break;
			rp = rp->ippr_nextp;
		}
		ASSERT(rp != NULL);

		rp->ippr_count--;
	} else {

		/*
		 * There is currently only a single reference, so unlink and
		 * free the reference structure.
		 */

		*rpp = rp->ippr_nextp;
		kmem_free(rp, sizeof (ipp_ref_t));

		/*
		 * Scan for the 'back pointer' in the referred action's list.
		 */

		rpp = &(ref_ap->ippa_refby);
		while ((rp = *rpp) != NULL) {
			if (rp->ippr_action == refby_ap)
				break;
			rpp = &(rp->ippr_nextp);
		}
		ASSERT(rp != NULL);

		/*
		 * Unlink and free this reference structure too.
		 */

		*rpp = rp->ippr_nextp;
		kmem_free(rp, sizeof (ipp_ref_t));
	}

	return (0);
}
#undef	__FN__

#define	__FN__	"is_action_refd"
static int
is_action_refd(
	ipp_action_t	*ap)
{
	/*
	 * Return a value which is true (non-zero) iff the action is not
	 * referred to by any other actions.
	 */

	return (ap->ippa_refby != NULL);
}
#undef	__FN__

#define	__FN__	"find_action"
static ipp_action_id_t
find_action(
	const char	*aname)
{
	ipp_action_id_t	aid;
	ipp_action_t	*ap;
	ipp_ref_t	*rp;
	int		hb;

	ASSERT(aname != NULL);

	rw_enter(ipp_action_byname_lock, RW_READER);

	/*
	 * Quick return if there are no actions defined at all.
	 */

	if (ipp_action_count == 0) {
		rw_exit(ipp_action_byname_lock);
		return (IPP_ACTION_INVAL);
	}

	/*
	 * Find the hash bucket where the action structure should be.
	 */

	hb = hash(aname);
	rp = ipp_action_byname[hb];

	/*
	 * Scan the bucket looking for a match.
	 */

	while (rp != NULL) {
		ap = rp->ippr_action;
		if (strcmp(ap->ippa_name, aname) == 0)
			break;
		rp = rp->ippr_nextp;
	}

	if (rp == NULL) {
		rw_exit(ipp_action_byname_lock);
		return (IPP_ACTION_INVAL);
	}

	if (ap->ippa_state == IPP_ASTATE_PROTO) {
		rw_exit(ipp_action_byname_lock);
		return (IPP_ACTION_INVAL);
	}

	aid = ap->ippa_id;
	rw_exit(ipp_action_byname_lock);

	return (aid);
}
#undef __FN__

#define	__FN__	"alloc_action"
static int
alloc_action(
	const char	*aname,
	ipp_action_id_t	*aidp)
{
	ipp_action_t	*ap;
	ipp_ref_t	**rpp;
	ipp_ref_t	*rp;
	int		hb;

	ASSERT(aidp != NULL);

	rw_enter(ipp_action_byname_lock, RW_WRITER);

	/*
	 * Find the right hash bucket for an action of the given name.
	 * (Nameless actions always go in a special bucket).
	 */

	if (aname != NULL) {
		hb = hash(aname);
		rpp = &ipp_action_byname[hb];
	} else
		rpp = &ipp_action_noname;

	/*
	 * Scan the bucket to make sure that an action with the given name
	 * does not already exist.
	 */

	while ((rp = *rpp) != NULL) {
		ap = rp->ippr_action;
		if (aname != NULL && strcmp(ap->ippa_name, aname) == 0) {
			DBG1(DBG_ACTION, "action '%s' already exists\n",
			    aname);
			rw_exit(ipp_action_byname_lock);
			return (EEXIST);
		}
		rpp = &(rp->ippr_nextp);
	}

	/*
	 * Allocate a new reference structure and a new action structure.
	 */

	if ((rp = kmem_zalloc(sizeof (ipp_ref_t), KM_NOSLEEP)) == NULL) {
		rw_exit(ipp_action_byname_lock);
		return (ENOMEM);
	}

	if ((ap = kmem_cache_alloc(ipp_action_cache, KM_NOSLEEP)) == NULL) {
		kmem_free(rp, sizeof (ipp_ref_t));
		rw_exit(ipp_action_byname_lock);
		return (ENOMEM);
	}

	/*
	 * Dream up a name if there isn't a real one and note that the action is
	 * really nameless.
	 */

	if (aname == NULL) {
		(void) sprintf(ap->ippa_name, "$%08X", ap->ippa_id);
		ap->ippa_nameless = B_TRUE;
	} else
		(void) strcpy(ap->ippa_name, aname);

	/*
	 * Make sure the 'destruct pending' flag is clear. This indicates that
	 * the structure is no longer part of the cache.
	 */

	LOCK_ACTION(ap, RW_WRITER);
	ap->ippa_destruct_pending = B_FALSE;
	UNLOCK_ACTION(ap);

	/*
	 * Fill in the reference structure and lint it onto the list.
	 */

	rp->ippr_action = ap;
	*rpp = rp;

	/*
	 * Increment the action count.
	 */

	ipp_action_count++;

	*aidp = ap->ippa_id;
	rw_exit(ipp_action_byname_lock);
	return (0);
}
#undef	__FN__

#define	__FN__	"free_action"
static void
free_action(
	ipp_action_t	*ap)
{
	ipp_ref_t	**rpp;
	ipp_ref_t	*rp;
	int		hb;

	rw_enter(ipp_action_byname_lock, RW_WRITER);

	/*
	 * Find the hash bucket where the action structure should be.
	 */

	if (!ap->ippa_nameless) {
		hb = hash(ap->ippa_name);
		rpp = &ipp_action_byname[hb];
	} else
		rpp = &ipp_action_noname;

	/*
	 * Scan the bucket for a match.
	 */

	while ((rp = *rpp) != NULL) {
		if (rp->ippr_action == ap)
			break;
		rpp = &(rp->ippr_nextp);
	}
	ASSERT(rp != NULL);

	/*
	 * Unlink and free the reference structure.
	 */

	*rpp = rp->ippr_nextp;
	kmem_free(rp, sizeof (ipp_ref_t));

	/*
	 * Decrement the action count.
	 */

	ipp_action_count--;

	/*
	 * Empty the name.
	 */

	*ap->ippa_name = '\0';

	/*
	 * If the hold count is zero then we can free the structure
	 * immediately, otherwise we defer to rele_action().
	 */

	LOCK_ACTION(ap, RW_WRITER);
	ap->ippa_destruct_pending = B_TRUE;
	if (ap->ippa_hold_count == 0) {
		UNLOCK_ACTION(ap);
		kmem_cache_free(ipp_action_cache, ap);
		rw_exit(ipp_action_byname_lock);
		return;
	}
	UNLOCK_ACTION(ap);

	rw_exit(ipp_action_byname_lock);
}
#undef __FN__

#define	__FN__	"hold_action"
static ipp_action_t *
hold_action(
	ipp_action_id_t	aid)
{
	ipp_action_t	*ap;

	if (aid < 0)
		return (NULL);

	/*
	 * Use the action id as an index into the array of all action
	 * structures.
	 */

	rw_enter(ipp_action_byid_lock, RW_READER);
	if ((ap = ipp_action_byid[aid]) == NULL) {
		rw_exit(ipp_action_byid_lock);
		return (NULL);
	}

	/*
	 * If the action has 'destruct pending' set then it means it is either
	 * still in the cache (i.e not allocated) or in the process of
	 * being set up by alloc_action().
	 */

	LOCK_ACTION(ap, RW_READER);
	if (ap->ippa_destruct_pending) {
		UNLOCK_ACTION(ap);
		rw_exit(ipp_action_byid_lock);
		return (NULL);
	}
	UNLOCK_ACTION(ap);

	/*
	 * Increment the hold count to prevent the structure from being
	 * freed.
	 */

	atomic_inc_32(&(ap->ippa_hold_count));
	rw_exit(ipp_action_byid_lock);

	return (ap);
}
#undef	__FN__

#define	__FN__	"rele_action"
static void
rele_action(
	ipp_action_t	*ap)
{
	/*
	 * This call means we're done with the pointer so we can drop the
	 * hold count.
	 */

	ASSERT(ap->ippa_hold_count != 0);
	atomic_dec_32(&(ap->ippa_hold_count));

	/*
	 * If the structure has 'destruct pending' set then we tried to free
	 * it but couldn't, so do it now.
	 */

	LOCK_ACTION(ap, RW_READER);
	if (ap->ippa_destruct_pending && ap->ippa_hold_count == 0) {
		UNLOCK_ACTION(ap);
		kmem_cache_free(ipp_action_cache, ap);
		return;
	}
	UNLOCK_ACTION(ap);
}
#undef	__FN__

#define	__FN__	"get_aid"
static ipp_action_id_t
get_aid(
	void)
{
	int	index;
	int	start;
	int	limit;

	ASSERT(rw_write_held(ipp_action_byid_lock));

	/*
	 * Start searching after the last action id that we allocated.
	 */

	start = (int)ipp_next_aid;
	limit = (int)ipp_aid_limit;

	/*
	 * Look for a spare slot in the array.
	 */

	index = start;
	while (ipp_action_byid[index] != NULL) {
		index++;
		if (index > limit)
			index = IPP_ACTION_RESERVED + 1;
		if (index == start)
			return (IPP_ACTION_INVAL);
	}

	/*
	 * Note that we've just allocated a new action id so that we can
	 * start our search there next time.
	 */

	index++;
	if (index > limit)
		ipp_next_aid = IPP_ACTION_RESERVED + 1;
	else
		ipp_next_aid = (ipp_action_id_t)index;

	return ((ipp_action_id_t)(--index));
}
#undef	__FN__

#define	__FN__	"alloc_packet"
static int
alloc_packet(
	const char	*name,
	ipp_action_id_t	aid,
	ipp_packet_t	**ppp)
{
	ipp_packet_t	*pp;
	ipp_class_t	*cp;

	if ((pp = kmem_cache_alloc(ipp_packet_cache, KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	/*
	 * Set the packet up with a single class.
	 */

	cp = &(pp->ippp_class_array[0]);
	pp->ippp_class_windex = 1;

	(void) strcpy(cp->ippc_name, name);
	cp->ippc_aid = aid;

	*ppp = pp;
	return (0);
}
#undef	__FN__

#define	__FN__	"realloc_packet"
static int
realloc_packet(
	ipp_packet_t	*pp)
{
	uint_t		length;
	ipp_class_t	*array;

	length = (pp->ippp_class_limit + 1) << 1;
	if ((array = kmem_alloc(length * sizeof (ipp_class_t),
	    KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	bcopy(pp->ippp_class_array, array,
	    (length >> 1) * sizeof (ipp_class_t));

	kmem_free(pp->ippp_class_array,
	    (length >> 1) * sizeof (ipp_class_t));

	pp->ippp_class_array = array;
	pp->ippp_class_limit = length - 1;

	return (0);
}
#undef	__FN__

#define	__FN__	"free_packet"
static void
free_packet(
	ipp_packet_t	*pp)
{
	pp->ippp_class_windex = 0;
	pp->ippp_class_rindex = 0;

	pp->ippp_data = NULL;
	pp->ippp_private = NULL;

	kmem_cache_free(ipp_packet_cache, pp);
}
#undef	__FN__

#define	__FN__ 	"hash"
static int
hash(
	const char	*name)
{
	int		val = 0;
	char		*ptr;

	/*
	 * Make a hash value by XORing all the ascii codes in the text string.
	 */

	for (ptr = (char *)name; *ptr != NULL; ptr++) {
		val ^= *ptr;
	}

	/*
	 * Return the value modulo the number of hash buckets we allow.
	 */

	return (val % IPP_NBUCKET);
}
#undef	__FN__

#define	__FN__	"update_stats"
static int
update_stats(
	kstat_t		*ksp,
	int		rw)
{
	ipp_stat_impl_t	*sip;

	ASSERT(ksp->ks_private != NULL);
	sip = (ipp_stat_impl_t *)ksp->ks_private;

	/*
	 * Call the update function passed to ipp_stat_create() for the given
	 * set of kstats.
	 */

	return (sip->ippsi_update((ipp_stat_t *)sip, sip->ippsi_arg, rw));
}
#undef	__FN__

#define	__FN__	"init_mods"
static void
init_mods(
	void)
{
	/*
	 * Initialise the array of all module structures and the module
	 * structure kmem cache.
	 */

	rw_init(ipp_mod_byid_lock, NULL, RW_DEFAULT,
	    (void *)ipltospl(LOCK_LEVEL));
	ipp_mod_byid = kmem_zalloc(sizeof (ipp_mod_t *) * (ipp_max_mod + 1),
	    KM_SLEEP);
	ipp_mod_byid[ipp_max_mod] = (ipp_mod_t *)-1;
	ipp_mid_limit = (ipp_mod_id_t)(ipp_max_mod - 1);

	ipp_mod_cache = kmem_cache_create("ipp_mod", sizeof (ipp_mod_t),
	    IPP_ALIGN, mod_constructor, mod_destructor, NULL, NULL, NULL, 0);
	ASSERT(ipp_mod_cache != NULL);

	/*
	 * Initialize the 'module by name' hash bucket array.
	 */

	rw_init(ipp_mod_byname_lock, NULL, RW_DEFAULT,
	    (void *)ipltospl(LOCK_LEVEL));
	bzero(ipp_mod_byname, IPP_NBUCKET * sizeof (ipp_ref_t *));
}
#undef	__FN__

#define	__FN__	"init_actions"
static void
init_actions(
	void)
{
	/*
	 * Initialise the array of all action structures and the action
	 * structure cache.
	 */

	rw_init(ipp_action_byid_lock, NULL, RW_DEFAULT,
	    (void *)ipltospl(LOCK_LEVEL));
	ipp_action_byid = kmem_zalloc(sizeof (ipp_action_t *) *
	    (ipp_max_action + 1), KM_SLEEP);
	ipp_action_byid[ipp_max_action] = (ipp_action_t *)-1;
	ipp_aid_limit = (ipp_action_id_t)(ipp_max_action - 1);

	ipp_action_cache = kmem_cache_create("ipp_action",
	    sizeof (ipp_action_t), IPP_ALIGN, action_constructor,
	    action_destructor, NULL, NULL, NULL, 0);
	ASSERT(ipp_action_cache != NULL);

	/*
	 * Initialize the 'action by name' hash bucket array (and the special
	 * 'hash' bucket for nameless actions).
	 */

	rw_init(ipp_action_byname_lock, NULL, RW_DEFAULT,
	    (void *)ipltospl(LOCK_LEVEL));
	bzero(ipp_action_byname, IPP_NBUCKET * sizeof (ipp_ref_t *));
	ipp_action_noname = NULL;
}
#undef	__FN__

#define	__FN__	"init_packets"
static void
init_packets(
	void)
{
	/*
	 * Initialise the packet structure cache.
	 */

	ipp_packet_cache = kmem_cache_create("ipp_packet",
	    sizeof (ipp_packet_t), IPP_ALIGN, packet_constructor,
	    packet_destructor, NULL, NULL, NULL, 0);
	ASSERT(ipp_packet_cache != NULL);
}
#undef	__FN__

/*
 * Kmem cache constructor/destructor functions.
 */

#define	__FN__	"mod_constructor"
/*ARGSUSED*/
static int
mod_constructor(
	void		*buf,
	void		*cdrarg,
	int		kmflags)
{
	ipp_mod_t	*imp;
	ipp_mod_id_t	mid;

	ASSERT(buf != NULL);
	bzero(buf, sizeof (ipp_mod_t));
	imp = (ipp_mod_t *)buf;

	rw_enter(ipp_mod_byid_lock, RW_WRITER);

	/*
	 * Get a new module id.
	 */

	if ((mid = get_mid()) <= IPP_MOD_RESERVED) {
		rw_exit(ipp_mod_byid_lock);
		return (-1);
	}

	/*
	 * Initialize the buffer as a module structure in PROTO form.
	 */

	imp->ippm_destruct_pending = B_TRUE;
	imp->ippm_state = IPP_MODSTATE_PROTO;
	rw_init(imp->ippm_lock, NULL, RW_DEFAULT,
	    (void *)ipltospl(LOCK_LEVEL));

	/*
	 * Insert it into the array of all module structures.
	 */

	imp->ippm_id = mid;
	ipp_mod_byid[mid] = imp;

	rw_exit(ipp_mod_byid_lock);

	return (0);
}
#undef	__FN__

#define	__FN__	"mod_destructor"
/*ARGSUSED*/
static void
mod_destructor(
	void		*buf,
	void		*cdrarg)
{
	ipp_mod_t	*imp;

	ASSERT(buf != NULL);
	imp = (ipp_mod_t *)buf;

	ASSERT(imp->ippm_state == IPP_MODSTATE_PROTO);
	ASSERT(imp->ippm_action == NULL);
	ASSERT(*imp->ippm_name == '\0');
	ASSERT(imp->ippm_destruct_pending);

	rw_enter(ipp_mod_byid_lock, RW_WRITER);
	ASSERT(imp->ippm_hold_count == 0);

	/*
	 * NULL the entry in the array of all module structures.
	 */

	ipp_mod_byid[imp->ippm_id] = NULL;

	/*
	 * Clean up any remnants of the module structure as the buffer is
	 * about to disappear.
	 */

	rw_destroy(imp->ippm_lock);
	rw_exit(ipp_mod_byid_lock);
}
#undef	__FN__

#define	__FN__	"action_constructor"
/*ARGSUSED*/
static int
action_constructor(
	void		*buf,
	void		*cdrarg,
	int		kmflags)
{
	ipp_action_t	*ap;
	ipp_action_id_t	aid;

	ASSERT(buf != NULL);
	bzero(buf, sizeof (ipp_action_t));
	ap = (ipp_action_t *)buf;

	rw_enter(ipp_action_byid_lock, RW_WRITER);

	/*
	 * Get a new action id.
	 */

	if ((aid = get_aid()) <= IPP_ACTION_RESERVED) {
		rw_exit(ipp_action_byid_lock);
		return (-1);
	}

	/*
	 * Initialize the buffer as an action structure in PROTO form.
	 */

	ap->ippa_state = IPP_ASTATE_PROTO;
	ap->ippa_destruct_pending = B_TRUE;
	rw_init(ap->ippa_lock, NULL, RW_DEFAULT,
	    (void *)ipltospl(LOCK_LEVEL));
	CONFIG_LOCK_INIT(ap->ippa_config_lock);

	/*
	 * Insert it into the array of all action structures.
	 */

	ap->ippa_id = aid;
	ipp_action_byid[aid] = ap;

	rw_exit(ipp_action_byid_lock);
	return (0);
}
#undef	__FN__

#define	__FN__	"action_destructor"
/*ARGSUSED*/
static void
action_destructor(
	void		*buf,
	void		*cdrarg)
{
	ipp_action_t	*ap;

	ASSERT(buf != NULL);
	ap = (ipp_action_t *)buf;

	ASSERT(ap->ippa_state == IPP_ASTATE_PROTO);
	ASSERT(ap->ippa_ref == NULL);
	ASSERT(ap->ippa_refby == NULL);
	ASSERT(ap->ippa_packets == 0);
	ASSERT(*ap->ippa_name == '\0');
	ASSERT(ap->ippa_destruct_pending);

	rw_enter(ipp_action_byid_lock, RW_WRITER);
	ASSERT(ap->ippa_hold_count == 0);

	/*
	 * NULL the entry in the array of all action structures.
	 */

	ipp_action_byid[ap->ippa_id] = NULL;

	/*
	 * Clean up any remnants of the action structure as the buffer is
	 * about to disappear.
	 */

	CONFIG_LOCK_FINI(ap->ippa_config_lock);
	rw_destroy(ap->ippa_lock);

	rw_exit(ipp_action_byid_lock);
}
#undef	__FN__

#define	__FN__	"packet_constructor"
/*ARGSUSED*/
static int
packet_constructor(
	void		*buf,
	void		*cdrarg,
	int		kmflags)
{
	ipp_packet_t	*pp;
	ipp_class_t	*cp;

	ASSERT(buf != NULL);
	bzero(buf, sizeof (ipp_packet_t));
	pp = (ipp_packet_t *)buf;

	if ((cp = kmem_alloc(ipp_packet_classes * sizeof (ipp_class_t),
	    KM_NOSLEEP)) == NULL)
		return (ENOMEM);

	pp->ippp_class_array = cp;
	pp->ippp_class_windex = 0;
	pp->ippp_class_rindex = 0;
	pp->ippp_class_limit = ipp_packet_classes - 1;

	return (0);
}
#undef	__FN__

#define	__FN__	"packet_destructor"
/*ARGSUSED*/
static void
packet_destructor(
	void		*buf,
	void		*cdrarg)
{
	ipp_packet_t	*pp;

	ASSERT(buf != NULL);
	pp = (ipp_packet_t *)buf;

	ASSERT(pp->ippp_data == NULL);
	ASSERT(pp->ippp_class_windex == 0);
	ASSERT(pp->ippp_class_rindex == 0);
	ASSERT(pp->ippp_private == NULL);
	ASSERT(pp->ippp_private_free == NULL);

	kmem_free(pp->ippp_class_array,
	    (pp->ippp_class_limit + 1) * sizeof (ipp_class_t));

	if (pp->ippp_log != NULL) {
		kmem_free(pp->ippp_log,
		    (pp->ippp_log_limit + 1) * sizeof (ipp_log_t));
	}
}
#undef	__FN__

/*
 * Debug message printout code.
 */

#ifdef	IPP_DBG
static void
ipp_debug(
	uint64_t	type,
	const char	*fn,
	char		*fmt,
			...)
{
	char		buf[255];
	va_list		adx;

	if ((type & ipp_debug_flags) == 0)
		return;

	mutex_enter(debug_mutex);
	va_start(adx, fmt);
	(void) vsnprintf(buf, 255, fmt, adx);
	va_end(adx);

	printf("(%llx) %s: %s", (unsigned long long)curthread->t_did, fn,
	    buf);
	mutex_exit(debug_mutex);
}
#endif	/* IPP_DBG */
