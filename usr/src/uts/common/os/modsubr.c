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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/modhash.h>
#include <sys/open.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/pathname.h>
#include <sys/vnode.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/esunddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/systeminfo.h>
#include <sys/hwconf.h>
#include <sys/file.h>
#include <sys/varargs.h>
#include <sys/thread.h>
#include <sys/cred.h>
#include <sys/autoconf.h>
#include <sys/kobj.h>
#include <sys/consdev.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/atomic.h>

extern struct dev_ops nodev_ops;
extern struct dev_ops mod_nodev_ops;

struct mod_noload {
	struct mod_noload *mn_next;
	char *mn_name;
};

/*
 * Function prototypes
 */
static int init_stubs(struct modctl *, struct mod_modinfo *);
static int nm_hash(char *);
static void make_syscallname(char *, int);
static void hwc_hash_init();
static void hwc_hash(struct hwc_spec *, major_t);
static void hwc_unhash(struct hwc_spec *);

int
major_valid(major_t major)
{
	return (major != DDI_MAJOR_T_NONE &&
	    (major >= 0 && major < devcnt));
}

int
driver_installed(major_t major)
{
	return (major_valid(major) && devnamesp[major].dn_name != NULL);
}

int
driver_active(major_t major)
{
	return (driver_installed(major) && !(devnamesp[major].dn_flags &
	    (DN_DRIVER_REMOVED|DN_DRIVER_INACTIVE)));
}

struct dev_ops *
mod_hold_dev_by_major(major_t major)
{
	struct dev_ops **devopspp, *ops;
	int loaded;
	char *drvname;

	if (!driver_active(major))
		return (NULL);

	LOCK_DEV_OPS(&(devnamesp[major].dn_lock));
	devopspp = &devopsp[major];
	loaded = 1;
	while (loaded && !CB_DRV_INSTALLED(*devopspp)) {
		UNLOCK_DEV_OPS(&(devnamesp[major].dn_lock));
		drvname = mod_major_to_name(major);
		if (drvname == NULL)
			return (NULL);
		loaded = (modload("drv", drvname) != -1);
		LOCK_DEV_OPS(&(devnamesp[major].dn_lock));
	}
	if (loaded) {
		INCR_DEV_OPS_REF(*devopspp);
		ops = *devopspp;
	} else {
		ops = NULL;
	}
	UNLOCK_DEV_OPS(&(devnamesp[major].dn_lock));
	return (ops);
}

#ifdef	DEBUG_RELE
static int mod_rele_pause = DEBUG_RELE;
#endif	/* DEBUG_RELE */

void
mod_rele_dev_by_major(major_t major)
{
	struct dev_ops *ops;
	struct devnames *dnp;

	if (!driver_active(major))
		return;

	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&dnp->dn_lock);
	ops = devopsp[major];
	ASSERT(CB_DRV_INSTALLED(ops));

#ifdef	DEBUG_RELE
	if (!DEV_OPS_HELD(ops))  {
		char *s;
		static char *msg = "mod_rele_dev_by_major: unheld driver!";

		printf("mod_rele_dev_by_major: Major dev <%u>, name <%s>\n",
		    (uint_t)major,
		    (s = mod_major_to_name(major)) ? s : "unknown");
		if (mod_rele_pause)
			debug_enter(msg);
		else
			printf("%s\n", msg);
		UNLOCK_DEV_OPS(&dnp->dn_lock);
		return;			/* XXX: Note changed behavior */
	}

#endif	/* DEBUG_RELE */

	if (!DEV_OPS_HELD(ops)) {
		cmn_err(CE_PANIC,
		    "mod_rele_dev_by_major: Unheld driver: major number <%u>",
		    (uint_t)major);
	}
	DECR_DEV_OPS_REF(ops);
	UNLOCK_DEV_OPS(&dnp->dn_lock);
}

struct dev_ops *
mod_hold_dev_by_devi(dev_info_t *devi)
{
	major_t major;
	char *name;

	name = ddi_get_name(devi);
	if ((major = mod_name_to_major(name)) == DDI_MAJOR_T_NONE)
		return (NULL);
	return (mod_hold_dev_by_major(major));
}

void
mod_rele_dev_by_devi(dev_info_t *devi)
{
	major_t major;
	char *name;

	name = ddi_get_name(devi);
	if ((major = mod_name_to_major(name)) == DDI_MAJOR_T_NONE)
		return;
	mod_rele_dev_by_major(major);
}

int
nomod_zero()
{
	return (0);
}

int
nomod_minus_one()
{
	return (-1);
}

int
nomod_einval()
{
	return (EINVAL);
}

void
nomod_void()
{
	/* nothing */
}

/*
 * Install all the stubs for a module.
 * Return zero if there were no errors or an errno value.
 */
int
install_stubs_by_name(struct modctl *modp, char *name)
{
	char *p;
	char *filenamep;
	char namebuf[MODMAXNAMELEN + 12];
	struct mod_modinfo *mp;

	p = name;
	filenamep = name;

	while (*p)
		if (*p++ == '/')
			filenamep = p;

	/*
	 * Concatenate "name" with "_modname" then look up this symbol
	 * in the kernel.  If not found, we're done.
	 * If found, then find the "mod" info structure and call init_stubs().
	 */
	p = namebuf;

	while (*filenamep && *filenamep != '.')
		*p++ = *filenamep++;

	(void) strcpy(p, "_modinfo");

	if ((mp = (struct mod_modinfo *)modgetsymvalue(namebuf, 1)) != 0)
		return (init_stubs(modp, mp));
	else
		return (0);
}

static int
init_stubs(struct modctl *modp, struct mod_modinfo *mp)
{
	struct mod_stub_info *sp;
	int i;
	ulong_t offset;
	uintptr_t funcadr;
	char *funcname;

	modp->mod_modinfo = mp;

	/*
	 * Fill in all stubs for this module.  We can't be lazy, since
	 * some calls could come in from interrupt level, and we
	 * can't modlookup then (symbols may be paged out).
	 */
	sp = mp->modm_stubs;
	for (i = 0; sp->mods_func_adr; i++, sp++) {
		funcname = modgetsymname(sp->mods_stub_adr, &offset);
		if (funcname == NULL) {
			printf("init_stubs: couldn't find symbol "
			    "in module %s\n", mp->modm_module_name);
			return (EFAULT);
		}
		funcadr = kobj_lookup(modp->mod_mp, funcname);

		if (kobj_addrcheck(modp->mod_mp, (caddr_t)funcadr)) {
			printf("%s:%s() not defined properly\n",
			    mp->modm_module_name, funcname);
			return (EFAULT);
		}
		sp->mods_func_adr = funcadr;
	}
	mp->mp = modp;
	return (0);
}

/*
 * modp->mod_modinfo has to be checked in these functions before
 * mod_stub_info is accessed because it's not guranteed that all
 * modules define mod_stub_info structures.
 */
void
install_stubs(struct modctl *modp)
{
	struct mod_stub_info *stub;

	if (modp->mod_modinfo) {
		membar_producer();
		for (stub = modp->mod_modinfo->modm_stubs;
		    stub->mods_func_adr; stub++) {
			stub->mods_flag |= MODS_INSTALLED;
		}
		membar_producer();
	}
}

void
uninstall_stubs(struct modctl *modp)
{
	struct mod_stub_info *stub;

	if (modp->mod_modinfo) {
		membar_producer();
		for (stub = modp->mod_modinfo->modm_stubs;
		    stub->mods_func_adr; stub++) {
			stub->mods_flag &= ~MODS_INSTALLED;
		}
		membar_producer();
	}
}

void
reset_stubs(struct modctl *modp)
{
	struct mod_stub_info *stub;

	if (modp->mod_modinfo) {
		for (stub = modp->mod_modinfo->modm_stubs;
		    stub->mods_func_adr; stub++) {
			if (stub->mods_flag & (MODS_WEAK | MODS_NOUNLOAD))
				stub->mods_func_adr =
				    (uintptr_t)stub->mods_errfcn;
			else
				stub->mods_func_adr =
				    (uintptr_t)mod_hold_stub;
		}
		modp->mod_modinfo->mp = NULL;
	}
}

struct modctl *
mod_getctl(struct modlinkage *modlp)
{
	struct modctl	*modp;

	mutex_enter(&mod_lock);
	modp = &modules;
	do {
		if (modp->mod_linkage == modlp) {
			mutex_exit(&mod_lock);
			return (modp);
		}
	} while ((modp = modp->mod_next) != &modules);
	mutex_exit(&mod_lock);
	return (NULL);
}


/*
 * Attach driver.conf info to devnames for a driver
 */
struct par_list *
impl_make_parlist(major_t major)
{
	int err;
	struct par_list *pl = NULL, *tmp;
	ddi_prop_t *props = NULL;
	char *confname, *drvname;
	struct devnames *dnp;

	dnp = &devnamesp[major];

	ASSERT(mutex_owned(&dnp->dn_lock));

	/*
	 * If .conf file already parsed or driver removed, just return.
	 * May return NULL.
	 */
	if (dnp->dn_flags & (DN_CONF_PARSED | DN_DRIVER_REMOVED))
		return (dnp->dn_pl);

	drvname = mod_major_to_name(major);
	if (drvname == NULL)
		return (NULL);

	confname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) snprintf(confname, MAXNAMELEN, "drv/%s.conf", drvname);
	err = hwc_parse(confname, &pl, &props);
	kmem_free(confname, MAXNAMELEN);
	if (err)	/* file doesn't exist */
		return (NULL);

	/*
	 * If there are global properties, reference it from dnp.
	 */
	if (props)
		dnp->dn_global_prop_ptr = i_ddi_prop_list_create(props);

	/*
	 * Hash specs to be looked up by nexus drivers
	 */
	tmp = pl;
	while (tmp) {
		(void) hwc_hash(tmp->par_specs, major);
		tmp = tmp->par_next;
	}

	if (!i_ddi_io_initialized()) {
		if (i_ddi_prop_search(DDI_DEV_T_ANY, DDI_FORCEATTACH,
		    DDI_PROP_TYPE_INT, &props))
			dnp->dn_flags |= DN_FORCE_ATTACH;
		if (i_ddi_prop_search(DDI_DEV_T_ANY, DDI_OPEN_RETURNS_EINTR,
		    DDI_PROP_TYPE_INT, &props))
			dnp->dn_flags |= DN_OPEN_RETURNS_EINTR;
		if (i_ddi_prop_search(DDI_DEV_T_ANY, "scsi-size-clean",
		    DDI_PROP_TYPE_INT, &props))
			dnp->dn_flags |= DN_SCSI_SIZE_CLEAN;
	}

	if (i_ddi_prop_search(DDI_DEV_T_ANY, DDI_VHCI_CLASS,
	    DDI_PROP_TYPE_STRING, &props))
		dnp->dn_flags |= DN_PHCI_DRIVER;

	if (i_ddi_prop_search(DDI_DEV_T_ANY, DDI_DEVID_REGISTRANT,
	    DDI_PROP_TYPE_INT, &props)) {
		dnp->dn_flags |= DN_DEVID_REGISTRANT;
	}

	dnp->dn_flags |= DN_CONF_PARSED;
	dnp->dn_pl = pl;
	return (pl);
}

/*
 * Destroy driver.conf info in devnames array for a driver
 */
int
impl_free_parlist(major_t major)
{
	struct par_list *pl;
	struct devnames *dnp = &devnamesp[major];

	/*
	 * Unref driver global property list. Don't destroy it
	 * because some instances may still be referencing it.
	 * The property list will be freed when the last ref
	 * goes away.
	 */
	if (dnp->dn_global_prop_ptr) {
		i_ddi_prop_list_rele(dnp->dn_global_prop_ptr, dnp);
		dnp->dn_global_prop_ptr = NULL;
	}

	/*
	 * remove specs from hash table
	 */
	for (pl = dnp->dn_pl; pl; pl = pl->par_next)
		hwc_unhash(pl->par_specs);

	impl_delete_par_list(dnp->dn_pl);
	dnp->dn_pl = NULL;
	dnp->dn_flags &= ~DN_CONF_PARSED;
	return (0);
}

struct bind *mb_hashtab[MOD_BIND_HASHSIZE];
struct bind *sb_hashtab[MOD_BIND_HASHSIZE];

static int
nm_hash(char *name)
{
	char c;
	int hash = 0;

	for (c = *name++; c; c = *name++)
		hash ^= c;

	return (hash & MOD_BIND_HASHMASK);
}

void
clear_binding_hash(struct bind **bhash)
{
	int i;
	struct bind *bp, *bp1;

	for (i = 0; i < MOD_BIND_HASHSIZE; i++) {
		bp = bhash[i];
		while (bp != NULL) {
			kmem_free(bp->b_name, strlen(bp->b_name) + 1);
			if (bp->b_bind_name) {
				kmem_free(bp->b_bind_name,
				    strlen(bp->b_bind_name) + 1);
			}
			bp1 = bp;
			bp = bp->b_next;
			kmem_free(bp1, sizeof (struct bind));
		}
		bhash[i] = NULL;
	}
}

/* Find an mbind by name match (caller can ask for deleted match) */
static struct bind *
find_mbind(char *name, struct bind **hashtab, int deleted)
{
	struct bind	*mb;

	for (mb = hashtab[nm_hash(name)]; mb; mb = mb->b_next) {
		if (deleted && (mb->b_num >= 0))
			continue;			/* skip active */
		if (!deleted && (mb->b_num < 0))
			continue;			/* skip deleted */

		/* return if name matches */
		if (strcmp(name, mb->b_name) == 0) {
			break;
		}
	}
	return (mb);
}

/*
 * Create an entry for the given (name, major, bind_name) tuple in the
 * hash table supplied.  Reject the attempt to do so if 'name' is already
 * in the hash table.
 *
 * Does not provide synchronization, so use only during boot or with
 * externally provided locking.
 */
int
make_mbind(char *name, int num, char *bind_name, struct bind **hashtab)
{
	struct bind	*mb;
	struct bind	**pmb;

	ASSERT(hashtab != NULL);
	ASSERT(num >= 0);

	/* Fail if the key being added is already established */
	if (find_mbind(name, hashtab, 0) != NULL)
		return (-1);

	/* Allocate new mbind */
	mb = kmem_zalloc(sizeof (struct bind), KM_SLEEP);
	mb->b_name = i_ddi_strdup(name, KM_SLEEP);
	mb->b_num = num;
	if (bind_name != NULL)
		mb->b_bind_name = i_ddi_strdup(bind_name, KM_SLEEP);

	/* Insert at head of hash */
	pmb = &hashtab[nm_hash(name)];
	mb->b_next = *pmb;
	*pmb = mb;
	return (0);
}

/*
 * Delete a binding from a binding-hash. Since there is no locking we
 * delete an mbind by making its b_num negative. We also support find_mbind
 * of deleted entries, so we still need deleted items on the list.
 */
void
delete_mbind(char *name, struct bind **hashtab)
{
	struct bind	*mb;

	for (mb = hashtab[nm_hash(name)]; mb; mb = mb->b_next) {
		if ((mb->b_num >= 0) && (strcmp(name, mb->b_name) == 0)) {
			/* delete by making b_num negative */
			if (moddebug & MODDEBUG_BINDING) {
				cmn_err(CE_CONT, "mbind: %s %d deleted\n",
				    name, mb->b_num);
			}
			mb->b_num = -mb->b_num;
			break;
		}
	}
}

/*
 * Delete all items in an mbind associated with specified num.
 * An example would be rem_drv deleting all aliases associated with a
 * driver major number.
 */
void
purge_mbind(int num, struct bind **hashtab)
{
	int		i;
	struct bind	*mb;

	/* search all hash lists for items that associated with 'num' */
	for (i = 0; i < MOD_BIND_HASHSIZE; i++) {
		for (mb = hashtab[i]; mb; mb = mb->b_next) {
			if (mb->b_num == num) {
				if (moddebug & MODDEBUG_BINDING)
					cmn_err(CE_CONT,
					    "mbind: %s %d purged\n",
					    mb->b_name, num);
				/* purge by changing the sign */
				mb->b_num = -num;
			}
		}
	}
}

major_t
mod_name_to_major(char *name)
{
	struct bind	*mbind;
	major_t		maj;

	/* Search for non-deleted match. */
	if ((mbind = find_mbind(name, mb_hashtab, 0)) != NULL) {
		if (moddebug & MODDEBUG_BINDING) {
			if (find_mbind(name, mb_hashtab, 1))
				cmn_err(CE_CONT,
				    "'%s' has deleted match too\n", name);
		}
		return ((major_t)mbind->b_num);
	}

	/*
	 * Search for deleted match: We may find that we have dependencies
	 * on drivers that have been deleted (but the old driver may still
	 * be bound to a node). These callers should be converted to use
	 * ddi_driver_major(i.e. devi_major).
	 */
	if (moddebug & MODDEBUG_BINDING) {
		if ((mbind = find_mbind(name, mb_hashtab, 1)) != NULL) {
			maj = (major_t)(-(mbind->b_num));
			cmn_err(CE_CONT, "Reference to deleted alias '%s' %d\n",
			    name, maj);
		}
	}

	return (DDI_MAJOR_T_NONE);
}

char *
mod_major_to_name(major_t major)
{
	if (!driver_installed(major))
		return (NULL);
	return ((&devnamesp[major])->dn_name);
}

/*
 * Set up the devnames array.  Error check for duplicate entries.
 */
void
init_devnamesp(int size)
{
	int hshndx;
	struct bind *bp;
	static char dupwarn[] =
	    "!Device entry \"%s %d\" conflicts with previous entry \"%s %d\" "
	    "in /etc/name_to_major.";
	static char badmaj[] = "The major number %u is invalid.";

	ASSERT(size <= L_MAXMAJ32 && size > 0);

	/*
	 * Allocate the devnames array.  All mutexes and cv's will be
	 * automagically initialized.
	 */
	devnamesp = kobj_zalloc(size * sizeof (struct devnames), KM_SLEEP);

	/*
	 * Stick the contents of mb_hashtab into the devnames array.  Warn if
	 * two hash entries correspond to the same major number, or if a
	 * major number is out of range.
	 */
	for (hshndx = 0; hshndx < MOD_BIND_HASHSIZE; hshndx++) {
		for (bp = mb_hashtab[hshndx]; bp; bp = bp->b_next) {
			if (make_devname(bp->b_name,
			    (major_t)bp->b_num, 0) != 0) {
				/*
				 * If there is not an entry at b_num already,
				 * then this must be a bad major number.
				 */
				char *nm = mod_major_to_name(bp->b_num);
				if (nm == NULL) {
					cmn_err(CE_WARN, badmaj,
					    (uint_t)bp->b_num);
				} else {
					cmn_err(CE_WARN, dupwarn, bp->b_name,
					    bp->b_num, nm, bp->b_num);
				}
			}
		}
	}

	/* Initialize hash table for hwc_spec's */
	hwc_hash_init();
}

int
make_devname(char *name, major_t major, int dn_flags)
{
	struct devnames *dnp;
	char *copy;

	/*
	 * Until on-disk support for major nums > 14 bits arrives, fail
	 * any major numbers that are too big.
	 */
	if (major > L_MAXMAJ32)
		return (EINVAL);

	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&dnp->dn_lock);
	if (dnp->dn_name) {
		if (strcmp(dnp->dn_name, name) != 0) {
			/* Another driver already here */
			UNLOCK_DEV_OPS(&dnp->dn_lock);
			return (EINVAL);
		}
		/* Adding back a removed driver */
		dnp->dn_flags &= ~DN_DRIVER_REMOVED;
		dnp->dn_flags |= dn_flags;
		UNLOCK_DEV_OPS(&dnp->dn_lock);
		return (0);
	}

	/*
	 * Check if flag is taken by getudev()
	 */
	if (dnp->dn_flags & DN_TAKEN_GETUDEV) {
		UNLOCK_DEV_OPS(&dnp->dn_lock);
		return (EINVAL);
	}

	copy = kmem_alloc(strlen(name) + 1, KM_SLEEP);
	(void) strcpy(copy, name);

	/* Make sure string is copied before setting dn_name */
	membar_producer();
	dnp->dn_name = copy;
	dnp->dn_flags = dn_flags;
	UNLOCK_DEV_OPS(&dnp->dn_lock);
	return (0);
}

/*
 * Set up the syscallnames array.
 */
void
init_syscallnames(int size)
{
	int hshndx;
	struct bind *bp;

	syscallnames = kobj_zalloc(size * sizeof (char *), KM_SLEEP);

	for (hshndx = 0; hshndx < MOD_BIND_HASHSIZE; hshndx++) {
		for (bp = sb_hashtab[hshndx]; bp; bp = bp->b_next) {
			if (bp->b_num < 0 || bp->b_num >= size) {
				cmn_err(CE_WARN,
				    "!Couldn't add system call \"%s %d\". "
				    "Value out of range (0..%d) in "
				    "/etc/name_to_sysnum.",
				    bp->b_name, bp->b_num, size - 1);
				continue;
			}
			make_syscallname(bp->b_name, bp->b_num);
		}
	}
}

static void
make_syscallname(char *name, int sysno)
{
	char **cp = &syscallnames[sysno];

	if (*cp != NULL) {
		cmn_err(CE_WARN, "!Couldn't add system call \"%s %d\". "
		    "It conflicts with \"%s %d\" in /etc/name_to_sysnum.",
		    name, sysno, *cp, sysno);
		return;
	}
	*cp = kmem_alloc(strlen(name) + 1, KM_SLEEP);
	(void) strcpy(*cp, name);
}

/*
 * Given a system call name, get its number.
 */
int
mod_getsysnum(char *name)
{
	struct bind *mbind;

	if ((mbind = find_mbind(name, sb_hashtab, 0)) != NULL)
		return (mbind->b_num);

	return (-1);
}

/*
 * Given a system call number, get the system call name.
 */
char *
mod_getsysname(int sysnum)
{
	return (syscallnames[sysnum]);
}

/*
 * Find the name of the module containing the specified pc.
 * Returns the name on success, "<unknown>" on failure.
 * No mod_lock locking is required because things are never deleted from
 * the &modules list.
 */
char *
mod_containing_pc(caddr_t pc)
{
	struct modctl	*mcp = &modules;

	do {
		if (mcp->mod_mp != NULL &&
		    (size_t)pc - (size_t)mcp->mod_text < mcp->mod_text_size)
			return (mcp->mod_modname);
	} while ((mcp = mcp->mod_next) != &modules);
	return ("<unknown>");
}

/*
 * Hash tables for hwc_spec
 *
 * The purpose of these hash tables are to allow the framework to discover
 * all possible .conf children for a given nexus. There are two hash tables.
 * One is hashed based on parent name, the on the class name. Each
 * driver.conf file translates to a list of hwc_spec's. Adding and
 * removing the entire list is an atomic operation, protected by
 * the hwc_hash_lock.
 *
 * What we get from all the hashing is the function hwc_get_child_spec().
 */
#define	HWC_SPEC_HASHSIZE	(1 << 6)	/* 64 */

static mod_hash_t *hwc_par_hash;	/* hash by parent name */
static mod_hash_t *hwc_class_hash;	/* hash by class name */
static kmutex_t hwc_hash_lock;		/* lock protecting hwc hashes */

/*
 * Initialize hash tables for parent and class specs
 */
static void
hwc_hash_init()
{
	hwc_par_hash = mod_hash_create_strhash("hwc parent spec hash",
	    HWC_SPEC_HASHSIZE, mod_hash_null_valdtor);
	hwc_class_hash = mod_hash_create_strhash("hwc class spec hash",
	    HWC_SPEC_HASHSIZE, mod_hash_null_valdtor);
}

/*
 * Insert a spec into hash table. hwc_hash_lock must be held
 */
static void
hwc_hash_insert(struct hwc_spec *spec, char *name, mod_hash_t *hash)
{
	mod_hash_key_t key;
	struct hwc_spec *entry = NULL;

	ASSERT(name != NULL);

	if (mod_hash_find(hash, (mod_hash_key_t)name,
	    (mod_hash_val_t)&entry) != 0) {
		/* Name doesn't exist, insert a new key */
		key = kmem_alloc(strlen(name) + 1, KM_SLEEP);
		(void) strcpy((char *)key, name);
		if (mod_hash_insert(hash, key, (mod_hash_val_t)spec) != 0) {
			kmem_free(key, strlen(name) + 1);
			cmn_err(CE_WARN, "hwc hash state inconsistent");
		}
		return;
	}

	/*
	 * Name is already present, append spec to the list.
	 * This is the case when driver.conf specifies multiple
	 * nodes under a single parent or class.
	 */
	while (entry->hwc_hash_next)
		entry = entry->hwc_hash_next;
	entry->hwc_hash_next = spec;
}

/*
 * Remove a spec entry from spec hash table, the spec itself is
 * destroyed external to this function.
 */
static void
hwc_hash_remove(struct hwc_spec *spec, char *name, mod_hash_t *hash)
{
	char *key;
	struct hwc_spec *entry;

	ASSERT(name != NULL);

	if (mod_hash_find(hash, (mod_hash_key_t)name,
	    (mod_hash_val_t)&entry) != 0) {
		return;	/* name not found in hash */
	}

	/*
	 * If the head is the spec to be removed, either destroy the
	 * entry or replace it with the remaining list.
	 */
	if (entry == spec) {
		if (spec->hwc_hash_next == NULL) {
			(void) mod_hash_destroy(hash, (mod_hash_key_t)name);
			return;
		}
		key = kmem_alloc(strlen(name) + 1, KM_SLEEP);
		(void) strcpy(key, name);
		(void) mod_hash_replace(hash, (mod_hash_key_t)key,
		    (mod_hash_val_t)spec->hwc_hash_next);
		spec->hwc_hash_next = NULL;
		return;
	}

	/*
	 * If the head is not the one, look for the spec in the
	 * hwc_hash_next linkage.
	 */
	while (entry->hwc_hash_next && (entry->hwc_hash_next != spec))
		entry = entry->hwc_hash_next;

	if (entry->hwc_hash_next) {
		entry->hwc_hash_next = spec->hwc_hash_next;
		spec->hwc_hash_next = NULL;
	}
}

/*
 * Hash a list of specs based on either parent name or class name
 */
static void
hwc_hash(struct hwc_spec *spec_list, major_t major)
{
	struct hwc_spec *spec = spec_list;

	mutex_enter(&hwc_hash_lock);
	while (spec) {
		/* Put driver major here so parent can find it */
		spec->hwc_major = major;

		if (spec->hwc_parent_name != NULL) {
			hwc_hash_insert(spec, spec->hwc_parent_name,
			    hwc_par_hash);
		} else if (spec->hwc_class_name != NULL) {
			hwc_hash_insert(spec, spec->hwc_class_name,
			    hwc_class_hash);
		} else {
			cmn_err(CE_WARN,
			    "hwc_hash: No class or parent specified");
		}
		spec = spec->hwc_next;
	}
	mutex_exit(&hwc_hash_lock);
}

/*
 * Remove a list of specs from hash tables. Don't destroy the specs yet.
 */
static void
hwc_unhash(struct hwc_spec *spec_list)
{
	struct hwc_spec *spec = spec_list;

	mutex_enter(&hwc_hash_lock);
	while (spec) {
		if (spec->hwc_parent_name != NULL) {
			hwc_hash_remove(spec, spec->hwc_parent_name,
			    hwc_par_hash);
		} else if (spec->hwc_class_name != NULL) {
			hwc_hash_remove(spec, spec->hwc_class_name,
			    hwc_class_hash);
		} else {
			cmn_err(CE_WARN,
			    "hwc_unhash: No class or parent specified");
		}
		spec = spec->hwc_next;
	}
	mutex_exit(&hwc_hash_lock);
}

/*
 * Make a copy of specs in a hash entry and add to the end of listp.
 * Called by nexus to locate a list of child specs.
 *
 * entry is a list of hwc_spec chained together with hwc_hash_next.
 * listp points to list chained together with hwc_next.
 */
static void
hwc_spec_add(struct hwc_spec **listp, struct hwc_spec *entry,
    major_t match_major)
{
	/* Find the tail of the list */
	while (*listp)
		listp = &(*listp)->hwc_next;

	while (entry) {
		struct hwc_spec *spec;

		if ((match_major != DDI_MAJOR_T_NONE) &&
		    (match_major != entry->hwc_major)) {
			entry = entry->hwc_hash_next;
			continue;
		}

		/*
		 * Allocate spec and copy the content of entry.
		 * No need to copy class/parent name since caller
		 * already knows the parent dip.
		 */
		spec = kmem_zalloc(sizeof (*spec), KM_SLEEP);
		spec->hwc_devi_name = i_ddi_strdup(
		    entry->hwc_devi_name, KM_SLEEP);
		spec->hwc_major = entry->hwc_major;
		spec->hwc_devi_sys_prop_ptr = i_ddi_prop_list_dup(
		    entry->hwc_devi_sys_prop_ptr, KM_SLEEP);

		*listp = spec;
		listp = &spec->hwc_next;
		entry = entry->hwc_hash_next;
	}
}

/*
 * Given a dip, find the list of child .conf specs from most specific
 * (parent pathname) to least specific (class name).
 *
 * This function allows top-down loading to be implemented without
 * changing the format of driver.conf file.
 */
struct hwc_spec *
hwc_get_child_spec(dev_info_t *dip, major_t match_major)
{
	extern char *i_ddi_parname(dev_info_t *, char *);
	extern int i_ddi_get_exported_classes(dev_info_t *, char ***);
	extern void i_ddi_free_exported_classes(char **, int);

	int i, nclass;
	char **classes;
	struct hwc_spec *list = NULL;
	mod_hash_val_t val;
	char *parname, *parname_buf;
	char *deviname, *deviname_buf;
	char *pathname, *pathname_buf;
	char *bindname;
	char *drvname;

	pathname_buf = kmem_alloc(3 * MAXPATHLEN, KM_SLEEP);
	deviname_buf = pathname_buf + MAXPATHLEN;
	parname_buf = pathname_buf + (2 * MAXPATHLEN);

	mutex_enter(&hwc_hash_lock);

	/*
	 * Lookup based on full path.
	 * In the case of root node, ddi_pathname would return
	 * null string so just skip calling it.
	 * As the pathname always begins with /, no simpler
	 * name can duplicate it.
	 */
	pathname = (dip == ddi_root_node()) ? "/" :
	    ddi_pathname(dip, pathname_buf);
	ASSERT(pathname != NULL);
	ASSERT(*pathname == '/');

	if (mod_hash_find(hwc_par_hash, (mod_hash_key_t)pathname, &val) == 0) {
		hwc_spec_add(&list, (struct hwc_spec *)val, match_major);
	}

	/*
	 * Lookup nodename@address.
	 * Note deviname cannot match pathname.
	 */
	deviname = ddi_deviname(dip, deviname_buf);
	if (*deviname != '\0') {
		/*
		 * Skip leading / returned by ddi_deviname.
		 */
		ASSERT(*deviname == '/');
		deviname++;
		if ((*deviname != '\0') && (mod_hash_find(hwc_par_hash,
		    (mod_hash_key_t)deviname, &val) == 0))
			hwc_spec_add(&list,
			    (struct hwc_spec *)val, match_major);
	}

	/*
	 * Lookup bindingname@address.
	 * Take care not to perform duplicate lookups.
	 */
	parname = i_ddi_parname(dip, parname_buf);
	if (*parname != '\0') {
		ASSERT(*parname != '/');
		if ((strcmp(parname, deviname) != 0) &&
		    (mod_hash_find(hwc_par_hash,
		    (mod_hash_key_t)parname, &val) == 0)) {
			hwc_spec_add(&list,
			    (struct hwc_spec *)val, match_major);
		}
	}

	/*
	 * Lookup driver binding name
	 */
	bindname = ddi_binding_name(dip);
	ASSERT(*bindname != '/');
	if ((strcmp(bindname, parname) != 0) &&
	    (strcmp(bindname, deviname) != 0) &&
	    (mod_hash_find(hwc_par_hash, (mod_hash_key_t)bindname, &val) == 0))
		hwc_spec_add(&list, (struct hwc_spec *)val, match_major);

	/*
	 * Lookup driver name
	 */
	drvname = (char *)ddi_driver_name(dip);
	ASSERT(*drvname != '/');
	if ((strcmp(drvname, bindname) != 0) &&
	    (strcmp(drvname, parname) != 0) &&
	    (strcmp(drvname, deviname) != 0) &&
	    (mod_hash_find(hwc_par_hash, (mod_hash_key_t)drvname, &val) == 0))
		hwc_spec_add(&list, (struct hwc_spec *)val, match_major);

	kmem_free(pathname_buf, 3 * MAXPATHLEN);

	/*
	 * Lookup classes exported by this node and lookup the
	 * class hash table for all .conf specs
	 */
	nclass = i_ddi_get_exported_classes(dip, &classes);
	for (i = 0; i < nclass; i++) {
		if (mod_hash_find(hwc_class_hash, (mod_hash_key_t)classes[i],
		    &val) == 0)
			hwc_spec_add(&list, (struct hwc_spec *)val,
			    match_major);
	}
	i_ddi_free_exported_classes(classes, nclass);

	mutex_exit(&hwc_hash_lock);
	return (list);
}
