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

/*
 * DACF: device autoconfiguration support
 *
 * DACF provides a fast, lightweight policy engine for the I/O subsystem.
 * This policy engine provides a mechanism for auto-configuring and
 * auto-unconfiguring devices.
 *
 * After a device is attach(9E)ed, additional configuration may be needed in
 * order to make the device available for use by the system.  For example,
 * STREAMS modules may need to be pushed atop the driver in order to create
 * a STREAMS stack.  If the device is to be removed from the system, these
 * configuration operations need to be undone, and the device prepared for
 * detach(9E).
 *
 * It is desirable to move the implementation of such policies outside of the
 * kernel proper, since such operations are typically infrequent.  To this end,
 * DACF manages kernel modules in (module_path)/dacf directories.  These adhere
 * to the api defined in sys/dacf.h, and register sets of configuration
 * operations.  The kernel loads these modules when the operations they
 * implement are needed, and can unload them at any time thereafter.
 * Implementing configuration operations in external modules can also increase
 * code reuse.
 *
 * DACF provides a policy database which associates
 *
 *   (device descr., kernel action) --> (configuration operation, parameters)
 *
 * - Device description is matching rule, for example:
 * 	minor-nodetype="ddi_keyboard"
 * - Kernel action is a reference to a dacf kernel hook.
 *      currently supported are "post-attach" and "pre-detach"
 * - Configuration action is a reference to a module and a set of operations
 *      within the module, for example:  consconfig:kbd_config
 * - Parameters is a list of name="value" parameters to be passed to the
 *      configuration operation when invoked.
 *
 * The contents of the rules database are loaded from /etc/dacf.conf upon boot.
 *
 * DACF kernel hooks are comprised of a call into the rule-matching engine,
 * using parameters from the hook in order find a matching rule.  If one is
 * found, the framework can invoke the configuration operation immediately, or
 * defer doing so until later, by putting the rule on a 'reservation list.'
 */

#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/pathname.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunddi.h>
#include <sys/autoconf.h>
#include <sys/modhash.h>
#include <sys/dacf.h>
#include <sys/dacf_impl.h>
#include <sys/systm.h>
#include <sys/varargs.h>
#include <sys/debug.h>
#include <sys/log.h>
#include <sys/fs/snode.h>

/*
 * Enumeration of the ops exported by the dacf framework.
 *
 * To add a new op to the framework, add it to this list, update dacf.h,
 * (don't miss DACF_NUM_OPIDS) and modify dacf_rule_matrix.
 *
 */
typedef struct dacf_opmap {
	const char *name;
	dacf_opid_t id;
} dacf_opmap_t;

static dacf_opmap_t dacf_ops[] = {
	{ "post-attach",	DACF_OPID_POSTATTACH		},
	{ "pre-detach",		DACF_OPID_PREDETACH		},
	{ NULL,			0				},
};

/*
 * Enumeration of the options exported by the dacf framework (currently none).
 *
 * To add a new option, add it to this array.
 */
typedef struct dacf_opt {
	const char *optname;
	uint_t optmask;
} dacf_opt_t;

static dacf_opt_t dacf_options[] = {
#ifdef DEBUG
	{ "testopt", 		1		},
	{ "testopt2", 		2		},
#endif
	{ NULL, 		0		},
};

static char kmod_name[] = "__kernel";

/*
 * Enumeration of the device specifiers exported by the dacf framework.
 *
 * To add a new devspec to the framework, add it to this list, update dacf.h,
 * (don't miss DACF_NUM_DEVSPECS), modify dacf_rule_matrix, and modify
 * dacf_match().
 */
typedef struct dacf_ds {
	const char *name;
	dacf_devspec_t id;
} dacf_ds_t;

static dacf_ds_t dacf_devspecs[] = {
	{ "minor-nodetype", 	DACF_DS_MIN_NT 		},
	{ "driver-minorname", 	DACF_DS_DRV_MNAME	},
	{ "device-path",	DACF_DS_DEV_PATH	},
	{ NULL,			NULL			},
};

mod_hash_t *posta_mntype, *posta_mname, *posta_devname;	/* post-attach */
mod_hash_t *pred_mntype, *pred_mname, *pred_devname;	/* pre-detach */

mod_hash_t *dacf_module_hash;
mod_hash_t *dacf_info_hash;

/*
 * This is the lookup table for the hash tables that dacf manages.  Given an
 * op id and devspec type, one can obtain the hash for that type of data.
 */
mod_hash_t **dacf_rule_matrix[DACF_NUM_OPIDS][DACF_NUM_DEVSPECS] = {
	{ &posta_mntype, 	&posta_mname,	&posta_devname	},
	{ &pred_mntype,		&pred_mname,	&pred_devname	},
};

kmutex_t dacf_lock;
kmutex_t dacf_module_lock;

int dacfdebug = 0;

static dacf_rule_t *dacf_rule_ctor(char *, char *, char *, dacf_opid_t,
    uint_t, dacf_arg_t *);
static mod_hash_t *dacf_get_op_hash(dacf_opid_t, dacf_devspec_t);
static void dacf_rule_val_dtor(mod_hash_val_t);
static void dacf_destroy_opsets(dacf_module_t *module);
static void dacf_opset_copy(dacf_opset_t *dst, dacf_opset_t *src);
static void dprintf(const char *, ...) __KPRINTFLIKE(1);

/*PRINTFLIKE1*/
static void
dprintf(const char *format, ...)
{
	va_list alist;
	char dp_buf[256], *dpbp;
	if (dacfdebug & DACF_DBG_MSGS) {
		va_start(alist, format);
		/*
		 * sprintf up the string that is 'dacf debug: <the message>'
		 */
		(void) sprintf(dp_buf, "dacf debug: ");
		dpbp = &(dp_buf[strlen(dp_buf)]);
		(void) vsnprintf(dpbp, sizeof (dp_buf) - strlen(dp_buf),
		    format, alist);
		printf(dp_buf);
		va_end(alist);
	}
}

/*
 * dacf_init()
 * 	initialize the dacf framework by creating the various hash tables.
 */
void
dacf_init()
{
	int i, j;
	char hbuf[40];

	mutex_enter(&dacf_lock);

	dprintf("dacf_init: creating hashmatrix\n");

#ifdef DEBUG
	/*
	 * Sanity check that DACF_NUM_DEVSPECS and the devspecs are in sync
	 */
	for (i = 0; dacf_devspecs[i].name != NULL; i++)
		continue;
	ASSERT(i == DACF_NUM_DEVSPECS);

	/*
	 * Sanity check that DACF_NUM_OPIDS and the dacf_ops are in sync
	 */
	for (i = 0; dacf_ops[i].name != NULL; i++)
		continue;
	ASSERT(i == DACF_NUM_OPIDS);
#endif

	for (i = 0; i < DACF_NUM_OPIDS; i++) {
		for (j = 0; j < DACF_NUM_DEVSPECS; j++) {
			if (dacf_rule_matrix[i][j] == NULL) {
				continue;
			}
			/*
			 * Set up a hash table with no key destructor.  The
			 * keys are carried in the rule_t, so the val_dtor
			 * will take care of the key as well.
			 */
			(void) snprintf(hbuf, sizeof (hbuf),
			    "dacf hashmatrix [%d][%d]", i, j);
			*(dacf_rule_matrix[i][j]) = mod_hash_create_extended(
			    hbuf,			/* hash name */
			    DACF_RULE_HASHSIZE,		/* # hash elems */
			    mod_hash_null_keydtor,	/* key dtor */
			    dacf_rule_val_dtor,		/* value dtor */
			    mod_hash_bystr, NULL, 	/* hash alg & data */
			    mod_hash_strkey_cmp,	/* key comparator */
			    KM_SLEEP);
		}
	}

	dprintf("dacf_init: creating module_hash\n");
	/*
	 * dacf_module_hash stores the currently registered dacf modules
	 * by name.
	 */
	dacf_module_hash = mod_hash_create_strhash("dacf module hash",
	    DACF_MODULE_HASHSIZE, mod_hash_null_valdtor);

	dprintf("dacf_init: creating info_hash\n");
	/*
	 * dacf_info_hash stores pointers to data that modules can associate
	 * on a per minornode basis.  The type of data stored is opaque to the
	 * framework-- thus there is no destructor supplied.
	 */
	dacf_info_hash = mod_hash_create_ptrhash("dacf info hash",
	    DACF_INFO_HASHSIZE, mod_hash_null_valdtor,
	    sizeof (struct ddi_minor_data));

	mutex_exit(&dacf_lock);

	/*
	 * Register the '__kernel' module.
	 *
	 * These are operations that are provided by the kernel, not by a
	 * module.  We just feed the framework a dacfsw structure; it will get
	 * marked as 'loaded' by dacf_module_register(), and will always be
	 * available.
	 */
	(void) dacf_module_register(kmod_name, &kmod_dacfsw);

	(void) read_dacf_binding_file(NULL);

	dprintf("dacf_init: dacf is ready\n");
}

/*
 * dacf_clear_rules()
 * 	clear the dacf rule database.  This is typically done in advance of
 * 	rereading the dacf binding file.
 */
void
dacf_clear_rules()
{
	int i, j;
	ASSERT(MUTEX_HELD(&dacf_lock));

	for (i = 0; i < DACF_NUM_OPIDS; i++) {
		for (j = 0; j < DACF_NUM_DEVSPECS; j++) {
			if ((dacf_rule_matrix[i][j] != NULL) &&
			    (*(dacf_rule_matrix[i][j]) != NULL)) {
				mod_hash_clear(*(dacf_rule_matrix[i][j]));
			}
		}
	}
}

/*
 * dacf_rule_insert()
 *	Create an entry in the dacf rule database.
 *	If 'module' is null, the kernel is the 'module'. (see dacf_rule_ctor()).
 */
int
dacf_rule_insert(dacf_devspec_t devspec_type, char *devspec_data,
    char *module, char *opset, dacf_opid_t opid, uint_t opts,
    dacf_arg_t *op_args)
{
	dacf_rule_t *rule;
	mod_hash_t *hash;

	ASSERT(devspec_type != DACF_DS_ERROR);
	ASSERT(devspec_data);
	ASSERT(opset);
	ASSERT(MUTEX_HELD(&dacf_lock));

	dprintf("dacf_rule_insert called: %s=\"%s\", %s:%s, %s\n",
	    dacf_devspec_to_str(devspec_type), devspec_data,
	    module ? module : "[kernel]", opset, dacf_opid_to_str(opid));

	/*
	 * Fetch the hash table associated with this op-name and devspec-type.
	 * Some ops may not support all devspec-types, since they may be
	 * meaningless, so hash may be null.
	 */
	hash = dacf_get_op_hash(opid, devspec_type);
	if (hash == NULL) {
		cmn_err(CE_WARN, "!dacf dev-spec '%s' does not support op '%s'",
		    dacf_devspec_to_str(devspec_type), dacf_opid_to_str(opid));
		return (-1);
	}

	/*
	 * Allocate a rule  and fill it in, take a hold on it.
	 */
	rule = dacf_rule_ctor(devspec_data, module, opset, opid, opts,
	    op_args);
	dacf_rule_hold(rule);

	if (mod_hash_insert(hash, (mod_hash_key_t)rule->r_devspec_data,
	    (mod_hash_val_t)rule) != 0) {
		/*
		 * We failed, so release hold.  This will cause the rule and
		 * associated data to get nuked.
		 */
		dacf_rule_rele(rule);

		cmn_err(CE_WARN, "!dacf rule %s='%s' %s:%s %s duplicates "
		    "another rule, ignored", dacf_devspec_to_str(devspec_type),
		    devspec_data, module, opset, dacf_opid_to_str(opid));
		return (-1);
	}
	return (0);
}

/*
 * dacf_rule_ctor()
 * 	Allocate and fill out entries in a dacf_rule_t.
 */
static dacf_rule_t *
dacf_rule_ctor(char *device_spec, char *module, char *opset, dacf_opid_t opid,
    uint_t opts, dacf_arg_t *op_args)
{
	dacf_rule_t *rule;
	dacf_arg_t *p;

	rule = kmem_alloc(sizeof (dacf_rule_t), KM_SLEEP);

	/*
	 * Fill in the entries
	 */
	rule->r_devspec_data = kmem_alloc(strlen(device_spec) + 1, KM_SLEEP);
	(void) strcpy(rule->r_devspec_data, device_spec);

	/*
	 * If module is 'null' we set it to __kernel, meaning that this op
	 * is implemented by the kernel.
	 */
	if (module == NULL) {
		module = kmod_name;
	}

	rule->r_module = kmem_alloc(strlen(module) + 1, KM_SLEEP);
	(void) strcpy(rule->r_module, module);

	rule->r_opset = kmem_alloc(strlen(opset) + 1, KM_SLEEP);
	(void) strcpy(rule->r_opset, opset);

	rule->r_refs = 0;	/* no refs yet */
	rule->r_opts = opts;
	rule->r_opid = opid;

	rule->r_args = NULL;
	p = op_args;
	while (p != NULL) {
		ASSERT(p->arg_name);
		ASSERT(p->arg_val);
		/*
		 * dacf_arg_insert() should always succeed, since we're copying
		 * another (already duplicate-free) list.
		 */
		(void) dacf_arg_insert(&rule->r_args, p->arg_name, p->arg_val);
		p = p->arg_next;
	}

	return (rule);
}

/*
 * dacf_rule_val_dtor()
 * 	This is the destructor for dacf_rule_t's in the rule database.  It
 * 	simply does a dacf_rule_rele() on the rule.  This function will take
 * 	care of destroying the rule if its ref count has dropped to 0.
 */
static void
dacf_rule_val_dtor(mod_hash_val_t val)
{
	ASSERT((void *)val != NULL);
	dacf_rule_rele((dacf_rule_t *)val);
}

/*
 * dacf_rule_destroy()
 * 	destroy a dacf_rule_t
 */
void
dacf_rule_destroy(dacf_rule_t *rule)
{
	ASSERT(rule->r_refs == 0);
	/*
	 * Free arguments.
	 */
	dacf_arglist_delete(&(rule->r_args));
	kmem_free(rule->r_devspec_data, strlen(rule->r_devspec_data) + 1);
	/*
	 * Module may be null for a kernel-managed op-set
	 */
	kmem_free(rule->r_module, strlen(rule->r_module) + 1);
	kmem_free(rule->r_opset, strlen(rule->r_opset) + 1);
	kmem_free(rule, sizeof (dacf_rule_t));
}

/*
 * dacf_rule_hold()
 * 	dacf rules are ref-counted.  This function increases the reference
 * 	count on an rule.
 */
void
dacf_rule_hold(dacf_rule_t *rule)
{
	ASSERT(MUTEX_HELD(&dacf_lock));

	rule->r_refs++;
}

/*
 * dacf_rule_rele()
 * 	drop the ref count on an rule, and destroy the rule if its
 * 	ref count drops to 0.
 */
void
dacf_rule_rele(dacf_rule_t *rule)
{
	ASSERT(MUTEX_HELD(&dacf_lock));
	ASSERT(rule->r_refs > 0);

	rule->r_refs--;
	if (rule->r_refs == 0) {
		dacf_rule_destroy(rule);
	}
}

/*
 * dacf_rsrv_make()
 * 	add an rule to a reservation list to be processed later.
 */
void
dacf_rsrv_make(dacf_rsrvlist_t *rsrv, dacf_rule_t *rule, void *info,
    dacf_rsrvlist_t **list)
{
	dacf_infohdl_t ihdl = info;
	ASSERT(MUTEX_HELD(&dacf_lock));
	ASSERT(info && rule && list);

	/*
	 * Bump the ref count on rule, so it won't get freed as long as it's on
	 * this reservation list.
	 */
	dacf_rule_hold(rule);

	rsrv->rsrv_rule = rule;
	rsrv->rsrv_ihdl = ihdl;
	rsrv->rsrv_result = DDI_SUCCESS;
	rsrv->rsrv_next = *list;
	*list = rsrv;

	dprintf("dacf: reservation made\n");
}

/*
 * dacf_clr_rsrvs()
 * 	clear reservation list of operations of type 'op'
 */
void
dacf_clr_rsrvs(dev_info_t *devi, dacf_opid_t op)
{
	dacf_process_rsrvs(&(DEVI(devi)->devi_dacf_tasks), op, DACF_PROC_RELE);
}

/*
 * dacf_process_rsrvs()
 * 	iterate across a locked reservation list, processing each element
 * 	which matches 'op' according to 'flags'.
 *
 * 	if DACF_PROC_INVOKE is specified, the elements that match 'op'
 * 	will have their operations invoked.  The return value from that
 * 	operation is placed in the rsrv_result field of the dacf_rsrvlist_t
 */
void
dacf_process_rsrvs(dacf_rsrvlist_t **list, dacf_opid_t op, int flags)
{
	dacf_rsrvlist_t *p, *dp;
	dacf_rsrvlist_t **prevptr;

	ASSERT(MUTEX_HELD(&dacf_lock));
	ASSERT(list);
	ASSERT(flags != 0);

	if (*list == NULL)
		return;

	dprintf("dacf_process_rsrvs: opid = %d, flags = 0x%x\n", op, flags);

	/*
	 * Walk the list, finding rules whose opid's match op, and performing
	 * the work described by 'flags'.
	 */
	prevptr = list;
	for (p = *list; p != NULL; ) {

		if (p->rsrv_rule->r_opid != op) {
			prevptr = &(p->rsrv_next);
			p = p->rsrv_next;
			continue;
		}

		if (flags & DACF_PROC_INVOKE) {
			p->rsrv_result = dacf_op_invoke(p->rsrv_rule,
			    p->rsrv_ihdl, 0);
		}

		if (flags & DACF_PROC_RELE) {
			*prevptr = p->rsrv_next;
			dp = p;
			p = p->rsrv_next;
			dacf_rule_rele(dp->rsrv_rule);
			kmem_free(dp, sizeof (dacf_rsrvlist_t));
		} else {
			prevptr = &(p->rsrv_next);
			p = p->rsrv_next;
		}
	}
}

/*
 * dacf_get_op_hash()
 * 	Given an op name, (i.e. "post-attach" or "pre-detach") and a
 * 	devspec-type, return the hash that represents that op indexed
 * 	by that devspec.
 */
static mod_hash_t *
dacf_get_op_hash(dacf_opid_t op, dacf_devspec_t ds_type)
{
	ASSERT(op <= DACF_NUM_OPIDS && op > 0);
	ASSERT(ds_type <= DACF_NUM_DEVSPECS && ds_type > 0);

	/*
	 * dacf_rule_matrix is an array of pointers to pointers to hashes.
	 */
	if (dacf_rule_matrix[op - 1][ds_type - 1] == NULL) {
		return (NULL);
	}
	return (*(dacf_rule_matrix[op - 1][ds_type - 1]));
}

/*
 * dacf_arg_insert()
 * 	Create and insert an entry in an argument list.
 * 	Returns -1 if the argument name is a duplicate of another already
 * 	present in the hash.
 */
int
dacf_arg_insert(dacf_arg_t **list, char *name, char *val)
{
	dacf_arg_t *arg;

	/*
	 * Don't allow duplicates.
	 */
	for (arg = *list; arg != NULL; arg = arg->arg_next) {
		if (strcmp(arg->arg_name, name) == 0) {
			return (-1);
		}
	}

	arg = kmem_alloc(sizeof (dacf_arg_t), KM_SLEEP);
	arg->arg_name = kmem_alloc(strlen(name) + 1, KM_SLEEP);
	(void) strcpy(arg->arg_name, name);
	arg->arg_val = kmem_alloc(strlen(val) + 1, KM_SLEEP);
	(void) strcpy(arg->arg_val, val);

	arg->arg_next = *list;
	*list = arg;

	return (0);
}

/*
 * dacf_arglist_delete()
 * 	free all the elements of a list of dacf_arg_t's.
 */
void
dacf_arglist_delete(dacf_arg_t **list)
{
	dacf_arg_t *arg, *narg;
	arg = *list;
	while (arg != NULL) {
		narg = arg->arg_next;
		kmem_free(arg->arg_name, strlen(arg->arg_name) + 1);
		kmem_free(arg->arg_val, strlen(arg->arg_val) + 1);
		kmem_free(arg, sizeof (dacf_arg_t));
		arg = narg;
	}
	*list = NULL;
}

/*
 * dacf_match()
 * 	Match a device-spec to a rule.
 */
dacf_rule_t *
dacf_match(dacf_opid_t op, dacf_devspec_t ds, void *match_info)
{
	dacf_rule_t *rule;

	ASSERT(MUTEX_HELD(&dacf_lock));

	if (mod_hash_find(dacf_get_op_hash(op, ds), (mod_hash_key_t)match_info,
	    (mod_hash_val_t *)&rule) == 0) {
		return (rule);
	}

	return (NULL);	/* Not Found */
}

/*
 * dacf_module_register()
 * 	register a module with the framework.  Use when a module gets loaded,
 * 	or for the kernel to register a "virtual" module (i.e. a "module"
 * 	which the kernel provides).  Makes a copy of the interface description
 * 	provided by the module.
 */
int
dacf_module_register(char *mod_name, struct dacfsw *sw)
{
	char *str;
	size_t i, nelems;
	dacf_module_t *module;
	dacf_opset_t *opsarray;

	if (sw == NULL) {
		return (EINVAL);
	}

	if (sw->dacf_rev != DACF_MODREV_1) {
		cmn_err(CE_WARN, "dacf: module '%s' exports unsupported "
		    "version %d interface, not registered\n", mod_name,
		    sw->dacf_rev);
		return (EINVAL);
	}

	/*
	 * count how many opsets are provided.
	 */
	for (nelems = 0; sw->dacf_opsets[nelems].opset_name != NULL; nelems++)
		;

	dprintf("dacf_module_register: found %lu opsets\n", nelems);

	/*
	 * Temporary: It's ok for the kernel dacf_sw to have no opsets, since
	 * we don't have any opsets to export yet (in NON-DEBUG).
	 */
	if ((nelems == 0) && (sw != &kmod_dacfsw)) {
		cmn_err(CE_WARN, "dacf module %s exports no opsets, "
		    "not registered.\n", mod_name);
		return (EINVAL);
	}

	/*
	 * Look to see if the module has been previously registered with the
	 * framework.  If so, we can fail with EBUSY.
	 */
	if (mod_hash_find(dacf_module_hash, (mod_hash_key_t)mod_name,
	    (mod_hash_val_t)&module) == 0) {
		/*
		 * See if it is loaded currently
		 */
		rw_enter(&module->dm_lock, RW_WRITER);
		if (module->dm_loaded) {
			rw_exit(&module->dm_lock);
			cmn_err(CE_WARN, "dacf module '%s' is "
			    "already registered.", mod_name);
			return (EBUSY);
		}
	} else {
		/*
		 * This is the first time we've ever seen the module; stick
		 * it into the module hash.  If that fails, we've had a
		 * race between two threads, both trying to insert the same
		 * new module.  It's safe to stick the module into the
		 * hash only partly filled in, since dm_lock protects the
		 * structure, and we've got that write-locked.
		 */
		module = kmem_zalloc(sizeof (dacf_module_t), KM_SLEEP);
		str = kmem_alloc(strlen(mod_name) + 1, KM_SLEEP);
		(void) strcpy(str, mod_name);
		rw_enter(&module->dm_lock, RW_WRITER);

		if (mod_hash_insert(dacf_module_hash, (mod_hash_key_t)str,
		    (mod_hash_val_t)module) != 0) {
			rw_exit(&module->dm_lock);
			kmem_free(str, strlen(str) + 1);
			kmem_free(module, sizeof (dacf_module_t));
			cmn_err(CE_WARN, "dacf module '%s' is "
			    "already registered.", mod_name);
			return (EBUSY);
		}
	}
	/*
	 * In either case (first time we've seen it or not), the module is
	 * not loaded, and we hold it write-locked.
	 */
	ASSERT(RW_WRITE_HELD(&module->dm_lock));

	/*
	 * Alloc array of opsets for this module.  Add one for the final
	 * NULL entry
	 */
	opsarray = kmem_zalloc(sizeof (dacf_opset_t) * (nelems + 1), KM_SLEEP);

	for (i = 0; i < nelems; i++) {
		dacf_opset_copy(&(opsarray[i]), &(sw->dacf_opsets[i]));
		ASSERT(opsarray[i].opset_name != NULL);
		ASSERT(opsarray[i].opset_ops != NULL);
	}
	opsarray[nelems].opset_name = NULL;
	opsarray[nelems].opset_ops = NULL;

	ASSERT(module->dm_opsets == NULL);	/* see dacf_destroy_opsets() */
	module->dm_opsets = opsarray;

	if (dacfdebug & DACF_DBG_MSGS) {
		dprintf("%s registered.\n", mod_name);
		for (i = 0; i < nelems; i++) {
			dprintf("registered %s\n", opsarray[i].opset_name);
		}
	}

	module->dm_loaded = 1;
	rw_exit(&module->dm_lock);

	return (0);
}

/*
 * dacf_module_unregister()
 * 	remove a module from the framework, and free framework-allocated
 * 	resources.
 */
int
dacf_module_unregister(char *mod_name)
{
	dacf_module_t *module;

	/*
	 * Can't unregister __kernel, since there is no real way to get it
	 * back-- Once it gets marked with dm_loaded == 0, the kernel will
	 * try to modload() if it is ever needed, which will fail utterly,
	 * and send op_invoke into a loop in it's modload logic
	 *
	 * If this is behavior is ever needed in the future, we can just
	 * add a flag indicating that this module is really a fake.
	 */
	ASSERT(strcmp(mod_name, kmod_name) != 0);

	dprintf("dacf_module_unregister: called for '%s'!\n", mod_name);

	/*
	 * If NOAUL_DACF is set, or we try to get a write-lock on dm_lock and
	 * that fails, return EBUSY, and fail to unregister.
	 */
	if (mod_hash_find(dacf_module_hash, (mod_hash_key_t)mod_name,
	    (mod_hash_val_t)&module) == 0) {
		if ((moddebug & MODDEBUG_NOAUL_DACF) ||
		    !rw_tryenter(&module->dm_lock, RW_WRITER)) {
			return (EBUSY);
		}
	} else {
		return (EINVAL);
	}

	ASSERT(RW_WRITE_HELD(&module->dm_lock));
	dacf_destroy_opsets(module);
	module->dm_loaded = 0;
	rw_exit(&module->dm_lock);
	return (0);
}

/*
 * dacf_destroy_opsets()
 * 	given a module, destroy all of it's associated op-sets.
 */
static void
dacf_destroy_opsets(dacf_module_t *module)
{
	dacf_opset_t *array = module->dm_opsets;
	dacf_opset_t *p;
	int i;
	size_t nelems;

	ASSERT(RW_WRITE_HELD(&module->dm_lock));
	ASSERT(module->dm_loaded == 1);

	for (i = 0; array[i].opset_name != NULL; i++) {
		p = &(array[i]);
		kmem_free(p->opset_name, strlen(p->opset_name) + 1);
		/*
		 * count nelems in opset_ops
		 */
		for (nelems = 0; ; nelems++) {
			if (p->opset_ops[nelems].op_id == DACF_OPID_END) {
				break;
			}
		}
		/*
		 * Free the array of op ptrs.
		 */
		kmem_free(p->opset_ops, sizeof (dacf_op_t) * (nelems + 1));
	}

	/*
	 * i has counted how big array is; +1 to account for the last element.
	 */
	kmem_free(array, (sizeof (dacf_opset_t)) * (i + 1));
	module->dm_opsets = NULL;
}

/*
 * dacf_opset_copy()
 * 	makes a copy of a dacf_opset_t.
 */
static void
dacf_opset_copy(dacf_opset_t *dst, dacf_opset_t *src)
{
	size_t nelems, i;
	ASSERT(src && dst);

	dprintf("dacf_opset_copy: called\n");

	dst->opset_name = kmem_alloc(strlen(src->opset_name) + 1, KM_SLEEP);
	(void) strcpy(dst->opset_name, src->opset_name);

	dprintf("dacf_opset_copy: counting ops\n");

	for (nelems = 0; ; nelems++) {
		if ((src->opset_ops[nelems].op_id == DACF_OPID_END) ||
		    (src->opset_ops[nelems].op_func == NULL)) {
			break;
		}
	}

	dprintf("dacf_opset_copy: found %lu ops\n", nelems);

	dst->opset_ops = kmem_alloc(sizeof (dacf_op_t) * (nelems + 1),
	    KM_SLEEP);

	dprintf("dacf_opset_copy: copying ops\n");
	for (i = 0; i < nelems; i++) {
		dst->opset_ops[i].op_id = src->opset_ops[i].op_id;
		dst->opset_ops[i].op_func = src->opset_ops[i].op_func;
	}
	dst->opset_ops[nelems].op_id = DACF_OPID_END;
	dst->opset_ops[nelems].op_func = NULL;

	dprintf("dacf_opset_copy: done copying ops\n");
}

int dacf_modload_laps = 0;	/* just a diagnostic aid */

/*
 * dacf_op_invoke()
 *	Invoke a op in a opset in a module given the rule to invoke.
 *
 *	If the return value of dacf_op_invoke is 0, then rval contains the
 *	return value of the _op_ being invoked. Otherwise, dacf_op_invoke's
 *	return value indicates why the op invocation failed.
 */
int
dacf_op_invoke(dacf_rule_t *rule, dacf_infohdl_t info_hdl, int flags)
{
	dacf_module_t *module;
	dacf_opset_t *opsarray;
	dacf_opset_t *opset;
	dacf_op_t *op = NULL;
	dacf_opid_t op_id;
	dacf_arghdl_t arg_hdl;
	dev_info_t *dip;
	int i, rval = -1;

	ASSERT(rule);
	ASSERT(MUTEX_HELD(&dacf_lock));

	op_id = rule->r_opid;
	dprintf("dacf_op_invoke: opid=%d\n", op_id);

	/*
	 * Take laps, trying to load the dacf module.  For the case of kernel-
	 * provided operations, __kernel will be found in the hash table, and
	 * no modload will be needed.
	 */
	for (;;) {
		if (mod_hash_find(dacf_module_hash,
		    (mod_hash_key_t)rule->r_module,
		    (mod_hash_val_t *)&module) == 0) {
			rw_enter(&module->dm_lock, RW_READER);
			/*
			 * Found the module, and it is loaded.
			 */
			if (module->dm_loaded != 0) {
				break;
			}
			rw_exit(&module->dm_lock);
		}

		/*
		 * If we're here, either: 1) it's not in the hash, or 2) it is,
		 * but dm_loaded is 0, meaning the module needs to be loaded.
		 */
		dprintf("dacf_op_invoke: calling modload\n");
		if (modload("dacf", rule->r_module) < 0) {
			return (DACF_ERR_MOD_NOTFOUND);
		}
		dacf_modload_laps++;
	}

	ASSERT(RW_READ_HELD(&module->dm_lock));

	opsarray = module->dm_opsets;

	/*
	 * Loop through the opsets exported by this module, and find the one
	 * we care about.
	 */
	opset = NULL;
	for (i = 0; opsarray[i].opset_name != NULL; i++) {
		if (strcmp(opsarray[i].opset_name, rule->r_opset) == 0) {
			opset = &opsarray[i];
			break;
		}
	}

	if (opset == NULL) {
		cmn_err(CE_WARN, "!dacf: couldn't invoke op, opset '%s' not "
		    "found in module '%s'", rule->r_opset, rule->r_module);
		rw_exit(&module->dm_lock);
		return (DACF_ERR_OPSET_NOTFOUND);
	}

	arg_hdl = (dacf_arghdl_t)rule->r_args;

	/*
	 * Call the appropriate routine in the target by looping across the
	 * ops until we find the one whose id matches opid.
	 */
	op = NULL;
	for (i = 0; opset->opset_ops[i].op_id != DACF_OPID_END; i++) {
		if (opset->opset_ops[i].op_id == op_id) {
			op = &(opset->opset_ops[i]);
			break;
		}
	}

	if (op == NULL) {
		cmn_err(CE_WARN, "!dacf: couldn't invoke op, op '%s' not found "
		    "in opset '%s' in module '%s'", dacf_opid_to_str(op_id),
		    rule->r_opset, rule->r_module);
		rw_exit(&module->dm_lock);
		return (DACF_ERR_OP_NOTFOUND);
	}

	dprintf("dacf_op_invoke: found op, invoking...\n");

	/*
	 * Drop dacf_lock here, so that op_func's that cause drivers to
	 * get loaded don't wedge the system when they try to acquire dacf_lock
	 * to do matching.
	 *
	 * Mark that an invoke is happening to prevent recursive invokes
	 */
	dip = ((struct ddi_minor_data *)info_hdl)->dip;

	mutex_enter(&(DEVI(dip)->devi_lock));
	DEVI_SET_INVOKING_DACF(dip);
	mutex_exit(&(DEVI(dip)->devi_lock));

	mutex_exit(&dacf_lock);

	rval = op->op_func(info_hdl, arg_hdl, flags);

	mutex_enter(&dacf_lock);

	/*
	 * Completed the invocation against module, so let go of it.
	 */
	mutex_enter(&(DEVI(dip)->devi_lock));
	DEVI_CLR_INVOKING_DACF(dip);
	mutex_exit(&(DEVI(dip)->devi_lock));

	/*
	 * Drop our r-lock on the module, now that we no longer need the module
	 * to stay loaded.
	 */
	rw_exit(&module->dm_lock);

	if (rval == DACF_SUCCESS) {
		return (DACF_SUCCESS);
	} else {
		return (DACF_ERR_OP_FAILED);
	}
}

/*
 * dacf_get_devspec()
 * 	given a devspec-type as a string, return a corresponding dacf_devspec_t
 */
dacf_devspec_t
dacf_get_devspec(char *name)
{
	dacf_ds_t *p = &dacf_devspecs[0];

	while (p->name != NULL) {
		if (strcmp(p->name, name) == 0) {
			return (p->id);
		}
		p++;
	}
	return (DACF_DS_ERROR);
}

/*
 * dacf_devspec_to_str()
 * 	given a dacf_devspec_t, return a pointer to the human readable string
 * 	representation of that device specifier.
 */
const char *
dacf_devspec_to_str(dacf_devspec_t ds)
{
	dacf_ds_t *p = &dacf_devspecs[0];

	while (p->name != NULL) {
		if (p->id == ds) {
			return (p->name);
		}
		p++;
	}
	return (NULL);
}

/*
 * dacf_get_op()
 * 	given a op name, returns the corresponding dacf_opid_t.
 */
dacf_opid_t
dacf_get_op(char *name)
{
	dacf_opmap_t *p = &dacf_ops[0];

	while (p->name != NULL) {
		if (strcmp(p->name, name) == 0) {
			return (p->id);
		}
		p++;
	}
	return (DACF_OPID_ERROR);
}

/*
 * dacf_opid_to_str()
 * 	given a dacf_opid_t, return the human-readable op-name.
 */
const char *
dacf_opid_to_str(dacf_opid_t tid)
{
	dacf_opmap_t *p = &dacf_ops[0];

	while (p->name != NULL) {
		if (p->id == tid) {
			return (p->name);
		}
		p++;
	}
	return (NULL);
}

/*
 * dacf_getopt()
 * 	given an option specified as a string, add it to the bit-field of
 * 	options given.  Returns -1 if the option is unrecognized.
 */
int
dacf_getopt(char *opt_str, uint_t *opts)
{
	dacf_opt_t *p = &dacf_options[0];

	/*
	 * Look through the list for the option given
	 */
	while (p->optname != NULL) {
		if (strcmp(opt_str, p->optname) == 0) {
			*opts |= p->optmask;
			return (0);
		}
		p++;
	}
	return (-1);
}



/*
 * This family of functions forms the dacf interface which is exported to
 * kernel/dacf modules.  Modules _should_not_ use any dacf_* functions
 * presented above this point.
 *
 * Note: These routines use a dacf_infohdl_t to struct ddi_minor_data * and
 * assume that the resulting pointer is not to an alias node.  That is true
 * because dacf_op_invoke guarantees it by first resolving the alias.
 */

/*
 * dacf_minor_name()
 * 	given a dacf_infohdl_t, obtain the minor name of the device instance
 * 	being configured.
 */
const char *
dacf_minor_name(dacf_infohdl_t info_hdl)
{
	struct ddi_minor_data *dmdp = (struct ddi_minor_data *)info_hdl;

	return (dmdp->ddm_name);
}

/*
 * dacf_minor_number()
 * 	given a dacf_infohdl_t, obtain the device minor number of the instance
 * 	being configured.
 */
minor_t
dacf_minor_number(dacf_infohdl_t info_hdl)
{
	struct ddi_minor_data *dmdp = (struct ddi_minor_data *)info_hdl;

	return (getminor(dmdp->ddm_dev));
}

/*
 * dacf_get_dev()
 *	given a dacf_infohdl_t, obtain the dev_t of the instance being
 *	configured.
 */
dev_t
dacf_get_dev(dacf_infohdl_t info_hdl)
{
	struct ddi_minor_data *dmdp = (struct ddi_minor_data *)info_hdl;

	return (dmdp->ddm_dev);
}

/*
 * dacf_driver_name()
 * 	given a dacf_infohdl_t, obtain the device driver name of the device
 * 	instance being configured.
 */
const char *
dacf_driver_name(dacf_infohdl_t info_hdl)
{
	struct ddi_minor_data *dmdp = (struct ddi_minor_data *)info_hdl;

	return (ddi_driver_name(dmdp->dip));
}

/*
 * dacf_devinfo_node()
 * 	given a dacf_infohdl_t, obtain the dev_info_t of the device instance
 * 	being configured.
 */
dev_info_t *
dacf_devinfo_node(dacf_infohdl_t info_hdl)
{
	struct ddi_minor_data *dmdp = (struct ddi_minor_data *)info_hdl;

	return (dmdp->dip);
}

/*
 * dacf_get_arg()
 * 	given the dacf_arghdl_t passed to a op and the name of an argument,
 * 	return the value of that argument.
 *
 * 	returns NULL if the argument is not found.
 */
const char *
dacf_get_arg(dacf_arghdl_t arghdl, char *arg_name)
{
	dacf_arg_t *arg_list = (dacf_arg_t *)arghdl;
	ASSERT(arg_name);

	while (arg_list != NULL) {
		if (strcmp(arg_list->arg_name, arg_name) == 0) {
			return (arg_list->arg_val);
		}
		arg_list = arg_list->arg_next;
	}

	return (NULL);
}

/*
 * dacf_store_info()
 * 	associate instance-specific data with a device instance.  Future
 * 	configuration ops invoked for this instance can retrieve this data using
 * 	dacf_retrieve_info() below.  Modules are responsible for cleaning up
 * 	this data as appropriate, and should store NULL as the value of 'data'
 * 	when the data is no longer valid.
 */
void
dacf_store_info(dacf_infohdl_t info_hdl, void *data)
{
	struct ddi_minor_data *dmdp = (struct ddi_minor_data *)info_hdl;

	/*
	 * If the client is 'storing NULL' we can represent that by blowing
	 * the info entry out of the hash.
	 */
	if (data == NULL) {
		(void) mod_hash_destroy(dacf_info_hash, (mod_hash_key_t)dmdp);
	} else {
		/*
		 * mod_hash_replace can only fail on out of memory, but we sleep
		 * for memory in this hash, so it is safe to ignore the retval.
		 */
		(void) mod_hash_replace(dacf_info_hash, (mod_hash_key_t)dmdp,
		    (mod_hash_val_t)data);
	}
}

/*
 * dacf_retrieve_info()
 * 	retrieve instance-specific data associated with a device instance.
 */
void *
dacf_retrieve_info(dacf_infohdl_t info_hdl)
{
	struct ddi_minor_data *dmdp = (struct ddi_minor_data *)info_hdl;
	void *data;

	if (mod_hash_find(dacf_info_hash, (mod_hash_key_t)dmdp,
	    (mod_hash_val_t *)&data) != 0) {
		return (NULL);
	}

	return (data);
}

/*
 * dacf_makevp()
 * 	make a vnode for the specified dacf_infohdl_t.
 */
struct vnode *
dacf_makevp(dacf_infohdl_t info_hdl)
{
	struct ddi_minor_data *dmdp = (struct ddi_minor_data *)info_hdl;
	struct vnode	*vp;

	vp = makespecvp(dmdp->ddm_dev, VCHR);
	spec_assoc_vp_with_devi(vp, dmdp->dip);
	return (vp);
}
