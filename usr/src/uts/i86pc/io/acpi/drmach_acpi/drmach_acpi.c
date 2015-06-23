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
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/note.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/varargs.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/cpupart.h>
#include <sys/mem_config.h>
#include <sys/mem_cage.h>
#include <sys/memnode.h>
#include <sys/callb.h>
#include <sys/ontrap.h>
#include <sys/obpdefs.h>
#include <sys/promif.h>
#include <sys/synch.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/x_call.h>
#include <sys/x86_archext.h>
#include <sys/fastboot_impl.h>
#include <sys/sysevent.h>
#include <sys/sysevent/dr.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_rsc.h>
#include <sys/acpidev_dr.h>
#include <sys/dr.h>
#include <sys/dr_util.h>
#include <sys/drmach.h>
#include "drmach_acpi.h"

/* utility */
#define	MBYTE		(1048576ull)
#define	_ptob64(p)	((uint64_t)(p) << PAGESHIFT)
#define	_b64top(b)	((pgcnt_t)((b) >> PAGESHIFT))

static int 		drmach_init(void);
static void 		drmach_fini(void);
static int		drmach_name2type_idx(char *);
static sbd_error_t	*drmach_mem_update_lgrp(drmachid_t);

static void drmach_board_dispose(drmachid_t id);
static sbd_error_t *drmach_board_release(drmachid_t);
static sbd_error_t *drmach_board_status(drmachid_t, drmach_status_t *);

static void drmach_io_dispose(drmachid_t);
static sbd_error_t *drmach_io_release(drmachid_t);
static sbd_error_t *drmach_io_status(drmachid_t, drmach_status_t *);

static void drmach_cpu_dispose(drmachid_t);
static sbd_error_t *drmach_cpu_release(drmachid_t);
static sbd_error_t *drmach_cpu_status(drmachid_t, drmach_status_t *);

static void drmach_mem_dispose(drmachid_t);
static sbd_error_t *drmach_mem_release(drmachid_t);
static sbd_error_t *drmach_mem_status(drmachid_t, drmach_status_t *);

#ifdef DEBUG
int drmach_debug = 1;		 /* set to non-zero to enable debug messages */
#endif /* DEBUG */

drmach_domain_info_t	 drmach_domain;

static char		*drmach_ie_fmt = "drmach_acpi.c %d";
static drmach_array_t	*drmach_boards;

/* rwlock to protect drmach_boards. */
static krwlock_t	 drmach_boards_rwlock;

/* rwlock to block out CPR thread. */
static krwlock_t	 drmach_cpr_rwlock;

/* CPR callb id. */
static callb_id_t	 drmach_cpr_cid;

static struct {
	const char	*name;
	const char	*type;
	sbd_error_t	*(*new)(drmach_device_t *, drmachid_t *);
} drmach_name2type[] = {
	{ ACPIDEV_NODE_NAME_CPU,	DRMACH_DEVTYPE_CPU, drmach_cpu_new },
	{ ACPIDEV_NODE_NAME_MEMORY,	DRMACH_DEVTYPE_MEM, drmach_mem_new },
	{ ACPIDEV_NODE_NAME_PCI,	DRMACH_DEVTYPE_PCI, drmach_io_new  },
};

/*
 * drmach autoconfiguration data structures and interfaces
 */
static struct modlmisc modlmisc = {
	&mod_miscops,
	"ACPI based DR v1.0"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

int
_init(void)
{
	int err;

	if ((err = drmach_init()) != 0) {
		return (err);
	}

	if ((err = mod_install(&modlinkage)) != 0) {
		drmach_fini();
	}

	return (err);
}

int
_fini(void)
{
	int	err;

	if ((err = mod_remove(&modlinkage)) == 0) {
		drmach_fini();
	}

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Internal support functions.
 */
static DRMACH_HANDLE
drmach_node_acpi_get_dnode(drmach_node_t *np)
{
	return ((DRMACH_HANDLE)(uintptr_t)np->here);
}

static dev_info_t *
drmach_node_acpi_get_dip(drmach_node_t *np)
{
	dev_info_t *dip = NULL;

	if (ACPI_FAILURE(acpica_get_devinfo((DRMACH_HANDLE)(np->here), &dip))) {
		return (NULL);
	}

	return (dip);
}

static int
drmach_node_acpi_get_prop(drmach_node_t *np, char *name, void *buf, int len)
{
	int		rv = 0;
	DRMACH_HANDLE	hdl;

	hdl = np->get_dnode(np);
	if (hdl == NULL) {
		DRMACH_PR("!drmach_node_acpi_get_prop: NULL handle");
		rv = -1;
	} else {
		rv = acpidev_dr_device_getprop(hdl, name, buf, len);
		if (rv >= 0) {
			ASSERT(rv <= len);
			rv = 0;
		}
	}

	return (rv);
}

static int
drmach_node_acpi_get_proplen(drmach_node_t *np, char *name, int *len)
{
	int		rv = 0;
	DRMACH_HANDLE	hdl;

	hdl = np->get_dnode(np);
	if (hdl == NULL) {
		DRMACH_PR("!drmach_node_acpi_get_proplen: NULL handle");
		rv = -1;
	} else {
		rv = acpidev_dr_device_getprop(hdl, name, NULL, 0);
		if (rv >= 0) {
			*len = rv;
			return (0);
		}
	}

	return (-1);
}

static ACPI_STATUS
drmach_node_acpi_callback(ACPI_HANDLE hdl, uint_t lvl, void *ctx, void **retval)
{
	_NOTE(ARGUNUSED(lvl));

	int rv;
	dev_info_t *dip;
	drmach_node_walk_args_t *argp = ctx;
	int (*cb)(drmach_node_walk_args_t *args);
	acpidev_class_id_t clsid;

	ASSERT(hdl != NULL);
	ASSERT(ctx != NULL);
	ASSERT(retval != NULL);

	/* Skip subtree if the device is not powered. */
	if (!acpidev_dr_device_is_powered(hdl)) {
		return (AE_CTRL_DEPTH);
	}

	/*
	 * Keep scanning subtree if it fails to lookup device node.
	 * There may be some ACPI objects without device nodes created.
	 */
	if (ACPI_FAILURE(acpica_get_devinfo(hdl, &dip))) {
		return (AE_OK);
	}

	argp->node->here = hdl;
	cb = (int (*)(drmach_node_walk_args_t *args))argp->func;
	rv = (*cb)(argp);
	argp->node->here = NULL;
	if (rv) {
		*(int *)retval = rv;
		return (AE_CTRL_TERMINATE);
	}

	/*
	 * Skip descendants of PCI/PCIex host bridges.
	 * PCI/PCIex devices will be handled by pcihp.
	 */
	clsid = acpidev_dr_device_get_class(hdl);
	if (clsid == ACPIDEV_CLASS_ID_PCI || clsid == ACPIDEV_CLASS_ID_PCIEX) {
		return (AE_CTRL_DEPTH);
	}

	return (AE_OK);
}

static int
drmach_node_acpi_walk(drmach_node_t *np, void *data,
    int (*cb)(drmach_node_walk_args_t *args))
{
	DRMACH_HANDLE		hdl;
	int			rv = 0;
	drmach_node_walk_args_t	args;

	/* initialize the args structure for callback */
	args.node = np;
	args.data = data;
	args.func = (void *)cb;

	/* save the handle, it will be modified when walking the tree. */
	hdl = np->get_dnode(np);
	if (hdl == NULL) {
		DRMACH_PR("!drmach_node_acpi_walk: failed to get device node.");
		return (EX86_INAPPROP);
	}

	if (ACPI_FAILURE(acpidev_dr_device_walk_device(hdl,
	    ACPIDEV_MAX_ENUM_LEVELS, drmach_node_acpi_callback,
	    &args, (void *)&rv))) {
		/*
		 * If acpidev_dr_device_walk_device() itself fails, rv won't
		 * be set to suitable error code. Set it here.
		 */
		if (rv == 0) {
			cmn_err(CE_WARN, "!drmach_node_acpi_walk: failed to "
			    "walk ACPI namespace.");
			rv = EX86_ACPIWALK;
		}
	}

	/* restore the handle to original value after walking the tree. */
	np->here = (void *)hdl;

	return ((int)rv);
}

static drmach_node_t *
drmach_node_new(void)
{
	drmach_node_t *np;

	np = kmem_zalloc(sizeof (drmach_node_t), KM_SLEEP);

	np->get_dnode = drmach_node_acpi_get_dnode;
	np->getdip = drmach_node_acpi_get_dip;
	np->getproplen = drmach_node_acpi_get_proplen;
	np->getprop = drmach_node_acpi_get_prop;
	np->walk = drmach_node_acpi_walk;

	return (np);
}

static drmachid_t
drmach_node_dup(drmach_node_t *np)
{
	drmach_node_t *dup;

	dup = drmach_node_new();
	dup->here = np->here;
	dup->get_dnode = np->get_dnode;
	dup->getdip = np->getdip;
	dup->getproplen = np->getproplen;
	dup->getprop = np->getprop;
	dup->walk = np->walk;

	return (dup);
}

static void
drmach_node_dispose(drmach_node_t *np)
{
	kmem_free(np, sizeof (*np));
}

static int
drmach_node_walk(drmach_node_t *np, void *param,
	int (*cb)(drmach_node_walk_args_t *args))
{
	return (np->walk(np, param, cb));
}

static DRMACH_HANDLE
drmach_node_get_dnode(drmach_node_t *np)
{
	return (np->get_dnode(np));
}

/*
 * drmach_array provides convenient array construction, access,
 * bounds checking and array destruction logic.
 */
static drmach_array_t *
drmach_array_new(uint_t min_index, uint_t max_index)
{
	drmach_array_t *arr;

	arr = kmem_zalloc(sizeof (drmach_array_t), KM_SLEEP);

	arr->arr_sz = (max_index - min_index + 1) * sizeof (void *);
	if (arr->arr_sz > 0) {
		arr->min_index = min_index;
		arr->max_index = max_index;

		arr->arr = kmem_zalloc(arr->arr_sz, KM_SLEEP);
		return (arr);
	} else {
		kmem_free(arr, sizeof (*arr));
		return (0);
	}
}

static int
drmach_array_set(drmach_array_t *arr, uint_t idx, drmachid_t val)
{
	if (idx < arr->min_index || idx > arr->max_index)
		return (-1);
	arr->arr[idx - arr->min_index] = val;
	return (0);
}

/*
 * Get the item with index idx.
 * Return 0 with the value stored in val if succeeds, otherwise return -1.
 */
static int
drmach_array_get(drmach_array_t *arr, uint_t idx, drmachid_t *val)
{
	if (idx < arr->min_index || idx > arr->max_index)
		return (-1);
	*val = arr->arr[idx - arr->min_index];
	return (0);
}

static int
drmach_array_first(drmach_array_t *arr, uint_t *idx, drmachid_t *val)
{
	int rv;

	*idx = arr->min_index;
	while ((rv = drmach_array_get(arr, *idx, val)) == 0 && *val == NULL)
		*idx += 1;

	return (rv);
}

static int
drmach_array_next(drmach_array_t *arr, uint_t *idx, drmachid_t *val)
{
	int rv;

	*idx += 1;
	while ((rv = drmach_array_get(arr, *idx, val)) == 0 && *val == NULL)
		*idx += 1;

	return (rv);
}

static void
drmach_array_dispose(drmach_array_t *arr, void (*disposer)(drmachid_t))
{
	drmachid_t	val;
	uint_t		idx;
	int		rv;

	rv = drmach_array_first(arr, &idx, &val);
	while (rv == 0) {
		(*disposer)(val);
		rv = drmach_array_next(arr, &idx, &val);
	}

	kmem_free(arr->arr, arr->arr_sz);
	kmem_free(arr, sizeof (*arr));
}

static drmach_board_t *
drmach_get_board_by_bnum(uint_t bnum)
{
	drmachid_t id;

	if (drmach_array_get(drmach_boards, bnum, &id) == 0)
		return ((drmach_board_t *)id);
	else
		return (NULL);
}

sbd_error_t *
drmach_device_new(drmach_node_t *node,
	drmach_board_t *bp, int portid, drmachid_t *idp)
{
	int		 i;
	int		 rv;
	drmach_device_t	 proto;
	sbd_error_t	*err;
	char		 name[OBP_MAXDRVNAME];

	rv = node->getprop(node, ACPIDEV_DR_PROP_DEVNAME, name, OBP_MAXDRVNAME);
	if (rv) {
		/* every node is expected to have a name */
		err = drerr_new(1, EX86_GETPROP, "device node %s: property %s",
		    ddi_node_name(node->getdip(node)),
		    ACPIDEV_DR_PROP_DEVNAME);
		return (err);
	}

	/*
	 * The node currently being examined is not listed in the name2type[]
	 * array.  In this case, the node is no interest to drmach.  Both
	 * dp and err are initialized here to yield nothing (no device or
	 * error structure) for this case.
	 */
	i = drmach_name2type_idx(name);
	if (i < 0) {
		*idp = (drmachid_t)0;
		return (NULL);
	}

	/* device specific new function will set unum */
	bzero(&proto, sizeof (proto));
	proto.type = drmach_name2type[i].type;
	proto.bp = bp;
	proto.node = node;
	proto.portid = portid;

	return (drmach_name2type[i].new(&proto, idp));
}

static void
drmach_device_dispose(drmachid_t id)
{
	drmach_device_t *self = id;

	self->cm.dispose(id);
}

static sbd_error_t *
drmach_device_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_common_t *cp;

	if (!DRMACH_IS_ID(id))
		return (drerr_new(0, EX86_NOTID, NULL));
	cp = id;

	return (cp->status(id, stat));
}

drmach_board_t *
drmach_board_new(uint_t bnum, int boot_board)
{
	sbd_error_t *err;
	drmach_board_t	*bp;
	dev_info_t *dip = NULL;

	bp = kmem_zalloc(sizeof (drmach_board_t), KM_SLEEP);
	bp->cm.isa = (void *)drmach_board_new;
	bp->cm.release = drmach_board_release;
	bp->cm.status = drmach_board_status;

	bp->bnum = bnum;
	bp->devices = NULL;
	bp->tree = drmach_node_new();

	acpidev_dr_lock_all();
	if (ACPI_FAILURE(acpidev_dr_get_board_handle(bnum, &bp->tree->here))) {
		acpidev_dr_unlock_all();
		drmach_board_dispose(bp);
		return (NULL);
	}
	acpidev_dr_unlock_all();
	ASSERT(bp->tree->here != NULL);

	err = drmach_board_name(bnum, bp->cm.name, sizeof (bp->cm.name));
	if (err != NULL) {
		sbd_err_clear(&err);
		drmach_board_dispose(bp);
		return (NULL);
	}

	if (acpidev_dr_device_is_powered(bp->tree->here)) {
		bp->boot_board = boot_board;
		bp->powered = 1;
	} else {
		bp->boot_board = 0;
		bp->powered = 0;
	}
	bp->assigned = boot_board;
	if (ACPI_SUCCESS(acpica_get_devinfo(bp->tree->here, &dip))) {
		bp->connected = 1;
	} else {
		bp->connected = 0;
	}

	(void) drmach_array_set(drmach_boards, bnum, bp);

	return (bp);
}

static void
drmach_board_dispose(drmachid_t id)
{
	drmach_board_t *bp;

	ASSERT(DRMACH_IS_BOARD_ID(id));
	bp = id;

	if (bp->tree)
		drmach_node_dispose(bp->tree);

	if (bp->devices)
		drmach_array_dispose(bp->devices, drmach_device_dispose);

	kmem_free(bp, sizeof (drmach_board_t));
}

static sbd_error_t *
drmach_board_release(drmachid_t id)
{
	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));

	return (NULL);
}

static int
drmach_board_check_power(drmach_board_t *bp)
{
	DRMACH_HANDLE	hdl;

	hdl = drmach_node_get_dnode(bp->tree);

	return (acpidev_dr_device_is_powered(hdl));
}

struct drmach_board_list_dep_arg {
	int	count;
	size_t	len;
	ssize_t	off;
	char	*buf;
	char	temp[MAXPATHLEN];
};

static ACPI_STATUS
drmach_board_generate_name(ACPI_HANDLE hdl, UINT32 lvl, void *ctx,
    void **retval)
{
	_NOTE(ARGUNUSED(retval));

	struct drmach_board_list_dep_arg *argp = ctx;

	ASSERT(hdl != NULL);
	ASSERT(lvl == UINT32_MAX);
	ASSERT(ctx != NULL);

	/* Skip non-board devices. */
	if (!acpidev_dr_device_is_board(hdl)) {
		return (AE_OK);
	}

	if (ACPI_FAILURE(acpidev_dr_get_board_name(hdl, argp->temp,
	    sizeof (argp->temp)))) {
		DRMACH_PR("!drmach_board_generate_name: failed to "
		    "generate board name for handle %p.", hdl);
		/* Keep on walking. */
		return (AE_OK);
	}
	argp->count++;
	argp->off += snprintf(argp->buf + argp->off, argp->len - argp->off,
	    " %s", argp->temp);
	if (argp->off >= argp->len) {
		return (AE_CTRL_TERMINATE);
	}

	return (AE_OK);
}

static ssize_t
drmach_board_list_dependency(ACPI_HANDLE hdl, boolean_t edl, char *prefix,
    char *buf, size_t len)
{
	ACPI_STATUS rc;
	ssize_t off;
	struct drmach_board_list_dep_arg *ap;

	ASSERT(buf != NULL && len != 0);
	if (buf == NULL || len == 0) {
		return (-1);
	}

	ap = kmem_zalloc(sizeof (*ap), KM_SLEEP);
	ap->buf = buf;
	ap->len = len;
	ap->off = snprintf(buf, len, "%s", prefix);
	if (ap->off >= len) {
		*buf = '\0';
		kmem_free(ap, sizeof (*ap));
		return (-1);
	}

	/* Generate the device dependency list. */
	if (edl) {
		rc = acpidev_dr_device_walk_edl(hdl,
		    drmach_board_generate_name, ap, NULL);
	} else {
		rc = acpidev_dr_device_walk_ejd(hdl,
		    drmach_board_generate_name, ap, NULL);
	}
	if (ACPI_FAILURE(rc)) {
		*buf = '\0';
		ap->off = -1;
	/* No device has dependency on this board. */
	} else if (ap->count == 0) {
		*buf = '\0';
		ap->off = 0;
	}

	off = ap->off;
	kmem_free(ap, sizeof (*ap));

	return (off);
}

static sbd_error_t *
drmach_board_status(drmachid_t id, drmach_status_t *stat)
{
	sbd_error_t	*err = NULL;
	drmach_board_t	*bp;
	DRMACH_HANDLE	hdl;
	size_t		off;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	bp = id;

	if (bp->tree == NULL)
		return (drerr_new(0, EX86_INAPPROP, NULL));
	hdl = drmach_node_get_dnode(bp->tree);
	if (hdl == NULL)
		return (drerr_new(0, EX86_INAPPROP, NULL));

	stat->busy = 0;			/* assume not busy */
	stat->configured = 0;		/* assume not configured */
	stat->assigned = bp->assigned;
	stat->powered = bp->powered = acpidev_dr_device_is_powered(hdl);
	stat->empty = !acpidev_dr_device_is_present(hdl);
	if (ACPI_SUCCESS(acpidev_dr_device_check_status(hdl))) {
		stat->cond = bp->cond = SBD_COND_OK;
	} else {
		stat->cond = bp->cond = SBD_COND_FAILED;
	}
	stat->info[0] = '\0';

	/* Generate the eject device list. */
	if (drmach_board_list_dependency(hdl, B_TRUE, "EDL:",
	    stat->info, sizeof (stat->info)) < 0) {
		DRMACH_PR("!drmach_board_status: failed to generate "
		    "eject device list for board %d.", bp->bnum);
		stat->info[0] = '\0';
	}
	off = strlen(stat->info);
	if (off < sizeof (stat->info)) {
		if (drmach_board_list_dependency(hdl, B_FALSE,
		    off ? ", EJD:" : "EJD:",
		    stat->info + off, sizeof (stat->info) - off) < 0) {
			DRMACH_PR("!drmach_board_status: failed to generate "
			    "eject dependent device for board %d.", bp->bnum);
			stat->info[off] = '\0';
		}
	}

	switch (acpidev_dr_get_board_type(bp->tree->get_dnode(bp->tree))) {
	case ACPIDEV_CPU_BOARD:
		(void) strlcpy(stat->type, "CPU Board", sizeof (stat->type));
		break;
	case ACPIDEV_MEMORY_BOARD:
		(void) strlcpy(stat->type, "MemoryBoard", sizeof (stat->type));
		break;
	case ACPIDEV_IO_BOARD:
		(void) strlcpy(stat->type, "IO Board", sizeof (stat->type));
		break;
	case ACPIDEV_SYSTEM_BOARD:
		/*FALLTHROUGH*/
	default:
		(void) strlcpy(stat->type, "SystemBoard", sizeof (stat->type));
		break;
	}

	if (bp->devices) {
		int		 rv;
		uint_t		 d_idx;
		drmachid_t	 d_id;

		rv = drmach_array_first(bp->devices, &d_idx, &d_id);
		while (rv == 0) {
			drmach_status_t	d_stat;

			err = drmach_device_status(d_id, &d_stat);
			if (err)
				break;

			stat->busy |= d_stat.busy;
			stat->configured |= d_stat.configured;

			rv = drmach_array_next(bp->devices, &d_idx, &d_id);
		}
	}

	return (err);
}

/*
 * When DR is initialized, we walk the device tree and acquire a hold on
 * all the nodes that are interesting to DR. This is so that the corresponding
 * branches cannot be deleted.
 */
static int
drmach_hold_rele_devtree(dev_info_t *rdip, void *arg)
{
	int *holdp = (int *)arg;
	ACPI_HANDLE hdl = NULL;
	acpidev_data_handle_t dhdl;

	/* Skip nodes and subtrees which are not created by acpidev. */
	if (ACPI_FAILURE(acpica_get_handle(rdip, &hdl))) {
		return (DDI_WALK_PRUNECHILD);
	}
	ASSERT(hdl != NULL);
	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		return (DDI_WALK_PRUNECHILD);
	}

	/* Hold/release devices which are interesting to DR operations. */
	if (acpidev_data_dr_ready(dhdl)) {
		if (*holdp) {
			ASSERT(!e_ddi_branch_held(rdip));
			e_ddi_branch_hold(rdip);
		} else {
			ASSERT(e_ddi_branch_held(rdip));
			e_ddi_branch_rele(rdip);
		}
	}

	return (DDI_WALK_CONTINUE);
}

static void
drmach_hold_devtree(void)
{
	dev_info_t *dip;
	int circ;
	int hold = 1;

	dip = ddi_root_node();
	ndi_devi_enter(dip, &circ);
	ddi_walk_devs(ddi_get_child(dip), drmach_hold_rele_devtree, &hold);
	ndi_devi_exit(dip, circ);
}

static void
drmach_release_devtree(void)
{
	dev_info_t *dip;
	int circ;
	int hold = 0;

	dip = ddi_root_node();
	ndi_devi_enter(dip, &circ);
	ddi_walk_devs(ddi_get_child(dip), drmach_hold_rele_devtree, &hold);
	ndi_devi_exit(dip, circ);
}

static boolean_t
drmach_cpr_callb(void *arg, int code)
{
	_NOTE(ARGUNUSED(arg));

	if (code == CB_CODE_CPR_CHKPT) {
		/*
		 * Temporarily block CPR operations if there are DR operations
		 * ongoing.
		 */
		rw_enter(&drmach_cpr_rwlock, RW_WRITER);
	} else {
		rw_exit(&drmach_cpr_rwlock);
	}

	return (B_TRUE);
}

static int
drmach_init(void)
{
	DRMACH_HANDLE	hdl;
	drmachid_t	id;
	uint_t		bnum;

	if (MAX_BOARDS > SHRT_MAX) {
		cmn_err(CE_WARN, "!drmach_init: system has too many (%d) "
		    "hotplug capable boards.", MAX_BOARDS);
		return (ENXIO);
	} else if (MAX_CMP_UNITS_PER_BOARD > 1) {
		cmn_err(CE_WARN, "!drmach_init: DR doesn't support multiple "
		    "(%d) physical processors on one board.",
		    MAX_CMP_UNITS_PER_BOARD);
		return (ENXIO);
	} else if (!ISP2(MAX_CORES_PER_CMP)) {
		cmn_err(CE_WARN, "!drmach_init: number of logical CPUs (%d) in "
		    "physical processor is not power of 2.",
		    MAX_CORES_PER_CMP);
		return (ENXIO);
	} else if (MAX_CPU_UNITS_PER_BOARD > DEVSET_CPU_NUMBER ||
	    MAX_MEM_UNITS_PER_BOARD > DEVSET_MEM_NUMBER ||
	    MAX_IO_UNITS_PER_BOARD > DEVSET_IO_NUMBER) {
		cmn_err(CE_WARN, "!drmach_init: system has more CPU/memory/IO "
		    "units than the DR driver can handle.");
		return (ENXIO);
	}

	rw_init(&drmach_cpr_rwlock, NULL, RW_DEFAULT, NULL);
	drmach_cpr_cid = callb_add(drmach_cpr_callb, NULL,
	    CB_CL_CPR_PM, "drmach");

	rw_init(&drmach_boards_rwlock, NULL, RW_DEFAULT, NULL);
	drmach_boards = drmach_array_new(0, MAX_BOARDS - 1);
	drmach_domain.allow_dr = acpidev_dr_capable();

	for (bnum = 0; bnum < MAX_BOARDS; bnum++) {
		hdl = NULL;
		if (ACPI_FAILURE(acpidev_dr_get_board_handle(bnum, &hdl)) ||
		    hdl == NULL) {
			cmn_err(CE_WARN, "!drmach_init: failed to lookup ACPI "
			    "handle for board %d.", bnum);
			continue;
		}
		if (drmach_array_get(drmach_boards, bnum, &id) == -1) {
			DRMACH_PR("!drmach_init: failed to get handle "
			    "for board %d.", bnum);
			ASSERT(0);
			goto error;
		} else if (id == NULL) {
			(void) drmach_board_new(bnum, 1);
		}
	}

	/*
	 * Walk descendants of the devinfo root node and hold
	 * all devinfo branches of interest.
	 */
	drmach_hold_devtree();

	return (0);

error:
	drmach_array_dispose(drmach_boards, drmach_board_dispose);
	rw_destroy(&drmach_boards_rwlock);
	rw_destroy(&drmach_cpr_rwlock);
	return (ENXIO);
}

static void
drmach_fini(void)
{
	rw_enter(&drmach_boards_rwlock, RW_WRITER);
	if (drmach_boards != NULL) {
		drmach_array_dispose(drmach_boards, drmach_board_dispose);
		drmach_boards = NULL;
	}
	rw_exit(&drmach_boards_rwlock);

	/*
	 * Walk descendants of the root devinfo node
	 * release holds acquired on branches in drmach_init()
	 */
	drmach_release_devtree();

	(void) callb_delete(drmach_cpr_cid);
	rw_destroy(&drmach_cpr_rwlock);
	rw_destroy(&drmach_boards_rwlock);
}

sbd_error_t *
drmach_io_new(drmach_device_t *proto, drmachid_t *idp)
{
	drmach_io_t	*ip;
	int		portid;

	portid = proto->portid;
	ASSERT(portid != -1);
	proto->unum = portid;

	ip = kmem_zalloc(sizeof (drmach_io_t), KM_SLEEP);
	bcopy(proto, &ip->dev, sizeof (ip->dev));
	ip->dev.node = drmach_node_dup(proto->node);
	ip->dev.cm.isa = (void *)drmach_io_new;
	ip->dev.cm.dispose = drmach_io_dispose;
	ip->dev.cm.release = drmach_io_release;
	ip->dev.cm.status = drmach_io_status;
	(void) snprintf(ip->dev.cm.name, sizeof (ip->dev.cm.name), "%s%d",
	    ip->dev.type, ip->dev.unum);

	*idp = (drmachid_t)ip;

	return (NULL);
}

static void
drmach_io_dispose(drmachid_t id)
{
	drmach_io_t *self;

	ASSERT(DRMACH_IS_IO_ID(id));

	self = id;
	if (self->dev.node)
		drmach_node_dispose(self->dev.node);

	kmem_free(self, sizeof (*self));
}

static sbd_error_t *
drmach_io_release(drmachid_t id)
{
	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));

	return (NULL);
}

static sbd_error_t *
drmach_io_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_device_t *dp;
	sbd_error_t	*err;
	int		 configured;

	ASSERT(DRMACH_IS_IO_ID(id));
	dp = id;

	err = drmach_io_is_attached(id, &configured);
	if (err)
		return (err);

	stat->assigned = dp->bp->assigned;
	stat->powered = dp->bp->powered;
	stat->configured = (configured != 0);
	stat->busy = dp->busy;
	(void) strlcpy(stat->type, dp->type, sizeof (stat->type));
	stat->info[0] = '\0';

	return (NULL);
}

sbd_error_t *
drmach_cpu_new(drmach_device_t *proto, drmachid_t *idp)
{
	int		 portid;
	processorid_t	 cpuid;
	drmach_cpu_t	*cp = NULL;

	/* the portid is APIC ID of the node */
	portid = proto->portid;
	ASSERT(portid != -1);

	/*
	 * Assume all CPUs are homogeneous and have the same number of
	 * cores/threads.
	 */
	proto->unum = portid % MAX_CPU_UNITS_PER_BOARD;

	cp = kmem_zalloc(sizeof (drmach_cpu_t), KM_SLEEP);
	bcopy(proto, &cp->dev, sizeof (cp->dev));
	cp->dev.node = drmach_node_dup(proto->node);
	cp->dev.cm.isa = (void *)drmach_cpu_new;
	cp->dev.cm.dispose = drmach_cpu_dispose;
	cp->dev.cm.release = drmach_cpu_release;
	cp->dev.cm.status = drmach_cpu_status;
	(void) snprintf(cp->dev.cm.name, sizeof (cp->dev.cm.name), "%s%d",
	    cp->dev.type, cp->dev.unum);

	cp->apicid = portid;
	if (ACPI_SUCCESS(acpica_get_cpu_id_by_object(
	    drmach_node_get_dnode(proto->node), &cpuid))) {
		cp->cpuid = cpuid;
	} else {
		cp->cpuid = -1;
	}

	/* Mark CPU0 as busy, many other components have dependency on it. */
	if (cp->cpuid == 0) {
		cp->dev.busy = 1;
	}

	*idp = (drmachid_t)cp;

	return (NULL);
}

static void
drmach_cpu_dispose(drmachid_t id)
{
	drmach_cpu_t	*self;

	ASSERT(DRMACH_IS_CPU_ID(id));

	self = id;
	if (self->dev.node)
		drmach_node_dispose(self->dev.node);

	kmem_free(self, sizeof (*self));
}

static sbd_error_t *
drmach_cpu_release(drmachid_t id)
{
	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));

	return (NULL);
}

static sbd_error_t *
drmach_cpu_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_cpu_t *cp;
	drmach_device_t *dp;

	ASSERT(DRMACH_IS_CPU_ID(id));
	cp = (drmach_cpu_t *)id;
	dp = &cp->dev;

	stat->assigned = dp->bp->assigned;
	stat->powered = dp->bp->powered;
	mutex_enter(&cpu_lock);
	stat->configured = (cpu_get(cp->cpuid) != NULL);
	mutex_exit(&cpu_lock);
	stat->busy = dp->busy;
	(void) strlcpy(stat->type, dp->type, sizeof (stat->type));
	stat->info[0] = '\0';

	return (NULL);
}

static int
drmach_setup_mc_info(DRMACH_HANDLE hdl, drmach_mem_t *mp)
{
	uint_t i, j, count;
	struct memlist	*ml = NULL, *ml2 = NULL;
	acpidev_regspec_t *regp;
	uint64_t align, addr_min, addr_max, total_size, skipped_size;

	if (hdl == NULL) {
		return (-1);
	} else if (ACPI_FAILURE(acpidev_dr_get_mem_alignment(hdl, &align))) {
		return (-1);
	} else {
		ASSERT((align & (align - 1)) == 0);
		mp->mem_alignment = align;
	}

	addr_min = UINT64_MAX;
	addr_max = 0;
	total_size = 0;
	skipped_size = 0;
	/*
	 * There's a memory hole just below 4G on x86, which needs special
	 * handling. All other addresses assigned to a specific memory device
	 * should be contiguous.
	 */
	if (ACPI_FAILURE(acpidev_dr_device_get_regspec(hdl, TRUE, &regp,
	    &count))) {
		return (-1);
	}
	for (i = 0, j = 0; i < count; i++) {
		uint64_t	addr, size;

		addr  = (uint64_t)regp[i].phys_mid << 32;
		addr |= (uint64_t)regp[i].phys_low;
		size  = (uint64_t)regp[i].size_hi << 32;
		size |= (uint64_t)regp[i].size_low;
		if (size == 0)
			continue;
		else
			j++;

		total_size += size;
		if (addr < addr_min)
			addr_min = addr;
		if (addr + size > addr_max)
			addr_max = addr + size;
		if (mp->dev.bp->boot_board ||
		    j <= acpidev_dr_max_segments_per_mem_device()) {
			ml = memlist_add_span(ml, addr, size);
		} else {
			skipped_size += size;
		}
	}
	acpidev_dr_device_free_regspec(regp, count);

	if (skipped_size != 0) {
		cmn_err(CE_WARN, "!drmach: too many (%d) segments on memory "
		    "device, max (%d) segments supported, 0x%" PRIx64 " bytes "
		    "of memory skipped.",
		    j, acpidev_dr_max_segments_per_mem_device(), skipped_size);
	}

	mp->slice_base = addr_min;
	mp->slice_top = addr_max;
	mp->slice_size = total_size;

	if (mp->dev.bp->boot_board) {
		uint64_t endpa = _ptob64(physmax + 1);

		/*
		 * we intersect phys_install to get base_pa.
		 * This only works at boot-up time.
		 */
		memlist_read_lock();
		ml2 = memlist_dup(phys_install);
		memlist_read_unlock();

		ml2 = memlist_del_span(ml2, 0ull, mp->slice_base);
		if (ml2 && endpa > addr_max) {
			ml2 = memlist_del_span(ml2, addr_max, endpa - addr_max);
		}
	}

	/*
	 * Create a memlist for the memory board.
	 * The created memlist only contains configured memory if there's
	 * configured memory on the board, otherwise it contains all memory
	 * on the board.
	 */
	if (ml2) {
		uint64_t nbytes = 0;
		struct memlist *p;

		for (p = ml2; p; p = p->ml_next) {
			nbytes += p->ml_size;
		}
		if (nbytes == 0) {
			memlist_delete(ml2);
			ml2 = NULL;
		} else {
			/* Node has configured memory at boot time. */
			mp->base_pa = ml2->ml_address;
			mp->nbytes = nbytes;
			mp->memlist = ml2;
			if (ml)
				memlist_delete(ml);
		}
	}
	if (ml2 == NULL) {
		/* Not configured at boot time. */
		mp->base_pa = UINT64_MAX;
		mp->nbytes = 0;
		mp->memlist = ml;
	}

	return (0);
}

sbd_error_t *
drmach_mem_new(drmach_device_t *proto, drmachid_t *idp)
{
	DRMACH_HANDLE	hdl;
	drmach_mem_t	*mp;
	int		portid;

	mp = kmem_zalloc(sizeof (drmach_mem_t), KM_SLEEP);
	portid = proto->portid;
	ASSERT(portid != -1);
	proto->unum = portid;

	bcopy(proto, &mp->dev, sizeof (mp->dev));
	mp->dev.node = drmach_node_dup(proto->node);
	mp->dev.cm.isa = (void *)drmach_mem_new;
	mp->dev.cm.dispose = drmach_mem_dispose;
	mp->dev.cm.release = drmach_mem_release;
	mp->dev.cm.status = drmach_mem_status;

	(void) snprintf(mp->dev.cm.name, sizeof (mp->dev.cm.name), "%s%d",
	    mp->dev.type, proto->unum);
	hdl = mp->dev.node->get_dnode(mp->dev.node);
	ASSERT(hdl != NULL);
	if (drmach_setup_mc_info(hdl, mp) != 0) {
		kmem_free(mp, sizeof (drmach_mem_t));
		*idp = (drmachid_t)NULL;
		return (drerr_new(1, EX86_MC_SETUP, NULL));
	}

	/* make sure we do not create memoryless nodes */
	if (mp->nbytes == 0 && mp->slice_size == 0) {
		kmem_free(mp, sizeof (drmach_mem_t));
		*idp = (drmachid_t)NULL;
	} else
		*idp = (drmachid_t)mp;

	return (NULL);
}

static void
drmach_mem_dispose(drmachid_t id)
{
	drmach_mem_t *mp;

	ASSERT(DRMACH_IS_MEM_ID(id));

	mp = id;

	if (mp->dev.node)
		drmach_node_dispose(mp->dev.node);

	if (mp->memlist) {
		memlist_delete(mp->memlist);
		mp->memlist = NULL;
	}

	kmem_free(mp, sizeof (*mp));
}

static sbd_error_t *
drmach_mem_release(drmachid_t id)
{
	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));

	return (NULL);
}

static sbd_error_t *
drmach_mem_status(drmachid_t id, drmach_status_t *stat)
{
	uint64_t	 pa;
	drmach_mem_t	*dp;
	struct memlist	*ml = NULL;

	ASSERT(DRMACH_IS_MEM_ID(id));
	dp = id;

	/* get starting physical address of target memory */
	pa = dp->base_pa;
	/* round down to slice boundary */
	pa &= ~(dp->mem_alignment - 1);

	/* stop at first span that is in slice */
	memlist_read_lock();
	for (ml = phys_install; ml; ml = ml->ml_next)
		if (ml->ml_address >= pa && ml->ml_address < dp->slice_top)
			break;
	memlist_read_unlock();

	stat->assigned = dp->dev.bp->assigned;
	stat->powered = dp->dev.bp->powered;
	stat->configured = (ml != NULL);
	stat->busy = dp->dev.busy;
	(void) strlcpy(stat->type, dp->dev.type, sizeof (stat->type));
	stat->info[0] = '\0';

	return (NULL);
}

/*
 * Public interfaces exported to support platform independent dr driver.
 */
uint_t
drmach_max_boards(void)
{
	return (acpidev_dr_max_boards());
}

uint_t
drmach_max_io_units_per_board(void)
{
	return (acpidev_dr_max_io_units_per_board());
}

uint_t
drmach_max_cmp_units_per_board(void)
{
	return (acpidev_dr_max_cmp_units_per_board());
}

uint_t
drmach_max_mem_units_per_board(void)
{
	return (acpidev_dr_max_mem_units_per_board());
}

uint_t
drmach_max_core_per_cmp(void)
{
	return (acpidev_dr_max_cpu_units_per_cmp());
}

sbd_error_t *
drmach_pre_op(int cmd, drmachid_t id, drmach_opts_t *opts, void *argp)
{
	drmach_board_t	*bp = (drmach_board_t *)id;
	sbd_error_t	*err = NULL;

	/* allow status and ncm operations to always succeed */
	if ((cmd == SBD_CMD_STATUS) || (cmd == SBD_CMD_GETNCM)) {
		return (NULL);
	}

	switch (cmd) {
	case SBD_CMD_POWERON:
	case SBD_CMD_POWEROFF:
		/*
		 * Disable fast reboot if CPU/MEM/IOH hotplug event happens.
		 * Note: this is a temporary solution and will be revised when
		 * fast reboot can support CPU/MEM/IOH DR operations in future.
		 *
		 * ACPI BIOS generates some static ACPI tables, such as MADT,
		 * SRAT and SLIT, to describe system hardware configuration on
		 * power-on. When CPU/MEM/IOH hotplug event happens, those
		 * static tables won't be updated and will become stale.
		 *
		 * If we reset system by fast reboot, BIOS will have no chance
		 * to regenerate those staled static tables. Fast reboot can't
		 * tolerate such inconsistency between staled ACPI tables and
		 * real hardware configuration yet.
		 *
		 * A temporary solution is introduced to disable fast reboot if
		 * CPU/MEM/IOH hotplug event happens. This solution should be
		 * revised when fast reboot is enhanced to support CPU/MEM/IOH
		 * DR operations.
		 */
		fastreboot_disable(FBNS_HOTPLUG);
		/*FALLTHROUGH*/

	default:
		/* Block out the CPR thread. */
		rw_enter(&drmach_cpr_rwlock, RW_READER);
		break;
	}

	/* check all other commands for the required option string */
	if ((opts->size > 0) && (opts->copts != NULL)) {
		if (strstr(opts->copts, ACPIDEV_CMD_OST_PREFIX) == NULL) {
			err = drerr_new(1, EX86_SUPPORT, NULL);
		}
	} else {
		err = drerr_new(1, EX86_SUPPORT, NULL);
	}

	if (!err && id && DRMACH_IS_BOARD_ID(id)) {
		switch (cmd) {
		case SBD_CMD_TEST:
			break;
		case SBD_CMD_CONNECT:
			if (bp->connected)
				err = drerr_new(0, ESBD_STATE, NULL);
			else if (!drmach_domain.allow_dr)
				err = drerr_new(1, EX86_SUPPORT, NULL);
			break;
		case SBD_CMD_DISCONNECT:
			if (!bp->connected)
				err = drerr_new(0, ESBD_STATE, NULL);
			else if (!drmach_domain.allow_dr)
				err = drerr_new(1, EX86_SUPPORT, NULL);
			break;
		default:
			if (!drmach_domain.allow_dr)
				err = drerr_new(1, EX86_SUPPORT, NULL);
			break;

		}
	}

	/*
	 * CPU/memory/IO DR operations will be supported in stages on x86.
	 * With early versions, some operations should be blocked here.
	 * This temporary hook will be removed when all CPU/memory/IO DR
	 * operations are supported on x86 systems.
	 *
	 * We only need to filter unsupported device types for
	 * SBD_CMD_CONFIGURE/SBD_CMD_UNCONFIGURE commands, all other
	 * commands are supported by all device types.
	 */
	if (!err && (cmd == SBD_CMD_CONFIGURE || cmd == SBD_CMD_UNCONFIGURE)) {
		int		i;
		dr_devset_t	*devsetp = (dr_devset_t *)argp;
		dr_devset_t	devset = *devsetp;

		switch (cmd) {
		case SBD_CMD_CONFIGURE:
			if (!plat_dr_support_cpu()) {
				DEVSET_DEL(devset, SBD_COMP_CPU,
				    DEVSET_ANYUNIT);
			} else {
				for (i = MAX_CPU_UNITS_PER_BOARD;
				    i < DEVSET_CPU_NUMBER; i++) {
					DEVSET_DEL(devset, SBD_COMP_CPU, i);
				}
			}

			if (!plat_dr_support_memory()) {
				DEVSET_DEL(devset, SBD_COMP_MEM,
				    DEVSET_ANYUNIT);
			} else {
				for (i = MAX_MEM_UNITS_PER_BOARD;
				    i < DEVSET_MEM_NUMBER; i++) {
					DEVSET_DEL(devset, SBD_COMP_MEM, i);
				}
			}

			/* No support of configuring IOH devices yet. */
			DEVSET_DEL(devset, SBD_COMP_IO, DEVSET_ANYUNIT);
			break;

		case SBD_CMD_UNCONFIGURE:
			if (!plat_dr_support_cpu()) {
				DEVSET_DEL(devset, SBD_COMP_CPU,
				    DEVSET_ANYUNIT);
			} else {
				for (i = MAX_CPU_UNITS_PER_BOARD;
				    i < DEVSET_CPU_NUMBER; i++) {
					DEVSET_DEL(devset, SBD_COMP_CPU, i);
				}
			}

			/* No support of unconfiguring MEM/IOH devices yet. */
			DEVSET_DEL(devset, SBD_COMP_MEM, DEVSET_ANYUNIT);
			DEVSET_DEL(devset, SBD_COMP_IO, DEVSET_ANYUNIT);
			break;
		}

		*devsetp = devset;
		if (DEVSET_IS_NULL(devset)) {
			err = drerr_new(1, EX86_SUPPORT, NULL);
		}
	}

	return (err);
}

sbd_error_t *
drmach_post_op(int cmd, drmachid_t id, drmach_opts_t *opts, int rv)
{
	_NOTE(ARGUNUSED(id, opts, rv));

	switch (cmd) {
	case SBD_CMD_STATUS:
	case SBD_CMD_GETNCM:
		break;

	default:
		rw_exit(&drmach_cpr_rwlock);
		break;
	}

	return (NULL);
}

sbd_error_t *
drmach_configure(drmachid_t id, int flags)
{
	_NOTE(ARGUNUSED(flags));

	drmach_device_t		*dp;
	sbd_error_t		*err = NULL;
	dev_info_t		*rdip;
	dev_info_t		*fdip = NULL;

	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	dp = id;

	rdip = dp->node->getdip(dp->node);
	ASSERT(rdip);
	ASSERT(e_ddi_branch_held(rdip));

	/* allocate cpu id for the CPU device. */
	if (DRMACH_IS_CPU_ID(id)) {
		DRMACH_HANDLE hdl = drmach_node_get_dnode(dp->node);
		ASSERT(hdl != NULL);
		if (ACPI_FAILURE(acpidev_dr_allocate_cpuid(hdl, NULL))) {
			err = drerr_new(1, EX86_ALLOC_CPUID, NULL);
		}
		return (err);
	}

	if (DRMACH_IS_MEM_ID(id)) {
		err = drmach_mem_update_lgrp(id);
		if (err)
			return (err);
	}

	if (e_ddi_branch_configure(rdip, &fdip, 0) != 0) {
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		dev_info_t *dip = (fdip != NULL) ? fdip : rdip;

		(void) ddi_pathname(dip, path);
		err = drerr_new(1, EX86_DRVFAIL, path);
		kmem_free(path, MAXPATHLEN);

		/* If non-NULL, fdip is returned held and must be released */
		if (fdip != NULL)
			ddi_release_devi(fdip);
	}

	return (err);
}

sbd_error_t *
drmach_unconfigure(drmachid_t id, int flags)
{
	_NOTE(ARGUNUSED(flags));

	drmach_device_t *dp;
	sbd_error_t	*err = NULL;
	dev_info_t	*rdip, *fdip = NULL;

	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	dp = id;

	rdip = dp->node->getdip(dp->node);
	ASSERT(rdip);
	ASSERT(e_ddi_branch_held(rdip));

	if (DRMACH_IS_CPU_ID(id)) {
		DRMACH_HANDLE hdl = drmach_node_get_dnode(dp->node);
		ASSERT(hdl != NULL);
		if (ACPI_FAILURE(acpidev_dr_free_cpuid(hdl))) {
			err = drerr_new(1, EX86_FREE_CPUID, NULL);
		}
		return (err);
	}

	/*
	 * Note: FORCE flag is no longer necessary under devfs
	 */
	if (e_ddi_branch_unconfigure(rdip, &fdip, 0)) {
		char		*path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		/*
		 * If non-NULL, fdip is returned held and must be released.
		 */
		if (fdip != NULL) {
			(void) ddi_pathname(fdip, path);
			ndi_rele_devi(fdip);
		} else {
			(void) ddi_pathname(rdip, path);
		}

		err = drerr_new(1, EX86_DRVFAIL, path);

		kmem_free(path, MAXPATHLEN);
	}

	return (err);
}

sbd_error_t *
drmach_get_dip(drmachid_t id, dev_info_t **dip)
{
	drmach_device_t	*dp;

	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	dp = id;

	*dip = dp->node->getdip(dp->node);

	return (NULL);
}

sbd_error_t *
drmach_release(drmachid_t id)
{
	drmach_common_t *cp;

	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	cp = id;

	return (cp->release(id));
}

sbd_error_t *
drmach_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_common_t *cp;
	sbd_error_t	*err;

	rw_enter(&drmach_boards_rwlock, RW_READER);
	if (!DRMACH_IS_ID(id)) {
		rw_exit(&drmach_boards_rwlock);
		return (drerr_new(0, EX86_NOTID, NULL));
	}
	cp = (drmach_common_t *)id;
	err = cp->status(id, stat);
	rw_exit(&drmach_boards_rwlock);

	return (err);
}

static sbd_error_t *
drmach_update_acpi_status(drmachid_t id, drmach_opts_t *opts)
{
	char		*copts;
	drmach_board_t	*bp;
	DRMACH_HANDLE	hdl;
	int		event, code;
	boolean_t	inprogress = B_FALSE;

	if (DRMACH_NULL_ID(id) || !DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	bp = (drmach_board_t *)id;
	hdl = drmach_node_get_dnode(bp->tree);
	ASSERT(hdl != NULL);
	if (hdl == NULL)
		return (drerr_new(0, EX86_INAPPROP, NULL));

	/* Get the status code. */
	copts = opts->copts;
	if (strncmp(copts, ACPIDEV_CMD_OST_INPROGRESS,
	    strlen(ACPIDEV_CMD_OST_INPROGRESS)) == 0) {
		inprogress = B_TRUE;
		code = ACPI_OST_STA_INSERT_IN_PROGRESS;
		copts += strlen(ACPIDEV_CMD_OST_INPROGRESS);
	} else if (strncmp(copts, ACPIDEV_CMD_OST_SUCCESS,
	    strlen(ACPIDEV_CMD_OST_SUCCESS)) == 0) {
		code = ACPI_OST_STA_SUCCESS;
		copts += strlen(ACPIDEV_CMD_OST_SUCCESS);
	} else if (strncmp(copts, ACPIDEV_CMD_OST_FAILURE,
	    strlen(ACPIDEV_CMD_OST_FAILURE)) == 0) {
		code = ACPI_OST_STA_FAILURE;
		copts += strlen(ACPIDEV_CMD_OST_FAILURE);
	} else if (strncmp(copts, ACPIDEV_CMD_OST_NOOP,
	    strlen(ACPIDEV_CMD_OST_NOOP)) == 0) {
		return (NULL);
	} else {
		return (drerr_new(0, EX86_UNKPTCMD, opts->copts));
	}

	/* Get the event type. */
	copts = strstr(copts, ACPIDEV_EVENT_TYPE_ATTR_NAME);
	if (copts == NULL) {
		return (drerr_new(0, EX86_UNKPTCMD, opts->copts));
	}
	copts += strlen(ACPIDEV_EVENT_TYPE_ATTR_NAME);
	if (copts[0] != '=') {
		return (drerr_new(0, EX86_UNKPTCMD, opts->copts));
	}
	copts += strlen("=");
	if (strncmp(copts, ACPIDEV_EVENT_TYPE_BUS_CHECK,
	    strlen(ACPIDEV_EVENT_TYPE_BUS_CHECK)) == 0) {
		event = ACPI_NOTIFY_BUS_CHECK;
	} else if (strncmp(copts, ACPIDEV_EVENT_TYPE_DEVICE_CHECK,
	    strlen(ACPIDEV_EVENT_TYPE_DEVICE_CHECK)) == 0) {
		event = ACPI_NOTIFY_DEVICE_CHECK;
	} else if (strncmp(copts, ACPIDEV_EVENT_TYPE_DEVICE_CHECK_LIGHT,
	    strlen(ACPIDEV_EVENT_TYPE_DEVICE_CHECK_LIGHT)) == 0) {
		event = ACPI_NOTIFY_DEVICE_CHECK_LIGHT;
	} else if (strncmp(copts, ACPIDEV_EVENT_TYPE_EJECT_REQUEST,
	    strlen(ACPIDEV_EVENT_TYPE_EJECT_REQUEST)) == 0) {
		event = ACPI_NOTIFY_EJECT_REQUEST;
		if (inprogress) {
			code = ACPI_OST_STA_EJECT_IN_PROGRESS;
		}
	} else {
		return (drerr_new(0, EX86_UNKPTCMD, opts->copts));
	}

	(void) acpidev_eval_ost(hdl, event, code, NULL, 0);

	return (NULL);
}

static struct {
	const char	*name;
	sbd_error_t	*(*handler)(drmachid_t id, drmach_opts_t *opts);
} drmach_pt_arr[] = {
	{ ACPIDEV_CMD_OST_PREFIX,	&drmach_update_acpi_status	},
	/* the following line must always be last */
	{ NULL,				NULL				}
};

sbd_error_t *
drmach_passthru(drmachid_t id, drmach_opts_t *opts)
{
	int		i;
	sbd_error_t	*err;

	i = 0;
	while (drmach_pt_arr[i].name != NULL) {
		int len = strlen(drmach_pt_arr[i].name);

		if (strncmp(drmach_pt_arr[i].name, opts->copts, len) == 0)
			break;

		i += 1;
	}

	if (drmach_pt_arr[i].name == NULL)
		err = drerr_new(0, EX86_UNKPTCMD, opts->copts);
	else
		err = (*drmach_pt_arr[i].handler)(id, opts);

	return (err);
}

/*
 * Board specific interfaces to support dr driver
 */
static int
drmach_get_portid(drmach_node_t *np)
{
	uint32_t	portid;

	if (np->getprop(np, ACPIDEV_DR_PROP_PORTID,
	    &portid, sizeof (portid)) == 0) {
		/*
		 * acpidev returns portid as uint32_t, validates it.
		 */
		if (portid > INT_MAX) {
			return (-1);
		} else {
			return (portid);
		}
	}

	return (-1);
}

/*
 * This is a helper function to determine if a given
 * node should be considered for a dr operation according
 * to predefined dr type nodes and the node's name.
 * Formal Parameter : The name of a device node.
 * Return Value: -1, name does not map to a valid dr type.
 *		 A value greater or equal to 0, name is a valid dr type.
 */
static int
drmach_name2type_idx(char *name)
{
	int 	index, ntypes;

	if (name == NULL)
		return (-1);

	/*
	 * Determine how many possible types are currently supported
	 * for dr.
	 */
	ntypes = sizeof (drmach_name2type) / sizeof (drmach_name2type[0]);

	/* Determine if the node's name correspond to a predefined type. */
	for (index = 0; index < ntypes; index++) {
		if (strcmp(drmach_name2type[index].name, name) == 0)
			/* The node is an allowed type for dr. */
			return (index);
	}

	/*
	 * If the name of the node does not map to any of the
	 * types in the array drmach_name2type then the node is not of
	 * interest to dr.
	 */
	return (-1);
}

static int
drmach_board_find_devices_cb(drmach_node_walk_args_t *args)
{
	drmach_node_t			*node = args->node;
	drmach_board_cb_data_t		*data = args->data;
	drmach_board_t			*obj = data->obj;

	int		rv, portid;
	uint32_t	bnum;
	drmachid_t	id;
	drmach_device_t	*device;
	char		name[OBP_MAXDRVNAME];

	portid = drmach_get_portid(node);
	rv = node->getprop(node, ACPIDEV_DR_PROP_DEVNAME,
	    name, OBP_MAXDRVNAME);
	if (rv)
		return (0);

	rv = node->getprop(node, ACPIDEV_DR_PROP_BOARDNUM,
	    &bnum, sizeof (bnum));
	if (rv) {
		return (0);
	}
	if (bnum > INT_MAX) {
		return (0);
	}

	if (bnum != obj->bnum)
		return (0);

	if (drmach_name2type_idx(name) < 0) {
		return (0);
	}

	/*
	 * Create a device data structure from this node data.
	 * The call may yield nothing if the node is not of interest
	 * to drmach.
	 */
	data->err = drmach_device_new(node, obj, portid, &id);
	if (data->err)
		return (-1);
	else if (!id) {
		/*
		 * drmach_device_new examined the node we passed in
		 * and determined that it was one not of interest to
		 * drmach.  So, it is skipped.
		 */
		return (0);
	}

	rv = drmach_array_set(obj->devices, data->ndevs++, id);
	if (rv) {
		data->err = DRMACH_INTERNAL_ERROR();
		return (-1);
	}
	device = id;

	data->err = (*data->found)(data->a, device->type, device->unum, id);

	return (data->err == NULL ? 0 : -1);
}

sbd_error_t *
drmach_board_find_devices(drmachid_t id, void *a,
	sbd_error_t *(*found)(void *a, const char *, int, drmachid_t))
{
	drmach_board_t		*bp = (drmach_board_t *)id;
	sbd_error_t		*err;
	int			 max_devices;
	int			 rv;
	drmach_board_cb_data_t	data;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));

	max_devices  = MAX_CPU_UNITS_PER_BOARD;
	max_devices += MAX_MEM_UNITS_PER_BOARD;
	max_devices += MAX_IO_UNITS_PER_BOARD;

	if (bp->devices == NULL)
		bp->devices = drmach_array_new(0, max_devices);
	ASSERT(bp->tree != NULL);

	data.obj = bp;
	data.ndevs = 0;
	data.found = found;
	data.a = a;
	data.err = NULL;

	acpidev_dr_lock_all();
	rv = drmach_node_walk(bp->tree, &data, drmach_board_find_devices_cb);
	acpidev_dr_unlock_all();
	if (rv == 0) {
		err = NULL;
	} else {
		drmach_array_dispose(bp->devices, drmach_device_dispose);
		bp->devices = NULL;

		if (data.err)
			err = data.err;
		else
			err = DRMACH_INTERNAL_ERROR();
	}

	return (err);
}

int
drmach_board_lookup(int bnum, drmachid_t *id)
{
	int	rv = 0;

	if (bnum < 0) {
		*id = 0;
		return (-1);
	}

	rw_enter(&drmach_boards_rwlock, RW_READER);
	if (drmach_array_get(drmach_boards, (uint_t)bnum, id)) {
		*id = 0;
		rv = -1;
	}
	rw_exit(&drmach_boards_rwlock);

	return (rv);
}

sbd_error_t *
drmach_board_name(int bnum, char *buf, int buflen)
{
	ACPI_HANDLE hdl;
	sbd_error_t *err = NULL;

	if (bnum < 0) {
		return (drerr_new(1, EX86_BNUM, "%d", bnum));
	}

	acpidev_dr_lock_all();
	if (ACPI_FAILURE(acpidev_dr_get_board_handle(bnum, &hdl))) {
		DRMACH_PR("!drmach_board_name: failed to lookup ACPI handle "
		    "for board %d.", bnum);
		err = drerr_new(1, EX86_BNUM, "%d", bnum);
	} else if (ACPI_FAILURE(acpidev_dr_get_board_name(hdl, buf, buflen))) {
		DRMACH_PR("!drmach_board_name: failed to generate board name "
		    "for board %d.", bnum);
		err = drerr_new(0, EX86_INVALID_ARG,
		    ": buffer is too small for board name.");
	}
	acpidev_dr_unlock_all();

	return (err);
}

int
drmach_board_is_floating(drmachid_t id)
{
	drmach_board_t *bp;

	if (!DRMACH_IS_BOARD_ID(id))
		return (0);

	bp = (drmach_board_t *)id;

	return ((drmach_domain.floating & (1ULL << bp->bnum)) ? 1 : 0);
}

static ACPI_STATUS
drmach_board_check_dependent_cb(ACPI_HANDLE hdl, UINT32 lvl, void *ctx,
    void **retval)
{
	uint32_t bdnum;
	drmach_board_t *bp;
	ACPI_STATUS rc = AE_OK;
	int cmd = (int)(intptr_t)ctx;

	ASSERT(hdl != NULL);
	ASSERT(lvl == UINT32_MAX);
	ASSERT(retval != NULL);

	/* Skip non-board devices. */
	if (!acpidev_dr_device_is_board(hdl)) {
		return (AE_OK);
	} else if (ACPI_FAILURE(acpidev_dr_get_board_number(hdl, &bdnum))) {
		DRMACH_PR("!drmach_board_check_dependent_cb: failed to get "
		    "board number for object %p.\n", hdl);
		return (AE_ERROR);
	} else if (bdnum > MAX_BOARDS) {
		DRMACH_PR("!drmach_board_check_dependent_cb: board number %u "
		    "is too big, max %u.", bdnum, MAX_BOARDS);
		return (AE_ERROR);
	}

	bp = drmach_get_board_by_bnum(bdnum);
	switch (cmd) {
	case SBD_CMD_CONNECT:
		/*
		 * Its parent board should be present, assigned, powered and
		 * connected when connecting the child board.
		 */
		if (bp == NULL) {
			*retval = hdl;
			rc = AE_ERROR;
		} else {
			bp->powered = acpidev_dr_device_is_powered(hdl);
			if (!bp->connected || !bp->powered || !bp->assigned) {
				*retval = hdl;
				rc = AE_ERROR;
			}
		}
		break;

	case SBD_CMD_POWERON:
		/*
		 * Its parent board should be present, assigned and powered when
		 * powering on the child board.
		 */
		if (bp == NULL) {
			*retval = hdl;
			rc = AE_ERROR;
		} else {
			bp->powered = acpidev_dr_device_is_powered(hdl);
			if (!bp->powered || !bp->assigned) {
				*retval = hdl;
				rc = AE_ERROR;
			}
		}
		break;

	case SBD_CMD_ASSIGN:
		/*
		 * Its parent board should be present and assigned when
		 * assigning the child board.
		 */
		if (bp == NULL) {
			*retval = hdl;
			rc = AE_ERROR;
		} else if (!bp->assigned) {
			*retval = hdl;
			rc = AE_ERROR;
		}
		break;

	case SBD_CMD_DISCONNECT:
		/*
		 * The child board should be disconnected if present when
		 * disconnecting its parent board.
		 */
		if (bp != NULL && bp->connected) {
			*retval = hdl;
			rc = AE_ERROR;
		}
		break;

	case SBD_CMD_POWEROFF:
		/*
		 * The child board should be disconnected and powered off if
		 * present when powering off its parent board.
		 */
		if (bp != NULL) {
			bp->powered = acpidev_dr_device_is_powered(hdl);
			if (bp->connected || bp->powered) {
				*retval = hdl;
				rc = AE_ERROR;
			}
		}
		break;

	case SBD_CMD_UNASSIGN:
		/*
		 * The child board should be disconnected, powered off and
		 * unassigned if present when unassigning its parent board.
		 */
		if (bp != NULL) {
			bp->powered = acpidev_dr_device_is_powered(hdl);
			if (bp->connected || bp->powered || bp->assigned) {
				*retval = hdl;
				rc = AE_ERROR;
			}
		}
		break;

	default:
		/* Return success for all other commands. */
		break;
	}

	return (rc);
}

sbd_error_t *
drmach_board_check_dependent(int cmd, drmach_board_t *bp)
{
	int reverse;
	char *name;
	sbd_error_t *err = NULL;
	DRMACH_HANDLE hdl;
	DRMACH_HANDLE dp = NULL;

	ASSERT(bp != NULL);
	ASSERT(DRMACH_IS_BOARD_ID(bp));
	ASSERT(RW_LOCK_HELD(&drmach_boards_rwlock));

	hdl = drmach_node_get_dnode(bp->tree);
	if (hdl == NULL)
		return (drerr_new(0, EX86_INAPPROP, NULL));

	switch (cmd) {
	case SBD_CMD_ASSIGN:
	case SBD_CMD_POWERON:
	case SBD_CMD_CONNECT:
		if (ACPI_SUCCESS(acpidev_dr_device_walk_ejd(hdl,
		    &drmach_board_check_dependent_cb,
		    (void *)(intptr_t)cmd, &dp))) {
			return (NULL);
		}
		reverse = 0;
		break;

	case SBD_CMD_UNASSIGN:
	case SBD_CMD_POWEROFF:
	case SBD_CMD_DISCONNECT:
		if (ACPI_SUCCESS(acpidev_dr_device_walk_edl(hdl,
		    &drmach_board_check_dependent_cb,
		    (void *)(intptr_t)cmd, &dp))) {
			return (NULL);
		}
		reverse = 1;
		break;

	default:
		return (drerr_new(0, EX86_INAPPROP, NULL));
	}

	if (dp == NULL) {
		return (drerr_new(1, EX86_WALK_DEPENDENCY, "%s", bp->cm.name));
	}
	name = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if (ACPI_FAILURE(acpidev_dr_get_board_name(dp, name, MAXPATHLEN))) {
		err = drerr_new(1, EX86_WALK_DEPENDENCY, "%s", bp->cm.name);
	} else if (reverse == 0) {
		err = drerr_new(1, EX86_WALK_DEPENDENCY,
		    "%s, depends on board %s", bp->cm.name, name);
	} else {
		err = drerr_new(1, EX86_WALK_DEPENDENCY,
		    "board %s depends on %s", name, bp->cm.name);
	}
	kmem_free(name, MAXPATHLEN);

	return (err);
}

sbd_error_t *
drmach_board_assign(int bnum, drmachid_t *id)
{
	sbd_error_t	*err = NULL;

	if (bnum < 0) {
		return (drerr_new(1, EX86_BNUM, "%d", bnum));
	}

	rw_enter(&drmach_boards_rwlock, RW_WRITER);

	if (drmach_array_get(drmach_boards, bnum, id) == -1) {
		err = drerr_new(1, EX86_BNUM, "%d", bnum);
	} else {
		drmach_board_t	*bp;

		/*
		 * Board has already been created, downgrade to reader.
		 */
		if (*id)
			rw_downgrade(&drmach_boards_rwlock);

		bp = *id;
		if (!(*id))
			bp = *id  =
			    (drmachid_t)drmach_board_new(bnum, 0);

		if (bp == NULL) {
			DRMACH_PR("!drmach_board_assign: failed to create "
			    "object for board %d.", bnum);
			err = drerr_new(1, EX86_BNUM, "%d", bnum);
		} else {
			err = drmach_board_check_dependent(SBD_CMD_ASSIGN, bp);
			if (err == NULL)
				bp->assigned = 1;
		}
	}

	rw_exit(&drmach_boards_rwlock);

	return (err);
}

sbd_error_t *
drmach_board_unassign(drmachid_t id)
{
	drmach_board_t	*bp;
	sbd_error_t	*err;
	drmach_status_t	 stat;

	if (DRMACH_NULL_ID(id))
		return (NULL);

	if (!DRMACH_IS_BOARD_ID(id)) {
		return (drerr_new(0, EX86_INAPPROP, NULL));
	}
	bp = id;

	rw_enter(&drmach_boards_rwlock, RW_WRITER);

	err = drmach_board_status(id, &stat);
	if (err) {
		rw_exit(&drmach_boards_rwlock);
		return (err);
	}

	if (stat.configured || stat.busy) {
		err = drerr_new(0, EX86_CONFIGBUSY, bp->cm.name);
	} else if (bp->connected) {
		err = drerr_new(0, EX86_CONNECTBUSY, bp->cm.name);
	} else if (stat.powered) {
		err = drerr_new(0, EX86_POWERBUSY, bp->cm.name);
	} else {
		err = drmach_board_check_dependent(SBD_CMD_UNASSIGN, bp);
		if (err == NULL) {
			if (drmach_array_set(drmach_boards, bp->bnum, 0) != 0)
				err = DRMACH_INTERNAL_ERROR();
			else
				drmach_board_dispose(bp);
		}
	}

	rw_exit(&drmach_boards_rwlock);

	return (err);
}

sbd_error_t *
drmach_board_poweron(drmachid_t id)
{
	drmach_board_t	*bp;
	sbd_error_t *err = NULL;
	DRMACH_HANDLE hdl;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	bp = id;

	hdl = drmach_node_get_dnode(bp->tree);
	if (hdl == NULL)
		return (drerr_new(0, EX86_INAPPROP, NULL));

	bp->powered = drmach_board_check_power(bp);
	if (bp->powered) {
		return (NULL);
	}

	rw_enter(&drmach_boards_rwlock, RW_WRITER);
	err = drmach_board_check_dependent(SBD_CMD_POWERON, bp);
	if (err == NULL) {
		acpidev_dr_lock_all();
		if (ACPI_FAILURE(acpidev_dr_device_poweron(hdl)))
			err = drerr_new(0, EX86_POWERON, NULL);
		acpidev_dr_unlock_all();

		/* Check whether the board is powered on. */
		bp->powered = drmach_board_check_power(bp);
		if (err == NULL && bp->powered == 0)
			err = drerr_new(0, EX86_POWERON, NULL);
	}
	rw_exit(&drmach_boards_rwlock);

	return (err);
}

sbd_error_t *
drmach_board_poweroff(drmachid_t id)
{
	sbd_error_t	*err = NULL;
	drmach_board_t	*bp;
	drmach_status_t	 stat;
	DRMACH_HANDLE	 hdl;

	if (DRMACH_NULL_ID(id))
		return (NULL);

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	bp = id;

	hdl = drmach_node_get_dnode(bp->tree);
	if (hdl == NULL)
		return (drerr_new(0, EX86_INAPPROP, NULL));

	/* Check whether the board is busy, configured or connected. */
	err = drmach_board_status(id, &stat);
	if (err != NULL)
		return (err);
	if (stat.configured || stat.busy) {
		return (drerr_new(0, EX86_CONFIGBUSY, bp->cm.name));
	} else if (bp->connected) {
		return (drerr_new(0, EX86_CONNECTBUSY, bp->cm.name));
	}

	bp->powered = drmach_board_check_power(bp);
	if (bp->powered == 0) {
		return (NULL);
	}

	rw_enter(&drmach_boards_rwlock, RW_WRITER);
	err = drmach_board_check_dependent(SBD_CMD_POWEROFF, bp);
	if (err == NULL) {
		acpidev_dr_lock_all();
		if (ACPI_FAILURE(acpidev_dr_device_poweroff(hdl)))
			err = drerr_new(0, EX86_POWEROFF, NULL);
		acpidev_dr_unlock_all();

		bp->powered = drmach_board_check_power(bp);
		if (err == NULL && bp->powered != 0)
			err = drerr_new(0, EX86_POWEROFF, NULL);
	}
	rw_exit(&drmach_boards_rwlock);

	return (err);
}

sbd_error_t *
drmach_board_test(drmachid_t id, drmach_opts_t *opts, int force)
{
	_NOTE(ARGUNUSED(opts, force));

	drmach_board_t	*bp;
	DRMACH_HANDLE	 hdl;

	if (DRMACH_NULL_ID(id))
		return (NULL);

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	bp = id;

	hdl = drmach_node_get_dnode(bp->tree);
	if (hdl == NULL)
		return (drerr_new(0, EX86_INAPPROP, NULL));

	if (ACPI_FAILURE(acpidev_dr_device_check_status(hdl)))
		return (drerr_new(0, EX86_IN_FAILURE, NULL));

	return (NULL);
}

sbd_error_t *
drmach_board_connect(drmachid_t id, drmach_opts_t *opts)
{
	_NOTE(ARGUNUSED(opts));

	sbd_error_t	*err = NULL;
	drmach_board_t	*bp = (drmach_board_t *)id;
	DRMACH_HANDLE	hdl;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	bp = (drmach_board_t *)id;

	hdl = drmach_node_get_dnode(bp->tree);
	if (hdl == NULL)
		return (drerr_new(0, EX86_INAPPROP, NULL));

	rw_enter(&drmach_boards_rwlock, RW_WRITER);
	err = drmach_board_check_dependent(SBD_CMD_CONNECT, bp);
	if (err == NULL) {
		acpidev_dr_lock_all();
		if (ACPI_FAILURE(acpidev_dr_device_insert(hdl))) {
			(void) acpidev_dr_device_remove(hdl);
			err = drerr_new(1, EX86_PROBE, NULL);
		} else {
			bp->connected = 1;
		}
		acpidev_dr_unlock_all();
	}
	rw_exit(&drmach_boards_rwlock);

	return (err);
}

sbd_error_t *
drmach_board_disconnect(drmachid_t id, drmach_opts_t *opts)
{
	_NOTE(ARGUNUSED(opts));

	DRMACH_HANDLE hdl;
	drmach_board_t *bp;
	drmach_status_t	stat;
	sbd_error_t *err = NULL;

	if (DRMACH_NULL_ID(id))
		return (NULL);
	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	bp = (drmach_board_t *)id;

	hdl = drmach_node_get_dnode(bp->tree);
	if (hdl == NULL)
		return (drerr_new(0, EX86_INAPPROP, NULL));

	/* Check whether the board is busy or configured. */
	err = drmach_board_status(id, &stat);
	if (err != NULL)
		return (err);
	if (stat.configured || stat.busy)
		return (drerr_new(0, EX86_CONFIGBUSY, bp->cm.name));

	rw_enter(&drmach_boards_rwlock, RW_WRITER);
	err = drmach_board_check_dependent(SBD_CMD_DISCONNECT, bp);
	if (err == NULL) {
		acpidev_dr_lock_all();
		if (ACPI_SUCCESS(acpidev_dr_device_remove(hdl))) {
			bp->connected = 0;
		} else {
			err = drerr_new(1, EX86_DEPROBE, bp->cm.name);
		}
		acpidev_dr_unlock_all();
	}
	rw_exit(&drmach_boards_rwlock);

	return (err);
}

sbd_error_t *
drmach_board_deprobe(drmachid_t id)
{
	drmach_board_t	*bp;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	bp = id;

	cmn_err(CE_CONT, "DR: detach board %d\n", bp->bnum);

	if (bp->devices) {
		drmach_array_dispose(bp->devices, drmach_device_dispose);
		bp->devices = NULL;
	}

	bp->boot_board = 0;

	return (NULL);
}

/*
 * CPU specific interfaces to support dr driver
 */
sbd_error_t *
drmach_cpu_disconnect(drmachid_t id)
{
	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));

	return (NULL);
}

sbd_error_t *
drmach_cpu_get_id(drmachid_t id, processorid_t *cpuid)
{
	drmach_cpu_t *cpu;

	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	cpu = (drmach_cpu_t *)id;

	if (cpu->cpuid == -1) {
		if (ACPI_SUCCESS(acpica_get_cpu_id_by_object(
		    drmach_node_get_dnode(cpu->dev.node), cpuid))) {
			cpu->cpuid = *cpuid;
		} else {
			*cpuid = -1;
		}
	} else {
		*cpuid = cpu->cpuid;
	}

	return (NULL);
}

sbd_error_t *
drmach_cpu_get_impl(drmachid_t id, int *ip)
{
	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));

	/* Assume all CPUs in system are homogeneous. */
	*ip = X86_CPU_IMPL_UNKNOWN;

	kpreempt_disable();
	if (cpuid_getvendor(CPU) == X86_VENDOR_Intel) {
		/* NHM-EX CPU */
		if (cpuid_getfamily(CPU) == 0x6 &&
		    cpuid_getmodel(CPU) == 0x2e) {
			*ip = X86_CPU_IMPL_NEHALEM_EX;
		}
	}
	kpreempt_enable();

	return (NULL);
}

/*
 * Memory specific interfaces to support dr driver
 */

/*
 * When drmach_mem_new() is called, the mp->base_pa field is set to the base
 * address of configured memory if there's configured memory on the board,
 * otherwise set to UINT64_MAX. For hot-added memory board, there's no
 * configured memory when drmach_mem_new() is called, so mp->base_pa is set
 * to UINT64_MAX and we need to set a correct value for it after memory
 * hot-add  operations.
 * A hot-added memory board may contain multiple memory segments,
 * drmach_mem_add_span() will be called once for each segment, so we can't
 * rely on the basepa argument. And it's possible that only part of a memory
 * segment is added into OS, so need to intersect with phys_installed list
 * to get the real base address of configured memory on the board.
 */
sbd_error_t *
drmach_mem_add_span(drmachid_t id, uint64_t basepa, uint64_t size)
{
	_NOTE(ARGUNUSED(basepa));

	uint64_t	nbytes = 0;
	uint64_t	endpa;
	drmach_mem_t	*mp;
	struct memlist	*ml2;
	struct memlist	*p;

	ASSERT(size != 0);

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	mp = (drmach_mem_t *)id;

	/* Compute basepa and size of installed memory. */
	endpa = _ptob64(physmax + 1);
	memlist_read_lock();
	ml2 = memlist_dup(phys_install);
	memlist_read_unlock();
	ml2 = memlist_del_span(ml2, 0ull, mp->slice_base);
	if (ml2 && endpa > mp->slice_top) {
		ml2 = memlist_del_span(ml2, mp->slice_top,
		    endpa - mp->slice_top);
	}

	ASSERT(ml2);
	if (ml2) {
		for (p = ml2; p; p = p->ml_next) {
			nbytes += p->ml_size;
			if (mp->base_pa > p->ml_address)
				mp->base_pa = p->ml_address;
		}
		ASSERT(nbytes > 0);
		mp->nbytes += nbytes;
		memlist_delete(ml2);
	}

	return (NULL);
}

static sbd_error_t *
drmach_mem_update_lgrp(drmachid_t id)
{
	ACPI_STATUS	rc;
	DRMACH_HANDLE	hdl;
	void		*hdlp;
	drmach_mem_t	*mp;
	update_membounds_t umb;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	mp = (drmach_mem_t *)id;
	/* No need to update lgrp if memory is already installed. */
	if (mp->nbytes != 0)
		return (NULL);
	/* No need to update lgrp if lgrp is disabled. */
	if (max_mem_nodes == 1)
		return (NULL);

	/* Add memory to lgroup */
	hdl = mp->dev.node->get_dnode(mp->dev.node);
	rc = acpidev_dr_device_get_memory_index(hdl, &umb.u_device_id);
	ASSERT(ACPI_SUCCESS(rc));
	if (ACPI_FAILURE(rc)) {
		cmn_err(CE_WARN, "drmach: failed to get device id of memory, "
		    "can't update lgrp information.");
		return (drerr_new(0, EX86_INTERNAL, NULL));
	}
	rc = acpidev_dr_get_mem_numa_info(hdl, mp->memlist, &hdlp,
	    &umb.u_domain, &umb.u_sli_cnt, &umb.u_sli_ptr);
	ASSERT(ACPI_SUCCESS(rc));
	if (ACPI_FAILURE(rc)) {
		cmn_err(CE_WARN, "drmach: failed to get lgrp info of memory, "
		    "can't update lgrp information.");
		return (drerr_new(0, EX86_INTERNAL, NULL));
	}
	umb.u_base = (uint64_t)mp->slice_base;
	umb.u_length = (uint64_t)(mp->slice_top - mp->slice_base);
	lgrp_plat_config(LGRP_CONFIG_MEM_ADD, (uintptr_t)&umb);
	acpidev_dr_free_mem_numa_info(hdlp);

	return (NULL);
}

sbd_error_t *
drmach_mem_enable(drmachid_t id)
{
	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	else
		return (NULL);
}

sbd_error_t *
drmach_mem_get_info(drmachid_t id, drmach_mem_info_t *mem)
{
	drmach_mem_t *mp;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	mp = (drmach_mem_t *)id;

	/*
	 * This is only used by dr to round up/down the memory
	 * for copying.
	 */
	mem->mi_alignment_mask = mp->mem_alignment - 1;
	mem->mi_basepa = mp->base_pa;
	mem->mi_size = mp->nbytes;
	mem->mi_slice_base = mp->slice_base;
	mem->mi_slice_top = mp->slice_top;
	mem->mi_slice_size = mp->slice_size;

	return (NULL);
}

sbd_error_t *
drmach_mem_get_slice_info(drmachid_t id,
    uint64_t *bp, uint64_t *ep, uint64_t *sp)
{
	drmach_mem_t *mp;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	mp = (drmach_mem_t *)id;

	if (bp)
		*bp = mp->slice_base;
	if (ep)
		*ep = mp->slice_top;
	if (sp)
		*sp = mp->slice_size;

	return (NULL);
}

sbd_error_t *
drmach_mem_get_memlist(drmachid_t id, struct memlist **ml)
{
#ifdef	DEBUG
	int		rv;
#endif
	drmach_mem_t	*mem;
	struct memlist	*mlist;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	mem = (drmach_mem_t *)id;

	mlist = memlist_dup(mem->memlist);
	*ml = mlist;

#ifdef DEBUG
	/*
	 * Make sure the incoming memlist doesn't already
	 * intersect with what's present in the system (phys_install).
	 */
	memlist_read_lock();
	rv = memlist_intersect(phys_install, mlist);
	memlist_read_unlock();
	if (rv) {
		DRMACH_PR("Derived memlist intersects with phys_install\n");
		memlist_dump(mlist);

		DRMACH_PR("phys_install memlist:\n");
		memlist_dump(phys_install);

		memlist_delete(mlist);
		return (DRMACH_INTERNAL_ERROR());
	}

	DRMACH_PR("Derived memlist:");
	memlist_dump(mlist);
#endif

	return (NULL);
}

processorid_t
drmach_mem_cpu_affinity(drmachid_t id)
{
	_NOTE(ARGUNUSED(id));

	return (CPU_CURRENT);
}

int
drmach_copy_rename_need_suspend(drmachid_t id)
{
	_NOTE(ARGUNUSED(id));

	return (0);
}

/*
 * IO specific interfaces to support dr driver
 */
sbd_error_t *
drmach_io_pre_release(drmachid_t id)
{
	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));

	return (NULL);
}

sbd_error_t *
drmach_io_unrelease(drmachid_t id)
{
	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));

	return (NULL);
}

sbd_error_t *
drmach_io_post_release(drmachid_t id)
{
	_NOTE(ARGUNUSED(id));

	return (NULL);
}

sbd_error_t *
drmach_io_post_attach(drmachid_t id)
{
	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));

	return (NULL);
}

sbd_error_t *
drmach_io_is_attached(drmachid_t id, int *yes)
{
	drmach_device_t *dp;
	dev_info_t	*dip;
	int		state;

	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, EX86_INAPPROP, NULL));
	dp = id;

	dip = dp->node->getdip(dp->node);
	if (dip == NULL) {
		*yes = 0;
		return (NULL);
	}

	state = ddi_get_devstate(dip);
	*yes = ((i_ddi_node_state(dip) >= DS_ATTACHED) ||
	    (state == DDI_DEVSTATE_UP));

	return (NULL);
}

/*
 * Miscellaneous interfaces to support dr driver
 */
int
drmach_verify_sr(dev_info_t *dip, int sflag)
{
	_NOTE(ARGUNUSED(dip, sflag));

	return (0);
}

void
drmach_suspend_last(void)
{
}

void
drmach_resume_first(void)
{
}

/*
 * Log a DR sysevent.
 * Return value: 0 success, non-zero failure.
 */
int
drmach_log_sysevent(int board, char *hint, int flag, int verbose)
{
	sysevent_t			*ev = NULL;
	sysevent_id_t			eid;
	int				rv, km_flag;
	sysevent_value_t		evnt_val;
	sysevent_attr_list_t		*evnt_attr_list = NULL;
	sbd_error_t			*err;
	char				attach_pnt[MAXNAMELEN];

	km_flag = (flag == SE_SLEEP) ? KM_SLEEP : KM_NOSLEEP;
	attach_pnt[0] = '\0';
	err = drmach_board_name(board, attach_pnt, MAXNAMELEN);
	if (err != NULL) {
		sbd_err_clear(&err);
		rv = -1;
		goto logexit;
	}
	if (verbose) {
		DRMACH_PR("drmach_log_sysevent: %s %s, flag: %d, verbose: %d\n",
		    attach_pnt, hint, flag, verbose);
	}

	if ((ev = sysevent_alloc(EC_DR, ESC_DR_AP_STATE_CHANGE,
	    SUNW_KERN_PUB"dr", km_flag)) == NULL) {
		rv = -2;
		goto logexit;
	}
	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = attach_pnt;
	if ((rv = sysevent_add_attr(&evnt_attr_list, DR_AP_ID, &evnt_val,
	    km_flag)) != 0)
		goto logexit;

	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = hint;
	if ((rv = sysevent_add_attr(&evnt_attr_list, DR_HINT, &evnt_val,
	    km_flag)) != 0) {
		sysevent_free_attr(evnt_attr_list);
		goto logexit;
	}

	(void) sysevent_attach_attributes(ev, evnt_attr_list);

	/*
	 * Log the event but do not sleep waiting for its
	 * delivery. This provides insulation from syseventd.
	 */
	rv = log_sysevent(ev, SE_NOSLEEP, &eid);

logexit:
	if (ev)
		sysevent_free(ev);
	if ((rv != 0) && verbose)
		cmn_err(CE_WARN, "!drmach_log_sysevent failed (rv %d) for %s "
		    " %s\n", rv, attach_pnt, hint);

	return (rv);
}
