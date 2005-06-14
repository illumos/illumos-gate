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

#ifndef	_SYS_PSHOT_H
#define	_SYS_PSHOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sunndi.h>

/*
 * user accessable features
 */

/* determines max pshot_minor allocation per softstate */
#define	PSHOT_MAX_MINOR_PERINST		2
#define	PSHOT_MAX_MINOR_NAMELEN		16

#define	PSHOT_NODENAME_DEVCTL		"devctl"
#define	PSHOT_NODENAME_TESTCTL		"testctl"

#define	PSHOT_PROP_DEVNAME	"dev-name"
#define	PSHOT_PROP_DEVNT	"dev-nt"
#define	PSHOT_PROP_DEVCOMPAT	"dev-compat"


#ifdef	_KERNEL


#define	PARENT_IS_PSHOT(self)	\
	(ddi_driver_major(self) == ddi_driver_major(ddi_get_parent(self)))


static int pshot_debug = 0;
static int pshot_event_test_enable = 0;

#ifdef DEBUG
#define	pshot_debug pshot_debug_on
#define	pshot_event_test_enable pshot_event_test_on

static int pshot_debug_on = 0;
static int pshot_event_test_on = 0;

#endif

#define	PSHOT_MAX_CBCACHE	6
#define	PSHOT_MAX_TSTCACHE	8

/*
 * soft state and minor node management
 * (includes user features above)
 */

/*
 * a "node number" is currently implemented as an index into a pshot_minor_t
 * array, therefore the max must be less than PSHOT_MAX_MINOR_PERINST and
 * ideally, the minor array should be fully populated, with a node number
 * defined for each index
 */
#define	PSHOT_NODENUM_DEVCTL		0
#define	PSHOT_NODENUM_TESTCTL		1
#define	PSHOT_MAX_NODENUM		PSHOT_NODENUM_TESTCTL

typedef struct pshot_minor pshot_minor_t;
typedef struct pshot pshot_t;

struct pshot_minor {
	pshot_t		*pshot;
	minor_t		minor;
	char		name[PSHOT_MAX_MINOR_NAMELEN];
};

struct pshot {
	kmutex_t	lock;
	uint_t		state;
	dev_info_t	*dip;
	int		instance;
	ndi_event_hdl_t	ndi_event_hdl;
	ndi_event_set_t	ndi_events;
	ddi_iblock_cookie_t	iblock_cookie;
	ddi_callback_id_t 	callback_cache[PSHOT_MAX_CBCACHE];
	ddi_callback_id_t	test_callback_cache[PSHOT_MAX_TSTCACHE];

	pshot_minor_t	nodes[PSHOT_MAX_MINOR_PERINST];
	int	level;		/* pm power level */
	int	busy;		/* pm busy state */
	int	busy_ioctl;	/* track busy and idle ioctl calls */
};


static size_t pshot_numbits(size_t);
static minor_t pshot_minor_encode(int, minor_t);
static int pshot_minor_decode_inst(minor_t);
static minor_t pshot_minor_decode_nodenum(minor_t);

#define	PSHOT_NODENUM_BITS()	pshot_numbits(PSHOT_MAX_MINOR_PERINST)

/*
 * children device configuration
 */

typedef struct pshot_device {
	char *name;
	char *nodetype;
	char *compat;
} pshot_device_t;

#define	PSHOT_DEV_ANYNT		0x1

static char *pshot_str2nt(char *);
static pshot_device_t *pshot_devices_from_props(dev_info_t *, size_t *, int);
static void pshot_devices_free(pshot_device_t *, size_t);
static int pshot_devices_setup(dev_info_t *);
static int pshot_devices_grow(pshot_device_t **, size_t,
    const pshot_device_t *, size_t);


/*
 * softstate state bits
 */
#define	IS_OPEN				0x0001
#define	IS_OPEN_EXCL			0x0002
#define	DEV_RESET_PENDING		0x0004
#define	BUS_RESET_PENDING		0x0008
#define	POWER_FLAG			0x0010
#define	FAIL_SUSPEND_FLAG		0x0020
#define	STRICT_PARENT			0x0040
#define	NO_INVOL_FLAG			0x0080
#define	PM_SUPPORTED			0x0100

/*
 * Leaf ops (supports hotplug controls to the device)
 */
static int pshot_open(dev_t *, int, int, cred_t *);
static int pshot_close(dev_t, int, int, cred_t *);
static int pshot_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int pshot_probe(dev_info_t *);
static int pshot_attach(dev_info_t *, ddi_attach_cmd_t);
static int pshot_detach(dev_info_t *, ddi_detach_cmd_t);
static int pshot_info(dev_info_t *, ddi_info_cmd_t,  void *, void **);
static int pshot_power(dev_info_t *dip, int cmpt, int level);

static int pshot_devctl(pshot_t *, minor_t, int, intptr_t, int, cred_t *,
    int *);
static int pshot_testctl(pshot_t *, minor_t, int, intptr_t, int, cred_t *,
    int *);

/*
 * Event handling prototype support.
 */
#define	PSHOT_EVENT_NAME_DEV_OFFLINE	"pshot_dev_offline"
#define	PSHOT_EVENT_NAME_DEV_RESET	"pshot_dev_reset"
#define	PSHOT_EVENT_NAME_BUS_RESET	"pshot_bus_reset"
#define	PSHOT_EVENT_NAME_BUS_QUIESCE	"pshot_bus_quiesce"
#define	PSHOT_EVENT_NAME_BUS_UNQUIESCE	"pshot_bus_unquiesce"
#define	PSHOT_EVENT_NAME_BUS_TEST_POST	"pshot_bus_test_post"
#define	PSHOT_EVENT_NAME_DEBUG_SET	"pshot_debug_set"
#define	PSHOT_EVENT_NAME_SUB_RESET	"pshot_sub_reset"
						/* for hash sanity check */

#define	PSHOT_EVENT_TAG_OFFLINE		0
#define	PSHOT_EVENT_TAG_DEV_RESET	1
#define	PSHOT_EVENT_TAG_BUS_RESET	2
#define	PSHOT_EVENT_TAG_BUS_QUIESCE	3
#define	PSHOT_EVENT_TAG_BUS_UNQUIESCE	4
#define	PSHOT_EVENT_TAG_TEST_POST	5

typedef struct pshot_event_callback {
	dev_info_t			*dip;
	int				(*callback)();
	void				*arg;
	struct pshot_event_callback	*next;
} ps_callback_t;


static void pshot_event_cb(dev_info_t *dip, ddi_eventcookie_t cookie,
	void *arg, void *bus_impldata);

static int pshot_event(pshot_t *pshot, int event_tag, dev_info_t *child,
	void *bus_impldata);

#ifdef DEBUG
static void pshot_event_cb_test(dev_info_t *dip, ddi_eventcookie_t cookie,
    void *arg, void *bus_impldata);
static void pshot_event_test(void *arg);
static void pshot_event_test_post_one(void *arg);
#endif

/* event busops */
static int pshot_get_eventcookie(dev_info_t *dip, dev_info_t *rdip,
    char *name, ddi_eventcookie_t *event_cookiep);
static int pshot_add_eventcall(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t eventid, void (*callback)(), void *arg,
    ddi_callback_id_t *cb_id);
static int pshot_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id);
static int pshot_post_event(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t eventid, void *impl_data);

/* function prototypes */
static int pshot_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result);
static int pshot_initchild(dev_info_t *, dev_info_t *);
static int pshot_uninitchild(dev_info_t *, dev_info_t *);
static int pshot_bus_config(dev_info_t *, uint_t,
	ddi_bus_config_op_t, void *, dev_info_t **);
static int pshot_bus_unconfig(dev_info_t *, uint_t,
    ddi_bus_config_op_t, void *);
static int pshot_bus_config_setup_nexus(dev_info_t *, char *cname, char *caddr);
static int pshot_bus_config_setup_leaf(dev_info_t *, char *cname, char *caddr);
static int pshot_bus_config_test_specials(dev_info_t *parent,
	char *devname, char *cname, char *caddr);
static int pshot_bus_introp(dev_info_t *, dev_info_t *, ddi_intr_op_t,
	ddi_intr_handle_impl_t *, void *);

static void pshot_setup_autoattach(dev_info_t *);
static int pshot_bus_power(dev_info_t *dip, void *impl_arg,
	    pm_bus_power_op_t op, void *arg, void *result);
static void pshot_nexus_properties(dev_info_t *, dev_info_t *, char *, char *);
static void pshot_leaf_properties(dev_info_t *, dev_info_t *, char *, char *);


#endif /* _KERNEL */


#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PSHOT_H */
