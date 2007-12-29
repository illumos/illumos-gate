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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "cfga_scsi.h"

/* Structure for walking the tree */
typedef struct {
	apid_t		*apidp;
	char		*hba_logp;
	ldata_list_t	*listp;
	scfga_cmd_t	cmd;
	cfga_stat_t	chld_config;
	cfga_stat_t	hba_rstate;
	scfga_ret_t	ret;
	int		l_errno;
} scfga_list_t;

typedef struct {
	uint_t itype;
	const char *ntype;
	const char *name;
} scfga_devtype_t;

/* The TYPE field is parseable and should not contain spaces */
#define	SCFGA_BUS_TYPE		"scsi-bus"

/* Function prototypes */
static scfga_ret_t postprocess_list_data(const ldata_list_t *listp,
    scfga_cmd_t cmd, cfga_stat_t chld_config, int *np);
static int stat_dev(di_node_t node, void *arg);
static scfga_ret_t do_stat_bus(scfga_list_t *lap, int limited_bus_stat);
static int get_bus_state(di_node_t node, void *arg);

static scfga_ret_t do_stat_dev(const di_node_t node, const char *nodepath,
    scfga_list_t *lap, int limited_dev_stat);
static cfga_stat_t bus_devinfo_to_recep_state(uint_t bus_di_state);
static cfga_stat_t dev_devinfo_to_occupant_state(uint_t dev_di_state);
static char *get_device_type(di_node_t);
static void get_hw_info(di_node_t node, cfga_list_data_t *clp);


static scfga_devtype_t device_list[] = {
	{ DTYPE_DIRECT,		DDI_NT_BLOCK_CHAN,	"disk"},
	{ DTYPE_DIRECT,		DDI_NT_BLOCK,		"disk"},
	{ DTYPE_DIRECT,		DDI_NT_BLOCK_WWN,	"disk"},
	{ DTYPE_DIRECT,		DDI_NT_BLOCK_FABRIC,	"disk"},
	{ DTYPE_SEQUENTIAL,	DDI_NT_TAPE,		"tape"},
	{ DTYPE_PRINTER,	NULL,			"printer"},
	{ DTYPE_PROCESSOR,	NULL,			"processor"},
	{ DTYPE_WORM,		NULL,			"WORM"},
	{ DTYPE_RODIRECT,	DDI_NT_CD_CHAN,		"CD-ROM"},
	{ DTYPE_RODIRECT,	DDI_NT_CD,		"CD-ROM"},
	{ DTYPE_SCANNER,	NULL,			"scanner"},
	{ DTYPE_OPTICAL,	NULL,			"optical"},
	{ DTYPE_CHANGER,	NULL,			"med-changer"},
	{ DTYPE_COMM,		NULL,			"comm-device"},
	{ DTYPE_ARRAY_CTRL,	NULL,			"array-ctrl"},
	{ DTYPE_ESI,		NULL,			"ESI"}
};

#define	N_DEVICE_TYPES	(sizeof (device_list) / sizeof (device_list[0]))

scfga_ret_t
do_list(
	apid_t *apidp,
	scfga_cmd_t cmd,
	ldata_list_t **llpp,
	int *nelemp,
	char **errstring)
{
	int n = -1, l_errno = 0, limited_bus_stat;
	walkarg_t u;
	scfga_list_t larg = {NULL};
	scfga_ret_t ret;
	int init_flag;

	assert(apidp->hba_phys != NULL && apidp->path != NULL);

	if (*llpp != NULL || *nelemp != 0) {
		return (SCFGA_ERR);
	}

	/* Create the HBA logid (also base component of logical ap_id) */
	ret = make_hba_logid(apidp->hba_phys, &larg.hba_logp, &l_errno);
	if (ret != SCFGA_OK) {
		cfga_err(errstring, l_errno, ERR_LIST, 0);
		return (SCFGA_ERR);
	}

	assert(larg.hba_logp != NULL);

	larg.cmd = cmd;
	larg.apidp = apidp;
	larg.hba_rstate = CFGA_STAT_NONE;


	/*
	 * For all list commands, the bus  and 1 or more devices
	 * needs to be stat'ed
	 */

	/*
	 * By default we use DINFOCACHE to get a "full" snapshot
	 * This much faster than DINFOFORCE which actually
	 * attaches devices. DINFOFORCE used only if caller
	 * explicitly requests it via a private option.
	 */
	init_flag = (apidp->flags & FLAG_USE_DIFORCE) ? DINFOFORCE : DINFOCACHE;
	limited_bus_stat = 0;

	switch (larg.cmd) {
		case SCFGA_STAT_DEV:
			limited_bus_stat = 1; /* We need only bus state */
			/*FALLTHRU*/
		case SCFGA_STAT_ALL:
			break;
		case SCFGA_STAT_BUS:
			/* limited_bus_stat = 0 and no DINFOCACHE/DINFOFORCE */
			init_flag = 0;
			break;
		default:
			cfga_err(errstring, EINVAL, ERR_LIST, 0);
			goto out;
	}

	/*
	 * DINFOCACHE implies DINFOCPYALL. DINFOCPYALL shouldn't
	 * be ORed with DINFOCACHE, else libdevinfo will return
	 * error
	 */
	if (init_flag != DINFOCACHE)
		init_flag |= DINFOCPYALL;

	if ((ret = do_stat_bus(&larg, limited_bus_stat)) != SCFGA_OK) {
		cfga_err(errstring, larg.l_errno, ERR_LIST, 0);
		goto out;
	}

#ifdef DEBUG
	if (limited_bus_stat) {
		assert(larg.listp == NULL);
	} else {
		assert(larg.listp != NULL);
	}
#endif

	/* Assume that the bus has no configured children */
	larg.chld_config = CFGA_STAT_UNCONFIGURED;

	/*
	 * If stat'ing a specific device, we don't know if it exists yet.
	 * If stat'ing a bus or a bus and child devices, we have at least the
	 * bus stat data at this point.
	 */
	if (larg.cmd == SCFGA_STAT_DEV) {
		larg.ret = SCFGA_APID_NOEXIST;
	} else {
		larg.ret = SCFGA_OK;
	}

	/* we need to stat at least 1 device for all commands */
	u.node_args.flags = DI_WALK_CLDFIRST;
	u.node_args.fcn = stat_dev;

	/*
	 * Subtree is ALWAYS rooted at the HBA (not at the device) as
	 * otherwise deadlock may occur if bus is disconnected.
	 */
	ret = walk_tree(apidp->hba_phys, &larg, init_flag, &u,
	    SCFGA_WALK_NODE, &larg.l_errno);

	if (ret != SCFGA_OK || (ret = larg.ret) != SCFGA_OK) {
		if (ret != SCFGA_APID_NOEXIST) {
			cfga_err(errstring, larg.l_errno, ERR_LIST, 0);
		}
		goto out;
	}

	assert(larg.listp != NULL);

	n = 0;
	ret = postprocess_list_data(larg.listp, cmd, larg.chld_config, &n);
	if (ret != SCFGA_OK) {
		cfga_err(errstring, 0, ERR_LIST, 0);
		ret = SCFGA_LIB_ERR;
		goto out;
	}

	*nelemp = n;
	*llpp = larg.listp;
	ret = SCFGA_OK;
	/* FALLTHROUGH */
out:
	if (ret != SCFGA_OK) list_free(&larg.listp);
	S_FREE(larg.hba_logp);
	return (ret);
}

static scfga_ret_t
postprocess_list_data(
	const ldata_list_t *listp,
	scfga_cmd_t cmd,
	cfga_stat_t chld_config,
	int *np)
{
	ldata_list_t *tmplp = NULL;
	cfga_list_data_t *hba_ldatap = NULL;
	int i;


	*np = 0;

	if (listp == NULL) {
		return (SCFGA_ERR);
	}

	hba_ldatap = NULL;
	tmplp = (ldata_list_t *)listp;
	for (i = 0; tmplp != NULL; tmplp = tmplp->next) {
		i++;
		if (GET_DYN(tmplp->ldata.ap_phys_id) == NULL) {
			/* A bus stat data */
			assert(GET_DYN(tmplp->ldata.ap_log_id) == NULL);
			hba_ldatap = &tmplp->ldata;
#ifdef DEBUG
		} else {
			assert(GET_DYN(tmplp->ldata.ap_log_id) != NULL);
#endif
		}
	}

	switch (cmd) {
	case SCFGA_STAT_DEV:
		if (i != 1 || hba_ldatap != NULL) {
			return (SCFGA_LIB_ERR);
		}
		break;
	case SCFGA_STAT_BUS:
		if (i != 1 || hba_ldatap == NULL) {
			return (SCFGA_LIB_ERR);
		}
		break;
	case SCFGA_STAT_ALL:
		if (i < 1 || hba_ldatap == NULL) {
			return (SCFGA_LIB_ERR);
		}
		break;
	default:
		return (SCFGA_LIB_ERR);
	}

	*np = i;

	/* Fill in the occupant (child) state. */
	if (hba_ldatap != NULL) {
		hba_ldatap->ap_o_state = chld_config;
	}
	return (SCFGA_OK);
}

static int
stat_dev(di_node_t node, void *arg)
{
	scfga_list_t *lap = NULL;
	char *devfsp = NULL, *nodepath = NULL;
	size_t len = 0;
	int limited_dev_stat = 0, match_minor, rv;
	scfga_ret_t ret;

	lap = (scfga_list_t *)arg;

	/* Skip stub nodes */
	if (IS_STUB_NODE(node)) {
		return (DI_WALK_CONTINUE);
	}

	/* Skip partial nodes */
	if (!known_state(node)) {
		return (DI_WALK_CONTINUE);
	}

	devfsp = di_devfs_path(node);
	if (devfsp == NULL) {
		rv = DI_WALK_CONTINUE;
		goto out;
	}

	len = strlen(DEVICES_DIR) + strlen(devfsp) + 1;

	nodepath = calloc(1, len);
	if (nodepath == NULL) {
		lap->l_errno = errno;
		lap->ret = SCFGA_LIB_ERR;
		rv = DI_WALK_TERMINATE;
		goto out;
	}

	(void) snprintf(nodepath, len, "%s%s", DEVICES_DIR, devfsp);

	/* Skip node if it is HBA */
	match_minor = 0;
	if (!dev_cmp(lap->apidp->hba_phys, nodepath, match_minor)) {
		rv = DI_WALK_CONTINUE;
		goto out;
	}

	/* If stat'ing a specific device, is this that device */
	if (lap->cmd == SCFGA_STAT_DEV) {
		assert(lap->apidp->path != NULL);
		if (dev_cmp(lap->apidp->path, nodepath, match_minor)) {
			rv = DI_WALK_CONTINUE;
			goto out;
		}
	}

	/*
	 * If stat'ing a bus only, we look at device nodes only to get
	 * bus configuration status. So a limited stat will suffice.
	 */
	if (lap->cmd == SCFGA_STAT_BUS) {
		limited_dev_stat = 1;
	} else {
		limited_dev_stat = 0;
	}

	/*
	 * Ignore errors if stat'ing a bus or listing all
	 */
	ret = do_stat_dev(node, nodepath, lap, limited_dev_stat);
	if (ret != SCFGA_OK) {
		if (lap->cmd == SCFGA_STAT_DEV) {
			lap->ret = ret;
			rv = DI_WALK_TERMINATE;
		} else {
			rv = DI_WALK_CONTINUE;
		}
		goto out;
	}

	/* Are we done ? */
	rv = DI_WALK_CONTINUE;
	if (lap->cmd == SCFGA_STAT_BUS &&
	    lap->chld_config == CFGA_STAT_CONFIGURED) {
		rv = DI_WALK_TERMINATE;
	} else if (lap->cmd == SCFGA_STAT_DEV) {
		/*
		 * If stat'ing a specific device, we are done at this point.
		 */
		lap->ret = SCFGA_OK;
		rv = DI_WALK_TERMINATE;
	}

	/*FALLTHRU*/
out:
	S_FREE(nodepath);
	if (devfsp != NULL) di_devfs_path_free(devfsp);
	return (rv);
}


struct bus_state {
	int	b_state;
	int	b_retired;
};

static scfga_ret_t
do_stat_bus(scfga_list_t *lap, int limited_bus_stat)
{
	cfga_list_data_t *clp = NULL;
	ldata_list_t *listp = NULL;
	int l_errno = 0;
	struct bus_state bstate = {0};
	walkarg_t u;
	scfga_ret_t ret;

	assert(lap->hba_logp != NULL);

	/* Get bus state */
	u.node_args.flags = 0;
	u.node_args.fcn = get_bus_state;

	ret = walk_tree(lap->apidp->hba_phys, &bstate, DINFOPROP, &u,
	    SCFGA_WALK_NODE, &l_errno);
	if (ret == SCFGA_OK) {
		lap->hba_rstate = bus_devinfo_to_recep_state(bstate.b_state);
	} else {
		lap->hba_rstate = CFGA_STAT_NONE;
	}

	if (limited_bus_stat) {
		/* We only want to know bus(receptacle) connect status */
		return (SCFGA_OK);
	}

	listp = calloc(1, sizeof (ldata_list_t));
	if (listp == NULL) {
		lap->l_errno = errno;
		return (SCFGA_LIB_ERR);
	}

	clp = &listp->ldata;

	(void) snprintf(clp->ap_log_id, sizeof (clp->ap_log_id), "%s",
	    lap->hba_logp);
	(void) snprintf(clp->ap_phys_id, sizeof (clp->ap_phys_id), "%s",
	    lap->apidp->hba_phys);

	clp->ap_class[0] = '\0';	/* Filled by libcfgadm */
	clp->ap_r_state = lap->hba_rstate;
	clp->ap_o_state = CFGA_STAT_NONE; /* filled in later by the plug-in */
	clp->ap_cond =
	    (bstate.b_retired) ? CFGA_COND_FAILED : CFGA_COND_UNKNOWN;
	clp->ap_busy = 0;
	clp->ap_status_time = (time_t)-1;
	clp->ap_info[0] = '\0';

	(void) snprintf(clp->ap_type, sizeof (clp->ap_type), "%s",
	    SCFGA_BUS_TYPE);

	/* Link it in */
	listp->next = lap->listp;
	lap->listp = listp;

	return (SCFGA_OK);
}

static int
get_bus_state(di_node_t node, void *arg)
{
	struct bus_state *bsp = (struct bus_state *)arg;

	bsp->b_state = di_state(node);
	bsp->b_retired = di_retired(node);

	return (DI_WALK_TERMINATE);
}

static scfga_ret_t
do_stat_dev(
	const di_node_t node,
	const char *nodepath,
	scfga_list_t *lap,
	int limited_dev_stat)
{
	uint_t devinfo_state = 0;
	char *dyncomp = NULL;
	cfga_list_data_t *clp = NULL;
	ldata_list_t *listp = NULL;
	cfga_stat_t ostate;
	scfga_ret_t ret;

	assert(lap->apidp->hba_phys != NULL);
	assert(lap->hba_logp != NULL);

	devinfo_state = di_state(node);
	ostate = dev_devinfo_to_occupant_state(devinfo_state);

	/* If child device is configured, record it */
	if (ostate == CFGA_STAT_CONFIGURED) {
		lap->chld_config = CFGA_STAT_CONFIGURED;
	}

	if (limited_dev_stat) {
		/* We only want to know device config state */
		return (SCFGA_OK);
	}

	listp = calloc(1, sizeof (ldata_list_t));
	if (listp == NULL) {
		lap->l_errno = errno;
		return (SCFGA_LIB_ERR);
	}

	clp = &listp->ldata;

	/* Create the dynamic component */
	ret = make_dyncomp(node, nodepath, &dyncomp, &lap->l_errno);
	if (ret != SCFGA_OK) {
		S_FREE(listp);
		return (ret);
	}

	assert(dyncomp != NULL);

	/* Create logical and physical ap_id */
	(void) snprintf(clp->ap_log_id, sizeof (clp->ap_log_id), "%s%s%s",
	    lap->hba_logp, DYN_SEP, dyncomp);

	(void) snprintf(clp->ap_phys_id, sizeof (clp->ap_phys_id), "%s%s%s",
	    lap->apidp->hba_phys, DYN_SEP, dyncomp);

	S_FREE(dyncomp);

	clp->ap_class[0] = '\0'; /* Filled in by libcfgadm */
	clp->ap_r_state = lap->hba_rstate;
	clp->ap_o_state = ostate;
	clp->ap_cond = di_retired(node) ? CFGA_COND_FAILED : CFGA_COND_UNKNOWN;
	clp->ap_busy = 0; /* no way to determine state change */
	clp->ap_status_time = (time_t)-1;

	get_hw_info(node, clp);

	/* Link it in */
	listp->next = lap->listp;
	lap->listp = listp;

	return (SCFGA_OK);
}

/* fill in device type, vid, pid from properties */
static void
get_hw_info(di_node_t node, cfga_list_data_t *clp)
{
	char *cp = NULL;
	char *inq_vid, *inq_pid;

	/*
	 * Fill in type information
	 */
	cp = (char *)get_device_type(node);
	if (cp == NULL) {
		cp = (char *)GET_MSG_STR(ERR_UNAVAILABLE);
	}
	(void) snprintf(clp->ap_type, sizeof (clp->ap_type), "%s", S_STR(cp));

	/*
	 * Fill in vendor and product ID.
	 */
	if ((di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    "inquiry-product-id", &inq_pid) == 1) &&
	    (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    "inquiry-vendor-id", &inq_vid) == 1)) {
		(void) snprintf(clp->ap_info, sizeof (clp->ap_info),
		    "%s %s", inq_vid, inq_pid);
	}
}

/*
 * Get dtype from "inquiry-device-type" property. If not present,
 * derive it from minor node type
 */
static char *
get_device_type(di_node_t node)
{
	char *name = NULL;
	int *inq_dtype;
	int i;

	if (di_prop_find(DDI_DEV_T_ANY, node, "smp-device") != DI_PROP_NIL) {
		return ("smp");
	}

	/* first, derive type based on inquiry property */
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "inquiry-device-type",
	    &inq_dtype) == 1) {
		int itype = (*inq_dtype) & DTYPE_MASK;

		for (i = 0; i < N_DEVICE_TYPES; i++) {
			if (device_list[i].itype == DTYPE_UNKNOWN)
				continue;
			if (itype == device_list[i].itype) {
				name = (char *)device_list[i].name;
				break;
			}
		}
	}

	/* if property fails, use minor nodetype */
	if (name == NULL) {
		char *nodetype;
		di_minor_t minor = di_minor_next(node, DI_MINOR_NIL);

		if ((minor != DI_MINOR_NIL) &&
		    ((nodetype = di_minor_nodetype(minor)) != NULL)) {
			for (i = 0; i < N_DEVICE_TYPES; i++) {
				if (device_list[i].ntype &&
				    (strcmp(nodetype, device_list[i].ntype)
				    == 0)) {
					name = (char *)device_list[i].name;
					break;
				}
			}
		}
	}

	if (name == NULL)	/* default to unknown */
		name = "unknown";
	return (name);
}

/* Transform linked list into an array */
scfga_ret_t
list_ext_postprocess(
	ldata_list_t		**llpp,
	int			nelem,
	cfga_list_data_t	**ap_id_list,
	int			*nlistp,
	char			**errstring)
{
	cfga_list_data_t *ldatap = NULL;
	ldata_list_t *tmplp = NULL;
	int i = -1;

	*ap_id_list = NULL;
	*nlistp = 0;

	if (*llpp == NULL || nelem < 0) {
		return (SCFGA_LIB_ERR);
	}

	if (nelem == 0) {
		return (SCFGA_APID_NOEXIST);
	}

	ldatap = calloc(nelem, sizeof (cfga_list_data_t));
	if (ldatap == NULL) {
		cfga_err(errstring, errno, ERR_LIST, 0);
		return (SCFGA_LIB_ERR);
	}

	/* Extract the list_data structures from the linked list */
	tmplp = *llpp;
	for (i = 0; i < nelem && tmplp != NULL; i++) {
		ldatap[i] = tmplp->ldata;
		tmplp = tmplp->next;
	}

	if (i < nelem || tmplp != NULL) {
		S_FREE(ldatap);
		return (SCFGA_LIB_ERR);
	}

	*nlistp = nelem;
	*ap_id_list = ldatap;

	return (SCFGA_OK);
}

/*
 * Convert bus state to receptacle state
 */
static cfga_stat_t
bus_devinfo_to_recep_state(uint_t bus_di_state)
{
	cfga_stat_t rs;

	switch (bus_di_state) {
	case DI_BUS_QUIESCED:
	case DI_BUS_DOWN:
		rs = CFGA_STAT_DISCONNECTED;
		break;
	/*
	 * NOTE: An explicit flag for active should probably be added to
	 * libdevinfo.
	 */
	default:
		rs = CFGA_STAT_CONNECTED;
		break;
	}

	return (rs);
}

/*
 * Convert device state to occupant state
 */
static cfga_stat_t
dev_devinfo_to_occupant_state(uint_t dev_di_state)
{
	/* Driver attached ? */
	if ((dev_di_state & DI_DRIVER_DETACHED) != DI_DRIVER_DETACHED) {
		return (CFGA_STAT_CONFIGURED);
	}

	if ((dev_di_state & DI_DEVICE_OFFLINE) == DI_DEVICE_OFFLINE ||
	    (dev_di_state & DI_DEVICE_DOWN) == DI_DEVICE_DOWN) {
		return (CFGA_STAT_UNCONFIGURED);
	} else {
		return (CFGA_STAT_NONE);
	}
}
