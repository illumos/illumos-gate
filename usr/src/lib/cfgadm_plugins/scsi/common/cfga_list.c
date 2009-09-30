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
	const char *pathname;
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
static char *get_device_type(di_node_t, dyncomp_t);
static void get_hw_info(di_node_t node, cfga_list_data_t *clp, dyncomp_t type);
static scfga_ret_t create_pathinfo_ldata(di_path_t pi_node, scfga_list_t *lap,
    int *l_errnop);


static scfga_devtype_t device_list[] = {
	{ DTYPE_DIRECT,	    DDI_NT_BLOCK_CHAN,	"disk",		"disk-path"},
	{ DTYPE_DIRECT,	    DDI_NT_BLOCK,	"disk",		"disk-path"},
	{ DTYPE_DIRECT,	    DDI_NT_BLOCK_WWN,	"disk",		"disk-path"},
	{ DTYPE_DIRECT,	    DDI_NT_BLOCK_FABRIC,    "disk",	"disk-path"},
	{ DTYPE_DIRECT,	    DDI_NT_BLOCK_SAS,   "disk",		"disk-path"},
	{ DTYPE_SEQUENTIAL, DDI_NT_TAPE,	"tape",		"tape-path"},
	{ DTYPE_PRINTER,    NULL,		"printer",	"printer-path"},
	{ DTYPE_PROCESSOR,  NULL,		"processor",	"PRCS-path"},
	{ DTYPE_WORM,	    NULL,		"WORM",		"WORM-path"},
	{ DTYPE_RODIRECT,   DDI_NT_CD_CHAN,	"CD-ROM",	"CD-ROM-path"},
	{ DTYPE_RODIRECT,   DDI_NT_CD,		"CD-ROM",	"CD-ROM-path"},
	{ DTYPE_SCANNER,    NULL,		"scanner",	"scanner-path"},
	{ DTYPE_OPTICAL,    NULL,		"optical",	"optical-path"},
	{ DTYPE_CHANGER,    NULL,		"med-changer",	"MEDCHGR-path"},
	{ DTYPE_COMM,	    NULL,		"comm-device",	"COMDEV-path"},
	{ DTYPE_ARRAY_CTRL, NULL,		"array-ctrl",	"ARRCTRL-path"},
	{ DTYPE_ESI,	    NULL,		"ESI",		"ESI-path"}
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
	if (apidp->dyntype == PATH_APID) {
		/*
		 * When cmd is SCFGA_STAT_DEV and the ap id is pathinfo
		 * related.
		 */
		ret = walk_tree(apidp->hba_phys, &larg, init_flag, NULL,
		    SCFGA_WALK_PATH, &larg.l_errno);
	} else {
		/* we need to stat at least 1 device for all commands */
		u.node_args.flags = DI_WALK_CLDFIRST;
		u.node_args.fcn = stat_dev;

		/*
		 * Subtree is ALWAYS rooted at the HBA (not at the device) as
		 * otherwise deadlock may occur if bus is disconnected.
		 */
		ret = walk_tree(apidp->hba_phys, &larg, init_flag, &u,
		    SCFGA_WALK_NODE, &larg.l_errno);

		/*
		 * Check path info on the following conditions.
		 *
		 * - chld_config is still set to CFGA_STAT_UNCONFIGURED for
		 *   SCFGA_STAT_BUS cmd after walking any child node.
		 * - walking node succeeded for SCFGA_STAT_ALL cmd(Continue on
		 *   stating path info node).
		 * - apid is pathinfo associated and larg.ret is still set to
		 *   SCFGA_APID_NOEXIST for SCFGA_STAT_DEV cmd.
		 */
		if (((cmd == SCFGA_STAT_BUS) &&
		    (larg.chld_config == CFGA_STAT_UNCONFIGURED)) ||
		    ((cmd == SCFGA_STAT_ALL) && (ret == SCFGA_OK))) {
			ret = walk_tree(apidp->hba_phys, &larg, init_flag, NULL,
			    SCFGA_WALK_PATH, &larg.l_errno);
		}
	}

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

/*
 * Create list date entry and add to ldata list.
 */
static scfga_ret_t
create_pathinfo_ldata(di_path_t pi_node, scfga_list_t *lap, int *l_errnop)
{
	ldata_list_t	*listp = NULL;
	cfga_list_data_t	*clp;
	di_node_t	client_node = DI_NODE_NIL;
	di_minor_t	minor;
	scfga_ret_t 	ret;
	di_path_state_t	pi_state;
	char		*dyncomp = NULL, *client_path = NULL;
	char		pathbuf[MAXPATHLEN], *client_devlink = NULL;
	int		match_minor;

	listp = calloc(1, sizeof (ldata_list_t));
	if (listp == NULL) {
		lap->l_errno = errno;
		return (SCFGA_LIB_ERR);
	}
	clp = &listp->ldata;
	ret = make_path_dyncomp(pi_node, &dyncomp, &lap->l_errno);
	if (ret != SCFGA_OK) {
		S_FREE(listp);
		return (ret);
	}

	client_node = di_path_client_node(pi_node);
	if (client_node == DI_NODE_NIL) {
		*l_errnop = errno;
		S_FREE(dyncomp);
		return (SCFGA_LIB_ERR);
	}

	/* Create logical and physical ap_id */
	(void) snprintf(clp->ap_log_id, sizeof (clp->ap_log_id), "%s%s%s",
	    lap->hba_logp, DYN_SEP, dyncomp);

	(void) snprintf(clp->ap_phys_id, sizeof (clp->ap_phys_id), "%s%s%s",
	    lap->apidp->hba_phys, DYN_SEP, dyncomp);

	S_FREE(dyncomp);

	/* ap class filled in by libcfgadm */
	clp->ap_class[0] = '\0';
	clp->ap_r_state = lap->hba_rstate;
	/* path info exist so set to configured. */
	clp->ap_o_state = CFGA_STAT_CONFIGURED;

	/* now fill up ap_info field with client dev link and instance #. */
	client_path = di_devfs_path(client_node);
	if (client_path) {
		/* get first minor node. */
		minor = di_minor_next(client_node, DI_MINOR_NIL);
		if (minor == DI_MINOR_NIL) {
			match_minor = 0;
			(void) snprintf(pathbuf, MAXPATHLEN, "%s:%s",
			    DEVICES_DIR, client_path);
		} else {
			match_minor = 1;
			(void) snprintf(pathbuf, MAXPATHLEN, "%s%s:%s",
			    DEVICES_DIR, client_path, di_minor_name(minor));
		}
		(void) physpath_to_devlink(pathbuf, &client_devlink, l_errnop,
		    match_minor);
		di_devfs_path_free(client_path);
	}

	if (client_devlink) {
		(void) snprintf(clp->ap_info, CFGA_INFO_LEN,
		    "%s: %s", "Client Device", client_devlink);
		S_FREE(client_devlink);
	}

	get_hw_info(client_node, clp, PATH_APID);

	if ((pi_state = di_path_state(pi_node)) == DI_PATH_STATE_OFFLINE) {
		clp->ap_o_state = CFGA_STAT_UNCONFIGURED;
	}

	if (pi_state == DI_PATH_STATE_FAULT) {
		clp->ap_cond = CFGA_COND_FAILED;
	} else {
		clp->ap_cond = CFGA_COND_UNKNOWN;
	}

	/* no way to determine state change */
	clp->ap_busy = 0;
	clp->ap_status_time = (time_t)-1;

	/* Link it in */
	listp->next = lap->listp;
	lap->listp = listp;

	return (SCFGA_OK);
}

/*
 * Routine to stat pathinfo nodes.
 *
 * No pathinfo founds returns a success.
 * When cmd is SCFGA_STAT_DEV, finds a matching pathinfo node and
 * and create ldata if found.
 * When cmd is SCFGA_STAT_ALL, create ldata for each pathinfo node.
 * When cmd is SCFGA_STAT_BUS, checks if any pathinfo exist.
 *
 * Return:
 *  0 for success
 *  -1 for failure.
 */
int
stat_path_info(
	di_node_t 	root,
	void		*arg,
	int 		*l_errnop)
{
	scfga_list_t	*lap = (scfga_list_t *)arg;
	di_path_t	pi_node;

	if (root == DI_NODE_NIL) {
		return (-1);
	}

	/*
	 * when there is no path_info node return SCFGA_OK.
	 */
	if (di_path_next_client(root, DI_PATH_NIL) == DI_PATH_NIL) {
		return (0);
	}

	if (lap->cmd == SCFGA_STAT_BUS) {
		lap->chld_config = CFGA_STAT_CONFIGURED;
		return (0);
	} else if (lap->cmd == SCFGA_STAT_DEV) {
		assert(lap->apidp->dyntype == PATH_APID);
		for (pi_node = di_path_next_client(root, DI_PATH_NIL); pi_node;
		    pi_node = di_path_next_client(root, pi_node)) {
			/*
			 * NOTE: apidt_create() validated pathinfo apid so
			 * the apid should have a valid format.
			 */

			/* check the length first. */
			if (strlen(di_path_bus_addr(pi_node)) !=
			    strlen(lap->apidp->dyncomp)) {
				continue;
			}

			/* check for full match. */
			if (strcmp(di_path_bus_addr(pi_node),
			    lap->apidp->dyncomp)) {
				continue;
			}

			/* found match, record information */
			if (create_pathinfo_ldata(pi_node, lap,
			    l_errnop) == SCFGA_OK) {
				lap->ret = SCFGA_OK;
				return (0);
			} else {
				return (-1);
			}
		}
	} else { /* cmd = STAT_ALL */
		/* set child config to configured */
		lap->chld_config = CFGA_STAT_CONFIGURED;
		for (pi_node = di_path_next_client(root, DI_PATH_NIL); pi_node;
		    pi_node = di_path_next_client(root, pi_node)) {
			/* continue on even if there is an error on one path. */
			(void) create_pathinfo_ldata(pi_node, lap, l_errnop);
		}
	}

	lap->ret = SCFGA_OK;
	return (0);

}

struct bus_state {
	int	b_state;
	int	b_retired;
	char	iconnect_type[16];
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
	int i;
	char itypelower[MAXNAMELEN];

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

	if (bstate.iconnect_type) {
		/*
		 * For SPI type, keep the existing SCFGA_BUS_TYPE.
		 * For other types, the ap type will be scsi-'interconnct-type'.
		 */
		if (strcmp(bstate.iconnect_type, "SPI") == 0) {
			(void) snprintf(clp->ap_type, sizeof (clp->ap_type),
			    "%s", SCFGA_BUS_TYPE);
		} else {
			for (i = 0; i < strlen(bstate.iconnect_type); i++) {
				itypelower[i] =
				    tolower(bstate.iconnect_type[i]);
			}
			itypelower[i] = '\0';
			(void) snprintf(clp->ap_type, sizeof (clp->ap_type),
			    "%s-%s", "scsi", itypelower);
		}
	}

	/* Link it in */
	listp->next = lap->listp;
	lap->listp = listp;

	return (SCFGA_OK);
}

static int
get_bus_state(di_node_t node, void *arg)
{
	struct bus_state *bsp = (struct bus_state *)arg;
	char *itype = NULL;

	bsp->b_state = di_state(node);
	bsp->b_retired = di_retired(node);
	(void) di_prop_lookup_strings(DDI_DEV_T_ANY,
	    node, "initiator-interconnect-type", &itype);
	if (itype != NULL) {
		(void) strlcpy(bsp->iconnect_type, itype, 16);
	} else {
		bsp->iconnect_type[0] = '\0';
	}

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

	get_hw_info(node, clp, DEV_APID);

	/* Link it in */
	listp->next = lap->listp;
	lap->listp = listp;

	return (SCFGA_OK);
}

/* fill in device type, vid, pid from properties */
static void
get_hw_info(di_node_t node, cfga_list_data_t *clp, dyncomp_t type)
{
	char *cp = NULL;
	char *inq_vid, *inq_pid;
	char client_inst[MAXNAMELEN];

	/*
	 * Fill in type information
	 */
	cp = (char *)get_device_type(node, type);
	if (cp == NULL) {
		cp = (char *)GET_MSG_STR(ERR_UNAVAILABLE);
	}
	(void) snprintf(clp->ap_type, sizeof (clp->ap_type), "%s", S_STR(cp));

	if (type == DEV_APID) {
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
	} else {
		if ((di_driver_name(node) != NULL) &&
		    (di_instance(node) != -1)) {
			if (clp->ap_info == NULL) {
				(void) snprintf(client_inst, MAXNAMELEN - 1,
				    "%s%d", di_driver_name(node),
				    di_instance(node));
				(void) snprintf(clp->ap_info, MAXNAMELEN - 1,
				    "Client Device: %s", client_inst);
			} else {
				(void) snprintf(client_inst, MAXNAMELEN - 1,
				    "(%s%d)", di_driver_name(node),
				    di_instance(node));
				(void) strlcat(clp->ap_info, client_inst,
				    CFGA_INFO_LEN);
			}
		}

	}
}

/*
 * Get dtype from "inquiry-device-type" property. If not present,
 * derive it from minor node type
 */
static char *
get_device_type(di_node_t node, dyncomp_t type)
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
				name = (type == DEV_APID) ?
				    (char *)device_list[i].name :
				    (char *)device_list[i].pathname;
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
					name = (type == DEV_APID) ?
					    (char *)device_list[i].name :
					    (char *)device_list[i].pathname;
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
	if (bus_di_state & (DI_BUS_QUIESCED | DI_BUS_DOWN))
		return (CFGA_STAT_DISCONNECTED);

	return (CFGA_STAT_CONNECTED);
}

/*
 * Convert device state to occupant state
 */
static cfga_stat_t
dev_devinfo_to_occupant_state(uint_t dev_di_state)
{
	if (dev_di_state & (DI_DEVICE_OFFLINE | DI_DEVICE_DOWN))
		return (CFGA_STAT_UNCONFIGURED);

	if (!(dev_di_state & DI_DRIVER_DETACHED))
		return (CFGA_STAT_CONFIGURED);

	return (CFGA_STAT_NONE);
}
