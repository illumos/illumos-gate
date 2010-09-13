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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <libdevinfo.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <string.h>
#include <librcm.h>
#include <dlfcn.h>

#undef	NDEBUG
#include <assert.h>

typedef struct rio_path {
	char		rpt_path[PATH_MAX];
	struct rio_path	*rpt_next;
} rio_path_t;

typedef struct rcm_arg {
	char		*rcm_root;
	di_node_t	rcm_node;
	int		rcm_supp;
	rcm_handle_t	*rcm_handle;
	int		rcm_retcode;
	di_retire_t	*rcm_dp;
	rio_path_t	*rcm_cons_nodes;
	rio_path_t	*rcm_rsrc_minors;
	int		(*rcm_offline)();
	int		(*rcm_online)();
	int		(*rcm_remove)();
} rcm_arg_t;

typedef struct selector {
	char	*sel_name;
	int	(*sel_selector)(di_node_t node, rcm_arg_t *rp);
} di_selector_t;

static void rio_assert(di_retire_t *dp, const char *EXstr, int line,
    const char *file);

#define	LIBRCM_PATH	"/usr/lib/librcm.so"
#define	RIO_ASSERT(d, x)	\
		{if (!(x)) rio_assert(d, #x, __LINE__, __FILE__); }

static int disk_select(di_node_t node, rcm_arg_t *rp);
static int nexus_select(di_node_t node, rcm_arg_t *rp);
static int enclosure_select(di_node_t node, rcm_arg_t *rp);
static int smp_select(di_node_t node, rcm_arg_t *rp);

di_selector_t supported_devices[] = {
	{"disk",	disk_select},
	{"nexus",	nexus_select},
	{"enclosure",	enclosure_select},
	{"smp",		smp_select},
	{NULL, 		NULL}
};

void *
s_calloc(size_t nelem, size_t elsize, int fail)
{
	if (fail) {
		errno = ENOMEM;
		return (NULL);
	} else {
		return (calloc(nelem, elsize));
	}
}

static void
rio_assert(di_retire_t *dp, const char *EXstr, int line, const char *file)
{
	char	buf[PATH_MAX];

	if (dp->rt_abort == NULL)
		assert(0);

	(void) snprintf(buf, sizeof (buf),
	    "Assertion failed: %s, file %s, line %d\n",
	    EXstr, file, line);
	dp->rt_abort(dp->rt_hdl, buf);
}

/*ARGSUSED*/
static int
enclosure_minor(di_node_t node, di_minor_t minor, void *arg)
{
	rcm_arg_t *rp = (rcm_arg_t *)arg;
	di_retire_t *dp = rp->rcm_dp;

	rp->rcm_supp = 1;
	dp->rt_debug(dp->rt_hdl, "[INFO]: enclosure_minor: "
	    "IDed this node as enclosure\n");
	return (DI_WALK_TERMINATE);
}

static int
enclosure_select(di_node_t node, rcm_arg_t *rp)
{
	rcm_arg_t rarg;
	di_retire_t	*dp = rp->rcm_dp;

	rarg.rcm_dp = dp;

	/*
	 * Check if this is an enclosure minor. If any one minor is DDI_NT_SGEN
	 * or DDI_NT_SCSI_ENCLOSURE we assume it is an enclosure.
	 */
	rarg.rcm_supp = 0;
	if (di_walk_minor(node, DDI_NT_SCSI_ENCLOSURE, 0, &rarg,
	    enclosure_minor) != 0) {
		dp->rt_debug(dp->rt_hdl, "[INFO]: enclosure_select:"
		    "di_walk_minor failed. Returning NOTSUP\n");
		return (0);
	}
	if (di_walk_minor(node, "ddi_generic:scsi", 0, &rarg,
	    enclosure_minor) != 0) {
		dp->rt_debug(dp->rt_hdl, "[INFO]: enclosure_select:"
		    "di_walk_minor failed. Returning NOTSUP\n");
		return (0);
	}

	return (rarg.rcm_supp);
}

/*ARGSUSED*/
static int
smp_minor(di_node_t node, di_minor_t minor, void *arg)
{
	rcm_arg_t *rp = (rcm_arg_t *)arg;
	di_retire_t *dp = rp->rcm_dp;

	rp->rcm_supp = 1;
	dp->rt_debug(dp->rt_hdl, "[INFO]: smp_minor: "
	    "IDed this node as smp\n");
	return (DI_WALK_TERMINATE);
}

static int
smp_select(di_node_t node, rcm_arg_t *rp)
{
	rcm_arg_t rarg;
	di_retire_t	*dp = rp->rcm_dp;

	rarg.rcm_dp = dp;

	/*
	 * Check if this is an smp minor. If any one minor is DDI_NT_SMP
	 * we assume it is an smp.
	 */
	rarg.rcm_supp = 0;
	if (di_walk_minor(node, DDI_NT_SMP, 0, &rarg, smp_minor) != 0) {
		dp->rt_debug(dp->rt_hdl, "[INFO]: smp_select:"
		    "di_walk_minor failed. Returning NOTSUP\n");
		return (0);
	}

	return (rarg.rcm_supp);
}

/*ARGSUSED*/
static int
disk_minor(di_node_t node, di_minor_t minor, void *arg)
{
	rcm_arg_t *rp = (rcm_arg_t *)arg;
	di_retire_t *dp = rp->rcm_dp;

	if (di_minor_spectype(minor) == S_IFBLK) {
		rp->rcm_supp = 1;
		dp->rt_debug(dp->rt_hdl, "[INFO]: disk_minor: is disk minor. "
		    "IDed this node as disk\n");
		return (DI_WALK_TERMINATE);
	}

	dp->rt_debug(dp->rt_hdl, "[INFO]: disk_minor: Not a disk minor. "
	    "Continuing minor walk\n");
	return (DI_WALK_CONTINUE);
}

static int
disk_select(di_node_t node, rcm_arg_t *rp)
{
	rcm_arg_t rarg;
	di_retire_t	*dp = rp->rcm_dp;

	rarg.rcm_dp = dp;

	/*
	 * Check if this is a disk minor. If any one minor is DDI_NT_BLOCK
	 * we assume it is a disk
	 */
	rarg.rcm_supp = 0;
	if (di_walk_minor(node, DDI_NT_BLOCK, 0, &rarg, disk_minor) != 0) {
		dp->rt_debug(dp->rt_hdl, "[INFO]: disk_select: di_walk_minor "
		    "failed. Returning NOTSUP\n");
		return (0);
	}

	return (rarg.rcm_supp);
}

static int
nexus_select(di_node_t node, rcm_arg_t *rp)
{
	int select;
	char *path;

	di_retire_t *dp = rp->rcm_dp;

	path = di_devfs_path(node);
	if (path == NULL) {
		dp->rt_debug(dp->rt_hdl, "[INFO]: nexus_select: "
		    "di_devfs_path() is NULL. Returning NOTSUP\n");
		return (0);
	}

	/*
	 * Check if it is a nexus
	 */
	if (di_driver_ops(node) & DI_BUS_OPS) {
		dp->rt_debug(dp->rt_hdl, "[INFO]: nexus_select: is nexus %s\n",
		    path);
		select = 1;
	} else {
		dp->rt_debug(dp->rt_hdl, "[INFO]: nexus_select: not nexus %s\n",
		    path);
		select = 0;
	}

	di_devfs_path_free(path);

	return (select);
}

static int
node_select(di_node_t node, void *arg)
{
	rcm_arg_t *rp = (rcm_arg_t *)arg;
	di_retire_t *dp;
	int	sel;
	int	i;
	char	*path;
	uint_t	state;

	dp = rp->rcm_dp;

	/* skip pseudo nodes - we only retire real hardware */
	path = di_devfs_path(node);
	if (strncmp(path, "/pseudo/", strlen("/pseudo/")) == 0 ||
	    strcmp(path, "/pseudo") == 0) {
		dp->rt_debug(dp->rt_hdl, "[INFO]: node_select: "
		    "pseudo device in subtree - returning NOTSUP: %s\n",
		    path);
		rp->rcm_supp = 0;
		di_devfs_path_free(path);
		return (DI_WALK_TERMINATE);
	}
	di_devfs_path_free(path);

	/*
	 * If a device is offline/detached/down it is
	 * retireable irrespective of the type of device,
	 * presumably the system is able to function without
	 * it.
	 */
	state = di_state(node);
	if ((state & DI_DRIVER_DETACHED) || (state & DI_DEVICE_OFFLINE) ||
	    (state & DI_BUS_DOWN)) {
		dp->rt_debug(dp->rt_hdl, "[INFO]: node_select: device "
		    "is offline/detached. Assuming retire supported\n");
		return (DI_WALK_CONTINUE);
	}

	sel = 0;
	for (i = 0; supported_devices[i].sel_name != NULL; i++) {
		sel = supported_devices[i].sel_selector(node, rp);
		if (sel == 1) {
			dp->rt_debug(dp->rt_hdl, "[INFO]: node_select: "
			    "found supported device: %s\n",
			    supported_devices[i].sel_name);
			break;
		}
	}

	if (sel != 1) {
		/*
		 * This node is not a supported device. Retire cannot proceed
		 */
		dp->rt_debug(dp->rt_hdl, "[INFO]: node_select: found "
		    "unsupported device. Returning NOTSUP\n");
		rp->rcm_supp = 0;
		return (DI_WALK_TERMINATE);
	}

	/*
	 * This node is supported. Check other nodes in this subtree.
	 */
	dp->rt_debug(dp->rt_hdl, "[INFO]: node_select: This node supported. "
	    "Checking other nodes in subtree: %s\n", rp->rcm_root);
	return (DI_WALK_CONTINUE);
}



/*
 * when in doubt assume that retire is not supported for this device.
 */
static int
retire_supported(rcm_arg_t *rp)
{
	di_retire_t	*dp;
	di_node_t rnode = rp->rcm_node;

	dp = rp->rcm_dp;

	/*
	 * We should not be here if devinfo snapshot is NULL.
	 */
	RIO_ASSERT(dp, rnode != DI_NODE_NIL);

	/*
	 * Note: We initally set supported to 1, then walk the
	 * subtree rooted at devpath, allowing each node the
	 * opportunity to veto the support. We cannot do things
	 * the other way around i.e. assume "not supported" and
	 * let individual nodes indicate that they are supported.
	 * In the latter case, the supported flag would be set
	 * if any one node in the subtree was supported which is
	 * not what we want.
	 */
	rp->rcm_supp = 1;
	if (di_walk_node(rnode, DI_WALK_CLDFIRST, rp, node_select) != 0) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: retire_supported: "
		    "di_walk_node: failed. Returning NOTSUP\n");
		rp->rcm_supp = 0;
	}

	if (rp->rcm_supp) {
		dp->rt_debug(dp->rt_hdl, "[INFO]: retire IS supported\n");
	}

	return (rp->rcm_supp);
}

static void
rcm_finalize(rcm_arg_t *rp, int retcode)
{
	rio_path_t 	*p;
	rio_path_t 	*tmp;
	int		flags = RCM_RETIRE_NOTIFY;
	int		retval;
	int		error;
	di_retire_t	*dp;

	dp = rp->rcm_dp;

	RIO_ASSERT(dp, retcode == 0 || retcode == -1);

	dp->rt_debug(dp->rt_hdl, "[INFO]: rcm_finalize: retcode=%d: dev=%s\n",
	    retcode, rp->rcm_root);

	for (p = rp->rcm_cons_nodes; p; ) {
		tmp = p;
		p = tmp->rpt_next;
		free(tmp);
	}
	rp->rcm_cons_nodes = NULL;

	dp->rt_debug(dp->rt_hdl, "[INFO]: rcm_finalize: cons_nodes NULL\n");

	for (p = rp->rcm_rsrc_minors; p; ) {
		tmp = p;
		p = tmp->rpt_next;
		if (retcode == 0) {
			retval = rp->rcm_remove(rp->rcm_handle,
			    tmp->rpt_path, flags, NULL);
			error = errno;
		} else {
			RIO_ASSERT(dp, retcode == -1);
			retval = rp->rcm_online(rp->rcm_handle,
			    tmp->rpt_path, flags, NULL);
			error = errno;
		}
		if (retval != RCM_SUCCESS) {
			dp->rt_debug(dp->rt_hdl, "[ERROR]: rcm_finalize: "
			    "rcm_%s: retval=%d: error=%s: path=%s\n",
			    retcode == 0 ? "remove" : "online", retval,
			    strerror(error), tmp->rpt_path);
		} else {
			dp->rt_debug(dp->rt_hdl, "[INFO]: rcm_finalize: "
			    "rcm_%s: SUCCESS: path=%s\n",
			    retcode == 0 ? "remove" : "online", tmp->rpt_path);
		}
		free(tmp);
	}
	rp->rcm_rsrc_minors = NULL;
}
/*ARGSUSED*/
static int
call_offline(di_node_t node, di_minor_t minor, void *arg)
{
	rcm_arg_t	*rp = (rcm_arg_t *)arg;
	di_retire_t	*dp = rp->rcm_dp;
	char		*mnp;
	rio_path_t	*rpt;
	int		retval;

	mnp = di_devfs_minor_path(minor);
	if (mnp == NULL) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: di_devfs_minor_path "
		    "failed. Returning RCM FAILURE: %s\n", rp->rcm_root);
		rp->rcm_retcode = RCM_FAILURE;
		return (DI_WALK_TERMINATE);
	}

	rpt = s_calloc(1, sizeof (rio_path_t), 0);
	if (rpt == NULL) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: calloc failed. "
		    "Returning RCM FAILURE: %s\n", rp->rcm_root);
		di_devfs_path_free(mnp);
		rp->rcm_retcode = RCM_FAILURE;
		return (DI_WALK_TERMINATE);
	}

	(void) snprintf(rpt->rpt_path, sizeof (rpt->rpt_path),
	    "/devices%s", mnp);

	di_devfs_path_free(mnp);

	retval = rp->rcm_offline(rp->rcm_handle, rpt->rpt_path,
	    RCM_RETIRE_REQUEST, NULL);

	rpt->rpt_next = rp->rcm_rsrc_minors;
	rp->rcm_rsrc_minors = rpt;

	if (retval == RCM_FAILURE) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: RCM OFFLINE failed "
		    "for: %s\n", rpt->rpt_path);
		rp->rcm_retcode = RCM_FAILURE;
		return (DI_WALK_TERMINATE);
	} else if (retval == RCM_SUCCESS) {
		rp->rcm_retcode = RCM_SUCCESS;
		dp->rt_debug(dp->rt_hdl, "[INFO]: RCM OFFLINE returned "
		    "RCM_SUCCESS: %s\n", rpt->rpt_path);
	} else if (retval != RCM_NO_CONSTRAINT) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: RCM OFFLINE returned "
		    "invalid value for: %s\n", rpt->rpt_path);
		rp->rcm_retcode = RCM_FAILURE;
		return (DI_WALK_TERMINATE);
	} else {
		dp->rt_debug(dp->rt_hdl, "[INFO]: RCM OFFLINE returned "
		    "RCM_NO_CONSTRAINT: %s\n", rpt->rpt_path);
	}

	return (DI_WALK_CONTINUE);
}

static int
offline_one(di_node_t node, void *arg)
{
	rcm_arg_t 	*rp = (rcm_arg_t *)arg;
	rio_path_t	*rpt;
	di_retire_t	*dp = rp->rcm_dp;
	char		*path;

	/*
	 * We should already have terminated the walk
	 * in case of failure
	 */
	RIO_ASSERT(dp, rp->rcm_retcode == RCM_SUCCESS ||
	    rp->rcm_retcode == RCM_NO_CONSTRAINT);

	dp->rt_debug(dp->rt_hdl, "[INFO]: offline_one: entered\n");

	rp->rcm_retcode = RCM_NO_CONSTRAINT;

	rpt = s_calloc(1, sizeof (rio_path_t), 0);
	if (rpt == NULL) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: rio_path_t calloc "
		    "failed: error: %s\n", strerror(errno));
		goto fail;
	}

	path = di_devfs_path(node);
	if (path == NULL) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: di_devfs_path "
		    "failed: error: %s\n", strerror(errno));
		free(rpt);
		goto fail;
	}

	(void) strlcpy(rpt->rpt_path, path, sizeof (rpt->rpt_path));

	di_devfs_path_free(path);

	if (di_walk_minor(node, NULL, 0, rp, call_offline) != 0) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: di_walk_minor "
		    "failed: error: %s: %s\n", strerror(errno), path);
		free(rpt);
		goto fail;
	}

	if (rp->rcm_retcode == RCM_FAILURE) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: di_walk_minor "
		    "returned: RCM_FAILURE: %s\n", rpt->rpt_path);
		free(rpt);
		goto fail;
	} else if (rp->rcm_retcode == RCM_SUCCESS) {
		dp->rt_debug(dp->rt_hdl, "[INFO]: di_walk_minor "
		    "returned: RCM_SUCCESS: %s\n", rpt->rpt_path);
		rpt->rpt_next = rp->rcm_cons_nodes;
		rp->rcm_cons_nodes = rpt;
	} else if (rp->rcm_retcode != RCM_NO_CONSTRAINT) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: di_walk_minor "
		    "returned: unknown RCM error code: %d, %s\n",
		    rp->rcm_retcode, rpt->rpt_path);
		free(rpt);
		goto fail;
	} else {
		dp->rt_debug(dp->rt_hdl, "[INFO]: di_walk_minor "
		    "returned: RCM_NO_CONSTRAINT: %s\n", rpt->rpt_path);
		free(rpt);
	}

	/*
	 * RCM_SUCCESS or RCM_NO_CONSTRAINT.
	 * RCM_SUCCESS implies we overcame a constraint, so keep walking.
	 * RCM_NO_CONSTRAINT implies no constraints applied via RCM.
	 *	Continue walking in the hope that contracts or LDI will
	 * 	apply constraints
	 * set retcode to RCM_SUCCESS to show that at least 1 node
	 * completely walked
	 */
	rp->rcm_retcode = RCM_SUCCESS;
	return (DI_WALK_CONTINUE);

fail:
	rp->rcm_retcode = RCM_FAILURE;
	return (DI_WALK_TERMINATE);
}

/*
 * Returns:
 *	RCM_SUCCESS:  RCM constraints (if any) were applied. The
 *	device paths for which constraints were applied is passed
 *	back via the pp argument
 *
 *	RCM_FAILURE: Either RCM constraints prevent a retire or
 *	an error occurred
 */
static int
rcm_notify(rcm_arg_t *rp, char **pp, size_t *clen)
{
	size_t	len;
	rio_path_t *p;
	rio_path_t *tmp;
	char *plistp;
	char *s;
	di_retire_t *dp;
	di_node_t rnode;

	dp = rp->rcm_dp;

	dp->rt_debug(dp->rt_hdl, "[INFO]: rcm_notify() entered\n");

	RIO_ASSERT(dp, rp->rcm_root);

	*pp = NULL;

	rnode = rp->rcm_node;
	if (rnode == DI_NODE_NIL) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: devinfo snapshot "
		    "NULL. Returning no RCM constraint: %s\n", rp->rcm_root);
		return (RCM_NO_CONSTRAINT);
	}

	rp->rcm_retcode = RCM_NO_CONSTRAINT;
	rp->rcm_cons_nodes = NULL;
	rp->rcm_rsrc_minors = NULL;
	if (di_walk_node(rnode, DI_WALK_CLDFIRST, rp, offline_one) != 0) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: di_walk_node "
		    "failed: error: %s: %s\n", strerror(errno), rp->rcm_root);
		/* online is idempotent - safe to online non-offlined nodes */
		rcm_finalize(rp, -1);
		rp->rcm_retcode = RCM_FAILURE;
		goto out;
	}

	if (rp->rcm_retcode == RCM_FAILURE) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: walk_node "
		    "returned retcode of RCM_FAILURE: %s\n", rp->rcm_root);
		rcm_finalize(rp, -1);
		goto out;
	}

	if (rp->rcm_retcode == RCM_NO_CONSTRAINT) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: di_walk_node "
		    " - no nodes walked: RCM_NO_CONSTRAINT: %s\n",
		    rp->rcm_root);
	} else {
		dp->rt_debug(dp->rt_hdl, "[INFO]: walk_node: RCM_SUCCESS\n");
	}

	/*
	 * Convert to a sequence of NUL separated strings terminated by '\0'\0'
	 */
	for (len = 0, p = rp->rcm_cons_nodes; p; p = p->rpt_next) {
		RIO_ASSERT(dp, p->rpt_path);
		RIO_ASSERT(dp, strlen(p->rpt_path) > 0);
		len += (strlen(p->rpt_path) + 1);
	}
	len++;	/* list terminating '\0' */

	dp->rt_debug(dp->rt_hdl, "[INFO]: len of constraint str = %lu\n", len);

	plistp = s_calloc(1, len, 0);
	if (plistp == NULL) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: fail to alloc "
		    "constraint list: error: %s: %s\n", strerror(errno),
		    rp->rcm_root);
		rcm_finalize(rp, -1);
		rp->rcm_retcode = RCM_FAILURE;
		goto out;
	}

	for (s = plistp, p = rp->rcm_cons_nodes; p; ) {
		tmp = p;
		p = tmp->rpt_next;
		(void) strcpy(s, tmp->rpt_path);
		s += strlen(s) + 1;
		RIO_ASSERT(dp, s - plistp < len);
		free(tmp);
	}
	rp->rcm_cons_nodes = NULL;
	RIO_ASSERT(dp, s - plistp == len - 1);
	*s = '\0';

	dp->rt_debug(dp->rt_hdl, "[INFO]: constraint str = %p\n", plistp);

	*pp = plistp;
	*clen = len;

	rp->rcm_retcode = RCM_SUCCESS;
out:
	return (rp->rcm_retcode);
}


/*ARGSUSED*/
int
di_retire_device(char *devpath, di_retire_t *dp, int flags)
{
	char path[PATH_MAX];
	struct stat sb;
	int retval = EINVAL;
	char *constraint = NULL;
	size_t clen;
	void *librcm_hdl;
	rcm_arg_t rarg = {0};
	int (*librcm_alloc_handle)();
	int (*librcm_free_handle)();

	if (dp == NULL || dp->rt_debug == NULL || dp->rt_hdl == NULL)
		return (EINVAL);

	if (devpath == NULL || devpath[0] == '\0') {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: NULL argument(s)\n");
		return (EINVAL);
	}

	if (devpath[0] != '/' || strlen(devpath) >= PATH_MAX ||
	    strncmp(devpath, "/devices/", strlen("/devices/")) == 0 ||
	    strstr(devpath, "../devices/") || strrchr(devpath, ':')) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: invalid devpath: %s\n",
		    devpath);
		return (EINVAL);
	}

	if (flags != 0) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: flags should be 0: %d\n",
		    flags);
		return (EINVAL);
	}

	/*
	 * dlopen rather than link against librcm since libdevinfo
	 * resides in / and librcm resides in /usr. The dlopen is
	 * safe to do since fmd which invokes the retire code
	 * resides on /usr and will not come here until /usr is
	 * mounted.
	 */
	librcm_hdl = dlopen(LIBRCM_PATH, RTLD_LAZY);
	if (librcm_hdl == NULL) {
		char *errstr = dlerror();
		dp->rt_debug(dp->rt_hdl, "[ERROR]: Cannot dlopen librcm: %s\n",
		    errstr ? errstr : "Unknown error");
		return (ENOSYS);
	}

	librcm_alloc_handle = (int (*)())dlsym(librcm_hdl, "rcm_alloc_handle");
	rarg.rcm_offline = (int (*)())dlsym(librcm_hdl, "rcm_request_offline");
	rarg.rcm_online = (int (*)())dlsym(librcm_hdl, "rcm_notify_online");
	rarg.rcm_remove = (int (*)())dlsym(librcm_hdl, "rcm_notify_remove");
	librcm_free_handle = (int (*)())dlsym(librcm_hdl, "rcm_free_handle");

	if (librcm_alloc_handle == NULL ||
	    rarg.rcm_offline == NULL ||
	    rarg.rcm_online == NULL ||
	    rarg.rcm_remove == NULL ||
	    librcm_free_handle == NULL) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: dlsym failed\n");
		retval = ENOSYS;
		goto out;
	}

	/*
	 * Take a libdevinfo snapshot here because we cannot do so
	 * after device is retired. If device doesn't attach, we retire
	 * anyway i.e. it is not fatal.
	 */
	rarg.rcm_node = di_init(devpath, DINFOCPYALL);
	if (rarg.rcm_node == DI_NODE_NIL) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: device doesn't attach, "
		    "retiring anyway: %s\n", devpath);
	}

	rarg.rcm_handle = NULL;
	if (librcm_alloc_handle(NULL, 0,  NULL, &rarg.rcm_handle)
	    != RCM_SUCCESS) {
		retval = errno;
		dp->rt_debug(dp->rt_hdl, "[ERROR]: failed to alloc "
		    "RCM handle. Returning RCM failure: %s\n", devpath);
		rarg.rcm_handle = NULL;
		goto out;
	}

	rarg.rcm_root = devpath;
	rarg.rcm_dp = dp;

	/*
	 * If device is already detached/nonexistent and cannot be
	 * attached, allow retire without checking device type.
	 * XXX
	 * Else, check if retire is supported for this device type.
	 */
	(void) snprintf(path, sizeof (path), "/devices%s", devpath);
	if (stat(path, &sb) == -1 || !S_ISDIR(sb.st_mode)) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: detached or nonexistent "
		    "device. Bypassing retire_supported: %s\n", devpath);
	} else if (!retire_supported(&rarg)) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: retire not supported for "
		    "device type: %s\n", devpath);
		retval = ENOTSUP;
		goto out;
	}

	clen = 0;
	constraint = NULL;
	retval = rcm_notify(&rarg, &constraint, &clen);
	if (retval == RCM_FAILURE) {
		/* retire not permitted */
		dp->rt_debug(dp->rt_hdl, "[ERROR]: RCM constraints block "
		    "retire: %s\n", devpath);
		retval = EBUSY;
		goto out;
	} else if (retval == RCM_SUCCESS) {
		dp->rt_debug(dp->rt_hdl, "[INFO]: RCM constraints applied"
		    ": %s\n", devpath);
	} else if (retval == RCM_NO_CONSTRAINT) {
		dp->rt_debug(dp->rt_hdl, "[INFO]: No RCM constraints applied"
		    ": %s\n", devpath);
	} else {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: notify returned unknown "
		    "return code: %d: %s\n", retval, devpath);
		retval = ESRCH;
		goto out;
	}

	if (modctl(MODRETIRE, devpath, constraint, clen) != 0) {
		retval = errno;
		dp->rt_debug(dp->rt_hdl, "[ERROR]: retire modctl() failed: "
		    "%s: %s\n", devpath, strerror(retval));
		rcm_finalize(&rarg, -1);
		goto out;
	}

	dp->rt_debug(dp->rt_hdl, "[INFO]: retire modctl() succeeded: %s\n",
	    devpath);

	rcm_finalize(&rarg, 0);

	retval = 0;

out:
	if (rarg.rcm_handle)
		(void) librcm_free_handle(rarg.rcm_handle);

	RIO_ASSERT(dp, rarg.rcm_cons_nodes == NULL);
	RIO_ASSERT(dp, rarg.rcm_rsrc_minors == NULL);

	(void) dlclose(librcm_hdl);

	free(constraint);

	if (rarg.rcm_node != DI_NODE_NIL)
		di_fini(rarg.rcm_node);

	return (retval);
}

/*ARGSUSED*/
int
di_unretire_device(char *devpath, di_retire_t *dp)
{
	if (dp == NULL || dp->rt_debug == NULL || dp->rt_hdl == NULL)
		return (EINVAL);

	if (devpath == NULL || devpath[0] == '\0') {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: NULL devpath\n");
		return (EINVAL);
	}

	if (devpath[0] != '/' || strlen(devpath) >= PATH_MAX ||
	    strncmp(devpath, "/devices/", strlen("/devices/")) == 0 ||
	    strstr(devpath, "../devices/") || strrchr(devpath, ':')) {
		dp->rt_debug(dp->rt_hdl, "[ERROR]: invalid devpath: %s\n",
		    devpath);
		return (EINVAL);
	}

	if (modctl(MODUNRETIRE, devpath) != 0) {
		int err = errno;
		dp->rt_debug(dp->rt_hdl, "[ERROR]: unretire modctl() failed: "
		    "%s: %s\n", devpath, strerror(err));
		return (err);
	}

	dp->rt_debug(dp->rt_hdl, "[INFO]: unretire modctl() done: %s\n",
	    devpath);

	return (0);
}
