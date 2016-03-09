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

/*
 * Implementation of ri_init routine for obtaining mapping
 * of system board attachment points to physical devices and to
 * the Reconfiguration Coordination Manager (RCM) client usage
 * of these devices.
 */
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <kstat.h>
#include <sys/param.h>
#include <sys/sbd_ioctl.h>
#include "rsrc_info_impl.h"

/*
 * Occupant types exported by cfgadm sbd plugin via
 * config_admin(3CFGADM).
 */
#define	SBD_CM_CPU	"cpu"
#define	SBD_CM_MEM	"memory"
#define	SBD_CM_IO	"io"

/*
 * RCM abstract resource names.
 */
#define	RCM_MEM_ALL	"SUNW_memory"
#define	RCM_CPU_ALL	"SUNW_cpu"
#define	RCM_CPU		RCM_CPU_ALL"/cpu"

#define	KBYTE		1024
#define	MBYTE		1048576
#define	USAGE_ALLOC_SIZE	128

/*
 * define to allow io_cm_info to return NODE is NULL to ri_init,
 * in order to skip over nodes w/unattached drivers
 */
#define	RI_NODE_NIL	1

/*
 * This code is CMP aware as it parses the
 * cfgadm info field for individual cpuids.
 */
#define	CPUID_SEP	","
#define	CPU_INFO_FMT	"cpuid=%s speed=%d ecache=%d"

typedef struct {
	cfga_list_data_t *cfga_list_data;
	int		nlist;
} apd_t;

typedef struct {
	long		pagesize;
	long		syspages;
	long		sysmb;
} mem_stat_t;

#define	ms_syspages	m_stat.syspages
#define	ms_pagesize	m_stat.pagesize
#define	ms_sysmb	m_stat.sysmb

typedef int32_t		cpuid_t;

typedef struct {
	int	cpuid_max;	/* maximum cpuid value */
	int	ecache_curr;	/* cached during tree walk */
	int	*ecache_sizes;	/* indexed by cpuid */
} ecache_info_t;

typedef struct {
	rcm_handle_t	*hdl;
	rcm_info_t	*offline_query_info;
	char		**rlist;
	int		nrlist;
	cpuid_t		*cpus;
	int		ncpus;
	int		ndevs;
	uint_t		query_pages;
	mem_stat_t	m_stat;
	ecache_info_t	ecache_info;
} rcmd_t;

typedef struct {
	const char	*rsrc;
	const char	*info;
} usage_t;

/* Lookup table entry for matching IO devices to RCM resource usage */
typedef struct {
	int		index;		/* index into the table array */
	di_node_t	node;		/* associated devinfo node */
	char		*name;		/* device full path name */
	int		n_usage;
	usage_t		*usage;
} lookup_entry_t;

typedef struct {
	int		n_entries;
	int		n_slots;
	lookup_entry_t	*table;
} lookup_table_t;

typedef struct {
	int			err;
	di_node_t		node;
	char			*pathbuf;
	lookup_table_t		*table;
	di_devlink_handle_t	linkhd;
} devinfo_arg_t;

static int dyn_ap_ids(char *, cfga_list_data_t **, int *);
static int rcm_init(rcmd_t *, apd_t [], int, int);
static void rcm_fini(rcmd_t *);
static int rcm_query_init(rcmd_t *, apd_t [], int);
static int cap_request(ri_hdl_t *, rcmd_t *);
static int syscpus(cpuid_t **, int *);
static int cpu_cap_request(ri_hdl_t *, rcmd_t *);
static int mem_cap_request(ri_hdl_t *, rcmd_t *);
static int (*cm_rcm_qpass_func(cfga_type_t))(cfga_list_data_t *, rcmd_t *);
static int cpu_rcm_qpass(cfga_list_data_t *, rcmd_t *);
static int mem_rcm_qpass(cfga_list_data_t *, rcmd_t *);
static int io_rcm_qpass(cfga_list_data_t *, rcmd_t *);
static int (*cm_info_func(cfga_type_t))(ri_ap_t *, cfga_list_data_t *, int,
    rcmd_t *);
static int cpu_cm_info(ri_ap_t *, cfga_list_data_t *, int, rcmd_t *);
static int i_cpu_cm_info(processorid_t, int, int, ri_ap_t *, rcmd_t *);
static int mem_cm_info(ri_ap_t *, cfga_list_data_t *, int, rcmd_t *);
static int io_cm_info(ri_ap_t *, cfga_list_data_t *, int, rcmd_t *);
static int ident_leaf(di_node_t);
static int mk_drv_inst(di_node_t, char [], char *);
static int devinfo_node_walk(di_node_t, void *);
static int devinfo_minor_walk(di_node_t, di_minor_t, void *);
static int devinfo_devlink_walk(di_devlink_t, void *);
static int add_rcm_clients(ri_client_t **, rcmd_t *, rcm_info_t *, int, int *);
static int rcm_ignore(char *, char *);
static int add_query_state(rcmd_t *, ri_client_t *, const char *, const char *);
static int state2query(int);
static void dev_list_append(ri_dev_t **, ri_dev_t *);
static void dev_list_cpu_insert(ri_dev_t **, ri_dev_t *, processorid_t);
static rcm_info_tuple_t *tuple_lookup(rcmd_t *, const char *, const char *);
static ri_ap_t *ri_ap_alloc(char *, ri_hdl_t *);
static ri_dev_t *ri_dev_alloc(void);
static ri_dev_t *io_dev_alloc(char *);
static ri_client_t *ri_client_alloc(char *, char *);
static void apd_tbl_free(apd_t [], int);
static char *pstate2str(int);
static int ecache_info_init(ecache_info_t *);
static int find_cpu_nodes(di_node_t, void *);
static int prop_lookup_int(di_node_t, di_prom_handle_t, char *, int **);
static int add_lookup_entry(lookup_table_t *, const char *, di_node_t);
static int table_compare_names(const void *, const void *);
static int table_compare_indices(const void *, const void *);
static lookup_entry_t *lookup(lookup_table_t *table, const char *);
static int add_usage(lookup_entry_t *, const char *, rcm_info_tuple_t *);
static void empty_table(lookup_table_t *);

#ifdef DEBUG
static void		dump_apd_tbl(FILE *, apd_t *, int);
#endif /* DEBUG */

static struct {
	char	*type;
	int	(*cm_info)(ri_ap_t *, cfga_list_data_t *, int, rcmd_t *);
	int	(*cm_rcm_qpass)(cfga_list_data_t *, rcmd_t *);
} cm_ctl[] = {
	{SBD_CM_CPU,	cpu_cm_info,	cpu_rcm_qpass},
	{SBD_CM_MEM,	mem_cm_info,	mem_rcm_qpass},
	{SBD_CM_IO,	io_cm_info,	io_rcm_qpass}
};

/*
 * Table of known info string prefixes for RCM modules that do not
 * represent actual resource usage, but instead provide name translations
 * or sequencing within the RCM namespace. Since RCM provides no way to
 * filter these out, we must maintain this hack.
 */
static char *rcm_info_filter[] = {
	"Network interface",		/* Network naming module */
	NULL
};


/*
 * Allocate snapshot handle.
 */
int
ri_init(int n_apids, char **ap_ids, int flags, ri_hdl_t **hdlp)
{
	int			i, j;
	ri_hdl_t		*ri_hdl;
	ri_ap_t			*ap_hdl;
	rcmd_t			*rcm = NULL;
	cfga_list_data_t	*cfga_ldata;
	apd_t			*apd, *apd_tbl = NULL;
	int			(*cm_info)(ri_ap_t *, cfga_list_data_t *,
				    int, rcmd_t *);
	int			rv = RI_SUCCESS;
	int			cm_info_rv;

	if (n_apids <= 0 || ap_ids == NULL || hdlp == NULL)
		return (RI_INVAL);

	if (flags & ~RI_REQ_MASK)
		return (RI_NOTSUP);

	*hdlp = NULL;
	if ((ri_hdl = calloc(1, sizeof (*ri_hdl))) == NULL ||
	    (rcm = calloc(1, sizeof (*rcm))) == NULL ||
	    (apd_tbl = calloc(n_apids, sizeof (*apd_tbl))) == NULL) {
		dprintf((stderr, "calloc: %s\n", strerror(errno)));
		rv = RI_FAILURE;
		goto out;
	}

	/*
	 * Create mapping of boards to components.
	 */
	for (i = 0, apd = apd_tbl; i < n_apids; i++, apd++) {
		if (dyn_ap_ids(ap_ids[i], &apd->cfga_list_data,
		    &apd->nlist) == -1) {
			rv = RI_INVAL;
			goto out;
		}
	}
#ifdef DEBUG
	dump_apd_tbl(stderr, apd_tbl, n_apids);
#endif /* DEBUG */

	if (rcm_init(rcm, apd_tbl, n_apids, flags) != 0) {
		rv = RI_FAILURE;
		goto out;
	}

	/*
	 * Best effort attempt to read cpu ecache sizes from
	 * OBP/Solaris device trees. These are later looked up
	 * in i_cpu_cm_info().
	 */
	(void) ecache_info_init(&rcm->ecache_info);

	for (i = 0, apd = apd_tbl; i < n_apids; i++, apd++) {
		if ((ap_hdl = ri_ap_alloc(ap_ids[i], ri_hdl)) == NULL) {
			rv = RI_FAILURE;
			goto out;
		}

		/*
		 * Add component info based on occupant type. Note all
		 * passes through the apd table skip over the first
		 * cfgadm_list_data entry, which is the static system board
		 * attachment point.
		 */
		for (j = 1, cfga_ldata = &apd->cfga_list_data[1];
		    j < apd->nlist; j++, cfga_ldata++) {
			if (cfga_ldata->ap_o_state != CFGA_STAT_CONFIGURED) {
				continue;
			}

			if ((cm_info =
			    cm_info_func(cfga_ldata->ap_type)) != NULL) {
				cm_info_rv =
				    (*cm_info)(ap_hdl, cfga_ldata, flags, rcm);
				if (cm_info_rv != 0) {
					/*
					 * If we cannot obtain info for the ap,
					 * skip it and do not fail the entire
					 * operation.  This case occurs when the
					 * driver for a device is not attached:
					 * di_init() returns failed back to
					 * io_cm_info().
					 */
					if (cm_info_rv == RI_NODE_NIL)
						continue;
					else {
						rv = RI_FAILURE;
						goto out;
					}
				}
			}
		}
	}

	if ((flags & RI_INCLUDE_QUERY) && cap_request(ri_hdl, rcm) != 0)
		rv = RI_FAILURE;

out:
	if (apd_tbl != NULL)
		apd_tbl_free(apd_tbl, n_apids);
	if (rcm != NULL)
		rcm_fini(rcm);

	if (rv == RI_SUCCESS)
		*hdlp = ri_hdl;
	else
		ri_fini(ri_hdl);

	return (rv);
}

/*
 * Map static board attachment point to dynamic attachment points (components).
 */
static int
dyn_ap_ids(char *ap_id, cfga_list_data_t **ap_id_list, int *nlist)
{
	cfga_err_t	cfga_err;
	char		*errstr;
	char		*opts = "parsable";
	char		*listops = "class=sbd";

	cfga_err = config_list_ext(1, &ap_id, ap_id_list, nlist,
	    opts, listops, &errstr, CFGA_FLAG_LIST_ALL);
	if (cfga_err != CFGA_OK) {
		dprintf((stderr, "config_list_ext: %s\n",
		    config_strerror(cfga_err)));
		return (-1);
	}

	return (0);
}

/*
 * Initialize rcm handle, memory stats. Cache query result if necessary.
 */
static int
rcm_init(rcmd_t *rcm, apd_t apd_tbl[], int napds, int flags)
{
	longlong_t	ii;
	int		rv = 0;

	rcm->offline_query_info = NULL;
	rcm->rlist = NULL;
	rcm->cpus = NULL;

	if (rcm_alloc_handle(NULL, RCM_NOPID, NULL, &rcm->hdl) != RCM_SUCCESS) {
		dprintf((stderr, "rcm_alloc_handle (errno=%d)\n", errno));
		return (-1);
	}

	if ((rcm->ms_pagesize = sysconf(_SC_PAGE_SIZE)) == -1 ||
	    (rcm->ms_syspages = sysconf(_SC_PHYS_PAGES)) == -1) {
		dprintf((stderr, "sysconf: %s\n", strerror(errno)));
		return (-1);
	}
	ii = (longlong_t)rcm->ms_pagesize * rcm->ms_syspages;
	rcm->ms_sysmb = (int)((ii+MBYTE-1) / MBYTE);

	if (flags & RI_INCLUDE_QUERY)
		rv = rcm_query_init(rcm, apd_tbl, napds);

	return (rv);
}

static void
rcm_fini(rcmd_t *rcm)
{
	char	**cpp;

	assert(rcm != NULL);

	if (rcm->offline_query_info != NULL)
		rcm_free_info(rcm->offline_query_info);
	if (rcm->hdl != NULL)
		rcm_free_handle(rcm->hdl);

	if (rcm->rlist != NULL) {
		for (cpp = rcm->rlist; *cpp != NULL; cpp++)
			s_free(*cpp);
		free(rcm->rlist);
	}

	s_free(rcm->cpus);
	free(rcm);
}

#define	NODENAME_CMP		"cmp"
#define	NODENAME_SSM		"ssm"
#define	PROP_CPUID		"cpuid"
#define	PROP_DEVICE_TYPE	"device-type"
#define	PROP_ECACHE_SIZE	"ecache-size"
#define	PROP_L2_CACHE_SIZE	"l2-cache-size"
#define	PROP_L3_CACHE_SIZE	"l3-cache-size"

typedef struct {
	di_node_t		root;
	di_prom_handle_t	ph;
	ecache_info_t		*ecache_info;
} di_arg_t;

/*
 * The ecache sizes for individual cpus are read from the
 * OBP/Solaris device trees. This info cannot be derived
 * from the cfgadm_sbd cpu attachment point ecache info,
 * which may be a sum of multiple cores for CMP.
 */
static int
ecache_info_init(ecache_info_t *ec)
{
	di_arg_t	di_arg;
	di_prom_handle_t ph = DI_PROM_HANDLE_NIL;
	di_node_t	root = DI_NODE_NIL;
	int		cpuid_max, rv = 0;

	assert(ec != NULL && ec->cpuid_max == 0 && ec->ecache_sizes == NULL);

	if ((cpuid_max = sysconf(_SC_CPUID_MAX)) == -1) {
		dprintf((stderr, "sysconf fail: %s\n", strerror(errno)));
		rv = -1;
		goto done;
	}

	if ((root = di_init("/", DINFOCPYALL)) == DI_NODE_NIL) {
		dprintf((stderr, "di_init fail: %s\n", strerror(errno)));
		rv = -1;
		goto done;
	}

	if ((ph = di_prom_init()) == DI_PROM_HANDLE_NIL) {
		dprintf((stderr, "di_prom_init fail: %s\n", strerror(errno)));
		rv = -1;
		goto done;
	}

	if ((ec->ecache_sizes = calloc(cpuid_max + 1, sizeof (int))) == NULL) {
		dprintf((stderr, "calloc fail: %s\n", strerror(errno)));
		rv = -1;
		goto done;
	}
	ec->cpuid_max = cpuid_max;

	dprintf((stderr, "cpuid_max is set to %d\n", ec->cpuid_max));

	di_arg.ph = ph;
	di_arg.root = root;
	di_arg.ecache_info = ec;

	if (di_walk_node(root, DI_WALK_CLDFIRST, (void *)&di_arg,
	    find_cpu_nodes) != 0) {
		dprintf((stderr, "di_walk_node fail: %s\n", strerror(errno)));
		rv = -1;
	}

done:
	if (root != DI_NODE_NIL)
		di_fini(root);
	if (ph != DI_PROM_HANDLE_NIL)
		di_prom_fini(ph);

	return (rv);
}

/*
 * Libdevinfo node walk callback for reading ecache size
 * properties for cpu device nodes. Subtrees not containing
 * cpu nodes are filtered out.
 */
static int
find_cpu_nodes(di_node_t node, void *arg)
{
	char			*name;
	int			*cpuid, *ecache;
	di_arg_t		*di_arg = (di_arg_t *)arg;
	ecache_info_t		*ec = di_arg->ecache_info;
	di_prom_handle_t	ph = di_arg->ph;
	int			walk_child = 0;

	if (node == DI_NODE_NIL) {
		return (DI_WALK_TERMINATE);
	}

	if (node == di_arg->root) {
		return (DI_WALK_CONTINUE);
	}

	if (di_nodeid(node) == DI_PSEUDO_NODEID) {
		return (DI_WALK_PRUNECHILD);
	}

	name = di_node_name(node);
	if (name != NULL) {
		/*
		 * CMP nodes will be the parent of cpu nodes. On some platforms,
		 * cpu nodes will be under the ssm node. In either case,
		 * continue searching this subtree.
		 */
		if (strncmp(name, NODENAME_SSM, strlen(NODENAME_SSM)) == 0 ||
		    strncmp(name, NODENAME_CMP, strlen(NODENAME_CMP)) == 0) {
			return (DI_WALK_CONTINUE);
		}
	}

	dprintf((stderr, "find_cpu_nodes: node=%p, name=%s, binding_name=%s\n",
	    node, di_node_name(node), di_binding_name(node)));

	/*
	 * Ecache size property name differs with processor implementation.
	 * Panther has both L2 and L3, so check for L3 first to differentiate
	 * from Jaguar, which has only L2.
	 */
	if (prop_lookup_int(node, ph, PROP_ECACHE_SIZE, &ecache) == 0 ||
	    prop_lookup_int(node, ph, PROP_L3_CACHE_SIZE, &ecache) == 0 ||
	    prop_lookup_int(node, ph, PROP_L2_CACHE_SIZE, &ecache) == 0) {
		/*
		 * On some platforms the cache property is in the core
		 * node while the cpuid is in the child cpu node.  It may
		 * be needed while processing this node or a child node.
		 */
		ec->ecache_curr = *ecache;
		walk_child = 1;
	}

	if (prop_lookup_int(node, ph, PROP_CPUID, &cpuid) == 0) {

		assert(ec != NULL && ec->ecache_sizes != NULL &&
		    *cpuid <= ec->cpuid_max);

		if (ec->ecache_curr != 0) {
			ec->ecache_sizes[*cpuid] = ec->ecache_curr;

		}
	}

	return (walk_child ? DI_WALK_CONTINUE : DI_WALK_PRUNECHILD);
}

/*
 * Given a di_node_t, call the appropriate int property lookup routine.
 * Note: This lookup fails if the int property has multiple value entries.
 */
static int
prop_lookup_int(di_node_t node, di_prom_handle_t ph, char *propname, int **ival)
{
	int rv;

	rv = (di_nodeid(node) == DI_PROM_NODEID) ?
	    di_prom_prop_lookup_ints(ph, node, propname, ival) :
	    di_prop_lookup_ints(DDI_DEV_T_ANY, node, propname, ival);

	return (rv == 1 ? 0 : -1);
}

/*
 * For offline queries, RCM must be given a list of all resources
 * so modules can have access to the full scope of the operation.
 * The rcm_get_info calls are made individually in order to map the
 * returned rcm_info_t's to physical devices. The rcm_request_offline
 * result is cached so the query state can be looked up as we process
 * the rcm_get_info calls. This routine also tallies up the amount of
 * memory going away and creates a list of cpu ids to be used
 * later for rcm_request_capacity_change.
 */
static int
rcm_query_init(rcmd_t *rcm, apd_t apd_tbl[], int napds)
{
	apd_t			*apd;
	int 			i, j;
	cfga_list_data_t	*cfga_ldata;
	int			(*cm_rcm_qpass)(cfga_list_data_t *, rcmd_t *);
#ifdef DEBUG
	char			**cpp;
#endif /* DEBUG */

	/*
	 * Initial pass to size cpu and resource name arrays needed to
	 * interface with RCM. Attachment point ids for CMP can represent
	 * multiple cpus (and resource names). Instead of parsing the
	 * cfgadm info field here, use the worse case that all component
	 * attachment points are CMP.
	 */
	rcm->ndevs = 0;
	for (i = 0, apd = apd_tbl; i < napds; i++, apd++) {
		for (j = 1, cfga_ldata = &apd->cfga_list_data[1];
		    j < apd->nlist; j++, cfga_ldata++) {
			if (cfga_ldata->ap_o_state != CFGA_STAT_CONFIGURED) {
				continue;
			}
			rcm->ndevs += SBD_MAX_CORES_PER_CMP;
		}
	}

	/* account for trailing NULL in rlist */
	if (rcm->ndevs > 0 &&
	    ((rcm->cpus = calloc(rcm->ndevs, sizeof (cpuid_t))) == NULL ||
	    (rcm->rlist = calloc(rcm->ndevs + 1, sizeof (char *))) == NULL)) {
		dprintf((stderr, "calloc: %s\n", strerror(errno)));
		return (-1);
	}

	/*
	 * Second pass to fill in the RCM resource and cpu lists.
	 */
	for (i = 0, apd = apd_tbl; i < napds; i++, apd++) {
		for (j = 1, cfga_ldata = &apd->cfga_list_data[1];
		    j < apd->nlist; j++, cfga_ldata++) {
			if (cfga_ldata->ap_o_state != CFGA_STAT_CONFIGURED) {
				continue;
			}
			if ((cm_rcm_qpass =
			    cm_rcm_qpass_func(cfga_ldata->ap_type)) != NULL &&
			    (*cm_rcm_qpass)(cfga_ldata, rcm) != 0) {
				return (-1);
			}
		}
	}

	if (rcm->nrlist == 0)
		return (0);

	/*
	 * Cache query result. Since we are only interested in the
	 * set of RCM clients processed and not their request status,
	 * the return value is irrelevant.
	 */
	(void) rcm_request_offline_list(rcm->hdl, rcm->rlist,
	    RCM_QUERY|RCM_SCOPE, &rcm->offline_query_info);

#ifdef DEBUG
	dprintf((stderr, "RCM rlist: nrlist=%d\n", rcm->nrlist));
	for (cpp = rcm->rlist, i = 0; *cpp != NULL; cpp++, i++) {
		dprintf((stderr, "rlist[%d]=%s\n", i, *cpp));
	}
#endif /* DEBUG */

	return (0);
}

static int
cap_request(ri_hdl_t *ri_hdl, rcmd_t *rcm)
{
	return (((rcm->ncpus > 0 && cpu_cap_request(ri_hdl, rcm) != 0) ||
	    (rcm->query_pages > 0 && mem_cap_request(ri_hdl, rcm) != 0)) ?
	    -1 : 0);
}

/*
 * RCM capacity change request for cpus.
 */
static int
cpu_cap_request(ri_hdl_t *ri_hdl, rcmd_t *rcm)
{
	cpuid_t		*syscpuids, *newcpuids;
	int		sysncpus, newncpus;
	rcm_info_t	*rcm_info = NULL;
	int		i, j, k;
	nvlist_t	*nvl;
	int		rv = 0;

	/* get all cpus in the system */
	if (syscpus(&syscpuids, &sysncpus) == -1)
		return (-1);

	newncpus = sysncpus - rcm->ncpus;
	if ((newcpuids = calloc(newncpus, sizeof (cpuid_t))) == NULL) {
		dprintf((stderr, "calloc: %s", strerror(errno)));
		rv = -1;
		goto out;
	}

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		dprintf((stderr, "nvlist_alloc fail\n"));
		rv = -1;
		goto out;
	}

	/*
	 * Construct the new cpu list.
	 */
	for (i = 0, j = 0; i < sysncpus; i++) {
		for (k = 0; k < rcm->ncpus; k++) {
			if (rcm->cpus[k] == syscpuids[i]) {
				break;
			}
		}
		if (k == rcm->ncpus) {
			newcpuids[j++] = syscpuids[i];
		}
	}

	if (nvlist_add_int32(nvl, "old_total", sysncpus) != 0 ||
	    nvlist_add_int32(nvl, "new_total", newncpus) != 0 ||
	    nvlist_add_int32_array(nvl, "old_cpu_list", syscpuids,
	    sysncpus) != 0 ||
	    nvlist_add_int32_array(nvl, "new_cpu_list", newcpuids,
	    newncpus) != 0) {
		dprintf((stderr, "nvlist_add fail\n"));
		rv = -1;
		goto out;
	}

#ifdef DEBUG
	dprintf((stderr, "old_total=%d\n", sysncpus));
	for (i = 0; i < sysncpus; i++) {
		dprintf((stderr, "old_cpu_list[%d]=%d\n", i, syscpuids[i]));
	}
	dprintf((stderr, "new_total=%d\n", newncpus));
	for (i = 0; i < newncpus; i++) {
		dprintf((stderr, "new_cpu_list[%d]=%d\n", i, newcpuids[i]));
	}
#endif /* DEBUG */

	(void) rcm_request_capacity_change(rcm->hdl, RCM_CPU_ALL,
	    RCM_QUERY|RCM_SCOPE, nvl, &rcm_info);

	rv = add_rcm_clients(&ri_hdl->cpu_cap_clients, rcm, rcm_info, 0, NULL);

out:
	s_free(syscpuids);
	s_free(newcpuids);
	nvlist_free(nvl);
	if (rcm_info != NULL)
		rcm_free_info(rcm_info);

	return (rv);
}

static int
syscpus(cpuid_t **cpuids, int *ncpus)
{
	kstat_t		*ksp;
	kstat_ctl_t	*kc;
	cpuid_t		*cp;
	int		i;

	if ((*ncpus = sysconf(_SC_NPROCESSORS_CONF)) == -1) {
		dprintf((stderr, "sysconf: %s\n", errno));
		return (-1);
	}

	if ((kc = kstat_open()) == NULL) {
		dprintf((stderr, "kstat_open fail\n"));
		return (-1);
	}

	if ((cp = calloc(*ncpus, sizeof (cpuid_t))) == NULL) {
		dprintf((stderr, "calloc: %s\n", errno));
		(void) kstat_close(kc);
		return (-1);
	}

	for (i = 0, ksp = kc->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		if (strcmp(ksp->ks_module, "cpu_info") == 0) {
			cp[i++] = ksp->ks_instance;
		}
	}

	(void) kstat_close(kc);
	*cpuids = cp;

	return (0);
}

/*
 * RCM capacity change request for memory.
 */
static int
mem_cap_request(ri_hdl_t *ri_hdl, rcmd_t *rcm)
{
	nvlist_t	*nvl;
	rcm_info_t	*rcm_info = NULL;
	long 		newpages;
	int		rv = 0;

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		dprintf((stderr, "nvlist_alloc fail\n"));
		return (-1);
	}

	newpages = rcm->ms_syspages - rcm->query_pages;
	if (nvlist_add_int32(nvl, "page_size", rcm->ms_pagesize) != 0 ||
	    nvlist_add_int32(nvl, "old_pages", rcm->ms_syspages) != 0 ||
	    nvlist_add_int32(nvl, "new_pages", newpages) != 0) {
		dprintf((stderr, "nvlist_add fail\n"));
		nvlist_free(nvl);
		return (-1);
	}

	dprintf((stderr, "memory capacity change req: "
	    "page_size=%d, old_pages=%d, new_pages=%d\n",
	    rcm->ms_pagesize, rcm->ms_syspages, newpages));

	(void) rcm_request_capacity_change(rcm->hdl, RCM_MEM_ALL,
	    RCM_QUERY|RCM_SCOPE, nvl, &rcm_info);

	rv = add_rcm_clients(&ri_hdl->mem_cap_clients, rcm, rcm_info, 0, NULL);

	nvlist_free(nvl);
	if (rcm_info != NULL)
		rcm_free_info(rcm_info);

	return (rv);
}

static int
(*cm_rcm_qpass_func(cfga_type_t ap_type))(cfga_list_data_t *, rcmd_t *)
{
	int i;

	for (i = 0; i < sizeof (cm_ctl) / sizeof (cm_ctl[0]); i++) {
		if (strcmp(cm_ctl[i].type, ap_type) == 0) {
			return (cm_ctl[i].cm_rcm_qpass);
		}
	}
	return (NULL);
}

/*
 * Save cpu ids and RCM abstract resource names.
 * Cpu ids will be used for the capacity change request.
 * Resource names will be used for the offline query.
 */
static int
cpu_rcm_qpass(cfga_list_data_t *cfga_ldata, rcmd_t *rcm)
{
	processorid_t	cpuid;
	char		*cpustr, *lasts, *rsrcname, rbuf[32];
	char		cbuf[CFGA_INFO_LEN];
	int		speed, ecache;

	assert(sscanf(cfga_ldata->ap_info, CPU_INFO_FMT, &cbuf, &speed,
	    &ecache) == 3);

	for (cpustr = (char *)strtok_r(cbuf, CPUID_SEP, &lasts);
	    cpustr != NULL;
	    cpustr = (char *)strtok_r(NULL, CPUID_SEP, &lasts)) {
		cpuid = atoi(cpustr);

		(void) snprintf(rbuf, sizeof (rbuf), "%s%d", RCM_CPU, cpuid);
		if ((rsrcname = strdup(rbuf)) == NULL) {
			dprintf((stderr, "strdup fail\n"));
			return (-1);
		}
		assert(rcm->nrlist < rcm->ndevs && rcm->ncpus < rcm->ndevs);
		rcm->rlist[rcm->nrlist++] = rsrcname;
		rcm->cpus[rcm->ncpus++] = (cpuid_t)cpuid;

		dprintf((stderr, "cpu_cm_info: cpuid=%d, rsrcname=%s",
		    cpuid, rsrcname));
	}

	return (0);
}

/*
 * No RCM resource names for individual memory units, so
 * just add to offline query page count.
 */
static int
mem_rcm_qpass(cfga_list_data_t *cfga, rcmd_t *rcm)
{
	char		*cp;
	uint_t		kbytes;
	longlong_t	ii;

	if ((cp = strstr(cfga->ap_info, "size")) == NULL ||
	    sscanf(cp, "size=%u", &kbytes) != 1) {
		dprintf((stderr, "unknown sbd info format: %s\n", cp));
		return (-1);
	}

	ii = (longlong_t)kbytes * KBYTE;
	rcm->query_pages += (uint_t)(ii / rcm->ms_pagesize);

	dprintf((stderr, "%s: npages=%u\n", cfga->ap_log_id,
	    (uint_t)(ii / rcm->ms_pagesize)));

	return (0);
}

/*
 * Add physical I/O bus name to RCM resource list.
 */
static int
io_rcm_qpass(cfga_list_data_t *cfga, rcmd_t *rcm)
{
	char		path[MAXPATHLEN];
	char		buf[MAXPATHLEN];
	char		*rsrcname;

	if (sscanf(cfga->ap_info, "device=%s", path) != 1) {
		dprintf((stderr, "unknown sbd info format: %s\n",
		    cfga->ap_info));
		return (-1);
	}

	(void) snprintf(buf, sizeof (buf), "/devices%s", path);
	if ((rsrcname = strdup(buf)) == NULL) {
		dprintf((stderr, "strdup fail\n"));
		return (-1);
	}

	assert(rcm->nrlist < rcm->ndevs);
	rcm->rlist[rcm->nrlist++] = rsrcname;

	return (0);
}

static int
(*cm_info_func(cfga_type_t ap_type))(ri_ap_t *, cfga_list_data_t *,
    int, rcmd_t *)
{
	int i;

	for (i = 0; i < sizeof (cm_ctl) / sizeof (cm_ctl[0]); i++) {
		if (strcmp(cm_ctl[i].type, ap_type) == 0) {
			return (cm_ctl[i].cm_info);
		}
	}
	return (NULL);
}

/*
 * Create cpu handle, adding properties exported by sbd plugin and
 * RCM client usage.
 */
/* ARGSUSED */
static int
cpu_cm_info(ri_ap_t *ap, cfga_list_data_t *cfga, int flags, rcmd_t *rcm)
{
	processorid_t	cpuid;
	int		speed, ecache, rv = 0;
	char		buf[CFGA_INFO_LEN], *cpustr, *lasts;

	if (sscanf(cfga->ap_info, CPU_INFO_FMT, &buf, &speed, &ecache) != 3) {
		dprintf((stderr, "unknown sbd info format: %s\n",
		    cfga->ap_info));
		return (-1);
	}

	/* parse cpuids */
	for (cpustr = (char *)strtok_r(buf, CPUID_SEP, &lasts);
	    cpustr != NULL;
	    cpustr = (char *)strtok_r(NULL, CPUID_SEP, &lasts)) {
		cpuid = atoi(cpustr);
		if ((rv = i_cpu_cm_info(cpuid, speed, ecache, ap, rcm)) != 0) {
			break;
		}
	}

	return (rv);
}

static int
i_cpu_cm_info(processorid_t cpuid, int speed, int ecache_cfga, ri_ap_t *ap,
    rcmd_t *rcm)
{
	int		ecache_mb = 0;
	int		ecache_kb = 0;
	char		*state, buf[32];
	processor_info_t cpu_info;
	ri_dev_t	*cpu = NULL;
	rcm_info_t	*rcm_info = NULL;

	/*
	 * Could have been unconfigured in the interim, so cannot
	 * count on processor_info recognizing it.
	 */
	state = (processor_info(cpuid, &cpu_info) == 0) ?
	    pstate2str(cpu_info.pi_state) : "unknown";

	if ((cpu = ri_dev_alloc()) == NULL) {
		dprintf((stderr, "ri_dev_alloc failed\n"));
		return (-1);
	}

	/*
	 * Assume the ecache_info table has the right e-cache size for
	 * this CPU.  Use the value found in cfgadm (ecache_cfga) if not.
	 */
	if (rcm->ecache_info.ecache_sizes != NULL) {
		assert(rcm->ecache_info.cpuid_max != 0 &&
		    cpuid <= rcm->ecache_info.cpuid_max);
		ecache_mb = rcm->ecache_info.ecache_sizes[cpuid] / MBYTE;
		ecache_kb = rcm->ecache_info.ecache_sizes[cpuid] / KBYTE;
	}

	if (ecache_mb == 0) {
		ecache_mb = ecache_cfga;
	}

	dprintf((stderr, "i_cpu_cm_info: cpu(%d) ecache=%d MB\n",
	    cpuid, ecache));

	if (nvlist_add_int32(cpu->conf_props, RI_CPU_ID, cpuid) != 0 ||
	    nvlist_add_int32(cpu->conf_props, RI_CPU_SPEED, speed) != 0 ||
	    nvlist_add_int32(cpu->conf_props, RI_CPU_ECACHE, ecache_mb) != 0 ||
	    nvlist_add_string(cpu->conf_props, RI_CPU_STATE, state) != 0) {
		dprintf((stderr, "nvlist_add fail\n"));
		ri_dev_free(cpu);
		return (-1);
	}

	/*
	 * Report cache size in kilobyte units if available.  This info is
	 * added to support processors with cache sizes that are non-integer
	 * megabyte multiples.
	 */
	if (ecache_kb != 0) {
		if (nvlist_add_int32(cpu->conf_props, RI_CPU_ECACHE_KBYTE,
		    ecache_kb) != 0)  {
			dprintf((stderr, "nvlist_add fail: %s\n",
			    RI_CPU_ECACHE_KBYTE));
			ri_dev_free(cpu);
			return (-1);
		}
	}

	(void) snprintf(buf, sizeof (buf), "%s%d", RCM_CPU, cpuid);
	dprintf((stderr, "rcm_get_info(%s)\n", buf));
	if (rcm_get_info(rcm->hdl, buf, RCM_INCLUDE_DEPENDENT,
	    &rcm_info) != RCM_SUCCESS) {
		dprintf((stderr, "rcm_get_info (errno=%d)\n", errno));
		ri_dev_free(cpu);
		if (rcm_info != NULL)
			rcm_free_info(rcm_info);
		return (-1);
	}

	dev_list_cpu_insert(&ap->cpus, cpu, cpuid);

	return (0);
}

/*
 * Create memory handle, adding properties exported by sbd plugin.
 * No RCM tuples to be saved unless RCM is modified to export names
 * for individual memory units.
 */
/* ARGSUSED */
static int
mem_cm_info(ri_ap_t *ap, cfga_list_data_t *cfga, int flags, rcmd_t *rcm)
{
	ri_dev_t	*mem;
	char		*cp;
	char		*cpval;
	int		len;
	uint64_t	base_addr;				/* required */
	int32_t		size_kb;				/* required */
	int32_t		perm_kb = 0;				/* optional */
	char		target[CFGA_AP_LOG_ID_LEN] = "";	/* optional */
	int32_t		del_kb = 0;				/* optional */
	int32_t		rem_kb = 0;				/* optional */
	char		source[CFGA_AP_LOG_ID_LEN] = "";	/* optional */

	if (sscanf(cfga->ap_info, "address=0x%llx size=%u", &base_addr,
	    &size_kb) != 2) {
		goto err_fmt;
	}

	if ((cp = strstr(cfga->ap_info, "permanent")) != NULL &&
	    sscanf(cp, "permanent=%u", &perm_kb) != 1) {
		goto err_fmt;
	}

	if ((cp = strstr(cfga->ap_info, "target")) != NULL) {
		if ((cpval = strstr(cp, "=")) == NULL) {
			goto err_fmt;
		}
		for (len = 0; cpval[len] != '\0' && cpval[len] != ' '; len++) {
			if (len >= CFGA_AP_LOG_ID_LEN) {
				goto err_fmt;
			}
		}
		if (sscanf(cp, "target=%s deleted=%u remaining=%u", &target,
		    &del_kb, &rem_kb) != 3) {
			goto err_fmt;
		}
	}

	if ((cp = strstr(cfga->ap_info, "source")) != NULL) {
		if ((cpval = strstr(cp, "=")) == NULL) {
			goto err_fmt;
		}
		for (len = 0; cpval[len] != '\0' && cpval[len] != ' '; len++) {
			if (len >= CFGA_AP_LOG_ID_LEN) {
				goto err_fmt;
			}
		}
		if (sscanf(cp, "source=%s", &source) != 1) {
			goto err_fmt;
		}
	}

	dprintf((stderr, "%s: base=0x%llx, size=%u, permanent=%u\n",
	    cfga->ap_log_id, base_addr, size_kb, perm_kb));

	if ((mem = ri_dev_alloc()) == NULL)
		return (-1);

	/*
	 * Convert memory sizes to MB (truncate).
	 */
	if (nvlist_add_uint64(mem->conf_props, RI_MEM_ADDR, base_addr) != 0 ||
	    nvlist_add_int32(mem->conf_props, RI_MEM_BRD, size_kb/KBYTE) != 0 ||
	    nvlist_add_int32(mem->conf_props, RI_MEM_PERM,
	    perm_kb/KBYTE) != 0) {
		dprintf((stderr, "nvlist_add failure\n"));
		ri_dev_free(mem);
		return (-1);
	}

	if (target[0] != '\0' &&
	    (nvlist_add_string(mem->conf_props, RI_MEM_TARG, target) != 0 ||
	    nvlist_add_int32(mem->conf_props, RI_MEM_DEL, del_kb/KBYTE) != 0 ||
	    nvlist_add_int32(mem->conf_props, RI_MEM_REMAIN,
	    rem_kb/KBYTE) != 0)) {
		dprintf((stderr, "nvlist_add failure\n"));
		ri_dev_free(mem);
		return (-1);
	}

	if (source[0] != '\0' &&
	    nvlist_add_string(mem->conf_props, RI_MEM_SRC, source) != 0) {
		dprintf((stderr, "nvlist_add failure\n"));
		ri_dev_free(mem);
		return (-1);
	}

	/*
	 * XXX - move this property to attachment point hdl?
	 */
	if (nvlist_add_int32(mem->conf_props, RI_MEM_DOMAIN,
	    rcm->ms_sysmb) != 0) {
		dprintf((stderr, "nvlist_add failure\n"));
		ri_dev_free(mem);
		return (-1);
	}

	dev_list_append(&ap->mems, mem);
	return (0);

err_fmt:
	dprintf((stderr, "unknown sbd info format: %s\n", cfga->ap_info));
	return (-1);
}

/*
 * Initiate a libdevinfo walk on the IO bus path.
 * XXX - investigate performance using two threads here: one thread to do the
 * libdevinfo snapshot and treewalk; and one thread to get RCM usage info
 */
static int
io_cm_info(ri_ap_t *ap, cfga_list_data_t *cfga, int flags, rcmd_t *rcm)
{
	int			i;
	int			j;
	int			k;
	int			set_size;
	int			retval = 0;
	int			n_usage;
	devinfo_arg_t		di_arg;
	lookup_table_t		devicetable;
	lookup_entry_t		*deventry;
	lookup_entry_t		*lastdeventry;
	ri_dev_t		*io = NULL;
	ri_client_t		*client;
	ri_client_t		*tmp;
	di_devlink_handle_t	linkhd = NULL;
	di_node_t		root = DI_NODE_NIL;
	di_node_t		node = DI_NODE_NIL;
	rcm_info_tuple_t	*rcm_tuple;
	rcm_info_t		*rcm_info = NULL;
	const char		*rcm_rsrc = NULL;
	char			drv_inst[MAXPATHLEN];
	char			path[MAXPATHLEN];
	char			pathbuf[MAXPATHLEN];

	dprintf((stderr, "io_cm_info(%s)\n", cfga->ap_log_id));

	/* Extract devfs path from cfgadm information */
	if (sscanf(cfga->ap_info, "device=%s\n", path) != 1) {
		dprintf((stderr, "unknown sbd info format: %s\n",
		    cfga->ap_info));
		return (-1);
	}

	/* Initialize empty device lookup table */
	devicetable.n_entries = 0;
	devicetable.n_slots = 0;
	devicetable.table = NULL;

	/* Get libdevinfo snapshot */
	dprintf((stderr, "di_init(%s)\n", path));
	if ((root = di_init(path, DINFOCPYALL)) == DI_NODE_NIL) {
		dprintf((stderr, "di_init: %s\n", strerror(errno)));
		retval = RI_NODE_NIL; /* tell ri_init to skip this node */
		goto end;
	}

	/*
	 * Map in devlinks database.
	 * XXX - This could be moved to ri_init() for better performance.
	 */
	dprintf((stderr, "di_devlink_init()\n"));
	if ((linkhd = di_devlink_init(NULL, 0)) == NULL) {
		dprintf((stderr, "di_devlink_init: %s\n", strerror(errno)));
		retval = -1;
		goto end;
	}

	/* Initialize argument for devinfo treewalk */
	di_arg.err = 0;
	di_arg.node = DI_NODE_NIL;
	di_arg.pathbuf = pathbuf;
	di_arg.table = &devicetable;
	di_arg.linkhd = linkhd;

	/* Use libdevinfo treewalk to build device lookup table */
	if (di_walk_node(root, DI_WALK_CLDFIRST, (void *)&di_arg,
	    devinfo_node_walk) != 0) {
		dprintf((stderr, "di_walk_node: %s\n", strerror(errno)));
		retval = -1;
		goto end;
	}
	if (di_arg.err != 0) {
		dprintf((stderr, "di_walk_node: device tree walk failed\n"));
		retval = -1;
		goto end;
	}

	/* Call RCM to gather usage information */
	(void) snprintf(pathbuf, MAXPATHLEN, "/devices%s", path);
	dprintf((stderr, "rcm_get_info(%s)\n", pathbuf));
	if (rcm_get_info(rcm->hdl, pathbuf,
	    RCM_INCLUDE_SUBTREE|RCM_INCLUDE_DEPENDENT, &rcm_info) !=
	    RCM_SUCCESS) {
		dprintf((stderr, "rcm_get_info (errno=%d)\n", errno));
		retval = -1;
		goto end;
	}

	/* Sort the device table by name (proper order for lookups) */
	qsort(devicetable.table, devicetable.n_entries, sizeof (lookup_entry_t),
	    table_compare_names);

	/* Perform mappings of RCM usage segments to device table entries */
	lastdeventry = NULL;
	rcm_tuple = NULL;
	while ((rcm_tuple = rcm_info_next(rcm_info, rcm_tuple)) != NULL) {
		if ((rcm_rsrc = rcm_info_rsrc(rcm_tuple)) == NULL)
			continue;
		if (deventry = lookup(&devicetable, rcm_rsrc)) {
			if (add_usage(deventry, rcm_rsrc, rcm_tuple)) {
				retval = -1;
				goto end;
			}
			lastdeventry = deventry;
		} else {
			if (add_usage(lastdeventry, rcm_rsrc, rcm_tuple)) {
				retval = -1;
				goto end;
			}
		}
	}

	/* Re-sort the device table by index number (original treewalk order) */
	qsort(devicetable.table, devicetable.n_entries, sizeof (lookup_entry_t),
	    table_compare_indices);

	/*
	 * Use the mapped usage and the device table to construct ri_dev_t's.
	 * Construct one for each set of entries in the device table with
	 * matching di_node_t's, if: 1) it has mapped RCM usage, or 2) it is
	 * a leaf node and the caller has requested that unmanaged nodes be
	 * included in the output.
	 */
	i = 0;
	while (i < devicetable.n_entries) {

		node = devicetable.table[i].node;

		/* Count how many usage records are mapped to this node's set */
		n_usage = 0;
		set_size = 0;
		while (((i + set_size) < devicetable.n_entries) &&
		    (devicetable.table[i + set_size].node == node)) {
			n_usage += devicetable.table[i + set_size].n_usage;
			set_size += 1;
		}

		/*
		 * If there's no usage, then the node is unmanaged.  Skip this
		 * set of devicetable entries unless the node is a leaf node
		 * and the caller has requested information on unmanaged leaves.
		 */
		if ((n_usage == 0) &&
		    !((flags & RI_INCLUDE_UNMANAGED) && (ident_leaf(node)))) {
			i += set_size;
			continue;
		}

		/*
		 * The checks above determined that this node is going in.
		 * So determine its driver/instance name and allocate an
		 * ri_dev_t for this node.
		 */
		if (mk_drv_inst(node, drv_inst, devicetable.table[i].name)) {
			dprintf((stderr, "mk_drv_inst failed\n"));
			retval = -1;
			break;
		}
		if ((io = io_dev_alloc(drv_inst)) == NULL) {
			dprintf((stderr, "io_dev_alloc failed\n"));
			retval = -1;
			break;
		}

		/* Now add all the RCM usage records (if any) to the ri_dev_t */
		for (j = i; j < (i + set_size); j++) {
			for (k = 0; k < devicetable.table[j].n_usage; k++) {
				/* Create new ri_client_t for basic usage */
				client = ri_client_alloc(
				    (char *)devicetable.table[j].usage[k].rsrc,
				    (char *)devicetable.table[j].usage[k].info);
				if (client == NULL) {
					dprintf((stderr,
					    "ri_client_alloc failed\n"));
					ri_dev_free(io);
					retval = -1;
					goto end;
				}

				/* Add extra query usage to the ri_client_t */
				if ((flags & RI_INCLUDE_QUERY) &&
				    (add_query_state(rcm, client,
				    devicetable.table[j].usage[k].rsrc,
				    devicetable.table[j].usage[k].info) != 0)) {
					dprintf((stderr,
					    "add_query_state failed\n"));
					ri_dev_free(io);
					ri_client_free(client);
					retval = -1;
					goto end;
				}

				/* Link new ri_client_t to ri_dev_t */
				if (io->rcm_clients) {
					tmp = io->rcm_clients;
					while (tmp->next)
						tmp = tmp->next;
					tmp->next = client;
				} else {
					io->rcm_clients = client;
				}
			}
		}

		/* Link the ri_dev_t into the return value */
		dev_list_append(&ap->ios, io);

		/* Advance to the next node set */
		i += set_size;
	}

end:
	if (rcm_info != NULL)
		rcm_free_info(rcm_info);
	if (linkhd != NULL)
		di_devlink_fini(&linkhd);
	if (root != DI_NODE_NIL)
		di_fini(root);
	empty_table(&devicetable);

	dprintf((stderr, "io_cm_info: returning %d\n", retval));
	return (retval);
}

static int
ident_leaf(di_node_t node)
{
	di_minor_t	minor = DI_MINOR_NIL;

	return ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL &&
	    di_child_node(node) == DI_NODE_NIL);
}

/* ARGSUSED */
static int
mk_drv_inst(di_node_t node, char drv_inst[], char *devfs_path)
{
	char	*drv;
	int	inst;

	if ((drv = di_driver_name(node)) == NULL) {
		dprintf((stderr, "no driver bound to %s\n",
		    devfs_path));
		return (-1);
	}

	if ((inst = di_instance(node)) == -1) {
		dprintf((stderr, "no instance assigned to %s\n",
		    devfs_path));
		return (-1);
	}
	(void) snprintf(drv_inst, MAXPATHLEN, "%s%d", drv, inst);

	return (0);
}

/*
 * Libdevinfo walker.
 *
 * During the tree walk of the attached IO devices, for each node
 * and all of its associated minors, the following actions are performed:
 *  -  The /devices path of the physical device node or minor
 *     is stored in a lookup table along with a reference to the
 *     libdevinfo node it represents via add_lookup_entry().
 *  -  The device links associated with each device are also
 *     stored in the same lookup table along with a reference to
 *     the libdevinfo node it represents via the minor walk callback.
 *
 */
static int
devinfo_node_walk(di_node_t node, void *arg)
{
	char			*devfs_path;
#ifdef DEBUG
	char			*drv;
#endif /* DEBUG */
	devinfo_arg_t		*di_arg = (devinfo_arg_t *)arg;

	if (node == DI_NODE_NIL) {
		return (DI_WALK_TERMINATE);
	}

	if (((di_state(node) & DI_DRIVER_DETACHED) == 0) &&
	    ((devfs_path = di_devfs_path(node)) != NULL)) {

		/* Use the provided path buffer to create full /devices path */
		(void) snprintf(di_arg->pathbuf, MAXPATHLEN, "/devices%s",
		    devfs_path);

#ifdef DEBUG
		dprintf((stderr, "devinfo_node_walk(%s)\n", di_arg->pathbuf));
		if ((drv = di_driver_name(node)) != NULL)
			dprintf((stderr, " driver name %s instance %d\n", drv,
			    di_instance(node)));
#endif

		/* Free the devfs_path */
		di_devfs_path_free(devfs_path);

		/* Add an entry to the lookup table for this physical device */
		if (add_lookup_entry(di_arg->table, di_arg->pathbuf, node)) {
			dprintf((stderr, "add_lookup_entry: %s\n",
			    strerror(errno)));
			di_arg->err = 1;
			return (DI_WALK_TERMINATE);
		}

		/* Check if this node has minors */
		if ((di_minor_next(node, DI_MINOR_NIL)) != DI_MINOR_NIL) {
			/* Walk this node's minors */
			di_arg->node = node;
			if (di_walk_minor(node, NULL, DI_CHECK_ALIAS, arg,
			    devinfo_minor_walk) != 0) {
				dprintf((stderr, "di_walk_minor: %s\n",
				    strerror(errno)));
				di_arg->err = 1;
				return (DI_WALK_TERMINATE);
			}
		}
	}

	return (DI_WALK_CONTINUE);
}

/*
 * Use di_devlink_walk to find the /dev link from /devices path for this minor
 */
static int
devinfo_minor_walk(di_node_t node, di_minor_t minor, void *arg)
{
	char		*name;
	char		*devfs_path;
	devinfo_arg_t	*di_arg = (devinfo_arg_t *)arg;
	char		pathbuf[MAXPATHLEN];

#ifdef DEBUG
	dprintf((stderr, "devinfo_minor_walk(%d) %s\n", minor,
	    di_arg->pathbuf));

	if ((name = di_minor_name(minor)) != NULL) {
		dprintf((stderr, "  minor name %s\n", name));
	}
#endif /* DEBUG */

	/* Terminate the walk when the device node changes */
	if (node != di_arg->node) {
		return (DI_WALK_TERMINATE);
	}

	/* Construct full /devices path for this minor */
	if ((name = di_minor_name(minor)) == NULL) {
		return (DI_WALK_CONTINUE);
	}
	(void) snprintf(pathbuf, MAXPATHLEN, "%s:%s", di_arg->pathbuf, name);

	/* Add lookup entry for this minor node */
	if (add_lookup_entry(di_arg->table, pathbuf, node)) {
		dprintf((stderr, "add_lookup_entry: %s\n", strerror(errno)));
		di_arg->err = 1;
		return (DI_WALK_TERMINATE);
	}

	/*
	 * Walk the associated device links.
	 * Note that di_devlink_walk() doesn't want "/devices" in its paths.
	 * Also note that di_devlink_walk() will fail if there are no device
	 * links, which is fine; so ignore if it fails.  Only check for
	 * internal failures during such a walk.
	 */
	devfs_path = &pathbuf[strlen("/devices")];
	(void) di_devlink_walk(di_arg->linkhd, NULL, devfs_path, 0, arg,
	    devinfo_devlink_walk);
	if (di_arg->err != 0) {
		return (DI_WALK_TERMINATE);
	}

	return (DI_WALK_CONTINUE);
}

static int
devinfo_devlink_walk(di_devlink_t devlink, void *arg)
{
	const char	*linkpath;
	devinfo_arg_t	*di_arg = (devinfo_arg_t *)arg;

	/* Get the devlink's path */
	if ((linkpath = di_devlink_path(devlink)) == NULL) {
		dprintf((stderr, "di_devlink_path: %s\n", strerror(errno)));
		di_arg->err = 1;
		return (DI_WALK_TERMINATE);
	}
	dprintf((stderr, "devinfo_devlink_walk: %s\n", linkpath));

	/* Add lookup entry for this devlink */
	if (add_lookup_entry(di_arg->table, linkpath, di_arg->node)) {
		dprintf((stderr, "add_lookup_entry: %s\n", strerror(errno)));
		di_arg->err = 1;
		return (DI_WALK_TERMINATE);
	}

	return (DI_WALK_CONTINUE);
}

/*
 * Map rcm_info_t's to ri_client_t's, filtering out "uninteresting" (hack)
 * RCM clients. The number of "interesting" ri_client_t's is returned
 * in cnt if passed non-NULL.
 */
static int
add_rcm_clients(ri_client_t **client_list, rcmd_t *rcm, rcm_info_t *info,
    int flags, int *cnt)
{
	rcm_info_tuple_t	*tuple;
	char			*rsrc, *usage;
	ri_client_t		*client, *tmp;

	assert(client_list != NULL && rcm != NULL);

	if (info == NULL)
		return (0);

	if (cnt != NULL)
		*cnt = 0;

	tuple = NULL;
	while ((tuple = rcm_info_next(info, tuple)) != NULL) {
		if ((rsrc = (char *)rcm_info_rsrc(tuple)) == NULL ||
		    (usage = (char *)rcm_info_info(tuple)) == NULL) {
			continue;
		}

		if (rcm_ignore(rsrc, usage) == 0)
			continue;

		if ((client = ri_client_alloc(rsrc, usage)) == NULL)
			return (-1);

		if ((flags & RI_INCLUDE_QUERY) && add_query_state(rcm, client,
		    rsrc, usage) != 0) {
			ri_client_free(client);
			return (-1);
		}

		if (cnt != NULL)
			++*cnt;

		/*
		 * Link in
		 */
		if ((tmp = *client_list) == NULL) {
			*client_list = client;
			continue;
		}
		while (tmp->next != NULL) {
			tmp = tmp->next;
		}
		tmp->next = client;
	}

	return (0);
}

/*
 * Currently only filtering out based on known info string prefixes.
 */
/* ARGSUSED */
static int
rcm_ignore(char *rsrc, char *infostr)
{
	char	**cpp;

	for (cpp = rcm_info_filter; *cpp != NULL; cpp++) {
		if (strncmp(infostr, *cpp, strlen(*cpp)) == 0) {
			return (0);
		}
	}
	return (-1);
}

/*
 * If this tuple was cached in the offline query pass, add the
 * query state and error string to the ri_client_t.
 */
static int
add_query_state(rcmd_t *rcm, ri_client_t *client, const char *rsrc,
    const char *info)
{
	int			qstate = RI_QUERY_UNKNOWN;
	char			*errstr = NULL;
	rcm_info_tuple_t	*cached_tuple;

	if ((cached_tuple = tuple_lookup(rcm, rsrc, info)) != NULL) {
		qstate = state2query(rcm_info_state(cached_tuple));
		errstr = (char *)rcm_info_error(cached_tuple);
	}

	if (nvlist_add_int32(client->usg_props, RI_QUERY_STATE, qstate) != 0 ||
	    (errstr != NULL && nvlist_add_string(client->usg_props,
	    RI_QUERY_ERR, errstr) != 0)) {
		dprintf((stderr, "nvlist_add fail\n"));
		return (-1);
	}

	return (0);
}

static int
state2query(int rcm_state)
{
	int	query;

	switch (rcm_state) {
	case RCM_STATE_OFFLINE_QUERY:
	case RCM_STATE_SUSPEND_QUERY:
		query = RI_QUERY_OK;
		break;
	case RCM_STATE_OFFLINE_QUERY_FAIL:
	case RCM_STATE_SUSPEND_QUERY_FAIL:
		query = RI_QUERY_FAIL;
		break;
	default:
		query = RI_QUERY_UNKNOWN;
		break;
	}

	return (query);
}

static void
dev_list_append(ri_dev_t **head, ri_dev_t *dev)
{
	ri_dev_t	*tmp;

	if ((tmp = *head) == NULL) {
		*head = dev;
		return;
	}
	while (tmp->next != NULL) {
		tmp = tmp->next;
	}
	tmp->next = dev;
}

/*
 * The cpu list is ordered on cpuid since CMP cpuids will not necessarily
 * be discovered in sequence.
 */
static void
dev_list_cpu_insert(ri_dev_t **listp, ri_dev_t *dev, processorid_t newid)
{
	ri_dev_t	*tmp;
	int32_t		cpuid;

	while ((tmp = *listp) != NULL &&
	    nvlist_lookup_int32(tmp->conf_props, RI_CPU_ID, &cpuid) == 0 &&
	    cpuid < newid) {
		listp = &tmp->next;
	}

	dev->next = tmp;
	*listp = dev;
}

/*
 * Linear lookup. Should convert to hash tab.
 */
static rcm_info_tuple_t *
tuple_lookup(rcmd_t *rcm, const char *krsrc, const char *kinfo)
{
	rcm_info_tuple_t	*tuple = NULL;
	const char		*rsrc, *info;

	if ((rcm == NULL) || (krsrc == NULL) || (kinfo == NULL)) {
		return (NULL);
	}

	while ((tuple = rcm_info_next(rcm->offline_query_info,
	    tuple)) != NULL) {
		if ((rsrc = rcm_info_rsrc(tuple)) == NULL ||
		    (info = rcm_info_info(tuple)) == NULL) {
			continue;
		}

		if (strcmp(rsrc, krsrc) == 0 && strcmp(info, kinfo) == 0) {
			return (tuple);
		}
	}
	return (NULL);
}

/*
 * Create and link attachment point handle.
 */
static ri_ap_t *
ri_ap_alloc(char *ap_id, ri_hdl_t *hdl)
{
	ri_ap_t		*ap, *tmp;

	if ((ap = calloc(1, sizeof (*ap))) == NULL) {
		dprintf((stderr, "calloc: %s\n", strerror(errno)));
		return (NULL);
	}

	if (nvlist_alloc(&ap->conf_props, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_string(ap->conf_props, RI_AP_REQ_ID, ap_id) != 0) {
		nvlist_free(ap->conf_props);
		free(ap);
		return (NULL);
	}

	if ((tmp = hdl->aps) == NULL) {
		hdl->aps = ap;
	} else {
		while (tmp->next != NULL) {
			tmp = tmp->next;
		}
		tmp->next = ap;
	}

	return (ap);
}

static ri_dev_t *
ri_dev_alloc(void)
{
	ri_dev_t	*dev;

	if ((dev = calloc(1, sizeof (*dev))) == NULL ||
	    nvlist_alloc(&dev->conf_props, NV_UNIQUE_NAME, 0) != 0) {
		s_free(dev);
	}
	return (dev);
}

static ri_dev_t *
io_dev_alloc(char *drv_inst)
{
	ri_dev_t	*io;

	assert(drv_inst != NULL);

	if ((io = ri_dev_alloc()) == NULL)
		return (NULL);

	if (nvlist_add_string(io->conf_props, RI_IO_DRV_INST,
	    drv_inst) != 0) {
		dprintf((stderr, "nvlist_add_string fail\n"));
		ri_dev_free(io);
		return (NULL);
	}

	return (io);
}

static ri_client_t *
ri_client_alloc(char *rsrc, char *usage)
{
	ri_client_t	*client;

	assert(rsrc != NULL && usage != NULL);

	if ((client = calloc(1, sizeof (*client))) == NULL) {
		dprintf((stderr, "calloc: %s\n", strerror(errno)));
		return (NULL);
	}

	if (nvlist_alloc(&client->usg_props, NV_UNIQUE_NAME, 0) != 0) {
		dprintf((stderr, "nvlist_alloc fail\n"));
		free(client);
		return (NULL);
	}

	if (nvlist_add_string(client->usg_props, RI_CLIENT_RSRC, rsrc) != 0 ||
	    nvlist_add_string(client->usg_props, RI_CLIENT_USAGE, usage) != 0) {
		dprintf((stderr, "nvlist_add_string fail\n"));
		ri_client_free(client);
		return (NULL);
	}

	return (client);
}

static void
apd_tbl_free(apd_t apd_tbl[], int napds)
{
	int	i;
	apd_t	*apd;

	for (i = 0, apd = apd_tbl; i < napds; i++, apd++)
		s_free(apd->cfga_list_data);

	free(apd_tbl);
}

static char *
pstate2str(int pi_state)
{
	char	*state;

	switch (pi_state) {
	case P_OFFLINE:
		state = PS_OFFLINE;
		break;
	case P_ONLINE:
		state = PS_ONLINE;
		break;
	case P_FAULTED:
		state = PS_FAULTED;
		break;
	case P_POWEROFF:
		state = PS_POWEROFF;
		break;
	case P_NOINTR:
		state = PS_NOINTR;
		break;
	case P_SPARE:
		state = PS_SPARE;
		break;
	default:
		state = "unknown";
		break;
	}

	return (state);
}

#ifdef DEBUG
static void
dump_apd_tbl(FILE *fp, apd_t *apds, int n_apds)
{
	int			i, j;
	cfga_list_data_t	*cfga_ldata;

	for (i = 0; i < n_apds; i++, apds++) {
		dprintf((stderr, "apd_tbl[%d].nlist=%d\n", i, apds->nlist));
		for (j = 0, cfga_ldata = apds->cfga_list_data; j < apds->nlist;
		    j++, cfga_ldata++) {
			dprintf((fp,
			    "apd_tbl[%d].cfga_list_data[%d].ap_log_id=%s\n",
			    i, j, cfga_ldata->ap_log_id));
		}
	}
}
#endif /* DEBUG */

/*
 * The lookup table is a simple array that is grown in chunks
 * to optimize memory allocation.
 * Indices are assigned to each array entry in-order so that
 * the original device tree ordering can be discerned at a later time.
 *
 * add_lookup_entry is called from the libdevinfo tree traversal callbacks:
 * 1) devinfo_node_walk - physical device path for each node in
 *    the devinfo tree via di_walk_node(), lookup entry name is
 *    /devices/[di_devfs_path]
 * 2) devinfo_minor_walk - physical device path plus minor name for
 *    each minor associated with a node via di_walk_minor(), lookup entry
 *    name is /devices/[di_devfs_path:di_minor_name]
 * 3) devinfo_devlink_walk - for each minor's /dev link from its /devices
 *    path via di_devlink_walk(), lookup entry name is di_devlink_path()
 */
static int
add_lookup_entry(lookup_table_t *table, const char *name, di_node_t node)
{
	size_t		size;
	lookup_entry_t	*new_table;


	/* Grow the lookup table by USAGE_ALLOC_SIZE slots if necessary */
	if (table->n_entries == table->n_slots) {
		size = (table->n_slots + USAGE_ALLOC_SIZE) *
		    sizeof (lookup_entry_t);
		new_table = (lookup_entry_t *)realloc(table->table, size);
		if (new_table == NULL) {
			dprintf((stderr, "add_lookup_entry: alloc failed: %s\n",
			    strerror(errno)));
			errno = ENOMEM;
			return (-1);
		}
		table->table = new_table;
		table->n_slots += USAGE_ALLOC_SIZE;
	}

	dprintf((stderr, "add_lookup_entry[%d]:%s\n", table->n_entries, name));

	/* Add this name to the next slot */
	if ((table->table[table->n_entries].name = strdup(name)) == NULL) {
		dprintf((stderr, "add_lookup_entry: strdup failed: %s\n",
		    strerror(errno)));
		errno = ENOMEM;
		return (-1);
	}
	table->table[table->n_entries].index = table->n_entries;
	table->table[table->n_entries].node = node;
	table->table[table->n_entries].n_usage = 0;
	table->table[table->n_entries].usage = NULL;
	table->n_entries += 1;

	return (0);
}

/*
 * lookup table entry names are full pathname strings, all start with /
 */
static int
table_compare_names(const void *a, const void *b)
{
	lookup_entry_t *entry1 = (lookup_entry_t *)a;
	lookup_entry_t *entry2 = (lookup_entry_t *)b;

	return (strcmp(entry1->name, entry2->name));
}


/*
 * Compare two indices and return -1 for less, 1 for greater, 0 for equal
 */
static int
table_compare_indices(const void *a, const void *b)
{
	lookup_entry_t *entry1 = (lookup_entry_t *)a;
	lookup_entry_t *entry2 = (lookup_entry_t *)b;

	if (entry1->index < entry2->index)
		return (-1);
	if (entry1->index > entry2->index)
		return (1);
	return (0);
}

/*
 * Given a RCM resource name, find the matching entry in the IO device table
 */
static lookup_entry_t *
lookup(lookup_table_t *table, const char *rcm_rsrc)
{
	lookup_entry_t	*entry;
	lookup_entry_t	lookup_arg;

	dprintf((stderr, "lookup:%s\n", rcm_rsrc));
	lookup_arg.name = (char *)rcm_rsrc;
	entry = bsearch(&lookup_arg, table->table, table->n_entries,
	    sizeof (lookup_entry_t), table_compare_names);

#ifdef DEBUG
	if (entry != NULL) {
		dprintf((stderr, " found entry:%d\n", entry->index));
	}
#endif /* DEBUG */
	return (entry);
}

/*
 * Add RCM usage to the given device table entry.
 * Returns -1 on realloc failure.
 */
static int
add_usage(lookup_entry_t *entry, const char *rcm_rsrc, rcm_info_tuple_t *tuple)
{
	size_t		size;
	const char	*info;
	usage_t		*new_usage;

	if ((entry == NULL) ||
	    ((info = rcm_info_info(tuple)) == NULL))
		return (0);

	if (rcm_ignore((char *)rcm_rsrc, (char *)info) == 0)
		return (0);

	size = (entry->n_usage + 1) * sizeof (usage_t);
	new_usage = (usage_t *)realloc(entry->usage, size);
	if (new_usage == NULL) {
		dprintf((stderr, "add_usage: alloc failed: %s\n",
		    strerror(errno)));
		return (-1);
	}
	dprintf((stderr, "add_usage: entry %d rsrc: %s info: %s\n",
	    entry->index, rcm_rsrc, info));

	entry->usage = new_usage;
	entry->usage[entry->n_usage].rsrc = rcm_rsrc;
	entry->usage[entry->n_usage].info = info;
	entry->n_usage += 1;
	return (0);
}

static void
empty_table(lookup_table_t *table)
{
	int i;

	if (table) {
		for (i = 0; i < table->n_entries; i++) {
			if (table->table[i].name)
				free(table->table[i].name);
			/*
			 * Note: the strings pointed to from within
			 * usage were freed already by rcm_free_info
			 */
			if (table->table[i].usage)
				free(table->table[i].usage);
		}
		if (table->table)
			free(table->table);
		table->table = NULL;
		table->n_entries = 0;
		table->n_slots = 0;
	}
}
