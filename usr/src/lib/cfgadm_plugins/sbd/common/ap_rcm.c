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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <macros.h>
#include <errno.h>
#include <kstat.h>
#include <sys/kmem.h>
#include <dlfcn.h>
#include <libdevinfo.h>
#include <librcm.h>
#include <libintl.h>
#define	CFGA_PLUGIN_LIB
#include <config_admin.h>
#include <sys/sbd_ioctl.h>
#include "ap.h"

typedef int32_t	cpuid_t;

typedef struct {
	int valid;
	cfga_stat_t ostate;
	int ncap;
	union {
		long npages;
		cpuid_t cpuid[SBD_MAX_CORES_PER_CMP];
	} type;
} cap_info_t;

typedef struct {
	int firstcm;		/* first component to operate on */
	int lastcm;		/* last component to operate on */
	void *lib;
	char **rlist;
	cap_info_t *capinfo;
	int ncpus;		/* # of CPUs in cpuids list */
	cpuid_t *cpuids;	/* List of cpuids */
	int capcpus;		/* # of CPUs - tracking capacity */
	int cappages;		/* # of memory pages - tracking capacity */
	rcm_handle_t *hd;
	rcm_info_t *rinfo;
	rcm_info_tuple_t *infot;
	int (*alloc_handle)(char *, uint_t, void *, rcm_handle_t **);
	void (*free_handle)(rcm_handle_t *);
	int (*get_info)(rcm_handle_t *, char *, uint_t, rcm_info_t **);
	void (*free_info)(rcm_info_t *);
	rcm_info_tuple_t *(*info_next)(rcm_info_t *, rcm_info_tuple_t *);
	int (*info_state)(rcm_info_tuple_t *);
	pid_t (*info_pid)(rcm_info_tuple_t *);
	const char *(*info_error)(rcm_info_tuple_t *);
	const char *(*info_info)(rcm_info_tuple_t *);
	const char *(*info_rsrc)(rcm_info_tuple_t *);
	int (*request_offline_list)(rcm_handle_t *, char **, uint_t,
	    rcm_info_t **);
	int (*notify_online_list)(rcm_handle_t *, char **, uint_t,
	    rcm_info_t **);
	int (*request_suspend)(rcm_handle_t *, char *, uint_t, timespec_t *,
		rcm_info_t **);
	int (*notify_resume)(rcm_handle_t *, char *, uint_t, rcm_info_t **);
	int (*notify_remove_list)(rcm_handle_t *, char **, uint_t,
	    rcm_info_t **);
	int (*request_capacity_change)(rcm_handle_t *, char *, uint_t,
		nvlist_t *, rcm_info_t **);
	int (*notify_capacity_change)(rcm_handle_t *, char *, uint_t,
		nvlist_t *, rcm_info_t **);
} rcmd_t;

static char *
ap_rcm_ops[] = {
	"rcm_alloc_handle",
	"rcm_free_handle",
	"rcm_get_info",
	"rcm_free_info",
	"rcm_info_next",
	"rcm_info_state",
	"rcm_info_pid",
	"rcm_info_error",
	"rcm_info_info",
	"rcm_info_rsrc",
	"rcm_request_offline_list",
	"rcm_notify_online_list",
	"rcm_request_suspend",
	"rcm_notify_resume",
	"rcm_notify_remove_list",
	"rcm_request_capacity_change",
	"rcm_notify_capacity_change",
	NULL
};

#define	ALLOC_HANDLE		0
#define	FREE_HANDLE		1
#define	GET_INFO		2
#define	FREE_INFO		3
#define	INFO_TUPLE_NEXT		4
#define	INFO_TUPLE_STATE	5
#define	INFO_TUPLE_ID		6
#define	INFO_TUPLE_ERROR	7
#define	INFO_TUPLE_INFO		8
#define	INFO_TUPLE_RSRC		9
#define	REQUEST_OFFLINE		10
#define	NOTIFY_ONLINE		11
#define	REQUEST_SUSPEND		12
#define	NOTIFY_RESUME		13
#define	NOTIFY_REMOVE		14
#define	REQUEST_CAP_CHANGE	15
#define	NOTIFY_CAP_CHANGE	16

/*
 * There is no consumer for SUNW_OS. This is defined here
 * for generic OS quiescence.
 */
#define	OS	"SUNW_OS"	/* XXX */

/* Max width of an RCM formatted message line */
#define	RCM_MAX_FORMAT	80

#ifdef	__sparcv9
#define	RCMLIB	"/lib/sparcv9/librcm.so";
#elif defined(__amd64)
#define	RCMLIB	"/lib/amd64/librcm.so";
#else
#define	RCMLIB	"/lib/librcm.so";
#endif

static cfga_err_t
ap_capinfo(apd_t *a, int firstcm, int lastcm, cap_info_t **capinfo)
{
	int cm;
	int ncm;
	void *cap;
	int *ncap;
	cfga_stat_t *os;
	cap_info_t *cinfo, *cp;

	DBG("ap_capinfo(%p)\n", (void *)a);

	if (capinfo == NULL) {
		ap_err(a, ERR_PLUGIN, "null capinfo");
		return (CFGA_LIB_ERROR);
	}

	/*
	 * Assume there are components with valid capacity
	 * information and allocate space for them.  If there
	 * are none at the end, free the allocated space.
	 */
	ncm = lastcm - firstcm + 1;

	cinfo = (cap_info_t *)calloc(ncm, sizeof (cap_info_t));
	if (cinfo == NULL) {
		ap_err(a, ERR_NOMEM);
		return (CFGA_LIB_ERROR);
	}

	*capinfo = NULL;
	ncm = 0;
	for (cp = cinfo, cm = firstcm; cm <= lastcm; cm++, cp++) {
		os = &cp->ostate;
		ncap = &cp->ncap;

		switch (ap_cm_type(a, cm)) {
		case AP_CPU:
		case AP_CMP:
			cap = (void *)(cp->type.cpuid);
			break;
		case AP_MEM:
			cap = (void *)&(cp->type.npages);
			break;
		default:
			continue;
		}
		/*
		 * Remember which components have valid
		 * capacity information.
		 */
		if (ap_cm_capacity(a, cm, cap, ncap, os)) {
			cp->valid = 1;
			ncm++;
		}
	}

	if (ncm == 0)
		free(cinfo);
	else
		*capinfo = cinfo;

	return (CFGA_OK);
}

static int
getsyscpuids(int *ncpuids, cpuid_t **cpuids)
{
	int		ncpu;
	int		maxncpu;
	kstat_t		*ksp;
	kstat_ctl_t	*kc = NULL;
	cpuid_t		*cp;

	DBG("getsyscpuids\n");

	if ((maxncpu = sysconf(_SC_NPROCESSORS_MAX)) == -1 ||
	    (kc = kstat_open()) == NULL ||
	    (cp = (cpuid_t *)calloc(maxncpu, sizeof (cpuid_t))) == NULL) {
		/* if calloc failed, clean up kstats */
		if (kc != NULL) {
			(void) kstat_close(kc);
		}
		return (-1);
	}

	DBG("syscpuids: ");
	for (ncpu = 0, ksp = kc->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		if (strcmp(ksp->ks_module, "cpu_info") == 0) {
			cp[ncpu++] = ksp->ks_instance;
			DBG("%d ", ksp->ks_instance);
		}
	}
	DBG("\n");

	(void) kstat_close(kc);
	*cpuids = cp;
	*ncpuids = ncpu;
	return (0);
}

cfga_err_t
ap_rcm_init(apd_t *a)
{
	int i;
	char *err;
	char *rcmlib;
	void *sym;
	void *lib;
	char **op;
	rcmd_t *rcm;
	cfga_err_t rc;
	struct stat buf;

	DBG("ap_rcm_init(%p)\n", (void *)a);

	/*
	 * If the initial command is status, or the RCM feature is not
	 * available, or the RCM interface has already been initialized,
	 * just return.
	 */

	if ((a->statonly != 0) || (a->norcm != 0) ||
	    ((rcm = (rcmd_t *)a->rcm) != NULL)) {
		return (CFGA_OK);
	}

	rcmlib = RCMLIB;
	rc = CFGA_LIB_ERROR;

	DBG("Looking for %s\n", rcmlib);
	/*
	 * If the library is not present, there is nothing more
	 * to do.  The RCM offline/suspend steps become no-ops
	 * in that case.
	 */
	if (stat(rcmlib, &buf) == -1) {
		if (errno == ENOENT) {
			a->norcm++;
			ap_msg(a, MSG_NORCM);
			return (CFGA_OK);
		} else {
			ap_err(a, ERR_STAT, rcmlib);
			return (rc);
		}
	}
	DBG("%s found\n", rcmlib);

	if ((a->rcm = calloc(1, sizeof (rcmd_t))) == NULL) {
		ap_err(a, ERR_NOMEM);
		return (rc);
	}

	rcm = (rcmd_t *)a->rcm;

	if ((lib = dlopen(rcmlib, RTLD_NOW)) == NULL) {
		if ((err = dlerror()) != NULL)
			err = strdup(err);
		ap_err(a, ERR_LIB_OPEN, rcmlib, err);
		if (err != NULL)
			free(err);
		return (rc);
	}

	rcm->lib = lib;

	for (i = 0, op = ap_rcm_ops; *op != NULL; op++, i++) {
		if ((sym = dlsym(lib, *op)) == NULL) {
			ap_err(a, ERR_LIB_SYM, rcmlib, *op);
			return (rc);
		}
		switch (i) {
		case ALLOC_HANDLE:
			rcm->alloc_handle = (int(*)
			    (char *, uint_t, void *, rcm_handle_t **))sym;
			break;
		case FREE_HANDLE:
			rcm->free_handle = (void (*)(rcm_handle_t *))sym;
			break;
		case GET_INFO:
			rcm->get_info = (int (*)
			    (rcm_handle_t *, char *, uint_t, rcm_info_t **))sym;
			break;
		case FREE_INFO:
			rcm->free_info = (void (*)(rcm_info_t *))sym;
			break;
		case INFO_TUPLE_NEXT:
			rcm->info_next = (rcm_info_tuple_t *(*)
			    (rcm_info_t *, rcm_info_tuple_t *))sym;
			break;
		case INFO_TUPLE_STATE:
			rcm->info_state = (int (*)(rcm_info_tuple_t *))sym;
			break;
		case INFO_TUPLE_ID:
			rcm->info_pid = (pid_t (*)(rcm_info_tuple_t *))sym;
			break;
		case INFO_TUPLE_ERROR:
			rcm->info_error = (const char *(*)
			    (rcm_info_tuple_t *))sym;
			break;
		case INFO_TUPLE_INFO:
			rcm->info_info = (const char *(*)
			    (rcm_info_tuple_t *))sym;
			break;
		case INFO_TUPLE_RSRC:
			rcm->info_rsrc = (const char *(*)
			    (rcm_info_tuple_t *))sym;
			break;
		case REQUEST_OFFLINE:
			rcm->request_offline_list = (int (*)
			    (rcm_handle_t *, char **, uint_t,
			    rcm_info_t **))sym;
			break;
		case NOTIFY_ONLINE:
			rcm->notify_online_list = (int (*)
			    (rcm_handle_t *, char **, uint_t,
			    rcm_info_t **))sym;
			break;
		case REQUEST_SUSPEND:
			rcm->request_suspend = (int (*)
			    (rcm_handle_t *, char *, uint_t,
			    timespec_t *, rcm_info_t **))sym;
			break;
		case NOTIFY_RESUME:
			rcm->notify_resume = (int (*)
			    (rcm_handle_t *, char *, uint_t,
			    rcm_info_t **))sym;
			break;
		case NOTIFY_REMOVE:
			rcm->notify_remove_list = (int (*)
			    (rcm_handle_t *, char **, uint_t,
			    rcm_info_t **))sym;
			break;
		case REQUEST_CAP_CHANGE:
			rcm->request_capacity_change = (int (*)
			    (rcm_handle_t *, char *, uint_t,
			    nvlist_t *, rcm_info_t **))sym;
			break;
		case NOTIFY_CAP_CHANGE:
			rcm->notify_capacity_change = (int (*)
			    (rcm_handle_t *, char *, uint_t,
			    nvlist_t *, rcm_info_t **))sym;
			break;
		default:
			break;
		}
	}

	if (rcm->alloc_handle == NULL ||
	    (*rcm->alloc_handle)(NULL, RCM_NOPID, NULL, &rcm->hd)
	    != RCM_SUCCESS) {
		ap_err(a, ERR_RCM_HANDLE);
		return (CFGA_LIB_ERROR);
	}

	/*
	 * Offlining/onlining a board means offlining/onlining
	 * all components on the board.  When operating on a
	 * single component no component sequence number is
	 * needed since the default is the current (target)
	 * component.
	 */
	if (a->tgt == AP_BOARD) {
		rcm->firstcm = 0;
		rcm->lastcm = a->ncm - 1;
	} else {
		rcm->firstcm = CM_DFLT;
		rcm->lastcm = CM_DFLT;
	}

	if (rcm->cpuids == NULL) {
		int cm;
		int ncpu;

		/*
		 * Allocate space for the cpu capacity change info.
		 * Not every cpu may be relevant to the capacity
		 * request, but allocating for the maximum makes
		 * it easier, and the space is insignifcant.
		 */
		for (ncpu = 0, cm = rcm->firstcm; cm <= rcm->lastcm; cm++) {

			ap_target_t type = ap_cm_type(a, cm);

			if ((type == AP_CPU) || (type == AP_CMP)) {
				ncpu += ap_cm_ncap(a, cm);
			}
		}

		rcm->ncpus = ncpu;
		if ((rcm->cpuids = (cpuid_t *)calloc(ncpu, sizeof (cpuid_t)))
		    == NULL) {
			ap_err(a, ERR_NOMEM);
			return (CFGA_LIB_ERROR);
		}
	}

	/*
	 * Remember initial capacity information.
	 * This information is based on the initial
	 * state of the ap_id, i.e. before any
	 * state change change operations were
	 * executed.  We will later get the
	 * current capacity information in order
	 * to figure out exactly what has changed
	 * as the result of the executed command
	 * sequence.
	 */
	rc = ap_capinfo(a, rcm->firstcm, rcm->lastcm, &rcm->capinfo);

	rcm->capcpus = sysconf(_SC_NPROCESSORS_CONF);
	rcm->cappages = sysconf(_SC_PHYS_PAGES);

	return (rc);
}

void
ap_rcm_fini(apd_t *a)
{
	rcmd_t *rcm;
	char **rp;

	DBG("ap_rcm_fini(%p)\n", (void *)a);

	if ((rcm = (rcmd_t *)a->rcm) == NULL)
		return;

	if (rcm->hd)
		(*rcm->free_handle)(rcm->hd);

	(void) dlclose(rcm->lib);

	/*
	 * Free all the names in the resource list, followed
	 * by the resource list itself.
	 */
	if (rcm->rlist)
		for (rp = rcm->rlist; *rp; rp++)
			s_free(*rp);
	s_free(rcm->rlist);
	s_free(rcm->cpuids);
	s_free(rcm->capinfo);
	s_free(a->rcm);
}

static cfga_err_t
ap_rcm_rlist(apd_t *a, int firstcm, int lastcm, char ***rlist, int cmd)
{
	int n;
	int cm;
	int ncap;
	char *path;
	char *cpuname;
	char **rp;

	DBG("ap_rcm_rlist(%p)\n", (void *)a);

	/*
	 * Allocate space for the maximum number of components
	 * that can be affected by this operation.
	 */
	for (ncap = 0, cm = firstcm; cm <= lastcm; cm++) {
		ncap += ap_cm_ncap(a, cm);
	}

	DBG("ncap=%d\n", ncap);

	if ((rp = (char **)calloc(ncap + 1, sizeof (char *))) == NULL) {
		ap_err(a, ERR_NOMEM);
		return (CFGA_LIB_ERROR);
	}

	n = 12;	/* SUNW_cpu/cpuCCC */
		/* <--- 12 --->    */
	cpuname = "SUNW_cpu/cpuCCC";
	/*
	 * Set the RCM resource name for each component:
	 *
	 * io:		<device-path>
	 * cpu:		SUNW_cpu/cpu<cpuid>
	 *
	 */
	for (ncap = 0, cm = firstcm; cm <= lastcm; cm++) {
		switch (ap_cm_type(a, cm)) {
		case AP_CPU:
		case AP_CMP: {
			int		i;
			int		len;
			cap_info_t	cap;
			cfga_stat_t	os;
			cpuid_t		*cpuid;
			int		*nc;
			cap_info_t	*prevcap;
			rcmd_t		*rcm;
			int		allow_op;
			int		capindex;

			cpuid = cap.type.cpuid;
			nc = &cap.ncap;

			/*
			 * See if the request target is a single
			 * (default) component
			 */
			capindex = (cm == CM_DFLT) ? 0 : cm;

			/* Get the previous capacity info */
			rcm = (rcmd_t *)a->rcm;
			prevcap = rcm->capinfo;

			if (!ap_cm_capacity(a, cm, cpuid, nc, &os)) {
				break;
			}

			len = (strlen(cpuname) - n) + 1;

			/*
			 * For CMD_RCM_OFFLINE and REMOVE, add the CPU to the
			 * list if it is currently configured. For
			 * CMD_RCM_ONLINE, do so only if the state has changed
			 * to CFGA_STAT_CONFIGURED.
			 */
			allow_op = 0;
			if ((cmd == CMD_RCM_OFFLINE) ||
			    (cmd == CMD_RCM_REMOVE)) {
				if (os == CFGA_STAT_CONFIGURED)
					allow_op = 1;
			} else {
				if ((os == CFGA_STAT_CONFIGURED) &&
				    ((prevcap == NULL) ||
				    (prevcap[capindex].ostate != os)))
					allow_op = 1;
			}

			if (allow_op) {
				for (i = 0; i < *nc; i++) {
					if ((path = strdup(cpuname)) == NULL) {
						ap_err(a, ERR_NOMEM);
						return (CFGA_LIB_ERROR);
					}
					(void) snprintf(&path[n], len, "%d",
					    cpuid[i]);

					DBG("rp[%d]=%s\n", ncap, path);
					rp[ncap++] = path;
				}
			}
			break;
		}
		case AP_IO:
			if ((path = ap_cm_devpath(a, cm)) != NULL) {
				DBG("rp[%d]=%s\n", ncap, path);
				rp[ncap++] = path;
			}
			break;
		case AP_MEM:
			/*
			 * Nothing to do for AP_MEM since only capacity
			 * change notifications apply to SUNW_memory
			 */
		default:
			break;
		}
	}

	rp[ncap] = NULL;
	if (rlist)
		*rlist = rp;
	return (CFGA_OK);
}

/*
 * Returns 1 if the cpu ID 'cpuid' is in the list of CPU IDs
 * 'list' of length 'length'. Returns 0 otherwise.
 */
static int
is_cpu_in_list(cpuid_t cpuid, cpuid_t *list, int length)
{
	int i;

	DBG("is_cpu_in_list\n");

	if (list == NULL)
		return (0);

	for (i = 0; i < length; i++) {
		if (list[i] == cpuid)
			return (1);
	}
	return (0);
}

static int
ap_rcm_cap_cpu(apd_t *a, rcmd_t *rcm, rcm_handle_t *hd, uint_t flags,
	rcm_info_t **rinfo, int cmd, int change)
{
	int i;
	int rv = RCM_FAILURE;
	int ncpuids;
	int oldncpuids;
	int newncpuids;
	char buf[32];
	const char *fmt;
	size_t size;
	nvlist_t *nvl = NULL;
	cpuid_t *cpuids = NULL;
	cpuid_t *oldcpuids = NULL;
	cpuid_t *newcpuids = NULL;

	DBG("ap_rcm_cap_cpu(%p)\n", (void *)a);

	/*
	 * Get the current number of configured cpus.
	 */
	if (getsyscpuids(&ncpuids, &cpuids) == -1)
		return (rv);
	else if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		free(cpuids);
		goto done;
	}

	if (change == 1)
		fmt = "(%d cpu)";
	else
		fmt = "(%d cpus)";

	size = sizeof (cpuid_t);

	if (cmd == CMD_RCM_CAP_DEL) {
		/*
		 * A delete request. rcm->cpuids represents the
		 * cpus that will be unconfigured. The current
		 * set of cpus, before the unconfigure operation,
		 * are the old CPUs. The new CPUs are those
		 * that would remain.
		 */
		oldncpuids = ncpuids;
		oldcpuids = cpuids;

		/*
		 * Fill newcpuids with the CPU IDs in the cpuids array,
		 * but not in rcm->cpuids.
		 */
		newcpuids = (cpuid_t *)calloc(ncpuids, size);
		if (newcpuids == NULL)
			goto done;

		newncpuids = 0;
		for (i = 0; i < ncpuids; i++) {
			if (!is_cpu_in_list(cpuids[i], rcm->cpuids, change))
				newcpuids[newncpuids++] = cpuids[i];
		}
	} else if (cmd == CMD_RCM_CAP_NOTIFY) {
		/*
		 * An unconfigure capacity change notification. This
		 * notification is sent after a DR unconfigure, whether
		 * or not the DR was successful. rcm->cpuids represents
		 * the CPUs that have been unconfigured.
		 */

		/* New CPU IDs are the CPUs configured right now. */
		newncpuids = ncpuids;
		newcpuids = cpuids;

		/*
		 * Old CPU IDs are the CPUs configured right now
		 * in addition to those that have been unconfigured.
		 * We build the old CPU ID list by concatenating
		 * cpuids and rcm->cpuids.
		 */
		oldcpuids = (cpuid_t *)calloc(ncpuids + change, size);
		if (oldcpuids == NULL)
			goto done;

		oldncpuids = 0;
		for (i = 0; i < ncpuids; i++) {
			if (!is_cpu_in_list(cpuids[i], rcm->cpuids, change))
				oldcpuids[oldncpuids++] = cpuids[i];
		}
		for (i = 0; i < change; i++)
			oldcpuids[oldncpuids++] = rcm->cpuids[i];
	} else {
		DBG("ap_rcm_cap_cpu: CPU capacity, old = %d, new = %d \n",
		    rcm->capcpus, ncpuids);
		if (rcm->capcpus == ncpuids) {
			/* No real change in CPU capacity */
			rv = RCM_SUCCESS;
			goto done;
		}

		/*
		 * An add notification.  rcm->cpuids represents the
		 * cpus that have been configured.  The current
		 * set of cpus, after the configure operation,
		 * are the new CPU IDs.
		 */
		newncpuids = ncpuids;
		newcpuids = cpuids;

		/*
		 * Fill oldcpuids with the CPU IDs in the cpuids array,
		 * but not in rcm->cpuids.
		 */
		oldcpuids = (cpuid_t *)calloc(ncpuids, size);
		if (oldcpuids == NULL)
			goto done;

		oldncpuids = 0;
		for (i = 0; i < ncpuids; i++) {
			if (!is_cpu_in_list(cpuids[i], rcm->cpuids, change))
				oldcpuids[oldncpuids++] = cpuids[i];
		}
	}

	DBG("oldcpuids: ");
	for (i = 0; i < oldncpuids; i++)
		DBG("%d ", oldcpuids[i]);
	DBG("\n");
	DBG("change   : ");
	for (i = 0; i < change; i++)
		DBG("%d ", rcm->cpuids[i]);
	DBG("\n");
	DBG("newcpuids: ");
	for (i = 0; i < newncpuids; i++)
		DBG("%d ", newcpuids[i]);
	DBG("\n");

	if (nvlist_add_string(nvl, "state", "capacity") != 0 ||
	    nvlist_add_int32(nvl, "old_total", oldncpuids) != 0 ||
	    nvlist_add_int32(nvl, "new_total", newncpuids) != 0 ||
	    nvlist_add_int32_array(nvl, "old_cpu_list", oldcpuids,
	    oldncpuids) != 0 ||
	    nvlist_add_int32_array(nvl, "new_cpu_list", newcpuids,
	    newncpuids) != 0)
		goto done;

	(void) snprintf(buf, sizeof (buf), fmt, change);
	ap_msg(a, MSG_ISSUE, cmd, buf);

	if (cmd == CMD_RCM_CAP_DEL) {
		rv = (*rcm->request_capacity_change)(hd, "SUNW_cpu",
		    flags, nvl, rinfo);
	} else {
		rv = (*rcm->notify_capacity_change)(hd, "SUNW_cpu",
		    flags & ~RCM_FORCE, nvl, rinfo);
	}

done:
	nvlist_free(nvl);
	s_free(oldcpuids);
	s_free(newcpuids);
	return (rv);
}

static int
ap_rcm_cap_mem(apd_t *a, rcmd_t *rcm, rcm_handle_t *hd, uint_t flags,
	rcm_info_t **rinfo, int cmd, long change)
{
	int rv;
	int pgsize;
	long oldpages;
	long newpages;
	long currpages;
	char buf[32];
	nvlist_t *nvl;

	DBG("ap_rcm_cap_mem(%p)\n", (void *)a);

	/*
	 * Get the current amount of configured memory.
	 */
	if ((pgsize = sysconf(_SC_PAGE_SIZE)) == -1 ||
	    (currpages = sysconf(_SC_PHYS_PAGES)) == -1 ||
	    nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) > 0)
		return (RCM_FAILURE);

	/*
	 * If this is a (delete) request, change represents
	 * the amount of capacity that will be deleted from the
	 * system.  If this is an (add) notification, change
	 * represents the amount of capacity that has already
	 * been added to the system.
	 */
	if (cmd == CMD_RCM_CAP_DEL) {
		oldpages = currpages;
		newpages = currpages - change;
	} else if (cmd == CMD_RCM_CAP_NOTIFY) {
		newpages = currpages;
		oldpages = rcm->cappages;
	} else {
		if (rcm->cappages == currpages) {
			/* No real change in memory capacity */
			DBG("ap_rcm_cap_mem: no change in capacity.\n");
			nvlist_free(nvl);
			return (RCM_SUCCESS);
		}

		oldpages = currpages - change;
		newpages = currpages;
	}

	DBG("ap_rcm_cap_mem: Memory capacity, old = %ld, new = %ld\n",
	    oldpages, newpages);

	if (nvlist_add_string(nvl, "state", "capacity") != 0 ||
	    nvlist_add_int32(nvl, "page_size", pgsize) != 0 ||
	    nvlist_add_int32(nvl, "old_pages", oldpages) != 0 ||
	    nvlist_add_int32(nvl, "new_pages", newpages) != 0) {
		nvlist_free(nvl);
		return (RCM_FAILURE);
	}

	(void) snprintf(buf, sizeof (buf), "(%ld pages)", change);
	ap_msg(a, MSG_ISSUE, cmd, buf);

	if (cmd == CMD_RCM_CAP_DEL) {
		rv = (*rcm->request_capacity_change)(hd, "SUNW_memory",
		    flags, nvl, rinfo);
	} else {
		rv = (*rcm->notify_capacity_change)(hd, "SUNW_memory",
		    flags & ~RCM_FORCE, nvl, rinfo);
	}

	nvlist_free(nvl);

	return (rv);
}

static cfga_err_t
ap_rcm_request_cap(apd_t *a, rcmd_t *rcm, rcm_handle_t *hd,
	int *rv, uint_t flags, rcm_info_t **rinfo)
{
	int cm;
	int ncpus;
	long npages;
	cap_info_t *capinfo;
	ap_target_t type;

	DBG("ap_rcm_request_cap(%p)\n", (void *)a);

	if ((capinfo = rcm->capinfo) == NULL) {
		ap_err(a, ERR_PLUGIN, "null capinfo");
		return (CFGA_LIB_ERROR);
	}

	ncpus = npages = 0;

	for (cm = rcm->firstcm; cm <= rcm->lastcm; cm++) {
		int i, j;

		/*
		 * See if the request target is a single
		 * (default) component
		 */
		i = (cm == CM_DFLT) ? 0 : cm;

		/*
		 * We are interested only in those components
		 * in the configured state since they represent
		 * available capacity.
		 */
		type = ap_cm_type(a, cm);
		if (capinfo[i].valid == 0 ||
		    capinfo[i].ostate != CFGA_STAT_CONFIGURED)
			continue;
		else if ((type == AP_CPU) || (type == AP_CMP)) {
			for (j = 0; j < capinfo[i].ncap; j++) {
				rcm->cpuids[ncpus++] = capinfo[i].type.cpuid[j];
			}
		} else if (type == AP_MEM)
			npages += capinfo[i].type.npages;
	}

	if (ncpus && ((*rv = ap_rcm_cap_cpu(a, rcm, hd, flags, rinfo,
	    CMD_RCM_CAP_DEL, ncpus)) != RCM_SUCCESS)) {
		return (CFGA_LIB_ERROR);
	}
	if (npages && ((*rv = ap_rcm_cap_mem(a, rcm, hd, flags, rinfo,
	    CMD_RCM_CAP_DEL, npages)) != RCM_SUCCESS)) {
		return (CFGA_LIB_ERROR);
	}

	return (CFGA_OK);
}

static cfga_err_t
ap_rcm_add_cap(apd_t *a, rcmd_t *rcm, rcm_handle_t *hd,
	int *rv, uint_t flags, rcm_info_t **rinfo)
{
	int cm;
	int ncpus;
	long npages;
	cap_info_t *capinfo, *prevcapinfo;
	cfga_err_t rc;

	DBG("ap_rcm_add_cap(%p)\n", (void *)a);

	/* Get the new capacity info to figure out what has changed */
	if ((rc = ap_capinfo(a, rcm->firstcm, rcm->lastcm, &capinfo)) !=
	    CFGA_OK)
		return (rc);

	if (capinfo == NULL) {
		DBG("no pertinent capacity info\n");
		return (CFGA_OK);
	}

	ncpus = npages = 0;
	prevcapinfo = rcm->capinfo;

	for (cm = rcm->firstcm; cm <= rcm->lastcm; cm++) {
		int i, j;
		cfga_stat_t os, prevos;
		int prevvalidity;
		ap_target_t type;

		/*
		 * See if the request target is a single
		 * (default) component
		 */
		i = cm == CM_DFLT ? 0 : cm;

		os = capinfo[i].ostate;
		if (prevcapinfo == NULL) {
			prevos = CFGA_STAT_EMPTY;
			prevvalidity = 1;
		} else {
			prevos = prevcapinfo[i].ostate;
			prevvalidity = prevcapinfo[i].valid;
		}

		type = ap_cm_type(a, cm);

		DBG("cm=%d valid=%d type=%d, prevos=%d os=%d\n",
		    cm, prevvalidity, type, prevos, os);

		/*
		 * We are interested only in those components
		 * whose states have changed to configured as
		 * the result of the current cfgadm request.
		 */
		if (prevvalidity == 0 || os != CFGA_STAT_CONFIGURED) {
			capinfo[i].valid = 0;
			continue;
		} else if (prevos != CFGA_STAT_CONFIGURED) {
			/*
			 * The occupant state is configured, and
			 * the previous occupant state was not.
			 */
			if ((type == AP_CPU) || (type == AP_CMP)) {
				for (j = 0; j < capinfo[i].ncap; j++) {
					rcm->cpuids[ncpus++] =
					    capinfo[i].type.cpuid[j];
				}
			} else if (type == AP_MEM)
				npages += capinfo[i].type.npages;
		}
	}
	free(capinfo);

	if (ncpus && ((*rv = ap_rcm_cap_cpu(a, rcm, hd, flags, rinfo,
	    CMD_RCM_CAP_ADD, ncpus)) != RCM_SUCCESS)) {
		return (CFGA_LIB_ERROR);
	}
	if (npages && ((*rv = ap_rcm_cap_mem(a, rcm, hd, flags, rinfo,
	    CMD_RCM_CAP_ADD, npages)) != RCM_SUCCESS)) {
		return (CFGA_LIB_ERROR);
	}

	return (CFGA_OK);
}

/*
 * ap_rcm_notify_cap:
 *
 * This routine handles the CMD_RCM_CAP_NOTIFY command. It
 * is called after a successful/failed DR unconfigure
 * operation. It filters out components that have changed
 * and passes this information on to ap_rcm_cap_{cpu,mem}.
 *
 * ap_rcm_cap_{cpu,mem} will still be called if all the
 * components have not changed and at least one {cpu,mem}
 * component was originally configured.
 */
static cfga_err_t
ap_rcm_notify_cap(apd_t *a, rcmd_t *rcm, rcm_handle_t *hd,
	int *rv, uint_t flags, rcm_info_t **rinfo)
{
	cfga_err_t  rc;
	cap_info_t  *capinfo;
	cap_info_t  *prevcapinfo;
	int	    cm;
	long	    npages	= 0;
	int	    ncpus	= 0;
	int	    prev_mem	= 0; /* # of prev. configured mem components */
	int	    prev_cpus	= 0; /* # of prev. configured CPUs */

	DBG("ap_rcm_notify_cap(%p)\n", (void *)a);

	/* Get the new capacity info to figure out what has changed */
	if ((rc = ap_capinfo(a, rcm->firstcm, rcm->lastcm, &capinfo)) !=
	    CFGA_OK)
		return (rc);

	if (capinfo == NULL) {
		DBG("no pertinent capacity info\n");
		return (CFGA_OK);
	}

	/* The original capacity info */
	prevcapinfo = rcm->capinfo;

	/*
	 * Cycle through all components that we are operating
	 * on. Record which components' occupant states have
	 * changed.
	 */
	for (cm = rcm->firstcm; cm <= rcm->lastcm; cm++) {
		int i;
		cfga_stat_t prevos, os;
		ap_target_t type;
		int prev_conf = 0;
		int now_conf  = 0;

		/*
		 * See if the request target is a single
		 * (default) component
		 */
		i = cm == CM_DFLT ? 0 : cm;

		os = capinfo[i].ostate;

		if (prevcapinfo == NULL) {
			prevos = CFGA_STAT_EMPTY;
		} else {
			prevos = prevcapinfo[i].ostate;
			if (prevcapinfo[i].valid == 0) {
				DBG("ap_rcm_notify_cap: skipping component "
				    "due to prevvalidity == 0\n");
				continue;
			}
		}

		type = ap_cm_type(a, cm);

		prev_conf = (prevos == CFGA_STAT_CONFIGURED);
		now_conf  = (os == CFGA_STAT_CONFIGURED);

		/*
		 * Build up rcm->cpuids with the IDs of CPUs that
		 * have been removed. Record the number of removed
		 * CPUs and pages.
		 */
		if (type == AP_CPU || type == AP_CMP) {
			if (prev_conf)
				prev_cpus++;
			if (prev_conf && !now_conf) {
				int j;
				for (j = 0; j < capinfo[i].ncap; j++) {
					rcm->cpuids[ncpus++] =
					    capinfo[i].type.cpuid[j];
				}
			}
		} else if (type == AP_MEM) {
			if (prev_conf)
				prev_mem++;
			if (prev_conf && !now_conf)
				npages += capinfo[i].type.npages;
		}
	}
	free(capinfo);

	/*
	 * If any CPU or memory components were operated on,
	 * successfully or not, the rcm_notify_capacity_change()
	 * routine must be called.
	 */

	if (prev_cpus) {
		*rv = ap_rcm_cap_cpu(a, rcm, hd, flags, rinfo,
		    CMD_RCM_CAP_NOTIFY, ncpus);

		if (*rv != RCM_SUCCESS)
			return (CFGA_LIB_ERROR);
	}

	if (prev_mem) {
		*rv = ap_rcm_cap_mem(a, rcm, hd, flags, rinfo,
		    CMD_RCM_CAP_NOTIFY, npages);

		if (*rv != RCM_SUCCESS)
			return (CFGA_LIB_ERROR);
	}

	return (CFGA_OK);
}

cfga_err_t
ap_rcm_ctl(apd_t *a, int cmd)
{
	int i;
	int rv;
	int noop;
	int ncpus;
	int cm;
	uint_t flags;
	char *rsrc;
	char **rlist;
	rcmd_t *rcm;
	rcm_info_t *rinfo;
	rcm_handle_t *hd;
	cfga_err_t rc;
	cpuid_t *growcpuids;

	DBG("ap_rcm_ctl(%p)\n", (void *)a);

	if ((rcm = (rcmd_t *)a->rcm) == NULL) {
		ap_msg(a, MSG_SKIP, cmd, a->target);
		return (CFGA_OK);
	}

	hd = rcm->hd;
	rv = RCM_SUCCESS;
	rc = CFGA_OK;
	if (ap_getopt(a, OPT_FORCE))
		flags = RCM_FORCE;
	else
		flags = 0;
	rinfo = NULL;
	rlist = NULL;
	rsrc = NULL;
	noop = 0;

	switch (cmd) {
	case CMD_RCM_CAP_DEL:
		if (rcm->capinfo == NULL)
			noop++;
		else
			rc = ap_rcm_request_cap(a, rcm, hd, &rv, flags, &rinfo);
		break;
	case CMD_RCM_CAP_ADD:
		rc = ap_rcm_add_cap(a, rcm, hd, &rv, flags, &rinfo);
		break;
	case CMD_RCM_CAP_NOTIFY:
		rc = ap_rcm_notify_cap(a, rcm, hd, &rv, flags, &rinfo);
		break;
	case CMD_RCM_ONLINE:
		/* Refresh changed component states */
		if ((rc = ap_stat(a, 1)) != CFGA_OK) {
			noop++;
			break;
		}

		if (a->tgt == AP_BOARD) {
			rcm->firstcm = 0;
			rcm->lastcm = a->ncm - 1;

			/* Check if we need to grow our cpuids list */
			for (ncpus = 0, cm = rcm->firstcm; cm <= rcm->lastcm;
			    cm++) {
				ap_target_t type = ap_cm_type(a, cm);
				if ((type == AP_CPU) || (type == AP_CMP))
					ncpus += ap_cm_ncap(a, cm);
			}

			if (rcm->ncpus < ncpus) {
				if ((growcpuids =
				    (cpuid_t *)realloc(rcm->cpuids,
				    (ncpus * sizeof (cpuid_t)))) == NULL) {
					ap_err(a, ERR_NOMEM);
					return (CFGA_LIB_ERROR);
				}
				rcm->ncpus = ncpus;
				rcm->cpuids = growcpuids;
			}

		} else {
			rcm->firstcm = CM_DFLT;
			rcm->lastcm = CM_DFLT;
		}

		/*FALLTHROUGH*/

	case CMD_RCM_OFFLINE:
	case CMD_RCM_REMOVE: {
		uint_t nrsrc;

		if (cmd == CMD_RCM_REMOVE) {
			/*
			 * An unconfigure has just taken place, so
			 * refresh the changed component states.
			 */
			if ((rc = ap_stat(a, 1)) != CFGA_OK) {
				noop++;
				break;
			}
		}

		/* Check if this is an empty board, i.e. no components */
		if (a->ncm == 0) {
			noop++;
			break;
		}

		if ((rlist = rcm->rlist) == NULL) {
			rc = ap_rcm_rlist(a, rcm->firstcm, rcm->lastcm, &rlist,
			    cmd);
			if ((rc == CFGA_OK) && (rlist != NULL) &&
			    (rlist[0] != NULL)) {
				rcm->rlist = rlist;
			} else {
				/* Do not pass up empty resource list to RCM */
				noop++;
				break;
			}
		}
		for (nrsrc = 0; rlist[nrsrc] != NULL; nrsrc++)
			ap_msg(a, MSG_ISSUE, cmd, rlist[nrsrc]);
		if (cmd == CMD_RCM_OFFLINE)
			rv = (*rcm->request_offline_list)(hd, rlist, flags,
			    &rinfo);
		else if (cmd == CMD_RCM_ONLINE)
			rv = (*rcm->notify_online_list)(hd, rlist,
			    flags & ~RCM_FORCE, &rinfo);
		else
			rv = (*rcm->notify_remove_list)(hd, rlist,
			    flags & ~RCM_FORCE, &rinfo);
		break;
	}
	case CMD_RCM_SUSPEND: {
		timespec_t t;
		t.tv_sec = (time_t)0;
		t.tv_nsec = (long)0;
		rsrc = OS;
		ap_msg(a, MSG_ISSUE, cmd, rsrc);
		rv = (*rcm->request_suspend)(hd, rsrc, flags, &t, &rinfo);
		break;
	}
	case CMD_RCM_RESUME:
		rsrc = OS;
		ap_msg(a, MSG_ISSUE, cmd, rsrc);
		rv = (*rcm->notify_resume)(hd, rsrc, 0, &rinfo);
		break;
	default:
		ap_err(a, ERR_CMD_INVAL, cmd);
		return (CFGA_INVAL);
	}

	if (rv != RCM_SUCCESS) {
		rcm->rinfo = rinfo;
		rcm->infot = NULL;
		ap_err(a, ERR_RCM_CMD, cmd);
		(*rcm->free_info)(rinfo);
		if (rc == CFGA_OK)
			rc = CFGA_LIB_ERROR;	/* make sure error is set */
	}
	if ((rc == CFGA_OK) && (noop == 0)) {
		if (rlist)
			for (i = 0; rlist[i]; i++)
				ap_msg(a, MSG_DONE, cmd, rlist[i]);
		else if (rsrc)
			ap_msg(a, MSG_DONE, cmd, rsrc);
		else
			ap_msg(a, MSG_DONE, cmd, a->target);
	}

	return (rc);
}

/*
 * ap_rcm_info
 *
 * Takes an ap_id and a character pointer, and formats
 * the rcm_info_t data in the form of a table to the given character pointer.
 * Code duplicated from the scsi plugin.
 * Note: This function will go away when a generic librcm callback is
 *	implemented to format RCM messages for plugins.
 */
int
ap_rcm_info(apd_t *a, char **msg)
{
	rcmd_t *rcm;
	rcm_info_t *rinfo;
	int i;
	size_t w;
	size_t width = 0;
	size_t w_rsrc = 0;
	size_t w_info = 0;
	size_t msg_size = 0;
	uint_t tuples = 0;
	rcm_info_tuple_t *tuple = NULL;
	char *rsrc;
	char *info;
	char *newmsg;
	static char format[RCM_MAX_FORMAT];
	const char *infostr;


	DBG("ap_rcm_info(%p)\n", (void *)a);

	/* Protect against invalid arguments */
	if ((a == NULL) || ((rcm = (rcmd_t *)a->rcm) == NULL) ||
	    ((rinfo = rcm->rinfo) == NULL) || (msg == NULL)) {
		return (-1);
	}

	/* Set localized table header strings */
	rsrc = dgettext(TEXT_DOMAIN, "Resource");
	info = dgettext(TEXT_DOMAIN, "Information");

	/* A first pass, to size up the RCM information */
	while (tuple = (*rcm->info_next)(rinfo, tuple)) {
		if ((infostr = (*rcm->info_info)(tuple)) != NULL) {
			tuples++;
			if ((w = strlen((*rcm->info_rsrc)(tuple))) > w_rsrc)
				w_rsrc = w;
			if ((w = strlen(infostr)) > w_info)
				w_info = w;
		}
	}

	/* If nothing was sized up above, stop early */
	if (tuples == 0)
		return (0);

	/* Adjust column widths for column headings */
	if ((w = strlen(rsrc)) > w_rsrc)
		w_rsrc = w;
	else if ((w_rsrc - w) % 2)
		w_rsrc++;
	if ((w = strlen(info)) > w_info)
		w_info = w;
	else if ((w_info - w) % 2)
		w_info++;

	/*
	 * Compute the total line width of each line,
	 * accounting for intercolumn spacing.
	 */
	width = w_info + w_rsrc + 4;

	/* Allocate space for the table */
	msg_size = (2 + tuples) * (width + 1) + 2;
	if (*msg == NULL) {
		/* zero fill for the strcat() call below */
		*msg = calloc(msg_size, sizeof (char));
		if (*msg == NULL)
			return (-1);
	} else {
		newmsg = realloc(*msg, strlen(*msg) + msg_size);
		if (newmsg == NULL)
			return (-1);
		else
			*msg = newmsg;
	}

	/* Place a table header into the string */

	/* The resource header */
	(void) strcat(*msg, "\n");
	w = strlen(rsrc);
	for (i = 0; i < ((w_rsrc - w) / 2); i++)
		(void) strcat(*msg, " ");
	(void) strcat(*msg, rsrc);
	for (i = 0; i < ((w_rsrc - w) / 2); i++)
		(void) strcat(*msg, " ");

	/* The information header */
	(void) strcat(*msg, "  ");
	w = strlen(info);
	for (i = 0; i < ((w_info - w) / 2); i++)
		(void) strcat(*msg, " ");
	(void) strcat(*msg, info);
	for (i = 0; i < ((w_info - w) / 2); i++)
		(void) strcat(*msg, " ");

	/* Underline the headers */
	(void) strcat(*msg, "\n");
	for (i = 0; i < w_rsrc; i++)
		(void) strcat(*msg, "-");
	(void) strcat(*msg, "  ");
	for (i = 0; i < w_info; i++)
		(void) strcat(*msg, "-");

	/* Construct the format string */
	(void) snprintf(format, RCM_MAX_FORMAT, "%%-%ds  %%-%ds",
	    (int)w_rsrc, (int)w_info);

	/* Add the tuples to the table string */
	tuple = NULL;
	while ((tuple = (*rcm->info_next)(rinfo, tuple)) != NULL) {
		if ((infostr = (*rcm->info_info)(tuple)) != NULL) {
			(void) strcat(*msg, "\n");
			(void) sprintf(&((*msg)[strlen(*msg)]), format,
			    (*rcm->info_rsrc)(tuple), infostr);
		}
	}

	DBG("ap_rcm_info(%p) success\n", (void *)a);
	return (0);
}
