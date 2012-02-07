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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */


#include <sys/task.h>
#include <sys/types.h>
#include <unistd.h>

#include <ctype.h>
#include <project.h>
#include <rctl.h>
#include <secdb.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <nss_dbdefs.h>
#include <pwd.h>
#include <pool.h>
#include <libproc.h>
#include <priv.h>
#include <priv_utils.h>
#include <zone.h>
#include <sys/pool.h>
#include <sys/pool_impl.h>
#include <sys/rctl_impl.h>

static void
xstrtolower(char *s)
{
	for (; *s != '\0'; s++)
		*s = tolower(*s);
}

static void
remove_spaces(char *s)
{
	char *current;
	char *next;

	current = next = s;

	while (*next != '\0') {
		while (isspace(*next))
			next++;
		*current++ = *next++;
	}
	*current = '\0';
}

int
build_rctlblk(rctlblk_t *blk, int comp_num, char *component)
{
	char *signam;
	int sig = 0;
	uint_t act = rctlblk_get_local_action(blk, &sig);

	if (comp_num == 0) {
		/*
		 * Setting privilege level for resource control block.
		 */
		xstrtolower(component);

		if (strcmp("basic", component) == 0) {
			rctlblk_set_privilege(blk, RCPRIV_BASIC);
			return (0);
		}

		if (strcmp("priv", component) == 0 ||
		    strcmp("privileged", component) == 0) {
			rctlblk_set_privilege(blk, RCPRIV_PRIVILEGED);
			return (0);
		}

		return (-1);
	}

	if (comp_num == 1) {

		/*
		 * Setting value for resource control block.
		 */
		unsigned long long val;
		char *t;

		/* Negative numbers are not allowed */
		if (strchr(component, '-') != NULL)
			return (-1);

		errno = 0;
		val = strtoull(component, &t, 10);
		if (errno != 0 || t == component || *t != '\0')
			return (-1);

		rctlblk_set_value(blk, (rctl_qty_t)val);
		return (0);
	}

	/*
	 * Setting one or more actions on this resource control block.
	 */
	if (comp_num >= 2) {
		if (strcmp("none", component) == 0) {
			rctlblk_set_local_action(blk, 0, 0);
			return (0);
		}

		if (strcmp("deny", component) == 0) {
			act |= RCTL_LOCAL_DENY;

			rctlblk_set_local_action(blk, act, sig);

			return (0);
		}

		/*
		 * The last, and trickiest, form of action is the signal
		 * specification.
		 */
		if ((signam = strchr(component, '=')) == NULL)
			return (-1);

		*signam++ = '\0';

		if (strcmp("sig", component) == 0 ||
		    strcmp("signal", component) == 0) {
			if (strncmp("SIG", signam, 3) == 0)
				signam += 3;

			if (str2sig(signam, &sig) == -1)
				return (-1);

			act |= RCTL_LOCAL_SIGNAL;

			rctlblk_set_local_action(blk, act, sig);

			return (0);
		}
	}
	return (-1);
}

/*
 * States:
 */
#define	INPAREN		0x1

/*
 * Errors:
 */
#define	SETFAILED	(-1)
#define	COMPLETE	1
#define	NESTING		2
#define	UNCLOSED	3
#define	CLOSEBEFOREOPEN	4
#define	BADSPEC		5

static void
reinit_blk(rctlblk_t *blk, int local_action)
{
	rctlblk_set_privilege(blk, RCPRIV_PRIVILEGED);
	rctlblk_set_value(blk, 0);
	rctlblk_set_local_flags(blk, 0);
	rctlblk_set_local_action(blk, local_action, 0);
}

static int
rctl_set(char *ctl_name, char *val, struct ps_prochandle *Pr, int flags)
{
	int error = 0;
	uint_t component = 0;
	int valuecount = 0;
	uint_t state = 0;
	char *component_head;
	rctlblk_t *blk;
	rctlblk_t *ablk;
	int project_entity = 0;
	int count = 0;
	char *tmp;
	int local_act;
	rctlblk_t *rnext;
	int teardown_basic = 0;
	int teardown_priv = 0;

	/* We cannot modify a zone resource control */
	if (strncmp(ctl_name, "zone.", strlen("zone.")) == 0) {
		return (SETFAILED);
	}

	remove_spaces(val);

	if (strncmp(ctl_name, "project.", strlen("project.")) == 0) {
		project_entity = 1;
	} else if ((strncmp(ctl_name, "process.", strlen("process.")) != 0) &&
	    (strncmp(ctl_name, "task.", strlen("task.")) != 0)) {
		return (SETFAILED);
	}

	/* Determine how many attributes we'll be setting */
	for (tmp = val; *tmp != '\0'; tmp++) {
		if (*tmp == '(')
			count++;
	}
	/* Allocate sufficient memory for rctl blocks */
	if ((count == 0) || ((ablk =
	    (rctlblk_t *)malloc(rctlblk_size() * count)) == NULL)) {
		return (SETFAILED);
	}
	blk = ablk;

	/*
	 * In order to set the new rctl's local_action, we'll need the
	 * current value of global_flags.  We obtain global_flags by
	 * performing a pr_getrctl().
	 *
	 * The ctl_name has been verified as valid, so we have no reason
	 * to suspect that pr_getrctl() will return an error.
	 */
	(void) pr_getrctl(Pr, ctl_name, NULL, blk, RCTL_FIRST);


	/*
	 * Set initial local action based on global deny properties.
	 */
	rctlblk_set_privilege(blk, RCPRIV_PRIVILEGED);
	rctlblk_set_value(blk, 0);
	rctlblk_set_local_flags(blk, 0);

	if (rctlblk_get_global_flags(blk) & RCTL_GLOBAL_DENY_ALWAYS)
		local_act = RCTL_LOCAL_DENY;
	else
		local_act = RCTL_LOCAL_NOACTION;

	rctlblk_set_local_action(blk, local_act, 0);

	for (; ; val++) {

		switch (*val) {
			case '(':
				if (state & INPAREN) {
					error = NESTING;
					break;
				}

				state |= INPAREN;
				component_head = (char *)val + 1;

				break;
			case ')':
				if (state & INPAREN) {
					*val = '\0';
					if (component < 2) {
						error = BADSPEC;
						break;
					}
					if (build_rctlblk(blk, component,
					    component_head) == -1) {
						error = BADSPEC;
						break;
					}
					state &= ~INPAREN;
					component = 0;
					valuecount++;

					if (project_entity &&
					    (rctlblk_get_privilege(blk) ==
					    RCPRIV_BASIC)) {
						error = SETFAILED;
					} else {
						if (rctlblk_get_privilege(blk)
						    == RCPRIV_BASIC)
							teardown_basic = 1;

						if (rctlblk_get_privilege(blk)
						    == RCPRIV_PRIVILEGED)
							teardown_priv = 1;

						if (valuecount > count) {
							free(ablk);
							return (SETFAILED);
						}

						if (valuecount != count) {
							blk = RCTLBLK_INC(ablk,
							    valuecount);
							/* re-initialize blk */
							reinit_blk(blk,
							    local_act);
						}
					}

				} else {
					error = CLOSEBEFOREOPEN;
				}
				break;
			case ',':
				if (state & INPAREN) {
					*val = '\0';
					if (build_rctlblk(blk, component,
					    component_head) == -1)
						error = BADSPEC;

					component++;
					component_head = (char *)val + 1;

				}
				break;
			case '\0':
				if (valuecount == 0)
					error = BADSPEC;
				else if (state & INPAREN)
					error = UNCLOSED;
				else
					error = COMPLETE;
				break;
			default:
				if (!(state & INPAREN))
					error = BADSPEC;
				break;
		}

		if (error)
			break;
	}
	/* ablk points to array of rctlblk_t */

	if (valuecount == 0)
		error = BADSPEC;

	if (error != COMPLETE) {
		free(ablk);
		return (error);
	}

	/* teardown rctls if required */
	if (!project_entity) {

		if ((rnext = (rctlblk_t *)malloc(rctlblk_size())) == NULL) {
			free(ablk);
			return (SETFAILED);
		}

restart:
		if (pr_getrctl(Pr, ctl_name, NULL, rnext, RCTL_FIRST) == 0) {
			while (1) {
				if ((rctlblk_get_privilege(rnext) ==
				    RCPRIV_PRIVILEGED) &&
				    (teardown_priv == 1)) {
					(void) pr_setrctl(Pr, ctl_name, NULL,
					    rnext, RCTL_DELETE);
					goto restart;
				}
				if ((rctlblk_get_privilege(rnext) ==
				    RCPRIV_BASIC) && (teardown_basic == 1)) {
					(void) pr_setrctl(Pr, ctl_name, NULL,
					    rnext, RCTL_DELETE);
					goto restart;
				}

				if (pr_getrctl(Pr, ctl_name, rnext, rnext,
				    RCTL_NEXT) == -1)
					break;
			}
		}

		free(rnext);
	}

	/* set rctls */

	blk = ablk;

	if (project_entity) {
		if (pr_setprojrctl(Pr, ctl_name, blk, count, flags) == -1)
			error = SETFAILED;
	} else {
		valuecount = 0;
		while (valuecount < count) {
			if (pr_setrctl(Pr, ctl_name,
			    NULL, blk, RCTL_INSERT) == -1) {
				error = SETFAILED;
				break;
				}
			valuecount++;
			blk = RCTLBLK_INC(ablk, valuecount);
		}
	}



	free(ablk);

	if (error != COMPLETE)
		return (error);

	return (0);
}

static int
rctlwalkfunc(const char *name, void *data)
{

	if (strcmp(name, (char *)data) == 0)
		return (-1);
	else
		return (0);

}

/*
 * This routine determines if /dev/pool device is present on the system and
 * pools are currently enabled.  We want to do this directly from libproject
 * without using libpool's pool_get_status() routine because pools could be
 * completely removed from the system.  Return 1 if pools are enabled, or
 * 0 otherwise.  When used inside local zones, always pretend that pools
 * are disabled because binding is not allowed and we're already in the
 * right pool.
 */
static int
pools_enabled(void)
{
	pool_status_t status;
	int fd;

	if (getzoneid() != GLOBAL_ZONEID)
		return (0);
	if ((fd = open("/dev/pool", O_RDONLY)) < 0)
		return (0);
	if (ioctl(fd, POOL_STATUSQ, &status) < 0) {
		(void) close(fd);
		return (0);
	}
	(void) close(fd);
	return (status.ps_io_state);
}

/*
 * A pool_name of NULL means to attempt to bind to the default pool.
 * If the "force" flag is non-zero, the value of "system.bind-default" will be
 * ignored, and the process will be bound to the default pool if one exists.
 */
static int
bind_to_pool(const char *pool_name, pid_t pid, int force)
{
	pool_value_t *pvals[] = { NULL, NULL };
	pool_t **pools;
	uint_t nelem;
	uchar_t bval;
	pool_conf_t *conf;
	const char *nm;
	int retval;

	if ((conf = pool_conf_alloc()) == NULL)
		return (-1);
	if (pool_conf_open(conf, pool_dynamic_location(), PO_RDONLY) < 0) {
		/*
		 * Pools configuration file is corrupted; allow logins.
		 */
		pool_conf_free(conf);
		return (0);
	}
	if (pool_name != NULL && pool_get_pool(conf, pool_name) != NULL) {
		/*
		 * There was a project.pool entry, and the pool it refers to
		 * is a valid (active) pool.
		 */
		(void) pool_conf_close(conf);
		pool_conf_free(conf);
		if (pool_set_binding(pool_name, P_PID, pid) != PO_SUCCESS) {
			if (pool_error() != POE_SYSTEM)
				errno = EINVAL;
			return (-1);
		}
		return (0);
	}

	/*
	 * Bind to the pool with 'pool.default' = 'true' if
	 * 'system.bind-default' = 'true'.
	 */
	if ((pvals[0] = pool_value_alloc()) == NULL) {
		pool_conf_close(conf);
		pool_conf_free(conf);
		return (-1);
	}
	if (!force && pool_get_property(conf, pool_conf_to_elem(conf),
	    "system.bind-default", pvals[0]) != POC_BOOL ||
	    pool_value_get_bool(pvals[0], &bval) != PO_SUCCESS ||
	    bval == PO_FALSE) {
		pool_value_free(pvals[0]);
		pool_conf_close(conf);
		pool_conf_free(conf);
		errno = pool_name == NULL ? EACCES : ESRCH;
		return (-1);
	}
	(void) pool_value_set_name(pvals[0], "pool.default");
	pool_value_set_bool(pvals[0], PO_TRUE);
	if ((pools = pool_query_pools(conf, &nelem, pvals)) == NULL) {
		/*
		 * No default pools exist.
		 */
		pool_value_free(pvals[0]);
		pool_conf_close(conf);
		pool_conf_free(conf);
		errno = pool_name == NULL ? EACCES : ESRCH;
		return (-1);
	}
	if (nelem != 1 ||
	    pool_get_property(conf, pool_to_elem(conf, pools[0]), "pool.name",
	    pvals[0]) != POC_STRING) {
		/*
		 * Configuration is invalid.
		 */
		free(pools);
		pool_value_free(pvals[0]);
		(void) pool_conf_close(conf);
		pool_conf_free(conf);
		return (0);
	}
	free(pools);
	(void) pool_conf_close(conf);
	pool_conf_free(conf);
	(void) pool_value_get_string(pvals[0], &nm);
	if (pool_set_binding(nm, P_PID, pid) != PO_SUCCESS) {
		if (pool_error() != POE_SYSTEM)
			errno = EINVAL;
		retval = -1;
	} else {
		retval = 0;
	}
	pool_value_free(pvals[0]);
	return (retval);
}

/*
 * Changes the assigned project, task and resource pool of a stopped target
 * process.
 *
 * We may not have access to the project table if our target process is in
 * getprojbyname()'s execution path. Similarly, we may not be able to get user
 * information if the target process is in getpwnam()'s execution path. Thus we
 * give the caller the option of skipping these checks by providing a pointer to
 * a pre-validated project structure in proj (whose name matches project_name)
 * and taking responsibility for ensuring that the target process' owner is a
 * member of the target project.
 *
 * Callers of this function should always provide a pre-validated project
 * structure in proj unless they can be sure that the target process will never
 * be in setproject_proc()'s execution path.
 */

projid_t
setproject_proc(const char *project_name, const char *user_name, int flags,
    pid_t pid, struct ps_prochandle *Pr, struct project *proj)
{
	char pwdbuf[NSS_BUFLEN_PASSWD];
	char prbuf[PROJECT_BUFSZ];
	projid_t projid;
	struct passwd pwd;
	int i;
	int unknown = 0;
	int ret = 0;
	kva_t *kv_array;
	struct project local_proj; /* space to store proj if not provided */
	const char *pool_name = NULL;

	if (project_name != NULL) {
		/*
		 * Sanity checks.
		 */
		if (strcmp(project_name, "") == 0 ||
		    user_name == NULL) {
			errno = EINVAL;
			return (SETPROJ_ERR_TASK);
		}

		/*
		 * If proj is NULL, acquire project information to ensure that
		 * project_name is a valid project, and confirm that user_name
		 * exists and is a member of the specified project.
		 */
		if (proj == NULL) {
			if ((proj = getprojbyname(project_name, &local_proj,
			    prbuf, PROJECT_BUFSZ)) == NULL) {
				errno = ESRCH;
				return (SETPROJ_ERR_TASK);
			}

			if (getpwnam_r(user_name, &pwd,
			    pwdbuf, NSS_BUFLEN_PASSWD) == NULL) {
				errno = ESRCH;
				return (SETPROJ_ERR_TASK);
			}
			/*
			 * Root can join any project.
			 */
			if (pwd.pw_uid != (uid_t)0 &&
			    !inproj(user_name, project_name, prbuf,
			    PROJECT_BUFSZ)) {
				errno = ESRCH;
				return (SETPROJ_ERR_TASK);
			}
		}
		projid = proj->pj_projid;
	} else {
		projid = getprojid();
	}


	if ((kv_array = _str2kva(proj->pj_attr, KV_ASSIGN,
	    KV_DELIMITER)) != NULL) {
		for (i = 0; i < kv_array->length; i++) {
			if (strcmp(kv_array->data[i].key,
			    "project.pool") == 0) {
				pool_name = kv_array->data[i].value;
			}
			if (strcmp(kv_array->data[i].key, "task.final") == 0) {
				flags |= TASK_FINAL;
			}
		}
	}

	/*
	 * Bind process to a pool only if pools are configured
	 */
	if (pools_enabled() == 1) {
		char *old_pool_name;
		/*
		 * Attempt to bind to pool before calling
		 * settaskid().
		 */
		old_pool_name = pool_get_binding(pid);
		if (bind_to_pool(pool_name, pid, 0) != 0) {
			if (old_pool_name)
				free(old_pool_name);
			_kva_free(kv_array);
			return (SETPROJ_ERR_POOL);
		}
		if (pr_settaskid(Pr, projid, flags & TASK_MASK) == -1) {
			int saved_errno = errno;

			/*
			 * Undo pool binding.
			 */
			(void) bind_to_pool(old_pool_name, pid, 1);
			if (old_pool_name)
				free(old_pool_name);
			_kva_free(kv_array);
			/*
			 * Restore errno
			 */
			errno = saved_errno;
			return (SETPROJ_ERR_TASK);
		}
		if (old_pool_name)
			free(old_pool_name);
	} else {
		/*
		 * Pools are not configured, so simply create new task.
		 */
		if (pr_settaskid(Pr, projid, flags & TASK_MASK) == -1) {
			_kva_free(kv_array);
			return (SETPROJ_ERR_TASK);
		}
	}

	if (project_name == NULL) {
		/*
		 * In the case that we are starting a new task in the
		 * current project, we are finished, since the current
		 * resource controls will still apply. (Implicit behaviour:
		 * a project must be entirely logged out before name
		 * service changes will take effect.)
		 */
		_kva_free(kv_array);
		return (projid);
	}

	if (kv_array == NULL)
		return (0);

	for (i = 0; i < kv_array->length; i++) {
		/*
		 * Providing a special, i.e. a non-resource control, key?  Then
		 * parse that key here and end with "continue;".
		 */

		/*
		 * For generic bindings, the kernel performs the binding, as
		 * these are resource controls advertised by kernel subsystems.
		 */

		/*
		 * Check for known attribute name.
		 */
		errno = 0;
		if (rctl_walk(rctlwalkfunc, (void *)kv_array->data[i].key)
		    == 0)
			continue;
		if (errno) {
			_kva_free(kv_array);
			return (SETPROJ_ERR_TASK);
		}

		ret = rctl_set(kv_array->data[i].key,
		    kv_array->data[i].value, Pr, flags & TASK_PROJ_MASK);

		if (ret && unknown == 0) {
			/*
			 * We only report the first failure.
			 */
			unknown = i + 1;
		}

		if (ret && ret != SETFAILED) {
			/*
			 * We abort if we couldn't set a component, but if
			 * it's merely that the system didn't recognize it, we
			 * continue, as this could be a third party attribute.
			 */
			break;
		}
	}
	_kva_free(kv_array);

	return (unknown);
}

projid_t
setproject(const char *project_name, const char *user_name, int flags)
{
	return (setproject_proc(project_name, user_name, flags, P_MYID, NULL,
	    NULL));
}


priv_set_t *
setproject_initpriv(void)
{
	static priv_t taskpriv = PRIV_PROC_TASKID;
	static priv_t rctlpriv = PRIV_SYS_RESOURCE;
	static priv_t poolpriv = PRIV_SYS_RES_CONFIG;
	static priv_t schedpriv = PRIV_PROC_PRIOCNTL;
	int res;

	priv_set_t *nset;

	if (getzoneid() == GLOBAL_ZONEID) {
		res = __init_suid_priv(0, taskpriv, rctlpriv, poolpriv,
		    schedpriv, (char *)NULL);
	} else {
		res = __init_suid_priv(0, taskpriv, rctlpriv, (char *)NULL);
	}

	if (res != 0)
		return (NULL);

	nset = priv_allocset();
	if (nset != NULL) {
		priv_emptyset(nset);
		(void) priv_addset(nset, taskpriv);
		(void) priv_addset(nset, rctlpriv);
		/*
		 * Only need these if we need to change pools, which can
		 * only happen if the target is in the global zone.  Rather
		 * than checking the target's zone just check our own
		 * (since if we're in a non-global zone we won't be able
		 * to control processes in other zones).
		 */
		if (getzoneid() == GLOBAL_ZONEID) {
			(void) priv_addset(nset, poolpriv);
			(void) priv_addset(nset, schedpriv);
		}
	}
	return (nset);
}
