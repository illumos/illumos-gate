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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/procset.h>
#include <sys/corectl.h>
#include <sys/zone.h>
#include <sys/cmn_err.h>
#include <sys/policy.h>

/*
 * Core File Settings
 * ------------------
 *
 * A process's core file path and content live in separate reference-counted
 * structures. The corectl_content_t structure is fairly straightforward --
 * the only subtlety is that we only really _need_ the mutex on architectures
 * on which 64-bit memory operations are not atomic. The corectl_path_t
 * structure is slightly trickier in that it contains a refstr_t rather than
 * just a char * string. This is to allow consumers of the data in that
 * structure (the core dumping sub-system for example) to safely use the
 * string without holding any locks on it in light of updates.
 *
 * At system and zone boot, init_core() sets init(8)'s core file path and
 * content to the same value as the fields core_default_path and
 * core_default_content respectively (for the global zone). All subsequent
 * children of init(8) reference those same settings. During boot coreadm(8)
 * is invoked with the -u option to update the system settings from
 * /etc/coreadm.conf. This has the effect of also changing the values in
 * core_default_path and core_default_content which updates the core file
 * settings for all processes in the zone.  Each zone has different default
 * settings; when processes enter a non-global zone, their core file path and
 * content are set to the zone's default path and content.
 *
 * Processes that have their core file settings explicitly overridden using
 * coreadm(8) no longer reference core_default_path or core_default_content
 * so subsequent changes to the default will not affect them.
 */

zone_key_t	core_zone_key;

static int set_proc_info(pid_t pid, const char *path, core_content_t content);

static corectl_content_t *
corectl_content_alloc(core_content_t cc)
{
	corectl_content_t *ccp;

	ccp = kmem_zalloc(sizeof (corectl_content_t), KM_SLEEP);
	ccp->ccc_content = cc;
	ccp->ccc_refcnt = 1;

	return (ccp);
}

core_content_t
corectl_content_value(corectl_content_t *ccp)
{
	core_content_t content;

	mutex_enter(&ccp->ccc_mtx);
	content = ccp->ccc_content;
	mutex_exit(&ccp->ccc_mtx);

	return (content);
}

static void
corectl_content_set(corectl_content_t *ccp, core_content_t content)
{
	mutex_enter(&ccp->ccc_mtx);
	ccp->ccc_content = content;
	mutex_exit(&ccp->ccc_mtx);
}

void
corectl_content_hold(corectl_content_t *ccp)
{
	atomic_inc_32(&ccp->ccc_refcnt);
}

void
corectl_content_rele(corectl_content_t *ccp)
{
	if (atomic_dec_32_nv(&ccp->ccc_refcnt) == 0)
		kmem_free(ccp, sizeof (corectl_content_t));
}


static corectl_path_t *
corectl_path_alloc(const char *path)
{
	corectl_path_t *ccp;

	ccp = kmem_zalloc(sizeof (corectl_path_t), KM_SLEEP);
	ccp->ccp_path = refstr_alloc(path);
	ccp->ccp_refcnt = 1;

	return (ccp);
}

refstr_t *
corectl_path_value(corectl_path_t *ccp)
{
	refstr_t *path;

	mutex_enter(&ccp->ccp_mtx);
	refstr_hold(path = ccp->ccp_path);
	mutex_exit(&ccp->ccp_mtx);

	return (path);
}

static void
corectl_path_set(corectl_path_t *ccp, const char *path)
{
	refstr_t *npath = refstr_alloc(path);

	mutex_enter(&ccp->ccp_mtx);
	refstr_rele(ccp->ccp_path);
	ccp->ccp_path = npath;
	mutex_exit(&ccp->ccp_mtx);
}

void
corectl_path_hold(corectl_path_t *ccp)
{
	atomic_inc_32(&ccp->ccp_refcnt);
}

void
corectl_path_rele(corectl_path_t *ccp)
{
	if (atomic_dec_32_nv(&ccp->ccp_refcnt) == 0) {
		refstr_rele(ccp->ccp_path);
		kmem_free(ccp, sizeof (corectl_path_t));
	}
}

/*
 * Constructor routine to be called when a zone is created.
 */
/*ARGSUSED*/
static void *
core_init_zone(zoneid_t zoneid)
{
	struct core_globals *cg;

	cg = kmem_alloc(sizeof (*cg), KM_SLEEP);
	mutex_init(&cg->core_lock, NULL, MUTEX_DEFAULT, NULL);
	cg->core_file = NULL;
	cg->core_options = CC_PROCESS_PATH;
	cg->core_content = CC_CONTENT_DEFAULT;
	cg->core_rlimit = RLIM64_INFINITY;
	cg->core_default_path = corectl_path_alloc("core");
	cg->core_default_content = corectl_content_alloc(CC_CONTENT_DEFAULT);

	return (cg);
}

/*
 * Destructor routine to be called when a zone is destroyed.
 */
/*ARGSUSED*/
static void
core_free_zone(zoneid_t zoneid, void *arg)
{
	struct core_globals *cg = arg;

	if (cg == NULL)
		return;
	if (cg->core_file != NULL)
		refstr_rele(cg->core_file);
	corectl_path_rele(cg->core_default_path);
	corectl_content_rele(cg->core_default_content);
	kmem_free(cg, sizeof (*cg));
}

/*
 * Called from start_init_common(), to set init's core file path and content.
 */
void
init_core(void)
{
	struct core_globals *cg;

	/*
	 * The first time we hit this, in the global zone, we have to
	 * initialize the zsd key.
	 */
	if (INGLOBALZONE(curproc)) {
		zone_key_create(&core_zone_key, core_init_zone, NULL,
		    core_free_zone);
	}

	/*
	 * zone_key_create will have called core_init_zone for the
	 * global zone, which sets up the default path and content
	 * variables.
	 */
	VERIFY((cg = zone_getspecific(core_zone_key, curproc->p_zone)) != NULL);

	corectl_path_hold(cg->core_default_path);
	corectl_content_hold(cg->core_default_content);

	curproc->p_corefile = cg->core_default_path;
	curproc->p_content = cg->core_default_content;
}

int
corectl(int subcode, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
	int error = 0;
	proc_t *p;
	refstr_t *rp;
	size_t size;
	char *path;
	core_content_t content = CC_CONTENT_INVALID;
	struct core_globals *cg;
	zone_t *zone = curproc->p_zone;

	cg = zone_getspecific(core_zone_key, zone);
	ASSERT(cg != NULL);

	switch (subcode) {
	case CC_SET_OPTIONS:
		if ((error = secpolicy_coreadm(CRED())) == 0) {
			if (arg1 & ~CC_OPTIONS)
				error = EINVAL;
			else
				cg->core_options = (uint32_t)arg1;
		}
		break;

	case CC_GET_OPTIONS:
		return (cg->core_options);

	case CC_GET_GLOBAL_PATH:
	case CC_GET_DEFAULT_PATH:
	case CC_GET_PROCESS_PATH:
		if (subcode == CC_GET_GLOBAL_PATH) {
			mutex_enter(&cg->core_lock);
			if ((rp = cg->core_file) != NULL)
				refstr_hold(rp);
			mutex_exit(&cg->core_lock);
		} else if (subcode == CC_GET_DEFAULT_PATH) {
			rp = corectl_path_value(cg->core_default_path);
		} else {
			rp = NULL;
			mutex_enter(&pidlock);
			if ((p = prfind((pid_t)arg3)) == NULL ||
			    p->p_stat == SIDL) {
				mutex_exit(&pidlock);
				error = ESRCH;
			} else {
				mutex_enter(&p->p_lock);
				mutex_exit(&pidlock);
				mutex_enter(&p->p_crlock);
				if (!hasprocperm(p->p_cred, CRED()))
					error = EPERM;
				else if (p->p_corefile != NULL)
					rp = corectl_path_value(p->p_corefile);
				mutex_exit(&p->p_crlock);
				mutex_exit(&p->p_lock);
			}
		}
		if (rp == NULL) {
			if (error == 0 && suword8((void *)arg1, 0))
				error = EFAULT;
		} else {
			error = copyoutstr(refstr_value(rp), (char *)arg1,
			    (size_t)arg2, NULL);
			refstr_rele(rp);
		}
		break;

	case CC_SET_GLOBAL_PATH:
	case CC_SET_DEFAULT_PATH:
		if ((error = secpolicy_coreadm(CRED())) != 0)
			break;

		/* FALLTHROUGH */
	case CC_SET_PROCESS_PATH:
		if ((size = MIN((size_t)arg2, MAXPATHLEN)) == 0) {
			error = EINVAL;
			break;
		}
		path = kmem_alloc(size, KM_SLEEP);
		error = copyinstr((char *)arg1, path, size, NULL);
		if (error == 0) {
			if (subcode == CC_SET_PROCESS_PATH) {
				error = set_proc_info((pid_t)arg3, path, 0);
			} else if (subcode == CC_SET_DEFAULT_PATH) {
				corectl_path_set(cg->core_default_path, path);
			} else if (*path != '\0' && *path != '/') {
				error = EINVAL;
			} else {
				refstr_t *nrp = refstr_alloc(path);

				mutex_enter(&cg->core_lock);
				rp = cg->core_file;
				if (*path == '\0')
					cg->core_file = NULL;
				else
					refstr_hold(cg->core_file = nrp);
				mutex_exit(&cg->core_lock);

				if (rp != NULL)
					refstr_rele(rp);

				refstr_rele(nrp);
			}
		}
		kmem_free(path, size);
		break;

	case CC_SET_GLOBAL_CONTENT:
	case CC_SET_DEFAULT_CONTENT:
		if ((error = secpolicy_coreadm(CRED())) != 0)
			break;

		/* FALLTHROUGH */
	case CC_SET_PROCESS_CONTENT:
		error = copyin((void *)arg1, &content, sizeof (content));
		if (error != 0)
			break;

		/*
		 * If any unknown bits are set, don't let this charade
		 * continue.
		 */
		if (content & ~CC_CONTENT_ALL) {
			error = EINVAL;
			break;
		}

		if (subcode == CC_SET_PROCESS_CONTENT) {
			error = set_proc_info((pid_t)arg2, NULL, content);
		} else if (subcode == CC_SET_DEFAULT_CONTENT) {
			corectl_content_set(cg->core_default_content, content);
		} else {
			mutex_enter(&cg->core_lock);
			cg->core_content = content;
			mutex_exit(&cg->core_lock);
		}

		break;

	case CC_GET_GLOBAL_CONTENT:
		content = cg->core_content;
		error = copyout(&content, (void *)arg1, sizeof (content));
		break;

	case CC_GET_DEFAULT_CONTENT:
		content = corectl_content_value(cg->core_default_content);
		error = copyout(&content, (void *)arg1, sizeof (content));
		break;

	case CC_GET_PROCESS_CONTENT:
		mutex_enter(&pidlock);
		if ((p = prfind((pid_t)arg2)) == NULL || p->p_stat == SIDL) {
			mutex_exit(&pidlock);
			error = ESRCH;
			break;
		}

		mutex_enter(&p->p_lock);
		mutex_exit(&pidlock);
		mutex_enter(&p->p_crlock);
		if (!hasprocperm(p->p_cred, CRED()))
			error = EPERM;
		else if (p->p_content == NULL)
			content = CC_CONTENT_NONE;
		else
			content = corectl_content_value(p->p_content);
		mutex_exit(&p->p_crlock);
		mutex_exit(&p->p_lock);

		if (error == 0)
			error = copyout(&content, (void *)arg1,
			    sizeof (content));
		break;

	default:
		error = EINVAL;
		break;
	}

	if (error)
		return (set_errno(error));
	return (0);
}

typedef struct {
	int			cc_count;
	corectl_path_t		*cc_path;
	corectl_content_t	*cc_content;
} counter_t;

static int
set_one_proc_info(proc_t *p, counter_t *counterp)
{
	corectl_path_t *corefile;
	corectl_content_t *content;

	mutex_enter(&p->p_crlock);

	if (!(p->p_flag & SSYS) && hasprocperm(p->p_cred, CRED())) {
		mutex_exit(&p->p_crlock);
		counterp->cc_count++;
		if (counterp->cc_path != NULL) {
			corectl_path_hold(counterp->cc_path);
			mutex_enter(&p->p_lock);
			corefile = p->p_corefile;
			p->p_corefile = counterp->cc_path;
			mutex_exit(&p->p_lock);
			if (corefile != NULL)
				corectl_path_rele(corefile);
		} else {
			corectl_content_hold(counterp->cc_content);
			mutex_enter(&p->p_lock);
			content = p->p_content;
			p->p_content = counterp->cc_content;
			mutex_exit(&p->p_lock);
			if (content != NULL)
				corectl_content_rele(content);
		}
	} else {
		mutex_exit(&p->p_crlock);
	}

	return (0);
}

static int
set_proc_info(pid_t pid, const char *path, core_content_t content)
{
	proc_t *p;
	counter_t counter;
	int error = 0;

	counter.cc_count = 0;
	/*
	 * Only one of the core file path or content can be set at a time.
	 */
	if (path != NULL) {
		counter.cc_path = corectl_path_alloc(path);
		counter.cc_content = NULL;
	} else {
		counter.cc_path = NULL;
		counter.cc_content = corectl_content_alloc(content);
	}

	if (pid == -1) {
		procset_t set;

		setprocset(&set, POP_AND, P_ALL, P_MYID, P_ALL, P_MYID);
		error = dotoprocs(&set, set_one_proc_info, (char *)&counter);
		if (error == 0 && counter.cc_count == 0)
			error = EPERM;
	} else if (pid > 0) {
		mutex_enter(&pidlock);
		if ((p = prfind(pid)) == NULL || p->p_stat == SIDL) {
			error = ESRCH;
		} else {
			(void) set_one_proc_info(p, &counter);
			if (counter.cc_count == 0)
				error = EPERM;
		}
		mutex_exit(&pidlock);
	} else {
		int nfound = 0;
		pid_t pgid;

		if (pid == 0)
			pgid = curproc->p_pgrp;
		else
			pgid = -pid;

		mutex_enter(&pidlock);
		for (p = pgfind(pgid); p != NULL; p = p->p_pglink) {
			if (p->p_stat != SIDL) {
				nfound++;
				(void) set_one_proc_info(p, &counter);
			}
		}
		mutex_exit(&pidlock);
		if (nfound == 0)
			error = ESRCH;
		else if (counter.cc_count == 0)
			error = EPERM;
	}

	if (path != NULL)
		corectl_path_rele(counter.cc_path);
	else
		corectl_content_rele(counter.cc_content);

	if (error)
		return (set_errno(error));
	return (0);
}

/*
 * Give current process the default core settings for its current zone;
 * used for processes entering a zone via zone_enter.
 */
void
set_core_defaults(void)
{
	proc_t *p = curproc;
	struct core_globals *cg;
	corectl_path_t *oldpath, *newpath;
	corectl_content_t *oldcontent, *newcontent;

	cg = zone_getspecific(core_zone_key, p->p_zone);

	/* make local copies of default values to protect against change */
	newpath = cg->core_default_path;
	newcontent = cg->core_default_content;

	corectl_path_hold(newpath);
	corectl_content_hold(newcontent);
	mutex_enter(&p->p_lock);
	oldpath = p->p_corefile;
	p->p_corefile = newpath;
	oldcontent = p->p_content;
	p->p_content = newcontent;
	mutex_exit(&p->p_lock);
	if (oldpath != NULL)
		corectl_path_rele(oldpath);
	if (oldcontent != NULL)
		corectl_content_rele(oldcontent);
}
