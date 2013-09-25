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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Joyent Inc.
 */

/*
 * method.c - method execution functions
 *
 * This file contains the routines needed to run a method:  a fork(2)-exec(2)
 * invocation monitored using either the contract filesystem or waitpid(2).
 * (Plain fork1(2) support is provided in fork.c.)
 *
 * Contract Transfer
 *   When we restart a service, we want to transfer any contracts that the old
 *   service's contract inherited.  This means that (a) we must not abandon the
 *   old contract when the service dies and (b) we must write the id of the old
 *   contract into the terms of the new contract.  There should be limits to
 *   (a), though, since we don't want to keep the contract around forever.  To
 *   this end we'll say that services in the offline state may have a contract
 *   to be transfered and services in the disabled or maintenance states cannot.
 *   This means that when a service transitions from online (or degraded) to
 *   offline, the contract should be preserved, and when the service transitions
 *   from offline to online (i.e., the start method), we'll transfer inherited
 *   contracts.
 */

#include <sys/contract/process.h>
#include <sys/ctfs.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <libgen.h>
#include <librestart.h>
#include <libscf.h>
#include <limits.h>
#include <port.h>
#include <sac.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <atomic.h>
#include <poll.h>
#include <libscf_priv.h>

#include "startd.h"

#define	SBIN_SH		"/sbin/sh"

/*
 * Used to tell if contracts are in the process of being
 * stored into the svc.startd internal hash table.
 */
volatile uint16_t	storing_contract = 0;

/*
 * Mapping from restart_on method-type to contract events.  Must correspond to
 * enum method_restart_t.
 */
static uint_t method_events[] = {
	/* METHOD_RESTART_ALL */
	CT_PR_EV_HWERR | CT_PR_EV_SIGNAL | CT_PR_EV_CORE | CT_PR_EV_EMPTY,
	/* METHOD_RESTART_EXTERNAL_FAULT */
	CT_PR_EV_HWERR | CT_PR_EV_SIGNAL,
	/* METHOD_RESTART_ANY_FAULT */
	CT_PR_EV_HWERR | CT_PR_EV_SIGNAL | CT_PR_EV_CORE
};

/*
 * method_record_start(restarter_inst_t *)
 *   Record a service start for rate limiting.  Place the current time
 *   in the circular array of instance starts.
 */
static void
method_record_start(restarter_inst_t *inst)
{
	int index = inst->ri_start_index++ % RINST_START_TIMES;

	inst->ri_start_time[index] = gethrtime();
}

/*
 * method_rate_critical(restarter_inst_t *)
 *    Return true if the average start interval is less than the permitted
 *    interval.  The implicit interval defaults to RINST_FAILURE_RATE_NS and
 *    RINST_START_TIMES but may be overridden with the svc properties
 *    startd/critical_failure_count and startd/critical_failure_period
 *    which represent the number of failures to consider and the amount of
 *    time in seconds in which that number may occur, respectively. Note that
 *    this time is measured as of the transition to 'enabled' rather than wall
 *    clock time.
 *    Implicit success if insufficient measurements for an average exist.
 */
int
method_rate_critical(restarter_inst_t *inst)
{
	hrtime_t critical_failure_period;
	uint_t critical_failure_count = RINST_START_TIMES;
	uint_t n = inst->ri_start_index;
	hrtime_t avg_ns = 0;
	uint64_t scf_fr, scf_st;
	scf_propvec_t *prop = NULL;
	scf_propvec_t restart_critical[] = {
		{ "critical_failure_period", NULL, SCF_TYPE_INTEGER, NULL, 0 },
		{ "critical_failure_count", NULL, SCF_TYPE_INTEGER, NULL, 0 },
		{ NULL }
	};

	if (instance_is_wait_style(inst))
		critical_failure_period = RINST_WT_SVC_FAILURE_RATE_NS;
	else
		critical_failure_period = RINST_FAILURE_RATE_NS;

	restart_critical[0].pv_ptr = &scf_fr;
	restart_critical[1].pv_ptr = &scf_st;

	if (scf_read_propvec(inst->ri_i.i_fmri, "startd",
	    B_TRUE, restart_critical, &prop) != SCF_FAILED) {
		/*
		 * critical_failure_period is expressed
		 * in seconds but tracked in ns
		 */
		critical_failure_period = (hrtime_t)scf_fr * NANOSEC;
		critical_failure_count = (uint_t)scf_st;
	}
	if (inst->ri_start_index < critical_failure_count)
		return (0);

	avg_ns =
	    (inst->ri_start_time[(n - 1) % critical_failure_count] -
	    inst->ri_start_time[n % critical_failure_count]) /
	    (critical_failure_count - 1);

	return (avg_ns < critical_failure_period);
}

/*
 * int method_is_transient()
 *   Determine if the method for the given instance is transient,
 *   from a contract perspective. Return 1 if it is, and 0 if it isn't.
 */
static int
method_is_transient(restarter_inst_t *inst, int type)
{
	if (instance_is_transient_style(inst) || type != METHOD_START)
		return (1);
	else
		return (0);
}

/*
 * void method_store_contract()
 *   Store the newly created contract id into local structures and
 *   the repository.  If the repository connection is broken it is rebound.
 */
static void
method_store_contract(restarter_inst_t *inst, int type, ctid_t *cid)
{
	int r;
	boolean_t primary;

	if (errno = contract_latest(cid))
		uu_die("%s: Couldn't get new contract's id", inst->ri_i.i_fmri);

	primary = !method_is_transient(inst, type);

	if (!primary) {
		if (inst->ri_i.i_transient_ctid != 0) {
			log_framework(LOG_INFO,
			    "%s: transient ctid expected to be 0 but "
			    "was set to %ld\n", inst->ri_i.i_fmri,
			    inst->ri_i.i_transient_ctid);
		}

		inst->ri_i.i_transient_ctid = *cid;
	} else {
		if (inst->ri_i.i_primary_ctid != 0) {
			/*
			 * There was an old contract that we transferred.
			 * Remove it.
			 */
			method_remove_contract(inst, B_TRUE, B_FALSE);
		}

		if (inst->ri_i.i_primary_ctid != 0) {
			log_framework(LOG_INFO,
			    "%s: primary ctid expected to be 0 but "
			    "was set to %ld\n", inst->ri_i.i_fmri,
			    inst->ri_i.i_primary_ctid);
		}

		inst->ri_i.i_primary_ctid = *cid;
		inst->ri_i.i_primary_ctid_stopped = 0;

		log_framework(LOG_DEBUG, "Storing primary contract %ld for "
		    "%s.\n", *cid, inst->ri_i.i_fmri);

		contract_hash_store(*cid, inst->ri_id);
	}

again:
	if (inst->ri_mi_deleted)
		return;

	r = restarter_store_contract(inst->ri_m_inst, *cid, primary ?
	    RESTARTER_CONTRACT_PRIMARY : RESTARTER_CONTRACT_TRANSIENT);
	switch (r) {
	case 0:
		break;

	case ECANCELED:
		inst->ri_mi_deleted = B_TRUE;
		break;

	case ECONNABORTED:
		libscf_handle_rebind(scf_instance_handle(inst->ri_m_inst));
		/* FALLTHROUGH */

	case EBADF:
		libscf_reget_instance(inst);
		goto again;

	case ENOMEM:
	case EPERM:
	case EACCES:
	case EROFS:
		uu_die("%s: Couldn't store contract id %ld",
		    inst->ri_i.i_fmri, *cid);
		/* NOTREACHED */

	case EINVAL:
	default:
		bad_error("restarter_store_contract", r);
	}
}

/*
 * void method_remove_contract()
 *   Remove any non-permanent contracts from internal structures and
 *   the repository, then abandon them.
 *   Returns
 *     0 - success
 *     ECANCELED - inst was deleted from the repository
 *
 *   If the repository connection was broken, it is rebound.
 */
void
method_remove_contract(restarter_inst_t *inst, boolean_t primary,
    boolean_t abandon)
{
	ctid_t * const ctidp = primary ? &inst->ri_i.i_primary_ctid :
	    &inst->ri_i.i_transient_ctid;

	int r;

	assert(*ctidp != 0);

	log_framework(LOG_DEBUG, "Removing %s contract %lu for %s.\n",
	    primary ? "primary" : "transient", *ctidp, inst->ri_i.i_fmri);

	if (abandon)
		contract_abandon(*ctidp);

again:
	if (inst->ri_mi_deleted) {
		r = ECANCELED;
		goto out;
	}

	r = restarter_remove_contract(inst->ri_m_inst, *ctidp, primary ?
	    RESTARTER_CONTRACT_PRIMARY : RESTARTER_CONTRACT_TRANSIENT);
	switch (r) {
	case 0:
		break;

	case ECANCELED:
		inst->ri_mi_deleted = B_TRUE;
		break;

	case ECONNABORTED:
		libscf_handle_rebind(scf_instance_handle(inst->ri_m_inst));
		/* FALLTHROUGH */

	case EBADF:
		libscf_reget_instance(inst);
		goto again;

	case ENOMEM:
	case EPERM:
	case EACCES:
	case EROFS:
		log_error(LOG_INFO, "%s: Couldn't remove contract id %ld: "
		    "%s.\n", inst->ri_i.i_fmri, *ctidp, strerror(r));
		break;

	case EINVAL:
	default:
		bad_error("restarter_remove_contract", r);
	}

out:
	if (primary)
		contract_hash_remove(*ctidp);

	*ctidp = 0;
}

static const char *method_names[] = { "start", "stop", "refresh" };

/*
 * int method_ready_contract(restarter_inst_t *, int, method_restart_t, int)
 *
 *   Activate a contract template for the type method of inst.  type,
 *   restart_on, and cte_mask dictate the critical events term of the contract.
 *   Returns
 *     0 - success
 *     ECANCELED - inst has been deleted from the repository
 */
static int
method_ready_contract(restarter_inst_t *inst, int type,
    method_restart_t restart_on, uint_t cte_mask)
{
	int tmpl, err, istrans, iswait, ret;
	uint_t cevents, fevents;

	/*
	 * Correctly supporting wait-style services is tricky without
	 * rearchitecting startd to cope with multiple event sources
	 * simultaneously trying to stop an instance.  Until a better
	 * solution is implemented, we avoid this problem for
	 * wait-style services by making contract events fatal and
	 * letting the wait code alone handle stopping the service.
	 */
	iswait = instance_is_wait_style(inst);
	istrans = method_is_transient(inst, type);

	tmpl = open64(CTFS_ROOT "/process/template", O_RDWR);
	if (tmpl == -1)
		uu_die("Could not create contract template");

	/*
	 * We assume non-login processes are unlikely to create
	 * multiple process groups, and set CT_PR_PGRPONLY for all
	 * wait-style services' contracts.
	 */
	err = ct_pr_tmpl_set_param(tmpl, CT_PR_INHERIT | CT_PR_REGENT |
	    (iswait ? CT_PR_PGRPONLY : 0));
	assert(err == 0);

	if (istrans) {
		cevents = 0;
		fevents = 0;
	} else {
		assert(restart_on >= 0);
		assert(restart_on <= METHOD_RESTART_ANY_FAULT);
		cevents = method_events[restart_on] & ~cte_mask;
		fevents = iswait ?
		    (method_events[restart_on] & ~cte_mask & CT_PR_ALLFATAL) :
		    0;
	}

	err = ct_tmpl_set_critical(tmpl, cevents);
	assert(err == 0);

	err = ct_tmpl_set_informative(tmpl, 0);
	assert(err == 0);
	err = ct_pr_tmpl_set_fatal(tmpl, fevents);
	assert(err == 0);

	err = ct_tmpl_set_cookie(tmpl, istrans ?  METHOD_OTHER_COOKIE :
	    METHOD_START_COOKIE);
	assert(err == 0);

	if (type == METHOD_START && inst->ri_i.i_primary_ctid != 0) {
		ret = ct_pr_tmpl_set_transfer(tmpl, inst->ri_i.i_primary_ctid);
		switch (ret) {
		case 0:
			break;

		case ENOTEMPTY:
			/* No contracts for you! */
			method_remove_contract(inst, B_TRUE, B_TRUE);
			if (inst->ri_mi_deleted) {
				ret = ECANCELED;
				goto out;
			}
			break;

		case EINVAL:
		case ESRCH:
		case EACCES:
		default:
			bad_error("ct_pr_tmpl_set_transfer", ret);
		}
	}

	err = ct_pr_tmpl_set_svc_fmri(tmpl, inst->ri_i.i_fmri);
	assert(err == 0);
	err = ct_pr_tmpl_set_svc_aux(tmpl, method_names[type]);
	assert(err == 0);

	err = ct_tmpl_activate(tmpl);
	assert(err == 0);

	ret = 0;

out:
	err = close(tmpl);
	assert(err == 0);

	return (ret);
}

static void
exec_method(const restarter_inst_t *inst, int type, const char *method,
    struct method_context *mcp, uint8_t need_session)
{
	char *cmd;
	const char *errf;
	char **nenv;
	int rsmc_errno = 0;

	cmd = uu_msprintf("exec %s", method);

	if (inst->ri_utmpx_prefix[0] != '\0' && inst->ri_utmpx_prefix != NULL)
		(void) utmpx_mark_init(getpid(), inst->ri_utmpx_prefix);

	setlog(inst->ri_logstem);
	log_instance(inst, B_FALSE, "Executing %s method (\"%s\").",
	    method_names[type], method);

	if (need_session)
		(void) setpgrp();

	/* Set credentials. */
	rsmc_errno = restarter_set_method_context(mcp, &errf);
	if (rsmc_errno != 0) {
		log_instance(inst, B_FALSE,
		    "svc.startd could not set context for method: ");

		if (rsmc_errno == -1) {
			if (strcmp(errf, "core_set_process_path") == 0) {
				log_instance(inst, B_FALSE,
				    "Could not set corefile path.");
			} else if (strcmp(errf, "setproject") == 0) {
				log_instance(inst, B_FALSE, "%s: a resource "
				    "control assignment failed", errf);
			} else if (strcmp(errf, "pool_set_binding") == 0) {
				log_instance(inst, B_FALSE, "%s: a system "
				    "error occurred", errf);
			} else {
#ifndef NDEBUG
				uu_warn("%s:%d: Bad function name \"%s\" for "
				    "error %d from "
				    "restarter_set_method_context().\n",
				    __FILE__, __LINE__, errf, rsmc_errno);
#endif
				abort();
			}

			exit(1);
		}

		if (errf != NULL && strcmp(errf, "pool_set_binding") == 0) {
			switch (rsmc_errno) {
			case ENOENT:
				log_instance(inst, B_FALSE, "%s: the pool "
				    "could not be found", errf);
				break;

			case EBADF:
				log_instance(inst, B_FALSE, "%s: the "
				    "configuration is invalid", errf);
				break;

			case EINVAL:
				log_instance(inst, B_FALSE, "%s: pool name "
				    "\"%s\" is invalid", errf,
				    mcp->resource_pool);
				break;

			default:
#ifndef NDEBUG
				uu_warn("%s:%d: Bad error %d for function %s "
				    "in restarter_set_method_context().\n",
				    __FILE__, __LINE__, rsmc_errno, errf);
#endif
				abort();
			}

			exit(SMF_EXIT_ERR_CONFIG);
		}

		if (errf != NULL && strcmp(errf, "chdir") == 0) {
			switch (rsmc_errno) {
			case EACCES:
			case EFAULT:
			case EIO:
			case ELOOP:
			case ENAMETOOLONG:
			case ENOENT:
			case ENOLINK:
			case ENOTDIR:
				log_instance(inst, B_FALSE, "%s: %s (\"%s\")",
				    errf,
				    strerror(rsmc_errno), mcp->working_dir);
				break;

			default:
#ifndef NDEBUG
				uu_warn("%s:%d: Bad error %d for function %s "
				    "in restarter_set_method_context().\n",
				    __FILE__, __LINE__, rsmc_errno, errf);
#endif
				abort();
			}

			exit(SMF_EXIT_ERR_CONFIG);
		}

		if (errf != NULL) {
			errno = rsmc_errno;
			perror(errf);

			switch (rsmc_errno) {
			case EINVAL:
			case EPERM:
			case ENOENT:
			case ENAMETOOLONG:
			case ERANGE:
			case ESRCH:
				exit(SMF_EXIT_ERR_CONFIG);
				/* NOTREACHED */

			default:
				exit(1);
			}
		}

		switch (rsmc_errno) {
		case ENOMEM:
			log_instance(inst, B_FALSE, "Out of memory.");
			exit(1);
			/* NOTREACHED */

		case ENOENT:
			log_instance(inst, B_FALSE, "Missing passwd entry for "
			    "user.");
			exit(SMF_EXIT_ERR_CONFIG);
			/* NOTREACHED */

		default:
#ifndef NDEBUG
			uu_warn("%s:%d: Bad miscellaneous error %d from "
			    "restarter_set_method_context().\n", __FILE__,
			    __LINE__, rsmc_errno);
#endif
			abort();
		}
	}

	nenv = set_smf_env(mcp->env, mcp->env_sz, NULL, inst,
	    method_names[type]);

	log_preexec();

	(void) execle(SBIN_SH, SBIN_SH, "-c", cmd, NULL, nenv);

	exit(10);
}

static void
write_status(restarter_inst_t *inst, const char *mname, int stat)
{
	int r;

again:
	if (inst->ri_mi_deleted)
		return;

	r = libscf_write_method_status(inst->ri_m_inst, mname, stat);
	switch (r) {
	case 0:
		break;

	case ECONNABORTED:
		libscf_reget_instance(inst);
		goto again;

	case ECANCELED:
		inst->ri_mi_deleted = 1;
		break;

	case EPERM:
	case EACCES:
	case EROFS:
		log_framework(LOG_INFO, "Could not write exit status "
		    "for %s method of %s: %s.\n", mname,
		    inst->ri_i.i_fmri, strerror(r));
		break;

	case ENAMETOOLONG:
	default:
		bad_error("libscf_write_method_status", r);
	}
}

/*
 * int method_run()
 *   Execute the type method of instp.  If it requires a fork(), wait for it
 *   to return and return its exit code in *exit_code.  Otherwise set
 *   *exit_code to 0 if the method succeeds & -1 if it fails.  If the
 *   repository connection is broken, it is rebound, but inst may not be
 *   reset.
 *   Returns
 *     0 - success
 *     EINVAL - A correct method or method context couldn't be retrieved.
 *     EIO - Contract kill failed.
 *     EFAULT - Method couldn't be executed successfully.
 *     ELOOP - Retry threshold exceeded.
 *     ECANCELED - inst was deleted from the repository before method was run
 *     ERANGE - Timeout retry threshold exceeded.
 *     EAGAIN - Failed due to external cause, retry.
 */
int
method_run(restarter_inst_t **instp, int type, int *exit_code)
{
	char *method;
	int ret_status;
	pid_t pid;
	method_restart_t restart_on;
	uint_t cte_mask;
	uint8_t need_session;
	scf_handle_t *h;
	scf_snapshot_t *snap;
	const char *mname;
	mc_error_t *m_error;
	struct method_context *mcp;
	int result = 0, timeout_fired = 0;
	int sig, r;
	boolean_t transient;
	uint64_t timeout;
	uint8_t timeout_retry;
	ctid_t ctid;
	int ctfd = -1;
	restarter_inst_t *inst = *instp;
	int id = inst->ri_id;
	int forkerr;

	assert(MUTEX_HELD(&inst->ri_lock));
	assert(instance_in_transition(inst));

	if (inst->ri_mi_deleted)
		return (ECANCELED);

	*exit_code = 0;

	assert(0 <= type && type <= 2);
	mname = method_names[type];

	if (type == METHOD_START)
		inst->ri_pre_online_hook();

	h = scf_instance_handle(inst->ri_m_inst);

	snap = scf_snapshot_create(h);
	if (snap == NULL ||
	    scf_instance_get_snapshot(inst->ri_m_inst, "running", snap) != 0) {
		log_framework(LOG_DEBUG,
		    "Could not get running snapshot for %s.  "
		    "Using editing version to run method %s.\n",
		    inst->ri_i.i_fmri, mname);
		scf_snapshot_destroy(snap);
		snap = NULL;
	}

	/*
	 * After this point, we may be logging to the instance log.
	 * Make sure we've noted where that log is as a property of
	 * the instance.
	 */
	r = libscf_note_method_log(inst->ri_m_inst, st->st_log_prefix,
	    inst->ri_logstem);
	if (r != 0) {
		log_framework(LOG_WARNING,
		    "%s: couldn't note log location: %s\n",
		    inst->ri_i.i_fmri, strerror(r));
	}

	if ((method = libscf_get_method(h, type, inst, snap, &restart_on,
	    &cte_mask, &need_session, &timeout, &timeout_retry)) == NULL) {
		if (errno == LIBSCF_PGROUP_ABSENT)  {
			log_framework(LOG_DEBUG,
			    "%s: instance has no method property group '%s'.\n",
			    inst->ri_i.i_fmri, mname);
			if (type == METHOD_REFRESH)
				log_instance(inst, B_TRUE, "No '%s' method "
				    "defined.  Treating as :true.", mname);
			else
				log_instance(inst, B_TRUE, "Method property "
				    "group '%s' is not present.", mname);
			scf_snapshot_destroy(snap);
			return (0);
		} else if (errno == LIBSCF_PROPERTY_ABSENT)  {
			log_framework(LOG_DEBUG,
			    "%s: instance has no '%s/exec' method property.\n",
			    inst->ri_i.i_fmri, mname);
			log_instance(inst, B_TRUE, "Method property '%s/exec "
			    "is not present.", mname);
			scf_snapshot_destroy(snap);
			return (0);
		} else {
			log_error(LOG_WARNING,
			    "%s: instance libscf_get_method failed\n",
			    inst->ri_i.i_fmri);
			scf_snapshot_destroy(snap);
			return (EINVAL);
		}
	}

	/* open service contract if stopping a non-transient service */
	if (type == METHOD_STOP && (!instance_is_transient_style(inst))) {
		if (inst->ri_i.i_primary_ctid == 0) {
			/* service is not running, nothing to stop */
			log_framework(LOG_DEBUG, "%s: instance has no primary "
			    "contract, no service to stop.\n",
			    inst->ri_i.i_fmri);
			scf_snapshot_destroy(snap);
			return (0);
		}
		if ((ctfd = contract_open(inst->ri_i.i_primary_ctid, "process",
		    "events", O_RDONLY)) < 0) {
			result = EFAULT;
			log_instance(inst, B_TRUE, "Could not open service "
			    "contract %ld.  Stop method not run.",
			    inst->ri_i.i_primary_ctid);
			goto out;
		}
	}

	if (restarter_is_null_method(method)) {
		log_framework(LOG_DEBUG, "%s: null method succeeds\n",
		    inst->ri_i.i_fmri);

		log_instance(inst, B_TRUE, "Executing %s method (null).",
		    mname);

		if (type == METHOD_START)
			write_status(inst, mname, 0);
		goto out;
	}

	sig = restarter_is_kill_method(method);
	if (sig >= 0) {

		if (inst->ri_i.i_primary_ctid == 0) {
			log_error(LOG_ERR, "%s: :kill with no contract\n",
			    inst->ri_i.i_fmri);
			log_instance(inst, B_TRUE, "Invalid use of \":kill\" "
			    "as stop method for transient service.");
			result = EINVAL;
			goto out;
		}

		log_framework(LOG_DEBUG,
		    "%s: :killing contract with signal %d\n",
		    inst->ri_i.i_fmri, sig);

		log_instance(inst, B_TRUE, "Executing %s method (:kill).",
		    mname);

		if (contract_kill(inst->ri_i.i_primary_ctid, sig,
		    inst->ri_i.i_fmri) != 0) {
			result = EIO;
			goto out;
		} else
			goto assured_kill;
	}

	log_framework(LOG_DEBUG, "%s: forking to run method %s\n",
	    inst->ri_i.i_fmri, method);

	m_error = restarter_get_method_context(RESTARTER_METHOD_CONTEXT_VERSION,
	    inst->ri_m_inst, snap, mname, method, &mcp);

	if (m_error != NULL) {
		log_instance(inst, B_TRUE, "%s", m_error->msg);
		restarter_mc_error_destroy(m_error);
		result = EINVAL;
		goto out;
	}

	r = method_ready_contract(inst, type, restart_on, cte_mask);
	if (r != 0) {
		assert(r == ECANCELED);
		assert(inst->ri_mi_deleted);
		restarter_free_method_context(mcp);
		result = ECANCELED;
		goto out;
	}

	/*
	 * Validate safety of method contexts, to save children work.
	 */
	if (!restarter_rm_libs_loadable())
		log_framework(LOG_DEBUG, "%s: method contexts limited "
		    "to root-accessible libraries\n", inst->ri_i.i_fmri);

	/*
	 * For wait-style svc, sanity check that method exists to prevent an
	 * infinite loop.
	 */
	if (instance_is_wait_style(inst) && type == METHOD_START) {
		char *pend;
		struct stat64 sbuf;

		/*
		 * We need to handle start method strings that have arguments,
		 * such as '/lib/svc/method/console-login %i'.
		 */
		if ((pend = strchr(method, ' ')) != NULL)
			*pend = '\0';

		if (*method == '/' && stat64(method, &sbuf) == -1 &&
		    errno == ENOENT) {
			log_instance(inst, B_TRUE, "Missing start method (%s), "
			    "changing state to maintenance.", method);
			restarter_free_method_context(mcp);
			result = ENOENT;
			goto out;
		}
		if (pend != NULL)
			*pend = ' ';
	}

	/*
	 * If the service is restarting too quickly, send it to
	 * maintenance.
	 */
	if (type == METHOD_START) {
		method_record_start(inst);
		if (method_rate_critical(inst) &&
		    !instance_is_wait_style(inst)) {
			log_instance(inst, B_TRUE, "Restarting too quickly, "
			    "changing state to maintenance.");
			result = ELOOP;
			restarter_free_method_context(mcp);
			goto out;
		}
	}

	atomic_add_16(&storing_contract, 1);
	pid = startd_fork1(&forkerr);
	if (pid == 0)
		exec_method(inst, type, method, mcp, need_session);

	if (pid == -1) {
		atomic_add_16(&storing_contract, -1);
		if (forkerr == EAGAIN)
			result = EAGAIN;
		else
			result = EFAULT;

		log_error(LOG_WARNING,
		    "%s: Couldn't fork to execute method %s: %s\n",
		    inst->ri_i.i_fmri, method, strerror(forkerr));

		restarter_free_method_context(mcp);
		goto out;
	}


	/*
	 * Get the contract id, decide whether it is primary or transient, and
	 * stash it in inst & the repository.
	 */
	method_store_contract(inst, type, &ctid);
	atomic_add_16(&storing_contract, -1);

	restarter_free_method_context(mcp);

	/*
	 * Similarly for the start method PID.
	 */
	if (type == METHOD_START && !inst->ri_mi_deleted)
		(void) libscf_write_start_pid(inst->ri_m_inst, pid);

	if (instance_is_wait_style(inst) && type == METHOD_START) {
		/* Wait style instances don't get timeouts on start methods. */
		if (wait_register(pid, inst->ri_i.i_fmri, 1, 0)) {
			log_error(LOG_WARNING,
			    "%s: couldn't register %ld for wait\n",
			    inst->ri_i.i_fmri, pid);
			result = EFAULT;
			goto contract_out;
		}
		write_status(inst, mname, 0);

	} else {
		int r, err;
		time_t start_time;
		time_t end_time;

		/*
		 * Because on upgrade/live-upgrade we may have no chance
		 * to override faulty timeout values on the way to
		 * manifest import, all services on the path to manifest
		 * import are treated the same as INFINITE timeout services.
		 */

		start_time = time(NULL);
		if (timeout != METHOD_TIMEOUT_INFINITE && !is_timeout_ovr(inst))
			timeout_insert(inst, ctid, timeout);
		else
			timeout = METHOD_TIMEOUT_INFINITE;

		/* Unlock the instance while waiting for the method. */
		MUTEX_UNLOCK(&inst->ri_lock);

		do {
			r = waitpid(pid, &ret_status, NULL);
		} while (r == -1 && errno == EINTR);
		if (r == -1)
			err = errno;

		/* Re-grab the lock. */
		inst = inst_lookup_by_id(id);

		/*
		 * inst can't be removed, as the removal thread waits
		 * for completion of this one.
		 */
		assert(inst != NULL);
		*instp = inst;

		if (inst->ri_timeout != NULL && inst->ri_timeout->te_fired)
			timeout_fired = 1;

		timeout_remove(inst, ctid);

		log_framework(LOG_DEBUG,
		    "%s method for %s exited with status %d.\n", mname,
		    inst->ri_i.i_fmri, WEXITSTATUS(ret_status));

		if (r == -1) {
			log_error(LOG_WARNING,
			    "Couldn't waitpid() for %s method of %s (%s).\n",
			    mname, inst->ri_i.i_fmri, strerror(err));
			result = EFAULT;
			goto contract_out;
		}

		if (type == METHOD_START)
			write_status(inst, mname, ret_status);

		/* return ERANGE if this service doesn't retry on timeout */
		if (timeout_fired == 1 && timeout_retry == 0) {
			result = ERANGE;
			goto contract_out;
		}

		if (!WIFEXITED(ret_status)) {
			/*
			 * If method didn't exit itself (it was killed by an
			 * external entity, etc.), consider the entire
			 * method_run as failed.
			 */
			if (WIFSIGNALED(ret_status)) {
				char buf[SIG2STR_MAX];
				(void) sig2str(WTERMSIG(ret_status), buf);

				log_error(LOG_WARNING, "%s: Method \"%s\" "
				    "failed due to signal %s.\n",
				    inst->ri_i.i_fmri, method, buf);
				log_instance(inst, B_TRUE, "Method \"%s\" "
				    "failed due to signal %s.", mname, buf);
			} else {
				log_error(LOG_WARNING, "%s: Method \"%s\" "
				    "failed with exit status %d.\n",
				    inst->ri_i.i_fmri, method,
				    WEXITSTATUS(ret_status));
				log_instance(inst, B_TRUE, "Method \"%s\" "
				    "failed with exit status %d.", mname,
				    WEXITSTATUS(ret_status));
			}
			result = EAGAIN;
			goto contract_out;
		}

		*exit_code = WEXITSTATUS(ret_status);
		if (*exit_code != 0) {
			log_error(LOG_WARNING,
			    "%s: Method \"%s\" failed with exit status %d.\n",
			    inst->ri_i.i_fmri, method, WEXITSTATUS(ret_status));
		}

		log_instance(inst, B_TRUE, "Method \"%s\" exited with status "
		    "%d.", mname, *exit_code);

		if (*exit_code != 0)
			goto contract_out;

		end_time = time(NULL);

		/* Give service contract remaining seconds to empty */
		if (timeout != METHOD_TIMEOUT_INFINITE)
			timeout -= (end_time - start_time);
	}

assured_kill:
	/*
	 * For stop methods, assure that the service contract has emptied
	 * before returning.
	 */
	if (type == METHOD_STOP && (!instance_is_transient_style(inst)) &&
	    !(contract_is_empty(inst->ri_i.i_primary_ctid))) {
		int times = 0;

		if (timeout != METHOD_TIMEOUT_INFINITE)
			timeout_insert(inst, inst->ri_i.i_primary_ctid,
			    timeout);

		for (;;) {
			/*
			 * Check frequently at first, then back off.  This
			 * keeps startd from idling while shutting down.
			 */
			if (times < 20) {
				(void) poll(NULL, 0, 5);
				times++;
			} else {
				(void) poll(NULL, 0, 100);
			}
			if (contract_is_empty(inst->ri_i.i_primary_ctid))
				break;
		}

		if (timeout != METHOD_TIMEOUT_INFINITE)
			if (inst->ri_timeout->te_fired)
				result = EFAULT;

		timeout_remove(inst, inst->ri_i.i_primary_ctid);
	}

contract_out:
	/* Abandon contracts for transient methods & methods that fail. */
	transient = method_is_transient(inst, type);
	if ((transient || *exit_code != 0 || result != 0) &&
	    (restarter_is_kill_method(method) < 0))
		method_remove_contract(inst, !transient, B_TRUE);

out:
	if (ctfd >= 0)
		(void) close(ctfd);
	scf_snapshot_destroy(snap);
	free(method);
	return (result);
}

/*
 * The method thread executes a service method to effect a state transition.
 * The next_state of info->sf_id should be non-_NONE on entrance, and it will
 * be _NONE on exit (state will either be what next_state was (on success), or
 * it will be _MAINT (on error)).
 *
 * There are six classes of methods to consider: start & other (stop, refresh)
 * for each of "normal" services, wait services, and transient services.  For
 * each, the method must be fetched from the repository & executed.  fork()ed
 * methods must be waited on, except for the start method of wait services
 * (which must be registered with the wait subsystem via wait_register()).  If
 * the method succeeded (returned 0), then for start methods its contract
 * should be recorded as the primary contract for the service.  For other
 * methods, it should be abandoned.  If the method fails, then depending on
 * the failure, either the method should be reexecuted or the service should
 * be put into maintenance.  Either way the contract should be abandoned.
 */
void *
method_thread(void *arg)
{
	fork_info_t *info = arg;
	restarter_inst_t *inst;
	scf_handle_t	*local_handle;
	scf_instance_t	*s_inst = NULL;
	int r, exit_code;
	boolean_t retryable;
	restarter_str_t reason;

	assert(0 <= info->sf_method_type && info->sf_method_type <= 2);

	/* Get (and lock) the restarter_inst_t. */
	inst = inst_lookup_by_id(info->sf_id);

	assert(inst->ri_method_thread != 0);
	assert(instance_in_transition(inst) == 1);

	/*
	 * We cannot leave this function with inst in transition, because
	 * protocol.c withholds messages for inst otherwise.
	 */

	log_framework(LOG_DEBUG, "method_thread() running %s method for %s.\n",
	    method_names[info->sf_method_type], inst->ri_i.i_fmri);

	local_handle = libscf_handle_create_bound_loop();

rebind_retry:
	/* get scf_instance_t */
	switch (r = libscf_fmri_get_instance(local_handle, inst->ri_i.i_fmri,
	    &s_inst)) {
	case 0:
		break;

	case ECONNABORTED:
		libscf_handle_rebind(local_handle);
		goto rebind_retry;

	case ENOENT:
		/*
		 * It's not there, but we need to call this so protocol.c
		 * doesn't think it's in transition anymore.
		 */
		(void) restarter_instance_update_states(local_handle, inst,
		    inst->ri_i.i_state, RESTARTER_STATE_NONE, RERR_NONE,
		    restarter_str_none);
		goto out;

	case EINVAL:
	case ENOTSUP:
	default:
		bad_error("libscf_fmri_get_instance", r);
	}

	inst->ri_m_inst = s_inst;
	inst->ri_mi_deleted = B_FALSE;

retry:
	if (info->sf_method_type == METHOD_START)
		log_transition(inst, START_REQUESTED);

	r = method_run(&inst, info->sf_method_type, &exit_code);

	if (r == 0 && exit_code == 0) {
		/* Success! */
		assert(inst->ri_i.i_next_state != RESTARTER_STATE_NONE);

		/*
		 * When a stop method succeeds, remove the primary contract of
		 * the service, unless we're going to offline, in which case
		 * retain the contract so we can transfer inherited contracts to
		 * the replacement service.
		 */

		if (info->sf_method_type == METHOD_STOP &&
		    inst->ri_i.i_primary_ctid != 0) {
			if (inst->ri_i.i_next_state == RESTARTER_STATE_OFFLINE)
				inst->ri_i.i_primary_ctid_stopped = 1;
			else
				method_remove_contract(inst, B_TRUE, B_TRUE);
		}
		/*
		 * We don't care whether the handle was rebound because this is
		 * the last thing we do with it.
		 */
		(void) restarter_instance_update_states(local_handle, inst,
		    inst->ri_i.i_next_state, RESTARTER_STATE_NONE,
		    info->sf_event_type, info->sf_reason);

		(void) update_fault_count(inst, FAULT_COUNT_RESET);

		goto out;
	}

	/* Failure.  Retry or go to maintenance. */

	if (r != 0 && r != EAGAIN) {
		retryable = B_FALSE;
	} else {
		switch (exit_code) {
		case SMF_EXIT_ERR_CONFIG:
		case SMF_EXIT_ERR_NOSMF:
		case SMF_EXIT_ERR_PERM:
		case SMF_EXIT_ERR_FATAL:
			retryable = B_FALSE;
			break;

		default:
			retryable = B_TRUE;
		}
	}

	if (retryable && update_fault_count(inst, FAULT_COUNT_INCR) != 1)
		goto retry;

	/* maintenance */
	if (r == ELOOP)
		log_transition(inst, START_FAILED_REPEATEDLY);
	else if (r == ERANGE)
		log_transition(inst, START_FAILED_TIMEOUT_FATAL);
	else if (exit_code == SMF_EXIT_ERR_CONFIG)
		log_transition(inst, START_FAILED_CONFIGURATION);
	else if (exit_code == SMF_EXIT_ERR_FATAL)
		log_transition(inst, START_FAILED_FATAL);
	else
		log_transition(inst, START_FAILED_OTHER);

	if (r == ELOOP) {
		reason = restarter_str_restarting_too_quickly;
	} else if (retryable) {
		reason = restarter_str_fault_threshold_reached;
	} else {
		reason = restarter_str_method_failed;
	}

	(void) restarter_instance_update_states(local_handle, inst,
	    RESTARTER_STATE_MAINT, RESTARTER_STATE_NONE, RERR_FAULT,
	    reason);

	if (!method_is_transient(inst, info->sf_method_type) &&
	    inst->ri_i.i_primary_ctid != 0)
		method_remove_contract(inst, B_TRUE, B_TRUE);

out:
	inst->ri_method_thread = 0;

	/*
	 * Unlock the mutex after broadcasting to avoid a race condition
	 * with restarter_delete_inst() when the 'inst' structure is freed.
	 */
	(void) pthread_cond_broadcast(&inst->ri_method_cv);
	MUTEX_UNLOCK(&inst->ri_lock);

	scf_instance_destroy(s_inst);
	scf_handle_destroy(local_handle);
	startd_free(info, sizeof (fork_info_t));
	return (NULL);
}
