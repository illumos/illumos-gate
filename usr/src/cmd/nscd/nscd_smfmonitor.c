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
 *
 * Copyright 2018 Joyent, Inc.
 */

#include <stdlib.h>
#include <libscf.h>
#include <string.h>
#include "nscd_switch.h"
#include "nscd_log.h"
#include "nscd_door.h"

extern int	_whoami;

/*
 * Service states monitored by nscd. Protected by
 * readers/writer lock nscd_smf_service_state_lock
 */
nscd_smf_state_t *nscd_smf_service_state;
static rwlock_t nscd_smf_service_state_lock = DEFAULTRWLOCK;
/*
 * init service state table
 */
nscd_rc_t
_nscd_alloc_service_state_table()
{
	int i;

	nscd_smf_service_state = calloc(NSCD_NUM_SMF_FMRI,
	    sizeof (nscd_smf_state_t));

	if (nscd_smf_service_state == NULL)
		return (NSCD_NO_MEMORY);

	for (i = 1; i < NSCD_NUM_SMF_FMRI; i++)
		NSCD_SMF_SVC_STATE(i) = NSCD_SVC_STATE_UNINITED;

	return (NSCD_SUCCESS);
}

static int
query_smf_state(int srci)
{

	int	ret = NSCD_SVC_STATE_UNINITED;
	char	*state = NULL;
	char	*me = "query_smf_state";

	state = smf_get_state(NSCD_SMF_SVC_FMRI(srci));
	if (state == NULL)
		return (ret);

	_NSCD_LOG(NSCD_LOG_SMF_MONITOR, NSCD_LOG_LEVEL_DEBUG)
		(me, "%s -- %s\n", state, NSCD_SMF_SVC_FMRI(srci));

	(void) rw_wrlock(&nscd_smf_service_state_lock);

	if (nscd_smf_service_state[srci].src_name == NULL)
		nscd_smf_service_state[srci].src_name =
		    NSCD_NSW_SRC_NAME(srci);

	if (strcmp(state, SCF_STATE_STRING_UNINIT) == 0)
		NSCD_SMF_SVC_STATE(srci) = SCF_STATE_UNINIT;
	else if (strcmp(state, SCF_STATE_STRING_MAINT) == 0)
		NSCD_SMF_SVC_STATE(srci) = SCF_STATE_MAINT;
	else if (strcmp(state, SCF_STATE_STRING_OFFLINE) == 0)
		NSCD_SMF_SVC_STATE(srci) = SCF_STATE_OFFLINE;
	else if (strcmp(state, SCF_STATE_STRING_DISABLED) == 0)
		NSCD_SMF_SVC_STATE(srci) = SCF_STATE_DISABLED;
	else if (strcmp(state, SCF_STATE_STRING_ONLINE) == 0)
		NSCD_SMF_SVC_STATE(srci) = SCF_STATE_ONLINE;
	else if (strcmp(state, SCF_STATE_STRING_DEGRADED) == 0)
		NSCD_SMF_SVC_STATE(srci) = SCF_STATE_DEGRADED;

	ret = NSCD_SMF_SVC_STATE(srci);
	(void) rw_unlock(&nscd_smf_service_state_lock);

	free(state);
	return (ret);
}

/* ARGSUSED */
static void *
set_smf_state(void *arg)
{

	int	i;
	int	st;

	(void) thr_setname(thr_self(), "set_smf_state");

	/*
	 * the forker nscd needs not monitor the state
	 * of the client services
	 */
	if (_whoami == NSCD_FORKER)
		thr_exit(0);

	/*CONSTCOND*/
	while (1) {

		/* skip the first service which is nscd */
		for (i = 1; i < NSCD_NUM_SMF_FMRI; i++) {
			st = query_smf_state(i);
			if (st == NSCD_SVC_STATE_UNINITED)
				break;
		}

		(void) sleep(NSCD_SW_CFG_G.check_smf_state_interval_g);
	}
	/* NOTREACHED */
	/*LINTED E_FUNC_HAS_NO_RETURN_STMT*/
}

nscd_rc_t
_nscd_init_smf_monitor() {

	int	errnum;
	char	*me = "_nscd_init_smf_monitor";

	_NSCD_LOG(NSCD_LOG_SMF_MONITOR, NSCD_LOG_LEVEL_DEBUG)
	(me, "initializing the smf monitor\n");

	/*
	 * start a thread to check the state of the client services
	 */
	if (thr_create(NULL, NULL, set_smf_state,
		NULL, THR_DETACHED, NULL) != 0) {
		errnum = errno;
		_NSCD_LOG(NSCD_LOG_SMF_MONITOR, NSCD_LOG_LEVEL_ERROR)
		(me, "thr_create: %s\n", strerror(errnum));
		return (NSCD_THREAD_CREATE_ERROR);
	}

	return (NSCD_SUCCESS);
}

int
_nscd_get_smf_state(int srci, int dbi, int recheck)
{
	int	s;
	char	*n;

	n = NSCD_NSW_SRC_NAME(srci);

	/* the files, compat, and dns backends are always available */
	if ((*n == 'f' || *n == 'c' || *n == 'd' || *n == 'a') &&
	    (strcmp(NSCD_NSW_SRC_NAME(srci), "files") == 0 ||
	    strcmp(NSCD_NSW_SRC_NAME(srci), "compat") == 0 ||
	    strcmp(NSCD_NSW_SRC_NAME(srci), "ad") == 0 ||
	    strcmp(NSCD_NSW_SRC_NAME(srci), "dns") == 0)) {
		return (SCF_STATE_ONLINE);
	}

	/*
	 * for the printer database and user backend, treat the
	 * backend as a unsupported one, as nscd can not access
	 * the home directory of the user
	 */
	if (*n == 'u' && strcmp(NSCD_NSW_SRC_NAME(srci), "user") == 0) {
		if (strcmp(NSCD_NSW_DB_NAME(dbi), NSS_DBNAM_PRINTERS) == 0)
			return (NSCD_SVC_STATE_UNSUPPORTED_SRC);
		else
			return (SCF_STATE_ONLINE);
	}

	/*
	 * Foreign backend is not supported by nscd unless
	 * the backend supports the nss2 interface (global
	 * symbol _nss_<backname name>_version is present),
	 * tell the switch engine to return NSS_TRYLOCAL
	 * if needed via rc NSCD_SVC_STATE_FOREIGN_SRC.
	 */
	if (srci >= _nscd_cfg_num_nsw_src)
		return (NSCD_SVC_STATE_FOREIGN_SRC);

	if (recheck == 1)
		return (query_smf_state(srci));

	(void) rw_rdlock(&nscd_smf_service_state_lock);
	s = NSCD_SMF_SVC_STATE(srci);
	(void) rw_unlock(&nscd_smf_service_state_lock);

	/*
	 * if the state has been queried at least once but is
	 * still not online, query one more time
	 */
	if (s != NSCD_SVC_STATE_UNINITED && s < SCF_STATE_ONLINE)
		s = query_smf_state(srci);

	return (s);
}
