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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif /* _FILE_OFFSET_BITS */

#include <sys/contract/process.h>
#include <sys/ctfs.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <libuutil.h>
#include <limits.h>
#include <procfs.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "startd.h"

void
contract_abandon(ctid_t ctid)
{
	int err;

	assert(ctid != 0);

	err = contract_abandon_id(ctid);

	if (err)
		log_framework(LOG_NOTICE,
		    "failed to abandon contract %ld: %s\n", ctid,
		    strerror(err));
}

int
contract_kill(ctid_t ctid, int sig, const char *fmri)
{
	if (sigsend(P_CTID, ctid, sig) == -1 && errno != ESRCH) {
		log_error(LOG_WARNING,
		    "%s: Could not signal all contract members: %s\n", fmri,
		    strerror(errno));
		return (-1);
	}

	return (0);
}

ctid_t
contract_init()
{
	int psfd, csfd;
	ctid_t ctid, configd_ctid = -1;
	psinfo_t psi;
	ct_stathdl_t s;
	ctid_t *ctids;
	uint_t nctids;
	uint_t n;
	int err;

	/*
	 * 2.  Acquire any contracts we should have inherited.  First, find the
	 * contract we belong to, then get its status.
	 */
	if ((psfd = open("/proc/self/psinfo", O_RDONLY)) < 0) {
		log_error(LOG_WARNING, "Can not open /proc/self/psinfo; unable "
		    "to check to adopt contracts: %s\n", strerror(errno));
		return (-1);
	}

	if (read(psfd, &psi, sizeof (psinfo_t)) != sizeof (psinfo_t)) {
		log_error(LOG_WARNING, "Can not read from /proc/self/psinfo; "
		    "unable to adopt contracts: %s\n",
		    strerror(errno));
		startd_close(psfd);
		return (-1);
	}

	ctid = psi.pr_contract;

	startd_close(psfd);

	if ((csfd = contract_open(ctid, "process", "status", O_RDONLY)) < 0) {
		log_error(LOG_WARNING, "Can not open containing contract "
		    "status; unable to adopt contracts: %s\n", strerror(errno));
		return (-1);
	}

	/* 3.  Go about adopting our member list. */

	err = ct_status_read(csfd, CTD_ALL, &s);
	startd_close(csfd);
	if (err) {
		log_error(LOG_WARNING, "Can not read containing contract "
		    "status; unable to adopt: %s\n", strerror(err));
		return (-1);
	}

	if (err = ct_pr_status_get_contracts(s, &ctids, &nctids)) {
		log_error(LOG_WARNING, "Can not get my inherited contracts; "
		    "unable to adopt: %s\n", strerror(err));
		ct_status_free(s);
		return (-1);
	}

	if (nctids == 0) {
		/*
		 * We're booting, as a svc.startd which managed to fork a
		 * child will always have a svc.configd contract to adopt.
		 */
		st->st_initial = 1;
		ct_status_free(s);
		return (-1);
	}

	/*
	 * We're restarting after an interruption of some kind.
	 */
	log_framework(LOG_NOTICE, "restarting after interruption\n");
	st->st_initial = 0;

	/*
	 * 3'.  Loop through the array, adopting them all where possible, and
	 * noting which one contains svc.configd (via a cookie vlaue of
	 * CONFIGD_COOKIE).
	 */
	for (n = 0; n < nctids; n++) {
		int ccfd;
		ct_stathdl_t cs;

		if ((ccfd = contract_open(ctids[n], "process", "ctl",
		    O_WRONLY)) < 0) {
			log_error(LOG_WARNING, "Can not open contract %ld ctl "
			    "for adoption: %s\n", ctids[n], strerror(err));

			continue;
		}

		if ((csfd = contract_open(ctids[n], "process", "status",
		    O_RDONLY)) < 0) {
			log_error(LOG_WARNING, "Can not open contract %ld "
			    "status for cookie: %s\n", ctids[n], strerror(err));
			startd_close(ccfd);

			continue;
		}

		if (err = ct_ctl_adopt(ccfd)) {
			log_error(LOG_WARNING, "Can not adopt contract %ld: "
			    "%s\n", ctids[n], strerror(err));
			startd_close(ccfd);
			startd_close(csfd);

			continue;
		}

		startd_close(ccfd);

		if (err = ct_status_read(csfd, CTD_COMMON, &cs)) {
			log_error(LOG_WARNING, "Can not read contract %ld"
			    "status; unable to fetch cookie: %s\n", ctids[n],
			    strerror(err));

			ct_status_free(cs);
			startd_close(csfd);

			continue;
		}

		if (ct_status_get_cookie(cs) == CONFIGD_COOKIE)
			configd_ctid = ctids[n];

		ct_status_free(cs);

		startd_close(csfd);
	}

	ct_status_free(s);

	return (configd_ctid);
}

int
contract_is_empty(ctid_t ctid)
{
	int fd;
	ct_stathdl_t ctstat;
	pid_t *members;
	uint_t num;
	int ret;

	fd = contract_open(ctid, "process", "status", O_RDONLY);
	if (fd < 0)
		return (1);

	ret = ct_status_read(fd, CTD_ALL, &ctstat);
	(void) close(fd);
	if (ret != 0)
		return (1);

	ret = ct_pr_status_get_members(ctstat, &members, &num);
	ct_status_free(ctstat);
	if (ret != 0)
		return (1);

	if (num == 0)
		return (1);
	else
		return (0);
}

typedef struct contract_bucket {
	pthread_mutex_t cb_lock;
	uu_list_t	*cb_list;
} contract_bucket_t;

#define	CI_HASH_SIZE	64
#define	CI_HASH_MASK	(CI_HASH_SIZE - 1);

/*
 * contract_hash is a hash table of contract ids to restarter instance
 * IDs.  It can be used for quick lookups when processing contract events,
 * because the restarter instance lock doesn't need to be held to access
 * its entries.
 */
static contract_bucket_t contract_hash[CI_HASH_SIZE];

static contract_bucket_t *
contract_hold_bucket(ctid_t ctid)
{
	contract_bucket_t *bp;
	int hash;

	hash = ctid & CI_HASH_MASK;

	bp = &contract_hash[hash];
	MUTEX_LOCK(&bp->cb_lock);
	return (bp);
}

static void
contract_release_bucket(contract_bucket_t *bp)
{
	assert(MUTEX_HELD(&bp->cb_lock));
	MUTEX_UNLOCK(&bp->cb_lock);
}

static contract_entry_t *
contract_lookup(contract_bucket_t *bp, ctid_t ctid)
{
	contract_entry_t *ce;

	assert(MUTEX_HELD(&bp->cb_lock));

	if (bp->cb_list == NULL)
		return (NULL);

	for (ce = uu_list_first(bp->cb_list); ce != NULL;
	    ce = uu_list_next(bp->cb_list, ce)) {
		if (ce->ce_ctid == ctid)
			return (ce);
	}

	return (NULL);
}

static void
contract_insert(contract_bucket_t *bp, contract_entry_t *ce)
{
	int r;

	if (bp->cb_list == NULL)
		bp->cb_list = startd_list_create(contract_list_pool, bp, 0);

	uu_list_node_init(ce, &ce->ce_link, contract_list_pool);
	r = uu_list_insert_before(bp->cb_list, NULL, ce);
	assert(r == 0);
}

void
contract_hash_init()
{
	int i;

	for (i = 0; i < CI_HASH_SIZE; i++)
		(void) pthread_mutex_init(&contract_hash[i].cb_lock,
		    &mutex_attrs);
}

void
contract_hash_store(ctid_t ctid, int instid)
{
	contract_bucket_t *bp;
	contract_entry_t *ce;

	bp = contract_hold_bucket(ctid);
	assert(contract_lookup(bp, ctid) == NULL);
	ce = startd_alloc(sizeof (contract_entry_t));
	ce->ce_ctid = ctid;
	ce->ce_instid = instid;

	contract_insert(bp, ce);

	contract_release_bucket(bp);
}

void
contract_hash_remove(ctid_t ctid)
{
	contract_bucket_t *bp;
	contract_entry_t *ce;

	bp = contract_hold_bucket(ctid);

	ce = contract_lookup(bp, ctid);
	if (ce != NULL) {
		uu_list_remove(bp->cb_list, ce);
		startd_free(ce, sizeof (contract_entry_t));
	}

	contract_release_bucket(bp);
}

/*
 * int lookup_inst_by_contract()
 *   Lookup the instance id in the hash table by the contract id.
 *   Returns instid if found, -1 if not.  Doesn't do a hold on the
 *   instance, so a check for continued existence is required.
 */
int
lookup_inst_by_contract(ctid_t ctid)
{
	contract_bucket_t *bp;
	contract_entry_t *ce;
	int id = -1;

	bp = contract_hold_bucket(ctid);
	ce = contract_lookup(bp, ctid);
	if (ce != NULL)
		id = ce->ce_instid;
	contract_release_bucket(bp);

	return (id);
}
