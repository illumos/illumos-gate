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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <errno.h>
#include <libintl.h>
#include <sys/wait.h>
#include <sys/ctfs.h>
#include <sys/contract/process.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "inetd_impl.h"


/* paths/filenames of contract related files */
#define	CONTRACT_ROOT_PATH	CTFS_ROOT "/process/"
#define	CONTRACT_TEMPLATE_PATH  CONTRACT_ROOT_PATH "template"

static int active_tmpl_fd = -1;

/*
 * Creates and configures the the contract template used for all inetd's
 * methods.
 * Returns -1 on error, else the fd of the created template.
 */
static int
create_contract_template(void)
{
	int		fd;
	int		err;

	if ((fd = open(CONTRACT_TEMPLATE_PATH, O_RDWR)) == -1) {
		error_msg(gettext("Failed to open contract file %s: %s"),
		    CONTRACT_TEMPLATE_PATH, strerror(errno));
		return (-1);
	}

	/*
	 * Make contract inheritable and make hardware errors fatal.
	 * We also limit the scope of fatal events to the process
	 * group.  In order of preference we would have contract-aware
	 * login services or a property indicating which services need
	 * such scoping, but for the time being we'll assume that most
	 * non login-style services run in a single process group.
	 */
	if (((err = ct_pr_tmpl_set_param(fd,
	    CT_PR_INHERIT|CT_PR_PGRPONLY)) != 0) ||
	    ((err = ct_pr_tmpl_set_fatal(fd, CT_PR_EV_HWERR)) != 0) ||
	    ((err = ct_tmpl_set_critical(fd, 0)) != 0) ||
	    ((err = ct_tmpl_set_informative(fd, 0)) != 0)) {
		error_msg(gettext(
		    "Failed to set parameter for contract template: %s"),
		    strerror(err));
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

/* Returns -1 on error, else 0. */
int
contract_init(void)
{
	if ((active_tmpl_fd = create_contract_template()) == -1) {
		error_msg(gettext("Failed to create contract template"));
		return (-1);
	}
	return (0);
}

void
contract_fini(void)
{
	if (active_tmpl_fd != -1) {
		(void) close(active_tmpl_fd);
		active_tmpl_fd = -1;
	}
}

/*
 * To be called directly before a service method is forked, this function
 * results in the method process being in a new contract based on the active
 * contract template.
 */
int
contract_prefork(const char *fmri, int method)
{
	int err;

	if ((err = ct_pr_tmpl_set_svc_fmri(active_tmpl_fd, fmri)) != 0) {
		error_msg(gettext("Failed to set svc_fmri term: %s"),
		    strerror(err));
		return (-1);
	}
	if ((err = ct_pr_tmpl_set_svc_aux(active_tmpl_fd,
	    methods[method].name)) != 0) {
		error_msg(gettext("Failed to set svc_aux term: %s"),
		    strerror(err));
		return (-1);
	}

	if ((err = ct_tmpl_activate(active_tmpl_fd)) != 0) {
		error_msg(gettext("Failed to activate contract template: %s"),
		    strerror(err));
		return (-1);
	}
	return (0);
}

/*
 * To be called in both processes directly after a service method is forked,
 * this function results in switching off contract creation for any
 * forks done by either process, unless contract_prefork() is called beforehand.
 */
void
contract_postfork(void)
{
	int err;

	if ((err = ct_tmpl_clear(active_tmpl_fd)) != 0)
		error_msg("Failed to clear active contract template: %s",
		    strerror(err));
}

/*
 * Fetch the latest created contract id into the space referenced by 'cid'.
 * Returns -1 on error, else 0.
 */
int
get_latest_contract(ctid_t *cid)
{
	if ((errno = contract_latest(cid)) != 0) {
		error_msg(gettext("Failed to get new contract's id: %s"),
		    strerror(errno));
		return (-1);
	}

	return (0);
}

/* Returns -1 on error (with errno set), else fd. */
static int
open_contract_ctl_file(ctid_t cid)
{
	return (contract_open(cid, "process", "ctl", O_WRONLY));
}

/*
 * Adopt a contract.  Emits an error message and returns -1 on failure, else
 * 0.
 */
int
adopt_contract(ctid_t ctid, const char *fmri)
{
	int fd;
	int err;
	int ret = 0;

	if ((fd = open_contract_ctl_file(ctid)) == -1) {
		if (errno == EACCES || errno == ENOENT) {
			/*
			 * We must not have inherited this contract.  That can
			 * happen if we were disabled and restarted.
			 */
			debug_msg("Could not adopt contract %ld for %s "
			    "(could not open ctl file: permission denied).\n",
			    ctid, fmri);
			return (-1);
		}

		error_msg(gettext("Could not adopt contract id %ld registered "
		    "with %s (could not open ctl file: %s).  Events will be "
		    "ignored."), ctid, fmri, strerror(errno));
		return (-1);
	}

	if ((err = ct_ctl_adopt(fd)) != 0) {
		error_msg(gettext("Could not adopt contract id %ld registered "
		    "with %s (%s).  Events will be ignored."), ctid, fmri,
		    strerror(err));
		ret = -1;
	}

	err = close(fd);
	if (err != 0)
		error_msg(gettext("Could not close file descriptor %d."), fd);

	return (ret);
}

/* Returns -1 on error, else 0. */
int
abandon_contract(ctid_t ctid)
{
	int fd;
	int err;

	assert(ctid != -1);

	if ((fd = open_contract_ctl_file(ctid)) == -1) {
		error_msg(gettext("Failed to abandon contract %d: %s"), ctid,
		    strerror(errno));
		return (-1);
	}

	if ((err = ct_ctl_abandon(fd)) != 0) {
		(void) close(fd);
		error_msg(gettext("Failed to abandon contract %d: %s"), ctid,
		    strerror(err));
		return (-1);
	}

	(void) close(fd);

	return (0);
}
