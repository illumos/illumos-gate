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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libuutil.h>
#include "rcapd.h"
#include "rcapd_conf.h"
#include "rcapd_stat.h"
#include "utils.h"

/*
 * Read configuration and set the fields of an rcfg_t correspondingly.
 * Verify that the statistics file is writable, with the optional
 * verify_stat_file_creation() callback.
 */
int
rcfg_read(rcfg_t *_rcfg, int(*verify_stat_file_creation)(void))
{
	scf_simple_handle_t	*simple_h;
	uint64_t		count_val;
	int			ret = E_ERROR;

	rcfg_init(_rcfg);

	if ((simple_h = scf_general_pg_setup(RCAP_FMRI, CONFIG_PG))
	    == NULL) {
		warn(gettext("SMF initialization problem: %s\n"),
		    scf_strerror(scf_error()));
		goto err;
	}

	if (scf_read_count_property(simple_h, PRESSURE, &count_val)
	    == SCF_FAILED) {
		warn(gettext("Configuration property '%s' "
		    "not found. \n"), PRESSURE);
		goto err;
	} else {
		if (count_val > 100)
			_rcfg->rcfg_memory_cap_enforcement_pressure = 100;
		else
			_rcfg->rcfg_memory_cap_enforcement_pressure
			    = count_val;

		debug("cap max pressure: %d%%\n",
		    _rcfg->rcfg_memory_cap_enforcement_pressure);
	}

	if (scf_read_count_property(simple_h, RECONFIG_INT, &count_val)
	    == SCF_FAILED) {
		warn(gettext("Configuration property '%s' "
		    "not found. \n"), RECONFIG_INT);
		goto err;
	} else {
		_rcfg->rcfg_reconfiguration_interval = count_val;
		debug("reconfiguration interval: %d seconds\n",
		    _rcfg->rcfg_reconfiguration_interval);
	}

	if (scf_read_count_property(simple_h, REPORT_INT, &count_val)
	    == SCF_FAILED) {
		warn(gettext("Configuration property '%s' "
		    "not found. \n"), REPORT_INT);
		goto err;
	} else {
		_rcfg->rcfg_report_interval = count_val;
		debug("report interval: %d seconds\n",
		    _rcfg->rcfg_report_interval);
	}

	if (scf_read_count_property(simple_h, RSS_SAMPLE_INT, &count_val)
	    == SCF_FAILED) {
		warn(gettext("Configuration property '%s' "
		    "not found. \n"), RSS_SAMPLE_INT);
		goto err;
	} else {
		_rcfg->rcfg_rss_sample_interval = count_val;
		debug("RSS sample interval: %d seconds\n",
		    _rcfg->rcfg_rss_sample_interval);
	}

	if (scf_read_count_property(simple_h, WALK_INT, &count_val)
	    == SCF_FAILED) {
		warn(gettext("Configuration property '%s' "
		    "not found. \n"), WALK_INT);
		goto err;
	} else {
		_rcfg->rcfg_proc_walk_interval = count_val;
		debug("proc_walk interval: %d seconds\n",
		    _rcfg->rcfg_proc_walk_interval);
	}

	if (_rcfg->rcfg_mode_name == NULL) {
		/*
		 * Set project mode, by default.
		 */
		_rcfg->rcfg_mode = rctype_project;
		_rcfg->rcfg_mode_name = "project";
		debug("mode: %s\n", _rcfg->rcfg_mode_name);
	}

	if (verify_stat_file_creation != 0 && verify_stat_file_creation()
	    != 0) {
		warn(gettext("cannot create statistics file, " "%s"),
		    _rcfg->rcfg_stat_file);
		goto err;
	}

	debug("done parsing\n");
	ret = E_SUCCESS;
	goto out;

err:
	if (scf_error() != SCF_ERROR_NONE) {
		warn(gettext("Unexpected libscf error: %s. \n"),
		    scf_strerror(scf_error()));
	}

out:
	scf_simple_handle_destroy(simple_h);
	return (ret);
}

void
rcfg_init(rcfg_t *rcfg)
{
	bzero(rcfg, sizeof (*rcfg));
	(void) strcpy(rcfg->rcfg_stat_file, STAT_FILE_DEFAULT);
}

/*
 * Modify configuration in repository given the rcfg_t structure.
 */
int
modify_config(rcfg_t *conf)
{
	scf_simple_handle_t	*simple_h;
	scf_transaction_t	*tx = NULL;
	int			rval, ret = E_ERROR;

	if ((simple_h = scf_general_pg_setup(RCAP_FMRI, CONFIG_PG))
	    == NULL) {
		warn(gettext("SMF initialization problem: %s\n"),
		    scf_strerror(scf_error()));
		goto out;
	}

	if ((tx = scf_transaction_setup(simple_h)) == NULL) {
		warn(gettext("SMF initialization problem: %s\n"),
		    scf_strerror(scf_error()));
		goto out;
	}

	do {
		if (scf_set_count_property(tx, PRESSURE,
		    conf->rcfg_memory_cap_enforcement_pressure, 0)
		    != SCF_SUCCESS) {
			warn(gettext("Couldn't set '%s' property. \n"),
			    PRESSURE);
			goto out;
		}

		if (scf_set_count_property(tx, RECONFIG_INT,
		    conf->rcfg_reconfiguration_interval, 0) != SCF_SUCCESS) {
			warn(gettext("Couldn't set '%s' property. \n"),
			    RECONFIG_INT);
			goto out;
		}

		if (scf_set_count_property(tx, RSS_SAMPLE_INT,
		    conf->rcfg_rss_sample_interval, 0) != SCF_SUCCESS) {
			warn(gettext("Couldn't set '%s' property. \n"),
			    RSS_SAMPLE_INT);
			goto out;
		}

		if (scf_set_count_property(tx, REPORT_INT,
		    conf->rcfg_report_interval, 0) != SCF_SUCCESS) {
			warn(gettext("Couldn't set '%s' property. \n"),
			    REPORT_INT);
			goto out;
		}

		if (scf_set_count_property(tx, WALK_INT,
		    conf->rcfg_proc_walk_interval, 0) != SCF_SUCCESS) {
			warn(gettext("Couldn't set '%s' property. \n"),
			    WALK_INT);
			goto out;
		}

		if ((rval = scf_transaction_commit(tx)) == -1)
			goto out;

		if (rval == 0) {
			if (scf_transaction_restart(simple_h, tx)
			    != SCF_SUCCESS) {
				warn(gettext("SMF initialization problem: "
				    "%s\n"), scf_strerror(scf_error()));
				goto out;
			}
		}
	} while (rval == 0);

	ret = E_SUCCESS;

out:
	if (tx != NULL) {
		scf_transaction_destroy_children(tx);
		scf_transaction_destroy(tx);
	}
	scf_simple_handle_destroy(simple_h);
	return (ret);
}
