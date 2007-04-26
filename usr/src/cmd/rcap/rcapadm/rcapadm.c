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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libintl.h>
#include <locale.h>
#include <zone.h>
#include <libzonecfg.h>

#include "utils.h"
#include "rcapd.h"
#include "rcapd_conf.h"
#include "rcapd_stat.h"

static void
usage()
{
	(void) fprintf(stderr,
	    gettext("usage: rcapadm\n"
	    "               [-E|-D]                                "
	    "# enable/disable rcapd\n"
	    "               [-n]                                   "
	    "# don't start/stop rcapd\n"
	    "               [-i <scan|sample|report|config>=value] "
	    "# set intervals\n"
	    "               [-c <percent>]                         "
	    "# set memory cap\n"
	    "                                                      "
	    "# enforcement threshold\n"
	    "               [-z <zonename> -m <max-rss>]               "
	    "# update zone memory cap\n"));
	exit(E_USAGE);
}

static rcfg_t conf;
static int enable = -1;
static int disable = -1;
static int pressure = -1;
static int no_starting_stopping = -1;
static int scan_interval = -1;
static int report_interval = -1;
static int config_interval = -1;
static int sample_interval = -1;

static char *subopt_v[] = {
	"scan",
	"sample",
	"report",
	"config",
	NULL
};

typedef enum {
	OPT_SCAN = 0,
	OPT_SAMPLE,
	OPT_REPORT,
	OPT_CONFIG
} subopt_idx_t;

static void
print_state(void)
{
	scf_simple_prop_t *persistent_prop = NULL;
	scf_simple_prop_t *temporary_prop = NULL;
	uint8_t *persistent = NULL;
	uint8_t *temporary = NULL;
	scf_handle_t *h;
	/* LINTED: conditionally assigned and used in function */
	ssize_t numvals;

	if ((h = scf_handle_create(SCF_VERSION)) == NULL ||
	    scf_handle_bind(h) != 0)
		goto out;

	if ((persistent_prop = scf_simple_prop_get(h, RCAP_FMRI,
	    SCF_PG_GENERAL, SCF_PROPERTY_ENABLED)) != NULL && (numvals =
	    scf_simple_prop_numvalues(persistent_prop)) > 0)
		persistent = scf_simple_prop_next_boolean(persistent_prop);

	if ((temporary_prop = scf_simple_prop_get(h, RCAP_FMRI,
	    SCF_PG_GENERAL_OVR, SCF_PROPERTY_ENABLED)) != NULL && (numvals =
	    scf_simple_prop_numvalues(temporary_prop)) > 0)
		temporary = scf_simple_prop_next_boolean(temporary_prop);

out:
	if (!persistent)
		(void) printf(gettext("                                      "
		    "state: unknown"));
	else if (temporary && *temporary != *persistent)
		(void) printf(gettext("                                      "
		    "state: %s (%s at next boot)\n"), *temporary ?
		    gettext("enabled") : gettext("disabled"), *persistent ?
		    gettext("enabled") : gettext("disabled"));
	else
		(void) printf(gettext("                                      "
		    "state: %s\n"), *persistent ? gettext("enabled") :
			gettext("disabled"));

	(void) printf(gettext("           memory cap enforcement"
	    " threshold: %d%%\n"), conf.rcfg_memory_cap_enforcement_pressure);
	(void) printf(gettext("                    process scan rate"
	    " (sec): %d\n"), conf.rcfg_proc_walk_interval);
	(void) printf(gettext("                 reconfiguration rate"
	    " (sec): %d\n"), conf.rcfg_reconfiguration_interval);
	(void) printf(gettext("                          report rate"
	    " (sec): %d\n"), conf.rcfg_report_interval);
	(void) printf(gettext("                    RSS sampling rate"
	    " (sec): %d\n"), conf.rcfg_rss_sample_interval);

	scf_simple_prop_free(temporary_prop);
	scf_simple_prop_free(persistent_prop);
	scf_handle_destroy(h);
}

/*
 * Update the in-kernel memory cap for the specified zone.
 */
static int
update_zone_mcap(char *zonename, char *maxrss)
{
	zoneid_t zone_id;
	uint64_t num;

	if (getzoneid() != GLOBAL_ZONEID || zonecfg_in_alt_root())
		return (E_SUCCESS);

	/* get the running zone from the kernel */
	if ((zone_id = getzoneidbyname(zonename)) == -1) {
		(void) fprintf(stderr, gettext("zone '%s' must be running\n"),
		    zonename);
		return (E_ERROR);
	}

	if (zonecfg_str_to_bytes(maxrss, &num) == -1) {
		(void) fprintf(stderr, gettext("invalid max-rss value\n"));
		return (E_ERROR);
	}

	if (zone_setattr(zone_id, ZONE_ATTR_PHYS_MCAP, &num, 0) == -1) {
		(void) fprintf(stderr, gettext("could not set memory "
		    "cap for zone '%s'\n"), zonename);
		return (E_ERROR);
	}

	return (E_SUCCESS);
}

int
main(int argc, char *argv[])
{
	char *subopts, *optval;
	int modified = 0;
	boolean_t refresh = B_FALSE;
	int opt;
	char *zonename;
	char *maxrss = NULL;

	(void) setprogname("rcapadm");
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((opt = getopt(argc, argv, "DEc:i:m:nz:")) != EOF) {
		switch (opt) {
		case 'n':
			no_starting_stopping = 1;
			break;
		case 'c':
			if ((pressure = xatoi(optarg)) < 0 ||
			    pressure > 100 ||
			    errno == EINVAL)
				usage();
			modified++;
			break;
		case 'E':
			enable = 1;
			disable = 0;
			break;
		case 'D':
			disable = 1;
			enable = 0;
			break;
		case 'i':
			subopts = optarg;
			while (*subopts != '\0') {
				switch (getsubopt(&subopts, subopt_v,
				    &optval)) {
					case OPT_SCAN:
						if (optval == NULL ||
						    (scan_interval =
						    xatoi(optval)) <= 0)
							usage();
						break;
					case OPT_SAMPLE:
						if (optval == NULL ||
						    (sample_interval =
						    xatoi(optval)) <= 0)
							usage();
						break;
					case OPT_REPORT:
						if (optval == NULL ||
						    (report_interval =
						    xatoi(optval)) < 0)
							usage();
						break;
					case OPT_CONFIG:
						if (optval == NULL ||
						    (config_interval =
						    xatoi(optval)) < 0)
							usage();
						break;
					default:
						usage();
				}
			}
			modified++;
			break;
		case 'm':
			maxrss = optarg;
			break;
		case 'z':
			refresh = B_TRUE;
			zonename = optarg;
			break;
		default:
			usage();
		}
	}

	/* the -z & -m options must be used together */
	if (argc > optind || (refresh && maxrss == NULL) ||
	    (!refresh && maxrss != NULL))
		usage();

	if (refresh && (no_starting_stopping > 0 || modified))
		usage();

	/*
	 * disable/enable before reading configuration from the repository
	 * which may fail and prevents the disabling/enabling to complete.
	 */
	if (disable > 0) {
		if (smf_disable_instance(RCAP_FMRI, no_starting_stopping > 0
		    ? SMF_AT_NEXT_BOOT : 0) != 0)
			die(gettext("cannot disable service: %s\n"),
			    scf_strerror(scf_error()));
	}

	if (enable > 0) {
		if (smf_enable_instance(RCAP_FMRI, no_starting_stopping > 0
		    ? SMF_AT_NEXT_BOOT : 0) != 0)
			die(gettext("cannot enable service: %s\n"),
			    scf_strerror(scf_error()));
	}

	if (rcfg_read(&conf, NULL) != E_SUCCESS) {
		/*
		 * If instance is enabled, put it in maintenance since we
		 * failed to read configuration from the repository or
		 * create statistics file.
		 */
		if (strcmp(smf_get_state(RCAP_FMRI),
		    SCF_STATE_STRING_DISABLED) != 0)
			(void) smf_maintain_instance(RCAP_FMRI, 0);

		die(gettext("resource caps not configured\n"));
	} else {
		/* Done reading configuration */
		if (strcmp(conf.rcfg_mode_name, "project") != 0) {
			warn(gettext("%s mode specification ignored -- using"
			    " project mode\n"), conf.rcfg_mode_name);
			conf.rcfg_mode_name = "project";
			conf.rcfg_mode = rctype_project;
		}
	}

	if (refresh)
		return (update_zone_mcap(zonename, maxrss));

	if (modified) {
		if (pressure >= 0)
			conf.rcfg_memory_cap_enforcement_pressure = pressure;
		if (config_interval >= 0)
			conf.rcfg_reconfiguration_interval = config_interval;
		if (scan_interval >= 0)
			conf.rcfg_proc_walk_interval = scan_interval;
		if (report_interval >= 0)
			conf.rcfg_report_interval = report_interval;
		if (sample_interval >= 0)
			conf.rcfg_rss_sample_interval = sample_interval;

		/*
		 * Modify configuration with the new parameter(s). The
		 * function will exit if it fails.
		 */
		if ((modify_config(&conf)) != 0)
			die(gettext("Error updating repository \n"));

		if (smf_refresh_instance(RCAP_FMRI) != 0)
			die(gettext("cannot refresh service: %s\n"),
			    scf_strerror(scf_error()));
	}

	/*
	 * Display current configuration
	 */
	print_state();
	return (E_SUCCESS);
}
