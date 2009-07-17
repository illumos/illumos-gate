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
 * Copyright (c) 2008-2009, Intel Corporation.
 * All Rights Reserved.
 */

#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <libgen.h>
#include <signal.h>
#include "latencytop.h"

#define	CMPOPT(a, b)	strncmp((a), (b), sizeof (b))

lt_config_t g_config;

/*
 * Prints help for command line parameters.
 */
static void
print_usage(const char *execname)
{
	char buffer[PATH_MAX];
	(void) snprintf(buffer, sizeof (buffer), "%s", execname);
	(void) fprintf(stderr, "\nUsage: %s [option(s)]\n", basename(buffer));
	(void) fprintf(stderr, "Options:\n"
	    "    -h, --help\n"
	    "        Print this help.\n"
	    "    -t, --interval TIME\n"
	    "        Set refresh interval to TIME. "
	    "Valid range [1...60] seconds, default = 5\n"
	/*
	 * Keep this option private, until we have chance to properly document
	 * the format of translation rules.
	 */
#if 0
	    "    -c, --config FILE\n"
	    "        Use translation rules defined in FILE.\n"
#endif
	    "    -o, --output-log-file FILE\n"
	    "        Output kernel log to FILE. Default = "
	    DEFAULT_KLOG_FILE "\n"
	    "    -k, --kernel-log-level LEVEL\n"
	    "        Set kernel log level to LEVEL.\n"
	    "        0(default) = None, 1 = Unmapped, 2 = Mapped, 3 = All.\n"
	    "    -f, --feature [no]feature1,[no]feature2,...\n"
	    "        Enable/disable features in LatencyTOP.\n"
	    "        [no]filter:\n"
	    "        Filter large interruptible latencies, e.g. sleep.\n"
	    "        [no]sched:\n"
	    "        Monitors sched (PID=0).\n"
	    "        [no]sobj:\n"
	    "        Monitors synchronization objects.\n"
	    "        [no]low:\n"
	    "        Lower overhead by sampling small latencies.\n"
	    "    -l, --log-period TIME\n"
	    "        Write and restart log every TIME seconds, TIME > 60s\n");
}

/*
 * Properly shut down when latencytop receives SIGINT or SIGTERM.
 */
/* ARGSUSED */
static void
signal_handler(int sig)
{
	lt_gpipe_break("q");
}

/*
 * Convert string to integer, return error if extra characters are found.
 */
static int
to_int(const char *str, int *result)
{
	char *tail = NULL;
	long ret;

	if (str == NULL || result == NULL) {
		return (-1);
	}

	ret = strtol(str, &tail, 10);

	if (tail != NULL && *tail != '\0') {
		return (-1);
	}

	*result = (int)ret;

	return (0);
}

/*
 * The main function.
 */
int
main(int argc, char *argv[])
{
	const char *opt_string = "t:o:k:hf:l:c:";
	struct option const longopts[] =
	{
		{"interval", required_argument, NULL, 't'},
		{"output-log-file", required_argument, NULL, 'o'},
		{"kernel-log-level", required_argument, NULL, 'k'},
		{"help", no_argument, NULL, 'h'},
		{"feature", required_argument, NULL, 'f'},
		{"log-period", required_argument, NULL, 'l'},
		{"config", required_argument, NULL, 'c'},
		{NULL, 0, NULL, 0}
	};

	int optc;
	int longind = 0;
	int running = 1;
	int unknown_option = FALSE;
	int refresh_interval = 5;
	int klog_level = 0;
	int log_interval = 0;
	long long last_logged = 0;
	char *token = NULL;
	int retval = 0;
	int gpipe;
	int err;
	uint64_t collect_end;
	uint64_t current_time;
	uint64_t delta_time;

	lt_gpipe_init();
	(void) signal(SIGINT, signal_handler);
	(void) signal(SIGTERM, signal_handler);

	(void) printf("%s\n%s\n", TITLE, COPYRIGHT);

	/* Default global settings */
	g_config.enable_filter = 0;
	g_config.trace_sched = 0;
	g_config.trace_syncobj = 1;
	g_config.low_overhead_mode = 0;
	g_config.snap_interval = 1000;	/* DTrace snapshot every 1 sec */
#ifdef EMBED_CONFIGS
	g_config.config_name = NULL;
#else
	g_config.config_name = lt_strdup(DEFAULT_CONFIG_NAME);
#endif

	/* Parse command line arguments. */
	while ((optc = getopt_long(argc, argv, opt_string,
	    longopts, &longind)) != -1) {
		switch (optc) {
		case 'h':
			print_usage(argv[0]);
			goto end_none;
		case 't':
			if (to_int(optarg, &refresh_interval) != 0 ||
			    refresh_interval < 1 || refresh_interval > 60) {
				lt_display_error(
				    "Invalid refresh interval: %s\n", optarg);
				unknown_option = TRUE;
			}
			break;
		case 'k':
			if (to_int(optarg, &klog_level) != 0 ||
			    lt_klog_set_log_level(klog_level) != 0) {
				lt_display_error(
				    "Invalid log level: %s\n", optarg);
				unknown_option = TRUE;
			}
			break;
		case 'o':
			err = lt_klog_set_log_file(optarg);
			if (err == 0) {
				(void) printf("Writing to log file %s.\n",
				    optarg);
			} else if (err == -1) {
				lt_display_error(
				    "Log file name is too long: %s\n",
				    optarg);
				unknown_option = TRUE;
			} else if (err == -2) {
				lt_display_error(
				    "Cannot write to log file: %s\n",
				    optarg);
				unknown_option = TRUE;
			}
			break;
		case 'f':
			for (token = strtok(optarg, ","); token != NULL;
			    token = strtok(NULL, ",")) {
				int v = TRUE;
				if (strncmp(token, "no", 2) == 0) {
					v = FALSE;
					token = &token[2];
				}
				if (CMPOPT(token, "filter") == 0) {
					g_config.enable_filter = v;
				} else if (CMPOPT(token, "sched") == 0) {
					g_config.trace_sched = v;
				} else if (CMPOPT(token, "sobj") == 0) {
					g_config.trace_syncobj = v;
				} else if (CMPOPT(token, "low") == 0) {
					g_config.low_overhead_mode = v;
				} else {
					lt_display_error(
					    "Unknown feature: %s\n", token);
					unknown_option = TRUE;
				}
			}
			break;
		case 'l':
			if (to_int(optarg, &log_interval) != 0 ||
			    log_interval < 60) {
				lt_display_error(
				    "Invalid refresh interval: %s\n", optarg);
				unknown_option = TRUE;
			}
			break;
		case 'c':
			if (strlen(optarg) > PATH_MAX) {
				lt_display_error(
				    "Configuration name is too long.\n");
				unknown_option = TRUE;
			} else {
				g_config.config_name = lt_strdup(optarg);
			}
			break;
		default:
			unknown_option = TRUE;
			break;
		}
	}

	/* Throw error for commands like: "latencytop 12345678" */
	if (optind  < argc) {
		int tmpind = optind;
		(void) printf("Unknown option(s): ");
		while (tmpind < argc) {
			(void) printf("%s ", argv[tmpind++]);
		}
		(void) printf("\n");
		unknown_option = TRUE;
	}

	if (unknown_option) {
		print_usage(argv[0]);
		retval = 1;
		goto end_none;
	}

	/* Initialization */
	lt_klog_init();
	if (lt_table_init() != 0) {
		lt_display_error("Unable to load configuration table.\n");
		retval = 1;
		goto end_notable;
	}
	if (lt_dtrace_init() != 0) {
		lt_display_error("Unable to initialize dtrace.\n");
		retval = 1;
		goto end_nodtrace;
	}

	last_logged = lt_millisecond();

	(void) printf("Collecting data for %d seconds...\n",
	    refresh_interval);

	gpipe = lt_gpipe_readfd();
	collect_end = last_logged + refresh_interval * 1000;
	for (;;) {
		fd_set read_fd;
		struct timeval timeout;
		int tsleep = collect_end - lt_millisecond();

		if (tsleep <= 0) {
			break;
		}

		if (tsleep > g_config.snap_interval * 1000) {
			tsleep = g_config.snap_interval * 1000;
		}

		timeout.tv_sec = tsleep / 1000;
		timeout.tv_usec = (tsleep % 1000) * 1000;

		FD_ZERO(&read_fd);
		FD_SET(gpipe, &read_fd);
		if (select(gpipe + 1, &read_fd, NULL, NULL, &timeout) > 0) {
			goto end_ubreak;
		}

		(void) lt_dtrace_work(0);
	}

	lt_display_init();

	do {
		current_time = lt_millisecond();

		lt_stat_clear_all();
		(void) lt_dtrace_collect();

		delta_time = current_time;
		current_time = lt_millisecond();
		delta_time = current_time - delta_time;

		if (log_interval > 0 &&
		    current_time - last_logged > log_interval * 1000) {
			lt_klog_write();
			last_logged = current_time;
		}

		running = lt_display_loop(refresh_interval * 1000 -
		    delta_time);
	} while (running != 0);

	lt_klog_write();

	/* Cleanup */
	lt_display_deinit();

end_ubreak:
	lt_dtrace_deinit();
	lt_stat_free_all();

end_nodtrace:
	lt_table_deinit();

end_notable:
	lt_klog_deinit();

end_none:
	lt_gpipe_deinit();
	if (g_config.config_name != NULL) {
		free(g_config.config_name);
	}

	return (retval);
}
