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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/sysevent/eventdefs.h>
#include <sys/fm/util.h>
#include <fm/fmd_log.h>
#include <libsysevent.h>

#include <inj.h>
#include <inj_err.h>
#include <inj_string.h>

int verbose;
int quiet;

static int
usage(void)
{
	(void) fprintf(stderr, "Usage: %s [-nqv] [-c chan] [file]\n"
	    "\t-c  specify alternate channel to use for publication\n"
	    "\t-n  compile program but do not inject any events\n"
	    "\t-q  enable quiet mode (silence status messages)\n"
	    "\t-v  enable verbose output (display event details)\n",
	    getpname());

	return (E_USAGE);
}

/*
 * Sysevent-based event delivery
 */
static void *
sev_open(const char *chan)
{
	evchan_t *hdl;

	if (chan == NULL)
		chan = FM_ERROR_CHAN;

	if ((errno = sysevent_evc_bind(chan, &hdl,
	    EVCH_CREAT | EVCH_HOLD_PEND)) != 0)
		die("can't bind to error channel %s", chan);

	return (hdl);
}

static void
sev_send(void *arg, nvlist_t *msg)
{
	if ((errno = sysevent_evc_publish(arg, EC_FM, ESC_FM_ERROR,
	    "com.sun", getpname(), msg, EVCH_SLEEP)) != 0)
		warn("failed to send event");
}

static void
sev_close(void *arg)
{
	(void) sysevent_evc_unbind(arg);
}

static inj_mode_ops_t sysevent_ops = {
	sev_open,
	sev_send,
	sev_close
};

/*
 * Simulated delivery
 */
/*ARGSUSED*/
static void *
sim_open(const char *arg)
{
	return ((void *)1);
}

/*ARGSUSED*/
static void
sim_send(void *arg, nvlist_t *msg)
{
}

/*ARGSUSED*/
static void
sim_close(void *arg)
{
}

static inj_mode_ops_t simulate_ops = {
	sim_open,
	sim_send,
	sim_close
};

int
main(int argc, char *argv[])
{
	const inj_mode_ops_t *mode = NULL;
	void *mode_arg = NULL;
	int c;

	const char *file;
	inj_list_t *program;
	fmd_log_t *lp;

	while ((c = getopt(argc, argv, "c:nqv")) != EOF) {
		switch (c) {
		case 'c':
			if (mode != NULL || mode_arg != NULL)
				return (usage());

			mode = &sysevent_ops;
			mode_arg = optarg;
			break;

		case 'n':
			if (mode != NULL)
				return (usage());

			mode = &simulate_ops;
			break;

		case 'q':
			quiet = 1;
			break;

		case 'v':
			verbose = 1;
			break;

		default:
			return (usage());
		}
	}

	if (mode == NULL)
		mode = &sysevent_ops;

	argc -= optind;
	argv += optind;

	if (argc == 0)
		file = "-";
	else if (argc == 1)
		file = argv[0];
	else
		return (usage());

	srand48(gethrtime());

	if (argc > 0 && (lp = fmd_log_open(FMD_LOG_VERSION, file, &c)) != NULL)
		program = inj_logfile_read(lp);
	else
		program = inj_program_read(file);

	inj_program_run(program, mode, mode_arg);
	return (0);
}
