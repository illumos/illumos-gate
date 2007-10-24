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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/uadmin.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>
#include <libscf.h>
#include <strings.h>

#define	SMF_RST	"/etc/svc/volatile/resetting"
#define	AUDITD_FMRI	"svc:/system/auditd:default"

static const char *Usage = "Usage: %s cmd fcn [mdep]\n";

static int turnoff_auditd();
static void wait_for_auqueue();

int
main(int argc, char *argv[])
{
	int cmd, fcn;
	uintptr_t mdep = NULL;
	sigset_t set;
	adt_session_data_t *ah;  /* audit session handle */
	adt_event_data_t *event = NULL; /* event to be generated */
	au_event_t event_id;
	enum adt_uadmin_fcn fcn_id;

	if (argc < 3 || argc > 4) {
		(void) fprintf(stderr, Usage, argv[0]);
		return (1);
	}

	(void) sigfillset(&set);
	(void) sigprocmask(SIG_BLOCK, &set, NULL);

	cmd = atoi(argv[1]);
	fcn = atoi(argv[2]);
	if (argc == 4) {	/* mdep argument given */
		if (cmd != A_REBOOT && cmd != A_SHUTDOWN && cmd != A_DUMP &&
		    cmd != A_FREEZE) {
			(void) fprintf(stderr, "%s: mdep argument not "
			    "allowed for this cmd value\n", argv[0]);
			(void) fprintf(stderr, Usage, argv[0]);
			return (1);
		} else {
			mdep = (uintptr_t)argv[3];
		}
	}

	/* set up audit session and event */
	if (adt_start_session(&ah, NULL, ADT_USE_PROC_DATA) != 0) {
		(void) fprintf(stderr, "%s: can't start audit session\n",
		    argv[0]);
	}
	switch (cmd) {
	case A_SHUTDOWN:
		event_id = ADT_uadmin_shutdown;
		break;
	case A_REBOOT:
		event_id = ADT_uadmin_reboot;
		break;
	case A_DUMP:
		event_id = ADT_uadmin_dump;
		break;
	case A_REMOUNT:
		event_id = ADT_uadmin_remount;
		break;
	case A_FREEZE:
		event_id = ADT_uadmin_freeze;
		break;
	case A_FTRACE:
		event_id = ADT_uadmin_ftrace;
		break;
	case A_SWAPCTL:
		event_id = ADT_uadmin_swapctl;
		break;
	default:
		event_id = 0;
	}
	if ((event_id != 0) &&
	    (event = adt_alloc_event(ah, event_id)) == NULL) {
		(void) fprintf(stderr, "%s: can't allocate audit event\n",
		    argv[0]);
	}
	switch (fcn) {
	case AD_HALT:
		fcn_id = ADT_UADMIN_FCN_AD_HALT;
		break;
	case AD_POWEROFF:
		fcn_id = ADT_UADMIN_FCN_AD_POWEROFF;
		break;
	case AD_BOOT:
		fcn_id = ADT_UADMIN_FCN_AD_BOOT;
		break;
	case AD_IBOOT:
		fcn_id = ADT_UADMIN_FCN_AD_IBOOT;
		break;
	case AD_SBOOT:
		fcn_id = ADT_UADMIN_FCN_AD_SBOOT;
		break;
	case AD_SIBOOT:
		fcn_id = ADT_UADMIN_FCN_AD_SIBOOT;
		break;
	case AD_NOSYNC:
		fcn_id = ADT_UADMIN_FCN_AD_NOSYNC;
		break;
	default:
		fcn_id = 0;
	}
	if (cmd == A_FREEZE) {
		switch (fcn) {
		case AD_SUSPEND_TO_DISK:
			fcn_id = ADT_UADMIN_FCN_AD_SUSPEND_TO_DISK;
			break;
		case AD_CHECK_SUSPEND_TO_DISK:
			fcn_id = ADT_UADMIN_FCN_AD_CHECK_SUSPEND_TO_DISK;
			break;
		case AD_FORCE:
			fcn_id = ADT_UADMIN_FCN_AD_FORCE;
			break;
		case AD_SUSPEND_TO_RAM:
			fcn_id = ADT_UADMIN_FCN_AD_SUSPEND_TO_RAM;
			break;
		case AD_CHECK_SUSPEND_TO_RAM:
			fcn_id = ADT_UADMIN_FCN_AD_CHECK_SUSPEND_TO_RAM;
			break;
		case AD_REUSEINIT:
			fcn_id = ADT_UADMIN_FCN_AD_REUSEINIT;
			break;
		case AD_REUSABLE:
			fcn_id = ADT_UADMIN_FCN_AD_REUSABLE;
			break;
		case AD_REUSEFINI:
			fcn_id = ADT_UADMIN_FCN_AD_REUSEFINI;
			break;
		}
	} else if (cmd == A_FTRACE) {
		switch (fcn) {
		case AD_FTRACE_START:
			fcn_id = ADT_UADMIN_FCN_AD_FTRACE_START;
			break;
		case AD_FTRACE_STOP:
			fcn_id = ADT_UADMIN_FCN_AD_FTRACE_STOP;
			break;
		}
	}

	if (geteuid() == 0) {
		if (event != NULL) {
			switch (cmd) {
			case A_SHUTDOWN:
				event->adt_uadmin_shutdown.fcn = fcn_id;
				event->adt_uadmin_shutdown.mdep = (char *)mdep;
				break;
			case A_REBOOT:
				event->adt_uadmin_reboot.fcn = fcn_id;
				event->adt_uadmin_reboot.mdep = (char *)mdep;
				break;
			case A_DUMP:
				event->adt_uadmin_dump.fcn = fcn_id;
				event->adt_uadmin_dump.mdep = (char *)mdep;
				break;
			case A_REMOUNT:
				/* no parameters */
				break;
			case A_FREEZE:
				event->adt_uadmin_freeze.fcn = fcn_id;
				event->adt_uadmin_freeze.mdep = (char *)mdep;
				break;
			case A_FTRACE:
				event->adt_uadmin_ftrace.fcn = fcn_id;
				break;
			case A_SWAPCTL:
				event->adt_uadmin_swapctl.fcn = fcn_id;
				break;
			}

			if (adt_put_event(event, ADT_SUCCESS, 0) != 0) {
				(void) fprintf(stderr,
				    "%s: can't put audit event\n", argv[0]);
			}
			/*
			 * allow audit record to be processed in the kernel
			 * audit queue
			 */
			wait_for_auqueue();
		}

		if (turnoff_auditd() == -1)
			(void) fprintf(stderr, "%s: can't turn off auditd\n",
			    argv[0]);

		if (cmd == A_SHUTDOWN || cmd == A_REBOOT)
			(void) creat(SMF_RST, 0777);
	}

	(void) adt_free_event(event);
	(void) adt_end_session(ah);

	if (uadmin(cmd, fcn, mdep) < 0) {
		perror("uadmin");

		(void) unlink(SMF_RST);

		return (1);
	}

	return (0);
}

static int
turnoff_auditd()
{
	char	*smf_state;
	int	rc = -1;
	int	retries = 15;

	if (smf_disable_instance(AUDITD_FMRI, SMF_TEMPORARY) != 0) {
		(void) fprintf(stderr, "error disabling auditd: %s\n",
		    scf_strerror(scf_error()));
		return (-1);
	}

	/* wait for auditd to finish its work */
	do {
		if ((smf_state = smf_get_state(AUDITD_FMRI)) == NULL) {
			(void) fprintf(stderr,
			    "getting state of auditd failed: %s\n",
			    scf_strerror(scf_error()));
			return (-1);
		}

		if (strcmp(smf_state, SCF_STATE_STRING_DISABLED)) {
			retries--;
			(void) sleep(1);
		} else {
			rc = 0;
		}
		free(smf_state);
	} while (rc && retries);

	return (rc);
}

static void
wait_for_auqueue()
{
	au_stat_t	au_stat;
	int		retries = 10;

	while (retries-- && auditon(A_GETSTAT, (caddr_t)&au_stat, NULL) == 0) {
		if (au_stat.as_enqueue == au_stat.as_written) {
			break;
		}
		(void) sleep(1);
	}
}
