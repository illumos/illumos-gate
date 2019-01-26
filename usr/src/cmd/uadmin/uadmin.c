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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/



#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#ifdef	__i386
#include <libscf_priv.h>
#endif /* __i386 */

#include <bsm/adt.h>
#include <bsm/adt_event.h>

#include <sys/types.h>
#include <sys/uadmin.h>
#include <sys/wait.h>

#define	SMF_RST	"/etc/svc/volatile/resetting"
#define	RETRY_COUNT 15	/* number of 1 sec retries for audit(1M) to complete */

static const char *Usage = "Usage: %s cmd fcn [mdep]\n";

static int closeout_audit(int, int);
static int turnoff_auditd(void);
static void wait_for_auqueue();
static int change_audit_file(void);

int
main(int argc, char *argv[])
{
	int cmd, fcn;
	uintptr_t mdep = (uintptr_t)NULL;
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
	case A_CONFIG:
		event_id = ADT_uadmin_config;
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
	case AD_FASTREBOOT:
#ifdef __i386
		fcn_id = ADT_UADMIN_FCN_AD_FASTREBOOT;
		mdep = (uintptr_t)NULL;	/* Ignore all arguments */
#else /* __i386 */
		fcn = AD_BOOT;
		fcn_id = ADT_UADMIN_FCN_AD_BOOT;
#endif /* __i386 */
		break;
	case AD_FASTREBOOT_DRYRUN:
		fcn_id = ADT_UADMIN_FCN_AD_FASTREBOOT_DRYRUN;
		mdep = (uintptr_t)NULL;	/* Ignore all arguments */
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
#ifdef	__i386
	} else if (cmd == A_CONFIG) {
		uint8_t boot_config = 0;
		uint8_t boot_config_ovr = 0;

		switch (fcn) {
		case AD_UPDATE_BOOT_CONFIG:
			fcn_id = ADT_UADMIN_FCN_AD_UPDATE_BOOT_CONFIG;
			scf_get_boot_config(&boot_config);
			boot_config_ovr = boot_config;
			scf_get_boot_config_ovr(&boot_config_ovr);
			boot_config &= boot_config_ovr;
			mdep = (uintptr_t)(&boot_config);
			break;
		}
#endif /* __i386 */
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
				event->adt_uadmin_ftrace.mdep = (char *)mdep;
				break;
			case A_CONFIG:
				event->adt_uadmin_config.fcn = fcn_id;
				event->adt_uadmin_config.mdep = (char *)mdep;
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

		if (closeout_audit(cmd, fcn) == -1)
			(void) fprintf(stderr, "%s: can't turn off auditd\n",
			    argv[0]);

		if (cmd == A_SHUTDOWN || cmd == A_REBOOT)
			(void) creat(SMF_RST, 0777);
	}

	(void) adt_free_event(event);
	if (uadmin(cmd, fcn, mdep) < 0) {
		perror("uadmin");

		(void) unlink(SMF_RST);

		return (1);
	}

	/* If returning from a suspend, audit thaw */
	if ((cmd == A_FREEZE) &&
	    ((fcn == AD_FORCE) ||
	    (fcn == AD_REUSABLE) ||
	    (fcn == AD_SUSPEND_TO_DISK) ||
	    (fcn == AD_SUSPEND_TO_RAM))) {
		if ((event = adt_alloc_event(ah, ADT_uadmin_thaw)) == NULL) {
			(void) fprintf(stderr, "%s: can't allocate thaw audit "
			    "event\n", argv[0]);
		}
		event->adt_uadmin_thaw.fcn = fcn_id;
		if (adt_put_event(event, ADT_SUCCESS, 0) != 0) {
			(void) fprintf(stderr, "%s: can't put thaw audit "
			    "event\n", argv[0]);
		}
		(void) adt_free_event(event);
	}
	(void) adt_end_session(ah);

	return (0);
}

static int
closeout_audit(int cmd, int fcn)
{
	if (!adt_audit_state(AUC_AUDITING)) {
		/* auditd not running, just return */
		return (0);
	}
	switch (cmd) {
	case A_SHUTDOWN:
		switch (fcn) {
		case AD_FASTREBOOT_DRYRUN:
			/* No system discontinuity, don't turn off auditd */
			return (0);
		default:
			break;	/* For all the other shutdown functions */
		}
		/* FALLTHROUGH */
	case A_REBOOT:
	case A_DUMP:
		/* system shutting down, turn off auditd */
		return (turnoff_auditd());
	case A_REMOUNT:
	case A_SWAPCTL:
	case A_FTRACE:
	case A_CONFIG:
		/* No system discontinuity, don't turn off auditd */
		return (0);
	case A_FREEZE:
		switch (fcn) {
		case AD_CHECK_SUSPEND_TO_DISK:	/* AD_CHECK */
		case AD_CHECK_SUSPEND_TO_RAM:
		case AD_REUSEINIT:
		case AD_REUSEFINI:
			/* No system discontinuity, don't turn off auditd */
			return (0);
		case AD_REUSABLE:
		case AD_SUSPEND_TO_DISK:	/* AD_COMPRESS */
		case AD_SUSPEND_TO_RAM:
		case AD_FORCE:
			/* suspend the system, change audit files */
			return (change_audit_file());
		default:
			return (0);	/* not an audit error */
		}
	default:
		return (0);	/* not an audit error */
	}
}

static int
turnoff_auditd(void)
{
	int	rc;
	int	retries = RETRY_COUNT;

	if ((rc = (int)fork()) == 0) {
		(void) execl("/usr/sbin/audit", "audit", "-T", NULL);
		(void) fprintf(stderr, "error disabling auditd: %s\n",
		    strerror(errno));
		_exit(-1);
	} else if (rc == -1) {
		(void) fprintf(stderr, "error disabling auditd: %s\n",
		    strerror(errno));
		return (-1);
	}

	/*
	 * wait for auditd to finish its work.  auditd will change the
	 * auditstart from AUC_AUDITING (auditd up and running) to
	 * AUC_NOAUDIT.  Other states are errors, so we're done as well.
	 */
	do {
		int	auditstate;

		rc = -1;
		if ((auditon(A_GETCOND, (caddr_t)&auditstate,
		    sizeof (auditstate)) == 0) &&
		    (auditstate == AUC_AUDITING)) {
			retries--;
			(void) sleep(1);
		} else {
			rc = 0;
		}
	} while ((rc != 0) && (retries != 0));

	return (rc);
}

static int
change_audit_file(void)
{
	pid_t	pid;

	if ((pid = fork()) == 0) {
		(void) execl("/usr/sbin/audit", "audit", "-n", NULL);
		(void) fprintf(stderr, "error changing audit files: %s\n",
		    strerror(errno));
		_exit(-1);
	} else if (pid == -1) {
		(void) fprintf(stderr, "error changing audit files: %s\n",
		    strerror(errno));
		return (-1);
	} else {
		pid_t	rc;
		int	retries = RETRY_COUNT;

		/*
		 * Wait for audit(1M) -n process to complete
		 *
		 */
		do {
			if ((rc = waitpid(pid, NULL, WNOHANG)) == pid) {
				return (0);
			} else if (rc == -1) {
				return (-1);
			} else {
				(void) sleep(1);
				retries--;
			}

		} while (retries != 0);
	}
	return (-1);
}

static void
wait_for_auqueue()
{
	au_stat_t	au_stat;
	int		retries = 10;

	while (retries-- && auditon(A_GETSTAT, (caddr_t)&au_stat, 0) == 0) {
		if (au_stat.as_enqueue == au_stat.as_written) {
			break;
		}
		(void) sleep(1);
	}
}
