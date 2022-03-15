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

#include <errno.h>
#include <locale.h>
#include <pwd.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <nss_dbdefs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <tsol/label.h>
#include <zone.h>
#include <bsm/devalloc.h>
#include "allocate.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SUNW_OST_OSCMD"
#endif

#define	ALLOC	"allocate"
#define	DEALLOC	"deallocate"
#define	LIST	"list_devices"

extern void audit_allocate_argv(int, int, char *[]);
extern int audit_allocate_record(int);

int system_labeled = 0;
static int windowing = 0;
static int wdwmsg(char *name, char *msg);

static void
usage(int func)
{
	if (system_labeled) {
		char *use[6];

		use[0] = gettext("allocate [-s] [-w] [-U uname] [-z zonename] "
		    "[-F] device|-g dev-type");
		use[1] = gettext("deallocate [-s] [-w] [-z zonename] "
		    "[-F] device|-c dev-class|-g dev-type");
		use[2] = gettext("deallocate [-s] [-w] [-z zonename] -I");
		use[3] = gettext("list_devices [-s] [-U uid] [-z zonename] "
		    "[-a [-w]] -l|-n|-u [device]");
		use[4] = gettext("list_devices [-s] [-U uid] [-z zonename] "
		    "[-a [-w]] [-l|-n|-u] -c dev-class");
		use[5] = gettext("list_devices [-s] -d [dev-type]");

		switch (func) {
			case 0:
				(void) fprintf(stderr, "%s\n", use[0]);
				break;
			case 1:
				(void) fprintf(stderr, "%s\n%s\n",
				    use[1], use[2]);
				break;
			case 2:
				(void) fprintf(stderr, "%s\n%s\n%s\n",
				    use[3], use[4], use[5]);
				break;
			default:
				(void) fprintf(stderr,
				    "%s\n%s\n%s\n%s\n%s\n%s\n",
				    use[0], use[1], use[2], use[3], use[4],
				    use[5]);
		}
	} else {
		char *use[5];

		use[0] = gettext("allocate "
		    "[-s] [-U uname] [-F] device|-g dev-type");
		use[1] = gettext("deallocate [-s] [-F] device|-c dev-class");
		use[2] = gettext("deallocate [-s] -I");
		use[3] = gettext("list_devices "
		    "[-s] [-U uid] -l|-n|-u [device]");
		use[4] = gettext("list_devices "
		    "[-s] [-U uid] [-l|-n|-u] -c dev-class");

		switch (func) {
			case 0:
				(void) fprintf(stderr, "%s\n", use[0]);
				break;
			case 1:
				(void) fprintf(stderr, "%s\n%s\n",
				    use[1], use[2]);
				break;
			case 2:
				(void) fprintf(stderr, "%s\n%s\n",
				    use[3], use[4]);
				break;
			default:
				(void) fprintf(stderr, "%s\n%s\n%s\n%s\n%s\n",
				    use[0], use[1], use[2], use[3], use[4]);
		}
	}
	exit(1);
}

void
print_error(int error, char *name)
{
	char	*msg;
	char	msgbuf[200];

	switch (error) {
	case ALLOCUERR:
		msg = gettext("Specified device is allocated to another user.");
		break;
	case CHOWNERR:
		msg = gettext("Failed to chown.");
		break;
	case CLEANERR:
		msg = gettext("Unable to clean up device.");
		break;
	case CNTDEXECERR:
		msg = gettext(
		    "Can't exec device-clean program for specified device.");
		break;
	case CNTFRCERR:
		msg = gettext("Can't force deallocate specified device.");
		break;
	case DACACCERR:
		msg = gettext(
		    "Can't access DAC file for the device specified.");
		break;
	case DAOFFERR:
		msg = gettext(
		    "Device allocation feature is not activated "
		    "on this system.");
		break;
	case DAUTHERR:
		msg = gettext("Device not allocatable.");
		break;
	case DEFATTRSERR:
		msg = gettext("No default attributes for specified "
		    "device type.");
		break;
	case DEVLKERR:
		msg = gettext("Concurrent operations for specified device, "
		    "try later.");
		break;
	case DEVLONGERR:
		msg = gettext("Device name is too long.");
		break;
	case DEVNALLOCERR:
		msg = gettext("Device not allocated.");
		break;
	case DEVNAMEERR:
		msg = gettext("Device name error.");
		break;
	case DEVSTATEERR:
		msg = gettext("Device specified is in allocate error state.");
		break;
	case DEVZONEERR:
		msg = gettext("Can't find name of the zone to which "
		    "device is allocated.");
		break;
	case DSPMISSERR:
		msg = gettext(
		    "Device special file(s) missing for specified device.");
		break;
	case LABELRNGERR:
		msg = gettext(
		    "Operation inconsistent with device's label range.");
		break;
	case LOGINDEVPERMERR:
		msg = gettext("Device controlled by logindevperm(5)");
		break;
	case NODAERR:
		msg = gettext("No entry for specified device.");
		break;
	case NODMAPERR:
		msg = gettext("No entry for specified device.");
		break;
	case PREALLOCERR:
		msg = gettext("Device already allocated.");
		break;
	case SETACLERR:
		msg = gettext("Failed to set ACL.");
		break;
	case UAUTHERR:
		msg = gettext(
		    "User lacks authorization required for this operation.");
		break;
	case ZONEERR:
		msg = gettext("Failed to configure device in zone.");
		break;
	default:
		msg = gettext("Unknown error code.");
		break;
	}

	if (windowing) {
		(void) snprintf(msgbuf, sizeof (msgbuf), "%s: %s\n", name, msg);
		(void) wdwmsg(name, msgbuf);
	} else {
		(void) fprintf(stderr, "%s: %s\n", name, msg);
		(void) fflush(stderr);
	}
}

char *newenv[] = {"PATH=/usr/bin:/usr/sbin",
			NULL,			/* for LC_ALL		*/
			NULL,			/* for LC_COLLATE	*/
			NULL,			/* for LC_CTYPE		*/
			NULL,			/* for LC_MESSAGES	*/
			NULL,			/* for LC_NUMERIC	*/
			NULL,			/* for LC_TIME		*/
			NULL,			/* for LANG		*/
			NULL
};

static char *
getenvent(char *name, char *env[])
{
	for (; *env != NULL; env++) {
		if (strncmp(*env, name, strlen(name)) == 0)
			return (*env);
	}
	return (NULL);
}

int
main(int argc, char *argv[], char *envp[])
{
	char		*name, *env;
	int		func = -1, optflg = 0, error = 0, c;
	zoneid_t	zoneid;
	uid_t		uid;
	char		*uname = NULL, *device = NULL, *zonename = NULL;
	char		*zname;
	char		pw_buf[NSS_BUFLEN_PASSWD];
	struct passwd	pw_ent;
	int 		env_num = 1;	/* PATH= is 0 entry */
#ifdef DEBUG
	struct stat	statbuf;
#endif

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	system_labeled = is_system_labeled();

	/* test hook: see also mkdevalloc.c and devfsadm.c */
	if (!system_labeled) {
		system_labeled = is_system_labeled_debug(&statbuf);
		if (system_labeled) {
			fprintf(stderr, "/ALLOCATE_FORCE_LABEL is set,\n"
			    "forcing system label on for testing...\n");
		}
	}

	/*
	 * get all enviroment variables
	 * which affect on internationalization.
	 */
	env = getenvent("LC_ALL=", envp);
	if (env != NULL)
		newenv[env_num++] = env;
	env = getenvent("LC_COLLATE=", envp);
	if (env != NULL)
		newenv[env_num++] = env;
	env = getenvent("LC_CTYPE=", envp);
	if (env != NULL)
		newenv[env_num++] = env;
	env = getenvent("LC_MESSAGES=", envp);
	if (env != NULL)
		newenv[env_num++] = env;
	env = getenvent("LC_NUMERIC=", envp);
	if (env != NULL)
		newenv[env_num++] = env;
	env = getenvent("LC_TIME=", envp);
	if (env != NULL)
		newenv[env_num++] = env;
	env = getenvent("LANG=", envp);
	if (env != NULL)
		newenv[env_num] = env;

	if ((name = strrchr(argv[0], '/')) == NULL)
		name = argv[0];
	else
		name++;

	if (strcmp(name, ALLOC) == 0)
		func = 0;
	else if (strcmp(name, DEALLOC) == 0)
		func = 1;
	else if (strcmp(name, LIST) == 0)
		func = 2;
	else
		usage(-1);

	audit_allocate_argv(func, argc, argv);

	if (system_labeled) {
		/*
		 * allocate, deallocate, list_devices run in
		 * global zone only.
		 */
		zoneid = getzoneid();
		if (zoneid != GLOBAL_ZONEID)
			exit(GLOBALERR);
		zname = GLOBAL_ZONENAME;
		/*
		 * check if device allocation is activated.
		 */
		if (da_is_on() == 0) {
			(void) fprintf(stderr, "%s%s",
			    gettext("Turn device allocation on"),
			    gettext(" to use this feature.\n"));
			exit(DAOFFERR);
		}
	}

	if (func == 0) {	/* allocate */
		while ((c = getopt(argc, argv, "g:swz:FU:")) != -1) {
			switch (c) {
			case 'g':
				optflg |= TYPE;
				device = optarg;
				break;
			case 's':
				optflg |= SILENT;
				break;
			case 'w':
				if (system_labeled) {
					optflg |= WINDOWING;
					windowing = 1;
				} else {
					usage(func);
				}
				break;
			case 'z':
				if (system_labeled) {
					optflg |= ZONENAME;
					zonename = optarg;
				} else {
					usage(func);
				}
				break;
			case 'F':
				optflg |= FORCE;
				break;
			case 'U':
				optflg |= USERNAME;
				uname = optarg;
				break;
			case '?':
			default :
				usage(func);
			}
		}

		/*
		 * allocate(1) must be supplied with one device argument
		 */
		if (device && ((argc - optind) >= 1))
			usage(func);
		if (device == NULL) {
			if ((argc - optind) != 1)
				usage(func);
			device = argv[optind];
		}
	}

	else if (func == 1) {	/* deallocate */
		while ((c = getopt(argc, argv, "c:g:swz:FI")) != -1) {
			switch (c) {
			case 'c':
				if (optflg & (TYPE | FORCE_ALL))
					usage(func);
				optflg |= CLASS;
				device = optarg;
				break;
			case 'g':
				if (system_labeled) {
					if (optflg & (CLASS | FORCE_ALL))
						usage(func);
					optflg |= TYPE;
					device = optarg;
				} else {
					usage(func);
				}
				break;
			case 's':
				optflg |= SILENT;
				break;
			case 'w':
				if (system_labeled) {
					optflg |= WINDOWING;
					windowing = 1;
				} else {
					usage(func);
				}
				break;
			case 'z':
				if (system_labeled) {
					optflg |= ZONENAME;
					zonename = optarg;
				} else {
					usage(func);
				}
				break;
			case 'F':
				if (optflg & FORCE_ALL)
					usage(func);
				optflg |= FORCE;
				break;
			case 'I':
				if (optflg & (CLASS | TYPE | FORCE))
					usage(func);
				optflg |= FORCE_ALL;
				break;
			case '?':
			default :
				usage(func);
			}
		}

		/*
		 * deallocate(1) must be supplied with one device
		 * argument unless the '-I' argument is supplied
		 */
		if (device || (optflg & FORCE_ALL)) {
			if ((argc - optind) >= 1)
				usage(func);
		} else if (device == NULL) {
			if ((argc - optind) != 1)
				usage(func);
			device = argv[optind];
		}
	}

	else if (func == 2) {	/* list_devices */
		while ((c = getopt(argc, argv, "ac:dlnsuwz:U:")) != -1) {
			switch (c) {
			case 'a':
				if (system_labeled) {
					/*
					 * list auths, cleaning programs,
					 * labels.
					 */
					if (optflg & LISTDEFS)
						usage(func);
					optflg |= LISTATTRS;
				} else {
					usage(func);
				}
				break;
			case 'c':
				optflg |= CLASS;
				device = optarg;
				break;
			case 'd':
				if (system_labeled) {
					/*
					 * List devalloc_defaults
					 * This cannot used with anything other
					 * than -s.
					 */
					if (optflg & (LISTATTRS | CLASS |
					    LISTALL | LISTFREE | LISTALLOC |
					    WINDOWING | ZONENAME | USERID))
						usage(func);
					optflg |= LISTDEFS;
				} else {
					usage(func);
				}
				break;
			case 'l':
				if (optflg & (LISTFREE | LISTALLOC | LISTDEFS))
					usage(func);
				optflg |= LISTALL;
				break;
			case 'n':
				if (optflg & (LISTALL | LISTALLOC | LISTDEFS))
					usage(func);
				optflg |= LISTFREE;
				break;
			case 's':
				optflg |= SILENT;
				break;
			case 'u':
				if (optflg & (LISTALL | LISTFREE | LISTDEFS))
					usage(func);
				optflg |= LISTALLOC;
				break;
			case 'w':
				if (system_labeled) {
					if (optflg & LISTDEFS)
						usage(func);
					optflg |= WINDOWING;
				} else {
					usage(func);
				}
				break;
			case 'z':
				if (system_labeled) {
					if (optflg & LISTDEFS)
						usage(func);
					optflg |= ZONENAME;
					zonename = optarg;
				} else {
					usage(func);
				}
				break;
			case 'U':
				if (optflg & LISTDEFS)
					usage(func);
				optflg |= USERID;
				uid = atoi(optarg);
				break;
			case '?':
			default :
				usage(func);
			}
		}

		if (system_labeled) {
			if (!(optflg & (LISTALL | LISTFREE | LISTALLOC |
			    LISTDEFS | WINDOWING))) {
				if (!(optflg & CLASS))
					usage(func);
			}
		} else if (!(optflg & (LISTALL | LISTFREE | LISTALLOC))) {
			if (!(optflg & CLASS))
				usage(func);
		}

		/*
		 * list_devices(1) takes an optional device argument.
		 */
		if (device && ((argc - optind) >= 1))
			usage(func);
		if (device == NULL) {
			if ((argc - optind) == 1)
				device = argv[optind];
			else if ((argc - optind) > 1)
				usage(func);
		}
	}

	if (optflg & USERNAME) {
		if (getpwnam_r(uname, &pw_ent, pw_buf, sizeof (pw_buf)) ==
		    NULL) {
			(void) fprintf(stderr,
			    gettext("Invalid user name -- %s -- \n"), uname);
			exit(1);
		}
		uid = pw_ent.pw_uid;
	} else if (optflg & USERID) {
		if (getpwuid_r(uid, &pw_ent, pw_buf, sizeof (pw_buf)) == NULL) {
			(void) fprintf(stderr,
			    gettext("Invalid user ID -- %d -- \n"), uid);
			exit(1);
		}
		uid = pw_ent.pw_uid;
	} else {
		/*
		 * caller's uid is the default if no user specified.
		 */
		uid = getuid();
	}

	/*
	 * global zone is the default if no zonename specified.
	 */
	if (zonename == NULL) {
		zonename = zname;
	} else {
		if (zone_get_id(zonename, &zoneid) != 0) {
			(void) fprintf(stderr,
			    gettext("Invalid zone name -- %s -- \n"), zonename);
			exit(1);
		}
	}

	if (func == 0)
		error = allocate(optflg, uid, device, zonename);
	else if (func == 1)
		error = deallocate(optflg, uid, device, zonename);
	else if (func == 2)
		error = list_devices(optflg, uid, device, zonename);

	(void) audit_allocate_record(error);

	if (error) {
		if (!(optflg & SILENT))
			print_error(error, name);
		exit(error);
	}

	return (0);
}

/*
 * Display error message via /etc/security/lib/wdwmsg script
 */
static int
wdwmsg(char *name, char *msg)
{
	pid_t child_pid;
	pid_t wait_pid;
	int child_status;

	/* Fork a child */
	switch (child_pid = fork()) {
	case -1:	/* FAILURE */
		return (-1);
		break;

	case 0:		/* CHILD */
		(void) execl("/etc/security/lib/wdwmsg", "wdwmsg", msg,
		    name, "OK", NULL);
		/* If exec failed, send message to stderr */
		(void) fprintf(stderr, "%s", msg);
		return (-1);

	default:	/* PARENT */
		/* Wait for child to exit */
		wait_pid = waitpid(child_pid, &child_status, 0);
		if ((wait_pid < 0) && (errno == ECHILD))
			return (0);
		if ((wait_pid < 0) || (wait_pid != child_pid))
			return (-1);
		if (WIFEXITED(child_status))
			return (WEXITSTATUS(child_status));
		if (WIFSIGNALED(child_status))
			return (WTERMSIG(child_status));
		return (0);
	}
}
