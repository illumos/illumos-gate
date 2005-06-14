/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1992-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <locale.h>
#include <pwd.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>

#include "allocate.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SUNW_OST_OSCMD"
#endif

extern void audit_allocate_argv(int, int, char *[]);
extern int audit_allocate_record(int);

static void
usage(int func)
{
	char *use[5];

	use[0] = gettext("allocate [-s] [-U uname] [-F] device");
	use[1] = gettext("allocate [-s] [-U uname] -g dev_type");
	use[2] = gettext("deallocate [-s] [-F] device");
	use[3] = gettext("deallocate [-s] [-I]");
	use[4] = gettext("list_devices [-s] [-U uname] {-l|-n|-u} [device]");

	switch (func) {
		case 0:
			(void) fprintf(stderr, "%s\n%s\n", use[0], use[1]);
			break;
		case 1:
			(void) fprintf(stderr, "%s\n%s\n", use[2], use[3]);
			break;
		case 2:
			(void) fprintf(stderr, "%s\n", use[4]);
			break;
		default:
			(void) fprintf(stderr, "%s\n%s\n%s\n%s\n%s\n",
				use[0], use[1], use[2], use[3], use[4]);
	}
}

static void
print_error(int error, char *name)
{
	char *msg;

	switch (error) {
	case SYSERROR:
		msg = gettext("Unknown System error.");
		break;
	case IMPORT_ERR:
		msg = gettext(
		    "User lacks authorization required for this operation.");
		break;
	case NODAENT:
		msg = gettext(
		    "No device allocate file entry for specified device.");
		break;
	case NODMAPENT:
		msg = gettext(
		    "No device maps file entry for specified device.");
		break;
	case DACLCK:
		msg = gettext("Concurrent operations for specified device, "
		    "try later.");
		break;
	case DACACC:
		msg = gettext(
		    "Can't access DAC file for the device specified.");
		break;
	case DEVLST:
		msg = gettext(
		    "Could not use device list for the device specified.");
		break;
	case NALLOCU:
		msg = gettext("Specified device is allocated to another user.");
		break;
	case NOTAUTH:
		msg = gettext("Not authorized for specified operation.");
		break;
	case CNTFRC:
		msg = gettext("Can't force deallocate specified device.");
		break;
	case CNTDEXEC:
		msg = gettext(
		    "Can't exec device-clean program for specified device.");
		break;
	case NO_DEVICE:
		msg = gettext(
		    "Can't find a device of type requested to allocate.");
		break;
	case DSPMISS:
		msg = gettext(
		    "Device special file(s) missing for specified device.");
		break;
	case ALLOCERR:
		msg = gettext("Device specified is in allocate error state.");
		break;
	case CHOWN_PERR:
		msg = gettext("Process lacks privilege required to chown().");
		break;
	case ALLOC:
		msg = gettext("Device already allocated.");
		break;
	case ALLOC_OTHER:
		msg = gettext("Device allocated to another user.");
		break;
	case NALLOC:
		msg = gettext("Device not allocated.");
		break;
	case AUTHERR:
		msg = gettext("Device not allocatable.");
		break;
	case CLEAN_ERR:
		msg = gettext("Unable to clean up the device.");
		break;
	case SETACL_PERR:
		msg = gettext("Process lacks privilege required to set ACL.");
		break;
	case DEVNAME_ERR:
		msg = gettext("Error forming device name.");
		break;
	case DEVNAME_TOOLONG:
		msg = gettext("Device name is too long.");
		break;
	default:
		msg = gettext("Unknown error code.");
		break;
	}

	(void) fprintf(stderr, "%s: %s\n", name, msg);
	(void) fflush(stderr);
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
	char	*name, *env;
	int	func = -1, optflg = 0, errflg = 0, error = 0, c;
	uid_t	uid = getuid();
	char	*uname = NULL, *device = NULL;
	struct passwd *pw_ent;
	int env_num = 1;	/* PATH= is 0 entry */

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

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

	if (strcmp(name, "allocate") == 0)
		func = 0;
	else if (strcmp(name, "deallocate") == 0)
		func = 1;
	else if (strcmp(name, "list_devices") == 0)
		func = 2;
	else {
		usage(ALL);
		exit(1);
	}

	audit_allocate_argv(func, argc, argv);

	while ((c = getopt(argc, argv, "slnugIU:F")) != -1)
		switch (c) {
		case 's':
			optflg |= SILENT;
			break;
		case 'U':
			optflg |= USERID;
			uname = optarg;
			break;
		case 'g':
			optflg |= TYPE;
			break;
		case 'l':
			optflg |= LIST;
			break;
		case 'n':
			optflg |= FREE;
			break;
		case 'u':
			optflg |= CURRENT;
			break;
		case 'F':
			optflg |= FORCE;
			break;
		case 'I':
			optflg |= FORCE_ALL;
			break;
		case '?':
			errflg++;
			break;
		default :
			(void) fprintf(stderr, gettext("Bad option '%c'\n"), c);
		}

	if (optind < argc) {
		device = argv[optind];
	}

	if (device == NULL && !(optflg & (LIST | FREE | CURRENT | FORCE_ALL)))
		errflg++;

	if (errflg) {
		usage(func);
		exit(2);
	}

	if (optflg & USERID) {
		if ((pw_ent = getpwnam(uname)) == NULL) {
			(void) fprintf(stderr, gettext(
			    "Invalid user name -- %s -- \n"), uname);
			exit(4);
		}
		uid = pw_ent->pw_uid;
	}

	if (func == 0) {
		if (optflg & ~ALLOC_OPTS) {
			usage(func);
			exit(3);
		} else {
			error = allocate(optflg, uid, device);
		}
	} else if (func == 1) {
		if (optflg & ~DEALLOC_OPTS) {
			usage(func);
			exit(3);
		} else {
			error = deallocate(optflg, uid, device);
		}
	} else if (func == 2) {
		if (optflg & ~LIST_OPTS) {
			usage(func);
			exit(3);
		} else {
			error = list_devices(optflg, uid, device);
		}
	}
	(void) audit_allocate_record(error);

	if (error) {
		if (!(optflg & SILENT))
			print_error(error, name);
		exit(error);
	}

	return (0);
}
