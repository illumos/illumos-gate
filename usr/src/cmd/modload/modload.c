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

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <zone.h>

void	l_exec_userfile(char *execfile, int id, char **envp);
void	l_usage();

extern void fatal(char *fmt, ...);
extern void error(char *fmt, ...);

/*
 * Load a module.
 */
int
main(int argc, char *argv[], char *envp[])
{
	char *execfile = NULL;		/* name of file to exec after loading */
	char *modpath = NULL;
	int id;
	extern int optind;
	extern char *optarg;
	int opt;
	int use_path = 0;
	char path[1024];

	if (argc < 2 || argc > 5) {
		l_usage();
	}

	while ((opt = getopt(argc, argv, "e:p")) != -1) {
		switch (opt) {
		case 'e':
			execfile = optarg;
			break;
		case 'p':
			use_path++;
			break;
		case '?':
			l_usage();
		}
	}

	if (getzoneid() != GLOBAL_ZONEID) {
		fatal("modload can only be run from the global zone\n");
	}

	modpath = argv[optind];

	if (modpath == NULL) {
		(void) printf("modpath is null\n");
		l_usage();
	}
	if (!use_path && modpath[0] != '/') {
		if (getcwd(path, 1023 - strlen(modpath)) == NULL)
			fatal("Can't get current directory\n");
		(void) strcat(path, "/");
		(void) strcat(path, modpath);
	} else
		(void) strcpy(path, modpath);

	/*
	 * Load the module.
	 */
	if (modctl(MODLOAD, use_path, path, &id) != 0) {
		if (errno == EPERM)
			fatal("Insufficient privileges to load a module\n");
		else
			error("can't load module");
	}

	/*
	 * Exec the user's file (if any)
	 */
	if (execfile)
		l_exec_userfile(execfile, id, envp);

	return (0);		/* success */
}

/*
 * Exec the user's file
 */
void
l_exec_userfile(char *execfile, int id, char **envp)
{
	struct modinfo modinfo;

	int child;
	int status;
	int waitret;
	char module_id[8];
	char mod0[8];

	if ((child = fork()) == -1)
		error("can't fork %s", execfile);

	/*
	 * exec the user program.
	 */
	if (child == 0) {
		modinfo.mi_id = id;
		modinfo.mi_nextid = id;
		modinfo.mi_info = MI_INFO_ONE;
		if (modctl(MODINFO, id, &modinfo) < 0)
			error("can't get module status");

		(void) sprintf(module_id, "%d", modinfo.mi_id);
		(void) sprintf(mod0, "%d", modinfo.mi_msinfo[0].msi_p0);
		(void) execle(execfile, execfile, module_id, mod0, NULL, envp);

		/* Shouldn't get here if execle was successful */

		error("couldn't exec %s", execfile);
	} else {
		do {
			/* wait for exec'd program to finish */
			waitret = wait(&status);
		} while ((waitret != child) && (waitret != -1));

		waitret = (waitret == -1) ? waitret : status;

		if ((waitret & 0377) != 0) {
			/* exited because of a signal */
			(void) printf("'%s' terminated because of signal %d",
			    execfile, (waitret & 0177));
			if (waitret & 0200)
				(void) printf(" and produced a core file\n");
			(void) printf(".\n");
			exit(waitret >> 8);
		} else {
			/* simple termination */
			if (((waitret >> 8) & 0377) != 0) {
				(void) printf("'%s' returned error %d.\n",
				    execfile, (waitret >> 8) & 0377);
				exit(waitret >> 8);
			}
		}
	}
}

void
l_usage()
{
	fatal("usage:  modload [-p] [-e <exec_file>] <filename>\n");
}
