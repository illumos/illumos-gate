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
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/modctl.h>
#include <zone.h>

void	usage();
void	exec_userfile(char *execfile, int id, char **envp);

extern void fatal(char *fmt, ...);
extern void error(char *fmt, ...);

/*
 * Unload a loaded module.
 */
int
main(int argc, char *argv[], char *envp[])
{
	int child;
	int status;
	int id;
	char *execfile = NULL;
	int opt;
	extern char *optarg;

	if (argc < 3)
		usage();

	while ((opt = getopt(argc, argv, "i:e:")) != -1) {
		switch (opt) {
		case 'i':
			if (sscanf(optarg, "%d", &id) != 1)
				fatal("Invalid id %s\n", optarg);
			break;
		case 'e':
			execfile = optarg;
		}
	}

	if (getzoneid() != GLOBAL_ZONEID) {
		fatal("modunload can only be run from the global zone\n");
	}

	if (execfile) {
		child = fork();
		if (child == -1)
			error("can't fork %s", execfile);
		else if (child == 0)
			exec_userfile(execfile, id, envp);
		else {
			(void) wait(&status);
			if (status != 0) {
				(void) printf("%s returned error %d.\n",
				    execfile, status);
				(void) exit(status >> 8);
			}
		}
	}

	/*
	 * Unload the module.
	 */
	if (modctl(MODUNLOAD, id) < 0) {
		if (errno == EPERM)
			fatal("Insufficient privileges to unload a module\n");
		else if (id != 0)
			error("can't unload the module");
	}

	return (0);			/* success */
}

/*
 * exec the user file.
 */
void
exec_userfile(char *execfile, int id, char **envp)
{
	struct modinfo modinfo;

	char modid[8];
	char mod0[8];

	modinfo.mi_id = modinfo.mi_nextid = id;
	modinfo.mi_info = MI_INFO_ONE;
	if (modctl(MODINFO, id, &modinfo) < 0)
		error("can't get module information");

	(void) sprintf(modid, "%d", id);
	(void) sprintf(mod0, "%d", modinfo.mi_msinfo[0].msi_p0);

	(void) execle(execfile, execfile, modid, mod0, NULL, envp);

	error("couldn't exec %s\n", execfile);
}


void
usage()
{
	fatal("usage:  modunload -i <module_id> [-e <exec_file>]\n");
}
