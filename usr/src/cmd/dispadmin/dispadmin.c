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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<string.h>
#include	<limits.h>
#include	<wait.h>
#include	<zone.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/priocntl.h>

#include	"dispadmin.h"

/*
 * This file contains the code implementing the class independent part
 * of the dispadmin command.  Most of the functionality of the dispadmin
 * command is provided by the class specific sub-commands, the code for
 * which is elsewhere.  The class independent part of the command is
 * responsible for switching out to the appropriate class specific
 * sub-command based on the user supplied class argument.
 * Code in this file should never assume any knowledge of any specific
 * scheduler class (other than the SYS class).
 */

#define	BASENMSZ	16
#define	BUFSZ		(PATH_MAX + 80)
#define	CLASSPATH	"/usr/lib/class"
#define	CONFIGPATH	"/etc/dispadmin.conf"
#define	CONFIGOWNER	0	/* uid 0 (root) */
#define	CONFIGGROUP	1	/* gid 1 (other) */
#define	CONFIGPERM	(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) /* 0644 */
#define	TOKENNAME	"DEFAULT_SCHEDULER"

extern char *basename();

static char usage[] =
"usage:	dispadmin -l\n\
	dispadmin -c class [class-specific options]\n\
	dispadmin -d [class]\n";

static char basenm[BASENMSZ];
static char cmdpath[PATH_MAX];

static void print_classlist();
static void exec_cscmd(char *, char **);
static void set_scheduler(char *);
static void class_info(pcinfo_t *);
static void set_default_class();

int
main(int argc, char **argv)
{
	extern char	*optarg;
	extern int	optind, opterr;

	int		c;
	int		uflag, cflag, dflag, lflag, csoptsflag;
	char		*clname;

	(void) strncpy(cmdpath, argv[0], PATH_MAX);
	(void) strncpy(basenm, basename(argv[0]), BASENMSZ);
	cflag = dflag = lflag = uflag = csoptsflag = 0;
	opterr = 0;
	while ((c = getopt(argc, argv, "c:dlu")) != -1) {
		switch (c) {

		case 'c':
			cflag++;
			clname = optarg;
			break;

		case 'd':
			dflag++;
			clname = argv[optind];
			break;

		case 'l':
			lflag++;
			break;

		case 'u':
			uflag++;
			break;


		case '?':
			/*
			 * We assume for now that any option that
			 * getopt() doesn't recognize is intended for a
			 * class specific subcommand.
			 */
			csoptsflag++;
			if (argv[optind] && argv[optind][0] != '-') {


				/*
				 * Class specific option takes an
				 * argument which we skip over for now.
				 */
				optind++;
			}
			break;

		default:
			break;
		}
	}

	if (lflag) {
		if (uflag || cflag || dflag || csoptsflag)
			fatalerr(usage);

		print_classlist();
		exit(0);

	} else if (uflag) {
		if (lflag || dflag || csoptsflag)
			fatalerr(usage);

		set_default_class();
	} else if (cflag) {
		if (lflag || dflag)
			fatalerr(usage);

		exec_cscmd(clname, argv);

	} else if (dflag) {
		if (cflag || lflag || csoptsflag)
			fatalerr(usage);
		set_scheduler(clname);
		exit(0);

	} else {
		fatalerr(usage);
	}
	return (1);
}


/*
 * Print the heading for the class list and execute the
 * class specific sub-command with the -l option for each
 * configured class.
 */
static void
print_classlist()
{
	id_t		cid;
	int		nclass;
	pcinfo_t	pcinfo;

	if ((nclass = priocntl(0, 0, PC_GETCLINFO, NULL)) == -1)
		fatalerr("%s: Can't get number of configured classes\n",
		    cmdpath);

	(void) printf("CONFIGURED CLASSES\n==================\n\n");
	(void) printf("SYS\t(System Class)\n");
	(void) fflush(stdout);
	for (cid = 1; cid < nclass; cid++) {
		pcinfo.pc_cid = cid;
		if (priocntl(0, 0, PC_GETCLINFO, (caddr_t)&pcinfo) == -1)
			fatalerr("%s: Can't get class name (class ID = %d)\n",
			    cmdpath, cid);
		class_info(&pcinfo);
	}
}


/*
 * Execute the appropriate class specific sub-command for the class
 * specified by clname, passing it the arguments in subcmdargv.
 */
static void
exec_cscmd(char *clname, char **subcmdargv)
{
	pcinfo_t	pcinfo;
	char		subcmdpath[PATH_MAX];

	/*
	 * Do a quick check to make sure clname is valid.
	 * We could just wait and see if the exec below
	 * succeeds but we wouldn't know much about the reason.
	 * This way we can give the user a more meaningful error
	 * message.
	 */
	(void) strncpy(pcinfo.pc_clname, clname, PC_CLNMSZ);
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("%s: Invalid or unconfigured class %s\n", cmdpath,
		    clname);

	(void) snprintf(subcmdpath, PATH_MAX, "%s/%s/%s%s", CLASSPATH,
	    clname, clname, basenm);
	subcmdargv[0] = subcmdpath;

	(void) execv(subcmdpath, subcmdargv);
	fatalerr("%s: Can't execute %s sub-command\n", cmdpath, clname);
}

static void
class_info(pcinfo_t *pcinfo)
{
	int pid;
	char subcmdpath[PATH_MAX];

	(void) snprintf(subcmdpath, PATH_MAX, "%s/%s/%s%s", CLASSPATH,
	    pcinfo->pc_clname, pcinfo->pc_clname, basenm);
	if ((pid = fork()) == 0) {
		(void) execl(subcmdpath, subcmdpath, "-l", (char *)0);
		fatalerr("%s\n\tCan't execute %s specific subcommand\n",
		    pcinfo->pc_clname, pcinfo->pc_clname);
	} else if (pid == (pid_t)-1) {
		(void) fprintf(stderr,
		    "%s\nCan't execute %s specific subcommand)\n",
		    pcinfo->pc_clname, pcinfo->pc_clname);
	} else {
		(void) wait(NULL);
	}
}

/*
 * Return the current default scheduling class as specified in
 * /etc/dispadmin.conf.
 */
static char *
read_default_file(FILE *fp)
{
	char buf[BUFSZ];
	int line;

	for (line = 1; fgets(buf, BUFSZ, fp) != NULL; line++) {
		char name[BUFSZ], value[BUFSZ];
		int len;

		if (buf[0] == '#' || buf[0] == '\n')
			continue;
		/* LINTED - unbounded string specifier */
		if (sscanf(buf, " %[^=]=%s \n%n", name, value, &len) == 2 &&
		    name[0] != '\0' && value[0] != '\0' && len == strlen(buf)) {

			if (strcmp(name, TOKENNAME) != 0)
				fatalerr("\"%s\", line %d: invalid "
				    "token: %s\n", CONFIGPATH, line, name);

			(void) fclose(fp);
			return (strdup(value));
		} else {
			fatalerr("\"%s\", line %d: syntax error\n", CONFIGPATH,
			    line);
			(void) fclose(fp);
		}
	}
	if (line == 1)
		fatalerr("%s: %s is empty\n", cmdpath, CONFIGPATH);
	return (NULL);
}

/*
 * Set the default scheduling class for the system.
 * Update /etc/dispadmin.conf if necessary.
 */
static void
set_scheduler(char *clname)
{
	pcinfo_t pcinfo;
	FILE *fp;
	int fd;

	if (getzoneid() != GLOBAL_ZONEID)
		fatalerr("%s: Operation not supported in non-global zones\n",
		    cmdpath);

	if (clname == NULL) {
		if ((fd = open(CONFIGPATH, O_RDONLY, CONFIGPERM)) == -1) {
			if (errno == ENOENT)
				fatalerr("%s: Default scheduling class "
				    "is not set\n", cmdpath);
			else
				fatalerr("%s: Failed to open %s (%s)\n",
				    cmdpath, CONFIGPATH, strerror(errno));
		}

		if ((fp = fdopen(fd, "r")) == NULL)
			fatalerr("%s: Failed to open stream for %s (%s)\n",
			    cmdpath, CONFIGPATH, strerror(errno));
		clname = read_default_file(fp);
		(void) strncpy(pcinfo.pc_clname, clname, PC_CLNMSZ);

		if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
			fatalerr("\"%s\", scheduling class %s is not "
			    "available\n", CONFIGPATH, clname);
		else
			class_info(&pcinfo);
		return;
	}

	/*
	 * Do a quick check to make sure clname is valid class name.
	 */
	(void) strncpy(pcinfo.pc_clname, clname, PC_CLNMSZ);
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1)
		fatalerr("%s: Invalid or unconfigured class %s\n", cmdpath,
		    clname);
	if ((fd = open(CONFIGPATH, O_RDWR | O_CREAT, CONFIGPERM)) == -1)
		fatalerr("%s: Failed to open %s (%s)\n", cmdpath, CONFIGPATH,
		    strerror(errno));
	if ((fp = fdopen(fd, "w")) == NULL)
		fatalerr("%s: Failed to open stream for %s\n", CONFIGPATH);
	if (ftruncate(fd, (off_t)0) == -1)
		fatalerr("%s: Failed to truncate %s\n", cmdpath, CONFIGPATH);
	(void) fputs("#\n# /etc/dispadmin.conf\n#\n"
	    "# Do NOT edit this file by hand -- use dispadmin(8) instead.\n"
	    "#\n", fp);
	if ((fprintf(fp, "%s=%s\n", TOKENNAME, clname)) == -1)
		fatalerr("%s: Failed to write to %s\n", cmdpath, CONFIGPATH);
	if (fflush(fp) != 0)
		(void) fprintf(stderr,
		    "%s: warning: failed to flush config file\n",
		    cmdpath);
	if (fsync(fd) == -1)
		(void) fprintf(stderr,
		    "%s: warning: failed to sync config file to disk\n",
		    cmdpath);
	if (fchmod(fd, CONFIGPERM) == -1)
		(void) fprintf(stderr,
		    "%s: warning: failed to reset config file mode\n",
		    cmdpath);
	if (fchown(fd, CONFIGOWNER, CONFIGGROUP) == -1)
		(void) fprintf(stderr,
		    "%s: warning: failed to reset config file owner\n",
		    cmdpath);
	(void) fclose(fp);

	if (priocntl(0, 0, PC_SETDFLCL, clname) == -1)
		fatalerr("%s: failed to set default class %s in kernel: %s\n",
		    cmdpath, clname, strerror(errno));
}

static void
set_default_class()
{
	char *clname;
	FILE *fp;
	int fd;

	if ((fd = open(CONFIGPATH, O_RDONLY, CONFIGPERM)) == -1) {
		/* silently succeed, there is nothing to do */
		if (errno == ENOENT)
			return;
		else
			fatalerr("%s: Failed to open %s (%s)\n",
			    cmdpath, CONFIGPATH, strerror(errno));
	}

	if ((fp = fdopen(fd, "r")) == NULL)
		fatalerr("%s: Failed to open stream for %s (%s)\n",
		    cmdpath, CONFIGPATH, strerror(errno));

	if ((clname = read_default_file(fp)) != NULL) {
		if (priocntl(0, 0, PC_SETDFLCL, clname) == -1)
			fatalerr("%s: failed to set default class %s in "
			    "kernel: %s\n", cmdpath, clname, strerror(errno));
	}
}
