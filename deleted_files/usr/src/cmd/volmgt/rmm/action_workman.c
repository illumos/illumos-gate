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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * if this cdrom has audio tracks, start up workman
 */

#include	<malloc.h>
#include	<sys/types.h>
#include	<sys/dkio.h>
#include	<sys/cdio.h>
#include	<sys/vtoc.h>
#include	<sys/param.h>
#include	<sys/systeminfo.h>
#include	<sys/stat.h>
#include	<rpc/types.h>
#include	<errno.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<pwd.h>
#include	<limits.h>
#include	<signal.h>
#include	<string.h>
#include	<libintl.h>
#include	<rmmount.h>
#include	<volmgt.h>


static void	setup_user(void);
static void	set_user_env(int, char **);
static void	add_to_args(int *, char ***, int, char **);
static void	clean_args(int *, char **);

extern void	dprintf(const char *fmt, ...);

/* for debug messages -- from rmmount */
extern char	*prog_name;
extern pid_t	prog_pid;

/* name of the config file */
extern char	*rmm_config;

#define	MAX_NEWARGS	20	/* more than this an something's wrong */

#ifdef	DEBUG
static void	print_args(char *, int, char **);
#endif

int
action(struct action_arg **aa, int argc, char **argv)
{
	struct cdrom_tochdr	th;
	struct cdrom_tocentry	te;
	uchar_t			i;
	int			fd;
	int			found_audio = FALSE;
	extern char		*rmm_dsodir;
	char			*atype = getenv("VOLUME_ACTION");
	int			result = TRUE;


	/* we don't care about removes, just inserts */
	if (strcmp(atype, "insert") != 0) {
		result = FALSE;
		goto dun;
	}

	/*
	 * XXX if we have a mounted file system, for now
	 * we do not want to run workman
	 */

	/* can't do anything without a path */
	if (aa[0]->aa_rawpath == NULL) {
		dprintf("action_workman: no rawpath\n");
		result = FALSE;
		goto dun;
	}

	/* ensure something to exec was passed in */
	if (argc < 2) {
		(void) fprintf(stderr, gettext(
	"%s(%d) error: workman pathname not supplied in %s\n"),
		    prog_name, prog_pid, rmm_config);
		result = FALSE;
		goto dun;
	}

	dprintf("action_workman: using path \"%s\"\n", aa[0]->aa_rawpath);

	/* open the device and read the table of contents */
	if ((fd = open(aa[0]->aa_rawpath, O_RDONLY)) < 0) {
		dprintf("action_workman: open failed; %m\n");
		result = FALSE;
		goto dun;
	}
	if (ioctl(fd, CDROMREADTOCHDR, &th) < 0) {
		dprintf("action_workman: ioctl failed; %m\n");
		(void) close(fd);
		result = FALSE;
		goto dun;
	}
	te.cdte_format = CDROM_MSF;
	for (i = (uchar_t)th.cdth_trk0; i < (uchar_t)th.cdth_trk1+1; i++) {
		te.cdte_track = i;
		if (ioctl(fd, CDROMREADTOCENTRY, &te) < 0) {
			/* can't read an entry -- just try the next */
			continue;
		}
		if ((uint_t)te.cdte_datamode == 255) {
			found_audio = TRUE;
			break;
		}
	}
	(void) close(fd);

	/* if we didn't find any audio then give up now */
	if (found_audio == FALSE) {
		dprintf("action_workman: no audio\n");
		result = FALSE;
		goto dun;
	}

	dprintf("action_workman: found audio (track %d, %d tracks ttl)\n",
	    i, th.cdth_trk1 - th.cdth_trk0 + 1);

	/*
	 * Set the ENXIO on eject attribute.  This causes workman
	 * to get an ENXIO if someone types eject from another
	 * window.  Workman, when started with the -X flag, exits
	 * as soon as it ejects the media, or if it ever sees an
	 * ENXIO from an ioctl.
	 */
	media_setattr(aa[0]->aa_rawpath, "s-enxio", "true");

	/* start workman: don't care about errors just fire and forget */
	if (fork() == 0) {
		int		fd;
		int		argc_new = 0;
		char		*argv_new[MAX_NEWARGS];
		char		sympath[MAXNAMELEN];


#ifdef	DEBUG
		dprintf("DEBUG: child is running (pid = %d)\n", getpid());
#endif
		/* child */
		chdir(rmm_dsodir);

		/* stick their error messages out on the console */
		if ((fd = open("/dev/console", O_RDWR)) >= 0) {
			(void) dup2(fd, fileno(stdin));
			(void) dup2(fd, fileno(stdout));
			(void) dup2(fd, fileno(stderr));
		}

		/* clean up args */
		clean_args(&argc, argv);

		set_user_env(argc, argv);
		setup_user();
#ifdef	DEBUG
		dprintf("DEBUG: child: after setting up env\n");
#endif
		/* remove leading shared-object name (ours!) */
		argc--; argv++;

		/* set up path to use (instead of rawpath) */
		(void) sprintf(sympath, "/vol/dev/aliases/%s",
		    getenv("VOLUME_SYMDEV"));

		/* add to argv passed in */
		argv_new[argc_new++] = strdup("-c");
		argv_new[argc_new++] = sympath;
		argv_new[argc_new++] = "-o";
		argv_new[argc_new++] = "-X";
		argv_new[argc_new] = NULL;
#ifdef	DEBUG
		dprintf("DEBUG: child: about to add to args ...\n");
#endif
		/* combine our argv and the new list */
		add_to_args(&argc, &argv, argc_new, argv_new);
#ifdef	DEBUG
		print_args("before exec", argc, argv);
#endif
		(void) execv(argv[0], argv);

		/* bummer, it failed -- EXIT, don't return!! */
		(void) fprintf(stderr,
		    gettext("%s(%ld) error: exec of \"%s\" failed; %s\n"),
		    prog_name, prog_pid, argv[0], strerror(errno));
		exit(1);
		/*NOTREACHED*/
	}


dun:

	return (result);
}


/*
 * setup_user:
 *	set a reasonable user and group to run workman as.  The default
 *	is to make it be daemon/other.
 *	The other thing we want to do is make the cwd to be
 *	the user's home directory so all the nice workman databases
 *	work right.
 */
void
setup_user(void)
{
	struct stat	sb;
	uid_t		uid = 1;	/* daemon */
	gid_t		gid = 1;	/* other */
	struct passwd	*pw;
	char		namebuf[MAXNAMELEN];


	/*
	 * The assumption is that a workstation is being used by
	 * the person that's logged into the console and that they
	 * just inserted the cdrom.  This breaks down on servers,
	 * but the most common case (by far) is someone listening
	 * to a cdrom at thier desk, while logged in and running the
	 * window system.
	 */
	if (stat("/dev/console", &sb) == 0) {
		if (sb.st_uid != 0) {
			uid = sb.st_uid;
		}
	}
	/* set HOME env. var. */
	if ((pw = getpwuid(uid)) != NULL) {
		gid = pw->pw_gid;
		(void) sprintf(namebuf, "HOME=%s", pw->pw_dir);
		(void) putenv(strdup(namebuf));
	} else {
		(void) putenv("HOME=/tmp");
	}

	if (setgid(gid) < 0) {
		perror("Failed to set gid:");
	}

	if (setuid(uid) < 0) {
		perror("Failed to set uid:");
	}

}


/*
 * set_user_env -- set up user environment
 */
static void set_user_env(int ac, char **av)
{
	int			i;
	bool_t			display_specified = FALSE;
	static char		hostname[MAXNAMELEN+1];
	static char		display[MAXNAMELEN+1];
	static char		ld_lib_path[MAXNAMELEN+1];
	static char		xfsp[MAXNAMELEN+1];
	static char		xufsp[MAXNAMELEN+1];



#ifdef	DEBUG
	dprintf("DEBUG: set_user_env(): entering\n");
	print_args("entry to set_user_env()", ac, av);
#endif

	/* only set display if it wasn't passed in */
	for (i = 0; i < ac; i++) {
		if ((strcmp(av[i], "-display") == 0) &&
		    (ac > (i+1))) {
			display_specified = TRUE;
			(void) strcpy(display, av[i+1]);
			break;
		}
	}
#ifdef	DEBUG
	dprintf("DEBUG: set_user_env(): display found = %s\n",
	    display_specified ? "TRUE" : "FALSE");
#endif
	if (!display_specified) {
		(void) sysinfo(SI_HOSTNAME, hostname, MAXNAMELEN);
		(void) sprintf(display, "DISPLAY=%s:0.0", hostname);
		(void) putenv(display);
	}

	(void) sprintf(ld_lib_path, "LD_LIBRARY_PATH=%s:%s:%s",
	    "/usr/lib",
	    "/usr/openwin/lib",
	    "/usr/ucblib");
	(void) putenv(ld_lib_path);

	(void) sprintf(xfsp, "XFILESEARCHPATH=%s:%s",
	    "/usr/openwin/lib/app-defaults/%L/%N",
	    "/usr/openwin/lib/app-defaults/%N");
	(void) putenv(xfsp);

	(void) sprintf(xufsp, "XUSERFILESEARCHPATH=%s:%s",
	    "/usr/openwin/lib/app-defaults/%L/%N",
	    "/usr/openwin/lib/app-defaults/%N");
	(void) putenv(xufsp);

	(void) putenv("OPENWINHOME=/usr/openwin");

#ifdef	DEBUG
	dprintf("DEBUG: set_user_env(): leaving\n");
#endif

}


/*
 * add src args to dest arg list
 */
static void
add_to_args(
	int *dest_argcp,			/* ptr to dest argc */
	char ***dest_argvp,			/* ptr to dest argv */
	int src_argc,				/* src argc */
	char **src_argv)			/* src argv */
{
	int		dest_argc = *dest_argcp;
	char		**dest_argv = *dest_argvp;
	int		amt;
	char		**arr;
	int		ind;
	int		i;



	/* find size of new array */
	amt = dest_argc + src_argc;

	/* allocate array */
	if ((arr = (char **)malloc((size_t)
	    ((amt + 1) * (size_t)sizeof (char *)))) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s(%ld) error: can't allocate space; %s\n"),
		    prog_name, prog_pid, strerror(errno));
		return;		/* just return the orig array ?? */
	}

	/* copy old and new array into our new space */
	ind = 0;
	for (i = 0; i < dest_argc; i++) {
		arr[ind++] = dest_argv[i];
	}
	for (i = 0; i < src_argc; i++) {
		arr[ind++] = src_argv[i];
	}
	arr[ind] = NULL;

	/* return result in place of dest junk */
	*dest_argcp = amt;
	*dest_argvp = arr;
}


/*
 * clean up args:
 *	- ensure av[0] == av[1]
 *	- ensure that *acp is correct
 *	- correct the device crap		-- NOT YET IMPLEMENTED
 */
static void
clean_args(int *acp, char **av)
{
	int	i;

	/* ensure count is correct */
	for (i = 0; i < *acp; i++) {
		if (av[i] == NULL) {
			*acp = i;
			break;
		}
	}
}

#ifdef	DEBUG
static char *
safe(char *str)
{
	static char	*ohoh = "<null ptr>";


	if (str != NULL) {
		return (str);
	}
	return (ohoh);
}


static void
print_args(char *tag, int ac, char **av)
{
	int	i;


	dprintf("DEBUG: %s:\n", tag);

	for (i = 0; i < ac; i++) {
		dprintf(" arg[%d] = \"%s\"\n", i, safe(av[i]));
	}
}

#endif	/* DEBUG */
