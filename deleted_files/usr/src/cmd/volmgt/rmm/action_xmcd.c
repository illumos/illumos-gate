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
 * Copyright (c) 1995 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<errno.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<pwd.h>
#include	<limits.h>
#include	<signal.h>
#include	<string.h>
#include	<rmmount.h>
#include	<libintl.h>
#include	<sys/types.h>
#include	<sys/dkio.h>
#include	<sys/cdio.h>
#include	<sys/vtoc.h>
#include	<sys/param.h>
#include	<sys/systeminfo.h>
#include	<sys/stat.h>
#include	<volmgt.h>


/*
 * If this cdrom has audio tracks, start up xmcd.
 */


/* return values for the "action()" routine */
#ifdef	FALSE
#undef	FALSE
#endif
#define	FALSE	(0)

typedef enum {false, true}	bool_t;

static void	setup_user(void);
static void	set_user_env(int, char **);
static void	add_to_args(int *, char ***, int, char **);
static void	clean_args(int *, char **);

extern void	dprintf(const char *, ...);

/* for debug messages -- from rmmount */
extern char	*prog_name;
extern pid_t	prog_pid;

#ifdef	DEBUG
static void	print_args(char *, int, char **);
#endif


/*
 * this should never return, since it tries to exec xmcd
 * if it does, it'll return FALSE
 */
int
action(struct action_arg **aa, int argc, char **argv)
{
	struct cdrom_tochdr	th;
	struct cdrom_tocentry	te;
	unsigned char		i;
	int			fd;
	bool_t			found_audio = false;
	extern char		*rmm_dsodir;
	char			*atype = getenv("VOLUME_ACTION");



	if (strcmp(atype, "insert") != 0) {
		return (FALSE);
	}

	/* ensure caller has specified the program to run */
	if (argc < 2) {
		dprintf("action_xmcd: no program to run!\n");
		return (FALSE);
	}

	if (aa[0]->aa_rawpath == NULL) {
		dprintf("action_xmcd: no rawpath\n");
		return (FALSE);
	}

	dprintf("action_xmcd: raw path = \"%s\"\n", aa[0]->aa_rawpath);

	if ((fd = open(aa[0]->aa_rawpath, O_RDONLY)) < 0) {
		dprintf("action_xmcd: open; %m\n");
		return (FALSE);
	}

	/* read the TOC (tbl of contents) */
	if (ioctl(fd, CDROMREADTOCHDR, &th) < 0) {
		dprintf("action_xmcd: ioctl; %m\n");
		close(fd);
		return (FALSE);
	}

	/* look for audio */
	te.cdte_format = CDROM_MSF;
	for (i = th.cdth_trk0; i < (uint_t)th.cdth_trk1+1; i++) {
		te.cdte_track = i;
		if (ioctl(fd, CDROMREADTOCENTRY, &te) < 0) {
			continue;
		}
		if ((int)te.cdte_datamode == 255) {
			found_audio = true;
			break;
		}
	}
	close(fd);

	if (!found_audio) {
		dprintf("action_xmcd: no audio\n");
		return (FALSE);
	}

	dprintf("action_xmcd: found audio (%d tracks)\n",
		th.cdth_trk1 - th.cdth_trk0 + 1);

	/*
	 * Set the ENXIO on eject attribute.  This causes xmcd
	 * to get an ENXIO if someone types eject from another
	 * window.  Workman, when started with the -X flag, exits
	 * as soon as it ejects the media, or if it ever sees an
	 * ENXIO from an ioctl.
	 */
	media_setattr(aa[0]->aa_rawpath, "s-enxio", "true");

	/* start xmcd: don't care about errors just fire and forget */
	if (fork() == 0) {
		int		fd;
		int		argc_new = 0;
		char		*argv_new[3];
		char		sympath[MAXNAMELEN];


#ifdef	DEBUG
		dprintf("DEBUG: child is running (pid = %d)\n", getpid());
#endif
		/* child */
		chdir(rmm_dsodir);

		/* stick his error messages out on the console */
		fd = open("/dev/console", O_RDWR);

		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);

#ifdef	DEBUG
		dprintf("DEBUG: child: after switching output\n");
#endif
		/* clean up args */
		clean_args(&argc, argv);
#ifdef	DEBUG
		dprintf("DEBUG: child: after cleaning up args\n");
#endif

		/*
		 * set_user_env() and setup_user() do similar things, but
		 * the former is new for xmcd and the latter is around
		 * around for historical reasons
		 */
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
		argv_new[argc_new++] = strdup("-dev");
		argv_new[argc_new++] = sympath;
		argv_new[argc_new] = NULL;

#ifdef	DEBUG
		dprintf("DEBUG: child: about to add to args ...\n");
#endif

		add_to_args(&argc, &argv, argc_new, argv_new);

#ifdef	DEBUG
		print_args("before exec", argc, argv);
#endif
		/* run that hoser */
		execv(argv[0], argv);

		(void) fprintf(stderr,
		    gettext("%s(%ld) error: exec of \"%s\" failed; %s\n"),
		    prog_name, prog_pid, argv[0], strerror(errno));

		/* bummer, it failed -- EXIT, don't return!! */
		exit(1);
	}

	/*
	 * we return false here because audio might not be the only thing
	 * on the disk, and we want actions to continue.
	 */
#ifdef	DEBUG
	dprintf("DEBUG: sleeping a while -- just wait\n");
	sleep(15);
#endif
	return (FALSE);
}


/*
 * setup_user:
 *	set a reasonable user and group to run workman as.  The default
 *	is to make it be daemon/other.
 *	The other thing we want to do is make the cwd to be
 *	the user's home directory so all the nice workman databases
 *	work right.
 */
static void
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
	if (uid != 1) {
		if ((pw = getpwuid(uid)) != NULL) {
			gid = pw->pw_gid;
			(void) sprintf(namebuf, "HOME=%s", pw->pw_dir);
			(void) putenv(strdup(namebuf));
		} else {
			(void) putenv(strdup("HOME=/tmp"));
		}
	}

	(void) setuid(uid);
	(void) seteuid(uid);
	(void) setgid(gid);
	(void) setegid(gid);
}


/*
 * set_user_env -- set up user environment
 */
static void
set_user_env(int ac, char **av)
{
	static bool_t		is_dir(char *);
	int			i;
	bool_t			display_specified = false;
	char			env_buf[MAXNAMELEN];
	static char		hostname[MAXNAMELEN];
	static char		xufsp[MAXNAMELEN];


#ifdef	DEBUG
	dprintf("DEBUG: set_user_env: entering\n");
	print_args("entry to set_user_env()", ac, av);
#endif

	/* only set display if it wasn't passed in */
	for (i = 0; i < ac; i++) {
		if ((strcmp(av[i], "-display") == 0) && (ac > (i+1))) {
			display_specified = true;
			break;
		}
	}

#ifdef	DEBUG
	dprintf("DEBUG: set_user_env: display found = %s\n",
	    display_specified ? "TRUE" : "FALSE");
#endif

	/* only set display if not done by user */
	if (!display_specified) {
		(void) sysinfo(SI_HOSTNAME, hostname, MAXNAMELEN);
		(void) sprintf(env_buf, "DISPLAY=%s:0.0", hostname);
		(void) putenv(strdup(env_buf));
	}

	/* set up where to look for app-defaults files at */
	(void) sprintf(env_buf, "XFILESEARCHPATH=%s:%s",
	    "/usr/openwin/lib/app-defaults/%L/%N",
	    "/usr/openwin/lib/app-defaults/%N");
	(void) putenv(strdup(env_buf));
	(void) sprintf(xufsp, "XUSERFILESEARCHPATH=%s:%s",
	    "/usr/openwin/lib/app-defaults/%L/%N",
	    "/usr/openwin/lib/app-defaults/%N");
	(void) putenv(strdup(env_buf));

	/* where Solaris openwindows is located at */
	if (is_dir("/usr/openwin")) {
#ifdef	DEBUG
		dprintf("set_user_env: setting OPENWINHOME env var\n");
#endif
		(void) putenv(strdup("OPENWINHOME=/usr/openwin"));
	}

	/* set the XMCD_LIBDIR env var */
	if (is_dir("/usr/openwin/lib/xmcd")) {
#ifdef	DEBUG
		dprintf("set_user_env: setting XMCD_LIBDIR env var\n");
#endif
		(void) putenv(strdup("XMCD_LIBDIR=/usr/openwin/lib/xmcd"));
	}

#ifdef	DEBUG
	dprintf("DEBUG: set_user_env: leaving\n");
#endif

}


/*
 * is the specified path a directory?
 */
static bool_t
is_dir(char *path)
{
	struct stat	sb;


	if (stat(path, &sb) < 0) {
		return (false);
	}
	if (!S_ISDIR(sb.st_mode)) {
		return (false);
	}

	return (true);
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
	if ((arr = (char **)malloc((amt + 1) * sizeof (char *))) == NULL) {
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
	static char	*ohoh = "(void ptr!)";


	if (str) {
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
