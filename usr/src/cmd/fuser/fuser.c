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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <errno.h>
#include <fcntl.h>
#include <kstat.h>
#include <libdevinfo.h>
#include <locale.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mnttab.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utssys.h>
#include <sys/var.h>

/*
 * Command line options for fuser command. Mutually exclusive.
 */
#define	OPT_FILE_ONLY		0x0001		/* -f */
#define	OPT_CONTAINED		0x0002		/* -c */

/*
 * Command line option modifiers for fuser command.
 */
#define	OPT_SIGNAL		0x0100		/* -k, -s */
#define	OPT_USERID		0x0200		/* -u */
#define	OPT_NBMANDLIST		0x0400		/* -n */
#define	OPT_DEVINFO		0x0800		/* -d */

#define	NELEM(a)		(sizeof (a) / sizeof ((a)[0]))

/*
 * System call prototype
 */
extern int utssys(void *buf, int arg, int type, void *outbp);

/*
 * Option flavors or types of options fuser command takes. Exclusive
 * options (EXCL_OPT) are mutually exclusive key options, while
 * modifier options (MOD_OPT) add to the key option. Examples are -f
 * for EXCL_OPT and -u for MOD_OPT.
 */
typedef enum {EXCL_OPT, MOD_OPT} opt_flavor_t;

struct co_tab {
	int	c_flag;
	char	c_char;
};

static struct co_tab code_tab[] = {
	{F_CDIR,	'c'},	/* current directory */
	{F_RDIR,	'r'},	/* root directory (via chroot) */
	{F_TEXT,	't'},	/* textfile */
	{F_OPEN,	'o'},	/* open (creat, etc.) file */
	{F_MAP,		'm'},	/* mapped file */
	{F_TTY,		'y'},	/* controlling tty */
	{F_TRACE,	'a'},	/* trace file */
	{F_NBM,		'n'}	/* nbmand lock/share reservation on file */
};

/*
 * Return a pointer to the mount point matching the given special name, if
 * possible, otherwise, exit with 1 if mnttab corruption is detected, else
 * return NULL.
 *
 * NOTE:  the underlying storage for mget and mref is defined static by
 * libos.  Repeated calls to getmntany() overwrite it; to save mnttab
 * structures would require copying the member strings elsewhere.
 */
static char *
spec_to_mount(char *specname)
{
	struct mnttab 	mref, mget;
	struct stat 	st;
	FILE		*frp;
	int 		ret;

	/* get mount-point */
	if ((frp = fopen(MNTTAB, "r")) == NULL)
		return (NULL);

	mntnull(&mref);
	mref.mnt_special = specname;
	ret = getmntany(frp, &mget, &mref);
	(void) fclose(frp);

	if (ret == 0) {
		if ((stat(specname, &st) == 0) && S_ISBLK(st.st_mode))
			return (mget.mnt_mountp);
	} else if (ret > 0) {
		(void) fprintf(stderr, gettext("mnttab is corrupted\n"));
		exit(1);
	}
	return (NULL);
}

/*
 * The main objective of this routine is to allocate an array of f_user_t's.
 * In order for it to know how large an array to allocate, it must know
 * the value of v.v_proc in the kernel.  To get this, we do a kstat
 * lookup to get the var structure from the kernel.
 */
static fu_data_t *
get_f_user_buf()
{
	fu_data_t	fu_header, *fu_data;
	kstat_ctl_t	*kc;
	struct var	v;
	kstat_t		*ksp;
	int		count;

	if ((kc = kstat_open()) == NULL ||
	    (ksp = kstat_lookup(kc, "unix", 0, "var")) == NULL ||
	    kstat_read(kc, ksp, &v) == -1) {
		perror(gettext("kstat_read() of struct var failed"));
		exit(1);
	}
	(void) kstat_close(kc);

	/*
	 * get a count of the current number of kernel file consumers
	 *
	 * the number of kernel file consumers can change between
	 * the time when we get this count of all kernel file
	 * consumers and when we get the actual file usage
	 * information back from the kernel.
	 *
	 * we use the current count as a maximum because we assume
	 * that not all kernel file consumers are accessing the
	 * file we're interested in.  this assumption should make
	 * the current number of kernel file consumers a valid
	 * upper limit of possible file consumers.
	 *
	 * this call should never fail
	 */
	fu_header.fud_user_max = 0;
	fu_header.fud_user_count = 0;
	(void) utssys(NULL, F_KINFO_COUNT, UTS_FUSERS, &fu_header);

	count = v.v_proc + fu_header.fud_user_count;

	fu_data = (fu_data_t *)malloc(fu_data_size(count));
	if (fu_data == NULL) {
		(void) fprintf(stderr,
		    gettext("fuser: could not allocate buffer\n"));
		exit(1);
	}
	fu_data->fud_user_max = count;
	fu_data->fud_user_count = 0;
	return (fu_data);
}

/*
 * display the fuser usage message and exit
 */
static void
usage()
{
	(void) fprintf(stderr,
	    gettext("Usage:  fuser [-[k|s sig]un[c|f|d]] files"
	    " [-[[k|s sig]un[c|f|d]] files]..\n"));
	exit(1);
}

static int
report_process(f_user_t *f_user, int options, int sig)
{
	struct passwd	*pwdp;
	int		i;

	(void) fprintf(stdout, " %7d", (int)f_user->fu_pid);
	(void) fflush(stdout);

	/* print out any character codes for the process */
	for (i = 0; i < NELEM(code_tab); i++) {
		if (f_user->fu_flags & code_tab[i].c_flag)
			(void) fprintf(stderr, "%c", code_tab[i].c_char);
	}

	/* optionally print the login name for the process */
	if ((options & OPT_USERID) &&
	    ((pwdp = getpwuid(f_user->fu_uid)) != NULL))
		(void) fprintf(stderr, "(%s)", pwdp->pw_name);

	/* optionally send a signal to the process */
	if (options & OPT_SIGNAL)
		(void) kill(f_user->fu_pid, sig);

	return (0);
}

static char *
i_get_dev_path(f_user_t *f_user, char *drv_name, int major, di_node_t *di_root)
{
	di_minor_t	di_minor;
	di_node_t	di_node;
	dev_t		dev;
	char		*path;

	/*
	 * if we don't have a snapshot of the device tree yet, then
	 * take one so we can try to look up the device node and
	 * some kind of path to it.
	 */
	if (*di_root == DI_NODE_NIL) {
		*di_root = di_init("/", DINFOSUBTREE | DINFOMINOR);
		if (*di_root == DI_NODE_NIL) {
			perror(gettext("devinfo snapshot failed"));
			return ((char *)-1);
		}
	}

	/* find device nodes that are bound to this driver */
	di_node = di_drv_first_node(drv_name, *di_root);
	if (di_node == DI_NODE_NIL)
		return (NULL);

	/* try to get a dev_t for the device node we want to look up */
	if (f_user->fu_minor == -1)
		dev = DDI_DEV_T_NONE;
	else
		dev = makedev(major, f_user->fu_minor);

	/* walk all the device nodes bound to this driver */
	do {

		/* see if we can get a path to the minor node */
		if (dev != DDI_DEV_T_NONE) {
			di_minor = DI_MINOR_NIL;
			while (di_minor = di_minor_next(di_node, di_minor)) {
				if (dev != di_minor_devt(di_minor))
					continue;
				path = di_devfs_minor_path(di_minor);
				if (path == NULL) {
					perror(gettext(
						"unable to get device path"));
					return ((char *)-1);
				}
				return (path);
			}
		}

		/* see if we can get a path to the device instance */
		if ((f_user->fu_instance != -1) &&
		    (f_user->fu_instance == di_instance(di_node))) {
			path = di_devfs_path(di_node);
			if (path == NULL) {
				perror(gettext("unable to get device path"));
				return ((char *)-1);
			}
			return (path);
		}
	} while (di_node = di_drv_next_node(di_node));

	return (NULL);
}

static int
report_kernel(f_user_t *f_user, di_node_t *di_root)
{
	struct modinfo	modinfo;
	char		*path;
	int		major = -1;

	/* get the module name */
	modinfo.mi_info = MI_INFO_ONE | MI_INFO_CNT | MI_INFO_NOBASE;
	modinfo.mi_id = modinfo.mi_nextid = f_user->fu_modid;
	if (modctl(MODINFO, f_user->fu_modid, &modinfo) < 0) {
		perror(gettext("unable to get kernel module information"));
		return (-1);
	}

	/*
	 * if we don't have any device info then just
	 * print the module name
	 */
	if ((f_user->fu_instance == -1) && (f_user->fu_minor == -1)) {
		(void) fprintf(stderr, " [%s]", modinfo.mi_name);
		return (0);
	}

	/* get the driver major number */
	if (modctl(MODGETMAJBIND,
	    modinfo.mi_name, strlen(modinfo.mi_name) + 1, &major) < 0) {
		perror(gettext("unable to get driver major number"));
		return (-1);
	}

	path = i_get_dev_path(f_user, modinfo.mi_name, major, di_root);
	if (path == (char *)-1)
		return (-1);

	/* check if we couldn't get any device pathing info */
	if (path == NULL) {
		if (f_user->fu_minor == -1) {
			/*
			 * we don't really have any more info on the device
			 * so display the driver name in the same format
			 * that we would for a plain module
			 */
			(void) fprintf(stderr, " [%s]", modinfo.mi_name);
			return (0);
		} else {
			/*
			 * if we only have dev_t information, then display
			 * the driver name and the dev_t info
			 */
			(void) fprintf(stderr, " [%s,dev=(%d,%d)]",
			    modinfo.mi_name, major, f_user->fu_minor);
			return (0);
		}
	}

	/* display device pathing information */
	if (f_user->fu_minor == -1) {
		/*
		 * display the driver name and a path to the device
		 * instance.
		 */
		(void) fprintf(stderr, " [%s,dev_path=%s]",
		    modinfo.mi_name, path);
	} else {
		/*
		 * here we have lot's of info.  the driver name, the minor
		 * node dev_t, and a path to the device.  display it all.
		 */
		(void) fprintf(stderr, " [%s,dev=(%d,%d),dev_path=%s]",
		    modinfo.mi_name, major, f_user->fu_minor, path);
	}

	di_devfs_path_free(path);
	return (0);
}

/*
 * Show pids and usage indicators for the nusers processes in the users list.
 * When OPT_USERID is set, give associated login names.  When OPT_SIGNAL is
 * set, issue the specified signal to those processes.
 */
static void
report(fu_data_t *fu_data, int options, int sig)
{
	di_node_t	di_root = DI_NODE_NIL;
	f_user_t 	*f_user;
	int		err, i;

	for (err = i = 0; (err == 0) && (i <  fu_data->fud_user_count); i++) {

		f_user = &(fu_data->fud_user[i]);
		if (f_user->fu_flags & F_KERNEL) {
			/* a kernel module is using the file */
			err = report_kernel(f_user, &di_root);
		} else {
			/* a userland process using the file */
			err = report_process(f_user, options, sig);
		}
	}

	if (di_root != DI_NODE_NIL)
		di_fini(di_root);
}

/*
 * Sanity check the option "nextopt" and OR it into *options.
 */
static void
set_option(int *options, int nextopt, opt_flavor_t type)
{
	static const char	*excl_opts[] = {"-c", "-f", "-d"};
	int			i;

	/*
	 * Disallow repeating options
	 */
	if (*options & nextopt)
		usage();

	/*
	 * If EXCL_OPT, allow only one option to be set
	 */
	if ((type == EXCL_OPT) && (*options)) {
		(void) fprintf(stderr,
		    gettext("Use only one of the following options :"));
		for (i = 0; i < NELEM(excl_opts); i++) {
			if (i == 0) {
				(void) fprintf(stderr, gettext(" %s"),
				    excl_opts[i]);
			} else {
				(void) fprintf(stderr, gettext(", %s"),
				    excl_opts[i]);
			}
		}
		(void) fprintf(stderr, "\n"),
		usage();
	}
	*options |= nextopt;
}

/*
 * Determine which processes are using a named file or file system.
 * On stdout, show the pid of each process using each command line file
 * with indication(s) of its use(s).  Optionally display the login
 * name with each process.  Also optionally, issue the specified signal to
 * each process.
 *
 * X/Open Commands and Utilites, Issue 5 requires fuser to process
 * the complete list of names it is given, so if an error is encountered
 * it will continue through the list, and then exit with a non-zero
 * value. This is a change from earlier behavior where the command
 * would exit immediately upon an error.
 *
 * The preferred use of the command is with a single file or file system.
 */

int
main(int argc, char **argv)
{
	fu_data_t	*fu_data;
	char		*mntname;
	int		c, newfile = 0, errors = 0, opts = 0, flags = 0;
	int		uts_flags, sig, okay, err;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (argc < 2)
		usage();

	do {
		while ((c = getopt(argc, argv, "cdfkns:u")) != EOF) {
			if (newfile) {
				/*
				 * Starting a new group of files.
				 * Clear out options currently in
				 * force.
				 */
				flags = opts = newfile = 0;
			}
			switch (c) {
			case 'd':
				set_option(&opts, OPT_DEVINFO, EXCL_OPT);
				break;
			case 'k':
				set_option(&flags, OPT_SIGNAL, MOD_OPT);
				sig = SIGKILL;
				break;
			case 's':
				set_option(&flags, OPT_SIGNAL, MOD_OPT);
				if (str2sig(optarg, &sig) != 0) {
					(void) fprintf(stderr,
					    gettext("Invalid signal %s\n"),
					    optarg);
					usage();
				}
				break;
			case 'u':
				set_option(&flags, OPT_USERID, MOD_OPT);
				break;
			case 'n':
				/*
				 * Report only users with NBMAND locks
				 */
				set_option(&flags, OPT_NBMANDLIST, MOD_OPT);
				break;
			case 'c':
				set_option(&opts, OPT_CONTAINED, EXCL_OPT);
				break;
			case 'f':
				set_option(&opts, OPT_FILE_ONLY, EXCL_OPT);
				break;
			default:
				(void) fprintf(stderr,
				    gettext("Illegal option %c.\n"), c);
				usage();
			}
		}

		if ((optind < argc) && (newfile)) {
			/*
			 * Cancel the options currently in
			 * force if a lone dash is specified.
			 */
			if (strcmp(argv[optind], "-") == 0) {
				flags = opts = newfile = 0;
				optind++;
			}
		}

		/*
		 * newfile is set when a new group of files is found.  If all
		 * arguments are processed and newfile isn't set here, then
		 * the user did not use the correct syntax
		 */
		if (optind > argc - 1) {
			if (!newfile) {
				(void) fprintf(stderr,
				    gettext("fuser: missing file name\n"));
				usage();
			}
		} else {
			if (argv[optind][0] == '-') {
				(void) fprintf(stderr,
				    gettext("fuser: incorrect use of -\n"));
				usage();
			} else {
				newfile = 1;
			}
		}

		/* allocate a buffer to hold usage data */
		fu_data = get_f_user_buf();

		/*
		 * First print file name on stderr
		 * (so stdout (pids) can be piped to kill)
		 */
		(void) fflush(stdout);
		(void) fprintf(stderr, "%s: ", argv[optind]);

		/*
		 * if not OPT_FILE_ONLY, OPT_DEVINFO, or OPT_CONTAINED,
		 * attempt to translate the target file name to a mount
		 * point via /etc/mnttab.
		 */
		okay = 0;
		if (!opts &&
		    (mntname = spec_to_mount(argv[optind])) != NULL) {

			uts_flags = F_CONTAINED |
			    ((flags & OPT_NBMANDLIST) ? F_NBMANDLIST : 0);

			err = utssys(mntname, uts_flags, UTS_FUSERS, fu_data);
			if (err == 0) {
				report(fu_data, flags, sig);
				okay = 1;
			}
		}

		uts_flags = \
		    ((opts & OPT_CONTAINED) ? F_CONTAINED : 0) |
		    ((opts & OPT_DEVINFO) ? F_DEVINFO : 0) |
		    ((flags & OPT_NBMANDLIST) ? F_NBMANDLIST : 0);

		err = utssys(argv[optind], uts_flags, UTS_FUSERS, fu_data);
		if (err == 0) {
			report(fu_data, flags, sig);
		} else if (!okay) {
			perror("fuser");
			errors = 1;
			free(fu_data);
			continue;
		}

		(void) fprintf(stderr, "\n");
		free(fu_data);
	} while (++optind < argc);

	return (errors);
}
