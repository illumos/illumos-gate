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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<ctype.h>
#include	<string.h>
#include	<signal.h>
#include	<utmpx.h>
#include	<pwd.h>
#include	<dirent.h>
#include	<sys/param.h>
#include	<sys/acl.h>
#include	<sys/stat.h>
#include	<sys/types.h>
#include	<sys/mkdev.h>
#include	<sys/console.h>
#include	<libdevinfo.h>
#include	"ttymon.h"
#include	"tmextern.h"
#include	"tmstruct.h"

static	char	devbuf[BUFSIZ];
static	char	*devname;

static	int	parse_args(int, char **, struct pmtab *);
static	void	ttymon_options(int, char **, struct pmtab *);
static	void	getty_options(int, char **, struct pmtab *);
static	void	usage(void);
static	char	*find_ttyname(int);

/*
 * ttymon_express - This is call when ttymon is invoked with args
 *		    or invoked as getty
 *		  - This special version of ttymon will monitor
 *		    one port only
 *		  - It is intended to be used when some process
 *		    wants to have a login session on the fly
 */
void
ttymon_express(int argc, char **argv)
{
	struct	pmtab	*pmtab;
	struct	sigaction	sigact;
#ifdef	DEBUG
#endif

#ifdef	DEBUG
	opendebug(TRUE);
#endif

	sigact.sa_flags = 0;
	sigact.sa_handler = SIG_IGN;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaction(SIGINT, &sigact, NULL);

	if ((pmtab = ALLOC_PMTAB) == NULL) {
		log("ttymon_express: ALLOC_PMTAB failed");
		exit(1);
	}

	if (parse_args(argc, argv, pmtab) != 0) {
		log("ttymon_express: parse_args failed");
		exit(1);
	}

	read_ttydefs(NULL, FALSE);

	if ((pmtab->p_device != NULL) && (*(pmtab->p_device) != '\0'))
		while (checkut_line(pmtab->p_device))
			(void) sleep(15);

	if ((pmtab->p_device == NULL) || (*(pmtab->p_device) == '\0')) {
		devname = find_ttyname(0);
		if ((devname == NULL) || (*devname == '\0')) {
			log("ttyname cannot find the device on fd 0");
			exit(1);
		}
		pmtab->p_device = devname;
#ifdef	DEBUG
		debug("ttymon_express: devname = %s", devname);
#endif
		/*
		 * become session leader
		 * fd 0 is closed and reopened just to make sure
		 * controlling tty is set up right
		 */
		(void) setsid();
		(void) close(0);
		revokedevaccess(pmtab->p_device, 0, 0, 0);
		if (open(pmtab->p_device, O_RDWR) < 0) {
			log("open %s failed: %s", pmtab->p_device,
			    strerror(errno));
			exit(1);
		}
		if ((pmtab->p_modules != NULL) &&
		    (*(pmtab->p_modules) != '\0')) {
			if (push_linedisc(0, pmtab->p_modules,
			    pmtab->p_device) == -1)
				exit(1);
		}
		if (initial_termio(0, pmtab) == -1)
			exit(1);
		(void) di_devperm_logout((const char *)pmtab->p_device);
	} else {
		(void) setsid();
		(void) close(0);
		Retry = FALSE;
		open_device(pmtab);
		if (Retry)		/* open failed */
			exit(1);
	}
	tmchild(pmtab);
	exit(1);	/*NOTREACHED*/
}

/*
 * For serial device, return ttyX-mode property value.
 */
static char *
get_ttymode_prop(dev_t rconsdev)
{
	char *rootpath = "/";
	char path[MAXPATHLEN];
	di_node_t root;
	char *propname, *v;
	struct stat st;

	(void) snprintf(path, sizeof (path), "/dev/tty%c",
	    'a' + minor(rconsdev));
	if (stat(path, &st) < 0)
		return (NULL);

	if (st.st_rdev != rconsdev)
		return (NULL);

	if (asprintf(&propname, "%s-mode", path + 5) <= 0)
		return (NULL);

	root = di_init(rootpath, DINFOPROP);
	if (root == DI_NODE_NIL) {
		free(propname);
		return (NULL);
	}

	v = NULL;
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, root, propname, &v) > 0)
		v = strdup(v);

	di_fini(root);
	free(propname);
	return (v);
}

/*
 * parse_arg	- parse cmd line arguments
 */
static	int
parse_args(int argc, char **argv, struct pmtab *pmtab)
{
	static	char	p_server[] = "/usr/bin/login";
	static	char	termbuf[MAX_TERM_TYPE_LEN];
	static	struct	cons_getterm cnterm = {sizeof (termbuf), termbuf};

	/* initialize fields to some default first */
	pmtab->p_tag = "";
	pmtab->p_flags = 0;
	pmtab->p_identity = "root";
	pmtab->p_res1 = "reserved";
	pmtab->p_res2 = "reserved";
	pmtab->p_res3 = "reserved";
	pmtab->p_uid = 0;
	pmtab->p_gid = 0;
	pmtab->p_dir = "/";
	pmtab->p_ttyflags = 0;
	pmtab->p_count = 0;
	pmtab->p_server = p_server;
	pmtab->p_timeout = 0;
	pmtab->p_modules = "";
	pmtab->p_prompt = "login: ";
	pmtab->p_dmsg = "";
	pmtab->p_termtype = "";
	pmtab->p_device = "";
	pmtab->p_status = GETTY;
	pmtab->p_ttymode = NULL;
	if (strcmp(lastname(argv[0]), "getty") == 0) {
		pmtab->p_ttylabel = "300";
		getty_options(argc, argv, pmtab);
	} else {
		int	cn_fd;
		struct	cons_getdev cnd;

		pmtab->p_ttylabel = "9600";
		ttymon_options(argc, argv, pmtab);

		/*
		 * The following code is only reached if -g was specified.
		 * It attempts to determine a suitable terminal type for
		 * the console login process, and in case we are using
		 * serial console, tty mode line.
		 *
		 * If -d /dev/console also specified, we send an ioctl
		 * to the console device to query the TERM type.
		 *
		 * If any of the tests, system calls, or ioctls fail
		 * then pmtab->p_termtype retains its default value
		 * of "".  otherwise it is set to a term type value
		 * that was returned.
		 */
		if (strcmp(pmtab->p_device, "/dev/console") == 0 &&
		    (cn_fd = open("/dev/console", O_RDONLY)) != -1) {

			if (strlen(pmtab->p_termtype) == 0 &&
			    ioctl(cn_fd, CONS_GETTERM, &cnterm) != -1) {
				pmtab->p_termtype = cnterm.cn_term_type;
			}

			if (ioctl(cn_fd, CONS_GETDEV, &cnd) != -1)
				pmtab->p_ttymode =
				    get_ttymode_prop(cnd.cnd_rconsdev);
			(void) close(cn_fd);
		}
	}

	if ((pmtab->p_device != NULL) && (*(pmtab->p_device) != '\0'))
		getty_account(pmtab->p_device); /* utmp accounting */
	return (0);
}


/*
 *	ttymon_options - scan and check args for ttymon express
 */

static	void
ttymon_options(int argc, char **argv, struct pmtab *pmtab)
{
	int	c;			/* option letter */
	char	*timeout;
	int	gflag = 0;		/* -g seen */
	int	size = 0;
	char	tbuf[BUFSIZ];

	while ((c = getopt(argc, argv, "T:gd:ht:p:m:l:")) != -1) {
		switch (c) {
		case 'g':
			gflag = 1;
			break;
		case 'd':
			pmtab->p_device = optarg;
			break;
		case 'h':
			pmtab->p_ttyflags &= ~H_FLAG;
			break;

		case 'T':
			pmtab->p_termtype = optarg;
			break;
/*
 *		case 'b':
 *			pmtab->p_ttyflags |= B_FLAG;
 *			pmtab->p_ttyflags |= R_FLAG;
 *			break;
 */
		case 't':
			timeout = optarg;
			while (*optarg) {
				if (!isdigit(*optarg++)) {
					log("Invalid argument for "
					    "\"-t\" -- number expected.");
					usage();
				}
			}
			pmtab->p_timeout = atoi(timeout);
			break;
		case 'p':
			copystr(tbuf, optarg);
			pmtab->p_prompt = strsave(getword(tbuf, &size, TRUE));
			break;
		case 'm':
			pmtab->p_modules = optarg;
			if (vml(pmtab->p_modules) != 0)
				usage();
			break;
		case 'l':
			pmtab->p_ttylabel = optarg;
			break;
		case '?':
			usage();
			break;	/*NOTREACHED*/
		}
	}
	if (optind < argc)
		usage();

	if (!gflag)
		usage();
}

/*
 * usage - print out a usage message
 */

static	void
usage(void)
{
	char	*umsg = "Usage: ttymon\n  ttymon -g [-h] [-d device] "
	    "[-l ttylabel] [-t timeout] [-p prompt] [-m modules]\n";

	if (isatty(STDERR_FILENO))
		(void) fprintf(stderr, "%s", umsg);
	else
		cons_printf(umsg);
	exit(1);
}

/*
 *	getty_options	- this is cut from getty.c
 *			- it scan getty cmd args
 *			- modification is made to stuff args in pmtab
 */
static	void
getty_options(int argc, char **argv, struct pmtab *pmtab)
{
	char	*ptr;

	/*
	 * the pre-4.0 getty's hang_up_line() is a no-op.
	 * For compatibility, H_FLAG cannot be set for this "getty".
	 */
	pmtab->p_ttyflags &= ~(H_FLAG);

	while (--argc && **++argv == '-') {
		for (ptr = *argv + 1; *ptr; ptr++) {
			switch (*ptr) {
			case 'h':
				break;
			case 't':
				if (isdigit(*++ptr)) {
					(void) sscanf(ptr, "%d",
					    &(pmtab->p_timeout));
					while (isdigit(*++ptr))
						;
					ptr--;
				} else if (--argc) {
					if (isdigit(*(ptr = *++argv)))
						(void) sscanf(ptr, "%d",
						    &(pmtab->p_timeout));
					else {
						log("getty: timeout argument "
						    "<%s> invalid", *argv);
						exit(1);
					}
				}
				break;

			case 'c':
				log("Use \"sttydefs -l\" to check "
				    "/etc/ttydefs.");
				exit(0);
			default:
				break;
			}
		}
	}

	if (argc < 1) {
		log("getty: no terminal line specified.");
		exit(1);
	} else {
		(void) strcat(devbuf, "/dev/");
		(void) strcat(devbuf, *argv);
		pmtab->p_device = devbuf;
	}

	if (--argc > 0) {
		pmtab->p_ttylabel = *++argv;
	}

	/*
	 * every thing after this will be ignored
	 * i.e. termtype and linedisc are ignored
	 */
}

/*
 * find_ttyname(fd)	- find the name of device associated with fd.
 *			- it first tries utmpx to see if an entry exists
 *			- with my pid and ut_line is defined. If ut_line
 *			- is defined, it will see if the major and minor
 *			- number of fd and devname from utmpx match.
 *			- If utmpx search fails, ttyname(fd) will be called.
 */
static	char	*
find_ttyname(int fd)
{
	pid_t ownpid;
	struct utmpx *u;
	static	struct	stat	statf, statu;
	static	char	buf[BUFSIZ];

	ownpid = getpid();
	setutxent();
	while ((u = getutxent()) != NULL) {
		if (u->ut_pid == ownpid) {
			if (strlen(u->ut_line) != 0) {
				if (*(u->ut_line) != '/') {
					(void) strcpy(buf, "/dev/");
					(void) strncat(buf, u->ut_line,
					    sizeof (u->ut_line));
				} else {
					(void) strncat(buf, u->ut_line,
					    sizeof (u->ut_line));
				}
			}
			else
				u = NULL;
			break;
		}
	}
	endutxent();
	if ((u != NULL) &&
	    (fstat(fd, &statf) == 0) &&
	    (stat(buf, &statu) == 0) &&
	    (statf.st_dev == statu.st_dev) &&
	    (statf.st_rdev == statu.st_rdev)) {
#ifdef	DEBUG
			debug("ttymon_express: find device name from utmpx.");
#endif
			return (buf);
	} else {
#ifdef	DEBUG
		debug("ttymon_express: calling ttyname to find device name.");
#endif
		return (ttyname(fd));
	}
}

/*
 * Revoke all access to a device node and make sure that there are
 * no interposed streams devices attached.  Must be called before a
 * device is actually opened.
 * When fdetach is called, the underlying device node is revealed; it
 * will have the previous owner and that owner can re-attach; so we
 * retry until we win.
 * Ignore non-existent devices.
 */
void
revokedevaccess(char *dev, uid_t uid, gid_t gid, mode_t mode)
{
	do {
		if (chown(dev, uid, gid) == -1)
			return;
	} while (fdetach(dev) == 0);

	/* Remove ACLs */

	(void) acl_strip(dev, uid, gid, mode);
}
