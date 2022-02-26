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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ramdiskadm - administer ramdisk(4D). Allows creation and deletion of
 * ramdisks, and display status. All the ioctls are private between
 * ramdisk and ramdiskadm, and so are very simple - device information is
 * communicated via a name or a minor number.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ramdisk.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/sunddi.h>
#include <libdevinfo.h>
#include <stdio.h>
#include <fcntl.h>
#include <locale.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <ctype.h>
#include "utils.h"

#define	RD_BLOCK_DEV_PFX	"/dev/" RD_BLOCK_NAME "/"
#define	RD_CHAR_DEV_PFX		"/dev/" RD_CHAR_NAME "/"

#define	HEADING	"%-*.*s %20s  %-10s\n"
#define	FORMAT	"%-*.*s %20llu    %s\n"
#define	FW	(sizeof (RD_BLOCK_DEV_PFX) - 1 + RD_NAME_LEN)

static char *pname;

static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("Usage: %s [ -a <name> <size>[g|m|k|b] | -d <name> ]\n"),
	    pname);
	exit(E_USAGE);
}

/*
 * This might be the first time we've used this minor device. If so,
 * it might also be that the /dev links are in the process of being created
 * by devfsadmd (or that they'll be created "soon"). We cannot return
 * until they're there or the invoker of ramdiskadm might try to use them
 * and not find them. This can happen if a shell script is running on
 * an MP.
 */
static void
wait_until_dev_complete(char *name)
{
	di_devlink_handle_t hdl;

	hdl = di_devlink_init(RD_DRIVER_NAME, DI_MAKE_LINK);
	if (hdl == NULL) {
		die(gettext("couldn't create device link for\"%s\""), name);
	}
	(void) di_devlink_fini(&hdl);
}

/*
 * Create a named ramdisk.
 */
static void
alloc_ramdisk(int ctl_fd, char *name, uint64_t size)
{
	struct rd_ioctl	ri;

	(void) strlcpy(ri.ri_name, name, sizeof (ri.ri_name));
	ri.ri_size = size;

	if (ioctl(ctl_fd, RD_CREATE_DISK, &ri) == -1) {
		die(gettext("couldn't create ramdisk \"%s\""), name);
	}
	wait_until_dev_complete(name);

	(void) printf(RD_BLOCK_DEV_PFX "%s\n", name);
}

/*
 * Delete a named ramdisk.
 */
static void
delete_ramdisk(int ctl_fd, char *name)
{
	struct rd_ioctl	ri;

	(void) strlcpy(ri.ri_name, name, sizeof (ri.ri_name));

	if (ioctl(ctl_fd, RD_DELETE_DISK, &ri) == -1) {
		die(gettext("couldn't delete ramdisk \"%s\""), name);
	}
}

/*ARGSUSED*/
static int
di_callback(di_node_t node, di_minor_t minor, void *arg)
{
	static boolean_t	heading_done = B_FALSE;
	boolean_t		obp_ramdisk;
	char			*name;
	char			devnm[MAXNAMELEN];
	uint64_t		*sizep;
	char			blkpath[MAXPATHLEN];

	/*
	 * Only consider block nodes bound to the ramdisk driver.
	 */
	if (strcmp(di_driver_name(node), RD_DRIVER_NAME) == 0 &&
	    di_minor_spectype(minor) == S_IFBLK) {
		/*
		 * Determine whether this ramdisk is pseudo or OBP-created.
		 */
		obp_ramdisk = (di_nodeid(node) == DI_PROM_NODEID);

		/*
		 * If this is an OBP-created ramdisk use the node name, having
		 * first stripped the "ramdisk-" prefix.  For pseudo ramdisks
		 * use the minor name, having first stripped any ",raw" suffix.
		 */
		if (obp_ramdisk) {
			RD_STRIP_PREFIX(name, di_node_name(node));
			(void) strlcpy(devnm, name, sizeof (devnm));
		} else {
			(void) strlcpy(devnm, di_minor_name(minor),
			    sizeof (devnm));
			RD_STRIP_SUFFIX(devnm);
		}

		/*
		 * Get the size of the ramdisk.
		 */
		if (di_prop_lookup_int64(di_minor_devt(minor), node,
		    "Size", (int64_t **)&sizep) == -1) {
			die(gettext("couldn't obtain size of ramdisk"));
		}

		/*
		 * Print information about the ramdisk.  Prepend a heading
		 * if this is the first/only one.
		 */
		if (!heading_done) {
			(void) printf(HEADING, FW, FW, gettext("Block Device"),
			    gettext("Size"), gettext("Removable"));
			heading_done = B_TRUE;
		}
		(void) snprintf(blkpath, sizeof (blkpath),
		    RD_BLOCK_DEV_PFX "%s", devnm);
		(void) printf(FORMAT, FW, FW, blkpath, *sizep,
		    obp_ramdisk ? gettext("No") : gettext("Yes"));
	}

	return (DI_WALK_CONTINUE);
}

/*
 * Print the list of all the ramdisks, their size, and whether they
 * are removeable (i.e. non-OBP ramdisks).
 */
static void
print_ramdisk(void)
{
	di_node_t	root;

	/*
	 * Create a snapshot of the device tree, then walk it looking
	 * for, and printing information about, ramdisk nodes.
	 */
	if ((root = di_init("/", DINFOCPYALL)) == DI_NODE_NIL) {
		die(gettext("couldn't create device tree snapshot"));
	}

	if (di_walk_minor(root, DDI_PSEUDO, 0, NULL, di_callback) == -1) {
		di_fini(root);
		die(gettext("device tree walk failure"));
	}

	di_fini(root);
}

int
main(int argc, char *argv[])
{
	int		c;
	char		*name = NULL;
	int		allocflag = 0;
	int		deleteflag = 0;
	int		errflag = 0;
	char		*suffix;
	uint64_t	size;
	int		openflag;
	int		ctl_fd = 0;
	static char	rd_ctl[] = "/dev/" RD_CTL_NAME;

	pname = getpname(argv[0]);

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "a:d:")) != EOF) {
		switch (c) {
		case 'a':
			allocflag = 1;
			name = optarg;

			if (((argc - optind) <= 0) || (*argv[optind] == '-')) {
				warn(gettext("<size> missing\n"));
				usage();
				/*NOTREACHED*/
			}
			size = strtoll(argv[optind], &suffix, 0);
			if (strcmp(suffix, "b") == 0) {
				size *= 512;
				++suffix;
			} else if (strcmp(suffix, "k") == 0) {
				size *= 1024;
				++suffix;
			} else if (strcmp(suffix, "m") == 0) {
				size *= (1024 * 1024);
				++suffix;
			} else if (strcmp(suffix, "g") == 0) {
				size *= (1024 * 1024 * 1024);
				++suffix;
			}
			if (size == 0 || *suffix != '\0') {
				warn(gettext("Illegal <size> \"%s\"\n"),
				    argv[optind]);
				usage();
				/*NOTREACHED*/
			}
			++optind;
			break;
		case 'd':
			deleteflag = 1;
			name = optarg;
			break;
		default:
			errflag = 1;
			break;
		}
	}
	if (errflag || (allocflag && deleteflag) || (argc - optind) > 0) {
		usage();
		/*NOTREACHED*/
	}

	if (allocflag || deleteflag) {
		boolean_t	nameok = B_TRUE;
		char		*p;

		/*
		 * Strip off any leading "/dev/{r}ramdisk/" prefix.
		 */
		if (strncmp(name, RD_BLOCK_DEV_PFX,
		    sizeof (RD_BLOCK_DEV_PFX)-1) == 0) {
			name += sizeof (RD_BLOCK_DEV_PFX)-1;
		} else if (strncmp(name, RD_CHAR_DEV_PFX,
		    sizeof (RD_CHAR_DEV_PFX)-1) == 0) {
			name += sizeof (RD_CHAR_DEV_PFX)-1;
		}

		/*
		 * Check that name isn't too long, and that it only contains
		 * valid characters, i.e. [a-zA-Z0-9_][a-zA-Z0-9_-]*
		 */
		if (name[0] == '-') {		/* permit only within name */
			nameok = B_FALSE;
		} else {
			for (p = name; *p != '\0'; p++) {
				if (!isalnum(*p) && *p != '_' && *p != '-') {
					nameok = B_FALSE;
					break;
				}
			}
		}
		if (!nameok || (p - name) > RD_NAME_LEN) {
			warn(gettext("illegal <name> \"%s\"\n"), name);
			usage();
			/*NOTREACHED*/
		}
	}

	/*
	 * Now do the real work.
	 */
	openflag = O_EXCL;
	if (allocflag || deleteflag)
		openflag |= O_RDWR;
	else
		openflag |= O_RDONLY;
	ctl_fd = open(rd_ctl, openflag);
	if (ctl_fd == -1) {
		if ((errno == EPERM) || (errno == EACCES)) {
			die(gettext("you do not have permission to perform "
			    "that operation.\n"));
		} else {
			die("%s", rd_ctl);
		}
		/*NOTREACHED*/
	}

	if (allocflag) {
		alloc_ramdisk(ctl_fd, name, size);
	} else if (deleteflag) {
		delete_ramdisk(ctl_fd, name);
	} else {
		print_ramdisk();
	}

	return (E_SUCCESS);
}
