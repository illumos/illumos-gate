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
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <memory.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>
#include <bsm/devices.h>
#define	DMPFILE	"/etc/security/device_maps"
#define	RETRY_SLEEP	6
#define	RETRY_COUNT	10
#define	EINVOKE	2
#define	EFAIL 1

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SUNW_BSM_DMINFO"
#endif

extern off_t lseek();

char	*getdmapfield();
char	*getdmapdfield();
static void	printdmapent();
static void	dmapi_err();

static char	*prog_name;

/*
 * printdmapent(dmapp) prints a devmap_t structure pointed to by dmapp.
 */
static void
printdmapent(dmapp)
	devmap_t *dmapp;
{
	(void) printf("%s:", dmapp->dmap_devname);
	(void) printf("%s:", dmapp->dmap_devtype);
	(void) printf("%s", dmapp->dmap_devlist);
	(void) printf("\n");
}


/*
 * dmapi_err(exit_code,err_msg) prints message pointed to by err_msg to
 * stderr. Then prints usage message to stderr. Then exits program with
 * exit_code.
 *
 */
static void
dmapi_err(int exit_code, char *err_msg)
{
	if (err_msg != NULL) {
		(void) fprintf(stderr, "dmapinfo:%s\n", err_msg);
	}
	if (exit_code == EINVOKE) {
		(void) fprintf(stderr,
			"Usage: %s [-v] [-a] [-f filename] %s\n",
			prog_name,
			"[-d device ...]");
		(void) fprintf(stderr,
			"       %s [-v] [-a] [-f filename] %s\n",
			prog_name,
			"[-n name ...]");
		(void) fprintf(stderr,
			"       %s [-v] [-a] [-f filename] %s\n",
			prog_name,
			"[-t type ...]");
		(void) fprintf(stderr,
			"       %s [-v] [-a] [-f filename] %s\n",
			prog_name,
			"[-u Entry]");
	}

	exit(exit_code);
}

int
main(int argc, char **argv)
{
	devmap_t *dmapp;
	devmap_t dmap;
	char	*mptr;
	char	*tptr;
	char	*nptr;
	char	*filename = DMPFILE;
	int	name = 0;
	int	device = 0;
	int	file = 0;
	int	verbose = 0;
	int	cntr = 0;
	int	any = 0;
	int	update = 0;
	int	tp = 0;
	int	des;
	int	status;

	/* Internationalization */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * point prog_name to invocation name
	 */
	if ((tptr = strrchr(*argv, '/')) != NULL)
		prog_name = ++tptr;
		else
		prog_name = *argv;
	argc--;
	argv++;
	/*
	 * parse arguments
	 */
	while ((argc >= 1) && (argv[0][0] == '-')) {
		switch (argv[0][1]) {
		case 'a':
			any++;
			break;
		case 'd':
			if ((name) || (device) || (update) || (tp)) {
				dmapi_err(EINVOKE,
					gettext("option conflict"));
			}
			device++;
			break;
		case 'f':
			argc--;
			argv++;
			if (argc <= 0)
				dmapi_err(EINVOKE,
					gettext("missing file name"));
			filename = *argv;
			file++;
			break;
		case 'n':
			if ((name) || (device) || (update) || (tp)) {
				dmapi_err(EINVOKE,
					gettext("option conflict"));
			}
			name++;
			break;
		case 't':
			if ((name) || (device) || (update) || (tp)) {
				dmapi_err(EINVOKE,
					gettext("option conflict"));
			}
			tp++;
			break;
		case 'u':
			if ((name) || (device) || (update) || (tp)) {
				dmapi_err(EINVOKE,
					gettext("option conflict"));
			}
			update++;
			break;
		case 'v':
			verbose++;
			break;
		default:
			dmapi_err(EINVOKE,
				gettext("bad option"));
			break;
		}
		argc--;
		argv++;
	}
	/*
	 * -d(device) -n(name) and -u(update) switches require at least one
	 * argument.
	 */
	if (file)
		setdmapfile(filename);
	if ((device) || (name) || (update) || (tp)) {
		if (argc < 1) {
			dmapi_err(EINVOKE,
				gettext("insufficient args for this option"));
		}
	}
	if (update) {
		/*
		 * -u(update) switch requires only one argument
		 */
		if (argc != 1) {
			dmapi_err(EINVOKE,
				gettext("too many args for this option"));
		}
		/*
		 * read entry argument from stdin into a devmap_t known as dmap
		 */
		if ((dmap.dmap_devname = getdmapfield(*argv)) == NULL) {
			dmapi_err(EINVOKE,
				gettext("Bad dmap_devname in entry argument"));
		}
		if ((dmap.dmap_devtype = getdmapfield(NULL)) ==
			NULL) {
			dmapi_err(EINVOKE,
				gettext("Bad dmap_devtype in entry Argument"));
		}
		if ((dmap.dmap_devlist = getdmapfield(NULL)) ==
			NULL) {
			dmapi_err(EINVOKE,
				gettext("Bad dmap_devlist in entry argument"));
		}
		/*
		 * Find out how long device list is and create a buffer to
		 * hold it.  Then copy it there. This is done since we do not
		 * want to corrupt the existing string.
		 */
		cntr = strlen(dmap.dmap_devlist) + 1;
		mptr = calloc((unsigned)cntr, sizeof (char));
		if (mptr == NULL) {
			if (verbose) {
				(void) fprintf(stderr,
					gettext(
					"dmapinfo: Cannot calloc memory\n"));
			}
			exit(1);
		}
		(void) strcpy(mptr, dmap.dmap_devlist);
		/*
		 * open the device maps file for read/ write. We are not
		 * sure we want to write to it yet but we may and this is a
		 * easy way to get the file descriptor. We want the file
		 * descriptor so we can lock the file.
		 */
		if ((des = open(filename, O_RDWR)) < 0) {
			if (verbose) {
				(void) fprintf(stderr,
				gettext("dmapinfo: Cannot open %s\n"),
				    filename);
			}
			exit(1);
		}
		cntr = 0;
#ifdef CMW
		while ((status = flock(des, LOCK_EX | LOCK_NB) == -1) &&
			(cntr++ < RETRY_COUNT)) {
			(void) sleep(RETRY_SLEEP);
		}
#else
		while (((status = lockf(des, F_TLOCK, 0)) == -1) &&
			(cntr++ < RETRY_COUNT)) {
			(void) sleep(RETRY_SLEEP);
		}
#endif
		if (status == -1) {
			if (verbose) {
				(void) fprintf(stderr,
			gettext("dmapinfo: Cannot lock %s\n"), filename);
			}
			exit(1);
		}
		/*
		 * Now that we have the device_maps file then lets check
		 * for previous entrys with the same name.  If it already
		 * exists then we will exit with status of 1.
		 */
		if (verbose) {
			(void) fprintf(stderr,
			gettext("dmapinfo: Checking %s for name (%s).\n"),
				filename, dmap.dmap_devname);
		}
		if (getdmapnam(dmap.dmap_devname) != NULL) {
			if (verbose) {
				(void) fprintf(stderr,
			gettext("dmapinfo: Device name (%s) found in %s.\n"),
					dmap.dmap_devname, filename);
			}
			exit(1);
		}
		if (verbose) {
			(void) fprintf(stderr,
		gettext("dmapinfo: Device name (%s) not found in %s.\n"),
				dmap.dmap_devname, filename);
		}
		/*
		 * We now Know name does not exist and now we need to check
		 * to see if any of the devices in the device list are in the
		 * device maps file. If the already exist then we will exit
		 * with a status of 1.
		 */
		nptr = mptr;
		nptr = getdmapdfield(nptr);
		while (nptr) {
			if (verbose) {
				(void) fprintf(stderr,
				    gettext("dmapinfo: "
					"Check %s for device (%s).\n"),
				    filename, nptr);
			}
			if (getdmapdev(nptr) != NULL) {
				if (verbose) {
					(void) fprintf(stderr,
					    gettext("dmapinfo: "
						"Device (%s) found in %s.\n"),
					    nptr, filename);
				}
				exit(1);
			}
			if (verbose) {
				(void) fprintf(stderr,
				    gettext("dmapinfo: "
					"Device (%s) not found in %s.\n"),
				    nptr, filename);
			}
			nptr = getdmapdfield(NULL);
		}
		/*
		 * Good the entry is uniq. So lets find out how long it is
		 * and add it to the end of device maps file in a pretty
		 * way.
		 */
		if (verbose) {
			(void) fprintf(stderr, "dmapinfo: Adding entry to %s\n",
				filename);
			printdmapent(&dmap);
		}
		cntr = strlen(dmap.dmap_devname);
		cntr += strlen(dmap.dmap_devtype);
		cntr += strlen(dmap.dmap_devlist);
		cntr += 15;
		tptr = calloc((unsigned)cntr, sizeof (char));
		if (tptr == NULL) {
			exit(1);
		}
		(void) strcat(tptr, dmap.dmap_devname);
		(void) strcat(tptr, ":\\\n\t");
		(void) strcat(tptr, dmap.dmap_devtype);
		(void) strcat(tptr, ":\\\n\t");
		(void) strcat(tptr, dmap.dmap_devlist);
		(void) strcat(tptr, ":\\\n\t");
		(void) strcat(tptr, "\n");
		cntr = strlen(tptr);
#ifdef CMW
		if (lseek(des, 0L, L_XTND) == -1L) {
			exit(1);
		}
#else
		if (lseek(des, 0L, SEEK_END) == -1L) {
			exit(1);
		}
#endif
		if (write(des, tptr, cntr) == -1) {
			exit(1);
		}
		if (close(des) == -1) {
			exit(1);
		}
		if (verbose) {
			(void) fprintf(stderr, "dmapinfo: Entry added to %s\n",
				filename);
		}
		exit(0);
	}
	/*
	 * Look for devices in device_maps file. If verbose switch is set
	 * then print entry(s) found. If "any" switch  is set then, if any
	 * device is found will result in a exit status of 0. If "any" switch
	 * is not set then, if any device is not will result in a exit status
	 * of 1.
	 */
	if (device) {
		setdmapent();
		while (argc >= 1) {
			if ((dmapp = getdmapdev(*argv)) != NULL) {
				if (verbose) {
					printdmapent(dmapp);
				}
				cntr++;
			} else if (any == 0) {
				enddmapent();
				exit(1);
			}
			argc--;
			argv++;
		}
		enddmapent();
		if (cntr != 0)
			exit(0);
		exit(1);
	}
	/*
	 * Look for names in device_maps file. If verbose switch is set
	 * then print entry(s) found. If "any" switch  is set then, if any
	 * name is found will result in a exit status of 0. If "any" switch
	 * is not set then, if any name is not will result in a exit status
	 * of 1.
	 */
	if (name) {
		setdmapent();
		while (argc >= 1) {
			if ((dmapp = getdmapnam(*argv)) != NULL) {
				if (verbose) {
					printdmapent(dmapp);
				}
				cntr++;
			} else if (any == 0)
				exit(1);
			argc--;
			argv++;
		}
		enddmapent();
		if (cntr != 0)
			exit(0);
		exit(1);
	}
	/*
	 * Read all entrys from device maps file. If verbose flag is set
	 * then all the device maps files are printed.  This is useful for
	 * piping to grep. Also this option used without the verbose option
	 * is useful to check for device maps file and for at least one
	 * entry.  If the device maps file is found and there is one entry
	 * the return status is 0.
	 */
	if (tp) {
		cntr = 0;
		setdmapent();
		while (argc >= 1) {
			while ((dmapp = getdmaptype(*argv)) != 0) {
				cntr++;
				if (verbose) {
					printdmapent(dmapp);
				}
			}
			if ((any == 0) && (cntr == 0)) {
				enddmapent();
				exit(1);
			}
			argc--;
			argv++;
		}
		enddmapent();
		if (cntr == 0)
			exit(1);
		exit(0);
	}
	/*
	 * Read all entrys from device maps file. If verbose flag is set
	 * then all the device maps files are printed.  This is useful for
	 * piping to grep. Also this option used without the verbose option
	 * is useful to check for device maps file and for atleast one
	 * entry.  If the device maps file is found and there is one entry
	 * the return status is 0.
	 */
	cntr = 0;
	setdmapent();
	while ((dmapp = getdmapent()) != 0) {
		cntr++;
		if (verbose) {
			printdmapent(dmapp);
		}
	}
	enddmapent();
	if (cntr == 0)
		exit(1);
	return (0);
}
