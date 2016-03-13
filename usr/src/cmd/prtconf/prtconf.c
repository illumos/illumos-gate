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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <sys/systeminfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "prtconf.h"

struct prt_opts	opts;
struct prt_dbg	dbg;
static char	new_path[MAXPATHLEN];

#define	INDENT_LENGTH	4

#ifdef	__x86
static const char *usage = "%s [ -V | -x | -abcdvpPD ] [ <device_path > ]\n";
#else
static const char *usage =
	"%s [ -F | -V | -x | -abcdvpPD ][ <device_path > ]\n";
#endif	/* __x86 */

static void
setpname(const char *name)
{
	char *p;

	if (name == NULL)
		opts.o_progname = "prtconf";
	else if (p = strrchr(name, '/'))
		opts.o_progname = (const char *) p + 1;
	else
		opts.o_progname = name;
}

/*PRINTFLIKE1*/
void
dprintf(const char *fmt, ...)
{
	if (dbg.d_debug) {
		va_list ap;
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
}

void
indent_to_level(int ilev)
{
	(void) printf("%*s", INDENT_LENGTH * ilev, "");
}

static void
cleanup_path(const char *input_path, char *path)
{
	char	*ptr, *ptr2;
	size_t	len;

	if ((input_path == NULL) || (path == NULL))
		return;

	(void) strcpy(path, input_path);

	/*LINTED*/
	while (1) {
		len = strlen(path);
		if (len == 0)
			break;

		/* change substring "//" into "/" */
		if (ptr = strstr(path, "//")) {
			len = strlen(ptr + 1);
			(void) memmove(ptr, ptr + 1, len + 1);
			continue;
		}
		/* change substring "/./" into "/" */
		if (ptr = strstr(path, "/./")) {
			len = strlen(ptr + 2);
			(void) memmove(ptr, ptr + 2, len + 1);
			continue;
		}

		/* change substring "/<foo>/../" into "/" */
		if (ptr = strstr(path, "/../")) {
			len = strlen(ptr + 3);
			*ptr = '\0';
			ptr2 = strrchr(path, (int)'/');
			if (ptr2 == NULL) {
				/* path had a leading "/../" */
				ptr2 = path;
			}
			(void) memmove(ptr2, ptr + 3, len + 1);
			continue;
		}

		/* change trailing "/<foo>/.." into "/" */
		if ((len >= 3) &&
		    (path[len - 3] == '/') &&
		    (path[len - 2] == '.') &&
		    (path[len - 1] == '.')) {
			path[len - 3] = '\0';
			ptr2 = strrchr(path, (int)'/');
			if (ptr2 != NULL) {
				ptr2[1] = '\0';
			} else {
				/* path was "/.." */
				path[0] = '/';
				path[1] = '\0';
			}
			continue;
		}

		/* change trailing "/." into "/" */
		if ((len >= 2) &&
		    (path[len - 2] == '/') &&
		    (path[len - 1] == '.')) {
			path[len - 1] = '\0';
			continue;
		}

		/* remove trailing "/" unless it's the root */
		if ((len > 1) && (path[len - 1] == '/')) {
			path[len - 1] = '\0';
			continue;
		}

		break;
	}
}


/*
 * debug version has two more flags:
 *	-L force load driver
 *	-M: print per driver list
 */

#ifdef	DEBUG
static const char *optstring = "abcdDvVxpPFf:M:dLuC";
#else
static const char *optstring = "abcdDvVxpPFf:uC";
#endif	/* DEBUG */

int
main(int argc, char *argv[])
{
	long pagesize, npages;
	int c, ret;
	char hw_provider[SYS_NMLN];

	setpname(argv[0]);
	opts.o_promdev = "/dev/openprom";

	while ((c = getopt(argc, argv, optstring)) != -1)  {
		switch (c)  {
		case 'a':
			++opts.o_ancestors;
			break;
		case 'b':
			++opts.o_productinfo;
			break;
		case 'c':
			++opts.o_children;
			break;
		case 'd':
			++opts.o_pciid;
			break;
		case 'D':
			++opts.o_drv_name;
			break;
		case 'v':
			++opts.o_verbose;
			break;
		case 'p':
			++opts.o_prominfo;
			break;
		case 'f':
			opts.o_promdev = optarg;
			break;
		case 'V':
			++opts.o_promversion;
			break;
		case 'x':
			++opts.o_prom_ready64;
			break;
		case 'F':
			++opts.o_fbname;
			++opts.o_noheader;
			break;
		case 'P':
			++opts.o_pseudodevs;
			break;
		case 'C':
			++opts.o_forcecache;
			break;
#ifdef	DEBUG
		case 'M':
			dbg.d_drivername = optarg;
			++dbg.d_bydriver;
			break;
		case 'L':
			++dbg.d_forceload;
			break;
#endif	/* DEBUG */

		default:
			(void) fprintf(stderr, usage, opts.o_progname);
			return (1);
		}
	}

	(void) uname(&opts.o_uts);

	if (opts.o_fbname)
		return (do_fbname());

	if (opts.o_promversion)
		return (do_promversion());

	if (opts.o_prom_ready64)
		return (do_prom_version64());

	if (opts.o_productinfo)
		return (do_productinfo());

	opts.o_devices_path = NULL;
	opts.o_devt = DDI_DEV_T_NONE;
	opts.o_target = 0;
	if (optind < argc) {
		struct stat	sinfo;
		char		*path = argv[optind];
		int		error;

		if (opts.o_prominfo) {
			/* PROM tree cannot be used with path */
			(void) fprintf(stderr, "%s: path and -p option are "
			    "mutually exclusive\n", opts.o_progname);
			return (1);
		}

		if (strlen(path) >= MAXPATHLEN) {
			(void) fprintf(stderr, "%s: "
			    "path specified is too long\n", opts.o_progname);
			return (1);
		}

		if (error = stat(path, &sinfo)) {

			/* an invalid path was specified */
			(void) fprintf(stderr, "%s: invalid path specified\n",
			    opts.o_progname);
			return (1);

		} else if (((sinfo.st_mode & S_IFMT) == S_IFCHR) ||
		    ((sinfo.st_mode & S_IFMT) == S_IFBLK)) {

			opts.o_devt = sinfo.st_rdev;
			error = 0;

		} else if ((sinfo.st_mode & S_IFMT) == S_IFDIR) {
			size_t	len, plen;

			/* clean up the path */
			cleanup_path(path, new_path);

			len = strlen(new_path);
			plen = strlen("/devices");
			if (len < plen) {
				/* This is not a valid /devices path */
				error = 1;
			} else if ((len == plen) &&
			    (strcmp(new_path, "/devices") == 0)) {
				/* /devices is the root nexus */
				opts.o_devices_path = "/";
				error = 0;
			} else if (strncmp(new_path, "/devices/", plen + 1)) {
				/* This is not a valid /devices path */
				error = 1;
			} else {
				/* a /devices/ path was specified */
				opts.o_devices_path = new_path + plen;
				error = 0;
			}

		} else {
			/* an invalid device path was specified */
			error = 1;
		}

		if (error) {
			(void) fprintf(stderr, "%s: "
			    "invalid device path specified\n",
			    opts.o_progname);
			return (1);
		}

		opts.o_target = 1;
	}

	if ((opts.o_ancestors || opts.o_children) && (!opts.o_target)) {
		(void) fprintf(stderr, "%s: options require a device path\n",
		    opts.o_progname);
		return (1);
	}

	if (opts.o_target) {
		prtconf_devinfo();
		return (0);
	}

	ret = sysinfo(SI_HW_PROVIDER, hw_provider, sizeof (hw_provider));
	/*
	 * If 0 bytes are returned (the system returns '1', for the \0),
	 * we're probably on x86, default to "Unknown Hardware Vendor".
	 */
	if (ret <= 1) {
		(void) strncpy(hw_provider, "Unknown Hardware Vendor",
		    sizeof (hw_provider));
	}
	(void) printf("System Configuration:  %s  %s\n", hw_provider,
	    opts.o_uts.machine);

	pagesize = sysconf(_SC_PAGESIZE);
	npages = sysconf(_SC_PHYS_PAGES);
	(void) printf("Memory size: ");
	if (pagesize == -1 || npages == -1)
		(void) printf("unable to determine\n");
	else {
		const int64_t kbyte = 1024;
		const int64_t mbyte = 1024 * 1024;
		int64_t ii = (int64_t)pagesize * npages;

		if (ii >= mbyte)
			(void) printf("%ld Megabytes\n",
			    (long)((ii+mbyte-1) / mbyte));
		else
			(void) printf("%ld Kilobytes\n",
			    (long)((ii+kbyte-1) / kbyte));
	}

	if (opts.o_prominfo) {
		(void) printf("System Peripherals (PROM Nodes):\n\n");
		if (do_prominfo() == 0)
			return (0);
		(void) fprintf(stderr, "%s: Defaulting to non-PROM mode...\n",
		    opts.o_progname);
	}

	(void) printf("System Peripherals (Software Nodes):\n\n");

	(void) prtconf_devinfo();

	return (0);
}
