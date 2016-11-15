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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * lx_support is a small cli utility used to perform some brand-specific
 * tasks when booting, halting, or verifying a zone.  This utility is not
 * intended to be called by users - it is intended to be invoked by the
 * zones utilities.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stropts.h>
#include <sys/ioccom.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>

#include <libzonecfg.h>
#include <sys/lx_brand.h>

static void lxs_err(char *msg, ...) __NORETURN;
static void usage(void) __NORETURN;

#define	CP_CMD		"/usr/bin/cp"
#define	MOUNT_CMD	"/sbin/mount"

static char *bname = NULL;
static char *zonename = NULL;
static char *zoneroot = NULL;

#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif

static void
lxs_err(char *msg, ...)
{
	char	buf[1024];
	va_list	ap;

	va_start(ap, msg);
	/*LINTED*/
	(void) vsnprintf(buf, sizeof (buf), msg, ap);
	va_end(ap);

	(void) printf("%s error: %s\n", bname, buf);

	exit(1);
	/*NOTREACHED*/
}

/*
 * Cleanup from earlier versions of the code which created a /dev/initctl FIFO.
 */
static void
lxs_remove_initctl()
{
	char		special[MAXPATHLEN];

	if (snprintf(special, sizeof (special), "%s/dev/initctl", zoneroot) >=
	    sizeof (special))
		lxs_err("%s: %s", gettext("Failed to cleanup /dev/initctl"),
		    gettext("zoneroot is too long"));

	(void) unlink(special);
}

/*
 * fsck gets really confused when run inside a zone.  Removing this file
 * prevents it from running
 */
static void
lxs_remove_autofsck()
{
	char	path[MAXPATHLEN];
	int	err;

	if (snprintf(path, MAXPATHLEN, "%s/root/.autofsck", zoneroot) >=
	    MAXPATHLEN)
		lxs_err("%s: %s", gettext("Failed to remove /.autofsck"),
		    gettext("zoneroot is too long"));

	if (unlink(path) < 0) {
		err = errno;
		if (err != ENOENT)
			lxs_err("%s: %s",
			    gettext("Failed to remove /.autofsck"),
			    strerror(err));
	}
}

/*
 * Extract any lx-supported attributes from the zone configuration file.
 */
static void
lxs_getattrs(zone_dochandle_t zdh, char **krelease)
{
	struct zone_attrtab	attrtab;
	int			err;

	/* initialize the attribute iterator */
	if (zonecfg_setattrent(zdh) != Z_OK) {
		zonecfg_fini_handle(zdh);
		lxs_err(gettext("error accessing zone configuration"));
	}

	*krelease = (char *)malloc(LX_KERN_RELEASE_MAX);
	if (*krelease == NULL)
		lxs_err(gettext("out of memory"));

	bzero(*krelease, LX_KERN_RELEASE_MAX);
	while ((err = zonecfg_getattrent(zdh, &attrtab)) == Z_OK) {
		if ((strcmp(attrtab.zone_attr_name, "kernel-version") == 0) &&
		    (zonecfg_get_attr_string(&attrtab, *krelease,
		    LX_KERN_RELEASE_MAX) != Z_OK))
			lxs_err(gettext("invalid type for zone attribute: %s"),
			    attrtab.zone_attr_name);
	}

	if (strlen(*krelease) == 0) {
		free(*krelease);
		*krelease = NULL;
	}

	/* some kind of error while looking up attributes */
	if (err != Z_NO_ENTRY)
		lxs_err(gettext("error accessing zone configuration"));
}

static int
lxs_boot()
{
	zoneid_t	zoneid;
	zone_dochandle_t zdh;
	char		*krelease;

	lxs_remove_initctl();
	lxs_remove_autofsck();

	if ((zdh = zonecfg_init_handle()) == NULL)
		lxs_err(gettext("unable to initialize zone handle"));

	if (zonecfg_get_handle((char *)zonename, zdh) != Z_OK) {
		zonecfg_fini_handle(zdh);
		lxs_err(gettext("unable to load zone configuration"));
	}

	/* Extract any relevant attributes from the config file. */
	lxs_getattrs(zdh, &krelease);
	zonecfg_fini_handle(zdh);

	/*
	 * Let the kernel know whether or not this zone's init process
	 * should be automatically restarted on its death.
	 */
	if ((zoneid = getzoneidbyname(zonename)) < 0)
		lxs_err(gettext("unable to get zoneid"));

	if (krelease != NULL) {
		/* Backward compatability with incomplete version attr */
		if (strcmp(krelease, "2.4") == 0) {
			krelease = "2.4.21";
		} else if (strcmp(krelease, "2.6") == 0) {
			krelease = "2.6.18";
		}

		if (zone_setattr(zoneid, LX_ATTR_KERN_RELEASE, krelease,
		    strlen(krelease)) < 0)
			lxs_err(gettext("unable to set kernel version"));
	}

	return (0);
}

static int
lxs_halt()
{
	return (0);
}

static int
lxs_verify(char *xmlfile)
{
	zone_dochandle_t	handle;
	char			*krelease;
	char			hostidp[HW_HOSTID_LEN];
	zone_iptype_t		iptype;

	if ((handle = zonecfg_init_handle()) == NULL)
		lxs_err(gettext("internal libzonecfg.so.1 error"), 0);

	if (zonecfg_get_xml_handle(xmlfile, handle) != Z_OK) {
		zonecfg_fini_handle(handle);
		lxs_err(gettext("zonecfg provided an invalid XML file"));
	}

	/*
	 * Check to see whether the zone has hostid emulation enabled.
	 */
	if (zonecfg_get_hostid(handle, hostidp, sizeof (hostidp)) == Z_OK) {
		zonecfg_fini_handle(handle);
		lxs_err(gettext("lx zones do not support hostid emulation"));
	}

	/*
	 * Only exclusive stack is supported.
	 */
	if (zonecfg_get_iptype(handle, &iptype) != Z_OK ||
	    iptype != ZS_EXCLUSIVE) {
		zonecfg_fini_handle(handle);
		lxs_err(gettext("lx zones do not support shared IP stacks"));
	}

	/* Extract any relevant attributes from the config file. */
	lxs_getattrs(handle, &krelease);
	zonecfg_fini_handle(handle);

	if (krelease) {
		char *pdot, *ep;
		long major_ver;

		pdot = strchr(krelease, '.');
		if (pdot != NULL)
			*pdot = '\0';
		errno = 0;
		major_ver = strtol(krelease, &ep, 10);
		if (major_ver < 2 || errno != 0 || *ep != '\0')
			lxs_err(gettext("invalid value for zone attribute: %s"),
			    "kernel-version");
		if (pdot != NULL)
			*pdot = '.';

	}
	return (0);
}

static void
usage()
{

	(void) fprintf(stderr,
	    gettext("usage:\t%s boot <zoneroot> <zonename>\n"), bname);
	(void) fprintf(stderr,
	    gettext("      \t%s halt <zoneroot> <zonename>\n"), bname);
	(void) fprintf(stderr,
	    gettext("      \t%s verify <xml file>\n\n"), bname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	bname = basename(argv[0]);

	if (argc < 3)
		usage();

	if (strcmp(argv[1], "boot") == 0) {
		if (argc != 4)
			lxs_err(gettext("usage: %s %s <zoneroot> <zonename>"),
			    bname, argv[1]);
		zoneroot = argv[2];
		zonename = argv[3];
		return (lxs_boot());
	}

	if (strcmp(argv[1], "halt") == 0) {
		if (argc != 4)
			lxs_err(gettext("usage: %s %s <zoneroot> <zonename>"),
			    bname, argv[1]);
		zoneroot = argv[2];
		zonename = argv[3];
		return (lxs_halt());
	}

	if (strcmp(argv[1], "verify") == 0) {
		if (argc != 3)
			lxs_err(gettext("usage: %s verify <xml file>"),
			    bname);
		return (lxs_verify(argv[2]));
	}

	usage();
	/*NOTREACHED*/
}
