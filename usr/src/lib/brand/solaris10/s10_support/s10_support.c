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

/*
 * s10_support is a small cli utility used to perform some brand-specific
 * tasks when verifying a zone.  This utility is not intended to be called
 * by users - it is intended to be invoked by the zones utilities.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <s10_brand.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stropts.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/varargs.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <dirent.h>
#include <sys/systeminfo.h>

#include <libzonecfg.h>

static void s10_err(char *msg, ...) __NORETURN;
static void usage(void) __NORETURN;

/*
 * XXX This is a temporary flag for the initial release to enable the
 * use of features which are not yet tested or fully implemented.
 */
static boolean_t override = B_FALSE;

static char *bname = NULL;

#define	PKGINFO_RD_LEN	128
#define	PATCHLIST	"PATCHLIST="

#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif

/*PRINTFLIKE1*/
static void
s10_err(char *msg, ...)
{
	char	buf[1024];
	va_list	ap;

	va_start(ap, msg);
	(void) vsnprintf(buf, sizeof (buf), msg, ap);
	va_end(ap);

	/* This needs go to stdout so the msgs show up through zoneadm. */
	(void) printf("Error: %s\n", buf);

	exit(1);
	/*NOTREACHED*/
}

static int
s10_verify(char *xmlfile)
{
	zone_dochandle_t	handle;
	struct zone_fstab	fstab;
	struct zone_devtab	devtab;
	zone_iptype_t		iptype;
	struct zone_dstab	dstab;

	if ((handle = zonecfg_init_handle()) == NULL)
		s10_err(gettext("internal libzonecfg.so.1 error"), 0);

	if (zonecfg_get_xml_handle(xmlfile, handle) != Z_OK) {
		zonecfg_fini_handle(handle);
		s10_err(gettext("zonecfg provided an invalid XML file"));
	}

	/*
	 * Check to see whether the zone has any inherit-pkg-dirs
	 * configured.
	 */
	if (zonecfg_setipdent(handle) != Z_OK) {
		zonecfg_fini_handle(handle);
		s10_err(gettext("zonecfg provided an invalid XML file"));
	}
	if (zonecfg_getipdent(handle, &fstab) == Z_OK) {
		zonecfg_fini_handle(handle);
		s10_err(gettext("solaris10 zones do not support "
		    "inherit-pkg-dirs"));
	}
	(void) zonecfg_endipdent(handle);

	/*
	 * Check to see whether the zone has any unsupported devices
	 * configured.
	 *
	 * The audio framework has changed in Solaris Next as compared to
	 * S10.  Data indicates the less than 1/10 of 1 percent of zones
	 * are using /dev/sound.  Given the low usage vs. the effort to
	 * provide emulation, /dev/sound is currently disallowed.  We can
	 * revisit this if there is enough demand.
	 */
	if (zonecfg_setdevent(handle) != Z_OK) {
		zonecfg_fini_handle(handle);
		s10_err(gettext("zonecfg provided an invalid XML file"));
	}
	if (zonecfg_getdevent(handle, &devtab) == Z_OK) {
		if (strncmp(devtab.zone_dev_match, "/dev/sound", 10) == 0 &&
		    !override) {
			zonecfg_fini_handle(handle);
			s10_err(gettext("solaris10 zones do not currently "
			    "support /dev/sound"));
		}
	}
	(void) zonecfg_enddevent(handle);

	/*
	 * Check to see whether the zone has any experimental features
	 * configured.
	 */
	if (zonecfg_get_iptype(handle, &iptype) == Z_OK &&
	    iptype == ZS_EXCLUSIVE && !override) {
		zonecfg_fini_handle(handle);
		s10_err(gettext("solaris10 zones do not currently support "
		    "exclusive ip-type stacks"));
	}

	if (zonecfg_setdsent(handle) != Z_OK) {
		zonecfg_fini_handle(handle);
		s10_err(gettext("zonecfg provided an invalid XML file"));
	}
	if (zonecfg_getdsent(handle, &dstab) == Z_OK && !override) {
		zonecfg_fini_handle(handle);
		s10_err(gettext("solaris10 zones do not currently support "
		    "delegated datasets"));
	}
	(void) zonecfg_enddsent(handle);

	zonecfg_fini_handle(handle);
	return (0);
}

/*
 * Read an entry from a pkginfo file.  Some of these lines can
 * either be arbitrarily long or be continued by a backslash at the end of
 * the line.  This function coalesces lines that are longer than the read
 * buffer, and lines that are continued, into one buffer which is returned.
 * The caller must free this memory.  NULL is returned when we hit EOF or
 * if we run out of memory (errno is set to ENOMEM).
 */
static char *
read_pkg_data(FILE *fp)
{
	char *start;
	char *inp;
	char *p;
	int char_cnt = 0;

	errno = 0;
	if ((start = (char *)malloc(PKGINFO_RD_LEN)) == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	inp = start;
	while ((p = fgets(inp, PKGINFO_RD_LEN, fp)) != NULL) {
		int len;

		len = strlen(inp);
		if (inp[len - 1] == '\n' &&
		    (len == 1 || inp[len - 2] != '\\')) {
			char_cnt = len;
			break;
		}

		if (inp[len - 1] == '\n' && inp[len - 2] == '\\')
			char_cnt += len - 2;
		else
			char_cnt += PKGINFO_RD_LEN - 1;

		if ((p = realloc(start, char_cnt + PKGINFO_RD_LEN)) == NULL) {
			errno = ENOMEM;
			break;
		}

		start = p;
		inp = start + char_cnt;
	}

	if (errno == ENOMEM || (p == NULL && char_cnt == 0)) {
		free(start);
		start = NULL;
	}

	return (start);
}

/*
 * Read the SUNWcakr pkginfo file and get the PATCHLIST for the pkg.
 */
static int
get_ku_patchlist(char *zonename, char **patchlist)
{
	char		zonepath[MAXPATHLEN];
	char		pkginfo[MAXPATHLEN];
	FILE		*fp;
	char		*buf;
	int		err = 0;

	if (zone_get_zonepath(zonename, zonepath, sizeof (zonepath)) != Z_OK)
		s10_err(gettext("error getting zone's path"));

	if (snprintf(pkginfo, sizeof (pkginfo),
	    "%s/root/var/sadm/pkg/SUNWcakr/pkginfo", zonepath)
	    >= sizeof (pkginfo))
		s10_err(gettext("error formating pkg path"));

	if ((fp = fopen(pkginfo, "r")) == NULL)
		return (errno);

	while ((buf = read_pkg_data(fp)) != NULL) {
		if (strncmp(buf, PATCHLIST, sizeof (PATCHLIST) - 1) == 0) {
			int len;

			/* remove trailing newline */
			len = strlen(buf);
			buf[len - 1] = '\0';

			if ((*patchlist =
			    strdup(buf + sizeof (PATCHLIST) - 1)) == NULL)
				err = ENOMEM;

			free(buf);
			break;
		}

		free(buf);
	}
	(void) fclose(fp);

	return (err);
}

/*
 * Verify that we have the minimum KU needed.
 * Note that KU patches are accumulative so future KUs will still deliver
 * 141444 or 141445.
 */
static boolean_t
have_valid_ku(char *zonename)
{
	char		*p;
	char		*lastp;
	char		*pstr;
	char		*patchlist = NULL;
	int		i;
	char 		*vers_table[] = {
			    "141444-09",
			    "141445-09",
			    NULL};

	if (get_ku_patchlist(zonename, &patchlist) != 0 || patchlist == NULL)
		return (B_FALSE);

	pstr = patchlist;
	while ((p = strtok_r(pstr, " ", &lastp)) != NULL) {
		for (i = 0; vers_table[i] != NULL; i++)
			if (strcmp(p, vers_table[i]) == 0)
				return (B_TRUE);

		pstr = NULL;
	}

	return (B_FALSE);
}

/*
 * Get the emulation version from the /usr/lib/brand/solaris10/version file
 * in either the global zone or the non-global zone.
 */
static int
get_emul_version_number(char *verspath)
{
	int	vers = 0;
	FILE	*fp;
	char	buf[LINE_MAX];

	/* If the file doesn't exist, assume version 0 */
	if ((fp = fopen(verspath, "r")) == NULL)
		return (vers);

	while (fgets(buf, sizeof (buf), fp) != NULL) {
		if (buf[0] == '#')
			continue;

		errno = 0;
		vers = strtol(buf, (char **)NULL, 10);
		if (errno != 0) {
			(void) fclose(fp);
			s10_err(gettext("error reading minimum version"));
		}
	}

	(void) fclose(fp);

	return (vers);
}

/*
 * Get the current emulation version that is implemented.
 */
static int
get_current_emul_version()
{
	return (get_emul_version_number("/usr/lib/brand/solaris10/version"));
}

/*
 * Get the emulation version that the S10 image requires.  This
 * reads the optional /usr/lib/brand/solaris10/version file that might
 * exist on Solaris 10.  That file specifies the minimal solaris10 brand
 * emulation version that the specific release of S10 requires.  If no
 * minimal version is specified, the initial emulation remains compatible.
 *
 * If a new KU patch is created which needs different handling by the
 * emulation, then the S10 /usr/lib/brand/solaris10/version file should be
 * updated to specify a new version.
 */
static int
get_image_emul_rqd_version(char *zonename)
{
	char	zonepath[MAXPATHLEN];
	char	verspath[MAXPATHLEN];

	if (zone_get_zonepath(zonename, zonepath, sizeof (zonepath)) != Z_OK)
		s10_err(gettext("error getting zone's path"));

	if (snprintf(verspath, sizeof (verspath),
	    "%s/root/usr/lib/brand/solaris10/version",
	    zonepath) >= sizeof (verspath))
		s10_err(gettext("error formating version path"));

	return (get_emul_version_number(verspath));
}

static void
fail_xvm()
{
	char buf[80];

	if (sysinfo(SI_PLATFORM, buf, sizeof (buf)) != -1 &&
	    strcmp(buf, "i86xpv") == 0 && !override)
		s10_err(gettext("running the solaris10 brand "
		    "in a paravirtualized\ndomain is currently not supported"));
}

static int
s10_boot(char *zonename)
{
	zoneid_t zoneid;
	int emul_vers;
	int rqd_emul_vers;

	if (!have_valid_ku(zonename))
		s10_err(gettext("The installed version of Solaris 10 is "
		    "not supported"));

	emul_vers = get_current_emul_version();
	rqd_emul_vers = get_image_emul_rqd_version(zonename);

	if (rqd_emul_vers > emul_vers)
		s10_err(gettext("The zone's version of Solaris 10 is "
		    "incompatible with the current version of the solaris10 "
		    "brand."));

	if ((zoneid = getzoneidbyname(zonename)) < 0)
		s10_err(gettext("unable to get zoneid"));

	if (zone_setattr(zoneid, S10_EMUL_VERSION_NUM, &rqd_emul_vers,
	    sizeof (int)) == -1)
		s10_err(gettext("error setting zone's emulation version "
		    "property"));

	fail_xvm();

	return (0);
}

static void
usage()
{
	(void) fprintf(stderr, gettext(
	    "usage:\t%s verify <xml file>\n"
	    "\t%s boot\n"),
	    bname, bname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	bname = basename(argv[0]);

	if (argc != 3)
		usage();

	/*
	 * XXX This is a temporary env variable for the initial release to
	 * enable the use of features which are not yet tested or fully
	 * implemented.
	 */
	if (getenv("S10BRAND_TEST") != NULL)
		override = B_TRUE;

	if (strcmp(argv[1], "verify") == 0)
		return (s10_verify(argv[2]));

	if (strcmp(argv[1], "boot") == 0)
		return (s10_boot(argv[2]));

	usage();
	/*NOTREACHED*/
}
