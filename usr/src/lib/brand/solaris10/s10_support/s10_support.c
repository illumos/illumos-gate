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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
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
get_ku_patchlist(char *zonepath, char **patchlist)
{
	char		pkginfo[MAXPATHLEN];
	FILE		*fp;
	char		*buf;
	int		err = 0;

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
	char		zonepath[MAXPATHLEN];
	char		sanity_skip[MAXPATHLEN];
	struct stat64	buf;
	boolean_t	is_xpv = B_FALSE;
	char		platform[80];
	char		*xpv_vers = "142910";
	char 		*vers_table[] = {
			    "141444-09",
			    "141445-09"};

	if (zone_get_zonepath(zonename, zonepath, sizeof (zonepath)) != Z_OK)
		s10_err(gettext("error getting zone's path"));

	/*
	 * If the zone was installed to bypass sanity checking for internal
	 * testing purposes, just return success.
	 */
	if (snprintf(sanity_skip, sizeof (sanity_skip), "%s/root/.sanity_skip",
	    zonepath) >= sizeof (sanity_skip))
		s10_err(gettext("error formating file path"));

	if (stat64(sanity_skip, &buf) == 0)
		return (B_TRUE);

	if (get_ku_patchlist(zonepath, &patchlist) != 0 || patchlist == NULL)
		return (B_FALSE);

	/*
	 * Check if we're running on the i86xpv platform.  If so, the zone
	 * needs a different ku patch to work properly.
	 */
	if (sysinfo(SI_PLATFORM, platform, sizeof (platform)) != -1 &&
	    strcmp(platform, "i86xpv") == 0)
		is_xpv = B_TRUE;

	pstr = patchlist;
	while ((p = strtok_r(pstr, " ", &lastp)) != NULL) {
		if (is_xpv) {
			if (strncmp(p, xpv_vers, 6) == 0)
				return (B_TRUE);
		} else {
			if (strcmp(p, vers_table[0]) == 0 ||
			    strcmp(p, vers_table[1]) == 0)
				return (B_TRUE);
		}

		pstr = NULL;
	}

	if (is_xpv)
		s10_err(gettext("the zone must have patch 142910 installed "
		    "when running in a paravirtualized domain"));


	return (B_FALSE);
}

/*
 * Determine which features/behaviors should be emulated and construct a bitmap
 * representing the results.  Associate the bitmap with the zone so that
 * the brand's emulation library will be able to retrieve the bitmap and
 * determine how the zone's process' behaviors should be emulated.
 *
 * This function does not return if an error occurs.
 */
static void
set_zone_emul_bitmap(char *zonename)
{
	char			req_emulation_dir_path[MAXPATHLEN];
	DIR			*req_emulation_dirp;
	struct dirent		*emul_feature_filep;
	char			*filename_endptr;
	s10_emul_bitmap_t	bitmap;
	unsigned int		bit_index;
	zoneid_t		zoneid;

	/*
	 * If the Solaris 10 directory containing emulation feature files
	 * doesn't exist in the zone, then assume that it only needs the
	 * most basic emulation and, therefore, doesn't need a bitmap.
	 */
	if (zone_get_rootpath(zonename, req_emulation_dir_path,
	    sizeof (req_emulation_dir_path)) != Z_OK)
		s10_err(gettext("error getting zone's path"));
	if (strlcat(req_emulation_dir_path, S10_REQ_EMULATION_DIR,
	    sizeof (req_emulation_dir_path)) >= sizeof (req_emulation_dir_path))
		s10_err(gettext("error formatting version path"));
	if ((req_emulation_dirp = opendir(req_emulation_dir_path)) == NULL)
		return;
	bzero(bitmap, sizeof (bitmap));

	/*
	 * Iterate over the contents of the directory and determine which
	 * features the brand should emulate for this zone.
	 */
	while ((emul_feature_filep = readdir(req_emulation_dirp)) != NULL) {
		if (strcmp(emul_feature_filep->d_name, ".") == 0 ||
		    strcmp(emul_feature_filep->d_name, "..") == 0)
			continue;

		/*
		 * Convert the file's name to an unsigned integer.  Ignore
		 * files whose names aren't unsigned integers.
		 */
		errno = 0;
		bit_index = (unsigned int)strtoul(emul_feature_filep->d_name,
		    &filename_endptr, 10);
		if (errno != 0 || *filename_endptr != '\0' ||
		    filename_endptr == emul_feature_filep->d_name)
			continue;

		/*
		 * Determine if the brand can emulate the feature specified
		 * by bit_index.
		 */
		if (bit_index >= S10_NUM_EMUL_FEATURES) {
			/*
			 * The zone requires emulation that the brand can't
			 * provide.  Notify the user by displaying an error
			 * message.
			 */
			s10_err(gettext("The zone's version of Solaris 10 is "
			    "incompatible with the\ncurrent version of the "
			    "solaris10 brand.\nPlease update your Solaris "
			    "system to the latest release."));
		} else {
			/*
			 * Set the feature's flag in the bitmap.
			 */
			bitmap[(bit_index >> 3)] |= (1 << (bit_index & 0x7));
		}
	}

	/*
	 * We're done scanning files.  Set the zone's emulation bitmap.
	 */
	(void) closedir(req_emulation_dirp);
	if ((zoneid = getzoneidbyname(zonename)) < 0)
		s10_err(gettext("unable to get zoneid"));
	if (zone_setattr(zoneid, S10_EMUL_BITMAP, bitmap, sizeof (bitmap)) != 0)
		s10_err(gettext("error setting zone's emulation bitmap"));
}

static int
s10_boot(char *zonename)
{
	if (!have_valid_ku(zonename))
		s10_err(gettext("The installed version of Solaris 10 is "
		    "not supported"));

	set_zone_emul_bitmap(zonename);

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
