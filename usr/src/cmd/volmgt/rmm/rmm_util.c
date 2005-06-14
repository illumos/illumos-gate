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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	DEBUG	1

#include	<stdio.h>
#include	<dlfcn.h>
#include	<errno.h>
#include	<string.h>
#include	<stdarg.h>
#include	<fcntl.h>
#include	<rmmount.h>
#include	<libintl.h>
#include	<stdlib.h>
#include	<limits.h>
#include	<string.h>
#include	<ctype.h>
#include	<unistd.h>
#include	<sys/types.h>
#include	<rpc/types.h>
#include	<sys/param.h>
#include	<sys/stat.h>
#include	<sys/cdio.h>
#include	<sys/mnttab.h>
#include	"rmm_int.h"


/*
 * file pointer for mnttab
 */
static FILE	*mnttab_fp = NULL;


/*
 * Load a dso named "name" into our address space, and return a pointer
 * to the function named "funcname"
 */
void *
dso_load(char *name, char *funcname, int vers)
{
	char		namebuf[MAXNAMELEN+1];
	void		*dso_handle = NULL;
	void		*initfunc = NULL;
	struct stat	sb;


	/*
	 * Look for the name with the correct version in various places.
	 * Algorithm:  	/usr/lib/rmmount/name.version
	 *		./name.version
	 *		/usr/lib/name		(warning)
	 *		./name			(warning)
	 */
	(void) sprintf(namebuf, "%s/%s.%d", rmm_dsodir, name, vers);
	if (stat(namebuf, &sb) < 0) {

		(void) sprintf(namebuf, "%s.%d", name, vers);
		if (stat(namebuf, &sb) < 0) {

			(void) sprintf(namebuf, "%s/%s", rmm_dsodir, name);
			if (stat(namebuf, &sb) < 0) {

				(void) sprintf(namebuf, "%s", name);
				if (stat(namebuf, &sb) < 0) {

					dprintf(
					    "dso_load: %s/%s.%d not found\n",
					    rmm_dsodir, name, vers);
					return (FALSE);
				}
			}
			dprintf("trying unversioned dso %s (want ver %d)\n",
			    namebuf, vers);
		}
	}

	/*
	 * decided on a name, now on to the real work.
	 */
	if ((dso_handle = dlopen(namebuf, RTLD_LAZY)) == NULL) {
		dprintf("db_dlopen: %s in %s\n", dlerror(), namebuf);
		return (FALSE);
	}

	if ((initfunc = dlsym(dso_handle, funcname)) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s(%ld) warning: dso_load on \"%s\": %s\n"),
		    prog_name, prog_pid, namebuf, dlerror());
	}

	return (initfunc);
}


void
makeargv(int *ac, char **av, char *buf)
{
	char		*s;
	bool_t		getit = TRUE;
	bool_t		setnull = FALSE;
	char		**oav = av;
	bool_t		quote = FALSE;


	*ac = 0;

	for (s = buf; *s; s++) {

		if (*s == '"') {
			if (quote) {
				quote = FALSE;
			} else {
				quote = TRUE;
			}
		}

		if (setnull) {
			s[-1] = NULL;
			setnull = FALSE;
		}

		if (*s == '\n') {
			*s = NULL;
		}

		if (!isspace(*s) && getit) {
			*av++ = s;
			(*ac)++;
			getit = FALSE;
		} else if (isspace(*s) && !quote) {
			getit = TRUE;
			setnull = TRUE;
		}

		if (*ac > MAX_ARGC) {
			break;
		}
	}

	oav[*ac] = NULL;
}


/*
 * Go through the av strings and remove any quotes.
 * This really doesn't fix any extremely general case.  It's intended
 * to just take care of an argv that looks like:
 * "this is a crock"
 * and turn it into:
 * this is a crock
 */
void
quote_clean(int ac, char **av)
{
	int	i;
	int	j;
	int	k;
	char	*s;


	for (i = 0; i < ac; i++) {

		if (*av[i] == '"') {

			s = strdup(av[i]);

			(void) memset(av[i], 0, strlen(av[i]));

			for (j = 0, k = 0; s[k]; k++) {
				if (s[k] == '"') {
					continue;
				}
				av[i][j++] = s[k];
			}
			free(s);
		}
	}
}


/*
 * swiped from mkdir.c
 */
int
makepath(char *dir, mode_t mode)
{
	int		err;
	char		*slash;


	if ((mkdir(dir, mode) == 0) || (errno == EEXIST)) {
		return (0);
	}
	if (errno != ENOENT) {
		return (-1);
	}
	if ((slash = strrchr(dir, '/')) == NULL) {
		return (-1);
	}
	*slash = NULLC;
	err = makepath(dir, mode);
	*slash++ = '/';

	if (err || (*slash == NULLC)) {
		return (err);
	}

	return (mkdir(dir, mode));
}


void
dprintf(const char *fmt, ...)
{

	va_list		ap;
	const char	*p;
	char		msg[BUFSIZ];
	extern char	*sys_errlist[];
	char		*errmsg = sys_errlist[errno];
	char		*s;



	if (rmm_debug == 0) {
		return;
	}

	(void) memset(msg, 0, BUFSIZ);

	/* scan for %m and replace with errno msg */
	s = &msg[strlen(msg)];
	p = fmt;

	while (*p != NULLC) {
		if ((*p == '%') && (*(p+1) == 'm')) {
			(void) strcat(s, errmsg);
			p += 2;
			s += strlen(errmsg);
			continue;
		}
		*s++ = *p++;
	}
	*s = NULLC;	/* don't forget the null byte */

	/* write off to log file */

	va_start(ap, fmt);
	vfprintf(stderr, msg, ap);
	va_end(ap);
}


/*
 * Take a path and return the character device.  The getfullrawname
 * function only works with dsk and rdsk names.  I also do the
 * irritating floppy name.  Unlike getfullrawname, we return
 * NULL if we can't find the right stuff.
 */
char *
rawpath(char *n)
{
	extern char	*getfullrawname(char *);
	char		*rval;
	char		namebuf[PATH_MAX];
	char		*s;


	if ((rval = getfullrawname(n)) != NULL) {
		if (*rval != NULLC) {
			return (rval);
		}
	}

	if (rval != NULL) {
		free(rval);
	}

	/* ok, so we either have a bad device or a floppy. */

	/* the fd# form */
	if ((s = strstr(n, "/fd")) != NULL) {
		s++;	/* point at 'f' */
		*s = NULLC;
		(void) strcpy(namebuf, n);
		*s = 'f';
		(void) strcat(namebuf, "r");
		(void) strcat(namebuf, s);
		return (strdup(namebuf));
	}

	/* the diskette form */
	if ((s = strstr(n, "/diskette")) != NULL) {
		s++;	/* point at 'd' */
		*s = NULLC;
		strcpy(namebuf, n);
		*s = 'd';
		strcat(namebuf, "r");
		strcat(namebuf, s);
		return (strdup(namebuf));
	}

	/* no rawpath found! */
	return (strdup(""));
}


/*
 * audio_only: return TRUE iff CD-ROM has only audio on it
 *
 * note: it's better to return FALSE even if we have an audio-only CD-ROM
 * than it is to return TRUE incorrectly, since later code can handle the
 * latter error case more easily
 *
 * algorithm:
 *
 *	if no raw path then
 *		return FALSE
 *
 *	if open of raw path fails then
 *		return FALSE
 *
 *	if read of TOC HEADER fails then
 * try_leadout:
 *		// try to read just the LEADOUT track
 *		if read of TOC ENTRY for LEADOUT track fails then
 *			return FALSE
 *		if CDROM_DATA_TRACK flag set in cdte_ctrl field then
 *			return FALSE
 *		else
 *			return TRUE
 *
 *	// assume always at least one regular (i.e. non-LEADOUT) track
 *	for each entry listed in the TOC HEADER do
 *		if read of TOC ENTRY for this track fails then
 *			goto try_leadout
 *		if CDROM_DATA_TRACK flag set in cdte_ctrl field then
 *			return FALSE
 *
 *	// none of the tracks has the CDROM_DATA_TRACK flag set
 *	return TRUE
 */
int
audio_only(struct action_arg *aa)
{
	struct cdrom_tochdr	th;		/* OTC header */
	struct cdrom_tocentry	te;
	int			fd;
	int			res = FALSE;	/* to be returned */
	int			i;		/* track index */



	if (aa->aa_rawpath == NULL) {
		return (FALSE);
	}

	if ((fd = open(aa->aa_rawpath, O_RDONLY)) < 0) {
		dprintf("%s; %m\n", aa->aa_rawpath);
		goto dun;
	}

	/* try to read the TOC Header (may fail on some drive types) */
	if (ioctl(fd, CDROMREADTOCHDR, &th) < 0) {
		dprintf("audio_only: CDREADTOCHDR on \"%s\"; %m\n",
		    aa->aa_rawpath);
try_leadout:
		/* look at LEADOUT track to see if we have data or music */
		te.cdte_format = CDROM_MSF;
		te.cdte_track = (unsigned char)CDROM_LEADOUT;
		if (ioctl(fd, CDROMREADTOCENTRY, &te) < 0) {
			/* return FALSE and let caller figure it out */
			dprintf(
		"audio_only: CDROMREADTOCENTRY on LEADOUT for \"%s\"; %m\n",
			    aa->aa_rawpath);
			goto dun;
		}
		if (!(te.cdte_ctrl & CDROM_DATA_TRACK)) {
			/*
			 * a read of the TOC header or a TOC entry failed, but
			 * the LEADOUT track indicates audio, so
			 * *guess* "audio only"
			 */
			res = TRUE;
		}
		goto dun;
	}

	/* assume non-audio-only if start track > end track */
	if (th.cdth_trk0 > th.cdth_trk1) {
		goto dun;
	}

	/* look through tracks -- any non-music track -> NOT audioonly */
	te.cdte_format = CDROM_MSF;
	for (i = (int)th.cdth_trk0; i < (int)th.cdth_trk1+1; i++) {
		te.cdte_track = (unsigned char)i;
		if (ioctl(fd, CDROMREADTOCENTRY, &te) < 0) {
			dprintf(
		"audio_only: CDREADTOCENTRY for track %d on \"%s\"; %m\n",
			    i, aa->aa_rawpath);
			goto try_leadout;
		}
		if (te.cdte_ctrl & CDROM_DATA_TRACK) {
			goto dun;
		}
	}

	/* all tracks were non-data => music only */
	res = TRUE;

dun:
	dprintf("DEBUG: audio_only() returning %s for \"%s\"\n",
	    res ? "TRUE" : "FALSE", aa->aa_rawpath);
	return (res);
}


/*
 * This is very nasty business.  We must tell share if the file system
 * is to be exported read-only.  We rewack the option string if someone
 * put in 'rw'.  The real case we fix here is (for example) a floppy
 * that is mounted read-only because it's write protected.  It also
 * makes the cdrom thing easier too because you don't have to specify
 * '-o ro' in your share command, it'll just figure it out for you.
 */
void
share_readonly(struct mount_args *ma)
{
	char	*s, *p;
	int	ac;
	char	*av[MAX_ARGC];
	char	*fopt = NULL;
	char	*oopt = NULL;
	char	*dopt = NULL;
	int	c;
	char	buf[BUFSIZ];


	/*
	 * If he didn't give us any flags...
	 */
	if (*ma->ma_options == NULLC) {
		free(ma->ma_options);
		ma->ma_options = strdup("-o ro");
		return;
	}

	s = strdup(ma->ma_options);

	makeargv(&ac, av, s);

	optind = 0;	/* reset our getopt state */
	while ((c = getopt(ac, av, "F:d:o:")) != EOF) {
		switch (c) {
		case 'F':
			fopt = optarg;
			break;
		case 'd':
			dopt = optarg;
			break;
		case 'o':
			oopt = optarg;
			break;
		}
	}

	if (oopt != NULL) {
		/*
		 * Here's where we can really make a mess of things.
		 * We want to convert any 'rw' strings in the oopt
		 * into 'ro' strings.  The problem is differentiating
		 * between the 'rw' option and 'rw in a name (like
		 * a domain name).  So, we say 'rw' needs to be
		 * followed by a : or an = or a null.  I hope this
		 * works or whoever names their machine "cankerworm"
		 * will be upset with me.
		 */
		for (p = oopt; *p; p++) {
			if (*p == 'r' && *(p+1) == 'w') {
				if ((*(p+2) == ':') ||
				    (*(p+2) == '=') ||
				    (*(p+2) == NULLC)) {
					*(p+1) = 'o';
				}
			}
		}
	} else {
		oopt = "ro";
	}

	/* build the new thing */
	buf[0] = NULLC;

	if (fopt != NULL) {
		(void) strcat(buf, "-F ");
		(void) strcat(buf, fopt);
		(void) strcat(buf, " ");
	}
	if (dopt != NULL) {
		(void) strcat(buf, "-d ");
		(void) strcat(buf, dopt);
		(void) strcat(buf, " ");
	}
	if (oopt != NULL) {
		(void) strcat(buf, "-o ");
		(void) strcat(buf, oopt);
		(void) strcat(buf, " ");
	}
	/* whew! */
	free(ma->ma_options);
	ma->ma_options = strdup(buf);
	free(s);
}


/*
 * Convert a shell regular expression to a regex regular
 * expression.  Thanks to sam @ RMTC.
 */
char *
sh_to_regex(char *s)
{
	char	vi[MAXNAMELEN];
	char	*c;


	vi[0] = '^';				/* anchor search at start */

	for (c = vi+1; *s; ++c, ++s) {
		if (*s == '\\') {
			*(c++) = *(s++);
		} else if (*s == '*') {
			*(c++) = '.';
		} else if ((*s == '.') || (*s == '$') || (*s == '^')) {
			*(c++) = '\\';
		} else if (*s == '?') {
			*s = '.';
		}
		*c = *s;
		if (*s == NULLC) {
			++c;
			break;
		}
	}

	*(c++) = '$';				/* anchar search at end */
	*c = NULLC;

	return (strdup(vi));
}


/*
 * if mnttab not open, open it, else reset to its start
 */
static bool_t
reset_mnttab()
{
	if (mnttab_fp == NULL) {
		if ((mnttab_fp = fopen(MNTTAB, "r")) == NULL) {
			dprintf("%s(%ld) open of %s; %m\n", prog_name,
			    prog_pid, MNTTAB);
			return (FALSE);
		}
	} else {
		rewind(mnttab_fp);
	}

	return (TRUE);
}


/*
 * Given a special device, return the place where it's mounted
 * or NULL.
 */
char *
getmntpoint(char *special)
{
	struct mnttab	mp;
	struct mnttab	mpref;
	char		*res = NULL;
	size_t		len;



	(void) memset(&mp, 0, sizeof (mp));
	(void) memset(&mpref, 0, sizeof (mpref));

	if (!reset_mnttab()) {
		goto dun;
	}

	mpref.mnt_special = strdup(special);
	if (getmntany(mnttab_fp, &mp, &mpref) == 0) {
		goto found1;			/* found an entry */
	}

	/*
	 * we didn't find a mnttab entry -- try brute force search looking
	 * for something like "pathname:N" (for PCFS hard disk mounts)
	 */
	len = strlen(special);
	rewind(mnttab_fp);
	while (getmntent(mnttab_fp, &mp) == 0) {
		/* skip non-pcfs entries */
		if (strcmp(mp.mnt_fstype, "pcfs") != 0) {
			continue;
		}
		if (strncmp(special, mp.mnt_special, len) == 0 &&
		    mp.mnt_special[len] == ':' &&
		    isalpha(mp.mnt_special[len + 1]) &&
		    mp.mnt_special[len + 2] == '\0') {
			goto found1;		/* a match */
		}
	}

	/* nothing found */
	goto dun;

found1:
	/*
	 * found a mnttab entry -- check for cachefs mount
	 */
	if (strcmp(mp.mnt_fstype, "cachefs") == 0) {
		/*
		 * if we have a cachefs mount then we need to
		 * itererate again
		 * (XXX: is this correct?)
		 */
		rewind(mnttab_fp);
		free(mpref.mnt_special);
		mpref.mnt_special = NULL;
		mpref.mnt_special = strdup(mp.mnt_mountp);
		if (getmntany(mnttab_fp, &mp, &mpref) != 0) {
			dprintf(
			"%s(%ld): cachefs-used mount %s not found in mnttab\n",
			    prog_name, prog_pid, mpref.mnt_special);
			goto dun;
		}
	}

	/* success */
	res = strdup(mp.mnt_mountp);
dun:
	if (mpref.mnt_special != NULL) {
		free(mpref.mnt_special);
	}
	return (res);
}


/*
 * return the mountpath given a path
 *
 * normally these will be the same, but for PCFS on non-floppies, we must
 * append a ":N", where "N" is the partiticion number/name
 * (see mount_pcfs(1M))
 */
void
get_mountpath(char *blkpath, char *type, char *res)
{
	static char	*mtype = NULL;


	if (mtype == NULL) {
		if ((mtype = getenv("VOLUME_MEDIATYPE")) == NULL) {
			/*
			 * this should never happen since we should have
			 * checked for this earlier
			 */
			dprintf("%s(%ld): VOLUME_MEDIATYPE unspecified\n",
			    prog_name, prog_pid);
		}
	}
	if ((type != NULL) && (strcmp(type, "pcfs") == 0) &&
	    (mtype != NULL) && (strcmp(mtype, "floppy") != 0)) {
		/*
		 * XXX: just assume (hope?) that user is using first FDISK
		 * partition ???
		 */
		(void) sprintf(res, "%s:c", blkpath);
	} else {
		/* default to return the path passed in */
		(void) strcpy(res, blkpath);
	}
}
