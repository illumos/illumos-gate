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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T		*/
/*	  All Rights Reserved					*/
/*								*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * make directory.
 * If -m is used with a valid mode, directories will be
 * created in that mode.  Otherwise, the default mode will
 * be 777 possibly altered by the process's file mode creation
 * mask.
 * If -p is used, make the directory as well as
 * its non-existing parent directories.
 */

#include	<signal.h>
#include	<stdio.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<errno.h>
#include	<string.h>
#include	<locale.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<libgen.h>
#include	<stdarg.h>
#include	<wchar.h>

#define	MSGEXISTS	"\"%s\": Exists but is not a directory\n"
#define	MSGUSAGE 	"usage: mkdir [-m mode] [-p] dirname ...\n"
#define	MSGFMT1  	"\"%s\": %s\n"
#define	MSGFAILED	"Failed to make directory \"%s\"; %s\n"

extern int optind,  errno;
extern char *optarg;

static char
*simplify(char *path);

void
errmsg(int severity, int code, char *format, ...);

extern mode_t
newmode(char *ms, mode_t new_mode, mode_t umsk, char *file, char *path);

#define	ALLRWX (S_IRWXU | S_IRWXG | S_IRWXO)


int
main(int argc, char *argv[])
{
	int 	pflag, errflg, mflag;
	int 	c, local_errno, tmp_errno;
	mode_t	cur_umask;
	mode_t	mode;
	mode_t	modediff;
	char 	*d;
	struct stat	buf;

	pflag = mflag = errflg = 0;
	local_errno = 0;

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif

	(void) textdomain(TEXT_DOMAIN);

	cur_umask = umask(0);

	mode = ALLRWX;

	while ((c = getopt(argc, argv, "m:p")) != EOF) {
		switch (c) {
		case 'm':
			mflag++;
			mode = newmode(optarg, ALLRWX, cur_umask, "", "");
			break;
		case 'p':
			pflag++;
			break;
		case '?':
			errflg++;
			break;
		}
	}


	/*
	 * When using default ACLs, mkdir() should be called with
	 * 0777 always; and umask or default ACL should do the work.
	 * Because of the POSIX.2 requirement that the
	 * intermediate mode be at least -wx------,
	 * we do some trickery here.
	 *
	 * If pflag is not set, we can just leave the umask as
	 * it the user specified it, unless it masks any of bits 0300.
	 */
	if (pflag) {
		modediff = cur_umask & (S_IXUSR | S_IWUSR);
		if (modediff)
			cur_umask &= ~modediff;
	}
	(void) umask(cur_umask);

	argc -= optind;
	if (argc < 1 || errflg) {
		errmsg(0, 2, gettext(MSGUSAGE));
	}
	argv = &argv[optind];

	errno = 0;
	while (argc--) {
		if ((d = simplify(*argv++)) == NULL) {
			exit(2);
		}

		/*
		 * When -p is set, invokes mkdirp library routine.
		 * Although successfully invoked, mkdirp sets errno to ENOENT
		 * if one of the directory in the pathname does not exist,
		 * thus creates a confusion on success/failure status
		 * possibly checked by the calling routine or shell.
		 * Therefore, errno is reset only when
		 * mkdirp has executed successfully, otherwise save
		 * in local_errno.
		 */
		if (pflag) {
			/*
			 * POSIX.2 says that it is not an error if
			 * the argument names an existing directory.
			 * We will, however, complain if the argument
			 * exists but is not a directory.
			 */
			if (lstat(d, &buf) != -1) {
				if (S_ISDIR(buf.st_mode)) {
					continue;
				} else {
					local_errno = EEXIST;
					errmsg(0, 0, gettext(MSGEXISTS), d);
					continue;
				}
			}
			errno = 0;

			if (mkdirp(d, ALLRWX) < 0) {
				tmp_errno = errno;

				if (tmp_errno == EEXIST) {
					if (lstat(d, &buf) != -1) {
						if (! S_ISDIR(buf.st_mode)) {
							local_errno =
							    tmp_errno;
							errmsg(0, 0, gettext(
							    MSGEXISTS), d);
							continue;
						}
						/* S_ISDIR: do nothing */
					} else {
						local_errno = tmp_errno;
						perror("mkdir");
						errmsg(0, 0,
						    gettext(MSGFAILED), d,
						    strerror(local_errno));
						continue;
					}
				} else {
					local_errno = tmp_errno;
					errmsg(0, 0, gettext(MSGFMT1), d,
					    strerror(tmp_errno));
					continue;
				}
			}

			errno = 0;

			/*
			 * get the file mode for the newly
			 * created directory and test for
			 * set gid bit being inherited from the parent
			 * directory to include it with the file
			 * mode creation for the last directory
			 * on the dir path.
			 *
			 * This is only needed if mflag was specified
			 * or if the umask was adjusted with -wx-----
			 *
			 * If mflag is specified, we chmod to the specified
			 * mode, oring in the 02000 bit.
			 *
			 * If modediff is set, those bits need to be
			 * removed from the last directory component,
			 * all other bits are kept regardless of umask
			 * in case a default ACL is present.
			 */
			if (mflag || modediff) {
				mode_t tmpmode;

				(void) lstat(d, &buf);
				if (modediff && !mflag)
					tmpmode = (buf.st_mode & 07777)
								& ~modediff;
				else
					tmpmode = mode | (buf.st_mode & 02000);

				if (chmod(d, tmpmode) < 0) {
					tmp_errno = errno;
					local_errno = errno;
					errmsg(0, 0, gettext(MSGFMT1), d,
					    strerror(tmp_errno));
					continue;
				}
				errno = 0;
			}

			continue;
		} else {
			/*
			 * No -p. Make only one directory
			 */

			errno = 0;

			if (mkdir(d, mode) < 0) {
				local_errno = tmp_errno = errno;
				errmsg(0, 0, gettext(MSGFAILED), d,
				    strerror(tmp_errno));
				continue;
			}
			if (mflag) {
				mode_t tmpmode;
				(void) lstat(d, &buf);
				tmpmode = mode | (buf.st_mode & 02000);

				if (chmod(d, tmpmode) < 0) {
					tmp_errno = errno;
					local_errno = errno;
					errmsg(0, 0, gettext(MSGFMT1), d,
					    strerror(tmp_errno));
					continue;
				}
				errno = 0;
			}
		}
	} /* end while */

	/* When pflag is set, the errno is saved in local_errno */

	if (local_errno)
	    errno = local_errno;
	return (errno ? 2: 0);
}

/*
 *  errmsg - This is an interface required by the code common to mkdir and
 *		chmod. The severity parameter is ignored here, but is meaningful
 *		to chmod.
 */

/* ARGSUSED */
/* PRINTFLIKE3 */
void
errmsg(int severity, int code, char *format, ...)
{
	va_list ap;
	va_start(ap, format);

	(void) fprintf(stderr, "mkdir: ");
	(void) vfprintf(stderr, format, ap);

	va_end(ap);

	if (code > 0) {
		exit(code);
	}
}

/*
 *	simplify - given a pathname in a writable buffer, simplify that
 *		   path by removing meaningless occurances of path
 *		   syntax.
 *
 *		   The change happens in place in the argument.  The
 *		   result is neceassarily no longer than the original.
 *
 *		   Return the pointer supplied by the caller on success, or
 *		   NULL on error.
 *
 *		   The caller should handle error reporting based upon the
 *		   returned vlaue.
 */

static char *
simplify(char *mbPath)
{
	int i;
	size_t mbPathlen;	/* length of multi-byte path */
	size_t wcPathlen;	/* length of wide-character path */
	wchar_t *wptr;		/* scratch pointer */
	wchar_t *wcPath;	/* wide-character version of the path */

	/*
	 *  bail out if there is nothing there.
	 */

	if (!mbPath)
	    return (mbPath);

	/*
	 *  convert the multi-byte version of the path to a
	 *  wide-character rendering, for doing our figuring.
	 */

	mbPathlen = strlen(mbPath);

	if ((wcPath = calloc(sizeof (wchar_t), mbPathlen+1)) == NULL) {
		perror("mkdir");
		exit(2);
	}

	if ((wcPathlen = mbstowcs(wcPath, mbPath, mbPathlen)) == (size_t)-1) {
		free(wcPath);
		return (NULL);
	}

	/*
	 *  remove duplicate slashes first ("//../" -> "/")
	 */

	for (wptr = wcPath, i = 0; i < wcPathlen; i++) {
		*wptr++ = wcPath[i];

		if (wcPath[i] == '/') {
			i++;

			while (wcPath[i] == '/') {
				i++;
			}

			i--;
		}
	}

	*wptr = '\0';

	/*
	 *  next skip initial occurances of "./"
	 */

	for (wcPathlen = wcslen(wcPath), wptr = wcPath, i = 0;
	    i < wcPathlen-2 && wcPath[i] == '.' && wcPath[i+1] == '/';
	    i += 2) {
		/* empty body */
	}

	/*
	 *  now make reductions of various forms.
	 */

	while (i < wcPathlen) {
		if (i < wcPathlen-2 && wcPath[i] == '/' &&
		    wcPath[i+1] == '.' && wcPath[i+2] == '/') {
			/* "/./" -> "/" */
			i += 2;
		} else {
			/* Normal case: copy the character */
			*wptr++ = wcPath[i++];
		}
	}

	*wptr = '\0';

	/*
	 *  now convert back to the multi-byte format.
	 */

	if (wcstombs(mbPath, wcPath, mbPathlen) == (size_t)-1) {
		free(wcPath);
		return (NULL);
	}

	free(wcPath);
	return (mbPath);
}
