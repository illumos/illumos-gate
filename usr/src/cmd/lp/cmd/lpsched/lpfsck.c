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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include "stdarg.h"
#include "stdlib.h"
#include "fcntl.h"
#include <sys/param.h>
#include "lpsched.h"


static void check_link();

/**
 ** lpfsck()
 **/

#define	F	0
#define D	1
#define P	2
#define S	3

static void		proto (int, int, ...);
static int		va_makepath(va_list *, char **);
static void		_rename (char *, char *, ...);

void
lpfsck(void)
{
	struct stat		stbuf;
	int			real_am_in_background = am_in_background;


	/*
	 * Force log messages to go into the log file instead of stdout.
	 */
	am_in_background = 1;

	/*
	 * Most of these lines repeat the prototype file from the
	 * packaging and should match those items exactly.
	 * (In fact, they probably ought to be generated from that file,
	 * but that work is for a rainy day...)
	 */

	/*
	 * DIRECTORIES:
	 */
proto (D, 0,  Lp_A, NULL,			    0775, Lp_Uid, Lp_Gid);
proto (D, 1,  Lp_A_Classes, NULL,		    0775, Lp_Uid, Lp_Gid);
proto (D, 1,  Lp_A_Forms, NULL,			    0775, Lp_Uid, Lp_Gid);
proto (D, 1,  Lp_A_Interfaces, NULL,		    0775, Lp_Uid, Lp_Gid);
proto (D, 1,  Lp_A_Printers, NULL,		    0775, Lp_Uid, Lp_Gid);
proto (D, 1,  Lp_A_PrintWheels, NULL,		    0775, Lp_Uid, Lp_Gid);
proto (D, 0,  "/var/lp", NULL,			    0775, Lp_Uid, Lp_Gid);
proto (D, 1,  Lp_Logs, NULL,			    0775, Lp_Uid, Lp_Gid);
proto (D, 1,  Lp_Spooldir, NULL,		    0775, Lp_Uid, Lp_Gid);
proto (D, 1,  Lp_Admins, NULL,			    0775, Lp_Uid, Lp_Gid);
proto (D, 1,  Lp_Requests, NULL,		    0775, Lp_Uid, Lp_Gid);
proto (D, 1,  Lp_Requests, Local_System, NULL,	    0770, Lp_Uid, Lp_Gid);
proto (D, 1,  Lp_System, NULL,			    0775, Lp_Uid, Lp_Gid);
proto (D, 1,  Lp_Tmp, NULL,			    0771, Lp_Uid, Lp_Gid);
proto (D, 1,  Lp_Tmp, Local_System, NULL,	    0775, Lp_Uid, Lp_Gid);

	/*
	 * DIRECTORIES: not described in the packaging
	 */
proto (D, 0,  Lp_Spooldir, FIFOSDIR, NULL,	    0775, Lp_Uid, Lp_Gid);

	/*
	 * THE MAIN FIFO:
	 */
proto (P, 1,  Lp_FIFO, NULL,			    0666, Lp_Uid, Lp_Gid);

	/*
	 * SYMBOLIC LINKS:
	 * Watch out! These names are given in the reverse
	 * order found in the prototype file (sorry!)
	 */
proto (S, 1,  Lp_Model, NULL,			"/etc/lp/model", NULL);
proto (S, 1,  Lp_Logs, NULL,			"/etc/lp/logs", NULL);
/*     S, 1,  Lp_Tmp, Local_System, ...    DONE BELOW */
proto (S, 1,  Lp_Bin, NULL,			Lp_Spooldir, "bin", NULL);
proto (S, 1,  Lp_A, NULL,			Lp_Admins, "lp", NULL);

	/*
	 * OTHER FILES:
	 */

	/*
	 * SPECIAL CASE:
	 * If the "temp" symbolic link already exists,
	 * but is not correct, assume the machine's nodename changed.
	 * Rename directories that include the nodename, if possible,
	 * so that unprinted requests are saved. Then change the
	 * symbolic link.
	 * Watch out for a ``symbolic link'' that isn't!
	 */
	if (Lstat(Lp_Temp, &stbuf) == 0)
	    switch (stbuf.st_mode & S_IFMT) {

	    default:
		Unlink (Lp_Temp);
		break;

	    case S_IFDIR:
		Rmdir (Lp_Temp);
		break;

	    case S_IFLNK:
		check_link();
		break;
	    }

	proto(S, 1, Lp_Tmp, Local_System, NULL,	Lp_Temp, NULL);

	am_in_background = real_am_in_background;
	return;
}

static void
check_link()
{
	int len;
	char symbolic[MAXPATHLEN + 1];
	char *real_dir;
	char *old_system;

	if ((len = Readlink(Lp_Temp, symbolic, MAXPATHLEN)) <= 0) {
		Unlink(Lp_Temp);
		return;
	}

	/*
	 * If the symbolic link contained trailing slashes, remove
	 * them.
	 */
	while ((len > 1) && (symbolic[len - 1] == '/')) {
		len--;
	}
	symbolic[len] = 0;

	/* check that symlink points into /var/spool/lp/tmp */
	if (strncmp(Lp_Tmp, symbolic, strlen(Lp_Tmp)) != 0) {
		Unlink(Lp_Temp);
		return;
	}

	/*
	 * Check that symlink points to something.
	 * There should be at least 2 characters
	 * after the string '/var/spool/lp/tmp':
	 * a '/' and another character.
	 */
	if (len <= strlen(Lp_Tmp) + 1) {
		Unlink(Lp_Temp);
		return;
	}

	real_dir = makepath(Lp_Tmp, Local_System, NULL);
	if (!STREQU(real_dir, symbolic)) {
		if (!(old_system = strrchr(symbolic, '/')))
			old_system = symbolic;
		else
			old_system++;

		/*
		 * The "rename()" system call (buried
		 * inside the "_rename()" routine) should
		 * succeed, even though we blindly created
		 * the new directory earlier, as the only
		 * directory entries should be . and ..
		 * (although if someone already created
		 * them, we'll note the fact).
		 */
		_rename(old_system, Local_System, Lp_Tmp, NULL);
		_rename(old_system, Local_System, Lp_Requests, NULL);

		Unlink(Lp_Temp);
	}
	Free(real_dir);
}


/**
 ** proto()
 **/

static void
proto(int type, int rm_ok, ...)
{
	va_list			ap;

	char			*path,
				*symbolic;

	int			exist,
				err;

	mode_t			mode;

	uid_t			uid;

	gid_t			gid;

	struct stat		stbuf;


	va_start(ap, rm_ok);

	if ((err = va_makepath(&ap, &path)) < 0)
		fail ("\"%s\" is a truncated name!\n", path);

	exist = (stat(path, &stbuf) == 0);

	switch (type) {

	case S:
		if (!exist)
			fail ("%s is missing!\n", path);
		if ((err = va_makepath(&ap, &symbolic)) < 0)
			fail ("\"%s\" is a truncated name!\n", symbolic);
		Symlink (path, symbolic);
		Free (symbolic);
		Free (path);
		return;

	case D:
		if (exist && !S_ISDIR(stbuf.st_mode)) {
			if (!rm_ok)
				fail ("%s is not a directory!\n", path);
			else {
				Unlink (path);
				exist = 0;
			}
		}
		if (!exist)
			Mkdir (path, 0);
		break;

	case F:
		if (exist && !S_ISREG(stbuf.st_mode)) {
			if (!rm_ok)
				fail ("%s is not a file!\n", path);
			else {
				Unlink (path);
				exist = 0;
			}
		}
		if (!exist)
			Close(Creat(path, 0));
		break;

	case P:
		/*
		 * Either a pipe or a file.
		 */
		if (exist &&
		    !S_ISREG(stbuf.st_mode) && !S_ISFIFO(stbuf.st_mode)) {
			if (!rm_ok)
				fail ("%s is not a file or pipe!\n", path);
			else {
				Unlink (path);
				exist = 0;
			}
		}
		if (!exist)
			Close(Creat(path, 0));
		break;

	}

	mode = va_arg(ap, mode_t);
	uid = va_arg(ap, uid_t);
	gid = va_arg(ap, gid_t);
	(void) chownmod(path, uid, gid, mode);

	Free (path);
	return;
}

/*
 * va_makepath()
 *
 * Takes a variable length list of path components and attempts to string them
 * together into a path.  It returns a heap-allocated string via the output
 * parameter 'ret', and returns an integer success value: < 0 indicates failure,
 * 0 indicates success.  Note that 'ret' will never be NULL (unless the system
 * is so overloaded that it can't allocate a single byte), and should always be
 * free()d.
 */
static int
va_makepath (va_list *pap, char **ret)
{
	char			*component;
	char 			buf[MAXPATHLEN];
	int			buflen;

	memset(buf, 0, sizeof (buf));
	while ((component = va_arg((*pap), char *)) != NULL) {
		if (strlcat(buf, component, sizeof (buf)) >= sizeof (buf) ||
			strlcat(buf, "/", sizeof (buf)) >= sizeof (buf)) {
			if ((*ret = strdup(buf)) == NULL)
				*ret = strdup("");
			return (-1);
		}
	}

	/* remove the trailing slash */
	buflen = strlen(buf);
	if ((buflen > 1) && (buf[buflen - 1] == '/')) {
		buf[buflen - 1] = '\0';
	}

	if ((*ret = strdup(buf)) == NULL) {
		*ret = strdup("");
		return (-1);
	}
	return (0);
}

/**
 ** _rename()
 **/

static void
_rename(char *old_system, char *new_system, ...)
{
	va_list			ap;

	char *			prefix;
	char *			old;
	char *			new;
	int			err;


	va_start (ap, new_system);
	if ((err = va_makepath(&ap, &prefix)) < 0)
		fail (
			"Rename failed; prefix \"%s\" is a truncated name.\n",
			prefix
		);
	va_end (ap);

	old = makepath(prefix, old_system, (char *)0);
	new = makepath(prefix, new_system, (char *)0);

	if (Rename(old, new) == 0)
		note ("Renamed %s to %s.\n", old, new);
	else if (errno == EEXIST)
		note (
			"Rename of %s to %s failed because %s exists.\n",
			old,
			new,
			new
		);
	else
		fail (
			"Rename of %s to %s failed (%s).\n",
			old,
			new,
			PERROR
		);

	Free (new);
	Free (old);
	Free (prefix);

	return;
}
