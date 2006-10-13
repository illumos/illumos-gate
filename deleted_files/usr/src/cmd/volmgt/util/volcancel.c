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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Program to cancel pending i/o
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<string.h>
#include	<fcntl.h>
#include	<locale.h>
#include	<libintl.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/vol.h>
#include	<sys/param.h>
#include	<volmgt.h>

/*
 * ON-private libvolmgt routine(s)
 */
extern void	_media_printaliases(void);

/*
 * volcancel return codes:
 */

#define	SUCCESS			0
#define	USAGE_ERROR		1
#define	VOLMGT_NOT_RUNNING	2
#define	OPEN_ERROR		3
#define	IOCTL_ERROR		4


static char		*prog_name;
static void	usage(void);
static char	*pathify(char *);	/* add /vol/rdsk if needed */
static int	cancel(char *);


int
main(int argc, char **argv)
{
	extern int	optind;
	int		c;
	char		*name;
	int		excode = SUCCESS;


#ifdef DEBUG
	(void) fprintf(stderr, "VOLCANCEL: entering\n");
	(void) fflush(stderr);
#endif

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	prog_name = argv[0];

	/* process arguments */
	while ((c = getopt(argc, argv, "n")) != EOF) {
		switch (c) {
		case 'n':
			_media_printaliases();
			exit(SUCCESS);
		default:
			usage();
			exit(USAGE_ERROR);
		}
	}

	if (!volmgt_running()) {
		(void) fprintf(stderr,
		    gettext("%s: volume management is not running\n"),
		    prog_name);
#ifdef DEBUG
		(void) fprintf(stderr, "VOLCANCEL: exit value = %d\n",
		    VOLMGT_NOT_RUNNING);
		(void) fflush(stderr);
#endif

		exit(VOLMGT_NOT_RUNNING);
	}

	for (; optind < argc; optind++) {
		name = pathify(argv[optind]); /* pathify the arg */
		if (name == NULL)
			exit(OPEN_ERROR);
#ifdef DEBUG
		(void) fprintf(stderr, "VOLCANCEL: calling cancel(%s)\n",
		    name);
		(void) fflush(stderr);
#endif
		if ((excode = cancel(name)) != 0) {
			break;
		}
	}

#ifdef DEBUG
	(void) fprintf(stderr, "VOLCANCEL: returning %d\n", excode);
	(void) fflush(stderr);
#endif

	return (excode);
}


static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("usage: %s [name | nickname]\n"), prog_name);
}


static int
cancel(char *path)
{
	int	fd;


#ifdef DEBUG
	(void) fprintf(stderr, "VOLCANCEL: in cancel try open(%s)\n", path);
	(void) fflush(stderr);
#endif

	if ((fd = open(path, O_RDONLY|O_NDELAY)) < 0) {
#ifdef DEBUG
		perror(path);
#endif
		return (OPEN_ERROR);
	}

#ifdef DEBUG
	(void) fprintf(stderr, "VOLCANCEL: in cancel try ioctl\n");
	(void) fflush(stderr);
#endif

	if (ioctl(fd, VOLIOCCANCEL, 0) < 0) {
#ifdef DEBUG
		(void) fprintf(stderr,
	"volcancel error: ioctl(VOLIOCCANCEL) failed (errno %d; %s)\n",
		    errno, strerror(errno));
#endif
		return (IOCTL_ERROR);
	}

#ifdef DEBUG
	(void) fprintf(stderr, "VOLCANCEL: cancel() returning %d\n", SUCCESS);
	(void) fflush(stderr);
#endif
	return (SUCCESS);
}


static char *
pathify(char *path)
{
	/*
	 * ensure path exists -- if it doesn't, tack "/vol/rdsk" on front
	 * (oor alternate root if not "/vol")
	 */
	static char	vold_root[MAXPATHLEN] = "";
	static uint_t	vold_root_len;
	struct stat64	sb;		/* set but not used */
	static char	path_buf[MAXPATHLEN];
	char		*path_ptr = path;


	if (*vold_root == '\0') {
		(void) strcpy(vold_root, volmgt_root());
		(void) strcat(vold_root, "/");
		(void) strcat(vold_root, "rdsk");
		vold_root_len = strlen(vold_root);
	}

	if (stat64(path, &sb) < 0) {
		/* path doesn't already exist */
		if (strncmp(path, vold_root, vold_root_len) != 0) {
			/* found it in rdsk under vol root */
			(void) strcpy(path_buf, vold_root);
			(void) strcat(path_buf, "/");
			if (strlcat(path_buf, path, sizeof (path_buf))
			    >= sizeof (path_buf))
				return (NULL);
			path_ptr = path_buf;
		}
	}

	return (path_ptr);
}
