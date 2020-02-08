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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2020 Peter Tribble.
 */

/*
 * getfacl [-ad] file ...
 * This command displays discretionary information for a file or files.
 * display format:
 *	# file: filename
 *	# owner: uid
 *	# group: gid
 *	user::perm
 *	user:uid:perm
 *	group::perm
 *	group:gid:perm
 *	mask:perm
 *	other:perm
 *	default:user::perm
 *	default:user:uid:perm
 *	default:group::perm
 *	default:group:gid:perm
 *	default:mask:perm
 *	default:other:perm
 */

#include <stdlib.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <locale.h>
#include <sys/acl.h>
#include <errno.h>

static char	*pruname(uid_t);
static char	*prgname(gid_t);
static char	*display(int);
static void	usage();


int
main(int argc, char *argv[])
{
	int		c;
	int		aflag = 0;
	int		dflag = 0;
	int		errflag = 0;
	int		savecnt;
	int		aclcnt;
	int		mask = 0;
	aclent_t	*aclp;
	aclent_t	*tp;
	char		*permp;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (argc < 2)
		usage();

	while ((c = getopt(argc, argv, "ad")) != EOF) {
		switch (c) {
		case 'a':
			aflag++;
			break;
		case 'd':
			dflag++;
			break;
		case '?':
			errflag++;
			break;
		}
	}
	if (errflag)
		usage();

	if (optind >= argc)
		usage();

	for (; optind < argc; optind++) {
		register char *filep;

		filep = argv[optind];

		/* Get ACL info of the files */
		errno = 0;
		if ((aclcnt = acl(filep, GETACLCNT, 0, NULL)) < 0) {
			if (errno == ENOSYS) {
				(void) fprintf(stderr,
				    gettext("File system doesn't support "
				    "aclent_t style ACL's.\n"
				    "See acl(5) for more information on "
				    "POSIX-draft ACL support.\n"));
				exit(2);
			}
			perror(filep);
			exit(2);
		}
		if (aclcnt < MIN_ACL_ENTRIES) {
			(void) fprintf(stderr,
			    gettext("%d: acl count too small from %s\n"),
			    aclcnt, filep);
			exit(2);
		}

		if ((aclp = (aclent_t *)malloc(sizeof (aclent_t) * aclcnt))
		    == NULL) {
			(void) fprintf(stderr,
			    gettext("Insufficient memory\n"));
			exit(1);
		}

		errno = 0;
		if (acl(filep, GETACL, aclcnt, aclp) < 0) {
			perror(filep);
			exit(2);
		}

		/* display ACL: assume it is sorted. */
		(void) printf("\n# file: %s\n", filep);
		savecnt = aclcnt;
		for (tp = aclp; aclcnt--; tp++) {
			if (tp->a_type == USER_OBJ)
				(void) printf("# owner: %s\n",
				    pruname(tp->a_id));
			if (tp->a_type == GROUP_OBJ)
				(void) printf("# group: %s\n",
				    prgname(tp->a_id));
			if (tp->a_type == CLASS_OBJ)
				mask = tp->a_perm;
		}
		aclcnt = savecnt;
		for (tp = aclp; aclcnt--; tp++) {
			switch (tp->a_type) {
			case USER:
				if (!dflag) {
					permp = display(tp->a_perm);
					(void) printf("user:%s:%s\t\t",
					    pruname(tp->a_id), permp);
					free(permp);
					permp = display(tp->a_perm & mask);
					(void) printf(
					    "#effective:%s\n", permp);
					free(permp);
				}
				break;
			case USER_OBJ:
				if (!dflag) {
					/* no need to display uid */
					permp = display(tp->a_perm);
					(void) printf("user::%s\n", permp);
					free(permp);
				}
				break;
			case GROUP:
				if (!dflag) {
					permp = display(tp->a_perm);
					(void) printf("group:%s:%s\t\t",
					    prgname(tp->a_id), permp);
					free(permp);
					permp = display(tp->a_perm & mask);
					(void) printf(
					    "#effective:%s\n", permp);
					free(permp);
				}
				break;
			case GROUP_OBJ:
				if (!dflag) {
					permp = display(tp->a_perm);
					(void) printf("group::%s\t\t", permp);
					free(permp);
					permp = display(tp->a_perm & mask);
					(void) printf(
					    "#effective:%s\n", permp);
					free(permp);
				}
				break;
			case CLASS_OBJ:
				if (!dflag) {
					permp = display(tp->a_perm);
					(void) printf("mask:%s\n", permp);
					free(permp);
				}
				break;
			case OTHER_OBJ:
				if (!dflag) {
					permp = display(tp->a_perm);
					(void) printf("other:%s\n", permp);
					free(permp);
				}
				break;
			case DEF_USER:
				if (!aflag) {
					permp = display(tp->a_perm);
					(void) printf("default:user:%s:%s\n",
					    pruname(tp->a_id), permp);
					free(permp);
				}
				break;
			case DEF_USER_OBJ:
				if (!aflag) {
					permp = display(tp->a_perm);
					(void) printf("default:user::%s\n",
					    permp);
					free(permp);
				}
				break;
			case DEF_GROUP:
				if (!aflag) {
					permp = display(tp->a_perm);
					(void) printf("default:group:%s:%s\n",
					    prgname(tp->a_id), permp);
					free(permp);
				}
				break;
			case DEF_GROUP_OBJ:
				if (!aflag) {
					permp = display(tp->a_perm);
					(void) printf("default:group::%s\n",
					    permp);
					free(permp);
				}
				break;
			case DEF_CLASS_OBJ:
				if (!aflag) {
					permp = display(tp->a_perm);
					(void) printf("default:mask:%s\n",
					    permp);
					free(permp);
				}
				break;
			case DEF_OTHER_OBJ:
				if (!aflag) {
					permp = display(tp->a_perm);
					(void) printf("default:other:%s\n",
					    permp);
					free(permp);
				}
				break;
			default:
				(void) fprintf(stderr,
				    gettext("unrecognized entry\n"));
				break;
			}
		}
		free(aclp);
	}
	return (0);
}

static char *
display(int perm)
{
	char	*buf;

	buf = malloc(4);
	if (buf == NULL) {
		(void) fprintf(stderr, gettext("Insufficient memory\n"));
		exit(1);
	}

	if (perm & 4)
		buf[0] = 'r';
	else
		buf[0] = '-';
	if (perm & 2)
		buf[1] = 'w';
	else
		buf[1] = '-';
	if (perm & 1)
		buf[2] = 'x';
	else
		buf[2] = '-';
	buf[3] = '\0';
	return (buf);
}

static char *
pruname(uid_t uid)
{
	struct passwd	*passwdp;
	static char	uidp[10];	/* big enough */

	passwdp = getpwuid(uid);
	if (passwdp == (struct passwd *)NULL) {
		/* could not get passwd information: display uid instead */
		(void) sprintf(uidp, "%u", uid);
		return (uidp);
	} else
		return (passwdp->pw_name);
}

static char *
prgname(gid_t gid)
{
	struct group	*groupp;
	static char	gidp[10];	/* big enough */

	groupp = getgrgid(gid);
	if (groupp == (struct group *)NULL) {
		/* could not get group information: display gid instead */
		(void) sprintf(gidp, "%u", gid);
		return (gidp);
	} else
		return (groupp->gr_name);
}

static void
usage()
{
	(void) fprintf(stderr,
	    gettext("usage: getfacl [-ad] file ... \n"));
	exit(1);
}
