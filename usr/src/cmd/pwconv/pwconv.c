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
/*	  All Rights Reserved	*/

/*  pwconv.c  */
/*  Conversion aid to copy appropriate fields from the	*/
/*  password file to the shadow file.			*/

#include <pwd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <shadow.h>
#include <grp.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <locale.h>
#include <string.h>

#define	PRIVILEGED	0			/* privileged id */

/* exit  code */
#define	SUCCESS	0	/* succeeded */
#define	NOPERM	1	/* No permission */
#define	BADSYN	2	/* Incorrect syntax */
#define	FMERR	3	/* File manipulation error */
#define	FATAL	4	/* Old file can not be recover */
#define	FBUSY	5	/* Lock file busy */
#define	BADSHW	6	/* Bad entry in shadow file  */

#define	DELPTMP()	(void) unlink(PASSTEMP)
#define	DELSHWTMP()	(void) unlink(SHADTEMP)

char pwdflr[]	= "x";				/* password filler */
char *prognamp;
void f_err(void), f_miss(void), f_bdshw(void);

/*
 * getspnan routine that ONLY looks at the local shadow file
 */
struct spwd *
local_getspnam(char *name)
{
	FILE *shadf;
	struct spwd *sp;


	if ((shadf = fopen("/etc/shadow", "r")) == NULL)
		return (NULL);

	while ((sp = fgetspent(shadf)) != NULL) {
		if (strcmp(sp->sp_namp, name) == 0)
			break;
	}

	(void) fclose(shadf);

	return (sp);
}

int
main(int argc, char **argv)
{
	extern	int	errno;
	void  no_recover(void), no_convert(void);
	struct  passwd  *pwdp;
	struct	spwd	*sp, sp_pwd;		/* default entry */
	struct stat buf;
	FILE	*tp_fp, *tsp_fp;
	time_t	when, minweeks, maxweeks;
	int file_exist = 1;
	int end_of_file = 0;
	mode_t mode;
	mode_t pwd_mode;
	int pwerr = 0;
	ushort_t i;
	gid_t pwd_gid, sp_gid;
	uid_t pwd_uid, sp_uid;
	FILE *pwf;
	int black_magic = 0;
	int count;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	prognamp = argv[0];
	/* only PRIVILEGED can execute this command */
	if (getuid() != PRIVILEGED) {
		(void) fprintf(stderr, gettext("%s: Permission denied.\n"),
		    prognamp);
		exit(NOPERM);
	}

	/* No argument can be passed to the command */
	if (argc > 1) {
		(void) fprintf(stderr,
		    gettext("%s: Invalid command syntax.\n"), prognamp);
		(void) fprintf(stderr, gettext("Usage: pwconv\n"));
		exit(BADSYN);
	}

	/* lock file so that only one process can read or write at a time */
	if (lckpwdf() < 0) {
		(void) fprintf(stderr,
		    gettext("%s: Password file(s) busy.  Try again later.\n"),
		    prognamp);
		exit(FBUSY);
	}

	/* All signals will be ignored during the execution of pwconv */
	for (i = 1; i < NSIG; i++)
		(void) sigset(i, SIG_IGN);

	/* reset errno to avoid side effects of a failed */
	/* sigset (e.g., SIGKILL) */
	errno = 0;

	/* check the file status of the password file */
	/* get the gid of the password file */
	if (stat(PASSWD, &buf) < 0) {
		(void) f_miss();
		exit(FATAL);
	}
	pwd_gid = buf.st_gid;
	pwd_uid = buf.st_uid;
	pwd_mode = buf.st_mode;

	/* mode for the password file should be read-only or less */
	(void) umask(S_IAMB & ~(buf.st_mode & (S_IRUSR|S_IRGRP|S_IROTH)));

	/* open temporary password file */
	if ((tp_fp = fopen(PASSTEMP, "w")) == NULL) {
		(void) f_err();
		exit(FMERR);
	}

	if (chown(PASSTEMP, pwd_uid, pwd_gid) < 0) {
		DELPTMP();
		(void) f_err();
		exit(FMERR);
	}
	/* default mode mask of the shadow file */
	mode = S_IAMB & ~(S_IRUSR);

	/* check the existence of  shadow file */
	/* if the shadow file exists, get mode mask and group id of the file */
	/* if file does not exist, the default group name will be the group  */
	/* name of the password file.  */

	if (access(SHADOW, F_OK) == 0) {
		if (stat(SHADOW, &buf) == 0) {
			mode  = S_IAMB & ~(buf.st_mode & S_IRUSR);
			sp_gid = buf.st_gid;
			sp_uid = buf.st_uid;
		} else {
			DELPTMP();
			(void) f_err();
			exit(FMERR);
		}
	} else {
		sp_gid = pwd_gid;
		sp_uid = pwd_uid;
		file_exist = 0;
	}
	/*
	 * get the mode of shadow password file  -- mode of the file should
	 * be read-only for user or less.
	 */
	(void) umask(mode);

	/* open temporary shadow file */
	if ((tsp_fp = fopen(SHADTEMP, "w")) == NULL) {
		DELPTMP();
		(void) f_err();
		exit(FMERR);
	}

	/* change the group of the temporary shadow password file */
	if (chown(SHADTEMP, sp_uid, sp_gid) < 0) {
		(void) no_convert();
		exit(FMERR);
	}

	/* Reads the password file.				*/
	/* If the shadow password file not exists, or		*/
	/* if an entry doesn't have a corresponding entry in    */
	/* the shadow file, entries/entry will be created.	*/

	if ((pwf = fopen("/etc/passwd", "r")) == NULL) {
		no_recover();
		exit(FATAL);
	}

	count = 0;
	while (!end_of_file) {
		count++;
		if ((pwdp = fgetpwent(pwf)) != NULL) {
			if (!file_exist ||
			    (sp = local_getspnam(pwdp->pw_name)) == NULL) {
				if (errno == EINVAL) {
				/* Bad entry in shadow exit */
					DELSHWTMP();
					DELPTMP();
					(void) f_bdshw();
					exit(BADSHW);
				}
				sp = &sp_pwd;
				sp->sp_namp = pwdp->pw_name;
				if (!pwdp->pw_passwd ||
				    (pwdp->pw_passwd &&
				    *pwdp->pw_passwd == '\0')) {
					(void) fprintf(stderr, gettext(
					    "%s: WARNING user %s has no "
					    "password\n"),
					    prognamp, sp->sp_namp);
				}
				/*
				 * copy the password field in the password
				 * file to the shadow file.
				 * replace the password field with an 'x'.
				 */
				sp->sp_pwdp = pwdp->pw_passwd;
				pwdp->pw_passwd = pwdflr;
				/*
				 * if aging, split the aging info
				 * into age, max and min
				 * convert aging info from weeks to days
				 */
				if (pwdp->pw_age && *pwdp->pw_age != 0) {
					when = (long)a64l(pwdp->pw_age);
					maxweeks = when & 077;
					minweeks = (when >> 6) & 077;
					when >>= 12;
					sp->sp_lstchg = when * 7;
					sp->sp_min = minweeks * 7;
					sp->sp_max = maxweeks * 7;
					sp->sp_warn = -1;
					sp->sp_inact = -1;
					sp->sp_expire = -1;
					sp->sp_flag = 0;
					pwdp->pw_age = "";  /* do we care? */
				} else {
				/*
				 * if !aging, last_changed will be the day the
				 * conversion is done, min and max fields will
				 * be null - use timezone to get local time
				 */
					sp->sp_lstchg = DAY_NOW;
					sp->sp_min =  -1;
					sp->sp_max =  -1;
					sp->sp_warn = -1;
					sp->sp_inact = -1;
					sp->sp_expire = -1;
					sp->sp_flag = 0;
				}
			} else {
				/*
				 * if the passwd field has a string other than
				 * 'x', the entry will be written into the
				 * shadow file and the character 'x' is
				 * re-written as the passwd if !aging,
				 * last_changed as above
				 */

				/*
				 * with NIS, only warn about password missing
				 * if entry is not a NIS-lookup entry
				 * ("+" or "-") black_magic from getpwnam_r.c
				 */
				black_magic = (*pwdp->pw_name == '+' ||
				    *pwdp->pw_name == '-');
				/*
				 * moan about absence of non "+/-" passwd
				 * we could do more, but what?
				 */
				if ((!pwdp->pw_passwd ||
				    (pwdp->pw_passwd &&
				    *pwdp->pw_passwd == '\0')) &&
				    !black_magic) {
					(void) fprintf(stderr, gettext(
					    "%s: WARNING user %s has no "
					    "password\n"),
					    prognamp, sp->sp_namp);
				}
				if (pwdp->pw_passwd && *pwdp->pw_passwd) {
					if (strcmp(pwdp->pw_passwd, pwdflr)) {
						sp->sp_pwdp = pwdp->pw_passwd;
						pwdp->pw_passwd = pwdflr;
						if (!pwdp->pw_age ||
						    (pwdp->pw_age &&
						    *pwdp->pw_age == 0)) {
							sp->sp_lstchg = DAY_NOW;
							sp->sp_min =  -1;
							sp->sp_max =  -1;
							sp->sp_warn = -1;
							sp->sp_inact = -1;
							sp->sp_expire = -1;
							sp->sp_flag = 0;
						}
					}
				} else {
					/*
					 * black_magic needs a non-null passwd
					 * and pwdflr seem appropriate here
					 * clear garbage if any
					 */
					sp->sp_pwdp = "";
					pwdp->pw_passwd = pwdflr;
					sp->sp_lstchg = sp->sp_min =
					    sp->sp_max = -1;
					sp->sp_warn = sp->sp_inact =
					    sp->sp_expire = -1;
					sp->sp_flag = 0;
				}
				/*
				 * if aging, split the aging info
				 * into age, max and min
				 * convert aging info from weeks to days
				 */
				if (pwdp->pw_age && *pwdp->pw_age != '\0') {
					when = (long)a64l(pwdp->pw_age);
					maxweeks = when & 077;
					minweeks = (when >> 6) & 077;
					when >>= 12;
					sp->sp_lstchg = when * 7;
					sp->sp_min = minweeks * 7;
					sp->sp_max = maxweeks * 7;
					sp->sp_warn = -1;
					sp->sp_inact = -1;
					sp->sp_expire = -1;
					sp->sp_flag = 0;
					pwdp->pw_age = ""; /* do we care? */
				}
			}

			/* write an entry to temporary password file */
			if ((putpwent(pwdp, tp_fp)) != 0) {
				(void) no_convert();
				exit(FMERR);
			}

			/* write an entry to temporary shadow password file */
			if (putspent(sp, tsp_fp) != 0) {
				(void) no_convert();
				exit(FMERR);
			}
		} else {
			if (feof(pwf)) {
				end_of_file = 1;
			} else {
				errno = 0;
				pwerr = 1;
				(void) fprintf(stderr,
				    gettext("%s: ERROR: bad entry or blank "
				    "line at line %d in /etc/passwd\n"),
				    prognamp, count);
			}
		}
	} /* end of while */

	(void) fclose(pwf);
	(void) fclose(tsp_fp);
	(void) fclose(tp_fp);
	if (pwerr) {
		(void) no_convert();
		exit(FMERR);
	}

	/* delete old password file if it exists */
	if (unlink(OPASSWD) && (access(OPASSWD, F_OK) == 0)) {
		(void) no_convert();
		exit(FMERR);
	}

	/* rename the password file to old password file  */
	if (rename(PASSWD, OPASSWD) == -1) {
		(void) no_convert();
		exit(FMERR);
	}

	/* rename temporary password file to password file */
	if (rename(PASSTEMP, PASSWD) == -1) {
		/* link old password file to password file */
		if (link(OPASSWD, PASSWD) < 0) {
			(void) no_recover();
			exit(FATAL);
		}
		(void) no_convert();
		exit(FMERR);
	}

	/* delete old shadow password file if it exists */
	if (unlink(OSHADOW) && (access(OSHADOW, R_OK) == 0)) {
		/* link old password file to password file */
		if (unlink(PASSWD) || link(OPASSWD, PASSWD)) {
			(void) no_recover();
			exit(FATAL);
		}
		(void) no_convert();
		exit(FMERR);
	}

	/* link shadow password file to old shadow password file */
	if (file_exist && rename(SHADOW, OSHADOW)) {
		/* link old password file to password file */
		if (unlink(PASSWD) || link(OPASSWD, PASSWD)) {
			(void) no_recover();
			exit(FATAL);
		}
		(void) no_convert();
		exit(FMERR);
	}


	/* link temporary shadow password file to shadow password file */
	if (rename(SHADTEMP, SHADOW) == -1) {
		/* link old shadow password file to shadow password file */
		if (file_exist && (link(OSHADOW, SHADOW))) {
			(void) no_recover();
			exit(FATAL);
		}
		if (unlink(PASSWD) || link(OPASSWD, PASSWD)) {
			(void) no_recover();
			exit(FATAL);
		}
		(void) no_convert();
		exit(FMERR);
	}

	/* Make new mode same as old */
	(void) chmod(PASSWD, pwd_mode);

	/* Change old password file to read only by owner   */
	/* If chmod fails, delete the old password file so that */
	/* the password fields can not be read by others */
	if (chmod(OPASSWD, S_IRUSR) < 0)
		(void) unlink(OPASSWD);

	(void) ulckpwdf();
	return (0);
}

void
no_recover(void)
{
	DELPTMP();
	DELSHWTMP();
	(void) f_miss();
}

void
no_convert(void)
{
	DELPTMP();
	DELSHWTMP();
	(void) f_err();
}

void
f_err(void)
{
	(void) fprintf(stderr,
	    gettext("%s: Unexpected failure. Conversion not done.\n"),
	    prognamp);
	(void) ulckpwdf();
}

void
f_miss(void)
{
	(void) fprintf(stderr,
	    gettext("%s: Unexpected failure. Password file(s) missing.\n"),
	    prognamp);
	(void) ulckpwdf();
}

void
f_bdshw(void)
{
	(void) fprintf(stderr,
	    gettext("%s: Bad entry in /etc/shadow. Conversion not done.\n"),
	    prognamp);
	(void) ulckpwdf();
}
