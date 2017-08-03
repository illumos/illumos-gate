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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <stdio.h>
#include <sys/types.h>
#include <shadow.h>
#include <pwd.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <locale.h>
#include <fcntl.h>
#include <secdb.h>
#include <user_attr.h>
#include <nss.h>

#define	CMT_SIZE	(128+1)	/* Argument sizes + 1 (for '\0') */
#define	DIR_SIZE	(256+1)
#define	SHL_SIZE	(256+1)
#define	ENTRY_LENGTH	512	/* Max length of an /etc/passwd entry */
#define	UID_MIN		100	/* Lower bound of default UID */

#define	M_MASK		01	/* Masks for the optn_mask variable */
#define	L_MASK		02	/* It keeps track of which options   */
#define	C_MASK		04	/* have been entered */
#define	H_MASK		010
#define	U_MASK		020
#define	G_MASK		040
#define	S_MASK		0100
#define	O_MASK		0200
#define	A_MASK		0400
#define	D_MASK		01000
#define	F_MASK		02000
#define	E_MASK		04000

#define	UATTR_MASK	010000

					/* flags for info_mask */
#define	LOGNAME_EXIST	01		/* logname exists */
#define	BOTH_FILES	02		/* touch both password files */
#define	WRITE_P_ENTRY	04		/* write out password entry */
#define	WRITE_S_ENTRY	010		/* write out shadow entry */
#define	NEED_DEF_UID	020		/* need default uid */
#define	FOUND		040		/* found the entry in password file */
#define	LOCKED		0100		/* did we lock the password file */
#define	UATTR_FILE	0200		/* touch user_attr file */
#define	BAD_ENT_MESSAGE	"%s: Bad entry found in /etc/passwd.  Run pwconv.\n"

typedef struct kvopts {
	const char	option;
	const char	*key;
	char		*newvalue;
} kvopts_t;

/* mapping of extensible keywords and options */
kvopts_t ua_opts[] =  {
{ 'A',	USERATTR_AUTHS_KW },
{ 'P',	USERATTR_PROFILES_KW },
{ 'R',	USERATTR_ROLES_KW },
{ 'T',	USERATTR_TYPE_KW },
{ '\0', USERATTR_DEFAULTPROJ_KW },
{ '\0',	USERATTR_LIMPRIV_KW },
{ '\0',	USERATTR_DFLTPRIV_KW },
{ '\0', USERATTR_LOCK_AFTER_RETRIES_KW },
{ '\0', USERATTR_LABELVIEW },
{ '\0', USERATTR_CLEARANCE },
{ '\0', USERATTR_MINLABEL },
{ '\0', USERATTR_AUDIT_FLAGS_KW },
};

#define	UA_KEYS		(sizeof (ua_opts)/sizeof (kvopts_t))


char defdir[] = "/home/";	/* default home directory for new user */
char pwdflr[] =	"x";		/* password string for /etc/passwd */
char lkstring[] = "*LK*";	/* lock string for shadow password */
char nullstr[] = "";		/* null string */
char	*msg;			/* pointer to error message	*/

#define	DATMSK "DATEMSK=/etc/datemsk"

#define	OUSERATTR_FILENAME	"/etc/ouser_attr"
#define	USERATTR_TEMP		"/etc/uatmp"

struct uid_blk {
	struct uid_blk *link;
	uid_t low;		/* low bound for this uid block */
	uid_t high;		/* high bound for this uid block */
};

extern userattr_t *fgetuserattr(FILE *);


/*
 * Declare all functions that do not return integers.  This is here
 * to get rid of some lint messages
 */

void	uid_bcom(struct uid_blk *), add_ublk(uid_t, struct uid_blk *),
	bad_perm(void),
	bad_usage(char *), bad_arg(char *), bad_uid(void), bad_pasf(void),
	file_error(void), bad_news(void), no_lock(void), add_uid(uid_t),
	rid_tmpf(void), ck_p_sz(struct passwd *), ck_s_sz(struct spwd *),
	bad_name(char *), bad_uattr(void);

void file_copy(FILE *spf, long NIS_pos);

static FILE *fp_ptemp, *fp_stemp, *fp_uatemp;
static int fd_ptemp, fd_stemp, fd_uatemp;

/*
 * The uid_blk structure is used in the search for the default
 * uid.  Each uid_blk represent a range of uid(s) that are currently
 * used on the system.
 */


#ifndef att
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

	fclose(shadf);

	return (sp);
}
#endif

static void
putuserattrent(userattr_t *user, FILE *f)
{
	int		i, j;
	char		*key;
	char		*val;
	kv_t		*kv_pair;

	/*
	 * Avoid trivial entries.  Those with no attributes or with
	 * only "type=normal".  This retains backward compatibility.
	 */
	if (user->attr == NULL)
		return;

	kv_pair = user->attr->data;

	for (i = j = 0; i < user->attr->length; i++) {
		key = kv_pair[i].key;
		val = kv_pair[i].value;
		if ((key == NULL) || (val == NULL))
			break;
		if (strlen(val) == 0 ||
		    (strcmp(key, USERATTR_TYPE_KW) == 0 &&
		    strcmp(val, USERATTR_TYPE_NORMAL_KW) == 0))
			continue;
		j++;
	}
	if (j == 0)
		return;

	(void) fprintf(f, "%s:%s:%s:%s:", user->name, user->qualifier,
	    user->res1, user->res2);

	for (i = j = 0; i < user->attr->length; i++) {
		key = kv_pair[i].key;
		val = _escape(kv_pair[i].value, KV_SPECIAL);
		if ((key == NULL) || (val == NULL))
			break;
		if (strlen(val) == 0)
			continue;
		if (j > 0)
			(void) fprintf(f, KV_DELIMITER);
		(void) fprintf(f, "%s=%s", key, val);
		j++;
	}
	(void) fprintf(f, "\n");
}

static void
assign_attr(userattr_t *user, const char *newkey, char *val)
{

	int		i;
	char		*key;
	kv_t		*kv_pair;
	int		avail = -1;

	if (user->attr != NULL) {
		kv_pair = user->attr->data;
		for (i = 0; i < user->attr->length; i++) {
			key = kv_pair[i].key;
			if (key == NULL) {
				avail = i;
				continue;
			} else if (strcmp(key, newkey) == 0) {
				kv_pair[i].value = strdup(val);
				return;
			}
		}

		if (avail == -1)
			avail = user->attr->length++;
		kv_pair[avail].key = strdup(newkey);
		kv_pair[avail].value = strdup(val);
	}
}

static void
unassign_role(userattr_t *user, char *rolelist, char *role)
{

	char *roleptr;
	char *templist;
	char *temprole;
	int  length;

	roleptr = rolelist;
	templist = strdup(roleptr);
	temprole = strtok(templist, ",");
	while (temprole) {
		if (strcmp(temprole, role) == 0) {

			length = strlen(role);
			roleptr += temprole - templist;

			if (*(roleptr + length) == ',')
				length++;
			strcpy(roleptr, roleptr + length);
			length = strlen(roleptr) - 1;
			if (*(roleptr + length) == ',')
				*(roleptr + length) = '\0';
			assign_attr(user, USERATTR_ROLES_KW, rolelist);
			break;
		} else {
			temprole = strtok(NULL, ",");
		}
	}
}

struct uid_blk *uid_sp;
char *prognamp;			/* program name */
extern int errno;
int optn_mask = 0, info_mask = 0;
extern int getdate_err;

int
main(int argc, char **argv)
{
	int c, i;
	char *lognamp, *char_p;
	int end_of_file = 0;
	int error;
	long date = 0;
	FILE *pwf, *spf, *uaf;

	struct passwd *pw_ptr1p, passwd_st;
	struct spwd *sp_ptr1p, shadow_st;
	userattr_t *ua_ptr1p, userattr_st;
	static kv_t ua_kv[KV_ADD_KEYS];
	kva_t ua_kva;
	struct stat statbuf;
	struct tm *tm_ptr;
	int NIS_entry_seen;		/* NIS scanning flag */
	/*
	 * NIS start pos, really pointer to first entry AFTER first
	 * NIS-referant entry
	 */
	long NIS_pos;
	long cur_pos;		/* Current pos, used with nis-pos above */

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	tzset();
	/* Get program name */
	prognamp = argv[0];

	/* Check identity */
	if (geteuid() != 0)
		bad_perm();

	/* Lock the password file(s) */

	if (lckpwdf() != 0)
		no_lock();
	info_mask |= LOCKED;		/* remember we locked */

	/* initialize the two structures */

	passwd_st.pw_passwd = pwdflr;		/* bogus password */
	passwd_st.pw_name = nullstr;		/* login name */
	passwd_st.pw_uid = -1;			/* no uid */
	passwd_st.pw_gid = 1;			/* default gid */
	passwd_st.pw_age = nullstr;		/* no aging info. */
	passwd_st.pw_comment = nullstr;	/* no comments */
	passwd_st.pw_gecos = nullstr;		/* no comments */
	passwd_st.pw_dir = nullstr;		/* no default directory */
	passwd_st.pw_shell = nullstr;		/* no default shell */

	shadow_st.sp_namp = nullstr;	/* no name */
	shadow_st.sp_pwdp = lkstring;	/* locked password */
	shadow_st.sp_lstchg = -1;	/* no lastchanged date */
	shadow_st.sp_min = -1;	/* no min */
	shadow_st.sp_max = -1;	/* no max */
	shadow_st.sp_warn = -1; 	/* no warn */
	shadow_st.sp_inact = -1;	/* no inactive */
	shadow_st.sp_expire = -1;	/* no expire */
	shadow_st.sp_flag = 0;	/* no flag */

	userattr_st.name = nullstr;
	userattr_st.qualifier = nullstr;
	userattr_st.res1 = nullstr;
	userattr_st.res2 = nullstr;

	ua_kva.length = 1;
	ua_kv[0].key = USERATTR_TYPE_KW;
	ua_kv[0].value = USERATTR_TYPE_NORMAL_KW;
	ua_kva.data = ua_kv;
	userattr_st.attr = &ua_kva;

	/* parse the command line */

	while ((c = getopt(argc, argv,
	    "ml:c:h:u:g:s:f:e:k:A:P:R:T:oadK:")) != -1) {

		switch (c) {
		case 'm':
			/* Modify */

			if ((A_MASK|D_MASK|M_MASK) & optn_mask)
				bad_usage("Invalid combination of options");

			optn_mask |= M_MASK;
			break;

		case 'l' :
			/* Change logname */

			if ((A_MASK|D_MASK|L_MASK) & optn_mask)
				bad_usage("Invalid combination of options");

			if (strpbrk(optarg, ":\n") ||
			    strlen(optarg) == 0)
				bad_arg("Invalid argument to option -l");

			optn_mask |= L_MASK;
			passwd_st.pw_name = optarg;
			shadow_st.sp_namp = optarg;
			userattr_st.name = optarg;
			break;

		case 'f' :
			/* set inactive */

			if ((D_MASK|F_MASK) & optn_mask)
				bad_usage("Invalid combination of options");
			if (((shadow_st.sp_inact =
			    strtol(optarg, &char_p, 10)) < (long)0) ||
			    (*char_p != '\0') ||
			    strlen(optarg) == 0)
				bad_arg("Invalid argument to option -f");
			if (shadow_st.sp_inact == 0)
				shadow_st.sp_inact = -1;
			optn_mask |= F_MASK;
			break;

		case 'e' :
			/* set expire date */

			if ((D_MASK|E_MASK) & optn_mask)
				bad_usage("Invalid combination of options");

			if ((strlen(optarg)) < (size_t)2)
				shadow_st.sp_expire = -1;
			else {
				putenv(DATMSK);
				if ((tm_ptr =  getdate(optarg)) == NULL) {
					msg = "Invalid argument to option -e";
					bad_arg(msg);
				}
				if ((date =  mktime(tm_ptr)) < 0) {
					msg = "Invalid argument to option -e";
					bad_arg(msg);
				}
				shadow_st.sp_expire = (date / DAY);
				if (shadow_st.sp_expire <= DAY_NOW) {
					msg = "Invalid argument to option -e";
					bad_arg(msg);
				}
			}

			optn_mask |= E_MASK;
			break;

		case 'c' :
			/* The comment */

			if ((D_MASK|C_MASK) & optn_mask)
				bad_usage("Invalid combination of options");

			if (strlen(optarg) > (size_t)CMT_SIZE ||
			    strpbrk(optarg, ":\n"))
				bad_arg("Invalid argument to option -c");

			optn_mask |= C_MASK;
			passwd_st.pw_comment = optarg;
			passwd_st.pw_gecos = optarg;
			break;

		case 'h' :
			/* The home directory */

			if ((D_MASK|H_MASK) & optn_mask)
				bad_usage("Invalid combination of options");

			if (strlen(optarg) > (size_t)DIR_SIZE ||
			    strpbrk(optarg, ":\n"))
				bad_arg("Invalid argument to option -h");

			optn_mask |= H_MASK;
			passwd_st.pw_dir = optarg;
			break;

		case 'u' :
			/* The uid */

			if ((D_MASK|U_MASK) & optn_mask)
				bad_usage("Invalid combination of options");

			optn_mask |= U_MASK;
			passwd_st.pw_uid = (uid_t)strtol(optarg, &char_p, 10);
			if ((*char_p != '\0') ||
			    (passwd_st.pw_uid < 0) ||
			    (strlen(optarg) == 0))
				bad_arg("Invalid argument to option -u");

			break;

		case 'g' :
			/* The gid */

			if ((D_MASK|G_MASK) & optn_mask)
				bad_usage("Invalid combination of options");

			optn_mask |= G_MASK;
			passwd_st.pw_gid = (gid_t)strtol(optarg, &char_p, 10);

			if ((*char_p != '\0') || (passwd_st.pw_gid < 0) ||
			    (strlen(optarg) == 0))
				bad_arg("Invalid argument to option -g");
			break;

		case 's' :
			/* The shell */

			if ((D_MASK|S_MASK) & optn_mask)
				bad_usage("Invalid combination of options");

			if (strlen(optarg) > (size_t)SHL_SIZE ||
			    strpbrk(optarg, ":\n"))
				bad_arg("Invalid argument to option -s");

			optn_mask |= S_MASK;
			passwd_st.pw_shell = optarg;
			break;

		case 'o' :
			/* Override unique uid	*/

			if ((D_MASK|O_MASK) & optn_mask)
				bad_usage("Invalid combination of options");

			optn_mask |= O_MASK;
			break;

		case 'a' :
			/* Add */

			if ((A_MASK|M_MASK|D_MASK|L_MASK) & optn_mask)
				bad_usage("Invalid combination of options");

			optn_mask |= A_MASK;
			break;

		case 'd' :
			/* Delete */

			if ((D_MASK|M_MASK|L_MASK|C_MASK|
			    H_MASK|U_MASK|G_MASK|S_MASK|
			    O_MASK|A_MASK) & optn_mask)
				bad_usage("Invalid combination of options");

			optn_mask |= D_MASK;
			break;

		case 'K':
			if (D_MASK & optn_mask)
				bad_usage("Invalid combination of options");

			char_p = strchr(optarg, '=');
			if (char_p == NULL)
				bad_usage("Missing value in -K option");

			*char_p++ = '\0';

			for (i = 0; i < UA_KEYS; i++) {
				if (strcmp(optarg, ua_opts[i].key) == 0) {
					ua_opts[i].newvalue =
					    _escape(char_p, KV_SPECIAL);
					assign_attr(&userattr_st, optarg,
					    char_p);
					break;
				}
			}
			if (i == UA_KEYS)
				bad_usage("bad key");
			optn_mask |= UATTR_MASK;
			break;

		case '?' :

			bad_usage("");
			break;

		default :
			/* Extended User Attributes */
			{
				int j;

				for (j = 0; j < UA_KEYS; j++) {
					if (ua_opts[j].option == (char)c) {
						if ((D_MASK) & optn_mask)
							bad_usage("Invalid "
							"combination of "
							" options");
						optn_mask |= UATTR_MASK;
						assign_attr(&userattr_st,
						    ua_opts[j].key,
						    _escape(optarg,
						    KV_SPECIAL));
						ua_opts[j].newvalue =
						    _escape(optarg, KV_SPECIAL);
						break;
					}
				}
				break;
			}
		}
	}

	/* check command syntax for the following errors */
	/* too few or too many arguments */
	/* no -a -m or -d option */
	/* -o without -u */
	/* -m with no other option */

	if (optind == argc || argc > (optind+1) ||
	    !((A_MASK|M_MASK|D_MASK) & optn_mask) ||
	    ((optn_mask & O_MASK) && !(optn_mask & U_MASK)) ||
	    ((optn_mask & M_MASK) &&
	    !(optn_mask &
	    (L_MASK|C_MASK|H_MASK|U_MASK|G_MASK|S_MASK|F_MASK|
	    E_MASK|UATTR_MASK))))
		bad_usage("Invalid command syntax");

	/* null string argument or bad characters ? */
	if ((strlen(argv[optind]) == 0) || strpbrk(argv[optind], ":\n"))
		bad_arg("Invalid name");

	lognamp = argv [optind];

	/*
	 * if we are adding a new user or modifying an existing user
	 * (not the logname), then copy logname into the two data
	 *  structures
	 */

	if ((A_MASK & optn_mask) ||
	    ((M_MASK & optn_mask) && !(optn_mask & L_MASK))) {
		passwd_st.pw_name = argv [optind];
		shadow_st.sp_namp = argv [optind];
		userattr_st.name = argv [optind];
	}

	/* Put in directory if we are adding and we need a default */

	if (!(optn_mask & H_MASK) && (optn_mask & A_MASK)) {
		if ((passwd_st.pw_dir = malloc((size_t)DIR_SIZE)) == NULL)
			file_error();

		*passwd_st.pw_dir = '\0';
		(void) strcat(passwd_st.pw_dir, defdir);
		(void) strcat(passwd_st.pw_dir, lognamp);
	}

	/* Check the number of password files we are touching */

	if ((!((M_MASK & optn_mask) && !(L_MASK & optn_mask))) ||
	    ((M_MASK & optn_mask) && ((E_MASK & optn_mask) ||
	    (F_MASK & optn_mask))))
		info_mask |= BOTH_FILES;

	if ((D_MASK|L_MASK|UATTR_MASK) & optn_mask)
		info_mask |= UATTR_FILE;

	/* Open the temporary file(s) with appropriate permission mask */
	/* and the appropriate owner */

	if (stat(PASSWD, &statbuf) < 0)
		file_error();

	fd_ptemp = open(PASSTEMP, O_CREAT|O_EXCL|O_WRONLY, statbuf.st_mode);
	if (fd_ptemp == -1) {
		if (errno == EEXIST) {
			if (unlink(PASSTEMP)) {
				msg = "%s: warning: cannot unlink %s\n";
				(void) fprintf(stderr, gettext(msg), prognamp,
				    PASSTEMP);
			}
			fd_ptemp = open(PASSTEMP, O_CREAT|O_EXCL|O_WRONLY,
			    statbuf.st_mode);
			if (fd_ptemp == -1) {
				file_error();
			}

		} else
			file_error();
	}
	fp_ptemp = fdopen(fd_ptemp, "w");
	if (fp_ptemp == NULL)
		file_error();
	error = fchown(fd_ptemp, statbuf.st_uid, statbuf.st_gid);
	if (error == 0)
		error = fchmod(fd_ptemp, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if (error != 0) {
		(void) fclose(fp_ptemp);
		if (unlink(PASSTEMP)) {
			msg = "%s: warning: cannot unlink %s\n";
			(void) fprintf(stderr, gettext(msg), prognamp,
			    PASSTEMP);
		}
		file_error();
	}

	if (info_mask & BOTH_FILES) {
		if (stat(SHADOW, &statbuf) < 0) {
			rid_tmpf();
			file_error();
		}
		fd_stemp = open(SHADTEMP, O_CREAT|O_EXCL|O_WRONLY,
		    statbuf.st_mode);
		if (fd_stemp == -1) {
			if (errno == EEXIST) {
				if (unlink(SHADTEMP)) {
					msg = "%s: warning: cannot unlink %s\n";
					(void) fprintf(stderr, gettext(msg),
					    prognamp, SHADTEMP);
				}
				fd_stemp = open(SHADTEMP,
				    O_CREAT|O_EXCL|O_WRONLY, statbuf.st_mode);
				if (fd_stemp == -1) {
					rid_tmpf();
					file_error();
				}

			} else {
				rid_tmpf();
				file_error();
			}
		}
		fp_stemp = fdopen(fd_stemp, "w");
		if (fp_stemp == NULL) {
			rid_tmpf();
			file_error();
		}
		error = fchown(fd_stemp, statbuf.st_uid, statbuf.st_gid);
		if (error == 0)
			error = fchmod(fd_stemp, S_IRUSR);
		if (error != 0) {
			rid_tmpf();
			file_error();
		}
	}

	if (info_mask & UATTR_FILE) {
		if (stat(USERATTR_FILENAME, &statbuf) < 0) {
			rid_tmpf();
			file_error();
		}
		fd_uatemp = open(USERATTR_TEMP, O_CREAT|O_EXCL|O_WRONLY,
		    statbuf.st_mode);
		if (fd_uatemp == -1) {
			if (errno == EEXIST) {
				if (unlink(USERATTR_TEMP)) {
					msg = "%s: warning: cannot unlink %s\n";
					(void) fprintf(stderr, gettext(msg),
					    prognamp, USERATTR_TEMP);
				}
				fd_uatemp = open(USERATTR_TEMP,
				    O_CREAT|O_EXCL|O_WRONLY, statbuf.st_mode);
				if (fd_uatemp == -1) {
					rid_tmpf();
					file_error();
				}

			} else {
				rid_tmpf();
				file_error();
			}
		}
		fp_uatemp = fdopen(fd_uatemp, "w");
		if (fp_uatemp == NULL) {
			rid_tmpf();
			file_error();
		}
		error = fchown(fd_uatemp, statbuf.st_uid, statbuf.st_gid);
		if (error == 0)
			error = fchmod(fd_uatemp,
			    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
		if (error != 0) {
			rid_tmpf();
			file_error();
		}
	}
	/* Default uid needed ? */

	if (!(optn_mask & U_MASK) && (optn_mask & A_MASK)) {
		/* mark it in the information mask */
		info_mask |= NEED_DEF_UID;

		/* create the head of the uid number list */
		uid_sp = malloc(sizeof (struct uid_blk));
		if (uid_sp == NULL) {
			rid_tmpf();
			file_error();
		}

		uid_sp->link = NULL;
		uid_sp->low = (UID_MIN -1);
		uid_sp->high = (UID_MIN -1);
	}

	/*
	 * This next section is modified to allow for NIS passwd file
	 * conventions.  In the case where a password entry was being
	 * added to the password file, the original AT&T code read
	 * the entire password file in, noted any information needed, and
	 * copied the entries to a temporary file.  Then the new entry
	 * was added to the temporary file, and the temporary file was
	 * moved to be the real password file.
	 *
	 * The problem is, that with NIS compatability, we want to add new
	 * entries BEFORE the first NIS-referrant entry, so as not to have
	 * any surprises.  To accomplish this without extensively modifying
	 * the logic of the code below, as soon as a NIS-referrant entry is
	 * found we stop copying entries to the TEMP file and instead we
	 * remember
	 * the first NIS entry and where we found it, scan the rest of the
	 * password file without copying entries, then write the new entry, copy
	 * the stored password entry, then copy the rest of the password file.
	 */


	error = 0;

	if ((pwf = fopen("/etc/passwd", "r")) == NULL) {
		rid_tmpf();
		if (errno == ENOENT)
			bad_news();
		else
			file_error();
	}

	NIS_entry_seen = 0;
	cur_pos = 0;
	/* The while loop for reading PASSWD entries */
	info_mask |= WRITE_P_ENTRY;

	while (!end_of_file) {
		pw_ptr1p = fgetpwent(pwf);
		if (pw_ptr1p == NULL) {
			if (!feof(pwf)) {
				/* A real error - report it and exit */
				rid_tmpf();
				bad_pasf();
			}
			else
				break;
		}

		if (!NIS_entry_seen)
			info_mask |= WRITE_P_ENTRY;
		else
			info_mask &= ~WRITE_P_ENTRY;

		/*
		 * Set up the uid usage blocks to find the first
		 * available uid above UID_MIN, if needed
		 */

		if (info_mask & NEED_DEF_UID)
			add_uid(pw_ptr1p->pw_uid);

		/* Check for unique UID */

		if (strcmp(lognamp, pw_ptr1p->pw_name) &&
		    (pw_ptr1p->pw_uid == passwd_st.pw_uid) &&
		    ((optn_mask & U_MASK) && !(optn_mask & O_MASK))) {
			rid_tmpf();		/* get rid of temp files */
			bad_uid();
		}

		/* Check for unique new logname */

		if (strcmp(lognamp, pw_ptr1p->pw_name) == 0 &&
		    optn_mask & L_MASK &&
		    strcmp(pw_ptr1p->pw_name, passwd_st.pw_name) == 0) {
			rid_tmpf();
#ifdef att
			if (!getspnam(pw_ptr1p->pw_name))
#else
			if (!local_getspnam(pw_ptr1p->pw_name))
#endif
				bad_pasf();
			else
				bad_name("logname already exists");
		}

		if (strcmp(lognamp, pw_ptr1p->pw_name) == 0) {

			/* no good if we want to add an existing logname */
			if (optn_mask & A_MASK) {
				rid_tmpf();
#ifdef att
				if (!getspnam(lognamp))
#else
				if (!local_getspnam(lognamp))
#endif
					bad_pasf();
				else
					bad_name("name already exists");
			}

			/* remember we found it */
			info_mask |= FOUND;

			/* Do not write it out on the fly */
			if (optn_mask & D_MASK)
				info_mask &= ~WRITE_P_ENTRY;

			if (optn_mask & M_MASK) {

#ifdef att
				if (!getspnam(lognamp))
#else
				if (!local_getspnam(lognamp))
#endif
				{
					rid_tmpf();
					bad_pasf();
				}
				if (optn_mask & L_MASK)
					pw_ptr1p->pw_name = passwd_st.pw_name;

				if (optn_mask & U_MASK)
					pw_ptr1p->pw_uid = passwd_st.pw_uid;

				if (optn_mask & G_MASK)
					pw_ptr1p->pw_gid = passwd_st.pw_gid;

				if (optn_mask & C_MASK) {
					pw_ptr1p->pw_comment =
					    passwd_st.pw_comment;

					pw_ptr1p->pw_gecos =
					    passwd_st.pw_comment;
				}

				if (optn_mask & H_MASK)
					pw_ptr1p->pw_dir = passwd_st.pw_dir;

				if (optn_mask & S_MASK)
					pw_ptr1p->pw_shell = passwd_st.pw_shell;
				ck_p_sz(pw_ptr1p);  /* check entry size */
			}
		}

		if (optn_mask & A_MASK) {
			if (!NIS_entry_seen) {
				char	*p;
				p  = strchr("+-", pw_ptr1p->pw_name[0]);
				if (p != NULL) {
					/*
					 * Found first NIS entry.
					 * so remember it.
					 */
					NIS_pos = cur_pos;
					NIS_entry_seen = 1;
					info_mask &= ~WRITE_P_ENTRY;
				}
				else
					cur_pos = ftell(pwf);
			}
		}

		if (info_mask & WRITE_P_ENTRY) {
			if (putpwent(pw_ptr1p, fp_ptemp)) {
				rid_tmpf();
				file_error();
			}
		}
	} /* end-of-while-loop */

	if (error >= 1) {
		msg = "%s: Bad entry found in /etc/passwd.  Run pwconv.\n";
		fprintf(stderr, gettext(msg), prognamp);
	}

	/* Cannot find the target entry and we are deleting or modifying */

	if (!(info_mask & FOUND) && (optn_mask & (D_MASK|M_MASK))) {
		rid_tmpf();
#ifdef att
		if (getspnam(lognamp) != NULL)
#else
		if (local_getspnam(lognamp) != NULL)
#endif
			bad_pasf();
		else
			bad_name("name does not exist");
	}

	/* First available uid above UID_MIN is ... */

	if (info_mask & NEED_DEF_UID)
		passwd_st.pw_uid = uid_sp->high + 1;

	/* Write out the added entry now */

	if (optn_mask & A_MASK) {
		ck_p_sz(&passwd_st);	/* Check entry size */
		if (putpwent(&passwd_st, fp_ptemp)) {
			rid_tmpf();
			file_error();
		}
		/*
		 * Now put out the rest of the password file, if needed.
		 */
		if (NIS_entry_seen) {
			int n;
			char buf[1024];

			if (fseek(pwf, NIS_pos, SEEK_SET) < 0) {
				rid_tmpf();
				file_error();
			}
			while ((n = fread(buf, sizeof (char), 1024, pwf)) > 0) {
				if (fwrite(buf, sizeof (char), n, fp_ptemp)
				    != n) {
					rid_tmpf();
					file_error();
				}
			}
		}
	}

	(void) fclose(pwf);

	/* flush and sync the file before closing it */
	if (fflush(fp_ptemp) != 0 || fsync(fd_ptemp) != 0)
		file_error();

	/* Now we are done with PASSWD */
	(void) fclose(fp_ptemp);

	/* Do this if we are touching both password files */


	if (info_mask & BOTH_FILES) {
		info_mask &= ~FOUND;		/* Reset FOUND flag */

		/* The while loop for reading SHADOW entries */
		info_mask |= WRITE_S_ENTRY;

		end_of_file = 0;
		errno = 0;
		error = 0;

		NIS_entry_seen = 0;
		cur_pos = 0;

		if ((spf = fopen("/etc/shadow", "r")) == NULL) {
			rid_tmpf();
			file_error();
		}

		while (!end_of_file) {
			sp_ptr1p = fgetspent(spf);
			if (sp_ptr1p == NULL) {
				if (!feof(spf)) {
					rid_tmpf();
					bad_pasf();
				}
				else
					break;
			}

			if (!NIS_entry_seen)
				info_mask |= WRITE_S_ENTRY;
			else
				info_mask &= ~WRITE_S_ENTRY;

			/*
			 * See if the new logname already exist in the
			 * shadow passwd file
			 */
			if ((optn_mask & M_MASK) &&
			    strcmp(lognamp, shadow_st.sp_namp) != 0 &&
			    strcmp(sp_ptr1p->sp_namp, shadow_st.sp_namp) == 0) {
				rid_tmpf();
				bad_pasf();
			}

			if (strcmp(lognamp, sp_ptr1p->sp_namp) == 0) {
				info_mask |= FOUND;
				if (optn_mask & A_MASK) {
					/* password file inconsistent */
					rid_tmpf();
					bad_pasf();
				}

				if (optn_mask & M_MASK) {
					sp_ptr1p->sp_namp = shadow_st.sp_namp;
					if (F_MASK & optn_mask)
						sp_ptr1p->sp_inact =
						    shadow_st.sp_inact;
					if (E_MASK & optn_mask)
						sp_ptr1p->sp_expire =
						    shadow_st.sp_expire;

					ck_s_sz(sp_ptr1p);
				}

				if (optn_mask & D_MASK)
					info_mask &= ~WRITE_S_ENTRY;
			}

			if (optn_mask & A_MASK) {
				if (!NIS_entry_seen) {
					char	*p;
					p = strchr("+-", sp_ptr1p->sp_namp[0]);
					if (p != NULL) {
						/*
						 * Found first NIS entry.
						 * so remember it.
						 */
						NIS_pos = cur_pos;
						NIS_entry_seen = 1;
						info_mask &= ~WRITE_S_ENTRY;
					}
					else
						cur_pos = ftell(spf);
				}
			}

			if (info_mask & WRITE_S_ENTRY) {
				if (putspent(sp_ptr1p, fp_stemp)) {
					rid_tmpf();
					file_error();
				}
			}

		} /* end-of-while-loop */

		if (error >= 1) {

			msg = BAD_ENT_MESSAGE;
			fprintf(stderr, gettext(msg), prognamp);
		}

		/*
		 * If we cannot find the entry and we are deleting or
		 *  modifying
		 */

		if (!(info_mask & FOUND) && (optn_mask & (D_MASK|M_MASK))) {
			rid_tmpf();
			bad_pasf();
		}

		if (optn_mask & A_MASK) {
			ck_s_sz(&shadow_st);
			if (putspent(&shadow_st, fp_stemp)) {
				rid_tmpf();
				file_error();
			}

			/*
			 * Now put out the rest of the shadow file, if needed.
			 */
			if (NIS_entry_seen) {
				file_copy(spf, NIS_pos);
			}
		}

		/* flush and sync the file before closing it */
		if (fflush(fp_stemp) != 0 || fsync(fd_stemp) != 0)
			file_error();
		(void) fclose(fp_stemp);

		/* Done with SHADOW */
		(void) fclose(spf);

	} /* End of if info_mask */

	if (info_mask & UATTR_FILE) {
		info_mask &= ~FOUND;		/* Reset FOUND flag */

		/* The while loop for reading USER_ATTR entries */
		info_mask |= WRITE_S_ENTRY;

		end_of_file = 0;
		errno = 0;
		error = 0;

		NIS_entry_seen = 0;
		cur_pos = 0;

		if ((uaf = fopen(USERATTR_FILENAME, "r")) == NULL) {
			rid_tmpf();
			file_error();
		}

		while (!end_of_file) {
			ua_ptr1p = fgetuserattr(uaf);
			if (ua_ptr1p == NULL) {
				if (!feof(uaf)) {
					rid_tmpf();
					bad_uattr();
				}
				else
					break;
			}

			if (ua_ptr1p->name[0] == '#') {
				/*
				 * If this is a comment, write it back as it
				 * is.
				 */
				if (ua_ptr1p->qualifier[0] == '\0' &&
				    ua_ptr1p->res1[0] == '\0' &&
				    ua_ptr1p->res2[0] == '\0' &&
				    (ua_ptr1p->attr == NULL ||
				    ua_ptr1p->attr->length == 0))
					(void) fprintf(fp_uatemp, "%s\n",
					    ua_ptr1p->name);
				else
					/*
					 * This is a commented user_attr entry;
					 * reformat it, and write it back.
					 */
					putuserattrent(ua_ptr1p, fp_uatemp);
				free_userattr(ua_ptr1p);
				continue;
			}

			if (!NIS_entry_seen)
				info_mask |= WRITE_S_ENTRY;
			else
				info_mask &= ~WRITE_S_ENTRY;

			/*
			 * See if the new logname already exist in the
			 * user_attr file
			 */
			if ((optn_mask & M_MASK) &&
			    strcmp(lognamp, userattr_st.name) != 0 &&
			    strcmp(ua_ptr1p->name, userattr_st.name) == 0) {
				rid_tmpf();
				bad_pasf();
			}

			if (strcmp(lognamp, ua_ptr1p->name) == 0) {
				info_mask |= FOUND;
				if (optn_mask & A_MASK) {
					/* password file inconsistent */
					rid_tmpf();
					bad_pasf();
				}

				if (optn_mask & M_MASK) {
					int	j;
					char	*value;

					for (j = 0; j < UA_KEYS; j++) {
						if (ua_opts[j].newvalue != NULL)
							continue;
						value =
						    kva_match(ua_ptr1p->attr,
						    (char *)ua_opts[j].key);
						if (value == NULL)
							continue;
						assign_attr(&userattr_st,
						    ua_opts[j].key,
						    value);
					}
					free_userattr(ua_ptr1p);
					ua_ptr1p = &userattr_st;
				}

				if (optn_mask & D_MASK)
					info_mask &= ~WRITE_S_ENTRY;
			} else if (optn_mask & D_MASK) {
				char *rolelist;

				rolelist = kva_match(ua_ptr1p->attr,
				    USERATTR_ROLES_KW);
				if (rolelist) {
					unassign_role(ua_ptr1p,
					    rolelist, lognamp);
				}
			}

			if (info_mask & WRITE_S_ENTRY) {
				putuserattrent(ua_ptr1p, fp_uatemp);
			}

			if (!(optn_mask & M_MASK))
				free_userattr(ua_ptr1p);
		} /* end-of-while-loop */

		if (error >= 1) {

			msg = BAD_ENT_MESSAGE;
			fprintf(stderr, gettext(msg), prognamp);
		}

		/*
		 * Add entry in user_attr if masks is UATTR_MASK
		 * We don't need to do anything for L_MASK if there's
		 * no user_attr entry for the user being modified.
		 */
		if (!(info_mask & FOUND) && !(L_MASK & optn_mask) &&
		    !(D_MASK & optn_mask)) {
			putuserattrent(&userattr_st, fp_uatemp);
		}

		/* flush and sync the file before closing it */
		if (fflush(fp_uatemp) != 0 || fsync(fd_uatemp) != 0)
			file_error();
		(void) fclose(fp_uatemp);

		/* Done with USERATTR */
		(void) fclose(uaf);

	} /* End of if info_mask */
	/* ignore all signals */

	for (i = 1; i < NSIG; i++)
		(void) sigset(i, SIG_IGN);

	errno = 0;		/* For correcting sigset to SIGKILL */

	if (unlink(OPASSWD) && access(OPASSWD, 0) == 0)
		file_error();

	if (link(PASSWD, OPASSWD) == -1)
			file_error();


	if (rename(PASSTEMP, PASSWD) == -1) {
		if (link(OPASSWD, PASSWD))
			bad_news();
		file_error();
	}


	if (info_mask & BOTH_FILES) {

		if (unlink(OSHADOW) && access(OSHADOW, 0) == 0) {
			if (rec_pwd())
				bad_news();
			else
				file_error();
		}

		if (link(SHADOW, OSHADOW) == -1) {
			if (rec_pwd())
				bad_news();
			else
				file_error();
		}


		if (rename(SHADTEMP, SHADOW) == -1) {
			if (rename(OSHADOW, SHADOW) == -1)
				bad_news();

			if (rec_pwd())
				bad_news();
			else
				file_error();
		}

	}
	if (info_mask & UATTR_FILE) {
		if (unlink(OUSERATTR_FILENAME) &&
		    access(OUSERATTR_FILENAME, 0) == 0) {
			if (rec_pwd())
				bad_news();
			else
				file_error();
		}

		if (link(USERATTR_FILENAME, OUSERATTR_FILENAME) == -1) {
			if (rec_pwd())
				bad_news();
			else
				file_error();
		}


		if (rename(USERATTR_TEMP, USERATTR_FILENAME) == -1) {
			if (rename(OUSERATTR_FILENAME, USERATTR_FILENAME) == -1)
				bad_news();

			if (rec_pwd())
				bad_news();
			else
				file_error();
		}

	}

	ulckpwdf();

	/*
	 * Return 0 status, indicating success
	 */
	return (0);

}  /* end of main */

/* Try to recover the old password file */

int
rec_pwd(void)
{
	if (unlink(PASSWD) || link(OPASSWD, PASSWD))
		return (-1);

	return (0);
}

/* combine two uid_blk's */

void
uid_bcom(struct uid_blk *uid_p)
{
	struct uid_blk *uid_tp;

	uid_tp = uid_p->link;
	uid_p->high = uid_tp->high;
	uid_p->link = uid_tp->link;

	free(uid_tp);
}

/* add a new uid_blk */

void
add_ublk(uid_t num, struct uid_blk *uid_p)
{
	struct uid_blk *uid_tp;

	uid_tp = malloc(sizeof (struct uid_blk));
	if (uid_tp == NULL) {
		rid_tmpf();
		file_error();
	}

	uid_tp->high = uid_tp->low = num;
	uid_tp->link = uid_p->link;
	uid_p->link = uid_tp;
}

/*
 *	Here we are using a linked list of uid_blk to keep track of all
 *	the used uids.	Each uid_blk represents a range of used uid,
 *	with low represents the low inclusive end and high represents
 *	the high inclusive end.  In the beginning, we initialize a linked
 *	list of one uid_blk with low = high = (UID_MIN-1).  This was
 *	done in main().
 *	Each time we read in another used uid, we add it onto the linked
 *	list by either making a new uid_blk, decrementing the low of
 *	an existing uid_blk, incrementing the high of an existing
 *	uid_blk, or combining two existing uid_blks.  After we finished
 *	building this linked list, the first available uid above or
 *	equal to UID_MIN is the high of the first uid_blk in the linked
 *	list + 1.
 */
/* add_uid() adds uid to the link list of used uids */
void
add_uid(uid_t uid)
{
	struct uid_blk *uid_p;
	/* Only keep track of the ones above UID_MIN */

	if (uid >= UID_MIN) {
		uid_p = uid_sp;

		while (uid_p != NULL) {

			if (uid_p->link != NULL) {

				if (uid >= uid_p->link->low)
					uid_p = uid_p->link;

				else if (uid >= uid_p->low &&
				    uid <= uid_p->high) {
					uid_p = NULL;
				}

				else if (uid == (uid_p->high+1)) {

					if (++uid_p->high ==
					    (uid_p->link->low - 1)) {
						uid_bcom(uid_p);
					}
					uid_p = NULL;
				}

				else if (uid == (uid_p->link->low - 1)) {
					uid_p->link->low --;
					uid_p = NULL;
				}

				else if (uid < uid_p->link->low) {
					add_ublk(uid, uid_p);
					uid_p = NULL;
				}
			} /* if uid_p->link */

			else {

				if (uid == (uid_p->high + 1)) {
					uid_p->high++;
					uid_p = NULL;
				} else if (uid >= uid_p->low &&
				    uid <= uid_p->high) {
					uid_p = NULL;
				} else {
					add_ublk(uid, uid_p);
					uid_p = NULL;
				}
			} /* else */
		} /* while uid_p */

	} /* if uid */
}

void
bad_perm(void)
{
	(void) fprintf(stderr, gettext("%s: Permission denied\n"), prognamp);
	exit(1);
}

void
bad_usage(char *sp)
{
	if (strlen(sp) != 0)
		(void) fprintf(stderr, "%s: %s\n", prognamp, gettext(sp));
	(void) fprintf(stderr, gettext("Usage:\n\
%s -a [-c comment] [-h homedir] [-u uid [-o]] [-g gid] \n\
	    [-s shell] [-f inactive] [-e expire] name\n\
%s -m  -c comment | -h homedir | -u uid [-o] | -g gid |\n\
	    -s shell | -f inactive | -e expire	|  -l logname  name\n\
%s -d name\n"), prognamp, prognamp, prognamp);
	if (info_mask & LOCKED)
		ulckpwdf();
	exit(2);
}

void
bad_arg(char *s)
{
	(void) fprintf(stderr, "%s: %s\n", prognamp, gettext(s));

	if (info_mask & LOCKED)
		ulckpwdf();
	exit(3);
}

void
bad_name(char *s)
{
	(void) fprintf(stderr, "%s: %s\n", prognamp, gettext(s));
	ulckpwdf();
	exit(9);
}

void
bad_uid(void)
{
	(void) fprintf(stderr, gettext("%s: UID in use\n"), prognamp);

	ulckpwdf();
	exit(4);
}

void
bad_pasf(void)
{
	msg = "%s: Inconsistent password files\n";
	(void) fprintf(stderr, gettext(msg), prognamp);

	ulckpwdf();
	exit(5);
}

void
bad_uattr(void)
{
	msg = "%s: Bad user_attr database\n";
	(void) fprintf(stderr, gettext(msg), prognamp);

	ulckpwdf();
	exit(5);
}

void
file_error(void)
{
	msg = "%s: Unexpected failure.	Password files unchanged\n";
	(void) fprintf(stderr, gettext(msg), prognamp);

	ulckpwdf();
	exit(6);
}

void
bad_news(void)
{
	msg = "%s: Unexpected failure.	Password file(s) missing\n";
	(void) fprintf(stderr, gettext(msg), prognamp);

	ulckpwdf();
	exit(7);
}

void
no_lock(void)
{
	msg = "%s: Password file(s) busy.  Try again later\n";
	(void) fprintf(stderr, gettext(msg), prognamp);

	exit(8);
}

/* Check for the size of the whole passwd entry */
void
ck_p_sz(struct passwd *pwp)
{
	char ctp[128];

	/* Ensure that the combined length of the individual */
	/* fields will fit in a passwd entry. The 1 accounts for the */
	/* newline and the 6 accounts for the colons (:'s) */
	if (((int)strlen(pwp->pw_name) + 1 +
	    sprintf(ctp, "%d", pwp->pw_uid) +
	    sprintf(ctp, "%d", pwp->pw_gid) +
	    (int)strlen(pwp->pw_comment) +
	    (int)strlen(pwp->pw_dir) +
	    (int)strlen(pwp->pw_shell) + 6) > (ENTRY_LENGTH-1)) {
		rid_tmpf();
		bad_arg("New password entry too long");
	}
}

/* Check for the size of the whole passwd entry */
void
ck_s_sz(struct spwd *ssp)
{
	char ctp[128];

	/* Ensure that the combined length of the individual */
	/* fields will fit in a shadow entry. The 1 accounts for the */
	/* newline and the 7 accounts for the colons (:'s) */
	if (((int)strlen(ssp->sp_namp) + 1 +
	    (int)strlen(ssp->sp_pwdp) +
	    sprintf(ctp, "%d", ssp->sp_lstchg) +
	    sprintf(ctp, "%d", ssp->sp_min) +
	    sprintf(ctp, "%d", ssp->sp_max) +
	    sprintf(ctp, "%d", ssp->sp_warn) +
	    sprintf(ctp, "%d", ssp->sp_inact) +
	    sprintf(ctp, "%d", ssp->sp_expire) + 7) > (ENTRY_LENGTH - 1)) {
		rid_tmpf();
		bad_arg("New password entry too long");
	}
}

/* Get rid of the temp files */
void
rid_tmpf(void)
{
	(void) fclose(fp_ptemp);

	if (unlink(PASSTEMP)) {
		msg = "%s: warning: cannot unlink %s\n";
		(void) fprintf(stderr, gettext(msg), prognamp, PASSTEMP);
	}

	if (info_mask & BOTH_FILES) {
		(void) fclose(fp_stemp);

		if (unlink(SHADTEMP)) {
			msg = "%s: warning: cannot unlink %s\n";
			(void) fprintf(stderr, gettext(msg), prognamp,
			    SHADTEMP);
		}
	}

	if (info_mask & UATTR_FILE) {
		(void) fclose(fp_uatemp);

		if (unlink(USERATTR_TEMP)) {
			msg = "%s: warning: cannot unlink %s\n";
			(void) fprintf(stderr, gettext(msg), prognamp,
			    USERATTR_TEMP);
		}
	}
}

void
file_copy(FILE *spf, long NIS_pos)
{
	int n;
	char buf[1024];

	if (fseek(spf, NIS_pos, SEEK_SET) < 0) {
		rid_tmpf();
		file_error();
	}
	while ((n = fread(buf, sizeof (char), 1024, spf)) > 0) {
		if (fwrite(buf, sizeof (char), n, fp_stemp) != n) {
			rid_tmpf();
			file_error();
		}
	}
}
