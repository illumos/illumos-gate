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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2020 Peter Tribble.
 */

/*
 * setfacl [-r] -f aclfile file ...
 * setfacl [-r] -d acl_entries file ...
 * setfacl [-r] -m acl_entries file ...
 * setfacl [-r] -s acl_entries file ...
 * This command deletes/adds/modifies/sets discretionary information for a file
 * or files.
 */

#include <stdlib.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <locale.h>
#include <sys/acl.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#define	ADD	1
#define	MODIFY	2
#define	DELETE	3
#define	SET	4

static int get_acl_info(char *filep, aclent_t **aclpp);
static int mod_entries(aclent_t *, int, char *, char *, char *, int);
static int set_file_entries(char *, char *, int);
static int set_online_entries(char *, char *, int);
static void usage();
static int parse_entry_list(aclent_t **, int *, char *, int);
static int convert_to_aclent_t(char *, int *, aclent_t **, int);
static int parse_entry(char *, aclent_t *, int);
static void err_handle(int, aclent_t *);
static int conv_id(char *);

int
main(int argc, char *argv[])
{
	int		c;
	int		dflag = 0;
	int		mflag = 0;
	int		rflag = 0;
	int		sflag = 0;
	int		fflag = 0;
	int		errflag = 0;
	int		aclcnt;			/* used by -m -d */
	aclent_t	*aclp;			/* used by -m -d */
	char		*aclfilep = NULL;		/* acl file argument */
	char		*d_entryp = NULL;	/* ptr to del entry list */
	char		*m_entryp = NULL;	/* ptr to mod entry list */
	char		*s_entryp = NULL;	/* ptr to set entry list */
	char		*work_dp = NULL;	/* working ptrs for the above */
	char		*work_mp = NULL;
	char		*work_sp = NULL;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (argc < 3)
		usage();

	while ((c = getopt(argc, argv, "rm:d:s:f:")) != EOF) {
		switch (c) {
		case 'r':
			rflag++;
			break;
		case 'd':
			if (dflag || fflag || sflag)
				usage();
			dflag++;
			d_entryp = optarg;
			break;
		case 'm':
			if (mflag || fflag || sflag)
				usage();
			mflag++;
			m_entryp = optarg;
			break;
		case 's':
			if (fflag || sflag || mflag || dflag)
				usage();
			sflag++;
			s_entryp = optarg;
			break;
		case 'f':
			if (fflag || sflag || mflag || dflag)
				usage();
			fflag++;
			aclfilep = optarg;
			break;
		case '?':
			errflag++;
			break;
		}
	}
	if (errflag)
		usage();

	/* one of these flags should be set */
	if (!fflag && !sflag && !mflag && !dflag)
		usage();

	/* no file arguments */
	if (optind >= argc)
		usage();

	for (; optind < argc; optind++) {
		register char *filep;

		filep = argv[optind];

		/* modify and delete: we need to get the ACL first */
		if (mflag || dflag) {
			if (m_entryp != NULL) {
				free(work_mp);
				work_mp = strdup(m_entryp);
				if (work_mp == NULL) {
					fprintf(stderr,
					    gettext("out of memory %s\n"),
					    m_entryp);
					exit(1);
				}
			}

			if (d_entryp != NULL) {
				free(work_dp);
				work_dp = strdup(d_entryp);
				if (work_dp == NULL) {
					fprintf(stderr,
					    gettext("out of memory %s\n"),
					    d_entryp);
					exit(1);
				}
			}

			aclcnt = get_acl_info(filep, &aclp);
			if (aclcnt == -1)
				exit(2);
			if (mod_entries(aclp, aclcnt, work_mp,
			    work_dp, filep, rflag) == -1)
				exit(2);
		} else if (fflag) {
			if (set_file_entries(aclfilep, filep, rflag) == -1)
				exit(2);
		} else if (sflag) {
			if (s_entryp != NULL) {
				free(work_sp);
				work_sp = strdup(s_entryp);
				if (work_sp == NULL) {
					fprintf(stderr,
					    gettext("out of memory %s\n"),
					    s_entryp);
					exit(1);
				}
			}
			if (set_online_entries(work_sp, filep, rflag) == -1)
				exit(2);
		}
	}
	return (0);
}

/*
 * For add, modify, and delete, we need to get the ACL of the file first.
 */
static int
get_acl_info(char *filep, aclent_t **aclpp)
{
	int	aclcnt;

	if ((aclcnt = acl(filep, GETACLCNT, 0, NULL)) < 0) {
		if (errno == ENOSYS) {
			(void) fprintf(stderr,
			    gettext("File system doesn't support aclent_t "
			    "style ACL's.\n"
			    "See acl(5) for more information on "
			    "POSIX-draft ACL support.\n"));
			return (-1);
		}
		(void) fprintf(stderr,
		    gettext("%s: failed to get acl count\n"), filep);
		perror("get acl count error");
		return (-1);
	}
	if (aclcnt < MIN_ACL_ENTRIES) {
		(void) fprintf(stderr,
		    gettext("%d: acl count is too small from %s\n"),
		    aclcnt, filep);
		return (-1);
	}

	if ((*aclpp = (aclent_t *)malloc(sizeof (aclent_t) * aclcnt)) == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		return (-1);
	}
	if (acl(filep, GETACL, aclcnt, *aclpp) < 0) {
		(void) fprintf(stderr,
		    gettext("%s: failed to get acl entries\n"), filep);
		perror("getacl error");
		return (-1);
	}
	return (aclcnt);
}

/*
 * mod_entries() handles add, delete, and modify ACL entries of a file.
 * The real action is in convert_to_aclent_t() called by parse_entry_list().
 * aclp: points ACL of a file and may be changed by lower level routine.
 * modp: modify entry list in ascii format
 * delp: delete entry list in ascii format
 * fnamep: file of interest
 */
static int
mod_entries(aclent_t *aclp, int cnt, char *modp, char *delp,
    char *fnamep, int rfg)
{
	/* modify and add: from -m option */
	if (parse_entry_list(&aclp, &cnt, modp, MODIFY) == -1)
		return (-1);

	/* deletion: from -d option */
	if (parse_entry_list(&aclp, &cnt, delp, DELETE) == -1)
		return (-1);

	if (aclsort(cnt, rfg, aclp) == -1) {
		(void) err_handle(cnt, aclp);
		(void) fprintf(stderr,
		    gettext("aclcnt %d, file %s\n"), cnt, fnamep);
		return (-1);
	}

	if (acl(fnamep, SETACL, cnt, aclp) < 0) {
		fprintf(stderr,
		    gettext("%s: failed to set acl entries\n"), fnamep);
		perror("setacl error");
		return (-1);
	}
	return (0);
}

/*
 * set_file_entries() creates ACL entries from ACL file (acl_fnamep).
 * It opens the file and converts every line (one line per acl entry)
 * into aclent_t format. It then recalculates the mask according to rflag.
 * Finally it sets ACL to the file (fnamep).
 */
static int
set_file_entries(char *acl_fnamep, char *fnamep, int rflag)
{
	int		aclcnt = 0;
	FILE		*acl_fp;
	aclent_t	*aclp;
	char		buf[BUFSIZ];
	char		*tp;

	if (strcmp(acl_fnamep, "-") == 0)
		acl_fp = stdin;
	else {
		if ((acl_fp = fopen(acl_fnamep, "r")) == NULL) {
			fprintf(stderr, gettext("Can't open acl file %s\n"),
			    acl_fnamep);
			return (-1);
		}
	}
	while (fgets(buf, BUFSIZ, acl_fp) != NULL) {
		if (buf[0] == '#' || buf[0] == '\n')
			continue;

		/* check effective permission: add a null after real perm */
		if ((tp = (char *)strchr(buf, '#')) != NULL) {
			tp--;
			while (*tp == ' ' || *tp == '\t') {
				if (tp != buf)
					tp--;
				else {
					fprintf(stderr,
					    gettext("entry format error %s\n"),
					    buf);
					exit(1);
				}
			}
			*(tp+1) = '\0';
		}

		/* remove <nl> at the end if there is one */
		if ((tp = (char *)strchr(buf, '\n')) != NULL)
			*tp = '\0';
		aclcnt++;
		if (convert_to_aclent_t(buf, &aclcnt, &aclp, SET) == -1)
			return (-1);
	}

	if (aclsort(aclcnt, rflag, aclp) == -1) {
		(void) err_handle(aclcnt, aclp);
		(void) fprintf(stderr, gettext("aclcnt %d, aclfile %s\n"),
		    aclcnt, acl_fnamep);
		return (-1);
	}

	if (acl(fnamep, SETACL, aclcnt, aclp) < 0) {
		fprintf(stderr,
		    gettext("%s: failed to set acl entries\n"), fnamep);
		perror("setacl error");
		return (-1);
	}
	return (0);
}

/*
 * set_online_entries() parses the acl entries from command line (setp).
 * It converts the comma separated acl entries into aclent_t format.
 * It then recalculates the mask according to rflag.
 * Finally it sets ACL to the file (fnamep).
 */
static int
set_online_entries(char *setp, char *fnamep, int rflag)
{
	aclent_t	*aclp;
	int		aclcnt = 0;

	if (parse_entry_list(&aclp, &aclcnt, setp, SET) == -1)
		return (-1);

	if (aclsort(aclcnt, rflag, aclp) == -1) {
		(void) err_handle(aclcnt, aclp);
		(void) fprintf(stderr,
		    gettext("aclcnt %d, file %s\n"), aclcnt, fnamep);
		return (-1);
	}

	if (acl(fnamep, SETACL, aclcnt, aclp) < 0) {
		fprintf(stderr,
		    gettext("%s: failed to set acl entries\n"), fnamep);
		perror("setacl error");
		return (-1);
	}
	return (0);
}

/*
 * parse_entry_list() parses entry list (listp) separated by commas.
 * Once it gets an ACL entry, it calls convert_to_aclent_t() to convert
 * to internal format.
 */
static int
parse_entry_list(aclent_t **aclpp, int *aclcntp, char *listp, int mode)
{
	char	*commap;

	if (listp == NULL)
		return (0);
	while ((commap = (char *)strchr(listp, ',')) != NULL) {
		*commap = '\0';
		*aclcntp += 1;
		/* aclcnt may be updated after the call: add or modify */
		if (convert_to_aclent_t(listp, aclcntp, aclpp, mode) == -1)
			return (-1);
		listp = ++commap;
	}
	/* this is for only one entry or last entry */
	if (*listp != '\0') {
		*aclcntp += 1;
		if (convert_to_aclent_t(listp, aclcntp, aclpp, mode) == -1)
			return (-1);
	}
	return (0);
}

/*
 * convert_to_aclent_t() converts an acl entry in ascii format (fields separated
 * by colon) into aclent_t and appends it to the current ACL. It also handles
 * memory allocation/deallocation for acl entries in aclent_t format.
 * aclpp that contains acl entries in acl format will be returned.
 * We don't check duplicates.
 */
static int
convert_to_aclent_t(char *entryp, int *cntp, aclent_t **aclpp, int mode)
{
	aclent_t	*new_aclp;
	aclent_t	tmpacl;
	aclent_t	*taclp, *centry = NULL, *gentry = NULL;
	int		cur_cnt;
	int		found = 0;
	int		is_obj;

	if (entryp == NULL)
		return (0);

	tmpacl.a_id = 0;	/* id field needs to be initialized */
	if (entryp[0] == 'u')
		tmpacl.a_id = getuid();	/* id field for user */
	if (entryp[0] == 'g')
		tmpacl.a_id = getgid();	/* id field for group */

	tmpacl.a_type = 0;
	if (parse_entry(entryp, &tmpacl, mode) == -1)
		return (-1);

	is_obj = ((tmpacl.a_type == USER_OBJ) ||
	    (tmpacl.a_type == GROUP_OBJ) ||
	    (tmpacl.a_type == CLASS_OBJ) ||
	    (tmpacl.a_type == DEF_USER_OBJ) ||
	    (tmpacl.a_type == DEF_GROUP_OBJ) ||
	    (tmpacl.a_type == DEF_OTHER_OBJ));

	if (*cntp > 1)
		new_aclp = (aclent_t *)realloc(*aclpp,
		    sizeof (aclent_t) * (*cntp));
	else
		new_aclp = (aclent_t *) malloc(sizeof (aclent_t) * (*cntp));
	if (new_aclp == NULL) {
		fprintf(stderr,
		    gettext("Insufficient memory for acl %d\n"), *cntp);
		return (-1);
	}

	cur_cnt = *cntp - 1;
	switch (mode) {
	case MODIFY:	/* and add */
		for (taclp = new_aclp; cur_cnt-- > 0; taclp++) {
			if (taclp->a_type == tmpacl.a_type &&
			    ((taclp->a_id == tmpacl.a_id) || is_obj)) {
				found++;
				/* cnt is added before it's called */
				*cntp -= 1;
				taclp->a_perm = tmpacl.a_perm;
				break;
			}
		}
		if (!found)	/* Add it to the end: no need to change cntp */
			memcpy(new_aclp + *cntp -1, &tmpacl, sizeof (aclent_t));
		break;

	case DELETE:
		for (taclp = new_aclp; cur_cnt-- > 0; taclp++) {
			if (taclp->a_type == tmpacl.a_type &&
			    ((taclp->a_id == tmpacl.a_id) || is_obj)) {
				found++;
				/* move up the rest */
				while (cur_cnt-- > 0) {
					memcpy(taclp, taclp+1,
					    sizeof (aclent_t));
					taclp++;
				}
				*cntp = *cntp - 2;
				break;
			}
		}
		if (!found)
			*cntp -= 1;
		break;

	case SET:
		/* we may check duplicate before copying over?? */
		memcpy(new_aclp + *cntp -1, &tmpacl, sizeof (aclent_t));
		break;

	default:
		fprintf(stderr,
		    gettext("Unrecognized mode: internal error\n"));
		break;
	}

	/*
	 * If converting from non-trivial acl entry to trivial one,
	 * reset CLASS_OBJ's permission with that of GROUP_OBJ.
	 */

	if (mode == DELETE) {
		boolean_t	trivial = B_TRUE;	/* assumption */
		cur_cnt = *cntp;
		for (taclp = new_aclp; cur_cnt-- > 0; taclp++) {
			switch (taclp->a_type) {
				case USER_OBJ:
				case OTHER_OBJ:
					break;
				case CLASS_OBJ:
					centry = taclp;
					break;
				case GROUP_OBJ:
					gentry = taclp;
					break;
				default:
					/*
					 * Confirmed that the new acl set is
					 * still a non-trivial acl.
					 * Skip reset.
					 */
					trivial = B_FALSE;
			}
		}
		if (centry != NULL && gentry != NULL && trivial == B_TRUE)
			centry->a_perm = gentry->a_perm;
	}
	*aclpp = new_aclp;	/* return new acl entries */
	return (0);
}

static void
usage()
{
	(void) fprintf(stderr, gettext("usage:\n"));
	(void) fprintf(stderr,
	    gettext("\tsetfacl [-r] -f aclfile file ...\n"));
	(void) fprintf(stderr,
	    gettext("\tsetfacl [-r] -d acl_entries file ...\n"));
	(void) fprintf(stderr,
	    gettext("\tsetfacl [-r] -m acl_entries file ...\n"));
	(void) fprintf(stderr,
	    gettext("\tsetfacl [-r] -s acl_entries file ...\n"));
	exit(1);
}

static void
err_handle(int cnt, aclent_t *aclentp)
{
	int	rc;
	int	which;

	rc = aclcheck(aclentp, cnt, &which);
	switch (rc) {
	case USER_ERROR:
		fprintf(stderr,
		    gettext("There is more than one user owner entry"));
		fprintf(stderr,
		    gettext(" -- error found at entry index %d\n"), which);
		break;
	case GRP_ERROR:
		fprintf(stderr,
		    gettext("There is more than one group owner entry"));
		fprintf(stderr,
		    gettext(" -- error found at entry index %d\n"), which);
		break;
	case CLASS_ERROR:
		fprintf(stderr,
		    gettext("There is more than one mask entry"));
		fprintf(stderr,
		    gettext(" -- error found at entry index %d\n"), which);
		break;
	case OTHER_ERROR:
		fprintf(stderr,
		    gettext("There is more than one other entry"));
		fprintf(stderr,
		    gettext(" -- error found at entry index %d\n"), which);
		break;
	case DUPLICATE_ERROR:
		fprintf(stderr,
		    gettext("Duplicate user or group entries"));
		fprintf(stderr,
		    gettext(" -- error found at entry index %d\n"), which);
		break;
	case MISS_ERROR:
		fprintf(stderr,
		    gettext("Missing user/group owner, other, mask entry\n"));
		break;
	case MEM_ERROR:
		fprintf(stderr,
		    gettext("Insufficient memory\n"));
		break;
	case ENTRY_ERROR:
		fprintf(stderr,
		    gettext("Unrecognized entry type"));
		fprintf(stderr,
		    gettext(" -- error found at entry index %d\n"), which);
		break;
	default:
		/* error is not from aclcheck */
		fprintf(stderr,
		    gettext("aclsort error\n"));
		break;
	}
}

static int
parse_entry(char *fieldp, aclent_t *aclentp, int mode)
{
	char		*colonp;
	int		def_flag = 0, mo_flag = 0;
	int		id;
	struct passwd	*pwp;
	struct group	*grp;

	colonp = (char *)strchr(fieldp, ':');
	if (colonp == NULL) {
		fprintf(stderr,
		    gettext("Can't find colon delimiter %s\n"), fieldp);
		return (-1);
	}
	*colonp = '\0';
	if ((strcmp(fieldp, "default") == 0) || (strcmp(fieldp, "d") == 0)) {
		def_flag++;
		fieldp = ++colonp;
		colonp = (char *)strchr(fieldp, ':');
		if (colonp == NULL) {
			fprintf(stderr,
			    gettext("Can't find colon delimiter %s\n"), fieldp);
			return (-1);
		}
		*colonp = '\0';
	}

	/* process entry type */
	if ((strcmp(fieldp, "user") == 0) || (strcmp(fieldp, "u") == 0)) {
		if (def_flag)
			aclentp->a_type = DEF_USER;
		else
			aclentp->a_type = USER;
	}
	if ((strcmp(fieldp, "group") == 0) || (strcmp(fieldp, "g") == 0)) {
		if (def_flag)
			aclentp->a_type = DEF_GROUP;
		else
			aclentp->a_type = GROUP;
	}
	if ((strcmp(fieldp, "mask") == 0) || (strcmp(fieldp, "m") == 0)) {
		if (def_flag)
			aclentp->a_type = DEF_CLASS_OBJ;
		else
			aclentp->a_type = CLASS_OBJ;
	}
	if ((strcmp(fieldp, "other") == 0) || (strcmp(fieldp, "o") == 0)) {
		if (def_flag)
			aclentp->a_type = DEF_OTHER_OBJ;
		else
			aclentp->a_type = OTHER_OBJ;
	}

	/* still can't determine entry type */
	if (aclentp->a_type == 0) {
		fprintf(stderr,
		    gettext("Unrecognized entry type %s \n"), fieldp);
		return (-1);
	}

	/* mask and other entries dont have id field */
	if (aclentp->a_type != CLASS_OBJ && aclentp->a_type != OTHER_OBJ &&
	    aclentp->a_type != DEF_CLASS_OBJ &&
	    aclentp->a_type != DEF_OTHER_OBJ) {
		/* process id: */
		fieldp = ++colonp;
		colonp = (char *)strchr(fieldp, ':');
		if (colonp == NULL) {
			if (mode != DELETE) {
				fprintf(stderr,
				    gettext("Can't find colon delimiter %s\n"),
				    fieldp);
				return (-1);
			}
		} else
			*colonp = '\0';

		if (*fieldp == '\0') {
			/* empty uid */
			if (aclentp->a_type == USER)
				aclentp->a_type = USER_OBJ;
			if (aclentp->a_type == DEF_USER)
				aclentp->a_type = DEF_USER_OBJ;
			if (aclentp->a_type == GROUP)
				aclentp->a_type = GROUP_OBJ;
			if (aclentp->a_type == DEF_GROUP)
				aclentp->a_type = DEF_GROUP_OBJ;
		} else {
			/* see if it's a user/group name */
			if (aclentp->a_type == USER ||
			    aclentp->a_type == USER_OBJ ||
			    aclentp->a_type == DEF_USER ||
			    aclentp->a_type == DEF_USER_OBJ) {
				if ((pwp = getpwnam(fieldp)) != NULL)
					aclentp->a_id = pwp->pw_uid;
				else {
					/* treat it as numeric id */
					id = conv_id(fieldp);
					if (id == -1)
						return (-1);
					aclentp->a_id = id;
				}
			} else {
				/* group name */
				if ((grp = getgrnam(fieldp)) != NULL)
					aclentp->a_id = grp->gr_gid;
				else {
					id = conv_id(fieldp);
					if (id == -1)
						return (-1);
					aclentp->a_id = id;
				}
			}
		}
	} else {
		/* it is mask/other entry */
		mo_flag = 1;
	}

	/* process permission: rwx and [0]n  format */
	if (mode == DELETE)
		/* delete format: no permission field */
		return (0);
	fieldp = ++colonp;
	colonp = (char *)strchr(fieldp, ':');
	if (colonp != NULL) {
		if (mo_flag == 1) {
			/* Use only single : on mask/other entry */
			(void) fprintf(stderr, gettext("use only 1 colon for "
			    "mask and other entries.\n"));
			return (-1);
		} else {
			/* it's ok to have extra colon */
			*colonp = '\0';
		}
	}

	if ((int)strlen(fieldp) > 3) {
		fprintf(stderr,
		    gettext("only rwx or [0]n format is allowed\n"));
		return (-1);
	}
	if (strlen(fieldp) == 3) {
		aclentp->a_perm = 0;
		/* treat it as rwx */
		if (*fieldp == 'r')
			aclentp->a_perm += 4;
		else
			if (*fieldp != '-') {
				fprintf(stderr,
				    gettext("Unrecognized character "));
				fprintf(stderr,
				    gettext("found in mode field\n"));
				return (-1);
			}
		fieldp++;
		if (*fieldp == 'w')
			aclentp->a_perm += 2;
		else
			if (*fieldp != '-') {
				fprintf(stderr,
				    gettext("Unrecognized character "));
				fprintf(stderr,
				    gettext("found in mode field\n"));
				return (-1);
			}
		fieldp++;
		if (*fieldp == 'x')
			aclentp->a_perm += 1;
		else
			if (*fieldp != '-') {
				fprintf(stderr,
				    gettext("Unrecognized character "));
				fprintf(stderr,
				    gettext("found in mode field\n"));
				return (-1);
			}
		return (0);
	}

	if (*fieldp == '\0')
		return (0);

	if (*fieldp >= '0' && *fieldp <= '7')
		aclentp->a_perm = *fieldp - '0';
	else {
		fprintf(stderr, gettext("Unrecognized character "));
		fprintf(stderr, gettext("found in mode field\n"));
		return (-1);
	}
	if (aclentp->a_perm == 0 && *++fieldp != '\0') {
		/* look at next char */
		if (*fieldp >= '0' && *fieldp <= '7')
			aclentp->a_perm = *fieldp - '0';
		else {
			fprintf(stderr, gettext("Unrecognized character "));
			fprintf(stderr, gettext("found in mode field\n"));
			fprintf(stderr,
			    gettext("Check also the number of fields "));
			fprintf(stderr,
			    gettext("(default) mask and other entries\n"));
			return (-1);
		}
	}
	/* check for junk at the end ??? */
	return (0);
}

/*
 * This function is different from atoi() in that it checks for
 * valid digit in the id field whereas atoi() won't report any
 * error.
 */
static int
conv_id(char *fieldp)
{
	int	a_id = 0;

	for (; *fieldp != '\0'; fieldp++) {
		if (!isdigit(*fieldp)) {
			fprintf(stderr, gettext("non-digit in id field\n"));
			return (-1);
		}
		a_id = a_id * 10 + (*fieldp - '0');
	}
	return (a_id);
}
