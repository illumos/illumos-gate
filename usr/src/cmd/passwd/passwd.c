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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

/*
 * passwd is a program whose sole purpose is to manage
 * the password file, map, or table. It allows system administrator
 * to add, change and display password attributes.
 * Non privileged user can change password or display
 * password attributes which corresponds to their login name.
 */

#include <stdio.h>
#include <pwd.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <locale.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>
#include <rpcsvc/nis.h>
#undef GROUP
#include <syslog.h>
#include <userdefs.h>
#include <passwdutil.h>

#include <nss_dbdefs.h>

#include <deflt.h>

#undef	GROUP
#include <bsm/adt.h>
#include <bsm/adt_event.h>

/*
 * flags indicate password attributes to be modified
 */

#define	LFLAG 0x001		/* lock user's password  */
#define	DFLAG 0x002		/* delete user's  password */
#define	MFLAG 0x004		/* set max field -- # of days passwd is valid */
#define	NFLAG 0x008		/* set min field -- # of days between */
				/* password changes */
#define	SFLAG 0x010		/* display password attributes */
#define	FFLAG 0x020		/* expire  user's password */
#define	AFLAG 0x040		/* display password attributes for all users */
#define	SAFLAG (SFLAG|AFLAG)	/* display password attributes for all users */
#define	WFLAG 0x100		/* warn user to change passwd */
#define	OFLAG 0x200		/* domain name */
#define	EFLAG 0x400		/* change shell */
#define	GFLAG 0x800		/* change gecos information */
#define	HFLAG 0x1000		/* change home directory */
#define	XFLAG 0x2000		/* no login */
#define	UFLAG 0x4000		/* unlock user's password */

#define	NONAGEFLAG	(EFLAG | GFLAG | HFLAG)
#define	AGEFLAG	(LFLAG | FFLAG | MFLAG | NFLAG | WFLAG | XFLAG | UFLAG)
#define	MUTEXFLAG	(DFLAG | LFLAG | XFLAG | UFLAG | SAFLAG)


/*
 * exit code
 */

#define	SUCCESS	0	/* succeeded */
#define	NOPERM	1	/* No permission */
#define	BADOPT	2	/* Invalid combination of option */
#define	FMERR	3	/* File/table manipulation error */
#define	FATAL	4	/* Old file/table can not be recovered */
#define	FBUSY	5	/* Lock file/table busy */
#define	BADSYN	6	/* Incorrect syntax */
#define	BADAGE	7	/* Aging is disabled  */
#define	NOMEM	8	/* No memory */
#define	SYSERR	9	/* System error */
#define	EXPIRED	10	/* Account expired */

/*
 * define error messages
 */
#define	MSG_NP		"Permission denied"
#define	MSG_BS		"Invalid combination of options"
#define	MSG_FE		"Unexpected failure. Password file/table unchanged."
#define	MSG_FF		"Unexpected failure. Password file/table missing."
#define	MSG_FB		"Password file/table busy. Try again later."
#define	MSG_NV  	"Invalid argument to option"
#define	MSG_AD		"Password aging is disabled"
#define	MSG_RS		"Cannot change from restricted shell %s\n"
#define	MSG_NM		"Out of memory."
#define	MSG_UNACCEPT	"%s is unacceptable as a new shell\n"
#define	MSG_UNAVAIL	"warning: %s is unavailable on this machine\n"
#define	MSG_COLON	"':' is not allowed.\n"
#define	MSG_MAXLEN	"Maximum number of characters allowed is %d."
#define	MSG_CONTROL	"Control characters are not allowed.\n"
#define	MSG_SHELL_UNCHANGED	"Login shell unchanged.\n"
#define	MSG_GECOS_UNCHANGED	"Finger information unchanged.\n"
#define	MSG_DIR_UNCHANGED	"Homedir information unchanged.\n"
#define	MSG_NAME	"\nName [%s]: "
#define	MSG_HOMEDIR	"\nHome Directory [%s]: "
#define	MSG_OLDSHELL	"Old shell: %s\n"
#define	MSG_NEWSHELL	"New shell: "
#define	MSG_AGAIN	"\nPlease try again\n"
#define	MSG_INPUTHDR	"Default values are printed inside of '[]'.\n" \
			"To accept the default, type <return>.\n" \
			"To have a blank entry, type the word 'none'.\n"
#define	MSG_UNKNOWN	"%s: User unknown: %s\n"
#define	MSG_ACCOUNT_EXP	"User account has expired: %s\n"
#define	MSG_AUTHTOK_EXP	"Your password has been expired for too long.\n" \
			"Please contact the system administrator.\n"
#define	MSG_NIS_HOMEDIR	"-h does not apply to NIS"
#define	MSG_CUR_PASS	"Enter existing login password: "
#define	MSG_CUR_PASS_UNAME	"Enter %s's existing login password: "
#define	MSG_SUCCESS	"%s: password information changed for %s\n"
#define	MSG_SORRY	"%s: Sorry, wrong passwd\n"
#define	MSG_INFO	"%s: Changing password for %s\n"


/*
 * return code from ckarg() routine
 */
#define	FAIL 		-1

/*
 *  defind password file name
 */
#define	PASSWD 			"/etc/passwd"

#define	MAX_INPUT_LEN		512

#define	DEF_ATTEMPTS	3

/* Number of characters in that make up an encrypted password (for now) */
#define	NUMCP			13

#ifdef DEBUG
#define	dprintf1	printf
#else
#define	dprintf1(w, x)
#endif

extern int	optind;

static int		retval = SUCCESS;
static int		pam_retval = PAM_SUCCESS;
static uid_t		uid;
static char		*prognamep;
static long		maxdate;	/* password aging information */
static int		passwd_conv(int, struct pam_message **,
			    struct pam_response **, void *);
static struct pam_conv	pam_conv = {passwd_conv, NULL};
static pam_handle_t	*pamh;		/* Authentication handle */
static char		*usrname;	/* user whose attribute we update */
static adt_session_data_t *ah;  /* audit session handle */
static adt_event_data_t *event = NULL; /* event to be generated */

static pam_repository_t	auth_rep;
static pwu_repository_t	repository;
static pwu_repository_t	__REPFILES = { "files", NULL, 0 };

/*
 * Function Declarations
 */

extern	void		setusershell(void);
extern	char		*getusershell(void);
extern	void		endusershell(void);

static	void		passwd_exit(int retcode) __NORETURN;
static	void		rusage(void);
static	int		ckuid(void);
static	int		ckarg(int argc, char **argv, attrlist **attributes);

static	int		get_namelist(pwu_repository_t, char ***, int *);
static	int		get_namelist_files(char ***, int *);
static	int		get_namelist_local(char ***, int *);
static	int		get_attr(char *, pwu_repository_t *, attrlist **);
static	void		display_attr(char *, attrlist *);
static	void		free_attr(attrlist *);
static	void		attrlist_add(attrlist **, attrtype, char *);
static	void		attrlist_reorder(attrlist **);
static	char		*userinput(char *, pwu_repository_t *, attrtype);
static	char		*getresponse(char *);

/*
 * main():
 *	The main routine will call ckarg() to parse the command line
 *	arguments and call the appropriate functions to perform the
 *	tasks specified by the arguments. It allows system
 * 	administrator to add, change and display password attributes.
 * 	Non privileged user can change password or display
 * 	password attributes which corresponds to their login name.
 */

int
main(int argc, char *argv[])
{

	int	flag;
	char	**namelist;
	int	num_user;
	int	i;
	attrlist *attributes = NULL;
	char	*input;
	int	tries = 1;
	int	updated_reps;


	if ((prognamep = strrchr(argv[0], '/')) != NULL)
		++prognamep;
	else
		prognamep = argv[0];

	auth_rep.type = NULL;
	auth_rep.scope = NULL;
	repository.type = NULL;
	repository.scope = NULL;
	repository.scope_len = 0;


	/* initialization for variables, set locale and textdomain  */
	i = 0;
	flag = 0;

	uid = getuid();		/* get the user id */
	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * ckarg() parses the arguments. In case of an error,
	 * it sets the retval and returns FAIL (-1).
	 */

	flag = ckarg(argc, argv, &attributes);
	dprintf1("flag is %0x\n", flag);
	if (flag == FAIL)
		passwd_exit(retval);

	argc -= optind;

	if (argc < 1) {
		if ((usrname = getlogin()) == NULL) {
			struct passwd *pass = getpwuid(uid);
			if (pass != NULL)
				usrname = pass->pw_name;
			else {
				rusage();
				exit(NOPERM);
			}
		} else if (flag == 0) {
			/*
			 * If flag is zero, change passwd.
			 * Otherwise, it will display or
			 * modify password aging attributes
			 */
			(void) fprintf(stderr, gettext(MSG_INFO), prognamep,
			    usrname);
		}
	} else {
		usrname = argv[optind];
	}

	if (pam_start("passwd", usrname, &pam_conv, &pamh) != PAM_SUCCESS) {
		passwd_exit(NOPERM);
	}

	auth_rep.type = repository.type;
	auth_rep.scope = repository.scope;
	auth_rep.scope_len = repository.scope_len;

	if (auth_rep.type != NULL) {
		if (pam_set_item(pamh, PAM_REPOSITORY, (void *)&auth_rep)
		    != PAM_SUCCESS) {
			passwd_exit(NOPERM);
		}
	}

	if (flag ==  SAFLAG) {	/* display password attributes for all users */
		retval = get_namelist(repository, &namelist, &num_user);
		if (retval != SUCCESS)
			(void) passwd_exit(retval);

		if (num_user == 0) {
			(void) fprintf(stderr, "%s: %s\n", prognamep,
			    gettext(MSG_FF));
			passwd_exit(FATAL);
		}
		i = 0;
		while (namelist[i] != NULL) {
			(void) get_attr(namelist[i], &repository,
			    &attributes);
			(void) display_attr(namelist[i], attributes);
			(void) free(namelist[i]);
			(void) free_attr(attributes);
			i++;
		}
		(void) free(namelist);
		passwd_exit(SUCCESS);
	} else if (flag == SFLAG) { /* display password attributes by user */
		if (get_attr(usrname, &repository, &attributes) ==
		    PWU_SUCCESS) {
			(void) display_attr(usrname, attributes);
			(void) free_attr(attributes);
		}
		passwd_exit(SUCCESS);
		/* NOT REACHED */
	}


	switch (pam_authenticate(pamh, 0)) {
	case PAM_SUCCESS:
		break;
	case PAM_USER_UNKNOWN:
		(void) fprintf(stderr, gettext(MSG_UNKNOWN), prognamep,
		    usrname);
		passwd_exit(NOPERM);
		break;
	case PAM_PERM_DENIED:
		passwd_exit(NOPERM);
		break;
	case PAM_AUTH_ERR:
		(void) fprintf(stderr, gettext(MSG_SORRY), prognamep);
		passwd_exit(NOPERM);
		break;
	default:
		/* system error */
		passwd_exit(FMERR);
		break;
	}

	if (flag == 0) {			/* changing user password */
		int	chk_authtok = 0;	/* check password strength */

		dprintf1("call pam_chauthtok() repository name =%s\n",
		    repository.type);

		/* Set up for Audit */
		if (adt_start_session(&ah, NULL, ADT_USE_PROC_DATA) != 0) {
			perror("adt_start_session");
			passwd_exit(SYSERR);
		}
		if ((event = adt_alloc_event(ah, ADT_passwd)) == NULL) {
			perror("adt_alloc_event");
			passwd_exit(NOMEM);
		}

		/* Don't check account expiration when invoked by root */
		if (ckuid() != SUCCESS) {
			pam_retval = pam_acct_mgmt(pamh, PAM_SILENT);
			switch (pam_retval) {
			case PAM_ACCT_EXPIRED:
				(void) fprintf(stderr,
				    gettext(MSG_ACCOUNT_EXP), usrname);
				passwd_exit(EXPIRED);
				break;
			case PAM_AUTHTOK_EXPIRED:
				(void) fprintf(stderr,
				    gettext(MSG_AUTHTOK_EXP));
				passwd_exit(NOPERM);
				break;
			case PAM_NEW_AUTHTOK_REQD:
				/* valid error when changing passwords */
				break;
			case PAM_SUCCESS:
				/* Ok to change password */
				break;
			default:
				passwd_exit(NOPERM);
			}
		}


		pam_retval = PAM_AUTHTOK_ERR;
		tries = 1;
		if (ckuid() == SUCCESS) {
			/* bypass password strength checks */
			chk_authtok = PAM_NO_AUTHTOK_CHECK;
		}

		while (pam_retval == PAM_AUTHTOK_ERR && tries <= DEF_ATTEMPTS) {
			if (tries > 1)
				(void) printf(gettext(MSG_AGAIN));
			pam_retval = pam_chauthtok(pamh, chk_authtok);
			if (pam_retval == PAM_TRY_AGAIN) {
				(void) sleep(1);
				pam_retval = pam_chauthtok(pamh, chk_authtok);
			}
			tries++;
		}

		switch (pam_retval) {
		case PAM_SUCCESS:
			retval = SUCCESS;
			break;
		case PAM_AUTHTOK_DISABLE_AGING:
			retval = BADAGE;
			break;
		case PAM_AUTHTOK_LOCK_BUSY:
			retval = FBUSY;
			break;
		case PAM_TRY_AGAIN:
			retval = FBUSY;
			break;
		case PAM_AUTHTOK_ERR:
		case PAM_AUTHTOK_RECOVERY_ERR:
		default:
			retval = NOPERM;
			break;
		}

		(void) passwd_exit(retval);
		/* NOT REACHED */
	} else {		/* changing attributes */
		switch (flag) {
		case EFLAG:		/* changing user password attributes */
			input = userinput(usrname, &repository, ATTR_SHELL);
			if (input)
				attrlist_add(&attributes, ATTR_SHELL, input);
			else
				(void) printf(gettext(MSG_SHELL_UNCHANGED));
			break;
		case GFLAG:
			input = userinput(usrname, &repository, ATTR_GECOS);
			if (input)
				attrlist_add(&attributes, ATTR_GECOS, input);
			else
				(void) printf(gettext(MSG_GECOS_UNCHANGED));
			break;
		case HFLAG:
			input = userinput(usrname, &repository, ATTR_HOMEDIR);
			if (input)
				attrlist_add(&attributes, ATTR_HOMEDIR, input);
			else
				(void) printf(gettext(MSG_DIR_UNCHANGED));
			break;
		}

		if (attributes != NULL) {
			retval = __set_authtoken_attr(usrname,
			    pamh->ps_item[PAM_AUTHTOK].pi_addr,
			    &repository, attributes, &updated_reps);
			switch (retval) {
			case PWU_SUCCESS:
				for (i = 1; i <= REP_LAST; i <<= 1) {
					if ((updated_reps & i) == 0)
						continue;
					(void) printf(gettext(MSG_SUCCESS),
					    prognamep, usrname);
				}
				retval = SUCCESS;
				break;
			case PWU_AGING_DISABLED:
				retval = BADAGE;
				break;
			default:
				retval = NOPERM;
				break;
			}
		} else {
			retval = SUCCESS; /* nothing to change won't fail */
		}
		(void) passwd_exit(retval);
	}
	/* NOTREACHED */
	return (0);
}

/*
 * Get a line of input from the user.
 *
 * If the line is empty, or the input equals 'oldval', NULL is returned.
 * therwise, a malloced string containing the input (minus the trailing
 * newline) is returned.
 */
char *
getresponse(char *oldval)
{
	char    resp[MAX_INPUT_LEN];
	char    *retval = NULL;
	int	resplen;

	(void) fgets(resp, sizeof (resp) - 1, stdin);
	resplen = strlen(resp) - 1;
	if (resp[resplen] == '\n')
		resp[resplen] = '\0';
	if (*resp != '\0' && strcmp(resp, oldval) != 0)
		retval = strdup(resp);
	return (retval);
}

/*
 * char *userinput(item)
 *
 * user conversation function. The old value of attribute "item" is
 * displayed while the user is asked to provide a new value.
 *
 * returns a malloc()-ed string if the user actualy provided input
 * or NULL if the user simply hit return or the input equals the old
 * value (not changed).
 */
char *
userinput(char *name, pwu_repository_t *rep, attrtype type)
{
	attrlist oldattr;
	char *oldval;			/* shorthand for oldattr.data.val_s */
	char *valid;			/* points to valid shells */
	char *response;
	char *cp;

	oldattr.type = type;
	oldattr.next = NULL;

	if (__get_authtoken_attr(name, rep, &oldattr) != PWU_SUCCESS)
		passwd_exit(FMERR);

	oldval = oldattr.data.val_s;

	if (type == ATTR_SHELL) {
		/* No current shell: set DEFSHL as default choice */
		if (*oldval == '\0') {
			free(oldval);
			oldval = strdup(DEFSHL);
		}

		if (ckuid() != SUCCESS) {
			/* User must currently have a valid shell */
			setusershell();
			valid = getusershell();
			while (valid && strcmp(valid, oldval) != 0)
				valid = getusershell();
			endusershell();

			if (valid == NULL) {
				(void) fprintf(stderr, gettext(MSG_RS), oldval);
				free(oldval);
				return (NULL);
			}
		}
		(void) printf(gettext(MSG_OLDSHELL), oldval);
		(void) printf(gettext(MSG_NEWSHELL));
		(void) fflush(stdout);

		response = getresponse(oldval);
		free(oldval); /* We don't need the old value anymore */

		if (response == NULL || *response == '\0')
			return (NULL);

		/* Make sure new shell is listed */
		setusershell();
		valid = getusershell();
		while (valid) {
			char *cp;

			/* Allow user to give shell without path */
			if (*response == '/') {
				cp = valid;
			} else {
				if ((cp = strrchr(valid, '/')) == NULL)
					cp = valid;
				else
					cp++;
			}
			if (strcmp(cp, response) == 0) {
				if (*response != '/') {
					/* take shell name including path */
					free(response);
					response = strdup(valid);
				}
				break;
			}
			valid = getusershell();
		}
		endusershell();

		if (valid == NULL) {    /* No valid shell matches */
			(void) fprintf(stderr, gettext(MSG_UNACCEPT), response);
			return (NULL);
		}

		if (access(response, X_OK) < 0)
			(void) fprintf(stderr, gettext(MSG_UNAVAIL), response);
		return (response);
		/* NOT REACHED */
	}
	/*
	 * if type == SHELL, we have returned by now. Only GECOS and
	 * HOMEDIR get to this point.
	 */
	(void) printf(gettext(MSG_INPUTHDR));

	/*
	 * PRE: oldval points to malloced string with Old Value
	 * INV: oldval remains unchanged
	 * POST:response points to valid string or NULL.
	 */
	for (;;) {
		if (type == ATTR_GECOS)
			(void) printf(gettext(MSG_NAME), oldval);
		else if (type == ATTR_HOMEDIR)
			(void) printf(gettext(MSG_HOMEDIR), oldval);

		response = getresponse(oldval);

		if (response && strcmp(response, "none") == 0)
			*response = '\0';

		/* No-change or empty string are OK */
		if (response == NULL || *response == '\0')
			break;

		/* Check for illegal characters */
		if (strchr(response, ':')) {
			(void) fprintf(stderr, "%s", gettext(MSG_COLON));
			free(response);
		} else if (strlen(response) > MAX_INPUT_LEN - 1) {
			(void) fprintf(stderr, gettext(MSG_MAXLEN),
			    MAX_INPUT_LEN);
			free(response);
		} else {
			/* don't allow control characters */
			for (cp = response; *cp >= 040; cp++)
				;
			if (*cp != '\0') {
				(void) fprintf(stderr, gettext(MSG_CONTROL));
				free(response);
			} else
				break;	/* response is a valid string */
		}
		/*
		 * We only get here if the input was invalid.
		 * In that case, we again ask the user for input.
		 */
	}
	free(oldval);
	return (response);
}
/*
 * ckarg():
 *	This function parses and verifies the
 * 	arguments.  It takes three parameters:
 * 	argc => # of arguments
 * 	argv => pointer to an argument
 * 	attrlist => pointer to list of password attributes
 */

static int
ckarg(int argc, char **argv, attrlist **attributes)
{
	extern char	*optarg;
	char		*char_p;
	int	opt;
	int	flag;

	flag = 0;

	while ((opt = getopt(argc, argv, "r:aldefghsux:n:w:N")) != EOF) {
		switch (opt) {

		case 'r': /* Repository Specified */
			/* repository: this option should be specified first */

			if (repository.type != NULL) {
				(void) fprintf(stderr, gettext(
			"Repository is already defined or specified.\n"));
				rusage();
				retval = BADSYN;
				return (FAIL);
			}
			if (strcmp(optarg, "nis") == 0) {
				repository.type = optarg;
			} else if (strcmp(optarg, "ldap") == 0) {
				repository.type = optarg;
			} else if (strcmp(optarg, "files") == 0) {
				repository.type = optarg;
			} else {
				(void) fprintf(stderr,
				    gettext("invalid repository: %s\n"),
				    optarg);
				rusage();
				retval = BADSYN;
				return (FAIL);
			}
			break;

		case 'd': /* Delete Auth Token */
			/* if no repository the default for -d is files */
			if (repository.type == NULL)
				repository = __REPFILES;

			/*
			 * Delete the password - only privileged processes
			 * can execute this for FILES or LDAP
			 */
			if (IS_FILES(repository) == FALSE &&
			    IS_LDAP(repository) == FALSE) {
				(void) fprintf(stderr, gettext(
				    "-d only applies to files "
				    "or ldap repository\n"));
				rusage();	/* exit */
				retval = BADSYN;
				return (FAIL);
			}

			if (ckuid() != SUCCESS) {
				retval = NOPERM;
				return (FAIL);
			}
			if (flag & (LFLAG|SAFLAG|DFLAG|XFLAG|UFLAG)) {
				rusage();
				retval = BADOPT;
				return (FAIL);
			}
			flag |= DFLAG;
			attrlist_add(attributes, ATTR_PASSWD, NULL);
			break;

		case 'N': /* set account to be "no login" */

			/* if no repository the default for -N is files */
			if (repository.type == NULL)
				repository = __REPFILES;

			if (IS_FILES(repository) == FALSE &&
			    IS_LDAP(repository) == FALSE) {
				(void) fprintf(stderr, gettext(
				    "-N only applies to files or ldap "
				    "repository\n"));
				rusage();	/* exit */
				retval = BADOPT;
				return (FAIL);
			}

			/*
			 * Only privileged processes can execute this
			 * for FILES or LDAP
			 */
			if ((IS_FILES(repository) || IS_LDAP(repository)) &&
			    ((retval = ckuid()) != SUCCESS))
				return (FAIL);
			if (flag & (MUTEXFLAG|NONAGEFLAG)) {
				rusage();	/* exit */
				retval = BADOPT;
				return (FAIL);
			}
			flag |= XFLAG;
			attrlist_add(attributes, ATTR_NOLOGIN_ACCOUNT, NULL);
			break;

		case 'l': /* lock the password */

			/* if no repository the default for -l is files */
			if (repository.type == NULL)
				repository = __REPFILES;

			if (IS_FILES(repository) == FALSE &&
			    IS_LDAP(repository) == FALSE) {
				(void) fprintf(stderr, gettext(
				    "-l only applies to files or ldap "
				    "repository\n"));
				rusage();	/* exit */
				retval = BADOPT;
				return (FAIL);
			}

			/*
			 * Only privileged processes can execute this
			 * for FILES or LDAP
			 */
			if ((IS_FILES(repository) || IS_LDAP(repository)) &&
			    ((retval = ckuid()) != SUCCESS))
				return (FAIL);
			if (flag & (MUTEXFLAG|NONAGEFLAG)) {
				rusage();	/* exit */
				retval = BADOPT;
				return (FAIL);
			}
			flag |= LFLAG;
			attrlist_add(attributes, ATTR_LOCK_ACCOUNT, NULL);
			break;

		case 'u': /* unlock the password */

			/* if no repository the default for -u is files */
			if (repository.type == NULL)
				repository = __REPFILES;

			if (IS_FILES(repository) == FALSE &&
			    IS_LDAP(repository) == FALSE) {
				(void) fprintf(stderr, gettext(
				    "-u only applies to files or ldap "
				    "repository\n"));
				rusage();	/* exit */
				retval = BADOPT;
				return (FAIL);
			}

			/*
			 * Only privileged processes can execute this
			 * for FILES or LDAP
			 */
			if ((IS_FILES(repository) || IS_LDAP(repository)) &&
			    ((retval = ckuid()) != SUCCESS))
				return (FAIL);
			if (flag & (MUTEXFLAG|NONAGEFLAG)) {
				rusage();	/* exit */
				retval = BADOPT;
				return (FAIL);
			}
			flag |= UFLAG;
			attrlist_add(attributes, ATTR_UNLOCK_ACCOUNT, NULL);
			attrlist_add(attributes, ATTR_RST_FAILED_LOGINS, NULL);
			break;

		case 'x': /* set the max date */

			/* if no repository the default for -x is files */
			if (repository.type == NULL)
				repository = __REPFILES;

			if (IS_FILES(repository) == FALSE &&
			    IS_LDAP(repository) == FALSE) {
				(void) fprintf(stderr, gettext(
				    "-x only applies to files or ldap "
				    "repository\n"));
				rusage();	/* exit */
				retval = BADSYN;
				return (FAIL);
			}

			/*
			 * Only privileged process can execute this
			 * for FILES or LDAP
			 */
			if ((IS_FILES(repository) || IS_LDAP(repository)) &&
			    (ckuid() != SUCCESS)) {
				retval = NOPERM;
				return (FAIL);
			}
			if (flag & (SAFLAG|MFLAG|NONAGEFLAG)) {
				retval = BADOPT;
				return (FAIL);
			}
			flag |= MFLAG;
			if ((int)strlen(optarg)  <= 0 ||
			    (maxdate = strtol(optarg, &char_p, 10)) < -1 ||
			    *char_p != '\0') {
				(void) fprintf(stderr, "%s: %s -x\n",
				    prognamep, gettext(MSG_NV));
				retval = BADSYN;
				return (FAIL);
			}
			attrlist_add(attributes, ATTR_MAX, optarg);
			break;

		case 'n': /* set the min date */

			/* if no repository the default for -n is files */
			if (repository.type == NULL)
				repository = __REPFILES;

			if (IS_FILES(repository) == FALSE &&
			    IS_LDAP(repository) == FALSE) {
				(void) fprintf(stderr, gettext(
				    "-n only applies to files or ldap "
				    "repository\n"));
				rusage();	/* exit */
				retval = BADSYN;
				return (FAIL);
			}

			/*
			 * Only privileged process can execute this
			 * for FILES or LDAP
			 */
			if ((IS_FILES(repository) || IS_LDAP(repository)) &&
			    ((retval = ckuid()) != SUCCESS))
				return (FAIL);
			if (flag & (SAFLAG|NFLAG|NONAGEFLAG)) {
				retval = BADOPT;
				return (FAIL);
			}
			flag |= NFLAG;
			if ((int)strlen(optarg)  <= 0 ||
			    (strtol(optarg, &char_p, 10)) < 0 ||
			    *char_p != '\0') {
				(void) fprintf(stderr, "%s: %s -n\n",
				    prognamep, gettext(MSG_NV));
				retval = BADSYN;
				return (FAIL);
			}
			attrlist_add(attributes, ATTR_MIN, optarg);
			break;

		case 'w': /* set the warning field */

			/* if no repository the default for -w is files */
			if (repository.type == NULL)
				repository = __REPFILES;

			if (IS_FILES(repository) == FALSE &&
			    IS_LDAP(repository) == FALSE) {
				(void) fprintf(stderr, gettext(
				    "-w only applies to files or ldap "
				    "repository\n"));
				rusage();	/* exit */
				retval = BADSYN;
				return (FAIL);
			}

			/*
			 * Only privileged process can execute this
			 * for FILES or LDAP
			 */
			if ((IS_FILES(repository) || IS_LDAP(repository)) &&
			    (ckuid() != SUCCESS)) {
				retval = NOPERM;
				return (FAIL);
			}
			if (flag & (SAFLAG|WFLAG|NONAGEFLAG)) {
				retval = BADOPT;
				return (FAIL);
			}
			flag |= WFLAG;
			if ((int)strlen(optarg)  <= 0 ||
			    (strtol(optarg, &char_p, 10)) < 0 ||
			    *char_p != '\0') {
				(void) fprintf(stderr, "%s: %s -w\n",
				    prognamep, gettext(MSG_NV));
				retval = BADSYN;
				return (FAIL);
			}
			attrlist_add(attributes, ATTR_WARN, optarg);
			break;

		case 's': /* display password attributes */

			/* if no repository the default for -s is files */
			if (repository.type == NULL)
				repository = __REPFILES;


			/* display password attributes */
			if (IS_FILES(repository) == FALSE &&
			    IS_LDAP(repository) == FALSE) {
				(void) fprintf(stderr, gettext(
				    "-s only applies to files or ldap "
				    "repository\n"));
				rusage();	/* exit */
				retval = BADSYN;
				return (FAIL);
			}

			/*
			 * Only privileged process can execute this
			 * for FILES or LDAP
			 */
			if ((IS_FILES(repository) || IS_LDAP(repository)) &&
			    ((retval = ckuid()) != SUCCESS))
				return (FAIL);
			if (flag && (flag != AFLAG)) {
				retval = BADOPT;
				return (FAIL);
			}
			flag |= SFLAG;
			break;

		case 'a': /* display password attributes */

			/* if no repository the default for -a is files */
			if (repository.type == NULL)
				repository = __REPFILES;

			if (IS_FILES(repository) == FALSE &&
			    IS_LDAP(repository) == FALSE) {
				(void) fprintf(stderr, gettext(
				    "-a only applies to files or ldap "
				    "repository\n"));
				rusage();	/* exit */
				retval = BADSYN;
				return (FAIL);
			}

			/*
			 * Only privileged process can execute this
			 * for FILES or LDAP
			 */
			if ((IS_FILES(repository) || IS_LDAP(repository)) &&
			    ((retval = ckuid()) != SUCCESS))
				return (FAIL);
			if (flag && (flag != SFLAG)) {
				retval = BADOPT;
				return (FAIL);
			}
			flag |= AFLAG;
			break;

		case 'f': /* expire password attributes	*/

			/* if no repository the default for -f is files */
			if (repository.type == NULL)
				repository = __REPFILES;

			if (IS_FILES(repository) == FALSE &&
			    IS_LDAP(repository) == FALSE) {
				(void) fprintf(stderr, gettext(
				    "-f only applies to files or ldap "
				    "repository\n"));
				rusage();	/* exit */
				retval = BADSYN;
				return (FAIL);
			}

			/*
			 * Only privileged process can execute this
			 * for FILES or LDAP
			 */
			if ((IS_FILES(repository) || IS_LDAP(repository)) &&
			    ((retval = ckuid()) != SUCCESS))
				return (FAIL);
			if (flag & (SAFLAG|FFLAG|NONAGEFLAG)) {
				retval = BADOPT;
				return (FAIL);
			}
			flag |= FFLAG;
			attrlist_add(attributes, ATTR_EXPIRE_PASSWORD, NULL);
			break;

		case 'e': /* change login shell */

			/* if no repository the default for -e is files */
			if (repository.type == NULL)
				repository = __REPFILES;

			if (flag & (EFLAG|SAFLAG|AGEFLAG)) {
				retval = BADOPT;
				return (FAIL);
			}
			flag |= EFLAG;
			break;

		case 'g': /* change gecos information */

			/* if no repository the default for -g is files */
			if (repository.type == NULL)
				repository = __REPFILES;

			/*
			 * Only privileged process can execute this
			 * for FILES
			 */
			if (IS_FILES(repository) && (ckuid() != SUCCESS)) {
				retval = NOPERM;
				return (FAIL);
			}
			if (flag & (GFLAG|SAFLAG|AGEFLAG)) {
				retval = BADOPT;
				return (FAIL);
			}
			flag |= GFLAG;
			break;

		case 'h': /* change home dir */

			/* if no repository the default for -h is files */
			if (repository.type == NULL)
				repository = __REPFILES;
			/*
			 * Only privileged process can execute this
			 * for FILES
			 */
			if (IS_FILES(repository) && (ckuid() != SUCCESS)) {
				retval = NOPERM;
				return (FAIL);
			}
			if (IS_NIS(repository)) {
				(void) fprintf(stderr, "%s\n",
				    gettext(MSG_NIS_HOMEDIR));
				retval = BADSYN;
				return (FAIL);
			}

			if (flag & (HFLAG|SAFLAG|AGEFLAG)) {
				retval = BADOPT;
				return (FAIL);
			}
			flag |= HFLAG;
			break;

		case '?':
			rusage();
			retval = BADOPT;
			return (FAIL);
		}
	}

	argc -= optind;
	if (argc > 1) {
		rusage();
		retval = BADSYN;
		return (FAIL);
	}

	/* Make sure (EXPIRE comes after (MAX comes after MIN)) */
	attrlist_reorder(attributes);

	/* If no options are specified or only the show option */
	/* is specified, return because no option error checking */
	/* is needed */
	if (!flag || (flag == SFLAG))
		return (flag);

	/* AFLAG must be used with SFLAG */
	if (flag == AFLAG) {
		rusage();
		retval = BADSYN;
		return (FAIL);
	}

	if (flag != SAFLAG && argc < 1) {
		/*
		 * user name is not specified (argc<1), it can't be
		 * aging info update.
		 */
		if (!(flag & NONAGEFLAG)) {
			rusage();
			retval = BADSYN;
			return (FAIL);
		}
	}

	/* user name(s) may not be specified when SAFLAG is used. */
	if (flag == SAFLAG && argc >= 1) {
		rusage();
		retval = BADSYN;
		return (FAIL);
	}

	/*
	 * If aging is being turned off (maxdate == -1), mindate may not
	 * be specified.
	 */
	if ((maxdate == -1) && (flag & NFLAG)) {
		(void) fprintf(stderr, "%s: %s -n\n",
		    prognamep, gettext(MSG_NV));
		retval = BADOPT;
		return (FAIL);
	}

	return (flag);
}

/*
 *
 * ckuid():
 *	This function returns SUCCESS if the caller is root, else
 *	it returns NOPERM.
 *
 */

static int
ckuid(void)
{
	if (uid != 0) {
		return (retval = NOPERM);
	}
	return (SUCCESS);
}


/*
 * get_attr()
 */
int
get_attr(char *username, pwu_repository_t *repository, attrlist **attributes)
{
	int res;

	attrlist_add(attributes, ATTR_PASSWD, NULL);
	attrlist_add(attributes, ATTR_LSTCHG, "0");
	attrlist_add(attributes, ATTR_MIN, "0");
	attrlist_add(attributes, ATTR_MAX, "0");
	attrlist_add(attributes, ATTR_WARN, "0");

	res = __get_authtoken_attr(username, repository, *attributes);

	if (res == PWU_SUCCESS) {
		retval = SUCCESS;
		return (PWU_SUCCESS);
	}

	if (res == PWU_NOT_FOUND)
		(void) fprintf(stderr, gettext(MSG_UNKNOWN), prognamep,
		    username);

	retval = NOPERM;
	passwd_exit(retval);
	/*NOTREACHED*/
}

/*
 * display_attr():
 * This function prints out the password attributes of a usr
 * onto standand output.
 */
void
display_attr(char *usrname, attrlist *attributes)
{
	char	*status = NULL;
	char	*passwd;
	long	lstchg;
	int	min = 0, max = 0, warn = 0;

	while (attributes) {
		switch (attributes->type) {
		case ATTR_PASSWD:
			passwd = attributes->data.val_s;
			if (passwd == NULL || *passwd == '\0')
				status = "NP  ";
			else if (strncmp(passwd, LOCKSTRING,
			    sizeof (LOCKSTRING)-1) == 0)
				status = "LK  ";
			else if (strncmp(passwd, NOLOGINSTRING,
			    sizeof (NOLOGINSTRING)-1) == 0)
				status = "NL  ";
			else if ((strlen(passwd) == 13 && passwd[0] != '$') ||
			    passwd[0] == '$')
				status = "PS  ";
			else
				status = "UN  ";
			break;
		case ATTR_LSTCHG:
			lstchg = attributes->data.val_i * DAY;
			break;
		case ATTR_MIN:
			min = attributes->data.val_i;
			break;
		case ATTR_MAX:
			max = attributes->data.val_i;
			break;
		case ATTR_WARN:
			warn = attributes->data.val_i;
			break;
		default:
			break;
		}
		attributes = attributes->next;
	}
	(void) fprintf(stdout, "%-8s  ", usrname);

	if (status)
		(void) fprintf(stdout, "%s  ", status);

	if (max != -1) {
		if (lstchg == 0) {
			(void) fprintf(stdout, "00/00/00  ");
		} else {
			struct tm *tmp;
			tmp = gmtime(&lstchg);
			(void) fprintf(stdout, "%.2d/%.2d/%.2d  ",
			    tmp->tm_mon + 1,
			    tmp->tm_mday,
			    tmp->tm_year % 100);
		}
		(void) fprintf(stdout, (min >= 0) ? "%4d  " : "      ", min);
		(void) fprintf(stdout, "%4d  ", max);
		(void) fprintf(stdout, (warn > 0) ? "%4d  " : "      ", warn);
	}
	(void) fprintf(stdout, "\n");
}

void
free_attr(attrlist *attributes)
{
	while (attributes) {
		if (attributes->type == ATTR_PASSWD)
			free(attributes->data.val_s);
		attributes = attributes->next;
	}
}

/*
 *
 * get_namelist_files():
 *	This function gets a list of user names on the system from
 *	the /etc/passwd file.
 *
 */
int
get_namelist_files(char ***namelist_p, int *num_user)
{
	FILE		*pwfp;
	struct passwd	*pwd;
	int		max_user;
	int		nuser;
	char	**nl;

	nuser = 0;
	errno = 0;
	pwd = NULL;

	if ((pwfp = fopen(PASSWD, "r")) == NULL)
		return (NOPERM);

	/*
	 * find out the actual number of entries in the PASSWD file
	 */
	max_user = 1;			/* need one slot for terminator NULL */
	while ((pwd = fgetpwent(pwfp)) != NULL)
		max_user++;

	/*
	 *	reset the file stream pointer
	 */
	rewind(pwfp);

	nl = (char **)calloc(max_user, (sizeof (char *)));
	if (nl == NULL) {
		(void) fclose(pwfp);
		return (FMERR);
	}

	while ((pwd = fgetpwent(pwfp)) != NULL) {
		if ((nl[nuser] = strdup(pwd->pw_name)) == NULL) {
			(void) fclose(pwfp);
			return (FMERR);
		}
		nuser++;
	}

	nl[nuser] = NULL;
	*num_user = nuser;
	*namelist_p = nl;
	(void) fclose(pwfp);
	return (SUCCESS);
}

/*
 * get_namelist_local
 *
 */

/*
 * Our private version of the switch frontend for getspent.  We want
 * to search just the ldap sp file, so we want to bypass
 * normal nsswitch.conf based processing.  This implementation
 * compatible with version 2 of the name service switch.
 */
#define	NSS_LDAP_ONLY		"ldap"

extern int str2spwd(const char *, int, void *, char *, int);

static DEFINE_NSS_DB_ROOT(db_root);
static DEFINE_NSS_GETENT(context);

static char *local_config;
static void
_lc_nss_initf_shadow(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_SHADOW;
	p->config_name    = NSS_DBNAM_PASSWD;	/* Use config for "passwd" */
	p->default_config = local_config;   	/* Use ldap only */
	p->flags = NSS_USE_DEFAULT_CONFIG;
}

static void
_lc_setspent(void)
{
	nss_setent(&db_root, _lc_nss_initf_shadow, &context);
}

static void
_lc_endspent(void)
{
	nss_endent(&db_root, _lc_nss_initf_shadow, &context);
	nss_delete(&db_root);
}

static struct spwd *
_lc_getspent_r(struct spwd *result, char *buffer, int buflen)
{
	nss_XbyY_args_t arg;
	char		*nam;

	/* In getXXent_r(), protect the unsuspecting caller from +/- entries */

	do {
		NSS_XbyY_INIT(&arg, result, buffer, buflen, str2spwd);
			/* No key to fill in */
		(void) nss_getent(&db_root, _lc_nss_initf_shadow, &context,
		    &arg);
	} while (arg.returnval != 0 &&
	    (nam = ((struct spwd *)arg.returnval)->sp_namp) != 0 &&
	    (*nam == '+' || *nam == '-'));

	return (struct spwd *)NSS_XbyY_FINI(&arg);
}

static nss_XbyY_buf_t *buffer;

static struct spwd *
_lc_getspent(void)
{
	nss_XbyY_buf_t	*b;

	b = NSS_XbyY_ALLOC(&buffer, sizeof (struct spwd), NSS_BUFLEN_SHADOW);

	return (b == 0 ? 0 : _lc_getspent_r(b->result, b->buffer, b->buflen));
}

int
get_namelist_local(char ***namelist_p, int *num_user)
{
	int nuser = 0;
	int alloced = 100;
	char **nl;
	struct spwd *p;


	if ((nl = calloc(alloced, sizeof (*nl))) == NULL)
		return (FMERR);

	(void) _lc_setspent();
	while ((p = _lc_getspent()) != NULL) {
		if ((nl[nuser] = strdup(p->sp_namp)) == NULL) {
			_lc_endspent();
			return (FMERR);
		}
		if (++nuser == alloced) {
			alloced += 100;
			nl = realloc(nl, alloced * (sizeof (*nl)));
			if (nl == NULL) {
				_lc_endspent();
				return (FMERR);
			}
		}
	}
	(void) _lc_endspent();
	nl[nuser] = NULL;

	*namelist_p = nl;
	*num_user = nuser;		/* including NULL */

	return (SUCCESS);
}

int
get_namelist(pwu_repository_t repository, char ***namelist, int *num_user)
{
	if (IS_LDAP(repository)) {
		local_config = NSS_LDAP_ONLY;
		return (get_namelist_local(namelist, num_user));
	} else if (IS_FILES(repository))
		return (get_namelist_files(namelist, num_user));

	rusage();
	return (BADSYN);
}

/*
 *
 * passwd_exit():
 *	This function will call exit() with appropriate exit code
 *	according to the input "retcode" value.
 *	It also calls pam_end() to clean-up buffers before exit.
 *
 */

void
passwd_exit(int retcode)
{

	if (pamh)
		(void) pam_end(pamh, pam_retval);

	switch (retcode) {
	case SUCCESS:
			break;
	case NOPERM:
			(void) fprintf(stderr, "%s\n", gettext(MSG_NP));
			break;
	case BADOPT:
			(void) fprintf(stderr, "%s\n", gettext(MSG_BS));
			break;
	case FMERR:
			(void) fprintf(stderr, "%s\n", gettext(MSG_FE));
			break;
	case FATAL:
			(void) fprintf(stderr, "%s\n", gettext(MSG_FF));
			break;
	case FBUSY:
			(void) fprintf(stderr, "%s\n", gettext(MSG_FB));
			break;
	case BADSYN:
			(void) fprintf(stderr, "%s\n", gettext(MSG_NV));
			break;
	case BADAGE:
			(void) fprintf(stderr, "%s\n", gettext(MSG_AD));
			break;
	case NOMEM:
			(void) fprintf(stderr, "%s\n", gettext(MSG_NM));
			break;
	default:
			(void) fprintf(stderr, "%s\n", gettext(MSG_NP));
			retcode = NOPERM;
			break;
	}
	/* write password record */
	if (event != NULL) {
		struct passwd *pass;

		if ((pass = getpwnam(usrname)) == NULL) {
			/* unlikely to ever get here, but ... */
			event->adt_passwd.username = usrname;
		} else if (pass->pw_uid != uid) {
			/* save target user */
			event->adt_passwd.uid = pass->pw_uid;
			event->adt_passwd.username = pass->pw_name;
		}

		if (adt_put_event(event,
		    retcode == SUCCESS ? ADT_SUCCESS : ADT_FAILURE,
		    retcode == SUCCESS ? ADT_SUCCESS : ADT_FAIL_PAM +
		    pam_retval) != 0) {
			adt_free_event(event);
			(void) adt_end_session(ah);
			perror("adt_put_event");
			exit(retcode);
		}
		adt_free_event(event);
	}
	(void) adt_end_session(ah);
	exit(retcode);
}

/*
 *
 * passwd_conv():
 *	This is the conv (conversation) function called from
 *	a PAM authentication module to print error messages
 *	or garner information from the user.
 *
 */

/*ARGSUSED*/
static int
passwd_conv(int num_msg, struct pam_message **msg,
	    struct pam_response **response, void *appdata_ptr)
{
	struct pam_message	*m;
	struct pam_response	*r;
	char 			*temp;
	int			k, i;

	if (num_msg <= 0)
		return (PAM_CONV_ERR);

	*response = (struct pam_response *)calloc(num_msg,
	    sizeof (struct pam_response));
	if (*response == NULL)
		return (PAM_BUF_ERR);

	k = num_msg;
	m = *msg;
	r = *response;
	while (k--) {

		switch (m->msg_style) {

		case PAM_PROMPT_ECHO_OFF:
			temp = getpassphrase(m->msg);
			if (temp != NULL) {
				r->resp = strdup(temp);
				(void) memset(temp, 0, strlen(temp));
				if (r->resp == NULL) {
					/* free responses */
					r = *response;
					for (i = 0; i < num_msg; i++, r++) {
						if (r->resp)
							free(r->resp);
					}
					free(*response);
					*response = NULL;
					return (PAM_BUF_ERR);
				}
			}
			m++;
			r++;
			break;

		case PAM_PROMPT_ECHO_ON:
			if (m->msg != NULL) {
				(void) fputs(m->msg, stdout);
			}
			r->resp = (char *)calloc(PAM_MAX_RESP_SIZE,
			    sizeof (char));
			if (r->resp == NULL) {
				/* free responses */
				r = *response;
				for (i = 0; i < num_msg; i++, r++) {
					if (r->resp)
						free(r->resp);
				}
				free(*response);
				*response = NULL;
				return (PAM_BUF_ERR);
			}
			if (fgets(r->resp, PAM_MAX_RESP_SIZE-1, stdin)) {
				int len = strlen(r->resp);
				if (r->resp[len-1] == '\n')
					r->resp[len-1] = '\0';
			}
			m++;
			r++;
			break;

		case PAM_ERROR_MSG:
			if (m->msg != NULL) {
				(void) fputs(m->msg, stderr);
				(void) fputs("\n", stderr);
			}
			m++;
			r++;
			break;
		case PAM_TEXT_INFO:
			if (m->msg != NULL) {
				(void) fputs(m->msg, stdout);
				(void) fputs("\n", stdout);
			}
			m++;
			r++;
			break;

		default:
			break;
		}
	}
	return (PAM_SUCCESS);
}

/*
 * 		Utilities Functions
 */

/*
 * int attrlist_add(attrlist **l, attrtype type, char *val)
 * add an item, with type "type" and value "val", at the tail of list l.
 * This functions exits the application on OutOfMem error.
 */
void
attrlist_add(attrlist **l, attrtype type, char *val)
{
	attrlist **w;

	/* tail insert */
	for (w = l; *w != NULL; w = &(*w)->next)
		;

	if ((*w = malloc(sizeof (**w))) == NULL)
		passwd_exit(NOMEM);

	(*w)->type = type;
	(*w)->next = NULL;

	switch (type) {
	case ATTR_MIN:
	case ATTR_WARN:
	case ATTR_MAX:
		(*w)->data.val_i = atoi(val);
		break;
	default:
		(*w)->data.val_s = val;
		break;
	}
}

/*
 * attrlist_reorder(attrlist **l)
 * Make sure that
 * 	- if EXPIRE and MAX or MIN is set, EXPIRE comes after MAX/MIN
 *	- if both MIN and MAX are set, MAX comes before MIN.
 */

static void
attrlist_reorder(attrlist **l)
{
	attrlist	**w;
	attrlist	*exp = NULL;	/* ATTR_EXPIRE_PASSWORD, if found */
	attrlist	*max = NULL;	/* ATTR_MAX, if found */

	if (*l == NULL || (*l)->next == NULL)
		return;		/* order of list with <= one item is ok */

	/*
	 * We simply walk the list, take off the EXPIRE and MAX items if
	 * they appear, and put them (first MAX, them EXPIRE) at the end
	 * of the list.
	 */
	w = l;
	while (*w != NULL) {
		if ((*w)->type == ATTR_EXPIRE_PASSWORD) {
			exp = *w;
			*w = (*w)->next;
		} else if ((*w)->type == ATTR_MAX) {
			max = *w;
			*w = (*w)->next;
		} else
			w = &(*w)->next;
	}

	/* 'w' points to the address of the 'next' field of the last element */

	if (max) {
		*w = max;
		w = &max->next;
	}
	if (exp) {
		*w = exp;
		w = &exp->next;
	}
	*w = NULL;
}

void
rusage(void)
{

#define	MSG(a) (void) fprintf(stderr, gettext((a)));

	MSG("usage:\n");
	MSG("\tpasswd [-r files | -r nis | -r ldap] [name]\n");
	MSG("\tpasswd [-r files] [-egh] [name]\n");
	MSG("\tpasswd [-r files] -sa\n");
	MSG("\tpasswd [-r files] -s [name]\n");
	MSG("\tpasswd [-r files] [-d|-l|-N|-u] [-f] [-n min] [-w warn] "
	    "[-x max] name\n");
	MSG("\tpasswd -r nis [-eg] [name]\n");
	MSG("\t\t[-x max] name\n");
	MSG("\tpasswd -r ldap [-egh] [name]\n");
	MSG("\tpasswd -r ldap -sa\n");
	MSG("\tpasswd -r ldap -s [name]\n");
	MSG("\tpasswd -r ldap [-l|-N|-u] [-f] [-n min] [-w warn] "
	    "[-x max] name\n");
#undef MSG
}
