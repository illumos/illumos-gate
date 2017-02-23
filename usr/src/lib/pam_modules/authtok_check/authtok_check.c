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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <stdio.h>
#include <stdlib.h>
#include <deflt.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <syslog.h>
#include <libintl.h>
#include <errno.h>
#include <pwd.h>
#include "packer.h"

#include <passwdutil.h>

#define	PWADMIN "/etc/default/passwd"

#define	MINLENGTH	6
#define	MINDIFF		3
#define	MINALPHA	2
#define	MINNONALPHA	1

mutex_t dictlock = DEFAULTMUTEX;

/*
 * We implement:
 *	PASSLENGTH (int)	minimum password length
 *	NAMECHECK (yes/no)	perform comparison of password and loginname
 *	MINDIFF (int)		minimum number of character-positions in which
 *				the old	and the new password should differ.
 *	MINALPHA (int)		minimum number of Alpha characters
 *	MINUPPER (int)		minimum number of upper-case characters
 *	MINLOWER (int)		minimum number of lower-case characters
 *	MAXREPEATS (int)	maximum number of consecutively repeating chars
 *	WHITESPACE (yes/no)	Are whitespaces allowed?
 *
 * Furthermore, these two mutualy exclusive groups of options are allowed:
 *
 *	MINNONALPHA (int)	minimum number of characters from the
 *				character classes [ punct, space, digit ]
 *				if WHITESPACE == NO, whitespaces don't count.
 * and
 *	MINSPECIAL (int)	minimum number of punctuation characters.
 *				if WHITESPACE != NO, whitespace is seen as
 *				a "special" character.
 *	MINDIGIT (int)		minimum number of digits
 *
 * specifying options from both groups results in an error to syslog and
 * failure to change the password.
 *
 * NOTE:
 *	HISTORY is implemented at the repository level (passwdutil).
 */

/*
 * default password-strength-values, compiled-in or stored in PWADMIN
 * are kept in here
 */
struct pwdefaults {
	boolean_t server_policy;	/* server policy flag from pam.conf */
	uint_t minlength;	/* minimum password lenght */
	uint_t maxlength;	/* maximum (significant) length */
	boolean_t do_namecheck;	/* check password against user's gecos */
	char db_location[MAXPATHLEN]; /* location of the generated database */
	boolean_t do_dictcheck;	/* perform dictionary lookup */
	char *dicts;		/* list of dictionaries configured */
	uint_t mindiff;		/* old and new should differ by this much */
	uint_t minalpha;	/* minimum alpha characters required */
	uint_t minupper;	/* minimum uppercase characters required */
	uint_t minlower;	/* minimum lowercase characters required */
	uint_t minnonalpha; 	/* minimum special (non alpha) required */
	uint_t maxrepeat;	/* maximum number of repeating chars allowed */
	uint_t minspecial;	/* punctuation characters */
	uint_t mindigit;	/* minimum number of digits required */
	boolean_t whitespace;	/* is whitespace allowed in a password */
};


/*PRINTFLIKE3*/
void
error(pam_handle_t *pamh, int flags, char *fmt, ...)
{
	va_list ap;
	char msg[1][PAM_MAX_MSG_SIZE];

	va_start(ap, fmt);
	(void) vsnprintf(msg[0], sizeof (msg[0]), fmt, ap);
	va_end(ap);
	if ((flags & PAM_SILENT) == 0)
		(void) __pam_display_msg(pamh, PAM_ERROR_MSG, 1, msg, NULL);
}

int
defread_int(char *name, uint_t *ip, void *defp)
{
	char *q;
	int r = 0;
	if ((q = defread_r(name, defp)) != NULL) {
		if (!isdigit(*q)) {
			syslog(LOG_ERR, "pam_authtok_check: %s contains "
			    "non-integer value for %s: %s. "
			    "Using default instead.", PWADMIN, name, q);
		} else {
			*ip = atoi(q);
			r = 1;
		}
	}
	return (r);
}

/*
 * fill in static defaults, and augment with settings from PWADMIN
 * get system defaults with regard to maximum password length
 */
int
get_passwd_defaults(pam_handle_t *pamh, char *user, struct pwdefaults *p)
{
	char *q;
	boolean_t minnonalpha_defined = B_FALSE;
	pwu_repository_t *pwu_rep;
	struct pam_repository *pam_rep;
	attrlist attr[2];
	int result;
	char *progname;
	void	*defp;

	(void) pam_get_item(pamh, PAM_SERVICE, (void **)&progname);

	/* Module defaults */
	p->minlength = MINLENGTH;
	p->do_namecheck = B_TRUE;
	p->do_dictcheck = B_FALSE;
	p->dicts = NULL;
	p->mindiff = MINDIFF;
	p->minalpha = MINALPHA;
	p->minnonalpha = MINNONALPHA;
	p->minupper = 0;	/* not configured by default */
	p->minlower = 0;	/* not configured by default */
	p->maxrepeat = 0;	/* not configured by default */

	p->minspecial = 0;
	p->mindigit = 0;
	p->whitespace = B_TRUE;

	if ((defp = defopen_r(PWADMIN)) == NULL)
		return (PAM_SUCCESS);

	(void) defread_int("PASSLENGTH=", &p->minlength, defp);

	if ((q = defread_r("NAMECHECK=", defp)) != NULL &&
	    strcasecmp(q, "NO") == 0)
		p->do_namecheck = B_FALSE;

	if ((q = defread_r("DICTIONLIST=", defp)) != NULL) {
		if ((p->dicts = strdup(q)) == NULL) {
			syslog(LOG_ERR, "pam_authtok_check: out of memory");
			defclose_r(defp);
			return (PAM_BUF_ERR);

		}
		p->do_dictcheck = B_TRUE;
	} else {
		p->dicts = NULL;
	}

	if ((q = defread_r("DICTIONDBDIR=", defp)) != NULL) {
		if (strlcpy(p->db_location, q, sizeof (p->db_location)) >=
		    sizeof (p->db_location)) {
			syslog(LOG_ERR, "pam_authtok_check: value for "
			    "DICTIONDBDIR too large.");
			defclose_r(defp);
			return (PAM_SYSTEM_ERR);
		}
		p->do_dictcheck = B_TRUE;
	} else {
		(void) strlcpy(p->db_location, CRACK_DIR,
		    sizeof (p->db_location));
	}

	(void) defread_int("MINDIFF=", &p->mindiff, defp);
	(void) defread_int("MINALPHA=", &p->minalpha, defp);
	(void) defread_int("MINUPPER=", &p->minupper, defp);
	(void) defread_int("MINLOWER=", &p->minlower, defp);
	if (defread_int("MINNONALPHA=", &p->minnonalpha, defp))
		minnonalpha_defined = B_TRUE;
	(void) defread_int("MAXREPEATS=", &p->maxrepeat, defp);

	if (defread_int("MINSPECIAL=", &p->minspecial, defp)) {
		if (minnonalpha_defined) {
			syslog(LOG_ERR, "pam_authtok_check: %s contains "
			    "definition for MINNONALPHA and for MINSPECIAL. "
			    "These options are mutually exclusive.", PWADMIN);
			defclose_r(defp);
			return (PAM_SYSTEM_ERR);
		}
		p->minnonalpha = 0;
	}

	if (defread_int("MINDIGIT=", &p->mindigit, defp)) {
		if (minnonalpha_defined) {
			syslog(LOG_ERR, "pam_authtok_check: %s contains "
			    "definition for MINNONALPHA and for MINDIGIT. "
			    "These options are mutually exclusive.", PWADMIN);
			defclose_r(defp);
			return (PAM_SYSTEM_ERR);
		}
		p->minnonalpha = 0;
	}

	if ((q = defread_r("WHITESPACE=", defp)) != NULL)
		p->whitespace =
		    (strcasecmp(q, "no") == 0 || strcmp(q, "0") == 0)
		    ? B_FALSE : B_TRUE;

	defclose_r(defp);

	/*
	 * Determine the number of significant characters in a password
	 *
	 * we find out where the user information came from (which repository),
	 * and which password-crypt-algorithm is to be used (based on the
	 * old password, or the system default).
	 *
	 * If the user comes from a repository other than FILES/NIS
	 * the module-flag "server_policy" means that we don't perform
	 * any checks on the user, but let the repository decide instead.
	 */

	(void) pam_get_item(pamh, PAM_REPOSITORY, (void **)&pam_rep);
	if (pam_rep != NULL) {
		if ((pwu_rep = calloc(1, sizeof (*pwu_rep))) == NULL)
			return (PAM_BUF_ERR);
		pwu_rep->type = pam_rep->type;
		pwu_rep->scope = pam_rep->scope;
		pwu_rep->scope_len = pam_rep->scope_len;
	} else {
		pwu_rep = PWU_DEFAULT_REP;
	}

	attr[0].type = ATTR_PASSWD; attr[0].next = &attr[1];
	attr[1].type = ATTR_REP_NAME; attr[1].next = NULL;
	result = __get_authtoken_attr(user, pwu_rep, attr);
	if (pwu_rep != PWU_DEFAULT_REP)
		free(pwu_rep);

	if (result != PWU_SUCCESS) {
		/*
		 * In the unlikely event that we can't obtain any info about
		 * the users password, we assume the most strict scenario.
		 */
		p->maxlength = _PASS_MAX_XPG;
	} else {
		char *oldpw = attr[0].data.val_s;
		char *repository = attr[1].data.val_s;
		if ((strcmp(repository, "files") == 0 ||
		    strcmp(repository, "nis") == 0) ||
		    p->server_policy == B_FALSE) {
			char *salt;
			/*
			 * We currently need to supply this dummy to
			 * crypt_gensalt(). This will change RSN.
			 */
			struct passwd dummy;

			dummy.pw_name = user;

			salt = crypt_gensalt(oldpw, &dummy);
			if (salt && *salt == '$')
				p->maxlength = _PASS_MAX;
			else
				p->maxlength = _PASS_MAX_XPG;

			free(salt);

			p->server_policy = B_FALSE; /* we perform checks */
		} else {
			/* not files or nis AND server_policy is set */
			p->maxlength = _PASS_MAX;
		}
		free(attr[0].data.val_s);
		free(attr[1].data.val_s);
	}

	/* sanity check of the configured parameters */
	if (p->minlength < p->mindigit + p->minspecial + p->minnonalpha +
	    p->minalpha) {
		syslog(LOG_ERR, "%s: pam_authtok_check: Defined minimum "
		    "password length (PASSLENGTH=%d) is less then minimum "
		    "characters in the various classes (%d)", progname,
		    p->minlength,
		    p->mindigit + p->minspecial + p->minnonalpha + p->minalpha);
		p->minlength = p->mindigit + p->minspecial + p->minnonalpha +
		    p->minalpha;
		syslog(LOG_ERR, "%s: pam_authtok_check: effective "
		    "PASSLENGTH set to %d.", progname, p->minlength);
		/* this won't lead to failure */
	}

	if (p->maxlength < p->minlength) {
		syslog(LOG_ERR, "%s: pam_authtok_check: The configured "
		    "minimum password length (PASSLENGTH=%d) is larger than "
		    "the number of significant characters the current "
		    "encryption algorithm uses (%d). See policy.conf(4) for "
		    "alternative password encryption algorithms.", progname);
		/* this won't lead to failure */
	}

	return (PAM_SUCCESS);
}

/*
 * free_passwd_defaults(struct pwdefaults *p)
 *
 * free space occupied by the defaults read from PWADMIN
 */
void
free_passwd_defaults(struct pwdefaults *p)
{
	if (p && p->dicts)
		free(p->dicts);
}

/*
 * check_circular():
 * This function return 1 if string "t" is a circular shift of
 * string "s", else it returns 0. -1 is returned on failure.
 * We also check to see if string "t" is a reversed-circular shift
 * of string "s", i.e. "ABCDE" vs. "DCBAE".
 */
static int
check_circular(s, t)
	char *s, *t;
{
	char c, *p, *o, *r, *buff, *ubuff, *pubuff;
	unsigned int i, j, k, l, m;
	size_t len;
	int ret = 0;

	i = strlen(s);
	l = strlen(t);
	if (i != l)
		return (0);
	len = i + 1;

	buff = malloc(len);
	ubuff = malloc(len);
	pubuff = malloc(len);

	if (buff == NULL || ubuff == NULL || pubuff == NULL) {
		syslog(LOG_ERR, "pam_authtok_check: out of memory.");
		return (-1);
	}

	m = 2;
	o = &ubuff[0];
	for (p = s; c = *p++; *o++ = c)
		if (islower(c))
			c = toupper(c);
	*o = '\0';
	o = &pubuff[0];
	for (p = t; c = *p++; *o++ = c)
		if (islower(c))
			c = toupper(c);

	*o = '\0';

	p = &ubuff[0];
	while (m--) {
		for (k = 0; k  <  i; k++) {
			c = *p++;
			o = p;
			l = i;
			r = &buff[0];
			while (--l)
				*r++ = *o++;
			*r++ = c;
			*r = '\0';
			p = &buff[0];
			if (strcmp(p, pubuff) == 0) {
				ret = 1;
				goto out;
			}
		}
		p = p + i;
		r = &ubuff[0];
		j = i;
		while (j--)
			*--p = *r++;	/* reverse test-string for m==0 pass */
	}
out:
	(void) memset(buff, 0, len);
	(void) memset(ubuff, 0, len);
	(void) memset(pubuff, 0, len);
	free(buff);
	free(ubuff);
	free(pubuff);
	return (ret);
}


/*
 * count the different character classes present in the password.
 */
int
check_composition(char *pw, struct pwdefaults *pwdef, pam_handle_t *pamh,
    int flags)
{
	uint_t alpha_cnt = 0;
	uint_t upper_cnt = 0;
	uint_t lower_cnt = 0;
	uint_t special_cnt = 0;
	uint_t whitespace_cnt = 0;
	uint_t digit_cnt = 0;
	uint_t maxrepeat = 0;
	uint_t repeat = 1;
	int ret = 0;
	char *progname;
	char errmsg[256];
	char lastc = '\0';
	uint_t significant = pwdef->maxlength;
	char *w;

	(void) pam_get_item(pamh, PAM_SERVICE, (void **)&progname);

	/* go over the password gathering statistics */
	for (w = pw; significant != 0 && *w != '\0'; w++, significant--) {
		if (isalpha(*w)) {
			alpha_cnt++;
			if (isupper(*w)) {
				upper_cnt++;
			} else {
				lower_cnt++;
			}
		} else if (isspace(*w))
			whitespace_cnt++;
		else if (isdigit(*w))
			digit_cnt++;
		else
			special_cnt++;
		if (*w == lastc) {
			if (++repeat > maxrepeat)
				maxrepeat = repeat;
		} else {
			repeat = 1;
		}
		lastc = *w;
	}

	/*
	 * If we only consider part of the password (the first maxlength
	 * characters) we give a modified error message. Otherwise, a
	 * user entering FooBar1234 with PASSLENGTH=6, MINDIGIT=4, while
	 * we're using the default UNIX crypt (8 chars significant),
	 * would not understand what's going on when they're told that
	 * "The password should contain at least 4 digits"...
	 * Instead, we now tell them
	 * "The first 8 characters of the password should contain at least
	 *  4 digits."
	 */
	if (pwdef->maxlength < strlen(pw))
		/*
		 * TRANSLATION_NOTE
		 * - Make sure the % and %% come over intact
		 * - The last %%s will be replaced by strings like
		 *	"alphabetic character(s)"
		 *	"numeric or special character(s)"
		 *	"special character(s)"
		 *	"digit(s)"
		 *	"uppercase alpha character(s)"
		 *	"lowercase alpha character(s)"
		 *   So the final string written to the user might become
		 * "passwd: The first 8 characters of the password must contain
		 *   at least 4 uppercase alpha characters(s)"
		 */
		(void) snprintf(errmsg, sizeof (errmsg), dgettext(TEXT_DOMAIN,
		    "%s: The first %d characters of the password must "
		    "contain at least %%d %%s."), progname, pwdef->maxlength);
	else
		/*
		 * TRANSLATION_NOTE
		 * - Make sure the % and %% come over intact
		 * - The last %%s will be replaced by strings like
		 *	"alphabetic character(s)"
		 *	"numeric or special character(s)"
		 *	"special character(s)"
		 *	"digit(s)"
		 *	"uppercase alpha character(s)"
		 *	"lowercase alpha character(s)"
		 *   So the final string written to the user might become
		 * "passwd: The password must contain at least 4 uppercase
		 *   alpha characters(s)"
		 */
		(void) snprintf(errmsg, sizeof (errmsg), dgettext(TEXT_DOMAIN,
		    "%s: The password must contain at least %%d %%s."),
		    progname);

	/* Check for whitespace first since it influences special counts */
	if (whitespace_cnt > 0 && pwdef->whitespace == B_FALSE) {
		error(pamh, flags, dgettext(TEXT_DOMAIN,
		    "%s: Whitespace characters are not allowed."), progname);
		ret = 1;
		goto out;
	}

	/*
	 * Once we get here, whitespace_cnt is either 0, or whitespaces are
	 * to be treated a special characters.
	 */

	if (alpha_cnt < pwdef->minalpha) {
		error(pamh, flags, errmsg, pwdef->minalpha,
		    dgettext(TEXT_DOMAIN, "alphabetic character(s)"));
		ret = 1;
		goto out;
	}

	if (pwdef->minnonalpha > 0) {
		/* specials are defined by MINNONALPHA */
		/* nonalpha = special+whitespace+digit */
		if ((special_cnt + whitespace_cnt + digit_cnt) <
		    pwdef->minnonalpha) {
			error(pamh, flags, errmsg, pwdef->minnonalpha,
			    dgettext(TEXT_DOMAIN,
			    "numeric or special character(s)"));
			ret = 1;
			goto out;
		}
	} else {
		/* specials are defined by MINSPECIAL and/or MINDIGIT */
		if ((special_cnt + whitespace_cnt) < pwdef->minspecial) {
			error(pamh, flags, errmsg, pwdef->minspecial,
			    dgettext(TEXT_DOMAIN, "special character(s)"));
			ret = 1;
			goto out;
		}
		if (digit_cnt < pwdef->mindigit) {
			error(pamh, flags, errmsg, pwdef->mindigit,
			    dgettext(TEXT_DOMAIN, "digit(s)"));
			ret = 1;
			goto out;
		}
	}

	if (upper_cnt < pwdef->minupper) {
		error(pamh, flags, errmsg, pwdef->minupper,
		    dgettext(TEXT_DOMAIN, "uppercase alpha character(s)"));
		ret = 1;
		goto out;
	}
	if (lower_cnt < pwdef->minlower) {
		error(pamh, flags, errmsg, pwdef->minlower,
		    dgettext(TEXT_DOMAIN, "lowercase alpha character(s)"));
		ret = 1;
		goto out;
	}

	if (pwdef->maxrepeat > 0 && maxrepeat > pwdef->maxrepeat) {
		error(pamh, flags, dgettext(TEXT_DOMAIN,
		    "%s: Too many consecutively repeating characters. "
		    "Maximum allowed is %d."), progname, pwdef->maxrepeat);
		ret = 1;
	}
out:
	return (ret);
}

/*
 * make sure that old and new password differ by at least 'mindiff'
 * positions. Return 0 if OK, 1 otherwise
 */
int
check_diff(char *pw, char *opw, struct pwdefaults *pwdef, pam_handle_t *pamh,
    int flags)
{
	size_t pwlen, opwlen, max;
	unsigned int diff;	/* difference between old and new */

	if (opw == NULL)
		opw = "";

	max = pwdef->maxlength;
	pwlen = MIN(strlen(pw), max);
	opwlen = MIN(strlen(opw), max);

	if (pwlen > opwlen)
		diff = pwlen - opwlen;
	else
		diff = opwlen - pwlen;

	while (*opw != '\0' && *pw != '\0' && max-- != 0) {
		if (*opw != *pw)
			diff++;
		opw++;
		pw++;
	}

	if (diff  < pwdef->mindiff) {
		char *progname;

		(void) pam_get_item(pamh, PAM_SERVICE, (void **)&progname);

		error(pamh, flags, dgettext(TEXT_DOMAIN,
		    "%s: The first %d characters of the old and new passwords "
		    "must differ by at least %d positions."), progname,
		    pwdef->maxlength, pwdef->mindiff);
		return (1);
	}

	return (0);
}

/*
 * check to see if password is in one way or another based on a
 * dictionary word. Returns 0 if password is OK, 1 if it is based
 * on a dictionary word and hence should be rejected.
 */
int
check_dictionary(char *pw, struct pwdefaults *pwdef, pam_handle_t *pamh,
    int flags)
{
	int crack_ret;
	int ret;
	char *progname;

	(void) pam_get_item(pamh, PAM_SERVICE, (void **)&progname);

	/* dictionary check isn't MT-safe */
	(void) mutex_lock(&dictlock);

	if (pwdef->dicts &&
	    make_dict_database(pwdef->dicts, pwdef->db_location) != 0) {
		(void) mutex_unlock(&dictlock);
		syslog(LOG_ERR, "pam_authtok_check:pam_sm_chauthtok: "
		    "Dictionary database not present.");
		error(pamh, flags, dgettext(TEXT_DOMAIN,
		    "%s: password dictionary missing."), progname);
		return (PAM_SYSTEM_ERR);
	}

	crack_ret = DictCheck(pw, pwdef->db_location);

	(void) mutex_unlock(&dictlock);

	switch (crack_ret) {
	case DATABASE_OPEN_FAIL:
		syslog(LOG_ERR, "pam_authtok_check:pam_sm_chauthtok: "
		    "dictionary database open failure: %s", strerror(errno));
		error(pamh, flags, dgettext(TEXT_DOMAIN,
		    "%s: failed to open dictionary database."), progname);
		ret = PAM_SYSTEM_ERR;
		break;
	case DICTIONARY_WORD:
		error(pamh, flags, dgettext(TEXT_DOMAIN,
		    "%s: password is based on a dictionary word."), progname);
		ret = PAM_AUTHTOK_ERR;
		break;
	case REVERSE_DICTIONARY_WORD:
		error(pamh, flags, dgettext(TEXT_DOMAIN,
		    "%s: password is based on a reversed dictionary word."),
		    progname);
		ret = PAM_AUTHTOK_ERR;
		break;
	default:
		ret = PAM_SUCCESS;
		break;
	}
	return (ret);
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int	debug = 0;
	int	retcode = 0;
	int	force_check = 0;
	int 	i;
	size_t	pwlen;
	char	*usrname;
	char	*pwbuf, *opwbuf;
	pwu_repository_t *pwu_rep = PWU_DEFAULT_REP;
	pam_repository_t *pwd_rep = NULL;
	struct pwdefaults pwdef;
	char *progname;

	/* needs to be set before option processing */
	pwdef.server_policy = B_FALSE;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			debug = 1;
		if (strcmp(argv[i], "force_check") == 0)
			force_check = 1;
		if (strcmp(argv[i], "server_policy") == 0)
			pwdef.server_policy = B_TRUE;
	}

	if (debug)
		syslog(LOG_AUTH | LOG_DEBUG,
		    "pam_authtok_check: pam_sm_chauthok called(%x) "
		    "force_check = %d", flags, force_check);

	if ((flags & PAM_PRELIM_CHECK) == 0)
		return (PAM_IGNORE);

	(void) pam_get_item(pamh, PAM_SERVICE, (void **)&progname);
	(void) pam_get_item(pamh, PAM_USER, (void **)&usrname);
	if (usrname == NULL || *usrname == '\0') {
		syslog(LOG_ERR, "pam_authtok_check: username name is empty");
		return (PAM_USER_UNKNOWN);
	}

	(void) pam_get_item(pamh, PAM_AUTHTOK, (void **)&pwbuf);
	(void) pam_get_item(pamh, PAM_OLDAUTHTOK, (void **)&opwbuf);
	if (pwbuf == NULL)
		return (PAM_AUTHTOK_ERR);

	/* none of these checks holds if caller say so */
	if ((flags & PAM_NO_AUTHTOK_CHECK) != 0 && force_check == 0)
		return (PAM_SUCCESS);

	/* read system-defaults */
	retcode = get_passwd_defaults(pamh, usrname, &pwdef);
	if (retcode != PAM_SUCCESS)
		return (retcode);

	if (debug) {
		syslog(LOG_AUTH | LOG_DEBUG,
		    "pam_authtok_check: MAXLENGTH= %d, server_policy = %s",
		    pwdef.maxlength, pwdef.server_policy ? "true" : "false");
		syslog(LOG_AUTH | LOG_DEBUG,
		    "pam_authtok_check: PASSLENGTH= %d", pwdef.minlength);
		syslog(LOG_AUTH | LOG_DEBUG, "pam_authtok_check: NAMECHECK=%s",
		    pwdef.do_namecheck == B_TRUE ? "Yes" : "No");
		syslog(LOG_AUTH | LOG_DEBUG,
		    "pam_authtok_check: do_dictcheck = %s\n",
		    pwdef.do_dictcheck ? "true" : "false");
		if (pwdef.do_dictcheck) {
			syslog(LOG_AUTH | LOG_DEBUG,
			    "pam_authtok_check: DICTIONLIST=%s",
			    (pwdef.dicts != NULL) ? pwdef.dicts : "<not set>");
			syslog(LOG_AUTH | LOG_DEBUG,
			    "pam_authtok_check: DICTIONDBDIR=%s",
			    pwdef.db_location);
		}
		syslog(LOG_AUTH | LOG_DEBUG, "pam_authtok_check: MINDIFF=%d",
		    pwdef.mindiff);
		syslog(LOG_AUTH | LOG_DEBUG,
		    "pam_authtok_check: MINALPHA=%d, MINNONALPHA=%d",
		    pwdef.minalpha, pwdef.minnonalpha);
		syslog(LOG_AUTH | LOG_DEBUG,
		    "pam_authtok_check: MINSPECIAL=%d, MINDIGIT=%d",
		    pwdef.minspecial, pwdef.mindigit);
		syslog(LOG_AUTH | LOG_DEBUG, "pam_authtok_check: WHITESPACE=%s",
		    pwdef.whitespace ? "YES" : "NO");
		syslog(LOG_AUTH | LOG_DEBUG,
		    "pam_authtok_check: MINUPPER=%d, MINLOWER=%d",
		    pwdef.minupper, pwdef.minlower);
		syslog(LOG_AUTH | LOG_DEBUG, "pam_authtok_check: MAXREPEATS=%d",
		    pwdef.maxrepeat);
	}

	/*
	 * If server policy is still true (might be changed from the
	 * value specified in /etc/pam.conf by get_passwd_defaults()),
	 * we return ignore and let the server do all the checks.
	 */
	if (pwdef.server_policy == B_TRUE) {
		free_passwd_defaults(&pwdef);
		return (PAM_IGNORE);
	}

	/*
	 * XXX: JV: we can't really make any assumption on the length of
	 *	the password that will be used by the crypto algorithm.
	 *	for UNIX-style encryption, minalpha=5,minnonalpha=5 might
	 *	be impossible, but not for MD5 style hashes... what to do?
	 *
	 *	since we don't know what alg. will be used, we operate on
	 *	the password as entered, so we don't sanity check anything
	 *	for now.
	 */

	/*
	 * Make sure new password is long enough
	 */
	pwlen = strlen(pwbuf);

	if (pwlen < pwdef.minlength) {
		error(pamh, flags, dgettext(TEXT_DOMAIN,
		    "%s: Password too short - must be at least %d "
		    "characters."), progname, pwdef.minlength);
		free_passwd_defaults(&pwdef);
		return (PAM_AUTHTOK_ERR);
	}

	/* Make sure the password doesn't equal--a shift of--the username */
	if (pwdef.do_namecheck) {
		switch (check_circular(usrname, pwbuf)) {
		case 1:
			error(pamh, flags, dgettext(TEXT_DOMAIN,
			    "%s: Password cannot be circular shift of "
			    "logonid."), progname);
			free_passwd_defaults(&pwdef);
			return (PAM_AUTHTOK_ERR);
		case -1:
			free_passwd_defaults(&pwdef);
			return (PAM_BUF_ERR);
		default:
			break;
		}
	}

	/* Check if new password is in history list. */
	(void) pam_get_item(pamh, PAM_REPOSITORY, (void **)&pwd_rep);
	if (pwd_rep != NULL) {
		if ((pwu_rep = calloc(1, sizeof (*pwu_rep))) == NULL)
			return (PAM_BUF_ERR);
		pwu_rep->type = pwd_rep->type;
		pwu_rep->scope = pwd_rep->scope;
		pwu_rep->scope_len = pwd_rep->scope_len;
	}

	if (__check_history(usrname, pwbuf, pwu_rep) == PWU_SUCCESS) {
		/* password found in history */
		error(pamh, flags, dgettext(TEXT_DOMAIN,
		    "%s: Password in history list."), progname);
		if (pwu_rep != PWU_DEFAULT_REP)
			free(pwu_rep);
		free_passwd_defaults(&pwdef);
		return (PAM_AUTHTOK_ERR);
	}

	if (pwu_rep != PWU_DEFAULT_REP)
		free(pwu_rep);

	/* check MINALPHA, MINLOWER, etc. */
	if (check_composition(pwbuf, &pwdef, pamh, flags) != 0) {
		free_passwd_defaults(&pwdef);
		return (PAM_AUTHTOK_ERR);
	}

	/* make sure the old and new password are not too much alike */
	if (check_diff(pwbuf, opwbuf, &pwdef, pamh, flags) != 0) {
		free_passwd_defaults(&pwdef);
		return (PAM_AUTHTOK_ERR);
	}

	/* dictionary check */
	if (pwdef.do_dictcheck) {
		retcode = check_dictionary(pwbuf, &pwdef, pamh, flags);
		if (retcode != PAM_SUCCESS) {
			free_passwd_defaults(&pwdef);
			return (retcode);
		}
	}

	free_passwd_defaults(&pwdef);
	/* password has passed all tests: it's strong enough */
	return (PAM_SUCCESS);
}
