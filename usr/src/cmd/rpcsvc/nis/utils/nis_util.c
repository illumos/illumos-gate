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
 *	nis_util.c
 *
 * Copyright 1988-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpcsvc/nis.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <shadow.h>
#include <stdlib.h>

/*
 * nisname_index()
 *
 * Return pointer to place in string s of first match with char c.
 * Do not match between quotes ("...").
 *
 * Totally rewritten as part of the fix for bug# 1263305.
 * XXX - This can now probably be replaced by strchr_quotes().
 */
char *
nisname_index(char *s, char c)
{
	do {
		if (*s == '"') {
			s++;
			while (*s && *s != '"')
				s++;
		} else if (*s == c)
			return (s);
	} while (*s++);
	return (NULL);
}

/*
 * Parse a passed name into a basename and search criteria.
 * if there is no criteria present the *crit == 0. You must
 * pass in allocated data for the three strings.
 *
 * Returns 0 if successful, non-zero otherwise.
 */
int
nisname_split(name, base, crit, max_len)
	char	*name;
	char	*base;
	char	*crit;
	int	max_len;
{
	register char	*p, *q;

	p = name;
	while (*p && (isspace(*p)))
		p++;
	if (*p != '[') {
		*crit = 0;
		return (strlcpy(base, p, max_len) >= max_len);
	}

	/* it has a criteria, copy the whole thing in */
	if (strlcpy(crit, p, max_len) >= max_len)
		return (1);
	q = nisname_index(crit, ']');
	if (! q) {
		*crit = 0;	/* error condition */
		*base = 0;
		return (1);
	}
	q++;
	if (*q == ',') {
		*q = 0;
		q++;
	}
	if (strlcpy(base, q, max_len) >= max_len)
		return (1);
	*q = 0; /* just in case there wasn't a comma */

	return (0);
}

bool_t
nis_verifycred(n, flags)
	nis_name	n;
	uint_t		flags;
{
	nis_result	*res;
	int		err;
	char		dname[NIS_MAXNAMELEN];

	(void) snprintf(dname, sizeof (dname), "[cname=%s],cred.org_dir.%s", n,
		nis_domain_of(n));
	res = nis_list(dname, flags, NULL, NULL);
	err = (res->status == NIS_SUCCESS);
	nis_freeresult(res);
	return (err);
}

#define	NIS_ALL_ACC (NIS_READ_ACC|NIS_MODIFY_ACC|NIS_CREATE_ACC|NIS_DESTROY_ACC)

static int
parse_rights_field(rights, shift, p)
	uint_t *rights;
	int shift;
	char *p;
{
	int set;

	while (*p && (*p != ',')) {
		switch (*p) {
		case '=':
			*rights &= ~(NIS_ALL_ACC << shift);
		case '+':
			set = 1;
			break;
		case '-':
			set = 0;
			break;
		default:
			return (0);
		}
		for (p++; *p && (*p != ',') && (*p != '=') && (*p != '+') &&
							(*p != '-'); p++) {
			switch (*p) {
			case 'r':
				if (set)
					*rights |= (NIS_READ_ACC << shift);
				else
					*rights &= ~(NIS_READ_ACC << shift);
				break;
			case 'm':
				if (set)
					*rights |= (NIS_MODIFY_ACC << shift);
				else
					*rights &= ~(NIS_MODIFY_ACC << shift);
				break;
			case 'c':
				if (set)
					*rights |= (NIS_CREATE_ACC << shift);
				else
					*rights &= ~(NIS_CREATE_ACC << shift);
				break;
			case 'd':
				if (set)
					*rights |= (NIS_DESTROY_ACC << shift);
				else
					*rights &= ~(NIS_DESTROY_ACC << shift);
				break;
			default:
				return (0);
			}
		}
	}
	return (1);
}

#define	NIS_NOBODY_FLD 1
#define	NIS_OWNER_FLD 2
#define	NIS_GROUP_FLD 4
#define	NIS_WORLD_FLD 8
#define	NIS_ALL_FLD NIS_OWNER_FLD|NIS_GROUP_FLD|NIS_WORLD_FLD

int
parse_rights(rights, p)
	uint_t *rights;
	char *p;
{
	uint_t f;

	if (p)
		while (*p) {
			for (f = 0; (*p != '=') && (*p != '+') && (*p != '-');
									p++)
				switch (*p) {
				case 'n':
					f |= NIS_NOBODY_FLD;
					break;
				case 'o':
					f |= NIS_OWNER_FLD;
					break;
				case 'g':
					f |= NIS_GROUP_FLD;
					break;
				case 'w':
					f |= NIS_WORLD_FLD;
					break;
				case 'a':
					f |= NIS_ALL_FLD;
					break;
				default:
					return (0);
				}
			if (f == 0)
				f = NIS_ALL_FLD;

			if ((f & NIS_NOBODY_FLD) &&
			    !parse_rights_field(rights, 24, p))
				return (0);

			if ((f & NIS_OWNER_FLD) &&
			    !parse_rights_field(rights, 16, p))
				return (0);

			if ((f & NIS_GROUP_FLD) &&
			    !parse_rights_field(rights, 8, p))
				return (0);

			if ((f & NIS_WORLD_FLD) &&
			    !parse_rights_field(rights, 0, p))
				return (0);

			while (*(++p))
				if (*p == ',') {
					p++;
					break;
				}
		}
	return (1);
}


int
parse_flags(flags, p)
	uint_t *flags;
	char *p;
{
	if (p) {
		while (*p) {
			switch (*(p++)) {
			case 'B':
				*flags |= TA_BINARY;
				break;
			case 'X':
				*flags |= TA_XDR;
				break;
			case 'S':
				*flags |= TA_SEARCHABLE;
				break;
			case 'I':
				*flags |= TA_CASE;
				break;
			case 'C':
				*flags |= TA_CRYPT;
				break;
			default:
				return (0);
			}
		}
		return (1);
	} else {
		fprintf(stderr,
	"Invalid table schema: At least one column must be searchable.\n");
		exit(1);
	}
}


int
parse_time(time, p)
	uint32_t *time;
	char *p;
{
	char *s;
	uint32_t x;

	*time = 0;

	if (p)
		while (*p) {
			if (!isdigit(*p))
				return (0);
			x = strtol(p, &s, 10);
			switch (*s) {
			case '\0':
				(*time) += x;
				p = s;
				break;
			case 's':
			case 'S':
				(*time) += x;
				p = s+1;
				break;
			case 'm':
			case 'M':
				(*time) += x*60;
				p = s+1;
				break;
			case 'h':
			case 'H':
				(*time) += x*(60*60);
				p = s+1;
				break;
			case 'd':
			case 'D':
				(*time) += x*(24*60*60);
				p = s+1;
				break;
			default:
				return (0);
			}
		}

	return (1);
}


static int
nis_getsubopt(optionsp, tokens, sep, valuep)
	char **optionsp;
	char * const *tokens;
	const int sep; /* if this is a char we get an alignment error */
	char **valuep;
{
	register char *s = *optionsp, *p, *q;
	register int i, optlen;

	*valuep = NULL;
	if (*s == '\0')
		return (-1);
	q = strchr(s, (char)sep);	/* find next option */
	if (q == NULL) {
		q = s + strlen(s);
	} else {
		*q++ = '\0';		/* mark end and point to next */
	}
	p = strchr(s, '=');		/* find value */
	if (p == NULL) {
		optlen = strlen(s);
		*valuep = NULL;
	} else {
		optlen = p - s;
		*valuep = ++p;
	}
	for (i = 0; tokens[i] != NULL; i++) {
		if ((optlen == strlen(tokens[i])) &&
		    (strncmp(s, tokens[i], optlen) == 0)) {
			/* point to next option only if success */
			*optionsp = q;
			return (i);
		}
	}
	/* no match, point value at option and return error */
	*valuep = s;
	return (-1);
}


nis_object nis_default_obj;

/*
 * We record the source of the defaults.
 *     0 => default
 *     1 => from NIS_DEFAULTS env variable
 *     2 => from arg passed to nis_defaults_init
 */
#define	NIS_SRC_DEFAULT 0
#define	NIS_SRC_ENV 1
#define	NIS_SRC_ARG 2

int nis_default_owner_src = NIS_SRC_DEFAULT;
int nis_default_group_src = NIS_SRC_DEFAULT;
int nis_default_access_src = NIS_SRC_DEFAULT;
int nis_default_ttl_src = NIS_SRC_DEFAULT;

static char *nis_defaults_tokens[] = {
	"owner",
	"group",
	"access",
	"ttl",
	0
};

#define	T_OWNER 0
#define	T_GROUP 1
#define	T_ACCESS 2
#define	T_TTL 3

static int
nis_defaults_set(optstr, src)
	char *optstr;
	int src;
{
	char str[1024], *p, *v;
	int i;

	if (strlcpy(str, optstr, sizeof (str)) >= sizeof (str))
		return (0);
	p = str;

	while ((i = nis_getsubopt(&p, nis_defaults_tokens, ':', &v)) != -1) {
		switch (i) {
		case T_OWNER:
			if (v == 0 || v[strlen(v)-1] != '.')
				return (0);
			nis_default_obj.zo_owner = strdup(v);
			nis_default_owner_src = src;
			break;
		case T_GROUP:
			if (v == 0 || v[strlen(v)-1] != '.')
				return (0);
			nis_default_obj.zo_group = strdup(v);
			nis_default_group_src = src;
			break;
		case T_ACCESS:
			if ((v == 0) ||
			    (!parse_rights(&(nis_default_obj.zo_access), v)))
				return (0);
			nis_default_access_src = src;
			break;
		case T_TTL:
			if ((v == 0) ||
			    !(parse_time(&(nis_default_obj.zo_ttl), v)))
				return (0);
			nis_default_ttl_src = src;
			break;
		}
	}

	if (*p)
		return (0);

	return (1);
}

extern char *getenv();

int
nis_defaults_init(optstr)
	char *optstr;
{
	char *envstr;

	/* XXX calling this multiple times may leak memory */
	memset((char *)&nis_default_obj, 0, sizeof (nis_default_obj));

	nis_default_obj.zo_owner = nis_local_principal();
	nis_default_obj.zo_group = nis_local_group();
	nis_default_obj.zo_access = DEFAULT_RIGHTS;
	nis_default_obj.zo_ttl = 12 * 60 * 60;

	if (envstr = getenv("NIS_DEFAULTS"))
		if (!nis_defaults_set(envstr, NIS_SRC_ENV)) {
			fprintf(stderr,
			"can't parse NIS_DEFAULTS environment variable.\n");
			return (0);
		}

	if (optstr)
		if (!nis_defaults_set(optstr, NIS_SRC_ARG)) {
			fprintf(stderr, "can't parse nis_defaults argument.\n");
			return (0);
		}

	return (1);
}



/*
 * Converts an NIS+ entry object for a passwd table to its
 * pwent structure.
 * XXX: This function returns a pointer to a static structure.
 */
static struct passwd *
nis_object_to_pwent(obj, error)
	nis_object	*obj;
	nis_error	*error;
{
	static struct passwd	pw;
	static char	spacebuf[1024]; /* The pwent structure points to this */
	static char	nullstring;	/* used for NULL data */
	char		*tmp;
	char		*end;

	memset((void *)&pw, 0, sizeof (struct passwd));
	memset((void *)&spacebuf[0], 0, 1024);
	tmp = &spacebuf[0];
	end = tmp + sizeof (spacebuf);

	if ((obj->zo_data.zo_type != NIS_ENTRY_OBJ) ||
	    (obj->EN_data.en_cols.en_cols_len < 8)) {
		*error = NIS_INVALIDOBJ;
		return (NULL);
	}
	if (ENTRY_LEN(obj, 0) == 0) {
		*error = NIS_INVALIDOBJ;
		return (NULL);
	} else {
		(void) strlcpy(tmp, ENTRY_VAL(obj, 0),
			end > tmp ? end - tmp : 0);
		pw.pw_name = tmp;
		tmp += strlen(pw.pw_name) + 1;
	}

	if (ENTRY_LEN(obj, 1) == 0) {
		pw.pw_passwd = &nullstring;
	} else {
		/* XXX: Should I be returning X here? */
		(void) strlcpy(tmp, ENTRY_VAL(obj, 1),
			end > tmp ? end - tmp : 0);
		pw.pw_passwd = tmp;
		tmp += strlen(pw.pw_passwd) + 1;
	}

	if (ENTRY_LEN(obj, 2) == 0) {
		*error = NIS_INVALIDOBJ;
		return (NULL);
	}
	pw.pw_uid = atoi(ENTRY_VAL(obj, 2));

	if (ENTRY_LEN(obj, 3) == 0)
		pw.pw_gid = 0; /* Is this default value? */
	else
		pw.pw_gid = atoi(ENTRY_VAL(obj, 3));

	if (ENTRY_LEN(obj, 4) == 0) {
		pw.pw_gecos = &nullstring;
	} else {
		(void) strlcpy(tmp, ENTRY_VAL(obj, 4),
			end > tmp ? end - tmp : 0);
		pw.pw_gecos = tmp;
		tmp += strlen(pw.pw_gecos) + 1;
	}

	if (ENTRY_LEN(obj, 5) == 0) {
		pw.pw_dir = &nullstring;
	} else {
		(void) strlcpy(tmp, ENTRY_VAL(obj, 5),
			end > tmp ? end - tmp : 0);
		pw.pw_dir = tmp;
		tmp += strlen(pw.pw_dir) + 1;
	}

	if (ENTRY_LEN(obj, 6) == 0) {
		pw.pw_shell = &nullstring;
	} else {
		(void) strlcpy(tmp, ENTRY_VAL(obj, 6),
			end > tmp ? end - tmp : 0);
		pw.pw_shell = tmp;
		tmp += strlen(pw.pw_shell) + 1;
	}

	pw.pw_age = &nullstring;
	pw.pw_comment = &nullstring;
	*error = NIS_SUCCESS;
	return (&pw);
}


/*
 * This will go to the NIS+ master to get the data.  This code
 * is ugly because the internals of the switch had to be opened
 * up here.  Wish there was a way to pass a MASTER_ONLY flag
 * to getpwuid() and all such getXbyY() calls.  Some of this code
 * is being copied from the NIS+ switch backend.
 *
 * XXX: We will not bother to make this MT-safe.  If any of the callers
 * for this function want to use getpwuid_r(), then a corresponding
 * function will have to written.
 */
struct passwd *
getpwuid_nisplus_master(domain, uid, error)
	char *domain;
	uid_t	uid;
	nis_error *error;
{
	struct passwd	*passwd_ent;
	nis_result	*res;
	char		namebuf[NIS_MAXNAMELEN];
	uint_t		flags;

	(void) snprintf(namebuf, sizeof (namebuf),
		"[uid=%ld],passwd.org_dir.%s", uid, domain);
	flags = EXPAND_NAME|FOLLOW_LINKS|FOLLOW_PATH|USE_DGRAM|MASTER_ONLY;
	res = nis_list(namebuf, flags, 0, 0);
	if (res == NULL) {
		*error = NIS_NOMEMORY;
		return (NULL);
	}
	if (res->status != NIS_SUCCESS) {
		nis_freeresult(res);
		*error = res->status;
		return (NULL);
	}
	if (NIS_RES_NUMOBJ(res) == 0) {
		nis_freeresult(res);
		*error = NIS_NOTFOUND;
		return (NULL);
	}

	passwd_ent = nis_object_to_pwent(NIS_RES_OBJECT(res), error);
	nis_freeresult(res);
	return (passwd_ent);
}

/*
 * Converts an NIS+ entry object for a shadow table to its
 * spwent structure.  We only fill in the sp_namp and sp_pwdp fields.
 * XXX: This function returns a pointer to a static structure.
 */
static struct spwd *
nis_object_to_spwent(obj, error)
	nis_object	*obj;
	nis_error	*error;
{
	static struct spwd	spw;
	static char	spacebuf[1024]; /* The pwent structure points to this */
	static char	nullstring;	/* used for NULL data */
	char		*tmp;
	char		*end;

	memset((void *)&spw, 0, sizeof (struct spwd));
	memset((void *)&spacebuf[0], 0, 1024);
	tmp = &spacebuf[0];
	end = tmp + sizeof (spacebuf);

	if ((obj->zo_data.zo_type != NIS_ENTRY_OBJ) ||
	    (obj->EN_data.en_cols.en_cols_len < 8)) {
		*error = NIS_INVALIDOBJ;
		return (NULL);
	}
	if (ENTRY_LEN(obj, 0) == 0) {
		*error = NIS_INVALIDOBJ;
		return (NULL);
	} else {
		(void) strlcpy(tmp, ENTRY_VAL(obj, 0),
			end > tmp ? end - tmp : 0);
		spw.sp_namp = tmp;
		tmp += strlen(spw.sp_namp) + 1;
	}

	if (ENTRY_LEN(obj, 1) == 0) {
		spw.sp_pwdp = &nullstring;
	} else {
		(void) strlcpy(tmp, ENTRY_VAL(obj, 1),
			end > tmp ? end - tmp : 0);
		spw.sp_pwdp = tmp;
		tmp += strlen(spw.sp_pwdp) + 1;
	}

	*error = NIS_SUCCESS;
	return (&spw);
}


/*
 * This will go to the NIS+ master to get the data.  This code
 * is ugly because the internals of the switch had to be opened
 * up here.  Wish there was a way to pass a MASTER_ONLY flag
 * to getspnam() and all such getXbyY() calls.  Some of this code
 * is being copied from the NIS+ switch backend.
 *
 * XXX: We will not bother to make this MT-safe.  If any of the callers
 * for this function want to use getpwuid_r(), then a corresponding
 * function will have to written.
 */
struct spwd *
getspnam_nisplus_master(domain, name, error)
	char *domain;
	char *name;
	nis_error *error;
{
	struct spwd	*shadow_ent;
	nis_result	*res;
	char		namebuf[NIS_MAXNAMELEN];
	uint_t		flags;

	(void) snprintf(namebuf, sizeof (namebuf),
		"[name=%s],passwd.org_dir.%s", name, domain);
	flags = EXPAND_NAME|FOLLOW_LINKS|FOLLOW_PATH|USE_DGRAM|MASTER_ONLY;
	res = nis_list(namebuf, flags, 0, 0);
	if (res == NULL) {
		*error = NIS_NOMEMORY;
		return (NULL);
	}
	if (res->status != NIS_SUCCESS) {
		nis_freeresult(res);
		*error = res->status;
		return (NULL);
	}
	if (NIS_RES_NUMOBJ(res) == 0) {
		nis_freeresult(res);
		*error = NIS_NOTFOUND;
		return (NULL);
	}

	shadow_ent = nis_object_to_spwent(NIS_RES_OBJECT(res), error);
	nis_freeresult(res);
	return (shadow_ent);
}

/* begin bug# 1263305 */

/*
 * __nis_quote_key()
 *
 * Enclose NIS+ terminating characters ']' and ',' within '"' and
 * escape  '"' by doubling it so the string is safe to pass to
 * nis_list(3N) and associated routines.  For example, a src string
 * of "foo[]bar" will result in a dst string of ""foo["]"bar""
 */
char *
__nis_quote_key(const char *src, char *dst, int dstsize)
{

	char *dstorig = dst;
	int dstleft;

	dstleft = dstsize - 4;
	for (; *src != '\0' && dstleft > 0; src++) {
		switch (*src) {
		case ']':
		case ',':
			/* quote the character */
			*dst++ = '"';
			*dst++ = *src;
			*dst++ = '"';
			dstleft -= 3;
			break;

		case '"':
			/* double the quote */
			*dst++ = '"';
			dstleft--;
			/* fall through... */

		default:
			*dst++ = *src;
			dstleft--;
			break;
		}
	}
	*dst = '\0';

	if (*src)
		fprintf(stderr,
			"nis_quote_key: warning: src string too long\n");

	return (dstorig);
}

/*
 * *str* routines below originated in libc.
 */

/*
 * strpbrk_quotes()
 *
 * Like strpbrk except it will not match target chars inside quoted
 * strings ("...").
 */
char *
strpbrk_quotes(char *string, char *brkset)
{
	register const char *p;

	do {
		for (p = brkset; *p != '\0' && *string != '"' && *p != *string;
		    ++p)
			;

		if (*string == '"') {
		    string++;
		    while (*string != '\0' && *string != '"')
			string++;
		} else if (*p != '\0')
			return ((char *)string);
	}
	while (*string++);
	return (NULL);
}


/*
 * strtok_r_quotes()
 *
 * uses strpbrk_quotes and strspn to break string into tokens on
 * sequentially subsequent calls.  returns NULL when no
 * non-separator characters remain.
 * `subsequent' calls are calls with first argument NULL.
 *
 */

static char *
strtok_r_quotes(char *string, char *sepset, char **lasts)
{
	char	*q, *r;

	/* first or subsequent call */
	if (string == NULL)
		string = *lasts;

	if (string == 0)		/* return if no tokens remaining */
		return (NULL);

	q = string + strspn(string, sepset);	/* skip leading separators */

	if (*q == '\0')		/* return if no tokens remaining */
		return (NULL);

	if ((r = strpbrk_quotes(q, sepset)) == NULL)	/* move past token */
		*lasts = 0;	/* indicate this is last token */
	else {
		*r = '\0';
		*lasts = r+1;
	}
	return (q);
}


/*
 * strtok_quotes()
 *
 * Like strtok except it will not match target chars within quoted
 * strings ("...").
 */
char *
strtok_quotes(char *string, char *sepset)
{
	static char *lasts;

	return (strtok_r_quotes(string, sepset, &lasts));
}

/*
 * strchr_quotes()
 *
 * Like strchr but will not match within quoted strings ("...").
 */
char *
strchr_quotes(char *s, char c)
{
	do {
		if (*s == '"') {
			s++;
			while (*s && *s != '"')
				s++;
		} else if (*s == c)
			return (s);
	} while (*s++);
	return (NULL);
}

/* end bug# 1263305 */
