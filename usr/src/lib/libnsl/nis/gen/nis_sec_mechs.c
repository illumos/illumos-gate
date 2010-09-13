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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module contains the interfaces for the NIS+ security mechanisms.
 */

#include "mt.h"
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <rpc/rpc.h>
#include <netconfig.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <thread.h>
#include <synch.h>
#include <dlfcn.h>
#include <rpcsvc/nis_dhext.h>


/*
 * NIS+ security file
 */

#define	NIS_SEC_CF_MAX_LINELEN		512

/* the min number of fields allowable per line */
#define	NIS_SEC_CF_MIN_FIELDS		5
/* the max number of fields processed per line */
#define	NIS_SEC_CF_MAX_FIELDS		7

/* field "Not Applicable" char */
#define	NIS_SEC_CF_NA_CHAR	'-'
#define	NIS_SEC_CF_NA_CMP(a)	((a)[0] == NIS_SEC_CF_NA_CHAR && (a)[1] == '\0')


static const char	*cf_entry_type_mech_str = "mech";
static const char	*cf_mech_des_str = NIS_SEC_CF_DES_ALIAS;
static const char	*cf_mech_dh1920_str = "dh192-0";

static const char	*cf_secserv_default_str = "default";
static const char	*cf_secserv_none_str = "none";
static const char	*cf_secserv_integrity_str = "integrity";
static const char	*cf_secserv_privacy_str = "privacy";

static mutex_t		nis_sec_cf_lock = DEFAULTMUTEX;


/*
 * GSS mechanisms file
 *
 * This is currently a private NIS+ interface but at some point in the future
 * can be broken out and made available to other apps that need to access
 * GSS backends.
 */

#define	MF_MAX_LINELEN	256
#define	MF_MAX_FLDLEN	MAXDHNAME

/* mech file entry type */
typedef struct {
	char *mechname;
	char *oid;
	char *libname;
	/* the 4th field is not used by user land apps */
} mfent_t;

static const char	mech_file[] = "/etc/gss/mech";
static const int	mech_file_flds_max = 3;
static const int	mech_file_flds_min = 3;
static mutex_t		mech_file_lock = DEFAULTMUTEX;
static const char	dh_str[] = "diffie_hellman";


#define	MECH_LIB_PREFIX1	"/usr/lib/"

#ifdef _LP64

#define	MECH_LIB_PREFIX2	"64/"

#else   /* _LP64 */

#define	MECH_LIB_PREFIX2	""

#endif  /* _LP64 */

#define	MECH_LIB_DIR		"gss/"

#define	MECH_LIB_PREFIX	MECH_LIB_PREFIX1 MECH_LIB_PREFIX2 MECH_LIB_DIR


static void
list_free_all(void (*free_ent)(), void **mpp)
{
	void **tpp = mpp;

	if (tpp) {
		for (; *tpp; tpp++)
			(*free_ent)(*tpp);
		free(mpp);
	}
}

static void **
list_append_ent(void *ent, void **list, uint_t cnt, void (*free_ent)())
{
	void **new_l;

	if (!(new_l = realloc(list, sizeof (*list) * (cnt + 1)))) {
		list_free_all(free_ent, list);
		return (NULL);
	}
	*(new_l + cnt - 1) = ent;
	*(new_l + cnt) = NULL;

	return (new_l);
}

static void **
list_copy(void *(*cp_ent)(), void **mpp)
{
	void	**tpp_h;
	void	**tpp;
	void	*tp;
	int 	diff;

	if (!mpp)
		return (NULL);

	for (tpp = mpp; *tpp; tpp++)
		;

	diff = tpp - mpp;

	if (!(tpp_h = calloc(diff + 1, sizeof (*mpp))))
		return (NULL);

	for (tpp = tpp_h; *mpp; mpp++) {
		if (!(tp = (*cp_ent)(*mpp))) {
			free(tpp_h);
			return (NULL);
		}
		*tpp++ = tp;
	}

	return (tpp_h);
}

static char *
nextline(fd, line)
	FILE *fd;
	char *line;
{
	char *cp;

	if (fgets(line, NIS_SEC_CF_MAX_LINELEN, fd) == NULL)
		return (NULL);
	cp = index(line, '\n');
	if (cp)
		*cp = '\0';
	return (line);
}

static int
nextfield(char **cpp, char *op, int n)
{

	intptr_t max;
	char *dst = op;
	char *cp = *cpp;

	while (*cp == ' ' || *cp == '\t')
		cp++;
	if (*cp == '\0' || *cp == '#')
		return (0);

	max = (intptr_t)op + n;
	while (*cp && *cp != ' ' && *cp != '\t' && *cp != '#' &&
		(intptr_t)dst < max)
		*dst++ = *cp++;
	*dst = '\0';

	if ((intptr_t)dst >= max)
		/* not much else to do but move past current field */
		while (*cp && *cp != ' ' && *cp != '\t' && *cp != '#')
			cp++;

	*cpp = cp;

	return (1);
}


static rpc_gss_service_t
str_to_secserv_t(const char *s)
{

	if (s) {
		if (strncmp(cf_secserv_none_str, s,
			    strlen(cf_secserv_none_str)) == 0)
			return (rpc_gss_svc_none);
		if (strncmp(cf_secserv_integrity_str, s,
			    strlen(cf_secserv_integrity_str)) == 0)
			return (rpc_gss_svc_integrity);
		if (strncmp(cf_secserv_privacy_str, s,
			    strlen(cf_secserv_privacy_str)) == 0)
			return (rpc_gss_svc_privacy);
	}

	return (rpc_gss_svc_default);
}

/*
 * Return TRUE if all the chars up to the NUL are of the digit type.
 * Else return FALSE.
 */
static bool_t
isnumberstr(const char *s)
{

	for (; *s; s++)
		if (!isdigit(*s))
			return (FALSE);

	return (TRUE);
}

/*
 * Free security file mechanism entry.
 */
static void
sf_free_mech_ent(mechanism_t *mp)
{
	if (mp) {
		if (mp->mechname)
			free(mp->mechname);
		if (mp->alias)
			free(mp->alias);
		if (mp->qop)
			free(mp->qop);
		free(mp);
	}
}

static void
free_fields(char **cpp, int cnt)
{
	char **tpp = cpp;

	if (cpp) {
		if (cnt)
			for (; cnt > 0; cnt--, tpp++)
				if (*tpp)
					free(*tpp);
				else
					break;
		free(cpp);
	}
}

/*
 * Generic parse-linestr-of-config-file routine.  Arg linep is ptr
 * (which will be modified) to the input string .  Arg minflds is the
 * minimum number of fields expected.  Arg maxflds is the max number
 * of fields that will be parsed.  Arg bufsiz is the max len of each
 * field that will  be copied to the return area.
 *
 * If there are less fields in the entry than the max number,
 * the remainding ptrs will be 0.
 *
 * Returns a ptr to an array of ptrs to strings on success else
 * NULL on failure.
 *
 * The caller must free the storage (of a successful return only).
 */
static char **
parse_line(char *linep, int minflds, int maxflds, int bufsiz)
{
	char **fpp = calloc(maxflds, sizeof (linep));
	char **tpp = fpp;
	char *cp;
	int	i;

	if (!fpp)
		return (NULL);

	if (!(cp = malloc(bufsiz))) {
		free(fpp);
		return (NULL);
	}

	for (i = 0; i < maxflds; i++, tpp++) {
		char *tp;
		if (!nextfield(&linep, cp, bufsiz)) {
			free(cp);
			if (i < minflds) {
				free_fields(fpp, i);
				return (NULL);
			} else
				return (fpp);
		}
		if (!(tp = strdup(cp))) {
			free_fields(fpp, i);
			free(cp);
			return (NULL);
		}
		*tpp = tp;
	}

	free(cp);
	return (fpp);
}

/*
 * Return a ptr to a mechanism entry read from a line of the sec conf file.
 * Return NULL on EOF or error.
 *
 * An alias field of "des" (case not sig) will override any settings
 * in the keylen or algtype fields like so:
 *    keylen  = 192
 *    algtype = 0
 */

static mechanism_t *
get_secfile_ent(FILE *fptr)
{
	mechanism_t	*m;
	char		*cp;
	char		**flds;  /* line fields */
	const int	num_flds_min = NIS_SEC_CF_MIN_FIELDS;
	const int	num_flds_max = NIS_SEC_CF_MAX_FIELDS;
	char		line[NIS_SEC_CF_MAX_LINELEN + 1 ] = {0};
	const int	line_len = NIS_SEC_CF_MAX_LINELEN + 1;

	/*
	 * NIS+ security conf file layout
	 * <Entry_type>
	 * mech 	<GSS_mechanism_name> <Mech_bit_size> <Mech_alg_type>
	 * 		<Alias> <GSS_quality_of_protection> <GSS_sec_svc>
	 *
	 * QOP and sec_svc are optional.
	 */
	const int	mn_offset = 1; /* mechname */
	const int	kl_offset = 2; /* key length */
	const int	at_offset = 3; /* alg type */
	const int	al_offset = 4; /* mech alias */
	const int	qp_offset = 5; /* qop */
	const int	ss_offset = 6; /* security svc */

cont:
	while (((cp = nextline(fptr, line)) != NULL) &&
		(*cp == '#' || *cp == '\0'))
		;
	if (cp == NULL)
		return (NULL);

	if (!(flds = parse_line(cp, num_flds_min, num_flds_max,
					line_len)))
		goto cont;

	if (strncmp(cf_entry_type_mech_str, *flds,
		    strlen(cf_entry_type_mech_str))) {
		free_fields(flds, num_flds_max);
		goto cont;
	}

	if (!(m = malloc(sizeof (mechanism_t)))) {
		free_fields(flds, num_flds_max);
		return (NULL);
	}

	/* mechanism name */
	m->mechname = NIS_SEC_CF_NA_CMP(*(flds + mn_offset)) ? NULL
		: strdup(*(flds + mn_offset));

	/* mechanism alias */
	m->alias = NIS_SEC_CF_NA_CMP(*(flds + al_offset)) ? NULL
		: strdup(*(flds + al_offset));

	/*
	 * qop: optional field
	 * Make qop NULL if the field was empty or was "default" or
	 * was '-'.
	 */
	if (!*(flds + qp_offset) ||
	    (strncasecmp(*(flds + qp_offset), cf_secserv_default_str,
				strlen(cf_secserv_default_str)) == 0) ||
	    NIS_SEC_CF_NA_CMP(*(flds + qp_offset)))
		m->qop = NULL;
	else
		m->qop = strdup(*(flds + qp_offset));

	/* security service: optional field */
	m->secserv  = str_to_secserv_t(*(flds + ss_offset));

	/* mech alias */
	if (*(flds + al_offset) &&
	    (strncasecmp(*(flds + al_offset), cf_mech_des_str,
				strlen(cf_mech_des_str)) == 0)) {
		/* we've got the AUTH_DES compat line */
		m->keylen = 192;
		m->algtype = 0;
	} else {
		/* key length (bits) */
		if (NIS_SEC_CF_NA_CMP(*(flds + kl_offset)))
			m->keylen = NIS_SEC_CF_NA_KA;
		else if (!isnumberstr(*(flds + kl_offset))) {
			free_fields(flds, num_flds_max);
			sf_free_mech_ent(m);
			goto cont;
		} else
			m->keylen =  atoi(*(flds + kl_offset));

		/* algorithm type */
		if (NIS_SEC_CF_NA_CMP(*(flds + at_offset)))
			m->algtype = NIS_SEC_CF_NA_KA;
		else if (!isnumberstr(*(flds + at_offset))) {
			free_fields(flds, num_flds_max);
			sf_free_mech_ent(m);
			goto cont;
		} else
			m->algtype =  atoi(*(flds + at_offset));
	}

	free_fields(flds, num_flds_max);

	return (m);
}

/*
 * Return TRUE if both entries have the same
 * mechname/alias/keylen/algotype combo.  Else return FALSE.
 */
static bool_t
equal_entries(const mechanism_t *mp, const mechanism_t *tp)
{
	if (mp && tp) {
		if (mp->keylen != tp->keylen)
			return (FALSE);
		if (mp->algtype != tp->algtype)
			return (FALSE);

		/* both NULL, the 2 are equal */
		if (!mp->mechname && !tp->mechname)
			return (TRUE);
		/* only one NULL, not equal */
		if (!mp->mechname || !tp->mechname)
			return (FALSE);
		if (strcmp(mp->mechname, tp->mechname) != 0)
			return (FALSE);

		if (!mp->alias && !tp->alias)
			return (TRUE);
		if (!mp->alias || !tp->alias)
			return (FALSE);
		if (strcmp(mp->alias, tp->alias) != 0)
			return (FALSE);
	}

	return (TRUE);
}

static mechanism_t *
sf_copy_mech_ent(mechanism_t *mp)
{
	mechanism_t *tp = calloc(1, sizeof (*mp));

	if (!mp || !tp)
		return (NULL);

	tp->mechname = mp->mechname ? strdup(mp->mechname) : NULL;
	tp->alias = mp->alias ? strdup(mp->alias) : NULL;
	tp->qop = mp->qop ? strdup(mp->qop) : NULL;
	tp->keylen = mp->keylen;
	tp->algtype = mp->algtype;
	tp->secserv = mp->secserv;

	return (tp);
}

/*
 * Return TRUE if the mechname/alias/keylen/algtype combo
 * already exists in the no dups array.  Else return FALSE.
 */
static bool_t
member_of_dups(mechanism_t **t, const mechanism_t *mp)
{

	if (t)
		for (; *t; t++)
			if (equal_entries(mp, *t))
				return (TRUE);

	return (FALSE);
}

/*
 * Return a list of valid mechanisms ranked by sequence in the NIS+
 * security conf file.  Return NULL if there are no valid entries.
 * On success, the last pointer of the array of pointers will be NULL.
 *
 * If input arg 'qop_secserv' is TRUE, include duplicate
 * mechname/alias/keylen/algtype entries that differ only in the QOP
 * and security service.  Else, duplicates are omitted.
 *
 * The list of mechanisms are gauranteed to be valid ones installed
 * on the system.
 *
 * This implementation returns copies of the "master" list.  The "master"
 * list will updated if the file is modified.
 */

mechanism_t **
__nis_get_mechanisms(bool_t qop_secserv)
{
	/*
	 * 'mechs' is the "master" list of valid mechanisms from
	 * the NIS+ security conf file.
	 * 'mechs_no_dups' is the "master" list of valid mechanisms
	 * that differ only in QOP/SecuritySvc fields.
	 */
	static mechanism_t	**mechs = NULL;
	static mechanism_t	**mechs_no_dups = NULL;

	mechanism_t	*mp;
	mechanism_t	**tmechs = NULL;	 /* temp mechs */
	mechanism_t	**tmechs_no_dups = NULL; /* temp mechs sans dups */
	int		ent_cnt = 0;		 /* valid cf file entry count */
	int		ent_cnt_no_dups = 0;	 /* valid cf count, no dups */
	static uint_t	last = 0;
	struct stat	sbuf;
	FILE 		*fptr;

	if (stat(NIS_SEC_CF_PATHNAME, &sbuf) != 0)
		return (NULL);

	(void) mutex_lock(&nis_sec_cf_lock);
	if (sbuf.st_mtime > last) {
		last = sbuf.st_mtime;

		if (mechs) {
			/* free old master lists */
			__nis_release_mechanisms(mechs);
			if (mechs_no_dups)
				free(mechs_no_dups);
		}
		mechs = mechs_no_dups = NULL;

		if (!(fptr = fopen(NIS_SEC_CF_PATHNAME, "rF"))) {
			(void) mutex_unlock(&nis_sec_cf_lock);
			return (NULL);
		}

		while (mp = get_secfile_ent(fptr)) {
			/*
			 * Make sure entry is either the AUTH_DES compat
			 * one or a valid GSS one that is installed.
			 */
			if (!(AUTH_DES_COMPAT_CHK(mp) ||
				(NIS_SEC_CF_GSS_MECH(mp) &&
					rpc_gss_is_installed(mp->mechname)))) {
				continue;
			}

			ent_cnt++;
			tmechs = (mechanism_t **)
			    list_append_ent((void *)mp, (void **)tmechs,
			    ent_cnt, (void (*)())sf_free_mech_ent);
			if (tmechs == NULL) {
				(void) fclose(fptr);
				(void) mutex_unlock(&nis_sec_cf_lock);
				return (NULL);
			}

			if (member_of_dups(tmechs_no_dups, mp))
				continue;

			ent_cnt_no_dups++;
			tmechs_no_dups = (mechanism_t **)
			    list_append_ent((void *)mp, (void **)tmechs_no_dups,
			    ent_cnt_no_dups, (void (*)())sf_free_mech_ent);
			if (tmechs_no_dups == NULL) {
				(void) fclose(fptr);
				(void) mutex_unlock(&nis_sec_cf_lock);
				return (NULL);
			}
		}
		(void) fclose(fptr);

		/* set master lists to point to new built ones */
		mechs = tmechs;
		mechs_no_dups = tmechs_no_dups;
	}
	(void) mutex_unlock(&nis_sec_cf_lock);

	if (qop_secserv)
		/* return a copy of the list with possible dups */
		return (mechs ?
			(mechanism_t **)list_copy(
				(void *(*)()) sf_copy_mech_ent,
				(void **)mechs) :
			NULL);

	/* return a copy of the list without dups */
	return (mechs_no_dups ?
		(mechanism_t **)list_copy((void *(*)()) sf_copy_mech_ent,
						(void **)mechs_no_dups) :
		NULL);
}

/*
 * Search the mechs (no dups array) for an entry (mechname or alias)
 * that matches (case not sig) the given mechname.  On target match,
 * load the given memory locations pointed to by args keylen and
 * algtype with values from the matched entry.
 *
 * The AUTH_DES "compat" line (alias == "des") will return 192-0
 * (overriding the fields in the conf file).
 *
 * For any other entry, a conf file field of '-' (not applicable),
 * in the keylen or algtype field will result in the locations for
 * keylen and algtype being set to -1. (this is actually done in
 * __nis_get_mechanisms()).
 *
 * Returns 0 on success and -1 on failure.
 */
int
__nis_translate_mechanism(const char *mechname, int *keylen, int *algtype)
{
	mechanism_t **mpp;
	mechanism_t **mpp_h;

	if (!mechname || !keylen || !algtype)
		return (-1);

	/* AUTH_DES */
	if (strcmp(mechname, NIS_SEC_CF_DES_ALIAS) == 0) {
		*keylen = AUTH_DES_KEYLEN;
		*algtype = AUTH_DES_ALGTYPE;
		return (0);
	}

	if (!(mpp = __nis_get_mechanisms(FALSE)))
		return (-1);

	mpp_h = mpp;
	for (; *mpp; mpp++) {
		mechanism_t *mp = *mpp;
		if (mp->mechname &&
		    (!strcasecmp(mechname, mp->mechname))) {
				*keylen = mp->keylen;
				*algtype = mp->algtype;
				__nis_release_mechanisms(mpp_h);
				return (0);
		}
		if (mp->alias &&
		    (!strcasecmp(mechname, mp->alias))) {
				*keylen = mp->keylen;
				*algtype = mp->algtype;
				__nis_release_mechanisms(mpp_h);
				return (0);
		}
	}

	__nis_release_mechanisms(mpp_h);
	return (-1);
}


/*
 * Translate a mechname to an alias name.
 *
 * Returns alias on success or NULL on failure.
 *
 * Note alias will be the nullstring CSTYLE(on success) if cf
 * alias field was "Not Applicable".
 */
char *
__nis_mechname2alias(const char *mechname,	/* in */
			char *alias,		/* out */
			size_t bufsize)		/* in */
{
	mechanism_t **mpp;
	mechanism_t **mpp_h;

	if (!mechname || !alias)
		return (NULL);

	if (!(mpp = __nis_get_mechanisms(FALSE)))
		return (NULL);

	mpp_h = mpp;
	for (; *mpp; mpp++) {
		mechanism_t *mp = *mpp;
		int len;

		if (mp->mechname &&
		    (strcasecmp(mechname, mp->mechname) == 0)) {
			if (mp->alias) {
				if ((len = strlen(mp->alias)) < bufsize) {
					(void) strncpy(alias, mp->alias,
							len + 1);
					__nis_release_mechanisms(mpp_h);
					return (alias);
				}
			} else { /* cf file entry alias field was NA */
				alias[0] = '\0';
				__nis_release_mechanisms(mpp_h);
				return (alias);
			}

		}
	}

	__nis_release_mechanisms(mpp_h);
	return (NULL);
}

void
__nis_release_mechanisms(mechanism_t **mpp)
{
	list_free_all(sf_free_mech_ent, (void **)mpp);
}

/*
 * Convert an authtype (ie. DH640-0) to mechanism alias (ie. dh640-0).
 * Input the authtype ptr, the mechalis ptr and the size of the mechalias
 * buf.
 *
 * If mechalias buf is not large enough, truncate and don't indicate failure.
 *
 * Return the mechalias ptr on success or NULL on failure CSTYLE(any of
 * the input args are NULL/0).
 */
char *
__nis_authtype2mechalias(
	const char *authtype,	/* in */
	char *mechalias,	/* out */
	size_t mechaliaslen)	/* in */
{
	char *dst = mechalias;
	const char *src = authtype;
	const char *max = src + mechaliaslen;

	if (!src || !dst || mechaliaslen == 0)
		return (NULL);

	while (*src && src < max - 1)
		*dst++ = tolower(*src++);

	*dst = '\0';

	return (mechalias);
}

/*
 * Convert an mechalias (ie. dh640-0) to authtype (ie. DH640-0).
 * Input the authtype ptr, the mechalis ptr and the size of the mechalias
 * buf.
 *
 * A special mechalias of "dh192-0" will get converted to "DES".
 *
 * If authtype buf is not large enough, truncate and don't indicate failure.
 *
 * Return the authtype ptr on success or NULL on failure (any of
 * the input args are NULL/0.
 */
char *
__nis_mechalias2authtype(
	const char *mechalias,	/* in */
	char *authtype,		/* out */
	size_t authtypelen)	/* in */

{
	const char *src = mechalias;
	char *dst = authtype;
	const char *max = src + authtypelen;
	const int slen = strlen(cf_mech_dh1920_str);

	if (!src || !dst || !authtypelen)
		return (NULL);

	if (strncasecmp(src, cf_mech_dh1920_str, slen + 1)
	    == 0) {
		if (slen >= authtypelen)
			return (NULL);
		(void) strcpy(authtype, AUTH_DES_AUTH_TYPE);
		return (authtype);
	}

	while (*src && src < max - 1)
		*dst++ = toupper(*src++);

	*dst = '\0';

	return (authtype);
}

/*
 * Given a DH key length and algorithm type, return the mech
 * alias string.  If the keyalg is not the classic AUTH_DES,
 * then search the NIS+ security cf.
 *
 * On success return the mech alias string address.  Return
 * NULL on failure.  Failure occurs if keylen or algtype is
 * not found or the length of the input buf is too small
 * or input args are bogus.  Alias buf will not be
 * changed on failure.
 */
char *
__nis_keyalg2mechalias(
	keylen_t	keylen,		/* in */
	algtype_t	algtype,	/* in */
	char		*alias,		/* out */
	size_t		alias_len)	/* in */
{
	mechanism_t	**mechs;  /* array of mechanisms */

	if (!alias)
		return (NULL);

	if (AUTH_DES_KEY(keylen, algtype)) {
		if (alias_len > strlen(NIS_SEC_CF_DES_ALIAS)) {
			(void) strcpy(alias, NIS_SEC_CF_DES_ALIAS);
			return (alias);
		}
		else
			return (NULL);
	} else
		if (mechs = __nis_get_mechanisms(FALSE)) {
			mechanism_t **mpp;

			for (mpp = mechs; *mpp; mpp++) {
				mechanism_t *mp = *mpp;

				if (!VALID_MECH_ENTRY(mp) ||
				    AUTH_DES_COMPAT_CHK(mp))
					continue;

				if (keylen == mp->keylen &&
				    algtype == mp->algtype && mp->alias) {
					int al_len = strlen(mp->alias);

					if (alias_len > al_len) {
						(void) strncpy(alias, mp->alias,
							al_len + 1);
						return (alias);
					} else {
						__nis_release_mechanisms(mechs);
						return (NULL);
					}
				}
			}
			__nis_release_mechanisms(mechs);
		}

	return (NULL);
}

/*
 * Given the key length and algorithm type, return the auth type
 * string suitable for the cred table.
 *
 * Return the authtype on success and NULL on failure.
 */
char *
__nis_keyalg2authtype(
	keylen_t keylen,	/* in */
	algtype_t algtype,	/* in */
	char *authtype,		/* out */
	size_t authtype_len)	/* in */
{
	char alias[MECH_MAXALIASNAME+1] = {0};


	if (!authtype || authtype_len == 0)
		return (NULL);

	if (!__nis_keyalg2mechalias(keylen, algtype, alias, sizeof (alias)))
		return (NULL);

	if (!__nis_mechalias2authtype(alias, authtype, authtype_len))
		return (NULL);

	return (authtype);
}

/*
 * Return a ptr to the next mech file entry or NULL on EOF.
 * The caller should free the storage of a successful return.
 */
static mfent_t *
get_mechfile_ent(FILE *fptr)
{
	mfent_t		*m;
	char		*cp;
	char		**flds;
	char		line[MF_MAX_LINELEN] = {0};


cont:
	while (((cp = nextline(fptr, line)) != NULL) &&
		(*cp == '#' || *cp == '\0'))
		;
	if (cp == NULL)
		return (NULL);

	if (!(flds = parse_line(cp, mech_file_flds_min,
					mech_file_flds_max, MF_MAX_FLDLEN)))
		goto cont;

	if (!(m = malloc(sizeof (mfent_t)))) {
		free_fields(flds, mech_file_flds_max);
		return (NULL);
	}

	m->mechname = strdup(*flds);
	m->oid = strdup(*(flds + 1));
	m->libname = strdup(*(flds + 2));

	free_fields(flds, mech_file_flds_max);

	return (m);
}

static mfent_t *
mf_copy_ent(mfent_t *mp)
{
	mfent_t *tp = calloc(1, sizeof (*mp));

	if (!mp || !tp)
		return (NULL);

	tp->mechname = mp->mechname ? strdup(mp->mechname) : NULL;
	tp->oid = mp->oid ? strdup(mp->oid) : NULL;
	tp->libname = mp->libname ? strdup(mp->libname) : NULL;

	return (tp);
}


static void
mf_free_ent(mfent_t *mp)
{
	if (mp) {
		if (mp->mechname)
			free(mp->mechname);
		if (mp->oid)
			free(mp->oid);
		if (mp->libname)
			free(mp->libname);
		free(mp);
	}
}


static void
mf_free_mechs(mfent_t **mpp)
{
	list_free_all(mf_free_ent, (void **)mpp);
}

/*
 * Return a copy of the list of the mech file entries.  The ptr to the last
 * entry will be NULL on success.  The master list will be updated when
 * the mechs file is modified.
 *
 * Return NULL if the file does not exist or no valid mechs exist in the
 * file.
 */
static mfent_t **
mf_get_mechs()
{
	static mfent_t	**mechs = NULL;		/* master mechs list */
	mfent_t		*mp;			/* a mech entry */
	mfent_t		**tmechs = NULL;	/* temp mechs list */
	uint_t		ent_cnt = 0;		/* valid cf file entry count */
	static uint_t	last = 0;		/* file last modified date */
	struct stat	sbuf;
	FILE 		*fptr;

	if (stat(mech_file, &sbuf) != 0)
		return (NULL);

	(void) mutex_lock(&mech_file_lock);
	if (sbuf.st_mtime > last) {
		last = sbuf.st_mtime;

		if (mechs) {
			/* free old master list */
			mf_free_mechs(mechs);
			mechs = NULL;
		}

		if (!(fptr = fopen(mech_file, "rF"))) {
			(void) mutex_unlock(&mech_file_lock);
			return (NULL);
		}

		while (mp = get_mechfile_ent(fptr)) {
			ent_cnt++;
			tmechs = (mfent_t **)list_append_ent((void *)mp,
			    (void **)tmechs, ent_cnt, (void (*)()) mf_free_ent);
			if (tmechs == NULL) {
				(void) fclose(fptr);
				(void) mutex_unlock(&mech_file_lock);
				return (NULL);
			}
		}
		(void) fclose(fptr);

		mechs = tmechs;  /* set master list to pt to newly built one */
	}
	(void) mutex_unlock(&mech_file_lock);

	/* return a copy of the master list */
	return (mechs ? (mfent_t **)list_copy((void *(*)()) mf_copy_ent,
						(void **)mechs) : NULL);
}

/*
 * Translate a full mechname to it's corresponding library name
 * as specified in the mech file.
 */
char *
mechfile_name2lib(const char *mechname, char *libname, int len)
{
	mfent_t **mechs = mf_get_mechs();
	mfent_t **mpp;

	if (!mechs || !mechname || !libname || !len)
		return (NULL);

	for (mpp = mechs; *mpp; mpp++) {
		mfent_t *mp = *mpp;

		if (mp->mechname && strcasecmp(mechname, mp->mechname) == 0) {
			if (strlen(mp->libname) < len) {
				(void) strcpy(libname, mp->libname);
					mf_free_mechs(mechs);
					return (libname);
				}
		}
	}
	mf_free_mechs(mechs);

	return (NULL);
}

/*
 * Given a key length and algo type, return the appro DH mech library
 * name.
 */
char *
__nis_get_mechanism_library(keylen_t keylen, algtype_t algtype,
			    char *buffer, size_t buflen)
{
	char mechname[MAXDHNAME + 1];

	if (keylen == 0 || !buffer || buflen == 0)
		return (NULL);

	(void) snprintf(mechname, sizeof (mechname),
					"%s_%d_%d", dh_str, keylen, algtype);

	if (!mechfile_name2lib(mechname, buffer, buflen))
		return (NULL);

	return (buffer);
}

/*
 * Input key length, algorithm type, and a string identifying a symbol
 * (example: "__gen_dhkeys").
 *
 * Returns a function pointer to the specified symbol in the appropriate
 * key length/algorithm type library, or NULL if the symbol isn't found.
 */
void *
__nis_get_mechanism_symbol(keylen_t keylen,
				algtype_t algtype,
				const char *symname)

{
	void *handle;
	char libname[MAXDHNAME+1];
	char libpath[MAXPATHLEN+1];

	if (!__nis_get_mechanism_library(keylen, algtype, libname, MAXDHNAME))
		return (NULL);

	if (strlen(MECH_LIB_PREFIX) + strlen(libname) + 1 > sizeof (libpath))
		return (NULL);

	(void) snprintf(libpath, sizeof (libpath),
					"%s%s", MECH_LIB_PREFIX, libname);

	if (!(handle = dlopen(libpath, RTLD_LAZY)))
		return (NULL);

	return (dlsym(handle, symname));
}
