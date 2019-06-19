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
 */

#pragma	weak _crypt = crypt
#pragma weak _encrypt = encrypt
#pragma weak _setkey = setkey

#include "lint.h"
#include "mtlib.h"
#include <synch.h>
#include <thread.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/time.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>
#include <atomic.h>

#include <crypt.h>
#include <libc.h>
#include "tsd.h"

#define	CRYPT_ALGORITHMS_ALLOW		"CRYPT_ALGORITHMS_ALLOW"
#define	CRYPT_ALGORITHMS_DEPRECATE	"CRYPT_ALGORITHMS_DEPRECATE"
#define	CRYPT_DEFAULT			"CRYPT_DEFAULT"
#define	CRYPT_UNIX			"__unix__"

#define	CRYPT_CONFFILE		"/etc/security/crypt.conf"
#define	POLICY_CONF_FILE	"/etc/security/policy.conf"

#define	CRYPT_CONFLINELENGTH	1024

#define	CRYPT_MODULE_ISA	"/$ISA/"
#ifdef	_LP64
#define	CRYPT_MODULE_DIR	"/usr/lib/security/64/"
#define	CRYPT_ISA_DIR		"/64/"
#else	/* !_LP64 */
#define	CRYPT_MODULE_DIR	"/usr/lib/security/"
#define	CRYPT_ISA_DIR		"/"
#endif	/* _LP64 */

/*
 * MAX_ALGNAME_LEN:
 *
 * In practical terms this is probably never any bigger than about 10, but...
 *
 * It has to fix the encrypted password filed of struct spwd it is
 * theoretically the maximum length of the cipher minus the magic $ sign.
 * Though that would be unexpected.
 * Since it also has to fit in crypt.conf it is CRYPT_CONFLINELENGTH
 * minus the path to the module and the minimum white space.
 *
 * CRYPT_MAXCIPHERTEXTLEN is defined in crypt.h and is smaller than
 * CRYPT_CONFLINELENGTH, and probably always will be.
 */
#define	MAX_ALGNAME_LEN	(CRYPT_MAXCIPHERTEXTLEN - 1)

struct crypt_alg_s {
	void	*a_libhandle;
	char	*(*a_genhash)(char *, const size_t, const char *,
		    const char *, const char **);
	char	*(*a_gensalt)(char *, const size_t,
		    const char *, const struct passwd *, const char **);
	char	**a_params;
	int	a_nparams;
};

struct crypt_policy_s {
	char	*cp_default;
	char	*cp_allow;
	char	*cp_deny;
};

enum crypt_policy_error_e {
	CPE_BOTH = 1,
	CPE_MULTI
};

static struct crypt_policy_s *getcryptpolicy(void);
static void free_crypt_policy(struct crypt_policy_s *policy);
static struct crypt_alg_s  *getalgbyname(const char *algname, boolean_t *found);
static void free_crypt_alg(struct crypt_alg_s *alg);
static char *getalgfromsalt(const char *salt);
static boolean_t alg_valid(const char *algname,
    const struct crypt_policy_s *policy);
static char *isa_path(const char *path);

static char *_unix_crypt(const char *pw, const char *salt, char *iobuf);
static char *_unix_crypt_gensalt(char *gsbuffer, size_t gsbufflen,
	    const char *oldpuresalt, const struct passwd *userinfo,
	    const char *params[]);


/*
 * crypt - string encoding function
 *
 * This function encodes strings in a suitable for for secure storage
 * as passwords.  It generates the password hash given the plaintext and salt.
 *
 * If the first character of salt is "$" then we use crypt.conf(4) to
 * determine which plugin to use and run the crypt_genhash_impl(3c) function
 * from it.
 * Otherwise we use the old unix algorithm.
 *
 * RETURN VALUES
 *	On Success we return a pointer to the encoded string.  The
 *	return value points to thread specific static data and should NOT
 *	be passed free(3c).
 *	On failure we return NULL and set errno to one of:
 *		EINVAL, ELIBACC, ENOMEM, ENOSYS.
 */
char *
crypt(const char *plaintext, const char *salt)
{
	struct crypt_alg_s *alg;
	char *ctbuffer;
	char *ciphertext;
	char *algname;
	boolean_t found;

	ctbuffer = tsdalloc(_T_CRYPT, CRYPT_MAXCIPHERTEXTLEN, NULL);
	if (ctbuffer == NULL)
		return (NULL);
	bzero(ctbuffer, CRYPT_MAXCIPHERTEXTLEN);

	/*
	 * '$' is never a possible salt char with the traditional unix
	 * algorithm.  If the salt passed in is NULL or the first char
	 * of the salt isn't a $ then do the traditional thing.
	 * We also do the traditional thing if the salt is only 1 char.
	 */
	if (salt == NULL || salt[0] != '$' || strlen(salt) == 1) {
		return (_unix_crypt(plaintext, salt, ctbuffer));
	}

	/*
	 * Find the algorithm name from the salt and look it up in
	 * crypt.conf(4) to find out what shared object to use.
	 * If we can't find it in crypt.conf then getalgbyname would
	 * have returned with found = B_FALSE so we use the unix algorithm.
	 * If alg is NULL but found = B_TRUE then there is a problem with
	 * the plugin so we fail leaving errno set to what getalgbyname()
	 * set it to or EINVAL it if wasn't set.
	 */
	if ((algname = getalgfromsalt(salt)) == NULL) {
		return (NULL);
	}

	errno = 0;
	alg = getalgbyname(algname, &found);
	if ((alg == NULL) || !found) {
		if (errno == 0)
			errno = EINVAL;
		ciphertext = NULL;
		goto cleanup;
	} else if (!found) {
		ciphertext = _unix_crypt(plaintext, salt, ctbuffer);
	} else {
		ciphertext = alg->a_genhash(ctbuffer, CRYPT_MAXCIPHERTEXTLEN,
		    plaintext, salt, (const char **)alg->a_params);
	}

cleanup:
	free_crypt_alg(alg);
	if (algname != NULL)
		free(algname);

	return (ciphertext);
}

/*
 * crypt_gensalt - generate salt string for string encoding
 *
 * This function generates the salt string pased to crypt(3c).
 * If oldsalt is NULL, the use the default algorithm.
 * Other wise check the policy in policy.conf to ensure that it is
 * either still allowed or not deprecated.
 *
 * RETURN VALUES
 * 	Return a pointer to the new salt, the caller is responsible
 * 	for using free(3c) on the return value.
 * 	Returns NULL on error and sets errno to one of:
 * 		EINVAL, ELIBACC, ENOMEM
 */
char *
crypt_gensalt(const char *oldsalt, const struct passwd *userinfo)
{
	struct crypt_alg_s *alg = NULL;
	struct crypt_policy_s *policy = NULL;
	char *newsalt = NULL;
	char *gsbuffer;
	char *algname = NULL;
	boolean_t found;

	gsbuffer = calloc(CRYPT_MAXCIPHERTEXTLEN, sizeof (char *));
	if (gsbuffer == NULL) {
		errno = ENOMEM;
		goto cleanup;
	}

	policy = getcryptpolicy();
	if (policy == NULL) {
		errno = EINVAL;
		goto cleanup;
	}

	algname = getalgfromsalt(oldsalt);
	if (!alg_valid(algname, policy)) {
		free(algname);
		algname = strdup(policy->cp_default);
	}

	if (strcmp(algname, CRYPT_UNIX) == 0) {
		newsalt = _unix_crypt_gensalt(gsbuffer, CRYPT_MAXCIPHERTEXTLEN,
		    oldsalt, userinfo, NULL);
	} else {
		errno = 0;
		alg = getalgbyname(algname, &found);
		if (alg == NULL || !found) {
			if (errno == 0)
				errno = EINVAL;
			goto cleanup;
		}
		newsalt = alg->a_gensalt(gsbuffer, CRYPT_MAXCIPHERTEXTLEN,
		    oldsalt, userinfo, (const char **)alg->a_params);
	}

cleanup:
	free_crypt_policy(policy);
	free_crypt_alg(alg);
	if (newsalt == NULL && gsbuffer != NULL)
		free(gsbuffer);
	if (algname != NULL)
		free(algname);

	return (newsalt);
}

/*
 * ===========================================================================
 * The remainder of this file contains internal interfaces for
 * the implementation of crypt(3c) and crypt_gensalt(3c)
 * ===========================================================================
 */


/*
 * getalgfromsalt - extract the algorithm name from the salt string
 */
static char *
getalgfromsalt(const char *salt)
{
	char algname[CRYPT_MAXCIPHERTEXTLEN];
	int i;
	int j;

	if (salt == NULL || strlen(salt) > CRYPT_MAXCIPHERTEXTLEN)
		return (NULL);
	/*
	 * Salts are in this format:
	 * $<algname>[,var=val,[var=val ...][$puresalt]$<ciphertext>
	 *
	 * The only bit we need to worry about here is extracting the
	 * name which is the string between the first "$" and the first
	 * of "," or second "$".
	 */
	if (salt[0] != '$') {
		return (strdup(CRYPT_UNIX));
	}

	i = 1;
	j = 0;
	while (salt[i] != '\0' && salt[i] != '$' && salt[i] != ',') {
		algname[j] = salt[i];
		i++;
		j++;
	}
	if (j == 0)
		return (NULL);

	algname[j] = '\0';

	return (strdup(algname));
}


/*
 * log_invalid_policy - syslog helper
 */
static void
log_invalid_policy(enum crypt_policy_error_e error, char *value)
{
	switch (error) {
	case CPE_BOTH:
		syslog(LOG_AUTH | LOG_ERR,
		    "crypt(3c): %s contains both %s and %s; only one may be "
		    "specified, using first entry in file.", POLICY_CONF_FILE,
		    CRYPT_ALGORITHMS_ALLOW, CRYPT_ALGORITHMS_DEPRECATE);
		break;
	case CPE_MULTI:
		syslog(LOG_AUTH | LOG_ERR,
		    "crypt(3c): %s contains multiple %s entries;"
		    "using first entry file.", POLICY_CONF_FILE, value);
		break;
	}
}

static char *
getval(const char *ival)
{
	char *tmp;
	char *oval;
	int off;

	if (ival == NULL)
		return (NULL);

	if ((tmp = strchr(ival, '=')) == NULL)
		return (NULL);

	oval = strdup(tmp + 1);	/* everything after the "=" */
	if (oval == NULL)
		return (NULL);
	off = strlen(oval) - 1;
	if (off < 0) {
		free(oval);
		return (NULL);
	}
	if (oval[off] == '\n')
		oval[off] = '\0';

	return (oval);
}

/*
 * getcryptpolicy - read /etc/security/policy.conf into a crypt_policy_s
 */
static struct crypt_policy_s *
getcryptpolicy(void)
{
	FILE	*pconf;
	char	line[BUFSIZ];
	struct crypt_policy_s *policy;

	if ((pconf = fopen(POLICY_CONF_FILE, "rF")) == NULL) {
		return (NULL);
	}

	policy = malloc(sizeof (struct crypt_policy_s));
	if (policy == NULL) {
		return (NULL);
	}
	policy->cp_default = NULL;
	policy->cp_allow = NULL;
	policy->cp_deny = NULL;

	while (!feof(pconf) &&
	    (fgets(line, sizeof (line), pconf) != NULL)) {
		if (strncasecmp(CRYPT_DEFAULT, line,
		    strlen(CRYPT_DEFAULT)) == 0) {
			if (policy->cp_default != NULL) {
				log_invalid_policy(CPE_MULTI, CRYPT_DEFAULT);
			} else {
				policy->cp_default = getval(line);
			}
		}
		if (strncasecmp(CRYPT_ALGORITHMS_ALLOW, line,
		    strlen(CRYPT_ALGORITHMS_ALLOW)) == 0) {
			if (policy->cp_deny != NULL) {
				log_invalid_policy(CPE_BOTH, NULL);
			} else if (policy->cp_allow != NULL) {
				log_invalid_policy(CPE_MULTI,
				    CRYPT_ALGORITHMS_ALLOW);
			} else {
				policy->cp_allow = getval(line);
			}
		}
		if (strncasecmp(CRYPT_ALGORITHMS_DEPRECATE, line,
		    strlen(CRYPT_ALGORITHMS_DEPRECATE)) == 0) {
			if (policy->cp_allow != NULL) {
				log_invalid_policy(CPE_BOTH, NULL);
			} else if (policy->cp_deny != NULL) {
				log_invalid_policy(CPE_MULTI,
				    CRYPT_ALGORITHMS_DEPRECATE);
			} else {
				policy->cp_deny = getval(line);
			}
		}
	}
	(void) fclose(pconf);

	if (policy->cp_default == NULL) {
		policy->cp_default = strdup(CRYPT_UNIX);
		if (policy->cp_default == NULL)
			free_crypt_policy(policy);
	}

	return (policy);
}


/*
 * alg_valid - is this algorithm valid given the policy ?
 */
static boolean_t
alg_valid(const char *algname, const struct crypt_policy_s *policy)
{
	char *lasts;
	char *list;
	char *entry;
	boolean_t allowed = B_FALSE;

	if ((algname == NULL) || (policy == NULL)) {
		return (B_FALSE);
	}

	if (strcmp(algname, policy->cp_default) == 0) {
		return (B_TRUE);
	}

	if (policy->cp_deny != NULL) {
		list = policy->cp_deny;
		allowed = B_FALSE;
	} else if (policy->cp_allow != NULL) {
		list = policy->cp_allow;
		allowed = B_TRUE;
	} else {
		/*
		 * Neither of allow or deny policies are set so anything goes.
		 */
		return (B_TRUE);
	}
	lasts = list;
	while ((entry = strtok_r(NULL, ",", &lasts)) != NULL) {
		if (strcmp(entry, algname) == 0) {
			return (allowed);
		}
	}

	return (!allowed);
}

/*
 * getalgbyname - read crypt.conf(4) looking for algname
 *
 * RETURN VALUES
 *	On error NULL and errno is set
 *	On success the alg details including an open handle to the lib
 *	If crypt.conf(4) is okay but algname doesn't exist in it then
 *	return NULL the caller should then use the default algorithm
 *	as per the policy.
 */
static struct crypt_alg_s *
getalgbyname(const char *algname, boolean_t *found)
{
	struct stat	stb;
	int		configfd;
	FILE		*fconf = NULL;
	struct crypt_alg_s *alg = NULL;
	char		line[CRYPT_CONFLINELENGTH];
	int		linelen = 0;
	int		lineno = 0;
	char		*pathname = NULL;
	char		*lasts = NULL;
	char		*token = NULL;

	*found = B_FALSE;
	if ((algname == NULL) || (strcmp(algname, CRYPT_UNIX) == 0)) {
		return (NULL);
	}

	if ((configfd = open(CRYPT_CONFFILE, O_RDONLY)) == -1) {
		syslog(LOG_ALERT, "crypt: open(%s) failed: %s",
		    CRYPT_CONFFILE, strerror(errno));
		return (NULL);
	}

	/*
	 * Stat the file so we can check modes and ownerships
	 */
	if (fstat(configfd, &stb) < 0) {
		syslog(LOG_ALERT, "crypt: stat(%s) failed: %s",
		    CRYPT_CONFFILE, strerror(errno));
		goto cleanup;
	}

	/*
	 * Check the ownership of the file
	 */
	if (stb.st_uid != (uid_t)0) {
		syslog(LOG_ALERT,
		    "crypt: Owner of %s is not root", CRYPT_CONFFILE);
		goto cleanup;
	}

	/*
	 * Check the modes on the file
	 */
	if (stb.st_mode & S_IWGRP) {
		syslog(LOG_ALERT,
		    "crypt: %s writable by group", CRYPT_CONFFILE);
		goto cleanup;
	}
	if (stb.st_mode & S_IWOTH) {
		syslog(LOG_ALERT,
		    "crypt: %s writable by world", CRYPT_CONFFILE);
		goto cleanup;
	}

	if ((fconf = fdopen(configfd, "rF")) == NULL) {
		syslog(LOG_ALERT, "crypt: fdopen(%d) failed: %s",
		    configfd, strerror(errno));
		goto cleanup;
	}

	/*
	 * /etc/security/crypt.conf has 3 fields:
	 * <algname>	<pathname>	[<name[=val]>[<name[=val]>]]
	 */
	errno = 0;
	while (!(*found) &&
	    ((fgets(line, sizeof (line), fconf) != NULL) && !feof(fconf))) {
		lineno++;
		/*
		 * Skip over comments
		 */
		if ((line[0] == '#') || (line[0] == '\n')) {
			continue;
		}

		linelen = strlen(line);
		line[--linelen] = '\0';	/* chop the trailing \n */

		token = strtok_r(line, " \t", &lasts);
		if (token == NULL) {
			continue;
		}
		if (strcmp(token, algname) == 0) {
			*found = B_TRUE;
		}
	}
	if (!found) {
		errno = EINVAL;
		goto cleanup;
	}

	token = strtok_r(NULL, " \t", &lasts);
	if (token == NULL) {
		/*
		 * Broken config file
		 */
		syslog(LOG_ALERT, "crypt(3c): %s may be corrupt at line %d",
		    CRYPT_CONFFILE, lineno);
		*found = B_FALSE;
		errno = EINVAL;
		goto cleanup;
	}

	if ((pathname = isa_path(token)) == NULL) {
		if (errno != ENOMEM)
			errno = EINVAL;
		*found = B_FALSE;
		goto cleanup;
	}

	if ((alg = malloc(sizeof (struct crypt_alg_s))) == NULL) {
		*found = B_FALSE;
		goto cleanup;
	}
	alg->a_libhandle = NULL;
	alg->a_genhash = NULL;
	alg->a_gensalt = NULL;
	alg->a_params = NULL;
	alg->a_nparams = 0;

	/*
	 * The rest of the line is module specific params, space
	 * seprated. We wait until after we have checked the module is
	 * valid before parsing them into a_params, this saves us
	 * having to free them later if there is a problem.
	 */
	if ((alg->a_libhandle = dlopen(pathname, RTLD_NOW)) == NULL) {
		syslog(LOG_ERR, "crypt(3c) unable to dlopen %s: %s",
		    pathname, dlerror());
		errno = ELIBACC;
		*found = B_FALSE;
		goto cleanup;
	}

	alg->a_genhash =
	    (char *(*)())dlsym(alg->a_libhandle, "crypt_genhash_impl");
	if (alg->a_genhash == NULL) {
		syslog(LOG_ERR, "crypt(3c) unable to find cryp_genhash_impl"
		    "symbol in %s: %s", pathname, dlerror());
		errno = ELIBACC;
		*found = B_FALSE;
		goto cleanup;
	}
	alg->a_gensalt =
	    (char *(*)())dlsym(alg->a_libhandle, "crypt_gensalt_impl");
	if (alg->a_gensalt == NULL) {
		syslog(LOG_ERR, "crypt(3c) unable to find crypt_gensalt_impl"
		    "symbol in %s: %s", pathname, dlerror());
		errno = ELIBACC;
		*found = B_FALSE;
		goto cleanup;
	}

	/*
	 * We have a good module so build the a_params if we have any.
	 * Count how much space we need first and then allocate an array
	 * to hold that many module params.
	 */
	if (lasts != NULL) {
		int nparams = 0;
		char *tparams;
		char *tplasts;

		if ((tparams = strdup(lasts)) == NULL) {
			*found = B_FALSE;
			goto cleanup;
		}

		(void) strtok_r(tparams, " \t", &tplasts);
		do {
			nparams++;
		} while (strtok_r(NULL, " \t", &tplasts) != NULL);
		free(tparams);

		alg->a_params = calloc(nparams + 1, sizeof (char *));
		if (alg->a_params == NULL) {
			*found = B_FALSE;
			goto cleanup;
		}

		while ((token = strtok_r(NULL, " \t", &lasts)) != NULL) {
			alg->a_params[alg->a_nparams++] = token;
		}
	}

cleanup:
	if (*found == B_FALSE) {
		free_crypt_alg(alg);
		alg = NULL;
	}

	if (pathname != NULL) {
		free(pathname);
	}

	if (fconf != NULL) {
		(void) fclose(fconf);
	} else {
		(void) close(configfd);
	}

	return (alg);
}

static void
free_crypt_alg(struct crypt_alg_s *alg)
{
	if (alg == NULL)
		return;

	if (alg->a_libhandle != NULL) {
		(void) dlclose(alg->a_libhandle);
	}
	free(alg->a_params);
	free(alg);
}

static void
free_crypt_policy(struct crypt_policy_s *policy)
{
	if (policy == NULL)
		return;

	if (policy->cp_default != NULL) {
		bzero(policy->cp_default, strlen(policy->cp_default));
		free(policy->cp_default);
		policy->cp_default = NULL;
	}

	if (policy->cp_allow != NULL) {
		bzero(policy->cp_allow, strlen(policy->cp_allow));
		free(policy->cp_allow);
		policy->cp_allow = NULL;
	}

	if (policy->cp_deny != NULL) {
		bzero(policy->cp_deny, strlen(policy->cp_deny));
		free(policy->cp_deny);
		policy->cp_deny = NULL;
	}

	free(policy);
}


/*
 * isa_path - prepend the default dir or patch up the $ISA in path
 * 	Caller is responsible for calling free(3c) on the result.
 */
static char *
isa_path(const char *path)
{
	char *ret = NULL;

	if ((path == NULL) || (strlen(path) > PATH_MAX)) {
		return (NULL);
	}

	ret = calloc(PATH_MAX, sizeof (char));

	/*
	 * Module path doesn't start with "/" then prepend
	 * the default search path CRYPT_MODULE_DIR (/usr/lib/security/$ISA)
	 */
	if (path[0] != '/') {
		if (snprintf(ret, PATH_MAX, "%s%s", CRYPT_MODULE_DIR,
		    path) > PATH_MAX) {
			free(ret);
			return (NULL);
		}
	} else { /* patch up $ISA */
		char *isa;

		if ((isa = strstr(path, CRYPT_MODULE_ISA)) != NULL) {
			*isa = '\0';
			isa += strlen(CRYPT_MODULE_ISA);
			if (snprintf(ret, PATH_MAX, "%s%s%s", path,
			    CRYPT_ISA_DIR, isa) > PATH_MAX) {
				free(ret);
				return (NULL);
			}
		} else {
			free(ret);
			ret = strdup(path);
		}
	}

	return (ret);
}


/*ARGSUSED*/
static char *
_unix_crypt_gensalt(char *gsbuffer,
	    size_t gsbufflen,
	    const char *oldpuresalt,
	    const struct passwd *userinfo,
	    const char *argv[])
{
	static const char saltchars[] =
	    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	struct timeval tv;

	(void) gettimeofday(&tv, (void *) 0);
	srand48(tv.tv_sec ^ tv.tv_usec);
	gsbuffer[0] = saltchars[lrand48() % 64]; /* lrand48() is MT-SAFE */
	gsbuffer[1] = saltchars[lrand48() % 64]; /* lrand48() is MT-SAFE */
	gsbuffer[2] = '\0';

	return (gsbuffer);
}

/*
 * The rest of the code below comes from the old crypt.c and is the
 * implementation of the hardwired/fallback traditional algorithm
 * It has been otimized to take better advantage of MT features.
 *
 * It is included here to reduce the overhead of dlopen()
 * for the common case.
 */


/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/



/*
 * This program implements a data encryption algorithm to encrypt passwords.
 */

static mutex_t crypt_lock = DEFAULTMUTEX;
#define	TSDBUFSZ	(66 + 16)

static const char IP[] = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
};

static const char FP[] = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15,  55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
};

static const char PC1_C[] = {
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
};

static const char PC1_D[] = {
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4,
};

static const char shifts[] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
};

static const char PC2_C[] = {
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
};

static const char PC2_D[] = {
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32,
};

static char C[28];
static char D[28];
static char *KS;

static char E[48];
static const char e2[] = {
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1,
};

/*
 * The KS array (768 bytes) is allocated once, and only if
 * one of _unix_crypt(), encrypt() or setkey() is called.
 * The complexity below is due to the fact that calloc()
 * must not be called while holding any locks.
 */
static int
allocate_KS(void)
{
	char *ks;
	int failed;
	int assigned;

	if (KS != NULL) {		/* already allocated */
		membar_consumer();
		return (0);
	}

	ks = calloc(16, 48 * sizeof (char));
	failed = 0;
	lmutex_lock(&crypt_lock);
	if (KS != NULL) {	/* someone else got here first */
		assigned = 0;
	} else {
		assigned = 1;
		membar_producer();
		if ((KS = ks) == NULL)	/* calloc() failed */
			failed = 1;
	}
	lmutex_unlock(&crypt_lock);
	if (!assigned)
		free(ks);
	return (failed);
}

static void
unlocked_setkey(const char *key)
{
	int i, j, k;
	char t;

	for (i = 0; i < 28; i++) {
		C[i] = key[PC1_C[i]-1];
		D[i] = key[PC1_D[i]-1];
	}
	for (i = 0; i < 16; i++) {
		for (k = 0; k < shifts[i]; k++) {
			t = C[0];
			for (j = 0; j < 28-1; j++)
				C[j] = C[j+1];
			C[27] = t;
			t = D[0];
			for (j = 0; j < 28-1; j++)
				D[j] = D[j+1];
			D[27] = t;
		}
		for (j = 0; j < 24; j++) {
			int index = i * 48;

			*(KS+index+j) = C[PC2_C[j]-1];
			*(KS+index+j+24) = D[PC2_D[j]-28-1];
		}
	}
	for (i = 0; i < 48; i++)
		E[i] = e2[i];
}

static const char S[8][64] = {
	14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
	0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
	4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
	15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,

	15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
	3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
	0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
	13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,

	10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
	13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
	13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
	1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,

	7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
	13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
	10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
	3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,

	2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
	14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
	4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
	11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,

	12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
	10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
	9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
	4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,

	4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
	13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
	1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
	6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,

	13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
	1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
	7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
	2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
};

static const char P[] = {
	16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25,
};

static char L[64];
static char tempL[32];
static char f[32];

static char preS[48];

/*ARGSUSED*/
static void
unlocked_encrypt(char *block, int fake)
{
	int	i;
	int t, j, k;
	char *R = &L[32];

	for (j = 0; j < 64; j++)
		L[j] = block[IP[j]-1];
	for (i = 0; i < 16; i++) {
		int index = i * 48;

		for (j = 0; j < 32; j++)
			tempL[j] = R[j];
		for (j = 0; j < 48; j++)
			preS[j] = R[E[j]-1] ^ *(KS+index+j);
		for (j = 0; j < 8; j++) {
			t = 6 * j;
			k = S[j][(preS[t+0]<<5) +
			    (preS[t+1]<<3) +
			    (preS[t+2]<<2) +
			    (preS[t+3]<<1) +
			    (preS[t+4]<<0) +
			    (preS[t+5]<<4)];
			t = 4*j;
			f[t+0] = (k>>3)&01;
			f[t+1] = (k>>2)&01;
			f[t+2] = (k>>1)&01;
			f[t+3] = (k>>0)&01;
		}
		for (j = 0; j < 32; j++)
			R[j] = L[j] ^ f[P[j]-1];
		for (j = 0; j < 32; j++)
			L[j] = tempL[j];
	}
	for (j = 0; j < 32; j++) {
		t = L[j];
		L[j] = R[j];
		R[j] = (char)t;
	}
	for (j = 0; j < 64; j++)
		block[j] = L[FP[j]-1];
}

char *
_unix_crypt(const char *pw, const char *salt, char *iobuf)
{
	int c, i, j;
	char temp;
	char *block;

	block = iobuf + 16;

	if (iobuf == 0) {
		errno = ENOMEM;
		return (NULL);
	}
	if (allocate_KS() != 0)
		return (NULL);
	lmutex_lock(&crypt_lock);
	for (i = 0; i < 66; i++)
		block[i] = 0;
	for (i = 0; (c = *pw) != '\0' && i < 64; pw++) {
		for (j = 0; j < 7; j++, i++)
			block[i] = (c>>(6-j)) & 01;
		i++;
	}

	unlocked_setkey(block);

	for (i = 0; i < 66; i++)
		block[i] = 0;

	for (i = 0; i < 2; i++) {
		c = *salt++;
		iobuf[i] = (char)c;
		if (c > 'Z')
			c -= 6;
		if (c > '9')
			c -= 7;
		c -= '.';
		for (j = 0; j < 6; j++) {
			if ((c>>j) & 01) {
				temp = E[6*i+j];
				E[6*i+j] = E[6*i+j+24];
				E[6*i+j+24] = temp;
			}
		}
	}

	for (i = 0; i < 25; i++)
		unlocked_encrypt(block, 0);

	lmutex_unlock(&crypt_lock);
	for (i = 0; i < 11; i++) {
		c = 0;
		for (j = 0; j < 6; j++) {
			c <<= 1;
			c |= block[6*i+j];
		}
		c += '.';
		if (c > '9')
			c += 7;
		if (c > 'Z')
			c += 6;
		iobuf[i+2] = (char)c;
	}
	iobuf[i+2] = 0;
	if (iobuf[1] == 0)
		iobuf[1] = iobuf[0];
	return (iobuf);
}


/*ARGSUSED*/
void
encrypt(char *block, int fake)
{
	if (fake != 0) {
		errno = ENOSYS;
		return;
	}
	if (allocate_KS() != 0)
		return;
	lmutex_lock(&crypt_lock);
	unlocked_encrypt(block, fake);
	lmutex_unlock(&crypt_lock);
}


void
setkey(const char *key)
{
	if (allocate_KS() != 0)
		return;
	lmutex_lock(&crypt_lock);
	unlocked_setkey(key);
	lmutex_unlock(&crypt_lock);
}
