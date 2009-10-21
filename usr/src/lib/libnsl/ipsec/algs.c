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

#include "mt.h"
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <ipsec_util.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <synch.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

/* Globals... */
static rwlock_t proto_rw = DEFAULTRWLOCK; /* Protects cached algorithm list. */
static time_t proto_last_update;
static ipsec_proto_t *protos;
static int num_protos;

void
_clean_trash(ipsec_proto_t *proto, int num)
{
	int alg_offset;

	if (proto == NULL)
		return;

	while (num-- != 0) {
		free(proto[num].proto_name);
		free(proto[num].proto_pkg);
		for (alg_offset = 0; alg_offset < proto[num].proto_numalgs;
		    alg_offset++)
			freeipsecalgent(proto[num].proto_algs[alg_offset]);
		free(proto[num].proto_algs);
		for (alg_offset = 0; alg_offset < proto[num].proto_algs_npkgs;
		    alg_offset++)
			free(proto[num].proto_algs_pkgs[alg_offset].pkg_name);
		free(proto[num].proto_algs_pkgs);
	}

	free(proto);
}

static const char *pipechar = "|";
static const char *comma = ",";
static const char *dash = "-";
static const char *slash = "/";

/*
 * Returns >= 0 if success (and > 0 means "increment").
 * Returns -1 if failure.
 */
static int
build_keysizes(int **sizep, char *input_string)
{
	char *lasts, *token;
	int *key_sizes = NULL, num_sizes, key_low, key_high, key_default;
	int key_increment = 0;

	/*
	 * Okay, let's check the format of the key string.  It'll be either:
	 *
	 * enumeration: size1,size2...,sizeN
	 * range: defaultSize/sizeLow-sizeHi,increment
	 *
	 * In the case of an enumeration, the default key size is the
	 * first one in the list.
	 */

	if (strchr(input_string, '/') != NULL) {
		/* key sizes specified by range */

		/* default */
		token = strtok_r(input_string, slash, &lasts);
		if (token == NULL || (key_default = atoi(token)) == 0)
			return (-1);

		/* low */
		token = strtok_r(NULL, dash, &lasts);
		if (token == NULL || (key_low = atoi(token)) == 0)
			return (-1);

		/* high */
		token = strtok_r(NULL, comma, &lasts);
		if (token == NULL || (key_high = atoi(token)) == 0 ||
		    key_high <= key_low)
			return (-1);

		/* increment */
		token = strtok_r(NULL, "", &lasts);
		if (token == NULL || (key_increment = atoi(token)) == 0)
			return (-1);

		key_sizes = (int *)malloc(LIBIPSEC_ALGS_KEY_NUM_VAL *
		    sizeof (int));
		if (key_sizes == NULL)
			return (-1);

		key_sizes[LIBIPSEC_ALGS_KEY_DEF_IDX] = key_default;
		key_sizes[LIBIPSEC_ALGS_KEY_MIN_IDX] = key_low;
		key_sizes[LIBIPSEC_ALGS_KEY_MAX_IDX] = key_high;
		key_sizes[LIBIPSEC_ALGS_KEY_MAX_IDX + 1] = 0;
	} else {
		/* key sizes specified by enumeration */

		key_sizes = (int *)malloc(sizeof (int));
		if (key_sizes == NULL)
			return (-1);
		num_sizes = 0;

		token = strtok_r(input_string, comma, &lasts);
		if (token == NULL) {
			free(key_sizes);
			return (-1);
		}
		*key_sizes = 0;
		do {
			int *nks;

			nks = (int *)realloc(key_sizes,
			    sizeof (int) * ((++num_sizes) + 1));
			if (nks == NULL) {
				free(key_sizes);
				return (-1);
			}
			key_sizes = nks;
			/* Can't check for atoi() == 0 here... */
			key_sizes[num_sizes - 1] = atoi(token);
			key_sizes[num_sizes] = 0;
		} while ((token = strtok_r(NULL, comma, &lasts)) != NULL);
	}
	*sizep = key_sizes;

	return (key_increment);
}

/*
 * Find the execution mode corresponding to the given string.
 * Returns 0 on success, -1 on failure.
 */
int
_str_to_ipsec_exec_mode(char *str, ipsecalgs_exec_mode_t *exec_mode)
{
	if (strcmp(str, "sync") == 0) {
		*exec_mode = LIBIPSEC_ALGS_EXEC_SYNC;
		return (0);
	} else if (strcmp(str, "async") == 0) {
		*exec_mode = LIBIPSEC_ALGS_EXEC_ASYNC;
		return (0);
	}

	return (-1);
}

/*
 * Given a file pointer, read all the text from the file and convert it into
 * a bunch of ipsec_proto_t's, each with an array of struct ipsecalgent
 * pointers - one for each algorithm.
 */
static ipsec_proto_t *
build_list(FILE *f, int *num)
{
	char line[1024];
	char *token, *lasts, *alg_names, *ef_name, *key_string, *block_string;
	char *proto_name, *params_string;
	ipsec_proto_t *rc = NULL, *new_proto = NULL;
	int *block_sizes = NULL, *key_sizes = NULL, *mech_params = NULL;
	int rc_num = 0, key_increment;
	int new_num, alg_num, num_sizes, flags = 0;
	struct ipsecalgent *curalg, **newalglist;
	char cur_pkg[1024];
	boolean_t doing_pkg = B_FALSE;
	ipsecalgs_exec_mode_t exec_mode;
	char diag_buf[128];

	diag_buf[0] = '\0';

	while (fgets(line, sizeof (line), f) != NULL) {
		if (strncasecmp(line, LIBIPSEC_ALGS_LINE_PROTO,
		    sizeof (LIBIPSEC_ALGS_LINE_PROTO) - 1) != 0 &&
		    strncasecmp(line, LIBIPSEC_ALGS_LINE_ALG,
		    sizeof (LIBIPSEC_ALGS_LINE_ALG) - 1) != 0 &&
		    strncasecmp(line, LIBIPSEC_ALGS_LINE_PKGSTART,
		    sizeof (LIBIPSEC_ALGS_LINE_PKGSTART) - 1) != 0 &&
		    strncasecmp(line, LIBIPSEC_ALGS_LINE_PKGEND,
		    sizeof (LIBIPSEC_ALGS_LINE_PKGEND) - 1) != 0) {
			if ((token = strtok_r(line, " \t\n", &lasts)) == NULL ||
			    token[0] == '#') {
				continue;
			} else {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "non-recognized start of line");
				goto bail;
			}
		}

		if (strncasecmp(line, LIBIPSEC_ALGS_LINE_PROTO,
		    sizeof (LIBIPSEC_ALGS_LINE_PROTO) - 1) == 0) {
			/* current line defines a new protocol */

			/* skip the protocol token */
			token = strtok_r(line, pipechar, &lasts);

			/* protocol number */
			token = strtok_r(NULL, pipechar, &lasts);
			if (token == NULL || (new_num = atoi(token)) == 0) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "invalid protocol number");
				goto bail;
			}

			/* protocol name */
			token = strtok_r(NULL, pipechar, &lasts);
			if (token == NULL) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "cannot read protocol name");
				goto bail;
			}
			proto_name = token;

			/* execution mode */
			token = strtok_r(NULL, pipechar, &lasts);
			if (token == NULL) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "cannot read execution mode");
				goto bail;
			}
			/* remove trailing '\n' */
			token[strlen(token) - 1] = '\0';
			if (_str_to_ipsec_exec_mode(token, &exec_mode) != 0) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "invalid execution mode: \"%s\"", token);
				goto bail;
			}

			/* initialize protocol structure */
			rc_num++;
			new_proto = (ipsec_proto_t *)realloc(rc,
			    sizeof (ipsec_proto_t) * rc_num);
			rc = new_proto;
			if (new_proto == NULL)
				goto bail;
			new_proto += (rc_num - 1);
			new_proto->proto_num = new_num;
			new_proto->proto_algs = NULL;
			new_proto->proto_numalgs = 0;
			new_proto->proto_name = strdup(proto_name);
			if (new_proto->proto_name == NULL)
				goto bail;
			new_proto->proto_exec_mode = exec_mode;

			if (doing_pkg) {
				/* record proto as being part of current pkg */
				new_proto->proto_pkg = strdup(cur_pkg);
				if (new_proto->proto_pkg == NULL)
					goto bail;
			} else {
				new_proto->proto_pkg = NULL;
			}

			new_proto->proto_algs_pkgs = NULL;
			new_proto->proto_algs_npkgs = 0;

		} else if (strncasecmp(line, LIBIPSEC_ALGS_LINE_ALG,
		    sizeof (LIBIPSEC_ALGS_LINE_ALG) - 1) == 0) {
			/* current line defines a new algorithm */

			/* skip the algorithm token */
			token = strtok_r(line, pipechar, &lasts);

			/* protocol number */
			token = strtok_r(NULL, pipechar, &lasts);
			if (token == NULL || (new_num = atoi(token)) == 0) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "invalid algorithm number");
				goto bail;
			}

			/* We can be O(N) for now.  There aren't that many. */
			for (new_proto = rc; new_proto < (rc + new_num);
			    new_proto++)
				if (new_proto->proto_num == new_num)
					break;
			if (new_proto == (rc + new_num)) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "invalid protocol number %d for algorithm",
				    new_num);
				goto bail;
			}

			/* algorithm number */
			token = strtok_r(NULL, pipechar, &lasts);
			if (token == NULL) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "cannot read algorithm number");
				goto bail;
			}
			/* Can't check for 0 here. */
			alg_num = atoi(token);

			/* algorithm names */
			token = strtok_r(NULL, pipechar, &lasts);
			if (token == NULL) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "cannot read algorithm number");
				goto bail;
			}
			alg_names = token;

			/* mechanism name */
			token = strtok_r(NULL, pipechar, &lasts);
			if (token == NULL) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "cannot read mechanism name for alg %d "
				    "(proto %d)", alg_num,
				    new_proto->proto_num);
				goto bail;
			}
			ef_name = token;

			/* key sizes */
			token = strtok_r(NULL, pipechar, &lasts);
			if (token == NULL) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "cannot read key sizes for alg %d "
				    "(proto %d)", alg_num,
				    new_proto->proto_num);
				goto bail;
			}
			key_string = token;

			/* block sizes */
			token = strtok_r(NULL, pipechar, &lasts);
			if (token == NULL) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "cannot read block sizes for alg %d "
				    "(proto %d)", alg_num,
				    new_proto->proto_num);
				goto bail;
			}
			block_string = token;

			/*
			 * Check for mechanism params and flags. As these
			 * are optional, we won't bail if they don't exist.
			 */
			token = strtok_r(NULL, pipechar, &lasts);
			params_string = token;

			token = strtok_r(NULL, pipechar, &lasts);
			if (token != NULL)
				flags = atoi(token);

			/* extract key sizes */
			key_increment = build_keysizes(&key_sizes, key_string);
			if (key_increment == -1) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "invalid key sizes for alg %d (proto %d)",
				    alg_num, new_proto->proto_num);
				goto bail;
			}

			/* extract block sizes */
			block_sizes = (int *)malloc(sizeof (int));
			if (block_sizes == NULL) {
				goto bail;
			}
			num_sizes = 0;
			token = strtok_r(block_string, comma, &lasts);
			if (token == NULL) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "invalid block sizes for alg %d (proto %d)",
				    alg_num, new_proto->proto_num);
				goto bail;
			}
			*block_sizes = 0;
			do {
				int *nbk;

				nbk = (int *)realloc(block_sizes,
				    sizeof (int) * ((++num_sizes) + 1));
				if (nbk == NULL) {
					goto bail;
				}
				block_sizes = nbk;
				/* Can't check for 0 here... */
				block_sizes[num_sizes - 1] = atoi(token);
				block_sizes[num_sizes] = 0;
			} while ((token = strtok_r(NULL, comma, &lasts)) !=
			    NULL);

			/* extract mech params */
			mech_params = (int *)malloc(sizeof (int));
			if (mech_params == NULL) {
				goto bail;
			}
			*mech_params = 0;
			num_sizes = 0;
			if (params_string != NULL) {
				token = strtok_r(params_string, comma, &lasts);
				if (token == NULL) {
					(void) snprintf(diag_buf,
					    sizeof (diag_buf), "invalid mech "
					    "params for alg %d (proto %d)",
					    alg_num, new_proto->proto_num);
					goto bail;
				}
				do {
					int *nbk;

					nbk = (int *)realloc(mech_params,
					    sizeof (int) * ((++num_sizes) + 1));
					if (nbk == NULL) {
						goto bail;
					}
					mech_params = nbk;
					/* Can't check for 0 here... */
					mech_params[num_sizes - 1] =
					    atoi(token);
					mech_params[num_sizes] = 0;
				} while ((token = strtok_r(NULL, comma, &lasts))
				    != NULL);
			}
			/* Allocate a new struct ipsecalgent. */
			curalg = (struct ipsecalgent *)calloc(
			    sizeof (struct ipsecalgent), 1);
			if (curalg == NULL) {
				goto bail;
			}
			curalg->a_proto_num = new_num;
			curalg->a_alg_num = alg_num;
			curalg->a_block_sizes = block_sizes;
			curalg->a_alg_flags = flags;
			curalg->a_mech_params = mech_params;
			curalg->a_key_sizes = key_sizes;
			curalg->a_key_increment = key_increment;
			if ((curalg->a_mech_name = strdup(ef_name)) == NULL) {
				freeipsecalgent(curalg);
				goto bail;
			}
			/* Set names. */
			curalg->a_names = (char **)malloc(sizeof (char *));
			num_sizes = 0;	/* Recycle "sizes" */
			token = strtok_r(alg_names, comma, &lasts);
			if (curalg->a_names == NULL || token == NULL) {
				freeipsecalgent(curalg);
				goto bail;
			}
			do {
				char **nnames;

				nnames = (char **)realloc(curalg->a_names,
				    sizeof (char *) * ((++num_sizes) + 1));
				if (nnames == NULL) {
					freeipsecalgent(curalg);
					goto bail;
				}
				curalg->a_names = nnames;
				curalg->a_names[num_sizes] = NULL;
				curalg->a_names[num_sizes - 1] =
				    strdup(token);
				if (curalg->a_names[num_sizes - 1] == NULL) {
					freeipsecalgent(curalg);
					goto bail;
				}
			} while ((token = strtok_r(NULL, comma, &lasts)) !=
			    NULL);

			if (doing_pkg) {
				/* record alg as being part of current pkg */
				int npkgs = new_proto->proto_algs_npkgs;

				new_proto->proto_algs_pkgs = realloc(
				    new_proto->proto_algs_pkgs,
				    (npkgs + 1) * sizeof (ipsecalgs_pkg_t));
				if (new_proto->proto_algs_pkgs == NULL)
					goto bail;

				new_proto->proto_algs_pkgs[npkgs].alg_num =
				    curalg->a_alg_num;
				new_proto->proto_algs_pkgs[npkgs].pkg_name =
				    strdup(cur_pkg);
				if (new_proto->proto_algs_pkgs[npkgs].pkg_name
				    == NULL)
					goto bail;

				new_proto->proto_algs_npkgs = npkgs + 1;
			}

			/* add new alg to protocol */
			newalglist = realloc(new_proto->proto_algs,
			    (new_proto->proto_numalgs + 1) *
			    sizeof (struct ipsecalgent *));
			if (newalglist == NULL) {
				freeipsecalgent(curalg);
				goto bail;
			}
			newalglist[new_proto->proto_numalgs] = curalg;
			new_proto->proto_numalgs++;
			new_proto->proto_algs = newalglist;

		} else if (strncasecmp(line, LIBIPSEC_ALGS_LINE_PKGSTART,
		    sizeof (LIBIPSEC_ALGS_LINE_PKGSTART) - 1) == 0) {
			/* start of package delimiter */
			if (doing_pkg) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "duplicate package start delimiters");
				goto bail;
			}
			(void) strncpy(cur_pkg, line +
			    (sizeof (LIBIPSEC_ALGS_LINE_PKGSTART) - 1),
			    sizeof (cur_pkg));
			/* remove trailing '\n' */
			cur_pkg[strlen(cur_pkg) - 1] = '\0';
			doing_pkg = B_TRUE;

		} else {
			/* end of package delimiter */
			char tmp_pkg[1024];

			if (!doing_pkg) {
				(void) snprintf(diag_buf, sizeof (diag_buf),
				    "end package delimiter without start");
				goto bail;
			}
			/*
			 * Get specified pkg name, fail if it doesn't match
			 * the package specified by the last # Begin.
			 */
			(void) strncpy(tmp_pkg, line +
			    (sizeof (LIBIPSEC_ALGS_LINE_PKGEND) - 1),
			    sizeof (tmp_pkg));
			/* remove trailing '\n' */
			tmp_pkg[strlen(tmp_pkg) - 1] = '\0';
			if (strncmp(cur_pkg, tmp_pkg, sizeof (cur_pkg)) != 0)
				goto bail;
			doing_pkg = B_FALSE;
		}
	}

	*num = rc_num;
	return (rc);

bail:
	if (strlen(diag_buf) > 0) {
		syslog(LOG_ERR, "possibly corrupt %s file: %s\n",
		    INET_IPSECALGSFILE, diag_buf);
	}
	free(key_sizes);
	free(block_sizes);
	free(mech_params);
	_clean_trash(rc, rc_num);
	return (NULL);
}

/*
 * If alg_context is NULL, update the library's cached copy of
 * INET_IPSECALGSFILE.  If alg_context is non-NULL, hang a
 * library-internal representation of a cached copy.  The latter is useful
 * for routines in libipsecutil that _write_ the contents out.
 */
void
_build_internal_algs(ipsec_proto_t **alg_context, int *alg_nums)
{
	FILE *f;
	int rc, trash_num;
	ipsec_proto_t *new_protos = NULL, *trash;
	time_t filetime;
	struct stat statbuf;

	/*
	 * Construct new_protos from the file.
	 */
	if (alg_context == NULL) {
		/*
		 * Check the time w/o holding the lock.  This is just a
		 * cache reality check.  We'll do it again for real if this
		 * surface check fails.
		 */
		if (stat(INET_IPSECALGSFILE, &statbuf) == -1 ||
		    (statbuf.st_mtime < proto_last_update && protos != NULL))
			return;
		(void) rw_wrlock(&proto_rw);
	}

	f = fopen(INET_IPSECALGSFILE, "rF");
	if (f != NULL) {
		rc = fstat(fileno(f), &statbuf);
		if (rc != -1) {
			/*
			 * Update if the file is newer than our
			 * last cached copy.
			 */
			filetime = statbuf.st_mtime;
			if (alg_context != NULL ||
			    filetime > proto_last_update)
				new_protos = build_list(f, &rc);
		}
		/* Since f is read-only, can avoid all of the failures... */
		(void) fclose(f);
	}

	if (alg_context == NULL) {
		/*
		 * If we have failed anywhere above, new_protoss will be NULL.
		 * This way, the previous cached protos will still be intact.
		 */
		if (new_protos != NULL) {
			proto_last_update = filetime;
			trash = protos;
			trash_num = num_protos;
			protos = new_protos;
			num_protos = rc;
		} else {
			/*
			 * Else the original protocols and algorithms lists
			 * remains the same.
			 */
			trash = NULL;
		}
		(void) rw_unlock(&proto_rw);
		_clean_trash(trash, trash_num);
	} else {
		/*
		 * Assume caller has done the appropriate locking,
		 * cleanup, etc.  And if new_protos is NULL, it's the caller's
		 * problem.
		 */
		*alg_context = new_protos;
		*alg_nums = rc;
	}

}

/*
 * Assume input is 0-terminated.
 */
static int *
duplicate_intarr(int *orig)
{
	size_t allocsize = sizeof (int);
	int *iwalker = orig;

	if (orig == NULL)
		return (NULL);

	while (*iwalker != 0) {
		allocsize += sizeof (int);
		iwalker++;
	}

	iwalker = malloc(allocsize);
	if (iwalker != NULL)
		(void) memcpy(iwalker, orig, allocsize);

	return (iwalker);
}

/*
 * Assume input is NULL terminated.
 */
static char **
duplicate_strarr(char **orig)
{
	int i;
	char **swalker;
	char **newbie;

	if (orig == NULL)
		return (NULL);

	/* count number of elements in source array */
	for (swalker = orig; *swalker != NULL; swalker++)
		;

	/* use calloc() to get NULL-initialization */
	newbie = calloc(swalker - orig + 1, sizeof (char *));

	if (newbie != NULL) {
		/* do the copy */
		for (i = 0; orig[i] != NULL; i++) {
			newbie[i] = strdup(orig[i]);
			if (newbie[i] == NULL) {
				for (swalker = newbie; *swalker != NULL;
				    swalker++)
					free(*swalker);
				free(newbie);
				return (NULL);
			}
		}
	}

	return (newbie);
}

struct ipsecalgent *
_duplicate_alg(struct ipsecalgent *orig)
{
	struct ipsecalgent *rc;

	/* use calloc() to get NULL-initialization. */
	rc = calloc(1, sizeof (struct ipsecalgent));
	if (rc == NULL)
		return (NULL);

	rc->a_proto_num = orig->a_proto_num;
	rc->a_alg_num = orig->a_alg_num;
	rc->a_key_increment = orig->a_key_increment;
	rc->a_mech_name = strdup(orig->a_mech_name);
	rc->a_alg_flags = orig->a_alg_flags;
	rc->a_block_sizes = duplicate_intarr(orig->a_block_sizes);
	rc->a_mech_params = duplicate_intarr(orig->a_mech_params);
	rc->a_key_sizes = duplicate_intarr(orig->a_key_sizes);
	rc->a_names = duplicate_strarr(orig->a_names);

	if (rc->a_mech_name == NULL || rc->a_block_sizes == NULL ||
	    rc->a_key_sizes == NULL || rc->a_names == NULL ||
	    rc->a_mech_params == NULL) {
		freeipsecalgent(rc);
		return (NULL);
	}

	return (rc);
}

/*
 * Assume the rwlock is held for reading.
 */
static ipsec_proto_t *
findprotobynum(int proto_num)
{
	int i;

	for (i = 0; i < num_protos; i++) {
		if (protos[i].proto_num == proto_num)
			return (protos + i);
	}

	return (NULL);
}

static ipsec_proto_t *
findprotobyname(const char *name)
{
	int i;

	if (name == NULL)
		return (NULL);

	for (i = 0; i < num_protos; i++) {
		/* Can use strcasecmp because our proto_name is bounded. */
		if (strcasecmp(protos[i].proto_name, name) == 0)
			return (protos + i);
	}

	return (NULL);
}

int *
_real_getipsecprotos(int *nentries)
{
	int *rc, i;

	if (nentries == NULL)
		return (NULL);

	_build_internal_algs(NULL, NULL);

	(void) rw_rdlock(&proto_rw);
	*nentries = num_protos;
	/*
	 * Allocate 1 byte if there are no protocols so a non-NULL return
	 * happens.
	 */
	rc = malloc((num_protos == 0) ? 1 : num_protos * sizeof (int));
	if (rc != NULL) {
		for (i = 0; i < num_protos; i++)
			rc[i] = protos[i].proto_num;
	}
	(void) rw_unlock(&proto_rw);
	return (rc);
}

int *
_real_getipsecalgs(int *nentries, int proto_num)
{
	int *rc = NULL, i;
	ipsec_proto_t *proto;

	if (nentries == NULL)
		return (NULL);

	_build_internal_algs(NULL, NULL);

	(void) rw_rdlock(&proto_rw);
	proto = findprotobynum(proto_num);
	if (proto != NULL) {
		*nentries = proto->proto_numalgs;
		/*
		 * Allocate 1 byte if there are no algorithms so a non-NULL
		 * return happens.
		 */
		rc = malloc((proto->proto_numalgs == 0) ? 1 :
		    proto->proto_numalgs * sizeof (int));
		if (rc != NULL) {
			for (i = 0; i < proto->proto_numalgs; i++)
				rc[i] = proto->proto_algs[i]->a_alg_num;
		}
	}
	(void) rw_unlock(&proto_rw);
	return (rc);
}

struct ipsecalgent *
getipsecalgbyname(const char *name, int proto_num, int *errnop)
{
	ipsec_proto_t *proto;
	struct ipsecalgent *rc = NULL;
	int i, my_errno = ENOENT;
	char **name_check;

	_build_internal_algs(NULL, NULL);
	if (name == NULL) {
		my_errno = EFAULT;
		goto bail;
	}

	(void) rw_rdlock(&proto_rw);
	proto = findprotobynum(proto_num);
	if (proto != NULL) {
		for (i = 0; i < proto->proto_numalgs; i++) {
			for (name_check = proto->proto_algs[i]->a_names;
			    *name_check != NULL; name_check++) {
				/*
				 * Can use strcasecmp because our name_check
				 * is bounded.
				 */
				if (strcasecmp(*name_check, name) == 0) {
					/* found match */
					rc = _duplicate_alg(
					    proto->proto_algs[i]);
					my_errno = (rc == NULL) ? ENOMEM : 0;
					(void) rw_unlock(&proto_rw);
					goto bail;
				}
			}
		}
	} else {
		my_errno = EINVAL;
	}

	(void) rw_unlock(&proto_rw);
bail:
	if (errnop != NULL)
		*errnop = my_errno;
	return (rc);
}

struct ipsecalgent *
getipsecalgbynum(int alg_num, int proto_num, int *errnop)
{
	ipsec_proto_t *proto;
	struct ipsecalgent *rc = NULL;
	int i, my_errno = ENOENT;

	_build_internal_algs(NULL, NULL);

	(void) rw_rdlock(&proto_rw);

	proto = findprotobynum(proto_num);
	if (proto != NULL) {
		for (i = 0; i < proto->proto_numalgs; i++) {
			if (proto->proto_algs[i]->a_alg_num == alg_num) {
				rc = _duplicate_alg(proto->proto_algs[i]);
				my_errno = (rc == NULL) ? ENOMEM : 0;
				break;
			}
		}
	} else {
		my_errno = EINVAL;
	}

	(void) rw_unlock(&proto_rw);
	if (errnop != NULL)
		*errnop = my_errno;
	return (rc);
}

int
getipsecprotobyname(const char *proto_name)
{
	int rc = -1;
	ipsec_proto_t *proto;

	_build_internal_algs(NULL, NULL);

	(void) rw_rdlock(&proto_rw);
	proto = findprotobyname(proto_name);
	if (proto != NULL)
		rc = proto->proto_num;
	(void) rw_unlock(&proto_rw);
	return (rc);
}

char *
getipsecprotobynum(int proto_num)
{
	ipsec_proto_t *proto;
	char *rc = NULL;

	_build_internal_algs(NULL, NULL);

	(void) rw_rdlock(&proto_rw);
	proto = findprotobynum(proto_num);
	if (proto != NULL)
		rc = strdup(proto->proto_name);

	(void) rw_unlock(&proto_rw);
	return (rc);
}

void
freeipsecalgent(struct ipsecalgent *ptr)
{
	char **walker;

	if (ptr == NULL)
		return;

	if (ptr->a_names != NULL) {
		for (walker = ptr->a_names; *walker != NULL; walker++)
			free(*walker);
	}

	/*
	 * Remember folks, free(NULL) works.
	 */
	free(ptr->a_names);
	free(ptr->a_mech_name);
	free(ptr->a_block_sizes);
	free(ptr->a_mech_params);
	free(ptr->a_key_sizes);
	free(ptr);
}
