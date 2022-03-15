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

#include <sys/types.h>
#include <sys/stat.h>
#include <ipsec_util.h>
#include <stdlib.h>
#include <strings.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <libintl.h>
#include <errno.h>

static char *preamble =
"# /etc/inet/ipsecalgs output from ipsecalgs(8)\n"
"#\n"
"# DO NOT EDIT OR PARSE THIS FILE!\n"
"#\n"
"# Use the ipsecalgs(8) command to change the contents of this file.\n"
"# The algorithm descriptions contained in this file are synchronised to the\n"
"# kernel with ipsecalgs -s, the kernel validates the entries at this point."
"\n\n"
"# PROTO|protocol-id|protocol-name|exec-mode\n"
"##  NOTE:  Some protocol numbers are well-known and defined in <netdb.h>\n\n"
"# ALG|protocol-id|alg-id|name,name,...|ef-id| \n"
"#        {default/}{key,key..}or{key-key,inc}|block_size or MAC-size|\n"
"#        [parameter,parameter..]|[flags]\n\n"
"#\n"
"## Note:   Parameters and flags only apply to certain algorithms.\n\n";

#define	CFG_PERMS S_IRUSR | S_IRGRP | S_IROTH	/* Perms 0444. */
#define	CFG_OWNER 0	/* root */
#define	CFG_GROUP 1	/* "other" */

/*
 * write_new_algfile() helper macros to check for write errors.
 */

#define	FPRINTF_ERR(fcall) if ((fcall) < 0) {	\
	rc = LIBIPSEC_ALGS_DIAG_ALGSFILEWRITE;	\
	goto bail;				\
}

#define	FPUT_ERR(fcall) if ((fcall) == EOF) {	\
	rc = LIBIPSEC_ALGS_DIAG_ALGSFILEWRITE;	\
	goto bail;				\
}

/*
 * Helper macros to start and finish a list of entries that were added
 * as part of a package installation.
 */

#define	PKG_SEC_START(pkgname, doing_pkg, cur_pkg) {		\
	(void) strcpy((cur_pkg), (pkgname));			\
	FPRINTF_ERR(fprintf(f, "%s%s\n",			\
	    LIBIPSEC_ALGS_LINE_PKGSTART, (cur_pkg)));		\
	(doing_pkg) = B_TRUE;					\
}

#define	PKG_SEC_END(doing_pkg, cur_pkg) {			\
	if (doing_pkg) {					\
		FPRINTF_ERR(fprintf(f, "%s%s\n",		\
		    LIBIPSEC_ALGS_LINE_PKGEND, (cur_pkg)));	\
		(doing_pkg) = B_FALSE;				\
	}							\
}

/*
 * Take a zero-terminated int array and print int1,int2...,intN.
 * If zero-only, then print a single '0'.
 * Returns 0 on success, -1 if an error occurred while writing to
 * the specified file.
 */
int
list_ints(FILE *f, int *floater)
{
	boolean_t executed = B_FALSE;

	while (*floater != 0) {
		executed = B_TRUE;
		if (fprintf(f, "%d", *floater) < 0)
			return (-1);
		if (*(++floater) != 0)
			if (fputc(',', f) == EOF)
				return (-1);
	}

	if (!executed)
		if (fputc('0', f) == EOF)
			return (-1);

	return (0);
}

/*
 * If the specified algorithm was defined within a package section, i.e.
 * between the lines "# Start <pkgname>" and "# End <pkgname>", returns
 * the value of <pkgname>.
 */
static char *
alg_has_pkg(ipsec_proto_t *proto, struct ipsecalgent *alg)
{
	int i;

	if (proto->proto_algs_pkgs == NULL)
		return (NULL);

	for (i = 0; i < proto->proto_algs_npkgs; i++)
		if (proto->proto_algs_pkgs[i].alg_num == alg->a_alg_num)
			return (proto->proto_algs_pkgs[i].pkg_name);

	return (NULL);
}

/*
 * Writes the package start/end delimiters according to the package
 * name associated with the current protocol or algorithm, and
 * the state of the packaging information already written to the file.
 * Called by write_new_algfile(). Returns 0 on success, one of the
 * LIBIPSEC_DIAG codes on failure.
 */
static int
pkg_section(FILE *f, char *pkg_name, boolean_t *doing_pkg, char *cur_pkg)
{
	int rc = 0;

	if (pkg_name != NULL) {
		/* protocol or algorithm is associated with a package */
		if (!*doing_pkg) {
			/* start of a new package section */
			PKG_SEC_START(pkg_name, *doing_pkg, cur_pkg);
		} else {
			/* already in a package section */
			if (strcmp(pkg_name, cur_pkg) != 0) {
				/* different package name */
				PKG_SEC_END(*doing_pkg, cur_pkg);
				PKG_SEC_START(pkg_name, *doing_pkg, cur_pkg);
			}
		}
	} else if (*doing_pkg) {
		/* in a package section when the entry isn't */
		PKG_SEC_END(*doing_pkg, cur_pkg);
	}
bail:
	return (rc);
}

/*
 * Given a list of protocols and number, write them to a new algorithm file.
 * This function takes num_protos + num_protos * dois-per-alg operations.
 * Also free the protocol structure.
 *
 * Note that no locking spans the read/update/write phases that can be
 * used by callers of this routine. This could cause this function to suffer
 * from the "lost update" problem. Since updates to the IPsec protocols
 * and algorithm tables are very infrequent, this should not be a issue in
 * practice.
 */
static int
write_new_algfile(ipsec_proto_t *protos, int num_protos)
{
	FILE *f;
	int fd, i, j, k;
	int rc = 0;
	struct ipsecalgent *alg;
	char cur_pkg[1024];
	boolean_t doing_pkg = B_FALSE;
	char *alg_pkg;
	char tmp_name_template[] = INET_IPSECALGSPATH "ipsecalgsXXXXXX";
	char *tmp_name;

	/*
	 * In order to avoid potentially corrupting the configuration
	 * file on file system failure, write the new configuration info
	 * to a temporary file which is then renamed to the configuration
	 * file (INET_IPSECALGSFILE.)
	 */
	tmp_name = mktemp(tmp_name_template);

	fd = open(tmp_name, O_WRONLY|O_CREAT|O_EXCL, CFG_PERMS);
	if (fd == -1) {
		rc = LIBIPSEC_ALGS_DIAG_ALGSFILEOPEN;
		goto bail;
	}

	f = fdopen(fd, "w");
	if (f == NULL) {
		(void) close(fd);
		rc = LIBIPSEC_ALGS_DIAG_ALGSFILEFDOPEN;
		goto bail;
	}

	FPUT_ERR(fputs(preamble, f));

	/* Write protocol entries. */
	for (i = 0; i < num_protos; i++) {

		/* add package section delimiters if needed */
		rc = pkg_section(f, protos[i].proto_pkg, &doing_pkg, cur_pkg);
		if (rc != 0)
			goto bail;

		FPRINTF_ERR(fprintf(f, "%s%d|%s|",
		    LIBIPSEC_ALGS_LINE_PROTO,
		    protos[i].proto_num, protos[i].proto_name));
		switch (protos[i].proto_exec_mode) {
		case LIBIPSEC_ALGS_EXEC_SYNC:
			FPRINTF_ERR(fprintf(f, "sync\n"));
			break;
		case LIBIPSEC_ALGS_EXEC_ASYNC:
			FPRINTF_ERR(fprintf(f, "async\n"));
			break;
		}
	}

	/* terminate the package section for the protocols if needed */
	PKG_SEC_END(doing_pkg, cur_pkg);

	FPUT_ERR(fputs("\n", f));

	/* Write algorithm entries. */

	for (i = 0; i < num_protos; i++) {
		for (j = 0; j < protos[i].proto_numalgs; j++) {
			alg = protos[i].proto_algs[j];

			/* add package section delimiters if needed */
			alg_pkg = alg_has_pkg(&protos[i], alg);
			rc = pkg_section(f, alg_pkg, &doing_pkg, cur_pkg);
			if (rc != 0)
				goto bail;

			/* protocol and algorithm numbers */
			FPRINTF_ERR(fprintf(f, "%s%d|%d|",
			    LIBIPSEC_ALGS_LINE_ALG,
			    alg->a_proto_num, alg->a_alg_num));

			/* algorithm names */
			for (k = 0; alg->a_names[k] != NULL; k++) {
				FPRINTF_ERR(fprintf(f, "%s", alg->a_names[k]));
				if (alg->a_names[k+1] != NULL)
					FPRINTF_ERR(fprintf(f, ","));
			}

			/* mechanism name */
			FPRINTF_ERR(fprintf(f, "|%s|", alg->a_mech_name));

			/* key sizes */
			if (alg->a_key_increment == 0) {
				/* key sizes defined by enumeration */
				if (list_ints(f, alg->a_key_sizes) == -1) {
					rc = LIBIPSEC_ALGS_DIAG_ALGSFILEWRITE;
					goto bail;
				}
			} else {
				/* key sizes defined by range */
				FPRINTF_ERR(fprintf(f, "%d/%d-%d,%d",
				    alg->a_key_sizes[0], alg->a_key_sizes[1],
				    alg->a_key_sizes[2], alg->a_key_increment));
			}
			FPUT_ERR(fputc('|', f));

			/* block sizes */
			if (list_ints(f, alg->a_block_sizes) == -1) {
				rc = LIBIPSEC_ALGS_DIAG_ALGSFILEWRITE;
				goto bail;
			}
			FPUT_ERR(fputc('|', f));

			/*
			 * Some algorithms require extra parameters, these
			 * are stored in an array. For algorithms that don't
			 * need these parameters, or flags (below), these
			 * extra fields in the ipsecalgs file must contain a
			 * zero. This fuction will get called if a algorithm
			 * entry is added, at this point the extra fields will
			 * be added to the file.
			 */
			if (list_ints(f, alg->a_mech_params) == -1) {
				rc = LIBIPSEC_ALGS_DIAG_ALGSFILEWRITE;
				goto bail;
			}
			/* flags */
			FPRINTF_ERR(fprintf(f, "|%d\n", alg->a_alg_flags));
		}
	}

	/* terminate the package section for the algorithms if needed */
	PKG_SEC_END(doing_pkg, cur_pkg);

	if (fchmod(fd, CFG_PERMS) == -1) {
		rc = LIBIPSEC_ALGS_DIAG_ALGSFILECHMOD;
		goto bail;
	}
	if (fchown(fd, CFG_OWNER, CFG_GROUP) == -1) {
		rc = LIBIPSEC_ALGS_DIAG_ALGSFILECHOWN;
		goto bail;
	}
	if (fclose(f) == EOF) {
		rc = LIBIPSEC_ALGS_DIAG_ALGSFILECLOSE;
		goto bail;
	}

	if (rename(tmp_name, INET_IPSECALGSFILE) == -1)
		rc = LIBIPSEC_ALGS_DIAG_ALGSFILERENAME;

bail:
	_clean_trash(protos, num_protos);
	return (rc);
}

/*
 * Return a pointer to the protocol entry corresponding to the specified
 * protocol num proto_num. Also builds the list of currently defined
 * protocols.
 */
static ipsec_proto_t *
proto_setup(ipsec_proto_t **protos, int *num_protos, int proto_num,
    boolean_t cleanup)
{
	int i;
	ipsec_proto_t *current_proto, *ret_proto = NULL;

	_build_internal_algs(protos, num_protos);

	if (*protos == NULL)
		return (NULL);

	for (i = 0; i < *num_protos; i++) {
		current_proto = (*protos) + i;
		if (current_proto->proto_num == proto_num) {
			ret_proto = current_proto;
			break;
		}
	}

	if (ret_proto == NULL) {
		if (cleanup)
			_clean_trash(*protos, *num_protos);
		/* else caller wants parsed /etc/inet/ipsecalgs anyway */
	}

	return (ret_proto);
}

/*
 * Delete the first found algorithm of the specified protocol which
 * has the same name as the one specified by alg_name. Deletion of
 * the entry takes place only if the delete_it flag is set. If an
 * entry was found, return B_TRUE, otherwise return B_FALSE.
 */
static boolean_t
delipsecalgbyname_common(const char *name, ipsec_proto_t *proto,
    boolean_t delete_it)
{
	int i;
	char **name_check;
	boolean_t found_match = B_FALSE;

	for (i = 0; i < proto->proto_numalgs; i++) {
		if (!found_match) {
			for (name_check =
			    proto->proto_algs[i]->a_names;
			    *name_check != NULL; name_check++) {
				/*
				 * Can use strcmp because the algorithm names
				 * are bound.
				 */
				if (strcmp(*name_check, name) == 0) {
					found_match = B_TRUE;
					if (!delete_it)
						return (found_match);
					freeipsecalgent(proto->proto_algs[i]);
					break;
				}
			}
		} else {
			proto->proto_algs[i - 1] = proto->proto_algs[i];
		}
	}

	if (found_match)
		proto->proto_numalgs--;

	return (found_match);
}

/*
 * Returns B_TRUE if the specified 0-terminated lists of key or
 * block sizes match, B_FALSE otherwise.
 */
static boolean_t
sizes_match(int *a1, int *a2)
{
	int i;

	for (i = 0; (a1[i] != 0) && (a2[i] != 0); i++) {
		if (a1[i] != a2[i])
			return (B_FALSE);
	}
	if ((a1[i] != 0) || (a2[i] != 0))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Returns B_TRUE if an _exact_ equivalent of the specified algorithm
 * already exists, B_FALSE otherwise.
 */
static boolean_t
ipsecalg_exists(struct ipsecalgent *newbie, ipsec_proto_t *proto)
{
	struct ipsecalgent *curalg;
	char **curname, **newbiename;
	int i;
	boolean_t match;

	for (i = 0; i < proto->proto_numalgs; i++) {
		curalg = proto->proto_algs[i];

		if (curalg->a_alg_num != newbie->a_alg_num)
			continue;

		if (curalg->a_key_increment != newbie->a_key_increment)
			continue;

		if (strcmp(curalg->a_mech_name, newbie->a_mech_name) != 0)
			continue;

		curname = curalg->a_names;
		newbiename = newbie->a_names;
		match = B_TRUE;
		while ((*curname != NULL) && (*newbiename != NULL) && match) {
			match = (strcmp(*curname, *newbiename) == 0);
			curname++;
			newbiename++;
		}
		if (!match || (*curname != NULL) || (*newbiename != NULL))
			continue;

		if (!sizes_match(curalg->a_block_sizes, newbie->a_block_sizes))
			continue;

		if (!sizes_match(curalg->a_key_sizes, newbie->a_key_sizes))
			continue;

		/* we found an exact match */
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Add a new algorithm to the /etc/inet/ipsecalgs file.  Caller must free
 * or otherwise address "newbie".
 */
int
addipsecalg(struct ipsecalgent *newbie, uint_t flags)
{
	ipsec_proto_t *protos, *current_proto;
	struct ipsecalgent *clone, **holder;
	int num_protos, i;
	char **name_check;
	boolean_t forced_add = (flags & LIBIPSEC_ALGS_ADD_FORCE) != 0;
	boolean_t found_match;

	if ((current_proto = proto_setup(&protos, &num_protos,
	    newbie->a_proto_num, B_TRUE)) == NULL)
		return (LIBIPSEC_ALGS_DIAG_UNKN_PROTO);

	/*
	 * If an algorithm that matches _exactly_ the new algorithm
	 * already exists, we're done.
	 */
	if (ipsecalg_exists(newbie, current_proto))
		return (0);

	/*
	 * We don't allow a new algorithm to be created if one of
	 * its names is already defined for an existing algorithm,
	 * unless the operation is forced, in which case existing
	 * algorithm entries that conflict with the new one are
	 * deleted.
	 */
	for (name_check = newbie->a_names; *name_check != NULL; name_check++) {
		found_match = delipsecalgbyname_common(*name_check,
		    current_proto, forced_add);
		if (found_match && !forced_add) {
			/*
			 * Duplicate entry found, but the addition was
			 * not forced.
			 */
			_clean_trash(protos, num_protos);
			return (LIBIPSEC_ALGS_DIAG_ALG_EXISTS);
		}
	}

	for (i = 0; i < current_proto->proto_numalgs; i++) {
		if (current_proto->proto_algs[i]->a_alg_num ==
		    newbie->a_alg_num) {
			/*
			 * An algorithm with the same protocol number
			 * and algorithm number already exists. Fail
			 * addition unless the operation is forced.
			 */
			if (flags & LIBIPSEC_ALGS_ADD_FORCE) {
				clone = _duplicate_alg(newbie);
				if (clone != NULL) {
					freeipsecalgent(
					    current_proto->proto_algs[i]);
					current_proto->proto_algs[i] = clone;
					return (write_new_algfile(protos,
					    num_protos));
				} else {
					_clean_trash(protos, num_protos);
					return (LIBIPSEC_ALGS_DIAG_NOMEM);
				}
			} else {
				_clean_trash(protos, num_protos);
				return (LIBIPSEC_ALGS_DIAG_ALG_EXISTS);
			}
		}
	}

	/* append the new algorithm */
	holder = realloc(current_proto->proto_algs,
	    sizeof (struct ipsecalgent *) * (i + 1));
	if (holder == NULL) {
		_clean_trash(protos, num_protos);
		return (LIBIPSEC_ALGS_DIAG_NOMEM);
	}
	clone = _duplicate_alg(newbie);
	if (clone == NULL) {
		free(holder);
		_clean_trash(protos, num_protos);
		return (LIBIPSEC_ALGS_DIAG_NOMEM);
	}
	current_proto->proto_numalgs++;
	current_proto->proto_algs = holder;
	current_proto->proto_algs[i] = clone;
	return (write_new_algfile(protos, num_protos));
}

/*
 * Delete an algorithm by name & protocol number from /etc/inet/ipsecalgs.
 * Only deletes the first encountered instance.
 */
int
delipsecalgbyname(const char *name, int proto_num)
{
	ipsec_proto_t *protos, *current_proto;
	int num_protos;

	if ((current_proto = proto_setup(&protos, &num_protos, proto_num,
	    B_TRUE)) == NULL)
		return (LIBIPSEC_ALGS_DIAG_UNKN_PROTO);

	if (delipsecalgbyname_common(name, current_proto, B_TRUE))
		return (write_new_algfile(protos, num_protos));

	_clean_trash(protos, num_protos);
	return (LIBIPSEC_ALGS_DIAG_UNKN_ALG);
}

/*
 * Delete an algorithm by num + protocol num from /etc/inet/ipsecalgs.
 */
int
delipsecalgbynum(int alg_num, int proto_num)
{
	ipsec_proto_t *protos, *current_proto;
	int i, num_protos;
	boolean_t found_match = B_FALSE;

	if ((current_proto = proto_setup(&protos, &num_protos, proto_num,
	    B_TRUE)) == NULL)
		return (LIBIPSEC_ALGS_DIAG_UNKN_PROTO);

	for (i = 0; i < current_proto->proto_numalgs; i++) {
		if (!found_match) {
			if (current_proto->proto_algs[i]->a_alg_num ==
			    alg_num) {
				found_match = B_TRUE;
				freeipsecalgent(current_proto->proto_algs[i]);
			}
		} else {
			current_proto->proto_algs[i - 1] =
			    current_proto->proto_algs[i];
		}
	}

	if (found_match) {
		current_proto->proto_numalgs--;
		return (write_new_algfile(protos, num_protos));
	}

	_clean_trash(protos, num_protos);
	return (LIBIPSEC_ALGS_DIAG_UNKN_ALG);
}

/*
 * Remove the specified protocol entry from the list of protocols.
 */
static void
delipsecproto_common(ipsec_proto_t *protos, int num_protos,
    ipsec_proto_t *proto)
{
	int i;

	/* free protocol storage */
	free(proto->proto_name);
	for (i = 0; i < proto->proto_numalgs; i++)
		freeipsecalgent(proto->proto_algs[i]);

	/* remove from list of prototocols */
	for (i = (proto - protos + 1); i < num_protos; i++)
		protos[i - 1] = protos[i];
}

/*
 * Add an IPsec protocol to /etc/inet/ipsecalgs.
 */
int
addipsecproto(const char *proto_name, int proto_num,
    ipsecalgs_exec_mode_t proto_exec_mode, uint_t flags)
{
	ipsec_proto_t *protos, *current_proto, *new_proto;
	int i, num_protos;

	/*
	 * NOTE:If build_internal_algs returns NULL for any
	 *	reason, we will end up clobbering /etc/inet/ipsecalgs!
	 */

	current_proto = proto_setup(&protos, &num_protos, proto_num, B_FALSE);

	/* check for protocol with duplicate id */
	if (current_proto != NULL) {
		if ((strcmp(proto_name, current_proto->proto_name) == 0) &&
		    (proto_exec_mode == current_proto->proto_exec_mode)) {
			/*
			 * The current protocol being added matches
			 * exactly an existing protocol, we're done.
			 */
			return (0);
		}
		if (!(flags & LIBIPSEC_ALGS_ADD_FORCE))
			return (LIBIPSEC_ALGS_DIAG_PROTO_EXISTS);
		delipsecproto_common(protos, num_protos--, current_proto);
	}

	/* check for protocol with duplicate name */
	for (i = 0; i < num_protos; i++) {
		if (strcmp(protos[i].proto_name, proto_name) == 0) {
			if (!(flags & LIBIPSEC_ALGS_ADD_FORCE))
				return (LIBIPSEC_ALGS_DIAG_PROTO_EXISTS);
			delipsecproto_common(protos, num_protos--, &protos[i]);
			break;
		}
	}

	/* add new protocol */
	num_protos++;
	new_proto = realloc(protos, num_protos *
	    sizeof (ipsec_proto_t));
	if (new_proto == NULL) {
		_clean_trash(protos, num_protos - 1);
		return (LIBIPSEC_ALGS_DIAG_NOMEM);
	}
	protos = new_proto;
	new_proto += (num_protos - 1);

	/* initialize protocol entry */
	new_proto->proto_num = proto_num;
	new_proto->proto_numalgs = 0;
	new_proto->proto_algs = NULL;
	new_proto->proto_name = strdup(proto_name);
	if (new_proto->proto_name == NULL) {
		_clean_trash(protos, num_protos);
		return (LIBIPSEC_ALGS_DIAG_NOMEM);
	}
	new_proto->proto_pkg = NULL;
	new_proto->proto_algs_pkgs = NULL;
	new_proto->proto_algs_npkgs = 0;
	new_proto->proto_exec_mode = proto_exec_mode;

	return (write_new_algfile(protos, num_protos));
}

/*
 * Delete an IPsec protocol entry from /etc/inet/ipsecalgs.  This also
 * nukes the associated algorithms.
 */
int
delipsecprotobynum(int proto_num)
{
	ipsec_proto_t *protos, *current_proto;
	int num_protos;

	if ((current_proto = proto_setup(&protos, &num_protos, proto_num,
	    B_TRUE)) == NULL)
		return (LIBIPSEC_ALGS_DIAG_UNKN_PROTO);

	delipsecproto_common(protos, num_protos--, current_proto);

	return (write_new_algfile(protos, num_protos));
}

int
delipsecprotobyname(const char *proto_name)
{
	int proto_num;

	proto_num = getipsecprotobyname(proto_name);
	if (proto_num == -1)
		return (LIBIPSEC_ALGS_DIAG_UNKN_PROTO);

	return (delipsecprotobynum(proto_num));
}

/*
 * Implement these in libnsl since these are read-only operations.
 */
int *
getipsecprotos(int *nentries)
{
	return (_real_getipsecprotos(nentries));
}

int *
getipsecalgs(int *nentries, int proto_num)
{
	return (_real_getipsecalgs(nentries, proto_num));
}

const char *
ipsecalgs_diag(int diag)
{
	switch (diag) {
	case LIBIPSEC_ALGS_DIAG_ALG_EXISTS:
		return (dgettext(TEXT_DOMAIN, "Algorithm already exists"));
	case LIBIPSEC_ALGS_DIAG_PROTO_EXISTS:
		return (dgettext(TEXT_DOMAIN, "Protocol already exists"));
	case LIBIPSEC_ALGS_DIAG_UNKN_PROTO:
		return (dgettext(TEXT_DOMAIN, "Unknown protocol"));
	case LIBIPSEC_ALGS_DIAG_UNKN_ALG:
		return (dgettext(TEXT_DOMAIN, "Unknown algorithm"));
	case LIBIPSEC_ALGS_DIAG_NOMEM:
		return (dgettext(TEXT_DOMAIN, "Out of memory"));
	case LIBIPSEC_ALGS_DIAG_ALGSFILEOPEN:
		return (dgettext(TEXT_DOMAIN, "open() failed"));
	case LIBIPSEC_ALGS_DIAG_ALGSFILEFDOPEN:
		return (dgettext(TEXT_DOMAIN, "fdopen() failed"));
	case LIBIPSEC_ALGS_DIAG_ALGSFILELOCK:
		return (dgettext(TEXT_DOMAIN, "lockf() failed"));
	case LIBIPSEC_ALGS_DIAG_ALGSFILERENAME:
		return (dgettext(TEXT_DOMAIN, "rename() failed"));
	case LIBIPSEC_ALGS_DIAG_ALGSFILEWRITE:
		return (dgettext(TEXT_DOMAIN, "write to file failed"));
	case LIBIPSEC_ALGS_DIAG_ALGSFILECHMOD:
		return (dgettext(TEXT_DOMAIN, "chmod() failed"));
	case LIBIPSEC_ALGS_DIAG_ALGSFILECHOWN:
		return (dgettext(TEXT_DOMAIN, "chown() failed"));
	case LIBIPSEC_ALGS_DIAG_ALGSFILECLOSE:
		return (dgettext(TEXT_DOMAIN, "close() failed"));
	default:
		return (dgettext(TEXT_DOMAIN, "failed"));
	}
}

/*
 * Get the execution mode corresponding to the specified protocol.
 * Returns 0 on success, one of the LIBIPSEC_ALGS_DIAG_* values on
 * failure.
 */
int
ipsecproto_get_exec_mode(int proto_num, ipsecalgs_exec_mode_t *exec_mode)
{
	ipsec_proto_t *protos, *current_proto;
	int num_protos;

	if ((current_proto = proto_setup(&protos, &num_protos, proto_num,
	    B_TRUE)) == NULL)
		return (LIBIPSEC_ALGS_DIAG_UNKN_PROTO);

	*exec_mode = current_proto->proto_exec_mode;

	_clean_trash(protos, num_protos);
	return (0);
}

/*
 * Set the execution mode of the specified protocol. Returns 0 on success,
 * or one of the LIBIPSEC_ALGS_DIAG_* values on failure.
 */
int
ipsecproto_set_exec_mode(int proto_num, ipsecalgs_exec_mode_t exec_mode)
{
	ipsec_proto_t *protos, *current_proto;
	int num_protos;

	if ((current_proto = proto_setup(&protos, &num_protos, proto_num,
	    B_TRUE)) == NULL)
		return (LIBIPSEC_ALGS_DIAG_UNKN_PROTO);

	current_proto->proto_exec_mode = exec_mode;

	return (write_new_algfile(protos, num_protos));
}
