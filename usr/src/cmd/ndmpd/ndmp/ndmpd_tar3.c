/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* Copyright (c) 2007, The Storage Networking Industry Association. */
/* Copyright (c) 1996, 1997 PDC, Network Appliance. All Rights Reserved */
/* Copyright 2014 Nexenta Systems, Inc. All rights reserved. */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/acl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <cstack.h>
#include "ndmp.h"
#include "ndmpd.h"
#include <bitmap.h>
#include <traverse.h>


/*
 * Maximum length of the string-representation of u_longlong_t type.
 */
#define	QUAD_DECIMAL_LEN	20


/* Is Y=yes or T=true */
#define	IS_YORT(c)	(strchr("YT", toupper(c)))

/* Is F=file format (vs D=node-dir format) */
#define	IS_F(c)		(toupper(c) == 'F')

/*
 * If path is defined.
 */
#define	ISDEFINED(cp)	((cp) && *(cp))
#define	SHOULD_LBRBK(bpp)	(!((bpp)->bp_opr & TLM_OP_CHOOSE_ARCHIVE))

/*
 * Component boundary means end of path or on a '/'.  At this
 * point both paths should be on component boundary.
 */
#define	COMPBNDRY(p)	(!*(p) || (*p) == '/')

typedef struct bk_param_v3 {
	ndmpd_session_t *bp_session;
	ndmp_lbr_params_t *bp_nlp;
	tlm_job_stats_t *bp_js;
	tlm_cmd_t *bp_lcmd;
	tlm_commands_t *bp_cmds;
	tlm_acls_t *bp_tlmacl;
	int bp_opr;
	char *bp_tmp;
	char *bp_chkpnm;
	char **bp_excls;
	char *bp_unchkpnm;
} bk_param_v3_t;


/*
 * Multiple destination restore mode
 */
#define	MULTIPLE_DEST_DIRS 128

int multiple_dest_restore = 0;

/*
 * Plug-in module ops
 */
ndmp_plugin_t *ndmp_pl;

/*
 * NDMP exclusion list
 */
char **ndmp_excl_list = NULL;

/*
 * split_env
 *
 * Splits the string into list of sections separated by the
 * sep character.
 *
 * Parameters:
 *   envp (input) - the environment variable that should be broken
 *   sep (input) - the separator character
 *
 * Returns:
 *   Array of character pointers: On success.  The array is allocated
 *	as well as all its entries.  They all should be freed by the
 *	caller.
 *   NULL: on error
 */
static char **
split_env(char *envp, char sep)
{
	char *bp, *cp, *ep;
	char *save;
	char **cpp;
	int n;

	if (!envp)
		return (NULL);

	while (isspace(*envp))
		envp++;

	if (!*envp)
		return (NULL);

	bp = save = strdup(envp);
	if (!bp)
		return (NULL);

	/*
	 * Since the env variable is not empty, it contains at least one
	 * component
	 */
	n = 1;
	while ((cp = strchr(bp, sep))) {
		if (cp > save && *(cp-1) != '\\')
			n++;

		bp = cp + 1;
	}

	n++; /* for the terminating NULL pointer */
	cpp = ndmp_malloc(sizeof (char *) * n);
	if (!cpp) {
		free(save);
		return (NULL);
	}

	(void) memset(cpp, 0, n * sizeof (char *));
	n = 0;
	cp = bp = ep = save;
	while (*cp)
		if (*cp == sep) {
			*ep = '\0';
			if (strlen(bp) > 0) {
				cpp[n] = strdup(bp);
				if (!cpp[n++]) {
					tlm_release_list(cpp);
					cpp = NULL;
					break;
				}
			}
			ep = bp = ++cp;
		} else if (*cp == '\\') {
			++cp;
			if (*cp == 'n') {	/* "\n" */
				*ep++ = '\n';
				cp++;
			} else if (*cp == 't') {	/* "\t" */
				*ep++ = '\t';
				cp++;
			} else
				*ep++ = *cp++;
		} else
			*ep++ = *cp++;

	*ep = '\0';
	if (cpp) {
		if (strlen(bp) > 0) {
			cpp[n] = strdup(bp);
			if (!cpp[n++]) {
				tlm_release_list(cpp);
				cpp = NULL;
			} else
				cpp[n] = NULL;
		}

		if (n == 0 && cpp != NULL) {
			tlm_release_list(cpp);
			cpp = NULL;
		}
	}

	free(save);
	return (cpp);
}


/*
 * prl
 *
 * Print the array of character pointers passed to it.  This is
 * used for debugging purpose.
 *
 * Parameters:
 *   lpp (input) - pointer to the array of strings
 *
 * Returns:
 *   void
 */
static void
prl(char **lpp)
{
	if (!lpp) {
		NDMP_LOG(LOG_DEBUG, "empty");
		return;
	}

	while (*lpp)
		NDMP_LOG(LOG_DEBUG, "\"%s\"", *lpp++);
}


/*
 * inlist
 *
 * Looks through all the strings of the array to see if the ent
 * matches any of the strings.  The strings are patterns.
 *
 * Parameters:
 *   lpp (input) - pointer to the array of strings
 *   ent (input) - the entry to be matched
 *
 * Returns:
 *   TRUE: if there is a match
 *   FALSE: invalid argument or no match
 */
static boolean_t
inlist(char **lpp, char *ent)
{
	if (!lpp || !ent) {
		NDMP_LOG(LOG_DEBUG, "empty list");
		return (FALSE);
	}

	while (*lpp) {
		/*
		 * Fixing the sync_sort NDMPV3 problem, it sends the inclusion
		 * like "./" which we should skip the "./"
		 */
		char *pattern = *lpp;
		if (strncmp(pattern, "./", 2) == 0)
			pattern += 2;

		NDMP_LOG(LOG_DEBUG, "pattern %s, ent %s", pattern, ent);

		if (match(pattern, ent)) {
			NDMP_LOG(LOG_DEBUG, "match(%s,%s)", pattern, ent);
			return (TRUE);
		}
		lpp++;
	}

	NDMP_LOG(LOG_DEBUG, "no match");
	return (FALSE);
}


/*
 * inexl
 *
 * Checks if the entry is in the list.  This is used for exclusion
 * list.  If the exclusion list is empty, FALSE should be returned
 * showing that nothing should be excluded by default.
 *
 * Parameters:
 *   lpp (input) - pointer to the array of strings
 *   ent (input) - the entry to be matched
 *
 * Returns:
 *   TRUE: if there is a match
 *   FALSE: invalid argument or no match
 *
 */
static boolean_t
inexl(char **lpp, char *ent)
{
	if (!lpp || !ent)
		return (FALSE);

	return (inlist(lpp, ent));
}


/*
 * ininc
 *
 * Checks if the entry is in the list.  This is used for inclusion
 * list.  If the inclusion list is empty, TRUE should be returned
 * showing that everything should be included by default.
 *
 * Parameters:
 *   lpp (input) - pointer to the array of strings
 *   ent (input) - the entry to be matched
 *
 * Returns:
 *   TRUE: if there is a match or the list is empty
 *   FALSE: no match
 */
static boolean_t
ininc(char **lpp, char *ent)
{
	if (!lpp || !ent || !*ent)
		return (TRUE);

	return (inlist(lpp, ent));
}


/*
 * setupsels
 *
 * Set up the selection list for Local B/R functions.  A new array of
 * "char *" is created and the pointers point to the original paths of
 * the Nlist.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *   index(input) - If not zero is the DAR entry position
 *
 * Returns:
 *   list pointer: on success
 *   NULL: on error
 */
/*ARGSUSED*/
char **
setupsels(ndmpd_session_t *session, ndmpd_module_params_t *params,
    ndmp_lbr_params_t *nlp, int index)
{
	char **lpp, **save;
	int i, n;
	int len;
	int start, end;
	mem_ndmp_name_v3_t *ep;

	n = session->ns_data.dd_nlist_len;

	save = lpp = ndmp_malloc(sizeof (char *) * (n + 1));
	if (!lpp) {
		MOD_LOGV3(params, NDMP_LOG_ERROR, "Insufficient memory.\n");
		return (NULL);
	}

	if (index) { /* DAR, just one entry */
		/*
		 * We have to setup a list of strings that will not match any
		 * file. One DAR entry will be added in the right position later
		 * in this function.
		 * When the match is called from tar_getdir the
		 * location of the selection that matches the entry is
		 * important
		 */
		for (i = 0; i < n; ++i)
			*(lpp+i) = " ";
		n = 1;
		start = index-1;
		end = start+1;
		lpp += start; /* Next selection entry will be in lpp[start] */
	} else {
		start = 0;
		end = n;
	}

	for (i = start; i < end; i++) {
		ep = (mem_ndmp_name_v3_t *)MOD_GETNAME(params, i);
		if (!ep)
			continue;

		/*
		 * Check for clients that send original path as "."(like
		 * CA products). In this situation opath is something like
		 * "/v1/." and we should change it to "/v1/"
		 */
		len = strlen(ep->nm3_opath);
		if (len > 1 && ep->nm3_opath[len-2] == '/' &&
		    ep->nm3_opath[len-1] == '.') {
			ep->nm3_opath[len-1] = '\0';
			NDMP_LOG(LOG_DEBUG,
			    "nm3_opath changed from %s. to %s",
			    ep->nm3_opath, ep->nm3_opath);
		}
		*lpp++ = ep->nm3_opath;
	}

	/* list termination indicator is a null pointer */
	*lpp = NULL;

	return (save);
}


/*
 * mkrsp
 *
 * Make Restore Path.
 * It gets a path, a selection (with which the path has matched) a new
 * name and makes a new name for the path.
 * All the components of the path and the selection are skipped as long
 * as they are the same.  If either of the path or selection are not on
 * a component boundary, the match was reported falsefully and no new name
 * is generated(Except the situation in which both path and selection
 * end with trailing '/' and selection is the prefix of the path).
 * Otherwise, the remaining of the path is appended to the
 * new name.  The result is saved in the buffer passed.
 *
 * Parameters:
 *   bp (output) - pointer to the result buffer
 *   pp (input) - pointer to the path
 *   sp (input) - pointer to the selection
 *   np (input) - pointer to the new name
 *
 * Returns:
 *   pointer to the bp: on success
 *   NULL: otherwise
 */
char *
mkrsp(char *bp, char *pp, char *sp, char *np)
{
	if (!bp || !pp)
		return (NULL);


	pp += strspn(pp, "/");
	if (sp) {
		sp += strspn(sp, "/");

		/* skip as much as match */
		while (*sp && *pp && *sp == *pp) {
			sp++;
			pp++;
		}

		if (!COMPBNDRY(pp) || !COMPBNDRY(sp))
			/* An exception to the boundary rule */
			/* (!(!*sp && (*(pp - 1)) == '/')) */
			if (*sp || (*(pp - 1)) != '/')
				return (NULL);

		/* if pp shorter than sp, it should not be restored */
		if (!*pp && *sp) {
			sp += strspn(sp, "/");
			if (strlen(sp) > 0)
				return (NULL);
		}
	}

	if (np)
		np += strspn(np, "/");
	else
		np = "";

	if (!tlm_cat_path(bp, np, pp)) {
		NDMP_LOG(LOG_ERR, "Restore path too long %s/%s.", np, pp);
		return (NULL);
	}

	return (bp);
}


/*
 * mknewname
 *
 * This is used as callback for creating the restore path. This function
 * can handle both single destination and multiple restore paths.
 *
 * Make up the restore destination path for a particular file/directory, path,
 * based on nm3_opath and nm3_dpath.  path should have matched nm3_opath
 * in some way.
 */
char *
mknewname(struct rs_name_maker *rnp, char *buf, int idx, char *path)
{
	char *rv;
	ndmp_lbr_params_t *nlp;
	mem_ndmp_name_v3_t *ep;

	rv = NULL;
	if (!buf) {
		NDMP_LOG(LOG_DEBUG, "buf is NULL");
	} else if (!path) {
		NDMP_LOG(LOG_DEBUG, "path is NULL");
	} else if ((nlp = rnp->rn_nlp) == 0) {
		NDMP_LOG(LOG_DEBUG, "rnp->rn_nlp is NULL");
	} else if (!nlp->nlp_params) {
		NDMP_LOG(LOG_DEBUG, "nlp->nlp_params is NULL");
	} else
		if (!ndmp_full_restore_path) {
			if (idx < 0 || idx >= (int)nlp->nlp_nfiles) {
				NDMP_LOG(LOG_DEBUG,
				    "Invalid idx %d range (0, %d)",
				    idx, nlp->nlp_nfiles);
			} else if (!(ep = (mem_ndmp_name_v3_t *)MOD_GETNAME(
			    nlp->nlp_params, idx))) {
				NDMP_LOG(LOG_DEBUG,
				    "nlist entry %d is NULL", idx);
			} else {
				rv = mkrsp(buf, path, ep->nm3_opath,
				    ep->nm3_dpath);

				NDMP_LOG(LOG_DEBUG,
				    "idx %d org \"%s\" dst \"%s\"",
				    idx, ep->nm3_opath, ep->nm3_dpath);
				if (rv) {
					NDMP_LOG(LOG_DEBUG,
					    "path \"%s\": \"%s\"", path, rv);
				} else {
					NDMP_LOG(LOG_DEBUG,
					    "path \"%s\": NULL", path);
				}
			}
		} else {
			if (!tlm_cat_path(buf, nlp->nlp_restore_path, path)) {
				NDMP_LOG(LOG_ERR, "Path too long %s/%s.",
				    nlp->nlp_restore_path, path);
				rv = NULL;
			} else {
				rv = buf;
				NDMP_LOG(LOG_DEBUG,
				    "path \"%s\": \"%s\"", path, rv);
			}
		}

	return (rv);
}


/*
 * chopslash
 *
 * Remove the slash from the end of the given path
 */
static void
chopslash(char *cp)
{
	int ln;

	if (!cp || !*cp)
		return;

	ln = strlen(cp);
	cp += ln - 1; /* end of the string */
	while (ln > 0 && *cp == '/') {
		*cp-- = '\0';
		ln--;
	}
}


/*
 * joinpath
 *
 * Join two given paths
 */
static char *
joinpath(char *bp, char *pp, char *np)
{
	if (pp && *pp) {
		if (np && *np)
			(void) tlm_cat_path(bp, pp, np);
		else
			(void) strlcpy(bp, pp, TLM_MAX_PATH_NAME);
	} else {
		if (np && *np)
			(void) strlcpy(bp, np, TLM_MAX_PATH_NAME);
		else
			bp = NULL;
	}

	return (bp);
}


/*
 * voliswr
 *
 * Is the volume writable?
 */
static int
voliswr(char *path)
{
	int rv;

	if (!path)
		return (0);

	rv = !fs_is_rdonly(path) && !fs_is_chkpntvol(path);
	NDMP_LOG(LOG_DEBUG, "%d path \"%s\"", rv, path);
	return (rv);

}


/*
 * is_valid_backup_dir_v3
 *
 * Checks the validity of the backup path.  Backup path should
 * have the following characteristics to be valid:
 *	1) It should be an absolute path.
 *	2) It should be a directory.
 *	3) It should not be checkpoint root directory
 *	4) If the file system is read-only, the backup path
 *	    should be a checkpointed path.  Checkpoint cannot
 *	    be created on a read-only file system.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure.
 *   bkpath (input) - the backup path
 *
 * Returns:
 *   TRUE: if everything's OK
 *   FALSE: otherwise.
 */
static boolean_t
is_valid_backup_dir_v3(ndmpd_module_params_t *params, char *bkpath)
{
	char *msg;
	struct stat64 st;

	if (*bkpath != '/') {
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "Relative backup path not allowed \"%s\".\n", bkpath);
		return (FALSE);
	}
	if (stat64(bkpath, &st) < 0) {
		msg = strerror(errno);
		MOD_LOGV3(params, NDMP_LOG_ERROR, "\"%s\" %s.\n",
		    bkpath, msg);
		return (FALSE);
	}
	if (!S_ISDIR(st.st_mode)) {
		/* only directories can be specified as the backup path */
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "\"%s\" is not a directory.\n", bkpath);
		return (FALSE);
	}
	if (fs_is_rdonly(bkpath) && !fs_is_chkpntvol(bkpath) &&
	    fs_is_chkpnt_enabled(bkpath)) {
		/* it is not a chkpnted path */
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "\"%s\" is not a checkpointed path.\n", bkpath);
		return (FALSE);
	}

	return (TRUE);
}


/*
 * log_date_token_v3
 *
 * Log the token sequence number and also the date of the
 * last backup for token-based backup in the system log
 * and also send them as normal log to the client.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   void
 */
static void
log_date_token_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	MOD_LOGV3(params, NDMP_LOG_NORMAL, "Token sequence counter: %d.\n",
	    nlp->nlp_tokseq);

	MOD_LOGV3(params, NDMP_LOG_NORMAL, "Date of the last backup: %s.\n",
	    cctime(&nlp->nlp_tokdate));

	if (nlp->nlp_dmpnm) {
		MOD_LOGV3(params, NDMP_LOG_NORMAL,
		    "Backup date log file name: \"%s\".\n", nlp->nlp_dmpnm);
	}
}


/*
 * log_lbr_bk_v3
 *
 * Log the backup level and data of the backup for LBR-type
 * backup in the system log and also send them as normal log
 * to the client.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   void
 */
static void
log_lbr_bk_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	MOD_LOGV3(params, NDMP_LOG_NORMAL,
	    "Date of this level '%c': %s.\n", nlp->nlp_clevel,
	    cctime(&nlp->nlp_cdate));

	if (nlp->nlp_dmpnm) {
		MOD_LOGV3(params, NDMP_LOG_NORMAL,
		    "Backup date log file name: \"%s\".\n", nlp->nlp_dmpnm);
	}
}


/*
 * log_level_v3
 *
 * Log the backup level and date of the last and the current
 * backup for level-type backup in the system log and also
 * send them as normal log to the client.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   void
 */
static void
log_level_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	MOD_LOGV3(params, NDMP_LOG_NORMAL,
	    "Date of the last level '%u': %s.\n", nlp->nlp_llevel,
	    cctime(&nlp->nlp_ldate));

	MOD_LOGV3(params, NDMP_LOG_NORMAL,
	    "Date of this level '%u': %s.\n", nlp->nlp_clevel,
	    cctime(&nlp->nlp_cdate));

	MOD_LOGV3(params, NDMP_LOG_NORMAL, "Update: %s.\n",
	    NDMP_TORF(NLP_ISSET(nlp, NLPF_UPDATE)));
}


/*
 * log_bk_params_v3
 *
 * Dispatcher function which calls the appropriate function
 * for logging the backup date and level in the system log
 * and also send them as normal log message to the client.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   void
 */
static void
log_bk_params_v3(ndmpd_session_t *session, ndmpd_module_params_t *params,
    ndmp_lbr_params_t *nlp)
{
	MOD_LOGV3(params, NDMP_LOG_NORMAL, "Backing up \"%s\".\n",
	    nlp->nlp_backup_path);

	if (session->ns_mover.md_data_addr.addr_type == NDMP_ADDR_LOCAL)
		MOD_LOGV3(params, NDMP_LOG_NORMAL,
		    "Tape record size: %d.\n",
		    session->ns_mover.md_record_size);

	MOD_LOGV3(params, NDMP_LOG_NORMAL, "File history: %c.\n",
	    NDMP_YORN(NLP_ISSET(nlp, NLPF_FH)));

	if (NLP_ISSET(nlp, NLPF_TOKENBK))
		log_date_token_v3(params, nlp);
	else if (NLP_ISSET(nlp, NLPF_LBRBK))
		log_lbr_bk_v3(params, nlp);
	else if (NLP_ISSET(nlp, NLPF_LEVELBK))
		log_level_v3(params, nlp);
	else {
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "Internal error: backup level not defined for \"%s\".\n",
		    nlp->nlp_backup_path);
	}
}


/*
 * get_update_env_v3
 *
 * Is the UPDATE environment variable specified?  If it is
 * the corresponding flag is set in the flags field of the
 * nlp structure, otherwise the flag is cleared.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   void
 */
static void
get_update_env_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	char *envp;

	envp = MOD_GETENV(params, "UPDATE");
	if (!envp) {
		NLP_SET(nlp, NLPF_UPDATE);
		NDMP_LOG(LOG_DEBUG,
		    "env(UPDATE) not defined, default to TRUE");
	} else {
		NDMP_LOG(LOG_DEBUG, "env(UPDATE): \"%s\"", envp);
		if (IS_YORT(*envp))
			NLP_SET(nlp, NLPF_UPDATE);
		else
			NLP_UNSET(nlp, NLPF_UPDATE);
	}
}


/*
 * get_hist_env_v3
 *
 * Is backup history requested?  If it is, the corresponding
 * flag is set in the flags field of the nlp structure, otherwise
 * the flag is cleared.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   void
 */
static void
get_hist_env_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	char *envp;

	envp = MOD_GETENV(params, "HIST");
	if (!envp) {
		NDMP_LOG(LOG_DEBUG, "env(HIST) not defined");
		NLP_UNSET(nlp, NLPF_FH);
	} else {
		NDMP_LOG(LOG_DEBUG, "env(HIST): \"%s\"", envp);
		if (IS_YORT(*envp) || IS_F(*envp))
			NLP_SET(nlp, NLPF_FH);
		else
			NLP_UNSET(nlp, NLPF_FH);

		/* Force file format if specified */
		if (IS_F(*envp)) {
			params->mp_file_history_path_func =
			    ndmpd_api_file_history_file_v3;
			params->mp_file_history_dir_func = 0;
			params->mp_file_history_node_func = 0;
		}
	}
}


/*
 * get_exc_env_v3
 *
 * Gets the EXCLUDE environment variable and breaks it
 * into strings.  The separator of the EXCLUDE environment
 * variable is the ',' character.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   void
 */
static void
get_exc_env_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	char *envp;

	envp = MOD_GETENV(params, "EXCLUDE");
	if (!envp) {
		NDMP_LOG(LOG_DEBUG, "env(EXCLUDE) not defined");
		nlp->nlp_exl = NULL;
	} else {
		NDMP_LOG(LOG_DEBUG, "env(EXCLUDE): \"%s\"", envp);
		nlp->nlp_exl = split_env(envp, ',');
		prl(nlp->nlp_exl);
	}
}


/*
 * get_inc_env_v3
 *
 * Gets the FILES environment variable that shows which files
 * should be backed up, and breaks it into strings.  The
 * separator of the FILES environment variable is the space
 * character.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   void
 */
static void
get_inc_env_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	char *envp;

	envp = MOD_GETENV(params, "FILES");
	if (!envp) {
		NDMP_LOG(LOG_DEBUG, "env(FILES) not defined");
		nlp->nlp_inc = NULL;
	} else {
		NDMP_LOG(LOG_DEBUG, "env(FILES): \"%s\"", envp);
		nlp->nlp_inc = split_env(envp, ' ');
		prl(nlp->nlp_inc);
	}
}


/*
 * get_direct_env_v3
 *
 * Gets the DIRECT environment variable that shows if the fh_info should
 * be sent to the client or not.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   void
 */
static void
get_direct_env_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	char *envp;

	/*
	 * We should send the fh_info to the DMA, unless it is specified
	 * in the request that we should not send fh_info.
	 * At the moment we do not support DAR on directories, so if the user
	 * needs to restore a directory they should disable the DAR.
	 */
	if (params->mp_operation == NDMP_DATA_OP_RECOVER && !ndmp_dar_support) {
		NDMP_LOG(LOG_DEBUG, "Direct Access Restore Disabled");
		NLP_UNSET(nlp, NLPF_DIRECT);
		MOD_LOGV3(params, NDMP_LOG_NORMAL,
		    "DAR is disabled. Running Restore without DAR");
		return;
	}

	/*
	 * Regardless of whether DIRECT is defined at backup time we send
	 * back the fh_info, for some clients do not use get_backup_attrs.
	 * If operation is restore we have to unset the DIRECT, for
	 * some clients do not set the MOVER window.
	 */
	if (params->mp_operation == NDMP_DATA_OP_BACKUP) {
		NDMP_LOG(LOG_DEBUG, "backup default env(DIRECT): YES");
		NLP_SET(nlp, NLPF_DIRECT);
	} else {

		envp = MOD_GETENV(params, "DIRECT");
		if (!envp) {
			NDMP_LOG(LOG_DEBUG, "env(DIRECT) not defined");
			NLP_UNSET(nlp, NLPF_DIRECT);
		} else {
			NDMP_LOG(LOG_DEBUG, "env(DIRECT): \"%s\"", envp);
			if (IS_YORT(*envp)) {
				NLP_SET(nlp, NLPF_DIRECT);
				NDMP_LOG(LOG_DEBUG,
				    "Direct Access Restore Enabled");
			} else {
				NLP_UNSET(nlp, NLPF_DIRECT);
				NDMP_LOG(LOG_DEBUG,
				    "Direct Access Restore Disabled");
			}
		}
	}

	if (NLP_ISSET(nlp, NLPF_DIRECT)) {
		if (params->mp_operation == NDMP_DATA_OP_BACKUP)
			MOD_LOGV3(params, NDMP_LOG_NORMAL,
			    "Direct Access Restore information is supported");
		else
			MOD_LOGV3(params, NDMP_LOG_NORMAL,
			    "Running Restore with Direct Access Restore");
	} else {
		if (params->mp_operation == NDMP_DATA_OP_BACKUP)
			MOD_LOGV3(params, NDMP_LOG_NORMAL,
			    "Direct Access Restore is not supported");
		else
			MOD_LOGV3(params, NDMP_LOG_NORMAL,
			    "Running Restore without Direct Access Restore");
	}
}


/*
 * get_date_token_v3
 *
 * Parse the token passed as the argument.  Evaluate it and
 * issue any warning or error if needed.  Save the date and
 * token sequence in the nlp structure fields.  The sequence
 * number in the token should be less than hard-limit.  If
 * it's between soft and hard limit, a warning is issued.
 * There is a configurable limit which should be less than
 * the soft-limit saved in ndmp_max_tok_seq variable.
 *
 * The NLPF_TOKENBK flag is set in the nlp flags field to
 * show that the backup type is token-based.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *   basedate (input) - the value of the BASE_DATE environment
 *	variable.
 *
 * Returns:
 *   NDMP_NO_ERR: on success
 *   != NDMP_NO_ERR: Otherwise
 *
 */
static ndmp_error
get_date_token_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp,
    char *basedate)
{
	char *endp;
	uint_t seq;
	ndmp_error rv;
	time_t tstamp;
	u_longlong_t tok;

	if (!params || !nlp || !basedate || !*basedate)
		return (NDMP_ILLEGAL_ARGS_ERR);

	if (MOD_GETENV(params, "LEVEL")) {
		MOD_LOGV3(params, NDMP_LOG_WARNING,
		    "Both BASE_DATE and LEVEL environment variables "
		    "defined.\n");
		MOD_LOGCONTV3(params, NDMP_LOG_WARNING,
		    "BASE_DATE is being used for this backup.\n");
	}

	tok = strtoll(basedate, &endp, 10);
	if (endp == basedate) {
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "Invalid BASE_DATE environment variable: \"%s\".\n",
		    basedate);
		return (NDMP_ILLEGAL_ARGS_ERR);
	}

	tstamp = tok & 0xffffffff;
	seq = (tok >> 32) & 0xffffffff;
	NDMP_LOG(LOG_DEBUG, "basedate \"%s\" %lld seq %u tstamp %u",
	    basedate, tok, seq, tstamp);

	if ((int)seq > ndmp_get_max_tok_seq()) {
		rv = NDMP_ILLEGAL_ARGS_ERR;
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "The sequence counter of the token exceeds the "
		    "maximum permitted value.\n");
		MOD_LOGCONTV3(params, NDMP_LOG_ERROR,
		    "Token sequence: %u, maxiumum value: %u.\n",
		    seq, ndmp_get_max_tok_seq());
	} else if (seq >= NDMP_TOKSEQ_HLIMIT) {
		rv = NDMP_ILLEGAL_ARGS_ERR;
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "The sequence counter the of token exceeds the "
		    "hard-limit.\n");
		MOD_LOGCONTV3(params, NDMP_LOG_ERROR,
		    "Token sequence: %u, hard-limit: %u.\n",
		    seq, NDMP_TOKSEQ_HLIMIT);
	} else {
		rv = NDMP_NO_ERR;
		/*
		 * Issue a warning if the seq is equal to the maximum
		 * permitted seq number or equal to the soft-limit.
		 */
		if (seq == NDMP_TOKSEQ_SLIMIT) {
			MOD_LOGV3(params, NDMP_LOG_WARNING,
			    "The sequence counter of the token has reached "
			    "the soft-limit.\n");
			MOD_LOGCONTV3(params, NDMP_LOG_WARNING,
			    "Token sequence: %u, soft-limit: %u.\n",
			    seq, NDMP_TOKSEQ_SLIMIT);
		} else if ((int)seq == ndmp_get_max_tok_seq()) {
			MOD_LOGV3(params, NDMP_LOG_WARNING,
			    "The sequence counter of the token has reached "
			    "the maximum permitted value.\n");
			MOD_LOGCONTV3(params, NDMP_LOG_WARNING,
			    "Token sequence: %u, maxiumum value: %u.\n",
			    seq, ndmp_get_max_tok_seq());
		}

		/*
		 * The current seq is equal to the seq field of the
		 * token.  It will be increased after successful backup
		 * before setting the DUMP_DATE environment variable.
		 */
		nlp->nlp_dmpnm = MOD_GETENV(params, "DMP_NAME");
		NLP_SET(nlp, NLPF_TOKENBK);
		NLP_UNSET(nlp, NLPF_LEVELBK);
		NLP_UNSET(nlp, NLPF_LBRBK);
		nlp->nlp_tokseq = seq;
		nlp->nlp_tokdate = tstamp;
		/*
		 * The value of nlp_cdate will be set to the checkpoint
		 * creation time after it is created.
		 */
	}

	return (rv);
}


/*
 * get_lbr_bk_v3
 *
 * Sets the level fields of the nlp structures for
 * LBR-type backup.  The NLPF_LBRBK flag of the
 * nlp flags is also set to show the backup type.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *   type (input) - the backup level: 'F', 'A', 'I', 'D' or
 *	their lower-case values.
 *
 * Returns:
 *   NDMP_NO_ERR: on success
 *   != NDMP_NO_ERR: Otherwise
 */
static ndmp_error
get_lbr_bk_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp, char *type)
{
	if (!params || !nlp || !type || !*type)
		return (NDMP_ILLEGAL_ARGS_ERR);

	NLP_SET(nlp, NLPF_LBRBK);
	NLP_UNSET(nlp, NLPF_TOKENBK);
	NLP_UNSET(nlp, NLPF_LEVELBK);
	nlp->nlp_dmpnm = MOD_GETENV(params, "DMP_NAME");
	nlp->nlp_llevel = toupper(*type);
	nlp->nlp_ldate = (time_t)0;
	nlp->nlp_clevel = nlp->nlp_llevel;
	(void) time(&nlp->nlp_cdate);

	return (NDMP_NO_ERR);
}


/*
 * get_backup_level_v3
 *
 * Gets the backup level from the environment variables.  If
 * BASE_DATE is specified, it will be used, otherwise LEVEL
 * will be used.  If neither is specified, LEVEL = '0' is
 * assumed.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   NDMP_NO_ERR: on success
 *   != NDMP_NO_ERR: Otherwise
 */
static ndmp_error
get_backup_level_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	char *envp;
	ndmp_error rv;

	/*
	 * If the BASE_DATE env variable is specified use it, otherwise
	 * look to see if LEVEL is specified.  If LEVEL is not
	 * specified either, backup level '0' must be made. Level backup
	 * does not clear the archive bit.
	 *
	 * If LEVEL environment varaible is specified, values for
	 * 'F', 'D', 'I' and 'A' (for 'Full', 'Differential',
	 * 'Incremental', and 'Archive' is checked first.  Then
	 * level '0' to '9' will be checked.
	 *
	 * LEVEL environment variable can hold only one character.
	 * If its length is longer than 1, an error is returned.
	 */
	envp = MOD_GETENV(params, "BASE_DATE");
	if (envp)
		return (get_date_token_v3(params, nlp, envp));


	envp = MOD_GETENV(params, "LEVEL");
	if (!envp) {
		NDMP_LOG(LOG_DEBUG, "env(LEVEL) not defined, default to 0");
		NLP_SET(nlp, NLPF_LEVELBK);
		NLP_UNSET(nlp, NLPF_LBRBK);
		NLP_UNSET(nlp, NLPF_TOKENBK);
		nlp->nlp_llevel = 0;
		nlp->nlp_ldate = 0;
		nlp->nlp_clevel = 0;
		/*
		 * The value of nlp_cdate will be set to the checkpoint
		 * creation time after it is created.
		 */
		return (NDMP_NO_ERR);
	}

	if (*(envp+1) != '\0') {
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "Invalid backup level \"%s\".\n", envp);
		return (NDMP_ILLEGAL_ARGS_ERR);
	}

	if (IS_LBR_BKTYPE(*envp))
		return (get_lbr_bk_v3(params, nlp, envp));

	if (!isdigit(*envp)) {
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "Invalid backup level \"%s\".\n", envp);
		return (NDMP_ILLEGAL_ARGS_ERR);
	}

	NLP_SET(nlp, NLPF_LEVELBK);
	NLP_UNSET(nlp, NLPF_LBRBK);
	NLP_UNSET(nlp, NLPF_TOKENBK);
	nlp->nlp_llevel = *envp - '0';
	nlp->nlp_ldate = 0;
	nlp->nlp_clevel = nlp->nlp_llevel;
	/*
	 * The value of nlp_cdate will be set to the checkpoint
	 * creation time after it is created.
	 */
	if (ndmpd_get_dumptime(nlp->nlp_backup_path, &nlp->nlp_llevel,
	    &nlp->nlp_ldate) < 0) {
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "Getting dumpdates for %s level '%c'.\n",
		    nlp->nlp_backup_path, *envp);
		return (NDMP_NO_MEM_ERR);
	} else {
		get_update_env_v3(params, nlp);
		rv = NDMP_NO_ERR;
	}

	return (rv);
}


/*
 * save_date_token_v3
 *
 * Make the value of DUMP_DATE env variable and append the values
 * of the current backup in the file specified with the DMP_NAME
 * env variable if any file is specified.  The file will be
 * relative name in the backup directory path.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   void
 */
static void
save_date_token_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	char val[QUAD_DECIMAL_LEN];
	u_longlong_t tok;

	if (!params || !nlp)
		return;

	nlp->nlp_tokseq++;
	tok = ((u_longlong_t)nlp->nlp_tokseq << 32) | nlp->nlp_cdate;
	(void) snprintf(val, sizeof (val), "%llu", tok);

	NDMP_LOG(LOG_DEBUG, "tok: %lld %s", tok, val);

	if (MOD_SETENV(params, "DUMP_DATE", val) != 0) {
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "Could not set DUMP_DATE to %s", val);
	} else if (!nlp->nlp_dmpnm) {
		NDMP_LOG(LOG_DEBUG, "No log file defined");
	} else if (ndmpd_append_dumptime(nlp->nlp_dmpnm, nlp->nlp_backup_path,
	    nlp->nlp_tokseq, nlp->nlp_tokdate) < 0) {
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "Saving backup date for \"%s\" in \"%s\".\n",
		    nlp->nlp_backup_path, nlp->nlp_dmpnm);
	}
}


/*
 * save_lbr_bk_v3
 *
 * Append the backup type and date in the DMP_NAME file for
 * LBR-type backup if any file is specified.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   void
 */
static void
save_lbr_bk_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	if (!params || !nlp)
		return;

	if (!nlp->nlp_dmpnm) {
		NDMP_LOG(LOG_DEBUG, "No log file defined");
	} else if (ndmpd_append_dumptime(nlp->nlp_dmpnm, nlp->nlp_backup_path,
	    nlp->nlp_clevel, nlp->nlp_cdate) < 0) {
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "Saving backup date for \"%s\" in \"%s\".\n",
		    nlp->nlp_backup_path, nlp->nlp_dmpnm);
	}
}


/*
 * save_level_v3
 *
 * Save the date and level of the current backup in the dumpdates
 * file.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   void
 */
static void
save_level_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	if (!params || !nlp)
		return;

	if (!NLP_SHOULD_UPDATE(nlp)) {
		NDMP_LOG(LOG_DEBUG, "update not requested");
	} else if (ndmpd_put_dumptime(nlp->nlp_backup_path, nlp->nlp_clevel,
	    nlp->nlp_cdate) < 0) {
		MOD_LOGV3(params, NDMP_LOG_ERROR, "Logging backup date.\n");
	}
}


/*
 * save_backup_date_v3
 *
 * A dispatcher function to call the corresponding save function
 * based on the backup type.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   void
 */
static void
save_backup_date_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	if (!params || !nlp)
		return;

	if (NLP_ISSET(nlp, NLPF_TOKENBK))
		save_date_token_v3(params, nlp);
	else if (NLP_ISSET(nlp, NLPF_LBRBK))
		save_lbr_bk_v3(params, nlp);
	else if (NLP_ISSET(nlp, NLPF_LEVELBK))
		save_level_v3(params, nlp);
	else {
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "Internal error: lost backup level type for \"%s\".\n",
		    nlp->nlp_backup_path);
	}
}


/*
 * backup_alloc_structs_v3
 *
 * Create the structures for V3 backup.  This includes:
 *	Job stats
 *	Reader writer IPC
 *	File history callback structure
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   jname (input) - name assigned to the current backup for
 *	job stats strucure
 *
 * Returns:
 *   0: on success
 *   -1: otherwise
 */
static int
backup_alloc_structs_v3(ndmpd_session_t *session, char *jname)
{
	int n;
	long xfer_size;
	ndmp_lbr_params_t *nlp;
	tlm_commands_t *cmds;

	nlp = ndmp_get_nlp(session);
	if (!nlp) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (-1);
	}

	nlp->nlp_jstat = tlm_new_job_stats(jname);
	if (!nlp->nlp_jstat) {
		NDMP_LOG(LOG_DEBUG, "Creating job stats");
		return (-1);
	}

	cmds = &nlp->nlp_cmds;
	(void) memset(cmds, 0, sizeof (*cmds));

	xfer_size = ndmp_buffer_get_size(session);
	if (xfer_size < 512*KILOBYTE) {
		/*
		 * Read multiple of mover_record_size near to 512K.  This
		 * will prevent the data being copied in the mover buffer
		 * when we write the data.
		 */
		n = 512 * KILOBYTE / xfer_size;
		if (n <= 0)
			n = 1;
		xfer_size *= n;
		NDMP_LOG(LOG_DEBUG, "Adjusted read size: %d",
		    xfer_size);
	}

	cmds->tcs_command = tlm_create_reader_writer_ipc(TRUE, xfer_size);
	if (!cmds->tcs_command) {
		tlm_un_ref_job_stats(jname);
		return (-1);
	}

	nlp->nlp_logcallbacks = lbrlog_callbacks_init(session,
	    ndmpd_fhpath_v3_cb, ndmpd_fhdir_v3_cb, ndmpd_fhnode_v3_cb);
	if (!nlp->nlp_logcallbacks) {
		tlm_release_reader_writer_ipc(cmds->tcs_command);
		tlm_un_ref_job_stats(jname);
		return (-1);
	}
	nlp->nlp_jstat->js_callbacks = (void *)(nlp->nlp_logcallbacks);
	nlp->nlp_restored = NULL;

	return (0);
}


/*
 * restore_alloc_structs_v3
 *
 * Create the structures for V3 Restore.  This includes:
 *	Job stats
 *	Reader writer IPC
 *	File recovery callback structure
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   jname (input) - name assigned to the current backup for
 *	job stats strucure
 *
 * Returns:
 *   0: on success
 *   -1: otherwise
 */
int
restore_alloc_structs_v3(ndmpd_session_t *session, char *jname)
{
	long xfer_size;
	ndmp_lbr_params_t *nlp;
	tlm_commands_t *cmds;

	nlp = ndmp_get_nlp(session);
	if (!nlp) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (-1);
	}

	/* this is used in ndmpd_path_restored_v3() */
	nlp->nlp_lastidx = -1;

	nlp->nlp_jstat = tlm_new_job_stats(jname);
	if (!nlp->nlp_jstat) {
		NDMP_LOG(LOG_DEBUG, "Creating job stats");
		return (-1);
	}

	cmds = &nlp->nlp_cmds;
	(void) memset(cmds, 0, sizeof (*cmds));

	xfer_size = ndmp_buffer_get_size(session);
	cmds->tcs_command = tlm_create_reader_writer_ipc(FALSE, xfer_size);
	if (!cmds->tcs_command) {
		tlm_un_ref_job_stats(jname);
		return (-1);
	}

	nlp->nlp_logcallbacks = lbrlog_callbacks_init(session,
	    ndmpd_path_restored_v3, NULL, NULL);
	if (!nlp->nlp_logcallbacks) {
		tlm_release_reader_writer_ipc(cmds->tcs_command);
		tlm_un_ref_job_stats(jname);
		return (-1);
	}
	nlp->nlp_jstat->js_callbacks = (void *)(nlp->nlp_logcallbacks);

	nlp->nlp_rsbm = bm_alloc(nlp->nlp_nfiles, 0);
	if (nlp->nlp_rsbm < 0) {
		NDMP_LOG(LOG_ERR, "Out of memory.");
		lbrlog_callbacks_done(nlp->nlp_logcallbacks);
		tlm_release_reader_writer_ipc(cmds->tcs_command);
		tlm_un_ref_job_stats(jname);
		return (-1);
	}

	return (0);
}


/*
 * free_structs_v3
 *
 * Release the resources allocated by backup_alloc_structs_v3
 * function.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   jname (input) - name assigned to the current backup for
 *	job stats strucure
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
static void
free_structs_v3(ndmpd_session_t *session, char *jname)
{
	ndmp_lbr_params_t *nlp;
	tlm_commands_t *cmds;

	nlp = ndmp_get_nlp(session);
	if (!nlp) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return;
	}
	cmds = &nlp->nlp_cmds;
	if (!cmds) {
		NDMP_LOG(LOG_DEBUG, "cmds == NULL");
		return;
	}

	if (nlp->nlp_logcallbacks) {
		lbrlog_callbacks_done(nlp->nlp_logcallbacks);
		nlp->nlp_logcallbacks = NULL;
	} else
		NDMP_LOG(LOG_DEBUG, "FH CALLBACKS == NULL");

	if (cmds->tcs_command) {
		if (cmds->tcs_command->tc_buffers != NULL)
			tlm_release_reader_writer_ipc(cmds->tcs_command);
		else
			NDMP_LOG(LOG_DEBUG, "BUFFERS == NULL");
		cmds->tcs_command = NULL;
	} else
		NDMP_LOG(LOG_DEBUG, "COMMAND == NULL");

	if (nlp->nlp_bkmap >= 0) {
		(void) dbm_free(nlp->nlp_bkmap);
		nlp->nlp_bkmap = -1;
	}

	if (session->ns_data.dd_operation == NDMP_DATA_OP_RECOVER) {
		if (nlp->nlp_rsbm < 0) {
			NDMP_LOG(LOG_DEBUG, "nlp_rsbm < 0 %d", nlp->nlp_rsbm);
		} else {
			(void) bm_free(nlp->nlp_rsbm);
			nlp->nlp_rsbm = -1;
		}
	}
}


/*
 * backup_dirv3
 *
 * Backup a directory and update the bytes processed field of the
 * data server.
 *
 * Parameters:
 *   bpp (input) - pointer to the backup parameters structure
 *   pnp (input) - pointer to the path node
 *   enp (input) - pointer to the entry node
 *
 * Returns:
 *   0: on success
 *   != 0: otherwise
 */
static int
backup_dirv3(bk_param_v3_t *bpp, fst_node_t *pnp,
    fst_node_t *enp)
{
	longlong_t apos, bpos;
	acl_t *aclp = NULL;
	char *acltp;
	struct stat64 st;
	char fullpath[TLM_MAX_PATH_NAME];
	char *p;

	if (!bpp || !pnp || !enp) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument");
		return (-1);
	}

	NDMP_LOG(LOG_DEBUG, "d(%s)", bpp->bp_tmp);

	if (lstat64(bpp->bp_tmp, &st) != 0)
		return (0);

	if (acl_get(bpp->bp_tmp, ACL_NO_TRIVIAL, &aclp) != 0) {
		NDMP_LOG(LOG_DEBUG, "acl_get error errno=%d", errno);
		return (-1);
	}
	if (aclp && (acltp = acl_totext(aclp,
	    ACL_APPEND_ID | ACL_SID_FMT | ACL_COMPACT_FMT)) != NULL) {
		(void) strlcpy(bpp->bp_tlmacl->acl_info.attr_info,
		    acltp, TLM_MAX_ACL_TXT);
		acl_free(aclp);
		free(acltp);
	} else {
		*bpp->bp_tlmacl->acl_info.attr_info = '\0';
	}

	bpos = tlm_get_data_offset(bpp->bp_lcmd);

	p = bpp->bp_tmp + strlen(bpp->bp_chkpnm);
	if (*p == '/')
		(void) snprintf(fullpath, TLM_MAX_PATH_NAME, "%s%s",
		    bpp->bp_unchkpnm, p);
	else
		(void) snprintf(fullpath, TLM_MAX_PATH_NAME, "%s/%s",
		    bpp->bp_unchkpnm, p);

	if (tm_tar_ops.tm_putdir != NULL)
		(void) (tm_tar_ops.tm_putdir)(fullpath, bpp->bp_tlmacl,
		    bpp->bp_lcmd, bpp->bp_js);

	apos = tlm_get_data_offset(bpp->bp_lcmd);
	bpp->bp_session->ns_data.dd_module.dm_stats.ms_bytes_processed +=
	    apos - bpos;

	return (0);
}


/*
 * backup_filev3
 *
 * Backup a file and update the bytes processed field of the
 * data server.
 *
 * Parameters:
 *   bpp (input) - pointer to the backup parameters structure
 *   pnp (input) - pointer to the path node
 *   enp (input) - pointer to the entry node
 *
 * Returns:
 *   0: on success
 *   != 0: otherwise
 */
static int
backup_filev3(bk_param_v3_t *bpp, fst_node_t *pnp,
    fst_node_t *enp)
{
	char *ent;
	longlong_t rv;
	longlong_t apos, bpos;
	acl_t *aclp = NULL;
	char *acltp;
	struct stat64 st;
	char fullpath[TLM_MAX_PATH_NAME];
	char *p;

	if (!bpp || !pnp || !enp) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument");
		return (-1);
	}

	NDMP_LOG(LOG_DEBUG, "f(%s)", bpp->bp_tmp);

	if (lstat64(bpp->bp_tmp, &st) != 0)
		return (0);

	if (!S_ISLNK(bpp->bp_tlmacl->acl_attr.st_mode)) {
		if (acl_get(bpp->bp_tmp, ACL_NO_TRIVIAL, &aclp) != 0) {
			NDMP_LOG(LOG_DEBUG, "acl_get error");
			return (-1);
		}

		if (aclp &&
		    (acltp = acl_totext(aclp,
		    ACL_APPEND_ID | ACL_SID_FMT | ACL_COMPACT_FMT)) != NULL) {
			(void) strlcpy(bpp->bp_tlmacl->acl_info.attr_info,
			    acltp, TLM_MAX_ACL_TXT);
			acl_free(aclp);
			free(acltp);
		} else {
			*bpp->bp_tlmacl->acl_info.attr_info = '\0';
		}
	}

	bpos = tlm_get_data_offset(bpp->bp_lcmd);
	ent = enp->tn_path ? enp->tn_path : "";

	p = pnp->tn_path + strlen(bpp->bp_chkpnm);
	if (*p == '/')
		(void) snprintf(fullpath, TLM_MAX_PATH_NAME, "%s%s",
		    bpp->bp_unchkpnm, p);
	else
		(void) snprintf(fullpath, TLM_MAX_PATH_NAME, "%s/%s",
		    bpp->bp_unchkpnm, p);

	if (tm_tar_ops.tm_putfile != NULL)
		rv = (tm_tar_ops.tm_putfile)(fullpath, ent, pnp->tn_path,
		    bpp->bp_tlmacl, bpp->bp_cmds, bpp->bp_lcmd, bpp->bp_js,
		    bpp->bp_session->hardlink_q);

	apos = tlm_get_data_offset(bpp->bp_lcmd);
	bpp->bp_session->ns_data.dd_module.dm_stats.ms_bytes_processed +=
	    apos - bpos;

	return (rv < 0 ? rv : 0);
}


/*
 * check_bk_args
 *
 * Check the argument of the bpp.  This is shared function between
 * timebk_v3 and lbrbk_v3 functions.  The checks include:
 *	- The bpp itself.
 *	- If the session pointer of the bpp is valid.
 *	- If the session connection to the DMA is closed.
 *	- If the nlp pointer of the bpp is valid.
 *	- If the backup is aborted.
 *
 * Parameters:
 *   bpp (input) - pointer to the backup parameters structure
 *
 * Returns:
 *   0: if everything's OK
 *   != 0: otherwise
 */
static int
check_bk_args(bk_param_v3_t *bpp)
{
	int rv;

	if (!bpp) {
		rv = -1;
		NDMP_LOG(LOG_DEBUG, "Lost bpp");
	} else if (!bpp->bp_session) {
		rv = -1;
		NDMP_LOG(LOG_DEBUG, "Session is NULL");
	} else if (bpp->bp_session->ns_eof) {
		rv = -1;
		NDMP_LOG(LOG_INFO,
		    "Connection client is closed for backup \"%s\"",
		    bpp->bp_nlp->nlp_backup_path);
	} else if (!bpp->bp_nlp) {
		NDMP_LOG(LOG_DEBUG, "Lost nlp");
		return (-1);
	} else if (bpp->bp_session->ns_data.dd_abort) {
		rv = -1;
		NDMP_LOG(LOG_INFO, "Backup aborted \"%s\"",
		    bpp->bp_nlp->nlp_backup_path);
	} else
		rv = 0;

	return (rv);
}


/*
 * shouldskip
 *
 * Determines if the current entry should be skipped or it
 * should be backed up.
 *
 * Parameters:
 *   bpp (input) - pointer to the backup parameters structure
 *   pnp (input) - pointer to the path node
 *   enp (input) - pointer to the entry node
 *   errp (output) - pointer to the error value that should be
 *	returned by the caller
 *
 * Returns:
 *   TRUE: if the entry should not be backed up
 *   FALSE: otherwise
 */
static boolean_t
shouldskip(bk_param_v3_t *bpp, fst_node_t *pnp,
    fst_node_t *enp, int *errp)
{
	char *ent;
	boolean_t rv;
	struct stat64 *estp;

	if (!bpp || !pnp || !enp || !errp) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument");
		return (TRUE);
	}

	if (!enp->tn_path) {
		ent = "";
		estp = pnp->tn_st;
	} else {
		ent = enp->tn_path;
		estp = enp->tn_st;
	}

	/*
	 * When excluding or skipping entries, FST_SKIP should be
	 * returned, otherwise, 0 should be returned to
	 * get other entries in the directory of this entry.
	 */
	if (!dbm_getone(bpp->bp_nlp->nlp_bkmap, (u_longlong_t)estp->st_ino)) {
		rv = TRUE;
		*errp = S_ISDIR(estp->st_mode) ? FST_SKIP : 0;
		NDMP_LOG(LOG_DEBUG, "Skipping %d %s/%s",
		    *errp, pnp->tn_path, ent);
	} else if (tlm_is_excluded(pnp->tn_path, ent, bpp->bp_excls)) {
		rv = TRUE;
		*errp = S_ISDIR(estp->st_mode) ? FST_SKIP : 0;
		NDMP_LOG(LOG_DEBUG, "excl %d \"%s/%s\"",
		    *errp, pnp->tn_path, ent);
	} else if (inexl(bpp->bp_nlp->nlp_exl, ent)) {
		rv = TRUE;
		*errp = S_ISDIR(estp->st_mode) ? FST_SKIP : 0;
		NDMP_LOG(LOG_DEBUG, "out %d \"%s/%s\"",
		    *errp, pnp->tn_path, ent);
	} else if (!S_ISDIR(estp->st_mode) &&
	    !ininc(bpp->bp_nlp->nlp_inc, ent)) {
		rv = TRUE;
		*errp = 0;
		NDMP_LOG(LOG_DEBUG, "!in \"%s/%s\"", pnp->tn_path, ent);
	} else
		rv = FALSE;

	return (rv);
}


/*
 * ischngd
 *
 * Check if the object specified should be backed up or not.
 * If stp belongs to a directory and if it is marked in the
 * bitmap vector, it shows that either the directory itself is
 * modified or there is something below it that will be backed
 * up.
 *
 * By setting ndmp_force_bk_dirs global variable to a non-zero
 * value, directories are backed up anyways.
 *
 * Backing up the directories unconditionally helps
 * restoring the metadata of directories as well, when one
 * of the objects below them are being restored.
 *
 * For non-directory objects, if the modification or change
 * time of the object is after the date specified by the
 * bk_selector_t, the the object must be backed up.
 */
static boolean_t
ischngd(struct stat64 *stp, time_t t, ndmp_lbr_params_t *nlp)
{
	boolean_t rv;

	if (!stp) {
		rv = FALSE;
		NDMP_LOG(LOG_DEBUG, "stp is NULL");
	} else if (!nlp) {
		rv = FALSE;
		NDMP_LOG(LOG_DEBUG, "nlp is NULL");
	} else if (t == 0) {
		/*
		 * if we are doing base backup then we do not need to
		 * check the time, for we should backup everything.
		 */
		rv = TRUE;
		NDMP_LOG(LOG_DEBUG, "Base Backup");
	} else if (S_ISDIR(stp->st_mode) && ndmp_force_bk_dirs) {
		rv = TRUE;
		NDMP_LOG(LOG_DEBUG, "d(%lu)", (uint_t)stp->st_ino);
	} else if (S_ISDIR(stp->st_mode) &&
	    dbm_getone(nlp->nlp_bkmap, (u_longlong_t)stp->st_ino) &&
	    ((NLP_ISDUMP(nlp) && ndmp_dump_path_node) ||
	    (NLP_ISTAR(nlp) && ndmp_tar_path_node))) {
		/*
		 * If the object is a directory and it leads to a modified
		 * object (that should be backed up) and for that type of
		 * backup the path nodes should be backed up, then return
		 * TRUE.
		 *
		 * This is required by some DMAs like Backup Express, which
		 * needs to receive ADD_NODE (for dump) or ADD_PATH (for tar)
		 * for the intermediate directories of a modified object.
		 * Other DMAs, like net_backup and net_worker, do not have such
		 * requirement.  This requirement makes sense for dump format
		 * but for 'tar' format, it does not.  In provision to the
		 * NDMP-v4 spec, for 'tar' format the intermediate directories
		 * need not to be reported.
		 */
		rv = TRUE;
		NDMP_LOG(LOG_DEBUG, "p(%lu)", (u_longlong_t)stp->st_ino);
	} else if (stp->st_mtime > t) {
		rv = TRUE;
		NDMP_LOG(LOG_DEBUG, "m(%lu): %lu > %lu",
		    (uint_t)stp->st_ino, (uint_t)stp->st_mtime, (uint_t)t);
	} else if (stp->st_ctime > t) {
		if (NLP_IGNCTIME(nlp)) {
			rv = FALSE;
			NDMP_LOG(LOG_DEBUG, "ign c(%lu): %lu > %lu",
			    (uint_t)stp->st_ino, (uint_t)stp->st_ctime,
			    (uint_t)t);
		} else {
			rv = TRUE;
			NDMP_LOG(LOG_DEBUG, "c(%lu): %lu > %lu",
			    (uint_t)stp->st_ino, (uint_t)stp->st_ctime,
			    (uint_t)t);
		}
	} else {
		rv = FALSE;
		NDMP_LOG(LOG_DEBUG, "mc(%lu): (%lu,%lu) < %lu",
		    (uint_t)stp->st_ino, (uint_t)stp->st_mtime,
		    (uint_t)stp->st_ctime, (uint_t)t);
	}

	return (rv);
}


/*
 * iscreated
 *
 * This function is used to check last mtime (currently inside the ACL
 * structure) instead of ctime for checking if the file is to be backed up
 * or not. See option "inc.lmtime" for more details
 */
/*ARGSUSED*/
int iscreated(ndmp_lbr_params_t *nlp, char *name, tlm_acls_t *tacl,
    time_t t)
{
	int ret;
	acl_t *aclp = NULL;
	char *acltp;

	NDMP_LOG(LOG_DEBUG, "flags %x", nlp->nlp_flags);
	if (NLP_INCLMTIME(nlp) == FALSE)
		return (0);

	ret = acl_get(name, ACL_NO_TRIVIAL, &aclp);
	if (ret != 0) {
		NDMP_LOG(LOG_DEBUG,
		    "Error getting the acl information: err %d", ret);
		return (0);
	}
	if (aclp && (acltp = acl_totext(aclp,
	    ACL_APPEND_ID | ACL_SID_FMT | ACL_COMPACT_FMT)) != NULL) {
		(void) strlcpy(tacl->acl_info.attr_info, acltp,
		    TLM_MAX_ACL_TXT);
		acl_free(aclp);
		free(acltp);
	}

	/* Need to add support for last mtime */

	return (0);
}

/*
 * size_cb
 *
 * The callback function for calculating the size of
 * the backup path. This is used to get an estimate
 * of the progress of backup during NDMP backup
 */
static int
size_cb(void *arg, fst_node_t *pnp, fst_node_t *enp)
{
	struct stat64 *stp;

	stp = enp->tn_path ? enp->tn_st : pnp->tn_st;
	*((u_longlong_t *)arg) += stp->st_size;

	return (0);
}

/*
 * timebk_v3
 *
 * The callback function for backing up objects based on
 * their time stamp.  This is shared between token-based
 * and level-based backup, which look at the time stamps
 * of the objects to determine if they should be backed
 * up.
 *
 * Parameters:
 *   arg (input) - pointer to the backup parameters structure
 *   pnp (input) - pointer to the path node
 *   enp (input) - pointer to the entry node
 *
 * Returns:
 *   0: if backup should continue
 *   -1: if the backup should be stopped
 *   FST_SKIP: if backing up the current directory is enough
 */
static int
timebk_v3(void *arg, fst_node_t *pnp, fst_node_t *enp)
{
	char *ent;
	int rv;
	time_t t;
	bk_param_v3_t *bpp;
	struct stat64 *stp;
	fs_fhandle_t *fhp;

	bpp = (bk_param_v3_t *)arg;

	rv = check_bk_args(bpp);
	if (rv != 0)
		return (rv);

	stp = enp->tn_path ? enp->tn_st : pnp->tn_st;
	if (shouldskip(bpp, pnp, enp, &rv))
		return (rv);

	if (enp->tn_path) {
		ent = enp->tn_path;
		stp = enp->tn_st;
		fhp = enp->tn_fh;
	} else {
		ent = "";
		stp = pnp->tn_st;
		fhp = pnp->tn_fh;
	}


	if (!tlm_cat_path(bpp->bp_tmp, pnp->tn_path, ent)) {
		NDMP_LOG(LOG_ERR, "Path too long %s/%s.", pnp->tn_path, ent);
		return (FST_SKIP);
	}
	if (NLP_ISSET(bpp->bp_nlp, NLPF_TOKENBK))
		t = bpp->bp_nlp->nlp_tokdate;
	else if (NLP_ISSET(bpp->bp_nlp, NLPF_LEVELBK)) {
		t = bpp->bp_nlp->nlp_ldate;
	} else {
		NDMP_LOG(LOG_DEBUG, "Unknown backup type on \"%s/%s\"",
		    pnp->tn_path, ent);
		return (-1);
	}

	if (S_ISDIR(stp->st_mode)) {
		bpp->bp_tlmacl->acl_dir_fh = *fhp;
		(void) ndmpd_fhdir_v3_cb(bpp->bp_nlp->nlp_logcallbacks,
		    bpp->bp_tmp, stp);

		if (ischngd(stp, t, bpp->bp_nlp)) {
			(void) memcpy(&bpp->bp_tlmacl->acl_attr, stp,
			    sizeof (struct stat64));
			rv = backup_dirv3(bpp, pnp, enp);
		}
	} else {
		if (ischngd(stp, t, bpp->bp_nlp) ||
		    iscreated(bpp->bp_nlp, bpp->bp_tmp, bpp->bp_tlmacl, t)) {
			rv = 0;
			(void) memcpy(&bpp->bp_tlmacl->acl_attr, stp,
			    sizeof (struct stat64));
			bpp->bp_tlmacl->acl_fil_fh = *fhp;
			(void) backup_filev3(bpp, pnp, enp);
		}
	}

	return (rv);
}


/*
 * lbrbk_v3
 *
 * The callback function for backing up objects based on
 * their archive directory bit.  This is used in LBR-type
 * backup.  In which the objects are backed up if their
 * archive bit is set.
 *
 * Parameters:
 *   arg (input) - pointer to the backup parameters structure
 *   pnp (input) - pointer to the path node
 *   enp (input) - pointer to the entry node
 *
 * Returns:
 *   0: if backup should continue
 *   -1: if the backup should be stopped
 *   FST_SKIP: if backing up the current directory is enough
 */
static int
lbrbk_v3(void *arg, fst_node_t *pnp, fst_node_t *enp)
{
	char *ent;
	int rv;
	bk_param_v3_t *bpp;
	struct stat64 *stp;
	fs_fhandle_t *fhp;

	bpp = (bk_param_v3_t *)arg;
	rv = check_bk_args(bpp);
	if (rv != 0)
		return (rv);

	stp = enp->tn_path ? enp->tn_st : pnp->tn_st;
	if (shouldskip(bpp, pnp, enp, &rv))
		return (rv);

	if (enp->tn_path) {
		ent = enp->tn_path;
		stp = enp->tn_st;
		fhp = enp->tn_fh;
	} else {
		ent = "";
		stp = pnp->tn_st;
		fhp = pnp->tn_fh;
	}

	if (!tlm_cat_path(bpp->bp_tmp, pnp->tn_path, ent)) {
		NDMP_LOG(LOG_ERR, "Path too long %s/%s.", pnp->tn_path, ent);
		return (FST_SKIP);
	}
	if (!NLP_ISSET(bpp->bp_nlp, NLPF_LBRBK)) {
		NDMP_LOG(LOG_DEBUG, "!NLPF_LBRBK");
		return (-1);
	}

	if (S_ISDIR(stp->st_mode)) {
		bpp->bp_tlmacl->acl_dir_fh = *fhp;
		(void) ndmpd_fhdir_v3_cb(bpp->bp_nlp->nlp_logcallbacks,
		    bpp->bp_tmp, stp);

		if (SHOULD_LBRBK(bpp)) {
			bpp->bp_tlmacl->acl_attr = *stp;
			rv = backup_dirv3(bpp, pnp, enp);
		}
	} else if (SHOULD_LBRBK(bpp)) {
		rv = 0;
		bpp->bp_tlmacl->acl_attr = *stp;
		bpp->bp_tlmacl->acl_fil_fh = *fhp;
		(void) backup_filev3(bpp, pnp, enp);
	}

	return (rv);
}


/*
 * backup_reader_v3
 *
 * The reader thread for the backup.  It sets up the callback
 * parameters and traverses the backup hierarchy in level-order
 * way.
 *
 * Parameters:
 *   jname (input) - name assigned to the current backup for
 *	job stats strucure
 *   nlp (input) - pointer to the nlp structure
 *   cmds (input) - pointer to the tlm_commands_t structure
 *
 * Returns:
 *   0: on success
 *   != 0: otherwise
 */
static int
backup_reader_v3(backup_reader_arg_t *argp)
{
	int rv;
	tlm_cmd_t *lcmd;
	tlm_acls_t tlm_acls;
	longlong_t bpos, n;
	bk_param_v3_t bp;
	fs_traverse_t ft;
	char *jname;
	ndmp_lbr_params_t *nlp;
	tlm_commands_t *cmds;

	if (!argp)
		return (-1);

	jname = argp->br_jname;
	nlp = argp->br_nlp;
	cmds = argp->br_cmds;

	rv = 0;
	lcmd = cmds->tcs_command;
	lcmd->tc_ref++;
	cmds->tcs_reader_count++;

	(void) memset(&tlm_acls, 0, sizeof (tlm_acls));

	/* NDMP parameters */
	bp.bp_session = nlp->nlp_session;
	bp.bp_nlp = nlp;

	/* LBR-related parameters  */
	bp.bp_js = tlm_ref_job_stats(jname);
	bp.bp_cmds = cmds;
	bp.bp_lcmd = lcmd;
	bp.bp_tlmacl = &tlm_acls;
	bp.bp_opr = 0;

	/* release the parent thread, after referencing the job stats */
	(void) pthread_barrier_wait(&argp->br_barrier);

	bp.bp_tmp = ndmp_malloc(sizeof (char) * TLM_MAX_PATH_NAME);
	if (!bp.bp_tmp)
		return (-1);

	/*
	 * Make the checkpointed paths for traversing the
	 * backup hierarchy, if we make the checkpoint.
	 */
	bp.bp_unchkpnm = nlp->nlp_backup_path;
	if (!NLP_ISCHKPNTED(nlp)) {
		tlm_acls.acl_checkpointed = TRUE;
		bp.bp_chkpnm = ndmp_malloc(sizeof (char) * TLM_MAX_PATH_NAME);
		if (!bp.bp_chkpnm) {
			NDMP_FREE(bp.bp_tmp);
			return (-1);
		}
		(void) tlm_build_snapshot_name(nlp->nlp_backup_path,
		    bp.bp_chkpnm, nlp->nlp_jstat->js_job_name);
	} else {
		tlm_acls.acl_checkpointed = FALSE;
		bp.bp_chkpnm = nlp->nlp_backup_path;
	}
	bp.bp_excls = ndmpd_make_exc_list();

	/* set traversing arguments */
	ft.ft_path = nlp->nlp_backup_path;
	ft.ft_lpath = bp.bp_chkpnm;

	NDMP_LOG(LOG_DEBUG, "path %s lpath %s", ft.ft_path, ft.ft_lpath);
	if (NLP_ISSET(nlp, NLPF_TOKENBK) || NLP_ISSET(nlp, NLPF_LEVELBK)) {
		ft.ft_callbk = timebk_v3;
		tlm_acls.acl_clear_archive = FALSE;
	} else if (NLP_ISSET(nlp, NLPF_LBRBK)) {
		ft.ft_callbk = lbrbk_v3;
		tlm_acls.acl_clear_archive = FALSE;

		NDMP_LOG(LOG_DEBUG, "bp_opr %x clr_arc %c",
		    bp.bp_opr, NDMP_YORN(tlm_acls.acl_clear_archive));
	} else {
		rv = -1;
		MOD_LOGV3(nlp->nlp_params, NDMP_LOG_ERROR,
		    "Unknow backup type.\n");
	}
	ft.ft_arg = &bp;
	ft.ft_logfp = (ft_log_t)ndmp_log;
	ft.ft_flags = FST_VERBOSE | FST_STOP_ONERR;

	/* take into account the header written to the stream so far */
	n = tlm_get_data_offset(lcmd);
	nlp->nlp_session->ns_data.dd_module.dm_stats.ms_bytes_processed = n;

	if (rv == 0) {
		/* start traversing the hierarchy and actual backup */
		rv = traverse_level(&ft);
		if (rv == 0) {
			/* write the trailer and update the bytes processed */
			bpos = tlm_get_data_offset(lcmd);
			(void) write_tar_eof(lcmd);
			n = tlm_get_data_offset(lcmd) - bpos;
			nlp->nlp_session->
			    ns_data.dd_module.dm_stats.ms_bytes_processed += n;
		} else {
			MOD_LOGV3(nlp->nlp_params, NDMP_LOG_ERROR,
			    "Filesystem traverse error.\n");
			ndmpd_data_error(nlp->nlp_session,
			    NDMP_DATA_HALT_INTERNAL_ERROR);
		}
	}

	if (!NLP_ISCHKPNTED(nlp))
		NDMP_FREE(bp.bp_chkpnm);
	NDMP_FREE(bp.bp_tmp);
	NDMP_FREE(bp.bp_excls);

	cmds->tcs_reader_count--;
	lcmd->tc_writer = TLM_STOP;
	tlm_release_reader_writer_ipc(lcmd);
	tlm_un_ref_job_stats(jname);
	return (rv);

}


/*
 * tar_backup_v3
 *
 * Traverse the backup hierarchy if needed and make the bitmap.
 * Then launch reader and writer threads to do the actual backup.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *   jname (input) - job name
 *
 * Returns:
 *   0: on success
 *   != 0: otherwise
 */
static int
tar_backup_v3(ndmpd_session_t *session, ndmpd_module_params_t *params,
    ndmp_lbr_params_t *nlp, char *jname)
{
	tlm_commands_t *cmds;
	backup_reader_arg_t arg;
	pthread_t rdtp;
	char info[256];
	int result;
	ndmp_context_t nctx;
	int err;

	if (ndmp_get_bk_dir_ino(nlp))
		return (-1);

	result = err = 0;

	/* exit as if there was an internal error */
	if (session->ns_eof)
		return (-1);

	if (!session->ns_data.dd_abort) {
		if (backup_alloc_structs_v3(session, jname) < 0) {
			nlp->nlp_bkmap = -1;
			return (-1);
		}

		if (ndmpd_mark_inodes_v3(session, nlp) != 0) {
			if (nlp->nlp_bkmap != -1) {
				(void) dbm_free(nlp->nlp_bkmap);
				nlp->nlp_bkmap = -1;
			}
			free_structs_v3(session, jname);
			return (-1);
		}

		nlp->nlp_jstat->js_start_ltime = time(NULL);
		nlp->nlp_jstat->js_start_time = nlp->nlp_jstat->js_start_ltime;
		nlp->nlp_jstat->js_chkpnt_time = nlp->nlp_cdate;

		cmds = &nlp->nlp_cmds;
		cmds->tcs_reader = cmds->tcs_writer = TLM_BACKUP_RUN;
		cmds->tcs_command->tc_reader = TLM_BACKUP_RUN;
		cmds->tcs_command->tc_writer = TLM_BACKUP_RUN;

		if (ndmp_write_utf8magic(cmds->tcs_command) < 0) {
			free_structs_v3(session, jname);
			return (-1);
		}

		NDMP_LOG(LOG_DEBUG,
		    "Backing up \"%s\" started.", nlp->nlp_backup_path);

		/* Plug-in module */
		if (ndmp_pl != NULL &&
		    ndmp_pl->np_pre_backup != NULL) {
			(void) memset(&nctx, 0, sizeof (ndmp_context_t));
			nctx.nc_plversion = ndmp_pl->np_plversion;
			nctx.nc_plname = ndmpd_get_prop(NDMP_PLUGIN_PATH);
			nctx.nc_cmds = cmds;
			nctx.nc_params = params;
			nctx.nc_ddata = (void *) session;
			if ((err = ndmp_pl->np_pre_backup(ndmp_pl, &nctx,
			    nlp->nlp_backup_path)) != 0) {
				NDMP_LOG(LOG_ERR, "Pre-backup plug-in: %m");
				goto backup_out;
			}
		}

		(void) memset(&arg, 0, sizeof (backup_reader_arg_t));
		arg.br_jname = jname;
		arg.br_nlp = nlp;
		arg.br_cmds = cmds;

		(void) pthread_barrier_init(&arg.br_barrier, 0, 2);

		err = pthread_create(&rdtp, NULL, (funct_t)backup_reader_v3,
		    (void *)&arg);
		if (err == 0) {
			(void) pthread_barrier_wait(&arg.br_barrier);
			(void) pthread_barrier_destroy(&arg.br_barrier);
		} else {
			(void) pthread_barrier_destroy(&arg.br_barrier);
			free_structs_v3(session, jname);
			NDMP_LOG(LOG_DEBUG, "Launch backup_reader_v3: %m");
			return (-1);
		}

		if ((err = ndmp_tar_writer(session, params, cmds)) != 0)
			result = EIO;

		nlp->nlp_jstat->js_stop_time = time(NULL);

		(void) snprintf(info, sizeof (info),
		    "Runtime [%s] %llu bytes (%llu): %d seconds\n",
		    nlp->nlp_backup_path,
		    session->ns_data.dd_module.dm_stats.ms_bytes_processed,
		    session->ns_data.dd_module.dm_stats.ms_bytes_processed,
		    nlp->nlp_jstat->js_stop_time -
		    nlp->nlp_jstat->js_start_ltime);
		MOD_LOGV3(params, NDMP_LOG_NORMAL, info);

		ndmp_wait_for_reader(cmds);
		(void) pthread_join(rdtp, NULL);

		/* exit as if there was an internal error */
		if (session->ns_eof) {
			result = EPIPE;
			err = -1;
		}
		if (!session->ns_data.dd_abort) {
			ndmpd_audit_backup(session->ns_connection,
			    nlp->nlp_backup_path,
			    session->ns_data.dd_data_addr.addr_type,
			    session->ns_tape.td_adapter_name, result);
			NDMP_LOG(LOG_DEBUG, "Backing up \"%s\" Finished.",
			    nlp->nlp_backup_path);
		}
	}

	if (session->ns_data.dd_abort) {
		ndmpd_audit_backup(session->ns_connection,
		    nlp->nlp_backup_path,
		    session->ns_data.dd_data_addr.addr_type,
		    session->ns_tape.td_adapter_name, EINTR);
		NDMP_LOG(LOG_DEBUG,
		    "Backing up \"%s\" aborted.", nlp->nlp_backup_path);
		err = -1;
	} else {

backup_out:
		/* Plug-in module */
		if (ndmp_pl != NULL &&
		    ndmp_pl->np_post_backup != NULL &&
		    ndmp_pl->np_post_backup(ndmp_pl, &nctx, err) == -1) {
			NDMP_LOG(LOG_DEBUG, "Post-backup plug-in: %m");
			return (-1);
		}
	}

	free_structs_v3(session, jname);
	return (err);
}

/*
 * get_backup_size
 *
 * Find the estimate of backup size. This is used to get an estimate
 * of the progress of backup during NDMP backup.
 */
void
get_backup_size(ndmp_bkup_size_arg_t *sarg)
{
	fs_traverse_t ft;
	u_longlong_t bk_size;
	char spath[PATH_MAX];
	int rv;

	bk_size = 0;
	if (fs_is_chkpntvol(sarg->bs_path)) {
		ft.ft_path = sarg->bs_path;
	} else {
		(void) tlm_build_snapshot_name(sarg->bs_path,
		    spath, sarg->bs_jname);
		ft.ft_path = spath;
	}

	ft.ft_lpath = ft.ft_path;
	ft.ft_callbk = size_cb;
	ft.ft_arg = &bk_size;
	ft.ft_logfp = (ft_log_t)ndmp_log;
	ft.ft_flags = FST_VERBOSE;

	if ((rv = traverse_level(&ft)) != 0) {
		NDMP_LOG(LOG_DEBUG, "bksize err=%d", rv);
		bk_size = 0;
	} else {
		NDMP_LOG(LOG_DEBUG, "bksize %lld, %lldKB, %lldMB\n",
		    bk_size, bk_size / 1024, bk_size /(1024 * 1024));
	}
	sarg->bs_session->ns_data.dd_data_size = bk_size;
}

/*
 * get_rs_path_v3
 *
 * Find the restore path
 */
ndmp_error
get_rs_path_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	char *dp;
	ndmp_error rv;
	mem_ndmp_name_v3_t *ep;
	int i, nm_cnt;
	char *nm_dpath_list[MULTIPLE_DEST_DIRS];
	static char mdest_buf[256];

	*mdest_buf = 0;
	*nm_dpath_list = "";
	for (i = 0, nm_cnt = 0; i < (int)nlp->nlp_nfiles; i++) {
		ep = (mem_ndmp_name_v3_t *)MOD_GETNAME(params, i);
		if (!ep) {
			NDMP_LOG(LOG_DEBUG, "Can't get Nlist[%d]", i);
			return (NDMP_ILLEGAL_ARGS_ERR);
		}
		if (strcmp(nm_dpath_list[nm_cnt], ep->nm3_dpath) != 0 &&
		    nm_cnt < MULTIPLE_DEST_DIRS - 1)
			nm_dpath_list[++nm_cnt] = ep->nm3_dpath;
	}

	multiple_dest_restore = (nm_cnt > 1);
	nlp->nlp_restore_path = mdest_buf;

	for (i = 1; i < nm_cnt + 1; i++) {
		if (ISDEFINED(nm_dpath_list[i]))
			dp = nm_dpath_list[i];
		else
			/* the default destination path is backup directory */
			dp = nlp->nlp_backup_path;

		/* check the destination directory exists and is writable */
		if (!fs_volexist(dp)) {
			rv = NDMP_ILLEGAL_ARGS_ERR;
			MOD_LOGV3(params, NDMP_LOG_ERROR,
			    "Invalid destination path volume \"%s\".\n", dp);
		} else if (!voliswr(dp)) {
			rv = NDMP_ILLEGAL_ARGS_ERR;
			MOD_LOGV3(params, NDMP_LOG_ERROR,
			    "The destination path volume"
			    " is not writable \"%s\".\n", dp);
		} else {
			rv = NDMP_NO_ERR;
			(void) strlcat(nlp->nlp_restore_path, dp,
			    sizeof (mdest_buf));
			NDMP_LOG(LOG_DEBUG, "rspath: \"%s\"", dp);
		}

		/*
		 * Exit if there is an error or it is not a multiple
		 * destination restore mode
		 */
		if (rv != NDMP_NO_ERR || !multiple_dest_restore)
			break;

		if (i < nm_cnt)
			(void) strlcat(nlp->nlp_restore_path, ", ",
			    sizeof (mdest_buf));
	}

	return (rv);
}


/*
 * fix_nlist_v3
 *
 * Check if the recovery list is valid and fix it if there are some
 * unspecified entries in it. It checks for original, destination
 * and new path for all NDMP names provided inside the list.
 *
 * V3: dpath is the destination directory.  If newnm is not NULL, the
 * destination path is dpath/newnm.  Otherwise the destination path is
 * dpath/opath_last_node, where opath_last_node is the last node in opath.
 *
 * V4: If newnm is not NULL, dpath is the destination directory, and
 * dpath/newnm is the destination path.  If newnm is NULL, dpath is
 * the destination path (opath is not involved in forming destination path).
 */
ndmp_error
fix_nlist_v3(ndmpd_session_t *session, ndmpd_module_params_t *params,
    ndmp_lbr_params_t *nlp)
{
	char *cp, *buf, *bp;
	int i, n;
	int iswrbk;
	int bvexists;
	ndmp_error rv;
	mem_ndmp_name_v3_t *ep;
	char *dp;
	char *nm;
	int existsvol;
	int isrwdst;

	buf = ndmp_malloc(TLM_MAX_PATH_NAME);
	if (!buf) {
		MOD_LOGV3(params, NDMP_LOG_ERROR, "Insufficient memory.\n");
		return (NDMP_NO_MEM_ERR);
	}

	bvexists = fs_volexist(nlp->nlp_backup_path);
	iswrbk = voliswr(nlp->nlp_backup_path);

	rv = NDMP_NO_ERR;
	n = session->ns_data.dd_nlist_len;
	for (i = 0; i < n; i++) {
		ep = (mem_ndmp_name_v3_t *)MOD_GETNAME(params, i);
		if (!ep)
			continue;

		/* chop off the trailing slashes */
		chopslash(ep->nm3_opath);

		chopslash(ep->nm3_dpath);
		chopslash(ep->nm3_newnm);

		/* existing and non-empty destination path */
		if (ISDEFINED(ep->nm3_dpath)) {
			dp = ep->nm3_dpath;
			existsvol = fs_volexist(dp);
			isrwdst = voliswr(dp);
		} else {
			/* the default destination path is backup directory */
			dp = nlp->nlp_backup_path;
			existsvol = bvexists;
			isrwdst = iswrbk;
		}

		/* check the destination directory exists and is writable */
		if (!existsvol) {
			rv = NDMP_ILLEGAL_ARGS_ERR;
			MOD_LOGV3(params, NDMP_LOG_ERROR,
			    "Invalid destination path volume "
			    "\"%s\".\n", dp);
			break;
		}
		if (!isrwdst) {
			rv = NDMP_ILLEGAL_ARGS_ERR;
			MOD_LOGV3(params, NDMP_LOG_ERROR,
			    "The destination path volume is not "
			    "writable \"%s\".\n", dp);
			break;
		}

		/*
		 * If new name is not specified, the default new name is
		 * the last component of the original path, if any
		 * (except in V4).
		 */
		if (ISDEFINED(ep->nm3_newnm)) {
			nm = ep->nm3_newnm;
		} else {
			char *p, *q;

			/*
			 * Find the last component of nm3_opath.
			 * nm3_opath has no trailing '/'.
			 */
			p = strrchr(ep->nm3_opath, '/');
			nm = p ? p + 1 : ep->nm3_opath;

			/*
			 * In DDAR the last component could
			 * be repeated in nm3_dpath
			 */
			q = strrchr(ep->nm3_dpath, '/');
			q = q ? q + 1 : ep->nm3_dpath;
			if (strcmp(nm, q) == 0)
				nm = NULL;

		}

		bp = joinpath(buf, dp, nm);
		if (!bp) {
			/*
			 * Note: What should be done with this entry?
			 * We leave it untouched for now, hence no path in
			 * the backup image matches with this entry and will
			 * be reported as not found.
			 */
			MOD_LOGV3(params, NDMP_LOG_ERROR,
			    "Destination path too long(%s/%s)", dp, nm);
			continue;
		}
		cp = strdup(bp);
		if (!cp) {
			MOD_LOGV3(params, NDMP_LOG_ERROR,
			    "Insufficient memory.\n");
			rv = NDMP_NO_MEM_ERR;
			break;
		}
		free(ep->nm3_dpath);
		ep->nm3_dpath = cp;
		NDMP_FREE(ep->nm3_newnm);

		bp = joinpath(buf, nlp->nlp_backup_path, ep->nm3_opath);
		if (!bp) {
			/*
			 * Note: The same problem of above with long path.
			 */
			MOD_LOGV3(params, NDMP_LOG_ERROR,
			    "Path too long(%s/%s)",
			    nlp->nlp_backup_path, ep->nm3_opath);
			continue;
		}
		cp = strdup(bp);
		if (!cp) {
			MOD_LOGV3(params, NDMP_LOG_ERROR,
			    "Insufficient memory.\n");
			rv = NDMP_NO_MEM_ERR;
			break;
		}
		NDMP_FREE(ep->nm3_opath);
		ep->nm3_opath = cp;

		NDMP_LOG(LOG_DEBUG, "orig[%d]: \"%s\"", i, ep->nm3_opath);
		if (ep->nm3_dpath) {
			NDMP_LOG(LOG_DEBUG,
			    "dest[%d]: \"%s\"", i, ep->nm3_dpath);
		} else {
			NDMP_LOG(LOG_DEBUG, "dest[%d]: \"%s\"", i, "NULL");
		}
	}

	free(buf);

	return (rv);
}


/*
 * allvalidfh
 *
 * Run a sanity check on the file history info. The file history
 * info is the offset of the record starting the entry on the tape
 * and is used in DAR (direct access restore mode).
 */
static boolean_t
allvalidfh(ndmpd_session_t *session, ndmpd_module_params_t *params)
{
	int i, n;
	boolean_t rv;
	mem_ndmp_name_v3_t *ep;

	rv = TRUE;
	n = session->ns_data.dd_nlist_len;
	for (i = 0; i < n; i++) {
		ep = (mem_ndmp_name_v3_t *)MOD_GETNAME(params, i);
		if (!ep)
			continue;
		/*
		 * The fh_info's sent from the client are multiples
		 * of RECORDSIZE which is 512 bytes.
		 *
		 * All our fh_info's are at the RECORDSIZE boundary.  If there
		 * is any fh_info that is less than RECORDSIZE (this covers 0
		 * and -1 values too), then the result is that DAR cannot be
		 * done.
		 */
		if (ep->nm3_fh_info < RECORDSIZE ||
		    ep->nm3_fh_info % RECORDSIZE != 0) {
			rv = FALSE;
			break;
		}
	}

	return (rv);
}


/*
 * log_rs_params_v3
 *
 * Log a copy of all values of the restore parameters
 */
void
log_rs_params_v3(ndmpd_session_t *session, ndmpd_module_params_t *params,
    ndmp_lbr_params_t *nlp)
{
	MOD_LOGV3(params, NDMP_LOG_NORMAL, "Restoring to \"%s\".\n",
	    (nlp->nlp_restore_path) ? nlp->nlp_restore_path : "NULL");

	if (session->ns_data.dd_data_addr.addr_type == NDMP_ADDR_LOCAL) {
		MOD_LOGV3(params, NDMP_LOG_NORMAL, "Tape server: local.\n");
		MOD_LOGV3(params, NDMP_LOG_NORMAL,
		    "Tape record size: %d.\n",
		    session->ns_mover.md_record_size);
	} else if (session->ns_data.dd_data_addr.addr_type == NDMP_ADDR_TCP)
		MOD_LOGV3(params, NDMP_LOG_NORMAL,
		    "Tape server: remote at %s:%d.\n",
		    inet_ntoa(IN_ADDR(session->ns_data.dd_data_addr.tcp_ip_v3)),
		    session->ns_data.dd_data_addr.tcp_port_v3);
	else
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "Unknown tape server address type.\n");

	if (NLP_ISSET(nlp, NLPF_DIRECT))
		MOD_LOGV3(params, NDMP_LOG_NORMAL,
		    "Direct Access Restore.\n");
}


/*
 * send_unrecovered_list_v3
 *
 * Create the list of files that were in restore list but
 * not recovered due to some errors.
 */
int
send_unrecovered_list_v3(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	int i, rv;
	int err;

	if (!params) {
		NDMP_LOG(LOG_DEBUG, "params == NULL");
		return (-1);
	}
	if (!nlp) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (-1);
	}

	if (nlp->nlp_lastidx != -1) {
		if (!bm_getone(nlp->nlp_rsbm, (u_longlong_t)nlp->nlp_lastidx))
			err = ENOENT;
		else
			err = 0;
		(void) ndmp_send_recovery_stat_v3(params, nlp,
		    nlp->nlp_lastidx, err);
		nlp->nlp_lastidx = -1;
	}

	rv = 0;
	for (i = 0; i < (int)nlp->nlp_nfiles; i++) {
		if (!bm_getone(nlp->nlp_rsbm, (u_longlong_t)i)) {
			rv = ndmp_send_recovery_stat_v3(params, nlp, i, ENOENT);
			if (rv < 0)
				break;
		}
	}

	return (rv);
}



/*
 * restore_dar_alloc_structs_v3
 *
 * Allocates the necessary structures for running DAR restore.
 * It just creates the reader writer IPC.
 * This function is called for each entry in the restore entry list.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   jname (input) - Job name
 *
 * Returns:
 *    0: on success
 *   -1: on error
 */
int
restore_dar_alloc_structs_v3(ndmpd_session_t *session, char *jname)
{
	long xfer_size;
	ndmp_lbr_params_t *nlp;
	tlm_commands_t *cmds;

	nlp = ndmp_get_nlp(session);
	if (!nlp) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (-1);
	}

	cmds = &nlp->nlp_cmds;
	(void) memset(cmds, 0, sizeof (*cmds));

	xfer_size = ndmp_buffer_get_size(session);
	cmds->tcs_command = tlm_create_reader_writer_ipc(FALSE, xfer_size);
	if (!cmds->tcs_command) {
		tlm_un_ref_job_stats(jname);
		return (-1);
	}

	return (0);
}


/*
 * free_dar_structs_v3
 *
 * To free the structures were created by restore_dar_alloc_structs_v3.
 * This funnction is called for each entry in restore entry list.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   jname (input) - job name
 *
 * Returns:
 *	NONE
 */
/*ARGSUSED*/
static void
free_dar_structs_v3(ndmpd_session_t *session, char *jname)
{
	ndmp_lbr_params_t *nlp;
	tlm_commands_t *cmds;

	nlp = ndmp_get_nlp(session);
	if (!nlp) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return;
	}
	cmds = &nlp->nlp_cmds;
	if (!cmds) {
		NDMP_LOG(LOG_DEBUG, "cmds == NULL");
		return;
	}

	if (cmds->tcs_command) {
		if (cmds->tcs_command->tc_buffers != NULL)
			tlm_release_reader_writer_ipc(cmds->tcs_command);
		else
			NDMP_LOG(LOG_DEBUG, "BUFFERS == NULL");
		cmds->tcs_command = NULL;
	} else
		NDMP_LOG(LOG_DEBUG, "COMMAND == NULL");
}


/*
 * ndmp_dar_tar_init_v3
 *
 * Constructor for the DAR restore. Creates job name, allocates structures
 * needed for keeping the statistics, and reports the start of restore action.
 * It is called once for each DAR restore request.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   char pointer: on success
 *   NULL: on error
 */
static char *ndmpd_dar_tar_init_v3(ndmpd_session_t *session,
    ndmp_lbr_params_t *nlp)
{
	char *jname;

	jname = ndmp_malloc(TLM_MAX_BACKUP_JOB_NAME);

	if (!jname)
		return (NULL);

	(void) ndmp_new_job_name(jname);

	if (!nlp) {
		free(jname);
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (NULL);
	}

	nlp->nlp_jstat = tlm_new_job_stats(jname);
	if (!nlp->nlp_jstat) {
		free(jname);
		NDMP_LOG(LOG_DEBUG, "Creating job stats");
		return (NULL);
	}

	nlp->nlp_jstat->js_start_ltime = time(NULL);
	nlp->nlp_jstat->js_start_time = nlp->nlp_jstat->js_start_ltime;

	nlp->nlp_logcallbacks = lbrlog_callbacks_init(session,
	    ndmpd_path_restored_v3, NULL, NULL);
	if (!nlp->nlp_logcallbacks) {
		tlm_un_ref_job_stats(jname);
		free(jname);
		return (NULL);
	}
	nlp->nlp_jstat->js_callbacks = (void *)(nlp->nlp_logcallbacks);

	nlp->nlp_rsbm = bm_alloc(nlp->nlp_nfiles, 0);
	if (nlp->nlp_rsbm < 0) {
		NDMP_LOG(LOG_ERR, "Out of memory.");
		lbrlog_callbacks_done(nlp->nlp_logcallbacks);
		tlm_un_ref_job_stats(jname);
		free(jname);
		return (NULL);
	}

	/* this is used in ndmpd_path_restored_v3() */
	nlp->nlp_lastidx = -1;

	NDMP_LOG(LOG_DEBUG, "Restoring from %s tape(s).",
	    ndmp_data_get_mover_mode(session));

	return (jname);
}

/*
 * ndmpd_dar_tar_end_v3
 *
 * Deconstructor for the DAR restore. This function is called once per
 * DAR request. It deallocates memories allocated by ndmpd_dar_tar_init_v3.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *   jname(input) - job name
 *
 * Returns:
 *   0: on success
 *   -1: on error
 */
static int ndmpd_dar_tar_end_v3(ndmpd_session_t *session,
    ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp, char *jname)
{
	int err = 0;


	NDMP_LOG(LOG_DEBUG, "lastidx %d", nlp->nlp_lastidx);

	/* nothing restored. */
	(void) send_unrecovered_list_v3(params, nlp);

	if (nlp->nlp_jstat) {
		nlp->nlp_bytes_total =
		    (u_longlong_t)nlp->nlp_jstat->js_bytes_total;
		tlm_un_ref_job_stats(jname);
		nlp->nlp_jstat = NULL;
	} else {
		NDMP_LOG(LOG_DEBUG, "JSTAT == NULL");
	}

	if (nlp->nlp_logcallbacks) {
		lbrlog_callbacks_done(nlp->nlp_logcallbacks);
		nlp->nlp_logcallbacks = NULL;
	} else {
		NDMP_LOG(LOG_DEBUG, "FH CALLBACKS == NULL");
	}

	if (session->ns_data.dd_abort) {
		NDMP_LOG(LOG_DEBUG, "Restoring to \"%s\" aborted.",
		    (nlp->nlp_restore_path) ? nlp->nlp_restore_path : "NULL");
		err = EINTR;
	} else {
		NDMP_LOG(LOG_DEBUG, "Restoring to \"%s\" finished. (%d)",
		    (nlp->nlp_restore_path) ? nlp->nlp_restore_path :
		    "NULL", err);
	}

	if (session->ns_data.dd_operation == NDMP_DATA_OP_RECOVER) {
		if (nlp->nlp_rsbm < 0) {
			NDMP_LOG(LOG_DEBUG, "nlp_rsbm < 0 %d", nlp->nlp_rsbm);
		} else {
			(void) bm_free(nlp->nlp_rsbm);
			nlp->nlp_rsbm = -1;
		}
	}

	free(jname);

	return (err);
}


/*
 * ndmpd_dar_tar_v3
 *
 * This function is called for each entry in DAR entry list. The window
 * is already located and we should be in the right position to read
 * the data from the tape.
 * For each entry we setup selection list; so that, if the file name from
 * tape is not as the name client asked for, error be returned.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *   jname (input) - job name
 *   dar_index(input) - Index of this entry in the restore list
 *
 * Returns:
 *   0: on success
 *   -1: on error
 */
static int
ndmpd_dar_tar_v3(ndmpd_session_t *session, ndmpd_module_params_t *params,
    ndmp_lbr_params_t *nlp, char *jname, int dar_index)
{
	char *excl;
	char **sels;
	int flags;
	int err;
	tlm_commands_t *cmds;
	struct rs_name_maker rn;
	int data_addr_type = session->ns_data.dd_data_addr.addr_type;
	ndmp_tar_reader_arg_t arg;
	pthread_t rdtp;
	ndmp_context_t nctx;
	mem_ndmp_name_v3_t *ep;

	err = 0;

	/*
	 * We have to allocate and deallocate buffers every time we
	 * run the restore, for we need to flush the buffers.
	 */
	if (restore_dar_alloc_structs_v3(session, jname) < 0)
		return (-1);

	sels = setupsels(session, params, nlp, dar_index);
	if (!sels) {
		free_dar_structs_v3(session, jname);
		return (-1);
	}
	excl = NULL;
	flags = RSFLG_OVR_ALWAYS;
	rn.rn_nlp = nlp;
	rn.rn_fp = mknewname;

	if (!session->ns_data.dd_abort) {
		cmds = &nlp->nlp_cmds;
		cmds->tcs_reader = cmds->tcs_writer = TLM_RESTORE_RUN;
		cmds->tcs_command->tc_reader = TLM_RESTORE_RUN;
		cmds->tcs_command->tc_writer = TLM_RESTORE_RUN;

		arg.tr_session = session;
		arg.tr_mod_params = params;
		arg.tr_cmds = cmds;

		err = pthread_create(&rdtp, NULL, (funct_t)ndmp_tar_reader,
		    (void *)&arg);
		if (err == 0) {
			tlm_cmd_wait(cmds->tcs_command, TLM_TAR_READER);
		} else {
			NDMP_LOG(LOG_DEBUG, "launch ndmp_tar_reader: %m");
			return (-1);
		}

		cmds->tcs_command->tc_ref++;
		cmds->tcs_writer_count++;

		/* Plug-in module */
		if (ndmp_pl != NULL &&
		    ndmp_pl->np_pre_restore != NULL) {
			(void) memset(&nctx, 0, sizeof (ndmp_context_t));
			nctx.nc_cmds = cmds;
			nctx.nc_params = params;
			nctx.nc_ddata = (void *) session;
			ep = (mem_ndmp_name_v3_t *)MOD_GETNAME(params,
			    dar_index - 1);

			if ((err = ndmp_pl->np_pre_restore(ndmp_pl, &nctx,
			    ep->nm3_opath, ep->nm3_dpath))
			    != 0) {
				NDMP_LOG(LOG_ERR, "Pre-restore plug-in: %m");
				ndmp_stop_local_reader(session, cmds);
				ndmp_wait_for_reader(cmds);
				(void) pthread_join(rdtp, NULL);
				ndmp_stop_remote_reader(session);
				goto restore_out;
			}
		}

		if (tm_tar_ops.tm_getdir != NULL) {
			char errbuf[256];

			err = (tm_tar_ops.tm_getdir)(cmds, cmds->tcs_command,
			    nlp->nlp_jstat, &rn, 1, 1, sels, &excl, flags,
			    dar_index, nlp->nlp_backup_path,
			    session->hardlink_q);
			/*
			 * If the fatal error from tm_getdir looks like an
			 * errno code, we send the error description to DMA.
			 */
			if (err > 0 && strerror_r(err, errbuf,
			    sizeof (errbuf)) == 0) {
				MOD_LOGV3(params, NDMP_LOG_ERROR,
				    "Fatal error during the restore: %s\n",
				    errbuf);
			}
		}

		cmds->tcs_writer_count--;
		cmds->tcs_command->tc_ref--;
		NDMP_LOG(LOG_DEBUG, "stop local reader.");
		ndmp_stop_local_reader(session, cmds);

		ndmp_wait_for_reader(cmds);
		(void) pthread_join(rdtp, NULL);

		/*
		 * If this is the last DAR entry and it is a three-way
		 * restore then we should close the connection.
		 */
		if ((data_addr_type == NDMP_ADDR_TCP) &&
		    (dar_index == (int)session->ns_data.dd_nlist_len)) {
			NDMP_LOG(LOG_DEBUG, "stop remote reader.");
			ndmp_stop_remote_reader(session);
		}

		/* exit as if there was an internal error */
		if (session->ns_eof)
			err = -1;
restore_out:
		/* Plug-in module */
		if (ndmp_pl != NULL &&
		    ndmp_pl->np_post_restore != NULL &&
		    ndmp_pl->np_post_restore(ndmp_pl, &nctx, err) == -1) {
			NDMP_LOG(LOG_DEBUG, "Post-restore plug-in: %m");
			err = -1;
		}
	}

	NDMP_FREE(sels);

	free_dar_structs_v3(session, jname);

	return (err);
}

/*
 * ndmpd_dar_locate_windwos_v3
 *
 * Locating the right window in which the requested file is backed up.
 * We should go through windows to find the exact location, for the
 * file can be located in for example 10th window after the current window.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   params (input) - pointer to the parameters structure
 *   fh_info (input) - index from the beginning of the backup stream
 *   len (input) - Length of the mover window
 *
 * Returns:
 *   0: on success
 *   -1: on error
 */
static int
ndmpd_dar_locate_window_v3(ndmpd_session_t *session,
    ndmpd_module_params_t *params, u_longlong_t fh_info, u_longlong_t len)
{
	int ret = 0;


	for (; ; ) {
		ret = (*params->mp_seek_func)(session, fh_info, len);

		NDMP_LOG(LOG_DEBUG, "ret %d", ret);
		if (ret == 0) /* Seek was done successfully */
			break;
		else if (ret < 0) {
			NDMP_LOG(LOG_DEBUG, "Seek error");
			break;
		}

		/*
		 * DMA moved to a new window.
		 * If we are reading the remainig of the file from
		 * new window, seek is handled by ndmpd_local_read_v3.
		 * Here we should continue the seek inside the new
		 * window.
		 */
		continue;
	}
	return (ret);
}

/*
 * ndmpd_rs_dar_tar_v3
 *
 * Main DAR function. It calls the constructor, then for each entry it
 * calls the locate_window_v3 to find the exact position of the file. Then
 * it restores the file.
 * When all restore requests are done it calls the deconstructor to clean
 * everything up.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   0: on success
 *   -1: on error
 */
static int
ndmpd_rs_dar_tar_v3(ndmpd_session_t *session, ndmpd_module_params_t *params,
    ndmp_lbr_params_t *nlp)
{
	mem_ndmp_name_v3_t *ep;
	u_longlong_t len;
	char *jname;
	int n = session->ns_data.dd_nlist_len;
	int i, ret = 0;
	int result = 0;

	jname = ndmpd_dar_tar_init_v3(session, nlp);

	if (!jname)
		return (-1);

	/*
	 * We set the length = sizeof (tlm_tar_hdr_t)
	 * This is important for three-way DAR restore, for we should
	 * read the header first (If we ask for more data then we have
	 * to read and discard the remaining data in the socket)
	 */
	len = tlm_tarhdr_size();

	for (i = 0; i < n; ++i) {
		ep = (mem_ndmp_name_v3_t *)MOD_GETNAME(params, i);
		if (!ep) {
			NDMP_LOG(LOG_DEBUG, "ep NULL, i %d", i);
			continue;
		}
		NDMP_LOG(LOG_DEBUG,
		    "restoring opath %s, dpath %s, fh_info %lld",
		    ep->nm3_opath ? ep->nm3_opath : "NULL",
		    ep->nm3_dpath ? ep->nm3_dpath : "NULL",
		    ep->nm3_fh_info);

		/*
		 * We should seek till finding the window in which file
		 * is located.
		 */
		ret = ndmpd_dar_locate_window_v3(session, params,
		    ep->nm3_fh_info, len);

		if (ret < 0) /* If seek fails, restore should be aborted */
			break;
		/*
		 * We are inside the target window.
		 * for each restore we will use one entry as selection list
		 */
		if ((ret = ndmpd_dar_tar_v3(session, params, nlp, jname, i+1))
		    != 0)
			result = EIO;
		ndmpd_audit_restore(session->ns_connection,
		    ep->nm3_opath ? ep->nm3_opath : "NULL",
		    session->ns_data.dd_data_addr.addr_type,
		    session->ns_tape.td_adapter_name, result);
	}

	NDMP_LOG(LOG_DEBUG, "End of restore list");

	(void) ndmpd_dar_tar_end_v3(session, params, nlp, jname);

	return (ret);
}

/*
 * ndmp_plugin_pre_restore
 *
 * Wrapper for pre-restore callback with multiple path
 */
static int
ndmp_plugin_pre_restore(ndmp_context_t *ctxp, ndmpd_module_params_t *params,
    int ncount)
{
	mem_ndmp_name_v3_t *ep;
	int err;
	int i;

	for (i = 0; i < ncount; i++) {
		if (!(ep = (mem_ndmp_name_v3_t *)MOD_GETNAME(params, i)))
			continue;
		if ((err = ndmp_pl->np_pre_restore(ndmp_pl, ctxp,
		    ep->nm3_opath, ep->nm3_dpath)) != 0)
			return (err);
	}

	return (0);
}

/*
 * get_absolute_path
 *
 * Get resolved path name which does not involve ".", ".." or extra
 * "/" or symbolic links.
 *
 * e.g.
 *
 * /backup/path/ -> /backup/path
 * /backup/path/. -> /backup/path
 * /backup/path/../path/ -> /backup/path
 * /link-to-backup-path -> /backup/path
 *
 * Returns:
 * 	Pointer to the new path (allocated)
 * 	NULL if the path doesnt exist
 */
static char *
get_absolute_path(const char *bkpath)
{
	char *pbuf;
	char *rv;

	if (!(pbuf = ndmp_malloc(TLM_MAX_PATH_NAME)))
		return (NULL);

	if ((rv = realpath(bkpath, pbuf)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "Invalid path [%s] err=%d",
		    bkpath, errno);
	}
	return (rv);
}

/*
 * Expands the format string and logs the resulting message to the
 * remote DMA
 */
void
ndmp_log_dma(ndmp_context_t *nctx, ndmp_log_dma_type_t lt, const char *fmt, ...)
{
	va_list ap;
	char buf[256];
	ndmpd_module_params_t *params;

	if (nctx == NULL ||
	    (params = (ndmpd_module_params_t *)nctx->nc_params) == NULL)
		return;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	MOD_LOGV3(params, (ndmp_log_type)lt, "%s", buf);
}


/*
 * ndmpd_rs_sar_tar_v3
 *
 * Main non-DAR restore function. It will try to restore all the entries
 * that have been backed up.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   params (input) - pointer to the parameters structure
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   0: on success
 *   -1: on error
 */
static int
ndmpd_rs_sar_tar_v3(ndmpd_session_t *session, ndmpd_module_params_t *params,
    ndmp_lbr_params_t *nlp)
{
	char jname[TLM_MAX_BACKUP_JOB_NAME];
	char *excl;
	char **sels;
	int flags;
	int err;
	tlm_commands_t *cmds;
	struct rs_name_maker rn;
	ndmp_tar_reader_arg_t arg;
	pthread_t rdtp;
	int result;
	ndmp_context_t nctx;

	result = err = 0;
	(void) ndmp_new_job_name(jname);
	if (restore_alloc_structs_v3(session, jname) < 0)
		return (-1);

	sels = setupsels(session, params, nlp, 0);
	if (!sels) {
		free_structs_v3(session, jname);
		return (-1);
	}
	excl = NULL;
	flags = RSFLG_OVR_ALWAYS;
	rn.rn_nlp = nlp;
	rn.rn_fp = mknewname;

	nlp->nlp_jstat->js_start_ltime = time(NULL);
	nlp->nlp_jstat->js_start_time = nlp->nlp_jstat->js_start_ltime;

	if (!session->ns_data.dd_abort && !session->ns_data.dd_abort) {
		cmds = &nlp->nlp_cmds;
		cmds->tcs_reader = cmds->tcs_writer = TLM_RESTORE_RUN;
		cmds->tcs_command->tc_reader = TLM_RESTORE_RUN;
		cmds->tcs_command->tc_writer = TLM_RESTORE_RUN;

		NDMP_LOG(LOG_DEBUG, "Restoring to \"%s\" started.",
		    (nlp->nlp_restore_path) ? nlp->nlp_restore_path : "NULL");

		arg.tr_session = session;
		arg.tr_mod_params = params;
		arg.tr_cmds = cmds;
		err = pthread_create(&rdtp, NULL, (funct_t)ndmp_tar_reader,
		    (void *)&arg);
		if (err == 0) {
			tlm_cmd_wait(cmds->tcs_command, TLM_TAR_READER);
		} else {
			NDMP_LOG(LOG_DEBUG, "Launch ndmp_tar_reader: %m");
			free_structs_v3(session, jname);
			return (-1);
		}

		if (!ndmp_check_utf8magic(cmds->tcs_command)) {
			NDMP_LOG(LOG_DEBUG, "UTF8Magic not found!");
		} else {
			NDMP_LOG(LOG_DEBUG, "UTF8Magic found");
		}

		/* Plug-in module */
		if (ndmp_pl != NULL &&
		    ndmp_pl->np_pre_restore != NULL) {
			(void) memset(&nctx, 0, sizeof (ndmp_context_t));
			nctx.nc_cmds = cmds;
			nctx.nc_params = params;
			nctx.nc_ddata = (void *) session;
			if ((err = ndmp_plugin_pre_restore(&nctx, params,
			    nlp->nlp_nfiles))
			    != 0) {
				NDMP_LOG(LOG_ERR, "Pre-restore plug-in: %m");
				ndmp_stop_local_reader(session, cmds);
				ndmp_wait_for_reader(cmds);
				(void) pthread_join(rdtp, NULL);
				ndmp_stop_remote_reader(session);
				goto restore_out;
			}
		}

		cmds->tcs_command->tc_ref++;
		cmds->tcs_writer_count++;

		if (tm_tar_ops.tm_getdir != NULL) {
			char errbuf[256];

			err = (tm_tar_ops.tm_getdir)(cmds, cmds->tcs_command,
			    nlp->nlp_jstat, &rn, 1, 1, sels, &excl, flags, 0,
			    nlp->nlp_backup_path, session->hardlink_q);
			/*
			 * If the fatal error from tm_getdir looks like an
			 * errno code, we send the error description to DMA.
			 */
			if (err > 0 && strerror_r(err, errbuf,
			    sizeof (errbuf)) == 0) {
				MOD_LOGV3(params, NDMP_LOG_ERROR,
				    "Fatal error during the restore: %s\n",
				    errbuf);
			}
		}

		cmds->tcs_writer_count--;
		cmds->tcs_command->tc_ref--;
		nlp->nlp_jstat->js_stop_time = time(NULL);

		/* Send the list of un-recovered files/dirs to the client.  */
		(void) send_unrecovered_list_v3(params, nlp);

		ndmp_stop_local_reader(session, cmds);
		ndmp_wait_for_reader(cmds);
		(void) pthread_join(rdtp, NULL);

		ndmp_stop_remote_reader(session);

		/* exit as if there was an internal error */
		if (session->ns_eof)
			err = -1;
		if (err == -1)
			result = EIO;
	}

	(void) send_unrecovered_list_v3(params, nlp); /* nothing restored. */
	if (session->ns_data.dd_abort) {
		NDMP_LOG(LOG_DEBUG, "Restoring to \"%s\" aborted.",
		    (nlp->nlp_restore_path) ? nlp->nlp_restore_path : "NULL");
		result = EINTR;
		ndmpd_audit_restore(session->ns_connection,
		    nlp->nlp_restore_path,
		    session->ns_data.dd_data_addr.addr_type,
		    session->ns_tape.td_adapter_name, result);
		err = -1;
	} else {
		NDMP_LOG(LOG_DEBUG, "Restoring to \"%s\" finished. (%d)",
		    (nlp->nlp_restore_path) ? nlp->nlp_restore_path : "NULL",
		    err);
		ndmpd_audit_restore(session->ns_connection,
		    nlp->nlp_restore_path,
		    session->ns_data.dd_data_addr.addr_type,
		    session->ns_tape.td_adapter_name, result);

restore_out:
		/* Plug-in module */
		if (ndmp_pl != NULL &&
		    ndmp_pl->np_post_restore != NULL &&
		    ndmp_pl->np_post_restore(ndmp_pl, &nctx, err) == -1) {
			NDMP_LOG(LOG_DEBUG, "Post-restore plug-in: %m");
			err = -1;
		}
	}

	NDMP_FREE(sels);
	free_structs_v3(session, jname);

	return (err);
}


/*
 * ndmp_backup_get_params_v3
 *
 * Get the backup parameters from the NDMP env variables
 * and log them in the system log and as normal messages
 * to the DMA.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   params (input) - pointer to the parameters structure
 *
 * Returns:
 *   NDMP_NO_ERR: on success
 *   != NDMP_NO_ERR: otherwise
 */
ndmp_error
ndmp_backup_get_params_v3(ndmpd_session_t *session,
    ndmpd_module_params_t *params)
{
	ndmp_lbr_params_t *nlp;

	if (!session || !params)
		return (NDMP_ILLEGAL_ARGS_ERR);

	nlp = ndmp_get_nlp(session);
	if (!nlp) {
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "Internal error: NULL nlp.\n");
		return (NDMP_ILLEGAL_ARGS_ERR);
	} else {
		if (!(nlp->nlp_backup_path = get_backup_path_v3(params)) ||
		    !is_valid_backup_dir_v3(params, nlp->nlp_backup_path))
		return (NDMP_ILLEGAL_ARGS_ERR);
	}

	nlp->nlp_backup_path = get_absolute_path(nlp->nlp_backup_path);
	if (!nlp->nlp_backup_path)
		return (NDMP_ILLEGAL_ARGS_ERR);

	if (fs_is_chkpntvol(nlp->nlp_backup_path) ||
	    fs_is_rdonly(nlp->nlp_backup_path) ||
	    !fs_is_chkpnt_enabled(nlp->nlp_backup_path))
		NLP_SET(nlp, NLPF_CHKPNTED_PATH);
	else
		NLP_UNSET(nlp, NLPF_CHKPNTED_PATH);

	/* Should the st_ctime be ignored when backing up? */
	if (ndmp_ignore_ctime) {
		NDMP_LOG(LOG_DEBUG, "ignoring st_ctime");
		NLP_SET(nlp, NLPF_IGNCTIME);
	} else {
		NLP_UNSET(nlp, NLPF_IGNCTIME);
	}

	if (ndmp_include_lmtime == TRUE) {
		NDMP_LOG(LOG_DEBUG, "including st_lmtime");
		NLP_SET(nlp, NLPF_INCLMTIME);
	} else {
		NLP_UNSET(nlp, NLPF_INCLMTIME);
	}

	NDMP_LOG(LOG_DEBUG, "flags %x", nlp->nlp_flags);

	get_hist_env_v3(params, nlp);
	get_exc_env_v3(params, nlp);
	get_inc_env_v3(params, nlp);
	get_direct_env_v3(params, nlp);
	return (get_backup_level_v3(params, nlp));
}


/*
 * ndmpd_tar_backup_starter_v3
 *
 * Create the checkpoint for the backup and do the backup,
 * then remove the backup checkpoint if we created it.
 * Save the backup time information based on the backup
 * type and stop the data server.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *
 * Returns:
 *   0: on success
 *   != 0: otherwise
 */
int
ndmpd_tar_backup_starter_v3(void *arg)
{
	ndmpd_module_params_t *params = arg;
	int err;
	ndmpd_session_t *session;
	ndmp_lbr_params_t *nlp;
	char jname[TLM_MAX_BACKUP_JOB_NAME];
	ndmp_bkup_size_arg_t sarg;
	pthread_t tid;

	session = (ndmpd_session_t *)(params->mp_daemon_cookie);
	*(params->mp_module_cookie) = nlp = ndmp_get_nlp(session);
	ndmp_session_ref(session);
	(void) ndmp_new_job_name(jname);

	err = 0;
	if (!NLP_ISCHKPNTED(nlp) &&
	    ndmp_create_snapshot(nlp->nlp_backup_path, jname) < 0) {
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "Creating checkpoint on \"%s\".\n",
		    nlp->nlp_backup_path);
		err = -1;
	}

	NDMP_LOG(LOG_DEBUG, "err %d, chkpnted %c",
	    err, NDMP_YORN(NLP_ISCHKPNTED(nlp)));

	if (err == 0) {
		sarg.bs_session = session;
		sarg.bs_jname = jname;
		sarg.bs_path = nlp->nlp_backup_path;

		/* Get an estimate of the data size */
		if (pthread_create(&tid, NULL, (funct_t)get_backup_size,
		    (void *)&sarg) == 0)
			(void) pthread_detach(tid);

		err = ndmp_get_cur_bk_time(nlp, &nlp->nlp_cdate, jname);
		if (err != 0) {
			NDMP_LOG(LOG_DEBUG, "err %d", err);
		} else {
			log_bk_params_v3(session, params, nlp);
			err = tar_backup_v3(session, params, nlp, jname);
		}
	}

	if (!NLP_ISCHKPNTED(nlp))
		(void) ndmp_remove_snapshot(nlp->nlp_backup_path, jname);

	NDMP_LOG(LOG_DEBUG, "err %d, update %c",
	    err, NDMP_YORN(NLP_SHOULD_UPDATE(nlp)));

	if (err == 0)
		save_backup_date_v3(params, nlp);

	MOD_DONE(params, err);

	/* nlp_params is allocated in start_backup_v3() */
	NDMP_FREE(nlp->nlp_params);
	NDMP_FREE(nlp->nlp_backup_path);

	NS_DEC(nbk);
	ndmp_session_unref(session);
	return (err);

}


/*
 * ndmpd_tar_backup_abort_v3
 *
 * Abort the backup operation and stop the reader thread.
 *
 * Parameters:
 *   module_cookie (input) - pointer to the nlp structure
 *
 * Returns:
 *   0: always
 */
int
ndmpd_tar_backup_abort_v3(void *module_cookie)
{
	ndmp_lbr_params_t *nlp;

	nlp = (ndmp_lbr_params_t *)module_cookie;
	if (nlp && nlp->nlp_session) {
		if (nlp->nlp_session->ns_data.dd_data_addr.addr_type ==
		    NDMP_ADDR_TCP &&
		    nlp->nlp_session->ns_data.dd_sock != -1) {
			(void) close(nlp->nlp_session->ns_data.dd_sock);
			nlp->nlp_session->ns_data.dd_sock = -1;
		}
		ndmp_stop_reader_thread(nlp->nlp_session);
	}

	return (0);
}


/*
 * ndmp_restore_get_params_v3
 *
 * Get the parameters specified for recovery such as restore path, type
 * of restore (DAR, non-DAR) etc
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   params (input) - pointer to the parameters structure
 *
 * Returns:
 *   NDMP_NO_ERR: on success
 *   != NDMP_NO_ERR: otherwise
 */
ndmp_error
ndmp_restore_get_params_v3(ndmpd_session_t *session,
    ndmpd_module_params_t *params)
{
	ndmp_error rv;
	ndmp_lbr_params_t *nlp;

	if (!(nlp = ndmp_get_nlp(session))) {
		NDMP_LOG(LOG_DEBUG, "nlp is NULL");
		rv = NDMP_ILLEGAL_ARGS_ERR;
	} else if (!(nlp->nlp_backup_path = get_backup_path_v3(params)))
		rv = NDMP_ILLEGAL_ARGS_ERR;
	else if ((nlp->nlp_nfiles = session->ns_data.dd_nlist_len) == 0) {
		NDMP_LOG(LOG_DEBUG, "nfiles: %d", nlp->nlp_nfiles);
		rv = NDMP_ILLEGAL_ARGS_ERR;
	} else if (get_rs_path_v3(params, nlp) != NDMP_NO_ERR) {
		rv = NDMP_ILLEGAL_ARGS_ERR;
	} else if ((rv = fix_nlist_v3(session, params, nlp)) != NDMP_NO_ERR) {
		NDMP_LOG(LOG_DEBUG, "fix_nlist_v3: %d", rv);
	} else {
		rv = NDMP_NO_ERR;
		get_direct_env_v3(params, nlp);
		if (NLP_ISSET(nlp, NLPF_DIRECT)) {
			if (NLP_ISSET(nlp, NLPF_RECURSIVE)) {
				/* Currently we dont support DAR on directory */
				NDMP_LOG(LOG_DEBUG,
				    "Can't have RECURSIVE and DIRECT together");
				rv = NDMP_ILLEGAL_ARGS_ERR;
				return (rv);
			}

			/*
			 * DAR can be done if all the fh_info's are valid.
			 */
			if (allvalidfh(session, params)) {
				ndmp_sort_nlist_v3(session);
			} else {
				MOD_LOGV3(params, NDMP_LOG_WARNING,
				    "Cannot do direct access recovery. "
				    "Some 'fh_info'es are not valid.\n");
				NLP_UNSET(nlp, NLPF_DIRECT);
			}
		}

		log_rs_params_v3(session, params, nlp);
	}

	return (rv);
}


/*
 * ndmpd_tar_restore_starter_v3
 *
 * The main restore starter function. It will start a DAR or
 * non-DAR recovery based on the parameters. (V3 and V4 only)
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure
 *
 * Returns:
 *   NDMP_NO_ERR: on success
 *   != NDMP_NO_ERR: otherwise
 */
int
ndmpd_tar_restore_starter_v3(void *arg)
{
	ndmpd_module_params_t *params = arg;
	int err;
	ndmpd_session_t *session;
	ndmp_lbr_params_t *nlp;


	session = (ndmpd_session_t *)(params->mp_daemon_cookie);
	*(params->mp_module_cookie) = nlp = ndmp_get_nlp(session);
	ndmp_session_ref(session);

	if (NLP_ISSET(nlp, NLPF_DIRECT))
		err = ndmpd_rs_dar_tar_v3(session, params, nlp);
	else
		err = ndmpd_rs_sar_tar_v3(session, params, nlp);

	MOD_DONE(params, err);

	NS_DEC(nrs);
	/* nlp_params is allocated in start_recover() */
	NDMP_FREE(nlp->nlp_params);
	ndmp_session_unref(session);
	return (err);

}

/*
 * ndmp_tar_restore_abort_v3
 *
 * Restore abort function (V3 and V4 only)
 *
 * Parameters:
 *   module_cookie (input) - pointer to nlp
 *
 * Returns:
 *   0
 */
int
ndmpd_tar_restore_abort_v3(void *module_cookie)
{
	ndmp_lbr_params_t *nlp;

	nlp = (ndmp_lbr_params_t *)module_cookie;
	if (nlp != NULL && nlp->nlp_session != NULL) {
		if (nlp->nlp_session->ns_data.dd_mover.addr_type ==
		    NDMP_ADDR_TCP &&
		    nlp->nlp_session->ns_data.dd_sock != -1) {
			(void) close(nlp->nlp_session->ns_data.dd_sock);
			nlp->nlp_session->ns_data.dd_sock = -1;
		}
		ndmp_stop_writer_thread(nlp->nlp_session);
	}

	return (0);
}
