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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _MGMT_UTIL_H
#define	_MGMT_UTIL_H


#include <sys/types.h>
#include <stdio.h>
#include <limits.h>
#include <libnvpair.h>
#include <libscf.h>
#include <sys/statvfs.h>

#include "mms.h"
#include "mgmt_sym.h"

/* Generic parsing constant */
#define	WHITESPACE " \11\12\15"

/* define commonly used string lengths */
#define	MAXSERIALNUMLEN	MAXNAMELEN

/* define commonly-used paths */
#define	PROCDIR		"/proc"
#define	TAPEDEVDIR	"/dev/rmt"

#define	TMP_DIR "/tmp"
#define	default_tmpfile_dir TMP_DIR	/* TBD: change this location */

/* define commonly used sizes */
#define	KILO	(uint64_t)(1024LL)
#define	MEGA	(uint64_t)(1024LL * 1024)
#define	GIGA	(uint64_t)(1024LL * 1024 * 1024)
#define	TERA	(uint64_t)(1024LL * 1024 * 1024 * 1024)
#define	PETA	(uint64_t)(1024LL * 1024 * 1024 * 1024 * 1024)
#define	EXA	(uint64_t)(1024LL * 1024 * 1024 * 1024 * 1024 * 1024)


/* SMF service states */
typedef enum {
	ENABLE,
	DISABLE,
	REFRESH,
	RESTART,
	MAINTAIN,
	DEGRADE,
	RESTORE
} mms_svcstate_t;

/* data structures for setting options */

typedef struct {
	char		*name;
	char		*mmpopt;
	char		*defval;
	boolean_t	required;
	int		(*validate_func)(char *val);
} mms_mgmt_setopt_t;

#define	MGMT_ADD_ERR(errs, opt, in_err) { \
	if (errs) { \
		(void) nvlist_add_int32(errs, opt, in_err); \
	} \
}

#define	MGMT_ADD_OPTERR(errs, opt, in_err) { \
	if (in_err == ENOENT) { \
		in_err = MMS_MGMT_ERR_REQUIRED; \
	} \
	MGMT_ADD_ERR(errs, opt, in_err) \
}

/* function prototypes */

int
exec_mgmt_cmd(
	FILE		**outstr,
	FILE		**errstr,
	uid_t		euid,
	gid_t		egid,
	boolean_t	daemon,
	char		*cmd[]);

int
check_exit(pid_t pid, int *signo);

/*
 * mms_gen_taskid()
 *
 * Parameters:
 *	- tid		unique task identifier
 *
 * This function returns a task identifier (TID). All responses to an MMP
 * command will include the TID of the initiating command. The TID will be
 * unique in the context of a session so that the client can determine which
 * responses go with which command. tid must be a buffer of at least 128 bytes.
 */
int mms_gen_taskid(char *tid);

/*
 * create_mm_clnt()
 */
int
create_mm_clnt(char *app, char *inst, char *pass, char *tag, void **session);

int
mgmt_set_svc_state(
	char		*fmri,
	mms_svcstate_t	targetState,
	char		**original);

int
create_dir(char *dir, mode_t perms, char *user, uid_t uid, char *group,
	gid_t gid);

int cp_file(
	const char *old,
	const char *new);

/* helper function to use read() correctly */
int
readbuf(int fd, void* buffer, int len);

/*
 * mk_wc_path()
 *
 * Function to generate a path name for working copies of
 * files and creates the file.
 */
int
mk_wc_path(
	char *original,		/* IN - path to original file */
	char *tmppath,		/* IN/OUT - buffer to hold new file path */
	size_t buflen);		/* IN - length of buffer */


/*
 * make_working_copy()
 *
 * Copies a file to the default temporary location and returns
 * the pathname of the copy.
 *
 */
int
make_working_copy(char *path, char *wc_path, int pathlen);

int
find_process(char *exename, mms_list_t *procs);

void
mgmt_unsetall_cfgvar(void);

int
mgmt_xlate_cfgerr(scf_error_t in_err);

/* helper function for MMS lists */
void
mms_list_free_and_destroy(mms_list_t *, void (*)(void *));

/* helper validation functions */
int val_numonly(char *val);
int val_passwd(char *val);
int val_objtype(char *val);
int val_path(char *val);
int val_level(char *val);
int val_yesno(char *val);
int val_truefalse(char *val);
int val_mms_size(char *val);
int do_val_mms_size(char *val, uint64_t *bytes);
int val_density(char *val);


/* MMP helper functions */
int
mms_mgmt_send_cmd(void *sess, char *tid, char *cmd, char *pfx, void **response);

int
mmp_get_nvattrs(char *key,  boolean_t useropt, void *response, nvlist_t **nvl);

int
mmp_get_nvattrs_array(char *key, boolean_t useropt,
    void *response, nvlist_t *nvl);

int
mms_mgmt_mmp_count(void *response, uint32_t *count);

int
create_mmp_clause(char *objtype, mms_mgmt_setopt_t *opts, nvlist_t *inopts,
    nvlist_t *errs, char *cmd, size_t cmdlen);
int
mms_add_object(void *session, char *objtype, mms_mgmt_setopt_t *objopts,
    nvlist_t *nvl, nvlist_t *errs);

int
mgmt_find_changed_attrs(char *objtype, mms_mgmt_setopt_t *opts, nvlist_t *nvl,
    char **carray, int *count, nvlist_t *errs);

void
mk_set_clause(char *objtype, mms_mgmt_setopt_t *opts, char **carray,
    char *buf, int buflen);

void
cmp_mmp_opts(mms_mgmt_setopt_t *opts, char **carray, nvlist_t *nva, int *count);

char **
mgmt_var_to_array(nvlist_t *nvl, char *optname, int *count);

void
mgmt_free_str_arr(char **inarr, int count);

int
mgmt_opt_to_var(char *in_str, boolean_t allow_empty, nvlist_t *nvl);

int
mgmt_set_str_or_arr(char *inargs, char *key, nvlist_t *nvl);

int write_buf(int fd, void* buffer, int len);

int
mgmt_compare_hosts(char *host1, char *host2);

const char *
mms_mgmt_get_errstr(int errcode);

int
mgmt_chk_auth(char *authname);

int
mms_mgmt_get_pwd(char *pwfile, char *key, char *phrase[2], nvlist_t *nvl,
    nvlist_t *errs);

void
mgmt_filter_results(nvlist_t *filter, nvlist_t *nvl);

#endif /* _MGMT_UTIL_H */
