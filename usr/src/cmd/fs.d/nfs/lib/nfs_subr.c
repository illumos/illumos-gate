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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <rpcsvc/nlm_prot.h>
#include <sys/utsname.h>
#include <nfs/nfs.h>
#include "nfs_subr.h"
#include <errno.h>
#include <deflt.h>
#include <rpcsvc/daemon_utils.h>
#include "smfcfg.h"

#include <nfs/nfssys.h>
extern int _nfssys(enum nfssys_op, void *);

/*
 * This function is added to detect compatibility problem with SunOS4.x.
 * The compatibility problem exists when fshost cannot decode the request
 * arguments for NLM_GRANTED procedure.
 * Only in this case  we use local locking.
 * In any other case we use fshost's lockd for remote file locking.
 * Return value: 1 if we should use local locking, 0 if not.
 */
int
remote_lock(char *fshost, caddr_t fh)
{
	nlm_testargs rlm_args;
	nlm_res rlm_res;
	struct timeval timeout = { 5, 0};
	CLIENT *cl;
	enum clnt_stat rpc_stat;
	struct utsname myid;

	(void) memset((char *)&rlm_args, 0, sizeof (nlm_testargs));
	(void) memset((char *)&rlm_res, 0, sizeof (nlm_res));
	/*
	 * Assign the hostname and the file handle for the
	 * NLM_GRANTED request below.  If for some reason the uname call fails,
	 * list the server as the caller so that caller_name has some
	 * reasonable value.
	 */
	if (uname(&myid) == -1)  {
		rlm_args.alock.caller_name = fshost;
	} else {
		rlm_args.alock.caller_name = myid.nodename;
	}
	rlm_args.alock.fh.n_len = sizeof (fhandle_t);
	rlm_args.alock.fh.n_bytes = fh;

	cl = clnt_create(fshost, NLM_PROG, NLM_VERS, "datagram_v");
	if (cl == NULL)
		return (0);

	rpc_stat = clnt_call(cl, NLM_GRANTED,
	    xdr_nlm_testargs, (caddr_t)&rlm_args,
	    xdr_nlm_res, (caddr_t)&rlm_res, timeout);
	clnt_destroy(cl);

	return (rpc_stat == RPC_CANTDECODEARGS);
}

#define	fromhex(c)  ((c >= '0' && c <= '9') ? (c - '0') : \
			((c >= 'A' && c <= 'F') ? (c - 'A' + 10) :\
			((c >= 'a' && c <= 'f') ? (c - 'a' + 10) : 0)))

/*
 * The implementation of URLparse guarantees that the final string will
 * fit in the original one. Replaces '%' occurrences followed by 2 characters
 * with its corresponding hexadecimal character.
 */
void
URLparse(char *str)
{
	char *p, *q;

	p = q = str;
	while (*p) {
		*q = *p;
		if (*p++ == '%') {
			if (*p) {
				*q = fromhex(*p) * 16;
				p++;
				if (*p) {
					*q += fromhex(*p);
					p++;
				}
			}
		}
		q++;
	}
	*q = '\0';
}

/*
 * Convert from URL syntax to host:path syntax.
 */
int
convert_special(char **specialp, char *host, char *oldpath, char *newpath,
    char *cur_special)
{

	char *url;
	char *newspec;
	char *p;
	char *p1, *p2;

	/*
	 * Rebuild the URL. This is necessary because parse replica
	 * assumes that nfs: is the host name.
	 */
	url = malloc(strlen("nfs:") + strlen(oldpath) + 1);

	if (url == NULL)
		return (-1);

	strcpy(url, "nfs:");
	strcat(url, oldpath);

	/*
	 * If we haven't done any conversion yet, allocate a buffer for it.
	 */
	if (*specialp == NULL) {
		newspec = *specialp = strdup(cur_special);
		if (newspec == NULL) {
			free(url);
			return (-1);
		}

	} else {
		newspec = *specialp;
	}

	/*
	 * Now find the first occurence of the URL in the special string.
	 */
	p = strstr(newspec, url);

	if (p == NULL) {
		free(url);
		return (-1);
	}

	p1 = p;
	p2 = host;

	/*
	 * Overwrite the URL in the special.
	 *
	 * Begin with the host name.
	 */
	for (;;) {
		/*
		 * Sine URL's take more room than host:path, there is
		 * no way we should hit a null byte in the original special.
		 */
		if (*p1 == '\0') {
			free(url);
			free(*specialp);
			*specialp = NULL;
			return (-1);
		}

		if (*p2 == '\0') {
			break;
		}

		*p1 = *p2;
		p1++;
		p2++;
	}

	/*
	 * Add the : separator.
	 */
	*p1 = ':';
	p1++;

	/*
	 * Now over write into special the path portion of host:path in
	 */
	p2 = newpath;
	for (;;) {
		if (*p1 == '\0') {
			free(url);
			free(*specialp);
			*specialp = NULL;
			return (-1);
		}
		if (*p2 == '\0') {
			break;
		}
		*p1 = *p2;
		p1++;
		p2++;
	}

	/*
	 * Now shift the rest of original special into the gap created
	 * by replacing nfs://host[:port]/path with host:path.
	 */
	p2 = p + strlen(url);
	for (;;) {
		if (*p1 == '\0') {
			free(url);
			free(*specialp);
			*specialp = NULL;
			return (-1);
		}
		if (*p2 == '\0') {
			break;
		}
		*p1 = *p2;
		p1++;
		p2++;
	}

	*p1 = '\0';

	free(url);
	return (0);
}

#define	AUTOFS_MOUNT_TIMEOUT	600	/* default min time mount will */

void
set_nfsv4_ephemeral_mount_to(void)
{
	char valbuf[6];
	int bufsz = sizeof (valbuf);

	uint_t mount_to = AUTOFS_MOUNT_TIMEOUT;

	/*
	 * Get the value from SMF
	 */
	if (autofs_smf_get_prop("timeout", valbuf, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, AUTOMOUNTD, &bufsz) == SA_OK) {
		const char *errstr;
		uint_t val = strtonum(valbuf, 0, UINT_MAX, &errstr);
		if (errstr == NULL)
			mount_to = val;
	}

	(void) _nfssys(NFS4_EPHEMERAL_MOUNT_TO, &mount_to);
}
