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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>
#include <string.h>
#include <syslog.h>
#include <locale.h>
#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfssys.h>
#include <nfs/nfs_log.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <nfs/nfs_log.h>
#include "../lib/nfslog_config.h"
#include "buffer_list.h"
#include "nfslogd.h"

extern int _nfssys(int, void *);

/*
 * simple list used to keep track of bad tag messages syslogged.
 */
struct nfs_log_list {
	char *l_name;
	struct nfs_log_list *l_next;
};

static void badtag_notify(char *tag);
static struct nfs_log_list *badtag_list = NULL;

static void cleanup_elf_state(nfsl_config_t *);
static void cleanup_trans_state(nfsl_config_t *);

/*
 * Read the contents of the 'bufferpath', process them and store the
 * user-readable log in 'elfpath', updating the 'fhpath' filehandle
 * table.
 * The contents of the configuration list (*config_list) may be
 * modified if the configuration file has been updated and we can not
 * find the configuration entry in the currently loaded list.
 *
 * Returns 0 on success and sets *buffer_processed to 1.
 *	   non zero error on failure and *buffer_processed set to 0.
 */
int
process_buffer(
	struct buffer_ent *bep,
	nfsl_config_t **config_list,
	int min_size,
	int idle_time,
	int *buffer_processed)
{
	struct stat st;
	struct nfsl_flush_args nfa;
	struct nfslog_buf *lbp = NULL;
	struct nfslog_lr *lrp;
	char *path1 = NULL;
	char *path2 = NULL;
	char *buffer_inprog = NULL;
	int buffer_inprog_len;
	int error = 0;
	nfsl_config_t *ncp = NULL, *last_good_ncp;
	char *bufferpath = bep->be_name;
	char *tag;
	boolean_t elf_checked = B_FALSE;
	boolean_t trans_checked = B_FALSE;

	assert(buffer_processed != NULL);
	assert(bufferpath != NULL);

	if (stat(bufferpath, &st) == -1) {
		error = errno;
		if (error == ENOENT) {
			error = 0;
			buffer_inprog_len = strlen(bufferpath) +
			    strlen(LOG_INPROG_STRING) + 1;
			buffer_inprog = (char *)malloc(buffer_inprog_len);
			if (buffer_inprog == NULL) {
				syslog(LOG_ERR, gettext(
				    "process_buffer: malloc failed"));
				return (ENOMEM);
			}
			(void) sprintf(buffer_inprog, "%s%s", bufferpath,
			    LOG_INPROG_STRING);

			if (stat(buffer_inprog, &st) == -1) {
				error = errno;
				if (bep->be_error != error) {
					syslog(LOG_ERR, gettext(
					    "Can not stat %s: %s"),
					    buffer_inprog, strerror(error));
				}
				free(buffer_inprog);
				return (error);
			}

			free(buffer_inprog);

			/*
			 * Does the buffer in progress meet our minimum
			 * processing requirements? or has it been around
			 * longer than we're willing to wait for more
			 * data to be logged?
			 */
			if ((st.st_size < min_size) &&
			    ((time(0) - bep->be_lastprocessed) < idle_time)) {
				/*
				 * The buffer does not meet the minimum
				 * size processing requirements, and it has not
				 * been around longer than we're willing to
				 * wait for more data collection.
				 * We return now without processing it.
				 */
				return (0);
			}

			/*
			 * Issue the LOG_FLUSH system call to flush the
			 * buffer and process it.
			 */
			(void) memset((void *)&nfa, 0, sizeof (nfa));
			nfa.version = NFSL_FLUSH_ARGS_VERS;
			nfa.directive = NFSL_RENAME | NFSL_SYNC;
			nfa.buff = bufferpath;
			nfa.buff_len = strlen(bufferpath) + 1;

			if (_nfssys(LOG_FLUSH, &nfa) < 0) {
				error = errno;
				if (bep->be_error != error) {
					syslog(LOG_ERR, gettext(
					    "_nfssys(%s) failed: %s"),
					    nfa.buff, strerror(error));
				}
				return (error);
			}
		} else {
			if (bep->be_error != error) {
				syslog(LOG_ERR, gettext("Can not stat %s: %s"),
				    bufferpath, strerror(error));
			}
			return (error);
		}
	}

	/*
	 * Open and lock input buffer.
	 * Passes in the value of the last error so that it will not
	 * print it again if it is still hitting the same error condition.
	 */
	error = bep->be_error;
	if ((lbp = nfslog_open_buf(bufferpath, &error)) == NULL)
		goto done;

	if ((ncp = last_good_ncp =
	    nfsl_findconfig(*config_list, "global", &error)) == NULL) {
		assert(error != 0);
		nfsl_freeconfig_list(config_list);
		if (error != bep->be_error) {
			syslog(LOG_ERR, gettext(
			    "Could not search config list: %s"),
			    strerror(error));
		}
		goto done;
	}

	assert(error == 0);
	while ((lrp = nfslog_get_logrecord(lbp)) != NULL && keep_running) {

		if (*buffer_processed == 0)
			(*buffer_processed)++;

		/*
		 * Get the matching config entry.
		 */
		tag = lrp->log_record.re_tag;
		if (strcmp(tag, last_good_ncp->nc_name) != 0) {
			ncp = nfsl_findconfig(*config_list, tag, &error);
			if (error) {
				if (error != bep->be_error) {
					syslog(LOG_ERR, gettext(
					    "Could not search config list: %s"),
					    strerror(error));
				}
				nfsl_freeconfig_list(config_list);
				goto done;
			}
			if (ncp == NULL) {
				badtag_notify(tag);
				ncp = last_good_ncp;
				goto skip;
			}
			last_good_ncp = ncp;
		}

		if (ncp->nc_flags & NC_UPDATED) {
			/*
			 * The location of the log files may have changed,
			 * we need to close transactions and invalidate
			 * cookies so that the log files can be reopened
			 * further down.
			 */
			cleanup_elf_state(ncp);
			cleanup_trans_state(ncp);

			ncp->nc_flags &= ~NC_UPDATED;

			/*
			 * Force cookies to be recreated if necessary.
			 */
			elf_checked = trans_checked = B_FALSE;
		}

		/*
		 * Open output files.
		 */
		if (ncp->nc_rpclogpath != NULL) {
			/*
			 * Log rpc requests in W3C-ELF format.
			 */
			if (!elf_checked && ncp->nc_elfcookie != NULL) {
				/*
				 * Make sure file still exists.
				 * Do this once per buffer.
				 */
				if (stat(ncp->nc_rpclogpath, &st) == -1 &&
				    errno == ENOENT) {
					/*
					 * The open rpclogfile has been
					 * deleted.  Get new one below.
					 */
					cleanup_elf_state(ncp);
				}
				elf_checked = B_TRUE;
			}
			if (ncp->nc_elfcookie == NULL) {
				error = bep->be_error;
				ncp->nc_elfcookie = nfslog_open_elf_file(
				    ncp->nc_rpclogpath, &lbp->bh, &error);
				if (ncp->nc_elfcookie == NULL) {
					bep->be_error = error;
					goto done;
				}
			}
		}

		if (ncp->nc_logpath != NULL) {
			/*
			 * Log rpc reqs in trans/ftp format.
			 */
			if (!trans_checked && ncp->nc_transcookie != NULL) {
				/*
				 * Do this once per buffer.
				 */
				if (stat(ncp->nc_logpath, &st) == -1 &&
				    errno == ENOENT) {
					/*
					 * The open transaction file has been
					 * deleted. Close pending transaction
					 * work. A new transaction log will be
					 * opened by nfslog_open_trans_file()
					 * below.
					 */
					cleanup_trans_state(ncp);
				}
				trans_checked = B_TRUE;
			}
			if (ncp->nc_transcookie == NULL) {
				int transtolog;

				transtolog =
				    (ncp->nc_logformat == TRANSLOG_BASIC) ?
				    TRANSTOLOG_OPER_READWRITE : TRANSTOLOG_ALL;
				error = bep->be_error;
				ncp->nc_transcookie = nfslog_open_trans_file(
				    ncp->nc_logpath, ncp->nc_logformat,
				    transtolog, &error);
				if (ncp->nc_transcookie == NULL) {
					bep->be_error = error;
					goto done;
				}
			}
		}

		assert(ncp->nc_fhpath != NULL);

		if (nfslog_process_fh_rec(lrp, ncp->nc_fhpath, &path1, &path2,
		    ncp->nc_elfcookie != NULL)) {
			/*
			 * Make sure there is room.
			 */
			if (ncp->nc_elfcookie != NULL) {
				(void) nfslog_process_elf_rec(ncp->nc_elfcookie,
				    &lrp->log_record, path1, path2);
			}

			if (ncp->nc_transcookie != NULL) {
				(void) nfslog_process_trans_rec(
				    ncp->nc_transcookie,
				    &lrp->log_record, ncp->nc_fhpath,
				    path1, path2);
			}
		}

skip:		if (path1 != NULL)
			free(path1);
		if (path2 != NULL)
			free(path2);

		path1 = path2 = NULL;
		nfslog_free_logrecord(lrp, TRUE);
	} /* while */

	if (!error && keep_running) {
		/*
		 * Keep track of when this buffer was last processed.
		 */
		bep->be_lastprocessed = time(0);

		if (test && *buffer_processed != 0) {
			/*
			 * Save the buffer for future debugging. We do this
			 * by following the log cycling policy, with a maximum
			 * of 'max_logs_preserve' to save.
			 */
			if (cycle_log(bufferpath, max_logs_preserve)) {
				syslog(LOG_ERR, gettext(
				    "could not save copy of buffer \"%s\""),
				    bufferpath);
			}
		} else {
			/*
			 * Remove buffer since it has been processed.
			 */
			if (unlink(bufferpath)) {
				error = errno;
				syslog(LOG_ERR, gettext(
				    "could not unlink %s: %s"),
				    bufferpath, strerror(error));
				/*
				 * Buffer was processed correctly.
				 */
				error = 0;
			}
		}
	}

done:
	if (lbp != NULL)
		nfslog_close_buf(lbp, quick_cleaning);
	if (ncp && !quick_cleaning)
		cleanup_elf_state(ncp);

	return (error);
}

static void
cleanup_elf_state(nfsl_config_t *ncp)
{
	if (ncp->nc_elfcookie != NULL) {
		nfslog_close_elf_file(&ncp->nc_elfcookie);
		assert(ncp->nc_elfcookie == NULL);
	}
}

static void
cleanup_trans_state(nfsl_config_t *ncp)
{
	if (ncp->nc_transcookie != NULL) {
		nfslog_close_transactions(&ncp->nc_transcookie);
		assert(ncp->nc_transcookie == NULL);
	}
}

/*
 * Searches the list of previously seen bad tags. Note that this
 * list is never pruned. This should not be a problem since the
 * list of bad tags should be fairl small. New entries are inserted
 * at the beginning of the list assuming it will be accessed more
 * frequently since we have just seen it.
 */
static void
badtag_notify(char *tag)
{
	struct nfs_log_list *lp, *p;
	int error;

	for (p = badtag_list; p != NULL; p = p->l_next) {
		if (strcmp(tag, p->l_name) == 0) {
			/*
			 * We've seen this before, nothing to do.
			 */
			return;
		}
	}

	/*
	 * Not on the list, add it.
	 */
	syslog(LOG_ERR, gettext("tag \"%s\" not found in %s - "
	    "ignoring records referencing such tag."),
	    tag, NFSL_CONFIG_FILE_PATH);

	if ((lp = (struct nfs_log_list *)malloc(sizeof (*lp))) != NULL) {
		if ((lp->l_name = strdup(tag)) != NULL) {
			lp->l_next = badtag_list;
			badtag_list = lp;
			return;		/* done */
		}
	}

	if (lp->l_name != NULL)
		free(lp->l_name);
	if (lp)
		free(lp);
	error = errno;
	syslog(LOG_ERR, gettext(
	    "Cannot add \"%s\" to bad tag list: %s"), tag, strerror(error));
}
