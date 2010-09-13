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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <malloc.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <limits.h>
#include <meta.h>
#include <svm.h>
#include <libsvm.h>

#define	MODEBITS	(S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO)
#define	ISREG(A)	(((A).st_mode & S_IFMT) == S_IFREG)
#define	DEFAULT_ROOTDIR "/a"


/*
 * FUNCTION: svm_start
 *	starts SDS/SVM configuration. If root mirroring exists then the
 *	components of the root mirror are returned in svmpp.
 *
 * INPUT: mntpnt - root mount point
 *	  svmpp - prealloced structure to return components
 *	  repl_state_flag - SVM_CONV/SVM_DONT_CONV
 *
 * RETURN:
 *	  0 - SUCCESS
 *	  !0 - ERROR
 *	  if > 0 errno
 */

int
svm_start(char *mntpnt, svm_info_t **svmpp, int repl_state_flag)
{
	char *rootdir, *tf;
	char *mdevnamep = NULL;
	char system_file[PATH_MAX];
	char mdconf[PATH_MAX];
	int rval = 0;

	if (mntpnt == NULL)
		rootdir = DEFAULT_ROOTDIR;
	else
		rootdir = mntpnt;

	if ((rval = snprintf(system_file, PATH_MAX, "%s%s",
					rootdir, SYSTEM_FILE)) < 0) {
		return (RET_ERROR);
	}

	if ((rval = snprintf(mdconf, PATH_MAX, "%s%s",
					rootdir, MD_CONF)) < 0) {
		return (RET_ERROR);
	}

	debug_printf("svm_start(): repl_state_flag %s\n",
		(repl_state_flag == SVM_DONT_CONV) ? "SVM_DONT_CONV":
						"SVM_CONV");

	if (copyfile(MD_CONF, MD_CONF_ORIG))
		return (RET_ERROR);

	switch (rval = convert_bootlist(system_file, mdconf, &tf)) {
		case 0:
		case -1:			/* found in etc/system flag */
			break;
		default: /* convert bootlist failed */
			debug_printf("svm_start(): convert_bootlist failed."
					"rval %d\n", rval);
			goto errout;
	}

	if (repl_state_flag == SVM_DONT_CONV) {
		rval = create_in_file_prop(PROP_KEEP_REPL_STATE, tf);
		if (rval != 0)
			goto errout;
	}

	if (is_upgrade_prop(PROP_DEVID_DESTROY)) {
		rval = create_in_file_prop(PROP_DEVID_DESTROY, tf);
		/*
		 * For the idempotent behavior reset internal
		 * flag incase we have to return due to errors
		 */
		set_upgrade_prop(PROP_DEVID_DESTROY, 0);
		if (rval != 0)
			goto errout;
	}


	/*
	 * Since svm_start is called only after svm_check,
	 * we can assume that there is a valid metadb. If the mddb_bootlist
	 * is not found in etc/system, then it must be in md.conf which
	 * we copied to temporary file pointed to by tf
	 */
	if (copyfile(tf, MD_CONF)) {
		debug_printf("svm_start(): copy of %s to %s failed\n", tf,
			MD_CONF);
		goto errout;
	}

	if ((rval = write_xlate_to_mdconf(rootdir)) != 0) {
		debug_printf("svm_start(): write_xlate_to_mdconf(%s) failed\n",
				rootdir);
		goto errout;
	}

	if ((rval = write_targ_nm_table(rootdir)) != 0) {
		goto errout;
	}

	/* run devfsadm to create the devices specified in md.conf */
	if ((rval = system("/usr/sbin/devfsadm -r /tmp -p "
		"/tmp/root/etc/path_to_inst -i md")) != 0) {
		debug_printf("svm_start(): devfsadm -i md failed: %d\n", rval);
		goto errout;
	}

	/*
	 * We have to unload md after the devfsadm run so that when metainit
	 * loads things it gets the right information from md.conf.
	 */
	if (rval = svm_stop()) {
		debug_printf("svm_start(): svm_stop failed.\n");
		return (RET_ERROR);
	}

	if ((rval = system("/usr/sbin/metainit -r")) != 0) {
		debug_printf("svm_start(): metainit -r failed: %d\n", rval);
		goto errout;
	}

	create_diskset_links();

	if ((rval = system("/usr/sbin/metasync -r")) != 0) {
		debug_printf("svm_start(): metasync -r failed: %d\n", rval);
		goto errout;
	}

	/*
	 * We ignore failures from metadevadm, since it can fail if
	 * miniroot dev_t's don't match target dev_ts. But it still
	 * will update md.conf with device Id information which is
	 * why we are calling it here.
	 */

	(void) system("/usr/sbin/metadevadm -r");

	/*
	 * check to see if we have a root metadevice and if so
	 *  get its components.
	 */

	if ((rval = get_rootmetadevice(rootdir, &mdevnamep)) == 0) {
		if (rval = get_mdcomponents(mdevnamep, svmpp)) {
			debug_printf("svm_start(): get_mdcomponents(%s,..)"
				"failed %d\n", mdevnamep, rval);
			goto errout;
		}

	} else {
		rval = 0; /* not a mirrored root */
		debug_printf("svm_start(): get_rootmetadevice(%s,..) "
			"No root mirrors! ", rootdir);
	}
errout:
	free(mdevnamep);
	if (rval != 0) {
		struct stat sbuf;
		if (stat(MD_CONF_ORIG, &sbuf) == 0)
			(void) copyfile(MD_CONF_ORIG, MD_CONF);
		debug_printf("svm_start(): svm_start failed: %d\n", rval);
	} else {
		int i;

		if ((*svmpp)->count > 0) {
			debug_printf("svmpp: ");
			debug_printf("    root_md: %s", (*svmpp)->root_md);
			debug_printf("    count: %d", (*svmpp)->count);
			for (i = 0; i < (*svmpp)->count; i++) {
				debug_printf("    md_comps[%d]: %s", i,
				(*svmpp)->md_comps[i]);
			}
			debug_printf(" \n");
		} else {
			if ((*svmpp)->count == 0)
				debug_printf("svm_start(): no mirrored root\n");
		}
		debug_printf("svm_start(): svm_start succeeded.\n");
	}
	return (rval);
}

/*
 * FUNCTION: copyfile
 *
 * INPUT: self descriptive
 *
 * RETURN:
 *	RET_SUCCESS
 *	RET_ERROR
 */
int
copyfile(char *from, char *to)
{
	int fromfd, tofd;
	char buf[1024];
	ssize_t	rbytes;
	struct stat fromstat;

	if ((fromfd = open(from, O_RDONLY | O_NDELAY)) < 0)
		return (RET_ERROR);

	if ((fstat(fromfd, &fromstat) < 0) || ! ISREG(fromstat)) {
		(void) close(fromfd);
		return (RET_ERROR);
	}

	if ((tofd = open(to, O_CREAT | O_WRONLY | O_TRUNC,
		(fromstat.st_mode & MODEBITS))) < 0) {
		(void) close(fromfd);
		return (RET_ERROR);
	}

	/*
	 * in case the file exists then perm is forced by this chmod
	 */
	(void) fchmod(tofd, fromstat.st_mode & MODEBITS);

	for (;;) {
		rbytes = read(fromfd, buf, sizeof (buf));
		/*
		 * no need to check for negative values since the file
		 * has been successfully stat'ed
		 */
		if (rbytes == 0)
			break;
		if (write(tofd, buf, rbytes) != rbytes) {
				rbytes = -1;
				break;
		}
	}

	(void) close(fromfd);
	(void) close(tofd);
	if (rbytes < 0) {
		(void) unlink(to);
		return (RET_ERROR);
	}
	return (RET_SUCCESS);
}
