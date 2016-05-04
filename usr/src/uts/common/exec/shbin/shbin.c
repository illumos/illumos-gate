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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/pathname.h>
#include <sys/disp.h>
#include <sys/exec.h>
#include <sys/kmem.h>
#include <sys/note.h>

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

/* Local prototypes */
static int
shbinexec(
	struct vnode *vp,
	struct execa *uap,
	struct uarg *args,
	struct intpdata *idatap,
	int level,
	long *execsz,
	int setid,
	caddr_t exec_file,
	struct cred *cred,
	int brand_action);

#define	SHBIN_CNTL(x)	((x)&037)
#define	SHBINMAGIC_LEN	4
extern char shbinmagicstr[];

/*
 * Our list where we may find a copy of ksh93. The ordering is:
 * 1. 64bit (may not be installed or not supported in hardware)
 * 2. 32bit
 * 3. Use /sbin/ksh93 when /usr is not available
 *
 * ([1] and [2] explicitly bypass /usr/bin/ksh93 to avoid the
 * isaexec overhead).
 */
static char *shell_list[] =
{
/* Bypass /usr/bin/ksh93 (which is "isaexec") for performance */
#if defined(__sparc)
	"/usr/bin/sparcv9/ksh93",
	"/usr/bin/sparcv7/ksh93",
#elif defined(__amd64)
	"/usr/bin/amd64/ksh93",
	"/usr/bin/i86/ksh93",
#elif defined(__i386)
	"/usr/bin/i86/ksh93",
#else
#error "Unrecognized platform/CPU (use /usr/bin/ksh93 when in doubt)."
#endif
	"/sbin/ksh93",
	NULL
};

static struct execsw esw = {
	shbinmagicstr,
	0,
	SHBINMAGIC_LEN,
	shbinexec,
	NULL
};

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_execops;

static struct modlexec modlexec = {
	&mod_execops, "exec mod for shell binaries (ksh93)", &esw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlexec, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
checkshbinmagic(struct vnode *vp)
{
	int error;
	char linep[SHBINMAGIC_LEN];
	ssize_t resid;

	/*
	 * Read the entire line and confirm that it starts with the magic
	 * sequence for compiled ksh93 shell scripts.
	 */
	if (error = vn_rdwr(UIO_READ, vp, linep, sizeof (linep), (offset_t)0,
	    UIO_SYSSPACE, 0, (rlim64_t)0, CRED(), &resid))
		return (error);

	if (memcmp(linep, shbinmagicstr, SHBINMAGIC_LEN) != 0)
		return (ENOEXEC);

	return (0);
}

static int
shbinexec(
	struct vnode *vp,
	struct execa *uap,
	struct uarg *args,
	struct intpdata *idatap,
	int level,
	long *execsz,
	int setid,
	caddr_t exec_file,
	struct cred *cred,
	int brand_action)
{
	_NOTE(ARGUNUSED(brand_action))
	vnode_t *nvp;
	int error = 0;
	struct intpdata idata;
	struct pathname intppn;
	struct pathname resolvepn;
	char *opath;
	char devfd[19]; /* 32-bit int fits in 10 digits + 8 for "/dev/fd/" */
	int fd = -1;
	int i;

	if (level) {		/* Can't recurse */
		error = ENOEXEC;
		goto bad;
	}

	ASSERT(idatap == (struct intpdata *)NULL);

	/*
	 * Check whether the executable has the correct magic value.
	 */
	if (error = checkshbinmagic(vp))
		goto fail;

	pn_alloc(&resolvepn);

	/*
	 * Travel the list of shells and look for one which is available...
	 */
	for (i = 0; shell_list[i] != NULL; i++) {
		error = pn_get(shell_list[i], UIO_SYSSPACE, &intppn);
		if (error != 0) {
			break;
		}

		error = lookuppn(&intppn, &resolvepn, FOLLOW, NULLVPP, &nvp);
		if (!error) {
			/* Found match */
			break;
		}

		/* No match found ? Then continue with the next item... */
		pn_free(&intppn);
	}

	if (error) {
		pn_free(&resolvepn);
		goto fail;
	}

	/*
	 * Setup interpreter data
	 * "--" is passed to mark the end-of-arguments before adding
	 * the scripts file name, preventing problems when a
	 * a script's name starts with a '-' character.
	 */
	idata.intp = NULL;
	idata.intp_name[0] = shell_list[i];
	idata.intp_arg[0] = "--";

	opath = args->pathname;
	args->pathname = resolvepn.pn_path;
	/* don't free resolvepn until we are done with args */
	pn_free(&intppn);

	/*
	 * When we're executing a set-uid script resulting in uids
	 * mismatching or when we execute with additional privileges,
	 * we close the "replace script between exec and open by shell"
	 * hole by passing the script as /dev/fd parameter.
	 */
	if ((setid & EXECSETID_PRIVS) != 0 ||
	    (setid & (EXECSETID_UGIDS|EXECSETID_SETID)) ==
	    (EXECSETID_UGIDS|EXECSETID_SETID)) {
		(void) strcpy(devfd, "/dev/fd/");
		if (error = execopen(&vp, &fd))
			goto done;
		numtos(fd, &devfd[8]);
		args->fname = devfd;
	}

	error = gexec(&nvp, uap, args, &idata, ++level, execsz, exec_file, cred,
	    EBA_NONE);

	if (!error) {
		/*
		 * Close this script as the sh interpreter
		 * will open and close it later on.
		 */
		(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, cred, NULL);
	}
done:
	VN_RELE(nvp);
	args->pathname = opath;
	pn_free(&resolvepn);
fail:
	if (error && fd != -1)
		(void) execclose(fd);
bad:
	return (error);
}
