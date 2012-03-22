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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/* from S5R4 1.6 */

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

extern int intpexec(struct vnode *, struct execa *, struct uarg *,
    struct intpdata *, int, long *, int, caddr_t, struct cred *, int);

static struct execsw esw = {
	intpmagicstr,
	0,
	2,
	intpexec,
	NULL
};

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_execops;

static struct modlexec modlexec = {
	&mod_execops, "exec mod for interp", &esw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlexec, NULL
};

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * Crack open a '#!' line.
 */
static int
getintphead(struct vnode *vp, struct intpdata *idatap)
{
	int error;
	char *cp, *linep = idatap->intp;
	ssize_t resid;

	/*
	 * Read the entire line and confirm that it starts with '#!'.
	 */
	if (error = vn_rdwr(UIO_READ, vp, linep, INTPSZ, (offset_t)0,
	    UIO_SYSSPACE, 0, (rlim64_t)0, CRED(), &resid))
		return (error);
	if (resid > INTPSZ-2 || linep[0] != '#' || linep[1] != '!')
		return (ENOEXEC);
	/*
	 * Blank all white space and find the newline.
	 */
	for (cp = &linep[2]; cp < &linep[INTPSZ] && *cp != '\n'; cp++)
		if (*cp == '\t')
			*cp = ' ';
	if (cp >= &linep[INTPSZ])
		return (ENOEXEC);
	ASSERT(*cp == '\n');
	*cp = '\0';

	/*
	 * Locate the beginning and end of the interpreter name.
	 * In addition to the name, one additional argument may
	 * optionally be included here, to be prepended to the
	 * arguments provided on the command line.  Thus, for
	 * example, you can say
	 *
	 * 	#! /usr/bin/awk -f
	 */
	for (cp = &linep[2]; *cp == ' '; cp++)
		;
	if (*cp == '\0')
		return (ENOEXEC);
	idatap->intp_name = cp;
	while (*cp && *cp != ' ')
		cp++;
	if (*cp == '\0')
		idatap->intp_arg = NULL;
	else {
		*cp++ = '\0';
		while (*cp == ' ')
			cp++;
		if (*cp == '\0')
			idatap->intp_arg = NULL;
		else {
			idatap->intp_arg = cp;
			while (*cp && *cp != ' ')
				cp++;
			*cp = '\0';
		}
	}
	return (0);
}

int
intpexec(
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

	if (level) {		/* Can't recurse */
		error = ENOEXEC;
		goto bad;
	}

	ASSERT(idatap == (struct intpdata *)NULL);

	/*
	 * Allocate a buffer to read in the interpreter pathname.
	 */
	idata.intp = kmem_alloc(INTPSZ, KM_SLEEP);
	if (error = getintphead(vp, &idata))
		goto fail;

	/*
	 * Look the new vnode up.
	 */
	if (error = pn_get(idata.intp_name, UIO_SYSSPACE, &intppn))
		goto fail;
	pn_alloc(&resolvepn);
	if (error = lookuppn(&intppn, &resolvepn, FOLLOW, NULLVPP, &nvp)) {
		pn_free(&resolvepn);
		pn_free(&intppn);
		goto fail;
	}
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
		 * Close this executable as the interpreter
		 * will open and close it later on.
		 */
		(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, cred, NULL);
	}
done:
	VN_RELE(nvp);
	args->pathname = opath;
	pn_free(&resolvepn);
fail:
	kmem_free(idata.intp, INTPSZ);
	if (error && fd != -1)
		(void) execclose(fd);
bad:
	return (error);
}
