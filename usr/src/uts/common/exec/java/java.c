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

/*
 * Launch Java executables via exec(2).
 *
 * Java executables are platform-independent executable files
 * based on the JAR file format.  Executable JAR files contain a
 * special 'extra field' header in the first file of the archive
 * that marks the file as a true executable.   The data in that field
 * is used to pass additional run-time information to the Java VM.
 *
 * This handler looks for the appropriate magic number on the
 * front of the file, checks that the JAR file is executable, then
 * invokes the Java runtime environment to do the rest of the work.
 */

#include <sys/types.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/exec.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/pathname.h>

/*
 * These variables can be tweaked via /etc/system to allow prototyping
 * and debugging.  See PSARC/1997/123.
 *
 * Modified by PSARC/1999/012 to be Contract Private between Solaris and
 * the Java Technology Group.  It is expected that any future change to
 * these variables be coordinated between the consolidations.
 */
#if defined(__sparc)
char *jexec = "/usr/java/jre/lib/sparc/jexec";
#elif defined(__i386) || defined(__i386_COMPAT)
char *jexec = "/usr/java/jre/lib/i386/jexec";
#else
#error "Unknown ISA"
#endif
char *jexec_arg = "-jar";

/*
 * ZIP/JAR file header information
 */
#define	SIGSIZ		4
#define	LOCSIG		"PK\003\004"
#define	LOCHDRSIZ	30

#define	CH(b, n)	(((unsigned char *)(b))[n])
#define	SH(b, n)	(CH(b, n) | (CH(b, n+1) << 8))
#define	LG(b, n)	(SH(b, n) | (SH(b, n+2) << 16))

#define	LOCNAM(b)	(SH(b, 26))	/* filename size */
#define	LOCEXT(b)	(SH(b, 28))	/* extra field size */

#define	XFHSIZ		4		/* header id, data size */
#define	XFHID(b)	(SH(b, 0))	/* extract field header id */
#define	XFDATASIZ(b)	(SH(b, 2))	/* extract field data size */
#define	XFJAVASIG	0xcafe		/* java executables */

/*ARGSUSED3*/
static int
javaexec(vnode_t *vp, struct execa *uap, struct uarg *args,
    struct intpdata *idatap, int level, long *execsz, int setid,
    caddr_t execfile, cred_t *cred, int brand_action)
{
	struct intpdata idata;
	int error;
	ssize_t resid;
	vnode_t *nvp;
	off_t xoff, xoff_end;
	char lochdr[LOCHDRSIZ];
	struct pathname lookpn;
	struct pathname resolvepn;
	char *opath;

	if (level)
		return (ENOEXEC);	/* no recursion */

	/*
	 * Read in the full local file header, and validate
	 * the initial signature.
	 */
	if ((error = vn_rdwr(UIO_READ, vp, lochdr, sizeof (lochdr),
	    0, UIO_SYSSPACE, 0, (rlim64_t)0, cred, &resid)) != 0)
		return (error);
	if (resid != 0 || strncmp(lochdr, LOCSIG, SIGSIZ) != 0)
		return (ENOEXEC);

	/*
	 * Ok, so this -is- a ZIP file, and might even be a JAR file.
	 * Is it a Java executable?
	 */
	xoff = sizeof (lochdr) + LOCNAM(lochdr);
	xoff_end = xoff + LOCEXT(lochdr);

	while (xoff < xoff_end) {
		char xfhdr[XFHSIZ];

		if ((error = vn_rdwr(UIO_READ, vp, xfhdr, sizeof (xfhdr),
		    xoff, UIO_SYSSPACE, 0, (rlim64_t)0, cred, &resid)) != 0)
			return (error);
		if (resid != 0)
			return (ENOEXEC);
		if (XFHID(xfhdr) == XFJAVASIG)
			break;
		xoff += sizeof (xfhdr) + XFDATASIZ(xfhdr);
	}

	if (xoff >= xoff_end)
		return (ENOEXEC);

	/*
	 * Note: If we ever make setid execution work, we need to ensure
	 * that we use /dev/fd to avoid the classic setuid shell script
	 * security hole.
	 */
	if (setid)
		return (EACCES);

	/*
	 * Find and invoke the Java runtime environment on the file
	 */
	idata.intp = NULL;
	idata.intp_name[0] = jexec;
	idata.intp_arg[0] = jexec_arg;
	if (error = pn_get(idata.intp_name[0], UIO_SYSSPACE, &lookpn))
		return (error);
	pn_alloc(&resolvepn);
	if (error = lookuppn(&lookpn, &resolvepn, FOLLOW, NULLVPP, &nvp)) {
		pn_free(&resolvepn);
		pn_free(&lookpn);
		return (ENOEXEC);
	}
	opath = args->pathname;
	args->pathname = resolvepn.pn_path;
	/* don't free resolvepn until we are done with args */
	pn_free(&lookpn);
	error = gexec(&nvp, uap, args, &idata, level + 1, execsz, execfile,
	    cred, EBA_NONE);

	if (!error) {
		/*
		 * Close this Java executable as the interpreter
		 * will open and close it later on.
		 */
		(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, cred, NULL);
	}

	VN_RELE(nvp);
	args->pathname = opath;
	pn_free(&resolvepn);
	return (error);
}

static struct execsw jexecsw = {
	javamagicstr,
	0,
	4,
	javaexec,
	NULL
};

static struct modlexec jmodlexec = {
	&mod_execops, "exec for Java", &jexecsw
};

static struct modlinkage jmodlinkage = {
	MODREV_1, &jmodlexec, NULL
};

int
_init(void)
{
	return (mod_install(&jmodlinkage));
}

int
_fini(void)
{
	return (mod_remove(&jmodlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&jmodlinkage, modinfop));
}
