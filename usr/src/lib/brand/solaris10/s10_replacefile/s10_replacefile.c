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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <unistd.h>

/*
 * This program aids the Solaris 10 patch tools (specifically
 * /usr/lib/patch/patch_common_lib) in DAP patching.
 *
 * Whenever the patch tools replace a critical system component (e.g.,
 * /lib/libc.so.1), they move the old component to a temporary location,
 * move the new component to where the old component was, and establish
 * an overlay mount of the old component on top of the new component.
 * The patch tools do this with a shell script; consequently, the three
 * operations occur in three processes.
 *
 * This doesn't work inside Solaris 10 Containers (S10Cs).  Suppose the
 * patch tools need to replace /lib/libc.so.1.  The tools will move the old
 * libc.so.1 to a temporary location.  But when they try to move the new
 * libc.so.1, they fork a mv(1) process, which loads the solaris10 brand's
 * emulation library.  The emulation library will try to load the zone's
 * libc.so.1, but the library no longer exists; consequently, the emulation
 * library aborts and the zone's users won't be able to start any processes.
 *
 * This program solves the problem by combining the move and mount operations
 * into a single process.  The emulation library will already have loaded
 * libc.so.1 for the process by the time the process starts to replace
 * libc.so.1.
 *
 * This program takes six parameters that correspond to six variables within
 * /usr/lib/patch/patch_common_lib:InstallSafemodeObject():
 *
 *	argv[1] - dstActual (the path to the file that will be replaced)
 *	argv[2] - tmp_file (the temporary location to which the file will be
 *		moved)
 *	argv[3] - tmpDst (the path to the replacement file)
 *	argv[4] - tmpFile (the path to a temporary copy of the running system's
 *		version of the file being replaced; the source [special] of
 *		the overlay mount)
 *	argv[5] - cksumTmpDst (checksum of the file represented by tmpDst)
 *	argv[6] - cksumTmpFile (checksum of the file represented by tmpFile)
 *
 * NOTE: This program will only establish an overlay mount if argv[4] or argv[5]
 * is emtpy or if argv[4] and argv[5] differ.
 *
 * This program returns zero when it succeeds.  Non-negative values indicate
 * failure.
 */
int
main(int argc, char **argv)
{
	struct stat statbuf;
	char mntoptions[MAX_MNTOPT_STR];

	/*
	 * Check the number of arguments that were passed to s10_replacefile.
	 */
	if (argc != 7) {
		(void) fprintf(stderr, "Usage: %s dstActual tmp_file tmpDst "
		    "tmpFile cksumTmpDst cksumTmpFile\n", argv[0]);
		return (1);
	}

	/*
	 * Move the destination file (dstActual) out of the way and move the
	 * new file (tmpDst) into its place.
	 *
	 * NOTE: s10_replacefile won't print error messages here because
	 * the Solaris 10 patch tools will.
	 */
	if (rename(argv[1], argv[2]) != 0)
		return (2);
	if (rename(argv[3], argv[1]) != 0)
		return (3);

	/*
	 * If there was a lofs mount on dstActual (which we just moved), then
	 * s10_replacefile should reestablish the lofs mount.  A lofs mount
	 * existed if tmpFile exists.
	 */
	if (stat(argv[4], &statbuf) == 0 && (statbuf.st_mode & S_IFREG)) {
		/*
		 * Create a lofs overlay mount only if the checksums of the
		 * old file at dstActual and the new file at dstActual differ.
		 */
		if (argv[5][0] == '\0' || argv[6][0] == '\0' ||
		    strcmp(argv[5], argv[6]) != 0) {
			mntoptions[0] = '\0';
			if (mount(argv[4], argv[1], MS_OVERLAY | MS_OPTIONSTR,
			    MNTTYPE_LOFS, NULL, 0, mntoptions,
			    sizeof (mntoptions)) != 0) {
				/*
				 * Although the patch tools will print error
				 * messages, the tools won't know that
				 * s10_replacefile failed to establish an
				 * overlay mount.  Printing an error message
				 * here clarifies the problem for the user.
				 */
				(void) fprintf(stderr, "ERROR: Failed to "
				    "overlay mount %s onto %s\n", argv[4],
				    argv[1]);
				return (4);
			}
		} else {
			/*
			 * dstActual does not need an overlay mount.  Delete
			 * tmpFile.
			 */
			(void) unlink(argv[4]);
		}
	}
	return (0);
}
