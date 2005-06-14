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
 * Copyright (c) 1992, by Sun Microsystems, Inc.
 */

#ifndef	_RMMOUNT_H
#define	_RMMOUNT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * For the "action" function(s).
 */
struct action_arg {
	char	*aa_path;	/* special device in question (block) */
	char	*aa_rawpath;	/* character special of above */
	char	*aa_type;	/* file system type */
	char	*aa_media;	/* type of media */
	char	*aa_partname;	/* iff a partition, partition name */
	char	*aa_mountpoint;	/* path this file system mounted on */
	int	aa_clean;	/* does filesystem need fsck? (TRUE | FALSE) */
	int	aa_mnt;		/* was it mounted? (TRUE | FALSE) */
};

/*
 * The "action" function is passed a null terminated array of
 * action_arg structures.  The last array entry denoted by
 * aa_path == NULL.  Argc and argv are the arguments from
 * the configuration file.  argv[0] == the name of the dso of
 * this action.
 */
int	action(struct action_arg **aa, int argc, char **argv);

/*
 * The ident_fs function is passed an open file descriptor to the block
 * device and the pathname of the character device if it can be
 * discovered.  Otherwise "rawpath" is NULL.
 * it is to return TRUE if the data that can be read through
 * fd represents a file system that it recognizes.
 */
int	ident_fs(int fd, char *rawpath, int *clean, int verbose);

#ifdef	__cplusplus
}
#endif

#endif	/* _RMMOUNT_H */
