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
 * Copyright 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _VROOT_H_
#define _VROOT_H_

#include <stdio.h>
#include <nl_types.h>

#define VROOT_DEFAULT ((pathpt)-1)

typedef struct {
	char		*path;
	short		length;
} pathcellt, *pathcellpt, patht;
typedef patht		*pathpt;

extern	void		add_dir_to_path(const char *path, register pathpt *pointer, register int position);
extern	void		flush_path_cache(void);
extern	void		flush_vroot_cache(void);
extern	const char	*get_path_name(void);
extern	char		*get_vroot_path(register char **vroot, register char **path, register char **filename);
extern	const char	*get_vroot_name(void);
extern	int		open_vroot(char *path, int flags, int mode, pathpt vroot_path, pathpt vroot_vroot);
extern	pathpt		parse_path_string(register char *string, register int remove_slash);
extern	void		scan_path_first(void);
extern	void		scan_vroot_first(void);
extern	void		set_path_style(int style);

extern	int		access_vroot(char *path, int mode, pathpt vroot_path, pathpt vroot_vroot);

extern	int		execve_vroot(char *path, char **argv, char **environ, pathpt vroot_path, pathpt vroot_vroot);

extern	int		lstat_vroot(char *path, struct stat *buffer, pathpt vroot_path, pathpt vroot_vroot);
extern	int		stat_vroot(char *path, struct stat *buffer, pathpt vroot_path, pathpt vroot_vroot);
extern	int		readlink_vroot(char *path, char *buffer, int buffer_size, pathpt vroot_path, pathpt vroot_vroot);

#endif
