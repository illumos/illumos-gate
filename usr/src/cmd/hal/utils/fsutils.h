/***************************************************************************
 *
 * fsutils.h : definitions for filesystem utilities
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef FSUTILS_H
#define	FSUTILS_H

#include <sys/types.h>
#include <sys/vtoc.h>

boolean_t dos_to_dev(char *path, char **devpath, int *num);
char *get_slice_name(char *devlink);
boolean_t is_dos_drive(uchar_t id);
boolean_t is_dos_extended(uchar_t id);
boolean_t find_dos_drive(int fd, int num, uint_t secsz, off_t *offset);
int get_num_dos_drives(int fd, uint_t);
boolean_t vtoc_one_slice_entire_disk(struct vtoc *vtoc);

#endif /* FSUTILS_H */
