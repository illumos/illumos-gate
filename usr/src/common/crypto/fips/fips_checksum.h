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

#ifndef _SYS_CRYPTO_FIPS_H
#define	_SYS_CRYPTO_FIPS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef  _KERNEL
#include <sys/elf.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/kmem.h>
#include <sys/sha1.h>
#include <sys/ddi.h>
#else
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <libelf.h>
#include <gelf.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <sys/elf_SPARC.h>
#endif


#define	FAILURE -1
#define	SUCCESS 0

#ifdef  _KERNEL
extern int	fips_calc_checksum(struct _buf *, Elf64_Ehdr *, char *);
extern int	fips_check_module(char *modname, void *_initaddr);
#else
extern int	fips_read_file(int, char *, int, int);
extern int	fips_calc_checksum(int, Elf64_Ehdr *, char *);
#endif


#ifdef __cplusplus
}
#endif

#endif /* _SYS_CRYPTO_FIPS_H */
