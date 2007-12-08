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
 * Copyright (c) 1994, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _CBOOTBLK_H
#define	_CBOOTBLK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern int openfile(char *, char *);
extern int closefile(int);
extern int readfile(int, char *, int);
extern void seekfile(int, off_t);

extern void exit(void);
extern void puts(char *);
extern int utox(char *p, u_int n);

extern void fw_init(void *);

extern char *getbootdevice(char *);

extern int devbread(void *, void *, int, int);
extern void *devopen(char *);
extern int devclose(void *);
extern void get_rootfs_start(char *device);
extern u_int fdisk2rootfs(u_int offset);

extern void bcopy(const void *, void *, size_t);
extern void bzero(void *, size_t);
extern int strcmp(const char *, const char *);
extern int strncmp(const char *, const char *, size_t);
extern size_t strlen(const char *);
extern char *strcpy(char *, const char *);

extern void main(void *);
extern void exitto(void *, void *);

extern char ident[];
extern char fscompname[];
extern unsigned long read_elf_file(int, char *);
void sync_instruction_memory(caddr_t, u_int);

#ifdef	__cplusplus
}
#endif

#endif	/* _CBOOTBLK_H */
