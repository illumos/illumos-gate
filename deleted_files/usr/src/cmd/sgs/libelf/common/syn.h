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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	SYN_DOT_H
#define	SYN_DOT_H

/*
 * Synonyms for ANSI C.
 *	Line profiling currently pulls libelf into the a.out file.
 *	These definitions let that happen without polluting the
 *	user's name space with elf... symbols.  Instead, the libelf
 *	names that appear are _elf....  Names without a leading
 *	underscore will be weak symbols.
 */


#if !defined(__lint)

#define	elf_begin	_elf_begin
#define	elf_cntl	_elf_cntl
#define	elf_end		_elf_end
#define	elf_errmsg	_elf_errmsg
#define	elf_errmsg_r	_elf_errmsg_r
#define	elf_errno	_elf_errno
#define	elf_fill	_elf_fill
#define	elf_flagdata	_elf_flagdata
#define	elf_flagehdr	_elf_flagehdr
#define	elf_flagelf	_elf_flagelf
#define	elf_flagphdr	_elf_flagphdr
#define	elf_flagscn	_elf_flagscn
#define	elf_flagshdr	_elf_flagshdr
#define	elf32_fsize	_elf32_fsize
#define	elf_getarhdr	_elf_getarhdr
#define	elf_getarsym	_elf_getarsym
#define	elf_getbase	_elf_getbase
#define	elf_getdata	_elf_getdata
#define	elf32_getehdr	_elf32_getehdr
#define	elf_getident	_elf_getident
#define	elf32_getphdr	_elf32_getphdr
#define	elf_getscn	_elf_getscn
#define	elf32_getshdr	_elf32_getshdr
#define	elf_hash	_elf_hash
#define	elf_kind	_elf_kind
#define	elf_memory	_elf_memory
#define	elf_ndxscn	_elf_ndxscn
#define	elf_newdata	_elf_newdata
#define	elf32_newehdr	_elf32_newehdr
#define	elf32_newphdr	_elf32_newphdr
#define	elf_newscn	_elf_newscn
#define	elf_nextscn	_elf_nextscn
#define	elf_next	_elf_next
#define	elf_rand	_elf_rand
#define	elf_rawdata	_elf_rawdata
#define	elf_rawfile	_elf_rawfile
#define	elf_strptr	_elf_strptr
#define	elf_update	_elf_update
#define	elf_version	_elf_version
#define	elf32_xlatetof	_elf32_xlatetof
#define	elf32_xlatetom	_elf32_xlatetom

#endif	/* !__lint */

#endif	/* SYN_DOT_H */
