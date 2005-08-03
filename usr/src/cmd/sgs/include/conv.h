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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 *
 *	Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

#ifndef	_CONV_H
#define	_CONV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Global include file for conversion library.
 */

#include <stdlib.h>
#include <libelf.h>
#include <dlfcn.h>
#include <libld.h>
#include <sgs.h>
#include <machdep.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Configuration features available - maintained here (instead of debug.h)
 * to save libconv from having to include debug.h which results in numerous
 * "declared but not used or defined" lint errors.
 */
#define	CONF_EDLIBPATH	0x000100	/* ELF default library path */
#define	CONF_ESLIBPATH	0x000200	/* ELF secure library path */
#define	CONF_ADLIBPATH	0x000400	/* AOUT default library path */
#define	CONF_ASLIBPATH	0x000800	/* AOUT secure library path */
#define	CONF_DIRCFG	0x001000	/* directory configuration available */
#define	CONF_OBJALT	0x002000	/* object alternatives available */
#define	CONF_MEMRESV	0x004000	/* memory reservation required */
#define	CONF_ENVS	0x008000	/* environment variables available */
#define	CONF_FLTR	0x010000	/* filter information available */
#define	CONF_FEATMSK	0xffff00

/*
 * Functions
 */
extern	void		conv_check_native(char **, char **);
extern	const char	*conv_binding_str(uint_t);
extern	const char	*conv_bindent_str(uint_t);
extern	const char	*conv_d_type_str(Elf_Type);
extern	const char	*conv_deftag_str(Symref);
extern	const char	*conv_dlflag_str(int, int);
extern	const char	*conv_dlmode_str(int, int);
extern	const char	*conv_dyntag_str(uint64_t, ushort_t);
extern	const char	*conv_dynflag_str(uint_t);
extern	const char	*conv_dynflag_1_str(uint_t);
extern	const char	*conv_dynposflag_1_str(uint_t);
extern	const char	*conv_dynfeature_1_str(uint_t);
extern	const char	*conv_captag_str(uint64_t);
extern	const char	*conv_capval_str(uint64_t, uint64_t, ushort_t);
extern	const char	*conv_config_str(int);
extern	const char	*conv_config_obj(ushort_t);
extern	const char	*conv_dwarf_ehe_str(uint_t);
extern	const char	*conv_eclass_str(uchar_t);
extern	const char	*conv_edata_str(uchar_t);
extern	const char	*conv_emach_str(ushort_t);
extern	const char	*conv_ever_str(uint_t);
extern	const char	*conv_etype_str(ushort_t);
extern	const char	*conv_eflags_str(ushort_t, uint_t);
extern	const char	*conv_hwcap_1_str(uint64_t, ushort_t);
extern	const char	*conv_hwcap_1_386_str(uint64_t);
extern	const char	*conv_hwcap_1_SPARC_str(uint64_t);
extern	const char	*conv_sfcap_1_str(uint64_t, ushort_t);
extern	const char	*conv_grphdrflags_str(uint_t);
extern	const char	*conv_info_bind_str(uchar_t);
extern	const char	*conv_info_type_str(ushort_t, uchar_t);
extern	const char	*conv_invalid_str(char *, size_t, uint64_t, int);
extern	Isa_desc	*conv_isalist(void);
extern	const char	*conv_lddstub(int);
extern	const char	*conv_phdrflg_str(uint_t);
extern	const char	*conv_phdrtyp_str(ushort_t, uint_t);
extern	const char	*conv_reloc_type_str(ushort_t, uint_t);
extern	const char	*conv_reloc_SPARC_type_str(uint_t);
extern	const char	*conv_reloc_386_type_str(uint_t);
extern	const char	*conv_reloc_amd64_type_str(uint_t);
extern	const char	*conv_reject_str(Rej_desc *);
extern	const char	*conv_sym_dem(const char *);
extern	const char	*conv_sym_value_str(ushort_t, uint_t, uint64_t);
extern	const char	*conv_sym_SPARC_value_str(uint64_t);
extern	const char	*conv_sym_stother(uchar_t);
extern	const char	*conv_secflg_str(ushort_t, uint_t);
extern	const char	*conv_secinfo_str(uint_t, uint_t);
extern	const char	*conv_sectyp_str(ushort_t, uint_t);
extern	const char	*conv_segaflg_str(uint_t);
extern	const char	*conv_shndx_str(ushort_t);
extern	int		conv_sys_eclass();
extern	const char	*conv_upm_string(const char *, const char *,
			    const char *, size_t);
extern	Uts_desc	*conv_uts(void);
extern	const char	*conv_verflg_str(ushort_t);

#ifdef	__cplusplus
}
#endif

#endif /* _CONV_H */
