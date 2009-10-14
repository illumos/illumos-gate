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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DEBUG_DOT_H
#define	_DEBUG_DOT_H

#include <debug.h>
#include <conv.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Debugging is enabled by various tokens (see debug.c) that result in an
 * internal bit mask (d_class) being initialized.  Each debugging function is
 * appropriate for one or more of the classes specified by the bit mask.  Each
 * debugging function validates whether it is appropriate for the present
 * classes before printing anything.
 */
#define	DBG_NOTCLASS(c)	!(dbg_desc->d_class & (c))

#define	DBG_C_ARGS	0x00000001
#define	DBG_C_AUDITING	0x00000002
#define	DBG_C_BASIC	0x00000004
#define	DBG_C_BINDINGS	0x00000008
#define	DBG_C_CAP	0x00000010
#define	DBG_C_DEMANGLE	0x00000020
#define	DBG_C_ENTRY	0x00000040
#define	DBG_C_FILES	0x00000080
#define	DBG_C_GOT	0x00000100
#define	DBG_C_INIT	0x00000200
#define	DBG_C_LIBS	0x00000400
#define	DBG_C_MAP	0x00000800
#define	DBG_C_MOVE	0x00001000
#define	DBG_C_RELOC	0x00002000
#define	DBG_C_SECTIONS	0x00004000
#define	DBG_C_SEGMENTS	0x00008000
#define	DBG_C_STATS	0x00010000
#define	DBG_C_STRTAB	0x00020000
#define	DBG_C_SUPPORT	0x00040000
#define	DBG_C_SYMBOLS	0x00080000
#define	DBG_C_TLS	0x00100000
#define	DBG_C_UNUSED	0x00200000
#define	DBG_C_VERSIONS	0x00400000


#define	DBG_C_ALL	0xffffffff

typedef struct {
	const char	*o_name;	/* command line argument name */
	uint_t		o_class;	/* associated class for this name */
	uint_t		o_extra;	/* associated extra for this name */
} DBG_options;

#define	AL_CNT_DEBUG	4

/*
 * Some Dbg_*() format strings differ depending on whether they are used for
 * 32-bit or 64-bit values.
 */
#if	defined(_ELF64)

#define	MSG_EDATA_TITLE		MSG_EDATA_TITLE_64
#define	MSG_EDATA_ENTRY		MSG_EDATA_ENTRY_64

#else

#define	MSG_EDATA_TITLE		MSG_EDATA_TITLE_32
#define	MSG_EDATA_ENTRY		MSG_EDATA_ENTRY_32

#endif

/*
 * Some Elf_*() format strings differ depending on whether they are used for
 * 32-bit or 64-bit values.
 */
#if	defined(_ELF64)

#define	MSG_GOT_TITLE		MSG_GOT_TITLE_64
#define	MSG_GOT_ENTRY_RE	MSG_GOT_ENTRY_RE_64
#define	MSG_GOT_ENTRY_NR	MSG_GOT_ENTRY_NR_64
#define	MSG_GOT_COLUMNS1	MSG_GOT_COLUMNS1_64
#define	MSG_GOT_COLUMNS2	MSG_GOT_COLUMNS2_64
#define	MSG_GOT_FORMAT1		MSG_GOT_FORMAT1_64
#define	MSG_GOT_FORMAT2		MSG_GOT_FORMAT2_64

#define	MSG_PHD_VADDR		MSG_PHD_VADDR_64
#define	MSG_PHD_PADDR		MSG_PHD_PADDR_64
#define	MSG_PHD_FILESZ		MSG_PHD_FILESZ_64
#define	MSG_PHD_OFFSET		MSG_PHD_OFFSET_64

#define	MSG_REL_EFSA_TITLE	MSG_REL_EFSA_TITLE_64
#define	MSG_REL_EFLA_TITLE	MSG_REL_EFLA_TITLE_64
#define	MSG_REL_EFSN_TITLE	MSG_REL_EFSN_TITLE_64
#define	MSG_REL_EFLN_TITLE	MSG_REL_EFLN_TITLE_64
#define	MSG_REL_EFSA_ENTRY	MSG_REL_EFSA_ENTRY_64
#define	MSG_REL_EFLA_ENTRY	MSG_REL_EFLA_ENTRY_64
#define	MSG_REL_EFSN_ENTRY	MSG_REL_EFSN_ENTRY_64
#define	MSG_REL_EFLN_ENTRY	MSG_REL_EFLN_ENTRY_64
#define	MSG_REL_RT_APLREG	MSG_REL_RT_APLREG_64
#define	MSG_REL_RT_APLVAL	MSG_REL_RT_APLVAL_64
#define	MSG_REL_RTA_TITLE	MSG_REL_RTA_TITLE_64
#define	MSG_REL_RTN_TITLE	MSG_REL_RTN_TITLE_64
#define	MSG_REL_RTV_TITLE	MSG_REL_RTV_TITLE_64
#define	MSG_REL_RTA_ENTRY	MSG_REL_RTA_ENTRY_64
#define	MSG_REL_RTN_ENTRY	MSG_REL_RTN_ENTRY_64
#define	MSG_REL_LDSA_TITLE	MSG_REL_LDSA_TITLE_64
#define	MSG_REL_LDSN_TITLE	MSG_REL_LDSN_TITLE_64
#define	MSG_REL_LDSA_ENTRY	MSG_REL_LDSA_ENTRY_64
#define	MSG_REL_LDSN_ENTRY	MSG_REL_LDSN_ENTRY_64
#define	MSG_REL_LDSV_TITLE	MSG_REL_LDSV_TITLE_64
#define	MSG_REL_LDSV_ENTRY	MSG_REL_LDSV_ENTRY_64
#define	MSG_REL_LDLA_TITLE	MSG_REL_LDLA_TITLE_64
#define	MSG_REL_LDLN_TITLE	MSG_REL_LDLN_TITLE_64
#define	MSG_REL_LDLA_ENTRY	MSG_REL_LDLA_ENTRY_64
#define	MSG_REL_LDLN_ENTRY	MSG_REL_LDLN_ENTRY_64
#define	MSG_REL_LDLV_TITLE	MSG_REL_LDLV_TITLE_64
#define	MSG_REL_LDLV_ENTRY	MSG_REL_LDLV_ENTRY_64

#define	MSG_SHD_ADDR		MSG_SHD_ADDR_64
#define	MSG_SHD_SIZE		MSG_SHD_SIZE_64
#define	MSG_SHD_OFFSET		MSG_SHD_OFFSET_64
#define	MSG_SHD_OFFSET_ENT	MSG_SHD_OFFSET_ENT_64
#define	MSG_SHD_ALIGN		MSG_SHD_ALIGN_64
#define	MSG_SHD_LINK		MSG_SHD_LINK_64

#define	MSG_SYM_EFS_ENTRY	MSG_SYM_EFS_ENTRY_64
#define	MSG_SYM_EFL_ENTRY	MSG_SYM_EFL_ENTRY_64
#define	MSG_SYM_EFS_TITLE	MSG_SYM_EFS_TITLE_64
#define	MSG_SYM_EFL_TITLE	MSG_SYM_EFL_TITLE_64
#define	MSG_SYM_LDS_TITLE	MSG_SYM_LDS_TITLE_64
#define	MSG_SYM_LDL_TITLE	MSG_SYM_LDL_TITLE_64

#else

#define	MSG_GOT_TITLE		MSG_GOT_TITLE_32
#define	MSG_GOT_ENTRY_RE	MSG_GOT_ENTRY_RE_32
#define	MSG_GOT_ENTRY_NR	MSG_GOT_ENTRY_NR_32
#define	MSG_GOT_COLUMNS1	MSG_GOT_COLUMNS1_32
#define	MSG_GOT_COLUMNS2	MSG_GOT_COLUMNS2_32
#define	MSG_GOT_FORMAT1		MSG_GOT_FORMAT1_32
#define	MSG_GOT_FORMAT2		MSG_GOT_FORMAT2_32

#define	MSG_PHD_VADDR		MSG_PHD_VADDR_32
#define	MSG_PHD_PADDR		MSG_PHD_PADDR_32
#define	MSG_PHD_FILESZ		MSG_PHD_FILESZ_32
#define	MSG_PHD_OFFSET		MSG_PHD_OFFSET_32

#define	MSG_REL_EFSA_TITLE	MSG_REL_EFSA_TITLE_32
#define	MSG_REL_EFLA_TITLE	MSG_REL_EFLA_TITLE_32
#define	MSG_REL_EFSN_TITLE	MSG_REL_EFSN_TITLE_32
#define	MSG_REL_EFLN_TITLE	MSG_REL_EFLN_TITLE_32
#define	MSG_REL_EFSA_ENTRY	MSG_REL_EFSA_ENTRY_32
#define	MSG_REL_EFLA_ENTRY	MSG_REL_EFLA_ENTRY_32
#define	MSG_REL_EFSN_ENTRY	MSG_REL_EFSN_ENTRY_32
#define	MSG_REL_EFLN_ENTRY	MSG_REL_EFLN_ENTRY_32
#define	MSG_REL_RT_APLREG	MSG_REL_RT_APLREG_32
#define	MSG_REL_RT_APLVAL	MSG_REL_RT_APLVAL_32
#define	MSG_REL_RTA_TITLE	MSG_REL_RTA_TITLE_32
#define	MSG_REL_RTN_TITLE	MSG_REL_RTN_TITLE_32
#define	MSG_REL_RTV_TITLE	MSG_REL_RTV_TITLE_32
#define	MSG_REL_RTA_ENTRY	MSG_REL_RTA_ENTRY_32
#define	MSG_REL_RTN_ENTRY	MSG_REL_RTN_ENTRY_32
#define	MSG_REL_LDSA_TITLE	MSG_REL_LDSA_TITLE_32
#define	MSG_REL_LDSN_TITLE	MSG_REL_LDSN_TITLE_32
#define	MSG_REL_LDSA_ENTRY	MSG_REL_LDSA_ENTRY_32
#define	MSG_REL_LDSN_ENTRY	MSG_REL_LDSN_ENTRY_32
#define	MSG_REL_LDSV_TITLE	MSG_REL_LDSV_TITLE_32
#define	MSG_REL_LDSV_ENTRY	MSG_REL_LDSV_ENTRY_32
#define	MSG_REL_LDLA_TITLE	MSG_REL_LDLA_TITLE_32
#define	MSG_REL_LDLN_TITLE	MSG_REL_LDLN_TITLE_32
#define	MSG_REL_LDLA_ENTRY	MSG_REL_LDLA_ENTRY_32
#define	MSG_REL_LDLN_ENTRY	MSG_REL_LDLN_ENTRY_32
#define	MSG_REL_LDLV_TITLE	MSG_REL_LDLV_TITLE_32
#define	MSG_REL_LDLV_ENTRY	MSG_REL_LDLV_ENTRY_32

#define	MSG_SHD_ADDR		MSG_SHD_ADDR_32
#define	MSG_SHD_SIZE		MSG_SHD_SIZE_32
#define	MSG_SHD_OFFSET		MSG_SHD_OFFSET_32
#define	MSG_SHD_OFFSET_ENT	MSG_SHD_OFFSET_ENT_32
#define	MSG_SHD_ALIGN		MSG_SHD_ALIGN_32
#define	MSG_SHD_LINK		MSG_SHD_LINK_32

#define	MSG_SYM_EFS_ENTRY	MSG_SYM_EFS_ENTRY_32
#define	MSG_SYM_EFL_ENTRY	MSG_SYM_EFL_ENTRY_32
#define	MSG_SYM_EFS_TITLE	MSG_SYM_EFS_TITLE_32
#define	MSG_SYM_EFL_TITLE	MSG_SYM_EFL_TITLE_32
#define	MSG_SYM_LDS_TITLE	MSG_SYM_LDS_TITLE_32
#define	MSG_SYM_LDL_TITLE	MSG_SYM_LDL_TITLE_32

#endif

#define	INDEX_STR_SIZE		10

/*
 * Buffer used by dbg_isec_name() to format input section
 * names. The size was selected to satisfy two opposing
 * constraints:
 * -	To be large enough to handle the largest C++ mangled name.
 *	Although we can malloc buffers, we don't want that to happen.
 * -	To be small enough on the thread stack to not cause problems.
 */
typedef char dbg_isec_name_buf_t[INDEX_STR_SIZE + 2048];

#if	defined(_ELF64)
#define	dbg_fmt_isec_name	dbg64_fmt_isec_name
#define	dbg_fmt_isec_name2	dbg64_fmt_isec_name2
#else
#define	dbg_fmt_isec_name	dbg32_fmt_isec_name
#define	dbg_fmt_isec_name2	dbg32_fmt_isec_name2
#endif
extern	const char	*dbg_fmt_isec_name(Is_desc *, dbg_isec_name_buf_t,
			    char **);
extern	const char	*dbg_fmt_isec_name2(const char *, Word,
			    dbg_isec_name_buf_t, char **);

#ifdef	__cplusplus
}
#endif

#endif	/* _DEBUG_DOT_H */
