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

/*
 * String conversion routines for symbol attributes.
 */
#include	<stdio.h>
#include	<sys/elf_SPARC.h>
#include	<sys/elf_amd64.h>
#include	"_conv.h"
#include	"symbols_msg.h"

const char *
conv_sym_other(uchar_t other, Conv_inv_buf_t *inv_buf)
{
	static const char	visibility[7] = {
		'D',	/* STV_DEFAULT */
		'I',	/* STV_INTERNAL */
		'H',	/* STV_HIDDEN */
		'P',	/* STV_PROTECTED */
		'X',	/* STV_EXPORTED */
		'S',	/* STV_SINGLETON */
		'E'	/* STV_ELIMINATE */
	};
	uchar_t		vis = ELF_ST_VISIBILITY(other);
	uint_t		ndx = 0;

	inv_buf->buf[ndx++] = visibility[vis];

	/*
	 * If unknown bits are present in st_other - throw out a '?'
	 */
	if (other & ~MSK_SYM_VISIBILITY)
		inv_buf->buf[ndx++] = '?';
	inv_buf->buf[ndx++] = '\0';

	return (inv_buf->buf);
}

static const conv_ds_t **
conv_sym_other_vis_strings(Conv_fmt_flags_t fmt_flags)
{
	static const Msg	vis_def[] = {
		MSG_STV_DEFAULT_DEF,	MSG_STV_INTERNAL_DEF,
		MSG_STV_HIDDEN_DEF,	MSG_STV_PROTECTED_DEF,
		MSG_STV_EXPORTED_DEF,	MSG_STV_SINGLETON_DEF,
		MSG_STV_ELIMINATE_DEF
	};
	static const Msg	vis_cf[] = {
		MSG_STV_DEFAULT_CF,	MSG_STV_INTERNAL_CF,
		MSG_STV_HIDDEN_CF,	MSG_STV_PROTECTED_CF,
		MSG_STV_EXPORTED_CF,	MSG_STV_SINGLETON_CF,
		MSG_STV_ELIMINATE_CF
	};
	static const Msg	vis_nf[] = {
		MSG_STV_DEFAULT_NF,	MSG_STV_INTERNAL_NF,
		MSG_STV_HIDDEN_NF,	MSG_STV_PROTECTED_NF,
		MSG_STV_EXPORTED_NF,	MSG_STV_SINGLETON_NF,
		MSG_STV_ELIMINATE_NF
	};
	static const conv_ds_msg_t ds_vis_def = {
	    CONV_DS_MSG_INIT(STV_DEFAULT, vis_def) };
	static const conv_ds_msg_t ds_vis_cf = {
	    CONV_DS_MSG_INIT(STV_DEFAULT, vis_cf) };
	static const conv_ds_msg_t ds_vis_nf = {
	    CONV_DS_MSG_INIT(STV_DEFAULT, vis_nf) };

	/* Build NULL terminated return arrays for each string style */
	static const conv_ds_t	*ds_def[] = {
		CONV_DS_ADDR(ds_vis_def), NULL };
	static const conv_ds_t	*ds_cf[] = {
		CONV_DS_ADDR(ds_vis_cf), NULL };
	static const conv_ds_t	*ds_nf[] = {
		CONV_DS_ADDR(ds_vis_nf), NULL };

	/* Select the strings to use */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_CF:
		return (ds_cf);
	case CONV_FMT_ALT_NF:
		return (ds_nf);
	}

	return (ds_def);
}

const char *
conv_sym_other_vis(uchar_t value, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, value,
	    conv_sym_other_vis_strings(fmt_flags), fmt_flags, inv_buf));
}

conv_iter_ret_t
conv_iter_sym_other_vis(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	return (conv_iter_ds(ELFOSABI_NONE, EM_NONE,
	    conv_sym_other_vis_strings(fmt_flags), func, uvalue));
}

static const conv_ds_t **
conv_sym_info_type_strings(Half mach, Conv_fmt_flags_t fmt_flags)
{
	/*
	 * This routine can return an array with 1 generic array, and
	 * a machine array, plus the NULL termination.
	 */
#define	MAX_RET	3

	static const Msg	types_def[] = {
		MSG_STT_NOTYPE_DEF,	MSG_STT_OBJECT_DEF,
		MSG_STT_FUNC_DEF,	MSG_STT_SECTION_DEF,
		MSG_STT_FILE_DEF,	MSG_STT_COMMON_DEF,
		MSG_STT_TLS_DEF,	MSG_STT_IFUNC_DEF
	};
	static const Msg	types_cf[] = {
		MSG_STT_NOTYPE_CF,	MSG_STT_OBJECT_CF,
		MSG_STT_FUNC_CF,	MSG_STT_SECTION_CF,
		MSG_STT_FILE_CF,	MSG_STT_COMMON_CF,
		MSG_STT_TLS_CF,		MSG_STT_IFUNC_CF
	};
	static const Msg	types_nf[] = {
		MSG_STT_NOTYPE_NF,	MSG_STT_OBJECT_NF,
		MSG_STT_FUNC_NF,	MSG_STT_SECTION_NF,
		MSG_STT_FILE_NF,	MSG_STT_COMMON_NF,
		MSG_STT_TLS_NF,		MSG_STT_IFUNC_NF
	};
	static const conv_ds_msg_t ds_types_def = {
	    CONV_DS_MSG_INIT(STT_NOTYPE, types_def) };
	static const conv_ds_msg_t ds_types_cf = {
	    CONV_DS_MSG_INIT(STT_NOTYPE, types_cf) };
	static const conv_ds_msg_t ds_types_nf = {
	    CONV_DS_MSG_INIT(STT_NOTYPE, types_nf) };


	static const Msg	sparc_def[] = { MSG_STT_SPARC_REGISTER_DEF };
	static const Msg	sparc_cf[] = { MSG_STT_SPARC_REGISTER_CF };
	static const Msg	sparc_nf[] = { MSG_STT_SPARC_REGISTER_NF };
	static const conv_ds_msg_t ds_sparc_def = {
	    CONV_DS_MSG_INIT(STT_SPARC_REGISTER, sparc_def) };
	static const conv_ds_msg_t ds_sparc_cf = {
	    CONV_DS_MSG_INIT(STT_SPARC_REGISTER, sparc_cf) };
	static const conv_ds_msg_t ds_sparc_nf = {
	    CONV_DS_MSG_INIT(STT_SPARC_REGISTER, sparc_nf) };


	static const conv_ds_t	*retarr[MAX_RET];

	int	retndx = 0;
	int	is_sparc;

	is_sparc = (mach == EM_SPARC) || (mach == EM_SPARCV9) ||
	    (mach == EM_SPARC32PLUS) || (mach == CONV_MACH_ALL);

	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_CF:
		retarr[retndx++] = CONV_DS_ADDR(ds_types_cf);
		if (is_sparc)
			retarr[retndx++] = CONV_DS_ADDR(ds_sparc_cf);
		break;
	case CONV_FMT_ALT_NF:
		retarr[retndx++] = CONV_DS_ADDR(ds_types_nf);
		if (is_sparc)
			retarr[retndx++] = CONV_DS_ADDR(ds_sparc_nf);
		break;
	default:
		retarr[retndx++] = CONV_DS_ADDR(ds_types_def);
		if (is_sparc)
			retarr[retndx++] = CONV_DS_ADDR(ds_sparc_def);
		break;
	}

	retarr[retndx++] = NULL;
	assert(retndx <= MAX_RET);
	return (retarr);
}

const char *
conv_sym_info_type(Half mach, uchar_t type, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	return (conv_map_ds(ELFOSABI_NONE, mach, type,
	    conv_sym_info_type_strings(mach, fmt_flags), fmt_flags, inv_buf));
}

conv_iter_ret_t
conv_iter_sym_info_type(Half mach, Conv_fmt_flags_t fmt_flags,
    conv_iter_cb_t func, void *uvalue)
{
	return (conv_iter_ds(ELFOSABI_NONE, mach,
	    conv_sym_info_type_strings(mach, fmt_flags), func, uvalue));
}

static const conv_ds_t **
conv_sym_info_bind_strings(Conv_fmt_flags_t fmt_flags)
{
	static const Msg	binds_def[] = {
		MSG_STB_LOCAL_DEF,	MSG_STB_GLOBAL_DEF,
		MSG_STB_WEAK_DEF
	};
	static const Msg	binds_cf[] = {
		MSG_STB_LOCAL_CF,	MSG_STB_GLOBAL_CF,
		MSG_STB_WEAK_CF
	};
	static const Msg	binds_nf[] = {
		MSG_STB_LOCAL_NF,	MSG_STB_GLOBAL_NF,
		MSG_STB_WEAK_NF
	};
	static const conv_ds_msg_t ds_binds_def = {
	    CONV_DS_MSG_INIT(STB_LOCAL, binds_def) };
	static const conv_ds_msg_t ds_binds_cf = {
	    CONV_DS_MSG_INIT(STB_LOCAL, binds_cf) };
	static const conv_ds_msg_t ds_binds_nf = {
	    CONV_DS_MSG_INIT(STB_LOCAL, binds_nf) };


	/* Build NULL terminated return arrays for each string style */
	static const conv_ds_t	*ds_def[] = {
		CONV_DS_ADDR(ds_binds_def), NULL };
	static const conv_ds_t	*ds_cf[] = {
		CONV_DS_ADDR(ds_binds_cf), NULL };
	static const conv_ds_t	*ds_nf[] = {
		CONV_DS_ADDR(ds_binds_nf), NULL };


	/* Select the strings to use */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_CF:
		return (ds_cf);
	case CONV_FMT_ALT_NF:
		return (ds_nf);
	}

	return (ds_def);
}

const char *
conv_sym_info_bind(uchar_t bind, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, bind,
	    conv_sym_info_bind_strings(fmt_flags), fmt_flags, inv_buf));
}

conv_iter_ret_t
conv_iter_sym_info_bind(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	return (conv_iter_ds(ELFOSABI_NONE, EM_NONE,
	    conv_sym_info_bind_strings(fmt_flags), func, uvalue));
}

static const conv_ds_t **
conv_sym_shndx_strings(Conv_fmt_flags_t fmt_flags)
{
#define	ALL	ELFOSABI_NONE, EM_NONE
#define	SOL	ELFOSABI_SOLARIS, EM_NONE
#define	AMD	ELFOSABI_NONE, EM_AMD64

	/*
	 * There aren't many of these values, and they are sparse,
	 * so rather than separate them into different ranges, I use
	 * a single Val_desc2 array for all of them.
	 */
	static const Val_desc2 shn_def[] = {
		{ SHN_UNDEF,		ALL,	MSG_SHN_UNDEF_CFNP },
		{ SHN_BEFORE,		ALL,	MSG_SHN_BEFORE_CFNP },
		{ SHN_AFTER,		ALL,	MSG_SHN_AFTER_CFNP },
		{ SHN_AMD64_LCOMMON,	AMD,	MSG_SHN_AMD64_LCOMMON_DEF },
		{ SHN_SUNW_IGNORE,	SOL,	MSG_SHN_SUNW_IGNORE_DEF },
		{ SHN_ABS,		ALL,	MSG_SHN_ABS_CFNP },
		{ SHN_COMMON,		ALL,	MSG_SHN_COMMON_CFNP },
		{ SHN_XINDEX,		ALL,	MSG_SHN_XINDEX_CFNP },
		{ 0 }
	};
	static const Val_desc2 shn_cf[] = {
		{ SHN_UNDEF,		ALL,	MSG_SHN_UNDEF_CF },
		{ SHN_BEFORE,		ALL,	MSG_SHN_BEFORE_CF },
		{ SHN_AFTER,		ALL,	MSG_SHN_AFTER_CF },
		{ SHN_AMD64_LCOMMON,	AMD,	MSG_SHN_AMD64_LCOMMON_CF },
		{ SHN_SUNW_IGNORE,	SOL,	MSG_SHN_SUNW_IGNORE_CF },
		{ SHN_ABS,		ALL,	MSG_SHN_ABS_CF },
		{ SHN_COMMON,		ALL,	MSG_SHN_COMMON_CF },
		{ SHN_XINDEX,		ALL,	MSG_SHN_XINDEX_CF },
		{ 0 }
	};
	static const Val_desc2 shn_cfnp[] = {
		{ SHN_UNDEF,		ALL,	MSG_SHN_UNDEF_CFNP },
		{ SHN_BEFORE,		ALL,	MSG_SHN_BEFORE_CFNP },
		{ SHN_AFTER,		ALL,	MSG_SHN_AFTER_CFNP },
		{ SHN_AMD64_LCOMMON,	AMD,	MSG_SHN_AMD64_LCOMMON_CFNP },
		{ SHN_SUNW_IGNORE,	SOL,	MSG_SHN_SUNW_IGNORE_CFNP },
		{ SHN_ABS,		ALL,	MSG_SHN_ABS_CFNP },
		{ SHN_COMMON,		ALL,	MSG_SHN_COMMON_CFNP },
		{ SHN_XINDEX,		ALL,	MSG_SHN_XINDEX_CFNP },
		{ 0 }
	};
	static const Val_desc2 shn_nf[] = {
		{ SHN_UNDEF,		ALL,	MSG_SHN_UNDEF_NF },
		{ SHN_BEFORE,		ALL,	MSG_SHN_BEFORE_NF },
		{ SHN_AFTER,		ALL,	MSG_SHN_AFTER_NF },
		{ SHN_AMD64_LCOMMON,	AMD,	MSG_SHN_AMD64_LCOMMON_NF },
		{ SHN_SUNW_IGNORE,	SOL,	MSG_SHN_SUNW_IGNORE_NF },
		{ SHN_ABS,		ALL,	MSG_SHN_ABS_NF },
		{ SHN_COMMON,		ALL,	MSG_SHN_COMMON_NF },
		{ SHN_XINDEX,		ALL,	MSG_SHN_XINDEX_NF },
		{ 0 }
	};
	static const conv_ds_vd2_t ds_shn_def = {
	    CONV_DS_VD2, SHN_UNDEF, SHN_XINDEX, shn_def };
	static const conv_ds_vd2_t ds_shn_cf = {
	    CONV_DS_VD2, SHN_UNDEF, SHN_XINDEX, shn_cf };
	static const conv_ds_vd2_t ds_shn_cfnp = {
	    CONV_DS_VD2, SHN_UNDEF, SHN_XINDEX, shn_cfnp };
	static const conv_ds_vd2_t ds_shn_nf = {
	    CONV_DS_VD2, SHN_UNDEF, SHN_XINDEX, shn_nf };

	/* Build NULL terminated return arrays for each string style */
	static const conv_ds_t	*ds_def[] = {
		CONV_DS_ADDR(ds_shn_def), NULL };
	static const conv_ds_t	*ds_cf[] = {
		CONV_DS_ADDR(ds_shn_cf), NULL };
	static const conv_ds_t	*ds_cfnp[] = {
		CONV_DS_ADDR(ds_shn_cfnp), NULL };
	static const conv_ds_t	*ds_nf[] = {
		CONV_DS_ADDR(ds_shn_nf), NULL };

	/* Select the strings to use */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_CF:
		return (ds_cf);
	case CONV_FMT_ALT_CFNP:
		return (ds_cfnp);
	case CONV_FMT_ALT_NF:
		return (ds_nf);
	}

	return (ds_def);

#undef ALL
#undef SOL
#undef AMD
}

const char *
conv_sym_shndx(uchar_t osabi, Half mach, Half shndx, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	return (conv_map_ds(osabi, mach, shndx,
	    conv_sym_shndx_strings(fmt_flags), fmt_flags, inv_buf));
}

conv_iter_ret_t
conv_iter_sym_shndx(conv_iter_osabi_t osabi, Half mach,
    Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func, void *uvalue)
{
	static const Msg amd64_alias_cf[] = { MSG_SHN_X86_64_LCOMMON_CF };
	static const conv_ds_msg_t ds_msg_amd64_alias_cf = {
	    CONV_DS_MSG_INIT(SHN_X86_64_LCOMMON, amd64_alias_cf) };
	static const conv_ds_t	*ds_amd64_alias_cf[] = {
	    CONV_DS_ADDR(ds_msg_amd64_alias_cf), NULL };

	static const Msg amd64_alias_cfnp[] = { MSG_SHN_X86_64_LCOMMON_CFNP };
	static const conv_ds_msg_t ds_msg_amd64_alias_cfnp = {
	    CONV_DS_MSG_INIT(SHN_X86_64_LCOMMON, amd64_alias_cfnp) };
	static const conv_ds_t	*ds_amd64_alias_cfnp[] = {
	    CONV_DS_ADDR(ds_msg_amd64_alias_cfnp), NULL };

	static const Msg amd64_alias_nf[] = { MSG_SHN_X86_64_LCOMMON_NF };
	static const conv_ds_msg_t ds_msg_amd64_alias_nf = {
	    CONV_DS_MSG_INIT(SHN_X86_64_LCOMMON, amd64_alias_nf) };
	static const conv_ds_t	*ds_amd64_alias_nf[] = {
	    CONV_DS_ADDR(ds_msg_amd64_alias_nf), NULL };


	if (conv_iter_ds(osabi, mach, conv_sym_shndx_strings(fmt_flags),
	    func, uvalue) == CONV_ITER_DONE)
		return (CONV_ITER_DONE);

	/*
	 * SHN_AMD64_LCOMMON is also known as SHN_X86_64_LCOMMON
	 */
	if (mach == EM_AMD64) {
		const conv_ds_t	**ds;

		switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
		case CONV_FMT_ALT_CF:
			ds = ds_amd64_alias_cf;
			break;
		case CONV_FMT_ALT_NF:
			ds = ds_amd64_alias_nf;
			break;
		default:
			ds = ds_amd64_alias_cfnp;
			break;
		}
		return (conv_iter_ds(ELFOSABI_NONE, mach, ds, func, uvalue));
	}

	return (CONV_ITER_CONT);
}
