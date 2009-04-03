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
 * String conversion routines for program header attributes.
 */
#include	<stdio.h>
#include	<string.h>
#include	<_conv.h>
#include	<phdr_msg.h>

static const conv_ds_t **
conv_phdr_type_strings(Conv_fmt_flags_t fmt_flags)
{
#define	ALL	ELFOSABI_NONE, EM_NONE
#define	SOL	ELFOSABI_SOLARIS, EM_NONE
#define	LIN	ELFOSABI_LINUX, EM_NONE

	static const Msg	phdrs_def[] = {
		MSG_PT_NULL,			MSG_PT_LOAD,
		MSG_PT_DYNAMIC,			MSG_PT_INTERP,
		MSG_PT_NOTE,			MSG_PT_SHLIB,
		MSG_PT_PHDR,			MSG_PT_TLS
	};
	static const Msg	phdrs_dmp[] = {
		MSG_PT_NULL_CFNP,		MSG_PT_LOAD_CFNP,
		MSG_PT_DYNAMIC_DMP,		MSG_PT_INTERP_CFNP,
		MSG_PT_NOTE_CFNP,		MSG_PT_SHLIB_CFNP,
		MSG_PT_PHDR_CFNP,		MSG_PT_TLS_CFNP
	};
	static const Msg	phdrs_cf[] = {
		MSG_PT_NULL_CF,			MSG_PT_LOAD_CF,
		MSG_PT_DYNAMIC_CF,		MSG_PT_INTERP_CF,
		MSG_PT_NOTE_CF,			MSG_PT_SHLIB_CF,
		MSG_PT_PHDR_CF,			MSG_PT_TLS_CF
	};
	static const Msg	phdrs_cfnp[] = {
		MSG_PT_NULL_CFNP,		MSG_PT_LOAD_CFNP,
		MSG_PT_DYNAMIC_CFNP,		MSG_PT_INTERP_CFNP,
		MSG_PT_NOTE_CFNP,		MSG_PT_SHLIB_CFNP,
		MSG_PT_PHDR_CFNP,		MSG_PT_TLS_CFNP
	};
	static const Msg	phdrs_nf[] = {
		MSG_PT_NULL_NF,			MSG_PT_LOAD_NF,
		MSG_PT_DYNAMIC_NF,		MSG_PT_INTERP_NF,
		MSG_PT_NOTE_NF,			MSG_PT_SHLIB_NF,
		MSG_PT_PHDR_NF,			MSG_PT_TLS_NF
	};
#if PT_NUM != (PT_TLS + 1)
error "PT_NUM has grown. Update phdrs[]"
#endif
	static const conv_ds_msg_t ds_phdrs_def = {
	    CONV_DS_MSG_INIT(PT_NULL, phdrs_def) };
	static const conv_ds_msg_t ds_phdrs_dmp = {
	    CONV_DS_MSG_INIT(PT_NULL, phdrs_dmp) };
	static const conv_ds_msg_t ds_phdrs_cf = {
	    CONV_DS_MSG_INIT(PT_NULL, phdrs_cf) };
	static const conv_ds_msg_t ds_phdrs_cfnp = {
	    CONV_DS_MSG_INIT(PT_NULL, phdrs_cfnp) };
	static const conv_ds_msg_t ds_phdrs_nf = {
	    CONV_DS_MSG_INIT(PT_NULL, phdrs_nf) };


	static const Val_desc2 phdrs_osabi_def[] = {
		{ PT_SUNWBSS,		SOL,	MSG_PT_SUNWBSS },
		{ PT_SUNWSTACK, 	SOL,	MSG_PT_SUNWSTACK },
		{ PT_SUNWDTRACE,	SOL,	MSG_PT_SUNWDTRACE },
		{ PT_SUNWCAP,		SOL,	MSG_PT_SUNWCAP },
		{ PT_SUNW_UNWIND,	SOL,	MSG_PT_SUNW_UNWIND },
		{ PT_SUNW_EH_FRAME,	SOL,	MSG_PT_SUNW_EH_FRAME },

		{ PT_GNU_EH_FRAME,	LIN,	MSG_PT_GNU_EH_FRAME },
		{ PT_GNU_STACK,		LIN,	MSG_PT_GNU_STACK },
		{ PT_GNU_RELRO,		LIN,	MSG_PT_GNU_RELRO },

		{ 0 }
	};
	static const Val_desc2 phdrs_osabi_cf[] = {
		{ PT_SUNWBSS,		SOL,	MSG_PT_SUNWBSS_CF },
		{ PT_SUNWSTACK, 	SOL,	MSG_PT_SUNWSTACK_CF },
		{ PT_SUNWDTRACE,	SOL,	MSG_PT_SUNWDTRACE_CF },
		{ PT_SUNWCAP,		SOL,	MSG_PT_SUNWCAP_CF },
		{ PT_SUNW_UNWIND,	SOL,	MSG_PT_SUNW_UNWIND_CF },
		{ PT_SUNW_EH_FRAME,	SOL,	MSG_PT_SUNW_EH_FRAME_CF },

		{ PT_GNU_EH_FRAME,	LIN,	MSG_PT_GNU_EH_FRAME_CF },
		{ PT_GNU_STACK,		LIN,	MSG_PT_GNU_STACK_CF },
		{ PT_GNU_RELRO,		LIN,	MSG_PT_GNU_RELRO_CF },

		{ 0 }
	};
	static const Val_desc2 phdrs_osabi_cfnp[] = {
		{ PT_SUNWBSS,		SOL,	MSG_PT_SUNWBSS_CFNP },
		{ PT_SUNWSTACK, 	SOL,	MSG_PT_SUNWSTACK_CFNP },
		{ PT_SUNWDTRACE,	SOL,	MSG_PT_SUNWDTRACE_CFNP },
		{ PT_SUNWCAP,		SOL,	MSG_PT_SUNWCAP_CFNP },
		{ PT_SUNW_UNWIND,	SOL,	MSG_PT_SUNW_UNWIND_CFNP },
		{ PT_SUNW_EH_FRAME,	SOL,	MSG_PT_SUNW_EH_FRAME_CFNP },

		{ PT_GNU_EH_FRAME,	LIN,	MSG_PT_GNU_EH_FRAME_CFNP },
		{ PT_GNU_STACK,		LIN,	MSG_PT_GNU_STACK_CFNP },
		{ PT_GNU_RELRO,		LIN,	MSG_PT_GNU_RELRO_CFNP },

		{ 0 }
	};
	static const Val_desc2 phdrs_osabi_nf[] = {
		{ PT_SUNWBSS,		SOL,	MSG_PT_SUNWBSS_NF },
		{ PT_SUNWSTACK, 	SOL,	MSG_PT_SUNWSTACK_NF },
		{ PT_SUNWDTRACE,	SOL,	MSG_PT_SUNWDTRACE_NF },
		{ PT_SUNWCAP,		SOL,	MSG_PT_SUNWCAP_NF },
		{ PT_SUNW_UNWIND,	SOL,	MSG_PT_SUNW_UNWIND_NF },
		{ PT_SUNW_EH_FRAME,	SOL,	MSG_PT_SUNW_EH_FRAME_NF },

		{ PT_GNU_EH_FRAME,	LIN,	MSG_PT_GNU_EH_FRAME_NF },
		{ PT_GNU_STACK,		LIN,	MSG_PT_GNU_STACK_NF },
		{ PT_GNU_RELRO,		LIN,	MSG_PT_GNU_RELRO_NF },

		{ 0 }
	};
#if PT_LOSUNW != PT_SUNWBSS
#error "PT_LOSUNW has grown. Update phdrs_osabi[]"
#endif
	static const conv_ds_vd2_t ds_phdrs_osabi_def = {
	    CONV_DS_VD2, PT_LOOS, PT_HIOS, phdrs_osabi_def };
	static const conv_ds_vd2_t ds_phdrs_osabi_cf = {
	    CONV_DS_VD2, PT_LOOS, PT_HIOS, phdrs_osabi_cf };
	static const conv_ds_vd2_t ds_phdrs_osabi_cfnp = {
	    CONV_DS_VD2, PT_LOOS, PT_HIOS, phdrs_osabi_cfnp };
	static const conv_ds_vd2_t ds_phdrs_osabi_nf = {
	    CONV_DS_VD2, PT_LOOS, PT_HIOS, phdrs_osabi_nf };


	/* Build NULL terminated return arrays for each string style */
	static const const conv_ds_t	*ds_def[] = {
		CONV_DS_ADDR(ds_phdrs_def), CONV_DS_ADDR(ds_phdrs_osabi_def),
		NULL };
	static const conv_ds_t	*ds_dmp[] = {
		CONV_DS_ADDR(ds_phdrs_dmp), CONV_DS_ADDR(ds_phdrs_osabi_cfnp),
		NULL };
	static const conv_ds_t	*ds_cf[] = {
		CONV_DS_ADDR(ds_phdrs_cf), CONV_DS_ADDR(ds_phdrs_osabi_cf),
		NULL };
	static const conv_ds_t	*ds_cfnp[] = {
		CONV_DS_ADDR(ds_phdrs_cfnp), CONV_DS_ADDR(ds_phdrs_osabi_cfnp),
		NULL };
	static const conv_ds_t	*ds_nf[] = {
		CONV_DS_ADDR(ds_phdrs_nf), CONV_DS_ADDR(ds_phdrs_osabi_nf),
		NULL };

	/* Select the strings to use */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_DUMP:
		return (ds_dmp);
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
#undef LIN
}

const char *
conv_phdr_type(uchar_t osabi, Half mach, Word type, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	return (conv_map_ds(osabi, mach, type,
	    conv_phdr_type_strings(fmt_flags), fmt_flags, inv_buf));
}

conv_iter_ret_t
conv_iter_phdr_type(conv_iter_osabi_t osabi, Conv_fmt_flags_t fmt_flags,
    conv_iter_cb_t func, void *uvalue)
{
	return (conv_iter_ds(osabi, EM_NONE,
	    conv_phdr_type_strings(fmt_flags), func, uvalue));
}


static const Val_desc2 *
conv_phdr_flags_strings(Conv_fmt_flags_t fmt_flags)
{
	/* The CF style has the longest strings */
#define	PHDRSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_PF_X_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_PF_W_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_PF_R_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_PF_SUNW_FAILURE_CF_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

	/*
	 * Ensure that Conv_phdr_flags_buf_t is large enough:
	 *
	 * PHDRSZ is the real minimum size of the buffer required by
	 * conv_phdr_flags(). However, Conv_phdr_flags_buf_t uses
	 * CONV_PHDR_FLAGS_BUFSIZE to set the buffer size. We do things this
	 * way because the definition of PHDRSZ uses information that is not
	 * available in the environment of other programs that include the
	 * conv.h header file.
	 */
#if (CONV_PHDR_FLAGS_BUFSIZE != PHDRSZ) && !defined(__lint)
#define	REPORT_BUFSIZE PHDRSZ
#include "report_bufsize.h"
#error "CONV_PHDR_FLAGS_BUFSIZE does not match PHDRSZ"
#endif

#define	ALL	ELFOSABI_NONE, EM_NONE
#define	SOL	ELFOSABI_SOLARIS, EM_NONE

	static const Val_desc2 vda_cf[] = {
		{ PF_X,			ALL,	MSG_PF_X_CF },
		{ PF_W,			ALL,	MSG_PF_W_CF },
		{ PF_R,			ALL,	MSG_PF_R_CF },
		{ PF_SUNW_FAILURE,	SOL,	MSG_PF_SUNW_FAILURE_CF },
		{ 0 }
	};
	static const Val_desc2 vda_nf[] = {
		{ PF_X,			ALL,	MSG_PF_X_NF },
		{ PF_W,			ALL,	MSG_PF_W_NF },
		{ PF_R,			ALL,	MSG_PF_R_NF },
		{ PF_SUNW_FAILURE,	SOL,	MSG_PF_SUNW_FAILURE_NF },
		{ 0 }
	};

	return ((CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_NF) ?
	    vda_nf : vda_cf);

#undef ALL
#undef SOL
}

const char *
conv_phdr_flags(uchar_t osabi, Word flags, Conv_fmt_flags_t fmt_flags,
    Conv_phdr_flags_buf_t *phdr_flags_buf)
{
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (phdr_flags_buf->buf) };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = phdr_flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field2(&conv_arg, osabi, EM_NONE,
	    conv_phdr_flags_strings(fmt_flags), fmt_flags);

	return ((const char *)phdr_flags_buf->buf);
}

conv_iter_ret_t
conv_iter_phdr_flags(conv_iter_osabi_t osabi, Conv_fmt_flags_t fmt_flags,
    conv_iter_cb_t func, void *uvalue)
{
	if (conv_iter_vd2(osabi, EM_NONE,
	    conv_phdr_flags_strings(fmt_flags),
	    func, uvalue) == CONV_ITER_DONE)
		return (CONV_ITER_DONE);

	return (CONV_ITER_CONT);
}
