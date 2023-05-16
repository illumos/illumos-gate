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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2022 Oxide Computer Company
 */

#include	<stdlib.h>
#include	<stdio.h>
#include	<_elfedit.h>
#include	<conv.h>
#include	<msg.h>



/*
 * This file contains support for mapping well known ELF constants
 * to their numeric values. It is a layer on top of the elfedit_atoui()
 * routines defined in util.c. The idea is that centralizing all the
 * support for such constants will improve consistency between modules,
 * allow for sharing of commonly needed items, and make the modules
 * simpler.
 */




/*
 * elfedit output style, with and without leading -o
 */
static elfedit_atoui_sym_t sym_outstyle[] = {
	{ MSG_ORIG(MSG_STR_DEFAULT),		ELFEDIT_OUTSTYLE_DEFAULT },
	{ MSG_ORIG(MSG_STR_SIMPLE),		ELFEDIT_OUTSTYLE_SIMPLE },
	{ MSG_ORIG(MSG_STR_NUM),		ELFEDIT_OUTSTYLE_NUM },
	{ NULL }
};
static elfedit_atoui_sym_t sym_minus_o_outstyle[] = {
	{ MSG_ORIG(MSG_STR_MINUS_O_DEFAULT),	ELFEDIT_OUTSTYLE_DEFAULT },
	{ MSG_ORIG(MSG_STR_MINUS_O_SIMPLE),	ELFEDIT_OUTSTYLE_SIMPLE },
	{ MSG_ORIG(MSG_STR_MINUS_O_NUM),	ELFEDIT_OUTSTYLE_NUM },
	{ NULL }
};


/*
 * Booleans
 */
static elfedit_atoui_sym_t sym_bool[] = {
	{ MSG_ORIG(MSG_STR_T),			1 },
	{ MSG_ORIG(MSG_STR_F),			0 },
	{ MSG_ORIG(MSG_STR_TRUE),		1 },
	{ MSG_ORIG(MSG_STR_FALSE),		0 },
	{ MSG_ORIG(MSG_STR_ON),			1 },
	{ MSG_ORIG(MSG_STR_OFF),		0 },
	{ MSG_ORIG(MSG_STR_YES),		1 },
	{ MSG_ORIG(MSG_STR_NO),			0 },
	{ MSG_ORIG(MSG_STR_Y),			1 },
	{ MSG_ORIG(MSG_STR_N),			0 },
	{ NULL }
};

/*
 * ELF strings for SHT_STRTAB
 */
static elfedit_atoui_sym_t sym_sht_strtab[] = {
	{ MSG_ORIG(MSG_SHT_STRTAB),		SHT_STRTAB },
	{ MSG_ORIG(MSG_SHT_STRTAB_ALT1),	SHT_STRTAB },

	{ NULL }
};


/*
 * Strings for SHT_SYMTAB
 */
static elfedit_atoui_sym_t sym_sht_symtab[] = {
	{ MSG_ORIG(MSG_SHT_SYMTAB),		SHT_SYMTAB },
	{ MSG_ORIG(MSG_SHT_SYMTAB_ALT1),	SHT_SYMTAB },

	{ NULL }
};

/*
 * Strings for SHT_DYNSYM
 */
static elfedit_atoui_sym_t sym_sht_dynsym[] = {
	{ MSG_ORIG(MSG_SHT_DYNSYM),		SHT_DYNSYM },
	{ MSG_ORIG(MSG_SHT_DYNSYM_ALT1),	SHT_DYNSYM },

	{ NULL }
};

/*
 * Strings for SHT_SUNW_LDYNSYM
 */
static elfedit_atoui_sym_t sym_sht_ldynsym[] = {
	{ MSG_ORIG(MSG_SHT_SUNW_LDYNSYM),	SHT_SUNW_LDYNSYM },
	{ MSG_ORIG(MSG_SHT_SUNW_LDYNSYM_ALT1),	SHT_SUNW_LDYNSYM },

	{ NULL }
};



/*
 * Types of items found in sym_table[]. All items other than STE_STATIC
 * pulls strings from libconv, differing in the interface required by
 * the libconv iteration function used.
 */
typedef enum {
	STE_STATIC =		0,	/* Constants are statically defined */
	STE_LC =		1,	/* Libconv, pull once */
	STE_LC_OS =		2,	/* From libconv, osabi dependency */
	STE_LC_MACH =		3,	/* From libconv, mach dependency */
	STE_LC_OS_MACH =	4	/* From libconv, osabi/mach dep. */
} ste_type_t;

/*
 * Interface of functions called to fill strings from libconv
 */
typedef conv_iter_ret_t	(* libconv_iter_func_simple_t)(
			    Conv_fmt_flags_t, conv_iter_cb_t, void *);
typedef conv_iter_ret_t	(* libconv_iter_func_os_t)(conv_iter_osabi_t,
			    Conv_fmt_flags_t, conv_iter_cb_t, void *);
typedef conv_iter_ret_t	(* libconv_iter_func_mach_t)(Half,
			    Conv_fmt_flags_t, conv_iter_cb_t, void *);
typedef conv_iter_ret_t	(* libconv_iter_func_os_mach_t)(conv_iter_osabi_t, Half,
			    Conv_fmt_flags_t, conv_iter_cb_t, void *);
typedef union {
	libconv_iter_func_simple_t	simple;
	libconv_iter_func_os_t		osabi;
	libconv_iter_func_mach_t	mach;
	libconv_iter_func_os_mach_t	osabi_mach;
} libconv_iter_func_t;

/*
 * State for each type of constant
 */
typedef struct {
	ste_type_t		ste_type;	/* Type of entry */
	elfedit_atoui_sym_t	*ste_arr;	/* NULL, or atoui array */
	void			*ste_alloc;	/* Current memory allocation */
	size_t			ste_nelts;	/* # items in ste_alloc */
	libconv_iter_func_t	ste_conv_func;	/* libconv fill function */
} sym_table_ent_t;


/*
 * Array of state for each constant type, including the array of atoui
 * pointers, for each constant type, indexed by elfedit_const_t value.
 * The number and order of entries in this table must agree with the
 * definition of elfedit_const_t in elfedit.h.
 *
 * note:
 * -	STE_STATIC items must supply a statically allocated buffer here.
 * -	The non-STE_STATIC items use libconv strings. These items are
 *	initialized by init_libconv_strings() at runtime, and are represented
 *	by a simple { 0 } here. The memory used for these arrays is dynamic,
 *	and can be released and rebuilt at runtime as necessary to keep up
 *	with changes in osabi or machine type.
 */
static sym_table_ent_t sym_table[ELFEDIT_CONST_NUM] = {
						/* #: ELFEDIT_CONST_xxx */
	{ STE_STATIC, sym_outstyle },		/* 0: OUTSTYLE */
	{ STE_STATIC, sym_minus_o_outstyle },	/* 1: OUTSTYLE_MO */
	{ STE_STATIC, sym_bool },		/* 2: BOOL */
	{ STE_STATIC, sym_sht_strtab },		/* 3: SHT_STRTAB */
	{ STE_STATIC, sym_sht_symtab },		/* 4: SHT_SYMTAB */
	{ STE_STATIC, sym_sht_dynsym },		/* 5: SHT_DYNSYM */
	{ STE_STATIC, sym_sht_ldynsym },	/* 6: SHT_LDYNSYM */
	{ 0 },					/* 7: SHN */
	{ 0 },					/* 8: SHT */
	{ 0 },					/* 9: SHT_ALLSYMTAB */
	{ 0 },					/* 10: DT */
	{ 0 },					/* 11: DF */
	{ 0 },					/* 12: DF_P1 */
	{ 0 },					/* 13: DF_1 */
	{ 0 },					/* 14: DTF_1 */
	{ 0 },					/* 15: EI */
	{ 0 },					/* 16: ET */
	{ 0 },					/* 17: ELFCLASS */
	{ 0 },					/* 18: ELFDATA */
	{ 0 },					/* 19: EF */
	{ 0 },					/* 20: EV */
	{ 0 },					/* 21: EM */
	{ 0 },					/* 22: ELFOSABI */
	{ 0 },					/* 23: EAV osabi version */
	{ 0 },					/* 24: PT */
	{ 0 },					/* 25: PF */
	{ 0 },					/* 26: SHF */
	{ 0 },					/* 27: STB */
	{ 0 },					/* 28: STT */
	{ 0 },					/* 29: STV */
	{ 0 },					/* 30: SYMINFO_BT */
	{ 0 },					/* 31: SYMINFO_FLG */
	{ 0 },					/* 32: CA */
	{ 0 },					/* 33: AV */
	{ 0 },					/* 34: SF1_SUNW */
};
#if ELFEDIT_CONST_NUM != (ELFEDIT_CONST_SF1_SUNW)
error "ELFEDIT_CONST_NUM has grown. Update sym_table[]"
#endif




/*
 * Used to count the number of descriptors that will be needed to hold
 * strings from libconv.
 */
/*ARGSUSED*/
static conv_iter_ret_t
libconv_count_cb(const char *str, Conv_elfvalue_t value, void *uvalue)
{
	size_t *cnt = (size_t *)uvalue;

	(*cnt)++;
	return (CONV_ITER_CONT);
}

/*
 * Used to fill in the descriptors with strings from libconv.
 */
typedef struct {
	size_t			cur;	/* Index of next descriptor */
	size_t			cnt;	/* # of descriptors */
	elfedit_atoui_sym_t	*desc;	/* descriptors */
} libconv_fill_state_t;

static conv_iter_ret_t
libconv_fill_cb(const char *str, Conv_elfvalue_t value, void *uvalue)
{
	libconv_fill_state_t	*fill_state = (libconv_fill_state_t *)uvalue;
	elfedit_atoui_sym_t	*sym = &fill_state->desc[fill_state->cur++];

	sym->sym_name = str;
	sym->sym_value = value;
	return (CONV_ITER_CONT);
}


/*
 * Call the iteration function using the correct calling sequence for
 * the libconv routine.
 */
static void
libconv_fill_iter(sym_table_ent_t *sym, conv_iter_osabi_t osabi, Half mach,
    conv_iter_cb_t func, void *uvalue)
{
	switch (sym->ste_type) {
	case STE_LC:
		(void) (* sym->ste_conv_func.simple)(
		    CONV_FMT_ALT_CF, func, uvalue);
		(void) (* sym->ste_conv_func.simple)(
		    CONV_FMT_ALT_NF, func, uvalue);
		break;

	case STE_LC_OS:
		(void) (* sym->ste_conv_func.osabi)(osabi,
		    CONV_FMT_ALT_CF, func, uvalue);
		(void) (* sym->ste_conv_func.osabi)(osabi,
		    CONV_FMT_ALT_NF, func, uvalue);
		break;

	case STE_LC_MACH:
		(void) (* sym->ste_conv_func.mach)(mach,
		    CONV_FMT_ALT_CF, func, uvalue);
		(void) (* sym->ste_conv_func.mach)(mach,
		    CONV_FMT_ALT_NF, func, uvalue);
		break;

	case STE_LC_OS_MACH:
		(void) (* sym->ste_conv_func.osabi_mach)(osabi, mach,
		    CONV_FMT_ALT_CF, func, uvalue);
		(void) (* sym->ste_conv_func.osabi_mach)(osabi, mach,
		    CONV_FMT_ALT_NF, func, uvalue);
		break;

	case STE_STATIC:
		break;
	}
}

/*
 * Allocate/Fill an atoui array for the specified constant.
 */
static void
libconv_fill(sym_table_ent_t *sym, conv_iter_osabi_t osabi, Half mach)
{
	libconv_fill_state_t	fill_state;

	/* How many descriptors will we need? */
	fill_state.cnt = 1;		/* Extra for NULL termination */
	libconv_fill_iter(sym, osabi, mach, libconv_count_cb, &fill_state.cnt);

	/*
	 * If there is an existing allocation, and it is not large enough,
	 * release it.
	 */
	if ((sym->ste_alloc != NULL) && (fill_state.cnt > sym->ste_nelts)) {
		free(sym->ste_alloc);
		sym->ste_alloc = NULL;
		sym->ste_nelts = 0;
	}

	/* Allocate memory if don't already have an allocation */
	if (sym->ste_alloc == NULL) {
		sym->ste_alloc = elfedit_malloc(MSG_INTL(MSG_ALLOC_ELFCONDESC),
		    fill_state.cnt * sizeof (*fill_state.desc));
		sym->ste_nelts = fill_state.cnt;
	}

	/* Fill the array */
	fill_state.desc = sym->ste_alloc;
	fill_state.cur = 0;
	libconv_fill_iter(sym, osabi, mach, libconv_fill_cb, &fill_state);

	/* Add null termination */
	fill_state.desc[fill_state.cur].sym_name = NULL;
	fill_state.desc[fill_state.cur].sym_value = 0;

	/* atoui array for this item is now available */
	sym->ste_arr = fill_state.desc;
}

/*
 * Should be called on first call to elfedit_const_to_atoui(). Does the
 * runtime initialization of sym_table.
 */
static void
init_libconv_strings(conv_iter_osabi_t *osabi, Half *mach)
{
	/*
	 * It is critical that the ste_type and ste_conv_func values
	 * agree. Since the libconv iteration function signatures can
	 * change (gain or lose an osabi or mach argument), we want to
	 * ensure that the compiler will catch such changes.
	 *
	 * The compiler will catch an attempt to assign a function of
	 * the wrong type to ste_conv_func. Using these macros, we ensure
	 * that the ste_type and function assignment happen as a unit.
	 */
#define	LC(_ndx, _func) sym_table[_ndx].ste_type = STE_LC; \
	sym_table[_ndx].ste_conv_func.simple = _func;
#define	LC_OS(_ndx, _func) sym_table[_ndx].ste_type = STE_LC_OS; \
	sym_table[_ndx].ste_conv_func.osabi = _func;
#define	LC_MACH(_ndx, _func) sym_table[_ndx].ste_type = STE_LC_MACH; \
	sym_table[_ndx].ste_conv_func.mach = _func;
#define	LC_OS_MACH(_ndx, _func) sym_table[_ndx].ste_type = STE_LC_OS_MACH; \
	sym_table[_ndx].ste_conv_func.osabi_mach = _func;


	if (!state.file.present) {
		/*
		 * No input file: Supply the maximal set of strings for
		 * all osabi and mach values understood by libconv.
		 */
		*osabi = CONV_OSABI_ALL;
		*mach = CONV_MACH_ALL;
	} else if (state.elf.elfclass == ELFCLASS32) {
		*osabi = state.elf.obj_state.s32->os_ehdr->e_ident[EI_OSABI];
		*mach = state.elf.obj_state.s32->os_ehdr->e_machine;
	} else {
		*osabi = state.elf.obj_state.s64->os_ehdr->e_ident[EI_OSABI];
		*mach = state.elf.obj_state.s64->os_ehdr->e_machine;
	}

	/* Set up non- STE_STATIC libconv fill functions */
	LC_OS_MACH(ELFEDIT_CONST_SHN,		conv_iter_sym_shndx);
	LC_OS_MACH(ELFEDIT_CONST_SHT,		conv_iter_sec_type);
	LC_OS(ELFEDIT_CONST_SHT_ALLSYMTAB,	conv_iter_sec_symtab);
	LC_OS_MACH(ELFEDIT_CONST_DT,		conv_iter_dyn_tag);
	LC(ELFEDIT_CONST_DF,			conv_iter_dyn_flag);
	LC(ELFEDIT_CONST_DF_P1,			conv_iter_dyn_posflag1);
	LC(ELFEDIT_CONST_DF_1,			conv_iter_dyn_flag1);
	LC(ELFEDIT_CONST_DTF_1,			conv_iter_dyn_feature1);
	LC(ELFEDIT_CONST_EI,			conv_iter_ehdr_eident);
	LC_OS(ELFEDIT_CONST_ET,			conv_iter_ehdr_type);
	LC(ELFEDIT_CONST_ELFCLASS,		conv_iter_ehdr_class);
	LC(ELFEDIT_CONST_ELFDATA,		conv_iter_ehdr_data);
	LC_MACH(ELFEDIT_CONST_EF,		conv_iter_ehdr_flags);
	LC(ELFEDIT_CONST_EV,			conv_iter_ehdr_vers);
	LC(ELFEDIT_CONST_EM,			conv_iter_ehdr_mach);
	LC(ELFEDIT_CONST_ELFOSABI,		conv_iter_ehdr_osabi);
	LC_OS(ELFEDIT_CONST_EAV,		conv_iter_ehdr_abivers);
	LC_OS(ELFEDIT_CONST_PT,			conv_iter_phdr_type);
	LC_OS(ELFEDIT_CONST_PF,			conv_iter_phdr_flags);
	LC_OS_MACH(ELFEDIT_CONST_SHF,		conv_iter_sec_flags);
	LC(ELFEDIT_CONST_STB,			conv_iter_sym_info_bind);
	LC_MACH(ELFEDIT_CONST_STT,		conv_iter_sym_info_type);
	LC(ELFEDIT_CONST_STV,			conv_iter_sym_other_vis);
	LC(ELFEDIT_CONST_SYMINFO_BT,		conv_iter_syminfo_boundto);
	LC(ELFEDIT_CONST_SYMINFO_FLG,		conv_iter_syminfo_flags);
	LC(ELFEDIT_CONST_CA,			conv_iter_cap_tags);
	LC_MACH(ELFEDIT_CONST_HW1_SUNW,		conv_iter_cap_val_hw1);
	LC(ELFEDIT_CONST_SF1_SUNW,		conv_iter_cap_val_sf1);
	LC_MACH(ELFEDIT_CONST_HW2_SUNW,		conv_iter_cap_val_hw2);
	LC_MACH(ELFEDIT_CONST_HW3_SUNW,		conv_iter_cap_val_hw3);

#undef LC
#undef LC_OS
#undef LC_MACH
#undef LC_OS_MACH
}

/*
 * If the user has changed the osabi or machine type of the object,
 * then we need to discard the strings we've loaded from libconv
 * that are dependent on these values.
 */
static void
invalidate_libconv_strings(conv_iter_osabi_t *osabi, Half *mach)
{
	uchar_t		cur_osabi;
	Half		cur_mach;
	sym_table_ent_t	*sym;
	int		osabi_change, mach_change;
	int		i;


	/* Reset the ELF header change notification */
	state.elf.elfconst_ehdr_change = 0;

	if (state.elf.elfclass == ELFCLASS32) {
		cur_osabi = state.elf.obj_state.s32->os_ehdr->e_ident[EI_OSABI];
		cur_mach = state.elf.obj_state.s32->os_ehdr->e_machine;
	} else {
		cur_osabi = state.elf.obj_state.s64->os_ehdr->e_ident[EI_OSABI];
		cur_mach = state.elf.obj_state.s64->os_ehdr->e_machine;
	}

	/* What has changed? */
	mach_change = *mach != cur_mach;
	osabi_change = *osabi != cur_osabi;
	if (!(mach_change || osabi_change))
		return;

	/*
	 * Set the ste_arr pointer to NULL for any items that
	 * depend on the things that have changed. Note that we
	 * do not release the allocated memory --- it may turn
	 * out to be large enough to hold the new strings, so we
	 * keep the allocation and leave that decision to the fill
	 * routine, which will run the next time those strings are
	 * needed.
	 */
	for (i = 0, sym = sym_table;
	    i < (sizeof (sym_table) / sizeof (sym_table[0])); i++, sym++) {
		if (sym->ste_arr == NULL)
			continue;

		switch (sym->ste_type) {
		case STE_STATIC:
		case STE_LC:
			break;

		case STE_LC_OS:
			if (osabi_change)
				sym->ste_arr = NULL;
			break;

		case STE_LC_MACH:
			if (mach_change)
				sym->ste_arr = NULL;
			break;

		case STE_LC_OS_MACH:
			if (osabi_change || mach_change)
				sym->ste_arr = NULL;
			break;
		}
	}

	*mach = cur_mach;
	*osabi = cur_osabi;
}



/*
 * Given an elfedit_const_t value, return the array of elfedit_atoui_sym_t
 * entries that it represents.
 */
elfedit_atoui_sym_t *
elfedit_const_to_atoui(elfedit_const_t const_type)
{
	static int			first = 1;
	static conv_iter_osabi_t	osabi;
	static Half			mach;

	sym_table_ent_t	*sym;

	if (first) {
		init_libconv_strings(&osabi, &mach);
		first = 0;
	}

	if ((const_type < 0) ||
	    (const_type >= (sizeof (sym_table) / sizeof (sym_table[0]))))
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_BADCONST));
	sym = &sym_table[const_type];

	/*
	 * If the constant is not STE_STATIC, then we may need to fetch
	 * the strings from libconv.
	 */
	if (sym->ste_type != STE_STATIC) {
		/*
		 * If the ELF header has changed since the last
		 * time we were called, then we need to invalidate any
		 * strings previously pulled from libconv that have
		 * an osabi or machine dependency.
		 */
		if (state.elf.elfconst_ehdr_change)
			invalidate_libconv_strings(&osabi, &mach);

		/* If we don't already have the strings, get them */
		if (sym->ste_arr == NULL)
			libconv_fill(sym, osabi, mach);
	}

	return (sym->ste_arr);
}
