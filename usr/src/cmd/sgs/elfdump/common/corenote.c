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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/corectl.h>
#include <procfs.h>
#include <msg.h>
#include <_elfdump.h>
#include <struct_layout.h>
#include <conv.h>


/*
 * This module contains the code that displays data from the note
 * sections found in Solaris core files. The format of these
 * note sections are described in the core(4) manpage.
 */




/*
 * Much of the code in this file uses the "%*s" format to set
 * the left margin indentation. This macro combines the indent
 * integer argument and the NULL string that follows it.
 */
#define	INDENT state->ns_indent, MSG_ORIG(MSG_STR_EMPTY)

/*
 * Indent unit, used for each nesting
 */
#define	INDENT_STEP 4

/*
 * The PRINT_ macros are convenience wrappers on print_num(),
 * print_subtype(), and print_strbuf(). They reduce code
 * clutter by hiding the boilerplate arguments.
 *
 * Assumptions:
 *	- A variable named "layout" exists in the compilation
 *		environment, referencing the layout information for the
 *		current type.
 *	- The variable "state" references the current note state.
 */
#define	PRINT_DEC(_title, _field) \
	print_num(state, _title, &layout->_field, SL_FMT_NUM_DEC)
#define	PRINT_DEC_2UP(_title1, _field1, _title2, _field2) \
	print_num_2up(state, _title1, &layout->_field1, SL_FMT_NUM_DEC, \
	    _title2, &layout->_field2, SL_FMT_NUM_DEC)
#define	PRINT_HEX(_title, _field) \
	print_num(state, _title, &layout->_field, SL_FMT_NUM_HEX)
#define	PRINT_HEX_2UP(_title1, _field1, _title2, _field2) \
	print_num_2up(state, _title1, &layout->_field1, SL_FMT_NUM_HEX, \
	    _title2, &layout->_field2, SL_FMT_NUM_HEX)
#define	PRINT_ZHEX(_title, _field) \
	print_num(state, _title, &layout->_field, SL_FMT_NUM_ZHEX)
#define	PRINT_ZHEX_2UP(_title1, _field1, _title2, _field2) \
	print_num_2up(state, _title1, &layout->_field1, SL_FMT_NUM_ZHEX, \
	    _title2, &layout->_field2, SL_FMT_NUM_ZHEX)
#define	PRINT_SUBTYPE(_title, _field, _func) \
	print_subtype(state, _title, &layout->_field, _func)
#define	PRINT_STRBUF(_title, _field) \
	print_strbuf(state, _title, &layout->_field)



/*
 * Structure used to maintain state data for a core note, or a subregion
 * (sub-struct) of a core note. These values would otherwise need to be
 * passed to nearly every routine.
 */
typedef struct {
	Half		ns_mach;	/* ELF machine type of core file */
	const sl_arch_layout_t *ns_arch; /* structure layout def for mach */
	int		ns_swap;	/* True if byte swapping is needed */
	int		ns_indent;	/* Left margin indentation */
	int		ns_vcol;	/* Column where value starts */
	int		ns_t2col;	/* Column where 2up title starts */
	int		ns_v2col;	/* Column where 2up value starts */
	const char	*ns_data;	/* Pointer to struct data area */
	Word		ns_len;		/* Length of struct data area */
} note_state_t;

/*
 * Standard signature for a dump function used to process a note
 * or a sub-structure within a note.
 */
typedef void (* dump_func_t)(note_state_t *state, const char *title);






/*
 * Some core notes contain string buffers of fixed size
 * that are expected to contain NULL terminated strings.
 * If the NULL is there, we can print these strings directly.
 * However, the potential exists for a corrupt file to have
 * a non-terminated buffer. This routine examines the given
 * string, and if the string is terminated, the string itself
 * is returned. Otherwise, it is copied to a static buffer,
 * and a pointer to the buffer is returned.
 */
static const char *
safe_str(const char *str, size_t n)
{
	static char	buf[512];
	char		*s;
	size_t		i;

	if (n == 0)
		return (MSG_ORIG(MSG_STR_EMPTY));

	for (i = 0; i < n; i++)
		if (str[i] == '\0')
			return (str);

	i = (n >= sizeof (buf)) ? (sizeof (buf) - 4) : (n - 1);
	(void) memcpy(buf, str, i);
	s = buf + i;
	if (n >= sizeof (buf)) {
		*s++ = '.';
		*s++ = '.';
		*s++ = '.';
	}
	*s = '\0';
	return (buf);
}

/*
 * Convenience wrappers on top of the corresponding sl_XXX() functions.
 */
static Word
extract_as_word(note_state_t *state, const sl_field_t *fdesc)
{
	return (sl_extract_as_word(state->ns_data, state->ns_swap, fdesc));
}
static Lword
extract_as_lword(note_state_t *state, const sl_field_t *fdesc)
{
	return (sl_extract_as_lword(state->ns_data, state->ns_swap, fdesc));
}
static int
extract_as_sword(note_state_t *state, const sl_field_t *fdesc)
{
	return (sl_extract_as_sword(state->ns_data, state->ns_swap, fdesc));
}
static const char *
fmt_num(note_state_t *state, const sl_field_t *fdesc,
    sl_fmt_num_t fmt_type, sl_fmtbuf_t buf)
{
	return (sl_fmt_num(state->ns_data, state->ns_swap, fdesc,
	    fmt_type, buf));
}


/*
 * Return true of the data for the specified field is available.
 */
inline static int
data_present(note_state_t *state, const sl_field_t *fdesc)
{
	return ((fdesc->slf_offset + fdesc->slf_eltlen) <= state->ns_len);
}

/*
 * indent_enter/exit are used to start/end output for a subitem.
 * On entry, a title is output, and the indentation level is raised
 * by one unit. On exit, the indentation level is restrored to its
 * previous value.
 */
static void
indent_enter(note_state_t *state, const char *title,
    const sl_field_t *first_fdesc)
{
	/*
	 * If the first field offset and extent fall past the end of the
	 * available data, then return without printing a title. That note
	 * is from an older core file that doesn't have all the fields
	 * that we know about.
	 */
	if (data_present(state, first_fdesc))
		dbg_print(0, MSG_ORIG(MSG_CNOTE_FMT_TITLE), INDENT, title);

	state->ns_indent += INDENT_STEP;
}
static void
indent_exit(note_state_t *state)
{
	state->ns_indent -= INDENT_STEP;
}


/*
 * print_num outputs a field on one line, in the format:
 *
 *	title: value
 */
static void
print_num(note_state_t *state, const char *title,
    const sl_field_t *fdesc, sl_fmt_num_t fmt_type)
{
	sl_fmtbuf_t	buf;

	/*
	 * If the field offset and extent fall past the end of the
	 * available data, then return without doing anything. That note
	 * is from an older core file that doesn't have all the fields
	 * that we know about.
	 */
	if (!data_present(state, fdesc))
		return;

	dbg_print(0, MSG_ORIG(MSG_CNOTE_FMT_LINE), INDENT,
	    state->ns_vcol - state->ns_indent, title,
	    fmt_num(state, fdesc, fmt_type, buf));
}

/*
 * print_num_2up outputs two fields on one line, in the format:
 *
 *	title1: value1	title2: value2
 */
static void
print_num_2up(note_state_t *state, const char *title1,
    const sl_field_t *fdesc1, sl_fmt_num_t fmt_type1, const char *title2,
    const sl_field_t *fdesc2, sl_fmt_num_t fmt_type2)
{
	sl_fmtbuf_t	buf1, buf2;

	/*
	 * If the field offset and extent fall past the end of the
	 * available data, then return without doing anything. That note
	 * is from an older core file that doesn't have all the fields
	 * that we know about.
	 */
	if (!(data_present(state, fdesc1) &&
	    data_present(state, fdesc2)))
		return;

	dbg_print(0, MSG_ORIG(MSG_CNOTE_FMT_LINE_2UP), INDENT,
	    state->ns_vcol - state->ns_indent, title1,
	    state->ns_t2col - state->ns_vcol,
	    fmt_num(state, fdesc1, fmt_type1, buf1),
	    state->ns_v2col - state->ns_t2col, title2,
	    fmt_num(state, fdesc2, fmt_type2, buf2));
}

/*
 * print_strbuf outputs a fixed sized character buffer field
 * on one line, in the format:
 *
 *	title: value
 */
static void
print_strbuf(note_state_t *state, const char *title,
    const sl_field_t *fdesc)
{
	Word	n;

	/*
	 * If we are past the end of the data area, then return
	 * without doing anything. That note is from an older core
	 * file that doesn't have all the fields that we know about.
	 *
	 * Note that we are willing to accept a partial buffer,
	 * so we don't use data_present() for this test.
	 */
	if (fdesc->slf_offset >= state->ns_len)
		return;

	/*
	 * We expect the full buffer to be present, but if there
	 * is less than that, we will still proceed. The use of safe_str()
	 * protects us from the effect of printing garbage data.
	 */
	n = state->ns_len - fdesc->slf_offset;
	if (n > fdesc->slf_nelts)
		n = fdesc->slf_nelts;

	dbg_print(0, MSG_ORIG(MSG_CNOTE_FMT_LINE), INDENT,
	    state->ns_vcol - state->ns_indent,
	    title, safe_str(fdesc->slf_offset + state->ns_data, n));
}

/*
 * print_str outputs an arbitrary string value item
 * on one line, in the format:
 *
 *	title: str
 */
static void
print_str(note_state_t *state, const char *title, const char *str)
{
	dbg_print(0, MSG_ORIG(MSG_CNOTE_FMT_LINE), INDENT,
	    state->ns_vcol - state->ns_indent, title, str);
}

/*
 * Used when one dump function needs to call another dump function
 * in order to display a subitem. This routine constructs a state
 * block for the sub-region, and then calls the dump function with it.
 * This limits the amount of data visible to the sub-function to that
 * for the sub-item.
 */
static void
print_subtype(note_state_t *state, const char *title,
    const sl_field_t *fdesc, dump_func_t dump_func)
{
	note_state_t sub_state;

	/*
	 * If there is no data for the sub-item, return immediately.
	 * Partial data is left to the dump function to handle,
	 * as that can be a sign of an older core file with less data,
	 * which can still be interpreted.
	 */
	if (fdesc->slf_offset >= state->ns_len)
		return;

	/*
	 * Construct a state block that reflects the sub-item
	 */
	sub_state = *state;
	sub_state.ns_data += fdesc->slf_offset;
	sub_state.ns_len -= fdesc->slf_offset;
	if (sub_state.ns_len > fdesc->slf_eltlen)
		sub_state.ns_len = fdesc->slf_eltlen;

	(* dump_func)(&sub_state, title);
}


/*
 * Output a sequence of array elements, giving each
 * element an index, in the format:
 *
 *	[ndx] value
 *
 * entry:
 *	state - Current state
 *	base_desc - Field descriptor for 1st element of array
 *	nelts - # of array elements to display
 *	check_nelts - If True (1), nelts is clipped to fdesc->slf_nelts.
 *		If False (1), nelts is not clipped.
 *	title - Name of array
 */
static void
print_array(note_state_t *state, const sl_field_t *base_desc,
    sl_fmt_num_t fmt_type, int nelts, int check_nelts, const char *title)
{
	char		index1[MAXNDXSIZE], index2[MAXNDXSIZE];
	int		i;
	sl_field_t	fdesc1, fdesc2;

	if (check_nelts && (check_nelts > base_desc->slf_nelts))
		nelts = base_desc->slf_nelts;
	if (nelts == 0)
		return;

	indent_enter(state, title, base_desc);

	fdesc1 = fdesc2 = *base_desc;
	for (i = 0; i < nelts; ) {
		if (i == (nelts - 1)) {
			/*  One final value is left  */
			if (!data_present(state, &fdesc1))
				break;
			(void) snprintf(index1, sizeof (index1),
			    MSG_ORIG(MSG_FMT_INDEX2), EC_WORD(i));
			print_num(state, index1, &fdesc1, fmt_type);
			fdesc1.slf_offset += fdesc1.slf_eltlen;
			i++;
			continue;
		}

		/* There are at least 2 items left. Show 2 up. */
		fdesc2.slf_offset = fdesc1.slf_offset + fdesc1.slf_eltlen;
		if (!(data_present(state, &fdesc1) &&
		    data_present(state, &fdesc2)))
			break;
		(void) snprintf(index1, sizeof (index1),
		    MSG_ORIG(MSG_FMT_INDEX2), EC_WORD(i));
		(void) snprintf(index2, sizeof (index2),
		    MSG_ORIG(MSG_FMT_INDEX2), EC_WORD(i + 1));
		print_num_2up(state, index1, &fdesc1, fmt_type,
		    index2, &fdesc2, fmt_type);
		fdesc1.slf_offset += 2 * fdesc1.slf_eltlen;
		i += 2;
	}

	indent_exit(state);
}


/*
 * Output information from auxv_t structure.
 */
static void
dump_auxv(note_state_t *state, const char *title)
{
	const sl_auxv_layout_t	*layout = state->ns_arch->auxv;
	union {
		Conv_cap_val_hw1_buf_t		hw1;
		Conv_cap_val_hw2_buf_t		hw2;
		Conv_cnote_auxv_af_buf_t	auxv_af;
		Conv_ehdr_flags_buf_t		ehdr_flags;
		Conv_secflags_buf_t		secflags;
		Conv_inv_buf_t			inv;
	} conv_buf;
	sl_fmtbuf_t	buf;
	int		ndx, ndx_start;
	Word		sizeof_auxv;

	sizeof_auxv = layout->sizeof_struct.slf_eltlen;

	indent_enter(state, title, &layout->sizeof_struct);

	/*
	 * Immediate indent_exit() restores the indent level to
	 * that of the title. We include indentation as part of
	 * the index string, which is right justified, and don't
	 * want the usual indentation spacing.
	 */
	indent_exit(state);

	ndx = 0;
	while (state->ns_len > sizeof_auxv) {
		char		index[(MAXNDXSIZE * 2) + 1];
		sl_fmt_num_t	num_fmt = SL_FMT_NUM_ZHEX;
		const char	*vstr = NULL;
		Word		w;
		int		type;
		sl_field_t	a_type_next;

		type = extract_as_word(state, &layout->a_type);
		ndx_start = ndx;
		switch (type) {
		case AT_NULL:
			a_type_next = layout->a_type;
			a_type_next.slf_offset += sizeof_auxv;
			while ((state->ns_len - sizeof_auxv) >= sizeof_auxv) {
				type = extract_as_word(state, &a_type_next);
				if (type != AT_NULL)
					break;
				ndx++;
				state->ns_data += sizeof_auxv;
				state->ns_len -= sizeof_auxv;
			}
			num_fmt = SL_FMT_NUM_HEX;
			break;



		case AT_IGNORE:
		case AT_SUN_IFLUSH:
			num_fmt = SL_FMT_NUM_HEX;
			break;

		case AT_EXECFD:
		case AT_PHENT:
		case AT_PHNUM:
		case AT_PAGESZ:
		case AT_SUN_UID:
		case AT_SUN_RUID:
		case AT_SUN_GID:
		case AT_SUN_RGID:
		case AT_SUN_LPAGESZ:
		case AT_SUN_FPSIZE:
		case AT_SUN_FPTYPE:
			num_fmt = SL_FMT_NUM_DEC;
			break;

		case AT_FLAGS:	/* processor flags */
			w = extract_as_word(state, &layout->a_val);
			vstr = conv_ehdr_flags(state->ns_mach, w,
			    0, &conv_buf.ehdr_flags);
			break;

		case AT_SUN_HWCAP:
			w = extract_as_word(state, &layout->a_val);
			vstr = conv_cap_val_hw1(w, state->ns_mach,
			    0, &conv_buf.hw1);
			/*
			 * conv_cap_val_hw1() produces output like:
			 *
			 *	0xfff [ flg1 flg2 0xff]
			 *
			 * where the first hex value is the complete value,
			 * and the second is the leftover bits. We only
			 * want the part in brackets, and failing that,
			 * would rather fall back to formatting the full
			 * value ourselves.
			 */
			while ((*vstr != '\0') && (*vstr != '['))
				vstr++;
			if (*vstr != '[')
				vstr = NULL;
			num_fmt = SL_FMT_NUM_HEX;
			break;
		case AT_SUN_HWCAP2:
			w = extract_as_word(state, &layout->a_val);
			vstr = conv_cap_val_hw2(w, state->ns_mach,
			    0, &conv_buf.hw2);
			/*
			 * conv_cap_val_hw2() produces output like:
			 *
			 *	0xfff [ flg1 flg2 0xff]
			 *
			 * where the first hex value is the complete value,
			 * and the second is the leftover bits. We only
			 * want the part in brackets, and failing that,
			 * would rather fall back to formatting the full
			 * value ourselves.
			 */
			while ((*vstr != '\0') && (*vstr != '['))
				vstr++;
			if (*vstr != '[')
				vstr = NULL;
			num_fmt = SL_FMT_NUM_HEX;
			break;



		case AT_SUN_AUXFLAGS:
			w = extract_as_word(state, &layout->a_val);
			vstr = conv_cnote_auxv_af(w, 0, &conv_buf.auxv_af);
			num_fmt = SL_FMT_NUM_HEX;
			break;
		}

		if (ndx == ndx_start)
			(void) snprintf(index, sizeof (index),
			    MSG_ORIG(MSG_FMT_INDEX2), EC_WORD(ndx));
		else
			(void) snprintf(index, sizeof (index),
			    MSG_ORIG(MSG_FMT_INDEXRNG),
			    EC_WORD(ndx_start), EC_WORD(ndx));

		if (vstr == NULL)
			vstr = fmt_num(state, &layout->a_val, num_fmt, buf);
		dbg_print(0, MSG_ORIG(MSG_CNOTE_FMT_AUXVLINE), INDENT, index,
		    state->ns_vcol - state->ns_indent,
		    conv_cnote_auxv_type(type, CONV_FMT_DECIMAL,
		    &conv_buf.inv), vstr);

		state->ns_data += sizeof_auxv;
		state->ns_len -= sizeof_auxv;
		ndx++;
	}
}


/*
 * Output information from fltset_t structure.
 */
static void
dump_fltset(note_state_t *state, const char *title)
{
#define	NELTS 4

	const sl_fltset_layout_t	*layout = state->ns_arch->fltset;
	Conv_cnote_fltset_buf_t	buf;
	sl_field_t		fdesc;
	uint32_t		mask[NELTS];
	int			i, nelts;

	if (!data_present(state, &layout->sizeof_struct))
		return;

	fdesc = layout->word;
	nelts = fdesc.slf_nelts;
	if (nelts > NELTS)	/* Type has grown? Show what we understand */
		nelts = NELTS;
	for (i = 0; i < nelts; i++) {
		mask[i] = extract_as_word(state, &fdesc);
		fdesc.slf_offset += fdesc.slf_eltlen;
	}

	print_str(state, title, conv_cnote_fltset(mask, nelts, 0, &buf));

#undef NELTS
}


/*
 * Output information from sigset_t structure.
 */
static void
dump_sigset(note_state_t *state, const char *title)
{
#define	NELTS 4

	const sl_sigset_layout_t	*layout = state->ns_arch->sigset;
	Conv_cnote_sigset_buf_t	buf;
	sl_field_t		fdesc;
	uint32_t		mask[NELTS];
	int			i, nelts;

	if (!data_present(state, &layout->sizeof_struct))
		return;

	fdesc = layout->sigbits;
	nelts = fdesc.slf_nelts;
	if (nelts > NELTS)	/* Type has grown? Show what we understand */
		nelts = NELTS;
	for (i = 0; i < nelts; i++) {
		mask[i] = extract_as_word(state, &fdesc);
		fdesc.slf_offset += fdesc.slf_eltlen;
	}

	print_str(state, title, conv_cnote_sigset(mask, nelts, 0, &buf));

#undef NELTS
}


/*
 * Output information from sigaction structure.
 */
static void
dump_sigaction(note_state_t *state, const char *title)
{
	const sl_sigaction_layout_t	*layout = state->ns_arch->sigaction;
	Conv_cnote_sa_flags_buf_t	conv_buf;
	Word	w;

	indent_enter(state, title, &layout->sa_flags);

	if (data_present(state, &layout->sa_flags)) {
		w = extract_as_word(state, &layout->sa_flags);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_SA_FLAGS),
		    conv_cnote_sa_flags(w, 0, &conv_buf));
	}

	PRINT_ZHEX_2UP(MSG_ORIG(MSG_CNOTE_T_SA_HANDLER), sa_hand,
	    MSG_ORIG(MSG_CNOTE_T_SA_SIGACTION), sa_sigact);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_SA_MASK), sa_mask, dump_sigset);

	indent_exit(state);
}


/*
 * Output information from siginfo structure.
 */
static void
dump_siginfo(note_state_t *state, const char *title)
{
	const sl_siginfo_layout_t	*layout = state->ns_arch->siginfo;
	Conv_inv_buf_t	inv_buf;
	Word		w;
	int		v_si_code, v_si_signo;

	if (!data_present(state, &layout->sizeof_struct))
		return;

	indent_enter(state, title, &layout->f_si_signo);

	v_si_signo = extract_as_sword(state, &layout->f_si_signo);
	print_str(state, MSG_ORIG(MSG_CNOTE_T_SI_SIGNO),
	    conv_cnote_signal(v_si_signo, CONV_FMT_DECIMAL, &inv_buf));

	w = extract_as_word(state, &layout->f_si_errno);
	print_str(state, MSG_ORIG(MSG_CNOTE_T_SI_ERRNO),
	    conv_cnote_errno(w, CONV_FMT_DECIMAL, &inv_buf));

	v_si_code = extract_as_sword(state, &layout->f_si_code);
	print_str(state, MSG_ORIG(MSG_CNOTE_T_SI_CODE),
	    conv_cnote_si_code(state->ns_mach, v_si_signo, v_si_code,
	    CONV_FMT_DECIMAL, &inv_buf));

	if ((v_si_signo == 0) || (v_si_code == SI_NOINFO)) {
		indent_exit(state);
		return;
	}

	/* User generated signals have (si_code <= 0) */
	if (v_si_code <= 0) {
		PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_SI_PID), f_si_pid);
		PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_SI_UID), f_si_uid);
		PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_SI_CTID), f_si_ctid);
		PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_SI_ZONEID), f_si_zoneid);
		switch (v_si_code) {
		case SI_QUEUE:
		case SI_TIMER:
		case SI_ASYNCIO:
		case SI_MESGQ:
			indent_enter(state, MSG_ORIG(MSG_CNOTE_T_SI_VALUE),
			    &layout->f_si_value_int);
			PRINT_ZHEX(MSG_ORIG(MSG_CNOTE_T_SIVAL_INT),
			    f_si_value_int);
			PRINT_ZHEX(MSG_ORIG(MSG_CNOTE_T_SIVAL_PTR),
			    f_si_value_ptr);
			indent_exit(state);
			break;
		}
		indent_exit(state);
		return;
	}

	/*
	 * Remaining cases are kernel generated signals. Output any
	 * signal or code specific information.
	 */
	if (v_si_code == SI_RCTL)
		PRINT_HEX(MSG_ORIG(MSG_CNOTE_T_SI_ENTITY), f_si_entity);
	switch (v_si_signo) {
	case SIGILL:
	case SIGFPE:
	case SIGSEGV:
	case SIGBUS:
		PRINT_ZHEX(MSG_ORIG(MSG_CNOTE_T_SI_ADDR), f_si_addr);
		break;
	case SIGCHLD:
		PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_SI_PID), f_si_pid);
		PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_SI_STATUS), f_si_status);
		break;
	case SIGPOLL:
		PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_SI_BAND), f_si_band);
		break;
	}

	indent_exit(state);
}


/*
 * Output information from stack_t structure.
 */
static void
dump_stack(note_state_t *state, const char *title)
{
	const sl_stack_layout_t		*layout = state->ns_arch->stack;
	Conv_cnote_ss_flags_buf_t	conv_buf;
	Word		w;

	indent_enter(state, title, &layout->ss_size);

	print_num_2up(state, MSG_ORIG(MSG_CNOTE_T_SS_SP), &layout->ss_sp,
	    SL_FMT_NUM_ZHEX, MSG_ORIG(MSG_CNOTE_T_SS_SIZE), &layout->ss_size,
	    SL_FMT_NUM_HEX);

	if (data_present(state, &layout->ss_flags)) {
		w = extract_as_word(state, &layout->ss_flags);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_SS_FLAGS),
		    conv_cnote_ss_flags(w, 0, &conv_buf));
	}

	indent_exit(state);
}


/*
 * Output information from sysset_t structure.
 */
static void
dump_sysset(note_state_t *state, const char *title)
{
#define	NELTS 16

	const sl_sysset_layout_t	*layout = state->ns_arch->sysset;
	Conv_cnote_sysset_buf_t	buf;
	sl_field_t		fdesc;
	uint32_t		mask[NELTS];
	int			i, nelts;

	if (!data_present(state, &layout->sizeof_struct))
		return;

	fdesc = layout->word;
	nelts = fdesc.slf_nelts;
	if (nelts > NELTS)	/* Type has grown? Show what we understand */
		nelts = NELTS;
	for (i = 0; i < nelts; i++) {
		mask[i] = extract_as_word(state, &fdesc);
		fdesc.slf_offset += fdesc.slf_eltlen;
	}

	print_str(state, title, conv_cnote_sysset(mask, nelts, 0, &buf));

#undef NELTS
}


/*
 * Output information from timestruc_t structure.
 */
static void
dump_timestruc(note_state_t *state, const char *title)
{
	const sl_timestruc_layout_t *layout = state->ns_arch->timestruc;

	indent_enter(state, title, &layout->tv_sec);

	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_TV_SEC), tv_sec,
	    MSG_ORIG(MSG_CNOTE_T_TV_NSEC), tv_nsec);

	indent_exit(state);
}

/*
 * Output information from prsecflags_t structure.
 */
static void
dump_secflags(note_state_t *state, const char *title)
{
	const sl_prsecflags_layout_t *layout = state->ns_arch->prsecflags;
	Conv_secflags_buf_t inv;
	Lword lw;
	Word w;

	indent_enter(state, title, &layout->pr_version);

	w = extract_as_word(state, &layout->pr_version);

	if (w != PRSECFLAGS_VERSION_1) {
		PRINT_DEC(MSG_INTL(MSG_NOTE_BAD_SECFLAGS_VER), pr_version);
		dump_hex_bytes(state->ns_data, state->ns_len, state->ns_indent,
		    4, 3);
	} else {
		PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_VERSION), pr_version);
		lw = extract_as_lword(state, &layout->pr_effective);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_EFFECTIVE),
		    conv_prsecflags(lw, 0, &inv));

		lw = extract_as_lword(state, &layout->pr_inherit);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_INHERIT),
		    conv_prsecflags(lw, 0, &inv));

		lw = extract_as_lword(state, &layout->pr_lower);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_LOWER),
		    conv_prsecflags(lw, 0, &inv));

		lw = extract_as_lword(state, &layout->pr_upper);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_UPPER),
		    conv_prsecflags(lw, 0, &inv));
	}

	indent_exit(state);
}

/*
 * Output information from utsname structure.
 */
static void
dump_utsname(note_state_t *state, const char *title)
{
	const sl_utsname_layout_t	*layout = state->ns_arch->utsname;

	indent_enter(state, title, &layout->sysname);

	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_UTS_SYSNAME), sysname);
	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_UTS_NODENAME), nodename);
	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_UTS_RELEASE), release);
	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_UTS_VERSION), version);
	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_UTS_MACHINE), machine);

	indent_exit(state);
}


/*
 * Dump register contents
 */
static void
dump_prgregset(note_state_t *state, const char *title)
{
	sl_field_t	fdesc1, fdesc2;
	sl_fmtbuf_t	buf1, buf2;
	Conv_inv_buf_t	inv_buf1, inv_buf2;
	Word		w;

	fdesc1 = fdesc2 = state->ns_arch->prgregset->elt0;
	indent_enter(state, title, &fdesc1);

	for (w = 0; w < fdesc1.slf_nelts; ) {
		if (w == (fdesc1.slf_nelts - 1)) {
			/* One last register is left */
			if (!data_present(state, &fdesc1))
				break;
			dbg_print(0, MSG_ORIG(MSG_CNOTE_FMT_LINE),
			    INDENT, state->ns_vcol - state->ns_indent,
			    conv_cnote_pr_regname(state->ns_mach, w,
			    CONV_FMT_DECIMAL, &inv_buf1),
			    fmt_num(state, &fdesc1, SL_FMT_NUM_ZHEX, buf1));
			fdesc1.slf_offset += fdesc1.slf_eltlen;
			w++;
			continue;
		}

		/* There are at least 2 more registers left. Show 2 up */
		fdesc2.slf_offset = fdesc1.slf_offset + fdesc1.slf_eltlen;
		if (!(data_present(state, &fdesc1) &&
		    data_present(state, &fdesc2)))
			break;
		dbg_print(0, MSG_ORIG(MSG_CNOTE_FMT_LINE_2UP), INDENT,
		    state->ns_vcol - state->ns_indent,
		    conv_cnote_pr_regname(state->ns_mach, w,
		    CONV_FMT_DECIMAL, &inv_buf1),
		    state->ns_t2col - state->ns_vcol,
		    fmt_num(state, &fdesc1, SL_FMT_NUM_ZHEX, buf1),
		    state->ns_v2col - state->ns_t2col,
		    conv_cnote_pr_regname(state->ns_mach, w + 1,
		    CONV_FMT_DECIMAL, &inv_buf2),
		    fmt_num(state, &fdesc2, SL_FMT_NUM_ZHEX, buf2));
		fdesc1.slf_offset += 2 * fdesc1.slf_eltlen;
		w += 2;
	}

	indent_exit(state);
}

/*
 * Output information from lwpstatus_t structure.
 */
static void
dump_lwpstatus(note_state_t *state, const char *title)
{
	const sl_lwpstatus_layout_t	*layout = state->ns_arch->lwpstatus;
	Word		w, w2;
	int32_t		i;
	union {
		Conv_inv_buf_t			inv;
		Conv_cnote_pr_flags_buf_t	flags;
	} conv_buf;

	indent_enter(state, title, &layout->pr_flags);

	if (data_present(state, &layout->pr_flags)) {
		w = extract_as_word(state, &layout->pr_flags);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_FLAGS),
		    conv_cnote_pr_flags(w, 0, &conv_buf.flags));
	}

	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_LWPID), pr_lwpid);

	if (data_present(state, &layout->pr_why)) {
		w = extract_as_word(state, &layout->pr_why);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_WHY),
		    conv_cnote_pr_why(w, 0, &conv_buf.inv));

		if (data_present(state, &layout->pr_what)) {
			w2 = extract_as_word(state, &layout->pr_what);
			print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_WHAT),
			    conv_cnote_pr_what(w, w2, 0, &conv_buf.inv));
		}
	}

	if (data_present(state, &layout->pr_cursig)) {
		w = extract_as_word(state, &layout->pr_cursig);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_CURSIG),
		    conv_cnote_signal(w, CONV_FMT_DECIMAL, &conv_buf.inv));
	}

	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_INFO), pr_info, dump_siginfo);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_LWPPEND), pr_lwppend,
	    dump_sigset);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_LWPHOLD), pr_lwphold,
	    dump_sigset);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_ACTION), pr_action,
	    dump_sigaction);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_ALTSTACK), pr_altstack,
	    dump_stack);

	PRINT_ZHEX(MSG_ORIG(MSG_CNOTE_T_PR_OLDCONTEXT), pr_oldcontext);

	if (data_present(state, &layout->pr_syscall)) {
		w = extract_as_word(state, &layout->pr_syscall);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_SYSCALL),
		    conv_cnote_syscall(w, CONV_FMT_DECIMAL, &conv_buf.inv));
	}

	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_NSYSARG), pr_nsysarg);

	if (data_present(state, &layout->pr_errno)) {
		w = extract_as_word(state, &layout->pr_errno);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_ERRNO),
		    conv_cnote_errno(w, CONV_FMT_DECIMAL, &conv_buf.inv));
	}

	if (data_present(state, &layout->pr_nsysarg)) {
		w2 = extract_as_word(state, &layout->pr_nsysarg);
		print_array(state, &layout->pr_sysarg, SL_FMT_NUM_ZHEX, w2, 1,
		    MSG_ORIG(MSG_CNOTE_T_PR_SYSARG));
	}

	PRINT_HEX_2UP(MSG_ORIG(MSG_CNOTE_T_PR_RVAL1), pr_rval1,
	    MSG_ORIG(MSG_CNOTE_T_PR_RVAL2), pr_rval2);
	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_PR_CLNAME), pr_clname);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_TSTAMP), pr_tstamp,
	    dump_timestruc);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_UTIME), pr_utime, dump_timestruc);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_STIME), pr_stime, dump_timestruc);

	if (data_present(state, &layout->pr_errpriv)) {
		i = extract_as_sword(state, &layout->pr_errpriv);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_ERRPRIV),
		    conv_cnote_priv(i, CONV_FMT_DECIMAL, &conv_buf.inv));
	}

	PRINT_ZHEX_2UP(MSG_ORIG(MSG_CNOTE_T_PR_USTACK), pr_ustack,
	    MSG_ORIG(MSG_CNOTE_T_PR_INSTR), pr_instr);

	/*
	 * In order to line up all the values in a single column,
	 * we would have to set vcol to a very high value, which results
	 * in ugly looking output that runs off column 80. So, we use
	 * two levels of vcol, one for the contents so far, and a
	 * higher one for the pr_reg sub-struct.
	 */
	state->ns_vcol += 3;
	state->ns_t2col += 3;
	state->ns_v2col += 2;
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_REG), pr_reg, dump_prgregset);
	state->ns_vcol -= 3;
	state->ns_t2col -= 3;
	state->ns_v2col -= 2;

	/*
	 * The floating point register state is complex, and highly
	 * platform dependent. For now, we simply display it as
	 * a hex dump. This can be replaced if better information
	 * is required.
	 */
	if (data_present(state, &layout->pr_fpreg)) {
		indent_enter(state, MSG_ORIG(MSG_CNOTE_T_PR_FPREG),
		    &layout->pr_fpreg);
		dump_hex_bytes(layout->pr_fpreg.slf_offset + state->ns_data,
		    layout->pr_fpreg.slf_eltlen, state->ns_indent, 4, 3);
		indent_exit(state);
	}

	indent_exit(state);
}


/*
 * Output information from pstatus_t structure.
 */
static void
dump_pstatus(note_state_t *state, const char *title)
{
	const sl_pstatus_layout_t	*layout = state->ns_arch->pstatus;
	Word				w;
	union {
		Conv_inv_buf_t			inv;
		Conv_cnote_pr_flags_buf_t	flags;
	} conv_buf;

	indent_enter(state, title, &layout->pr_flags);

	if (data_present(state, &layout->pr_flags)) {
		w = extract_as_word(state, &layout->pr_flags);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_FLAGS),
		    conv_cnote_pr_flags(w, 0, &conv_buf.flags));
	}

	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_NLWP), pr_nlwp);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_PID), pr_pid,
	    MSG_ORIG(MSG_CNOTE_T_PR_PPID), pr_ppid);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_PGID), pr_pgid,
	    MSG_ORIG(MSG_CNOTE_T_PR_SID), pr_sid);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_ASLWPID), pr_aslwpid,
	    MSG_ORIG(MSG_CNOTE_T_PR_AGENTID), pr_agentid);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_SIGPEND), pr_sigpend,
	    dump_sigset);
	print_num_2up(state, MSG_ORIG(MSG_CNOTE_T_PR_BRKBASE),
	    &layout->pr_brkbase, SL_FMT_NUM_ZHEX,
	    MSG_ORIG(MSG_CNOTE_T_PR_BRKSIZE),
	    &layout->pr_brksize, SL_FMT_NUM_HEX);
	print_num_2up(state, MSG_ORIG(MSG_CNOTE_T_PR_STKBASE),
	    &layout->pr_stkbase, SL_FMT_NUM_ZHEX,
	    MSG_ORIG(MSG_CNOTE_T_PR_STKSIZE),
	    &layout->pr_stksize, SL_FMT_NUM_HEX);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_UTIME), pr_utime, dump_timestruc);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_STIME), pr_stime, dump_timestruc);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_CUTIME), pr_cutime,
	    dump_timestruc);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_CSTIME), pr_cstime,
	    dump_timestruc);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_SIGTRACE), pr_sigtrace,
	    dump_sigset);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_FLTTRACE), pr_flttrace,
	    dump_fltset);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_SYSENTRY), pr_sysentry,
	    dump_sysset);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_SYSEXIT), pr_sysexit,
	    dump_sysset);

	if (data_present(state, &layout->pr_dmodel)) {
		w = extract_as_word(state, &layout->pr_dmodel);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_DMODEL),
		    conv_cnote_pr_dmodel(w, 0, &conv_buf.inv));
	}

	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_TASKID), pr_taskid,
	    MSG_ORIG(MSG_CNOTE_T_PR_PROJID), pr_projid);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_NZOMB), pr_nzomb,
	    MSG_ORIG(MSG_CNOTE_T_PR_ZONEID), pr_zoneid);

	/*
	 * In order to line up all the values in a single column,
	 * we would have to set vcol to a very high value, which results
	 * in ugly looking output that runs off column 80. So, we use
	 * two levels of vcol, one for the contents so far, and a
	 * higher one for the pr_lwp sub-struct.
	 */
	state->ns_vcol += 5;
	state->ns_t2col += 5;
	state->ns_v2col += 5;

	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_LWP), pr_lwp, dump_lwpstatus);
	state->ns_vcol -= 5;
	state->ns_t2col -= 5;
	state->ns_v2col -= 5;

	indent_exit(state);
}


/*
 * Output information from prstatus_t (<sys/old_procfs.h>) structure.
 */
static void
dump_prstatus(note_state_t *state, const char *title)
{
	const sl_prstatus_layout_t	*layout = state->ns_arch->prstatus;
	Word				w, w2;
	int				i;
	union {
		Conv_inv_buf_t			inv;
		Conv_cnote_old_pr_flags_buf_t	flags;
	} conv_buf;

	indent_enter(state, title, &layout->pr_flags);

	if (data_present(state, &layout->pr_flags)) {
		w = extract_as_word(state, &layout->pr_flags);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_FLAGS),
		    conv_cnote_old_pr_flags(w, 0, &conv_buf.flags));
	}

	if (data_present(state, &layout->pr_why)) {
		w = extract_as_word(state, &layout->pr_why);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_WHY),
		    conv_cnote_pr_why(w, 0, &conv_buf.inv));


		if (data_present(state, &layout->pr_what)) {
			w2 = extract_as_word(state, &layout->pr_what);
			print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_WHAT),
			    conv_cnote_pr_what(w, w2, 0, &conv_buf.inv));
		}
	}

	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_INFO), pr_info, dump_siginfo);

	if (data_present(state, &layout->pr_cursig)) {
		w = extract_as_word(state, &layout->pr_cursig);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_CURSIG),
		    conv_cnote_signal(w, CONV_FMT_DECIMAL, &conv_buf.inv));
	}

	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_NLWP), pr_nlwp);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_SIGPEND), pr_sigpend,
	    dump_sigset);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_SIGHOLD), pr_sighold,
	    dump_sigset);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_ALTSTACK), pr_altstack,
	    dump_stack);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_ACTION), pr_action,
	    dump_sigaction);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_PID), pr_pid,
	    MSG_ORIG(MSG_CNOTE_T_PR_PPID), pr_ppid);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_PGRP), pr_pgrp,
	    MSG_ORIG(MSG_CNOTE_T_PR_SID), pr_sid);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_UTIME), pr_utime, dump_timestruc);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_STIME), pr_stime, dump_timestruc);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_CUTIME), pr_cutime,
	    dump_timestruc);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_CSTIME), pr_cstime,
	    dump_timestruc);
	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_PR_CLNAME), pr_clname);

	if (data_present(state, &layout->pr_syscall)) {
		w = extract_as_word(state, &layout->pr_syscall);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_SYSCALL),
		    conv_cnote_syscall(w, CONV_FMT_DECIMAL, &conv_buf.inv));
	}

	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_NSYSARG), pr_nsysarg);

	if (data_present(state, &layout->pr_nsysarg)) {
		w2 = extract_as_word(state, &layout->pr_nsysarg);
		print_array(state, &layout->pr_sysarg, SL_FMT_NUM_ZHEX, w2, 1,
		    MSG_ORIG(MSG_CNOTE_T_PR_SYSARG));
	}

	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_WHO), pr_who);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_LWPPEND), pr_sigpend,
	    dump_sigset);
	PRINT_ZHEX(MSG_ORIG(MSG_CNOTE_T_PR_OLDCONTEXT), pr_oldcontext);
	print_num_2up(state, MSG_ORIG(MSG_CNOTE_T_PR_BRKBASE),
	    &layout->pr_brkbase, SL_FMT_NUM_ZHEX,
	    MSG_ORIG(MSG_CNOTE_T_PR_BRKSIZE),
	    &layout->pr_brksize, SL_FMT_NUM_HEX);
	print_num_2up(state, MSG_ORIG(MSG_CNOTE_T_PR_STKBASE),
	    &layout->pr_stkbase, SL_FMT_NUM_ZHEX,
	    MSG_ORIG(MSG_CNOTE_T_PR_STKSIZE),
	    &layout->pr_stksize, SL_FMT_NUM_HEX);
	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_PROCESSOR), pr_processor);

	if (data_present(state, &layout->pr_bind)) {
		i = extract_as_sword(state, &layout->pr_bind);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_BIND),
		    conv_cnote_psetid(i, CONV_FMT_DECIMAL, &conv_buf.inv));
	}

	PRINT_ZHEX(MSG_ORIG(MSG_CNOTE_T_PR_INSTR), pr_instr);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_REG), pr_reg, dump_prgregset);

	indent_exit(state);
}


/*
 * Print percent from 16-bit binary fraction [0 .. 1]
 * Round up .01 to .1 to indicate some small percentage (the 0x7000 below).
 *
 * Note: This routine was copied from ps(1) and then modified.
 */
static const char *
prtpct_value(note_state_t *state, const sl_field_t *fdesc,
    sl_fmtbuf_t buf)
{
	uint_t value;		/* need 32 bits to compute with */

	value = extract_as_word(state, fdesc);
	value = ((value * 1000) + 0x7000) >> 15;	/* [0 .. 1000] */
	if (value >= 1000)
		value = 999;

	(void) snprintf(buf, sizeof (sl_fmtbuf_t),
	    MSG_ORIG(MSG_CNOTE_FMT_PRTPCT), value / 10, value % 10);

	return (buf);
}



/*
 * Version of prtpct() used for a 2-up display of two adjacent percentages.
 */
static void
prtpct_2up(note_state_t *state, const sl_field_t *fdesc1,
    const char *title1, const sl_field_t *fdesc2, const char *title2)
{
	sl_fmtbuf_t	buf1, buf2;

	if (!(data_present(state, fdesc1) &&
	    data_present(state, fdesc2)))
		return;

	dbg_print(0, MSG_ORIG(MSG_CNOTE_FMT_LINE_2UP), INDENT,
	    state->ns_vcol - state->ns_indent, title1,
	    state->ns_t2col - state->ns_vcol,
	    prtpct_value(state, fdesc1, buf1),
	    state->ns_v2col - state->ns_t2col, title2,
	    prtpct_value(state, fdesc2, buf2));
}


/*
 * The psinfo_t and prpsinfo_t structs have pr_state and pr_sname
 * fields that we wish to print in a 2up format. The pr_state is
 * an integer, while pr_sname is a single character.
 */
static void
print_state_sname_2up(note_state_t *state,
    const sl_field_t *state_fdesc,
    const sl_field_t *sname_fdesc)
{
	sl_fmtbuf_t	buf1, buf2;
	int		sname;

	/*
	 * If the field slf_offset and extent fall past the end of the
	 * available data, then return without doing anything. That note
	 * is from an older core file that doesn't have all the fields
	 * that we know about.
	 */
	if (!(data_present(state, state_fdesc) &&
	    data_present(state, sname_fdesc)))
		return;

	sname = extract_as_sword(state, sname_fdesc);
	buf2[0] = sname;
	buf2[1] = '\0';

	dbg_print(0, MSG_ORIG(MSG_CNOTE_FMT_LINE_2UP), INDENT,
	    state->ns_vcol - state->ns_indent, MSG_ORIG(MSG_CNOTE_T_PR_STATE),
	    state->ns_t2col - state->ns_vcol,
	    fmt_num(state, state_fdesc, SL_FMT_NUM_DEC, buf1),
	    state->ns_v2col - state->ns_t2col, MSG_ORIG(MSG_CNOTE_T_PR_SNAME),
	    buf2);
}

/*
 * Output information from lwpsinfo_t structure.
 */
static void
dump_lwpsinfo(note_state_t *state, const char *title)
{
	const sl_lwpsinfo_layout_t	*layout = state->ns_arch->lwpsinfo;
	Word			w;
	int32_t			i;
	union {
		Conv_cnote_proc_flag_buf_t	proc_flag;
		Conv_inv_buf_t			inv;
	} conv_buf;

	indent_enter(state, title, &layout->pr_flag);

	if (data_present(state, &layout->pr_flag)) {
		w = extract_as_word(state, &layout->pr_flag);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_FLAG),
		    conv_cnote_proc_flag(w, 0, &conv_buf.proc_flag));
	}

	print_num_2up(state, MSG_ORIG(MSG_CNOTE_T_PR_LWPID), &layout->pr_lwpid,
	    SL_FMT_NUM_DEC, MSG_ORIG(MSG_CNOTE_T_PR_ADDR), &layout->pr_addr,
	    SL_FMT_NUM_ZHEX);
	PRINT_HEX(MSG_ORIG(MSG_CNOTE_T_PR_WCHAN), pr_wchan);

	if (data_present(state, &layout->pr_stype)) {
		w = extract_as_word(state, &layout->pr_stype);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_STYPE),
		    conv_cnote_pr_stype(w, CONV_FMT_DECIMAL, &conv_buf.inv));
	}

	print_state_sname_2up(state, &layout->pr_state, &layout->pr_sname);

	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_NICE), pr_nice);

	if (data_present(state, &layout->pr_syscall)) {
		w = extract_as_word(state, &layout->pr_syscall);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_SYSCALL),
		    conv_cnote_syscall(w, CONV_FMT_DECIMAL, &conv_buf.inv));
	}

	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_OLDPRI), pr_oldpri,
	    MSG_ORIG(MSG_CNOTE_T_PR_CPU), pr_cpu);

	if (data_present(state, &layout->pr_pri) &&
	    data_present(state, &layout->pr_pctcpu)) {
		sl_fmtbuf_t	buf1, buf2;

		dbg_print(0, MSG_ORIG(MSG_CNOTE_FMT_LINE_2UP), INDENT,
		    state->ns_vcol - state->ns_indent,
		    MSG_ORIG(MSG_CNOTE_T_PR_PRI),
		    state->ns_t2col - state->ns_vcol,
		    fmt_num(state, &layout->pr_pri, SL_FMT_NUM_DEC, buf1),
		    state->ns_v2col - state->ns_t2col,
		    MSG_ORIG(MSG_CNOTE_T_PR_PCTCPU),
		    prtpct_value(state, &layout->pr_pctcpu, buf2));
	}

	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_START), pr_start, dump_timestruc);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_TIME), pr_time, dump_timestruc);
	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_PR_CLNAME), pr_clname);
	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_PR_NAME), pr_name);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_ONPRO), pr_onpro,
	    MSG_ORIG(MSG_CNOTE_T_PR_BINDPRO), pr_bindpro);

	if (data_present(state, &layout->pr_bindpset)) {
		i = extract_as_sword(state, &layout->pr_bindpset);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_BINDPSET),
		    conv_cnote_psetid(i, CONV_FMT_DECIMAL, &conv_buf.inv));
	}

	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_LGRP), pr_lgrp);

	indent_exit(state);
}


/*
 * Output information from psinfo_t structure.
 */
static void
dump_psinfo(note_state_t *state, const char *title)
{
	const sl_psinfo_layout_t	*layout = state->ns_arch->psinfo;
	Word				w;
	union {
		Conv_cnote_proc_flag_buf_t	proc_flag;
		Conv_inv_buf_t			inv;
	} conv_buf;

	indent_enter(state, title, &layout->pr_flag);

	if (data_present(state, &layout->pr_flag)) {
		w = extract_as_word(state, &layout->pr_flag);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_FLAG),
		    conv_cnote_proc_flag(w, 0, &conv_buf.proc_flag));
	}

	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_NLWP), pr_nlwp);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_PID), pr_pid,
	    MSG_ORIG(MSG_CNOTE_T_PR_PPID), pr_ppid);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_PGID), pr_pgid,
	    MSG_ORIG(MSG_CNOTE_T_PR_SID), pr_sid);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_UID), pr_uid,
	    MSG_ORIG(MSG_CNOTE_T_PR_EUID), pr_euid);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_GID), pr_gid,
	    MSG_ORIG(MSG_CNOTE_T_PR_EGID), pr_egid);
	print_num_2up(state, MSG_ORIG(MSG_CNOTE_T_PR_ADDR), &layout->pr_addr,
	    SL_FMT_NUM_ZHEX, MSG_ORIG(MSG_CNOTE_T_PR_SIZE), &layout->pr_size,
	    SL_FMT_NUM_HEX);
	print_num_2up(state, MSG_ORIG(MSG_CNOTE_T_PR_RSSIZE),
	    &layout->pr_rssize, SL_FMT_NUM_HEX, MSG_ORIG(MSG_CNOTE_T_PR_TTYDEV),
	    &layout->pr_ttydev, SL_FMT_NUM_DEC);
	prtpct_2up(state, &layout->pr_pctcpu, MSG_ORIG(MSG_CNOTE_T_PR_PCTCPU),
	    &layout->pr_pctmem, MSG_ORIG(MSG_CNOTE_T_PR_PCTMEM));
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_START), pr_start, dump_timestruc);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_TIME), pr_time, dump_timestruc);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_CTIME), pr_ctime, dump_timestruc);
	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_PR_FNAME), pr_fname);
	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_PR_PSARGS), pr_psargs);
	print_num_2up(state, MSG_ORIG(MSG_CNOTE_T_PR_WSTAT), &layout->pr_wstat,
	    SL_FMT_NUM_HEX, MSG_ORIG(MSG_CNOTE_T_PR_ARGC), &layout->pr_argc,
	    SL_FMT_NUM_DEC);
	PRINT_ZHEX_2UP(MSG_ORIG(MSG_CNOTE_T_PR_ARGV), pr_argv,
	    MSG_ORIG(MSG_CNOTE_T_PR_ENVP), pr_envp);

	if (data_present(state, &layout->pr_dmodel)) {
		w = extract_as_word(state, &layout->pr_dmodel);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_DMODEL),
		    conv_cnote_pr_dmodel(w, 0, &conv_buf.inv));
	}

	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_TASKID), pr_taskid,
	    MSG_ORIG(MSG_CNOTE_T_PR_PROJID), pr_projid);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_NZOMB), pr_nzomb,
	    MSG_ORIG(MSG_CNOTE_T_PR_POOLID), pr_poolid);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_ZONEID), pr_zoneid,
	    MSG_ORIG(MSG_CNOTE_T_PR_CONTRACT), pr_contract);

	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_LWP), pr_lwp, dump_lwpsinfo);

	indent_exit(state);
}

/*
 * Output information from prpsinfo_t structure.
 */
static void
dump_prpsinfo(note_state_t *state, const char *title)
{
	const sl_prpsinfo_layout_t	*layout = state->ns_arch->prpsinfo;
	Word				w;
	union {
		Conv_cnote_proc_flag_buf_t	proc_flag;
		Conv_inv_buf_t			inv;
	} conv_buf;

	indent_enter(state, title, &layout->pr_state);

	print_state_sname_2up(state, &layout->pr_state, &layout->pr_sname);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_ZOMB), pr_zomb,
	    MSG_ORIG(MSG_CNOTE_T_PR_NICE), pr_nice);

	if (data_present(state, &layout->pr_flag)) {
		w = extract_as_word(state, &layout->pr_flag);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_FLAG),
		    conv_cnote_proc_flag(w, 0, &conv_buf.proc_flag));
	}


	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_UID), pr_uid,
	    MSG_ORIG(MSG_CNOTE_T_PR_GID), pr_gid);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_PID), pr_pid,
	    MSG_ORIG(MSG_CNOTE_T_PR_PPID), pr_ppid);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_PGRP), pr_pgrp,
	    MSG_ORIG(MSG_CNOTE_T_PR_SID), pr_sid);
	print_num_2up(state, MSG_ORIG(MSG_CNOTE_T_PR_ADDR), &layout->pr_addr,
	    SL_FMT_NUM_ZHEX, MSG_ORIG(MSG_CNOTE_T_PR_SIZE), &layout->pr_size,
	    SL_FMT_NUM_HEX);
	PRINT_HEX_2UP(MSG_ORIG(MSG_CNOTE_T_PR_RSSIZE), pr_rssize,
	    MSG_ORIG(MSG_CNOTE_T_PR_WCHAN), pr_wchan);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_START), pr_start, dump_timestruc);
	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_TIME), pr_time, dump_timestruc);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_PRI), pr_pri,
	    MSG_ORIG(MSG_CNOTE_T_PR_OLDPRI), pr_oldpri);
	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_CPU), pr_cpu);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_OTTYDEV), pr_ottydev,
	    MSG_ORIG(MSG_CNOTE_T_PR_LTTYDEV), pr_lttydev);
	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_PR_CLNAME), pr_clname);
	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_PR_FNAME), pr_fname);
	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_PR_PSARGS), pr_psargs);

	if (data_present(state, &layout->pr_syscall)) {
		w = extract_as_word(state, &layout->pr_syscall);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_SYSCALL),
		    conv_cnote_syscall(w, CONV_FMT_DECIMAL, &conv_buf.inv));
	}

	PRINT_SUBTYPE(MSG_ORIG(MSG_CNOTE_T_PR_CTIME), pr_ctime, dump_timestruc);
	PRINT_HEX_2UP(MSG_ORIG(MSG_CNOTE_T_PR_BYSIZE), pr_bysize,
	    MSG_ORIG(MSG_CNOTE_T_PR_BYRSSIZE), pr_byrssize);
	print_num_2up(state, MSG_ORIG(MSG_CNOTE_T_PR_ARGC), &layout->pr_argc,
	    SL_FMT_NUM_DEC, MSG_ORIG(MSG_CNOTE_T_PR_ARGV), &layout->pr_argv,
	    SL_FMT_NUM_ZHEX);
	print_num_2up(state, MSG_ORIG(MSG_CNOTE_T_PR_ENVP), &layout->pr_envp,
	    SL_FMT_NUM_ZHEX, MSG_ORIG(MSG_CNOTE_T_PR_WSTAT), &layout->pr_wstat,
	    SL_FMT_NUM_HEX);
	prtpct_2up(state, &layout->pr_pctcpu, MSG_ORIG(MSG_CNOTE_T_PR_PCTCPU),
	    &layout->pr_pctmem, MSG_ORIG(MSG_CNOTE_T_PR_PCTMEM));
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_EUID), pr_euid,
	    MSG_ORIG(MSG_CNOTE_T_PR_EGID), pr_egid);
	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_ASLWPID), pr_aslwpid);

	if (data_present(state, &layout->pr_dmodel)) {
		w = extract_as_word(state, &layout->pr_dmodel);
		print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_DMODEL),
		    conv_cnote_pr_dmodel(w, 0, &conv_buf.inv));
	}

	indent_exit(state);
}


/*
 * Output information from prcred_t structure.
 */
static void
dump_prcred(note_state_t *state, const char *title)
{
	const sl_prcred_layout_t *layout = state->ns_arch->prcred;
	Word		ngroups;

	indent_enter(state, title, &layout->pr_euid);

	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_EUID), pr_euid,
	    MSG_ORIG(MSG_CNOTE_T_PR_RUID), pr_ruid);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_SUID), pr_suid,
	    MSG_ORIG(MSG_CNOTE_T_PR_EGID), pr_egid);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_RGID), pr_rgid,
	    MSG_ORIG(MSG_CNOTE_T_PR_SGID), pr_sgid);
	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_NGROUPS), pr_ngroups);

	if (data_present(state, &layout->pr_ngroups)) {
		ngroups = extract_as_word(state, &layout->pr_ngroups);
		print_array(state, &layout->pr_groups, SL_FMT_NUM_DEC, ngroups,
		    0, MSG_ORIG(MSG_CNOTE_T_PR_GROUPS));
	}

	indent_exit(state);
}


/*
 * Output information from prpriv_t structure.
 */
static void
dump_prpriv(note_state_t *state, const char *title)
{
	const sl_prpriv_layout_t *layout = state->ns_arch->prpriv;
	Word		nsets;

	indent_enter(state, title, &layout->pr_nsets);

	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_NSETS), pr_nsets);
	PRINT_HEX(MSG_ORIG(MSG_CNOTE_T_PR_SETSIZE), pr_setsize);
	PRINT_HEX(MSG_ORIG(MSG_CNOTE_T_PR_INFOSIZE), pr_infosize);

	if (data_present(state, &layout->pr_nsets)) {
		nsets = extract_as_word(state, &layout->pr_nsets);
		print_array(state, &layout->pr_sets, SL_FMT_NUM_ZHEX, nsets,
		    0, MSG_ORIG(MSG_CNOTE_T_PR_SETS));
	}

	indent_exit(state);
}

static void
dump_prfdinfo(note_state_t *state, const char *title)
{
	const sl_prfdinfo_layout_t *layout = state->ns_arch->prfdinfo;
	char buf[1024];
	uint32_t fileflags, mode;

	indent_enter(state, title, &layout->pr_fd);

	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_FD), pr_fd);
	mode = extract_as_word(state, &layout->pr_mode);

	print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_MODE),
	    conv_cnote_filemode(mode, 0, buf, sizeof (buf)));

	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_UID), pr_uid,
	    MSG_ORIG(MSG_CNOTE_T_PR_GID), pr_gid);

	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_MAJOR), pr_major,
	    MSG_ORIG(MSG_CNOTE_T_PR_MINOR), pr_minor);
	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_RMAJOR), pr_rmajor,
	    MSG_ORIG(MSG_CNOTE_T_PR_RMINOR), pr_rminor);

	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_INO), pr_ino);

	PRINT_DEC_2UP(MSG_ORIG(MSG_CNOTE_T_PR_SIZE), pr_size,
	    MSG_ORIG(MSG_CNOTE_T_PR_OFFSET), pr_offset);

	fileflags = extract_as_word(state, &layout->pr_fileflags);

	print_str(state, MSG_ORIG(MSG_CNOTE_T_PR_FILEFLAGS),
	    conv_cnote_fileflags(fileflags, 0, buf, sizeof (buf)));

	PRINT_DEC(MSG_ORIG(MSG_CNOTE_T_PR_FDFLAGS), pr_fdflags);

	PRINT_STRBUF(MSG_ORIG(MSG_CNOTE_T_PR_PATH), pr_path);

	indent_exit(state);
}

/*
 * Output information from priv_impl_info_t structure.
 */
static void
dump_priv_impl_info(note_state_t *state, const char *title)
{
	const sl_priv_impl_info_layout_t *layout;

	layout = state->ns_arch->priv_impl_info;
	indent_enter(state, title, &layout->priv_headersize);

	PRINT_HEX_2UP(MSG_ORIG(MSG_CNOTE_T_PRIV_HEADERSIZE), priv_headersize,
	    MSG_ORIG(MSG_CNOTE_T_PRIV_FLAGS), priv_flags);

	print_num_2up(state, MSG_ORIG(MSG_CNOTE_T_PRIV_NSETS),
	    &layout->priv_nsets, SL_FMT_NUM_DEC,
	    MSG_ORIG(MSG_CNOTE_T_PRIV_SETSIZE), &layout->priv_setsize,
	    SL_FMT_NUM_HEX);
	print_num_2up(state, MSG_ORIG(MSG_CNOTE_T_PRIV_MAX), &layout->priv_max,
	    SL_FMT_NUM_DEC, MSG_ORIG(MSG_CNOTE_T_PRIV_INFOSIZE),
	    &layout->priv_infosize, SL_FMT_NUM_HEX);
	PRINT_HEX(MSG_ORIG(MSG_CNOTE_T_PRIV_GLOBALINFOSIZE),
	    priv_globalinfosize);

	indent_exit(state);
}


/*
 * Dump information from an asrset_t array. This data
 * structure is specific to sparcv9, and does not appear
 * on any other platform.
 *
 * asrset_t is a simple array, defined in <sys/regset.h> as
 *	typedef	int64_t	asrset_t[16];	 %asr16 - > %asr31
 *
 * As such, we do not make use of the struct_layout facilities
 * for this routine.
 */
static void
dump_asrset(note_state_t *state, const char *title)
{
	static const sl_field_t ftemplate = { 0, sizeof (int64_t), 16, 0 };
	sl_field_t	fdesc1, fdesc2;
	sl_fmtbuf_t	buf1, buf2;
	char		index1[MAXNDXSIZE * 2], index2[MAXNDXSIZE * 2];
	Word		w, nelts;

	fdesc1 = fdesc2 =  ftemplate;

	/* We expect 16 values, but will print whatever is actually there */
	nelts = state->ns_len / ftemplate.slf_eltlen;
	if (nelts == 0)
		return;

	indent_enter(state, title, &fdesc1);

	for (w = 0; w < nelts; ) {
		(void) snprintf(index1, sizeof (index1),
		    MSG_ORIG(MSG_FMT_ASRINDEX), w + 16);

		if (w == (nelts - 1)) {
			/* One last register is left */
			dbg_print(0, MSG_ORIG(MSG_CNOTE_FMT_LINE),
			    INDENT, state->ns_vcol - state->ns_indent, index1,
			    fmt_num(state, &fdesc1, SL_FMT_NUM_ZHEX, buf1));
			fdesc1.slf_offset += fdesc1.slf_eltlen;
			w++;
			continue;
		}

		/* There are at least 2 more registers left. Show 2 up */
		(void) snprintf(index2, sizeof (index2),
		    MSG_ORIG(MSG_FMT_ASRINDEX), w + 17);

		fdesc2.slf_offset = fdesc1.slf_offset + fdesc1.slf_eltlen;
		dbg_print(0, MSG_ORIG(MSG_CNOTE_FMT_LINE_2UP), INDENT,
		    state->ns_vcol - state->ns_indent, index1,
		    state->ns_t2col - state->ns_vcol,
		    fmt_num(state, &fdesc1, SL_FMT_NUM_ZHEX, buf1),
		    state->ns_v2col - state->ns_t2col, index2,
		    fmt_num(state, &fdesc2, SL_FMT_NUM_ZHEX, buf2));
		fdesc1.slf_offset += 2 * fdesc1.slf_eltlen;
		w += 2;
	}

	indent_exit(state);
}

corenote_ret_t
corenote(Half mach, int do_swap, Word type,
    const char *desc, Word descsz)
{
	note_state_t		state;

	/*
	 * Get the per-architecture layout definition
	 */
	state.ns_mach = mach;
	state.ns_arch = sl_mach(state.ns_mach);
	if (sl_mach(state.ns_mach) == NULL)
		return (CORENOTE_R_BADARCH);

	state.ns_swap = do_swap;
	state.ns_indent = 4;
	state.ns_t2col = state.ns_v2col = 0;
	state.ns_data = desc;
	state.ns_len = descsz;

	switch (type) {
	case NT_PRSTATUS:		/* prstatus_t <sys/old_procfs.h> */
		state.ns_vcol = 26;
		state.ns_t2col = 46;
		state.ns_v2col = 60;
		dump_prstatus(&state, MSG_ORIG(MSG_CNOTE_DESC_PRSTATUS_T));
		return (CORENOTE_R_OK);

	case NT_PRFPREG:		/* prfpregset_t	<sys/procfs_isa.h> */
		return (CORENOTE_R_OK_DUMP);

	case NT_PRPSINFO:		/* prpsinfo_t	<sys/old_procfs.h> */
		state.ns_vcol = 20;
		state.ns_t2col = 41;
		state.ns_v2col = 54;
		dump_prpsinfo(&state, MSG_ORIG(MSG_CNOTE_DESC_PRPSINFO_T));
		return (CORENOTE_R_OK);

	case NT_PRXREG:			/* prxregset_t <sys/procfs_isa.h> */
		return (CORENOTE_R_OK_DUMP);

	case NT_PLATFORM:		/* string from sysinfo(SI_PLATFORM) */
		dbg_print(0, MSG_ORIG(MSG_NOTE_DESC));
		dbg_print(0, MSG_ORIG(MSG_FMT_INDENT), safe_str(desc, descsz));
		return (CORENOTE_R_OK);

	case NT_AUXV:			/* auxv_t array	<sys/auxv.h> */
		state.ns_vcol = 18;
		dump_auxv(&state, MSG_ORIG(MSG_CNOTE_DESC_AUXV_T));
		return (CORENOTE_R_OK);

	case NT_GWINDOWS:		/* gwindows_t SPARC only */
		return (CORENOTE_R_OK_DUMP);

	case NT_ASRS:			/* asrset_t <sys/regset> sparcv9 only */
		state.ns_vcol = 18;
		state.ns_t2col = 38;
		state.ns_v2col = 46;
		dump_asrset(&state, MSG_ORIG(MSG_CNOTE_DESC_ASRSET_T));
		return (CORENOTE_R_OK);

	case NT_LDT:			/* ssd array <sys/sysi86.h> IA32 only */
		return (CORENOTE_R_OK_DUMP);

	case NT_PSTATUS:		/* pstatus_t <sys/procfs.h> */
		state.ns_vcol = 22;
		state.ns_t2col = 42;
		state.ns_v2col = 54;
		dump_pstatus(&state, MSG_ORIG(MSG_CNOTE_DESC_PSTATUS_T));
		return (CORENOTE_R_OK);

	case NT_PSINFO:			/* psinfo_t <sys/procfs.h> */
		state.ns_vcol = 25;
		state.ns_t2col = 45;
		state.ns_v2col = 58;
		dump_psinfo(&state, MSG_ORIG(MSG_CNOTE_DESC_PSINFO_T));
		return (CORENOTE_R_OK);

	case NT_PRCRED:			/* prcred_t <sys/procfs.h> */
		state.ns_vcol = 20;
		state.ns_t2col = 34;
		state.ns_v2col = 44;
		dump_prcred(&state, MSG_ORIG(MSG_CNOTE_DESC_PRCRED_T));
		return (CORENOTE_R_OK);

	case NT_UTSNAME:		/* struct utsname <sys/utsname.h> */
		state.ns_vcol = 18;
		dump_utsname(&state, MSG_ORIG(MSG_CNOTE_DESC_STRUCT_UTSNAME));
		return (CORENOTE_R_OK);

	case NT_LWPSTATUS:		/* lwpstatus_t <sys/procfs.h> */
		state.ns_vcol = 24;
		state.ns_t2col = 44;
		state.ns_v2col = 54;
		dump_lwpstatus(&state, MSG_ORIG(MSG_CNOTE_DESC_LWPSTATUS_T));
		return (CORENOTE_R_OK);

	case NT_LWPSINFO:		/* lwpsinfo_t <sys/procfs.h> */
		state.ns_vcol = 22;
		state.ns_t2col = 42;
		state.ns_v2col = 54;
		dump_lwpsinfo(&state, MSG_ORIG(MSG_CNOTE_DESC_LWPSINFO_T));
		return (CORENOTE_R_OK);

	case NT_PRPRIV:			/* prpriv_t <sys/procfs.h> */
		state.ns_vcol = 21;
		state.ns_t2col = 34;
		state.ns_v2col = 38;
		dump_prpriv(&state, MSG_ORIG(MSG_CNOTE_DESC_PRPRIV_T));
		return (CORENOTE_R_OK);

	case NT_PRPRIVINFO:		/* priv_impl_info_t <sys/priv.h> */
		state.ns_vcol = 29;
		state.ns_t2col = 41;
		state.ns_v2col = 56;
		dump_priv_impl_info(&state,
		    MSG_ORIG(MSG_CNOTE_DESC_PRIV_IMPL_INFO_T));
		return (CORENOTE_R_OK);

	case NT_CONTENT:		/* core_content_t <sys/corectl.h> */
		if (sizeof (core_content_t) > descsz)
			return (CORENOTE_R_BADDATA);
		{
			static sl_field_t fdesc = { 0, 8, 0, 0 };
			Conv_cnote_cc_content_buf_t conv_buf;
			core_content_t content;

			state.ns_vcol = 8;
			indent_enter(&state,
			    MSG_ORIG(MSG_CNOTE_DESC_CORE_CONTENT_T),
			    &fdesc);
			content = extract_as_lword(&state, &fdesc);
			print_str(&state, MSG_ORIG(MSG_STR_EMPTY),
			    conv_cnote_cc_content(content, 0, &conv_buf));
			indent_exit(&state);
		}
		return (CORENOTE_R_OK);

	case NT_ZONENAME:		/* string from getzonenamebyid(3C) */
		dbg_print(0, MSG_ORIG(MSG_NOTE_DESC));
		dbg_print(0, MSG_ORIG(MSG_FMT_INDENT), safe_str(desc, descsz));
		return (CORENOTE_R_OK);


	case NT_FDINFO:
		state.ns_vcol = 22;
		state.ns_t2col = 41;
		state.ns_v2col = 54;
		dump_prfdinfo(&state, MSG_ORIG(MSG_CNOTE_DESC_PRFDINFO_T));
		return (CORENOTE_R_OK);

	case NT_SPYMASTER:
		state.ns_vcol = 25;
		state.ns_t2col = 45;
		state.ns_v2col = 58;
		dump_psinfo(&state, MSG_ORIG(MSG_CNOTE_DESC_PSINFO_T));
		return (CORENOTE_R_OK);

	case NT_SECFLAGS:
		state.ns_vcol = 23;
		state.ns_t2col = 41;
		state.ns_v2col = 54;
		dump_secflags(&state, MSG_ORIG(MSG_CNOTE_DESC_PRSECFLAGS_T));
		return (CORENOTE_R_OK);
	}

	return (CORENOTE_R_BADTYPE);
}
