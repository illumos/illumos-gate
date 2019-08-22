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
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Map file parsing, Version 2 syntax (solaris).
 */
#include	<stdio.h>
#include	<unistd.h>
#include	<ctype.h>
#include	<sys/elf_amd64.h>   /* SHF_AMD64_LARGE */
#include	<elfcap.h>
#include	"msg.h"
#include	"_libld.h"
#include	"_map.h"

/*
 * Use a case insensitive string match when looking up capability mask
 * values by name, and omit the AV_ prefix.
 */
#define	ELFCAP_STYLE ELFCAP_STYLE_LC | ELFCAP_STYLE_F_ICMP

/*
 * Signature for functions used to parse top level mapfile directives
 */
typedef Token (*dir_func_t)(Mapfile *mf);

/*
 * Signature for functions used to parse attribute level assignments
 *	mf - Mapfile descriptor
 *	eq_tok - One of the equal tokens (TK_EQUAL, TK_PLUSEQ, TK_MINUSEQ)
 *		or TK_ERROR. See the comment for attr_fmt_t below.
 *	uvalue - An arbitrary pointer "user value" passed by the
 *		caller to parse_attributes() for use by the function.
 */
typedef Token (* attr_func_t)(Mapfile *mf, Token eq_tok, void *uvalue);

/*
 * Signature for gettoken_str() err_func argument. This is a function
 * called to issue an appropriate error message.
 *
 * The gts prefix stands for "Get Token Str"
 */
typedef void (* gts_efunc_t)(Mapfile *mf, Token tok, ld_map_tkval_t *tkv);

/*
 * The attr_fmt_t tells parse_attributes how far to go in parsing
 * an attribute before it calls the at_func function to take over:
 *
 *	ATTR_FMT_NAME - Parse the name, and immediately call the function.
 *		This is useful in cases where there is more than
 *		one possible syntax for a given attribute. The value of
 *		eq_tok passed to the at_func function will be TK_ERROR,
 *		reflecting the fact that it has no meaning in this context.
 *
 *	ATTR_FMT_EQ - Parse the name, and the following '=', and then call
 *		the function. The value passed to the at_func function for
 *		eq_tok will be TK_EQUAL.
 *
 *	ATTR_FMT_EQ_PEQ - Parse the name, and a following equal token which
 *		can be '=' or '+=', and then call the function. The value
 *		passed to the at_func function for eq_tok will be one of
 *		TK_EQUAL, or TK_PLUSEQ.
 *
 *	ATTR_FMT_EQ_ALL - Parse the name, and a following equal token which
 *		can be any of the three forms (=, +=, -=), and then call
 *		the function. The value passed to the at_func function for
 *		eq_tok will be one of TK_EQUAL, TK_PLUSEQ, or TK_MINUSEQ.
 */
typedef enum {
	ATTR_FMT_NAME,
	ATTR_FMT_EQ,
	ATTR_FMT_EQ_PEQ,
	ATTR_FMT_EQ_ALL,
} attr_fmt_t;

/*
 * Type used to describe a set of valid attributes to parse_attributes():
 *	at_name - Name of attribute
 *	at_func - Function to call when attribute is recognized,
 *	at_all_eq - True if attribute allows the '+=' and '-=' forms of
 *		assignment token, and False to only allow '='.
 *
 * The array of these structs passed to parse_attributes() must be
 * NULL terminated (the at_name field must be set to NULL).
 */
typedef struct {
	const char	*at_name;	/* Name of attribute */
	attr_func_t	at_func;	/* Function to call */
	attr_fmt_t	at_fmt;		/* How much to parse before calling */
					/*	at_func */
} attr_t;

/*
 * Mapfile version and symbol state are separate but related concepts
 * that are best represented using two different types. However, our
 * style of passing a single uvalue via parse_attributes() makes it
 * convenient to be able to reference them from a single address.
 */
typedef struct {
	ld_map_ver_t	ss_mv;
	ld_map_sym_t	ss_ms;
} symbol_state_t;

/*
 * Process an expected equal operator. Deals with the fact that we
 * have three variants.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	eq_type - Types of equal operators accepted. One of ATTR_FMT_EQ,
 *		ATTR_FMT_EQ_PEQ, or ATTR_FMT_EQ_ALL.
 *	lhs - Name that appears on the left hand side of the expected
 *		equal operator.
 *
 * exit:
 *	Returns one of TK_EQUAL, TK_PLUSEQ, TK_MINUSEQ, or TK_ERROR.
 */
static Token
gettoken_eq(Mapfile *mf, attr_fmt_t eq_type, const char *lhs)
{
	Token		tok;
	ld_map_tkval_t	tkv;
	const char	*err;
	Conv_inv_buf_t	inv_buf;

	switch (tok = ld_map_gettoken(mf, 0, &tkv)) {
	case TK_ERROR:
	case TK_EQUAL:
		return (tok);

	case TK_PLUSEQ:
		switch (eq_type) {
		case ATTR_FMT_EQ_PEQ:
		case ATTR_FMT_EQ_ALL:
			return (tok);
		}
		break;

	case TK_MINUSEQ:
		if (eq_type == ATTR_FMT_EQ_ALL)
			return (tok);
		break;
	}

	switch (eq_type) {
	case ATTR_FMT_EQ:
		err = MSG_INTL(MSG_MAP_EXP_EQ);
		break;
	case ATTR_FMT_EQ_PEQ:
		err = MSG_INTL(MSG_MAP_EXP_EQ_PEQ);
		break;
	case ATTR_FMT_EQ_ALL:
		err = MSG_INTL(MSG_MAP_EXP_EQ_ALL);
		break;
	default:
		/*NOTREACHED*/
		assert(0);
	}
	mf_fatal(mf, err, lhs, ld_map_tokenstr(tok, &tkv, &inv_buf));
	return (TK_ERROR);
}

/*
 * Apply one of the three equal tokens to a bitmask value
 *
 * entry:
 *	dst - Address of bitmask variable to alter
 *	eq_tok - One of TK_EQUAL, TK_PLUSEQ, TK_MINUSEQ, representing
 *		the operation to carry out.
 *	value - Value for right hand side
 *
 * exit:
 *	The operation has been carried out:
 *
 *	TK_EQUAL - *dst is set to value
 *	TK_PLUSEQ - Bits in value have been set in *dst
 *	TK_MINUSEQ - Bits in value have been removed from *dst
 */
static void
setflags_eq(Word *dst, Token eq_tok, Word value)
{
	switch (eq_tok) {
	case TK_EQUAL:
		*dst = value;
		break;
	case TK_PLUSEQ:
		*dst |= value;
		break;
	case TK_MINUSEQ:
		*dst &= ~value;
		break;
	default:
		/*NOTREACHED*/
		assert(0);
	}
}

/*
 * Apply one of the three equal tokens to a capabilities Capmask.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	capmask - Address of Capmask variable to alter
 *	eq_tok - One of TK_EQUAL, TK_PLUSEQ, TK_MINUSEQ, representing
 *		the operation to carry out.
 *	type - Capability type (CA_SUNW_*)
 *	value - Value for right hand side
 *	title - True if a title is needed, False otherwise.
 *
 * exit:
 *	On success, returns TRUE (1), otherwise FALSE (0)
 */
static Boolean
set_capmask(Mapfile *mf, Capmask *capmask, Token eq_tok,
    Word type, elfcap_mask_t value, Boolean title)
{
	if (title)
		DBG_CALL(Dbg_cap_mapfile_title(mf->mf_ofl->ofl_lml,
		    mf->mf_lineno));
	DBG_CALL(Dbg_cap_val_entry(mf->mf_ofl->ofl_lml, DBG_STATE_CURRENT,
	    type, capmask->cm_val, ld_targ.t_m.m_mach));

	switch (eq_tok) {
	case TK_EQUAL:
		capmask->cm_val = value;
		capmask->cm_exc = 0;
		ld_map_cap_set_ovflag(mf, type);
		DBG_CALL(Dbg_cap_val_entry(mf->mf_ofl->ofl_lml,
		    DBG_STATE_RESET, type, capmask->cm_val,
		    ld_targ.t_m.m_mach));
		break;
	case TK_PLUSEQ:
		DBG_CALL(Dbg_cap_val_entry(mf->mf_ofl->ofl_lml,
		    DBG_STATE_ADD, type, value, ld_targ.t_m.m_mach));
		capmask->cm_val |= value;
		capmask->cm_exc &= ~value;
		break;
	case TK_MINUSEQ:
		DBG_CALL(Dbg_cap_val_entry(mf->mf_ofl->ofl_lml,
		    DBG_STATE_EXCLUDE, type, value, ld_targ.t_m.m_mach));
		capmask->cm_val &= ~value;
		capmask->cm_exc |= value;
		break;
	default:
		/*NOTREACHED*/
		assert(0);
	}

	/* Sanity check the resulting bits */
	if (!ld_map_cap_sanitize(mf, type, capmask))
		return (FALSE);

	/* Report the final configuration */
	DBG_CALL(Dbg_cap_val_entry(mf->mf_ofl->ofl_lml,
	    DBG_STATE_RESOLVED, type, capmask->cm_val, ld_targ.t_m.m_mach));

	return (TRUE);
}

/*
 * Apply one of the three equal tokens to a capabilities Caplist.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	caplist - Address of Caplist variable to alter
 *	eq_tok - One of TK_EQUAL, TK_PLUSEQ, TK_MINUSEQ, representing
 *		the operation to carry out.
 *	type - Capability type (CA_SUNW_*)
 *	str - String for right hand side
 *	title - True if a title is needed, False otherwise.
 *
 * exit:
 *	On success, returns TRUE (1), otherwise FALSE (0)
 */
static Boolean
set_capstr(Mapfile *mf, Caplist *caplist, Token eq_tok,
    Word type, APlist *strs)
{
	Capstr		*capstr;
	Aliste		idx1;
	char		*str;

	DBG_CALL(Dbg_cap_mapfile_title(mf->mf_ofl->ofl_lml, mf->mf_lineno));

	if ((caplist->cl_val == NULL) || (alist_nitems(caplist->cl_val) == 0)) {
		DBG_CALL(Dbg_cap_ptr_entry(mf->mf_ofl->ofl_lml,
		    DBG_STATE_CURRENT, type, NULL));
	} else {
		for (ALIST_TRAVERSE(caplist->cl_val, idx1, capstr)) {
			DBG_CALL(Dbg_cap_ptr_entry(mf->mf_ofl->ofl_lml,
			    DBG_STATE_CURRENT, type, capstr->cs_str));
		}
	}

	switch (eq_tok) {
	case TK_EQUAL:
		if (caplist->cl_val) {
			(void) free(caplist->cl_val);
			caplist->cl_val = NULL;
		}
		if (caplist->cl_exc) {
			(void) free(caplist->cl_exc);
			caplist->cl_exc = NULL;
		}
		if (strs) {
			for (APLIST_TRAVERSE(strs, idx1, str)) {
				if ((capstr = alist_append(&caplist->cl_val,
				    NULL, sizeof (Capstr),
				    AL_CNT_CAP_NAMES)) == NULL)
					return (FALSE);
				capstr->cs_str = str;
				DBG_CALL(Dbg_cap_ptr_entry(mf->mf_ofl->ofl_lml,
				    DBG_STATE_RESET, type, capstr->cs_str));
			}
		} else {
			DBG_CALL(Dbg_cap_ptr_entry(mf->mf_ofl->ofl_lml,
			    DBG_STATE_RESET, type, NULL));
		}
		ld_map_cap_set_ovflag(mf, type);
		break;
	case TK_PLUSEQ:
		for (APLIST_TRAVERSE(strs, idx1, str)) {
			Aliste		idx2;
			const char	*ostr;
			int		found = 0;

			/*
			 * Add this name to the list of names, provided the
			 * name doesn't already exist.
			 */
			for (ALIST_TRAVERSE(caplist->cl_val, idx2, capstr)) {
				if (strcmp(str, capstr->cs_str) == 0) {
					found++;
					break;
				}
			}
			if ((found == 0) && ((capstr =
			    (Capstr *)alist_append(&caplist->cl_val, NULL,
			    sizeof (Capstr), AL_CNT_CAP_NAMES)) == NULL))
				return (FALSE);
			capstr->cs_str = str;

			/*
			 * Remove this name from the list of excluded names,
			 * provided the name already exists.
			 */
			for (APLIST_TRAVERSE(caplist->cl_exc, idx2, ostr)) {
				if (strcmp(str, ostr) == 0) {
					aplist_delete(caplist->cl_exc, &idx2);
					break;
				}
			}
			DBG_CALL(Dbg_cap_ptr_entry(mf->mf_ofl->ofl_lml,
			    DBG_STATE_ADD, type, str));
		}
		break;
	case TK_MINUSEQ:
		for (APLIST_TRAVERSE(strs, idx1, str)) {
			Aliste		idx2;
			const char	*ostr;
			int		found = 0;

			/*
			 * Delete this name from the list of names, provided
			 * the name already exists.
			 */
			for (ALIST_TRAVERSE(caplist->cl_val, idx2, capstr)) {
				if (strcmp(str, capstr->cs_str) == 0) {
					alist_delete(caplist->cl_val, &idx2);
					break;
				}
			}

			/*
			 * Add this name to the list of excluded names,
			 * provided the name already exists.
			 */
			for (APLIST_TRAVERSE(caplist->cl_exc, idx2, ostr)) {
				if (strcmp(str, ostr) == 0) {
					found++;
					break;
				}
			}
			if ((found == 0) && (aplist_append(&caplist->cl_exc,
			    str, AL_CNT_CAP_NAMES) == NULL))
				return (FALSE);

			DBG_CALL(Dbg_cap_ptr_entry(mf->mf_ofl->ofl_lml,
			    DBG_STATE_EXCLUDE, type, str));
		}
		break;
	default:
		/*NOTREACHED*/
		assert(0);
	}

	/* Report the final configuration */
	if ((caplist->cl_val == NULL) || (alist_nitems(caplist->cl_val) == 0)) {
		DBG_CALL(Dbg_cap_ptr_entry(mf->mf_ofl->ofl_lml,
		    DBG_STATE_RESOLVED, type, NULL));
	} else {
		for (ALIST_TRAVERSE(caplist->cl_val, idx1, capstr)) {
			DBG_CALL(Dbg_cap_ptr_entry(mf->mf_ofl->ofl_lml,
			    DBG_STATE_RESOLVED, type, capstr->cs_str));
		}
	}

	return (TRUE);
}

/*
 * Process the next token, which is expected to start an optional
 * nesting of attributes (';' or '{').
 *
 * entry:
 *	mf - Mapfile descriptor
 *	lhs - Name of the directive or attribute being processed.
 *
 * exit:
 *	Returns TK_SEMICOLON or TK_LEFTBKT for success, and TK_ERROR otherwise.
 */
static Token
gettoken_optattr(Mapfile *mf, const char *lhs)
{
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;

	switch (tok = ld_map_gettoken(mf, 0, &tkv)) {
	case TK_ERROR:
	case TK_SEMICOLON:
	case TK_LEFTBKT:
		return (tok);
	}

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SEMLBKT), lhs,
	    ld_map_tokenstr(tok, &tkv, &inv_buf));
	return (TK_ERROR);
}

/*
 * Process the next token, which is expected to be a line terminator
 * (';' or '}').
 *
 * entry:
 *	mf - Mapfile descriptor
 *	lhs - Name of the directive or attribute being processed.
 *
 * exit:
 *	Returns TK_SEMICOLON or TK_RIGHTBKT for success, and TK_ERROR otherwise.
 */
static Token
gettoken_term(Mapfile *mf, const char *lhs)
{
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;

	switch (tok = ld_map_gettoken(mf, 0, &tkv)) {
	case TK_ERROR:
	case TK_SEMICOLON:
	case TK_RIGHTBKT:
		return (tok);
	}

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SEMRBKT), lhs,
	    ld_map_tokenstr(tok, &tkv, &inv_buf));
	return (TK_ERROR);
}

/*
 * Process the next token, which is expected to be a semicolon.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	lhs - Name of the directive or attribute being processed.
 *
 * exit:
 *	Returns TK_SEMICOLON for success, and TK_ERROR otherwise.
 */
static Token
gettoken_semicolon(Mapfile *mf, const char *lhs)
{
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;

	switch (tok = ld_map_gettoken(mf, 0, &tkv)) {
	case TK_ERROR:
	case TK_SEMICOLON:
		return (tok);
	}

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SEM), lhs,
	    ld_map_tokenstr(tok, &tkv, &inv_buf));
	return (TK_ERROR);
}

/*
 * Process the next token, which is expected to be a '{'
 *
 * entry:
 *	mf - Mapfile descriptor
 *	lhs - Name of the item directly to the left of the expected left
 *		bracket.
 *
 * exit:
 *	Returns TK_LEFTBKT for success, and TK_ERROR otherwise.
 */
static Token
gettoken_leftbkt(Mapfile *mf, const char *lhs)
{
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;

	switch (tok = ld_map_gettoken(mf, 0, &tkv)) {
	case TK_ERROR:
	case TK_LEFTBKT:
		return (tok);
	}

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_LBKT), lhs,
	    ld_map_tokenstr(tok, &tkv, &inv_buf));
	return (TK_ERROR);
}

/*
 * Process the next token, which is expected to be an integer
 *
 * entry:
 *	mf - Mapfile descriptor
 *	lhs - Name of the directive or attribute being processed.
 *	tkv - Address of token value struct to be filled in
 *
 * exit:
 *	Updates *tkv and returns TK_INT for success, TK_ERROR otherwise.
 */
static Token
gettoken_int(Mapfile *mf, const char *lhs, ld_map_tkval_t *tkv)
{
	Token		tok;
	Conv_inv_buf_t	inv_buf;

	switch (tok = ld_map_gettoken(mf, 0, tkv)) {
	case TK_ERROR:
	case TK_INT:
		return (tok);
	}

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_INT), lhs,
	    ld_map_tokenstr(tok, tkv, &inv_buf));
	return (TK_ERROR);
}

/*
 * Process the next token, which is expected to be a string
 *
 * entry:
 *	mf - Mapfile descriptor
 *	lhs - Name of the directive or attribute being processed.
 *	tkv - Address of token value struct to be filled in
 *	err_func - Function to call if an error occurs
 *
 * exit:
 *	Updates *tkv and returns TK_STRING for success. Calls the
 *	supplied err_func function and returns TK_ERROR otherwise.
 */
static Token
gettoken_str(Mapfile *mf, int flags, ld_map_tkval_t *tkv, gts_efunc_t efunc)
{
	Token		tok;

	switch (tok = ld_map_gettoken(mf, flags, tkv)) {
	case TK_ERROR:
	case TK_STRING:
		return (tok);
	}

	/* User supplied function reports the error */
	(* efunc)(mf, tok, tkv);

	return (TK_ERROR);
}

/*
 * Given a construct of the following common form:
 *
 *	item_name {
 *		attribute = ...;
 *		...
 *	}
 *
 * where the caller has detected the item_name and opening bracket,
 * parse the construct and call the attribute functions for each
 * attribute detected, stopping when the closing '}' is seen.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	item_name - Already detected name of item for which attributes
 *		are being parsed.
 *	attr_list - NULL terminated array of attr_t structures describing the
 *		valid attributes for the item.
 *	expect_str - Comma separated string listing the names of expected
 *		attributes.
 *	uvalue - User value, passed to the attribute functions without
 *		examination by parse_attributes(), usable for maintaining
 *		shared state between the caller and the functions.
 *
 * exit:
 *	parse_attributes() reads the attribute name and equality token,
 *	and then calls the attribute function given by the attr_list array
 *	to handle everything up to and including the terminating ';'.
 *	This continues until the closing '}' is seen.
 *
 *	If everything is successful, TK_RIGHTBKT is returned. Otherwise,
 *	a suitable error is issued and TK_ERROR is returned.
 */
static Token
parse_attributes(Mapfile *mf, const char *item_name, attr_t *attr_list,
    size_t attr_list_bufsize, void *uvalue)
{
	attr_t		*attr;
	Token		tok, op_tok;
	ld_map_tkval_t	tkv;
	int		done;
	int		attr_cnt = 0;
	Conv_inv_buf_t	inv_buf;

	/* Read attributes until the closing '}' is seen */
	for (done = 0; done == 0; ) {
		switch (tok = ld_map_gettoken(mf, TK_F_KEYWORD, &tkv)) {
		case TK_ERROR:
			return (TK_ERROR);

		case TK_STRING:
			attr = ld_map_kwfind(tkv.tkv_str, attr_list,
			    SGSOFFSETOF(attr_t, at_name), sizeof (attr[0]));
			if (attr == NULL)
				goto bad_attr;

			/*
			 * Depending on the value of at_fmt, there are
			 * fout different actions to take:
			 *	ATTR_FMT_NAME - Call at_func function
			 *	ATTR_FMT_EQ - Read and verify a TK_EQUAL
			 *	ATTR_FMT_EQ_PEQ - Read and verify a TK_EQUAL
			 *		or TK_PLUSEQ.
			 *	ATTR_FMT_EQ_ALL - Read/Verify one of the
			 *		three possible equal tokens
			 *		(TK_EQUAL, TK_PLUSEQ, TK_MINUSEQ).
			 */
			if (attr->at_fmt == ATTR_FMT_NAME) {
				/* Arbitrary value to pass to at_func */
				op_tok = TK_ERROR;
			} else {
				/* Read/Verify appropriate equal operator */
				op_tok = gettoken_eq(mf, attr->at_fmt,
				    attr->at_name);
				if (op_tok == TK_ERROR)
					return (TK_ERROR);
			}

			/* Call the associated function */
			switch (tok = attr->at_func(mf, op_tok, uvalue)) {
			default:
				return (TK_ERROR);
			case TK_SEMICOLON:
				break;
			case TK_RIGHTBKT:
				done = 1;
				break;
			}
			attr_cnt++;
			break;

		case TK_RIGHTBKT:
			done = 1;
			break;

		case TK_SEMICOLON:
			break;		/* Ignore empty statement */

		default:
		bad_attr:
			{
				char buf[VLA_SIZE(attr_list_bufsize)];

				mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_ATTR),
				    ld_map_kwnames(attr_list,
				    SGSOFFSETOF(attr_t, at_name),
				    sizeof (attr[0]), buf, attr_list_bufsize),
				    ld_map_tokenstr(tok, &tkv, &inv_buf));
			}
			return (TK_ERROR);
		}
	}

	/* Make sure there was at least one attribute between the {} brackets */
	if (attr_cnt == 0) {
		mf_fatal(mf, MSG_INTL(MSG_MAP_NOATTR), item_name);
		return (TK_ERROR);
	}

	return (tok);
}

/*
 * Read whitespace delimited segment flags from the input and convert into
 * bitmask of PF_ values they represent. Flags are terminated by a semicolon
 * or right bracket.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	flags - Address of variable to be set to resulting flags value
 *
 * exit:
 *	Returns the terminator token (TK_SEMICOLON or TK_LEFTBKT) on success,
 *	and TK_ERROR otherwise.
 */
static Token
parse_segment_flags(Mapfile *mf, Xword *flags)
{
	/*
	 * Map flag names to their values. Since DATA and STACK have
	 * platform dependent values, we have to determine them at runtime.
	 * We indicate this by setting the top bit.
	 */
#define	PF_DATA		0x80000000
#define	PF_STACK	0x80000001
	typedef struct {
		const char	*name;
		Word		value;
	} segflag_t;
	static segflag_t flag_list[] = {
		{ MSG_ORIG(MSG_MAPKW_DATA),	PF_DATA },
		{ MSG_ORIG(MSG_MAPKW_EXECUTE),	PF_X },
		{ MSG_ORIG(MSG_MAPKW_READ),	PF_R },
		{ MSG_ORIG(MSG_MAPKW_STACK),	PF_STACK },
		{ MSG_ORIG(MSG_MAPKW_WRITE),	PF_W },

		/* List must be null terminated */
		{ 0 },
	};

	/*
	 * Size of buffer needed to format the names in flag_list[]. Must
	 * be kept in sync with flag_list.
	 */
	static size_t	flag_list_bufsize =
	    KW_NAME_SIZE(MSG_MAPKW_DATA) +
	    KW_NAME_SIZE(MSG_MAPKW_EXECUTE) +
	    KW_NAME_SIZE(MSG_MAPKW_READ) +
	    KW_NAME_SIZE(MSG_MAPKW_STACK) +
	    KW_NAME_SIZE(MSG_MAPKW_WRITE);

	Token		tok;
	ld_map_tkval_t	tkv;
	segflag_t	*flag;
	size_t		cnt = 0;
	int		done;
	Conv_inv_buf_t	inv_buf;

	*flags = 0;

	/* Read attributes until the ';' terminator is seen */
	for (done = 0; done == 0; ) {
		switch (tok = ld_map_gettoken(mf, TK_F_KEYWORD, &tkv)) {
		case TK_ERROR:
			return (TK_ERROR);

		case TK_STRING:
			flag = ld_map_kwfind(tkv.tkv_str, flag_list,
			    SGSOFFSETOF(segflag_t, name),
			    sizeof (flag_list[0]));
			if (flag == NULL)
				goto bad_flag;
			switch (flag->value) {
			case PF_DATA:
				*flags |= ld_targ.t_m.m_dataseg_perm;
				break;
			case PF_STACK:
				*flags |= ld_targ.t_m.m_stack_perm;
				break;
			default:
				*flags |= flag->value;
			}
			cnt++;
			break;

		case TK_INT:
			/*
			 * Accept 0 for notational convenience, but refuse
			 * any other value. Note that we don't actually have
			 * to set the flags to 0 here, because there are
			 * already initialized to that before the main loop.
			 */
			if (tkv.tkv_int.tkvi_value != 0)
				goto bad_flag;
			cnt++;
			break;

		case TK_SEMICOLON:
		case TK_RIGHTBKT:
			done = 1;
			break;

		default:
		bad_flag:
			{
				char buf[VLA_SIZE(flag_list_bufsize)];

				mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SEGFLAG),
				    ld_map_kwnames(flag_list,
				    SGSOFFSETOF(segflag_t, name),
				    sizeof (flag[0]), buf, flag_list_bufsize),
				    ld_map_tokenstr(tok, &tkv, &inv_buf));
			}
			return (TK_ERROR);
		}
	}

	/* Make sure there was at least one flag */
	if (cnt == 0) {
		mf_fatal(mf, MSG_INTL(MSG_MAP_NOVALUES),
		    MSG_ORIG(MSG_MAPKW_FLAGS));
		return (TK_ERROR);
	}

	return (tok);

#undef PF_DATA
#undef PF_STACK
}

/*
 * Parse one of the capabilities attributes that corresponds directly to a
 * capabilities bitmask value (CA_SUNW_HW_x, CA_SUNW_SF_xx).  Values can be
 * integers, or symbolic names that correspond to the capabilities mask
 * in question.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	eq_tok - One of TK_EQUAL, TK_PLUSEQ, TK_MINUSEQ, representing
 *		the operation to carry out.
 *	capmask - Capmask from output descriptor for capability being processed.
 *	type - Capability type (CA_SUNW_*)
 *	elfcap_from_str_func - pointer to elfcap-string-to-value function
 *		for capability being processed.
 *
 * exit:
 *	Returns TK_SEMICOLON or TK_RIGHTBKT for success, and TK_ERROR otherwise.
 */
static Token
parse_cap_mask(Mapfile *mf, Token eq_tok, Capmask *capmask,
    Word type, elfcap_from_str_func_t *elfcap_from_str_func)
{
	int		done;
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;
	elfcap_mask_t	value = 0;
	uint64_t	v;

	for (done = 0; done == 0; ) {
		switch (tok = ld_map_gettoken(mf, TK_F_KEYWORD, &tkv)) {
		case TK_ERROR:
			return (TK_ERROR);

		case TK_STRING:
			if ((v = (* elfcap_from_str_func)(ELFCAP_STYLE,
			    tkv.tkv_str, ld_targ.t_m.m_mach)) != 0) {
				value |= v;
				break;
			}
			goto bad_flag;

		case TK_INT:
			value |= tkv.tkv_int.tkvi_value;
			break;

		case TK_SEMICOLON:
		case TK_RIGHTBKT:
			done = 1;
			break;

		default:
		bad_flag:
			mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_CAPMASK),
			    ld_map_tokenstr(tok, &tkv, &inv_buf));
			return (TK_ERROR);
		}
	}

	if (!set_capmask(mf, capmask, eq_tok, type, value, TRUE))
		return (TK_ERROR);
	return (tok);
}

/*
 * Parse one of the capabilities attributes that manages lists of names
 * (CA_SUNW_PLAT and CA_SUNW_MACH).  Values are symbolic names that correspond
 * to the capabilities mask in question.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	eq_tok - One of TK_EQUAL, TK_PLUSEQ, TK_MINUSEQ, representing
 *		the operation to carry out.
 *	caplist - Caplist from output descriptor for capability being processed.
 *	type - Capability type (CA_SUNW_*)
 *
 * exit:
 *	Returns TK_SEMICOLON or TK_RIGHTBKT for success, and TK_ERROR otherwise.
 */
static Token
parse_cap_list(Mapfile *mf, Token eq_tok, Caplist *caplist,
    Word type)
{
	int		done, found;
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;
	APlist		*strs = NULL;
	Aliste		idx;
	const char	*str;

	for (done = 0, found = 0; done == 0; found = 0) {
		switch (tok = ld_map_gettoken(mf, 0, &tkv)) {
		case TK_ERROR:
			return (TK_ERROR);

		case TK_STRING:
			/*
			 * The name is in tkv.tkv_str.  Save this string for
			 * set_capstr() processing, but remove any duplicates.
			 */
			for (APLIST_TRAVERSE(strs, idx, str)) {
				if (strcmp(str, tkv.tkv_str) == 0) {
					found++;
					break;
				}
			}
			if ((found == 0) && (aplist_append(&strs, tkv.tkv_str,
			    AL_CNT_CAP_NAMES) == NULL))
				return (TK_ERROR);
			break;

		case TK_SEMICOLON:
		case TK_RIGHTBKT:
			done = 1;
			break;

		default:
			mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_CAPNAME),
			    ld_map_tokenstr(tok, &tkv, &inv_buf));
			return (TK_ERROR);
		}
	}

	if (!set_capstr(mf, caplist, eq_tok, type, strs))
		return (TK_ERROR);
	return (tok);
}

/*
 * CAPABILITY [capid] { HW = hwcap_flags...
 * -------------------------^
 */
/* ARGSUSED 2 */
static Token
at_cap_hw(Mapfile *mf, Token eq_tok, void *uvalue)
{
	int		done;
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;
	Word		hw1 = 0, hw2 = 0;
	uint64_t	v;

	for (done = 0; done == 0; ) {
		switch (tok = ld_map_gettoken(mf, TK_F_KEYWORD, &tkv)) {
		case TK_ERROR:
			return (TK_ERROR);

		case TK_STRING:
			if ((v = elfcap_hw1_from_str(ELFCAP_STYLE,
			    tkv.tkv_str, ld_targ.t_m.m_mach)) != 0) {
				hw1 |= v;
				break;
			}
			if ((v = elfcap_hw2_from_str(ELFCAP_STYLE,
			    tkv.tkv_str, ld_targ.t_m.m_mach)) != 0) {
				hw2 |= v;
				break;
			}
			goto bad_flag;

		case TK_SEMICOLON:
		case TK_RIGHTBKT:
			done = 1;
			break;

		default:
		bad_flag:
			mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_CAPHW),
			    ld_map_tokenstr(tok, &tkv, &inv_buf));
			return (TK_ERROR);
		}
	}

	if (!set_capmask(mf, &mf->mf_ofl->ofl_ocapset.oc_hw_1, eq_tok,
	    CA_SUNW_HW_1, hw1, TRUE))
		return (TK_ERROR);
	if (!set_capmask(mf, &mf->mf_ofl->ofl_ocapset.oc_hw_2, eq_tok,
	    CA_SUNW_HW_2, hw2, FALSE))
		return (TK_ERROR);
	return (tok);
}

/*
 * CAPABILITY [capid] { HW_1 = value ;
 * ---------------------------^
 */
/* ARGSUSED 2 */
static Token
at_cap_hw_1(Mapfile *mf, Token eq_tok, void *uvalue)
{
	return (parse_cap_mask(mf, eq_tok, &mf->mf_ofl->ofl_ocapset.oc_hw_1,
	    CA_SUNW_HW_1, elfcap_hw1_from_str));
}

/*
 * CAPABILITY [capid] { HW_2 = value ;
 * ---------------------------^
 */
/* ARGSUSED 2 */
static Token
at_cap_hw_2(Mapfile *mf, Token eq_tok, void *uvalue)
{
	return (parse_cap_mask(mf, eq_tok, &mf->mf_ofl->ofl_ocapset.oc_hw_2,
	    CA_SUNW_HW_2, elfcap_hw2_from_str));
}

/*
 * CAPABILITY [capid] { SF = sfcap_flags...
 * -------------------------^
 */
/* ARGSUSED 2 */
static Token
at_cap_sf(Mapfile *mf, Token eq_tok, void *uvalue)
{
	int		done;
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;
	Word		sf1 = 0;
	uint64_t	v;

	for (done = 0; done == 0; ) {
		switch (tok = ld_map_gettoken(mf, TK_F_KEYWORD, &tkv)) {
		case TK_ERROR:
			return (TK_ERROR);

		case TK_STRING:
			if ((v = elfcap_sf1_from_str(ELFCAP_STYLE,
			    tkv.tkv_str, ld_targ.t_m.m_mach)) != 0) {
				sf1 |= v;
				break;
			}
			goto bad_flag;

		case TK_SEMICOLON:
		case TK_RIGHTBKT:
			done = 1;
			break;

		default:
		bad_flag:
			mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_CAPSF),
			    ld_map_tokenstr(tok, &tkv, &inv_buf));
			return (TK_ERROR);
		}
	}

	if (!set_capmask(mf, &mf->mf_ofl->ofl_ocapset.oc_sf_1, eq_tok,
	    CA_SUNW_SF_1, sf1, TRUE))
		return (TK_ERROR);

	return (tok);
}

/*
 * CAPABILITY [capid] { SF_1 = value ;
 * ---------------------------^
 */
/* ARGSUSED 2 */
static Token
at_cap_sf_1(Mapfile *mf, Token eq_tok, void *uvalue)
{
	return (parse_cap_mask(mf, eq_tok, &mf->mf_ofl->ofl_ocapset.oc_sf_1,
	    CA_SUNW_SF_1, elfcap_sf1_from_str));
}

/*
 * CAPABILITY [capid] { MACHINE = value ;
 * ------------------------------^
 */
/* ARGSUSED 2 */
static Token
at_cap_mach(Mapfile *mf, Token eq_tok, void *uvalue)
{
	return (parse_cap_list(mf, eq_tok, &mf->mf_ofl->ofl_ocapset.oc_mach,
	    CA_SUNW_MACH));
}

/*
 * CAPABILITY [capid] { PLATFORM = value ;
 * -------------------------------^
 */
/* ARGSUSED 2 */
static Token
at_cap_plat(Mapfile *mf, Token eq_tok, void *uvalue)
{
	return (parse_cap_list(mf, eq_tok, &mf->mf_ofl->ofl_ocapset.oc_plat,
	    CA_SUNW_PLAT));
}

/*
 * Top Level Directive:
 *
 * CAPABILITY [capid] { ...
 * ----------^
 */
static Token
dir_capability(Mapfile *mf)
{
	/* CAPABILITY attributes */
	static attr_t attr_list[] = {
		{ MSG_ORIG(MSG_MAPKW_HW),	at_cap_hw, ATTR_FMT_EQ_ALL },
		{ MSG_ORIG(MSG_MAPKW_HW_1),	at_cap_hw_1, ATTR_FMT_EQ_ALL },
		{ MSG_ORIG(MSG_MAPKW_HW_2),	at_cap_hw_2, ATTR_FMT_EQ_ALL },

		{ MSG_ORIG(MSG_MAPKW_MACHINE),	at_cap_mach, ATTR_FMT_EQ_ALL },
		{ MSG_ORIG(MSG_MAPKW_PLATFORM),	at_cap_plat, ATTR_FMT_EQ_ALL },

		{ MSG_ORIG(MSG_MAPKW_SF),	at_cap_sf, ATTR_FMT_EQ_ALL },
		{ MSG_ORIG(MSG_MAPKW_SF_1),	at_cap_sf_1, ATTR_FMT_EQ_ALL },

		/* List must be null terminated */
		{ 0 }
	};

	/*
	 * Size of buffer needed to format the names in attr_list[]. Must
	 * be kept in sync with attr_list.
	 */
	static size_t	attr_list_bufsize =
	    KW_NAME_SIZE(MSG_MAPKW_HW) +
	    KW_NAME_SIZE(MSG_MAPKW_HW_1) +
	    KW_NAME_SIZE(MSG_MAPKW_HW_2) +
	    KW_NAME_SIZE(MSG_MAPKW_MACHINE) +
	    KW_NAME_SIZE(MSG_MAPKW_PLATFORM) +
	    KW_NAME_SIZE(MSG_MAPKW_SF) +
	    KW_NAME_SIZE(MSG_MAPKW_SF_1);

	Capstr		*capstr;
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;

	/*
	 * The first token can be one of:
	 * -	An opening '{'
	 * -	A name, followed by a '{', or a ';'.
	 * Read this initial sequence.
	 */

	switch (tok = ld_map_gettoken(mf, 0, &tkv)) {
	case TK_ERROR:
		return (TK_ERROR);

	case TK_STRING:
		capstr = &mf->mf_ofl->ofl_ocapset.oc_id;

		/*
		 * The ID name is in tkv.tkv_str.  Save this name in the output
		 * capabilities structure.  Note, should multiple ID entries
		 * be encounterd, the last entry wins.
		 */
		DBG_CALL(Dbg_cap_id(mf->mf_ofl->ofl_lml, mf->mf_lineno,
		    capstr->cs_str, tkv.tkv_str));

		capstr->cs_str = tkv.tkv_str;
		mf->mf_ofl->ofl_ocapset.oc_flags |= FLG_OCS_USRDEFID;

		/*
		 * The name can be followed by an opening '{', or a
		 * terminating ';'
		 */
		switch (tok = gettoken_optattr(mf, capstr->cs_str)) {
		case TK_SEMICOLON:
			return (TK_SEMICOLON);
		case TK_LEFTBKT:
			break;
		default:
			return (TK_ERROR);
		}
		break;

	case TK_LEFTBKT:
		/* Directive has no capid, but does supply attributes */
		break;

	default:
		mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_CAPID),
		    MSG_ORIG(MSG_MAPKW_CAPABILITY),
		    ld_map_tokenstr(tok, &tkv, &inv_buf));
		return (TK_ERROR);
	}

	/* Parse the attributes */
	if (parse_attributes(mf, MSG_ORIG(MSG_MAPKW_CAPABILITY),
	    attr_list, attr_list_bufsize, NULL) == TK_ERROR)
		return (TK_ERROR);

	/* Terminating ';' */
	return (gettoken_semicolon(mf, MSG_ORIG(MSG_MAPKW_CAPABILITY)));
}

/*
 * at_dv_allow(): Value for ALLOW= is not a version string
 */
static void
gts_efunc_at_dv_allow(Mapfile *mf, Token tok, ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_VERSION),
	    MSG_ORIG(MSG_MAPKW_ALLOW), ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * DEPEND_VERSIONS object_name { ALLOW = version
 * -------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_dv_allow(Mapfile *mf, Token eq_tok, void *uvalue)
{
	ld_map_tkval_t	tkv;

	if (gettoken_str(mf, 0, &tkv, gts_efunc_at_dv_allow) == TK_ERROR)
		return (TK_ERROR);

	/* Enter the version. uvalue points at the Sdf_desc descriptor */
	if (!ld_map_dv_entry(mf, uvalue, FALSE, tkv.tkv_str))
		return (TK_ERROR);

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_ALLOW)));
}

/*
 * at_dv_allow(): Value for REQUIRE= is not a version string
 */
static void
gts_efunc_at_dv_require(Mapfile *mf, Token tok, ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_VERSION),
	    MSG_ORIG(MSG_MAPKW_REQUIRE), ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * DEPEND_VERSIONS object_name { REQURE = version
 * --------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_dv_require(Mapfile *mf, Token eq_tok, void *uvalue)
{
	ld_map_tkval_t	tkv;

	/* version_name */
	if (gettoken_str(mf, 0, &tkv, gts_efunc_at_dv_require) == TK_ERROR)
		return (TK_ERROR);

	/* Enter the version. uvalue points at the Sdf_desc descriptor */
	if (!ld_map_dv_entry(mf, uvalue, TRUE, tkv.tkv_str))
		return (TK_ERROR);

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_REQUIRE)));
}

/*
 * dir_depend_versions(): Expected object name is not present
 */
static void
gts_efunc_dir_depend_versions(Mapfile *mf, Token tok, ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_OBJNAM),
	    MSG_ORIG(MSG_MAPKW_DEPEND_VERSIONS),
	    ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * Top Level Directive:
 *
 * DEPEND_VERSIONS object_name { ATTR = ...
 * ---------------^
 */
static Token
dir_depend_versions(Mapfile *mf)
{
	/* DEPEND_VERSIONS attributes */
	static attr_t attr_list[] = {
		{ MSG_ORIG(MSG_MAPKW_ALLOW),	at_dv_allow,	ATTR_FMT_EQ },
		{ MSG_ORIG(MSG_MAPKW_REQUIRE),	at_dv_require,	ATTR_FMT_EQ },

		/* List must be null terminated */
		{ 0 }
	};

	/*
	 * Size of buffer needed to format the names in attr_list[]. Must
	 * be kept in sync with attr_list.
	 */
	static size_t	attr_list_bufsize =
	    KW_NAME_SIZE(MSG_MAPKW_ALLOW) +
	    KW_NAME_SIZE(MSG_MAPKW_REQUIRE);

	ld_map_tkval_t	tkv;
	Sdf_desc	*sdf;

	/* object_name */
	if (gettoken_str(mf, 0, &tkv, gts_efunc_dir_depend_versions) ==
	    TK_ERROR)
		return (TK_ERROR);

	/* Get descriptor for dependency */
	if ((sdf = ld_map_dv(mf, tkv.tkv_str)) == NULL)
		return (TK_ERROR);

	/* Opening '{' token */
	if (gettoken_leftbkt(mf, tkv.tkv_str) == TK_ERROR)
		return (TK_ERROR);

	/* Parse the attributes */
	if (parse_attributes(mf, MSG_ORIG(MSG_MAPKW_DEPEND_VERSIONS),
	    attr_list, attr_list_bufsize, sdf) == TK_ERROR)
		return (TK_ERROR);

	/* Terminating ';' */
	return (gettoken_semicolon(mf, MSG_ORIG(MSG_MAPKW_DEPEND_VERSIONS)));
}

/*
 * Top Level Directive:
 *
 * HDR_NOALLOC ;
 * -----------^
 */
static Token
dir_hdr_noalloc(Mapfile *mf)
{
	mf->mf_ofl->ofl_dtflags_1 |= DF_1_NOHDR;
	DBG_CALL(Dbg_map_hdr_noalloc(mf->mf_ofl->ofl_lml, mf->mf_lineno));

	/* ';' terminator token */
	return (gettoken_semicolon(mf, MSG_ORIG(MSG_MAPKW_HDR_NOALLOC)));
}

/*
 * Top Level Directive:
 *
 * PHDR_ADD_NULL = cnt ;
 * -------------^
 */
static Token
dir_phdr_add_null(Mapfile *mf)
{
	Sg_desc		*sgp;
	ld_map_tkval_t	tkv;		/* Value of token */

	/* '=' token */
	if (gettoken_eq(mf, ATTR_FMT_EQ,
	    MSG_ORIG(MSG_MAPKW_PHDR_ADD_NULL)) == TK_ERROR)
		return (TK_ERROR);

	/* integer token */
	if (gettoken_int(mf, MSG_ORIG(MSG_MAPKW_PHDR_ADD_NULL), &tkv) ==
	    TK_ERROR)
		return (TK_ERROR);

	while (tkv.tkv_int.tkvi_value-- > 0) {
		if ((sgp = ld_map_seg_alloc(NULL, PT_NULL,
		    FLG_SG_P_TYPE | FLG_SG_EMPTY)) == NULL)
			return (TK_ERROR);
		if (ld_map_seg_insert(mf, DBG_STATE_NEW, sgp, 0) ==
		    SEG_INS_FAIL)
			return (TK_ERROR);
	}

	/* ';' terminator token */
	return (gettoken_semicolon(mf, MSG_ORIG(MSG_MAPKW_PHDR_ADD_NULL)));
}

/*
 * segment_directive segment_name { ALIGN = value
 * ----------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_seg_align(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Sg_desc		*sgp = uvalue;
	ld_map_tkval_t	tkv;

	/* value */
	if (gettoken_int(mf, MSG_ORIG(MSG_MAPKW_ALIGN), &tkv) == TK_ERROR)
		return (TK_ERROR);

	sgp->sg_phdr.p_align = tkv.tkv_int.tkvi_value;
	sgp->sg_flags |= FLG_SG_P_ALIGN;

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_ALIGN)));
}

/*
 * at_seg_assign_file_basename(): Value for FILE_BASENAME= is not a file name
 */
static void
gts_efunc_at_seg_assign_file_basename(Mapfile *mf, Token tok,
    ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_FILNAM),
	    MSG_ORIG(MSG_MAPKW_FILE_BASENAME),
	    ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * segment_directive segment_name { ASSIGN { FILE_BASENAME = file_name
 * ---------------------------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_seg_assign_file_basename(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Ent_desc	*enp = uvalue;
	ld_map_tkval_t	tkv;

	/* file_name */
	if (gettoken_str(mf, 0, &tkv, gts_efunc_at_seg_assign_file_basename) ==
	    TK_ERROR)
		return (TK_ERROR);

	if (!ld_map_seg_ent_files(mf, enp, TYP_ECF_BASENAME, tkv.tkv_str))
		return (TK_ERROR);

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_FILE_BASENAME)));
}

/*
 * at_seg_assign_file_objname(): Value for FILE_OBJNAME= is not an object name
 */
static void
gts_efunc_at_seg_assign_file_objname(Mapfile *mf, Token tok,
    ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_OBJNAM),
	    MSG_ORIG(MSG_MAPKW_FILE_OBJNAME),
	    ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * segment_directive segment_name { ASSIGN { FILE_OBJNAME = name
 * --------------------------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_seg_assign_file_objname(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Ent_desc	*enp = uvalue;
	ld_map_tkval_t	tkv;

	/* file_objname */
	if (gettoken_str(mf, 0, &tkv, gts_efunc_at_seg_assign_file_objname) ==
	    TK_ERROR)
		return (TK_ERROR);

	if (!ld_map_seg_ent_files(mf, enp, TYP_ECF_OBJNAME, tkv.tkv_str))
		return (TK_ERROR);

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_FILE_OBJNAME)));
}

/*
 * at_seg_assign_file_path(): Value for FILE_PATH= is not a file path
 */
static void
gts_efunc_at_seg_assign_file_path(Mapfile *mf, Token tok, ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_FILPATH),
	    MSG_ORIG(MSG_MAPKW_FILE_PATH),
	    ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * segment_directive segment_name { ASSIGN { FILE_PATH = file_path
 * -----------------------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_seg_assign_file_path(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Ent_desc	*enp = uvalue;
	ld_map_tkval_t	tkv;

	/* file_path */
	if (gettoken_str(mf, 0, &tkv, gts_efunc_at_seg_assign_file_path) ==
	    TK_ERROR)
		return (TK_ERROR);

	if (!ld_map_seg_ent_files(mf, enp, TYP_ECF_PATH, tkv.tkv_str))
		return (TK_ERROR);

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_FILE_PATH)));
}

/*
 * segment_directive segment_name { ASSIGN { FLAGS = ... ;
 * -------------------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_seg_assign_flags(Mapfile *mf, Token eq_tok, void *uvalue)
{
	typedef struct {
		const char	*name;
		Word		value;
	} secflag_t;
	static secflag_t flag_list[] = {
		{ MSG_ORIG(MSG_MAPKW_ALLOC),		SHF_ALLOC },
		{ MSG_ORIG(MSG_MAPKW_EXECUTE),		SHF_EXECINSTR },
		{ MSG_ORIG(MSG_MAPKW_WRITE),		SHF_WRITE },
		{ MSG_ORIG(MSG_MAPKW_AMD64_LARGE),	SHF_AMD64_LARGE },

		/* List must be null terminated */
		{ 0 },
	};

	/*
	 * Size of buffer needed to format the names in flag_list[]. Must
	 * be kept in sync with flag_list.
	 */
	static size_t	flag_list_bufsize =
	    KW_NAME_SIZE(MSG_MAPKW_ALLOC) +
	    KW_NAME_SIZE(MSG_MAPKW_EXECUTE) +
	    KW_NAME_SIZE(MSG_MAPKW_WRITE) +
	    KW_NAME_SIZE(MSG_MAPKW_AMD64_LARGE);

	Ent_desc	*enp = uvalue;
	int		bcnt = 0, cnt = 0;
	secflag_t	*flag;
	int		done;
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;

	/* Read and process tokens until the closing terminator is seen */
	for (done = 0; done == 0; ) {
		switch (tok = ld_map_gettoken(mf, 0, &tkv)) {
		case TK_ERROR:
			return (TK_ERROR);

		case TK_BANG:
			/* Ensure ! only specified once per flag */
			if (bcnt != 0) {
				mf_fatal0(mf, MSG_INTL(MSG_MAP_SFLG_ONEBANG));
				return (TK_ERROR);
			}
			bcnt++;
			break;

		case TK_STRING:
			flag = ld_map_kwfind(tkv.tkv_str, flag_list,
			    SGSOFFSETOF(secflag_t, name), sizeof (flag[0]));
			if (flag == NULL)
				goto bad_flag;
			cnt++;
			enp->ec_attrmask |= flag->value;
			if (bcnt == 0)
				enp->ec_attrbits |=  flag->value;
			bcnt = 0;
			break;

		case TK_RIGHTBKT:
		case TK_SEMICOLON:
			done = 1;
			break;

		default:
		bad_flag:
			{
				char buf[VLA_SIZE(flag_list_bufsize)];

				mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SECFLAG),
				    ld_map_kwnames(flag_list,
				    SGSOFFSETOF(secflag_t, name),
				    sizeof (flag[0]), buf, flag_list_bufsize),
				    ld_map_tokenstr(tok, &tkv, &inv_buf));
			}
			return (TK_ERROR);
		}
	}

	/*
	 * Ensure that a trailing '!' was not left at the end of the line
	 * without a corresponding flag to apply it to.
	 */
	if (bcnt != 0) {
		mf_fatal0(mf, MSG_INTL(MSG_MAP_SFLG_EXBANG));
		return (TK_ERROR);
	}

	/* Make sure there was at least one flag */
	if (cnt == 0) {
		mf_fatal(mf, MSG_INTL(MSG_MAP_NOVALUES),
		    MSG_ORIG(MSG_MAPKW_FLAGS));
		return (TK_ERROR);
	}

	return (tok);		/* Either TK_SEMICOLON or TK_RIGHTBKT */
}

/*
 * at_seg_assign_is_name(): Value for IS_NAME= is not a section name
 */
static void
gts_efunc_at_seg_assign_is_name(Mapfile *mf, Token tok, ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SECNAM),
	    MSG_ORIG(MSG_MAPKW_IS_NAME), ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * segment_directive segment_name { ASSIGN { IS_NAME = section_name ;
 * ---------------------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_seg_assign_is_name(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Ent_desc	*enp = uvalue;
	ld_map_tkval_t	tkv;

	/* section_name */
	if (gettoken_str(mf, 0, &tkv, gts_efunc_at_seg_assign_is_name) ==
	    TK_ERROR)
		return (TK_ERROR);
	enp->ec_is_name = tkv.tkv_str;

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_IS_NAME)));
}

/*
 * at_seg_assign_type(): Value for TYPE= is not a section type
 */
static void
gts_efunc_at_seg_assign_type(Mapfile *mf, Token tok, ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SHTYPE),
	    ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * segment_directive segment_name { ASSIGN { TYPE = section_type ;
 * ------------------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_seg_assign_type(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Ent_desc		*enp = uvalue;
	ld_map_tkval_t		tkv;
	conv_strtol_uvalue_t	conv_uvalue;

	/* section type */
	if (gettoken_str(mf, TK_F_KEYWORD, &tkv,
	    gts_efunc_at_seg_assign_type) == TK_ERROR)
		return (TK_ERROR);

	/*
	 * Use the libconv iteration facility to map the given name to
	 * its value. This allows us to keep up with any new sections
	 * without having to change this code.
	 */
	if (conv_iter_strtol_init(tkv.tkv_str, &conv_uvalue) != 0) {
		conv_iter_ret_t	status;

		/* Look at the canonical form */
		status = conv_iter_sec_type(CONV_OSABI_ALL, CONV_MACH_ALL,
		    CONV_FMT_ALT_CF, conv_iter_strtol, &conv_uvalue);

		/* Failing that, look at the normal form */
		if (status != CONV_ITER_DONE)
			(void) conv_iter_sec_type(CONV_OSABI_ALL,
			    CONV_MACH_ALL, CONV_FMT_ALT_NF, conv_iter_strtol,
			    &conv_uvalue);

		/* If we didn't match anything report error */
		if (!conv_uvalue.csl_found) {
			gts_efunc_at_seg_assign_type(mf, TK_STRING, &tkv);
			return (TK_ERROR);
		}
	}

	enp->ec_type = conv_uvalue.csl_value;

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_TYPE)));
}

/*
 * segment_directive segment_name { ASSIGN { ...
 * -----------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_seg_assign(Mapfile *mf, Token eq_tok, void *uvalue)
{
	/* segment_directive ASSIGN sub-attributes */
	static attr_t attr_list[] = {
		{ MSG_ORIG(MSG_MAPKW_FILE_BASENAME),
		    at_seg_assign_file_basename,	ATTR_FMT_EQ },
		{ MSG_ORIG(MSG_MAPKW_FILE_OBJNAME),
		    at_seg_assign_file_objname,		ATTR_FMT_EQ },
		{ MSG_ORIG(MSG_MAPKW_FILE_PATH),
		    at_seg_assign_file_path,		ATTR_FMT_EQ },
		{ MSG_ORIG(MSG_MAPKW_FLAGS),
		    at_seg_assign_flags,		ATTR_FMT_EQ_ALL },
		{ MSG_ORIG(MSG_MAPKW_IS_NAME),
		    at_seg_assign_is_name,		ATTR_FMT_EQ },
		{ MSG_ORIG(MSG_MAPKW_TYPE),
		    at_seg_assign_type,			ATTR_FMT_EQ },

		/* List must be null terminated */
		{ 0 }
	};

	/*
	 * Size of buffer needed to format the names in attr_list[]. Must
	 * be kept in sync with attr_list.
	 */
	static size_t	attr_list_bufsize =
	    KW_NAME_SIZE(MSG_MAPKW_FILE_BASENAME) +
	    KW_NAME_SIZE(MSG_MAPKW_FILE_PATH) +
	    KW_NAME_SIZE(MSG_MAPKW_FLAGS) +
	    KW_NAME_SIZE(MSG_MAPKW_FILE_OBJNAME) +
	    KW_NAME_SIZE(MSG_MAPKW_IS_NAME) +
	    KW_NAME_SIZE(MSG_MAPKW_TYPE);

	Sg_desc		*sgp = uvalue;
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;
	const char	*name = NULL;
	Ent_desc	*enp;

	/*
	 * ASSIGN takes an optional name, plus attributes are optional,
	 * so expect a name, an opening '{', or a ';'.
	 */
	tok = ld_map_gettoken(mf, 0, &tkv);
	switch (tok) {
	case TK_ERROR:
		return (TK_ERROR);

	case TK_STRING:
		name = tkv.tkv_str;
		tok = ld_map_gettoken(mf, 0, &tkv);
		break;
	}

	/* Add a new entrance criteria descriptor to the segment */
	if ((enp = ld_map_seg_ent_add(mf, sgp, name)) == NULL)
		return (TK_ERROR);

	/* Having handled the name, expect either '{' or ';' */
	switch (tok) {
	default:
		mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SEMLBKT),
		    MSG_ORIG(MSG_MAPKW_ASSIGN_SECTION),
		    ld_map_tokenstr(tok, &tkv, &inv_buf));
		return (TK_ERROR);
	case TK_ERROR:
		return (TK_ERROR);
	case TK_SEMICOLON:
	case TK_RIGHTBKT:
		/* No attributes: It will match anything */
		enp->ec_flags |= FLG_EC_CATCHALL;
		break;
	case TK_LEFTBKT:
		/* Parse the attributes */
		if (parse_attributes(mf, MSG_ORIG(MSG_MAPKW_ASSIGN_SECTION),
		    attr_list, attr_list_bufsize, enp) == TK_ERROR)
			return (TK_ERROR);

		/* Terminating ';',  or '}' which also terminates caller */
		tok = gettoken_term(mf, MSG_ORIG(MSG_MAPKW_ASSIGN_SECTION));
		if (tok == TK_ERROR)
			return (TK_ERROR);
		break;
	}

	DBG_CALL(Dbg_map_ent(mf->mf_ofl->ofl_lml, enp, mf->mf_ofl,
	    mf->mf_lineno));
	return (tok);
}

/*
 * segment_directive segment_name { DISABLE ;
 * ----------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_seg_disable(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Sg_desc		*sgp = uvalue;

	/* If the segment cannot be disabled, issue error */
	if (sgp->sg_flags & FLG_SG_NODISABLE) {
		mf_fatal(mf, MSG_INTL(MSG_MAP_CNTDISSEG), sgp->sg_name);
		return (TK_ERROR);
	}

	/* Disable the segment */
	sgp->sg_flags |= FLG_SG_DISABLED;

	/* terminator */
	return (gettoken_semicolon(mf, MSG_ORIG(MSG_MAPKW_DISABLE)));
}

/*
 * segment_directive segment_name { FLAGS eq-op ...
 * --------------------------------------------^
 *
 * Note that this routine is also used for the STACK directive,
 * as STACK also manipulates a segment descriptor.
 *
 * STACK { FLAGS eq-op ... ;
 * -------------------^
 */
/* ARGSUSED 2 */
static Token
at_seg_flags(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Sg_desc		*sgp = uvalue;
	Token		tok;
	Xword		flags;

	tok = parse_segment_flags(mf, &flags);
	if (tok == TK_ERROR)
		return (TK_ERROR);

	setflags_eq(&sgp->sg_phdr.p_flags, eq_tok, flags);
	sgp->sg_flags |= FLG_SG_P_FLAGS;

	return (tok);
}

/*
 * segment_directive segment_name { IS_ORDER eq_op value
 * -----------------------------------------------^
 */
/* ARGSUSED 2 */
static Token
at_seg_is_order(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Sg_desc		*sgp = uvalue;
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;
	int		done;
	Aliste		idx;
	Ent_desc	*enp, *enp2;

	/*
	 * The '=' form of assignment resets the list. The list contains
	 * pointers to our mapfile text, so we do not have to free anything.
	 */
	if (eq_tok == TK_EQUAL)
		aplist_reset(sgp->sg_is_order);

	/*
	 * One or more ASSIGN names, terminated by a semicolon.
	 */
	for (done = 0; done == 0; ) {
		switch (tok = ld_map_gettoken(mf, 0, &tkv)) {
		case TK_ERROR:
			return (TK_ERROR);

		case TK_STRING:
			/*
			 * The referenced entrance criteria must have
			 * already been defined.
			 */
			enp = ld_ent_lookup(mf->mf_ofl, tkv.tkv_str, NULL);
			if (enp == NULL) {
				mf_fatal(mf, MSG_INTL(MSG_MAP_UNKENT),
				    tkv.tkv_str);
				return (TK_ERROR);
			}

			/*
			 * Make sure it's not already on the list
			 */
			for (APLIST_TRAVERSE(sgp->sg_is_order, idx, enp2))
				if (enp == enp2) {
					mf_fatal(mf,
					    MSG_INTL(MSG_MAP_DUP_IS_ORD),
					    tkv.tkv_str);
					return (TK_ERROR);
				}

			/* Put it at the end of the order list */
			if (aplist_append(&sgp->sg_is_order, enp,
			    AL_CNT_SG_IS_ORDER) == NULL)
				return (TK_ERROR);
			break;

		case TK_SEMICOLON:
		case TK_RIGHTBKT:
			done = 1;
			break;

		default:
			mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_ECNAM),
			    ld_map_tokenstr(tok, &tkv, &inv_buf));
			return (TK_ERROR);
		}
	}

	return (tok);
}

/*
 * segment_directive segment_name { MAX_SIZE = value
 * -------------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_seg_max_size(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Sg_desc		*sgp = uvalue;
	ld_map_tkval_t	tkv;

	/* value */
	if (gettoken_int(mf, MSG_ORIG(MSG_MAPKW_MAX_SIZE), &tkv) == TK_ERROR)
		return (TK_ERROR);

	sgp->sg_length = tkv.tkv_int.tkvi_value;
	sgp->sg_flags |= FLG_SG_LENGTH;

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_MAX_SIZE)));
}

/*
 * segment_directive segment_name { NOHDR ;
 * --------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_seg_nohdr(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Sg_desc		*sgp = uvalue;

	/*
	 * Set the nohdr flag on the segment. If this segment is the
	 * first loadable segment, the ELF and program headers will
	 * not be included.
	 *
	 * The HDR_NOALLOC top level directive is preferred. This feature
	 * exists to give 1:1 feature parity with version 1 mapfiles that
	 * use the ?N segment flag and expect it to only take effect
	 * if that segment ends up being first.
	 */
	sgp->sg_flags |= FLG_SG_NOHDR;

	/* terminator */
	return (gettoken_semicolon(mf, MSG_ORIG(MSG_MAPKW_NOHDR)));
}

/*
 * segment_directive segment_name { OS_ORDER eq_op assign_name...
 * -----------------------------------------------^
 */
/* ARGSUSED 2 */
static Token
at_seg_os_order(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Sg_desc		*sgp = uvalue;
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;
	int		done;

	/*
	 * The '=' form of assignment resets the list. The list contains
	 * pointers to our mapfile text, so we do not have to free anything.
	 */
	if (eq_tok == TK_EQUAL)
		alist_reset(sgp->sg_os_order);

	/*
	 * One or more section names, terminated by a semicolon.
	 */
	for (done = 0; done == 0; ) {
		switch (tok = ld_map_gettoken(mf, 0, &tkv)) {
		case TK_ERROR:
			return (TK_ERROR);

		case TK_STRING:
			if (!ld_map_seg_os_order_add(mf, sgp, tkv.tkv_str))
				return (TK_ERROR);
			break;

		case TK_SEMICOLON:
		case TK_RIGHTBKT:
			done = 1;
			break;

		default:
			mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SECNAM),
			    ld_map_tokenstr(tok, &tkv, &inv_buf));
			return (TK_ERROR);
		}
	}

	return (tok);
}

/*
 * segment_directive segment_name { PADDR = paddr
 * ----------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_seg_paddr(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Sg_desc		*sgp = uvalue, *sgp2;
	Aliste		idx;
	ld_map_tkval_t	tkv;

	/*
	 * Ensure that the segment isn't in the segment order list.
	 */
	for (APLIST_TRAVERSE(mf->mf_ofl->ofl_segs_order, idx, sgp2))
		if (sgp == sgp2) {
			mf_fatal(mf,
			    MSG_INTL(MSG_MAP_CNTADDRORDER), sgp->sg_name);
			return (TK_ERROR);
		}

	/* value */
	if (gettoken_int(mf, MSG_ORIG(MSG_MAPKW_PADDR), &tkv) == TK_ERROR)
		return (TK_ERROR);

	sgp->sg_phdr.p_paddr = tkv.tkv_int.tkvi_value;
	sgp->sg_flags |= FLG_SG_P_PADDR;

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_PADDR)));
}

/*
 * segment_directive segment_name { ROUND = value
 * ----------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_seg_round(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Sg_desc		*sgp = uvalue;
	ld_map_tkval_t	tkv;

	/* value */
	if (gettoken_int(mf, MSG_ORIG(MSG_MAPKW_ROUND), &tkv) == TK_ERROR)
		return (TK_ERROR);

	sgp->sg_round = tkv.tkv_int.tkvi_value;
	sgp->sg_flags |= FLG_SG_ROUND;

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_ROUND)));
}

/*
 * segment_directive segment_name { SIZE_SYMBOL = symbol_name
 * ----------------------------------------------^
 */
/* ARGSUSED 2 */
static Token
at_seg_size_symbol(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Sg_desc		*sgp = uvalue;
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;
	int		done, cnt = 0;

	/*
	 * One or more symbol names, terminated by a semicolon.
	 */
	for (done = 0; done == 0; ) {
		switch (tok = ld_map_gettoken(mf, 0, &tkv)) {
		case TK_ERROR:
			return (TK_ERROR);

		case TK_STRING:
			if (!ld_map_seg_size_symbol(mf, sgp, eq_tok,
			    tkv.tkv_str))
				return (TK_ERROR);
			cnt++;

			/*
			 * If the operator is TK_EQUAL, turn it into
			 * TK_PLUSEQ for any symbol names after the first.
			 * These additional symbols are added, and are not
			 * replacements for the first one.
			 */
			eq_tok = TK_PLUSEQ;
			break;

		case TK_SEMICOLON:
		case TK_RIGHTBKT:
			done = 1;
			break;

		default:
			mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SYMNAM),
			    MSG_ORIG(MSG_MAPKW_SIZE_SYMBOL),
			    ld_map_tokenstr(tok, &tkv, &inv_buf));
			return (TK_ERROR);
		}
	}

	/* Make sure there was at least one name */
	if (cnt == 0) {
		mf_fatal(mf, MSG_INTL(MSG_MAP_NOVALUES),
		    MSG_ORIG(MSG_MAPKW_SIZE_SYMBOL));
		return (TK_ERROR);
	}

	return (tok);
}

/*
 * segment_directive segment_name { VADDR = vaddr
 * ----------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_seg_vaddr(Mapfile *mf, Token eq_tok, void *uvalue)
{
	Sg_desc		*sgp = uvalue, *sgp2;
	Aliste		idx;
	ld_map_tkval_t	tkv;

	/*
	 * Ensure that the segment isn't in the segment order list.
	 */
	for (APLIST_TRAVERSE(mf->mf_ofl->ofl_segs_order, idx, sgp2))
		if (sgp == sgp2) {
			mf_fatal(mf,
			    MSG_INTL(MSG_MAP_CNTADDRORDER), sgp->sg_name);
			return (TK_ERROR);
		}

	/* value */
	if (gettoken_int(mf, MSG_ORIG(MSG_MAPKW_VADDR), &tkv) == TK_ERROR)
		return (TK_ERROR);

	sgp->sg_phdr.p_vaddr = tkv.tkv_int.tkvi_value;
	sgp->sg_flags |= FLG_SG_P_VADDR;

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_VADDR)));
}

/*
 * Top Level Directive:
 *
 * {LOAD|NOTE|NULL}_SEGMENT segment_name { ...
 * ------------------------^
 *
 * Common implementation body for the family of segment directives. These
 * take the same syntax, and share a common subset of attributes. They differ
 * in the type of segments they handle and the specific attributes accepted.
 *
 * entry:
 *	mf - Mapfile descriptor ({LOAD|NOTE|NULL}_SEGMENT)
 *	dir_name - Name of directive.
 *	seg_type - Type of segment (PT_LOAD, PT_NOTE, PT_NULL).
 *	attr_list - NULL terminated attribute array
 *	attr_list_bufsize - Size of required buffer to format all the
 *		names in attr_list.
 *	gts_efunc - Error function to pass to gettoken_str() when trying
 *		to obtain a segment name token.
 */
static Token
dir_segment_inner(Mapfile *mf, const char *dir_name, Word seg_type,
    attr_t *attr_list, size_t attr_list_bufsize, gts_efunc_t gts_efunc)
{
	Token		tok;
	ld_map_tkval_t	tkv;
	Sg_desc		*sgp;
	Boolean		new_segment;
	Xword		ndx;
	avl_index_t	where;

	/* segment_name */
	if (gettoken_str(mf, 0, &tkv, gts_efunc) == TK_ERROR)
		return (TK_ERROR);
	sgp = ld_seg_lookup(mf->mf_ofl, tkv.tkv_str, &where);
	new_segment = (sgp == NULL);

	if (new_segment) {
		/* Allocate a descriptor for new segment */
		if ((sgp = ld_map_seg_alloc(tkv.tkv_str, seg_type,
		    FLG_SG_P_TYPE)) == NULL)
			return (TK_ERROR);
	} else {
		/* Make sure it's the right type of segment */
		if (sgp->sg_phdr.p_type != seg_type) {
			Conv_inv_buf_t	inv_buf;

			mf_fatal(mf, MSG_INTL(MSG_MAP_EXPSEGTYPE),
			    conv_phdr_type(ELFOSABI_SOLARIS, ld_targ.t_m.m_mach,
			    sgp->sg_phdr.p_type, CONV_FMT_ALT_CF, &inv_buf),
			    dir_name, tkv.tkv_str);
			return (TK_ERROR);
		}

		/* If it was disabled, being referenced enables it */
		sgp->sg_flags &= ~FLG_SG_DISABLED;

		if (DBG_ENABLED) {
			/*
			 * Not a new segment, so show the initial value
			 * before modifying it.
			 */
			ndx = ld_map_seg_index(mf, sgp);
			DBG_CALL(Dbg_map_seg(mf->mf_ofl, DBG_STATE_MOD_BEFORE,
			    ndx, sgp, mf->mf_lineno));
		}
	}

	/*
	 * Attributes are optional, so expect an opening '{', or a ';'.
	 */
	switch (tok = gettoken_optattr(mf, dir_name)) {
	default:
		tok = TK_ERROR;
		break;
	case TK_SEMICOLON:
		break;
	case TK_LEFTBKT:
		/* Parse the attributes */
		if (parse_attributes(mf, dir_name,
		    attr_list, attr_list_bufsize, sgp) == TK_ERROR)
			return (TK_ERROR);

		/* Terminating ';' */
		tok = gettoken_semicolon(mf, dir_name);
		if (tok == TK_ERROR)
			return (TK_ERROR);

		break;
	}

	/*
	 * If this is a new segment, finish its initialization
	 * and insert it into the segment list.
	 */
	if (new_segment) {
		if (ld_map_seg_insert(mf, DBG_STATE_NEW, sgp, where) ==
		    SEG_INS_FAIL)
			return (TK_ERROR);
	} else {
		/* Not new. Show what's changed */
		DBG_CALL(Dbg_map_seg(mf->mf_ofl, DBG_STATE_MOD_AFTER,
		    ndx, sgp, mf->mf_lineno));
	}

	return (tok);
}

/*
 * dir_load_segment(): Expected loadable segment name is not present
 */
static void
gts_efunc_dir_load_segment(Mapfile *mf, Token tok, ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SEGNAM),
	    MSG_ORIG(MSG_MAPKW_LOAD_SEGMENT),
	    ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * Top Level Directive:
 *
 * LOAD_SEGMENT segment_name { ...
 * ------------^
 */
static Token
dir_load_segment(Mapfile *mf)
{
	/* LOAD_SEGMENT attributes */
	static attr_t attr_list[] = {
		{ MSG_ORIG(MSG_MAPKW_ALIGN),	at_seg_align,	ATTR_FMT_EQ },
		{ MSG_ORIG(MSG_MAPKW_ASSIGN_SECTION),
		    at_seg_assign,	ATTR_FMT_NAME },
		{ MSG_ORIG(MSG_MAPKW_DISABLE),	at_seg_disable,	ATTR_FMT_NAME },
		{ MSG_ORIG(MSG_MAPKW_FLAGS),	at_seg_flags,
		    ATTR_FMT_EQ_ALL },
		{ MSG_ORIG(MSG_MAPKW_IS_ORDER),	at_seg_is_order,
		    ATTR_FMT_EQ_PEQ },
		{ MSG_ORIG(MSG_MAPKW_MAX_SIZE),	at_seg_max_size, ATTR_FMT_EQ },
		{ MSG_ORIG(MSG_MAPKW_NOHDR),	at_seg_nohdr,	ATTR_FMT_NAME },
		{ MSG_ORIG(MSG_MAPKW_OS_ORDER),	at_seg_os_order,
		    ATTR_FMT_EQ_PEQ },
		{ MSG_ORIG(MSG_MAPKW_PADDR),	at_seg_paddr,	ATTR_FMT_EQ },
		{ MSG_ORIG(MSG_MAPKW_ROUND),	at_seg_round,	ATTR_FMT_EQ },
		{ MSG_ORIG(MSG_MAPKW_SIZE_SYMBOL),
		    at_seg_size_symbol,	ATTR_FMT_EQ_PEQ },
		{ MSG_ORIG(MSG_MAPKW_VADDR),	at_seg_vaddr,	ATTR_FMT_EQ },

		/* List must be null terminated */
		{ 0 }
	};

	/*
	 * Size of buffer needed to format the names in attr_list[]. Must
	 * be kept in sync with attr_list.
	 */
	static size_t	attr_list_bufsize =
	    KW_NAME_SIZE(MSG_MAPKW_ALIGN) +
	    KW_NAME_SIZE(MSG_MAPKW_ASSIGN_SECTION) +
	    KW_NAME_SIZE(MSG_MAPKW_DISABLE) +
	    KW_NAME_SIZE(MSG_MAPKW_FLAGS) +
	    KW_NAME_SIZE(MSG_MAPKW_IS_ORDER) +
	    KW_NAME_SIZE(MSG_MAPKW_MAX_SIZE) +
	    KW_NAME_SIZE(MSG_MAPKW_PADDR) +
	    KW_NAME_SIZE(MSG_MAPKW_ROUND) +
	    KW_NAME_SIZE(MSG_MAPKW_OS_ORDER) +
	    KW_NAME_SIZE(MSG_MAPKW_SIZE_SYMBOL) +
	    KW_NAME_SIZE(MSG_MAPKW_VADDR);

	return (dir_segment_inner(mf, MSG_ORIG(MSG_MAPKW_LOAD_SEGMENT),
	    PT_LOAD, attr_list, attr_list_bufsize, gts_efunc_dir_load_segment));

}

/*
 * Common shared segment directive attributes
 */
static attr_t segment_core_attr_list[] = {
	{ MSG_ORIG(MSG_MAPKW_ASSIGN_SECTION), at_seg_assign, ATTR_FMT_NAME },
	{ MSG_ORIG(MSG_MAPKW_DISABLE),	at_seg_disable,	 ATTR_FMT_NAME },
	{ MSG_ORIG(MSG_MAPKW_IS_ORDER),	at_seg_is_order, ATTR_FMT_EQ_PEQ },
	{ MSG_ORIG(MSG_MAPKW_OS_ORDER),	at_seg_os_order, ATTR_FMT_EQ_PEQ },

	/* List must be null terminated */
	{ 0 }
};

/*
 * Size of buffer needed to format the names in segment_core_attr_list[].
 * Must be kept in sync with segment_core_attr_list.
 */
static size_t	segment_core_attr_list_bufsize =
	KW_NAME_SIZE(MSG_MAPKW_ASSIGN_SECTION) +
	KW_NAME_SIZE(MSG_MAPKW_DISABLE) +
	KW_NAME_SIZE(MSG_MAPKW_IS_ORDER) +
	KW_NAME_SIZE(MSG_MAPKW_OS_ORDER);

/*
 * dir_note_segment(): Expected note segment name is not present
 */
static void
gts_efunc_dir_note_segment(Mapfile *mf, Token tok, ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SEGNAM),
	    MSG_ORIG(MSG_MAPKW_NOTE_SEGMENT),
	    ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * Top Level Directive:
 *
 * NOTE_SEGMENT segment_name { ...
 * ------------^
 */
static Token
dir_note_segment(Mapfile *mf)
{
	return (dir_segment_inner(mf, MSG_ORIG(MSG_MAPKW_NOTE_SEGMENT),
	    PT_NOTE, segment_core_attr_list, segment_core_attr_list_bufsize,
	    gts_efunc_dir_note_segment));

}

/*
 * dir_null_segment(): Expected null segment name is not present
 */
static void
gts_efunc_dir_null_segment(Mapfile *mf, Token tok, ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SEGNAM),
	    MSG_ORIG(MSG_MAPKW_NULL_SEGMENT),
	    ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * Top Level Directive:
 *
 * NULL_SEGMENT segment_name { ...
 * ------------^
 */
static Token
dir_null_segment(Mapfile *mf)
{
	return (dir_segment_inner(mf, MSG_ORIG(MSG_MAPKW_NULL_SEGMENT),
	    PT_NULL, segment_core_attr_list, segment_core_attr_list_bufsize,
	    gts_efunc_dir_null_segment));

}

/*
 * Top Level Directive:
 *
 * SEGMENT_ORDER segment_name ... ;
 */
static Token
dir_segment_order(Mapfile *mf)
{
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;
	Aliste		idx;
	Sg_desc		*sgp, *sgp2;
	int		done;

	/* Expect either a '=' or '+=' */
	tok = gettoken_eq(mf, ATTR_FMT_EQ_PEQ,
	    MSG_ORIG(MSG_MAPKW_SEGMENT_ORDER));
	if (tok == TK_ERROR)
		return (TK_ERROR);

	DBG_CALL(Dbg_map_seg_order(mf->mf_ofl, ELFOSABI_SOLARIS,
	    ld_targ.t_m.m_mach, DBG_STATE_MOD_BEFORE, mf->mf_lineno));

	/*
	 * The '=' form of assignment resets the list. The list contains
	 * pointers to our mapfile text, so we do not have to free anything.
	 */
	if (tok == TK_EQUAL)
		aplist_reset(mf->mf_ofl->ofl_segs_order);

	/* Read segment names, and add to list until terminator (';') is seen */
	for (done = 0; done == 0; ) {
		switch (tok = ld_map_gettoken(mf, 0, &tkv)) {
		case TK_ERROR:
			return (TK_ERROR);

		case TK_STRING:
			/*
			 * The segment must have already been defined.
			 */
			sgp = ld_seg_lookup(mf->mf_ofl, tkv.tkv_str, NULL);
			if (sgp == NULL) {
				mf_fatal(mf, MSG_INTL(MSG_MAP_UNKSEG),
				    tkv.tkv_str);
				return (TK_ERROR);
			}

			/*
			 * Make sure it's not already on the list
			 */
			for (APLIST_TRAVERSE(mf->mf_ofl->ofl_segs_order,
			    idx, sgp2))
				if (sgp == sgp2) {
					mf_fatal(mf,
					    MSG_INTL(MSG_MAP_DUPORDSEG),
					    MSG_ORIG(MSG_MAPKW_SEGMENT_ORDER),
					    tkv.tkv_str);
					return (TK_ERROR);
				}

			/*
			 * It can't be ordered and also have an explicit
			 * paddr or vaddr.
			 */
			if (sgp->sg_flags & (FLG_SG_P_PADDR | FLG_SG_P_VADDR)) {
				mf_fatal(mf, MSG_INTL(MSG_MAP_CNTADDRORDER),
				    sgp->sg_name);
				return (TK_ERROR);
			}


			/* Put it at the end of the list */
			if (aplist_append(&mf->mf_ofl->ofl_segs_order, sgp,
			    AL_CNT_SG_IS_ORDER) == NULL)
				return (TK_ERROR);
			break;

		case TK_SEMICOLON:
			done = 1;
			break;

		default:
			mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SEGNAM),
			    MSG_ORIG(MSG_MAPKW_SEGMENT_ORDER),
			    ld_map_tokenstr(tok, &tkv, &inv_buf));
			return (TK_ERROR);
		}
	}

	DBG_CALL(Dbg_map_seg_order(mf->mf_ofl, ELFOSABI_SOLARIS,
	    ld_targ.t_m.m_mach, DBG_STATE_MOD_AFTER, mf->mf_lineno));

	return (tok);
}

/*
 * Top Level Directive:
 *
 * STACK { ...
 * -----^
 */
static Token
dir_stack(Mapfile *mf)
{
	/* STACK attributes */
	static attr_t attr_list[] = {
		{ MSG_ORIG(MSG_MAPKW_FLAGS), at_seg_flags, ATTR_FMT_EQ_ALL },

		/* List must be null terminated */
		{ 0 }
	};

	/*
	 * Size of buffer needed to format the names in attr_list[]. Must
	 * be kept in sync with attr_list.
	 */
	static size_t	attr_list_bufsize =
	    KW_NAME_SIZE(MSG_MAPKW_FLAGS);

	Sg_desc	*sgp;
	Token	tok;


	/* Opening '{' token */
	if (gettoken_leftbkt(mf, MSG_ORIG(MSG_MAPKW_STACK)) == TK_ERROR)
		return (TK_ERROR);

	/* Fetch the PT_SUNWSTACK segment descriptor */
	sgp = ld_map_seg_stack(mf);

	/* Parse the attributes */
	if (parse_attributes(mf, MSG_ORIG(MSG_MAPKW_STACK),
	    attr_list, attr_list_bufsize, sgp) == TK_ERROR)
		return (TK_ERROR);

	/* Terminating ';' */
	tok = gettoken_semicolon(mf, MSG_ORIG(MSG_MAPKW_STACK));
	if (tok == TK_ERROR)
		return (TK_ERROR);

	if (DBG_ENABLED) {
		Xword ndx = ld_map_seg_index(mf, sgp);

		Dbg_map_seg(mf->mf_ofl, DBG_STATE_MOD_AFTER, ndx, sgp,
		    mf->mf_lineno);
	}

	return (tok);
}

/*
 * at_sym_aux(): Value for AUXILIARY= is not an object name
 */
static void
gts_efunc_at_sym_aux(Mapfile *mf, Token tok, ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_OBJNAM),
	    MSG_ORIG(MSG_MAPKW_AUX), ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * SYMBOL [version_name] { symbol_name { AUXILIARY = soname
 * -------------------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_sym_aux(Mapfile *mf, Token eq_tok, void *uvalue)
{
	symbol_state_t	*ss = uvalue;
	ld_map_tkval_t	tkv;

	/* auxiliary filter soname */
	if (gettoken_str(mf, 0, &tkv, gts_efunc_at_sym_aux) == TK_ERROR)
		return (TK_ERROR);

	ld_map_sym_filtee(mf, &ss->ss_mv, &ss->ss_ms, FLG_SY_AUXFLTR,
	    tkv.tkv_str);

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_AUX)));
}

/*
 * at_sym_filter(): Value for FILTER= is not an object name
 */
static void
gts_efunc_at_sym_filter(Mapfile *mf, Token tok, ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_OBJNAM),
	    MSG_ORIG(MSG_MAPKW_FILTER), ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * SYMBOL [version_name] { symbol_name { FILTER = soname
 * ----------------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_sym_filter(Mapfile *mf, Token eq_tok, void *uvalue)
{
	symbol_state_t	*ss = uvalue;
	ld_map_tkval_t	tkv;

	/* filter soname */
	if (gettoken_str(mf, 0, &tkv, gts_efunc_at_sym_filter) == TK_ERROR)
		return (TK_ERROR);

	ld_map_sym_filtee(mf, &ss->ss_mv, &ss->ss_ms, FLG_SY_STDFLTR,
	    tkv.tkv_str);

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_FILTER)));
}

/*
 * SYMBOL [version_name] { symbol_name { FLAGS = ...
 * ---------------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_sym_flags(Mapfile *mf, Token eq_tok, void *uvalue)
{
	typedef struct {
		const char	*name;
		sd_flag_t	value;
	} symflag_t;

	static symflag_t symflag_list[] = {
		{ MSG_ORIG(MSG_MAPKW_DIRECT),		FLG_SY_DIR },
		{ MSG_ORIG(MSG_MAPKW_DYNSORT),		FLG_SY_DYNSORT },
		{ MSG_ORIG(MSG_MAPKW_EXTERN),		FLG_SY_EXTERN },
		{ MSG_ORIG(MSG_MAPKW_INTERPOSE),	FLG_SY_INTPOSE },
		{ MSG_ORIG(MSG_MAPKW_NODIRECT),		FLG_SY_NDIR },
		{ MSG_ORIG(MSG_MAPKW_NODYNSORT),	FLG_SY_NODYNSORT },
		{ MSG_ORIG(MSG_MAPKW_PARENT),		FLG_SY_PARENT },

		/* List must be null terminated */
		{ 0 }
	};

	/*
	 * Size of buffer needed to format the names in flag_list[]. Must
	 * be kept in sync with flag_list.
	 */
	static size_t	symflag_list_bufsize =
	    KW_NAME_SIZE(MSG_MAPKW_DIRECT) +
	    KW_NAME_SIZE(MSG_MAPKW_DYNSORT) +
	    KW_NAME_SIZE(MSG_MAPKW_EXTERN) +
	    KW_NAME_SIZE(MSG_MAPKW_INTERPOSE) +
	    KW_NAME_SIZE(MSG_MAPKW_NODIRECT) +
	    KW_NAME_SIZE(MSG_MAPKW_NODYNSORT) +
	    KW_NAME_SIZE(MSG_MAPKW_PARENT);

	symbol_state_t	*ss = uvalue;
	int		done;
	symflag_t	*symflag;
	int		cnt = 0;
	Token		tok;
	ld_map_tkval_t	tkv;
	Conv_inv_buf_t	inv_buf;
	Ofl_desc	*ofl = mf->mf_ofl;

	for (done = 0; done == 0; ) {
		switch (tok = ld_map_gettoken(mf, TK_F_KEYWORD, &tkv)) {
		case TK_ERROR:
			return (TK_ERROR);

		case TK_STRING:
			symflag = ld_map_kwfind(tkv.tkv_str, symflag_list,
			    SGSOFFSETOF(symflag_t, name), sizeof (symflag[0]));
			if (symflag == NULL)
				goto bad_flag;
			cnt++;
			/*
			 * Apply the flag:
			 *
			 * Although tempting to make all of this table-driven
			 * via added fields in symflag_t, there's enough
			 * variation in what each flag does to make that
			 * not quite worthwhile.
			 *
			 * Similarly, it is tempting to use common code to
			 * to do this work from map_support.c. However, the
			 * v1 code mixes unrelated things (flags, symbol types,
			 * value, size, etc) in single cascading series of
			 * strcmps, whereas our parsing separates those things
			 * from each other. Merging the code would require doing
			 * two strcmps for each item, or other complexity,
			 * which I judge not to be worthwhile.
			 */
			switch (symflag->value) {
			case FLG_SY_DIR:
				ss->ss_ms.ms_sdflags |= FLG_SY_DIR;
				ofl->ofl_flags |= FLG_OF_SYMINFO;
				break;
			case FLG_SY_DYNSORT:
				ss->ss_ms.ms_sdflags |= FLG_SY_DYNSORT;
				ss->ss_ms.ms_sdflags &= ~FLG_SY_NODYNSORT;
				break;
			case FLG_SY_EXTERN:
				ss->ss_ms.ms_sdflags |= FLG_SY_EXTERN;
				ofl->ofl_flags |= FLG_OF_SYMINFO;
				break;
			case FLG_SY_INTPOSE:
				if (!(ofl->ofl_flags & FLG_OF_EXEC)) {
					mf_fatal0(mf,
					    MSG_INTL(MSG_MAP_NOINTPOSE));
					ss->ss_mv.mv_errcnt++;
					break;
				}
				ss->ss_ms.ms_sdflags |= FLG_SY_INTPOSE;
				ofl->ofl_flags |= FLG_OF_SYMINFO;
				ofl->ofl_dtflags_1 |= DF_1_SYMINTPOSE;
				break;
			case FLG_SY_NDIR:
				ss->ss_ms.ms_sdflags |= FLG_SY_NDIR;
				ofl->ofl_flags |= FLG_OF_SYMINFO;
				ofl->ofl_flags1 |=
				    (FLG_OF1_NDIRECT | FLG_OF1_NGLBDIR);
				break;
			case FLG_SY_NODYNSORT:
				ss->ss_ms.ms_sdflags &= ~FLG_SY_DYNSORT;
				ss->ss_ms.ms_sdflags |= FLG_SY_NODYNSORT;
				break;
			case FLG_SY_PARENT:
				ss->ss_ms.ms_sdflags |= FLG_SY_PARENT;
				ofl->ofl_flags |= FLG_OF_SYMINFO;
				break;
			}
			break;
		case TK_RIGHTBKT:
		case TK_SEMICOLON:
			done = 1;
			break;

		default:
		bad_flag:
			{
				char buf[VLA_SIZE(symflag_list_bufsize)];

				mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SYMFLAG),
				    ld_map_kwnames(symflag_list,
				    SGSOFFSETOF(symflag_t, name),
				    sizeof (symflag[0]), buf,
				    symflag_list_bufsize),
				    ld_map_tokenstr(tok, &tkv, &inv_buf));
			}
			return (TK_ERROR);
		}
	}

	/* Make sure there was at least one flag specified */
	if (cnt == 0) {
		mf_fatal(mf, MSG_INTL(MSG_MAP_NOVALUES),
		    MSG_ORIG(MSG_MAPKW_FLAGS));
		return (TK_ERROR);
	}

	return (tok);		/* Either TK_SEMICOLON or TK_RIGHTBKT */
}

/*
 * SYMBOL [version_name] { symbol_name { SIZE = value
 * --------------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_sym_size(Mapfile *mf, Token eq_tok, void *uvalue)
{
	symbol_state_t	*ss = uvalue;
	ld_map_tkval_t	tkv;

	/* value */
	if (gettoken_int(mf, MSG_ORIG(MSG_MAPKW_SIZE), &tkv) == TK_ERROR)
		return (TK_ERROR);

	ss->ss_ms.ms_size = tkv.tkv_int.tkvi_value;

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_SIZE)));
}

typedef struct {
	const char	*name;		/* type name */
	Word		ms_shndx;	/* symbol section index */
	uchar_t		ms_type;	/* STT_ symbol type */
} at_sym_type_t;

static at_sym_type_t at_sym_type_list[] = {
	{ MSG_ORIG(MSG_MAPKW_COMMON),	SHN_COMMON,	STT_OBJECT },
	{ MSG_ORIG(MSG_MAPKW_DATA),	SHN_ABS,	STT_OBJECT },
	{ MSG_ORIG(MSG_MAPKW_FUNCTION),	SHN_ABS,	STT_FUNC },

	/* List must be null terminated */
	{ 0 }
};

/*
 * Size of buffer needed to format the names in at_sym_type_list[]. Must
 * be kept in sync with at_sym_type_list.
 */
static size_t	at_sym_type_list_bufsize =
    KW_NAME_SIZE(MSG_MAPKW_COMMON) +
    KW_NAME_SIZE(MSG_MAPKW_DATA) +
    KW_NAME_SIZE(MSG_MAPKW_FUNCTION);

/*
 * at_sym_type(): Value for TYPE= is not a symbol type
 */
static void
gts_efunc_at_sym_type(Mapfile *mf, Token tok, ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;
	char		buf[VLA_SIZE(at_sym_type_list_bufsize)];

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SYMTYPE),
	    ld_map_kwnames(at_sym_type_list, SGSOFFSETOF(at_sym_type_t, name),
	    sizeof (at_sym_type_list[0]), buf, at_sym_type_list_bufsize),
	    ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * SYMBOL [version_name] { symbol_name { TYPE = symbol_type
 * --------------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_sym_type(Mapfile *mf, Token eq_tok, void *uvalue)
{
	symbol_state_t	*ss = uvalue;
	at_sym_type_t	*type;
	ld_map_tkval_t	tkv;

	/* type keyword */
	if (gettoken_str(mf, TK_F_KEYWORD, &tkv, gts_efunc_at_sym_type) ==
	    TK_ERROR)
		return (TK_ERROR);

	type = ld_map_kwfind(tkv.tkv_str, at_sym_type_list,
	    SGSOFFSETOF(at_sym_type_t, name), sizeof (type[0]));
	if (type == NULL) {
		gts_efunc_at_sym_type(mf, TK_STRING, &tkv);
		return (TK_ERROR);
	}

	ss->ss_ms.ms_shndx = type->ms_shndx;
	ss->ss_ms.ms_sdflags |= FLG_SY_SPECSEC;
	ss->ss_ms.ms_type = type->ms_type;

	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_TYPE)));
}

/*
 * SYMBOL [version_name] { symbol_name { VALUE = value
 * ---------------------------------------------^
 */
/* ARGSUSED 1 */
static Token
at_sym_value(Mapfile *mf, Token eq_tok, void *uvalue)
{
	symbol_state_t	*ss = uvalue;
	ld_map_tkval_t	tkv;

	/* value */
	if (gettoken_int(mf, MSG_ORIG(MSG_MAPKW_VALUE), &tkv) == TK_ERROR)
		return (TK_ERROR);

	ss->ss_ms.ms_value = tkv.tkv_int.tkvi_value;
	ss->ss_ms.ms_value_set = TRUE;


	/* terminator */
	return (gettoken_term(mf, MSG_ORIG(MSG_MAPKW_VALUE)));
}

/*
 * Parse the attributes for a SCOPE or VERSION symbol directive.
 *
 * entry:
 *	mf - Mapfile descriptor
 *	dir_name - Name of directive.
 *	ss - Pointer to symbol state block that has had its ss_nv
 *		member initialzed via a call to ld_map_sym_ver_init().
 *
 * exit:
 *	parse_symbol_attributes() returns TK_RIGHTBKT on success, and TK_ERROR
 *	on failure.
 */
static Token
parse_symbol_attributes(Mapfile *mf, const char *dir_name, symbol_state_t *ss)
{
	/* Symbol attributes */
	static attr_t attr_list[] = {
		{ MSG_ORIG(MSG_MAPKW_AUX),	at_sym_aux,	ATTR_FMT_EQ },
		{ MSG_ORIG(MSG_MAPKW_FILTER),	at_sym_filter,	ATTR_FMT_EQ },
		{ MSG_ORIG(MSG_MAPKW_FLAGS),	at_sym_flags,	ATTR_FMT_EQ },
		{ MSG_ORIG(MSG_MAPKW_SIZE),	at_sym_size,	ATTR_FMT_EQ },
		{ MSG_ORIG(MSG_MAPKW_TYPE),	at_sym_type,	ATTR_FMT_EQ },
		{ MSG_ORIG(MSG_MAPKW_VALUE),	at_sym_value,	ATTR_FMT_EQ },

		/* List must be null terminated */
		{ 0 }
	};

	/*
	 * Size of buffer needed to format the names in attr_list[]. Must
	 * be kept in sync with attr_list.
	 */
	static size_t	attr_list_bufsize =
	    KW_NAME_SIZE(MSG_MAPKW_AUX) +
	    KW_NAME_SIZE(MSG_MAPKW_FILTER) +
	    KW_NAME_SIZE(MSG_MAPKW_FLAGS) +
	    KW_NAME_SIZE(MSG_MAPKW_SIZE) +
	    KW_NAME_SIZE(MSG_MAPKW_TYPE) +
	    KW_NAME_SIZE(MSG_MAPKW_VALUE);

	Token		tok;
	ld_map_tkval_t	tkv, tkv_sym;
	int		done;
	Conv_inv_buf_t	inv_buf;

	/* Read attributes until the closing '}' is seen */
	for (done = 0; done == 0; ) {
		/*
		 * We have to allow quotes around symbol names, but the
		 * name we read may also be a symbol scope keyword. We won't
		 * know which until we read the following token, and so have
		 * to allow quotes for both. Hence, symbol scope names can
		 * be quoted --- an unlikely occurrence and not worth
		 * complicating the code.
		 */
		switch (tok = ld_map_gettoken(mf, 0, &tkv_sym)) {
		case TK_ERROR:
			return (TK_ERROR);

		case TK_STRING:
			/* Default value for all symbol attributes is 0 */
			(void) memset(&ss->ss_ms, 0, sizeof (ss->ss_ms));
			ss->ss_ms.ms_name = tkv_sym.tkv_str;

			/*
			 * Turn off the WEAK flag to indicate that definitions
			 * are associated with this version. It would probably
			 * be more accurate to only remove this flag with the
			 * specification of global symbols, however setting it
			 * here allows enough slop to compensate for the
			 * various user inputs we've seen so far. Only if a
			 * closed version is specified (i.e., "SUNW_1.x {};")
			 * will a user get a weak version (which is how we
			 * document the creation of weak versions).
			 */
			ss->ss_mv.mv_vdp->vd_flags &= ~VER_FLG_WEAK;

			/*
			 * The meaning of this name depends on the following
			 * character:
			 *
			 *	:	Scope
			 *	;	Symbol without attributes
			 *	{	Symbol with attributes
			 */
			switch (tok = ld_map_gettoken(mf, 0, &tkv)) {
			case TK_ERROR:
				return (TK_ERROR);

			case TK_COLON:
				ld_map_sym_scope(mf, tkv_sym.tkv_str,
				    &ss->ss_mv);
				break;
			case TK_LEFTBKT:
				/* name is a symbol with attributes */
				if (parse_attributes(mf, tkv_sym.tkv_str,
				    attr_list, attr_list_bufsize, ss) ==
				    TK_ERROR)
					return (TK_ERROR);
				/* Terminating ';', or '}' */
				tok = gettoken_term(mf,
				    MSG_INTL(MSG_MAP_SYMATTR));
				if (tok == TK_ERROR)
					return (TK_ERROR);
				if (tok == TK_RIGHTBKT)
					done = 1;

				/* FALLTHROUGH */
			case TK_SEMICOLON:
				/*
				 * Add the new symbol. It should be noted that
				 * all symbols added by the mapfile start out
				 * with global scope, thus they will fall
				 * through the normal symbol resolution
				 * process.  Symbols defined as locals will
				 * be reduced in scope after all input file
				 * processing.
				 */
				if (!ld_map_sym_enter(mf, &ss->ss_mv,
				    &ss->ss_ms))
					return (TK_ERROR);
				break;
			default:
				mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SYMDELIM),
				    ld_map_tokenstr(tok, &tkv, &inv_buf));
				return (TK_ERROR);
			}
			break;

		case TK_RIGHTBKT:
			done = 1;
			break;

		case TK_SEMICOLON:
			break;		/* Ignore empty statement */

		case TK_STAR:
			/*
			 * Turn off the WEAK flag, as explained above for
			 * TK_STRING.
			 */
			ss->ss_mv.mv_vdp->vd_flags &= ~VER_FLG_WEAK;

			ld_map_sym_autoreduce(mf, &ss->ss_mv);

			/*
			 * Following token must be ';' to terminate the stmt,
			 * or '}' to terminate the whole directive.
			 */
			switch (tok = gettoken_term(mf, dir_name)) {
			case TK_ERROR:
				return (TK_ERROR);
			case TK_RIGHTBKT:
				done = 1;
				break;
			}
			break;

		default:
			mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_SYM),
			    ld_map_tokenstr(tok, &tkv_sym, &inv_buf));
			return (TK_ERROR);
		}
	}

	/*
	 * In the SYMBOL directive, we keep parsing in the face of
	 * errors that don't involve resources, to maximize what we
	 * can report in a single invocation. If we encountered such
	 * an error, act on the error(s) now.
	 */
	if (ss->ss_mv.mv_errcnt)
		return (TK_ERROR);

	return (tok);
}


/*
 * Top Level Directive:
 *
 * SYMBOL_SCOPE { ...
 * ------------^
 */
static Token
dir_symbol_scope(Mapfile *mf)
{
	symbol_state_t	ss;

	/* The first token must be a '{' */
	if (gettoken_leftbkt(mf, MSG_ORIG(MSG_MAPKW_SYMBOL_SCOPE)) == TK_ERROR)
		return (TK_ERROR);

	/* Establish the version descriptor and related data */
	if (!ld_map_sym_ver_init(mf, NULL, &ss.ss_mv))
		return (TK_ERROR);

	/* Read attributes until the closing '}' is seen */
	if (parse_symbol_attributes(mf, MSG_ORIG(MSG_MAPKW_SYMBOL_SCOPE),
	    &ss) == TK_ERROR)
		return (TK_ERROR);

	/* Terminating ';' */
	return (gettoken_semicolon(mf, MSG_ORIG(MSG_MAPKW_SYMBOL_SCOPE)));
}


/*
 * at_dv_allow(): Value for ALLOW= is not a version string
 */
static void
gts_efunc_dir_symbol_version(Mapfile *mf, Token tok, ld_map_tkval_t *tkv)
{
	Conv_inv_buf_t	inv_buf;

	mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_VERSION),
	    MSG_ORIG(MSG_MAPKW_SYMBOL_VERSION),
	    ld_map_tokenstr(tok, tkv, &inv_buf));
}

/*
 * Top Level Directive:
 *
 * SYMBOL_VERSION version_name { ...
 * --------------^
 */
static Token
dir_symbol_version(Mapfile *mf)
{

	ld_map_tkval_t	tkv;
	symbol_state_t	ss;

	/* The first token must be a version name */
	if (gettoken_str(mf, 0, &tkv, gts_efunc_dir_symbol_version) == TK_ERROR)
		return (TK_ERROR);

	/* The next token is expected to be '{' */
	if (gettoken_leftbkt(mf, MSG_ORIG(MSG_MAPKW_SYMBOL_VERSION)) ==
	    TK_ERROR)
		return (TK_ERROR);

	/* Establish the version descriptor and related data */
	if (!ld_map_sym_ver_init(mf, tkv.tkv_str, &ss.ss_mv))
		return (TK_ERROR);

	/* Read attributes until the closing '}' is seen */
	if (parse_symbol_attributes(mf, MSG_ORIG(MSG_MAPKW_SYMBOL_VERSION),
	    &ss) == TK_ERROR)
		return (TK_ERROR);

	/*
	 * Determine if any version references are provided after the close
	 * bracket, parsing up to the terminating ';'.
	 */
	if (!ld_map_sym_ver_fini(mf, &ss.ss_mv))
		return (TK_ERROR);

	return (TK_SEMICOLON);
}


/*
 * Parse the mapfile --- Solaris syntax
 */
Boolean
ld_map_parse_v2(Mapfile *mf)
{
	/* Valid top level mapfile directives */
	typedef struct {
		const char	*name;	/* Directive */
		dir_func_t	func;	/* Function to parse directive */
	} tldir_t;


	tldir_t dirlist[] = {
		{ MSG_ORIG(MSG_MAPKW_CAPABILITY),	dir_capability },
		{ MSG_ORIG(MSG_MAPKW_DEPEND_VERSIONS),	dir_depend_versions },
		{ MSG_ORIG(MSG_MAPKW_HDR_NOALLOC),	dir_hdr_noalloc },
		{ MSG_ORIG(MSG_MAPKW_LOAD_SEGMENT),	dir_load_segment },
		{ MSG_ORIG(MSG_MAPKW_NOTE_SEGMENT),	dir_note_segment },
		{ MSG_ORIG(MSG_MAPKW_NULL_SEGMENT),	dir_null_segment },
		{ MSG_ORIG(MSG_MAPKW_PHDR_ADD_NULL),	dir_phdr_add_null },
		{ MSG_ORIG(MSG_MAPKW_SEGMENT_ORDER),	dir_segment_order },
		{ MSG_ORIG(MSG_MAPKW_STACK),		dir_stack },
		{ MSG_ORIG(MSG_MAPKW_SYMBOL_SCOPE),	dir_symbol_scope },
		{ MSG_ORIG(MSG_MAPKW_SYMBOL_VERSION),	dir_symbol_version },

		/* List must be null terminated */
		{ 0 }
	};

	/*
	 * Size of buffer needed to format the names in dirlist[]. Must
	 * be kept in sync with dirlist.
	 */
	static size_t dirlist_bufsize =
	    KW_NAME_SIZE(MSG_MAPKW_CAPABILITY) +
	    KW_NAME_SIZE(MSG_MAPKW_DEPEND_VERSIONS) +
	    KW_NAME_SIZE(MSG_MAPKW_HDR_NOALLOC) +
	    KW_NAME_SIZE(MSG_MAPKW_LOAD_SEGMENT) +
	    KW_NAME_SIZE(MSG_MAPKW_NOTE_SEGMENT) +
	    KW_NAME_SIZE(MSG_MAPKW_NULL_SEGMENT) +
	    KW_NAME_SIZE(MSG_MAPKW_PHDR_ADD_NULL) +
	    KW_NAME_SIZE(MSG_MAPKW_SEGMENT_ORDER) +
	    KW_NAME_SIZE(MSG_MAPKW_STACK) +
	    KW_NAME_SIZE(MSG_MAPKW_SYMBOL_SCOPE) +
	    KW_NAME_SIZE(MSG_MAPKW_SYMBOL_VERSION);

	Token		tok;		/* current token. */
	ld_map_tkval_t	tkv;		/* Value of token */
	tldir_t		*tldir;
	Conv_inv_buf_t	inv_buf;

	for (;;) {
		tok = ld_map_gettoken(mf, TK_F_EOFOK | TK_F_KEYWORD, &tkv);
		switch (tok) {
		case TK_ERROR:
			return (FALSE);
		case TK_EOF:
			return (TRUE);
		case TK_SEMICOLON: /* Terminator, or empty directive: Ignore */
			break;
		case TK_STRING:
			/* Map name to entry in dirlist[] */
			tldir = ld_map_kwfind(tkv.tkv_str, dirlist,
			    SGSOFFSETOF(tldir_t, name), sizeof (dirlist[0]));

			/* Not a directive we know? */
			if (tldir == NULL)
				goto bad_dirtok;

			/* Call the function associated with this directive */
			if (tldir->func(mf) == TK_ERROR)
				return (FALSE);
			break;
		default:
		bad_dirtok:
			{
				char buf[VLA_SIZE(dirlist_bufsize)];

				mf_fatal(mf, MSG_INTL(MSG_MAP_EXP_DIR),
				    ld_map_kwnames(dirlist,
				    SGSOFFSETOF(tldir_t, name),
				    sizeof (dirlist[0]), buf, dirlist_bufsize),
				    ld_map_tokenstr(tok, &tkv, &inv_buf));
			}
			return (FALSE);
		}
	}
}
