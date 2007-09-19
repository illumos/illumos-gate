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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdlib.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<libintl.h>
#include	<libelf.h>
#include	<sys/machelf.h>
#include	<link.h>
#include	<strings.h>
#include	<ctype.h>
#include	<elfedit.h>
#include	<_elfedit.h>
#include	<sys/elf_SPARC.h>
#include	<sys/elf_amd64.h>
#include	<msg.h>



/*
 * This file contains utility functions that are of general use
 * to different elfedit modules for solving common problems.
 * The functions in this file are not ELFCLASS specific. Those
 * functions are found in util_machelf.c
 *
 * NOTE: This module contains functions with names
 * elfedit_atoi, and elfedit_atoui, that are otherwise identical.
 * These functions are for signed, and unsigned integers, respectively.
 * In general, I supply one comment header for each such pair,
 * and put their implementations together.
 *
 * There are also functions with names elfedit_atoconst. These are
 * convenience wrappers that use the corresponding elfedit_atoui()
 * function to process an array of symbolic names provided by a call
 * elfedit_const_to_atoui().
 */




/*
 * Given a value and an array of elfedit_ato[u]i items, return a pointer
 * to the symbolic name for the value.
 *
 * entry:
 *	sym - NULL terminated array of name->value mappings.
 *	value - Value to be found
 *	required - If True, and value is not found, an error is issued.
 *		Callers should only set required to True when they know
 *		a priori that the value will be found --- the error
 *		is reported as an internal programming error.
 *
 * exit:
 *	If the array contains an entry with the given value, the
 *	name for the first such entry will be returned.
 *
 *	If no entry is found: If required is True (1), an error is
 *	issued and this routine does not return to the caller. If required
 *	is False (0), then NULL is returned.
 */
const char *
elfedit_atoi_value_to_str(const elfedit_atoi_sym_t *sym, elfedit_atoi_t value,
    int required)
{
	for (; sym->sym_name != NULL; sym++)
		if (value == sym->sym_value)
			return (sym->sym_name);

	/* Value did not match any of the entries */
	if (required)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_BADGETVAL));
	return (NULL);
}
const char *
elfedit_atoui_value_to_str(const elfedit_atoui_sym_t *sym,
    elfedit_atoui_t value, int required)
{
	for (; sym->sym_name != NULL; sym++)
		if (value == sym->sym_value)
			return (sym->sym_name);

	/* Value did not match any of the entries */
	if (required)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_BADGETVAL));
	return (NULL);
}
const char *
elfedit_atoconst_value_to_str(elfedit_const_t const_type, elfedit_atoui_t value,
    int required)
{
	return (elfedit_atoui_value_to_str(elfedit_const_to_atoui(const_type),
	    value, required));
}


/*
 * Process the symbolic name to value mappings passed to the
 * atoi and atoui  functions.
 *
 * entry:
 *	sym - NULL terminated array of name->value mappings.
 *	value - Address of variable to recieve corresponding value.
 *
 * exit:
 *	If a mapping is found, *value is set to it, and True is returned.
 *	Otherwise False is returned.
 */
static int
atoi_sym_process(const char *str, const elfedit_atoi_sym_t *sym,
    elfedit_atoi_t *value)
{
	size_t		cmp_len;
	const char	*tail;

	while (isspace(*str))
		str++;

	tail = str + strlen(str);
	while ((tail > str) && isspace(*(tail - 1)))
		tail--;

	cmp_len = tail - str;

	for (; sym->sym_name != NULL; sym++) {
		if ((strlen(sym->sym_name) == cmp_len) &&
		    (strncasecmp(sym->sym_name, str, cmp_len) == 0)) {
			*value = sym->sym_value;
			return (1);
		}
	}

	/* No symbolic mapping was found */
	return (0);
}
static int
atoui_sym_process(const char *str, const elfedit_atoui_sym_t *sym,
    elfedit_atoui_t *value)
{
	size_t		cmp_len;
	const char	*tail;

	while (isspace(*str))
		str++;

	tail = str + strlen(str);
	while ((tail > str) && isspace(*(tail - 1)))
		tail--;

	cmp_len = tail - str;

	for (; sym->sym_name != NULL; sym++) {
		if ((strlen(sym->sym_name) == cmp_len) &&
		    (strncasecmp(sym->sym_name, str, cmp_len) == 0)) {
			*value = sym->sym_value;
			return (1);
		}
	}

	/* No symbolic mapping was found */
	return (0);
}



/*
 * A command completion function for atoi and atoui mappings.
 */
void
elfedit_cpl_atoi(void *cpldata, const elfedit_atoi_sym_t *sym)
{
	for (; sym->sym_name != NULL; sym++)
		elfedit_cpl_match(cpldata, sym->sym_name, 1);
}
void
elfedit_cpl_atoui(void *cpldata, const elfedit_atoui_sym_t *sym)
{
	for (; sym->sym_name != NULL; sym++)
		elfedit_cpl_match(cpldata, sym->sym_name, 1);
}
void
elfedit_cpl_atoconst(void *cpldata, elfedit_const_t const_type)
{
	elfedit_cpl_atoui(cpldata, elfedit_const_to_atoui(const_type));
}





/*
 * Convert a string to a numeric value. Strings starting with '0'
 * are taken to be octal, those staring with '0x' are hex, and all
 * others are decimal.
 *
 * entry:
 *	str - String to be converted
 *	sym - NULL, or NULL terminated array of name/value pairs.
 *
 *	[elfedit_atoi2() and elfedit_atoui2() only]
 *	v - Address of variable to receive resulting value.
 *
 * exit:
 *	elfedit_atoi2() and elfedit_atoui2():
 *		On success, returns True (1) and *v is set to the value.
 *		On failure, returns False (0) and *v is undefined.
 *
 *	elfedit_atoi() and elfedit_atoui():
 *		If the string is convertable, the value is returned.
 *		Otherwise an error is issued and this routine does
 *		not return to the caller.
 */
int
elfedit_atoi2(const char *str, const elfedit_atoi_sym_t *sym, elfedit_atoi_t *v)
{
	char		*endptr;

	if (sym && atoi_sym_process(str, sym, v))
		return (1);

	*v = strtoll(str, &endptr, 0);

	/* If the left over part contains anything but whitespace, fail */
	for (; *endptr; endptr++)
		if (!isspace(*endptr))
			return (0);
	return (1);
}
elfedit_atoi_t
elfedit_atoi(const char *str, const elfedit_atoi_sym_t *sym)
{
	elfedit_atoi_t v;
	if (elfedit_atoi2(str, sym, &v) == 0)
		elfedit_msg(ELFEDIT_MSG_ERR,
		    MSG_INTL(MSG_ERR_BADATOISTR), str);
	return (v);
}
int
elfedit_atoui2(const char *str, const elfedit_atoui_sym_t *sym,
    elfedit_atoui_t *v)
{
	char		*endptr;

	if (sym && atoui_sym_process(str, sym, v))
		return (1);

	*v = strtoull(str, &endptr, 0);

	/* If the left over part contains anything but whitespace, fail */
	for (; *endptr; endptr++)
		if (!isspace(*endptr))
			return (0);
	return (1);
}
elfedit_atoui_t
elfedit_atoui(const char *str, const elfedit_atoui_sym_t *sym)
{
	elfedit_atoui_t v;
	if (elfedit_atoui2(str, sym, &v) == 0)
		elfedit_msg(ELFEDIT_MSG_ERR,
		    MSG_INTL(MSG_ERR_BADATOISTR), str);
	return (v);
}
int
elfedit_atoconst2(const char *str, elfedit_const_t const_type,
    elfedit_atoui_t *v)
{
	return (elfedit_atoui2(str, elfedit_const_to_atoui(const_type), v));
}
elfedit_atoui_t
elfedit_atoconst(const char *str, elfedit_const_t const_type)
{
	return (elfedit_atoui(str, elfedit_const_to_atoui(const_type)));
}

/*
 * Convert a string to a numeric value using elfedit_ato[u]i and
 * ensure that the resulting value lies within a given range.
 * elfedit_ato[u]i_range() requires values to be in the range
 * (min <= value <= max).
 *
 * entry:
 *	str - String to be converted
 *	min, max - If check_range is true, the allowed range that the
 *		resulting value must lie in.
 *	sym - NULL, or NULL terminated array of name/value pairs.
 *
 * entry [elfedit_atoi_range() and elfedit_atoui_range() only]:
 *	item_name - String describing item for which value is being read.
 *
 * entry [elfedit_atoi_range2() and elfedit_atoui_range2() only]:
 *	v - Address of variable to receive resulting value.
 *
 * exit:
 *	elfedit_atoi_range2() and elfedit_atoui_range2():
 *		On success, returns True (1) and *v is set to the value.
 *		On failure, returns False (0) and *v is undefined.
 *
 *	elfedit_atoi_range() and elfedit_atoui_range():
 *		If the string is convertable, the value is returned.
 *		Otherwise an error is issued and this routine does
 *		not return to the caller.
 */
int
elfedit_atoi_range2(const char *str, elfedit_atoi_t min, elfedit_atoi_t max,
    const elfedit_atoi_sym_t *sym, elfedit_atoi_t *v)
{
	return ((elfedit_atoi2(str, sym, v) != 0) &&
	    (*v >= min) && (*v <= max));
}
elfedit_atoi_t
elfedit_atoi_range(const char *str, const char *item_name,
    elfedit_atoi_t min, elfedit_atoi_t max, const elfedit_atoi_sym_t *sym)
{
	elfedit_atoi_t v = elfedit_atoi(str, sym);

	if ((v < min) || (v > max))
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_ATOIRANGE),
		    item_name, EC_XWORD(min), EC_XWORD(max), EC_XWORD(v));

	return (v);
}
int
elfedit_atoui_range2(const char *str, elfedit_atoui_t min, elfedit_atoui_t max,
    const elfedit_atoui_sym_t *sym, elfedit_atoui_t *v)
{
	return ((elfedit_atoui2(str, sym, v) != 0) &&
	    (*v >= min) && (*v <= max));
}
elfedit_atoui_t
elfedit_atoui_range(const char *str, const char *item_name,
    elfedit_atoui_t min, elfedit_atoui_t max, const elfedit_atoui_sym_t *sym)
{
	elfedit_atoui_t v = elfedit_atoui(str, sym);

	if ((v < min) || (v > max))
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_ATOUIRANGE),
		    item_name, EC_XWORD(min), EC_XWORD(max), EC_XWORD(v));

	return (v);
}
int
elfedit_atoconst_range2(const char *str, elfedit_atoui_t min,
    elfedit_atoui_t max, elfedit_const_t const_type, elfedit_atoui_t *v)
{
	return (elfedit_atoui_range2(str, min, max,
	    elfedit_const_to_atoui(const_type), v));
}
elfedit_atoui_t
elfedit_atoconst_range(const char *str, const char *item_name,
    elfedit_atoui_t min, elfedit_atoui_t max, elfedit_const_t const_type)
{
	return (elfedit_atoui_range(str, item_name, min, max,
	    elfedit_const_to_atoui(const_type)));
}


/*
 * Convenience wrapper on elfedit_atoui_range() that expects to see
 * boolean values. Returns 1 for true, and 0 for false.
 */
int
elfedit_atobool(const char *str, const char *item_name)
{

	return (elfedit_atoconst_range(str, item_name, 0, 1,
	    ELFEDIT_CONST_BOOL) != 0);
}



/*
 * Convenience wrapper on elfedit_atoui() to read a section index
 * that understands the special SHN_ names.
 *
 * entry:
 *	str - String to process
 *	shnum - Number of sections in the ELF file
 *
 * exit:
 *	If it is possible to convert str to a number, that value
 *	is returned. If the value is out of range for the file,
 *	a warning message to that effect is issued. On failure,
 *	an error is issued and this routine does not return to
 *	the caller.
 */
elfedit_atoui_t
elfedit_atoshndx(const char *str, size_t shnum)
{
	elfedit_atoui_t ndx;

	ndx = elfedit_atoconst(str, ELFEDIT_CONST_SHN);
	if ((ndx >= shnum) && ((ndx < SHN_LORESERVE) || (ndx > SHN_HIRESERVE)))
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_SHNDX_RANGE),
		    EC_WORD(ndx), EC_WORD(shnum-1));

	return (ndx);
}



/*
 * Convert an output style string into it's integer constant. This
 * routine reports success/failure via the return value rather than
 * by throwing errors so that it can be used to process command
 * line options at program startup, before
 * the elfedit framework is initialized.
 */
int
elfedit_atooutstyle(const char *str, elfedit_outstyle_t *outstyle)
{
	int		ret;
	elfedit_atoui_t	value;

	ret = atoui_sym_process(str,
	    elfedit_const_to_atoui(ELFEDIT_CONST_OUTSTYLE), &value);
	if (ret != 0)
		*outstyle = value;
	return (ret);
}




/*
 * Initialize a state block for processing by elfedit_getopt().
 *
 * entry:
 *	state - State block to initialize
 *	cmd_name - NULL, or name of command for which we are processing
 *		options.
 *	argc, argv - Address of variables giving number of options and
 *		access to the option strings.
 *
 * note:
 *	cmd_name can only be set to NULL when this routine is called
 *	by, or below, a currently active command. Otherwise, results
 *	are undefined (crashing or corruption) if there isn't one.
 */
void
elfedit_getopt_init(elfedit_getopt_state_t *state,
    int *argc, const char **argv[])
{
	elfeditGC_cmd_t *cmd = elfedit_curcmd();

	state->go_argc = argc;
	state->go_argv = argv;
	state->go_optarg = cmd->cmd_opt;
	state->go_idmask = 0;
	state->go_done = 0;
	state->go_sglgrp = NULL;
}



/*
 * elfedit-centric version of getopt()
 *
 * entry:
 *	state - Getopt state, which must have been previously initialized
 *		via a call to elfedit_getopt_init.
 *
 * exit:
 *	If an option is matched, this routine returns a pointer to an
 *	elfedit_getopt_ret_t buffer (which comes from the storage used
 *	for state). If there are no more options to process, NULL is returned.
 *
 *	Syntax errors are reported via elfedit_command_usage(), and this
 *	routine does not return to the caller.
 *
 * note:
 *	- The caller should not access the contents of state directly.
 *		Those contents are private, and subject to change.
 *	- Once a call to this routine returns NULL, the argc/argv have
 *		have been ajusted so that they reference the plain arguments.
 */
elfedit_getopt_ret_t *
elfedit_getopt(elfedit_getopt_state_t *state)
{
	elfedit_cmd_optarg_t	*optarg;
	const char		*argstr;
	int			argc = *(state->go_argc);
	const char		**argv = *(state->go_argv);
	elfedit_optarg_item_t	item;
	struct {
		int			valid;
		int			is_outstyle;
		elfedit_getopt_ret_t	ret;
		elfedit_cmd_oa_mask_t	excmask;
	} sgl_with_value;

	if (state->go_sglgrp == NULL) {
		/*
		 * Reasons to bail out immediately:
		 *	- The command does not accept options
		 *	- We've already reported the final option.
		 *	- There are no more arguments.
		 *	- The next argument does not start with '-'
		 */
		if ((state->go_optarg == NULL) || state->go_done ||
		    (argc <= 0) || (*(argv[0]) != '-')) {
			state->go_done = 1;
			return (NULL);
		}

		argstr = argv[0];

		/* A '-' by itself is a syntax error */
		if (argstr[1] == '\0')
			elfedit_command_usage();

		/* A '--' option means we should stop at this point */
		if ((argstr[1] == '-') && (argstr[2] == '\0')) {
			(*state->go_argc)--;
			(*state->go_argv)++;
			return (NULL);
		}

		/*
		 * We have a string that starts with a '-'.
		 * Does it match an option?
		 */
		sgl_with_value.valid = 0;
		for (optarg = state->go_optarg; optarg->oa_name != NULL; ) {
			int is_outstyle =
			    (optarg->oa_flags & ELFEDIT_CMDOA_F_INHERIT) &&
			    (optarg->oa_name == ELFEDIT_STDOA_OPT_O);
			int need_value;

			elfedit_next_optarg(&optarg, &item);
			need_value = item.oai_flags & ELFEDIT_CMDOA_F_VALUE;

			/*
			 * If the option is a single letter that accepts
			 * a value, then we allow the combined syntax
			 * -ovalue, where no space is reqired between the
			 * option flag and the value string.
			 */
			if ((item.oai_name[2] == '\0') && need_value &&
			    (argstr[1] == item.oai_name[1]) &&
			    (argstr[2] != '\0')) {
				/*
				 * We have a match. However, there may also
				 * be a straightforward match that we have
				 * not yet found. If so, we want to prefer that
				 * case over this one. So rather than return
				 * it immediately, we capture the information
				 * and keep looking. If nothing else surfaces,
				 * we'll use this later.
				 */
				sgl_with_value.valid = 1;
				sgl_with_value.ret.gor_idmask = item.oai_idmask;
				sgl_with_value.excmask = item.oai_excmask;
				sgl_with_value.ret.gor_value = argstr + 2;
				sgl_with_value.is_outstyle = is_outstyle;
				continue;
			}

			/* Try for a straightforward match */
			if (strcmp(argstr, item.oai_name) == 0) {
				(*state->go_argc) = --argc;
				(*state->go_argv) = ++argv;

				/* Mutually exclusive option already seen? */
				if (item.oai_excmask & state->go_idmask)
					elfedit_command_usage();

				/* Return the match */
				state->go_idmask |= item.oai_idmask;
				state->go_ret.gor_idmask = item.oai_idmask;
				if (need_value) {
					    /* If out of args, syntax error */
					if (argc <= 0)
						elfedit_command_usage();
					state->go_ret.gor_value = argv[0];
					(*state->go_argc)--;
					(*state->go_argv)++;
				} else {
					state->go_ret.gor_value = NULL;
				}
				if (is_outstyle)
					elfedit_set_cmd_outstyle(
					    state->go_ret.gor_value);
				return (&state->go_ret);
			}
		}

		/*
		 * No straightforward matches: Did we get a match with
		 * the special single letter and combined value? If so
		 * return that now.
		 */
		if (sgl_with_value.valid) {
			(*state->go_argc)--;
			(*state->go_argv)++;

			/* Mutually exclusive option already seen? */
			if (sgl_with_value.excmask & state->go_idmask)
				elfedit_command_usage();

			state->go_idmask |= sgl_with_value.ret.gor_idmask;
			state->go_ret = sgl_with_value.ret;
			if (sgl_with_value.is_outstyle)
				elfedit_set_cmd_outstyle(
				    state->go_ret.gor_value);

			return (&state->go_ret);
		}

		/*
		 * If nothing above matched, make this option the single
		 * group string and see if the characters in it all match
		 * as single letter options without values.
		 */
		state->go_sglgrp = argstr + 1;	/* Skip '-' */
	}

	/*
	 * If there is a single group string, take the first character
	 * and try to match it to an 1-letter option that does not
	 * require a value.
	 */
	if (state->go_sglgrp != NULL) {
		int ch = *state->go_sglgrp++;

		/* If that is the last character, clear single group mode */
		if (*state->go_sglgrp == '\0') {
			(*state->go_argc)--;
			(*state->go_argv)++;
			state->go_sglgrp = NULL;
		}

		for (optarg = state->go_optarg; optarg->oa_name != NULL; ) {
			elfedit_next_optarg(&optarg, &item);

			if ((item.oai_name[2] == '\0') &&
			    (ch == item.oai_name[1])) {
				/*
				 * It matches. If the option requires a value
				 * then it cannot be in a group.
				 */
				if (item.oai_flags & ELFEDIT_CMDOA_F_VALUE)
					elfedit_command_usage();

				/* Mutually exclusive option already seen? */
				if (item.oai_excmask & state->go_idmask)
					elfedit_command_usage();

				/* Return the match */
				state->go_idmask |= item.oai_idmask;
				state->go_ret.gor_idmask = item.oai_idmask;
				state->go_ret.gor_value = NULL;
				return (&state->go_ret);
			}
		}
	}

	/* Nothing matched. We have a syntax error */
	elfedit_command_usage();
	/*NOTREACHED*/
	return (NULL);
}


/*
 * Return the count of non-zero bits in the value v.
 *
 * entry:
 *	v - Value to test
 *	sizeof_orig_v - The result of using the sizeof operator
 *		on the original value of v. The value received
 *		by this routine has been cast to an unsigned 64-bit
 *		integer, so having the caller use sizeof allows us to
 *		avoid testing bits that were not in the original.
 */
int
elfedit_bits_set(u_longlong_t v, int sizeof_orig_v)
{
	int	nbits = sizeof_orig_v * 8;
	int	mask;
	int	cnt = 0;

	for (mask = 1; (nbits-- > 0) && (cnt < 2); mask *= 2)
		if (v & mask)
			cnt++;

	return (cnt);
}


/*
 * "delete" items in an array by copying the following items up
 * over the "deleted" items and then zero filling the vacated
 * slots at the bottom.
 *
 * entry:
 *	name_str - Array identification prefix to use for debug message
 *	data_start - Address of 1st byte in array
 *	entsize - sizeof a single element of the array
 *	num_ent - # of elements in array
 *	start_ndx - Index of first item to be deleted
 *	cnt - # of items to delete
 *
 * exit:
 *	Any errors are issued and control does not return to the
 *	caller. On success, the items have been removed, zero filling
 *	has been done, and debug messages issued.
 */
void
elfedit_array_elts_delete(const char *name_str, void *data_start,
    size_t entsize, size_t num_ent, size_t start_ndx, size_t cnt)
{
	char	*data = data_start;

	/* The specified index and range must be in bounds */
	if ((start_ndx + cnt) > num_ent)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_ARRBNDS),
		    name_str, EC_WORD(num_ent), EC_WORD(num_ent - 1));

	/*
	 * Everything below the deleted items moves up.
	 * Note that bcopy() is documented to handle overlapping
	 * src/dst correctly, so we make no effort to handle this
	 * element by element, but issue a single operation.
	 *
	 * If we're doing the last element, there is nothing to
	 * move up, and we skip this step, moving on to the zeroing below.
	 */
	if (start_ndx < (num_ent - 1)) {
		size_t ncpy = num_ent - (start_ndx + cnt);

		bcopy(data + ((start_ndx + cnt) * entsize),
		    data + (start_ndx * entsize), ncpy * entsize);
		if (ncpy == 1) {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_ARRCPY_1), name_str,
			    EC_WORD(start_ndx + cnt), EC_WORD(start_ndx));
		} else {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_ARRCPY_N), name_str,
			    EC_WORD(start_ndx + cnt),
			    EC_WORD(start_ndx + cnt + ncpy - 1),
			    EC_WORD(start_ndx),
			    EC_WORD(start_ndx + ncpy - 1));
		}
	}

	/* Zero out the vacated elements at the end */
	bzero(data + ((num_ent - cnt) * entsize), entsize * cnt);

	if (cnt == 1) {
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_ARRZERO_1),
		    name_str, EC_WORD(num_ent - 1));
	} else {
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_ARRZERO_N),
		    name_str, EC_WORD(num_ent - cnt),
		    EC_WORD(num_ent - 1), EC_WORD(cnt));
	}
}


/*
 * move the location of items in an array by shifting the surround
 * items into the vacated hole and them putting the values into
 * the new location.
 *
 * entry:
 *	name_str - Array identification prefix to use for debug message
 *	data_start - Address of 1st byte in array
 *	entsize - sizeof a single element of the array
 *	num_ent - # of elements in array
 *	start_ndx - Index of first item to be moved
 *	dst_ndx - Index to receive the moved block
 *	cnt - # of items to move
 *	scr_item - Space allocated by the caller sufficient to hold
 *		one item from the array. Used to swap elements.
 *
 * exit:
 *	Any errors are issued and control does not return to the
 *	caller. On success, the items have been moved, and debug
 *	messages issued.
 */
void
elfedit_array_elts_move(const char *name_str, void *data_start,
    size_t entsize, size_t num_ent, size_t srcndx,
    size_t dstndx, size_t cnt, void *scr_item)
{
	char	*data = data_start;

	/* The specified source and destination ranges must be in bounds */
	if (((srcndx + cnt) > num_ent) || ((dstndx + cnt) > num_ent))
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_ARRBNDS),
		    name_str, EC_WORD(num_ent), EC_WORD(num_ent - 1));

	/* If source and destination are same, there's nothing to do */
	if (srcndx == dstndx)
		return;

	/*
	 * It is meaningless to do a move where the source and destination
	 * are overlapping, because this "move" amounts to shifting
	 * the existing items around into a new position. If there is
	 * more than one element, then overlap is possible and we need
	 * to test for it.
	 */
	if (cnt > 1) {
		size_t low, hi;

		if (srcndx > dstndx) {
			low = dstndx;
			hi = srcndx;
		} else {
			low = srcndx;
			hi = dstndx;
		}
		/* Ensure that the src and dst don't overlap */
		if ((low + cnt) > hi)
			elfedit_msg(ELFEDIT_MSG_ERR,
			    MSG_INTL(MSG_ERR_ARRMVOVERLAP), name_str,
			    EC_WORD(srcndx), EC_WORD(srcndx + cnt - 1),
			    EC_WORD(dstndx), EC_WORD(dstndx + cnt - 1));
	}

	if (cnt == 1)
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_ARRMOVE_1),
		    name_str, EC_WORD(srcndx), EC_WORD(dstndx));
	else
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_ARRMOVE_N),
		    name_str, EC_WORD(cnt),
		    EC_WORD(srcndx), EC_WORD(srcndx + cnt - 1),
		    EC_WORD(dstndx), EC_WORD(dstndx + cnt - 1));

	if (srcndx < dstndx) {
		srcndx += cnt - 1;
		dstndx += cnt - 1;
		for (; cnt-- > 0; srcndx--, dstndx--) {
			/*
			 * Copy item at srcndx to scratch location
			 *
			 *	save = dyn[srcndx];
			 */
			bcopy(data + (srcndx * entsize), scr_item, entsize);

			/*
			 * Shift items after source up through destination
			 * to source. bcopy() handles overlapped copies.
			 *
			 *	for (i = srcndx; i < dstndx; i++)
			 *		dyn[i] = dyn[i + 1];
			 */
			bcopy(data + ((srcndx + 1) * entsize),
			    data + (srcndx * entsize),
			    (dstndx - srcndx) * entsize);

			/*
			 * Copy saved item into destination slot
			 *
			 *	dyn[dstndx] = save;
			 */
			bcopy(scr_item, data + (dstndx * entsize), entsize);
		}
	} else {
		for (; cnt-- > 0; srcndx++, dstndx++) {
			/*
			 * Copy item at srcndx to scratch location
			 *
			 *	save = dyn[srcndx];
			 */
			bcopy(data + (srcndx * entsize), scr_item, entsize);

			/*
			 * Shift items from destination through item below
			 * source up one. bcopy() handles overlapped copies.
			 *
			 *	for (i = srcndx; i > dstndx; i--)
			 *		dyn[i] = dyn[i - 1];
			 */
			bcopy(data + (dstndx * entsize),
			    data + ((dstndx + 1) * entsize),
			    (srcndx - dstndx) * entsize);

			/*
			 * Copy saved item into destination slot
			 *
			 *	dyn[dstndx] = save;
			 */
			bcopy(scr_item, data + (dstndx * entsize), entsize);
		}
	}
}
