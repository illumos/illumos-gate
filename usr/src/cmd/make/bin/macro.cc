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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	macro.cc
 *
 *	Handle expansion of make macros
 */

/*
 * Included files
 */
#include <mk/defs.h>
#include <mksh/macro.h>		/* getvar(), expand_value() */
#include <mksh/misc.h>		/* getmem() */

/*
 * Defined macros
 */

/*
 * typedefs & structs
 */

/*
 * Static variables
 */

/*
 * File table of contents
 */

void
setvar_append(register Name name, register Name value)
{
	register Property	macro_apx = get_prop(name->prop, macro_append_prop);
	register Property	macro = get_prop(name->prop, macro_prop);
	int			length;
	String_rec		destination;
	wchar_t			buffer[STRING_BUFFER_LENGTH];
	register Chain		chain;
	Name			val = NULL;

	if(macro_apx == NULL) {
		macro_apx = append_prop(name, macro_append_prop);
		if(macro != NULL) {
			macro_apx->body.macro_appendix.value = macro->body.macro.value;
		}
	}

	val = macro_apx->body.macro_appendix.value_to_append;

	INIT_STRING_FROM_STACK(destination, buffer);
	buffer[0] = 0;
	if (val != NULL) {
		APPEND_NAME(val,
			      &destination,
			      (int) val->hash.length);
		if (value != NULL) {
			MBTOWC(wcs_buffer, " ");
			append_char(wcs_buffer[0], &destination);
		}
	}
	if (value != NULL) {
		APPEND_NAME(value,
			      &destination,
			      (int) value->hash.length);
	}
	value = GETNAME(destination.buffer.start, FIND_LENGTH);
	if (destination.free_after_use) {
		retmem(destination.buffer.start);
	}
	macro_apx->body.macro_appendix.value_to_append = value;

	SETVAR(name, empty_name, true);
}

/*
 *	setvar_envvar()
 *
 *	This function scans the list of environment variables that have
 *	dynamic values and sets them.
 *
 *	Parameters:
 *
 *	Global variables used:
 *		envvar		A list of environment vars with $ in value
 */
void
setvar_envvar(void)
{
	wchar_t			buffer[STRING_BUFFER_LENGTH];
	int			length;
	register	char	*mbs, *tmp_mbs_buffer = NULL;
	register	char	*env, *tmp_mbs_buffer2 = NULL;
	Envvar			p;
	String_rec		value;

	for (p = envvar; p != NULL; p = p->next) {
		if (p->already_put
		    ) {
			continue;
		}
		INIT_STRING_FROM_STACK(value, buffer);		
		expand_value(p->value, &value, false);
		if ((length = wcslen(value.buffer.start)) >= MAXPATHLEN) {
			mbs = tmp_mbs_buffer = getmem((length + 1) * MB_LEN_MAX);
			(void) wcstombs(mbs,
			                value.buffer.start,
			                (length + 1) * MB_LEN_MAX);
		} else {
			mbs = mbs_buffer;
			WCSTOMBS(mbs, value.buffer.start);
		}
		length = 2 + strlen(p->name->string_mb) + strlen(mbs);
		if (!p->already_put || length > (MAXPATHLEN * MB_LEN_MAX)) {
			env = tmp_mbs_buffer2 = getmem(length);
		} else {
			env = mbs_buffer2;
		}
		(void) sprintf(env,
			       "%s=%s",
			       p->name->string_mb,
			       mbs);
		if (!p->already_put) {
			(void) putenv(env);
			p->already_put = true;
			if (p->env_string) {
				retmem_mb(p->env_string);
			}
			p->env_string = env;
			tmp_mbs_buffer2 = NULL; // We should not return this memory now
		}
		if (tmp_mbs_buffer2) {
			retmem_mb(tmp_mbs_buffer2);
			tmp_mbs_buffer2 = NULL;
		}
		if (tmp_mbs_buffer) {
			retmem_mb(tmp_mbs_buffer);
			tmp_mbs_buffer = NULL;
		}
	}
}


