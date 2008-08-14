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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <msg_sub.h>

char		*
mms_msg_sub(char *template, char *arg, char *text)
{
	char		*buf;
	char		*arg_ptn;
	int		ptn_len;

	/*
	 * Set up arg pattern - $arg$
	 */
	ptn_len = strlen(arg) + 2;
	arg_ptn = malloc(ptn_len + 1);
	if (arg_ptn == NULL) {
		return (NULL);
	}
	(void) snprintf(arg_ptn, ptn_len + 1, "$%s$", arg);
	buf = mms_text_sub(template, arg_ptn, text);
	free(arg_ptn);
	return (buf);
}

char		*
mms_text_sub(char *template, char *arg, char *text)
{
	int		out_incr;
	int		out_len;
	int		out_off;
	char		*out;
	int		in_incr;
	int		in_len;
	int		in_off;
	char		*in;
	int		text_len = strlen(text);
	int		arg_len = strlen(arg);

	in = template;
	in_len = strlen(in);
	in_off = 0;

	out_len = strlen(in) * 2;	/* get more space */
	out_off = 0;
	out = malloc(out_len + 1);
	if (out == NULL) {	/* can't get out buffer */
		return (NULL);
	}
	for (in_off = 0, in_incr = 1, out_off = 0, out_incr = 1;
	    in_off < in_len;
	    in_off += in_incr, out_off += out_incr) {
		in_incr = 1;
		out_incr = 1;
		if (strncmp(in + in_off, arg, arg_len)) {
			/* not arg pattern */
			out[out_off] = in[in_off];
		} else {
			/* matched pattern */
			while ((out_len - out_off) <
			    (in_len - in_off - arg_len + text_len)) {
				/*
				 * If output buf cannot hold the remaining
				 * input and the text length, then get
				 * more space
				 */
				char		*new;
				int		new_len;

				new_len = out_len * 2;
				new = realloc(out, new_len);
				if (new == NULL) {
					free(out);
					return (NULL);
				}
				out = new;
				out_len = new_len;
			}
			(void) strlcpy(out + out_off, text,
			    (out_len + 1 - out_off));
			in_incr = arg_len;
			out_incr = text_len;
		}
	}
	out[out_off] = '\0';
	return (out);
}
