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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

int
prom_stdout_is_framebuffer(void)
{
	static int remember = -1;

	if (remember == -1)
		remember = prom_devicetype((pnode_t)prom_stdout_node(),
			OBP_DISPLAY);
	return (remember);
}

/*
 * get current cursor position from the stdout handle, which
 * containing the instance handle of the OBP console output device.
 */
void
prom_get_tem_pos(uint32_t *row, uint32_t *col)
{
	prom_interpret(
	    "my-self >r stdout @ is my-self "
	    "line# swap l! column# swap l! "
	    "r> is my-self",
	    (uintptr_t)row, (uintptr_t)col, 0, 0, 0);
}


/*
 * get the font size and the start window top of
 * OBP terminal emulator
 */
void
prom_get_term_font_size(int *charheight, int *window_top)
{
	prom_interpret(
	    "my-self >r stdout @ is my-self "
	    "char-height swap l! window-top swap l! "
	    "r> is my-self",
	    (uintptr_t)charheight, (uintptr_t)window_top, 0, 0, 0);

}

/* Clear the spining "|" character and hide the PROM cursor. */
void
prom_hide_cursor(void)
{
	prom_interpret(
	    "my-self >r stdout @ is my-self "
	    "toggle-cursor "
	    "1 delete-characters "
	    "r> is my-self",
	    0, 0, 0, 0, 0);
}

static size_t
prom_atol(const char *str, int len)
{
	size_t n = 0;

	while (len-- && (*str != '\0')) {
		n = n * 10 + (*str - '0');
		str++;
	}

	return (n);
}

/*
 * Here we use the "screen-#columns" and "screen-#rows" settings of
 * PROM to help us decide the console size and cursor position. The
 * actual sizes of PROM's TEM and the console might be different with
 * those "screen-#.." settings, in cases that they are too big to
 * accommodate.
 */
void
prom_get_tem_size(size_t *height, size_t *width)
{
	char buf[MAXPATHLEN];
	char name[16];
	pnode_t node;
	int len;

	if ((node = prom_optionsnode()) == OBP_BADNODE)
		return;

	(void) prom_strcpy(name, "screen-#rows");
	if ((len = prom_getproplen(node, (caddr_t)name)) > 0) {
		(void) prom_getprop(node, (caddr_t)name, (caddr_t)buf);
		*height = prom_atol(buf, len);
	}

	(void) prom_strcpy(name, "screen-#columns");
	if ((len = prom_getproplen(node, (caddr_t)name)) > 0) {
		(void) prom_getprop(node, (caddr_t)name, (caddr_t)buf);
		*width = prom_atol(buf, len);
	}
}
