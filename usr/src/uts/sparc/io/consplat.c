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
 * Copyright 2019 Peter Tribble.
 */

/*
 * isa-specific console configuration routines
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/promif.h>
#include <sys/modctl.h>
#include <sys/termios.h>

extern char *get_alias(char *alias, char *buf);

extern int polled_debug;

int
plat_use_polled_debug()
{
	return (polled_debug);
}

int
plat_support_serial_kbd_and_ms()
{
	return (1);
}

/*
 * Return generic path to keyboard device from the alias.
 */
char *
plat_kbdpath(void)
{
	static char *kbdpath = NULL;
	static char buf[MAXPATHLEN];
	char *path;

	if (kbdpath != NULL)
		return (kbdpath);

	/*
	 * look for the keyboard property in /aliases
	 * The keyboard alias is required on 1275 systems
	 */
	path = get_alias("keyboard", buf);
	if (path != NULL) {
		kbdpath = path;
		return (path);
	}

	return (NULL);
}

/*
 * Return generic path to display device from the alias.
 */
char *
plat_fbpath(void)
{
	static char *fbpath = NULL;
	static char buf[MAXPATHLEN];
	char *path;

	if (fbpath != NULL)
		return (fbpath);

	/* look for the screen property in /aliases */
	path = get_alias("screen", buf);
	if (path != NULL) {
		fbpath = path;
		return (path);
	}

	return (NULL);
}

char *
plat_mousepath(void)
{
	static char *mousepath = NULL;
	static char buf[MAXPATHLEN];
	char *path, *p, *q;
	major_t zs_major, kb_major;

	if (mousepath != NULL)
		return (mousepath);

	/* look for the mouse property in /aliases */
	path = get_alias("mouse", buf);
	if (path != NULL) {
		mousepath = path;
		return (path);
	}

	if (!plat_support_serial_kbd_and_ms())
		return (NULL);

	if ((zs_major = mod_name_to_major("zs")) == -1)
		return (NULL);

	if ((path = plat_kbdpath()) == NULL)
		return (NULL);

	if ((kb_major = path_to_major(path)) == (major_t)-1)
		return (NULL);

	if (zs_major != kb_major)
		return (NULL);

	/*
	 * If we didn't find the mouse property and we're on an OBP
	 * system with a 'zs' port keyboard/mouse duart then the mouse
	 * is the 'b' channel of the keyboard duart. Change :a to :b
	 * or append :b to the last component of the path.
	 * (It's still canonical without :a)
	 */
	(void) strcpy(buf, path);
	p = (strrchr(buf, '/'));	/* p points to last comp. */
	if (p != NULL) {
		q = strchr(p, ':');
		if (q != 0)
			*q = (char)0;	/* Replace or append options */
		(void) strcat(p, ":b");
		mousepath = buf;
		return (mousepath);
	}
	return (NULL);
}

char *
plat_stdinpath(void)
{
	return (prom_stdinpath());
}

char *
plat_stdoutpath(void)
{
	static char *outpath;
	static char buf[MAXPATHLEN];
	char *p;

	if (outpath != NULL)
		return (outpath);

	p = prom_stdoutpath();
	if (p == NULL)
		return (NULL);

	/*
	 * If the output device is a framebuffer, we don't
	 * care about monitor resolution options strings.
	 * In fact, we can't handle them at all, so strip them.
	 */
	if (prom_stdout_is_framebuffer()) {
		prom_strip_options(p, buf);
		p = buf;
	}

	outpath = p;
	return (outpath);
}

/*
 * stub definition for consconfig_dacf
 */
char *
plat_diagpath(void)
{
	return (NULL);
}

int
plat_stdin_is_keyboard(void)
{
	return (prom_stdin_is_keyboard());
}

int
plat_stdout_is_framebuffer(void)
{
	return (prom_stdout_is_framebuffer());
}

void
plat_tem_get_inverses(int *inverse, int *inverse_screen)
{
	prom_get_tem_inverses(inverse, inverse_screen);
}

void
plat_tem_get_prom_font_size(int *charheight, int *windowtop)
{
	prom_get_term_font_size(charheight, windowtop);
}

void
plat_tem_get_prom_size(size_t *height, size_t *width)
{
	prom_get_tem_size(height, width);
}

void
plat_tem_hide_prom_cursor(void)
{
	prom_hide_cursor();
}

void
plat_tem_get_prom_pos(uint32_t *row, uint32_t *col)
{
	prom_get_tem_pos(row, col);
}

/*
 * Find the path of the virtual console (if available on the
 * current architecture).
 *
 * Returns: -1 if not found, else actual path length.
 */
int
plat_virtual_console_path(char **bufp)
{
	pnode_t		pnode;
	int		buflen;
	static char	buf[OBP_MAXPATHLEN];

	pnode = prom_finddevice("/virtual-devices/console");

	if (pnode == OBP_BADNODE)
		return (-1);

	if ((buflen = prom_phandle_to_path(pnode, buf, sizeof (buf))) < 0)
		return (-1);

	*bufp = buf;

	return (buflen);
}
