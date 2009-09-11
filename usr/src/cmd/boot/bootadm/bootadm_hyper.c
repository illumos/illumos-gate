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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <ctype.h>
#include <sys/types.h>

#include "message.h"
#include "bootadm.h"

#define	HYPER_KERNEL_DIR 		"/platform/i86xpv/kernel"
#define	METAL_KERNEL_DIR 		"/platform/i86pc/kernel"

#define	BOOTRC_FILE			"/boot/solaris/bootenv.rc"
#define	ZFS_BOOTSTR			"$ZFS-BOOTFS"

#define	BFLAG				"-B"
#define	DEFAULT_SERIAL			"9600,8,n,1"

#define	TTYXMODE_TO_COMNUM(ttyxmode)	((int)(*((ttyxmode) + 3) - '`'))
#define	COMNAME_TO_COMNUM(comname)	((int)(*((comname) + 3) - '0'))

#define	WHITESPC(x)			(x)

static char *serial_config[2] = { NULL, NULL };

static char *console_dev = NULL;

static unsigned zfs_boot = 0;

/*
 * Append the string pointed to by "str" to the string pointed to by "orig"
 * adding the delimeter "delim" in between.
 *
 * Return a pointer to the new string or NULL, if we were passed a bad string
 * or we couldn't allocate memory for the new one.
 */
static char *
append_str(char *orig, char *str, char *delim)
{
	char *newstr;
	int len;

	if ((orig == NULL) || (str == NULL) || (delim == NULL))
		return (NULL);

	if (*orig == NULL)
		return (s_strdup(str));

	len = strlen(orig) + strlen(str) + strlen(delim) + 1;
	newstr = s_realloc(orig, len);

	if (newstr != NULL)
		(void) snprintf(newstr, len, "%s%s%s", orig, delim, str);

	return (newstr);
}

/*
 * Replace the substring "old_str" in a path with the substring "new_str"
 *
 * Return a pointer to the  modified string or NULL, if we couldn't allocate
 * memory for the new string.
 */
static char *
modify_path(char *path, char *old_str, char *new_str)
{
	char *newpath;
	char *oldpath;
	char *pc;

	oldpath = s_strdup(path);

	if ((pc = strstr(oldpath, old_str)) == NULL) {
		free(oldpath);
		return (path);
	}

	/*
	 * Allocate space for duplicate of path with name changes and
	 * NULL terminating byte
	 */
	if ((newpath = s_realloc(path,
	    strlen(oldpath) - strlen(old_str) + strlen(new_str) + 1)) == NULL) {
		free(oldpath);
		return (NULL);
	}

	(void) strlcpy(newpath, oldpath, (pc - oldpath) + 1);
	free(oldpath);

	(void) strcat(newpath, new_str);
	pc += strlen(old_str);
	return (strcat(newpath, pc));
}

/*
 * Set "token" to be the the string starting from the pointer "str" delimited
 * by any character in the string "delim" or the end of the string, but IGNORE
 * any characters between single or double quotes.
 *
 * Return a pointer to the next non-whitespace character after the delimiter
 * or NULL if we hit the end of the string. Also return NULL upon failure to
 * find any characters from the delimeter string or upon failure to allocate
 * memory for the new token string.
 */
static char *
get_token(char **token, char *str, char *delim)
{
	char *dp;
	char *start = str;
	unsigned len;

	*token = NULL;

	if ((str == NULL) || (*str == NULL))
		return (NULL);

	do {
		if ((*str == '\'') || (*str == '"')) {
			char quote = *str++;

			while ((*str != NULL) && (*str != quote))
				str++;

			/* no matching quote found in string */
			if (*str++ == NULL)
				return (NULL);
		}

		/* look for a character from the delimiter string */
		for (dp = delim; ((*dp != NULL) && (*dp != *str)); dp++)
			;

		if (*dp != NULL) {
			len = str - start + 1;

			/* found a delimiter, so create a token string */
			if ((*token = malloc(len)) == NULL) {
				bam_error(NO_MEM, len);
				return (NULL);
			}

			(void) strlcpy(*token, start, len);

			while (isspace((int)*++str))
				;

			return (str);
		}
	} while (*str++ != NULL);

	/* if we hit the end of the string, the token is the whole string  */
	*token = s_strdup(start);
	return (NULL);
}

/*
 * Convert a metal "console" device name to an equivalent one suitable for
 * use with the hypervisor.
 *
 * Default to "vga" if we can't parse the console device.
 */
static void
console_metal_to_hyper(char *console)
{
	if ((*console == '\'') || (*console == '"'))
		console++;

	if (strncmp(console, "ttya", 4) == 0)
		console_dev = "console=com1";
	else if (strncmp(console, "ttyb", 4) == 0)
		console_dev = "console=com2";
	else
		console_dev = "console=vga";
}

static int
set_serial_rate(int com, char *rate)
{
	char **rp = &serial_config[com - 1];

	/*
	 * If rate is a NULL pointer, erase any existing serial configuration
	 * for this serial port.
	 */
	if (rate == NULL) {
		if (*rp != NULL) {
			free(*rp);
			*rp = NULL;
		}
		return (0);
	}

	*rp = s_realloc(*rp, strlen(rate));
	(void) strcpy(*rp, rate);
	return (0);
}

/*
 * Convert "metal" serial port parameters to values compatible with the
 * hypervisor.
 *
 * Return 0 on success, otherwise -1.
 */
static int
serial_metal_to_hyper(char *metal_port, char *metal_serial)
{
#define	COM_RATE_LEN	16	/* strlen("com1=115200,8n1") */

	char com_rate[COM_RATE_LEN];

	unsigned com, baud, bits, stop;
	char parity, handshake;

	if ((strcmp(metal_port, "ttya-mode") == 0) ||
	    (strcmp(metal_port, "ttyb-mode") == 0))
		com = TTYXMODE_TO_COMNUM(metal_port);
	else
		return (-1);

	if ((*metal_serial == '\'') || (*metal_serial == '"'))
		metal_serial++;

	/*
	 * Check if it's specified as the default rate; if so it defaults to
	 * "auto" and we need not set it for they hypervisor.
	 */
	if (strncmp(metal_serial, DEFAULT_SERIAL,
	    strlen(DEFAULT_SERIAL)) == 0) {
		(void) set_serial_rate(com, NULL);
		return (0);
	}

	/* read the serial port format as set forth in common/io/asy.c */
	if (sscanf(metal_serial, "%u,%u,%c,%u,%c", &baud, &bits, &parity, &stop,
	    &handshake) != 5)
		return (-1);

	/* validate serial port parameters */
	if (((bits < 5) || (bits > 8)) || (stop > 1) ||
	    ((parity != 'n') && (parity != 'e') && (parity != 'o')) ||
	    ((handshake != '-') && (handshake != 'h') && (handshake != 's')))
		return (-1);

	/* validate baud rate */
	switch (baud) {
		case 150:
		case 300:
		case 600:
		case 1200:
		case 2400:
		case 4800:
		case 9600:
		case 19200:
		case 38400:
		case 57600:
		case 115200:
			break;

		default:
			return (-1);
	}

	/*
	 * The hypervisor has no way to specify a handshake method, so it gets
	 * quietly dropped in the conversion.
	 */
	(void) snprintf(com_rate, COM_RATE_LEN, "com%d=%u,%u%c%u", com, baud,
	    bits, parity, stop);
	(void) set_serial_rate(com, com_rate);
	return (0);
}

/*
 * Convert bootenv.rc boot property strings of the form:
 *
 *     setprop property value
 *
 * into boot option lines suitable for use with the hypervisor.
 *
 * Our main concerns are the console device and serial port settings.
 *
 * Return values:
 *
 *    -1:	Unparseable line
 *    0:	Success
 *    (n > 0):	A property unimportant to us
 */
static int
cvt_bootprop(char *propstr)
{
	char *parsestr, *port, *token;

	int retval = 0;

	/* get initial "setprop" */
	if ((parsestr = get_token(&token, propstr, " \t")) == NULL) {
		if (token != NULL)
			free(token);

		return (-1);
	}

	if (strcmp(token, "setprop")) {
		free(token);
		return (1);
	}

	free(token);

	/* get property name */
	if ((parsestr = get_token(&token, parsestr, " \t")) == NULL) {
		if (token != NULL)
			free(token);

		return (-2);
	}

	if (strcmp(token, "console") == 0) {
		free(token);

		/* get console property value */
		parsestr = get_token(&token, parsestr, " \t");
		if (token == NULL)
			return (-3);

		console_metal_to_hyper(token);
		free(token);
		return (0);
	}

	/* check if it's a serial port setting */
	if ((strcmp(token, "ttya-mode") == 0) ||
	    (strcmp(token, "ttyb-mode") == 0)) {
		port = token;
	} else {
		free(token);
		return (3);
	}

	/* get serial port setting */
	parsestr = get_token(&token, parsestr, " \t");

	if (token == NULL) {
		free(port);
		return (-1);
	}

	retval = serial_metal_to_hyper(port, token);

	free(port);
	free(token);
	return (retval);
}

/*
 * Convert "name=value" metal options to values suitable for use with the
 * hypervisor.
 *
 * Our main concerns are the console device and serial port settings.
 *
 * Return values:
 *
 *    -1:	Unparseable line
 *    0:	Success
 *    (n > 0):	A property unimportant to us
 */
static int
cvt_metal_option(char *optstr)
{
	char *value;
	unsigned namlen;

	if (strcmp(optstr, ZFS_BOOTSTR) == 0) {
		zfs_boot = 1;
		return (0);
	}

	if ((value = strchr(optstr, '=')) == NULL)
		return (-1);

	namlen = value - optstr;

	if (*++value == NULL)
		return (1);

	if (strncmp(optstr, "console", namlen) == 0) {
		console_metal_to_hyper(value);
		return (0);
	}

	if ((strncmp(optstr, "ttya-mode", namlen) == 0) ||
	    (strncmp(optstr, "ttyb-mode", namlen) == 0)) {
		char *port = alloca(namlen + 1);

		(void) strlcpy(port, optstr, namlen);
		return (serial_metal_to_hyper(port, value));
	}

	return (1);
}

/*
 * Convert "name=value" properties for use with a bare metal kernel
 *
 * Our main concerns are the console setting and serial port modes.
 *
 * Return values:
 *
 *    -1:	Unparseable line
 *    0:	Success
 *    (n > 0):	A property unimportant to us
 */
static int
cvt_hyper_option(char *optstr)
{
#define	SER_LEN		27	/* strlen("ttyb-mode='115200,8,n,1,-'") */

	char ser[SER_LEN];
	char *value;

	unsigned namlen;

	unsigned baud;
	char bits, parity, stop;

	if (strcmp(optstr, ZFS_BOOTSTR) == 0) {
		zfs_boot = 1;
		return (0);
	}

	/*
	 * If there's no "=" in the token, it's likely a standalone
	 * hypervisor token we don't care about (e.g. "noreboot" or
	 * "nosmp") so we ignore it.
	 */
	if ((value = strchr(optstr, '=')) == NULL)
		return (1);

	namlen = value - optstr;

	if (*++value == NULL)
		return (1);

	/*
	 * Note that we use strncmp against the values because the
	 * hypervisor allows setting console parameters for both the
	 * console and debugger via the format:
	 *
	 *   console=cons_dev,debug_dev
	 *
	 * and we only care about "cons_dev."
	 *
	 * This also allows us to extract "comN" from hypervisor constructs
	 * like "com1H" or "com2L," concepts unsupported on bare metal kernels.
	 *
	 * Default the console device to "text" if it was "vga" or was
	 * unparseable.
	 */
	if (strncmp(optstr, "console", namlen) == 0) {
		/* ignore the "console=hypervisor" option */
		if (strcmp(value, "hypervisor") == 0)
			return (0);

		if (strncmp(value, "com1", 4) == 0)
			console_dev = "console=ttya";
		else if (strncmp(value, "com2", 4) == 0)
			console_dev = "console=ttyb";
		else
			console_dev = "console=text";
	}

	/* serial port parameter conversion */

	if ((strncmp(optstr, "com1", namlen) == 0) ||
	    (strncmp(optstr, "com2", namlen) == 0)) {
		unsigned com = COMNAME_TO_COMNUM(optstr);

		/*
		 * Check if it's "auto" - if so, use the default setting
		 * of "9600,8,n,1,-".
		 *
		 * We can't just assume the serial port will default to
		 * "9600,8,n,1" as there could be a directive in bootenv.rc
		 * that would set it to some other value and we want the serial
		 * parameters to be the same as that used by the hypervisor.
		 */
		if (strcmp(value, "auto") == 0) {
			(void) snprintf(ser, SER_LEN,
			    "tty%c-mode='9600,8,n,1,-'", '`' + com);

			if (set_serial_rate(com, ser) != 0)
				return (-1);

			return (0);
		}

		/*
		 * Extract the "B,PS" setting from the com line; ignore other
		 * settings like io_base or IRQ.
		 */
		if (sscanf(value, "%u,%c%c%c", &baud, &bits, &parity,
		    &stop) != 4)
			return (-1);

		/* validate serial port parameters */
		if (((stop != '0') && (stop != '1')) ||
		    ((bits < '5') && (bits > '8')) ||
		    ((parity != 'n') && (parity != 'e') && (parity != 'o')))
			return (-1);

		/* validate baud rate */
		switch (baud) {
			case 150:
			case 300:
			case 600:
			case 1200:
			case 2400:
			case 4800:
			case 19200:
			case 38400:
			case 57600:
			case 115200:
				break;

			default:
				return (-1);
		}

		/*
		 * As the hypervisor has no way to denote handshaking in its
		 * serial port settings, emit a metal serial port configuration
		 * with none as well.
		 */
		(void) snprintf(ser, SER_LEN, "tty%c-mode='%u,%c,%c,%c,-'",
		    '`' + com, baud, bits, parity, stop);

		if (set_serial_rate(com, ser) != 0)
			return (-1);

		return (0);
	}

	return (1);
}

/*
 * Parse a hardware kernel's "kernel$" specifier into parameters we can then
 * use to construct an appropriate "module$" line that can be used to specify
 * how to boot the hypervisor's dom0.
 *
 * Return 0 on success, non-zero on failure.
 */
static int
cvt_metal_kernel(char *kernstr, char **path)
{
	char *token, *parsestr;

	if ((parsestr = get_token(path, kernstr, " \t,")) == NULL)
		return (*path == NULL);

	/*
	 * If the metal kernel specified contains the name of the hypervisor,
	 * we're probably trying to convert an entry already setup to run the
	 * hypervisor, so error out now.
	 */
	if (strstr(*path, XEN_MENU) != NULL) {
		bam_error(ALREADY_HYPER);
		return (-1);
	}

	/* if the path was the last item on the line, that's OK. */
	if ((parsestr = get_token(&token, parsestr, " \t,")) == NULL) {
		if (token != NULL)
			free(token);
		return (0);
	}

	/* if the next token is "-B" process boot options */
	if (strncmp(token, BFLAG, strlen(BFLAG)) != 0) {
		free(token);
		return (0);
	}

	while ((parsestr = get_token(&token, parsestr, ",")) != NULL) {
		(void) cvt_metal_option(token);
		free(token);
	}

	if (token != NULL) {
		(void) cvt_metal_option(token);
		free(token);
	}

	return (0);
}

/*
 * Parse a hypervisor's "kernel$" line into parameters that can be used to
 * help build an appropriate "kernel$" line for booting a bare metal kernel.
 *
 * Return 0 on success, non-zero on failure.
 */
static int
cvt_hyper_kernel(char *kernel)
{
	char *token, *parsestr;

	/* eat the kernel path, which should be the first token */
	if ((parsestr = get_token(&token, kernel, " \t,")) == NULL)
		return (0);

	/*
	 * If the hypervisor kernel specified lives in the metal kernel
	 * directory, we're probably trying to convert an entry already setup
	 * to run on bare metal, so error out now.
	 */
	if (strncmp(token, METAL_KERNEL_DIR, strlen(METAL_KERNEL_DIR)) == 0) {
		bam_error(ALREADY_METAL);
		(void) free(token);
		return (-1);
	}

	/* if the path was the last item on the line, that's OK. */
	free(token);

	/* check for kernel options */
	while ((parsestr = get_token(&token, parsestr, " ")) != NULL) {
		(void) cvt_hyper_option(token);
		free(token);
	}

	if (token != NULL) {
		(void) cvt_hyper_option(token);
		free(token);
	}

	return (0);
}

/*
 * Parse a hypervisor's "module$" line into parameters that can be used to
 * help build an appropriate "kernel$" line for booting a bare metal kernel.
 */
static void
cvt_hyper_module(char *modstr, char **path)
{
	char *token;
	char *parsestr = modstr;

	/*
	 * If multiple pathnames exist on the module$ line, we just want
	 * the last one.
	 */
	while ((parsestr = get_token(path, parsestr, " \t,")) != NULL) {
		if (*parsestr != '/')
			break;

		free(*path);
	}

	/* if the path was the last item on the line, that's OK. */
	if ((parsestr == NULL) ||
	    ((parsestr = get_token(&token, parsestr, " \t,")) == NULL)) {
		if (token != NULL)
			free(token);
		return;
	}

	/* check for "-B" option */
	if (strncmp(token, BFLAG, strlen(BFLAG)) != 0) {
		free(token);
		return;
	}

	/* check for kernel options */
	while ((parsestr = get_token(&token, parsestr, ",")) != NULL) {
		(void) cvt_hyper_option(token);
		free(token);
	}

	if (token != NULL) {
		(void) cvt_hyper_option(token);
		free(token);
	}
}

static void
parse_bootenvrc(char *osroot)
{
#define	LINEBUF_SZ	1024

	FILE *fp;
	char *rcpath;
	char line[LINEBUF_SZ];	/* make line buffer large but not ridiculous */
	int len;

	assert(osroot);

	len = strlen(osroot) + strlen(BOOTRC_FILE) + 1;
	rcpath = alloca(len);
	(void) snprintf(rcpath, len, "%s%s", osroot, BOOTRC_FILE);

	/* if we couldn't open the bootenv.rc file, ignore the issue. */
	if ((fp = fopen(rcpath, "r")) == NULL) {
		BAM_DPRINTF((D_NO_BOOTENVRC, rcpath, strerror(errno)));
		return;
	}

	while (s_fgets(line, LINEBUF_SZ, fp) != NULL) {
		/* we're only interested in parsing "setprop" directives. */
		if (strncmp(line, "setprop", 7) != NULL)
			continue;

		(void) cvt_bootprop(line);
	}

	(void) fclose(fp);
}

error_t
cvt_to_hyper(menu_t *mp, char *osroot, char *extra_args)
{
	const char *fcn = "cvt_to_hyper()";

	line_t *lp;
	entry_t *ent;
	size_t len, zfslen;

	char *osdev;

	char *title = NULL;
	char *findroot = NULL;
	char *bootfs = NULL;
	char *kernel = NULL;
	char *mod_kernel = NULL;
	char *module = NULL;

	char *kern_path = NULL;
	char *kern_bargs = NULL;

	int curdef;
	int kp_allocated = 1;
	int ret = BAM_ERROR;

	assert(osroot);

	BAM_DPRINTF((D_FUNC_ENTRY2, fcn, osroot, extra_args));

	/*
	 * First just check to verify osroot is a sane directory.
	 */
	if ((osdev = get_special(osroot)) == NULL) {
		bam_error(CANT_FIND_SPECIAL, osroot);
		return (BAM_ERROR);
	}

	free(osdev);

	/*
	 * While the effect is purely cosmetic, if osroot is "/" don't
	 * bother prepending it to any paths as they are constructed to
	 * begin with "/" anyway.
	 */
	if (strcmp(osroot, "/") == 0)
		osroot = "";

	/*
	 * Found the GRUB signature on the target partitions, so now get the
	 * default GRUB boot entry number from the menu.lst file
	 */
	curdef = atoi(mp->curdefault->arg);

	/* look for the first line of the matching boot entry */
	for (ent = mp->entries; ((ent != NULL) && (ent->entryNum != curdef));
	    ent = ent->next)
		;

	/* couldn't find it, so error out */
	if (ent == NULL) {
		bam_error(CANT_FIND_DEFAULT, curdef);
		goto abort;
	}

	/*
	 * We found the proper menu entry, so first we need to process the
	 * bootenv.rc file to look for boot options the hypervisor might need
	 * passed as kernel start options such as the console device and serial
	 * port parameters.
	 *
	 * If there's no bootenv.rc, it's not an issue.
	 */
	parse_bootenvrc(osroot);

	/*
	 * Now process the entry itself.
	 */
	for (lp = ent->start; lp != NULL; lp = lp->next) {
		/*
		 * Process important lines from menu.lst boot entry.
		 */
		if (lp->flags == BAM_TITLE) {
			title = alloca(strlen(lp->arg) + 1);
			(void) strcpy(title, lp->arg);
		} else if (strcmp(lp->cmd, "findroot") == 0) {
			findroot = alloca(strlen(lp->arg) + 1);
			(void) strcpy(findroot, lp->arg);
		} else if (strcmp(lp->cmd, "bootfs") == 0) {
			bootfs = alloca(strlen(lp->arg) + 1);
			(void) strcpy(bootfs, lp->arg);
		} else if (strcmp(lp->cmd, menu_cmds[MODULE_DOLLAR_CMD]) == 0) {
			module = alloca(strlen(lp->arg) + 1);
			(void) strcpy(module, lp->arg);
		} else if ((strcmp(lp->cmd,
		    menu_cmds[KERNEL_DOLLAR_CMD]) == 0) &&
		    (cvt_metal_kernel(lp->arg, &kern_path) < 0)) {
			ret = BAM_NOCHANGE;
			goto abort;
		}

		if (lp == ent->end)
			break;
	}

	/*
	 * If findroot, module or kern_path are NULL, boot entry was malformed
	 */
	if (findroot == NULL) {
		bam_error(FINDROOT_NOT_FOUND, curdef);
		goto abort;
	}

	if (module == NULL) {
		bam_error(MODULE_NOT_PARSEABLE, curdef);
		goto abort;
	}

	if (kern_path == NULL) {
		bam_error(KERNEL_NOT_FOUND, curdef);
		goto abort;
	}

	/* assemble new kernel and module arguments from parsed values */
	if (console_dev != NULL) {
		kern_bargs = s_strdup(console_dev);

		if (serial_config[0] != NULL)
			kern_bargs = append_str(kern_bargs, serial_config[0],
			    " ");

		if (serial_config[1] != NULL)
			kern_bargs = append_str(kern_bargs, serial_config[1],
			    " ");
	}

	if ((extra_args != NULL) && (*extra_args != NULL))
		kern_bargs = append_str(kern_bargs, extra_args, " ");

	len = strlen(osroot) + strlen(XEN_MENU) + strlen(kern_bargs) +
	    WHITESPC(1) + 1;

	kernel = alloca(len);

	if ((kern_bargs != NULL) && (*kern_bargs != NULL)) {
		(void) snprintf(kernel, len, "%s%s %s", osroot, XEN_MENU,
		    kern_bargs);
		free(kern_bargs);
	} else {
		(void) snprintf(kernel, len, "%s%s", osroot, XEN_MENU);
	}

	/*
	 * Change the kernel directory from the metal version to that needed for
	 * the hypervisor.  Convert either "direct boot" path to the default
	 * path.
	 */
	if ((strcmp(kern_path, DIRECT_BOOT_32) == 0) ||
	    (strcmp(kern_path, DIRECT_BOOT_64) == 0)) {
		kern_path = HYPERVISOR_KERNEL;
		kp_allocated = 0;
	} else {
		kern_path = modify_path(kern_path, METAL_KERNEL_DIR,
		    HYPER_KERNEL_DIR);
	}

	/*
	 * We need to allocate space for the kernel path (twice) plus an
	 * intervening space, possibly the ZFS boot string, and NULL,
	 * of course.
	 */
	len = (strlen(kern_path) * 2) + WHITESPC(1) + 1;
	zfslen = (zfs_boot ? (WHITESPC(1) + strlen(ZFS_BOOT)) : 0);

	mod_kernel = alloca(len + zfslen);

	(void) snprintf(mod_kernel, len, "%s %s", kern_path, kern_path);

	if (kp_allocated)
		free(kern_path);

	if (zfs_boot) {
		char *zfsstr = alloca(zfslen + 1);

		(void) snprintf(zfsstr, zfslen + 1, " %s", ZFS_BOOT);
		(void) strcat(mod_kernel, zfsstr);
	}

	/* shut off warning messages from the entry line parser */
	if (ent->flags & BAM_ENTRY_BOOTADM)
		ent->flags &= ~BAM_ENTRY_BOOTADM;

	BAM_DPRINTF((D_CVT_CMD_KERN_DOLLAR, fcn, kernel));
	BAM_DPRINTF((D_CVT_CMD_MOD_DOLLAR, fcn, mod_kernel));

	/*
	 * Now try to delete the current default entry from the menu and add
	 * the new hypervisor entry with the parameters we've setup.
	 */
	if (delete_boot_entry(mp, curdef, DBE_QUIET) != BAM_SUCCESS)
		bam_print(NEW_BOOT_ENTRY, title);

	curdef = add_boot_entry(mp, title, findroot, kernel, mod_kernel,
	    module, bootfs);

	/*
	 * If we successfully created the new entry, set the default boot
	 * entry to that entry and let the caller know the new menu should
	 * be written out.
	 */
	if (curdef != BAM_ERROR)
		return (set_global(mp, menu_cmds[DEFAULT_CMD], curdef));

	return (BAM_ERROR);

abort:
	if ((kp_allocated) && (kern_path != NULL))
		free(kern_path);

	if (ret != BAM_NOCHANGE)
		bam_error(HYPER_ABORT, ((*osroot == NULL) ? "/" : osroot));

	return (ret);
}

/*ARGSUSED*/
error_t
cvt_to_metal(menu_t *mp, char *osroot, char *menu_root)
{
	const char *fcn = "cvt_to_metal()";

	line_t *lp;
	entry_t *ent;
	size_t len, zfslen;

	char *delim = ", ";
	char *osdev;

	char *title = NULL;
	char *findroot = NULL;
	char *bootfs = NULL;
	char *kernel = NULL;
	char *module = NULL;

	char *barchive_path = DIRECT_BOOT_ARCHIVE;
	char *kern_path = NULL;

	int curdef;
	int emit_bflag = 1;
	int ret = BAM_ERROR;

	assert(osroot);

	BAM_DPRINTF((D_FUNC_ENTRY2, fcn, osroot, ""));

	/*
	 * First just check to verify osroot is a sane directory.
	 */
	if ((osdev = get_special(osroot)) == NULL) {
		bam_error(CANT_FIND_SPECIAL, osroot);
		return (BAM_ERROR);
	}

	free(osdev);

	/*
	 * Found the GRUB signature on the target partitions, so now get the
	 * default GRUB boot entry number from the menu.lst file
	 */
	curdef = atoi(mp->curdefault->arg);

	/* look for the first line of the matching boot entry */
	for (ent = mp->entries; ((ent != NULL) && (ent->entryNum != curdef));
	    ent = ent->next)
		;

	/* couldn't find it, so error out */
	if (ent == NULL) {
		bam_error(CANT_FIND_DEFAULT, curdef);
		goto abort;
	}

	/*
	 * Now process the entry itself.
	 */
	for (lp = ent->start; lp != NULL; lp = lp->next) {
		/*
		 * Process important lines from menu.lst boot entry.
		 */
		if (lp->flags == BAM_TITLE) {
			title = alloca(strlen(lp->arg) + 1);
			(void) strcpy(title, lp->arg);
		} else if (strcmp(lp->cmd, "findroot") == 0) {
			findroot = alloca(strlen(lp->arg) + 1);
			(void) strcpy(findroot, lp->arg);
		} else if (strcmp(lp->cmd, "bootfs") == 0) {
			bootfs = alloca(strlen(lp->arg) + 1);
			(void) strcpy(bootfs, lp->arg);
		} else if (strcmp(lp->cmd, menu_cmds[MODULE_DOLLAR_CMD]) == 0) {
			if (strstr(lp->arg, "boot_archive") == NULL) {
				module = alloca(strlen(lp->arg) + 1);
				(void) strcpy(module, lp->arg);
				cvt_hyper_module(module, &kern_path);
			} else {
				barchive_path = alloca(strlen(lp->arg) + 1);
				(void) strcpy(barchive_path, lp->arg);
			}
		} else if ((strcmp(lp->cmd,
		    menu_cmds[KERNEL_DOLLAR_CMD]) == 0) &&
		    (cvt_hyper_kernel(lp->arg) < 0)) {
			ret = BAM_NOCHANGE;
			goto abort;
		}

		if (lp == ent->end)
			break;
	}

	/*
	 * If findroot, module or kern_path are NULL, boot entry was malformed
	 */
	if (findroot == NULL) {
		bam_error(FINDROOT_NOT_FOUND, curdef);
		goto abort;
	}

	if (module == NULL) {
		bam_error(MODULE_NOT_PARSEABLE, curdef);
		goto abort;
	}

	if (kern_path == NULL) {
		bam_error(KERNEL_NOT_FOUND, curdef);
		goto abort;
	}

	/*
	 * Assemble new kernel and module arguments from parsed values.
	 *
	 * First, change the kernel directory from the hypervisor version to
	 * that needed for a metal kernel.
	 */
	kern_path = modify_path(kern_path, HYPER_KERNEL_DIR, METAL_KERNEL_DIR);

	/* allocate initial space for the kernel path */
	len = strlen(kern_path) + 1;
	zfslen = (zfs_boot ? (WHITESPC(1) + strlen(ZFS_BOOT)) : 0);

	if ((kernel = malloc(len + zfslen)) == NULL) {
		free(kern_path);
		bam_error(NO_MEM, len);
		goto abort;
	}

	(void) snprintf(kernel, len, "%s", kern_path);
	free(kern_path);

	if (zfs_boot) {
		char *zfsstr = alloca(zfslen + 1);

		(void) snprintf(zfsstr, zfslen + 1, " %s", ZFS_BOOT);
		(void) strcat(kernel, zfsstr);
		emit_bflag = 0;
	}

	if (console_dev != NULL) {
		if (emit_bflag) {
			kernel = append_str(kernel, BFLAG, " ");
			kernel = append_str(kernel, console_dev, " ");
			emit_bflag = 0;
		} else {
			kernel = append_str(kernel, console_dev, ", ");
		}
	}

	/*
	 * We have to do some strange processing here because the
	 * hypervisor's serial ports default to "9600,8,n,1,-" if
	 * "comX=auto" is specified, or to "auto" if nothing is
	 * specified.
	 *
	 * Since there could be entries in the bootenv.rc file that
	 * set the serial port to some other setting, when converting
	 * a hypervisor entry to a metal entry we must force the
	 * serial ports to their defaults.
	 */

	if (emit_bflag) {
		kernel = append_str(kernel, BFLAG, " ");
		delim = " ";
		emit_bflag = 0;
	}

	if (serial_config[0] != NULL)
		kernel = append_str(kernel, serial_config[0], delim);
	else
		kernel = append_str(kernel, "ttya-mode='9600,8,n,1,-'", delim);

	if (serial_config[1] != NULL)
		kernel = append_str(kernel, serial_config[1], ", ");
	else
		kernel = append_str(kernel, "ttyb-mode='9600,8,n,1,-'", ", ");

	/* shut off warning messages from the entry line parser */
	if (ent->flags & BAM_ENTRY_BOOTADM)
		ent->flags &= ~BAM_ENTRY_BOOTADM;

	BAM_DPRINTF((D_CVT_CMD_KERN_DOLLAR, fcn, kernel));
	BAM_DPRINTF((D_CVT_CMD_MOD_DOLLAR, fcn, module));

	/*
	 * Now try to delete the current default entry from the menu and add
	 * the new hypervisor entry with the parameters we've setup.
	 */
	if (delete_boot_entry(mp, curdef, DBE_QUIET) != BAM_SUCCESS)
		bam_print(NEW_BOOT_ENTRY, title);

	curdef = add_boot_entry(mp, title, findroot, kernel, NULL,
	    barchive_path, bootfs);

	/*
	 * If we successfully created the new entry, set the default boot
	 * entry to that entry and let the caller know the new menu should
	 * be written out.
	 */
	if (curdef != BAM_ERROR)
		return (set_global(mp, menu_cmds[DEFAULT_CMD], curdef));

	return (BAM_ERROR);

abort:
	if (ret != BAM_NOCHANGE)
		bam_error(METAL_ABORT, osroot);

	return (ret);
}
