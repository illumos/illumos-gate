/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Parse the boot arguments.
 */

#include <sys/reboot.h>
#include <sys/promif.h>
#include <sys/boot.h>
#include <sys/salib.h>
#include <sys/param.h>
#include <util/getoptstr.h>
#include "bootprop.h"
#include "debug.h"

int boothowto;
int verbosemode;
char *bootprog;
char *bootfile;
char bootargs[MAXNAMELEN];
char bootprop[MAXPATHLEN];
static char bootfile_buf[MAXNAMELEN];
static char bootprog_buf[MAXNAMELEN];
static int grub_line_present;


/*
 * Parse the boot arguments and place results in bootprog, bootfile,
 * bootargs, and bootprops. Note that anything unknown is treated as
 * [kern-args] and is passed to kernel as is.
 *
 * The format for the GRUB args is:
 *	/boot/multiboot [bootfile [-D path]] [-Vadvk]
 *	[-B prop=value[,prop=value...]] [kern-args]
 *
 * The format for the eeprom boot-file is:
 *	[bootfile [-D path]] [-Vadvk] [kern-args]
 *
 * The grub line takes precedence
 */
static void
get_bootargs(char *args, int grub)
{
	struct gos_params params;
	const char *cp, *SPC = " \t";
	char *np;
	size_t npres;
	int c;

	/* parse grub bootprog (multiboot) and -B */
	if (grub) {
		char *dash_B = strstr(args, " -B");
		if (dash_B) {
			/* copy -B arg to bootprop */
			cp = strtok(dash_B + 3, SPC);
			(void) strncpy(bootprop, cp, MAXPATHLEN - 1);
			bootprop[MAXPATHLEN - 1] = 0;

			/* move the end string forward */
			cp = strtok(NULL, "");
			if (cp) {
				*dash_B++ = ' ';
				while (*dash_B++ = *cp++)
					;
			} else {
				*dash_B = 0;
			}
		}

		/* get the multiboot prog (must be present) */
		bootprog = strtok(args, SPC);
		strcpy(bootprog_buf, bootprog);
		bootprog = bootprog_buf;
		bootfile = strtok(NULL, SPC);
		grub_line_present = (bootfile != NULL);
	} else {
		/* don't process bootfile_prop if grub line is present */
		if (grub_line_present) {
			if (args && verbosemode)
				printf("grub line specified, ignoring "
				    "boot-file setting %s in bootenv.rc\n",
				    args);
			return;
		}
		bootfile = strtok(args, SPC);
	}

	/* check for leading kmdb/kadb for compatibility */
	if (bootfile == NULL)
		return;

	if (*bootfile == '-') {
		args = bootfile;
		/* XXX undo strtok, if have additional tokens */
		if (strtok(NULL, ""))
			args[strlen(bootfile)] = ' ';
		bootfile = NULL;
	} else {
		if (strcmp(bootfile, "kmdb") == 0 ||
		    strcmp(bootfile, "kadb") == 0) {
			bootfile = NULL;
			boothowto |= RB_KMDB;
		} else {
			/* copy to buf to avoid being overwritten */
			strcpy(bootfile_buf, bootfile);
			bootfile = bootfile_buf;
		}
		/* get the remainder of string */
		args = strtok(NULL, "");
		if (args == NULL)
			args = "";
	}

	params.gos_opts = "CD:Vadvk";
	params.gos_strp = args;
	getoptstr_init(&params);
	while ((c = getoptstr(&params)) != -1) {
		extern void check_iopath(void);

		switch (c) {
		case 'V':	/* Undocumented. */
			verbosemode = 1;
			break;
		case 'C':	/* Undocumented for checking IO path */
			check_iopath();
			/* never returns here */
			break;
		case 'D':
			if (bootfile || (boothowto & RB_KMDB) == 0) {
				printf("boot: -D invalid without kadb/kmdb.  "
				    "Ignoring.\n");
				break;
			}
			if (params.gos_optarglen >= sizeof (bootfile_buf)) {
				printf("boot: -D argument too long.  "
				    "Ignoring.\n");
				break;
			}
			(void) strncpy(bootfile_buf, params.gos_optargp,
			    params.gos_optarglen);
			bootfile_buf[params.gos_optarglen] = '\0';
			bootfile = bootfile_buf;
			break;

		/* Consumed by the kernel */
		case 'a':	/* Undocumented. */
			boothowto |= RB_ASKNAME;
			break;
		case 'd':
			boothowto |= RB_DEBUGENTER;
			break;
		case 'v':
			boothowto |= RB_VERBOSE;
			break;
		case 'k':
			boothowto |= RB_KMDB;
			break;

		case '?':
			/*
			 * Error.  Either an unrecognized option, or an option
			 * without an argument.  Check for the latter.
			 */
			switch (params.gos_last_opt) {
			case 'D':
			case 'O':
				printf("boot: -%c flag missing required "
				    "argument.  Ignoring.\n",
				    params.gos_last_opt);
				break;
			default:
				/* Unrecognized flag: stop. */
				goto done;
			}
			break;

		default:
			printf("boot: Ignoring unimplemented option -%c.", c);
		}
	}
done:

	/*
	 * Construct the arguments for the standalone.
	 */
	*bootargs = '\0';
	np = bootargs;

	/*
	 * Start with '-' if we encountered an unrecognized option or if we
	 * need to pass flags to the standalone.
	 */
	if (c == '?' || (boothowto &
	    /* These flags are to be passed to the kernel. */
	    (RB_ASKNAME | RB_DEBUGENTER | RB_VERBOSE |
	    RB_KMDB))) {
		*np++ = '-';
		if (boothowto & RB_ASKNAME)
			*np++ = 'a';
		if (boothowto & RB_DEBUGENTER)
			*np++ = 'd';
		if (boothowto & RB_VERBOSE)
			*np++ = 'v';
		if (boothowto & RB_KMDB)
			*np++ = 'k';

		/*
		 * If we didn't encounter an unrecognized flag and there's
		 * more to copy, add a space to separate these flags.
		 * (Otherwise, unrecognized flags can be appended since we
		 * started this word with a dash.)
		 */
		if (c == -1 && params.gos_strp[0] != '\0')
			*np++ = ' ';
	}

	npres = sizeof (bootargs) - (size_t)(np - bootargs);

	/*
	 * Unrecognized flag. gos_errp contains the remaining bootargs
	 */

	if (c == '?')
		cp = params.gos_errp;
	else
		cp = params.gos_strp;

	while (npres > 0 && (*np++ = *cp++) != '\0')
		npres--;
	*np = 0;

	if (verbosemode) {
		printf("bootprog = %s\n", bootprog);
		if (bootfile)
			printf("bootfile = %s\n", bootfile);
		printf("boot-args = %s\n", bootargs);
		printf("bootprop = %s\n", bootprop);
	}
}

void
get_grub_bootargs(char *args)
{
	/* grub args is always present */
	get_bootargs(args, 1);
}

void
get_eeprom_bootargs(char *args)
{
	if (args)	/* boot-file prop may not be present */
		get_bootargs(args, 0);
}
