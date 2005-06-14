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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/bootconf.h>
#include <sys/reboot.h>
#include <sys/param.h>
#include <sys/salib.h>
#include <sys/debug.h>
#include <sys/promif.h>
#include <sys/boot.h>
#include <sys/sysmacros.h>
#include <util/getoptstr.h>
#include "boot_plat.h"

static char impl_arch_buf[MAXNAMELEN];
static char default_path_buf[MAXPATHLEN];

char	wanboot_arguments[OBP_MAXPATHLEN];	/* args following "-o" */

/*
 * Parse the boot arguments, adding the options found to the existing boothowto
 * value (if any) or other state.  Then rewrite the buffer with arguments for
 * the standalone.
 *
 * We assume that the buffer contains only the arguments (no preceeding
 * filename or whitespace).  We start interpreting flags, ignoring those used
 * by the boot block (-H, -X, and -F filename) and acting on those intended
 * for us (those documented in boot(1M) as well as some undocumented), and
 * stop at unknown flags.  Finally we reconstitute flags to be passed on to
 * the standalone and the remaining arguments, excluding the first "--", to
 * the beginning of the buffer, and return an integer representing our flags.
 *
 * NOTE: boothowto may already have bits set when this function is called
 */
void
bootflags(char *args, size_t argsz)
{
	static char newargs[OBP_MAXPATHLEN];
	struct gos_params params;
	const char *cp;
	char *np;
	size_t npres;
	int c;

	impl_arch_name = NULL;
	cmd_line_default_path = NULL;

	params.gos_opts = "HXF:VnI:D:advhko:";
	params.gos_strp = args;
	getoptstr_init(&params);
	while ((c = getoptstr(&params)) != -1) {
		switch (c) {
		/*
		 * Bootblock flags: ignore.
		 */
		case 'H':
		case 'X':
		case 'F':
			break;

		/*
		 * Boot flags.
		 */
		case 'V':
			verbosemode = 1;
			break;
		case 'n':
			cache_state = 0;
			printf("Warning: boot will not enable cache\n");
			break;

		case 'I':
			if (params.gos_optarglen >= sizeof (impl_arch_buf)) {
				printf("boot: -I argument too long.  "
				    "Ignoring.\n");
				break;
			}
			(void) strncpy(impl_arch_buf, params.gos_optargp,
			    params.gos_optarglen);
			impl_arch_buf[params.gos_optarglen] = '\0';
			impl_arch_name = impl_arch_buf;
			break;

		case 'D':
			if (params.gos_optarglen >= sizeof (default_path_buf)) {
				printf("boot: -D argument too long.  "
				    "Ignoring.\n");
				break;
			}
			(void) strncpy(default_path_buf, params.gos_optargp,
			    params.gos_optarglen);
			default_path_buf[params.gos_optarglen] = '\0';
			cmd_line_default_path = default_path_buf;
			break;

		case 'o':
			if (params.gos_optarglen >=
			    sizeof (wanboot_arguments)) {
				printf("boot: -o argument too long.  "
				    "Ignoring.\n");
				break;
			}
			(void) strncpy(wanboot_arguments, params.gos_optargp,
			    params.gos_optarglen);
			wanboot_arguments[params.gos_optarglen] = '\0';
			break;

		case 'a':
			boothowto |= RB_ASKNAME;
			break;

		case 'd':
			boothowto |= RB_DEBUGENTER;
			break;
		case 'v':
			boothowto |= RB_VERBOSE;
			break;
		case 'h':
			boothowto |= RB_HALT;
			break;

		/* Consumed by the kernel */
		case 'k':
			boothowto |= RB_KMDB;
			break;

		/*
		 * Unrecognized flags: stop.
		 */
		case '?':
			/*
			 * Error.  Either an unrecognized option, or an option
			 * without an argument.  Check for the latter.
			 */
			switch (params.gos_last_opt) {
			case 'F':
				/* -F is a bootblock flag, so ignore. */
				break;
			case 'I':
			case 'D':
			case 'o':
				printf("boot: -%c flag missing required "
				    "argument.  Ignoring.\n",
				    params.gos_last_opt);
				break;
			default:
				/* Unrecognized option.  Stop. */
				goto done;
			}
			break;

		default:
			printf("boot: Ignoring unimplemented option -%c.\n", c);
		}
	}
done:

	/*
	 * Construct the arguments for the standalone.
	 */

	*newargs = '\0';
	np = newargs;

	/*
	 * We need a dash if we encountered an unrecognized option or if we
	 * need to pass flags on.
	 */
	if (c == '?' || (boothowto &
	    /* These flags are to be passed to the standalone. */
	    (RB_ASKNAME | RB_DEBUGENTER | RB_VERBOSE | RB_HALT | RB_KMDB))) {
		*np++ = '-';

		/*
		 * boot(1M) says to pass these on.
		 */
		if (boothowto & RB_ASKNAME)
			*np++ = 'a';

		/*
		 * boot isn't documented as consuming these flags, so pass
		 * them on.
		 */
		if (boothowto & RB_DEBUGENTER)
			*np++ = 'd';
		if (boothowto & RB_KMDB)
			*np++ = 'k';
		if (boothowto & RB_VERBOSE)
			*np++ = 'v';
		if (boothowto & RB_HALT)
			*np++ = 'h';

		/*
		 * If we didn't encounter an unrecognized flag and there's
		 * more to copy, add a space to separate these flags.
		 * (Otherwise, unrecognized flags can be appended since we
		 * started this word with a dash.)
		 */
		if (c == -1 && params.gos_strp[0] != '\0')
			*np++ = ' ';
	}

	npres = sizeof (newargs) - (size_t)(np - newargs);

	if (c == '?') {
		/*
		 * Unrecognized flag: Copy gos_errp to end of line or a "--"
		 * word.
		 */
		cp = params.gos_errp;
		while (*cp && npres > 0) {
			if (cp[0] == '-' && cp[1] == '-' &&
			    (cp[2] == '\0' || ISSPACE(cp[2]))) {
				cp += 2;
				SKIP_SPC(cp);
				break;
			} else {
				const char *sp = cp;
				size_t sz;

				/* Copy until the next word. */
				while (*cp && !ISSPACE(*cp))
					cp++;
				while (ISSPACE(*cp))
					cp++;

				sz = MIN(npres, (size_t)(cp - sp));
				npres -= sz;
				bcopy(sp, np, sz);
				np += sz;
			}
		}
	} else {
		cp = params.gos_strp;
	}

	while (npres > 0 && (*np++ = *cp++) != '\0')
		npres--;

	newargs[sizeof (newargs) - 1] = '\0';
	(void) strlcpy(args, newargs, argsz);

	/*
	 * If a default filename was specified in the args, set it.
	 */
	if (cmd_line_default_path)
		set_default_filename(cmd_line_default_path);
}
