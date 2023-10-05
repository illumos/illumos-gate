/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/sunddi.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#endif
#include <sys/debug.h>
#include <sys/ilstr.h>

/*
 * Rendering of the boot banner, used on the system and zone consoles.
 */

/*
 * Expand a boot banner template string.  The following expansion tokens
 * are supported:
 *
 *	^^	a literal caret
 *	^s	the base kernel name (utsname.sysname)
 *	^o	the operating system name ("illumos")
 *	^v	the operating system version (utsname.version)
 *	^r	the operating system release (utsname.release)
 *	^w	the native address width in bits (e.g., "32" or "64")
 */
static void
bootbanner_expand_template(const char *input, ilstr_t *output)
{
	size_t pos = 0;
	enum {
		ST_REST,
		ST_CARET,
	} state = ST_REST;

#ifndef _KERNEL
	struct utsname utsname;
	bzero(&utsname, sizeof (utsname));
	(void) uname(&utsname);
#endif

	for (;;) {
		char c = input[pos];

		if (c == '\0') {
			/*
			 * Even if the template came to an end mid way through
			 * a caret expansion, it seems best to just print what
			 * we have and drive on.  The onus will be on the
			 * distributor to ensure their templates are
			 * well-formed at build time.
			 */
			break;
		}

		switch (state) {
		case ST_REST:
			if (c == '^') {
				state = ST_CARET;
			} else {
				ilstr_append_char(output, c);
			}
			pos++;
			continue;

		case ST_CARET:
			if (c == '^') {
				ilstr_append_char(output, c);
			} else if (c == 's') {
				ilstr_append_str(output, utsname.sysname);
			} else if (c == 'o') {
				ilstr_append_str(output, "illumos");
			} else if (c == 'r') {
				ilstr_append_str(output, utsname.release);
			} else if (c == 'v') {
				ilstr_append_str(output, utsname.version);
			} else if (c == 'w') {
#ifdef _KERNEL
				ilstr_aprintf(output, "%u",
				    NBBY * (uint_t)sizeof (void *));
#else
				char *bits;
				char buf[32];
				int r;

				if ((r = sysinfo(SI_ADDRESS_WIDTH, buf,
				    sizeof (buf))) > 0 &&
				    r < (int)sizeof (buf)) {
					bits = buf;
				} else {
					bits = "64";
				}

				ilstr_append_str(output, bits);
#endif
			} else {
				/*
				 * Try to make it obvious what went wrong:
				 */
				ilstr_append_str(output, "!^");
				ilstr_append_char(output, c);
				ilstr_append_str(output, " UNKNOWN!");
			}
			state = ST_REST;
			pos++;
			continue;
		}
	}
}

static void
bootbanner_print_one(ilstr_t *s, void (*printfunc)(const char *, uint_t),
    const char *template, uint_t *nump)
{
	ilstr_reset(s);

	bootbanner_expand_template(template, s);

	if (ilstr_errno(s) == ILSTR_ERROR_OK) {
		if (ilstr_len(s) > 0) {
			printfunc(ilstr_cstr(s), *nump);
			*nump += 1;
		}
	} else {
		char ebuf[128];

		snprintf(ebuf, sizeof (ebuf), "boot banner error: %s",
		    ilstr_errstr(s));

		printfunc(ebuf, *nump);
		*nump += 1;
	}
}

/*
 * This routine should be called during early system boot to render the boot
 * banner on the system console, and during zone boot to do so on the zone
 * console.
 *
 * The "printfunc" argument is a callback function.  When passed a string, the
 * function must print it in a fashion appropriate for the context.  The
 * callback will only be called while within the call to bootbanner_print().
 */
void
bootbanner_print(void (*printfunc)(const char *, uint_t))
{
	/*
	 * To avoid the need to allocate in early boot, we'll use a static
	 * buffer four times the size of a tasteful terminal width.  Note that
	 * ilstr will allow us to produce diagnostic output if this buffer
	 * would have been overrun.
	 */
	char sbuf[80 * 4];
	ilstr_t s;
	uint_t num = 0;

	ilstr_init_prealloc(&s, sbuf, sizeof (sbuf));

	bootbanner_print_one(&s, printfunc, BOOTBANNER1, &num);
	bootbanner_print_one(&s, printfunc, BOOTBANNER2, &num);
	bootbanner_print_one(&s, printfunc, BOOTBANNER3, &num);
	bootbanner_print_one(&s, printfunc, BOOTBANNER4, &num);
	bootbanner_print_one(&s, printfunc, BOOTBANNER5, &num);

	ilstr_fini(&s);
}
