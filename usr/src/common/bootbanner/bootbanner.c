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
 * Copyright 2020 Oxide Computer Company
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

/*
 * Rendering of the boot banner, used on the system and zone consoles.
 */

typedef enum ilstr_errno {
	ILSTR_ERROR_OK = 0,
	ILSTR_ERROR_NOMEM,
	ILSTR_ERROR_OVERFLOW,
} ilstr_errno_t;

typedef struct ilstr {
	char *ils_data;
	size_t ils_datalen;
	size_t ils_strlen;
	uint_t ils_errno;
	int ils_kmflag;
} ilstr_t;

static void
ilstr_init(ilstr_t *ils, int kmflag)
{
	bzero(ils, sizeof (*ils));
	ils->ils_kmflag = kmflag;
}

static void
ilstr_reset(ilstr_t *ils)
{
	if (ils->ils_strlen > 0) {
		/*
		 * Truncate the string but do not free the buffer so that we
		 * can use it again without further allocation.
		 */
		ils->ils_data[0] = '\0';
		ils->ils_strlen = 0;
	}
	ils->ils_errno = ILSTR_ERROR_OK;
}

static void
ilstr_fini(ilstr_t *ils)
{
	if (ils->ils_data != NULL) {
#ifdef _KERNEL
		kmem_free(ils->ils_data, ils->ils_datalen);
#else
		free(ils->ils_data);
#endif
	}
}

static void
ilstr_append_str(ilstr_t *ils, const char *s)
{
	size_t len;
	size_t chunksz = 64;

	if (ils->ils_errno != ILSTR_ERROR_OK) {
		return;
	}

	if ((len = strlen(s)) < 1) {
		return;
	}

	/*
	 * Check to ensure that the new string length does not overflow,
	 * leaving room for the termination byte:
	 */
	if (len >= SIZE_MAX - ils->ils_strlen - 1) {
		ils->ils_errno = ILSTR_ERROR_OVERFLOW;
		return;
	}
	size_t new_strlen = ils->ils_strlen + len;

	if (new_strlen + 1 >= ils->ils_datalen) {
		size_t new_datalen = ils->ils_datalen;
		char *new_data;

		/*
		 * Grow the string buffer to make room for the new string.
		 */
		while (new_datalen < new_strlen + 1) {
			if (chunksz >= SIZE_MAX - new_datalen) {
				ils->ils_errno = ILSTR_ERROR_OVERFLOW;
				return;
			}
			new_datalen += chunksz;
		}

#ifdef _KERNEL
		new_data = kmem_alloc(new_datalen, ils->ils_kmflag);
#else
		new_data = malloc(new_datalen);
#endif
		if (new_data == NULL) {
			ils->ils_errno = ILSTR_ERROR_NOMEM;
			return;
		}

		if (ils->ils_data != NULL) {
			bcopy(ils->ils_data, new_data, ils->ils_strlen + 1);
#ifdef _KERNEL
			kmem_free(ils->ils_data, ils->ils_datalen);
#else
			free(ils->ils_data);
#endif
		}

		ils->ils_data = new_data;
		ils->ils_datalen = new_datalen;
	}

	bcopy(s, ils->ils_data + ils->ils_strlen, len + 1);
	ils->ils_strlen = new_strlen;
}

#ifdef _KERNEL
static void
ilstr_append_uint(ilstr_t *ils, uint_t n)
{
	char buf[64];

	if (ils->ils_errno != ILSTR_ERROR_OK) {
		return;
	}

	VERIFY3U(snprintf(buf, sizeof (buf), "%u", n), <, sizeof (buf));

	ilstr_append_str(ils, buf);
}
#endif

static void
ilstr_append_char(ilstr_t *ils, char c)
{
	char buf[2];

	if (ils->ils_errno != ILSTR_ERROR_OK) {
		return;
	}

	buf[0] = c;
	buf[1] = '\0';

	ilstr_append_str(ils, buf);
}

static ilstr_errno_t
ilstr_errno(ilstr_t *ils)
{
	return (ils->ils_errno);
}

static const char *
ilstr_cstr(ilstr_t *ils)
{
	return (ils->ils_data);
}

static size_t
ilstr_len(ilstr_t *ils)
{
	return (ils->ils_strlen);
}

static const char *
ilstr_errstr(ilstr_t *ils)
{
	switch (ils->ils_errno) {
	case ILSTR_ERROR_OK:
		return ("ok");
	case ILSTR_ERROR_NOMEM:
		return ("could not allocate memory");
	case ILSTR_ERROR_OVERFLOW:
		return ("tried to construct too large a string");
	default:
		return ("unknown error");
	}
}

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
				ilstr_append_uint(output,
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
 * The "kmflag" value accepts the same values as kmem_alloc(9F) in the kernel,
 * and is ignored otherwise.
 */
void
bootbanner_print(void (*printfunc)(const char *, uint_t), int kmflag)
{
	ilstr_t s;
	uint_t num = 0;

	ilstr_init(&s, kmflag);

	bootbanner_print_one(&s, printfunc, BOOTBANNER1, &num);
	bootbanner_print_one(&s, printfunc, BOOTBANNER2, &num);
	bootbanner_print_one(&s, printfunc, BOOTBANNER3, &num);
	bootbanner_print_one(&s, printfunc, BOOTBANNER4, &num);
	bootbanner_print_one(&s, printfunc, BOOTBANNER5, &num);

	ilstr_fini(&s);
}
