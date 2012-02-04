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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * FMD Message Library
 *
 * This library supports a simple set of routines for use in converting FMA
 * events and message codes to localized human-readable message strings.
 *
 * 1. Library API
 *
 * The APIs are as follows:
 *
 * fmd_msg_init - set up the library and return a handle
 * fmd_msg_fini - destroy the handle from fmd_msg_init
 *
 * fmd_msg_locale_set - set the default locale (initially based on environ(5))
 * fmd_msg_locale_get - get the default locale
 *
 * fmd_msg_url_set - set the default URL for knowledge articles
 * fmd_msg_url_get - get the default URL for knowledge articles
 *
 * fmd_msg_gettext_nv - format the entire message for the given event
 * fmd_msg_gettext_id - format the entire message for the given event code
 * fmd_msg_gettext_key - format the entire message for the given dict for the
 *                       given explicit message key
 *
 * fmd_msg_getitem_nv - format a single message item for the given event
 * fmd_msg_getitem_id - format a single message item for the given event code
 *
 * Upon success, fmd_msg_gettext_* and fmd_msg_getitem_* return newly-allocated
 * localized strings in multi-byte format.  The caller must call free() on the
 * resulting buffer to deallocate the string after making use of it.  Upon
 * failure, these functions return NULL and set errno as follows:
 *
 * ENOMEM - Memory allocation failure while formatting message
 * ENOENT - No message was found for the specified message identifier
 * EINVAL - Invalid argument (e.g. bad event code, illegal fmd_msg_item_t)
 * EILSEQ - Illegal multi-byte sequence detected in message
 *
 * 2. Variable Expansion
 *
 * The human-readable messages are stored in msgfmt(1) message object files in
 * the corresponding locale directories.  The values for the message items are
 * permitted to contain variable expansions, currently defined as follows:
 *
 * %%     - literal % character
 * %s     - knowledge article URL (e.g. http://illumos.org/msg/<MSG-ID>)
 * %< x > - value x from the current event, using the expression syntax below:
 *
 * foo.bar  => print nvlist_t member "bar" contained within nvlist_t "foo"
 * foo[123] => print array element 123 of nvlist_t member "foo"
 * foo[123].bar => print member "bar" of nvlist_t element 123 in array "foo"
 *
 * For example, the msgstr value for FMD-8000-2K might be defined as:
 *
 * msgid "FMD-8000-2K.action"
 * msgstr "Use fmdump -v -u %<uuid> to locate the module.  Use fmadm \
 *     reset %<fault-list[0].asru.mod-name> to reset the module."
 *
 * 3. Locking
 *
 * In order to format a human-readable message, libfmd_msg must get and set
 * the process locale and potentially alter text domain bindings.  At present,
 * these facilities in libc are not fully MT-safe.  As such, a library-wide
 * lock is provided: fmd_msg_lock() and fmd_msg_unlock().  These locking calls
 * are made internally as part of the top-level library entry points, but they
 * can also be used by applications that themselves call setlocale() and wish
 * to appropriately synchronize with other threads that are calling libfmd_msg.
 */


#include <sys/fm/protocol.h>

#include <libintl.h>
#include <locale.h>
#include <wchar.h>

#include <alloca.h>
#include <assert.h>
#include <netdb.h>
#include <pthread.h>
#include <synch.h>
#include <strings.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/sysmacros.h>

#include <fmd_msg.h>

#define	FMD_MSGBUF_SZ	256

struct fmd_msg_hdl {
	int fmh_version;	/* libfmd_msg client abi version number */
	char *fmh_urlbase;	/* base url for all knowledge articles */
	char *fmh_binding;	/* base directory for bindtextdomain() */
	char *fmh_locale;	/* default program locale from environment */
	const char *fmh_template; /* FMD_MSG_TEMPLATE value for fmh_locale */
};

typedef struct fmd_msg_buf {
	wchar_t *fmb_data;	/* wide-character data buffer */
	size_t fmb_size;	/* size of fmb_data in wchar_t units */
	size_t fmb_used;	/* used portion of fmb_data in wchar_t units */
	int fmb_error;		/* error if any has occurred */
} fmd_msg_buf_t;

static const char *const fmd_msg_items[] = {
	"type",			/* key for FMD_MSG_ITEM_TYPE */
	"severity",		/* key for FMD_MSG_ITEM_SEVERITY */
	"description",		/* key for FMD_MSG_ITEM_DESC */
	"response",		/* key for FMD_MSG_ITEM_RESPONSE */
	"impact", 		/* key for FMD_MSG_ITEM_IMPACT */
	"action", 		/* key for FMD_MSG_ITEM_ACTION */
	"url",			/* key for FMD_MSG_ITEM_URL */
};

static pthread_rwlock_t fmd_msg_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static const char FMD_MSG_DOMAIN[] = "FMD";
static const char FMD_MSG_TEMPLATE[] = "syslog-msgs-message-template";
static const char FMD_MSG_URLKEY[] = "syslog-url";
static const char FMD_MSG_URLBASE[] = "http://illumos.org/msg/";
static const char FMD_MSG_NLSPATH[] = "NLSPATH=/usr/lib/fm/fmd/fmd.cat";
static const char FMD_MSG_MISSING[] = "-";

/*
 * An enumeration of token types.  The following are valid tokens that can be
 * embedded into the message content:
 *
 * T_INT - integer tokens (for array indices)
 * T_IDENT - nvpair identifiers
 * T_DOT - "."
 * T_LBRAC - "["
 * T_RBRAC - "]"
 *
 * A NULL character (T_EOF) is used to terminate messages.
 * Invalid tokens are assigned the type T_ERR.
 */
typedef enum {
	T_EOF,
	T_ERR,
	T_IDENT,
	T_INT,
	T_DOT,
	T_LBRAC,
	T_RBRAC
} fmd_msg_nv_tkind_t;

typedef struct fmd_msg_nv_token {
	fmd_msg_nv_tkind_t t_kind;
	union {
		char tu_str[256];
		uint_t tu_int;
	} t_data;
} fmd_msg_nv_token_t;

static const struct fmd_msg_nv_type {
	data_type_t nvt_type;
	data_type_t nvt_base;
	size_t nvt_size;
	int (*nvt_value)();
	int (*nvt_array)();
} fmd_msg_nv_types[] = {
	{ DATA_TYPE_INT8, DATA_TYPE_INT8,
	    sizeof (int8_t), nvpair_value_int8, NULL },
	{ DATA_TYPE_INT16, DATA_TYPE_INT16,
	    sizeof (int16_t), nvpair_value_int16, NULL },
	{ DATA_TYPE_INT32, DATA_TYPE_INT32,
	    sizeof (int32_t), nvpair_value_int32, NULL },
	{ DATA_TYPE_INT64, DATA_TYPE_INT64,
	    sizeof (int64_t), nvpair_value_int64, NULL },
	{ DATA_TYPE_UINT8, DATA_TYPE_UINT8,
	    sizeof (uint8_t), nvpair_value_uint8, NULL },
	{ DATA_TYPE_UINT16, DATA_TYPE_UINT16,
	    sizeof (uint16_t), nvpair_value_uint16, NULL },
	{ DATA_TYPE_UINT32, DATA_TYPE_UINT32,
	    sizeof (uint32_t), nvpair_value_uint32, NULL },
	{ DATA_TYPE_UINT64, DATA_TYPE_UINT64,
	    sizeof (uint64_t), nvpair_value_uint64, NULL },
	{ DATA_TYPE_BYTE, DATA_TYPE_BYTE,
	    sizeof (uchar_t), nvpair_value_byte, NULL },
	{ DATA_TYPE_BOOLEAN, DATA_TYPE_BOOLEAN,
	    0, NULL, NULL },
	{ DATA_TYPE_BOOLEAN_VALUE, DATA_TYPE_BOOLEAN_VALUE,
	    sizeof (boolean_t), nvpair_value_boolean_value, NULL },
	{ DATA_TYPE_HRTIME, DATA_TYPE_HRTIME,
	    sizeof (hrtime_t), nvpair_value_hrtime, NULL },
	{ DATA_TYPE_STRING, DATA_TYPE_STRING,
	    sizeof (char *), nvpair_value_string, NULL },
	{ DATA_TYPE_NVLIST, DATA_TYPE_NVLIST,
	    sizeof (nvlist_t *), nvpair_value_nvlist, NULL },
	{ DATA_TYPE_INT8_ARRAY, DATA_TYPE_INT8,
	    sizeof (int8_t), NULL, nvpair_value_int8_array },
	{ DATA_TYPE_INT16_ARRAY, DATA_TYPE_INT16,
	    sizeof (int16_t), NULL, nvpair_value_int16_array },
	{ DATA_TYPE_INT32_ARRAY, DATA_TYPE_INT32,
	    sizeof (int32_t), NULL, nvpair_value_int32_array },
	{ DATA_TYPE_INT64_ARRAY, DATA_TYPE_INT64,
	    sizeof (int64_t), NULL, nvpair_value_int64_array },
	{ DATA_TYPE_UINT8_ARRAY, DATA_TYPE_UINT8,
	    sizeof (uint8_t), NULL, nvpair_value_uint8_array },
	{ DATA_TYPE_UINT16_ARRAY, DATA_TYPE_UINT16,
	    sizeof (uint16_t), NULL, nvpair_value_uint16_array },
	{ DATA_TYPE_UINT32_ARRAY, DATA_TYPE_UINT32,
	    sizeof (uint32_t), NULL, nvpair_value_uint32_array },
	{ DATA_TYPE_UINT64_ARRAY, DATA_TYPE_UINT64,
	    sizeof (uint64_t), NULL, nvpair_value_uint64_array },
	{ DATA_TYPE_BYTE_ARRAY, DATA_TYPE_BYTE,
	    sizeof (uchar_t), NULL, nvpair_value_byte_array },
	{ DATA_TYPE_BOOLEAN_ARRAY, DATA_TYPE_BOOLEAN_VALUE,
	    sizeof (boolean_t), NULL, nvpair_value_boolean_array },
	{ DATA_TYPE_STRING_ARRAY, DATA_TYPE_STRING,
	    sizeof (char *), NULL, nvpair_value_string_array },
	{ DATA_TYPE_NVLIST_ARRAY, DATA_TYPE_NVLIST,
	    sizeof (nvlist_t *), NULL, nvpair_value_nvlist_array },
	{ DATA_TYPE_UNKNOWN, DATA_TYPE_UNKNOWN, 0, NULL, NULL }
};

static int fmd_msg_nv_parse_nvpair(fmd_msg_buf_t *, nvpair_t *, char *);
static int fmd_msg_nv_parse_nvname(fmd_msg_buf_t *, nvlist_t *, char *);
static int fmd_msg_nv_parse_nvlist(fmd_msg_buf_t *, nvlist_t *, char *);

/*ARGSUSED*/
static int
fmd_msg_lock_held(fmd_msg_hdl_t *h)
{
	return (RW_WRITE_HELD(&fmd_msg_rwlock));
}

void
fmd_msg_lock(void)
{
	if (pthread_rwlock_wrlock(&fmd_msg_rwlock) != 0)
		abort();
}

void
fmd_msg_unlock(void)
{
	if (pthread_rwlock_unlock(&fmd_msg_rwlock) != 0)
		abort();
}

static fmd_msg_hdl_t *
fmd_msg_init_err(fmd_msg_hdl_t *h, int err)
{
	fmd_msg_fini(h);
	errno = err;
	return (NULL);
}

fmd_msg_hdl_t *
fmd_msg_init(const char *root, int version)
{
	fmd_msg_hdl_t *h = NULL;
	const char *s;
	size_t len;

	if (version != FMD_MSG_VERSION)
		return (fmd_msg_init_err(h, EINVAL));

	if ((h = malloc(sizeof (fmd_msg_hdl_t))) == NULL)
		return (fmd_msg_init_err(h, ENOMEM));

	bzero(h, sizeof (fmd_msg_hdl_t));
	h->fmh_version = version;

	if ((h->fmh_urlbase = strdup(FMD_MSG_URLBASE)) == NULL)
		return (fmd_msg_init_err(h, ENOMEM));

	/*
	 * Initialize the program's locale from the environment if it hasn't
	 * already been initialized, and then retrieve the default setting.
	 */
	(void) setlocale(LC_ALL, "");
	s = setlocale(LC_ALL, NULL);
	h->fmh_locale = strdup(s ? s : "C");

	if (h->fmh_locale == NULL)
		return (fmd_msg_init_err(h, ENOMEM));

	/*
	 * If a non-default root directory is specified, then look up the base
	 * directory for our default catalog, and set fmh_binding as the same
	 * directory prefixed with the new root directory.  This simply turns
	 * usr/lib/locale into <rootdir>/usr/lib/locale, but handles all of the
	 * environ(5) settings that can change the default messages binding.
	 */
	if (root != NULL && root[0] != '\0' && strcmp(root, "/") != 0) {
		if (root[0] != '/')
			return (fmd_msg_init_err(h, EINVAL));

		if ((s = bindtextdomain(FMD_MSG_DOMAIN, NULL)) == NULL)
			s = "/usr/lib/locale"; /* substitute default */

		len = strlen(root) + strlen(s) + 1;

		if ((h->fmh_binding = malloc(len)) == NULL)
			return (fmd_msg_init_err(h, ENOMEM));

		(void) snprintf(h->fmh_binding, len, "%s%s", root, s);
	}

	/*
	 * All FMA event dictionaries use msgfmt(1) message objects to produce
	 * messages, even for the C locale.  We therefore want to use dgettext
	 * for all message lookups, but its defined behavior in the C locale is
	 * to return the input string.  Since our input strings are event codes
	 * and not format strings, this doesn't help us.  We resolve this nit
	 * by setting NLSPATH to a non-existent file: the presence of NLSPATH
	 * is defined to force dgettext(3C) to do a full lookup even for C.
	 */
	if (getenv("NLSPATH") == NULL &&
	    ((s = strdup(FMD_MSG_NLSPATH)) == NULL || putenv((char *)s) != 0))
		return (fmd_msg_init_err(h, errno));

	/*
	 * Cache the message template for the current locale.  This is the
	 * snprintf(3C) format string for the final human-readable message.
	 * If the lookup fails for the current locale, fall back to the C locale
	 * and try again.  Then restore the original locale.
	 */
	if ((h->fmh_template = dgettext(FMD_MSG_DOMAIN, FMD_MSG_TEMPLATE))
	    == FMD_MSG_TEMPLATE && strcmp(h->fmh_locale, "C") != 0) {
		(void) setlocale(LC_ALL, "C");
		h->fmh_template = dgettext(FMD_MSG_DOMAIN, FMD_MSG_TEMPLATE);
		(void) setlocale(LC_ALL, h->fmh_locale);
	}

	return (h);
}

void
fmd_msg_fini(fmd_msg_hdl_t *h)
{
	if (h == NULL)
		return; /* simplify caller code */

	free(h->fmh_binding);
	free(h->fmh_urlbase);
	free(h->fmh_locale);
	free(h);
}

int
fmd_msg_locale_set(fmd_msg_hdl_t *h, const char *locale)
{
	char *l;

	if (locale == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if ((l = strdup(locale)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	fmd_msg_lock();

	if (setlocale(LC_ALL, l) == NULL) {
		free(l);
		errno = EINVAL;
		fmd_msg_unlock();
		return (-1);
	}

	h->fmh_template = dgettext(FMD_MSG_DOMAIN, FMD_MSG_TEMPLATE);
	free(h->fmh_locale);
	h->fmh_locale = l;

	fmd_msg_unlock();
	return (0);
}

const char *
fmd_msg_locale_get(fmd_msg_hdl_t *h)
{
	return (h->fmh_locale);
}

int
fmd_msg_url_set(fmd_msg_hdl_t *h, const char *url)
{
	char *u;

	if (url == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if ((u = strdup(url)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	fmd_msg_lock();

	free(h->fmh_urlbase);
	h->fmh_urlbase = u;

	fmd_msg_unlock();
	return (0);
}

const char *
fmd_msg_url_get(fmd_msg_hdl_t *h)
{
	return (h->fmh_urlbase);
}

static wchar_t *
fmd_msg_mbstowcs(const char *s)
{
	size_t n = strlen(s) + 1;
	wchar_t *w = malloc(n * sizeof (wchar_t));

	if (w == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	if (mbstowcs(w, s, n) == (size_t)-1) {
		free(w);
		return (NULL);
	}

	return (w);
}

static void
fmd_msg_buf_init(fmd_msg_buf_t *b)
{
	bzero(b, sizeof (fmd_msg_buf_t));
	b->fmb_data = malloc(sizeof (wchar_t) * FMD_MSGBUF_SZ);

	if (b->fmb_data == NULL)
		b->fmb_error = ENOMEM;
	else
		b->fmb_size = FMD_MSGBUF_SZ;
}

static void
fmd_msg_buf_fini(fmd_msg_buf_t *b)
{
	free(b->fmb_data);
	bzero(b, sizeof (fmd_msg_buf_t));
}

static char *
fmd_msg_buf_read(fmd_msg_buf_t *b)
{
	char *s;

	if (b->fmb_error != 0) {
		errno = b->fmb_error;
		return (NULL);
	}

	if ((s = malloc(b->fmb_used * MB_CUR_MAX)) == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	if (wcstombs(s, b->fmb_data, b->fmb_used) == (size_t)-1) {
		free(s);
		return (NULL);
	}

	return (s);
}

/*
 * Buffer utility function to write a wide-character string into the buffer,
 * appending it at the end, and growing the buffer as needed as we go.  Any
 * allocation errors are stored in fmb_error and deferred until later.
 */
static void
fmd_msg_buf_write(fmd_msg_buf_t *b, const wchar_t *w, size_t n)
{
	if (b->fmb_used + n > b->fmb_size) {
		size_t size = MAX(b->fmb_size * 2, b->fmb_used + n);
		wchar_t *data = malloc(sizeof (wchar_t) * size);

		if (data == NULL) {
			if (b->fmb_error == 0)
				b->fmb_error = ENOMEM;
			return;
		}

		bcopy(b->fmb_data, data, b->fmb_used * sizeof (wchar_t));
		free(b->fmb_data);

		b->fmb_data = data;
		b->fmb_size = size;
	}

	bcopy(w, &b->fmb_data[b->fmb_used], sizeof (wchar_t) * n);
	b->fmb_used += n;
}

/*
 * Buffer utility function to printf a multi-byte string, convert to wide-
 * character form, and then write the result into an fmd_msg_buf_t.
 */
/*PRINTFLIKE2*/
static void
fmd_msg_buf_printf(fmd_msg_buf_t *b, const char *format, ...)
{
	ssize_t len;
	va_list ap;
	char *buf;
	wchar_t *w;

	va_start(ap, format);
	len = vsnprintf(NULL, 0, format, ap);
	buf = alloca(len + 1);
	(void) vsnprintf(buf, len + 1, format, ap);
	va_end(ap);

	if ((w = fmd_msg_mbstowcs(buf)) == NULL) {
		if (b->fmb_error != 0)
			b->fmb_error = errno;
	} else {
		fmd_msg_buf_write(b, w, wcslen(w));
		free(w);
	}
}

/*PRINTFLIKE1*/
static int
fmd_msg_nv_error(const char *format, ...)
{
	int err = errno;
	va_list ap;

	if (getenv("FMD_MSG_DEBUG") == NULL)
		return (1);

	(void) fprintf(stderr, "libfmd_msg DEBUG: ");
	va_start(ap, format);
	(void) vfprintf(stderr, format, ap);
	va_end(ap);

	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", strerror(err));

	return (1);
}

static const struct fmd_msg_nv_type *
fmd_msg_nv_type_lookup(data_type_t type)
{
	const struct fmd_msg_nv_type *t;

	for (t = fmd_msg_nv_types; t->nvt_type != DATA_TYPE_UNKNOWN; t++) {
		if (t->nvt_type == type)
			break;
	}

	return (t);
}

/*
 * Print the specified string, escaping any unprintable character sequences
 * using the ISO C character escape sequences.
 */
static void
fmd_msg_nv_print_string(fmd_msg_buf_t *b, const char *s)
{
	char c;

	while ((c = *s++) != '\0') {
		if (c >= ' ' && c <= '~' && c != '\'') {
			fmd_msg_buf_printf(b, "%c", c);
			continue;
		}

		switch (c) {
		case '\0':
			fmd_msg_buf_printf(b, "\\0");
			break;
		case '\a':
			fmd_msg_buf_printf(b, "\\a");
			break;
		case '\b':
			fmd_msg_buf_printf(b, "\\b");
			break;
		case '\f':
			fmd_msg_buf_printf(b, "\\f");
			break;
		case '\n':
			fmd_msg_buf_printf(b, "\\n");
			break;
		case '\r':
			fmd_msg_buf_printf(b, "\\r");
			break;
		case '\t':
			fmd_msg_buf_printf(b, "\\t");
			break;
		case '\v':
			fmd_msg_buf_printf(b, "\\v");
			break;
		case '\'':
			fmd_msg_buf_printf(b, "\\'");
			break;
		case '"':
			fmd_msg_buf_printf(b, "\\\"");
			break;
		case '\\':
			fmd_msg_buf_printf(b, "\\\\");
			break;
		default:
			fmd_msg_buf_printf(b, "\\x%02x", (uchar_t)c);
		}
	}
}

/*
 * Print the value of the specified nvpair into the supplied buffer.
 *
 * For nvpairs that are arrays types, passing -1 as the idx param indicates
 * that we want to print all of the elements in the array.
 *
 * Returns 0 on success, 1 otherwise.
 */
static int
fmd_msg_nv_print_items(fmd_msg_buf_t *b, nvpair_t *nvp,
    data_type_t type, void *p, uint_t n, uint_t idx)
{
	const struct fmd_msg_nv_type *nvt = fmd_msg_nv_type_lookup(type);
	uint_t i;

	if (idx != -1u) {
		if (idx >= n) {
			return (fmd_msg_nv_error("index %u out-of-range for "
			    "array %s: valid range is [0 .. %u]\n",
			    idx, nvpair_name(nvp), n ? n - 1 : 0));
		}
		p = (uchar_t *)p + nvt->nvt_size * idx;
		n = 1;
	}

	for (i = 0; i < n; i++, p = (uchar_t *)p + nvt->nvt_size) {
		if (i > 0)
			fmd_msg_buf_printf(b, " "); /* array item delimiter */

		switch (type) {
		case DATA_TYPE_INT8:
			fmd_msg_buf_printf(b, "%d", *(int8_t *)p);
			break;

		case DATA_TYPE_INT16:
			fmd_msg_buf_printf(b, "%d", *(int16_t *)p);
			break;

		case DATA_TYPE_INT32:
			fmd_msg_buf_printf(b, "%d", *(int32_t *)p);
			break;

		case DATA_TYPE_INT64:
			fmd_msg_buf_printf(b, "%lld", *(longlong_t *)p);
			break;

		case DATA_TYPE_UINT8:
			fmd_msg_buf_printf(b, "%u", *(uint8_t *)p);
			break;

		case DATA_TYPE_UINT16:
			fmd_msg_buf_printf(b, "%u", *(uint16_t *)p);
			break;

		case DATA_TYPE_UINT32:
			fmd_msg_buf_printf(b, "%u", *(uint32_t *)p);
			break;

		case DATA_TYPE_UINT64:
			fmd_msg_buf_printf(b, "%llu", *(u_longlong_t *)p);
			break;

		case DATA_TYPE_BYTE:
			fmd_msg_buf_printf(b, "0x%x", *(uchar_t *)p);
			break;

		case DATA_TYPE_BOOLEAN_VALUE:
			fmd_msg_buf_printf(b,
			    *(boolean_t *)p ? "true" : "false");
			break;

		case DATA_TYPE_HRTIME:
			fmd_msg_buf_printf(b, "%lld", *(longlong_t *)p);
			break;

		case DATA_TYPE_STRING:
			fmd_msg_nv_print_string(b, *(char **)p);
			break;
		}
	}

	return (0);
}

/*
 * Writes the value of the specified nvpair to the supplied buffer.
 *
 * Returns 0 on success, 1 otherwise.
 */
static int
fmd_msg_nv_print_nvpair(fmd_msg_buf_t *b, nvpair_t *nvp, uint_t idx)
{
	data_type_t type = nvpair_type(nvp);
	const struct fmd_msg_nv_type *nvt = fmd_msg_nv_type_lookup(type);

	uint64_t v;
	void *a;
	uint_t n;
	int err;

	if (nvt->nvt_type == DATA_TYPE_BOOLEAN) {
		fmd_msg_buf_printf(b, "true");
		err = 0;
	} else if (nvt->nvt_array != NULL) {
		(void) nvt->nvt_array(nvp, &a, &n);
		err = fmd_msg_nv_print_items(b, nvp, nvt->nvt_base, a, n, idx);
	} else if (nvt->nvt_value != NULL) {
		(void) nvt->nvt_value(nvp, &v);
		err = fmd_msg_nv_print_items(b, nvp, nvt->nvt_base, &v, 1, idx);
	} else {
		err = fmd_msg_nv_error("unknown data type %u", type);
	}

	return (err);
}

/*
 * Consume a token from the specified string, fill in the specified token
 * struct, and return the new string position from which to continue parsing.
 */
static char *
fmd_msg_nv_parse_token(char *s, fmd_msg_nv_token_t *tp)
{
	char *p = s, *q, c = *s;

	/*
	 * Skip whitespace and then look for an integer token first.  We can't
	 * use isspace() or isdigit() because we're in setlocale() context now.
	 */
	while (c == ' ' || c == '\t' || c == '\v' || c == '\n' || c == '\r')
		c = *++p;

	if (c >= '0' && c <= '9') {
		errno = 0;
		tp->t_data.tu_int = strtoul(p, &q, 0);

		if (errno != 0 || p == q) {
			tp->t_kind = T_ERR;
			return (p);
		}

		tp->t_kind = T_INT;
		return (q);
	}

	/*
	 * Look for a name-value pair identifier, which we define to be the
	 * regular expression [a-zA-Z_][a-zA-Z0-9_-]*  (NOTE: Ideally "-" would
	 * not be allowed here and we would require ISO C identifiers, but many
	 * FMA event members use hyphens.)  This code specifically cannot use
	 * the isspace(), isalnum() etc. macros because we are currently in the
	 * context of an earlier call to setlocale() that may have installed a
	 * non-C locale, but this code needs to always operate on C characters.
	 */
	if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
		for (q = p + 1; (c = *q) != '\0'; q++) {
			if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			    (c < '0' || c > '9') && (c != '_' && c != '-'))
				break;
		}

		if (sizeof (tp->t_data.tu_str) <= (size_t)(q - p)) {
			tp->t_kind = T_ERR;
			return (p);
		}

		bcopy(p, tp->t_data.tu_str, (size_t)(q - p));
		tp->t_data.tu_str[(size_t)(q - p)] = '\0';
		tp->t_kind = T_IDENT;
		return (q);
	}

	switch (c) {
	case '\0':
		tp->t_kind = T_EOF;
		return (p);
	case '.':
		tp->t_kind = T_DOT;
		return (p + 1);
	case '[':
		tp->t_kind = T_LBRAC;
		return (p + 1);
	case ']':
		tp->t_kind = T_RBRAC;
		return (p + 1);
	default:
		tp->t_kind = T_ERR;
		return (p);
	}
}

static int
fmd_msg_nv_parse_error(const char *s, fmd_msg_nv_token_t *tp)
{
	if (tp->t_kind == T_ERR)
		return (fmd_msg_nv_error("illegal character at \"%s\"\n", s));
	else
		return (fmd_msg_nv_error("syntax error near \"%s\"\n", s));
}

/*
 * Parse an array expression for referencing an element of the specified
 * nvpair_t, which is expected to be of an array type.  If it's an array of
 * intrinsics, print the specified value.  If it's an array of nvlist_t's,
 * call fmd_msg_nv_parse_nvlist() recursively to continue parsing.
 */
static int
fmd_msg_nv_parse_array(fmd_msg_buf_t *b, nvpair_t *nvp, char *s1)
{
	fmd_msg_nv_token_t t;
	nvlist_t **nva;
	uint_t i, n;
	char *s2;

	if (fmd_msg_nv_type_lookup(nvpair_type(nvp))->nvt_array == NULL) {
		return (fmd_msg_nv_error("inappropriate use of operator [ ]: "
		    "element '%s' is not an array\n", nvpair_name(nvp)));
	}

	s2 = fmd_msg_nv_parse_token(s1, &t);
	i = t.t_data.tu_int;

	if (t.t_kind != T_INT)
		return (fmd_msg_nv_error("expected integer index after [\n"));

	s2 = fmd_msg_nv_parse_token(s2, &t);

	if (t.t_kind != T_RBRAC)
		return (fmd_msg_nv_error("expected ] after [ %u\n", i));

	/*
	 * An array of nvlist is different from other array types in that it
	 * permits us to continue parsing instead of printing a terminal node.
	 */
	if (nvpair_type(nvp) == DATA_TYPE_NVLIST_ARRAY) {
		(void) nvpair_value_nvlist_array(nvp, &nva, &n);

		if (i >= n) {
			return (fmd_msg_nv_error("index %u out-of-range for "
			    "array %s: valid range is [0 .. %u]\n",
			    i, nvpair_name(nvp), n ? n - 1 : 0));
		}

		return (fmd_msg_nv_parse_nvlist(b, nva[i], s2));
	}

	(void) fmd_msg_nv_parse_token(s2, &t);

	if (t.t_kind != T_EOF) {
		return (fmd_msg_nv_error("expected end-of-string "
		    "in expression instead of \"%s\"\n", s2));
	}

	return (fmd_msg_nv_print_nvpair(b, nvp, i));
}

/*
 * Parse an expression rooted at an nvpair_t.  If we see EOF, print the entire
 * nvpair.  If we see LBRAC, parse an array expression.  If we see DOT, call
 * fmd_msg_nv_parse_nvname() recursively to dereference an embedded member.
 */
static int
fmd_msg_nv_parse_nvpair(fmd_msg_buf_t *b, nvpair_t *nvp, char *s1)
{
	fmd_msg_nv_token_t t;
	nvlist_t *nvl;
	char *s2;

	s2 = fmd_msg_nv_parse_token(s1, &t);

	if (t.t_kind == T_EOF)
		return (fmd_msg_nv_print_nvpair(b, nvp, -1));

	if (t.t_kind == T_LBRAC)
		return (fmd_msg_nv_parse_array(b, nvp, s2));

	if (t.t_kind != T_DOT)
		return (fmd_msg_nv_parse_error(s1, &t));

	if (nvpair_type(nvp) != DATA_TYPE_NVLIST) {
		return (fmd_msg_nv_error("inappropriate use of operator '.': "
		    "element '%s' is not of type nvlist\n", nvpair_name(nvp)));
	}

	(void) nvpair_value_nvlist(nvp, &nvl);
	return (fmd_msg_nv_parse_nvname(b, nvl, s2));
}

/*
 * Parse an expression for a name-value pair name (IDENT).  If we find a match
 * continue parsing with the corresponding nvpair_t.
 */
static int
fmd_msg_nv_parse_nvname(fmd_msg_buf_t *b, nvlist_t *nvl, char *s1)
{
	nvpair_t *nvp = NULL;
	fmd_msg_nv_token_t t;
	char *s2;

	s2 = fmd_msg_nv_parse_token(s1, &t);

	if (t.t_kind != T_IDENT)
		return (fmd_msg_nv_parse_error(s1, &t));

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		if (strcmp(nvpair_name(nvp), t.t_data.tu_str) == 0)
			break;
	}

	if (nvp == NULL) {
		return (fmd_msg_nv_error("no such name-value pair "
		    "member: %s\n", t.t_data.tu_str));
	}

	return (fmd_msg_nv_parse_nvpair(b, nvp, s2));
}

/*
 * Parse an expression rooted at an nvlist: if we see EOF, print nothing.
 * If we see DOT, continue parsing to retrieve a name-value pair name.
 */
static int
fmd_msg_nv_parse_nvlist(fmd_msg_buf_t *b, nvlist_t *nvl, char *s1)
{
	fmd_msg_nv_token_t t;
	char *s2;

	s2 = fmd_msg_nv_parse_token(s1, &t);

	if (t.t_kind == T_EOF)
		return (0);

	if (t.t_kind == T_DOT)
		return (fmd_msg_nv_parse_nvname(b, nvl, s2));

	return (fmd_msg_nv_parse_error(s1, &t));
}

/*
 * This function is the main engine for formatting an event message item, such
 * as the Description field.  It loads the item text from a message object,
 * expands any variables defined in the item text, and then returns a newly-
 * allocated multi-byte string with the localized message text, or NULL with
 * errno set if an error occurred.
 */
static char *
fmd_msg_getitem_locked(fmd_msg_hdl_t *h,
    nvlist_t *nvl, const char *dict, const char *code, fmd_msg_item_t item)
{
	const char *istr = fmd_msg_items[item];
	size_t len = strlen(code) + 1 + strlen(istr) + 1;
	char *key = alloca(len);

	fmd_msg_buf_t buf;
	wchar_t *c, *u, *w, *p, *q;

	const char *url, *txt;
	char *s, *expr;
	size_t elen;
	int i;

	assert(fmd_msg_lock_held(h));

	/*
	 * If <dict>.mo defines an item with the key <FMD_MSG_URLKEY> then it
	 * is used as the URL; otherwise the default from our handle is used.
	 * Once we have the multi-byte URL, convert it to wide-character form.
	 */
	if ((url = dgettext(dict, FMD_MSG_URLKEY)) == FMD_MSG_URLKEY)
		url = h->fmh_urlbase;

	/*
	 * If the item is FMD_MSG_ITEM_URL, then its value is directly computed
	 * as the URL base concatenated with the code.  Otherwise the item text
	 * is derived by looking up the key <code>.<istr> in the dict object.
	 * Once we're done, convert the 'txt' multi-byte to wide-character.
	 */
	if (item == FMD_MSG_ITEM_URL) {
		len = strlen(url) + strlen(code) + 1;
		key = alloca(len);
		(void) snprintf(key, len, "%s%s", url, code);
		txt = key;
	} else {
		len = strlen(code) + 1 + strlen(istr) + 1;
		key = alloca(len);
		(void) snprintf(key, len, "%s.%s", code, istr);
		txt = dgettext(dict, key);
	}

	c = fmd_msg_mbstowcs(code);
	u = fmd_msg_mbstowcs(url);
	w = fmd_msg_mbstowcs(txt);

	if (c == NULL || u == NULL || w == NULL) {
		free(c);
		free(u);
		free(w);
		return (NULL);
	}

	/*
	 * Now expand any escape sequences in the string, storing the final
	 * text in 'buf' in wide-character format, and then convert it back
	 * to multi-byte for return.  We expand the following sequences:
	 *
	 * %%   - literal % character
	 * %s   - base URL for knowledge articles
	 * %<x> - expression x in the current event, if any
	 *
	 * If an invalid sequence is present, it is elided so we can safely
	 * reserve any future characters for other types of expansions.
	 */
	fmd_msg_buf_init(&buf);

	for (q = w, p = w; (p = wcschr(p, L'%')) != NULL; q = p) {
		if (p > q)
			fmd_msg_buf_write(&buf, q, (size_t)(p - q));

		switch (p[1]) {
		case L'%':
			fmd_msg_buf_write(&buf, p, 1);
			p += 2;
			break;

		case L's':
			fmd_msg_buf_write(&buf, u, wcslen(u));
			fmd_msg_buf_write(&buf, c, wcslen(c));

			p += 2;
			break;

		case L'<':
			q = p + 2;
			p = wcschr(p + 2, L'>');

			if (p == NULL)
				goto eos;

			/*
			 * The expression in %< > must be an ASCII string: as
			 * such allocate its length in bytes plus an extra
			 * MB_CUR_MAX for slop if a multi-byte character is in
			 * there, plus another byte for \0.  Since we move a
			 * byte at a time, any multi-byte chars will just be
			 * silently overwritten and fail to parse, which is ok.
			 */
			elen = (size_t)(p - q);
			expr = malloc(elen + MB_CUR_MAX + 1);

			if (expr == NULL) {
				buf.fmb_error = ENOMEM;
				goto eos;
			}

			for (i = 0; i < elen; i++)
				(void) wctomb(&expr[i], q[i]);

			expr[i] = '\0';

			if (nvl != NULL)
				(void) fmd_msg_nv_parse_nvname(&buf, nvl, expr);
			else
				fmd_msg_buf_printf(&buf, "%%<%s>", expr);

			free(expr);
			p++;
			break;

		case L'\0':
			goto eos;

		default:
			p += 2;
			break;
		}
	}
eos:
	fmd_msg_buf_write(&buf, q, wcslen(q) + 1);

	free(c);
	free(u);
	free(w);

	s = fmd_msg_buf_read(&buf);
	fmd_msg_buf_fini(&buf);

	return (s);
}

/*
 * This is a private interface used by the notification daemons to parse tokens
 * in user-supplied message templates.
 */
char *
fmd_msg_decode_tokens(nvlist_t *nvl, const char *msg, const char *url)
{
	fmd_msg_buf_t buf;
	wchar_t *h, *u, *w, *p, *q;

	char *s, *expr, host[MAXHOSTNAMELEN + 1];
	size_t elen;
	int i;

	u = fmd_msg_mbstowcs(url);

	(void) gethostname(host, MAXHOSTNAMELEN + 1);
	h = fmd_msg_mbstowcs(host);

	if ((w = fmd_msg_mbstowcs(msg)) == NULL)
		return (NULL);

	/*
	 * Now expand any escape sequences in the string, storing the final
	 * text in 'buf' in wide-character format, and then convert it back
	 * to multi-byte for return.  We expand the following sequences:
	 *
	 * %%   - literal % character
	 * %h   - hostname
	 * %s   - base URL for knowledge articles
	 * %<x> - expression x in the current event, if any
	 *
	 * If an invalid sequence is present, it is elided so we can safely
	 * reserve any future characters for other types of expansions.
	 */
	fmd_msg_buf_init(&buf);

	for (q = w, p = w; (p = wcschr(p, L'%')) != NULL; q = p) {
		if (p > q)
			fmd_msg_buf_write(&buf, q, (size_t)(p - q));

		switch (p[1]) {
		case L'%':
			fmd_msg_buf_write(&buf, p, 1);
			p += 2;
			break;

		case L'h':
			if (h != NULL)
				fmd_msg_buf_write(&buf, h, wcslen(h));

			p += 2;
			break;

		case L's':
			if (u != NULL)
				fmd_msg_buf_write(&buf, u, wcslen(u));

			p += 2;
			break;

		case L'<':
			q = p + 2;
			p = wcschr(p + 2, L'>');

			if (p == NULL)
				goto eos;

			/*
			 * The expression in %< > must be an ASCII string: as
			 * such allocate its length in bytes plus an extra
			 * MB_CUR_MAX for slop if a multi-byte character is in
			 * there, plus another byte for \0.  Since we move a
			 * byte at a time, any multi-byte chars will just be
			 * silently overwritten and fail to parse, which is ok.
			 */
			elen = (size_t)(p - q);
			expr = malloc(elen + MB_CUR_MAX + 1);

			if (expr == NULL) {
				buf.fmb_error = ENOMEM;
				goto eos;
			}

			for (i = 0; i < elen; i++)
				(void) wctomb(&expr[i], q[i]);

			expr[i] = '\0';

			if (nvl != NULL)
				(void) fmd_msg_nv_parse_nvname(&buf, nvl, expr);
			else
				fmd_msg_buf_printf(&buf, "%%<%s>", expr);

			free(expr);
			p++;
			break;

		case L'\0':
			goto eos;

		default:
			p += 2;
			break;
		}
	}
eos:
	fmd_msg_buf_write(&buf, q, wcslen(q) + 1);

	free(h);
	free(u);
	free(w);

	s = fmd_msg_buf_read(&buf);
	fmd_msg_buf_fini(&buf);

	return (s);
}

/*
 * This function is the main engine for formatting an entire event message.
 * It retrieves the master format string for an event, formats the individual
 * items, and then produces the final string composing all of the items.  The
 * result is a newly-allocated multi-byte string of the localized message
 * text, or NULL with errno set if an error occurred.
 */
static char *
fmd_msg_gettext_locked(fmd_msg_hdl_t *h,
    nvlist_t *nvl, const char *dict, const char *code)
{
	char *items[FMD_MSG_ITEM_MAX];
	const char *format;
	char *buf = NULL;
	size_t len;
	int i;

	nvlist_t *fmri, *auth;
	struct tm tm, *tmp;

	int64_t *tv;
	uint_t tn = 0;
	time_t sec;
	char date[64];

	char *uuid, *src_name, *src_vers;
	char *platform, *server, *csn;

	assert(fmd_msg_lock_held(h));
	bzero(items, sizeof (items));

	for (i = 0; i < FMD_MSG_ITEM_MAX; i++) {
		items[i] = fmd_msg_getitem_locked(h, nvl, dict, code, i);
		if (items[i] == NULL)
			goto out;
	}

	/*
	 * If <dict>.mo defines an item with the key <FMD_MSG_TEMPLATE> then it
	 * is used as the format; otherwise the default from FMD.mo is used.
	 */
	if ((format = dgettext(dict, FMD_MSG_TEMPLATE)) == FMD_MSG_TEMPLATE)
		format = h->fmh_template;

	if (nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid) != 0)
		uuid = (char *)FMD_MSG_MISSING;

	if (nvlist_lookup_int64_array(nvl, FM_SUSPECT_DIAG_TIME,
	    &tv, &tn) == 0 && tn == 2 && (sec = (time_t)tv[0]) != (time_t)-1 &&
	    (tmp = localtime_r(&sec, &tm)) != NULL)
		(void) strftime(date, sizeof (date), "%a %b %e %H:%M:%S %Z %Y",
		    tmp);
	else
		(void) strlcpy(date, FMD_MSG_MISSING, sizeof (date));

	/*
	 * Extract the relevant identifying elements of the FMRI and authority.
	 * Note: for now, we ignore FM_FMRI_AUTH_DOMAIN (only for SPs).
	 */
	if (nvlist_lookup_nvlist(nvl, FM_SUSPECT_DE, &fmri) != 0)
		fmri = NULL;

	if (nvlist_lookup_nvlist(fmri, FM_FMRI_AUTHORITY, &auth) != 0)
		auth = NULL;

	if (nvlist_lookup_string(fmri, FM_FMRI_FMD_NAME, &src_name) != 0)
		src_name = (char *)FMD_MSG_MISSING;

	if (nvlist_lookup_string(fmri, FM_FMRI_FMD_VERSION, &src_vers) != 0)
		src_vers = (char *)FMD_MSG_MISSING;

	if (nvlist_lookup_string(auth, FM_FMRI_AUTH_PRODUCT, &platform) != 0)
		platform = (char *)FMD_MSG_MISSING;

	if (nvlist_lookup_string(auth, FM_FMRI_AUTH_SERVER, &server) != 0)
		server = (char *)FMD_MSG_MISSING;

	if (nvlist_lookup_string(auth, FM_FMRI_AUTH_PRODUCT_SN, &csn) != 0 &&
	    nvlist_lookup_string(auth, FM_FMRI_AUTH_CHASSIS, &csn) != 0)
		csn = (char *)FMD_MSG_MISSING;

	/*
	 * Format the message once to get its length, allocate a buffer, and
	 * then format the message again into the buffer to return it.
	 */
	len = snprintf(NULL, 0, format, code,
	    items[FMD_MSG_ITEM_TYPE], items[FMD_MSG_ITEM_SEVERITY],
	    date, platform, csn, server, src_name, src_vers, uuid,
	    items[FMD_MSG_ITEM_DESC], items[FMD_MSG_ITEM_RESPONSE],
	    items[FMD_MSG_ITEM_IMPACT], items[FMD_MSG_ITEM_ACTION]);

	if ((buf = malloc(len + 1)) == NULL) {
		errno = ENOMEM;
		goto out;
	}

	(void) snprintf(buf, len + 1, format, code,
	    items[FMD_MSG_ITEM_TYPE], items[FMD_MSG_ITEM_SEVERITY],
	    date, platform, csn, server, src_name, src_vers, uuid,
	    items[FMD_MSG_ITEM_DESC], items[FMD_MSG_ITEM_RESPONSE],
	    items[FMD_MSG_ITEM_IMPACT], items[FMD_MSG_ITEM_ACTION]);
out:
	for (i = 0; i < FMD_MSG_ITEM_MAX; i++)
		free(items[i]);

	return (buf);
}

/*
 * Common code for fmd_msg_getitem_nv() and fmd_msg_getitem_id(): this function
 * handles locking, changing locales and domains, and restoring i18n state.
 */
static char *
fmd_msg_getitem(fmd_msg_hdl_t *h,
    const char *locale, nvlist_t *nvl, const char *code, fmd_msg_item_t item)
{
	char *old_b, *old_c;
	char *dict, *key, *p, *s;
	size_t len;
	int err;

	if ((p = strchr(code, '-')) == NULL || p == code) {
		errno = EINVAL;
		return (NULL);
	}

	if (locale != NULL && strcmp(h->fmh_locale, locale) == 0)
		locale = NULL; /* simplify later tests */

	dict = strndupa(code, p - code);

	fmd_msg_lock();

	/*
	 * If a non-default text domain binding was requested, save the old
	 * binding perform the re-bind now that fmd_msg_lock() is held.
	 */
	if (h->fmh_binding != NULL) {
		p = bindtextdomain(dict, NULL);
		old_b = strdupa(p);
		(void) bindtextdomain(dict, h->fmh_binding);
	}

	/*
	 * Compute the lookup code for FMD_MSG_ITEM_TYPE: we'll use this to
	 * determine if the dictionary contains any data for this code at all.
	 */
	len = strlen(code) + 1 + strlen(fmd_msg_items[FMD_MSG_ITEM_TYPE]) + 1;
	key = alloca(len);

	(void) snprintf(key, len, "%s.%s",
	    code, fmd_msg_items[FMD_MSG_ITEM_TYPE]);

	/*
	 * Save the current locale string, and if we've been asked to fetch
	 * the text for a different locale, switch locales now under the lock.
	 */
	p = setlocale(LC_ALL, NULL);
	old_c = strdupa(p);

	if (locale != NULL)
		(void) setlocale(LC_ALL, locale);

	/*
	 * Prefetch the first item: if this isn't found, and we're in a non-
	 * default locale, attempt to fall back to the C locale for this code.
	 */
	if (dgettext(dict, key) == key &&
	    (locale != NULL || strcmp(h->fmh_locale, "C") != 0)) {
		(void) setlocale(LC_ALL, "C");
		locale = "C"; /* restore locale */
	}

	if (dgettext(dict, key) == key) {
		s = NULL;
		err = ENOENT;
	} else {
		s = fmd_msg_getitem_locked(h, nvl, dict, code, item);
		err = errno;
	}

	if (locale != NULL)
		(void) setlocale(LC_ALL, old_c);

	if (h->fmh_binding != NULL)
		(void) bindtextdomain(dict, old_b);

	fmd_msg_unlock();

	if (s == NULL)
		errno = err;

	return (s);
}

char *
fmd_msg_getitem_nv(fmd_msg_hdl_t *h,
    const char *locale, nvlist_t *nvl, fmd_msg_item_t item)
{
	char *code;

	if (item >= FMD_MSG_ITEM_MAX) {
		errno = EINVAL;
		return (NULL);
	}

	if (nvlist_lookup_string(nvl, FM_SUSPECT_DIAG_CODE, &code) != 0) {
		errno = EINVAL;
		return (NULL);
	}

	return (fmd_msg_getitem(h, locale, nvl, code, item));
}

char *
fmd_msg_getitem_id(fmd_msg_hdl_t *h,
    const char *locale, const char *code, fmd_msg_item_t item)
{
	if (item >= FMD_MSG_ITEM_MAX) {
		errno = EINVAL;
		return (NULL);
	}

	return (fmd_msg_getitem(h, locale, NULL, code, item));
}

char *
fmd_msg_gettext_key(fmd_msg_hdl_t *h,
    const char *locale, const char *dict, const char *key)
{
	char *old_b, *old_c, *p, *s;

	fmd_msg_lock();

	/*
	 * If a non-default text domain binding was requested, save the old
	 * binding perform the re-bind now that fmd_msg_lock() is held.
	 */
	if (h->fmh_binding != NULL) {
		p = bindtextdomain(dict, NULL);
		old_b = alloca(strlen(p) + 1);
		(void) strcpy(old_b, p);
		(void) bindtextdomain(dict, h->fmh_binding);
	}

	/*
	 * Save the current locale string, and if we've been asked to fetch
	 * the text for a different locale, switch locales now under the lock.
	 */
	p = setlocale(LC_ALL, NULL);
	old_c = alloca(strlen(p) + 1);
	(void) strcpy(old_c, p);

	if (locale != NULL)
		(void) setlocale(LC_ALL, locale);

	/*
	 * First attempt to fetch the string in the current locale.  If this
	 * fails and we're in a non-default locale, attempt to fall back to the
	 * C locale and try again.  If it still fails then we return NULL and
	 * set errno.
	 */
	if ((s = dgettext(dict, key)) == key &&
	    (locale != NULL || strcmp(h->fmh_locale, "C") != 0)) {
		(void) setlocale(LC_ALL, "C");
		locale = "C"; /* restore locale */

		if ((s = dgettext(dict, key)) == key) {
			s = NULL;
			errno = ENOENT;
		}
	}
	if (locale != NULL)
		(void) setlocale(LC_ALL, old_c);

	if (h->fmh_binding != NULL)
		(void) bindtextdomain(dict, old_b);

	fmd_msg_unlock();

	return (s);
}

/*
 * Common code for fmd_msg_gettext_nv() and fmd_msg_gettext_id(): this function
 * handles locking, changing locales and domains, and restoring i18n state.
 */
static char *
fmd_msg_gettext(fmd_msg_hdl_t *h,
    const char *locale, nvlist_t *nvl, const char *code)
{
	char *old_b, *old_c;
	char *dict, *key, *p, *s;
	size_t len;
	int err;

	if ((p = strchr(code, '-')) == NULL || p == code) {
		errno = EINVAL;
		return (NULL);
	}

	if (locale != NULL && strcmp(h->fmh_locale, locale) == 0)
		locale = NULL; /* simplify later tests */

	dict = strndupa(code, p - code);

	fmd_msg_lock();

	/*
	 * If a non-default text domain binding was requested, save the old
	 * binding perform the re-bind now that fmd_msg_lock() is held.
	 */
	if (h->fmh_binding != NULL) {
		p = bindtextdomain(dict, NULL);
		old_b = strdupa(p);
		(void) bindtextdomain(dict, h->fmh_binding);
	}

	/*
	 * Compute the lookup code for FMD_MSG_ITEM_TYPE: we'll use this to
	 * determine if the dictionary contains any data for this code at all.
	 */
	len = strlen(code) + 1 + strlen(fmd_msg_items[FMD_MSG_ITEM_TYPE]) + 1;
	key = alloca(len);

	(void) snprintf(key, len, "%s.%s",
	    code, fmd_msg_items[FMD_MSG_ITEM_TYPE]);

	/*
	 * Save the current locale string, and if we've been asked to fetch
	 * the text for a different locale, switch locales now under the lock.
	 */
	p = setlocale(LC_ALL, NULL);
	old_c = strdupa(p);

	if (locale != NULL)
		(void) setlocale(LC_ALL, locale);

	/*
	 * Prefetch the first item: if this isn't found, and we're in a non-
	 * default locale, attempt to fall back to the C locale for this code.
	 */
	if (dgettext(dict, key) == key &&
	    (locale != NULL || strcmp(h->fmh_locale, "C") != 0)) {
		(void) setlocale(LC_ALL, "C");
		locale = "C"; /* restore locale */
	}

	if (dgettext(dict, key) == key) {
		s = NULL;
		err = ENOENT;
	} else {
		s = fmd_msg_gettext_locked(h, nvl, dict, code);
		err = errno;
	}

	if (locale != NULL)
		(void) setlocale(LC_ALL, old_c);

	if (h->fmh_binding != NULL)
		(void) bindtextdomain(dict, old_b);

	fmd_msg_unlock();

	if (s == NULL)
		errno = err;

	return (s);
}

char *
fmd_msg_gettext_nv(fmd_msg_hdl_t *h, const char *locale, nvlist_t *nvl)
{
	char *code;

	if (nvlist_lookup_string(nvl, FM_SUSPECT_DIAG_CODE, &code) != 0) {
		errno = EINVAL;
		return (NULL);
	}

	return (fmd_msg_gettext(h, locale, nvl, code));
}

char *
fmd_msg_gettext_id(fmd_msg_hdl_t *h, const char *locale, const char *code)
{
	return (fmd_msg_gettext(h, locale, NULL, code));
}
