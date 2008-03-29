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

#ifndef	_LIBSES_PLUGIN_H
#define	_LIBSES_PLUGIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	LIBSES_PLUGIN_VERSION	1

/*
 * These are the primary APIs for plugins to interact with libses.
 */

struct ses_plugin;
typedef struct ses_plugin ses_plugin_t;

typedef enum {
	SES_PAGE_DIAG,
	SES_PAGE_CTL
} ses_pagetype_t;

typedef struct ses_pagedesc {
	int		spd_pagenum;
	size_t		(*spd_ctl_len)(uint_t, int, size_t);
	void		*(*spd_ctl_fill)(ses_plugin_t *, void *, size_t,
	    ses_node_t *);
	void		*(*spd_index)(ses_plugin_t *, ses_node_t *,
	    void *, size_t, size_t *);
	int		spd_gcoff;
} ses_pagedesc_t;

typedef struct ses_plugin_config {
	ses_pagedesc_t	*spc_pages;
	int		(*spc_node_parse)(ses_plugin_t *, ses_node_t *);
	int		(*spc_node_ctl)(ses_plugin_t *, ses_node_t *,
	    const char *, nvlist_t *);
} ses_plugin_config_t;

extern int ses_plugin_register(ses_plugin_t *, int, ses_plugin_config_t *);

extern void *ses_plugin_page_lookup(ses_plugin_t *, ses_snap_t *, int,
    ses_node_t *, size_t *);

extern void *ses_plugin_ctlpage_lookup(ses_plugin_t *, ses_snap_t *, int,
    size_t, ses_node_t *, boolean_t);

extern void ses_plugin_setspecific(ses_plugin_t *, void *);
extern void *ses_plugin_getspecific(ses_plugin_t *);

/*
 * The following are support functions provided by libses.
 */

extern int ses_assert(const char *, const char *, int);

#define	VERIFY(x)	((void)((x) || ses_assert(#x, __FILE__, __LINE__)))

#ifdef DEBUG
#define	ASSERT(x)	VERIFY(x)
#else
#define	ASSERT(x)
#endif

#define	SES_NV_ADD(_t, _e, _l, _n, ...)	\
	if (((_e) = nvlist_add_##_t((_l), (_n), __VA_ARGS__)) != 0) \
	    return (ses_set_nverrno((_e), (_n)))

#define	SES_NV_ADD_OR_FREE(_t, _e, _l, _n, ...)	\
	if (((_e) = nvlist_add_##_t((_l), (_n), __VA_ARGS__)) != 0) { \
	    nvlist_free(_l); return (ses_set_nverrno((_e), (_n))); }

#define	SES_NV_ADD_FS(_e, _l, _name, _buf)	\
	SES_NV_ADD(fixed_string, (_e), (_l), (_name), (_buf), sizeof (_buf))

#define	SES_NV_ADD_FS_TRUNC(_e, _l, _name, _buf)	\
	SES_NV_ADD(fixed_string_trunc, (_e), (_l), (_name), (_buf), \
	    sizeof (_buf))

#define	SES_NV_CTLBOOL(_l, _n, _b)	\
	{	\
		boolean_t v = B_FALSE;	\
		(void) nvlist_lookup_boolean_value((_l), (_n), &v);	\
		(_b) = v;	\
	}

#define	SES_NV_CTLBOOL_INVERT(_l, _n, _b)	\
	{	\
		boolean_t v = B_FALSE;	\
		(void) nvlist_lookup_boolean_value((_l), (_n), &v);	\
		(_b) = !v;	\
	}

#define	SES_NV_CTL64(_l, _n, _v)	\
	{	\
		uint64_t v = 0;	\
		(void) nvlist_lookup_uint64((_l), (_n), &v);	\
		(_v) = v;	\
	}

#define	SES_NV_CTL16(_l, _n, _v)	\
	{	\
		uint16_t v = 0;	\
		(void) nvlist_lookup_uint16((_l), (_n), &v);	\
		SCSI_WRITE16(&(_v), v);	\
	}

extern void *ses_alloc(size_t);
extern void *ses_zalloc(size_t);
extern char *ses_strdup(const char *);
extern void *ses_realloc(void *, size_t);
extern void ses_free(void *);

extern int ses_set_errno(ses_errno_t);
extern int ses_set_nverrno(int, const char *);
extern int ses_error(ses_errno_t, const char *, ...);
extern int ses_nverror(int, const char *, const char *, ...);
extern void ses_panic(const char *, ...) __NORETURN;

extern int nvlist_add_fixed_string(nvlist_t *, const char *,
    const char *, size_t);
extern int nvlist_add_fixed_string_trunc(nvlist_t *, const char *,
    const char *, size_t);

#define	SES_WITHIN_PAGE(sp, size, data, len)	\
	((char *)(sp) <= (char *)(data) + (len) - (size))
#define	SES_WITHIN_PAGE_STRUCT(sp, data, len)	\
	SES_WITHIN_PAGE((sp), sizeof (*(sp)), (data), (len))

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSES_PLUGIN_H */
