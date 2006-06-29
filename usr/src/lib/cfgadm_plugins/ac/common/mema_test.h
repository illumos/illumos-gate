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
 * Copyright (c) 1996-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MEMA_TEST_H
#define	_MEMA_TEST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

struct mtest_alloc_ent {
	struct mtest_alloc_ent	*next;
	void			*buf;
};

struct mtest_handle {
	u_longlong_t		bank_size;
	ulong_t			page_size;
	ulong_t			line_size;
	ulong_t			lines_per_page;
	cfga_cond_t		condition;
	int			fd;
	ulong_t			max_errors;
	struct mtest_alloc_ent	*alloc_list;
	void			*drvhandle;
	struct cfga_msg		*msgp;
};

typedef struct mtest_handle *mtest_handle_t;

typedef int mtest_func_t(mtest_handle_t);

struct mtest_table_ent {
	const char	*test_name;
	mtest_func_t	*test_func;
};
extern struct mtest_table_ent mtest_table[];
#define	MTEST_DEFAULT_TEST	(0)
extern char **mtest_build_opts(int *maxerr_idx);

#define	BANK_SIZE(H)		((H)->bank_size)
#define	PAGE_SIZE(H)		((H)->page_size)
#define	LINE_SIZE(H)		((H)->line_size)
#define	LINES_PER_PAGE(H)	((H)->lines_per_page)
#define	SET_CONDITION(H, C)	((H)->condition = (C))

struct mtest_error {
	int		error_type;
};

/*
 * Error types.
 */
#define	MTEST_ERR_NONE		0
#define	MTEST_ERR_UE		1
#define	MTEST_ERR_CE		2

/*
 * Test routine return codes.
 */
#define	MTEST_DONE		0
#define	MTEST_LIB_ERROR		1
#define	MTEST_DEV_ERROR		2

/*
 * Each test is allowed maximum number of errors and the index has
 * to be coordinated with the token table size in mema_test_config.c
 */
#define	MAX_ERRORS		32
#define	REPORT_SEC		5

/*
 * Test functions should use this buffer allocation interface.
 * The test framework will deallocate them on return.
 */
extern void *mtest_allocate_buf(mtest_handle_t, size_t);
#define	mtest_allocate_page_buf(H)	mtest_allocate_buf((H), \
					(size_t)PAGE_SIZE(H))
extern void mtest_deallocate_buf(mtest_handle_t, void *);
extern void mtest_deallocate_buf_all(mtest_handle_t);

/*
 * Test write: mtest_write(handle, buffer, page_num, line_offset, line_count)
 * A line count of 0 indicates the whole page.
 * A return of 0 indicates success.  A return of -1 indicates a failure of
 * the device interface.
 */
extern int mtest_write(mtest_handle_t, void *, u_longlong_t, uint_t, uint_t);
extern int mtest_read(mtest_handle_t, void *, u_longlong_t, uint_t, uint_t,
    struct mtest_error *);

/*
 * Message interface. If the upper layer has verbose on, the
 * message will be seen by the user.
 */
extern void mtest_message(mtest_handle_t, const char *);

#ifdef __cplusplus
}
#endif

#endif /* _MEMA_TEST_H */
