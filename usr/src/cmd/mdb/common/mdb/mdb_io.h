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
 *
 * Copyright 2020 Joyent, Inc.
 */

#ifndef	_MDB_IO_H
#define	_MDB_IO_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

#include <sys/types.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>

typedef struct mdb_iob mdb_iob_t;	/* I/O buffer */
typedef struct mdb_io mdb_io_t;		/* I/O implementation */
struct mdb_arg;				/* Argument structure */

#define	MDB_IOB_DEFTAB		8	/* Default tabstop */
#define	MDB_IOB_DEFMARGIN	16	/* Default margin width */
#define	MDB_IOB_DEFROWS		24	/* Default rows */
#define	MDB_IOB_DEFCOLS		80	/* Default columns */

#define	MDB_IOB_RDONLY		0x0001	/* Buffer is for reading */
#define	MDB_IOB_WRONLY		0x0002	/* Buffer is for writing */
#define	MDB_IOB_EOF		0x0004	/* Read buffer has reached EOF */
#define	MDB_IOB_ERR		0x0008	/* Underlying i/o error occurred */
#define	MDB_IOB_INDENT		0x0010	/* Lines are auto-indented */
#define	MDB_IOB_PGENABLE	0x0020	/* Pager enabled */
#define	MDB_IOB_PGSINGLE	0x0040	/* Line-at-a-time pager active */
#define	MDB_IOB_PGCONT		0x0080	/* Continue paging until next reset */
#define	MDB_IOB_AUTOWRAP	0x0100	/* Auto-wrap if next chunk won't fit */
#define	MDB_IOB_TTYLIKE		0x0200	/* Input is interactive like a tty */

typedef struct mdb_iob_stack {
	mdb_iob_t *stk_top;		/* Topmost stack element */
	size_t stk_size;		/* Number of stack elements */
} mdb_iob_stack_t;

typedef struct mdb_iob_ctx {
	jmp_buf ctx_rpcb;		/* Read-side context label */
	jmp_buf ctx_wpcb;		/* Write-side context label */
	void *ctx_rptr;			/* Read-side client data */
	void *ctx_wptr;			/* Write-side client data */
	void *ctx_data;			/* Pointer to client data */
	mdb_iob_t *ctx_iob;		/* Storage for iob save/restore */
} mdb_iob_ctx_t;

#define	MDB_IOB_RDIOB	0		/* Index for pipe's read-side iob */
#define	MDB_IOB_WRIOB	1		/* Index for pipe's write-side iob */

typedef void mdb_iobsvc_f(mdb_iob_t *, mdb_iob_t *, mdb_iob_ctx_t *);

#define	MDBIOC		(('m' << 24) | ('d' << 16) | ('b' << 8))

#define	MDB_IOC_CTTY	(MDBIOC | 0x01)	/* Clear child tty settings */
#define	MDB_IOC_TSET	(MDBIOC | 0x02)	/* Set terminal type */
#define	MDB_IOC_GETFD	(MDBIOC | 0x04) /* Get file descriptor (if any) */


typedef void mdb_table_print_f(void *);

#define	MDB_TBL_DONE	0
#define	MDB_TBL_PRNT	1
#define	MDB_TBL_FUNC	2

extern mdb_io_t *mdb_io_hold(mdb_io_t *);
extern void mdb_io_rele(mdb_io_t *);
extern void mdb_io_destroy(mdb_io_t *);

extern mdb_iob_t *mdb_iob_create(mdb_io_t *, uint_t);
extern void mdb_iob_pipe(mdb_iob_t **, mdb_iobsvc_f *, mdb_iobsvc_f *);
extern void mdb_iob_destroy(mdb_iob_t *);

extern void mdb_iob_flush(mdb_iob_t *);
extern void mdb_iob_nlflush(mdb_iob_t *);
extern void mdb_iob_discard(mdb_iob_t *);

extern void mdb_iob_push_io(mdb_iob_t *, mdb_io_t *);
extern mdb_io_t *mdb_iob_pop_io(mdb_iob_t *);

extern void mdb_iob_resize(mdb_iob_t *, size_t, size_t);
extern void mdb_iob_setpager(mdb_iob_t *, mdb_io_t *);
extern void mdb_iob_clearlines(mdb_iob_t *);
extern void mdb_iob_tabstop(mdb_iob_t *, size_t);
extern void mdb_iob_margin(mdb_iob_t *, size_t);
extern void mdb_iob_setbuf(mdb_iob_t *, void *, size_t);

extern void mdb_iob_setflags(mdb_iob_t *, uint_t);
extern void mdb_iob_clrflags(mdb_iob_t *, uint_t);
extern uint_t mdb_iob_getflags(mdb_iob_t *);

extern void mdb_iob_vprintf(mdb_iob_t *, const char *, va_list);
extern void mdb_iob_aprintf(mdb_iob_t *, const char *, const struct mdb_arg *);
extern void mdb_iob_printf(mdb_iob_t *, const char *, ...);

extern size_t mdb_iob_vsnprintf(char *, size_t, const char *, va_list);
extern size_t mdb_iob_asnprintf(char *, size_t, const char *,
    const struct mdb_arg *);
extern size_t mdb_iob_snprintf(char *, size_t, const char *, ...);

extern void mdb_iob_nputs(mdb_iob_t *, const char *, size_t);
extern void mdb_iob_puts(mdb_iob_t *, const char *);
extern void mdb_iob_putc(mdb_iob_t *, int);

extern void mdb_iob_fill(mdb_iob_t *, int, size_t);
extern void mdb_iob_ws(mdb_iob_t *, size_t);
extern void mdb_iob_tab(mdb_iob_t *);
extern void mdb_iob_nl(mdb_iob_t *);

extern ssize_t mdb_iob_ngets(mdb_iob_t *, char *, size_t);
extern int mdb_iob_getc(mdb_iob_t *);
extern int mdb_iob_ungetc(mdb_iob_t *, int);
extern int mdb_iob_eof(mdb_iob_t *);
extern int mdb_iob_err(mdb_iob_t *);

extern ssize_t mdb_iob_read(mdb_iob_t *, void *, size_t);
extern ssize_t mdb_iob_write(mdb_iob_t *, const void *, size_t);
extern int mdb_iob_ctl(mdb_iob_t *, int, void *);
extern const char *mdb_iob_name(mdb_iob_t *);
extern size_t mdb_iob_lineno(mdb_iob_t *);
extern size_t mdb_iob_gettabstop(mdb_iob_t *);
extern size_t mdb_iob_getmargin(mdb_iob_t *);

extern void mdb_iob_set_autowrap(mdb_iob_t *);

extern void mdb_iob_stack_create(mdb_iob_stack_t *);
extern void mdb_iob_stack_destroy(mdb_iob_stack_t *);
extern void mdb_iob_stack_push(mdb_iob_stack_t *, mdb_iob_t *, size_t);
extern mdb_iob_t *mdb_iob_stack_pop(mdb_iob_stack_t *);
extern size_t mdb_iob_stack_size(mdb_iob_stack_t *);

extern const char *mdb_iob_format2str(const char *);

/*
 * Available i/o backend constructors for common MDB code.  These are
 * implemented in the corresponding .c files.
 */
extern mdb_io_t *mdb_logio_create(mdb_io_t *);
extern mdb_io_t *mdb_fdio_create_path(const char **, const char *, int, mode_t);
extern mdb_io_t *mdb_fdio_create_named(int fd, const char *);
extern mdb_io_t *mdb_fdio_create(int);
extern mdb_io_t *mdb_strio_create(const char *);
extern mdb_io_t *mdb_termio_create(const char *, mdb_io_t *, mdb_io_t *);
extern mdb_io_t *mdb_pipeio_create(mdb_iobsvc_f *, mdb_iobsvc_f *);
extern mdb_io_t *mdb_nullio_create(void);
extern mdb_io_t *mdb_memio_create(char *, size_t);

/*
 * Functions for testing whether the given iob is of a given backend type:
 */
extern int mdb_iob_isastr(mdb_iob_t *);
extern int mdb_iob_isatty(mdb_iob_t *);
extern int mdb_iob_isapipe(mdb_iob_t *);

extern void mdb_table_print(uint_t, const char *, ...);

extern int mdb_setupterm(const char *, mdb_io_t *, int *);

extern int mdb_fdio_fileno(mdb_io_t *);

#endif /* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_IO_H */
