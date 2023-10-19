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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SORT_TYPES_H
#define	_SORT_TYPES_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/resource.h>
#include <sys/types.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

typedef	int flag_t;

typedef	int (*cmp_fcn_t)(void *, void *, flag_t);

typedef union vchar {
	char	sc;
	uchar_t	usc;
	wchar_t	wc;
} vchar_t;

typedef union vcharptr {
	char	*sp;
	uchar_t	*usp;
	wchar_t *wp;
} vcharptr_t;

typedef struct line_rec {
	vcharptr_t l_data;		/* raw data */
	vcharptr_t l_raw_collate;	/* collatable raw data */
	vcharptr_t l_collate;		/* key-ordered collatable string */
	ssize_t	l_data_length;
	ssize_t	l_collate_length;
	ssize_t	l_collate_bufsize;
} line_rec_t;

enum field_species {
	ALPHA,
	MONTH,
	NUMERIC
};

#define	FIELD_DICTIONARY_ORDER		0x1
#define	FIELD_FOLD_UPPERCASE		0x2
#define	FIELD_IGNORE_NONPRINTABLES	0x4
#define	FIELD_IGNORE_BLANKS_START	0x8
#define	FIELD_IGNORE_BLANKS_END		0x10

#define	FIELD_REVERSE_COMPARISONS	0x20

#define	FIELD_MODIFIERS_DEFINED		0x40

typedef struct field {
	struct field		*f_next;

	/*
	 * field ops vector
	 */
	ssize_t			(*f_convert)(struct field *, line_rec_t *,
	    vchar_t, ssize_t, ssize_t, ssize_t);
	enum field_species	f_species;

	/*
	 * starting and ending fields, and offsets
	 */
	int			f_start_field;
	ssize_t			f_start_offset;

	int			f_end_field;
	ssize_t			f_end_offset;

	flag_t			f_options;
} field_t;

#define	STREAM_SOURCE_MASK	0x000f
#define	STREAM_NO_SOURCE	0x0000
#define	STREAM_ARRAY		0x0001
#define	STREAM_MMAP		0x0002
#define	STREAM_SINGLE		0x0004
#define	STREAM_WIDE		0x0008

#define	STREAM_OPEN		0x0010
#define	STREAM_PRIMED		0x0020

#define	STREAM_OUTPUT		0x0040
#define	STREAM_EOS_REACHED	0x0080
#define	STREAM_NOTFILE		0x0100
#define	STREAM_UNIQUE		0x0200
#define	STREAM_INSTANT		0x0400
#define	STREAM_TEMPORARY	0x0800
#define	STREAM_NOT_FREEABLE	0x1000

#define	DEFAULT_INPUT_SIZE	(1 * MEGABYTE)
#define	DEFAULT_RELEASE_SIZE	(MEGABYTE / 2)

#define	CHAR_AVG_LINE	32
#define	WCHAR_AVG_LINE	(sizeof (wchar_t) * CHAR_AVG_LINE)
#define	XFRM_MULTIPLIER	8

#define	NEXT_LINE_COMPLETE	0x0
#define	NEXT_LINE_INCOMPLETE	0x1

#define	PRIME_SUCCEEDED		0x0
#define	PRIME_FAILED_EMPTY_FILE	0x1
#define	PRIME_FAILED		0x2

typedef struct stream_array {
	line_rec_t	**s_array;
	ssize_t		s_array_size;
	ssize_t		s_cur_index;
} stream_array_t;

typedef struct stream_simple_file {
	/*
	 * stream_simple_file_t is used for STREAM_MMAP and for STREAM_OUTPUT
	 * for either single- (STREAM_SINGLE | STREAM_OUTPUT) or multi-byte
	 * (STREAM_WIDE | STREAM_OUTPUT) locales.
	 */
	int		s_fd;			/* file descriptor */
	caddr_t		s_release_origin;	/* start for next madvise(3C) */
} stream_simple_file_t;

typedef struct stream_buffered_file {
	/*
	 * stream_buffered_file_t is used for both STREAM_STDIO and
	 * STREAM_WIDE.
	 */
	FILE		*s_fp;			/* file stream */
	void		*s_vbuf;		/* stdio alternate buffer */
	size_t		s_bytes_used;
} stream_buffered_file_t;

typedef union stream_type {
	stream_array_t		LA;	/* array of line records */
	stream_simple_file_t	SF;	/* file accessed via mmap */
	stream_buffered_file_t	BF;	/* file accessed via stdio */
} stream_type_t;

struct stream;

typedef struct stream_ops {
	int	(*sop_is_closable)(struct stream *);
	int	(*sop_close)(struct stream *);
	int	(*sop_eos)(struct stream *);
	ssize_t	(*sop_fetch)(struct stream *);
	void	(*sop_flush)(struct stream *);
	int	(*sop_free)(struct stream *);
	int	(*sop_open_for_write)(struct stream *);
	int	(*sop_prime)(struct stream *);
	void	(*sop_put_line)(struct stream *, line_rec_t *);
	void	(*sop_release_line)(struct stream *);
	void	(*sop_send_eol)(struct stream *);
	int	(*sop_unlink)(struct stream *);
} stream_ops_t;

#define	SOP_IS_CLOSABLE(s)	((s)->s_ops.sop_is_closable)(s)
#define	SOP_CLOSE(s)		((s)->s_ops.sop_close)(s)
#define	SOP_EOS(s)		((s)->s_ops.sop_eos)(s)
#define	SOP_FETCH(s)		((s)->s_ops.sop_fetch)(s)
#define	SOP_FLUSH(s)		((s)->s_ops.sop_flush)(s)
#define	SOP_FREE(s)		((s)->s_ops.sop_free)(s)
#define	SOP_OPEN_FOR_WRITE(s)	((s)->s_ops.sop_open_for_write)(s)
#define	SOP_PRIME(s)		((s)->s_ops.sop_prime)(s)
#define	SOP_PUT_LINE(s, l)	((s)->s_ops.sop_put_line)(s, l)
#define	SOP_RELEASE_LINE(s)	((s)->s_ops.sop_release_line)(s)
#define	SOP_SEND_EOL(s)		((s)->s_ops.sop_send_eol)(s)
#define	SOP_UNLINK(s)		((s)->s_ops.sop_unlink)(s)

/*
 * The stream_t type is provided to simplify access to files, particularly for
 * external merges.
 */
typedef struct stream {
	struct stream	*s_consumer;	/* dependent on s_buffer */
	struct stream	*s_previous;
	struct stream	*s_next;

	char		*s_filename;

	line_rec_t	s_current;	/* present line buffers */
	stream_ops_t	s_ops;		/* type-specific ops vector */
	stream_type_t	s_type;		/* type-specific attributes */

	void		*s_buffer;
	size_t		s_buffer_size;
	off_t		s_filesize;
	size_t		s_element_size;
	flag_t		s_status;	/* flags */
	ino_t		s_ino;
	dev_t		s_dev;
} stream_t;

/*
 * sort(1) has, for debugging purposes, a primitive compile-time option to
 * generate statistics of various operations executed during an invocation.
 * These statistics are recorded in the following sort_statistics_t structure.
 */
typedef struct sort_statistics {
	u_longlong_t	st_avail_mem;
	u_longlong_t	st_convert_reallocs;
	u_longlong_t	st_fetched_lines;
	u_longlong_t	st_insert_full_down;
	u_longlong_t	st_insert_full_input;
	u_longlong_t	st_insert_full_up;
	u_longlong_t	st_line_conversions;
	u_longlong_t	st_not_unique_lines;
	u_longlong_t	st_put_lines;
	u_longlong_t	st_put_temp_lines_internal;
	u_longlong_t	st_put_temp_lines_merge;
	u_longlong_t	st_put_unique_lines;
	u_longlong_t	st_shelved_lines;
	u_longlong_t	st_subfiles;		/* number of insertion sorts */
	u_longlong_t	st_swaps;
	u_longlong_t	st_tqs_calls;

	uint_t		st_input_files;
	uint_t		st_merge_files;
} sort_statistics_t;

typedef struct sort {
	stream_t	*m_input_streams;
	char		*m_output_filename;

	stream_t	*m_temporary_streams;
	char		*m_tmpdir_template;

	field_t		*m_fields_head;

	cmp_fcn_t	m_compare_fn;
	ssize_t		(*m_coll_convert)(field_t *, line_rec_t *, flag_t,
	    vchar_t);

	sort_statistics_t *m_stats;
	size_t		m_memory_limit;
	size_t		m_memory_available;

	flag_t		m_check_if_sorted_only;
	flag_t		m_merge_only;
	flag_t		m_unique_lines;
	flag_t		m_entire_line;

	enum field_species m_default_species;
	flag_t		m_field_options;
	vchar_t		m_field_separator;

	flag_t		m_c_locale;
	flag_t		m_single_byte_locale;
	flag_t		m_input_from_stdin;
	flag_t		m_output_to_stdout;
	flag_t		m_verbose;
} sort_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SORT_TYPES_H */
