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
 * Copyright (c) 2019 Peter Tribble.
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * File name: praudit.h
 * praudit.c defines, globals
 */

#ifndef	_PRAUDIT_H
#define	_PRAUDIT_H

#ifdef __cplusplus
extern "C" {
#endif

/* DEFINES */

/*
 * output value types
 */
#define	PRA_INT32 0
#define	PRA_UINT32 1
#define	PRA_INT64 2
#define	PRA_UINT64 3
#define	PRA_SHORT 4
#define	PRA_USHORT 5
#define	PRA_CHAR 6
#define	PRA_UCHAR 7
#define	PRA_STRING 8
#define	PRA_HEX32 9
#define	PRA_HEX64 10
#define	PRA_SHEX 11
#define	PRA_OCT 12
#define	PRA_BYTE 13
#define	PRA_OUTREC 14
#define	PRA_LOCT 15

/*
 * Formatting flags
 */
#define	PRF_DEFAULTM	0x0000		/* Default mode */
#define	PRF_RAWM	0x0001		/* Raw mode */
#define	PRF_SHORTM	0x0002		/* Short mode */
#define	PRF_XMLM	0x0004		/* XML format */
#define	PRF_ONELINE	0x0008		/* one-line output */
#define	PRF_NOCACHE	0x0010		/* don't cache event names */

/*
 * source of audit data (data_mode)
 */
#define	FILEMODE	1
#define	PIPEMODE	2
#define	BUFMODE		3

/*
 * max. number of audit file names entered on command line
 */
#define	MAXFILENAMES 100

/*
 * max. size of file name
 */
#define	MAXFILELEN MAXPATHLEN+MAXNAMLEN+1

/*
 * used to store value to be output
 */
typedef union u_tag {
	int32_t		int32_val;
	uint32_t	uint32_val;
	int64_t		int64_val;
	uint64_t	uint64_val;
	short		short_val;
	ushort_t	ushort_val;
	char		char_val;
	char		uchar_val;
	char		*string_val;
} u_tag_t;
typedef	struct u_val {
	int	uvaltype;
	u_tag_t	tag;
} uval_t;
#define	int32_val tag.int32_val
#define	uint32_val tag.uint32_val
#define	int64_val tag.int64_val
#define	uint64_val tag.uint64_val
#define	short_val tag.short_val
#define	ushort_val tag.ushort_val
#define	char_val tag.char_val
#define	uchar_val tag.uchar_val
#define	string_val tag.string_val


/*
 * Strings and things for xml prolog & ending printing.
 */
#define	prolog1 "<?xml version='1.0' encoding='UTF-8' ?>\n"
#define	prolog2  "\n<!DOCTYPE audit PUBLIC " \
	"'-//Sun Microsystems, Inc.//DTD Audit V1//EN' " \
	"'file:///usr/share/lib/xml/dtd/adt_record.dtd.1'>\n\n"
#define	prolog_xsl "<?xml-stylesheet type='text/xsl' " \
	"href='file:///usr/share/lib/xml/style/adt_record.xsl.1' ?>\n"

	/* Special main element: */
#define	xml_start "<audit>"
#define	xml_ending "\n</audit>\n"

#define	xml_prolog_len (sizeof (prolog1) + sizeof (prolog2) + \
    sizeof (prolog_xsl) + sizeof (xml_start) + 1)
#define	xml_end_len (sizeof (xml_ending) + 1)

/*
 * used to save context for print_audit and related functions.
 */

#define	SEP_SIZE 4

struct pr_context {
	int	format;
	int	data_mode;
	char	SEPARATOR[SEP_SIZE];	/* field separator */
	signed char	tokenid;	/* initial token ID */
	adr_t	*audit_adr;		/* audit record */
	adrf_t	*audit_adrf;		/* audit record, file mode */
	int	audit_rec_len;
	char	*audit_rec_start;

	char	*inbuf_start;
	char	*inbuf_last;		/* ptr to byte after latest completed */
					/* header or file token in the input */
	int	inbuf_totalsize;
	char	*outbuf_p;
	char	*outbuf_start;
	char	*outbuf_last;		/* ptr to byte after latest completed */
					/* header or file token in the output */
	int	outbuf_remain_len;

	int	pending_flag;		/* open of extended tag not completed */
	int	current_rec;		/* id of current record */
};
typedef struct pr_context pr_context_t;


extern void	loadgroups(FILE *f);
extern void	loadnames(FILE *f);

extern void	init_tokens(void);

extern int	open_tag(pr_context_t *context, int);
extern int	finish_open_tag(pr_context_t *context);
extern int	check_close_rec(pr_context_t *context, int);
extern int	close_tag(pr_context_t *context, int);
extern int	process_tag(pr_context_t *context, int, int, int);

extern int	is_file_token(int);
extern int	is_header_token(int);
extern int	is_token(int);
extern int	do_newline(pr_context_t *context, int);

extern char	*bu2string(char basic_unit);
extern int	convert_char_to_string(char printmode, char c, char *p);
extern int	convert_int32_to_string(char printmode, int32_t c, char *p);
extern int	convert_int64_to_string(char printmode, int64_t c, char *p);
extern int	convert_short_to_string(char printmode, short c, char *p);
extern int	findfieldwidth(char basicunit, char howtoprint);
extern void	get_Hname(uint32_t addr, char *buf, size_t buflen);
extern void	get_Hname_ex(uint32_t *addr, char *buf, size_t buflen);
extern char	*hexconvert(char *c, int size, int chunk);
extern char	*htp2string(char print_sugg);
extern int	pa_print(pr_context_t *context, uval_t *uval, int flag);
extern int	pa_reclen(pr_context_t *context, int status);
extern int	pa_file_string(pr_context_t *context, int status, int flag);
extern int	pa_adr_int32(pr_context_t *context, int status, int flag);
extern int	pa_adr_int64(pr_context_t *context, int status, int flag);
extern int	pa_utime32(pr_context_t *context, int status, int flag);
extern int	pa_ntime32(pr_context_t *context, int status, int flag);
extern int	pa_utime64(pr_context_t *context, int status, int flag);
extern int	pa_ntime64(pr_context_t *context, int status, int flag);
extern int	pa_adr_string(pr_context_t *context, int status, int flag);
extern int	pa_adr_u_int32(pr_context_t *context, int status, int flag);
extern int	pa_adr_u_int64(pr_context_t *context, int status, int flag);
extern int	pa_adr_byte(pr_context_t *context, int status, int flag);
extern int	pa_event_type(pr_context_t *context, int status, int flag);
extern int	pa_event_modifier(pr_context_t *context, int status, int flag);
extern int	pa_adr_int32hex(pr_context_t *context, int status, int flag);
extern int	pa_adr_int64hex(pr_context_t *context, int status, int flag);
extern int	pa_pw_uid(pr_context_t *context, int status, int flag);
extern int	pa_gr_uid(pr_context_t *context, int status, int flag);
extern int	pa_pw_uid_gr_gid(pr_context_t *context, int status, int flag);
extern int	pa_ace(pr_context_t *context, int status, int flag);
extern int	pa_hostname(pr_context_t *context, int status, int flag);
extern int	pa_hostname_ex(pr_context_t *context, int status, int flag);
extern int	pa_hostname_so(pr_context_t *context, int status, int flag);
extern int	pa_adr_u_short(pr_context_t *context, int status, int flag);
extern int	pa_tid32(pr_context_t *context, int status, int flag);
extern int	pa_tid64(pr_context_t *context, int status, int flag);
extern int	pa_tid32_ex(pr_context_t *context, int status, int flag);
extern int	pa_tid64_ex(pr_context_t *context, int status, int flag);
extern int	pa_adr_charhex(pr_context_t *context, int status, int flag);
extern int	pa_adr_short(pr_context_t *context, int status, int flag);
extern int	pa_adr_shorthex(pr_context_t *context, int status, int flag);
extern int	pa_mode(pr_context_t *context, int status, int flag);
extern int	pa_cmd(pr_context_t *context, int status, int flag);
extern int	pa_string(pr_context_t *context, int status, int flag);
extern int	pa_liaison(pr_context_t *context, int status, int flag);
extern int	pa_xgeneric(pr_context_t *context);
extern int	pa_xid(pr_context_t *context, int status, int flag);
extern void	pa_error(const uchar_t err, char *buf, size_t buflen);
extern void	pa_retval(const uchar_t, const int32_t, char *, size_t);
extern int	pa_ip_addr(pr_context_t *context, int status, int flag);
extern int	pr_adr_char(pr_context_t *context, char *cp, int count);
extern int	pr_adr_short(pr_context_t *context, short *sp, int count);
extern int	pr_adr_int32(pr_context_t *context, int32_t *lp, int count);
extern int	pr_adr_int64(pr_context_t *context, int64_t *lp, int count);
extern int	pr_adr_u_int32(pr_context_t *context, uint32_t *cp, int count);
extern int	pr_adr_u_char(pr_context_t *context, uchar_t *cp, int count);
extern int	pr_adr_u_int64(pr_context_t *context, uint64_t *lp, int count);
extern int	pr_adr_u_short(pr_context_t *context, ushort_t *sp, int count);
extern int	pr_putchar(pr_context_t *context, char);
extern int	pr_printf(pr_context_t *context, const char *format, ...);
extern int	pr_input_remaining(pr_context_t *context, size_t size);

/*
 * Functions that format audit data
 */
extern int	print_audit(const int, const char *);
extern int	print_audit_buf(char **, int *, char **, int *, const int,
    const char *);
extern void	print_audit_xml_prolog(void);
extern void	print_audit_xml_ending(void);
extern int	print_audit_xml_prolog_buf(char *out_buf,
    const int out_buf_len);
extern int	print_audit_xml_ending_buf(char *out_buf,
    const int out_buf_len);


#ifdef __cplusplus
}
#endif

#endif	/* _PRAUDIT_H */
