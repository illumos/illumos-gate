/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy is of the CDDL is also available via the Internet
 * at http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 Nexenta Systems, Inc.
 * Copyright 2013 DEY Storage Systmes, Inc.
 */

/*
 * POSIX localedef.
 */

/* Common header files. */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <libintl.h>

extern int com_char;
extern int esc_char;
extern int mb_cur_max;
extern int mb_cur_min;
extern int last_kw;
extern int verbose;
extern int yydebug;
extern int lineno;
extern int undefok;	/* mostly ignore undefined symbols */
extern int warnok;
extern int warnings;

void yyerror(const char *);
void errf(const char *, ...);
void warn(const char *, ...);

int putl_category(const char *, FILE *);
int wr_category(void *, size_t, FILE *);
FILE *open_category(void);
void delete_category(FILE *);
void close_category(FILE *);
void copy_category(char *);

int get_category(void);
void reset_scanner(const char *);
void scan_to_eol(void);
void add_wcs(wchar_t);
wchar_t *get_wcs(void);

/* charmap.c - CHARMAP handling */
void init_charmap(void);
void add_charmap(const char *, int);
void add_charmap_undefined(char *);
void add_charmap_posix(void);
void add_charmap_range(char *, char *, int);
void add_charmap_char(const char *name, int val);
int lookup_charmap(const char *, wchar_t *);
int check_charmap_undefined(char *);
int check_charmap(wchar_t);

/* collate.o - LC_COLLATE handling */
typedef struct collelem collelem_t;
typedef struct collsym collsym_t;
void init_collate(void);
void define_collsym(char *);
void define_collelem(char *, wchar_t *);
void add_order_directive(void);
void add_order_bit(int);
void dump_collate(void);
collsym_t *lookup_collsym(char *);
collelem_t *lookup_collelem(char *);
void start_order_collelem(collelem_t *);
void start_order_undefined(void);
void start_order_symbol(char *);
void start_order_char(wchar_t);
void start_order_ellipsis(void);
void end_order_collsym(collsym_t *);
void end_order(void);
void add_weight_num(int);
void add_order_collelem(collelem_t *);
void add_order_collsym(collsym_t *);
void add_order_char(wchar_t);
void add_order_ignore(void);
void add_order_ellipsis(void);
void add_order_symbol(char *);
void add_order_subst(void);
void add_subst_char(wchar_t);
void add_subst_collsym(collsym_t *);
void add_subst_collelem(collelem_t *);
void add_subst_symbol(char *);

/* ctype.c - LC_CTYPE handling */
void init_ctype(void);
void add_ctype(int);
void add_ctype_range(wchar_t);
void add_width(int, int);
void add_width_range(int, int, int);
void add_caseconv(int, int);
void dump_ctype(void);

/* messages.c - LC_MESSAGES handling */
void init_messages(void);
void add_message(wchar_t *);
void dump_messages(void);

/* monetary.c - LC_MONETARY handling */
void init_monetary(void);
void add_monetary_str(wchar_t *);
void add_monetary_num(int);
void reset_monetary_group(void);
void add_monetary_group(int);
void dump_monetary(void);

/* numeric.c - LC_NUMERIC handling */
void init_numeric(void);
void add_numeric_str(wchar_t *);
void reset_numeric_group(void);
void add_numeric_group(int);
void dump_numeric(void);

/* time.c - LC_TIME handling */
void init_time(void);
void add_time_str(wchar_t *);
void reset_time_list(void);
void add_time_list(wchar_t *);
void check_time_list(void);
void dump_time(void);

/* wide.c -  Wide character handling. */
int to_wide(wchar_t *, const char *);
int to_mbs(char *, wchar_t);
char *to_mb_string(const wchar_t *);
void set_wide_encoding(const char *);
const char *get_wide_encoding(void);
int max_wide(void);

#define	_(x)	gettext(x)
#define	INTERR	errf(_("internal fault (%s:%d)"), __FILE__, __LINE__)
