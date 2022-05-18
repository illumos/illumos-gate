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

#ifndef	_IO_H
#define	_IO_H

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Bounds structure for integer and disk input.
 */
struct bounds {
	diskaddr_t	lower;
	diskaddr_t	upper;
};

/*
 * List of strings with arbitrary matching values
 */
typedef struct slist {
	char	*str;
	char	*help;
	int	value;
} slist_t;

/*
 * Input structure for current partition information
 */
typedef struct partition_defaults {
	uint_t start_cyl;
	uint_t deflt_size;
} part_deflt_t;

typedef struct efi_defaults {
	uint64_t	start_sector;
	uint64_t	end_sector;
} efi_deflt_t;

/*
 * Input parameter can be any one of these types.
 */
typedef union input_param {
	struct slist	*io_slist;
	char		**io_charlist;
	struct bounds	io_bounds;
} u_ioparam_t;

/*
 * These declarations define the legal input types.
 */
#define	FIO_BN		0		/* block number */
#define	FIO_INT		1		/* integer input */
#define	FIO_CSTR	2		/* closed string - exact match */
#define	FIO_MSTR	3		/* matched string, with abbreviations */
#define	FIO_OSTR	4		/* open string - anything's legal */
#define	FIO_BLNK	5		/* blank line */
#define	FIO_SLIST	6		/* one string out of a list, abbr. */
#define	FIO_CYL		7		/* nblocks, on cylinder boundary */
#define	FIO_OPINT	8		/* optional integer input */
#define	FIO_ECYL	9		/* allows end cylinder input */
#define	FIO_INT64	10		/* Input for EFI partitions */
#define	FIO_EFI		11		/* Input EFI part size	*/

/*
 * Miscellaneous definitions.
 */
#define	TOKEN_SIZE	36			/* max length of a token */
typedef	char TOKEN[TOKEN_SIZE+1];		/* token type */
#define	DATA_INPUT	0			/* 2 modes of input */
#define	CMD_INPUT	1
#define	WILD_STRING	"$"			/* wildcard character */
#define	COMMENT_CHAR	'#'			/* comment character */


/*
 *	Prototypes for ANSI C
 */
char	*gettoken(char *inbuf);
void	clean_token(char *cleantoken, char *token);
int	geti(char *str, int *iptr, int *wild);
uint64_t	input(int, char *, int, u_ioparam_t *, int *, int);
int	find_value(slist_t *slist, char *match_str, int *match_value);
char	*find_string(slist_t *slist, int match_value);
void	fmt_print(char *format, ...) __PRINTFLIKE(1);
void	nolog_print(char *format, ...) __PRINTFLIKE(1);
void	log_print(char *format, ...) __PRINTFLIKE(1);
void	err_print(char *format, ...) __PRINTFLIKE(1);
void	print_buf(char *buf, int nbytes);
void	pr_diskline(struct disk_info *disk, int num);
void	pr_dblock(void (*func)(char *, ...), diskaddr_t bn);
int	sup_gettoken(char *buf);
void	sup_pushtoken(char *token_buf, int token_type);
void	get_inputline(char *, int);
int	istokenpresent(void);
int	execute_shell(char *, size_t);
void	print_efi_string(char *vendor, char *product, char *revision,
    uint64_t capacity);

/*
 * Most recent token type
 */
extern	int	last_token_type;

#ifdef	__cplusplus
}
#endif

#endif	/* _IO_H */
