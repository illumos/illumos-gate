%{
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
 *
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <locale.h>
#include <sys/param.h>
#include <sys/fs/udf_volume.h>

char	shell_name[128] = "/bin/sh";
extern char	prompt[];
extern uint16_t ricb_prn;
extern uint32_t ricb_loc;
extern int32_t bsize, bmask, l2d, l2b;

int	base = 16;
int	old_value = 0;
int	value = 0;
int	count = 0;


int	last_op_type = 0;
#define	TYPE_NONE	0
#define	TYPE_INODE	1
#define	TYPE_DIRENT	2
#define	TYPE_BLOCK	3
#define	TYPE_CD		4

uint32_t i_number = 0;
uint32_t d_entry = 0;
int	error_override = 0;

int	register_array[256];
char	cwd[MAXPATHLEN] = "/";

int32_t ls_flags;
#define	LONG_LIST	0x1
#define	RECU_LIST	0x2
#define	LIST_LS		0x4

int32_t find_flags;
#define	FIND_DIR	0x1
#define	FIND_NAME	0x2
#define	FIND_INODE	0x4
#define	FIND_DONE	0x8
char find_dir[1024];
char find_name[1024];
uint32_t find_in;

%}

%union
{
	uint8_t		*strval;
	uint64_t	intval;
};

%token BASE BLOCK CD DIRECTORY TFILE FIND FILL
%token INODE LS OVERRIDE PROMPT PWD QUIT TAG BANG

%token AVD MVDS RVDS INTS FSDS ROOT
%token ATTZ ATYE ATMO ATDA ATHO ATMI ATSE ATCE ATHU ATMIC
%token CTTZ CTYE CTMO CTDA CTHO CTMI CTSE CTCE CTHU CTMIC
%token MTTZ MTYE MTMO MTDA MTHO MTMI MTSE MTCE MTHU MTMIC
%token GID LN MD MAJ MIO NM SZ UID UNIQ
%token DOT
%token NL

%token WORD

%left '-' '+'
%left '*' '%'

%type <strval>	WORD
%type <intval> expr

%%

session		: statement_list

statement_list	: /* empty */			{ print_prompt(); }
		| statement_list statement
			{
				ls_flags = 0;
			}
		;

statement	: empty_statement
		| current_value
		| register
		| base | block | cd | directory | file | find | fill
		| inode | ls | override | nprompt | pwd | quit | tag | shell
		| avd | mvds | rvds | ints | fsds | root
		| at | ct | gid | ln | mt | md
		| maj | min | nm | sz | uid | uniq
		| dump | texpr
		| error	{ yyclearin; yyerrok; }
		;

empty_statement	: NL
			{
				print_prompt();
			}
		;


current_value	: DOT
			{
				if (last_op_type == TYPE_INODE) {
					print_inode(i_number << l2b);
				} else if (last_op_type == TYPE_DIRENT) {
					print_dent(i_number << l2b, d_entry);
				} else {
					fprintf(stdout,
						gettext("%x\n"), value);
				}
			}
			;

register	: '<' WORD
			{
				if ((strlen((caddr_t)$2) == 1) &&
					((($2[0] >= 'a') &&
						($2[0] <= 'z')) ||
					(($2[0] >= 'A') &&
						($2[0] <= 'Z')))) {
					value = register_array[$2[0]];
				} else {
					fprintf(stdout,
						gettext("Registers can"
						" be only a-z or A-Z\n"));
				}
			}
		| '>' WORD
			{
				if ((strlen((caddr_t)$2) == 1) &&
					((($2[0] >= 'a') &&
						($2[0] <= 'z')) ||
					(($2[0] >= 'A') &&
						($2[0] <= 'Z')))) {
					register_array[$2[0]] = value;
				} else {
					fprintf(stdout,
						gettext("Registers can"
						" be only a-z or A-Z\n"));
				}
			}
		;

base		: BASE '=' expr
			{
				if (($3 == 8) || ($3 == 10) || ($3 == 16)) {
					base = $3;
				} else {
					fprintf(stdout,
						gettext("Requested %x Only"
						" Oct, Dec and"
						" Hex are Supported\n"), $3);
				}
			}
		| BASE
			{
				fprintf(stdout,
					gettext("Current Base in Decimal"
					" : %d\n"), base);
			}
		;

block		: BLOCK
			{
				last_op_type = TYPE_NONE;
				value = value * DEV_BSIZE;
			}
		;

cd		: CD ' ' WORD
			{
				uint8_t fl;
				uint32_t temp;
				char temp_cwd[MAXPATHLEN];

				strcpy(temp_cwd, cwd);
				if (strcmp((caddr_t)$3, "..") == 0) {
					if (strlen(temp_cwd) == 1) {
						if (temp_cwd[0] != '/') {
							fprintf(stdout,
							gettext("cwd is invalid"
							"setting to /\n"));
							strcpy(temp_cwd, "/");
						}
					} else {
						dirname(temp_cwd);
					}
				} else {
					int32_t len;

					len = strlen(temp_cwd);
					if (temp_cwd[len - 1] != '/') {
						temp_cwd[len] = '/';
						temp_cwd[len + 1] = '\0';
					}
					strcat(temp_cwd, (caddr_t)$3);
				}
				if (inode_from_path(temp_cwd, &temp,
							&fl) != 0) {
					fprintf(stdout,
						gettext("Could not locate inode"
						" for path %s\n"), temp_cwd);
					strcpy(temp_cwd, "/");
					if ((temp = ud_xlate_to_daddr(ricb_prn,
						ricb_loc)) == 0) {
						fprintf(stdout,
						gettext("Failed to translate"
						" prn %x loc %x\n"),
						ricb_prn, ricb_loc);
					}
				} else {
					if ((fl & FID_DIR) == 0) {
						fprintf(stdout,
						gettext("%s is not a"
						" directory\n"), temp_cwd);
					} else {
						strcpy(cwd, temp_cwd);
						value = temp << l2b;
						last_op_type = TYPE_CD;
						i_number = temp;
					}
				}
			}
		| CD
			{
				uint32_t block;

				(void) strcpy(cwd, "/");
				/*
				 * set current value to root icb
				 */
				if ((block = ud_xlate_to_daddr(ricb_prn,
						ricb_loc)) == 0) {
					fprintf(stdout,
						gettext("Failed to translate "
						"prn %x loc %x\n"),
						ricb_prn, ricb_loc);
				} else {
					value = block << l2b;
					last_op_type = TYPE_CD;
					i_number = block;
				}
			}
		;

directory	: DIRECTORY
			{
				if (verify_dent(i_number << l2b, value) == 0) {
					last_op_type = TYPE_DIRENT;
					d_entry = value;
				}
			}
		;

file		: TFILE
			{
			}
		;

find		: xfind
			{
				if ((find_flags & (FIND_NAME | FIND_INODE)) &&
					(find_flags & FIND_DONE)) {
					if (find_dir[0] != '/') {
						char buf[1024];

						strcpy(buf, find_dir);
						if ((strlen(cwd) == 1) &&
							(cwd[0] == '/')) {
							strcpy(find_dir, "/");
						} else {
							strcpy(find_dir, cwd);
							strcat(find_dir, "/");
						}
						strcat(find_dir, buf);
					}
					find_it(find_dir, find_name, find_in,
				(find_flags & (FIND_NAME | FIND_INODE)));
				}
				find_flags = 0;
				find_dir[0] = '\0';
				find_name[0] = '\0';
				find_in = 0;
			}
		;

xfind		: FIND WORD
			{
				strcpy(find_dir, (char *)$2);
				find_flags = FIND_DIR;
			}
		| xfind ' ' WORD
			{
				if (find_flags == FIND_DIR) {
					if (strcmp((char *)$3, "-name") == 0) {
						find_flags = FIND_NAME;
					} else if (strcmp((char *)$3, "-inum")
							== 0) {
						find_flags = FIND_INODE;
					} else {
						fprintf(stdout,
				gettext("find dir-name {-name n | -inum n}\n"));
					}
				} else if (find_flags == FIND_NAME) {
					strcpy(find_name, (char *)$3);
					find_flags |= FIND_DONE;
				} else if (find_flags == FIND_INODE) {
					uint64_t temp;

					if (check_and_get_int($3, &temp) ==
						0) {
						find_in = temp;
						find_flags |= FIND_DONE;
					} else {
						fprintf(stdout,
				gettext("find dir-name {-name n | -inum n}\n"));
					}
				} else {
					fprintf(stdout,
				gettext("find dir-name {-name n | -inum n}\n"));
				}
			}
		| xfind ' ' expr
			{
				if (find_flags == FIND_INODE) {
					find_in = $3;
					find_flags |= FIND_DONE;
				} else {
					fprintf(stdout,
				gettext("find dir-name {-name n | -inum n}\n"));
				}
			}
		;


fill		: FILL '=' WORD
			{
				fill_pattern(value, count, $3);
			}
		;

inode		: INODE
			{
				uint32_t temp;

				if (last_op_type == TYPE_CD) {
					temp = value;
				} else {
					temp = value << l2b;
				}
				last_op_type = TYPE_INODE;
				if (verify_inode(temp, 0) != 0) {
					i_number = temp >> l2b;
					d_entry = 0;
				}
			}
		;

ls		: xls
			{
				if (ls_flags & LIST_LS) {
					list(".", i_number, ls_flags);
				}
			}
		;

xls		: LS
			{
				/* Do nothing */
				ls_flags = LIST_LS;
			}
		| xls ' ' WORD
			{
				if (strcmp((caddr_t)$3, "-l") == 0) {
					ls_flags |= LONG_LIST;
				} else if (strcmp((caddr_t)$3, "-R") == 0) {
					ls_flags |= RECU_LIST;
				} else if ((strcmp((caddr_t)$3, "-lR") == 0) ||
					(strcmp((caddr_t)$3, "-Rl") == 0)) {
					ls_flags |= LONG_LIST | RECU_LIST;
				} else {
					list(".", i_number, ls_flags);
					ls_flags &= ~LIST_LS;
				}
			}
		;

override	: OVERRIDE
			{
				if (error_override == 0) {
					error_override = 1;
					(void) fprintf(stdout,
					gettext("error checking on\n"));
				} else {
					error_override = 0;
					(void) fprintf(stdout,
					gettext("error checking off\n"));
				}
			}
		;

nprompt		: PROMPT '=' WORD
			{
				(void) strcpy(prompt, (caddr_t)$3);
			}
		;

pwd		: PWD
			{
				fprintf(stdout, gettext("%s\n"), cwd);
			}
		;

quit		: QUIT
			{
				exit (0);
			}
		;

tag		: TAG
			{
				print_desc(value, 0);
			}
		;

shell		: BANG
			{
				system(shell_name);
			}
		;

avd		: AVD	{ print_desc(NULL, AVD); }
		;
mvds		: MVDS	{ print_desc(NULL, MVDS); }
		;
rvds		: RVDS	{ print_desc(NULL, RVDS); }
		;
ints		: INTS	{ print_desc(NULL, INTS); }
		;
fsds		: FSDS	{ print_desc(NULL, FSDS); }
		;
root		: ROOT	{ print_desc(NULL, ROOT); }
		;

at		: ATTZ '=' expr	{ set_file(ATTZ, i_number << l2b, $3); }
		| ATYE '=' expr	{ set_file(ATYE, i_number << l2b, $3); }
		| ATMO '=' expr	{ set_file(ATMO, i_number << l2b, $3); }
		| ATDA '=' expr	{ set_file(ATDA, i_number << l2b, $3); }
		| ATHO '=' expr	{ set_file(ATHO, i_number << l2b, $3); }
		| ATMI '=' expr	{ set_file(ATMI, i_number << l2b, $3); }
		| ATSE '=' expr	{ set_file(ATSE, i_number << l2b, $3); }
		| ATCE '=' expr	{ set_file(ATCE, i_number << l2b, $3); }
		| ATHU '=' expr	{ set_file(ATHU, i_number << l2b, $3); }
		| ATMIC '=' expr
			{
				set_file(ATMIC, i_number << l2b, $3);
			}
		;

ct		: CTTZ '=' expr	{ set_file(CTTZ, i_number << l2b, $3); }
		| CTYE '=' expr	{ set_file(CTYE, i_number << l2b, $3); }
		| CTMO '=' expr	{ set_file(CTMO, i_number << l2b, $3); }
		| CTDA '=' expr	{ set_file(CTDA, i_number << l2b, $3); }
		| CTHO '=' expr	{ set_file(CTHO, i_number << l2b, $3); }
		| CTMI '=' expr	{ set_file(CTMI, i_number << l2b, $3); }
		| CTSE '=' expr	{ set_file(CTSE, i_number << l2b, $3); }
		| CTCE '=' expr	{ set_file(CTCE, i_number << l2b, $3); }
		| CTHU '=' expr	{ set_file(CTHU, i_number << l2b, $3); }
		| CTMIC '=' expr
			{
				set_file(CTMIC, i_number << l2b, $3);
			}
		;

mt		: MTTZ '=' expr	{ set_file(MTTZ, i_number << l2b, $3); }
		| MTYE '=' expr	{ set_file(MTYE, i_number << l2b, $3); }
		| MTMO '=' expr	{ set_file(MTMO, i_number << l2b, $3); }
		| MTDA '=' expr	{ set_file(MTDA, i_number << l2b, $3); }
		| MTHO '=' expr	{ set_file(MTHO, i_number << l2b, $3); }
		| MTMI '=' expr	{ set_file(MTMI, i_number << l2b, $3); }
		| MTSE '=' expr	{ set_file(MTSE, i_number << l2b, $3); }
		| MTCE '=' expr	{ set_file(MTCE, i_number << l2b, $3); }
		| MTHU '=' expr	{ set_file(MTHU, i_number << l2b, $3); }
		| MTMIC '=' expr
			{
				set_file(MTMIC, i_number << l2b, $3);
			}
		;


gid		: GID '=' expr	{ set_file(GID, i_number << l2b, $3); }
		;

ln		: LN '=' expr	{ set_file(LN, i_number << l2b, $3); }
		;

md		: MD '=' expr	{ set_file(MD, i_number << l2b, $3); }
		;

maj		: MAJ '=' expr	{ set_file(MAJ, i_number << l2b, $3); }
		;

min		: MIO '=' expr	{ set_file(MIO, i_number << l2b, $3); }
		;

nm		: NM '=' expr	{ set_file(NM, i_number << l2b, $3); }
		;

sz		: SZ '=' expr	{ set_file(SZ, i_number << l2b, $3); }
		;

uid		: UID '=' expr	{ set_file(UID, i_number << l2b, $3); }
		;

uniq		: UNIQ '=' expr	{ set_file(UNIQ, i_number << l2b, $3); }
		;

dump		: '/' WORD
			{
				if (strlen((char *)$2) != 1) {
					fprintf(stdout,
						gettext("Invalid command\n"));
				} else {
					dump_disk(value, count, $2);
				}
			}
		| '?' WORD
			{
				if (strcmp((char *)$2, "i") == 0) {
					if (verify_inode(value << l2b,
							0) != 0) {
						print_inode(value << l2b);
						i_number = value;
						last_op_type == TYPE_INODE;
					}
				} else if (strcmp((char *)$2, "d") == 0) {
					if (verify_dent(i_number << l2b,
							value) == 0) {
						print_dent(i_number << l2b,
							value);
						d_entry = value;
						last_op_type == TYPE_DIRENT;
					}
				} else {
					fprintf(stdout,
						gettext("Invalid command\n"));
				}
			}
		;

texpr		: expr
			{
				value = $1;
				count = 0;
			}
		| expr ',' expr
			{
				value = $1;
				count = $3;
			}
		;

expr		: '+'
			{
				if (last_op_type == TYPE_INODE) {
					if (verify_inode((i_number + 1) << l2b,
							0) != 0) {
						i_number ++;
						print_inode(i_number << l2b);
						$$ = i_number << l2b;
					}
				} else if (last_op_type == TYPE_DIRENT) {
					if (verify_dent(i_number << l2b,
							d_entry + 1) == 0) {
						d_entry ++;
						print_dent(i_number << l2b,
							d_entry);
					}
				} else {
					count = 0; $$ = value++;
				}
			}
		| '-'
			{
				if (last_op_type == TYPE_INODE) {
					if (verify_inode((i_number - 1) << l2b,
							0) != 0) {
						i_number --;
						print_inode(i_number << l2b);
						$$ = i_number << l2b;
					}
				} else if (last_op_type == TYPE_DIRENT) {
					if (verify_dent(i_number << l2b,
							d_entry - 1) == 0) {
						d_entry --;
						print_dent(i_number << l2b,
							d_entry);
					}
				} else {
					count = 0; $$ = value--;
				}
			}
		| '-' WORD
			{
				uint64_t number;

				if (check_and_get_int($2, &number) == 0) {
					count = 0;
					$$ = value - number;
				}
			}
		| '+' WORD
			{
				uint64_t number;

				if (check_and_get_int($2, &number) == 0) {
					count = 0;
					$$ = value + number;
				}
			}
		| '*' WORD
			{
				uint64_t number;

				if (check_and_get_int($2, &number) == 0) {
					count = 0;
					$$ = value * number;
				}
			}
		| '%' WORD
			{
				uint64_t number;

				if (check_and_get_int($2, &number) == 0) {
					if (number == 0) {
						fprintf(stdout,
						gettext("Divide by zero ?\n"));
					} else {
						count = 0;
						$$ = value / number;
					}
				}
			}
		| expr '-' expr		{ count = 0; $$ = $1 - $3; }
		| expr '+' expr		{ count = 0; $$ = $1 + $3; }
		| expr '*' expr		{ count = 0; $$ = $1 * $3; }
		| expr '%' expr
			{
				if ($3 == 0) {
					fprintf(stdout,
						gettext("Divide by zero ?\n"));
				} else {
					$$ = $1 / $3;
				}
				count = 0;
			}
		| WORD
			{
				uint64_t number;

				count = 0;
				if (check_and_get_int($1, &number) == 0) {
					$$ = number;
				}
			}
		;

%%

int32_t
check_and_get_int(uint8_t *str, uint64_t *value)
{
	int32_t length, cbase, index, cvalue;

	*value = 0;
	length = strlen((caddr_t)str);
	/*
	 * Decide on what base to be used
	 * and strip off the base specifier
	 */
	if ((str[0] == '0') && (str[1] == 'x')) {
		cbase = 0x10;
		index = 2;
	} else if ((str[0] == '0') && (str[1] == 't')) {
		cbase = 0xa;
		index = 2;
	} else if (str[0] == '0') {
		cbase = 0x8;
		index = 1;
	} else {
		cbase = base;
		index = 0;
	}

	/*
	 * Verify if the string is integer
	 * and convert to a binary value
	 */
	for ( ; index < length; index++) {
		if (cbase == 0x8) {
			if ((str[index] < '0') ||
				(str[index] > '7')) {
				fprintf(stdout,
					gettext("Invalid Octal Number %s\n"),
					str);
				return (1);
			}
			cvalue = str[index] - '0';
		} else if (cbase == 0xa) {
			if ((str[index] < '0') ||
				(str[index] > '9' )) {
				fprintf(stdout,
					gettext("Invalid Decimal Number %s\n"),
					str);
				return (1);
			}
			cvalue = str[index] - '0';
		} else {
			if ((str[index] >= '0') &&
					(str[index] <= '9')) {
				cvalue = str[index] - '0';
			} else if ((str[index] >= 'a') &&
					(str[index] <= 'f')) {	
				cvalue = str[index] - 'a' + 10;
			} else if ((str[index] >= 'A') &&
					(str[index] <= 'F')) {
				cvalue = str[index] - 'A' + 10;
			} else {
				fprintf(stdout,
					gettext("Invalid Hex Number %s\n"),
					str);
				return (1);
			}
		}
		*value = *value * cbase + cvalue;
	}
	return (0);
}

void print_prompt();
extern FILE *yyin;

void
print_prompt()
{
	fprintf(stdout, gettext("%s"), prompt);
}

int32_t
run_fsdb()
{
	yyin = stdin;
	if (yyparse() != 0)
		return (-1);
	return 0;
}
