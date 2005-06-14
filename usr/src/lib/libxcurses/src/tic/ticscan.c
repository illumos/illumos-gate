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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	ticscan.c		Terminal Information Compiler
 *
 *	Copyright 1990, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 *	Portions of this code Copyright 1982 by Pavel Curtis.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/tic/rcs/ticscan.c 1.13 1994/02/08 20:19:29 rog Exp $";
#endif
#endif

#include "tic.h"
#include <limits.h>
#include <ctype.h>

#define iswhite(ch)	(ch == ' ' || ch == '\t')


token curr_token;
long curr_file_pos;
int curr_column = -1;
char line[LINE_MAX+1];
static int first_column;		/* See 'next_char()' below */

STATIC int next_char ANSI((void));
STATIC int trans_string ANSI((char *));
STATIC int escape ANSI((int));
STATIC void backspace ANSI((void));

char early_eof[] = m_textstr(3122, "Premature EOF", "E");
char nl_middle[] = m_textstr(3123, "Newline in middle of terminal name", "E");
char ill_char[] = m_textstr(3124, "Illegal character - '%c'", "E char");
char ill_ctrl[] = m_textstr(3125, "Illegal control character - '%c'", "E char");
char off_beg[] = m_textstr(3126, "Backspaced off beginning of line", "E");
char no_comma[] = m_textstr(3127, "Missing comma", "E");
char very_long[] = m_textstr(3128, "Very long string found.  Missing comma?", "E");
char token_msg[] = m_textstr(3129, "Token: ", "I");
char bool_msg[] = m_textstr(3130, "Boolean;  name='%s'\n", "I string");
char num_msg[] = m_textstr(3131, "Number; name='%s', value=%d\n", "I name value");
char str_msg[] = m_textstr(3132, "String; name='%s', value='%s'\n", "I name value");
char cancel[] = m_textstr(3133, "Cancel; name='%s'\n", "I name");
char names[] = m_textstr(3134, "Names; value='%s'\n", "I value");
char eof_msg[] = m_textstr(3135, "End of file.\n", "I");
char bad_token[] = m_textstr(3136, "Bad token type", "E");


/*f
 *	Scans the input for the next token, storing the specifics in the
 *	global structure 'curr_token' and returning one of the following:
 *
 *		NAMES		A line beginning in column 1.  'name'
 *				will be set to point to everything up to
 *				but not including the first comma on the line.
 *		BOOLEAN		An entry consisting of a name followed by
 *				a comma.  'name' will be set to point to the
 *				name of the capability.
 *		NUMBER		An entry of the form
 *					name#digits,
 *				'name' will be set to point to the capability
 *				name and 'valnumber' to the number given.
 *		STRING		An entry of the form
 *					name=characters,
 *				'name' is set to the capability name and
 *				'valstring' to the string of characters, with
 *				input translations done.
 *		CANCEL		An entry of the form
 *					name@,
 *				'name' is set to the capability name and
 *				'valnumber' to -1.
 *		EOF		The end of the file has been reached.
 */
int
get_token()
{
	long		number;
	int		type;
	int             ch;
	static char	buffer[1024];
	register char	*ptr;
	int		dot_flag = 0;

	while ((ch = next_char()) == '\n' || iswhite(ch)) {
		;
	}

	if (ch == EOF)
	    type = EOF;
	else
	{
	    if (ch == '.')
	    {
		dot_flag = 1;

		while ((ch = next_char()) == ' ' || ch == '\t')
		    ;
	    }

	    if (! isalnum(ch)) {
			warning(m_strmsg(ill_char), ch);
			panic_mode(',');
	    }

	    ptr = buffer;
	    *(ptr++) = ch;

	    if (first_column)
	    {
		while ((ch = next_char()) != ',' && ch != '\n' && ch != EOF)
		    *(ptr++) = ch;
		
		if (ch == EOF)
		    err_abort(m_strmsg(early_eof));
		else if (ch == '\n') {
		    warning(m_strmsg(nl_middle));
		    panic_mode(',');
		}
		
		*ptr = '\0';
		curr_token.tk_name = buffer;
		type = NAMES;
	    }
	    else
	    {
		ch = next_char();
		while (isalnum(ch))
		{
		    *(ptr++) = ch;
		    ch = next_char();
		}

		*ptr++ = '\0';
		switch (ch)
		{
		    case ',':
			curr_token.tk_name = buffer;
			type = BOOLEAN;
			break;

		    case '@':
			if (next_char() != ',')
			    warning(m_strmsg(no_comma));
			curr_token.tk_name = buffer;
			type = CANCEL;
			break;

		    case '#':
			number = 0;
			while (isdigit(ch = next_char()))
			    number = number * 10 + ch - '0';
			if (ch != ',')
			    warning(m_strmsg(no_comma));
			curr_token.tk_name = buffer;
			curr_token.tk_valnumber = number;
			type = NUMBER;
			break;
		    
		    case '=':
			ch = trans_string(ptr);
			if (ch != ',')
			    warning(m_strmsg(no_comma));
			curr_token.tk_name = buffer;
			curr_token.tk_valstring = ptr;
			type = STRING;
			break;

		    default:
			warning(m_strmsg(ill_char), ch);
		}
	    } /* end else (first_column == 0) */
	} /* end else (ch != EOF) */

	if (dot_flag == 1)
	    DEBUG(8, "Commented out ", "");

	if (debug_level >= 8)
	{
	    fprintf(stderr, m_strmsg(token_msg));
	    switch (type)
	    {
		case BOOLEAN:
		    fprintf(stderr, m_strmsg(bool_msg), curr_token.tk_name);
		    break;
		
		case NUMBER:
			fprintf(
				stderr, m_strmsg(num_msg),
				curr_token.tk_name, curr_token.tk_valnumber
			);
			break;
		
		case STRING:
			fprintf(
				stderr, m_strmsg(str_msg),
				curr_token.tk_name, curr_token.tk_valstring
			);
			break;
		
		case CANCEL:
		    fprintf(stderr, m_strmsg(cancel), curr_token.tk_name);
		    break;
		
		case NAMES:
		    fprintf(stderr, m_strmsg(names), curr_token.tk_name);
		    break;

		case EOF:
		    fprintf(stderr, m_strmsg(eof_msg));
		    break;

		default:
		    warning(m_strmsg(bad_token));
	    }
	}

	if (dot_flag == 1)		/* if commented out, use the next one */
	    type = get_token();

	return(type);
}


/*f
 *	Returns the next character in the input stream.  Comments and leading
 *	white space are stripped.  The global state variable 'firstcolumn' is
 *	set TRUE if the character returned is from the first column of the input
 * 	line.  The global variable curr_line is incremented for each new line.
 *	The global variable curr_file_pos is set to the file offset of the
 *	beginning of each line.
 */
STATIC int
next_char()
{
	char *rtn_value;

	if (curr_column < 0 || LINE_MAX < curr_column
	|| line[curr_column] == '\0') {
		do {
			curr_file_pos = ftell(stdin);
			if ((rtn_value = fgets(line, LINE_MAX, stdin)) != NULL)
				curr_line++;
		} while (rtn_value != NULL && line[0] == '#');

		if (rtn_value == NULL)
			return (EOF);

		curr_column = 0;
		while (iswhite(line[curr_column]))
			curr_column++;
	}
	first_column = curr_column == 0 && *line != '\n';
	return (line[curr_column++]);
}


/*f
 * go back one character
 */
STATIC void
backspace()
{
	curr_column--;

	if (curr_column < 0)
	    syserr_abort(m_strmsg(off_beg));
}


/*f
 *	Resets the input-reading routines.  Used after a seek has been done.
 */
void
reset_input()
{
	curr_column = -1;
}

/*f
 *	Reads characters using next_char() until encountering a comma, newline
 *	or end-of-file.  The returned value is the character which caused
 *	reading to stop.  The following translations are done on the input:
 *
 *		^X  goes to  ctrl-X (i.e. X & 037)
 *		{backslash-E,backslash-n,backslash-r,backslash-b,
 *				backslash-t,backslash-f}  go to
 *			{ESCAPE,newline,carriage-return,backspace,tab,formfeed}
 *		{backslash-^,backslash-backslash}  go to  {carat,backslash}
 *		backslash-ddd (for ddd = up to three octal digits)  goes to
 *							the character ddd
 *
 *		backslash-e == backslash-E
 *		backslash-0 == backslash-200
 */
STATIC int
trans_string(ptr)
char *ptr;
{
	int i, number, ch;
	register int count = 0;

	while ((ch = next_char()) != ',' && ch != EOF) {
		if (ch == '^') {
			ch = next_char();
			if (ch == EOF)
				err_abort(m_strmsg(early_eof));
			if (!isprint(ch))
				warning(m_strmsg(ill_ctrl), ch);
			*(ptr++) = ch & 037;
		} else if (ch == '\\') {
			/* Try to read a three character octal number. */
			for (number = i = 0; i < 3; ++i) {
				ch = next_char();
				if (ch == EOF)
					err_abort(m_strmsg(early_eof));
				if (ch < '0' || '7' < ch) {
					backspace();
					break;
				}
				number = number * 8 + ch - '0';
			}
			if (0 < i) {
				/* Read an octal number. */
				*ptr++ = number == 0 ? 0200 : (char) number;
			} else {
				/* Escape mapping translation. */
				ch = escape(next_char());
				*ptr++ = ch;
			} 
		} else {
			*(ptr++) = ch;
		}
		if (500 < ++count)
			warning(m_strmsg(very_long));
	}
	*ptr = '\0';
	return (ch);
}

/*f
 * Panic mode error recovery - skip everything until a "ch" is found.
 */
void
panic_mode(ch)
char ch;
{
	int c;
	for (;;) {
		c = next_char();
		if (c == ch)
			return;
		if (c == EOF);
			return;
	}
}

/*f
 *	This routine is a codeset independent method of specifying a translation
 *	from an unambiguous printable form, to an internal binary value.
 *	This mapping is defined by Table 2-13 in section 2-12 of POSIX.2.
 *
 * 	This table has been extended to account for tic/infocmp specification
 *	of additional characters: <escape>, <space>, <colon>, <caret>, <comma> 
 *
 *	Assume that the escape lead-in character has been processed and 
 *	any escaped octal sequence.
 */
STATIC int
escape(c)
int c;
{
	int i;
	static int cntl_code[] = { 
		'\0', '\\', M_ALERT, '\b', '\f', '\n', '\r', '\t', 
		M_VTAB, M_ESCAPE, M_ESCAPE, ' ', ':', '^', ',', 
		-1
	};
	static int escape_char[] = {
		'\0', '\\', 'a', 'b', 'f', 'n', 'r', 't', 
		'v', 'E', 'e', 's', ':', '^', ',',
		-1
	};
	for (i = 0; escape_char[i] != -1; ++i)
		if (c == escape_char[i])
			return (cntl_code[i]);
	return (c);
}
