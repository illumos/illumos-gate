#ifndef getline_h
#define getline_h

/*
 * Copyright (c) 2000, 2001, 2002, 2003, 2004 by Martin C. Shepherd.
 * 
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, provided that the above
 * copyright notice(s) and this permission notice appear in all copies of
 * the Software and that both the above copyright notice(s) and this
 * permission notice appear in supporting documentation.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
 * OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL
 * INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * Except as contained in this notice, the name of a copyright holder
 * shall not be used in advertising or otherwise to promote the sale, use
 * or other dealings in this Software without prior written authorization
 * of the copyright holder.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Set the name of the getline configuration file.
 */
#define TECLA_CONFIG_FILE "~/.teclarc"

/*
 * The following macro returns non-zero if a character is
 * a control character.
 */
#define IS_CTRL_CHAR(c) ((unsigned char)(c) < ' ' || (unsigned char)(c)=='\177')

/*
 * The following macro returns non-zero if a character is
 * a meta character.
 */
#define IS_META_CHAR(c) (((unsigned char)(c) & 0x80) && !isprint((int)(unsigned char)(c)))

/*
 * Return the character that would be produced by pressing the
 * specified key plus the control key.
 */
#define MAKE_CTRL(c) ((c)=='?' ? '\177' : ((unsigned char)toupper(c) & ~0x40))

/*
 * Return the character that would be produced by pressing the
 * specified key plus the meta key.
 */
#define MAKE_META(c) ((unsigned char)(c) | 0x80)

/*
 * Given a binary control character, return the character that
 * had to be pressed at the same time as the control key.
 */
#define CTRL_TO_CHAR(c) (toupper((unsigned char)(c) | 0x40))

/*
 * Given a meta character, return the character that was pressed
 * at the same time as the meta key.
 */
#define META_TO_CHAR(c) ((unsigned char)(c) & ~0x80)

/*
 * Specify the string of characters other than the alphanumeric characters,
 * that are to be considered parts of words.
 */
#define GL_WORD_CHARS "_*\?\\[]"

/*
 * Define the escape character, both as a string and as a character.
 */
#define GL_ESC_STR "\033"
#define GL_ESC_CHAR '\033'

#endif
