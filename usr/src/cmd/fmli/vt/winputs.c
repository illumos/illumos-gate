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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1986 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.5 */

#include	<curses.h>
#include	"wish.h"
#include	"vt.h"
#include	"attrs.h"

char *attr_off();
char *attr_on();

/*
   ----------------------------------------------------------------------------
   winputs
       output the string `s' to window `w' after processing escape sequences.
         Calls wputchar  to output characters. If `w' is NULL wputchar will 
         write to the current window.  Escape processing involves replacing
         \b \n \r \t with backspace, newline, carrage return or tab characters 
         respectively, or setting/clearing video attributes when \+ or \-
         sequences are found.  Video attributes remain in effect for the
         rest of the string s (only).
   ---------------------------------------------------------------------------- 
*/

void
winputs(s, win)
char	*s;
WINDOW  *win;
{
	register char	*p;
        chtype attrs = Attr_normal;

	for (p = s; *p; p++) {
		if (*p == '\\') {
			switch(*(++p)) {
			case 'b':
				*p = '\b';
				break;
			case '-':	     /* turn off output attribute */
				p = attr_off(p, &attrs, win );
				continue;    /* don't need to wputchar    */
			case 'n':
				*p = '\n';
				break;
			case '+':	   /* turn on output attribute */
				p = attr_on(p, &attrs, win);
				continue;  /* don't need to wputchar   */
			case 'r':
				*p = '\r';
				break;
			case 't':
				*p = '\t';
				break;
			case '\0':
				return;
			}
		}
		wputchar(*p, attrs, win);
	}
}


/* ----------------------------------------------------------------------------- 
   attr_on
           Finish parsing an escape sequence of the form `\+at' where `at'
	   is a 2 character code for the video attribute to turn on.  The
	   `\+' have already been parsed before calling this routine.
	   ACTION:       outputs a `\' if the attribute requested is unknown.
	   SIDE EFFECTS: set bits in `attrs' corresponding to the attribute to 
	                 be turned on.
	   RETURN VALUE: if successful, pointer to the last character in the
	                 escape sequence; else pointer to the character before
			 the 1st one parsed (ie. to the `+') 

   ----------------------------------------------------------------------------- */
char *
attr_on(p, attrs, win)
char   *p;
chtype *attrs;
WINDOW *win;
{
	   p++; 
	   switch(*(p++)) 
	   {
	      case 'a':
	   	      if (*p == 'c') 
		      {
		         *attrs |= A_ALTCHARSET;
			 return(p);
		      }
		      break;
              case 'b':
	              if (*p == 'd') 
		      {
		         *attrs |= A_BOLD;
			 return(p);
		      }
		      else if (*p == 'k') 
		      {
		         *attrs |= A_BLINK;
			 return(p);
		      }
		      break;
  	      case 'd':
		      if (*p == 'm') 
		      {
			 *attrs |= A_DIM;
			 return(p);
		      }
		      break;
	      case 'n':
		      if (*p == 'm') 
		      {
			 *attrs = A_NORMAL;
			 return(p);
		      }
		      break;
	      case 'r':
		      if (*p == 'v') 
		      {
			 *attrs |= A_REVERSE;
			 return(p);
		      }
		      break;
              case 's':
		      if (*p == 'o') 
		      {
			 *attrs |= A_STANDOUT;
			 return(p);
		      }
		      break;
	      case 'u':
		      if (*p == 'l') 
		      {
			 *attrs |= A_UNDERLINE;
			 return(p);
		      }
		      break;
	      default:
		      break;
	   }
	   wputchar ('\\', *attrs, win);
	   p -= 3;

	   return (p);
}

/* ----------------------------------------------------------------------------- 
   attr_off
           Finish parsing an escape sequence of the form `\-at' where `at'
	   is a 2 character code for the video attribute to turn off.  The
	   `\-' have already been parsed before calling this routine.
	   ACTION:       outputs a `\' if the attribute requested is unknown.
	   SIDE EFFECTS: clears the bits in `attrs' corresponding to the 
	                 attribute to be turned on.
	   RETURN VALUE: if successful, pointer to the last character in the
	                 escape sequence; else pointer to the character before
			 the 1st one parsed (ie. to the `-') 

   ----------------------------------------------------------------------------- */


char *
attr_off(p, attrs, win)
char	*p;
chtype *attrs;
WINDOW *win;
{

           p++;
	   switch(*(p++)) 
	   {
	      case 'a':
	   	      if (*p == 'c') 
		      {
		         *attrs &= ~A_ALTCHARSET;
			 return(p);
		      }
		      break;
              case 'b':
	              if (*p == 'd') 
		      {
		         *attrs &= ~A_BOLD;
			 return(p);
		      }
		      else if (*p == 'k') 
		      {
			 *attrs &= ~A_BLINK;
			 return(p);
		      }
		      break;
  	      case 'd':
		      if (*p == 'm') 
		      {
			 *attrs &= ~A_DIM;
			 return(p);
		      }
		      break;
	      case 'n':
		      if (*p == 'm') 
		      {
			 /* not meaningful -- ignore. */
			 return(p);
		      }
		      break;
	      case 'r':
		      if (*p == 'v') 
		      {
			 *attrs &= ~A_REVERSE;
			 return(p);
		      }
		      break;
              case 's':
		      if (*p == 'o') 
		      {
			 *attrs &= ~A_STANDOUT;
			 return(p);
		      }
		      break;
	      case 'u':
		      if (*p == 'l') 
		      {
			 *attrs &= ~A_UNDERLINE;
			 return(p);
		      }
		      break;
	      default:
		      break;
	   }
	   wputchar ('\\', *attrs, win);
	   p -= 3;

	   return (p);
}
