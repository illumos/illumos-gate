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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Cay S. Horstmann & Gary Cornell, Core Java
 * Published By Sun Microsystems Press/Prentice-Hall
 * Copyright (C) 1997 Sun Microsystems Inc.
 * All Rights Reserved.
 *
 * Permission to use, copy, modify, and distribute this 
 * software and its documentation for NON-COMMERCIAL purposes
 * and without fee is hereby granted provided that this 
 * copyright notice appears in all copies. 
 * 
 * THE AUTHORS AND PUBLISHER MAKE NO REPRESENTATIONS OR 
 * WARRANTIES ABOUT THE SUITABILITY OF THE SOFTWARE, EITHER 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT. THE AUTHORS
 * AND PUBLISHER SHALL NOT BE LIABLE FOR ANY DAMAGES SUFFERED 
 * BY LICENSEE AS A RESULT OF USING, MODIFYING OR DISTRIBUTING 
 * THIS SOFTWARE OR ITS DERIVATIVES.
 */
 
/**
 * A class for formatting numbers that follows printf conventions.
 * Also implements C-like atoi and atof functions
 * @version 1.01 15 Feb 1996 
 * @author Cay Horstmann
 */

package com.sun.dhcpmgr.cli.common;

import java.io.*;

public class Format

{
    /** 
     * Formats the number following printf conventions.
     * Main limitation: Can only handle one format parameter at a time
     * Use multiple Format objects to format more than one number
     * @param s the format string following printf conventions
     * The string has a prefix, a format code and a suffix. The prefix and 
     * suffix become part of the formatted output. The format code directs the
     * formatting of the (single) parameter to be formatted. The code has the
     * following structure
     * <ul>
     * <li> a % (required)
     * <li> a modifier (optional)
     * <dl>
     * <dt> + <dd> forces display of + for positive numbers
     * <dt> 0 <dd> show leading zeroes
     * <dt> - <dd> align left in the field
     * <dt> space <dd> prepend a space in front of positive numbers
     * <dt> # <dd> use "alternate" format. Add 0 or 0x for octal or hexadecimal
     * numbers. Don't suppress trailing zeroes in general floating point format.
     * </dl>
     * <li> an integer denoting field width (optional)
     * <li> a period followed by an integer denoting precision (optional)
     * <li> a format descriptor (required)
     * <dl>
     * <dt>f <dd> floating point number in fixed format
     * <dt>e, E <dd> floating point number in exponential notation (scientific 
     * format). The E format results in an uppercase E for the exponent
     * (1.14130E+003), the e format in a lowercase e.
     * <dt>g, G <dd> floating point number in general format (fixed format for
     * small numbers, exponential format for large numbers). Trailing zeroes
     * are suppressed. The G format results in an uppercase E for the exponent
     * (if any), the g format in a lowercase e.
     * <dt>d, i <dd> integer in decimal
     * <dt>x <dd> integer in hexadecimal
     * <dt>o <dd> integer in octal
     * <dt>s <dd> string
     * <dt>c <dd> character
     * </dl>
     * </ul>
     * @exception IllegalArgumentException if bad format
     */
    public Format(String s) {
	width = 0;
	precision = -1;
	pre = "";
	post = "";
	leading_zeroes = false;
	show_plus = false;
	alternate = false;
	show_space = false;
	left_align = false;
	fmt = ' '; 

	int state = 0; 
	int length = s.length();
	int parse_state = 0; 
	// 0 = prefix, 1 = flags, 2 = width, 3 = precision,
	// 4 = format, 5 = end
	int i = 0;

	while (parse_state == 0) {
	    if (i >= length) {
		parse_state = 5;
	    } else if (s.charAt(i) == '%') {
		if (i < length - 1) {
		    if (s.charAt(i + 1) == '%') {
			pre = pre + '%';
			i++;
		    } else {
			parse_state = 1;
		    }
	 	} else {
		    throw new java.lang.IllegalArgumentException();
		}
	    } else {
		pre = pre + s.charAt(i);
	    }
	    i++;
	}

	while (parse_state == 1) {
	    if (i >= length) {
	        parse_state = 5;
	    } else if (s.charAt(i) == ' ') {
		show_space = true;
	    } else if (s.charAt(i) == '-') {
		left_align = true; 
	    } else if (s.charAt(i) == '+') {
		show_plus = true;
	    } else if (s.charAt(i) == '0') {
		leading_zeroes = true;
	    } else if (s.charAt(i) == '#') {
		alternate = true;
	    } else {
		parse_state = 2; i--;
	    }
	    i++;
	}

	while (parse_state == 2) {
	    if (i >= length) {
		parse_state = 5;
	    } else if ('0' <= s.charAt(i) && s.charAt(i) <= '9') {
		width = width * 10 + s.charAt(i) - '0';
		i++;
	    } else if (s.charAt(i) == '.') {
		parse_state = 3;
		precision = 0;
		i++;
	    } else {
		parse_state = 4;            
	    }
	}

	while (parse_state == 3) {
	    if (i >= length) {
		parse_state = 5;
	    } else if ('0' <= s.charAt(i) && s.charAt(i) <= '9') {
		precision = precision * 10 + s.charAt(i) - '0';
		i++;
	    } else {
		parse_state = 4;                  
	    }
	}

	if (parse_state == 4) {
	    if (i >= length) {
		parse_state = 5;
	    } else {
		fmt = s.charAt(i);
	    }
	    i++;
	}

	if (i < length) {
	    post = s.substring(i, length);
	}      
    }      

    /** 
     * prints a formatted number following printf conventions
     * @param s a PrintStream
     * @param fmt the format string
     * @param x the double to print
     */
    public static void print(java.io.PrintStream s, String fmt, double x) {
	s.print(new Format(fmt).form(x));
    }

    /** 
     * prints a formatted number following printf conventions
     * @param s a PrintStream
     * @param fmt the format string
     * @param x the long to print
     */
    public static void print(java.io.PrintStream s, String fmt, long x) {
	s.print(new Format(fmt).form(x));
    }

    /** 
     * prints a formatted number following printf conventions
     * @param s a PrintStream
     * @param fmt the format string
     * @param x the character to 
     */
    public static void print(java.io.PrintStream s, String fmt, char x) {
	s.print(new Format(fmt).form(x));
    }

    /** 
     * prints a formatted number following printf conventions
     * @param s a PrintStream, fmt the format string
     * @param x a string that represents the digits to print
     */
    public static void print(java.io.PrintStream s, String fmt, String x) {
	s.print(new Format(fmt).form(x));
    }
   
    /** 
     * Converts a string of digits(decimal, octal or hex) to an integer
     * @param s a string
     * @return the numeric value of the prefix of s representing a base
     * 10 integer
     */
    public static int atoi(String s) {
	return (int)atol(s);
    } 
   
    /** 
     * Converts a string of digits(decimal, octal or hex) to a long integer
     * @param s a string
     * @return the numeric value of the prefix of s representing a base
     * 10 integer
     */
    public static long atol(String s) {
	int i = 0;

	while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
	    i++;
	}

	if (i < s.length() && s.charAt(i) == '0') {
	    if (i + 1 < s.length() && (s.charAt(i + 1) == 'x' ||
		s.charAt(i + 1) == 'X')) {
		return parseLong(s.substring(i + 2), 16);
	    } else {
		return parseLong(s, 8);
	    }
	} else {
	    return parseLong(s, 10);
	}
    }

    private static long parseLong(String s, int base) {
	int i = 0;
	int sign = 1;
	long r = 0;
      
	while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
	    i++;
	}

	if (i < s.length() && s.charAt(i) == '-') {
	    sign = -1; i++;
	} else if (i < s.length() && s.charAt(i) == '+') {
	    i++;
	}

	while (i < s.length()) {
	    char ch = s.charAt(i);
	    if ('0' <= ch && ch < '0' + base) {
		r = r * base + ch - '0';
	    } else if ('A' <= ch && ch < 'A' + base - 10) {
		r = r * base + ch - 'A' + 10;
	    } else if ('a' <= ch && ch < 'a' + base - 10) {
		r = r * base + ch - 'a' + 10;
	    } else {
		return r * sign;
	    }
	    i++;
	}
	return r * sign;      
    }
      
    /** 
    * Converts a string of digits to an double
    * @param s a string
    */
    public static double atof(String s) {
	int i = 0;
	int sign = 1;
	double r = 0; // integer part
	double f = 0; // fractional part
	double p = 1; // exponent of fractional part
	int state = 0; // 0 = int part, 1 = frac part
      
	while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
	    i++;
	}

	if (i < s.length() && s.charAt(i) == '-') {
	    sign = -1; i++;
	} else if (i < s.length() && s.charAt(i) == '+') {
	    i++;
	}

	while (i < s.length()) {
	    char ch = s.charAt(i);
	    if ('0' <= ch && ch <= '9') {
		if (state == 0) {
		    r = r * 10 + ch - '0';
		} else if (state == 1) {
		    p = p / 10;
		    r = r + p * (ch - '0');
		}
	    } else if (ch == '.') {
		if (state == 0) {
		    state = 1; 
		} else {
		    return sign * r;
		}
	    } else if (ch == 'e' || ch == 'E') {
		long e = (int)parseLong(s.substring(i + 1), 10);
		return sign * r * Math.pow(10, e);
	    } else {
		return sign * r;
	    }
	    i++;
	}
	return sign * r;
    }
            
    /** 
     * Formats a double into a string (like sprintf in C)
     * @param x the number to format
     * @return the formatted string 
     * @exception IllegalArgumentException if bad argument
     */
    public String form(double x) {
	String r;
	if (precision < 0) {
	    precision = 6;
	}

	int s = 1;
	if (x < 0) {
	    x = -x;
	    s = -1;
	}

	if (fmt == 'f') {
	    r = fixed_format(x);
	} else if (fmt == 'e' || fmt == 'E' || fmt == 'g' || fmt == 'G') {
	    r = exp_format(x);
	} else {
	    throw new java.lang.IllegalArgumentException();
	}
      
	return pad(sign(s, r));
    }
   
    /** 
     * Formats a long integer into a string (like sprintf in C)
     * @param x the number to format
     * @return the formatted string 
     */
    public String form(long x) {
	String r; 
	int s = 0;
	if (fmt == 'd' || fmt == 'i') {
	    s = 1;
	    if (x < 0) {
		x = -x; s = -1;
	    }
	    r = "" + x;
	} else if (fmt == 'o') {
	    r = convert(x, 3, 7, "01234567");
	} else if (fmt == 'x') {
	    r = convert(x, 4, 15, "0123456789abcdef");
	} else if (fmt == 'X') {
	    r = convert(x, 4, 15, "0123456789ABCDEF");
	} else {
	    throw new java.lang.IllegalArgumentException();
	}         
	return pad(sign(s, r));
    }
   
    /** 
     * Formats a character into a string (like sprintf in C)
     * @param x the value to format
     * @return the formatted string 
     */
    public String form(char c) {
	if (fmt != 'c') {
	    throw new java.lang.IllegalArgumentException();
	}
	String r = "" + c;
	return pad(r);
    }
   
    /** 
     * Formats a string into a larger string (like sprintf in C)
     * @param x the value to format
     * @return the formatted string 
     */
    public String form(String s) {
	if (fmt != 's') {
	    throw new java.lang.IllegalArgumentException();
	}

	if (precision >= 0) {
	    s = s.substring(0, precision);
	}
	return pad(s);
    }
   
    private static String repeat(char c, int n) {
	if (n <= 0) {
	    return "";
	}
	StringBuffer s = new StringBuffer(n);
	for (int i = 0; i < n; i++) {
	    s.append(c);
	}
	return s.toString();
    }

    private static String convert(long x, int n, int m, String d) {
	if (x == 0) {
	    return "0";
	}
	String r = "";
	while (x != 0) {
	    r = d.charAt((int)(x & m)) + r;
	    x = x >>> n;
	}
	return r;
    }

    private String pad(String r) {
	String p = repeat(' ', width - r.length());
	if (left_align) {
	    return pre + r + p + post;
	} else {
	    return pre + p + r + post;
	}
    }
   
    private String sign(int s, String r) {
	String p = "";
	if (s < 0) {
	    p = "-"; 
	} else if (s > 0) {
	    if (show_plus) {
		p = "+";
	    } else if (show_space) {
		p = " ";
	    }
	} else {
	    if (fmt == 'o' && alternate && r.length() > 0 &&
		r.charAt(0) != '0') {
		p = "0";
	    } else if (fmt == 'x' && alternate) {
		p = "0x";
	    } else if (fmt == 'X' && alternate) {
		p = "0X";
	    }
	}

	int w = 0;
	if (leading_zeroes) {
	    w = width;
	} else if ((fmt == 'd' || fmt == 'i' || fmt == 'x' || 
	    fmt == 'X' || fmt == 'o') && precision > 0) {
	    w = precision;
	}
      
	return p + repeat('0', w - p.length() - r.length()) + r;
    }
   
           
    private String fixed_format(double d) {
	String f = "";

	if (d > 0x7FFFFFFFFFFFFFFFL) {
	    return exp_format(d);
	}
   
	long l = (long)(precision == 0 ? d + 0.5 : d);
	f = f + l;
      
	double fr = d - l; // fractional part
	if (fr >= 1 || fr < 0) {
	    return exp_format(d);
	}
    
	return f + frac_part(fr);
    }   
   
    private String frac_part(double fr) {
	// precondition: 0 <= fr < 1
	String z = "";
	if (precision > 0) {
	    double factor = 1;
	    String leading_zeroes = "";
	    for (int i = 1; i <= precision && factor <= 0x7FFFFFFFFFFFFFFFL;
		i++) {
		factor *= 10; 
		leading_zeroes = leading_zeroes + "0"; 
	    }
	    long l = (long) (factor * fr + 0.5);

	    z = leading_zeroes + l;
	    z = z.substring(z.length() - precision, z.length());
	}

      
	if (precision > 0 || alternate) {
	    z = "." + z;
	}

	if ((fmt == 'G' || fmt == 'g') && !alternate) {
	    // remove trailing zeroes and decimal point
	    int t = z.length() - 1;
	    while (t >= 0 && z.charAt(t) == '0') {
		t--;
	    }
	    if (t >= 0 && z.charAt(t) == '.') {
		t--;
	    }
	    z = z.substring(0, t + 1);
	}
	return z;
    }

    private String exp_format(double d) {
	String f = "";
	int e = 0;
	double dd = d;
	double factor = 1;

	while (dd > 10) {
	    e++; factor /= 10; dd = dd / 10;
	}

	while (dd < 1) {
	    e--; factor *= 10; dd = dd * 10;
	}

	if ((fmt == 'g' || fmt == 'G') && e >= -4 && e < precision) {
	    return fixed_format(d);
	}
      
	d = d * factor;
	f = f + fixed_format(d);
      
	if (fmt == 'e' || fmt == 'g') {
	    f = f + "e";
	} else {
	    f = f + "E";
	}

	String p = "000";      
	if (e >= 0)  {
	    f = f + "+";
	    p = p + e;
	} else {
	    f = f + "-";
	    p = p + (-e);
	}
         
	return f + p.substring(p.length() - 3, p.length());
    }
   
    private int width;
    private int precision;
    private String pre;
    private String post;
    private boolean leading_zeroes;
    private boolean show_plus;
    private boolean alternate;
    private boolean show_space;
    private boolean left_align;
    private char fmt; // one of cdeEfgGiosxXos
}
