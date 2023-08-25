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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */


/**
 * This is a replacement for StringTokenizer since there
 * is an incompatibility between JDK 1.2 and JDK 1.3.1
 * and beyond which breaks slp.jar support for apps which
 * could use either JDK.
 */

package com.sun.slp;

import java.util.Enumeration;
import java.util.NoSuchElementException;

public class SLPTokenizer implements Enumeration
{

    private String str;
    private String delims;
    private boolean bRetDel;
    private int index;

    private void initialize(String s, String d, boolean b)
    {
	str = s;
	delims = d;
	bRetDel = b;
	index = 0;
    }

    public SLPTokenizer(String s)
    {
	initialize(s, "", false);
    }

    public SLPTokenizer(String s, String delim)
    {
	initialize(s, delim, false);
    }

    public SLPTokenizer(String s, String delim, boolean returnDelims)
    {
	initialize(s, delim, returnDelims);
    }

    /**
     * Calculates the number of times that this tokenizer's
     * nextToken method can be called before it generates an
     * exception.
     */
    public int countTokens()
    {
	int i = 0;

	if (str.length() < 1) {
            return 0;
        }

	char c = str.charAt(0);
	boolean inToken = false;

	// a token starts if
	//  (a) next character is a non delimiter
	//  (b) there are more characters

	for (int j = 0; j < str.length(); j++)
	{
	    c = str.charAt(j);
	    if (delims.indexOf(c) != -1) {
		if (bRetDel) {
		    i++;
		}

		if (inToken == true) {
		    i++; // we were in a token, now completed it
		    inToken = false;
		}
	    } else {

		// To get here, we must be in a token.
		inToken = true;
	    }
	}

	if (inToken) {
	    i++;
	}

	return i;
    }

    /**
     * Returns the same value as the hasMoreTokens method.
     */

    public boolean hasMoreElements()
    {
	if (str.length() < 1) {
            return false;
        }

	if (index >= str.length()) {
            return false;
        }

	if (bRetDel == false) {
	    // Check to see if all there is left are delimiters.
	    // If so there are no more elements.
	    for (int i = index; i < str.length(); i++) {

		if (delims.indexOf(str.charAt(i)) == -1) {
		    return true;  // A non-delim char found!
                }
	    }
	    return false; // No non-delim chars remain!
	}

	return true;  // Something remains.
    }

    /**
     * Tests if there are more tokens available from this
     * tokenizer's string.
     */
    public boolean hasMoreTokens()
    {
	return hasMoreElements();
    }

    /**
     * Returns the same value as the nextToken method,
     * except that its declared return value is Object
     * rather than String.
     */
    public Object nextElement()
	throws NoSuchElementException
    {
	return (Object) nextToken();
    }

    /**
     * Returns the next token from this string tokenizer.
     *
     */
    public String nextToken()
	throws NoSuchElementException
    {
	if (index >= str.length()) throw new NoSuchElementException();

	StringBuffer sb = new StringBuffer();
        char c = str.charAt(index);

	if (bRetDel == true)
        {

	    if (delims.indexOf(c) != -1) {

		// We begin at a delimiter.  Return it & advance over.
		sb.append(str.charAt(index));
		index++;
		return sb.toString();

	    } else {
		// Advance to next delimiter and stop.  Return string.
		while (index < str.length()) {

		    c = str.charAt(index);
		    if (delims.indexOf(c) != -1) {

			return sb.toString();

		    } else {

			sb.append(c);

		    }
		    index++;
		}
		// We get here only if this is the last token.
		return sb.toString();
	    }
	} else {
	    // 3 cases
	    //   token till the end
            //   token till a delimiter
	    //   only delimiters till the end (exception!)
	    while (index < str.length()) {

		c = str.charAt(index);
		if (delims.indexOf(c) != -1) {
		    if (sb.length() != 0) {

			index++; // Skip past the delimiter.
			return sb.toString();
		    }
		    index++; // Do not include delimiters if no content yet.

		} else { // Not the delimiter yet.

		    sb.append(c);
		    index++;
		}
	    }

	    if (sb.length() == 0) {
                throw new NoSuchElementException();
            }

	    return sb.toString();
	}
    }

    /**
     * Returns the next token in this string tokenizer's string.
     */
    public String nextToken(String delim)
	throws NoSuchElementException
    {
	String saveDelims = delims;
	delims = delim;
	try
	{
	    // This is not thread safe, but it will String.
	    // There are no guarantees StringTokenizer is
	    // thread safe either.
	    String ret = nextToken();
	    delims = saveDelims;
	    return ret;
	}
	catch (NoSuchElementException nsee)
	{
	    delims = saveDelims;
	    throw nsee;
	}
    }
}
