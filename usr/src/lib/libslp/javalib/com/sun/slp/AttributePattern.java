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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

//  AttributePattern.java: Models a pattern for attribute matching.
//  Author:           James Kempf
//  Created On:       Tue Feb  3 15:26:30 1998
//  Last Modified By: James Kempf
//  Last Modified On: Thu Aug  6 14:33:57 1998
//  Update Count:     19
//

package com.sun.slp;

import java.util.*;
import java.io.*;

/**
 * The AttributePattern class models an attribute pattern. It handles
 * wildcard matching of lowercased, space-compressed strings. Each
 * element in the parts vector is a PatternPart object. A PatternPart
 * object is a pattern consisting of (maximally) a beginning wildcard and
 * string pattern. A PatternPart may be lacking the
 * any of these, but will always have at least one.
 *
 * @author James Kempf
 */

class AttributePattern extends AttributeString {

    private static final String WILDCARD = "*";

    private Vector parts = new Vector();

    /**
     * The PatternPart class models a single component of a pattern.
     * It may have a beginning wildcard and string
     * pattern in the middle. Any of the parts may be missing, but it will
     * always have at least one.
     *
     * @author James Kempf
     */


    private class PatternPart extends Object {

	boolean wildcard = false;
	String pattern = "";

	PatternPart(boolean wc, String str) {
	    wildcard = wc;
	    pattern = str;

	}
    }

    AttributePattern(String str, Locale locale) {

	super(str, locale);

	// Parse out wildcards into PatternPart objects.

	// If there's no wildcards, simply insert the string in as the pattern.

	if (cstring.indexOf(WILDCARD) == -1) {
	    parts.addElement(new PatternPart(false, cstring));

	} else {

	    // Parse the patterns into parts.

	    StringTokenizer tk = new StringTokenizer(cstring, WILDCARD, true);

	    while (tk.hasMoreTokens()) {
		String middle = "";
		boolean wc = false;

		String tok = tk.nextToken();

		// Beginning wildcard, or, if none, then the middle.

		if (tok.equals(WILDCARD)) {
		    wc = true;

		    // Need to look for middle.

		    if (tk.hasMoreTokens()) {
			middle = tk.nextToken();

		    }

		} else {
		    middle = tok;

		}

		// Note that there may be a terminal pattern part that just
		//  consists of a wildcard.

		parts.addElement(new PatternPart(wc, middle));
	    }
	}
    }

    boolean isWildcarded() {
	return (parts.size() > 1);

    }

    // Match the AttributeString object against this pattern,
    //  returning true if they match.

    public boolean match(AttributeString str) {
	String cstring = str.cstring;
	int offset = 0, len = cstring.length();
	int i = 0, n = parts.size();
	boolean match = true;

	// March through the parts, matching against the string.

	for (; i < n; i++) {
	    PatternPart p = (PatternPart)parts.elementAt(i);

	    // If there's a wildcard, check the remainder of the string for
	    //  the pattern.

	    if (p.wildcard) {

		// Note that if the pattern string is empty (""), then this
		//  will return offset, but on the next iteration, it will
		//  fall out of the loop because an empty pattern string
		//  can only occur at the end (like "foo*").

		if ((offset = cstring.indexOf(p.pattern, offset)) == -1) {

		    // The pattern was not found. Break out of the loop.

		    match = false;
		    break;
		}

		offset += p.pattern.length();

		// We are at the end of the string.

		if (offset >= len) {

		    // If we are not at the end of the pattern, then we may not
		    //  have a match.

		    if (i < (n - 1)) {

			// If there is one more in the pattern, and it is
			// a pure wildcard, then we *do* have a match.

			if (i == (n - 2)) {
			    p = (PatternPart)parts.elementAt(i+1);

			    if (p.wildcard == true &&
			       p.pattern.length() <= 0) {
				break;

			    }
			}

			match = false;

		    }

		    // Break out of the loop, no more string to analyze.

		    break;
		}

	    } else {

		// The pattern string must match the beginning part of the
		// argument string.

		if (!cstring.regionMatches(offset,
					   p.pattern,
					   0,
					   p.
					   pattern.length())) {
		    match = false;
		    break;

		}

		// Bump up offset by the pattern length, and exit if
		// we're beyond the end of the string.

		offset += p.pattern.length();

		if (offset >= len) {
		    break;

		}
	    }
	}

	return match;
    }
}
