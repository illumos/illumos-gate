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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *        Copyright (C) 1996  Active Software, Inc.
 *                  All rights reserved.
 *
 * @(#) ListParser.java 1.16 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Global;

import java.util.*;

/**
 * Utility class for parsing lists of things in the style of Tcl.
 *
 * @version 	1.16, 07/25/97
 */
public class ListParser {
    
    // Character constants
    private static final char CHAR_a	= /* NOI18N */ 'a';
    private static final char CHAR_b	= /* NOI18N */ 'b';
    private static final char CHAR_f	= /* NOI18N */ 'f';
    private static final char CHAR_n	= /* NOI18N */ 'n';
    private static final char CHAR_r	= /* NOI18N */ 'r';
    private static final char CHAR_t	= /* NOI18N */ 't';
    private static final char CHAR_x	= /* NOI18N */ 'x';
    private static final char CHAR_A	= /* NOI18N */ 'A';
    private static final char CHAR_F	= /* NOI18N */ 'F';
    private static final char BACKSLASH	= /* NOI18N */ '\\';
    private static final char BACKSPACE	= /* NOI18N */ '\b';
    private static final char DQUOTE	= /* NOI18N */ '"';
    private static final char EQUALS	= /* NOI18N */ '=';
    private static final char FORMFEED	= /* NOI18N */ '\f';
    private static final char LBRACE	= /* NOI18N */ '{';
    private static final char NEWLINE	= /* NOI18N */ '\n';
    private static final char NINE	= /* NOI18N */ '9';
    private static final char NULL	= /* NOI18N */ '\0';
    private static final char RBRACE	= /* NOI18N */ '}';
    private static final char RETURN	= /* NOI18N */ '\r';
    private static final char SPACE	= /* NOI18N */ ' ';
    private static final char TAB		= /* NOI18N */ '\t';
    private static final char ZERO	= /* NOI18N */ '0';
    
    private Vector list;
    
    public ListParser(String str) {
        int begin = 0;
        int end = str.length();
        initList(str, begin, end);
    }
    
    public ListParser(String str, int offset) {
        int begin, end = str.length();
        if (offset >= 0 && offset < end)
            begin = offset;
        else
            begin = end;
        
        initList(str, begin, end);
    }
    
    public ListParser(String str, int begin, int end) {
        int len = str.length();
        if (end < 0 || end > len)
            end = len;
        if (begin < 0)
            begin = 0;
        if (begin > end)
            begin = end;
        
        initList(str, begin, end);
    }
    
    public Enumeration elements() {
        return list.elements();
    }
    
    public int size() {
        return list.size();
    }
    
    private void initList(String str, int begin, int end) {
        list = new Vector();
        
        int len = end-begin;
        char buf[] = new char[len];
        str.getChars(begin, end, buf, 0);
        
        parseList(list, buf);
    }
    
    private void parseList(Vector list, char buf[]) {
        nextIndex = 0;
        
        while (nextIndex < buf.length && buf[nextIndex] != 0) {
            try {
                findElement(buf, nextIndex);
            }
            catch (ParseException ex) {
                list.removeAllElements();
                throw ex;
            }
            
            if (elementSize != 0 ||
		(elementIndex < buf.length && buf[elementIndex] != 0)) {
                if (brace) {
                    list.addElement(new String(buf, elementIndex,
					       elementSize));
                } else {
                    list.addElement(collapse(buf, elementIndex,
					     elementSize));
                }
            }
        }
    }
    
    /* BEGIN JSTYLED */
    /* 
     *----------------------------------------------------------------------
     *
     * findElement --
     *
     *	Given a character buffer containing a Tcl list, locate the first
     *    (or next) element in the list.
     *
     * Results:
     *    None.
     *
     * Side effects:
     *	If an exception is not thrown, then elementIndex will be set to
     *    the position of the first element of the list, 
     *     and nextIndex will
     *    be set to the position of the character just after 
     *     any white space
     *    following the last character that's part of the element.  If this
     *    is the last argument in the list, then nextIndex will point to the
     *    NULL character at the end of list.  elementSize is set to
     *	the number of characters in the element.  If the element is in
     *	braces, then elementIndex will point to the character after the
     *	opening brace and elementSize will not include either of the braces.
     *	If there isn't an element in the list, elementSize will be zero,
     *	elementIndex will refer to the null character at the end of list,
     *    and brace will be set to true.
     *
     *    Note:  this procedure does NOT collapse backslash sequences.
     *
     *----------------------------------------------------------------------
     */

    /* END JSTYLED */
    // Side effect variables
    private int elementIndex;
    private int nextIndex;
    private int elementSize;
    private boolean brace;
    
    private void findElement(char buf[], int offset) {
        
        int list = offset;
        int p;
        int openBraces = 0;
        boolean inQuotes = false;
        int size = 0;
        char c;
        
        /*
         * Skim off leading white space and check for 
	 * an opening brace or
	 * quote.
	 */
        
        while (list < buf.length && Character.isSpace(buf[list])) {
            list++;
        }
        
        if (list < buf.length && buf[list] == LBRACE) {
            openBraces = 1;
            list++;
        } else if (list < buf.length && buf[list] == DQUOTE) {
            inQuotes = true;
            list++;
        }
        brace = (openBraces == 1);
        p = list;
        
        /*
         * Find the end of the element (either a space or a 
	 * close brace or
	 * the end of the string).
	 */
        
        try {
            while (true) {
                if (p < buf.length)
                    c = buf[p];
                else
                    c = 0;
                switch (c) {
                    
                    /*
                     * Open brace: don't treat specially unless 
		     * the element is
		     * in braces.  In this case, keep a nesting count.
		     */
                    
		case LBRACE:
                    if (openBraces != 0) {
                        openBraces++;
                    }
                    break;
                    
                    /*
                     * Close brace: if element is in braces, 
		     * keep nesting
		     * count and quit when the last close brace
		     * is seen.
                    */
                    
		case RBRACE:
                    if (openBraces == 1) {
                        int p2;
                        
                        size = p - list;
                        p++;
                        if (p >= buf.length || buf[p] == 0 ||
			    Character.isSpace(buf[p])) {
                            throw new DoneException();
                        }
                        for (p2 = p; p2 < buf.length && buf[p2] != 0 &&
				 !Character.isSpace(buf[p2]) && (p2 < p+20);
			     p2++) {
                            /* null body */
                        }
                        
                        String err = new String(buf, p, p2-p);
                        throw new ParseException(
						 /* JSTYLED */
						 Global.fmtMsg("sunsoft.jws.visual.rt.type.ListParser.SpaceExpected", String.valueOf(buf, p, p2-p)));
                        
                    } else if (openBraces != 0) {
                        openBraces--;
                    }
                    break;
                    
                    /*
                     * Backslash:  skip over everything up to 
		     * the end of the
		     * backslash sequence.
		     */
                    
		case BACKSLASH: {
		    IntHolder backslashSize = new IntHolder();
		    backslash(buf, p, backslashSize);
		    p += backslashSize.value - 1;
		    break;
		}
                    
		/*
		 * Space: ignore if element is in braces or 
		 * quotes;  otherwise
		 * terminate element.
		 */
                    
		case SPACE:
		case FORMFEED:
		case NEWLINE:
		case RETURN:
		case TAB:
                    if ((openBraces == 0) && !inQuotes) {
                        size = p - list;
                        throw new DoneException();
                    }
                    break;
                    
                    /*
                     * Double-quote:  if element is in quotes then 
		     * terminate it.
                    */
                    
		case DQUOTE:
                    if (inQuotes) {
                        int p2;
                        
                        size = p-list;
                        p++;
                        if (p >= buf.length || buf[p] == 0 ||
			    Character.isSpace(buf[p])) {
                            throw new DoneException();
                        }
                        for (p2 = p; (p2 < buf.length && buf[p2] != 0)
				 &&
				 (!Character.isSpace(buf[p2])) && (p2 < p+20);
			     p2++) {
                            /* null body */
                        }
                        
                        throw new ParseException(
						 /* JSTYLED */
			 Global.fmtMsg("sunsoft.jws.visual.rt.type.ListParser.SpaceExpected2",
		       String.valueOf(buf, p, p2-p), String.valueOf
				       (buf, p, buf.length-1)));
                        
                    }
                    break;
                    
                    /*
                     * End of list:  terminate element.
                     */
                    
		case 0:
                    if (openBraces != 0) {
			/* BEGIN JSTYLED */
			throw new ParseException(Global.getMsg("sunsoft.jws.visual.rt.type.ListParser.UnmatchedBrace"));
		    } else if (inQuotes) {
			throw new ParseException(Global.getMsg("sunsoft.jws.visual.rt.type.ListParser.UnmatchedQuote"));
		    }
			    
		    size = p - list;
		    throw new DoneException();
		}
		p++;
	    }
	}
	catch (DoneException ex) {
	}
                
	while (p < buf.length && Character.isSpace(buf[p])) {
	    p++;
	}
                
	elementIndex = list;
	nextIndex = p;
	elementSize = size;
    }
            
    /*
     *----------------------------------------------------------------------
     *
     * collapse --
     *
     *	Return a new string after eliminating any backslashes that
     *    aren't in braces.
     *
     * Results:
     *	Returns a string that is a substring of buf starting at offset,
     *    and count characters long.  If backslash sequences are found
     *    outside braces, the backslashes are eliminated in the new string.
     *
     * Side effects:
     *	None.
     *
     *----------------------------------------------------------------------
     */
    /* END JSTYLED */
                        
    private String collapse(char buf[], int offset, int count) {
	int p = offset;
	char c;
	IntHolder numRead = new IntHolder();
	char dst[] = new char[buf.length+1];
	int p2 = 0;
                            
	while (count > 0) {
	    if (p < buf.length)
		c = buf[p];
	    else
		c = 0;
                                
	    if (c == BACKSLASH) {
		dst[p2] = backslash(buf, p, numRead);
		p2++;
		p += numRead.value-1;
		count -= numRead.value-1;
	    } else {
		dst[p2] = c;
		p2++;
	    }
	    p++;
	    count--;
	}
	dst[p2] = 0;
                            
	return new String(dst, 0, p2);
    }
                        
	/*
	*------------------------------------------
	*
	* backslash --
	*
	*	Figure out how to handle a backslash sequence.
	*
	* Results:
	*	The return value is the character that should be substituted
	*	in place of the backslash sequence that starts at src.
	*	The "readPtr" variable is set to the number of characters
	*    in the backslash sequence.
	*
	* Side effects:
	*   none
	*
	* Parameters:
	*   char buf[];		Character buffer containing
	* the backslash
	*				sequence.
	*   int offset;		Offset within buf where the backslash
	*				sequence begins.
	*------------------------------------------
	*/
                        
    private static char backslash(char buf[], int offset,
				  IntHolder readPtr) {
                            
	int p = offset+1;
	char result;
	int count;
	char c;
                            
	count = 2;
                            
	if (p < buf.length)
	    c = buf[p];
	else
	    c = 0;
	switch (c) {
	case CHAR_a:
	    result = 0x7;	/* Don't say '\a' here, */
                                /* since some compilers */
	    break;		/* don't support it. */
	case CHAR_b:
	    result = BACKSPACE;
	    break;
	case CHAR_f:
	    result = FORMFEED;
	    break;
	case CHAR_n:
	    result = NEWLINE;
	    break;
	case CHAR_r:
	    result = RETURN;
	    break;
	case CHAR_t:
	    result = TAB;
	    break;
	case CHAR_x:
	    if (isxdigit(buf[p+1])) {
		int p2 = p+1;
		while (isxdigit(buf[p2])) {
		    p2++;
		}
                                    
		result = (char)
		    Integer.parseInt(String.valueOf(buf, p+1, p2), 16);
		count = p2 - offset;
	    } else {
		count = 2;
		result = CHAR_x;
	    }
	    break;
	case NEWLINE:
	    do {
		p++;
	    } while ((buf[p] == SPACE) || (buf[p] == TAB));
	    result = SPACE;
	    count = p - offset;
	    break;
	case 0:
	    result = BACKSLASH;
	    count = 1;
	    break;
	default:
	    if (isdigit(buf[p])) {
		result = (char)(buf[p] - ZERO);
		p++;
		if (!isdigit(buf[p])) {
		    break;
		}
		count = 3;
		result = (char)((result << 3) + (buf[p] - ZERO));
		p++;
		if (!isdigit(buf[p])) {
		    break;
		}
		count = 4;
		result = (char)((result << 3) + (buf[p] - ZERO));
		break;
	    }
	    result = buf[p];
	    count = 2;
	    break;
	}
                            
	if (readPtr != null)
	    readPtr.value = count;
                            
	return result;
    }
    /* BEGIN JSTYLED */
            
    /*
     * The following values are used in the flags 
     * returned by Tcl_ScanElement
     * and used by Tcl_ConvertElement.  The value 
     * TCL_DONT_USE_BRACES is also
     * defined in tcl.h;  make sure its value doesn't 
     * overlap with any of the
     * values below.
     *
     * TCL_DONT_USE_BRACES -	1 means the string mustn't 
     * be enclosed in
     *				braces (e.g. it contains 
     * unmatched braces,
     *				or ends in a backslash 
     * character, or user
     *				just doesn't want braces);  handle all
     *				special characters by adding 
     * backslashes.
     * USE_BRACES -		1 means the string contains a special
     *				character that can be handled simply by
     *				enclosing the entire argument 
     * in braces.
     * BRACES_UNMATCHED -		1 means that braces 
     * aren't properly matched
     *				in the argument.
     */
            
    private static final int TCL_DONT_USE_BRACES = 1;
    private static final int USE_BRACES = 2;
    private static final int BRACES_UNMATCHED = 4;
            
    /*
     *-----------------------------------
     *
     * scanElement --
     *
     *	This procedure is a companion procedure to Tcl_ConvertElement.
     *	It scans a string to see what needs to be done to it (e.g.
     *	add backslashes or enclosing braces) to make the string into
     *	a valid Tcl list element.
     *
     * Results:
     *	The return value is an overestimate of the number of characters
     *	that will be needed by Tcl_ConvertElement to produce a valid
     *	list element from string.  The word at *flagPtr is filled in
     *	with a value needed by Tcl_ConvertElement when doing the actual
     *	conversion.
     *
     * Side effects:
     *	None.
     *
     *---------------------------------------
    */
            
    // char *string;	/* String to convert to Tcl list element. */
    // int *flagPtr;    /* Where to store information to guide */
    //			     /* Tcl_ConvertElement. */

	
    private static int scanElement(char buf[], IntHolder flagPtr) {
	int flags, nestingLevel;
	int p;
                
	/*
	 * This procedure and Tcl_ConvertElement together 
	 * do two things:
	 *
	 * 1. They produce a proper list, one that will yield back the
	 * argument strings when evaluated or when disassembled with
	 * Tcl_SplitList.  This is the most important thing.
	 * 
	 * 2. They try to produce legible output, which means 
	 *	 minimizing the
	 * use of backslashes (using braces instead).  However, 
	 *	 there are
	 * some situations where backslashes must be used 
	 * (e.g. an element
	 * like "{abc": the leading brace will have to be 
	 *	 backslashed.  For
	 * each element, one of three things must be done:
	 *
	 * (a) Use the element as-is (it doesn't contain 
	 *	 anything special
	 * characters).  This is the most desirable option.
	 *
	 * (b) Enclose the element in braces, but leave the 
	 *	 contents alone.
	 * This happens if the element contains embedded space, 
	 *	 or if it
	 * contains characters with special interpretation 
	 * ($, [, ;, or \),
	 * or if it starts with a brace or double-quote, or 
	 * if there are
	 * no characters in the element.
	 *
	 * (c) Don't enclose the element in braces, but 
	 *	 add backslashes to
	 * prevent special interpretation of special characters.  
	 *	 This is a
	 * last resort used when the argument would normally 
	 *	 fall under case
	 * (b) but contains unmatched braces.  It also occurs 
	 *	 if the last
	 * character of the argument is a backslash or if the 
	 *	 element contains
	 * a backslash followed by newline.
	 *
	 * The procedure figures out how many bytes will be 
	 *	 needed to store
	 * the result (actually, it overestimates).  It also 
	 *	 collects information
	 * about the element in the form of a flags word.
	 */
                
	/* END JSTYLED */
	nestingLevel = 0;
	flags = 0;
	if (buf == null) {
	    buf = new char[0];
	}
	p = 0;
	if ((p >= buf.length) || (buf[p] == LBRACE) ||
	    (buf[p] == DQUOTE) || (buf[p] == 0)) {
	    flags |= USE_BRACES;
	}
	for (; p < buf.length && buf[p] != 0; p++) {
	    switch (buf[p]) {
	    case LBRACE:
		nestingLevel++;
		break;
	    case RBRACE:
		nestingLevel--;
		if (nestingLevel < 0) {
		    flags |= TCL_DONT_USE_BRACES|BRACES_UNMATCHED;
		}
		break;
	    case SPACE:
	    case FORMFEED:
	    case NEWLINE:
	    case RETURN:
	    case TAB:
		flags |= USE_BRACES;
		break;
	    case BACKSLASH:
		if ((buf[p+1] == 0) || (buf[p+1] == NEWLINE)) {
		    flags = TCL_DONT_USE_BRACES;
		} else {
		    IntHolder size = new IntHolder();
                                    
		    backslash(buf, p, size);
		    p += size.value-1;
		    flags |= USE_BRACES;
		}
		break;
	    }
	}
	if (nestingLevel != 0) {
	    flags = TCL_DONT_USE_BRACES | BRACES_UNMATCHED;
	}
	flagPtr.value = flags;
                        
	/*
	 * Allow enough space to backslash every character plus leave
	 * two spaces for braces.
	 */
                        
	return 2*p + 2;
    }
                    
    /* BEGIN JSTYLED */
    /*
     *------------------------------------------
     *
     * convertElement --
     *
     *	This is a companion procedure to scanElement.  Given the
     *	information produced by scanElement, this procedure converts
     *	a string to a list element equal to that string.
     *
     * Results:
     *	Information is copied to *dst in the form of a list element
     *	identical to src (i.e. if Tcl_SplitList is applied to dst it
     *	will produce a string identical to src).  The return value is
     *	a count of the number of characters copied (not including the
     *	terminating NULL character).
     *
     * Side effects:
     *	None.
     *
     *--------------------------------------
    */
    /* END JSTYLED */
                    
    // register char *src;  /* Source information for list element. */
    // char *dst;	    /* Place to put list-ified element. */
    // int flags;	    /* Flags produced by Tcl_ScanElement. */
                    
    private static int convertElement(char src[], char dst[],
				      int flags) {
                        
	int p = 0;
                        
	/*
	 * See the comment block at the beginning 
	 * of the Tcl_ScanElement
	 * code for details of how this works.
	 */
                        
	if ((src == null) || (src.length == 0)) {
	    dst[p] = LBRACE;
	    dst[p+1] = RBRACE;
	    dst[p+2] = 0;
	    return 2;
	}
	if ((flags & USE_BRACES) != 0 &&
	    (flags & TCL_DONT_USE_BRACES) == 0) {
	    dst[p] = LBRACE;
	    p++;
	    for (int p2 = 0; p2 < src.length && src[p2] != 0;
		 p++, p2++) {
		dst[p] = src[p2];
	    }
	    dst[p] = RBRACE;
	    p++;
	} else {
	    int p2 = 0;
	    if (src[p2] == LBRACE) {
                                /*
                                 * Can't have a leading brace unless 
				 * the whole element is
				 * enclosed in braces.  Add a backslash
				 * before the brace.
				 * Furthermore, this may destroy the
				 * balance between open
				 * and close braces, so set BRACES_UNMATCHED.
				 */
                                
		dst[p] = BACKSLASH;
		dst[p+1] = LBRACE;
		p += 2;
		p2++;
		flags |= BRACES_UNMATCHED;
	    }
	    for (; p2 < src.length && src[p2] != 0; p2++) {
		switch (src[p2]) {
		case SPACE:
		case BACKSLASH:
		case DQUOTE:
		    dst[p] = BACKSLASH;
		    p++;
		    break;
		case LBRACE:
		case RBRACE:
		    /* BEGIN JSTYLED */
		    /*
		     * It may not seem necessary to backslash 
		     * braces, but
		     * it is.  The reason for this is that 
		     * the resulting
		     * list element may actually be an 
		     * element of a sub-list
		     * enclosed in braces (e.g. if 
		     * Tcl_DStringStartSublist
		     * has been invoked), so there may be a 
		     * brace mismatch
		     * if the braces aren't backslashed.
		     */
		    /* END JSTYLED */
                                    
		    if ((flags & BRACES_UNMATCHED) != 0) {
			dst[p] = BACKSLASH;
			p++;
		    }
		    break;
		case FORMFEED:
		    dst[p] = BACKSLASH;
		    p++;
		    dst[p] = CHAR_f;
		    p++;
		    continue;
		case NEWLINE:
		    dst[p] = BACKSLASH;
		    p++;
		    dst[p] = CHAR_n;
		    p++;
		    continue;
		case RETURN:
		    dst[p] = BACKSLASH;
		    p++;
		    dst[p] = CHAR_r;
		    p++;
		    continue;
		case TAB:
		    dst[p] = BACKSLASH;
		    p++;
		    dst[p] = CHAR_t;
		    p++;
		    continue;
		}
		dst[p] = src[p2];
		p++;
	    }
	}
	dst[p] = NULL;
	return p;
    }
                    
    /*
     * Returns a new string that is a listified version of the string
     * argument.  The string will be enclosed with braces if necessary,
     * and all special characters will be escaped.
     */
    public static String list(String string) {
	char src[] = string.toCharArray();
                        
	IntHolder flagPtr = new IntHolder();
	int len = scanElement(src, flagPtr);
	char dst[] = new char[len+1];
	len = convertElement(src, dst, flagPtr.value);
                        
	return new String(dst, 0, len);
    }
                    
    /*
     * Appends a new string to the string buffer argument that is a
     * listified version of the string argument.  The string will be
     * enclosed with braces if necessary, and all special characters
     * will be escaped.
     */
    public static void list(String string, StringBuffer buf) {
	char src[] = string.toCharArray();
                        
	IntHolder flagPtr = new IntHolder();
	int len = scanElement(src, flagPtr);
	char dst[] = new char[len+1];
	len = convertElement(src, dst, flagPtr.value);
                        
	buf.append(dst, 0, len);
    }
                    
    /*
     * Returns a new string that is a quoted version of the string
     * argument.  The string will be enclosed with quotes if necessary,
     * and all special characters will be escaped.  If the forceQuotes
     * argument is true, then the string will be enclosed with quotes
     * even if it is not strictly necessary.  Also, if forceQuotes
     * is true, then the '\n' character will be replaced with the
     * string "\n".
     */
    public static String quote(String string, boolean forceQuotes) {
	char src[] = string.toCharArray();
	char dst[] = quote(src, forceQuotes);
	return new String(dst);
    }
                    
    /*
     * Appends a new string to the string buffer argument that is a
     * quoted version of the string argument.  The string will be
     * enclosed with quotes if necessary, and all special characters
     * will be escaped.  If the forceQuotes argument is true, then the
     * string will be enclosed with quotes even if it is not strictly
     * necessary.  Also, if forceQuotes is true, then the '\n' 
     * character
     * will be replaced with the string "\n".
     */
    public static void quote(String string, StringBuffer buf,
			     boolean forceQuotes) {
	char src[] = string.toCharArray();
	char dst[] = quote(src, forceQuotes);
	buf.append(dst);
    }
    /* BEGIN JSTYLED */
    /**
     * Puts quotes around the given character array if it 
     *     contains spaces
     * or double-quotes.  Only part of the string buffer 
     *     is quoted, determined
     * by the "startIndex" argument.  The substring of the 
     *     buffer starting
     * at "startIndex" and ending at the end of the buffer is quoted.
     * This method operates on a string buffer instead of a string for
     * improved performance.
     *
     * The "quote" method also does escaping.  A backslash is placed in
     * front of any double-quote or backslash in the string 
     *     itself.  Also,
     * new-line characters are replaced with the 
     *     characters \ and n
     *
     * Added argument: forceQuotes.  If this is true, then 
     *     always put quotes
     * around the text (necessary for code generation).  
     *     Also, replace the
     * '\n' character with the string "\n".
     */
    /* END JSTYLED */
    public static char[] quote(char src[], boolean forceQuotes) {
	boolean needQuotes;
	int backslash = 0;
                        
	if (src.length == 0) {
	    needQuotes = true;
	} else {
	    needQuotes = false;
	    if (!forceQuotes && src[0] == LBRACE &&
		src[src.length-1] == RBRACE) {
		return src;
	    }
	}
                        
	for (int i = 0; i < src.length; i++) {
	    switch (src[i]) {
	    case LBRACE:
	    case RBRACE:
	    case SPACE:
	    case TAB:
		needQuotes = true;
		break;
                                
	    case DQUOTE:
	    case BACKSLASH:
		needQuotes = true;
		backslash++;
		break;
                                
	    case FORMFEED:
	    case RETURN:
	    case NEWLINE:
		needQuotes = true;
		if (forceQuotes)
		    backslash++;
		break;
	    }
	}
                        
	int len = src.length + backslash;
	if (needQuotes || forceQuotes)
	    len += 2;
                        
	char dst[] = new char[len];
	int p = 0;
                        
	if (needQuotes || forceQuotes)
	    dst[p++] = DQUOTE;
                        
	for (int i = 0; i < src.length; i++) {
	    switch (src[i]) {
	    case DQUOTE:
	    case BACKSLASH:
		dst[p++] = BACKSLASH;
		break;
                                
	    case FORMFEED:
	    case RETURN:
	    case NEWLINE:
		if (forceQuotes) {
		    dst[p++] = BACKSLASH;
		    switch (src[i]) {
		    case FORMFEED:
			dst[p++] = CHAR_f;
			break;
		    case RETURN:
			dst[p++] = CHAR_r;
			break;
		    case NEWLINE:
			dst[p++] = CHAR_n;
			break;
		    }
		    continue;
		}
		break;
	    }
	    dst[p++] = src[i];
	}
                        
	if (needQuotes || forceQuotes)
	    dst[p++] = DQUOTE;
                        
	return dst;
    }
    /* BEGIN JSTYLED */
    /**
     * Returns a string that can be used as a newline.  
     * This string includes
     * a carriage return if we are running on Windows.
     */
    /* END JSTYLED */
    public static String newline() {
	return (Global.newline());
    }
                    
    /**
     * Appends a newline to buf.  This also appends a carriage return
     * if we are running on Windows.
     */
    public static void newline(StringBuffer buf) {
	Global.newline(buf);
    }
                    
    private static final String indentString = /* NOI18N */"  ";
                    
    /**
     * Indents "buf" based on the given indent level.
     */
    public static void indent(StringBuffer buf, int indentLevel) {
	for (int i = 0; i < indentLevel; i++)
	    buf.append(indentString);
    }
                    
    public static boolean isdigit(char ch) {
	return Character.isDigit(ch);
    }
                    
    public static boolean isxdigit(char ch) {
	return
	    ((ch >= ZERO) && (ch <= NINE)) ||
	    ((ch >= CHAR_A) && (ch <= CHAR_F)) ||
	    ((ch >= CHAR_a) && (ch <= CHAR_f));
    }
                    
    public static Enumeration getListElements(String s, int mult) {
	ListParser parser = new ListParser(s);
                        
	// if ((parser.size() % mult) != 0) {
	/* JSTYLED */
	// System.out.println("ParseWarning: Expecting a multiple of " + mult +
	// " list elements, got " + parser.size());
	// }
                        
	return parser.elements();
    }
                    
    public static Hashtable makeListTable(String s) {
	Enumeration e = getListElements(s, 2);
	Hashtable table = new Hashtable();
	while (e.hasMoreElements()) {
	    try {
		table.put((String)e.nextElement(),
			  (String)e.nextElement());
	    }
	    catch (NoSuchElementException ex) {
                                /* JSTYLED */
		throw new ParseException(Global.fmtMsg("sunsoft.jws.visual.rt.type.ListParser.ExpectingTwoElements", s));
	    }
	}
	return table;
    }
                    
    public static int parseInt(String s) {
	try {
	    return Integer.parseInt(s);
	}
	catch (NumberFormatException ex) {
	    throw new ParseException(/* NOI18N */"\n\t" +
				     ex.toString());
	}
    }
}
                
                
/**
 * An Exception that can be thrown and caught internally by ListParser.
 *
 * @see ListParser
 * @version 1.16, 07/25/97
 */
class DoneException extends Exception {
    DoneException() {
	super();
    }
                    
    DoneException(String message) {
	super(message);
    }
}
