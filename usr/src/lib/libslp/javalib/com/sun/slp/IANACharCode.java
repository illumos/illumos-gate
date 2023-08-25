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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

//  IANACharCode.java: SLPv1 Character encoding support
//  Author:           James Kempf
//  Created On:       Fri Sep 11 13:24:02 1998
//  Last Modified By: James Kempf
//  Last Modified On: Wed Oct 28 14:33:02 1998
//  Update Count:     7
//


package com.sun.slp;

import java.util.*;
import java.io.*;

/**
 * The IANACharCode class supports static methods for decoding IANA
 * character codes into strings appropriate for the Java Writer subclass
 * encoding String arguments, and for encoding the String descriptions
 * of character codings into the integer codes. Ideally, Java itself
 * should support this.
 *
 * @author James Kempf
 */

abstract class IANACharCode extends Object {

    // Character code descriptors. These can be used with the Java
    //  character encoding utilities. For Unicode, we use little on
    //  input,

    static final String ASCII = "Default";
    static final String LATIN1 = "latin1";
    static final String UTF8 = "UTF8";
    static final String UNICODE = "Unicode";
    static final String UNICODE_LITTLE = "UnicodeLittle";
    static final String UNICODE_BIG = "UnicodeBig";
    static final String UNICODE_BIG_NO_HDR = "UnicodeBigNoHdr";

    // Error code for misidentified character set.

    static final short CHARSET_NOT_UNDERSTOOD = 5;

    // Character codes.

    protected static final int CHAR_ASCII   = 3;
    protected static final int CHAR_LATIN1  = 4;
    protected static final int CHAR_UTF8    = 6;
    protected static final int CHAR_UNICODE = 1000;

    // First two bytes indicate that string is big/little endian Unicode.
    //  If this flag isn't set, then big endian is assumed and we
    //  must add the big endian bytes on every call.

    protected static final byte[] UNICODE_LITTLE_FLAG =
					{(byte)0xFF, (byte)0xFE};

    protected static final byte[] UNICODE_BIG_FLAG =
					{(byte)0xFE, (byte)0xFF};

    /**
     * Encode the String describing a character encoding into
     * the approprate integer descriptor code.
     *
     * @param encoding The String describing the encoding.
     * @exception ServiceLocationCharSetNotUnderstoodException Thrown if the
     *			String is not recognized.
     */

    static int encodeCharacterEncoding(String encoding)
	throws ServiceLocationException {

	if (encoding.equals(ASCII)) {
	    return CHAR_ASCII;
	} else if (encoding.equals(LATIN1)) {
	    return CHAR_LATIN1;
	} else if (encoding.equals(UTF8)) {
	    return CHAR_UTF8;
	} else if (encoding.equals(UNICODE)) {
	    return CHAR_UNICODE;
	} else if (encoding.equals(UNICODE_BIG)) {
	    return CHAR_UNICODE;
	} else if (encoding.equals(UNICODE_LITTLE)) {
	    return CHAR_UNICODE;
	} else if (encoding.equals(UNICODE_BIG_NO_HDR)) {
	    return CHAR_UNICODE;
	}

	throw
	    new ServiceLocationException(
				CHARSET_NOT_UNDERSTOOD,
				"v1_unsupported_encoding",
				new Object[] {encoding});
    }

    /**
     * Decode the integer describing a character encoding into
     * the approprate String descriptor.
     *
     * @param code The integer coding the String set.
     * @exception ServiceLocationCharSetNotUnderstoodException Thrown if the
     *			integer is not recognized.
     */

    static String decodeCharacterEncoding(int code)
	throws ServiceLocationException {

	switch (code) {
	case CHAR_ASCII: 	return ASCII;
	case CHAR_LATIN1:	return LATIN1;
	case CHAR_UTF8:	return UTF8;
	case CHAR_UNICODE:	return UNICODE;
	}

	throw
	    new ServiceLocationException(
				CHARSET_NOT_UNDERSTOOD,
				"v1_unsupported_encoding",
				new Object[] {Integer.toString(code)});
    }

    /**
     * Return a string of integers giving the character's encoding in
     * the character set passed in as encoding.
     *
     * @param c The character to escape.
     * @param encoding The character set encoding to use.
     * @return The character as a string of integers for the encoding.
     * @exception ServiceLocationException Thrown if the encoding is not
     *		 recognized, if the character's encoding
     *		 has more than 8 bytes or if the sign bit gets turned on.
     */

    static String escapeChar(char c, String encoding)
	throws ServiceLocationException {

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	try {
	    OutputStreamWriter osw = new OutputStreamWriter(baos, encoding);

	    osw.write(c);
	    osw.flush();

	} catch (UnsupportedEncodingException ex) {

	    throw
		new ServiceLocationException(
				CHARSET_NOT_UNDERSTOOD,
				"v1_unsupported_encoding",
				new Object[] {encoding});

	} catch (IOException ex) {

	}

	byte b[] = baos.toByteArray();
	int code = 0;

	// Assemble the character code based on the encoding type.

	if (encoding.equals(UNICODE) ||
	    encoding.equals(UNICODE_BIG) ||
	    encoding.equals(UNICODE_LITTLE)) {

	    code = (int)(b[0] & 0xFF);		// control bytes...
	    code = (int)(code | ((b[1] & 0xFF) << 8));
	    code = (int)(code | ((b[2] & 0xFF) << 16));
	    code = (int)(code | ((b[3] & 0xFF) << 24));

	    if (b.length <= 4) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_charcode_error",
				new Object[] {new Character(c), encoding});
	    }

	} else if (encoding.equals(ASCII) || encoding.equals(LATIN1)) {

	    code = (int)(b[0] & 0xFF);

	    if (b.length > 1) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_charcode_error",
				new Object[] {new Character(c), encoding});
	    }
	} else if (encoding.equals(UTF8)) {

	    if (b.length > 3) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_charcode_error",
				new Object[] {new Character(c), encoding});
	    }


	    code = (int)(b[0] & 0xFF);

	    if (b.length > 1) {
		code = (int)(code | ((b[1] & 0xFF) << 8));
	    }

	    if (b.length > 2) {
		code = (int)(code | ((b[2] & 0xFF) << 16));
	    }
	}

	return Integer.toString(code);
    }

    /**
     * Unescape the character encoded as the string.
     *
     * @param ch The character as a string of Integers.
     * @param encoding The character set encoding to use.
     * @return The character.
     * @exception ServiceLocationException Thrown if the string can't
     *		 be parsed into an integer or if the encoding isn't
     *		 recognized.
     */

    static String unescapeChar(String ch, String encoding)
	throws ServiceLocationException {

	int code = 0;

	try {
	    code = Integer.parseInt(ch);

	} catch (NumberFormatException ex) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_stringcode_error",
				new Object[] {ch, encoding});

	}

	// Convert to bytes. We need to taylor the array size to the
	//  number of bytes because otherwise, in encodings that
	//  take less bytes, the resulting string will have garbage
	//  in it.

	String str = null;
	byte b0 = 0, b1 = 0, b2 = 0, b3 = 0;
	byte b[] = null;

	b0 = (byte) (code & 0xFF);
	b1 = (byte) ((code >> 8) & 0xFF);
	b2 = (byte) ((code >> 16) & 0xFF);
	b3 = (byte) ((code >> 24) & 0xFf);

	// We create an array sized to the encoding.

	if (encoding.equals(UNICODE_BIG) ||
	    encoding.equals(UNICODE_LITTLE)) {
	    b = new byte[4];
	    b[0] = b0;
	    b[1] = b1;
	    b[2] = b2;
	    b[3] = b3;

	} else if (encoding.equals(LATIN1) || encoding.equals(ASCII)) {
	    // single byte
	    b = new byte[1];
	    b[0] = b0;

	    if (b1 != 0 || b2 != 0) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_stringcode_error",
				new Object[] {ch, encoding});
	    }


	} else if (encoding.equals(UTF8)) {// vari-byte

	    if (b3 != 0) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_stringcode_error",
				new Object[] {ch, encoding});
	    }

	    if (b2 != 0) {
		b = new byte[3];
		b[2] = b2;
		b[1] = b1;
		b[0] = b0;
	    } else if (b1 != 0) {
		b = new byte[2];
		b[1] = b1;
		b[0] = b0;
	    } else {
		b = new byte[1];
		b[0] = b0;
	    }
	}

	// Make a string out of it.

	try {
	    str = new String(b, encoding);

	} catch (UnsupportedEncodingException ex) {
	    Assert.slpassert(false,
			  "v1_unsupported_encoding",
			  new Object[] {encoding});
	}

	return str;
    }

    // Determine from the flag bytes whether this is big or little endian
    //  Unicode. If there are no flag bytes, then just return UNICODE.

    static String getUnicodeEndianess(byte[] bytes) {

	if (bytes.length >= 2) {

	    if (bytes[0] == UNICODE_LITTLE_FLAG[0] &&
		bytes[1] == UNICODE_LITTLE_FLAG[1]) {
		return UNICODE_LITTLE;

	    } else if (bytes[0] == UNICODE_BIG_FLAG[0] &&
		       bytes[1] == UNICODE_BIG_FLAG[1]) {
		return UNICODE_BIG;

	    }
	}

	// We can`t tell from the byte header, so it's big endian. But
	//  since we need to add the byte header, we say we don't know.

	return UNICODE;

    }

    // Add the big endian flag to a Unicode string.

    static byte[] addBigEndianFlag(byte[] bytes) {

	byte[] flaggedBytes = new byte[bytes.length + 2];

	flaggedBytes[0] = UNICODE_BIG_FLAG[0];
	flaggedBytes[1] = UNICODE_BIG_FLAG[1];

	System.arraycopy(flaggedBytes, 2, bytes, 0, bytes.length);

	return flaggedBytes;

    }
}
