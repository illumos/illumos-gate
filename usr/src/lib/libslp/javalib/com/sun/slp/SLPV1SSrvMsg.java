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

//  SLPV1SSrvMsg.java: SLPv1 server side service rqst/reply.
//  Author:           James Kempf
//  Created On:       Thu Sep 10 15:33:58 1998
//  Last Modified By: James Kempf
//  Last Modified On: Fri Nov  6 14:03:00 1998
//  Update Count:     41
//


package com.sun.slp;

import java.util.*;
import java.io.*;


/**
 * The SLPV1SSrvMsg class models the SLP server side service request message.
 *
 * @author James Kempf
 */

class SLPV1SSrvMsg extends SSrvMsg {

    // For eating whitespace.

    final static char SPACE = ' ';

    // Comma for list parsing.

    final static char COMMA = ',';

    // Logical operators.

    final static char OR_OP = '|';
    final static char AND_OP = '&';

    // Logical operator corner case needs this.

    final static char HASH = '#';

    // Comparison/Assignment operators.

    final static char EQUAL_OP = '=';
    final static char NOT_OP = '!';
    final static char LESS_OP = '<';
    final static char GREATER_OP = '>';
    final static char GEQUAL_OP = 'g';
    final static char LEQUAL_OP = 'l';

    // Parens.

    final static char OPEN_PAREN = '(';
    final static char CLOSE_PAREN = ')';

    // LDAP present operator

    final static char PRESENT = '*';

    // Wildcard operator.

    final static String WILDCARD = "*";

    // Character code for parsing.

    String charCode = IANACharCode.UTF8;

    // For creating a null reply.

    protected SLPV1SSrvMsg() {}

    // Construct a SLPV1SSrvMsg from the input stream.

    SLPV1SSrvMsg(SrvLocHeader hdr, DataInputStream dis)
	throws ServiceLocationException, IOException {
	super(hdr, dis);

    }

    // Construct an empty SLPV1SSrvMsg, for monolingual off.

    static SrvLocMsg makeEmptyReply(SLPHeaderV1 hdr)
	throws ServiceLocationException {

	SLPV1SSrvMsg msg = new SLPV1SSrvMsg();
	msg.hdr = hdr;

	msg.makeReply(new Hashtable(), null);

	return msg;

    }

    // Initialize the message from the input stream.

    void initialize(DataInputStream dis)
	throws ServiceLocationException, IOException {

	SLPHeaderV1 hdr = (SLPHeaderV1)getHeader();
	StringBuffer buf = new StringBuffer();

	// First get the previous responder.

	hdr.parsePreviousRespondersIn(dis);

	// Now get the raw query.

	hdr.getString(buf, dis);

	String rq = buf.toString();

	// Parse the raw query to pull out the service type, scope,
	//  and query.

	StringTokenizer st = new StringTokenizer(rq, "/", true);

	try {

	    String type =
		Defaults.SERVICE_PREFIX + ":" +
		st.nextToken().trim().toLowerCase() + ":";

	    serviceType =
		hdr.checkServiceType(type);

	    st.nextToken();  // get rid of slash.

	    // Get the scope.

	    String scope = st.nextToken().trim().toLowerCase();

	    // Special case if scope is empty (meaning the next
	    //  token will be a slash).

	    if (scope.equals("/")) {
		scope = "";

	    } else {

		st.nextToken();  // get rid of slash.

		if (scope.length() > 0) {

		    // Validate the scope name.

		    hdr.validateScope(scope);
		}
	    }

	    // Set up scopes vector.

	    hdr.scopes = new Vector();

	    // Substitute default scope here.

	    if (scope.length() <= 0) {
		scope = Defaults.DEFAULT_SCOPE;

	    }

	    hdr.scopes.addElement(scope.toLowerCase().trim());

	    // Parsing the query is complicated by opaques having slashes.

	    String q = "";

	    while (st.hasMoreTokens()) {
		q = q + st.nextToken();

	    }

	    // Drop off the final backslash, error if none.

	    if (!q.endsWith("/")) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {rq});
	    }

	    query = q.substring(0, q.length()-1);

	    // Save header char code for parsing.

	    charCode = hdr.charCode;

	    // Convert the query into a V2 query.

	    convertQuery();

	    // If the query is for "service:directory-agent", then we
	    //  mark it as having been multicast, because that is the
	    //  only kind of multicast that we accept for SLPv1. Anybody
	    //  who unicasts this to us will time out.

	    if (serviceType.equals(Defaults.DA_SERVICE_TYPE.toString())) {
		hdr.mcast = true;

	    }

	    // Construct description.

	    hdr.constructDescription("SrvRqst",
				     "        service type=``" +
				     serviceType + "''\n" +
				     "        query=``" +
				     query + "''");

	}  catch (NoSuchElementException ex) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {rq});
	}
    }

    // Make a reply message.

    SrvLocMsg makeReply(Hashtable urltable,
			Hashtable URLSignatures)
	throws ServiceLocationException {

	SLPHeaderV1 hdr =
	    ((SLPHeaderV1)getHeader()).makeReplyHeader();

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	// Edit out abstract types and nonService: URLs.

	Enumeration en = urltable.keys();
	Vector urls = new Vector();

	while (en.hasMoreElements()) {
	    ServiceURL surl = (ServiceURL)en.nextElement();

	    // Reject if abstract type or nonservice: URL.

	    ServiceType type = surl.getServiceType();

	    if (!type.isAbstractType() && type.isServiceURL()) {
		urls.addElement(surl);

	    }
	}

	hdr.iNumReplies = urls.size();
	// keep this info so SAs can drop 0 replies

	int n = urls.size();

	// Write out the size of the list.

	hdr.putInt(n, baos);

	en = urls.elements();

	// Write out the size of the list.

	while (en.hasMoreElements()) {
	    ServiceURL surl = (ServiceURL)en.nextElement();

	    hdr.parseServiceURLOut(surl, true, baos);

	}

	// We ignore the signatures because we only do V1 compatibility
	//  for nonprotected scopes.

	hdr.payload = baos.toByteArray();

	hdr.constructDescription("SrvRply",
				 "        service URLs=``" + urls + "''\n");

	return hdr;

    }

    // Convert the query to a V2 query.

    void convertQuery()
	throws ServiceLocationException {

	// Check for empty query.

	query = query.trim();

	if (query.length() <= 0) {
	    return;

	}

	// Check for query join.

	if (!(query.startsWith("(") && query.endsWith(")"))) {

	    // Rewrite to a standard query.

	    query = rewriteQueryJoin(query);

	}

	// Now rewrite the query into v2 format.

	query = rewriteQuery(query);
    }


    // Rewrite a query join as a conjunction.

    private String rewriteQueryJoin(String query)
	throws ServiceLocationException {

	// Turn infix expression into prefix.

	StringBuffer sbuf = new StringBuffer();
	StringTokenizer tk = new StringTokenizer(query, ",", true);
	boolean lastTokComma = true;
	int numEx = 0;

	while (tk.hasMoreElements()) {
	    String exp = tk.nextToken().trim();

	    if (exp.equals(",")) {
		if (lastTokComma) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});

		} else {
		    lastTokComma = true;
		}

	    } else {
		lastTokComma = false;

		if (exp.length() <= 0) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});

		}

		// Put in parens

		sbuf.append("(");
		sbuf.append(exp);
		sbuf.append(")");

		numEx++;
	    }
	}

	if (lastTokComma || numEx == 0) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});

	}

	if (numEx > 1) {
	    sbuf.insert(0, "(&");
	    sbuf.append(")");

	}

	return sbuf.toString();
    }

    // Rewrite a v1 query into v2 format. This includes character escaping.

    private String rewriteQuery(String whereList)
	throws ServiceLocationException {

	// Parse a logical expression.

	StreamTokenizer tk =
	    new StreamTokenizer(new StringReader(whereList));

	tk.resetSyntax();  		// make all chars ordinary...
	tk.whitespaceChars('\000','\037');
	tk.ordinaryChar(SPACE);		// but beware of embedded whites...
	tk.wordChars('!', '%');
	tk.ordinaryChar(AND_OP);
	tk.wordChars('\'', '\'');
	tk.ordinaryChar(OPEN_PAREN);
	tk.ordinaryChar(CLOSE_PAREN);
	tk.wordChars('*', '{');
	tk.ordinaryChar(OR_OP);
	tk.wordChars('}', '~');

	// Initialize parse tables in terminal.

	tk.ordinaryChar(EQUAL_OP);
	tk.ordinaryChar(NOT_OP);
	tk.ordinaryChar(LESS_OP);
	tk.ordinaryChar(GREATER_OP);

	StringBuffer buf = new StringBuffer();


	// Parse through the expression.

	try {
	    parseInternal(tk, buf, true);

	} catch (IOException ex) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});

	}

	return buf.toString();
    }

    // Do the actual parsing, using the passed-in stream tokenizer.

    private void
	parseInternal(StreamTokenizer tk, StringBuffer buf, boolean start)
	throws ServiceLocationException, IOException {

	int tok = 0;
	boolean ret = true;

	do {
	    tok = eatWhite(tk);

	    // We should be at the beginning a parenthesized
	    //  where list.

	    if (tok == OPEN_PAREN) {

		// Get the next token. Eat whitespace in the process.

		tok = eatWhite(tk);

		// If it's a logOp, then process as a logical expression.
		//  This handles the following nasty case:
		//
		//  	(&#44;&#45==the rest of it)

		int logOp = tok;

		if (logOp == AND_OP) {

		    // Need to check for escape as first thing.

		    tok = tk.nextToken();
		    String str = tk.sval; // not used if token not a string...
		    tk.pushBack();

		    if (tok == StreamTokenizer.TT_WORD) {

			if (str.charAt(0) != HASH) {
			    parseLogicalExpression(logOp, tk, buf);

			} else {
			    parse(tk, buf, true);
					// cause we can't push back twice

			}

		    } else {
			parseLogicalExpression(logOp, tk, buf);

		    }

		    break;

		} else if (logOp == OR_OP) {

		    parseLogicalExpression(logOp, tk, buf);

		    break;

		} else {

		    // It's a terminal expression. Push back the last token
		    //  and parse the terminal.

		    tk.pushBack();

		    parse(tk, buf, false);

		    break;

		}

	    } else {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});
	    }

	} while (true);

	// Since terminals are allowed alone at the top level,
	//  we need to check here whether anything else is
	//  in the query.

	if (start) {

	    tok = eatWhite(tk);

	    if (tok != StreamTokenizer.TT_EOF) {

		// The line should have ended by now.

		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});
	    }
	}

    }

    // Rewrite a logical expression.

    private void
	parseLogicalExpression(int logOp, StreamTokenizer tk, StringBuffer buf)
	throws ServiceLocationException, IOException {

	// Append paren and operator to buffer.

	buf.append((char)OPEN_PAREN);
	buf.append((char)logOp);

	int tok = 0;

	do {

	    tok = eatWhite(tk);

	    if (tok == OPEN_PAREN) {

		// So parseInternal() sees a parenthesized list.

		tk.pushBack();

		// Go back to parseInternal.

		parseInternal(tk, buf, false);

	    } else if (tok == CLOSE_PAREN) {

		// Append the character to the buffer and return.

		buf.append((char)tok);

		return;

	    } else {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});
	    }

	} while (tok != StreamTokenizer.TT_EOF);

	// Error if we've not caught ourselves before this.

	throw
	    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});
    }

    // Parse a terminal. Opening paren has been got.

    private void parse(StreamTokenizer tk,
		       StringBuffer buf,
		       boolean firstEscaped)
	throws ServiceLocationException, IOException {

	String tag = "";
	int tok = 0;

	tok = eatWhite(tk);

	// Gather the tag and value.

	if (tok != StreamTokenizer.TT_WORD) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});
	}

	// Parse the tag.

	tag = parseTag(tk, firstEscaped);

	if (tag.length() <= 0) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});
	}

	// Unescape tag.

	tag = ServiceLocationAttributeV1.unescapeAttributeString(tag,
								 charCode);

	// Now escape in v2 format,

	tag = ServiceLocationAttribute.escapeAttributeString(tag, true);

	// Parse the operator.

	char compOp = parseOperator(tk);

	// If this was a keyword operator, then add present
	// operator and closing paren and return.

	if (compOp == PRESENT) {
	    buf.append(OPEN_PAREN);
	    buf.append(tag);
	    buf.append(EQUAL_OP);
	    buf.append(PRESENT);
	    buf.append(CLOSE_PAREN);
	    return;

	}

	// Parse value by reading up to the next close paren.
	//  Returned value will be in v2 format.

	String valTok = parseValue(tk);

	// Construct the comparision depending on the operator.

	if (compOp == NOT_OP) {

	    // If the value is an integer, we can construct a query
	    //  that will exclude the number.

	    try {

		int n = Integer.parseInt(valTok);

		// Bump the integer up and down to catch numbers on both
		//  sides of the required number. Be careful not to
		//  overstep bounds.

		if (n < Integer.MAX_VALUE) {
		    buf.append(OPEN_PAREN);
		    buf.append(tag);
		    buf.append(GREATER_OP);
		    buf.append(EQUAL_OP);
		    buf.append(n + 1);
		    buf.append(CLOSE_PAREN);

		}

		if (n > Integer.MIN_VALUE) {
		    buf.append(OPEN_PAREN);
		    buf.append(tag);
		    buf.append(LESS_OP);
		    buf.append(EQUAL_OP);
		    buf.append(n - 1);
		    buf.append(CLOSE_PAREN);

		}

		if ((n < Integer.MAX_VALUE) && (n > Integer.MIN_VALUE)) {
		    buf.insert(0, OR_OP);
		    buf.insert(0, OPEN_PAREN);
		    buf.append(CLOSE_PAREN);

		}

	    } catch (NumberFormatException ex) {

		// It's not an integer. We can construct a query expression
		// that will not always work. The query rules out advertisments
		// where the attribute value doesn't match and there are
		// no other attributes or values, and advertisements
		// that don't contain the attribute, but it doesn't rule out
		// a multivalued attribute with other values or if there
		// are other attributes. The format of the query is:
		// "(&(<tag>=*)(!(<tag>=<value>))).

		buf.append(OPEN_PAREN);
		buf.append(AND_OP);
		buf.append(OPEN_PAREN);
		buf.append(tag);
		buf.append(EQUAL_OP);
		buf.append(PRESENT);
		buf.append(CLOSE_PAREN);
		buf.append(OPEN_PAREN);
		buf.append(NOT_OP);
		buf.append(OPEN_PAREN);
		buf.append(tag);
		buf.append(EQUAL_OP);
		buf.append(valTok);
		buf.append(CLOSE_PAREN);
		buf.append(CLOSE_PAREN);
		buf.append(CLOSE_PAREN);

	    }

	} else if ((compOp == LESS_OP) || (compOp == GREATER_OP)) {

	    int n = 0;

	    try {

		n = Integer.parseInt(valTok);

	    } catch (NumberFormatException ex) {

		// It's a parse error here.

		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});

	    }

	    // We don't attempt to handle something that would cause
	    // arithmetic overflow.

	    if ((n == Integer.MAX_VALUE) || (n == Integer.MIN_VALUE)) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});

	    }

	    // Construct a query that includes everything
	    //  to the correct side.

	    buf.append(OPEN_PAREN);
	    buf.append(tag);

	    if (compOp == LESS_OP) {
		buf.append(LESS_OP);
		buf.append(EQUAL_OP);
		buf.append(n - 1);

	    } else {
		buf.append(GREATER_OP);
		buf.append(EQUAL_OP);
		buf.append(n + 1);

	    }

	    buf.append(CLOSE_PAREN);

	} else {

	    // Simple, single operator. Just add it with the
	    //  value.

	    buf.append(OPEN_PAREN);
	    buf.append(tag);

	    // Need to distinguish less and greater equal.

	    if (compOp == LEQUAL_OP) {
		buf.append(LESS_OP);
		buf.append(EQUAL_OP);

	    } else if (compOp == GEQUAL_OP) {
		buf.append(GREATER_OP);
		buf.append(EQUAL_OP);

	    } else {
		buf.append(compOp);

	    }

	    buf.append(valTok);
	    buf.append(CLOSE_PAREN);

	}

    }

    // Gather tokens with embedded whitespace and return.

    private String parseTag(StreamTokenizer tk, boolean ampStart)
	throws ServiceLocationException, IOException {

	String value = "";

	// Take care of corner case here.

	if (ampStart) {
	    value = value +"&";
	    ampStart = false;
	}

	do {

	    if (tk.ttype == StreamTokenizer.TT_WORD) {
		value += tk.sval;

	    } else if ((char)tk.ttype == SPACE) {
		value = value + " ";

	    } else if ((char)tk.ttype == AND_OP) {
		value = value + "&";

	    } else {
		break;

	    }
	    tk.nextToken();

	} while (true);

	return value.trim();  // removes trailing whitespace...
    }

    private char parseOperator(StreamTokenizer tk)
	throws ServiceLocationException, IOException {

	int tok = tk.ttype;

	// If the token is a close paren, then this was a keyword
	// (e.g. "(foo)". Return the present operator.

	if ((char)tok == CLOSE_PAREN) {
	    return PRESENT;

	}

	if (tok != EQUAL_OP && tok != NOT_OP &&
	    tok != LESS_OP && tok != GREATER_OP) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});

	}

	char compOp = (char)tok;

	// Get the next token.

	tok = tk.nextToken();

	// Look for dual character operators.

	if ((char)tok == EQUAL_OP) {

	    // Here, we can have either "!=", "<=", ">=", or "==".
	    //  Anything else is wrong.

	    if (compOp != LESS_OP && compOp != GREATER_OP &&
		compOp != EQUAL_OP && compOp != NOT_OP) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});
	    }

	    // Assign the right dual operator.

	    if (compOp == LESS_OP) {
		compOp = LEQUAL_OP;

	    } else if (compOp == GREATER_OP) {
		compOp = GEQUAL_OP;

	    }

	} else if (compOp != LESS_OP && compOp != GREATER_OP) {

	    // Error if the comparison operator was something other
	    //  than ``<'' or ``>'' and there is no equal. This
	    //  rules out ``!'' or ``='' alone.

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});

	} else {

	    // Push back the last token if it wasn't a two character operator.

	    tk.pushBack();

	}

	return compOp;
    }


    private String parseValue(StreamTokenizer tk)
	throws ServiceLocationException, IOException {

	int tok = 0;
	StringBuffer valTok = new StringBuffer();

	// Eat leading whitespace.

	tok = eatWhite(tk);

	// If the first value is a paren, then we've got an
	//  opaque.

	if ((char)tok == OPEN_PAREN) {

	    valTok.append("(");

	    // Collect all tokens up to the closing paren.

	    do {

		tok = tk.nextToken();

		// It's a closing paren. break out of the loop.

		if ((char)tok == CLOSE_PAREN) {
		    valTok.append(")");
		    break;

		} else if ((char)tok == EQUAL_OP) {
		    valTok.append("=");

		} else if (tok == StreamTokenizer.TT_WORD) {
		    valTok.append(tk.sval);

		} else {
		    throw
			new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});
		}

	    } while (true);


	    // Eat whitespace until closing paren.

	    tok = eatWhite(tk);

	    if ((char)tok != CLOSE_PAREN) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});

	    }

	} else {

	    // Error if just a closed paren.

	    if (tok == CLOSE_PAREN) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_query_error",
				new Object[] {query});

	    }

	    do {

		// Append the token if a WORD

		if (tok == StreamTokenizer.TT_WORD) {
		    valTok.append(tk.sval);

		} else if ((tok != StreamTokenizer.TT_EOF) &&
			   (tok != StreamTokenizer.TT_EOL) &&
			   (tok != CLOSE_PAREN)) {

		    // Otherwise, it's a token char, so append.

		    valTok.append((char)tok);

		}

		tok = tk.nextToken();

	    } while (tok != CLOSE_PAREN);
	}

	// If a wildcard, remove wildcard stars here for later re-insertion.

	String strval = valTok.toString().trim();
	boolean wildstart = false;
	boolean wildend = false;

	if (strval.startsWith(WILDCARD)) {
	    wildstart = true;
	    strval = strval.substring(1, strval.length());

	}

	if (strval.endsWith(WILDCARD)) {
	    wildend = true;
	    strval = strval.substring(0, strval.length()-1);

	}

	// Evaluate the value.

	Object val =
	    ServiceLocationAttributeV1.evaluate(strval, charCode);

	// Now convert to v2 format, and return.

	if (val instanceof String) {
	    strval =
		ServiceLocationAttribute.escapeAttributeString(val.toString(),
							       false);

	    // Add wildcards back in.

	    if (wildstart) {
		strval = WILDCARD + strval;

	    }

	    if (wildend) {
		strval = strval + WILDCARD;

	    }

	} else {
	    strval = val.toString();

	}

	return strval;

    }

    // Eat whitespace.

    private int eatWhite(StreamTokenizer tk)
	throws IOException {

	int tok = tk.nextToken();

	while (tok == SPACE) {
	    tok = tk.nextToken();

	}

	return tok;
    }
}
