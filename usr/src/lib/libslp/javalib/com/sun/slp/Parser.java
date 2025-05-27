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
 * Copyright 2001,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

//  Parser.java:      LDAP Parser for those service stores that need it.
//  Author:           James Kempf
//  Created On:       Mon Apr 27 08:11:08 1998
//  Last Modified By: James Kempf
//  Last Modified On: Mon Mar  1 08:29:36 1999
//  Update Count:     45
//

package com.sun.slp;

import java.util.*;
import java.io.*;

/**
 * The Parser class implements LDAP query parsing for ServiceStoreInMemory.
 * It is an internal class because it must know about the internal
 * structure of the hashtables.
 *
 * @author James Kempf
 */

abstract class Parser extends Object {

    final private static char NONASCII_LOWER = '\u0080';
    final private static char NONASCII_UPPER = '\uffff';

    final static char EQUAL = '=';
    final static char LESS = '<';
    final static char GREATER = '>';
    private final static char STAR = '*';
    final static char PRESENT = STAR;

    private final static char OPAREN = '(';
    private final static char CPAREN = ')';
    private final static char APPROX = '~';
    private final static char NOT = '!';
    private final static char AND = '&';
    private final static char OR = '|';
    private final static char SPACE = ' ';

    /**
     * Record for returning stuff to the service store.
     *
     * @author James Kempf
     */

    static final class ParserRecord extends Object {

	Hashtable services = new Hashtable();
	Hashtable signatures = new Hashtable();

    }


    /**
     * The QueryEvaluator interface evaluates a term in a query, given
     * the attribute id, the operator, the object, and whether the
     * term is currently under negation from a not operator. Only those
     * ServiceStore implemenations that want to use the Parser
     * class to perform query parsing must provide this.
     *
     * @author James Kempf
     */

    interface QueryEvaluator {

	/**
	 * Evaluate the query, storing away the services that match.
	 *
	 * @param tag The attribute tag for the term.
	 * @param op The term operator.
	 * @param pattern the operand of the term.
	 * @param invert True if the results of the comparison should be
	 *		     inverted due to a not operator.
	 * @param returns Hashtable for the returns. The returns are
	 *		      structured exactly like the hashtable
	 *		      returned from findServices().
	 * @return True if the term matched, false if not.
	 */

	boolean evaluate(AttributeString tag,
			 char op,
			 Object pattern,
			 boolean invert,
			 ParserRecord returns)
	    throws ServiceLocationException;

    }

    /**
     * Parse a query and incrementally evaluate.
     *
     * @param urlLevel Hashtable of langlevel hashtables containing
     *                 registrations for the service type and scope.
     * @param query The query. Escapes have not yet been processed.
     * @param ret   Vector for returned records.
     * @param locale Locale in which to interpret query strings.
     * @param ret ParserRecord in which to return the results.
     */

    static void
	parseAndEvaluateQuery(String query,
			      Parser.QueryEvaluator ev,
			      Locale locale,
			      ParserRecord ret)
	throws ServiceLocationException {

	// Create and initialize lexical analyzer.

	StreamTokenizer tk = new StreamTokenizer(new StringReader(query));

	tk.resetSyntax();  		 // make all chars ordinary...
	tk.wordChars('\177','\177');	 // treat controls as part of tokens
	tk.wordChars('\000', SPACE);
	tk.ordinaryChar(NOT);              // 'NOT' operator
	tk.wordChars('"', '%');
	tk.ordinaryChar(AND);              // 'AND' operator
	tk.wordChars('\'', '\'');
	tk.ordinaryChar(OPAREN);           // filter grouping
	tk.ordinaryChar(CPAREN);
	tk.ordinaryChar(STAR);             // present operator
	tk.wordChars('+', '{');
	tk.ordinaryChar(OR);               // 'OR' operator
	tk.wordChars('}', '~');
	tk.ordinaryChar(EQUAL);            // comparision operator
	tk.ordinaryChar(LESS);             // less operator
	tk.ordinaryChar(GREATER);          // greater operator
	tk.ordinaryChar(APPROX);           // approx operator

	// Begin parsing.

	try {
	    ParserRecord rec = parseFilter(tk, ev, locale, false, true);

	    // Throw exception if anything occurs after the
	    //  parsed expression.

	    if (tk.nextToken() != StreamTokenizer.TT_EOF) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"par_char_closing",
				new Object[] {query});

	    }

	    // Merge in returns. Use OR operator so all returned
	    //  values are merged in.

	    mergeQueryReturns(ret, rec, OR);

	} catch (IOException ex) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"par_syn_err",
				new Object[] {query});

	}
    }

    //
    // Routines for dealing with parse returns record.
    //

    // Merge source to target. The target has already
    //  been precharged with ones that must match
    //  if the op is AND. If it's OR, then simply
    //  stuff them in.

    private static boolean
	mergeQueryReturns(ParserRecord target,
			  ParserRecord source,
			  char op) {
	Hashtable targetServices = target.services;
	Hashtable sourceServices = source.services;
	boolean eval;

	if (op == AND) {
	    eval = mergeTablesWithAnd(targetServices, sourceServices);

	} else {
	    eval = mergeTablesWithOr(targetServices, sourceServices);

	}

	Hashtable targetSigs = target.signatures;
	Hashtable sourceSigs = source.signatures;

	if (op == AND) {
	    mergeTablesWithAnd(targetSigs, sourceSigs);

	} else {
	    mergeTablesWithOr(targetSigs, sourceSigs);

	}

	return eval;
    }


    // Merge tables by removing anything from target that isn't in source.

    private static boolean mergeTablesWithAnd(Hashtable target,
					      Hashtable source) {

	Enumeration en = target.keys();

	// Remove any from target that aren't in source.

	while (en.hasMoreElements()) {
	    Object tkey = en.nextElement();

	    if (source.get(tkey) == null) {
		target.remove(tkey);

	    }
	}

	// If there's nothing left, return false to indicate no further
	//  evaluation needed.

	if (target.size() <= 0) {
	    return false;

	}

	return true;
    }

    // Merge tables by adding everything from source into target.

    private static boolean mergeTablesWithOr(Hashtable target,
					     Hashtable source) {

	Enumeration en = source.keys();

	while (en.hasMoreElements()) {
	    Object skey = en.nextElement();

	    target.put(skey, source.get(skey));

	}

	return true;
    }

    //
    // Parsing for various productions.
    //


    // Parse the filter production.

    private static ParserRecord
	parseFilter(StreamTokenizer tk,
		    Parser.QueryEvaluator ev,
		    Locale locale,
		    boolean invert,
		    boolean eval)
	throws ServiceLocationException, IOException {

	ParserRecord ret = null;
	int tok = tk.nextToken();

	// Check for opening paren.

	if (tok != OPAREN) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"par_init_par",
				new Object[0]);

	}

	// Parse inside.

	tok = tk.nextToken();

	// Check for a logical operator.

	if (tok == AND || tok == OR) {
	    ret = parseFilterlist(tk, ev, locale, (char)tok, invert, eval);

	} else if (tok == NOT) {
	    ret =  parseFilter(tk, ev, locale, !invert, eval);

	} else if (tok == StreamTokenizer.TT_WORD) {
	    tk.pushBack();
	    ret =  parseItem(tk, ev, locale, invert, eval);

	} else {

	    // Since we've covered the ASCII character set, the only other
	    //  thing that could be here is a nonASCII character. We push it
	    //  back and deal with it in parseItem().

	    tk.pushBack();
	    ret = parseItem(tk, ev, locale, invert, eval);

	}

	tok = tk.nextToken();

	// Check for closing paren.

	if (tok != CPAREN) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"par_final_par",
				new Object[0]);

	}

	return ret;
    }

    // Parse a filterlist production.

    private static ParserRecord
	parseFilterlist(StreamTokenizer tk,
			Parser.QueryEvaluator ev,
			Locale locale,
			char op,
			boolean invert,
			boolean eval)
	throws ServiceLocationException, IOException {
	boolean match;

	ParserRecord mrex = null;

	// Parse through the list of filters.

	do {
	    ParserRecord prex = null;

	    if (op == AND) {

		prex = parseFilter(tk, ev, locale, invert, eval);

	    } else {

		prex = parseFilter(tk, ev, locale, invert, eval);

	    }

	    // We need to start off with something.

	    if (mrex == null) {
		mrex = prex;

	    } else {

		// Merge in returns.

		eval = mergeQueryReturns(mrex, prex, op);

	    }

	    // Look for ending paren.

	    int tok = tk.nextToken();
	    tk.pushBack();

	    if (tok == CPAREN) {

		return mrex;

	    }

	} while (true);

    }

    // Parse item.

    private static ParserRecord
	parseItem(StreamTokenizer tk,
		  Parser.QueryEvaluator ev,
		  Locale locale,
		  boolean invert,
		  boolean eval)
	throws ServiceLocationException, IOException {

	ParserRecord prex = new ParserRecord();
	AttributeString attr = parseAttr(tk, locale);
	char op = parseOp(tk);
	Object value = null;

	// If operator is PRESENT, then check whether
	//  it's not really a wildcarded value. If the next
	//  token isn't a closing paren, then it's
	//  a wildcarded value.

	if (op == PRESENT) {
	    int tok = tk.nextToken();

	    tk.pushBack();  // ...in any event...

	    if ((char)tok != CPAREN) { // It's a wildcarded pattern...
		op = EQUAL;
		value = parseValue(tk, locale);

		// Need to convert to a wildcarded pattern. Regardless
		//  of type, since wildcard makes the type be a
		//  string.

		value =
		    new AttributePattern(PRESENT + value.toString(), locale);

	    }
	} else {
	    value = parseValue(tk, locale);

	}

	// Check for inappropriate pattern.

	if (value instanceof AttributePattern &&
	    ((AttributePattern)value).isWildcarded() &&
	    op != EQUAL) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"par_wild_op",
				new Object[] {Character.valueOf(op)});

	}

	// Check for inappropriate boolean.

	if ((value instanceof Boolean ||
	    value instanceof Opaque) &&
	    (op == GREATER || op == LESS)) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"par_bool_op",
				new Object[] {Character.valueOf(op)});

	}

	// Check for wrong operator with keyword.

	if ((value == null || value.toString().length() <= 0) &&
	    op != PRESENT) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"par_key_op",
				new Object[] {Character.valueOf(op)});
	}

	if (eval) {
	    /*
	     * Try and evaluate the query. If the evaluation failed and the
	     * value was an Integer or Boolean try again after converting the
	     * value to a String. This is because the value in the query will
	     * be converted to an Integer or Boolean in preference to a String
	     * even though the query starts out as a String.  Hence when an
	     * attribute is registered with a String value that can equally be
	     * parsed as a valid Integer or Boolean value the String will
	     * almost always be parsed as an Integer or Boolean. This results
	     * in the failing of the initial type check when performing the
	     * query. By converting the value to a String there is another shot
	     * at fulfulling the query.
	     */
	    if (!ev.evaluate(attr, op, value, invert, prex) &&
		    !(value instanceof AttributeString)) {
		ev.evaluate(attr,
			    op,
			    new AttributeString(
				value.toString().trim(),
				locale),
			    invert,
			    prex);
	    }

	}

	return prex;
    }

    // Parse attribute tag.

    private static AttributeString parseAttr(StreamTokenizer tk, Locale locale)
	throws ServiceLocationException, IOException {

	String str  = parsePotentialNonASCII(tk);

	str =
	    ServiceLocationAttribute.unescapeAttributeString(str, true);

	return new AttributeString(str, locale);
    }

    // Parse attribute operator.

    private static char parseOp(StreamTokenizer tk)
	throws ServiceLocationException, IOException {

	int tok = tk.nextToken();

	// Identify operator

	switch (tok) {

	case EQUAL:

	    // Is it present?

	    tok = tk.nextToken();

	    if (tok == STAR) {
		return PRESENT;

	    } else {
		tk.pushBack();
		return EQUAL;

	    }

	case APPROX: case GREATER: case LESS:

	    // Need equals.

	    if (tk.nextToken() != EQUAL) {
		break;

	    }

	    if (tok == APPROX) {
		tok = EQUAL;

	    }

	    return (char)tok;

	default:
	    break;

	}

	throw
	    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"par_comp_op",
				new Object[0]);

    }

    // Parse expression value.

    private static Object parseValue(StreamTokenizer tk, Locale locale)
	throws ServiceLocationException, IOException {

	StringBuffer buf = new StringBuffer();

	// Parse until the next closing paren.

	do {
	    int tok = tk.nextToken();

	    if (tok == CPAREN) {
		tk.pushBack();

		Object o =
		    ServiceLocationAttribute.evaluate(buf.toString().trim());

		if (o instanceof String) {
		    o = new AttributePattern((String)o, locale);

		} else if (o instanceof byte[]) {
		    o = new Opaque((byte[])o);

		}

		return o;

	    } else if (tok != StreamTokenizer.TT_EOF) {

		if (tok == StreamTokenizer.TT_WORD) {
		    buf.append(tk.sval);

		} else if (tok == StreamTokenizer.TT_NUMBER) {
		    Assert.slpassert(false,
				  "par_ntok",
				  new Object[0]);

		} else {
		    buf.append((char)tok);

		}

	    } else {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"par_qend",
				new Object[0]);
	    }
	} while (true);

    }

    // NonASCII characters may be in the string. StreamTokenizer
    //  can't handle them as part of words, so we need to resort to
    //  this loop to handle it.

    private static String parsePotentialNonASCII(StreamTokenizer tk)
	throws IOException {

	StringBuffer buf = new StringBuffer();

	do {

	    int tok = tk.nextToken();

	    if (tok == StreamTokenizer.TT_WORD) {
		buf.append(tk.sval);

	    } else if (((char)tok >= NONASCII_LOWER) &&
		       ((char)tok <= NONASCII_UPPER)) {
		buf.append((char)tok);

	    } else {
		tk.pushBack();
		break;

	    }

	} while (true);

	return buf.toString();
    }
}
