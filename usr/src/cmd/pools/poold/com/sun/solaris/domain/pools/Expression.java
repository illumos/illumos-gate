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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */

package com.sun.solaris.domain.pools;

import java.util.regex.*;

/**
 * This class provides the base implementation of an Expression. All
 * types of Expression must inherit from this class.
 *
 * An objective is always specified in terms of an expression. The
 * only recognized expressions are those known by this class. An
 * expression is create using the valueOf() factory method, which is
 * why Expressions must be known to this class.
 */
abstract class Expression
{
	/**
	 * Expression importance
	 */
	private long imp = -1;

	/**
	 * Expression name
	 */
	private String name;

	/**
	 * Sole constructor.  (For invocation by subclass constructors)
	 */
	protected Expression(long imp, String name)
	{
		this.imp = imp;
		this.name = name;
	}

	/**
	 * Return the name of the expression.
	 */
	String getName()
	{
		return (this.name);
	}

	/**
	 * Return the importance of the expression.
	 */
	long getImportance()
	{
		return (imp);
	}

	/**
	 * Returns the supplied string as an expression.
	 *
	 * This utility function attempts to identify the supplied
	 * string as an expression. It tries in turn each of the known
	 * sub-classes until finally, if none can be recognized, an
	 * exception is thrown. This function is not immune to
	 * mistakenly mis-classifying an expression. It is the
	 * responsibility of the concrete Exrpession classes to ensure
	 * that syntactic integrity is maintained with respect to
	 * potential cases of mistaken identity.
	 *
	 * @param raw The candidate expression
	 * @throws IllegalArgumentException If no valid expression can
	 * be found
	 */
	static Expression valueOf(String raw) throws IllegalArgumentException
	{
		Expression exp = null;
		/*
		 * TODO It would be better if subclasses registered,
		 * but this hard coded list will do until such a time
		 */
		if ((exp = KVOpExpression.valueOf(raw)) == null)
			if ((exp = KVExpression.valueOf(raw)) == null)
				exp = KExpression.valueOf(raw);
		if (exp == null)
			throw new IllegalArgumentException(
			    "unrecognized expression: " + raw);
		return (exp);
	}

	/**
	 * Ensure that the supplied importance is a valid value.
	 *
	 * @param imps String representation of the importance.
	 *
	 * @throws IllegalArgumentException if the importance is not
	 * valid.
	 */
	protected static long validateImportance(String imps)
	    throws IllegalArgumentException
	{
		long imp;

		try {
			imp = Long.parseLong(imps);
		} catch (NumberFormatException nfe) {
			throw new IllegalArgumentException("importance value " +
			    imps + " is not legal");
		}

		if (imp < 0)
			throw new IllegalArgumentException("importance value " +
			    imps + " is not legal (must be positive)");
		return (imp);
	}

	/**
	 * Ensure that the supplied keyword is a member of the
	 * supplied keys.
	 *
	 * @param keys Array of valid key strings.
	 * @param key Key sought.
	 *
	 * @throws IllegalArgumentException if the sought key is not
	 * a member of the keys array.
	 */
	protected static void validateKeyword(String keys[], String key)
	    throws IllegalArgumentException
	{
		for (int i = 0; i < keys.length; i++) {
			if (keys[i].compareTo(key) == 0)
				return;
		}
		throw new IllegalArgumentException("keyword " + key +
		    " is not recognized");
	}

	/**
	 * Return true if the supplied expression "contradicts" this
	 * expression. The definition of contradiction is left down to
	 * each implementing sub-class.
	 *
	 * @param o Expression to examine for contradiction.
	 */
	public abstract boolean contradicts(Expression o);
}

/**
 * This class implements the functionality for a key-value-operator
 * expression.
 *
 * The general form of this expression is defined in the pattern
 * member. A simplified rendition of which is:
 *
 * [[imp]:] <key> <op> <value>
 *
 * key is a string which identifies the expression
 * op is the operator for the expression ( < | > | ~)
 * value is the value of the expression
 *
 * For example:
 *
 * 10: utilization < 80
 */
final class KVOpExpression extends Expression
{
	/**
	 * The operator for this expression.
	 */
	private char op;

	/**
	 * The value of this expression.
	 */
	private int val;

	/**
	 * The pattern used to recognize this type of expression.
	 */
	private static final Pattern pattern = Pattern.compile(
	    "\\s*((\\d+)\\s*:)?\\s*(\\w+)\\s*([~<>])\\s*(\\d+)\\s*");

	/**
	 * The array of valid keys for this type of expression.
	 */
	private static final String keys[] = { "utilization" };

	/**
	 * A greater than operator.
	 */
	static final char GT = '>';

	/**
	 * A less than operator.
	 */
	static final char LT = '<';

	/**
	 * A near to operator.
	 */
	static final char NT = '~';

	/**
	 * Private constructor used in the valueOf() factory method.
	 *
	 * @param imp The importance of this expression.
	 * @param name The name of this expression.
	 * @param op The operator of this expression.
	 * @param val The value of this expression.
	 */
	private KVOpExpression(long imp, String name, String op, int val)
	{
		super(imp, name);
		this.op = op.charAt(0);
		this.val = val;
	}

	/**
	 * Create and return an expression from the input string.
	 *
	 * Determine if the input string matches the syntax defined by
	 * this expression. If the expression cannot be matched, an
	 * exception will be thrown.
	 *
	 * @param raw Candidate expression string.
	 *
	 * @throws IllegalArgumentExpression if the string is not a
	 * valid expression of this type.
	 */
	static Expression valueOf(String raw) throws IllegalArgumentException
	{
		KVOpExpression exp = null;
		Matcher m = pattern.matcher(raw);

		if (m.matches()) {
			long imp = 1;
			int val = Integer.parseInt(m.group(5));

			if (m.group(2) != null)
				imp = validateImportance(m.group(2));

			validateKeyword(keys, m.group(3));
			if (val > 100 || val < 0)
				throw new IllegalArgumentException(
				    "expression value " + val +
				    " is outside the legal range (0-100)");
			exp = new KVOpExpression(imp, m.group(3),
			    m.group(4), val);
		}
		return (exp);
	}

	/**
	 * Return the operator for this expression.
	 */
	char getOp()
	{
		return (op);
	}

	/**
	 * Return the value of this expression.
	 */
	int getValue()
	{
		return (val);
	}

	/**
	 * Return a string representation of this expresssion.
	 */
	public String toString()
	{
		return ("(" + getImportance() + ", " + getName() + ", '" + op +
		    "', " + val + ")");
	}

	/**
	 * Indicates whether some other KVOpExpression is "equal to
	 * this one.
	 * @param o the reference object with which to compare.
	 * @return <code>true</code> if this object is the same as the
	 * o argument; <code>false</code> otherwise.
	 * @see	#hashCode()
	 */
	public boolean equals(Object o)
	{
		if (o == this)
			return (true);
		if (!(o instanceof KVOpExpression))
			return (false);
		KVOpExpression other = (KVOpExpression) o;
		if (getName().compareTo(other.getName()) != 0 ||
		    op != other.getOp() || val != other.getValue())
			return (false);
		return (true);
	}

	/**
	 * Returns a hash code value for the object. This method is
	 * supported for the benefit of hashtables such as those provided by
	 * <code>java.util.Hashtable</code>.
	 *
	 * @return a hash code value for this object.
	 * @see	#equals(java.lang.Object)
	 * @see	java.util.Hashtable
	 */
	public int hashCode()
	{
		return (getName().hashCode() + (int) op + val);
	}

	/**
	 * Return true if the supplied expression "contradicts" this
	 * expression. If the supplied expression is not of the same
	 * type, then it cannot contradict it. If the names are
	 * different then there can be no contradiction.
	 *
	 * Contradiction occurs if the operator is the same or if they
	 * aren't the same and the operator is < or > and the values
	 * aren't simultanteously achievable.
	 *
	 * @param o Expression to examine for contradiction.
	 */
	public boolean contradicts(Expression o)
	{
		if (!(o instanceof KVOpExpression))
			return (false);
		KVOpExpression other = (KVOpExpression) o;
		if (getName().compareTo(other.getName()) != 0)
			return (false);
		if (getOp() != other.getOp()) {
			if (getOp() != NT && other.getOp() != NT) {
				if (getOp() == GT) {
					if (getValue() < other.getValue())
						return (false);
				} else {
					if (getValue() > other.getValue())
						return (false);
				}
			} else
				return (false);
		}
		return (true);
	}
}

/**
 * This class implements the functionality for a key-value expression.
 *
 * The general form of this expression is defined in the pattern
 * member. A simplified rendition of which is:
 *
 * [[imp]:] <key> <value>
 *
 * key is a string which identifies the expression
 * value is the value of the expression
 *
 * For example:
 *
 * 10: locality tight
 */
final class KVExpression extends Expression
{
	/**
	 * The value of this expression.
	 */
	private String val;

	/**
	 * The pattern used to recognize this type of expression.
	 */
	private static final Pattern pattern = Pattern.compile(
	    "\\s*((\\d+)\\s*:)?\\s*(\\w+)\\s+(tight|loose|none)\\s*");

	/**
	 * The array of valid keys for this type of expression.
	 */
	private static final String keys[] = { "locality" };

	/**
	 * Private constructor used in the valueOf() factory method.
	 *
	 * @param imp The importance of this expression.
	 * @param name The name of this expression.
	 * @param val The value of this expression.
	 */
	private KVExpression(long imp, String name, String val)
	{
		super(imp, name);
		this.val = val;
	}

	/**
	 * Create and return an expression from the input string.
	 *
	 * Determine if the input string matches the syntax defined by
	 * this expression. If the expression cannot be matched, an
	 * exception will be thrown.
	 *
	 * @param raw Candidate expression string.
	 *
	 * @throws IllegalArgumentExpression if the string is not a
	 * valid expression of this type.
	 */
	static Expression valueOf(String raw) throws IllegalArgumentException
	{
		KVExpression exp = null;
		Matcher m = pattern.matcher(raw);

		if (m.matches()) {
			long imp = 1;

			if (m.group(2) != null)
				imp = validateImportance(m.group(2));

			validateKeyword(keys, m.group(3));
			exp = new KVExpression(imp, m.group(3), m.group(4));
		}
		return (exp);
	}

	/**
	 * Return the value of this expression.
	 */
	String getValue()
	{
		return (val);
	}

	/**
	 * Return a string representation of this expresssion.
	 */
	public String toString()
	{
		StringBuffer buf = new StringBuffer();

		buf.append("(");
		buf.append(getImportance());
		buf.append(", ");
		buf.append(getName());
		buf.append(", ");
		buf.append(val);
		buf.append(")");

		return (buf.toString());
	}

	/**
	 * Indicates whether some other KVExpression is "equal to
	 * this one.
	 * @param o the reference object with which to compare.
	 * @return <code>true</code> if this object is the same as the
	 * o argument; <code>false</code> otherwise.
	 * @see	#hashCode()
	 */
	public boolean equals(Object o)
	{
		if (o == this)
			return (true);
		if (!(o instanceof KVExpression))
			return (false);
		KVExpression other = (KVExpression) o;
		if (getName().compareTo(other.getName()) != 0 ||
		    val.compareTo(other.getValue()) != 0)
			return (false);
		return (true);
	}

	/**
	 * Returns a hash code value for the object. This method is
	 * supported for the benefit of hashtables such as those provided by
	 * <code>java.util.Hashtable</code>.
	 *
	 * @return a hash code value for this object.
	 * @see	#equals(java.lang.Object)
	 * @see	java.util.Hashtable
	 */
	public int hashCode()
	{
		return (getName().hashCode() + val.hashCode());
	}

	/**
	 * Return true if the supplied expression "contradicts" this
	 * expression. If the supplied expression is not of the same
	 * type, then it cannot contradict it. If the names are
	 * different then there can be no contradiction.
	 *
	 * Contradiction occurs if the value is different.
	 *
	 * @param o Expression to examine for contradiction.
	 */
	public boolean contradicts(Expression o)
	{
		if (!(o instanceof KVExpression))
			return (false);
		KVExpression other = (KVExpression) o;
		if (getName().compareTo(other.getName()) != 0)
			return (false);
		if (val.compareTo(other.getValue()) == 0)
			return (false);
		return (true);
	}
}

/**
 * This class implements the functionality for a key expression.
 *
 * The general form of this expression is defined in the pattern
 * member. A simplified rendition of which is:
 *
 * [[imp]:] <key>
 *
 * key is a string which identifies the expression
 *
 * For example:
 *
 * 10: wt-load
 */
final class KExpression extends Expression
{
	/**
	 * The pattern used to recognize this type of expression.
	 */
	private static final Pattern pattern = Pattern.compile(
	    "\\s*((\\d+)\\s*:)?\\s*([\\w-]+)\\s*");

	/**
	 * The array of valid keys for this type of expression.
	 */
	private static final String keys[] = { "wt-load" };

	/**
	 * Private constructor used in the valueOf() factory method.
	 *
	 * @param imp The importance of this expression.
	 * @param name The name of this expression.
	 */
	private KExpression(long imp, String name)
	{
		super(imp, name);
	}

	/**
	 * Create and return an expression from the input string.
	 *
	 * Determine if the input string matches the syntax defined by
	 * this expression. If the expression cannot be matched, an
	 * exception will be thrown.
	 *
	 * @param raw Candidate expression string.
	 *
	 * @throws IllegalArgumentExpression if the string is not a
	 * valid expression of this type.
	 */
	static Expression valueOf(String raw) throws IllegalArgumentException
	{
		KExpression exp = null;
		Matcher m = pattern.matcher(raw);

		if (m.matches()) {
			long imp = 1;

			if (m.group(2) != null)
				imp = validateImportance(m.group(2));

			validateKeyword(keys, m.group(3));
			exp = new KExpression(imp, m.group(3));
		}
		return (exp);
	}

	/**
	 * Return a string representation of this expresssion.
	 */
	public String toString()
	{
		return ("(" + getImportance() + ", " + getName() + ")");
	}

	/**
	 * Indicates whether some other KExpression is "equal to
	 * this one.
	 * @param o the reference object with which to compare.
	 * @return <code>true</code> if this object is the same as the
	 * o argument; <code>false</code> otherwise.
	 * @see	#hashCode()
	 */
	public boolean equals(Object o)
	{
		if (o == this)
			return (true);
		if (!(o instanceof KExpression))
			return (false);
		KExpression other = (KExpression) o;
		if (getName().compareTo(other.getName()) != 0)
			return (false);
		return (true);
	}

	/**
	 * Returns a hash code value for the object. This method is
	 * supported for the benefit of hashtables such as those provided by
	 * <code>java.util.Hashtable</code>.
	 *
	 * @return a hash code value for this object.
	 * @see	#equals(java.lang.Object)
	 * @see	java.util.Hashtable
	 */
	public int hashCode()
	{
		return (getName().hashCode());
	}

	/**
	 * Return true if the supplied expression "contradicts" this
	 * expression. If the supplied expression is not of the same
	 * type, then it cannot contradict it. If the names are
	 * different then there can be no contradiction.
	 *
	 * @param o Expression to examine for contradiction.
	 */
	public boolean contradicts(Expression o)
	{
		if (!(o instanceof KExpression))
			return (false);
		KExpression other = (KExpression) o;
		if (getName().compareTo(other.getName()) != 0)
			return (false);
		return (true);
	}
}
