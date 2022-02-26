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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package org.opensolaris.os.dtrace;

import java.io.Serializable;
import java.io.ObjectInputStream;
import java.io.InvalidObjectException;
import java.io.IOException;
import java.beans.*;

/**
 * A DTrace option and its value.  Compile-time options must be set
 * before calling {@code Consumer} {@link Consumer#compile(String
 * program, String[] macroArgs) compile(String program, ...)} or {@link
 * Consumer#compile(File program, String[] macroArgs) compile(File
 * program, ...)} in order to affect program compilation.  Runtime
 * options may be set anytime before calling {@code Consumer} {@link
 * Consumer#go() go()}, and some of them may be changed while a consumer
 * is running.
 * <p>
 * See the <a
 * href=http://dtrace.org/guide/chp-opt.html>
 * <b>Options and Tunables</b></a> chapter of the <i>Dynamic
 * Tracing Guide</i>.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @author Tom Erickson
 */
public final class Option implements Serializable {
    static final long serialVersionUID = 2734100173861424920L;

    /**
     * Value returned by {@link Consumer#getOption(String option)} when
     * the given boolean option is unset.
     */
    public static final long UNSET = -2L;

    /**
     * Value returned by {@link Consumer#getOption(String option)} for
     * the {@link #bufpolicy} option when the {@link #VALUE_RING ring}
     * buffer policy is set.
     */
    public static final long BUFPOLICY_RING = 0L;

    /**
     * Value returned by {@link Consumer#getOption(String option)} for
     * the {@link #bufpolicy} option when the {@link #VALUE_FILL fill}
     * buffer policy is set.
     */
    public static final long BUFPOLICY_FILL = 1L;

    /**
     * Value returned by {@link Consumer#getOption(String option)} for
     * the {@link #bufpolicy} option when the default {@link
     * #VALUE_SWITCH switch} buffer policy is set.
     */
    public static final long BUFPOLICY_SWITCH = 2L;

    /**
     * Value returned by {@link Consumer#getOption(String option)} for
     * the {@link #bufresize} option when the default {@link #VALUE_AUTO
     * auto} buffer resize policy is set.
     */
    public static final long BUFRESIZE_AUTO = 0L;

    /**
     * Value returned by {@link Consumer#getOption(String option)} for
     * the {@link #bufresize} option when the {@link #VALUE_MANUAL
     * manual} buffer resize policy is set.
     */
    public static final long BUFRESIZE_MANUAL = 1L;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(Option.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"name", "value"})
	    {
		/*
		 * Need to prevent DefaultPersistenceDelegate from using
		 * overridden equals() method, resulting in a
		 * StackOverFlowError.  Revert to PersistenceDelegate
		 * implementation.  See
		 * http://forum.java.sun.com/thread.jspa?threadID=
		 * 477019&tstart=135
		 */
		protected boolean
		mutatesTo(Object oldInstance, Object newInstance)
		{
		    return (newInstance != null && oldInstance != null &&
			    oldInstance.getClass() == newInstance.getClass());
		}
	    };
	    BeanDescriptor d = info.getBeanDescriptor();
	    d.setValue("persistenceDelegate", persistenceDelegate);
	} catch (IntrospectionException e) {
	    System.out.println(e);
	}
    }

    //
    // See lib/libdtrace/common/dt_options.c
    //

    /**
     * Gets a size option value indicating the given number of
     * kilobytes.
     *
     * @param n number of kilobytes
     * @return size option value indicating the given number of
     * kilobytes
     */
    public static String
    kb(int n)
    {
	return (Integer.toString(n) + "k");
    }

    /**
     * Gets a size option value indicating the given number of
     * megabytes.
     *
     * @param n number of megabytes
     * @return size option value indicating the given number of
     * megabytes
     */
    public static String
    mb(int n)
    {
	return (Integer.toString(n) + "m");
    }

    /**
     * Gets a size option value indicating the given number of
     * gigabytes.
     *
     * @param n number of gigabytes
     * @return size option value indicating the given number of
     * gigabytes
     */
    public static String
    gb(int n)
    {
	return (Integer.toString(n) + "g");
    }

    /**
     * Gets a size option value indicating the given number of
     * terabytes.
     *
     * @param n number of terabytes
     * @return size option value indicating the given number of
     * terabytes
     */
    public static String
    tb(int n)
    {
	return (Integer.toString(n) + "t");
    }

    /**
     * Gets a time option value indicating the given number of
     * nanoseconds.
     *
     * @param n number of nanoseconds
     * @return time option value indicating the given number of
     * nanoseconds
     */
    public static String
    nanos(int n)
    {
	return (Integer.toString(n) + "ns");
    }

    /**
     * Gets a time option value indicating the given number of
     * microseconds.
     *
     * @param n number of microseconds
     * @return time option value indicating the given number of
     * microseconds
     */
    public static String
    micros(int n)
    {
	return (Integer.toString(n) + "us");
    }

    /**
     * Gets a time option value indicating the given number of
     * milliseconds.
     *
     * @param n number of milliseconds
     * @return time option value indicating the given number of
     * milliseconds
     */
    public static String
    millis(int n)
    {
	return (Integer.toString(n) + "ms");
    }

    /**
     * Gets a time option value indicating the given number of seconds.
     *
     * @param n number of seconds
     * @return time option value indicating the given number of seconds
     */
    public static String
    seconds(int n)
    {
	return (Integer.toString(n) + "s");
    }

    /**
     * Gets a time option value indicating the given number of minutes.
     *
     * @param n number of minutes
     * @return time option value indicating the given number of minutes
     */
    public static String
    minutes(int n)
    {
	return (Integer.toString(n) + "m");
    }

    /**
     * Gets a time option value indicating the given number of hours.
     *
     * @param n number of hours
     * @return time option value indicating the given number of hours
     */
    public static String
    hours(int n)
    {
	return (Integer.toString(n) + "h");
    }

    /**
     * Gets a time option value indicating the given number of days.
     *
     * @param n number of days
     * @return time option value indicating the given number of days
     */
    public static String
    days(int n)
    {
	return (Integer.toString(n) + "d");
    }

    /**
     * Gets a time option value indicating the given rate per second.
     *
     * @param n number of cycles per second (hertz)
     * @return time option value indicating rate per second
     */
    public static String
    hz(int n)
    {
	return (Integer.toString(n) + "hz");
    }

    /**
     * May be passed to {@link Consumer#setOption(String option, String
     * value)} to set a boolean option such as {@link #flowindent}.
     * However, a more convenient way to set boolean options is {@link
     * Consumer#setOption(String option)}.
     */
    public static final String VALUE_SET = "set";

    /**
     * May be passed to {@link Consumer#setOption(String option, String
     * value)} to unset a boolean option such as {@link #flowindent}.
     * However, a more convenient way to unset boolean options is {@link
     * Consumer#unsetOption(String option)}.
     */
    public static final String VALUE_UNSET = "unset";

    /**
     * {@link #bufpolicy} value: use {@code ring} principal buffer
     * policy.
     */
    public static final String VALUE_RING = "ring";
    /**
     * {@link #bufpolicy} value: use {@code fill} principal buffer
     * policy.
     */
    public static final String VALUE_FILL = "fill";
    /**
     * {@link #bufpolicy} default value: use {@code switch} principal
     * buffer policy.
     */
    public static final String VALUE_SWITCH = "switch";

    /**
     * {@link #bufresize} default value: use {@code auto} buffer
     * resizing policy.
     */
    public static final String VALUE_AUTO = "auto";
    /**
     * {@link #bufresize} value: use {@code manual} buffer resizing
     * policy.
     */
    public static final String VALUE_MANUAL = "manual";

    //
    // See lib/libdtrace/common/dt_options.c
    //

    /**
     * Set program attribute minimum (compile-time).  The format of the
     * option value is defined by the {@link
     * InterfaceAttributes#toString()} method.
     *
     * @see Program#getInfo()
     */
    public static final String amin = "amin";
    /**
     * Do not require all macro args to be used (compile-time; no option
     * value).
     *
     * @see Consumer#compile(String program, String[] macroArgs)
     * @see Consumer#compile(File program, String[] macroArgs)
     */
    public static final String argref = "argref";
    /**
     * Run cpp(1) preprocessor on D script files (compile-time; no
     * option value).
     */
    public static final String cpp = "cpp";
    /**
     * Used together with {@link #cpp} option, specifies which {@code
     * cpp} to run by its pathname (compile-time).
     */
    public static final String cpppath = "cpppath";
    /**
     * Use zero (0) or empty string ("") as the value for unspecified macro args
     * (compile-time; no option value).
     *
     * @see Consumer#compile(String program, String[] macroArgs)
     * @see Consumer#compile(File program, String[] macroArgs)
     */
    public static final String defaultargs = "defaultargs";
    /**
     * Define symbol when invoking preprocessor (compile-time).
     */
    public static final String define = "define";
    /**
     * Permit compilation of empty D source files (compile-time; no
     * option value).
     */
    public static final String empty = "empty";
    /**
     * Adds error tags to default error messages (compile-time; no
     * option value).
     */
    public static final String errtags = "errtags";
    /**
     * Add include directory to preprocessor search path (compile-time).
     */
    public static final String incdir = "incdir";
    /**
     * Permit unresolved kernel symbols (compile-time; no option value).
     */
    public static final String knodefs = "knodefs";
    /**
     * Add library directory to library search path (compile-time).
     */
    public static final String libdir = "libdir";
    /**
     * Specify ISO C conformance settings for preprocessor
     * (compile-time).
     */
    public static final String stdc = "stdc";
    /**
     * Undefine symbol when invoking preprocessor (compile-time).
     */
    public static final String undef = "undef";
    /**
     * Permit unresolved user symbols (compile-time; no option value).
     */
    public static final String unodefs = "unodefs";
    /**
     * Request specific version of native DTrace library (compile-time).
     */
    public static final String version = "version";
    /**
     * Permit probe definitions that match zero probes (compile-time; no
     * option value).
     */
    public static final String zdefs = "zdefs";

    /** Rate of aggregation reading (time).  Runtime option. */
    public static final String aggrate = "aggrate";
    /** Aggregation buffer size (size).  Runtime option. */
    public static final String aggsize = "aggsize";
    /**
     * Denotes that aggregation data should be sorted in tuple order,
     * with ties broken by value order (no option value).  Runtime
     * option.
     *
     * @see AggregationRecord
     * @see Option#aggsortkeypos
     * @see Option#aggsortpos
     * @see Option#aggsortrev
     */
    public static final String aggsortkey = "aggsortkey";
    /**
     * When multiple aggregation tuple elements are present, the
     * position of the tuple element that should act as the primary sort
     * key (zero-based index).  Runtime option.
     *
     * @see Option#aggsortkey
     * @see Option#aggsortpos
     * @see Option#aggsortrev
     */
    public static final String aggsortkeypos = "aggsortkeypos";
    /**
     * When multiple aggregations are being printed, the position of the
     * aggregation that should act as the primary sort key (zero-based
     * index).  Runtime option.
     * <p>
     * Here "position" refers to the position of the aggregation in the
     * {@code printa()} argument list after the format string (if
     * any).  For example, given the following statement:
     * <pre><code>
     * printa("%d %@7d %@7d\n", @a, @b);
     * </code></pre>
     * setting {@code aggsortpos} to {@code "0"} indicates that output
     * should be sorted using the values of {@code @a} as the primary
     * sort key, while setting {@code aggsortpos} to {@code "1"}
     * indicates that output should be sorted using the values of
     * {@code @b} as the primary sort key.
     *
     * @see Option#aggsortkey
     * @see Option#aggsortkeypos
     * @see Option#aggsortrev
     */
    public static final String aggsortpos = "aggsortpos";
    /**
     * Denotes that aggregation data should be sorted in descending
     * order (no option value).  Runtime option.
     * <p>
     * The {@code aggsortrev} option is useful in combination with the
     * {@code aggsortkey}, {@code aggsortkeypos}, and {@code aggsortpos}
     * options, which define the ascending sort reversed by this option.
     *
     * @see Option#aggsortkey
     * @see Option#aggsortkeypos
     * @see Option#aggsortpos
     */
    public static final String aggsortrev = "aggsortrev";
    /** Principal buffer size (size).  Runtime option. */
    public static final String bufsize = "bufsize";
    /**
     * Buffering policy ({@link #VALUE_SWITCH switch}, {@link
     * #VALUE_FILL fill}, or {@link #VALUE_RING ring}).  Runtime option.
     * <p>
     * See the <a
     * href=http://dtrace.org/guide/chp-buf.html#chp-buf-2>
     * <b>Principal Buffer Policies</b></a> section of the
     * <b>Buffers and Buffering</b> chapter of the <i>Dynamic
     * Tracing Guide</i>.
     */
    public static final String bufpolicy = "bufpolicy";
    /**
     * Buffer resizing policy ({@link #VALUE_AUTO auto} or {@link
     * #VALUE_MANUAL manual}).  Runtime option.
     * <p>
     * See the <a
     * href=http://dtrace.org/guide/chp-buf.html#chp-buf-5>
     * <b>Buffer Resizing Policy</b></a> section of the <b>Buffers
     * and Buffering</b> chapter of the <i>Dynamic Tracing
     * Guide</i>.
     */
    public static final String bufresize = "bufresize";
    /** Cleaning rate (time).  Runtime option. */
    public static final String cleanrate = "cleanrate";
    /** CPU on which to enable tracing (scalar).  Runtime option. */
    public static final String cpu = "cpu";
    /** Permit destructive actions (no option value).  Runtime option. */
    public static final String destructive = "destructive";
    /** Dynamic variable space size (size).  Runtime option. */
    public static final String dynvarsize = "dynvarsize";
    /**
     * Adds {@link Flow} information to generated {@link ProbeData}
     * indicating direction of control flow (entry or return) across
     * function boundaries and depth in call stack (no option value).
     * Runtime option.
     */
    public static final String flowindent = "flowindent";
    /** Number of speculations (scalar).  Runtime option. */
    public static final String nspec = "nspec";
    /**
     * Only output explicitly traced data (no option value).  Makes no
     * difference to generated {@link ProbeData}, but user apps may use
     * the {@code quiet} flag as a rendering hint similar to the {@code
     * -q} {@code dtrace(8)} command option.  Runtime option.
     */
    public static final String quiet = "quiet";
    /** Speculation buffer size (size).  Runtime option. */
    public static final String specsize = "specsize";
    /** Number of stack frames (scalar).  Runtime option. */
    public static final String stackframes = "stackframes";
    /** Rate of status checking (time).  Runtime option. */
    public static final String statusrate = "statusrate";
    /** String size (size).  Runtime option. */
    public static final String strsize = "strsize";
    /** Rate of buffer switching (time).  Runtime option. */
    public static final String switchrate = "switchrate";
    /** Number of user stack frames (scalar).  Runtime option. */
    public static final String ustackframes = "ustackframes";

    /** @serial */
    private final String name;
    /** @serial */
    private final String value;

    /**
     * Creates an option without an associated value.  The created
     * boolean option has the value {@link Option#VALUE_SET}.  To
     * specify that the named option be unset, use {@link
     * Option#VALUE_UNSET}.
     *
     * @param optionName DTrace option name
     * @throws NullPointerException if the given option name is {@code
     * null}
     * @see #Option(String optionName, String optionValue)
     */
    public
    Option(String optionName)
    {
	this(optionName, Option.VALUE_SET);
    }

    /**
     * Creates an option with the given name and value.
     *
     * @param optionName DTrace option name
     * @param optionValue DTrace option value
     * @throws NullPointerException if the given option name or value is
     * {@code null}
     */
    public
    Option(String optionName, String optionValue)
    {
	name = optionName;
	value = optionValue;
	validate();
    }

    private final void
    validate()
    {
	if (name == null) {
	    throw new NullPointerException("option name is null");
	}
	if (value == null) {
	    throw new NullPointerException("option value is null");
	}
    }

    /**
     * Gets the option name.
     *
     * @return non-null option name
     */
    public String
    getName()
    {
	return name;
    }

    /**
     * Gets the option value.
     *
     * @return option value, or {@code null} if no value is associated
     * with the option
     */
    public String
    getValue()
    {
	return value;
    }

    /**
     * Compares the specified object with this option for equality.
     * Defines equality as having equal names and values.
     *
     * @return {@code true} if and only if the specified object is an
     * {@code Option} with the same name and the same value as this
     * option.  Option values are the same if they are both {@code null}
     * or if they are equal as defined by {@link String#equals(Object o)
     * String.equals()}.
     */
    public boolean
    equals(Object o)
    {
	if (o instanceof Option) {
	    Option opt = (Option)o;
	    return (name.equals(opt.name) &&
		    value.equals(opt.value));
	}
	return false;
    }

    /**
     * Overridden to ensure that equal options have equal hashcodes.
     */
    @Override
    public int
    hashCode()
    {
	int hash = 17;
	hash = (37 * hash) + name.hashCode();
	hash = (37 * hash) + value.hashCode();
	return hash;
    }

    private void
    readObject(ObjectInputStream s)
            throws IOException, ClassNotFoundException
    {
	s.defaultReadObject();
	// check invariants
	try {
	    validate();
	} catch (Exception e) {
	    InvalidObjectException x = new InvalidObjectException(
		    e.getMessage());
	    x.initCause(e);
	    throw x;
	}
    }

    /**
     * Gets a string representation of this option useful for logging
     * and not intended for display.  The exact details of the
     * representation are unspecified and subject to change, but the
     * following format may be regarded as typical:
     * <pre><code>
     * class-name[property1 = value1, property2 = value2]
     * </code></pre>
     */
    public String
    toString()
    {
	StringBuilder buf = new StringBuilder();
	buf.append(Option.class.getName());
	buf.append("[name = ");
	buf.append(name);
	buf.append(", value = ");
	buf.append(value);
	buf.append(']');
	return buf.toString();
    }
}
