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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */
package org.opensolaris.os.dtrace;

import java.io.*;

/**
 * Identifies a compiled D program.  This identifier is valid only on
 * the {@link LocalConsumer} from which it was obtained.  Some {@code
 * Consumer} methods attach additional {@link ProgramInfo} to this
 * identifier.
 * <p>
 * Not intended for persistence, since it identifies nothing after its
 * source {@code LocalConsumer} closes.
 *
 * @see Consumer#compile(String program, String[] macroArgs)
 * @see Consumer#compile(java.io.File program, String[] macroArgs)
 * @see Consumer#enable(Program program)
 * @see Consumer#getProgramInfo(Program program)
 * @see Consumer#listProgramProbes(Program program)
 * @see Consumer#listProgramProbeDetail(Program program)
 *
 * @author Tom Erickson
 */
public class Program implements Serializable {
    static final long serialVersionUID = 364989786308628466L;

    /**
     * Identifies this program among all of a consumer's programs.  Set
     * by native code.
     *
     * @serial
     */
    private int id = -1;

    // Set by LocalConsumer.compile()
    /** @serial */
    LocalConsumer.Identifier consumerID;
    /** @serial */
    String contents;

    /** @serial */
    private ProgramInfo info;

    /**
     * Called by native code
     */
    private Program()
    {
    }

    // Called by LocalConsumer.compile() to ensure that only valid
    // instances are made accessible to users.  Similarly called by
    // readObject to ensure that only valid instances are deserialized.
    final void
    validate()
    {
	if (id < 0) {
	    throw new IllegalArgumentException("id is negative");
	}
	if (consumerID == null) {
	    throw new NullPointerException("consumer ID is null");
	}
    }

    /**
     * Gets the full pre-compiled text of the identified program.
     *
     * @return the {@code String} passed to {@link
     * Consumer#compile(String program, String[] macroArgs)}, or the
     * contents of the {@code File} passed to {@link
     * Consumer#compile(java.io.File program, String[] macroArgs)}
     */
    public String
    getContents()
    {
	return contents;
    }

    /**
     * Gets information about this compiled program provided by {@link
     * Consumer#getProgramInfo(Program program)} or {@link
     * Consumer#enable(Program program)}.
     *
     * @return information about this compiled program, or {@code null}
     * if this {@code Program} has not been passed to {@link
     * Consumer#getProgramInfo(Program program)} or {@link
     * Consumer#enable(Program program)}
     */
    public ProgramInfo
    getInfo()
    {
	return info;
    }

    /**
     * Sets additional information about this compiled program,
     * including program stability and matching probe count.  Several
     * {@code Consumer} methods attach such information to a given
     * {@code Program} argument.  The method is {@code public} to
     * support implementations of the {@code Consumer} interface other
     * than {@link LocalConsumer}.  Although a {@code Program} can only
     * be obtained from a {@code LocalConsumer}, other {@code Consumer}
     * implemenations may provide a helpful layer of abstraction while
     * using a {@code LocalConsumer} internally to compile DTrace
     * programs.  Users of the API are not otherwise expected to call
     * the {@code setInfo()} method directly.
     *
     * @param programInfo optional additional information about this
     * compiled program
     * @see #getInfo()
     * @see Consumer#enable(Program program)
     * @see Consumer#getProgramInfo(Program program)
     */
    public void
    setInfo(ProgramInfo programInfo)
    {
	info = programInfo;
    }

    private void
    readObject(ObjectInputStream s)
	    throws IOException, ClassNotFoundException
    {
	s.defaultReadObject();
	// check class invariants
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
     * Gets the contents of the given file as a string.
     *
     * @return non-null contents of the given file as a string
     * @throws IOException if the method fails to read the contents of
     * the given file
     */
    static String
    getProgramString(java.io.File programFile) throws IOException
    {
	if (programFile == null) {
	    return null;
	}

	StringBuilder buf = new StringBuilder();
	InputStream in;
	in = new BufferedInputStream(new FileInputStream(programFile));
	int i = in.read();
	while (i >= 0) {
	    buf.append((char)i);
	    i = in.read();
	}

	String s = buf.toString();
	return s;
    }

    /**
     * Gets a string representation of this {@code Program} instance
     * useful for logging and not intended for display.  The exact
     * details of the representation are unspecified and subject to
     * change, but the following format may be regarded as typical:
     * <pre><code>
     * class-name[property1 = value1, property2 = value2]
     * </code></pre>
     */
    public String
    toString()
    {
	StringBuilder buf = new StringBuilder();
	buf.append(Program.class.getName());
	buf.append("[contents = ");
	buf.append(contents);
	buf.append(", info = ");
	buf.append(info);
	buf.append(']');
	return buf.toString();
    }

    /**
     * Identifies a compiled D program, specifically one that has been
     * compiled from a file.
     */
    public static final class File extends Program {
	static final long serialVersionUID = 6217493430514165300L;

	// Set by LocalConsumer.compile()
	/** @serial */
	java.io.File file;

	private
	File()
	{
	}

	// Called by LocalConsumer.compile() to ensure that only valid
	// instances are made accessible to users.  Similarly called by
	// readObject to ensure that only valid instances are deserialized.
	final void
	validateFile()
	{
	    if (file == null) {
		throw new NullPointerException("file is null");
	    }
	}

	/**
	 * Gets the program file.
	 *
	 * @return the {@code File} passed to {@link
	 * Consumer#compile(java.io.File program, String[] macroArgs)}
	 */
	public java.io.File
	getFile()
	{
	    return file;
	}

	private void
	readObject(ObjectInputStream s)
		throws IOException, ClassNotFoundException
	{
	    s.defaultReadObject();
	    // check class invariants
	    try {
		validateFile();
	    } catch (Exception e) {
		InvalidObjectException x = new InvalidObjectException(
			e.getMessage());
		x.initCause(e);
		throw x;
	    }
	}

	public String
	toString()
	{
	    StringBuilder buf = new StringBuilder();
	    buf.append(Program.File.class.getName());
	    buf.append("[super = ");
	    buf.append(super.toString());
	    buf.append(", file = ");
	    buf.append(file);
	    buf.append(']');
	    return buf.toString();
	}
    }
}
