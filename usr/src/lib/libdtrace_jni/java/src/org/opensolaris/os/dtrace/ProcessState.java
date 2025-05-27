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
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */
package org.opensolaris.os.dtrace;

import java.io.*;
import java.beans.*;

/**
 * State of a target process designated by {@link
 * Consumer#createProcess(String command)} or {@link
 * Consumer#grabProcess(int pid)}.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see ConsumerListener#processStateChanged(ProcessEvent e)
 *
 * @author Tom Erickson
 */
public final class ProcessState implements Serializable {
    static final long serialVersionUID = -3395911213431317292L;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(ProcessState.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"processID", "state",
		    "terminationSignal", "terminationSignalName",
		    "exitStatus", "message"})
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

		protected Expression
		instantiate(Object oldInstance, Encoder out)
		{
		    ProcessState pstate = (ProcessState)oldInstance;
		    return new Expression(oldInstance, oldInstance.getClass(),
			    "new", new Object[] { pstate.getProcessID(),
			    pstate.getState().name(),
			    pstate.getTerminationSignal(),
			    pstate.getTerminationSignalName(),
			    pstate.getExitStatus(),
			    pstate.getMessage() });
		}
	    };
	    BeanDescriptor d = info.getBeanDescriptor();
	    d.setValue("persistenceDelegate", persistenceDelegate);
	} catch (IntrospectionException e) {
	    System.out.println(e);
	}
    }

    /**
     * State of a target process.
     */
    public enum State {
	/** Process is running. */
	RUN,
	/** Process is stopped. */
	STOP,
	/** Process is lost to control. */
	LOST,
	/** Process is terminated (zombie). */
	UNDEAD,
	/** Process is terminated (core file). */
	DEAD
    }

    /** @serial */
    private int processID;
    /** @serial */
    private State state;
    /** @serial */
    private int terminationSignal;
    /** @serial */
    private String terminationSignalName;
    /** @serial */
    private Integer exitStatus;
    /** @serial */
    private String message;

    /**
     * Creates a {@code ProcessState} instance with the given state.
     *
     * @param pid non-negative target process ID
     * @param processState target process state
     * @param processTerminationSignal signal that terminated the target
     * process, {@code -1} if the process was not terminated by a signal
     * or if the terminating signal is unknown
     * @param processTerminationSignalName name of the signal that
     * terminated the target process, {@code null} if the process was
     * not terminated by a signal or if the terminating signal is
     * unknown
     * @param processExitStatus target process exit status, {@code null}
     * if the process has not exited or the exit status is unknown
     * @param msg message included by DTrace, if any
     * @throws NullPointerException if the given process state is {@code
     * null}
     * @throws IllegalArgumentException if the given process ID is negative
     */
    public
    ProcessState(int pid, State processState,
	    int processTerminationSignal,
	    String processTerminationSignalName,
	    Integer processExitStatus, String msg)
    {
	processID = pid;
	state = processState;
	terminationSignal = processTerminationSignal;
	terminationSignalName = processTerminationSignalName;
	exitStatus = processExitStatus;
	message = msg;
	validate();
    }

    /**
     * Supports XML persistence.
     *
     * @see #ProcessState(int pid, State processState, int
     * processTerminationSignal, String processTerminationSignalName,
     * Integer processExitStatus, String msg)
     * @throws IllegalArgumentException if there is no {@link
     * ProcessState.State} value with the given state name.
     */
    public
    ProcessState(int pid, String processStateName,
	    int processTerminationSignal,
	    String processTerminationSignalName,
	    Integer processExitStatus, String msg)
    {
	processID = pid;
	state = Enum.valueOf(State.class, processStateName);
	terminationSignal = processTerminationSignal;
	terminationSignalName = processTerminationSignalName;
	exitStatus = processExitStatus;
	message = msg;
	validate();
    }

    private final void
    validate()
    {
	if (processID < 0) {
	    throw new IllegalArgumentException("pid is negative");
	}
	if (state == null) {
	    throw new NullPointerException("process state is null");
	}
    }

    /**
     * Gets the process ID.
     *
     * @return non-negative target process ID
     */
    public int
    getProcessID()
    {
	return processID;
    }

    /**
     * Gets the process state.
     *
     * @return non-null target process state
     */
    public State
    getState()
    {
	return state;
    }

    /**
     * Gets the signal that terminated the process.
     *
     * @return termination signal, {@code -1} if the process was not
     * terminated by a signal or if the terminating signal is unknown
     */
    public int
    getTerminationSignal()
    {
	return terminationSignal;
    }

    /**
     * Gets the name of the signal that terminated the process.
     *
     * @return termination signal name, {@code null} if the process was
     * not terminated by a signal or if the terminating signal is
     * unknown
     */
    public String
    getTerminationSignalName()
    {
	return terminationSignalName;
    }

    /**
     * Gets the process exit status.
     *
     * @return exit status, or {@code null} if the process has not
     * exited or the exit status is unknown
     */
    public Integer
    getExitStatus()
    {
	return exitStatus;
    }

    /**
     * Called by native code.
     */
    private void
    setExitStatus(int status)
    {
	exitStatus = Integer.valueOf(status);
    }

    /**
     * Gets the message from DTrace describing this process state.
     *
     * @return DTrace message, or {@code null} if DTrace did not include
     * a message with this process state
     */
    public String
    getMessage()
    {
	return message;
    }

    /**
     * Compares the specified object with this {@code ProcessState}
     * instance for equality.  Defines equality as having the same
     * attributes.
     *
     * @return {@code true} if and only if the specified object is also
     * a {@code ProcessState} and both instances have the same
     * attributes
     */
    @Override
    public boolean
    equals(Object o)
    {
	if (o instanceof ProcessState) {
	    ProcessState s = (ProcessState)o;
	    return ((processID == s.processID) &&
		    (state == s.state) &&
		    (terminationSignal == s.terminationSignal) &&
		    ((terminationSignalName == null) ?
		    (s.terminationSignalName == null) :
		    terminationSignalName.equals(s.terminationSignalName)) &&
		    ((exitStatus == null) ?
		    (s.exitStatus == null) :
		    exitStatus.equals(s.exitStatus)) &&
		    ((message == null) ? (s.message == null) :
		    message.equals(s.message)));
	}
	return false;
    }

    /**
     * Overridden to ensure that equal instances have equal hash codes.
     */
    @Override
    public int
    hashCode()
    {
	int hash = 17;
	hash = (37 * hash) + processID;
	hash = (37 * hash) + state.hashCode();
	hash = (37 * hash) + terminationSignal;
	hash = (37 * hash) + (exitStatus == null ? 0 :
		exitStatus.hashCode());
	hash = (37 * hash) + (message == null ? 0 : message.hashCode());
	return hash;
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
     * Gets a string representation of this process state useful for
     * logging and not intended for display.  The exact details of the
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
	buf.append(ProcessState.class.getName());
	buf.append("[pid = ");
	buf.append(processID);
	buf.append(", state = ");
	buf.append(state);
	buf.append(", terminationSignal = ");
	buf.append(terminationSignal);
	buf.append(", terminationSignalName = ");
	buf.append(terminationSignalName);
	buf.append(", exitStatus = ");
	buf.append(exitStatus);
	buf.append(", message = ");
	buf.append(message);
	buf.append(']');
	return buf.toString();
    }
}
