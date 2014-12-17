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
 */
package org.opensolaris.os.dtrace;

import java.io.*;
import java.util.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import javax.swing.event.EventListenerList;
import java.util.logging.*;

/**
 * Interface to the native DTrace library, each instance is a single
 * DTrace consumer.
 *
 * @author Tom Erickson
 */
public class LocalConsumer implements Consumer {
    //
    // Implementation notes:
    //
    // libdtrace is *not* thread-safe.  You cannot make multiple calls
    // into it simultaneously from different threads, even if those
    // threads are operating on different dtrace_hdl_t's.  Calls to
    // libdtrace are synchronized on a global lock, LocalConsumer.class.

    static Logger logger = Logger.getLogger(LocalConsumer.class.getName());

    // Needs to match the version in dtrace_jni.c
    private static final int DTRACE_JNI_VERSION = 3;

    private static final Option[] DEFAULT_OPTIONS = new Option[] {
	new Option(Option.bufsize, Option.kb(256)),
	new Option(Option.aggsize, Option.kb(256)),
    };

    private static native void _loadJniTable();

    // Undocumented configuration options
    private static boolean debug;
    private static int maxConsumers;

    static {
	LocalConsumer.configureLogging();
	// Undocumented configuration options settable using
	// java -Doption=value
	LocalConsumer.getConfigurationOptions();

	Utility.loadLibrary("libdtrace_jni.so.1", debug);

	_checkVersion(DTRACE_JNI_VERSION);
	_setDebug(debug);
	if (maxConsumers > 0) {
	    _setMaximumConsumers(maxConsumers);
	}

	//
	// Last of all in case configuration options affect the loading
	// of the JNI table.
	//
	_loadJniTable();
    }

    // Native JNI interface (see lib/libdtrace_jni/dtrace_jni.c)
    private static native void _checkVersion(int version);
    private native void _open(OpenFlag[] flags) throws DTraceException;
    private native Program _compileString(String program, String[] args)
	    throws DTraceException;
    private native Program.File _compileFile(String path, String[] args)
	    throws DTraceException;
    private native void _exec(Program program) throws DTraceException;
    private native void _getProgramInfo(Program program)
	    throws DTraceException;
    private native void _setOption(String option, String value)
	    throws DTraceException;
    private native long _getOption(String option) throws DTraceException;
    private native boolean _isEnabled();
    private native void _checkProgramEnabling();
    private native void _go() throws DTraceException;
    private native void _stop() throws DTraceException;
    private native void _consume() throws DTraceException;
    private native void _interrupt();
    private native void _close();
    private native Aggregate _getAggregate(AggregateSpec spec)
	    throws DTraceException;
    private native int _createProcess(String cmd) throws DTraceException;
    private native void _grabProcess(int pid) throws DTraceException;
    private native void _listProbes(List <ProbeDescription> probeList,
	    ProbeDescription filter);
    private native void _listProbeDetail(List <Probe> probeList,
	    ProbeDescription filter);
    private native void _listCompiledProbes(
	    List <ProbeDescription> probeList, Program program);
    private native void _listCompiledProbeDetail(
	    List <Probe> probeList, Program program);
    private static native String _getVersion();
    private static native int _openCount();
    //
    // Releases memory held in the JNI layer after dtrace_close() has
    // released critical system resources like file descriptors, and
    // calls to libdtrace are no longer needed (or possible).
    //
    private native void _destroy();
    // Called by LogDistribution
    static native long _quantizeBucket(int i);
    //
    // Cannot be static because the necessary dtrace handle is specific
    // to this Consumer.
    //
    private native String _lookupKernelFunction(Number address);
    private native String _lookupUserFunction(int pid, Number address);
    private static native String _getExecutableName();

    // Undocumented configuration options
    private static native void _setMaximumConsumers(int max);
    private static native void _setDebug(boolean debug);

    protected EventListenerList listenerList;
    protected ExceptionHandler exceptionHandler;

    private int _handle = -1;    // native C identifier (do not modify)
    private final Identifier id; // java identifier

    private enum State {
	INIT,
	OPEN,
	COMPILED,
	GO,
	STARTED,
	STOPPED,
	CLOSED
    }

    private State state = State.INIT;
    private boolean stopCalled;
    private boolean abortCalled;

    //
    // Per-consumer lock used in native code to prevent conflict between
    // the native consumer loop and the getAggregate() thread without
    // locking this LocalConsumer.  A distinct per-consumer lock allows
    // the stop() method to be synchronized without causing deadlock
    // when the consumer loop grabs the per-consumer lock before
    // dtrace_work().
    //
    private Object consumerLock;

    //
    // stopLock is a synchronization lock used to ensure that the stop()
    // method does not return until this consumer has actually stopped.
    // Correct lock ordering is needed to ensure that listeners cannot
    // deadlock this consumer:
    // 1. stop() grabs the lock on this consumer before determining if
    //    this consumer is running (to ensure valid state).
    // 2. Once stop() determines that this consumer is actually running,
    //    it releases the lock on this consumer.  Failing to release the
    //    lock makes it possible for a ConsumerListener to deadlock this
    //    consumer by calling any synchronized LocalConcumer method
    //    (because the listener called by the worker thread prevents the
    //    worker thread from finishing while it waits for stop() to
    //    release the lock, which it will never do until the worker
    //    thread finishes).
    // 3. stop() interrupts this consumer and grabs the stopLock, then
    //    waits on the stopLock for this consumer to stop (i.e. for the
    //    worker thread to finish).
    // 4. The interrupted worker thread grabs the stopLock when it
    //    finishes so it can notify waiters on the stopLock (in this
    //    case the stop() method) that the worker thread is finished.
    //    The workEnded flag (whose access is protected by the
    //    stopLock), is used in case the interrupted worker thread
    //    finishes and grabs the stopLock before the stop() method does.
    //    Setting the flag in that case tells the stop() method it has
    //    nothing to wait for (otherwise stop() would wait forever,
    //    since there is no one left after the worker thread finishes to
    //    notify the stop() method to stop waiting).
    // 5. The worker thread updates the state member to STOPPED and
    //    notifies listeners while it holds the stopLock and before it
    //    notifies waiters on the stopLock.  This is to ensure that
    //    state has been updated to STOPPED and that listeners have
    //    executed consumerStopped() before the stop() method returns,
    //    to ensure valid state and in case the caller of stop() is
    //    relying on anything having been done by consumerStopped()
    //    before it proceeds to the next statement.
    // 6. The worker thread notifies waiters on the stopLock before
    //    releasing it.  stop() returns.
    //
    private Object stopLock;
    private boolean workEnded;

    private static int sequence = 0;

    private static void
    configureLogging()
    {
	logger.setUseParentHandlers(false);
	Handler handler = new ConsoleHandler();
	handler.setLevel(Level.ALL);
	logger.addHandler(handler);
        logger.setLevel(Level.OFF);
    }

    private static Integer
    getIntegerProperty(String name)
    {
	Integer value = null;
	String property = System.getProperty(name);
	if (property != null && property.length() != 0) {
	    try {
		value = Integer.parseInt(property);
		System.out.println(name + "=" + value);
	    } catch (NumberFormatException e) {
		System.err.println("Warning: property ignored: " +
			name + "=" + property);
	    }
	}
	return value;
    }

    private static void
    getConfigurationOptions()
    {
	Integer property;
	property = getIntegerProperty("JAVA_DTRACE_API_DEBUG");
	if (property != null) {
	    debug = (property != 0);
	}
	property = getIntegerProperty("JAVA_DTRACE_MAX_CONSUMERS");
	if (property != null) {
	    maxConsumers = property;
	}
    }

    /**
     * Creates a consumer that interacts with the native DTrace library
     * on the local system.
     */
    public
    LocalConsumer()
    {
	id = new LocalConsumer.Identifier(this);
	consumerLock = new Object();
	stopLock = new Object();
	listenerList = new EventListenerList();
    }

    /**
     * Called by native C code only
     */
    private int
    getHandle()
    {
	return _handle;
    }

    /**
     * Called by native C code only
     */
    private void
    setHandle(int n)
    {
	_handle = n;
    }

    public synchronized void
    open(OpenFlag ... flags) throws DTraceException
    {
	if (state == State.CLOSED) {
	    throw new IllegalStateException("cannot reopen a closed consumer");
	}
	if (state != State.INIT) {
	    throw new IllegalStateException("consumer already open");
	}

	for (OpenFlag flag : flags) {
	    if (flag == null) {
		throw new NullPointerException("open flag is null");
	    }
	}

	synchronized (LocalConsumer.class) {
	    _open(flags);
	}

	state = State.OPEN;
	setOptions(DEFAULT_OPTIONS);

	if (abortCalled) {
	    _interrupt();
	}

	if (logger.isLoggable(Level.INFO)) {
	    logger.info("consumer table count: " + _openCount());
	}
    }

    private synchronized void
    checkCompile()
    {
	switch (state) {
	    case INIT:
		throw new IllegalStateException("consumer not open");
	    case OPEN:
	    case COMPILED: // caller may compile more than one program
		break;
	    case GO:
	    case STARTED:
		throw new IllegalStateException("go() already called");
	    case STOPPED:
		throw new IllegalStateException("consumer stopped");
	    case CLOSED:
		throw new IllegalStateException("consumer closed");
	}
    }

    public synchronized Program
    compile(String program, String ... macroArgs) throws DTraceException
    {
	if (program == null) {
	    throw new NullPointerException("program string is null");
	}
	checkCompile();
	Program p = null;

	String[] argv = null;
	if (macroArgs != null) {
	    for (String macroArg : macroArgs) {
		if (macroArg == null) {
		    throw new NullPointerException("macro argument is null");
		}
	    }
	    argv = new String[macroArgs.length + 1];
	    synchronized (LocalConsumer.class) {
		//
		// Could be an application with an embedded JVM, not
		// necessarily "java".
		//
		argv[0] = _getExecutableName();
	    }
	    System.arraycopy(macroArgs, 0, argv, 1, macroArgs.length);
	} else {
	    synchronized (LocalConsumer.class) {
		argv = new String[] { _getExecutableName() };
	    }
	}
	synchronized (LocalConsumer.class) {
	    p = _compileString(program, argv);
	}
	p.consumerID = id;
	p.contents = program;
	p.validate();
	state = State.COMPILED;

	return p;
    }

    public synchronized Program
    compile(File program, String ... macroArgs) throws DTraceException,
            IOException, SecurityException
    {
	if (program == null) {
	    throw new NullPointerException("program file is null");
	}
	if (!program.canRead()) {
	    throw new FileNotFoundException("failed to open " +
		    program.getName());
	}
	checkCompile();
	Program.File p = null;

	String[] argv = null;
	if (macroArgs != null) {
	    for (String macroArg : macroArgs) {
		if (macroArg == null) {
		    throw new NullPointerException("macro argument is null");
		}
	    }
	    argv = new String[macroArgs.length + 1];
	    argv[0] = program.getPath();
	    System.arraycopy(macroArgs, 0, argv, 1, macroArgs.length);
	} else {
	    macroArgs = new String[] { program.getPath() };
	}
	synchronized (LocalConsumer.class) {
	    p = _compileFile(program.getPath(), argv);
	}
	p.consumerID = id;
	p.contents = Program.getProgramString(program);
	p.file = program;
	p.validate();
	p.validateFile();
	state = State.COMPILED;

	return p;
    }

    private synchronized void
    checkProgram(Program program)
    {
	if (program == null) {
	    throw new NullPointerException("program is null");
	}
	if (!id.equals(program.consumerID)) {
	    throw new IllegalArgumentException("program not compiled " +
		    "by this consumer");
	}
    }

    public void
    enable() throws DTraceException
    {
	enable(null);
    }

    public synchronized void
    enable(Program program) throws DTraceException
    {
	switch (state) {
	    case INIT:
		throw new IllegalStateException("consumer not open");
	    case OPEN:
		throw new IllegalStateException("no compiled program");
	    case COMPILED:
		break;
	    case GO:
	    case STARTED:
		throw new IllegalStateException("go() already called");
	    case STOPPED:
		throw new IllegalStateException("consumer stopped");
	    case CLOSED:
		throw new IllegalStateException("consumer closed");
	}

	// Compile all programs if null
	if (program != null) {
	    checkProgram(program);
	}

	//
	// Left to native code to throw IllegalArgumentException if the
	// program is already enabled, since only the native code knows
	// the enabled state.
	//
	synchronized (LocalConsumer.class) {
	    _exec(program);
	}
    }

    public synchronized void
    getProgramInfo(Program program) throws DTraceException
    {
	checkProgram(program);
	if (state == State.CLOSED) {
	    throw new IllegalStateException("consumer closed");
	}

	//
	// The given program was compiled by this consumer, so we can
	// assert the following:
	//
	assert ((state != State.INIT) && (state != State.OPEN));

	synchronized (LocalConsumer.class) {
	    _getProgramInfo(program);
	}
    }

    private void
    setOptions(Option[] options) throws DTraceException
    {
	for (Option o : options) {
	    setOption(o.getName(), o.getValue());
	}
    }

    public void
    setOption(String option) throws DTraceException
    {
	setOption(option, Option.VALUE_SET);
    }

    public void
    unsetOption(String option) throws DTraceException
    {
	setOption(option, Option.VALUE_UNSET);
    }

    public synchronized void
    setOption(String option, String value) throws DTraceException
    {
	if (option == null) {
	    throw new NullPointerException("option is null");
	}
	if (value == null) {
	    throw new NullPointerException("option value is null");
	}

	switch (state) {
	    case INIT:
		throw new IllegalStateException("consumer not open");
	    case OPEN:
	    case COMPILED:
	    case GO:
	    case STARTED: // Some options can be set on a running consumer
	    case STOPPED: // Allowed (may affect getAggregate())
		break;
	    case CLOSED:
		throw new IllegalStateException("consumer closed");
	}

	synchronized (LocalConsumer.class) {
	    _setOption(option, value);
	}
    }

    public synchronized long
    getOption(String option) throws DTraceException
    {
	if (option == null) {
	    throw new NullPointerException("option is null");
	}

	switch (state) {
	    case INIT:
		throw new IllegalStateException("consumer not open");
	    case OPEN:
	    case COMPILED:
	    case GO:
	    case STARTED:
	    case STOPPED:
		break;
	    case CLOSED:
		throw new IllegalStateException("consumer closed");
	}

	long value;
	synchronized (LocalConsumer.class) {
	    value = _getOption(option);
	}
	return value;
    }

    public final synchronized boolean
    isOpen()
    {
	return ((state != State.INIT) && (state != State.CLOSED));
    }

    public final synchronized boolean
    isEnabled()
    {
	if (state != State.COMPILED) {
	    return false;
	}

	return _isEnabled();
    }

    public final synchronized boolean
    isRunning()
    {
	return (state == State.STARTED);
    }

    public final synchronized boolean
    isClosed()
    {
	return (state == State.CLOSED);
    }

    /**
     * Called in the runnable target of the thread returned by {@link
     * #createThread()} to run this DTrace consumer.
     *
     * @see #createThread()
     */
    protected final void
    work()
    {
	try {
	    synchronized (this) {
		if (state != State.GO) {
		    //
		    // stop() was called after go() but before the
		    // consumer started
		    //
		    return; // executes finally block before returning
		}

		state = State.STARTED;
		fireConsumerStarted(new ConsumerEvent(this,
			System.nanoTime()));
	    }

	    //
	    // We should not prevent other consumers from running
	    // concurrently while this consumer blocks on the native
	    // consumer loop.  Instead, native code will acquire the
	    // LocalConsumer.class monitor as needed before calling
	    // libdtrace functions.
	    //
	    _consume();

	} catch (Throwable e) {
	    if (exceptionHandler != null) {
		exceptionHandler.handleException(e);
	    } else {
		e.printStackTrace();
	    }
	} finally {
	    synchronized (stopLock) {
		// Notify listeners while holding stopLock to guarantee
		// that listeners finish executing consumerStopped()
		// before the stop() method returns.
		synchronized (this) {
		    if (state == State.STOPPED || state == State.CLOSED) {
			//
			// This consumer was stopped just after calling
			// go() but before starting (the premature return
			// case at the top of this work() method). It is
			// possible to call close() on a consumer that has
			// been stopped before starting. In that case the
			// premature return above still takes us here in the
			// finally clause, and we must not revert the CLOSED
			// state to STOPPED.
			//
		    } else {
			state = State.STOPPED;
			fireConsumerStopped(new ConsumerEvent(this,
				System.nanoTime()));
		    }
		}

		// Notify the stop() method to stop waiting
		workEnded = true;
		stopLock.notifyAll();
	    }
	}
    }

    /**
     * Creates the background thread started by {@link #go()} to run
     * this consumer.  Override this method if you need to set
     * non-default {@code Thread} options or create the thread in a
     * {@code ThreadGroup}.  If you don't need to create the thread
     * yourself, set the desired options on {@code super.createThread()}
     * before returning it.  Otherwise, the {@code Runnable} target of
     * the created thread must call {@link #work()} in order to run this
     * DTrace consumer.  For example, to modify the default background
     * consumer thread:
     * <pre><code>
     *	protected Thread
     *	createThread()
     *	{
     *		Thread t = super.createThread();
     *		t.setPriority(Thread.MIN_PRIORITY);
     *		return t;
     *	}
     * </code></pre>
     * Or if you need to create your own thread:
     * <pre></code>
     *	protected Thread
     *	createThread()
     *	{
     *		Runnable target = new Runnable() {
     *			public void run() {
     *				work();
     *			}
     *		};
     *		String name = "Consumer " + UserApplication.sequence++;
     *		Thread t = new Thread(UserApplication.threadGroup,
     *			target, name);
     *		return t;
     *	}
     * </code></pre>
     * Do not start the returned thread, otherwise {@code go()} will
     * throw an {@link IllegalThreadStateException} when it tries to
     * start the returned thread a second time.
     */
    protected Thread
    createThread()
    {
	Thread t = new Thread(new Runnable() {
	    public void run() {
		work();
	    }
	}, "DTrace consumer " + id);
	return t;
    }

    /**
     * @inheritDoc
     * @throws IllegalThreadStateException if a subclass calls {@link
     * Thread#start()} on the value of {@link #createThread()}
     * @see #createThread()
     */
    public void
    go() throws DTraceException
    {
	go(null);
    }

    /**
     * @inheritDoc
     * @throws IllegalThreadStateException if a subclass calls {@link
     * Thread#start()} on the value of {@link #createThread()}
     * @see #createThread()
     */
    public synchronized void
    go(ExceptionHandler h) throws DTraceException
    {
	switch (state) {
	    case INIT:
		throw new IllegalStateException("consumer not open");
	    case OPEN:
		throw new IllegalStateException("no compiled program");
	    case COMPILED:
		//
		// Throws IllegalStateException if not all compiled programs are
		// also enabled.  Does not make any calls to libdtrace.
		//
		_checkProgramEnabling();
		break;
	    case GO:
	    case STARTED:
		throw new IllegalStateException("go() already called");
	    case STOPPED:
		throw new IllegalStateException("consumer stopped");
	    case CLOSED:
		throw new IllegalStateException("consumer closed");
	    default:
		throw new IllegalArgumentException("unknown state: " + state);
	}

	synchronized (LocalConsumer.class) {
	    _go();
	}

	state = State.GO;
	exceptionHandler = h;
	Thread t = createThread();
	t.start();
    }

    /**
     * @inheritDoc
     *
     * @throws IllegalThreadStateException if attempting to {@code
     * stop()} a running consumer while holding the lock on that
     * consumer
     */
    public void
    stop()
    {
	boolean running = false;

	synchronized (this) {
	    switch (state) {
		case INIT:
		    throw new IllegalStateException("consumer not open");
		case OPEN:
		case COMPILED:
		    throw new IllegalStateException("go() not called");
		case GO:
		    try {
			synchronized (LocalConsumer.class) {
			    _stop();
			}
			state = State.STOPPED;
			fireConsumerStopped(new ConsumerEvent(this,
				System.nanoTime()));
		    } catch (DTraceException e) {
			if (exceptionHandler != null) {
			    exceptionHandler.handleException(e);
			} else {
			    e.printStackTrace();
			}
		    }
		    break;
		case STARTED:
		    running = true;
		    break;
		case STOPPED:
		    //
		    // The work() thread that runs the native consumer
		    // loop may have terminated because of the exit()
		    // action in a DTrace program.  In that case, a
		    // RuntimeException is inappropriate because there
		    // is no misuse of the API.  Creating a new checked
		    // exception type to handle this case seems to offer
		    // no benefit for the trouble to the caller.
		    // Instead, the situation calls for stop() to be
		    // quietly tolerant.
		    //
		    if (stopCalled) {
			throw new IllegalStateException(
				"consumer already stopped");
		    }
		    logger.fine("consumer already stopped");
		    break;
		case CLOSED:
		    throw new IllegalStateException("consumer closed");
		default:
		    throw new IllegalArgumentException("unknown state: " +
			    state);
	    }

	    stopCalled = true;
	}

	if (running) {
	    if (Thread.holdsLock(this)) {
		throw new IllegalThreadStateException("The current " +
			"thread cannot stop this LocalConsumer while " +
			"holding the lock on this LocalConsumer");
	    }

	    //
	    // Calls no libdtrace methods, so no synchronization is
	    // needed.  Sets a native flag that causes the consumer
	    // thread to exit the consumer loop and call native
	    // dtrace_stop() at the end of the current interval (after
	    // grabbing the global Consumer.class lock required for any
	    // libdtrace call).
	    //
	    _interrupt();

	    synchronized (stopLock) {
		//
		// Wait for work() to set workEnded.  If the work()
		// thread got the stopLock first, then workEnded is
		// already set.
		//
		while (!workEnded) {
		    try {
			stopLock.wait();
		    } catch (InterruptedException e) {
			logger.warning(e.toString());
			// do nothing but re-check the condition for
			// waiting
		    }
		}
	    }
	}
    }

    public synchronized void
    abort()
    {
	if ((state != State.INIT) && (state != State.CLOSED)) {
	    _interrupt();
	}
	abortCalled = true;
    }

    /**
     * @inheritDoc
     *
     * @throws IllegalThreadStateException if attempting to {@code
     * close()} a running consumer while holding the lock on that
     * consumer
     */
    public void
    close()
    {
	synchronized (this) {
	    if ((state == State.INIT) || (state == State.CLOSED)) {
		state = State.CLOSED;
		return;
	    }
	}

	try {
	    stop();
	} catch (IllegalStateException e) {
	    // ignore (we don't have synchronized state access because
	    // it is illegal to call stop() while holding the lock on
	    // this consumer)
	}

	synchronized (this) {
	    if (state != State.CLOSED) {
		synchronized (LocalConsumer.class) {
		    _close();
		}
		_destroy();
		state = State.CLOSED;

		if (logger.isLoggable(Level.INFO)) {
		    logger.info("consumer table count: " + _openCount());
		}
	    }
	}
    }

    public void
    addConsumerListener(ConsumerListener l)
    {
        listenerList.add(ConsumerListener.class, l);
    }

    public void
    removeConsumerListener(ConsumerListener l)
    {
        listenerList.remove(ConsumerListener.class, l);
    }

    public Aggregate
    getAggregate() throws DTraceException
    {
	// include all, clear none
	return getAggregate(null, Collections. <String> emptySet());
    }

    public Aggregate
    getAggregate(Set <String> includedAggregationNames)
            throws DTraceException
    {
	return getAggregate(includedAggregationNames,
		Collections. <String> emptySet());
    }

    public Aggregate
    getAggregate(Set <String> includedAggregationNames,
	    Set <String> clearedAggregationNames)
            throws DTraceException
    {
	AggregateSpec spec = new AggregateSpec();

	if (includedAggregationNames == null) {
	    spec.setIncludeByDefault(true);
	} else {
	    spec.setIncludeByDefault(false);
	    for (String included : includedAggregationNames) {
		spec.addIncludedAggregationName(included);
	    }
	}

	if (clearedAggregationNames == null) {
	    spec.setClearByDefault(true);
	} else {
	    spec.setClearByDefault(false);
	    for (String cleared : clearedAggregationNames) {
		spec.addClearedAggregationName(cleared);
	    }
	}

	return getAggregate(spec);
    }

    private synchronized Aggregate
    getAggregate(AggregateSpec spec) throws DTraceException
    {
	//
	// It should be possible to request aggregation data after a
	// consumer has stopped but not after it has been closed.
	//
	checkGoCalled();

	//
	// Getting the aggregate is a time-consuming request that should not
	// prevent other consumers from running concurrently.  Instead,
	// native code will acquire the LocalConsumer.class monitor as
	// needed before calling libdtrace functions.
	//
	Aggregate aggregate = _getAggregate(spec);
	return aggregate;
    }

    private synchronized void
    checkGoCalled()
    {
	switch (state) {
	    case INIT:
		throw new IllegalStateException("consumer not open");
	    case OPEN:
	    case COMPILED:
		throw new IllegalStateException("go() not called");
	    case GO:
	    case STARTED:
	    case STOPPED:
		break;
	    case CLOSED:
		throw new IllegalStateException("consumer closed");
	}
    }

    private synchronized void
    checkGoNotCalled()
    {
	switch (state) {
	    case INIT:
		throw new IllegalStateException("consumer not open");
	    case OPEN:
	    case COMPILED:
		break;
	    case GO:
	    case STARTED:
		throw new IllegalStateException("go() already called");
	    case STOPPED:
		throw new IllegalStateException("consumer stopped");
	    case CLOSED:
		throw new IllegalStateException("consumer closed");
	}
    }

    public synchronized int
    createProcess(String command) throws DTraceException
    {
	if (command == null) {
	    throw new NullPointerException("command is null");
	}

	checkGoNotCalled();

	int pid;
	synchronized (LocalConsumer.class) {
	    pid = _createProcess(command);
	}
	return pid;
    }

    public synchronized void
    grabProcess(int pid) throws DTraceException
    {
	checkGoNotCalled();

	synchronized (LocalConsumer.class) {
	    _grabProcess(pid);
	}
    }

    public synchronized List <ProbeDescription>
    listProbes(ProbeDescription filter) throws DTraceException
    {
	checkGoNotCalled();
	List <ProbeDescription> probeList =
		new LinkedList <ProbeDescription> ();
	if (filter == ProbeDescription.EMPTY) {
	    filter = null;
	}
	synchronized (LocalConsumer.class) {
	    _listProbes(probeList, filter);
	}
	return probeList;
    }

    public synchronized List <Probe>
    listProbeDetail(ProbeDescription filter) throws DTraceException
    {
	checkGoNotCalled();
	List <Probe> probeList = new LinkedList <Probe> ();
	if (filter == ProbeDescription.EMPTY) {
	    filter = null;
	}
	synchronized (LocalConsumer.class) {
	    _listProbeDetail(probeList, filter);
	}
	return probeList;
    }

    public synchronized List <ProbeDescription>
    listProgramProbes(Program program) throws DTraceException
    {
	checkProgram(program);
	checkGoNotCalled();
	List <ProbeDescription> probeList =
		new LinkedList <ProbeDescription> ();
	synchronized (LocalConsumer.class) {
	    _listCompiledProbes(probeList, program);
	}
	return probeList;
    }

    public synchronized List <Probe>
    listProgramProbeDetail(Program program) throws DTraceException
    {
	checkProgram(program);
	checkGoNotCalled();
	List <Probe> probeList = new LinkedList <Probe> ();
	synchronized (LocalConsumer.class) {
	    _listCompiledProbeDetail(probeList, program);
	}
	return probeList;
    }

    public synchronized String
    lookupKernelFunction(int address)
    {
	checkGoCalled();
	synchronized (LocalConsumer.class) {
	    return _lookupKernelFunction(new Integer(address));
	}
    }

    public synchronized String
    lookupKernelFunction(long address)
    {
	checkGoCalled();
	synchronized (LocalConsumer.class) {
	    return _lookupKernelFunction(new Long(address));
	}
    }

    public synchronized String
    lookupUserFunction(int pid, int address)
    {
	checkGoCalled();
	synchronized (LocalConsumer.class) {
	    return _lookupUserFunction(pid, new Integer(address));
	}
    }

    public synchronized String
    lookupUserFunction(int pid, long address)
    {
	checkGoCalled();
	synchronized (LocalConsumer.class) {
	    return _lookupUserFunction(pid, new Long(address));
	}
    }

    public String
    getVersion()
    {
	synchronized (LocalConsumer.class) {
	    return LocalConsumer._getVersion();
	}
    }

    /**
     * Called by native code.
     */
    private void
    nextProbeData(ProbeData probeData) throws ConsumerException
    {
	fireDataReceived(new DataEvent(this, probeData));
    }

    /**
     * Called by native code.
     */
    private void
    dataDropped(Drop drop) throws ConsumerException
    {
	fireDataDropped(new DropEvent(this, drop));
    }

    /**
     * Called by native code.
     */
    private void
    errorEncountered(Error error) throws ConsumerException
    {
	fireErrorEncountered(new ErrorEvent(this, error));
    }

    /**
     * Called by native code.
     */
    private void
    processStateChanged(ProcessState processState) throws ConsumerException
    {
	fireProcessStateChanged(new ProcessEvent(this, processState));
    }

    protected void
    fireDataReceived(DataEvent e) throws ConsumerException
    {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == ConsumerListener.class) {
                ((ConsumerListener)listeners[i + 1]).dataReceived(e);
            }
        }
    }

    protected void
    fireDataDropped(DropEvent e) throws ConsumerException
    {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == ConsumerListener.class) {
                ((ConsumerListener)listeners[i + 1]).dataDropped(e);
            }
        }
    }

    protected void
    fireErrorEncountered(ErrorEvent e) throws ConsumerException
    {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == ConsumerListener.class) {
                ((ConsumerListener)listeners[i + 1]).errorEncountered(e);
            }
        }
    }

    protected void
    fireProcessStateChanged(ProcessEvent e) throws ConsumerException
    {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == ConsumerListener.class) {
                ((ConsumerListener)listeners[i + 1]).processStateChanged(e);
            }
        }
    }

    protected void
    fireConsumerStarted(ConsumerEvent e)
    {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == ConsumerListener.class) {
                ((ConsumerListener)listeners[i + 1]).consumerStarted(e);
            }
        }
    }

    protected void
    fireConsumerStopped(ConsumerEvent e)
    {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == ConsumerListener.class) {
                ((ConsumerListener)listeners[i + 1]).consumerStopped(e);
            }
        }
    }

    // Called by native code
    private void
    intervalBegan()
    {
	fireIntervalBegan(new ConsumerEvent(this, System.nanoTime()));
    }

    protected void
    fireIntervalBegan(ConsumerEvent e)
    {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == ConsumerListener.class) {
                ((ConsumerListener)listeners[i + 1]).intervalBegan(e);
            }
        }
    }

    // Called by native code
    private void
    intervalEnded()
    {
	fireIntervalEnded(new ConsumerEvent(this, System.nanoTime()));
    }

    protected void
    fireIntervalEnded(ConsumerEvent e)
    {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == ConsumerListener.class) {
                ((ConsumerListener)listeners[i + 1]).intervalEnded(e);
            }
        }
    }

    /**
     * Gets a string representation of this consumer useful for logging
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
	StringBuilder buf = new StringBuilder(LocalConsumer.class.getName());
	synchronized (this) {
	    buf.append("[open = ");
	    buf.append(isOpen());
	    buf.append(", enabled = ");
	    buf.append(isEnabled());
	    buf.append(", running = ");
	    buf.append(isRunning());
	    buf.append(", closed = ");
	    buf.append(isClosed());
	}
	buf.append(']');
	return buf.toString();
    }

    /**
     * Ensures that the {@link #close()} method of this consumer has
     * been called before it is garbage-collected.  The intended safety
     * net is weak because the JVM does not guarantee that an object
     * will be garbage-collected when it is no longer referenced.  Users
     * of the API should call {@code close()} to ensure that all
     * resources associated with this consumer are reclaimed in a timely
     * manner.
     *
     * @see #close()
     */
    protected void
    finalize()
    {
	close();
    }

    private String
    getTag()
    {
	return super.toString();
    }

    //
    // Uniquely identifies a consumer across systems so it is possible
    // to validate that an object such as a Program passed to a remote
    // client over a socket was created by this consumer and no other.
    //
    static class Identifier implements Serializable {
	static final long serialVersionUID = 2183165132305302834L;

	// local identifier
	private int id;
	private long timestamp;
	// remote identifier
	private InetAddress localHost;
	private String tag; // in case localHost not available

	private
	Identifier(LocalConsumer consumer)
	{
	    id = LocalConsumer.sequence++;
	    timestamp = System.currentTimeMillis();
	    try {
		localHost = InetAddress.getLocalHost();
	    } catch (UnknownHostException e) {
		localHost = null;
	    }
	    tag = consumer.getTag();
	}

	@Override
	public boolean
	equals(Object o)
	{
	    if (o == this) {
		return true;
	    }
	    if (o instanceof Identifier) {
		Identifier i = (Identifier)o;
		return ((id == i.id) &&
			(timestamp == i.timestamp) &&
			((localHost == null) ? (i.localHost == null) :
			 localHost.equals(i.localHost)) &&
			tag.equals(i.tag));
	    }
	    return false;
	}

	@Override
	public int
	hashCode()
	{
	    int hash = 17;
	    hash = (37 * hash) + id;
	    hash = (37 * hash) + ((int)(timestamp ^ (timestamp >>> 32)));
	    hash = (37 * hash) + (localHost == null ? 0 :
		    localHost.hashCode());
	    hash = (37 * hash) + tag.hashCode();
	    return hash;
	}

	@Override
	public String
	toString()
	{
	    StringBuilder buf = new StringBuilder();
	    buf.append(Identifier.class.getName());
	    buf.append("[id = ");
	    buf.append(id);
	    buf.append(", timestamp = ");
	    buf.append(timestamp);
	    buf.append(", localHost = ");
	    buf.append(localHost);
	    buf.append(", tag = ");
	    buf.append(tag);
	    buf.append(']');
	    return buf.toString();
	}
    }
}
