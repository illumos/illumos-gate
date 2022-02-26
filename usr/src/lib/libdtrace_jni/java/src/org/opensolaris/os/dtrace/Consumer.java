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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package org.opensolaris.os.dtrace;

import java.io.*;
import java.util.*;

/**
 * Interface to the native DTrace library, each instance is a single
 * DTrace consumer.  To consume the output of DTrace program actions,
 * {@link #addConsumerListener(ConsumerListener l) register a probe data
 * listener}.  To get a snapshot of all aggregations in a D program on
 * your own programmatic interval without relying on DTrace actions to
 * generate that output, use the {@link #getAggregate()} method.
 *
 * @see ProbeData
 * @see Aggregate
 *
 * @author Tom Erickson
 */
public interface Consumer {

    /**
     * Optional flags passed to {@link #open(Consumer.OpenFlag[] flags)
     * open()}.
     */
    public enum OpenFlag {
	/**
	 * Generate 32-bit D programs.  {@code ILP32} and {@link
	 * Consumer.OpenFlag#LP64 LP64} are mutually exclusive.
	 */
	ILP32,
	/**
	 * Generate 64-bit D programs.  {@code LP64} and {@link
	 * Consumer.OpenFlag#ILP32 ILP32} are mutually exclusive.
	 */
	LP64,
    };

    /**
     * Opens this DTrace consumer.  Optional flags indicate behaviors
     * that can only be set at the time of opening.  Most optional
     * behaviors are set using {@link #setOption(String option, String
     * value) setOption()} after opening the consumer.  In the great
     * majority of cases, the consumer is opened without specifying any
     * flags:
     * <pre>		{@code consumer.open();}</pre>
     * Subsequent calls to set options, compile DTrace programs, enable
     * probes, and run this consumer may be made from any thread.
     *
     * @throws NullPointerException if any of the given open flags is
     * {@code null}
     * @throws IllegalArgumentException if any of the given flags are
     * mutually exclusive
     * @throws IllegalStateException if this consumer is closed or has
     * already been opened
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     * @see #compile(File program, String[] macroArgs)
     * @see #compile(String program, String[] macroArgs)
     * @see #enable()
     * @see #go()
     */
    public void open(OpenFlag ... flags) throws DTraceException;

    /**
     * Compiles the given D program string.  Optional macro arguments
     * replace corresponding numbered macro variables in the D program
     * starting at {@code $1}.
     *
     * @param program program string
     * @param macroArgs macro substitutions for <i>$n</i> placeholders
     * embedded in the given D program: {@code macroArgs[0]} replaces
     * all occurrences of {@code $1}, {@code macroArgs[1]} replaces all
     * occurrences of {@code $2}, and so on.  {@code $0} is
     * automatically replaced by the executable name and should not be
     * included in the {@code macroArgs} parameter.  See the <a
     * href=http://dtrace.org/guide/chp-script.html#chp-script-3>
     * <b>Macro Arguments</b></a> section of the <b>Scripting</b>
     * chapter of the <i>Dynamic Tracing Guide</i>.
     * @return a non-null {@code Program} identifier that may be passed
     * to {@link #enable(Program program) enable()}
     * @throws NullPointerException if the given program string or any
     * of the given macro arguments is {@code null}
     * @throws IllegalStateException if called before {@link
     * #open(OpenFlag[] flags) open()} or after {@link #go()}, or if the
     * consumer is closed
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     * @see #compile(File program, String[] macroArgs)
     */
    public Program compile(String program, String ... macroArgs)
	    throws DTraceException;

    /**
     * Compiles the given D program file.  Optional macro arguments
     * replace corresponding numbered macro variables in the D program
     * starting at {@code $1}.
     *
     * @param program program file
     * @param macroArgs macro substitutions for <i>$n</i> placeholders
     * embedded in the given D program: {@code macroArgs[0]} replaces
     * all occurrences of {@code $1}, {@code macroArgs[1]} replaces all
     * occurrences of {@code $2}, and so on.  {@code $0} is
     * automatically set to the name of the given file and should not be
     * included in the {@code macroArgs} parameter.  See the <a
     * href=http://dtrace.org/guide/chp-script.html#chp-script-3>
     * <b>Macro Arguments</b></a> section of the <b>Scripting</b>
     * chapter of the <i>Dynamic Tracing Guide</i>.
     * @return a non-null {@code Program} identifier that may be passed
     * to {@link #enable(Program program) enable()}
     * @throws NullPointerException if the given program file or any of
     * the given macro arguments is {@code null}
     * @throws IllegalStateException if called before {@link
     * #open(OpenFlag[] flags) open()} or after {@link #go()}, or if the
     * consumer is closed
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     * @throws FileNotFoundException if the given program file cannot be
     * opened
     * @throws IOException if an I/O error occurs while reading the
     * contents of the given program file
     * @throws SecurityException if a security manager exists and its
     * {@code checkRead()} method denies read access to the file
     * @see #compile(String program, String[] macroArgs)
     */
    public Program compile(File program, String ... macroArgs)
	    throws DTraceException, IOException, SecurityException;

    /**
     * Enables all DTrace probes compiled by this consumer.  Call {@code
     * enable()} with no argument to enable everything this consumer has
     * compiled so far (most commonly a single program, the only one to
     * be compiled).  Call with one {@link Program} at a time if you
     * need information about enabled probes specific to each program.
     *
     * @throws IllegalStateException if called before compiling at least
     * one program, or if any compiled program is already enabled, or if
     * {@link #go()} was already called, or if this consumer is closed
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     * @see #enable(Program program)
     */
    public void enable() throws DTraceException;

    /**
     * Enables DTrace probes matching the given program and attaches
     * information about those probes to the given program.  A probe
     * matched multiple times (within the same D program or in multiple
     * D programs) triggers the actions associated with each matching
     * occurrence every time that probe fires.
     *
     * @param program  A {@code Program} identifier returned by {@link
     * #compile(String program, String[] macroArgs) compile(String
     * program, ...)} or {@link #compile(File program, String[]
     * macroArgs) compile(File program, ...)}:  If the given program is
     * {@code null}, the call has the same behavior as {@link #enable()}
     * with no argument; if the given program is non-null, the call
     * enables only those probes matching that program.  In the latter
     * case, the {@code Program} parameter is modified as a way of
     * passing back information about the given program and its matching
     * probes, including program stability.
     * @throws IllegalArgumentException if the given program is non-null
     * and not compiled by this {@code Consumer}
     * @throws IllegalStateException if the given program is already
     * enabled (or if the given program is {@code null} and <i>any</i>
     * program is already enabled), or if {@link #go()} was already
     * called, or if this consumer is closed
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     * @see #compile(String program, String[] macroArgs)
     * @see #compile(File program, String[] macroArgs)
     * @see #enable()
     * @see #getProgramInfo(Program program)
     */
    public void enable(Program program) throws DTraceException;

    /**
     * Attaches information about matching DTrace probes to the given
     * program.  Attaches the same information to the given program as
     * that attached by {@link #enable(Program program)} but without
     * enabling the probes.
     *
     * @throws NullPointerException if the given program is {@code null}
     * @throws IllegalArgumentException if the given program was not
     * compiled by this {@code Consumer}
     * @throws IllegalStateException if called after {@link #close()}
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     * @see #compile(String program, String[] macroArgs)
     * @see #compile(File program, String[] macroArgs)
     * @see #enable(Program program)
     */
    public void getProgramInfo(Program program) throws DTraceException;

    /**
     * Sets a boolean option.
     *
     * @throws NullPointerException if the given option is {@code null}
     * @throws DTraceException if a value is expected for the given
     * option, or if the option is otherwise invalid
     * @throws IllegalStateException if called before {@link
     * #open(OpenFlag[] flags) open()} or after {@link #close()}, or if
     * the given option is a boolean compile-time option and {@link
     * #go()} has already been called (see {@link Option} for a
     * breakdown of runtime and compile-time options)
     * @see #setOption(String option, String value)
     * @see #unsetOption(String option)
     */
    public void setOption(String option) throws DTraceException;

    /**
     * Unsets a boolean option.
     *
     * @throws NullPointerException if the given option is {@code null}
     * @throws DTraceException if the given option is not a boolean
     * option, or if the option is otherwise invalid
     * @throws IllegalStateException if called before {@link
     * #open(OpenFlag[] flags) open()} or after {@link #close()}, or if
     * the given option is a boolean compile-time option and {@link
     * #go()} has already been called (see {@link Option} for a
     * breakdown of runtime and compile-time options)
     * @see #setOption(String option)
     */
    public void unsetOption(String option) throws DTraceException;

    /**
     * Sets the value of a DTrace option.  If the given option affects
     * compile-time behavior, it must be set before calling {@link
     * #compile(String program, String[] macroArgs) compile(String
     * program, ...)} or {@link #compile(File program, String[]
     * macroArgs) compile(File program, ...)} in order to have an effect
     * on compilation.  Some runtime options including {@link
     * Option#switchrate switchrate} and {@link Option#aggrate aggrate}
     * are settable while a consumer is running; others must be set
     * before calling {@link #go()}.  See the <a
     * href=http://dtrace.org/guide/chp-opt.html#chp-opt>
     * <b>Options and Tunables</b></a> chapter of the <i>Dynamic Tracing
     * Guide</i> for information about specific options.
     *
     * @throws NullPointerException if the given option or value is
     * {@code null}
     * @throws IllegalStateException if called before {@link
     * #open(OpenFlag[] flags) open()} or after {@link #close()}, or if
     * the given option is a boolean compile-time option and {@code
     * go()} has already been called (see {@link Option} for a breakdown
     * of runtime and compile-time options)
     * @throws DTraceException for any of the following:
     * <ul><li>The option is invalid</li>
     * <li>The value is invalid for the given option</li>
     * <li>{@code go()} has been called to start this consumer, and the
     * option is not settable on a running consumer (some runtime
     * options, including {@link Option#switchrate switchrate} and
     * {@link Option#aggrate aggrate} are settable while the consumer is
     * running)</li></ul>
     *
     * @see #open(OpenFlag[] flags)
     * @see #getOption(String option)
     * @see Option
     */
    public void setOption(String option, String value) throws DTraceException;

    /**
     * Gets the value of a DTrace option.
     *
     * @throws NullPointerException if the given option is {@code null}
     * @throws IllegalStateException if called before {@link
     * #open(OpenFlag[] flags) open()} or after {@link #close()}
     * @throws DTraceException if the given option is invalid
     * @return the value of the given DTrace option: If the given option
     * is a boolean option and is currently unset, the returned value is
     * {@link Option#UNSET}.  If the given option is a <i>size</i>
     * option, the returned value is in bytes.  If the given option is a
     * <i>time</i> option, the returned value is in nanoseconds.  If the
     * given option is {@link Option#bufpolicy bufpolicy}, the returned
     * value is one of {@link Option#BUFPOLICY_RING BUFPOLICY_RING},
     * {@link Option#BUFPOLICY_FILL BUFPOLICY_FILL}, or {@link
     * Option#BUFPOLICY_SWITCH BUFPOLICY_SWITCH}.  If the given option
     * is {@link Option#bufresize bufresize}, the returned value is one
     * of {@link Option#BUFRESIZE_AUTO BUFRESIZE_AUTO} or {@link
     * Option#BUFRESIZE_MANUAL BUFRESIZE_MANUAL}.
     *
     * @see #setOption(String option)
     * @see #unsetOption(String option)
     * @see #setOption(String option, String value)
     * @see Option
     */
    public long getOption(String option) throws DTraceException;

    /**
     * Reports whether or not this consumer is open.
     *
     * @return {@code true} if and only if {@link #open(OpenFlag[]
     * flags) open()} has been called on this consumer and {@link
     * #close()} has not
     */
    public boolean isOpen();

    /**
     * Reports whether or not it is valid to call {@link #go()}.
     *
     * @return {@code true} if and only if at least one program has been
     * compiled, all compiled programs have been enabled, {@code go()}
     * has not already been called, and {@link #close()} has not been
     * called
     */
    public boolean isEnabled();

    /**
     * Reports whether or not this consumer is running.  There may be a
     * delay after calling {@link #go()} before this consumer actually
     * starts running (listeners are notified by the {@link
     * ConsumerListener#consumerStarted(ConsumerEvent e)
     * consumerStarted()} method).
     *
     * @return {@code true} if this consumer is running, {@code false}
     * otherwise
     */
    public boolean isRunning();

    /**
     * Reports whether or not this consumer is closed.  A closed
     * consumer cannot be reopened.
     * <p>
     * Note that a closed consumer is different from a consumer that has
     * not yet been opened.
     *
     * @return {@code true} if {@link #close()} has been called on this
     * consumer, {@code false} otherwise
     */
    public boolean isClosed();

    /**
     * Begin tracing and start a background thread to consume generated
     * probe data.
     *
     * @throws IllegalStateException if not {@link #isEnabled()}
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     * @see #go(ExceptionHandler h)
     * @see #open(OpenFlag[] flags)
     * @see #compile(String program, String[] macroArgs)
     * @see #compile(File program, String[] macroArgs)
     * @see #enable()
     * @see #stop()
     * @see #close()
     */
    public void go() throws DTraceException;

    /**
     * Begin tracing and start a background thread to consume generated
     * probe data.  Handle any exception thrown in the consumer thread
     * with the given handler.
     *
     * @throws IllegalStateException if not {@link #isEnabled()}
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     * @see #go()
     */
    public void go(ExceptionHandler h) throws DTraceException;

    /**
     * Stops all tracing, as well as the background thread started by
     * {@link #go()} to consume generated probe data.  A stopped
     * consumer cannot be restarted.  It is necessary to {@code close()}
     * a stopped consumer to release the system resources it holds.
     * <p>
     * A consumer may stop on its own in response to the {@code exit()}
     * action (see <b>{@code exit()}</b> in the <a
     * href=http://dtrace.org/guide/chp-actsub.html#chp-actsub-5>
     * <b>Special Actions</b></a> section of the <b>Actions and
     * Subroutines</b> chapter of the <i>Dynamic Tracing
     * Guide</i>).  Similarly, a consumer stops automatically if it has
     * at least one target process and all its target processes have
     * completed (see {@link #createProcess(String command)
     * createProcess()} and {@link #grabProcess(int pid)
     * grabProcess()}).  A consumer also stops automatically if it
     * encounters an exception while consuming probe data.  In these
     * cases it is not necessary to call {@code stop()}.  If a consumer
     * stops for any reason (an explicit call to {@code stop()} or any
     * of the reasons just given), listeners are notified through the
     * {@link ConsumerListener#consumerStopped(ConsumerEvent e)
     * consumerStopped()} method.
     * <p>
     * Note that a call to {@code stop()} blocks until the background
     * thread started by {@code go()} actually stops.  After {@code
     * stop()} returns, a call to {@link #isRunning()} returns {@code
     * false}.  If a {@code DTraceException} is thrown while stopping
     * this consumer, it is handled by the handler passed to {@link
     * #go(ExceptionHandler h)} (or a default handler if none is
     * specified).
     *
     * @throws IllegalStateException if called before {@link #go()} or
     * if {@code stop()} was already called
     * @see #go()
     * @see #abort()
     * @see #close()
     */
    public void stop();

    /**
     * Aborts the background thread started by {@link #go()}.  {@code
     * abort()} is effectively the same as {@link #stop()} except that
     * it does not block (i.e. it does not wait until the background
     * thread actually stops).  {@link #isRunning()} is likely {@code
     * true} immediately after a call to {@code abort()}, since an
     * aborted consumer stops at a time specified as later.
     * Specifically, a call to {@code abort()} stops tracing just before
     * the next {@link ConsumerListener#intervalBegan(ConsumerEvent e)
     * intervalBegan()} event and stops consuming probe data by the
     * subsequent {@link ConsumerListener#intervalEnded(ConsumerEvent e)
     * intervalEnded()} event.  When the aborted consumer actually
     * stops, listeners are notified in the {@link
     * ConsumerListener#consumerStopped(ConsumerEvent e)
     * consumerStopped()} method, where it is convenient to {@link
     * #close()} the stopped consumer after requesting the final
     * aggregate.
     * <p>
     * The {@code abort()} and {@code stop()} methods have slightly
     * different behavior when called <i>just after</i> {@code go()} but
     * <i>before</i> the consumer actually starts running:  It is
     * possible to {@code stop()} a consumer before it starts running
     * (resulting in a {@code consumerStopped()} event without a
     * matching {@code consumerStarted()} event), whereas an aborted
     * consumer will not stop until after it starts running, when it
     * completes a single interval (that interval does not include
     * sleeping to wait for traced probe data).  Calling {@code abort()}
     * before {@code go()} is legal and has the same effect as calling
     * it after {@code go()} and before the consumer starts running.
     * The last behavior follows from the design: You do not know the
     * state of a consumer after calling {@code abort()}, nor is it
     * necessary to know the state of a consumer before calling {@code
     * abort()}.  That may be preferable, for example, when you want to
     * abort a consumer opened and started in another thread.
     *
     * @see #stop()
     */
    public void abort();

    /**
     * Closes an open consumer and releases the system resources it was
     * holding.  If the consumer is running, {@code close()} will {@link
     * #stop()} it automatically.  A closed consumer cannot be
     * reopened.  Closing a consumer that has not yet been opened makes
     * it illegal to open that consumer afterwards.  It is a no-op to
     * call {@code close()} on a consumer that is already closed.
     *
     * @see #open(OpenFlag[] flags)
     */
    public void close();

    /**
     * Adds a listener for probe data generated by this consumer.
     */
    public void addConsumerListener(ConsumerListener l);

    /**
     * Removes a listener for probe data generated by this consumer.
     */
    public void removeConsumerListener(ConsumerListener l);

    /**
     * Gets a snapshot of all aggregations except those that have
     * already been captured in a {@link PrintaRecord}.  Does not clear
     * any aggregation.
     * <p>
     * Provides a programmatic alternative to the {@code printa(})
     * action (see <a
     * href=http://dtrace.org/guide/chp-fmt.html#chp-fmt-printa>
     * <b>{@code printa()}</b></a> in the <b>Output Formatting</b>
     * chapter of the <i>Dynamic Tracing Guide</i>).
     *
     * @throws IllegalStateException if called before {@link #go()} or
     * after {@link #close()}
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     * @see #getAggregate(Set includedAggregationNames, Set
     * clearedAggregationNames)
     */
    public Aggregate getAggregate() throws DTraceException;

    /**
     * Gets a snapshot of all the specified aggregations except those
     * that have already been captured in a {@link PrintaRecord}.  Does
     * not clear any aggregation.
     * <p>
     * Provides a programmatic alternative to the {@code printa(})
     * action (see <a
     * href=http://dtrace.org/guide/chp-fmt.html#chp-fmt-printa>
     * <b>{@code printa()}</b></a> in the <b>Output Formatting</b>
     * chapter of the <i>Dynamic Tracing Guide</i>).
     *
     * @param includedAggregationNames  if {@code null}, all available
     * aggregations are included; if non-null, only those aggregations
     * specifically named by the given set are included
     * @throws IllegalStateException if called before {@link #go()} or
     * after {@link #close()}
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     * @see #getAggregate(Set includedAggregationNames, Set
     * clearedAggregationNames)
     */
    public Aggregate getAggregate(Set <String> includedAggregationNames)
            throws DTraceException;

    /**
     * Gets a snapshot of all the specified aggregations except those
     * that have already been captured in a {@link PrintaRecord}, with
     * the side effect of atomically clearing any subset of those
     * aggregations.  Clearing an aggregation resets all of its values
     * to zero without removing any of its keys.  Leave aggregations
     * uncleared to get running totals, otherwise specify that an
     * aggregation be cleared to get values per time interval.  Note
     * that once an aggregation is captured in a {@code PrintaRecord}
     * (as a result of the {@code printa()} action), it is no longer
     * available to the {@code getAggregate()} method.
     * <p>
     * Provides a programmatic alternative to the {@code printa(}) (see
     * <a
     * href=http://dtrace.org/guide/chp-fmt.html#chp-fmt-printa>
     * <b>{@code printa()}</b></a> in the <b>Output Formatting</b>
     * chapter of the <i>Dynamic Tracing Guide</i>) and {@code
     * clear()} actions.
     *
     * @param includedAggregationNames  if {@code null}, all available
     * aggregations are included; if non-null, only those aggregations
     * specifically named by the given set are included
     * @param clearedAggregationNames  if {@code null}, all available
     * aggregations are cleared; if non-null, only those aggregations
     * specifically named by the given set are cleared
     * @throws IllegalStateException if called before {@link #go()} or
     * after {@link #close()}
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     */
    public Aggregate getAggregate(Set <String> includedAggregationNames,
	    Set <String> clearedAggregationNames) throws DTraceException;

    /**
     * Creates a process by executing the given command on the system
     * and returns the created process ID.  The created process is
     * suspended until calling {@link #go()} so that the process waits
     * to do anything until this consumer has started tracing (allowing
     * a process to be traced from the very beginning of its execution).
     * The macro variable {@code $target} in a D program will be
     * replaced by the process ID of the created process.  When the
     * created process exits, this consumer notifies listeners through
     * the {@link ConsumerListener#processStateChanged(ProcessEvent e)
     * processStateChanged()} method.
     * <p>
     * See the <a
     * href=http://dtrace.org/guide/chp-script.html#chp-script-4>
     * <b>Target Process ID</b></a> section of the <b>Scripting</b>
     * chapter of the <i>Dynamic Tracing Guide</i>.
     *
     * @param command  a string whose first token is assumed to be the
     * name of the command and whose subsequent tokens are the arguments
     * to that command.
     * @return ID of the created process (pid)
     * @throws NullPointerException if the given command is {@code null}
     * @throws IllegalArgumentException if the given command is empty or
     * contains only whitespace
     * @throws IllegalStateException if called before {@link
     * #open(Consumer.OpenFlag[] flags) open()} or after {@link #go()},
     * or if the consumer is closed
     * @throws DTraceException if the process cannot be created
     * @see #grabProcess(int pid)
     */
    public int createProcess(String command) throws DTraceException;

    /**
     * Grabs the specified process and caches its symbol tables.  The
     * macro variable {@code $target} in a D program will be replaced by
     * the process ID of the grabbed process.  When the specified
     * process exits, this consumer notifies listeners through the
     * {@link ConsumerListener#processStateChanged(ProcessEvent e)
     * processStateChanged()} method.
     * <p>
     * See the <a
     * href=http://dtrace.org/guide/chp-script.html#chp-script-4>
     * <b>Target Process ID</b></a> section of the <b>Scripting</b>
     * chapter of the <i>Dynamic Tracing Guide</i>.
     *
     * @param pid  process ID of the process to be grabbed
     * @throws IllegalStateException if called before {@link
     * #open(Consumer.OpenFlag[] flags) open()} or after {@link #go()},
     * or if the consumer is closed
     * @throws DTraceException if the process cannot be grabbed
     * @see #createProcess(String command)
     */
    public void grabProcess(int pid) throws DTraceException;

    /**
     * Lists probes that match the given probe description.  See {@link
     * ProbeDescription} for information about pattern syntax and
     * wildcarding.
     *
     * @param filter use {@link ProbeDescription#EMPTY} to get all
     * probes, otherwise get only those probes that match the given
     * filter
     * @return a non-null list of probe descriptions
     * @throws IllegalStateException if called before {@link
     * #open(Consumer.OpenFlag[] flags) open()} or after {@link #go()},
     * or if the consumer is closed
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     * @see #open(OpenFlag[] flags)
     * @see #close()
     * @see #listProbeDetail(ProbeDescription filter)
     * @see #listProgramProbes(Program program)
     */
    public List <ProbeDescription> listProbes(ProbeDescription filter)
	    throws DTraceException;

    /**
     * Lists probes that match the given probe description and includes
     * detail such as stability information about each listed probe.
     *
     * @param filter use {@link ProbeDescription#EMPTY} to get all
     * probes, otherwise get only those probes that match the given
     * filter
     * @return a non-null list of probe detail
     * @throws IllegalStateException if called before {@link
     * #open(Consumer.OpenFlag[] flags) open()} or after {@link #go()},
     * or if the consumer is closed
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     * @see #listProbes(ProbeDescription filter)
     * @see #listProgramProbeDetail(Program program)
     */
    public List <Probe> listProbeDetail(ProbeDescription filter)
	    throws DTraceException;

    /**
     * Lists probes that match the given compiled program.  A probe
     * matches a D program if that program contains any matching probe
     * description.
     *
     * @param program  a {@code Program} identifier returned by {@link
     * #compile(String program, String[] macroArgs) compile(String
     * program, ...)} or {@link #compile(File program, String[]
     * macroArgs) compile(File program, ...)}
     * @return a non-null list of probe descriptions
     * @throws NullPointerException if the given program identifier is
     * {@code null}
     * @throws IllegalArgumentException if the specified program was not
     * compiled by this consumer
     * @throws IllegalStateException if called before {@link
     * #open(Consumer.OpenFlag[] flags) open()} or after {@link #go()},
     * or if the consumer is closed
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     * @see #listProbes(ProbeDescription filter)
     */
    public List <ProbeDescription> listProgramProbes(Program program)
	    throws DTraceException;

    /**
     * Lists probes that match the given compiled program and includes
     * detail such as stability information about each listed probe.
     *
     * @param program  a {@code Program} identifier returned by {@link
     * #compile(String program, String[] macroArgs) compile(String
     * program, ...)} or {@link #compile(File program, String[]
     * macroArgs) compile(File program, ...)}
     * @return a non-null list of probe detail
     * @throws NullPointerException if the given program identifier is
     * {@code null}
     * @throws IllegalArgumentException if the specified program was not
     * compiled by this consumer
     * @throws IllegalStateException if called before {@link
     * #open(Consumer.OpenFlag[] flags) open()} or after {@link #go()},
     * or if the consumer is closed
     * @throws DTraceException if an exception occurs in the native
     * DTrace library
     * @see #listProgramProbes(Program program)
     * @see #listProbeDetail(ProbeDescription filter)
     */
    public List <Probe> listProgramProbeDetail(Program program)
	    throws DTraceException;

    /**
     * Gets the kernel function name for the given 32-bit kernel
     * address.
     *
     * @param  address 32-bit kernel function address, such as the value
     * of a {@link Tuple} member in an {@link AggregationRecord} to be
     * converted for display
     * @return the result of kernel function lookup as one of the
     * following:<ul><li>{@code module`function}</li>
     * <li>{@code module`function+offset}</li>
     * <li>{@code module`address}</li>
     * <li>{@code address}</li></ul> where {@code module} and {@code
     * function} are names, and {@code offset} and {@code address} are
     * integers in hexadecimal format preceded by "{@code 0x}".  {@code
     * offset} is the number of bytes from the beginning of the
     * function, included when non-zero.  {@code address} is simply the
     * hex form of the input paramater, returned when function lookup
     * fails.  The exact details of this format are subject to change.
     * @throws IllegalStateException if called before {@link #go()} or
     * after {@link #close()}
     * @see #lookupKernelFunction(long address)
     */
    public String lookupKernelFunction(int address);

    /**
     * Gets the kernel function name for the given 64-bit kernel
     * address.
     *
     * @param  address 64-bit kernel function address
     * @return kernel function name
     * @throws IllegalStateException if called before {@link #go()} or
     * after {@link #close()}
     * @see #lookupKernelFunction(int address)
     */
    public String lookupKernelFunction(long address);

    /**
     * Gets the user function name for the given 32-bit user address and
     * process ID.
     *
     * @param  pid ID of the user process containing the addressed
     * function
     * @param  address 32-bit user function address, such as the value
     * of a {@link Tuple} member in an {@link AggregationRecord} to be
     * converted for display.
     * @return result of user function lookup as one of the
     * following:<ul> <li>{@code module`function}</li>
     * <li>{@code module`function+offset}</li>
     * <li>{@code module`address}</li>
     * <li>{@code address}</li></ul> where {@code module} and {@code
     * function} are names, and {@code offset} and {@code address} are
     * integers in hexadecimal format preceded by "{@code 0x}".  {@code
     * offset} is the number of bytes from the beginning of the
     * function, included when non-zero.  {@code address} is simply the
     * hex form of the input paramater, returned when function lookup
     * fails.  The exact details of this format are subject to change.
     * @throws IllegalStateException if called before {@link #go()} or
     * after {@link #close()}
     * @see #lookupUserFunction(int pid, long address)
     */
    public String lookupUserFunction(int pid, int address);

    /**
     * Gets the user function name for the given 64-bit user address and
     * process ID.
     *
     * @param  pid ID of the user process containing the addressed
     * function
     * @param  address 64-bit user function address
     * @return user function name
     * @throws IllegalStateException if called before {@link #go()} or
     * after {@link #close()}
     * @see #lookupUserFunction(int pid, int address)
     */
    public String lookupUserFunction(int pid, long address);

    /**
     * Gets the version of the native DTrace library.
     *
     * @return version string generated by the native DTrace library
     * (same as the output of {@code dtrace(8)} with the {@code -V}
     * option)
     */
    public String getVersion();
}
