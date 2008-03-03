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

import java.util.*;
import java.io.*;
import java.beans.*;

/**
 * Data generated when a DTrace probe fires, contains one record for
 * every record-generating action in the probe.  (Some D actions, such
 * as {@code clear()}, do not generate a {@code ProbeData} record.)  A
 * {@link Consumer} gets data from DTrace by registering a {@link
 * ConsumerListener listener} to get probe data whenever a probe fires:
 * <pre><code>
 *     Consumer consumer = new LocalConsumer();
 *     consumer.addConsumerListener(new ConsumerAdapter() {
 *         public void dataReceived(DataEvent e) {
 *             ProbeData probeData = e.getProbeData();
 *             System.out.println(probeData);
 *         }
 *     });
 * </code></pre>
 * Getting DTrace to generate that probe data involves compiling,
 * enabling, and running a D program:
 * <pre><code>
 *     try {
 *         consumer.open();
 *         consumer.compile(program);
 *         consumer.enable(); // instruments code at matching probe points
 *         consumer.go(); // non-blocking; generates probe data in background
 *     } catch (DTraceException e) {
 *         e.printStackTrace();
 *     }
 * </code></pre>
 * Currently the {@code ProbeData} instance does not record a timestamp.
 * If you need a timestamp, trace the built-in {@code timestamp}
 * variable in your D program.  (See the
 * <a href=http://docs.sun.com/app/docs/doc/817-6223/6mlkidlfv?a=view>
 * <b>Built-in Variables</b></a> section of the <b>Variables</b> chapter of
 * the <i>Solaris Dynamic Tracing Guide</i>).
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see Consumer#addConsumerListener(ConsumerListener l)
 * @see ConsumerListener#dataReceived(DataEvent e)
 *
 * @author Tom Erickson
 */
public final class ProbeData implements Serializable, Comparable <ProbeData> {
    static final long serialVersionUID = -7021504416192099215L;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(ProbeData.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"enabledProbeID", "CPU",
		    "enabledProbeDescription", "flow", "records"});
	    BeanDescriptor d = info.getBeanDescriptor();
	    d.setValue("persistenceDelegate", persistenceDelegate);
	} catch (IntrospectionException e) {
	    System.out.println(e);
	}
    }

    private static Comparator <ProbeData> DEFAULT_CMP;

    static {
	try {
	    DEFAULT_CMP = ProbeData.getComparator(KeyField.RECORDS,
		    KeyField.EPID);
	} catch (Throwable e) {
	    e.printStackTrace();
	    System.exit(1);
	}
    }

    /** @serial */
    private int epid;
    /** @serial */
    private int cpu;
    /** @serial */
    private ProbeDescription enabledProbeDescription;
    /** @serial */
    private Flow flow;
    // Scratch data, one element per native probedata->dtpda_edesc->dtepd_nrecs
    // element, cleared after records list is fully populated.
    private transient List <Record> nativeElements;
    /** @serial */
    private List <Record> records;

    /**
     * Enumerates the fields by which {@link ProbeData} may be sorted
     * using the {@link #getComparator(KeyField[] f) getComparator()}
     * convenience method.
     */
    public enum KeyField {
	/** Specifies {@link ProbeData#getCPU()} */
	CPU,
	/** Specifies {@link ProbeData#getEnabledProbeDescription()} */
	PROBE,
	/** Specifies {@link ProbeData#getEnabledProbeID()} */
	EPID,
	/** Specifies {@link ProbeData#getRecords()} */
	RECORDS
    }

    /**
     * Called by native code.
     */
    private
    ProbeData(int enabledProbeID, int cpuID, ProbeDescription p,
	    Flow f, int nativeElementCount)
    {
	epid = enabledProbeID;
	cpu = cpuID;
	enabledProbeDescription = p;
	flow = f;
	nativeElements = new ArrayList <Record> (nativeElementCount);
	records = new ArrayList <Record> ();
	validate();
    }

    /**
     * Creates a probe data instance with the given properties and list
     * of records.  Supports XML persistence.
     *
     * @param enabledProbeID identifies the enabled probe that fired;
     * the ID is generated by the native DTrace library to distinguish
     * all probes enabled by the source consumer (as opposed to
     * all probes on the system)
     * @param cpuID non-negative ID, identifies the CPU on which the
     * probe fired
     * @param p identifies the enabled probe that fired
     * @param f current state of control flow (entry or return and depth
     * in call stack) at time of probe firing, included if {@link
     * Option#flowindent flowindent} option used, {@code null} otherwise
     * @param recordList list of records generated by D actions in the
     * probe that fired, one record per action, may be empty
     * @throws NullPointerException if the given probe description or
     * list of records is {@code null}
     */
    public
    ProbeData(int enabledProbeID, int cpuID, ProbeDescription p,
	    Flow f, List <Record> recordList)
    {
	epid = enabledProbeID;
	cpu = cpuID;
	enabledProbeDescription = p;
	flow = f;
	records = new ArrayList <Record> (recordList.size());
	records.addAll(recordList);
	validate();
    }

    private final void
    validate()
    {
	if (enabledProbeDescription == null) {
	    throw new NullPointerException(
		    "enabled probe description is null");
	}
	if (records == null) {
	    throw new NullPointerException("record list is null");
	}
    }

    private void
    addDataElement(Record o)
    {
	// Early error detection if native code adds the wrong type
	Record r = Record.class.cast(o);

	nativeElements.add(o);
    }

    /**
     * Called by native code.
     */
    private void
    addRecord(Record record)
    {
	records.add(record);
    }

    /**
     * Called by native code.
     */
    private void
    addTraceRecord(int i)
    {
	// trace() value is preceded by one null for every D program
	// statement preceding trace() that is not a D action, such as
	// assignment to a variable (results in a native probedata
	// record with no data).
	int len = nativeElements.size();
	Record rec = null;
	for (; ((rec = nativeElements.get(i)) == null) && (i < len); ++i);
	records.add(rec);
    }

    /**
     * Called by native code.
     */
    private void
    addSymbolRecord(int i, String lookupString)
    {
	int len = nativeElements.size();
	Record rec = null;
	for (; ((rec = nativeElements.get(i)) == null) && (i < len); ++i);
	SymbolValueRecord symbol = SymbolValueRecord.class.cast(rec);
	if (symbol instanceof KernelSymbolRecord) {
	    KernelSymbolRecord.class.cast(symbol).setSymbol(lookupString);
	} else if (symbol instanceof UserSymbolRecord) {
	    UserSymbolRecord.class.cast(symbol).setSymbol(lookupString);
	} else {
	    throw new IllegalStateException("no symbol record at index " + i);
	}
	records.add(symbol);
    }

    /**
     * Called by native code.
     */
    private void
    addStackRecord(int i, String framesString)
    {
	int len = nativeElements.size();
	Record rec = null;
	for (; ((rec = nativeElements.get(i)) == null) && (i < len); ++i);
	StackValueRecord stack = StackValueRecord.class.cast(rec);
	StackFrame[] frames = KernelStackRecord.parse(framesString);
	if (stack instanceof KernelStackRecord) {
	    KernelStackRecord.class.cast(stack).setStackFrames(frames);
	} else if (stack instanceof UserStackRecord) {
	    UserStackRecord.class.cast(stack).setStackFrames(frames);
	} else {
	    throw new IllegalStateException("no stack record at index " + i);
	}
	records.add(stack);
    }

    /**
     * Called by native code.
     */
    private void
    addPrintfRecord()
    {
	records.add(new PrintfRecord());
    }

    /**
     * Called by native code.
     */
    private void
    addPrintaRecord(long snaptimeNanos, boolean isFormatString)
    {
	records.add(new PrintaRecord(snaptimeNanos, isFormatString));
    }

    private PrintaRecord
    getLastPrinta()
    {
	ListIterator <Record> itr = records.listIterator(records.size());
	PrintaRecord printa = null;
	Record record;
	while (itr.hasPrevious() && (printa == null)) {
	    record = itr.previous();
	    if (record instanceof PrintaRecord) {
		printa = PrintaRecord.class.cast(record);
	    }
	}
	return printa;
    }

    /**
     * Called by native code.
     */
    private void
    addAggregationRecord(String aggregationName, long aggid,
	    AggregationRecord rec)
    {
	PrintaRecord printa = getLastPrinta();
	if (printa == null) {
	    throw new IllegalStateException(
		    "No PrintaRecord in this ProbeData");
	}
	printa.addRecord(aggregationName, aggid, rec);
    }

    /**
     * Called by native code.
     */
    private void
    invalidatePrintaRecord()
    {
	PrintaRecord printa = getLastPrinta();
	if (printa == null) {
	    throw new IllegalStateException(
		    "No PrintaRecord in this ProbeData");
	}
	printa.invalidate();
    }

    /**
     * Called by native code.
     */
    private void
    addPrintaFormattedString(Tuple tuple, String s)
    {
	PrintaRecord printa = getLastPrinta();
	if (printa == null) {
	    throw new IllegalStateException(
		    "No PrintaRecord in this ProbeData");
	}
	printa.addFormattedString(tuple, s);
    }

    /**
     * Called by native code.
     */
    private void
    addExitRecord(int i)
    {
	int len = nativeElements.size();
	Record rec = null;
	for (; ((rec = nativeElements.get(i)) == null) && (i < len); ++i);
	ScalarRecord scalar = ScalarRecord.class.cast(rec);
	Integer exitStatus = Integer.class.cast(scalar.getValue());
	records.add(new ExitRecord(exitStatus));
    }

    /**
     * Called by native code.  Attaches native probedata elements cached
     * between the given first index and last index inclusive to the most
     * recently added record if applicable.
     */
    private void
    attachRecordElements(int first, int last)
    {
	Record record = records.get(records.size() - 1);
	if (record instanceof PrintfRecord) {
	    PrintfRecord printf = PrintfRecord.class.cast(record);
	    Record e;
	    for (int i = first; i <= last; ++i) {
		e = nativeElements.get(i);
		if (e == null) {
		    // printf() unformatted elements are preceded by one
		    // null for every D program statement preceding the
		    // printf() that is not a D action, such as
		    // assignment to a variable (generates a probedata
		    // record with no data).
		    continue;
		}
		printf.addUnformattedElement(ScalarRecord.class.cast(e));
	    }
	}
    }

    /**
     * Called by native code.
     */
    void
    clearNativeElements()
    {
	nativeElements = null;
    }

    /**
     * Called by native code.
     */
    private void
    setFormattedString(String s)
    {
	Record record = records.get(records.size() - 1);
	if (record instanceof PrintfRecord) {
	    PrintfRecord printf = PrintfRecord.class.cast(record);
	    printf.setFormattedString(s);
	}
    }

    /**
     * Convenience method, gets a comparator that sorts multiple {@link
     * ProbeDescription} instances by the specified field or fields.  If
     * more than one sort field is specified, the probe data are sorted
     * by the first field, and in case of a tie, by the second field,
     * and so on, in the order that the fields are specified.
     *
     * @param f field specifiers given in descending order of sort
     * priority; lower priority fields are only compared (as a tie
     * breaker) when all higher priority fields are equal
     * @return non-null probe data comparator that sorts by the
     * specified sort fields in the given order
     */
    public static Comparator <ProbeData>
    getComparator(KeyField ... f)
    {
	return new Cmp(f);
    }

    private static class Cmp implements Comparator <ProbeData> {
	private KeyField[] sortFields;

	private
	Cmp(KeyField ... f)
	{
	    sortFields = f;
	}

	public int
	compare(ProbeData d1, ProbeData d2)
	{
	    return ProbeData.compare(d1, d2, sortFields);
	}
    }

    static int
    compareUnsigned(int i1, int i2)
    {
	int cmp;

	if (i1 < 0) {
	    if (i2 < 0) {
		cmp = (i1 < i2 ? -1 : (i1 > i2 ? 1 : 0));
	    } else {
		cmp = 1; // negative > positive
	    }
	} else if (i2 < 0) {
	    cmp = -1; // positive < negative
	} else {
	    cmp = (i1 < i2 ? -1 : (i1 > i2 ? 1 : 0));
	}

	return cmp;
    }

    static int
    compareUnsigned(long i1, long i2)
    {
	int cmp;

	if (i1 < 0) {
	    if (i2 < 0) {
		cmp = (i1 < i2 ? -1 : (i1 > i2 ? 1 : 0));
	    } else {
		cmp = 1; // negative > positive
	    }
	} else if (i2 < 0) {
	    cmp = -1; // positive < negative
	} else {
	    cmp = (i1 < i2 ? -1 : (i1 > i2 ? 1 : 0));
	}

	return cmp;
    }

    static int
    compareUnsigned(byte i1, byte i2)
    {
	int cmp;

	if (i1 < 0) {
	    if (i2 < 0) {
		cmp = (i1 < i2 ? -1 : (i1 > i2 ? 1 : 0));
	    } else {
		cmp = 1; // negative > positive
	    }
	} else if (i2 < 0) {
	    cmp = -1; // positive < negative
	} else {
	    cmp = (i1 < i2 ? -1 : (i1 > i2 ? 1 : 0));
	}

	return cmp;
    }

    static int
    compareByteArrays(byte[] a1, byte[] a2)
    {
	int cmp = 0;
	int len1 = a1.length;
	int len2 = a2.length;

	for (int i = 0; (cmp == 0) && (i < len1) && (i < len2); ++i) {
	    cmp = compareUnsigned(a1[i], a2[i]);
	}

	if (cmp == 0) {
	    cmp = (len1 < len2 ? -1 : (len1 > len2 ? 1 : 0));
	}

	return cmp;
    }

    @SuppressWarnings("unchecked")
    static int
    compareUnsigned(Comparable v1, Comparable v2)
    {
	int cmp;

	if (v1 instanceof Integer) {
	    int i1 = Integer.class.cast(v1);
	    int i2 = Integer.class.cast(v2);
	    cmp = compareUnsigned(i1, i2);
	} else if (v1 instanceof Long) {
	    long i1 = Long.class.cast(v1);
	    long i2 = Long.class.cast(v2);
	    cmp = compareUnsigned(i1, i2);
	} else {
	    cmp = v1.compareTo(v2);
	}

	return cmp;
    }

    /**
     * @throws ClassCastException if records or their data are not
     * mutually comparable
     */
    @SuppressWarnings("unchecked")
    private static int
    compareRecords(Record r1, Record r2)
    {
	int cmp;
	if (r1 instanceof ScalarRecord) {
	    ScalarRecord t1 = ScalarRecord.class.cast(r1);
	    ScalarRecord t2 = ScalarRecord.class.cast(r2);
	    Object o1 = t1.getValue();
	    Object o2 = t2.getValue();
	    if (o1 instanceof byte[]) {
		byte[] a1 = byte[].class.cast(o1);
		byte[] a2 = byte[].class.cast(o2);
		cmp = compareByteArrays(a1, a2);
	    } else {
		Comparable v1 = Comparable.class.cast(o1);
		Comparable v2 = Comparable.class.cast(o2);
		cmp = v1.compareTo(v2); // compare signed values
	    }
	} else if (r1 instanceof Comparable) {
	    // StackValueRecord, SymbolValueRecord
	    Comparable v1 = Comparable.class.cast(r1);
	    Comparable v2 = Comparable.class.cast(r2);
	    cmp = v1.compareTo(v2);
	} else if (r1 instanceof ExitRecord) {
	    ExitRecord e1 = ExitRecord.class.cast(r1);
	    ExitRecord e2 = ExitRecord.class.cast(r2);
	    int status1 = e1.getStatus();
	    int status2 = e2.getStatus();
	    cmp = (status1 < status2 ? -1 : (status1 > status2 ? 1 : 0));
	} else {
	    // PrintfRecord, PrintaRecord
	    r1.getClass().cast(r2);
	    String s1 = r1.toString();
	    String s2 = r2.toString();
	    cmp = s1.compareTo(s2);
	}

	return cmp;
    }

    /**
     * @throws ClassCastException if lists are not mutually comparable
     * because corresponding list elements are not comparable or the
     * list themselves are different lengths
     */
    private static int
    compareRecordLists(ProbeData d1, ProbeData d2)
    {
	List <Record> list1 = d1.getRecords();
	List <Record> list2 = d2.getRecords();
	int len1 = list1.size();
	int len2 = list2.size();
	if (len1 != len2) {
	    throw new ClassCastException("Record lists of different " +
		    "length are not comparable (lengths are " +
		    len1 + " and " + len2 + ").");
	}

	int cmp;
	Record r1;
	Record r2;

	for (int i = 0; (i < len1) && (i < len2); ++i) {
	    r1 = list1.get(i);
	    r2 = list2.get(i);

	    cmp = compareRecords(r1, r2);
	    if (cmp != 0) {
		return cmp;
	    }
	}

	return 0;
    }

    private static int
    compare(ProbeData d1, ProbeData d2, KeyField[] comparedFields)
    {
	int cmp;
	for (KeyField f : comparedFields) {
	    switch (f) {
		case CPU:
		    int cpu1 = d1.getCPU();
		    int cpu2 = d2.getCPU();
		    cmp = (cpu1 < cpu2 ? -1 : (cpu1 > cpu2 ? 1 : 0));
		    break;
		case PROBE:
		    ProbeDescription p1 = d1.getEnabledProbeDescription();
		    ProbeDescription p2 = d2.getEnabledProbeDescription();
		    cmp = p1.compareTo(p2);
		    break;
		case EPID:
		    int epid1 = d1.getEnabledProbeID();
		    int epid2 = d2.getEnabledProbeID();
		    cmp = (epid1 < epid2 ? -1 : (epid1 > epid2 ? 1 : 0));
		    break;
		case RECORDS:
		    cmp = compareRecordLists(d1, d2);
		    break;
		default:
		    throw new IllegalArgumentException(
			    "Unexpected sort field " + f);
	    }

	    if (cmp != 0) {
		return cmp;
	    }
	}

	return 0;
    }

    /**
     * Gets the enabled probe ID.  Identifies the enabled probe that
     * fired and generated this {@code ProbeData}.  The "epid" is
     * different from {@link ProbeDescription#getID()} in that it
     * identifies a probe among all probes enabled by the source {@link
     * Consumer}, rather than among all the probes on the system.
     *
     * @return the enabled probe ID generated by the native DTrace
     * library
     */
    public int
    getEnabledProbeID()
    {
	return epid;
    }

    /**
     * Gets the ID of the CPU on which the probe fired.
     *
     * @return ID of the CPU on which the probe fired
     */
    public int
    getCPU()
    {
	return cpu;
    }

    /**
     * Gets the enabled probe description.  Identifies the enabled probe
     * that fired and generated this {@code ProbeData}.
     *
     * @return non-null probe description
     */
    public ProbeDescription
    getEnabledProbeDescription()
    {
	return enabledProbeDescription;
    }

    /**
     * Gets the current state of control flow (function entry or return,
     * and depth in call stack) at the time of the probe firing that
     * generated this {@code ProbeData} instance, or {@code null} if
     * such information was not requested with the {@code flowindent}
     * option.
     *
     * @return a description of control flow across function boundaries,
     * or {@code null} if {@code Consumer.getOption(Option.flowindent)}
     * returns {@link Option#UNSET}
     * @see Consumer#setOption(String option)
     * @see Option#flowindent
     */
    public Flow
    getFlow()
    {
	return flow;
    }

    /**
     * Gets the records generated by the actions of the probe that
     * fired, in the same order as the actions that generated the
     * records.  The returned list includes one record for every
     * record-generating D action (some D actions, such as {@code
     * clear()}, do not generate records).
     *
     * @return non-null, unmodifiable list view of the records belonging
     * to this {@code ProbeData} in the order of the actions in the
     * DTrace probe that generated them (record-producing actions are
     * generally those that produce output, such as {@code printf()},
     * but also the {@code exit()} action)
     */
    public List <Record>
    getRecords()
    {
	return Collections. <Record> unmodifiableList(records);
    }

    /**
     * Natural ordering of probe data.  Sorts probe data by records
     * first, then if record data is equal, by enabled probe ID.
     *
     * @param d probe data to be compared with this probe data
     * @return a negative number, zero, or a positive number as this
     * probe data is less than, equal to, or greater than the given
     * probe data
     * @see ProbeData#getComparator(KeyField[] f)
     * @throws NullPointerException if the given probe data is
     * {@code null}
     * @throws ClassCastException if record lists of both {@code
     * ProbeData} instances are not mutually comparable because
     * corresponding list elements are not comparable or the lists
     * themselves are different lengths
     */
    public int
    compareTo(ProbeData d)
    {
	return DEFAULT_CMP.compare(this, d);
    }

    private void
    readObject(ObjectInputStream s)
            throws IOException, ClassNotFoundException
    {
	s.defaultReadObject();
	// Defensively copy record list _before_ validating.
	int len = records.size();
	ArrayList <Record> copy = new ArrayList <Record> (len);
	copy.addAll(records);
	records = copy;
	// Check class invariants
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
     * Gets a string representation of this {@code ProbeData} instance
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
	buf.append(ProbeData.class.getName());
	buf.append("[epid = ");
	buf.append(epid);
	buf.append(", cpu = ");
	buf.append(cpu);
	buf.append(", enabledProbeDescription = ");
	buf.append(enabledProbeDescription);
	buf.append(", flow = ");
	buf.append(flow);
	buf.append(", records = ");

	Record record;
	Object value;
	buf.append('[');
	for (int i = 0; i < records.size(); ++i) {
	    if (i > 0) {
		buf.append(", ");
	    }
	    record = records.get(i);
	    if (record instanceof ValueRecord) {
		value = ValueRecord.class.cast(record).getValue();
		if (value instanceof String) {
		    buf.append("\"");
		    buf.append(String.class.cast(value));
		    buf.append("\"");
		} else {
		    buf.append(record);
		}
	    } else {
		buf.append(record);
	    }
	}
	buf.append(']');

	buf.append(']');
	return buf.toString();
    }
}
