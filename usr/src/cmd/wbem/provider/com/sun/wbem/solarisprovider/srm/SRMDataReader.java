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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * SRMDataReader.java
 */


package com.sun.wbem.solarisprovider.srm;

import java.io.*;


/**
 * This class works out the protocol layer of the unidirectional data interface
 * between the rds and the client. The protocol contains a header with a lists
 * of data. Each list has a header and some elements, which have again a header
 * and some fields of data:
 * protocol  = { pheader,  n * list }
 * pheader  == { "@RDS-MAG@", PROTV, LISTN }
 * PROTV    == { protocol version }
 * LISTN    == { number of lists }
 * list     == { lheader, n * element }
 * lheader  == { LISTT, ELEMN }
 * LISTT    == { type of the list }
 * ELEMN    == { number of elements in the list }
 * element  == { eheader, field }
 * eheader  == { ELMID, FILDN }
 * ELMID    == { element id, like pid, uid, project name }
 * field    == { KEY, VALUE }
 * All protocol elements has a key and a value separated by one space.
 * The value begins after the first space and ends at the new line character.
 * Protocol keys are: "@RDS-MAG@", PROTV, LISTN,  LISTT, ELEMN ELMID, FILDN,
 * RDERR. The special key RDERR can occur in any line indicates error condition,
 * where the VALUE is the error message from rds.
 * @author Sun Microsystems, Inc.
 * @version	1.1 08/31/01
 */
class SRMDataReader {

    // Protocol keys
    private static final String PROTM = "@RDS-MAG@"; // protocol starts with it
    private static final String RDERR = "RDERR"; // error notification from rds
    private static final String PROTV = "PROTV"; // protocol version
    private static final String LISTT = "LISTT"; // list type
    private static final String LISTN = "LISTN"; // number of lists
    private static final String ELEMN = "ELEMN"; // number of elements in a list
    private static final String ELMID = "ELMID"; // element id
    private static final String FILDN = "FILDN"; // number of fields in element
    private static final String BUSY  = "BUSY";  // busy notification from rds

    private static final String RDS_PV_ERR = "RDS protocol violation: ";
    private static final int PROT_VERSION = 100; // supported protocol version

    private static final String COMMAND  = "command ";
    private static final String PROMPT = "@RDS@>";
    private static final String PROMPT_WHAT = " ?";

    // RDS commands
    private static final String CMD_ALIVE =  "alive";
    private static final String CMD_EXIT =   "exit";

    private DataModel		dm;
    private Process         	p;
    private int         	exitV;
    private BufferedReader	in, err;
    private PrintWriter		pw;
    private String		line; 	    // last read line
    private String		stdErrline; // last read line
    private String		errline;    // last read error line
    private String		key;  // last read key
    private String		val;  // last read value

    // Timeout for waiting for the first line from rds after its start.
    // Since rds can be busy for a long time reading and scanning its
    // persistence file, this time must set be relative high.
    private static final int OPEN_READTIMEOUT = 30000;	// ms

    // Default timeout for reading RDS responses
    private static final int DEFAULT_READTIMEOUT = 1000;	// ms

    // If rds is too busy to respond, wait this long before retrying
    private static final int RDS_RETRY_SLEEPTIME = 500;	// milliseconds

    // Retry and rds command no more than this many times
    private static final int MAX_RDS_RETRIES = 140;

    protected int readTimeout = DEFAULT_READTIMEOUT;

    private long charsRead = 0;

    private SRMWorker worker;

    /**
     * Constructor.
     * @param	dm	data model that reads and interprets the protocol data
     *			fields.
     */
    public SRMDataReader(DataModel dm) {
	this.dm = dm;

	// initialize the response timeout according to resource property
	String s = Util.propertyREADTIMEOUT;

	if (s != null && s.length() > 0) {
	    try {
		readTimeout = Integer.parseInt(s);
	    } catch (Exception e) {
	    	SRMDebug.trace(SRMDebug.TRACE_ALL, e.getMessage());	
	    }
	}
	worker = new SRMWorker();
	worker.start();
    }
    
    /**
     * Start the by cmdArgs defined rds, and check the protocol header.
     * @param	cmdArgs	contains the path of rds and the arguments to use.
     * @exception SRMProtocolException if a protocol violation has occurred.
     */
    public void startRDS(String []cmdArgs) throws SRMProtocolException {
    	worker.start(cmdArgs, OPEN_READTIMEOUT);
    }
    
    /**
     * Send exit command to rds and close the rds pipe.
     */
    public void closeRDS() {
    	worker.close(readTimeout);
    }

    /**
     * Close the rds pipe and shutdown the rds procces.
     */
    public void shutdownRDS() {
    	worker.shutdown(readTimeout);
    }

    /**
     * Start the udpate.
     * If parse returns an error code it is assumed that rds is busy.
     * The request will then be retried.
     *
     * @param option defines the rds command opion, -S -p ...
     * @exception SRMProtocolException if a protocol violation has occurred.
     */
    public void getUpdate(String option) throws SRMProtocolException {
    	worker.update(option, readTimeout);
    }
    
    /**
     * Force the RDS to keep alive by sending the ALIVE command
     * @exception SRMProtocolException if a protocol violation has occurred.
     */
    public void alive() throws SRMProtocolException {
	worker.alive(readTimeout);
    }

    /**
     * Start the by cmdArgs defined rds, and check the protocol header.
     * This method is called by the worker thread.
     * @param	cmdArgs	contains the path of rds and the arguments to use.
     * @exception SRMProtocolException if a protocol violation has occurred.
     */
    private void _startRDS(String []cmdArgs) throws SRMProtocolException {
	open(cmdArgs);
	try {
	    readHeader();
	} catch (SRMProtocolException e) {
	    SRMDebug.trace(SRMDebug.TRACE_ALL, e.getMessage());
	    shutdownRDS();
	    throw e;
	}
    }

    
    /**
     * Send exit command to rds and close the rds pipe.
     * This method is called by the worker thread.
     */
    private void _closeRDS() {
    
    	/* 
	 * First we try to close rds carefully by sending an exit command.
	 * If it failed we will destroy the rds process. In both cases
	 * we will wait for its termination.
	 */
    	try {
    	    wrCmd(CMD_EXIT);
    	    checkPrompt();
    	    SRMDebug.trace(SRMDebug.RDS_CMD_IFC,
	    	"waiting for rds to terminate");
    	    p.waitFor();
	    close();
    	} catch (SRMProtocolException e) {
    	    shutdownRDS();
    	} catch (InterruptedException e) {
    	    SRMDebug.trace(SRMDebug.TRACE_ALL, e.getMessage());	
	} 
    	SRMDebug.trace(SRMDebug.RDS_CMD_IFC, "done");
    }
    
    /**
     * Close the rds pipe and shutdown the rds procces.
     * This method is called by the worker thread.
     */
    private void _shutdownRDS() {
    
    	/*
    	 * First check if it is still running if so destroy it and wait
	 * for its termination.
	 */
    	if (checkRDSrunning()) {
	    p.destroy();
    	    try {
    		SRMDebug.trace(SRMDebug.RDS_CMD_IFC,
		    "waiting for rds to terminate");
    		p.waitFor();
    	    } catch (InterruptedException e) {
    		SRMDebug.trace(SRMDebug.TRACE_ALL, e.getMessage());	
	    }
    	    SRMDebug.trace(SRMDebug.RDS_CMD_IFC, "done");
    	}
	close();
    }

    /**
     * Start the udpate.
     * This method is called by the worker thread.
     * If parse returns an error code it is assumed that rds is busy.
     * The request will then be retried.
     *
     * @param option defines the rds command opion, -S -p ...
     * @exception SRMProtocolException if a protocol violation has occurred.
     */
    private void _getUpdate(String option) throws SRMProtocolException {
	int numRetries = MAX_RDS_RETRIES;

	do {
	    wrCmd(option);
	    if (parse() == 0 || numRetries <= 0)
		break;

	    try {
		Thread.sleep(RDS_RETRY_SLEEPTIME, 0);
	    } catch (InterruptedException x) {
		;
	    }
	} while (numRetries-- > 0);
	
    	if (numRetries == 0) {
	    throw new SRMProtocolException(
		"Cannot read rds '" + option + "' command output");
	} else {
	    SRMDebug.trace(SRMDebug.RDS_CMD_IFC, "charsRead = " + charsRead);
	}
    }

    /**
     * Force the RDS to keep alive
     * This method is called by the worker thread.
     * @exception SRMProtocolException if a protocol violation has occurred.
     */
    private void _alive() throws SRMProtocolException {
	wrCmd(CMD_ALIVE);
    }

    /**
     * Start the rds and create a BufferedReader input stream.
     * @param	cmdArgs	contains the path of rds and the arguments to use.
     */
    private void open(String []cmdArgs) throws SRMProtocolException {

	InputStream is, errs;
	OutputStream os;
	Runtime     r = Runtime.getRuntime();
	
	if (SRMDebug.isOn(SRMDebug.RDS_CMD_IFC)) {
    	    StringBuffer rdsCallStr = new StringBuffer(cmdArgs[0]);
	    for (int i = 1; i < cmdArgs.length; i++) {
	    	rdsCallStr.append(" " + cmdArgs[i]);
	    }
    	    SRMDebug.trace(SRMDebug.RDS_CMD_IFC, rdsCallStr.toString());
	}
	try {
	    p = r.exec(cmdArgs);
	    is = p.getInputStream();
	    errs = p.getErrorStream();
	    os = p.getOutputStream();
	} catch (IOException e) {
	    throw new SRMProtocolException("Cannot start 'rds', " +
		e.getMessage());
	}
    	if (!checkRDSrunning()) {
	    throw new SRMProtocolException("Cannot start 'rds', " +
			    "rds terminated with exit code =" + exitV);
    	}
	in = new BufferedReader(new InputStreamReader(is));
	err = new BufferedReader(new InputStreamReader(errs));
	pw  = new PrintWriter(os);

    } // end open

    /**
     * Close the data stream to rds.
     */
    private void close() {

    	SRMDebug.trace(SRMDebug.RDS_CMD_IFC, "");
	try {
	    in.close();
	    pw.close();
	    err.close();
	} catch (IOException e) {
	    SRMDebug.trace(SRMDebug.TRACE_ALL, e.getMessage());	
	}

    } // end close

    /**
     * Read the data stream and wait for RDS protocol header, check version.
     * @exception SRMProtocolException if a protocol violation has occurred.
     */
    private void readHeader() throws SRMProtocolException  {

	int protv;
	try {
	    // Waiting for header with the magic value @RDS-MAG@
	    while ((line = in.readLine()) != null) {
		if (line.length() < PROTM.length())
		    continue;
		if (line.equals(PROTM))
		    break;
	    }
	    if (line == null) {
		throw new SRMProtocolException(
		    "Unexpected end of RDS input stream");
	    }
	    // Check the protocol version
	    parseKeyValue();
	    if (!key.equals(PROTV)) {
		throw new SRMProtocolException(RDS_PV_ERR + line);
	    } else {
		protv = Integer.parseInt(val);
		if (PROT_VERSION != protv) {
		    throw new SRMProtocolException(
			"Unsupported RDS protocol version: ex:" +
			PROT_VERSION + ", ac: " + protv);
		}
	    }

	} catch (IOException e) {
	    if (SRMDebug.isOn(SRMDebug.RDS_CMD_IFC))
	    	dumpStdErr();
	    throw new SRMProtocolException("Cannot read RDS protocol header, " +
		e.getMessage());
	}

    } // end readHeader

    /**
     * Parse the data stream from rds, evaluate and strip the protocol elements.
     *
     * Returns 0 if OK, 1 if rds responded 'busy'
     *
     * @exception SRMProtocolException if a protocol violation has occurred.
     */
    private int parse() throws SRMProtocolException  {

	int protv, listn, listt, elemn;
	try {
	    // fetch the number of lists (or maybe it's busy)
	    parseKeyValue();
	    if (!key.equals(LISTN)) {
		throw new SRMProtocolException(RDS_PV_ERR + line);
	    } else {
		listn = Integer.parseInt(val);
	    }
	    
	    for (int lno = 0; lno < listn; lno++) {

		// read the type of the list
		parseKeyValue();
		if (!key.equals(LISTT)) {
		    throw new SRMProtocolException(RDS_PV_ERR + line);
		} else {
		    listt = Integer.parseInt(val);
		}

		// read the number of elements in the list
		parseKeyValue();
		if (!key.equals(ELEMN)) {
		    throw new SRMProtocolException(RDS_PV_ERR + line);
		} else {
		    elemn = Integer.parseInt(val);
		}
		for (int eno = 0; eno < elemn; eno++) {
		    parseElement(listt);
		}
	    }

	} catch (NumberFormatException e) {
	    throw new SRMProtocolException(RDS_PV_ERR + line);
	} catch (SRMProtocolBusyException b) {
	    return 1;
	}

	return 0;
	
    } // end parse

    /**
     * Parse the fields in a element of a list of type listt. The client
     * should know the how to interpret the fields of a element of a particular
     * list type.
     * @param	listt	the type of the list.
     * @exception SRMProtocolException if a protocol violation has occurred.
     */
    private void parseElement(int listt) throws SRMProtocolException {

	int fieldn;
	SRMProviderDataModel pdm;
	String elemidStr;

	parseKeyValue();
	if (!key.equals(ELMID)) {
	    throw new SRMProtocolException(RDS_PV_ERR + line);
	} else {
	    // get the consumer of fields of this element.
	    if ((pdm = dm.getProviderDataModel(listt, val)) == null) {
		throw new SRMProtocolException(RDS_PV_ERR +
		    "wrong list type: " + line);
		}
	}
	parseKeyValue();
	if (!key.equals(FILDN)) {
	    throw new SRMProtocolException(RDS_PV_ERR + line);
	} else {
	    fieldn = Integer.parseInt(val);
	}
	for (int fno = 0; fno < fieldn; fno++) {
	    parseKeyValue();
	    // The provider data model will take the value and set its property
	    pdm.setProperty(key, val);
	}

    } // end parseElement

    /**
     * Parse one line of the input stream and split it into a KEY
     * and VALUE. The read line is stored in the class field line,
     * the KEY in key and VALUE in value. These fields should
     * remains unchanged till the next call of this method. Since they
     * are used in several places in this class.
     * @exception SRMProtocolBusyException if the key is "busy"
     * @exception SRMProtocolException if a protocol violation has occurred.
     */
    private void parseKeyValue() throws SRMProtocolException {

	int idx;
	try {
	    if ((line = in.readLine()) != null) {
		if (line.startsWith(BUSY)) {
		    throw new SRMProtocolBusyException("RDS busy");
		} else if ((idx = line.indexOf(' ')) == -1) {
		    throw new SRMProtocolException(RDS_PV_ERR + line);
		} else {
		    key = line.substring(0, idx);
		    val = line.substring(idx + 1);
		    if (key.equals(RDERR)) {
			throw new SRMProtocolException("RDS error: " + val);
		    }
		}
	    }

	} catch (IOException e) {
	    throw new SRMProtocolException("Cannot read 'rds' input, " +
		e.getMessage());
	}

    } // end parseKeyValue

    /**
     * To synchronize the protocol wait for RDS prompt and then send 
     * a given command to RDS.
     * @param cmd defines the rds command, -S -p ...
     * @throws SRMProtocolException if a protocol violation has occurred.
     */
    private void wrCmd(String cmd) throws SRMProtocolException {

	if (checkPrompt()) {
	    SRMDebug.trace(SRMDebug.RDS_CMD_IFC, "> " + COMMAND + cmd);
	    pw.println(COMMAND + cmd);
	    pw.flush();
	} else {
	    throw new SRMProtocolException(
		"Cannot execute \"" + cmd + "\" command");
	}

    } // end wrCmd

    /**
     * Read the data stream and wait for RDS prompt. This will synchronize
     * the protocol flow.
     * @throws SRMProtocolException if a protocol violation has occurred.
     */
    private boolean checkPrompt() throws SRMProtocolException {

	int tries = 1000;
	int idx;
	try {
	    while (tries-- > 0) {
		if ((line = in.readLine()) != null) {
		    SRMDebug.trace(SRMDebug.RDS_CMD_IFC, "< " + line);
		    if ((idx = line.indexOf(' ')) == -1) {
			key = line;
			if (key.equals(PROMPT)) {
			    return true;
			} else {
			    continue;
			}
		    } else {
			key = line.substring(0, idx);
			val = line.substring(idx + 1);
			if (key.equals(RDERR)) {
			    throw new SRMProtocolException("RDS error: " + val);
			} else if (key.equals(PROMPT)) {
			    return false;
			} else {
			    continue;
			}
		    }

		} else {
		    throw new SRMProtocolException("Cannot read 'rds' prompt");
		}
	    }

	} catch (IOException e) {
	    throw new SRMProtocolException("Cannot read 'rds' prompt," +
		e.getMessage());
	}
	return false;

    } // end checkPrompt

    /**
     * Check if rds is still running
     */
    private boolean checkRDSrunning() {
    
    	try {
    	    exitV = p.exitValue();
	    return false;
	} catch (IllegalThreadStateException e) {
	    return true;
    	}
    }

    /**
     * Dump remianders from rds stderr stream.
     */
    private void dumpStdErr() {
    	String inLine;
	
    	try {	    
    	    while (err.ready()) {
	    	inLine = err.readLine();
	    	SRMDebug.trace2("RDS stderr: " + inLine);
	    }
    	} catch (IOException e) {
	    SRMDebug.trace(SRMDebug.TRACE_ALL, e.getMessage());	
	}
    }

    private synchronized String readLine()
	    throws IOException {

	    return in.readLine();
    }

    /**
     * This thread carries out the public methods start, update,
     * alive, close and shutdown in its own execution thread. The caller
     * of these methods waits for the results the from him specified timeout.
     */
    class SRMWorker extends Thread {
    	// internal code method calls
    	private final static int START_METHOD = 1;
    	private final static int UPDATE_METHOD = 2;
    	private final static int ALIVE_METHOD = 3;
    	private final static int CLOSE_METHOD = 4;
    	private final static int SHUTDOWN_METHOD = 5;
    	// last method's exception is end in ran method and checked
	// in 
	private SRMProtocolException methodException;
	// method to be called in run 
    	private int methodToRun;
	private boolean methodFinished = false;
	// args to be passed in run
    	private String	args;
	private String	argsArray[];
	// All clients should check this flag before calling notifyAll().
	// If false, the client should  call wait() and wait till this
	// thread is executing its run() method.
    	private boolean readyToRun = false;
    
    	public SRMWorker() {
	    super("SRMWorker");
	}
    
    	public void start(String []cmdArgs, int timeout)
	    throws SRMProtocolException {
	    argsArray = cmdArgs;
	    runMethod(START_METHOD, timeout);
	}
	public void update(String option, int timeout)
	    throws SRMProtocolException {
    	    args = option;
    	    runMethod(UPDATE_METHOD, timeout);
	}
	public void alive(int timeout) throws SRMProtocolException {
    	    args = null;
    	    runMethod(ALIVE_METHOD, timeout);
	}
    	public void close(int timeout) {
	    args = null;
	    try {
	    	runMethod(CLOSE_METHOD, timeout);
	    } catch (SRMProtocolException e) {};
	}
	public void shutdown(int timeout) {
    	    args = null;
	    try {
    	    	runMethod(SHUTDOWN_METHOD, timeout);
	    } catch (SRMProtocolException e) {};
	}

    	public synchronized void run() {

    	    readyToRun = true; // synchronize with posible clients
	    notifyAll(); 
	    try {
    	    	while (true) {
	    	    wait(); // wait for task
			try {
			    switch (methodToRun) {
			    case START_METHOD : _startRDS(argsArray); break;
			    case UPDATE_METHOD: _getUpdate(args); break;
			    case ALIVE_METHOD: _alive(); break;
			    case CLOSE_METHOD : _closeRDS(); break;
			    case SHUTDOWN_METHOD : _shutdownRDS(); break;
			    default : methodException =
			    	new SRMProtocolException("unknown method: " +
				    methodToRun);
			    }
			} catch (SRMProtocolException e) {
			    // pass it to the caller
			    methodException  = e;
			}
			methodFinished = true;
			notifyAll();
		}
	    } catch (InterruptedException e) {};
	}
		
	private synchronized void runMethod(int method, int timeout)
	    throws SRMProtocolException {
	
    	    methodToRun = method;
	    methodException = null;
	    methodFinished = false;
	    try {
	    	// wait till this thread has reached its run method.
    	    	if (readyToRun == false) {
	    	    wait(timeout);
	    	}
	    	notifyAll();	// kick it off
	    	wait(timeout); 
	    } catch (InterruptedException e) {
	    	return;
	    }
	    // pass an exception if any
	    if (methodException != null)
	    	throw methodException;
	    // check if the call was finished in the given time 
	    if (methodFinished == false)
		throw new 
		SRMProtocolException("can't execute rds command, timeout");
	}
    }
    
    /**
     * An exception thrown by the parsing code if rds reports 'busy'.
     */
    class SRMProtocolBusyException extends SRMProtocolException {

	public SRMProtocolBusyException(String s) {
	    super(s);
	}

    } // end class SRMProtocolBusyException

} // end class SRMDataReader
