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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

//  sldp.java : The service location daemon.
//  Author:           Erik Guttman
//

package com.sun.slp;

import java.io.*;
import java.util.*;
import java.net.*;
import java.lang.reflect.*;
import java.awt.*;

/**
 * The slpd class is the main class for the slpd directory agent/
 * service agent server of SLP. Slpd can run in two possible modes,
 * depending on the configuration of the classes with which it was shipped
 * and information read from the optional configuration file argument:
 *
 *   <ol>
 *     <li> <b> Service Agent server </b>
 *          In this mode, slpd functions as a service agent server only.
 *	    Directory agent functionality is disabled. Service agent
 *	    clients on the local machine register and deregister services
 *	    with slpd, and slpd responds to multicast requests for
 *	    services. It passively and actively listens for directory agent
 *	    advertisements, caches them, and forwards them to both
 *	    user agent and service agent clients. A file of serialized
 *	    proxy registrations can be read at startup.
 *	    This mode is normally default.
 *
 *     <li> <b> Directory Agent/Service Agent server </b>
 *          In this mode, slpd functions  as a directory agent
 *	    for port 427 on the local machine. The directory agent
 *	    caches service advertisements, makes directory agent
 *	    advertisements of its services, and responds to requests
 *          for TCP connections with service agents and user agents.
 *	    In addition, slpd functions in the first mode, as a
 *	    service agent server, for SAs and UAs on the local host.
 *
 *   </ol>
 *
 * The slpd is invoked as follows:<br>
 *<blockquote>
 *
 *	java com.sun.slpd [monitor] [stop] [-f <config file name>]
 *
 *</blockquote>
 *
 * The optional monitor argument specifies that a GUI monitor should be
 * brought up. The optional stop argument indicates that slpd should
 * signal a running slpd to stop. The optional <config file name> argument
 * specifies that the named file should be used as the configuration file.
 * <p>
 * See <a href="slpd.conf.html">slpd.conf</a> for more information on
 * configuration file syntax and <a href="slpd.reg.html">slpd.reg</a>
 * for more information on proxy registration file syntax.
 *
 * @author Erik Guttman, James Kempf
 */

// Note that the inheritance is *only* so slpd can initialize the
// internals of SLP config.

public class slpd extends SLPConfig {

    private static final String SERVER_BUNDLE_NAME = "com/sun/slp/Server";

    // Server bundle. Set the parent.

    static class ServerBundle extends ResourceBundle {

	private ResourceBundle bundle = null;

	static ResourceBundle
	    getBundle(ResourceBundle parent, Locale locale)
	    throws MissingResourceException {

	    return new ServerBundle(parent, locale);

	}

	private ServerBundle(ResourceBundle parent, Locale locale)
	    throws MissingResourceException {

	    if (parent != null) {
		this.parent = parent;

	    }

	    try {
		URL[] urls = null;
		urls = new URL[] {new URL("file:/usr/share/lib/locale/")};
		URLClassLoader ld = new URLClassLoader(urls);

		bundle =
		    ResourceBundle.getBundle(SERVER_BUNDLE_NAME, locale, ld);

	    } catch (MalformedURLException e) {
		// fallthru to default location
	    }	// No locales in slpd.jar, so propagate the
		// MissingResourceException

	    bundle = bundle != null ?
		bundle :
		ResourceBundle.getBundle(SERVER_BUNDLE_NAME, locale);

	}

	protected Object handleGetObject(String key)
	    throws MissingResourceException {
	    Object ret = null;

	    try {

		ret = bundle.getObject(key);

	    } catch (MissingResourceException ex) {
		ret = parent.getObject(key);

	    }

	    return ret;

	}

	public Enumeration getKeys() {
	    return bundle.getKeys();

	}

    }

    /**
     * Log object for SLP to write to GUI. This class follows the
     * semantics of the other SLP logging classes:
     *
     * This class does not actually write anything until the flush() method
     * in invoked; this will write the concatenation of all messages
     * passed to the write() method since the last invocation of flush().
     *
     * The actual logging class used can be controlled via the
     * sun.net.slp.loggerClass property.
     *
     * See also the StderrLog and Syslog classes.
     */

    static class SLPLog extends Writer {

	private TextArea taLog = null;
	private StringBuffer buf;

	SLPLog(TextArea nta) {
	    taLog = nta;
	    buf = new StringBuffer();

	}

	// Write to the StringBuffer

	public void write(char[] cbuf, int off, int len)
	    throws IOException {
	    buf.append(cbuf, off, len);

	}

	// Write to the Frame.

	public void flush() throws IOException {
	    String date = SLPConfig.getDateString();

	    taLog.append(
			 "********" +
			 date + "\n" +
			 buf.toString() + "\n" +
			 "********\n");
	    buf = new StringBuffer();

	}

	// These is a no-op

	public void close() throws IOException {}

    }

    //
    // slpd definition.
    //

    private static String  configFile;		// name of configuration file
    private static SLPDgui slpdgui;		// GUI monitor, if desired
    private static SLPConfig config;		// handles system properties
    private static ServerDATable daTable;	// handle recording of DAs

    // Called by the slpd and subclasses only.

    protected slpd() {
	super();
    }

    private static void usage() {
	ResourceBundle bundle =
	    getMessageBundleInternal(Locale.getDefault(), null);
	System.err.println(formatMessageInternal("slpd_usage",
						 new Object[0],
						 bundle));
	System.exit(1);
    }

    /**
     * Usage: slpd [monitor] [stop] [-f config-file name]<br>
     * <br>
     * String arguments are:
     * <br>
     * <b> monitor </b> Puts up a rudimentary GUI for the slpd.<br>
     * <b>stop <b> Bring down a running slpd and exit.
     * <b> config-file name </b> Reads the specified configuration file.<br>
     *
     * The default running mode is to have no GUI and to use SLP
     * defined configuration.
     */

    public static void main(String args[]) {
	boolean bMon  = false;
	boolean bStop = false;
	configFile    = null;

	Thread.currentThread().setName("slpd");

	// Process args.

	if (args.length > 3) {
	    usage();

	}

	int i, n = args.length;

	for (i = 0; i < n; i++) {

	    // Argument is a config file.

	    if (args[i].equals("-f")) {

		if (configFile != null) {
		    usage();

		}

		// Make sure we can open it.

		try {
		    File f = new File(args[++i]);
		    configFile = args[i];

		} catch (Exception ex) {
		    usage();

		}
	    } else if (args[i].equals("monitor")) {
		bMon = true;

	    } else if (args[i].equals("stop")) {
		bStop = true;

	    } else {
		usage();

	    }
	}

	// Read message bundle file, load config file into properties.

	ResourceBundle bundle =
	    getMessageBundleInternal(Locale.getDefault(), null);

	try {
	    if (configFile != null) {
		Properties props = System.getProperties();
		props.setProperty("sun.net.slp.configURL",
				  "file:" + configFile);

	    }

	    // Create a new SLP Config object from the config file.
	    config = initializeSLPConfig();

	    // Create a GUI if the user asked for one.

	    if (bMon) {

		try {
		    slpdgui = new SLPDgui(configFile);
		    SLPLog log = new SLPLog(slpdgui.getTALog());

		    synchronized (config) {
			config.log = log;
		    }

		    slpdgui.setVisible(true);

		} catch (Exception ex) {
		    System.err.println(formatMessageInternal("slpd_no_gui",
							     new Object[0],
							     bundle));
		}
	    }

	    // Either start or stop the server, depending on what was
	    //  requested.

	    if (!bStop) {
		start();

	    } else {
		stop();

	    }
	} catch (ServiceLocationException ex) {

	    errorExit(bundle, ex);

	}

    }

    /**
     * Start the slpd.
     *
     * @param bMon	True if initializing with GUI monitor.
     * @exception ServiceLocationException Internal error or network
     *			initialization error or
     *			internal networking error.
     *
     */

    static void start() throws ServiceLocationException {

	// Initialize the service table.

	ServiceTable table = ServiceTable.getServiceTable();

	// Initialize the class name for the DA table to the Sun-specific
	//  DA table.

	Properties props = System.getProperties();
	props.put(DATable.DA_TABLE_CLASS_PROP, "com.sun.slp.SunServerDATable");

	// If there is a request on stdin, process it now
	try {
	    if (System.in.available() > 0) {
		RequestHandler rh =
		    new RequestHandler(System.in, System.out, config);
		rh.start();
	    }
	} catch (IOException e) {}

	// Start a StreamListener on loopback to start accepting locals regs

	StreamListener.initializeStreamListenerOnInterface(
							config.getLoopback());

	// Create a ServerDATable from the class. This will initialize
	//  active discovery. Note that we need to record our own presence
	//  in the DA table because we are not yet listening for requests.
	//  We do this after deserialization so that if we discover any
	//  DAs, we can perform registrations of the serialized advertisements.

	daTable = ServerDATable.getServerDATable();

	// Deserialize any serialized advertisements and do them now.
	//  Waiting until here allows any error messages to appear in
	//  the GUI log, if any, and at this point the DA table is ready.

	table.deserializeTable();

	// Need to create datagram and stream listeners, and a
	//  DAAdvertiser on all network interfaces.

	Vector interfaces = config.getInterfaces();
	int i, n = interfaces.size();

	for (i = 0; i < n; i++) {
	    InetAddress interfac = (InetAddress)interfaces.elementAt(i);

	    // Initialize the complex of listener/sender objects on the
	    // interface. This includes a datagram listener, a DAAdvertiser
	    // (which shares the same socket as the datagram listener), and
	    // a stream listener.

	    Listener.initializeInterfaceManagers(interfac);

	}

	// If we've been configured as a DA, then create a DA advertiser to
	//  periodically advertise our presence on this interface. This
	//  is only done on the default interface.

	if (config.isDA()) {
	    DAAdvertiser.initializeDAAdvertiserOnInterface(
							config.getLocalHost());

	}

	// Report scopes and whether DA or SA.

	Vector discoveredScopes = daTable.findScopes();
	Vector serverScopes = config.getSAConfiguredScopes();
	Vector daAttributes = config.getDAAttributes();
	Vector saAttributes = config.getSAAttributes();

	// Report that we are running if tracing is on

	if (config.regTest() ||
	    config.traceMsg() ||
	    config.traceDrop() ||
	    config.traceDATraffic()) {

	    config.writeLog((config.isDA() ? "hello_da":"hello"),
			    new Object[] {interfaces,
					      serverScopes,
					      discoveredScopes,
					      (config.isDA() ?
					       daAttributes:saAttributes)});
	}

	// If V1 is supported, crank up V1 support as well.

	if (config.isV1Supported()) {
	    SLPV1Manager.start(config, daTable, table);

	}
    }

    // Stop a running server by sending a DAAdvert or SAAdvert.

    static void stop() throws ServiceLocationException {

	if (daemonIsDA()) {
	    stopDA();

	} else {
	    stopSA();

	}
    }

    // Determine whether the daemon running on this machine is a DA
    //  or not.

    static boolean daemonIsDA() throws ServiceLocationException {

	// Get a DA table with available DAs.

	DATable table =
	    DATable.getDATable();

	// Get DAs.

	Hashtable das =
	    table.findDAScopes(config.getSAConfiguredScopes());
	Vector daRecs = (Vector)das.get(DATable.UNICAST_KEY);
	Vector interfaces = config.getInterfaces();

	// If no DAs, then simply return.

	if (daRecs == null) {
	    return false;

	}

	// Find our address in the list, if it exists.

	int i, n = daRecs.size();

	for (i = 0; i < n; i++) {
	    DATable.DARecord rec =
		(DATable.DARecord)daRecs.elementAt(i);
	    Vector daAddresses = rec.daAddresses;

	    int j, m = interfaces.size();

	    for (j = 0; j < m; j++) {
		if (daAddresses.contains(interfaces.elementAt(i))) {
		    return true;

		}
	    }
	}

	return false;
    }

    // Stop a DA by multicasting the DAAdvert with boot timestamp 0.

    private static void stopDA() throws ServiceLocationException {

	// Make the DA URL and the DAAdvert. Note that we only need signal
	//  on the default local host interface because that is the only
	//  one on which the server is listening.

	ServiceURL url =
	    new ServiceURL(Defaults.DA_SERVICE_TYPE +
			   "://" +
			   config.getLocalHost().getHostAddress(),
			   ServiceURL.LIFETIME_DEFAULT);

	SDAAdvert advert =
	    new SDAAdvert(new SLPServerHeaderV2(),
			  (short)0x0,  // sez we're unsolicited...
			  0L,    // sez we're going down...
			  url,
			  config.getSAConfiguredScopes(),
			  new Vector()); // no attributes needed to go down...

	// Make the DAAdvertiser.

	DAAdvertiser daadv = new DAAdvertiser(config.getLocalHost(),
					      advert.getHeader());

	// Send out unsolicted "going down" message.

	daadv.sendAdvert();

	// That's it! No need for any messages here.

	System.exit(0);

    }

    // Stop an SA server by unicasting an SA advert with xid 0.

    private static void stopSA() throws ServiceLocationException {

	// We signal for stop on the local host, which is guaranteed
	//  to have an SA listener.

	ServiceURL url =
	    new ServiceURL(Defaults.SA_SERVICE_TYPE + "://" +
			   config.getLocalHost().getHostAddress(),
			   ServiceURL.LIFETIME_DEFAULT);

	SSAAdvert advert = new SSAAdvert(Defaults.version,
					 (short)0x0, // sez we're going down...
					 config.getLocale(),
					 url,
					 config.getSAConfiguredScopes(),
					 new Vector());
						// don't care about attrs..,

	// Send it TCP. We ignore NETWORK_ERROR because it only means
	//  that the daemon didn't send us a reply, which is expected.

	try {

	    SrvLocMsg msg =
		Transact.transactTCPMsg(config.getLoopback(), advert, false);

	    if (msg.getErrorCode() != ServiceLocationException.OK) {
		config.writeLog("slpd_sa_stop_failure",
				new Object[] {
		    Integer.valueOf(msg.getErrorCode())});

	    }

	} catch (ServiceLocationException ex) {

	    if (ex.getErrorCode() != ServiceLocationException.NETWORK_ERROR) {
		config.writeLog("slpd_sa_stop_failure",
			new Object[] {Integer.valueOf(ex.getErrorCode())});

	    }

	}

	// That's it!

	System.exit(0);
    }

    // Print error message, exit.

    static void errorExit(ResourceBundle bundle, ServiceLocationException ex) {

	switch (ex.getErrorCode()) {

	case ServiceLocationException.INTERNAL_SYSTEM_ERROR:
	    System.err.println(formatMessageInternal("slpd_int_err",
						     new Object[] {
		ex.getMessage()},
		bundle));
	    break;

	case ServiceLocationException.NETWORK_INIT_FAILED:
	    System.err.println(formatMessageInternal("slpd_intnet_err",
						     new Object[] {
		ex.getMessage()},
		bundle));
	    break;

	case ServiceLocationException.NETWORK_ERROR:
	    System.err.println(formatMessageInternal("slpd_net_err",
						     new Object[] {
		ex.getMessage()},
		bundle));
	    break;

	default:
	    System.err.println(formatMessageInternal("slpd_err",
						     new Object[] {
		Integer.valueOf(ex.getErrorCode()),
		    ex.getMessage()},
		bundle));

	}

	ex.printStackTrace();
	System.err.println(formatMessageInternal("exiting_msg",
						 new Object[0],
						 bundle));

	System.exit(1);

    }

    // Make a new SLPConfig object of the right class type.

    private static SLPConfig initializeSLPConfig() {

	// The server *always* runs as an SA. It may also run as a DA.

	config.isSA = true;

	// set default logging class for slpd to syslog

	if (System.getProperty("sun.net.slp.loggerClass") == null) {
	    Properties props = System.getProperties();
	    props.setProperty("sun.net.slp.loggerClass", "com.sun.slp.Syslog");
	    System.setProperties(props);

	}

	// slpd is the server side config.

	theSLPConfig = new slpd();

	return theSLPConfig;

    }

    //
    // Extensions to sldp for server side only.
    //

    boolean isDA() {
	return Boolean.getBoolean("net.slp.isDA");
    }

    // Determine whether V1 is supported. Default is no.

    boolean isV1Supported() {

	if (!isDA() || super.getSLPv1NotSupported()) {
	    return false;

	}

	boolean v1Supported = false;

	try {

	    Class.forName("com.sun.slp.SLPV1Manager");
	    v1Supported = true;

	} catch (ClassNotFoundException ex) {

	    // Not there.

	}

	return v1Supported;

    }

    // Load server message bundle.

    private static final String serverMsgBundle = "Server";

    ResourceBundle getMessageBundle(Locale locale) {

	// Get the parent bundle first.

	ResourceBundle parentBundle = super.getMessageBundle(locale);

	return getMessageBundleInternal(locale, parentBundle);

    }

    // We need this in case we get an error before the config object is
    //  created.

    static private ResourceBundle getMessageBundleInternal(
						Locale locale,
						ResourceBundle parentBundle) {

	// Now create a server subclass.

	ResourceBundle msgBundle = null;

	try {
	    msgBundle = ServerBundle.getBundle(parentBundle, locale);

	} catch (MissingResourceException ex) {  // can't localize this one!

	    // We can't print out to the log, because we may be in the
	    //  process of trying to.

	    System.out.println("Missing resource bundle ``"+
			       SERVER_BUNDLE_NAME+
			       "'' for locale ``"+
			       locale+
			       "''");
	    // Hosed if the default locale is missing.

	    if (locale.equals(Defaults.locale)) {

		System.out.println("Exiting...");
		System.exit(1);
	    }

	    // Otherwise, return the default locale.

	    System.out.println("Using SLP default locale ``" +
			       Defaults.locale+"''");

	    msgBundle =
		getMessageBundleInternal(Defaults.locale, parentBundle);

	}

	return msgBundle;
    }

}
