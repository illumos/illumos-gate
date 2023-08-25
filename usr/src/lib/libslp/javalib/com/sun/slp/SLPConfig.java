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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

//  SLPConfig.java
//

/**
 * This class is a singleton - it has the configuration which
 * is the default.  It reads from a configuration file and
 * this overrides the default.  If the config file does not
 * expressly forbid it, the ServiceLocationManager interface
 * allows some of these configuration options to be modified.
 * This configuration is refered to by many points of the
 * implementation. Note that the class itself is abstract,
 * and is extended by two classes, one that allows slpd to
 * run as an SA server only, the other allows it to run
 * as a DA as well.
 *
 * @see com.sun.slp.ServiceLocationManager
 */

package com.sun.slp;

import java.net.*;
import java.util.*;
import java.text.*;
import java.io.*;

/*
 * This class contains all configuration information.  It
 * is hard coded to know the defaults, and will read a config
 * file if it is present.  The config file will override the
 * default values and policy.  If the config file allows it
 * the user may reset some of these values using the
 * ServiceLocationManager interface.
 *
 */
class SLPConfig {

    /**
     * A Java properties file defines `\' as an escape character, which
     * conflicts with the SLP API escape convention. Therefore, we need
     * to subclass properties so we can parse in the file ourselves.
     */

    public static class SLPProperties extends Properties {

	SLPProperties(Properties p) {
	    super(p);

	}

	// Parse the SLP properties file ourselves. Groan! We don't recognize
	//  backslash as an escape.

	public synchronized void load(InputStream in) throws IOException {

	    BufferedReader rd = new BufferedReader(new InputStreamReader(in));

	    while (rd.ready()) {
		String ln = rd.readLine();

		// Throw out anything that begins with '#' or ';'.

		if (ln.startsWith("#") ||
		    ln.startsWith(";") ||
		    ln.length() <= 0) {
		    continue;

		}

		// Parse out equals sign, if any. Note that we trim any
		//  white space preceding or following data strings.
		//  Although the grammar doesn't allow it, users may
		//  enter blanks in their configuration files.
		// NOTE:  White space is not allowed in the data of
		//  property tag or values.  If included, according
		//  to RFC 2614, Section 2.1 these MUST be escaped,
		//  ie. space would be represented with '\20'.
		//  Therefore, it is *completely* safe to perform
		//  these trim()s.  They will catch errors resulting
		//  from sloppy data entry in slp.conf files and
		//  never corrupt or alter correctly formatted
		//  properties.

		SLPTokenizer tk = new SLPTokenizer(ln, "=");

		if (!tk.hasMoreTokens()) {// empty line...
		    continue;

		}

		String prop = tk.nextToken().trim();

		if (prop.trim().length() <= 0) {// line has just spaces...
		    continue;

		}

		if (!tk.hasMoreTokens()) {// line has no definition...
		    continue;

		}

		// Register the property.
		String def = tk.nextToken().trim();
		this.setProperty(prop, def);
	    }
	}

    }

    protected SLPConfig() {

	// Create a temporary, default log to report any errors during
	//  configuration.
	log = new StderrLog();

	// Initialize properties. Properties on command line override config
	//  file properties, and both override defaults.

	Properties sysProps = (Properties)(System.getProperties().clone());

	// Load Defalts.

	try {
	    Class.forName("com.sun.slp.Defaults");

	} catch (ClassNotFoundException ex) {

	    Assert.printMessageAndDie(this,
				      "no_class",
				      new Object[] {"com.sun.slp.Defaults"});
	}

	// System properties now contain Defaults
	Properties defaultProps = System.getProperties();

	// Load config file.

	SLPProperties slpProps = new SLPProperties(new Properties());
	try {
	    InputStream fis = getConfigURLStream();
	    if (fis != null) {
		slpProps.load(fis);
		System.setProperties(slpProps);
	    }

	} catch (IOException ex) {
	    writeLog("unparsable_config_file",
		     new Object[] {ex.getMessage()});
	}

	// Add config properties to Defaults, overwritting any pre-existing
	//  entries
	defaultProps.putAll(slpProps);

	// Now add in system props, overwritting any pre-existing entries
	defaultProps.putAll(sysProps);

	System.setProperties(defaultProps);


	// Initialize useScopes property. This is read-only after the file
	//  has been loaded.

	configuredScopes = initializeScopes("net.slp.useScopes");
	saConfiguredScopes = (Vector)configuredScopes.clone();

	// Add default scope to scopes for SA.

	if (saConfiguredScopes.size() <= 0) {
	    saConfiguredScopes.addElement(Defaults.DEFAULT_SCOPE);

	}

	// Initialize SA scopes. This uses a Sun specific property for
	//  scopes only used by the SA and adds in the DA scopes.

	saOnlyScopes = initializeScopes(DATable.SA_ONLY_SCOPES_PROP);

	// Initialized preconfigured DAs.

	preconfiguredDAs = initializePreconfiguredDAs();

	// Initialize broadcast flag.

	broadcastOnly = Boolean.getBoolean("net.slp.isBroadcastOnly");

	// Initialize logging. Default is stderr, first check for alternate.

	String failed = null;

	try {
	    String loggerClassName =
		System.getProperty("sun.net.slp.loggerClass");
	    if (loggerClassName != null) {
		Class loggerClass = Class.forName(loggerClassName);
		// Protect against disastrous pilot error, such as trying
		// to use com.sun.slp.SLPConfig as the log class
		// (causes stack recursion)
		if (Class.forName("java.io.Writer").isAssignableFrom(
							loggerClass)) {
		    Object logger = loggerClass.newInstance();
		    log = (Writer) logger;
		} else {
		    failed = formatMessage(
					   "bad_log_class",
					   new Object[] {
			loggerClass.toString()}) + "\n";
		}
	    }

	} catch (Throwable ex) {
	    log = null;
	    failed = formatMessage(
				   "bad_log",
				   new Object[] {
		ex.toString()}) + "\n";
	}

	// If no alternate log, revert to minimal default
	if (log == null) {
	    log = new StderrLog();

	    // If the alternate log failed, log it through the default log
	    if (failed != null) {
		try {
		    synchronized (log) {
			log.write(failed);
			log.flush();
		    }
		} catch (IOException giveUp) {}
	    }
	}

    }

    private InputStream getConfigURLStream() {

	// Open a URL onto the configuration file.

	String conf = System.getProperty("sun.net.slp.configURL");

	if (conf == null) {
	    conf = Defaults.SOLARIS_CONF;

	}

	InputStream str = null;

	try {

	    URL confURL = new URL(conf);

	    str = confURL.openStream();

	} catch (MalformedURLException ex) {
	    writeLog("url_malformed",
		     new Object[] {conf});

	} catch (IOException ex) {
	    if (conf != Defaults.SOLARIS_CONF) {
		// don't complain if we can't find our own default
		writeLog("unparsable_config_file",
			 new Object[] {ex.getMessage()});
	    }

	}

	return str;
    }

    // ------------------------------------------------------------
    // Property manipulation functions
    //

    private boolean OKBound(int i, int lb, int ub) {
	if (i < lb || i > ub)
	    return false;
	else
	    return true;
    }

    int getIntProperty(String prop, int df, int lb, int ub) {

	int i = Integer.getInteger(prop, df).intValue();

	if (OKBound(i, lb, ub)) {
	    return i;

	} else {
	    writeLog("bad_prop_tag", new Object[] {prop});

	    return df;
	}
    }

    // ------------------------------------------------------------
    // Multicast radius
    //
    private int iMinMCRadius = 1;   // link local scope
    private int iMaxMCRadius = 255; // universal scope

    int getMCRadius() {
	return getIntProperty("net.slp.multicastTTL",
			      Defaults.iMulticastRadius,
			      iMinMCRadius,
			      iMaxMCRadius);
    }

    // ------------------------------------------------------------
    // Heartbeat interval, seconds.
    //
    private final int iMinHeart = 2000;    // 10 minutes
    private final int iMaxHeart = 259200000; // 3 days

    int getAdvertHeartbeatTime() {
	return getIntProperty("net.slp.DAHeartBeat",
			      Defaults.iHeartbeat,
			      iMinHeart,
			      iMaxHeart);
    }

    // ------------------------------------------------------------
    // Active discovery interval, seconds.
    //

    private final int iMinDisc = 300;    // 5 minutes
    private final int iMaxDisc = 10800;  // 3 hours

    int getActiveDiscoveryInterval() {

	// We allow zero in order to turn active discovery off, but
	//  if 5 minutes is the smallest actual time.

	int prop = getIntProperty("net.slp.DAActiveDiscoveryInterval",
				  Defaults.iActiveDiscoveryInterval,
				  0,
				  iMaxDisc);
	if (prop > 0 && prop < iMinDisc) {
	    writeLog("bad_prop_tag",
		     new Object[] {"net.slp.DAActiveDiscoveryInterval"});
	    return iMinDisc;

	}

	return prop;
    }


    // ------------------------------------------------------------
    // Active discovery granularity, seconds.
    //

    private int iMaxDiscGran = iMaxDisc * 2;

    int getActiveDiscoveryGranularity() {
	return getIntProperty("sun.net.slp.DAActiveDiscoveryGranularity",
			      Defaults.iActiveDiscoveryGranularity,
			      0,
			      iMaxDiscGran);
    }

    // ------------------------------------------------------------
    // Bound for random wait, milliseconds.
    //

    private final int iMinWait = 1000;  // 1 sec.
    private final int iMaxWait = 3000;  // 3 sec.

    int getRandomWaitBound() {
	return getIntProperty("net.slp.randomWaitBound",
			      Defaults.iRandomWaitBound,
			      iMinWait,
			      iMaxWait);
    }

    private static Random randomWait = null;

    long getRandomWait() {

	if (randomWait == null) {
	    randomWait = new Random();
	}

	double r = randomWait.nextDouble();
	double max = (double)getRandomWaitBound();

	return (long)(max * r);
    }

    // ------------------------------------------------------------
    // TCP timeout, milliseconds.
    //
    final static private int iMinTimeout = 100;
    final static private int iMaxTimeout = 360000;

    int getTCPTimeout() {
	return getIntProperty("sun.net.slp.TCPTimeout",
			      Defaults.iTCPTimeout,
			      iMinTimeout,
			      iMaxTimeout);
    }

    // ------------------------------------------------------------
    //  Path MTU
    //
    private final int iMinMTU = 128; // used for some ppp connections
    private final int iMaxMTU = 8192; // used on some LANs

    int getMTU() {
	return getIntProperty("net.slp.MTU",
			      Defaults.iMTU,
			      iMinMTU,
			      iMaxMTU);
    }


    // ------------------------------------------------------------
    // Serialized registrations.
    //

    String getSerializedRegURL() {

	return System.getProperty("net.slp.serializedRegURL", null);

    }

    // ------------------------------------------------------------
    // Are we running as a DA or SA server?
    //

    protected static boolean isSA = false;

    boolean isDA() {
	return false;
    }

    boolean isSA() {
	return isSA;
    }

    // ------------------------------------------------------------
    // DA and SA attributes
    //

    Vector getDAAttributes() {
	return getAttributes("net.slp.DAAttributes",
			     Defaults.defaultDAAttributes,
			     true);
    }

    Vector getSAAttributes() {
	return getAttributes("net.slp.SAAttributes",
			     Defaults.defaultSAAttributes,
			     false);
    }

    private Vector getAttributes(String prop,
				 Vector defaults,
				 boolean daAttrs) {
	String attrList =
	    System.getProperty(prop);

	if (attrList == null || attrList.length() <= 0) {
	    return (Vector)defaults.clone();

	}

	try {
	    Vector sAttrs =
		SrvLocHeader.parseCommaSeparatedListIn(attrList, false);

	    Vector attrs = new Vector();
	    int i, n = sAttrs.size();

	    // Create attribute objects.

	    for (i = 0; i < n; i++) {
		String attrExp = (String)sAttrs.elementAt(i);
		ServiceLocationAttribute attr =
		    new ServiceLocationAttribute(attrExp, false);

		// If this is the min-refresh-interval, then check the value.

		if (daAttrs &&
		    attr.getId().equals(
				Defaults.MIN_REFRESH_INTERVAL_ATTR_ID)) {
		    Vector values = attr.getValues();
		    boolean errorp = true;

		    if (values != null && values.size() == 1) {
			Object val = values.elementAt(0);

			if (val instanceof Integer) {
			    int ival = ((Integer)val).intValue();

			    if (ival >= 0 &&
				ival <= ServiceURL.LIFETIME_MAXIMUM) {
				errorp = false;

			    }
			}
		    }

		    // Throw exception if it didn't work.

		    if (errorp) {
			throw new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"syntax_error_prop",
				new Object[] {prop, attrs});

		    }
		}

		// Add attribute to vector.

		attrs.addElement(attr);

	    }

	    return attrs;

	} catch (Exception ex) {

	    writeLog("syntax_error_prop",
		     new Object[] {prop, attrList});
	    return (Vector)defaults.clone();

	}
    }

    // -------------------------------------------------------------
    // Do we support V1?
    //

    boolean isV1Supported() {
	return false;
    }

    // -------------------------------------------------------------
    // Queue length for server socket.
    //

    int getServerSocketQueueLength() {
	return getIntProperty("sun.net.slp.serverSocketQueueLength",
			      Defaults.iSocketQueueLength,
			      0,
			      Integer.MAX_VALUE);
    }

    // ------------------------------------------------------------
    // Testing options
    //


    boolean traceAll() {// not official!
	return Boolean.getBoolean("sun.net.slp.traceALL");
    }

    boolean regTest() {
	if (Boolean.getBoolean("sun.net.slp.traceALL") ||
	    Boolean.getBoolean("net.slp.traceReg"))
	    return true;
	else
	    return false;
    }

    boolean traceMsg() {
	if (Boolean.getBoolean("sun.net.slp.traceALL") ||
	    Boolean.getBoolean("net.slp.traceMsg"))
	    return true;
	else
	    return false;
    }

    boolean traceDrop() {
	if (Boolean.getBoolean("sun.net.slp.traceALL") ||
	    Boolean.getBoolean("net.slp.traceDrop"))
	    return true;
	else
	    return false;
    }

    boolean traceDATraffic() {
	if (Boolean.getBoolean("sun.net.slp.traceALL") ||
	    Boolean.getBoolean("net.slp.traceDATraffic"))
	    return true;
	else
	    return false;
    }

    // cannot use Boolean.getBoolean as the default is 'true'
    // using that mechanism, absense would be considered 'false'

    boolean passiveDADetection() {

	String sPassive =
	    System.getProperty("net.slp.passiveDADetection", "true");
	if (sPassive.equalsIgnoreCase("true"))
	    return true;
	else
	    return false;

    }

    // Initialized when the SLPConfig object is created to avoid changing
    //  during the program.
    private boolean broadcastOnly = false;

    boolean isBroadcastOnly() {
	return broadcastOnly;
    }


    // ------------------------------------------------------------
    // Multicast/broadcast socket mangement.
    //
    DatagramSocket broadSocket = null;   // cached broadcast socket.


    // Reopen the multicast/broadcast socket bound to the
    //  interface. If groups is not null, then join all
    //  the groups. Otherwise, this is send only.

    DatagramSocket
	refreshMulticastSocketOnInterface(InetAddress interfac,
					  Vector groups) {

	try {

	    // Reopen it.

	    DatagramSocket dss =
		getMulticastSocketOnInterface(interfac,
					      (groups == null ? true:false));

	    if ((groups != null) && (dss instanceof MulticastSocket)) {
		int i, n = groups.size();
		MulticastSocket mss = (MulticastSocket)dss;

		for (i = 0; i < n; i++) {
		    InetAddress maddr = (InetAddress)groups.elementAt(i);

		    mss.joinGroup(maddr);

		}
	    }

	    return dss;

	} catch (Exception ex) {

	    // Any exception in error recovery causes program to die.

	    Assert.slpassert(false,
			  "cast_socket_failure",
			  new Object[] {ex, ex.getMessage()});

	}

	return null;
    }

    // Open a multicast/broadcast socket on the interface. Note that if
    //  the socket is broadcast, the network interface is not specified in the
    //  creation message. Is it bound to all interfaces? The isSend parameter
    //  specifies whether the socket is for send only.

    DatagramSocket
	getMulticastSocketOnInterface(InetAddress interfac, boolean isSend)
	throws ServiceLocationException {

	DatagramSocket castSocket = null;

	// Substitute broadcast if we are configured for it.

	if (isBroadcastOnly()) {

	    try {

		// If transmit, then simply return a new socket.

		if (isSend) {
		    castSocket = new DatagramSocket();

		} else {

		    // Return cached socket if there.

		    if (broadSocket != null) {
			castSocket = broadSocket;

		    } else {

			// Make a new broadcast socket.

			castSocket =
			    new DatagramSocket(Defaults.iSLPPort,
					       getBroadcastAddress());

		    }

		    // Cache for future reference.

		    broadSocket = castSocket;
		}
	    } catch (SocketException ex) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.NETWORK_INIT_FAILED,
				"socket_creation_failure",
				new Object[] {
			getBroadcastAddress(), ex.getMessage()});
	    }

	} else {

	    // Create a multicast socket.

	    MulticastSocket ms;

	    try {

		if (isSend) {
		    ms = new MulticastSocket();

		} else {
		    ms = new MulticastSocket(Defaults.iSLPPort);

		}

	    } catch (IOException ex) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.NETWORK_INIT_FAILED,
				"socket_creation_failure",
				new Object[] {interfac, ex.getMessage()});
	    }


	    try {

		// Set the TTL and the interface on the multicast socket.
		//  Client is responsible for joining group.

		ms.setTimeToLive(getMCRadius());
		ms.setInterface(interfac);

	    } catch (IOException ex) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.NETWORK_INIT_FAILED,
				"socket_initializtion_failure",
				new Object[] {interfac, ex.getMessage()});
	    }

	    castSocket = ms;

	}

	return castSocket;
    }

    // ------------------------------------------------------------
    // Type hint
    //

    // Return a vector of ServiceType objects for the type hint.

    Vector getTypeHint() {
	Vector hint = new Vector();
	String sTypeList = System.getProperty("net.slp.typeHint", "");

	if (sTypeList.length() <= 0) {
	    return hint;

	}

	// Create a vector of ServiceType objects for the type hint.

	try {

	    hint = SrvLocHeader.parseCommaSeparatedListIn(sTypeList, true);

	    int i, n = hint.size();

	    for (i = 0; i < n; i++) {
		String type = (String)hint.elementAt(i);

		hint.setElementAt(new ServiceType(type), i);

	    }
	} catch (ServiceLocationException ex) {

	    writeLog("syntax_error_prop",
		     new Object[] {"net.slp.typeHint", sTypeList});

	    hint.removeAllElements();

	}

	return hint;

    }

    // ------------------------------------------------------------
    // Configured scope handling
    //

    // Vector of configured scopes.

    private Vector configuredScopes = null;

    // Vector of configures scopes for SA.

    private Vector saConfiguredScopes = null;

    // Vector of scopes only in the sa server.

    private Vector saOnlyScopes = null;

    // Return the configured scopes.

    Vector getConfiguredScopes() {
	return (Vector)configuredScopes.clone();
    }

    // Return SA scopes.

    Vector getSAOnlyScopes() {
	return (Vector)saOnlyScopes.clone();

    }

    // Return the configured scopes for the SA.

    Vector getSAConfiguredScopes() {
	return (Vector)saConfiguredScopes.clone();

    }

    // Add scopes discovered during preconfigured DA contact.
    //  These count as configured scopes.

    void addPreconfiguredDAScopes(Vector scopes) {

	int i, n = scopes.size();

	for (i = 0; i < n; i++) {
	    Object scope = scopes.elementAt(i);

	    if (!configuredScopes.contains(scope)) {
		configuredScopes.addElement(scope);

	    }

	    // There better be none extra here for the SA server/DA.

	    if (isSA() || isDA()) {
		Assert.slpassert(saConfiguredScopes.contains(scope),
			      "sa_new_scope",
			      new Object[] {scope, saConfiguredScopes});

	    }
	}
    }

    // Initialize the scopes list on property.

    private Vector initializeScopes(String prop) {

	String sScopes = System.getProperty(prop);

	if (sScopes == null || sScopes.length() <= 0) {
	    return new Vector();
	}

	try {

	    Vector vv =
		SrvLocHeader.parseCommaSeparatedListIn(sScopes, true);

	    // Unescape scope strings.

	    SLPHeaderV2.unescapeScopeStrings(vv);

	    // Validate, lower case scope names.

	    DATable.validateScopes(vv, getLocale());

	    if (vv.size() > 0) {
		return vv;
	    }

	} catch (ServiceLocationException ex) {
	    writeLog("syntax_error_prop",
		     new Object[] {
		prop,
		    sScopes});


	}

	return new Vector();
    }

    // Vector of preconfigured DAs. Read only after initialized.

    private Vector preconfiguredDAs = null;

    // Return a vector of DA addresses.

    Vector getPreconfiguredDAs() {
	return (Vector)preconfiguredDAs.clone();

    }

    // Initialize preconfigured DA list.

    private Vector initializePreconfiguredDAs() {
	String sDAList = System.getProperty("net.slp.DAAddresses", "");
	Vector ret = new Vector();

	sDAList.trim();

	if (sDAList.length() <= 0) {
	    return ret;

	}

	try {

	    ret = SrvLocHeader.parseCommaSeparatedListIn(sDAList, true);

	} catch (ServiceLocationException ex) {

	    writeLog("syntax_error_prop",
		     new Object[] {"net.slp.DAAddress", sDAList});

	    return ret;

	}

	// Convert to InetAddress objects.

	int i;

	for (i = 0; i < ret.size(); i++) {
	    String da = "";

	    try {
		da = ((String)ret.elementAt(i)).trim();
		InetAddress daAddr = InetAddress.getByName(da);

		ret.setElementAt(daAddr, i);

	    } catch (UnknownHostException ex) {

		writeLog("resolve_failed",
			 new Object[] {da});

		/*
		 *  Must decrement the index 'i' otherwise the next iteration
		 *  around the loop will miss the element immediately after
		 *  the element removed.
		 *
		 *  WARNING: Do not use 'i' again until the loop has
		 *           iterated as it may, after decrementing,
		 *           be negative.
		 */
		ret.removeElementAt(i);
		i--;
		continue;
	    }
	}


	return ret;
    }

    // ------------------------------------------------------------
    // SLPv1 Support Switches
    //

    boolean getSLPv1NotSupported() {// not official!
	return Boolean.getBoolean("sun.net.slp.SLPv1NotSupported");

    }

    boolean getAcceptSLPv1UnscopedRegs() {// not official!

	if (!getSLPv1NotSupported()) {
	    return Boolean.getBoolean("sun.net.slp.acceptSLPv1UnscopedRegs");

	}

	return false;
    }

    // ------------------------------------------------------------
    // Accessor for SLPConfig object
    //

    protected static SLPConfig theSLPConfig = null;

    static SLPConfig getSLPConfig() {

	if (theSLPConfig == null) {
	    theSLPConfig = new SLPConfig();
	}

	return theSLPConfig;

    }

    /**
     * @return Maximum number of messages/objects to return.
     */

    int getMaximumResults()  {
	int i = Integer.getInteger("net.slp.maxResults",
				   Defaults.iMaximumResults).intValue();
	if (i == -1) {
	    i = Integer.MAX_VALUE;

	}

	if (OKBound(i, 1, Integer.MAX_VALUE)) {
	    return i;

	} else {

	    writeLog("bad_prop_tag",
		     new Object[] {
		"net.slp.maxResults"});

	    return Defaults.iMaximumResults;

	}
    }

    /**
     * Convert a language tag into a locale.
     */

    static Locale langTagToLocale(String ltag) {

	// We treat the first part as the ISO 639 language and the
	// second part as the ISO 3166 country tag, even though RFC
	// 1766 doesn't necessarily require that. We should probably
	// use a lookup table here to determine if they are correct.

	StringTokenizer tk = new StringTokenizer(ltag, "-");
	String lang = "";
	String country = "";

	if (tk.hasMoreTokens()) {
	    lang = tk.nextToken();

	    if (tk.hasMoreTokens()) {
		country = tk.nextToken("");
					// country name may have "-" in it...

	    }
	}

	return new Locale(lang, country);
    }

    /**
     * Convert a Locale object into a language tag for output.
     *
     * @param locale The Locale.
     * @return String with the language tag encoded.
     */

    static String localeToLangTag(Locale locale) {

	// Construct the language tag.

	String ltag = locale.getCountry();
	ltag = locale.getLanguage() + (ltag.length() <= 0 ? "" : ("-" + ltag));

	return ltag;

    }

    /**
     * @return the language requests will be made in.
     */
    static Locale  getLocale()    {
	String s = System.getProperty("net.slp.locale");

	if (s != null && s.length() > 0) {
	    return langTagToLocale(s);

	} else {

	    // Return the Java default if the SLP property is not set.

	    return Locale.getDefault();

	}
    }

    /**
     * @return the InetAddress of the broadcast interface.
     */

    static private InetAddress broadcastAddress;

    static InetAddress getBroadcastAddress() {
	if (broadcastAddress == null) {

	    try {
		broadcastAddress =
		    InetAddress.getByName(Defaults.sBroadcast);
	    } catch (UnknownHostException uhe) {

		Assert.slpassert(false,
			      "cast_address_failure",
			      new Object[] {Defaults.sBroadcast});

	    }
	}
	return broadcastAddress;
    }


    /**
     * @return the InetAddress of the multicast group.
     */

    static private InetAddress multicastAddress;

    static InetAddress getMulticastAddress() {
	if (multicastAddress == null) {

	    try {
		multicastAddress =
		    InetAddress.getByName(Defaults.sGeneralSLPMCAddress);
	    } catch (UnknownHostException uhe) {
		Assert.slpassert(false,
			      "cast_address_failure",
			      new Object[] {Defaults.sGeneralSLPMCAddress});

	    }
	}
	return multicastAddress;
    }

    /**
     * @return the interfaces on which SLP should listen and transmit.
     */

    private static Vector interfaces = null;

    Vector getInterfaces() {

	if (interfaces == null) {
	    InetAddress iaLocal = null;

	    // Get local host.

	    try {
		iaLocal =  InetAddress.getLocalHost();

	    }  catch (UnknownHostException ex) {
		Assert.slpassert(false,
			      "resolve_failed",
			      new Object[] {"localhost"});
	    }

	    String mcastI = System.getProperty("net.slp.interfaces");
	    interfaces = new Vector();

	    // Only add local host if nothing else is given.

	    if (mcastI == null || mcastI.length() <= 0) {
		interfaces.addElement(iaLocal);
		return interfaces;

	    }

	    Vector nintr;

	    try {

		nintr = SrvLocHeader.parseCommaSeparatedListIn(mcastI, true);

	    } catch (ServiceLocationException ex) {
		writeLog("syntax_error_prop",
			 new Object[] {
		    "net.slp.multicastInterfaces",
			mcastI});

		// Add local host.

		interfaces.addElement(iaLocal);

		return interfaces;

	    }

	    // See if they are really there.

	    int i, n = nintr.size();

	    for (i = 0; i < n; i++) {
		InetAddress ia;
		String host = (String)nintr.elementAt(i);

		try {

		    ia = InetAddress.getByName(host);

		} catch (UnknownHostException ex) {
		    writeLog("unknown_interface",
			     new Object[] {host,
					       "net.slp.multicastInterfaces"});
		    continue;

		}

		if (!interfaces.contains(ia)) {

		    // Add default at beginning.

		    if (ia.equals(iaLocal)) {
			interfaces.insertElementAt(ia, 0);

		    } else {
			interfaces.addElement(ia);

		    }
		}
	    }
	}

	return interfaces;

    }

    /**
     * @return An InetAddress object representing 127.0.0.1
     */
    InetAddress getLoopback() {
	InetAddress iaLoopback = null;

	try {
	    iaLoopback = InetAddress.getByName(Defaults.LOOPBACK_ADDRESS);

	}  catch (UnknownHostException ex) {
	    Assert.slpassert(false,
			  "resolve_failed",
			  new Object[] {"localhost loopback"});
	}

	return iaLoopback;
    }

    /**
     * @return The default interface, which should be the first in the
     *         interfaces vector Vector.
     */

    InetAddress getLocalHost() {
	Vector inter = getInterfaces();
	return (InetAddress)inter.elementAt(0);

    }

    // Return true if the address is one of the local interfaces.

    boolean isLocalHostSource(InetAddress addr) {

	// First check loopback

	if (addr.equals(getLoopback())) {
	    return true;

	}

	return interfaces.contains(addr);

    }

    // -----------------
    // Timeouts
    //

    // Return the maximum wait for multicast convergence.

    final static private int iMultiMin = 1000;  // one second
    final static private int iMultiMax = 60000; // one minute

    int getMulticastMaximumWait() {

	return getIntProperty("net.slp.multicastMaximumWait",
			      Defaults.iMulticastMaxWait,
			      iMultiMin,
			      iMultiMax);
    }

    /*
     * @return Vector of timeouts for multicast convergence.
     */

    int[] getMulticastTimeouts() {
	int[] timeouts = parseTimeouts("net.slp.multicastTimeouts",
			     Defaults.a_iConvergeTimeout);

	timeouts = capTimeouts("net.slp.multicastTimeouts",
			       timeouts,
			       false,
			       0,
			       0);

	return timeouts;
    }

    /**
     * @return Vector of timeouts to try for datagram transmission.
     */

    int[] getDatagramTimeouts() {
	int[] timeouts = parseTimeouts("net.slp.datagramTimeouts",
			     Defaults.a_iDatagramTimeout);

	timeouts = capTimeouts("net.slp.datagramTimeouts",
			       timeouts,
			       true,
			       iMultiMin,
			       iMultiMax);

	return timeouts;
    }

    /**
     * @return Vector of timeouts for DA discovery multicast.
     */

    int[] getDADiscoveryTimeouts() {
	int[] timeouts = parseTimeouts("net.slp.DADiscoveryTimeouts",
			     Defaults.a_iDADiscoveryTimeout);

	timeouts = capTimeouts("net.slp.DADiscoveryTimeouts",
				timeouts,
				false,
				0,
				0);

	return timeouts;
    }

    /**
     *  This method ensures that all the timeouts are within valid ranges.
     *  The sum of all timeouts for the given property name must not
     *  exceed the value returned by <i>getMulticastMaximumWait()</i>. If
     *  the sum of all timeouts does exceed the maximum wait period the
     *  timeouts are averaged out so that the sum equals the maximum wait
     *  period.
     *	<br>
     *  Additional range checking is also performed when <i>rangeCheck</i>
     *  is true. Then the sum of all timeouts must also be between <i>min</i>
     *  and <i>max</i>. If the sum of all timeouts is not within the range
     *  the average is taken from the closest range boundary.
     *
     *  @param property
     *	    Name of timeout property being capped. This is only present for
     *	    reporting purposes and no actual manipulation of the property
     *      is made within this method.
     *  @param timeouts
     *      Array of timeout values.
     *  @param rangeCheck
     *      Indicator of whether additional range checking is required. When
     *      false <i>min</i> and <i>max</i> are ignored.
     *  @param min
     *      Additional range checking lower boundary.
     *  @param max
     *      Additional range checking upper boundary.
     *  @return
     *      Array of capped timeouts. Note this may be the same array as
     *      passed in (<i>timeouts</i>).
     */
    private int[] capTimeouts(String property,
			      int[] timeouts,
			      boolean rangeCheck,
			      int min,
			      int max) {

	int averagedTimeout;
	int totalWait = 0;

	for (int index = 0; index < timeouts.length; index++) {
	    totalWait += timeouts[index];
	}

	if (rangeCheck) {
	    // If sum of timeouts within limits then finished.
	    if (totalWait >= min && totalWait <= max) {
		return timeouts;
	    }

	    // Average out the timeouts so the sum is equal to the closest
	    // range boundary.
	    if (totalWait < min) {
		averagedTimeout = min / timeouts.length;
	    } else {
		averagedTimeout = max / timeouts.length;
	    }

	    writeLog("capped_range_timeout_prop",
		     new Object[] {property,
				   String.valueOf(totalWait),
				   String.valueOf(min),
				   String.valueOf(max),
				   String.valueOf(timeouts.length),
				   String.valueOf(averagedTimeout)});
	} else {
	    // Sum of all timeouts must not exceed this value.
	    int maximumWait = getMulticastMaximumWait();

	    // If sum of timeouts within limits then finished.
	    if (totalWait <= maximumWait) {
		return timeouts;
	    }

	    // Average out the timeouts so the sum is equal to the maximum
	    // timeout.
	    averagedTimeout = maximumWait / timeouts.length;

	    writeLog("capped_timeout_prop",
		     new Object[] {property,
				   String.valueOf(totalWait),
				   String.valueOf(maximumWait),
				   String.valueOf(timeouts.length),
				   String.valueOf(averagedTimeout)});
	}

	for (int index = 0; index < timeouts.length; index++) {
	    timeouts[index] = averagedTimeout;
	}

	return timeouts;
    }

    private int[] parseTimeouts(String property, int[] defaults) {

	String sTimeouts = System.getProperty(property);

	if (sTimeouts == null || sTimeouts.length() <= 0) {
	    return defaults;

	}

	Vector timeouts = null;

	try {
	    timeouts = SrvLocHeader.parseCommaSeparatedListIn(sTimeouts, true);

	} catch (ServiceLocationException ex) {
	    writeLog("syntax_error_prop",
		     new Object[] {property, sTimeouts});
	    return defaults;

	}

	int iCount = 0;
	int[] iTOs = new int[timeouts.size()];

	for (Enumeration en = timeouts.elements(); en.hasMoreElements(); ) {
	    String s1 = (String)en.nextElement();

	    try {
		iTOs[iCount] = Integer.parseInt(s1);

	    }	catch (NumberFormatException nfe) {
		writeLog("syntax_error_prop",
			 new Object[] {property, sTimeouts});
		return defaults;

	    }

	    if (iTOs[iCount] < 0) {
		writeLog("invalid_timeout_prop",
			 new Object[] {property, String.valueOf(iTOs[iCount])});
		return defaults;
	    }

	    iCount++;
	}

	return iTOs;
    }

    // -----------------------------
    // SLP Time Calculation
    //

    /**
     * Returns the number of seconds since 00:00 Universal Coordinated
     * Time, January 1, 1970.
     *
     * Java returns the number of milliseconds, so all the method does is
     * divide by 1000.
     *
     * This implementation still will have a problem when the Java time
     * values wraps, but there isn't much we can do now.
     */
    static long currentSLPTime() {
	return (System.currentTimeMillis() / 1000);
    }

    /* security */

    // Indicates whether security class is available.

    boolean getSecurityEnabled() {
	return securityEnabled;

    }

    private static boolean securityEnabled;

    // Indicates whether the securityEnabled property is true

    boolean getHasSecurity() {
	return securityEnabled &&
	    (new Boolean(System.getProperty("net.slp.securityEnabled",
					    "false")).booleanValue());
    }

    // I18N Support.

    private static final String BASE_BUNDLE_NAME = "com/sun/slp/ClientLib";

    ResourceBundle getMessageBundle(Locale locale) {

	ResourceBundle msgBundle = null;

	// First try the Solaris Java locale area

	try {
	    URL[] urls = new URL[] {new URL("file:/usr/share/lib/locale/")};

	    URLClassLoader ld = new URLClassLoader(urls);

	    msgBundle = ResourceBundle.getBundle(BASE_BUNDLE_NAME, locale, ld);

	    return msgBundle;
	} catch (MalformedURLException e) {	// shouldn't get here
	} catch (MissingResourceException ex) {
	    System.err.println("Missing resource bundle ``"+
			       "/usr/share/lib/locale/" + BASE_BUNDLE_NAME +
			       "'' for locale ``" +
			       locale + "''; trying default...");
	}

	try {
	    msgBundle = ResourceBundle.getBundle(BASE_BUNDLE_NAME, locale);

	} catch (MissingResourceException ex) {  // can't localize this one!

	    // We can't print out to the log, because we may be in the
	    //  process of trying to.

	    System.err.println("Missing resource bundle ``"+
			       BASE_BUNDLE_NAME+
			       "'' for locale ``"+
			       locale+
			       "''");
	    // Hosed if the default locale is missing.

	    if (locale.equals(Defaults.locale)) {

		System.err.println("Exiting...");
		System.exit(1);
	    }

	    // Otherwise, return the default locale.

	    System.err.println("Using SLP default locale ``" +
			       Defaults.locale +
			       "''");

	    msgBundle = getMessageBundle(Defaults.locale);

	}

	return msgBundle;
    }

    String formatMessage(String msgTag, Object[] params) {
	ResourceBundle bundle = getMessageBundle(getLocale());
	return formatMessageInternal(msgTag, params, bundle);

    }

    // MessageFormat is picky about types. Convert the params into strings.

    static void convertToString(Object[] params) {
	int i, n = params.length;

	for (i = 0; i < n; i++) {

	    if (params[i] != null) {
		params[i] = params[i].toString();

	    } else {
		params[i] = "<null>";

	    }
	}
    }

    static String
	formatMessageInternal(String msgTag,
			      Object[] params,
			      ResourceBundle bundle) {
	String pattern = "";

	try {
	    pattern = bundle.getString(msgTag);

	} catch (MissingResourceException ex) {

	    // Attempt to report error. Can't use Assert here because it
	    //  calls back into SLPConfig.
	    String msg = "Can''t find message ``{0}''''.";

	    try {
		pattern = bundle.getString("cant_find_resource");
		msg = MessageFormat.format(pattern, new Object[] {msgTag});

	    } catch (MissingResourceException exx) {

	    }

	    System.err.println(msg);
	    System.exit(-1);
	}

	convertToString(params);

	return MessageFormat.format(pattern, params);
    }

    // logging.

    // Protected so slpd can replace it.

    protected Writer log;

    // Synchronized so writes from multiple threads don't get interleaved.

    void writeLog(String msgTag, Object[] params) {

	// MessageFormat is picky about types. Convert the params into strings.

	convertToString(params);

	try {
	    synchronized (log) {
		log.write(formatMessage(msgTag, params));
		log.flush();
	    }
	} catch (IOException ex) {}
    }

    void writeLogLine(String msgTag, Object[] params) {

	try {
	    String pattern = getMessageBundle(getLocale()).getString(msgTag);

	    synchronized (log) {
		log.write(formatMessage(msgTag, params));
		log.write("\n");
		log.flush();
	    }
	} catch (IOException ex) {}

    }

    static String getDateString() {

	DateFormat df = DateFormat.getDateTimeInstance(DateFormat.DEFAULT,
						       DateFormat.DEFAULT,
						       getLocale());
	Calendar calendar = Calendar.getInstance(getLocale());
	return df.format(calendar.getTime());

    }


    // On load, check whether the signature class is available, and turn
    //  security off if not.

    static {

	securityEnabled = true;
	try {
	    Class c = Class.forName("com.sun.slp.AuthBlock");

	} catch (ClassNotFoundException e) {
	    securityEnabled = false;
	}
    }

}
