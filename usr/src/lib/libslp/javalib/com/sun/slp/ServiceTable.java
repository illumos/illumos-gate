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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

//  ServiceTable.java: Storage of all services.
//  Author:           James Kempf
//  Created On:       Fri Oct 10 14:23:25 1997
//  Last Modified By: James Kempf
//  Last Modified On: Thu Apr  1 10:33:46 1999
//  Update Count:     461
//

package com.sun.slp;

import java.util.*;
import java.io.*;
import java.security.*;
import java.net.*;

/**
 * The ServiceTable object records all service registrations. Note
 * that any exceptions internal to the service table are processed
 * and either returned as SrvRply objects or are reported.
 *
 * @author James Kempf
 */

class ServiceTable extends Object {

    // Key for SDAAdvert class.

    static final String SDAADVERT = "com.sun.slp.SDAAdvert";

    private static final String locationMsg = "Service table";

    //
    // Instance variables.
    //

    // The service store.

    protected ServiceStore store = null;

    //
    // Class variables.

    // System properties.

    static protected SLPConfig conf = null;

    // Singleton objects for the service tables.

    static protected ServiceTable table = null;

    // The ager thread.

    static protected AgerThread thrAger = null;

    // Time to sleep. Adjusted depending on incoming URLs.

    private static long sleepyTime = Defaults.lMaxSleepTime;

    //
    // Creation of singleton.
    //

    // Protected constructor.

    protected ServiceTable() {

	if (thrAger != null) {
	    return;

	}

	// Create the ager thread.

	thrAger = new AgerThread();

	// Set the priority low, so other things (like active discovery)
	//  take priority.

	thrAger.setPriority(Thread.MIN_PRIORITY);

	thrAger.start();

    }

    /**
     * Return an SA service store.
     *
     * @return The distinguished table object.
     */

    static ServiceTable getServiceTable()
	throws ServiceLocationException {

	if (conf == null) {
	    conf = SLPConfig.getSLPConfig();

	}

	if (table == null) {

	    table = createServiceTable();

	}

	return table;
    }

    /**
     * Return a service table object.
     *
     * @return The service table object.
     */

    private static ServiceTable createServiceTable()
	throws ServiceLocationException {

	ServiceTable table = new ServiceTable();

	table.store = ServiceStoreFactory.createServiceStore();

	return table;
    }

    //
    // Support for serializated registrations.
    //

    /**
     * If any serialized registrations are pending, then unserialize
     * and register.
     */

    public void deserializeTable() {

	// If there are any serialized registrations, then get
	//  them and perform registrations.

	String serializedURL = conf.getSerializedRegURL();

	if (serializedURL != null) {

	    ServiceStore serStore = getStoreFromURL(serializedURL);

	    if (serStore != null) {
		registerStore(serStore);
	    }
	}
    }

    /**
     * Serialize the table to the URL.
     *
     * @param URL String giving the URL to which the store should be
     * serialized.
     */

    void serializeServiceStore(String URL) {

	// Open an object output stream for the URL, serialize through
	//  the factory.

	try {

	    URL url = new URL(URL);
	    URLConnection urlConn = url.openConnection();
	    OutputStream os = urlConn.getOutputStream();
	    BufferedWriter di =
		new BufferedWriter(new OutputStreamWriter(os));

	    // Serialize the store.

	    ServiceStoreFactory.serialize(di, store);

	} catch (MalformedURLException ex) {

	    conf.writeLog("st_serialized_malform",
			  new Object[] {URL});

	} catch (UnsupportedEncodingException ex) {

	    conf.writeLog("st_unsupported_encoding",
			  new Object[] {URL});

	} catch (IOException ex) {

	    conf.writeLog("st_serialized_ioexception",
			  new Object[] {URL, ex});

	} catch (ServiceLocationException ex) {

	    conf.writeLog("st_serialized_sle",
			  new Object[] {URL, ex.getMessage()});

	}

    }

    // Read proxy registrations from the URL.

    private ServiceStore getStoreFromURL(String serializedURL) {

	ServiceStore serStore = null;

	// Open an object input stream for the URL, deserialize through
	//  the factory.

	try {

	    URL url = new URL(serializedURL);
	    InputStream is = url.openStream();
	    BufferedReader di = new BufferedReader(new InputStreamReader(is));

	    // Deserialize the objects.

	    serStore =
		ServiceStoreFactory.deserializeServiceStore(di);

	} catch (MalformedURLException ex) {

	    conf.writeLog("st_serialized_malform",
			  new Object[] {serializedURL});

	} catch (UnsupportedEncodingException ex) {

	    conf.writeLog("st_unsupported_encoding",
			  new Object[] {serializedURL});

	} catch (IOException ex) {

	    conf.writeLog("st_serialized_ioexception",
			  new Object[] {
		serializedURL,
		    ex.getMessage()});

	} catch (ServiceLocationException ex) {

	    conf.writeLog("st_serialized_sle",
			  new Object[] {
		serializedURL,
		    ex.getMessage()});

	}

	return serStore;
    }

    // Walk the table, performing actual registrations on all records.

    private void registerStore(ServiceStore serStore) {

	// Walk the table.

	Enumeration en = serStore.getServiceRecordsByScope(null);
	boolean hasURLSig = conf.getHasSecurity();
	boolean hasAttrSig = conf.getHasSecurity();
	PermSARegTable pregTable = 	SARequester.getPermSARegTable();

	while (en.hasMoreElements()) {
	    ServiceStore.ServiceRecord rec =
		(ServiceStore.ServiceRecord)en.nextElement();
	    ServiceURL surl = rec.getServiceURL();
	    Vector scopes = rec.getScopes();
	    Vector attrs = rec.getAttrList();
	    Locale locale = rec.getLocale();
	    Hashtable urlSig = null;
	    Hashtable attrSig = null;

	    // Note that we can't use the Advertiser to register here,
	    //  because we may not be listening yet for registrations.
	    //  We need to do this all by hand.

	    try {

		// Create a registration message for refreshing.

		CSrvReg creg = new CSrvReg(false,
					   locale,
					   surl,
					   scopes,
					   attrs,
					   null,
					   null);

		// We externalize to a server side message if authentication
		//  is needed. This creates the auth blocks for the scopes.
		//  Doing this in any other way is alot more complicated,
		//  although doing it this way seems kludgy.

		if (hasURLSig || hasAttrSig) {
		    ByteArrayOutputStream baos = new ByteArrayOutputStream();

		    creg.getHeader().externalize(baos, false, true);

		    ByteArrayInputStream bais =
			new ByteArrayInputStream(baos.toByteArray());
		    bais.read();	// pop off version and function code...
		    bais.read();
		    DataInputStream dis = new DataInputStream(bais);
		    SLPHeaderV2 hdr = new SLPHeaderV2();
		    hdr.parseHeader(SrvLocHeader.SrvReg, dis);
		    SSrvReg sreg = new SSrvReg(hdr, dis);

		    // Now we've got it, after much effort. Get the auths.

		    urlSig = sreg.URLSignature;
		    attrSig = sreg.attrSignature;

		}

		store.register(surl, attrs, scopes, locale, urlSig, attrSig);

		// Now we've got to put the registration into the
		//  PermSARegTable. Again, we do everything by hand
		//  because we can't use Advertiser.

		if (surl.getIsPermanent()) {
		    pregTable.reg(surl, creg);

		}

		// Report registration.

		if (conf.regTest()) {
		    conf.writeLog("st_reg_add",
				  new Object[] {
			locationMsg,
			    locale,
			    surl.getServiceType(),
			    surl,
			    attrs,
			    scopes});

		}
	    } catch (ServiceLocationException ex) {

		String msg = ex.getMessage();

		conf.writeLog("st_serialized_seex",
			      new Object[] {
		    Integer.valueOf(ex.getErrorCode()),
			surl,
			(msg == null ? "<no message>":msg)});

	    } catch (Exception ex) {

		String msg = ex.getMessage();

		conf.writeLog("st_serialized_seex",
			      new Object[] {
		    surl,
			(msg == null ? "<no message>":msg)});
	    }
	}
    }

    //
    // Record aging.
    //

    //
    // Run the thread that ages out records.
    //

    private class AgerThread extends Thread {

	public void run() {

	    setName("SLP Service Table Age-out");
	    long alarmTime = sleepyTime;  // when to wake up next
	    long wentToSleep = 0;	    // what time we went to bed

	    while (true) {

		try {

		    // Record when we went to sleep.

		    wentToSleep = System.currentTimeMillis();

		    // Sleep for the minimum amount of time needed before we
		    //  must wake up and check.

		    sleep(alarmTime);

		} catch (InterruptedException ie) {

		    // A new registration came in. Calculate how much time
		    //  remains until we would have woken up. If this is
		    //  less than the new sleepyTime, then we set the alarm
		    //  for this time. If it is more, then we set the alarm
		    //  for the new sleepyTime.

		    long remainingSleepTime =
			(wentToSleep + alarmTime) - System.currentTimeMillis();

		    remainingSleepTime =		// just in case...
			((remainingSleepTime <= 0) ? 0 : remainingSleepTime);

		    alarmTime = sleepyTime;

		    if (remainingSleepTime < alarmTime) {
			alarmTime = remainingSleepTime;

		    }

		    continue;  // we don't have to walk yet...

		}

		// Walk the table, get the new alarm and sleepy times.

		if (table != null) {
		    table.ageStore();

		    alarmTime = sleepyTime;

		}
	    }
	}

    }

    /**
     * Age the service store.
     */

    // this method cannot be private... due to compiler weakness
    void ageStore() {

	try {

	    // We synchronize in case somebody registers and tries to
	    //  change sleepy time.

	    synchronized (store) {
		Vector deleted = new Vector();

		sleepyTime = store.ageOut(deleted);

		// Track unregistered services.

		int i, n = deleted.size();

		for (i = 0; i < n; i++) {
		    ServiceStore.ServiceRecord rec =
			(ServiceStore.ServiceRecord)deleted.elementAt(i);
		    ServiceURL surl = rec.getServiceURL();

		    trackRegisteredServiceTypes(); // it's deleted...

		}

	    }

	} catch (RuntimeException ex) {

	    reportNonfatalException(ex, new Vector(), store);

	} catch (ServiceLocationException ex) {

	    reportNonfatalException(ex, new Vector(), store);

	}

    }

    //
    // SLP Service Table operations (register, deregister, etc.)
    //

    /**
     * Process the registration and record if no errors found.
     *
     * @param req Service registration request message.
     * @return SrvLocMsg A service registration acknowledgement.
     */

    SrvLocMsg register(SSrvReg req) {

	SrvLocHeader hdr = req.getHeader();
	Locale locale = hdr.locale;
	boolean fresh = hdr.fresh;
	Vector scopes = hdr.scopes;
	ServiceURL surl = req.URL;
	String serviceType = req.serviceType;
	Vector attrList = req.attrList;
	Hashtable urlSig = req.URLSignature;
	Hashtable attrSig = req.attrSignature;
	short errorCode =
	    (fresh ? ServiceLocationException.INVALID_REGISTRATION :
	    ServiceLocationException.INVALID_UPDATE);

	try {

	    // If a sig block came in, verify it.

	    if (urlSig != null) {

		AuthBlock.verifyAll(urlSig);
	    }

	    if (attrSig != null) {

		AuthBlock.verifyAll(attrSig);

	    }

	    // Check whether the URL has a zero lifetime. If so, it
	    // isn't cached.

	    if (surl.getLifetime() <= 0) {
		throw
		    new ServiceLocationException(errorCode,
						 "st_zero",
						 new Object[0]);

	    }

	    // Check if the service type is restricted. If so, nobody outside
	    //  this process is allowed to register it.

	    checkForRestrictedType(surl.getServiceType());

	    // Check that attribute signature bit on implies URL signature
	    //  bit on.

	    if (attrSig != null && urlSig == null) {
		throw
		    new ServiceLocationException(errorCode,
						 "st_attr_sig",
						 new Object[0]);

	    }

	    // If a signature and the fresh bit was not set, error since signed
	    //  registrations don't allow updating.

	    if (urlSig != null && !fresh) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.INVALID_UPDATE,
				"st_prot_update",
				new Object[0]);
	    }

	    // Check if scopes are supported.

	    if (!areSupportedScopes(scopes)) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.SCOPE_NOT_SUPPORTED,
				"st_scope_unsup",
				new Object[0]);
	    }

	    // Check if the reg is signed and auth is off or vice versa.
	    //  Check is really simple. If security is on, then all regs
	    //  to this DA/SA server must be signed, so toss out any regs
	    //  that aren't, and vice versa.

	    if (conf.getHasSecurity() && (urlSig == null || attrSig == null)) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.AUTHENTICATION_FAILED,
				"st_unprot_non_reg",
				new Object[0]);

	    } else if (!conf.getHasSecurity() &&
		       (urlSig != null || attrSig != null)) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.INVALID_REGISTRATION,
				"st_prot_non_reg",
				new Object[0]);

	    }

	    // Merge any duplicates.

	    Vector attrs = new Vector();
	    Hashtable attrHash = new Hashtable();
	    int i, n = attrList.size();

	    for (i = 0; i < n; i++) {
		ServiceLocationAttribute attr =
		    (ServiceLocationAttribute)attrList.elementAt(i);

		ServiceLocationAttribute.mergeDuplicateAttributes(
								  attr,
								  attrHash,
								  attrs,
								  false);
	    }

	    // Store register or update.

	    boolean existing = false;

	    if (fresh) {
		existing = store.register(surl,
					  attrs,
					  scopes,
					  locale,
					  urlSig,
					  attrSig);

		// Track registred service types in case we get a
		// SAAdvert solicatation.

		trackRegisteredServiceTypes();

	    } else {
		store.updateRegistration(surl, attrs, scopes, locale);

	    }

	    // Create the reply.

	    SrvLocMsg ack = req.makeReply(existing);

	    if (conf.regTest()) {
		conf.writeLog((fresh ? "st_reg_add":"st_reg_update"),
			      new Object[] {
		    locationMsg,
			locale,
			serviceType,
			surl,
			attrs,
			scopes});

	    }

	    if (conf.traceAll()) {
		conf.writeLog("st_dump", new Object[] {locationMsg});
		store.dumpServiceStore();

	    }

	    // Calculate time increment until next update. This is used
	    //  to adjust the sleep interval in the ager thread.

	    long sTime = getSleepIncrement(surl);

	    // We synchronize in case the ager thread is in the middle
	    //  of trying to set the time.

	    synchronized (store) {

		// If we need to wake up sooner, adjust the sleep time.

		if (sTime < sleepyTime) {

		    sleepyTime = sTime;

		    // Interrupt the thread so we go back to
		    //  sleep for the right amount of time.

		    thrAger.interrupt();
		}
	    }

	    return ack;

	} catch (ServiceLocationException ex) {

	    if (conf.traceDrop()) {
		conf.writeLog("st_reg_drop",
			      new Object[] {
		    locationMsg,
			ex.getMessage()+"("+ex.getErrorCode()+")",
			locale,
			serviceType,
			surl,
			attrList,
			scopes});
	    }

	    return hdr.makeErrorReply(ex);

	} catch (RuntimeException ex) {

	    // These exceptions are not declared in throws but can occur
	    //  anywhere.

	    Vector args = new Vector();

	    args.addElement(req);

	    reportNonfatalException(ex, args, store);

	    return hdr.makeErrorReply(ex);

	}
    }

    /**
     * Process the deregistration and return the result in a reply.
     *
     * @param req Service deregistration request message.
     * @return SrvLocMsg A service registration acknowledgement.
     */

    SrvLocMsg deregister(SSrvDereg req) {

	// We need to determine whether this is an attribute deregistration
	//  or a deregistration of the entire URL.

	SrvLocHeader hdr = req.getHeader();
	Locale locale = hdr.locale;
	Vector scopes = hdr.scopes;
	ServiceURL surl = req.URL;
	Hashtable urlSig = req.URLSignature;
	Vector tags = req.tags;
	short errorCode = ServiceLocationException.OK;

	try {

	    // Verify if signature is nonnull.

	    if (urlSig != null) {
		AuthBlock.verifyAll(urlSig);

	    }

	    // Check if the service type is restricted. If so, nobody outside
	    //  this process is allowed to register it.

	    checkForRestrictedType(surl.getServiceType());

	    // Error if there's a signature and attempt at deleting attributes.

	    if ((urlSig != null) && (tags != null)) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.AUTHENTICATION_FAILED,
				"st_prot_attr_dereg",
				new Object[0]);
	    }

	    // Check if scope is protected and auth is off or vice versa.
	    //  Check is really simple. If security is on, then all scopes
	    //  in this DA/SA server are protected, so toss out any regs
	    //  that aren't, and vice versa.

	    if (conf.getHasSecurity() && urlSig == null) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.AUTHENTICATION_FAILED,
				"st_unprot_non_dereg",
				new Object[0]);

	    } else if (!conf.getHasSecurity() && urlSig != null) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.INVALID_REGISTRATION,
				"st_prot_non_dereg",
				new Object[0]);

	    }

	    // If it's a service URL, then deregister the URL.

	    if (tags == null) {
		store.deregister(surl, scopes, urlSig);

		// Track registred service types in case we get a
		// SAAdvert solicatation.

		trackRegisteredServiceTypes();

	    } else {

		// Just delete the attributes.

		store.deleteAttributes(surl, scopes, tags, locale);

	    }

	    // Create the reply.

	    SrvLocMsg ack = req.makeReply();

	    if (conf.regTest()) {
		conf.writeLog((tags == null ? "st_dereg":"st_delattr"),
			      new Object[] {
		    locationMsg,
	                locale,
			surl.getServiceType(),
			surl,
			tags});

	    }

	    if (conf.traceAll()) {
		conf.writeLog("st_dump",
			      new Object[] {locationMsg});
		store.dumpServiceStore();

	    }

	    return ack;

	} catch (ServiceLocationException ex) {

	    if (conf.traceDrop()) {
		conf.writeLog((tags == null ?
			       "st_dereg_drop" : "st_dereg_attr_drop"),
			      new Object[] {
		    locationMsg,
			ex.getMessage()+"("+ex.getErrorCode()+")",
			locale,
			surl.getServiceType(),
			surl,
			tags});
	    }

	    return hdr.makeErrorReply(ex);

	} catch (RuntimeException ex) {

	    // These exceptions are not declared in throws but can occur
	    //  anywhere.

	    Vector args = new Vector();

	    args.addElement(req);

	    reportNonfatalException(ex, args, store);

	    return hdr.makeErrorReply(ex);

	}
    }

    /**
     * Process the service type request and return the result in a reply.
     *
     * @param req Service type request message.
     * @return SrvTypeRply A service type reply.
     */

    SrvLocMsg findServiceTypes(SSrvTypeMsg req) {

	SrvLocHeader hdr = req.getHeader();
	Vector scopes = hdr.scopes;
	String namingAuthority = req.namingAuthority;
	short errorCode = ServiceLocationException.OK;

	try {

	    // Check whether the scope is supported.

	    if (!areSupportedScopes(scopes)) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.SCOPE_NOT_SUPPORTED,
				"st_scope_unsup",
				new Object[0]);

	    }

	    // Get the vector of service types in the store, independent
	    //  of language.

	    Vector types = store.findServiceTypes(namingAuthority, scopes);

	    // Create the reply.

	    SrvLocMsg ack = req.makeReply(types);

	    if (conf.traceAll()) {
		conf.writeLog("st_stypes",
			      new Object[] {
		    locationMsg,
			namingAuthority,
			scopes,
			types});
	    }

	    return ack;

	} catch (ServiceLocationException ex) {

	    if (conf.traceDrop()) {
		conf.writeLog("st_stypes_drop",
			      new Object[] {
		    locationMsg,
			ex.getMessage()+"("+ex.getErrorCode()+")",
			namingAuthority,
			scopes,
			hdr.locale});
	    }

	    return hdr.makeErrorReply(ex);

	} catch (RuntimeException ex) {

	    // These exceptions are not declared in throws but can occur
	    //  anywhere.

	    Vector args = new Vector();

	    args.addElement(req);

	    reportNonfatalException(ex, args, store);

	    return hdr.makeErrorReply(ex);

	}
    }

    /**
     * Process the service request and return the result in a reply.
     *
     * @param req Service request message.
     * @return SrvRply A service reply.
     */

    SrvLocMsg findServices(SSrvMsg req) {

	SrvLocHeader hdr = req.getHeader();
	Locale locale = hdr.locale;
	Vector scopes = hdr.scopes;
	String serviceType = req.serviceType;
	String query = req.query;
	short errorCode = ServiceLocationException.OK;

	try {

	    // Check whether the scope is supported.

	    if (!areSupportedScopes(scopes)) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.SCOPE_NOT_SUPPORTED,
				"st_scope_unsup",
				new Object[0]);
	    }

	    // Get the hashtable of returns.

	    Hashtable returns =
		store.findServices(serviceType,
				   scopes,
				   query,
				   locale);

	    // Get the hashtable of services v.s. scopes, and signatures, if
	    //  any.

	    Hashtable services =
		(Hashtable)returns.get(ServiceStore.FS_SERVICES);
	    Hashtable signatures =
		(Hashtable)returns.get(ServiceStore.FS_SIGTABLE);
	    boolean hasSignatures = (signatures != null);

	    // for each candidate URL, make sure it has the requested SPI
	    // (if any)
	    if (hasSignatures && !req.spi.equals("")) {
		Enumeration allSurls = services.keys();
		while (allSurls.hasMoreElements()) {
		    Object aSurl = allSurls.nextElement();
		    Hashtable auths = (Hashtable) signatures.get(aSurl);
		    AuthBlock auth =
			AuthBlock.getEquivalentAuth(req.spi, auths);
		    if (auth == null) {
			// doesn't have the requested SPI
			services.remove(aSurl);
		    }
		}
	    }

	    // Create return message.

	    SrvLocMsg ack = req.makeReply(services, signatures);

	    if (conf.traceAll()) {
		conf.writeLog("st_sreq",
			      new Object[] {
		    locationMsg,
			serviceType,
			scopes,
			query,
			locale,
			services,
			signatures});
	    }

	    return ack;

	} catch (ServiceLocationException ex) {

	    if (conf.traceDrop()) {
		conf.writeLog("st_sreq_drop",
			      new Object[] {
		    locationMsg,
			ex.getMessage()+"("+ex.getErrorCode()+")",
			serviceType,
			scopes,
			query,
			locale});
	    }

	    return hdr.makeErrorReply(ex);

	} catch (RuntimeException ex) {

	    // These exceptions are not declared in throws but can occur
	    //  anywhere.

	    Vector args = new Vector();

	    args.addElement(req);

	    reportNonfatalException(ex, args, store);

	    return hdr.makeErrorReply(ex);

	}
    }

    /**
     * Process the attribute request and return the result in a reply.
     *
     * @param req Attribute request message.
     * @return AttrRply An attribute reply.
     */

    SrvLocMsg findAttributes(SAttrMsg req) {

	// We need to determine whether this is a request for attributes
	//  on a specific URL or for an entire service type.

	SrvLocHeader hdr = req.getHeader();
	Vector scopes = hdr.scopes;
	Locale locale = hdr.locale;
	ServiceURL surl = req.URL;
	String serviceType = req.serviceType;
	Vector tags = req.tags;
	short errorCode = ServiceLocationException.OK;

	try {

	    // Check whether the scope is supported.

	    if (!areSupportedScopes(scopes)) {
	throw
	    new ServiceLocationException(
				ServiceLocationException.SCOPE_NOT_SUPPORTED,
				"st_scope_unsup",
				new Object[0]);
	    }

	    Vector attributes = null;
	    Hashtable sig = null;

	    // If it's a service URL, then get the attributes just for
	    // that URL.

	    if (serviceType == null) {

		// If the attrs are signed, then error if any tags, since
		//  we must ask for *all* attributes in for a signed reg

		if (!req.spi.equals("") && tags.size() > 0) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.AUTHENTICATION_FAILED,
				"st_par_attr",
				new Object[0]);

		}

		Hashtable ht =
		    store.findAttributes(surl, scopes, tags, locale);

		// Get the attributes and signatures.

		attributes = (Vector)ht.get(ServiceStore.FA_ATTRIBUTES);

		sig = (Hashtable)ht.get(ServiceStore.FA_SIG);

		// make sure the attr has the requested SPI (if any)
		if (sig != null && !req.spi.equals("")) {
		    AuthBlock auth = AuthBlock.getEquivalentAuth(req.spi, sig);
		    if (auth == null) {
			// return empty
			attributes = new Vector();
		    }
		}

	    } else {

		if (!req.spi.equals("")) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.AUTHENTICATION_FAILED,
				"st_par_attr",
				new Object[0]);
		}

		// Otherwise find the attributes for all service types.

		attributes =
		    store.findAttributes(serviceType, scopes, tags, locale);

	    }

	    ServiceType type =
		(serviceType == null ? surl.getServiceType():
		 new ServiceType(serviceType));


	    // Create the reply.

	    SrvLocMsg ack = req.makeReply(attributes, sig);

	    if (conf.traceAll()) {
		conf.writeLog((serviceType != null ?
			       "st_st_attr" : "st_url_attr"),
			      new Object[] {
		    locationMsg,
			(serviceType != null ? serviceType.toString() :
			 surl.toString()),
		      	scopes,
			tags,
			locale,
			attributes});
	    }

	    return ack;

	} catch (ServiceLocationException ex) {

	    if (conf.traceDrop()) {
		conf.writeLog((serviceType != null ? "st_st_attr_drop":
			       "st_url_attr_drop"),
			      new Object[] {
		    locationMsg,
			ex.getMessage()+"("+ex.getErrorCode()+")",
		        (serviceType != null ? serviceType.toString() :
			 surl.toString()),
		        scopes,
			tags,
			locale});
	    }

	    return hdr.makeErrorReply(ex);

	} catch (RuntimeException ex) {

	    // These exceptions are not declared in throws but can occur
	    //  anywhere.

	    Vector args = new Vector();

	    args.addElement(req);

	    reportNonfatalException(ex, args, store);

	    return hdr.makeErrorReply(ex);

	}
    }

    // Return the service record corresponding to the URL.

    ServiceStore.ServiceRecord getServiceRecord(ServiceURL URL,
						Locale locale) {
	return store.getServiceRecord(URL, locale);

    }

    //
    // Utility methods.
    //

    //
    //  Protected/private methods.
    //

    // Check whether the type is restricted, through an exception if so.

    private void checkForRestrictedType(ServiceType type)
	throws ServiceLocationException {

	if (Defaults.restrictedTypes.contains(type)) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.INVALID_REGISTRATION,
				"st_restricted_type",
				new Object[] {type});
	}
    }

    // Insert a record for type "service-agent" with attributes having
    //  the types currently supported, if the new URL is not on the
    //  list of supported types. This allows us to perform queries
    //  for supported service types.

    private void trackRegisteredServiceTypes()
	throws ServiceLocationException {

	// First find the types.

	Vector types = store.findServiceTypes(Defaults.ALL_AUTHORITIES,
					      conf.getSAConfiguredScopes());

	// Get preconfigured attributes.

	Vector attrs = conf.getSAAttributes();

	// Make an attribute with the service types.

	ServiceLocationAttribute attr =
	    new ServiceLocationAttribute(Defaults.SERVICE_TYPE_ATTR_ID,
					 types);

	attrs.addElement(attr);

	// Construct URL to use on all interfaces.

	Vector interfaces = conf.getInterfaces();
	int i, n = interfaces.size();

	for (i = 0; i < n; i++) {
	    InetAddress addr = (InetAddress)interfaces.elementAt(i);
	    ServiceURL url =
		new ServiceURL(Defaults.SUN_SA_SERVICE_TYPE + "://" +
			       addr.getHostAddress(),
			       ServiceURL.LIFETIME_MAXIMUM);

	    Vector scopes = conf.getSAOnlyScopes();

	    Locale locale = Defaults.locale;

	    // Make a new registration for this SA.

	    store.register(url,
			   attrs,
			   scopes,
			   locale,
			   null,
			   null);  // we could sign, but we do that later...
	}

	// Note that we don't need a refresh on the URLs because they
	//  will get refreshed when the service URLs that they track
	//  are refreshed. If the tracked URLs aren't refreshed, then
	//  these will get updated when the tracked URLs age out.
    }

    // Return true if the scopes in the vector are supported by the DA
    //  or SA server.

    final private boolean areSupportedScopes(Vector scopes) {

	Vector configuredScopes = conf.getSAConfiguredScopes();
	Vector saOnlyScopes = conf.getSAOnlyScopes();
	int i = 0;

	while (i < scopes.size()) {
	    Object o = scopes.elementAt(i);

	    // Remove it if we don't support it.

	    if (!configuredScopes.contains(o) && !saOnlyScopes.contains(o)) {
		// This will shift the Vector's elements down one, so
		// don't increment i
		scopes.removeElementAt(i);
	    } else {
		i++;
	    }
	}

	if (scopes.size() <= 0) {
	    return false;

	}

	return true;
    }

    /**
     * Return the sleep increment from the URL lifetime. Used by the
     * ServiceStore to calculate the new sleep interval in addition
     * to this class, when a new URL comes in. The algorithm
     * subtracts x% of the lifetime from the lifetime and schedules the
     * timeout at that time.
     *
     * @param url The URL to use for calculation.
     * @return The sleep interval.
     */

    private long getSleepIncrement(ServiceURL url) {
	long urlLifetime = (long)(url.getLifetime() * 1000);
	long increment =
	    (long)((float)urlLifetime * Defaults.fRefreshGranularity);
	long sTime = urlLifetime - increment;

	// If URL lives only one second, update every half second.

	if (sTime <= 0) {
	    sTime = 500;

	}

	return sTime;
    }

    // Make a DAADvert for the DA service request. This only applies
    //  to DAs, not to SA servers.

    SrvLocMsg
	makeDAAdvert(SSrvMsg rqst,
		     InetAddress daAddr,
		     SLPConfig conf) {

	SrvLocHeader hdr = rqst.getHeader();
	Vector scopes = hdr.scopes;
	short xid = hdr.xid;
	String query = rqst.query;

	try {

	    // If security is on, proceed only if we can sign as rqst.spi
	    if (conf.getHasSecurity() && !AuthBlock.canSignAs(rqst.spi)) {
		throw new ServiceLocationException(
			ServiceLocationException.AUTHENTICATION_UNKNOWN,
			"st_cant_sign_as",
			new Object[] {rqst.spi});
	    }

	    // Get the hashtable of service URLs v.s. scopes.

	    Hashtable services =
		ServerDATable.getServerDATable().returnMatchingDAs(query);

	    // Go through the table checking whether the IP address came back.

	    Enumeration urls = services.keys();
	    boolean foundIt = false;
	    String strDAAddr = daAddr.getHostAddress();

	    while (urls.hasMoreElements()) {
		ServiceURL url = (ServiceURL)urls.nextElement();

		if (url.getHost().equals(strDAAddr)) {
		    foundIt = true;
		    break;

		}
	    }

	    // If we didn't find anything, make a null service reply.

	    if (!foundIt) {
		return rqst.makeReply(new Hashtable(), new Hashtable());

	    }

	    return makeDAAdvert(hdr, daAddr, xid, scopes, conf);


	} catch (ServiceLocationException ex) {

	    return hdr.makeErrorReply(ex);

	}

    }

    // Make a DAAdvert from the input arguments.
    SrvLocMsg
	makeDAAdvert(SrvLocHeader hdr,
		     InetAddress daAddr,
		     short xid,
		     Vector scopes,
		     SLPConfig config)
	throws ServiceLocationException {

	// If this is a request for a V1 Advert, truncate the scopes vector
	//  since DA solicitations in V1 are always unscoped

	if (hdr.version == 1) {
	    scopes = new Vector();

	}

	// Check if we support scopes first. If not, return an
	//  error reply unless the scope vector is zero. Upper layers
	//  must sort out whether this is a unicast or multicast.

	if (scopes.size() > 0 && !areSupportedScopes(scopes)) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.SCOPE_NOT_SUPPORTED,
				"st_scope_unsup",
				new Object[0]);

	}

	// Get the service store's timestamp. This must be the
	//  time since last stateless reboot for a stateful store,
	//  or the current time.

	long timestamp = store.getStateTimestamp();

	ServiceURL url =
	    new ServiceURL(Defaults.DA_SERVICE_TYPE + "://" +
			   daAddr.getHostAddress(),
			   ServiceURL.LIFETIME_DEFAULT);

	SDAAdvert advert =
	    hdr.getDAAdvert(xid,
			    timestamp,
			    url,
			    scopes,
			    conf.getDAAttributes());

	return advert;
    }

    // Make a SAADvert for the SA service request. This only applies
    //  to SA servers, not DA's. Note that we only advertise the "public"
    //  scopes, not the private ones.

    SSAAdvert
	makeSAAdvert(SSrvMsg rqst,
		     InetAddress interfac,
		     SLPConfig conf)
	throws ServiceLocationException {
	SrvLocHeader hdr = rqst.getHeader();
	int version = hdr.version;
	short xid = hdr.xid;
	Locale locale = hdr.locale;
	Vector scopes = hdr.scopes;
	String query = rqst.query;
	String serviceType = rqst.serviceType;
	Vector saOnlyScopes = conf.getSAOnlyScopes();

	// If security is on, proceed only if we can sign as rqst.spi
	if (conf.getHasSecurity() && !AuthBlock.canSignAs(rqst.spi)) {
	    throw new ServiceLocationException(
			ServiceLocationException.AUTHENTICATION_UNKNOWN,
			"st_cant_sign_as",
			new Object[] {rqst.spi});
	}


	// Check if we support scopes first. Note that this may allow
	//  someone to get at the SA only scopes off machine, but that's
	//  OK. Since the SAAdvert is only ever multicast, this is OK.

	if (!areSupportedScopes(scopes) && !(scopes.size() <= 0)) {
	    return null;

	}

	// If the scopes vector is null, then use all configured scopes.

	if (scopes.size() <= 0) {
	    scopes = (Vector)conf.getSAConfiguredScopes().clone();

	}

	// Check to be sure the query matches.
	//  If it doesn't, we don't need to return anything.

	Hashtable returns =
	    store.findServices(Defaults.SUN_SA_SERVICE_TYPE.toString(),
			       saOnlyScopes,
			       query,
			       Defaults.locale);
	Hashtable services =
	    (Hashtable)returns.get(ServiceStore.FS_SERVICES);
	Enumeration en = services.keys();

	// Indicates we don't support the service type.

	if (!en.hasMoreElements()) {
	    return null;

	}

	// Find the URL to use. The interface on which the message came in
	//  needs to match one of the registered URLs.

	ServiceURL url = null;
	ServiceURL surl = null;
	String addr = interfac.getHostAddress();

	while (en.hasMoreElements()) {
	    surl = (ServiceURL)en.nextElement();

	    if (addr.equals(surl.getHost())) {
		url = new ServiceURL(Defaults.SA_SERVICE_TYPE + "://" +
				     addr,
				     ServiceURL.LIFETIME_DEFAULT);
		break;
	    }
	}

	// If none of the URLs matched this interface, then return null.

	if (url == null) {
	    return null;

	}

	// Find the SA's attributes.

	Hashtable ht =
	    store.findAttributes(surl,
				 saOnlyScopes,
				 new Vector(),
				 Defaults.locale);

	Vector attrs = (Vector)ht.get(ServiceStore.FA_ATTRIBUTES);

	// Construct return.

	return
	    new SSAAdvert(version,
			  xid,
			  locale,
			  url,
			  conf.getSAConfiguredScopes(), // report all scopes...
			  attrs);
    }

    /**
     * Report a fatal exception to the log.
     *
     * @param ex The exception to report.
     */

    protected static void reportFatalException(Exception ex) {

	reportException(true, ex, new Vector());

	if (table != null) {
	    table.store.dumpServiceStore();
	}

	conf.writeLog("exiting_msg", new Object[0]);

	System.exit(1);

    }

    /**
     * Report a nonfatal exception to the log.
     *
     * @param ex The exception to report.
     * @param args The method arguments.
     * @param store The service store being processed.
     */

    protected static void reportNonfatalException(Exception ex,
						  Vector args,
						  ServiceStore store) {

	reportException(false, ex, args);

	if (conf.traceAll()) {
	    store.dumpServiceStore();
	}

    }

    /**
     * Report an exception to the log.
     *
     * @param isFatal Indicates whether the exception is fatal or not.
     * @param ex The exception to report.
     * @param args A potentially null vector of arguments to the
     * 			method where the exception was caught.
     */

    private static void
	reportException(boolean isFatal, Exception ex, Vector args) {

	StringWriter sw = new StringWriter();
	PrintWriter writer = new PrintWriter(sw);

	// Get the backtrace.

	ex.printStackTrace(writer);

	String severity = (isFatal ? "fatal_error":"nonfatal_error");
	String msg = ex.getMessage();

	if (msg == null) {
	    msg = conf.formatMessage("no_message", new Object[0]);

	} else if (ex instanceof ServiceLocationException) {
	    msg = msg +
		"(" + ((ServiceLocationException)ex).getErrorCode() + ")";

	}

	StringBuffer argMsg = new StringBuffer();

	int i, n = args.size();

	for (i = 0; i < n; i++) {
	    argMsg.append("\n        (" + Integer.toString(i) + "):" +
			  args.elementAt(i).toString());
	}

	conf.writeLog(severity,
		      new Object[] {
	    ex.getClass().getName(),
		msg,
		argMsg,
		sw.toString()});

    }
}
