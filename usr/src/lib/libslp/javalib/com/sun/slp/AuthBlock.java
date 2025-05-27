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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

package com.sun.slp;

import java.util.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;

/**
 * The AuthBlock class models both the client and server side
 * authentication blocks.
 *<p>
 * AuthBlocks are agnostic as to which components from a given
 * message should be used in authentication. Thus each message
 * must provide the correct components in the correct order.
 *<p>
 * These components are passed via Object[]s. The Object[] elements
 * should be in externalized form, and should be ordered as stated
 * in the protocol specification for auth blocks. AuthBlocks will
 * add the externalized SPI string before the Object[] and the
 * externalized timestamp after the vector.
 *<p>
 * The AuthBlock class provides a number of static convenience
 * methods which operate on sets of AuthBlocks. The sets of
 * AuthBlocks are stored in Hashtables, keyed by SPIs.
 */

class AuthBlock {

    static private String SPI_PROPERTY = "sun.net.slp.SPIs";

    /**
     * A convenience method for creating a set of auth blocks
     * from internal data structures.
     *
     * @param message The ordered components of the SLP message
     *			over which the signature should be computed,
     *			in externalized (byte[]) form.
     * @param lifetime The lifetime for this message, in seconds.
     * @return A Hashtable of AuthBlocks, one for each SPI, null if no
     *		SPIs have been configured.
     * @exception ServiceLocationException If a key management or crypto
     *					algorithm provider cannot be
     *					instantiated, a SYSTEM_ERROR exception
     *					is thrown.
     * @exception IllegalArgumentException If any of the parameters are null
     *					or empty.
     */
    static Hashtable makeAuthBlocks(Object[] message, int lifetime)
	throws ServiceLocationException, IllegalArgumentException {

	Hashtable spis = getSignAs();
	if (spis == null) {
	    throw new ServiceLocationException(
		ServiceLocationException.AUTHENTICATION_FAILED,
		"cant_sign", new Object[0]);
	}

	Hashtable blocks = new Hashtable();
	Enumeration spisEnum = spis.keys();
	while (spisEnum.hasMoreElements()) {
	    String spi = (String) spisEnum.nextElement();
	    int bsd = ((Integer)(spis.get(spi))).intValue();
	    blocks.put(spi, new AuthBlock(message, spi, bsd, lifetime));
	}
	return blocks;
    }

    /**
     * A convenience method which creates a Hashtable of auth blocks
     * from an input stream.
     *
     * @param hdr Header of message being parsed out.
     * @param message The ordered components of the SLP message
     *			over which the signature should have been computed,
     *			in externalized (byte[]) form.
     * @param dis Input stream with the auth block bytes queued up as the
     *			next thing.
     * @param nBlocks Number of auth blocks to read.
     * @return A Hashtable of AuthBlocks.
     * @exception ServiceLocationException If anything goes wrong during
     *					parsing. If nBlocks is 0, the
     *					error code is AUTHENTICATION_ABSENT.
     * @exception IllegalArgumentException If any of the parameters are null
     *					or empty.
     * @exception IOException If DataInputStream throws it.
     */
    static Hashtable makeAuthBlocks(SrvLocHeader hdr,
				    Object[] message,
				    DataInputStream dis,
				    byte nBlocks)
	throws ServiceLocationException,
	       IllegalArgumentException,
	       IOException {

	Hashtable blocks = new Hashtable();

	for (byte cnt = 0; cnt < nBlocks; cnt++) {
	    AuthBlock ab = new AuthBlock(hdr, message, dis);
	    blocks.put(ab.getSPI(), ab);
	}

	return blocks;
    }

    /**
     * A convenience method which verifies all auth blocks in the
     * input Hashtable.
     *
     * @param authBlocks A Hashtable containing AuthBlocks.
     * @exception ServiceLocationException Thrown if authentication fails,
     *            with the error code
     *            ServiceLocationException.AUTHENTICATION_FAILED. If any
     *            other error occurs during authentication, the
     *            error code is ServiceLocationException.SYSTEM_ERROR.
     *            If the signature hasn't been calculated the
     *		   authentication fails.
     * @exception IllegalArgumentException If authBlocks is null or empty.
     */
    static void verifyAll(Hashtable authBlocks)
	throws ServiceLocationException, IllegalArgumentException {

	ensureNonEmpty(authBlocks, "authBlocks");

	Enumeration blocks = authBlocks.elements();

	while (blocks.hasMoreElements()) {
	    AuthBlock ab = (AuthBlock) blocks.nextElement();
	    ab.verify();
	}
    }

    /**
     * A convenience method which finds the shortest lifetime in a
     * set of AuthBlocks.
     *
     * @param authBlocks A Hashtable containing AuthBlocks.
     * @return The shortest lifetime found.
     * @exception IllegalArgumentException If authBlocks is null or empty.
     */
    static int getShortestLifetime(Hashtable authBlocks)
	    throws IllegalArgumentException {

	ensureNonEmpty(authBlocks, "authBlocks");

	Enumeration blocks = authBlocks.elements();
	int lifetime = Integer.MAX_VALUE;

	while (blocks.hasMoreElements()) {
	    AuthBlock ab = (AuthBlock) blocks.nextElement();
	    int abLife = ab.getLifetime();
	    lifetime = (lifetime < abLife) ? lifetime : abLife;
	}

	return lifetime;
    }

    /**
     * A convenience method which externalizes a set of AuthBlocks
     * into a ByteArrayOutputStream. The number of blocks is NOT
     * written onto the stream.
     *
     * @param hdr Header of message being externalized.
     * @param authBlocks A Hashtable containing AuthBlocks.
     * @param baos The output stream into which to write.
     * @exception ServiceLocationException Thrown if an error occurs during
     *					  output, with PARSE_ERROR error code.
     * @exception IllegalArgumentException If any parameters are null, or
     *					  if authBlocks is empty.
     */
    static void externalizeAll(SrvLocHeader hdr,
			       Hashtable authBlocks,
			       ByteArrayOutputStream baos)
	throws ServiceLocationException, IllegalArgumentException {

	ensureNonEmpty(authBlocks, "authBlocks");

	Enumeration blocks = authBlocks.elements();

	while (blocks.hasMoreElements()) {
	    AuthBlock ab = (AuthBlock) blocks.nextElement();
	    ab.externalize(hdr, baos);
	}
    }

    /**
     * Returns the message parts obtained from the AuthBlock contructor.
     * The Object[] will not have been altered. Note that all AuthBlocks
     * contain the same message Object[] Object.
     *
     * @param authBlocks A Hashtable containing AuthBlocks.
     * @return This auth block's message components Object[].
     * @exception IllegalArgumentException If authBlocks is null or empty.
     */
    static Object[] getContents(Hashtable authBlocks)
	throws IllegalArgumentException {

	ensureNonEmpty(authBlocks, "authBlocks");

	Enumeration blocks = authBlocks.elements();
	AuthBlock ab = (AuthBlock) blocks.nextElement();
	return ab.getMessageParts();
    }

    /**
     * Creates a String describing all auth blocks in authBlocks.
     * We dont't use toString() since that would get Hashtable.toString(),
     * and we can format it a little prettier.
     *
     * @param authBlocks A Hashtable containing AuthBlocks.
     * @return A String description of all AuthBlocks in this Hashtable
     */
    static String desc(Hashtable authBlocks) {

	if (authBlocks == null) {
	    return "null";
	}

	Enumeration blocks = authBlocks.elements();
	int size = authBlocks.size();
	String desc = size == 1 ? "1 Auth Block:\n" : size + " Auth Blocks:\n";
	int cnt = 0;

	while (blocks.hasMoreElements()) {
	    AuthBlock ab = (AuthBlock) blocks.nextElement();
	    desc = desc + "             " + (cnt++) + ": " + ab.toString();
	}

	return desc;
    }

    /**
     * Returns the list of SPIs configured with this 'prop', or null
     * if the property hasn't been set.
     */
    static LinkedList getSPIList(String prop) {
	String spiProp = System.getProperty(prop);
	if (spiProp == null) {
	    return null;
	}

	return commaSeparatedListToLinkedList(spiProp);
    }

    /**
     * Converts a comma-separaterd list in a String to a LinkedList.
     */
    static LinkedList commaSeparatedListToLinkedList(String listStr) {
	StringTokenizer stk_comma = new StringTokenizer(listStr, ",");
	LinkedList answer = new LinkedList();
	while (stk_comma.hasMoreTokens()) {
	    String spi = stk_comma.nextToken();
	    answer.add(spi);
	}

	return answer;
    }

    /**
     * Returns true if this principal is someDH, or if this principal's
     * cert has been signed by someDN.
     */
    static boolean canSignAs(String someDN) throws ServiceLocationException {
	X509Certificate myCert = getSignAsCert();
	if (myCert == null) {
	    return false;
	}

	KeyStore ks = getKeyStore();
	if (ks == null) {
	    return false;
	}

	X509Certificate cert = getCert(someDN, ks);

	return onCertChain(
		myCert.getSubjectDN().toString(), cert.getSubjectDN());
    }

    /**
     * Checks if caDN is in ab's equivalency set, i.e. if caDN
     * is in ab's cert chain.
     */
    static boolean checkEquiv(String caDN, AuthBlock ab) {
	// Get cert for input DN
	X509Certificate caCert;
	try {
	    KeyStore ks = getKeyStore();

	    caCert = getCert(caDN, ks);
	} catch (Exception e) {
	    SLPConfig.getSLPConfig().writeLog(
		"cant_get_equivalency",
		new Object[] {caDN, e.getMessage()});
	    return false;
	}

	return ab.inEqSet(caCert.getSubjectDN());
    }

    /**
     * Filters out from auths all auth blocks which have not been
     * signed by DNs equivalent to caDN.
     */
    static AuthBlock getEquivalentAuth(String caDN, Hashtable authBlocks) {
	if (authBlocks.size() == 0) {
	    return null;
	}

	// Get cert for input DN
	X509Certificate caCert;
	try {
	    KeyStore ks = getKeyStore();

	    caCert = getCert(caDN, ks);
	} catch (Exception e) {
	    SLPConfig.getSLPConfig().writeLog(
		"cant_get_equivalency",
		new Object[] { caDN, e.getMessage()});
	    return null;
	}

	Enumeration blocks = authBlocks.elements();

	while (blocks.hasMoreElements()) {
	    AuthBlock ab = (AuthBlock) blocks.nextElement();
	    if (ab.inEqSet(caCert.getSubjectDN())) {
		return ab;
	    }
	}

	return null;
    }


    /**
     * Gets a list of signing identities. Returns a Hashtable of
     * which the keys are SPI strings (DNs) and the values
     * are BSD Integers.
     */
    static Hashtable getSignAs() throws ServiceLocationException {
	X509Certificate cert = getSignAsCert();
	Hashtable answer = new Hashtable();

	if (cert == null) {
	    return null;
	}

	/* derive DN from alias */
	String DN = cert.getSubjectDN().toString();
	String e_DN = null;
	// escape DN
	try {
	    e_DN = ServiceLocationAttribute.escapeAttributeString(DN, false);
	} catch (ServiceLocationException e) {
	    // Shouldn't get here if badTag == false
	    e_DN = DN;
	}
	DN = e_DN;

	String alg = cert.getPublicKey().getAlgorithm();
	int ibsd;
	if (alg.equals("DSA")) {
	    ibsd = 2;
	} else if (alg.equals("RSA")) {
	    ibsd = 1;
	} else {
	    SLPConfig.getSLPConfig().writeLog("bad_alg_for_alias",
					      new Object[] {alg});
	    return null;
	}

	answer.put(DN, Integer.valueOf(ibsd));

	return answer;
    }

    /**
     * Returns the cert corresponding to our signing alias.
     * @@@ change this when AMI goes in to use private AMI interface.
     */
    static X509Certificate getSignAsCert() throws ServiceLocationException {
	String spiProp = System.getProperty("sun.net.slp.signAs");
	if (spiProp == null) {
	    SLPConfig.getSLPConfig().writeLog(
		"no_spis_given", new Object[0]);
	    return null;
	}

	/* load key store */
	KeyStore ks = getKeyPkg();

	StringTokenizer stk_comma = new StringTokenizer(spiProp, ",");
	X509Certificate cert = null;

	// Can only sign with one alias, so ignore any extras
	if (stk_comma.hasMoreTokens()) {
	    String alias = stk_comma.nextToken();

	    /* get keypkg for this alias */
	    cert = getCert(alias, ks);
	}

	return cert;
    }

    /**
     * Creates a new AuthBlock based on the SPI and message parts.
     *
     * @param message The ordered components of the SLP message
     *			over which the signature should be computed,
     *			in externalized (byte[]) form.
     * @param spi The SLP SPI for which to create the auth block.
     * @param lifetime The lifetime for this message, in seconds.
     * @exception ServiceLocationException If a key management or crypto
     *					algorithm provider cannot be
     *					instantiated, a SYSTEM_ERROR exception
     *					is thrown.
     * @exception IllegalArgumentException If any of the parameters are null
     *					or empty.
     */
    AuthBlock(Object[] message, String spi, int bsd, int lifetime)
	throws ServiceLocationException, IllegalArgumentException {

	ensureNonEmpty(message, "message");
	Assert.nonNullParameter(spi, "spi");

	// init crypto provider associated with bsd
	this.bsd = bsd;
	getSecurityProvider(bsd);

	this.message = message;
	this.spi = spi;
	this.lifetime = lifetime;
	this.timeStamp = SLPConfig.currentSLPTime() + lifetime;

	// Create the signature: create and sign the hash

	try {
	    // @@@ how to sign for different aliases?
	    sig.initSign(null);
	    computeHash();
	    abBytes = sig.sign();
	} catch (InvalidKeyException e) {	// @@@ will change for AMI
	  SLPConfig conf = SLPConfig.getSLPConfig();
	    throw
		new IllegalArgumentException(
				conf.formatMessage(
					"cant_sign_for_spi",
					new Object[] {
						spi,
						e.getMessage() }));
	} catch (SignatureException e) {
	  SLPConfig conf = SLPConfig.getSLPConfig();
	    throw
		new IllegalArgumentException(
				conf.formatMessage(
					"cant_sign_for_spi",
					new Object[] {
						spi,
						e.getMessage() }));
	}

	// calculate the length
	abLength =
		2 + // bsd
		2 + // length
		4 + // timestamp
		spiBytes.length + // externalized SPI string, with length
		abBytes.length; // structured auth block
    }

    /**
     * Creates a new AuthBlock from an input stream.
     *
     * @param hdr The header of the message being parsed.
     * @param message The ordered components of the SLP message
     *			over which the signature should have been computed,
     *			in externalized (byte[]) form.
     * @param dis Input stream with the auth block bytes queued up as the
     *			next thing.
     * @exception ServiceLocationException If anything goes wrong during
     *					parsing. If nBlocks is 0, the
     *					error code is AUTHENTICATION_ABSENT.
     * @exception IllegalArgumentException If any of the parameters are null
     *					or empty.
     * @exception IOException If DataInputStream throws it.
     */
    AuthBlock(SrvLocHeader hdr, Object[] message, DataInputStream dis)
	throws ServiceLocationException,
	       IllegalArgumentException,
	       IOException {

	Assert.nonNullParameter(hdr, "hdr");
	ensureNonEmpty(message, "message");
	Assert.nonNullParameter(dis, "dis");

	this.message = message;
	this.eqSet = new HashSet();

	// parse in the auth block from the input stream;
	// first get the BSD and length
	bsd = hdr.getInt(dis);
	abLength = hdr.getInt(dis);

	int pos = 4;	// bsd and length have already been consumed

	// get the timestamp
	timeStamp = getInt32(dis);
	pos += 4;
	hdr.nbytes += 4;

	// get the SPI
	StringBuffer buf = new StringBuffer();
	hdr.getString(buf, dis);
	spi = buf.toString();
	if (spi.length() == 0) {
		throw new ServiceLocationException(
		    ServiceLocationException.PARSE_ERROR,
		    "no_spi_string",
		    new Object[0]);
	}
	pos += (2 + spi.length());

	// get the structured auth block
	abBytes = new byte[abLength - pos];
	dis.readFully(abBytes, 0, abLength - pos);
	hdr.nbytes += abBytes.length;

	// calculate remaining lifetime from timestamp
	long time = timeStamp - SLPConfig.currentSLPTime();
	time = time <= Integer.MAX_VALUE ? time : 0;	// no crazy values
	lifetime = (int) time;
	lifetime = lifetime < 0 ? 0 : lifetime;

	// Initialize the crypto provider
	getSecurityProvider(bsd);
    }

    /**
     * Gets the size of this auth block, after externalization, in bytes.
     *
     * @return The number of bytes in this auth block.
     */
    int nBytes() {
	return abLength;
    }

    /**
     * Returns the message parts obtained from the AuthBlock contructor.
     * The Object[] will not have been altered.
     *
     * @return This auth block's message components Object[].
     */
    Object[] getMessageParts() {
	return message;
    }

    /**
     * Verifies the signature on this auth block.
     *
     * @exception ServiceLocationException Thrown if authentication fails,
     *            with the error code
     *            ServiceLocationException.AUTHENTICATION_FAILED. If any
     *            other error occurs during authentication, the
     *            error code is ServiceLocationException.SYSTEM_ERROR.
     *            If the signature hasn't been calculated, the
     *		   fails.
     */
    void verify() throws ServiceLocationException {
	// Load the keystore
	KeyStore ks = null;
	try {
	    ks = KeyStore.getInstance("amicerts", "SunAMI");
	    ks.load(null, null);
	} catch (Exception e) {
	    throw
		new ServiceLocationException(
			ServiceLocationException.AUTHENTICATION_FAILED,
			"no_keystore",
			new Object[] {e.getMessage()});
	}

	// Unescape the SPI for cleaner logging
	String u_DN = null;
	try {
	    u_DN =
		ServiceLocationAttribute.unescapeAttributeString(spi, false);
	} catch (ServiceLocationException e) {
	    u_DN = spi;
	}

	// get cert for this spi
	X509Certificate cert = getCert(spi, ks);

	// check cert validity
	try {
	    cert.checkValidity();
	} catch (CertificateException e) {
	    throw new ServiceLocationException(
		ServiceLocationException.AUTHENTICATION_FAILED,
		"invalid_cert",
		new Object[] {u_DN, e.getMessage()});
	}

	// check the lifetime
	if (lifetime == 0) {
	    throw new ServiceLocationException(
		ServiceLocationException.AUTHENTICATION_FAILED,
		"timestamp_failure",
		new Object[] {u_DN});
	}

	// make sure this SPI matches up with configured SPIs
	try {
	    checkSPIs(cert, ks);
	} catch (GeneralSecurityException e) {
	    throw new ServiceLocationException(
		ServiceLocationException.AUTHENTICATION_FAILED,
		"cant_match_spis",
		new Object[] {cert.getSubjectDN(), e.getMessage()});
	}


	// check the signature
	try {
	    sig.initVerify(cert.getPublicKey());
	} catch (InvalidKeyException ex) {
	    throw
		new ServiceLocationException(
			ServiceLocationException.INTERNAL_SYSTEM_ERROR,
			"init_verify_failure",
			new Object[] {
				u_DN,
				    ex.getMessage()});
	}

	computeHash();

	ServiceLocationException vex =
	    new ServiceLocationException(
		ServiceLocationException.AUTHENTICATION_FAILED,
		"verify_failure",
		new Object[] {u_DN});

	try {
	    if (!sig.verify(abBytes))
		throw vex;
	} catch (SignatureException ex) {
	    throw vex;
	}
    }

    /**
     * Convert the auth block into its on-the-wire format.
     *
     * @param hdr The header of the message being parsed out.
     * @param baos The output stream into which to write.
     * @exception ServiceLocationException Thrown if an error occurs during
     *					  output, with PARSE_ERROR error code.
     * @exception IllegalArgumentException If any baos is null.
     */
    void externalize(SrvLocHeader hdr, ByteArrayOutputStream baos)
	throws ServiceLocationException, IllegalArgumentException {

	Assert.nonNullParameter(hdr, "hdr");
	Assert.nonNullParameter(baos, "baos");

	// Lay out the auth block, starting with the BSD
	hdr.putInt(bsd, baos);

	// write out the length
	hdr.putInt(abLength, baos);

	// calculate and write out the timestamp
	putInt32(timeStamp, baos);
	hdr.nbytes += 4;

	// write the SPI string
	hdr.putString(spi, baos);

	// Finish by writting the structured auth block
	baos.write(abBytes, 0, abBytes.length);
	hdr.nbytes += abBytes.length;
    }

    /**
     * Returns the SPI associated with this auth block.
     *
     * @return The SLP SPI for this auth block.
     */
    String getSPI() {
	return spi;
    }

    /**
     * Returns the lifetime computed from this auth block.
     *
     * @return The lifetime from this auth block.
     */
    int getLifetime() {
	return lifetime;
    }

    /**
     * Given a BSD, sets this AuthBlock's Signature to the
     * right algorithm.
     */
    private void getSecurityProvider(int bsd)
	throws ServiceLocationException {

	String algo = "Unknown BSD";
	try {
	    if (bsd == 2) {
		// get DSA/SHA1 provider
		algo = "DSA";
		sig = Signature.getInstance("SHA/DSA", "SunAMI");
		return;
	    } else if (bsd == 1) {
		algo = "MD5/RSA";
		sig = Signature.getInstance("MD5/RSA", "SunAMI");
		return;
	    } else if (bsd == 3) {
		algo = "Keyed HMAC with MD5";
	    }
	} catch (GeneralSecurityException e) {
	    // system error -- no such provider
	    throw new ServiceLocationException(
		ServiceLocationException.INTERNAL_SYSTEM_ERROR,
		"cant_get_security_provider",
		new Object[] {
			Integer.valueOf(bsd),
			algo,
			e.getMessage()});
	}

	// Unknown or unsupported BSD
	throw new ServiceLocationException(
	    ServiceLocationException.INTERNAL_SYSTEM_ERROR,
	    "cant_get_security_provider",
	    new Object[] {
		Integer.valueOf(bsd),
		algo,
		"Unknown or unsupported BSD"});
    }

    /**
     * throws an IllegalArgumentException if v is null or empty.
     * v can be either a Hashtable or a Object[].
     */
    static private void ensureNonEmpty(Object v, String param)
	throws IllegalArgumentException {

	int size = 0;
	if (v != null) {
	    if (v instanceof Object[]) {
		size = ((Object[]) v).length;
	    } else {
		// this will force a class cast exception if not a Hashtable
		size = ((Hashtable) v).size();
	    }
	}

	if (v == null || size == 0) {
	    SLPConfig conf = SLPConfig.getSLPConfig();
	    String msg =
		conf.formatMessage("null_or_empty_vector",
				   new Object[] {param});
	    throw
		new IllegalArgumentException(msg);
	}
    }

    /**
     * Computes a hash over the SPI String, message componenets,
     * and timstamp. Which hash is used depends on which crypto
     * provider was installed.
     *
     * This method assumes that the class variables spi, sig,
     * message, and timeStamp have all been initialized. As a side
     * effect, it places the externalized SPI String into spiBytes.
     */
    private void computeHash() throws ServiceLocationException {
	try {
	    // get the SPI String bytes
	    ByteArrayOutputStream baosT = new ByteArrayOutputStream();
	    SrvLocHeader.putStringField(spi, baosT, Defaults.UTF8);
	    spiBytes = baosT.toByteArray();
	    sig.update(spiBytes);

	    // Add each message component
	    int mSize = message.length;
	    for (int i = 0; i < mSize; i++) {
		sig.update((byte[]) message[i]);
	    }

	    // end by adding the timestamp
	    baosT = new ByteArrayOutputStream();
	    putInt32(timeStamp, baosT);
	    sig.update(baosT.toByteArray());
	} catch (SignatureException e) {
	    throw new ServiceLocationException(
		ServiceLocationException.INTERNAL_SYSTEM_ERROR,
		"cant_compute_hash",
		new Object[] {e.getMessage()});
	}
    }

    static private long getInt32(DataInputStream dis) throws IOException {
	byte[] bytes = new byte[4];

	dis.readFully(bytes, 0, 4);

	long a = (long)(bytes[0] & 0xFF);
	long b = (long)(bytes[1] & 0xFF);
	long c = (long)(bytes[2] & 0xFF);
	long d = (long)(bytes[3] & 0xFF);

	long i = a << 24;
	i += b << 16;
	i += c << 8;
	i += d;

	return i;
    }

    static private void putInt32(long i, ByteArrayOutputStream baos) {
	baos.write((byte) ((i >> 24) & 0xFF));
	baos.write((byte) ((i >> 16) & 0xFF));
	baos.write((byte) ((i >> 8)  & 0xFF));
	baos.write((byte) (i & 0XFF));
    }

    /**
     * Determines if this process' SPI configuration allows
     * messages signed by 'cert' to be verified. This method
     * also verifies and validates 'cert's cert chain.
     */
    private void checkSPIs(X509Certificate cert, KeyStore ks)
	throws ServiceLocationException, GeneralSecurityException {

	// get the list of configured SPIs
	String conf_spis = System.getProperty("sun.net.slp.SPIs");
	if (conf_spis == null) {
	    throw new ServiceLocationException(
		ServiceLocationException.AUTHENTICATION_FAILED,
		"no_spis_configured", new Object[0]);
	}

	// Get cert chain
	java.security.cert.Certificate[] chain =
	    ks.getCertificateChain(cert.getSubjectDN().toString());
	if (chain == null) {
	    throw new ServiceLocationException(
		ServiceLocationException.AUTHENTICATION_FAILED,
		"no_cert_chain",
		new Object[] {cert.getSubjectDN().toString()});
	}

	// validate all links in chain
	int i = 0;
	try {
	    // Add cert's own subjec to equiv set
	    eqSet.add(((X509Certificate)chain[0]).getSubjectDN());

	    for (i = 1; i < chain.length; i++) {
		((X509Certificate)chain[i]).checkValidity();
		chain[i-1].verify(chain[i].getPublicKey(), "SunAMI");

		// OK, so add to equivalency set
		eqSet.add(((X509Certificate)chain[i]).getSubjectDN());
	    }
	} catch (ClassCastException e) {
	    throw new ServiceLocationException(
		ServiceLocationException.AUTHENTICATION_FAILED,
		"not_x509cert",
		new Object[] { chain[i].getType(), e.getMessage() });
	}

	if (configuredToVerify(chain, conf_spis, ks)) {
	    return;
	}

	// if we get here, no SPIs matched, so the authentication fails
	throw new ServiceLocationException(
		ServiceLocationException.AUTHENTICATION_FAILED,
		"cant_match_spis",
		new Object[] {cert.getSubjectDN().toString(), ""});
    }

    /**
     * Determines if, given a set of SPIs 'conf_spis', we can
     * verify a message signed by the Principal named by 'cert'.
     */
    static private boolean configuredToVerify(
				java.security.cert.Certificate[] chain,
				String conf_spis,
				KeyStore ks) {

	StringTokenizer stk = new StringTokenizer(conf_spis, ",");
	while (stk.hasMoreTokens()) {
	    String spi;

	    try {
		spi = stk.nextToken();
	    } catch (NoSuchElementException e) {
		break;
	    }

	    // get CA cert to get CA Principal
	    Principal ca;
	    try {
		X509Certificate cacert = getCert(spi, ks);
		ca = cacert.getSubjectDN();
	    } catch (ServiceLocationException e) {
		SLPConfig.getSLPConfig().writeLog(
			"cant_process_spi",
			new Object[] {spi, e.getMessage()});
		continue;
	    }

	    if (onCertChain(ca, chain)) {
		return true;
	    }
	}

	return false;
    }

    /**
     * Determines if sub if equivalent to ca by getting sub's cert
     * chain and walking the chain looking for ca.
     * This routine does not verify the cert chain.
     */
    private static boolean onCertChain(String sub, Principal ca)
	throws ServiceLocationException {

	java.security.cert.Certificate[] chain;

	ServiceLocationException ex = new ServiceLocationException(
			ServiceLocationException.AUTHENTICATION_UNKNOWN,
			"no_cert_chain",
			new Object[] {sub});

	try {
	    // Get cert keystore
	    KeyStore ks = getKeyStore();

	    // Get cert chain for subject
	    chain = ks.getCertificateChain(sub);
	} catch (KeyStoreException e) {
	    throw ex;
	}

	if (chain == null) {
	    throw ex;
	}

	// walk the cert chain
	return onCertChain(ca, chain);
    }

    /**
     * Operates the same as above, but rather than getting the cert
     * chain for sub, uses a given cert chain.
     */
    private static boolean onCertChain(Principal ca,
				       java.security.cert.Certificate[] chain)
    {
	// walk the cert chain
	for (int i = 0; i < chain.length; i++) {
	    Principal sub = ((X509Certificate)chain[i]).getSubjectDN();
	    if (ca.equals(sub)) {
		return true;
	    }
	}

	return false;
    }

    /**
     * Returns true if someDN is in this AuthBlock's equivalence set.
     */
    private boolean inEqSet(Principal someDN) {
	return eqSet.contains(someDN);
    }

    /**
     * Retrieves from the KeyStore 'ks' the X509Certificate named
     * by DN.
     */
    static private X509Certificate getCert(String DN, KeyStore ks)
	throws ServiceLocationException {

	X509Certificate cert = null;

	// Unescape DN
	try {
	    DN = ServiceLocationAttribute.unescapeAttributeString(DN, false);
	} catch (ServiceLocationException e) {
	    throw new ServiceLocationException(
		ServiceLocationException.PARSE_ERROR,
		"spi_parse_error",
		new Object[] {DN, e.getMessage()});
	}

	try {
	    cert = (X509Certificate)ks.getCertificate(DN);
	} catch (ClassCastException e) {
	    throw new ServiceLocationException(
		ServiceLocationException.AUTHENTICATION_FAILED,
		"not_x509cert",
		new Object[] {cert.getType(), e.getMessage()});
	} catch (KeyStoreException e) {
	    throw new ServiceLocationException(
		ServiceLocationException.AUTHENTICATION_FAILED,
		"no_cert",
		new Object[] {DN, e.getMessage()});
	}

	if (cert == null) {
	    throw new ServiceLocationException(
		ServiceLocationException.AUTHENTICATION_FAILED,
		"no_cert",
		new Object[] {DN, "" });
	}

	return cert;
    }

    /**
     * Gets a handle to the trusted key package for this process.
     */
    static private synchronized KeyStore getKeyPkg()
	throws ServiceLocationException {

	if (keypkg != null) {
	    return keypkg;
	}

	/* else load key store */
	try {
	    keypkg = KeyStore.getInstance("amiks", "SunAMI");
	    keypkg.load(null, null);
	} catch (Exception e) {
	    throw new ServiceLocationException(
		ServiceLocationException.AUTHENTICATION_FAILED,
		"no_keystore",
		new Object[] {e.getMessage()});
	}

	return keypkg;
    }

    /**
     * Gets a handle to a certificate repository.
     */
    static private synchronized KeyStore getKeyStore()
	throws ServiceLocationException {

	if (keystore != null) {
	    return keystore;
	}

	try {
	    keystore = KeyStore.getInstance("amicerts", "SunAMI");
	    keystore.load(null, null);
	} catch (Exception e) {
	    throw
		new ServiceLocationException(
			ServiceLocationException.AUTHENTICATION_FAILED,
			"no_keystore",
			new Object[] {e.getMessage()});
	}

	return keystore;
    }

    public String toString() {
	return  "SPI=``" + spi + "''\n" +
		"                BSD=``" + bsd + "''\n" +
		"                timeStamp=``" + timeStamp + "''\n" +
		"                AuthBlock bytes=" + abLength + " bytes\n";
    }


    // Instance variables
    int bsd;
    String spi;
    Object[] message;
    int lifetime;	// need both: lifetime is for optimization,
    long timeStamp;	// timeStamp is needed to compute the hash
    SrvLocHeader hdr;
    Signature sig;
    int abLength;
    byte[] abBytes;
    byte[] spiBytes;
    HashSet eqSet;	// built only during authblock verification

    // cached per process
    static private KeyStore keystore;	// Certificate repository
    static private KeyStore keypkg;	// My own keypkg
}
