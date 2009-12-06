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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.data;

import java.util.ArrayList;
import java.util.Arrays;
import java.io.Serializable;
import com.sun.dhcpmgr.data.qualifier.*;

/**
 * DhcpdOptions models the option settings for the in.dhcpd daemon.  We read
 * and write the option settings in the daemon's defaults file.
 * Getter and setter methods are provided for each individual option.
 */

public class DhcpdOptions implements DhcpConfigOpts, Serializable {
    /* The list of facility choices the user may select from for logging */
    private static final Integer [] loggingFacilities = {
        new Integer(0), new Integer(1), new Integer(2), new Integer(3),
	new Integer(4), new Integer(5), new Integer(6), new Integer(7)
    };

    // Store the option settings here
    private ArrayList options;

    /**
     *  Dirty flag. Set after a clear or a set on an option.
     */
    private boolean dirty = false;

    public DhcpdOptions() {
    	options = new ArrayList();
    }

    public DhcpdOptions(DhcpResource [] opts) {
    	options = new ArrayList(Arrays.asList(opts));
    }

    public Object clone() {
	DhcpdOptions o = new DhcpdOptions();
	o.options = (ArrayList)options.clone();
	return o;
    }

    /**
     * Test whether a particular option is set.
     * @param key
     *   The name of the option to set.
     * @return
     *   True if the option is set, otherwise false.
     */
    public boolean isSet(String key) {
	return internalIsSet(key);
    }

    /**
     * Set an option to a supplied value.
     * @param key
     *   The name of the option to set.
     * @param value
     *   The value of the option.
     */
    public void set(String key, String value) {
	set(key, value, false);
    }

    /**
     * Set an option to a supplied value, or add a comment line to the
     * table.
     * @param key
     *   The name of the option to set.
     * @param value
     *   The value of the option.
     * @param comment
     *   true if this is a comment, in which case value is ignored
     * and the comment text is contained entirely in key.
     */
    public void set(String key, String value, boolean comment) {
	internalSet(key, value, comment);

	/*
	 * Ensure that the run mode is kept consistent with the
	 * configuration parameters.  Mgt. tools rely on this!
	 */
	if (key.equals(DSVC_CK_PATH)) {
	    internalSet(DSVC_CK_RUN_MODE, DSVC_CV_SERVER);
	} else if (key.equals(DSVC_CK_RELAY_DESTINATIONS)) {
	    internalSet(DSVC_CK_RUN_MODE, DSVC_CV_RELAY);
	} else if (key.equals(DSVC_CK_RESOURCE)) {
	    internalSet(DSVC_CK_RUN_MODE, DSVC_CV_SERVER);
	}
    }

    /**
     * Clear an option.
     * @param key
     *   The name of the option to clear.
     */
    public void clear(String key) {
	internalClear(key);

	if (key.equals(DSVC_CK_RELAY_DESTINATIONS)) {
	    internalSet(DSVC_CK_RUN_MODE, DSVC_CV_SERVER);
	}
    }

    /**
     * Return the value of an option setting; null if it's not set.
     * @param key
     *   The option whose value is to be retrieved.
     * @return
     *   The value of an option setting; null if it's not set.
     */
    public String valueOf(String key) {
	return internalValueOf(key);
    }

    // Test whether a particular option is set
    private boolean internalIsSet(String key) {
	DhcpResource res = new DhcpResource();
	res.setKey(key);
	return options.contains(res);
    }

    // Set an option to a supplied value
    private void internalSet(String key, String value) {
	internalSet(key, value, false);
    }

    /**
     * Set an option to a supplied value, or add a comment line to the
     * table.
     * @param key The name of the option to set
     * @param value The value of the option
     * @param comment true if this is a comment, in which case value is ignored
     * and the comment text is contained entirely in key.
     */
    private void internalSet(String key, String value, boolean comment) {
	DhcpResource res = new DhcpResource(key, value, comment);
	int i = options.indexOf(res);
	if (i != -1) {
	    DhcpResource existing = (DhcpResource)options.get(i);

	    if (!existing.getValue().equals(res.getValue())) {
		options.set(i, res);
		dirty = true;
	    }
	} else {
	    options.add(res);
	    dirty = true;
	}
    }

    // Clear an option
    private void internalClear(String key) {
	DhcpResource res = new DhcpResource();
	res.setKey(key);
	int i = options.indexOf(res);
	if (i != -1) {
	    options.remove(i);
	    dirty = true;
	}
    }

    /**
     * Return the value of an option setting; null if it's not set
     * @param key The option whose value is to be retrieved
     * @return The value of an option setting; null if it's not set
     */
    private String internalValueOf(String key) {
	DhcpResource res = new DhcpResource();
	res.setKey(key);
	int i = options.indexOf(res);
	if (i != -1) {
	    return ((DhcpResource)options.get(i)).getValue();
	} else {
	    return null;
	}
    }

    /**
     * Return all of the option settings as an array
     * @return An array of Objects which will all be DhcpResources
     */
    public Object [] getAll() {
    	return options.toArray();
    }

    /**
     * Test to see whether or not the daemon is enabled.
     * @return true if daemon is enabled, false if not.
     */
    public boolean isDaemonEnabled() {
	return DSVC_CV_TRUE.equals(valueOf(DSVC_CK_DAEMON_ENABLED));
    }

    /**
     * Set daemon enabled or disabled
     * @param state true for enabled, false for disabled
     */
    public void setDaemonEnabled(boolean state) {
	set(DSVC_CK_DAEMON_ENABLED, state ? DSVC_CV_TRUE : DSVC_CV_FALSE);
    }

    /**
     * Set the DhcpDatastore attributes.
     * @param resource the data store resource attribute
     * @param location the data store location attribute
     * @param config the data store config attribute
     * @param version the data store version attribute
     */
    public void setDhcpDatastore(String resource, String location,
	String config, int version) {
	setResource(resource);
	setPath(location);
	setConfig(config);
	setResourceVersion(version);
    } // setDhcpDatastore

    /**
     * Set the DhcpDatastore attributes.
     * @param datastore a datastore object whose attributes
     * are the desired attributes.
     */
    public void setDhcpDatastore(DhcpDatastore datastore) {
	setResource(datastore.getResource());
	setPath(datastore.getLocation());
	setConfig(datastore.getConfig());
	setResourceVersion(datastore.getVersion());
    } // setDhcpDatastore

    /**
     * Set the DhcpDatastore attributes.
     * @param resource the data store resource attribute
     * @param location the data store location attribute
     * @param config the data store config attribute
     * @param version the data store version attribute
     */
    public DhcpDatastore getDhcpDatastore() {
	return (new DhcpDatastore(getResource(), getPath(),
	    getConfig(), getResourceVersion()));
    } // getDhcpDatastore

    /**
     * Set the resource (aka data store) in which DHCP data is stored.
     * This automatically also sets the run mode to server.
     * @param s Unique name of resource
     */
    public void setResource(String s) {
    	set(DSVC_CK_RESOURCE, s);
    }

    /**
     * Retrieve the name of the resource/data store used for DHCP.
     * @return The unique name of the resource; null if not set
     */
    public String getResource() {
    	return valueOf(DSVC_CK_RESOURCE);
    }

    /**
     * Set the version of the resource in which DHCP data is stored.
     * @param i version number
     */
    public void setResourceVersion(int i) {
    	set(DSVC_CK_CONVER, Integer.toString(i));
    }

    /**
     * Retrieve the version of the resource/data store used for DHCP.
     * @return The version number or -1 if not valid.
     */
    public int getResourceVersion() {
	try {
	    return Integer.parseInt(valueOf(DSVC_CK_CONVER));
	} catch (NumberFormatException e) {
	    return -1;
	}
    }

    /**
     * Set the path within the resource in which to place the tables.
     * For files, this is a Unix pathname; for NIS+, the directory name.
     * @param s The path
     */
    public void setPath(String s) {
    	set(DSVC_CK_PATH, s);
    }

    /**
     * Get the path used for data storage.
     * @return The path within the resource; null if not set
     */
    public String getPath() {
    	return valueOf(DSVC_CK_PATH);
    }

    /**
     * Set the config for the resource.
     * @param s The config
     */
    public void setConfig(String s) {
	if (s != null) {
	    set(DSVC_CK_RESOURCE_CONFIG, s);
	} else {
	    clear(DSVC_CK_RESOURCE_CONFIG);
	}
    }

    /**
     * Get the config for data store.
     * @return The config; null if not set
     */
    public String getConfig() {
    	return valueOf(DSVC_CK_RESOURCE_CONFIG);
    }

    /**
     * Set the hosts resource (aka data store) in which host data is stored.
     * @param s Unique name of resource
     */
    public void setHostsResource(String s) {
    	set(DSVC_CK_HOSTS_RESOURCE, s);
    }

    /**
     * Retrieve the name of the resource/data store used for hosts.
     * @return The unique name of the resource; null if not set
     */
    public String getHostsResource() {
    	return valueOf(DSVC_CK_HOSTS_RESOURCE);
    }

    /**
     * Set the domain within the hosts resource in which to place the tables.
     * For files resource, this value is meaningless.
     * @param s The domain
     */
    public void setHostsDomain(String s) {
    	set(DSVC_CK_HOSTS_DOMAIN, s);
    }

    /**
     * Get the domain used for hosts data storage.
     * @return The domain within the resource; null if not set
     */
    public String getHostsDomain() {
    	return valueOf(DSVC_CK_HOSTS_DOMAIN);
    }

    /**
     * Test whether BOOTP compatibility is enabled.
     * @return true if BOOTP compatibility is enabled.
     */
    public boolean isBootpCompatible() {
	return isSet(DSVC_CK_BOOTP_COMPAT);
    }

    /**
     * Enable or disable BOOTP compatibility.
     * @param state true if BOOTP compatibility is enabled, false if not.
     * @param isAutomatic true if automatic allocation is allowed.
     */
    public void setBootpCompatible(boolean state, boolean isAutomatic) {
	if (state) {
	    if (isAutomatic) {
		set(DSVC_CK_BOOTP_COMPAT, DSVC_CV_AUTOMATIC);
	    } else {
		set(DSVC_CK_BOOTP_COMPAT, DSVC_CV_MANUAL);
	    }
	} else {
	    clear(DSVC_CK_BOOTP_COMPAT);
	}
    }

    /**
     * Test whether BOOTP compatibility is automatic or manual
     * @return true if BOOTP compatibility is automatic.
     */
    public boolean isBootpAutomatic() {
	return DSVC_CV_AUTOMATIC.equals(valueOf(DSVC_CK_BOOTP_COMPAT));
    }

    /**
     * Test whether relay hop limit is set.
     * @return true if the limit is set, false if default value is used.
     */
    public boolean isRelayHops() {
	return isSet(DSVC_CK_RELAY_HOPS);
    }

    /**
     * Set the relay hop limit.
     * @param state true if hop limit should be set, false if not
     * @param hops Number of hops to limit forwarding to
     */
    public void setRelayHops(boolean state, Integer hops) {
	if (state) {
	    set(DSVC_CK_RELAY_HOPS, hops.toString());
	} else {
	    clear(DSVC_CK_RELAY_HOPS);
	}
    }

    /**
     * Get the relay hop limit.
     * @return The number of hops currently set, or null if this isn't set.
     */
    public Integer getRelayHops() {
	String hops = valueOf(DSVC_CK_RELAY_HOPS);
	if (hops != null) {
	    return new Integer(hops);
	} else {
	    return null;
	}
    }

    /**
     * Test whether a network interface list is set; failure to set an interface
     * list implies that all interfaces will be monitored.
     * @return true if an interface list is set
     */
    public boolean isInterfaces() {
	return isSet(DSVC_CK_INTERFACES);
    }

    /**
     * Set the network interface list.
     * @param state true if interface list is to be set, false if it should be
     * cleared
     * @param list A comma-separated list of interface names
     */
    public void setInterfaces(boolean state, String list) {
	if (state) {
	    set(DSVC_CK_INTERFACES, list);
	} else {
	    clear(DSVC_CK_INTERFACES);
	}
    }

    /**
     * Get the list of network interfaces.
     * @return The comma-separated list of interfaces; null if not set
     */
    public String getInterfaces() {
	return valueOf(DSVC_CK_INTERFACES);
    }

    /**
     * Test whether ICMP address verification is enabled
     * @return true if ICMP verification is performed
     */
    public boolean isICMPVerify() {
	/*
	 * Use this double-inverse comparison so that the default behavior of
	 * ICMP enabled is handled correctly.
	 */
	return !DSVC_CV_FALSE.equals(valueOf(DSVC_CK_ICMP_VERIFY));
    }

    /**
     * Set ICMP verification
     * @param state true if verification should be done, false otherwise
     */
    public void setICMPVerify(boolean state) {
	set(DSVC_CK_ICMP_VERIFY, state ? DSVC_CV_TRUE : DSVC_CV_FALSE);
    }

    /**
     * Test whether offer cache timeout is set
     * @return true if it is set
     */
    public boolean isOfferTtl() {
	return isSet(DSVC_CK_OFFER_CACHE_TIMEOUT);
    }

    /**
     * Set offer cache timeout value
     * @param state true if offer cache timeout value is set, false if server's
     * default will be used instead
     * @param time Number of seconds to hold offers in the cache
     */
    public void setOfferTtl(boolean state, Integer time) {
	if (state) {
	    set(DSVC_CK_OFFER_CACHE_TIMEOUT, time.toString());
	} else {
	    clear(DSVC_CK_OFFER_CACHE_TIMEOUT);
	}
    }

    /**
     * Get the offer cache timeout value
     * @return timeout value set, or null if server default is used
     */
    public Integer getOfferTtl() {
	String s = valueOf(DSVC_CK_OFFER_CACHE_TIMEOUT);
	if (s != null) {
	    return new Integer(s);
	} else {
	    return null;
	}
    }

    /**
     * Test whether server is running in relay mode
     * @return true if running as relay
     */
    public boolean isRelay() {
	return DSVC_CV_RELAY.equals(valueOf(DSVC_CK_RUN_MODE));
    }

    /**
     * Set relay mode and server list
     * @param state true if relay mode is desired, false for normal server
     * @param servers list of servers to which requests should be forwarded
     */
    public void setRelay(boolean state, String servers) {
	if (state) {
	    set(DSVC_CK_RELAY_DESTINATIONS, servers);
	} else {
	    clear(DSVC_CK_RELAY_DESTINATIONS);
	}
    }

    /**
     * Get list of server targets for relay
     * @return list of relay targets; null if not set
     */
    public String getRelay() {
	return valueOf(DSVC_CK_RELAY_DESTINATIONS);
    }

    /**
     * Test for server automatic reload of dhcptab
     * @return true if server is rescanning dhcptab
     */
    public boolean isRescan() {
	return isSet(DSVC_CK_RESCAN_INTERVAL);
    }

    /**
     * Set the rescan interval
     * @param state true if rescanning is enabled, false if not
     * @param interval number of minutes between rescans
     */
    public void setRescan(boolean state, Integer interval) {
	if (state) {
	    set(DSVC_CK_RESCAN_INTERVAL, interval.toString());
	} else {
	    clear(DSVC_CK_RESCAN_INTERVAL);
	}
    }

    /**
     * Get the rescan interval
     * @return the rescan interval in minutes, or null if rescan is not enabled
     */
    public Integer getRescan() {
	String s = valueOf(DSVC_CK_RESCAN_INTERVAL);
	if (s != null) {
	    return new Integer(s);
	} else {
	    return null;
	}
    }

    /**
     * Test whether ownerip
     * @return true if ownerip
     */
    public boolean isOwnerip() {
	return isSet(DSVC_CK_OWNER_IP);
    }

    /**
     * Set ownerip server list
     * @param state true if ownerip is desired, false for normal server
     * @param ownerips list of servers ownerips
     */
    public void setOwnerip(boolean state, String ownerips) {
	if (state) {
	    set(DSVC_CK_OWNER_IP, ownerips);
	} else {
	    clear(DSVC_CK_OWNER_IP);
	}
    }

    /**
     * Get list of server targets for ownerip
     * @return list of ownerip targets; null if not set
     */
    public String getOwnerip() {
	return valueOf(DSVC_CK_OWNER_IP);
    }


    /**
     * Test for server dynamic DNS updates
     * @return true if server is updating DNS
     */
    public boolean isDnsUpdated() {
	return isSet(DSVC_CK_NSU_TIMEOUT);
    }

    /**
     * Set the DNS update timeout value
     * @param state true if DNS updates are enabled, false if not
     * @param timeout number of seconds before timeout
     */
    public void setDnsTimeout(boolean state, Integer timeout) {
	if (state) {
	    set(DSVC_CK_NSU_TIMEOUT, timeout.toString());
	} else {
	    clear(DSVC_CK_NSU_TIMEOUT);
	}
    }

    /**
     * Get the DNS update timeout value
     * @return the timeout in seconds, or null if DNS updates are not enabled
     */
    public Integer getDnsTimeout() {
	String s = valueOf(DSVC_CK_NSU_TIMEOUT);
	if (s != null) {
	    return new Integer(s);
	} else {
	    return null;
	}
    }

    /**
     * Test for verbose logging mode
     * @return true if verbose logging, false for normal
     */
    public boolean isVerbose() {
	return DSVC_CV_TRUE.equals(valueOf(DSVC_CK_VERBOSE));
    }

    /**
     * Set verbose logging mode
     * @param state true for verbose, false for normal
     */
    public void setVerbose(boolean state) {
	set(DSVC_CK_VERBOSE, state ? DSVC_CV_TRUE : DSVC_CV_FALSE);
    }


    /**
     * Test for transaction logging mode.
     * @return true if transaction logging is enabled
     */
    public boolean isLogging() {
    	return isSet(DSVC_CK_LOGGING_FACILITY);
    }

    /**
     * Get the syslog facility number used for transaction logging
     * @return facility number, which will be between 0 and 7
     */
    public Integer getLogging() {
	String s = valueOf(DSVC_CK_LOGGING_FACILITY);
    	if (s != null) {
	    return new Integer(s);
	} else {
	    return null;
	}
    }

    /**
     * Set transaction logging
     * @param state true to enable transaction logging, false to disable
     * @param value syslog facility number 0-7 used for logging
     */
    public void setLogging(boolean state, Integer value) {
        if (state) {
	    set(DSVC_CK_LOGGING_FACILITY, value.toString());
	} else {
	    clear(DSVC_CK_LOGGING_FACILITY);
	}
    }

    /**
     * Get the list of logging facility choices
     * @return an array of facility numbers
     */
    public static Integer [] getLoggingFacilities() {
    	return loggingFacilities;
    }

    /**
     * Return an indicator of whether the parameters may have been changed
     * by a set() or a clear() since the last call to clearDirty().
     *
     * @return
     *   True if a set() or a clear() has occurred since the last call to
     *   clearDirty(), otherwise false.
     */
    public boolean isDirty() {
	return dirty;
    }

    /**
     * Set the dirty indicator to false. Any subsequent calls to set() or
     * clear() may set the dirty flag.
     */
    public void clearDirty() {
	dirty = false;
    }

    /**
     * Get the parameters qualifier.
     *
     * @param key
     *   Parameters keyword.
     * @return
     *   The qualifier for the parameter if one exists, otherwise null.
     */
    public Qualifier getQualifier(String key) {
	Qualifier qualifier = null;

	if (key.equals(DSVC_CK_BOOTP_COMPAT)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_BOOTP_COMPAT, false, false,
			    new QualifierStringEnum(
				new String[] {
				    DSVC_CV_AUTOMATIC,
				    DSVC_CV_MANUAL
				}));
	} else if (key.equals(DSVC_CK_CACHE_TIMEOUT)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_CACHE_TIMEOUT, false, false,
			    new QualifierIntegerRange(
				0,
				Integer.MAX_VALUE));

	} else if (key.equals(DSVC_CK_CONVER)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_CONVER, true, false,
			    new QualifierInteger());

	} else if (key.equals(DSVC_CK_DAEMON_ENABLED)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_DAEMON_ENABLED, true, false,
			    new QualifierBoolean(
				DSVC_CV_TRUE,
				DSVC_CV_FALSE));

	} else if (key.equals(DSVC_CK_DBG_MEMORY_NET)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_DBG_MEMORY_NET, false, true,
			    new QualifierIntegerRange(
				0,
				Integer.MAX_VALUE));

	} else if (key.equals(DSVC_CK_DBG_PORT_OFFSET)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_DBG_PORT_OFFSET, false, true,
			    new QualifierIntegerRange(
				0,
				Integer.MAX_VALUE));

	} else if (key.equals(DSVC_CK_HOSTS_DOMAIN)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_HOSTS_DOMAIN, true, false,
			    new QualifierStringEnum(
				new String[] {
				    DSVC_CV_DNS
				}));
	} else if (key.equals(DSVC_CK_HOSTS_RESOURCE)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_HOSTS_RESOURCE, true, false,
			    new QualifierStringEnum(
				new String[] {
				    DSVC_CV_DNS,
				    DSVC_CV_FILES
				}));
	} else if (key.equals(DSVC_CK_ICMP_VERIFY)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_ICMP_VERIFY, false, false,
			    new QualifierBoolean(
				DSVC_CV_TRUE,
				DSVC_CV_FALSE));

	} else if (key.equals(DSVC_CK_INTERFACES)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_INTERFACES, false, false,
			    new QualifierArray(
				new QualifierString()));

	} else if (key.equals(DSVC_CK_LEASE_MIN_LRU)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_LEASE_MIN_LRU, false, true,
			    new QualifierIntegerRange(
				0,
				Integer.MAX_VALUE));

	} else if (key.equals(DSVC_CK_LOGGING_FACILITY)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_LOGGING_FACILITY, false, false,
			    new QualifierIntegerRange(
				DSVC_CV_LOGGING_FACILITY_MIN,
				DSVC_CV_LOGGING_FACILITY_MAX));

	} else if (key.equals(DSVC_CK_MAX_CLIENTS)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_MAX_CLIENTS, false, true,
			    new QualifierIntegerRange(
				-1,
				Integer.MAX_VALUE));

	} else if (key.equals(DSVC_CK_MAX_THREADS)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_MAX_THREADS, false, true,
			    new QualifierIntegerRange(
				-1,
				Integer.MAX_VALUE));

	} else if (key.equals(DSVC_CK_OFFER_CACHE_TIMEOUT)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_OFFER_CACHE_TIMEOUT, false, false,
			    new QualifierIntegerRange(
				0,
				Integer.MAX_VALUE));

	} else if (key.equals(DSVC_CK_PATH)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_PATH, true, false,
			    new QualifierString());

	} else if (key.equals(DSVC_CK_RELAY_DESTINATIONS)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_RELAY_DESTINATIONS, false, false,
			    new QualifierArray(
				new QualifierOr(
				    new QualifierFQDN(),
				    new QualifierIPv4())));

	} else if (key.equals(DSVC_CK_RELAY_HOPS)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_RELAY_HOPS, false, false,
			    new QualifierIntegerRange(
				0,
				Integer.MAX_VALUE));

	} else if (key.equals(DSVC_CK_RESCAN_INTERVAL)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_RESCAN_INTERVAL, false, false,
			    new QualifierIntegerRange(
				0, Integer.MAX_VALUE));

	} else if (key.equals(DSVC_CK_OWNER_IP)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_OWNER_IP, false, false,
			    new QualifierArray(
				new QualifierIPv4()));

	} else if (key.equals(DSVC_CK_RESOURCE)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_RESOURCE, true, false,
			    new QualifierString());

	} else if (key.equals(DSVC_CK_RESOURCE_CONFIG)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_RESOURCE_CONFIG, true, false,
			    new QualifierString());

	} else if (key.equals(DSVC_CK_RUN_MODE)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_RUN_MODE, true, false,
			    new QualifierStringEnum(
				new String[] {
				    DSVC_CV_SERVER,
				    DSVC_CV_RELAY
				}));
	} else if (key.equals(DSVC_CK_RENOG_INTERVAL)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_RENOG_INTERVAL, false, false,
			    new QualifierIntegerRange(
				0,
				Integer.MAX_VALUE));

	} else if (key.equals(DSVC_CK_NSU_TIMEOUT)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_NSU_TIMEOUT, false, false,
			    new QualifierIntegerRange(
				-1,
				Integer.MAX_VALUE));

	} else if (key.equals(DSVC_CK_VERBOSE)) {
	    qualifier =
		    new QualifierImpl(DSVC_CK_VERBOSE, false, false,
			    new QualifierBoolean(
				DSVC_CV_TRUE,
				DSVC_CV_FALSE));
	}

	return qualifier;
    }

    /**
     * Convert this object to a String representation
     */
    public String toString() {
	StringBuffer b = new StringBuffer();
	for (int i = 0; i < options.size(); ++i) {
	    DhcpResource res = (DhcpResource)options.get(i);
	    b.append(res.getKey());
	    String s = res.getValue();
	    if (s != null) {
		b.append('=');
		b.append(s);
	    }
	    b.append('\n');
	}
	return b.toString();
    }
}
