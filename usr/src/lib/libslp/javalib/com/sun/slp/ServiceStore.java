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

//  ServiceStore.java: Interface for different storage implementations
//  Author:           James Kempf
//  Created On:       Thu Oct 16 07:46:45 1997
//  Last Modified By: James Kempf
//  Last Modified On: Wed Feb 17 09:28:53 1999
//  Update Count:     91
//

package com.sun.slp;

import java.util.*;
import java.io.*;

/**
 * ServiceStore specifies the interface between the storage back end for
 * the SLP DA/slpd and the communications front end. There can be
 * various implementations of the ServiceStore. The ServiceStoreFactory
 * class is responsible for instantiating the ServiceStore object.
 * Each ServiceStore implementation must also supply ServiceRecord
 * objects.
 *
 * @author James Kempf
 */

interface ServiceStore {

    /**
     * Key for fetching attribute values from findAttributes() returned
     * hashtable.
     */

    final static String FA_ATTRIBUTES = "FA_ATTRIBUTES";

    /**
     * Key for fetching attribute auth block from findAttributes() returned
     * hashtable.
     */

    final static String FA_SIG = "FA_SIG";

    /**
     * Key for fetching hashtable of service URLs v.s. scopes values from
     * findServices() returned hashtable.
     */

    final static String FS_SERVICES = "FS_SERVICES";

    /**
     * Key for fetching hashtable of service URLs v.s. signatures from
     * findServices() returned hashtable.
     */

    final static String FS_SIGTABLE = "FS_SIGTABLE";

    /**
     * The ServiceRecord interface specifies the record structure of
     * stored in the ServiceStore. The methods are all property
     * accessors.
     *
     * @author James Kempf
     */

    interface ServiceRecord {

	/**
	 * Return the ServiceURL for the record.
	 *
	 * @return The record's service URL.
	 */

	ServiceURL getServiceURL();

	/**
	 * Return the Vector of ServiceLocationAttribute objects for the record
	 *
	 * @return Vector of ServiceLocationAttribute objects for the record.
	 */

	Vector getAttrList();

	/**
	 * Return the locale in which this record is registered.
	 *
	 * @return The language locale in which this record is registered.
	 */

	Locale getLocale();

	/**
	 * Return the Vector of scopes in which this record is registered.
	 *
	 * @return The Vector of scopes in which this record is registered.
	 */

	Vector getScopes();

	/**
	 * Return the expiration time for the record. This informs the
	 * service store when the record should expire and be removed
	 * from the table.
	 *
	 * @return The expiration time for the record.
	 */

	long getExpirationTime();

	/**
	 * Return the URL signature, or null if there's none.
	 *
	 * @return auth block Hashtable for URL signature.
	 */

	Hashtable getURLSignature();

	/**
	 * Return the attribute signature, or null if there's none.
	 *
	 * @return auth block Hashtable for attribute signature.
	 */

	Hashtable getAttrSignature();

    }

    //
    // ServiceStore interface methods.
    //

    /**
     * On first call, return the time since the last stateless reboot
     * of the ServiceStore for a stateful store. Otherwise, return the
     * current time. This is for DAs.
     *
     * @return A Long giving the time since the last stateless reboot,
     *         in NTP format.
     */

    long getStateTimestamp();

    /**
     * Age out all records whose time has expired.
     *
     * @param deleted A Vector for return of ServiceStore.Service records
     *		     containing deleted services.
     * @return The time interval until another table walk must be done,
     *         in milliseconds.
     *
     */

    long ageOut(Vector deleted);

    /**
     * Create a new registration with the given parameters.
     *
     * @param url The ServiceURL.
     * @param attrs The Vector of ServiceLocationAttribute objects.
     * @param locale The Locale.
     * @param scopes Vector of scopes in which this record is registered.
     * @param urlSig Hashtable for URL signatures, or null if none.
     * @param attrSig Hashtable for URL signatures, or null if none.
     * @return True if there is an already existing registration which
     *         this one replaced.
     * @exception ServiceLocationException Thrown if any
     *			error occurs during registration or if the table
     * 			requires a network connection that failed. This
     *			includes timeout failures.
     */

    boolean register(ServiceURL url, Vector attrs,
		     Vector scopes, Locale locale,
		     Hashtable urlSig, Hashtable attrSig)
	throws ServiceLocationException;

    /**
     * Deregister a ServiceURL from the database for every locale
     * and every scope. There will be only one record for each URL
     * and locale deregistered, regardless of the number of scopes in
     * which the URL was registered, since the attributes will be the
     * same in each scope if the locale is the same.
     *
     * @param url The ServiceURL
     * @param scopes Vector of scopes.
     * @param urlSig The URL signature, if any.
     * @exception ServiceLocationException Thrown if the
     *			ServiceStore does not contain the URL, or if any
     *			error occurs during the operation, or if the table
     * 			requires a network connection that failed. This
     *			includes timeout failures.
     */

    void deregister(ServiceURL url, Vector scopes, Hashtable urlSig)
	throws ServiceLocationException;

    /**
     * Update the service registration with the new parameters, adding
     * attributes and updating the service URL's lifetime.
     *
     * @param url The ServiceURL.
     * @param attrs The Vector of ServiceLocationAttribute objects.
     * @param locale The Locale.
     * @param scopes Vector of scopes in which this record is registered.
     * @exception ServiceLocationException Thrown if any
     *			error occurs during registration or if the table
     * 			requires a network connection that failed. This
     *			includes timeout failures.
     */

    void updateRegistration(ServiceURL url, Vector attrs,
			    Vector scopes, Locale locale)
	throws ServiceLocationException;

    /**
     * Delete the attributes from the ServiceURL object's table entries.
     * Delete for every locale that has the attributes and every scope.
     * Note that the attribute tags must be lower-cased in the locale of
     * the registration, not in the locale of the request.
     *
     * @param url The ServiceURL.
     * @param scopes Vector of scopes.
     * @param attrTags The Vector of String
     *			objects specifying the attribute tags of
     *			the attributes to delete.
     * @param locale Locale of the request.
     * @exception ServiceLocationException Thrown if the
     *			ServiceStore does not contain the URL or if any
     *			error occurs during the operation or if the table
     * 			requires a network connection that failed. This
     *			includes timeout failures.
     */

    void
	deleteAttributes(ServiceURL url,
			 Vector scopes,
			 Vector attrTags,
			 Locale locale)
    throws ServiceLocationException;

    /**
     * Return a Vector of String containing the service types for this
     * scope and naming authority. If there are none, an empty vector is
     * returned.
     *
     * @param namingAuthority The namingAuthority, or "*" if for all.
     * @param scopes The scope names.
     * @return A Vector of String objects that are the type names, or
     *		an empty vector if there are none.
     * @exception ServiceLocationException Thrown if any
     *			error occurs during the operation or if the table
     * 			requires a network connection that failed. This
     *			includes timeout failures.
     */

    Vector findServiceTypes(String namingAuthority, Vector scopes)
	throws ServiceLocationException;

    /**
     * Return a Hashtable with the key FS_SERVICES matched to the
     * hashtable of ServiceURL objects as key and a vector
     * of their scopes as value, and the key FS_SIGTABLE
     * matched to a hashtable with ServiceURL objects as key
     * and the auth block Hashtable for the URL (if any) for value. The
     * returned service URLs will match the service type, scope, query,
     * and locale. If there are no signatures, the FS_SIGTABLE
     * key returns null. If there are no
     * registrations in any locale, FS_SERVICES is bound to an
     * empty table.
     *
     * @param serviceType The service type name.
     * @param scope The scope name.
     * @param query The query, with any escaped characters as yet unprocessed.
     * @param locale The locale in which to lowercase query and search.
     * @return A Hashtable with the key FS_SERVICES matched to the
     *         hashtable of ServiceURL objects as key and a vector
     *         of their scopes as value, and the key FS_SIGTABLE
     *         matched to a hashtable with ServiceURL objects as key
     *         and the auth block Hashtable for the URL (if any) for value.
     *         If there are no registrations in any locale, FS_SERVICES
     *	      is bound to an empty table.
     * @exception ServiceLocationException Thrown if a parse error occurs
     *			during query parsing or if any
     *			error occurs during the operation or if the table
     * 			requires a network connection that failed. This
     *			includes timeout failures.
     */

    Hashtable findServices(String serviceType,
			   Vector scopes,
			   String query,
			   Locale locale)
    throws ServiceLocationException;

    /**
     * Return a Hashtable with key FA_ATTRIBUTES matched to the
     * vector of ServiceLocationAttribute objects and key FA_SIG
     * matched to the auth block Hashtable for the attributes (if any)
     * The attribute objects will have tags matching the tags in
     * the input parameter vector. If there are no registrations in any locale,
     * FA_ATTRIBUTES is an empty vector.
     *
     * @param url The ServiceURL for which the records should be returned.
     * @param scopes The scope names for which to search.
     * @param attrTags The Vector of String
     *			objects containing the attribute tags.
     * @param locale The locale in which to lower case tags and search.
     * @return A Hashtable with a vector of ServiceLocationAttribute objects
     *         as the key and the auth block Hashtable for the attributes
     *         (if any) as the value.
     *         If there are no registrations in any locale, FA_ATTRIBUTES
     *         is an empty vector.
     * @exception ServiceLocationException Thrown if any
     *			error occurs during the operation or if the table
     * 			requires a network connection that failed. This
     *			includes timeout failures. An error should be
     *			thrown if the tag vector is for a partial request
     *			and any of the scopes are protected.
     */

    Hashtable findAttributes(ServiceURL url,
			     Vector scopes,
			     Vector attrTags,
			     Locale locale)
	throws ServiceLocationException;

    /**
     * Return a Vector of ServiceLocationAttribute objects with attribute tags
     * matching the tags in the input parameter vector for all service URL's
     * of the service type. If there are no registrations
     * in any locale, an empty vector is returned.
     *
     * @param serviceType The service type name.
     * @param scopes The scope names for which to search.
     * @param attrTags The Vector of String
     *			objects containing the attribute tags.
     * @param locale The locale in which to lower case tags.
     * @return A Vector of ServiceLocationAttribute objects matching the query.
     *         If no match occurs but there are registrations
     * 	      in other locales, null is returned. If there are no registrations
     *         in any locale, an empty vector is returned.
     * @exception ServiceLocationException Thrown if any
     *		 error occurs during the operation or if the table
     * 		 requires a network connection that failed. This
     *		 includes timeout failures. An error should also be
     *            signalled if any of the scopes are protected.
     */

    Vector findAttributes(String serviceType,
			  Vector scopes,
			  Vector attrTags,
			  Locale locale)
	throws ServiceLocationException;

    /**
     * Dump the service store to the log.
     *
     */

    void dumpServiceStore();

    /**
     * Obtain the record matching the service URL and locale.
     *
     * @param URL The service record to match.
     * @param locale The locale of the record.
     * @return The ServiceRecord object, or null if none.
     */

    public ServiceRecord
	getServiceRecord(ServiceURL URL, Locale locale);

    /**
     * Obtains service records with scopes matching from vector scopes.
     * If scopes is null, then returns all records.
     *
     * @param scopes Vector of scopes to match.
     * @return Enumeration   Of ServiceRecord Objects.
     */

    Enumeration getServiceRecordsByScope(Vector scopes);

}
