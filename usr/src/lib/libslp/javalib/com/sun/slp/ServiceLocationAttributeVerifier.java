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

//  ServiceLocationAttributeVerifier.java: Attribute parser for SLP templates.
//  Author:           James Kempf
//  Created On:       Thu Jun 19 10:20:25 1997
//  Last Modified By: James Kempf
//  Last Modified On: Wed Jun 24 15:50:43 1998
//  Update Count:     22
//

package com.sun.slp;

import java.util.*;

/**
 * Classes implementing the <b>ServiceLocationAttributeVerifier</b> interface
 * parse SLP template definitions, provide information on attribute
 * definitions for service types, and verify whether a
 * <b>ServiceLocationAttribute</b> object matches a template for a particular
 * service type. Clients obtain <b>ServiceLocationAttributeVerifier</b>
 * objects for specific SLP service types through the <b>TemplateRegistry</b>.
 *
 * @author James Kempf
 *
 */

public interface ServiceLocationAttributeVerifier {

    /**
     * Returns the SLP service type for which this is the verifier.
     *
     * @return The SLP service type name.
     */

    public ServiceType getServiceType();

    /**
     * Returns the SLP language locale of this is the verifier.
     *
     * @return The SLP language locale.
     */

    public Locale getLocale();

    /**
     * Returns the SLP version of this is the verifier.
     *
     * @return The SLP version.
     */

    public String getVersion();

    /**
     * Returns the SLP URL syntax of this is the verifier.
     *
     * @return The SLP URL syntax.
     */

    public String getURLSyntax();

    /**
     * Returns the SLP description of this is the verifier.
     *
     * @return The SLP description.
     */

    public String getDescription();

    /**
     * Returns the <b>ServiceLocationAttributeDescriptor</b> object for the
     * attribute having the named id. IF no such attribute exists in the
     * template, returns null. This method is primarily for GUI tools to
     * display attribute information. Programmatic verification of attributes
     * should use the <b>verifyAttribute()</b> method.
     *
     * @param attrId Id of attribute to return.
     * @return The <b>ServiceLocationAttributeDescriptor<b> object
     * 	       corresponding to the parameter, or null if none.
     */

    public ServiceLocationAttributeDescriptor
	getAttributeDescriptor(String attrId);

    /**
     * Returns an <b>Enumeration</b> of
     * <b>ServiceLocationAttributeDescriptors</b> for the template. This method
     * is primarily for GUI tools to display attribute information.
     * Programmatic verification of attributes should use the
     * <b>verifyAttribute()</b> method. Note that small memory implementations
     * may want to implement the <b>Enumeration</b> so that attributes are
     * parsed on demand rather than at creation time.
     *
     * @return A <b>Dictionary</b> with attribute id's as the keys and
     *	      <b>ServiceLocationAttributeDescriptor</b> objects for the
     *	      attributes as the values.
     */

    public Enumeration getAttributeDescriptors();

    /**
     * Verify that the attribute parameter is a valid SLP attribute.
     *
     * @param <i>attribute</i> The <b>ServiceLocationAttribute</b> to be
     *			      verified.
     * @exception ServiceLocationException Thrown if the
     *		 attribute vector is not valid. The message contains
     *		 information on the attribute name and problem, and
     *		 the error code is <b>ServiceLocation.PARSE_ERROR</b>.
     */

    public void verifyAttribute(ServiceLocationAttribute attribute)
	throws ServiceLocationException;

    /**
     * Verify that the set of registration attributes matches the
     * required attributes for the service.
     *
     * @param <i>attributeVector</i> A <b>Vector</b> of
     *				    <b>ServiceLocationAttribute</b> objects
     *				    for the registration.
     * @exception ServiceLocationException Thrown if the
     *		 attribute vector is not valid. The message contains
     *		 information on the attribute name and problem, and
     *		 the error code is <b>ServiceLocation.PARSE_ERROR</b>.
     */

    public void verifyRegistration(Vector attributeVector)
	throws ServiceLocationException;
}
