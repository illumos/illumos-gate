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

//  TemplateRegistry.java:
//  Author:           James Kempf
//  Created On:       Fri Jul  4 11:38:39 1997
//  Last Modified By: James Kempf
//  Last Modified On: Mon Jun  1 13:41:07 1998
//  Update Count:     26
//

package com.sun.slp;

import java.util.*;

/**
 * Classes subclassing the <b>TemplateRegistry</b> class register and
 * unregister service templates, look up the template URL's based on the
 * service type name, and return attribute verifiers for verifying
 * template attributes.
 *
 * @author James Kempf
 *
 */

public abstract class TemplateRegistry extends Object {

    protected static TemplateRegistry templateRegistry = null;

    /**
     * The property accessor for the TemplateRegistry.
     *
     * @return The TemplateRegistry object.
     * @exception ServiceLocationException If the registry can't be created.
     */

    public static TemplateRegistry getTemplateRegistry()
	throws ServiceLocationException
    {

	if (templateRegistry == null) {
	    templateRegistry = new SLPTemplateRegistry();

	}

	return templateRegistry;
    }

    /**
     * Register the new service.
     *
     * @param <i>serviceType</i>		Name of the service.
     * @param <i>documentURL</i>		URL of the template document.
     * @param <i>languageLocale</i>	Locale of the template langugae.
     * @param <i>version</i>		Version number of template document.
     * @exception ServiceLocationException If the registration fails.
     * @exception IllegalArgumentException Thrown if any parameters are null.
     *
     */

    abstract public void
	registerServiceTemplate(ServiceType serviceType,
				String documentURL,
				Locale languageLocale,
				String version)
	throws ServiceLocationException;

    /**
     * Deregister the template for service type.
     *
     * @param <i>serviceType</i>	Name of service.
     * @param <i>languageLocale</i> Language locale of template.
     * @param <i>version</i> Version of the template, null for latest.
     * @exception ServiceLocationException Thrown if the template
     *	 		is not registered.
     * @exception IllegalArgumentException Thrown if the serviceType or
     *					  languageLocale parameter is null.
     *
     */

    abstract public void
	deregisterServiceTemplate(ServiceType serviceType,
				  Locale languageLocale,
				  String version)
	throws ServiceLocationException;

    /**
     * Find the document URL for the service.
     *
     * @param <i>serviceType</i>		Name of service.
     * @param <i>languageLocale</i> Language locale of template.
     * @param <i>version</i> Version of the template, null for latest.
     * @return <b>String</b> for the service's template document.
     *         If the service doesn't exist, returns null.
     * @exception ServiceLocationException If more than one template
     *					  document URL is returned.
     *</blockquote>
     * @exception IllegalArgumentException Thrown if the service type or
     *					  languageLocal parameter is null.
     *
     */

    abstract public String
	findTemplateURL(ServiceType serviceType,
			Locale languageLocale,
			String version)
	throws ServiceLocationException;

    /**
     * Create an attribute verifier for the template document URL.
     *
     * @param <i>documentURL</i> A URL for the template document.
     * @return An attribute verifier for the service
     * @exception ServiceLocationException If a parse error occurs or
     *					  if the document can't be found.
     * @exception IllegalArgumentException Thrown if any parameters are null.
     *
     */

    abstract public
	ServiceLocationAttributeVerifier attributeVerifier(String documentURL)
	throws ServiceLocationException;
}
