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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * SRMProviderDataModel.java
 */


package com.sun.wbem.solarisprovider.srm;

import javax.wbem.cim.*;

import java.util.LinkedHashMap;
import java.util.Iterator;
import java.util.Vector;

/**
 * This is the base class for the SRM provider data models.
 * @author Sun Microsystems
 */
abstract class SRMProviderDataModel implements SRMProviderProperties {

    /*
     * The updated flag is set if this data model has been updated, data model
     * be reomoved from their list.that hasn't been
     */
    private boolean		updated;
    private CIMObjectPath	op;   // the CIM object path to 'ci'
    protected CIMInstance	ci;   // the CIM instance of this data model
    protected Vector		opProperties; // object path properties

    /**
     * The keyValTab table contains, for each properties of the CIM class,
     * one entry, where the hash key is the key from the RDS protocol and
     * the hash value is a object of a class that implements the
     * PropertyAccessInterface interface. It knows the type of the property
     * and consequently how to access it.
     */
    protected LinkedHashMap   keyValTab;

    // Computer name, common for all instances
    protected static String csName = null;
    // OS name, common for all instances
    protected static String osName = null;
    // provider's key name
    protected String name = null;


    /**
     * Constructor, initialize the keyValTab. So, the setProperty() method can
     * find the suitable property access object.
     */
    public SRMProviderDataModel() {
	initKeyValTable();
    }

    /**
     * Get a cim object path to a Solaris_SRMxxy object.
     * @param cc - the class reference
     * @return	object path to a Solaris_SRMxxyy instance
     *		hosted by this object.
     */
    public CIMInstance getCIMInstance(CIMClass cc) {

        if (ci == null) {
            ci = cc.newInstance();
	    Iterator i = keyValTab.values().iterator();
	    while (i.hasNext()) {
		((PropertyAccessInterface) i.next()).
		    set(ci, PropertyAccessInterface.FLUSH, null);
	    }
	    setCIMInstance(true);
        }
        return ci;
    }

    /**
     * Get a CIM object path to the CIM instance hosted by this object.
     * @param elementName The name of the instance 
     * @return object path to the  CIM instance hosted by this object.
     */
    public CIMObjectPath getCIMObjectPath(String elementName) {

        if (op == null) {
            op = new CIMObjectPath(elementName);
            op.setNameSpace(NAMESPACE);
            if (opProperties == null) {
		opProperties = new Vector();
                setOpPropertiesVector();
            }
            op.setKeys(opProperties);
        }
        return op;
    }

    /**
     * Return all properties of this CIM instance as a string of name and
     * values pairs.
     * @return	String of properties name and value pairs.
     */
    public String toString() {

	Iterator i = keyValTab.values().iterator();
	StringBuffer sb = new StringBuffer();
	while (i.hasNext()) {
	    sb.append(((PropertyAccessInterface) i.next()).toString());
	}
	return sb.toString();
    }

    /**
     * Return all property values of this CIM instance as a string. The
     * values are in order defined in mof file and separated by ' '.
     * @return	String of property values separated by ' '.
     */
    public String toBulkData() {

	Iterator i = keyValTab.values().iterator();
	StringBuffer sb = new StringBuffer();
	sb.append(name +  ' ');
	while (i.hasNext()) {
	    sb.append(((PropertyAccessInterface) i.next()).getValue() + ' ');
	}
	sb.append("\n");
	return sb.toString();
    }

    /**
     * Set a property to the given value. Which property and how to access it
     * will be find in the keyValTab according to the given key.
     * @param	key	hash key value
     * @param	val	the property value
     */
    void setProperty(String key, String val) {

	PropertyAccessInterface ac;

	if ((ac = (PropertyAccessInterface) keyValTab.get(key)) == null) {
	    /* 
	     * The rds has sent unknown key value pair,
	     * just keep it secret
	     */
	} else {
	    /*
	     * Since, this method can be called before the cim instance has been
	     * created we have to check that.
	     * If ci hasn't been created keep the value in cache, otherwise
	     * write it through the cache into the CIM instance.
	     */
	    ac.set(ci, (ci == null) ? PropertyAccessInterface.CACHE :
		PropertyAccessInterface.CHECK_WTHROUGH, val);
	}

    } // end setProperty

    /**
     * If the value v is different form the current property value,
     * set a string property.
     * @param	b	force to set the property
     * @param	n	the name of the property
     * @param	v	the property value
     */
    void setStrProp(boolean b, String n,  String v) {

        if (b || v.equals((String) (ci.getProperty(n).getValue().getValue())))
	    ci.setProperty(n, new CIMValue(v));
    }

    /**
     * Should be used to mark this data model as updated.
     * @param	b	true marks this model as currently updated.
     */
    void setUpdated(boolean b) {
	updated = b;
    }

    /**
     * Returns true if this data model has been updated in the last update
     * process.
     * @return	the updated flag
     */
    boolean isUpdated() {
	return updated;
    }

    /**
     * Set additional properties, that can't be set through the setProperty
     * method.
     * @param	newInstance indicates a new instance and therefore force to
     * to set all properties.
     * @return	the updated flag
     */
    abstract protected void setCIMInstance(boolean newInstance);

    /**
     * Set the properties of the CIM object path instance. The properties
     * are saved in the opProperties class field.
     */
    abstract protected void setOpPropertiesVector();

    /**
     * Set the keyValTab hash table.
     * The keyValTab table contains, for each properties of the CIM class,
     * one entry, where the hash key is the key from the RDS protocol and
     * the hash value is a object of a class that implements the
     * PropertyAccessInterface interface. This object knows the type of
     * the property and consequently how to access it.
     */
    abstract protected void initKeyValTable();

} // end class SRMProviderDataModel
