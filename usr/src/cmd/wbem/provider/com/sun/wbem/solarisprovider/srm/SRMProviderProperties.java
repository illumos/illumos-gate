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
 * SRMProviderProperties.java
 */


package com.sun.wbem.solarisprovider.srm;

/**
 * This class defines common properties used in Acacia
 * providers.
 * @author SMI
 */
public interface SRMProviderProperties {

    // Solaris classes
    
    /**
     * CIM class name
     */
    static final String SOLARIS_ACTIVEPROJECT = "Solaris_ActiveProject";

    /**
     * CIM class name
     */
    static final String SOLARIS_ACTIVEUSER = "Solaris_ActiveUser";

    /**
     * CIM class name
     */
    static final String SOLARIS_ACTIVEUSERPROCESSAGGREGATESTATISTICS =
                        "Solaris_ActiveUserProcessAggregateStatistics";

    /**
     * CIM class name
     */
    static final String SOLARIS_ACTIVEPROJECTPROCESSAGGREGATESTATISTICS =
                        "Solaris_ActiveProjectProcessAggregateStatistics";
    
    /**
     * CIM class name
     */
    static final String SOLARIS_PROCESSSTATISTICS  =
                        "Solaris_ProcessStatistics";
    
    /**
     * CIM class name
     */
    static final String SOLARIS_PROCESSSTATISTICALINFORMATION  =
                        "Solaris_ProcessStatisticalInformation";
    
    /**
     * CIM class name
     */
    static final String SOLARIS_PROCESS  =
                        "Solaris_Process";
    
    /**
     * CIM class name
     */
    static final String SOLARIS_PROCESSAGGREGATESTATISTICALINFORMATION  =
                        "Solaris_ProcessAggregateStatisticalInformation";
    
    /**
     * CIM class name
     */
    static final String SOLARIS_USERPROCESSAGGREGATESTATISTICALINFORMATION  =
                        "Solaris_UserProcessAggregateStatisticalInformation";
    
    /**
     * CIM class name
     */
    static final String SOLARIS_PROJECTPROCESSAGGREGATESTATISTICALINFORMATION  =
                        "Solaris_ProjectProcessAggregateStatisticalInformation";
    
    /**
     * CIM class name
     */
    static final String SOLARIS_PROCESSAGGREGATESTATISTICS  =
                        "Solaris_ProcessAggregateStatistics";

    
    // Common properties
    
    /**
     * Reference to the monitoring object
     */
    static final String ELEMENT  = "Element";
    
    /**
     * Reference to the statistical information object
     */
    static final String STATS    = "Stats";
    static final String NAME	 = "Name";
    
    /**
     * The scoping ComputerSystem's CreationClassName.
     */
    static final String CSCREATIONCLASSNAME =	"CSCreationClassName";
    
    /**
     * The scoping ComputerSystem's Name.
     */
    static final String CSNAME =		"CSName";
    
    /**
     * The key of CSNAME property in RDS protocol
     */
    static final String CSNAME_KEY =		"sys_name";
    
    /**
     * The scoping OperatingSystem's CreationClassName.
     */
    static final String OSCREATIONCLASSNAME =	"OSCreationClassName";
    
    /**
     * The scoping OperatingSystem's Name.
     */
    static final String OSNAME =		"OSName";
    
    /**
     * The key of OSNAME property in RDS protocol
     */
    static final String OSNAME_KEY =		"sys_nodename";

    /** 
     * CreationClassName indicates the name of the class or the subclass
     * used in the creation of an instance. When used with the other key
     * properties of this class, this property allows all instances of
     * this class and its subclasses to be uniquely identified.
     */
    static final String CREATIONCLASSNAME =	"CreationClassName";
    
    /**
     * The scoping ComputerSystem's CreationClassName.
     */
    static final String SYSTEMCREATIONCLASSNAME = "SystemCreationClassName";
    
    /**
     * The scoping ComputerSystem's Name.
     */
    static final String SYSTEMNAME =		"SystemName";


    // properties in the CIM_ManagedElement supersupersuperclass
    
    /**
     * The Caption property is a short textual description (one-line string
     * of the object.
     */
    static String   CAPTION = "Caption";
    
    /**
     * The Description property provides a textual description of the object.
     */
    static String   DESCRIPTION = "Description";

    
    // properties in the CIM_ManagedSystemElement supersuperclass

    /** 
     * A datetime value indicating when the object was installed. A lack of
     * a value does not indicate that the object is not installed.
     */
    static String   INSTALL_DATE = "InstallDate";
    
    static String   STATUS	 = "Status";

    
    // properties in the CIM_Process
    static String   HANDLE = "Handle";

    
    // common properties value
    
    /**
     * Value of the SOLARIS_CSCREATIONCLASSNAME property
     */
    static String   SOLARIS_COMPUTERSYSTEM  = "Solaris_ComputerSystem";
    
    /**
     * Value of the SOLARIS_OSCREATIONCLASSNAME property
     */
    static String   SOLARIS_OPERATINGSYSTEM = "Solaris_OperatingSystem";

    
    // common constants
    static String   NAMESPACE	= "root/cimv2";
}
