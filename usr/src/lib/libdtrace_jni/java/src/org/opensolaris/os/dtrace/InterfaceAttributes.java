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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package org.opensolaris.os.dtrace;

import java.io.*;
import java.beans.*;

/**
 * Triplet of attributes consisting of two stability levels and a
 * dependency class.  Attributes may vary independently.  They use
 * labels described in the {@code attributes(7)} man page to help set
 * expectations for what kinds of changes might occur in different kinds
 * of future releases.  The D compiler includes features to dynamically
 * compute the stability levels of D programs you create.  For more
 * information, refer to the <a
 * href=http://dtrace.org/guide/chp-stab.html>
 * <b>Stability</b></a> chapter of the <i>Dynamic Tracing
 * Guide</i>.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see Consumer#getProgramInfo(Program program)
 * @see Consumer#enable(Program program)
 * @see Consumer#listProbes(ProbeDescription filter)
 * @see Consumer#listProgramProbes(Program program)
 *
 * @author Tom Erickson
 */
public final class InterfaceAttributes implements Serializable {
    static final long serialVersionUID = -2814012588381562694L;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(InterfaceAttributes.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"nameStability", "dataStability",
		    "dependencyClass" })
	    {
		/*
		 * Need to prevent DefaultPersistenceDelegate from using
		 * overridden equals() method, resulting in a
		 * StackOverFlowError.  Revert to PersistenceDelegate
		 * implementation.  See
		 * http://forum.java.sun.com/thread.jspa?threadID=
		 * 477019&tstart=135
		 */
		protected boolean
		mutatesTo(Object oldInstance, Object newInstance)
		{
		    return (newInstance != null && oldInstance != null &&
			    oldInstance.getClass() == newInstance.getClass());
		}

		protected Expression
		instantiate(Object oldInstance, Encoder out)
		{
		    InterfaceAttributes attr = (InterfaceAttributes)
			    oldInstance;
		    return new Expression(oldInstance, oldInstance.getClass(),
			    "new", new Object[] {
			    attr.getNameStability().name(),
			    attr.getDataStability().name(),
			    attr.getDependencyClass().name() });
		}
	    };
	    BeanDescriptor d = info.getBeanDescriptor();
	    d.setValue("persistenceDelegate", persistenceDelegate);
	} catch (IntrospectionException e) {
	    e.printStackTrace();
	}
    }

    /**
     * Interface stability level.  Assists developers in making risk
     * assessments when developing scripts and tools based on DTrace by
     * indicating how likely an interface or DTrace entity is to change
     * in a future release or patch.
     */
    public enum Stability {
	/**
	 * The interface is private to DTrace itself and represents an
	 * implementation detail of DTrace.  Internal interfaces might
	 * change in minor or micro releases.
	 */
	INTERNAL("Internal"),
	/**
	 * The interface is private to Sun and represents an interface
	 * developed for use by other Sun products that is not yet
	 * publicly documented for use by customers and ISVs.  Private
	 * interfaces might change in minor or micro releases.
	 */
	PRIVATE("Private"),
	/**
	 * The interface is supported in the current release but is
	 * scheduled to be removed, most likely in a future minor
	 * release.  When support of an interface is to be discontinued,
	 * Sun will attempt to provide notification before discontinuing
	 * the interface.  The D compiler might produce warning messages
	 * if you attempt to use an Obsolete interface.
	 */
	OBSOLETE("Obsolete"),
	/**
	 * The interface is controlled by an entity other than Sun.  At
	 * Sun's discretion, Sun can deliver updated and possibly
	 * incompatible versions as part of any release, subject to
	 * their availability from the controlling entity.  Sun makes no
	 * claims regarding either the source or binary compatibility
	 * for External interfaces between two releases.  Applications
	 * based on these interfaces might not work in future releases,
	 * including patches that contain External interfaces.
	 */
	EXTERNAL("External"),
	/**
	 * The interface is provided to give developers early access to
	 * new or rapidly changing technology or to an implementation
	 * artifact that is essential for observing or debugging system
	 * behavior for which a more stable solution is anticipated in
	 * the future.  Sun makes no claims about either source of
	 * binary compatibility for Unstable interfaces from one minor
	 * release to another.
	 */
	UNSTABLE("Unstable"),
	/**
	 * The interface might eventually become Standard or Stable but
	 * is still in transition.  Sun will make reasonable efforts to
	 * ensure compatibility with previous releases as it evolves.
	 * When non-upward compatible changes become necessary, they
	 * will occur in minor and major releases.  These changes will
	 * be avoided in micro releases whenever possible.  If such a
	 * change is necessary, it will be documented in the release
	 * notes for the affected release, and when feasible, Sun will
	 * provide migration aids for binary compatibility and continued
	 * D program development.
	 */
	EVOLVING("Evolving"),
	/**
	 * The interface is a mature interface under Sun's control.  Sun
	 * will try to avoid non-upward-compatible changes to these
	 * interfaces, especially in minor or micro releases.  If
	 * support of a Stable interface must be discontinued, Sun will
	 * attempt to provide notification and the stability level
	 * changes to Obsolete.
	 */
	STABLE("Stable"),
	/**
	 * The interface complies with an industry standard.  The
	 * corresponding documentation for the interface will describe
	 * the standard to which the interface conforms.  Standards are
	 * typically controlled by a standards development organization,
	 * and changes can be made to the interface in accordance with
	 * approved changes to the standard.  This stability level can
	 * also apply to interfaces that have been adopted (without a
	 * formal standard) by an industry convention.  Support is
	 * provided for only the specified versions of a standard;
	 * support for later versions is not guaranteed.  If the
	 * standards development organization approves a
	 * non-upward-compatible change to a Standard interface that Sun
	 * decides to support, Sun will announce a compatibility and
	 * migration strategy.
	 */
	STANDARD("Standard");

	private String s;

	private
	Stability(String displayName)
	{
	    s = displayName;
	}

	/**
	 * Overridden to get the default display value.  To
	 * internationalize the display value, use {@link
	 * java.lang.Enum#name()} instead as a lookup key.
	 */
	@Override
	public String
	toString()
	{
	    return s;
	}
    }

    /**
     * Architectural dependency class.  Tells whether an interface is
     * common to all platforms and processors, or whether the
     * interface is associated with a particular architecture such as
     * SPARC processors only.
     */
    public enum DependencyClass {
	// Note that the compareTo() method depends on the order in
	// which the instances are instantiated

	/**
	 * The interface has an unknown set of architectural dependencies.
	 * DTrace does not necessarily know the architectural dependencies of
	 * all entities, such as data types defined in the operating system
	 * implementation.  The Unknown label is typically applied to interfaces
	 * of very low stability for which dependencies cannot be computed.  The
	 * interface might not be available when using DTrace on <i>any</i>
	 * architecture other than the one you are currently using.
	 */
	UNKNOWN("Unknown"),
	/**
	 * The interface is specific to the CPU model of the current
	 * system.  You can use the {@code psrinfo(8)} utility's {@code
	 * -v} option to display the current CPU model and
	 * implementation names.  Interfaces with CPU model dependencies
	 * might not be available on other CPU implementations, even if
	 * those CPUs export the same instruction set architecture
	 * (ISA).  For example, a CPU-dependent interface on an
	 * UltraSPARC-III+ microprocessor might not be available on an
	 * UltraSPARC-II microprocessor, even though both processors
	 * support the SPARC instruction set.
	 */
	CPU("CPU"),
	/**
	 * The interface is specific to the hardware platform of the current
	 * system.  A platform typically associates a set of system components
	 * and architectural characteristics such as a set of supported CPU
	 * models with a system name such as <code>SUNW,
	 * Ultra-Enterprise-10000</code>.  You can display the current
	 * platform name using the {@code uname(1)} {@code -i} option.
	 * The interface might not be available on other hardware
	 * platforms.
	 */
	PLATFORM("Platform"),
	/**
	 * The interface is specific to the hardware platform group of the
	 * current system.  A platform group typically associates a set of
	 * platforms with related characteristics together under a single name,
	 * such as {@code sun4u}.  You can display the current platform
	 * group name using the {@code uname(1)} {@code -m} option.  The
	 * interface is available on other platforms in the platform
	 * group, but might not be available on hardware platforms that
	 * are not members of the group.
	 */
	GROUP("Group"),
	/**
	 * The interface is specific to the instruction set architecture (ISA)
	 * supported by the microprocessor on this system.  The ISA describes a
	 * specification for software that can be executed on the
	 * microprocessor, including details such as assembly language
	 * instructions and registers.  You can display the native
	 * instruction sets supported by the system using the {@code
	 * isainfo(1)} utility.  The interface might not be supported on
	 * systems that do not export any of of the same instruction
	 * sets.  For example, an ISA-dependent interface on a
	 * SPARC system might not be supported on an x86 system.
	 */
	ISA("ISA"),
	/**
	 * The interface is common to all systems regardless of the
	 * underlying hardware.  DTrace programs and layered applications that
	 * depend only on Common interfaces can be executed and deployed on
	 * other systems with the same illumos and DTrace revisions.
	 * The majority of DTrace interfaces are Common, so you can use them
	 * wherever you use illumos.
	 */
	COMMON("Common");

	private String s;

	private
	DependencyClass(String displayString)
	{
	    s = displayString;
	}

	/**
	 * Overridden to get the default display value.  To
	 * internationalize the display value, use {@link
	 * java.lang.Enum#name()} instead as a lookup key.
	 */
	@Override
	public String
	toString()
	{
	    return s;
	}
    }

    /** @serial */
    private Stability nameStability;
    /** @serial */
    private Stability dataStability;
    /** @serial */
    private DependencyClass dependencyClass;

    /**
     * Called by native code.
     */
    private
    InterfaceAttributes()
    {
    }

    /**
     * Creates an interface attribute triplet from the given attributes.
     *
     * @param nameStabilityAttribute the stability level of the
     * interface associated with its name in a D program
     * @param dataStabilityAttribute stability of the data format used
     * by the interface and any associated data semantics
     * @param dependencyClassAttribute describes whether the interface
     * is specific to the current operating platform or microprocessor
     * @throws NullPointerException if any parameter is {@code null}
     */
    public
    InterfaceAttributes(Stability nameStabilityAttribute,
	    Stability dataStabilityAttribute,
	    DependencyClass dependencyClassAttribute)
    {
	nameStability = nameStabilityAttribute;
	dataStability = dataStabilityAttribute;
	dependencyClass = dependencyClassAttribute;
	validate();
    }

    /**
     * Creates an interface attribute triplet from the given attribute
     * names.  Supports XML persistence.
     *
     * @throws NullPointerException if any parameter is {@code null}
     * @throws IllegalArgumentException if any parameter fails to match
     * an enumerated stability value
     */
    public
    InterfaceAttributes(String nameStabilityAttributeName,
	    String dataStabilityAttributeName,
	    String dependencyClassAttributeName)
    {
	this(Enum.valueOf(Stability.class, nameStabilityAttributeName),
		Enum.valueOf(Stability.class, dataStabilityAttributeName),
		Enum.valueOf(DependencyClass.class,
		dependencyClassAttributeName));
	// validate() unnecessary because Enum.valueOf() has already
	// thrown the exception
    }

    private final void
    validate()
    {
	if (nameStability == null) {
	    throw new NullPointerException("nameStability is null");
	}
	if (dataStability == null) {
	    throw new NullPointerException("dataStability is null");
	}
	if (dependencyClass == null) {
	    throw new NullPointerException("dependencyClass is null");
	}
    }

    /**
     * Gets the stability level of an interface associated with its name
     * as it appears in a D program.  For example, the {@code execname}
     * D variable is a {@link Stability#STABLE STABLE} name: Sun
     * guarantees this identifier will continue to be supported in D
     * programs according to the rules described for Stable interfaces.
     *
     * @return the stability level of an interface associated with its
     * name as it appears in a D program
     */
    public Stability
    getNameStability()
    {
	return nameStability;
    }

    /**
     * Called by native code.
     */
    private void
    setNameStability(String s)
    {
	nameStability = Enum.valueOf(Stability.class, s);
    }

    /**
     * Gets the stability level of the data format used by an interface
     * and any associated data semantics.  For example, the {@code pid}
     * D variable is a {@link Stability#STABLE STABLE} interface:
     * process IDs are a stable concept in illumos, and it is guaranteed
     * that the {@code pid} variable will be of type {@code pid_t} with
     * the semantic that it is set to the process ID corresponding to
     * the thread that fired a given probe in accordance with the rules
     * described for Stable interfaces.
     *
     * @return the stability level of the data format used by an
     * interface and any associated data semantics.
     */
    public Stability
    getDataStability()
    {
	return dataStability;
    }

    /**
     * Called by native code.
     */
    private void
    setDataStability(String s)
    {
	dataStability = Enum.valueOf(Stability.class, s);
    }

    /**
     * Gets the interface dependency class.
     *
     * @return the dependency class describing whether the interface is
     * specific to the current operating platform or microprocessor
     */
    public DependencyClass
    getDependencyClass()
    {
	return dependencyClass;
    }

    /**
     * Called by native code.
     */
    private void
    setDependencyClass(String s)
    {
	dependencyClass = Enum.valueOf(DependencyClass.class, s);
    }

    /**
     * Compares the specified object with this attribute triplet for
     * equality.  Defines equality as having the same attributes.
     *
     * @return {@code true} if and only if the specified object is also
     * an {@code InterfaceAttributes} instance and has all the same
     * attributes as this instance.
     */
    @Override
    public boolean
    equals(Object o)
    {
	if (o == this) {
	    return true;
	}
	if (o instanceof InterfaceAttributes) {
	    InterfaceAttributes a = (InterfaceAttributes)o;
	    return ((nameStability == a.nameStability) &&
		    (dataStability == a.dataStability) &&
		    (dependencyClass == a.dependencyClass));
	}
	return false;
    }

    /**
     * Overridden to ensure that equal {@code InterfaceAttributes}
     * instances have equal hashcodes.
     */
    @Override
    public int
    hashCode()
    {
	int hash = 17;
	hash = (37 * hash) + nameStability.hashCode();
	hash = (37 * hash) + dataStability.hashCode();
	hash = (37 * hash) + dependencyClass.hashCode();
	return hash;
    }

    private void
    readObject(ObjectInputStream s)
            throws IOException, ClassNotFoundException
    {
	s.defaultReadObject();
	// Check constructor invariants
	try {
	    validate();
	} catch (Exception e) {
	    InvalidObjectException x = new InvalidObjectException(
		    e.getMessage());
	    x.initCause(e);
	    throw x;
	}
    }

    /**
     * Gets the string representation of this triplet of interface
     * attributes.  The format follows the convention described in the
     * <a href=http://dtrace.org/guide/chp-stab.html#chp-stab-3>
     * <b>Interface Attributes</b></a> section of the <b>Stability</b>
     * chapter of the <i>Dynamic Tracing Guide</i>.  The
     * attributes appear in the following order, separated by slashes:
     * <pre><code>
     * <i>name-stability / data-stability / dependency-class</i>
     * </code></pre>
     */
    public String
    toString()
    {
	StringBuilder buf = new StringBuilder();
	buf.append(nameStability);
	buf.append(" / ");
	buf.append(dataStability);
	buf.append(" / ");
	buf.append(dependencyClass);
	return buf.toString();
    }
}
