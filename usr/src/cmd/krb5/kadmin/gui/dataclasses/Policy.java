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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

import java.util.ResourceBundle;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.MissingResourceException;

/**
 * Class representing a Kerberos V5 policy
 * Class data items correspond to fields in struct _kadm5_policy_ent_t
 */
class Policy {
    String PolicyName;	// char		*policy;
    Integer PwMinLife;	// long		pw_min_life;
    Integer PwMaxLife;	// long		pw_max_life;
    Integer PwMinLength;	// long		pw_min_length;
    Integer PwMinClasses;	// long		pw_min_classes;
    Integer PwSaveCount;	// long		pw_history_num;
    Integer RefCount;	// long		policy_refcnt;
    Kadmin Kadmin;
    boolean isNew;
    boolean dummy;

    // For I18N
    private static ResourceBundle rb =
        ResourceBundle.getBundle("GuiResource" /* NOI18N */); 
    private static NumberFormat nf = NumberFormat.getInstance();

    /**
     * Initialize new policy to defaults - this one is for new creations
     */
    public Policy() {
	dummy = true;
	isNew = true;
	PolicyName = new String("");
	PwMinLife = new Integer(0);
	PwMaxLife = new Integer(30 * 24 * 60  * 60);   /* 30 days */
	PwMinLength = new Integer(4);
	PwMinClasses = new Integer(2);
	PwSaveCount = new Integer(3);
	RefCount = new Integer(0);
    }

    /*
     * This is used for loading an existing principal
     */
    public Policy(String Pname) {
	/* Get some specific data from somewhere */
	this();
	dummy = true;
	isNew = false;
	PolicyName = Pname;
	loadPolicy(Pname);
    }

    /*
     * This is used for duplicating a new principal from an old one
     */
    public Policy(Policy old) {
	/* Copy old principal to new one */
	this();
	dummy = true;
	copyPolicy(old, this);
    }

    /*
     * For real data, use Kadmin as a first argument
     */
    public Policy(Kadmin session) {
	this();
	dummy = false;
	Kadmin = session;
    }

    public Policy(Kadmin session, String Pname) {
	this();
	isNew = false;
	dummy = false;
	Kadmin = session;
	PolicyName = Pname;
	loadPolicy(Pname);
    }

    public Policy(Kadmin session, Policy old) {
	this(old);
	dummy = false;
	Kadmin = session;
    }

    /**
     * Copy relevant fields from old policy, overriding as necessary
     */
    public void copyPolicy(Policy old, Policy curr) {
	curr.PolicyName = new String("");	/* override */
	curr.PwMinLife = new Integer(old.PwMinLife.intValue());
	curr.PwMaxLife = new Integer(old.PwMaxLife.intValue());
	curr.PwMinLength = new Integer(old.PwMinLength.intValue());
	curr.PwMinClasses = new Integer(old.PwMinClasses.intValue());
	curr.PwSaveCount = new Integer(old.PwSaveCount.intValue());
	curr.RefCount = new Integer(0);		/* override */
    }

    public boolean loadPolicy(String name) {
	if (dummy)
	    return true;
	boolean b = Kadmin.loadPolicy(name, this);
	// System.out.println(this.toString());
	return b;
    }

    public boolean savePolicy() {
	// System.out.println(this.toString());
	if (dummy)
	    return true;
	if (this.isNew)
	    return Kadmin.createPolicy(this);
	else
	    return Kadmin.savePolicy(this);
    }

    public boolean setName(String name) {
	  // xxx: see where this gets called from to determine if a new Policy
	  // just added can have a duplicate name or whether that would have 
	  // been screened out earlier.
	  PolicyName = name;
	  return true;
    }

    /**
     * @param val Contains one number representing the length.
     */
    public boolean setPolPwLength(String val) {
	  try {
		PwMinLength = new Integer(nf.parse(val).intValue());
	  } catch (ParseException e) {
		return false;
	  }
	  return true;
    }

    /**
     * @param val Contains one number representing the number of classes
     */
    public boolean setPolPwClasses(String val) {
        try {
	    PwMinClasses = new Integer(nf.parse(val).intValue());
        } catch (ParseException e) {
    	    return false;
        }
        return true;
    }

    /**
     * @param val Contains one number representing the save count.
     */
    public boolean setPolPwHistory(String val) {
      // xxx: Is pwHistory the same as pwSaveCount?
        try {
	    PwSaveCount = new Integer(nf.parse(val).intValue());
        } catch (ParseException e) {
	  return false;
        }      
        return true;
    }

    /**
     * @param val Contains one number representing the lifetime in seconds.
     */
    public boolean setPolMinlife(String val) {
        try {
  	    PwMinLife =  new Integer(nf.parse(val.trim()).intValue());
        } catch (ParseException e) {
	    return false;
        }
        return true;
    }

    /**
     * @param val Contains one number representing the lifetime in seconds.
     */
    public boolean setPolMaxlife(String val) {
        try {
	    PwMaxLife = new Integer(nf.parse(val.trim()).intValue());
        } catch (ParseException e) {
	    return false;
        }
	    return true;
    }

    /*
     * Obtain a string representation of this policy.
     * @return a String containing the following information about this policy:
     * <br><ul>
     * <li>policy name
     * <li>password minimum life
     * <li>password maximum life
     * <li>password minimum length
     * <li>password minimum classes
     * <li>password save count
     * <li>reference count
     *</ul>
     */
    public String toString() {

        StringBuffer sb = new StringBuffer();

        sb.append(getString("Policy Name:") + "  " + PolicyName).append('\n');
        sb.append(getString("Reference Count:") + "  " 
              +  RefCount).append("\n");
        sb.append(getString("Minimum Password Lifetime (seconds):") 
	      + "  " +  PwMinLife).append("\t");
        sb.append(getString("Maximum Password Lifetime (seconds):") 
	      + "  " + PwMaxLife).append("\n");
        sb.append(getString("Minimum Password Length:") + "  " 
              + PwMinLength).append("\t");
        sb.append(getString("Minimum Password Classes:") + "  "
	      + PwMinClasses).append("\n");
        sb.append(getString("Password Save Count:") + "  "
	      + PwSaveCount).append("\n");

        return sb.toString();
    }

    /**
     * Call rb.getString(), but catch exception and return English
     * key so that small spelling errors don't cripple the GUI
     *
     */
    private static final String getString(String key) {
        try {
    	    String res = rb.getString(key);
	    return res;
        } catch (MissingResourceException e) {
	    System.out.println("Missing resource "+key+", using English.");
	    return key;
        }
    }

}
