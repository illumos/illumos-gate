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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

import java.util.Date;
import java.text.DateFormat;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.Calendar;
import java.util.ResourceBundle;
import java.util.MissingResourceException;

/**
 * Class representing a Kerberos V5 principal
 * Class data items correspond to fields in struct _kadm5_principal_ent_t_v2
 */
class Principal {

    private static DateFormat df;
    private static NumberFormat nf;
    private static String neverString;

    private static Integer INFINITE_LIFE = new Integer(Integer.MAX_VALUE);

    Flags flags;

    // For I18N
    private static ResourceBundle rb;
  
    String PrName;		// krb5_principal principal;
    Date PrExpireTime;		// krb5_timestamp princ_expire_time;
    String Policy;		// char *policy;
    Date LastPwChange;		// krb5_timestamp last_pwd_change;
    Date PwExpireTime;		// krb5_timestamp pw_expiration;
    Integer MaxLife;	        // krb5_deltat max_life;
    Integer MaxRenew;		// krb5_deltat max_renewable_life;
    Date ModTime;		// krb5_timestamp mod_date;
    String ModName;		// krb5_principal mod_name;
    Date LastSuccess;		// krb5_timestamp last_success;
    Date LastFailure;		// krb5_timestamp last_failed;
    Integer NumFailures;	// krb5_kvno fail_auth_count;
    String Comments;		// ==> entry in tl_data array
    Integer Kvno;		// krb5_kvno kvno;
    Integer Mkvno;		// krb5_kvno mkvno;

    String PrPasswd;		// standalone field in Kadmin API
    Kadmin Kadmin;
    boolean isNew;		// newly created principal?
    boolean dummy;		// use dummy data?
    boolean newComments;	// are comments new or changed?
    String EncTypes;		// enc type list to be used for key gen
  
    /**
     * Initialize new principal to defaults - this one is for new creations
     */
    public Principal() {
        isNew = true;
        dummy = true;
        newComments = false;
        PrName = new String("");
        PrPasswd = new String("");
        Calendar cal = Calendar.getInstance();
        cal.setTime(new Date());	    /* start with now ... */
        cal.add(Calendar.YEAR, 1);	    /* ... add a year ... XXX */
        PrExpireTime = cal.getTime();  /* ... to get expiry */
        Policy = new String("");
        LastPwChange = new Date(0);    /* never */
        PwExpireTime = null; // may be server side default
        MaxLife = null; // may be server side default
        MaxRenew = null; // may be server side default
        ModTime = new Date();	    /* now */
        ModName = System.getProperty("user.name");
        LastSuccess = new Date(0);	    /* never */
        LastFailure = new Date(0);	    /* never */
        NumFailures = new Integer(0);
        Comments = new String("");
        Kvno = new Integer(0);
        Mkvno = new Integer(0);
        flags = new Flags();
	EncTypes = new String("");
    }

    /*
     * This is used for loading an existing principal
     */
    public Principal(String Pname) {
	/* Get some specific data from somewhere */
	this();
	isNew = false;
	PrName = Pname;
	PwExpireTime = new Date(0);
	loadPrincipal(Pname);
    }

    /*
     * This is used for duplicating a new principal from an old one
     */
    public Principal(Principal old) {
	/* Copy old principal to new one */
	this();
	copyPrincipal(old, this);
    }

    /*
     * For real data, use Kadmin as a first argument
     */
    public Principal(Kadmin session, Defaults defaults) {
	this();
	dummy = false;
	Kadmin = session;
	setDefaults(defaults);
    }

    public Principal(Kadmin session, String Pname) {
	this();
	isNew = false;
	dummy = false;
	Kadmin = session;
	PrName = Pname;
	PwExpireTime = new Date(0);
	loadPrincipal(Pname);
    }

    public Principal(Kadmin session, Principal old) {
	this(old);
	dummy = false;
	Kadmin = session;
    }

    public void setDefaults(Defaults defaults) {
        flags = new Flags(defaults.getFlags().getBits());
        if (!defaults.getServerSide()) {
            MaxLife  = defaults.getMaxTicketLife();
            MaxRenew = defaults.getMaxTicketRenewableLife();
        }
        PrExpireTime = defaults.getAccountExpiryDate();
    }

    /**
     * Copy relevant fields from old principal, overriding as necessary
     */
    public static void copyPrincipal(Principal old, Principal curr) {
	curr.PrName = new String("");	    /* override */
	curr.PrPasswd = new String("");	    /* override */
	curr.PrExpireTime = new Date(old.PrExpireTime.getTime());
	curr.Policy = new String(old.Policy);
	curr.EncTypes = new String(old.EncTypes);
	curr.LastPwChange = new Date(0);    /* override: never */
	if (old.PwExpireTime == null)
	    curr.PwExpireTime = null;
	else
	    curr.PwExpireTime = new Date(old.PwExpireTime.getTime());
	curr.MaxLife = new Integer(old.MaxLife.intValue());
	curr.MaxRenew = new Integer(old.MaxRenew.intValue());
	curr.ModTime = new Date();	    /* override: now */
	curr.ModName = System.getProperty("user.name");	    /* override */
	curr.LastSuccess = new Date(0);	    /* override: never */
	curr.LastFailure = new Date(0);	    /* override: never */
	curr.NumFailures = new Integer(0);  /* override: none */
	curr.Comments = new String(old.Comments);
	curr.Kvno = new Integer(old.Kvno.intValue());
	curr.Mkvno = new Integer(old.Mkvno.intValue());
	curr.flags = new Flags(old.flags.getBits());
    }

    public boolean loadPrincipal(String name) {
	if (dummy)
		return true;
	boolean b = Kadmin.loadPrincipal(name, this);
	// System.out.println(this.toString());
	return b;
    }

    public boolean savePrincipal() {
	// System.out.println(this.toString());
	if (dummy)
		return true;
	if (MaxLife == null)
	  MaxLife = INFINITE_LIFE;
	if (MaxRenew == null)
	  MaxRenew = INFINITE_LIFE;
	if (this.isNew)
	    return Kadmin.createPrincipal(this);
	else
	    return Kadmin.savePrincipal(this);
    }


    public boolean setName(String name) {
	// xxx: see where this gets called from to determine if a new Principal
	// just added can have a duplicate name or whether that would have been
	// screened out earlier.

	PrName = name;
	return true;
    }

    public boolean setComments(String comments) {
	  // xxx: check to see if all characters are in the allowable list of
	  // characters. The list needs to be I18N. No length restrictions on
	  // Java side but what about the c side?
        Comments = comments;
        newComments = true;
        return true;
    }
    
    public boolean setPolicy(String pol) {
	  // xxx: is this a valid policy name? Should we assume that error is
	  // already trapped before this point?
	Policy = pol;
	return true;
    }

    public boolean setPassword(String pw) {
	  // xxx: check to see if the passwd follows the rules laid down by
	  // the policy
	PrPasswd = pw;
	return true;
    }

    public boolean setEncType(String enctype) {
	EncTypes = enctype;
	// Don't have to check enc type list provided given that list was
	// populated from the checkbox list
	return true;
    }
     
    /**
     * @param exp Contains a date formatted by the default locale,
     * representing the expiry time for the principal's expiration.
     */
    public boolean setExpiry(String exp) {
        exp = exp.trim();
        if (exp.equalsIgnoreCase(neverString))
           PrExpireTime = new Date(0);
        else {
            try {
   	        PrExpireTime = df.parse(exp);
            } catch (ParseException e) {
	        return false;
            } catch (NullPointerException e) {
	        // gets thrown when parse string begins with text
	        // probable JDK bug
	        return false;
            } catch (StringIndexOutOfBoundsException e) {
	        // gets thrown when parse string contains only one number
	        // probable JDK bug
	        return false;
            }
        }
        return true;
    }

    /**
     * @param exp Contains a date formatted by the default locale,
     * representing the expiry time for the password expiration.
     */
    public boolean setPwExpiry(String exp) {
        exp = exp.trim();
        if (exp.equals(""))
            PwExpireTime = null;
        else if (exp.equalsIgnoreCase(neverString))
            PwExpireTime = new Date(0);
        else {
            try {
    	        PwExpireTime = df.parse(exp);
            } catch (ParseException e) {
	        return false;
            } catch (NullPointerException e) {
	        // gets thrown when parse string begins with text
	        // probable JDK bug
	        return false;
            }  catch (StringIndexOutOfBoundsException e) {
	        // gets thrown when parse string contains only one number
	        // probable JDK bug
	        return false;
            }
        }
        return true;
    }
  
    public String getModTime() {
        if (ModTime.getTime() == 0)
            return neverString;
        else 
            return df.format(ModTime);
    }

    public String getEncType() {
            return EncTypes;
    }

    public String getExpiry() {
        if (PrExpireTime.getTime() == 0)
            return neverString;
        else 
            return df.format(PrExpireTime);
    }
  
    public String getLastSuccess() {
        if (LastSuccess.getTime() == 0)
            return neverString;
        else 
            return df.format(LastSuccess);
    }
  
    public String getLastFailure() {
        if (LastFailure.getTime() == 0)
            return neverString;
        else 
            return df.format(LastFailure);
    }
  
    public String getLastPwChange() {
        if (LastPwChange.getTime() == 0)
            return neverString;
        else 
            return df.format(LastPwChange);
    }
  
    public String getPwExpireTime() {
        if (PwExpireTime == null)
            return new String("");
        else if (PwExpireTime.getTime() == 0)
            return neverString;
        else 
            return df.format(PwExpireTime);
    }

    public String getMaxLife() {
        if (MaxLife != null)
            return nf.format(MaxLife.longValue());
        else
            return "";
    }
  
    public String getMaxRenew() {
        if (MaxRenew != null)
            return nf.format(MaxRenew.longValue());
        else
            return "";
    }
  
    /**
     * @param vers Contains a number representing the key version.
     */
    public boolean setKvno(String vers) {
	try {
	    Kvno = new Integer(nf.parse(vers.trim()).intValue());
	}catch (ParseException e) {
	    return false;
	}
	return true;
    }

    /**
     * @param val Contains a number representing the maximum lifetime, in
     * seconds, of a ticket for this principal.
     */
    public boolean setMaxlife(String val) {
	try {
	    String noSpace = val.trim(); 
	    if (noSpace.length() == 0) 
	        return true; 
	    MaxLife = new Integer(nf.parse(noSpace).intValue());
	}catch (ParseException e) {
	    return false;
	}
	return true;
    }

    /**
     * @param val Contains a number representing the maximum renewable lifetime,
     * in seconds, of a ticket for this principal.
     */
    public boolean setMaxrenew(String val) {
	try {
	    String noSpace = val.trim(); 
	    if (noSpace.length() == 0) 
	        return true; 
	    MaxRenew = new Integer(nf.parse(noSpace).intValue());		
	}catch (ParseException e) {
	    return false;
	}
	return true;
    }

    /**
     * Toggles a particular flag.
     * @param mask one of the statically defined masks indicating which flag to
     * toggle.
     */
    public boolean setFlag(int mask) {
        flags.toggleFlags(mask);
        return true;
    }

    /**
     * Obtain a string representation of this principal.
     * @return a String containing the following information about this 
     * principal:<br>
     * <ul>
     * <li>principal name
     *<li>policy being applied
     *<li>expiry date
     *<li>comments
     *<li>key version number
     *<li>password expire time
     *<li>maximum lifetime
     *<li>maximum renewable lifetime
     * <li> flags
     *</ul>
     */
    public String toString() {

        StringBuffer sb = new StringBuffer();

        sb.append(getString("Principal Name:") + "  " + PrName).append('\n');
        sb.append(getString("Account Expires:") + "  "
              + getExpiry()).append('\n');
        sb.append(getString("Policy:") + "  " + Policy).append('\n');
        sb.append(getString("Enc Types:") + "  " + EncTypes).append('\n');
        sb.append(getString("Comments:") + "  " + Comments).append('\n');
        sb.append(getString("Key Version:") + "	" + Kvno).append('\t');
        sb.append(getString("Password Expires:") + "  "
              + getPwExpireTime()).append('\n');
        sb.append(getString("Maximum Lifetime (seconds):")
	      + "	 " + getMaxLife()).append('\t'); 
        sb.append(getString("Maximum Renewal (seconds):") 
	      + "	 " + getMaxRenew()).append('\n'); 
        sb.append(getString("Flags:")).append('\n').append(flags.toString());

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

    static {
        rb = ResourceBundle.getBundle("GuiResource" /* NOI18N */);     
        df = DateFormat.getDateTimeInstance(DateFormat.MEDIUM,
                                            DateFormat.MEDIUM);
        nf = NumberFormat.getInstance();
        neverString = getString("Never");
    }

}
