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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * stats.java
 */

package com.sun.wbem.solarisprovider.srm;

import java.util.*;
import java.net.InetAddress;
import javax.wbem.cim.*;
import javax.wbem.client.*;

public class stats {
    /*
     * -u username
     * -p project
     * -h host
     * -I id to auth
     * -P passwd
     */

    CIMClient client = null;
    String user = new String("");
    String project = new String("");
    String host = "";
    String id = new String("");
    String passwd = new String("");
    boolean showproject = false;
    boolean listprops = false;
    boolean checkonly = false;
    int intervalms = 5000;
    
    String usage = new String(
	"Usage: " + this.getClass().getName() + "\n" +
	  "\t" + "-u userid  -p projectname\n" +
	  "\t" + "-r{aw} [property name] -d{elta} [property name]\n" +
	  "\t" + "-L{ist all property names}\n" +
	  "\t" + "-C{heck for existence}\n" + 
	  "\t" + "-i [update interval (sec)]\n" +
	  "\t" + "-h host -I auth_user_id  -P auth_user_passwd\n" +
	  "\n" +
	  "-I and -P are always required.\n" +
	  "At least one of -r or -d is required unless -L or -C are used.\n" +
	  "If -L is specifed, -r, -d, and -i are ignored.\n" +
	  "If -C is specified, one of -u or -p must be used.\n" +
	  "Default value for -i is " +
	  	Integer.toString(intervalms / 1000) + " seconds.\n" +
	  "Default value for -h is \"localhost\".");
    
    
    void badarg(String s) {
	System.err.println("Ignoring invalid argument \"" + s + "\"");
    }

    
    void parseargs(String args[]) {
	int argc = args.length;
	int i, l;
	
	for (i = 0; i < argc; i++)  {

	    if (args[i].startsWith("-u")) {

		// specific user to monitor
		if ((l = args[i].length()) > 2)
		    user = args[i].substring(2, l);
		else if ((i < argc - 1) && (!args[i + 1].startsWith("-"))) 
		    user = args[++i];
		else
		    badarg(args[i]);
		
	    } else if (args[i].startsWith("-p")) {
		
		// specific project to monitor
		if ((l = args[i].length()) > 2)
		    project = args[i].substring(2, l);
		else if ((i < argc - 1) && (!args[i + 1].startsWith("-"))) 
		    project = args[++i];
		else
		    badarg(args[i]);
		
	    } else if (args[i].startsWith("-h")) {
		
		// hostname
		if ((l = args[i].length()) > 2)
		    host = args[i].substring(2, l);
		else if ((i < argc - 1) && (!args[i + 1].startsWith("-"))) 
		    host = args[++i];
		else
		    badarg(args[i]);
		
	    } else if (args[i].startsWith("-i")) {
		
		// update interval
		String s = Integer.toString(intervalms / 1000);
		if ((l = args[i].length()) > 2)
		     s = args[i].substring(2, l);
		else if ((i < argc - 1) && (!args[i + 1].startsWith("-"))) 
		    s = args[++i];
		else
		    badarg(args[i]);
		intervalms = Integer.valueOf(s).intValue() * 1000;
		
	    } else if (args[i].startsWith("-I")) {
		
		// user authentication identity 
		if ((l = args[i].length()) > 2)
		    id = args[i].substring(2, l);
		else if ((i < argc - 1) && (!args[i + 1].startsWith("-"))) {
		    id = args[++i];
		}
		else
		    badarg(args[i]);
		
	    } else if (args[i].startsWith("-P")) {
		
		// user authentication password 
		if ((l = args[i].length()) > 2)
		    passwd = args[i].substring(2, l);
		else if ((i < argc - 1) && (!args[i + 1].startsWith("-"))) 
		    passwd = args[++i];
		else
		    badarg(args[i]);
		
	    } else if (args[i].startsWith("-r")) {
		
		// raw property to be monitored
		String tmp = new String("");
		if ((l = args[i].length()) > 2)
		    tmp = args[i].substring(2, l);
		else if ((i < argc - 1) && (!args[i + 1].startsWith("-"))) 
		    tmp = args[++i];
		else {
		    badarg(args[i]);
		    continue;
		}
		props.addElement(tmp);
		
	    } else if (args[i].startsWith("-d")) {
		
		// delta property to be monitored
		String tmp = new String("");
		if ((l = args[i].length()) > 2)
		    tmp = args[i].substring(2, l);
		else if ((i < argc - 1) && (!args[i + 1].startsWith("-"))) 
		    tmp = args[++i];
		else {
		    badarg(args[i]);
		    continue;
		}
		props.addElement(tmp);
		deltaprops.add(tmp);
		
	    } else if (args[i].startsWith("-L")) {

		// list property names only
		listprops = true;
		
	    } else if (args[i].startsWith("-C")) {

		// check for existence  only
		checkonly = true;
		
	    } else {

		// unknown arg
		System.err.println(usage);
		return;
		
	    }
	}
    }

    Vector props = new Vector();
    HashSet deltaprops = new HashSet();
    
    void printHeader(String s, Vector v) {
	System.out.println((showproject ? "Project " : " User ") + s);
	Enumeration e = v.elements();
	while (e.hasMoreElements()) 
	    System.out.print((String) e.nextElement() + "\t");
	System.out.println("");
    }


    // compute val1 - val2
    String delta(CIMValue val1, CIMValue val2) {
	String rv = new String("empty");

	if (val1 == null || val2 == null)
	    return new String("null");
	
      	Object a = val1.getValue();
	Object b = val2.getValue();

	if (!(a instanceof Number) || !(b instanceof Number))
	    rv = new String("NAN");
	else if (a instanceof UnsignedInt64 && b instanceof UnsignedInt64) {
	    long x = ((UnsignedInt64) a).longValue();
	    long y = ((UnsignedInt64) b).longValue();
	    long z = x - y;
	    rv = new String(Long.toString(z));
	} else if (a instanceof UnsignedInt32 && b instanceof UnsignedInt32) {
	    int x = ((UnsignedInt32) a).intValue();
	    int y = ((UnsignedInt32) b).intValue();
	    int z = x - y;
	    rv = new String(Integer.toString(z));
	} else if (a instanceof Float && b instanceof Float) {
	    float x = ((Float) a).floatValue();
	    float y = ((Float) b).floatValue();
	    float z = x - y;
	    rv = new String(Float.toString(z));
	} else
	    rv = new String("unknown");

	return rv;
    }


    void checkOnly(String name) {
	CIMInstance ci = null;

	String className = new String("Solaris_Active");
	className += (showproject ? "Project" : "User");

	CIMObjectPath op = new CIMObjectPath(className);

	if (showproject) {
	    op.addKey("ProjectName",
	      new CIMValue(new String(name)));
	    op.addKey("CreationClassName",
	      new CIMValue("Solaris_ActiveProject"));
	} else {
	    op.addKey("UserID",
	      new CIMValue(new Integer(name)));
	    op.addKey("CreationClassName",
	      new CIMValue("Solaris_ActiveUser"));
	}
	op.addKey("CSCreationClassName",
	  new CIMValue("Solaris_ComputerSystem"));
	op.addKey("CSName",
	  new CIMValue(host));
	op.addKey("OSCreationClassName",
	  new CIMValue("Solaris_OperatingSystem"));
	op.addKey("OSName",
	  new CIMValue("SunOS"));
	
	try {
	    ci = client.getInstance(op, false);
	} catch (CIMException x) {
	    System.err.println(x);
	    Runtime.getRuntime().exit(-1);
	}
	
	System.err.println("CI: " + ci);

	Runtime.getRuntime().exit(0);
    }
    

    void validateProps() {
	// assume User and ProcessAggregate are the same...
	String className = new String(
	    "Solaris_UserProcessAggregateStatisticalInformation");
	CIMObjectPath op = new CIMObjectPath(className);
	CIMClass c = null;

	try {
	    c = client.getClass(op, false);
	} catch (CIMException x) {
	    System.err.println(x);
	    Runtime.getRuntime().exit(-1);
	}
	    
	String propname = null;
	Enumeration e = props.elements();
	while (e.hasMoreElements()) {
	    propname = (String) e.nextElement();
	    if (c.getProperty(propname) == null) {
		System.err.println(
		    "Unknown property `" + propname + "' -- try -L.");
		Runtime.getRuntime().exit(-1);
	    }
	}
    }

    
    void listProps() {
	// assume User and ProcessAggregate are the same...
	String className = new String(
	    "Solaris_UserProcessAggregateStatisticalInformation");

	try {
	    CIMObjectPath op = new CIMObjectPath(className);
	    CIMClass c = client.getClass(op, false);
	    Vector v = c.getAllProperties();
	    Enumeration e = v.elements();
	    while (e.hasMoreElements()) {
		CIMProperty p = (CIMProperty) e.nextElement();
		System.out.println("\t" + p.getName());
	    }
	} catch (Exception x) {
	    System.out.println(x);
	}
    }

    
    public void _main(String args[]) {
	String name = new String("");

	// handle comd-line args
	parseargs(args);

	// default to localhost
	if (host.length() == 0) {
	    try {
		host = new String(InetAddress.getLocalHost().getHostName());
	    } catch (Exception x) {
		System.err.println(x);
		Runtime.getRuntime().exit(-1);
	    }
	}

	// always need auth id
	if (id.length() == 0 || passwd.length() == 0) {
	    System.err.println("Username (-I) and password (-P) are required.");
	    System.err.println(usage);
	    Runtime.getRuntime().exit(-1);
	}

	// initialize client connection to CIMOM
	try {
	    CIMNameSpace ns = new CIMNameSpace(host);
	    UserPrincipal principal = new UserPrincipal(id);
            PasswordCredential credential = new PasswordCredential(passwd);
	    client = new CIMClient(ns, principal, credential);
	    // System.err.println("CLIENT: " + client);
	} catch (CIMException x) {
	    System.err.println(x);
	    Runtime.getRuntime().exit(-1);
	}

	// just list available properties?
	if (listprops) {
	    listProps();
	    Runtime.getRuntime().exit(0);
	}

	// always need a user id or project name
	if (user.length() == 0) {
	    if (project.length() == 0) {
		System.err.println(
		    "User (-u) or project (-p) must be specified.");
		System.err.println(usage);
		Runtime.getRuntime().exit(-1);
	    } else {
		name = project;
		showproject = true;
	    }
	} else
	    name = user;

	// just check for entity existence?
	if (checkonly) {
	    checkOnly(name);
	    Runtime.getRuntime().exit(0);
	}


	// examine specified process aggregate 
	String className = new String("Solaris_");
	className += (showproject ? "Project" : "User");
	className += "ProcessAggregateStatisticalInformation";

	// check that all specified props exist
	validateProps();
	
	printHeader(name, props);

	long timestamp = 0;
	long lastTimestamp = 0;

	Hashtable oldVals = new Hashtable();
	Hashtable newVals = new Hashtable();
	String p;
	
	try {
	    
	    CIMObjectPath op = new CIMObjectPath(className);
	    op.addKey("Name", new CIMValue(name));
	    // System.err.println("OP: " + op);

	    while (true) {
		CIMInstance ci = client.getInstance(op, false);
		// System.err.println("CI: " + ci);

		CIMValue val = ci.getProperty("Timestamp").getValue();
		timestamp = ((UnsignedInt64) val.getValue()).longValue();
		newVals.put("Timestamp", val);
		
		if (timestamp > lastTimestamp) {
		    Enumeration e = props.elements();
		    while (e.hasMoreElements()) {
			p = (String) e.nextElement();
			val = ci.getProperty(p).getValue();
			newVals.put(p, val);
		    }
		    lastTimestamp = timestamp;

		    e = props.elements();
		    while (e.hasMoreElements()) {
			p = (String) e.nextElement();
			String s = new String();
			CIMValue o = (CIMValue) oldVals.get(p);
			CIMValue n = (CIMValue) newVals.get(p);

			{
			    String a = "x";
			    String b = "x";
			    if (o != null)
				a = o.toString();
			    if (n != null)
				b = n.toString();
			    // System.out.print(p + ": " + a + "/" + b + "\t");
			}
			
			if (deltaprops.contains(p)) {
			    s = delta(n, o);
			    oldVals.put(p, n);
			} else {
			    s = n.toString();
			}
			System.out.print(s + "\t");
		    }
		    System.out.println();
		    
		}
		Thread.sleep(intervalms);
	    }
		
	} catch (Exception x) {
	    x.printStackTrace();
	}
    }

    
    public static void main(String args[]) {
	stats inst = new stats();
	inst._main(args);

    }
}
