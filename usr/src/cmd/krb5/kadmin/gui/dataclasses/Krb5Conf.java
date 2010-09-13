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

//
// Class representing the info from /etc/krb5/krb5.conf.
// Currently, the admin tool only needs to access all of the 
// admin servers for all of the realms enumerated in the file,
// and the default realm.
// A sample file looks like this:

/*

[libdefaults]
	default_realm = SUNSOFT.FOO.SUN.COM

[realms]
	GENESIS.FOO.SUN.COM = {
		kdc = xxxxx.eng.sun.com
		admin_server = xxxxx.eng.sun.com
	}
	SUNSOFT.FOO.SUN.COM = {
		kdc = gandolf.eng.sun.com
		kdc = ulong.eng.sun.com
		admin_server = gandolf.eng.sun.com:749
	}

[domain_realm]
	.eng.sun.com = SUNSOFT.FOO.SUN.COM
	.sun.com = SUNSOFT.FOO.SUN.COM

[logging]
	default = FILE:/var/krb5/kdc.log
	kdc = FILE:/var/krb5/kdc.log

[appdefaults]
	gkadmin = {
                help_url = http:...
	}
*/

import java.io.*;
import java.util.Vector;
import java.util.StringTokenizer;

public class Krb5Conf {

    private String DefRealm = null;
    private String HelpURL = null;
    private Vector RealmVector = new Vector(10, 10);

    public Krb5Conf() {
    	
    	FileReader fr = null;

    	try {
	    fr = new FileReader("/etc/krb5/krb5.conf");
	} catch (FileNotFoundException e) {
	    // System.out.println("Error: " + e);
	    return;
	}
	BufferedReader in = new BufferedReader(fr);

	String line = null, Name = null, Server = "", Port = "0";
	boolean wantdef = false, wantrealm = false;
	boolean wantadmin = false, skipcurly = false;
	boolean wantapp = false, wanturl = false;
	RealmInfo r = null;

	// Read each line of the file
	do {
	    try {
		line = in.readLine();
	    } catch (IOException e) {
		// System.out.println("Error: " + e);
		return;
	    }
	    if (line == null)
		break;
//	    System.out.println(line);

	    // Get some help with parsing
	    StringTokenizer t = new StringTokenizer(line);
	    if (!t.hasMoreTokens())
		continue;
	    String s = t.nextToken();
	    if (s.charAt(0) == '#')
		continue;

	    // Look for [realm], [libdefaults] or [appdefaults]
	    if (s.charAt(0) == '[') {
		wantdef = false;
		wantrealm = false;
		wantapp = false;
		if (s.compareTo("[libdefaults]") == 0)
		    wantdef = true;
		if (s.compareTo("[realms]") == 0)
		    wantrealm = true;
		if (s.compareTo("[appdefaults]") == 0)
		    wantapp = true;
	    } else {

		// Have we seen [libdefaults]?
		if (wantdef && s.compareTo("default_realm") == 0) {
		    if (t.hasMoreTokens()) {
			DefRealm = t.nextToken(" \t\n\r=");
			wantdef = false;
		    }

		// Have we seen [realm] instead?
		} else if (wantrealm) {

		    // We got what we needed; skip until "{" is balanced
		    if (skipcurly && s.compareTo("}") == 0) {
			skipcurly = false;
			continue;
		    }
		    // First the realm name, then the admin server
		    if (!wantadmin) {
			Name = new String(s);
			wantadmin = true;
			Server = "";
			Port = "0";
		    } else {
			if (s.compareTo("admin_server") == 0) {
			    s = t.nextToken(" \t\n\r=:");
			    Server = new String(s);
			    if (t.hasMoreTokens()) {
				s = t.nextToken(" \t\n\r=:");
				Port = new String(s);
			    }

			    // Store result in the vector
			    r = new RealmInfo(Name, Server, Port);
			    RealmVector.addElement(r);
			    wantadmin = false;
			    skipcurly = true;
			}
		    }
		} else if (wantapp) {
		    if (wanturl && s.compareTo("help_url") == 0) {
			if (t.hasMoreTokens()) {
			    HelpURL = t.nextToken(" \t\n\r=");
			    wantapp = false;
			    wanturl = false;
			}
		    } else if (s.compareTo("gkadmin") == 0)
			wanturl = true;
		}
	    }	    
	} while (line != null);
    }

    public String getDefaultRealm() {
	return DefRealm;
    }

    public String getHelpURL() {
	return HelpURL;
    }

    public String getAllRealms() {
	String s = "";
	for (int i = 0; i < RealmVector.size(); i++) {
	    RealmInfo r = (RealmInfo)RealmVector.elementAt(i);
	    s = new String(s + " " + r.RealmName);
	}
	return s;
    }

    public String getRealmServer(String realm) {
	for (int i = 0; i < RealmVector.size(); i++) {
	    RealmInfo r = (RealmInfo)RealmVector.elementAt(i);
	    if (realm.compareTo(r.RealmName) == 0)
		return r.AdminServer;
	}
	return null;
    }
    
    public String getRealmPort(String realm) {
	for (int i = 0; i < RealmVector.size(); i++) {
	    RealmInfo r = (RealmInfo)RealmVector.elementAt(i);
	    if (realm.compareTo(r.RealmName) == 0)
		return r.ServerPort;
	}
	return null;
    }

    class RealmInfo extends Object {
	String RealmName;
	String AdminServer;
	String ServerPort;
	
	public RealmInfo(String name, String server, String port) {
	    RealmName = new String(name);
	    AdminServer = new String(server);
	    ServerPort = new String(port);
	}
    }

    public static void main(String[] args) {
	Krb5Conf c = new Krb5Conf();
	System.out.println("Default: " + c.getDefaultRealm());
	System.out.println("Realms: " + c.getAllRealms());
	StringTokenizer t = new StringTokenizer(c.getAllRealms());
	while (t.hasMoreTokens()) {
	    String r = t.nextToken();
	    String s = c.getRealmServer(r);
	    String p = c.getRealmPort(r);
	    System.out.println("For realm " + r + ", server is " + s
				     + ", port is " + p);
	}
	System.out.println("HelpURL: " + c.getHelpURL());
    }
}
