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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * NameService class
 * Methods and state associated with a name service.
 */

package com.sun.admin.pm.server;

import java.io.*;

public class NameService
{
    private String nameservice = null;
    private String nshost = null;
    private String user = null;
    private String passwd = null;
    private boolean boundtonisslave = false;
    private boolean isauth = false;

    //
    // Constructors
    //
    // This constructor is used internally in the server package.
    public NameService()
    {
	nameservice = "system";
	isauth = true;
    }
    // This constructor should always be used by the client.
    public NameService(String nsname) throws Exception
    {
	if ((nsname.equals("system")) ||
	    (nsname.equals("nis")) ||
	    (nsname.equals("ldap"))) {
		nameservice = nsname;
	} else {
		throw new pmInternalErrorException(
			"Unknown name service: " + nsname);
	}

	Host h = new Host();
	h.isNSConfigured(nameservice);

	if (nsname.equals("nis")) {
		String nm = h.getNisHost("master");
		String nb = h.getNisHost("bound");
		if (!nm.equals(nb)) {
			boundtonisslave = true;
		}
		setUser("root");
		setNameServiceHost(nm);
		setPasswd("");
	} else if (nsname.equals("ldap")) {
		String master = h.getLDAPMaster();
		if (master == null) {
			setNameServiceHost("");
		} else {
			setNameServiceHost(master);
		}

		String admin = h.getDefaultAdminDN();
		if (admin == null) {
			setUser("");
		} else {
			setUser(admin);
		}

		setPasswd("");
	}

    }

    public void setNameServiceHost(String arg)
    {
	nshost = arg;
    }
    public void setUser(String arg)
    {
	user = arg;
    }
    public void setPasswd(String arg)
    {
	passwd = arg;
    }

    public String getNameService()
    {
	return (nameservice);
    }
    public String getNameServiceHost()
    {
	return (nshost);
    }
    public String getUser()
    {
	return (user);
    }
    public String getPasswd()
    {
	return (passwd);
    }
    public boolean getBoundToNisSlave()
    {
	return (boundtonisslave);
    }
    public boolean isAuth()
    {
	return (isauth);
    }

    public void checkAuth() throws Exception
    {
	Debug.message("SVR: NameService.checkAuth()");

	DoPrinterNS.doAuth(this);
	isauth = true;
    }
}
