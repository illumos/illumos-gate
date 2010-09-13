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

import java.awt.*;

import Principal;
import Policy;
import Defaults;

public class Test {

	/**
	 * main method for easier debugging
	 */
	public static void main(String[] args) {
	    System.out.println("\nThese are unit tests for the JNI code.");
	    System.out.println("They assume the existence of a jnitest/admin");
	    System.out.println("user principal, with the password 'test123',");
	    System.out.println("and the existance of a 'default' policy.\n");

	    Kadmin k = new Kadmin();
	    String [] p;
	    Defaults d = new Defaults("$HOME/.gkadmin", Color.white);

	    System.out.println("==> Set up a session for jnitest/admin.\n");
	    boolean b = false;

	    System.out.println("*** First, one with a bogus port number.");
	    try {
		b = k.sessionInit("jnitest/admin", "test123",
		    "SUNSOFT.ENG.SUN.COM", "ulong.eng.sun.com", 333);
		b = false;
		k.sessionExit();
		System.out.println("Unexpected success!\n");
	    } catch (Exception e) {
		b = false;
		System.out.println("Expected failure "+e.getMessage()+"\n");
	    }

	    System.out.println("*** Next, one with the correct port number.");
	    try {
		b = k.sessionInit("jnitest/admin", "test123",
		    "SUNSOFT.ENG.SUN.COM", "ulong.eng.sun.com", 749);
		b = false;
		k.sessionExit();
		System.out.println("sessionInit was successful.\n");
	    } catch (Exception e) {
		b = false;
		System.out.println("Unexpected exception!"+e.getMessage()+"\n");
	    }

	    System.out.println("*** Finally, try one with a zero port number.");
	    try {
		b = k.sessionInit("jnitest/admin", "test123",
		    "SUNSOFT.ENG.SUN.COM", "ulong.eng.sun.com", 0);
	    } catch (Exception e) {
		b = false;
		System.out.println("Unexpected exception!"+e.getMessage()+"\n");
	    }
	    if (!b) {
		System.out.println("sessionInit failed\n");
		return;
	    }
	    System.out.println("sessionInit was successful!\n");


	    System.out.println("==> Get the lists\n");
	    System.out.println("*** Principal list");
	    try {
		p = k.getPrincipalList();
		System.out.println("Called getPrincipalList()");
	    } catch (Exception e) {
		p = null;
		System.out.println("getPrincipalList exception"+e.getMessage());
	    }
	    for (int i = 0; p != null && i < p.length; i++)
		System.out.println(p[i]);
	    System.out.println(new Integer(p.length).toString()+" entries.");
	    System.out.println("Principal list done\n");


	    System.out.println("*** Policy list");
	    try {
		p = k.getPolicyList();
		System.out.println("Called getPolicyList()");
	    } catch (Exception e) {
		p = null;
		System.out.println("getPolicyList exception "+e.getMessage());
	    }
	    for (int i = 0; p != null && i < p.length; i++)
		System.out.println(p[i]);
	    System.out.println(new Integer(p.length).toString()+" entries.");
	    System.out.println("Policy list done\n");


	    System.out.println("==> Get privileges\n");
	    System.out.println("Calling getPrivs()");
	    int privs = 0;
	    try {
		privs = k.getPrivs();
		System.out.println("Privs are "
		    +(new Integer(privs)).toHexString(privs)+"\n");
	    } catch (Exception e) {
		System.out.println("getPrivs exception "+e.getMessage()+"\n");
	    }


	    System.out.println("==> Database tests\n");
	    System.out.println("*** load a principal");
	    System.out.println("Calling Principal(k)");
	    Principal pr = new Principal(k, d);
	    System.out.println("Calling loadPrincipal(jnitest/admin)");
	    try {
		b = k.loadPrincipal("jnitest/admin", pr);
	    } catch (Exception e) {
		b = false;
		System.out.println("loadPrincipal exception "+e.getMessage());
	    }
	    if (!b)
		System.out.println("loadPrincipal failed\n");
	    else {
		System.out.println("loadPrincipal succeeded, details:");
		System.out.println(pr.toString());
	    }


	    System.out.println("*** load a policy");
	    Policy po = new Policy(k);
	    try {
		b = k.loadPolicy("default", po);
	    } catch (Exception e) {
		b = false;
		System.out.println("loadPolicy exception "+e.getMessage());
	    }
	    if (!b)
		System.out.println("loadPolicy failed\n");
	    else {
		System.out.println("loadPolicy succeeded");
		System.out.println("RefCount for "+po.PolicyName+" is "
		    +po.RefCount.toString());
		System.out.println("PwMinLife for "+po.PolicyName+" is "
		    +po.PwMinLife.toString()+"\n");
	    }


	    System.out.println("*** load and store a policy");
	    try {
		b = k.loadPolicy("default", po);
	    } catch (Exception e) {
		b = false;
		System.out.println("loadPolicy exception "+e.getMessage());
	    }
	    if (b) {
		po.setPolMinlife("555");
		try {
		    b = k.savePolicy(po);
		} catch (Exception e) {
		    b = false;
		    System.out.println("savePolicy exception "+e.getMessage());
		}
		if (!b)
		    System.out.println("savePolicy failed\n");
		else
		    System.out.println("savePolicy succeeded\n");
	    }


	    System.out.println("*** create a policy");
	    po = new Policy("aliens");
	    try {
		b = k.createPolicy(po);
	    } catch (Exception e) {
		b = false;
		System.out.println("createPolicy exception "+e.getMessage());
	    }
	    if (!b)
		System.out.println("createPolicy failed\n");
	    else
		System.out.println("createPolicy succeeded\n");

	    System.out.println("*** verify creation");
	    try {
		p = k.getPolicyList();
		System.out.println("Called getPolicyList()");
	    } catch (Exception e) {
		p = null;
		System.out.println("getPolicyList exception "+e.getMessage());
	    }
	    for (int i = 0; p != null && i < p.length; i++)
		if (p[i].equals("aliens"))
		    System.out.println("Found 'aliens' as expected");
	    System.out.println(new Integer(p.length).toString()+" entries.");
	    System.out.println("Policy list done\n");


	    System.out.println("*** delete a policy");
	    try {
		b = k.deletePolicy("aliens");
	    } catch (Exception e) {
		b = false;
		System.out.println("deletePolicy exception "+e.getMessage());
	    }
	    if (!b)
		System.out.println("deletePolicy failed\n");
	    else
		System.out.println("deletePolicy succeeded\n");

	    System.out.println("*** verify deletion");
	    try {
		p = k.getPolicyList();
		System.out.println("Called getPolicyList()");
	    } catch (Exception e) {
		p = null;
		System.out.println("getPolicyList exception "+e.getMessage());
	    }
	    for (int i = 0; p != null && i < p.length; i++)
		if (p[i].equals("aliens"))
		    System.out.println("Found 'aliens' - oops!");
	    System.out.println(new Integer(p.length).toString()+" entries.");
	    System.out.println("Policy list done\n");


	    System.out.println("*** load and store a principal");
	    try {
		b = k.loadPrincipal("jnitest/admin", pr);
	    } catch (Exception e) {
		b = false;
		System.out.println("loadPrincipal exception "+e);
	    }
	    if (b) {
		System.out.println("Loaded "+pr.toString());
		pr.setPolicy("default");
		System.out.println("Expiry "+pr.PrExpireTime.toString());
		System.out.println("PwExpiry "+pr.PwExpireTime.toString());
		try {
		    b = k.savePrincipal(pr);
		} catch (Exception e) {
		    b = false;
		    System.out.println("savePrincipal exception "+e);
		}
		if (!b)
		    System.out.println("savePrincipal failed\n");
		else
		    System.out.println("savePrincipal succeeded\n");
	    }


	    System.out.println("*** ensure a principal is absent");
	    try {
		b = k.deletePrincipal("harriet");
	        System.out.println("deleted principal\n");
	    } catch (Exception e) {
	        System.out.println("Expected exception"+e+"\n");
	    }


	    System.out.println("*** create a principal");
	    pr = new Principal("harriet");
	    pr.setPassword("test123");
	    System.out.println("Built "+pr.toString());
	    try {
		b = k.createPrincipal(pr);
	    } catch (Exception e) {
		b = false;
		System.out.println("createPrincipal exception "+e);
	    }
	    if (!b)
		System.out.println("createPrincipal failed");
	    else
		System.out.println("createPrincipal succeeded");

	    System.out.println("*** verify creation");
	    try {
		p = k.getPrincipalList();
	    } catch (Exception e) {
		p = null;
		System.out.println("getPrincipalList exception "+e);
	    }
	    System.out.println("Called getPrincipalList()");
	    for (int i = 0; p != null && i < p.length; i++)
		if (p[i].equals("harriet"))
		    System.out.println("Found 'harriet' as expected");
	    System.out.println(new Integer(p.length).toString()+" entries.");
	    System.out.println("Principal list done\n");


	    System.out.println("*** set comments");
	    pr = new Principal(k, d);
	    try {
		b = k.loadPrincipal("harriet", pr);
	    } catch (Exception e) {
		b = false;
		System.out.println("loadPrincipal exception "+e);
	    }
	    if (b) {
		pr.setComments("Who knows this user?");
		try {
		    b = k.savePrincipal(pr);
		} catch (Exception e) {
		    b = false;
		    System.out.println("savePrincipal exception "+e);
		}
		if (b) {
		    try {
			b = k.loadPrincipal("harriet", pr);
		    } catch (Exception e) {
			b = false;
			System.out.println("loadPrincipal exception "+e);
		    }
		    System.out.println("Loaded "+pr.toString());
		    System.out.println("Comments are "+pr.Comments+"\n");
		} else
		    System.out.println("savePrincipal failed");
	    }


	    System.out.println("*** set password");
	    pr = new Principal(k, d);
	    try {
		b = k.loadPrincipal("harriet", pr);
	    } catch (Exception e) {
		b = false;
		System.out.println("loadPrincipal exception "+e);
	    }
	    if (b) {
		pr.setPassword("test234");
		try {
		    b = k.savePrincipal(pr);
		} catch (Exception e) {
		    b = false;
		    System.out.println("savePrincipal exception "+e);
		}
		if (!b)
		    System.out.println("savePrincipal failed\n");
		else
		    System.out.println("savePrincipal succeeded\n");
	    }


	    System.out.println("*** delete principal");
	    try {
		b = k.deletePrincipal("harriet");
	    } catch (Exception e) {
		b = false;
		System.out.println("deletePrincipal exception "+e);
	    }
	    if (!b)
		System.out.println("deletePrincipal failed\n");
	    else
		System.out.println("deletePrincipal succeeded\n");

	    System.out.println("*** verify deletion");
	    try {
		p = k.getPrincipalList();
		System.out.println("Called getPrincipalList()");
	    } catch (Exception e) {
		p = null;
		System.out.println("getPrincipalList exception "+e);
	    }
	    for (int i = 0; p != null && i < p.length; i++)
		if (p[i].equals("harriet"))
		    System.out.println("Found 'harriet' - oops!");
	    System.out.println(new Integer(p.length).toString()+" entries.");
	    System.out.println("Principal list done\n");


	    System.out.println("*** create a principal with comments");
	    pr = new Principal("harriet");
	    pr.setPassword("test123");
	    pr.setComments("Room 1229");
	    System.out.println("Built "+pr.toString());
	    try {
		b = k.createPrincipal(pr);
	    } catch (Exception e) {
		b = false;
		System.out.println("createPrincipal exception "+e);
	    }
	    if (!b)
		System.out.println("createPrincipal failed\n");
	    else
		System.out.println("createPrincipal succeeded\n");

	    System.out.println("*** verify comments");
	    try {
		b = k.loadPrincipal("harriet", pr);
	    } catch (Exception e) {
		b = false;
		System.out.println("loadPrincipal exception "+e);
	    }
	    if (b) {
		System.out.println("Loaded "+pr.toString());
		System.out.println("Comments "+pr.Comments+"\n");
		try {
		    b = k.deletePrincipal("harriet");
		} catch (Exception e) {
		    b = false;
		    System.out.println("deletePrincipal exception "+e);
		}
	    }

	    System.out.println("All tests completed.\n");
	    k.sessionExit();
	}
}
