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
 * Copyright (c) 2001-2002 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */
package com.sun.audit;

// audit event:  AUE_usermgr_modify = 6198

public class AuditEvent_usermgr_modify extends AuditEvent {

	private native void putEvent(byte[]session, 
	    int status, int ret_val,
	    String	object_name,
	    String	domain,
	    String	name_service,
	    String	auth_used,
	    String	changed_values);

	public AuditEvent_usermgr_modify(AuditSession session)
		throws Exception {
		super(session);
	}


	private String object_name_val = "";	// required
	public void object_name(String setTo) {
		object_name_val = setTo;
	}

	private String domain_val;	// optional
	public void domain(String setTo) {
		domain_val = setTo;
	}

	private String name_service_val = "";	// required
	public void name_service(String setTo) {
		name_service_val = setTo;
	}

	private String auth_used_val;	// optional
	public void auth_used(String setTo) {
		auth_used_val = setTo;
	}

	private String changed_values_val = "";	// required
	public void changed_values(String setTo) {
		changed_values_val = setTo;
	}

	public void putEvent(int status, int ret_val) {
		byte[]	session = super.sh.getSession();

		if ((super.sh.AuditIsOn) && (super.sh.ValidSession))
			putEvent(session, status, ret_val,
			    object_name_val,
			    domain_val,
			    name_service_val,
			    auth_used_val,
			    changed_values_val);
	}
}
