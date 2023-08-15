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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */
package com.sun.audit;

import java.util.Stack;
import java.io.Serializable;

public class AuditSession implements Serializable
{
	// LD_LIBRARY_PATH determines directory for libadt_jni.so.
	// When you get an UnsatisfiedLinkError, and have determined
	// the path is right, the problem is probably in the library
	// itself, but Java doesn't say what it is.  Set up a cc
	// command to link the library to see what the actual error
	// is.

	static private boolean library_loaded = false;
	static {
		try {
			System.loadLibrary("adt_jni");
			library_loaded = true;
		} catch (Exception ex) {
			library_loaded = false;
		} catch (java.lang.UnsatisfiedLinkError ul) {
			library_loaded = false;
		}
	}
	private native boolean bsmAuditOn();
	private native byte[] startSession(
	    byte[] context, long flags)
	    throws Error;
	private native byte[] dupSession(
	    byte[] source)
	    throws Error;
	private native void endSession(byte[] sessionHandle)
	    throws Error;
	private native String getSessionId(byte[] sessionHandle)
	    throws Error;
	private native byte[] exportSessionData(byte[] sessionHandle)
	    throws Error;
	private native void sessionAttr(byte[] sessionHandle,
	    int euid, int egid, int ruid, int rgid,
            String hostname, int context)
	    throws Error;
//TSOL only
//	private native void setSL(byte[] sessionHandle, String label);
//end TSOL

	private byte[] sh;  // current session handle

	private Stack stateStack = new Stack();  // for push/pop

	boolean AuditIsOn = true;		// Underlying BSM state
	boolean ValidSession = true;		// Session object state

	// Create an audit session.
	// The fixed length of 8 corresponds to a 64 bit pointer;
	// valid overkill on 32 bit systems.
	// Even if bsmAuditOn returns false, need to create a session.

	public AuditSession(byte[] context) {

		if (!library_loaded) {
			ValidSession = false;
			AuditIsOn = false;
			sh = new byte[8];  // NULL pointer in C
			return;
		}
		AuditIsOn = bsmAuditOn();
		try {
			sh = startSession(context, 0);
		}
		catch (java.lang.Exception e) {
			ValidSession = false;
			sh = new byte[8];
		}
		catch (java.lang.Error e) {
			ValidSession = false;
			sh = new byte[8];
			throw e;
		}
	}

	// getSession() is for use by AuditEvent, not much use to caller of
	// AuditSession "package protected"  == not public
	//
	// If you think you need this C pointer (sh), see
	// exportSession() and the "context" parameter to
	// startSession() for a way to pass an audit thread from one
	// process to another or from one language to another.

	byte[] getSession() {
		return sh;
	}

	public String getSessionId() throws Exception {
		String	sessionId;

		if (ValidSession) {
			try {
				sessionId = getSessionId(sh);
			}
			catch (Exception e) {
				sessionId = null;
				throw e;
			}
			catch (Error e) {
				sessionId = null;
				throw e;
			}
		} else {
			sessionId = null;
		}
		return sessionId;
	}

	// auditOn: The return value does not reveal whether or
	// auditing is on, but whether or not the current audit
	// session was created ok.

	public boolean auditOn() {
		return (ValidSession);
	}

	public void finalize() {
		byte[]	state;

		while (!stateStack.empty()) {
			state = (byte[])stateStack.pop();
			endSession(state);
		}
		endSession(sh);
	}

	// Returns export data even if auditing is off.  If the
	// session is invalid (no jni library, memory error in
	// startSession), returns null.
	//
	// If you use exportSession(), it is important that you first
	// call setUser() even when auditOn() returns false; otherwise
	// the exported session will result in remote processes being
	// unable to generate an valid audit trail.

	public byte[] exportSession() throws Exception {
		byte[]	exportedData;

		if (ValidSession) {
			try {
				exportedData = exportSessionData(sh);
			}
			catch (java.lang.Exception e) {
				throw e;
			}
		} else {
			exportedData = null;
		}
		return exportedData;
	}

	// ADT_NEW, ADT_UPDATE and ADT_USER are the only valid values
	// for the context input to setUser().  If the user has
	// completed initial authentication, use ADT_NEW; if the user
	// is to change ids, such as to a role or to root, use
	// ADT_UPDATE.  If the process audit context is already set,
	// use ADT_USER.

	// If a uid or gid is unknown (e.g., unrecognized login id)
	// then use ADT_NO_ATTRIB for the uid/gid.
	//
	// For ADT_UPDATE only, use ADT_NO_CHANGE for any uid or gid
	// that you don't wish to change.

	public static final int ADT_NEW = 0;
	public static final int ADT_UPDATE = 1;
	public static final int ADT_USER = 2;
	public static final int ADT_NO_ATTRIB = -1;
	public static final int ADT_NO_CHANGE = -2;

	public void setUser(int euid, int egid, int ruid, int rgid,
			     String hostname, int context) {

		if (ValidSession) {
			try {
				sessionAttr(sh, euid, egid, ruid, rgid,
				    hostname, context);
			}
			catch (java.lang.Error e) {
				throw e;
			}
		}
	}

	// pushState duplicates the session handle, puts the source
	// handle on a stack, and makes the duplicate the current
	// handle dupSession throws an out of memory error to be
	// caught higher up.

	public void pushState() throws Exception {
		byte[]		copy;
		int		i;

		copy = dupSession(sh);
		stateStack.push(sh);
		sh = copy;
	}

	// popState frees the current handle and pops a handle off a
	// stack to become the new current handle.
	// As with pushState, it lets the caller deal with any exceptions.

	public void popState() throws Exception {

		endSession(sh);
		sh = (byte[])stateStack.pop();
	}
//TSOL -- stub for base Solaris; should be called even if auditOn is
//false.
	public void setLabel(String label) throws Exception {
	//	if (ValidSession)
	//		setSL(sh, label);
	}
//end TSOL
}
