#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Automatically generated code; do not edit
#
# lib/libadt_jni/spec/private.spec

function        j2c_pointer
include         <bsm/adt.h>, <jni.h>, "../../com/sun/audit/AuditSession.h", <string.h> <netdb.h>
declaration     int j2c_pointer(JNIEnv *, jbyteArray, caddr_t *)
version         SUNWprivate_1.1
end

function        c2j_pointer
include         <bsm/adt.h>, <jni.h>, "../../com/sun/audit/AuditSession.h", <string.h> <netdb.h>
declaration     void c2j_pointer(JNIEnv *, caddr_t, jbyteArray *)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditSession_bsmAuditOn
include         <bsm/adt.h>, <jni.h>, "../../com/sun/audit/AuditSession.h", <string.h> <netdb.h>
declaration     jboolean Java_com_sun_audit_AuditSession_bsmAuditOn(JNIEnv *, jobject)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditSession_startSession
include         <bsm/adt.h>, <jni.h>, "../../com/sun/audit/AuditSession.h", <string.h> <netdb.h>
declaration     jbyteArray Java_com_sun_audit_AuditSession_startSession(JNIEnv *, jobject, jbyteArray, jlong)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditSession_endSession
include         <bsm/adt.h>, <jni.h>, "../../com/sun/audit/AuditSession.h", <string.h> <netdb.h>
declaration     void Java_com_sun_audit_AuditSession_endSession(JNIEnv *, jobject, jbyteArray)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditSession_dupSession
include         <bsm/adt.h>, <jni.h>, "../../com/sun/audit/AuditSession.h", <string.h> <netdb.h>
declaration     jbyteArray Java_com_sun_audit_AuditSession_dupSession(JNIEnv *, jobject, jbyteArray)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditSession_getSessionId
include         <bsm/adt.h>, <jni.h>, "../../com/sun/audit/AuditSession.h", <string.h> <netdb.h>
declaration     jstring Java_com_sun_audit_AuditSession_getSessionId(JNIEnv *, jobject, jbyteArray)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditSession_exportSessionData
include         <bsm/adt.h>, <jni.h>, "../../com/sun/audit/AuditSession.h", <string.h> <netdb.h>
declaration     jbyteArray Java_com_sun_audit_AuditSession_exportSessionData (JNIEnv *, jobject, jbyteArray)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditSession_sessionAttr
include         <bsm/adt.h>, <jni.h>, "../../com/sun/audit/AuditSession.h", <string.h> <netdb.h>
declaration     void Java_com_sun_audit_AuditSession_sessionAttr(JNIEnv *, jobject, jbyteArray, jint, jint, jint, jint, jstring, jint)
version         SUNWprivate_1.1
end

/* One subclass of AuditEvent per audit record... */

function        Java_com_sun_audit_AuditEvent_1admin_1authenticate_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1admin_1authenticate_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jint)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1filesystem_1add_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1filesystem_1add_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1filesystem_1delete_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1filesystem_1delete_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1filesystem_1modify_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1filesystem_1modify_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1login_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1login_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jint)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1logout_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1logout_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1network_1add_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1network_1add_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1network_1delete_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1network_1delete_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1network_1modify_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1network_1modify_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1passwd_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1passwd_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1printer_1add_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1printer_1add_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1printer_1delete_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1printer_1delete_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1printer_1modify_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1printer_1modify_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1rlogin_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1rlogin_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jint)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1role_1login_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1role_1login_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jint)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1scheduledjob_1add_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1scheduledjob_1add_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1scheduledjob_1delete_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1scheduledjob_1delete_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1scheduledjob_1modify_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1scheduledjob_1modify_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1screenlock_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1screenlock_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1screenunlock_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1screenunlock_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1serialport_1add_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1serialport_1add_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1serialport_1delete_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1serialport_1delete_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1serialport_1modify_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1serialport_1modify_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1ssh_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1ssh_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jint)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1su_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1su_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1telnet_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1telnet_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jint)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1uauth_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1uauth_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1usermgr_1add_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1usermgr_1add_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1usermgr_1delete_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1usermgr_1delete_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end

function        Java_com_sun_audit_AuditEvent_1usermgr_1modify_putEvent
include         "../../../libbsm/common/adt_xlate.h", <jni.h>, <string.h>
declaration     void Java_com_sun_audit_AuditEvent_1usermgr_1modify_putEvent(JNIEnv *, jobject, jbyteArray, jint, jint, jstring, jstring, jstring, jstring, jstring)
version         SUNWprivate_1.1
end
