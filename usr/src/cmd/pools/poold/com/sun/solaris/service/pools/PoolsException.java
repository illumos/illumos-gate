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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */

package com.sun.solaris.service.pools;

/**
 * The <code>PoolsException</code> class represents a pools error.  It
 * is used to report any errors in native code.  See
 * <code>errno(3C)</code> for information on the system (POE_SYSTEM)
 * error codes.
 */
public class PoolsException extends Exception {
	/**
	 * EPERM.
	 */
	public static final int EPERM = 1;

	/**
	 * ENOENT.
	 */
	public static final int ENOENT = 2;

	/**
	 * ESRCH.
	 */
	public static final int ESRCH = 3;

	/**
	 * EINTR.
	 */
	public static final int EINTR = 4;

	/**
	 * EIO.
	 */
	public static final int EIO = 5;

	/**
	 * ENXIO.
	 */
	public static final int ENXIO = 6;

	/**
	 * E2BIG.
	 */
	public static final int E2BIG = 7;

	/**
	 * ENOEXEC.
	 */
	public static final int ENOEXEC = 8;

	/**
	 * EBADF.
	 */
	public static final int EBADF = 9;

	/**
	 * ECHILD.
	 */
	public static final int ECHILD = 10;

	/**
	 * EAGAIN.
	 */
	public static final int EAGAIN = 11;

	/**
	 * ENOMEM.
	 */
	public static final int ENOMEM = 12;

	/**
	 * EACCES.
	 */
	public static final int EACCES = 13;

	/**
	 * EFAULT.
	 */
	public static final int EFAULT = 14;

	/**
	 * ENOTBLK.
	 */
	public static final int ENOTBLK = 15;

	/**
	 * EBUSY.
	 */
	public static final int EBUSY = 16;

	/**
	 * EEXIST.
	 */
	public static final int EEXIST = 17;

	/**
	 * EXDEV.
	 */
	public static final int EXDEV = 18;

	/**
	 * ENODEV.
	 */
	public static final int ENODEV = 19;

	/**
	 * ENOTDIR.
	 */
	public static final int ENOTDIR = 20;

	/**
	 * EISDIR.
	 */
	public static final int EISDIR = 21;

	/**
	 * EINVAL.
	 */
	public static final int EINVAL = 22;

	/**
	 * ENFILE.
	 */
	public static final int ENFILE = 23;

	/**
	 * EMFILE.
	 */
	public static final int EMFILE = 24;

	/**
	 * ENOTTY.
	 */
	public static final int ENOTTY = 25;

	/**
	 * ETXTBSY.
	 */
	public static final int ETXTBSY = 26;

	/**
	 * EFBIG.
	 */
	public static final int EFBIG = 27;

	/**
	 * ENOSPC.
	 */
	public static final int ENOSPC = 28;

	/**
	 * ESPIPE.
	 */
	public static final int ESPIPE = 29;

	/**
	 * EROFS.
	 */
	public static final int EROFS = 30;

	/**
	 * EMLINK.
	 */
	public static final int EMLINK = 31;

	/**
	 * EPIPE.
	 */
	public static final int EPIPE = 32;

	/**
	 * EDOM.
	 */
	public static final int EDOM = 33;

	/**
	 * ERANGE.
	 */
	public static final int ERANGE = 34;

	/**
	 * ENOMSG.
	 */
	public static final int ENOMSG = 35;

	/**
	 * EIDRM.
	 */
	public static final int EIDRM = 36;

	/**
	 * ECHRNG.
	 */
	public static final int ECHRNG = 37;

	/**
	 * EL2NSYNC.
	 */
	public static final int EL2NSYNC = 38;

	/**
	 * EL3HLT.
	 */
	public static final int EL3HLT = 39;

	/**
	 * EL3RST.
	 */
	public static final int EL3RST = 40;

	/**
	 * ELNRNG.
	 */
	public static final int ELNRNG = 41;

	/**
	 * EUNATCH.
	 */
	public static final int EUNATCH = 42;

	/**
	 * ENOCSI.
	 */
	public static final int ENOCSI = 43;

	/**
	 * EL2HLT.
	 */
	public static final int EL2HLT = 44;

	/**
	 * EDEADLK.
	 */
	public static final int EDEADLK = 45;

	/**
	 * ENOLCK.
	 */
	public static final int ENOLCK = 46;

	/**
	 * ECANCELED.
	 */
	public static final int ECANCELED = 47;

	/**
	 * ENOTSUP.
	 */
	public static final int ENOTSUP = 48;

	/**
	 * EDQUOT.
	 */
	public static final int EDQUOT = 49;

	/**
	 * EBADE.
	 */
	public static final int EBADE = 50;

	/**
	 * EBADR.
	 */
	public static final int EBADR = 51;

	/**
	 * EXFULL.
	 */
	public static final int EXFULL = 52;

	/**
	 * ENOANO.
	 */
	public static final int ENOANO = 53;

	/**
	 * EBADRQC.
	 */
	public static final int EBADRQC = 54;

	/**
	 * EBADSLT.
	 */
	public static final int EBADSLT = 55;

	/**
	 * EDEADLOCK.
	 */
	public static final int EDEADLOCK = 56;

	/**
	 * EBFONT.
	 */
	public static final int EBFONT = 57;

	/**
	 * EOWNERDEAD.
	 */
	public static final int EOWNERDEAD = 58;

	/**
	 * ENOTRECOVERABLE.
	 */
	public static final int ENOTRECOVERABLE = 59;

	/**
	 * ENOSTR.
	 */
	public static final int ENOSTR = 60;

	/**
	 * ENODATA.
	 */
	public static final int ENODATA = 61;

	/**
	 * ETIME.
	 */
	public static final int ETIME = 62;

	/**
	 * ENOSR.
	 */
	public static final int ENOSR = 63;

	/**
	 * ENONET.
	 */
	public static final int ENONET = 64;

	/**
	 * ENOPKG.
	 */
	public static final int ENOPKG = 65;

	/**
	 * EREMOTE.
	 */
	public static final int EREMOTE = 66;

	/**
	 * ENOLINK.
	 */
	public static final int ENOLINK = 67;

	/**
	 * EADV.
	 */
	public static final int EADV = 68;

	/**
	 * ESRMNT.
	 */
	public static final int ESRMNT = 69;

	/**
	 * ECOMM.
	 */
	public static final int ECOMM = 70;

	/**
	 * EPROTO.
	 */
	public static final int EPROTO = 71;

	/**
	 * ELOCKUNMAPPED.
	 */
	public static final int ELOCKUNMAPPED = 72;

	/**
	 * ENOTACTIVE.
	 */
	public static final int ENOTACTIVE = 73;

	/**
	 * EMULTIHOP.
	 */
	public static final int EMULTIHOP = 74;

	/**
	 * EBADMSG.
	 */
	public static final int EBADMSG = 77;

	/**
	 * ENAMETOOLONG.
	 */
	public static final int ENAMETOOLONG = 78;

	/**
	 * EOVERFLOW.
	 */
	public static final int EOVERFLOW = 79;

	/**
	 * ENOTUNIQ.
	 */
	public static final int ENOTUNIQ = 80;

	/**
	 * EBADFD.
	 */
	public static final int EBADFD = 81;

	/**
	 * EREMCHG.
	 */
	public static final int EREMCHG = 82;

	/**
	 * ELIBACC.
	 */
	public static final int ELIBACC = 83;

	/**
	 * ELIBBAD.
	 */
	public static final int ELIBBAD = 84;

	/**
	 * ELIBSCN.
	 */
	public static final int ELIBSCN = 85;

	/**
	 * ELIBMAX.
	 */
	public static final int ELIBMAX = 86;

	/**
	 * ELIBEXEC.
	 */
	public static final int ELIBEXEC = 87;

	/**
	 * EILSEQ.
	 */
	public static final int EILSEQ = 88;

	/**
	 * ENOSYS.
	 */
	public static final int ENOSYS = 89;

	/**
	 * ELOOP.
	 */
	public static final int ELOOP = 90;

	/**
	 * ERESTART.
	 */
	public static final int ERESTART = 91;

	/**
	 * ESTRPIPE.
	 */
	public static final int ESTRPIPE = 92;

	/**
	 * ENOTEMPTY.
	 */
	public static final int ENOTEMPTY = 93;

	/**
	 * EUSERS.
	 */
	public static final int EUSERS = 94;

	/**
	 * ENOTSOCK.
	 */
	public static final int ENOTSOCK = 95;

	/**
	 * EDESTADDRREQ.
	 */
	public static final int EDESTADDRREQ = 96;

	/**
	 * EMSGSIZE.
	 */
	public static final int EMSGSIZE = 97;

	/**
	 * EPROTOTYPE.
	 */
	public static final int EPROTOTYPE = 98;

	/**
	 * ENOPROTOOPT.
	 */
	public static final int ENOPROTOOPT = 99;

	/**
	 * EPROTONOSUPPORT.
	 */
	public static final int EPROTONOSUPPORT = 120;

	/**
	 * ESOCKTNOSUPPORT.
	 */
	public static final int ESOCKTNOSUPPORT = 121;

	/**
	 * EOPNOTSUPP.
	 */
	public static final int EOPNOTSUPP = 122;

	/**
	 * EPFNOSUPPORT.
	 */
	public static final int EPFNOSUPPORT = 123;

	/**
	 * EAFNOSUPPORT.
	 */
	public static final int EAFNOSUPPORT = 124;

	/**
	 * EADDRINUSE.
	 */
	public static final int EADDRINUSE = 125;

	/**
	 * EADDRNOTAVAIL.
	 */
	public static final int EADDRNOTAVAIL = 126;

	/**
	 * ENETDOWN.
	 */
	public static final int ENETDOWN = 127;

	/**
	 * ENETUNREACH.
	 */
	public static final int ENETUNREACH = 128;

	/**
	 * ENETRESET.
	 */
	public static final int ENETRESET = 129;

	/**
	 * ECONNABORTED.
	 */
	public static final int ECONNABORTED = 130;

	/**
	 * ECONNRESET.
	 */
	public static final int ECONNRESET = 131;

	/**
	 * ENOBUFS.
	 */
	public static final int ENOBUFS = 132;

	/**
	 * EISCONN.
	 */
	public static final int EISCONN = 133;

	/**
	 * ENOTCONN.
	 */
	public static final int ENOTCONN = 134;

	/**
	 * ESHUTDOWN.
	 */
	public static final int ESHUTDOWN = 143;

	/**
	 * ETOOMANYREFS.
	 */
	public static final int ETOOMANYREFS = 144;

	/**
	 * ETIMEDOUT.
	 */
	public static final int ETIMEDOUT = 145;

	/**
	 * ECONNREFUSED.
	 */
	public static final int ECONNREFUSED = 146;

	/**
	 * EHOSTDOWN.
	 */
	public static final int EHOSTDOWN = 147;

	/**
	 * EHOSTUNREACH.
	 */
	public static final int EHOSTUNREACH = 148;

	/**
	 * EALREADY.
	 */
	public static final int EALREADY = 149;

	/**
	 * EINPROGRESS.
	 */
	public static final int EINPROGRESS = 150;

	/**
	 * ESTALE.
	 */
	public static final int ESTALE = 151;

	private final int errorCode = PoolInternal.pool_error();

	/**
	 * Constructor.
	 */
	public PoolsException()
	{
		super(description(PoolInternal.pool_error()));
	}

	private static String description(int errorCode)
	{
		StringBuffer sb = new StringBuffer(PoolInternal.pool_strerror(
		    errorCode));
		if (errorCode == PoolInternal.POE_SYSTEM)
			sb.append(": " + PoolInternal.pool_strerror_sys());
		return (sb.toString());
	}

	/**
	 * Returns the native pool error code.
	 *
	 * @return the native pool error code.
	 */
	public int getCode()
	{
		return (errorCode);
	}

	/**
	 * Returns <code>errno</code>, if the pool error is
	 * <code>POE_SYSTEM</code>.
	 */
	public native int getErrno();
}
