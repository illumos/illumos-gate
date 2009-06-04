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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PKGLIBMSGS_H
#define	_PKGLIBMSGS_H


#ifdef __cplusplus
extern "C" {
#endif

/* srchcfile messages */
#define	ERR_MISSING_NEWLINE	"missing newline at end of entry"
#define	ERR_ILLEGAL_SEARCH_PATH	"illegal search path specified"
#define	ERR_CANNOT_READ_MM_NUMS	"unable to read major/minor device numbers"
#define	ERR_INCOMPLETE_ENTRY	"incomplete entry"
#define	ERR_VOLUMENO_UNEXPECTED	"volume number not expected"
#define	ERR_FTYPE_I_UNEXPECTED	"ftype <i> not expected"
#define	ERR_CANNOT_READ_CLASS_TOKEN	"unable to read class token"
#define	ERR_CANNOT_READ_PATHNAME_FLD	"unable to read pathname field"
#define	ERR_UNKNOWN_FTYPE	"unknown ftype"
#define	ERR_CANNOT_READ_LL_PATH	"unable to read local/link path"
#define	ERR_INCOMPLETE_ENTRY	"incomplete entry"
#define	ERR_NO_LINK_SOURCE_SPECIFIED	"no link source specified"
#define	ERR_CANNOT_READ_MOG	"unable to read mode/owner/group"
#define	ERR_CANNOT_READ_CONTENT_INFO	"unable to read content info"
#define	ERR_PACKAGE_NAME_TOO_LONG	"package name too long"
#define	ERR_NO_MEMORY	"no memory for package information"
#define	ERR_BAD_ENTRY_END	"bad end of entry"
#define	ERR_EXTRA_TOKENS	"extra token(s) on input line"

/* pkgtrans messages */
#define	MSG_TRANSFER	"Transferring <%s> package instance\n"
#define	MSG_STORE_ACC	"Retrieving signature certificates from <%s>\n"
#define	MSG_SIGNING	"Generating digital signature for signer <%s>\n"
#define	MSG_RENAME 	"\t... instance renamed <%s> on destination\n"

#define	ERR_TRANSFER	"unable to complete package transfer"
#define	MSG_SEQUENCE	"- volume is out of sequence"
#define	MSG_MEM		"- no memory"
#define	MSG_CMDFAIL	"- process <%s> failed, exit code %d"
#define	MSG_POPEN	"- popen of <%s> failed, errno=%d"
#define	MSG_PCLOSE	"- pclose of <%s> failed, errno=%d"
#define	MSG_BADDEV	"- invalid or unknown device <%s>"
#define	MSG_GETVOL	"- unable to obtain package volume"
#define	MSG_NOSIZE 	"- unable to obtain maximum part size from pkgmap"
#define	MSG_CHDIR	"- unable to change directory to <%s>"
#define	MSG_SYMLINK	"- unable to create symbolic link to <%s> from <%s>"
#define	MSG_STATDIR	"- unable to stat <%s>"
#define	MSG_CHOWNDIR	"- unable to chown <%s>"
#define	MSG_CHMODDIR	"- unable to chmod <%s>"
#define	MSG_FSTYP	"- unable to determine filesystem type for <%s>"
#define	MSG_NOTEMP	"- unable to create or use temporary directory <%s>"
#define	MSG_SAMEDEV	"- source and destination represent the same device"
#define	MSG_NOTMPFIL	"- unable to create or use temporary file <%s>"
#define	MSG_NOPKGMAP	"- unable to open pkgmap for <%s>"
#define	MSG_BADPKGINFO	"- unable to determine contents of pkginfo file"
#define	MSG_NOPKGS	"- no packages were selected from <%s>"
#define	MSG_MKDIR	"- unable to make directory <%s>"
#define	MSG_NOEXISTS	"- package instance <%s> does not exist on source " \
			"device"
#define	MSG_EXISTS	"- no permission to overwrite existing path <%s>"
#define	MSG_DUPVERS	"- identical version of <%s> already exists on " \
			"destination device"
#define	MSG_TWODSTREAM	"- both source and destination devices cannot be a " \
			"datastream"
#define	MSG_OPEN	"- open of <%s> failed, errno=%d"
#define	MSG_STATVFS	"- statvfs(%s) failed, errno=%d"

/* security problems */
#define	ERR_PARSE		"unable to parse keystore <%s>, invalid " \
				"format or corrupt"
#define	ERR_BADPASS		"Invalid password.  Password does not " \
				"decrypt keystore"

#define	MSG_PASSWD_FILE		"Password file <%s> cannot be read"
#define	MSG_PASSWD_AGAIN	"For Verification"
#define	MSG_PASSWD_NOMATCH	"Passwords do not match"
#define	MSG_BADPASSARG		"Password retrieval method <%s> invalid"
#define	MSG_NOPASS		"Cannot get passphrase using " \
				"retrieval method <%s>"

#define	ERR_MISMATCHPASS	"<%s> encrypted with different password " \
				" than <%s>, keystore <%s> corrupt"

#define	MSG_CHSIGDIR	"- unable to change directory to <%s/%s>"
#define	MSG_MKSIGDIR	"- unable to make directory <%s/%s>"
#define	ERR_CANTSIGN	"- destination device must be datastream in order to" \
			" sign contents"
#define	ERR_STORE	"unable to find or use store <%s> from application " \
			"<%s>:<%s>"

#define	ERR_NO_KEYSTORE	"unable to open keystore <%s> for reading"
#define	ERR_NOT_REG	"<%s> is not a regular file"
#define	ERR_KEYSTORE_CORRUPT	"Keystore file <%s> is corrupt or unparseable"
#define	ERR_KEYSTORE_REPAIR	"unable to repair keystore <%s>"
#define	ERR_KEYSTORE_LOCKED_READ	"unable to lock keystore file <%s> " \
					"for reading, try again later"
#define	ERR_KEYSTORE_LOCKED	"unable to lock keystore <%s> for exclusive " \
				"access"
#define	ERR_KEYSTORE_UNLOCK	"unable to unlock keystore <%s> for " \
				"application <%s>"
#define	ERR_KEYSTORE_WRITE	"unable to open keystore <%s> for writing"
#define	ERR_KEYSTORE_REMOVE	"unable to delete keystore file <%s>"
#define	ERR_KEYSTORE_READ	"unable to open keystore <%s> for reading"
#define	ERR_KEYSTORE_OPEN	"unable to open keystore <%s>:<%s>"
#define	ERR_KEYSTORE_FORM	"unable to form PKCS12 keystore file for " \
				"writing to <%s>"

#define	ERR_KEYSTORE_NOPUBCERTS	"unable to find any public key certificates " \
				"in keystore file <%s>"

#define	ERR_KEYSTORE_NOPRIVKEYS	"unable to find any private keys in keystore "\
				"file <%s>"

#define	ERR_KEYSTORE_NOCACERTS	"unable to find any trusted certificates in "\
				"file <%s>"

#define	ERR_KEYSTORE_NOTRUST	"unable to find any trusted certificates in "\
				"keystore"

#define	ERR_KEYSTORE_NOMATCH	"unable to find certificate and key pair " \
				"with alias <%s> in keystore"

#define	ERR_KEYSTORE_DUPLICATECERT	"Certificate with alias <%s> " \
					"already exists in keystore"
#define	ERR_KEYSTORE_DUPLICATEKEY	"Private key with alias <%s> already" \
					" exists in keystore"
#define	ERR_KEYSTORE_NO_ALIAS	"Keystore certificate <%s> has no recorded " \
				"alias, must be deleted from keystore"
#define	ERR_KEYSTORE_NOCERT	"No certificate with alias <%s> found in " \
				"keystore <%s>"
#define	ERR_KEYSTORE_NOCERTKEY	"No certificates or private keys with alias " \
				"<%s> found in keystore <%s>"

#define	ERR_KEYSTORE_INTERNAL	"Internal Error file %s line %d"

#define	ERR_CURR_TIME	"Cannot determine current time from system"
#define	ERR_CERT_TIME	"Certificate <%s> has expired or is not yet valid.\n" \
			"Current time: <%s>\n  Certificate valid: <%s> - <%s>"
#define	ERR_MISMATCHED_KEYS	"Private key does not match public key in " \
			"certificate <%s>"
#define	ERR_CERT_TIME_BAD	"Certificate has corrupt validity dates, " \
				"cannot process"
#define	ERR_TRUSTSTORE	"unable to find or use trusted certificate " \
			"store <%s> from application <%s>:<%s>"

#define	ERR_STORE_PW	"unable to read password from <%s>"

#define	ERR_SEC		"unable to sign package contents using <%s> " \
			"private key"

#define	ERR_NOGEN	"unable to generate digital signature"

#define	ERR_STORE_PW	"unable to read password from <%s>"
#define	ERR_CORRUPTSIG  "Invalid or corrupt signature in datastream <%s>"
#define	ERR_CORRUPTSIG_TYPE  "Wrong PKCS7 signature type in datastream <%s>"
#define	ERR_CORRUPTSIG_DT   "Signature found but not detached in " \
	"datastream <%s>"
#define	ERR_KEYSTORE	"invalid or corrupt PKCS12 file <%s>."
#define	ERR_KEYSTORE_NOCERTS "Store <%s> contains no certificates"
#define	ERR_KEYSTORE_NOKEYS "Store <%s> contains no private keys"
#define	ERR_SIG_INT "Internal error during signature verification."
#define	MSG_VERIFY  "## Verifying signature for signer <%s>"
#define	MSG_VERIFY_OK  "## Signature for signer <%s> verified."
#define	ERR_VERIFY  "Signature verification failed."
#define	ERR_VERIFY_SIG  "Signature verification failed while verifying " \
			"certificate <subject=%s, issuer=%s>:<%s>."
#define	ERR_VERIFY_ISSUER  "Could not find issuer certificate for signer <%s>"
#define	ERR_OPENSIG	"Signature found in datastream but cannot be " \
			" opened: <%s>"

#define	ERR_SIGFOUND	"signature found in datastream <%s>, you must " \
	"specify a keystore with -k"
#define	ERR_DSINIT  "could not process datastream from <%s>"

#define	MSG_KEYSTORE_AL	"Keystore Alias"
#define	MSG_KEYSTORE_SN	"Serial Number"
#define	MSG_KEYSTORE_FP	"Fingerprint"
#define	MSG_KEYSTORE_CN	"Common Name"
#define	MSG_KEYSTORE_IN "Issuer Common Name"
#define	MSG_KEYSTORE_VD	"Validity Dates"
#define	MSG_KEYSTORE_TY	"Certificate Type"
#define	MSG_KEYSTORE_TRUSTED	"Trusted Certificate"
#define	MSG_KEYSTORE_UNTRUSTED	"Signing Certificate"
#define	MSG_KEYSTORE_UNKNOWN	"Unknown"

/* parameter errors */
#define	ERR_LEN		"length of parameter value <%s> exceeds limit"
#define	ERR_ASCII	"parameter <%s> must be ascii"
#define	ERR_ALNUM	"parameter <%s> must be alphanumeric"
#define	ERR_CHAR	"parameter <%s> has incorrect first character"
#define	ERR_UNDEF	"parameter <%s> cannot be null"

/* volume sequence errors */
#define	MSG_SEQ		"Volume is out of sequence."
#define	MSG_CORRUPT	"Volume is corrupt or is not part of the appropriate " \
			"package."
#define	ERR_NOPKGMAP	"ERROR: unable to process <%s>"
#define	ERR_BADPKGINFO	"ERROR: unable to process <%s>"

/* datastream processing errors */
#define	ERR_UNPACK	"attempt to process datastream failed"
#define	ERR_DSTREAMSEQ	"datastream sequence corruption"
#define	ERR_TRANSFER    "unable to complete package transfer"
#define	MSG_CMDFAIL	"- process <%s> failed, exit code %d"
#define	MSG_TOC		"- bad format in datastream table-of-contents"
#define	MSG_EMPTY	"- datastream table-of-contents appears to be empty"
#define	MSG_POPEN	"- popen of <%s> failed, errno=%d"
#define	MSG_OPEN	"- open of <%s> failed, errno=%d"
#define	MSG_PCLOSE	"- pclose of <%s> failed, errno=%d"
#define	MSG_PKGNAME	"- invalid package name in datastream table-of-contents"
#define	MSG_NOPKG	"- package <%s> not in datastream"
#define	MSG_STATFS	"- unable to stat filesystem, errno=%d"
#define	MSG_NOSPACE	"- not enough space, %d blocks required, %d available"

/* pkglist errors */
#define	ERR_MEMORY	"memory allocation failure, errno=%d"
#define	ERR_NOPKG	"no package associated with <%s>"
#define	HEADER		"The following packages are available:"
#define	HELP		"Please enter the package instances you wish to " \
			"process from the list provided (or 'all' to process " \
			"all packages.)"

#define	PROMPT		"Select package(s) you wish to process (or 'all' to " \
			"process all packages)."
/* pkgmap errors */
#define	ERR_READLINK	"unable to read link specification."
#define	ERR_NOVAR	"no value defined for%s variable <%s>."
#define	ERR_OWNTOOLONG	"owner string is too long."
#define	ERR_GRPTOOLONG	"group string is too long."
#define	ERR_IMODE	"mode must not be parametric at install time."
#define	ERR_BASEINVAL	"invalid base for mode."
#define	ERR_MODELONG	"mode string is too long."
#define	ERR_MODEALPHA	"mode is not numeric."
#define	ERR_MODEBITS	"invalid bits set in mode."

/* package mount errors and msgs */
#define	ERR_FSTYP	"unable to determine fstype for <%s>"
#define	ERR_NOTROOT	"You must be \"root\" when using mountable media."
#define	MOUNT		"/sbin/mount"
#define	UMOUNT		"/sbin/umount"
#define	FSTYP		"/usr/sbin/fstyp"

#define	LABEL0	"Insert %%v %d of %d for <%s> package into %%p."
#define	LABEL1	"Insert %%v %d of %d into %%p."
#define	LABEL2	"Insert %%v for <%s> package into %%p."
#define	LABEL3	"Insert %%v into %%p."

/* package verify errors */
#define	MSG_WLDDEVNO	"NOTE: <%s> created as device (%d, %d)."

#define	WRN_QV_SIZE	"WARNING: quick verify of <%s>; wrong size."
#define	WRN_QV_MTIME	"WARNING: quick verify of <%s>; wrong mod time."

#define	ERR_PKG_INTERNAL "Internal package library failure file %s line %d"
#define	ERR_UNKNOWN	"unable to determine object type"
#define	ERR_EXIST	"pathname does not exist"
#define	ERR_FTYPE	"file type <%c> expected <%c> actual"
#define	ERR_FTYPED	"<%s> is a door and is not being modified"
#define	ERR_LINK	"pathname not properly linked to <%s>"
#define	ERR_SLINK	"pathname not symbolically linked to <%s>"
#define	ERR_MTIME	"modtime <%s> expected <%s> actual"
#define	ERR_SIZE	"file size <%llu> expected <%llu> actual"
#define	ERR_CKSUM	"file cksum <%ld> expected <%ld> actual"
#define	ERR_NO_CKSUM	"unable to checksum, may need to re-run command as " \
			"user \"root\""
#define	ERR_MAJMIN	"major/minor device <%d, %d> expected <%d, %d> actual"
#define	ERR_PERM	"permissions <%04o> expected <%04o> actual"
#define	ERR_GROUP	"group name <%s> expected <%s> actual"
#define	ERR_OWNER	"owner name <%s> expected <%s> actual"
#define	ERR_MODFAIL	"unable to fix modification time"
#define	ERR_LINKFAIL	"unable to create link to <%s>"
#define	ERR_LINKISDIR	"<%s> is a directory, link() not performed"
#define	ERR_SLINKFAIL	"unable to create symbolic link to <%s>"
#define	ERR_DIRFAIL	"unable to create directory"
#define	ERR_CDEVFAIL	"unable to create character-special device"
#define	ERR_BDEVFAIL	"unable to create block-special device"
#define	ERR_PIPEFAIL	"unable to create named pipe"
#define	ERR_ATTRFAIL	"unable to fix attributes"
#define	ERR_BADGRPID	"unable to determine group name for gid <%d>"
#define	ERR_BADUSRID	"unable to determine owner name for uid <%d>"
#define	ERR_BADGRPNM	"group name <%s> not found in group table(s)"
#define	ERR_BADUSRNM	"owner name <%s> not found in passwd table(s)"
#define	ERR_GETWD	"unable to determine current working directory"
#define	ERR_CHDIR	"unable to change current working directory to <%s>"
#define	ERR_RMDIR	"unable to remove existing directory at <%s>"

/* others */
#define	ERR_ISCPIO_OPEN		"iscpio(): open(%s) failed!"
#define	ERR_ISCPIO_FSTAT	"iscpio(): fstat(%s) failed!"
#define	ERR_ISCPIO_READ		"iscpio(): read(%s) failed!"
#define	ERR_ISCPIO_NOCPIO	"iscpio(): <%s> is not a cpio archive!"

#define	ERR_DUPFAIL	"%s: strdup(%s) failed.\n"
#define	ERR_ADDFAIL	"%s: add_cache() failed.\n"
#define	ERR_BADMEMB	"%s: %s in \"%s\" %s structure is invalid.\n"
#define	ERR_NOGRP	"dup_gr_ent(): no group entry provided.\n"
#define	ERR_NOPWD	"dup_pw_ent(): no passwd entry provided.\n"
#define	ERR_NOINIT	"%s: init_cache() failed.\n"
#define	ERR_MALLOC	"%s: malloc(%d) failed for %s.\n"

#define	ERR_TOO_MANY_ARGS	"too many arguments passed to pkgexecl " \
				"for command <%s>"
#define	ERR_WAIT_FAILED	"wait for process %ld failed, pid <%ld> status " \
			"<0x%08lx> errno <%d> (%s)"
#define	ERR_FORK_FAILED	"fork() failed errno=%d (%s)"
#define	ERR_FREOPEN	"freopen(%s, \"%s\", %s) failed, errno=%d (%s)"
#define	ERR_FDOPEN	"fdopen(%d, \"%s\") failed, errno=%d (%s)"
#define	ERR_CLOSE	"close(%d) failed, errno=%d"
#define	ERR_SETGID	"setgid(%d) failed."
#define	ERR_SETUID	"setuid(%d) failed."
#define	ERR_EX_FAIL	"exec of %s failed, errno=%d"

/* pkgweb errors */
#define	MSG_DWNLD "\n## Downloading..."
#define	ERR_DWNLD_FAILED "\n## After %d retries, unable to complete transfer"
#define	MSG_DWNLD_TIMEOUT "\n## Timed out, retrying..."
#define	MSG_DWNLD_CONNREF "\n## Connection to <%s> refused, retrying..."
#define	MSG_DWNLD_HOSTDWN "\n## <%s> not responding, retrying..."
#define	MSG_DWNLD_PART "\n## Found partially downloaded file <%s> of " \
			"size <%ld> bytes.  To force a complete " \
			"re-download, delete this file and try again"
#define	MSG_DWNLD_PREV "\n## Using previously spooled package datastream <%s>"
#define	MSG_DWNLD_CONT "\n## Continuing previously attempted download..."
#define	MSG_DWNLD_COMPLETE "## Download Complete\n"

#define	ERR_DWNLD_NO_CONT "unable to open partially downloaded file <%s> " \
				"for appending"
#define	ERR_BAD_PATH "unable to locate keystore."
#define	ERR_EMPTYPATH "No valid path exists for the keystore file."
#define	ERR_RETRIES "The number of server retries is not a valid " \
	"value. Please specify a value within the range of %d - %d."
#define	ERR_TIMEOUT "The network timeout value is not a valid " \
	"value. Please specify a value within the range of %d - %d."
#define	ERR_PARSE_URL "unable to parse the url <%s>."
#define	ERR_MEM "unable to allocate memory."
#define	ERR_HTTPS_PASSWD "unable set password for HTTPS connection."
#define	ERR_HTTPS_CA "unable to set CA file for HTTPS connection."
#define	ERR_HTTP "Failure occurred with http(s) negotiation: <%s>"
#define	ERR_WRITE "Cannot write to file <%s> : <%s>"
#define	ERR_READ "Cannot read from file <%s> : <%s>"
#define	ERR_SVR_RESP "unable to establish a connection with the http(s) server."
#define	ERR_INIT_CONN "unable to establish a connection with <%s>."
#define	ERR_INIT_SESS "unable to intialize download session for <%s>."
#define	ERR_INIT_CONN_PROXY "unable to establish a connection with <%s> " \
	"using <%s> as the proxy"
#define	ERR_CLOSE_CONN "unable to close the connection with <%s>."
#define	ERR_NO_HEAD_VAL "HTTP Response did not include header <%s>."
/* CSTYLED */
#define	ERR_BAD_HEAD_VAL "HTTP Header value \"<%s>: <%s>\" unusable or " \
			"unparseable."
#define	ERR_BAD_CONTENT "The package <%s> attempting to be installed " \
	"is illegal."
#define	ERR_DWNLD "unable to download package datastream from <%s>."
#define	ERR_OPEN_TMP "unable to open temporary file for writing."
#define	ERR_WRITE_TMP "unable to write to temporary file."
#define	ERR_DISK_SPACE "Not enough disk space is available to download " \
	"package to\n%s. %llukb needed, %llukb available."
#define	ERR_CERTS "unable to find a valid certificate in <%s>."
#define	ERR_CERTCHAIN "unable to build certificate chain for subject <%s>:<%s>."
#define	ERR_ILL_ENV "The environment variable <%s=%s> is illegal"
#define	ERR_BAD_PROXY "Invalid proxy specification: <%s>"
#define	ERR_TMPDIR "unable to find temporary directory <%s>"
#define	ERR_MEM "unable to allocate memory."
#define	ERR_NO_DWNLD_DIR "No download directory available."
#define	MSG_OCSP_VERIFY "## Contacting OCSP Responder <%s> for " \
			"certificate <%s> status"
#define	MSG_OCSP_VERIFY_PROXY "## Contacting OCSP Responder <%s> through " \
				"proxy <%s:%d> for certificate <%s> status"
#define	ERR_OCSP_PARSE "OCSP Responder URL <%s> invalid or unparseable"
#define	ERR_OCSP_RESP_PARSE "OCSP Response <%s> unparseable or empty"
#define	ERR_OCSP_RESP_NOTOK "OCSP Request failed.  Expected status " \
			"<%d>, got <%d>, Reason=<%s>"
#define	WRN_OCSP_RESP_NONCE "WARNING: Invalid or no nonce found in " \
			"OCSP response."
#define	ERR_OCSP_RESP_TYPE "OCSP response message type invalid: <%s>, " \
			"expecting <%s>"
#define	ERR_OCSP_CONNECT "Cannot connect to OCSP Responder <%s> port <%d>"
#define	ERR_OCSP_SEND "Cannot send OCSP request to OCSP Responder <%s>"
#define	ERR_OCSP_READ "Cannot read OCSP response from OCSP Responder <%s>"
#define	ERR_OCSP_RESPONDER "OCSP Responder cannot process OCSP Request"
#define	ERR_OCSP_UNSUP "Unsupported OCSP Option <%s>"
#define	ERR_OCSP_VERIFY_NOTIME "Cannot access system time() to determine " \
				"OCSP Response validity"
#define	ERR_OCSP_VERIFY_SIG "OCSP Response, signed by <%s>, cannot be " \
			"verified: <%s>"
#define	ERR_OCSP_VERIFY_FAIL "unable to validate response from OCSP " \
			"Responder <%s>"
#define	ERR_OCSP_VERIFY_NO_STATUS "OCSP Responder did not supply validity " \
				"of certificate <%s> "
#define	ERR_OCSP_VERIFY_VALIDITY_NOTBEFORE "OCSP Response is only valid " \
			"after <%s>.  Current time is <%s>."
#define	ERR_OCSP_VERIFY_VALIDITY "OCSP Response is only valid from <%s> " \
			"to <%s>.  Current time is <%s>."
#define	ERR_OCSP_VERIFY_STATUS "OCSP Responder indicates certificate <%s> " \
			"status is <%s>"
#define	ERR_OCSP_VERIFY "OCSP Responder rejected certificate, or did not " \
			"recognize"
#define	ERR_OCSP_NO_URI "No OCSP Responder URL"

#define	MSG_BASE_USED   "Using <%s> as the package base directory."

#ifdef __cplusplus
}
#endif

#endif /* _PKGLIBMSGS_H */
