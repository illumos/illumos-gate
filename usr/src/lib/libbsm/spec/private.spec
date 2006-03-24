#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libbsm/spec/private.spec

function	adr_char
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adr_char(adr_t *adr, char *cp, int count);
version		SUNWprivate_1.1
end		

function	adr_count
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int adr_count(adr_t *adr)
version		SUNWprivate_1.1
end		

function	adr_int32
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adr_int32(adr_t *adr, int32_t *lp, int count)
version		SUNWprivate_1.1
end		

function	adr_int64
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adr_int64(adr_t *adr, int64_t *lp, int count)
version		SUNWprivate_1.1
end		

function	adr_short
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adr_short(adr_t *adr, short *sp, int count)
version		SUNWprivate_1.1
end		

function	adr_start
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adr_start(adr_t *adr, char *p)
version		SUNWprivate_1.1
end		

function	adrf_char
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int adrf_char(adrf_t *adrf, char *cp, int count)
version		SUNWprivate_1.1
end		

function	adrf_int32
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int adrf_int32(adrf_t *adrf, int32_t *cp, int count)
version		SUNWprivate_1.1
end		

function	adrf_int64
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int adrf_int64(adrf_t *adrf, int64_t *lp, int count)
version		SUNWprivate_1.1
end		

function	adrf_peek
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int adrf_peek(adrf_t *adrf)
version		SUNWprivate_1.1
end		

function	adrf_short
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int adrf_short(adrf_t *adrf, short *sp, int count)
version		SUNWprivate_1.1
end		

function	adrf_start
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adrf_start(adrf_t *adrf, adr_t *adr, FILE *fp)
version		SUNWprivate_1.1
end		

function	adrf_u_char
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int adrf_u_char(adrf_t *adrf, uchar_t *cp, int count)
version		SUNWprivate_1.1
end		

function	adrf_u_int32
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int adrf_u_int32(adrf_t *adrf, uint32_t *cp, int count)
version		SUNWprivate_1.1
end		

function	adrf_u_int64
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int adrf_u_int64(adrf_t *adrf, uint64_t *lp, int count)
version		SUNWprivate_1.1
end		

function	adrf_u_short
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int adrf_u_short(adrf_t *adrf, ushort_t *sp, int count)
version		SUNWprivate_1.1
end		

function	adrm_char
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adrm_char(adr_t *adr, char *cp, int count)
version		SUNWprivate_1.1
end		

function	adrm_int32
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adrm_int32(adr_t *adr, int32_t *cp, int count)
version		SUNWprivate_1.1
end		

function	adrm_int64
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adrm_int64(adr_t *adr, int64_t *lp, int count)
version		SUNWprivate_1.1
end		

function	adrm_short
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adrm_short(adr_t *adr, short *sp, int count)
version		SUNWprivate_1.1
end		

function	adrm_start
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adrm_start(adr_t *adr, char *p)
version		SUNWprivate_1.1
end		

function	adrm_u_char
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adrm_u_char(adr_t *adr, uchar_t *cp, int count)
version		SUNWprivate_1.1
end		

function	adrm_u_int32
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adrm_u_int32(adr_t *adr, uint32_t *cp, int count)
version		SUNWprivate_1.1
end		

function	adrm_u_int64
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adrm_u_int64(adr_t *adr, uint64_t *cp, int count)
version		SUNWprivate_1.1
end		

function	adrm_u_short
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void adrm_u_short(adr_t *adr, ushort_t *sp, int count)
version		SUNWprivate_1.1
end		

function	au_to_exec_args
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_exec_args(char **argv)
version		SUNWprivate_1.1
end		

function	au_to_exec_env
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_exec_env(char **envp)
version		SUNWprivate_1.1
end		

function	au_to_exit
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_exit(int retval, int err)
version		SUNWprivate_1.1
end		

function	au_to_header
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_header(au_event_t e_type, au_emod_t e_mod)
version		SUNWprivate_1.1
end		

function	au_to_header_ex
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_header_ex(au_event_t e_type, au_emod_t e_mod)
version		SUNWprivate_1.1
end		

function	au_to_seq
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_seq(int audit_count)
version		SUNWprivate_1.1
end		

function	au_to_trailer
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_trailer(void)
version		SUNWprivate_1.1
end		

function	au_to_xatom
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_xatom(ushort_t len, char *atom)
version		SUNWprivate_1.1
end		

function	au_to_xobj
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_xobj(int oid, int xid, int cuid)
version		SUNWprivate_1.1
end		

function	au_to_xproto
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_xproto(pid_t pid)
version		SUNWprivate_1.1
end		

function	au_to_xselect
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_xselect(char *pstring, char *type, \
			short dlen, char *data)
version		SUNWprivate_1.1
end		

function	au_to_mylabel
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_mylabel(void)
version		SUNWprivate_1.1
end		

function	au_to_label
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_label(bslabel_t *label)
version		SUNWprivate_1.1
end		

function	audit_allocate_argv
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_allocate_argv(int flg, int argc, char *argv[])
version		SUNWprivate_1.1
end		

function	audit_allocate_device
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_allocate_device(char *path)
version		SUNWprivate_1.1
end		

function	audit_allocate_list
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_allocate_list(char *list)
version		SUNWprivate_1.1
end		

function	audit_allocate_record
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_allocate_record(char status)
version		SUNWprivate_1.1
end		

function	audit_cron_session
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_cron_session(char *nam, uid_t uid)
version		SUNWprivate_1.1
end		

function	audit_ftpd_bad_pw
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_ftpd_bad_pw(char *uname)
version		SUNWprivate_1.1
end		

function	audit_ftpd_excluded
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_ftpd_excluded(char *uname)
version		SUNWprivate_1.1
end		

function	audit_ftpd_failure
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_ftpd_failure(char *uname)
version		SUNWprivate_1.1
end		

function	audit_ftpd_no_anon
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_ftpd_no_anon(void)
version		SUNWprivate_1.1
end		

function	audit_ftpd_success
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_ftpd_success(char *uname)
version		SUNWprivate_1.1
end		

function	audit_ftpd_unknown
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_ftpd_unknown(char *uname)
version		SUNWprivate_1.1
end		

function	audit_ftpd_logout
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_ftpd_logout(void)
version		SUNWprivate_1.1
end		

function	audit_halt_fail
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_halt_fail(void)
version		SUNWprivate_1.1
end		

function	audit_halt_setup
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_halt_setup(int argc, char **argv)
version		SUNWprivate_1.1
end		

function	audit_halt_success
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_halt_success(void)
version		SUNWprivate_1.1
end		

function	audit_inetd_config
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_inetd_config(void)
version		SUNWprivate_1.1
end		

function	audit_inetd_termid
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_inetd_termid(int)
version		SUNWprivate_1.1
end		

function	audit_inetd_service
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_inetd_service(char *service_name, struct passwd *pwd)
version		SUNWprivate_1.1
end		

function	audit_uadmin_setup
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_uadmin_setup(int argc, char **argv)
version		SUNWprivate_1.1
end		

function	audit_uadmin_success
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_uadmin_success(void)
version		SUNWprivate_1.1
end		

function	audit_settid
include		<sys/socket.h>, <netinet/in.h>, <strings.h>, <bsm/libbsm.h>
declaration	int audit_settid(int fd)
version		SUNWprivate_1.1
end

function	audit_mountd_mount
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_mountd_mount(char *clname, char *path, int success)
version		SUNWprivate_1.1
end		

function	audit_mountd_setup
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_mountd_setup(void)
version		SUNWprivate_1.1
end		

function	audit_mountd_umount
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_mountd_umount(char *clname, char *path)
version		SUNWprivate_1.1
end		

function	audit_reboot_fail
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_reboot_fail(void)
version		SUNWprivate_1.1
end		

function	audit_reboot_setup
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_reboot_setup(void)
version		SUNWprivate_1.1
end		

function	audit_reboot_success
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_reboot_success(void)
version		SUNWprivate_1.1
end		

function	audit_rexd_fail
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_rexd_fail(char *msg, char *hostname, char *user, \
			uid_t uid, gid_t gid, char *shell, char **cmdbuf)
version		SUNWprivate_1.1
end		

function	audit_rexd_setup
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_rexd_setup(void)
version		SUNWprivate_1.1
end		

function	audit_rexd_success
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_rexd_success(char *hostname, char *user, \
			uid_t uid, gid_t gid, char *shell, char **cmdbuf)
version		SUNWprivate_1.1
end		

function	audit_rexecd_fail
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_rexecd_fail(char *msg, char *hostname, char \
			*user, char *cmdbuf)
version		SUNWprivate_1.1
end		

function	audit_rexecd_setup
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_rexecd_setup(void)
version		SUNWprivate_1.1
end		

function	audit_rexecd_success
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void audit_rexecd_success(char *hostname, char *user, char \
			*cmdbuf)
version		SUNWprivate_1.1
end		

function	audit_rshd_fail
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_rshd_fail(char *msg, char *hostname, char \
			*remuser, char *locuser, char *cmdbuf)
version		SUNWprivate_1.1
end		

function	audit_rshd_setup
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_rshd_setup(void)
version		SUNWprivate_1.1
end		

function	audit_rshd_success
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_rshd_success(char *hostname, char *remuser, char \
			*locuser, char *cmdbuf)
version		SUNWprivate_1.1
end		

function	audit_shutdown_fail
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_shutdown_fail(void)
version		SUNWprivate_1.1
end		

function	audit_shutdown_setup
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_shutdown_setup(int argc, char **argv)
version		SUNWprivate_1.1
end		

function	audit_shutdown_success
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_shutdown_success(void)
version		SUNWprivate_1.1
end		

function	aug_audit
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int aug_audit(void)
version		SUNWprivate_1.1
end		

function	aug_get_machine
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int aug_get_machine(char *hostname)
version		SUNWprivate_1.1
end		

function	aug_get_port
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	dev_t aug_get_port(void)
version		SUNWprivate_1.1
end		

function	aug_init
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_init(void)
version		SUNWprivate_1.1
end		

function	aug_na_selected
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int aug_na_selected(void)
version		SUNWprivate_1.1
end		

function	aug_save_afunc
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_save_afunc(int (*afunc)())
version		SUNWprivate_1.1
end		

function	aug_save_asid
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_save_asid(au_asid_t id)
version		SUNWprivate_1.1
end		

function	aug_save_auid
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_save_auid(au_id_t id)
version		SUNWprivate_1.1
end		

function	aug_save_egid
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_save_egid(gid_t id)
version		SUNWprivate_1.1
end		

function	aug_save_euid
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_save_euid(uid_t id)
version		SUNWprivate_1.1
end		

function	aug_save_event
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_save_event(au_event_t id)
version		SUNWprivate_1.1
end		

function	aug_save_gid
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_save_gid(gid_t id)
version		SUNWprivate_1.1
end		

function	aug_save_me
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int aug_save_me(void)
version		SUNWprivate_1.1
end		

function	aug_save_na
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_save_na(int flag)
version		SUNWprivate_1.1
end		

function	aug_save_namask
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int aug_save_namask(void)
version		SUNWprivate_1.1
end		

function	aug_save_path
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_save_path(char *s)
version		SUNWprivate_1.1
end		

function	aug_save_pid
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_save_pid(pid_t id)
version		SUNWprivate_1.1
end		

function	aug_save_policy
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int aug_save_policy(void)
version		SUNWprivate_1.1
end		

function	aug_save_sorf
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_save_sorf(int sorf)
version		SUNWprivate_1.1
end		

function	aug_save_text
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_save_text(char *s)
version		SUNWprivate_1.1
end		

function	aug_save_tid
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_save_tid(dev_t port, uint_t machine)
version		SUNWprivate_1.1
end		

function	aug_save_uid
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	void aug_save_uid(uid_t id)
version		SUNWprivate_1.1
end		

function	aug_selected
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int aug_selected(void)
version		SUNWprivate_1.1
end		

function	cacheauclass
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int cacheauclass(au_class_ent_t **result, au_class_t class_no)
version		SUNWprivate_1.1
end		

function	cacheauclassnam
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int cacheauclassnam(au_class_ent_t **result, char *class_name)
version		SUNWprivate_1.1
end		

function	cacheauevent
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int cacheauevent(au_event_ent_t **result, au_event_t event_number)
version		SUNWprivate_1.1
end		

function	cannot_audit
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int cannot_audit(int force)
version		SUNWprivate_1.1
end		

function	_openac
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>
declaration	au_acinfo_t *_openac(char *)
version		SUNWprivate_1.1
end		

function	_endac
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>
declaration	void _endac(au_acinfo_t *)
version		SUNWprivate_1.1
end		

function	_rewindac
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>
declaration	void _rewindac(au_acinfo_t *)
version		SUNWprivate_1.1
end		

function	_getacdir
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>
declaration	int _getacdir(au_acinfo_t *, char *, int)
version		SUNWprivate_1.1
end		

function	_getacplug
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>
declaration	int _getacplug(au_acinfo_t *, kva_t **)
version		SUNWprivate_1.1
end		

function	_getacmin
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>
declaration	int _getacmin(au_acinfo_t *, int *)
version		SUNWprivate_1.1
end		

function	_getacna
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>
declaration	int _getacna(au_acinfo_t *, char *, int)
version		SUNWprivate_1.1
end		

function	_getacflg
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>
declaration	int _getacflg(au_acinfo_t *, char *, int)
version		SUNWprivate_1.1
end		

function	audit_at_create
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
version		SUNWprivate_1.1
end		

function	audit_at_delete
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
version		SUNWprivate_1.1
end		

function	audit_cron_bad_user
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
version		SUNWprivate_1.1
end		

function	audit_cron_create_anc_file
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
version		SUNWprivate_1.1
end		

function	audit_cron_delete_anc_file
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
version		SUNWprivate_1.1
end		

function	audit_cron_is_anc_name
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
version		SUNWprivate_1.1
end		

function	audit_cron_mode
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
version		SUNWprivate_1.1
end		

function	audit_cron_new_job
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
version		SUNWprivate_1.1
end		

function	audit_cron_setinfo
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
version		SUNWprivate_1.1
end		

function	audit_cron_user_acct_expired
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
version		SUNWprivate_1.1
end		

function	audit_crontab_not_allowed
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_crontab_not_allowed(uid_t)
version		SUNWprivate_1.1
end		

function	audit_crontab_delete
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
version		SUNWprivate_1.1
end		

function	audit_crontab_modify
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
version		SUNWprivate_1.1
end		

function	audit_crontab_process_not_audited
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	int audit_crontab_process_not_audited()
version		SUNWprivate_1.1
end		

function	audit_newgrp_login
include		<sys/types.h>, <bsm/audit.h>, <bsm/audit_uevents.h>, <stdio.h>, <bsm/libbsm.h> 
declaration	void audit_newgrp_login(char *, int)
version		SUNWprivate_1.1
end

function	adt_start_session
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	int adt_start_session(adt_session_data_t **, const adt_export_data_t *, adt_session_flags_t)
version		SUNWprivate_1.1
end

function	adt_end_session
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	int adt_end_session(adt_session_data_t *)
version		SUNWprivate_1.1
end

function	adt_dup_session
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	int adt_dup_session(const adt_session_data_t *, adt_session_data_t **)
version		SUNWprivate_1.1
end

function	adt_get_session_id
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	size_t adt_get_session_id(const adt_session_data_t *, char **)
version		SUNWprivate_1.1
end

function	adt_get_asid
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	void adt_get_asid(const adt_session_data_t *, au_asid_t *)
version		SUNWprivate_1.1
end

function	adt_set_asid
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	void adt_set_asid(const adt_session_data_t *, au_asid_t)
version		SUNWprivate_1.1
end

function	adt_get_auid
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	void adt_get_auid(const adt_session_data_t *, au_id_t *)
version		SUNWprivate_1.1
end

function	adt_set_auid
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	void adt_set_auid(const adt_session_data_t *, au_id_t)
version		SUNWprivate_1.1
end

function	adt_get_termid
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	void adt_get_termid(const adt_session_data_t *, au_tid_addr_t *)
version		SUNWprivate_1.1
end

function	adt_set_termid
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	void adt_set_termid(const adt_session_data_t *, const au_tid_addr_t *)
version		SUNWprivate_1.1
end

function	adt_get_mask
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	void adt_get_mask(const adt_session_data_t *, au_mask_t *)
version		SUNWprivate_1.1
end

function	adt_set_mask
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	void adt_set_mask(const adt_session_data_t *, const au_mask_t *)
version		SUNWprivate_1.1
end

function	adt_load_termid
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	int adt_load_termid(int, adt_termid_t **)
version		SUNWprivate_1.1
end

function	adt_load_hostname
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	int adt_load_hostname(const char *, adt_termid_t **)
version		SUNWprivate_1.1
end

function	adt_load_ttyname
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	int adt_load_ttyname(const char *, adt_termid_t **)
version		SUNWprivate_1.1
end

function	adt_alloc_event
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	adt_event_data_t *adt_alloc_event(const adt_session_data_t *, au_event_t)
version		SUNWprivate_1.1
end

function	adt_put_event
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	int adt_put_event(const adt_event_data_t *, int, int)
version		SUNWprivate_1.1
end

function	adt_free_event
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	void adt_free_event(adt_event_data_t *)
version		SUNWprivate_1.1
end

function	adt_export_session_data
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	size_t adt_export_session_data(const adt_session_data_t *, adt_export_data_t **)
version		SUNWprivate_1.1
end

function	adt_set_proc
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	int adt_set_proc(const adt_session_data_t *)
version		SUNWprivate_1.1
end

function	adt_set_user
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	int adt_set_user(const adt_session_data_t *, uid_t, gid_t, uid_t, gid_t, const adt_termid_t *, enum adt_user_context)
version		SUNWprivate_1.1
end

function	adt_set_from_ucred
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	int adt_set_from_ucred(const adt_session_data_t *, const ucred_t *, enum adt_user_context)
version		SUNWprivate_1.1
end

function	adt_import_proc
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	size_t adt_import_proc(pid_t pid, uid_t euid, gid_t egid, uid_t ruid, gid_t rgid, adt_export_data_t **)
version		SUNWprivate_1.1
end

function	adt_audit_enabled
include		<bsm/adt.h>, <assert.h>, <errno.h>, <md5.h>, <netdb.h>, <pwd.h>, <time.h>, <stdlib.h>, <string.h>, <synch.h>, <thread.h>, <unistd.h>
declaration	boolean_t adt_audit_enabled(void)
version		SUNWprivate_1.1
end

function	audit_krb5kdc_as_req
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <netinet/in.h>
declaration	void audit_krb5kdc_as_req( \
			struct in_addr *r_addr, \
			in_port_t r_port, \
			in_port_t l_port, \
			char *cname, \
			char *sname, \
			int sorf)
version		SUNWprivate_1.1
end		

function	audit_krb5kdc_tgs_req
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <netinet/in.h>
declaration	void audit_krb5kdc_tgs_req( \
			struct in_addr *r_addr, \
			in_port_t r_port, \
			in_port_t l_port, \
			char *cname, \
			char *sname, \
			int sorf)
version		SUNWprivate_1.1
end		

function	audit_krb5kdc_tgs_req_2ndtktmm
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <netinet/in.h>
declaration	void audit_krb5kdc_tgs_req_2ndtktmm( \
			struct in_addr *r_addr, \
			in_port_t r_port, \
			in_port_t l_port, \
			char *cname, \
			char *sname)
version		SUNWprivate_1.1
end		

function	audit_krb5kdc_tgs_req_alt_tgt
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <netinet/in.h>
declaration	void audit_krb5kdc_tgs_req_alt_tgt( \
			struct in_addr *r_addr, \
			in_port_t r_port, \
			in_port_t l_port, \
			char *cname, \
			char *sname, \
			int sorf)
version		SUNWprivate_1.1
end		

function	audit_kadmind_auth
declaration	void audit_kadmind_auth( \
				SVCXPRT *xprt, \
				in_port_t l_port, \
				char *op, \
				char *prime_arg, \
				char *clnt_name, \
				int sorf)
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <netinet/in.h>, <rpc/rpc.h>
version		SUNWprivate_1.1
end		

function	audit_kadmind_unauth
declaration	void audit_kadmind_unauth( \
				SVCXPRT *xprt, \
				in_port_t l_port, \
				char *op, \
				char *prime_arg, \
				char *clnt_name)
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <netinet/in.h>, <rpc/rpc.h>
version		SUNWprivate_1.1
end		

function	__audit_dowarn
include		<errno.h>, <stdlib.h>, <string.h>, <unistd.h>, <sys/types.h>
declaration	void __audit_dowarn(char *option, char *filename, char *count)
version		SUNWprivate_1.1
end

function	__audit_dowarn2
include		<errno.h>, <stdlib.h>, <string.h>, <unistd.h>, <sys/types.h>
declaration	void __audit_dowarn2(char *option, char *filename, char *error, char *text, char *count)
version		SUNWprivate_1.1
end

function	__logpost
include		<errno.h>, <stdlib.h>, <string.h>, <unistd.h>, <sys/types.h>
declaration	int  __logpost(char *name)
version		SUNWprivate_1.1
end

function	__audit_syslog
include		<errno.h>, <stdlib.h>, <string.h>, <unistd.h>, <sys/types.h>, <pthread.h>
declaration	void __audit_syslog(const char *, int, int, int, const char *)
version		SUNWprivate_1.1
end

function	__auditd_debug_file_open
include		<errno.h>, <stdlib.h>, <string.h>, <unistd.h>, <sys/types.h>, <pthread.h>
declaration	FILE *__auditd_debug_file_open()
version		SUNWprivate_1.1
end

function        auditdoor
include         <sys/param.h>, <bsm/audit.h>
declaration     int auditdoor(int fd)
version         SUNWprivate_1.1
errno           EAGAIN EBADF EBUSY EFBIG EINTR EINVAL EIO \
                        ENXIO EPERM EWOULDBLOCK
exception       $return == -1
end

function	au_to_privset
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_privset(const char *priv_type, const priv_set_t *privilege)
version		SUNWprivate_1.1
end

function	au_to_uauth
include		<sys/types.h>, <bsm/audit.h>, <bsm/libbsm.h>, <bsm/audit_record.h>, <bsm/devices.h>, <pwd.h>
declaration	token_t *au_to_uauth(char *text)
version		SUNWprivate_1.1
end
