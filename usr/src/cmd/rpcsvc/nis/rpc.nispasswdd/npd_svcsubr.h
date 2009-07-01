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
 */

#ifndef _NPD_SVCSUBR_H
#define	_NPD_SVCSUBR_H

#include <rpcsvc/yppasswd.h>
#include <rpcsvc/nispasswd.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct nis_result *nis_getpwdent(char *user, char *domain);
int __npd_upd_all_pk_creds(char *user, char *domain, char *oldpass,
	char *newpass, int  *err);
void __npd_gen_rval(unsigned long *randval);
bool_t __npd_has_aged(struct nis_object *obj, int *res);
bool_t __authenticate_admin(char *prin, char *pass);
char *__npd_encryptpass(char *pass, nis_object *user);
bool_t __npd_can_do(unsigned long right, nis_object *obj, char *prin,
	int column);
bool_t __npd_find_obj(char *user, char *dirlist, nis_object **obj);
int update_authtok_nis_fwd(char *usrname, char *newpwe,
	char *oldpwu, char *master, char  *gecos, char *shell);
bool_t __npd_prin2netname(char *, char []);
bool_t __npd_am_master(char *host, char *dirlist);

bool_t nispasswd_authenticate_1_svc(npd_request *argp,
	nispasswd_authresult *result, struct svc_req *rqstp);
bool_t nispasswd_authenticate_2_svc(npd_request *argp,
	nispasswd_authresult *result, struct svc_req *rqstp);
bool_t nispasswd_authenticate_common_svc(npd_request *argp,
	nispasswd_authresult *result, struct svc_req *rqstp, rpcvers_t vers);

bool_t nispasswd_update_1_svc(npd_update *updreq, nispasswd_updresult *res,
	struct svc_req *rqstp);
bool_t nispasswd_update_2_svc(npd_update2 *updreq, nispasswd_updresult *res,
	struct svc_req *rqstp);
bool_t nispasswd_update_common_svc(void *updreq, nispasswd_updresult *res,
	struct svc_req *rqstp, rpcvers_t vers);

bool_t yppasswdproc_update_1_svc(struct yppasswd *yppass, int *result,
	struct svc_req *rqstp);

/* from libnsl */
extern bool_t __nis_ismaster(char *host, char *domain);
extern bool_t __nis_isadmin(char *princ, char *table, char *domain);
extern bool_t __nis_ck_perms(unsigned int right, unsigned int mask,
	nis_object *obj, nis_name pr, int level);
extern nis_server *__nis_host2nis_server(char *host, bool_t addpubkey,
	int *errcode);
extern bool_t __npd_ecb_crypt(uint32_t *val1, uint32_t *val2, des_block *buf,
	unsigned int bufsize, unsigned int mode, des_block *deskey);
extern bool_t __npd_cbc_crypt(uint32_t *val, char *str, unsigned int strsize,
	npd_newpass *buf, unsigned int bufsize, unsigned int mode,
	des_block *deskey);

extern bool_t __npd2_cbc_crypt(uint32_t *val, char *str, unsigned int strsize,
	npd_newpass2 *buf, unsigned int bufsize, unsigned int mode,
	des_block *deskey);

extern void __free_nis_server(nis_server *server);

#ifdef	__cplusplus
}
#endif

#endif	/* _NPD_SVCSUBR_H */
