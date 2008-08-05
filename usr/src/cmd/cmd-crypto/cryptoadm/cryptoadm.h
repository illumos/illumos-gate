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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CRYPTOADM_H
#define	_CRYPTOADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/crypto/ioctladmin.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	_PATH_KCF_CONF		"/etc/crypto/kcf.conf"
#define	_PATH_KCFD		"/usr/lib/crypto/kcfd"
#define	TMPFILE_TEMPLATE	"/etc/crypto/admXXXXXX"

#define	ERROR_USAGE	2

/*
 * Common keywords and delimiters for pkcs11.conf and kcf.conf files are
 * defined in usr/lib/libcryptoutil/common/cryptoutil.h.  The following is
 * the extra keywords and delimiters used in kcf.conf file.
 */
#define	SEP_SLASH		'/'
#define	EF_SUPPORTED		"supportedlist="
#define	HW_DRIVER_STRING	"driver_names"
#define	RANDOM			"random"
#define	UEF_FRAME_LIB		"/usr/lib/libpkcs11.so"

#define	ADD_MODE	1
#define	DELETE_MODE	2
#define	MODIFY_MODE	3

typedef char prov_name_t[MAXNAMELEN];
typedef char mech_name_t[CRYPTO_MAX_MECH_NAME];

typedef struct mechlist {
	mech_name_t	name;
	struct mechlist	*next;
} mechlist_t;


typedef struct entry {
	prov_name_t	name;
	mechlist_t	*suplist; /* supported list */
	uint_t 		sup_count;
	mechlist_t	*dislist; /* disabled list */
	uint_t 		dis_count;
} entry_t;


typedef struct entrylist {
	entry_t	*pent;
	struct entrylist *next;
} entrylist_t;

typedef enum {
	NO_RNG,
	HAS_RNG
} flag_val_t;

extern int errno;

/* adm_util */
extern boolean_t is_in_list(char *, mechlist_t *);
extern mechlist_t *create_mech(char *);
extern void free_mechlist(mechlist_t *);

/* adm_kef_util */
extern boolean_t is_device(char *);
extern char *ent2str(entry_t *);
extern entry_t *getent_kef(char *);
extern int check_active_for_soft(char *, boolean_t *);
extern int check_active_for_hard(char *, boolean_t *);
extern int disable_mechs(entry_t **, mechlist_t *, boolean_t, mechlist_t *);
extern int enable_mechs(entry_t **, boolean_t, mechlist_t *);
extern int get_kcfconf_info(entrylist_t **, entrylist_t **);
extern int get_admindev_info(entrylist_t **, entrylist_t **);
extern int get_mech_count(mechlist_t *);
extern int insert_kcfconf(entry_t *);
extern int split_hw_provname(char *, char *, int *);
extern int update_kcfconf(entry_t *, int);
extern void free_entry(entry_t *);
extern void free_entrylist(entrylist_t *);
extern void print_mechlist(char *, mechlist_t *);
extern void print_kef_policy(entry_t *, boolean_t, boolean_t);
extern boolean_t filter_mechlist(mechlist_t **, const char *);
extern uentry_t *getent_uef(char *);


/* adm_uef */
extern int list_mechlist_for_lib(char *, mechlist_t *, flag_val_t *,
		boolean_t, boolean_t, boolean_t);
extern int list_policy_for_lib(char *);
extern int disable_uef_lib(char *, boolean_t, boolean_t, mechlist_t *);
extern int enable_uef_lib(char *, boolean_t, boolean_t, mechlist_t *);
extern int install_uef_lib(char *);
extern int uninstall_uef_lib(char *);
extern int print_uef_policy(uentry_t *);
extern void display_token_flags(CK_FLAGS flags);
extern int convert_mechlist(CK_MECHANISM_TYPE **, CK_ULONG *, mechlist_t *);
extern void display_verbose_mech_header();
extern void display_mech_info(CK_MECHANISM_INFO *);
extern int display_policy(uentry_t *);
extern int update_pkcs11conf(uentry_t *);
extern int update_policylist(uentry_t *, mechlist_t *, int);

/* adm_kef */
extern int list_mechlist_for_soft(char *);
extern int list_mechlist_for_hard(char *);
extern int list_policy_for_soft(char *);
extern int list_policy_for_hard(char *);
extern int disable_kef_software(char *, boolean_t, boolean_t, mechlist_t *);
extern int disable_kef_hardware(char *, boolean_t, boolean_t, mechlist_t *);
extern int enable_kef(char *, boolean_t, boolean_t, mechlist_t *);
extern int install_kef(char *, mechlist_t *);
extern int uninstall_kef(char *);
extern int unload_kef_soft(char *, boolean_t);
extern int refresh(void);
extern int start_daemon(void);
extern int stop_daemon(void);

/* adm_ioctl */
extern crypto_load_soft_config_t *setup_soft_conf(entry_t *);
extern crypto_load_soft_disabled_t *setup_soft_dis(entry_t *);
extern crypto_load_dev_disabled_t *setup_dev_dis(entry_t *);
extern crypto_unload_soft_module_t *setup_unload_soft(entry_t *);
extern int get_dev_info(char *, int, int, mechlist_t **);
extern int get_dev_list(crypto_get_dev_list_t **);
extern int get_soft_info(char *, mechlist_t **);
extern int get_soft_list(crypto_get_soft_list_t **);

/* adm_metaslot */
extern int list_metaslot_info(boolean_t, boolean_t, mechlist_t *);
extern int list_metaslot_policy();
extern int disable_metaslot(mechlist_t *, boolean_t, boolean_t);
extern int enable_metaslot(char *, char *, boolean_t, mechlist_t *, boolean_t,
    boolean_t);

#ifdef __cplusplus
}
#endif

#endif /* _CRYPTOADM_H */
