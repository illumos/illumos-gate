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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBISCSITGT_H
#define	_LIBISCSITGT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Management API for the iSCSI Target.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These includes resolve
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/iscsi_protocol.h>
#include <sys/scsi/generic/inquiry.h>

#define	EUI64_SIZE	16
#define	VID_SIZE	8
#define	PID_SIZE	16

/*
 * []------------------------------------------------------------------[]
 * | Structures and enums returned by the list functions		|
 * []------------------------------------------------------------------[]
 */

typedef enum { LU_Offline, LU_Online } iscsit_status_t;
typedef enum { Target, Initiator, TPGT } iscsit_obj_type_t;

/*
 * Logical Unit (LU) Structure.
 * Each iSCSI Target has one or more Logical Units.
 */
typedef struct iscsit_lu {
	/* This is the LU number for SCSI commands */
	int		l_num;

	/* Globally unique identifier */
	uint8_t		l_guid[EUI64_SIZE];

	/*
	 * VID/PID used in SCSI INQUIRY responses
	 */
	char		l_vid[VID_SIZE],
			l_pid[PID_SIZE];
	/*
	 * Value will be one of DTYPE_DIRECT, DTYPE_SEQUENTIAL, etc ...
	 * Look at sys/scsi/generic/inquiry.h for full list
	 */
	uint8_t		l_dtype;

	/* Size of device in blocks */
	diskaddr_t	l_size;

	iscsit_status_t	l_status;
} iscsit_lu_t;

/*
 * iSCSI Session information.
 */
typedef struct iscsit_conn {
	char		c_name[ISCSI_MAX_NAME_LEN],
			*c_alias;
} iscsit_conn_t;

typedef struct iscsit_target {
	/* This is the full IQN name of the target */
	char		t_name[ISCSI_MAX_NAME_LEN];

	/*
	 * The Alias which is the same as "friendly name" used during the
	 * creation of the target.
	 */
	char		*t_alias;

	/*
	 * The number of Logical Units associated with this target.
	 * There will always be at least one LU with a value of 0.
	 * If there are more than LU the order is not guaranteed.
	 */
	int		t_lu_count;
	iscsit_lu_t	**t_lu_list;

	/*
	 * A list of initiator which may access this target. This list
	 * may be 0 in length.
	 */
	int		t_acl_count;
	char		**t_acl_list;

	/*
	 * Target Portal Group Tags. A value of zero for the count
	 * is valid.
	 */
	int		t_tpgt_count;
	char		**t_tpgt_list;

	/*
	 * The number of sessions that are currently attached to the
	 * target. Zero is valid.
	 */
	int		t_conn_count;
	iscsit_conn_t	**t_conn_list;
} iscsit_target_t;

/*
 * Information stored locally about initiators. Local initiator information
 * is setup when administrators wish to control access to each target. The
 * use of iSNS will be the prefered method once it's supported.
 */
typedef struct iscsit_initiator {
	char		i_name[ISCSI_MAX_NAME_LEN],
			*i_chap_name;
	/*
	 * While the target daemon has the CHAP secret available it's
	 * never returned. The CHAP name and secret can be changed at
	 * any time. This boolean will indicate if the CHAP secret is set
	 * and if so will cause the daemon to perform unidirectional
	 * authentication.
	 */
	boolean_t	i_chap_secret_set;
} iscsit_initiator_t;

/*
 * The list of IP addresses associated with a Target Portal Group Tag
 */
typedef struct iscsit_tpgt {
	int			t_ip_count;
	struct sockaddr_storage **t_ip_list;
} iscsit_tpgt_t;

/*
 * These are values which are used globally through the target daemon.
 */
typedef struct iscsit_admin {
	/*
	 * This is the targets CHAP information. When an initiator needs
	 * to authenticate the target these values are used when creating
	 * the response.
	 */
	char			*a_chap_name;
	boolean_t		a_chap_secret_set;

	/*
	 * The location of the target configuration and default storage for LUs
	 */
	char			*a_base_directory;

	struct sockaddr_storage	a_radius_server;
	boolean_t		a_radius_secret_set,
				a_isns_discovery;
	struct sockaddr_storage a_isns_ip;
	boolean_t		a_fast_write_ack;
} iscsit_admin_t;

typedef void *iscsit_handle_t;

/*
 * []------------------------------------------------------------------[]
 * | Funtion Prototypes							|
 * []------------------------------------------------------------------[]
 */

/*
 * []------------------------------------------------------------------[]
 * | Functions for ZFS							|
 * []------------------------------------------------------------------[]
 */
/*
 * iscsitgt_zfs_share -- advertise a ZFS volume through iSCSI
 * iscsitgt_zfs_unshare -- unadvertise a ZFS volume through iSCSI
 *
 * dataset = this must be a valid ZFS dataset which has a "type" property
 *    of "volume".
 *
 * These functions will return 0 on success and -1 on failure setting errno
 * thusly:
 *
 *    ENODEV - dataset not found
 *    EINVAL - a share parameter has an invalid value
 *    ENOSYS - the option string cannot be understood for any other reason
 */
int iscsitgt_zfs_share(const char *dataset);
int iscsitgt_zfs_unshare(const char *dataset);

/*
 * iscsitgt_zfs_is_shared -- returns 1 and 0 otherwise
 */
int iscsitgt_zfs_is_shared(const char *dataset);

/*
 * []------------------------------------------------------------------[]
 * | Functions to create handles which are used by methods defined below|
 * []------------------------------------------------------------------[]
 */
/*
 * iscsitgt_init -- Create a handle for each daemon
 *
 * A future release will enable this library to work to control multiple
 * daemons on different hosts. For now, the argument 'host' should be
 * set to NULL which will indicate the local host.
 */
iscsit_handle_t iscsitgt_init(char *host);

/*
 * iscsitgt_fini -- free resources allocated by iscsitgt_init()
 */
void iscsitgt_fini(iscsit_handle_t h);

/*
 * []------------------------------------------------------------------[]
 * | Funtions for creating base objects					|
 * []------------------------------------------------------------------[]
 */
/*
 * iscsitgt_creat_target -- creates a new target/lu
 *
 * h = This is handle which indicates to which target the request is sent.
 *    If NULL, the target daemon on the current host is used.
 * friendly_name = any ASCII string with the following restrictions.
 *    - it must be no more than 163 characters
 *    - it must only contain charcters from the set of 'a-z', 'A-Z', '0-9',
 *      ':', '.', or '-'
 *    The friendly_name will also be used as the iSCSI TargetAlias which
 *    is sent to the initiator as part of the log in parameters.
 * lun = If the friendly_name has never been used before then lun must be 0.
 *    If friendly_name has already been created other luns will be created
 *    under that target. 0 <= lun <= 65535. NOTE: Using LUNs larger than
 *    255 is not guaranteed to work for all initiators.
 * size = The requested size for the device in blocks. There must be
 *    available space on the device for the create to succeed. size may
 *    be zero if, and only if, a 'backing' argument is given which exists.
 * dtype = This indicates which type of emulation is performed by the
 *    daemon. Currently DTYPE_DIRECT, DTYPE_SEQUENTIAL, and DTYPE_UNKNOWN
 *    are supported. A dtype of DTYPE_UNKNOWN indicates to the daemon
 *    that a pass through mode should be used. For the pass through mode
 *    to work 'backing' must be a character device which supports the USCSI
 *    ioctl. For ZVOLs the dtype should be DTYPE_DIRECT.
 * backing = optional location for the backing store. Normally the storage
 *    for the LU is created in the directory supplied to iscsit_mod_adm_store().
 *    If the 'backing' file name doesn't exist *and* a valid device 'size' is
 *    given then the backing store will be created in that location. When the
 *    target/lu is removed this backing store will also be removed.
 *
 * Return codes:
 * EINVAL = one or more of the arguments are invalid
 * ENOSPC = No space remains to create the backing store.
 * EEXIST = A target with the same friendly_name already exists
 */
int iscsitgt_creat_target(iscsit_handle_t h, char *friendly_name,
    int lun, diskaddr_t size, int dtype, char *backing);

/*
 * iscsitgt_creat_initiator -- creates an initiator object
 *
 * Associates a fully compliant iSCSI name (IQN or EUI type) with
 * a really human readable name.
 *
 * h = Handle used to communicate with remote target daemons. A NULL
 *    value may be used to indicate that the local host target daemon
 * friendly_name = Any ASCII string.
 * iqn_name = An initiator IQN or EUI string. There will be no validation
 *    of the name to determine if it complies with RFC3720. This way if
 *    an initiator has a poorly formed name we can still be configured to
 *    work with it.
 *
 * Return codes:
 * 0 = success
 * EEXIST = The friendly_name is already used.
 */
int iscsitgt_creat_initiator(iscsit_handle_t h, char *friendly_name,
    char *iqn_name);

/*
 * iscsitgt_creat_tpgt -- Create a Target Portal Group Tag
 *
 * Once a TPGT object has been created iscsitgt_add_tpgt_ip would be used
 * to associate certain IP addresses with this TPGT. This is used to
 * limit which NICs connections are accepted on for a given target.
 * Once a TPGT is setup it can be added to a target using:
 *     iscsitgt_add_target_tpgt().
 *
 * h = See iscsitgt_creat_target
 * tpgt_num = a value between 1 and 65535 inclusive
 *
 * Return codes:
 * 0 = success
 * EEXIST = A tpgt with that number already exists.
 * EINVAL = TPGT must be a value between 1 and 65535 inclusive
 */
int iscsitgt_creat_tpgt(iscsit_handle_t h, int tpgt_num);

/*
 * []------------------------------------------------------------------[]
 * | Funtions for removing base objects					|
 * []------------------------------------------------------------------[]
 */

/*
 * iscsitgt_rem_target -- Removes a target/LU from the system
 *
 * Logical Unit Number 0 *must* be the last LUN removed from a target
 * If not, an error will be returned. When LUN0 is removed all references
 * to friendly_name are also removed from the system. e.g. Once the LU's
 * are removed there's nothing else required to remove the target.
 *
 * h = See iscsitgt_creat_target()
 * friendly_name = This is the same name used during the creation of
 *    the target.
 * lun = Logical Unit Number
 *
 * Return codes:
 * 0 = success
 * ENOENT = either friendly_name wasn't found or lun not found
 * EINVAL = attempt made to remove LUN0 while other LUs still exist.
 */
int iscsitgt_rem_target(iscsit_handle_t h, char *friendly_name,
    int lun);

/*
 * iscsitgt_rem_initiator -- Removes initiator object
 *
 * This method removes just the initiator object, but not any references
 * to this object. For example let's say an initiator was called
 * payroll_server and that this server was replaced with a new server
 * that had the same function, but with a new IQN value and CHAP secret.
 * The user of this library could then remove the initiator object
 * and create a new one with the changes *without* needing to update all
 * of the target objects that have a reference to 'payroll_server' in
 * their ACLs. This is a security feature. If a target has a reference
 * to an initiator object which doesn't exist, nobody will be able to
 * log into the target. If the daemon we're to remove all references
 * along with the object it would then be possible for an initiator to
 * log into the target during the time the target didn't have a reference.
 *
 * h = See iscsitgt_creat_target()
 * friendly_name = same value as that used during create.
 *
 * Return codes:
 * 0 = success
 * ENOENT = Can't find friendly_name
 */
int iscsitgt_rem_initiator(iscsit_handle_t h, char *friendly_name);

/*
 * iscsitgt_rem_tpgt -- Removes a tpgt object
 *
 * Similar in function to iscsitgt_rem_initiator. This method only
 * removes the TPGT object, but not any references to the object. This
 * alows the administrator to remove an old TPGT and create a new one
 * without needing to update each and every target first.
 *
 * h = See iscsitgt_creat_target
 * tpgt_num = value used during create
 *
 * Return codes:
 * 0 = success
 * ENOENT = tpgt_num wasn't found
 * EINVAL = a value outside of the accepted range for tpgt_num was used.
 */
int iscsitgt_rem_tpgt(iscsit_handle_t h, int tpgt_num);

/*
 * []------------------------------------------------------------------[]
 * | Funtions for adding attributes to base objects			|
 * []------------------------------------------------------------------[]
 */
/*
 * iscsitgt_add_target_initiator -- Adds an initiator object to ACL for target
 *
 * h = See iscsitgt_creat_target
 * friendly_name = Existing target
 * initiator = name of initiator object which doesn't need to exist before
 *    it's added.
 *
 * Return codes:
 * 0 = success
 * ENOENT = friendly_name doesn't exist.
 */
int iscsitgt_add_target_initiator(iscsit_handle_t h, char *friendly_name,
    char *initiator);

/*
 * iscsitgt_add_target_tpgt -- adds TPGT to the target
 *
 * h = See iscsitgt_creat_target()
 * friendly_name = Must be a valid target object name
 * tpgt_num = While the TPGT object doesn't need to exist, the value will
 *    be validated to see if it's within the valid range of 1 to 65535 inclusive
 *
 * Return codes:
 * 0 = success
 * ENOENT = friendly_name not found
 * EINVAL = tpgt_num is not within the valid range.
 */
int iscsitgt_add_target_tpgt(iscsit_handle_t h, char *friendly_name,
    int tpgt_num);

/*
 * iscsitgt_add_tpgt_ip -- Adds IP address to TPGT object
 *
 * Return codes:
 * 0 = success
 * ENOENT = tpgt_num doesn't exist
 * EINVAL = tpgt_num is not within the valid range
 */
int iscsitgt_add_tpgt_ip(iscsit_handle_t h, int tpgt_num,
    struct sockaddr_storage *s);

/*
 * []------------------------------------------------------------------[]
 * | Funtions for deleting attributes from base objects			|
 * []------------------------------------------------------------------[]
 */
/*
 * iscsitgt_del_target_initiator -- Removes initiator from target ACL
 *
 * h = See iscsitgt_creat_target()
 * friendly_name = target object
 * initiator = initiator object to remove from ACL
 *
 * Return codes:
 * 0 = success
 * ENOENT = friendly_name or initiator don't exist
 */
int iscsitgt_del_target_initiator(iscsit_handle_t h, char *friendly_name,
    char *initiator);

/*
 * iscsitgt_del_target_tpgt -- Removes TPGT from specific target
 *
 * Return codes:
 * 0 = success
 * ENOENT = Either friendly_name or tpgt_num doesn't exist as a valid
 *    type
 * EINVAL = tpgt_num is outside of the valid range (1 to 65535)
 */
int iscsitgt_del_target_tpgt(iscsit_handle_t h, char *friendly_name,
    int tpgt_num);

/*
 * iscsitgt_del_tpgt_ip -- Removes IP address from TPGT
 *
 * Return codes:
 * 0 = success
 * ENOENT = tpgt_num wasn't found or the IP address wasn't found within a valid
 *    tpgt
 * EINVAL = tpgt_num is outside of the valid range (1 to 65535)
 */
int iscsitgt_del_tpgt_ip(iscsit_handle_t h, int tpgt_num,
    struct sockaddr_storage *s);

/*
 * []------------------------------------------------------------------[]
 * | Funtions for modifying singular attributes for base objects	|
 * []------------------------------------------------------------------[]
 */
/*
 * iscsitgt_mode_target_alias -- Modifies the TargetAlias associated with target
 *
 * By default the TargetAlias is the same as that given for the friendly_name.
 * If another name is desired then it can be changed using this interface.
 *
 * h = See iscsitgt_creat_target()
 * friendly_name = target object
 *
 * Return codes:
 * 0 = success
 * ENOENT = friendly_name doesn't exist
 */
int iscsitgt_mod_target_alias(iscsit_handle_t h, char *friendly_name,
    char *alias);
int iscsitgt_mod_target_maxrec(iscsit_handle_t h, char *friendly_name,
    size_t maxrecv);
int iscsitgt_mod_initiator_chap(iscsit_handle_t h,
    char *friendly_name, char *chap_name, char *chap_secret);
int iscsitgt_mod_adm_store(iscsit_handle_t h, char *base);
int iscsitgt_mod_adm_chap(iscsit_handle_t h, char *chap_name,
    char *chap_secret);
int iscsitgt_mod_adm_radius(iscsit_handle_t h, struct sockaddr_storage *s,
    char *secret);
int iscsitgt_mod_adm_isns_discover(iscsit_handle_t h,
    boolean_t find);
int iscsitgt_mod_adm_isns(iscsit_handle_t h,
    struct sockaddr_storage *s);
int iscsitgt_mod_adm_fwa(iscsit_handle_t h, boolean_t enable);

/*
 * []------------------------------------------------------------------[]
 * | Funtions for listing objects					|
 * |									|
 * | NOTE: Each of the following function have a specific free routine	|
 * | which must be called to free the data.				|
 * []------------------------------------------------------------------[]
 */
/*
 * iscsit_list_find -- returns list of specific object names.
 *
 * There are three types of objects which are manipulated by these
 * interfaces (Target, Initiator, and TPGT). This function will return
 * an array of character strings which represent all of the available
 * objects of the specific type. These strings are the same ones that
 * where used during the creation.
 *
 * NOTE: Since there's no locking a call to this this function may
 * return a name which then doesn't exist when the user attempts to
 * get the specific information on that object. This would be caused
 * when another operator deletes an object between the first and second
 * calls.
 */
char **iscsit_list_find(iscsit_handle_t h, iscsit_obj_type_t t);
void iscsit_list_free(char **list);

/*
 * iscsit_list_target -- returns detailed information about a target
 */
iscsit_target_t *iscsit_list_target(iscsit_handle_t h, char *targ);
void iscsit_list_target_free(iscsit_target_t *t);

/*
 * iscsit_list_initiator -- returns detailed information about an initiator
 */
iscsit_initiator_t *iscsit_list_initiator(iscsit_handle_t h, char *initiator);
void iscsit_list_initiator_free(iscsit_initiator_t *t);

/*
 * iscsit_list_tpgt -- returns detailed information about a target port group
 */
iscsit_tpgt_t *iscsit_list_tpgt(iscsit_handle_t h, char *tpgt);
void iscsit_list_tpgt_free(iscsit_tpgt_t *t);

/*
 * iscsit_list_adm -- returns information about the global variables used.
 */
iscsit_admin_t *iscsit_list_adm(iscsit_handle_t h);
void iscsit_list_adm_free(iscsit_admin_t *t);

/*
 * Misc functions
 */
int iscsitgt_svc_online();

#ifdef __cplusplus
}
#endif

#endif /* _LIBISCSITGT_H */
