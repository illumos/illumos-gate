/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2015 Joyent, Inc.
 */

#ifndef _SYS_OVERLAY_PLUGIN_H
#define	_SYS_OVERLAY_PLUGIN_H

/*
 * overlay plugin interface for encapsulation/decapsulation modules
 *
 * This header file defines how encapsulation and decapsulation plugins
 * interact within the broader system. At this time, these interfaces are
 * considered private to illumos and therefore are subject to change. As we gain
 * more experience with a few of the different encapsulation formats, say nvgre
 * or geneve, then we can move to make this a more-stable interface.
 *
 * A plugin is a general kernel module that uses the miscellaneous mod-linkage.
 *
 * In it's _init(9E) routine, it must register itself with the overlay
 * subsystem. To do this, it allocates an overlay_plugin_register_t via
 * overlay_plugin_alloc(), that it then  * fills out with various required
 * information and then attempts to register with the system via a call to
 * overlay_plugin_register(). If that succeeds, it should then call
 * mod_install(9F). If the mod_install(9F) fails, then it should call
 * overlay_plugin_unregister(). Regardless of success or failure, it should call
 * overlay_plugin_free() to ensure that any memory that may be associated with
 * the registration is freed.
 *
 * When the module's _fini(9E) is called, overlay_plugin_unregister() should be
 * called first. It may return an error, such as EBUSY. In such cases, it should
 * be returned as the return status of _fini(9E). This is quite necessary, it
 * ensures that if the module is in use it doesn't get unloaded out from under
 * us the broader subsystem while it's still in use. A driver can use that to
 * know that there are no current instances of its private data.
 *
 * ------------------
 * Plugin Definitions
 * ------------------
 *
 * A plugin is required to fill in both an operations vector and a series of
 * information to the callback routine. Here are the routines and their
 * purposes. The full signatures are available below.
 *
 *   overlay_plugin_init_t
 *
 *	This interface is used to create a new instance of a plugin. An instance
 *	of a plugin will be created for each overlay device that is created. For
 *	example, if a device is created with VXLAN ID 23 and ID 42, then there
 *	will be two different calls to this function.
 *
 *	This function gives the plugin a chance to create a private data
 *	structure that will be returned on subsequent calls to the system.
 *
 *   overlay_plugin_fini_t
 *
 *	This is the opposite of overlay_plugin_init_t. It will be called when it
 *	is safe to remove any private data that is associated with this instance
 *	of the plugin.
 *
 *   overlay_plugin_propinfo_t
 *
 *	This is called with the name of a property that is registered when the
 *	plugin is created. This function will be called with the name of the
 *	property that information is being requested about. The plugin is
 *	responsible for filling out information such as setting the name, the
 *	type of property it is, the protection of the property (can a user
 *	update it?), whether the property is required, an optional default value
 *	for the property, and an optional set of values or ranges that are
 *	allowed.
 *
 *   overlay_plugin_getprop_t
 *
 *	Return the value of the named property from the current instance of the
 *	plugin.
 *
 *   overlay_plugin_setprop_t
 *
 *	Set the value of the named property to the specified value for the
 *	current instance of the plugin. Note, that it is the plugin's
 *	responsibility to ensure that the value of the property is valid and to
 *	update state as appropriate.
 *
 *   overlay_plugin_socket_t
 *
 *	Every overlay device has a corresponding socket that it uses to send and
 *	receive traffic. This routine is used to get the parameters that should
 *	be used to define such a socket. The actual socket may be multiplexed
 *	with other uses of it.
 *
 *   overlay_plugin_sockopt_t
 *
 *	Allow a plugin to set any necessary socket options that it needs on the
 *	kernel socket that is being used by a mux. This will only be called once
 *	for a given mux, if additional devices are added to a mux, it will not
 *	be called additional times.
 *
 *   overlay_plugin_encap_t
 *
 *	In this routine you're given a message block and information about the
 *	packet, such as the identifier and are asked to fill out a message block
 *	that represents the encapsulation header and optionally manipulate the
 *	input message if required.
 *
 *   overlay_plugin_decap_t
 *
 *	In this routine, you're given the encapsulated message block. The
 *	requirement is to decapsulate it and determine what is the correct
 *	overlay identifier for this network and to fill in the header size so
 *	the broader system knows how much of this data should be considered
 *	consumed.
 *
 *   ovpo_callbacks
 *
 *	This should be set to zero, it's reserved for future use.
 *
 * Once these properties are defined, the module should define the following
 * members in the overlay_plugin_register_t.
 *
 *   ovep_version
 *
 *	Should be set to the value of the macro OVEP_VERSION.
 *
 *   ovep_name
 *
 *	Should be set to a character string that has the name of the module.
 *	Generally this should match the name of the kernel module; however, this
 *	is the name that users will use to refer to this module when creating
 *	devices.
 *
 *   overlay_plugin_ops_t
 *
 *	Should be set to the functions as described above.
 *
 *   ovep_props
 *
 *	This is an array of character strings that holds the names of the
 *	properties of the encapsulation plugin.
 *
 *
 *   ovep_id_size
 *
 *	This is the size in bytes of the valid range for the identifier. The
 *	valid identifier range is considered a ovep_id_size byte unsigned
 *	integer, [ 0, 1 << (ovep_id_size * 8) ).
 *
 *   ovep_flags
 *
 *	A series of flags that indicate optional features that are supported.
 *	Valid flags include:
 *
 *		OVEP_F_VLAN_TAG
 *
 *			The encapsulation format allows for the encapsulated
 *			packet to maintain a VLAN tag.
 *
 *   ovep_dest
 *
 *	Describes the kind of destination that the overlay plugin supports for
 *	sending traffic. For example, vxlan uses UDP, therefore it requires both
 *	an IP address and a port; however, nvgre uses the gre header and
 *	therefore only requires an IP address. The following flags may be
 *	combined:
 *
 *		OVERLAY_PLUGIN_D_ETHERNET
 *
 *			Indicates that to send a packet to its destination, we
 *			require a link-layer ethernet address.
 *
 *		OVERLAY_PLUGIN_D_IP
 *
 *			Indicates that to send a packet to its destination, we
 *			require an IP address. Note, all IP addresses are
 *			transmitted as IPv6 addresses and for an IPv4
 *			destination, using an IPv4-mapped IPv6 address is the
 *			expected way to transmit that.
 *
 *		OVERLAY_PLUGIN_D_PORT
 *
 *			Indicates that to send a packet to its destination, a
 *			port is required, this usually indicates that the
 *			protocol uses something like TCP or UDP.
 *
 *
 * -------------------------------------------------
 * Downcalls, Upcalls, and Synchronization Guarantees
 * -------------------------------------------------
 *
 * Every instance of a given module is independent. The kernel only guarantees
 * that it will probably perform downcalls into different instances in parallel
 * at some point. No locking is provided by the framework for synchronization
 * across instances. If a module finds itself needing that, it will be up to it
 * to provide it.
 *
 * In a given instance, the kernel may call into entry points in parallel. If
 * the instance has private data, it should likely synchronize it. The one
 * guarantee that we do make, is that calls to getprop and setprop will be done
 * synchronized by a caller holding the MAC perimeter.
 *
 * While servicing a downcall from the general overlay device framework, a
 * kernel module should not make any upcalls, excepting those functions that are
 * defined in this header file, eg. the property related callbacks. Importantly,
 * it cannot make any assumptions about what locks may or may not be held by the
 * broader system. The only thing that it is safe for it to use are its own
 * locks.
 *
 * ----------------
 * Downcall Context
 * ----------------
 *
 * For all of the downcalls, excepting the overlay_plugin_encap_t and
 * overlay_plugin_decap_t, the calls will be made either in kernel or user
 * context, the module should not assume either way.
 *
 * overlay_plugin_encap_t and overlay_plugin_decap_t may be called in user,
 * kernel or interrupt context; however, it is guaranteed that the interrupt
 * will be below LOCK_LEVEL, and therefore it is safe to grab locks.
 */

#include <sys/stream.h>
#include <sys/mac_provider.h>
#include <sys/ksocket.h>
#include <sys/overlay_common.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	OVEP_VERSION	0x1

typedef enum overlay_plugin_flags {
	OVEP_F_VLAN_TAG	= 0x01	/* Supports VLAN Tags */
} overlay_plugin_flags_t;

/*
 * The ID space could easily be more than a 64-bit number, even
 * though today it's either a 24-64 bit value. How should we future
 * proof ourselves here?
 */
typedef struct ovep_encap_info {
	uint64_t	ovdi_id;
	size_t		ovdi_hdr_size;
} ovep_encap_info_t;

typedef struct __overlay_prop_handle *overlay_prop_handle_t;
typedef struct __overlay_handle *overlay_handle_t;

/*
 * Plugins are guaranteed that calls to setprop are serialized. However, any
 * number of other calls can be going on in parallel otherwise.
 */
typedef int (*overlay_plugin_encap_t)(void *, mblk_t *,
    ovep_encap_info_t *, mblk_t **);
typedef int (*overlay_plugin_decap_t)(void *, mblk_t *,
    ovep_encap_info_t *);
typedef int (*overlay_plugin_init_t)(overlay_handle_t, void **);
typedef void (*overlay_plugin_fini_t)(void *);
typedef int (*overlay_plugin_socket_t)(void *, int *, int *, int *,
    struct sockaddr *, socklen_t *);
typedef int (*overlay_plugin_sockopt_t)(ksocket_t);
typedef int (*overlay_plugin_getprop_t)(void *, const char *, void *,
    uint32_t *);
typedef int (*overlay_plugin_setprop_t)(void *, const char *, const void *,
    uint32_t);
typedef int (*overlay_plugin_propinfo_t)(const char *, overlay_prop_handle_t);

typedef struct overlay_plugin_ops {
	uint_t			ovpo_callbacks;
	overlay_plugin_init_t	ovpo_init;
	overlay_plugin_fini_t	ovpo_fini;
	overlay_plugin_encap_t	ovpo_encap;
	overlay_plugin_decap_t	ovpo_decap;
	overlay_plugin_socket_t ovpo_socket;
	overlay_plugin_sockopt_t ovpo_sockopt;
	overlay_plugin_getprop_t ovpo_getprop;
	overlay_plugin_setprop_t ovpo_setprop;
	overlay_plugin_propinfo_t ovpo_propinfo;
} overlay_plugin_ops_t;

typedef struct overlay_plugin_register {
	uint_t			ovep_version;
	const char		*ovep_name;
	const overlay_plugin_ops_t	*ovep_ops;
	const char		**ovep_props;
	uint_t			ovep_id_size;
	uint_t			ovep_flags;
	uint_t			ovep_dest;
} overlay_plugin_register_t;

/*
 * Functions that interact with registration
 */
extern overlay_plugin_register_t *overlay_plugin_alloc(uint_t);
extern void overlay_plugin_free(overlay_plugin_register_t *);
extern int overlay_plugin_register(overlay_plugin_register_t *);
extern int overlay_plugin_unregister(const char *);

/*
 * Property information callbacks
 */
extern void overlay_prop_set_name(overlay_prop_handle_t, const char *);
extern void overlay_prop_set_prot(overlay_prop_handle_t, overlay_prop_prot_t);
extern void overlay_prop_set_type(overlay_prop_handle_t, overlay_prop_type_t);
extern int overlay_prop_set_default(overlay_prop_handle_t, void *, ssize_t);
extern void overlay_prop_set_nodefault(overlay_prop_handle_t);
extern void overlay_prop_set_range_uint32(overlay_prop_handle_t, uint32_t,
    uint32_t);
extern void overlay_prop_set_range_str(overlay_prop_handle_t, const char *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_OVERLAY_PLUGIN_H */
