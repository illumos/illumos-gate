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
 * Copyright 2015 Joyent, Inc.
 */

#ifndef _LIBVARPD_PROVIDER_H
#define	_LIBVARPD_PROVIDER_H

/*
 * varpd provider interface for lookup modules
 *
 * This header file defines all the structures and functions that a given lookup
 * module needs to implement and perform its purpose. At this time, all of these
 * interfaces are considered private to illumos and therefore are subject to
 * change. At some point we will move to more broadly stabilize these interfaces
 * and commit to them. Until such time, expect breakage for out of gate
 * consumers.
 *
 * A plugin is a dynamic shared object that is placed inside of varpd's default
 * module.
 *
 * The shared object must define an initializer, such as with #pragma init. This
 * function will be run with the module is dlopened by libvarpd. In that init
 * function, the function must allocate a varpd_plugin_register by calling
 * libvarpd_plugin_alloc() and specifying VARPD_CURRENT_VERSION. If that
 * succeeds, then it should proceed to fill out the registration and then call,
 * libvarpd_plugin_register() with it. Regardless of whether it succeeds or
 * fails, it should call libvarpd_plugin_free(). In the case of failure, there
 * is not much that the module should do, other than log some message to
 * stderr.
 *
 * Once libvarpd_plugin_register() returns, the module should assume that any
 * of the operations it defined in the operation vector may be called and
 * therefore it is recommended that any other required initialization should be
 * performed at that time.
 *
 * At this time, once a plugin is loaded, it will not be unloaded. Therefore,
 * there is no corresponding requirement to unregister, though that may come in
 * a future version.
 *
 * -----------------------------
 * Plugin Types and Destinations
 * -----------------------------
 *
 * There are two different kinds of plugins in this world, there are point to
 * point plugins and there are dynamic plugins. The key difference is in how
 * packets are routed through the system. In a point to point plugin, a single
 * destination is used when the instance is started. In dynamic plugins,
 * destinations are looked up as they are required and an instance of a plugin
 * is required to provide that.
 *
 * These point to point plugins define a type of OVERLAY_TARGET_POINT and the
 * dynamic plugins instead define a type of OVERLAY_TARGET_DYNAMIC.
 *
 * Encapsulation plugins have multiple types of destinations. They may require
 * an Ethernet address (OVERLAY_PLUGIN_D_ETHERNET), IP address
 * (OVERLAY_PLUGIN_D_IP), and a port (OVERLAY_PLUGIN_D_PORT). For example,
 * consider vxlan, it requires an IP and a port; while a hypothetical nvgre,
 * would only require an IP.
 *
 * A plugin is allowed to describe which of these fields that it supports and
 * given which encapsulation plugin it is paired with, it can support a varying
 * degree of properties. For example, consider the example of the direct plugin.
 * It has a notion of a destination port and a destination IP. If it is paired
 * with a plugin that only requires an IP, then it wouldn't need to show a
 * property that's related to a destination port.
 *
 * ------------------
 * Plugin Definitions
 * ------------------
 *
 * A plugin is required to fill in both an operations vector and a series of
 * additional metadata that it passed in to libvarpd_plugin_register(). The
 * following lists all of the routines and their purposes. The full signatures
 * are available in the body of the header file.
 *
 *   varpd_plugin_create_f
 *
 *	Create a new instance of a plugin. Each instance refers to a different
 *	overlay device and thus a different overlay identifier. Each instance
 *	has its own property space and is unique. This function gives the chance
 *	for the plugin to create and provide any private data that it will
 *	require.
 *
 *	In addition, the plugin is given the type of destination that is
 *	required and it is its job to determine whether or not it supports it.
 *
 *   varpd_plugin_destroy_f
 *
 *	This is the opposite of varpd_plugin_create_f. It is called to allow the
 *	plugin to reclaim any resources with the private argument that it passed
 *	out as part of the destroy function.
 *
 *   varpd_plugin_start_f
 *
 *	This routine is called to indicate that an instance should be started.
 *	This is a plugin's chance to verify that it has all of its required
 *	properties set and to take care of any action that needs to be handled
 *	to begin the plugin. After this point it will be legal to have the
 *	varpd_plugin_default_f, varpd_plugin_lookup_f, varpd_plugin_arp_f and
 *	varpd_plugin_dhcp_f endpoints called.
 *
 *   varpd_plugin_stop_f
 *
 *	This routine is called to indicate that an instance is stopping, it is
 *	the opposite of varpd_plugin_start_f. This is a chance to clean up
 *	resources that are a side effect of having started the instance.
 *
 *   varpd_plugin_default_f
 *
 *	This routine is defined by plugins of type OVERLAY_TARGET_POINT. It is
 *	used to answer the question of where should all traffic for this
 *	instance be destined. Plugins of type OVERLAY_TARGET_DYNAMIC should
 *	leave this entry set to NULL.
 *
 *	On success, the default routine should return VARPD_LOOKUP_OK. On
 *	failure, it should return the macro VARPD_LOOKUP_DROP.
 *
 *   varpd_plugin_lookup_f
 *
 *	This routine must be defined by plugins of type OVERLAY_TARGET_DYNAMIC.
 *	It is used to lookup the destination for a given request. Each request
 *	comes in with its own MAC address this allows a plugin to direct it to
 *	any remote location.
 *
 *	This is designed as an asynchronous API. Once a lookup is completed it
 *	should call libvarpd_plugin_query_reply() and pass as the second
 *	argument either VARPD_LOOKUP_OK to indicate that it went alright or it
 *	should reply VARPD_LOOKUP_DROP to indicate that the packet should be
 *	dropped.
 *
 *	In addition, there are several utility routines that can take care of
 *	various kinds of traffic automatically. For example, if an ARP, NDP, or
 *	DHCP packet comes in, there are utilities such as
 *	libvarpd_plugin_proxy_arp(), libvarpd_plugin_proxy_ndp() and
 *	libvarpd_plugin_proxy_dhcp(), which allows the system to do the heavy
 *	lifting of validating the packet once it finds that it matches certain
 *	properties.
 *
 *   varpd_plugin_arp_f
 *
 *	This is an optional entry for plugins of type OVERLAY_TARGET_DYNAMIC.
 *	This is called after a plugin calls libvarpd_plugin_proxy_arp() and is
 *	used to ask the plugin to perform an ARP or NDP query. The type of query
 *	is passed in in the third argument, the only valid value for which will
 *	be VARPD_QTYPE_ETHERNET, to indicate we're doing an Ethernet lookup.
 *
 *	The layer three IP address that is being looked up will be included in
 *	the struct sockaddr. The sockaddr(3SOCKET)'s sa_family will be set to
 *	indicate the type, eg. AF_INET or AF_INET6 and that will indicate the
 *	kind of sockaddr that will be used. For more information see
 *	sockaddr(3SOCKET). The implementation ensures that enough space for the
 *	link layer address will exist.
 *
 *	This is an asynchronous lookup. Once the answer has been written, a
 *	plugin should call libvarpd_plugin_arp_reply and if it was successful,
 *	VARPD_LOOKUP_OK should be passed in and if it failed, VARPD_LOOKUP_DROP
 *	should be passed in instead.
 *
 *   varpd_plugin_dhcp_f
 *
 *	This is an optional entry for plugins of type OVERLAY_TARGET_DYNAMIC.
 *	This is called after a plugin calls the libvarpd_plugin_proxy_dhcp() and
 *	is used to ask the plugin to determine where is the DHCP server that
 *	this packet should actually be sent to. What is happening here is that
 *	rather than broadcast the initial DHCP request, we instead unicast it to
 *	a specified DHCP server that this operation vector indicates.
 *
 *	The plugin is given a type, the same as the ARP plugin which indicates
 *	the kind of link layer address, the only valid type is
 *	VARPD_QTYPE_ETHERNET, other types should be rejected. Then, like the arp
 *	entry point, the dhcp entry point should determine the link layer
 *	address of the DHCP server and write that out in the appropriate memory
 *	and call libvarpd_plugin_dhcp_reply() when done. Similar to the arp
 *	entry point, it should use VARPD_LOOKUP_OK to indicate that it was
 *	filled in and VARPD_LOOKUP_DROP to indicate that it was not.
 *
 *   varpd_plugin_nprops_f
 *
 *	This is used by a plugin to indicate the number of properties that
 *	should exist for this instance. Recall from the section that Plugin
 *	types and Destinations, that the number of entries here may vary. As
 *	such, the plugin should return the number that is appropriate for the
 *	instance.
 *
 *	This number will be used to obtain information about a property via the
 *	propinfo functions. However, the getprop and setprop interfaces will
 *	always use names to indicate the property it is getting and setting.
 *	This difference is structured this way to deal with property discovery
 *	and to make the getprop and setprop interfaces slightly easier for other
 *	parts of the broader varpd/dladm infrastructure.
 *
 *   varpd_plugin_propinfo_f
 *
 *	This interface is used to get information about a property, the property
 *	that information is being requested for is being passed in via the
 *	second argument. Here, callers should set properties such as the name,
 *	the protection, whether or not the property is required, set any default
 *	value, if it exist, and if relevant, set the valid range of values.
 *
 *   varpd_plugin_getprop_f
 *
 *	This is used to get the value of a property, if it is set. The passed in
 *	length indicates the length of the buffer that is used for updating
 *	properties. If it is not of sufficient size, the function should return
 *	an error and not update the buffer. Otherwise, it should update the size
 *	pointer with the valid size.
 *
 *   varpd_plugin_setprop_f
 *
 *	This is used to set the value of a property. An endpoint should validate
 *	that the property is valid before updating it. In addition, it should
 *	update its state as appropriate.
 *
 *   varpd_plugin_save_f
 *
 *	This is used to serialize the state of a given instance of a plugin such
 *	that if varpd crashes, it can be recovered. The plugin should write all
 *	state into the nvlist that it is passed in, it may use any keys and
 *	values that it wants. The only consumer of that nvlist will be the
 *	plugin itself when the restore endpoint is called.
 *
 *   varpd_plugin_restore_f
 *
 *	This is called by the server to restore an instance that used to exist,
 *	but was lost due to a crash. This is a combination of calling create and
 *	setting properties. The plugin should restore any private state that it
 *	can find recorded from the nvlist. The only items in the nvlist will be
 *	those that were written out during a previous call to
 *	varpd_plugin_save_f.
 *
 *
 * Once all of these interfaces are implemented, the plugin should define the
 * following members in the varpd_plugin_register_t.
 *
 *   vpr_version
 *
 *	This indicates the version of the plugin. Plugins should set this to the
 *	macro VARPD_CURRENT_VERSION.
 *
 *   vpr_mode
 *
 *	This indicates the mode of the plugin. The plugin's mode should be one
 *	of OVERLAY_TARGET_POINT and OVERLAY_TARGET_DYNAMIC. For more discussion
 *	of these types and the differences, see the section on Plugin Types and
 *	Destinations.
 *
 *   vpr_name
 *
 *	This is the name of the plugin. This is how users will refer to it in
 *	the context of running dladm(1M) commands. Note, this name must be
 *	unique across the different plugins, as it will cause others with the
 *	same name not to be registered.
 *
 *   vpr_ops
 *
 *	This is the operations vector as described above. Importantly, the
 *	member vpo_callbacks must be set to zero, this is being used for future
 *	expansion of the structure.
 *
 *
 * --------------------------------------------------
 * Downcalls, Upcalls, and Synchronization Guarantees
 * --------------------------------------------------
 *
 * Every instance of a plugin is independent. Calls into a plugin may be made
 * for different instances in parallel. Any necessary locking is left to the
 * plugin module. Within an instance, various calls may come in parallel.
 *
 * The primary guarantees are that none of the varpd_plugin_save_f,
 * varpd_plugin_lookup_f, varpd_default_f, varpd_plugin_arp_f, and
 * varpd_plugin_dhcp_f will be called until after a call to varpd_plugin_start_f
 * has been called. Similarly, they will not be called after a call to
 * varpd_plugin_stop_f.
 *
 * The functions documented in this header may be called back into from any
 * context, including from the operation vectors.
 */

#include <libvarpd.h>
#include <libnvpair.h>
#include <sys/socket.h>
#include <sys/overlay_target.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	VARPD_VERSION_ONE	1
#define	VARPD_CURRENT_VERSION	VARPD_VERSION_ONE

typedef struct __varpd_provier_handle varpd_provider_handle_t;
typedef struct __varpd_query_handle varpd_query_handle_t;
typedef struct __varpd_arp_handle varpd_arp_handle_t;
typedef struct __varpd_dhcp_handle varpd_dhcp_handle_t;

typedef int (*varpd_plugin_create_f)(varpd_provider_handle_t *, void **,
    overlay_plugin_dest_t);
typedef int (*varpd_plugin_start_f)(void *);
typedef void (*varpd_plugin_stop_f)(void *);
typedef void (*varpd_plugin_destroy_f)(void *);

#define	VARPD_LOOKUP_OK		(0)
#define	VARPD_LOOKUP_DROP	(-1)
typedef int (*varpd_plugin_default_f)(void *, overlay_target_point_t *);
typedef void (*varpd_plugin_lookup_f)(void *, varpd_query_handle_t *,
    const overlay_targ_lookup_t *, overlay_target_point_t *);

#define	VARPD_QTYPE_ETHERNET	0x0
typedef void (*varpd_plugin_arp_f)(void *, varpd_arp_handle_t *, int,
    const struct sockaddr *, uint8_t *);
typedef void (*varpd_plugin_dhcp_f)(void *, varpd_dhcp_handle_t *, int,
    const overlay_targ_lookup_t *, uint8_t *);

typedef int (*varpd_plugin_nprops_f)(void *, uint_t *);
typedef int (*varpd_plugin_propinfo_f)(void *, const uint_t,
    varpd_prop_handle_t *);
typedef int (*varpd_plugin_getprop_f)(void *, const char *, void *, uint32_t *);
typedef int (*varpd_plugin_setprop_f)(void *, const char *, const void *,
    const uint32_t);

typedef int (*varpd_plugin_save_f)(void *, nvlist_t *);
typedef int (*varpd_plugin_restore_f)(nvlist_t *, varpd_provider_handle_t *,
    overlay_plugin_dest_t, void **);

typedef struct varpd_plugin_ops {
	uint_t			vpo_callbacks;
	varpd_plugin_create_f	vpo_create;
	varpd_plugin_start_f	vpo_start;
	varpd_plugin_stop_f	vpo_stop;
	varpd_plugin_destroy_f	vpo_destroy;
	varpd_plugin_default_f	vpo_default;
	varpd_plugin_lookup_f	vpo_lookup;
	varpd_plugin_nprops_f	vpo_nprops;
	varpd_plugin_propinfo_f	vpo_propinfo;
	varpd_plugin_getprop_f	vpo_getprop;
	varpd_plugin_setprop_f	vpo_setprop;
	varpd_plugin_save_f	vpo_save;
	varpd_plugin_restore_f	vpo_restore;
	varpd_plugin_arp_f	vpo_arp;
	varpd_plugin_dhcp_f	vpo_dhcp;
} varpd_plugin_ops_t;

typedef struct varpd_plugin_register {
	uint_t		vpr_version;
	uint_t		vpr_mode;
	const char	*vpr_name;
	const varpd_plugin_ops_t *vpr_ops;
} varpd_plugin_register_t;

extern varpd_plugin_register_t *libvarpd_plugin_alloc(uint_t, int *);
extern void libvarpd_plugin_free(varpd_plugin_register_t *);
extern int libvarpd_plugin_register(varpd_plugin_register_t *);

/*
 * Blowing up and logging
 */
extern void libvarpd_panic(const char *, ...) __NORETURN;

/*
 * Misc. Information APIs
 */
extern uint64_t libvarpd_plugin_vnetid(varpd_provider_handle_t *);

/*
 * Lookup Replying query and proxying
 */
extern void libvarpd_plugin_query_reply(varpd_query_handle_t *, int);

extern void libvarpd_plugin_proxy_arp(varpd_provider_handle_t *,
    varpd_query_handle_t *, const overlay_targ_lookup_t *);
extern void libvarpd_plugin_proxy_ndp(varpd_provider_handle_t *,
    varpd_query_handle_t *, const overlay_targ_lookup_t *);
extern void libvarpd_plugin_arp_reply(varpd_arp_handle_t *, int);

extern void libvarpd_plugin_proxy_dhcp(varpd_provider_handle_t *,
    varpd_query_handle_t *, const overlay_targ_lookup_t *);
extern void libvarpd_plugin_dhcp_reply(varpd_dhcp_handle_t *, int);


/*
 * Property information callbacks
 */
extern void libvarpd_prop_set_name(varpd_prop_handle_t *, const char *);
extern void libvarpd_prop_set_prot(varpd_prop_handle_t *, overlay_prop_prot_t);
extern void libvarpd_prop_set_type(varpd_prop_handle_t *, overlay_prop_type_t);
extern int libvarpd_prop_set_default(varpd_prop_handle_t *, void *, ssize_t);
extern void libvarpd_prop_set_nodefault(varpd_prop_handle_t *);
extern void libvarpd_prop_set_range_uint32(varpd_prop_handle_t *, uint32_t,
    uint32_t);
extern void libvarpd_prop_set_range_str(varpd_prop_handle_t *, const char *);

/*
 * Various injecting and invalidation routines
 */
extern void libvarpd_inject_varp(varpd_provider_handle_t *, const uint8_t *,
    const overlay_target_point_t *);
extern void libvarpd_inject_arp(varpd_provider_handle_t *, const uint16_t,
    const uint8_t *, const struct in_addr *, const uint8_t *);
extern void libvarpd_fma_degrade(varpd_provider_handle_t *, const char *);
extern void libvarpd_fma_restore(varpd_provider_handle_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBVARPD_PROVIDER_H */
