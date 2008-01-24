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

#ifndef _FUNCTIONS_H
#define	_FUNCTIONS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* events.c: event queue handling */
extern void free_event(struct np_event *);
extern void np_queue_add_event(struct np_event *);
extern struct np_event *np_queue_get_event(void);
extern const char *npe_type_str(enum np_event_type);
extern boolean_t start_event_collection(void);

/* interface.c: interface and upper layer profile handling */
extern void check_drop_dhcp(struct interface *);
extern void gen_newif_event(struct interface *);
extern void initialize_interfaces(void);
extern struct interface *add_interface(sa_family_t, const char *, uint64_t);
extern struct interface *get_interface(const char *);
extern void walk_interface(void (*)(struct interface *, void *), void *);
extern enum interface_type find_if_type(const char *);
extern const char *if_type_str(enum interface_type);
extern boolean_t interface_is_active(const struct interface *);
extern void show_if_status(const char *);
extern boolean_t bringupinterface(const char *, const char *, const char *,
    boolean_t);
extern void takedowninterface(const char *, boolean_t, boolean_t);
extern void take_down_all_ifs(const char *);
extern void check_interface_timer(struct interface *, void *);
extern void start_if_info_collect(struct interface *, void *);
extern boolean_t ulp_is_active(void);
extern void activate_upper_layer_profile(boolean_t, const char *);
extern void deactivate_upper_layer_profile(void);
extern void display(const char *);
extern int lookup_boolean_property(const char *, const char *, boolean_t *);
extern int lookup_count_property(const char *, const char *, uint64_t *);

/* wireless.c: wifi link handling */
extern void init_mutexes(void);
extern boolean_t connect_chosen_lan(struct wireless_lan *, struct interface *);
extern struct wireless_lan *prompt_for_visited(void);
extern boolean_t handle_wireless_lan(struct interface *);
extern boolean_t scan_wireless_nets(struct interface *);
extern void create_known_wifi_nets_file(void);
extern void update_known_wifi_nets_file(const char *, const char *);
extern void *periodic_wireless_scan(void *);

/* llp.c: link layer profile handling */
extern void llp_parse_config(void);
extern llp_t *llp_lookup(const char *);
extern llp_t *llp_high_pri(llp_t *, llp_t *);
extern llp_t *llp_best_avail(void);
extern boolean_t llp_activate(llp_t *);
extern void llp_deactivate(void);
extern void llp_swap(llp_t *);
extern char *llp_prnm(llp_t *);

/* state_machine.c: state machine handling */
extern void state_machine(struct np_event *);
extern void cleanup(void);

/* util.c: utility & ipc functions */
extern void dprintf(const char *, ...);
extern uint64_t get_ifflags(const char *, sa_family_t);
extern boolean_t is_plugged_in(struct interface *);
extern int start_childv(const char *, char const * const *);
extern int start_child(const char *, ...);
extern void start_timer(uint32_t,  uint32_t);
extern boolean_t valid_graphical_user(boolean_t);
extern void lookup_zonename(char *, size_t);
extern struct sockaddr *dupsockaddr(const struct sockaddr *);
extern boolean_t cmpsockaddr(const struct sockaddr *, const struct sockaddr *);

#endif /* _FUNCTIONS_H */
