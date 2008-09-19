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

/* door.c: door-based control/status interface */
extern void initialize_door(void);
extern void terminate_door(void);
extern void report_interface_up(const char *, struct in_addr, int);
extern void report_interface_down(const char *, libnwam_diag_cause_t);
extern void report_interface_added(const char *);
extern void report_interface_removed(const char *);
extern void report_wlan_connect_fail(const char *);
extern void report_wlan_disconnect(const struct wireless_lan *);
extern void report_wlan_connected(const struct wireless_lan *);
extern void report_llp_selected(const char *);
extern void report_llp_unselected(const char *, libnwam_diag_cause_t);
extern void report_ulp_activated(const char *);
extern void report_ulp_deactivated(const char *);
extern void report_scan_complete(const char *, boolean_t,
    const struct wireless_lan *, int);
extern boolean_t request_wlan_key(struct wireless_lan *);
extern boolean_t request_wlan_selection(const char *,
    const struct wireless_lan *, int);
extern void check_door_life(uint32_t);

/* events.c: event queue handling */
extern void free_event(struct np_event *);
extern boolean_t np_queue_add_event(enum np_event_type, const char *);
extern struct np_event *np_queue_get_event(void);
extern const char *npe_type_str(enum np_event_type);
extern boolean_t start_event_collection(void);

/* interface.c: interface and upper layer profile handling */
extern void initialize_interfaces(void);
extern struct interface *add_interface(sa_family_t, const char *, uint64_t);
extern void remove_interface(const char *);
extern struct interface *get_interface(const char *);
extern void walk_interface(void (*)(struct interface *, void *), void *);
extern libnwam_interface_type_t find_if_type(const char *);
extern const char *if_type_str(libnwam_interface_type_t);
extern void update_interface_v4_address(const char *, in_addr_t);
extern void update_interface_flags(const char *, int);
extern boolean_t interface_is_active(const struct interface *);
extern void show_if_status(const char *);
extern return_vals_t bringupinterface(const char *, const char *, const char *,
    boolean_t);
extern void takedowninterface(const char *, libnwam_diag_cause_t);
extern void clear_cached_address(const char *);
extern void check_interface_timers(uint32_t);
extern void start_if_info_collect(struct interface *, void *);
extern boolean_t ulp_is_active(void);
extern void activate_upper_layer_profile(boolean_t, const char *);
extern void deactivate_upper_layer_profile(void);
extern int lookup_boolean_property(const char *, const char *, boolean_t *);
extern int lookup_count_property(const char *, const char *, uint64_t *);
extern boolean_t is_interface_ok(const char *);
extern libnwam_interface_type_t get_if_type(const char *);
extern void get_interface_state(const char *, boolean_t *, boolean_t *);
extern void print_interface_status(void);

/* wireless.c: wifi link handling */
extern void initialize_wireless(void);
extern void add_wireless_if(const char *);
extern void remove_wireless_if(const char *);
extern struct wireless_lan *prompt_for_visited(void);
extern return_vals_t handle_wireless_lan(const char *);
extern libnwam_known_ap_t *get_known_ap_list(size_t *, uint_t *);
extern int add_known_ap(const char *, const char *);
extern int delete_known_ap(const char *, const char *);
extern void *periodic_wireless_scan(void *);
extern boolean_t check_wlan_connected(const char *, const char *, const char *);
extern int set_specific_lan(const char *, const char *, const char *);
extern int set_wlan_key(const char *, const char *, const char *, const char *);
extern int launch_wireless_scan(const char *);
extern void disconnect_wlan(const char *);
extern void get_wireless_state(const char *, boolean_t *, boolean_t *);
extern void print_wireless_status(void);

/* llp.c: link layer profile handling */
extern void initialize_llp(void);
extern void llp_parse_config(void);
extern void llp_add_file(const llp_t *);
extern llp_t *llp_add(const char *);
extern void llp_delete(llp_t *);
extern llp_t *llp_lookup(const char *);
extern llp_t *llp_high_pri(llp_t *, llp_t *);
extern llp_t *llp_best_avail(void);
extern void llp_swap(llp_t *, libnwam_diag_cause_t);
extern char *llp_prnm(llp_t *);
extern void llp_write_changed_priority(llp_t *);
extern int set_llp_priority(const char *, int);
extern int set_locked_llp(const char *);
extern llp_t *get_llp_list(size_t *, uint_t *, char *, char *);
extern void llp_reselect(void);
extern void llp_get_name_and_type(char *, size_t, libnwam_interface_type_t *);
extern libnwam_ipv4src_t llp_get_ipv4src(const char *);
extern void print_llp_status(void);

/* state_machine.c: state machine handling */
extern void state_machine(struct np_event *);
extern void cleanup(void);

/* util.c: utility & ipc functions */
extern void dprintf(const char *, ...);
extern uint64_t get_ifflags(const char *, sa_family_t);
extern void zero_out_v4addr(const char *);
extern int start_childv(const char *, char const * const *);
extern int start_child(const char *, ...);
extern void start_timer(uint32_t,  uint32_t);
extern void lookup_zonename(char *, size_t);

#endif /* _FUNCTIONS_H */
