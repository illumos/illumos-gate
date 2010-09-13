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
 * Copyright 2000-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FCODE_PROTO_H
#define	_FCODE_PROTO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	FNPROTO(x)	void x(fcode_env_t *)

FNPROTO(bdo);
FNPROTO(bqdo);

FNPROTO(literal);
void branch_common(fcode_env_t *, short, fstack_t, int);
FNPROTO(zero);
FNPROTO(bloop);
FNPROTO(bplusloop);
FNPROTO(loop_i);
FNPROTO(loop_j);
FNPROTO(bleave);
FNPROTO(execute);
FNPROTO(add);
FNPROTO(subtract);
FNPROTO(multiply);
FNPROTO(slash_mod);
FNPROTO(uslash_mod);
FNPROTO(divide);
FNPROTO(mod);
FNPROTO(and);
FNPROTO(or);
FNPROTO(xor);
FNPROTO(invert);
FNPROTO(lshift);
FNPROTO(rshift);
FNPROTO(rshifta);
FNPROTO(negate);
FNPROTO(f_abs);
FNPROTO(f_min);
FNPROTO(f_max);
FNPROTO(to_r);
FNPROTO(from_r);
FNPROTO(rfetch);
FNPROTO(f_exit);
FNPROTO(zero_equals);
FNPROTO(zero_not_equals);
FNPROTO(zero_less);
FNPROTO(zero_less_equals);
FNPROTO(zero_greater);
FNPROTO(zero_greater_equals);
FNPROTO(less);
FNPROTO(greater);
FNPROTO(equals);
FNPROTO(not_equals);
FNPROTO(unsign_greater);
FNPROTO(unsign_less_equals);
FNPROTO(unsign_less);
FNPROTO(unsign_greater_equals);
FNPROTO(greater_equals);
FNPROTO(less_equals);
FNPROTO(between);
FNPROTO(within);
FNPROTO(drop);
FNPROTO(f_dup);
FNPROTO(over);
FNPROTO(swap);
FNPROTO(rot);
FNPROTO(minus_rot);
FNPROTO(tuck);
FNPROTO(nip);
FNPROTO(pick);
FNPROTO(roll);
FNPROTO(qdup);
FNPROTO(depth);
FNPROTO(two_drop);
FNPROTO(two_dup);
FNPROTO(two_over);
FNPROTO(two_swap);
FNPROTO(two_rot);
FNPROTO(two_slash);
FNPROTO(utwo_slash);
FNPROTO(two_times);
FNPROTO(slash_c);
FNPROTO(slash_w);
FNPROTO(slash_l);
FNPROTO(slash_n);
FNPROTO(ca_plus);
FNPROTO(wa_plus);
FNPROTO(la_plus);
FNPROTO(na_plus);
FNPROTO(c1_plus);
FNPROTO(w1_plus);
FNPROTO(l1_plus);
FNPROTO(cell_plus);
FNPROTO(do_chars);
FNPROTO(slash_w_times);
FNPROTO(slash_l_times);
FNPROTO(cells);
FNPROTO(do_off);
FNPROTO(do_on);
FNPROTO(fetch);
FNPROTO(lfetch);
FNPROTO(wfetch);
FNPROTO(swfetch);
FNPROTO(cfetch);
FNPROTO(store);
FNPROTO(lstore);
FNPROTO(wstore);
FNPROTO(cstore);

FNPROTO(noop);
FNPROTO(lwsplit);
FNPROTO(wljoin);
FNPROTO(lbsplit);
FNPROTO(bljoin);
FNPROTO(wbflip);
FNPROTO(upper_case);
FNPROTO(lower_case);
FNPROTO(pack_str);
FNPROTO(count_str);
FNPROTO(to_body);
FNPROTO(to_acf);
FNPROTO(bcase);
FNPROTO(bendcase);

FNPROTO(span);

FNPROTO(expect);

FNPROTO(emit);
FNPROTO(type);

FNPROTO(fc_crlf);

FNPROTO(base);
FNPROTO(dollar_number);
FNPROTO(digit);

FNPROTO(do_constant);
FNPROTO(do_defer);
FNPROTO(do_crash);
FNPROTO(do_field);
FNPROTO(idefer_exec);

FNPROTO(set_args);

void make_common_access(fcode_env_t *, char *, int, int, int,
    void (*acf_i)(fcode_env_t *), void (*acf_s)(fcode_env_t *),
    void (*set_a)(fcode_env_t *, int));

FNPROTO(do_create);

FNPROTO(instance);
FNPROTO(semi);

FNPROTO(dollar_find);
acf_t voc_find(fcode_env_t *env);

FNPROTO(evaluate);

FNPROTO(ccomma);
FNPROTO(wcomma);
FNPROTO(lcomma);
FNPROTO(comma);
FNPROTO(state);
FNPROTO(compile_comma);

FNPROTO(here);
FNPROTO(aligned);
FNPROTO(wbsplit);
FNPROTO(bwjoin);
FNPROTO(bmark);
FNPROTO(bresolve);

FNPROTO(f_error);
FNPROTO(fc_unimplemented);
FNPROTO(fc_obsolete);
FNPROTO(fc_historical);

FNPROTO(myspace);
FNPROTO(property);
FNPROTO(encode_int);
FNPROTO(encode_plus);
FNPROTO(encode_phys);
FNPROTO(encode_string);
FNPROTO(encode_bytes);
FNPROTO(model_prop);
FNPROTO(device_type);
FNPROTO(new_device);

FNPROTO(finish_device);

FNPROTO(device_name);

FNPROTO(lwflip);
FNPROTO(lbflip);

FNPROTO(child_node);
FNPROTO(peer_node);

FNPROTO(byte_load);

uchar_t  next_bytecode(fcode_env_t *);
ushort_t get_short(fcode_env_t *);
uint_t   get_int(fcode_env_t *);

char *get_name(long *);
FNPROTO(words);
void header(fcode_env_t *, char *, int, flag_t);
void do_code(fcode_env_t *, int, char *, FNPROTO((*)));
void push_string(fcode_env_t *, char *, int);

FNPROTO(verify_usage);
FNPROTO(dump_dictionary);
void print_stack_element(fcode_env_t *, fstack_t);
void dump_data_stack(fcode_env_t *, int);
void dump_return_stack(fcode_env_t *, int);
char *acf_lookup(fcode_env_t *, acf_t);
char *acf_to_name(fcode_env_t *, acf_t);
int within_dictionary(fcode_env_t *, void *);
char *acf_backup_search(fcode_env_t *, acf_t);
void dump_forth_environment(fcode_env_t *);
void forth_abort(fcode_env_t *, char *, ...);
void forth_perror(fcode_env_t *, char *, ...);
void return_to_interact(fcode_env_t *);
char *get_path(fcode_env_t *, device_t *);
char *search_for_fcode_file(fcode_env_t *, char *);
int current_debug_state(fcode_env_t *);
int debug_flags_to_mask(char *);
int do_exec_debug(fcode_env_t *, void *);
int name_is_debugged(fcode_env_t *, char *);
prop_t *find_property(device_t *, char *);
void buffer_init(fcode_env_t *env);
void check_for_debug_entry(fcode_env_t *);
void check_for_debug_exit(fcode_env_t *);
void check_semi_debug_exit(fcode_env_t *);
void check_vitals(fcode_env_t *);
void clear_debug_state(fcode_env_t *, int);
void debug_set_level(fcode_env_t *, int);
void define_actions(fcode_env_t *env, int n, token_t *array);
void do_alias(fcode_env_t *);
void do_bbranch(fcode_env_t *env);
void do_bdo(fcode_env_t *);
void do_bleave(fcode_env_t *env);
void do_bloop(fcode_env_t *env);
void do_bofbranch(fcode_env_t *env);
void do_bploop(fcode_env_t *env);
void do_bqbranch(fcode_env_t *env);
void do_bqdo(fcode_env_t *env);
void do_creator(fcode_env_t *env);
void do_default_action(fcode_env_t *env);
void do_emit(fcode_env_t *, uchar_t);
void do_literal(fcode_env_t *);
void dump_comma(fcode_env_t *, char *);
void dump_words(fcode_env_t *);
void fevaluate(fcode_env_t *);
void ibuffer_init(fcode_env_t *env);
void install_builtin_nodes(fcode_env_t *);
void install_does(fcode_env_t *);
void install_openprom_nodes(fcode_env_t *);
void install_package_nodes(fcode_env_t *);
void internal_env_addr(fcode_env_t *env);
void internal_env_fetch(fcode_env_t *env);
void internal_env_store(fcode_env_t *env);
void key(fcode_env_t *);
void keyquestion(fcode_env_t *);
void make_a_node(fcode_env_t *, char *, int);
void output_data_stack(fcode_env_t *, int);
void output_return_stack(fcode_env_t *, int, int);
void output_step_message(fcode_env_t *);
void output_vitals(fcode_env_t *);
void print_property(fcode_env_t *, prop_t *, char *);
void read_line(fcode_env_t *);
void run_daemon(fcode_env_t *);
void run_fcode_from_file(fcode_env_t *, char *, int);
void tick_literal(fcode_env_t *);
void unbug(fcode_env_t *);
void xbflip(fcode_env_t *);
void xfetch(fcode_env_t *);
void xlflip(fcode_env_t *);
void xstore(fcode_env_t *);
void expose_acf(fcode_env_t *, char *);

FNPROTO(do_semi);
FNPROTO(do_colon);
FNPROTO(do_next);
void do_run(fcode_env_t *, int);

void *safe_malloc(size_t, char *, int);
void *safe_realloc(void *, size_t, char *, int);
char *safe_strdup(char *, char *, int);
void safe_free(void *, char *, int);

FNPROTO(do_forth);
FNPROTO(do_current);
FNPROTO(do_context);
FNPROTO(do_definitions);
FNPROTO(do_interact);
FNPROTO(do_resume);
FNPROTO(do_vocab);
FNPROTO(create);
FNPROTO(colon);
FNPROTO(does);
FNPROTO(recursive);
FNPROTO(do_if);
FNPROTO(do_else);
FNPROTO(do_then);
FNPROTO(parse_word);
FNPROTO(do_quote);
FNPROTO(run_quote);

FNPROTO(do_order);
FNPROTO(do_also);
FNPROTO(do_previous);

FNPROTO(find_package);
FNPROTO(open_package);
FNPROTO(close_package);
FNPROTO(find_method);
FNPROTO(dollar_call_parent);
FNPROTO(my_parent);
FNPROTO(my_unit);
FNPROTO(ihandle_to_phandle);
FNPROTO(dollar_call_method);
FNPROTO(dollar_open_package);

FNPROTO(call_environment_method);

FNPROTO(f_abort);
FNPROTO(catch);
FNPROTO(throw);

FNPROTO(get_my_property);
FNPROTO(decode_int);
FNPROTO(decode_string);
FNPROTO(get_inherited_prop);
FNPROTO(delete_property);
FNPROTO(get_package_property);
void get_environment_property(fcode_env_t *env, int);

FNPROTO(root_node);
FNPROTO(current_device);
FNPROTO(dot_properties);
FNPROTO(pwd);
FNPROTO(do_ls);
FNPROTO(do_cd);
FNPROTO(do_select_dev);
FNPROTO(do_unselect_dev);
FNPROTO(device_end);
FNPROTO(value);
FNPROTO(buffer_colon);
FNPROTO(variable);
FNPROTO(constant);
FNPROTO(actions);
FNPROTO(use_actions);
FNPROTO(action_colon);
FNPROTO(perform_action);
FNPROTO(do_tick);
FNPROTO(bracket_tick);
FNPROTO(defer);
FNPROTO(bye);
FNPROTO(dump_device);
FNPROTO(dump_instance);
FNPROTO(compile_string);
FNPROTO(parse_two_int);

token_t *alloc_instance_data(fcode_env_t *, int, int, int *);
FNPROTO(fetch_instance_data);
FNPROTO(set_instance_data);
FNPROTO(address_instance_data);
FNPROTO(instance_variable);
FNPROTO(decode_phys);

void install_actions(fcode_env_t *env, token_t *table);
void set_value_actions(fcode_env_t *env, int);
void set_internal_value_actions(fcode_env_t *env);
void set_buffer_actions(fcode_env_t *env, int);

void system_message(fcode_env_t *env, char *msg);

void check_interrupt(void);
void complete_interrupt(void);

FNPROTO(do_set_action);
void push_a_string(fcode_env_t *, char *);
char *pop_a_string(fcode_env_t *, int *);
char *pop_a_duped_string(fcode_env_t *, int *);
char *parse_a_string(fcode_env_t *, int *);
void push_double(fcode_env_t *, dforth_t);
dforth_t pop_double(fcode_env_t *);
dforth_t peek_double(fcode_env_t *);
void push_xforth(fcode_env_t *, xforth_t);
xforth_t pop_xforth(fcode_env_t *);
xforth_t peek_xforth(fcode_env_t *);
void create_prop(fcode_env_t *, char *);
void create_int_prop(fcode_env_t *, char *, int);
void create_string_prop(fcode_env_t *, char *, char *);
void make_builtin_hooks(fcode_env_t *, char *);
fstack_t mapping_to_mcookie(uint64_t, size_t, uint64_t, size_t);
void delete_mapping(fstack_t);
int is_mcookie(fstack_t);
uint64_t mcookie_to_addr(fstack_t);
fstack_t mcookie_to_rlen(fstack_t);
fstack_t mcookie_to_rvirt(fstack_t);
void set_here(fcode_env_t *, uchar_t *, char *);
int call_my_parent(fcode_env_t *, char *);
FILE *get_dump_fd(fcode_env_t *);

void load_file(fcode_env_t *);
void token_roundup(fcode_env_t *, char *);

#ifdef DEBUG
void do_fclib_trace(fcode_env_t *, void *);
int do_fclib_step(fcode_env_t *);
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _FCODE_PROTO_H */
