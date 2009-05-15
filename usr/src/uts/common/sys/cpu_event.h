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
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#ifndef _SYS_CPU_EVENT_H
#define	_SYS_CPU_EVENT_H
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 * CPU idle notification callbacks are divided into three priority classes:
 *      1. Statically assigned high priority callbacks.
 *      2. Dynamically allocated normal priority callbacks.
 *      3. Statically assigned low priority callbacks.
 *
 * All registered callbacks will be called in priority order from high
 * to low just before CPU enters hardware idle state and from low to
 * high just after CPU wakes from idle state.
 *
 * The high and low priority classes are designed to support hardware
 * ordering requirements. A dynamically assigned priority allows the
 * framework to choose the order in which the callback is processed.
 * If a callback has no dependency on other callbacks, it should use
 * dynamic priority to avoid priority conflicts.
 *
 * Note that the priority doesn't describe how important a callback
 * is, but just the order in which they are processed.  If a callback
 * needs processing early in the idle notification cycle, it should
 * have a higher priority.  If it needs to be at the end, or early on
 * the exit, then it should have a lower priority.
 */

#define	CPU_IDLE_CB_PRIO_LOW_BASE	0x20000000U
#define	CPU_IDLE_CB_PRIO_DYN_BASE	0x40000000U
#define	CPU_IDLE_CB_PRIO_HIGH_BASE	0x40000001U
#define	CPU_IDLE_CB_PRIO_RESV_BASE	0x80000000U

/*
 * Indicating dynamic priority to cpu_idle_{un}register_callback().
 */
#define	CPU_IDLE_CB_PRIO_DYNAMIC	CPU_IDLE_CB_PRIO_DYN_BASE
/* Priority assigned to dtrace probe callback. */
#define	CPU_IDLE_CB_PRIO_DTRACE		(CPU_IDLE_CB_PRIO_LOW_BASE + 0xC000000)


#ifdef	__x86
/* Priority assigned to TLB flush callback. */
#define	CPU_IDLE_CB_PRIO_TLB		(CPU_IDLE_CB_PRIO_LOW_BASE + 0x100000)
#endif

/* Name of properties supported by CPU idle notification. */
#define	CPU_IDLE_PROP_IDLE_STATE	"idle-state"
#define	CPU_IDLE_PROP_ENTER_TIMESTAMP	"enter-ts"
#define	CPU_IDLE_PROP_EXIT_TIMESTAMP	"exit-ts"
#define	CPU_IDLE_PROP_LAST_IDLE_TIME	"last-idle-time"
#define	CPU_IDLE_PROP_LAST_BUSY_TIME	"last-busy-time"
#define	CPU_IDLE_PROP_TOTAL_IDLE_TIME	"total-idle-time"
#define	CPU_IDLE_PROP_TOTAL_BUSY_TIME	"total-busy-time"
#define	CPU_IDLE_PROP_INTERRUPT_COUNT	"interupt-count"

/*
 * sizeof(cpu_idle_prop_value_t) should be power of 2 to align on cache line.
 */
typedef union cpu_idle_prop_value {
	intptr_t			cipv_intptr;
	uint32_t			cipv_uint32;
	uint64_t			cipv_uint64;
	hrtime_t			cipv_hrtime;
} cpu_idle_prop_value_t;

typedef enum cpu_idle_prop_type {
	CPU_IDLE_PROP_TYPE_INTPTR,
	CPU_IDLE_PROP_TYPE_UINT32,
	CPU_IDLE_PROP_TYPE_UINT64,
	CPU_IDLE_PROP_TYPE_HRTIME,
} cpu_idle_prop_type_t;

typedef void *cpu_idle_callback_handle_t;
typedef void *cpu_idle_callback_context_t;
typedef void *cpu_idle_prop_handle_t;

/*
 * Function prototype for checking CPU wakeup events.
 * If CPU has already been awakened, check_wakeup callback should call
 * cpu_idle_exit() to notify CPU idle framework if it has been called yet.
 */
typedef void (* cpu_idle_check_wakeup_t)(void *arg);

/*
 * Function prototype for entering idle state notification callback.
 * Callback for entering idle state notification must obey all constraints
 * which apply to idle thread because it will be called in idle thread context.
 * The callback will be called with interrupt disabled. The callback may enable
 * interrupt if it can cooperate with corresponding idle_exit callback to
 * handle interrupt happening after enabling interrupt. If idle_enter callback
 * enables interrupt, the corresponding idle_exit callback may be called before
 * returning from idle_enter callback.
 */
typedef void (* cpu_idle_enter_cbfn_t)(void *arg,
    cpu_idle_callback_context_t ctx,
    cpu_idle_check_wakeup_t check_func, void *check_arg);

/*
 * Function prototype for exiting idle state notification callback.
 * Callback for exiting idle state notification will be called in idle thread
 * context or interrupt context with interrupt disabled.
 * There is a flag to distinguish the calling context.
 * The callback must not try to enable interrupts.
 */
typedef void (* cpu_idle_exit_cbfn_t)(void *arg,
    cpu_idle_callback_context_t ctx, int flag);

#define	CPU_IDLE_CB_FLAG_INTR	0x1	/* Called in interrupt context. */
#define	CPU_IDLE_CB_FLAG_IDLE	0x2	/* Called in idle thread context. */

typedef struct cpu_idle_callback {
	int				version;
	cpu_idle_enter_cbfn_t		idle_enter;
	cpu_idle_exit_cbfn_t		idle_exit;
} cpu_idle_callback_t;

#define	CPU_IDLE_CALLBACK_VER0		0
#define	CPU_IDLE_CALLBACK_VERS		CPU_IDLE_CALLBACK_VER0

/*
 * Register a callback to be called when CPU idle state changes.
 * All registered callbacks will be called in priority order from high to low
 * when CPU enters idle state and from low to high when CPU leaves idle state.
 * If CPU is predicted to sleep for a short time or be under heavy load,
 * framework may skip calling registered callbacks when idle state changes to
 * avoid overhead and reduce performance penalties.
 * It's guaranteed that each exiting notification will be paired with each
 * entering notification.
 * Return zero on success and error code on failure.
 * N.B.: this interface shouldn't be called from following conditions:
 *       1) from callback.
 */
extern int cpu_idle_register_callback(uint_t prio, cpu_idle_callback_t *cbp,
    void *arg, cpu_idle_callback_handle_t *hdlp);

/*
 * Un-register a registered callback.
 * Return zero on success and error code on failure.
 * N.B.: this interface shouldn't be called from following cases:
 *       1) from callback.
 */
extern int cpu_idle_unregister_callback(cpu_idle_callback_handle_t hdl);

/*
 * Called by CPU idle handler to notify entering idle state.
 * It should be called with interrupt disabled.
 * state: platform specific information of idle state to enter.
 *        On x86, it's CPU C state.
 * Idle thread should cancel entering hardware idle state if cpu_idle_enter
 * returns non-zero value.
 */
extern int cpu_idle_enter(int state, int flag,
    cpu_idle_check_wakeup_t check_func, void *check_arg);

/*
 * Called by CPU idle handler to notify exiting idle state.
 * It should be called with interrupt disabled.
 */
extern void cpu_idle_exit(int flag);

/*
 * Get CPU idle notification context corresponding to current CPU.
 */
extern cpu_idle_callback_context_t cpu_idle_get_context(void);

/*
 * Prototype of function called to update property value on demand.
 * The callback should update property value corresponding to current CPU.
 */
typedef int (* cpu_idle_prop_update_t)(void *arg, uint64_t seqnum,
    cpu_idle_prop_value_t *valp);

/*
 * Create a property with name and type.
 * If parameter update is not NULL, it will be called on demand to update
 * value of property corresponding to current CPU.
 * If parameter update is NULL, provider should call cpu_idle_property_set
 * to update property value for each CPU.
 * Return zero on success with handle stored in hdlp, otherwise error code.
 */
extern int cpu_idle_prop_create_property(const char *name,
    cpu_idle_prop_type_t type, cpu_idle_prop_update_t update, void *arg,
    cpu_idle_prop_handle_t *hdlp);

/*
 * Destroy property corresponding to hdl.
 * Return zero on success, otherwise error code.
 */
extern int cpu_idle_prop_destroy_property(cpu_idle_prop_handle_t hdl);

/*
 * Create handle for property with name 'name'.
 * Return zero on success with handle stored in hdlp, otherwise error code.
 */
extern int cpu_idle_prop_create_handle(const char *name,
    cpu_idle_prop_handle_t *hdlp);

/*
 * Destroy property handle.
 * Return zero on success, otherwise error code.
 */
extern int cpu_idle_prop_destroy_handle(cpu_idle_prop_handle_t hdl);

/*
 * CPU idle property manipulation functions.
 * All cpu_idle_prop_get/set_xxx functions with argument ctx should only be used
 * to manipulate properties associated with current CPU.
 * Context ctx shouldn't be passed to other CPUs to manipulate properties.
 */
extern cpu_idle_prop_type_t cpu_idle_prop_get_type(cpu_idle_prop_handle_t hdl);
extern const char *cpu_idle_prop_get_name(cpu_idle_prop_handle_t hdl);
extern int cpu_idle_prop_get_value(cpu_idle_prop_handle_t hdl,
    cpu_idle_callback_context_t ctx, cpu_idle_prop_value_t *valp);
extern uint32_t cpu_idle_prop_get_uint32(cpu_idle_prop_handle_t hdl,
    cpu_idle_callback_context_t ctx);
extern uint64_t cpu_idle_prop_get_uint64(cpu_idle_prop_handle_t hdl,
    cpu_idle_callback_context_t ctx);
extern intptr_t cpu_idle_prop_get_intptr(cpu_idle_prop_handle_t hdl,
    cpu_idle_callback_context_t ctx);
extern hrtime_t cpu_idle_prop_get_hrtime(cpu_idle_prop_handle_t hdl,
    cpu_idle_callback_context_t ctx);
extern void cpu_idle_prop_set_value(cpu_idle_prop_handle_t hdl,
    cpu_idle_callback_context_t ctx, cpu_idle_prop_value_t val);
extern void cpu_idle_prop_set_all(cpu_idle_prop_handle_t hdl,
    cpu_idle_prop_value_t val);

extern uint_t cpu_idle_get_cpu_state(cpu_t *cp);

extern void cpu_event_init(void);
extern void cpu_event_init_cpu(cpu_t *cp);
extern void cpu_event_fini_cpu(cpu_t *cp);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CPU_EVENT_H */
