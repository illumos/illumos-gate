#ifndef ECORE_ERASE
#ifdef __LINUX

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/crc32.h>
#include <linux/etherdevice.h>

#define ECORE_ALIGN(x, a) ALIGN(x, a)
#endif

/* Always define ECORE_OOO for VBD */
#define ECORE_OOO

#include "bcmtype.h"
#include "utils.h"
#include "lm5710.h"
#include "ecore_sp_verbs.h"
#include "command.h"
#include "debug.h"
#include "ecore_common.h"

/************************ Debug print macros **********************************/
#if !defined(UEFI) && defined(DBG)
#define ECORE_MSG(pdev, m, ...) \
	DbgMessage(pdev, WARNi, m, ##__VA_ARGS__)
#else
#define ECORE_MSG
#endif

/************************ Error prints ****************************************/
#if !defined(UEFI) && defined(DBG)
#define ECORE_ERR(str, ...) DbgMessage(pdev, FATAL, str, ##__VA_ARGS__)
#else
#define ECORE_ERR
#endif


/***********************  ECORE WRAPPER MACROS ********************************/

#define ECORE_RET_PENDING(pending_bit, pending) \
	(ECORE_TEST_BIT(pending_bit, pending) ? ECORE_PENDING : ECORE_SUCCESS)

#define ECORE_ZALLOC(_size, _flags, _pdev) mm_rt_zalloc_mem(_pdev, _size)
#define ECORE_CALLOC(_len, _size, _flags, _pdev) mm_rt_zalloc_mem(_pdev, _len * _size)
#define ECORE_FREE(_pdev, _buf, _size) mm_rt_free_mem(_pdev, _buf, _size, 0)

/*
 *  Ecore implementation of set/get flag
 *  (differs from VBD set_flags, get_flags)
 */
#define ECORE_SET_FLAG(value, mask, flag) \
	do {\
		(value) &= ~(mask);\
		(value) |= ((flag) << (mask##_SHIFT));\
	} while (0)

#define ECORE_GET_FLAG(value, mask) \
	(((value) &= (mask)) >> (mask##_SHIFT))

#define ecore_sp_post(_pdev, _cmd , _cid, _data, _con_type) \
	lm_sq_post(_pdev, _cid, (u8)(_cmd), CMD_PRIORITY_NORMAL, _con_type, \
	_data)

#define ECORE_SET_CTX_VALIDATION(_pdev, _cxt, _cid) \
	lm_set_cdu_validation_data(_pdev, _cid, FALSE) /* context? type? */
/************************ TODO for LM people!!! *******************************/
#define ECORE_TODO_UPDATE_COALESCE_SB_INDEX(a1, a2, a3, a4, a5)
#define ECORE_TODO_LINK_REPORT(pdev)
#define ECORE_TODO_FW_COMMAND(_pdev, _drv_msg_code, _val) (-1)

/************************ Lists ***********************************************/
#define ECORE_LIST_FOR_EACH_ENTRY(pos, _head, _link, cast) \
	for (pos = (cast *)d_list_peek_head(_head); \
	     pos; \
	     pos = (cast *)d_list_next_entry(&pos->_link))

/**
 * ECORE_LIST_FOR_EACH_ENTRY_SAFE - iterate over list of given type
 * @pos:        the type * to use as a loop cursor.
 * @n:          another type * to use as temporary storage
 * @head:       the head for your list.
 * @member:     the name of the list_struct within the struct.
 *
 * iterate over list of given type safe against removal of list entry
 */
#define ECORE_LIST_FOR_EACH_ENTRY_SAFE(pos, n, head, member, cast)   \
	 for (pos = (cast *)d_list_peek_head(head), \
	      n = (pos) ? (cast *)d_list_next_entry(&pos->member) : NULL; \
	      pos != NULL;  \
	      pos = (cast *)n, \
	      n = (pos) ? (cast *)d_list_next_entry(&pos->member) : NULL)

#define ECORE_LIST_IS_LAST(_link, _list)                (_link == (_list)->tail)

#define ECORE_LIST_IS_EMPTY(head)                       \
	d_list_is_empty(head)

#define ECORE_LIST_FIRST_ENTRY(head, cast, link)	\
	(cast *)d_list_peek_head(head)

#define ECORE_LIST_NEXT(pos, link, cast)	\
	(cast *)d_list_next_entry(&((pos)->link))

#define ECORE_LIST_INIT(head)				\
do { \
	d_list_clear(head); \
} while (0)

#define ECORE_LIST_PUSH_TAIL(link, head)		\
do { \
	d_list_push_tail(head, link); \
} while (0)

#define ECORE_LIST_PUSH_HEAD(link, head)		\
do { \
	d_list_push_head(head, link); \
} while (0)

#define ECORE_LIST_REMOVE_ENTRY(link, head)		\
do { \
	d_list_remove_entry(head, link); \
} while (0)

#define ECORE_LIST_SPLICE_INIT(new_head, head) \
do { \
	d_list_add_head(head, new_head); \
	d_list_clear(new_head); \
} while (0)

static __inline u32_t ecore_crc32_le(u32_t seed, u8_t *mac, u32_t len)
{
	u32_t packet_buf[2] = {0};

	memcpy(((u8_t *)(&packet_buf[0]))+2, &mac[0], 2);
	memcpy(&packet_buf[1], &mac[2], 4);
	return SWAP_BYTES32(calc_crc32((u8_t *)packet_buf, 8, seed, 0));
}

/************************ Per compilation target ******************************/
#ifdef __LINUX

#define ECORE_UNLIKELY	unlikely
#define ECORE_LIKELY	likely

#define ecore_atomic_read		mm_atomic_read
#define ecore_atomic_cmpxchg		mm_atomic_cmpxchg
#define ecore_atomic_set(a, v)		mm_atomic_set((u32_t *)(a), v)
#define smp_mb__before_atomic() mm_barrier()
#define smp_mb__after_atomic()  mm_barrier()

/* Other */
#define ECORE_IS_VALID_ETHER_ADDR(_mac)               is_valid_ether_addr(_mac)
#define ECORE_SET_WAIT_COUNT(_cnt)
#define ECORE_SET_WAIT_DELAY_US(_cnt, _delay_us)

/* Mutex related */
#define ECORE_MUTEX_INIT(_mutex)	mutex_init(_mutex)
#define ECORE_MUTEX_LOCK(_mutex)	mutex_lock(_mutex)
#define ECORE_MUTEX_UNLOCK(_mutex)	mutex_unlock(_mutex)

#define ECORE_MIGHT_SLEEP() ediag_might_sleep()
#define ECORE_TEST_BIT(bit, var)  test_bit(bit, var)
#define ECORE_TEST_AND_CLEAR_BIT(bit, var) test_and_clear_bit(bit, var)

#else /* ! LINUX */

typedef u16 __le16;

#define ecore_atomic_read		mm_atomic_read
#define ecore_atomic_cmpxchg		mm_atomic_cmpxchg
#define ecore_atomic_set(a, val)	mm_atomic_set((u32_t *)(a), val)

#define ECORE_UNLIKELY(x)	(x)
#define ECORE_LIKELY(x)		(x)
#define BUG() DbgBreakMsg("Bug")
#define smp_mb()                   mm_barrier()
#define smp_mb__before_atomic() mm_barrier()
#define smp_mb__after_atomic()  mm_barrier()
#define mb()                       mm_barrier()
#define wmb()                      mm_barrier()
#define mmiowb()		   mm_barrier()

#define ECORE_MIGHT_SLEEP() /* IRQL_PASSIVE_CODE() */

/* Mutex related */
#define ECORE_MUTEX_INIT(_mutex)
#define ECORE_MUTEX_LOCK(_mutex)
#define ECORE_MUTEX_UNLOCK(_mutex)

/* Atomic Bit Manipulation */
#define ECORE_TEST_BIT(_bit, _var) \
	(mm_atomic_long_read(_var) & (1 << (_bit)))

/* Other */
#define ECORE_IS_VALID_ETHER_ADDR(_mac)         TRUE
#define ECORE_SET_WAIT_DELAY_US(_cnt, _delay_us) \
do { \
	_delay_us = (_cnt >= 2360) ? 100 : 25000; \
} while (0)

/*
 * In VBD We'll wait 10,000 times 100us (1 second) +
 * 2360 times 25000us (59sec) = total 60 sec
 * (Winodws only note) the 25000 wait will cause
 * wait to be without CPU stall (look in win_util.c)
 */
#define ECORE_SET_WAIT_COUNT(_cnt) \
do { \
	_cnt = 10000 + 2360; \
} while (0)

static __inline BOOL ECORE_TEST_AND_CLEAR_BIT(int bit, unsigned long *vec)
{
	BOOL set = ECORE_TEST_BIT(bit, vec);
	ECORE_CLEAR_BIT(bit, vec);

	return set;
}

#endif /* END if "per LM target type" */

/* Spin lock related */
#define ECORE_SPIN_LOCK_INIT(_spin, _pdev)	mm_init_lock(_pdev, _spin)
#define ECORE_SPIN_LOCK_BH(_spin)		mm_acquire_lock(_spin)
#define ECORE_SPIN_UNLOCK_BH(_spin)		mm_release_lock(_spin)

#endif /* not ECORE_ERASE */
#if defined(__FreeBSD__) && !defined(NOT_LINUX)
#include "bxe.h"
#include "ecore_init.h"
#elif !defined(EDIAG)
#ifdef ECORE_ERASE
#include <linux/version.h>
#include <linux/module.h>
#include <linux/crc32.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#if (LINUX_VERSION_CODE >= 0x02061b) && !defined(BNX2X_DRIVER_DISK) && !defined(__VMKLNX__) /* BNX2X_UPSTREAM */
#include <linux/crc32c.h>
#endif
#include "bnx2x.h"
#include "bnx2x_cmn.h"
#include "bnx2x_sp.h"

#define ECORE_MAX_EMUL_MULTI		16
#endif
#endif

/**** Exe Queue interfaces ****/

/**
 * ecore_exe_queue_init - init the Exe Queue object
 *
 * @o:		pointer to the object
 * @exe_len:	length
 * @owner:	pointer to the owner
 * @validate:	validate function pointer
 * @optimize:	optimize function pointer
 * @exec:	execute function pointer
 * @get:	get function pointer
 */
static INLINE void ecore_exe_queue_init(struct _lm_device_t *pdev,
					struct ecore_exe_queue_obj *o,
					int exe_len,
					union ecore_qable_obj *owner,
					exe_q_validate validate,
					exe_q_remove remove,
					exe_q_optimize optimize,
					exe_q_execute exec,
					exe_q_get get)
{
	mm_memset(o, 0, sizeof(*o));

	ECORE_LIST_INIT(&o->exe_queue);
	ECORE_LIST_INIT(&o->pending_comp);

	ECORE_SPIN_LOCK_INIT(&o->lock, pdev);

	o->exe_chunk_len = exe_len;
	o->owner         = owner;

	/* Owner specific callbacks */
	o->validate      = validate;
	o->remove        = remove;
	o->optimize      = optimize;
	o->execute       = exec;
	o->get           = get;

	ECORE_MSG(pdev, "Setup the execution queue with the chunk length of %d\n",
		  exe_len);
}

static INLINE void ecore_exe_queue_free_elem(struct _lm_device_t *pdev,
					     struct ecore_exeq_elem *elem)
{
	ECORE_MSG(pdev, "Deleting an exe_queue element\n");
	ECORE_FREE(pdev, elem, sizeof(*elem));
}

static INLINE int ecore_exe_queue_length(struct ecore_exe_queue_obj *o)
{
	struct ecore_exeq_elem *elem;
	int cnt = 0;

#ifdef ECORE_ERASE
	spin_lock_bh(&o->lock);
#endif

	ECORE_LIST_FOR_EACH_ENTRY(elem, &o->exe_queue, link,
				  struct ecore_exeq_elem)
		cnt++;

#ifdef ECORE_ERASE
	spin_unlock_bh(&o->lock);
#endif

	return cnt;
}

/**
 * ecore_exe_queue_add - add a new element to the execution queue
 *
 * @pdev:	driver handle
 * @o:		queue
 * @cmd:	new command to add
 * @restore:	true - do not optimize the command
 *
 * If the element is optimized or is illegal, frees it.
 */
static INLINE int ecore_exe_queue_add(struct _lm_device_t *pdev,
				      struct ecore_exe_queue_obj *o,
				      struct ecore_exeq_elem *elem,
				      BOOL restore)
{
	int rc;

	ECORE_SPIN_LOCK_BH(&o->lock);

	if (!restore) {
		/* Try to cancel this element queue */
		rc = o->optimize(pdev, o->owner, elem);
		if (rc)
			goto free_and_exit;

		/* Check if this request is ok */
		rc = o->validate(pdev, o->owner, elem);
		if (rc) {
			ECORE_MSG(pdev, "Preamble failed: %d\n", rc);
			goto free_and_exit;
		}
	}

	/* If so, add it to the execution queue */
	ECORE_LIST_PUSH_TAIL(&elem->link, &o->exe_queue);

	ECORE_SPIN_UNLOCK_BH(&o->lock);

	return ECORE_SUCCESS;

free_and_exit:
	ecore_exe_queue_free_elem(pdev, elem);

	ECORE_SPIN_UNLOCK_BH(&o->lock);

	return rc;
}

static INLINE void __ecore_exe_queue_reset_pending(
	struct _lm_device_t *pdev,
	struct ecore_exe_queue_obj *o)
{
	struct ecore_exeq_elem *elem;

	while (!ECORE_LIST_IS_EMPTY(&o->pending_comp)) {
		elem = ECORE_LIST_FIRST_ENTRY(&o->pending_comp,
					      struct ecore_exeq_elem,
					      link);

		ECORE_LIST_REMOVE_ENTRY(&elem->link, &o->pending_comp);
		ecore_exe_queue_free_elem(pdev, elem);
	}
}

/**
 * ecore_exe_queue_step - execute one execution chunk atomically
 *
 * @pdev:		driver handle
 * @o:			queue
 * @ramrod_flags:	flags
 *
 * (Should be called while holding the exe_queue->lock).
 */
static INLINE int ecore_exe_queue_step(struct _lm_device_t *pdev,
				       struct ecore_exe_queue_obj *o,
				       unsigned long *ramrod_flags)
{
	struct ecore_exeq_elem *elem, spacer;
	int cur_len = 0, rc;

	mm_memset(&spacer, 0, sizeof(spacer));

	/* Next step should not be performed until the current is finished,
	 * unless a DRV_CLEAR_ONLY bit is set. In this case we just want to
	 * properly clear object internals without sending any command to the FW
	 * which also implies there won't be any completion to clear the
	 * 'pending' list.
	 */
	if (!ECORE_LIST_IS_EMPTY(&o->pending_comp)) {
		if (ECORE_TEST_BIT(RAMROD_DRV_CLR_ONLY, ramrod_flags)) {
			ECORE_MSG(pdev, "RAMROD_DRV_CLR_ONLY requested: resetting a pending_comp list\n");
			__ecore_exe_queue_reset_pending(pdev, o);
		} else {
			return ECORE_PENDING;
		}
	}

	/* Run through the pending commands list and create a next
	 * execution chunk.
	 */
	while (!ECORE_LIST_IS_EMPTY(&o->exe_queue)) {
		elem = ECORE_LIST_FIRST_ENTRY(&o->exe_queue,
					      struct ecore_exeq_elem,
					      link);
		DbgBreakIf(!elem->cmd_len);

		if (cur_len + elem->cmd_len <= o->exe_chunk_len) {
			cur_len += elem->cmd_len;
			/* Prevent from both lists being empty when moving an
			 * element. This will allow the call of
			 * ecore_exe_queue_empty() without locking.
			 */
			ECORE_LIST_PUSH_TAIL(&spacer.link, &o->pending_comp);
			mb();
			ECORE_LIST_REMOVE_ENTRY(&elem->link, &o->exe_queue);
			ECORE_LIST_PUSH_TAIL(&elem->link, &o->pending_comp);
			ECORE_LIST_REMOVE_ENTRY(&spacer.link, &o->pending_comp);
		} else
			break;
	}

	/* Sanity check */
	if (!cur_len)
		return ECORE_SUCCESS;

	rc = o->execute(pdev, o->owner, &o->pending_comp, ramrod_flags);
	if (rc < 0)
		/* In case of an error return the commands back to the queue
		 *  and reset the pending_comp.
		 */
		ECORE_LIST_SPLICE_INIT(&o->pending_comp, &o->exe_queue);
	else if (!rc)
		/* If zero is returned, means there are no outstanding pending
		 * completions and we may dismiss the pending list.
		 */
		__ecore_exe_queue_reset_pending(pdev, o);

	return rc;
}

static INLINE BOOL ecore_exe_queue_empty(struct ecore_exe_queue_obj *o)
{
	BOOL empty = ECORE_LIST_IS_EMPTY(&o->exe_queue);

	/* Don't reorder!!! */
	mb();

	return empty && ECORE_LIST_IS_EMPTY(&o->pending_comp);
}

static INLINE struct ecore_exeq_elem *ecore_exe_queue_alloc_elem(
	struct _lm_device_t *pdev)
{
	ECORE_MSG(pdev, "Allocating a new exe_queue element\n");
	return ECORE_ZALLOC(sizeof(struct ecore_exeq_elem), GFP_ATOMIC,
			    pdev);
}

/************************ raw_obj functions ***********************************/
static BOOL ecore_raw_check_pending(struct ecore_raw_obj *o)
{
	/*
     * !! converts the value returned by ECORE_TEST_BIT such that it
     * is guaranteed not to be truncated regardless of BOOL definition.
	 *
	 * Note we cannot simply define the function's return value type
     * to match the type returned by ECORE_TEST_BIT, as it varies by
     * platform/implementation.
	 */

	return !!ECORE_TEST_BIT(o->state, o->pstate);
}

static void ecore_raw_clear_pending(struct ecore_raw_obj *o)
{
	smp_mb__before_atomic();
	ECORE_CLEAR_BIT(o->state, o->pstate);
	smp_mb__after_atomic();
}

static void ecore_raw_set_pending(struct ecore_raw_obj *o)
{
	smp_mb__before_atomic();
	ECORE_SET_BIT(o->state, o->pstate);
	smp_mb__after_atomic();
}

/**
 * ecore_state_wait - wait until the given bit(state) is cleared
 *
 * @pdev:	device handle
 * @state:	state which is to be cleared
 * @state_p:	state buffer
 *
 */
static INLINE int ecore_state_wait(struct _lm_device_t *pdev, int state,
				   unsigned long *pstate)
{
	/* can take a while if any port is running */
	int cnt = 5000;

#ifndef ECORE_ERASE
	int delay_us = 1000;

	/* In VBD We'll wait 10,000 times 100us (1 second) +
	* 2360 times 25000us (59sec) = total 60 sec
	* (Winodws only note) the 25000 wait will cause wait
	* to be without CPU stall (look in win_util.c)
	*/
	cnt = 10000 + 2360;
#endif

	if (CHIP_REV_IS_EMUL(pdev))
		cnt *= 20;

	ECORE_MSG(pdev, "waiting for state to become %d\n", state);

	ECORE_MIGHT_SLEEP();
	while (cnt--) {
		if (!ECORE_TEST_BIT(state, pstate)) {
#ifdef ECORE_STOP_ON_ERROR
			ECORE_MSG(pdev, "exit  (cnt %d)\n", 5000 - cnt);
#endif
			return ECORE_SUCCESS;
		}

#ifndef ECORE_ERASE
		/* in case reset is in progress we won't get completion */
		if (lm_reset_is_inprogress(pdev))
			return 0;

		delay_us = (cnt >= 2360) ? 100 : 25000;
#endif
		mm_wait(pdev, delay_us);

		if (pdev->panic)
			return ECORE_IO;
	}

	/* timeout! */
	ECORE_ERR("timeout waiting for state %d\n", state);
#ifdef ECORE_STOP_ON_ERROR
	ecore_panic();
#endif

	return ECORE_TIMEOUT;
}

static int ecore_raw_wait(struct _lm_device_t *pdev, struct ecore_raw_obj *raw)
{
	return ecore_state_wait(pdev, raw->state, raw->pstate);
}

/***************** Classification verbs: Set/Del MAC/VLAN/VLAN-MAC ************/
/* credit handling callbacks */
static BOOL ecore_get_cam_offset_mac(struct ecore_vlan_mac_obj *o, int *offset)
{
	struct ecore_credit_pool_obj *mp = o->macs_pool;

	DbgBreakIf(!mp);

	return mp->get_entry(mp, offset);
}

static BOOL ecore_get_credit_mac(struct ecore_vlan_mac_obj *o)
{
	struct ecore_credit_pool_obj *mp = o->macs_pool;

	DbgBreakIf(!mp);

	return mp->get(mp, 1);
}

static BOOL ecore_get_cam_offset_vlan(struct ecore_vlan_mac_obj *o, int *offset)
{
	struct ecore_credit_pool_obj *vp = o->vlans_pool;

	DbgBreakIf(!vp);

	return vp->get_entry(vp, offset);
}

static BOOL ecore_get_credit_vlan(struct ecore_vlan_mac_obj *o)
{
	struct ecore_credit_pool_obj *vp = o->vlans_pool;

	DbgBreakIf(!vp);

	return vp->get(vp, 1);
}

static BOOL ecore_get_credit_vlan_mac(struct ecore_vlan_mac_obj *o)
{
	struct ecore_credit_pool_obj *mp = o->macs_pool;
	struct ecore_credit_pool_obj *vp = o->vlans_pool;

	if (!mp->get(mp, 1))
		return FALSE;

	if (!vp->get(vp, 1)) {
		mp->put(mp, 1);
		return FALSE;
	}

	return TRUE;
}

static BOOL ecore_put_cam_offset_mac(struct ecore_vlan_mac_obj *o, int offset)
{
	struct ecore_credit_pool_obj *mp = o->macs_pool;

	return mp->put_entry(mp, offset);
}

static BOOL ecore_put_credit_mac(struct ecore_vlan_mac_obj *o)
{
	struct ecore_credit_pool_obj *mp = o->macs_pool;

	return mp->put(mp, 1);
}

static BOOL ecore_put_cam_offset_vlan(struct ecore_vlan_mac_obj *o, int offset)
{
	struct ecore_credit_pool_obj *vp = o->vlans_pool;

	return vp->put_entry(vp, offset);
}

static BOOL ecore_put_credit_vlan(struct ecore_vlan_mac_obj *o)
{
	struct ecore_credit_pool_obj *vp = o->vlans_pool;

	return vp->put(vp, 1);
}

static BOOL ecore_put_credit_vlan_mac(struct ecore_vlan_mac_obj *o)
{
	struct ecore_credit_pool_obj *mp = o->macs_pool;
	struct ecore_credit_pool_obj *vp = o->vlans_pool;

	if (!mp->put(mp, 1))
		return FALSE;

	if (!vp->put(vp, 1)) {
		mp->get(mp, 1);
		return FALSE;
	}

	return TRUE;
}

/**
 * __ecore_vlan_mac_h_write_trylock - try getting the writer lock on vlan mac
 * head list.
 *
 * @pdev:	device handle
 * @o:		vlan_mac object
 *
 * @details: Non-blocking implementation; should be called under execution
 *           queue lock.
 */
static int __ecore_vlan_mac_h_write_trylock(struct _lm_device_t *pdev,
					    struct ecore_vlan_mac_obj *o)
{
	if (o->head_reader) {
		ECORE_MSG(pdev, "vlan_mac_lock writer - There are readers; Busy\n");
		return ECORE_BUSY;
	}

	ECORE_MSG(pdev, "vlan_mac_lock writer - Taken\n");
	return ECORE_SUCCESS;
}

/**
 * __ecore_vlan_mac_h_exec_pending - execute step instead of a previous step
 * which wasn't able to run due to a taken lock on vlan mac head list.
 *
 * @pdev:	device handle
 * @o:		vlan_mac object
 *
 * @details Should be called under execution queue lock; notice it might release
 *          and reclaim it during its run.
 */
static void __ecore_vlan_mac_h_exec_pending(struct _lm_device_t *pdev,
					    struct ecore_vlan_mac_obj *o)
{
	int rc;
	unsigned long ramrod_flags = o->saved_ramrod_flags;

	ECORE_MSG(pdev, "vlan_mac_lock execute pending command with ramrod flags %lu\n",
		  ramrod_flags);
	o->head_exe_request = FALSE;
	o->saved_ramrod_flags = 0;
	rc = ecore_exe_queue_step(pdev, &o->exe_queue, &ramrod_flags);
	if (rc != ECORE_SUCCESS) {
		ECORE_ERR("execution of pending commands failed with rc %d\n",
			  rc);
#ifdef ECORE_STOP_ON_ERROR
		ecore_panic();
#endif
	}
}

/**
 * __ecore_vlan_mac_h_pend - Pend an execution step which couldn't have been
 * called due to vlan mac head list lock being taken.
 *
 * @pdev:		device handle
 * @o:			vlan_mac object
 * @ramrod_flags:	ramrod flags of missed execution
 *
 * @details Should be called under execution queue lock.
 */
static void __ecore_vlan_mac_h_pend(struct _lm_device_t *pdev,
				    struct ecore_vlan_mac_obj *o,
				    unsigned long ramrod_flags)
{
	o->head_exe_request = TRUE;
	o->saved_ramrod_flags = ramrod_flags;
	ECORE_MSG(pdev, "Placing pending execution with ramrod flags %lu\n",
		  ramrod_flags);
}

/**
 * __ecore_vlan_mac_h_write_unlock - unlock the vlan mac head list writer lock
 *
 * @pdev:		device handle
 * @o:			vlan_mac object
 *
 * @details Should be called under execution queue lock. Notice if a pending
 *          execution exists, it would perform it - possibly releasing and
 *          reclaiming the execution queue lock.
 */
static void __ecore_vlan_mac_h_write_unlock(struct _lm_device_t *pdev,
					    struct ecore_vlan_mac_obj *o)
{
	/* It's possible a new pending execution was added since this writer
	 * executed. If so, execute again. [Ad infinitum]
	 */
	while(o->head_exe_request) {
		ECORE_MSG(pdev, "vlan_mac_lock - writer release encountered a pending request\n");
		__ecore_vlan_mac_h_exec_pending(pdev, o);
	}
}

/**
 * ecore_vlan_mac_h_write_unlock - unlock the vlan mac head list writer lock
 *
 * @pdev:		device handle
 * @o:			vlan_mac object
 *
 * @details Notice if a pending execution exists, it would perform it -
 *          possibly releasing and reclaiming the execution queue lock.
 */
void ecore_vlan_mac_h_write_unlock(struct _lm_device_t *pdev,
				   struct ecore_vlan_mac_obj *o)
{
	ECORE_SPIN_LOCK_BH(&o->exe_queue.lock);
	__ecore_vlan_mac_h_write_unlock(pdev, o);
	ECORE_SPIN_UNLOCK_BH(&o->exe_queue.lock);
}

/**
 * __ecore_vlan_mac_h_read_lock - lock the vlan mac head list reader lock
 *
 * @pdev:		device handle
 * @o:			vlan_mac object
 *
 * @details Should be called under the execution queue lock. May sleep. May
 *          release and reclaim execution queue lock during its run.
 */
static int __ecore_vlan_mac_h_read_lock(struct _lm_device_t *pdev,
					struct ecore_vlan_mac_obj *o)
{
	/* If we got here, we're holding lock --> no WRITER exists */
	o->head_reader++;
	ECORE_MSG(pdev, "vlan_mac_lock - locked reader - number %d\n",
		  o->head_reader);

	return ECORE_SUCCESS;
}

/**
 * ecore_vlan_mac_h_read_lock - lock the vlan mac head list reader lock
 *
 * @pdev:		device handle
 * @o:			vlan_mac object
 *
 * @details May sleep. Claims and releases execution queue lock during its run.
 */
int ecore_vlan_mac_h_read_lock(struct _lm_device_t *pdev,
			       struct ecore_vlan_mac_obj *o)
{
	int rc;

	ECORE_SPIN_LOCK_BH(&o->exe_queue.lock);
	rc = __ecore_vlan_mac_h_read_lock(pdev, o);
	ECORE_SPIN_UNLOCK_BH(&o->exe_queue.lock);

	return rc;
}

/**
 * __ecore_vlan_mac_h_read_unlock - unlock the vlan mac head list reader lock
 *
 * @pdev:		device handle
 * @o:			vlan_mac object
 *
 * @details Should be called under execution queue lock. Notice if a pending
 *          execution exists, it would be performed if this was the last
 *          reader. possibly releasing and reclaiming the execution queue lock.
 */
static void __ecore_vlan_mac_h_read_unlock(struct _lm_device_t *pdev,
					  struct ecore_vlan_mac_obj *o)
{
	if (!o->head_reader) {
		ECORE_ERR("Need to release vlan mac reader lock, but lock isn't taken\n");
#ifdef ECORE_STOP_ON_ERROR
		ecore_panic();
#endif
	} else {
		o->head_reader--;
		ECORE_MSG(pdev, "vlan_mac_lock - decreased readers to %d\n",
			  o->head_reader);
	}

	/* It's possible a new pending execution was added, and that this reader
	 * was last - if so we need to execute the command.
	 */
	if (!o->head_reader && o->head_exe_request) {
		ECORE_MSG(pdev, "vlan_mac_lock - reader release encountered a pending request\n");

		/* Writer release will do the trick */
		__ecore_vlan_mac_h_write_unlock(pdev, o);
	}
}

/**
 * ecore_vlan_mac_h_read_unlock - unlock the vlan mac head list reader lock
 *
 * @pdev:		device handle
 * @o:			vlan_mac object
 *
 * @details Notice if a pending execution exists, it would be performed if this
 *          was the last reader. Claims and releases the execution queue lock
 *          during its run.
 */
void ecore_vlan_mac_h_read_unlock(struct _lm_device_t *pdev,
				  struct ecore_vlan_mac_obj *o)
{
	ECORE_SPIN_LOCK_BH(&o->exe_queue.lock);
	__ecore_vlan_mac_h_read_unlock(pdev, o);
	ECORE_SPIN_UNLOCK_BH(&o->exe_queue.lock);
}

/**
 * ecore_vlan_mac_h_read_unlock - unlock the vlan mac head list reader lock
 *
 * @pdev:		device handle
 * @o:			vlan_mac object
 * @n:			number of elements to get
 * @base:		base address for element placement
 * @stride:		stride between elements (in bytes)
 */
static int ecore_get_n_elements(struct _lm_device_t *pdev, struct ecore_vlan_mac_obj *o,
				 int n, u8 *base, u8 stride, u8 size)
{
	struct ecore_vlan_mac_registry_elem *pos;
	u8 *next = base;
	int counter = 0;
	int read_lock;

	ECORE_MSG(pdev, "get_n_elements - taking vlan_mac_lock (reader)\n");
	read_lock = ecore_vlan_mac_h_read_lock(pdev, o);
	if (read_lock != ECORE_SUCCESS)
		ECORE_ERR("get_n_elements failed to get vlan mac reader lock; Access without lock\n");

	/* traverse list */
	ECORE_LIST_FOR_EACH_ENTRY(pos, &o->head, link,
				  struct ecore_vlan_mac_registry_elem) {
		if (counter < n) {
			mm_memcpy(next, &pos->u, size);
			counter++;
			ECORE_MSG(pdev, "copied element number %d to address %p element was:\n",
				  counter, next);
			next += stride + size;
		}
	}

	if (read_lock == ECORE_SUCCESS) {
		ECORE_MSG(pdev, "get_n_elements - releasing vlan_mac_lock (reader)\n");
		ecore_vlan_mac_h_read_unlock(pdev, o);
	}

	return counter * ETH_ALEN;
}

/* check_add() callbacks */
static int ecore_check_mac_add(struct _lm_device_t *pdev,
			       struct ecore_vlan_mac_obj *o,
			       union ecore_classification_ramrod_data *data)
{
	struct ecore_vlan_mac_registry_elem *pos;

	ECORE_MSG(pdev, "Checking MAC %02x:%02x:%02x:%02x:%02x:%02x for ADD command\n", data->mac.mac[0], data->mac.mac[1], data->mac.mac[2], data->mac.mac[3], data->mac.mac[4], data->mac.mac[5]);

	if (!ECORE_IS_VALID_ETHER_ADDR(data->mac.mac))
		return ECORE_INVAL;

	/* Check if a requested MAC already exists */
	ECORE_LIST_FOR_EACH_ENTRY(pos, &o->head, link,
				  struct ecore_vlan_mac_registry_elem)
		if (mm_memcmp(data->mac.mac, pos->u.mac.mac, ETH_ALEN) &&
		    (data->mac.is_inner_mac == pos->u.mac.is_inner_mac))
			return ECORE_EXISTS;

	return ECORE_SUCCESS;
}

static int ecore_check_vlan_add(struct _lm_device_t *pdev,
				struct ecore_vlan_mac_obj *o,
				union ecore_classification_ramrod_data *data)
{
	struct ecore_vlan_mac_registry_elem *pos;

	ECORE_MSG(pdev, "Checking VLAN %d for ADD command\n", data->vlan.vlan);

	ECORE_LIST_FOR_EACH_ENTRY(pos, &o->head, link,
				  struct ecore_vlan_mac_registry_elem)
		if (data->vlan.vlan == pos->u.vlan.vlan)
			return ECORE_EXISTS;

	return ECORE_SUCCESS;
}

static int ecore_check_vlan_mac_add(struct _lm_device_t *pdev,
				    struct ecore_vlan_mac_obj *o,
				   union ecore_classification_ramrod_data *data)
{
	struct ecore_vlan_mac_registry_elem *pos;

	ECORE_MSG(pdev, "Checking VLAN_MAC (%02x:%02x:%02x:%02x:%02x:%02x, %d) for ADD command\n",
		  data->vlan_mac.mac[0], data->vlan_mac.mac[1], data->vlan_mac.mac[2], data->vlan_mac.mac[3], data->vlan_mac.mac[4], data->vlan_mac.mac[5], data->vlan_mac.vlan);

	ECORE_LIST_FOR_EACH_ENTRY(pos, &o->head, link,
				  struct ecore_vlan_mac_registry_elem)
		if ((data->vlan_mac.vlan == pos->u.vlan_mac.vlan) &&
		    (mm_memcmp(data->vlan_mac.mac, pos->u.vlan_mac.mac,
				  ETH_ALEN)) &&
		    (data->vlan_mac.is_inner_mac ==
		     pos->u.vlan_mac.is_inner_mac))
			return ECORE_EXISTS;

	return ECORE_SUCCESS;
}

/* check_del() callbacks */
static struct ecore_vlan_mac_registry_elem *
	ecore_check_mac_del(struct _lm_device_t *pdev,
			    struct ecore_vlan_mac_obj *o,
			    union ecore_classification_ramrod_data *data)
{
	struct ecore_vlan_mac_registry_elem *pos;

	ECORE_MSG(pdev, "Checking MAC %02x:%02x:%02x:%02x:%02x:%02x for DEL command\n", data->mac.mac[0], data->mac.mac[1], data->mac.mac[2], data->mac.mac[3], data->mac.mac[4], data->mac.mac[5]);

	ECORE_LIST_FOR_EACH_ENTRY(pos, &o->head, link,
				  struct ecore_vlan_mac_registry_elem)
		if ((mm_memcmp(data->mac.mac, pos->u.mac.mac, ETH_ALEN)) &&
		    (data->mac.is_inner_mac == pos->u.mac.is_inner_mac))
			return pos;

	return NULL;
}

static struct ecore_vlan_mac_registry_elem *
	ecore_check_vlan_del(struct _lm_device_t *pdev,
			     struct ecore_vlan_mac_obj *o,
			     union ecore_classification_ramrod_data *data)
{
	struct ecore_vlan_mac_registry_elem *pos;

	ECORE_MSG(pdev, "Checking VLAN %d for DEL command\n", data->vlan.vlan);

	ECORE_LIST_FOR_EACH_ENTRY(pos, &o->head, link,
				  struct ecore_vlan_mac_registry_elem)
		if (data->vlan.vlan == pos->u.vlan.vlan)
			return pos;

	return NULL;
}

static struct ecore_vlan_mac_registry_elem *
	ecore_check_vlan_mac_del(struct _lm_device_t *pdev,
				 struct ecore_vlan_mac_obj *o,
				 union ecore_classification_ramrod_data *data)
{
	struct ecore_vlan_mac_registry_elem *pos;

	ECORE_MSG(pdev, "Checking VLAN_MAC (%02x:%02x:%02x:%02x:%02x:%02x, %d) for DEL command\n",
		  data->vlan_mac.mac[0], data->vlan_mac.mac[1], data->vlan_mac.mac[2], data->vlan_mac.mac[3], data->vlan_mac.mac[4], data->vlan_mac.mac[5], data->vlan_mac.vlan);

	ECORE_LIST_FOR_EACH_ENTRY(pos, &o->head, link,
				  struct ecore_vlan_mac_registry_elem)
		if ((data->vlan_mac.vlan == pos->u.vlan_mac.vlan) &&
		    (mm_memcmp(data->vlan_mac.mac, pos->u.vlan_mac.mac,
			     ETH_ALEN)) &&
		    (data->vlan_mac.is_inner_mac ==
		     pos->u.vlan_mac.is_inner_mac))
			return pos;

	return NULL;
}

/* check_move() callback */
static BOOL ecore_check_move(struct _lm_device_t *pdev,
			     struct ecore_vlan_mac_obj *src_o,
			     struct ecore_vlan_mac_obj *dst_o,
			     union ecore_classification_ramrod_data *data)
{
	struct ecore_vlan_mac_registry_elem *pos;
	int rc;

	/* Check if we can delete the requested configuration from the first
	 * object.
	 */
	pos = src_o->check_del(pdev, src_o, data);

	/*  check if configuration can be added */
	rc = dst_o->check_add(pdev, dst_o, data);

	/* If this classification can not be added (is already set)
	 * or can't be deleted - return an error.
	 */
	if (rc || !pos)
		return FALSE;

	return TRUE;
}

static BOOL ecore_check_move_always_err(
	struct _lm_device_t *pdev,
	struct ecore_vlan_mac_obj *src_o,
	struct ecore_vlan_mac_obj *dst_o,
	union ecore_classification_ramrod_data *data)
{
	return FALSE;
}

static INLINE u8 ecore_vlan_mac_get_rx_tx_flag(struct ecore_vlan_mac_obj *o)
{
	struct ecore_raw_obj *raw = &o->raw;
	u8 rx_tx_flag = 0;

	if ((raw->obj_type == ECORE_OBJ_TYPE_TX) ||
	    (raw->obj_type == ECORE_OBJ_TYPE_RX_TX))
		rx_tx_flag |= ETH_CLASSIFY_CMD_HEADER_TX_CMD;

	if ((raw->obj_type == ECORE_OBJ_TYPE_RX) ||
	    (raw->obj_type == ECORE_OBJ_TYPE_RX_TX))
		rx_tx_flag |= ETH_CLASSIFY_CMD_HEADER_RX_CMD;

	return rx_tx_flag;
}

void ecore_set_mac_in_nig(struct _lm_device_t *pdev,
			  BOOL add, unsigned char *dev_addr, int index)
{
	u32 wb_data[2];
	u32 reg_offset = PORT_ID(pdev) ? NIG_REG_LLH1_FUNC_MEM :
			 NIG_REG_LLH0_FUNC_MEM;

	if (!IS_MF_SI_MODE(pdev) && !IS_MF_AFEX(pdev))
		return;

	if (index > ECORE_LLH_CAM_MAX_PF_LINE)
		return;

	ECORE_MSG(pdev, "Going to %s LLH configuration at entry %d\n",
		  (add ? "ADD" : "DELETE"), index);

	if (add) {
		/* LLH_FUNC_MEM is a u64 WB register */
		reg_offset += 8*index;

		wb_data[0] = ((dev_addr[2] << 24) | (dev_addr[3] << 16) |
			      (dev_addr[4] <<  8) |  dev_addr[5]);
		wb_data[1] = ((dev_addr[0] <<  8) |  dev_addr[1]);

		REG_WR_DMAE_LEN(pdev, reg_offset, wb_data, 2);
	}

	REG_WR(pdev, (PORT_ID(pdev) ? NIG_REG_LLH1_FUNC_MEM_ENABLE :
				  NIG_REG_LLH0_FUNC_MEM_ENABLE) + 4*index, add);
}

/**
 * ecore_vlan_mac_set_cmd_hdr_e2 - set a header in a single classify ramrod
 *
 * @pdev:	device handle
 * @o:		queue for which we want to configure this rule
 * @add:	if TRUE the command is an ADD command, DEL otherwise
 * @opcode:	CLASSIFY_RULE_OPCODE_XXX
 * @hdr:	pointer to a header to setup
 *
 */
static INLINE void ecore_vlan_mac_set_cmd_hdr_e2(struct _lm_device_t *pdev,
	struct ecore_vlan_mac_obj *o, BOOL add, int opcode,
	struct eth_classify_cmd_header *hdr)
{
	struct ecore_raw_obj *raw = &o->raw;

	hdr->client_id = raw->cl_id;
	hdr->func_id = raw->func_id;

	/* Rx or/and Tx (internal switching) configuration ? */
	hdr->cmd_general_data |=
		ecore_vlan_mac_get_rx_tx_flag(o);

	if (add)
		hdr->cmd_general_data |= ETH_CLASSIFY_CMD_HEADER_IS_ADD;

	hdr->cmd_general_data |=
		(opcode << ETH_CLASSIFY_CMD_HEADER_OPCODE_SHIFT);
}

/**
 * ecore_vlan_mac_set_rdata_hdr_e2 - set the classify ramrod data header
 *
 * @cid:	connection id
 * @type:	ECORE_FILTER_XXX_PENDING
 * @hdr:	pointer to header to setup
 * @rule_cnt:
 *
 * currently we always configure one rule and echo field to contain a CID and an
 * opcode type.
 */
static INLINE void ecore_vlan_mac_set_rdata_hdr_e2(u32 cid, int type,
				struct eth_classify_header *hdr, int rule_cnt)
{
	hdr->echo = mm_cpu_to_le32((cid & ECORE_SWCID_MASK) |
				(type << ECORE_SWCID_SHIFT));
	hdr->rule_cnt = (u8)rule_cnt;
}

/* hw_config() callbacks */
static void ecore_set_one_mac_e2(struct _lm_device_t *pdev,
				 struct ecore_vlan_mac_obj *o,
				 struct ecore_exeq_elem *elem, int rule_idx,
				 int cam_offset)
{
	struct ecore_raw_obj *raw = &o->raw;
	struct eth_classify_rules_ramrod_data *data =
		(struct eth_classify_rules_ramrod_data *)(raw->rdata);
	int rule_cnt = rule_idx + 1, cmd = elem->cmd_data.vlan_mac.cmd;
	union eth_classify_rule_cmd *rule_entry = &data->rules[rule_idx];
	BOOL add = (cmd == ECORE_VLAN_MAC_ADD) ? TRUE : FALSE;
	unsigned long *vlan_mac_flags = &elem->cmd_data.vlan_mac.vlan_mac_flags;
	u8 *mac = elem->cmd_data.vlan_mac.u.mac.mac;

	/* Set LLH CAM entry: currently only iSCSI and ETH macs are
	 * relevant. In addition, current implementation is tuned for a
	 * single ETH MAC.
	 *
	 * When multiple unicast ETH MACs PF configuration in switch
	 * independent mode is required (NetQ, multiple netdev MACs,
	 * etc.), consider better utilisation of 8 per function MAC
	 * entries in the LLH register. There is also
	 * NIG_REG_P[01]_LLH_FUNC_MEM2 registers that complete the
	 * total number of CAM entries to 16.
	 *
	 * Currently we won't configure NIG for MACs other than a primary ETH
	 * MAC and iSCSI L2 MAC.
	 *
	 * If this MAC is moving from one Queue to another, no need to change
	 * NIG configuration.
	 */
	if (cmd != ECORE_VLAN_MAC_MOVE) {
		if (ECORE_TEST_BIT(ECORE_ISCSI_ETH_MAC, vlan_mac_flags))
			ecore_set_mac_in_nig(pdev, add, mac,
					     ECORE_LLH_CAM_ISCSI_ETH_LINE);
		else if (ECORE_TEST_BIT(ECORE_ETH_MAC, vlan_mac_flags))
			ecore_set_mac_in_nig(pdev, add, mac,
					     ECORE_LLH_CAM_ETH_LINE);
	}

	/* Reset the ramrod data buffer for the first rule */
	if (rule_idx == 0)
		mm_memset(data, 0, sizeof(*data));

	/* Setup a command header */
	ecore_vlan_mac_set_cmd_hdr_e2(pdev, o, add, CLASSIFY_RULE_OPCODE_MAC,
				      &rule_entry->mac.header);

	ECORE_MSG(pdev, "About to %s MAC %02x:%02x:%02x:%02x:%02x:%02x for Queue %d\n",
		  (add ? "add" : "delete"), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], raw->cl_id);

	/* Set a MAC itself */
	ecore_set_fw_mac_addr(&rule_entry->mac.mac_msb,
			      &rule_entry->mac.mac_mid,
			      &rule_entry->mac.mac_lsb, mac);
	rule_entry->mac.inner_mac =
		mm_cpu_to_le16(elem->cmd_data.vlan_mac.u.mac.is_inner_mac);

	/* MOVE: Add a rule that will add this MAC to the target Queue */
	if (cmd == ECORE_VLAN_MAC_MOVE) {
		rule_entry++;
		rule_cnt++;

		/* Setup ramrod data */
		ecore_vlan_mac_set_cmd_hdr_e2(pdev,
					elem->cmd_data.vlan_mac.target_obj,
					      TRUE, CLASSIFY_RULE_OPCODE_MAC,
					      &rule_entry->mac.header);

		/* Set a MAC itself */
		ecore_set_fw_mac_addr(&rule_entry->mac.mac_msb,
				      &rule_entry->mac.mac_mid,
				      &rule_entry->mac.mac_lsb, mac);
		rule_entry->mac.inner_mac =
			mm_cpu_to_le16(elem->cmd_data.vlan_mac.
				       u.mac.is_inner_mac);
	}

	/* Set the ramrod data header */
	/* TODO: take this to the higher level in order to prevent multiple
		 writing */
	ecore_vlan_mac_set_rdata_hdr_e2(raw->cid, raw->state, &data->header,
					rule_cnt);
}

/**
 * ecore_vlan_mac_set_rdata_hdr_e1x - set a header in a single classify ramrod
 *
 * @pdev:	device handle
 * @o:		queue
 * @type:
 * @cam_offset:	offset in cam memory
 * @hdr:	pointer to a header to setup
 *
 * E1/E1H
 */
static INLINE void ecore_vlan_mac_set_rdata_hdr_e1x(struct _lm_device_t *pdev,
	struct ecore_vlan_mac_obj *o, int type, int cam_offset,
	struct mac_configuration_hdr *hdr)
{
	struct ecore_raw_obj *r = &o->raw;

	hdr->length = 1;
	hdr->offset = (u8)cam_offset;
	hdr->client_id = mm_cpu_to_le16(0xff);
	hdr->echo = mm_cpu_to_le32((r->cid & ECORE_SWCID_MASK) |
				(type << ECORE_SWCID_SHIFT));
}

static INLINE void ecore_vlan_mac_set_cfg_entry_e1x(struct _lm_device_t *pdev,
	struct ecore_vlan_mac_obj *o, BOOL add, int opcode, u8 *mac,
	u16 vlan_id, struct mac_configuration_entry *cfg_entry)
{
	struct ecore_raw_obj *r = &o->raw;
	u32 cl_bit_vec = (1 << r->cl_id);

	cfg_entry->clients_bit_vector = mm_cpu_to_le32(cl_bit_vec);
	cfg_entry->pf_id = r->func_id;
	cfg_entry->vlan_id = mm_cpu_to_le16(vlan_id);

	if (add) {
		ECORE_SET_FLAG(cfg_entry->flags,
			       MAC_CONFIGURATION_ENTRY_ACTION_TYPE,
			       T_ETH_MAC_COMMAND_SET);
		ECORE_SET_FLAG(cfg_entry->flags,
			       MAC_CONFIGURATION_ENTRY_VLAN_FILTERING_MODE,
			       opcode);

		/* Set a MAC in a ramrod data */
		ecore_set_fw_mac_addr(&cfg_entry->msb_mac_addr,
				      &cfg_entry->middle_mac_addr,
				      &cfg_entry->lsb_mac_addr, mac);
	} else
		ECORE_SET_FLAG(cfg_entry->flags,
			       MAC_CONFIGURATION_ENTRY_ACTION_TYPE,
			       T_ETH_MAC_COMMAND_INVALIDATE);
}

static INLINE void ecore_vlan_mac_set_rdata_e1x(struct _lm_device_t *pdev,
	struct ecore_vlan_mac_obj *o, int type, int cam_offset, BOOL add,
	u8 *mac, u16 vlan_id, int opcode, struct mac_configuration_cmd *config)
{
	struct mac_configuration_entry *cfg_entry = &config->config_table[0];
	struct ecore_raw_obj *raw = &o->raw;

	ecore_vlan_mac_set_rdata_hdr_e1x(pdev, o, type, cam_offset,
					 &config->hdr);
	ecore_vlan_mac_set_cfg_entry_e1x(pdev, o, add, opcode, mac, vlan_id,
					 cfg_entry);

	ECORE_MSG(pdev, "%s MAC %02x:%02x:%02x:%02x:%02x:%02x CLID %d CAM offset %d\n",
		  (add ? "setting" : "clearing"),
		  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], raw->cl_id, cam_offset);
}

/**
 * ecore_set_one_mac_e1x - fill a single MAC rule ramrod data
 *
 * @pdev:	device handle
 * @o:		ecore_vlan_mac_obj
 * @elem:	ecore_exeq_elem
 * @rule_idx:	rule_idx
 * @cam_offset: cam_offset
 */
static void ecore_set_one_mac_e1x(struct _lm_device_t *pdev,
				  struct ecore_vlan_mac_obj *o,
				  struct ecore_exeq_elem *elem, int rule_idx,
				  int cam_offset)
{
	struct ecore_raw_obj *raw = &o->raw;
	struct mac_configuration_cmd *config =
		(struct mac_configuration_cmd *)(raw->rdata);
	/* 57710 and 57711 do not support MOVE command,
	 * so it's either ADD or DEL
	 */
	BOOL add = (elem->cmd_data.vlan_mac.cmd == ECORE_VLAN_MAC_ADD) ?
		TRUE : FALSE;

	/* Reset the ramrod data buffer */
	mm_memset(config, 0, sizeof(*config));

	ecore_vlan_mac_set_rdata_e1x(pdev, o, raw->state,
				     cam_offset, add,
				     elem->cmd_data.vlan_mac.u.mac.mac, 0,
				     ETH_VLAN_FILTER_ANY_VLAN, config);
}

static void ecore_set_one_vlan_e2(struct _lm_device_t *pdev,
				  struct ecore_vlan_mac_obj *o,
				  struct ecore_exeq_elem *elem, int rule_idx,
				  int cam_offset)
{
	struct ecore_raw_obj *raw = &o->raw;
	struct eth_classify_rules_ramrod_data *data =
		(struct eth_classify_rules_ramrod_data *)(raw->rdata);
	int rule_cnt = rule_idx + 1;
	union eth_classify_rule_cmd *rule_entry = &data->rules[rule_idx];
	enum ecore_vlan_mac_cmd cmd = elem->cmd_data.vlan_mac.cmd;
	BOOL add = (cmd == ECORE_VLAN_MAC_ADD) ? TRUE : FALSE;
	u16 vlan = elem->cmd_data.vlan_mac.u.vlan.vlan;

	/* Reset the ramrod data buffer for the first rule */
	if (rule_idx == 0)
		mm_memset(data, 0, sizeof(*data));

	/* Set a rule header */
	ecore_vlan_mac_set_cmd_hdr_e2(pdev, o, add, CLASSIFY_RULE_OPCODE_VLAN,
				      &rule_entry->vlan.header);

	ECORE_MSG(pdev, "About to %s VLAN %d\n", (add ? "add" : "delete"),
		  vlan);

	/* Set a VLAN itself */
	rule_entry->vlan.vlan = mm_cpu_to_le16(vlan);

	/* MOVE: Add a rule that will add this MAC to the target Queue */
	if (cmd == ECORE_VLAN_MAC_MOVE) {
		rule_entry++;
		rule_cnt++;

		/* Setup ramrod data */
		ecore_vlan_mac_set_cmd_hdr_e2(pdev,
					elem->cmd_data.vlan_mac.target_obj,
					      TRUE, CLASSIFY_RULE_OPCODE_VLAN,
					      &rule_entry->vlan.header);

		/* Set a VLAN itself */
		rule_entry->vlan.vlan = mm_cpu_to_le16(vlan);
	}

	/* Set the ramrod data header */
	/* TODO: take this to the higher level in order to prevent multiple
		 writing */
	ecore_vlan_mac_set_rdata_hdr_e2(raw->cid, raw->state, &data->header,
					rule_cnt);
}

static void ecore_set_one_vlan_mac_e2(struct _lm_device_t *pdev,
				      struct ecore_vlan_mac_obj *o,
				      struct ecore_exeq_elem *elem,
				      int rule_idx, int cam_offset)
{
	struct ecore_raw_obj *raw = &o->raw;
	struct eth_classify_rules_ramrod_data *data =
		(struct eth_classify_rules_ramrod_data *)(raw->rdata);
	int rule_cnt = rule_idx + 1;
	union eth_classify_rule_cmd *rule_entry = &data->rules[rule_idx];
	enum ecore_vlan_mac_cmd cmd = elem->cmd_data.vlan_mac.cmd;
	BOOL add = (cmd == ECORE_VLAN_MAC_ADD) ? TRUE : FALSE;
	u16 vlan = elem->cmd_data.vlan_mac.u.vlan_mac.vlan;
	u8 *mac = elem->cmd_data.vlan_mac.u.vlan_mac.mac;

	/* Reset the ramrod data buffer for the first rule */
	if (rule_idx == 0)
		mm_memset(data, 0, sizeof(*data));

	/* Set a rule header */
	ecore_vlan_mac_set_cmd_hdr_e2(pdev, o, add, CLASSIFY_RULE_OPCODE_PAIR,
				      &rule_entry->pair.header);

	/* Set VLAN and MAC themselves */
	rule_entry->pair.vlan = mm_cpu_to_le16(vlan);
	ecore_set_fw_mac_addr(&rule_entry->pair.mac_msb,
			      &rule_entry->pair.mac_mid,
			      &rule_entry->pair.mac_lsb, mac);
	rule_entry->pair.inner_mac =
			elem->cmd_data.vlan_mac.u.vlan_mac.is_inner_mac;
	/* MOVE: Add a rule that will add this MAC to the target Queue */
	if (cmd == ECORE_VLAN_MAC_MOVE) {
		rule_entry++;
		rule_cnt++;

		/* Setup ramrod data */
		ecore_vlan_mac_set_cmd_hdr_e2(pdev,
					elem->cmd_data.vlan_mac.target_obj,
					      TRUE, CLASSIFY_RULE_OPCODE_PAIR,
					      &rule_entry->pair.header);

		/* Set a VLAN itself */
		rule_entry->pair.vlan = mm_cpu_to_le16(vlan);
		ecore_set_fw_mac_addr(&rule_entry->pair.mac_msb,
				      &rule_entry->pair.mac_mid,
				      &rule_entry->pair.mac_lsb, mac);
		rule_entry->pair.inner_mac =
			elem->cmd_data.vlan_mac.u.vlan_mac.is_inner_mac;
	}

	/* Set the ramrod data header */
	/* TODO: take this to the higher level in order to prevent multiple
		 writing */
	ecore_vlan_mac_set_rdata_hdr_e2(raw->cid, raw->state, &data->header,
					rule_cnt);
}

/**
 * ecore_set_one_vlan_mac_e1h -
 *
 * @pdev:	device handle
 * @o:		ecore_vlan_mac_obj
 * @elem:	ecore_exeq_elem
 * @rule_idx:	rule_idx
 * @cam_offset:	cam_offset
 */
static void ecore_set_one_vlan_mac_e1h(struct _lm_device_t *pdev,
				       struct ecore_vlan_mac_obj *o,
				       struct ecore_exeq_elem *elem,
				       int rule_idx, int cam_offset)
{
	struct ecore_raw_obj *raw = &o->raw;
	struct mac_configuration_cmd *config =
		(struct mac_configuration_cmd *)(raw->rdata);
	/* 57710 and 57711 do not support MOVE command,
	 * so it's either ADD or DEL
	 */
	BOOL add = (elem->cmd_data.vlan_mac.cmd == ECORE_VLAN_MAC_ADD) ?
		TRUE : FALSE;

	/* Reset the ramrod data buffer */
	mm_memset(config, 0, sizeof(*config));

	ecore_vlan_mac_set_rdata_e1x(pdev, o, ECORE_FILTER_VLAN_MAC_PENDING,
				     cam_offset, add,
				     elem->cmd_data.vlan_mac.u.vlan_mac.mac,
				     elem->cmd_data.vlan_mac.u.vlan_mac.vlan,
				     ETH_VLAN_FILTER_CLASSIFY, config);
}

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

/**
 * ecore_vlan_mac_restore - reconfigure next MAC/VLAN/VLAN-MAC element
 *
 * @pdev:	device handle
 * @p:		command parameters
 * @ppos:	pointer to the cookie
 *
 * reconfigure next MAC/VLAN/VLAN-MAC element from the
 * previously configured elements list.
 *
 * from command parameters only RAMROD_COMP_WAIT bit in ramrod_flags is	taken
 * into an account
 *
 * pointer to the cookie  - that should be given back in the next call to make
 * function handle the next element. If *ppos is set to NULL it will restart the
 * iterator. If returned *ppos == NULL this means that the last element has been
 * handled.
 *
 */
static int ecore_vlan_mac_restore(struct _lm_device_t *pdev,
			   struct ecore_vlan_mac_ramrod_params *p,
			   struct ecore_vlan_mac_registry_elem **ppos)
{
	struct ecore_vlan_mac_registry_elem *pos;
	struct ecore_vlan_mac_obj *o = p->vlan_mac_obj;

	/* If list is empty - there is nothing to do here */
	if (ECORE_LIST_IS_EMPTY(&o->head)) {
		*ppos = NULL;
		return 0;
	}

	/* make a step... */
	if (*ppos == NULL)
		*ppos = ECORE_LIST_FIRST_ENTRY(&o->head,
					    struct ecore_vlan_mac_registry_elem,
					       link);
	else
		*ppos = ECORE_LIST_NEXT(*ppos, link,
					struct ecore_vlan_mac_registry_elem);

	pos = *ppos;

	/* If it's the last step - return NULL */
	if (ECORE_LIST_IS_LAST(&pos->link, &o->head))
		*ppos = NULL;

	/* Prepare a 'user_req' */
	mm_memcpy(&p->user_req.u, &pos->u, sizeof(pos->u));

	/* Set the command */
	p->user_req.cmd = ECORE_VLAN_MAC_ADD;

	/* Set vlan_mac_flags */
	p->user_req.vlan_mac_flags = pos->vlan_mac_flags;

	/* Set a restore bit */
	ECORE_SET_BIT_NA(RAMROD_RESTORE, &p->ramrod_flags);

	return ecore_config_vlan_mac(pdev, p);
}

/* ecore_exeq_get_mac/ecore_exeq_get_vlan/ecore_exeq_get_vlan_mac return a
 * pointer to an element with a specific criteria and NULL if such an element
 * hasn't been found.
 */
static struct ecore_exeq_elem *ecore_exeq_get_mac(
	struct ecore_exe_queue_obj *o,
	struct ecore_exeq_elem *elem)
{
	struct ecore_exeq_elem *pos;
	struct ecore_mac_ramrod_data *data = &elem->cmd_data.vlan_mac.u.mac;

	/* Check pending for execution commands */
	ECORE_LIST_FOR_EACH_ENTRY(pos, &o->exe_queue, link,
				  struct ecore_exeq_elem)
		if (mm_memcmp(&pos->cmd_data.vlan_mac.u.mac, data,
			      sizeof(*data)) &&
		    (pos->cmd_data.vlan_mac.cmd == elem->cmd_data.vlan_mac.cmd))
			return pos;

	return NULL;
}

static struct ecore_exeq_elem *ecore_exeq_get_vlan(
	struct ecore_exe_queue_obj *o,
	struct ecore_exeq_elem *elem)
{
	struct ecore_exeq_elem *pos;
	struct ecore_vlan_ramrod_data *data = &elem->cmd_data.vlan_mac.u.vlan;

	/* Check pending for execution commands */
	ECORE_LIST_FOR_EACH_ENTRY(pos, &o->exe_queue, link,
				  struct ecore_exeq_elem)
		if (mm_memcmp(&pos->cmd_data.vlan_mac.u.vlan, data,
			      sizeof(*data)) &&
		    (pos->cmd_data.vlan_mac.cmd == elem->cmd_data.vlan_mac.cmd))
			return pos;

	return NULL;
}

static struct ecore_exeq_elem *ecore_exeq_get_vlan_mac(
	struct ecore_exe_queue_obj *o,
	struct ecore_exeq_elem *elem)
{
	struct ecore_exeq_elem *pos;
	struct ecore_vlan_mac_ramrod_data *data =
		&elem->cmd_data.vlan_mac.u.vlan_mac;

	/* Check pending for execution commands */
	ECORE_LIST_FOR_EACH_ENTRY(pos, &o->exe_queue, link,
				  struct ecore_exeq_elem)
		if (mm_memcmp(&pos->cmd_data.vlan_mac.u.vlan_mac, data,
			      sizeof(*data)) &&
		    (pos->cmd_data.vlan_mac.cmd == elem->cmd_data.vlan_mac.cmd))
			return pos;

	return NULL;
}

/**
 * ecore_validate_vlan_mac_add - check if an ADD command can be executed
 *
 * @pdev:	device handle
 * @qo:		ecore_qable_obj
 * @elem:	ecore_exeq_elem
 *
 * Checks that the requested configuration can be added. If yes and if
 * requested, consume CAM credit.
 *
 * The 'validate' is run after the 'optimize'.
 *
 */
static INLINE int ecore_validate_vlan_mac_add(struct _lm_device_t *pdev,
					      union ecore_qable_obj *qo,
					      struct ecore_exeq_elem *elem)
{
	struct ecore_vlan_mac_obj *o = &qo->vlan_mac;
	struct ecore_exe_queue_obj *exeq = &o->exe_queue;
	int rc;

	/* Check the registry */
	rc = o->check_add(pdev, o, &elem->cmd_data.vlan_mac.u);
	if (rc) {
		ECORE_MSG(pdev, "ADD command is not allowed considering current registry state.\n");
		return rc;
	}

	/* Check if there is a pending ADD command for this
	 * MAC/VLAN/VLAN-MAC. Return an error if there is.
	 */
	if (exeq->get(exeq, elem)) {
		ECORE_MSG(pdev, "There is a pending ADD command already\n");
		return ECORE_EXISTS;
	}

	/* TODO: Check the pending MOVE from other objects where this
	 * object is a destination object.
	 */

	/* Consume the credit if not requested not to */
	if (!(ECORE_TEST_BIT(ECORE_DONT_CONSUME_CAM_CREDIT,
			     &elem->cmd_data.vlan_mac.vlan_mac_flags) ||
	    o->get_credit(o)))
		return ECORE_INVAL;

	return ECORE_SUCCESS;
}

/**
 * ecore_validate_vlan_mac_del - check if the DEL command can be executed
 *
 * @pdev:	device handle
 * @qo:		quable object to check
 * @elem:	element that needs to be deleted
 *
 * Checks that the requested configuration can be deleted. If yes and if
 * requested, returns a CAM credit.
 *
 * The 'validate' is run after the 'optimize'.
 */
static INLINE int ecore_validate_vlan_mac_del(struct _lm_device_t *pdev,
					      union ecore_qable_obj *qo,
					      struct ecore_exeq_elem *elem)
{
	struct ecore_vlan_mac_obj *o = &qo->vlan_mac;
	struct ecore_vlan_mac_registry_elem *pos;
	struct ecore_exe_queue_obj *exeq = &o->exe_queue;
	struct ecore_exeq_elem query_elem;

	/* If this classification can not be deleted (doesn't exist)
	 * - return a ECORE_EXIST.
	 */
	pos = o->check_del(pdev, o, &elem->cmd_data.vlan_mac.u);
	if (!pos) {
		ECORE_MSG(pdev, "DEL command is not allowed considering current registry state\n");
		return ECORE_EXISTS;
	}

	/* Check if there are pending DEL or MOVE commands for this
	 * MAC/VLAN/VLAN-MAC. Return an error if so.
	 */
	mm_memcpy(&query_elem, elem, sizeof(query_elem));

	/* Check for MOVE commands */
	query_elem.cmd_data.vlan_mac.cmd = ECORE_VLAN_MAC_MOVE;
	if (exeq->get(exeq, &query_elem)) {
		ECORE_ERR("There is a pending MOVE command already\n");
		return ECORE_INVAL;
	}

	/* Check for DEL commands */
	if (exeq->get(exeq, elem)) {
		ECORE_MSG(pdev, "There is a pending DEL command already\n");
		return ECORE_EXISTS;
	}

	/* Return the credit to the credit pool if not requested not to */
	if (!(ECORE_TEST_BIT(ECORE_DONT_CONSUME_CAM_CREDIT,
			     &elem->cmd_data.vlan_mac.vlan_mac_flags) ||
	    o->put_credit(o))) {
		ECORE_ERR("Failed to return a credit\n");
		return ECORE_INVAL;
	}

	return ECORE_SUCCESS;
}

/**
 * ecore_validate_vlan_mac_move - check if the MOVE command can be executed
 *
 * @pdev:	device handle
 * @qo:		quable object to check (source)
 * @elem:	element that needs to be moved
 *
 * Checks that the requested configuration can be moved. If yes and if
 * requested, returns a CAM credit.
 *
 * The 'validate' is run after the 'optimize'.
 */
static INLINE int ecore_validate_vlan_mac_move(struct _lm_device_t *pdev,
					       union ecore_qable_obj *qo,
					       struct ecore_exeq_elem *elem)
{
	struct ecore_vlan_mac_obj *src_o = &qo->vlan_mac;
	struct ecore_vlan_mac_obj *dest_o = elem->cmd_data.vlan_mac.target_obj;
	struct ecore_exeq_elem query_elem;
	struct ecore_exe_queue_obj *src_exeq = &src_o->exe_queue;
	struct ecore_exe_queue_obj *dest_exeq = &dest_o->exe_queue;

	/* Check if we can perform this operation based on the current registry
	 * state.
	 */
	if (!src_o->check_move(pdev, src_o, dest_o,
			       &elem->cmd_data.vlan_mac.u)) {
		ECORE_MSG(pdev, "MOVE command is not allowed considering current registry state\n");
		return ECORE_INVAL;
	}

	/* Check if there is an already pending DEL or MOVE command for the
	 * source object or ADD command for a destination object. Return an
	 * error if so.
	 */
	mm_memcpy(&query_elem, elem, sizeof(query_elem));

	/* Check DEL on source */
	query_elem.cmd_data.vlan_mac.cmd = ECORE_VLAN_MAC_DEL;
	if (src_exeq->get(src_exeq, &query_elem)) {
		ECORE_ERR("There is a pending DEL command on the source queue already\n");
		return ECORE_INVAL;
	}

	/* Check MOVE on source */
	if (src_exeq->get(src_exeq, elem)) {
		ECORE_MSG(pdev, "There is a pending MOVE command already\n");
		return ECORE_EXISTS;
	}

	/* Check ADD on destination */
	query_elem.cmd_data.vlan_mac.cmd = ECORE_VLAN_MAC_ADD;
	if (dest_exeq->get(dest_exeq, &query_elem)) {
		ECORE_ERR("There is a pending ADD command on the destination queue already\n");
		return ECORE_INVAL;
	}

	/* Consume the credit if not requested not to */
	if (!(ECORE_TEST_BIT(ECORE_DONT_CONSUME_CAM_CREDIT_DEST,
			     &elem->cmd_data.vlan_mac.vlan_mac_flags) ||
	    dest_o->get_credit(dest_o)))
		return ECORE_INVAL;

	if (!(ECORE_TEST_BIT(ECORE_DONT_CONSUME_CAM_CREDIT,
			     &elem->cmd_data.vlan_mac.vlan_mac_flags) ||
	    src_o->put_credit(src_o))) {
		/* return the credit taken from dest... */
		dest_o->put_credit(dest_o);
		return ECORE_INVAL;
	}

	return ECORE_SUCCESS;
}

static int ecore_validate_vlan_mac(struct _lm_device_t *pdev,
				   union ecore_qable_obj *qo,
				   struct ecore_exeq_elem *elem)
{
	switch (elem->cmd_data.vlan_mac.cmd) {
	case ECORE_VLAN_MAC_ADD:
		return ecore_validate_vlan_mac_add(pdev, qo, elem);
	case ECORE_VLAN_MAC_DEL:
		return ecore_validate_vlan_mac_del(pdev, qo, elem);
	case ECORE_VLAN_MAC_MOVE:
		return ecore_validate_vlan_mac_move(pdev, qo, elem);
	default:
		return ECORE_INVAL;
	}
}

static int ecore_remove_vlan_mac(struct _lm_device_t *pdev,
				  union ecore_qable_obj *qo,
				  struct ecore_exeq_elem *elem)
{
	int rc = 0;

	/* If consumption wasn't required, nothing to do */
	if (ECORE_TEST_BIT(ECORE_DONT_CONSUME_CAM_CREDIT,
			   &elem->cmd_data.vlan_mac.vlan_mac_flags))
		return ECORE_SUCCESS;

	switch (elem->cmd_data.vlan_mac.cmd) {
	case ECORE_VLAN_MAC_ADD:
	case ECORE_VLAN_MAC_MOVE:
		rc = qo->vlan_mac.put_credit(&qo->vlan_mac);
		break;
	case ECORE_VLAN_MAC_DEL:
		rc = qo->vlan_mac.get_credit(&qo->vlan_mac);
		break;
	default:
		return ECORE_INVAL;
	}

	if (rc != TRUE)
		return ECORE_INVAL;

	return ECORE_SUCCESS;
}

/**
 * ecore_wait_vlan_mac - passively wait for 5 seconds until all work completes.
 *
 * @pdev:	device handle
 * @o:		ecore_vlan_mac_obj
 *
 */
static int ecore_wait_vlan_mac(struct _lm_device_t *pdev,
			       struct ecore_vlan_mac_obj *o)
{
	int cnt = 5000, rc;
	struct ecore_exe_queue_obj *exeq = &o->exe_queue;
	struct ecore_raw_obj *raw = &o->raw;

	while (cnt--) {
		/* Wait for the current command to complete */
		rc = raw->wait_comp(pdev, raw);
		if (rc)
			return rc;

		/* Wait until there are no pending commands */
		if (!ecore_exe_queue_empty(exeq))
			mm_wait(pdev, 1000);
		else
			return ECORE_SUCCESS;
	}

	return ECORE_TIMEOUT;
}

static int __ecore_vlan_mac_execute_step(struct _lm_device_t *pdev,
					 struct ecore_vlan_mac_obj *o,
					 unsigned long *ramrod_flags)
{
	int rc = ECORE_SUCCESS;

	ECORE_SPIN_LOCK_BH(&o->exe_queue.lock);

	ECORE_MSG(pdev, "vlan_mac_execute_step - trying to take writer lock\n");
	rc = __ecore_vlan_mac_h_write_trylock(pdev, o);

	if (rc != ECORE_SUCCESS) {
		__ecore_vlan_mac_h_pend(pdev, o, *ramrod_flags);

		/** Calling function should not diffrentiate between this case
		 *  and the case in which there is already a pending ramrod
		 */
		rc = ECORE_PENDING;
	} else {
		rc = ecore_exe_queue_step(pdev, &o->exe_queue, ramrod_flags);
	}
	ECORE_SPIN_UNLOCK_BH(&o->exe_queue.lock);

	return rc;
}

/**
 * ecore_complete_vlan_mac - complete one VLAN-MAC ramrod
 *
 * @pdev:	device handle
 * @o:		ecore_vlan_mac_obj
 * @cqe:
 * @cont:	if TRUE schedule next execution chunk
 *
 */
static int ecore_complete_vlan_mac(struct _lm_device_t *pdev,
				   struct ecore_vlan_mac_obj *o,
				   union event_ring_elem *cqe,
				   unsigned long *ramrod_flags)
{
	struct ecore_raw_obj *r = &o->raw;
	int rc;

	/* Clearing the pending list & raw state should be made
	 * atomically (as execution flow assumes they represent the same)
	 */
	ECORE_SPIN_LOCK_BH(&o->exe_queue.lock);

	/* Reset pending list */
	__ecore_exe_queue_reset_pending(pdev, &o->exe_queue);

	/* Clear pending */
	r->clear_pending(r);

	ECORE_SPIN_UNLOCK_BH(&o->exe_queue.lock);

	/* If ramrod failed this is most likely a SW bug */
	if (cqe->message.error)
		return ECORE_INVAL;

	/* Run the next bulk of pending commands if requested */
	if (ECORE_TEST_BIT(RAMROD_CONT, ramrod_flags)) {
		rc = __ecore_vlan_mac_execute_step(pdev, o, ramrod_flags);
		if (rc < 0)
			return rc;
	}

	/* If there is more work to do return PENDING */
	if (!ecore_exe_queue_empty(&o->exe_queue))
		return ECORE_PENDING;

	return ECORE_SUCCESS;
}

/**
 * ecore_optimize_vlan_mac - optimize ADD and DEL commands.
 *
 * @pdev:	device handle
 * @o:		ecore_qable_obj
 * @elem:	ecore_exeq_elem
 */
static int ecore_optimize_vlan_mac(struct _lm_device_t *pdev,
				   union ecore_qable_obj *qo,
				   struct ecore_exeq_elem *elem)
{
	struct ecore_exeq_elem query, *pos;
	struct ecore_vlan_mac_obj *o = &qo->vlan_mac;
	struct ecore_exe_queue_obj *exeq = &o->exe_queue;

	mm_memcpy(&query, elem, sizeof(query));

	switch (elem->cmd_data.vlan_mac.cmd) {
	case ECORE_VLAN_MAC_ADD:
		query.cmd_data.vlan_mac.cmd = ECORE_VLAN_MAC_DEL;
		break;
	case ECORE_VLAN_MAC_DEL:
		query.cmd_data.vlan_mac.cmd = ECORE_VLAN_MAC_ADD;
		break;
	default:
		/* Don't handle anything other than ADD or DEL */
		return 0;
	}

	/* If we found the appropriate element - delete it */
	pos = exeq->get(exeq, &query);
	if (pos) {

		/* Return the credit of the optimized command */
		if (!ECORE_TEST_BIT(ECORE_DONT_CONSUME_CAM_CREDIT,
				     &pos->cmd_data.vlan_mac.vlan_mac_flags)) {
			if ((query.cmd_data.vlan_mac.cmd ==
			     ECORE_VLAN_MAC_ADD) && !o->put_credit(o)) {
				ECORE_ERR("Failed to return the credit for the optimized ADD command\n");
				return ECORE_INVAL;
			} else if (!o->get_credit(o)) { /* VLAN_MAC_DEL */
				ECORE_ERR("Failed to recover the credit from the optimized DEL command\n");
				return ECORE_INVAL;
			}
		}

		ECORE_MSG(pdev, "Optimizing %s command\n",
			  (elem->cmd_data.vlan_mac.cmd == ECORE_VLAN_MAC_ADD) ?
			  "ADD" : "DEL");

		ECORE_LIST_REMOVE_ENTRY(&pos->link, &exeq->exe_queue);
		ecore_exe_queue_free_elem(pdev, pos);
		return 1;
	}

	return 0;
}

/**
 * ecore_vlan_mac_get_registry_elem - prepare a registry element
 *
 * @pdev:  device handle
 * @o:
 * @elem:
 * @restore:
 * @re:
 *
 * prepare a registry element according to the current command request.
 */
static INLINE int ecore_vlan_mac_get_registry_elem(
	struct _lm_device_t *pdev,
	struct ecore_vlan_mac_obj *o,
	struct ecore_exeq_elem *elem,
	BOOL restore,
	struct ecore_vlan_mac_registry_elem **re)
{
	enum ecore_vlan_mac_cmd cmd = elem->cmd_data.vlan_mac.cmd;
	struct ecore_vlan_mac_registry_elem *reg_elem;

	/* Allocate a new registry element if needed. */
	if (!restore &&
	    ((cmd == ECORE_VLAN_MAC_ADD) || (cmd == ECORE_VLAN_MAC_MOVE))) {
		reg_elem = ECORE_ZALLOC(sizeof(*reg_elem), GFP_ATOMIC, pdev);
		if (!reg_elem)
			return ECORE_NOMEM;

		/* Get a new CAM offset */
		if (!o->get_cam_offset(o, &reg_elem->cam_offset)) {
			/* This shall never happen, because we have checked the
			 * CAM availability in the 'validate'.
			 */
			DbgBreakIf(1);
			ECORE_FREE(pdev, reg_elem, sizeof(*reg_elem));
			return ECORE_INVAL;
		}

		ECORE_MSG(pdev, "Got cam offset %d\n", reg_elem->cam_offset);

		/* Set a VLAN-MAC data */
		mm_memcpy(&reg_elem->u, &elem->cmd_data.vlan_mac.u,
			  sizeof(reg_elem->u));

		/* Copy the flags (needed for DEL and RESTORE flows) */
		reg_elem->vlan_mac_flags =
			elem->cmd_data.vlan_mac.vlan_mac_flags;
	} else /* DEL, RESTORE */
		reg_elem = o->check_del(pdev, o, &elem->cmd_data.vlan_mac.u);

	*re = reg_elem;
	return ECORE_SUCCESS;
}

/**
 * ecore_execute_vlan_mac - execute vlan mac command
 *
 * @pdev:		device handle
 * @qo:
 * @exe_chunk:
 * @ramrod_flags:
 *
 * go and send a ramrod!
 */
static int ecore_execute_vlan_mac(struct _lm_device_t *pdev,
				  union ecore_qable_obj *qo,
				  d_list_t *exe_chunk,
				  unsigned long *ramrod_flags)
{
	struct ecore_exeq_elem *elem;
	struct ecore_vlan_mac_obj *o = &qo->vlan_mac, *cam_obj;
	struct ecore_raw_obj *r = &o->raw;
	int rc, idx = 0;
	BOOL restore = ECORE_TEST_BIT(RAMROD_RESTORE, ramrod_flags);
	BOOL drv_only = ECORE_TEST_BIT(RAMROD_DRV_CLR_ONLY, ramrod_flags);
	struct ecore_vlan_mac_registry_elem *reg_elem;
	enum ecore_vlan_mac_cmd cmd;

	/* If DRIVER_ONLY execution is requested, cleanup a registry
	 * and exit. Otherwise send a ramrod to FW.
	 */
	if (!drv_only) {
		DbgBreakIf(r->check_pending(r));

		/* Set pending */
		r->set_pending(r);

		/* Fill the ramrod data */
		ECORE_LIST_FOR_EACH_ENTRY(elem, exe_chunk, link,
					  struct ecore_exeq_elem) {
			cmd = elem->cmd_data.vlan_mac.cmd;
			/* We will add to the target object in MOVE command, so
			 * change the object for a CAM search.
			 */
			if (cmd == ECORE_VLAN_MAC_MOVE)
				cam_obj = elem->cmd_data.vlan_mac.target_obj;
			else
				cam_obj = o;

			rc = ecore_vlan_mac_get_registry_elem(pdev, cam_obj,
							      elem, restore,
							      &reg_elem);
			if (rc)
				goto error_exit;

			DbgBreakIf(!reg_elem);

			/* Push a new entry into the registry */
			if (!restore &&
			    ((cmd == ECORE_VLAN_MAC_ADD) ||
			    (cmd == ECORE_VLAN_MAC_MOVE)))
				ECORE_LIST_PUSH_HEAD(&reg_elem->link,
						     &cam_obj->head);

			/* Configure a single command in a ramrod data buffer */
			o->set_one_rule(pdev, o, elem, idx,
					reg_elem->cam_offset);

			/* MOVE command consumes 2 entries in the ramrod data */
			if (cmd == ECORE_VLAN_MAC_MOVE)
				idx += 2;
			else
				idx++;
		}

		/* No need for an explicit memory barrier here as long as we
		 * ensure the ordering of writing to the SPQ element
		 * and updating of the SPQ producer which involves a memory
		 * read. If the memory read is removed we will have to put a
		 * full memory barrier there (inside ecore_sp_post()).
		 */
		rc = ecore_sp_post(pdev, o->ramrod_cmd, r->cid,
				   r->rdata_mapping.as_u64,
				   ETH_CONNECTION_TYPE);
		if (rc)
			goto error_exit;
	}

	/* Now, when we are done with the ramrod - clean up the registry */
	ECORE_LIST_FOR_EACH_ENTRY(elem, exe_chunk, link,
				  struct ecore_exeq_elem) {
		cmd = elem->cmd_data.vlan_mac.cmd;
		if ((cmd == ECORE_VLAN_MAC_DEL) ||
		    (cmd == ECORE_VLAN_MAC_MOVE)) {
			reg_elem = o->check_del(pdev, o,
						&elem->cmd_data.vlan_mac.u);

			DbgBreakIf(!reg_elem);

			o->put_cam_offset(o, reg_elem->cam_offset);
			ECORE_LIST_REMOVE_ENTRY(&reg_elem->link, &o->head);
			ECORE_FREE(pdev, reg_elem, sizeof(*reg_elem));
		}
	}

	if (!drv_only)
		return ECORE_PENDING;
	else
		return ECORE_SUCCESS;

error_exit:
	r->clear_pending(r);

	/* Cleanup a registry in case of a failure */
	ECORE_LIST_FOR_EACH_ENTRY(elem, exe_chunk, link,
				  struct ecore_exeq_elem) {
		cmd = elem->cmd_data.vlan_mac.cmd;

		if (cmd == ECORE_VLAN_MAC_MOVE)
			cam_obj = elem->cmd_data.vlan_mac.target_obj;
		else
			cam_obj = o;

		/* Delete all newly added above entries */
		if (!restore &&
		    ((cmd == ECORE_VLAN_MAC_ADD) ||
		    (cmd == ECORE_VLAN_MAC_MOVE))) {
			reg_elem = o->check_del(pdev, cam_obj,
						&elem->cmd_data.vlan_mac.u);
			if (reg_elem) {
				ECORE_LIST_REMOVE_ENTRY(&reg_elem->link,
							&cam_obj->head);
				ECORE_FREE(pdev, reg_elem, sizeof(*reg_elem));
			}
		}
	}

	return rc;
}

static INLINE int ecore_vlan_mac_push_new_cmd(
	struct _lm_device_t *pdev,
	struct ecore_vlan_mac_ramrod_params *p)
{
	struct ecore_exeq_elem *elem;
	struct ecore_vlan_mac_obj *o = p->vlan_mac_obj;
	BOOL restore = ECORE_TEST_BIT(RAMROD_RESTORE, &p->ramrod_flags);

	/* Allocate the execution queue element */
	elem = ecore_exe_queue_alloc_elem(pdev);
	if (!elem)
		return ECORE_NOMEM;

	/* Set the command 'length' */
	switch (p->user_req.cmd) {
	case ECORE_VLAN_MAC_MOVE:
		elem->cmd_len = 2;
		break;
	default:
		elem->cmd_len = 1;
	}

	/* Fill the object specific info */
	mm_memcpy(&elem->cmd_data.vlan_mac, &p->user_req, sizeof(p->user_req));

	/* Try to add a new command to the pending list */
	return ecore_exe_queue_add(pdev, &o->exe_queue, elem, restore);
}

/**
 * ecore_config_vlan_mac - configure VLAN/MAC/VLAN_MAC filtering rules.
 *
 * @pdev:  device handle
 * @p:
 *
 */
int ecore_config_vlan_mac(struct _lm_device_t *pdev,
			   struct ecore_vlan_mac_ramrod_params *p)
{
	int rc = ECORE_SUCCESS;
	struct ecore_vlan_mac_obj *o = p->vlan_mac_obj;
	unsigned long *ramrod_flags = &p->ramrod_flags;
	BOOL cont = ECORE_TEST_BIT(RAMROD_CONT, ramrod_flags);
	struct ecore_raw_obj *raw = &o->raw;

	/*
	 * Add new elements to the execution list for commands that require it.
	 */
	if (!cont) {
		rc = ecore_vlan_mac_push_new_cmd(pdev, p);
		if (rc)
			return rc;
	}

	/* If nothing will be executed further in this iteration we want to
	 * return PENDING if there are pending commands
	 */
	if (!ecore_exe_queue_empty(&o->exe_queue))
		rc = ECORE_PENDING;

	if (ECORE_TEST_BIT(RAMROD_DRV_CLR_ONLY, ramrod_flags))  {
		ECORE_MSG(pdev, "RAMROD_DRV_CLR_ONLY requested: clearing a pending bit.\n");
		raw->clear_pending(raw);
	}

	/* Execute commands if required */
	if (cont || ECORE_TEST_BIT(RAMROD_EXEC, ramrod_flags) ||
	    ECORE_TEST_BIT(RAMROD_COMP_WAIT, ramrod_flags)) {
		rc = __ecore_vlan_mac_execute_step(pdev, p->vlan_mac_obj,
						   &p->ramrod_flags);
		if (rc < 0)
			return rc;
	}

	/* RAMROD_COMP_WAIT is a superset of RAMROD_EXEC. If it was set
	 * then user want to wait until the last command is done.
	 */
	if (ECORE_TEST_BIT(RAMROD_COMP_WAIT, &p->ramrod_flags)) {
		/* Wait maximum for the current exe_queue length iterations plus
		 * one (for the current pending command).
		 */
		int max_iterations = ecore_exe_queue_length(&o->exe_queue) + 1;

		while (!ecore_exe_queue_empty(&o->exe_queue) &&
		       max_iterations--) {

			/* Wait for the current command to complete */
			rc = raw->wait_comp(pdev, raw);
			if (rc)
				return rc;

			/* Make a next step */
			rc = __ecore_vlan_mac_execute_step(pdev,
							   p->vlan_mac_obj,
							   &p->ramrod_flags);
			if (rc < 0)
				return rc;
		}

		return ECORE_SUCCESS;
	}

	return rc;
}

/**
 * ecore_vlan_mac_del_all - delete elements with given vlan_mac_flags spec
 *
 * @pdev:		device handle
 * @o:
 * @vlan_mac_flags:
 * @ramrod_flags:	execution flags to be used for this deletion
 *
 * if the last operation has completed successfully and there are no
 * more elements left, positive value if the last operation has completed
 * successfully and there are more previously configured elements, negative
 * value is current operation has failed.
 */
static int ecore_vlan_mac_del_all(struct _lm_device_t *pdev,
				  struct ecore_vlan_mac_obj *o,
				  unsigned long *vlan_mac_flags,
				  unsigned long *ramrod_flags)
{
	struct ecore_vlan_mac_registry_elem *pos = NULL;
	struct ecore_vlan_mac_ramrod_params p;
	struct ecore_exe_queue_obj *exeq = &o->exe_queue;
	struct ecore_exeq_elem *exeq_pos, *exeq_pos_n;
	unsigned long flags;
	int read_lock;
	int rc = 0;

	/* Clear pending commands first */

	ECORE_SPIN_LOCK_BH(&exeq->lock);

	ECORE_LIST_FOR_EACH_ENTRY_SAFE(exeq_pos, exeq_pos_n,
				       &exeq->exe_queue, link,
				       struct ecore_exeq_elem) {
		flags = exeq_pos->cmd_data.vlan_mac.vlan_mac_flags;
		if (ECORE_VLAN_MAC_CMP_FLAGS(flags) ==
		    ECORE_VLAN_MAC_CMP_FLAGS(*vlan_mac_flags)) {
			rc = exeq->remove(pdev, exeq->owner, exeq_pos);
			if (rc) {
				ECORE_ERR("Failed to remove command\n");
				ECORE_SPIN_UNLOCK_BH(&exeq->lock);
				return rc;
			}
			ECORE_LIST_REMOVE_ENTRY(&exeq_pos->link,
						&exeq->exe_queue);
			ecore_exe_queue_free_elem(pdev, exeq_pos);
		}
	}

	ECORE_SPIN_UNLOCK_BH(&exeq->lock);

	/* Prepare a command request */
	mm_memset(&p, 0, sizeof(p));
	p.vlan_mac_obj = o;
	p.ramrod_flags = *ramrod_flags;
	p.user_req.cmd = ECORE_VLAN_MAC_DEL;

	/* Add all but the last VLAN-MAC to the execution queue without actually
	 * execution anything.
	 */
	ECORE_CLEAR_BIT_NA(RAMROD_COMP_WAIT, &p.ramrod_flags);
	ECORE_CLEAR_BIT_NA(RAMROD_EXEC, &p.ramrod_flags);
	ECORE_CLEAR_BIT_NA(RAMROD_CONT, &p.ramrod_flags);

	ECORE_MSG(pdev, "vlan_mac_del_all -- taking vlan_mac_lock (reader)\n");
	read_lock = ecore_vlan_mac_h_read_lock(pdev, o);
	if (read_lock != ECORE_SUCCESS)
		return read_lock;

	ECORE_LIST_FOR_EACH_ENTRY(pos, &o->head, link,
				  struct ecore_vlan_mac_registry_elem) {
		flags = pos->vlan_mac_flags;
		if (ECORE_VLAN_MAC_CMP_FLAGS(flags) ==
		    ECORE_VLAN_MAC_CMP_FLAGS(*vlan_mac_flags)) {
			p.user_req.vlan_mac_flags = pos->vlan_mac_flags;
			mm_memcpy(&p.user_req.u, &pos->u, sizeof(pos->u));
			rc = ecore_config_vlan_mac(pdev, &p);
			if (rc < 0) {
				ECORE_ERR("Failed to add a new DEL command\n");
				ecore_vlan_mac_h_read_unlock(pdev, o);
				return rc;
			}
		}
	}

	ECORE_MSG(pdev, "vlan_mac_del_all -- releasing vlan_mac_lock (reader)\n");
	ecore_vlan_mac_h_read_unlock(pdev, o);

	p.ramrod_flags = *ramrod_flags;
	ECORE_SET_BIT_NA(RAMROD_CONT, &p.ramrod_flags);

	return ecore_config_vlan_mac(pdev, &p);
}

static INLINE void ecore_init_raw_obj(struct ecore_raw_obj *raw, u8 cl_id,
	u32 cid, u8 func_id, void *rdata, lm_address_t rdata_mapping, int state,
	unsigned long *pstate, ecore_obj_type type)
{
	raw->func_id = func_id;
	raw->cid = cid;
	raw->cl_id = cl_id;
	raw->rdata = rdata;
	raw->rdata_mapping = rdata_mapping;
	raw->state = state;
	raw->pstate = pstate;
	raw->obj_type = type;
	raw->check_pending = ecore_raw_check_pending;
	raw->clear_pending = ecore_raw_clear_pending;
	raw->set_pending = ecore_raw_set_pending;
	raw->wait_comp = ecore_raw_wait;
}

static INLINE void ecore_init_vlan_mac_common(struct ecore_vlan_mac_obj *o,
	u8 cl_id, u32 cid, u8 func_id, void *rdata, lm_address_t rdata_mapping,
	int state, unsigned long *pstate, ecore_obj_type type,
	struct ecore_credit_pool_obj *macs_pool,
	struct ecore_credit_pool_obj *vlans_pool)
{
	ECORE_LIST_INIT(&o->head);
	o->head_reader = 0;
	o->head_exe_request = FALSE;
	o->saved_ramrod_flags = 0;

	o->macs_pool = macs_pool;
	o->vlans_pool = vlans_pool;

	o->delete_all = ecore_vlan_mac_del_all;
	o->restore = ecore_vlan_mac_restore;
	o->complete = ecore_complete_vlan_mac;
	o->wait = ecore_wait_vlan_mac;

	ecore_init_raw_obj(&o->raw, cl_id, cid, func_id, rdata, rdata_mapping,
			   state, pstate, type);
}

void ecore_init_mac_obj(struct _lm_device_t *pdev,
			struct ecore_vlan_mac_obj *mac_obj,
			u8 cl_id, u32 cid, u8 func_id, void *rdata,
			lm_address_t rdata_mapping, int state,
			unsigned long *pstate, ecore_obj_type type,
			struct ecore_credit_pool_obj *macs_pool)
{
	union ecore_qable_obj *qable_obj = (union ecore_qable_obj *)mac_obj;

	ecore_init_vlan_mac_common(mac_obj, cl_id, cid, func_id, rdata,
				   rdata_mapping, state, pstate, type,
				   macs_pool, NULL);

	/* CAM credit pool handling */
	mac_obj->get_credit = ecore_get_credit_mac;
	mac_obj->put_credit = ecore_put_credit_mac;
	mac_obj->get_cam_offset = ecore_get_cam_offset_mac;
	mac_obj->put_cam_offset = ecore_put_cam_offset_mac;

	if (CHIP_IS_E1x(pdev)) {
		mac_obj->set_one_rule      = ecore_set_one_mac_e1x;
		mac_obj->check_del         = ecore_check_mac_del;
		mac_obj->check_add         = ecore_check_mac_add;
		mac_obj->check_move        = ecore_check_move_always_err;
		mac_obj->ramrod_cmd        = RAMROD_CMD_ID_ETH_SET_MAC;

		/* Exe Queue */
		ecore_exe_queue_init(pdev,
				     &mac_obj->exe_queue, 1, qable_obj,
				     ecore_validate_vlan_mac,
				     ecore_remove_vlan_mac,
				     ecore_optimize_vlan_mac,
				     ecore_execute_vlan_mac,
				     ecore_exeq_get_mac);
	} else {
		mac_obj->set_one_rule      = ecore_set_one_mac_e2;
		mac_obj->check_del         = ecore_check_mac_del;
		mac_obj->check_add         = ecore_check_mac_add;
		mac_obj->check_move        = ecore_check_move;
		mac_obj->ramrod_cmd        =
			RAMROD_CMD_ID_ETH_CLASSIFICATION_RULES;
		mac_obj->get_n_elements    = ecore_get_n_elements;

		/* Exe Queue */
		ecore_exe_queue_init(pdev,
				     &mac_obj->exe_queue, CLASSIFY_RULES_COUNT,
				     qable_obj, ecore_validate_vlan_mac,
				     ecore_remove_vlan_mac,
				     ecore_optimize_vlan_mac,
				     ecore_execute_vlan_mac,
				     ecore_exeq_get_mac);
	}
}

void ecore_init_vlan_obj(struct _lm_device_t *pdev,
			 struct ecore_vlan_mac_obj *vlan_obj,
			 u8 cl_id, u32 cid, u8 func_id, void *rdata,
			 lm_address_t rdata_mapping, int state,
			 unsigned long *pstate, ecore_obj_type type,
			 struct ecore_credit_pool_obj *vlans_pool)
{
	union ecore_qable_obj *qable_obj = (union ecore_qable_obj *)vlan_obj;

	ecore_init_vlan_mac_common(vlan_obj, cl_id, cid, func_id, rdata,
				   rdata_mapping, state, pstate, type, NULL,
				   vlans_pool);

	vlan_obj->get_credit = ecore_get_credit_vlan;
	vlan_obj->put_credit = ecore_put_credit_vlan;
	vlan_obj->get_cam_offset = ecore_get_cam_offset_vlan;
	vlan_obj->put_cam_offset = ecore_put_cam_offset_vlan;

	if (CHIP_IS_E1x(pdev)) {
		ECORE_ERR("Do not support chips others than E2 and newer\n");
		BUG();
	} else {
		vlan_obj->set_one_rule      = ecore_set_one_vlan_e2;
		vlan_obj->check_del         = ecore_check_vlan_del;
		vlan_obj->check_add         = ecore_check_vlan_add;
		vlan_obj->check_move        = ecore_check_move;
		vlan_obj->ramrod_cmd        =
			RAMROD_CMD_ID_ETH_CLASSIFICATION_RULES;
		vlan_obj->get_n_elements    = ecore_get_n_elements;

		/* Exe Queue */
		ecore_exe_queue_init(pdev,
				     &vlan_obj->exe_queue, CLASSIFY_RULES_COUNT,
				     qable_obj, ecore_validate_vlan_mac,
				     ecore_remove_vlan_mac,
				     ecore_optimize_vlan_mac,
				     ecore_execute_vlan_mac,
				     ecore_exeq_get_vlan);
	}
}

void ecore_init_vlan_mac_obj(struct _lm_device_t *pdev,
			     struct ecore_vlan_mac_obj *vlan_mac_obj,
			     u8 cl_id, u32 cid, u8 func_id, void *rdata,
			     lm_address_t rdata_mapping, int state,
			     unsigned long *pstate, ecore_obj_type type,
			     struct ecore_credit_pool_obj *macs_pool,
			     struct ecore_credit_pool_obj *vlans_pool)
{
	union ecore_qable_obj *qable_obj =
		(union ecore_qable_obj *)vlan_mac_obj;

	ecore_init_vlan_mac_common(vlan_mac_obj, cl_id, cid, func_id, rdata,
				   rdata_mapping, state, pstate, type,
				   macs_pool, vlans_pool);

	/* CAM pool handling */
	vlan_mac_obj->get_credit = ecore_get_credit_vlan_mac;
	vlan_mac_obj->put_credit = ecore_put_credit_vlan_mac;
	/* CAM offset is relevant for 57710 and 57711 chips only which have a
	 * single CAM for both MACs and VLAN-MAC pairs. So the offset
	 * will be taken from MACs' pool object only.
	 */
	vlan_mac_obj->get_cam_offset = ecore_get_cam_offset_mac;
	vlan_mac_obj->put_cam_offset = ecore_put_cam_offset_mac;

	if (CHIP_IS_E1(pdev)) {
		ECORE_ERR("Do not support chips others than E2\n");
		BUG();
	} else if (CHIP_IS_E1H(pdev)) {
		vlan_mac_obj->set_one_rule      = ecore_set_one_vlan_mac_e1h;
		vlan_mac_obj->check_del         = ecore_check_vlan_mac_del;
		vlan_mac_obj->check_add         = ecore_check_vlan_mac_add;
		vlan_mac_obj->check_move        = ecore_check_move_always_err;
		vlan_mac_obj->ramrod_cmd        = RAMROD_CMD_ID_ETH_SET_MAC;

		/* Exe Queue */
		ecore_exe_queue_init(pdev,
				     &vlan_mac_obj->exe_queue, 1, qable_obj,
				     ecore_validate_vlan_mac,
				     ecore_remove_vlan_mac,
				     ecore_optimize_vlan_mac,
				     ecore_execute_vlan_mac,
				     ecore_exeq_get_vlan_mac);
	} else {
		vlan_mac_obj->set_one_rule      = ecore_set_one_vlan_mac_e2;
		vlan_mac_obj->check_del         = ecore_check_vlan_mac_del;
		vlan_mac_obj->check_add         = ecore_check_vlan_mac_add;
		vlan_mac_obj->check_move        = ecore_check_move;
		vlan_mac_obj->ramrod_cmd        =
			RAMROD_CMD_ID_ETH_CLASSIFICATION_RULES;

		/* Exe Queue */
		ecore_exe_queue_init(pdev,
				     &vlan_mac_obj->exe_queue,
				     CLASSIFY_RULES_COUNT,
				     qable_obj, ecore_validate_vlan_mac,
				     ecore_remove_vlan_mac,
				     ecore_optimize_vlan_mac,
				     ecore_execute_vlan_mac,
				     ecore_exeq_get_vlan_mac);
	}
}

/* RX_MODE verbs: DROP_ALL/ACCEPT_ALL/ACCEPT_ALL_MULTI/ACCEPT_ALL_VLAN/NORMAL */
static INLINE void __storm_memset_mac_filters(struct _lm_device_t *pdev,
			struct tstorm_eth_mac_filter_config *mac_filters,
			u16 pf_id)
{
	size_t size = sizeof(struct tstorm_eth_mac_filter_config);

	u32 addr = BAR_TSTRORM_INTMEM +
			TSTORM_MAC_FILTER_CONFIG_OFFSET(pf_id);

	__storm_memset_struct(pdev, addr, size, (u32 *)mac_filters);
}

static int ecore_set_rx_mode_e1x(struct _lm_device_t *pdev,
				 struct ecore_rx_mode_ramrod_params *p)
{
	/* update the pdev MAC filter structure */
	u32 mask = (1 << p->cl_id);

	struct tstorm_eth_mac_filter_config *mac_filters =
		(struct tstorm_eth_mac_filter_config *)p->rdata;

	/* initial setting is drop-all */
	u8 drop_all_ucast = 1, drop_all_mcast = 1;
	u8 accp_all_ucast = 0, accp_all_bcast = 0, accp_all_mcast = 0;
	u8 unmatched_unicast = 0;

    /* In e1x there we only take into account rx accept flag since tx switching
     * isn't enabled. */
	if (ECORE_TEST_BIT(ECORE_ACCEPT_UNICAST, &p->rx_accept_flags))
		/* accept matched ucast */
		drop_all_ucast = 0;

	if (ECORE_TEST_BIT(ECORE_ACCEPT_MULTICAST, &p->rx_accept_flags))
		/* accept matched mcast */
		drop_all_mcast = 0;

	if (ECORE_TEST_BIT(ECORE_ACCEPT_ALL_UNICAST, &p->rx_accept_flags)) {
		/* accept all mcast */
		drop_all_ucast = 0;
		accp_all_ucast = 1;
	}
	if (ECORE_TEST_BIT(ECORE_ACCEPT_ALL_MULTICAST, &p->rx_accept_flags)) {
		/* accept all mcast */
		drop_all_mcast = 0;
		accp_all_mcast = 1;
	}
	if (ECORE_TEST_BIT(ECORE_ACCEPT_BROADCAST, &p->rx_accept_flags))
		/* accept (all) bcast */
		accp_all_bcast = 1;
	if (ECORE_TEST_BIT(ECORE_ACCEPT_UNMATCHED, &p->rx_accept_flags))
		/* accept unmatched unicasts */
		unmatched_unicast = 1;

	mac_filters->ucast_drop_all = drop_all_ucast ?
		mac_filters->ucast_drop_all | mask :
		mac_filters->ucast_drop_all & ~mask;

	mac_filters->mcast_drop_all = drop_all_mcast ?
		mac_filters->mcast_drop_all | mask :
		mac_filters->mcast_drop_all & ~mask;

	mac_filters->ucast_accept_all = accp_all_ucast ?
		mac_filters->ucast_accept_all | mask :
		mac_filters->ucast_accept_all & ~mask;

	mac_filters->mcast_accept_all = accp_all_mcast ?
		mac_filters->mcast_accept_all | mask :
		mac_filters->mcast_accept_all & ~mask;

	mac_filters->bcast_accept_all = accp_all_bcast ?
		mac_filters->bcast_accept_all | mask :
		mac_filters->bcast_accept_all & ~mask;

	mac_filters->unmatched_unicast = unmatched_unicast ?
		mac_filters->unmatched_unicast | mask :
		mac_filters->unmatched_unicast & ~mask;

	ECORE_MSG(pdev, "drop_ucast 0x%x\ndrop_mcast 0x%x\n accp_ucast 0x%x\n"
			 "accp_mcast 0x%x\naccp_bcast 0x%x\n",
	   mac_filters->ucast_drop_all, mac_filters->mcast_drop_all,
	   mac_filters->ucast_accept_all, mac_filters->mcast_accept_all,
	   mac_filters->bcast_accept_all);

	/* write the MAC filter structure*/
	__storm_memset_mac_filters(pdev, mac_filters, p->func_id);

	/* The operation is completed */
	ECORE_CLEAR_BIT(p->state, p->pstate);
	smp_mb__after_atomic();

	return ECORE_SUCCESS;
}

/* Setup ramrod data */
static INLINE void ecore_rx_mode_set_rdata_hdr_e2(u32 cid,
				struct eth_classify_header *hdr,
				u8 rule_cnt)
{
	hdr->echo = mm_cpu_to_le32(cid);
	hdr->rule_cnt = rule_cnt;
}

static INLINE void ecore_rx_mode_set_cmd_state_e2(struct _lm_device_t *pdev,
				unsigned long *accept_flags,
				struct eth_filter_rules_cmd *cmd,
				BOOL clear_accept_all)
{
	u16 state;

	/* start with 'drop-all' */
	state = ETH_FILTER_RULES_CMD_UCAST_DROP_ALL |
		ETH_FILTER_RULES_CMD_MCAST_DROP_ALL;

	if (ECORE_TEST_BIT(ECORE_ACCEPT_UNICAST, accept_flags))
		state &= ~ETH_FILTER_RULES_CMD_UCAST_DROP_ALL;

	if (ECORE_TEST_BIT(ECORE_ACCEPT_MULTICAST, accept_flags))
		state &= ~ETH_FILTER_RULES_CMD_MCAST_DROP_ALL;

	if (ECORE_TEST_BIT(ECORE_ACCEPT_ALL_UNICAST, accept_flags)) {
		state &= ~ETH_FILTER_RULES_CMD_UCAST_DROP_ALL;
		state |= ETH_FILTER_RULES_CMD_UCAST_ACCEPT_ALL;
	}

	if (ECORE_TEST_BIT(ECORE_ACCEPT_ALL_MULTICAST, accept_flags)) {
		state |= ETH_FILTER_RULES_CMD_MCAST_ACCEPT_ALL;
		state &= ~ETH_FILTER_RULES_CMD_MCAST_DROP_ALL;
	}
	if (ECORE_TEST_BIT(ECORE_ACCEPT_BROADCAST, accept_flags))
		state |= ETH_FILTER_RULES_CMD_BCAST_ACCEPT_ALL;

	if (ECORE_TEST_BIT(ECORE_ACCEPT_UNMATCHED, accept_flags)) {
		state &= ~ETH_FILTER_RULES_CMD_UCAST_DROP_ALL;
		state |= ETH_FILTER_RULES_CMD_UCAST_ACCEPT_UNMATCHED;
	}
	if (ECORE_TEST_BIT(ECORE_ACCEPT_ANY_VLAN, accept_flags))
		state |= ETH_FILTER_RULES_CMD_ACCEPT_ANY_VLAN;

	/* Clear ACCEPT_ALL_XXX flags for FCoE L2 Queue */
	if (clear_accept_all) {
		state &= ~ETH_FILTER_RULES_CMD_MCAST_ACCEPT_ALL;
		state &= ~ETH_FILTER_RULES_CMD_BCAST_ACCEPT_ALL;
		state &= ~ETH_FILTER_RULES_CMD_UCAST_ACCEPT_ALL;
		state &= ~ETH_FILTER_RULES_CMD_UCAST_ACCEPT_UNMATCHED;
	}

	cmd->state = mm_cpu_to_le16(state);
}

static int ecore_set_rx_mode_e2(struct _lm_device_t *pdev,
				struct ecore_rx_mode_ramrod_params *p)
{
	struct eth_filter_rules_ramrod_data *data = p->rdata;
	int rc;
	u8 rule_idx = 0;

	/* Reset the ramrod data buffer */
	mm_memset(data, 0, sizeof(*data));

	/* Setup ramrod data */

	/* Tx (internal switching) */
	if (ECORE_TEST_BIT(RAMROD_TX, &p->ramrod_flags)) {
		data->rules[rule_idx].client_id = p->cl_id;
		data->rules[rule_idx].func_id = p->func_id;

		data->rules[rule_idx].cmd_general_data =
			ETH_FILTER_RULES_CMD_TX_CMD;

		ecore_rx_mode_set_cmd_state_e2(pdev, &p->tx_accept_flags,
					       &(data->rules[rule_idx++]),
					       FALSE);
	}

	/* Rx */
	if (ECORE_TEST_BIT(RAMROD_RX, &p->ramrod_flags)) {
		data->rules[rule_idx].client_id = p->cl_id;
		data->rules[rule_idx].func_id = p->func_id;

		data->rules[rule_idx].cmd_general_data =
			ETH_FILTER_RULES_CMD_RX_CMD;

		ecore_rx_mode_set_cmd_state_e2(pdev, &p->rx_accept_flags,
					       &(data->rules[rule_idx++]),
					       FALSE);
	}

	/* If FCoE Queue configuration has been requested configure the Rx and
	 * internal switching modes for this queue in separate rules.
	 *
	 * FCoE queue shell never be set to ACCEPT_ALL packets of any sort:
	 * MCAST_ALL, UCAST_ALL, BCAST_ALL and UNMATCHED.
	 */
	if (ECORE_TEST_BIT(ECORE_RX_MODE_FCOE_ETH, &p->rx_mode_flags)) {
		/*  Tx (internal switching) */
		if (ECORE_TEST_BIT(RAMROD_TX, &p->ramrod_flags)) {
			data->rules[rule_idx].client_id = FCOE_CID(pdev);
			data->rules[rule_idx].func_id = p->func_id;

			data->rules[rule_idx].cmd_general_data =
						ETH_FILTER_RULES_CMD_TX_CMD;

			ecore_rx_mode_set_cmd_state_e2(pdev, &p->tx_accept_flags,
						       &(data->rules[rule_idx]),
						       TRUE);
			rule_idx++;
		}

		/* Rx */
		if (ECORE_TEST_BIT(RAMROD_RX, &p->ramrod_flags)) {
			data->rules[rule_idx].client_id = FCOE_CID(pdev);
			data->rules[rule_idx].func_id = p->func_id;

			data->rules[rule_idx].cmd_general_data =
						ETH_FILTER_RULES_CMD_RX_CMD;

			ecore_rx_mode_set_cmd_state_e2(pdev, &p->rx_accept_flags,
						       &(data->rules[rule_idx]),
						       TRUE);
			rule_idx++;
		}
	}

	/* Set the ramrod header (most importantly - number of rules to
	 * configure).
	 */
	ecore_rx_mode_set_rdata_hdr_e2(p->cid, &data->header, rule_idx);

	ECORE_MSG(pdev, "About to configure %d rules, rx_accept_flags 0x%lx, tx_accept_flags 0x%lx\n",
		  data->header.rule_cnt, p->rx_accept_flags,
		  p->tx_accept_flags);

	/* No need for an explicit memory barrier here as long as we
	 * ensure the ordering of writing to the SPQ element
	 * and updating of the SPQ producer which involves a memory
	 * read. If the memory read is removed we will have to put a
	 * full memory barrier there (inside ecore_sp_post()).
	 */

	/* Send a ramrod */
	rc = ecore_sp_post(pdev,
			   RAMROD_CMD_ID_ETH_FILTER_RULES,
			   p->cid,
			   p->rdata_mapping.as_u64,
			   ETH_CONNECTION_TYPE);
	if (rc)
		return rc;

	/* Ramrod completion is pending */
	return ECORE_PENDING;
}

static int ecore_wait_rx_mode_comp_e2(struct _lm_device_t *pdev,
				      struct ecore_rx_mode_ramrod_params *p)
{
	return ecore_state_wait(pdev, p->state, p->pstate);
}

static int ecore_empty_rx_mode_wait(struct _lm_device_t *pdev,
				    struct ecore_rx_mode_ramrod_params *p)
{
	/* Do nothing */
	return ECORE_SUCCESS;
}

int ecore_config_rx_mode(struct _lm_device_t *pdev,
			 struct ecore_rx_mode_ramrod_params *p)
{
	int rc;

	/* Configure the new classification in the chip */
	rc = p->rx_mode_obj->config_rx_mode(pdev, p);
	if (rc < 0)
		return rc;

	/* Wait for a ramrod completion if was requested */
	if (ECORE_TEST_BIT(RAMROD_COMP_WAIT, &p->ramrod_flags)) {
		rc = p->rx_mode_obj->wait_comp(pdev, p);
		if (rc)
			return rc;
	}

	return rc;
}

void ecore_init_rx_mode_obj(struct _lm_device_t *pdev,
			    struct ecore_rx_mode_obj *o)
{
	if (CHIP_IS_E1x(pdev)) {
		o->wait_comp      = ecore_empty_rx_mode_wait;
		o->config_rx_mode = ecore_set_rx_mode_e1x;
	} else {
		o->wait_comp      = ecore_wait_rx_mode_comp_e2;
		o->config_rx_mode = ecore_set_rx_mode_e2;
	}
}

/********************* Multicast verbs: SET, CLEAR ****************************/
static INLINE u8 ecore_mcast_bin_from_mac(u8 *mac)
{
	return (ecore_crc32_le(0, mac, ETH_ALEN) >> 24) & 0xff;
}

struct ecore_mcast_mac_elem {
	d_list_entry_t link;
	u8 mac[ETH_ALEN];
	u8 pad[2]; /* For a natural alignment of the following buffer */
};

struct ecore_pending_mcast_cmd {
	d_list_entry_t link;
	int type; /* ECORE_MCAST_CMD_X */
	union {
		d_list_t macs_head;
		u32 macs_num; /* Needed for DEL command */
		int next_bin; /* Needed for RESTORE flow with aprox match */
	} data;

	BOOL done; /* set to TRUE, when the command has been handled,
		    * practically used in 57712 handling only, where one pending
		    * command may be handled in a few operations. As long as for
		    * other chips every operation handling is completed in a
		    * single ramrod, there is no need to utilize this field.
		    */
#ifndef ECORE_ERASE
	u32 alloc_len; /* passed to ECORE_FREE */
#endif
};

static int ecore_mcast_wait(struct _lm_device_t *pdev,
			    struct ecore_mcast_obj *o)
{
	if (ecore_state_wait(pdev, o->sched_state, o->raw.pstate) ||
			o->raw.wait_comp(pdev, &o->raw))
		return ECORE_TIMEOUT;

	return ECORE_SUCCESS;
}

static int ecore_mcast_enqueue_cmd(struct _lm_device_t *pdev,
				   struct ecore_mcast_obj *o,
				   struct ecore_mcast_ramrod_params *p,
				   enum ecore_mcast_cmd cmd)
{
	int total_sz;
	struct ecore_pending_mcast_cmd *new_cmd;
	struct ecore_mcast_mac_elem *cur_mac = NULL;
	struct ecore_mcast_list_elem *pos;
	int macs_list_len = ((cmd == ECORE_MCAST_CMD_ADD) ?
			     p->mcast_list_len : 0);

	/* If the command is empty ("handle pending commands only"), break */
	if (!p->mcast_list_len)
		return ECORE_SUCCESS;

	total_sz = sizeof(*new_cmd) +
		macs_list_len * sizeof(struct ecore_mcast_mac_elem);

	/* Add mcast is called under spin_lock, thus calling with GFP_ATOMIC */
	new_cmd = ECORE_ZALLOC(total_sz, GFP_ATOMIC, pdev);

	if (!new_cmd)
		return ECORE_NOMEM;

	ECORE_MSG(pdev, "About to enqueue a new %d command. macs_list_len=%d\n",
		  cmd, macs_list_len);

	ECORE_LIST_INIT(&new_cmd->data.macs_head);

	new_cmd->type = cmd;
	new_cmd->done = FALSE;
#ifndef ECORE_ERASE
	new_cmd->alloc_len = total_sz;
#endif

	switch (cmd) {
	case ECORE_MCAST_CMD_ADD:
		cur_mac = (struct ecore_mcast_mac_elem *)
			  ((u8 *)new_cmd + sizeof(*new_cmd));

		/* Push the MACs of the current command into the pending command
		 * MACs list: FIFO
		 */
		ECORE_LIST_FOR_EACH_ENTRY(pos, &p->mcast_list, link,
					  struct ecore_mcast_list_elem) {
			mm_memcpy(cur_mac->mac, pos->mac, ETH_ALEN);
			ECORE_LIST_PUSH_TAIL(&cur_mac->link,
					     &new_cmd->data.macs_head);
			cur_mac++;
		}

		break;

	case ECORE_MCAST_CMD_DEL:
		new_cmd->data.macs_num = p->mcast_list_len;
		break;

	case ECORE_MCAST_CMD_RESTORE:
		new_cmd->data.next_bin = 0;
		break;

	default:
		ECORE_FREE(pdev, new_cmd, total_sz);
		ECORE_ERR("Unknown command: %d\n", cmd);
		return ECORE_INVAL;
	}

	/* Push the new pending command to the tail of the pending list: FIFO */
	ECORE_LIST_PUSH_TAIL(&new_cmd->link, &o->pending_cmds_head);

	o->set_sched(o);

	return ECORE_PENDING;
}

/**
 * ecore_mcast_get_next_bin - get the next set bin (index)
 *
 * @o:
 * @last:	index to start looking from (including)
 *
 * returns the next found (set) bin or a negative value if none is found.
 */
static INLINE int ecore_mcast_get_next_bin(struct ecore_mcast_obj *o, int last)
{
	int i, j, inner_start = last % BIT_VEC64_ELEM_SZ;

	for (i = last / BIT_VEC64_ELEM_SZ; i < ECORE_MCAST_VEC_SZ; i++) {
		if (o->registry.aprox_match.vec[i])
			for (j = inner_start; j < BIT_VEC64_ELEM_SZ; j++) {
				int cur_bit = j + BIT_VEC64_ELEM_SZ * i;
				if (BIT_VEC64_TEST_BIT(o->registry.aprox_match.
						       vec, cur_bit)) {
					return cur_bit;
				}
			}
		inner_start = 0;
	}

	/* None found */
	return -1;
}

/**
 * ecore_mcast_clear_first_bin - find the first set bin and clear it
 *
 * @o:
 *
 * returns the index of the found bin or -1 if none is found
 */
static INLINE int ecore_mcast_clear_first_bin(struct ecore_mcast_obj *o)
{
	int cur_bit = ecore_mcast_get_next_bin(o, 0);

	if (cur_bit >= 0)
		BIT_VEC64_CLEAR_BIT(o->registry.aprox_match.vec, cur_bit);

	return cur_bit;
}

static INLINE u8 ecore_mcast_get_rx_tx_flag(struct ecore_mcast_obj *o)
{
	struct ecore_raw_obj *raw = &o->raw;
	u8 rx_tx_flag = 0;

	if ((raw->obj_type == ECORE_OBJ_TYPE_TX) ||
	    (raw->obj_type == ECORE_OBJ_TYPE_RX_TX))
		rx_tx_flag |= ETH_MULTICAST_RULES_CMD_TX_CMD;

	if ((raw->obj_type == ECORE_OBJ_TYPE_RX) ||
	    (raw->obj_type == ECORE_OBJ_TYPE_RX_TX))
		rx_tx_flag |= ETH_MULTICAST_RULES_CMD_RX_CMD;

	return rx_tx_flag;
}

static void ecore_mcast_set_one_rule_e2(struct _lm_device_t *pdev,
					struct ecore_mcast_obj *o, int idx,
					union ecore_mcast_config_data *cfg_data,
					enum ecore_mcast_cmd cmd)
{
	struct ecore_raw_obj *r = &o->raw;
	struct eth_multicast_rules_ramrod_data *data =
		(struct eth_multicast_rules_ramrod_data *)(r->rdata);
	u8 func_id = r->func_id;
	u8 rx_tx_add_flag = ecore_mcast_get_rx_tx_flag(o);
	int bin;

	if ((cmd == ECORE_MCAST_CMD_ADD) || (cmd == ECORE_MCAST_CMD_RESTORE))
		rx_tx_add_flag |= ETH_MULTICAST_RULES_CMD_IS_ADD;

	data->rules[idx].cmd_general_data |= rx_tx_add_flag;

	/* Get a bin and update a bins' vector */
	switch (cmd) {
	case ECORE_MCAST_CMD_ADD:
		bin = ecore_mcast_bin_from_mac(cfg_data->mac);
		BIT_VEC64_SET_BIT(o->registry.aprox_match.vec, bin);
		break;

	case ECORE_MCAST_CMD_DEL:
		/* If there were no more bins to clear
		 * (ecore_mcast_clear_first_bin() returns -1) then we would
		 * clear any (0xff) bin.
		 * See ecore_mcast_validate_e2() for explanation when it may
		 * happen.
		 */
		bin = ecore_mcast_clear_first_bin(o);
		break;

	case ECORE_MCAST_CMD_RESTORE:
		bin = cfg_data->bin;
		break;

	default:
		ECORE_ERR("Unknown command: %d\n", cmd);
		return;
	}

	ECORE_MSG(pdev, "%s bin %d\n",
		  ((rx_tx_add_flag & ETH_MULTICAST_RULES_CMD_IS_ADD) ?
		   "Setting"  : "Clearing"), bin);

	data->rules[idx].bin_id    = (u8)bin;
	data->rules[idx].func_id   = func_id;
	data->rules[idx].engine_id = o->engine_id;
}

/**
 * ecore_mcast_handle_restore_cmd_e2 - restore configuration from the registry
 *
 * @pdev:	device handle
 * @o:
 * @start_bin:	index in the registry to start from (including)
 * @rdata_idx:	index in the ramrod data to start from
 *
 * returns last handled bin index or -1 if all bins have been handled
 */
static INLINE int ecore_mcast_handle_restore_cmd_e2(
	struct _lm_device_t *pdev, struct ecore_mcast_obj *o , int start_bin,
	int *rdata_idx)
{
	int cur_bin, cnt = *rdata_idx;
	union ecore_mcast_config_data cfg_data = {NULL};

	/* go through the registry and configure the bins from it */
	for (cur_bin = ecore_mcast_get_next_bin(o, start_bin); cur_bin >= 0;
	    cur_bin = ecore_mcast_get_next_bin(o, cur_bin + 1)) {

		cfg_data.bin = (u8)cur_bin;
		o->set_one_rule(pdev, o, cnt, &cfg_data,
				ECORE_MCAST_CMD_RESTORE);

		cnt++;

		ECORE_MSG(pdev, "About to configure a bin %d\n", cur_bin);

		/* Break if we reached the maximum number
		 * of rules.
		 */
		if (cnt >= o->max_cmd_len)
			break;
	}

	*rdata_idx = cnt;

	return cur_bin;
}

static INLINE void ecore_mcast_hdl_pending_add_e2(struct _lm_device_t *pdev,
	struct ecore_mcast_obj *o, struct ecore_pending_mcast_cmd *cmd_pos,
	int *line_idx)
{
	struct ecore_mcast_mac_elem *pmac_pos, *pmac_pos_n;
	int cnt = *line_idx;
	union ecore_mcast_config_data cfg_data = {NULL};

	ECORE_LIST_FOR_EACH_ENTRY_SAFE(pmac_pos, pmac_pos_n,
		&cmd_pos->data.macs_head, link, struct ecore_mcast_mac_elem) {

		cfg_data.mac = &pmac_pos->mac[0];
		o->set_one_rule(pdev, o, cnt, &cfg_data, cmd_pos->type);

		cnt++;

		ECORE_MSG(pdev, "About to configure %02x:%02x:%02x:%02x:%02x:%02x mcast MAC\n",
			  pmac_pos->mac[0], pmac_pos->mac[1], pmac_pos->mac[2], pmac_pos->mac[3], pmac_pos->mac[4], pmac_pos->mac[5]);

		ECORE_LIST_REMOVE_ENTRY(&pmac_pos->link,
					&cmd_pos->data.macs_head);

		/* Break if we reached the maximum number
		 * of rules.
		 */
		if (cnt >= o->max_cmd_len)
			break;
	}

	*line_idx = cnt;

	/* if no more MACs to configure - we are done */
	if (ECORE_LIST_IS_EMPTY(&cmd_pos->data.macs_head))
		cmd_pos->done = TRUE;
}

static INLINE void ecore_mcast_hdl_pending_del_e2(struct _lm_device_t *pdev,
	struct ecore_mcast_obj *o, struct ecore_pending_mcast_cmd *cmd_pos,
	int *line_idx)
{
	int cnt = *line_idx;

	while (cmd_pos->data.macs_num) {
		o->set_one_rule(pdev, o, cnt, NULL, cmd_pos->type);

		cnt++;

		cmd_pos->data.macs_num--;

		  ECORE_MSG(pdev, "Deleting MAC. %d left,cnt is %d\n",
				  cmd_pos->data.macs_num, cnt);

		/* Break if we reached the maximum
		 * number of rules.
		 */
		if (cnt >= o->max_cmd_len)
			break;
	}

	*line_idx = cnt;

	/* If we cleared all bins - we are done */
	if (!cmd_pos->data.macs_num)
		cmd_pos->done = TRUE;
}

static INLINE void ecore_mcast_hdl_pending_restore_e2(struct _lm_device_t *pdev,
	struct ecore_mcast_obj *o, struct ecore_pending_mcast_cmd *cmd_pos,
	int *line_idx)
{
	cmd_pos->data.next_bin = o->hdl_restore(pdev, o, cmd_pos->data.next_bin,
						line_idx);

	if (cmd_pos->data.next_bin < 0)
		/* If o->set_restore returned -1 we are done */
		cmd_pos->done = TRUE;
	else
		/* Start from the next bin next time */
		cmd_pos->data.next_bin++;
}

static INLINE int ecore_mcast_handle_pending_cmds_e2(struct _lm_device_t *pdev,
				struct ecore_mcast_ramrod_params *p)
{
	struct ecore_pending_mcast_cmd *cmd_pos, *cmd_pos_n;
	int cnt = 0;
	struct ecore_mcast_obj *o = p->mcast_obj;

	ECORE_LIST_FOR_EACH_ENTRY_SAFE(cmd_pos, cmd_pos_n,
		&o->pending_cmds_head, link, struct ecore_pending_mcast_cmd) {
		switch (cmd_pos->type) {
		case ECORE_MCAST_CMD_ADD:
			ecore_mcast_hdl_pending_add_e2(pdev, o, cmd_pos, &cnt);
			break;

		case ECORE_MCAST_CMD_DEL:
			ecore_mcast_hdl_pending_del_e2(pdev, o, cmd_pos, &cnt);
			break;

		case ECORE_MCAST_CMD_RESTORE:
			ecore_mcast_hdl_pending_restore_e2(pdev, o, cmd_pos,
							   &cnt);
			break;

		default:
			ECORE_ERR("Unknown command: %d\n", cmd_pos->type);
			return ECORE_INVAL;
		}

		/* If the command has been completed - remove it from the list
		 * and free the memory
		 */
		if (cmd_pos->done) {
			ECORE_LIST_REMOVE_ENTRY(&cmd_pos->link,
						&o->pending_cmds_head);
			ECORE_FREE(pdev, cmd_pos, cmd_pos->alloc_len);
		}

		/* Break if we reached the maximum number of rules */
		if (cnt >= o->max_cmd_len)
			break;
	}

	return cnt;
}

static INLINE void ecore_mcast_hdl_add(struct _lm_device_t *pdev,
	struct ecore_mcast_obj *o, struct ecore_mcast_ramrod_params *p,
	int *line_idx)
{
	struct ecore_mcast_list_elem *mlist_pos;
	union ecore_mcast_config_data cfg_data = {NULL};
	int cnt = *line_idx;

	ECORE_LIST_FOR_EACH_ENTRY(mlist_pos, &p->mcast_list, link,
				  struct ecore_mcast_list_elem) {
		cfg_data.mac = mlist_pos->mac;
		o->set_one_rule(pdev, o, cnt, &cfg_data, ECORE_MCAST_CMD_ADD);

		cnt++;

		ECORE_MSG(pdev, "About to configure %02x:%02x:%02x:%02x:%02x:%02x mcast MAC\n",
			  mlist_pos->mac[0], mlist_pos->mac[1], mlist_pos->mac[2], mlist_pos->mac[3], mlist_pos->mac[4], mlist_pos->mac[5]);
	}

	*line_idx = cnt;
}

static INLINE void ecore_mcast_hdl_del(struct _lm_device_t *pdev,
	struct ecore_mcast_obj *o, struct ecore_mcast_ramrod_params *p,
	int *line_idx)
{
	int cnt = *line_idx, i;

	for (i = 0; i < p->mcast_list_len; i++) {
		o->set_one_rule(pdev, o, cnt, NULL, ECORE_MCAST_CMD_DEL);

		cnt++;

		ECORE_MSG(pdev, "Deleting MAC. %d left\n",
			  p->mcast_list_len - i - 1);
	}

	*line_idx = cnt;
}

/**
 * ecore_mcast_handle_current_cmd -
 *
 * @pdev:	device handle
 * @p:
 * @cmd:
 * @start_cnt:	first line in the ramrod data that may be used
 *
 * This function is called iff there is enough place for the current command in
 * the ramrod data.
 * Returns number of lines filled in the ramrod data in total.
 */
static INLINE int ecore_mcast_handle_current_cmd(struct _lm_device_t *pdev,
			struct ecore_mcast_ramrod_params *p,
			enum ecore_mcast_cmd cmd,
			int start_cnt)
{
	struct ecore_mcast_obj *o = p->mcast_obj;
	int cnt = start_cnt;

	ECORE_MSG(pdev, "p->mcast_list_len=%d\n", p->mcast_list_len);

	switch (cmd) {
	case ECORE_MCAST_CMD_ADD:
		ecore_mcast_hdl_add(pdev, o, p, &cnt);
		break;

	case ECORE_MCAST_CMD_DEL:
		ecore_mcast_hdl_del(pdev, o, p, &cnt);
		break;

	case ECORE_MCAST_CMD_RESTORE:
		o->hdl_restore(pdev, o, 0, &cnt);
		break;

	default:
		ECORE_ERR("Unknown command: %d\n", cmd);
		return ECORE_INVAL;
	}

	/* The current command has been handled */
	p->mcast_list_len = 0;

	return cnt;
}

static int ecore_mcast_validate_e2(struct _lm_device_t *pdev,
				   struct ecore_mcast_ramrod_params *p,
				   enum ecore_mcast_cmd cmd)
{
	struct ecore_mcast_obj *o = p->mcast_obj;
	int reg_sz = o->get_registry_size(o);

	switch (cmd) {
	/* DEL command deletes all currently configured MACs */
	case ECORE_MCAST_CMD_DEL:
		o->set_registry_size(o, 0);
		/* Don't break */

	/* RESTORE command will restore the entire multicast configuration */
	case ECORE_MCAST_CMD_RESTORE:
		/* Here we set the approximate amount of work to do, which in
		 * fact may be only less as some MACs in postponed ADD
		 * command(s) scheduled before this command may fall into
		 * the same bin and the actual number of bins set in the
		 * registry would be less than we estimated here. See
		 * ecore_mcast_set_one_rule_e2() for further details.
		 */
		p->mcast_list_len = reg_sz;
		break;

	case ECORE_MCAST_CMD_ADD:
	case ECORE_MCAST_CMD_CONT:
		/* Here we assume that all new MACs will fall into new bins.
		 * However we will correct the real registry size after we
		 * handle all pending commands.
		 */
		o->set_registry_size(o, reg_sz + p->mcast_list_len);
		break;

	default:
		ECORE_ERR("Unknown command: %d\n", cmd);
		return ECORE_INVAL;
	}

	/* Increase the total number of MACs pending to be configured */
	o->total_pending_num += p->mcast_list_len;

	return ECORE_SUCCESS;
}

static void ecore_mcast_revert_e2(struct _lm_device_t *pdev,
				      struct ecore_mcast_ramrod_params *p,
				      int old_num_bins)
{
	struct ecore_mcast_obj *o = p->mcast_obj;

	o->set_registry_size(o, old_num_bins);
	o->total_pending_num -= p->mcast_list_len;
}

/**
 * ecore_mcast_set_rdata_hdr_e2 - sets a header values
 *
 * @pdev:	device handle
 * @p:
 * @len:	number of rules to handle
 */
static INLINE void ecore_mcast_set_rdata_hdr_e2(struct _lm_device_t *pdev,
					struct ecore_mcast_ramrod_params *p,
					u8 len)
{
	struct ecore_raw_obj *r = &p->mcast_obj->raw;
	struct eth_multicast_rules_ramrod_data *data =
		(struct eth_multicast_rules_ramrod_data *)(r->rdata);

	data->header.echo = mm_cpu_to_le32((r->cid & ECORE_SWCID_MASK) |
					(ECORE_FILTER_MCAST_PENDING <<
					 ECORE_SWCID_SHIFT));
	data->header.rule_cnt = len;
}

/**
 * ecore_mcast_refresh_registry_e2 - recalculate the actual number of set bins
 *
 * @pdev:	device handle
 * @o:
 *
 * Recalculate the actual number of set bins in the registry using Brian
 * Kernighan's algorithm: it's execution complexity is as a number of set bins.
 *
 * returns 0 for the compliance with ecore_mcast_refresh_registry_e1().
 */
static INLINE int ecore_mcast_refresh_registry_e2(struct _lm_device_t *pdev,
						  struct ecore_mcast_obj *o)
{
	int i, cnt = 0;
	u64 elem;

	for (i = 0; i < ECORE_MCAST_VEC_SZ; i++) {
		elem = o->registry.aprox_match.vec[i];
		for (; elem; cnt++)
			elem &= elem - 1;
	}

	o->set_registry_size(o, cnt);

	return ECORE_SUCCESS;
}

static int ecore_mcast_setup_e2(struct _lm_device_t *pdev,
				struct ecore_mcast_ramrod_params *p,
				enum ecore_mcast_cmd cmd)
{
	struct ecore_raw_obj *raw = &p->mcast_obj->raw;
	struct ecore_mcast_obj *o = p->mcast_obj;
	struct eth_multicast_rules_ramrod_data *data =
		(struct eth_multicast_rules_ramrod_data *)(raw->rdata);
	int cnt = 0, rc;

	/* Reset the ramrod data buffer */
	mm_memset(data, 0, sizeof(*data));

	cnt = ecore_mcast_handle_pending_cmds_e2(pdev, p);

	/* If there are no more pending commands - clear SCHEDULED state */
	if (ECORE_LIST_IS_EMPTY(&o->pending_cmds_head))
		o->clear_sched(o);

	/* The below may be TRUE iff there was enough room in ramrod
	 * data for all pending commands and for the current
	 * command. Otherwise the current command would have been added
	 * to the pending commands and p->mcast_list_len would have been
	 * zeroed.
	 */
	if (p->mcast_list_len > 0)
		cnt = ecore_mcast_handle_current_cmd(pdev, p, cmd, cnt);

	/* We've pulled out some MACs - update the total number of
	 * outstanding.
	 */
	o->total_pending_num -= cnt;

	/* send a ramrod */
	DbgBreakIf(o->total_pending_num < 0);
	DbgBreakIf(cnt > o->max_cmd_len);

	ecore_mcast_set_rdata_hdr_e2(pdev, p, (u8)cnt);

	/* Update a registry size if there are no more pending operations.
	 *
	 * We don't want to change the value of the registry size if there are
	 * pending operations because we want it to always be equal to the
	 * exact or the approximate number (see ecore_mcast_validate_e2()) of
	 * set bins after the last requested operation in order to properly
	 * evaluate the size of the next DEL/RESTORE operation.
	 *
	 * Note that we update the registry itself during command(s) handling
	 * - see ecore_mcast_set_one_rule_e2(). That's because for 57712 we
	 * aggregate multiple commands (ADD/DEL/RESTORE) into one ramrod but
	 * with a limited amount of update commands (per MAC/bin) and we don't
	 * know in this scope what the actual state of bins configuration is
	 * going to be after this ramrod.
	 */
	if (!o->total_pending_num)
		ecore_mcast_refresh_registry_e2(pdev, o);

	/* If CLEAR_ONLY was requested - don't send a ramrod and clear
	 * RAMROD_PENDING status immediately.
	 */
	if (ECORE_TEST_BIT(RAMROD_DRV_CLR_ONLY, &p->ramrod_flags)) {
		raw->clear_pending(raw);
		return ECORE_SUCCESS;
	} else {
		/* No need for an explicit memory barrier here as long as we
		 * ensure the ordering of writing to the SPQ element
		 * and updating of the SPQ producer which involves a memory
		 * read. If the memory read is removed we will have to put a
		 * full memory barrier there (inside ecore_sp_post()).
		 */

		/* Send a ramrod */
		rc = ecore_sp_post( pdev,
				    RAMROD_CMD_ID_ETH_MULTICAST_RULES,
				    raw->cid,
				    raw->rdata_mapping.as_u64,
				    ETH_CONNECTION_TYPE);
		if (rc)
			return rc;

		/* Ramrod completion is pending */
		return ECORE_PENDING;
	}
}

static int ecore_mcast_validate_e1h(struct _lm_device_t *pdev,
				    struct ecore_mcast_ramrod_params *p,
				    enum ecore_mcast_cmd cmd)
{
	/* Mark, that there is a work to do */
	if ((cmd == ECORE_MCAST_CMD_DEL) || (cmd == ECORE_MCAST_CMD_RESTORE))
		p->mcast_list_len = 1;

	return ECORE_SUCCESS;
}

static void ecore_mcast_revert_e1h(struct _lm_device_t *pdev,
				       struct ecore_mcast_ramrod_params *p,
				       int old_num_bins)
{
	/* Do nothing */
}

#define ECORE_57711_SET_MC_FILTER(filter, bit) \
do { \
	(filter)[(bit) >> 5] |= (1 << ((bit) & 0x1f)); \
} while (0)

static INLINE void ecore_mcast_hdl_add_e1h(struct _lm_device_t *pdev,
					   struct ecore_mcast_obj *o,
					   struct ecore_mcast_ramrod_params *p,
					   u32 *mc_filter)
{
	struct ecore_mcast_list_elem *mlist_pos;
	int bit;

	ECORE_LIST_FOR_EACH_ENTRY(mlist_pos, &p->mcast_list, link,
				  struct ecore_mcast_list_elem) {
		bit = ecore_mcast_bin_from_mac(mlist_pos->mac);
		ECORE_57711_SET_MC_FILTER(mc_filter, bit);

		ECORE_MSG(pdev, "About to configure %02x:%02x:%02x:%02x:%02x:%02x mcast MAC, bin %d\n",
			  mlist_pos->mac[0], mlist_pos->mac[1], mlist_pos->mac[2], mlist_pos->mac[3], mlist_pos->mac[4], mlist_pos->mac[5], bit);

		/* bookkeeping... */
		BIT_VEC64_SET_BIT(o->registry.aprox_match.vec,
				  bit);
	}
}

static INLINE void ecore_mcast_hdl_restore_e1h(struct _lm_device_t *pdev,
	struct ecore_mcast_obj *o, struct ecore_mcast_ramrod_params *p,
	u32 *mc_filter)
{
	int bit;

	for (bit = ecore_mcast_get_next_bin(o, 0);
	     bit >= 0;
	     bit = ecore_mcast_get_next_bin(o, bit + 1)) {
		ECORE_57711_SET_MC_FILTER(mc_filter, bit);
		ECORE_MSG(pdev, "About to set bin %d\n", bit);
	}
}

/* On 57711 we write the multicast MACs' approximate match
 * table by directly into the TSTORM's internal RAM. So we don't
 * really need to handle any tricks to make it work.
 */
static int ecore_mcast_setup_e1h(struct _lm_device_t *pdev,
				 struct ecore_mcast_ramrod_params *p,
				 enum ecore_mcast_cmd cmd)
{
	int i;
	struct ecore_mcast_obj *o = p->mcast_obj;
	struct ecore_raw_obj *r = &o->raw;

	/* If CLEAR_ONLY has been requested - clear the registry
	 * and clear a pending bit.
	 */
	if (!ECORE_TEST_BIT(RAMROD_DRV_CLR_ONLY, &p->ramrod_flags)) {
		u32 mc_filter[MC_HASH_SIZE] = {0};

		/* Set the multicast filter bits before writing it into
		 * the internal memory.
		 */
		switch (cmd) {
		case ECORE_MCAST_CMD_ADD:
			ecore_mcast_hdl_add_e1h(pdev, o, p, mc_filter);
			break;

		case ECORE_MCAST_CMD_DEL:
			ECORE_MSG(pdev,
				  "Invalidating multicast MACs configuration\n");

			/* clear the registry */
			mm_memset(o->registry.aprox_match.vec, 0,
			       sizeof(o->registry.aprox_match.vec));
			break;

		case ECORE_MCAST_CMD_RESTORE:
			ecore_mcast_hdl_restore_e1h(pdev, o, p, mc_filter);
			break;

		default:
			ECORE_ERR("Unknown command: %d\n", cmd);
			return ECORE_INVAL;
		}

		/* Set the mcast filter in the internal memory */
		for (i = 0; i < MC_HASH_SIZE; i++)
			REG_WR(pdev, MC_HASH_OFFSET(pdev, i), mc_filter[i]);
	} else
		/* clear the registry */
		mm_memset(o->registry.aprox_match.vec, 0,
		       sizeof(o->registry.aprox_match.vec));

	/* We are done */
	r->clear_pending(r);

	return ECORE_SUCCESS;
}

static int ecore_mcast_validate_e1(struct _lm_device_t *pdev,
				   struct ecore_mcast_ramrod_params *p,
				   enum ecore_mcast_cmd cmd)
{
	struct ecore_mcast_obj *o = p->mcast_obj;
	int reg_sz = o->get_registry_size(o);

	switch (cmd) {
	/* DEL command deletes all currently configured MACs */
	case ECORE_MCAST_CMD_DEL:
		o->set_registry_size(o, 0);
		/* Don't break */

	/* RESTORE command will restore the entire multicast configuration */
	case ECORE_MCAST_CMD_RESTORE:
		p->mcast_list_len = reg_sz;
		  ECORE_MSG(pdev, "Command %d, p->mcast_list_len=%d\n",
				  cmd, p->mcast_list_len);
		break;

	case ECORE_MCAST_CMD_ADD:
	case ECORE_MCAST_CMD_CONT:
		/* Multicast MACs on 57710 are configured as unicast MACs and
		 * there is only a limited number of CAM entries for that
		 * matter.
		 */
		if (p->mcast_list_len > o->max_cmd_len) {
			ECORE_ERR("Can't configure more than %d multicast MACs on 57710\n",
				  o->max_cmd_len);
			return ECORE_INVAL;
		}
		/* Every configured MAC should be cleared if DEL command is
		 * called. Only the last ADD command is relevant as long as
		 * every ADD commands overrides the previous configuration.
		 */
		ECORE_MSG(pdev, "p->mcast_list_len=%d\n", p->mcast_list_len);
		if (p->mcast_list_len > 0)
			o->set_registry_size(o, p->mcast_list_len);

		break;

	default:
		ECORE_ERR("Unknown command: %d\n", cmd);
		return ECORE_INVAL;
	}

	/* We want to ensure that commands are executed one by one for 57710.
	 * Therefore each none-empty command will consume o->max_cmd_len.
	 */
	if (p->mcast_list_len)
		o->total_pending_num += o->max_cmd_len;

	return ECORE_SUCCESS;
}

static void ecore_mcast_revert_e1(struct _lm_device_t *pdev,
				      struct ecore_mcast_ramrod_params *p,
				      int old_num_macs)
{
	struct ecore_mcast_obj *o = p->mcast_obj;

	o->set_registry_size(o, old_num_macs);

	/* If current command hasn't been handled yet and we are
	 * here means that it's meant to be dropped and we have to
	 * update the number of outstanding MACs accordingly.
	 */
	if (p->mcast_list_len)
		o->total_pending_num -= o->max_cmd_len;
}

static void ecore_mcast_set_one_rule_e1(struct _lm_device_t *pdev,
					struct ecore_mcast_obj *o, int idx,
					union ecore_mcast_config_data *cfg_data,
					enum ecore_mcast_cmd cmd)
{
	struct ecore_raw_obj *r = &o->raw;
	struct mac_configuration_cmd *data =
		(struct mac_configuration_cmd *)(r->rdata);

	/* copy mac */
	if ((cmd == ECORE_MCAST_CMD_ADD) || (cmd == ECORE_MCAST_CMD_RESTORE)) {
		ecore_set_fw_mac_addr(&data->config_table[idx].msb_mac_addr,
				      &data->config_table[idx].middle_mac_addr,
				      &data->config_table[idx].lsb_mac_addr,
				      cfg_data->mac);

		data->config_table[idx].vlan_id = 0;
		data->config_table[idx].pf_id = r->func_id;
		data->config_table[idx].clients_bit_vector =
			mm_cpu_to_le32(1 << r->cl_id);

		ECORE_SET_FLAG(data->config_table[idx].flags,
			       MAC_CONFIGURATION_ENTRY_ACTION_TYPE,
			       T_ETH_MAC_COMMAND_SET);
	}
}

/**
 * ecore_mcast_set_rdata_hdr_e1  - set header values in mac_configuration_cmd
 *
 * @pdev:	device handle
 * @p:
 * @len:	number of rules to handle
 */
static INLINE void ecore_mcast_set_rdata_hdr_e1(struct _lm_device_t *pdev,
					struct ecore_mcast_ramrod_params *p,
					u8 len)
{
	struct ecore_raw_obj *r = &p->mcast_obj->raw;
	struct mac_configuration_cmd *data =
		(struct mac_configuration_cmd *)(r->rdata);

	u8 offset = (CHIP_REV_IS_SLOW(pdev) ?
		     ECORE_MAX_EMUL_MULTI*(1 + r->func_id) :
		     ECORE_MAX_MULTICAST*(1 + r->func_id));

	data->hdr.offset = offset;
	data->hdr.client_id = mm_cpu_to_le16(0xff);
	data->hdr.echo = mm_cpu_to_le32((r->cid & ECORE_SWCID_MASK) |
				     (ECORE_FILTER_MCAST_PENDING <<
				      ECORE_SWCID_SHIFT));
	data->hdr.length = len;
}

/**
 * ecore_mcast_handle_restore_cmd_e1 - restore command for 57710
 *
 * @pdev:	device handle
 * @o:
 * @start_idx:	index in the registry to start from
 * @rdata_idx:	index in the ramrod data to start from
 *
 * restore command for 57710 is like all other commands - always a stand alone
 * command - start_idx and rdata_idx will always be 0. This function will always
 * succeed.
 * returns -1 to comply with 57712 variant.
 */
static INLINE int ecore_mcast_handle_restore_cmd_e1(
	struct _lm_device_t *pdev, struct ecore_mcast_obj *o , int start_idx,
	int *rdata_idx)
{
	struct ecore_mcast_mac_elem *elem;
	int i = 0;
	union ecore_mcast_config_data cfg_data = {NULL};

	/* go through the registry and configure the MACs from it. */
	ECORE_LIST_FOR_EACH_ENTRY(elem, &o->registry.exact_match.macs, link,
				  struct ecore_mcast_mac_elem) {
		cfg_data.mac = &elem->mac[0];
		o->set_one_rule(pdev, o, i, &cfg_data, ECORE_MCAST_CMD_RESTORE);

		i++;

		ECORE_MSG(pdev, "About to configure %02x:%02x:%02x:%02x:%02x:%02x mcast MAC\n",
			  cfg_data.mac[0], cfg_data.mac[1], cfg_data.mac[2], cfg_data.mac[3], cfg_data.mac[4], cfg_data.mac[5]);
	}

	*rdata_idx = i;

	return -1;
}

static INLINE int ecore_mcast_handle_pending_cmds_e1(
	struct _lm_device_t *pdev, struct ecore_mcast_ramrod_params *p)
{
	struct ecore_pending_mcast_cmd *cmd_pos;
	struct ecore_mcast_mac_elem *pmac_pos;
	struct ecore_mcast_obj *o = p->mcast_obj;
	union ecore_mcast_config_data cfg_data = {NULL};
	int cnt = 0;

	/* If nothing to be done - return */
	if (ECORE_LIST_IS_EMPTY(&o->pending_cmds_head))
		return 0;

	/* Handle the first command */
	cmd_pos = ECORE_LIST_FIRST_ENTRY(&o->pending_cmds_head,
					 struct ecore_pending_mcast_cmd, link);

	switch (cmd_pos->type) {
	case ECORE_MCAST_CMD_ADD:
		ECORE_LIST_FOR_EACH_ENTRY(pmac_pos, &cmd_pos->data.macs_head,
					  link, struct ecore_mcast_mac_elem) {
			cfg_data.mac = &pmac_pos->mac[0];
			o->set_one_rule(pdev, o, cnt, &cfg_data, cmd_pos->type);

			cnt++;

			ECORE_MSG(pdev, "About to configure %02x:%02x:%02x:%02x:%02x:%02x mcast MAC\n",
				  pmac_pos->mac[0], pmac_pos->mac[1], pmac_pos->mac[2], pmac_pos->mac[3], pmac_pos->mac[4], pmac_pos->mac[5]);
		}
		break;

	case ECORE_MCAST_CMD_DEL:
		cnt = cmd_pos->data.macs_num;
		ECORE_MSG(pdev, "About to delete %d multicast MACs\n", cnt);
		break;

	case ECORE_MCAST_CMD_RESTORE:
		o->hdl_restore(pdev, o, 0, &cnt);
		break;

	default:
		ECORE_ERR("Unknown command: %d\n", cmd_pos->type);
		return ECORE_INVAL;
	}

	ECORE_LIST_REMOVE_ENTRY(&cmd_pos->link, &o->pending_cmds_head);
	ECORE_FREE(pdev, cmd_pos, cmd_pos->alloc_len);

	return cnt;
}

/**
 * ecore_get_fw_mac_addr - revert the ecore_set_fw_mac_addr().
 *
 * @fw_hi:
 * @fw_mid:
 * @fw_lo:
 * @mac:
 */
static INLINE void ecore_get_fw_mac_addr(__le16 *fw_hi, __le16 *fw_mid,
					 __le16 *fw_lo, u8 *mac)
{
	mac[1] = ((u8 *)fw_hi)[0];
	mac[0] = ((u8 *)fw_hi)[1];
	mac[3] = ((u8 *)fw_mid)[0];
	mac[2] = ((u8 *)fw_mid)[1];
	mac[5] = ((u8 *)fw_lo)[0];
	mac[4] = ((u8 *)fw_lo)[1];
}

/**
 * ecore_mcast_refresh_registry_e1 -
 *
 * @pdev:	device handle
 * @cnt:
 *
 * Check the ramrod data first entry flag to see if it's a DELETE or ADD command
 * and update the registry correspondingly: if ADD - allocate a memory and add
 * the entries to the registry (list), if DELETE - clear the registry and free
 * the memory.
 */
static INLINE int ecore_mcast_refresh_registry_e1(struct _lm_device_t *pdev,
						  struct ecore_mcast_obj *o)
{
	struct ecore_raw_obj *raw = &o->raw;
	struct ecore_mcast_mac_elem *elem;
	struct mac_configuration_cmd *data =
			(struct mac_configuration_cmd *)(raw->rdata);

	/* If first entry contains a SET bit - the command was ADD,
	 * otherwise - DEL_ALL
	 */
	if (ECORE_GET_FLAG(data->config_table[0].flags,
			MAC_CONFIGURATION_ENTRY_ACTION_TYPE)) {
		int i, len = data->hdr.length;

		/* Break if it was a RESTORE command */
		if (!ECORE_LIST_IS_EMPTY(&o->registry.exact_match.macs))
			return ECORE_SUCCESS;

		elem = ECORE_CALLOC(len, sizeof(*elem), GFP_ATOMIC, pdev);
		if (!elem) {
			ECORE_ERR("Failed to allocate registry memory\n");
			return ECORE_NOMEM;
		}

		for (i = 0; i < len; i++, elem++) {
			ecore_get_fw_mac_addr(
				&data->config_table[i].msb_mac_addr,
				&data->config_table[i].middle_mac_addr,
				&data->config_table[i].lsb_mac_addr,
				elem->mac);
			ECORE_MSG(pdev, "Adding registry entry for [%02x:%02x:%02x:%02x:%02x:%02x]\n",
				  elem->mac[0], elem->mac[1], elem->mac[2], elem->mac[3], elem->mac[4], elem->mac[5]);
			ECORE_LIST_PUSH_TAIL(&elem->link,
					     &o->registry.exact_match.macs);
		}
	} else {
		elem = ECORE_LIST_FIRST_ENTRY(&o->registry.exact_match.macs,
					      struct ecore_mcast_mac_elem,
					      link);
		ECORE_MSG(pdev, "Deleting a registry\n");
		ECORE_FREE(pdev, elem, sizeof(*elem));
		ECORE_LIST_INIT(&o->registry.exact_match.macs);
	}

	return ECORE_SUCCESS;
}

static int ecore_mcast_setup_e1(struct _lm_device_t *pdev,
				struct ecore_mcast_ramrod_params *p,
				enum ecore_mcast_cmd cmd)
{
	struct ecore_mcast_obj *o = p->mcast_obj;
	struct ecore_raw_obj *raw = &o->raw;
	struct mac_configuration_cmd *data =
		(struct mac_configuration_cmd *)(raw->rdata);
	int cnt = 0, i, rc;

	/* Reset the ramrod data buffer */
	mm_memset(data, 0, sizeof(*data));

	/* First set all entries as invalid */
	for (i = 0; i < o->max_cmd_len ; i++)
		ECORE_SET_FLAG(data->config_table[i].flags,
			MAC_CONFIGURATION_ENTRY_ACTION_TYPE,
			T_ETH_MAC_COMMAND_INVALIDATE);

	/* Handle pending commands first */
	cnt = ecore_mcast_handle_pending_cmds_e1(pdev, p);

	/* If there are no more pending commands - clear SCHEDULED state */
	if (ECORE_LIST_IS_EMPTY(&o->pending_cmds_head))
		o->clear_sched(o);

	/* The below may be TRUE iff there were no pending commands */
	if (!cnt)
		cnt = ecore_mcast_handle_current_cmd(pdev, p, cmd, 0);

	/* For 57710 every command has o->max_cmd_len length to ensure that
	 * commands are done one at a time.
	 */
	o->total_pending_num -= o->max_cmd_len;

	/* send a ramrod */

	DbgBreakIf(cnt > o->max_cmd_len);

	/* Set ramrod header (in particular, a number of entries to update) */
	ecore_mcast_set_rdata_hdr_e1(pdev, p, (u8)cnt);

	/* update a registry: we need the registry contents to be always up
	 * to date in order to be able to execute a RESTORE opcode. Here
	 * we use the fact that for 57710 we sent one command at a time
	 * hence we may take the registry update out of the command handling
	 * and do it in a simpler way here.
	 */
	rc = ecore_mcast_refresh_registry_e1(pdev, o);
	if (rc)
		return rc;

	/* If CLEAR_ONLY was requested - don't send a ramrod and clear
	 * RAMROD_PENDING status immediately.
	 */
	if (ECORE_TEST_BIT(RAMROD_DRV_CLR_ONLY, &p->ramrod_flags)) {
		raw->clear_pending(raw);
		return ECORE_SUCCESS;
	} else {
		/* No need for an explicit memory barrier here as long as we
		 * ensure the ordering of writing to the SPQ element
		 * and updating of the SPQ producer which involves a memory
		 * read. If the memory read is removed we will have to put a
		 * full memory barrier there (inside ecore_sp_post()).
		 */

		/* Send a ramrod */
		rc = ecore_sp_post( pdev,
				    RAMROD_CMD_ID_ETH_SET_MAC,
				    raw->cid,
				    raw->rdata_mapping.as_u64,
				    ETH_CONNECTION_TYPE);
		if (rc)
			return rc;

		/* Ramrod completion is pending */
		return ECORE_PENDING;
	}
}

static int ecore_mcast_get_registry_size_exact(struct ecore_mcast_obj *o)
{
	return o->registry.exact_match.num_macs_set;
}

static int ecore_mcast_get_registry_size_aprox(struct ecore_mcast_obj *o)
{
	return o->registry.aprox_match.num_bins_set;
}

static void ecore_mcast_set_registry_size_exact(struct ecore_mcast_obj *o,
						int n)
{
	o->registry.exact_match.num_macs_set = n;
}

static void ecore_mcast_set_registry_size_aprox(struct ecore_mcast_obj *o,
						int n)
{
	o->registry.aprox_match.num_bins_set = n;
}

int ecore_config_mcast(struct _lm_device_t *pdev,
		       struct ecore_mcast_ramrod_params *p,
		       enum ecore_mcast_cmd cmd)
{
	struct ecore_mcast_obj *o = p->mcast_obj;
	struct ecore_raw_obj *r = &o->raw;
	int rc = 0, old_reg_size;

	/* This is needed to recover number of currently configured mcast macs
	 * in case of failure.
	 */
	old_reg_size = o->get_registry_size(o);

	/* Do some calculations and checks */
	rc = o->validate(pdev, p, cmd);
	if (rc)
		return rc;

	/* Return if there is no work to do */
	if ((!p->mcast_list_len) && (!o->check_sched(o)))
		return ECORE_SUCCESS;

	ECORE_MSG(pdev, "o->total_pending_num=%d p->mcast_list_len=%d o->max_cmd_len=%d\n",
		  o->total_pending_num, p->mcast_list_len, o->max_cmd_len);

	/* Enqueue the current command to the pending list if we can't complete
	 * it in the current iteration
	 */
	if (r->check_pending(r) ||
	    ((o->max_cmd_len > 0) && (o->total_pending_num > o->max_cmd_len))) {
		rc = o->enqueue_cmd(pdev, p->mcast_obj, p, cmd);
		if (rc < 0)
			goto error_exit1;

		/* As long as the current command is in a command list we
		 * don't need to handle it separately.
		 */
		p->mcast_list_len = 0;
	}

	if (!r->check_pending(r)) {

		/* Set 'pending' state */
		r->set_pending(r);

		/* Configure the new classification in the chip */
		rc = o->config_mcast(pdev, p, cmd);
		if (rc < 0)
			goto error_exit2;

		/* Wait for a ramrod completion if was requested */
		if (ECORE_TEST_BIT(RAMROD_COMP_WAIT, &p->ramrod_flags))
			rc = o->wait_comp(pdev, o);
	}

	return rc;

error_exit2:
	r->clear_pending(r);

error_exit1:
	o->revert(pdev, p, old_reg_size);

	return rc;
}

static void ecore_mcast_clear_sched(struct ecore_mcast_obj *o)
{
	smp_mb__before_atomic();
	ECORE_CLEAR_BIT(o->sched_state, o->raw.pstate);
	smp_mb__after_atomic();
}

static void ecore_mcast_set_sched(struct ecore_mcast_obj *o)
{
	smp_mb__before_atomic();
	ECORE_SET_BIT(o->sched_state, o->raw.pstate);
	smp_mb__after_atomic();
}

static BOOL ecore_mcast_check_sched(struct ecore_mcast_obj *o)
{
	return !!ECORE_TEST_BIT(o->sched_state, o->raw.pstate);
}

static BOOL ecore_mcast_check_pending(struct ecore_mcast_obj *o)
{
	return o->raw.check_pending(&o->raw) || o->check_sched(o);
}
#ifndef ECORE_ERASE
typedef int (*enqueue_cmd_func)(struct _lm_device_t *pdev,
				struct ecore_mcast_obj *o,
				struct ecore_mcast_ramrod_params *p,
				enum ecore_mcast_cmd cmd);

typedef int (*hdl_restore_func)(struct _lm_device_t *pdev,
				struct ecore_mcast_obj *o,
				int start_bin, int *rdata_idx);

typedef void (*set_one_rule_func)(struct _lm_device_t *pdev,
				  struct ecore_mcast_obj *o, int idx,
				  union ecore_mcast_config_data *cfg_data,
				  enum ecore_mcast_cmd cmd);
#endif

void ecore_init_mcast_obj(struct _lm_device_t *pdev,
			  struct ecore_mcast_obj *mcast_obj,
			  u8 mcast_cl_id, u32 mcast_cid, u8 func_id,
			  u8 engine_id, void *rdata, lm_address_t rdata_mapping,
			  int state, unsigned long *pstate, ecore_obj_type type)
{
	mm_memset(mcast_obj, 0, sizeof(*mcast_obj));

	ecore_init_raw_obj(&mcast_obj->raw, mcast_cl_id, mcast_cid, func_id,
			   rdata, rdata_mapping, state, pstate, type);

	mcast_obj->engine_id = engine_id;

	ECORE_LIST_INIT(&mcast_obj->pending_cmds_head);

	mcast_obj->sched_state = ECORE_FILTER_MCAST_SCHED;
	mcast_obj->check_sched = ecore_mcast_check_sched;
	mcast_obj->set_sched = ecore_mcast_set_sched;
	mcast_obj->clear_sched = ecore_mcast_clear_sched;

	if (CHIP_IS_E1(pdev)) {
		mcast_obj->config_mcast      = ecore_mcast_setup_e1;
		mcast_obj->enqueue_cmd       = ecore_mcast_enqueue_cmd;
		mcast_obj->hdl_restore       =
			ecore_mcast_handle_restore_cmd_e1;
		mcast_obj->check_pending     = ecore_mcast_check_pending;

		if (CHIP_REV_IS_SLOW(pdev))
			mcast_obj->max_cmd_len = ECORE_MAX_EMUL_MULTI;
		else
			mcast_obj->max_cmd_len = ECORE_MAX_MULTICAST;

		mcast_obj->wait_comp         = ecore_mcast_wait;
		mcast_obj->set_one_rule      = ecore_mcast_set_one_rule_e1;
		mcast_obj->validate          = ecore_mcast_validate_e1;
		mcast_obj->revert            = ecore_mcast_revert_e1;
		mcast_obj->get_registry_size =
			ecore_mcast_get_registry_size_exact;
		mcast_obj->set_registry_size =
			ecore_mcast_set_registry_size_exact;

		/* 57710 is the only chip that uses the exact match for mcast
		 * at the moment.
		 */
		ECORE_LIST_INIT(&mcast_obj->registry.exact_match.macs);

	} else if (CHIP_IS_E1H(pdev)) {
		mcast_obj->config_mcast  = ecore_mcast_setup_e1h;
		mcast_obj->enqueue_cmd   = (enqueue_cmd_func)NULL;
		mcast_obj->hdl_restore   = (hdl_restore_func)NULL;
		mcast_obj->check_pending = ecore_mcast_check_pending;

		/* 57711 doesn't send a ramrod, so it has unlimited credit
		 * for one command.
		 */
		mcast_obj->max_cmd_len       = -1;
		mcast_obj->wait_comp         = ecore_mcast_wait;
		mcast_obj->set_one_rule      = (set_one_rule_func)NULL;
		mcast_obj->validate          = ecore_mcast_validate_e1h;
		mcast_obj->revert            = ecore_mcast_revert_e1h;
		mcast_obj->get_registry_size =
			ecore_mcast_get_registry_size_aprox;
		mcast_obj->set_registry_size =
			ecore_mcast_set_registry_size_aprox;
	} else {
		mcast_obj->config_mcast      = ecore_mcast_setup_e2;
		mcast_obj->enqueue_cmd       = ecore_mcast_enqueue_cmd;
		mcast_obj->hdl_restore       =
			ecore_mcast_handle_restore_cmd_e2;
		mcast_obj->check_pending     = ecore_mcast_check_pending;
		/* TODO: There should be a proper HSI define for this number!!!
		 */
		mcast_obj->max_cmd_len       = 16;
		mcast_obj->wait_comp         = ecore_mcast_wait;
		mcast_obj->set_one_rule      = ecore_mcast_set_one_rule_e2;
		mcast_obj->validate          = ecore_mcast_validate_e2;
		mcast_obj->revert            = ecore_mcast_revert_e2;
		mcast_obj->get_registry_size =
			ecore_mcast_get_registry_size_aprox;
		mcast_obj->set_registry_size =
			ecore_mcast_set_registry_size_aprox;
	}
}

/*************************** Credit handling **********************************/

/**
 * atomic_add_ifless - add if the result is less than a given value.
 *
 * @v:	pointer of type atomic_t
 * @a:	the amount to add to v...
 * @u:	...if (v + a) is less than u.
 *
 * returns TRUE if (v + a) was less than u, and FALSE otherwise.
 *
 */
static INLINE BOOL __atomic_add_ifless(atomic_t *v, int a, int u)
{
	int c, old;

	c = ecore_atomic_read(v);
	for (;;) {
		if (ECORE_UNLIKELY(c + a >= u))
			return FALSE;

		old = ecore_atomic_cmpxchg((v), c, c + a);
		if (ECORE_LIKELY(old == c))
			break;
		c = old;
	}

	return TRUE;
}

/**
 * atomic_dec_ifmoe - dec if the result is more or equal than a given value.
 *
 * @v:	pointer of type atomic_t
 * @a:	the amount to dec from v...
 * @u:	...if (v - a) is more or equal than u.
 *
 * returns TRUE if (v - a) was more or equal than u, and FALSE
 * otherwise.
 */
static INLINE BOOL __atomic_dec_ifmoe(atomic_t *v, int a, int u)
{
	int c, old;

	c = ecore_atomic_read(v);
	for (;;) {
		if (ECORE_UNLIKELY(c - a < u))
			return FALSE;

		old = ecore_atomic_cmpxchg((v), c, c - a);
		if (ECORE_LIKELY(old == c))
			break;
		c = old;
	}

	return TRUE;
}

static BOOL ecore_credit_pool_get(struct ecore_credit_pool_obj *o, int cnt)
{
	BOOL rc;

	smp_mb();
	rc = __atomic_dec_ifmoe(&o->credit, cnt, 0);
	smp_mb();

	return rc;
}

static BOOL ecore_credit_pool_put(struct ecore_credit_pool_obj *o, int cnt)
{
	BOOL rc;

	smp_mb();

	/* Don't let to refill if credit + cnt > pool_sz */
	rc = __atomic_add_ifless(&o->credit, cnt, o->pool_sz + 1);

	smp_mb();

	return rc;
}

static int ecore_credit_pool_check(struct ecore_credit_pool_obj *o)
{
	int cur_credit;

	smp_mb();
	cur_credit = ecore_atomic_read(&o->credit);

	return cur_credit;
}

static BOOL ecore_credit_pool_always_TRUE(struct ecore_credit_pool_obj *o,
					  int cnt)
{
	return TRUE;
}

static BOOL ecore_credit_pool_get_entry(
	struct ecore_credit_pool_obj *o,
	int *offset)
{
	int idx, vec, i;

	*offset = -1;

	/* Find "internal cam-offset" then add to base for this object... */
	for (vec = 0; vec < ECORE_POOL_VEC_SIZE; vec++) {

		/* Skip the current vector if there are no free entries in it */
		if (!o->pool_mirror[vec])
			continue;

		/* If we've got here we are going to find a free entry */
		for (idx = vec * BIT_VEC64_ELEM_SZ, i = 0;
		      i < BIT_VEC64_ELEM_SZ; idx++, i++)

			if (BIT_VEC64_TEST_BIT(o->pool_mirror, idx)) {
				/* Got one!! */
				BIT_VEC64_CLEAR_BIT(o->pool_mirror, idx);
				*offset = o->base_pool_offset + idx;
				return TRUE;
			}
	}

	return FALSE;
}

static BOOL ecore_credit_pool_put_entry(
	struct ecore_credit_pool_obj *o,
	int offset)
{
	if (offset < o->base_pool_offset)
		return FALSE;

	offset -= o->base_pool_offset;

	if (offset >= o->pool_sz)
		return FALSE;

	/* Return the entry to the pool */
	BIT_VEC64_SET_BIT(o->pool_mirror, offset);

	return TRUE;
}

static BOOL ecore_credit_pool_put_entry_always_TRUE(
	struct ecore_credit_pool_obj *o,
	int offset)
{
	return TRUE;
}

static BOOL ecore_credit_pool_get_entry_always_TRUE(
	struct ecore_credit_pool_obj *o,
	int *offset)
{
	*offset = -1;
	return TRUE;
}
/**
 * ecore_init_credit_pool - initialize credit pool internals.
 *
 * @p:
 * @base:	Base entry in the CAM to use.
 * @credit:	pool size.
 *
 * If base is negative no CAM entries handling will be performed.
 * If credit is negative pool operations will always succeed (unlimited pool).
 *
 */
static INLINE void ecore_init_credit_pool(struct ecore_credit_pool_obj *p,
					  int base, int credit)
{
	/* Zero the object first */
	mm_memset(p, 0, sizeof(*p));

	/* Set the table to all 1s */
	mm_memset(&p->pool_mirror, 0xff, sizeof(p->pool_mirror));

	/* Init a pool as full */
	ecore_atomic_set(&p->credit, credit);

	/* The total poll size */
	p->pool_sz = credit;

	p->base_pool_offset = base;

	/* Commit the change */
	smp_mb();

	p->check = ecore_credit_pool_check;

	/* if pool credit is negative - disable the checks */
	if (credit >= 0) {
		p->put      = ecore_credit_pool_put;
		p->get      = ecore_credit_pool_get;
		p->put_entry = ecore_credit_pool_put_entry;
		p->get_entry = ecore_credit_pool_get_entry;
	} else {
		p->put      = ecore_credit_pool_always_TRUE;
		p->get      = ecore_credit_pool_always_TRUE;
		p->put_entry = ecore_credit_pool_put_entry_always_TRUE;
		p->get_entry = ecore_credit_pool_get_entry_always_TRUE;
	}

	/* If base is negative - disable entries handling */
	if (base < 0) {
		p->put_entry = ecore_credit_pool_put_entry_always_TRUE;
		p->get_entry = ecore_credit_pool_get_entry_always_TRUE;
	}
}

void ecore_init_mac_credit_pool(struct _lm_device_t *pdev,
				struct ecore_credit_pool_obj *p, u8 func_id,
				u8 func_num)
{
/* TODO: this will be defined in consts as well... */
#define ECORE_CAM_SIZE_EMUL 5

	int cam_sz;

	if (CHIP_IS_E1(pdev)) {
		/* In E1, Multicast is saved in cam... */
		if (!CHIP_REV_IS_SLOW(pdev))
			cam_sz = (MAX_MAC_CREDIT_E1 / 2) - ECORE_MAX_MULTICAST;
		else
			cam_sz = ECORE_CAM_SIZE_EMUL - ECORE_MAX_EMUL_MULTI;

		ecore_init_credit_pool(p, func_id * cam_sz, cam_sz);

	} else if (CHIP_IS_E1H(pdev)) {
		/* CAM credit is equally divided between all active functions
		 * on the PORT!.
		 */
		if ((func_num > 0)) {
			if (!CHIP_REV_IS_SLOW(pdev))
				cam_sz = (MAX_MAC_CREDIT_E1H / (2*func_num));
			else
				cam_sz = ECORE_CAM_SIZE_EMUL;
			ecore_init_credit_pool(p, func_id * cam_sz, cam_sz);
		} else {
			/* this should never happen! Block MAC operations. */
			ecore_init_credit_pool(p, 0, 0);
		}

	} else {

		/*
		 * CAM credit is equaly divided between all active functions
		 * on the PATH.
		 */
		if ((func_num > 1)) {
			if (!CHIP_REV_IS_SLOW(pdev))
				cam_sz = (MAX_MAC_CREDIT_E2
				- GET_NUM_VFS_PER_PATH(pdev))
				/ func_num
				+ GET_NUM_VFS_PER_PF(pdev);
			else
				cam_sz = ECORE_CAM_SIZE_EMUL;

			/* No need for CAM entries handling for 57712 and
			 * newer.
			 */
			ecore_init_credit_pool(p, -1, cam_sz);
		} else if (func_num == 1) {
			if (!CHIP_REV_IS_SLOW(pdev))
				cam_sz = MAX_MAC_CREDIT_E2;
			else
				cam_sz = ECORE_CAM_SIZE_EMUL;

			/* No need for CAM entries handling for 57712 and
			 * newer.
			 */
			ecore_init_credit_pool(p, -1, cam_sz);
		} else {
			/* this should never happen! Block MAC operations. */
			ecore_init_credit_pool(p, 0, 0);
		}
	}
}

void ecore_init_vlan_credit_pool(struct _lm_device_t *pdev,
				 struct ecore_credit_pool_obj *p,
				 u8 func_id,
				 u8 func_num)
{
	if (CHIP_IS_E1x(pdev)) {
		/* There is no VLAN credit in HW on 57710 and 57711 only
		 * MAC / MAC-VLAN can be set
		 */
		ecore_init_credit_pool(p, 0, -1);
	} else {
		/* CAM credit is equally divided between all active functions
		 * on the PATH.
		 */
		if (func_num > 0) {
			int credit = MAX_VLAN_CREDIT_E2 / func_num;
			ecore_init_credit_pool(p, func_id * credit, credit);
		} else
			/* this should never happen! Block VLAN operations. */
			ecore_init_credit_pool(p, 0, 0);
	}
}

/****************** RSS Configuration ******************/
#if defined(ECORE_ERASE) && !defined(__FreeBSD__)
/**
 * bnx2x_debug_print_ind_table - prints the indirection table configuration.
 *
 * @bp:		driver handle
 * @p:		pointer to rss configuration
 *
 * Prints it when NETIF_MSG_IFUP debug level is configured.
 */
static inline void bnx2x_debug_print_ind_table(struct bnx2x *bp,
					struct bnx2x_config_rss_params *p)
{
	int i;

	DP(BNX2X_MSG_SP, "Setting indirection table to:\n");
	DP(BNX2X_MSG_SP, "0x0000: ");
	for (i = 0; i < T_ETH_INDIRECTION_TABLE_SIZE; i++) {
		DP_CONT(BNX2X_MSG_SP, "0x%02x ", p->ind_table[i]);

		/* Print 4 bytes in a line */
		if ((i + 1 < T_ETH_INDIRECTION_TABLE_SIZE) &&
		    (((i + 1) & 0x3) == 0)) {
			DP_CONT(BNX2X_MSG_SP, "\n");
			DP(BNX2X_MSG_SP, "0x%04x: ", i + 1);
		}
	}

	DP_CONT(BNX2X_MSG_SP, "\n");
}
#endif /* ECORE_ERASE && !__FreeBSD__ */

/**
 * ecore_setup_rss - configure RSS
 *
 * @pdev:	device handle
 * @p:		rss configuration
 *
 * sends on UPDATE ramrod for that matter.
 */
static int ecore_setup_rss(struct _lm_device_t *pdev,
			   struct ecore_config_rss_params *p)
{
	struct ecore_rss_config_obj *o = p->rss_obj;
	struct ecore_raw_obj *r = &o->raw;
	struct eth_rss_update_ramrod_data *data =
		(struct eth_rss_update_ramrod_data *)(r->rdata);
	u16 caps = 0;
	u8 rss_mode = 0;
	int rc;

	mm_memset(data, 0, sizeof(*data));

	ECORE_MSG(pdev, "Configuring RSS\n");

	/* Set an echo field */
	data->echo = mm_cpu_to_le32((r->cid & ECORE_SWCID_MASK) |
				 (r->state << ECORE_SWCID_SHIFT));

	/* RSS mode */
	if (ECORE_TEST_BIT(ECORE_RSS_MODE_DISABLED, &p->rss_flags))
		rss_mode = ETH_RSS_MODE_DISABLED;
	else if (ECORE_TEST_BIT(ECORE_RSS_MODE_REGULAR, &p->rss_flags))
		rss_mode = ETH_RSS_MODE_REGULAR;
#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION < 55000) /* ! BNX2X_UPSTREAM */
	else if (ECORE_TEST_BIT(ECORE_RSS_MODE_ESX51, &p->rss_flags))
		rss_mode = ETH_RSS_MODE_ESX51;
#endif

	data->rss_mode = rss_mode;

	ECORE_MSG(pdev, "rss_mode=%d\n", rss_mode);

	/* RSS capabilities */
	if (ECORE_TEST_BIT(ECORE_RSS_IPV4, &p->rss_flags))
		caps |= ETH_RSS_UPDATE_RAMROD_DATA_IPV4_CAPABILITY;

	if (ECORE_TEST_BIT(ECORE_RSS_IPV4_TCP, &p->rss_flags))
		caps |= ETH_RSS_UPDATE_RAMROD_DATA_IPV4_TCP_CAPABILITY;

	if (ECORE_TEST_BIT(ECORE_RSS_IPV4_UDP, &p->rss_flags))
		caps |= ETH_RSS_UPDATE_RAMROD_DATA_IPV4_UDP_CAPABILITY;

	if (ECORE_TEST_BIT(ECORE_RSS_IPV6, &p->rss_flags))
		caps |= ETH_RSS_UPDATE_RAMROD_DATA_IPV6_CAPABILITY;

	if (ECORE_TEST_BIT(ECORE_RSS_IPV6_TCP, &p->rss_flags))
		caps |= ETH_RSS_UPDATE_RAMROD_DATA_IPV6_TCP_CAPABILITY;

	if (ECORE_TEST_BIT(ECORE_RSS_IPV6_UDP, &p->rss_flags))
		caps |= ETH_RSS_UPDATE_RAMROD_DATA_IPV6_UDP_CAPABILITY;

	if (ECORE_TEST_BIT(ECORE_RSS_IPV4_VXLAN, &p->rss_flags))
		caps |= ETH_RSS_UPDATE_RAMROD_DATA_IPV4_VXLAN_CAPABILITY;

	if (ECORE_TEST_BIT(ECORE_RSS_IPV6_VXLAN, &p->rss_flags))
		caps |= ETH_RSS_UPDATE_RAMROD_DATA_IPV6_VXLAN_CAPABILITY;

	if (ECORE_TEST_BIT(ECORE_RSS_NVGRE_KEY_ENTROPY, &p->rss_flags))
		caps |= ETH_RSS_UPDATE_RAMROD_DATA_NVGRE_KEY_ENTROPY_CAPABILITY;

	if (ECORE_TEST_BIT(ECORE_RSS_GRE_INNER_HDRS, &p->rss_flags))
		caps |= ETH_RSS_UPDATE_RAMROD_DATA_GRE_INNER_HDRS_CAPABILITY;

	data->capabilities = mm_cpu_to_le16(caps);

	/* Hashing mask */
	data->rss_result_mask = p->rss_result_mask;

	/* RSS engine ID */
	data->rss_engine_id = o->engine_id;

	ECORE_MSG(pdev, "rss_engine_id=%d\n", data->rss_engine_id);

	/* Indirection table */
	mm_memcpy(data->indirection_table, p->ind_table,
		  T_ETH_INDIRECTION_TABLE_SIZE);

	/* Remember the last configuration */
	mm_memcpy(o->ind_table, p->ind_table, T_ETH_INDIRECTION_TABLE_SIZE);

#if defined(ECORE_ERASE) && !defined(__FreeBSD__)
	/* Print the indirection table */
	if (netif_msg_ifup(bp))
		bnx2x_debug_print_ind_table(bp, p);
#endif

	/* RSS keys */
	if (ECORE_TEST_BIT(ECORE_RSS_SET_SRCH, &p->rss_flags)) {
		mm_memcpy(&data->rss_key[0], &p->rss_key[0],
		       sizeof(data->rss_key));
		data->capabilities |= ETH_RSS_UPDATE_RAMROD_DATA_UPDATE_RSS_KEY;
	}

	/* No need for an explicit memory barrier here as long as we
	 * ensure the ordering of writing to the SPQ element
	 * and updating of the SPQ producer which involves a memory
	 * read. If the memory read is removed we will have to put a
	 * full memory barrier there (inside ecore_sp_post()).
	 */

	/* Send a ramrod */
	rc = ecore_sp_post(pdev,
			     RAMROD_CMD_ID_ETH_RSS_UPDATE,
			     r->cid,
			     r->rdata_mapping.as_u64,
			     ETH_CONNECTION_TYPE);

	if (rc < 0)
		return rc;

	return ECORE_PENDING;
}

void ecore_get_rss_ind_table(struct ecore_rss_config_obj *rss_obj,
			     u8 *ind_table)
{
	mm_memcpy(ind_table, rss_obj->ind_table, sizeof(rss_obj->ind_table));
}

int ecore_config_rss(struct _lm_device_t *pdev,
		     struct ecore_config_rss_params *p)
{
	int rc;
	struct ecore_rss_config_obj *o = p->rss_obj;
	struct ecore_raw_obj *r = &o->raw;

	/* Do nothing if only driver cleanup was requested */
	if (ECORE_TEST_BIT(RAMROD_DRV_CLR_ONLY, &p->ramrod_flags)) {
		ECORE_MSG(pdev, "Not configuring RSS ramrod_flags=%lx\n",
			  p->ramrod_flags);
		return ECORE_SUCCESS;
	}

	r->set_pending(r);

	rc = o->config_rss(pdev, p);
	if (rc < 0) {
		r->clear_pending(r);
		return rc;
	}

	if (ECORE_TEST_BIT(RAMROD_COMP_WAIT, &p->ramrod_flags))
		rc = r->wait_comp(pdev, r);

	return rc;
}

void ecore_init_rss_config_obj(struct _lm_device_t *pdev,
			       struct ecore_rss_config_obj *rss_obj,
			       u8 cl_id, u32 cid, u8 func_id, u8 engine_id,
			       void *rdata, lm_address_t rdata_mapping,
			       int state, unsigned long *pstate,
			       ecore_obj_type type)
{
	ecore_init_raw_obj(&rss_obj->raw, cl_id, cid, func_id, rdata,
			   rdata_mapping, state, pstate, type);

	rss_obj->engine_id  = engine_id;
	rss_obj->config_rss = ecore_setup_rss;
}

#ifdef ECORE_ERASE
/********************** Queue state object ***********************************/

/**
 * ecore_queue_state_change - perform Queue state change transition
 *
 * @pdev:	device handle
 * @params:	parameters to perform the transition
 *
 * returns 0 in case of successfully completed transition, negative error
 * code in case of failure, positive (EBUSY) value if there is a completion
 * to that is still pending (possible only if RAMROD_COMP_WAIT is
 * not set in params->ramrod_flags for asynchronous commands).
 *
 */
int ecore_queue_state_change(struct _lm_device_t *pdev,
			     struct ecore_queue_state_params *params)
{
	struct ecore_queue_sp_obj *o = params->q_obj;
	int rc, pending_bit;
	unsigned long *pending = &o->pending;

	/* Check that the requested transition is legal */
	rc = o->check_transition(pdev, o, params);
	if (rc) {
		ECORE_ERR("check transition returned an error. rc %d\n", rc);
		return ECORE_INVAL;
	}

	/* Set "pending" bit */
	ECORE_MSG(pdev, "pending bit was=%lx\n", o->pending);
	pending_bit = o->set_pending(o, params);
	ECORE_MSG(pdev, "pending bit now=%lx\n", o->pending);

	/* Don't send a command if only driver cleanup was requested */
	if (ECORE_TEST_BIT(RAMROD_DRV_CLR_ONLY, &params->ramrod_flags))
		o->complete_cmd(pdev, o, pending_bit);
	else {
		/* Send a ramrod */
		rc = o->send_cmd(pdev, params);
		if (rc) {
			o->next_state = ECORE_Q_STATE_MAX;
			ECORE_CLEAR_BIT(pending_bit, pending);
			smp_mb__after_atomic();
			return rc;
		}

		if (ECORE_TEST_BIT(RAMROD_COMP_WAIT, &params->ramrod_flags)) {
			rc = o->wait_comp(pdev, o, pending_bit);
			if (rc)
				return rc;

			return ECORE_SUCCESS;
		}
	}

	return ECORE_RET_PENDING(pending_bit, pending);
}

static int ecore_queue_set_pending(struct ecore_queue_sp_obj *obj,
				   struct ecore_queue_state_params *params)
{
	enum ecore_queue_cmd cmd = params->cmd, bit;

	/* ACTIVATE and DEACTIVATE commands are implemented on top of
	 * UPDATE command.
	 */
	if ((cmd == ECORE_Q_CMD_ACTIVATE) ||
	    (cmd == ECORE_Q_CMD_DEACTIVATE))
		bit = ECORE_Q_CMD_UPDATE;
	else
		bit = cmd;

	ECORE_SET_BIT(bit, &obj->pending);
	return bit;
}

static int ecore_queue_wait_comp(struct _lm_device_t *pdev,
				 struct ecore_queue_sp_obj *o,
				 enum ecore_queue_cmd cmd)
{
	return ecore_state_wait(pdev, cmd, &o->pending);
}

/**
 * ecore_queue_comp_cmd - complete the state change command.
 *
 * @pdev:	device handle
 * @o:
 * @cmd:
 *
 * Checks that the arrived completion is expected.
 */
static int ecore_queue_comp_cmd(struct _lm_device_t *pdev,
				struct ecore_queue_sp_obj *o,
				enum ecore_queue_cmd cmd)
{
	unsigned long cur_pending = o->pending;

	if (!ECORE_TEST_AND_CLEAR_BIT(cmd, &cur_pending)) {
		ECORE_ERR("Bad MC reply %d for queue %d in state %d pending 0x%lx, next_state %d\n",
			  cmd, o->cids[ECORE_PRIMARY_CID_INDEX],
			  o->state, cur_pending, o->next_state);
		return ECORE_INVAL;
	}

	if (o->next_tx_only >= o->max_cos)
		/* >= because tx only must always be smaller than cos since the
		 * primary connection supports COS 0
		 */
		ECORE_ERR("illegal value for next tx_only: %d. max cos was %d",
			  o->next_tx_only, o->max_cos);

	ECORE_MSG(pdev,
		  "Completing command %d for queue %d, setting state to %d\n",
		  cmd, o->cids[ECORE_PRIMARY_CID_INDEX], o->next_state);

	if (o->next_tx_only)  /* print num tx-only if any exist */
		ECORE_MSG(pdev, "primary cid %d: num tx-only cons %d\n",
			  o->cids[ECORE_PRIMARY_CID_INDEX], o->next_tx_only);

	o->state = o->next_state;
	o->num_tx_only = o->next_tx_only;
	o->next_state = ECORE_Q_STATE_MAX;

	/* It's important that o->state and o->next_state are
	 * updated before o->pending.
	 */
	wmb();

	ECORE_CLEAR_BIT(cmd, &o->pending);
	smp_mb__after_atomic();

	return ECORE_SUCCESS;
}

static void ecore_q_fill_setup_data_e2(struct _lm_device_t *pdev,
				struct ecore_queue_state_params *cmd_params,
				struct client_init_ramrod_data *data)
{
	struct ecore_queue_setup_params *params = &cmd_params->params.setup;

	/* Rx data */

	/* IPv6 TPA supported for E2 and above only */
	data->rx.tpa_en |= ECORE_TEST_BIT(ECORE_Q_FLG_TPA_IPV6,
					  &params->flags) *
				CLIENT_INIT_RX_DATA_TPA_EN_IPV6;
}

static void ecore_q_fill_init_general_data(struct _lm_device_t *pdev,
				struct ecore_queue_sp_obj *o,
				struct ecore_general_setup_params *params,
				struct client_init_general_data *gen_data,
				unsigned long *flags)
{
	gen_data->client_id = o->cl_id;

	if (ECORE_TEST_BIT(ECORE_Q_FLG_STATS, flags)) {
		gen_data->statistics_counter_id =
					params->stat_id;
		gen_data->statistics_en_flg = 1;
		gen_data->statistics_zero_flg =
			ECORE_TEST_BIT(ECORE_Q_FLG_ZERO_STATS, flags);
	} else
		gen_data->statistics_counter_id =
					DISABLE_STATISTIC_COUNTER_ID_VALUE;

	gen_data->is_fcoe_flg = ECORE_TEST_BIT(ECORE_Q_FLG_FCOE,
						   flags);
	gen_data->activate_flg = ECORE_TEST_BIT(ECORE_Q_FLG_ACTIVE,
						    flags);
	gen_data->sp_client_id = params->spcl_id;
	gen_data->mtu = mm_cpu_to_le16(params->mtu);
	gen_data->func_id = o->func_id;

	gen_data->cos = params->cos;

	gen_data->traffic_type =
		ECORE_TEST_BIT(ECORE_Q_FLG_FCOE, flags) ?
		LLFC_TRAFFIC_TYPE_FCOE : LLFC_TRAFFIC_TYPE_NW;

	gen_data->fp_hsi_ver = ETH_FP_HSI_VERSION;

	ECORE_MSG(pdev, "flags: active %d, cos %d, stats en %d\n",
		  gen_data->activate_flg, gen_data->cos, gen_data->statistics_en_flg);
}

static void ecore_q_fill_init_tx_data(struct ecore_queue_sp_obj *o,
				struct ecore_txq_setup_params *params,
				struct client_init_tx_data *tx_data,
				unsigned long *flags)
{
	tx_data->enforce_security_flg =
		ECORE_TEST_BIT(ECORE_Q_FLG_TX_SEC, flags);
	tx_data->default_vlan =
		mm_cpu_to_le16(params->default_vlan);
	tx_data->default_vlan_flg =
		ECORE_TEST_BIT(ECORE_Q_FLG_DEF_VLAN, flags);
	tx_data->tx_switching_flg =
		ECORE_TEST_BIT(ECORE_Q_FLG_TX_SWITCH, flags);
	tx_data->anti_spoofing_flg =
		ECORE_TEST_BIT(ECORE_Q_FLG_ANTI_SPOOF, flags);
	tx_data->force_default_pri_flg =
		ECORE_TEST_BIT(ECORE_Q_FLG_FORCE_DEFAULT_PRI, flags);
	tx_data->refuse_outband_vlan_flg =
		ECORE_TEST_BIT(ECORE_Q_FLG_REFUSE_OUTBAND_VLAN, flags);
	tx_data->tunnel_lso_inc_ip_id =
		ECORE_TEST_BIT(ECORE_Q_FLG_TUN_INC_INNER_IP_ID, flags);
	tx_data->tunnel_non_lso_pcsum_location =
		ECORE_TEST_BIT(ECORE_Q_FLG_PCSUM_ON_PKT, flags) ? CSUM_ON_PKT :
							    CSUM_ON_BD;

	tx_data->tx_status_block_id = params->fw_sb_id;
	tx_data->tx_sb_index_number = params->sb_cq_index;
	tx_data->tss_leading_client_id = params->tss_leading_cl_id;

	tx_data->tx_bd_page_base.lo =
		mm_cpu_to_le32(U64_LO(params->dscr_map.as_u64));
	tx_data->tx_bd_page_base.hi =
		mm_cpu_to_le32(U64_HI(params->dscr_map.as_u64));

	/* Don't configure any Tx switching mode during queue SETUP */
	tx_data->state = 0;
}

static void ecore_q_fill_init_pause_data(struct ecore_queue_sp_obj *o,
				struct rxq_pause_params *params,
				struct client_init_rx_data *rx_data)
{
	/* flow control data */
	rx_data->cqe_pause_thr_low = mm_cpu_to_le16(params->rcq_th_lo);
	rx_data->cqe_pause_thr_high = mm_cpu_to_le16(params->rcq_th_hi);
	rx_data->bd_pause_thr_low = mm_cpu_to_le16(params->bd_th_lo);
	rx_data->bd_pause_thr_high = mm_cpu_to_le16(params->bd_th_hi);
	rx_data->sge_pause_thr_low = mm_cpu_to_le16(params->sge_th_lo);
	rx_data->sge_pause_thr_high = mm_cpu_to_le16(params->sge_th_hi);
	rx_data->rx_cos_mask = mm_cpu_to_le16(params->pri_map);
}

static void ecore_q_fill_init_rx_data(struct ecore_queue_sp_obj *o,
				struct ecore_rxq_setup_params *params,
				struct client_init_rx_data *rx_data,
				unsigned long *flags)
{
	rx_data->tpa_en = ECORE_TEST_BIT(ECORE_Q_FLG_TPA, flags) *
				CLIENT_INIT_RX_DATA_TPA_EN_IPV4;
	rx_data->tpa_en |= ECORE_TEST_BIT(ECORE_Q_FLG_TPA_GRO, flags) *
				CLIENT_INIT_RX_DATA_TPA_MODE;
#ifdef ECORE_UPSTREAM /* ECORE_UPSTREAM */
	rx_data->vmqueue_mode_en_flg = 0;
#else
	rx_data->vmqueue_mode_en_flg =
		ECORE_TEST_BIT(ECORE_Q_FLG_VMQUEUE_MODE, flags);
#endif

#ifdef ECORE_OOO /* ! ECORE_UPSTREAM */
	rx_data->extra_data_over_sgl_en_flg =
		ECORE_TEST_BIT(ECORE_Q_FLG_OOO, flags);
#endif
	rx_data->cache_line_alignment_log_size =
		params->cache_line_log;
	rx_data->enable_dynamic_hc =
		ECORE_TEST_BIT(ECORE_Q_FLG_DHC, flags);
	rx_data->max_sges_for_packet = params->max_sges_pkt;
	rx_data->client_qzone_id = params->cl_qzone_id;
	rx_data->max_agg_size = mm_cpu_to_le16(params->tpa_agg_sz);

	/* Always start in DROP_ALL mode */
	rx_data->state = mm_cpu_to_le16(CLIENT_INIT_RX_DATA_UCAST_DROP_ALL |
				     CLIENT_INIT_RX_DATA_MCAST_DROP_ALL);

	/* We don't set drop flags */
	rx_data->drop_ip_cs_err_flg = 0;
	rx_data->drop_tcp_cs_err_flg = 0;
	rx_data->drop_ttl0_flg = 0;
	rx_data->drop_udp_cs_err_flg = 0;
	rx_data->inner_vlan_removal_enable_flg =
		ECORE_TEST_BIT(ECORE_Q_FLG_VLAN, flags);
	rx_data->outer_vlan_removal_enable_flg =
		ECORE_TEST_BIT(ECORE_Q_FLG_OV, flags);
	rx_data->status_block_id = params->fw_sb_id;
	rx_data->rx_sb_index_number = params->sb_cq_index;
	rx_data->max_tpa_queues = params->max_tpa_queues;
	rx_data->max_bytes_on_bd = mm_cpu_to_le16(params->buf_sz);
	rx_data->sge_buff_size = mm_cpu_to_le16(params->sge_buf_sz);
	rx_data->bd_page_base.lo =
		mm_cpu_to_le32(U64_LO(params->dscr_map.as_u64));
	rx_data->bd_page_base.hi =
		mm_cpu_to_le32(U64_HI(params->dscr_map.as_u64));
	rx_data->sge_page_base.lo =
		mm_cpu_to_le32(U64_LO(params->sge_map.as_u64));
	rx_data->sge_page_base.hi =
		mm_cpu_to_le32(U64_HI(params->sge_map.as_u64));
	rx_data->cqe_page_base.lo =
		mm_cpu_to_le32(U64_LO(params->rcq_map.as_u64));
	rx_data->cqe_page_base.hi =
		mm_cpu_to_le32(U64_HI(params->rcq_map.as_u64));
	rx_data->is_leading_rss = ECORE_TEST_BIT(ECORE_Q_FLG_LEADING_RSS,
						 flags);

	if (ECORE_TEST_BIT(ECORE_Q_FLG_MCAST, flags)) {
		rx_data->approx_mcast_engine_id = params->mcast_engine_id;
		rx_data->is_approx_mcast = 1;
	}

	rx_data->rss_engine_id = params->rss_engine_id;

	/* silent vlan removal */
	rx_data->silent_vlan_removal_flg =
		ECORE_TEST_BIT(ECORE_Q_FLG_SILENT_VLAN_REM, flags);
	rx_data->silent_vlan_value =
		mm_cpu_to_le16(params->silent_removal_value);
	rx_data->silent_vlan_mask =
		mm_cpu_to_le16(params->silent_removal_mask);
}

/* initialize the general, tx and rx parts of a queue object */
static void ecore_q_fill_setup_data_cmn(struct _lm_device_t *pdev,
				struct ecore_queue_state_params *cmd_params,
				struct client_init_ramrod_data *data)
{
	ecore_q_fill_init_general_data(pdev, cmd_params->q_obj,
				       &cmd_params->params.setup.gen_params,
				       &data->general,
				       &cmd_params->params.setup.flags);

	ecore_q_fill_init_tx_data(cmd_params->q_obj,
				  &cmd_params->params.setup.txq_params,
				  &data->tx,
				  &cmd_params->params.setup.flags);

	ecore_q_fill_init_rx_data(cmd_params->q_obj,
				  &cmd_params->params.setup.rxq_params,
				  &data->rx,
				  &cmd_params->params.setup.flags);

	ecore_q_fill_init_pause_data(cmd_params->q_obj,
				     &cmd_params->params.setup.pause_params,
				     &data->rx);
}

/* initialize the general and tx parts of a tx-only queue object */
static void ecore_q_fill_setup_tx_only(struct _lm_device_t *pdev,
				struct ecore_queue_state_params *cmd_params,
				struct tx_queue_init_ramrod_data *data)
{
	ecore_q_fill_init_general_data(pdev, cmd_params->q_obj,
				       &cmd_params->params.tx_only.gen_params,
				       &data->general,
				       &cmd_params->params.tx_only.flags);

	ecore_q_fill_init_tx_data(cmd_params->q_obj,
				  &cmd_params->params.tx_only.txq_params,
				  &data->tx,
				  &cmd_params->params.tx_only.flags);

	ECORE_MSG(pdev, "cid %d, tx bd page lo %x hi %x",
		  cmd_params->q_obj->cids[0],
		  data->tx.tx_bd_page_base.lo,
		  data->tx.tx_bd_page_base.hi);
}

/**
 * ecore_q_init - init HW/FW queue
 *
 * @pdev:	device handle
 * @params:
 *
 * HW/FW initial Queue configuration:
 *      - HC: Rx and Tx
 *      - CDU context validation
 *
 */
static INLINE int ecore_q_init(struct _lm_device_t *pdev,
			       struct ecore_queue_state_params *params)
{
	struct ecore_queue_sp_obj *o = params->q_obj;
	struct ecore_queue_init_params *init = &params->params.init;
	u16 hc_usec;
	u8 cos;

	/* Tx HC configuration */
	if (ECORE_TEST_BIT(ECORE_Q_TYPE_HAS_TX, &o->type) &&
	    ECORE_TEST_BIT(ECORE_Q_FLG_HC, &init->tx.flags)) {
		hc_usec = init->tx.hc_rate ? 1000000 / init->tx.hc_rate : 0;

		ECORE_TODO_UPDATE_COALESCE_SB_INDEX(pdev, init->tx.fw_sb_id,
			init->tx.sb_cq_index,
			!ECORE_TEST_BIT(ECORE_Q_FLG_HC_EN, &init->tx.flags),
			hc_usec);
	}

	/* Rx HC configuration */
	if (ECORE_TEST_BIT(ECORE_Q_TYPE_HAS_RX, &o->type) &&
	    ECORE_TEST_BIT(ECORE_Q_FLG_HC, &init->rx.flags)) {
		hc_usec = init->rx.hc_rate ? 1000000 / init->rx.hc_rate : 0;

		ECORE_TODO_UPDATE_COALESCE_SB_INDEX(pdev, init->rx.fw_sb_id,
			init->rx.sb_cq_index,
			!ECORE_TEST_BIT(ECORE_Q_FLG_HC_EN, &init->rx.flags),
			hc_usec);
	}

	/* Set CDU context validation values */
	for (cos = 0; cos < o->max_cos; cos++) {
		ECORE_MSG(pdev, "setting context validation. cid %d, cos %d\n",
			  o->cids[cos], cos);
		ECORE_MSG(pdev, "context pointer %p\n", init->cxts[cos]);
		ECORE_SET_CTX_VALIDATION(pdev, init->cxts[cos], o->cids[cos]);
	}

	/* As no ramrod is sent, complete the command immediately  */
	o->complete_cmd(pdev, o, ECORE_Q_CMD_INIT);

	mmiowb();
	smp_mb();

	return ECORE_SUCCESS;
}

static INLINE int ecore_q_send_setup_e1x(struct _lm_device_t *pdev,
					struct ecore_queue_state_params *params)
{
	struct ecore_queue_sp_obj *o = params->q_obj;
	struct client_init_ramrod_data *rdata =
		(struct client_init_ramrod_data *)o->rdata;
	lm_address_t data_mapping = o->rdata_mapping;
	int ramrod = RAMROD_CMD_ID_ETH_CLIENT_SETUP;

	/* Clear the ramrod data */
	mm_memset(rdata, 0, sizeof(*rdata));

	/* Fill the ramrod data */
	ecore_q_fill_setup_data_cmn(pdev, params, rdata);

	/* No need for an explicit memory barrier here as long as we
	 * ensure the ordering of writing to the SPQ element
	 * and updating of the SPQ producer which involves a memory
	 * read. If the memory read is removed we will have to put a
	 * full memory barrier there (inside ecore_sp_post()).
	 */
	return ecore_sp_post(pdev,
			     ramrod,
			     o->cids[ECORE_PRIMARY_CID_INDEX],
			     data_mapping.as_u64,
			     ETH_CONNECTION_TYPE);
}

static INLINE int ecore_q_send_setup_e2(struct _lm_device_t *pdev,
					struct ecore_queue_state_params *params)
{
	struct ecore_queue_sp_obj *o = params->q_obj;
	struct client_init_ramrod_data *rdata =
		(struct client_init_ramrod_data *)o->rdata;
	lm_address_t data_mapping = o->rdata_mapping;
	int ramrod = RAMROD_CMD_ID_ETH_CLIENT_SETUP;

	/* Clear the ramrod data */
	mm_memset(rdata, 0, sizeof(*rdata));

	/* Fill the ramrod data */
	ecore_q_fill_setup_data_cmn(pdev, params, rdata);
	ecore_q_fill_setup_data_e2(pdev, params, rdata);

	/* No need for an explicit memory barrier here as long as we
	 * ensure the ordering of writing to the SPQ element
	 * and updating of the SPQ producer which involves a memory
	 * read. If the memory read is removed we will have to put a
	 * full memory barrier there (inside ecore_sp_post()).
	 */
	return ecore_sp_post(pdev,
			     ramrod,
			     o->cids[ECORE_PRIMARY_CID_INDEX],
			     data_mapping.as_u64,
			     ETH_CONNECTION_TYPE);
}

static inline int ecore_q_send_setup_tx_only(struct _lm_device_t *pdev,
				  struct ecore_queue_state_params *params)
{
	struct ecore_queue_sp_obj *o = params->q_obj;
	struct tx_queue_init_ramrod_data *rdata =
		(struct tx_queue_init_ramrod_data *)o->rdata;
	lm_address_t data_mapping = o->rdata_mapping;
	int ramrod = RAMROD_CMD_ID_ETH_TX_QUEUE_SETUP;
	struct ecore_queue_setup_tx_only_params *tx_only_params =
		&params->params.tx_only;
	u8 cid_index = tx_only_params->cid_index;

#ifdef ECORE_OOO /* ! ECORE_UPSTREAM */
	if (ECORE_TEST_BIT(ECORE_Q_TYPE_FWD, &o->type))
		ramrod = RAMROD_CMD_ID_ETH_FORWARD_SETUP;
	ECORE_MSG(pdev, "sending forward tx-only ramrod");
#endif

	if (cid_index >= o->max_cos) {
		ECORE_ERR("queue[%d]: cid_index (%d) is out of range\n",
			  o->cl_id, cid_index);
		return ECORE_INVAL;
	}

	ECORE_MSG(pdev, "parameters received: cos: %d sp-id: %d\n",
		  tx_only_params->gen_params.cos,
		  tx_only_params->gen_params.spcl_id);

	/* Clear the ramrod data */
	mm_memset(rdata, 0, sizeof(*rdata));

	/* Fill the ramrod data */
	ecore_q_fill_setup_tx_only(pdev, params, rdata);

	ECORE_MSG(pdev, "sending tx-only ramrod: cid %d, client-id %d, sp-client id %d, cos %d\n",
		  o->cids[cid_index], rdata->general.client_id,
		  rdata->general.sp_client_id, rdata->general.cos);

	/* No need for an explicit memory barrier here as long as we
	 * ensure the ordering of writing to the SPQ element
	 * and updating of the SPQ producer which involves a memory
	 * read. If the memory read is removed we will have to put a
	 * full memory barrier there (inside ecore_sp_post()).
	 */
	return ecore_sp_post(pdev, ramrod, o->cids[cid_index],
			     data_mapping.as_u64, ETH_CONNECTION_TYPE);
}

static void ecore_q_fill_update_data(struct _lm_device_t *pdev,
				     struct ecore_queue_sp_obj *obj,
				     struct ecore_queue_update_params *params,
				     struct client_update_ramrod_data *data)
{
	/* Client ID of the client to update */
	data->client_id = obj->cl_id;

	/* Function ID of the client to update */
	data->func_id = obj->func_id;

	/* Default VLAN value */
	data->default_vlan = mm_cpu_to_le16(params->def_vlan);

	/* Inner VLAN stripping */
	data->inner_vlan_removal_enable_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_IN_VLAN_REM,
			       &params->update_flags);
	data->inner_vlan_removal_change_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_IN_VLAN_REM_CHNG,
		       &params->update_flags);

	/* Outer VLAN stripping */
	data->outer_vlan_removal_enable_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_OUT_VLAN_REM,
			       &params->update_flags);
	data->outer_vlan_removal_change_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_OUT_VLAN_REM_CHNG,
		       &params->update_flags);

	/* Drop packets that have source MAC that doesn't belong to this
	 * Queue.
	 */
	data->anti_spoofing_enable_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_ANTI_SPOOF,
			       &params->update_flags);
	data->anti_spoofing_change_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_ANTI_SPOOF_CHNG,
		       &params->update_flags);

	/* Activate/Deactivate */
	data->activate_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_ACTIVATE, &params->update_flags);
	data->activate_change_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_ACTIVATE_CHNG,
			       &params->update_flags);

	/* Enable default VLAN */
	data->default_vlan_enable_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_DEF_VLAN_EN,
			       &params->update_flags);
	data->default_vlan_change_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_DEF_VLAN_EN_CHNG,
		       &params->update_flags);

	/* silent vlan removal */
	data->silent_vlan_change_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_SILENT_VLAN_REM_CHNG,
			       &params->update_flags);
	data->silent_vlan_removal_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_SILENT_VLAN_REM,
			       &params->update_flags);
	data->silent_vlan_value = mm_cpu_to_le16(params->silent_removal_value);
	data->silent_vlan_mask = mm_cpu_to_le16(params->silent_removal_mask);

	/* tx switching */
	data->tx_switching_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_TX_SWITCHING,
			       &params->update_flags);
	data->tx_switching_change_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_TX_SWITCHING_CHNG,
			       &params->update_flags);

	/* PTP */
	data->handle_ptp_pkts_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_PTP_PKTS,
			       &params->update_flags);
	data->handle_ptp_pkts_change_flg =
		ECORE_TEST_BIT(ECORE_Q_UPDATE_PTP_PKTS_CHNG,
			       &params->update_flags);
}

static INLINE int ecore_q_send_update(struct _lm_device_t *pdev,
				      struct ecore_queue_state_params *params)
{
	struct ecore_queue_sp_obj *o = params->q_obj;
	struct client_update_ramrod_data *rdata =
		(struct client_update_ramrod_data *)o->rdata;
	lm_address_t data_mapping = o->rdata_mapping;
	struct ecore_queue_update_params *update_params =
		&params->params.update;
	u8 cid_index = update_params->cid_index;

	if (cid_index >= o->max_cos) {
		ECORE_ERR("queue[%d]: cid_index (%d) is out of range\n",
			  o->cl_id, cid_index);
		return ECORE_INVAL;
	}

	/* Clear the ramrod data */
	mm_memset(rdata, 0, sizeof(*rdata));

	/* Fill the ramrod data */
	ecore_q_fill_update_data(pdev, o, update_params, rdata);

	/* No need for an explicit memory barrier here as long as we
	 * ensure the ordering of writing to the SPQ element
	 * and updating of the SPQ producer which involves a memory
	 * read. If the memory read is removed we will have to put a
	 * full memory barrier there (inside ecore_sp_post()).
	 */
	return ecore_sp_post(pdev, RAMROD_CMD_ID_ETH_CLIENT_UPDATE,
			     o->cids[cid_index], data_mapping.as_u64,
			     ETH_CONNECTION_TYPE);
}

/**
 * ecore_q_send_deactivate - send DEACTIVATE command
 *
 * @pdev:	device handle
 * @params:
 *
 * implemented using the UPDATE command.
 */
static INLINE int ecore_q_send_deactivate(struct _lm_device_t *pdev,
					struct ecore_queue_state_params *params)
{
	struct ecore_queue_update_params *update = &params->params.update;

	mm_memset(update, 0, sizeof(*update));

	ECORE_SET_BIT_NA(ECORE_Q_UPDATE_ACTIVATE_CHNG, &update->update_flags);

	return ecore_q_send_update(pdev, params);
}

/**
 * ecore_q_send_activate - send ACTIVATE command
 *
 * @pdev:	device handle
 * @params:
 *
 * implemented using the UPDATE command.
 */
static INLINE int ecore_q_send_activate(struct _lm_device_t *pdev,
					struct ecore_queue_state_params *params)
{
	struct ecore_queue_update_params *update = &params->params.update;

	mm_memset(update, 0, sizeof(*update));

	ECORE_SET_BIT_NA(ECORE_Q_UPDATE_ACTIVATE, &update->update_flags);
	ECORE_SET_BIT_NA(ECORE_Q_UPDATE_ACTIVATE_CHNG, &update->update_flags);

	return ecore_q_send_update(pdev, params);
}

static void ecore_q_fill_update_tpa_data(struct _lm_device_t *pdev,
				struct ecore_queue_sp_obj *obj,
				struct ecore_queue_update_tpa_params *params,
				struct tpa_update_ramrod_data *data)
{
	data->client_id = obj->cl_id;
	data->complete_on_both_clients = params->complete_on_both_clients;
	data->dont_verify_rings_pause_thr_flg =
		params->dont_verify_thr;
	data->max_agg_size = mm_cpu_to_le16(params->max_agg_sz);
	data->max_sges_for_packet = params->max_sges_pkt;
	data->max_tpa_queues = params->max_tpa_queues;
	data->sge_buff_size = mm_cpu_to_le16(params->sge_buff_sz);
	data->sge_page_base_hi = mm_cpu_to_le32(U64_HI(params->sge_map.as_u64));
	data->sge_page_base_lo = mm_cpu_to_le32(U64_LO(params->sge_map.as_u64));
	data->sge_pause_thr_high = mm_cpu_to_le16(params->sge_pause_thr_high);
	data->sge_pause_thr_low = mm_cpu_to_le16(params->sge_pause_thr_low);
	data->tpa_mode = params->tpa_mode;
	data->update_ipv4 = params->update_ipv4;
	data->update_ipv6 = params->update_ipv6;
}

static INLINE int ecore_q_send_update_tpa(struct _lm_device_t *pdev,
					struct ecore_queue_state_params *params)
{
	struct ecore_queue_sp_obj *o = params->q_obj;
	struct tpa_update_ramrod_data *rdata =
		(struct tpa_update_ramrod_data *)o->rdata;
	lm_address_t data_mapping = o->rdata_mapping;
	struct ecore_queue_update_tpa_params *update_tpa_params =
		&params->params.update_tpa;
	u16 type;

	/* Clear the ramrod data */
	mm_memset(rdata, 0, sizeof(*rdata));

	/* Fill the ramrod data */
	ecore_q_fill_update_tpa_data(pdev, o, update_tpa_params, rdata);

	/* Add the function id inside the type, so that sp post function
	 * doesn't automatically add the PF func-id, this is required
	 * for operations done by PFs on behalf of their VFs
	 */
	type = ETH_CONNECTION_TYPE |
		((o->func_id) << SPE_HDR_FUNCTION_ID_SHIFT);

	/* No need for an explicit memory barrier here as long as we
	 * ensure the ordering of writing to the SPQ element
	 * and updating of the SPQ producer which involves a memory
	 * read. If the memory read is removed we will have to put a
	 * full memory barrier there (inside ecore_sp_post()).
	 */
	return ecore_sp_post(pdev, RAMROD_CMD_ID_ETH_TPA_UPDATE,
			     o->cids[ECORE_PRIMARY_CID_INDEX],
			     data_mapping.as_u64, type);
}

static INLINE int ecore_q_send_halt(struct _lm_device_t *pdev,
				    struct ecore_queue_state_params *params)
{
	struct ecore_queue_sp_obj *o = params->q_obj;

#if !defined(ECORE_ERASE) || defined(__FreeBSD__)
	/* build eth_halt_ramrod_data.client_id in a big-endian friendly way */
	lm_address_t    data_mapping = { {0} };
	data_mapping.as_u32.low = o->cl_id;

	/* No need for an explicit memory barrier here as long as we
	 * ensure the ordering of writing to the SPQ element
	 * and updating of the SPQ producer which involves a memory
	 * read. If the memory read is removed we will have to put a
	 * full memory barrier there (inside ecore_sp_post()).
	 */
	return ecore_sp_post(pdev,
			     RAMROD_CMD_ID_ETH_HALT,
			     o->cids[ECORE_PRIMARY_CID_INDEX],
			     data_mapping.as_u64,
			     ETH_CONNECTION_TYPE);
#else
	return bnx2x_sp_post(pdev, RAMROD_CMD_ID_ETH_HALT,
			     o->cids[ECORE_PRIMARY_CID_INDEX], 0, o->cl_id,
			     ETH_CONNECTION_TYPE);
#endif
}

static INLINE int ecore_q_send_cfc_del(struct _lm_device_t *pdev,
				       struct ecore_queue_state_params *params)
{
	struct ecore_queue_sp_obj *o = params->q_obj;
	u8 cid_idx = params->params.cfc_del.cid_index;

	if (cid_idx >= o->max_cos) {
		ECORE_ERR("queue[%d]: cid_index (%d) is out of range\n",
			  o->cl_id, cid_idx);
		return ECORE_INVAL;
	}

	return ecore_sp_post(pdev, RAMROD_CMD_ID_COMMON_CFC_DEL,
			     o->cids[cid_idx], 0,
			     NONE_CONNECTION_TYPE);
}

static INLINE int ecore_q_send_terminate(struct _lm_device_t *pdev,
					struct ecore_queue_state_params *params)
{
	struct ecore_queue_sp_obj *o = params->q_obj;
	u8 cid_index = params->params.terminate.cid_index;

	if (cid_index >= o->max_cos) {
		ECORE_ERR("queue[%d]: cid_index (%d) is out of range\n",
			  o->cl_id, cid_index);
		return ECORE_INVAL;
	}

	return ecore_sp_post(pdev, RAMROD_CMD_ID_ETH_TERMINATE,
			     o->cids[cid_index], 0,
			     ETH_CONNECTION_TYPE);
}

static INLINE int ecore_q_send_empty(struct _lm_device_t *pdev,
				     struct ecore_queue_state_params *params)
{
	struct ecore_queue_sp_obj *o = params->q_obj;

	return ecore_sp_post(pdev, RAMROD_CMD_ID_ETH_EMPTY,
			     o->cids[ECORE_PRIMARY_CID_INDEX], 0,
			     ETH_CONNECTION_TYPE);
}

static INLINE int ecore_queue_send_cmd_cmn(struct _lm_device_t *pdev,
					struct ecore_queue_state_params *params)
{
	switch (params->cmd) {
	case ECORE_Q_CMD_INIT:
		return ecore_q_init(pdev, params);
	case ECORE_Q_CMD_SETUP_TX_ONLY:
		return ecore_q_send_setup_tx_only(pdev, params);
	case ECORE_Q_CMD_DEACTIVATE:
		return ecore_q_send_deactivate(pdev, params);
	case ECORE_Q_CMD_ACTIVATE:
		return ecore_q_send_activate(pdev, params);
	case ECORE_Q_CMD_UPDATE:
		return ecore_q_send_update(pdev, params);
	case ECORE_Q_CMD_UPDATE_TPA:
		return ecore_q_send_update_tpa(pdev, params);
	case ECORE_Q_CMD_HALT:
		return ecore_q_send_halt(pdev, params);
	case ECORE_Q_CMD_CFC_DEL:
		return ecore_q_send_cfc_del(pdev, params);
	case ECORE_Q_CMD_TERMINATE:
		return ecore_q_send_terminate(pdev, params);
	case ECORE_Q_CMD_EMPTY:
		return ecore_q_send_empty(pdev, params);
	default:
		ECORE_ERR("Unknown command: %d\n", params->cmd);
		return ECORE_INVAL;
	}
}

static int ecore_queue_send_cmd_e1x(struct _lm_device_t *pdev,
				    struct ecore_queue_state_params *params)
{
	switch (params->cmd) {
	case ECORE_Q_CMD_SETUP:
		return ecore_q_send_setup_e1x(pdev, params);
	case ECORE_Q_CMD_INIT:
	case ECORE_Q_CMD_SETUP_TX_ONLY:
	case ECORE_Q_CMD_DEACTIVATE:
	case ECORE_Q_CMD_ACTIVATE:
	case ECORE_Q_CMD_UPDATE:
	case ECORE_Q_CMD_UPDATE_TPA:
	case ECORE_Q_CMD_HALT:
	case ECORE_Q_CMD_CFC_DEL:
	case ECORE_Q_CMD_TERMINATE:
	case ECORE_Q_CMD_EMPTY:
		return ecore_queue_send_cmd_cmn(pdev, params);
	default:
		ECORE_ERR("Unknown command: %d\n", params->cmd);
		return ECORE_INVAL;
	}
}

static int ecore_queue_send_cmd_e2(struct _lm_device_t *pdev,
				   struct ecore_queue_state_params *params)
{
	switch (params->cmd) {
	case ECORE_Q_CMD_SETUP:
		return ecore_q_send_setup_e2(pdev, params);
	case ECORE_Q_CMD_INIT:
	case ECORE_Q_CMD_SETUP_TX_ONLY:
	case ECORE_Q_CMD_DEACTIVATE:
	case ECORE_Q_CMD_ACTIVATE:
	case ECORE_Q_CMD_UPDATE:
	case ECORE_Q_CMD_UPDATE_TPA:
	case ECORE_Q_CMD_HALT:
	case ECORE_Q_CMD_CFC_DEL:
	case ECORE_Q_CMD_TERMINATE:
	case ECORE_Q_CMD_EMPTY:
		return ecore_queue_send_cmd_cmn(pdev, params);
	default:
		ECORE_ERR("Unknown command: %d\n", params->cmd);
		return ECORE_INVAL;
	}
}

/**
 * ecore_queue_chk_transition - check state machine of a regular Queue
 *
 * @pdev:	device handle
 * @o:
 * @params:
 *
 * (not Forwarding)
 * It both checks if the requested command is legal in a current
 * state and, if it's legal, sets a `next_state' in the object
 * that will be used in the completion flow to set the `state'
 * of the object.
 *
 * returns 0 if a requested command is a legal transition,
 *         ECORE_INVAL otherwise.
 */
static int ecore_queue_chk_transition(struct _lm_device_t *pdev,
				      struct ecore_queue_sp_obj *o,
				      struct ecore_queue_state_params *params)
{
	enum ecore_q_state state = o->state, next_state = ECORE_Q_STATE_MAX;
	enum ecore_queue_cmd cmd = params->cmd;
	struct ecore_queue_update_params *update_params =
		 &params->params.update;
	u8 next_tx_only = o->num_tx_only;

	/* Forget all pending for completion commands if a driver only state
	 * transition has been requested.
	 */
	if (ECORE_TEST_BIT(RAMROD_DRV_CLR_ONLY, &params->ramrod_flags)) {
		o->pending = 0;
		o->next_state = ECORE_Q_STATE_MAX;
	}

	/* Don't allow a next state transition if we are in the middle of
	 * the previous one.
	 */
	if (o->pending) {
		ECORE_ERR("Blocking transition since pending was %lx\n",
			  o->pending);
		return ECORE_BUSY;
	}

	switch (state) {
	case ECORE_Q_STATE_RESET:
		if (cmd == ECORE_Q_CMD_INIT)
			next_state = ECORE_Q_STATE_INITIALIZED;

		break;
	case ECORE_Q_STATE_INITIALIZED:
		if (cmd == ECORE_Q_CMD_SETUP) {
			if (ECORE_TEST_BIT(ECORE_Q_FLG_ACTIVE,
					   &params->params.setup.flags))
				next_state = ECORE_Q_STATE_ACTIVE;
			else
				next_state = ECORE_Q_STATE_INACTIVE;
		}

		break;
	case ECORE_Q_STATE_ACTIVE:
		if (cmd == ECORE_Q_CMD_DEACTIVATE)
			next_state = ECORE_Q_STATE_INACTIVE;

		else if ((cmd == ECORE_Q_CMD_EMPTY) ||
			 (cmd == ECORE_Q_CMD_UPDATE_TPA))
			next_state = ECORE_Q_STATE_ACTIVE;

		else if (cmd == ECORE_Q_CMD_SETUP_TX_ONLY) {
			next_state = ECORE_Q_STATE_MULTI_COS;
			next_tx_only = 1;
		}

		else if (cmd == ECORE_Q_CMD_HALT)
			next_state = ECORE_Q_STATE_STOPPED;

		else if (cmd == ECORE_Q_CMD_UPDATE) {
			/* If "active" state change is requested, update the
			 *  state accordingly.
			 */
			if (ECORE_TEST_BIT(ECORE_Q_UPDATE_ACTIVATE_CHNG,
					   &update_params->update_flags) &&
			    !ECORE_TEST_BIT(ECORE_Q_UPDATE_ACTIVATE,
					    &update_params->update_flags))
				next_state = ECORE_Q_STATE_INACTIVE;
			else
				next_state = ECORE_Q_STATE_ACTIVE;
		}

		break;
	case ECORE_Q_STATE_MULTI_COS:
		if (cmd == ECORE_Q_CMD_TERMINATE)
			next_state = ECORE_Q_STATE_MCOS_TERMINATED;

		else if (cmd == ECORE_Q_CMD_SETUP_TX_ONLY) {
			next_state = ECORE_Q_STATE_MULTI_COS;
			next_tx_only = o->num_tx_only + 1;
		}

		else if ((cmd == ECORE_Q_CMD_EMPTY) ||
			 (cmd == ECORE_Q_CMD_UPDATE_TPA))
			next_state = ECORE_Q_STATE_MULTI_COS;

		else if (cmd == ECORE_Q_CMD_UPDATE) {
			/* If "active" state change is requested, update the
			 *  state accordingly.
			 */
			if (ECORE_TEST_BIT(ECORE_Q_UPDATE_ACTIVATE_CHNG,
					   &update_params->update_flags) &&
			    !ECORE_TEST_BIT(ECORE_Q_UPDATE_ACTIVATE,
					    &update_params->update_flags))
				next_state = ECORE_Q_STATE_INACTIVE;
			else
				next_state = ECORE_Q_STATE_MULTI_COS;
		}

		break;
	case ECORE_Q_STATE_MCOS_TERMINATED:
		if (cmd == ECORE_Q_CMD_CFC_DEL) {
			next_tx_only = o->num_tx_only - 1;
			if (next_tx_only == 0)
				next_state = ECORE_Q_STATE_ACTIVE;
			else
				next_state = ECORE_Q_STATE_MULTI_COS;
		}

		break;
	case ECORE_Q_STATE_INACTIVE:
		if (cmd == ECORE_Q_CMD_ACTIVATE)
			next_state = ECORE_Q_STATE_ACTIVE;

		else if ((cmd == ECORE_Q_CMD_EMPTY) ||
			 (cmd == ECORE_Q_CMD_UPDATE_TPA))
			next_state = ECORE_Q_STATE_INACTIVE;

		else if (cmd == ECORE_Q_CMD_HALT)
			next_state = ECORE_Q_STATE_STOPPED;

		else if (cmd == ECORE_Q_CMD_UPDATE) {
			/* If "active" state change is requested, update the
			 * state accordingly.
			 */
			if (ECORE_TEST_BIT(ECORE_Q_UPDATE_ACTIVATE_CHNG,
					   &update_params->update_flags) &&
			    ECORE_TEST_BIT(ECORE_Q_UPDATE_ACTIVATE,
					   &update_params->update_flags)){
				if (o->num_tx_only == 0)
					next_state = ECORE_Q_STATE_ACTIVE;
				else /* tx only queues exist for this queue */
					next_state = ECORE_Q_STATE_MULTI_COS;
			} else
				next_state = ECORE_Q_STATE_INACTIVE;
		}

		break;
	case ECORE_Q_STATE_STOPPED:
		if (cmd == ECORE_Q_CMD_TERMINATE)
			next_state = ECORE_Q_STATE_TERMINATED;

		break;
	case ECORE_Q_STATE_TERMINATED:
		if (cmd == ECORE_Q_CMD_CFC_DEL)
			next_state = ECORE_Q_STATE_RESET;

		break;
	default:
		ECORE_ERR("Illegal state: %d\n", state);
	}

	/* Transition is assured */
	if (next_state != ECORE_Q_STATE_MAX) {
		ECORE_MSG(pdev, "Good state transition: %d(%d)->%d\n",
			  state, cmd, next_state);
		o->next_state = next_state;
		o->next_tx_only = next_tx_only;
		return ECORE_SUCCESS;
	}

	ECORE_MSG(pdev, "Bad state transition request: %d %d\n", state, cmd);

	return ECORE_INVAL;
}
#ifdef ECORE_OOO /* ! ECORE_UPSTREAM */

/**
 * ecore_queue_chk_fwd_transition - check state machine of a Forwarding Queue.
 *
 * @pdev:	device handle
 * @o:
 * @params:
 *
 * It both checks if the requested command is legal in a current
 * state and, if it's legal, sets a `next_state' in the object
 * that will be used in the completion flow to set the `state'
 * of the object.
 *
 * returns 0 if a requested command is a legal transition,
 *         ECORE_INVAL otherwise.
 */
static int ecore_queue_chk_fwd_transition(struct _lm_device_t *pdev,
					  struct ecore_queue_sp_obj *o,
					struct ecore_queue_state_params *params)
{
	enum ecore_q_state state = o->state, next_state = ECORE_Q_STATE_MAX;
	enum ecore_queue_cmd cmd = params->cmd;

	switch (state) {
	case ECORE_Q_STATE_RESET:
		if (cmd == ECORE_Q_CMD_INIT)
			next_state = ECORE_Q_STATE_INITIALIZED;

		break;
	case ECORE_Q_STATE_INITIALIZED:
		if (cmd == ECORE_Q_CMD_SETUP_TX_ONLY) {
			if (ECORE_TEST_BIT(ECORE_Q_FLG_ACTIVE,
					   &params->params.tx_only.flags))
				next_state = ECORE_Q_STATE_ACTIVE;
			else
				next_state = ECORE_Q_STATE_INACTIVE;
		}

		break;
	case ECORE_Q_STATE_ACTIVE:
	case ECORE_Q_STATE_INACTIVE:
		if (cmd == ECORE_Q_CMD_CFC_DEL)
			next_state = ECORE_Q_STATE_RESET;

		break;
	default:
		ECORE_ERR("Illegal state: %d\n", state);
	}

	/* Transition is assured */
	if (next_state != ECORE_Q_STATE_MAX) {
		ECORE_MSG(pdev, "Good state transition: %d(%d)->%d\n",
			  state, cmd, next_state);
		o->next_state = next_state;
		return ECORE_SUCCESS;
	}

	ECORE_MSG(pdev, "Bad state transition request: %d %d\n", state, cmd);
	return ECORE_INVAL;
}
#endif

void ecore_init_queue_obj(struct _lm_device_t *pdev,
			  struct ecore_queue_sp_obj *obj,
			  u8 cl_id, u32 *cids, u8 cid_cnt, u8 func_id,
			  void *rdata,
			  lm_address_t rdata_mapping, unsigned long type)
{
	mm_memset(obj, 0, sizeof(*obj));

	/* We support only ECORE_MULTI_TX_COS Tx CoS at the moment */
	BUG_ON(ECORE_MULTI_TX_COS < cid_cnt);

	memcpy(obj->cids, cids, sizeof(obj->cids[0]) * cid_cnt);
	obj->max_cos = cid_cnt;
	obj->cl_id = cl_id;
	obj->func_id = func_id;
	obj->rdata = rdata;
	obj->rdata_mapping = rdata_mapping;
	obj->type = type;
	obj->next_state = ECORE_Q_STATE_MAX;

	if (CHIP_IS_E1x(pdev))
		obj->send_cmd = ecore_queue_send_cmd_e1x;
	else
		obj->send_cmd = ecore_queue_send_cmd_e2;

#ifdef ECORE_OOO /* ! ECORE_UPSTREAM */
	if (ECORE_TEST_BIT(ECORE_Q_TYPE_FWD, &type))
		obj->check_transition = ecore_queue_chk_fwd_transition;
	else
#endif
	obj->check_transition = ecore_queue_chk_transition;

	obj->complete_cmd = ecore_queue_comp_cmd;
	obj->wait_comp = ecore_queue_wait_comp;
	obj->set_pending = ecore_queue_set_pending;
}

/* return a queue object's logical state*/
int ecore_get_q_logical_state(struct _lm_device_t *pdev,
			       struct ecore_queue_sp_obj *obj)
{
	switch (obj->state) {
	case ECORE_Q_STATE_ACTIVE:
	case ECORE_Q_STATE_MULTI_COS:
		return ECORE_Q_LOGICAL_STATE_ACTIVE;
	case ECORE_Q_STATE_RESET:
	case ECORE_Q_STATE_INITIALIZED:
	case ECORE_Q_STATE_MCOS_TERMINATED:
	case ECORE_Q_STATE_INACTIVE:
	case ECORE_Q_STATE_STOPPED:
	case ECORE_Q_STATE_TERMINATED:
	case ECORE_Q_STATE_FLRED:
		return ECORE_Q_LOGICAL_STATE_STOPPED;
	default:
		return ECORE_INVAL;
	}
}

/********************** Function state object *********************************/
enum ecore_func_state ecore_func_get_state(struct _lm_device_t *pdev,
					   struct ecore_func_sp_obj *o)
{
	/* in the middle of transaction - return INVALID state */
	if (o->pending)
		return ECORE_F_STATE_MAX;

	/* unsure the order of reading of o->pending and o->state
	 * o->pending should be read first
	 */
	rmb();

	return o->state;
}

static int ecore_func_wait_comp(struct _lm_device_t *pdev,
				struct ecore_func_sp_obj *o,
				enum ecore_func_cmd cmd)
{
	return ecore_state_wait(pdev, cmd, &o->pending);
}

/**
 * ecore_func_state_change_comp - complete the state machine transition
 *
 * @pdev:	device handle
 * @o:
 * @cmd:
 *
 * Called on state change transition. Completes the state
 * machine transition only - no HW interaction.
 */
static INLINE int ecore_func_state_change_comp(struct _lm_device_t *pdev,
					       struct ecore_func_sp_obj *o,
					       enum ecore_func_cmd cmd)
{
	unsigned long cur_pending = o->pending;

	if (!ECORE_TEST_AND_CLEAR_BIT(cmd, &cur_pending)) {
		ECORE_ERR("Bad MC reply %d for func %d in state %d pending 0x%lx, next_state %d\n",
			  cmd, FUNC_ID(pdev), o->state,
			  cur_pending, o->next_state);
		return ECORE_INVAL;
	}

	ECORE_MSG(pdev,
		  "Completing command %d for func %d, setting state to %d\n",
		  cmd, FUNC_ID(pdev), o->next_state);

	o->state = o->next_state;
	o->next_state = ECORE_F_STATE_MAX;

	/* It's important that o->state and o->next_state are
	 * updated before o->pending.
	 */
	wmb();

	ECORE_CLEAR_BIT(cmd, &o->pending);
	smp_mb__after_atomic();

	return ECORE_SUCCESS;
}

/**
 * ecore_func_comp_cmd - complete the state change command
 *
 * @pdev:	device handle
 * @o:
 * @cmd:
 *
 * Checks that the arrived completion is expected.
 */
static int ecore_func_comp_cmd(struct _lm_device_t *pdev,
			       struct ecore_func_sp_obj *o,
			       enum ecore_func_cmd cmd)
{
	/* Complete the state machine part first, check if it's a
	 * legal completion.
	 */
	int rc = ecore_func_state_change_comp(pdev, o, cmd);
	return rc;
}

/**
 * ecore_func_chk_transition - perform function state machine transition
 *
 * @pdev:	device handle
 * @o:
 * @params:
 *
 * It both checks if the requested command is legal in a current
 * state and, if it's legal, sets a `next_state' in the object
 * that will be used in the completion flow to set the `state'
 * of the object.
 *
 * returns 0 if a requested command is a legal transition,
 *         ECORE_INVAL otherwise.
 */
static int ecore_func_chk_transition(struct _lm_device_t *pdev,
				     struct ecore_func_sp_obj *o,
				     struct ecore_func_state_params *params)
{
	enum ecore_func_state state = o->state, next_state = ECORE_F_STATE_MAX;
	enum ecore_func_cmd cmd = params->cmd;

	/* Forget all pending for completion commands if a driver only state
	 * transition has been requested.
	 */
	if (ECORE_TEST_BIT(RAMROD_DRV_CLR_ONLY, &params->ramrod_flags)) {
		o->pending = 0;
		o->next_state = ECORE_F_STATE_MAX;
	}

	/* Don't allow a next state transition if we are in the middle of
	 * the previous one.
	 */
	if (o->pending)
		return ECORE_BUSY;

	switch (state) {
	case ECORE_F_STATE_RESET:
		if (cmd == ECORE_F_CMD_HW_INIT)
			next_state = ECORE_F_STATE_INITIALIZED;

		break;
	case ECORE_F_STATE_INITIALIZED:
		if (cmd == ECORE_F_CMD_START)
			next_state = ECORE_F_STATE_STARTED;

		else if (cmd == ECORE_F_CMD_HW_RESET)
			next_state = ECORE_F_STATE_RESET;

		break;
	case ECORE_F_STATE_STARTED:
		if (cmd == ECORE_F_CMD_STOP)
			next_state = ECORE_F_STATE_INITIALIZED;
		/* afex ramrods can be sent only in started mode, and only
		 * if not pending for function_stop ramrod completion
		 * for these events - next state remained STARTED.
		 */
		else if ((cmd == ECORE_F_CMD_AFEX_UPDATE) &&
			 (!ECORE_TEST_BIT(ECORE_F_CMD_STOP, &o->pending)))
			next_state = ECORE_F_STATE_STARTED;

		else if ((cmd == ECORE_F_CMD_AFEX_VIFLISTS) &&
			 (!ECORE_TEST_BIT(ECORE_F_CMD_STOP, &o->pending)))
			next_state = ECORE_F_STATE_STARTED;

		/* Switch_update ramrod can be sent in either started or
		 * tx_stopped state, and it doesn't change the state.
		 */
		else if ((cmd == ECORE_F_CMD_SWITCH_UPDATE) &&
			 (!ECORE_TEST_BIT(ECORE_F_CMD_STOP, &o->pending)))
			next_state = ECORE_F_STATE_STARTED;

		else if ((cmd == ECORE_F_CMD_SET_TIMESYNC) &&
			 (!ECORE_TEST_BIT(ECORE_F_CMD_STOP, &o->pending)))
			next_state = ECORE_F_STATE_STARTED;

		else if (cmd == ECORE_F_CMD_TX_STOP)
			next_state = ECORE_F_STATE_TX_STOPPED;

		break;
	case ECORE_F_STATE_TX_STOPPED:
		if ((cmd == ECORE_F_CMD_SWITCH_UPDATE) &&
		    (!ECORE_TEST_BIT(ECORE_F_CMD_STOP, &o->pending)))
			next_state = ECORE_F_STATE_TX_STOPPED;

		else if ((cmd == ECORE_F_CMD_SET_TIMESYNC) &&
		    (!ECORE_TEST_BIT(ECORE_F_CMD_STOP, &o->pending)))
			next_state = ECORE_F_STATE_TX_STOPPED;

		else if (cmd == ECORE_F_CMD_TX_START)
			next_state = ECORE_F_STATE_STARTED;

		break;
	default:
		ECORE_ERR("Unknown state: %d\n", state);
	}

	/* Transition is assured */
	if (next_state != ECORE_F_STATE_MAX) {
		ECORE_MSG(pdev, "Good function state transition: %d(%d)->%d\n",
			  state, cmd, next_state);
		o->next_state = next_state;
		return ECORE_SUCCESS;
	}

	ECORE_MSG(pdev, "Bad function state transition request: %d %d\n",
		  state, cmd);

	return ECORE_INVAL;
}

/**
 * ecore_func_init_func - performs HW init at function stage
 *
 * @pdev:	device handle
 * @drv:
 *
 * Init HW when the current phase is
 * FW_MSG_CODE_DRV_LOAD_FUNCTION: initialize only FUNCTION-only
 * HW blocks.
 */
static INLINE int ecore_func_init_func(struct _lm_device_t *pdev,
				       const struct ecore_func_sp_drv_ops *drv)
{
	return drv->init_hw_func(pdev);
}

/**
 * ecore_func_init_port - performs HW init at port stage
 *
 * @pdev:	device handle
 * @drv:
 *
 * Init HW when the current phase is
 * FW_MSG_CODE_DRV_LOAD_PORT: initialize PORT-only and
 * FUNCTION-only HW blocks.
 *
 */
static INLINE int ecore_func_init_port(struct _lm_device_t *pdev,
				       const struct ecore_func_sp_drv_ops *drv)
{
	int rc = drv->init_hw_port(pdev);
	if (rc)
		return rc;

	return ecore_func_init_func(pdev, drv);
}

/**
 * ecore_func_init_cmn_chip - performs HW init at chip-common stage
 *
 * @pdev:	device handle
 * @drv:
 *
 * Init HW when the current phase is
 * FW_MSG_CODE_DRV_LOAD_COMMON_CHIP: initialize COMMON_CHIP,
 * PORT-only and FUNCTION-only HW blocks.
 */
static INLINE int ecore_func_init_cmn_chip(struct _lm_device_t *pdev,
					const struct ecore_func_sp_drv_ops *drv)
{
	int rc = drv->init_hw_cmn_chip(pdev);
	if (rc)
		return rc;

	return ecore_func_init_port(pdev, drv);
}

/**
 * ecore_func_init_cmn - performs HW init at common stage
 *
 * @pdev:	device handle
 * @drv:
 *
 * Init HW when the current phase is
 * FW_MSG_CODE_DRV_LOAD_COMMON_CHIP: initialize COMMON,
 * PORT-only and FUNCTION-only HW blocks.
 */
static INLINE int ecore_func_init_cmn(struct _lm_device_t *pdev,
				      const struct ecore_func_sp_drv_ops *drv)
{
	int rc = drv->init_hw_cmn(pdev);
	if (rc)
		return rc;

	return ecore_func_init_port(pdev, drv);
}

static int ecore_func_hw_init(struct _lm_device_t *pdev,
			      struct ecore_func_state_params *params)
{
	u32 load_code = params->params.hw_init.load_phase;
	struct ecore_func_sp_obj *o = params->f_obj;
	const struct ecore_func_sp_drv_ops *drv = o->drv;
	int rc = 0;

	ECORE_MSG(pdev, "function %d  load_code %x\n",
		  ABS_FUNC_ID(pdev), load_code);

	/* Prepare buffers for unzipping the FW */
	rc = drv->gunzip_init(pdev);
	if (rc)
		return rc;

	/* Prepare FW */
	rc = drv->init_fw(pdev);
	if (rc) {
		ECORE_ERR("Error loading firmware\n");
		goto init_err;
	}

	/* Handle the beginning of COMMON_XXX pases separately... */
	switch (load_code) {
	case FW_MSG_CODE_DRV_LOAD_COMMON_CHIP:
		rc = ecore_func_init_cmn_chip(pdev, drv);
		if (rc)
			goto init_err;

		break;
	case FW_MSG_CODE_DRV_LOAD_COMMON:
		rc = ecore_func_init_cmn(pdev, drv);
		if (rc)
			goto init_err;

		break;
	case FW_MSG_CODE_DRV_LOAD_PORT:
		rc = ecore_func_init_port(pdev, drv);
		if (rc)
			goto init_err;

		break;
	case FW_MSG_CODE_DRV_LOAD_FUNCTION:
		rc = ecore_func_init_func(pdev, drv);
		if (rc)
			goto init_err;

		break;
	default:
		ECORE_ERR("Unknown load_code (0x%x) from MCP\n", load_code);
		rc = ECORE_INVAL;
	}

init_err:
	drv->gunzip_end(pdev);

	/* In case of success, complete the command immediately: no ramrods
	 * have been sent.
	 */
	if (!rc)
		o->complete_cmd(pdev, o, ECORE_F_CMD_HW_INIT);

	return rc;
}

/**
 * ecore_func_reset_func - reset HW at function stage
 *
 * @pdev:	device handle
 * @drv:
 *
 * Reset HW at FW_MSG_CODE_DRV_UNLOAD_FUNCTION stage: reset only
 * FUNCTION-only HW blocks.
 */
static INLINE void ecore_func_reset_func(struct _lm_device_t *pdev,
					const struct ecore_func_sp_drv_ops *drv)
{
	drv->reset_hw_func(pdev);
}

/**
 * ecore_func_reset_port - reser HW at port stage
 *
 * @pdev:	device handle
 * @drv:
 *
 * Reset HW at FW_MSG_CODE_DRV_UNLOAD_PORT stage: reset
 * FUNCTION-only and PORT-only HW blocks.
 *
 *                 !!!IMPORTANT!!!
 *
 * It's important to call reset_port before reset_func() as the last thing
 * reset_func does is pf_disable() thus disabling PGLUE_B, which
 * makes impossible any DMAE transactions.
 */
static INLINE void ecore_func_reset_port(struct _lm_device_t *pdev,
					const struct ecore_func_sp_drv_ops *drv)
{
	drv->reset_hw_port(pdev);
	ecore_func_reset_func(pdev, drv);
}

/**
 * ecore_func_reset_cmn - reser HW at common stage
 *
 * @pdev:	device handle
 * @drv:
 *
 * Reset HW at FW_MSG_CODE_DRV_UNLOAD_COMMON and
 * FW_MSG_CODE_DRV_UNLOAD_COMMON_CHIP stages: reset COMMON,
 * COMMON_CHIP, FUNCTION-only and PORT-only HW blocks.
 */
static INLINE void ecore_func_reset_cmn(struct _lm_device_t *pdev,
					const struct ecore_func_sp_drv_ops *drv)
{
	ecore_func_reset_port(pdev, drv);
	drv->reset_hw_cmn(pdev);
}

static INLINE int ecore_func_hw_reset(struct _lm_device_t *pdev,
				      struct ecore_func_state_params *params)
{
	u32 reset_phase = params->params.hw_reset.reset_phase;
	struct ecore_func_sp_obj *o = params->f_obj;
	const struct ecore_func_sp_drv_ops *drv = o->drv;

	ECORE_MSG(pdev, "function %d  reset_phase %x\n", ABS_FUNC_ID(pdev),
		  reset_phase);

	switch (reset_phase) {
	case FW_MSG_CODE_DRV_UNLOAD_COMMON:
		ecore_func_reset_cmn(pdev, drv);
		break;
	case FW_MSG_CODE_DRV_UNLOAD_PORT:
		ecore_func_reset_port(pdev, drv);
		break;
	case FW_MSG_CODE_DRV_UNLOAD_FUNCTION:
		ecore_func_reset_func(pdev, drv);
		break;
	default:
		ECORE_ERR("Unknown reset_phase (0x%x) from MCP\n",
			  reset_phase);
		break;
	}

	/* Complete the command immediately: no ramrods have been sent. */
	o->complete_cmd(pdev, o, ECORE_F_CMD_HW_RESET);

	return ECORE_SUCCESS;
}

static INLINE int ecore_func_send_start(struct _lm_device_t *pdev,
					struct ecore_func_state_params *params)
{
	struct ecore_func_sp_obj *o = params->f_obj;
	struct function_start_data *rdata =
		(struct function_start_data *)o->rdata;
	lm_address_t data_mapping = o->rdata_mapping;
	struct ecore_func_start_params *start_params = &params->params.start;

	mm_memset(rdata, 0, sizeof(*rdata));

	/* Fill the ramrod data with provided parameters */
	rdata->function_mode	= (u8)start_params->mf_mode;
	rdata->sd_vlan_tag	= mm_cpu_to_le16(start_params->sd_vlan_tag);
	rdata->path_id		= PATH_ID(pdev);
	rdata->network_cos_mode	= start_params->network_cos_mode;
	rdata->tunnel_mode	= start_params->tunnel_mode;
	rdata->gre_tunnel_type	= start_params->gre_tunnel_type;
	rdata->inner_gre_rss_en = start_params->inner_gre_rss_en;
	rdata->vxlan_dst_port	= start_params->vxlan_dst_port;
	rdata->sd_accept_mf_clss_fail = start_params->class_fail;
	if (start_params->class_fail_ethtype) {
		rdata->sd_accept_mf_clss_fail_match_ethtype = 1;
		rdata->sd_accept_mf_clss_fail_ethtype =
			mm_cpu_to_le16(start_params->class_fail_ethtype);
	}
	rdata->sd_vlan_force_pri_flg = start_params->sd_vlan_force_pri;
	rdata->sd_vlan_force_pri_val = start_params->sd_vlan_force_pri_val;

	/** @@@TMP - until FW 7.10.7 (which will introduce an HSI change)
	 * `sd_vlan_eth_type' will replace ethertype in SD mode even if
	 * it's set to 0; This will probably break SD, so we're setting it
	 * to ethertype 0x8100 for now.
	 */
	if (start_params->sd_vlan_eth_type)
		rdata->sd_vlan_eth_type =
			mm_cpu_to_le16(start_params->sd_vlan_eth_type);
	else
		rdata->sd_vlan_eth_type =
			mm_cpu_to_le16((u16) 0x8100);

	rdata->no_added_tags = start_params->no_added_tags;

	/* No need for an explicit memory barrier here as long as we
	 * ensure the ordering of writing to the SPQ element
	 * and updating of the SPQ producer which involves a memory
	 * read. If the memory read is removed we will have to put a
	 * full memory barrier there (inside ecore_sp_post()).
	 */
	return ecore_sp_post(pdev, RAMROD_CMD_ID_COMMON_FUNCTION_START, 0,
			     data_mapping.as_u64, NONE_CONNECTION_TYPE);
}

static INLINE int ecore_func_send_switch_update(struct _lm_device_t *pdev,
					struct ecore_func_state_params *params)
{
	struct ecore_func_sp_obj *o = params->f_obj;
	struct function_update_data *rdata =
		(struct function_update_data *)o->rdata;
	lm_address_t data_mapping = o->rdata_mapping;
	struct ecore_func_switch_update_params *switch_update_params =
		&params->params.switch_update;

	mm_memset(rdata, 0, sizeof(*rdata));

	/* Fill the ramrod data with provided parameters */
	if (ECORE_TEST_BIT(ECORE_F_UPDATE_TX_SWITCH_SUSPEND_CHNG,
			   &switch_update_params->changes)) {
		rdata->tx_switch_suspend_change_flg = 1;
		rdata->tx_switch_suspend =
			ECORE_TEST_BIT(ECORE_F_UPDATE_TX_SWITCH_SUSPEND,
				       &switch_update_params->changes);
	}

	if (ECORE_TEST_BIT(ECORE_F_UPDATE_SD_VLAN_TAG_CHNG,
			   &switch_update_params->changes)) {
		rdata->sd_vlan_tag_change_flg = 1;
		rdata->sd_vlan_tag =
			mm_cpu_to_le16(switch_update_params->vlan);
	}

	if (ECORE_TEST_BIT(ECORE_F_UPDATE_SD_VLAN_ETH_TYPE_CHNG,
			   &switch_update_params->changes)) {
		rdata->sd_vlan_eth_type_change_flg = 1;
		rdata->sd_vlan_eth_type =
			mm_cpu_to_le16(switch_update_params->vlan_eth_type);
	}

	if (ECORE_TEST_BIT(ECORE_F_UPDATE_VLAN_FORCE_PRIO_CHNG,
			   &switch_update_params->changes)) {
		rdata->sd_vlan_force_pri_change_flg = 1;
		if (ECORE_TEST_BIT(ECORE_F_UPDATE_VLAN_FORCE_PRIO_FLAG,
				   &switch_update_params->changes))
			rdata->sd_vlan_force_pri_flg = 1;
		rdata->sd_vlan_force_pri_flg =
			switch_update_params->vlan_force_prio;
	}

	if (ECORE_TEST_BIT(ECORE_F_UPDATE_TUNNEL_CFG_CHNG,
			   &switch_update_params->changes)) {
		rdata->update_tunn_cfg_flg = 1;
		if (ECORE_TEST_BIT(ECORE_F_UPDATE_TUNNEL_CLSS_EN,
				   &switch_update_params->changes))
			rdata->tunn_clss_en = 1;
		if (ECORE_TEST_BIT(ECORE_F_UPDATE_TUNNEL_INNER_GRE_RSS_EN,
				   &switch_update_params->changes))
			rdata->inner_gre_rss_en = 1;
		rdata->tunnel_mode = switch_update_params->tunnel_mode;
		rdata->gre_tunnel_type = switch_update_params->gre_tunnel_type;
		rdata->vxlan_dst_port =
			mm_cpu_to_le16(switch_update_params->vxlan_dst_port);
	}

	rdata->echo = SWITCH_UPDATE;

	/* No need for an explicit memory barrier here as long as we
	 * ensure the ordering of writing to the SPQ element
	 * and updating of the SPQ producer which involves a memory
	 * read. If the memory read is removed we will have to put a
	 * full memory barrier there (inside ecore_sp_post()).
	 */
	return ecore_sp_post(pdev, RAMROD_CMD_ID_COMMON_FUNCTION_UPDATE, 0,
			     data_mapping.as_u64, NONE_CONNECTION_TYPE);
}

static INLINE int ecore_func_send_afex_update(struct _lm_device_t *pdev,
					 struct ecore_func_state_params *params)
{
	struct ecore_func_sp_obj *o = params->f_obj;
	struct function_update_data *rdata =
		(struct function_update_data *)o->afex_rdata;
	lm_address_t data_mapping = o->afex_rdata_mapping;
	struct ecore_func_afex_update_params *afex_update_params =
		&params->params.afex_update;

	mm_memset(rdata, 0, sizeof(*rdata));

	/* Fill the ramrod data with provided parameters */
	rdata->vif_id_change_flg = 1;
	rdata->vif_id = mm_cpu_to_le16(afex_update_params->vif_id);
	rdata->afex_default_vlan_change_flg = 1;
	rdata->afex_default_vlan =
		mm_cpu_to_le16(afex_update_params->afex_default_vlan);
	rdata->allowed_priorities_change_flg = 1;
	rdata->allowed_priorities = afex_update_params->allowed_priorities;
	rdata->echo = AFEX_UPDATE;

	/* No need for an explicit memory barrier here as long as we
	 * ensure the ordering of writing to the SPQ element
	 * and updating of the SPQ producer which involves a memory
	 * read. If the memory read is removed we will have to put a
	 * full memory barrier there (inside ecore_sp_post()).
	 */
	ECORE_MSG(pdev,
		  "afex: sending func_update vif_id 0x%x dvlan 0x%x prio 0x%x\n",
		  rdata->vif_id,
		  rdata->afex_default_vlan, rdata->allowed_priorities);

	return ecore_sp_post(pdev, RAMROD_CMD_ID_COMMON_FUNCTION_UPDATE, 0,
			     data_mapping.as_u64, NONE_CONNECTION_TYPE);
}

static
INLINE int ecore_func_send_afex_viflists(struct _lm_device_t *pdev,
					 struct ecore_func_state_params *params)
{
	struct ecore_func_sp_obj *o = params->f_obj;
	struct afex_vif_list_ramrod_data *rdata =
		(struct afex_vif_list_ramrod_data *)o->afex_rdata;
	struct ecore_func_afex_viflists_params *afex_vif_params =
		&params->params.afex_viflists;
	u64 *p_rdata = (u64 *)rdata;

	mm_memset(rdata, 0, sizeof(*rdata));

	/* Fill the ramrod data with provided parameters */
	rdata->vif_list_index = mm_cpu_to_le16(afex_vif_params->vif_list_index);
	rdata->func_bit_map          = afex_vif_params->func_bit_map;
	rdata->afex_vif_list_command = afex_vif_params->afex_vif_list_command;
	rdata->func_to_clear         = afex_vif_params->func_to_clear;

	/* send in echo type of sub command */
	rdata->echo = afex_vif_params->afex_vif_list_command;

	ECORE_MSG(pdev, "afex: ramrod lists, cmd 0x%x index 0x%x func_bit_map 0x%x func_to_clr 0x%x\n",
		  rdata->afex_vif_list_command, rdata->vif_list_index,
		  rdata->func_bit_map, rdata->func_to_clear);

	/* No need for an explicit memory barrier here as long as we
	 * ensure the ordering of writing to the SPQ element
	 * and updating of the SPQ producer which involves a memory
	 * read. If the memory read is removed we will have to put a
	 * full memory barrier there (inside ecore_sp_post()).
	 */

	/* this ramrod sends data directly and not through DMA mapping */
	return ecore_sp_post(pdev, RAMROD_CMD_ID_COMMON_AFEX_VIF_LISTS, 0,
			     *p_rdata, NONE_CONNECTION_TYPE);
}

static INLINE int ecore_func_send_stop(struct _lm_device_t *pdev,
				       struct ecore_func_state_params *params)
{
	return ecore_sp_post(pdev, RAMROD_CMD_ID_COMMON_FUNCTION_STOP, 0, 0,
			     NONE_CONNECTION_TYPE);
}

static INLINE int ecore_func_send_tx_stop(struct _lm_device_t *pdev,
				       struct ecore_func_state_params *params)
{
	return ecore_sp_post(pdev, RAMROD_CMD_ID_COMMON_STOP_TRAFFIC, 0, 0,
			     NONE_CONNECTION_TYPE);
}
static INLINE int ecore_func_send_tx_start(struct _lm_device_t *pdev,
				       struct ecore_func_state_params *params)
{
	struct ecore_func_sp_obj *o = params->f_obj;
	struct flow_control_configuration *rdata =
		(struct flow_control_configuration *)o->rdata;
	lm_address_t data_mapping = o->rdata_mapping;
	struct ecore_func_tx_start_params *tx_start_params =
		&params->params.tx_start;
	int i;

	mm_memset(rdata, 0, sizeof(*rdata));

	rdata->dcb_enabled = tx_start_params->dcb_enabled;
	rdata->dcb_version = tx_start_params->dcb_version;
	rdata->dont_add_pri_0_en = tx_start_params->dont_add_pri_0_en;

	for (i = 0; i < ARRAY_SIZE(rdata->traffic_type_to_priority_cos); i++)
		rdata->traffic_type_to_priority_cos[i] =
			tx_start_params->traffic_type_to_priority_cos[i];

	/* No need for an explicit memory barrier here as long as we
	 * ensure the ordering of writing to the SPQ element
	 * and updating of the SPQ producer which involves a memory
	 * read. If the memory read is removed we will have to put a
	 * full memory barrier there (inside ecore_sp_post()).
	 */
	return ecore_sp_post(pdev, RAMROD_CMD_ID_COMMON_START_TRAFFIC, 0,
			     data_mapping.as_u64, NONE_CONNECTION_TYPE);
}

static INLINE int ecore_func_send_set_timesync(struct _lm_device_t *pdev,
					struct ecore_func_state_params *params)
{
	struct ecore_func_sp_obj *o = params->f_obj;
	struct set_timesync_ramrod_data *rdata =
		(struct set_timesync_ramrod_data *)o->rdata;
	lm_address_t data_mapping = o->rdata_mapping;
	struct ecore_func_set_timesync_params *set_timesync_params =
		&params->params.set_timesync;

	mm_memset(rdata, 0, sizeof(*rdata));

	/* Fill the ramrod data with provided parameters */
	rdata->drift_adjust_cmd = set_timesync_params->drift_adjust_cmd;
	rdata->offset_cmd = set_timesync_params->offset_cmd;
	rdata->add_sub_drift_adjust_value =
		set_timesync_params->add_sub_drift_adjust_value;
	rdata->drift_adjust_value = set_timesync_params->drift_adjust_value;
	rdata->drift_adjust_period = set_timesync_params->drift_adjust_period;
	rdata->offset_delta.lo =
		mm_cpu_to_le32(U64_LO(set_timesync_params->offset_delta));
	rdata->offset_delta.hi =
		mm_cpu_to_le32(U64_HI(set_timesync_params->offset_delta));

	DP(BNX2X_MSG_SP, "Set timesync command params: drift_cmd = %d, offset_cmd = %d, add_sub_drift = %d, drift_val = %d, drift_period = %d, offset_lo = %d, offset_hi = %d\n",
	   rdata->drift_adjust_cmd, rdata->offset_cmd,
	   rdata->add_sub_drift_adjust_value, rdata->drift_adjust_value,
	   rdata->drift_adjust_period, rdata->offset_delta.lo,
	   rdata->offset_delta.hi);

	return ecore_sp_post(pdev, RAMROD_CMD_ID_COMMON_SET_TIMESYNC, 0,
			     data_mapping.as_u64, NONE_CONNECTION_TYPE);
}

static int ecore_func_send_cmd(struct _lm_device_t *pdev,
			       struct ecore_func_state_params *params)
{
	switch (params->cmd) {
	case ECORE_F_CMD_HW_INIT:
		return ecore_func_hw_init(pdev, params);
	case ECORE_F_CMD_START:
		return ecore_func_send_start(pdev, params);
	case ECORE_F_CMD_STOP:
		return ecore_func_send_stop(pdev, params);
	case ECORE_F_CMD_HW_RESET:
		return ecore_func_hw_reset(pdev, params);
	case ECORE_F_CMD_AFEX_UPDATE:
		return ecore_func_send_afex_update(pdev, params);
	case ECORE_F_CMD_AFEX_VIFLISTS:
		return ecore_func_send_afex_viflists(pdev, params);
	case ECORE_F_CMD_TX_STOP:
		return ecore_func_send_tx_stop(pdev, params);
	case ECORE_F_CMD_TX_START:
		return ecore_func_send_tx_start(pdev, params);
	case ECORE_F_CMD_SWITCH_UPDATE:
		return ecore_func_send_switch_update(pdev, params);
	case ECORE_F_CMD_SET_TIMESYNC:
		return ecore_func_send_set_timesync(pdev, params);
	default:
		ECORE_ERR("Unknown command: %d\n", params->cmd);
		return ECORE_INVAL;
	}
}

void ecore_init_func_obj(struct _lm_device_t *pdev,
			 struct ecore_func_sp_obj *obj,
			 void *rdata, lm_address_t rdata_mapping,
			 void *afex_rdata, lm_address_t afex_rdata_mapping,
			 struct ecore_func_sp_drv_ops *drv_iface)
{
	mm_memset(obj, 0, sizeof(*obj));

	ECORE_MUTEX_INIT(&obj->one_pending_mutex);

	obj->rdata = rdata;
	obj->rdata_mapping = rdata_mapping;
	obj->afex_rdata = afex_rdata;
	obj->afex_rdata_mapping = afex_rdata_mapping;
	obj->send_cmd = ecore_func_send_cmd;
	obj->check_transition = ecore_func_chk_transition;
	obj->complete_cmd = ecore_func_comp_cmd;
	obj->wait_comp = ecore_func_wait_comp;
	obj->drv = drv_iface;
}

/**
 * ecore_func_state_change - perform Function state change transition
 *
 * @pdev:	device handle
 * @params:	parameters to perform the transaction
 *
 * returns 0 in case of successfully completed transition,
 *         negative error code in case of failure, positive
 *         (EBUSY) value if there is a completion to that is
 *         still pending (possible only if RAMROD_COMP_WAIT is
 *         not set in params->ramrod_flags for asynchronous
 *         commands).
 */
int ecore_func_state_change(struct _lm_device_t *pdev,
			    struct ecore_func_state_params *params)
{
	struct ecore_func_sp_obj *o = params->f_obj;
	int rc, cnt = 300;
	enum ecore_func_cmd cmd = params->cmd;
	unsigned long *pending = &o->pending;

	ECORE_MUTEX_LOCK(&o->one_pending_mutex);

	/* Check that the requested transition is legal */
	rc = o->check_transition(pdev, o, params);
	if ((rc == ECORE_BUSY) &&
	    (ECORE_TEST_BIT(RAMROD_RETRY, &params->ramrod_flags))) {
		while ((rc == ECORE_BUSY) && (--cnt > 0)) {
			ECORE_MUTEX_UNLOCK(&o->one_pending_mutex);
			msleep(10);
			ECORE_MUTEX_LOCK(&o->one_pending_mutex);
			rc = o->check_transition(pdev, o, params);
		}
		if (rc == ECORE_BUSY) {
			ECORE_MUTEX_UNLOCK(&o->one_pending_mutex);
			ECORE_ERR("timeout waiting for previous ramrod completion\n");
			return rc;
		}
	} else if (rc) {
		ECORE_MUTEX_UNLOCK(&o->one_pending_mutex);
		return rc;
	}

	/* Set "pending" bit */
	ECORE_SET_BIT(cmd, pending);

	/* Don't send a command if only driver cleanup was requested */
	if (ECORE_TEST_BIT(RAMROD_DRV_CLR_ONLY, &params->ramrod_flags)) {
		ecore_func_state_change_comp(pdev, o, cmd);
		ECORE_MUTEX_UNLOCK(&o->one_pending_mutex);
	} else {
		/* Send a ramrod */
		rc = o->send_cmd(pdev, params);

		ECORE_MUTEX_UNLOCK(&o->one_pending_mutex);

		if (rc) {
			o->next_state = ECORE_F_STATE_MAX;
			ECORE_CLEAR_BIT(cmd, pending);
			smp_mb__after_atomic();
			return rc;
		}

		if (ECORE_TEST_BIT(RAMROD_COMP_WAIT, &params->ramrod_flags)) {
			rc = o->wait_comp(pdev, o, cmd);
			if (rc)
				return rc;

			return ECORE_SUCCESS;
		}
	}

	return ECORE_RET_PENDING(cmd, pending);
}
#endif
