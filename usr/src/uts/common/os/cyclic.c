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

/*
 * Copyright (c) 2012, Joyent Inc. All rights reserved.
 */

/*
 *  The Cyclic Subsystem
 *  --------------------
 *
 *  Prehistory
 *
 *  Historically, most computer architectures have specified interval-based
 *  timer parts (e.g. SPARCstation's counter/timer; Intel's i8254).  While
 *  these parts deal in relative (i.e. not absolute) time values, they are
 *  typically used by the operating system to implement the abstraction of
 *  absolute time.  As a result, these parts cannot typically be reprogrammed
 *  without introducing error in the system's notion of time.
 *
 *  Starting in about 1994, chip architectures began specifying high resolution
 *  timestamp registers.  As of this writing (1999), all major chip families
 *  (UltraSPARC, PentiumPro, MIPS, PowerPC, Alpha) have high resolution
 *  timestamp registers, and two (UltraSPARC and MIPS) have added the capacity
 *  to interrupt based on timestamp values.  These timestamp-compare registers
 *  present a time-based interrupt source which can be reprogrammed arbitrarily
 *  often without introducing error.  Given the low cost of implementing such a
 *  timestamp-compare register (and the tangible benefit of eliminating
 *  discrete timer parts), it is reasonable to expect that future chip
 *  architectures will adopt this feature.
 *
 *  The cyclic subsystem has been designed to take advantage of chip
 *  architectures with the capacity to interrupt based on absolute, high
 *  resolution values of time.
 *
 *  Subsystem Overview
 *
 *  The cyclic subsystem is a low-level kernel subsystem designed to provide
 *  arbitrarily high resolution, per-CPU interval timers (to avoid colliding
 *  with existing terms, we dub such an interval timer a "cyclic").  Cyclics
 *  can be specified to fire at high, lock or low interrupt level, and may be
 *  optionally bound to a CPU or a CPU partition.  A cyclic's CPU or CPU
 *  partition binding may be changed dynamically; the cyclic will be "juggled"
 *  to a CPU which satisfies the new binding.  Alternatively, a cyclic may
 *  be specified to be "omnipresent", denoting firing on all online CPUs.
 *
 *  Cyclic Subsystem Interface Overview
 *  -----------------------------------
 *
 *  The cyclic subsystem has interfaces with the kernel at-large, with other
 *  kernel subsystems (e.g. the processor management subsystem, the checkpoint
 *  resume subsystem) and with the platform (the cyclic backend).  Each
 *  of these interfaces is given a brief synopsis here, and is described
 *  in full above the interface's implementation.
 *
 *  The following diagram displays the cyclic subsystem's interfaces to
 *  other kernel components.  The arrows denote a "calls" relationship, with
 *  the large arrow indicating the cyclic subsystem's consumer interface.
 *  Each arrow is labeled with the section in which the corresponding
 *  interface is described.
 *
 *           Kernel at-large consumers
 *           -----------++------------
 *                      ||
 *                      ||
 *                     _||_
 *                     \  /
 *                      \/
 *            +---------------------+
 *            |                     |
 *            |  Cyclic subsystem   |<-----------  Other kernel subsystems
 *            |                     |
 *            +---------------------+
 *                   ^       |
 *                   |       |
 *                   |       |
 *                   |       v
 *            +---------------------+
 *            |                     |
 *            |   Cyclic backend    |
 *            | (platform specific) |
 *            |                     |
 *            +---------------------+
 *
 *
 *  Kernel At-Large Interfaces
 *
 *      cyclic_add()         <-- Creates a cyclic
 *      cyclic_add_omni()    <-- Creates an omnipresent cyclic
 *      cyclic_remove()      <-- Removes a cyclic
 *      cyclic_bind()        <-- Change a cyclic's CPU or partition binding
 *      cyclic_reprogram()   <-- Reprogram a cyclic's expiration
 *
 *  Inter-subsystem Interfaces
 *
 *      cyclic_juggle()      <-- Juggles cyclics away from a CPU
 *      cyclic_offline()     <-- Offlines cyclic operation on a CPU
 *      cyclic_online()      <-- Reenables operation on an offlined CPU
 *      cyclic_move_in()     <-- Notifies subsystem of change in CPU partition
 *      cyclic_move_out()    <-- Notifies subsystem of change in CPU partition
 *      cyclic_suspend()     <-- Suspends the cyclic subsystem on all CPUs
 *      cyclic_resume()      <-- Resumes the cyclic subsystem on all CPUs
 *
 *  Backend Interfaces
 *
 *      cyclic_init()        <-- Initializes the cyclic subsystem
 *      cyclic_fire()        <-- CY_HIGH_LEVEL interrupt entry point
 *      cyclic_softint()     <-- CY_LOCK/LOW_LEVEL soft interrupt entry point
 *
 *  The backend-supplied interfaces (through the cyc_backend structure) are
 *  documented in detail in <sys/cyclic_impl.h>
 *
 *
 *  Cyclic Subsystem Implementation Overview
 *  ----------------------------------------
 *
 *  The cyclic subsystem is designed to minimize interference between cyclics
 *  on different CPUs.  Thus, all of the cyclic subsystem's data structures
 *  hang off of a per-CPU structure, cyc_cpu.
 *
 *  Each cyc_cpu has a power-of-two sized array of cyclic structures (the
 *  cyp_cyclics member of the cyc_cpu structure).  If cyclic_add() is called
 *  and there does not exist a free slot in the cyp_cyclics array, the size of
 *  the array will be doubled.  The array will never shrink.  Cyclics are
 *  referred to by their index in the cyp_cyclics array, which is of type
 *  cyc_index_t.
 *
 *  The cyclics are kept sorted by expiration time in the cyc_cpu's heap.  The
 *  heap is keyed by cyclic expiration time, with parents expiring earlier
 *  than their children.
 *
 *  Heap Management
 *
 *  The heap is managed primarily by cyclic_fire().  Upon entry, cyclic_fire()
 *  compares the root cyclic's expiration time to the current time.  If the
 *  expiration time is in the past, cyclic_expire() is called on the root
 *  cyclic.  Upon return from cyclic_expire(), the cyclic's new expiration time
 *  is derived by adding its interval to its old expiration time, and a
 *  downheap operation is performed.  After the downheap, cyclic_fire()
 *  examines the (potentially changed) root cyclic, repeating the
 *  cyclic_expire()/add interval/cyclic_downheap() sequence until the root
 *  cyclic has an expiration time in the future.  This expiration time
 *  (guaranteed to be the earliest in the heap) is then communicated to the
 *  backend via cyb_reprogram.  Optimal backends will next call cyclic_fire()
 *  shortly after the root cyclic's expiration time.
 *
 *  To allow efficient, deterministic downheap operations, we implement the
 *  heap as an array (the cyp_heap member of the cyc_cpu structure), with each
 *  element containing an index into the CPU's cyp_cyclics array.
 *
 *  The heap is laid out in the array according to the following:
 *
 *   1.  The root of the heap is always in the 0th element of the heap array
 *   2.  The left and right children of the nth element are element
 *       (((n + 1) << 1) - 1) and element ((n + 1) << 1), respectively.
 *
 *  This layout is standard (see, e.g., Cormen's "Algorithms"); the proof
 *  that these constraints correctly lay out a heap (or indeed, any binary
 *  tree) is trivial and left to the reader.
 *
 *  To see the heap by example, assume our cyclics array has the following
 *  members (at time t):
 *
 *            cy_handler            cy_level      cy_expire
 *            ---------------------------------------------
 *     [ 0]   clock()                   LOCK     t+10000000
 *     [ 1]   deadman()                 HIGH   t+1000000000
 *     [ 2]   clock_highres_fire()       LOW          t+100
 *     [ 3]   clock_highres_fire()       LOW         t+1000
 *     [ 4]   clock_highres_fire()       LOW          t+500
 *     [ 5]   (free)                      --             --
 *     [ 6]   (free)                      --             --
 *     [ 7]   (free)                      --             --
 *
 *  The heap array could be:
 *
 *                [0]   [1]   [2]   [3]   [4]   [5]   [6]   [7]
 *              +-----+-----+-----+-----+-----+-----+-----+-----+
 *              |     |     |     |     |     |     |     |     |
 *              |  2  |  3  |  4  |  0  |  1  |  x  |  x  |  x  |
 *              |     |     |     |     |     |     |     |     |
 *              +-----+-----+-----+-----+-----+-----+-----+-----+
 *
 *  Graphically, this array corresponds to the following (excuse the ASCII art):
 *
 *                                       2
 *                                       |
 *                    +------------------+------------------+
 *                    3                                     4
 *                    |
 *          +---------+--------+
 *          0                  1
 *
 *  Note that the heap is laid out by layer:  all nodes at a given depth are
 *  stored in consecutive elements of the array.  Moreover, layers of
 *  consecutive depths are in adjacent element ranges.  This property
 *  guarantees high locality of reference during downheap operations.
 *  Specifically, we are guaranteed that we can downheap to a depth of
 *
 *      lg (cache_line_size / sizeof (cyc_index_t))
 *
 *  nodes with at most one cache miss.  On UltraSPARC (64 byte e-cache line
 *  size), this corresponds to a depth of four nodes.  Thus, if there are
 *  fewer than sixteen cyclics in the heap, downheaps on UltraSPARC miss at
 *  most once in the e-cache.
 *
 *  Downheaps are required to compare siblings as they proceed down the
 *  heap.  For downheaps proceeding beyond the one-cache-miss depth, every
 *  access to a left child could potentially miss in the cache.  However,
 *  if we assume
 *
 *      (cache_line_size / sizeof (cyc_index_t)) > 2,
 *
 *  then all siblings are guaranteed to be on the same cache line.  Thus, the
 *  miss on the left child will guarantee a hit on the right child; downheaps
 *  will incur at most one cache miss per layer beyond the one-cache-miss
 *  depth.  The total number of cache misses for heap management during a
 *  downheap operation is thus bounded by
 *
 *      lg (n) - lg (cache_line_size / sizeof (cyc_index_t))
 *
 *  Traditional pointer-based heaps are implemented without regard to
 *  locality.  Downheaps can thus incur two cache misses per layer (one for
 *  each child), but at most one cache miss at the root.  This yields a bound
 *  of
 *
 *      2 * lg (n) - 1
 *
 *  on the total cache misses.
 *
 *  This difference may seem theoretically trivial (the difference is, after
 *  all, constant), but can become substantial in practice -- especially for
 *  caches with very large cache lines and high miss penalties (e.g. TLBs).
 *
 *  Heaps must always be full, balanced trees.  Heap management must therefore
 *  track the next point-of-insertion into the heap.  In pointer-based heaps,
 *  recomputing this point takes O(lg (n)).  Given the layout of the
 *  array-based implementation, however, the next point-of-insertion is
 *  always:
 *
 *      heap[number_of_elements]
 *
 *  We exploit this property by implementing the free-list in the usused
 *  heap elements.  Heap insertion, therefore, consists only of filling in
 *  the cyclic at cyp_cyclics[cyp_heap[number_of_elements]], incrementing
 *  the number of elements, and performing an upheap.  Heap deletion consists
 *  of decrementing the number of elements, swapping the to-be-deleted element
 *  with the element at cyp_heap[number_of_elements], and downheaping.
 *
 *  Filling in more details in our earlier example:
 *
 *                                               +--- free list head
 *                                               |
 *                                               V
 *
 *                [0]   [1]   [2]   [3]   [4]   [5]   [6]   [7]
 *              +-----+-----+-----+-----+-----+-----+-----+-----+
 *              |     |     |     |     |     |     |     |     |
 *              |  2  |  3  |  4  |  0  |  1  |  5  |  6  |  7  |
 *              |     |     |     |     |     |     |     |     |
 *              +-----+-----+-----+-----+-----+-----+-----+-----+
 *
 *  To insert into this heap, we would just need to fill in the cyclic at
 *  cyp_cyclics[5], bump the number of elements (from 5 to 6) and perform
 *  an upheap.
 *
 *  If we wanted to remove, say, cyp_cyclics[3], we would first scan for it
 *  in the cyp_heap, and discover it at cyp_heap[1].  We would then decrement
 *  the number of elements (from 5 to 4), swap cyp_heap[1] with cyp_heap[4],
 *  and perform a downheap from cyp_heap[1].  The linear scan is required
 *  because the cyclic does not keep a backpointer into the heap.  This makes
 *  heap manipulation (e.g. downheaps) faster at the expense of removal
 *  operations.
 *
 *  Expiry processing
 *
 *  As alluded to above, cyclic_expire() is called by cyclic_fire() at
 *  CY_HIGH_LEVEL to expire a cyclic.  Cyclic subsystem consumers are
 *  guaranteed that for an arbitrary time t in the future, their cyclic
 *  handler will have been called (t - cyt_when) / cyt_interval times.  Thus,
 *  there must be a one-to-one mapping between a cyclic's expiration at
 *  CY_HIGH_LEVEL and its execution at the desired level (either CY_HIGH_LEVEL,
 *  CY_LOCK_LEVEL or CY_LOW_LEVEL).
 *
 *  For CY_HIGH_LEVEL cyclics, this is trivial; cyclic_expire() simply needs
 *  to call the handler.
 *
 *  For CY_LOCK_LEVEL and CY_LOW_LEVEL cyclics, however, there exists a
 *  potential disconnect:  if the CPU is at an interrupt level less than
 *  CY_HIGH_LEVEL but greater than the level of a cyclic for a period of
 *  time longer than twice the cyclic's interval, the cyclic will be expired
 *  twice before it can be handled.
 *
 *  To maintain the one-to-one mapping, we track the difference between the
 *  number of times a cyclic has been expired and the number of times it's
 *  been handled in a "pending count" (the cy_pend field of the cyclic
 *  structure).  cyclic_expire() thus increments the cy_pend count for the
 *  expired cyclic and posts a soft interrupt at the desired level.  In the
 *  cyclic subsystem's soft interrupt handler, cyclic_softint(), we repeatedly
 *  call the cyclic handler and decrement cy_pend until we have decremented
 *  cy_pend to zero.
 *
 *  The Producer/Consumer Buffer
 *
 *  If we wish to avoid a linear scan of the cyclics array at soft interrupt
 *  level, cyclic_softint() must be able to quickly determine which cyclics
 *  have a non-zero cy_pend count.  We thus introduce a per-soft interrupt
 *  level producer/consumer buffer shared with CY_HIGH_LEVEL.  These buffers
 *  are encapsulated in the cyc_pcbuffer structure, and, like cyp_heap, are
 *  implemented as cyc_index_t arrays (the cypc_buf member of the cyc_pcbuffer
 *  structure).
 *
 *  The producer (cyclic_expire() running at CY_HIGH_LEVEL) enqueues a cyclic
 *  by storing the cyclic's index to cypc_buf[cypc_prodndx] and incrementing
 *  cypc_prodndx.  The consumer (cyclic_softint() running at either
 *  CY_LOCK_LEVEL or CY_LOW_LEVEL) dequeues a cyclic by loading from
 *  cypc_buf[cypc_consndx] and bumping cypc_consndx.  The buffer is empty when
 *  cypc_prodndx == cypc_consndx.
 *
 *  To bound the size of the producer/consumer buffer, cyclic_expire() only
 *  enqueues a cyclic if its cy_pend was zero (if the cyclic's cy_pend is
 *  non-zero, cyclic_expire() only bumps cy_pend).  Symmetrically,
 *  cyclic_softint() only consumes a cyclic after it has decremented the
 *  cy_pend count to zero.
 *
 *  Returning to our example, here is what the CY_LOW_LEVEL producer/consumer
 *  buffer might look like:
 *
 *     cypc_consndx ---+                 +--- cypc_prodndx
 *                     |                 |
 *                     V                 V
 *
 *        [0]   [1]   [2]   [3]   [4]   [5]   [6]   [7]
 *      +-----+-----+-----+-----+-----+-----+-----+-----+
 *      |     |     |     |     |     |     |     |     |
 *      |  x  |  x  |  3  |  2  |  4  |  x  |  x  |  x  |   <== cypc_buf
 *      |     |     |  .  |  .  |  .  |     |     |     |
 *      +-----+-----+- | -+- | -+- | -+-----+-----+-----+
 *                     |     |     |
 *                     |     |     |              cy_pend  cy_handler
 *                     |     |     |          -------------------------
 *                     |     |     |          [ 0]      1  clock()
 *                     |     |     |          [ 1]      0  deadman()
 *                     |     +---- | -------> [ 2]      3  clock_highres_fire()
 *                     +---------- | -------> [ 3]      1  clock_highres_fire()
 *                                 +--------> [ 4]      1  clock_highres_fire()
 *                                            [ 5]      -  (free)
 *                                            [ 6]      -  (free)
 *                                            [ 7]      -  (free)
 *
 *  In particular, note that clock()'s cy_pend is 1 but that it is _not_ in
 *  this producer/consumer buffer; it would be enqueued in the CY_LOCK_LEVEL
 *  producer/consumer buffer.
 *
 *  Locking
 *
 *  Traditionally, access to per-CPU data structures shared between
 *  interrupt levels is serialized by manipulating programmable interrupt
 *  level:  readers and writers are required to raise their interrupt level
 *  to that of the highest level writer.
 *
 *  For the producer/consumer buffers (shared between cyclic_fire()/
 *  cyclic_expire() executing at CY_HIGH_LEVEL and cyclic_softint() executing
 *  at one of CY_LOCK_LEVEL or CY_LOW_LEVEL), forcing cyclic_softint() to raise
 *  programmable interrupt level is undesirable:  aside from the additional
 *  latency incurred by manipulating interrupt level in the hot cy_pend
 *  processing path, this would create the potential for soft level cy_pend
 *  processing to delay CY_HIGH_LEVEL firing and expiry processing.
 *  CY_LOCK/LOW_LEVEL cyclics could thereby induce jitter in CY_HIGH_LEVEL
 *  cyclics.
 *
 *  To minimize jitter, then, we would like the cyclic_fire()/cyclic_expire()
 *  and cyclic_softint() code paths to be lock-free.
 *
 *  For cyclic_fire()/cyclic_expire(), lock-free execution is straightforward:
 *  because these routines execute at a higher interrupt level than
 *  cyclic_softint(), their actions on the producer/consumer buffer appear
 *  atomic.  In particular, the increment of cy_pend appears to occur
 *  atomically with the increment of cypc_prodndx.
 *
 *  For cyclic_softint(), however, lock-free execution requires more delicacy.
 *  When cyclic_softint() discovers a cyclic in the producer/consumer buffer,
 *  it calls the cyclic's handler and attempts to atomically decrement the
 *  cy_pend count with a compare&swap operation.
 *
 *  If the compare&swap operation succeeds, cyclic_softint() behaves
 *  conditionally based on the value it atomically wrote to cy_pend:
 *
 *     - If the cy_pend was decremented to 0, the cyclic has been consumed;
 *       cyclic_softint() increments the cypc_consndx and checks for more
 *       enqueued work.
 *
 *     - If the count was decremented to a non-zero value, there is more work
 *       to be done on the cyclic; cyclic_softint() calls the cyclic handler
 *       and repeats the atomic decrement process.
 *
 *  If the compare&swap operation fails, cyclic_softint() knows that
 *  cyclic_expire() has intervened and bumped the cy_pend count (resizes
 *  and removals complicate this, however -- see the sections on their
 *  operation, below).  cyclic_softint() thus reloads cy_pend, and re-attempts
 *  the atomic decrement.
 *
 *  Recall that we bound the size of the producer/consumer buffer by
 *  having cyclic_expire() only enqueue the specified cyclic if its
 *  cy_pend count is zero; this assures that each cyclic is enqueued at
 *  most once.  This leads to a critical constraint on cyclic_softint(),
 *  however:  after the compare&swap operation which successfully decrements
 *  cy_pend to zero, cyclic_softint() must _not_ re-examine the consumed
 *  cyclic.  In part to obey this constraint, cyclic_softint() calls the
 *  cyclic handler before decrementing cy_pend.
 *
 *  Resizing
 *
 *  All of the discussion thus far has assumed a static number of cyclics.
 *  Obviously, static limitations are not practical; we need the capacity
 *  to resize our data structures dynamically.
 *
 *  We resize our data structures lazily, and only on a per-CPU basis.
 *  The size of the data structures always doubles and never shrinks.  We
 *  serialize adds (and thus resizes) on cpu_lock; we never need to deal
 *  with concurrent resizes.  Resizes should be rare; they may induce jitter
 *  on the CPU being resized, but should not affect cyclic operation on other
 *  CPUs.  Pending cyclics may not be dropped during a resize operation.
 *
 *  Three key cyc_cpu data structures need to be resized:  the cyclics array,
 *  the heap array and the producer/consumer buffers.  Resizing the first two
 *  is relatively straightforward:
 *
 *    1.  The new, larger arrays are allocated in cyclic_expand() (called
 *        from cyclic_add()).
 *    2.  cyclic_expand() cross calls cyclic_expand_xcall() on the CPU
 *        undergoing the resize.
 *    3.  cyclic_expand_xcall() raises interrupt level to CY_HIGH_LEVEL
 *    4.  The contents of the old arrays are copied into the new arrays.
 *    5.  The old cyclics array is bzero()'d
 *    6.  The pointers are updated.
 *
 *  The producer/consumer buffer is dicier:  cyclic_expand_xcall() may have
 *  interrupted cyclic_softint() in the middle of consumption. To resize the
 *  producer/consumer buffer, we implement up to two buffers per soft interrupt
 *  level:  a hard buffer (the buffer being produced into by cyclic_expire())
 *  and a soft buffer (the buffer from which cyclic_softint() is consuming).
 *  During normal operation, the hard buffer and soft buffer point to the
 *  same underlying producer/consumer buffer.
 *
 *  During a resize, however, cyclic_expand_xcall() changes the hard buffer
 *  to point to the new, larger producer/consumer buffer; all future
 *  cyclic_expire()'s will produce into the new buffer.  cyclic_expand_xcall()
 *  then posts a CY_LOCK_LEVEL soft interrupt, landing in cyclic_softint().
 *
 *  As under normal operation, cyclic_softint() will consume cyclics from
 *  its soft buffer.  After the soft buffer is drained, however,
 *  cyclic_softint() will see that the hard buffer has changed.  At that time,
 *  cyclic_softint() will change its soft buffer to point to the hard buffer,
 *  and repeat the producer/consumer buffer draining procedure.
 *
 *  After the new buffer is drained, cyclic_softint() will determine if both
 *  soft levels have seen their new producer/consumer buffer.  If both have,
 *  cyclic_softint() will post on the semaphore cyp_modify_wait.  If not, a
 *  soft interrupt will be generated for the remaining level.
 *
 *  cyclic_expand() blocks on the cyp_modify_wait semaphore (a semaphore is
 *  used instead of a condition variable because of the race between the
 *  sema_p() in cyclic_expand() and the sema_v() in cyclic_softint()).  This
 *  allows cyclic_expand() to know when the resize operation is complete;
 *  all of the old buffers (the heap, the cyclics array and the producer/
 *  consumer buffers) can be freed.
 *
 *  A final caveat on resizing:  we described step (5) in the
 *  cyclic_expand_xcall() procedure without providing any motivation.  This
 *  step addresses the problem of a cyclic_softint() attempting to decrement
 *  a cy_pend count while interrupted by a cyclic_expand_xcall().  Because
 *  cyclic_softint() has already called the handler by the time cy_pend is
 *  decremented, we want to assure that it doesn't decrement a cy_pend
 *  count in the old cyclics array.  By zeroing the old cyclics array in
 *  cyclic_expand_xcall(), we are zeroing out every cy_pend count; when
 *  cyclic_softint() attempts to compare&swap on the cy_pend count, it will
 *  fail and recognize that the count has been zeroed.  cyclic_softint() will
 *  update its stale copy of the cyp_cyclics pointer, re-read the cy_pend
 *  count from the new cyclics array, and re-attempt the compare&swap.
 *
 *  Removals
 *
 *  Cyclic removals should be rare.  To simplify the implementation (and to
 *  allow optimization for the cyclic_fire()/cyclic_expire()/cyclic_softint()
 *  path), we force removals and adds to serialize on cpu_lock.
 *
 *  Cyclic removal is complicated by a guarantee made to the consumer of
 *  the cyclic subsystem:  after cyclic_remove() returns, the cyclic handler
 *  has returned and will never again be called.
 *
 *  Here is the procedure for cyclic removal:
 *
 *    1.  cyclic_remove() calls cyclic_remove_xcall() on the CPU undergoing
 *        the removal.
 *    2.  cyclic_remove_xcall() raises interrupt level to CY_HIGH_LEVEL
 *    3.  The current expiration time for the removed cyclic is recorded.
 *    4.  If the cy_pend count on the removed cyclic is non-zero, it
 *        is copied into cyp_rpend and subsequently zeroed.
 *    5.  The cyclic is removed from the heap
 *    6.  If the root of the heap has changed, the backend is reprogrammed.
 *    7.  If the cy_pend count was non-zero cyclic_remove() blocks on the
 *        cyp_modify_wait semaphore.
 *
 *  The motivation for step (3) is explained in "Juggling", below.
 *
 *  The cy_pend count is decremented in cyclic_softint() after the cyclic
 *  handler returns.  Thus, if we find a cy_pend count of zero in step
 *  (4), we know that cyclic_remove() doesn't need to block.
 *
 *  If the cy_pend count is non-zero, however, we must block in cyclic_remove()
 *  until cyclic_softint() has finished calling the cyclic handler.  To let
 *  cyclic_softint() know that this cyclic has been removed, we zero the
 *  cy_pend count.  This will cause cyclic_softint()'s compare&swap to fail.
 *  When cyclic_softint() sees the zero cy_pend count, it knows that it's been
 *  caught during a resize (see "Resizing", above) or that the cyclic has been
 *  removed.  In the latter case, it calls cyclic_remove_pend() to call the
 *  cyclic handler cyp_rpend - 1 times, and posts on cyp_modify_wait.
 *
 *  Juggling
 *
 *  At first glance, cyclic juggling seems to be a difficult problem.  The
 *  subsystem must guarantee that a cyclic doesn't execute simultaneously on
 *  different CPUs, while also assuring that a cyclic fires exactly once
 *  per interval.  We solve this problem by leveraging a property of the
 *  platform:  gethrtime() is required to increase in lock-step across
 *  multiple CPUs.  Therefore, to juggle a cyclic, we remove it from its
 *  CPU, recording its expiration time in the remove cross call (step (3)
 *  in "Removing", above).  We then add the cyclic to the new CPU, explicitly
 *  setting its expiration time to the time recorded in the removal.  This
 *  leverages the existing cyclic expiry processing, which will compensate
 *  for any time lost while juggling.
 *
 *  Reprogramming
 *
 *  Normally, after a cyclic fires, its next expiration is computed from
 *  the current time and the cyclic interval. But there are situations when
 *  the next expiration needs to be reprogrammed by the kernel subsystem that
 *  is using the cyclic. cyclic_reprogram() allows this to be done. This,
 *  unlike the other kernel at-large cyclic API functions, is permitted to
 *  be called from the cyclic handler. This is because it does not use the
 *  cpu_lock to serialize access.
 *
 *  When cyclic_reprogram() is called for an omni-cyclic, the operation is
 *  applied to the omni-cyclic's component on the current CPU.
 *
 *  If a high-level cyclic handler reprograms its own cyclic, then
 *  cyclic_fire() detects that and does not recompute the cyclic's next
 *  expiration. However, for a lock-level or a low-level cyclic, the
 *  actual cyclic handler will execute at the lower PIL only after
 *  cyclic_fire() is done with all expired cyclics. To deal with this, such
 *  cyclics can be specified with a special interval of CY_INFINITY (INT64_MAX).
 *  cyclic_fire() recognizes this special value and recomputes the next
 *  expiration to CY_INFINITY. This effectively moves the cyclic to the
 *  bottom of the heap and prevents it from going off until its handler has
 *  had a chance to reprogram it. Infact, this is the way to create and reuse
 *  "one-shot" timers in the context of the cyclic subsystem without using
 *  cyclic_remove().
 *
 *  Here is the procedure for cyclic reprogramming:
 *
 *    1.  cyclic_reprogram() calls cyclic_reprogram_xcall() on the CPU
 *        that houses the cyclic.
 *    2.  cyclic_reprogram_xcall() raises interrupt level to CY_HIGH_LEVEL
 *    3.  The cyclic is located in the cyclic heap. The search for this is
 *        done from the bottom of the heap to the top as reprogrammable cyclics
 *        would be located closer to the bottom than the top.
 *    4.  The cyclic expiration is set and the cyclic is moved to its
 *        correct position in the heap (up or down depending on whether the
 *        new expiration is less than or greater than the old one).
 *    5.  If the cyclic move modified the root of the heap, the backend is
 *	  reprogrammed.
 *
 *  Reprogramming can be a frequent event (see the callout subsystem). So,
 *  the serialization used has to be efficient. As with all other cyclic
 *  operations, the interrupt level is raised during reprogramming. Plus,
 *  during reprogramming, the cyclic must not be juggled (regular cyclic)
 *  or stopped (omni-cyclic). The implementation defines a per-cyclic
 *  reader-writer lock to accomplish this. This lock is acquired in the
 *  reader mode by cyclic_reprogram() and writer mode by cyclic_juggle() and
 *  cyclic_omni_stop(). The reader-writer lock makes it efficient if
 *  an omni-cyclic is reprogrammed on different CPUs frequently.
 *
 *  Note that since the cpu_lock is not used during reprogramming, it is
 *  the responsibility of the user of the reprogrammable cyclic to make sure
 *  that the cyclic is not removed via cyclic_remove() during reprogramming.
 *  This is not an unreasonable requirement as the user will typically have
 *  some sort of synchronization for its cyclic-related activities. This
 *  little caveat exists because the cyclic ID is not really an ID. It is
 *  implemented as a pointer to a structure.
 */
#include <sys/cyclic_impl.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sdt.h>

#ifdef CYCLIC_TRACE

/*
 * cyc_trace_enabled is for the benefit of kernel debuggers.
 */
int cyc_trace_enabled = 1;
static cyc_tracebuf_t cyc_ptrace;
static cyc_coverage_t cyc_coverage[CY_NCOVERAGE];

/*
 * Seen this anywhere?
 */
static uint_t
cyclic_coverage_hash(char *p)
{
	unsigned int g;
	uint_t hval;

	hval = 0;
	while (*p) {
		hval = (hval << 4) + *p++;
		if ((g = (hval & 0xf0000000)) != 0)
			hval ^= g >> 24;
		hval &= ~g;
	}
	return (hval);
}

static void
cyclic_coverage(char *why, int level, uint64_t arg0, uint64_t arg1)
{
	uint_t ndx, orig;

	for (ndx = orig = cyclic_coverage_hash(why) % CY_NCOVERAGE; ; ) {
		if (cyc_coverage[ndx].cyv_why == why)
			break;

		if (cyc_coverage[ndx].cyv_why != NULL ||
		    casptr(&cyc_coverage[ndx].cyv_why, NULL, why) != NULL) {

			if (++ndx == CY_NCOVERAGE)
				ndx = 0;

			if (ndx == orig)
				panic("too many cyclic coverage points");
			continue;
		}

		/*
		 * If we're here, we have successfully swung our guy into
		 * the position at "ndx".
		 */
		break;
	}

	if (level == CY_PASSIVE_LEVEL)
		cyc_coverage[ndx].cyv_passive_count++;
	else
		cyc_coverage[ndx].cyv_count[level]++;

	cyc_coverage[ndx].cyv_arg0 = arg0;
	cyc_coverage[ndx].cyv_arg1 = arg1;
}

#define	CYC_TRACE(cpu, level, why, arg0, arg1) \
	CYC_TRACE_IMPL(&cpu->cyp_trace[level], level, why, arg0, arg1)

#define	CYC_PTRACE(why, arg0, arg1) \
	CYC_TRACE_IMPL(&cyc_ptrace, CY_PASSIVE_LEVEL, why, arg0, arg1)

#define	CYC_TRACE_IMPL(buf, level, why, a0, a1) { \
	if (panicstr == NULL) { \
		int _ndx = (buf)->cyt_ndx; \
		cyc_tracerec_t *_rec = &(buf)->cyt_buf[_ndx]; \
		(buf)->cyt_ndx = (++_ndx == CY_NTRACEREC) ? 0 : _ndx; \
		_rec->cyt_tstamp = gethrtime_unscaled(); \
		_rec->cyt_why = (why); \
		_rec->cyt_arg0 = (uint64_t)(uintptr_t)(a0); \
		_rec->cyt_arg1 = (uint64_t)(uintptr_t)(a1); \
		cyclic_coverage(why, level,	\
		    (uint64_t)(uintptr_t)(a0), (uint64_t)(uintptr_t)(a1)); \
	} \
}

#else

static int cyc_trace_enabled = 0;

#define	CYC_TRACE(cpu, level, why, arg0, arg1)
#define	CYC_PTRACE(why, arg0, arg1)

#endif

#define	CYC_TRACE0(cpu, level, why) CYC_TRACE(cpu, level, why, 0, 0)
#define	CYC_TRACE1(cpu, level, why, arg0) CYC_TRACE(cpu, level, why, arg0, 0)

#define	CYC_PTRACE0(why) CYC_PTRACE(why, 0, 0)
#define	CYC_PTRACE1(why, arg0) CYC_PTRACE(why, arg0, 0)

static kmem_cache_t *cyclic_id_cache;
static cyc_id_t *cyclic_id_head;
static hrtime_t cyclic_resolution;
static cyc_backend_t cyclic_backend;

/*
 * Returns 1 if the upheap propagated to the root, 0 if it did not.  This
 * allows the caller to reprogram the backend only when the root has been
 * modified.
 */
static int
cyclic_upheap(cyc_cpu_t *cpu, cyc_index_t ndx)
{
	cyclic_t *cyclics;
	cyc_index_t *heap;
	cyc_index_t heap_parent, heap_current = ndx;
	cyc_index_t parent, current;

	if (heap_current == 0)
		return (1);

	heap = cpu->cyp_heap;
	cyclics = cpu->cyp_cyclics;
	heap_parent = CYC_HEAP_PARENT(heap_current);

	for (;;) {
		current = heap[heap_current];
		parent = heap[heap_parent];

		/*
		 * We have an expiration time later than our parent; we're
		 * done.
		 */
		if (cyclics[current].cy_expire >= cyclics[parent].cy_expire)
			return (0);

		/*
		 * We need to swap with our parent, and continue up the heap.
		 */
		heap[heap_parent] = current;
		heap[heap_current] = parent;

		/*
		 * If we just reached the root, we're done.
		 */
		if (heap_parent == 0)
			return (1);

		heap_current = heap_parent;
		heap_parent = CYC_HEAP_PARENT(heap_current);
	}
}

static void
cyclic_downheap(cyc_cpu_t *cpu, cyc_index_t ndx)
{
	cyclic_t *cyclics = cpu->cyp_cyclics;
	cyc_index_t *heap = cpu->cyp_heap;

	cyc_index_t heap_left, heap_right, heap_me = ndx;
	cyc_index_t left, right, me;
	cyc_index_t nelems = cpu->cyp_nelems;

	for (;;) {
		/*
		 * If we don't have a left child (i.e., we're a leaf), we're
		 * done.
		 */
		if ((heap_left = CYC_HEAP_LEFT(heap_me)) >= nelems)
			return;

		left = heap[heap_left];
		me = heap[heap_me];

		heap_right = CYC_HEAP_RIGHT(heap_me);

		/*
		 * Even if we don't have a right child, we still need to compare
		 * our expiration time against that of our left child.
		 */
		if (heap_right >= nelems)
			goto comp_left;

		right = heap[heap_right];

		/*
		 * We have both a left and a right child.  We need to compare
		 * the expiration times of the children to determine which
		 * expires earlier.
		 */
		if (cyclics[right].cy_expire < cyclics[left].cy_expire) {
			/*
			 * Our right child is the earlier of our children.
			 * We'll now compare our expiration time to its; if
			 * ours is the earlier, we're done.
			 */
			if (cyclics[me].cy_expire <= cyclics[right].cy_expire)
				return;

			/*
			 * Our right child expires earlier than we do; swap
			 * with our right child, and descend right.
			 */
			heap[heap_right] = me;
			heap[heap_me] = right;
			heap_me = heap_right;
			continue;
		}

comp_left:
		/*
		 * Our left child is the earlier of our children (or we have
		 * no right child).  We'll now compare our expiration time
		 * to its; if ours is the earlier, we're done.
		 */
		if (cyclics[me].cy_expire <= cyclics[left].cy_expire)
			return;

		/*
		 * Our left child expires earlier than we do; swap with our
		 * left child, and descend left.
		 */
		heap[heap_left] = me;
		heap[heap_me] = left;
		heap_me = heap_left;
	}
}

static void
cyclic_expire(cyc_cpu_t *cpu, cyc_index_t ndx, cyclic_t *cyclic)
{
	cyc_backend_t *be = cpu->cyp_backend;
	cyc_level_t level = cyclic->cy_level;

	/*
	 * If this is a CY_HIGH_LEVEL cyclic, just call the handler; we don't
	 * need to worry about the pend count for CY_HIGH_LEVEL cyclics.
	 */
	if (level == CY_HIGH_LEVEL) {
		cyc_func_t handler = cyclic->cy_handler;
		void *arg = cyclic->cy_arg;

		CYC_TRACE(cpu, CY_HIGH_LEVEL, "handler-in", handler, arg);
		DTRACE_PROBE1(cyclic__start, cyclic_t *, cyclic);

		(*handler)(arg);

		DTRACE_PROBE1(cyclic__end, cyclic_t *, cyclic);
		CYC_TRACE(cpu, CY_HIGH_LEVEL, "handler-out", handler, arg);

		return;
	}

	/*
	 * We're at CY_HIGH_LEVEL; this modification to cy_pend need not
	 * be atomic (the high interrupt level assures that it will appear
	 * atomic to any softint currently running).
	 */
	if (cyclic->cy_pend++ == 0) {
		cyc_softbuf_t *softbuf = &cpu->cyp_softbuf[level];
		cyc_pcbuffer_t *pc = &softbuf->cys_buf[softbuf->cys_hard];

		/*
		 * We need to enqueue this cyclic in the soft buffer.
		 */
		CYC_TRACE(cpu, CY_HIGH_LEVEL, "expire-enq", cyclic,
		    pc->cypc_prodndx);
		pc->cypc_buf[pc->cypc_prodndx++ & pc->cypc_sizemask] = ndx;

		ASSERT(pc->cypc_prodndx != pc->cypc_consndx);
	} else {
		/*
		 * If the pend count is zero after we incremented it, then
		 * we've wrapped (i.e. we had a cy_pend count of over four
		 * billion.  In this case, we clamp the pend count at
		 * UINT32_MAX.  Yes, cyclics can be lost in this case.
		 */
		if (cyclic->cy_pend == 0) {
			CYC_TRACE1(cpu, CY_HIGH_LEVEL, "expire-wrap", cyclic);
			cyclic->cy_pend = UINT32_MAX;
		}

		CYC_TRACE(cpu, CY_HIGH_LEVEL, "expire-bump", cyclic, 0);
	}

	be->cyb_softint(be->cyb_arg, cyclic->cy_level);
}

/*
 *  cyclic_fire(cpu_t *)
 *
 *  Overview
 *
 *    cyclic_fire() is the cyclic subsystem's CY_HIGH_LEVEL interrupt handler.
 *    Called by the cyclic backend.
 *
 *  Arguments and notes
 *
 *    The only argument is the CPU on which the interrupt is executing;
 *    backends must call into cyclic_fire() on the specified CPU.
 *
 *    cyclic_fire() may be called spuriously without ill effect.  Optimal
 *    backends will call into cyclic_fire() at or shortly after the time
 *    requested via cyb_reprogram().  However, calling cyclic_fire()
 *    arbitrarily late will only manifest latency bubbles; the correctness
 *    of the cyclic subsystem does not rely on the timeliness of the backend.
 *
 *    cyclic_fire() is wait-free; it will not block or spin.
 *
 *  Return values
 *
 *    None.
 *
 *  Caller's context
 *
 *    cyclic_fire() must be called from CY_HIGH_LEVEL interrupt context.
 */
void
cyclic_fire(cpu_t *c)
{
	cyc_cpu_t *cpu = c->cpu_cyclic;
	cyc_backend_t *be = cpu->cyp_backend;
	cyc_index_t *heap = cpu->cyp_heap;
	cyclic_t *cyclic, *cyclics = cpu->cyp_cyclics;
	void *arg = be->cyb_arg;
	hrtime_t now = gethrtime();
	hrtime_t exp;

	CYC_TRACE(cpu, CY_HIGH_LEVEL, "fire", now, 0);

	if (cpu->cyp_nelems == 0) {
		/*
		 * This is a spurious fire.  Count it as such, and blow
		 * out of here.
		 */
		CYC_TRACE0(cpu, CY_HIGH_LEVEL, "fire-spurious");
		return;
	}

	for (;;) {
		cyc_index_t ndx = heap[0];

		cyclic = &cyclics[ndx];

		ASSERT(!(cyclic->cy_flags & CYF_FREE));

		CYC_TRACE(cpu, CY_HIGH_LEVEL, "fire-check", cyclic,
		    cyclic->cy_expire);

		if ((exp = cyclic->cy_expire) > now)
			break;

		cyclic_expire(cpu, ndx, cyclic);

		/*
		 * If the handler reprogrammed the cyclic, then don't
		 * recompute the expiration. Then, if the interval is
		 * infinity, set the expiration to infinity. This can
		 * be used to create one-shot timers.
		 */
		if (exp != cyclic->cy_expire) {
			/*
			 * If a hi level cyclic reprograms itself,
			 * the heap adjustment and reprogramming of the
			 * clock source have already been done at this
			 * point. So, we can continue.
			 */
			continue;
		}

		if (cyclic->cy_interval == CY_INFINITY)
			exp = CY_INFINITY;
		else
			exp += cyclic->cy_interval;

		/*
		 * If this cyclic will be set to next expire in the distant
		 * past, we have one of two situations:
		 *
		 *   a)	This is the first firing of a cyclic which had
		 *	cy_expire set to 0.
		 *
		 *   b)	We are tragically late for a cyclic -- most likely
		 *	due to being in the debugger.
		 *
		 * In either case, we set the new expiration time to be the
		 * the next interval boundary.  This assures that the
		 * expiration time modulo the interval is invariant.
		 *
		 * We arbitrarily define "distant" to be one second (one second
		 * is chosen because it's shorter than any foray to the
		 * debugger while still being longer than any legitimate
		 * stretch at CY_HIGH_LEVEL).
		 */

		if (now - exp > NANOSEC) {
			hrtime_t interval = cyclic->cy_interval;

			CYC_TRACE(cpu, CY_HIGH_LEVEL, exp == interval ?
			    "fire-first" : "fire-swing", now, exp);

			exp += ((now - exp) / interval + 1) * interval;
		}

		cyclic->cy_expire = exp;
		cyclic_downheap(cpu, 0);
	}

	/*
	 * Now we have a cyclic in the root slot which isn't in the past;
	 * reprogram the interrupt source.
	 */
	be->cyb_reprogram(arg, exp);
}

static void
cyclic_remove_pend(cyc_cpu_t *cpu, cyc_level_t level, cyclic_t *cyclic)
{
	cyc_func_t handler = cyclic->cy_handler;
	void *arg = cyclic->cy_arg;
	uint32_t i, rpend = cpu->cyp_rpend - 1;

	ASSERT(cyclic->cy_flags & CYF_FREE);
	ASSERT(cyclic->cy_pend == 0);
	ASSERT(cpu->cyp_state == CYS_REMOVING);
	ASSERT(cpu->cyp_rpend > 0);

	CYC_TRACE(cpu, level, "remove-rpend", cyclic, cpu->cyp_rpend);

	/*
	 * Note that we only call the handler cyp_rpend - 1 times; this is
	 * to account for the handler call in cyclic_softint().
	 */
	for (i = 0; i < rpend; i++) {
		CYC_TRACE(cpu, level, "rpend-in", handler, arg);
		DTRACE_PROBE1(cyclic__start, cyclic_t *, cyclic);

		(*handler)(arg);

		DTRACE_PROBE1(cyclic__end, cyclic_t *, cyclic);
		CYC_TRACE(cpu, level, "rpend-out", handler, arg);
	}

	/*
	 * We can now let the remove operation complete.
	 */
	sema_v(&cpu->cyp_modify_wait);
}

/*
 *  cyclic_softint(cpu_t *cpu, cyc_level_t level)
 *
 *  Overview
 *
 *    cyclic_softint() is the cyclic subsystem's CY_LOCK_LEVEL and CY_LOW_LEVEL
 *    soft interrupt handler.  Called by the cyclic backend.
 *
 *  Arguments and notes
 *
 *    The first argument to cyclic_softint() is the CPU on which the interrupt
 *    is executing; backends must call into cyclic_softint() on the specified
 *    CPU.  The second argument is the level of the soft interrupt; it must
 *    be one of CY_LOCK_LEVEL or CY_LOW_LEVEL.
 *
 *    cyclic_softint() will call the handlers for cyclics pending at the
 *    specified level.  cyclic_softint() will not return until all pending
 *    cyclics at the specified level have been dealt with; intervening
 *    CY_HIGH_LEVEL interrupts which enqueue cyclics at the specified level
 *    may therefore prolong cyclic_softint().
 *
 *    cyclic_softint() never disables interrupts, and, if neither a
 *    cyclic_add() nor a cyclic_remove() is pending on the specified CPU, is
 *    lock-free.  This assures that in the common case, cyclic_softint()
 *    completes without blocking, and never starves cyclic_fire().  If either
 *    cyclic_add() or cyclic_remove() is pending, cyclic_softint() may grab
 *    a dispatcher lock.
 *
 *    While cyclic_softint() is designed for bounded latency, it is obviously
 *    at the mercy of its cyclic handlers.  Because cyclic handlers may block
 *    arbitrarily, callers of cyclic_softint() should not rely upon
 *    deterministic completion.
 *
 *    cyclic_softint() may be called spuriously without ill effect.
 *
 *  Return value
 *
 *    None.
 *
 *  Caller's context
 *
 *    The caller must be executing in soft interrupt context at either
 *    CY_LOCK_LEVEL or CY_LOW_LEVEL.  The level passed to cyclic_softint()
 *    must match the level at which it is executing.  On optimal backends,
 *    the caller will hold no locks.  In any case, the caller may not hold
 *    cpu_lock or any lock acquired by any cyclic handler or held across
 *    any of cyclic_add(), cyclic_remove(), cyclic_bind() or cyclic_juggle().
 */
void
cyclic_softint(cpu_t *c, cyc_level_t level)
{
	cyc_cpu_t *cpu = c->cpu_cyclic;
	cyc_softbuf_t *softbuf;
	int soft, *buf, consndx, resized = 0, intr_resized = 0;
	cyc_pcbuffer_t *pc;
	cyclic_t *cyclics = cpu->cyp_cyclics;
	int sizemask;

	CYC_TRACE(cpu, level, "softint", cyclics, 0);

	ASSERT(level < CY_LOW_LEVEL + CY_SOFT_LEVELS);

	softbuf = &cpu->cyp_softbuf[level];
top:
	soft = softbuf->cys_soft;
	ASSERT(soft == 0 || soft == 1);

	pc = &softbuf->cys_buf[soft];
	buf = pc->cypc_buf;
	consndx = pc->cypc_consndx;
	sizemask = pc->cypc_sizemask;

	CYC_TRACE(cpu, level, "softint-top", cyclics, pc);

	while (consndx != pc->cypc_prodndx) {
		uint32_t pend, npend, opend;
		int consmasked = consndx & sizemask;
		cyclic_t *cyclic = &cyclics[buf[consmasked]];
		cyc_func_t handler = cyclic->cy_handler;
		void *arg = cyclic->cy_arg;

		ASSERT(buf[consmasked] < cpu->cyp_size);
		CYC_TRACE(cpu, level, "consuming", consndx, cyclic);

		/*
		 * We have found this cyclic in the pcbuffer.  We know that
		 * one of the following is true:
		 *
		 *  (a)	The pend is non-zero.  We need to execute the handler
		 *	at least once.
		 *
		 *  (b)	The pend _was_ non-zero, but it's now zero due to a
		 *	resize.  We will call the handler once, see that we
		 *	are in this case, and read the new cyclics buffer
		 *	(and hence the old non-zero pend).
		 *
		 *  (c)	The pend _was_ non-zero, but it's now zero due to a
		 *	removal.  We will call the handler once, see that we
		 *	are in this case, and call into cyclic_remove_pend()
		 *	to call the cyclic rpend times.  We will take into
		 *	account that we have already called the handler once.
		 *
		 * Point is:  it's safe to call the handler without first
		 * checking the pend.
		 */
		do {
			CYC_TRACE(cpu, level, "handler-in", handler, arg);
			DTRACE_PROBE1(cyclic__start, cyclic_t *, cyclic);

			(*handler)(arg);

			DTRACE_PROBE1(cyclic__end, cyclic_t *, cyclic);
			CYC_TRACE(cpu, level, "handler-out", handler, arg);
reread:
			pend = cyclic->cy_pend;
			npend = pend - 1;

			if (pend == 0) {
				if (cpu->cyp_state == CYS_REMOVING) {
					/*
					 * This cyclic has been removed while
					 * it had a non-zero pend count (we
					 * know it was non-zero because we
					 * found this cyclic in the pcbuffer).
					 * There must be a non-zero rpend for
					 * this CPU, and there must be a remove
					 * operation blocking; we'll call into
					 * cyclic_remove_pend() to clean this
					 * up, and break out of the pend loop.
					 */
					cyclic_remove_pend(cpu, level, cyclic);
					break;
				}

				/*
				 * We must have had a resize interrupt us.
				 */
				CYC_TRACE(cpu, level, "resize-int", cyclics, 0);
				ASSERT(cpu->cyp_state == CYS_EXPANDING);
				ASSERT(cyclics != cpu->cyp_cyclics);
				ASSERT(resized == 0);
				ASSERT(intr_resized == 0);
				intr_resized = 1;
				cyclics = cpu->cyp_cyclics;
				cyclic = &cyclics[buf[consmasked]];
				ASSERT(cyclic->cy_handler == handler);
				ASSERT(cyclic->cy_arg == arg);
				goto reread;
			}

			if ((opend =
			    cas32(&cyclic->cy_pend, pend, npend)) != pend) {
				/*
				 * Our cas32 can fail for one of several
				 * reasons:
				 *
				 *  (a)	An intervening high level bumped up the
				 *	pend count on this cyclic.  In this
				 *	case, we will see a higher pend.
				 *
				 *  (b)	The cyclics array has been yanked out
				 *	from underneath us by a resize
				 *	operation.  In this case, pend is 0 and
				 *	cyp_state is CYS_EXPANDING.
				 *
				 *  (c)	The cyclic has been removed by an
				 *	intervening remove-xcall.  In this case,
				 *	pend will be 0, the cyp_state will be
				 *	CYS_REMOVING, and the cyclic will be
				 *	marked CYF_FREE.
				 *
				 * The assertion below checks that we are
				 * in one of the above situations.  The
				 * action under all three is to return to
				 * the top of the loop.
				 */
				CYC_TRACE(cpu, level, "cas-fail", opend, pend);
				ASSERT(opend > pend || (opend == 0 &&
				    ((cyclics != cpu->cyp_cyclics &&
				    cpu->cyp_state == CYS_EXPANDING) ||
				    (cpu->cyp_state == CYS_REMOVING &&
				    (cyclic->cy_flags & CYF_FREE)))));
				goto reread;
			}

			/*
			 * Okay, so we've managed to successfully decrement
			 * pend.  If we just decremented the pend to 0, we're
			 * done.
			 */
		} while (npend > 0);

		pc->cypc_consndx = ++consndx;
	}

	/*
	 * If the high level handler is no longer writing to the same
	 * buffer, then we've had a resize.  We need to switch our soft
	 * index, and goto top.
	 */
	if (soft != softbuf->cys_hard) {
		/*
		 * We can assert that the other buffer has grown by exactly
		 * one factor of two.
		 */
		CYC_TRACE(cpu, level, "buffer-grow", 0, 0);
		ASSERT(cpu->cyp_state == CYS_EXPANDING);
		ASSERT(softbuf->cys_buf[softbuf->cys_hard].cypc_sizemask ==
		    (softbuf->cys_buf[soft].cypc_sizemask << 1) + 1 ||
		    softbuf->cys_buf[soft].cypc_sizemask == 0);
		ASSERT(softbuf->cys_hard == (softbuf->cys_soft ^ 1));

		/*
		 * If our cached cyclics pointer doesn't match cyp_cyclics,
		 * then we took a resize between our last iteration of the
		 * pend loop and the check against softbuf->cys_hard.
		 */
		if (cpu->cyp_cyclics != cyclics) {
			CYC_TRACE1(cpu, level, "resize-int-int", consndx);
			cyclics = cpu->cyp_cyclics;
		}

		softbuf->cys_soft = softbuf->cys_hard;

		ASSERT(resized == 0);
		resized = 1;
		goto top;
	}

	/*
	 * If we were interrupted by a resize operation, then we must have
	 * seen the hard index change.
	 */
	ASSERT(!(intr_resized == 1 && resized == 0));

	if (resized) {
		uint32_t lev, nlev;

		ASSERT(cpu->cyp_state == CYS_EXPANDING);

		do {
			lev = cpu->cyp_modify_levels;
			nlev = lev + 1;
		} while (cas32(&cpu->cyp_modify_levels, lev, nlev) != lev);

		/*
		 * If we are the last soft level to see the modification,
		 * post on cyp_modify_wait.  Otherwise, (if we're not
		 * already at low level), post down to the next soft level.
		 */
		if (nlev == CY_SOFT_LEVELS) {
			CYC_TRACE0(cpu, level, "resize-kick");
			sema_v(&cpu->cyp_modify_wait);
		} else {
			ASSERT(nlev < CY_SOFT_LEVELS);
			if (level != CY_LOW_LEVEL) {
				cyc_backend_t *be = cpu->cyp_backend;

				CYC_TRACE0(cpu, level, "resize-post");
				be->cyb_softint(be->cyb_arg, level - 1);
			}
		}
	}
}

static void
cyclic_expand_xcall(cyc_xcallarg_t *arg)
{
	cyc_cpu_t *cpu = arg->cyx_cpu;
	cyc_backend_t *be = cpu->cyp_backend;
	cyb_arg_t bar = be->cyb_arg;
	cyc_cookie_t cookie;
	cyc_index_t new_size = arg->cyx_size, size = cpu->cyp_size, i;
	cyc_index_t *new_heap = arg->cyx_heap;
	cyclic_t *cyclics = cpu->cyp_cyclics, *new_cyclics = arg->cyx_cyclics;

	ASSERT(cpu->cyp_state == CYS_EXPANDING);

	/*
	 * This is a little dicey.  First, we'll raise our interrupt level
	 * to CY_HIGH_LEVEL.  This CPU already has a new heap, cyclic array,
	 * etc.; we just need to bcopy them across.  As for the softint
	 * buffers, we'll switch the active buffers.  The actual softints will
	 * take care of consuming any pending cyclics in the old buffer.
	 */
	cookie = be->cyb_set_level(bar, CY_HIGH_LEVEL);

	CYC_TRACE(cpu, CY_HIGH_LEVEL, "expand", new_size, 0);

	/*
	 * Assert that the new size is a power of 2.
	 */
	ASSERT((new_size & new_size - 1) == 0);
	ASSERT(new_size == (size << 1));
	ASSERT(cpu->cyp_heap != NULL && cpu->cyp_cyclics != NULL);

	bcopy(cpu->cyp_heap, new_heap, sizeof (cyc_index_t) * size);
	bcopy(cyclics, new_cyclics, sizeof (cyclic_t) * size);

	/*
	 * Now run through the old cyclics array, setting pend to 0.  To
	 * softints (which are executing at a lower priority level), the
	 * pends dropping to 0 will appear atomic with the cyp_cyclics
	 * pointer changing.
	 */
	for (i = 0; i < size; i++)
		cyclics[i].cy_pend = 0;

	/*
	 * Set up the free list, and set all of the new cyclics to be CYF_FREE.
	 */
	for (i = size; i < new_size; i++) {
		new_heap[i] = i;
		new_cyclics[i].cy_flags = CYF_FREE;
	}

	/*
	 * We can go ahead and plow the value of cyp_heap and cyp_cyclics;
	 * cyclic_expand() has kept a copy.
	 */
	cpu->cyp_heap = new_heap;
	cpu->cyp_cyclics = new_cyclics;
	cpu->cyp_size = new_size;

	/*
	 * We've switched over the heap and the cyclics array.  Now we need
	 * to switch over our active softint buffer pointers.
	 */
	for (i = CY_LOW_LEVEL; i < CY_LOW_LEVEL + CY_SOFT_LEVELS; i++) {
		cyc_softbuf_t *softbuf = &cpu->cyp_softbuf[i];
		uchar_t hard = softbuf->cys_hard;

		/*
		 * Assert that we're not in the middle of a resize operation.
		 */
		ASSERT(hard == softbuf->cys_soft);
		ASSERT(hard == 0 || hard == 1);
		ASSERT(softbuf->cys_buf[hard].cypc_buf != NULL);

		softbuf->cys_hard = hard ^ 1;

		/*
		 * The caller (cyclic_expand()) is responsible for setting
		 * up the new producer-consumer buffer; assert that it's
		 * been done correctly.
		 */
		ASSERT(softbuf->cys_buf[hard ^ 1].cypc_buf != NULL);
		ASSERT(softbuf->cys_buf[hard ^ 1].cypc_prodndx == 0);
		ASSERT(softbuf->cys_buf[hard ^ 1].cypc_consndx == 0);
	}

	/*
	 * That's all there is to it; now we just need to postdown to
	 * get the softint chain going.
	 */
	be->cyb_softint(bar, CY_HIGH_LEVEL - 1);
	be->cyb_restore_level(bar, cookie);
}

/*
 * cyclic_expand() will cross call onto the CPU to perform the actual
 * expand operation.
 */
static void
cyclic_expand(cyc_cpu_t *cpu)
{
	cyc_index_t new_size, old_size;
	cyc_index_t *new_heap, *old_heap;
	cyclic_t *new_cyclics, *old_cyclics;
	cyc_xcallarg_t arg;
	cyc_backend_t *be = cpu->cyp_backend;
	char old_hard;
	int i;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu->cyp_state == CYS_ONLINE);

	cpu->cyp_state = CYS_EXPANDING;

	old_heap = cpu->cyp_heap;
	old_cyclics = cpu->cyp_cyclics;

	if ((new_size = ((old_size = cpu->cyp_size) << 1)) == 0) {
		new_size = CY_DEFAULT_PERCPU;
		ASSERT(old_heap == NULL && old_cyclics == NULL);
	}

	/*
	 * Check that the new_size is a power of 2.
	 */
	ASSERT((new_size - 1 & new_size) == 0);

	new_heap = kmem_alloc(sizeof (cyc_index_t) * new_size, KM_SLEEP);
	new_cyclics = kmem_zalloc(sizeof (cyclic_t) * new_size, KM_SLEEP);

	/*
	 * We know that no other expansions are in progress (they serialize
	 * on cpu_lock), so we can safely read the softbuf metadata.
	 */
	old_hard = cpu->cyp_softbuf[0].cys_hard;

	for (i = CY_LOW_LEVEL; i < CY_LOW_LEVEL + CY_SOFT_LEVELS; i++) {
		cyc_softbuf_t *softbuf = &cpu->cyp_softbuf[i];
		char hard = softbuf->cys_hard;
		cyc_pcbuffer_t *pc = &softbuf->cys_buf[hard ^ 1];

		ASSERT(hard == old_hard);
		ASSERT(hard == softbuf->cys_soft);
		ASSERT(pc->cypc_buf == NULL);

		pc->cypc_buf =
		    kmem_alloc(sizeof (cyc_index_t) * new_size, KM_SLEEP);
		pc->cypc_prodndx = pc->cypc_consndx = 0;
		pc->cypc_sizemask = new_size - 1;
	}

	arg.cyx_cpu = cpu;
	arg.cyx_heap = new_heap;
	arg.cyx_cyclics = new_cyclics;
	arg.cyx_size = new_size;

	cpu->cyp_modify_levels = 0;

	be->cyb_xcall(be->cyb_arg, cpu->cyp_cpu,
	    (cyc_func_t)cyclic_expand_xcall, &arg);

	/*
	 * Now block, waiting for the resize operation to complete.
	 */
	sema_p(&cpu->cyp_modify_wait);
	ASSERT(cpu->cyp_modify_levels == CY_SOFT_LEVELS);

	/*
	 * The operation is complete; we can now free the old buffers.
	 */
	for (i = CY_LOW_LEVEL; i < CY_LOW_LEVEL + CY_SOFT_LEVELS; i++) {
		cyc_softbuf_t *softbuf = &cpu->cyp_softbuf[i];
		char hard = softbuf->cys_hard;
		cyc_pcbuffer_t *pc = &softbuf->cys_buf[hard ^ 1];

		ASSERT(hard == (old_hard ^ 1));
		ASSERT(hard == softbuf->cys_soft);

		if (pc->cypc_buf == NULL)
			continue;

		ASSERT(pc->cypc_sizemask == ((new_size - 1) >> 1));

		kmem_free(pc->cypc_buf,
		    sizeof (cyc_index_t) * (pc->cypc_sizemask + 1));
		pc->cypc_buf = NULL;
	}

	if (old_cyclics != NULL) {
		ASSERT(old_heap != NULL);
		ASSERT(old_size != 0);
		kmem_free(old_cyclics, sizeof (cyclic_t) * old_size);
		kmem_free(old_heap, sizeof (cyc_index_t) * old_size);
	}

	ASSERT(cpu->cyp_state == CYS_EXPANDING);
	cpu->cyp_state = CYS_ONLINE;
}

/*
 * cyclic_pick_cpu will attempt to pick a CPU according to the constraints
 * specified by the partition, bound CPU, and flags.  Additionally,
 * cyclic_pick_cpu() will not pick the avoid CPU; it will return NULL if
 * the avoid CPU is the only CPU which satisfies the constraints.
 *
 * If CYF_CPU_BOUND is set in flags, the specified CPU must be non-NULL.
 * If CYF_PART_BOUND is set in flags, the specified partition must be non-NULL.
 * If both CYF_CPU_BOUND and CYF_PART_BOUND are set, the specified CPU must
 * be in the specified partition.
 */
static cyc_cpu_t *
cyclic_pick_cpu(cpupart_t *part, cpu_t *bound, cpu_t *avoid, uint16_t flags)
{
	cpu_t *c, *start = (part != NULL) ? part->cp_cpulist : CPU;
	cpu_t *online = NULL;
	uintptr_t offset;

	CYC_PTRACE("pick-cpu", part, bound);

	ASSERT(!(flags & CYF_CPU_BOUND) || bound != NULL);
	ASSERT(!(flags & CYF_PART_BOUND) || part != NULL);

	/*
	 * If we're bound to our CPU, there isn't much choice involved.  We
	 * need to check that the CPU passed as bound is in the cpupart, and
	 * that the CPU that we're binding to has been configured.
	 */
	if (flags & CYF_CPU_BOUND) {
		CYC_PTRACE("pick-cpu-bound", bound, avoid);

		if ((flags & CYF_PART_BOUND) && bound->cpu_part != part)
			panic("cyclic_pick_cpu:  "
			    "CPU binding contradicts partition binding");

		if (bound == avoid)
			return (NULL);

		if (bound->cpu_cyclic == NULL)
			panic("cyclic_pick_cpu:  "
			    "attempt to bind to non-configured CPU");

		return (bound->cpu_cyclic);
	}

	if (flags & CYF_PART_BOUND) {
		CYC_PTRACE("pick-part-bound", bound, avoid);
		offset = offsetof(cpu_t, cpu_next_part);
	} else {
		offset = offsetof(cpu_t, cpu_next_onln);
	}

	c = start;
	do {
		if (c->cpu_cyclic == NULL)
			continue;

		if (c->cpu_cyclic->cyp_state == CYS_OFFLINE)
			continue;

		if (c == avoid)
			continue;

		if (c->cpu_flags & CPU_ENABLE)
			goto found;

		if (online == NULL)
			online = c;
	} while ((c = *(cpu_t **)((uintptr_t)c + offset)) != start);

	/*
	 * If we're here, we're in one of two situations:
	 *
	 *  (a)	We have a partition-bound cyclic, and there is no CPU in
	 *	our partition which is CPU_ENABLE'd.  If we saw another
	 *	non-CYS_OFFLINE CPU in our partition, we'll go with it.
	 *	If not, the avoid CPU must be the only non-CYS_OFFLINE
	 *	CPU in the partition; we're forced to return NULL.
	 *
	 *  (b)	We have a partition-unbound cyclic, in which case there
	 *	must only be one CPU CPU_ENABLE'd, and it must be the one
	 *	we're trying to avoid.  If cyclic_juggle()/cyclic_offline()
	 *	are called appropriately, this generally shouldn't happen
	 *	(the offline should fail before getting to this code).
	 *	At any rate: we can't avoid the avoid CPU, so we return
	 *	NULL.
	 */
	if (!(flags & CYF_PART_BOUND)) {
		ASSERT(avoid->cpu_flags & CPU_ENABLE);
		return (NULL);
	}

	CYC_PTRACE("pick-no-intr", part, avoid);

	if ((c = online) != NULL)
		goto found;

	CYC_PTRACE("pick-fail", part, avoid);
	ASSERT(avoid->cpu_part == start->cpu_part);
	return (NULL);

found:
	CYC_PTRACE("pick-cpu-found", c, avoid);
	ASSERT(c != avoid);
	ASSERT(c->cpu_cyclic != NULL);

	return (c->cpu_cyclic);
}

static void
cyclic_add_xcall(cyc_xcallarg_t *arg)
{
	cyc_cpu_t *cpu = arg->cyx_cpu;
	cyc_handler_t *hdlr = arg->cyx_hdlr;
	cyc_time_t *when = arg->cyx_when;
	cyc_backend_t *be = cpu->cyp_backend;
	cyc_index_t ndx, nelems;
	cyc_cookie_t cookie;
	cyb_arg_t bar = be->cyb_arg;
	cyclic_t *cyclic;

	ASSERT(cpu->cyp_nelems < cpu->cyp_size);

	cookie = be->cyb_set_level(bar, CY_HIGH_LEVEL);

	CYC_TRACE(cpu, CY_HIGH_LEVEL,
	    "add-xcall", when->cyt_when, when->cyt_interval);

	nelems = cpu->cyp_nelems++;

	if (nelems == 0) {
		/*
		 * If this is the first element, we need to enable the
		 * backend on this CPU.
		 */
		CYC_TRACE0(cpu, CY_HIGH_LEVEL, "enabled");
		be->cyb_enable(bar);
	}

	ndx = cpu->cyp_heap[nelems];
	cyclic = &cpu->cyp_cyclics[ndx];

	ASSERT(cyclic->cy_flags == CYF_FREE);
	cyclic->cy_interval = when->cyt_interval;

	if (when->cyt_when == 0) {
		/*
		 * If a start time hasn't been explicitly specified, we'll
		 * start on the next interval boundary.
		 */
		cyclic->cy_expire = (gethrtime() / cyclic->cy_interval + 1) *
		    cyclic->cy_interval;
	} else {
		cyclic->cy_expire = when->cyt_when;
	}

	cyclic->cy_handler = hdlr->cyh_func;
	cyclic->cy_arg = hdlr->cyh_arg;
	cyclic->cy_level = hdlr->cyh_level;
	cyclic->cy_flags = arg->cyx_flags;

	if (cyclic_upheap(cpu, nelems)) {
		hrtime_t exp = cyclic->cy_expire;

		CYC_TRACE(cpu, CY_HIGH_LEVEL, "add-reprog", cyclic, exp);

		/*
		 * If our upheap propagated to the root, we need to
		 * reprogram the interrupt source.
		 */
		be->cyb_reprogram(bar, exp);
	}
	be->cyb_restore_level(bar, cookie);

	arg->cyx_ndx = ndx;
}

static cyc_index_t
cyclic_add_here(cyc_cpu_t *cpu, cyc_handler_t *hdlr,
    cyc_time_t *when, uint16_t flags)
{
	cyc_backend_t *be = cpu->cyp_backend;
	cyb_arg_t bar = be->cyb_arg;
	cyc_xcallarg_t arg;

	CYC_PTRACE("add-cpu", cpu, hdlr->cyh_func);
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu->cyp_state == CYS_ONLINE);
	ASSERT(!(cpu->cyp_cpu->cpu_flags & CPU_OFFLINE));
	ASSERT(when->cyt_when >= 0 && when->cyt_interval > 0);

	if (cpu->cyp_nelems == cpu->cyp_size) {
		/*
		 * This is expensive; it will cross call onto the other
		 * CPU to perform the expansion.
		 */
		cyclic_expand(cpu);
		ASSERT(cpu->cyp_nelems < cpu->cyp_size);
	}

	/*
	 * By now, we know that we're going to be able to successfully
	 * perform the add.  Now cross call over to the CPU of interest to
	 * actually add our cyclic.
	 */
	arg.cyx_cpu = cpu;
	arg.cyx_hdlr = hdlr;
	arg.cyx_when = when;
	arg.cyx_flags = flags;

	be->cyb_xcall(bar, cpu->cyp_cpu, (cyc_func_t)cyclic_add_xcall, &arg);

	CYC_PTRACE("add-cpu-done", cpu, arg.cyx_ndx);

	return (arg.cyx_ndx);
}

static void
cyclic_remove_xcall(cyc_xcallarg_t *arg)
{
	cyc_cpu_t *cpu = arg->cyx_cpu;
	cyc_backend_t *be = cpu->cyp_backend;
	cyb_arg_t bar = be->cyb_arg;
	cyc_cookie_t cookie;
	cyc_index_t ndx = arg->cyx_ndx, nelems, i;
	cyc_index_t *heap, last;
	cyclic_t *cyclic;
#ifdef DEBUG
	cyc_index_t root;
#endif

	ASSERT(cpu->cyp_state == CYS_REMOVING);

	cookie = be->cyb_set_level(bar, CY_HIGH_LEVEL);

	CYC_TRACE1(cpu, CY_HIGH_LEVEL, "remove-xcall", ndx);

	heap = cpu->cyp_heap;
	nelems = cpu->cyp_nelems;
	ASSERT(nelems > 0);
	cyclic = &cpu->cyp_cyclics[ndx];

	/*
	 * Grab the current expiration time.  If this cyclic is being
	 * removed as part of a juggling operation, the expiration time
	 * will be used when the cyclic is added to the new CPU.
	 */
	if (arg->cyx_when != NULL) {
		arg->cyx_when->cyt_when = cyclic->cy_expire;
		arg->cyx_when->cyt_interval = cyclic->cy_interval;
	}

	if (cyclic->cy_pend != 0) {
		/*
		 * The pend is non-zero; this cyclic is currently being
		 * executed (or will be executed shortly).  If the caller
		 * refuses to wait, we must return (doing nothing).  Otherwise,
		 * we will stash the pend value * in this CPU's rpend, and
		 * then zero it out.  The softint in the pend loop will see
		 * that we have zeroed out pend, and will call the cyclic
		 * handler rpend times.  The caller will wait until the
		 * softint has completed calling the cyclic handler.
		 */
		if (arg->cyx_wait == CY_NOWAIT) {
			arg->cyx_wait = CY_WAIT;
			goto out;
		}

		ASSERT(cyclic->cy_level != CY_HIGH_LEVEL);
		CYC_TRACE1(cpu, CY_HIGH_LEVEL, "remove-pend", cyclic->cy_pend);
		cpu->cyp_rpend = cyclic->cy_pend;
		cyclic->cy_pend = 0;
	}

	/*
	 * Now set the flags to CYF_FREE.  We don't need a membar_enter()
	 * between zeroing pend and setting the flags because we're at
	 * CY_HIGH_LEVEL (that is, the zeroing of pend and the setting
	 * of cy_flags appear atomic to softints).
	 */
	cyclic->cy_flags = CYF_FREE;

	for (i = 0; i < nelems; i++) {
		if (heap[i] == ndx)
			break;
	}

	if (i == nelems)
		panic("attempt to remove non-existent cyclic");

	cpu->cyp_nelems = --nelems;

	if (nelems == 0) {
		/*
		 * If we just removed the last element, then we need to
		 * disable the backend on this CPU.
		 */
		CYC_TRACE0(cpu, CY_HIGH_LEVEL, "disabled");
		be->cyb_disable(bar);
	}

	if (i == nelems) {
		/*
		 * If we just removed the last element of the heap, then
		 * we don't have to downheap.
		 */
		CYC_TRACE0(cpu, CY_HIGH_LEVEL, "remove-bottom");
		goto out;
	}

#ifdef DEBUG
	root = heap[0];
#endif

	/*
	 * Swap the last element of the heap with the one we want to
	 * remove, and downheap (this has the implicit effect of putting
	 * the newly freed element on the free list).
	 */
	heap[i] = (last = heap[nelems]);
	heap[nelems] = ndx;

	if (i == 0) {
		CYC_TRACE0(cpu, CY_HIGH_LEVEL, "remove-root");
		cyclic_downheap(cpu, 0);
	} else {
		if (cyclic_upheap(cpu, i) == 0) {
			/*
			 * The upheap didn't propagate to the root; if it
			 * didn't propagate at all, we need to downheap.
			 */
			CYC_TRACE0(cpu, CY_HIGH_LEVEL, "remove-no-root");
			if (heap[i] == last) {
				CYC_TRACE0(cpu, CY_HIGH_LEVEL, "remove-no-up");
				cyclic_downheap(cpu, i);
			}
			ASSERT(heap[0] == root);
			goto out;
		}
	}

	/*
	 * We're here because we changed the root; we need to reprogram
	 * the clock source.
	 */
	cyclic = &cpu->cyp_cyclics[heap[0]];

	CYC_TRACE0(cpu, CY_HIGH_LEVEL, "remove-reprog");

	ASSERT(nelems != 0);
	be->cyb_reprogram(bar, cyclic->cy_expire);
out:
	be->cyb_restore_level(bar, cookie);
}

static int
cyclic_remove_here(cyc_cpu_t *cpu, cyc_index_t ndx, cyc_time_t *when, int wait)
{
	cyc_backend_t *be = cpu->cyp_backend;
	cyc_xcallarg_t arg;
	cyclic_t *cyclic = &cpu->cyp_cyclics[ndx];
	cyc_level_t level = cyclic->cy_level;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu->cyp_rpend == 0);
	ASSERT(wait == CY_WAIT || wait == CY_NOWAIT);

	arg.cyx_ndx = ndx;
	arg.cyx_cpu = cpu;
	arg.cyx_when = when;
	arg.cyx_wait = wait;

	ASSERT(cpu->cyp_state == CYS_ONLINE);
	cpu->cyp_state = CYS_REMOVING;

	be->cyb_xcall(be->cyb_arg, cpu->cyp_cpu,
	    (cyc_func_t)cyclic_remove_xcall, &arg);

	/*
	 * If the cyclic we removed wasn't at CY_HIGH_LEVEL, then we need to
	 * check the cyp_rpend.  If it's non-zero, then we need to wait here
	 * for all pending cyclic handlers to run.
	 */
	ASSERT(!(level == CY_HIGH_LEVEL && cpu->cyp_rpend != 0));
	ASSERT(!(wait == CY_NOWAIT && cpu->cyp_rpend != 0));
	ASSERT(!(arg.cyx_wait == CY_NOWAIT && cpu->cyp_rpend != 0));

	if (wait != arg.cyx_wait) {
		/*
		 * We are being told that we must wait if we want to
		 * remove this cyclic; put the CPU back in the CYS_ONLINE
		 * state and return failure.
		 */
		ASSERT(wait == CY_NOWAIT && arg.cyx_wait == CY_WAIT);
		ASSERT(cpu->cyp_state == CYS_REMOVING);
		cpu->cyp_state = CYS_ONLINE;

		return (0);
	}

	if (cpu->cyp_rpend != 0)
		sema_p(&cpu->cyp_modify_wait);

	ASSERT(cpu->cyp_state == CYS_REMOVING);

	cpu->cyp_rpend = 0;
	cpu->cyp_state = CYS_ONLINE;

	return (1);
}

/*
 * If cyclic_reprogram() is called on the same CPU as the cyclic's CPU, then
 * it calls this function directly. Else, it invokes this function through
 * an X-call to the cyclic's CPU.
 */
static void
cyclic_reprogram_cyclic(cyc_cpu_t *cpu, cyc_index_t ndx, hrtime_t expire)
{
	cyc_backend_t *be = cpu->cyp_backend;
	cyb_arg_t bar = be->cyb_arg;
	cyc_cookie_t cookie;
	cyc_index_t nelems, i;
	cyc_index_t *heap;
	cyclic_t *cyclic;
	hrtime_t oexpire;
	int reprog;

	cookie = be->cyb_set_level(bar, CY_HIGH_LEVEL);

	CYC_TRACE1(cpu, CY_HIGH_LEVEL, "reprog-xcall", ndx);

	nelems = cpu->cyp_nelems;
	ASSERT(nelems > 0);
	heap = cpu->cyp_heap;

	/*
	 * Reprogrammed cyclics are typically one-shot ones that get
	 * set to infinity on every expiration. We shorten the search by
	 * searching from the bottom of the heap to the top instead of the
	 * other way around.
	 */
	for (i = nelems - 1; i >= 0; i--) {
		if (heap[i] == ndx)
			break;
	}
	if (i < 0)
		panic("attempt to reprogram non-existent cyclic");

	cyclic = &cpu->cyp_cyclics[ndx];
	oexpire = cyclic->cy_expire;
	cyclic->cy_expire = expire;

	reprog = (i == 0);
	if (expire > oexpire) {
		CYC_TRACE1(cpu, CY_HIGH_LEVEL, "reprog-down", i);
		cyclic_downheap(cpu, i);
	} else if (i > 0) {
		CYC_TRACE1(cpu, CY_HIGH_LEVEL, "reprog-up", i);
		reprog = cyclic_upheap(cpu, i);
	}

	if (reprog && (cpu->cyp_state != CYS_SUSPENDED)) {
		/*
		 * The root changed. Reprogram the clock source.
		 */
		CYC_TRACE0(cpu, CY_HIGH_LEVEL, "reprog-root");
		cyclic = &cpu->cyp_cyclics[heap[0]];
		be->cyb_reprogram(bar, cyclic->cy_expire);
	}

	be->cyb_restore_level(bar, cookie);
}

static void
cyclic_reprogram_xcall(cyc_xcallarg_t *arg)
{
	cyclic_reprogram_cyclic(arg->cyx_cpu, arg->cyx_ndx,
	    arg->cyx_when->cyt_when);
}

static void
cyclic_reprogram_here(cyc_cpu_t *cpu, cyc_index_t ndx, hrtime_t expiration)
{
	cyc_backend_t *be = cpu->cyp_backend;
	cyc_xcallarg_t arg;
	cyc_time_t when;

	ASSERT(expiration > 0);

	arg.cyx_ndx = ndx;
	arg.cyx_cpu = cpu;
	arg.cyx_when = &when;
	when.cyt_when = expiration;

	be->cyb_xcall(be->cyb_arg, cpu->cyp_cpu,
	    (cyc_func_t)cyclic_reprogram_xcall, &arg);
}

/*
 * cyclic_juggle_one_to() should only be called when the source cyclic
 * can be juggled and the destination CPU is known to be able to accept
 * it.
 */
static void
cyclic_juggle_one_to(cyc_id_t *idp, cyc_cpu_t *dest)
{
	cyc_cpu_t *src = idp->cyi_cpu;
	cyc_index_t ndx = idp->cyi_ndx;
	cyc_time_t when;
	cyc_handler_t hdlr;
	cyclic_t *cyclic;
	uint16_t flags;
	hrtime_t delay;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(src != NULL && idp->cyi_omni_list == NULL);
	ASSERT(!(dest->cyp_cpu->cpu_flags & (CPU_QUIESCED | CPU_OFFLINE)));
	CYC_PTRACE("juggle-one-to", idp, dest);

	cyclic = &src->cyp_cyclics[ndx];

	flags = cyclic->cy_flags;
	ASSERT(!(flags & CYF_CPU_BOUND) && !(flags & CYF_FREE));

	hdlr.cyh_func = cyclic->cy_handler;
	hdlr.cyh_level = cyclic->cy_level;
	hdlr.cyh_arg = cyclic->cy_arg;

	/*
	 * Before we begin the juggling process, see if the destination
	 * CPU requires an expansion.  If it does, we'll perform the
	 * expansion before removing the cyclic.  This is to prevent us
	 * from blocking while a system-critical cyclic (notably, the clock
	 * cyclic) isn't on a CPU.
	 */
	if (dest->cyp_nelems == dest->cyp_size) {
		CYC_PTRACE("remove-expand", idp, dest);
		cyclic_expand(dest);
		ASSERT(dest->cyp_nelems < dest->cyp_size);
	}

	/*
	 * Prevent a reprogram of this cyclic while we are relocating it.
	 * Otherwise, cyclic_reprogram_here() will end up sending an X-call
	 * to the wrong CPU.
	 */
	rw_enter(&idp->cyi_lock, RW_WRITER);

	/*
	 * Remove the cyclic from the source.  As mentioned above, we cannot
	 * block during this operation; if we cannot remove the cyclic
	 * without waiting, we spin for a time shorter than the interval, and
	 * reattempt the (non-blocking) removal.  If we continue to fail,
	 * we will exponentially back off (up to half of the interval).
	 * Note that the removal will ultimately succeed -- even if the
	 * cyclic handler is blocked on a resource held by a thread which we
	 * have preempted, priority inheritance assures that the preempted
	 * thread will preempt us and continue to progress.
	 */
	for (delay = NANOSEC / MICROSEC; ; delay <<= 1) {
		/*
		 * Before we begin this operation, disable kernel preemption.
		 */
		kpreempt_disable();
		if (cyclic_remove_here(src, ndx, &when, CY_NOWAIT))
			break;

		/*
		 * The operation failed; enable kernel preemption while
		 * spinning.
		 */
		kpreempt_enable();

		CYC_PTRACE("remove-retry", idp, src);

		if (delay > (cyclic->cy_interval >> 1))
			delay = cyclic->cy_interval >> 1;

		/*
		 * Drop the RW lock to avoid a deadlock with the cyclic
		 * handler (because it can potentially call cyclic_reprogram().
		 */
		rw_exit(&idp->cyi_lock);
		drv_usecwait((clock_t)(delay / (NANOSEC / MICROSEC)));
		rw_enter(&idp->cyi_lock, RW_WRITER);
	}

	/*
	 * Now add the cyclic to the destination.  This won't block; we
	 * performed any necessary (blocking) expansion of the destination
	 * CPU before removing the cyclic from the source CPU.
	 */
	idp->cyi_ndx = cyclic_add_here(dest, &hdlr, &when, flags);
	idp->cyi_cpu = dest;
	kpreempt_enable();

	/*
	 * Now that we have successfully relocated the cyclic, allow
	 * it to be reprogrammed.
	 */
	rw_exit(&idp->cyi_lock);
}

static int
cyclic_juggle_one(cyc_id_t *idp)
{
	cyc_index_t ndx = idp->cyi_ndx;
	cyc_cpu_t *cpu = idp->cyi_cpu, *dest;
	cyclic_t *cyclic = &cpu->cyp_cyclics[ndx];
	cpu_t *c = cpu->cyp_cpu;
	cpupart_t *part = c->cpu_part;

	CYC_PTRACE("juggle-one", idp, cpu);
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(!(c->cpu_flags & CPU_OFFLINE));
	ASSERT(cpu->cyp_state == CYS_ONLINE);
	ASSERT(!(cyclic->cy_flags & CYF_FREE));

	if ((dest = cyclic_pick_cpu(part, c, c, cyclic->cy_flags)) == NULL) {
		/*
		 * Bad news:  this cyclic can't be juggled.
		 */
		CYC_PTRACE("juggle-fail", idp, cpu)
		return (0);
	}

	cyclic_juggle_one_to(idp, dest);

	return (1);
}

static void
cyclic_unbind_cpu(cyclic_id_t id)
{
	cyc_id_t *idp = (cyc_id_t *)id;
	cyc_cpu_t *cpu = idp->cyi_cpu;
	cpu_t *c = cpu->cyp_cpu;
	cyclic_t *cyclic = &cpu->cyp_cyclics[idp->cyi_ndx];

	CYC_PTRACE("unbind-cpu", id, cpu);
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu->cyp_state == CYS_ONLINE);
	ASSERT(!(cyclic->cy_flags & CYF_FREE));
	ASSERT(cyclic->cy_flags & CYF_CPU_BOUND);

	cyclic->cy_flags &= ~CYF_CPU_BOUND;

	/*
	 * If we were bound to CPU which has interrupts disabled, we need
	 * to juggle away.  This can only fail if we are bound to a
	 * processor set, and if every CPU in the processor set has
	 * interrupts disabled.
	 */
	if (!(c->cpu_flags & CPU_ENABLE)) {
		int res = cyclic_juggle_one(idp);

		ASSERT((res && idp->cyi_cpu != cpu) ||
		    (!res && (cyclic->cy_flags & CYF_PART_BOUND)));
	}
}

static void
cyclic_bind_cpu(cyclic_id_t id, cpu_t *d)
{
	cyc_id_t *idp = (cyc_id_t *)id;
	cyc_cpu_t *dest = d->cpu_cyclic, *cpu = idp->cyi_cpu;
	cpu_t *c = cpu->cyp_cpu;
	cyclic_t *cyclic = &cpu->cyp_cyclics[idp->cyi_ndx];
	cpupart_t *part = c->cpu_part;

	CYC_PTRACE("bind-cpu", id, dest);
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(!(d->cpu_flags & CPU_OFFLINE));
	ASSERT(!(c->cpu_flags & CPU_OFFLINE));
	ASSERT(cpu->cyp_state == CYS_ONLINE);
	ASSERT(dest != NULL);
	ASSERT(dest->cyp_state == CYS_ONLINE);
	ASSERT(!(cyclic->cy_flags & CYF_FREE));
	ASSERT(!(cyclic->cy_flags & CYF_CPU_BOUND));

	dest = cyclic_pick_cpu(part, d, NULL, cyclic->cy_flags | CYF_CPU_BOUND);

	if (dest != cpu) {
		cyclic_juggle_one_to(idp, dest);
		cyclic = &dest->cyp_cyclics[idp->cyi_ndx];
	}

	cyclic->cy_flags |= CYF_CPU_BOUND;
}

static void
cyclic_unbind_cpupart(cyclic_id_t id)
{
	cyc_id_t *idp = (cyc_id_t *)id;
	cyc_cpu_t *cpu = idp->cyi_cpu;
	cpu_t *c = cpu->cyp_cpu;
	cyclic_t *cyc = &cpu->cyp_cyclics[idp->cyi_ndx];

	CYC_PTRACE("unbind-part", idp, c->cpu_part);
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu->cyp_state == CYS_ONLINE);
	ASSERT(!(cyc->cy_flags & CYF_FREE));
	ASSERT(cyc->cy_flags & CYF_PART_BOUND);

	cyc->cy_flags &= ~CYF_PART_BOUND;

	/*
	 * If we're on a CPU which has interrupts disabled (and if this cyclic
	 * isn't bound to the CPU), we need to juggle away.
	 */
	if (!(c->cpu_flags & CPU_ENABLE) && !(cyc->cy_flags & CYF_CPU_BOUND)) {
		int res = cyclic_juggle_one(idp);

		ASSERT(res && idp->cyi_cpu != cpu);
	}
}

static void
cyclic_bind_cpupart(cyclic_id_t id, cpupart_t *part)
{
	cyc_id_t *idp = (cyc_id_t *)id;
	cyc_cpu_t *cpu = idp->cyi_cpu, *dest;
	cpu_t *c = cpu->cyp_cpu;
	cyclic_t *cyc = &cpu->cyp_cyclics[idp->cyi_ndx];

	CYC_PTRACE("bind-part", idp, part);
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(!(c->cpu_flags & CPU_OFFLINE));
	ASSERT(cpu->cyp_state == CYS_ONLINE);
	ASSERT(!(cyc->cy_flags & CYF_FREE));
	ASSERT(!(cyc->cy_flags & CYF_PART_BOUND));
	ASSERT(part->cp_ncpus > 0);

	dest = cyclic_pick_cpu(part, c, NULL, cyc->cy_flags | CYF_PART_BOUND);

	if (dest != cpu) {
		cyclic_juggle_one_to(idp, dest);
		cyc = &dest->cyp_cyclics[idp->cyi_ndx];
	}

	cyc->cy_flags |= CYF_PART_BOUND;
}

static void
cyclic_configure(cpu_t *c)
{
	cyc_cpu_t *cpu = kmem_zalloc(sizeof (cyc_cpu_t), KM_SLEEP);
	cyc_backend_t *nbe = kmem_zalloc(sizeof (cyc_backend_t), KM_SLEEP);
	int i;

	CYC_PTRACE1("configure", cpu);
	ASSERT(MUTEX_HELD(&cpu_lock));

	if (cyclic_id_cache == NULL)
		cyclic_id_cache = kmem_cache_create("cyclic_id_cache",
		    sizeof (cyc_id_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	cpu->cyp_cpu = c;

	sema_init(&cpu->cyp_modify_wait, 0, NULL, SEMA_DEFAULT, NULL);

	cpu->cyp_size = 1;
	cpu->cyp_heap = kmem_zalloc(sizeof (cyc_index_t), KM_SLEEP);
	cpu->cyp_cyclics = kmem_zalloc(sizeof (cyclic_t), KM_SLEEP);
	cpu->cyp_cyclics->cy_flags = CYF_FREE;

	for (i = CY_LOW_LEVEL; i < CY_LOW_LEVEL + CY_SOFT_LEVELS; i++) {
		/*
		 * We don't need to set the sizemask; it's already zero
		 * (which is the appropriate sizemask for a size of 1).
		 */
		cpu->cyp_softbuf[i].cys_buf[0].cypc_buf =
		    kmem_alloc(sizeof (cyc_index_t), KM_SLEEP);
	}

	cpu->cyp_state = CYS_OFFLINE;

	/*
	 * Setup the backend for this CPU.
	 */
	bcopy(&cyclic_backend, nbe, sizeof (cyc_backend_t));
	nbe->cyb_arg = nbe->cyb_configure(c);
	cpu->cyp_backend = nbe;

	/*
	 * On platforms where stray interrupts may be taken during startup,
	 * the CPU's cpu_cyclic pointer serves as an indicator that the
	 * cyclic subsystem for this CPU is prepared to field interrupts.
	 */
	membar_producer();

	c->cpu_cyclic = cpu;
}

static void
cyclic_unconfigure(cpu_t *c)
{
	cyc_cpu_t *cpu = c->cpu_cyclic;
	cyc_backend_t *be = cpu->cyp_backend;
	cyb_arg_t bar = be->cyb_arg;
	int i;

	CYC_PTRACE1("unconfigure", cpu);
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu->cyp_state == CYS_OFFLINE);
	ASSERT(cpu->cyp_nelems == 0);

	/*
	 * Let the backend know that the CPU is being yanked, and free up
	 * the backend structure.
	 */
	be->cyb_unconfigure(bar);
	kmem_free(be, sizeof (cyc_backend_t));
	cpu->cyp_backend = NULL;

	/*
	 * Free up the producer/consumer buffers at each of the soft levels.
	 */
	for (i = CY_LOW_LEVEL; i < CY_LOW_LEVEL + CY_SOFT_LEVELS; i++) {
		cyc_softbuf_t *softbuf = &cpu->cyp_softbuf[i];
		uchar_t hard = softbuf->cys_hard;
		cyc_pcbuffer_t *pc = &softbuf->cys_buf[hard];
		size_t bufsize = sizeof (cyc_index_t) * (pc->cypc_sizemask + 1);

		/*
		 * Assert that we're not in the middle of a resize operation.
		 */
		ASSERT(hard == softbuf->cys_soft);
		ASSERT(hard == 0 || hard == 1);
		ASSERT(pc->cypc_buf != NULL);
		ASSERT(softbuf->cys_buf[hard ^ 1].cypc_buf == NULL);

		kmem_free(pc->cypc_buf, bufsize);
		pc->cypc_buf = NULL;
	}

	/*
	 * Finally, clean up our remaining dynamic structures and NULL out
	 * the cpu_cyclic pointer.
	 */
	kmem_free(cpu->cyp_cyclics, cpu->cyp_size * sizeof (cyclic_t));
	kmem_free(cpu->cyp_heap, cpu->cyp_size * sizeof (cyc_index_t));
	kmem_free(cpu, sizeof (cyc_cpu_t));

	c->cpu_cyclic = NULL;
}

static int
cyclic_cpu_setup(cpu_setup_t what, int id)
{
	/*
	 * We are guaranteed that there is still/already an entry in the
	 * cpu array for this CPU.
	 */
	cpu_t *c = cpu[id];
	cyc_cpu_t *cyp = c->cpu_cyclic;

	ASSERT(MUTEX_HELD(&cpu_lock));

	switch (what) {
	case CPU_CONFIG:
		ASSERT(cyp == NULL);
		cyclic_configure(c);
		break;

	case CPU_UNCONFIG:
		ASSERT(cyp != NULL && cyp->cyp_state == CYS_OFFLINE);
		cyclic_unconfigure(c);
		break;

	default:
		break;
	}

	return (0);
}

static void
cyclic_suspend_xcall(cyc_xcallarg_t *arg)
{
	cyc_cpu_t *cpu = arg->cyx_cpu;
	cyc_backend_t *be = cpu->cyp_backend;
	cyc_cookie_t cookie;
	cyb_arg_t bar = be->cyb_arg;

	cookie = be->cyb_set_level(bar, CY_HIGH_LEVEL);

	CYC_TRACE1(cpu, CY_HIGH_LEVEL, "suspend-xcall", cpu->cyp_nelems);
	ASSERT(cpu->cyp_state == CYS_ONLINE || cpu->cyp_state == CYS_OFFLINE);

	/*
	 * We won't disable this CPU unless it has a non-zero number of
	 * elements (cpu_lock assures that no one else may be attempting
	 * to disable this CPU).
	 */
	if (cpu->cyp_nelems > 0) {
		ASSERT(cpu->cyp_state == CYS_ONLINE);
		be->cyb_disable(bar);
	}

	if (cpu->cyp_state == CYS_ONLINE)
		cpu->cyp_state = CYS_SUSPENDED;

	be->cyb_suspend(bar);
	be->cyb_restore_level(bar, cookie);
}

static void
cyclic_resume_xcall(cyc_xcallarg_t *arg)
{
	cyc_cpu_t *cpu = arg->cyx_cpu;
	cyc_backend_t *be = cpu->cyp_backend;
	cyc_cookie_t cookie;
	cyb_arg_t bar = be->cyb_arg;
	cyc_state_t state = cpu->cyp_state;

	cookie = be->cyb_set_level(bar, CY_HIGH_LEVEL);

	CYC_TRACE1(cpu, CY_HIGH_LEVEL, "resume-xcall", cpu->cyp_nelems);
	ASSERT(state == CYS_SUSPENDED || state == CYS_OFFLINE);

	be->cyb_resume(bar);

	/*
	 * We won't enable this CPU unless it has a non-zero number of
	 * elements.
	 */
	if (cpu->cyp_nelems > 0) {
		cyclic_t *cyclic = &cpu->cyp_cyclics[cpu->cyp_heap[0]];
		hrtime_t exp = cyclic->cy_expire;

		CYC_TRACE(cpu, CY_HIGH_LEVEL, "resume-reprog", cyclic, exp);
		ASSERT(state == CYS_SUSPENDED);
		be->cyb_enable(bar);
		be->cyb_reprogram(bar, exp);
	}

	if (state == CYS_SUSPENDED)
		cpu->cyp_state = CYS_ONLINE;

	CYC_TRACE1(cpu, CY_HIGH_LEVEL, "resume-done", cpu->cyp_nelems);
	be->cyb_restore_level(bar, cookie);
}

static void
cyclic_omni_start(cyc_id_t *idp, cyc_cpu_t *cpu)
{
	cyc_omni_handler_t *omni = &idp->cyi_omni_hdlr;
	cyc_omni_cpu_t *ocpu = kmem_alloc(sizeof (cyc_omni_cpu_t), KM_SLEEP);
	cyc_handler_t hdlr;
	cyc_time_t when;

	CYC_PTRACE("omni-start", cpu, idp);
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu->cyp_state == CYS_ONLINE);
	ASSERT(idp->cyi_cpu == NULL);

	hdlr.cyh_func = NULL;
	hdlr.cyh_arg = NULL;
	hdlr.cyh_level = CY_LEVELS;

	when.cyt_when = 0;
	when.cyt_interval = 0;

	omni->cyo_online(omni->cyo_arg, cpu->cyp_cpu, &hdlr, &when);

	ASSERT(hdlr.cyh_func != NULL);
	ASSERT(hdlr.cyh_level < CY_LEVELS);
	ASSERT(when.cyt_when >= 0 && when.cyt_interval > 0);

	ocpu->cyo_cpu = cpu;
	ocpu->cyo_arg = hdlr.cyh_arg;
	ocpu->cyo_ndx = cyclic_add_here(cpu, &hdlr, &when, 0);
	ocpu->cyo_next = idp->cyi_omni_list;
	idp->cyi_omni_list = ocpu;
}

static void
cyclic_omni_stop(cyc_id_t *idp, cyc_cpu_t *cpu)
{
	cyc_omni_handler_t *omni = &idp->cyi_omni_hdlr;
	cyc_omni_cpu_t *ocpu = idp->cyi_omni_list, *prev = NULL;
	clock_t delay;
	int ret;

	CYC_PTRACE("omni-stop", cpu, idp);
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu->cyp_state == CYS_ONLINE);
	ASSERT(idp->cyi_cpu == NULL);
	ASSERT(ocpu != NULL);

	/*
	 * Prevent a reprogram of this cyclic while we are removing it.
	 * Otherwise, cyclic_reprogram_here() will end up sending an X-call
	 * to the offlined CPU.
	 */
	rw_enter(&idp->cyi_lock, RW_WRITER);

	while (ocpu != NULL && ocpu->cyo_cpu != cpu) {
		prev = ocpu;
		ocpu = ocpu->cyo_next;
	}

	/*
	 * We _must_ have found an cyc_omni_cpu which corresponds to this
	 * CPU -- the definition of an omnipresent cyclic is that it runs
	 * on all online CPUs.
	 */
	ASSERT(ocpu != NULL);

	if (prev == NULL) {
		idp->cyi_omni_list = ocpu->cyo_next;
	} else {
		prev->cyo_next = ocpu->cyo_next;
	}

	/*
	 * Remove the cyclic from the source.  We cannot block during this
	 * operation because we are holding the cyi_lock which can be held
	 * by the cyclic handler via cyclic_reprogram().
	 *
	 * If we cannot remove the cyclic without waiting, we spin for a time,
	 * and reattempt the (non-blocking) removal. If the handler is blocked
	 * on the cyi_lock, then we let go of it in the spin loop to give
	 * the handler a chance to run. Note that the removal will ultimately
	 * succeed -- even if the cyclic handler is blocked on a resource
	 * held by a thread which we have preempted, priority inheritance
	 * assures that the preempted thread will preempt us and continue
	 * to progress.
	 */
	for (delay = 1; ; delay <<= 1) {
		/*
		 * Before we begin this operation, disable kernel preemption.
		 */
		kpreempt_disable();
		ret = cyclic_remove_here(ocpu->cyo_cpu, ocpu->cyo_ndx, NULL,
		    CY_NOWAIT);
		/*
		 * Enable kernel preemption while spinning.
		 */
		kpreempt_enable();

		if (ret)
			break;

		CYC_PTRACE("remove-omni-retry", idp, ocpu->cyo_cpu);

		/*
		 * Drop the RW lock to avoid a deadlock with the cyclic
		 * handler (because it can potentially call cyclic_reprogram().
		 */
		rw_exit(&idp->cyi_lock);
		drv_usecwait(delay);
		rw_enter(&idp->cyi_lock, RW_WRITER);
	}

	/*
	 * Now that we have successfully removed the cyclic, allow the omni
	 * cyclic to be reprogrammed on other CPUs.
	 */
	rw_exit(&idp->cyi_lock);

	/*
	 * The cyclic has been removed from this CPU; time to call the
	 * omnipresent offline handler.
	 */
	if (omni->cyo_offline != NULL)
		omni->cyo_offline(omni->cyo_arg, cpu->cyp_cpu, ocpu->cyo_arg);

	kmem_free(ocpu, sizeof (cyc_omni_cpu_t));
}

static cyc_id_t *
cyclic_new_id()
{
	cyc_id_t *idp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	idp = kmem_cache_alloc(cyclic_id_cache, KM_SLEEP);

	/*
	 * The cyi_cpu field of the cyc_id_t structure tracks the CPU
	 * associated with the cyclic.  If and only if this field is NULL, the
	 * cyc_id_t is an omnipresent cyclic.  Note that cyi_omni_list may be
	 * NULL for an omnipresent cyclic while the cyclic is being created
	 * or destroyed.
	 */
	idp->cyi_cpu = NULL;
	idp->cyi_ndx = 0;
	rw_init(&idp->cyi_lock, NULL, RW_DEFAULT, NULL);

	idp->cyi_next = cyclic_id_head;
	idp->cyi_prev = NULL;
	idp->cyi_omni_list = NULL;

	if (cyclic_id_head != NULL) {
		ASSERT(cyclic_id_head->cyi_prev == NULL);
		cyclic_id_head->cyi_prev = idp;
	}

	cyclic_id_head = idp;

	return (idp);
}

/*
 *  cyclic_id_t cyclic_add(cyc_handler_t *, cyc_time_t *)
 *
 *  Overview
 *
 *    cyclic_add() will create an unbound cyclic with the specified handler and
 *    interval.  The cyclic will run on a CPU which both has interrupts enabled
 *    and is in the system CPU partition.
 *
 *  Arguments and notes
 *
 *    As its first argument, cyclic_add() takes a cyc_handler, which has the
 *    following members:
 *
 *      cyc_func_t cyh_func    <-- Cyclic handler
 *      void *cyh_arg          <-- Argument to cyclic handler
 *      cyc_level_t cyh_level  <-- Level at which to fire; must be one of
 *                                 CY_LOW_LEVEL, CY_LOCK_LEVEL or CY_HIGH_LEVEL
 *
 *    Note that cyh_level is _not_ an ipl or spl; it must be one the
 *    CY_*_LEVELs.  This layer of abstraction allows the platform to define
 *    the precise interrupt priority levels, within the following constraints:
 *
 *       CY_LOCK_LEVEL must map to LOCK_LEVEL
 *       CY_HIGH_LEVEL must map to an ipl greater than LOCK_LEVEL
 *       CY_LOW_LEVEL must map to an ipl below LOCK_LEVEL
 *
 *    In addition to a cyc_handler, cyclic_add() takes a cyc_time, which
 *    has the following members:
 *
 *       hrtime_t cyt_when     <-- Absolute time, in nanoseconds since boot, at
 *                                 which to start firing
 *       hrtime_t cyt_interval <-- Length of interval, in nanoseconds
 *
 *    gethrtime() is the time source for nanoseconds since boot.  If cyt_when
 *    is set to 0, the cyclic will start to fire when cyt_interval next
 *    divides the number of nanoseconds since boot.
 *
 *    The cyt_interval field _must_ be filled in by the caller; one-shots are
 *    _not_ explicitly supported by the cyclic subsystem (cyclic_add() will
 *    assert that cyt_interval is non-zero).  The maximum value for either
 *    field is INT64_MAX; the caller is responsible for assuring that
 *    cyt_when + cyt_interval <= INT64_MAX.  Neither field may be negative.
 *
 *    For an arbitrary time t in the future, the cyclic handler is guaranteed
 *    to have been called (t - cyt_when) / cyt_interval times.  This will
 *    be true even if interrupts have been disabled for periods greater than
 *    cyt_interval nanoseconds.  In order to compensate for such periods,
 *    the cyclic handler may be called a finite number of times with an
 *    arbitrarily small interval.
 *
 *    The cyclic subsystem will not enforce any lower bound on the interval;
 *    if the interval is less than the time required to process an interrupt,
 *    the CPU will wedge.  It's the responsibility of the caller to assure that
 *    either the value of the interval is sane, or that its caller has
 *    sufficient privilege to deny service (i.e. its caller is root).
 *
 *    The cyclic handler is guaranteed to be single threaded, even while the
 *    cyclic is being juggled between CPUs (see cyclic_juggle(), below).
 *    That is, a given cyclic handler will never be executed simultaneously
 *    on different CPUs.
 *
 *  Return value
 *
 *    cyclic_add() returns a cyclic_id_t, which is guaranteed to be a value
 *    other than CYCLIC_NONE.  cyclic_add() cannot fail.
 *
 *  Caller's context
 *
 *    cpu_lock must be held by the caller, and the caller must not be in
 *    interrupt context.  cyclic_add() will perform a KM_SLEEP kernel
 *    memory allocation, so the usual rules (e.g. p_lock cannot be held)
 *    apply.  A cyclic may be added even in the presence of CPUs that have
 *    not been configured with respect to the cyclic subsystem, but only
 *    configured CPUs will be eligible to run the new cyclic.
 *
 *  Cyclic handler's context
 *
 *    Cyclic handlers will be executed in the interrupt context corresponding
 *    to the specified level (i.e. either high, lock or low level).  The
 *    usual context rules apply.
 *
 *    A cyclic handler may not grab ANY locks held by the caller of any of
 *    cyclic_add(), cyclic_remove() or cyclic_bind(); the implementation of
 *    these functions may require blocking on cyclic handler completion.
 *    Moreover, cyclic handlers may not make any call back into the cyclic
 *    subsystem.
 */
cyclic_id_t
cyclic_add(cyc_handler_t *hdlr, cyc_time_t *when)
{
	cyc_id_t *idp = cyclic_new_id();

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(when->cyt_when >= 0 && when->cyt_interval > 0);

	idp->cyi_cpu = cyclic_pick_cpu(NULL, NULL, NULL, 0);
	idp->cyi_ndx = cyclic_add_here(idp->cyi_cpu, hdlr, when, 0);

	return ((uintptr_t)idp);
}

/*
 *  cyclic_id_t cyclic_add_omni(cyc_omni_handler_t *)
 *
 *  Overview
 *
 *    cyclic_add_omni() will create an omnipresent cyclic with the specified
 *    online and offline handlers.  Omnipresent cyclics run on all online
 *    CPUs, including CPUs which have unbound interrupts disabled.
 *
 *  Arguments
 *
 *    As its only argument, cyclic_add_omni() takes a cyc_omni_handler, which
 *    has the following members:
 *
 *      void (*cyo_online)()   <-- Online handler
 *      void (*cyo_offline)()  <-- Offline handler
 *      void *cyo_arg          <-- Argument to be passed to on/offline handlers
 *
 *  Online handler
 *
 *    The cyo_online member is a pointer to a function which has the following
 *    four arguments:
 *
 *      void *                 <-- Argument (cyo_arg)
 *      cpu_t *                <-- Pointer to CPU about to be onlined
 *      cyc_handler_t *        <-- Pointer to cyc_handler_t; must be filled in
 *                                 by omni online handler
 *      cyc_time_t *           <-- Pointer to cyc_time_t; must be filled in by
 *                                 omni online handler
 *
 *    The omni cyclic online handler is always called _before_ the omni
 *    cyclic begins to fire on the specified CPU.  As the above argument
 *    description implies, the online handler must fill in the two structures
 *    passed to it:  the cyc_handler_t and the cyc_time_t.  These are the
 *    same two structures passed to cyclic_add(), outlined above.  This
 *    allows the omni cyclic to have maximum flexibility; different CPUs may
 *    optionally
 *
 *      (a)  have different intervals
 *      (b)  be explicitly in or out of phase with one another
 *      (c)  have different handlers
 *      (d)  have different handler arguments
 *      (e)  fire at different levels
 *
 *    Of these, (e) seems somewhat dubious, but is nonetheless allowed.
 *
 *    The omni online handler is called in the same context as cyclic_add(),
 *    and has the same liberties:  omni online handlers may perform KM_SLEEP
 *    kernel memory allocations, and may grab locks which are also acquired
 *    by cyclic handlers.  However, omni cyclic online handlers may _not_
 *    call back into the cyclic subsystem, and should be generally careful
 *    about calling into arbitrary kernel subsystems.
 *
 *  Offline handler
 *
 *    The cyo_offline member is a pointer to a function which has the following
 *    three arguments:
 *
 *      void *                 <-- Argument (cyo_arg)
 *      cpu_t *                <-- Pointer to CPU about to be offlined
 *      void *                 <-- CPU's cyclic argument (that is, value
 *                                 to which cyh_arg member of the cyc_handler_t
 *                                 was set in the omni online handler)
 *
 *    The omni cyclic offline handler is always called _after_ the omni
 *    cyclic has ceased firing on the specified CPU.  Its purpose is to
 *    allow cleanup of any resources dynamically allocated in the omni cyclic
 *    online handler.  The context of the offline handler is identical to
 *    that of the online handler; the same constraints and liberties apply.
 *
 *    The offline handler is optional; it may be NULL.
 *
 *  Return value
 *
 *    cyclic_add_omni() returns a cyclic_id_t, which is guaranteed to be a
 *    value other than CYCLIC_NONE.  cyclic_add_omni() cannot fail.
 *
 *  Caller's context
 *
 *    The caller's context is identical to that of cyclic_add(), specified
 *    above.
 */
cyclic_id_t
cyclic_add_omni(cyc_omni_handler_t *omni)
{
	cyc_id_t *idp = cyclic_new_id();
	cyc_cpu_t *cpu;
	cpu_t *c;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(omni != NULL && omni->cyo_online != NULL);

	idp->cyi_omni_hdlr = *omni;

	c = cpu_list;
	do {
		if ((cpu = c->cpu_cyclic) == NULL)
			continue;

		if (cpu->cyp_state != CYS_ONLINE) {
			ASSERT(cpu->cyp_state == CYS_OFFLINE);
			continue;
		}

		cyclic_omni_start(idp, cpu);
	} while ((c = c->cpu_next) != cpu_list);

	/*
	 * We must have found at least one online CPU on which to run
	 * this cyclic.
	 */
	ASSERT(idp->cyi_omni_list != NULL);
	ASSERT(idp->cyi_cpu == NULL);

	return ((uintptr_t)idp);
}

/*
 *  void cyclic_remove(cyclic_id_t)
 *
 *  Overview
 *
 *    cyclic_remove() will remove the specified cyclic from the system.
 *
 *  Arguments and notes
 *
 *    The only argument is a cyclic_id returned from either cyclic_add() or
 *    cyclic_add_omni().
 *
 *    By the time cyclic_remove() returns, the caller is guaranteed that the
 *    removed cyclic handler has completed execution (this is the same
 *    semantic that untimeout() provides).  As a result, cyclic_remove() may
 *    need to block, waiting for the removed cyclic to complete execution.
 *    This leads to an important constraint on the caller:  no lock may be
 *    held across cyclic_remove() that also may be acquired by a cyclic
 *    handler.
 *
 *  Return value
 *
 *    None; cyclic_remove() always succeeds.
 *
 *  Caller's context
 *
 *    cpu_lock must be held by the caller, and the caller must not be in
 *    interrupt context.  The caller may not hold any locks which are also
 *    grabbed by any cyclic handler.  See "Arguments and notes", above.
 */
void
cyclic_remove(cyclic_id_t id)
{
	cyc_id_t *idp = (cyc_id_t *)id;
	cyc_id_t *prev = idp->cyi_prev, *next = idp->cyi_next;
	cyc_cpu_t *cpu = idp->cyi_cpu;

	CYC_PTRACE("remove", idp, idp->cyi_cpu);
	ASSERT(MUTEX_HELD(&cpu_lock));

	if (cpu != NULL) {
		(void) cyclic_remove_here(cpu, idp->cyi_ndx, NULL, CY_WAIT);
	} else {
		ASSERT(idp->cyi_omni_list != NULL);
		while (idp->cyi_omni_list != NULL)
			cyclic_omni_stop(idp, idp->cyi_omni_list->cyo_cpu);
	}

	if (prev != NULL) {
		ASSERT(cyclic_id_head != idp);
		prev->cyi_next = next;
	} else {
		ASSERT(cyclic_id_head == idp);
		cyclic_id_head = next;
	}

	if (next != NULL)
		next->cyi_prev = prev;

	kmem_cache_free(cyclic_id_cache, idp);
}

/*
 *  void cyclic_bind(cyclic_id_t, cpu_t *, cpupart_t *)
 *
 *  Overview
 *
 *    cyclic_bind() atomically changes the CPU and CPU partition bindings
 *    of a cyclic.
 *
 *  Arguments and notes
 *
 *    The first argument is a cyclic_id retuned from cyclic_add().
 *    cyclic_bind() may _not_ be called on a cyclic_id returned from
 *    cyclic_add_omni().
 *
 *    The second argument specifies the CPU to which to bind the specified
 *    cyclic.  If the specified cyclic is bound to a CPU other than the one
 *    specified, it will be unbound from its bound CPU.  Unbinding the cyclic
 *    from its CPU may cause it to be juggled to another CPU.  If the specified
 *    CPU is non-NULL, the cyclic will be subsequently rebound to the specified
 *    CPU.
 *
 *    If a CPU with bound cyclics is transitioned into the P_NOINTR state,
 *    only cyclics not bound to the CPU can be juggled away; CPU-bound cyclics
 *    will continue to fire on the P_NOINTR CPU.  A CPU with bound cyclics
 *    cannot be offlined (attempts to offline the CPU will return EBUSY).
 *    Likewise, cyclics may not be bound to an offline CPU; if the caller
 *    attempts to bind a cyclic to an offline CPU, the cyclic subsystem will
 *    panic.
 *
 *    The third argument specifies the CPU partition to which to bind the
 *    specified cyclic.  If the specified cyclic is bound to a CPU partition
 *    other than the one specified, it will be unbound from its bound
 *    partition.  Unbinding the cyclic from its CPU partition may cause it
 *    to be juggled to another CPU.  If the specified CPU partition is
 *    non-NULL, the cyclic will be subsequently rebound to the specified CPU
 *    partition.
 *
 *    It is the caller's responsibility to assure that the specified CPU
 *    partition contains a CPU.  If it does not, the cyclic subsystem will
 *    panic.  A CPU partition with bound cyclics cannot be destroyed (attempts
 *    to destroy the partition will return EBUSY).  If a CPU with
 *    partition-bound cyclics is transitioned into the P_NOINTR state, cyclics
 *    bound to the CPU's partition (but not bound to the CPU) will be juggled
 *    away only if there exists another CPU in the partition in the P_ONLINE
 *    state.
 *
 *    It is the caller's responsibility to assure that the specified CPU and
 *    CPU partition are self-consistent.  If both parameters are non-NULL,
 *    and the specified CPU partition does not contain the specified CPU, the
 *    cyclic subsystem will panic.
 *
 *    It is the caller's responsibility to assure that the specified CPU has
 *    been configured with respect to the cyclic subsystem.  Generally, this
 *    is always true for valid, on-line CPUs.  The only periods of time during
 *    which this may not be true are during MP boot (i.e. after cyclic_init()
 *    is called but before cyclic_mp_init() is called) or during dynamic
 *    reconfiguration; cyclic_bind() should only be called with great care
 *    from these contexts.
 *
 *  Return value
 *
 *    None; cyclic_bind() always succeeds.
 *
 *  Caller's context
 *
 *    cpu_lock must be held by the caller, and the caller must not be in
 *    interrupt context.  The caller may not hold any locks which are also
 *    grabbed by any cyclic handler.
 */
void
cyclic_bind(cyclic_id_t id, cpu_t *d, cpupart_t *part)
{
	cyc_id_t *idp = (cyc_id_t *)id;
	cyc_cpu_t *cpu = idp->cyi_cpu;
	cpu_t *c;
	uint16_t flags;

	CYC_PTRACE("bind", d, part);
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(part == NULL || d == NULL || d->cpu_part == part);

	if (cpu == NULL) {
		ASSERT(idp->cyi_omni_list != NULL);
		panic("attempt to change binding of omnipresent cyclic");
	}

	c = cpu->cyp_cpu;
	flags = cpu->cyp_cyclics[idp->cyi_ndx].cy_flags;

	if (c != d && (flags & CYF_CPU_BOUND))
		cyclic_unbind_cpu(id);

	/*
	 * Reload our cpu (we may have migrated).  We don't have to reload
	 * the flags field here; if we were CYF_PART_BOUND on entry, we are
	 * CYF_PART_BOUND now.
	 */
	cpu = idp->cyi_cpu;
	c = cpu->cyp_cpu;

	if (part != c->cpu_part && (flags & CYF_PART_BOUND))
		cyclic_unbind_cpupart(id);

	/*
	 * Now reload the flags field, asserting that if we are CPU bound,
	 * the CPU was specified (and likewise, if we are partition bound,
	 * the partition was specified).
	 */
	cpu = idp->cyi_cpu;
	c = cpu->cyp_cpu;
	flags = cpu->cyp_cyclics[idp->cyi_ndx].cy_flags;
	ASSERT(!(flags & CYF_CPU_BOUND) || c == d);
	ASSERT(!(flags & CYF_PART_BOUND) || c->cpu_part == part);

	if (!(flags & CYF_CPU_BOUND) && d != NULL)
		cyclic_bind_cpu(id, d);

	if (!(flags & CYF_PART_BOUND) && part != NULL)
		cyclic_bind_cpupart(id, part);
}

int
cyclic_reprogram(cyclic_id_t id, hrtime_t expiration)
{
	cyc_id_t *idp = (cyc_id_t *)id;
	cyc_cpu_t *cpu;
	cyc_omni_cpu_t *ocpu;
	cyc_index_t ndx;

	ASSERT(expiration > 0);

	CYC_PTRACE("reprog", idp, idp->cyi_cpu);

	kpreempt_disable();

	/*
	 * Prevent the cyclic from moving or disappearing while we reprogram.
	 */
	rw_enter(&idp->cyi_lock, RW_READER);

	if (idp->cyi_cpu == NULL) {
		ASSERT(curthread->t_preempt > 0);
		cpu = CPU->cpu_cyclic;

		/*
		 * For an omni cyclic, we reprogram the cyclic corresponding
		 * to the current CPU. Look for it in the list.
		 */
		ocpu = idp->cyi_omni_list;
		while (ocpu != NULL) {
			if (ocpu->cyo_cpu == cpu)
				break;
			ocpu = ocpu->cyo_next;
		}

		if (ocpu == NULL) {
			/*
			 * Didn't find it. This means that CPU offline
			 * must have removed it racing with us. So,
			 * nothing to do.
			 */
			rw_exit(&idp->cyi_lock);

			kpreempt_enable();

			return (0);
		}
		ndx = ocpu->cyo_ndx;
	} else {
		cpu = idp->cyi_cpu;
		ndx = idp->cyi_ndx;
	}

	if (cpu->cyp_cpu == CPU)
		cyclic_reprogram_cyclic(cpu, ndx, expiration);
	else
		cyclic_reprogram_here(cpu, ndx, expiration);

	/*
	 * Allow the cyclic to be moved or removed.
	 */
	rw_exit(&idp->cyi_lock);

	kpreempt_enable();

	return (1);
}

hrtime_t
cyclic_getres()
{
	return (cyclic_resolution);
}

void
cyclic_init(cyc_backend_t *be, hrtime_t resolution)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	CYC_PTRACE("init", be, resolution);
	cyclic_resolution = resolution;

	/*
	 * Copy the passed cyc_backend into the backend template.  This must
	 * be done before the CPU can be configured.
	 */
	bcopy(be, &cyclic_backend, sizeof (cyc_backend_t));

	/*
	 * It's safe to look at the "CPU" pointer without disabling kernel
	 * preemption; cyclic_init() is called only during startup by the
	 * cyclic backend.
	 */
	cyclic_configure(CPU);
	cyclic_online(CPU);
}

/*
 * It is assumed that cyclic_mp_init() is called some time after cyclic
 * init (and therefore, after cpu0 has been initialized).  We grab cpu_lock,
 * find the already initialized CPU, and initialize every other CPU with the
 * same backend.  Finally, we register a cpu_setup function.
 */
void
cyclic_mp_init()
{
	cpu_t *c;

	mutex_enter(&cpu_lock);

	c = cpu_list;
	do {
		if (c->cpu_cyclic == NULL) {
			cyclic_configure(c);
			cyclic_online(c);
		}
	} while ((c = c->cpu_next) != cpu_list);

	register_cpu_setup_func((cpu_setup_func_t *)cyclic_cpu_setup, NULL);
	mutex_exit(&cpu_lock);
}

/*
 *  int cyclic_juggle(cpu_t *)
 *
 *  Overview
 *
 *    cyclic_juggle() juggles as many cyclics as possible away from the
 *    specified CPU; all remaining cyclics on the CPU will either be CPU-
 *    or partition-bound.
 *
 *  Arguments and notes
 *
 *    The only argument to cyclic_juggle() is the CPU from which cyclics
 *    should be juggled.  CPU-bound cyclics are never juggled; partition-bound
 *    cyclics are only juggled if the specified CPU is in the P_NOINTR state
 *    and there exists a P_ONLINE CPU in the partition.  The cyclic subsystem
 *    assures that a cyclic will never fire late or spuriously, even while
 *    being juggled.
 *
 *  Return value
 *
 *    cyclic_juggle() returns a non-zero value if all cyclics were able to
 *    be juggled away from the CPU, and zero if one or more cyclics could
 *    not be juggled away.
 *
 *  Caller's context
 *
 *    cpu_lock must be held by the caller, and the caller must not be in
 *    interrupt context.  The caller may not hold any locks which are also
 *    grabbed by any cyclic handler.  While cyclic_juggle() _may_ be called
 *    in any context satisfying these constraints, it _must_ be called
 *    immediately after clearing CPU_ENABLE (i.e. before dropping cpu_lock).
 *    Failure to do so could result in an assertion failure in the cyclic
 *    subsystem.
 */
int
cyclic_juggle(cpu_t *c)
{
	cyc_cpu_t *cpu = c->cpu_cyclic;
	cyc_id_t *idp;
	int all_juggled = 1;

	CYC_PTRACE1("juggle", c);
	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * We'll go through each cyclic on the CPU, attempting to juggle
	 * each one elsewhere.
	 */
	for (idp = cyclic_id_head; idp != NULL; idp = idp->cyi_next) {
		if (idp->cyi_cpu != cpu)
			continue;

		if (cyclic_juggle_one(idp) == 0) {
			all_juggled = 0;
			continue;
		}

		ASSERT(idp->cyi_cpu != cpu);
	}

	return (all_juggled);
}

/*
 *  int cyclic_offline(cpu_t *)
 *
 *  Overview
 *
 *    cyclic_offline() offlines the cyclic subsystem on the specified CPU.
 *
 *  Arguments and notes
 *
 *    The only argument to cyclic_offline() is a CPU to offline.
 *    cyclic_offline() will attempt to juggle cyclics away from the specified
 *    CPU.
 *
 *  Return value
 *
 *    cyclic_offline() returns 1 if all cyclics on the CPU were juggled away
 *    and the cyclic subsystem on the CPU was successfully offlines.
 *    cyclic_offline returns 0 if some cyclics remain, blocking the cyclic
 *    offline operation.  All remaining cyclics on the CPU will either be
 *    CPU- or partition-bound.
 *
 *    See the "Arguments and notes" of cyclic_juggle(), below, for more detail
 *    on cyclic juggling.
 *
 *  Caller's context
 *
 *    The only caller of cyclic_offline() should be the processor management
 *    subsystem.  It is expected that the caller of cyclic_offline() will
 *    offline the CPU immediately after cyclic_offline() returns success (i.e.
 *    before dropping cpu_lock).  Moreover, it is expected that the caller will
 *    fail the CPU offline operation if cyclic_offline() returns failure.
 */
int
cyclic_offline(cpu_t *c)
{
	cyc_cpu_t *cpu = c->cpu_cyclic;
	cyc_id_t *idp;

	CYC_PTRACE1("offline", cpu);
	ASSERT(MUTEX_HELD(&cpu_lock));

	if (!cyclic_juggle(c))
		return (0);

	/*
	 * This CPU is headed offline; we need to now stop omnipresent
	 * cyclic firing on this CPU.
	 */
	for (idp = cyclic_id_head; idp != NULL; idp = idp->cyi_next) {
		if (idp->cyi_cpu != NULL)
			continue;

		/*
		 * We cannot possibly be offlining the last CPU; cyi_omni_list
		 * must be non-NULL.
		 */
		ASSERT(idp->cyi_omni_list != NULL);
		cyclic_omni_stop(idp, cpu);
	}

	ASSERT(cpu->cyp_state == CYS_ONLINE);
	cpu->cyp_state = CYS_OFFLINE;

	return (1);
}

/*
 *  void cyclic_online(cpu_t *)
 *
 *  Overview
 *
 *    cyclic_online() onlines a CPU previously offlined with cyclic_offline().
 *
 *  Arguments and notes
 *
 *    cyclic_online()'s only argument is a CPU to online.  The specified
 *    CPU must have been previously offlined with cyclic_offline().  After
 *    cyclic_online() returns, the specified CPU will be eligible to execute
 *    cyclics.
 *
 *  Return value
 *
 *    None; cyclic_online() always succeeds.
 *
 *  Caller's context
 *
 *    cyclic_online() should only be called by the processor management
 *    subsystem; cpu_lock must be held.
 */
void
cyclic_online(cpu_t *c)
{
	cyc_cpu_t *cpu = c->cpu_cyclic;
	cyc_id_t *idp;

	CYC_PTRACE1("online", cpu);
	ASSERT(c->cpu_flags & CPU_ENABLE);
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu->cyp_state == CYS_OFFLINE);

	cpu->cyp_state = CYS_ONLINE;

	/*
	 * Now that this CPU is open for business, we need to start firing
	 * all omnipresent cyclics on it.
	 */
	for (idp = cyclic_id_head; idp != NULL; idp = idp->cyi_next) {
		if (idp->cyi_cpu != NULL)
			continue;

		cyclic_omni_start(idp, cpu);
	}
}

/*
 *  void cyclic_move_in(cpu_t *)
 *
 *  Overview
 *
 *    cyclic_move_in() is called by the CPU partition code immediately after
 *    the specified CPU has moved into a new partition.
 *
 *  Arguments and notes
 *
 *    The only argument to cyclic_move_in() is a CPU which has moved into a
 *    new partition.  If the specified CPU is P_ONLINE, and every other
 *    CPU in the specified CPU's new partition is P_NOINTR, cyclic_move_in()
 *    will juggle all partition-bound, CPU-unbound cyclics to the specified
 *    CPU.
 *
 *  Return value
 *
 *    None; cyclic_move_in() always succeeds.
 *
 *  Caller's context
 *
 *    cyclic_move_in() should _only_ be called immediately after a CPU has
 *    moved into a new partition, with cpu_lock held.  As with other calls
 *    into the cyclic subsystem, no lock may be held which is also grabbed
 *    by any cyclic handler.
 */
void
cyclic_move_in(cpu_t *d)
{
	cyc_id_t *idp;
	cyc_cpu_t *dest = d->cpu_cyclic;
	cyclic_t *cyclic;
	cpupart_t *part = d->cpu_part;

	CYC_PTRACE("move-in", dest, part);
	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Look for CYF_PART_BOUND cyclics in the new partition.  If
	 * we find one, check to see if it is currently on a CPU which has
	 * interrupts disabled.  If it is (and if this CPU currently has
	 * interrupts enabled), we'll juggle those cyclics over here.
	 */
	if (!(d->cpu_flags & CPU_ENABLE)) {
		CYC_PTRACE1("move-in-none", dest);
		return;
	}

	for (idp = cyclic_id_head; idp != NULL; idp = idp->cyi_next) {
		cyc_cpu_t *cpu = idp->cyi_cpu;
		cpu_t *c;

		/*
		 * Omnipresent cyclics are exempt from juggling.
		 */
		if (cpu == NULL)
			continue;

		c = cpu->cyp_cpu;

		if (c->cpu_part != part || (c->cpu_flags & CPU_ENABLE))
			continue;

		cyclic = &cpu->cyp_cyclics[idp->cyi_ndx];

		if (cyclic->cy_flags & CYF_CPU_BOUND)
			continue;

		/*
		 * We know that this cyclic is bound to its processor set
		 * (otherwise, it would not be on a CPU with interrupts
		 * disabled); juggle it to our CPU.
		 */
		ASSERT(cyclic->cy_flags & CYF_PART_BOUND);
		cyclic_juggle_one_to(idp, dest);
	}

	CYC_PTRACE1("move-in-done", dest);
}

/*
 *  int cyclic_move_out(cpu_t *)
 *
 *  Overview
 *
 *    cyclic_move_out() is called by the CPU partition code immediately before
 *    the specified CPU is to move out of its partition.
 *
 *  Arguments and notes
 *
 *    The only argument to cyclic_move_out() is a CPU which is to move out of
 *    its partition.
 *
 *    cyclic_move_out() will attempt to juggle away all partition-bound
 *    cyclics.  If the specified CPU is the last CPU in a partition with
 *    partition-bound cyclics, cyclic_move_out() will fail.  If there exists
 *    a partition-bound cyclic which is CPU-bound to the specified CPU,
 *    cyclic_move_out() will fail.
 *
 *    Note that cyclic_move_out() will _only_ attempt to juggle away
 *    partition-bound cyclics; CPU-bound cyclics which are not partition-bound
 *    and unbound cyclics are not affected by changing the partition
 *    affiliation of the CPU.
 *
 *  Return value
 *
 *    cyclic_move_out() returns 1 if all partition-bound cyclics on the CPU
 *    were juggled away; 0 if some cyclics remain.
 *
 *  Caller's context
 *
 *    cyclic_move_out() should _only_ be called immediately before a CPU has
 *    moved out of its partition, with cpu_lock held.  It is expected that
 *    the caller of cyclic_move_out() will change the processor set affiliation
 *    of the specified CPU immediately after cyclic_move_out() returns
 *    success (i.e. before dropping cpu_lock).  Moreover, it is expected that
 *    the caller will fail the CPU repartitioning operation if cyclic_move_out()
 *    returns failure.  As with other calls into the cyclic subsystem, no lock
 *    may be held which is also grabbed by any cyclic handler.
 */
int
cyclic_move_out(cpu_t *c)
{
	cyc_id_t *idp;
	cyc_cpu_t *cpu = c->cpu_cyclic, *dest;
	cyclic_t *cyclic, *cyclics = cpu->cyp_cyclics;
	cpupart_t *part = c->cpu_part;

	CYC_PTRACE1("move-out", cpu);
	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * If there are any CYF_PART_BOUND cyclics on this CPU, we need
	 * to try to juggle them away.
	 */
	for (idp = cyclic_id_head; idp != NULL; idp = idp->cyi_next) {

		if (idp->cyi_cpu != cpu)
			continue;

		cyclic = &cyclics[idp->cyi_ndx];

		if (!(cyclic->cy_flags & CYF_PART_BOUND))
			continue;

		dest = cyclic_pick_cpu(part, c, c, cyclic->cy_flags);

		if (dest == NULL) {
			/*
			 * We can't juggle this cyclic; we need to return
			 * failure (we won't bother trying to juggle away
			 * other cyclics).
			 */
			CYC_PTRACE("move-out-fail", cpu, idp);
			return (0);
		}
		cyclic_juggle_one_to(idp, dest);
	}

	CYC_PTRACE1("move-out-done", cpu);
	return (1);
}

/*
 *  void cyclic_suspend()
 *
 *  Overview
 *
 *    cyclic_suspend() suspends all cyclic activity throughout the cyclic
 *    subsystem.  It should be called only by subsystems which are attempting
 *    to suspend the entire system (e.g. checkpoint/resume, dynamic
 *    reconfiguration).
 *
 *  Arguments and notes
 *
 *    cyclic_suspend() takes no arguments.  Each CPU with an active cyclic
 *    disables its backend (offline CPUs disable their backends as part of
 *    the cyclic_offline() operation), thereby disabling future CY_HIGH_LEVEL
 *    interrupts.
 *
 *    Note that disabling CY_HIGH_LEVEL interrupts does not completely preclude
 *    cyclic handlers from being called after cyclic_suspend() returns:  if a
 *    CY_LOCK_LEVEL or CY_LOW_LEVEL interrupt thread was blocked at the time
 *    of cyclic_suspend(), cyclic handlers at its level may continue to be
 *    called after the interrupt thread becomes unblocked.  The
 *    post-cyclic_suspend() activity is bounded by the pend count on all
 *    cyclics at the time of cyclic_suspend().  Callers concerned with more
 *    than simply disabling future CY_HIGH_LEVEL interrupts must check for
 *    this condition.
 *
 *    On most platforms, timestamps from gethrtime() and gethrestime() are not
 *    guaranteed to monotonically increase between cyclic_suspend() and
 *    cyclic_resume().  However, timestamps are guaranteed to monotonically
 *    increase across the entire cyclic_suspend()/cyclic_resume() operation.
 *    That is, every timestamp obtained before cyclic_suspend() will be less
 *    than every timestamp obtained after cyclic_resume().
 *
 *  Return value
 *
 *    None; cyclic_suspend() always succeeds.
 *
 *  Caller's context
 *
 *    The cyclic subsystem must be configured on every valid CPU;
 *    cyclic_suspend() may not be called during boot or during dynamic
 *    reconfiguration.  Additionally, cpu_lock must be held, and the caller
 *    cannot be in high-level interrupt context.  However, unlike most other
 *    cyclic entry points, cyclic_suspend() may be called with locks held
 *    which are also acquired by CY_LOCK_LEVEL or CY_LOW_LEVEL cyclic
 *    handlers.
 */
void
cyclic_suspend()
{
	cpu_t *c;
	cyc_cpu_t *cpu;
	cyc_xcallarg_t arg;
	cyc_backend_t *be;

	CYC_PTRACE0("suspend");
	ASSERT(MUTEX_HELD(&cpu_lock));
	c = cpu_list;

	do {
		cpu = c->cpu_cyclic;
		be = cpu->cyp_backend;
		arg.cyx_cpu = cpu;

		be->cyb_xcall(be->cyb_arg, c,
		    (cyc_func_t)cyclic_suspend_xcall, &arg);
	} while ((c = c->cpu_next) != cpu_list);
}

/*
 *  void cyclic_resume()
 *
 *    cyclic_resume() resumes all cyclic activity throughout the cyclic
 *    subsystem.  It should be called only by system-suspending subsystems.
 *
 *  Arguments and notes
 *
 *    cyclic_resume() takes no arguments.  Each CPU with an active cyclic
 *    reenables and reprograms its backend (offline CPUs are not reenabled).
 *    On most platforms, timestamps from gethrtime() and gethrestime() are not
 *    guaranteed to monotonically increase between cyclic_suspend() and
 *    cyclic_resume().  However, timestamps are guaranteed to monotonically
 *    increase across the entire cyclic_suspend()/cyclic_resume() operation.
 *    That is, every timestamp obtained before cyclic_suspend() will be less
 *    than every timestamp obtained after cyclic_resume().
 *
 *  Return value
 *
 *    None; cyclic_resume() always succeeds.
 *
 *  Caller's context
 *
 *    The cyclic subsystem must be configured on every valid CPU;
 *    cyclic_resume() may not be called during boot or during dynamic
 *    reconfiguration.  Additionally, cpu_lock must be held, and the caller
 *    cannot be in high-level interrupt context.  However, unlike most other
 *    cyclic entry points, cyclic_resume() may be called with locks held which
 *    are also acquired by CY_LOCK_LEVEL or CY_LOW_LEVEL cyclic handlers.
 */
void
cyclic_resume()
{
	cpu_t *c;
	cyc_cpu_t *cpu;
	cyc_xcallarg_t arg;
	cyc_backend_t *be;

	CYC_PTRACE0("resume");
	ASSERT(MUTEX_HELD(&cpu_lock));

	c = cpu_list;

	do {
		cpu = c->cpu_cyclic;
		be = cpu->cyp_backend;
		arg.cyx_cpu = cpu;

		be->cyb_xcall(be->cyb_arg, c,
		    (cyc_func_t)cyclic_resume_xcall, &arg);
	} while ((c = c->cpu_next) != cpu_list);
}
