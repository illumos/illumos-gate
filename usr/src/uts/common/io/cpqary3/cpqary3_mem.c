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
 * Copyright (C) 2013 Hewlett-Packard Development Company, L.P.
 */

#include <sys/sdt.h>
#include "cpqary3.h"

/*
 * Local Functions Definitions
 */
uint8_t	cleanstatus = 0;

/*
 * The Driver DMA Limit structure.
 */
static ddi_dma_attr_t cpqary3_ctlr_dma_attr = {
	DMA_ATTR_V0,	/* ddi_dma_attr version */
	0,		/* low address */
	0xFFFFFFFF,	/* high address */
	0x00FFFFFF,	/* Max DMA Counter register */
	0x20,		/* Byte Alignment */
	0x20,		/* burst sizes */
	DMA_UNIT_8,	/* minimum DMA xfer Size */
	0xFFFFFFFF,	/* maximum DMA xfer Size */
	0x0000FFFF, 	/* segment boundary restrictions */
	1,		/* scatter/gather list length */
	512,		/* device granularity */
	0		/* DMA flags */
};

/*
 * Driver device access attr struct
 */
extern ddi_device_acc_attr_t	cpqary3_dev_attributes;

/*
 * Function	:	cpqary3_meminit
 * Description	:	This routine initialises memory for the command list.
 *			Allocation of Physical contigous blocks and maintenance
 * 			of lists to these.
 * Called By	:	cpqary3_init_ctlr_resource()
 * Parameters	:	per_controller
 * Calls	:	cpqary3_alloc_phyctgs_mem, cpqary3_memfini
 * Return Values:	SUCCESS / FAILURE
 *			[If the required initialization and setup of memory
 *			is successful, send back a success. Else, failure]
 */
int16_t
cpqary3_meminit(cpqary3_t *cpqary3p)
{
	size_t			mempool_size;
	caddr_t			mempool_addr;
	uint16_t		i = 0;
	uint32_t		mem_size = 0;
	uint32_t		no_cmds	= 0;
	uint32_t		cntr;
	uint32_t		maxmemcnt;
	uint32_t		phyaddr;
	uint32_t		temp_phyaddr;
	uint32_t		size_of_cmdlist	= 0;
	uint32_t		size_of_HRE = 0; /* Header + Request + Error */
	uint32_t		unused_mem = 0;
	uint32_t		mempoolnum;
	uint32_t		CmdsOutMax;
	CommandList_t		*cmdlist_memaddr;
	cpqary3_phyctg_t	*cpqary3_phyctgp;
	cpqary3_cmdpvt_t	*ptr;
	cpqary3_cmdpvt_t	*head_pvtp;
	cpqary3_cmdpvt_t	*tail_pvtp;
	cpqary3_cmdmemlist_t	*memlistp = NULL;
	cpqary3_phys_hdl_addr_t	*blk_ptr = NULL;

	RETURN_FAILURE_IF_NULL(cpqary3p);

	CmdsOutMax = cpqary3p->ctlr_maxcmds;


	/*
	 * Allocate memory for the Structure to hold details about the
	 * Command Memory Pool.
	 * Update per_controller pointer to this.
	 */

	cpqary3p->cmdmemlistp = memlistp =
	    MEM_ZALLOC(sizeof (cpqary3_cmdmemlist_t));

	if (!cpqary3p->cmdmemlistp) {
		cmn_err(CE_NOTE, "CPQary3: Memory Initialization: "
		    "Low Kernel Memory");
		return (CPQARY3_FAILURE);
	}
	cleanstatus |= CPQARY3_MEMLIST_DONE; /* For cleaning purpose. */

	/*
	 * Allocate a Virtual Memory Pool of size
	 * NO_OF_CMDLIST_BLKS * NO_OF_CMDLIST_IN_A_BLK * sizeof (cmdmem_pvt_t)
	 * to store details of the above allocated Memory for
	 * NO_OF_CMDLIST_BLKS * NO_OF_CMDLIST_IN_A_BLK Commands
	 * Initialize this memory to act as a linked list to parse
	 * thru the entire list
	 * Initialize the Memory Mutex
	 */
	no_cmds  = (uint32_t)((CmdsOutMax / 3) * NO_OF_CMDLIST_IN_A_BLK);
	mem_size = (uint32_t)(no_cmds * sizeof (cpqary3_cmdpvt_t));

	head_pvtp = ptr = (cpqary3_cmdpvt_t *)(MEM_ZALLOC(mem_size));
	if (NULL == head_pvtp) {
		MEM_SFREE(cpqary3p->cmdmemlistp, sizeof (cpqary3_cmdmemlist_t));
		cpqary3p->cmdmemlistp = NULL;
		cleanstatus &= ~CPQARY3_MEMLIST_DONE; /* For cleaning. */
		cmn_err(CE_NOTE, "CPQary3: Memory Initialization: "
		    "Low Kernel Memory");
		return (CPQARY3_FAILURE);
	}

	tail_pvtp = &ptr[no_cmds - 1];
	cleanstatus |= CPQARY3_CMDMEM_DONE; /* For cleaning purpose. */

	DTRACE_PROBE4(cmd_init_start, uint32_t, no_cmds, uint32_t, mem_size,
	    cpqary3_cmdpvt_t *, head_pvtp, cpqary3_cmdpvt_t *, tail_pvtp);

	for (i = 0; i < no_cmds; i++) {
		ptr = &head_pvtp[i];
		ptr->occupied = CPQARY3_FREE;
		ptr->tag.tag_value = i;
		ptr->cmdlist_phyaddr = 0;
		ptr->cmdlist_erraddr = 0;
		ptr->cmdpvt_flag = 0;
		ptr->cmdlist_memaddr = (CommandList_t *)NULL;
		ptr->errorinfop = (ErrorInfo_t *)NULL;
		ptr->next = (cpqary3_cmdpvt_t *)((i == (no_cmds - 1)) ?
		    NULL : &head_pvtp[i+1]);
		ptr->prev = (cpqary3_cmdpvt_t *)((i == 0) ?
		    NULL : &head_pvtp[i-1]);
		ptr->ctlr = cpqary3p;
		ptr->pvt_pkt = (cpqary3_pkt_t *)NULL;
		ptr->sprev = (cpqary3_cmdpvt_t *)NULL;
		ptr->snext = (cpqary3_cmdpvt_t *)NULL;
	}
	cpqary3p->cmdmemlistp->head = head_pvtp; /* head Command Memory List */
	cpqary3p->cmdmemlistp->tail = tail_pvtp; /* tail Command Memory List */
	cpqary3p->cmdmemlistp->pool = head_pvtp; /* head Command Memory List */
	cpqary3p->cmdmemlistp->max_memcnt = 0; /* Maximum commands for ctlr */

	ptr = head_pvtp;

	DTRACE_PROBE(memlist_init_done);

	/*
	 * We require the size of the commandlist and the combined
	 * size of the Command Header, Request Block and the Error Desriptor
	 * In CPQary3, it is 564 and 52 respectively.
	 */
	size_of_cmdlist = sizeof (CommandList_t);
	size_of_HRE = size_of_cmdlist -
	    (sizeof (SGDescriptor_t) * CISS_MAXSGENTRIES);

	/*
	 * uint32_t alignment of cmdlist
	 * In CPQary3, after alignment, the size of each commandlist is 576
	 */
	if (size_of_cmdlist & 0x1F)
		size_of_cmdlist = ((size_of_cmdlist + 31) / 32) * 32;

	/*
	 * The CmdsOutMax member in the Configuration Table states the maximum
	 * outstanding commands supported by this controller.
	 * The following code allocates memory in blocks; each block holds
	 * 3 commands.
	 */

	for (mempoolnum = 0; mempoolnum < ((CmdsOutMax / 3)); mempoolnum++) {
		/* Allocate Memory for handle to maintain the Cmd Lists */
		cpqary3_phyctgp = (cpqary3_phyctg_t *)
		    MEM_ZALLOC(sizeof (cpqary3_phyctg_t));
		if (!cpqary3_phyctgp) {
			cpqary3_memfini(cpqary3p, cleanstatus);
			cmn_err(CE_NOTE, "CPQary3: Mem Initialization: "
			    "Low Kernel Memory");
			return (CPQARY3_FAILURE);
		}

		/*
		 * Get the Physically Contiguous Memory
		 * Allocate 32 extra bytes of memory such as to get atleast
		 * 2 Command Blocks from every allocation even if we add any
		 * extra bytes after the initial allocation to make it 32 bit
		 * aligned.
		 */
		if (mempoolnum == 0) {	/* Head of Memory Blocks' Linked List */
			memlistp->cpqary3_phyctgp = blk_ptr =
			    (cpqary3_phys_hdl_addr_t *)
			    MEM_ZALLOC(sizeof (cpqary3_phys_hdl_addr_t));
			blk_ptr->blk_addr = cpqary3_phyctgp;
			blk_ptr->next = NULL;
		} else {
			blk_ptr->next = (cpqary3_phys_hdl_addr_t *)
			    MEM_ZALLOC(sizeof (cpqary3_phys_hdl_addr_t));
			blk_ptr = blk_ptr->next;
			blk_ptr->blk_addr = cpqary3_phyctgp;
			blk_ptr->next = NULL;
		}

		phyaddr = 0;
		mempool_size = (size_of_cmdlist * NO_OF_CMDLIST_IN_A_BLK) + 32;
		mempool_addr = cpqary3_alloc_phyctgs_mem(cpqary3p,
		    mempool_size, &phyaddr, cpqary3_phyctgp);

		if (!mempool_addr) {
			if (!mempoolnum) { /* Failue in the first attempt */
				MEM_SFREE(blk_ptr,
				    sizeof (cpqary3_phys_hdl_addr_t));
				memlistp->cpqary3_phyctgp = NULL;
				cmn_err(CE_WARN, "CPQary3 : Memory "
				    "Initialization : Low Kernel Memory");
				return (CPQARY3_FAILURE);
			}

			/*
			 * Some memory allocation  has already been suucessful.
			 * The driver shall continue its initialization and
			 * working with whatever memory has been allocated.
			 *
			 * Free the latest virtual memory allocated.
			 * NULLify the last node created to maintain the memory
			 * block list.
			 * Terminate the Memory Q here by marking the Tail.
			 */
			blk_ptr->blk_addr = NULL;
			ptr--;
			ptr->next = NULL;
			memlistp->tail = ptr;
			return (CPQARY3_SUCCESS);
		}
		cleanstatus |= CPQARY3_PHYCTGS_DONE;

		bzero(mempool_addr, cpqary3_phyctgp->real_size);

		/*
		 * The 32 bit alignment is stated in the attribute structure.
		 * In case, it is not aligned as per requirement, we align it.
		 * uint32_t alignment of the first CMDLIST in the memory list
		 */
		temp_phyaddr = phyaddr;
		if (phyaddr & 0x1F) {
			phyaddr = (uint32_t)(((phyaddr + 31) / 32) * 32);
			unused_mem = (uint32_t)(phyaddr - temp_phyaddr);
		}

		/*
		 * If the memory allocated is not 32 byte aligned then unused
		 * will give the total no of bytes that must remain unused to
		 * make it 32 byte aligned memory
		 */
		mempool_addr = (char *)((char *)mempool_addr + unused_mem);

		/*
		 * Update Counter for no. of Command Blocks.
		 */
		maxmemcnt = 0;
		maxmemcnt = ((uint32_t)
		    (cpqary3_phyctgp->real_size - (uint32_t)unused_mem)) /
		    size_of_cmdlist;
		memlistp->max_memcnt = memlistp->max_memcnt + maxmemcnt;

		/*
		 * Get the base of mempool which is 32 Byte aligned
		 * Initialize each Command Block with its corresponding
		 * Physical Address, Virtual address and the Physical Addres
		 * of the Error Info Descriptor
		 */
		cmdlist_memaddr = (CommandList_t *)mempool_addr;

		for (cntr = 0; cntr < maxmemcnt; cntr++) {
			ptr->cmdlist_phyaddr = phyaddr;
			ptr->cmdlist_memaddr = cmdlist_memaddr;
			ptr->cmdlist_erraddr = phyaddr + size_of_HRE;
			ptr->errorinfop = (ErrorInfo_t *)
			    ((ulong_t)cmdlist_memaddr + size_of_HRE);
			phyaddr += size_of_cmdlist;
			cmdlist_memaddr = (CommandList_t *)
			    ((ulong_t)cmdlist_memaddr + size_of_cmdlist);
			ptr++;
		}
	}

#ifdef MEM_DEBUG
	ptr = memlistp->head;
	cmn_err(CE_CONT, "CPQary3 : _meminit : max_memcnt = %d \n",
	    memlistp->max_memcnt);
	for (cntr = 0; cntr <= memlistp->max_memcnt; cntr++) {
		cmn_err(CE_CONT, "CPQary3: %d %x |",
		    cntr, ptr->cmdlist_phyaddr);
		if (cntr == 0)
			debug_enter("");
		ptr++;
	}
	cmn_err(CE_CONT, "\nCPQary3 : _meminit : "
	    "cpqary3_cmdpvt starts at %x \n", memlistp->head);
	cmn_err(CE_CONT, "CPQary3 : _meminit : cpqary3_cmdpvt ends at %x \n",
	    memlistp->tail);
	cmn_err(CE_CONT, "CPQary3 : _meminit : Leaving Successfully \n");
#endif

	return (CPQARY3_SUCCESS);
}

/*
 * Function	: 	cpqary3_cmdlist_occupy
 * Description	: 	This routine fetches a command block from the
 *			initialised memory pool.
 * Called By	: 	cpqary3_transport(), cpqary3_send_NOE_command(),
 *			cpqary3_disable_NOE_command(), cpqary3_synccmd_alloc()
 * Parameters	: 	per_controller
 * Calls	: 	None
 * Return Values: 	pointer to a valid Command Block /
 *			NULL if none is available
 */
cpqary3_cmdpvt_t *
cpqary3_cmdlist_occupy(cpqary3_t *ctlr)
{
	cpqary3_cmdpvt_t	*memp = NULL;
	cpqary3_cmdmemlist_t	*memlistp;

	RETURN_NULL_IF_NULL(ctlr);
	memlistp = ctlr->cmdmemlistp;

	/*
	 * If pointer is NULL, we have no Command Memory Blocks available now.
	 * Else, occupy it and
	 * zero the commandlist so that old data is not existent.
	 * update tag, Error descriptor address & length in the CommandList
	 */

	mutex_enter(&ctlr->sw_mutex);
	memp = memlistp->head;
	if (NULL == memp) {
		mutex_exit(&ctlr->sw_mutex);
		return ((cpqary3_cmdpvt_t *)NULL);
	}

	memp->occupied = CPQARY3_OCCUPIED;
	bzero(memp->cmdlist_memaddr, sizeof (CommandList_t));
	memp->cmdlist_memaddr->Header.Tag.tag_value = memp->tag.tag_value;
	memp->cmdlist_memaddr->ErrDesc.Addr = memp->cmdlist_erraddr;
	memp->cmdlist_memaddr->ErrDesc.Len = sizeof (ErrorInfo_t);
	memlistp->head = memp->next;

	DTRACE_PROBE1(cmdlist_occupy, cpqary3_cmdpvt_t *, memp);

	if (memlistp->head) /* Atleast one more item is left in the Memory Q */
		memp->next->prev = NULL;
	else	/* No more items left in the Memory q */
		memlistp->tail	 = NULL;

	mutex_exit(&ctlr->sw_mutex);
	return (memp);
}

/*
 * Function	:	cpqary3_cmdlist_release
 * Description	: 	This routine releases a command block back to the
 *			initialised memory pool.
 * Called By	: 	cpqary3_transport(), cpqary3_process_pkt(),
 *			cpqary3_send_NOE_command(), cpqary3_NOE_handler()
 *			cpqary3_transport(), cpqary3_handle_flag_nointr()
 *			cpqary3_synccmd_cleanup()
 * Parameters	: 	pointer to Command Memory
 *			flag to specify if mutex is to be held
 * Calls	: 	None
 * Return Values: 	None
 */
void
cpqary3_cmdlist_release(cpqary3_cmdpvt_t *memp, uint8_t flag)
{
	cpqary3_cmdmemlist_t	*memlistp;

	if (memp == NULL)
		return;

	/*
	 * Hold The mutex ONLY if asked to (Else it means it is already held!)
	 * If both head & tail of the per-controller-memory-list are NULL,
	 * add this command list to the Available Q and Update head & tail.
	 * Else, append it to the Available Q.
	 */

	memlistp =
	    (cpqary3_cmdmemlist_t *)((cpqary3_t *)memp->ctlr)->cmdmemlistp;

	if (CPQARY3_HOLD_SW_MUTEX == flag)
		mutex_enter(&memp->ctlr->sw_mutex);

	if (memlistp->head == NULL) {	/* obviously, tail is also NULL */
		memlistp->head = memp;
		memlistp->tail = memp;
		memp->next = NULL;
		memp->prev = NULL;
	} else {
		memlistp->tail->next = memp;
		memp->prev = memlistp->tail;
		memp->next = NULL;
		memlistp->tail = memp;
	}

	memp->occupied = CPQARY3_FREE;
	memp->cmdpvt_flag = 0;
	memp->pvt_pkt = NULL;

	if (CPQARY3_HOLD_SW_MUTEX == flag)
		mutex_exit(&memp->ctlr->sw_mutex);
}

/*
 * Function	: 	cpqary3_memfini
 * Description	: 	This routine frees all command blocks that was
 * 			initialised for the Command Memory Pool.
 * 			It also fress any related memory that was occupied.
 * Called By	: 	cpqary3_cleanup(), cpqary3_meminit(),
 * 			cpqary3_init_ctlr_resource()
 * Parameters	: 	per-controller, identifier(what all to clean up)
 * Calls	:  	cpqary3_free_phyctgs_mem
 * Return Values: 	None
 */
void
cpqary3_memfini(cpqary3_t *ctlr, uint8_t level)
{
	uint32_t		mem_size;
	uint32_t		CmdsOutMax;
	cpqary3_cmdpvt_t	*memp;
	cpqary3_phys_hdl_addr_t	*blk_ptr;
	cpqary3_phys_hdl_addr_t	*tptr;

	ASSERT(ctlr != NULL);
	blk_ptr = (cpqary3_phys_hdl_addr_t *)ctlr->cmdmemlistp->cpqary3_phyctgp;

	CmdsOutMax = ctlr->ctlr_maxcmds;

	DTRACE_PROBE1(memfini_start, uint32_t, CmdsOutMax);

	/*
	 * Depending upon the identifier,
	 * Free Physical memory & Memory allocated to hold Block Details
	 * Virtual Memory used to maintain linked list of Command Memory Pool
	 * Memory which stores data relating to the Command Memory Pool
	 */

	mutex_enter(&ctlr->sw_mutex);
	if (level & CPQARY3_PHYCTGS_DONE) {
		if (blk_ptr) {
			while (blk_ptr->next) {
				tptr = blk_ptr;
				blk_ptr = blk_ptr->next;
				cpqary3_free_phyctgs_mem(
				    tptr->blk_addr, CPQARY3_FREE_PHYCTG_MEM);
				MEM_SFREE(tptr,
				    sizeof (cpqary3_phys_hdl_addr_t));
			}
			cpqary3_free_phyctgs_mem(
			    blk_ptr->blk_addr, CPQARY3_FREE_PHYCTG_MEM);
			MEM_SFREE(blk_ptr, sizeof (cpqary3_phys_hdl_addr_t));
		}
	}

	if (level & CPQARY3_CMDMEM_DONE) {
		mem_size = (uint32_t)((CmdsOutMax / 3) *
		    NO_OF_CMDLIST_IN_A_BLK * sizeof (cpqary3_cmdpvt_t));
		memp = ctlr->cmdmemlistp->pool;

		DTRACE_PROBE2(memfini, uint32_t, mem_size, void *, memp);
		MEM_SFREE(memp, mem_size);
	}
	mutex_exit(&ctlr->sw_mutex);

	if (level & CPQARY3_MEMLIST_DONE) {
		mutex_enter(&ctlr->hw_mutex);
		MEM_SFREE(ctlr->cmdmemlistp, sizeof (cpqary3_cmdmemlist_t));
		mutex_exit(&ctlr->hw_mutex);
	}
}

/*
 * Function	: 	cpqary3_alloc_phyctgs_mem
 * Description	: 	This routine allocates Physically Contiguous Memory
 *			for Commands or Scatter/Gather.
 * Called By	:	cpqary3_meminit(), cpqary3_send_NOE_command()
 *			cpqary3_synccmd_alloc()
 * Parameters	: 	per-controller, size,
 *			physical address that is sent back, per-physical
 * Calls	:	cpqary3_free_phyctgs_mem(), ddi_dma_addr_bind_handle(),
 *			ddi_dma_alloc_handle(), ddi_dma_mem_alloc()
 * Return Values: 	Actually, this function sends back 2 values, one as an
 *			explicit return and the other by updating a
 * 			pointer-parameter:
 * 			Virtual Memory Pointer to the allocated Memory(caddr_t),
 * 			Physical Address of the allocated Memory(phyaddr)
 */
caddr_t
cpqary3_alloc_phyctgs_mem(cpqary3_t *ctlr, size_t size_mempool,
    uint32_t *phyaddr, cpqary3_phyctg_t *phyctgp)
{
	size_t real_len;
	int32_t retvalue;
	caddr_t mempool = NULL;
	uint8_t cleanstat = 0;
	uint32_t cookiecnt;

	RETURN_NULL_IF_NULL(ctlr);
	RETURN_NULL_IF_NULL(phyctgp);

	/*
	 * Allocation of Physical Contigous Memory follws:
	 * allocate a handle for this memory
	 * Use this handle in allocating memory
	 * bind the handle to this memory
	 * If any of the above fails, return a FAILURE.
	 * If all succeed, update phyaddr to the physical address of the
	 * allocated memory and return the pointer to the virtul allocated
	 * memory.
	 */

	if (DDI_SUCCESS !=
	    (retvalue = ddi_dma_alloc_handle((dev_info_t *)ctlr->dip,
	    &cpqary3_ctlr_dma_attr, DDI_DMA_DONTWAIT, 0,
	    &phyctgp->cpqary3_dmahandle))) {
		switch (retvalue) {
		case DDI_DMA_NORESOURCES:
			cmn_err(CE_CONT, "CPQary3: No resources are available "
			    "to allocate the DMA Handle\n");
			break;

		case DDI_DMA_BADATTR:
			cmn_err(CE_CONT, "CPQary3: Bad attributes in "
			    "ddi_dma_attr cannot allocate the DMA Handle \n");
			break;

		default:
			cmn_err(CE_CONT, "CPQary3: Unexpected Value %x from "
			    "call to allocate the DMA Handle \n", retvalue);
		}
		/* Calling MEM_SFREE to free the memory */
		MEM_SFREE(phyctgp, sizeof (cpqary3_phyctg_t));
		return (NULL);
	}

	cleanstat |= CPQARY3_DMA_ALLOC_HANDLE_DONE;

	retvalue = ddi_dma_mem_alloc(phyctgp->cpqary3_dmahandle,
	    size_mempool, &cpqary3_dev_attributes,
	    DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, 0, &mempool, &real_len,
	    &phyctgp->cpqary3_acchandle);

	if (DDI_SUCCESS != retvalue) {
		cmn_err(CE_WARN, "CPQary3: Memory Allocation Failed: "
		    "Increase System Memory");
		cpqary3_free_phyctgs_mem(phyctgp, cleanstat);
		return (NULL);
	}

	phyctgp->real_size = real_len;

	cleanstat |= CPQARY3_DMA_ALLOC_MEM_DONE;

	retvalue = ddi_dma_addr_bind_handle(phyctgp->cpqary3_dmahandle,
	    NULL, mempool, real_len,
	    DDI_DMA_CONSISTENT | DDI_DMA_RDWR, DDI_DMA_DONTWAIT, 0,
	    &phyctgp->cpqary3_dmacookie, &cookiecnt);

	if (DDI_DMA_MAPPED == retvalue) {
		*phyaddr = phyctgp->cpqary3_dmacookie.dmac_address;
		return (mempool);
	}

	switch (retvalue) {
	case DDI_DMA_PARTIAL_MAP:
		cmn_err(CE_CONT, "CPQary3: Allocated the resources for part "
		    "of the object\n");
		break;

	case DDI_DMA_INUSE:
		cmn_err(CE_CONT, "CPQary3: Another I/O transaction is using "
		    "the DMA handle cannot bind to the DMA Handle\n");
		break;

	case DDI_DMA_NORESOURCES:
		cmn_err(CE_CONT, "CPQary3: No resources are available cannot "
		    "bind to the DMA Handle\n");
		break;

	case DDI_DMA_NOMAPPING:
		cmn_err(CE_CONT, "CPQary3: Object cannot be reached by the "
		    "device cannot bind to the DMA Handle\n");
		break;

	case DDI_DMA_TOOBIG:
		cmn_err(CE_CONT, "CPQary3: The object is too big cannot bind "
		    "to the DMA Handle\n");
		cmn_err(CE_WARN, "CPQary3: Mem Scarce : "
		    "Increase System Memory/lomempages");
		break;

	default:
		cmn_err(CE_WARN, "CPQary3 : Unexpected Return Value %x "
		    "from call to bind the DMA Handle", retvalue);
	}

	cpqary3_free_phyctgs_mem(phyctgp, cleanstat);

	mempool = NULL;
	return (mempool);
}

/*
 * Function	: 	cpqary3_free_phyctg_mem ()
 * Description	: 	This routine frees the Physically contigous memory
 *			that was allocated using ddi_dma operations.
 *			It also fress any related memory that was occupied.
 * Called By	: 	cpqary3_alloc_phyctgs_mem(), cpqary3_memfini(),
 *			cpqary3_send_NOE_command(), cpqary3_NOE_handler(),
 *			cpqary3_synccmd_alloc(), cpqary3_synccmd_cleanup()
 * Parameters	: 	per-physical, identifier(what all to free)
 * Calls	: 	None
 */
void
cpqary3_free_phyctgs_mem(cpqary3_phyctg_t *cpqary3_phyctgp, uint8_t cleanstat)
{

	if (cpqary3_phyctgp == NULL)
		return;

	/*
	 * Following the reverse prcess that was followed
	 * in allocating physical contigous memory
	 */

	if (cleanstat & CPQARY3_DMA_BIND_ADDR_DONE) {
		(void) ddi_dma_unbind_handle(
		    cpqary3_phyctgp->cpqary3_dmahandle);
	}

	if (cleanstat & CPQARY3_DMA_ALLOC_MEM_DONE) {
		ddi_dma_mem_free(&cpqary3_phyctgp->cpqary3_acchandle);
	}

	if (cleanstat & CPQARY3_DMA_ALLOC_HANDLE_DONE) {
		ddi_dma_free_handle(&cpqary3_phyctgp->cpqary3_dmahandle);
	}

	MEM_SFREE(cpqary3_phyctgp, sizeof (cpqary3_phyctg_t));
}
