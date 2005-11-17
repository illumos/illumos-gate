/*******************************************************************************
 *
 * Module Name: rsdump - Functions to display the resource structures.
 *              $Revision: 1.53 $
 *
 ******************************************************************************/

/******************************************************************************
 *
 * 1. Copyright Notice
 *
 * Some or all of this work - Copyright (c) 1999 - 2005, Intel Corp.
 * All rights reserved.
 *
 * 2. License
 *
 * 2.1. This is your license from Intel Corp. under its intellectual property
 * rights.  You may have additional license terms from the party that provided
 * you this software, covering your right to use that party's intellectual
 * property rights.
 *
 * 2.2. Intel grants, free of charge, to any person ("Licensee") obtaining a
 * copy of the source code appearing in this file ("Covered Code") an
 * irrevocable, perpetual, worldwide license under Intel's copyrights in the
 * base code distributed originally by Intel ("Original Intel Code") to copy,
 * make derivatives, distribute, use and display any portion of the Covered
 * Code in any form, with the right to sublicense such rights; and
 *
 * 2.3. Intel grants Licensee a non-exclusive and non-transferable patent
 * license (with the right to sublicense), under only those claims of Intel
 * patents that are infringed by the Original Intel Code, to make, use, sell,
 * offer to sell, and import the Covered Code and derivative works thereof
 * solely to the minimum extent necessary to exercise the above copyright
 * license, and in no event shall the patent license extend to any additions
 * to or modifications of the Original Intel Code.  No other license or right
 * is granted directly or by implication, estoppel or otherwise;
 *
 * The above copyright and patent license is granted only if the following
 * conditions are met:
 *
 * 3. Conditions
 *
 * 3.1. Redistribution of Source with Rights to Further Distribute Source.
 * Redistribution of source code of any substantial portion of the Covered
 * Code or modification with rights to further distribute source must include
 * the above Copyright Notice, the above License, this list of Conditions,
 * and the following Disclaimer and Export Compliance provision.  In addition,
 * Licensee must cause all Covered Code to which Licensee contributes to
 * contain a file documenting the changes Licensee made to create that Covered
 * Code and the date of any change.  Licensee must include in that file the
 * documentation of any changes made by any predecessor Licensee.  Licensee
 * must include a prominent statement that the modification is derived,
 * directly or indirectly, from Original Intel Code.
 *
 * 3.2. Redistribution of Source with no Rights to Further Distribute Source.
 * Redistribution of source code of any substantial portion of the Covered
 * Code or modification without rights to further distribute source must
 * include the following Disclaimer and Export Compliance provision in the
 * documentation and/or other materials provided with distribution.  In
 * addition, Licensee may not authorize further sublicense of source of any
 * portion of the Covered Code, and must include terms to the effect that the
 * license from Licensee to its licensee is limited to the intellectual
 * property embodied in the software Licensee provides to its licensee, and
 * not to intellectual property embodied in modifications its licensee may
 * make.
 *
 * 3.3. Redistribution of Executable. Redistribution in executable form of any
 * substantial portion of the Covered Code or modification must reproduce the
 * above Copyright Notice, and the following Disclaimer and Export Compliance
 * provision in the documentation and/or other materials provided with the
 * distribution.
 *
 * 3.4. Intel retains all right, title, and interest in and to the Original
 * Intel Code.
 *
 * 3.5. Neither the name Intel nor any other trademark owned or controlled by
 * Intel shall be used in advertising or otherwise to promote the sale, use or
 * other dealings in products derived from or relating to the Covered Code
 * without prior written authorization from Intel.
 *
 * 4. Disclaimer and Export Compliance
 *
 * 4.1. INTEL MAKES NO WARRANTY OF ANY KIND REGARDING ANY SOFTWARE PROVIDED
 * HERE.  ANY SOFTWARE ORIGINATING FROM INTEL OR DERIVED FROM INTEL SOFTWARE
 * IS PROVIDED "AS IS," AND INTEL WILL NOT PROVIDE ANY SUPPORT,  ASSISTANCE,
 * INSTALLATION, TRAINING OR OTHER SERVICES.  INTEL WILL NOT PROVIDE ANY
 * UPDATES, ENHANCEMENTS OR EXTENSIONS.  INTEL SPECIFICALLY DISCLAIMS ANY
 * IMPLIED WARRANTIES OF MERCHANTABILITY, NONINFRINGEMENT AND FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * 4.2. IN NO EVENT SHALL INTEL HAVE ANY LIABILITY TO LICENSEE, ITS LICENSEES
 * OR ANY OTHER THIRD PARTY, FOR ANY LOST PROFITS, LOST DATA, LOSS OF USE OR
 * COSTS OF PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES, OR FOR ANY INDIRECT,
 * SPECIAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THIS AGREEMENT, UNDER ANY
 * CAUSE OF ACTION OR THEORY OF LIABILITY, AND IRRESPECTIVE OF WHETHER INTEL
 * HAS ADVANCE NOTICE OF THE POSSIBILITY OF SUCH DAMAGES.  THESE LIMITATIONS
 * SHALL APPLY NOTWITHSTANDING THE FAILURE OF THE ESSENTIAL PURPOSE OF ANY
 * LIMITED REMEDY.
 *
 * 4.3. Licensee shall not export, either directly or indirectly, any of this
 * software or system incorporating such software without first obtaining any
 * required license or other approval from the U. S. Department of Commerce or
 * any other agency or department of the United States Government.  In the
 * event Licensee exports any such software from the United States or
 * re-exports any such software from a foreign destination, Licensee shall
 * ensure that the distribution and export/re-export of the software is in
 * compliance with all laws, regulations, orders, or other restrictions of the
 * U.S. Export Administration Regulations. Licensee agrees that neither it nor
 * any of its subsidiaries will export/re-export any technical data, process,
 * software, or service, directly or indirectly, to any country for which the
 * United States government or any agency thereof requires an export license,
 * other governmental approval, or letter of assurance, without first obtaining
 * such license, approval or letter.
 *
 *****************************************************************************/


#define __RSDUMP_C__

#include "acpi.h"
#include "acresrc.h"

#define _COMPONENT          ACPI_RESOURCES
        ACPI_MODULE_NAME    ("rsdump")


#if defined(ACPI_DEBUG_OUTPUT) || defined(ACPI_DEBUGGER)

/* Local prototypes */

static void
AcpiRsOutString (
    char                    *Title,
    char                    *Value);

static void
AcpiRsOutInteger8 (
    char                    *Title,
    UINT8                   Value);

static void
AcpiRsOutInteger16 (
    char                    *Title,
    UINT16                  Value);

static void
AcpiRsOutInteger32 (
    char                    *Title,
    UINT32                  Value);

static void
AcpiRsOutInteger64 (
    char                    *Title,
    UINT64                  Value);

static void
AcpiRsOutTitle (
    char                    *Title);

static void
AcpiRsDumpByteList (
    UINT32                  Length,
    UINT8                   *Data);

static void
AcpiRsDumpDwordList (
    UINT32                  Length,
    UINT32                  *Data);

static void
AcpiRsDumpShortByteList (
    UINT32                  Length,
    UINT32                  *Data);

static void
AcpiRsDumpResourceSource (
    ACPI_RESOURCE_SOURCE    *ResourceSource);

static void
AcpiRsDumpAddressCommon (
    ACPI_RESOURCE_DATA      *Resource);


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsOut*
 *
 * PARAMETERS:  Title       - Name of the resource field
 *              Value       - Value of the resource field
 *
 * RETURN:      None
 *
 * DESCRIPTION: Miscellaneous helper functions to consistently format the
 *              output of the resource dump routines
 *
 ******************************************************************************/

static void
AcpiRsOutString (
    char                    *Title,
    char                    *Value)
{
    AcpiOsPrintf ("%27s : %s\n", Title, Value);
}

static void
AcpiRsOutInteger8 (
    char                    *Title,
    UINT8                   Value)
{
    AcpiOsPrintf ("%27s : %2.2X\n", Title, Value);
}

static void
AcpiRsOutInteger16 (
    char                    *Title,
    UINT16                  Value)
{
    AcpiOsPrintf ("%27s : %4.4X\n", Title, Value);
}

static void
AcpiRsOutInteger32 (
    char                    *Title,
    UINT32                  Value)
{
    AcpiOsPrintf ("%27s : %8.8X\n", Title, Value);
}

static void
AcpiRsOutInteger64 (
    char                    *Title,
    UINT64                  Value)
{
    AcpiOsPrintf ("%27s : %8.8X%8.8X\n", Title,
        ACPI_FORMAT_UINT64 (Value));
}

static void
AcpiRsOutTitle (
    char                    *Title)
{
    AcpiOsPrintf ("%27s : ", Title);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDump*List
 *
 * PARAMETERS:  Length      - Number of elements in the list
 *              Data        - Start of the list
 *
 * RETURN:      None
 *
 * DESCRIPTION: Miscellaneous functions to dump lists of raw data
 *
 ******************************************************************************/

static void
AcpiRsDumpByteList (
    UINT32                  Length,
    UINT8                   *Data)
{
    UINT32                  i;


    for (i = 0; i < Length; i++)
    {
        AcpiOsPrintf ("%25s%2.2X : %2.2X\n",
            "Byte", i, Data[i]);
    }
}

static void
AcpiRsDumpDwordList (
    UINT32                  Length,
    UINT32                  *Data)
{
    UINT32                  i;


    for (i = 0; i < Length; i++)
    {
        AcpiOsPrintf ("%25s%2.2X : %8.8X\n",
            "Dword", i, Data[i]);
    }
}

static void
AcpiRsDumpShortByteList (
    UINT32                  Length,
    UINT32                  *Data)
{
    UINT32                  i;


    for (i = 0; i < Length; i++)
    {
        AcpiOsPrintf ("%X ", Data[i]);
    }
    AcpiOsPrintf ("\n");
}

static void
AcpiRsDumpMemoryAttribute (
    UINT32                      ReadWriteAttribute)
{

    AcpiRsOutString ("Read/Write Attribute",
        ACPI_READ_WRITE_MEMORY == ReadWriteAttribute ?
            "Read/Write" : "Read-Only");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpResourceSource
 *
 * PARAMETERS:  ResourceSource      - Pointer to a Resource Source struct
 *
 * RETURN:      None
 *
 * DESCRIPTION: Common routine for dumping the optional ResourceSource and the
 *              corresponding ResourceSourceIndex.
 *
 ******************************************************************************/

static void
AcpiRsDumpResourceSource (
    ACPI_RESOURCE_SOURCE    *ResourceSource)
{
    ACPI_FUNCTION_ENTRY ();


    if (ResourceSource->Index == 0xFF)
    {
        return;
    }

    AcpiRsOutInteger8 ("Resource Source Index",
        (UINT8) ResourceSource->Index);

    AcpiRsOutString ("Resource Source",
        ResourceSource->StringPtr ?
            ResourceSource->StringPtr : "[Not Specified]");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpAddressCommon
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the fields that are common to all Address resource
 *              descriptors
 *
 ******************************************************************************/

static void
AcpiRsDumpAddressCommon (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    /* Decode the type-specific flags */

    switch (Resource->Address.ResourceType)
    {
    case ACPI_MEMORY_RANGE:

        AcpiRsOutString ("Resource Type", "Memory Range");

        AcpiRsOutTitle ("Type-Specific Flags");

        switch (Resource->Address.Attribute.Memory.CacheAttribute)
        {
        case ACPI_NON_CACHEABLE_MEMORY:
            AcpiOsPrintf ("Noncacheable memory\n");
            break;

        case ACPI_CACHABLE_MEMORY:
            AcpiOsPrintf ("Cacheable memory\n");
            break;

        case ACPI_WRITE_COMBINING_MEMORY:
            AcpiOsPrintf ("Write-combining memory\n");
            break;

        case ACPI_PREFETCHABLE_MEMORY:
            AcpiOsPrintf ("Prefetchable memory\n");
            break;

        default:
            AcpiOsPrintf ("Invalid cache attribute\n");
            break;
        }

        AcpiRsDumpMemoryAttribute (
            Resource->Address.Attribute.Memory.ReadWriteAttribute);
        break;

    case ACPI_IO_RANGE:

        AcpiRsOutString ("Resource Type", "I/O Range");

        AcpiRsOutTitle ("Type-Specific Flags");

        switch (Resource->Address.Attribute.Io.RangeAttribute)
        {
        case ACPI_NON_ISA_ONLY_RANGES:
            AcpiOsPrintf ("Non-ISA I/O Addresses\n");
            break;

        case ACPI_ISA_ONLY_RANGES:
            AcpiOsPrintf ("ISA I/O Addresses\n");
            break;

        case ACPI_ENTIRE_RANGE:
            AcpiOsPrintf ("ISA and non-ISA I/O Addresses\n");
            break;

        default:
            AcpiOsPrintf ("Invalid range attribute\n");
            break;
        }

        AcpiRsOutString ("Translation Attribute",
            ACPI_SPARSE_TRANSLATION ==
                Resource->Address.Attribute.Io.TranslationAttribute ?
                "Sparse Translation" : "Dense Translation");
        break;

    case ACPI_BUS_NUMBER_RANGE:

        AcpiRsOutString ("Resource Type", "Bus Number Range");
        break;

    default:

        AcpiRsOutInteger8 ("Resource Type",
            (UINT8) Resource->Address.ResourceType);
        break;
    }

    /* Decode the general flags */

    AcpiRsOutString ("Resource",
        ACPI_CONSUMER == Resource->Address.ProducerConsumer ?
            "Consumer" : "Producer");

    AcpiRsOutString ("Decode",
        ACPI_SUB_DECODE == Resource->Address.Decode ?
            "Subtractive" : "Positive");

    AcpiRsOutString ("Min Address",
        ACPI_ADDRESS_FIXED == Resource->Address.MinAddressFixed ?
            "Fixed" : "Not Fixed");

    AcpiRsOutString ("Max Address",
        ACPI_ADDRESS_FIXED == Resource->Address.MaxAddressFixed ?
            "Fixed" : "Not Fixed");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpResourceList
 *
 * PARAMETERS:  ResourceList        - Pointer to a resource descriptor list
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dispatches the structure to the correct dump routine.
 *
 ******************************************************************************/

void
AcpiRsDumpResourceList (
    ACPI_RESOURCE           *ResourceList)
{
    UINT32                  Count = 0;


    ACPI_FUNCTION_ENTRY ();


    if (!(AcpiDbgLevel & ACPI_LV_RESOURCES) || !( _COMPONENT & AcpiDbgLayer))
    {
        return;
    }

    /* Dump all resource descriptors in the list */

    while (ResourceList)
    {
        AcpiOsPrintf ("\n[%02X] ", Count);

        /* Validate Type before dispatch */

        if (ResourceList->Type > ACPI_RESOURCE_TYPE_MAX)
        {
            AcpiOsPrintf (
                "Invalid descriptor type (%X) in resource list\n",
                ResourceList->Type);
            return;
        }

        /* Dump the resource descriptor */

        AcpiGbl_DumpResourceDispatch[ResourceList->Type] (&ResourceList->Data);

        /* Exit on end tag */

        if (ResourceList->Type == ACPI_RESOURCE_TYPE_END_TAG)
        {
            return;
        }

        /* Get the next resource structure */

        ResourceList = ACPI_PTR_ADD (ACPI_RESOURCE, ResourceList,
                            ResourceList->Length);
        Count++;
    }
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpIrq
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpIrq (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("IRQ Resource\n");

    AcpiRsOutString ("Triggering",
        ACPI_LEVEL_SENSITIVE == Resource->Irq.Triggering ? "Level" : "Edge");

    AcpiRsOutString ("Active",
        ACPI_ACTIVE_LOW == Resource->Irq.Polarity ? "Low" : "High");

    AcpiRsOutString ("Sharing",
        ACPI_SHARED == Resource->Irq.Sharable ? "Shared" : "Exclusive");

    AcpiRsOutInteger8 ("Interrupt Count",
        (UINT8) Resource->Irq.InterruptCount);

    AcpiRsOutTitle ("Interrupt List");
    AcpiRsDumpShortByteList (Resource->Irq.InterruptCount,
        Resource->Irq.Interrupts);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpDma
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpDma (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("DMA Resource\n");

    AcpiRsOutTitle ("DMA Type");
    switch (Resource->Dma.Type)
    {
    case ACPI_COMPATIBILITY:
        AcpiOsPrintf ("Compatibility mode\n");
        break;

    case ACPI_TYPE_A:
        AcpiOsPrintf ("Type A\n");
        break;

    case ACPI_TYPE_B:
        AcpiOsPrintf ("Type B\n");
        break;

    case ACPI_TYPE_F:
        AcpiOsPrintf ("Type F\n");
        break;

    default:
        AcpiOsPrintf ("**** Invalid DMA type\n");
        break;
    }

    AcpiRsOutString ("Bus Master",
        ACPI_BUS_MASTER == Resource->Dma.BusMaster ? "Yes" : "No");

    AcpiRsOutTitle ("Transfer Type");
    switch (Resource->Dma.Transfer)
    {
    case ACPI_TRANSFER_8:
        AcpiOsPrintf ("8-bit transfers only\n");
        break;

    case ACPI_TRANSFER_8_16:
        AcpiOsPrintf ("8-bit and 16-bit transfers\n");
        break;

    case ACPI_TRANSFER_16:
        AcpiOsPrintf ("16-bit transfers only\n");
        break;

    default:
        AcpiOsPrintf ("**** Invalid transfer preference\n");
        break;
    }

    AcpiRsOutInteger8 ("DMA Channel Count",
        (UINT8) Resource->Dma.ChannelCount);

    AcpiRsOutTitle ("Channel List");
    AcpiRsDumpShortByteList (Resource->Dma.ChannelCount,
        Resource->Dma.Channels);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpStartDpf
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpStartDpf (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("Start Dependent Functions Resource\n");

    AcpiRsOutTitle ("Compatibility Priority");
    switch (Resource->StartDpf.CompatibilityPriority)
    {
    case ACPI_GOOD_CONFIGURATION:
        AcpiOsPrintf ("Good configuration\n");
        break;

    case ACPI_ACCEPTABLE_CONFIGURATION:
        AcpiOsPrintf ("Acceptable configuration\n");
        break;

    case ACPI_SUB_OPTIMAL_CONFIGURATION:
        AcpiOsPrintf ("Sub-optimal configuration\n");
        break;

    default:
        AcpiOsPrintf ("**** Invalid compatibility priority\n");
        break;
    }

    AcpiRsOutTitle ("Performance/Robustness");
    switch (Resource->StartDpf.PerformanceRobustness)
    {
    case ACPI_GOOD_CONFIGURATION:
        AcpiOsPrintf ("Good configuration\n");
        break;

    case ACPI_ACCEPTABLE_CONFIGURATION:
        AcpiOsPrintf ("Acceptable configuration\n");
        break;

    case ACPI_SUB_OPTIMAL_CONFIGURATION:
        AcpiOsPrintf ("Sub-optimal configuration\n");
        break;

    default:
        AcpiOsPrintf ("**** Invalid performance robustness preference\n");
        break;
    }
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpIo
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpIo (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("I/O Resource\n");

    AcpiRsOutString ("Decode",
        ACPI_DECODE_16 == Resource->Io.IoDecode ? "16-bit" : "10-bit");

    AcpiRsOutInteger32 ("Address Minimum",
        Resource->Io.Minimum);

    AcpiRsOutInteger32 ("Address Maximum",
        Resource->Io.Maximum);

    AcpiRsOutInteger32 ("Alignment",
        Resource->Io.Alignment);

    AcpiRsOutInteger32 ("Address Length",
        Resource->Io.AddressLength);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpFixedIo
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpFixedIo (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("Fixed I/O Resource\n");

    AcpiRsOutInteger32 ("Address",
        Resource->FixedIo.Address);

    AcpiRsOutInteger32 ("Address Length",
        Resource->FixedIo.AddressLength);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpVendor
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpVendor (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("Vendor Specific Resource\n");

    AcpiRsOutInteger16 ("Length",
        (UINT16) Resource->Vendor.ByteLength);

    AcpiRsDumpByteList (Resource->Vendor.ByteLength,
        Resource->Vendor.ByteData);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpMemory24
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpMemory24 (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("24-Bit Memory Range Resource\n");

    AcpiRsDumpMemoryAttribute (
        Resource->Memory24.ReadWriteAttribute);

    AcpiRsOutInteger16 ("Address Minimum",
        (UINT16) Resource->Memory24.Minimum);

    AcpiRsOutInteger16 ("Address Maximum",
        (UINT16) Resource->Memory24.Maximum);

    AcpiRsOutInteger16 ("Alignment",
        (UINT16) Resource->Memory24.Alignment);

    AcpiRsOutInteger16 ("Address Length",
        (UINT16) Resource->Memory24.AddressLength);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpMemory32
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpMemory32 (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("32-Bit Memory Range Resource\n");

    AcpiRsDumpMemoryAttribute (
        Resource->Memory32.ReadWriteAttribute);

    AcpiRsOutInteger32 ("Address Minimum",
        Resource->Memory32.Minimum);

    AcpiRsOutInteger32 ("Address Maximum",
        Resource->Memory32.Maximum);

    AcpiRsOutInteger32 ("Alignment",
        Resource->Memory32.Alignment);

    AcpiRsOutInteger32 ("Address Length",
        Resource->Memory32.AddressLength);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpFixedMemory32
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpFixedMemory32 (
    ACPI_RESOURCE_DATA          *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("32-Bit Fixed Location Memory Range Resource\n");

    AcpiRsDumpMemoryAttribute (
        Resource->FixedMemory32.ReadWriteAttribute);

    AcpiRsOutInteger32 ("Address",
        Resource->FixedMemory32.Address);

    AcpiRsOutInteger32 ("Address Length",
        Resource->FixedMemory32.AddressLength);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpAddress16
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpAddress16 (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("16-Bit WORD Address Space Resource\n");

    AcpiRsDumpAddressCommon (Resource);

    AcpiRsOutInteger16 ("Granularity",
        (UINT16) Resource->Address16.Granularity);

    AcpiRsOutInteger16 ("Address Minimum",
        (UINT16) Resource->Address16.Minimum);

    AcpiRsOutInteger16 ("Address Maximum",
        (UINT16) Resource->Address16.Maximum);

    AcpiRsOutInteger16 ("Translation Offset",
        (UINT16) Resource->Address16.TranslationOffset);

    AcpiRsOutInteger16 ("Address Length",
        (UINT16) Resource->Address16.AddressLength);

    AcpiRsDumpResourceSource (&Resource->Address16.ResourceSource);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpAddress32
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpAddress32 (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("32-Bit DWORD Address Space Resource\n");

    AcpiRsDumpAddressCommon (Resource);

    AcpiRsOutInteger32 ("Granularity",
         Resource->Address32.Granularity);

    AcpiRsOutInteger32 ("Address Minimum",
        Resource->Address32.Minimum);

    AcpiRsOutInteger32 ("Address Maximum",
        Resource->Address32.Maximum);

    AcpiRsOutInteger32 ("Translation Offset",
        Resource->Address32.TranslationOffset);

    AcpiRsOutInteger32 ("Address Length",
        Resource->Address32.AddressLength);

    AcpiRsDumpResourceSource (&Resource->Address32.ResourceSource);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpAddress64
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpAddress64 (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("64-Bit QWORD Address Space Resource\n");

    AcpiRsDumpAddressCommon (Resource);

    AcpiRsOutInteger64 ("Granularity",
        Resource->Address64.Granularity);

    AcpiRsOutInteger64 ("Address Minimum",
        Resource->Address64.Minimum);

    AcpiRsOutInteger64 ("Address Maximum",
        Resource->Address64.Maximum);

    AcpiRsOutInteger64 ("Translation Offset",
        Resource->Address64.TranslationOffset);

    AcpiRsOutInteger64 ("Address Length",
        Resource->Address64.AddressLength);

    AcpiRsDumpResourceSource (&Resource->Address64.ResourceSource);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpExtAddress64
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpExtAddress64 (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("64-Bit Extended Address Space Resource\n");

    AcpiRsDumpAddressCommon (Resource);

    AcpiRsOutInteger64 ("Granularity",
        Resource->ExtAddress64.Granularity);

    AcpiRsOutInteger64 ("Address Minimum",
        Resource->ExtAddress64.Minimum);

    AcpiRsOutInteger64 ("Address Maximum",
        Resource->ExtAddress64.Maximum);

    AcpiRsOutInteger64 ("Translation Offset",
        Resource->ExtAddress64.TranslationOffset);

    AcpiRsOutInteger64 ("Address Length",
        Resource->ExtAddress64.AddressLength);

    AcpiRsOutInteger64 ("Type-Specific Attribute",
        Resource->ExtAddress64.TypeSpecificAttributes);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpExtIrq
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpExtIrq (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("Extended IRQ Resource\n");

    AcpiRsOutString ("Resource",
        ACPI_CONSUMER == Resource->ExtendedIrq.ProducerConsumer ?
            "Consumer" : "Producer");

    AcpiRsOutString ("Triggering",
        ACPI_LEVEL_SENSITIVE == Resource->ExtendedIrq.Triggering ?
            "Level" : "Edge");

    AcpiRsOutString ("Active",
        ACPI_ACTIVE_LOW == Resource->ExtendedIrq.Polarity ?
            "Low" : "High");

    AcpiRsOutString ("Sharing",
        ACPI_SHARED == Resource->ExtendedIrq.Sharable ?
            "Shared" : "Exclusive");

    AcpiRsDumpResourceSource (&Resource->ExtendedIrq.ResourceSource);

    AcpiRsOutInteger8 ("Interrupts",
        (UINT8) Resource->ExtendedIrq.InterruptCount);

    AcpiRsDumpDwordList (Resource->ExtendedIrq.InterruptCount,
        Resource->ExtendedIrq.Interrupts);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpGenericReg
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump the field names and values of the resource descriptor
 *
 ******************************************************************************/

void
AcpiRsDumpGenericReg (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("Generic Register Resource\n");

    AcpiRsOutInteger8 ("Space ID",
        (UINT8) Resource->GenericReg.SpaceId);

    AcpiRsOutInteger8 ("Bit Width",
        (UINT8) Resource->GenericReg.BitWidth);

    AcpiRsOutInteger8 ("Bit Offset",
        (UINT8) Resource->GenericReg.BitOffset);

    AcpiRsOutInteger8 ("Access Size",
        (UINT8) Resource->GenericReg.AccessSize);

    AcpiRsOutInteger64 ("Address",
        Resource->GenericReg.Address);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpEndDpf
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Print type, no data.
 *
 ******************************************************************************/

void
AcpiRsDumpEndDpf (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("EndDependentFunctions Resource\n");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpEndTag
 *
 * PARAMETERS:  Resource        - Pointer to an internal resource descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Print type, no data.
 *
 ******************************************************************************/

void
AcpiRsDumpEndTag (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    AcpiOsPrintf ("EndTag Resource\n");
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDumpIrqList
 *
 * PARAMETERS:  RouteTable      - Pointer to the routing table to dump.
 *
 * RETURN:      None
 *
 * DESCRIPTION: Print IRQ routing table
 *
 ******************************************************************************/

void
AcpiRsDumpIrqList (
    UINT8                   *RouteTable)
{
    UINT8                   *Buffer = RouteTable;
    UINT8                   Count = 0;
    ACPI_PCI_ROUTING_TABLE  *PrtElement;


    ACPI_FUNCTION_ENTRY ();


    if (!(AcpiDbgLevel & ACPI_LV_RESOURCES) || !( _COMPONENT & AcpiDbgLayer))
    {
        return;
    }

    PrtElement = ACPI_CAST_PTR (ACPI_PCI_ROUTING_TABLE, Buffer);

    /* Dump all table elements, Exit on null length element */

    while (PrtElement->Length)
    {
        AcpiOsPrintf ("\n[%02X] PCI IRQ Routing Table Package\n", Count);

        AcpiRsOutInteger64 ("Address",
            PrtElement->Address);

        AcpiRsOutInteger32 ("Pin", PrtElement->Pin);
        AcpiRsOutString ("Source", PrtElement->Source);
        AcpiRsOutInteger32 ("Source Index", PrtElement->SourceIndex);

        Buffer += PrtElement->Length;
        PrtElement = ACPI_CAST_PTR (ACPI_PCI_ROUTING_TABLE, Buffer);
        Count++;
    }
}

#endif

