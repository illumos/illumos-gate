/*******************************************************************************
 *
 * Module Name: rsio - IO and DMA resource descriptors
 *              $Revision: 1.32 $
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

#define __RSIO_C__

#include "acpi.h"
#include "acresrc.h"

#define _COMPONENT          ACPI_RESOURCES
        ACPI_MODULE_NAME    ("rsio")


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetIo
 *
 * PARAMETERS:  Aml                 - Pointer to the AML resource descriptor
 *              AmlResourceLength   - Length of the resource from the AML header
 *              Resource            - Where the internal resource is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert a raw AML resource descriptor to the corresponding
 *              internal resource descriptor, simplifying bitflags and handling
 *              alignment and endian issues if necessary.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsGetIo (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    ACPI_FUNCTION_TRACE ("RsGetIo");


    /* Get the Decode flag */

    Resource->Data.Io.IoDecode = Aml->Io.Information & 0x01;

    /*
     * Get the following contiguous fields from the AML descriptor:
     * Minimum Base Address
     * Maximum Base Address
     * Address Alignment
     * Length
     */
    ACPI_MOVE_16_TO_32 (&Resource->Data.Io.Minimum,
        &Aml->Io.Minimum);
    ACPI_MOVE_16_TO_32 (&Resource->Data.Io.Maximum,
        &Aml->Io.Maximum);
    Resource->Data.Io.Alignment = Aml->Io.Alignment;
    Resource->Data.Io.AddressLength = Aml->Io.AddressLength;

    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_IO;
    Resource->Length = ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_IO);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetIo
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Aml                 - Where the AML descriptor is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert an internal resource descriptor to the corresponding
 *              external AML resource descriptor.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsSetIo (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_FUNCTION_TRACE ("RsSetIo");


    /* I/O Information Byte */

    Aml->Io.Information = (UINT8) (Resource->Data.Io.IoDecode & 0x01);

    /*
     * Set the following contiguous fields in the AML descriptor:
     * Minimum Base Address
     * Maximum Base Address
     * Address Alignment
     * Length
     */
    ACPI_MOVE_32_TO_16 (&Aml->Io.Minimum, &Resource->Data.Io.Minimum);
    ACPI_MOVE_32_TO_16 (&Aml->Io.Maximum, &Resource->Data.Io.Maximum);
    Aml->Io.Alignment = (UINT8) Resource->Data.Io.Alignment;
    Aml->Io.AddressLength = (UINT8) Resource->Data.Io.AddressLength;

    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_IO, sizeof (AML_RESOURCE_IO), Aml);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetFixedIo
 *
 * PARAMETERS:  Aml                 - Pointer to the AML resource descriptor
 *              AmlResourceLength   - Length of the resource from the AML header
 *              Resource            - Where the internal resource is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert a raw AML resource descriptor to the corresponding
 *              internal resource descriptor, simplifying bitflags and handling
 *              alignment and endian issues if necessary.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsGetFixedIo (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    ACPI_FUNCTION_TRACE ("RsGetFixedIo");


    /*
     * Get the following contiguous fields from the AML descriptor:
     * Base Address
     * Length
     */
    ACPI_MOVE_16_TO_32 (&Resource->Data.FixedIo.Address,
        &Aml->FixedIo.Address);
    Resource->Data.FixedIo.AddressLength = Aml->FixedIo.AddressLength;

    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_FIXED_IO;
    Resource->Length = ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_FIXED_IO);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetFixedIo
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Aml                 - Where the AML descriptor is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert an internal resource descriptor to the corresponding
 *              external AML resource descriptor.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsSetFixedIo (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_FUNCTION_TRACE ("RsSetFixedIo");


    /*
     * Set the following contiguous fields in the AML descriptor:
     * Base Address
     * Length
     */
    ACPI_MOVE_32_TO_16 (&Aml->FixedIo.Address,
        &Resource->Data.FixedIo.Address);
    Aml->FixedIo.AddressLength = (UINT8) Resource->Data.FixedIo.AddressLength;

    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_FIXED_IO,
        sizeof (AML_RESOURCE_FIXED_IO), Aml);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetDma
 *
 * PARAMETERS:  Aml                 - Pointer to the AML resource descriptor
 *              AmlResourceLength   - Length of the resource from the AML header
 *              Resource            - Where the internal resource is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert a raw AML resource descriptor to the corresponding
 *              internal resource descriptor, simplifying bitflags and handling
 *              alignment and endian issues if necessary.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsGetDma (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    UINT32                  ChannelCount = 0;
    UINT32                  i;
    UINT8                   Temp8;


    ACPI_FUNCTION_TRACE ("RsGetDma");


    /* Decode the DMA channel bits */

    for (i = 0; i < 8; i++)
    {
        if ((Aml->Dma.DmaChannelMask >> i) & 0x01)
        {
            Resource->Data.Dma.Channels[ChannelCount] = i;
            ChannelCount++;
        }
    }

    Resource->Length = 0;
    Resource->Data.Dma.ChannelCount = ChannelCount;

    /*
     * Calculate the structure size based upon the number of channels
     * Note: Zero DMA channels is valid
     */
    if (ChannelCount > 0)
    {
        Resource->Length = (UINT32) (ChannelCount - 1) * 4;
    }

    /* Get the flags: transfer preference, bus mastering, channel speed */

    Temp8 = Aml->Dma.Flags;
    Resource->Data.Dma.Transfer  =  Temp8 & 0x03;
    Resource->Data.Dma.BusMaster = (Temp8 >> 2) & 0x01;
    Resource->Data.Dma.Type      = (Temp8 >> 5) & 0x03;

    if (Resource->Data.Dma.Transfer == 0x03)
    {
        ACPI_DEBUG_PRINT ((ACPI_DB_ERROR,
            "Invalid DMA.Transfer preference (3)\n"));
        return_ACPI_STATUS (AE_BAD_DATA);
    }

    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_DMA;
    Resource->Length += ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_DMA);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetDma
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Aml                 - Where the AML descriptor is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert an internal resource descriptor to the corresponding
 *              external AML resource descriptor.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsSetDma (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    UINT8                   i;


    ACPI_FUNCTION_TRACE ("RsSetDma");


    /* Convert channel list to 8-bit DMA channel bitmask */

    Aml->Dma.DmaChannelMask = 0;
    for (i = 0; i < Resource->Data.Dma.ChannelCount; i++)
    {
        Aml->Dma.DmaChannelMask |= (1 << Resource->Data.Dma.Channels[i]);
    }

    /* Set the DMA Flag bits */

    Aml->Dma.Flags = (UINT8)
        (((Resource->Data.Dma.Type & 0x03) << 5) |
         ((Resource->Data.Dma.BusMaster & 0x01) << 2) |
          (Resource->Data.Dma.Transfer & 0x03));

    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_DMA, sizeof (AML_RESOURCE_DMA), Aml);
    return_ACPI_STATUS (AE_OK);
}

