/*******************************************************************************
 *
 * Module Name: rsirq - IRQ resource descriptors
 *              $Revision: 1.47 $
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

#define __RSIRQ_C__

#include "acpi.h"
#include "acresrc.h"

#define _COMPONENT          ACPI_RESOURCES
        ACPI_MODULE_NAME    ("rsirq")


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetIrq
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
AcpiRsGetIrq (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    UINT16                  Temp16 = 0;
    UINT32                  InterruptCount = 0;
    UINT32                  i;
    UINT32                  ResourceLength;


    ACPI_FUNCTION_TRACE ("RsGetIrq");


    /* Get the IRQ mask (bytes 1:2) */

    ACPI_MOVE_16_TO_16 (&Temp16, &Aml->Irq.IrqMask);

    /* Decode the IRQ bits (up to 16 possible) */

    for (i = 0; i < 16; i++)
    {
        if ((Temp16 >> i) & 0x01)
        {
            Resource->Data.Irq.Interrupts[InterruptCount] = i;
            InterruptCount++;
        }
    }

    /* Zero interrupts is valid */

    ResourceLength = 0;
    Resource->Data.Irq.InterruptCount = InterruptCount;
    if (InterruptCount > 0)
    {
        /* Calculate the structure size based upon the number of interrupts */

        ResourceLength = (UINT32) (InterruptCount - 1) * 4;
    }

    /* Get Flags (Byte 3) if it is used */

    if (AmlResourceLength == 3)
    {
        /* Check for HE, LL interrupts */

        switch (Aml->Irq.Flags & 0x09)
        {
        case 0x01: /* HE */
            Resource->Data.Irq.Triggering = ACPI_EDGE_SENSITIVE;
            Resource->Data.Irq.Polarity = ACPI_ACTIVE_HIGH;
            break;

        case 0x08: /* LL */
            Resource->Data.Irq.Triggering = ACPI_LEVEL_SENSITIVE;
            Resource->Data.Irq.Polarity = ACPI_ACTIVE_LOW;
            break;

        default:
            /*
             * Only _LL and _HE polarity/trigger interrupts
             * are allowed (ACPI spec, section "IRQ Format")
             * so 0x00 and 0x09 are illegal.
             */
            ACPI_DEBUG_PRINT ((ACPI_DB_ERROR,
                "Invalid interrupt polarity/trigger in resource list, %X\n",
                Aml->Irq.Flags));
            return_ACPI_STATUS (AE_BAD_DATA);
        }

        /* Get Sharing flag */

        Resource->Data.Irq.Sharable = (Aml->Irq.Flags >> 3) & 0x01;
    }
    else
    {
        /*
         * Default configuration: assume Edge Sensitive, Active High,
         * Non-Sharable as per the ACPI Specification
         */
        Resource->Data.Irq.Triggering = ACPI_EDGE_SENSITIVE;
        Resource->Data.Irq.Polarity = ACPI_ACTIVE_HIGH;
        Resource->Data.Irq.Sharable = ACPI_EXCLUSIVE;
    }

    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_IRQ;
    Resource->Length = ResourceLength + ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_IRQ);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetIrq
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
AcpiRsSetIrq (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_SIZE               DescriptorLength;
    UINT16                  IrqMask;
    UINT8                   i;


    ACPI_FUNCTION_TRACE ("RsSetIrq");


    /* Convert interrupt list to 16-bit IRQ bitmask */

    IrqMask = 0;
    for (i = 0; i < Resource->Data.Irq.InterruptCount; i++)
    {
        IrqMask |= (1 << Resource->Data.Irq.Interrupts[i]);
    }

    /* Set the interrupt mask */

    ACPI_MOVE_16_TO_16 (&Aml->Irq.IrqMask, &IrqMask);

    /*
     * The descriptor field is set based upon whether a third byte is
     * needed to contain the IRQ Information.
     */
    if ((Resource->Data.Irq.Triggering == ACPI_EDGE_SENSITIVE) &&
        (Resource->Data.Irq.Polarity == ACPI_ACTIVE_HIGH) &&
        (Resource->Data.Irq.Sharable == ACPI_EXCLUSIVE))
    {
        /* IrqNoFlags() descriptor can be used */

        DescriptorLength = sizeof (AML_RESOURCE_IRQ_NOFLAGS);
    }
    else
    {
        /* Irq() descriptor must be used */

        DescriptorLength = sizeof (AML_RESOURCE_IRQ);

        /* Set the IRQ Info byte */

        Aml->Irq.Flags = (UINT8)
            ((Resource->Data.Irq.Sharable & 0x01) << 4);

        if (ACPI_LEVEL_SENSITIVE == Resource->Data.Irq.Triggering &&
            ACPI_ACTIVE_LOW == Resource->Data.Irq.Polarity)
        {
            Aml->Irq.Flags |= 0x08;
        }
        else
        {
            Aml->Irq.Flags |= 0x01;
        }
    }

    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_IRQ, DescriptorLength, Aml);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetExtIrq
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
AcpiRsGetExtIrq (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    char                    *OutResourceString;
    UINT8                   Temp8;


    ACPI_FUNCTION_TRACE ("RsGetExtIrq");


    /* Get the flag bits */

    Temp8 = Aml->ExtendedIrq.Flags;
    Resource->Data.ExtendedIrq.ProducerConsumer =  Temp8 & 0x01;
    Resource->Data.ExtendedIrq.Polarity         = (Temp8 >> 2) & 0x01;
    Resource->Data.ExtendedIrq.Sharable         = (Temp8 >> 3) & 0x01;

    /*
     * Check for Interrupt Mode
     *
     * The definition of an Extended IRQ changed between ACPI spec v1.0b
     * and ACPI spec 2.0 (section 6.4.3.6 in both).
     *
     * - Edge/Level are defined opposite in the table vs the headers
     */
    Resource->Data.ExtendedIrq.Triggering =
        (Temp8 & 0x2) ? ACPI_EDGE_SENSITIVE : ACPI_LEVEL_SENSITIVE;

    /* Get the IRQ Table length (Byte4) */

    Temp8 = Aml->ExtendedIrq.TableLength;
    Resource->Data.ExtendedIrq.InterruptCount = Temp8;
    if (Temp8 < 1)
    {
        /* Must have at least one IRQ */

        return_ACPI_STATUS (AE_AML_BAD_RESOURCE_LENGTH);
    }

    /*
     * Add any additional structure size to properly calculate
     * the next pointer at the end of this function
     */
    Resource->Length = (Temp8 - 1) * 4;
    OutResourceString = ACPI_CAST_PTR (char,
        (&Resource->Data.ExtendedIrq.Interrupts[0] + Temp8));

    /* Get every IRQ in the table, each is 32 bits */

    AcpiRsMoveData (Resource->Data.ExtendedIrq.Interrupts,
        Aml->ExtendedIrq.InterruptNumber,
        (UINT16) Temp8, ACPI_MOVE_TYPE_32_TO_32);

    /* Get the optional ResourceSource (index and string) */

    Resource->Length += 
        AcpiRsGetResourceSource (AmlResourceLength,
            (ACPI_SIZE) Resource->Length + sizeof (AML_RESOURCE_EXTENDED_IRQ),
            &Resource->Data.ExtendedIrq.ResourceSource,
            Aml, OutResourceString);

    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_EXTENDED_IRQ;
    Resource->Length += ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_EXTENDED_IRQ);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetExtIrq
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
AcpiRsSetExtIrq (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_SIZE               DescriptorLength;


    ACPI_FUNCTION_TRACE ("RsSetExtIrq");


    /* Set the Interrupt vector flags */

    Aml->ExtendedIrq.Flags = (UINT8)
        ((Resource->Data.ExtendedIrq.ProducerConsumer & 0x01) |
        ((Resource->Data.ExtendedIrq.Sharable & 0x01) << 3) |
        ((Resource->Data.ExtendedIrq.Polarity & 0x1) << 2));

    /*
     * Set the Interrupt Mode
     *
     * The definition of an Extended IRQ changed between ACPI spec v1.0b
     * and ACPI spec 2.0 (section 6.4.3.6 in both).  This code does not
     * implement the more restrictive definition of 1.0b
     *
     * - Edge/Level are defined opposite in the table vs the headers
     */
    if (Resource->Data.ExtendedIrq.Triggering == ACPI_EDGE_SENSITIVE)
    {
        Aml->ExtendedIrq.Flags |= 0x02;
    }

    /* Set the Interrupt table length */

    Aml->ExtendedIrq.TableLength = (UINT8)
        Resource->Data.ExtendedIrq.InterruptCount;

    DescriptorLength = (sizeof (AML_RESOURCE_EXTENDED_IRQ) - 4) +
        ((ACPI_SIZE) Resource->Data.ExtendedIrq.InterruptCount * sizeof (UINT32));

    /* Set each interrupt value */

    AcpiRsMoveData (Aml->ExtendedIrq.InterruptNumber,
        Resource->Data.ExtendedIrq.Interrupts,
        (UINT16) Resource->Data.ExtendedIrq.InterruptCount,
        ACPI_MOVE_TYPE_32_TO_32);

    /* Resource Source Index and Resource Source are optional */

    DescriptorLength = AcpiRsSetResourceSource (Aml, DescriptorLength,
                            &Resource->Data.ExtendedIrq.ResourceSource);

    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_EXTENDED_IRQ,
        DescriptorLength, Aml);
    return_ACPI_STATUS (AE_OK);
}

