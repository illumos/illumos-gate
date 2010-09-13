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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */

import org.opensolaris.os.dtrace.*;
import java.io.File;

public class TestAPI2 {
    public static void
    main(String[] args)
    {
	if (args.length < 1) {
	    System.err.println("Usage: java TestAPI2 <script> " +
		    "[ macroargs... ]");
	    System.exit(2);
	}

	File file = new File(args[0]);
	String[] macroArgs = new String[args.length - 1];
	System.arraycopy(args, 1, macroArgs, 0, (args.length - 1));

	Consumer consumer = new LocalConsumer();
	consumer.addConsumerListener(new ConsumerAdapter() {
	    public void dataReceived(DataEvent e) {
		// System.out.println(e.getProbeData());
		ProbeData data = e.getProbeData();
		java.util.List < Record > records = data.getRecords();
		for (Record r : records) {
		    if (r instanceof ExitRecord) {
		    } else {
			System.out.println(r);
		    }
		}
	    }
	});

	try {
	    consumer.open();
	    consumer.compile(file, macroArgs);
	    consumer.enable();
	    consumer.go();

	    Aggregate a;
	    do {
		Thread.sleep(1000);
		a = consumer.getAggregate();
		if (!a.asMap().isEmpty()) {
		    System.out.println(a);
		}
	    } while (consumer.isRunning());
	} catch (Exception e) {
	    e.printStackTrace();
	    System.exit(1);
	}
    }
}
