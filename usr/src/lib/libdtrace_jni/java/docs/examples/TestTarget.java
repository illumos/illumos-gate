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

public class TestTarget {
    public static void
    main(String[] args)
    {
	if (args.length != 2) {
	    System.err.println("Usage: java TestTarget <script> <command>");
	    System.exit(2);
	}

	File file = new File(args[0]);
	String command = args[1];

	final Consumer consumer = new LocalConsumer();
	consumer.addConsumerListener(new ConsumerAdapter() {
	    public void dataReceived(DataEvent e) {
		System.out.println(e.getProbeData());
	    }
	    public void consumerStopped(ConsumerEvent e) {
		try {
		    Aggregate a = consumer.getAggregate();
		    for (Aggregation agg : a.asMap().values()) {
			for (AggregationRecord rec : agg.asMap().values()) {
			    System.out.println(rec.getTuple() + " " +
				    rec.getValue());
			}
		    }
		} catch (Exception x) {
		    x.printStackTrace();
		    System.exit(1);
		}
		consumer.close();
	    }
	    public void processStateChanged(ProcessEvent e) {
		System.out.println(e.getProcessState());
	    }
	});

	try {
	    consumer.open();
	    // pid replaces $target variable in D script
	    consumer.createProcess(command);
	    consumer.compile(file);
	    consumer.enable();
	    consumer.go();
	} catch (Exception e) {
	    e.printStackTrace();
	    System.exit(1);
	}
    }
}
