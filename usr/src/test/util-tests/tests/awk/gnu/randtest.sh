# THIS PURPOSELY DOES NOT HAVE A !# LINE !!!!
#
# Date: Mon, 9 Sep 2013 14:49:43 -0700
# From: Bob Jewett <jewett@bill.scs.agilent.com>
# Message-Id: <201309092149.r89Lnh94010909@bill.scs.agilent.com>
# To: arnold@skeeve.com
# Subject: Re: [bug-gawk] Bug in random() in builtin.c
# 
# Hi Arnold,
# 
# Attached below is a script that tests gawk for this particular
# rand() problem.  The pair-wise combinations show a strong
# autocorrelation for a delay of 31 pairs of rand() samples. 
# 
# The script prints out the measured autocorrelation for a record
# of NSAMPLES pairs.  It also prints a fail message at the end if
# it fails. 
# 
# If you want to see the autocorrelation values, there is a print
# statement that if uncommented will save them to a file.
# 
# Please let me know if the mailer screws up the transfer or
# if you have any questions about the test.
# 
# Best regards,
# Bob
# 
# -------------- test_pair_power_autocorrelation -----------------------
# 
#!/bin/ksh

#GAWK=/bin/gawk

if [ -z "$AWK" ]; then
    printf '$AWK must be set\n' >&2
    exit 1
fi

# ADR: Get GAWK from the environment.
# Additional note: This wants ksh/bash for the use of $RANDOM below to
# seed the generator. However, shells that don't provide it won't be
# a problem since gawk will then seed the generator with the time of day,
# as srand() will be called without an argument.

# large NSAMPLES and NRUNS will bring any correlation out of the noise better
NSAMPLES=1024; MAX_ALLOWED_SIGMA=5; NRUNS=50;

$AWK 'BEGIN{ 
    srand('$RANDOM');
    nsamples=('$NSAMPLES');
    max_allowed_sigma=('$MAX_ALLOWED_SIGMA');
    nruns=('$NRUNS');
    for(tau=0;tau<nsamples/2;tau++) corr[tau]=0;

    for(run=0;run<nruns;run++) {
	sum=0;

	# Fill an array with a sequence of samples that are a
	# function of pairs of rand() values.

	for(i=0;i<nsamples;i++) {
	   samp[i]=((rand()-0.5)*(rand()-0.5))^2;
	   sum=sum+samp[i];
	   }

	# Subtract off the mean of the sequence:

	mean=sum/nsamples;
	for(i=0;i<nsamples;i++) samp[i]=samp[i]-mean;

	# Calculate an autocorrelation function on the sequence.
	# Because the values of rand() should be independent, there
	# should be no peaks in the autocorrelation.

	for(tau=0;tau<nsamples/2;tau++) {
	    sum=0;
	    for(i=0;i<nsamples/2;i++) sum=sum+samp[i]*samp[i+tau];
	    corr[tau]=corr[tau]+sum;
	    }

	}
    # Normalize the autocorrelation to the tau=0 value.

    max_corr=corr[0];
    for(tau=0;tau<nsamples/2;tau++) corr[tau]=corr[tau]/max_corr;

    # OPTIONALLY Print out the autocorrelation values:

    # for(tau=0;tau<nsamples/2;tau++) print tau, corr[tau] > "pairpower_corr.data";

    # Calculate the sigma for the non-zero tau values: 

    power_sum=0;

    for(tau=1;tau<nsamples/2;tau++) power_sum=power_sum+(corr[tau])^2;

    sigma=sqrt(power_sum/(nsamples/2-1));

    # See if any of the correlations exceed a reasonable number of sigma:

    passed=1;
    for(tau=1;tau<nsamples/2;tau++) {
	if ( abs(corr[tau])/sigma > max_allowed_sigma ) {
	    print "Tau=", tau ", Autocorr=", corr[tau]/sigma, "sigma";
	    passed=0;
	    }
        }
    if(!passed) {
	print "Test failed."
	exit(1);
        }
    else exit (0);
    }

function abs(abs_input) { return(sqrt(abs_input^2)) ; }
'
