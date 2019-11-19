#!/usr/bin/perl

$limit = 2;
$counter = 0;
$last_target = "";
@addr_pool = ();

while(<>) {
    chop;

    #printf("<%s>\n", $_);

    #
    # Skip timestamp
    #
    if (/^[A-Z][a-z]+ [A-Z][a-z]+ \d+ /) {
	##print "not matched\n";
	next;
    }

    #
    # Get the intruder's address
    #
    $target = "";
    @line = split();
    if ($line[2] =~ /^(\d+\.\d+\.\d+\.\d+)/) {
	$target = $1;
    }
    elsif ($line[3] =~ /^(\d+\.\d+\.\d+\.\d+)/) {
	$target = $1;
    }

    #
    # How many continuous attack?
    #
    if ($target eq $last_target) {
	if ($counter < $limit) {
	    printf("%s: counter = %s\n", $target, $counter);
	    $counter++;
	    next;
	}

	# limit counter is exceeded
	# Check if same address?
	#

	##printf("target = %s\n", $target);

	$where = -1;
	for($[ .. $#addr_pool) {
	    $where = $_, last if ($addr_pool[$_] eq $target);
	}
	if ($target ne "" && $where == -1) {
	    #
	    # new intruder coming
	    #
	    ##printf("%s: counter limit = %d\n", $target, $counter);
	    $line = sprintf("./ipsimple -I deny %s\n", $target);
	    print $line;
	    #system("execute something for %s\n", $line);

	    push(@addr_pool, $target);

	    ##print @addr_pool, "\n";

	}
	$counter = 0;
    }
    else {
	# something jam or not serious attack,
	# then reset counter
	$counter = 1;
	$last_target = $target;
    }
}
