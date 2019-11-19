#!/usr/bin/perl

$debug = 1; # 0: silent mode/no-log, 1: log to file, 2: verbose mode, 3...: real debug mode
$only_check = 0; # 0: Execute, 1: Just Show, Not Execute

$fname = "/var/log/secure-deny.log";
$limit = 3;

$popfail_limit = 3;
$popfail_special_add = 3; #old=5
$popfail_counter = 0;
$last_popfail_ip = "";

$pop_counter = 0;
$pop_limit = 3;
$pop_candidate_hour = -1;
$pop_candidate_min = -1;

$last_pop_hour = -1;
$last_pop_min = -1;
$last_pop_sec = -1;
$last_pop_ip = "";
$last2_pop_hour = -1;
$last2_pop_min = -1;
$last2_pop_sec = -1;
$last2_pop_ip = "";

$passwd_limit = 5;
$maxerr_limit = 6;
$counter = 0;
$last_target = "";

$reason = "";

@addr_pool = ();

if ($debug <= 1) {
    open(FILE, ">> $fname") || die "Can't open $fname: $!\n";
}
else {
    open(FILE, ">> /tmp/secure-$$") || die "Can't open $fname: $!\n";
}

while(<>) {
    chop;

    $ssh_fail = 0;
    $ssh_illegal = 0;
    $ftp_root = 0;
    $ftp_passwd = 0;
    $ftp_nosuch = 0;
    $ftp_admin = 0;
    $ftp_maxerr = 0;
    $pop3fail = 0;
    $target = "";

    ### printf("<%s>\n", $_) if ($debug > 2); ###

    #
    # Get the intruder's address
    #

    @line = split();

    #
    # pop3 check
    #
    if ($line[4] =~ /^pop/) {
      @poptime = split(/:/, $line[2]);
      $pop_hour = $poptime[0];
      $pop_min  = $poptime[1];
      $pop_sec  = $poptime[2];

      if ($line[9] eq "-ERR" &&
          $line[8] =~ /^\((\d+\.\d+\.\d+\.\d+)/ &&
          ($line[10] eq "[AUTH]" || ($line[7] !~ /\.jp$/ && $line[5] eq "(null)")) ) {

	$target = $1;
	if ($debug > 1) {
	    printf("ERR: = %s\n", $target);
	}
	$pop3fail = 1;
      }
      elsif ($line[6] eq "Servicing" &&
             $line[11] =~ /^(\d+\.\d+\.\d+\.\d+)/) {

	$target = $1;
        if (($last_pop_hour == $pop_hour
            && $last_pop_min == $pop_min
            && $last_pop_sec == $pop_sec
            && $last_pop_ip eq $pop_ip)
         && ($last2_pop_hour == $pop_hour
            && $last2_pop_min == $pop_min
            && $last2_pop_sec == $pop_sec
            && $last2_pop_ip eq $pop_ip)) {

            if ($debug > 5) {
                printf("popip: = %s, %d:%d\n",
                       $target, $pop_hour, $pop_min);
            }
	    $pop3fail = 2;

            #failed, refresh the last status
            $last_pop_hour = -1;
            $last_pop_min = -1;
            $last_pop_sec = -1;
            $last_pop_ip = "";
        }
        else {
            $last2_pop_hour = $last_pop_hour;
            $last2_pop_min = $last_pop_min;
            $last2_pop_sec = $last_pop_sec;
            $last2_pop_ip = $last_pop_ip;

            $last_pop_hour = $pop_hour;
            $last_pop_min = $pop_min;
            $last_pop_sec = $pop_sec;
            $last_pop_ip = $pop_ip;

            next;
        }
      }
    }
    else {
      #
      # Skip timestamp
      #
      if ($line[4] =~ /^sshd/) {
        ### printf("sshd not matched = <%s>\n", $line[4]); ###
	$target = "sshd";
      }
      elsif ($line[4] =~ /^proftpd/) {
        ### printf("proftpd not matched = <%s>\n", $line[4]); ###
	$target = "proftpd";
      }
      else {
        next;
      }

      if ($debug > 2) {
	print "!!3..12!! $line[3] $line[4] $line[5] $line[6] $line[7] $line[8] $line[9] $line[10] $line[11] $line[12]\n"; ###
      }
      if ($target eq "sshd") {
        $ssh_fail = $line[5] =~ /^Failed/;
        $ssf_illegal = $line[5] =~ /^Illegal/ || $line[5] =~ /^Invalid/ ;
      }
      elsif ($target eq "proftpd") {
        $ftp_root = 1 if ($line[8] eq "USER" && $line[9] =~ /root/);
        $ftp_admin = 1 if ($line[8] eq "USER" && $line[9] =~ /^admin/i);
        $ftp_nosuch = 1 if ($line[10] eq "no" && $line[11] eq "such");
        $ftp_maxerr = 1 if ($line[8] eq "Maximum");

        if ($debug > 2) {
            printf("*FTP*: root = %d, admin = %d, nosuch = %d, maxerr = %d\n",
		   $ftp_root, $ftp_admin, $ftp_nosuch, $ftp_maxerr);
        }
      }
    }
    printf("**Candidate !!<%s>\n", $_) if ($debug > 2); ###

    if ($pop3fail > 0) {
        if ($debug > 1) {
            printf("**pop3_fail(%d) = <%s>\n", $pop3fail, $target);
        }
        $last2_pop_min = "";
        $last_pop_min = "";
    }
    elsif ($ssh_illegal && $line[9] =~ /^(\d+\.\d+\.\d+\.\d+)/) {
        $target = $1;
        if ($debug > 1) {
            printf("**ssh_illegal = <%s>\n", $target);
        }
    }
    elsif ($ssh_fail && $line[10] =~ /^(\d+\.\d+\.\d+\.\d+)/) {
        $target = $1;
        if ($debug > 1) {
            printf("**ssh_fail = <%s>\n", $target);
        }
    }
    elsif ($ssh_fail && $line[12] =~ /^(\d+\.\d+\.\d+\.\d+)/) {
        $target = $1;
        if ($debug > 1) {
            printf("**ssh_fail(2) = <%s>\n", $target);
        }
    }

    elsif (($ftp_root || $ftp_passwd || $ftp_nosuch || $ftp_maxerr)
	   && $line[6] =~ /\[(\d+\.\d+\.\d+\.\d+)\]/) {
	$target = $1;
	if ($debug > 1) {
	    printf("**ftp-fail = <%s>\n", $target);
	}
    }
    else {
        next;
    }

    #
    # How many continuous attack?
    #
    if ($target eq $last_target) {

        if ($ftp_passwd && $counter < $passwd_limit) {
            if ($debug > 1) {
                printf("*** PASSWD: %s: counter = %s\n", $target, $counter); ###
            }
            $counter++;
            $reason = "PWD";
            next;
        }
        elsif ($ftp_maxerr && $counter < $maxerr_limit) {
            if ($debug > 1) {
                printf("*** MXERR: %s: counter = %s\n", $target, $counter); ###
            }
            $counter++;
            $reason = "TRY";
            next;
        }

        elsif ($pop3fail == 1) {
            if ($pop_candidate_hour != $pop_hour || $target != $last_popfail_ip) {
                if ($debug > 1) {
                    printf("*** POP3-FAIL %s: first candidate_hour = %s, hour = %s, last = %s\n",
                           $target, $pop_candidate_hour, $pop_hour, $last_popfail_ip); ###
                }
                $last_pop_hour = $pop_hour;
                $last_pop_min = $pop_min;
                $pop_candidate_hour = $pop_hour;
                $pop_candidate_min = $pop_min;
                $last_pop_ip = $target;
                $last_popfail_ip = $target;
                $popfail_counter = 1;
                $pop_counter = $popfail_special_add;
                next;
            }

            #last_popfail_ip is the same!
            #if ($pop_candidate_min == $pop_min) { # old
            if ($pop_candidate_min == $pop_min || ($pop_candidate_min + 1) == $pop_min) {
                # second time,
                if ($debug > 1) {
                    printf("*** POP3-SFAIL: too many failes in short term: %s: counter = %s\n", $target, $counter); ###
                }
                $reason = "SFAIL";
                $last_pop_hour = -1;
                $last_pop_min = -1;
                $pop_candidate_hour = -1;
                $pop_candidate_min = -1;
                $last_pop_ip = "";
                $last_popfail_ip = "";
                $pop_counter = 0;
                $popfail_counter = 0;
                #fall to error
            }
            elsif ($popfail_counter < $popfail_limit) {
                #OK, still allowed
                if ($debug > 1) {
                    printf("*** POP3-FAIL candidate: %s: counter = %s\n", $target, $counter); ###
                }
                $reason = "FAIL";
                $last_pop_hour = $pop_hour;
                $last_pop_min = $pop_min;
                $pop_candidate_hour = $pop_hour;
                $pop_candidate_min = $pop_min;
                $last_pop_ip = $target;
                $last_popfail_ip = $target;

                $pop_counter += $popfail_special_add;
                $popfail_counter++;
                next;
            }

            else {
                # POP3-FAILED
                if ($debug > 1) {
                    printf("*** POP3-FAIL %s: counter = %s\n", $target, $counter); ###
                }
                $reason = "FAIL";
                $last_pop_hour = -1;
                $last_pop_min = -1;
                $pop_candidate_hour = -1;
                $pop_candidate_min = -1;
                $last_pop_ip = "";
                $last_popfail_ip = "";
                $pop_counter = 0;
                $popfail_counter = 0;
                #fall to error
            }
        }

        elsif ($pop3fail == 2) {
            if ($pop_counter < $pop_limit) {
		if ($pop_candidate_min == $pop_min && $pop_candidate_hour == $pop_hour) {
		    if ($debug > 1) {
			printf("*** POP3 %s: counter = %s\n", $target, $counter); ###
		    }
		    $pop_counter++;
		    $reason = "POP";
		    next;
		}
		else {
                    ##$pop_candidate_min != $pop_min;
                    if ($debug > 1) {
                        printf("*** POP3 %s: (%d:%d) RESET pop_counter = %s\n",
                               $target, $pop_candidate_min, $pop_min, $pop_counter); ###
                    }
                    $reason = "POP";
                    $last_pop_hour = $pop_hour;
                    $last_pop_min = $pop_min;
                    $pop_candidate_hour = $pop_hour;
                    $pop_candidate_min = $pop_min;

                    if ($target eq $last_pop_ip) {
                        $pop_counter = 2;
                    }
                    else {
                        $pop_counter = 1;
                    }
                    $last_pop_ip = $target;
                    next;
                }
	    }
            else {
                $reason = "POP";
                $last_pop_hour = -1;
                $last_pop_min = -1;
                $pop_candidate_hour = -1;
                $pop_candidate_min = -1;
                $last_pop_ip = "";
                $last_popfail_ip = "";

                $pop_counter = 0;
                $popfail_counter = 0;
                # fall to error
            }
	}

        elsif ($counter < $limit) {
	    if ($debug > 1) {
		printf("%s: counter = %s\n", $target, $counter); ###
	    }
            $counter++;
            $reason = "SSH";
            next;
        }

        # limit counter is exceeded
        # Check if the same address?
        #
        $where = -1;
        for($[ .. $#addr_pool) {
            $where = $_, last if ($addr_pool[$_] eq $target);
        }
        if ($target ne "" && $where == -1) {
            #
            # new intruder coming
            #
            $line = sprintf("/usr/local/bin/ipsimple -I -a deny -S %s/32\n", $target);
            if ($debug > 0) {
		chop($date =`date`);
                print FILE $date . " [" . $reason  ."] : " . $line;
                ##print FILE $date . ": " . $line;
            }
	    if ($only_check == 0) {
		system($line);
	    }
	    if ($debug > 1) {
		printf("**system = <%s>\n", $line); ###
	    }
            push(@addr_pool, $target);
	    if ($debug > 3) {
		print @addr_pool, "\n";
	    }
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

sleep(1);

if ($only_check == 0) {
    system("/usr/local/bin/secure.pl < /tmp/secure &");
}
