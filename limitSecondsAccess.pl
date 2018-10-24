#!/usr/bin/perl

use strict;
use warnings;
use utf8;
use Time::HiRes qw(gettimeofday);
use CGI;
use File::Basename;
use JSON;

# Definition
sub limitSecondsAccess {

    eval {
        # Init
        ## Access Timestamp Build
        my ($sec_timestamp, $usec_timestamp) = gettimeofday();
        my $sec_usec_timestamp = ($sec_timestamp . '.' . $usec_timestamp) + 0;

        ## Access Limit Default Value
        ### Depends on Specifications: For Example 10
        my $access_limit = 10;

        ## Roots Build
        ### Depends on Environment: For Example '/tmp'
        my $tmp_root = '/tmp';
        my $access_root = $tmp_root . '/access';

        ## Auth Key
        ### Depends on Specifications: For Example 'app_id'
        my $auth_key = 'app_id';

        ## Response Content-Type
        ## Depends on Specifications: For Example JSON and UTF-8

        ## Response Bodies Build
        ### Depends on Design
        my %response_bodies;

        # Authorized Key Check
        my $CGI = new CGI;
        if (! defined($CGI->param($auth_key))) {
            die('Unauthorized`401`');
        }
        my $auth_id = $CGI->param($auth_key);

        # The Auth Root Build
        my $auth_root = $access_root . '/' . $auth_id;

        # The Access Root Check
        if (! -d $access_root) {
            ## The Access Root Creation
            if (! mkdir($access_root)) {
                die('Could not create the access root. ' . $access_root . '`500`');
            }
        }

        # The Auth Root Check
        if (! -d $auth_root) {
            ## The Auth Root Creation
            if (! mkdir($auth_root)) {
                die('Could not create the auth root. ' . $auth_root . '`500`');
            }
        }

        # A Access File Creation Using Micro Timestamp
        ## For example, other data resources such as memory cache or RDB transaction.
        ## In the case of this sample code, it is lightweight because it does not require file locking and transaction processing.
        ## However, in the case of a cluster configuration, file system synchronization is required.
        my $access_file_path = $auth_root . '/' . $sec_usec_timestamp;
        if (! open(FH, '>', $access_file_path)) {
            close FH;
            die('Could not create the access file. ' . $access_file_path . '`500`');
        }
        close FH;

        # The Auth Root Scanning
        my @file_pathes = glob($auth_root . "/*");
        if (! @file_pathes) {
            die('Could not scan the auth root. ' . $auth_root . '`500`');
        }

        # The Access Counts Check
        my $access_counts = 0;
        foreach my $file_path (@file_pathes) {

            ## Not File Type
            if (! -f $file_path) {
                next;
            }

            ## The Base Name Extract
            my $base_name = basename($file_path);

            ## The Base Name to Integer Data Type
            my $base_name_sec_timestamp = int($base_name);

            ## Same Seconds Timestamp
            if ($sec_timestamp eq $base_name_sec_timestamp) {
            
                ## The Base Name to Float Data Type
                my $base_name_sec_usec_timestamp = $base_name;

                ### A Overtaken Processing
                if ($sec_usec_timestamp lt $base_name_sec_usec_timestamp) {
                    next;
                }

                ### Access Counts Increment
                $access_counts++;

                ### Too Many Requests
                if ($access_counts > $access_limit) {
                    die("Too Many Requests`429`");
                }

                next;
            }

            ## Past Access Files Garbage Collection
            if ($sec_timestamp gt $base_name_sec_timestamp) {
                unlink($file_path);
            }
        }
    };

    if ($@) {
        # Error Elements Extract
        my @e = split(/`/, $@);

        # Exception to HTTP Status Code
        my $http_status = $e[0];
        my $http_code = '0';
        if (defined($e[1])) {
            $http_code = $e[1];
        }

        # 4xx
        if ($http_code ge '400' && $http_code le '499') {
            # logging
            ## snip...
        # 5xx
        } elsif ($http_code ge '500') {
            # logging
            ## snip...

            ## The Exception Message to HTTP Status
            $http_status = 'foo';
        # Others
        } else {
            # logging
            ## snip...

            $http_status = 'Internal Server Error';
            $http_code = '500';
        }

        # Response Headers Feed
        print("Status: " . $http_code . " " . $http_status . "\n");
        print('Content-Type: application/json; charset=utf-8' . "\n\n");

        # A Response Body Build
        my %response_bodies;
        $response_bodies{'message'} = $http_status;
        $a = \%response_bodies;
        my $response_body = encode_json($a);

        # The Response Body Feed
        print($response_body);
    }

}

# #Excecution
&limitSecondsAccess();
