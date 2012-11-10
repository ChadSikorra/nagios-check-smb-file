#!/usr/bin/perl -w
#
# check_smb_file.pl
# Copyright (c) 2012, Chad Sikorra <chad.sikorra@gmail.com>
#
## LICENSE:
## This work is made available to you under the terms of version 3 of
## the GNU General Public License. A copy of that license should have
## been provided with this software.
## If not, see <http://www.gnu.org/licenses/>.
##
## This work is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
## General Public License for more details.
#
# Check for a file or folder on a SMB share

use strict;
use POSIX;
use Getopt::Long;
 
my $VERSION    = '0.2';
my $START_TIME = time();

# Some Nagios specific stuff
my $TIMEOUT = 15;
my %ERRORS=('OK'=> 0,'WARNING' => 1,'CRITICAL' => 2,'UNKNOWN' => 3,'DEPENDENT' => 4);

# Command line option variables...
my $o_host;
my $o_username;
my $o_password;
my $o_workgroup;
my $o_filepath;
my $o_file_property;
my $o_warning;
my $o_critical;
my $o_warning_match;
my $o_critical_match;
my $o_match_case;
my $o_help;
my $o_smbflag_kerberos;
my $o_debug = 0;
my %o_smbinit = ();

# The default property to test for
my $FILE_PROPERTY = 'MODIFIED';

# Valid file properties to test
my %VALUE_PROPERTY = (
    'SIZE' => {
        'STAT'    => 7,
        'MEASURE' => 'SIZE'
    },
    'ACCESSED' => {
        'STAT'    => 10,
        'MEASURE' => 'TIME'
    },
    'MODIFIED' => {
        'STAT'    => 11,
        'MEASURE' => 'TIME'
    }
);

# Valid measures for values
my %VALUE_MEASURE = (
    'TIME' => {
        'SECONDS' => 1,
        'MINUTES' => 60,
        'HOURS'   => 3600,
        'DAYS'    => 86400
    },
    'SIZE' => {
        'KB' => 1024,
        'MB' => 1048576,
        'GB' => 1073741824
    }
);

sub usage {
    my $format=shift;
    printf($format,@_);
    exit $ERRORS{'UNKNOWN'};
}

# Print the usage for this script
sub help {
    print <<EOT
Usage: \t$0 -H <hostname> -f <filepath>

This plugin tests the existence/age/size/contents of a file/folder on a SMB share.

    -H, --host            <Hostname>    The hostname to check (required)
    -f, --filename        <filename>    The share and path path to the file (required)
    -w, --warning         <value>       Warning if targeted file property exceeds value
    -c, --critical        <value>       Critical if targeted file property exceeds value
        --warning-match   <regex>       Warning if contents match regex
        --critical-match  <regex>       Critical if contents match regex
        --match-case                    Match should be case sensitive
    -p, --property        <property>    The property to test (Default: modified)
    -f, --kerberos                      Use Kerberos for authentication
    -U, --username        <Username>    The username to connect with
    -P, --password        <Password>    The password to authenticate with
    -W, --workgroup       <Workgroup>   The workgroup the username is located in
    -K, --kerberos                      Use Kerberos for authentication
    -d, --debug           <0-10>        Set the debug level for libsmbclient
    -V, --version                       Display the version of this script and exit
    -h, --help                          Display this usage screen and exit

Warning and Critical Values
---------------------------
    The returned value for a non-existent file/path is CRITICAL.

    A warning or critical value can be a measure of time or size, with a suffix
    detailing the measure type. The below table is a list of possible measures.

    Time    | Size
    -------- ---------------
    seconds | KB (kilobytes)
    minutes | MB (megabytes)
    hours   | GB (gigabytes)
    days    |

    You can test a few different properties of the file. The below table lists
    the valid properties.

    Property | Description
    --------- ----------------------
    modified | Last modified time
    accessed | Last accessed time
    size     | Size of the file

Examples
--------
   Check for the existence of a file called "log.txt" on the root of the C drive

        $0 -H fileserver -U username -P password -W domainname -f 'C\$\\log.txt'

   Warning if the modification date is older than 5 days, critical if 10 days

        $0 -H fileserver -U username -P password -W domainname -f 'SomeShare\\logs\\file.txt' \\
            -w 5days -c 10days

   Warning if the file size greater than 800 KB, critical greater than 2MB

        $0 -H fileserver -U username -P password -W domainname -f 'C\$\\log.txt' \\
            --property size -w 800KB -c 2MB

   Critical if the file contains a specific pattern (regex values allowed)

        $0 -H fileserver -U username -P password -W domainname -f 'SomeShare\\logs\\file.txt' \\
            --critical-match "^error"
EOT
}

# Given the value entered as a warning or critical value, determine the value to
# convert it to depending on the file propety and measure given
sub convertPropertyValue {
    my ($time_unit) = $_[0];
    my $return_value_unit = defined $_[1]; 
    my $stat_position;
    my $unit;
    $time_unit =~ /^([0-9]+)([A-Za-z]+)?$/;

    my $measure_type = $VALUE_PROPERTY{$FILE_PROPERTY}{'MEASURE'};

    if (defined $2 and !exists $VALUE_MEASURE{$measure_type}{uc $2}) {
        usage("Invalid time/size measure '$2' for property '$FILE_PROPERTY'\n");
    }

    if ($FILE_PROPERTY eq 'MODIFIED' || $FILE_PROPERTY eq 'ACCESSED') {
        $unit = defined $2 ? uc $2 : 'DAYS';
    }
    elsif ($FILE_PROPERTY eq 'SIZE') {
        $unit = defined $2 ? uc $2 : 'MB';
    }

    if ($return_value_unit) {
        return $unit;
    }

    return $VALUE_MEASURE{$measure_type}{$unit} * $1;
}

# Check a file stat property for a specified value
sub checkFileProperty {
    my ($value) = shift;
    my (@file_stat) = @{(shift)};
    my ($state_check) = shift;

    # Get the value we should compare after applying the specified measure (days,hours,MB,GB,etc)
    my $value_real = convertPropertyValue($value);
    my $value_unit = convertPropertyValue($value, 1);
    my $measure_type = $VALUE_PROPERTY{$FILE_PROPERTY}{'MEASURE'};
    my $value_convert = $VALUE_MEASURE{$measure_type}{$value_unit};
    my $value_stat = $VALUE_PROPERTY{$FILE_PROPERTY}{'STAT'};

    if ($value_stat == 7) {
       if ($file_stat[7] > $value_real) {
           my $readable =  sprintf("%.2f", $file_stat[7] / $value_convert);
           print "$state_check: File size ${readable}${value_unit}\n";
           exit $ERRORS{$state_check};
       }
    }
    elsif ($value_stat == 11 || $value_stat == 10) {
       if (($START_TIME - $file_stat[$value_stat]) > $value_real) {
           my $readable =  sprintf("%.2f", ($START_TIME - $file_stat[$value_stat]) / $value_convert);
           print "$state_check: File property '$FILE_PROPERTY' is ${readable} ${value_unit} old. Time for property is " . localtime($file_stat[$value_stat]) . "\n";
           exit $ERRORS{$state_check};
       }
    }
}

# Read a file over SMB and check its contents for any patterns
sub checkFileContents {
    my $smb = shift;
    my $filepath = shift;
    my $warning_match = shift;
    my $critical_match = shift;

    my $fd = $smb->open($filepath, '0666');
    while (defined(my $line = $smb->read($fd, 1024))) {
        last if $line eq '';
        checkFileForPattern($line, $critical_match,'CRITICAL') if ($critical_match);
        checkFileForPattern($line, $warning_match,'WARNING') if ($warning_match);
    }
    $smb->close($fd);
}

# Given data from a file, check it for a pattern
sub checkFileForPattern {
    my $line = shift;
    my $pattern = shift;
    my $state = shift;

    if ($o_match_case and $line =~ m/$pattern/) {
       print "$state: File matches pattern [[ $pattern ]]\n";
       exit $ERRORS{$state};
    }
    elsif (!$o_match_case and $line =~ m/$pattern/i) {
       print "$state: File matches pattern [[ $pattern ]]\n";
       exit $ERRORS{$state};
    }
}

# Return the list of property values from a stat of a file
sub getFileStat {
    my $filepath = shift;
    my $smb = shift;

    my @filestat = $smb->stat($filepath);

    return \@filestat;
}

# Parse command line options...
Getopt::Long::Configure ("bundling");
GetOptions(
  'p|property=s'     => \$o_file_property,
  'f|filename=s'     => \$o_filepath,
  'w|warning=s'      => \$o_warning,
  'c|critical=s'     => \$o_critical,
  'warning-match=s'  => \$o_warning_match,
  'critical-match=s' => \$o_critical_match,
  'match-case'       => \$o_match_case,
  'H|host=s'         => \$o_host,
  'K|kerberos'       => \$o_smbflag_kerberos,
  'W|workgroup=s'    => \$o_smbinit{'workgroup'},
  'U|username=s'     => \$o_smbinit{'username'},
  'P|password=s'     => \$o_smbinit{'password'},
  'd|debug=i'        => \$o_smbinit{'debug'},
  'h|help'           => \$o_help,
  'V|version'        => sub { print "$VERSION\n"; exit 0; }
);
if ($o_help) { help(); exit 0}

# Some mandatory option checks
if (!$o_host) { usage("Host not specified\n"); }
if (!$o_filepath) { usage("File path not specified\n"); }
if ($o_file_property) {
   if (!exists $VALUE_PROPERTY{uc $o_file_property}) { usage("Invalid file property\n"); }
   $FILE_PROPERTY = uc $o_file_property;
}
if ($o_critical and $o_warning) {
    if (convertPropertyValue($o_critical) <= convertPropertyValue($o_warning)) {
        usage("The warning value must be less than the critical value\n"); 
    }
}

# Gracefully test for the Filesys::SmbClient module...
eval {
    require Filesys::SmbClient;
    Filesys::SmbClient->import;
};
if ( $@ ) {
    print "Missing Perl module Filesys::SmbClient\n";
    exit $ERRORS{'UNKNOWN'};
}
use Filesys::SmbClient 'SMB_CTX_FLAG_USE_KERBEROS';

# Cleanup the SmbClient init hash...
defined $o_smbinit{$_} or delete $o_smbinit{$_} for keys %o_smbinit;

# Replace any backslashes in the path for convenience...
$o_filepath =~ s/\\/\//g;
my $full_file_path = 'smb://' . $o_host . '/' . $o_filepath;

# By default libsmbclient will attempt to create a smb.conf file in
# the home directory as specified from the environment variable HOME. In
# some cases this is set to /root or a directory that cannot be written
# to. So work-around that here if needed...
if (!$ENV{'HOME'} || ! -w $ENV{'HOME'}) {
    $ENV{'HOME'} = '/tmp';
}
if (!-e "$ENV{HOME}/.smb/smb.conf") {
    # Attempt to create a smb.conf file for libsmbclient...
    mkdir "$ENV{HOME}/.smb", 0755 unless (-e "$ENV{HOME}/.smb");
    if (!open(F, ">$ENV{HOME}/.smb/smb.conf")) {
        print "Cannot create $ENV{HOME}/.smb/smb.conf: $!\n";
        exit $ERRORS{'UNKNOWN'};
    }
    close(F);
}

# Create the actual SMB object to access files from the hostname specified
my $smb = new Filesys::SmbClient(%o_smbinit);
$smb->set_flag(SMB_CTX_FLAG_USE_KERBEROS) if ($o_smbflag_kerberos);

my (@fileStat) = @{ getFileStat($full_file_path, $smb) };

# If we can not access the initial file/folder, throw a critical error
if ($#fileStat == 0) {
    print "CRITICAL: $! \n";
    exit $ERRORS{'CRITICAL'};
}

checkFileProperty($o_critical, \@fileStat, 'CRITICAL') if ($o_critical);
checkFileProperty($o_warning, \@fileStat,   'WARNING') if ($o_warning);
checkFileContents($smb, $full_file_path, $o_warning_match, $o_critical_match) if ($o_warning_match || $o_critical_match);

# If we made it this far then everything is OK...
print "OK: file/directory found.\n";
exit $ERRORS{'OK'};
