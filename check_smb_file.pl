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

#####################################################################################
### Variable Declarations
#####################################################################################
my $VERSION    = '0.5';
my $START_TIME = time();

#------------------------------------------------------------------------------------
# Some Nagios specific stuff
#------------------------------------------------------------------------------------
my $TIMEOUT = 15;
my %ERRORS=('OK'=> 0,'WARNING' => 1,'CRITICAL' => 2,'UNKNOWN' => 3,'DEPENDENT' => 4);

#------------------------------------------------------------------------------------
# Command line option variables
#------------------------------------------------------------------------------------
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
my $o_warning_files;
my $o_critical_files;
my $o_filename_match;
my $o_expand_datetime;
my $o_mode_directory;
my $o_match_case;
my $o_smbflag_kerberos;
my $o_no_data;
my $o_debug = 0;
my %o_smbinit = ();

#------------------------------------------------------------------------------------
# Variables and table info data used in subs and main script execution
#------------------------------------------------------------------------------------

# The critical and warining values split into distict pieces
my ($critical_value, $critical_uom, $warning_value, $warning_uom);

# Store relevant performance data here as the script progresses
my %PERF_DATA = ();

# If a warning/critical value is matched during execution, store the state here
my $ERROR_STATE;

# The default property to test for
my $FILE_PROPERTY = 'MODIFIED';

# Valid file properties to test
my %VALUE_PROPERTY = (
    'SIZE' => {
        'STAT'        => 7,
        'MEASURE'     => 'SIZE',
        'LABEL'       => 'size',
        'DEFAULT_UOM' => 'MB'
    },
    'ACCESSED' => {
        'STAT'        => 10,
        'MEASURE'     => 'TIME',
        'LABEL'       => 'lastAccessed',
        'DEFAULT_UOM' => 'DAYS'
    },
    'MODIFIED' => {
        'STAT'        => 11,
        'MEASURE'     => 'TIME',
        'LABEL'       => 'lastModified',
        'DEFAULT_UOM' => 'DAYS'
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

#####################################################################################
### Begin Subroutines 
#####################################################################################

#------------------------------------------------------------------------------------
# From Nagios utils. Prints a message on incorrect script usage
#------------------------------------------------------------------------------------
sub usage {
    my $format=shift;
    printf($format,@_);
    exit $ERRORS{'UNKNOWN'};
}

#------------------------------------------------------------------------------------
# Print the usage information for this script
#------------------------------------------------------------------------------------
sub help {
    print <<EOT
Usage: \t$0 -H <hostname> -f <filepath>

This plugin tests the existence/age/size/contents of a file/folder on a SMB share.

    -H, --host            <hostname>    The hostname to check (required)
    -f, --filename        <filename>    The share and path to the file/directory (required)
    -F  --filename-match  <regex>       Only check filenames matching this regex
    -D  --mode-directory                Treat the filename to check as a directory
    -w, --warning         <value>       Warning if file property exceeds value
    -c, --critical        <value>       Critical if file property exceeds value
    -m, --warning-match   <regex>       Warning if contents match regex
    -M, --critical-match  <regex>       Critical if contents match regex
    -t, --warning-files   <value>       Warning if the total files detected exceeds value
    -T, --critical-files  <value>       Critical if the total files detected exceeds value
    -p, --property        <property>    The property to test (Default: modified)
    -K, --kerberos                      Use Kerberos for authentication
    -U, --username        <username>    The username to connect with
    -P, --password        <password>    The password to authenticate with
    -W, --workgroup       <workgroup>   The workgroup the username is located in
    -K, --kerberos                      Use Kerberos for authentication
    -n, --no-data                       Do not collect performance data
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

File Paths
----------
    File paths are checked with forward slashes. So a path to check should be entered
    with forward slashes and not back slashes, such as...

    SomeShare/some_directory/some_file.txt

    However, if you enter back slashes the script will attempt to convert them to
    forward slashes and check the resulting path. Also, you can check hidden and 
    admin shares, such as the system drive, by using a double dollar sign in nagios
    commands...

    C\$\$/some_directory/some_file.txt

    Also note that file path checks are case-insensitive.

Examples
--------
    Check for the existence of a file called "log.txt" on the root of the C drive

    $0 -H fileserver -U username -P password -W domainname -f 'C\$\$/log.txt'

    Warning if the modification date is older than 5 days, critical if 10 days

    $0 -H fileserver -U username -P password -W domainname -f 'Share/log/file.txt' \\
        -w 5days -c 10days

    Warning if the file size greater than 800 KB, critical greater than 2MB

    $0 -H fileserver -U username -P password -W domainname -f 'C\$\$/log.txt' \\
        --property size -w 800KB -c 2MB

    Critical if the file contains a specific pattern (regex values allowed)

    $0 -H fileserver -U username -P password -W domainname -f 'Share/log/file.txt' \\
        --critical-match "^error"
EOT
}

#------------------------------------------------------------------------------------
# Convert an entered value to the value needed for the file property
#------------------------------------------------------------------------------------
sub convertPropertyValue {
    my ($value_entered, $uom) = @_;
    my $measure_type = $VALUE_PROPERTY{$FILE_PROPERTY}{'MEASURE'};

    return $VALUE_MEASURE{$measure_type}{$uom} * $value_entered;
}

#------------------------------------------------------------------------------------
# Split an entered critical/warning value into its distinct parts: The value and UOM
#------------------------------------------------------------------------------------
sub splitPropertyValue {
    my $full_value = shift;
    my $measure_type = $VALUE_PROPERTY{$FILE_PROPERTY}{'MEASURE'};
    my $unit;

    $full_value =~ /^([0-9]+)([A-Za-z]+)?$/;
    if (!defined $1) {
        usage("Invalid value '$full_value'\n");
    }
    if (defined $2 and !exists $VALUE_MEASURE{$measure_type}{uc $2}) {
        usage("Invalid measure '$2' for property '$FILE_PROPERTY'\n");
    }
    $unit = defined $2 ? uc $2 : $VALUE_PROPERTY{$FILE_PROPERTY}{'DEFAULT_UOM'};

    return ($1, $unit);
}

#------------------------------------------------------------------------------------
# Check a file stat property for a specified value
#------------------------------------------------------------------------------------
sub checkFilePropertyValue {
    my ($value) = shift;
    my ($uom) = shift;
    my (@file_stat) = @{(shift)};
    my $output;

    # Get the value we should compare after applying the specified measure
    my $value_real = convertPropertyValue($value, $uom);
    my $measure_type = $VALUE_PROPERTY{$FILE_PROPERTY}{'MEASURE'};
    my $value_convert = $VALUE_MEASURE{$measure_type}{$uom};
    my $value_stat = $VALUE_PROPERTY{$FILE_PROPERTY}{'STAT'};

    if ($value_stat == 7) {
        if ($file_stat[7] > $value_real) {
            my $readable =  sprintf("%.2f", $file_stat[7] / $value_convert);
            $output = "File size ${readable}${uom}";
        }
    }
    elsif ($value_stat == 11 || $value_stat == 10) {
        if (($START_TIME - $file_stat[$value_stat]) > $value_real) {
            my $readable =  sprintf(
                "%.2f",
                ($START_TIME - $file_stat[$value_stat]) / $value_convert
            );
            $output = "File property '$FILE_PROPERTY' is ${readable} ${uom} old. "
                . "Time for property is " . localtime($file_stat[$value_stat]) . "'";
       }
    }

    return $output;
}

#------------------------------------------------------------------------------------
# Read a file over SMB and check its contents for any patterns
#------------------------------------------------------------------------------------
sub checkFileContents {
    my $smb = shift;
    my $filepath = shift;
    my $warning_match = shift;
    my $critical_match = shift;
    my $check_state = 'OK';
    my $output;

    my $fd = $smb->open($filepath, '0666');
    while (defined(my $line = $smb->read($fd, 1024))) {
        last if $line eq '';
        if ($critical_match and checkFileForPattern($line, $critical_match)) {
            $output = "File matches pattern [[ $critical_match ]]";
            $check_state = 'CRITICAL';
            last;
        }
        if ($warning_match and checkFileForPattern($line, $warning_match)) {
            $output = "File matches pattern [[ $warning_match ]]";
            $check_state = 'WARNING';
            last;
        }
    }
    $smb->close($fd);

    return ($output, $check_state);
}

#------------------------------------------------------------------------------------
# Given data from a file, check it for a pattern
#------------------------------------------------------------------------------------
sub checkFileForPattern {
    my $line = shift;
    my $pattern = shift;

    if ($o_match_case and $line =~ m/$pattern/) {
        return 1
    }
    elsif (!$o_match_case and $line =~ m/$pattern/i) {
        return 1;
    }

    return 0;
}

#------------------------------------------------------------------------------------
# Print the plugin output and exit with the correct status
#------------------------------------------------------------------------------------
sub showOutputAndExit {
    my $error_state = $_[1];
    my $output = "$error_state: " . $_[0];

    if (keys %PERF_DATA) {
        $output .= '|';
        while (my ($key, $value) = each(%PERF_DATA)) {
            $output .= "'" . $$value{'LABEL'} . "'=" . $$value{'VALUE'}
             . $$value{'UOM'} . ';' . $$value{'WARN'} . ';' . $$value{'CRIT'} . ";;";
        }
    }
    print $output . "\n";

    exit $ERRORS{$error_state};
}

#------------------------------------------------------------------------------------
# Determine the default UOM to use for performance data
#------------------------------------------------------------------------------------
sub determineDefaultUom {
    my $warn_uom = shift;
    my $crit_uom = shift;
    my $measure_type = $VALUE_PROPERTY{$FILE_PROPERTY}{'MEASURE'};
    my $uom;

    if ($warn_uom and $crit_uom) {
        my $warn_uom_conversion = $VALUE_MEASURE{$measure_type}{$warn_uom};
        my $crit_uom_conversion = $VALUE_MEASURE{$measure_type}{$crit_uom};
        $uom = ($crit_uom_conversion > $warn_uom_conversion) ? $crit_uom : $warn_uom;
    }
    elsif ($warn_uom || $crit_uom) {
        $uom = $crit_uom ? $crit_uom : $warn_uom;
    }
    else {
        $uom = $VALUE_PROPERTY{$FILE_PROPERTY}{'DEFAULT_UOM'};
    }

    return $uom;
}

#------------------------------------------------------------------------------------
# Configure preformance data for output if specified
#------------------------------------------------------------------------------------
sub getPerformanceDataForProperty {
    my $warning_value  = shift;
    my $warning_uom    = shift;
    my $critical_value = shift;
    my $critical_uom   = shift;
    my (@file_stat) = @{(shift)};
    my %perf_data = (
       'WARN'  => '',
       'CRIT'  => '',
       'LABEL' => '',
       'VALUE' => '',
       'UOM'   => ''
    );

    my $default_uom = determineDefaultUom($warning_uom, $critical_uom);
    $perf_data{'UOM'} = $default_uom;
    if ($FILE_PROPERTY eq 'SIZE') {
        $perf_data{'VALUE'} = sprintf("%.2f", $file_stat[7] / $VALUE_MEASURE{'SIZE'}{$default_uom});
        $perf_data{'WARN'}  = sprintf("%.2f", convertPropertyValue($warning_value, $warning_uom) / $VALUE_MEASURE{'SIZE'}{$default_uom}) if $warning_value;
        $perf_data{'CRIT'}  = sprintf("%.2f", convertPropertyValue($critical_value, $critical_uom) / $VALUE_MEASURE{'SIZE'}{$default_uom}) if $critical_value;
    }
    elsif ($FILE_PROPERTY eq 'MODIFIED' || $FILE_PROPERTY eq 'ACCESSED') {
        my $value_stat = $VALUE_PROPERTY{$FILE_PROPERTY}{'STAT'};
        $perf_data{'VALUE'} = sprintf("%.2f", ($START_TIME - $file_stat[$value_stat]) / $VALUE_MEASURE{'TIME'}{$default_uom});
        $perf_data{'WARN'}  = sprintf("%.2f", convertPropertyValue($warning_value, $warning_uom) / $VALUE_MEASURE{'TIME'}{$default_uom}) if $warning_value;
        $perf_data{'CRIT'}  = sprintf("%.2f", convertPropertyValue($critical_value, $critical_uom) / $VALUE_MEASURE{'TIME'}{$default_uom}) if $critical_value;
        $perf_data{'UOM'}   = ($default_uom eq 'SECONDS') ? 's' : '';
    }
    $perf_data{'LABEL'} = $VALUE_PROPERTY{$FILE_PROPERTY}{'LABEL'};

    return \%perf_data
}

#------------------------------------------------------------------------------------
# Return the list of property values from a stat of a file
#------------------------------------------------------------------------------------
sub getFileStat {
    my $filepath = shift;
    my $smb = shift;

    my @filestat = $smb->stat($filepath);

    return \@filestat;
}

#####################################################################################
### Command Line Option Configuration
#####################################################################################
Getopt::Long::Configure ("bundling");
GetOptions(
    'p|property=s'       => \$o_file_property,
    'f|filename=s'       => \$o_filepath,
    'n|no-data'          => \$o_no_data,
    'w|warning=s'        => \$o_warning,
    'c|critical=s'       => \$o_critical,
    'm|warning-match=s'  => \$o_warning_match,
    'M|critical-match=s' => \$o_critical_match,
    't|warning-files=s'  => \$o_warning_files,
    'T|critical-files=s' => \$o_critical_files,
    'F|filename-match=s' => \$o_filename_match,
    'e|expand-datetime'  => \$o_expand_datetime,
    'C|match-case'       => \$o_match_case,
    'D|mode-directory'   => \$o_mode_directory,
    'H|host=s'           => \$o_host,
    'K|kerberos'         => \$o_smbflag_kerberos,
    'W|workgroup=s'      => \$o_smbinit{'workgroup'},
    'U|username=s'       => \$o_smbinit{'username'},
    'P|password=s'       => \$o_smbinit{'password'},
    'd|debug=i'          => \$o_smbinit{'debug'},
    'h|help'             => sub { help(); exit 0; },
    'V|version'          => sub { print "$VERSION\n"; exit 0; }
);

#####################################################################################
### Pre-Execution Checks
#####################################################################################
if (!$o_host) { usage("Host not specified\n"); }
if (!$o_filepath) { usage("File path not specified\n"); }
if ($o_file_property) {
    if (!exists $VALUE_PROPERTY{uc $o_file_property}) {
        usage("Invalid file property\n");
    }
    $FILE_PROPERTY = uc $o_file_property;
}
($critical_value, $critical_uom) = splitPropertyValue($o_critical) if ($o_critical);
($warning_value,   $warning_uom) = splitPropertyValue($o_warning) if ($o_warning);
if ($o_critical and $o_warning) {
    if (convertPropertyValue($critical_value, $critical_uom) <= convertPropertyValue($warning_value, $warning_uom)) {
        usage("The warning value must be less than the critical value\n"); 
    }
}
if (($o_critical_files || $o_warning_files) and (!$o_filename_match || !$o_mode_directory)) {
    usage("Checking for total files requires --filename-match --mode-directory\n"); 
}
if ($o_critical_files and $o_warning_files) {
    if ($o_critical_files <= $o_warning_files) {
        usage("The files warning value must be less than the files critical value\n"); 
    }
}

# Expand DateTime variables if the switch is enabled
$o_filename_match = ($o_filename_match and $o_expand_datetime) ?
    POSIX::strftime($o_filename_match, localtime) : $o_filename_match;
$o_filepath = ($o_expand_datetime) ?
    POSIX::strftime($o_filepath, localtime) : $o_filepath;

# Gracefully test for the Filesys::SmbClient module...
eval {
    require Filesys::SmbClient;
    Filesys::SmbClient->import;
};
if ( $@ ) {
    showOutputAndExit("Missing Perl module Filesys::SmbClient",'UNKNOWN');
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
        showOutputAndExit("Cannot create $ENV{HOME}/.smb/smb.conf: $!",'UNKNOWN');
    }
    close(F);
}

#####################################################################################
### Execute Main Plugin Checks
#####################################################################################
my $smb = new Filesys::SmbClient(%o_smbinit);
$smb->set_flag(SMB_CTX_FLAG_USE_KERBEROS) if ($o_smbflag_kerberos);

my (@fileStat) = @{ getFileStat($full_file_path, $smb) };

# If we can not access the initial file/folder, throw a critical error
showOutputAndExit("$! ($full_file_path)",'CRITICAL') if ($#fileStat == 0);

my $final_ok_message = '';

# Folder context mode if any of these are true...
if ($o_filename_match || $o_mode_directory) {
    my $fd;
    my %directory_files = ();
    my (@critical_matches, @warning_matches) = ();
    my (@critical_errors, @warning_errors) = ();

    # The checks are only valid if the path is a directory and is readable
    if (!($fd = $smb->opendir($full_file_path))) {
        showOutputAndExit("$! ($full_file_path)",'CRITICAL');
    }
    foreach my $filename ($smb->readdir($fd)) {
        if (($o_filename_match and !$o_match_case) and $filename =~ m/$o_filename_match/i) {
            my $full_filename = "$full_file_path/$filename";
            $directory_files{"$o_filepath/$filename"} = \@{ getFileStat($full_filename, $smb) };
        }
        elsif (($o_filename_match and $o_match_case) and $filename =~ m/$o_filename_match/) {
            my $full_filename = "$full_file_path/$filename";
            $directory_files{"$o_filepath/$filename"} = \@{ getFileStat($full_filename, $smb) };
        }
    }
    while (my ($key, $value) = each(%directory_files)) {
        if ($o_critical and my $c_output = checkFilePropertyValue($critical_value, $critical_uom, $value)) {
            push(@critical_errors, $key);
        }
        elsif ($o_warning and my $w_output = checkFilePropertyValue($warning_value, $warning_uom, $value)) {
            push(@warning_errors, $key);
        }
        if ($o_warning_match || $o_critical_match) {
            my ($match_output, $check_state) = checkFileContents(
                $smb,
                'smb://' . $o_host . '/' . $key,
                $o_warning_match,
                $o_critical_match
            );
            if ($match_output and $check_state eq 'CRITICAL') {
                push(@critical_matches,$key);
            }
            elsif ($match_output and $check_state eq 'WARNING') {
                push(@warning_matches,$key);
            }
        }
        if (!$o_no_data) {
            $PERF_DATA{$key} = getPerformanceDataForProperty(
                $warning_value, $warning_uom,
                $critical_value, $critical_uom,
                $value
            );
        }
    }
    $smb->close($fd);
    if (scalar keys %directory_files == 0) {
        showOutputAndExit("No files found",'CRITICAL');
    }
    if (scalar @critical_errors || scalar @warning_errors) {
        showOutputAndExit(
            scalar @critical_errors . " files are critical, " .
            scalar @warning_errors . " files with warnings. " .
            (keys %directory_files) . ' files checked.',
            ((scalar @critical_errors > scalar @warning_errors) ? 'CRITICAL' : 'WARNING')
        );
    }
    if (scalar @critical_matches || scalar @warning_matches) {
        showOutputAndExit(
            scalar @critical_matches . " files match the critical patttern, " .
            scalar @warning_matches . " files match the warning pattern. " .
            (keys %directory_files) . ' files checked.',
            ((scalar @critical_matches > scalar @warning_matches) ? 'CRITICAL' : 'WARNING')
        );
    }
    if ($o_critical_files || $o_warning_files) {
        if ($o_critical_files and scalar keys %directory_files >= $o_critical_files) { 
            showOutputAndExit("Total files found: " . (keys %directory_files),'CRITICAL');
        }
        if ($o_warning_files and scalar keys %directory_files >= $o_warning_files) { 
            showOutputAndExit("Total files found: " . (keys %directory_files),'WARNING');
        }
    }
    $final_ok_message = 'Directory found. ' . (keys %directory_files) . ' files checked. '
        . "($o_filepath)";
}
# Perform the checks in the context of a single file/folder
else {
    # Collect and process performance data unless told otherwise
    if (!$o_no_data) {
        $PERF_DATA{$o_filepath} = getPerformanceDataForProperty(
            $warning_value, $warning_uom,
            $critical_value, $critical_uom,
            \@fileStat
        );
    }

    if ($o_critical and my $output = checkFilePropertyValue($critical_value, $critical_uom, \@fileStat)) {
        showOutputAndExit($output,'CRITICAL');
    }
    if ($o_warning and my $output = checkFilePropertyValue($warning_value, $warning_uom, \@fileStat)) {
        showOutputAndExit($output,'WARNING');
    }

    if ($o_warning_match || $o_critical_match) {
        my ($output, $check_state) = checkFileContents(
            $smb,
            $full_file_path,
            $o_warning_match,
            $o_critical_match
        );
        showOutputAndExit($output, $check_state) if ($output);
    }
    $final_ok_message = "File/Directory found. ($o_filepath)";
}

# If we made it this far then everything is OK...
showOutputAndExit($final_ok_message,'OK');
