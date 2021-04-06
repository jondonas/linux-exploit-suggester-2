#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Std;

our $VERSION = '2';

my %opts;
getopts( 'k:hd', \%opts );
if (exists $opts{h}) {
    usage();
    exit;
};

print_banner();
my ( $khost, $is_partial ) = get_kernel();
print "  Local Kernel: \e[00;33m$khost\e[00m\n";

my %exploits = get_exploits();
print '  Searching ' . scalar keys(%exploits) . " exploits...\n\n";
print "  \e[1;35mPossible Exploits\e[00m\n";

my $count = 1;
my @applicable = ();
EXPLOIT:
foreach my $key ( sort keys %exploits ) {
    foreach my $kernel ( @{ $exploits{$key}{vuln} } ) {

        if (     $khost eq $kernel
              or ( $is_partial and index($kernel,$khost) == 0 )
        ) {
            $exploits{$key}{key} = $key;
            push(@applicable, $exploits{$key});
            print "  \e[00;33m[\e[00m\e[00;31m$count\e[00m\e[00;33m]\e[00m ";
            print "\e[00;33m$key\e[00m";
            print " \e[00;33m($kernel)\e[00m" if $is_partial;

            my $alt = $exploits{$key}{alt};
            my $cve = $exploits{$key}{cve};
            my $mlw = $exploits{$key}{mil};
            if ( $alt or $cve ) {
                print "\n";
            }
            if ( $alt ) { print "      Alt: $alt "; }
            if ( $cve ) { print "      CVE-$cve"; }
            if ( $mlw ) { print "\n      Source: $mlw"; }
            print "\n";
            $count += 1;
            next EXPLOIT;
        }
    }
}
print "\n";

if (!@applicable) {
    print "  No exploits are available for this kernel version\n\n";
    exit;
}

if (exists $opts{d}) {
    print "  \e[1;36mExploit Download\e[00m\n";
    print "  (Download all: \e[00;33m'a'\e[00m / Individually: \e[00;33m'2,4,5'\e[00m ";
    print "/ Exit: \e[00;33m^c\e[00m)\n";
    print "  Select exploits to download: ";

    while (1) {
        my $input = <STDIN>;
        $input =~ s/\s+//g;

        if ($input =~ /^a$/) {
            my @selected = ();
            for (my $i=1; $i <= scalar @applicable; $i++) {
               push(@selected, $i);
            }
            download_exploits(\@selected, \@applicable);
            last;
        }
        elsif ($input =~ /^(0|[1-9][0-9]*)(,(0|[1-9][0-9]*))*$/) {
            my @selected = uniq(split(',', $input));
            @selected = sort {$a <=> $b} @selected;
            if ($selected[0] > 0 && $selected[-1] <= scalar @applicable) {
                download_exploits(\@selected, \@applicable);
                last;
            }
            else {
               print "  \e[00;31mInput is out of range.\e[00m Select exploits to download: ";
            }
        }
        else {
            print "  \e[00;31mInvalid input.\e[00m Select exploits to download: ";
        }
    }
};
exit;

######################
## extra functions  ##
######################

sub get_kernel {
    my $khost = '';

    if ( exists $opts{k} ) {
        $khost = $opts{k};
    }
    else {
        $khost = `uname -r |cut -d"-" -f1`;
        chomp $khost;
    }

    if (!defined $khost || !($khost =~ /^[0-9]+([.][0-9]+)*$/)) {
        print "  \e[00;31mSpecified kernel is in the wrong format\e[00m\n";
        print "  Try a kernel format like this: 3.2.0\n\n";
        exit;
    }

    # partial kernels might be provided by the user,
    # such as '2.4' or '2.6.'
    my $is_partial = $khost =~ /^\d+\.\d+\.\d?/ ? 0 : 1;
    return ( $khost, $is_partial );
}

sub download_exploits {
    my ($sref, $aref) = @_;
    my @selected = @{ $sref };
    my @applicable = @{ $aref };
    my $exploit_base = "www.exploit-db.com/exploits";
    my $download_base = "https://www.exploit-db.com/raw/";
    print "\n";

    foreach my $num (@selected) {
        my $mil = $applicable[$num-1]{mil};
        next if (!defined $mil);
        my ($exploit_num) = ($mil =~ /^.*\/([1-9][0-9]*)\/?$/);
        
        if ($exploit_num && index($mil, $exploit_base) != -1) {
            my $url = $download_base . $exploit_num;
            my $file = "exploit_$applicable[$num-1]{key}";
            print "  Downloading \e[00;33m$url\e[00m -> \e[00;33m$file\e[00m\n";
            system "wget $url -O $file > /dev/null 2>&1";
        }
        else {
            print "  No exploit code available for \e[00;33m$applicable[$num-1]{key}\e[00m\n"; 
        }
    }
    print "\n";
}

sub uniq {
    my %seen;
    grep !$seen{$_}++, @_;
}

sub usage {
print_banner();
print "  \e[00;35mUsage:\e[00m $0 [-h] [-k kernel] [-d]\n\n";
print "  \e[00;33m[\e[00m\e[00;31m-h\e[00m\e[00;33m]\e[00m Help (this message)\n";
print "  \e[00;33m[\e[00m\e[00;31m-k\e[00m\e[00;33m]\e[00m Kernel number (eg. 2.6.28)\n";
print "  \e[00;33m[\e[00m\e[00;31m-d\e[00m\e[00;33m]\e[00m Open exploit download menu\n\n";

print "  You can also provide a partial kernel version (eg. 2.4)\n";
print "  to see all exploits available.\n\n";
}

sub print_banner {
print "\n\e[00;33m  #############################\e[00m\n";
print "\e[1;31m    Linux Exploit Suggester $VERSION\e[00m\n";
print "\e[00;33m  #############################\e[00m\n\n";
}

sub get_exploits {
  return (
    'w00t' => {
        vuln => [
            '2.4.10', '2.4.16', '2.4.17', '2.4.18',
            '2.4.19', '2.4.20', '2.4.21',
        ]
    },
    'brk' => {
        vuln => [ '2.4.10', '2.4.18', '2.4.19', '2.4.20', '2.4.21', '2.4.22' ],
    },
    'ave' => { vuln => [ '2.4.19', '2.4.20' ] },

    'elflbl' => {
        vuln => ['2.4.29'],
        mil  => 'http://www.exploit-db.com/exploits/744',
    },

    'elfdump'      => { vuln => ['2.4.27'] },
    'elfcd'        => { vuln => ['2.6.12'] },
    'expand_stack' => { vuln => ['2.4.29'] },

    'h00lyshit' => {
        vuln => [
            '2.6.8',  '2.6.10', '2.6.11', '2.6.12',
            '2.6.13', '2.6.14', '2.6.15', '2.6.16',
        ],
        cve => '2006-3626',
        mil => 'http://www.exploit-db.com/exploits/2013',
    },

    'kdump' => { vuln => ['2.6.13'] },
    'km2'   => { vuln => [ '2.4.18', '2.4.22' ] },
    'krad' =>
      { vuln => [ '2.6.5', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11' ] },

    'krad3' => {
        vuln => [ '2.6.5', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11' ],
        mil => 'http://exploit-db.com/exploits/1397',
    },

    'local26' => { vuln => ['2.6.13'] },
    'loko'    => { vuln => [ '2.4.22', '2.4.23', '2.4.24' ] },

    'mremap_pte' => {
        vuln => [ '2.4.20', '2.2.24', '2.4.25', '2.4.26', '2.4.27' ],
        mil => 'http://www.exploit-db.com/exploits/160',
    },

    'newlocal' => { vuln => [ '2.4.17', '2.4.19' ] },
    'ong_bak'  => { vuln => ['2.6.5'] },
    'ptrace' =>
      { vuln => [ '2.4.18', '2.4.19', '2.4.20', '2.4.21', '2.4.22' ] },
    'ptrace_kmod' => {
        vuln => [ '2.4.18', '2.4.19', '2.4.20', '2.4.21', '2.4.22' ],
        cve  => '2007-4573',
    },
    'ptrace_kmod2' => {
        vuln => [
            '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31',
            '2.6.32', '2.6.33', '2.6.34',
        ],
        alt => 'ia32syscall,robert_you_suck',
        mil => 'http://www.exploit-db.com/exploits/15023',
        cve => '2010-3301',
    },
    'ptrace24' => { vuln => ['2.4.9'] },
    'pwned'    => { vuln => ['2.6.11'] },
    'py2'      => { vuln => [ '2.6.9', '2.6.17', '2.6.15', '2.6.13' ] },
    'raptor_prctl' => {
        vuln => [ '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17' ],
        cve  => '2006-2451',
        mil => 'http://www.exploit-db.com/exploits/2031',
    },
    'prctl' => {
        vuln => [ '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17' ],
        mil => 'http://www.exploit-db.com/exploits/2004',
    },
    'prctl2' => {
        vuln => [ '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17' ],
        mil => 'http://www.exploit-db.com/exploits/2005',
    },
    'prctl3' => {
        vuln => [ '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17' ],
        mil => 'http://www.exploit-db.com/exploits/2006',
    },
    'prctl4' => {
        vuln => [ '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17' ],
        mil => 'http://www.exploit-db.com/exploits/2011',
    },
    'remap'      => { vuln => ['2.4'] },
    'rip'        => { vuln => ['2.2'] },
    'stackgrow2' => { vuln => [ '2.4.29', '2.6.10' ] },
    'uselib24' => {
        vuln => [ '2.6.10', '2.4.17', '2.4.22', '2.4.25', '2.4.27', '2.4.29' ]
    },
    'newsmp'   => { vuln => ['2.6'] },
    'smpracer' => { vuln => ['2.4.29'] },
    'loginx'   => { vuln => ['2.4.22'] },
    'exp.sh'   => { vuln => [ '2.6.9', '2.6.10', '2.6.16', '2.6.13' ] },
    'vmsplice1' => {
        vuln => [
            '2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22',
            '2.6.23', '2.6.24', '2.6.24.1',
        ],
        alt => 'jessica biel',
        cve => '2008-0600',
        mil => 'http://www.exploit-db.com/exploits/5092',
    },
    'vmsplice2' => {
        vuln => [ '2.6.23', '2.6.24' ],
        alt  => 'diane_lane',
        cve  => '2008-0600',
        mil  => 'http://www.exploit-db.com/exploits/5093',
    },
    'vconsole' => {
        vuln => ['2.6'],
        cve  => '2009-1046',
    },
    'sctp' => {
        vuln => ['2.6.26'],
        cve  => '2008-4113',
    },
    'ftrex' => {
        vuln => [
            '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16',
            '2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22',
        ],
        cve => '2008-4210',
        mil => 'http://www.exploit-db.com/exploits/6851',
    },
    'exit_notify' => {
        vuln => [ '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29' ],
        mil => 'http://www.exploit-db.com/exploits/8369',
    },
    'udev' => {
        vuln => [ '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29' ],
        alt  => 'udev <1.4.1',
        cve  => '2009-1185',
        mil => 'http://www.exploit-db.com/exploits/8478',
    },

    'sock_sendpage2' => {
        vuln => [
            '2.4.4',  '2.4.5',  '2.4.6',  '2.4.7',  '2.4.8',  '2.4.9',
            '2.4.10', '2.4.11', '2.4.12', '2.4.13', '2.4.14', '2.4.15',
            '2.4.16', '2.4.17', '2.4.18', '2.4.19', '2.4.20', '2.4.21',
            '2.4.22', '2.4.23', '2.4.24', '2.4.25', '2.4.26', '2.4.27',
            '2.4.28', '2.4.29', '2.4.30', '2.4.31', '2.4.32', '2.4.33',
            '2.4.34', '2.4.35', '2.4.36', '2.4.37', '2.6.0',  '2.6.1',
            '2.6.2',  '2.6.3',  '2.6.4',  '2.6.5',  '2.6.6',  '2.6.7',
            '2.6.8',  '2.6.9',  '2.6.10', '2.6.11', '2.6.12', '2.6.13',
            '2.6.14', '2.6.15', '2.6.16', '2.6.17', '2.6.18', '2.6.19',
            '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25',
            '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30',
        ],
        alt => 'proto_ops',
        cve => '2009-2692',
        mil => 'http://www.exploit-db.com/exploits/9436',
    },

    'sock_sendpage' => {
        vuln => [
            '2.4.4',  '2.4.5',  '2.4.6',  '2.4.7',  '2.4.8',  '2.4.9',
            '2.4.10', '2.4.11', '2.4.12', '2.4.13', '2.4.14', '2.4.15',
            '2.4.16', '2.4.17', '2.4.18', '2.4.19', '2.4.20', '2.4.21',
            '2.4.22', '2.4.23', '2.4.24', '2.4.25', '2.4.26', '2.4.27',
            '2.4.28', '2.4.29', '2.4.30', '2.4.31', '2.4.32', '2.4.33',
            '2.4.34', '2.4.35', '2.4.36', '2.4.37', '2.6.0',  '2.6.1',
            '2.6.2',  '2.6.3',  '2.6.4',  '2.6.5',  '2.6.6',  '2.6.7',
            '2.6.8',  '2.6.9',  '2.6.10', '2.6.11', '2.6.12', '2.6.13',
            '2.6.14', '2.6.15', '2.6.16', '2.6.17', '2.6.18', '2.6.19',
            '2.6.20', '2.6.21', '2.6.22', '2.6.23', '2.6.24', '2.6.25',
            '2.6.26', '2.6.27', '2.6.28', '2.6.29', '2.6.30',
        ],
        alt => 'wunderbar_emporium',
        cve => '2009-2692',
        mil => 'http://www.exploit-db.com/exploits/9435',
    },
    'udp_sendmsg_32bit' => {
        vuln => [
            '2.6.1',  '2.6.2',  '2.6.3',  '2.6.4',  '2.6.5',  '2.6.6',
            '2.6.7',  '2.6.8',  '2.6.9',  '2.6.10', '2.6.11', '2.6.12',
            '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17', '2.6.18',
            '2.6.19',
        ],
        cve => '2009-2698',
        mil =>
          'http://downloads.securityfocus.com/vulnerabilities/exploits/36108.c',
    },
    'pipe.c_32bit' => {
        vuln => [
            '2.4.4',  '2.4.5',  '2.4.6',  '2.4.7',  '2.4.8',  '2.4.9',
            '2.4.10', '2.4.11', '2.4.12', '2.4.13', '2.4.14', '2.4.15',
            '2.4.16', '2.4.17', '2.4.18', '2.4.19', '2.4.20', '2.4.21',
            '2.4.22', '2.4.23', '2.4.24', '2.4.25', '2.4.26', '2.4.27',
            '2.4.28', '2.4.29', '2.4.30', '2.4.31', '2.4.32', '2.4.33',
            '2.4.34', '2.4.35', '2.4.36', '2.4.37', '2.6.15', '2.6.16',
            '2.6.17', '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22',
            '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28',
            '2.6.29', '2.6.30', '2.6.31',
        ],
        cve => '2009-3547',
        mil =>
          'http://www.securityfocus.com/data/vulnerabilities/exploits/36901-1.c',
    },
    'do_pages_move' => {
        vuln => [
            '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23',
            '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29',
            '2.6.30', '2.6.31',
        ],
        alt => 'sieve',
        cve => '2010-0415',
        mil => 'Spenders Enlightenment',
    },
    'reiserfs' => {
        vuln => [
            '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23',
            '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29',
            '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34',
        ],
        cve => '2010-1146',
        mil => 'http://www.exploit-db.com/exploits/12130',
    },
    'can_bcm' => {
        vuln => [
            '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23',
            '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29',
            '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35',
            '2.6.36',
        ],
        cve => '2010-2959',
        mil => 'http://www.exploit-db.com/exploits/14814',
    },
    'rds' => {
        vuln => [
            '2.6.30', '2.6.31', '2.6.32', '2.6.33',
            '2.6.34', '2.6.35', '2.6.36',
        ],
        mil => 'http://www.exploit-db.com/exploits/15285',
        cve => '2010-3904',
    },
    'half_nelson1' => {
        vuln => [
            '2.6.0',  '2.6.1',  '2.6.2',  '2.6.3',  '2.6.4',  '2.6.5',
            '2.6.6',  '2.6.7',  '2.6.8',  '2.6.9',  '2.6.10', '2.6.11',
            '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17',
            '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23',
            '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29',
            '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35',
            '2.6.36',
        ],
        alt => 'econet',
        cve => '2010-3848',
        mil => 'http://www.exploit-db.com/exploits/17787',
    },
    'half_nelson2' => {
        vuln => [
            '2.6.0',  '2.6.1',  '2.6.2',  '2.6.3',  '2.6.4',  '2.6.5',
            '2.6.6',  '2.6.7',  '2.6.8',  '2.6.9',  '2.6.10', '2.6.11',
            '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17',
            '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23',
            '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29',
            '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35',
            '2.6.36',
        ],
        alt => 'econet',
        cve => '2010-3850',
        mil => 'http://www.exploit-db.com/exploits/17787',
    },
    'half_nelson3' => {
        vuln => [
            '2.6.0',  '2.6.1',  '2.6.2',  '2.6.3',  '2.6.4',  '2.6.5',
            '2.6.6',  '2.6.7',  '2.6.8',  '2.6.9',  '2.6.10', '2.6.11',
            '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17',
            '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23',
            '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29',
            '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35',
            '2.6.36',
        ],
        alt => 'econet',
        cve => '2010-4073',
        mil => 'http://www.exploit-db.com/exploits/17787',
    },
    'caps_to_root' => {
        vuln => [ '2.6.34', '2.6.35', '2.6.36' ],
        cve  => 'n/a',
        mil => 'http://www.exploit-db.com/exploits/15916',
    },
    'american-sign-language' => {
        vuln => [
            '2.6.0',  '2.6.1',  '2.6.2',  '2.6.3',  '2.6.4',  '2.6.5',
            '2.6.6',  '2.6.7',  '2.6.8',  '2.6.9',  '2.6.10', '2.6.11',
            '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17',
            '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23',
            '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29',
            '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35',
            '2.6.36',
        ],
        cve => '2010-4347',
        mil => 'http://www.securityfocus.com/bid/45408',
    },
    'pktcdvd' => {
        vuln => [
            '2.6.0',  '2.6.1',  '2.6.2',  '2.6.3',  '2.6.4',  '2.6.5',
            '2.6.6',  '2.6.7',  '2.6.8',  '2.6.9',  '2.6.10', '2.6.11',
            '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17',
            '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23',
            '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29',
            '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35',
            '2.6.36',
        ],
        cve => '2010-3437',
        mil => 'http://www.exploit-db.com/exploits/15150',
    },
    'video4linux' => {
        vuln => [
            '2.6.0',  '2.6.1',  '2.6.2',  '2.6.3',  '2.6.4',  '2.6.5',
            '2.6.6',  '2.6.7',  '2.6.8',  '2.6.9',  '2.6.10', '2.6.11',
            '2.6.12', '2.6.13', '2.6.14', '2.6.15', '2.6.16', '2.6.17',
            '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23',
            '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.28', '2.6.29',
            '2.6.30', '2.6.31', '2.6.32', '2.6.33',
        ],
        cve => '2010-3081',
        mil => 'http://www.exploit-db.com/exploits/15024',
    },
    'memodipper' => {
        vuln => [
            '2.6.39', '3.0.0', '3.0.1', '3.0.2', '3.0.3', '3.0.4',
            '3.0.5',  '3.0.6', '3.1.0',
        ],
        cve => '2012-0056',
        mil => 'http://www.exploit-db.com/exploits/18411',
    },
    'semtex' => {
        vuln => [
            '2.6.37', '2.6.38', '2.6.39', '3.0.0', '3.0.1', '3.0.2',
            '3.0.3',  '3.0.4',  '3.0.5',  '3.0.6', '3.1.0',
        ],
        cve => '2013-2094',
        mil => 'http://www.exploit-db.com/exploits/25444',
    },
    'perf_swevent' => {
        vuln => [
            '3.0.0', '3.0.1', '3.0.2', '3.0.3', '3.0.4', '3.0.5',
            '3.0.6', '3.1.0', '3.2.0', '3.3.0', '3.4.0', '3.4.1',
            '3.4.2', '3.4.3', '3.4.4', '3.4.5', '3.4.6', '3.4.8',
            '3.4.9', '3.5.0', '3.6.0', '3.7.0', '3.8.0', '3.8.1',
            '3.8.2', '3.8.3', '3.8.4', '3.8.5', '3.8.6', '3.8.7',
            '3.8.8', '3.8.9',
        ],
        cve => '2013-2094',
        mil => 'http://www.exploit-db.com/exploits/26131',
    },
    'msr' => {
        vuln => [
            '2.6.18', '2.6.19', '2.6.20', '2.6.21', '2.6.22', '2.6.23',
            '2.6.24', '2.6.25', '2.6.26', '2.6.27', '2.6.27', '2.6.28',
            '2.6.29', '2.6.30', '2.6.31', '2.6.32', '2.6.33', '2.6.34',
            '2.6.35', '2.6.36', '2.6.37', '2.6.38', '2.6.39', '3.0.0',
            '3.0.1',  '3.0.2',  '3.0.3',  '3.0.4',  '3.0.5',  '3.0.6',
            '3.1.0',  '3.2.0',  '3.3.0',  '3.4.0',  '3.5.0',  '3.6.0',
            '3.7.0',  '3.7.6',
        ],
        cve => '2013-0268',
        mil => 'http://www.exploit-db.com/exploits/27297',
    },
    'timeoutpwn' => {
        vuln => [
            '3.4.0',  '3.5.0',  '3.6.0',  '3.7.0',  '3.8.0',  '3.8.9', 
            '3.9.0',  '3.10.0', '3.11.0', '3.12.0', '3.13.0', '3.4.0',
            '3.5.0',  '3.6.0',  '3.7.0',  '3.8.0',  '3.8.5',  '3.8.6',  
            '3.8.9',  '3.9.0',  '3.9.6',  '3.10.0', '3.10.6', '3.11.0',
            '3.12.0', '3.13.0', '3.13.1'
        ],
        cve => '2014-0038',
        mil => 'http://www.exploit-db.com/exploits/31346',
    },
    'rawmodePTY' => {
        vuln => [
            '2.6.31', '2.6.32', '2.6.33', '2.6.34', '2.6.35', '2.6.36',
            '2.6.37', '2.6.38', '2.6.39', '3.14.0', '3.15.0'
        ],
        cve => '2014-0196',
        mil => 'http://packetstormsecurity.com/files/download/126603/cve-2014-0196-md.c',
    },
    'overlayfs' => {
        vuln => [
            '3.13.0', '3.16.0', '3.19.0'
        ],
        cve => '2015-8660',
        mil => 'http://www.exploit-db.com/exploits/39230',
    },
    'pp_key' => {
        vuln => [
			'3.4.0',  '3.5.0',  '3.6.0',  '3.7.0',  '3.8.0',  '3.8.1',  
            '3.8.2',  '3.8.3',  '3.8.4',  '3.8.5',  '3.8.6',  '3.8.7',  
            '3.8.8',  '3.8.9',  '3.9.0',  '3.9.6',  '3.10.0', '3.10.6', 
            '3.11.0', '3.12.0', '3.13.0', '3.13.1'
        ],
        cve => '2016-0728',
        mil => 'http://www.exploit-db.com/exploits/39277',
    },
    'dirty_cow' => {
        vuln => [
            '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27', 
			'2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31', '2.6.32', 
            '2.6.33', '2.6.34', '2.6.35', '2.6.36', '2.6.37', '2.6.38', 
            '2.6.39', '3.0.0',  '3.0.1',  '3.0.2',  '3.0.3',  '3.0.4',  
            '3.0.5',  '3.0.6',  '3.1.0',  '3.2.0',  '3.3.0',  '3.4.0',  
            '3.5.0',  '3.6.0',  '3.7.0',  '3.7.6',  '3.8.0',  '3.9.0'
        ],
        cve => '2016-5195',
        mil => 'http://www.exploit-db.com/exploits/40616',
    },
    'af_packet' => {
        vuln => ['4.4.0' ],
        cve => '2016-8655',
        mil => 'http://www.exploit-db.com/exploits/40871',
    },
    'packet_set_ring' => {
        vuln => ['4.8.0' ],
        cve => '2017-7308',
        mil => 'http://www.exploit-db.com/exploits/41994',
    },
    'clone_newuser' => {
        vuln => [
            '3.3.5', '3.3.4', '3.3.2', '3.2.13', '3.2.9', '3.2.1', 
            '3.1.8', '3.0.5', '3.0.4', '3.0.2', '3.0.1', '3.2', '3.0.1', '3.0'
        ],
        cve => 'N\A',
        mil => 'http://www.exploit-db.com/exploits/38390',
    },
    'get_rekt' => {
        vuln => [
            '4.4.0', '4.8.0', '4.10.0', '4.13.0'
        ],
        cve => '2017-16695',
        mil => 'http://www.exploit-db.com/exploits/45010',
    },
    'exploit_x' => {
        vuln => [
            '2.6.22', '2.6.23', '2.6.24', '2.6.25', '2.6.26', '2.6.27',
            '2.6.27', '2.6.28', '2.6.29', '2.6.30', '2.6.31', '2.6.32',
            '2.6.33', '2.6.34', '2.6.35', '2.6.36', '2.6.37', '2.6.38',
            '2.6.39', '3.0.0',  '3.0.1',  '3.0.2',  '3.0.3',  '3.0.4',
            '3.0.5',  '3.0.6',  '3.1.0',  '3.2.0',  '3.3.0',  '3.4.0',
            '3.5.0',  '3.6.0',  '3.7.0',  '3.7.6',  '3.8.0',  '3.9.0',
            '3.10.0', '3.11.0', '3.12.0', '3.13.0', '3.14.0', '3.15.0',
            '3.16.0', '3.17.0', '3.18.0', '3.19.0', '4.0.0',  '4.1.0',
            '4.2.0',  '4.3.0',  '4.4.0',  '4.5.0',  '4.6.0',  '4.7.0'
        ],
        cve => '2018-14665',
        mil => 'http://www.exploit-db.com/exploits/45697',
    },
  );
}

__END__
=head1 NAME

linux_exploit_suggester-2.pl - A local exploit suggester for linux

=head1 DESCRIPTION

This perl script will enumerate the possible exploits available for a given kernel version

=head1 USAGE

[-h] Help (this message)
[-k] Kernel number (eg. 2.6.28)
[-d] Open exploit download menu

You can also provide a partial kernel version (eg. 2.4)
to see all exploits available.

=head1 AUTHOR

Jonathan Donas (c) 2019

=cut

=head1 LICENSE

 Linux Exploit Suggester 2

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
        
 You should have received a copy of the GNU General Public License along
 with this program; if not, write to the Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

=cut
