#!/usr/bin/perl

############################################################
# sort_ip.pl
#
# Copyright 2009,2013,2017,2019,2023 (C) Christopher J. Dunkle
#
# Extracts all IP addresses in the given file(s) or STDIN
# Strict matching to filter proper dotted quad IP addresses
#
# 2009-07-21: Created
# 2009-07-23: Completed
# 2009-12-01: Added "relaxed" options for matching tcpdump output
# 2013-08-29: Added parsing of reverse DNS lookups
# 2017-02-15: Added zero padded addresses to relaxed parsing
# 2017-02-15: Fixed parsing of reverse DNS lookups 
# 2017-02-16: Fixed normalization of zero padded addresses
# 2019-09-15: Minor code style changes
# 2023-02-09: Removed dot from neg lookbehind in relaxed regex
# 2023-02-09: Removed CR from new lines
#
############################################################

use strict;
use warnings;

# create new object, package embedded within this script
my $sipl = new SortedIPList;

# parse command line parameters
parse_param($sipl);

# read data from files
$sipl->process_files();

# output data
$sipl->output();

1;

############################################################

# returns the program usage statement
sub usage {
	my $pgm = $0;
	$pgm = $1 if ($pgm =~ /([^\/]+)$/);
	return
	"Usage: $pgm [OPTIONS] [[FILENAME] ...]\n" .
	"  Options:\n" .
	"    -s: output IPs as found (default is to output sorted and unique IPs)\n" .
	"    -c: prefix IPs with the total number of occurences\n" .
	"    -f: only extract first IP address from each line\n" .
	"    -l: print entire line containing IPs\n" .
	"    -p: prepend lines with matching IP (for use with -l when sorted)\n" .
	"    -i: ignore comment lines (starting with #)\n" .
	"    -r: relaxed matching (will match tcpdump output, but also SNMP MIBs!)\n" .
	"    -h: print help (or -?)\n" .
	"  STDIN is used when FILENAME is omitted\n" .
	"";
}

############################################################

# parse command line parameters
sub parse_param {
	my $sipl = shift;

	my @files;

	# read command line parameters
	foreach (@ARGV) {

		# -s sort
		if (/^-s$/) {
			$sipl->{'opt'}{'sort'} ^= 1;
		}

		# -c count
		elsif (/^-c$/) {
			$sipl->{'opt'}{'count'} ^= 1;
		}

		# -f first
		elsif (/^-f$/) {
			$sipl->{'opt'}{'first'} ^= 1;
		}

		# -l line
		elsif (/^-l$/) {
			$sipl->{'opt'}{'lines'} ^= 1;
		}

		# -p prepend
		elsif (/^-p$/) {
			$sipl->{'opt'}{'prepend'} ^= 1;
		}

		# -i ignore comments
		elsif (/^-i$/) {
			$sipl->{'opt'}{'ignore'} ^= 1;
		}

		# -r relaxed matching
		elsif (/^-r$/) {
			$sipl->{'opt'}{'relaxed'} ^= 1;
		}

		# -? -h help
		elsif (/^-\?$/ || /^-h$/) {
			die usage();
		}

		# assume filename
		else {
			push @{$sipl->{'files'}}, $_;
		}
	}

	# final changes
	if ($sipl->{'opt'}{'relaxed'}) {
		# utilize relaxed regular expressions
		$sipl->{'regex'} = $sipl->{'regex_relaxed'};
	}

	1;
}

############################################################

package SortedIPList;

use strict;
use Carp;
use FileHandle;
use Socket;

sub new {
	my $class = shift;

	# default options
	my $opt = {
		sort => 1,
		count => 0,
		first => 0,
		lines => 0,
		prepend => 0,
		ignore => 0,
		relaxed => 0
	};

	# list of filenames
	my @files;

	# straight list of IP addresses found
	my @ip_list;

	# hash list of IP addresses found
	my %ip_hash;

	# straight list of entire lines containing IP addresses
	my @lines_list;

	# hash list of entire lines containing IP addresses
	my %lines_hash;

	# REGEX: strict/relaxed regular expressions
	# only match octets 0-255 with word boundaries
	my $RE_O_S = qr/(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9]|0)/;
	my $RE_O_R = qr/(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|0?[1-9][0-9]|0?0?[0-9])/;
	# IP address is a dotted quad
	my $RE_IP_S = qr/(?<![0-9a-zA-Z.])(?:${RE_O_S}[.]${RE_O_S}[.]${RE_O_S}[.]${RE_O_S})(?![0-9a-zA-Z.])/;
	my $RE_IP_R = qr/(?<![0-9a-zA-Z])(?:${RE_O_R}[.]${RE_O_R}[.]${RE_O_R}[.]${RE_O_R}(?:[.]in-addr[.]arpa)?)(?![0-9a-zA-Z])/;
	my $regex_strict = {
		octet => $RE_O_S,
		ip => $RE_IP_S
	};
	my $regex_relaxed = {
		octet => $RE_O_R,
		ip => $RE_IP_R
	};

	# initialize self
	my $self = {
		opt => $opt,
		files => \@files,
		ip_list => \@ip_list,
		ip_hash => \%ip_hash,
		lines_list => \@lines_list,
		lines_hash => \%lines_hash,
		regex => $regex_strict,
		regex_strict => $regex_strict,
		regex_relaxed => $regex_relaxed
	};

	bless $self, $class;
	return $self;
}

############################################################

# processes a line for IP addresses
sub process_line {
	my $self = shift;
	my $line = shift;

	return 0 unless (defined $line);

	# ignore comments
	if ($self->{'opt'}{'ignore'}) {
		if ($line =~ /^#/) {
			return 1;
		}
	}

	# remove CR/LFs
	chop($line) while($line =~ /(\r|\n)$/);

	# copy temporary line
	my $tmpline = $line;

	# loop through IPs within this line
	my $append_lines = 0;
	my $re_ip = $self->{'regex'}{'ip'};
	while($tmpline =~ /(${re_ip})(.*)/) {
		my $ip = $1;
		my $re_o = $self->{'regex'}{'octet'};

		$tmpline = $2;

		# fix IP address in reverse DNS lookups
		if ($ip =~ /^(${re_o})\.(${re_o})\.(${re_o})\.(${re_o})\.in-addr\.arpa$/) {
			$ip = "$4.$3.$2.$1";
		}

		# normalize IP address (remove leading zeros from each octet)
		$ip =~ s/(?<![0-9])0+(?=[0-9])//g;

		# append to list
		push @{$self->{'ip_list'}}, $ip;

		# increment count of this IP
		$self->{'ip_hash'}{$ip}++;

		# store full lines
		if ($self->{'opt'}{'lines'}) {

			# store in hash list by matching IP
			if ($self->{'opt'}{'sort'}) {
				if (!exists $self->{'lines_hash'}{$ip}) {
					my @list;
					$self->{'lines_hash'}{$ip} = \@list;
				}
				push @{$self->{'lines_hash'}{$ip}}, $line;
			}

			# append to straight list
			else {
				# only append once
				if (!$append_lines) {
					push @{$self->{'lines_list'}}, $line;
					$append_lines = 1;
				}
			}
		}

		# only use first IP found, clear remainder of line
		if ($self->{'opt'}{'first'}) {
			$tmpline = "";
		}
	}

	1;
}

############################################################

# process a file for IP addresses
# assumes filename has been taint checked
sub process_file {
	my $self = shift;
	my $filename = shift;

	# open file
	my $fh = new FileHandle;
	open($fh, $filename) or croak "could not open: $filename\n";

	# loop through file
	while(<$fh>) {
		$self->process_line($_);
	}

	# close file
	close($fh);

	1;
}

############################################################

# process all files
sub process_files {
	my $self = shift;

	my @files = @{$self->{'files'}};

	# use STDIN if no files defined
	if ($#files < 0) {
		$self->process_file("<&STDIN");
	}
	else {
		# loop through files
		foreach my $filename (@files) {

			# check filename
			if ($filename =~ /^([+<>|]|-\|)/) {
				die "invalid filename: $filename\n";
			}
			die "file not found: $filename\n" unless (-e $filename);
			die "invalid file: $filename\n" unless (-f $filename);

			# process
			$self->process_file($filename);
		}
	}

	1;
}

############################################################

# standalone function
# returns a sorted list of IP addresses according to octet
sub _sort_ip_list {
	return sort { _ip2num($a) <=> _ip2num($b) } @_;
}

############################################################

# standalone function
# returns the numerical value for an IP address
# assumes input is a proper IP address, otherwise returns -1
sub _ip2num {
	my $ip = shift;

	# convert string to 4 byte binary
	my $n = inet_aton($ip);

	# invalid IP address
	unless (defined $n) {
		warn "invalid IP address: $ip\n";
		return -1;
	}

	# unpack 4 byte value to decimal
	return unpack("N", $n);
}

############################################################

# sort data and output to screen
sub output {
	my $self = shift;

	my @keys = keys %{$self->{'ip_hash'}};

	# determine maximum count length
	my $max_cnt_len = 0;
	if ($self->{'opt'}{'count'}) {
		my $max = 0;
		foreach (@keys) {
			my $cur = $self->{'ip_hash'}{$_};
			$max = $cur if ($cur > $max);
		}
		$max_cnt_len = length($max);
	}
	$max_cnt_len = 7 if ($max_cnt_len < 7);

	# determine which list to use
	my @ip_list;
	if ($self->{'opt'}{'sort'}) {
		# sorted unique list
		@ip_list = _sort_ip_list(@keys);
	}
	else {
		# straight list
		@ip_list = @{$self->{'ip_list'}};
	}

	# print file lines
	# NOTE: the count option does not apply to full lines
	if ($self->{'opt'}{'lines'}) {

		# sorted lines
		if ($self->{'opt'}{'sort'}) {
			foreach my $ip (@ip_list) {
				my @lines = @{$self->{'lines_hash'}{$ip}};
				foreach my $line (@lines) {

					# prepend IP to lines
					if ($self->{'opt'}{'prepend'}) {
						print sprintf("%15s: ", $ip);
					}
					print $line, "\n";
				}
			}
		}

		# straight lines
		else {
			# prepend does not apply here because
			# the line could contain multiple IPs
			foreach my $line (@{$self->{'lines_list'}}) {
				print $line, "\n";
			}
		}
	}

	# print IPs only (default)
	else {

		# loop through list of IP addresses
		foreach my $ip (@ip_list) {

			# prepend with count
			if ($self->{'opt'}{'count'}) {
				my $cnt = $self->{'ip_hash'}{$ip};
				print sprintf("%${max_cnt_len}u ", $cnt);
			}

			# output IP address
			print $ip, "\n";
		}
	}

	1;
}

############################################################
