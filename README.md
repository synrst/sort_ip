# Name
sort_ip.pl - extracts and sorts IP addresses
# Description
Extracts, sorts, and prints a list of unique IP addresses found in the input. Reads from either STDIN or a list of specified filenames. IP addresses are sorted using numeric equivalent values.

IP addresses are matched using a strict regular expression that prevents matching on strings containing more than 4 dots. This intentionally excludes SNMP OIDs with a greater number of dotted values, but also excludes tcpdump output with a dotted port number after valid IP addresses. The `-r` option applies a relaxed regular expression that will correctly match tcpdump output, but will also incorrectly match SNMP OIDs. Use this option with caution.

Relaxed matching will also match on other common formats, such as octets with leading zeroes ("192.168.000.001") and reverse DNS lookup ("1.0.168.192.in-addr.arpa"). In these cases, IP addresses are normalized for consistency and sorting.
# Synopsis
`... | sort_ip.pl [OPTIONS] [[FILENAME] ...]`
# Options
* `-s` - Disable sorting and print IP addresses in the order in which they were found.
* `-c` - Count the number of occurences of each IP address and prefix each line with the total number.
* `-f` - Extract only the first IP address from each line. All other addresses on a line will be ignored.
* `-l` - Print the entire line where an IP address is found. If more than one IP address exists on a given line, that line will be printed multiple times for each IP address.
* `-p` - Prepend lines with the IP address matching on that line. Requires `-l` to be applied to print the entire line.
* `-i` - Ignore comment lines starting with #.
* `-r` - Perform relaxed matching. This option should only be used when the input is known to contain actual IP addresses, otherwise the output may contain invalid IP addresses.
* `-h`, `-?` - Print a basic help screen.
