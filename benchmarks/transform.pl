use strict;
use warnings;
use Tie::IxHash;

open(my $fh, '<', $ARGV[0]) or die "Cannot open file: $!";

tie my %hash, 'Tie::IxHash';
tie my %encr, 'Tie::IxHash';
tie my %decr, 'Tie::IxHash';
$hash{"Encrypt"} = \%encr;
$hash{"Decrypt"} = \%decr;

my $enc  = "";
my $curr = "";
my $type = "";
my $time = "";
# Read the file line by line
while (my $line = <$fh>) {
    chomp($line);  # Remove newline character from the end of the line
    # Process the line here
    if ($curr ne "") {
	if ($line =~ /.*time:.*\[.*? .*? (.*? .*?) .*? .*?\]$/) {
		continue if $1 =~ /\%/;
		$time = $1;
		$hash{$enc}{$curr}{$type}{time} = $time;
	} elsif ($line =~ /.*thrpt:.*\[.*? .*? (.*? .*?) .*? .*?\]$/) {
		continue if $1 =~ /\%/;
		$hash{$enc}{$curr}{$type}{th} = $1;
		$curr = "";
	}
    } elsif ($line =~ /^(Encrypt|Decrypt)\s(.*?)\/(.*?)$/) {
	$enc  = $1;
	$curr = $3;
	$type = $2;
    }
}
# Close the file
close($fh);

use Data::Dumper;
print Dumper(\%hash);

# generate plot data

my %units = (
    "B" => 1024*1024,
    "KIB" => 1024,
    "MIB" => 1,
    "GIB" => 1024
);

sub convert_to_mb {
    my ($value) = @_;
    
    my ($type, $size);
    if ($value =~ /^(\d+\.\d+)\s*(MiB|KiB|GiB)\/.*?$/) {
        $size = $1;
        $type = uc($2);
    }

    if (!exists $units{$type}) {
        print "Invalid unit: $type\n";
        exit 1;
    }

    if ($type eq "GIB") {
        return $size * $units{$type};
    } else {
        return $size / $units{$type};
    }
}

sub bytes_to_mb {
    my ($value) = @_;
    return $value/$units{"B"};
}

print "-------------------\n";

foreach my $key (keys %{$hash{"Encrypt"}}) {
    print "'results/encrypt_$key.txt' using 2:1 with linespoints title '".$key."', \\\n";
}

foreach my $key (keys %{$hash{"Encrypt"}}) {
    my $row = convert_to_mb($hash{"Encrypt"}{$key}{"1B"}{th})." ".bytes_to_mb(1)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"16B"}{th})." ".bytes_to_mb(16)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"32B"}{th})." ".bytes_to_mb(32)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"64B"}{th})." ".bytes_to_mb(64)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"100B"}{th})." ".bytes_to_mb(100)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"300B"}{th})." ".bytes_to_mb(300)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"500B"}{th})." ".bytes_to_mb(500)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"700B"}{th})." ".bytes_to_mb(700)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"1KB"}{th})." ".bytes_to_mb(1024)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"3KB"}{th})." ".bytes_to_mb(3072)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"5KB"}{th})." ".bytes_to_mb(5120)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"7KB"}{th})." ".bytes_to_mb(7168)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"10KB"}{th})." ".bytes_to_mb(10240)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"1MB"}{th})." ".bytes_to_mb(1048576)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"50MB"}{th})." ".bytes_to_mb(52428800)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"100MB"}{th})." ".bytes_to_mb(104857600)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"200MB"}{th})." ".bytes_to_mb(209715200)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"300MB"}{th})." ".bytes_to_mb(314572800)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"400MB"}{th})." ".bytes_to_mb(419430400)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"600MB"}{th})." ".bytes_to_mb(629145600)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"800MB"}{th})." ".bytes_to_mb(838860800)."\n";
    $row .= convert_to_mb($hash{"Encrypt"}{$key}{"1GB"}{th})." ".bytes_to_mb(1073741824)."\n";
    qx{echo "$row" > "results/encrypt_$key.txt"}
}

print "-------------------\n";

foreach my $key (keys %{$hash{"Decrypt"}}) {
    print "'results/decrypt_$key.txt' using 2:1 with linespoints title '".$key."', \\\n";
}

foreach my $key (keys %{$hash{"Decrypt"}}) {
    my $row = convert_to_mb($hash{"Decrypt"}{$key}{"1B"}{th})." ".bytes_to_mb(1)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"16B"}{th})." ".bytes_to_mb(16)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"32B"}{th})." ".bytes_to_mb(32)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"64B"}{th})." ".bytes_to_mb(64)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"100B"}{th})." ".bytes_to_mb(100)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"300B"}{th})." ".bytes_to_mb(300)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"500B"}{th})." ".bytes_to_mb(500)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"700B"}{th})." ".bytes_to_mb(700)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"1KB"}{th})." ".bytes_to_mb(1024)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"3KB"}{th})." ".bytes_to_mb(3072)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"5KB"}{th})." ".bytes_to_mb(5120)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"7KB"}{th})." ".bytes_to_mb(7168)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"10KB"}{th})." ".bytes_to_mb(10240)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"1MB"}{th})." ".bytes_to_mb(1048576)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"50MB"}{th})." ".bytes_to_mb(52428800)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"100MB"}{th})." ".bytes_to_mb(104857600)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"200MB"}{th})." ".bytes_to_mb(209715200)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"300MB"}{th})." ".bytes_to_mb(314572800)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"400MB"}{th})." ".bytes_to_mb(419430400)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"600MB"}{th})." ".bytes_to_mb(629145600)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"800MB"}{th})." ".bytes_to_mb(838860800)."\n";
    $row .= convert_to_mb($hash{"Decrypt"}{$key}{"1GB"}{th})." ".bytes_to_mb(1073741824)."\n";
    qx{echo "$row" > "results/decrypt_$key.txt"}
}
