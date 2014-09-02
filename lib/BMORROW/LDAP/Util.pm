package BMORROW::LDAP::Util;

use 5.012;
use warnings;

use Exporter "import";
our @EXPORT_OK = qw/ rdn /;

use Net::LDAP::Util     qw/ldap_explode_dn/;

sub rdn {
    my ($att, $dn) = @_;
    my $ex = ldap_explode_dn($dn, casefold => "lower")
        or die "Bad DN [$dn]";
    my $v = $ex->[0]{lc $att}
        or die "DN [$dn] has no [$att] RDN";
    return $v;
}

1;
