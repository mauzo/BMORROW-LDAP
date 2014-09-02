package BMORROW::LDAP::Entry;

use warnings;
use strict;

sub new {
    my ($class, $e) = @_;
    bless \$e, $class;
}

sub dn {
    my ($e) = @_;
    $$e->dn;
}

our $AUTOLOAD;
sub AUTOLOAD {
    my ($e) = @_;
    my ($att) = $AUTOLOAD =~ /([^:]+$)/;
    #warn "LdapEntry::AUTOLOAD [$e] [$att]\n";
    $$e->get_value($att);
}

sub can {
    my ($self, $meth) = @_;

    my $c = $self->UNIVERSAL::can($meth);
    $c and return $c;

    $$self->exists($meth) or return;

    $c = do { no strict "refs"; \&{$meth} };
    return $c;
}

# XXX isa and DOES should identify structural and auxiliary
# objectclasses respectively

sub DESTROY { }

1;
