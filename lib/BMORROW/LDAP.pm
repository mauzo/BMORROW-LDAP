package BMORROW::LDAP;

=head1 NAME

BMORROW::LDAP - My Net::LDAP subclass

=cut

use warnings;
use strict;
use mro "c3";

use BMORROW::Util   qw/ckisa call_all_methods/;
use Net::LDAP;
use Scalar::Util    qw/blessed/;
use Try::Tiny;

our $VERSION = "1";

sub ckldap {
    my ($msg, $rv) = @_;
    $rv->code == 0 and return $rv;
    die "$msg: LDAP error: " . $rv->error;
}

sub new {
    my ($class, $server, @bind) = @_;
    my $L = Net::LDAP->new($server)
        or die "Can't connect to LDAP server [$server]\n";
    ckldap "bind", $L->bind(@bind);
    return bless { L => $L }, $class;
}

sub L { $_[0]{L} }

sub entry_class { "BMORROW::LDAP::Entry" }

sub expand_search {
    my ($self, $s, $desc) = @_;
    ckisa $s, "Net::LDAP::Search";

    my $class = $self->entry_class;
    eval "require $class";

    wantarray and return map $class->new($_), $s->entries;

    my $count = $s->count or return;
    $count == 1 or die 
        "$desc: search returned more than one entry:" .
            join "", map "  \n", map $_->dn, $s->entries;

    $class->new($s->entry(0));
}

sub extra_attributes { "objectClass" }

sub get_extra_attributes {
    my ($self) = @_;
    my $extra = $self->{extra_attributes} ||= [
        call_all_methods $self, "extra_attributes", "down"
    ];
    @$extra;
}

sub add_extra_attributes {
    my ($self, @extra) = @_;
    $self->get_extra_attributes;
    push @{$self->{extra_attributes}}, @extra;
}

sub search {
    my ($self, $desc, %params) = @_;

    push @{$params{attrs}}, $self->get_extra_attributes;

    my $search = ckldap $desc, $self->L->search(%params);
    $self->expand_search($search, $desc);
}

1;

=head1 AUTHOR

Ben Morrow <ben@morrow.me.uk>

=head1 COPYRIGHT

Copyright 2014 Ben Morrow.

Released under the 2-clause BSD licence.

