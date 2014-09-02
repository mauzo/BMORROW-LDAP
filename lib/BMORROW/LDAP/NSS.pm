package BMORROW::LDAP::NSS;

use 5.010;
use warnings;
use strict;

use parent "BMORROW::LDAP";

use BMORROW::Util   qw/mkhash/;
use Data::Dump      qw/pp/;

my %Lookup = (
    passwd => { 
        class   => "posixAccount",
        by      => "uid",
        attrs   => [qw/ 
            uid uidNumber gidNumber loginClass
            shadowMax shadowLastChange shadowExpire
            gecos homeDirectory loginShell
        /],
    },
    group => { 
        class   => "posixGroup",
        by      => "cn",
        attrs   => [qw/ cn gidNumber uniqueMember /],
    },
    hosts => { 
        class   => "ipHost",
        by      => "cn",
        attrs   => [qw/ cn ipHostNumber /],
    },
    bootstrap => {
        class   => "bootstrapConfigSet",
        by      => "cn",
        attrs   => [qw/ cn bootstrapRequires /],
    },
    sudoers => {
        class   => "sudoRole",
        by      => "cn",
        # This is not complete. I don't care.
        attrs   => [qw/ 
            cn sudoUser sudoHost sudoCommand sudoOption sudoRunAsUser
            sudoRunAsGroup sudoOrder
        /],
    },
                        
);

sub profile { $_[0]{profile} }
sub lookup  { $_[0]{lookup}  }

sub _setif { 
    $_[1]   ? $_[0] = $_[1]     :
    @_ > 2  ? $_[0] = $_[2]     :
    $_[0]
}

sub read_profile {
    my ($L, $search) = @_;

    my $rv = $L->{profile} ||= {};

    my @ctxs = $L->L->root_dse->get_value("namingContexts");
    @ctxs == 1 or die "Root DSE has more than one naming context:"
        . join "", map "\n  $_", @ctxs;

    my $filter = "(objectClass=DUAConfigProfile)";
    length $search and $filter = "(&$filter$search)";

    warn "FIND PROFILE [$ctxs[0]?sub?$filter]\n";
    my $prof = $L->search("finding DUA profile [$search]",
        base    => $ctxs[0],
        scope   => "sub",
        filter  => $filter,
        attrs   => ['@DUAConfigProfile'],
    ) or return;
    say "Reading DUA profile [" . $prof->dn . "]";
    warn "DUA PROFILE: " . pp $prof;

    _setif $$rv{Base}, $prof->defaultSearchBase;
    _setif $$rv{Scope}, $prof->defaultSearchScope, "base";

    for ($prof->serviceSearchDescriptor) {
        my ($srv, $searches) = /(\w+):\s*(.*)/;
        my @searches = 
            map {
                $$_{base}   ||= $$rv{Base};
                $$_{base} =~ s/,$/,$$rv{Base}/;
                $$_{scope}  ||= $$rv{Scope};
                $$_{filter} //= "";
                $_;
            }
            map mkhash([qw/base scope filter/], $_),
            map [ split /\?/ ],
            split /;/, $searches;
        $$rv{Filter}{$srv} = \@searches;
    }
    for ($prof->objectClassMap) {
        my ($srv, $from, $to) = /(\w+):(\w+)=(\w+)/;
        $$rv{Map}{$srv}{class}{$from} = $to;
    }
    for ($prof->attributeMap) {
        my ($srv, $from, $to) = /(\w+):(\w+)=(\w+)/;
        $$rv{Map}{$srv}{att}{$from} = $to;
    }
    
    $L->build_service_maps;
}

sub remap {
    my ($self, $srv, $type, $k) = @_;
    $self->profile->{Map}{$srv}{$type}{$k} // $k;
}

sub build_service_maps {
    my ($self) = @_;
    my $Map = $self->profile;
    my %lookup;

    for my $srv (keys %Lookup) {
        my $l = $Lookup{$srv};
        my $f = $$Map{Filter}{$srv};

        my $oc  = $self->remap($srv, "class", $$l{class});
        my $key = $self->remap($srv, "att", $$l{by});
        my $filt = "(objectClass=$oc)$$_{filter}";

        my @att = map $self->remap($srv, "att", $_), @{$$l{attrs}};

        for (@$f) {
            push @{$lookup{$srv}}, {
                base    => $$_{base},
                scope   => $$_{scope},
                filter  => $filt,
                key     => $key,
                attrs   => \@att,
            };
        }
    }

    $self->{lookup} = \%lookup;
    warn "LOOKUP: " . pp \%lookup;
}

sub resolve {
    my ($L, $map, $key, $extra) = @_;
    my $Map = $L->lookup;
    my $ms = $$Map{$map} or die "No service map defined for [$map]\n";
    my @rv;

    for my $m (@$ms) {
        my $filt = "(&($$m{key}=$key)$$m{filter}$extra)";

        my $ssd = "$$m{base}?$$m{scope}?$filt"; 
        warn "RESOLVE [$ssd]\n";
        push @rv, $L->search("searching [$ssd]",
            base    => $$m{base},
            scope   => $$m{scope},
            filter  => $filt,
            attrs   => $$m{attrs},
        );
    }

    wantarray and return @rv;
    @rv > 1 and die "Expecting only one entry for [$map:$key]:" .
        join "", map "\n  $_", map $_->dn, @rv;
    return $rv[0];
}

1;
