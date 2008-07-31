package Net::LDAP::Class::User::AD;
use strict;
use warnings;
use base qw( Net::LDAP::Class::User );
use Carp;
use Data::Dump ();

use Net::LDAP::Class::MethodMaker (
    'scalar --get_set_init' => [qw( default_home_dir default_email_suffix )],
);

our $VERSION = '0.07';

=head1 NAME

Net::LDAP::Class::User::AD - Active Directory User class

=head1 SYNOPSIS

# subclass this class for your local LDAP
 package MyLDAPUser;
 use base qw( Net::LDAP::Class::User::AD );
 
 __PACKAGE__->meta->setup(
    base_dn             => 'dc=mycompany,dc=com',
    attributes          => __PACKAGE__->AD_attributes,
    unique_attributes   => __PACKAGE__->AD_unique_attributes,
 );
 
 1;
 
 # then use your class
 my $ldap = get_and_bind_LDAP_object(); # you write this
 
 use MyLDAPUser;
 my $user = MyLDAPUser->new( ldap => $ldap, sAMAccountName  => 'foobar' );
 $user->read_or_create;
 for my $group ($user->group, @{ $user->groups }) {
     printf("user %s in group %s\n", $user, $group);
 }

=head1 DESCRIPTION

Net::LDAP::Class::User::AD isa Net::LDAP::Class::User implementing
the Active Directory LDAP schema.

=head1 CLASS METHODS

=head2 AD_attributes

Returns array ref of a subset of the default Active Directory
attributes. Only a subset is used since the default schema contains
literally 100s of attributes. The subset was chosen based on its
similarity to the POSIX schema.

=cut

# full attribute list here:
# http://windowsitpro.com/article/articleid/84714/jsi-tip-9910-what-attribute-names-exist-in-my-active-directory-schema.html
# we list only a "relevant" subset

sub AD_attributes {
    [   qw(
            accountExpires
            adminCount
            canonicalName
            cn
            codePage
            countryCode
            description
            displayName
            distinguishedName
            givenName
            groupAttributes
            homeDirectory
            homeDrive
            instanceType
            lastLogoff
            lastLogon
            logonCount
            mail
            memberOf
            middleName
            modifyTimeStamp
            name
            notes
            objectClass
            objectGUID
            objectSID
            primaryGroupID
            profilePath
            pwdLastSet
            sAMAccountName
            sAMAccountType
            sn
            uid
            unicodePwd
            userAccountControl
            userPrincipalName
            uSNChanged
            uSNCreated
            whenCreated
            whenChanged
            )
    ];
}

=head2 AD_unique_attributes

Returns array ref of unique Active Directory attributes.

=cut

sub AD_unique_attributes {
    [qw( sAMAccountName distinguishedName objectSID )];
}

=head1 OBJECT METHODS

All the init_* methods can be specified to the new() constructor without
the init_ prefix.

=head2 fetch_group

Required MethodMaker method for retrieving primary group from LDAP.

Returns an object of type group_class().

=cut

sub fetch_group {
    my $self  = shift;
    my $class = $self->group_class or croak "group_class() required";
    my $gid   = shift || $self->gid;

    if ( !$gid ) {
        croak "cannot fetch group without a gid (primaryGroupID) set";
    }

    # because AD does not store primaryGroupToken but computes it,
    # we must do gymnastics using SIDs
    #warn "gid = $gid";

    my $user_sid_string = _sid2string( $self->objectSID );

    #warn "user_sid_string:  $user_sid_string";
    ( my $group_sid_string = $user_sid_string ) =~ s/\-[^\-]+$/-$gid/;

    #warn "group_sid_string: $group_sid_string";

    return $class->new(
        objectSID => $group_sid_string,
        ldap      => $self->ldap
    )->read;
}

sub _sid2string {
    my $sid = shift;
    my (@unpack) = unpack( "H2 H2 n N V*", $sid );
    my ( $sid_rev, $num_auths, $id1, $id2, @ids ) = (@unpack);
    return join( "-", "S", $sid_rev, ( $id1 << 32 ) + $id2, @ids );
}

sub _string2sid {
    my $string = shift;
    my (@split) = split( m/\-/, $string );
    my ( $prefix, $sid_rev, $auth_id, @ids ) = (@split);
    if ( $auth_id != scalar(@ids) ) {
        die "bad string: $string";
    }

    my $sid = pack( "C4", "$sid_rev", "$auth_id", 0, 0 );
    $sid .= pack( "C4",
        ( $auth_id & 0xff000000 ) >> 24,
        ( $auth_id & 0x00ff0000 ) >> 16,
        ( $auth_id & 0x0000ff00 ) >> 8,
        $auth_id & 0x000000ff );

    for my $i (@ids) {
        $sid .= pack( "I", $i );
    }

    return $sid;
}

=head2 fetch_groups

Required MethodMaker method for retrieving secondary groups from LDAP.

Returns array or array ref (based on context) of objects of type
group_class().

=cut

sub fetch_groups {
    my $self        = shift;
    my @group_dns   = $self->memberOf;
    my $group_class = $self->group_class;
    my @groups;
    for my $dn (@group_dns) {
        $dn =~ s/^cn=([^,]+),.+/$1/i;
        push(
            @groups,
            $group_class->new(
                cn   => $dn,
                ldap => $self->ldap
                )->read
        );
    }
    return wantarray ? @groups : \@groups;
}

=head2 gid

Alias for primaryGroupID() attribute.

=cut

sub gid {
    my $self = shift;
    $self->primaryGroupID(@_);
}

=head2 init_default_home_dir

Returns B<\home>.

=cut

sub init_default_home_dir {'\home'}

=head2 init_default_email_suffix

Returns an empty string.

=cut

sub init_default_email_suffix {''}

=head2 password([I<plain_password>])

Convenience wrapper around unicodePwd() attribute method.

This method will verify I<plain_password> is in the correct
encoding that AD expects and set it in the ldap_entry(). 

If no argument is supplied, returns the 
string set in ldap_entry() (if any).

=cut

sub password {
    my $self      = shift;
    my $attribute = 'unicodePwd';

    if ( !defined $self->ldap_entry && grep { $_ eq $attribute }
        @{ $self->attributes } )
    {

        if ( scalar @_ ) {
            $self->{_not_yet_set}->{$attribute}
                = $self->_encode_pass( $_[0] );
        }
        return
            exists $self->{_not_yet_set}->{$attribute}
            ? $self->{_not_yet_set}->{$attribute}
            : undef;

    }

    if (@_) {
        my $octets = $self->_encode_pass( $_[0] );
        my @old    = $self->ldap_entry->get_value($attribute);
        $self->ldap_entry->replace( $attribute, $octets );
        $self->{_was_set}->{$attribute}->{new} = $octets;

       # do not overwrite an existing 'old' value, since we might need to know
       # what was originally in the ldap_entry in order to replace it.
        unless ( exists $self->{_was_set}->{$attribute}->{old} ) {
            $self->{_was_set}->{$attribute}->{old}
                = @old > 1 ? \@old : $old[0];
        }
    }

    return $self->ldap_entry->get_value($attribute);
}

sub _is_encoded {
    my $str = shift;
    if ( $str =~ m/^"\000.+"\000$/ ) {
        return 1;
    }
    return 0;
}

sub _encode_pass {
    my $self = shift;
    my $pass = shift or croak "password required";

    # detect if password is already encoded and do not double encode
    if ( _is_encoded($pass) ) {
        return $pass;
    }

    my $npass = '';
    map { $npass .= "$_\000" } split( //, "\"$pass\"" );

    return $npass;
}

sub _decode_pass {
    my $self = shift;
    my $pass = shift or croak "password required";
    if ( !_is_encoded($pass) ) {
        return $pass;
    }

    my $decoded = '';
    for my $char ( split( //, $pass ) ) {
        $char =~ s/\000$//;
        $decoded .= $char;
    }
    $decoded =~ s/^"|"$//g;

    return $decoded;
}

=head2 action_for_create([ sAMAccountName => I<username> ])

Returns hash ref suitable for creating a Net::LDAP::Batch::Action::Add.

May be called as a class method with explicit B<uid> and B<uidNumber>
key/value pairs.

=cut

sub action_for_create {
    my $self     = shift;
    my %opts     = @_;
    my $username = delete $opts{sAMAccountName} || $self->sAMAccountName
        or croak "sAMAccountName required to create()";
    my $base_dn = delete $opts{base_dn} || $self->base_dn;

    my ( $group, $gid, $givenName, $sn, $cn, $email )
        = $self->setup_for_write;

    my @actions = (
        add => {
            dn   => "CN=$cn," . $base_dn,
            attr => [
                objectClass =>
                    [ "top", "person", "organizationalPerson", "user" ],
                sAMAccountName => $username,
                givenName      => $givenName,
                displayName    => $cn,
                sn             => $sn,
                cn             => $cn,
                homeDirectory  => $self->default_home_dir . "\\$username",
                mail           => $email,
            ],
        }
    );

    push( @{ $actions[1]->{attr} }, primaryGroupID => $gid ) if $gid;

    # set password if not set.
    # this is useful for default random passwords.
    # must do this as second update action rather than in initial add
    # due to AD security restriction.
    my $pass = $self->password || $self->random_string(10);
    $pass = $self->_encode_pass($pass);

# the 512 userAccountControl value indicates to AD
# that a password is required.
# see
# http://www.sysoptools.com/support/files/Fixing%20user%20accounts%20flagged%20as%20system%20accounts%20-%20the%20UserAccountControl%20AD%20attribute.doc
    push(
        @actions,
        update => {
            search => [
                base   => "CN=$cn," . $base_dn,
                scope  => 'sub',
                filter => "(CN=$cn)",
                attrs  => $self->attributes
            ],
            replace => { unicodePwd => $pass, userAccountControl => 512 },
        }
    );

    # groups
    if ( exists $self->{groups} ) {
        my @names;
        for my $group ( @{ $self->{groups} } ) {
            eval { $group->add_user($self); };
            if ($@) {
                if ( $@ =~ m/already/ ) {
                    next;
                }
                else {
                    croak $@;
                }
            }
        }
        push( @{ $actions[1]->{attr} }, memberOf => \@names );
    }

    return @actions;
}

=head2 setup_for_write

Utility method for generating default values for 
various attributes. Called by both action_for_create()
and action_for_update().

Returns array of values in this order:

 $groupname, $gid, $givenName, $sn, $cn, $email

=cut

sub setup_for_write {
    my $self = shift;

    my $gid;
    my $group = $self->{group} || $self->gid;
    if ($group) {
        if ( ref $group and $group->isa('Net::LDAP::Class::Group') ) {
            $gid = $group->gid;
        }
        else {
            my $group_obj = $self->fetch_group($group);
            if ( !$group_obj ) {
                croak "no such group in AD server: $group";
            }
            $gid = $group_obj->gid;
        }
    }

    # set name
    unless ( $self->displayName
        || $self->cn
        || $self->sn
        || $self->givenName )
    {
        croak "either displayName, cn, sn or givenName must be set";
    }

    # the name logic breaks horribly here for anything but trivial cases.
    my @name_parts = split( m/\s+/, $self->cn || $self->displayName || '' );
    my $givenName = $self->givenName || shift(@name_parts);
    my $sn        = $self->sn        || join( ' ', @name_parts );
    my $cn        = $self->cn        || join( ' ', $givenName, $sn );

    my $email = $self->mail || $self->username . $self->default_email_suffix;

    return ( $group, $gid, $givenName, $sn, $cn, $email );
}

=head2 action_for_update

Returns array ref suitable for creating a Net::LDAP::Batch::Action::Update.

=cut

sub action_for_update {
    my $self     = shift;
    my %opts     = @_;
    my $username = $self->username;

    unless ($username) {
        croak "must have sAMAccountName set to update";
    }

    my $base_dn = delete $opts{base_dn} || $self->base_dn;

    my @actions;

    my ( $group, $gid, $givenName, $sn, $cn, $email, $pass )
        = $self->setup_for_write;

    my %derived = (
        cn             => $cn,
        givenName      => $givenName,
        sn             => $sn,
        sAMAccountName => $username,
        unicodePwd     => $pass,
        primaryGroupID => $gid,
        displayName    => $cn,
        mail           => $email,
        homeDirectory  => $self->default_home_dir . "\\$username",
    );

    # which fields have changed.
    my %replace;
    for my $attr ( keys %{ $self->{_was_set} } ) {

        my $old = $self->{_was_set}->{$attr}->{old};
        my $new = $self->{_was_set}->{$attr}->{new} || $derived{$attr};

        if ( defined($old) and !defined($new) ) {
            $replace{$attr} = undef;
        }
        elsif ( !defined($old) and defined($new) ) {
            $replace{$attr} = $new;
        }
        elsif ( !defined($old) and !defined($new) ) {

            #$replace{$attr} = undef;
        }
        elsif ( $old ne $new ) {
            $replace{$attr} = $new;
        }

    }

    # what group(s) have changed?
    # compare primary group first
    # this assumes that setting group() is preferred to
    # explicitly setting gidNumber.
    if ( !exists $replace{primaryGroupID}
        and $self->group->gid != $self->gid )
    {

        # primary group has changed
        $replace{primaryGroupId} = $self->group->gid;

        # clear so next access re-fetches
        delete $self->{group};

    }

    # next, secondary group membership.
    # check if any have been set explicitly,
    # since otherwise there is nothing to be done.
    if ( exists $self->{groups} ) {

        #carp Data::Dump::dump $self->{groups};

        my $existing_groups = $self->fetch_groups;

        #carp Data::Dump::dump $existing_groups;

        my %existing = map { $_->cn => $_ } @$existing_groups;

        # the delete $self->{groups} has helpful side effect of clearing
        # cache.
        my %new = map { $_->cn => $_ } @{ delete $self->{groups} };

        # which should be added
        my @to_add;
        for my $cn ( keys %new ) {
            if ( !exists $existing{$cn} ) {
                my $group = $new{$cn};

                #warn "add_user $self to group $group";
                eval { $group->add_user($self) };

                #warn "\$\@ = $@";
                if ($@) {
                    if ( $@ =~ m/already a member/ ) {

                        # add_user already called
                        next;
                    }
                    else {
                        croak $@;
                    }
                }
                push( @to_add, $group->action_for_update );
            }
        }

        # which should be removed
        my @to_rm;
        for my $cn ( keys %existing ) {
            if ( !exists $new{$cn} ) {
                my $group = $existing{$cn};
                eval { $group->remove_user($self) };
                if ($@) {
                    if ( $@ =~ m/not a member/ ) {

                        # remove_user already called
                        next;
                    }
                    else {
                        croak $@;
                    }
                }
                push( @to_rm, $group->action_for_update );
            }
        }

        push( @actions, @to_add, @to_rm );

    }

    if (%replace) {
        push(
            @actions,
            update => {
                search => [
                    base   => $base_dn,
                    scope  => "sub",
                    filter => "(sAMAccountName=$username)",
                    attrs  => $self->attributes,
                ],
                replace => \%replace
            }
        );
    }

    if ( !@actions ) {
        warn "no fields have changed for User $username. Skipping update().";
        return;
    }

    carp "updating User with actions: " . Data::Dump::dump( \@actions )
        if $self->debug;

    return @actions;

}

=head2 action_for_delete

Returns action suitable for creating a Net::LDAP::Batch::Action::Delete.

=cut

sub action_for_delete {
    my $self     = shift;
    my %opts     = @_;
    my $username = delete $opts{sAMAccountName}
        || delete $opts{username}
        || $self->username;

    my $base_dn = delete $opts{base_dn} || $self->base_dn;

    if ( !$username ) {
        croak "username required to delete a User";
    }

    # delete the user
    my @actions = (
        delete => {
            search => [
                base   => $base_dn,
                scope  => "sub",
                filter => "(sAMAccountName=$username)",
                attrs  => $self->attributes,
            ]
        }
    );

    return @actions;
}

1;

__END__

=head1 AUTHOR

Peter Karman, C<< <karman at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-net-ldap-class at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-LDAP-Class>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::LDAP::Class

You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-LDAP-Class>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-LDAP-Class>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-LDAP-Class>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-LDAP-Class>

=back

=head1 ACKNOWLEDGEMENTS

The Minnesota Supercomputing Institute C<< http://www.msi.umn.edu/ >>
sponsored the development of this software.

=head1 COPYRIGHT

Copyright 2008 by the Regents of the University of Minnesota.
All rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 SEE ALSO

Net::LDAP

=cut
