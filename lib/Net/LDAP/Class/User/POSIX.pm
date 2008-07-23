package Net::LDAP::Class::User::POSIX;
use strict;
use warnings;
use Carp;
use Data::Dump qw( dump );
use Digest::SHA1;
use MIME::Base64;
use base qw( Net::LDAP::Class::User );
use Rose::Object::MakeMethods::Generic ( 'scalar --get_set_init' =>
        [qw( default_shell default_home_dir default_email_suffix )], );

our $VERSION = '0.06';

# see http://www.ietf.org/rfc/rfc2307.txt

=head1 NAME

Net::LDAP::Class::User::POSIX - user class for POSIX LDAP schema

=head1 SYNOPSIS

 # subclass this class for your local LDAP
 package MyLDAPUser;
 use base qw( Net::LDAP::Class::User::POSIX );
 
 __PACKAGE__->meta->setup(
    base_dn             => 'dc=mycompany,dc=com',
    attributes          => __PACKAGE__->POSIX_attributes,
    unique_attributes   => __PACKAGE__->POSIX_unique_attributes,
 );
 
 1;
 
 # then use your class
 my $ldap = get_and_bind_LDAP_object(); # you write this
 
 use MyLDAPUser;
 my $user = MyLDAPUser->new( ldap => $ldap, uid  => 'foobar' );
 $user->read_or_create;
 for my $group ($user->group, @{ $user->groups }) {
     printf("user %s in group %s\n", $user, $group);
 }

=head1 DESCRIPTION

Net::LDAP::Class::User::POSIX isa Net::LDAP::Class::User implementing
the POSIX LDAP schema.

=head1 CLASS METHODS

=head2 POSIX_attributes

Returns array ref of default POSIX attributes.

=cut

sub POSIX_attributes {

    return [
        qw(
            uid userPassword uidNumber gidNumber
            gecos cn mail sn givenName pwdChangedTime
            homeDirectory loginShell
            )
    ];

}

=head2 POSIX_unique_attributes

Returns array ref of unique POSIX attributes: B<uid> and B<uidNumber>.

=cut

sub POSIX_unique_attributes {
    return [qw( uid uidNumber )];
}

=head1 OBJECT METHODS

All the init_* methods can be specified to the new() constructor without
the init_ prefix.

=head2 init_default_shell

Returns B</bin/bash>.

=cut

sub init_default_shell {'/bin/bash'}

=head2 init_default_home_dir

Returns B</home>.

=cut

sub init_default_home_dir {'/home'}

=head2 init_default_email_suffix

Returns an empty string.

=cut

sub init_default_email_suffix {''}

=head2 init_group_class

Defaults to Net::LDAP::Class::Group::POSIX.
You likely want to override this in your subclass.

=cut

sub init_group_class {'Net::LDAP::Class::Group::POSIX'}

=head2 action_for_create([ uid => I<username>, uidNumber => I<nnn> ])

Returns hash ref suitable for creating a Net::LDAP::Batch::Action::Add.

May be called as a class method with explicit B<uid> and B<uidNumber>
key/value pairs.

=cut

sub action_for_create {
    my $self = shift;
    my %opts = @_;
    my $uid  = delete $opts{uidNumber} || $self->uidNumber
        or croak "uidNumber required to create()";
    my $username = delete $opts{uid} || $self->uid
        or croak "uid required to create()";

    my ( $group, $gid, $givenName, $sn, $gecos, $email, $hash )
        = $self->setup_for_write;

    # note that not setting a homeDirectory or sn is a schema error
    my @actions = (
        add => {
            dn   => "uid=$username,ou=$group,ou=People," . $self->base_dn,
            attr => [
                objectClass  => [ "top", "person", "posixAccount" ],
                cn           => $username,
                givenName    => $givenName,
                sn           => $sn,
                uid          => $username,
                userPassword => "$hash",
                uidNumber    => $uid,
                gidNumber    => $gid,
                gecos        => $gecos,
                homeDirectory    => $self->default_home_dir . "/$username",
                loginShell       => $self->default_shell,
                shadowMin        => "-1",
                shadowMax        => "99999",
                shadowWarning    => "7",
                shadowLastChange => "13767",
                mail             => $email
            ],
        }
    );

    # secondary groups
    if ( exists $self->{groups} ) {
        for my $group ( @{ $self->{groups} } ) {
            my @newUids;
            if ( $group->memberUid ) {
                @newUids = ( $group->memberUid, $username );
            }
            else {
                @newUids = ($username);
            }
            my $group_name = $group->cn;
            my $group_dn   = $group->base_dn;
            my $action     = {
                search => [
                    base   => "ou=Group,$group_dn",
                    scope  => "sub",
                    filter => "(cn=$group_name)",
                    attrs  => $group->meta->attributes,
                ],
                replace => { memberUid => [@newUids] }
            };
            push( @actions, update => $action );
        }
    }

    return @actions;
}

=head2 setup_for_write

Utility method for generating default values for 
various attributes. Called by both action_for_create()
and action_for_update().

Returns array of values in this order:

 $groupname, $gid, $givenName, $sn, $gecos, $email, $passwordHash

=cut

sub setup_for_write {
    my $self = shift;

    # must find the group name first so we can set up dn correctly
    unless ( $self->gidNumber or $self->group ) {
        croak "group or gidNumber required";
    }
    my ( $group, $gid );

    my $group_class = $self->group_class;

    $group = $self->group
        || $group_class->new(
        gidNumber => $self->gidNumber,
        ldap      => $self->ldap
        )->read;

    if ( !defined $group ) {
        croak "group "
            . $self->gidNumber
            . " is not yet in LDAP. Must add it before creating User";
    }

    if ( ref $group and $group->isa('Net::LDAP::Class::Group::POSIX') ) {
        $gid   = $group->gidNumber;
        $group = $group->cn;
    }
    $gid ||= $self->gidNumber || $self->group->gidNumber;

    # set name
    unless ( $self->gecos || $self->sn || $self->givenName ) {
        croak "either gecos, sn or givenName must be set";
    }

    # the name logic breaks horribly here for anything but trivial cases.
    my @name_parts = split( m/\s+/, $self->gecos || '' );
    my $givenName = $self->givenName || shift(@name_parts);
    my $sn        = $self->sn        || join( ' ', @name_parts );
    my $gecos     = $self->gecos     || join( ' ', $givenName, $sn );

    my $email = $self->mail || $self->username . $self->default_email_suffix;

    # set password if not set.
    # this is useful for default random passwords.
    my $hash = $self->userPassword || $self->new_password;

    return ( $group, $gid, $givenName, $sn, $gecos, $email, $hash );
}

=head2 action_for_update

Returns array ref suitable for creating a Net::LDAP::Batch::Action::Update.

=cut

sub action_for_update {
    my $self     = shift;
    my %opts     = @_;                 # currently unused
    my $uid      = $self->uidNumber;
    my $username = $self->uid;

    unless ( $username and $uid ) {
        croak "must have uid and uidNumber set to update";
    }

    my @actions;

    my ( $group, $gid, $givenName, $sn, $gecos, $email, $hash )
        = $self->setup_for_write;

    my %derived = (
        cn            => $username,
        givenName     => $givenName,
        sn            => $sn,
        uid           => $username,
        userPassword  => $hash,
        uidNumber     => $uid,
        gidNumber     => $gid,
        gecos         => $gecos,
        mail          => $email,
        homeDirectory => $self->default_home_dir . "/$username",
        loginShell    => $self->default_shell,
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

    if (%replace) {
        push(
            @actions,
            update => {
                search => [
                    base   => "ou=People," . $self->base_dn,
                    scope  => "sub",
                    filter => "(uid=$username)",
                    attrs  => $self->meta->attributes,
                ],
                replace => \%replace
            }
        );
    }

    # what group(s) have changed?
    # compare primary group first
    # this assumes that setting group() is preferred to
    # explicitly setting gidNumber.
    if ( !exists $replace{gidNumber}
        and $self->group->gidNumber != $self->gidNumber )
    {

        # primary group has changed
        # must set gidNumber and change dn in two steps.
        my $newgroup = $self->group->cn;
        push(
            @actions,
            update => [
                {   search => [
                        base   => "ou=People," . $self->base_dn,
                        scope  => "sub",
                        filter => "(uid=$username)",
                        attrs  => $self->meta->attributes,
                    ],
                    replace => { gidNumber => $self->group->gidNumber },
                },
                {   dn => {
                        'newrdn'       => "uid=$username",
                        'deleteoldrdn' => 1,
                        'newsuperior'  => "ou=$newgroup,ou=People,"
                            . $self->group->base_dn,
                    },
                    search => [
                        base   => "ou=People," . $self->base_dn,
                        scope  => "sub",
                        filter => "(uid=$username)",
                        attrs  => $self->meta->attributes,
                    ],
                }
            ],
        );

        # clear so next access re-fetches
        delete $self->{group};

    }

    # next, secondary group membership.
    # check if any have been set explicitly,
    # since otherwise there is nothing to be done.
    if ( exists $self->{groups} ) {

        my $existing_groups = $self->fetch_groups;
        my %existing = map { $_->gidNumber => $_ } @$existing_groups;
        
        # the delete $self->{groups} has helpful side effect of clearing
        # cache.
        my %new = map { $_->gidNumber => $_ } @{ delete $self->{groups} };

        # which should be added
        my @to_add;
        for my $gid ( keys %new ) {
            if ( !exists $existing{$gid} ) {
                my @newUids    = ( $new{$gid}->memberUid, $self->uid );
                my $group_name = $new{$gid}->cn;
                my $group_dn   = $new{$gid}->base_dn;
                my $action     = {
                    search => [
                        base   => "ou=Group,$group_dn",
                        scope  => "one",
                        filter => "(cn=$group_name)",
                        attrs  => $new{$gid}->meta->attributes,
                    ],
                    replace => { memberUid => [@newUids] }
                };
                push( @to_add, update => $action );
            }
        }

        # which should be removed
        my @to_rm;
        for my $gid ( keys %existing ) {
            if ( !exists $new{$gid} ) {
                my @newUids
                    = grep { $_ ne $self->uid } $existing{$gid}->memberUid;
                my $group_name = $existing{$gid}->cn;
                my $group_dn   = $existing{$gid}->base_dn;
                my $action     = {
                    search => [
                        base   => "ou=Group,$group_dn",
                        scope  => "one",
                        filter => "(cn=$group_name)",
                        attrs  => $existing{$gid}->meta->attributes,
                    ],
                    replace => { memberUid => [@newUids] }
                };
                push( @to_rm, update => $action );
            }
        }

        carp "to_add: " . dump( \@to_add ) if $self->debug;
        carp "to_rm: " . dump( \@to_rm )   if $self->debug;

        push( @actions, @to_add, @to_rm );

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

Returns hash ref suitable for creating a Net::LDAP::Batch::Action::Delete.

=cut

sub action_for_delete {
    my $self     = shift;
    my %opts     = @_;
    my $username = delete $opts{uid} || $self->uid;

    if ( !$username ) {
        croak "uid required to delete a User";
    }

    # delete the user
    my @actions = (
        delete => {
            search => [
                base   => "ou=People," . $self->base_dn,
                scope  => "sub",
                filter => "(uid=$username)",
                attrs  => $self->meta->attributes,
            ]
        }
    );

    return @actions;
}

=head2 fetch_group

Required MethodMaker method for retrieving primary group from LDAP.

Returns an object of type group_class().

=cut

sub fetch_group {
    my $self = shift;
    my $class = $self->group_class or croak "group_class() required";

    if ( !$self->gidNumber ) {
        croak "cannot fetch group without a gidNumber set";
    }

    # get groups too
    return $class->new(
        gidNumber => $self->gidNumber,
        ldap      => $self->ldap
    )->read;
}

=head2 fetch_groups

Required MethodMaker method for retrieving secondary groups from LDAP.

Returns array or array ref (based on context) of objects of type
group_class().

=cut

sub fetch_groups {
    my $self = shift;
    my $class = $self->group_class or croak "group_class() required";
    return $class->find(
        ldap    => $self->ldap,
        base_dn => 'ou=Group,' . $self->group->base_dn,
        filter  => "(memberUid=" . $self->uid . ")",
    );
}

=head2 gid

Alias for gidNumber() attribute.

=cut

sub gid {
    my $self = shift;
    $self->gidNumber(@_);
}

=head2 password([I<plain_password>])

Convenience wrapper around userPassword() attribute method.

This method will SHA-1-hashify I<plain_password> using ssha_hash()
and set the hash
in the ldap_entry(). If no argument is supplied, returns the hash
string set in ldap_entry() (if any).

=cut

sub password {
    my $self      = shift;
    my $attribute = 'userPassword';

    if ( !defined $self->ldap_entry && grep { $_ eq $attribute }
        @{ $self->attributes } )
    {

        if ( scalar @_ ) {
            $self->{_not_yet_set}->{$attribute} = $self->ssha_hash( $_[0] );
        }
        return
            exists $self->{_not_yet_set}->{$attribute}
            ? $self->{_not_yet_set}->{$attribute}
            : undef;

    }

    if (@_) {
        my $hash = $self->ssha_hash( $_[0] );
        my @old  = $self->ldap_entry->get_value($attribute);
        $self->ldap_entry->replace( $attribute, $hash );
        $self->{_was_set}->{$attribute}->{new} = $hash;

       # do not overwrite an existing 'old' value, since we might need to know
       # what was originally in the ldap_entry in order to replace it.
        unless ( exists $self->{_was_set}->{$attribute}->{old} ) {
            $self->{_was_set}->{$attribute}->{old}
                = @old > 1 ? \@old : $old[0];
        }
    }

    return $self->ldap_entry->get_value($attribute);
}

=head2 new_password([I<len>])

Returns a SHA-1-hashed password from a random string of length I<len>.
Default length is 8 characters. This method is just a simple
wrapper around ssha_hash() and random_string().

=cut

sub new_password {
    my $self = shift;
    return $self->ssha_hash( $self->random_string(@_) );
}

sub _random_seed {
    my ($len) = @_;
    my ( @charset, $usert, $system, $cuser,      $csystem );
    my ( $i,       $val,   $chars,  $tmp_passwd, @chars );

    # possible characters
    (@charset) = ( 'a' .. 'z', 'A' .. 'Z', '0' .. '9', '.', '/' );

    sleep( int( rand(3) + 1 ) );
    ( $usert, $system, $cuser, $csystem ) = times;

    srand( ( $$ ^ $usert ^ $system ^ time ) );

    for ( $i = 0; $i <= ( $len - 1 ); $i++ ) {
        $val = $charset[ int( rand($#charset) + 1 ) ];
        $chars[$i] = $val;
    }

    # pack characters into scalar
    $tmp_passwd = pack( 'aa', @chars );
    return $tmp_passwd;
}

=head2 ssha_hash( I<string> )

Returns seeded hash of I<string> using SHA-1. See
http://www.openldap.org/faq/data/cache/347.html

B<NOTE:> The hash will contain the LDAP-required
C<{SSHA}> prefix. If the prefix is already present, will
return I<string> untouched.

=cut

sub ssha_hash {
    my $self = shift;
    my $string = shift or croak "string required";
    return $string if $string =~ m/^\{SSHA\}/;

    my $seed = _random_seed(8);
    my $sha1 = Digest::SHA1->new;
    $sha1->add($string);
    $sha1->add($seed);

    return '{SSHA}' . encode_base64( $sha1->digest . $seed, '' );
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
