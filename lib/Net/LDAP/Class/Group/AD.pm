package Net::LDAP::Class::Group::AD;
use strict;
use warnings;
use base qw( Net::LDAP::Class::Group );
use Carp;
use Data::Dump ();

our $VERSION = '0.16';

=head1 NAME

Net::LDAP::Class::Group::AD - Active Directory group class

=head1 SYNOPSIS

 # create a subclass for your local Active Directory
 package MyLDAPGroup;
 use base qw( Net::LDAP::Class::Group::AD );
 
 __PACKAGE__->metadata->setup(
    base_dn             => 'dc=mycompany,dc=com',
    attributes          => __PACKAGE__->AD_attributes,
    unique_attributes   => __PACKAGE__->AD_unique_attributes,
 );
 
 1;
 
 # then use your class
 my $ldap = get_and_bind_LDAP_object(); # you write this
 
 use MyLDAPGroup;
 my $group = MyLDAPGroup->new( ldap => $ldap, cn => 'foobar' );
 $group->read_or_create;
 for my $user ($group->users) {
     printf("user %s in group %s\n", $user, $group);
 }

=head1 DESCRIPTION

Net::LDAP::Class::Group::AD isa Net::LDAP::Class::Group implementing
the Active Directory LDAP schema.

=head1 CLASS METHODS

=head2 AD_attributes

Returns array ref of a subset of the default Active Directory
attributes. Only a subset is used since the default schema contains
literally 100s of attributes. The subset was chosen based on its
similarity to the POSIX schema.

=cut

sub AD_attributes {
    [   qw(
            canonicalName
            cn
            description
            distinguishedName
            info
            member
            primaryGroupToken
            whenChanged
            whenCreated
            objectClass
            objectSID
            )
    ];
}

=head2 AD_unique_attributes

Returns array ref of unique Active Directory attributes.

=cut

sub AD_unique_attributes {
    [qw( cn objectSID distinguishedName )];
}

=head1 OBJECT METHODS

=head2 init_user_class

Defaults to Net::LDAP::Class::User::AD.
You likely want to override this in your subclass.

=cut

sub init_user_class {'Net::LDAP::Class::User::AD'}

=head2 fetch_primary_users

Required MethodMaker method for retrieving primary_users from LDAP.

Returns array or array ref based on context, of related User objects
who have this group assigned as their primary group.

=cut

sub fetch_primary_users {
    my $self       = shift;
    my $user_class = $self->user_class;
    my $pgt        = $self->primaryGroupToken;
    my @users      = $user_class->find(
        scope   => 'sub',
        filter  => "(primaryGroupID=$pgt)",
        ldap    => $self->ldap,
        base_dn => $self->base_dn,
    );

    return wantarray ? @users : \@users;
}

=head2 fetch_secondary_users

Required MethodMaker method for retrieving secondary_users from LDAP.

Returns array or array ref based on context, of related User objects
who have this group assigned as a secondary group (memberOf).

=cut

sub fetch_secondary_users {
    my $self = shift;

    $self->read;    # make sure we have latest ldap_entry for member

    my @members    = $self->member;
    my $user_class = $self->user_class;
    my @users;
    for my $dn (@members) {
        my ($cn) = ( $dn =~ m/^cn=([^,]+),/i );
        $dn =~ s/\(/\\(/g;
        $dn =~ s/\)/\\)/g;
        my $user = $user_class->new(
            distinguishedName => $dn,
            ldap              => $self->ldap,
            base_dn           => $self->base_dn,
        )->read;
        if ($user) {
            push( @users, $user );
        }
        else {
            croak "can't find user $cn ($dn) via LDAP";
        }
    }
    return wantarray ? @users : \@users;
}

=head2 gid

Alias for calling primaryGroupToken() method.
Note that primaryGroupToken is dynamically generated 
by the server and cannot be assigned (set).

=cut

sub gid { shift->primaryGroupToken }

=head2 action_for_create([ cn => I<cn_value> ])

Add a group to the database.

May be called as a class method with explicit B<cn> key/value pair.

=cut

sub action_for_create {
    my $self = shift;
    my %opts = @_;
    my $name = delete $opts{cn} || $self->cn
        or croak "cn required to create()";

    my @actions = (
        add => [
            {   dn   => "CN=$name," . $self->base_dn,
                attr => [
                    objectClass => [ 'top', 'group' ],
                    cn          => $name,
                ],
            },
        ]
    );

    return @actions;

}

=head2 action_for_update

Save new cn (name) for an existing group.

=cut

sub action_for_update {
    my $self = shift;
    my %opts = @_;

    my $base_dn = delete $opts{base_dn} || $self->base_dn;

    my @actions;

    # users get translated to 'member' attribute
    if ( exists $self->{users} ) {

        my @names;
        for my $user ( @{ delete $self->{users} } ) {
            my $dn = $user->ldap_entry->dn;
            push @names, $dn;
        }
        $self->member( \@names );    # should trigger _was_set below

    }

    # which fields have changed.
    my %replace;
    for my $attr ( keys %{ $self->{_was_set} } ) {

        next if $attr eq 'cn';                   # part of DN
        next if $attr eq 'objectSID';            # set by server
        next if $attr eq 'primaryGroupToken';    # set by server

        my $old = $self->{_was_set}->{$attr}->{old};
        my $new = $self->{_was_set}->{$attr}->{new};

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
        my $cn = $self->name;
        push(
            @actions,
            update => {
                search => [
                    base   => $base_dn,
                    scope  => "sub",
                    filter => "(cn=$cn)",
                    attrs  => $self->attributes,
                ],
                replace => \%replace
            }
        );
    }

    if ( exists $self->{_was_set}->{cn} ) {

        my $class = ref($self) || $self;

        my $old_name = $self->{_was_set}->{cn}->{old};
        my $new_name = $self->{_was_set}->{cn}->{new};
        if ( $self->debug ) {
            warn "renaming group $old_name to $new_name\n";
        }

        my $oldgroup
            = $class->new( ldap => $self->ldap, cn => $old_name )->read
            or croak "can't find $old_name in LDAP";

        # two steps since cn is part of the dn.
        # first, create a new group with the new name
        push( @actions, $self->action_for_create( cn => $new_name ) );

        # second, delete the old group.
        push( @actions, $self->action_for_delete( cn => $old_name ) );

    }

    if ( !@actions ) {
        warn "no attributes have changed for group $self. Skipping update().";
        return @actions;
    }

    return @actions;
}

=head2 action_for_delete( [cn => I<cn_value>] )

Removes array ref of actions for removing the Group.

You may call this as a class method with an explicit B<cn> key/value
pair.

=cut

sub action_for_delete {
    my $self = shift;
    my %opts = @_;
    my $name = delete $opts{cn} || $self->cn;

    if ( !$name ) {
        croak "cn required to delete a Group";
    }

    # even if called a class method, we need an object
    # in order to find users, etc.
    my $group
        = ref($self)
        ? $self
        : $self->new( cn => $name, ldap => $self->ldap )->read;
    if ( !$group ) {
        croak "no such Group to delete: $name";
    }

    # TODO update all related Users 'memberOf' ?

    my @actions = (
        {   search => [
                base   => $group->base_dn,
                scope  => 'sub',
                filter => "(cn=$name)",
                attrs  => $group->attributes,
            ],
        }
    );

    return ( delete => \@actions );
}

=head2 add_user( I<user_object> )

Push I<user_object> onto the list of member() DNs, checking
that I<user_object> is not already on the list.

=cut

sub add_user {
    my $self = shift;
    my $user = shift;
    if ( !$user or !ref($user) or !$user->isa('Net::LDAP::Class::User::AD') )
    {
        croak "Net::LDAP::Class::User::AD object required";
    }
    unless ( $user->username ) {
        croak
            "User object must have at least a username before adding to group $self";
    }
    for my $u ( $self->secondary_users ) {
        if ( "$u" eq "$user" ) {
            croak "User $user is already a member of group $self";
        }
    }
    my @users = $self->secondary_users;
    push( @users, $user );
    $self->{users} = \@users;
}

=head2 remove_user( I<user_object> )

Drop I<user_object> from the list of member() DNs, checking
that I<user_object> is already on the list.

=cut

sub remove_user {
    my $self = shift;
    my $user = shift;
    if ( !$user or !ref($user) or !$user->isa('Net::LDAP::Class::User::AD') )
    {
        croak "Net::LDAP::Class::User::AD object required";
    }
    unless ( $user->username ) {
        croak
            "User object must have at least a username before removing from group $self";
    }
    my %users = map { $_->username => $_ } @{ $self->secondary_users };
    if ( !exists $users{ $user->username } ) {
        croak "User $user is not a member of group $self";
    }
    delete $users{ $user->username };
    $self->{users} = [ values %users ];
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