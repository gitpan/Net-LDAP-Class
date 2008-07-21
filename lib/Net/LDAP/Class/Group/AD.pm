package Net::LDAP::Class::Group::AD;
use strict;
use warnings;
use base qw( Net::LDAP::Class::Group );
use Carp;
use Data::Dump ();

our $VERSION = '0.04';

=head1 NAME

Net::LDAP::Class::Group::AD - Active Directory group class

=head1 SYNOPSIS

 # create a subclass for your local Active Directory
 package MyLDAPGroup;
 use base qw( Net::LDAP::Class::Group::AD );
 
 __PACKAGE__->meta->setup(
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
    [qw( cn objectSID )];
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
        scope  => 'sub',
        filter => "(primaryGroupID=$pgt)",
        ldap   => $self->ldap,
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
        my $user = $user_class->new( cn => $cn, ldap => $self->ldap )->read;
        push( @users, $user );
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
            {   dn   => "CN=$name,CN=Users," . $self->base_dn,
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

    if ( !grep { exists $self->{_was_set}->{$_} } @{ $self->attributes } ) {
        warn "no attributes have changed for group $self. Skipping update().";
        return 1;
    }

    my @actions;

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

        # TODO must be change 'memberOf' attributes for all related users?

        # two steps since cn is part of the dn.
        # first, create a new group with the new name
        push( @actions, $self->action_for_create( cn => $new_name ) );

        # second, delete the old group.
        push( @actions, $self->action_for_delete( cn => $old_name ) );

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
    my $group = ref($self) ? $self : $self->new( cn => $name )->read;
    if ( !$group ) {
        croak "no such Group to delete: $name";
    }

    # TODO update all related Users 'memberOf' ?

    my @actions = (
        {   search => [
                base   => 'CN=Users,' . $group->base_dn,
                scope  => 'sub',
                filter => "(cn=$name)",
                attrs  => $group->meta->attributes,
            ],
        }
    );

    return ( delete => \@actions );
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
