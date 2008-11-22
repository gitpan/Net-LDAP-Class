package Net::LDAP::Class::Group;
use strict;
use warnings;
use Carp;
use base qw( Net::LDAP::Class );
use Net::LDAP::Class::MethodMaker (
    'scalar --get_set_init' => [qw( user_class )],
    'related_objects'       => [qw( primary_users secondary_users  )],

);

our $VERSION = '0.16';

=head1 NAME

Net::LDAP::Class::Group - base class for LDAP group objects

=head1 SYNOPSIS

 package MyGroup;
 use strict;
 use base qw( Net::LDAP::Class::Group );
 
 # define action_for_* methods for your LDAP schema
 
 1;

=head1 DESCRIPTION

Net::LDAP::Class::Group is a simple base class intended to be
subclassed by schema-specific Net::LDAP::Class::Group::* classes.

=head1 METHODS

=head2 init

Checks that user_class() is defined.

=cut

sub init {
    my $self = shift;
    $self->SUPER::init(@_);
    unless ( defined $self->user_class ) {
        croak "must define user_class()";
    }
    return $self;
}

=head2 users

Returns array or array ref (based on context) of primary_users()
and secondary_users().

=cut

sub users {
    my $self = shift;
    if (@_) {
        croak "users() is an accessor (getter) only";
    }
    my @users = ( @{ $self->primary_users }, @{ $self->secondary_users } );
    return wantarray ? @users : \@users;
}

=head2 has_user( I<user> )

Returns true if I<user> is amongst users(), false otherwise.

=cut

sub has_user {
    my $self = shift;
    my $user = shift or croak "User required";
    for my $u ( $self->users ) {

        #warn "member $u  <>  user $user";
        if ( "$u" eq "$user" ) {
            return 1;
        }
    }
    return 0;
}

=head2 init_user_class

Override this method in your subclass to set the default User class
for your Group class.

=cut

sub init_user_class { croak "must override init_user_class" }

=head2 name

Same as calling cn() with no arguments. 
A Group object stringifies to this method.

=cut

sub name { shift->cn }

=head2 stringify

Aliased to name().

=cut

sub stringify { shift->name }

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

Net::LDAP::Class

=cut
