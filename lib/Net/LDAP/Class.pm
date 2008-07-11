package Net::LDAP::Class;

use strict;
use warnings;
use base qw( Rose::Object );
use Carp;
use Data::Dump ();
use Net::LDAP;
use Net::LDAP::Entry;
use Net::LDAP::Batch;
use Net::LDAP::Class::Metadata;

use Net::LDAP::Class::MethodMaker (
    'scalar --get_set_init' => [qw( ldap ldap_entry debug batch )], );

use overload '""' => 'stringify';

our $VERSION = '0.03';

=head1 NAME

Net::LDAP::Class - object-relational mapper for Net::LDAP

=head1 SYNOPSIS

 # define your class
 
 package MyLDAPClass;
 use base qw( Net::LDAP::Class );
 
 __PACKAGE__->meta->setup(
    attributes          => [qw( name address phone email )],
    unique_attributes   => [qw( email )],
    base_dn             => 'dc=mycompany,dc=com',
 );
 
 1;
 
 # then use your class

 use MyLDAPClass;
 use Net::LDAP;
 
 my $ldap = create_Net_LDAP_object_and_bind();  # you write this
 
 # create an instance of your class
 my $person = MyLDAPClass->new( ldap => $ldap, email => 'foo@bar.com' );
 
 # load from LDAP or write if not yet existing
 $person->read or $person->create;
 
 # set the 'name' attribute
 $person->name( 'Joe Foo' );
 
 # write your changes 
 $person->update;
 
 # change your mind?
 $person->delete;


=head1 DESCRIPTION

Net::LDAP::Class (NLC) is an object-relational mapping for LDAP. 

I know, it's all wrong to confuse the ORM model with LDAP 
since LDAP is not relational in the same way that a RDBMS is. But the ORM
APIs of projects like DBIx::Class and Rose::DB::Object are so fun and easy to use, 
it seemed like LDAP management should be just as fun and easy.

The architecture of this package is based on Rose::DB::Object, which the author
uses to great effect for RDBMS management.

=head1 METHODS

NLC uses the Rose::Object package to create methods and handle the mundate get/set features.
In addition, Net::LDAP::Class::MethodMaker implements a new method type called B<related_objects>
which handles the get/set/fetch of NLC objects related to a given NLC object. Typically these
are Users and Groups. A User is typically related to one or more Groups, and a Group is typically
related to one or more Users. See Net::LDAP::Class::User and Net::LDAP::Class::Group for
examples.

There are some methods which every NLC subclass must implement. See L<SUBCLASSING> for details.

=head2 init

Override this in a subclass. Be sure to call SUPER::init in your subclass.

=cut

sub init {
    my $self = shift;
    $self->SUPER::init(@_);

    my $meta = $self->meta;
    if ( !$meta or !$meta->is_initialized ) {
        croak
            "must initialize Metadata class before instantiating a new object";
    }

    $self->{ldap} ||= $self->init_ldap;

    if ( !$self->ldap->isa('Net::LDAP') ) {
        croak "ldap value is not a Net::LDAP-derived object";
    }

    return $self;
}

=head2 meta_class

Returns 'Net::LDAP::Class::Metadata' by default.

=cut

sub meta_class {'Net::LDAP::Class::Metadata'}

=head2 meta

Returns an instance of the meta_class() containing all the metadata for
the NLC class. May be called as a class or object method.

=cut

sub meta {
    my ($self) = shift;

    # object method
    if ( ref $self ) {
        return $self->{_meta} ||= $self->meta_class->for_class( ref $self );
    }

    # class method
    return $Net::LDAP::Class::Metadata::Objects{$self}
        || $self->meta_class->for_class($self);
}

=head2 attributes

Shortcut for $self->meta->attributes.

=cut

sub attributes { shift->meta->attributes }

=head2 unique_attributes

Shortcut for $self->meta->unique_attributes.

=cut

sub unique_attributes { shift->meta->unique_attributes }

=head2 base_dn

Shortcut for $self->meta->base_dn.

=cut

sub base_dn { shift->meta->base_dn }

=head2 init_ldap

If you do not pass a Net::LDAP object to new(), you may instead 
set the ldap_uri() class method to a URI string and 
init_ldap() will create a Net::LDAP object and bind() it for you.

Returns a Net::LDAP object.

=cut

sub init_ldap {
    my $self = shift;
    if ( !$self->ldap_uri ) {
        croak "must set ldap_uri() or override init_ldap()";
    }

    my $ldap = Net::LDAP->new( $self->ldap_uri )
        or croak "can't create new Net::LDAP: $!";
    my $msg = $ldap->bind() or croak "can't do anonymous LDAP bind: $!";
    if ( $msg->code ) {
        croak "LDAP bind failed: " . $self->get_ldap_error($msg);
    }
    return $ldap;
}

=head2 init_debug

Sets the default debug flag to whatever the PERL_DEBUG env variable is set to.

=cut

sub init_debug { $ENV{PERL_DEBUG} }

=head2 init_ldap_entry

Returns undef by default.

=cut

sub init_ldap_entry { return undef }

=head2 get_ldap_error( I<ldap_msg> )

Stringify the error message for the I<ldap_msg> object.

=cut

sub get_ldap_error {
    my $self = shift;
    my $msg  = shift or croak "ldap_msg required";
    my $str  = "\n"
        . join( "\n",
        "Return code: " . $msg->code,
        "Message: " . $msg->error_name,
        " :" . $msg->error_text,
        "MessageID: " . $msg->mesg_id,
        "DN: " . $msg->dn,
        ) . "\n";
    return $str;
}

=head2 stringify

Returns the first unique attribute value that is not undef. If no
such value is found, returns the object.

By default all NLC-derived objects are overloaded with this method.

=cut

sub stringify {
    my $self = shift;
    for my $key ( @{ $self->unique_keys } ) {
        my $val = $self->$key;
        return $val if defined $val;
    }
    return $self;
}

=head2 find( I<opts> )

Returns array (or array ref if called in scalar context)
of objects matching I<opts>.

I<opts> may include:

=over

=item ldap

If not present, the ldap() method is called instead.

=item base_dn

If not present, the base_dn() method is called instead.

=back

Any other I<opts> are passed directly to the Net::LDAP search()
method.

Returns undef if no results matching I<opts> are found.
  
=cut

sub find {
    my $self  = shift;
    my $class = ref($self) || $self;
    my %opts  = @_;
    my $ldap  = delete $opts{ldap} || $self->ldap;

    if ( !$ldap ) {
        croak "Net::LDAP object required";
    }

    my $base = delete $opts{base_dn} || $self->base_dn;

    if ( !$base ) {
        croak "must indicate base_dn in opts or call as object method";
    }

    my $msg = $ldap->search(
        base => $base,
        %opts,

        # Net::LDAP::FAQ claims this should return everything for LDAPv2
        attrs => [],
    );

    my @results;

    for my $entry ( $msg->entries() ) {
        push(
            @results,
            $class->new(
                ldap       => $ldap,
                ldap_entry => $entry,
            )
        );
    }

    return unless @results;
    return wantarray ? @results : \@results;
}

=head2 create

Write a new object to the database. Calls the action_for_create() method -- see L<SUBCLASSING>.

=cut

sub create {
    my $self = shift;
    unless ( $self->check_unique_attributes_set ) {
        croak
            "at least one unique attribute must be set in order to create()";
    }
    my @action = $self->action_for_create or return;
    $self->do_batch(@action);
    $self->read or croak "cannot read newly created $self";
    return $self;
}

=head2 read

Read an object's attribute values from the database. You must have
previously set at least one unique attribute in the object
in order for the read() to work.

Returns the object on success, undef if the object was not found.

=cut

sub read {
    my $self = shift;
    my %opts = @_;

    my ( $filter, $value );

    if ( !$opts{filter} && !$opts{value} ) {

        unless ( $self->check_unique_attributes_set ) {
            croak "cannot read() without unique attribute set. "
                . "Unique attributes include: "
                . join( ', ', @{ $self->unique_attributes } );
        }

        # get first unique key set for filter

        for my $key ( @{ $self->unique_attributes } ) {
            if ( defined $self->$key ) {
                $filter = $key;
                $value  = $self->$key;
                last;
            }
        }

    }
    else {
        $filter = delete $opts{filter};
        $value  = delete $opts{value};
    }

    if ( !defined $filter ) {
        croak "could not find a unique filter to read() on";
    }
    if ( !defined $value ) {
        croak "could not find a unique value to read() on";
    }

    my $base_dn = delete $opts{base_dn} || $self->base_dn;

    my $msg = $self->ldap->search(
        base   => $base_dn,
        scope  => "sub",
        filter => "($filter=$value)",

        # Net::LDAP::FAQ claims this should return everything for LDAPv2
        # but perhaps we should explicitly call $self->attributes instead??
        attrs => [],
    );

    if ( $msg->count() > 0 ) {
        carp "$filter $value exists" if $self->debug;

        my $entry = $msg->entry(0);

        # set any entry attributes we've got cached in $self
        for my $attr ( keys %{ $self->{_not_yet_set} } ) {

            my $new = $self->{_not_yet_set}->{$attr};
            my $old = $entry->get_value($attr) || '';
            if ( $new ne $old ) {
                $entry->replace( $attr,
                    delete $self->{_not_yet_set}->{$attr} );
                $self->{_was_set}->{$attr}->{new} = $new;
                $self->{_was_set}->{$attr}->{old} = $old;
            }
            else {
                delete $self->{_not_yet_set}->{$attr};
            }

        }

        # this will cause any existing entry to be DESTROYed
        $self->ldap_entry($entry);

        return $self;
    }
    else {
        return;
    }
}

=head2 update

Write changes to the database. Calls action_for_update() -- see L<SUBCLASSING>.

If no changes are detected, aborts and returns undef.

On successful write, returns the value of read().

=cut

sub update {
    my $self = shift;
    $self->check_unique_attributes_set;
    unless ( $self->ldap_entry ) {
        croak "can't update() without first having a Net::LDAP::Entry loaded";
    }
    my @action = $self->action_for_update or return;

    # clear, since action_for_update() has already used them.
    $self->{_was_set} = {};

    $self->do_batch(@action);

    return $self->read;
}

=head2 delete

Remove the object from the database. You must call read() first.

Returns the value of do_batch().

=cut

sub delete {
    my $self = shift;
    $self->check_unique_attributes_set;
    unless ( $self->ldap_entry ) {
        croak "can't delete() without having a Net::LDAP::Entry loaded";
    }
    my @action = $self->action_for_delete or return;
    return $self->do_batch(@action);
}

=head2 read_or_create

Convenience method. If read() returns undef, create() is called.
Returns the object in any case.

=cut

sub read_or_create {
    my $self = shift;
    if ( !$self->read ) {
        $self->create;
    }
    return $self;
}

=head2 do_batch( I<array_of_actions> )

Creates and runs a Net::LDAP::Batch object, passing it
the I<array_of_actions> to run. Will croak on any error.

=cut

sub do_batch {
    my $self    = shift;
    my @actions = @_;
    if ( !@actions ) {
        warn "no actions to execute\n";
        return;
    }
    my $batch = Net::LDAP::Batch->new(
        ldap    => $self->ldap,
        actions => \@actions,
        debug   => $self->debug,
    );
    $batch->do or croak $batch->error;
    $self->batch($batch);
}

=head2 rollback

Will call the rollback() method on the Net::LDAP::Batch object returned
by batch(). If there is not batch() set, will croak.

=cut

sub rollback {
    my $self = shift;
    if ( $self->batch ) {
        $self->batch->rollback or croak $self->batch->error;
    }
    else {
        croak "no batch to rollback";
    }
    return 1;
}

=head2 action_for_create

See L<SUBCLASSING>.

=cut

sub action_for_create {
    croak "must override action_for_create()";
}

=head2 action_for_update

See L<SUBCLASSING>.

=cut

sub action_for_update {
    croak "must override action_for_update()";
}

=head2 action_for_delete

See L<SUBCLASSING>.

=cut

sub action_for_delete {
    croak "must override action_for_delete()";
}

=head2 check_unique_attributes_set

Returns true (1) if any unique attribute is set
with a defined value.

Returns false (0) if no unique attributes are set.

=cut

sub check_unique_attributes_set {
    my $self = shift;
    my $uk   = $self->unique_attributes;
    if ( !ref($uk) eq 'ARRAY' ) {
        croak "unique_keys must be an ARRAY ref";
    }
    for my $key (@$uk) {
        if ( defined $self->$key ) {
            return 1;
        }
    }
    return 0;
}

=head2 AUTOLOAD

Will croak() with a helpful message if you call a method that does
not exist. Mostly useful for catching cases where you forget to predefine
an attribute.

=cut

sub AUTOLOAD {
    my ( $self, @args ) = @_;

    my ($attribute) = ( our $AUTOLOAD =~ /([^:]+)$/ );

    #    carp "AUTOLOAD called for "
    #        . ref($self)
    #        . " -> $attribute "
    #        . Data::Dump::dump( \@args );

    if ( $attribute eq 'DESTROY' ) {

        #Data::Dump::dump($self);
        return;
    }

    croak qq[no such attribute or method "$attribute" defined for package "]
        . ref($self)
        . qq[ -- do you need to add '$attribute' to your setup() call?"];
}

=head2 dump

Returns Data::Dump::dump output for the NLC object. Useful for debugging.
See also the Net::LDAP::Entry dump() method which can be called on the ldap_entry
value.

 $nlc->dump;                # same as Data::Dump::dump( $nlc )
 $nlc->ldap_entry->dump;    # see Net::LDAP::Entry dump() method
 
=cut

sub dump {
    my $self = shift;
    return Data::Dump::dump($self);
}

1;

__END__

=head1 SUBCLASSING

NLC is designed as a base class with basic default behaviours for most common usage.
However, every subclass must implement some methods, usually because such methods
are specific to the particular LDAP schema you are using with the subclass.

The following methods are required by every NLC subclass. These B<action_for_*> methods
should return either a Net::LDAP::Batch::Action-based object or an array of values
that can be passed to the add_actions() method of the Net::LDAP::Batch class.

See Net::LDAP::Class::User::POSIX and Net::LDAP::Class::Group::POSIX for examples.

=over

=item 

action_for_create

=item 

action_for_update

=item

action_for_delete

=back

In addition, if you use the B<related_objects> MethodMaker feature, then your subclass must
implement a B<fetch_>I<method_name> method for each B<related_objects> method name. Again,
see Net::LDAP::Class::User::POSIX and Net::LDAP::Class::Group::POSIX for examples.

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

Net::LDAP, Net::LDAP::Batch

=cut