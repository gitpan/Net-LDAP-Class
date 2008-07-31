use Test::More tests => 37;
use strict;

use_ok('Net::LDAP::Class');
use_ok('Net::LDAP::Class::User::POSIX');
use_ok('Net::LDAP::Class::Group::POSIX');

use lib 't/lib';
use Net::LDAP;
use Data::Dump qw( dump );
use LDAPTestPOSIX;

ok( my $server = LDAPTestPOSIX::spawn_server(), "spawn server" );
ok( my $ldap = Net::LDAP->new(
        LDAPTestPOSIX::server_host(),
        port => LDAPTestPOSIX::server_port()
    ),
    "connect to server"
);

{

    package MyLDAPUser;
    use base 'Net::LDAP::Class::User::POSIX';

    __PACKAGE__->meta->setup(
        base_dn           => 'dc=test,dc=local',
        attributes        => __PACKAGE__->POSIX_attributes,
        unique_attributes => __PACKAGE__->POSIX_unique_attributes,
    );

    sub init_group_class {'MyLDAPGroup'}

}

{

    package MyLDAPGroup;
    use base 'Net::LDAP::Class::Group::POSIX';

    __PACKAGE__->meta->setup(
        base_dn           => 'dc=test,dc=local',
        attributes        => __PACKAGE__->POSIX_attributes,
        unique_attributes => __PACKAGE__->POSIX_unique_attributes,
    );

    sub init_user_class {'MyLDAPUser'}
}

ok( $ldap->bind, "bind to server" );

ok( my $group = MyLDAPGroup->new(
        gidNumber => 1000,
        cn        => 'foogroup',
        ldap      => $ldap,
    ),
    "new group"
);

ok( $group->create, "create $group" );

ok( my $bar_group = MyLDAPGroup->new(
        ldap      => $ldap,
        gidNumber => '1111',
        cn        => 'bargroup'
    ),
    "new bargroup"
);

ok( $bar_group->create, "create $bar_group" );

ok( my $user = MyLDAPUser->new(
        uid       => 'foouser',
        uidNumber => 1234,
        ldap      => $ldap,
        group     => $group,
        groups    => [$bar_group],
        gecos     => 'Foo User',
    ),
    "new user"
);

ok( $user->create, "create user" );

ok( $user->password, "random password was set" );

ok( my $user2 = MyLDAPUser->new(
        uid  => 'foouser',
        ldap => $ldap,
    ),
    "new user2"
);

ok( $user2->read, "can read user info" );

is( $user2->homeDirectory, '/home/foouser',
    "homeDirectory set automatically" );

is( $user2->loginShell, $user2->default_shell, "default shell is set" );

ok( $user2->loginShell('/dev/null'), "change user2 shell" );

ok( $user2->update, "save user2 changes" );

ok( $user->read, "re-read user from server" );

is( $user->loginShell, $user2->loginShell,
    "users have same loginShell -- write successful" );

# change primary group. this should exercise several features.
ok( my $foo_group2 = MyLDAPGroup->new(
        ldap      => $ldap,
        gidNumber => '5678',
        cn        => 'foogroup2',
    ),
    "new foogroup2"
);

ok( $foo_group2->create, "create $foo_group2" );

ok( $user->group($foo_group2), "set $user primary group to $foo_group2" );

ok( $user->add_to_group($group), "make $group a secondary group" );

ok( $user->update, "save group changes" );

cmp_ok( $foo_group2->gid, '==', $user->gid, "prim group changed" );

ok( $foo_group2->read, "re-read $foo_group2 from server" );

#diag( $foo_group2->dump );

cmp_ok( $foo_group2->users->[0], 'eq', $user, "$user moved to $foo_group2" );

cmp_ok( $group->read->fetch_secondary_users->[0],
    'eq', $user, "$user secondary group now $group" );

# undo our group change

ok( $user->group($group), "set $user primary group back to $group" );

ok( $user->remove_from_group($group),
    "remove $group as secondary group for $user" );

ok( $user->remove_from_group($bar_group),
    "remove $bar_group as secondary group"
);

ok( $user->update, "save changes to group undo" );

cmp_ok( $group->gid, '==', $user->gid, "prim group changed" );

ok( !@{ $user->groups }, "no secondary groups" );
ok( !@{ $group->fetch_secondary_users }, "no secondary users" );

