use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::LDAP::Class',
    AUTHOR              => 'Peter Karman <karman@cpan.org>',
    VERSION_FROM        => 'lib/Net/LDAP/Class.pm',
    ABSTRACT_FROM       => 'lib/Net/LDAP/Class.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'Data::Dump' => 0,
        'Digest::SHA1' => 0,
        'MIME::Base64' => 0,
        'Rose::Object' => 0,
        'Net::LDAP'    => 0,
        'Net::LDAP::Server::Test' => 0.07,
        'Net::LDAP::Batch' => 0,
        'Clone' => 0,

    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Net-LDAP-Class-*' },
);
