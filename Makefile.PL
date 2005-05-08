use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'LWP::UserAgent::iTMS_Client',
    AUTHOR       => 'William Hererra (whererra@skylightview.com)',
    ABSTRACT     => 'Interact with the Apple iTunes Music Store',
    VERSION_FROM => 'lib/LWP/UserAgent/iTMS_Client.pm', # finds $VERSION
    PREREQ_PM    => {   Crypt::Rijndael => 0, Digest::MD5 => 0, 
                        Crypt::AppleTwoFish => 0.02, Test::More => 0,
                        Crypt::Rijndael => 0, Carp => 0, Time::HiRes => 0,
                        XML::Twig => 0, CGI => 0, Compress::Zlib => 0,
                        Crypt::CBC => 0, MIME::Base64 => 0,
                    },
);


