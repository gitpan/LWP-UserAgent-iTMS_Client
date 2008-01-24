# t/01_test.t - check for newer indexing (songId versus itemId) and XML issues

require 5.006;
use Test::More tests => 3;

BEGIN { use_ok( 'LWP::UserAgent::iTMS_Client' ); }

use LWP::UserAgent::iTMS_Client;

my $ua =
  new LWP::UserAgent::iTMS_Client(user_id => "name", password => 'pw',
    download_dir => '.' );

my $results = $ua->search( all => 'Shania Twain' );
my @songs = grep { $_->{itemId} } @$results;
ok( scalar @songs > 10, "All check with two words ok" );

$results = $ua->search( artist => 'Shania Twain' );
@songs = grep { $_->{itemId} } @$results;
ok( scalar @songs > 10, "Artist check with two words ok" );


