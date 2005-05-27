# t/01_test.t - check module loading, etc

require 5.006;
use Test::More tests => 4;

BEGIN { use_ok( 'LWP::UserAgent::iTMS_Client' ); }

my $ua = 
  new LWP::UserAgent::iTMS_Client(user_id => "name", password => 'pw');
isa_ok ($ua, 'LWP::UserAgent::iTMS_Client');

my $results = $ua->search(artist => 'Vangelis', song => 'long ago');

ok( index($results->[0]->{songName}, 'ear') > 0);
ok( index($results->[0]->{playlistArtistName}, 'angel') > 0);

