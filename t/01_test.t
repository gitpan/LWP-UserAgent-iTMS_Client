# t/01_test.t - check module loading, etc

require 5.006;
use Test::More tests => 6;

BEGIN { use_ok( 'LWP::UserAgent::iTMS_Client' ); }

my $ua = 
  new LWP::UserAgent::iTMS_Client(user_id => "name", password => 'pw', 
    download_dir => '.' );
isa_ok ($ua, 'LWP::UserAgent::iTMS_Client');

my $results = $ua->search(artist => 'Vangelis', song => 'long ago');

ok( index($results->[0]->{songName}, 'ear') > 0);
ok( index($results->[0]->{playlistArtistName}, 'angel') > 0);

my $results2 = $ua->search(artist => 'u2', song => 'Blindness');
if($results2) {
    foreach my $b (@{$results2}) { $ua->preview($b) }
}

ok( opendir(my $dh, './previews') );
my @p = grep /^s0/, readdir $dh;
ok(scalar @p > 0);


