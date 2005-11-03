# t/01_test.t - check module loading, etc

require 5.006;
use Test::More tests => 6;

BEGIN { use_ok( 'LWP::UserAgent::iTMS_Client' ); }

my $ua = 
  new LWP::UserAgent::iTMS_Client(user_id => "name", password => 'pw', 
    download_dir => '.' );
isa_ok ($ua, 'LWP::UserAgent::iTMS_Client');

my $results = $ua->search(artist => 'Vangelis', song => 'long ago');

#while( my($k, $v) = each %{$results->[0]} ) { print "key: $k value: $v\n" } 

ok( index($results->[0]->{songName}, 'ear') > 0, 'search okay');
ok( index($results->[0]->{playlistName}, 'Best') > 0, 
  'search of artist okay');

my $results2 = $ua->search(composer => 'Mozart', song => 'piano duet', 
  artist => 'britten');
if($results2) {
    foreach my $b (@{$results2}) { $ua->preview($b) }
}

ok( opendir(my $dh, './previews'), 'Preview download directory created ok' );
my @p = grep /^s0/, readdir $dh;
ok(scalar @p > 0, 'got preview(s) ok' );


