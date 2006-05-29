# t/01_test.t - check module loading, etc

require 5.006;
use Test::More tests => 4;

BEGIN { use_ok( 'LWP::UserAgent::iTMS_Client' ); }

my $ua = 
  new LWP::UserAgent::iTMS_Client(user_id => "name", password => 'pw', 
    download_dir => '.' );
isa_ok ($ua, 'LWP::UserAgent::iTMS_Client');


my $results = $ua->search(composer => 'Mozart', song => 'piano duet', 
  artist => 'britten');
if($results) {
    foreach my $b (@{$results}) { $ua->preview($b) }
}

ok( opendir(my $dh, './previews'), 'Preview download directory created ok' );
my @p = grep /^s0/, readdir $dh;
ok(scalar @p > 0, 'got preview(s) ok' );


