# t/02_test.t - check various searches, etc

require 5.006;
use Test::More tests => 8;

BEGIN { use_ok( 'LWP::UserAgent::iTMS_Client' ); }

my $ua = 
  new LWP::UserAgent::iTMS_Client(user_id => "name", password => 'pw', 
    download_dir => '.' );
isa_ok ($ua, 'LWP::UserAgent::iTMS_Client');


#  media types from iTunes 7+

# video
$results = $ua->search(media => 'video', song => 'eagle feather', artist => 'Douglas' );
if($results) {
    my $num_results = scalar @{$results};
    ok( $num_results > 0, "video searching" );
}
else { print STDERR "No music video results.\n" }

# audio book
$results = $ua->search(media => 'book', author => 'Elliott' );
if($results) {
    my $num_results = scalar @{$results};
    ok( $num_results > 0, "audiobook searching" );
}
else { print STDERR "No audiobook results.\n" }

# podcast
$results = $ua->search(media => 'podcast', author => 'Elliott' );
if($results) {
    my $num_results = scalar @{$results};
    ok( $num_results > 0, "podcast searching" );
}
else { print STDERR "No podcast search results.\n" }

# music
$results = $ua->search(media => 'music', composer => 'Mozart', song => 'lacrimosa', );
if($results) {
    my $num_results = scalar @{$results};
    ok( $num_results > 0, "music searching" );
}
else { print STDERR "No music results.\n" }

# movie
$results = $ua->search(media => 'movie', movie => 'Bethlehem' );
if($results) {
    my $num_results = scalar @{$results};
    ok( $num_results > 0, "movie searching" );
}
else { print STDERR "No movie search results.\n" }

# TV
$results = $ua->search(media => 'TV', show => 'Heroes' );
if($results) {
    my $num_results = scalar @{$results};
    ok( $num_results > 0, "TV show searching" );
}
else { print STDERR "No TV show search results.\n" }

#  song previews: uncomment this to check preview downloading 
# my $results = $ua->search(composer => 'Mozart', song => 'piano duet', 
#  artist => 'britten');
#if($results) {
#    foreach my $b (@{$results}) { $ua->preview($b) }
#}

#opendir(my $dh, 'previews') 
#  or warn( "Unable to open preview download directory: $!" );
#my @p = grep /^s0/, readdir $dh;
#ok( scalar @p > 0, 'got preview(s) ok' );

