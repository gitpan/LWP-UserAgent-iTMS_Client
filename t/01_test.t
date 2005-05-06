# t/01_test.t - check module loading, etc

require 5.006;
use Test::More tests => 2;

BEGIN { use_ok( 'LWP::UserAgent::iTMS_Client' ); }

my $object = 
  new LWP::UserAgent::iTMS_Client(user_id => "name", password => 'pw');
isa_ok ($object, 'LWP::UserAgent::iTMS_Client');

