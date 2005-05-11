package LWP::UserAgent::iTMS_Client;

require 5.006;
use base qw 'LWP::UserAgent';
our $VERSION = '0.03';

use strict;
use warnings;
use Carp;
use Time::HiRes;
use XML::Twig;
use URI::Escape;
use Digest::MD5 qw 'md5_hex';
use Compress::Zlib;
use Crypt::CBC;
use Crypt::Rijndael;
use Crypt::AppleTwoFish;
use MIME::Base64 qw 'encode_base64 decode_base64';

# account type determines ID and password (apple vs AOL)
my %account_type_code = ( apple => 0, aol => 1 );

# country code is number of the store we buy from
my %country_code = (
#    Australia       => ???  FIXME
    Austria         => '143445-2',
    Belgium         => '143446-2',
    Canada          => '143455-6',
    Finland         => '143447',
    France          => '143442',
    Germany         => '143443',
    'Great Britain' => '143444',
    Greece          => '143448',
    Ireland         => '143449',
    Italy           => '143450',
    Luxembourg      => '143451-2',
    Netherlands     => '143452',
    Portugal        => '143453',
    Spain           => '143454',
    'United States' => '143441',
);

# for searches
my %search_topics = (   album => 'albumTerm', artist => 'artistTerm', 
                        composer => 'composerTerm', song => 'songTerm', 
                        genre => 'genreIndex', all => 'term' );
                    
my $all_search_url = 'http://phobos.apple.com/WebObjects/MZSearch.woa/wa/com.apple.jingle.search.DirectAction/search?';
my $advanced_search_url = 'http://phobos.apple.com/WebObjects/MZSearch.woa/wa/advancedSearchResults?';

my %iTMS_genres =   ( "All Genres" => 1, Alternative => 1, Audiobooks => 1,
  Blues => 1, "Children&#39;s Music" => 1, Classical => 1, Comedy => 1, 
  Country => 1, Dance => 1, Disney => 1, Electronic => 1, Folk => 1, 
  "French Pop" => 1, "German Pop" => 1, "German Pop" => 1, "Hip-Hop/Rap" => 1, 
  Holiday => 1, Inspirational => 1, Jazz => 1, Latin => 1," New Age" => 1, 
  Opera => 1, Pop => 1, 'R&amp;B/Soul' => 1, Reggae => 1, Rock => 1, 
  Soundtrack => 1, 'Spoken Word' => 1, Vocal => 1, World => 1, 
);

#  for buying
my $buy_url = 'https://phobos.apple.com/WebObjects/MZFinance.woa/wa/buyProduct?';

# error handling--croak by default
my $_error = sub { croak shift };

#************** methods in common with LWP::UserAgent ***********************#

sub new {
    my($class, %args) = @_;
    my %protocol_args;
    foreach my $k ( qw( account_type user_id ds_id gu_id password error_handler 
      deauth_wait_secs country home_dir maybe_dot path_sep download_dir ) ) 
      { $protocol_args{$k} = delete $args{$k} if $args{$k} }
    my $self = $class->SUPER::new(%args);
    $self->{protocol} = \%protocol_args;
    $self->{protocol}->{home_dir} ||= $ENV{APPDATA} || $ENV{HOME} || '~';
    $self->{protocol}->{maybe_dot} ||= ($^O =~ /Win/) ? '' : '.';
    $self->{protocol}->{path_sep} ||= '/';
    $self->{protocol}->{account_type_code} = 
      $account_type_code{ lc $self->{protocol}->{account_type} } || 0;
    $self->{protocol}->{deauth_wait_secs} ||= 90 + int rand(120);
    $self->{protocol}->{login_id} = 
      $self->{protocol}->{user_id} || '?? unknown ??';
    $self->{protocol}->{gu_id} ||= $self->gu_id;
    $self->{protocol}->{ds_id} ||= -1;
    $self->{protocol}->{download_dir} ||= $self->{protocol}->{home_dir} .
      "/My Documents/My Music/iTunes/iTunes Music";
    $self->{protocol}->{error_handler} ||= $_error;
    return $self;
}

sub request {
    my($self, $url, $params) = @_;
    # create request and send it via the base class method.
    my $hdr = $self->make_request_header($url);
    my $request = new HTTP::Request('GET' => $url . $params, $hdr);
    my $response = $self->SUPER::request($request);
    my $content;
    if ($response->is_success) {
        # process and decrypt or decompress the response.
        $self->{protocol}->{content} = $response->content;
        my $encoding = $response->content_encoding;
        return $response unless $encoding;
        if($encoding =~ /x-aes-cbc/) {
            my $key;
            my $h_twofish = $response->header('x-apple-twofish-key');
            my $h_protocol = $response->header('x-apple-protocol-key') || 0;
            my $h_iviv = $response->header('x-apple-crypto-iv');
            if( $h_twofish ) {
                my $tf = new Crypt::AppleTwoFish(hexToUchar($h_twofish));
                $key = $tf->decrypted_for_iTMS;
            }
            elsif($h_protocol == 2) { 
                $key = decode_base64("ip2tOZ+wFMExvmEYINeIlQ==");
            }
            elsif($h_protocol == 3) { 
                $key = decode_base64("mNHiLKoNir1l0UOtJ1pe5w==");
            }
            else { 
                $self->err("Bad encoding protocol in response from $url$params");
            }
            if ( $h_iviv ) {
                my $alg = new Crypt::Rijndael($key, Crypt::Rijndael::MODE_CBC);
                $alg->set_iv(hexToUchar($h_iviv));
                $response->content($alg->decrypt($response->content));
            }
            else { 
                $self->err("No aes crypto-iv given in response from $url$params");
            }
        }
        if($encoding =~ /gzip/) { 
            $response->content(Compress::Zlib::memGunzip($response->content));
        }
    }
    else { $self->err($response->status_line . "\n") }
    return $response;
}

#************ public methods unique to LWP::UserAgent::iTMS_Client ***********#

sub search {
    my($self, %search_terms) = @_;
    my $search_url = $advanced_search_url;
    my $params = '';
    my $loops = 0;
    my $had_song = 0;
    while( my($type, $term) = each %search_terms ) {
        if($type eq 'all') {
            $search_url = $all_search_url;
            $params = "term=$term";
            last;
        }
        $params .=  '&' if $loops;
        $had_song = 1 if $type eq 'song';
        $params .= $search_topics{$type} . '=' . uri_escape($term);
        $loops++;
    }
    $params .= '&songTerm=&sp;' unless $had_song; # kludge for iTMS server
    my $results = $self->request($search_url, $params);
    return $self->parse_dict($results->content, 'array/dict');
}

sub retrieve_keys_from_iTMS {
    my ($self) = @_;
    my $gu_id;
    my $save_id = 1;
    if($self->{protocol}->{gu_id}) { 
        $save_id = 0;
        $gu_id = $self->{protocol}->{gu_id};
    }
    else { $gu_id = $self->gu_id || $self->make_gu_id; }
    my $response_hashref = $self->login;
    my $auth_info = $response_hashref->{jingleDocType};
    $self->err("Machine authorization failed!") if $auth_info !~ /Success/i;
    $self->save_gu_id($gu_id) if $save_id;   
    $self->authorize;
    $self->save_keys;
}

sub retrieve_keys_with_temp_id {
    my ($self, $callback) = @_;
    $self->gu_id(0);
    my $gu_id = $self->make_gu_id;
    my $response_hashref = $self->login;
    my $auth_info = $response_hashref->{jingleDocType};
    $self->err("Machine authorization failed!") if $auth_info !~ /Success/i;
    $self->authorize;
    $self->save_keys;
    print "Please wait for deauthorization of temporary machine...";
    progress($self->{protocol}->{deauth_wait_secs}, $callback);
    $self->deauthorize_gu_id($self->{protocol}->{gu_id});
}

sub deauthorize_gu_id {
    my($self, $gu_id) = @_;
    my $user_id = $self->{protocol}->{user_id};
    my $password = $self->{protocol}->{password};
    my $account_type = $self->{protocol}->{account_type_code};
    $self->{protocol}->{gu_id} = $gu_id if $gu_id;
    $self->login($user_id, $password, $account_type);
    $self->deauthorize;
}

sub purchase {
    my($self, $song_id) = @_;
    return;   # FIXME
#    my $purchase_url = $buy_url . buyparams . '&creditBalance=' . 
#      $self->{protocol}->creditBalance . '&creditDisplay=' . 
#      urllib.quote(self.dspbalance) . '&freeSongBalance=' . 
#      $self->{protocol}->{fsbalance} .
#      '&guid=' . $self->gu_id . 
#      '&rebuy=false&buyWithoutAuthorization=true&wasWarnedAboutFirstTimeBuy=true';
      
}

#******************  internal class methods ****************************#

sub make_request_header {
    my($self, $url) = @_;
    my $agent_name = "iTunes/4.7.1 (Macintosh; U; PPC Mac OS X 10.3.8)";
    my $hdr = new HTTP::Headers(
        'User-agent' => $agent_name,
        'Accept-Language' => "en-us, en;q=0.50",
        'X-Apple-Tz' => $self->msec_since_epoch,
        'X-Apple-Validation' => $self->compute_validator($url, $agent_name),
        'Accept-Encoding' => "gzip, x-aes-cbc",
        'X-Apple-Store-Front' => $self->store_front,        
    );
    $hdr->header('X-Token' => $self->{protocol}->{password_token}) 
      if $self->{protocol}->{password_token};
    $hdr->header('X-Dsid' => $self->{protocol}->{ds_id}) 
      if $self->{protocol}->{ds_id} > 0;
    return $hdr;
}

sub login_id { return shift->{protocol}->{login_id} }

sub ds_id { return shift->{protocol}->{ds_id} }

sub gu_id {
    my($self) = @_;
    return $self->{protocol}->{gu_id} if $self->{protocol}->{gu_id};
    my $gu_id_file = $self->drms_dir . 'GUID';
    if(-e $gu_id_file) {
        open(my $guidfh, $gu_id_file) 
          or $self->err("Cannot read $gu_id_file: $!");
        read($guidfh, my $guid, -s $guidfh);
        return $self->{protocol}->{gu_id} = $guid;
    }
    return;
}

sub make_gu_id { 
    my($self) = @_;
    my($new_gu_id, @rands);
    for my $n (0 .. 6) { 
        push @rands, sprintf("%04X%04X", int rand 0xffff, int rand 0xffff);
    }
    $new_gu_id = join '.', @rands;
    $self->gu_id($new_gu_id) unless $self->gu_id;
    return $new_gu_id;
}

sub store_front { 
    my($self, $country) = @_;
    $self->{protocol}->{country_code} = $country_code{$country} if $country;
    return $self->{protocol}->{country_code} || $country_code{"United States"};
}

sub drms_dir {
    my($self) = @_;
    return sprintf( "%s%s%sdrms%s", $self->{protocol}->{home_dir}, 
      $self->{protocol}->{path_sep}, $self->{protocol}->{maybe_dot}, 
      $self->{protocol}->{path_sep} );
}

sub save_gu_id {
    # put guID for the auth in a safe place so can de-auth later
    my($self, $guid) = @_;
    return unless $guid and index($guid, '-') < 0;
    open(my $outfh, '>>', $self->drms_dir . "GUID") 
      or $self->err("Cannot save GUID, WRITE DOWN (base64) $guid:  $!");
    binmode $outfh;
    print $outfh $guid;
    close $outfh;
}

sub save_keys {
    # put keys in the user's home dir, FairKeys compatibility attempted
    my($self) = @_;
    my %user_keys = %{$self->{protocol}->{user_keys}};
    return unless %user_keys;
    my $num_new_keys = 0;
    my $basename = sprintf("%s/%08X", $self->drms_dir, $self->ds_id);
    foreach my $k (sort { $a <=> $b } keys %user_keys) {
        my $v = $user_keys{$k};
        my $pathname = sprintf("%s.%03d", $basename, $k); 
        $num_new_keys++ unless -e $pathname;
        open(my $kfh, '>', $pathname) 
          or $self->err("Cannot open $pathname for writing: $!");
        binmode $kfh;
        print $kfh $v;
        close $kfh;
    }
    $self->{protocol}->{new_key_count} = $num_new_keys;
}

sub get_saved_keys {
    my($self, $ds_id) = @_;
    $ds_id ||= $self->ds_id;
    my $hex_ds_id = sprintf("%08X", $ds_id);
    my $key_hashref = $self->{protocol}->{user_keys};
    return $key_hashref if $key_hashref and scalar %{$key_hashref};
    my $drms_dir = $self->drms_dir;
    opendir(my $dh, $drms_dir) or $self->err("Cannot open DRMS directory: $!");
    my @keyfile = readdir $dh;
    close $dh;
    @keyfile = grep { /(\w{8})\.\d{3}/ and ($1 eq $hex_ds_id) } @keyfile;
    my %keys;
    foreach my $fname (@keyfile) {
        next unless $fname =~ /\.(\d{3})$/;
        my $ky = $1;
        open(my $fh, $drms_dir . $fname) or carp "Cannot read $fname: $!";
        binmode $fh;
        read($fh, my $keyval, -s $fh);
        close $fh;
        $self->{protocol}->{user_keys}->{$ky} = $keyval if $keyval;
    }
    return $self->{protocol}->{user_keys};
}

sub get_key_count {
    my $n = shift->{protocol}->{user_keys};
    return length %{$n} if $n;
    return 0;
}

sub get_new_key_count { return shift->{protocol}->{new_key_count} }

sub compute_validator {
    my($self, $url, $user_agent) = @_;
    my $random = sprintf( "%04X%04X", rand(0x10000), rand(0x10000) );
    my $static = decode_base64("ROkjAaKid4EUF5kGtTNn3Q==");
    my $url_end = ($url =~ m|.*/.*/.*(/.+)$|) ? $1: '?';
    my $digest = md5_hex( $url_end, $user_agent, $static, $random );
    return $random . '-' . uc $digest;
}

sub parse_dict {
    my($self, $content, $path) = @_;
    my @entries;
    my $entry_index = -1;
    my $parser = sub {
        my $elt = $_;
        $entry_index++;
        while( $elt = $elt->next_elt('key') ) {
            my $key = $elt->text;
            my $next = $elt->next_elt;
            last if $next->name =~ /dict/;
            my $value = ($next) ? $next->next_elt_text : 1;
            $entries[$entry_index]->{$key} = $value;
        }
    };
    my $twig = new XML::Twig( TwigHandlers => { $path => $parser } );
    $twig->parse($content);
    # return reference to an array of hashrefs.
    # each hashref is a found item in a dict
    return \@entries;
}

sub parse_xml_response {
    my($self, $xml_response_text) = @_;
    my %url_bag_read;    
    my $parser = sub {
        my($twig, $elm) = @_;
        my($key, $string);
        while( $elm = $elm->next_elt('key') ) {
            next if $elm->text =~ /urlBag/i;
            $string = $elm->next_elt('string');
            next unless $string;
            $url_bag_read{$elm->text} = $string->text;
            $elm = $string;
        } 
    };
    my $twig = new XML::Twig( Twig_Handlers => { 'plist/dict' => $parser } );
    $twig->parse($xml_response_text);
    return \%url_bag_read;
}

sub login {
    my($self) = @_;
    $self->err("Need user_id and password in call to login for iTMS_Client") 
      unless $self->{protocol}->{user_id} and $self->{protocol}->{password};
    my $user_id = $self->{protocol}->{user_id};
    my $password = $self->{protocol}->{password};
    my $account_type = $self->{protocol}->{account_type_code};
    my $gu_id = $self->gu_id || $self->make_gu_id;
    $self->err("No guID for login") unless $gu_id;
    my $resp = $self->request("http://phobos.apple.com/storeBag.xml", '')
      or $self->err("Cannot reach iTMS key server phobos.apple.com via network");   
    $resp = $self->request("http://phobos.apple.com/secureBag.xml", '')
      or $self->err("Cannot retrieve secure bag from iTMS over network");
    $self->{protocol}->{url_bag} = $self->parse_xml_response($resp->content);
    my $authAccount = $self->{protocol}->{url_bag}->{authenticateAccount}
      or $self->err("URL for 'authenticateAccount' not found in iTMS bag.");
    $self->{protocol}->{login_id} = $user_id;
    my $cgi_params = '?appleId=' . uri_escape($user_id) . '&password=' .
      uri_escape($password) . '&accountKind=' . $account_type . 
      '&attempt=1&guid=' . uri_escape($self->gu_id || $self->make_gu_id);
    $resp = $self->request($authAccount, $cgi_params)
      or $self->err("Cannot authenticate user $user_id");
    my $auth_response = $self->parse_xml_response($resp->content);
    my $jingleDocType = $auth_response->{jingleDocType};
    my $customer_message = $auth_response->{customerMessage};
    if("authenticationsuccess" ne lc($jingleDocType)) 
      { $self->err("Login failure! Message: $customer_message") }
    $self->{protocol}->{password_token} = $auth_response->{passwordToken};
    $self->{protocol}->{ds_id} = $auth_response->{dsPersonId};
    $self->err("Bad dsID from login: $self->{protocol}->{ds_id}") 
      if $self->{protocol}->{ds_id} < 0;
    return $auth_response;
}

sub authorize {
    my($self) = @_;
    my $keys = $self->get_saved_keys;
    return $keys if $keys and scalar keys %{$keys} > 0;
    my $authorizeMachine = $self->{protocol}->{url_bag}->{authorizeMachine}
      or $self->err("No URL for authorizeMachine found in bag.");
    my $cgi_params = "?guid=" . $self->{protocol}->{gu_id};    
    my $resp = $self->request($authorizeMachine, $cgi_params)
      or $self->err("Failed to properly access authorizing server over network");
    my $dict = $self->parse_dict($resp->content, 'plist/dict')->[0];
    my $jingleDocType = $dict->{jingleDocType};
    $self->err("Authorization failure for guID " . $self->{protocol}->{gu_id})
      unless $jingleDocType and $jingleDocType =~ /success$/i;
    my $twofish = ($dict->{encryptionKeysTwofish}) ? 1 : 0;
    foreach my $k ( sort grep { $_ =~ /^\d+$/ } keys %{$dict} ) {
        my $hkey = $dict->{$k};
        my $bkey = hexToUchar($hkey);
        if($twofish) {
            my $tf = new Crypt::AppleTwoFish($bkey);
            $bkey = $tf->decrypted_for_DRMS;
        }
        $self->{protocol}->{user_keys}->{$k} = $bkey;
    }
    # user_keys references a hash, base index 1, of binary keys
    # with hash keys 1 .. number of keys
    return $self->{protocol}->{user_keys};
}

sub deauthorize {
    my($self) = @_;
    $self->login;
    my $deauth_url = $self->{protocol}->{url_bag}->{deauthorizeMachine} 
      or $self->err("URL for 'deauthorizeMachine' not found in url bag.");
    my $cgi_params = "?guid=" . uri_escape($self->{protocol}->{gu_id});
    my $resp = $self->request($deauth_url, $cgi_params) 
      or $self->err("Could not access $deauth_url over network");
    my $auth_response = $self->parse_xml_response($resp->content);
    my $jingleDocType = $auth_response->{jingleDocType};
    my $customerMessage = $auth_response->{customerMessage};
    unless( lc($jingleDocType) eq 'success' ) 
      { $self->err("Error: Failed to deauthorize user $self->{gu_id}") }
}

sub download_songs {
    my($self) = @_;
    # download all pending downloadable music.
    
}

sub err { 
    my($self, $msg) = @_; 
    $self->{protocol}->{error_handler}->($msg);
}

#************* non-method helper functions ****************#

sub msec_since_epoch { 
    my($sec, $microsec) = Time::HiRes::gettimeofday();
    return $sec * 1000 + int($microsec / 1000);
}

sub hexToUchar {
    my($hex_string) = @_;
    return unless $hex_string and length $hex_string;
    if($hex_string =~ /^0x/i) {
        $hex_string = substr $hex_string, 2;
        return unless $hex_string and length $hex_string;
    }
    return pack 'C*', map { hex } $hex_string =~ m/../g;
}

sub progress {
    my($duration, $callback) = @_;
    my $increment = 5;
    local $| = 1;
    my $bar = sub { 
        my $state = shift;
        my $char = '=';
        if   ($state =~ /begin/i) { print  "\n", 'Progress: |   ' }
        elsif($state =~ /end/i)   { print '| :Done!', "\n" }
        else { printf( "\x08\x08\x08%s%02d%%", $char, $state ) }
    };
    $callback ||= $bar;
    my $iters = $duration / $increment;
    $callback->('begin');
    for(my $i = 0; $i < $iters; $i++) { 
        sleep $increment;
        my $percent = int(100 * $i / $iters );
        $callback->($percent);
    }
    $callback->('end');
}

=head1 NAME

LWP::UserAgent::iTMS_Client - libwww-perl client for Apple iTunes music store

=head1 SYNOPSIS

    use LWP::UserAgent::iTMS_Client;
    
    # search the Store   
    my $ua = LWP::UserAgent::iTMS_Client->new(
      user_id => 'me@you', password => 'pwd');
    
    my $listings = $ua->search( song => 'apples' );
    foreach my $album (@{$listings}) { print $album->{songName} }

    $listings = $ua->search(artist => 'Vangelis', song => 'long', 
      genre => 'Electronic');
    foreach my $a (@{$results2}) { 
      foreach (sort keys %$a) { print "$_ => ", $a->{$_}, "\n" } 
    }

    # get my authorization keys
    my $ua = new LWP::UserAgent::iTMS_Client(
        account_type => 'apple',
        user_id => 'name@email.org',
        password => 'password',
    );
    $ua->retrieve_keys_from_iTMS;

=head1 DESCRIPTION

This perl module implements a user agent which can interact with the
Apple iTunes Music Store (iTMS). In the long run, we envision a Perl 
extension that will allow automated browsing and purchasing of music. For 
example, the module might be used to automatically get samples of new 
albums by a particular artist, or buy everything on a Top Ten list weekly.

LWP::UserAgent::iTMS_Client is a sub-class of LWP::UserAgent and implements 
the methods of UserAgent, but does so using Apple's officially undocumented 
protocols. Because these protocols change with revisions to iTunes, the 
modules may occasionally lag Apple's changes until this module, too, is 
updated.

The initial versions of this user agent will concentrate on browsing the 
listings and obtaining the user's keys.

=head1 METHODS

=item B<new>

    # set up new instance for anon search
    my $ua = 
      LWP::UserAgent::iTMS_Client->new(user_id => 'me@you', password => 'pwd');

    # set up for login
    my $ua = new LWP::UserAgent::iTMS_Client(
        account_type => 'apple',
        user_id => 'name@email.org',
        password => 'password',
        gu_id => 'CF1121F1.13F11411.11B1F151.1611F111.1DF11711.11811F19.1011F1A1',
    );

Create a new LWP::UserAgent::iTMS_Client object.
Options are:

    account_type
        Either 'apple' or 'aol', this determines where the authentication 
        password is to be checked--on an AOL user database or with Apple's 
        accounts.
        
    user_id (required)
        User name, usually an email address.
        
    ds_id 
        A user identifier used by iTMS for authentication. May be useful if
        accessing local key files.
        
    gu_id 
        A user's machine identifier used by iTMS for authorization.
        
    password (required)
        The user's own (user typed, in iTunes) password.
        
    deauth_wait_secs
      Reserved, not currently implemented. 
      This is to be a mandatory wait before deauthorizing a machine.
      
    country 
        The country where the user's account is based. Determines purchase 
        currency, etc.
    
    home_dir 
        The directory where the drms keys subdirectory is located. Generally it
        may be best to allow the module to locate this by default.
        
    maybe_dot 
        Determines if the drms subdirectory is called '.drms' or 'drms', again,
        best left to the default.
    
    path_sep
        Generally '/'. Path separator for the local OS.
    
=item B<request>

Sends a request to the iTunes Music Store. Handles encryption and compression, then 
returns an HTTP::Response object, as an overloaded method of the base LWP::UserAgent. 
Generally not called directly unless you know what you are doing. 

=item B<search>

use LWP::UserAgent::iTMS_Client;

my $ua = LWP::UserAgent::iTMS_Client->new;

my $results1 = $ua->search(song => 'Day', composer => 'Lennon');
print "\nResults for song => regret, artist => New Order:\n";
foreach my $a (@{$results1}) { 
    foreach (sort keys %$a) { print "$_ => ", $a->{$_}, "\n" } 
}

my $results2 = $ua->search(artist => 'Vangelis', song => 'long ago');
print "\nResults for song => apples:\n";
foreach my $a (@{$results2}) { 
   foreach (sort keys %$a) { print "$_ => ", $a->{$_}, "\n" } 
}

The following types of searches should be supported: album, artist, composer, 
song, genre, all. If used, 'all' should override other specifications.

=item B<retrieve_keys_from_iTMS>

Get the keys from the Store. Attempts to be compatible with key locations used 
by default by the Videolan project's media player (FairKeys compatibility). 
This should generally be used with a gu_id known by the user, preferentially 
one given as a gu_id => 11111111.11111111.11111111.11111111.11111111.11111111
(6 8-digit hex numbers separated by periods) argument to new.

=item B<deauthorize_gu_id>

$ua->deauthorize_gu_id($id);

Deauthorize the machine used to get the keys.


=item B<retrieve_keys_with_temp_id>

ua->retrieve_keys_with_temp_id(\&callback);
  
Create a temporary machine ID (you need to have one of your 5 machine 
useages for iTunes available), get the keys with this virtual machine's 
authorization, then deauthorize. Note that since this may result in an 
additional key being created, you should limit the number of times you 
do this. If you generally only purchase music on one or two machines 
that do not change ID's, and only play copied music on your other 
(iPod?) machines, once downloading your keys may be enough. The program
will display a progress bar betwwen key retrieval and deauthorization. The
optional argument is to allow custom display of the wait period, which by
default prints to stdout. The optional callback routine must accept a single 
argument which may have the values 'begin', an integer between 0 and 100, 
and 'end'.

=item B<purchase>

  $ua->purchase($song_id);
  
  Not yet working, will be soon we hope

=head1 BUGS

The searches do not work if both 'composer' and 'artist' are specified.

Overuse of the B<purchase> routine might allow you to spend more on music 
than you intended. This might be a bug, from the perspective of your budget. 
Enjoy :).

=head1 SEE ALSO

=item L<LWP::UserAgent>, L<Audio::M4P::QuickTime>, L<Audio::M4P::Decrypt>, L<Mac::iTunes>, L<Net::iTMS>

=head1 AUTHOR 

William Herrera L<wherrera@skylightview.com>. 

=head1 SUPPORT 

Questions, feature requests and bug reports should go to 
<wherrera@skylightview.com>.

=head1 COPYRIGHT 

=over 4

Copyright (c) 2003-2005 William Herrera. All rights reserved.  
This program is free software; you can redistribute it and/or modify 
it under the same terms as Perl itself.

=back

=cut

1;
