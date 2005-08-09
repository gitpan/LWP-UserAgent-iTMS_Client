package LWP::UserAgent::iTMS_Client;

require 5.006;
use base 'LWP::UserAgent';
our $VERSION = '0.12';

use strict;
use warnings;
use Carp;
use File::Path;
use Time::HiRes;
use XML::Twig;
use URI::Escape;
use Digest::MD5 'md5_hex';
use Compress::Zlib;
use Crypt::CBC;
use Crypt::Rijndael;
use Crypt::AppleTwoFish;
use MIME::Base64 qw( encode_base64 decode_base64 );

# account type determines ID and password (apple vs AOL)
my %account_type_code = ( apple => 0, aol => 1 );

# country code is number of the store we buy from
my %country_code = (
    Australia       => 143460,
    Austria         => 143445,
    Belgium         => 143446,
    Canada          => 143455,
    Denmark         => 143458,
    Finland         => 143447,
    France          => 143442,
    Germany         => 143443,
    Greece          => 143448,
    Ireland         => 143449,
    Italy           => 143450,
    Japan           => 143462,
    Luxembourg      => 143451,
    Netherlands     => 143452,
    Norway          => 143457,
    Portugal        => 143453,
    Spain           => 143454,
    Sweden          => 143456,
    Switzerland     => 143459,
    UK              => 143444,
    USA             => 143441,
);

# for searches
my %search_topics = (   album => 'albumTerm', artist => 'artistTerm', 
                        composer => 'composerTerm', song => 'songTerm', 
                        genre => 'genreIndex', all => 'term' );
                    
my $all_search_URL = 'http://phobos.apple.com/WebObjects/MZSearch.woa/wa/com.apple.jingle.search.DirectAction/search?';
my $advanced_search_URL = 'http://phobos.apple.com/WebObjects/MZSearch.woa/wa/advancedSearchResults?';

my %iTMS_genres =   ( "All Genres" => 1, Alternative => 1, Audiobooks => 1,
  Blues => 1, "Children&#39;s Music" => 1, Classical => 1, Comedy => 1, 
  Country => 1, Dance => 1, Disney => 1, Electronic => 1, Folk => 1, 
  "French Pop" => 1, "German Pop" => 1, "German Pop" => 1, "Hip-Hop/Rap" => 1, 
  Holiday => 1, Inspirational => 1, Jazz => 1, Latin => 1," New Age" => 1, 
  Opera => 1, Pop => 1, 'R&amp;B/Soul' => 1, Reggae => 1, Rock => 1, 
  Soundtrack => 1, 'Spoken Word' => 1, Vocal => 1, World => 1, 
);

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
    $self->{protocol}->{download_dir} ||= $ENV{USERPROFILE} .
      "/My Documents/My Music/iTunes/iTunes Music";
    $self->{protocol}->{error_handler} ||= $_error;
    return $self;
}

sub request {
    my($self, $url, $params, $cookie) = @_;
    # create request and send it via the base class method.
    my $hdr = $self->make_request_header($url, $cookie);
    my $request = new HTTP::Request('GET' => $url . $params, $hdr);
    my $response = $self->SUPER::request($request);
    if($response->is_success) {
        # process and decrypt or decompress the response.
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
            if( $h_iviv ) {
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
    else { $self->err($response->status_line) }
    return $response;
}

#************ public methods unique to LWP::UserAgent::iTMS_Client ***********#

# search the iTMS. Can be done without logging in first
sub search {
    my($self, %search_terms) = @_;
    # we could use the urlBag URL here, but hard coded we skip one request.
    my $search_url = $advanced_search_URL;
    my $params = '';
    my $loops = 0;
    my $had_song = 0;
    my %not_together = ( artist => 1, composer => 1 );
    my @together = ();
    while( my($type, $term) = each %search_terms ) {
        if($type eq 'all') {
            $search_url = $all_search_URL;
            $params = "term=$term";
            last;
        }
        push @together, $type if $not_together{$type};
        # kludge around what appears to be an advancedSearch iTMS CGI bug
        # when artist and composer are both specified in a search
        if ( (scalar @together) == 2 ) { 
            return $self->split_search(@together, \%search_terms); 
        }
        $params .=  '&' if $loops;
        $had_song = 1 if $type eq 'song';
        $params .= $search_topics{$type} . '=' . uri_escape($term);
        $loops++;
    }
    # kludge for encephalopathic iTMS advancedSearch CGI when no song specified
    # Music Store, you _need_ to be google spidered...are you dumb on purpose?
    $params .= '&songTerm=&sp;' 
      unless( $had_song or $search_url eq $all_search_URL ); 
    my $results = $self->request($search_url, $params);
    return $self->parse_dict($results->content, 'array/dict');
}

# log in to iTMS
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
    $self->{protocol}->{store_bag} = $resp->content;
    $resp = $self->request("http://phobos.apple.com/secureBag.xml", '')
      or $self->err("Cannot retrieve secure bag from iTMS over network");
    $self->{protocol}->{secure_bag} = $self->parse_xml_response($resp->content);
    my $authAccount = $self->{protocol}->{secure_bag}->{authenticateAccount}
      or $self->err("URL for 'authenticateAccount' not found in secure bag.");
    $self->{protocol}->{login_id} = $user_id;
    my $cgi_params = '?appleId=' . uri_escape($user_id) . '&password=' .
      uri_escape($password) . '&accountKind=' . $account_type . 
      '&attempt=1&guid=' . uri_escape($self->gu_id || $self->make_gu_id);
    $resp = $self->request($authAccount, $cgi_params)
      or $self->err("Cannot authenticate user $user_id");
    my $auth_response = $self->parse_xml_response($resp->content);
    my $customer_message = $auth_response->{customerMessage};
    my $jingleDocType = $auth_response->{jingleDocType};
    $self->err("Login failure! Message: $customer_message")
      unless $jingleDocType and $jingleDocType =~ /Success$/i;
    $self->{protocol}->{password_token} = $auth_response->{passwordToken};
    $self->{protocol}->{ds_id} = $auth_response->{dsPersonId};
    $self->{protocol}->{credit_balance} = $auth_response->{creditBalance};
    $self->{protocol}->{credit_display} = $auth_response->{creditDisplay};
    $self->{protocol}->{free_song_balance} = $auth_response->{freeSongBalance};
    $self->{protocol}->{authentication} = $auth_response; 
    return $auth_response;
}

# get user's iTMS keys--useful for Linux music players like 
# MPlayer or vlc that need user keys to play m4p's
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

# get keys with temp virtual machine--see jHymn for java version of this
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

# deauthorize virtual machine (so not to waste one of our 5 possible machines)
sub deauthorize_gu_id {
    my($self, $gu_id) = @_;
    my $user_id = $self->{protocol}->{user_id};
    my $password = $self->{protocol}->{password};
    my $account_type = $self->{protocol}->{account_type_code};
    $self->{protocol}->{gu_id} = $gu_id if $gu_id;
    $self->login($user_id, $password, $account_type);
    $self->deauthorize;
}

# buy music from iTMS--using an already signed up account 
sub purchase {
    my($self, $entry) = @_;
    # purchase a song (need the 'buyParams' returned from search)
    my $buy_url = $self->{protocol}->{secure_bag}->{buyProduct} 
      or $self->err("URL for 'buyProduct' not found in secure url bag.");
    my $buy_params = $entry->{buyParams}; 
    my $buy_request_params = '?' . $buy_params . 
      '&creditBalance=' . $self->{protocol}->{credit_balance} . 
      '&creditDisplay=' . uri_escape($self->{protocol}->{credit_display}) . 
      '&freeSongBalance=' . $self->{protocol}->{free_song_balance} . 
      '&guid=' . $self->gu_id . 
      '&rebuy=false&buyWithoutAuthorization=true&wasWarnedAboutFirstTimeBuy=true';
    my $response = $self->request($buy_url, $buy_request_params);
    if($response->is_success) {
        my $dict = $self->parse_xml_response($response->content);
        my $result_type = $dict->{jingleDocType};
        $self->err( "Failed to purchase song $entry->{songId}, 
          $entry->{songName}: " . $dict->{explanation} ) 
          unless $result_type and $result_type =~ /Success/i;
        # downloadable is a hash of hashes keyed by download params key
        my $download_param = 'downloadKey=' . $dict->{downloadKey};
        $self->{protocol}->{downloadable}->{$download_param} = $dict;
    }
    else { 
        $self->err("Failed in purchase request $buy_url$buy_request_params");
    }
    $self->download_songs;
    return $self->{protocol}->{downloadable};
}

# download purchased music not yet gotten from iTMS 
# song list of hashes is in $self->{protocol}->{downloadable}
sub download_songs {
    my($self) = @_;
    while(my($downloadKey, $info) = each %{$self->{protocol}->{downloadable}}) {
        my $key = $info->{encryptionKey};
        $key = hexToUchar($key) if length($key) == 32;
        next unless length($key) == 16;
        my $url = $info->{URL};
        my $response = $self->request($url, '', $downloadKey);
        next unless $response->is_success;
        my $iviv = decode_base64("JOb1Q/OHEFarNPJ/Zf8Adg==");
        my $alg = new Crypt::Rijndael($key, Crypt::Rijndael::MODE_CBC);
        $alg->set_iv($iviv);
        my $decoded = $alg->decrypt( substr($response->content, 0, 
          int((length $response->content) / 16) * 16 ) );
        my $moov_pos = index($decoded, 'moov');
        next unless $moov_pos > 0 and $moov_pos < 100;
        my $sep = $self->{protocol}->{path_sep};
        my $path = $self->{protocol}->{download_dir} . $sep . 
          $info->{playlistArtistName} . $sep . $info->{playlistName};
        my $fname = $info->{songName} . '.m4a';
        my $new_fh = $self->open_new_pathname($path, $fname);
        if($new_fh) { 
            binmode $new_fh; 
            print $new_fh $decoded;
            close $new_fh;
            $self->{protocol}->{completed_downloads}->{$info->{songId}} =
              $info;
        }
        else { 
            $self->err(
              "Cannot open pathname for song $info->{songName} at $path: $!");
        }
    }
}

# get a hashed list of songs we have purchased but not 
# signed off on downloading yet, keyed by downloadKey
sub pending_downloads {
    my($self) = @_;
    $self->login unless $self->{protocol}->{secure_bag};
    my $pending_song_url = $self->{protocol}->{secure_bag}->{pendingSongs} 
      or $self->err("URL for 'pendingSongs' not found in secure url bag.");
    my $response = $self->request($pending_song_url, '?guid=' . $self->gu_id);
    if($response->is_success) {
        my $dicts = $self->parse_dict($response->content, 'array/dict');
        foreach my $dict (@{$dicts}) {
            my $key = $dict->{downloadKey} or next;
            my $download_param = 'downloadKey=' . $key;
            $self->{protocol}->{downloadable}->{$download_param} = $dict;
        }
    }
    return $self->{protocol}->{downloadable};
}

# notify iTMS that song is downloaded--until then we can re-download the song
sub notify_downloads_done {
    my($self) = @_;
    my $songDownloadDone = $self->{protocol}->{secure_bag}->{songDownloadDone};
    foreach my $songId ( keys %{$self->{protocol}->{completed_downloads}} ) { 
        my $resp = $self->request($songDownloadDone, '?songId=' . $songId);
        if($resp->is_success) {
            my $response_vars = $self->parse_xml_response($resp->content);
            delete $self->{protocol}->{secure_bag}->{completed_downloads}->{songId}
            if( $response_vars->{jingleDocType} and 
                $response_vars->{jingleDocType} =~ /Success$/i );
        }
    }
    # return the list of completed downloads not yet notifieed successfully
    return $self->{protocol}->{completed_downloads};
}

# Get a song preview from preview URL returned with a search
sub preview {
    my($self, $preview_song) = @_;
    # download a song preview from {previewURL} from the song hash
    my $preview_url = $preview_song->{previewURL};
    my $preview_name = reverse ( (split /\//, reverse $preview_url)[0] );
    my $preview = $self->request($preview_url, '');
    if($preview->is_success) {
        my $sep = $self->{protocol}->{path_sep};
        my $path = $self->{protocol}->{download_dir} . $sep . 'previews';
        my $new_fh = 
          $self->open_new_pathname( $path, $preview_name ) or next;
        binmode $new_fh;
        print $new_fh $preview->content;
        close $new_fh;
    }
}

#****** internal class methods--interfaces below may change with updates *****#

sub make_request_header {
    my($self, $url, $cookie) = @_;
    my $agent_name = "iTunes/4.7.1 (Macintosh; U; PPC Mac OS X 10.3.8)";
    my $hdr = new HTTP::Headers(
        'User-agent' => $agent_name,
        'Accept-Language' => "en-us, en;q=0.50",
#        'Accept' => '*/*',
#        'Connection' => 'close',
        'X-Apple-Tz' => $self->msec_since_epoch,
        'X-Apple-Validation' => $self->compute_validator($url, $agent_name),
        'Accept-Encoding' => "gzip, x-aes-cbc",
        'X-Apple-Store-Front' => $self->store_front,        
    );
    $hdr->header('X-Token' => $self->{protocol}->{password_token}) 
      if $self->{protocol}->{password_token};
    $hdr->header('X-Dsid' => $self->{protocol}->{ds_id}) 
      if $self->{protocol}->{ds_id};
    $hdr->header('Cookie' => $cookie) if $cookie;
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
    return $self->{protocol}->{country_code} || $country_code{USA};
}

sub drms_dir {
    my($self) = @_;
    return sprintf( "%s%s%sdrms%s", $self->{protocol}->{home_dir}, 
      $self->{protocol}->{path_sep}, $self->{protocol}->{maybe_dot}, 
      $self->{protocol}->{path_sep} );
}

sub open_new_pathname {
    my($self, $path, $filename) = @_;
    $path =~ s|(\/.*):|$1|g;
    mkpath($path);
    open( my $fh, '>', $path . $self->{protocol}->{path_sep} . $filename )
      or return;
    return $fh;
}

sub save_gu_id {
    # put guID for the auth in a safe place so can de-auth later
    my($self, $guid) = @_;
    return unless $guid and index($guid, '-') < 0;
    open(my $outfh, '>>', $self->drms_dir . "GUID") 
      or $self->err("Cannot save GUID, WRITE DOWN NOW:  $guid   : $!");
    binmode $outfh;
    print $outfh $guid;
    close $outfh;
}

sub save_keys {
    # put keys in the user's home dir, FairKeys compatibility attempted
    my($self) = @_;
    my %user_keys = %{$self->{protocol}->{user_keys}};
    return unless %user_keys;
    my $basename = sprintf("%s/%08X", $self->drms_dir, $self->ds_id);
    foreach my $k (sort { $a <=> $b } keys %user_keys) {
        my $v = $user_keys{$k};
        my $pathname = sprintf("%s.%03d", $basename, $k); 
        open(my $kfh, '>', $pathname) 
          or $self->err("Cannot open $pathname for writing: $!");
        binmode $kfh;
        print $kfh $v;
        close $kfh;
    }
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

sub compute_validator {
    my($self, $url, $user_agent) = @_;
    my $random = sprintf( "%04X%04X", rand(0x10000), rand(0x10000) );
    my $static = decode_base64("ROkjAaKid4EUF5kGtTNn3Q==");
    my $url_end = ($url =~ m|.*/.*/.*(/.+)$|) ? $1: '?';
    my $digest = md5_hex( $url_end, $user_agent, $static, $random );
    return $random . '-' . uc $digest;
}

sub split_search {
    my($self, $term1, $term2, $search_terms) = @_;
    my %h1 = %{$search_terms};
    my %h2 = %{$search_terms};
    delete $h1{$term1};
    delete $h2{$term2};
    my $s1 = $self->search(%h1);
    my $s2 = $self->search(%h2);
    return song_keyed_intersection($s1, $s2);
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
            my $value = ($next) ? $next->next_elt_text : 1;
            $entries[$entry_index]->{$key} = $value;
        }
    };
    my $twig = new XML::Twig( TwigHandlers => { $path => $parser } );
    $twig->parse($content);
    # return reference to array of hashrefs, each a <dict> type of entry
    return \@entries;
}

sub parse_xml_response {
    # get the data in all XML dicts, combine them, return as hash reference.
    # use the basic parse_dict() method not this if duplicate keys in dicts
    my($self, $xml_response) = @_;
    my $dicts = $self->parse_dict($xml_response, 'dict');
    my %dict_hash;
    foreach my $d (@{$dicts}) { 
        while(my ($k, $v) = each %{$d}) { $dict_hash{$k} = $v }
    }
    return \%dict_hash;
}

sub authorize {
    my($self) = @_;
    my $keys = $self->get_saved_keys;
    return $keys if $keys and scalar keys %{$keys} > 0;
    my $authorizeMachine = $self->{protocol}->{secure_bag}->{authorizeMachine}
      or $self->err("No URL for authorizeMachine found in secure bag.");
    my $cgi_params = "?guid=" . $self->{protocol}->{gu_id};    
    my $resp = $self->request($authorizeMachine, $cgi_params)
      or $self->err("Failed to properly access authorizing server over network");
    my $dict = $self->parse_xml_response($resp->content);
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
    $self->{protocol}->{authentication} = $dict;
    # user_keys references a hash, base index 1, of binary keys
    # with hash keys 1 .. number of keys
    return $self->{protocol}->{user_keys};
}

sub deauthorize {
    my($self) = @_;
    $self->login;
    my $deauth_url = $self->{protocol}->{secure_bag}->{deauthorizeMachine} 
      or $self->err("URL for 'deauthorizeMachine' not found in url bag.");
    my $cgi_params = "?guid=" . uri_escape($self->{protocol}->{gu_id});
    my $resp = $self->request($deauth_url, $cgi_params) 
      or $self->err("Could not access $deauth_url over network");
    my $auth_response = $self->parse_xml_response($resp->content);
    my $msg = $auth_response->{customerMessage};
    $self->err("Failed to deauthorize user " . $self->{gu_id} . ": $msg")
      unless $auth_response->{jingleDocType} =~ /Success/i;
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

sub song_keyed_intersection {
    my($aref_1, $aref_2) = @_;
    return unless $aref_1 and $aref_2 and scalar @$aref_1 and scalar @$aref_2;
    my @intersection = ();
    my(%h1, $h, $k);
    foreach $h (@$aref_1) { 
        $k = $h->{songId}; 
        $h1{$k} = $h if $k;
    }
    foreach $h (@$aref_2) { 
        $k = $h->{songId} or next;
        my $song = $h1{$k} or next;
        push @intersection, $song;
    }
    return \@intersection;
}

sub progress {
    my($duration, $callback) = @_;
    my $increment = 5;
    local $| = 1;
    my $bar = sub { 
        my $state = shift;
        my $char = '=';
        if   ($state =~ /begin/i) { print  "\n", 'Progress: |   ' }
        elsif($state =~ /end/i)   { print "\x08\x08\x08", '| :Done!', "\n" }
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
    my $ua = LWP::UserAgent::iTMS_Client->new;
    
    my $listings = $ua->search( song => 'apples' );
    foreach my $song (@{$listings}) { print $song->{songName} }

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
Apple iTunes Music Store (iTMS). For example, this module could allow a 
perl program that would automatically get samples of new albums by a 
particular artist, or buy everything on a Top Ten list weekly.

LWP::UserAgent::iTMS_Client is a sub-class of LWP::UserAgent and implements 
the methods of UserAgent, but does so using Apple's officially undocumented 
protocols. Because these protocols change with revisions to iTunes, the 
modules may occasionally lag Apple's changes until this module, too, is 
updated.

=head1 METHODS

=item B<new>

    # set up new instance for anon search
    my $ua = LWP::UserAgent::iTMS_Client->new;

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
        
    error_handler
        Default error handling is to croak(). This allows alternate behavior by
        passing the name of a routine which takes a single scalar argument, 
        the error message.

    deauth_wait_secs
        This is a mandatory wait before deauthorizing a machine after
        a virtual machine is used to get user keys.
      
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
        
    download_dir
        The default location for downloaded music files.
    
=item B<request>

    $ua->request('http://phobos.apple.com/WebObjects/MZSearch.woa/wa/com.apple.jingle.search.DirectAction/search', 
      '?term=beautiful balloon');

    Sends a request to the iTunes Music Store. The first argument is the URL, 
    the second is the parameter string.Handles encryption and compression, 
    then returns an HTTP::Response object, as an overloaded method of the base 
    LWP::UserAgent. Generally not called directly unless you know what you 
    are doing. 

=item B<search>

    my $results = $ua->search(song => 'Day', composer => 'Lennon');
    print "Results for song => Day, composer => Lennon:\n";
    foreach my $a (@{$results1}) { 
        foreach (sort keys %$a) { print "$_ => ", $a->{$_}, "\n" } 
    }

    my $results2 = $ua->search(artist => 'Vangelis', song => 'long ago');
    print "\nResults for artist => Vangelis, song => long ago:\n";
    foreach my $a (@{$results2}) { 
        foreach (sort keys %$a) { print "$_ => ", $a->{$_}, "\n" } 
    }

    The following types of searches should be supported: album, artist, 
    composer, song, genre, all. If used, 'all' should override other 
    specifications.

=item B<login>

    Log in to the iTMS, using parameters given in new().

=item B<retrieve_keys_from_iTMS>

    $ua->retrieve_keys_from_iTMS;

    Get the keys from the Store. Attempts to be compatible with key locations 
    used by default by the Videolan project's media player (FairKeys 
    compatibility). This should generally be used with a gu_id known by the 
    user, preferentially one given as a 
    gu_id => 11111111.11111111.11111111.11111111.11111111.11111111
    (6 8-digit hex numbers separated by periods) argument to new.

=item B<deauthorize_gu_id>

    $ua->deauthorize_gu_id($id);

    Deauthorize the machine used to get the keys.

=item B<retrieve_keys_with_temp_id>

    $ua->retrieve_keys_with_temp_id;
    $ua->retrieve_keys_with_temp_id(\&callback);
  
    Create a temporary machine ID (you need to have one of your 5 machine 
    usages for iTunes available), get the keys with this virtual machine's 
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
  
    Purchase and download a song, by song id number or 'songId' as a search 
    result (use search to find the song and then get the songId from the 
    search result data structure, or "dict" hash reference). Should call the 
    B<download_songs> method automatically after the purchase.

=item B<download_songs>

    $ua->download_songs;

    Download any songs pending for the user, including those just purchased. In order 
    to download songs purchased but not immediately downloaded, should be called 
    after B<pending_downloads> is called.

=item B<pending_downloads>

    my $hashref = $ua->pending_downloads;
    
    Get a hashref, keyed by downloadKey, of purchased, but not yet downloaded 
    songs. This data is also stored in the object, so that B<download_songs>
    may be called after this method call to download the songs found.

=item B<notify_downloads_done>

    $qt->notify_downloads_done;
    
    Notify iTMS that downloads of purchased music during the login session 
    have been successful. After such notification, songs may not be available
    to be re-downloaded as entries with B<pending_downloads>.

=item B<preview>

    $ua->preview($song);
    
    Download a preview for a song entry, if available. $song is a reference
    to the hash of data for a song returned by the search method.

=head1 BUGS

The searches under 'artist' are currently crippled, due to a server issue. 
It seems that the artist name is seldom presently part of song metadata. There 
is a numeric artistId entry, but I don't currently have an index of artists 
for lookup.

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
