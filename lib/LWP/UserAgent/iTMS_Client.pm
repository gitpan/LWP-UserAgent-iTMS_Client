package LWP::UserAgent::iTMS_Client;

require 5.006;
use base qw/ LWP::UserAgent /;
our $VERSION = '0.01_01';

use strict;
use warnings;
use Carp;
use Time::HiRes;
use XML::Twig;
use CGI qw/ escapeHTML /;
use Digest::MD5 qw/ md5_hex /;
use Compress::Zlib;
use Crypt::CBC;
use Crypt::Rijndael;
use Crypt::AppleTwoFish;
use MIME::Base64 qw/ encode_base64 decode_base64 /;

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

my %TMS_genres =   ( "All Genres" => 1, Alternative => 1, Audiobooks => 1,
  Blues => 1, "Children&#39;s Music" => 1, Classical => 1, Comedy => 1, 
  Country => 1, Dance => 1, Disney => 1, Electronic => 1, Folk => 1, 
  "French Pop" => 1, "German Pop" => 1, "German Pop" => 1, "Hip-Hop/Rap" => 1, 
  Holiday => 1, Inspirational => 1, Jazz => 1, Latin => 1," New Age" => 1, 
  Opera => 1, Pop => 1, 'R&amp;B/Soul' => 1, Reggae => 1, Rock => 1, 
  Soundtrack => 1, 'Spoken Word' => 1, Vocal => 1, World => 1, 
);

#************** methods in common with LWP::UserAgent ***********************#

sub new {
    my($class, %args) = @_;
    my %protocol_args;
    foreach my $k ( qw( account_type user_id ds_id gu_id password 
      deauth_wait_secs DEBUG DEBUG_ID_FILE country home_dir password_token 
      maybe_dot path_sep ) ) 
      { $protocol_args{$k} = delete $args{$k} if $args{$k} }
    my $self = $class->SUPER::new(%args);
    $self->{protocol} = \%protocol_args;
    $self->{protocol}->{DEBUG}  ||= 0;
    $self->{protocol}->{home_dir} ||= $ENV{APPDATA} || $ENV{HOME} || '~';
    $self->{protocol}->{maybe_dot} ||= ($^O =~ /Win/) ? '' : '.';
    $self->{protocol}->{path_sep} ||= '/';
    $self->{protocol}->{account_type_code} = 
      $account_type_code{ lc $self->{protocol}->{account_type} } || 0;
    $self->{protocol}->{deauth_wait_secs} = 240 + int rand(120);
    $self->{protocol}->{login_id} = 
            $self->{protocol}->{user_id} || '?? unknown ??';
    $self->{protocol}->{max_machines} = -1;
    $self->{protocol}->{gu_id} ||= $self->gu_id;
    $self->{protocol}->{ds_id} ||= -1;
    croak "Need user_id and password in call to new for iTMS_Client"
      unless $self->{protocol}->{user_id} and $self->{protocol}->{password};
    return $self;
}

sub request {
    my($self, $url, $params) = @_;
    # create request and send it via the base class method.
    print "In request method, url is: $url and params are: $params\n\n" 
      if $self->{protocol}->{DEBUG};
    my $hdr = $self->make_request_header($url);
    my $request = new HTTP::Request('GET' => $url . $params, $hdr);
    print "Headers for request: ", $hdr->as_string, "\n"
      if $self->{protocol}->{DEBUG} and $self->{protocol}->{DEBUG} > 1;
    my $response = $self->SUPER::request($request);
    my $content;
    if ($response->is_success) {
        # process and decrypt or decompress the response.
        $self->{protocol}->{content} = $response->content;
        if($self->{protocol}->{DEBUG} and $self->{protocol}->{DEBUG} > 1) {
            print "Response headers:\n";
            my @flds = $response->header_field_names();
            foreach(@flds) { print "$_ => ", $response->header($_), "\n" }
        }
        my $encoding = $response->content_encoding;
        return $response unless $encoding;
        if($encoding =~ /x-aes-cbc/) {
            my $key;
            my $h_twofish = $response->header('x-apple-twofish-key');
            my $h_protocol = $response->header('x-apple-protocol-key') || 0;
            my $h_iviv = $response->header('x-apple-crypto-iv');
            if( $h_twofish ) {
                my $tf = new Crypt::AppleTwoFish(hexToUchar($h_twofish));
                $key = $tf->decrypted;
            }
            elsif($h_protocol == 2) { 
                $key = decode_base64("ip2tOZ+wFMExvmEYINeIlQ==");
            }
            elsif($h_protocol == 3) { 
                $key = decode_base64("mNHiLKoNir1l0UOtJ1pe5w==");
            }
            else { croak "Bad encoding protocol in response from $url$params" }
            if ( $h_iviv ) {
                my $alg = new Crypt::Rijndael($key, Crypt::Rijndael::MODE_CBC);
                $alg->set_iv(hexToUchar($h_iviv));
                $response->content($alg->decrypt($response->content));
            }
            else { croak "No aes crypto-iv given in response from $url$params" }
        }
        if($encoding =~ /gzip/) { 
            $response->content(Compress::Zlib::memGunzip($response->content));
            print "Gzip uncompressed content:\n", $response->content, "\n\n"
              if $self->{protocol}->{DEBUG} > 1;
        }
    }
    else { croak $response->status_line . "\n" }
    return $response;
}

#************ public methods unique to LWP::UserAgent::iTMS_Client ***********#

sub search {
    my($self, %search_terms) = @_;
    my $search_url = $advanced_search_url;
    my $params = '';
    my $loops = 0;
    while( my($type, $term) = each %search_terms ) {
        if($type eq 'all') {
            $search_url = $all_search_url;
            $params = "term=$term";
            last;
        }
        $params .=  '&' if $loops;
        $params .= $search_topics{$type} . '=' . escapeHTML($term);
        $loops++;
    }
    my $results = $self->request($search_url, $params);
    return $self->parse_dict($results->content, 'array/dict');
}

sub retrieve_keys_from_iTMS {
    my ($self) = @_;
    my $gu_id;
    my $save_id = 1;
    if($self->{protocol}->{gu_id} and $self->{protocol}->{gu_id} ne '-1') { 
        $save_id = 0;
        $gu_id = $self->{protocol}->{gu_id};
    }
    else {
        $gu_id = $self->gu_id || $self->make_gu_id;
    }
    my $response_hashref = $self->login;
    my $auth_info = $response_hashref->{jingleDocType};
    croak "Machine authorization failed!" if $auth_info !~ /Success/i;
    $self->save_gu_id($gu_id) if $save_id;   
    $self->authorize;
    $self->save_keys;
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

#******************  internal class methods ****************************/

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
          or croak "cannot $gu_id_file: $!";
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
    my $guid_b64 = encode_base64($guid);
    open(my $outfh, '>>', $self->drms_dir . "GUID") 
      or croak "Cannot save GUID, WRITE DOWN (base64) $guid_b64:  $!";
    print $outfh $guid_b64;
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
          or croak "Cannot open $pathname for writing: $!";
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
    opendir(my $dh, $drms_dir) or croak "Cannot open DRMS directory: $!";
    my @keyfile = readdir $dh;
    close $dh;
    @keyfile = grep { /(\w{8})\.\d{3}/ and ($1 eq $hex_ds_id) } @keyfile;
    my %keys;
    print "Looking for ", scalar @keyfile, " key files.\n"
      if $self->{protocol}->{DEBUG};
    foreach my $fname (@keyfile) {
        next unless $fname =~ /\.(\d{3})$/;
        my $ky = $1;
        open(my $fh, $drms_dir . $fname) or croak "Cannot read $fname: $!";
        read($fh, my $keyval, -s $fh);
        print "Key value: $keyval\n" 
          if $self->{protocol}->{DEBUG} and $self->{protocol}->{DEBUG} > 1;
        close $fh;
        $self->{protocol}->{user_keys}->{$ky} = $keyval;
    }
    print "Found on drive: ", scalar keys %{$self->{protocol}->{user_keys}}, 
      " total keys.\n" if $self->{protocol}->{DEBUG};   
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
    my $twig = new XML::Twig( 
        TwigHandlers => { $path => sub {
            my $elt = $_;
            $entry_index++;
            while( $elt = $elt->next_elt('key') ) {
                my $key = $elt->text;
                my $next = $elt->next_elt;
                last if $next->name =~ /dict/;
                my $value = ($next) ? $next->next_elt_text : 1;
                $entries[$entry_index]->{$key} = $value;
            }
        } }, 
    );
    $twig->parse($content);
    if($self->{protocol}->{DEBUG} and $self->{protocol}->{DEBUG} > 1) {
        print "parse_dict results: There are ", scalar @entries, " results.\n";
        foreach my $hr (@entries) {
            print "\n\n";
            while(my ($k, $v) = each %{$hr} ) {
                print "$k => $v \n";
            }
        }
    }
    # return reference to an array of hashrefs.
    # each hashref is a found item in a dict
    return \@entries;
}


sub parse_xml_response {
    my($self, $xml_response_text) = @_;
    my %url_bag_read;    
    my $key_string_reader = sub {
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
    my $twig = new XML::Twig( Twig_Handlers => 
      { 'plist/dict' => $key_string_reader } );
    $twig->parse($xml_response_text);
    if($self->{protocol}->{DEBUG} and $self->{protocol}->{DEBUG} > 1) {
        foreach my $k (keys %url_bag_read) { 
            print "$k : $url_bag_read{$k} \n";
        }
    }
    return \%url_bag_read;
}

sub login {
    my($self) = @_;
    my $user_id = $self->{protocol}->{user_id};
    my $password = $self->{protocol}->{password};
    my $account_type = $self->{protocol}->{account_type_code};
    my $gu_id = $self->gu_id || $self->make_gu_id;
    croak "No guID for login" unless $gu_id;
    print "iTMS login: user $user_id, password length ", length $password, "\n"
      if $self->{protocol}->{DEBUG};
    my $resp = $self->request("http://phobos.apple.com/storeBag.xml", '')
      or croak "Cannot reach iTMS key server phobos.apple.com via network";   
    $resp = $self->request("http://phobos.apple.com/secureBag.xml", '')
      or croak "Cannot retrieve secure bag from iTMS over network";
    $self->{protocol}->{url_bag} = $self->parse_xml_response($resp->content);
    my $authAccount = $self->{protocol}->{url_bag}->{authenticateAccount}
      or croak "URL for 'authenticateAccount' not found in iTMS bag.";
    $self->{protocol}->{login_id} = $user_id;
    print "Login progress: Authenticating user $user_id\n" 
      if $self->{protocol}->{DEBUG};
    my $cgi_params = '?appleId=' . escapeHTML($user_id) . '&password=' .
      escapeHTML($password) . '&accountKind=' . $account_type . 
      '&attempt=1&guid=' . escapeHTML($self->gu_id || $self->make_gu_id);
    $resp = $self->request($authAccount, $cgi_params)
      or croak "Cannot authenticate user $user_id";
    my $auth_response = $self->parse_xml_response($resp->content);
    my $jingleDocType = $auth_response->{jingleDocType};
    my $customer_message = $auth_response->{customerMessage};
    if("authenticationsuccess" ne lc($jingleDocType)) 
      { croak "Login failure! Message: $customer_message" }
    $self->{protocol}->{password_token} = $auth_response->{passwordToken};
    print "password token is ", $self->{protocol}->{password_token}, "\n"
          if $self->{protocol}->{DEBUG};
    $self->{protocol}->{ds_id} = $auth_response->{dsPersonId};
    croak "Bad dsID from login: $self->{protocol}->{ds_id}" 
      if $self->{protocol}->{ds_id} < 0;
    if($self->{protocol}->{DEBUG} and $self->{protocol}->{DEBUG_ID_FILE}) {
        open(my $fh, ">>", $self->{protocol}->{DEBUG_ID_FILE}) 
            or carp "Cannot open the debug dump file: $!";
        print $fh $resp->content;
        close $fh;
    }
    if($self->{protocol}->{DEBUG} and $self->{protocol}->{DEBUG} > 1) {
        print $resp->content;
        foreach my $ky (sort keys %{$auth_response}) {
            print "$ky => ", $auth_response->{$ky}, "\n";
        }
    }
    return $auth_response;
}

sub authorize {
    my($self) = @_;
    my $keys = $self->get_saved_keys;
    return $keys if $keys;
    print "Authorizing via iTMS\n" if $self->{protocol}->{DEBUG};   
    my $authorizeMachine = $self->{protocol}->{url_bag}->{authorizeMachine}
      or croak "No URL for authorizeMachine found in bag.";
    my $cgi_params = "?guid=" . $self->{protocol}->{gu_id};    
    my $resp = $self->request($authorizeMachine, $cgi_params)
      or croak "Failed to properly access authorizing server over network";
    my $dict = $self->parse_dict($resp->content, 'plist/dict')->[0];
    my $jingleDocType = $dict->{jingleDocType};
    croak( "Authorization failure for guID ", $self->{protocol}->{gu_id} )
      unless $jingleDocType and $jingleDocType =~ /success$/i;
    print("Authorized guID ", $self->{protocol}->{login_id}, "\n") 
      if $self->{protocol}->{DEBUG};
    my $twofish = ($dict->{encryptionKeysTwoFish}) ? 1 : 0;
    foreach my $k ( grep { $_ =~ /^\d+$/ } keys %{$dict} ) {
        my $hkey = $dict->{$k};
        print "Found key number $k, val $hkey\n" if $self->{protocol}->{DEBUG};
        my $bkey = hexToUchar($hkey);
        if($twofish) {
            my $tf = new Crypt::AppleTwoFish($bkey);
            $bkey = $tf->decrypted;
        }
        $self->{protocol}->{user_keys}->{$k} = $bkey;
    }
    print "At ", scalar localtime, " ", 
      scalar keys %{$self->{protocol}->{user_keys}}, 
      " keys retrived from server.\n" if $self->{protocol}->{DEBUG};
    # user_keys references a hash, base index 1, of binary keys
    # with hash keys 1 .. number of keys
    return $self->{protocol}->{user_keys};
}

sub deauthorize {
    my($self) = @_;
    print "Deauthorizing user ", $self->{protocol}->{gu_id}, "\n"
      if $self->{protocol}->{DEBUG};
    $self->login;
    my $deauth_url = $self->{protocol}->{url_bag}->{deauthorizeMachine} 
      or croak "URL for 'deauthorizeMachine' not found in url bag.";
    my $cgi_params = "?guid=" . escapeHTML($self->{protocol}->{gu_id});
    my $resp = $self->request($deauth_url, $cgi_params) 
      or croak "Could not access $deauth_url over network";
    my $auth_response = $self->parse_xml_response($resp->content);
    my $jingleDocType = $auth_response->{jingleDocType};
    my $customerMessage = $auth_response->{customerMessage};
    unless( lc($jingleDocType) eq 'success' ) 
      { croak "Error: Failed to deauthorize user $self->{gu_id}" }
    print "Deauthorized user ", $self->{protocol}->{gu_id}, "\n"
      if $self->{protocol}->{DEBUG};
    print "Deauthorizing complete" if $self->{protocol}->{DEBUG};
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


=head1 NAME

LWP::UserAgent::iTMS_Client - libwww-perl client for Apple iTunes music store

=head1 SYNOPSIS

    use LWP::UserAgent::iTMS_Client;
    
    # search the Store
    
    my $ua = LWP::UserAgent::iTMS_Client->new;
    my $listings = $ua->search( song => 'apples' );
    foreach my $album (@{$listings}) { print $album->{songName} }

    # get my authorization keys

    my $ua = new LWP::UserAgent::iTMS_Client(
        account_type => 'apple',
        user_id => 'name@email.org',
        password => 'password',
        DEBUG => 1,
        DEBUG_ID_FILE => "debug_id.txt",
        ds_id => 71111111,
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

=head1 METHODS  (to be finished later)

=item B<new>

=item B<request>

=item B<search>

=item B<retrieve_keys_from_iTMS>

=item B<deauthorize_gu_id>

=head1 BUGS

This is a development version, so no doubt there are lots of bugs. 
For starters, the searches only work with 'song' and 'all' at the moment. 
Making LWP look on the internet like a recent copy of iTunes is a bit 
of a moving target. Please don't use up your 5 iTunes machines with this 
module, fail to save youe guID strings, have to call iTMS to wipe your 
authorizations and start over, and then blame us. That is what the
deauthorize_gu_id routine is for.

=head2 SEE ALSO ON CPAN
    
=item L<Audio::M4P>, L<Audio::M4P::Atom>, L<Audio::M4PDecrypt>, L<Mac::iTunes>, L<Net::iTMS>

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
