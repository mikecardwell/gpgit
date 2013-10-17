#!/usr/bin/perl

##############################################################################
#                                                                            #
# Copyright 2011, Mike Cardwell - https://grepular.com/                      #
#                                                                            #
# This program is free software; you can redistribute it and/or modify       #
# it under the terms of the GNU General Public License as published by       #
# the Free Software Foundation; either version 2 of the License, or          #
# any later version.                                                         #
#                                                                            #
# This program is distributed in the hope that it will be useful,            #
# but WITHOUT ANY WARRANTY; without even the implied warranty of             #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              #
# GNU General Public License for more details.                               #
#                                                                            #
# You should have received a copy of the GNU General Public License          #
# along with this program; if not, write to the Free Software                #
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA #
#                                                                            #
##############################################################################

use strict;
use warnings;
use Mail::GnuPG;
use MIME::Parser;

## Parse args
  my $encrypt_mode   = 'pgpmime';
  my $inline_flatten = 0;
  my @recipients     = ();
  {
     help() unless @ARGV;
     my @args = @ARGV;
     while( @args ){
        my $key = shift @args;
	if( $key eq '--help' || $key eq '-h' ){
	   help();
	} elsif( $key eq '--encrypt-mode' ){
	   $encrypt_mode = shift @args;
	   unless( defined $encrypt_mode && grep( $encrypt_mode eq $_, 'prefer-inline', 'pgpmime', 'inline-or-plain' ) ){
	      die "Bad value for --encrypt-mode\n";
	   }
	} elsif( $key eq '--inline-flatten' ){
           $inline_flatten = 1;
	} elsif( $key =~ /^.+\@.+$/ ){
	   push @recipients, $key;
	} else {
           die "Bad argument: $key\n";
	}
     }
     die "Missing recipients\n" unless @recipients;
     if( $inline_flatten && $encrypt_mode eq 'pgpmime' ){
        die "inline-flatten option makes no sense with \"pgpmime\" encrypt-mode. See --help\n"
     }
  }

## Set the home environment variable from the user running the script
  $ENV{HOME} = (getpwuid($>))[7];

## Object for GPG encryption
  my $gpg = new Mail::GnuPG();

## Make sure we have the appropriate public key for all recipients
  foreach( @recipients ){
     unless( $gpg->has_public_key( $_ ) ){
        while(<STDIN>){
           print;
        }
        exit 0;
     }
  }

## Read the plain text email
  my $plain;
  {
     local $/ = undef;
     $plain = <STDIN>;
  }

## Parse the email
  my $mime;
  {
     my $parser = new MIME::Parser();
     $parser->decode_bodies(1);
     $parser->output_to_core(1);
     $mime = $parser->parse_data( $plain );
  }

## Test if it is already encrypted
  if( $gpg->is_encrypted( $mime ) ){
     print $plain; exit 0;
  }

## If the user has specified that they prefer/need inline encryption, instead of PGP/MIME, and the email is multipart, then
## we need to attempt to flatten the message down into a single text/plain part. There are a couple of safe'ish lossy ways of
## doing this:
##
## Removing text/html from multipart/alternative entities that also have a text/plain part
##   In this scenario, the two text parts are *supposed* to contain the same content. So it should be ok to strip the html part.
##   We only do this if the text/plain part contains at least 10 characters of data.
##
## Removing images from multipart/related entities when they are referred to from a HTML part
##   We'll be stripping the HTML parts, so if those HTML parts use a CID URL to refer to a related image, we may as well strip
##   those images too as they will no longer be used in the display of the email

  if( $inline_flatten ){
     if( $encrypt_mode eq 'prefer-inline' || $encrypt_mode eq 'inline-or-plain' ){
        if( $mime->mime_type =~ /^multipart\/(alternative|related)$/ ){

           ## We're going to try several things to flatten the email to a single text/plain part. We want to work on a duplicate
	   ## version of the message so we can fall back to the original if we don't manage to flatten all the way
             my $new_mime = $mime->dup;

           ## Remember the original MIME structure so we can add it to an information header
             my $orig_mime_structure = mime_structure( $mime );

	   ## We may already be able to safely flatten, if we have a multipart/x message with only a single child part. Unlikely
             $new_mime->make_singlepart;

           ## multipart/related
             flatten_related( $new_mime     ) if $new_mime->mime_type eq 'multipart/related';
             flatten_alternative( $new_mime ) if $new_mime->mime_type eq 'multipart/alternative';

           ## Keep the new message if it was succesfully flattened
             if( $new_mime->mime_type !~ /^multipart\// ){
                $new_mime->head->add('X-GPGIT-Flattened-From', $orig_mime_structure );
                $mime = $new_mime;
             }
        }
     }
  }

## Encrypt
  {
     my $code;
     if( $encrypt_mode eq 'pgpmime' ){
        $code = $gpg->mime_encrypt( $mime, @recipients );
     } elsif( $encrypt_mode eq 'prefer-inline' ){
        $mime->make_singlepart;
        $code = $mime->mime_type =~ /^text\/plain/
              ? $gpg->ascii_encrypt( $mime, @recipients )
              : $gpg->mime_encrypt(  $mime, @recipients );
     } elsif( $encrypt_mode eq 'inline-or-plain' ){
        $mime->make_singlepart;
        if( $mime->mime_type =~ /^text\/plain/ ){
	   $code = $gpg->ascii_encrypt( $mime, @recipients );
	} else {
	   print $plain; exit 0;
	}
     }

     if( $code ){
        print $plain;
	exit 0;
     }
  }

## Remove some headers which might have been broken by the process of encryption
  $mime->head()->delete($_) foreach qw( DKIM-Signature DomainKey-Signature );

## Print out the encrypted version
  print $mime->stringify;

## Flatten multipart/alternative by removing html parts when safe
  sub flatten_alternative {
     my $entity = shift;

     my @parts = $entity->parts;

     if( int(@parts) == 2 && $parts[0]->mime_type eq 'text/plain' && $parts[1]->mime_type eq 'text/html' ){
        my $body = $parts[0]->bodyhandle->as_string;
        $body =~ s/^[\s\r\n]*(.*?)[\s\r\n]*$/$1/s;
        if( length($body) >= 10 ){
           $entity->parts([$parts[0]]);
           $entity->make_singlepart;
        }
     }
  }

## Flatten multipart/related by removing images when safe
  sub flatten_related {
     my $entity = shift;

     ## Scan the existing parts
       my( @parts, %cids );
       foreach my $part ( $entity->parts ){
          if( $part->mime_type =~ /^image\// ){
             my $content_id = $part->head->get('Content-Id')||'';
             $content_id =~ s/^<(.+?)>$/$1/;
             $content_id =~ s/[\r\n]+//g;
             if( length($content_id) ){
                push @parts, { content_id => $content_id, part => $part };
                next;
             }
          } elsif( $part->mime_type eq 'text/html' ){
             $cids{$_} = 1 foreach get_cids_from_html( $part );
          } elsif( $part->mime_type eq 'multipart/alternative' ){
             foreach my $part ( grep( $_->mime_type eq 'text/html', $part->parts ) ){
                $cids{$_} = 1 foreach get_cids_from_html( $part );
             }
          }
          push @parts, { part => $part };
       }

     ## Remove images linked to from HTML
       my @new_parts;
       foreach my $part ( @parts ){
          next if exists $part->{content_id} && $cids{$part->{content_id}};
          push @new_parts, $part->{part};
       }

     ## If we've managed to get rid of at least one child part, then update the mime entity
       if( int(@new_parts) < int(@parts) ){
          $entity->parts(\@new_parts);
          $entity->make_singlepart();
       }
}

## Takes a HTML part, and looks for CID urls
  sub get_cids_from_html {
     my $entity = shift;

     ## Get the decoded HTML
       my $html = $entity->bodyhandle->as_string;

     ## Replace newlines with spaces
       $html =~ s/\s*[\r\n]+\s*/ /gsm;

     ## Parse out cid urls
       my @cids;
       $html =~ s/=\s*["']?cid:(.+?)["'\s\/>]/push @cids,$1/egoism;

     return @cids;
  }

  sub mime_structure {
     my $entity = shift;
     if( $entity->mime_type =~ /^multipart\/.+/ ){
        my @parts = $entity->parts;
	return $entity->mime_type.'('.join(",",map {mime_structure($_)} @parts).')';
     } else {
        return $entity->mime_type;
     }
  }

sub help {
   print << "END_HELP";
Usage: gpgit.pl recipient1 recipient2

Gpgit takes a list of email addresses as its arguments. The email is encrypted
using the public keys associated with those email addresses. Those public keys
*MUST* have been assigned "Ultimate" trust or it wont work.

Optional arguments:

  --help or -h

Display this usage information.

  --encrypt-mode prefer-inline / pgpmime / inline-or-plain

Single part text emails can be encrypted inline, or using PGP/MIME. Multi-part
emails can only be encrypted using PGP/MIME. "pgpmime" is the default for this
argument and means we will always use PGP/MIME. "prefer-inline" means that we
will use inline if possible, and PGP/MIME if not. "inline-or-plain" will use
inline encryption for single part emails, and no encryption for multi-part
emails.

  --inline-flatten

Only makes sense when using an "inline" encrypt-mode. When you enable this
option, we attempt to convert multipart emails to a single part text/plain
email, so inline encryption can be used. The methods we use are "lossy", but
I believe them to be safe(ish):

1.) When we find a multipart/alternative part which contains two parts: A 
    text/plain part with at least 10 characters in it, and a text/html part,
    we remove the text/html part. The text/plain part *should* contain the
    same content as the text/html part, but without the HTML markup.

2.) When we find a multipart/related part which contains image parts which
    are referred to from a HTML part via CID URLs, we remove those images.
    We can do this, because we will be removing the HTML parts that are
    referring to them, and so they *should* be redundant. We don't just
    remove image parts, we only remove "related" image parts that are
    referred by using CID URLs pointing at their Content-Id headers.
END_HELP
  exit 0;
}
