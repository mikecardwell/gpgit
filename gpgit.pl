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
  my $encrypt_mode           = 'pgpmime';
  my $alternative_strip_html = 0;
  my @recipients             = ();
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
	} elsif( $key eq '--alternative-strip-html' ){
           $alternative_strip_html = 1;
	} elsif( $key =~ /^.+\@.+$/ ){
	   push @recipients, $key;
	} else {
           die "Bad argument: $key\n";
	}
     }
     die "Missing recipients\n" unless @recipients;
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

## When we're in prefer-inline or inline-or-plain mode, we can't encrypt the common multipart/alternative,
## "text/plain followed by text/html" emails. Well, if we strip the HTML part, we can.

  if( $alternative_strip_html ){
     if( $encrypt_mode eq 'prefer-inline' || $encrypt_mode eq 'inline-or-plain' ){
        if( $mime->mime_type eq 'multipart/alternative' ){
           my @parts = $mime->parts();
           if( int(@parts) == 2 && $parts[0]->mime_type eq 'text/plain' && $parts[1]->mime_type eq 'text/html' ){
              ## Only do this when the body of the text/plain part is at least 10 characters long. Handling empty text/plain parts
                my $body = $parts[0]->bodyhandle->as_string;
                $body =~ s/^[\s\r\n]*(.*?)[\s\r\n]*$/$1/s;
                $mime->parts([$parts[0]]) if length($body) >= 10;
	   }
        }
     }
  }

## Encrypt
  {
     $mime->make_singlepart;

     my $code;
     if( $encrypt_mode eq 'pgpmime' ){
        $code = $gpg->mime_encrypt( $mime, @recipients );
     } elsif( $encrypt_mode eq 'prefer-inline' ){
        $code = $mime->mime_type =~ /^text\/plain/
              ? $gpg->ascii_encrypt( $mime, @recipients )
              : $gpg->mime_encrypt(  $mime, @recipients );
     } elsif( $encrypt_mode eq 'inline-or-plain' ){
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

sub help {
   print << "END_HELP";
Usage: gpgit.pl recipient1 recipient2

Gpgit takes a list of email addresses as its arguments. The email is encrypted
using the public keys associated with those email addresses.

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

  --alternative-strip-html

multipart/alternative emails containing a text/plain part followed by a
text/html part are quite common. These emails can only be encrypted using
PGP/MIME. So in inline-or-plain mode, they wont be encrypted, and in
prefer-inline mode, they will be encrypted using PGP/MIME. If you enable
this option, we strip off the HTML part of these emails, and pack them down
into a single part email so that inline encryption can be used. This only
happens if the body of the text/plain part is at least 10 characters long
as we don't want to keep blank text/plain parts. The text/plain and
text/html parts *should* contain the same information, so this *should*
be safe. It is disabled by default though.
END_HELP
  exit 0;
}
