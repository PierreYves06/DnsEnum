# PenTesting Scout v1.1
                               
Use it during recognition phase in web site's pentesting. This tool provides
dns enumeration with class C's reverse DNS and subdomain's bruteforce.
You can also use it to crawl web site's folder tree.
 
Be careful with sub domain's brute-force and spider, default
dictionnary is huge and this may take time. By default, the spider is settled for
2 level depth, change this with the appropriate option but this may result of
huge amount of HTTP request and possible problem with web's site's admin, even
with the Law. In theory, this is fully legal because all collected informations
are public but some sysadmins are nervous in front of log flood, be careful !

Same thing for the default dictionnary (directories.jbrofuzz), moreover, and this is
the application's weakness, spider and sub domain's brute-force sets a lot of time.
Performance improvement is on top of my TODO list.

By default, this application runs in interactive mode but you can launch dnsenum
or spider directly with corresponding arguments.

## Requirements

You have to install docopt and colorama with pip3

## Usage:

    python3 pentestingscout.py [-d NAME] [-esqf] [--depth=DEPTH] DOMAIN

## Arguments:

    DOMAIN          website to be test

## Options:
    -h --help       show this help message and exit
    --version       show version and exit
    -q              Quiet mode
    -f              Yes automatic to all questions
    -d NAME         name of your custom dictionnary, if not, directories.jbrofuzz
                    is used by default.This dictionnary must be in the 'dic' directory,
                    at the root of the application
    -e              Launch the dns enumeration directly (no interactive mode)
    -s              Launch the spider directly (no interactive mode)
    --depth=DEPTH   Depth of the spider process, number of url's level to crawl, 2 by default

## Historical
    1.1 : Add gathering informations and data storage in JSON
