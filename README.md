#PenTesting Scout v1.0
                               

Use it during recognition phase in web site's pentesting. This tool provides
dns enumeration with class C's reverse DNS and subdomain's bruteforce.
You can also use it to crawl web site's folder tree. This version is not finished
yet but it works.
 
Be careful with sub domain's brute-force and spider, default
dictionnary is huge and this may take time. By default, the spider is settled for
1 level depth, change it in display/displayCLI.py line 126 but this may result of
huge amount of HTTP request and possible problem with web's site's admin, even
with the Law. In theory, this is fully legal because all collected informations
are public but some sysadmins are nervous in front of log flood, be careful !

By default, this application runs in interactive mode but you can launch dnsenum
or spider directly with corresponding arguments.

##Usage:

    pentestingscout.py [-d NAME] [-es] [--depth=DEPTH] DOMAIN

##Arguments:
    DOMAIN          website to be test

##Options:
    -h --help       show this help message and exit
    --version       show version and exit
    -d NAME         name of your custom dictionnary, if not, directories.jbrofuzz
                    is used by default.This dictionnary must be in the 'dic' directory,
                    at the root of the application
    -e              Launch the dns enumeration directly (no interactive mode)
    -s              Launch the spider directly (no interactive mode)
    --depth=DEPTH   Depth of the spider process, number of url's level to crawl, 2 by default
