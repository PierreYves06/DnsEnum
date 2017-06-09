#!/usr/bin/python
# -*- coding: utf-8 -*-

from math import *
import sys, time, os, json
from colorama import init, Fore, Back, Style
from threading import Thread
from dom.domain import *

class displayCLI(Thread):
    """Class wich models CLI's display"""

    
    def __init__(self, args, dictio='directories.jbrofuzz', depth=2):
        """
            Initialization with starting up of the thread handling the display's loop, 
            a Domain's object and a dictionary
        """
        Thread.__init__(self)
        self.running = False

        #Parsing arguments provided by the user
        dom=args['DOMAIN']
        if (dom[:7] == 'http://'):
            dom=dom[7:]
        if (dom[:8] == 'https://'):
            dom=dom[8:]
        self.target=Domain(dom)
        if (args['-d']):
            self.dictio=args['-d']
        else:
            self.dictio=dictio
        if (args['--depth']):
            self.depth=int(args['--depth'])
        else:
            self.depth=depth
        if (args['-q']):
            self.verbose=False
        else:
            self.verbose=True
        self.args=args

    def writeResult(self, file, output):
        """Method for writing results in a file"""
        #Existence's verification of target's directory
        if (os.path.exists('results/') == False):
            os.mkdir('results/')
        if (os.path.exists('results/' + self.target.getUrl()) == False):
            os.mkdir('results/' + self.target.getUrl())
        f=open('results/' + self.target.getUrl() + '/' + file, 'w')
        f.write(output)
        f.close()

    def decoratorTimerProcess(process):
        """Decorator which adds a timer to a process"""
        def timerProcess(self, name):
            start=time.time()
            process(self)
            interval=time.time() - start
            if interval < 60:
                self.custom_print('Execution time ' + name + ' : ' + str(round(interval, 2))\
                                    + ' sec(s).', Fore.YELLOW)
            elif (60 < interval < 3600):
                minutes=interval/60
                seconds=interval%60
                self.custom_print('Execution time ' + name + ' : '\
                                    + str(floor(minutes)) + ' min(s) and ' + str(floor(seconds))\
                                    + ' sec(s).', Fore.YELLOW)
            else:
                hours=interval/3600
                rest=interval%3600
                minutes=rest/60
                seconds=rest%60
                self.custom_print('Execution time ' + name + ' : '\
                                    + str(floor(hours)) + ' hour(s) and ' + str(floor(minutes))\
                                    + ' min(s) and ' + str(floor(seconds)) + ' sec(s).', Fore.YELLOW)
        return timerProcess

    def decoratorColor(process):
        """Shell's colors decorator"""
        def colorize(self, string, color):
            print(color + process(self, string) + Style.RESET_ALL)
        return colorize

    @decoratorColor
    def custom_print(self, string):
        return string

    def verboseOnOff(self, output, file):
        """Method which handles verbose mode"""
        if (self.verbose):
            print(output)
        self.writeResult(self.target.getUrl() + file, output)

    def parseListeDictio(self, liste):
        """Method for reading dictionary's list"""
        output=''
        if (isinstance(liste, str)):
            output+=liste.strip('"') + '\n'
        else:
            for item in liste:
                if (isinstance(item, str)):
                    output+=item.strip('"') + '\n'
                else:
                    for key,value in item.items():
                        output+=key + ' : ' + value + '\n'
        return output

    def processResponseYN(self, response):
        """Method which handles choices Yes/No"""
        while (response != 'y') and (response != 'n'):
            print(Fore.RED + choice + ' : Unknown Choice' + Style.RESET_ALL)
            response=input(Style.BRIGHT + 'Make a new choice please(y/n) : ' + Style.RESET_ALL)
        if (response == 'y'):
            return True
        else:
            return False

    def lectureOtherResponse(self, dictio, type):
        """Method for reading and display ReverseDNS and subdomain's bruteforce"""
        output=''
        for key,value in dictio.items():
            output+='\n' + (40*'-') + '\n'
            #Display ReverseDNS
            if (type=='RD'):
                output+='IP : ' + key + '\n'
            else:
            #Display subdomain's bruteforce
                output+='Subdomain : ' + key + '\n'
            output+='Result(s) : \n'
            if (isinstance(value, str)):
                output+=value+'\n'
            else:
                for item in value:
                    output+=item+'\n'
            output+=(40*'-') + '\n'
        return output

    def lectureDigResponse(self, liste):
        """Method for reading dig's return"""
        output=''
        if liste == []:
            output+='No response\n'
        else:
            if (isinstance(liste, str)):
                output+=liste + '\n'
            else:
                if (liste['ans'] == 'empty'):
                    output+='No response\n'
                else:
                    output+=self.parseListeDictio(liste['ans'])

                output+='Additional information:\n'
                if (liste['add'] == 'empty'):
                    output+='No additional information\n'
                else:
                    output+=self.parseListeDictio(liste['add'])
        return output

    def lectureSpiderResponse(self, liste):
        """Method for reading Spider's return"""
        lvl=0
        output=''
        for item in liste:
            if (item == []):
                output+='Result\'s end\n'
                break
            lvl+=1
            output+='Tree structure\'s level : ' + str(lvl) + '\n'
            for dictio in item:
                for key,value in dictio.items():
                    if (value in [200,403]):
                        output+=key + ' : ' + str(value) + '\n'
        return output

    def displayDnsEnum(self):
        """Display's method of DNS's enumeration"""
        output=''
        output+='\nTarget\'s IP :\n'
        output+=self.lectureDigResponse(self.target.getIP())
        output+='\nTarget\'s nameserver :\n'
        output+=self.lectureDigResponse(self.target.getNS())
        output+='\nMail\'s server of the target :\n'
        output+=self.lectureDigResponse(self.target.getMX())
        output+='\nTXT\'s record of the target :\n'
        output+=self.lectureDigResponse(self.target.getTXT())
        return output

    def displayGatheringInfos(self, liste):
        output=''
        for dict in liste:
            for key,value in dict.items():
                if (isinstance(value, str)):
                    output+=key.strip('\n\xa0') + ' : ' + value.strip('\n\xa0') + '\n'
                elif (isinstance(value, list)):
                    output+=key + '\n'
                    for item in value:
                        newItem=[]
                        for entry in item:
                            newItem.append(entry.replace('\n', ''))
                        newItem[-1]=newItem[-1].replace(' ', '')
                        output+='\t'.join(newItem) + '\n'
        return output
        

    @decoratorTimerProcess
    def enumSolo(self, name='DNS\'s enumeration'):
        """Method which launches DNS's enumeration"""
        dnsenum=Dnsenum(self.target, self.dictio)
        print(Style.BRIGHT + 'DNS\'s enumeration in progress...' + Style.RESET_ALL)
        dnsenum.processDig()
        #output=self.displayDnsEnum()
        output=[self.target.getIP(), self.target.getNS(), self.target.getMX(), self.target.getTXT()]
        self.verboseOnOff(json.dumps(output), '_dnsenum.json')
        print('Result of the DNS\'s enumeration in the file results/' + self.target.getUrl() + '/' + self.target.getUrl() + '_dnsenum.json')

        if (self.args['-f']):
            resp=True
        else:
            choice=input('Do you want to make a reverse DNS of C class on the target ? (y/n) : ')
            resp=self.processResponseYN(choice)
        if (resp):
            print(Style.BRIGHT + 'Reverse DNS of C class in progress...' + Style.RESET_ALL)
            dnsenum.processReverseDns()
            print('Result of the reverse DNS of C class in the file results/' + self.target.getUrl() + '/' + self.target.getUrl() + '_rev_dns.txt')
            output=self.lectureOtherResponse(self.target.getReverseDNS(), 'RD')
            self.writeResult(self.target.getUrl() + '_rev_dns.txt', output)
        else:
            print(Fore.RED + Style.BRIGHT + 'Reverse DNS ignored' + Style.RESET_ALL)

        if (self.args['-f']):
            resp=True
        else:
            choice=input('Do you want to make a subdomain\'s bruteforce to the target ? (y/n) : ')
            resp=self.processResponseYN(choice)
        if (resp):
            print('Used dictionary : ' + Fore.MAGENTA + self.dictio + Style.RESET_ALL)
            print(Style.BRIGHT + 'Subdomain\'s bruteforce in progress...'+ Style.RESET_ALL)
            #dnsenum.processBFSubDomain()
            dnsenum.launchThreadBF()
            output=self.lectureOtherResponse(self.target.getSubDomain(), 'BF')
            self.verboseOnOff(output, '_bf_subdom.txt')
            print('Result of subdomain\'s bruteforce in the file results/' + self.target.getUrl() + '/' + self.target.getUrl() + '_bf_subdom.txt')
        else:
            print(Fore.RED + Style.BRIGHT + 'Subdomain\'s bruteforce ignored' + Style.RESET_ALL)

    @decoratorTimerProcess
    def spiderSolo(self, name='Spider'):
        """Method which launches the Spider"""
        spider=Spider(self.target, self.dictio)

        if (self.args['-f']):
            resp=True
        else:
            choice=input('Do you want to parse a possible robots.txt ? (y/n) : ')
            resp=self.processResponseYN(choice)
        if (resp):
            print(Style.BRIGHT + 'Reading robots.txt...' + Style.RESET_ALL)
            output=spider.readRobotsTxt(self.target.getUrl())
            self.writeResult(self.target.getUrl() + '_robots.txt', output)
            print('Robots.txt saved in the file results/' + self.target.getUrl() + '/' + self.target.getUrl() + '_robots.txt')
        else:
            print(Fore.RED + Style.BRIGHT + 'Parsing of robots.txt ignored' + Style.RESET_ALL)

        if (not (self.args['--depth'])):
            choice=input('Do you want to choose spider\'s depth (2 by default)? (y/n) : ')
            resp=self.processResponseYN(choice)
            if (resp):
                newDepth=input('Depth of the spider (be careful, this may take a lot of time !)? : ')
                self.depth=int(newDepth)
        print('Dictionary used : ' + Fore.MAGENTA + self.dictio + Style.RESET_ALL)
        print('Spider\'s depth : ' + Fore.MAGENTA + str(self.depth) + Style.RESET_ALL)
        print(Style.BRIGHT + 'Bruteforce of the tree structure in progress... ' + Style.RESET_ALL)
        spider.processDepthSpider(self.depth)
        output=self.lectureSpiderResponse(self.target.getArbo())
        self.verboseOnOff(output, '_spider.txt')
        print('Result of the spider in the file results/' + self.target.getUrl() + '/' + self.target.getUrl() + '_spider.txt')

    def enumSpider(self):
        """Method which launches DNS's enumeration and Spider"""
        self.enumSolo('DNS\'s enumeration')
        self.spiderSolo('Spider')

    def gatherInfos(self):
        gatherer = GatherInfos(self.target)
        gatherer.getNetcraftInfos()
        #output=self.displayGatheringInfos(self.target.getInfos())
        self.writeResult(self.target.getUrl() + '_informations.json', json.dumps(self.target.getInfos()))
        print('Result of the netcraft\'s gathering informations in the file results/' + self.target.getUrl() + '/' + self.target.getUrl() + '_informations.json')
        output=(gatherer.whoisProcess()).decode('utf-8')
        self.writeResult(self.target.getUrl() + '_whois.json', json.dumps(output))
        print('Result of the whois in the file results/' + self.target.getUrl() + '/' + self.target.getUrl() + '_whois.json')

    def quitCLI(self):
        """Method which stops the thread and quit the CLI"""
        print(Fore.CYAN + 'Bye !' + Style.RESET_ALL)
        self.running = False

    def run(self):
        """Method run of the Thread which launches display's loop"""
        options={'1': self.enumSolo,
                    '2': self.spiderSolo,
                    '3': self.enumSpider,
                    '4': self.gatherInfos,
                    '5': self.quitCLI,
        }
        self.running = True

        #Colorama start
        init()

        self.custom_print('\n\t\t\tPenTesting Scout v1.0\n', Fore.CYAN)
        while self.running:
            print('Your target : ', end='')
            self.custom_print(self.target.getUrl(), Fore.MAGENTA)
            if hasattr(self.target, 'IP'):
                print('IP address : ', end='') 
                self.custom_print(self.target.getIP(), Fore.MAGENTA)

            #According to provided arguments, we run the desired functionality
            if (self.args['-e']) and (self.args['-s']):
                self.enumSpider()
                self.quitCLI()
                continue
            if (self.args['-e']):
                self.enumSolo('DNS\'s enumeration')
                self.quitCLI()
                continue
            if (self.args['-s']):
                self.spiderSolo('Spider')
                self.quitCLI()
                continue
            if (self.args['-g']):
                self.gatherInfos()
                self.quitCLI()
                continue

            print('What do you want to do ?\n\n\t1 - ', end='')
            self.custom_print('DNS\'s enumeration', Fore.GREEN)
            print('\t2 - ', end='')
            self.custom_print('Spider', Fore.GREEN)
            print('\t3 - ', end='')
            self.custom_print('DNS\'s enumeration + Spider', Fore.GREEN)
            print('\t4 - ', end='')
            self.custom_print('Gather informations', Fore.GREEN)
            print('\t5 - ', end='')
            self.custom_print('Exit', Fore.GREEN)
            choice=input('\nYour choice ? : ')
            try:
                if (choice == '1'):
                    options[choice]('DNS\'s Enumeration')
                elif (choice == '2'):
                    options[choice]('Spider')
                else:
                    options[choice]()
            except KeyError as e:
                print(Fore.RED + choice + ' : Unknown choice' + Style.RESET_ALL)
