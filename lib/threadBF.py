#!/usr/bin/python
# -*- coding: utf-8 -*-

from threading import Thread

class ThreadBF(Thread):
    """Class which models threads dedicated to bruteforce"""
    def __init__(self, test):
        Thread.__init__(self)
        #self.running = False
        self.test=test

    def run(self):
        print(self.test)
