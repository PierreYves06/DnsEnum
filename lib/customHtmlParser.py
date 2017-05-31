#!/usr/bin/python
# -*- coding: utf-8 -*-

from html.parser import HTMLParser

class CustomHtmlParser(HTMLParser):
    """Class dedicated to custom HTML parser"""

    def handle_starttag(self, tag, attrs):
        print("Start tag:", tag)
