#coding:UTF-8
__author__ = 'dj'

import random

#Upload suffix name check
def allowed_file(filename):
    ALLOWED_EXTENSIONS = set(['pcap', 'cap'])
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

#Get the file suffix
def get_filetype(filename):
    return '.' + filename.rsplit('.', 1)[1]

#Generate a random string file name
def random_name():
    return ''.join(random.sample('1234567890qazxswedcvfrtgbnhyujmkiolp', 10))