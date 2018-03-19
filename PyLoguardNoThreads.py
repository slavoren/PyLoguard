import time
import os
import re
import xml.etree.ElementTree
from stat import ST_SIZE
from os import stat

CONFIG_FILE = 'C:\\Users\\Renoslav\\PycharmProjects\\PyLogGuard\\config.xml'

# Parse XML config
email_alias = {}
watcher_rule = []
key_def = {}
root = xml.etree.ElementTree.parse(CONFIG_FILE).getroot()
logdir = root.find('logdir').text

for mail_item in root.findall('mail'):
    email_alias[mail_item.find('alias').text] = [m.text for m in mail_item.findall('email')]

for watcher_item in root.findall('watcher'):
    watcher_rule.append({'name': watcher_item.find('name').text,
                         'filter_key': watcher_item.find('filter_key').text,
                         'history': watcher_item.find('history').text,
                         'history_key': watcher_item.find('history_key').text,
                         'mail_recipient': watcher_item.find('mail_recipient').text,
                         'description': watcher_item.find('description').text})

for key_item in root.findall('key'):
    key_def[key_item.find('name').text] = {'regex': key_item.find('regex').text,
                                           'regex_mode': key_item.find('regex_mode').text,
                                           'regex_group': key_item.find('regex_group').text}


def coroutine(func):
    """Coroutine helper"""
    def start(*args, **kwargs):
        cr = func(*args, **kwargs)
        cr.next()
        return cr

    return start


@coroutine
def grep(regex, regex_mode, regex_group, target):
    while True:
        line = (yield)
        #print(regex)
        if regex_mode == 'match':
            result = re.match(regex, line)
            if result:
                print("match OK")
                target.send(line)
        elif regex_mode == 'search':
            result = re.search(regex, line)
            if result:
                print("search OK")
                target.send(line)
        #print("GREP", pattern, target)
                # send to proper consumer


@coroutine
def jelenice():
    while True:
        line = (yield)
        print("jelenice")

@coroutine
def vevercice():
    while True:
        line = (yield)
        print("vevercice")


def open_logs(files):
    slovnik = {}
    for f in files:
        slovnik[f] = {'handle': open(os.path.join(logdir, f), 'r'),
                      'inode': os.stat(os.path.join(logdir, f)).st_ino,
                      'pos': None}
    return slovnik


def change_pos(logs_dict, offset, whence):
    for i in logs_dict:
        logs_dict[i]['handle'].seek(offset, whence)
        logs_dict[i]['pos'] = logs_dict[i]['handle'].tell()


def key_detect(line, key_signature):
    # key_signature nacist z xml
    for i in key_signature:
        result = i.search(line)
        if result:
            print(result.group(0), result.group(1), result.group(2))


def generate(files):
    logs = open_logs(files)
    change_pos(logs, 0, 2)  # kursor na konec vsech souboru
    while True:
        for i in logs:
            line = logs[i]['handle'].readline()
            if not line:
                time.sleep(0.5)  # Sleep briefly
                continue
            logs[i]['pos'] = logs[i]['handle'].tell()
            yield (i, line.strip(), logs[i]['pos'], str(logs[i]['handle']))


@coroutine
def broadcast(targets):
    while True:
        item = (yield)
        for target in targets:
            target.send(item)


if __name__ == '__main__':
    files = os.listdir(logdir)
    a = broadcast([grep(key_def[w['filter_key']]['regex'],
                        key_def[w['filter_key']]['regex_mode'],
                        key_def[w['filter_key']]['regex_group'],
                        jelenice()) for w in watcher_rule])
    #a = broadcast([grep('BPDU', jelenice()),
    #               grep('Authentication failed', vevercice())
    #               ])

    for i in generate(files):
        print(i)
        a.send(i[1])
