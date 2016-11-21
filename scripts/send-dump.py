#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

import sys
import os
from scapy.all import *
from time import gmtime, strftime


from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import COMMASPACE, formatdate
from subprocess import Popen, PIPE

INTERFACE = "eth4"
TIMEOUT = 60
CAPTURE_PACKETS = 1000
DUMP_ARCHIVE = "/root/ddos_dumps"

EMAIL_RECIPIENTS = ['netadmins@timeweb.ru']
EMAIL_TEXT = u'''Дамп трафика атаки во вложении. \
Локальная копия дампа сохранена в каталоге {0} на сервере {1}'''
EMAIL_SUBJECT = u'''Обнаружена DDoS атака {1} на сервер {0}'''


def mail(subject=u'DDoS detect',
         text=u'text',
         recipients=[],
         file=None):
    # Mail body
    msg = MIMEMultipart("alternative")
    msg.set_charset("utf-8")
    msg["From"] = "%s@%s" % ("ddosdetector", os.uname()[1])
    msg["To"] = COMMASPACE.join(recipients)
    msg['Date'] = formatdate(localtime=True)
    msg["Subject"] = Header(subject, 'utf-8')
    # Text
    txt = MIMEText(text.encode('UTF-8'), "plain")
    txt.set_charset("utf-8")
    msg.attach(txt)
    # Attach file
    with open(file, "rb") as f:
        part = MIMEApplication(
            f.read(),
            Name=os.path.basename(file)
        )
        part[
            'Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(file)
        msg.attach(part)
    # Send mail
    p = Popen(["/usr/sbin/sendmail", "-t"], stdin=PIPE)
    p.communicate(msg.as_string())


def create_dump(catch_filter="tcp", dump=""):
    pkts = sniff(iface=INTERFACE, filter=catch_filter,
                 L2socket=None, count=CAPTURE_PACKETS, timeout=TIMEOUT)
    wrpcap(dump, pkts)


if __name__ == "__main__":
    params = sys.argv[1].split('|')
    pcap_filter = "%s and dst host %s" % (params[0], params[1])
    dump_file = "%s/host_%s_%s.pcap" % (DUMP_ARCHIVE,
                                        params[1],
                                        strftime("%Y%m%d%H%M", gmtime()))
    # create dump in archive
    if not os.path.exists(DUMP_ARCHIVE):
        os.makedirs(DUMP_ARCHIVE)
    create_dump(pcap_filter, dump_file)
    # send dump to email
    mail(subject=EMAIL_SUBJECT.format(params[1], params[2]),
         text=EMAIL_TEXT.format(DUMP_ARCHIVE, os.uname()[1]),
         recipients=EMAIL_RECIPIENTS,
         file=dump_file)
