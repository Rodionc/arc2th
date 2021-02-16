#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-----------------------------------------------------------------------------
# The MIT License
#
# Copyright (c) 2021 Rodion Chekharin <rch@ast-security.ru>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#-----------------------------------------------------------------------------

from __future__ import print_function
from __future__ import unicode_literals

import requests
import sys
import json
import time
import uuid
import os
import lxml.etree
import lxml.html
commentStartWith = '#'
tString = "string"
arcBasePath = "//archive/SecurityEvent"

from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper

api = TheHiveApi('http://127.0.0.1:9000', 'apikey')

artifacts = [
    AlertArtifact(dataType='file', data=sys.argv[1], sighted=True, ioc=True)
]

xmlDoc = lxml.etree.parse(sys.argv[1])
evtID = xmlDoc.xpath(arcBasePath +'/@id')
evtName = xmlDoc.xpath(arcBasePath +'/@name')
agtName = xmlDoc.xpath(arcBasePath +'/agentHostName')
srcName = "N/A"
if agtName:
    srcName = str(agtName[0].text.strip())
lCustFields = list()
lTypes = list()
lXmlFieds = list()
try:
    with open(sys.argv[2]) as fOpts:
        for line in fOpts:
            if line[0]==commentStartWith:
                continue
            (cf, xf, cfType) = line.split(',',3)
            lCustFields.append(cf)
            lTypes.append(cfType.strip())
            lXmlFieds.append(xf)
except Exception as ex:
    print('Common exception at process: ' + str(ex))

customFields = CustomFieldHelper()
customFields.add_string('EventID',str(evtID[0]))
customFields.add_string('EventName',str(evtName[0]))
customFields.add_date('occurdate', int(time.time())*1000)

cnt = 0

for st in lCustFields:
    lVal = xmlDoc.xpath(arcBasePath +"/" + lXmlFieds[cnt])
    if lVal:
        if lTypes[cnt]==tString:
            customFields.add_string(lCustFields[cnt], str(lVal[0].text.strip()))
    cnt = cnt + 1

customFields2Add = customFields.build()

sourceRef = str(uuid.uuid4())[0:6]
alert = Alert(title='New Alert from ArcSight',
              tlp=3,
              tags=['ArcEvent', 'EventImport'],
              description='Total events: ' + str(len(evtID)),
              type='external',
              source=srcName,
              sourceRef=sourceRef,
              artifacts=artifacts,
              customFields=customFields2Add)

# Create the Alert
print('Create Alert')
print('-----------------------------')
id = None
response = api.create_alert(alert)
if response.status_code == 201:
    id = response.json()['id']
    print("Alert created: " + id)
else:
    print('ko: {}/{}'.format(response.status_code, response.text))
    sys.exit(0)
