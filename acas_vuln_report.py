#!/usr/bin/env python

import urllib2
import urllib
import json
import hashlib
import re
from collections import OrderedDict

def connect(module, action, input=()):
        data = {'module': module,
                'action': action,
                'input': json.dumps(input),
                'token': token,
                'request_id': 1}

        headers = {'Cookie': 'TNS_SESSIONID=' + cookie}

        url = server + '/request.php'

        try:
           request = urllib2.Request(url, urllib.urlencode(data), headers)
           response = urllib2.urlopen(request)
           content = json.loads(response.read())
           return content['response']

        except Exception, e:
           print "Error: " + str(e)
           return None

server = 'https://ip_or_url'
username = 'username'
password = 'password'
token = ''
cookie = ''
plugin = {}
input = {'username': username, 'password': password}
resp = connect('auth', 'login', input)
token = resp['token']
cookie = resp['sessionID']
input = {'tool': 'vulndetails',
         'sourceType': 'cumulative',
         'startOffset': 0,
         'endOffset': 0}
getRecs = connect('vuln', 'query', input)
totalRecords = int(getRecs['totalRecords'])


filters = [ # Uncomment/comment any set of filters you want to include/exclude:

# The  value 0:7 below will show results from the last 7 days. 0:30 would show vulns seen within the last 30 days.
#            {'filterName': 'lastSeen',
#             'operator': '=',
#             'value': '0:30'},

# Severity value 4,3,2 limits the results to Critical, Medium and High. 1 would show Low and 0 shows Info.
             {'filterName': 'severity',
              'operator': '=',
              'value': '4,3,2'},

# This filter will only show IAVM / CAT I & II results.
#            {'filterName': 'pluginText',
#            'operator': '~=',
#            'value': 'stig_severity>I<,stig_severity>II<'}
            ]



input = {'tool': 'vulndetails',
         'sourceType': 'cumulative',
         'filters': filters,
         'startOffset': 0,
         'endOffset': totalRecords}


vulns = connect('vuln', 'query', input)
severityText = ['Info','Low','Medium','High','Critical']
severityColor = ['green','#33BBFF','#FF8844','#991100','#7711FF']
returnedRecords = str(vulns['returnedRecords'])
filterTxt = str(filters)
filterTxt = re.sub(r'\'', '&#39;', filterTxt)
filterTxt = re.sub(r'"', '&#34;', filterTxt)

for vuln in vulns['results']:
    severity = int(vuln['severity'])
    pid = vuln['pluginID']

    if pid not in plugin:
        plugin[pid] = {}
    if 'groups' not in plugin[pid]:
        plugin[pid]['groups'] = {}

    plugin[pid]['name'] = vuln['pluginName']
    # For shorter lists of hostnames, you can use the sub below to chop off repeated text like domain names
    shortName = re.sub(r'\.example\.com', '', vuln['dnsName'])
    sol = re.sub(r'\\n', '<br>', vuln['solution'])
    plugin[pid]['solution'] = sol
    plugin[pid]['severity'] = severity
    syn = re.sub(r'\\n', '<br>', vuln['synopsis'])
    plugin[pid]['synopsis'] = syn
    iavmR = re.search(r'<iav.>(.*)</iav.>', vuln['pluginText'])
    stigR = re.search(r'stig_severity>(I*)<', vuln['pluginText'])
    outputR = re.search(r'plugin_output>(.*)</plugin_output', vuln['pluginText'])

    if iavmR is None:
        plugin[pid]['iavm'] = "NA"
    else:
        plugin[pid]['iavm'] = iavmR.group(1)
    if stigR is None:
        plugin[pid]['stig'] = "NA"
    else:
        plugin[pid]['stig'] = stigR.group(1)
    if outputR is None:
        outputHash = "solo"
    else:
        output = outputR.group(1)
        outputHash = hashlib.md5(output).hexdigest()
        outputHash = str(outputHash)

        if outputHash in plugin[pid]['groups']:
            if re.search(shortName, plugin[pid]['groups'][outputHash]['affectedHosts'], re.IGNORECASE) is None:
                plugin[pid]['groups'][outputHash]['affectedHosts'] += ', ' + shortName
        else:
            plugin[pid]['groups'][outputHash] = {}
            plugin[pid]['groups'][outputHash]['affectedHosts'] = shortName
            plugin[pid]['groups'][outputHash]['details'] = output

plugin = OrderedDict(sorted(plugin.iteritems(), key=lambda x: x[1]['severity'], reverse=True))

print '<html><style>body{font-family:arial;}tbody td:nth-of-type(odd){background:rgba(175,215,255,0.5);}tbody td:nth-of-type(even),tr:nth-of-type(even){background:rgba(200,230,255,0.5)}table{border-collapse:collapse;border-spacing:0;}td{padding:5px;border:1px solid black;}td:empty{border:none;}</style>'

# This block will check plugin 21745 for authentication erros so it can display them at the top of the list.
# However, you must recast the risk for this plugin to High or Critical, otherwise it won't be returned
# unless you are including Info results
if "21745" in plugin:
    print '<center><b style="color:#991100">Authentication Failure - Local Checks Not Run:</b><table><tr><td><b>Total</b></td><td><b>Hosts Affected</b></td><td><b>Details</b></td></tr>'
    for group in plugin['21745']['groups']:
        myHosts = plugin['21745']['groups'][group]['affectedHosts'].split()
        numHosts = len(myHosts)
        numHosts = str(numHosts)
        strOutput = re.sub(r'(^(<br/>)+)|((<br/>)+)$', '', plugin['21745']['groups'][group]['details'])

        print '<tr><td align=center valign=top>' + numHosts + '</td><td>' + plugin['21745']['groups'][group]['affectedHosts'] +'</td><td>'+ strOutput +'</td></tr>'
    print '</table></center><p><br>'
    del plugin['21745']

print '<b>Vulnerability Analysis:</b><i>(<a href=\'javascript:alert(\"' + filterTxt + '\")\'>Filters</a> matched ' + returnedRecords + ' of ' + str(totalRecords) + ' results.)</i><table><tr><td><b>Plugin</b></td><td><b>Title</b></td><td><b>IAVM</b></td><td><b>Severity</b></td><td><b>Details</b></td><td><b>Total</b></td><td><b>Hosts Affected</b></td></tr>'

for id in plugin:
    count = None
    groupLen = len(plugin[id]['groups'])
    groupLen = str(groupLen)

    for group in plugin[id]['groups']:
        myHosts = plugin[id]['groups'][group]['affectedHosts'].split()
        numHosts = len(myHosts)
        numHosts = str(numHosts)
        strOutput = re.sub(r'(^(<br/>)+)|((<br/>)+)$', '', plugin[id]['groups'][group]['details'])

        if count is None:
            if int(groupLen) > 1:
                row = '<tr><td rowspan="'+ groupLen +'" valign=top>' + id + '</td><td rowspan="'+ groupLen +'" valign=top>' + plugin[id]['name'] + '</td><td rowspan="'+ groupLen +'" valign=top>' + plugin[id]['iavm'] + '<br>CAT: ' + plugin[id]['stig'] + '</td><td rowspan="'+ groupLen +'" valign=top><b><font color=' + severityColor[plugin[id]['severity']] + '>' + severityText[plugin[id]['severity']] + '</font></b></td><td valign=top>' + strOutput + '</td><td valign=top>' + numHosts + '</td><td valign=top>' + plugin[id]['groups'][group]['affectedHosts'] + '</td></tr>'
                count = "multi"
            else:
                row = '<tr><td valign=top>' + id + '</td><td valign=top>' + plugin[id]['name'] + '</td><td valign=top>' + plugin[id]['iavm'] + '<br>CAT: ' + plugin[id]['stig'] + '</td><td valign=top><b><font color=' + severityColor[plugin[id]['severity']] + '>' + severityText[plugin[id]['severity']] + '</font></b></td><td valign=top>' + strOutput + '</td><td align=center valign=top>' + numHosts + '</td><td valign=top>' + plugin[id]['groups'][group]['affectedHosts'] + '</td></tr>'

        else:
            row = '<tr><td valign=top>' + strOutput + '</td><td valign=top>' + numHosts + '</td><td valign=top>' + plugin[id]['groups'][group]['affectedHosts'] + '</td></tr>'

        row = row.encode('ascii', 'ignore')
        print row
        print

print '</table></html>'
