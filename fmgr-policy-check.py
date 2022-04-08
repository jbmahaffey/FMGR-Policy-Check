#!/usr/bin/env python3

import ssl, json, requests, argparse, logging, csv, time, pprint

ssl._create_default_https_context = ssl._create_unverified_context
requests.packages.urllib3.disable_warnings() 


def main():
    ################ MODIFY THESE VARIABLES #############################################################################
    adom = 'root'                                      # FortiAnalyzer ADOM
    policypackage = 'jmahaffey-fmgr-api'               # Enter the start date and time in this format YYYY-MM-DDTHH:MM:SS
    #####################################################################################################################

    # Arg Parser to add arguments at runtime (./fmgr-policy-check.py --fortimanager 192.168.101.10 --user test --password changeme)
    parser = argparse.ArgumentParser()
    parser.add_argument('--fortimanager', default='', help='FortiManager IP Address')
    parser.add_argument('--user', default='', help='FMGR API User')
    parser.add_argument('--password', default='', help='FMGR API User Password')
    args = parser.parse_args() 

    url = 'https://%s/jsonrpc' % args.fortimanager
    headers = {'content-type': "application/json"}

    # Login to FMGR and get session key
    authlogin = {
        "method": "exec",
        "params": [
            {
            "data": {
                "passwd": args.password,
                "user": args.user
            },
            "url": "/sys/login/user"
            }
        ],
        "id": 1
        }

    try:
        token = requests.post(url, data=json.dumps(authlogin), headers=headers)
        tokenjson = token.json()
        sessionkey = tokenjson['session']
    except:
        logging.error('Unable to login to FortiManager')
        exit()

    # Refresh hit count
    hitcount = {
        "method": "exec",
        "params": [
            {
            "data": {
                "adom": "%s" % adom,
                "pkg": "%s" % policypackage,
            },
            "url": "/sys/hitcount"
            }
        ],
        "session": "%s" % sessionkey,
        "id": 3
        }
    
    requests.post(url, data=json.dumps(hitcount), headers=headers)

    # Pull policies in policy package
    policy = {
        "method": "get",
        "params": [
            {
            "get used": 0,
            "loadsub": 0,
            "option": "",
            "url": "/pm/config/adom/%s/pkg/%s/firewall/policy" % (adom, policypackage)
            }
        ],
        "session": "%s" % sessionkey,
        "id": 2
        }

    pol = requests.post(url, data=json.dumps(policy), headers=headers)
    poljson = pol.json()
    for polid in poljson['result'][0]['data']:
        print(polid['policyid'], polid['_hitcount'], polid['srcintf'], polid['dstintf'], polid['srcaddr'], polid['dstaddr'])

    # Logout of FMGR
    try:
        authlogout = {
            "method": "exec",
            "params": [
                {
                "url": "/sys/logout"
                }
            ],
            "session": "%s" % sessionkey,
            "id": 4
            } 

        requests.post(url, data=json.dumps(authlogout), headers=headers)
    except:
        logging.error('Unable to logout of FortiAnalyzer')

if __name__ == '__main__':
    main()