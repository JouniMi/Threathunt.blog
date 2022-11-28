#!/usr/bin/env python3
# Author: Jouni Mikkola
# Some parts of the script are work of others, if so the links to the original are stated within the script.
# Feel free to use the script for your liking. No restrictions attached.

import json
import urllib.request
import urllib.parse
from elasticsearch import Elasticsearch

#elasticsearch
es = Elasticsearch("http://your_elasticsearch_server:9200")

#Defender API keys
Client_id = "your_Defender_client_id"
Client_secret = "your_Defender_client_secret"
TenantId = "your_Defender_tenant_id"

# app_auth function copied from here: https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Notebooks/M365D%20APIs%20ep3.ipynb
def app_auth(cid,secret,tenantId):
    url = "https://login.windows.net/%s/oauth2/token" % (tenantId) # Login OAUTH2 page
    resourceAppIdUri = 'https://api.security.microsoft.com' # M365 Api

    body = {
        'resource' : resourceAppIdUri,
        'client_id' : cid,
        'client_secret' : secret,
        'grant_type' : 'client_credentials'
    }

    data = urllib.parse.urlencode(body).encode("utf-8")

    req = urllib.request.Request(url, data)
    response = urllib.request.urlopen(req)
    jsonResponse = json.loads(response.read())
    aadToken = jsonResponse["access_token"] # Access token for the next hour

    return aadToken

# Exec mtp query copied from here: https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Notebooks/M365D%20APIs%20ep3.ipynb
# Declare a function to query the M365 Defender API
# Minor changes made
def exec_mtp_query(query,aadToken):
    url = "https://api.security.microsoft.com/api/advancedhunting/run" #M365 Advanced Hunting API
    headers = { 
    'Content-Type' : 'application/json',
    'Accept' : 'application/json',
    'Authorization' : "Bearer " + aadToken
    }

    data = json.dumps({ 'Query' : query }).encode("utf-8")

    req = urllib.request.Request(url, data, headers)
    response = urllib.request.urlopen(req)
    jsonResponse = json.loads(response.read())
    results = jsonResponse["Results"]
    return results

#Add the filters to a dict
#Follow the same format to add your own queries.
queries = {
    'AADSpnSignInEventsBeta_testing': f'AADSpnSignInEventsBeta | where Timestamp > ago(30d)',
    'EmailUrlInfo_testing': f'EmailUrlInfo| where Timestamp > ago(30d)'
}

#Authenticate to the MDE API.
aadToken = app_auth(Client_id,Client_secret,TenantId)

#Run the queries stored in the queries dict, one by one.
for a in queries:
    results = exec_mtp_query(queries[a],aadToken)
    if results:
        for r in results:
            # Add the query name to the dict
            r['query_name'] = a
            resp = es.index(index="mde_data", document=r)
            print(resp['result'])
    else:
        print("Dict is empty, no results for the query " + a)
