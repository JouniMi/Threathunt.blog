# Author: Jouni Mikkola
# Some parts of the script are work of others, if so the links to the original are stated within the script.
# Feel free to use the script for your liking. No restrictions attached.
 

from shodan import Shodan
import pandas as pd
import json
import urllib.request
import urllib.parse
import datetime
from datetime import date, timedelta
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', None)

# API_keys
# These are a must to have for the script to work.
#Define Shodan, authenticate with the API key
shodanapi = Shodan('your_shodan_api_key')

#Defender API keys
Client_id = "your_client_ID"
Client_secret = "your_client_secret"
TenantId = "your_tenant_id"

def run_shodan_query_return_IP_filter(query):
    try:
        data = shodanapi.search(query)
        QueryFilter = "("
        for a in data['matches']:
            # Set the format for the timestamp
            format = "%Y-%m-%dT%H:%M:%S.%f"
            #Change the string format of the timestamp as datetime format
            IPDateTime = datetime.datetime.strptime(a['timestamp'],format)
            #Only return results where the IP address was detected less than 7 days ago
            if IPDateTime > datetime.datetime.now() - timedelta(7):
                QueryFilter = QueryFilter + "'" + a['ip_str'] + "',"
        l = len(QueryFilter)
        QueryFilter = QueryFilter[:l-1]
        QueryFilter = QueryFilter + ")"
        #Test if there are results for the Shodan queries
        if QueryFilter == ")":
            print("No results for the query : " + query)
            QueryFilter = ""
        return QueryFilter
    except Exception as e:
        print('Error: %s' % e)

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
    schema = jsonResponse["Schema"]
    results = jsonResponse["Results"]
    
    df = pd.DataFrame(results)
    
    return df

#Add the filters to a dict
#Follow the same format to add your own queries.
queries = {
    'CobaltStrikeJARMfilter': f'DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP in {run_shodan_query_return_IP_filter("ssl.jarm:07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2")}',
    'CobaltStrikeProductName': f'DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP in {run_shodan_query_return_IP_filter("""product:"Cobalt Strike Beacon" """)}',
    'PoshC2': f'DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP in {run_shodan_query_return_IP_filter("""ssl:"P18055077" """)}',
    'EmpireC2': f'DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP in {run_shodan_query_return_IP_filter("""product:"Empire C2" """)}',
    'DeimosC2': f'DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP in {run_shodan_query_return_IP_filter("http.html_hash:-14029177")}',
    'Google': f'DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP in {run_shodan_query_return_IP_filter("ip:8.8.8.8")}'
}

#Authenticate to the MDE API.
aadToken = app_auth(Client_id,Client_secret,TenantId)

#Run the queries stored in the queries dict, one by one.
for a in queries:
    if queries[a].endswith(")"):
        df = exec_mtp_query(queries[a],aadToken)
        if df.empty == False:
            #write the results to a json file in the working directory.
            filename = a+".json"
            jsonfile=df.to_json(orient="split")
            with open(filename,'w') as f:
                f.write(jsonfile)
                f.close()
