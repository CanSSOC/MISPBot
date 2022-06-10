#!/usr/bin/python3
import logging
import os
import re
import yaml                  #pip install pyyaml
from pymisp import PyMISP    #pip install pymisp
import ast

from slack_bolt import App   #pip install slack-bolt
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_bolt.context import say

class MispConnection():
    host = None
    api_key = None
    verify_cert = None
    Misp = None
    
    def __init__(self, host, api_key, verify_cert):
        self.host = host
        self.api_key = api_key
        self.verify_cert = verify_cert
        
        self.Misp = PyMISP(self.host, self.api_key, self.verify_cert, 'json')
        
    def search(self, indicator, indicator_type):
        return(self.Misp.search(value=indicator, type_attribute=indicator_type, limit=11, published=True, to_ids=True, deleted=False, pythonify=True))

    def searchExtended(self, indicator, indicator_type):
        return(self.Misp.search(value=indicator, type_attribute=indicator_type, limit=11, pythonify=True))

class ConfigManager():
    data = None
    
    def __init__(self, configfile):
        self.data = yaml.safe_load(open(configfile,"r"))
        
    def getValue(self, key):
        if key in self.data.keys():
            return (self.data[key])
        else:
            return (None)

config = ConfigManager("./settings.yml")
app = App(token=config.getValue("SLACK_BOT_TOKEN"), name="MispBot")
misp = MispConnection(config.getValue("MISP_SERVER"),config.getValue("MISP_API_KEY"),config.getValue("MISP_VERIFY_CERT"))

match config.getValue("LogLevel").lower():
    case "debug":
        logging.basicConfig(level=logging.DEBUG)
    case "info":
        logging.basicConfig(level=logging.INFO)
    case "warning":
        logging.basicConfig(level=logging.WARNING)
    case "error":
        logging.basicConfig(level=logging.ERROR)
    case "fatal":
        logging.basicConfig(level=logging.FATAL)
    case "critical":
        logging.basicConfig(level=logging.CRITICAL)
        
logger = logging.getLogger(__name__)

def help_text():    
    return(
"""*MispBot Help*\n\n\n*/mispbot vs @mispbot*\n:black_small_square:`/mispbot` command and results are only viewable to user.\n:black_small_square:`@mispbot` command and results are visible to the entire channel.\n\nOtherwise, they work in exactly the same way:\n:black_small_square:`/mispbot <command> <IOC>`\n:black_small_square:`@mispbot <command> <IOC>`\n\n\n\n*Command: help*\nThe help command lists all MispBot commands with instructions.\n\nExample: `/mispbot help`\n\n\n\n*Command: searchip*\nThe searchip command accepts an IP address as an argument and returns a list of published events where the IP address is listed as an attribute with the IDS flag set to True.\n\nExample: `/mispbot searchip 93.184.216.34`\n\n\n\n*Command: searchipext*\nThe searchipext command accepts an IP address as an argument and returns a list of both published and unpublished events where the IP address is listed as an attribute (regardless of whether the IDS flag is true).\n\nExample: `/mispbot searchipext 93.184.216.34`\n\n\n\n*Command: searchdomain (coming soon)*\nThe searchdomain command accepts a domain as an argument and returns a list of published events where the domain is listed as an attribute with the IDS flag set to True.\n\nExample: `/mispbot searchdomain example.com`\n\n\n\n*Command: searchdomainext (coming soon)*\nThe searchdomainext command accepts a domain as an argument and returns a list of both published and unpublished events where the domain is listed as an attribute (regardless of whether the IDS flag is true).\n\nExample: `/mispbot searchdomainext example.com`\n\n\n\n*Command: reversedns (coming soon)*\nThe reversedns command accepts an IP address as an argument and returns the domain or, in the case of multiple domains due to shared hosting, it will return the original IP address.\n\nExample: `/mispbot reversedns 8.8.8.8`\n\n\n\n*Command: resolvedomain (coming soon)*\nThe resolvedomain command accepts a domain as an argument and returns the IP address.\n\nExample: `/mispbot resolvedomain google.com`"""
    )

def defang(indicator):
    return (indicator.replace(".", "[.]")).replace("://", "[://]")

def filter_attribute(attribute, indicator, attribute_types):
    # Determine if the indicator should be included, True/False
    if attribute['type'] not in attribute_types:
        return(False)
    if (attribute['value']!=indicator):
        return(False)
    
    return(True)

def misp_search_ip(indicator):
    attribute_types = ["ip-src","ip-dst"]
    result = misp.search(indicator, attribute_types)
    #logger.debug(result)
    
    return(render_results(result, indicator, attribute_types))
    
def misp_search_ip_ext(indicator):
    attribute_types = ["ip-src","ip-dst"]
    result = misp.searchExtended(indicator, attribute_types)
    #logger.debug(result)
    
    return(render_results(result, indicator, attribute_types))

def make_link_to_event(eventid):
    # TODO: Make sure that there's a trailing slash on the MISP_SERVER param
    return("<" + config.getValue("MISP_SERVER") + "events/view/" + str(eventid) + "|Event " + str(eventid) + ">")

def make_timestamp(ts):
    return("<!date^" + str(int(ts.timestamp())) + "^{date_num} {time}|timestamp>" )

def render_results(result_object, indicator, attribute_types):
    # Make sure that we have a list of results, otherwise error
    if (type(result_object)!=list):
        return("*Error parsing MISP results*")
    
    # Check if the results are empty
    if (len(result_object)==0):
        return("No results found")
    
    # Structure notes:
    # i['id'] => Event Id
    # i['info'] => Event Title
    # i['Attribute'] => List of attributes
    # i['Object']['Attribute'] => Object attributes
    #
    # Within attributes
    # 'comment' => comment
    # 'timestamp' => timestamp (since epoch)
    # 'to_ids' => ids
    # 'type' => attribute type
    # 'value' => the actual content of the attribute.

    # TODO: Make sure to filter the attributes
    
    # Generate output
    output="" 
    
    # Step through each event in the result
    for i in result_object:

        # Check the published flag for the event
        published_flag = "~Published~"
        if (i['published']==True):
            published_flag = "Published"
            
        output += "*" + make_link_to_event(i['id']) + ":black_small_square:" + published_flag + ":black_small_square:" + str(i['info']) + "*\n"
        
        # Step through each attribute in the root level
        for j in i['Attribute']:
            attribute_type = j['type']
            if attribute_type in attribute_types:
                ids_flag="~IDS~"
                if (j['to_ids']==True):
                    ids_flag="IDS"
                        
                del_flag=""
                if (j['deleted']==True):
                    del_flag=" DEL"

                if(filter_attribute(j, indicator, attribute_types)):
                    output += ":black_small_square:" + defang(j['value']) + ":white_small_square:" + j['type'] + ":white_small_square:" + ids_flag + del_flag + ":white_small_square:" + make_timestamp(j['timestamp']) + ":white_small_square:" + j['comment'] + "\n"
            
        
        # If there's a sub object, step into it and parse.
        if 'Object' in i.keys():
            
            # Step through each object in the event
            for j in i['Object']:
                object_header=False
                
                # Step through each attribute in the Object
                for k in j['Attribute']:
                    attribute_type = k['type']
                    if attribute_type in attribute_types:
                        
                        ids_flag="~IDS~"
                        if (k['to_ids']==True):
                            ids_flag="IDS"
                        
                        del_flag=""
                        if (k['deleted']==True):
                            del_flag=" DEL"

                        if(filter_attribute(k, indicator, attribute_types)):
                            # Print the object header if it hasn't already been printed.
                            if object_header==False:
                                output += "Object Name:white_small_square:" + j['name'] + "\n"
                                object_header=True
                                
                            output += ":black_small_square:" + defang(k['value']) + ":white_small_square:" + k['type'] + ":white_small_square:" + ids_flag + del_flag + ":white_small_square:" + make_timestamp(k['timestamp']) + ":white_small_square:" + k['comment'] + "\n"
                  

    return(output)

def test_output():
    return(
"""*MispBot Help*\n\n\n*/mispbot vs @mispbot*\n:black_small_square:`/mispbot` command and results are only viewable to user.\n:black_small_square:`@mispbot` command and results are visible to the entire channel.\n\nOtherwise, they work in exactly the same way:\n:black_small_square:`/mispbot <command> <IOC>`\n:black_small_square:`@mispbot <command> <IOC>`\n\n\n\n*Command: help*\nThe help command lists all MispBot commands with instructions.\n\nExample: `/mispbot help`\n\n\n\n*Command: searchip*\nThe searchip command accepts an IP address as an argument and returns a list of published events where the IP address is listed as an attribute with the IDS flag set to True.\n\nExample: `/mispbot searchip 93.184.216.34`\n\n\n\n*Command: searchipext*\nThe searchipext command accepts an IP address as an argument and returns a list of both published and unpublished events where the IP address is listed as an attribute (regardless of whether the IDS flag is true).\n\nExample: `/mispbot searchipext 93.184.216.34`\n\n\n\n*Command: searchdomain (coming soon)*\nThe searchdomain command accepts a domain as an argument and returns a list of published events where the domain is listed as an attribute with the IDS flag set to True.\n\nExample: `/mispbot searchdomain example.com`\n\n\n\n*Command: searchdomainext (coming soon)*\nThe searchdomainext command accepts a domain as an argument and returns a list of both published and unpublished events where the domain is listed as an attribute (regardless of whether the IDS flag is true).\n\nExample: `/mispbot searchdomainext example.com`\n\n\n\n*Command: reversedns (coming soon)*\nThe reversedns command accepts an IP address as an argument and returns the domain or, in the case of multiple domains due to shared hosting, it will return the original IP address.\n\nExample: `/mispbot reversedns 8.8.8.8`\n\n\n\n*Command: resolvedomain (coming soon)*\nThe resolvedomain command accepts a domain as an argument and returns the IP address.\n\nExample: `/mispbot resolvedomain google.com`"""
)

def process_request(request_text):
    
    # Strip any leading or trailing whitespace
    request_text = request_text.strip()
    
    # Assume we have a bare keyword with no args.
    keyword=request_text
    args=[]
    
    # Unless there's at least two tokens.  If so, split it.
    if " " in request_text:
        keyword,args = request_text.split(" ",1)
    
        # Create a list of arguments
        if " " in args:
            args = args.split(" ")
        else:
            args = [args]

    # Determine the response
    response_text = None
    missing_params=False
    match keyword.lower():
        case "help":
            response_text=help_text()
        case "searchip":
            if(len(args)>=1):
                response_text = "*Search results for: " + defang(request_text) + "*\n\n"
                response_text += misp_search_ip(args[0])
            else:
                missing_params=True
        case "searchipext":
            if(len(args)>=1):
                response_text = "*Search results for: " + defang(request_text) + "*\n\n"
                response_text += misp_search_ip_ext(args[0])
            else:
                missing_params=True            
        case "searchdomain":
            response_text="Search Domain is not implemented yet!"
        case "test":
            response_text=test_output()
        case _:
            response_text="*Error: Invalid command*\nCheck /mispbot help"

    # Check if we're missing parameters
    if (missing_params):
        response_text="*Error: Missing parameters*"
        
    return(response_text)
        
@app.event("message")
def handle_mention(ack, say, body):
    ack()
    logger.debug(body)
    
    # Preprocess the text, depending on the type of message
    preprocessed_text = body['event']['text']
    response = process_request(preprocessed_text)
    say(response)

@app.event("app_mention")
def handle_mention(ack, say, body):
    ack()
    logger.debug(body)
    
    # mentions will come through tagged with the mispbot's userid
    preprocessed_text = body['event']['text'].split(" ",1)[1]
    response = process_request(preprocessed_text)
    
    # Reply to the channel
    say(response)
    
    
@app.command("/mispbot")
def handle_command(ack, respond, body):
    """Receive a slash command"""
    ack()
    logger.debug(body)

    respond(process_request(body['text']))        

def main():

    handler = SocketModeHandler(app, config.getValue("SLACK_APP_TOKEN"))
    handler.start()


if __name__ == "__main__":
    main()
