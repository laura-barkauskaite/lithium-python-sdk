import requests
import logging
import base64
import datetime
import dateutil.parser
from xml.dom import minidom
import json

from requests.exceptions import RequestException

logger = logging.getLogger('LithiumRestClient')

class LithiumRestClient(object):

    def __init__(self, community_id,client_id,login, password,object,batch_size):
        self.login = login
        self.password = password
        self.community_id = community_id
        self.client_id = client_id
        self.sessionkey = ''
        self.batch_size = batch_size
        self.object = object

# function to make get/post request
    def make_request(self, **kwargs):
        logger.info(u'{method} Request: {url}'.format(**kwargs))
        if kwargs.get('json'):
            logger.info('payload: {json}'.format(**kwargs))
        resp = requests.request(**kwargs)
        if resp.status_code == 200:
            text = ''
        else:
            text = resp.text
        logger.info(u'{method} response: {status} {text}'.format(
                    method=kwargs['method'],
                    status=resp.status_code,
                    text=text))
        return resp

# get request
    def get(self, url, headers):
        r = self.make_request(**dict(
            method='GET',
            url=url,
            headers=headers
        ))
        if r.status_code == 200:
            return r
        else:
            raise RequestException(('Status code is {status_code}.'
                                    'Response is {response}').format(
                status_code=str(r.status_code), response=r.text))

# get request
    def post(self, url, headers):
        r = self.make_request(**dict(
            method='POST',
            url=url,
            headers=headers
        ))
        if r.status_code == 200:
            return r
        else:
            raise RequestException(('Status code is {status_code}.'
                                    'Response is {response}').format(
                status_code=str(r.status_code), response=r.text))

 # function to build request headers
    def build_headers(self):
        headers = {
            'client-id': "{client_id}".format(client_id=self.client_id)
        }
        return headers

# function to get session key
    def get_session_key(self):
        resp = self.post('https://{community_id}/restapi/vc/authentication/sessions/login?user.login={login}&user.password={password}'.format(
        	community_id=self.community_id,login=self.login,password=self.password),'')

        xml = minidom.parseString(resp.text)
        keylist = xml.getElementsByTagName('value')
        self.sessionkey = keylist[0].firstChild.nodeValue

        return self.sessionkey

# function to get count
    def get_count(self):
        headers = self.build_headers()
        query = 'SELECT+count(*)+FROM+{object}'.format(object = self.object)
        sessionkey = self.get_session_key()
        self.sessionkey = sessionkey
        resp = self.get('https://{community_id}/api/2.0/search?q={query}&restapi.session_key={sessionkey}&api.pretty_print=true'.format(
            community_id = self.community_id,query = query,sessionkey=sessionkey)
        ,headers)
        respjson = json.loads(resp.text)
        count  = respjson["data"]["count"]
        return count

# function to get batch
    def get_batch(self,offset):
        headers = self.build_headers()
        query = 'SELECT+*+FROM+{object}+LIMIT+{limit}+OFFSET+{offset}'.format(object = self.object,limit = self.batch_size, offset = offset)
        sessionkey = self.get_session_key()
        resp = self.get('https://{community_id}/api/2.0/search?q={query}&restapi.session_key={sessionkey}&api.pretty_print=true'.format(
            community_id = self.community_id,query = query,sessionkey=sessionkey)
        ,headers)
        return resp.text
