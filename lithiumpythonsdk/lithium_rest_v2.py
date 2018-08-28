import requests
import logging
import base64
import datetime
import dateutil.parser
import json

from xml.dom import minidom
from requests.exceptions import RequestException

logger = logging.getLogger('LithiumRestV2Client')


class LithiumRestV2Client(object):

    def __init__(self, community_id, client_id, login, password, object, query, batch_size):
        self.login = login
        self.password = password
        self.community_id = community_id
        self.client_id = client_id
        self.object = object
        self.query = query
        self.batch_size = batch_size

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

# post request
    def post(self, url, headers):
        r = self.make_request(**dict(
            method='POST',
            url=url,
            headers=headers
        ))
        if r.status_code == 200:
            return r
        else:
            raise RequestException('Status code is {status_code}.Response is {response}'.format(
                status_code=str(r.status_code),
                response=r.text))

# get request
    def get(self, url, headers):
        r = self.make_request(**dict(
            method='GET',
            url=url,
            headers=headers
        ))
        if r.status_code == 200:
            return r.json()
        else:
            raise RequestException('Status code is {status_code}.Response is {response}'.format(
                status_code=str(r.status_code),
                response=r.text))

# function to build request headers
    def build_headers(self):
        headers = {
            'client-id': "{client_id}".format(client_id=self.client_id)
        }
        return headers

# function to get session key
    def get_session_key(self):
        resp = self.post('https://{community_id}/restapi/vc/authentication/sessions/login?user.login={login}&user.password={password}'.format(
          community_id=self.community_id,
          login=self.login,
          password=self.password), '')
        xml = minidom.parseString(resp.text)
        keylist = xml.getElementsByTagName('value')
        return keylist[0].firstChild.nodeValue

# function to get count
    def get_count(self):
        headers = self.build_headers()
        query = 'SELECT+count(*)+FROM+{object}'.format(object=self.object)
        resp = self.get('https://{community_id}/api/2.0/search?q={query}&restapi.session_key={sessionkey}&api.pretty_print=true'.format(
          community_id=self.community_id,
          query=query,
          sessionkey=self.get_session_key()), headers)
        count = resp["data"]["count"]
        return count

# function to get batch
    def get_batch(self, offset):
        headers = self.build_headers()
        query = query + '+LIMIT+{limit}+OFFSET+{offset}'.format(
            limit=self.batch_size,
            offset=offset)
        resp = self.get('https://{community_id}/api/2.0/search?q={query}&restapi.session_key={sessionkey}&api.pretty_print=true'.format(
          community_id=self.community_id,
          query=query,
          sessionkey=self.get_session_key()), headers)
        return resp
