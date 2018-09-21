import requests
import logging
import base64
import datetime
import dateutil.parser
import json

from xml.dom import minidom
from requests.exceptions import RequestException

logger = logging.getLogger('LithiumRestV1Client')


class LithiumRestV1Client(object):

    def __init__(self, community_id, login, password, path, page_size):
        self.community_id = community_id
        self.login = login
        self.password = password
        self.path = path
        self.page_size = page_size
        self.session_key = self.get_session_key()

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
            return r.text
        else:
            raise RequestException('Status code is {status_code}.Response is {response}'.format(
                status_code=str(r.status_code),
                response=r.text))

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

# function to build request headers
    def build_headers(self):
        headers = {}
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

# function to get batch
    def get_page(self, page):
        headers = self.build_headers()
        resp = self.get('https://{community_id}/restapi/vc/{path}?restapi.session_key={session_key}&restapi.response_format=json&api.pretty_print=true&page_size={page_size}&page={page}'.format(
          community_id=self.community_id,
          path=self.path,
          session_key=self.session_key,
          page_size=self.page_size,
          page=page), headers)
        return resp
