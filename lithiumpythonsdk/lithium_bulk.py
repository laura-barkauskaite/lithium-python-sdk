import requests
import logging
import base64
import datetime
import dateutil.parser

from requests.exceptions import RequestException

logger = logging.getLogger('LithiumBulkClient')
BULK_URL = 'https://eu.api.lithium.com/lsi-data/v1/data/export/community'


class LithiumBulkClient(object):

    def __init__(self, community_id, client_id, token):
        self.format = 'text/csv'
        self.community_id = community_id
        self.client_id = client_id
        self.token = token

# function to build request headers
    def buildHeaders(self):
        authorization_string = self.basicAuthorizationSting()
        headers = {
            'client_id': "{client_id}".format(client_id=self.client_id),
            'Accept': "{format}".format(format=self.format),
            'Authorization': "{authorization_string}".format(
                authorization_string=authorization_string)
        }
        return headers

# function to build basic authorization string
    def basicAuthorizationSting(self):
        token_bytes = "{token}:".format(token=self.token).encode("ascii")
        token_base64 = base64.b64encode(token_bytes)
        authorization_string = "Basic {token_base64}".format(
            token_base64=token_base64.decode("ascii"))
        return authorization_string

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
            return r.json()
        else:
            raise RequestException(('Status code is {status_code}.'
                                    'Response is {response}').format(
                status_code=str(r.status_code), response=r.text))

# function to check and format dates
    def valid_dates(self, start_date, end_date):

        try:
            start_date = dateutil.parser.parse(start_date)
        except ValueError as e:
            raise ValueError(
                "Can't parse start_date={start_date} to date format").format(
                start_date=start_date)
        try:
            end_date = dateutil.parser.parse(end_date)
        except ValueError as e:
            raise ValueError(
                "Can't parse end_date={end_date} to date format".format(
                 end_date=end_date))

        self.valid_interval(start_date, end_date)
        start_date = start_date.strftime("%Y%m%d%H%M")
        end_date = end_date.strftime("%Y%m%d%H%M")
        return start_date, end_date

# function to check if date interval is valid
    def valid_interval(self, start_date, end_date):
        if end_date <= start_date:
            raise ValueError("End date has to be grater than start date")
        if end_date > datetime.datetime.now():
            raise ValueError("End date has to be less or equal to today")
        if end_date > start_date + datetime.timedelta(7):
            raise ValueError(
                "Maximum of 7 days may be fetched with a single request")

# function to build request parameterstring
    def buildRequestParameterString(self, start_date, end_date, field_list):
        field_str = ','.join(field_list)
        parurl = ""
        if (start_date is not None and
            end_date is not None and 
            field_list is not None):
            parurl = ('?fromDate={start_date}&'
                     'toDate={end_date}&'
                     'fields={fields}').format(
                     start_date=start_date, 
                     end_date=end_date, 
                     fields=field_str)
        return parurl

# main function to get specified data of specified date interval in
# specified format
    def getData(
        self, 
        start_date, 
        end_date, 
        mime_type="text/csv", 
        field_list=[]):

        start_date, end_date = self.valid_dates(start_date, end_date)
        self.format = mime_type
        headers = self.buildHeaders()
        param = self.buildRequestParameterString(
            start_date, end_date, field_list)
        resp = self.get('{bulk_url}/{community_id}{param}'.format(
            bulk_url=BULK_URL,community_id=self.community_id, param=param)
        ,headers)
        return resp
