from urllib import urlencode
from urllib2 import urlopen
from xml.dom.minidom import parse as parse_xml
from .utils import get_text_by_tag, PolicyParameters, NessusPolicy, NessusScan


class NessusConnection(object):
    def __init__(self, username, password, url='https://localhost:8834'):
        self._username = username
        self._password = password
        self._url = url
        self._authenticated = False
        self._token = None

    def _get_reply(self, url, params={}):
        params['token'] = self._token

        f = urlopen(url, urlencode(params))
        dom = parse_xml(f)
        reply = dom.getElementsByTagName('reply')[0]
        status = get_text_by_tag(reply, 'status')
        if status != 'OK':
            raise Exception("Authentication failure")

        return reply

    def _authenticate(self):
        url = self._url + "/login"
        params = dict(login=self._username, password=self._password)
        reply = self._get_reply(url, params)
        self._token = get_text_by_tag(reply, 'token')
        self._authenticated = True

    def list_policies(self):
        """Lists all policies"""
        if not self._authenticated: self._authenticate()

        policies = [] 

        url = self._url + "/policy/list"
        reply = self._get_reply(url)
        node_policies = reply.getElementsByTagName("policy")
        for node_policy in node_policies:
            policy_id = int(get_text_by_tag(node_policy, 'policyID'))
            policy_name = get_text_by_tag(node_policy, 'policyName')
            policies.append(dict(policy_id=policy_id, policy_name=policy_name))
        
        return policies

    def create_policy(self, policy_name, policy_parameters=PolicyParameters()):
        """Creates a nessus policy with a given name"""
        if not self._authenticated: self._authenticate()

        url = self._url + "/policy/add"
        params = dict(policy_id=0, policy_name=policy_name, **policy_parameters)
        reply = self._get_reply(url, params)

        node_policy = reply.getElementsByTagName("policy")[0]
        return NessusPolicy.from_node(node_policy)

    def delete_policy(self, policy_id, policy_name):
        """Deletes a particular policy"""
        if not self._authenticated: self._authenticate()

        url = self._url + "/policy/delete"
        params = dict(policy_id=policy_id, policy_name=policy_name)
        self._get_reply(url, params)

    def create_scan(self, policy_id, scan_name, targets):
        if not self._authenticated: self._authenticate()

        url = self._url + "/scan/new"
        params = dict(policy_id=policy_id, scan_name=scan_name,
                      target=",".join(targets))
        reply = self._get_reply(url, params)

        node_scan = reply.getElementsByTagName("scan")[0]
        return NessusScan.from_node(node_scan)

    def list_reports(self):
        url = self._url + "/report/list"

    def download_report(self, report_name, fp):
        url = self._url + "/file/report/download"
