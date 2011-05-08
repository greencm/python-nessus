import nessus
import os.path
from mock import patch
from tempfile import NamedTemporaryFile

TEST_FILES = os.path.join(os.path.dirname(__file__), "testfiles")
TEST_AREA = os.path.join(os.path.dirname(__file__), "testarea")


class TestPolicyParameters(object):
    def test_init(self):
        params = nessus.PolicyParameters()
        assert params['max_hosts'] == 80

    def test_ssh(self):
        params = nessus.PolicyParameters()
        params.ssh_credentials('ahall', 'temp123')
        assert params['SSH settings[entry]:SSH user name :'] == 'ahall'
        assert params['SSH settings[password]:SSH password (unsafe!) :'] \
                == 'temp123'

    def test_smb(self):
        params = nessus.PolicyParameters()
        params.smb_credentials('ahall2', 'temp1234')
        assert params['Login configurations[entry]:SMB account :'] == 'ahall2'
        assert params['Login configurations[password]:SMB password :'] \
                == 'temp1234'


class TestNessusConnection(object):
    def _get_conn(self):
        return nessus.NessusConnection('ahall', 'temp123')

    @staticmethod
    def _fake_method(url, params):
        filename = ""

        if url.endswith('/login'):
            filename = "login.xml"
        elif url.endswith('/policy/list'):
            filename = "policy_list.xml"
        elif url.endswith('/policy/add'):
            filename = "policy_add.xml"
        elif url.endswith('/policy/delete'):
            filename = "policy_delete.xml"
        elif url.endswith('/scan/new'):
            filename = "scan_new.xml"
        elif url.endswith('/report/list'):
            filename = "report_list.xml"
        elif url.endswith('/file/report/download'):
            filename = "report_download.nessus"
        else:
            assert False

        return open(os.path.join(TEST_FILES, filename))

    @patch('nessus.common.urlopen')
    def test_list_policies(self, urlopen):
        urlopen.side_effect = self._fake_method

        conn = self._get_conn()
        policies = conn.list_policies()
        assert len(policies) == 8

    @patch('nessus.common.urlopen')
    def test_create_policy(self, urlopen):
        urlopen.side_effect = self._fake_method

        conn = self._get_conn()
        policy = conn.create_policy("new policy")
        assert policy.name == "new policy"

    @patch('nessus.common.urlopen')
    def test_delete_policy(self, urlopen):
        urlopen.side_effect = self._fake_method

        conn = self._get_conn()
        conn.delete_policy(9, "new policy")

    @patch('nessus.common.urlopen')
    def test_create_scan(self, urlopen):
        urlopen.side_effect = self._fake_method

        conn = self._get_conn()
        scan = conn.create_scan(9, "new scan", ["127.0.0.1"])
        assert scan.uuid == ("73f8bc9c-e5fb-0687-d483-"
                             "baa215ab1b577e350d022c048ff4")
        assert scan.owner == "ahall"
        assert scan.start_time == "1304807861"

    @patch('nessus.common.urlopen')
    def test_list_reports(self, urlopen):
        urlopen.side_effect = self._fake_method

        conn = self._get_conn()
        reports = conn.list_reports()
        assert len(reports) == 5
        completed = [x for x in reports if x.status == x.STATUS_COMPLETE]
        assert len(completed) == 2
        running = [x for x in reports if x.status == x.STATUS_RUNNING]
        assert len(running) == 3

    @patch('nessus.common.urlopen')
    def test_download_report(self, urlopen):
        urlopen.side_effect = self._fake_method

        conn = self._get_conn()

        with NamedTemporaryFile(dir=TEST_AREA) as np:
            conn.download_report("test", np)
            np.seek(0)
            comp_file = os.path.join(TEST_FILES, "report_download.nessus")
            assert np.read() == open(comp_file).read()
