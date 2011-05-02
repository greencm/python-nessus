from nessus import PolicyParameters


class TestPolicyParameters(object):
    def test_init(self):
        params = PolicyParameters()
        assert params['max_hosts'] == 80

    def test_ssh(self):
        params = PolicyParameters()
        params.ssh_credentials('ahall', 'temp123')
        assert params['SSH settings[entry]:SSH user name :'] == 'ahall'
        assert params['SSH settings[password]:SSH password (unsafe!) :'] == 'temp123'
        
    def test_smb(self):
        params = PolicyParameters()
        params.smb_credentials('ahall2', 'temp1234')
        assert params['Login configurations[entry]:SMB account :'] == 'ahall2'
        assert params['Login configurations[password]:SMB password :'] == 'temp1234'


class TestNessusConnection(object):
    def test_list_policies(self):
        assert True
