def get_text_by_tag(start, tagname, default=None):
    """Returns a text node from a tag"""
    node_back = start.getElementsByTagName(tagname)[0]
    for node in node_back.childNodes:
        if node.nodeType == node.TEXT_NODE:
            return node.data

    return default


class PolicyParameters(dict):
    def __init__(self):
        super(PolicyParameters, self).__init__()
        self.max_hosts(80)

    def max_hosts(self, value):
        self["max_hosts"] = value

    def smb_credentials(self, username, password):
        self["Login configurations[entry]:SMB account :"] = username
        self["Login configurations[password]:SMB password :"] = password
        
    def ssh_credentials(self, username, password):
        self["SSH settings[entry]:SSH user name :"] = username
        self["SSH settings[password]:SSH password (unsafe!) :"] = password


class NessusPolicy(object):
    def __init__(self, id, name):
        self._id = id
        self._name = name

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self._name

    @staticmethod
    def from_node(self, node):
        policy_id = int(get_text_by_tag(node, 'policyID'))
        policy_name = get_text_by_tag(node, 'policyName')
        return NessusPolicy(policy_id, policy_name)


class NessusScan(object):
    def __init__(self, uuid, owner, start_time, name):
        self._uuid = uuid
        self._owner = owner
        self._start_time = start_time
        self._name = name

    @staticmethod
    def from_node(self, node):
        uuid = get_text_by_tag(node, 'uuid')
        owner = get_text_by_tag(node, 'owner')
        start_time = get_text_by_tag(node, 'start_time')
        scan_name = get_text_by_tag(node, 'scan_name')

        return NessusScan(uuid, owner, start_time, scan_name)
