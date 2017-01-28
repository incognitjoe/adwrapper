import unittest

import fakeldap
import ldap
from mock import patch

from adwrapper import ADWrapper


class TestADWrapper(unittest.TestCase):
    tree = {
        'ou=users,dc=test,dc=com': {
            'ou': ['users']
        },
        'cn=joe butler,ou=users,dc=test=dc=com': {
            'cn': ['joe butler'],
            'sAMAccountName': 'incognitjoe'
        },
        "ou=test,dc=test,dc=com": {
            "member": ["cn=joe butler,ou=users,dc=test,dc=com"]
        }
    }
    _mock_ldap = fakeldap.MockLDAP(tree)
    fakeldap.ldap = ldap

    @classmethod
    def setUpClass(cls):
        cls.ldap_patcher = patch('adwrapper.ldap.initialize')
        cls.mock_ldap = cls.ldap_patcher.start()
        cls.mock_ldap.return_value = cls._mock_ldap
        cls.ad = ADWrapper(uri='ldap://localhost', who='', cred='')

    def test_get_members_of_group(self):
        result = self.ad.get_members_of_group(group='ou=test,dc=test,dc=com')
        assert result == ['cn=joe butler,ou=users,dc=test,dc=com'], result

    # FIXME: fakeldap doesn't work with these methods but a live AD server does.
    # Should probably write my own fixture that can deal with scopes and modify_s correctly.
    #
    # def test_add_member_to_group(self):
    #     add = self.ad.add_member_to_group(memberdn='cn=new user,ou=users,dc=test,dc=com',
    #                                       groupdn='ou=test,dc=test,dc=com')
    #     assert add is True, add
    #
    # def test_remove_member_from_group(self):
    #     rem = self.ad.remove_member_from_group(memberdn='cn=joe butler,ou=users,dc=test,dc=com',
    #                                       groupdn='ou=test,dc=test,dc=com')
    #     assert rem is True, rem
    #
    # def test_get_user_by_samaccountname(self):
    #     result = self.ad.get_user_by_samaccountname(base='ou=users,dc=test,dc=com',
    #                                       sam='incognitjoe', attrlist=['cn'])
    #     assert result == ('cn=joe butler,ou=users,dc=test=dc=com', {'cn': ['joe butler']}), result

    def tearDown(self):
        self._mock_ldap.reset()
        self.mock_ldap.stop()
