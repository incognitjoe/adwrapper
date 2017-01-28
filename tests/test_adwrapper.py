import unittest

import fakeldap
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

    def setUp(self):
        self.ldap_patcher = patch('adwrapper.ldap.initialize')
        self.mock_ldap_object = fakeldap.MockLDAP(self.tree)
        self.mock_ldap = self.ldap_patcher.start()
        self.mock_ldap.return_value = self.mock_ldap_object
        self.ad = ADWrapper(uri='ldap://localhost', who='', cred='')

    def test_get_members_of_group(self):
        result = self.ad.get_members_of_group(group='ou=test,dc=test,dc=com')
        assert result == ['cn=joe butler,ou=users,dc=test,dc=com'], result

    def test_create_new_entry(self):
        testdn = 'cn=new group,ou=groups,dc=test,dc=com'
        attrs = {'ou': 'new group'}
        self.ad.create_new_entry(dn=testdn, attrs=attrs)
        calls = self.mock_ldap_object.ldap_methods_called_with_arguments()
        self.assertTupleEqual(('add_s', {'dn': testdn, 'record': attrs.items()}), calls[1])

    def test_add_new_user(self):
        create = self.ad.create_new_user(dn='cn=new user,ou=users,dc=test,dc=com', sam='newuser', firstname='New',
                                         surname='User', email='newuser@example.com', principalname='newuser@test.com')
        assert create is True, 'Account creation failed.'

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
    #     assert result == ('cn=joe butler,ou=users,dc=test,dc=com', {'cn': ['joe butler']}), result

    def tearDown(self):
        self.mock_ldap_object.reset()
        self.mock_ldap.stop()
