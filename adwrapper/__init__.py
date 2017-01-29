import logging
import sys

import ldap


class ADWrapper(object):
    con = None

    def __init__(self, uri, who, cred, strictssl=True):
        """
        Initialize LDAP connection to target Active Directory instance
        :param uri: LDAP URI to connect to, e.g. 'ldap://localhost'
        :param who: distinguishedName of user to bind as, e.g. 'cn=administrator,dc=example,dc=com'
        :param cred: password for the given user account
        :param strictssl: True by default. If False, disable certification verification over LDAPS. Do not
                            use this unless you're sure you understand the risks.
        """
        if not strictssl:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
        self.bind(uri=uri, who=who, cred=cred)
        self._set_logging()

    def bind(self, uri, who, cred):
        """
        Bind to target URI with given credentials
        :param uri: LDAP URI to connect to, e.g. 'ldap://localhost'
        :param who: distinguishedName of user to bind as, e.g. 'cn=administrator,dc=example,dc=com'
        :param cred: password for the given user account:param cred: 
        """
        self.con = ldap.initialize(uri=uri)
        self.con.simple_bind_s(who=who, cred=cred)

    def _set_logging(self):
        logger = logging.getLogger('ADWrapper')
        logger.setLevel(logging.INFO)
        if not len(logger.handlers):
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('[ %(asctime)s ] %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        self.logger = logger

    def _search_subtree_for_multiple_results(self, base, filterstr='(objectClass=*)', attrlist=None):
        return self.con.search_s(base=base, scope=ldap.SCOPE_SUBTREE, filterstr=filterstr, attrlist=attrlist)

    def _search_subordinates_for_multiple_results(self, base, filterstr='(objectClass=*)', attrlist=None):
        return self.con.search_s(base=base, scope=ldap.SCOPE_ONELEVEL, filterstr=filterstr, attrlist=attrlist)

    def _search_base(self, base, attrlist=None):
        result = self.con.search_s(base=base, scope=ldap.SCOPE_BASE, attrlist=attrlist)
        return self._get_first_result(result)

    @staticmethod
    def _get_first_result(results):
        if not results:
            return None
        return results[0]

    @staticmethod
    def _get_add_dn_to_member_command(dn):
        return [(ldap.MOD_ADD, 'member', dn)]

    @staticmethod
    def _get_remove_dn_from_member_command(dn):
        return [(ldap.MOD_DELETE, 'member', dn)]

    def get_user_by_samaccountname(self, base, sam, attrlist=None):
        """
        Search given base OU for matching sAMAccountName.
        :param base: base DN to search, e.g. OU=Users,DC=example,DC=com
        :param sam: sAMAccountName to match
        :param attrlist: list of desired attributes, e.g. ['sAMAccountName', 'mail', 'memberOf']. None returns all.
        :return: Tuple of (distinguishedName, user attributes) or None
        """
        filterstr = '(sAMAccountName={sam})'.format(sam=sam)
        return self.search_subtree(base=base, filterstr=filterstr, attrlist=attrlist, first=True)

    def get_user_by_common_name(self, base, cn, attrlist=None):
        """
        Search given base OU for matching Common Name, e.g. Joe Butler
        :param base: base DN to search
        :param cn: Common Name to match
        :param attrlist: list of desired attributes, e.g. ['sAMAccountName', 'mail', 'memberOf']. None returns all.
        :return: Tuple of (distinguishedName, user attributes) or None
        """
        filterstr = '(cn={cn})'.format(cn=cn)
        return self.search_subtree(base=base, filterstr=filterstr, attrlist=attrlist, first=True)

    def get_attributes_for_distinguished_name(self, dn, attrlist=None):
        """
        Get attributes for a full DN, e.g. 'cn=joe butler,ou=users,dc=example,dc=com'
        :param dn: DN to return
        :param attrlist: list of desired attributes, e.g. ['sAMAccountName', 'mail', 'memberOf']. None returns all.
        :return: Tuple of (distinguishedName, attributes) or None
        """
        return self._search_base(base=dn, attrlist=attrlist)

    def get_members_of_group(self, group):
        """
        Return members of given group distinguishedName
        :param group: group DN, e.g. 'ou=mygroup,dc=example,dc=com'
        :return: List of distinguishedNames of members
        """
        result = self.get_attributes_for_distinguished_name(group, attrlist=['member'])
        if not result:
            return result
        return result[1].get('member')

    def add_member_to_group(self, memberdn, groupdn):
        """
        Add a member to a group
        :param memberdn: full distinguishedName of member to add
        :param groupdn: target group distinguishedName
        :return: True on success, False if member already exists
        """
        addcmd = self._get_add_dn_to_member_command(memberdn)
        try:
            self.con.modify_s(groupdn, addcmd)
            self.logger.info('Added {} to {}.'.format(memberdn, groupdn))
            return True
        except ldap.ALREADY_EXISTS as err:
            self.logger.info(err)
            return False

    def remove_member_from_group(self, memberdn, groupdn):
        """
        Remove a member from a group
        :param memberdn: full distinguishedName of member to remove
        :param groupdn: target group distinguishedName
        :return: True on success, False if user not present in group _or_
                    bind user's credentials are not sufficient to remove.
        """
        remcmd = self._get_remove_dn_from_member_command(memberdn)
        try:
            self.con.modify_s(groupdn, remcmd)
            self.logger.info('Removed {} from {}.'.format(memberdn, groupdn))
            return True
        except ldap.UNWILLING_TO_PERFORM as err:
            self.logger.info(err)
            return False

    def create_new_entry(self, dn, attrs):
        """
        Create a new LDAP object with the distinguishedName and attributes provided
        :param dn: full DN of target object, e.g. 'cn=new user,ou=users,dc=example,dc=com'
        :param attrs: attributes as dict, e.g. {'cn': 'new user', 'mail': 'new@example.com'}
        :return: True on success
        """
        self.con.add_s(dn, attrs.items())
        return True

    @staticmethod
    def _encode_ad_password(password):
        return unicode('\"{}\"'.format(password), 'iso-8859-1').encode('utf-16-le')

    def enable_account(self, dn):
        """
        Enable a user account.
        :param dn: distinguishedName of user
        :return: True on success, False on failure
        """
        try:
            enablecmd = [(ldap.MOD_REPLACE, 'userAccountControl', '512')]
            self.con.modify_s(dn, enablecmd)
            self.logger.info('Enabled {}.'.format(dn))
            return True
        except ldap.UNWILLING_TO_PERFORM as err:
            self.logger.warning('Enabling {} failed: {}'.format(dn, repr(err)))
            self.logger.warning('Account password may not meet domain policy set.')
            return False

    def disable_account(self, dn):
        """
        Disable user account.
        :param dn: distinguishedName of user
        :return: True on success, False on failure
        """
        try:
            disablecmd = [(ldap.MOD_REPLACE, 'userAccountControl', '514')]
            self.con.modify_s(dn, disablecmd)
            self.logger.info('Disabled {}.'.format(dn))
            return True
        except ldap.UNWILLING_TO_PERFORM as err:
            self.logger.warning('Disabling {} failed: {}'.format(dn, repr(err)))
            return False

    def create_new_user(self, dn, sam, principalname, firstname, surname, email,
                        password='CHANGEME1!', mustchangepass=False):
        """
        Create a new user account.
        :param dn: distinguishedName of new user, e.g. 'cn=new user,ou=users,dc=example,dc=com'
        :param sam: sAMAccountName
        :param principalname: userPrincipalName, aka User Logon Name
        :param firstname: User's firstname
        :param surname: User's surname
        :param password: password to set
        :param mustchangepass: Force user to change password on next logon
        :return: True on success, False on failure
        """
        userobjlist = ['organizationalPerson', 'person', 'top', 'user']
        if mustchangepass:
            pwdset = '0'
        else:
            pwdset = '-1'
        displayname = '{} {}'.format(firstname, surname)
        attrs = self._build_user_attrib_dict(sAMAccountName=sam, userPrincipalName=principalname,
                                             displayName=displayname, givenName=firstname, sn=surname,
                                             objectClass=userobjlist, mail=email, pwdLastSet=pwdset,
                                             unicodePwd=self._encode_ad_password(password))
        try:
            self.logger.info('Creating {} with attributes {}'.format(dn, attrs))
            self.create_new_entry(dn, attrs)
            return True
        except ldap.ALREADY_EXISTS as err:
            self.logger.warning('{} could not be created: {}'.format(dn, repr(err)))
            return False

    @staticmethod
    def _build_user_attrib_dict(**kwargs):
        return kwargs

    def search_subordinates(self, base, filterstr='(objectClass=*)', attrlist=None, first=False):
        """
        Search a DN's direct subordinates.
        :param base: distinguishedName to search
        :param filterstr: LDAP filter string
        :param attrlist: list of desired attributes, e.g. ['sAMAccountName', 'mail', 'memberOf']. None returns all.
        :param first: if True, return only first result
        :return: list of result tuples, or result tuple if first is True
        """
        results = self._search_subordinates_for_multiple_results(base=base, filterstr=filterstr, attrlist=attrlist)
        if first:
            return self._get_first_result(results)
        return results

    def search_subtree(self, base, filterstr='(objectClass=*)', attrlist=None, first=False):
        """
        Search DN's entire subtree.
        :param base: distinguishedName to search
        :param filterstr: LDAP filter string
        :param attrlist: list of desired attributes, e.g. ['sAMAccountName', 'mail', 'memberOf']. None returns all.
        :param first: if True, return only first result
        :return: list of result tuples, or result tuple if first is True
        """
        results = self._search_subtree_for_multiple_results(base=base, filterstr=filterstr, attrlist=attrlist)
        if first:
            return self._get_first_result(results)
        return results
