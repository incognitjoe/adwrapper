import logging
import sys

import ldap


class ADWrapper(object):
    def __init__(self, uri, who, cred):
        """
        Initialize LDAP connection to target Active Directory instance
        :param uri: LDAP URI to connect to, e.g. 'ldap://localhost'
        :param who: distinguishedName of user to bind as, e.g. 'cn=administrator,dc=example,dc=com'
        :param cred: password for the given user account
        """
        self.con = ldap.initialize(uri=uri)
        self.con.simple_bind_s(who=who, cred=cred)
        self._set_logging()

    def _set_logging(self):
        logger = logging.getLogger('ADWrapper')
        logger.setLevel(logging.INFO)
        if not len(logger.handlers):
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('[ %(asctime)s ] %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        self.logger = logger

    def _search_subtree_for_single_result(self, base, filterstr, attrlist=None):
        results = self._search_subtree_for_multiple_results(base=base, filterstr=filterstr, attrlist=attrlist)
        if not results:
            return None
        return results[0]

    def _search_subtree_for_multiple_results(self, base, filterstr, attrlist=None):
        return self.con.search_s(base=base, scope=ldap.SCOPE_SUBTREE, filterstr=filterstr, attrlist=attrlist)

    def _search_one_level_for_multiple_results(self, base, attrlist=None):
        return self.con.search_s(base=base, scope=ldap.SCOPE_ONELEVEL, attrlist=attrlist)

    def _search_base(self, base, attrlist=None):
        result = self.con.search_s(base=base, scope=ldap.SCOPE_BASE, attrlist=attrlist)
        if not result:
            return result
        return result[0]

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
        filterstr = '(&(sAMAccountName={sam})(objectClass=person))'.format(sam=sam)
        return self._search_subtree_for_single_result(base=base, filterstr=filterstr, attrlist=attrlist)

    def get_user_by_common_name(self, base, cn, attrlist=None):
        """
        Search given base OU for matching Common Name, e.g. Joe Butler
        :param base: base DN to search
        :param cn: Common Name to match
        :param attrlist: list of desired attributes, e.g. ['sAMAccountName', 'mail', 'memberOf']. None returns all.
        :return: Tuple of (distinguishedName, user attributes) or None
        """
        filterstr = '(&(cn={cn}))'.format(cn=cn)
        return self._search_subtree_for_single_result(base=base, filterstr=filterstr, attrlist=attrlist)

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
        result = self._search_base(base=group, attrlist=['member'])
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
            print(err)
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
            print(err)
            return False
