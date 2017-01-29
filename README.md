# ADWrapper
A simple wrapper for common Active Directory tasks, because I am eternally forgetful. 
Requires [python-ldap](https://www.python-ldap.org/).

## Installation

adwrapper is available through PyPi:

`pip install adwrapper`

## Usage

Running `help(ADWrapper)` in the REPL should return enough useful information to get going. 
For example, creating a new user and adding, then removing, them from a group:

```python
from adwrapper import ADWrapper
adw = ADWrapper(uri='ldap://localhost', who='CN=administrator,dc=test,dc=com', cred='password')
newuser = 'cn=new user,ou=users,dc=test,dc=com'
testgroup = 'ou=test,dc=test,dc=com'
adw.create_new_user(dn='cn=new user,ou=users,dc=test,dc=com', sam='newuser', firstname='New',
                    surname='User', email='newuser@example.com', principalname='newuser@test.com')
adw.enable_account(newuser)
print(adw.get_user_by_samaccountname(base='ou=users,dc=test,dc=com', sam='newuser', attrlist=['mail', 'memberOf']))
adw.add_member_to_group(memberdn=newuser, groupdn=testgroup)
print(adw.get_members_of_group(testgroup))
adw.remove_member_from_group(memberdn=newuser, groupdn=testgroup)
```

