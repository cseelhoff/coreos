run these on openldap container:

ldapmodify -H ldapi:/// -Y EXTERNAL <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * break
olcAccess: {1}to attrs=userPassword,shadowLastChange by self write by dn="cn=admin,dc=177cpt,dc=com" write by anonymous auth by * none
olcAccess: {2}to * by self read by dn="cn=admin,dc=177cpt,dc=com" write by group="cn=ldap_readers,ou=Groups,dc=177cpt,dc=com" read by * none
EOF

ldapmodify -H ldapi:/// -Y EXTERNAL <<EOF
dn: cn=vcadmins,ou=Groups,dc=177cpt,dc=com
objectclass: groupOfUniqueNames
cn: vcadmins
uniquemember: cn=frank.fleming,ou=Users,dc=177cpt,dc=com
EOF
