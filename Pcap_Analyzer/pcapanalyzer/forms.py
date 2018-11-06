from django import forms

class Protocolform(forms.Form):
    OPTIONS = ( 
                       ("00", "ALL"),
                       ("21","FTP"),
                        ("22","SSH"),
                       ("23","TELNET"),
                       ("25","SMTP"),
                       ("49","TACACS"),
                       ("67","DHCP Bootpc"),
                       ("68","DHCP Bootps"),
                       ("80","HTTP"),
                       ("88","Kerberos"),
                       ("137","NetBIOS Name Service NBNS"),
                       ("138","NetBios Datagram Service NBDS"),
                       ("156","SQL Service"),
                       ("161","SNMP"),
                       ("162","SNMP Trap"),
                       ("179","BGP"),
                       ("389","LDAP"),
                       ("443","HTTPS"),
                       ("445","SMB"),
                       ("520","RIP"),
                       ("530","RPC"),
                       ("636","LDAPssl"),
                       ("5060","SIP non encrypted"),
                       ("5061","SIP encrypted"),)
    Protocols = forms.MultipleChoiceField(widget=forms.CheckboxSelectMultiple,
                                             choices=OPTIONS)