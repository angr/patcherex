
class NetworkRules(object):

    def get_bitflip_rule(self):
        rule = r'''#bitflip
alert (name:"rotate_00"; side:client; match:"\x00",1; replace:"\x43"; state:unset,cdata;)
alert (name:"rotate_43"; side:client; match:"\x43",1; replace:"\x0a"; state:unset,cdata;)
alert (name:"rotate_0a"; side:client; match:"\x0a",1; replace:"\x31"; state:unset,cdata;)
alert (name:"rotate_31"; side:client; match:"\x31",1; replace:"\x00"; state:unset,cdata;)
alert (name:"ignore_uninteresting"; side:client; regex:"\C";)
'''
        return rule


