from xml_util import CDATA
from xml.etree import ElementTree as etree
from key_common import *
from key_xml_parser import namespace

class KeyResFormatter:

    def generate_response(self, res):
        if len(self.type) > 0:
            return self.fmt_handlers[self.type](res)
        else:
            return None

    def set_last_updated(self, last_updated):
        self.last_updated = last_updated

    def format_ckeys(self, responseNode, consortium):
        consortiumNode = etree.SubElement(responseNode, "Consortium")
        for key in consortium:
            keyNode = CDATA("Key", key['key'].strip(), id=key['key_id'], issued=key['issued'])
            consortiumNode.append(keyNode)

    def format_pkeys(self, responseNode, publishers):
        publishersNode = etree.SubElement(responseNode, "Publishers")
        for publisher in publishers:
            publisherNode = etree.SubElement(publishersNode, "Publisher", id=publisher['pub_id'], name=publisher['name'])
            for key in publisher['keys']:
                keyNode = CDATA("Key", key['key'].strip(), id=key['key_id'])
                publisherNode.append(keyNode)

    def get_keys_formatter(self, res):
        try:
            if not res or (('consortium' not in res) and ('publishers' not in res)):
                return self.error_invalid_token()

            if self.last_updated:
                responseNode = etree.Element("Encryption", 
                    xmlns=namespace['ns'], version="0.1", last_updated=self.last_updated)
            else:
                responseNode = etree.Element("Encryption", 
                    xmlns=namespace['ns'], version="0.1")

            print(res)
            if 'consortium' in res:
                self.format_ckeys(responseNode, res['consortium'])

            if 'publishers' in res:
                self.format_pkeys(responseNode, res['publishers'])

            return etree.tostring(responseNode)
        except Exception as e:
            print('error in get_keys_formatter : {}'.format(e))
        return None

    def put_pkeys_formatter(self, res):
        try:
            responseNode = etree.Element("Watermark", version="0.1")
            if res['ret']:
                responseNode.text = "uploading publisher keys are succeeded"
            else:
                responseNode.text = "uploading publisher keys are failed"
            
            return etree.tostring(responseNode)
        except Exception as e:
            print('error in put_pkeys_formatter : {}'.format(e))
        return None

    def create_token_formatter(self, res):
        try:
            responseNode = etree.Element("Watermark", version="1.0")
            if res['ret']:
                tokenNode = etree.SubElement(responseNode, "Token")
                tokenNode.text = res['token']

            return etree.tostring(responseNode)
        except Exception as e:
            print('error in create_token_formatter : {}'.format(e))
        return None

    def revoke_token_formatter(self, res):
        try:
            responseNode = etree.Element("Watermark", version="1.0")
            tokenNode = etree.SubElement(responseNode, "Token")
            if res['ret']:
                tokenNode.text = f"token({res['token_revoke']}) is revoked"
            else:
                tokenNode.text = f"error: token({res['token_revoke']}) is not revoked"

            print(etree.tostring(responseNode))
            return etree.tostring(responseNode)
        except Exception as e:
            print('error in revoke_token_formatter : {}'.format(e))
        return None

    def create_pub_formatter(self, res):
        try:
            responseNode = etree.Element("Watermark", version="1.0")
            if res['ret']:
                roleIdNode = etree.SubElement(responseNode, "RoleID")
                roleIdNode.text = res['role_id']
                secretIdNode = etree.SubElement(responseNode, "SecretID")
                secretIdNode.text = res['secret_id']
                tokenNode = etree.SubElement(responseNode, "Token")
                tokenNode.text = res['token']
            else:
                responseNode.text = "Failed to create a publisher"

            return etree.tostring(responseNode)
        except Exception as e:
            print('error in create_pub_formatter : {}'.format(e))
        return None

    def delete_pub_formatter(self, res):
        try:
            responseNode = etree.Element("Watermark", version="1.0")
            if res['ret']:
                responseNode.text = "publisher(pub_id={}) was removed successfully".format(res['pub_id'])
            else:
                responseNode.text = "Failed to create a publisher"

            return etree.tostring(responseNode)
        except Exception as e:
            print('error in delete_pub_formatter : {}'.format(e))
        return None

    def put_ckeys_formatter(self, res):
        try:
            responseNode = etree.Element("Watermark", version="0.1")
            if res['ret']:
                responseNode.text = "uploading consortium keys are succeeded"
            else:
                responseNode.text = "uploading consortium keys are failed"
            
            return etree.tostring(responseNode)
        except Exception as e:
            print('error in put_ckeys_formatter : {}'.format(e))
        return None

    def error_invalid_token(self):
        try:
            responseNode = etree.Element("Watermark", version="1.0")
            errorNode = etree.SubElement(responseNode, "Token")
            errorNode.text = "invalid token"

            return etree.tostring(responseNode)
        except Exception as e:
            print('error in error_invalid_token_formatter : {}'.format(e))
        return None

    def delete_expired_keys_formatter(self, res):
        return None

    def validate_response_type(self, response_type, required):
        if response_type in required:
            return True
        else:
            return False

    def __init__(self, type):
        self.fmt_handlers = { 
            GET_KEYS_CMD : self.get_keys_formatter,
            GET_PKEYS_CMD : self.get_keys_formatter,
            PUT_PKEYS_CMD : self.put_pkeys_formatter,
            CREATE_TOKEN_CMD : self.create_token_formatter,
            REVOKE_TOKEN_CMD : self.revoke_token_formatter,
            CREATE_PUB_CMD : self.create_pub_formatter,
            DELETE_PUB_CMD : self.delete_pub_formatter,
            GET_CKEYS_CMD : self.get_keys_formatter,
            PUT_CKEYS_CMD : self.put_ckeys_formatter,
            DEL_EXPIRED_KEYS_CMD : self.delete_expired_keys_formatter,
        }

        self.last_updated = None
        if self.validate_response_type(type, self.fmt_handlers.keys()):
            self.type = type
        else:
            self.type = ''