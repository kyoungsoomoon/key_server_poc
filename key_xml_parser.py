from datetime import datetime
from xml.etree import ElementTree as etree
from xml_util import CDATA, CDATA_START_TAG

namespace = {'ns': 'https://github.com/CognitiveNetworks/dai/blob/spec/spec/encryption_serve.md'}

def parse_ckeys(uploadKeysXML):
    try:
        root = etree.fromstring(uploadKeysXML)

        if root[0].tag == "{{{}}}Consortium".format(namespace['ns']) or root[0].tag == "Consortium":
            consortium = {}
            consortium['consortium_keys'] = []
            for keyInfo in root[0]:
                key = {}
                key['key_id']   = keyInfo.attrib['id']
                key['key']      = keyInfo.text.strip()
                if 'issued' in keyInfo.attrib.keys():
                    key['issued']   = keyInfo.attrib['issued']
                if 'expires' in keyInfo.attrib.keys():
                    key['expires']  = keyInfo.attrib['expires']
                consortium['consortium_keys'].append(key)

            return consortium
    except Exception as e:
        print("error : parse consortium keys {}".format(e))
    return None

def parse_pkeys(uploadKeysXML):
    try:
        root = etree.fromstring(uploadKeysXML)

        if root[0].tag == "{{{}}}Publishers".format(namespace['ns']) or root[0].tag == "Publishers":
            pubs = []
            pub = {}
            for publisher in root[0]:
                pub['pub_id']   = publisher.attrib['id']
                pub['name']     = publisher.attrib['name']
                pub['publisher_keys'] = []
                #key = {}
                for keyInfo in publisher:
                    key = {}
                    key['key_id']   = keyInfo.attrib['id']
                    key['key']      = keyInfo.text.strip()
                    if 'issued' in keyInfo.attrib.keys():
                        key['issued']   = keyInfo.attrib['issued']
                    if 'expires' in keyInfo.attrib.keys():
                        key['expires']  = keyInfo.attrib['expires']
                    pub['publisher_keys'].append(key)
                pubs.append(pub)

            return pubs
    except Exception as e:
        print("error : parse publisher keys {}".format(e))
    return None

def extract_consortium_keys(responseXML):
    try:
        root = etree.fromstring(responseXML)

        for child in root:
            if child.tag != "{{{}}}Consortium".format(namespace['ns']) and child.tag != "Consortium":
                root.remove(child)

        if '}' in root.tag:
            root.tag = root.tag.split('}', 1)[1]
        for child in root:
            if '}' in child.tag:
                child.tag = child.tag.split('}', 1)[1]
            for grandChild in child:
                if '}' in grandChild.tag:
                    grandChild.tag = grandChild.tag.split('}', 1)[1]

        root.attrib['xmlns'] = namespace['ns']
        return etree.tostring(root).decode("utf-8")
    except Exception as e:
        print("error in extracting consortium keys : {}".format(e))
    return None

def update_consortium_keys(orgResponseXML, consortium):
    try:
        root = etree.fromstring(orgResponseXML)
        consortium = convert_from_xml_consortium(consortium)

        for child in root:
            if child.tag == "{{{}}}Consortium".format(namespace['ns']) or child.tag == "Consortium":
                root.remove(child)

                # update consortium keys
                add_consortium(root, consortium)
                adjust_xml(root)
                return etree.tostring(root)

        # update consortium keys when there are no consortium keys
        add_consortium(root, consortium)
        adjust_xml(root)
        return etree.tostring(root)

    except Exception as e:
        print("error in updating consortium keys : {}".format(e))
    return None

def add_consortium(rootNode, consortium):
    consortiumNode = etree.SubElement(rootNode, "Consortium")
    for key in consortium['consortium_keys']:
        keyNode = etree.SubElement(consortiumNode, "Key", id=key['key_id'], issued=key['issued'])
        keyNode.text = key['key'].strip()

def add_publisher(publishersNode, publisher):
    publisherNode = etree.SubElement(publishersNode, "Publisher", id=publisher['pub_id'], name=publisher['name'])
    for key in publisher['publisher_keys']:
        keyNode = etree.SubElement(publisherNode, "Key", id=key['key_id'])
        keyNode.text = key['key'].strip()

""" remove namespace and make CDATA """
def adjust_xml(root):
    try:
        if '}' in root.tag:
            root.tag = root.tag.split('}', 1)[1]
        for child in root:
            if '}' in child.tag:
                child.tag = child.tag.split('}', 1)[1]
            for grandChild in child:
                if '}' in grandChild.tag:
                    grandChild.tag = grandChild.tag.split('}', 1)[1]
                if grandChild.tag == "Key":
                    grandChild.tag = CDATA_START_TAG + "Key"
                for grandGrandChild in grandChild:
                    if '}' in grandGrandChild.tag:
                        grandGrandChild.tag = grandGrandChild.tag.split('}', 1)[1]
                    if grandGrandChild.tag == "Key":
                        grandGrandChild.tag = CDATA_START_TAG + "Key"

        root.attrib['xmlns'] = namespace['ns']

    except Exception as e:
        print("error in extracting publisher keys : {}".format(e))

def extract_publisher_keys(responseXML, pub_id):
    try:
        root = etree.fromstring(responseXML)

        consortiumNode = None
        for publishers in root:
            if publishers.tag == "{{{}}}Consortium".format(namespace['ns']) or publishers.tag == "Consortium":
                consortiumNode = publishers
            elif publishers.tag == "{{{}}}Publishers".format(namespace['ns']) or publishers.tag == "Publishers":
                for child in publishers:
                    if child.attrib['id'] != pub_id and (child.tag == "{{{}}}Publisher".format(namespace['ns']) or child.tag == "Publisher"):
                        publishers.remove(child)
        if consortiumNode:
            root.remove(consortiumNode)

        if '}' in root.tag:
            root.tag = root.tag.split('}', 1)[1]
        for child in root:
            if '}' in child.tag:
                child.tag = child.tag.split('}', 1)[1]
            for grandChild in child:
                if '}' in grandChild.tag:
                    grandChild.tag = grandChild.tag.split('}', 1)[1]
                for grandGrandChild in grandChild:
                    if '}' in grandGrandChild.tag:
                        grandGrandChild.tag = grandGrandChild.tag.split('}', 1)[1]

        root.attrib['xmlns'] = namespace['ns']
        return etree.tostring(root).decode("utf-8")

    except Exception as e:
        print("error in extracting publisher keys : {}".format(e))
    return None

def convert_from_xml_consortium(xml):
    try:
        consortium = {}
        root = etree.fromstring(xml)
        for child in root:
            if child.tag == "{{{}}}Consortium".format(namespace['ns']) or child.tag == "Consortium":
                consortium = {}
                consortium['consortium_keys'] = []
                for keyInfo in child:
                    key = {}
                    key['key_id']   = keyInfo.attrib['id']
                    key['key']      = keyInfo.text.strip()
                    if 'issued' in keyInfo.attrib.keys():
                        key['issued']   = keyInfo.attrib['issued']
                    if 'expires' in keyInfo.attrib.keys():
                        key['expires']  = keyInfo.attrib['expires']
                    consortium['consortium_keys'].append(key)

                return consortium

    except Exception as e:
        print("error in converting from xml to list for consortium keys : {}".format(e))
    return None

def convert_from_xml_publisher(xml, pub_id):
    try:
        pub = {}
        root = etree.fromstring(xml)
        for child in root:
            if child.tag == "{{{}}}Publishers".format(namespace['ns']) or child.tag == "Publishers":
                for grandChild in child:
                    if grandChild.attrib['id'] == pub_id and (grandChild.tag == "{{{}}}Publisher".format(namespace['ns']) or grandChild.tag == "Publisher"):
                        pub['pub_id']           = pub_id
                        pub['name']             = grandChild.attrib['name']
                        pub['publisher_keys']   = []
                        for keyNode in grandChild:
                            key = {}
                            key['key_id']       = keyNode.attrib['id']
                            key['key']          = keyNode.text.strip()
                            if 'issued' in keyNode.attrib.keys():
                                key['issued']   = keyNode.attrib['issued']
                            if 'expires' in keyNode.attrib.keys():
                                key['expires']  = keyNode.attrib['expires']
                            pub['publisher_keys'].append(key)
                        return pub
    except Exception as e:
        print("error in converting from xml to list for publisher keys with pub_id_{} : {}".format(pub_id, e))
    return None

def update_publisher_keys(orgResponseXML, publisher, pub_id):
    try:
        root = etree.fromstring(orgResponseXML)
        publisher = convert_from_xml_publisher(publisher, pub_id)

        for publishers in root:
            if publishers.tag == "{{{}}}Publishers".format(namespace['ns']) or publishers.tag == "Publishers":
                for child in publishers:
                    if child.attrib['id'] == pub_id and (child.tag == "{{{}}}Publisher".format(namespace['ns']) or child.tag == "Publisher"):
                        publishers.remove(child)
                        break;
                # add or update publisher keys
                add_publisher(publishers, publisher)
                adjust_xml(root)
                return etree.tostring(root)

    except Exception as e:
        print("error in updating publisher keys : {}".format(e))
    return None

def delete_pub(response, pub_id, last_updated):
    try:
        root = etree.fromstring(responseXML)

        root.attrib['last_updated'] = last_updated
        for publishers in root:
            if publishers.tag == "{{{}}}Publishers".format(namespace['ns']) or publishers.tag == "Publishers":
                for child in publishers:
                    if child.attrib['id'] == pub_id and (child.tag == "{{{}}}Publisher".format(namespace['ns']) or child.tag == "Publisher"):
                        publishers.remove(child)
                        return etree.tostring(root)
        return etree.tostring(root)
    except Exception as e:
        print("error in extracting consortium keys {}".format(e))
    return None