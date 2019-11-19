from xml.etree import ElementTree as etree

CDATA_START_TAG = '![CDATA['
CDATA_END_TAG = ']]'

def CDATA(tag, text=None, **args):
    element = etree.Element(CDATA_START_TAG + tag, **args)
    element.text = text
    return element

etree._original_serialize_xml = etree._serialize_xml
def _serialize_xml(write, elem, qnames, namespaces,
                short_empty_elements, **kwargs):
    text = elem.text
    if elem.tag.startswith(CDATA_START_TAG):
        tag = elem.tag[len(CDATA_START_TAG):]
        if tag is None:
            if text:
                write(_escape_cdata(text))
            for e in elem:
                _serialize_xml(write, e, qnames, None,
                            short_empty_elements=short_empty_elements)
        else:
            write("<" + tag)
            items = list(elem.items())
            if items or namespaces:
                if namespaces:
                    for v, k in sorted(namespaces.items(),
                                    key=lambda x: x[1]):  # sort on prefix
                        if k:
                            k = ":" + k
                        write(" xmlns%s=\"%s\"" % (
                            k,
                            _escape_attrib(v)
                            ))
                for k, v in items:
                    write(" %s=\"%s\"" % (qnames[k], v))
            if text or len(elem) or not short_empty_elements:
                write(">")
                if text:
                    write("<" + CDATA_START_TAG)
                    write(text)
                    write(CDATA_END_TAG + ">")
                for e in elem:
                    _serialize_xml(write, e, qnames, None,
                                short_empty_elements=short_empty_elements)
                write("</" + tag + ">")
            else:
                write(" />")
        if elem.tail:
            write(_escape_cdata(elem.tail))
    else:
        return etree._original_serialize_xml(write, elem, qnames, namespaces, short_empty_elements, **kwargs)

etree._serialize_xml = etree._serialize['xml'] = _serialize_xml
