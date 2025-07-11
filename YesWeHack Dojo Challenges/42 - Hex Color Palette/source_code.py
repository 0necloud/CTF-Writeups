import io
import re
from urllib.parse import unquote
from jinja2 import Environment, FileSystemLoader
lxml = import_v("lxml", "5.3.2")
from lxml import etree


template = Environment(
    autoescape=True,
    loader=FileSystemLoader('/tmp/templates'),
).get_template('index.tpl')


def parse_palette(xml_data):
    parser = etree.XMLParser(load_dtd=True, resolve_entities=True)
    tree = etree.parse(io.StringIO(xml_data), parser)
    root = tree.getroot()
    colors = set()

    # Only parsing hex color
    for elem in root.iter():
        if elem.text and re.match(r"^#(?:[0-9a-fA-F]{3,6})$", elem.text.strip()):
            colors.add(elem.text.strip().lower())

    return list(colors)

def promptFromXML(s: str):
    if not s:
        return "No XML data received.", []

    return "Pallet successfully extracted", parse_palette(s)

data = unquote("")

try:
    parsed_text, colors = promptFromXML(data)
except Exception as e:
    parsed_text = f"Error : {str(e)}"
    colors = []

print(template.render(output=parsed_text, colors=colors, image=None))