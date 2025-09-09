import xml.etree.ElementTree as ET

def read_pom(pom_file):
    pom = ET.parse(pom_file)
    root = pom.getroot()

    nsmap = {'m': 'http://maven.apache.org/POM/4.0.0'}

    output = []

    for dep in root.findall('m:dependencies/m:dependency', nsmap):
        groupID = dep.find('m:groupId', nsmap).text
        artID = dep.find('m:artifactId', nsmap).text
        version = dep.find('m:version', nsmap).text

        output.append([groupID, artID, version])

    return output