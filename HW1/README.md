# README


## Getting Started

To get a local copy up and running follow these simple example steps.

### Running the program

1. Install dependencies
     ```pip3 install -r requirements.txt```
2. Run '''main.py''' with one of the following options
     - '''python .\main.py detect .\pom-3.xml''' to run with existing knowledge base
     - '''python .\main.py all .\pom-3.xml''' to re-load knowledge base, then run
3. Outputs can be found in '''Output.txt'''

## Options
1. Several pom files are available in the repo. I used pom-3.xml, which has vulnerabilities available in the current database. Simply add your pom file name to the command above
2. load_NVD.py has a START_YEAR and END_YEAR variable. These can be changed to adjust the JSON 2.0 feeds found at https://nvd.nist.gov/vuln/data-feeds. These are currently set to only return CVE's from 2021


