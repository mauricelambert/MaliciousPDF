![MaliciousPDF logo](https://mauricelambert.github.io/info/python/security/MaliciousPDF_small.png "MaliciousPDF logo")

# MaliciousPDF

## Description

This file implements a library and tool to make malicious PDF files.

## Requirements

This package require :
 - python3
 - python3 Standard Library

## Installation
```bash
pip install MaliciousPDF
```

## Usages

### Command line

```bash
python3 MaliciousPDF.py --help
python3 MaliciousPDF.py
python3 MaliciousPDF.py -f 'test.pdf' -t 'JS' -p 'app.alert("test");' -b 'My body' -T 'My title' -o -v '1.7' -a 'MyName' -d '2016-06-22 16:53:45' -i 'Title' -P 'Not MaliciousPDF'
```

### Python script

```python
from MaliciousPDF import *
init_obfuscation()
file, catalog, outlines, pages, page = pdf_bases("js_alert_test_obfuscation.pdf")

add_text(
    page,
    " - Hello.\n - Hi !\n - How are you ?\n - Fine.",
    (100, 700),
)

MaliciousJsFile(
    catalog, StringIO(javascript_obfuscation("app.alert('Test');"))
)

pdf_obfuscation(file)
```

## Links

 - [Github Page](https://github.com/mauricelambert/MaliciousPDF/)
 - [Documentation](https://mauricelambert.github.io/info/python/security/MaliciousPDF.html)
 - [Pypi package](https://pypi.org/project/MaliciousPDF/)
 - [Executable](https://mauricelambert.github.io/info/python/security/MaliciousPDF.pyz)

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
