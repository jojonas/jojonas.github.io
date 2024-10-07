---
title: 'Recognizing Serialization Patterns'
date: 2024-10-06T11:00:45+02:00
draft: true
tags: ["Reverse Engineering", "Networking"]
---

* Goals of serialization:
  * Transmit structured objects in binary form
  * Serialization vs. Encoding
    * Serialization: take an object and make an "ideal" stream
    * Encoding: adapt a byte stream for the underlying medium
    * However: steps are usually used in combination and therefore often not disambiguated
  * Other properties:
    * Self describing
    * Parsable if description is missing (e.g. for forward/backward compatibility)

* "Evolution"
  * Fixed-size fields
    * Advantages: Simple, fast (no dynamic allocations)
    * Disadvantages: No variable-length data; serialization strongly tied to content (no abstraction)
  * Terminators, Delimiters, Separators
    * Advantages: Variable-length data; however: serialization still strongly tied to content
    * Disadvantages: What to do with terminators in data:
      * Escaping/Error out
      * Dynamic Terminator
  * Length-Value
    * TLV
  * Others:
    * Indefinitive-Length encodings (e.g. highest bit)

```goat {width=700}
 0                   1                   2                   3  
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |        Destination Port       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Acknowledgment Number                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Offset|  Res. |     Flags     |             Window            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Checksum           |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```


* Concrete implementations
  * Text based
    * JSON (Terminator, self describing)
    * XML (Terminator, self describing)
    * YAML, TOML (Terminator, self describing)
    * CSV (Terminator, (usually) self describing)

  * Binary
    * BER/DER (ASN.1 - TLV, not self describing)
      * https://luca.ntop.org/Teaching/Appunti/asn1.html
      * https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/basic-encoding-rules.html
    * [Protobuf](https://protobuf.dev/programming-guides/encoding/) (TLV, not self describing)
    * [MessagePack](https://github.com/msgpack/msgpack/blob/master/spec.md#formats) (TLV, self describing)
    * Built-in
      * [Java serialization](https://docs.oracle.com/javase/6/docs/platform/serialization/spec/protocol.html)
      * [PHP serialization](https://www.phpinternalsbook.com/php5/classes_objects/serialization.html) (TLV)
      * [.NET serialization](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/75b9fe09-be15-475f-85b8-ae7b7558cfe5)
      * [Pickle](https://peps.python.org/pep-3154/) (TLV + opcode-based VM)
    * CBOR, BSON

* Other patterns to look out for:
  * Magic bytes
  * Compression
    * zlib
    * pkzip
  

* Tools:
  * ImHex
  * [Binwalk](https://github.com/ReFirmLabs/binwalk)