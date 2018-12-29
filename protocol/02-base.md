# Common Data Structures

A common common base structure is used across both Messages and Pages to simplify encoding and parsing. 
All pages provide contain an ID derived from the service or node public key and a signature, allowing validation of both Messages and Pages prior to parsing.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Page Kind           |     Flags     |    Reserved   |           
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Page Version         |            Data Len           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Secure Options Len      |       Public Options Len      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
/                               ID                              /
/             Protocol Defined ID Length (32-bytes)             /
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                             Data                              /
/       Optional, Variable Length Data (4-byte aligned)         /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                        Secure Options                         /
/        Optional, Variable Length Data (4-byte aligned)        /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                        Public Options                         /
/       Optional, Variable Length Data (4-byte aligned)         /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
/                           Signature                           /
/          Protocol Defined Signature Length (64-bytes)         /
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Header Fields
- **Kind** indicates protocol-specific page or message kind
  - this must be globally unique within DSD
  - To apply for a page kind (or kinds) apply for a PR on this repo against the `KINDS.yml` listing
  - For testing purposes and/or private use that does not require registration, a page kind of  `0x0FFF` may be used
  - Messages types are identified by setting the top bit (0x8000)
- **Flags**
  - Bit 0: Secondary, indicates a secondary page type
  - Bit 1: Encrypted, indicates data field has been encrypted
  - Bit 2: Address Request, messages only, indicates the responder should attach a peer address option to the response (used for address discovery)
  - Bits 2:7: Reserved, must be 0
- **Reserved**, for algorithm specifiers if required, must be 0
- **Page version**, monotonically increasing counter for page replacement
- **Data Length**, length of the variable length data field
- **Secure Options length**, length of the variable length secure options field
  - This allows options such as IP addresses for service connections to be encrypted alongside service data
- **Public options length**, length of the variable length public options field
  - These options are used to specify public page information such as Public Keys and Expiry Time
- **ID** is the Service ID for Pages or the Node ID for messages

## Body
- **Data** contains arbitrary data for service pages (based on the page kind), or DSD data for messages (such as pages to be transferred). The data section may be encrypted.
- **Secure Options** contain options that are encrypted and can thus only be parsed by those with the appropriate keys.
- **Public Options** contain public options associated with a page or message

## Signature
- **Signature** is a cryptographic signature across the whole object (header included) used to validate the authenticity of pages and messages.

### Pages

Pages are split into two types, Primary pages published at an SID by the service holding the corresponding key pair, and Secondary pages published at an SID by a third party providing supplemental information or services. For example, these may be used by the service publisher to provide transient information alongside the service page.

## Fields

See [Common](###Common) section for header information

- **ID**, Service ID (hash of service public key)
- **Data**, Arbitrary service data, parsing and encoding specific to a given service type (and thus page kind)
- **Secure Options**, private (and encrypted) well-defined service options for a given page
- **Public Options**, public well-defined service options for a given page
- **Signature**, a cryptographic signature over the whole page

If the `encrypted` flag is set, data and secure options fields must be decrypted before parsing.
