# Cobaltstrike_BOFLoader
This is an open source port/reimplementation of the Cobalt Strike BOF Loader **as is**. For the most part, everything is done as in the original Beacon + Teamserver in Cobalt Strike.

This includes shortcomings that are resolved in other open source COFF loaders such as the TrustedSec COFFLoader. This is intentional. The goal of this project is not to make a *good* COFF loader, it was to make an open source analog of the specific implementation in Cobalt Strike, to help with debugging in edge cases where BOFs work in other COFF Loaders but not in Cobalt Strike.

## Usage:
```
./compile.bat
python bof_pack.py Msgbox.x64.o -o bof.blob
./bofloader.exe .\bof.blob
```

## Why did I make this?
The Cobalt Strike BOF Loader has given me numerous issues in the past when doing BOF development, regarding sections (COMDATs, i'm looking at you) that aren't handled by the Beacon BOF loader. This is especially frustrating when the issues are not reproducible in open source COFF Loaders, which benefit from more debuggability.

To make things worse, the Cobalt Strike BOF Loader does not even take in full COFFs directly, there is some processing done on the teamserver side, which is barely documented. The resulting blob sent down to Beacon is much smaller than the original COFF, and the format is not documented.

This project aims to be a true 1:1 replica of the Cobalt Strike implementation, where any issues in one should be reproducible in the other.

## Credits
- Fortra, for being the cause of my misery
- A bunch of LLMs I used to mass clean up and port BOFLoader functionality, and to comment code because I am lazy
