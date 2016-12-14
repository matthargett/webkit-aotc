# Webkit with JavaScriptCore AOTB support

This is a modified version of [WebKit](https://webkit.org/). AOTB acronym stands for Ahead-Of-Time Bytecode saving. Main changes are in JavaScriptCore and it supports saving JSC bytecode in a file and later executing it. Saving is possible with or without running JavaScript program. Based on version 538.28.

## Building

The easiest way to build modified JavaScriptCore is to use the `Tools/Scripts/build-jsc` script. Basic options for Linux are `--gtk` and `--release`. Whole WebKit build is also supported, but the only difference outside JSC is that for local JS files URLs WebCore tries to load bytecode files instead of JS source, using the same path but with ".bytecode" additional file extension.

Bytecode saving (JS to bytecode conversion) is available only in command line JSC version.

## New command line options for JSC

option | description
:----: | -----------
<code>--save&nbsp;<file.js></code> | Main option for JS to bytecode conversion, saves bytecode for all functions in JS source without running it. Only one JS file allowed per one JSC run.
<code>-o&nbsp;\<file\></code> | Allows to specify output file name for bytecode file. Without this options, bytecode is stored in /tmp/<file.js>.bytecode
<code>-b&nbsp;\<file\> | Like -f for JS source, it runs code loaded from bytecode file. Several bytecode files are supported (each with its own -b <file> option) and mixing with normal JS files is also possible.
`--saveBytecode=<flag>` | Enables saving bytecode while running JS program, but only executed functions are saved. Default is false (0).
`--compression=<level>` | Enables zlib per-function bytecode compression level 0-9, zero (default) means no compression.

## Example

If standard run from command line looks like
```
$ jsc foo.js -- <params>
```

AOTB save command is
```
$ jsc --save foo.js -o foo.bc
```

To run existing bytecode file, use
```
$ jsc -b foo.bc -- <params>
```

## Description

JavaScriptCore parses each function only when it is called for the first time. After parsing it generates bytecode in memory and all execution levels (interpreter, baseline JIT, DFG JIT) work only with bytecode, without using source. This version allows to save bytecode in a file, even without running the JS program, and later load bytecode and execute it without parsing source.

Bytecode for runtime-generated JavaScript (like `eval()` or `new Function()` calls) is not saved, and while running from saved bytecode, it is processed as usual starting from parsing and creating syntax tree. JSC generates a bit different bytecode when function is used as constructor, we implement necessary conversion for bytecode to translate it from standard form into constructor form instead of saving both versions in a file. Our implementation successfully passes JSC regression tests except those which explicitly require the JS source code, for example, for printing function source or storing line numbers in exceptions.

The original idea was to store more different internal representations from JSC, and baseline JIT code saving was also implemented, but we publish only the AOTB part. AOTB is platform-independent, it was tested on x86_64 and ARMv7 under Linux.

## Resources

- Augmenting JavaScript JIT with Ahead-of-Time Compilation. Compiler, Architecture and Tools Conference 2015, Haifa, Israel. ([slides](https://software.intel.com/sites/default/files/managed/65/2f/aotc_haifa.pdf))
- Ahead-of-Time Compilation of JavaScript Programs. Programming and Computer Software, 2017, Vol. 43, No. 1, pp. 51–59, ISSN 0361-7688
- [Ahead of Time Optimization for JavaScript Programs. Trudy ISP RAN/Proc. ISP RAS, vol. 27, issue 6, 2015, pp. 67-86 (in Russian)](http://www.ispras.ru/proceedings/docs/2015/27/6/isp_27_2015_6_67.pdf)

## License

[WebKit License](https://webkit.org/licensing-webkit/)

