# DDISASM

[ddsiasm](https://git.grammatech.com/rewriting/ddisasm)

## Requirement

- [gtirb](https://github.com/grammatech/gtirb)
- [gtirb-pprinter](https://git.grammatech.com/rewriting/gtirb-pprinter)
- [ddisasm](https://git.grammatech.com/rewriting/ddisasm)
- capstone-gt
- [gtirb_capstone](https://github.com/GrammaTech/gtirb-capstone)


```
python3 -m pip install requirements.txt
```

## Usage

```
PYTHONPATH=../../protobuf_def python3 ddisasmBBnRef.py -i [input-binary or gtirb-ir-file] -o [output-path]
```
