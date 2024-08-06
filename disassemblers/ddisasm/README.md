# DDISASM

[ddsiasm](https://github.com/GrammaTech/ddisasm)

## Requirement

- [gtirb](https://github.com/Grammatech/gtirb)
- [ddisasm](https://github.com/GrammaTech/ddisasm)
- capstone-gt
- [gtirb_capstone](https://github.com/GrammaTech/gtirb-capstone)


```
python3 -m pip install requirements.txt
```

## Usage

```
PYTHONPATH=../../protobuf_def python3 ddisasmBBorRef.py -i [input-binary or gtirb-ir-file] -o [output-path]
```
