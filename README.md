# GoJAM

JAM (Join Accumulate Machine) implementation in Go.
Gray Paper: https://graypaper.com

## Tests

### Unit Tests

```
make test
```

### Integration Tests

Tiny spec
```
make tiny-integration
```

Full spec
```
make full-integration
```

## Development Status

Currently, implemeted block import state transition logics by Gray Paper Chapter 11 Reporting and Assurance.
Exceptions: ([#24](https://github.com/shunsukew/gojam/issues/24), [#25](https://github.com/shunsukew/gojam/issues/25), [#26](https://github.com/shunsukew/gojam/issues/26)).
