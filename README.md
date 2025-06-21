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

Currently, implemeted block import state transition logics through Gray Paper v0.6.2 Chapter 11 Reporting and Assurance.
Passing integration tests except test cases ([#24](https://github.com/shunsukew/gojam/issues/24), [#25](https://github.com/shunsukew/gojam/issues/25), [#26](https://github.com/shunsukew/gojam/issues/26)).
