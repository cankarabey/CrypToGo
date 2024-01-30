# Cryp-To-Go

A simple CLI tool for generating PGP keys and encrypting/decyprting files, written in Go!

Project is WIP

## Example Usage
Generating a keyset:
```
cryptogo generate-keys -n JohnDoe -c comment -e johndoe@mail.com
```

Encrypting a file:
```
cryptogo encrypt secretmessage.txt -p public.key
```

Decrypting a file:
```
cryptogo decrypt secretmessage.txt.pgp -k private.key
```


