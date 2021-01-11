# gematmw-go-cipher
This is a CLI Application coded in the Go Programming Language \
for my 1st term university project in GEMATMW(Mathematics in the Modern World) at De La Salle University Manila. \
This program will consist of different functions that can \
encrypt and decrypt messages.
> This application was made using [Commando](https://github.com/thatisuday/commando)

---
# How To


__Command format is:__
```
ciphers [ciphersystem] "message" [-k [key]] [-p [encrypt|decrypt]]
```
| Ciphersystem  | Arguments | Flags |
| :-----------: | :-------: | :---: |
| affine        | message   | key(number,number), process |
| atbash        | message   |           n/a        |
| shift         | message   | key(number), process |
| vigenere      | message   | key(string), process |
| rail          | message   | key(number), process |
| rsa*          | message   | key(number,number), process |

*in-development

__NOTE: No spaces for key inputs with 2 numbers__ 

---
# References
- [Most Common English Words](https://github.com/first20hours/google-10000-english)
- [Affine Ciphers, Decimation Ciphers, and Modular Arithmetic](http://pi.math.cornell.edu/~kozdron/Teaching/Cornell/135Summer06/Handouts/affine.pdf)
- [Rail Fence Reference](https://www.geeksforgeeks.org/rail-fence-cipher-encryption-decryption/)