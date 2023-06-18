# Part5-ECDH-from-the-scratch

The following parts 

- 100_point_addition.py
- 200_point_multiplication.py
- 300_point_compression.py
- 400_key_generation.py

can be taken unchanged from Part4-ECDSA-from-the-scratch. They are equally valid for ECDH.

-----------

**Part 5: Key agreement**

ECDH is described e.g. in [ECDH Key Exchange][5_1].

Given two key pairs: (privA, pubA) and (privB, pubB). Both sides A and B exchange the public keys and compute the point:   
Side A: sharedSecretPointA = privA * pubB    
Side B: sharedSecretPointB = privB * pubA    

The following applies:  
sharedSecretPointA = privA * pubB = privA * privB * G = privB * privA * G = privB * pubA = sharedSecretPointB.  
The x coordinate (of sharedSecretPointA or sharedSecretPointB) is used as shared secret.

Note that the shared secret is not used directly as key, but a derivation from it, e.g. via HKDF.  

*500_key_agreement.py* implements the ECDH key agreement. The implementation is tested with pyca/cryptography, so there is a corresponding dependency.

[5_1]: https://cryptobook.nakov.com/asymmetric-key-ciphers/ecdh-key-exchange

