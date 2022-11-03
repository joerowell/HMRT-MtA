# HMRT-MtA

## What's this?
This repository contains a toy Sage implementation of the multiplicative-to-additive (MtA) secret sharing method introduced in [1]. 

## How can I use this?
For any serious application, you obviously shouldn't: it doesn't even really support oblivious transfer. However, if you want to learn about the protocol, then 
the best way would be to look at the doctests in the file. Sample usage would look like this:

```python
>>> q = (2**16) + 1
>>> a = randrange(q)
>>> b = randrange(q)
>>> s = Sender(a, q)
>>> r = Receiver(b, q)
>>> sum(play(r, s)) % q == (s.secret * r.secret) % q
True
```

## What do I need?
All you need to get this to work is an implementation of Sage.

## References
[1] Iftach Haitner and Nikolaos Makriyannis and Samuel Ranellucci and Eliad Tsfadia, Highly Efficient OT-Based Multiplication Protocols, EUROCRYPT 2022, https://eprint.iacr.org/2021/1373
