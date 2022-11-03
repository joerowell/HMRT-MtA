"""
A Sage implementation of the multiplicative-to-additive scheme provided in:

Highly Efficient OT-Based Multiplication Protocols,
Iftach Haitner, Nikolaos Makriyannis, Samuel Ranellucci and Eliad Tsfadia,
Eurocrypt 2021.
"""

from sage.misc.prandom import randrange

# This global is used to set the security parameter: k implies k/4 bits of statistical security.
k = 512


def sample_t():
    """
    sample_t. This function returns either 1 or -1. The value returned is generated uniformly randomly.
    Note that this version of this function does not make any strong randomness guarantees: we simply use
    Sage's randrange function for this. 

    ::

    >>> lst = [sample_t() for t in range(100)]
    >>> [x for x in lst if x != 1 and x != -1]
    []
    """

    # There's probably a much better way to write this.
    if randrange(100) % 2 == True:
        return 1
    else:
        return -1


class Player:
    """
    Player. This class abstracts away the low-level details of participating in the scheme.
    In particular, this class holds the prime modulus (q), the secret (secret) and the
    number of OTs to carry out (n).
    """

    def __init__(self, secret, q):
        """
        __init__. This creates a new player object.
        This just sets the various parameters to be held in this object.
        :param secret: the secret value. Must be an element of Z_{q}.
        :param q: the moudlus of the underlying group. Must be prime.

        ::
        >>> secret = 3
        >>> q = 4
        >>> p = Player(secret, q)
        Traceback (most recent call last):
        ...
        ValueError: q must be prime

        >>> secret = 5
        >>> q = 3
        >>> p = Player(secret, q)
        Traceback (most recent call last):
        ...
        ValueError: secret should be smaller than q
        """
        if ZZ(q).is_prime() == False:
            raise ValueError("q must be prime")
        if secret >= q:
            raise ValueError("secret should be smaller than q")

        self.secret = secret
        self.q_ = q
        self.n_ = ceil(log(q, 2)) + k

    @property
    def q(self):
        """
        q. This function returns the player's q. Here q is the modulus
        of the underlying group.

        ::

        >>> a = 10
        >>> q = 11
        >>> s = Player(a, q)
        >>> s.q == q
        True

        """
        return self.q_

    @property
    def n(self):
        """
        n. This returns the player's n.
        Here n is the number of OT queries to carry out, computed as ceil(log(q, 2)) + k.

        ::
        >>> a = 10
        >>> q = 11
        >>> s = Player(a, q)
        >>> s.n == ceil(log(q, 2)) + k
        True

        """
        return self.n_


class Sender(Player):

    """
    Sender. This class acts as the Sender (P1) in the protocol. This party carries out
    the OTs and also holds the random mask (delta).
    """

    def __init__(self, a, q):
        """
        __init__. This creates a new sender object.
        This has the effect of sampling a uniformly random mask δ over Z_{q}^n and instantiating
        all other parameters.
        :param self: the object to construct.
        :param a: the secret held by the sender. Must be smaller than q.
        :param q: the modulus of the underlying group. Must be prime.

        ::

        >>> a = 10
        >>> q = 11
        >>> s = Sender(a, q)
        >>> len(s.delta) == ceil(log(q, 2)) + k
        True

        """
        Player.__init__(self, a, q)
        self.delta_ = [randrange(q) for t in range(self.n)]

    @property
    def delta(self):
        """
        delta. This function returns the sender's delta object.
        Here delta is a list of n elements chosen uniformly at
        random over Z_q.

        ::

        >>> a = 10
        >>> q = 11
        >>> s = Sender(a, q)
        >>> len(s.delta) == ceil(log(a, 2)) + k
        True
        >>> [x for x in s.delta if x >= q]
        []

        """
        return self.delta_

    def ot(self, i, t):
        """
        ot. This function carries out the retrieving functionality for the sender.
        Essentially, this function returns a + delta[i] iff t == 1 and
        -a + delta[i] iff t == -1. If t is not equal to either of these then this
        function raises a value error.

        :param i: the index to retrieve the value from.
        :param t: the choice input of the receiver party.
        :rtype int.

        ::

        >>> a = 10
        >>> q = 11
        >>> s = Sender(a, q)
        >>> s.ot(0, 2)
        Traceback (most recent call last):
        ...
        ValueError: t must be 1 or -1
        >>> s.ot(len(s.delta), -1)
        Traceback (most recent call last):
        ...
        ValueError: i is out of range
        >>> s.ot(0, 1) == (a + s.delta[0]) % q
        True
        >>> s.ot(0, -1) == (s.delta[0] - a) % q
        True
        """

        if i >= len(self.delta):
            raise ValueError("i is out of range")
        if t != 1 and t != -1:
            raise ValueError("t must be 1 or -1")

        # All operations are over Z_q.
        return (self.secret * t + self.delta[i]) % self.q


class Receiver(Player):
    """
    Receiver. This class acts as the receiver in the protocol (P2). This player
    holds the indices (t) and receives the messages from the Sender.
    """

    def __init__(self, b, q):

        """
        __init__. This is the constructor for the receiver.
        :param b: the secret held by the receiver.
        :param q: the prime modulus for the group.

        ::

        >>> b = 11
        >>> q = 13
        >>> r = Receiver(b, q)
        >>> r.q == q and r.n == ceil(log(q,2)) + k
        True
        >>> len(r.t) == ceil(log(q, 2)) + k and len([x for x in r.t if x != 1 and x != -1]) == 0
        True
        """

        Player.__init__(self, b, q)
        self.t_ = [sample_t() for x in range(self.n_)]

    @property
    def t(self):
        """
        t. This function returns the t vector held by the receiver. Here t
        is a list of entries of length `n` where each entry is either 1 or -1.

        ::
        >>> b = 5
        >>> q = 11
        >>> r = Receiver(b, q)
        >>> len(r.t) == ceil(log(q, 2)) + k and len([x for x in r.t if x != 1 and x != -1]) == 0
        True
        """
        return self.t_

    def v(self):
        """
        v. This function returns a vector, v, such that <v, t> = b.
        In other words, this function can be viewed as producing a solution to a random
        subset sum with slightly different constraints.

        Note that this function may not produce consistent `v` across calls.

        ::

        >>> b = 5
        >>> q = 2**16 + 1
        >>> r = Receiver(b, q)
        >>> v = r.v()
        >>> sum(map(lambda x, y : x * y, r.t, v)) % q == b
        True
        """

        # This function works by producing a random set of values,
        # then appropriately adding or subtracting the excess to an element of the
        # random set.
        v = [randrange(self.q) for t in range(self.n)]
        # Work out how far away from b we are.
        tot = sum(map(lambda x, y: x * y, self.t, v)) % self.q
        targ_b = (self.secret - tot) % self.q
        # Adjust the random value.
        rnd = randrange(self.n)
        v[rnd] = v[rnd] + targ_b * self.t[rnd]
        # This isn't separate for any good reason.
        v[rnd] = v[rnd] % self.q
        return v


def play(receiver, sender):
    """
    play. This function runs the protocol between "receiver" and "sender", returning
    (p1, p2) such that p1 + p2 = sender.secret * receiver.secret.

    :param receiver: the receiver party.
    :param sender: the sending party.
    :rtype a tuple.

    ::

    >>> q = (2**16) + 1
    >>> a = randrange(q)
    >>> b = randrange(q)
    >>> s = Sender(5, 11)
    >>> r = Receiver(5, 13)
    >>> play(r,s)
    Traceback (most recent call last):
    ...
    ValueError: receiver and sender q don't match

    >>> s = Sender(a, q)
    >>> r = Receiver(b, q)
    >>> sum(play(r, s)) % q == (s.secret * r.secret) % q
    True
    """

    if receiver.q != sender.q:
        raise ValueError("receiver and sender q don't match")

    z = [sender.ot(i, receiver.t[i]) for i in range(sender.n)]
    v = receiver.v()
    q = sender.q
    p1 = -sum(map(lambda x, y: x * y, sender.delta, v)) % q
    p2 = sum(map(lambda x, y: x * y, z, v)) % q
    return (p1, p2)


if __name__ == "__main__":
    import doctest

    doctest.testmod()
