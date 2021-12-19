# Cryptographic Election Technologies

This is a two-week project, aiming at collegiate computer science majors taking
a senior-level computer security or cryptography course, to gain experience
implementing and using modern concepts of cryptography (e.g., homomorphisms
and zero-knowledge proofs).

The code here is a simplification of
[Microsoft's ElectionGuard](https://github.com/microsoft/electionguard).
The project specifications, as well as the corresponding course slide decks,
can be found on the course Piazza forum.

**Table of contents:**
- [Student information](#student-information)
- [Installation and setup](#installation-and-setup)
- [Documentation](#documentation)
- [Your assignment](#your-assignment)
- [Coding advice](#coding-advice)
- [Debugging advice](#debugging-advice)
- [Written questions](#written-questions)

## Student Information
Please also edit _README.md_ and replace your instructor's name and NetID with your own:

_Student name 1_: Dan WALLACH

_Student NetID 1_: dwallach

_Student name 2_: Dan WALLACH

_Student NetID 2_: dwallach

Your NetID is typically your initials and a numeric digit. That's
what we need here.

_If you contacted us in advance and we approved a late submission,
please cut-and-paste the text from that email here._

## Installation and setup

Your project handout gives you additional details on how to configure
your computer with Python3.8 and the other necessary utilities.
After that, using [**make**](https://www.gnu.org/software/make/manual/make.html), you can do everything all at once:

```
make
```

The unit and integration tests can also be run with make:

```
make test
```

Or just run the autograder, which knows how to assign points
to the unit tests:

```
make autograder
```

If you're running in an IDE like PyCharm, make sure you've run `make` first,
which will create a Python "virtual environment" and set it up properly.
You then tell your IDE to use the fresh virtual environment.

Before you try coding anything new, make sure that the unit tests all pass,
except for the ones that correspond to work that you will need to do
for this assignment. Another thing is to try out the Python Console
(on the `Tools` menu). You should be able to have an interaction
like this:

![Animated REPL example](repl-recording.gif)

The console has some nice auto-complete functionality, so you
don't have to remember the names of everything. This
particular sequence of commands demonstrates encryption and
decryption, as well as a feature of this educational ElectionGuard
version that's here to help you debug your code: every encrypted
value in ElectionGuard keeps track of the **formula** that was used
to create it. This formula, in prefix notation similar to LISP
programs, is much easier to deal with than looking at hundreds
of decimal digits.

You might also find the "formula" feature useful for logging
or asking the IDE to print it during debugging sessions. Note
that, if this code was being used in production, you'd want to
take care not to write formulas out to disk or on the network,
since they can carry the plaintext value used to compute an
encryption.

## Documentation

For this project, we've stripped away a lot of the more complex features
of ElectionGuard. Still, you may find the official documentation to be helpful.

- [GitHub Pages](https://microsoft.github.io/electionguard-python/)
- [Read the Docs](https://electionguard-python.readthedocs.io/)

## Your assignment

Most of the code that you will write will be in: [simple_elections.py](src/electionguard/simple_elections.py). In this file,
you'll find a variety of Python functions which can encrypt, decrypt, tally, and verify
some "simple" elections, where that means that we're only dealing with a single
contest, where a voter is only allowed to pick zero or one choices. See, as well,
the corresponding data structures in [simple_election_data.py](src/electionguard/simple_election_data.py).
Your code will build on all the other machinery that's already present here,
including ElGamal encryption. You'll ultimately be graded on getting the
tests in [test_simple_elections_part1.py](tests/test_simple_elections_part1.py)
and [test_simple_elections_part2.py](tests/test_simple_elections_part2.py) to
pass. Some of these tests are incomplete, and you'll need to fill them in.

Be sure to read the project handout, which goes into more details, and includes
some of the math that you'll be converting to code.

**Don't forget that you're also responsible for answering some
written questions, at the bottom of this file.**

## Coding advice
You should generally work one function or method at a time,
and make sure the relevant unit tests pass. Do this incrementally,
and commit and save your code often. Don't just write everything
then try to debug it all at once. That way lies madness.

You'll notice that some functions you need to implement
can use other functions that you need to implement as subroutines
of whatever sort. Work your way up from the bottom, debugging
as you go. (See the [debugging advice](#debugging-advice) below
as well.)

Also, you need to properly handle errors. Consider this decryption
function:

```python
class ElGamalCiphertext:
    ...
    def decrypt_known_product(self, product: ElementModP) -> Optional[int]:
        return discrete_log(div_p(self.data, product))
    
    def decrypt(
        self, secret_key: Union[ElGamalSecretKey, ElGamalKeyPair]
    ) -> Optional[int]:
        if isinstance(secret_key, ElGamalKeyPair):
            secret_key = secret_key.secret_key

        return self.decrypt_known_product(pow_p(self.pad, secret_key))
```
The discrete log function (`discrete_log`) will give up if it gets past
a (fairly large) threshold. This ensures that it doesn't just
run forever; it instead gives up and  returns `None`. That means
that the ElGamal decryption function has the potential to fail.
That failure is indicated by returning `Optional[int]`, which could be
the plaintext integer, or it could be `None`. Callers of this
decryption function must then deal with this failure. Generally
that means passing on a failure as another possible return value.
It generally doesn't mean ignoring the failure and causing
a `TypeError` to get thrown. That's bad style.

Now, in a unit test, where you are *testing* for something to
succeed, it's perfectly fine to fail with an exception
as a way to indicate a test failure.
Perfect for tests. Not sufficient for main code.

Lastly, please make sure your code is properly indented.
We've included a package in the Gradle configuration that
can do exactly this. Just run `make auto-lint`, which
will run the `black` indenter and then several different
static checks on the resulting Python code.

## Debugging advice

When you have a unit test that fails, you might be tempted to
single-step your way through the code, or even to print out
and carefully analyze the formulas that have been generated
to see why they aren't matching up.

Instead, you should consider building simplifying tests. If
a Hypothesis test fails, try to do it with constants that
you specify, rather than those generated by Hypothesis. 
Similarly, it's helpful to set conditional breakpoints 
([official documentation](https://www.jetbrains.com/pycharm/guide/tips/conditional-breakpoints/)).
If, for example, you're debugging one of the cryptographic proof
validation functions, they often validate several different
things. You might set a breakpoint at each one, with a condition
that the breakpoint only triggers when the proof requirement is false.
That helps you narrow things down. Similarly, you might add
additional logging code, anywhere in the library, to create
a more useful trace of what happened. Just use the logging
functions inside [logs.py](src/electionguard/logs.py).

Also, if your proof isn't validating, it's entirely possible
that the proof checker is fine, but the proof itself was computed
incorrectly. 

## Running the autograder

This project uses the [grade](https://github.com/thoward27/grade) autograder.
You can run it from the command-line with `make autograder`.
It's also configured to run every time you push a commit to GitHub.
If you've completed everything, the output will look something like
this:
```
┌──────────────────────────────────────────────────────────────────────────────
│ TestPart1.test_encryption_decryption_inverses                    :  2/ 2 ✅ 
│ TestPart1.test_invalid_encryption_proofs_fail                    :  3/ 3 ✅ 
│ TestPart1.test_partial_decryption                                :  1/ 1 ✅ 
│ TestPart1.test_proof_validation                                  :  3/ 3 ✅ 
├──────────────────────────────────────────────────────────────────────────────
│ TestPart2.test_ballot_accumulation                               :  1/ 1 ✅ 
│ TestPart2.test_broken_chaum_pedersen_ballot_proofs_fail          :  1/ 1 ✅ 
│ TestPart2.test_chaum_pedersen_ballot_proofs_validate             :  1/ 1 ✅ 
│ TestPart2.test_encryption_decryption_inverses                    :  1/ 1 ✅ 
│ TestPart2.test_encryption_determinism                            :  1/ 1 ✅ 
│ TestPart2.test_invalid_ballot_ciphertexts_behave_differently     :  1/ 1 ✅ 
│ TestPart2.test_overvoted_ballots_become_blank_ballots            :  1/ 1 ✅ 
│ TestPart2.test_unique_ballot_ids                                 :  1/ 1 ✅ 
│ TestPart2.test_unique_nonces                                     :  1/ 1 ✅ 
├──────────────────────────────────────────────────────────────────────────────
│ Mypy, no errors                                                  :  1/ 1 ✅ 
│ Subtotal: TestPart1                                              :  9/ 9 ✅ 
│ Subtotal: TestPart2                                              :  9/ 9 ✅ 
├──────────────────────────────────────────────────────────────────────────────
│ TOTALS                                                           : 19/19 ✅ 
└──────────────────────────────────────────────────────────────────────────────
```

Your instructor will probably look at the "part 1" points (corresponding to
the unit tests in [test_simple_elections_part1.py](tests/test_simple_elections_part1.py))
separately from the "part 2" points (corresponding to the unit tests
in [test_simple_elections_part2.py](tests/test_simple_elections_part2.py)),
perhaps looking at whatever you had pushed to GitHub before relevant deadlines.
There's also a point in the autograder based on getting no warnings or errors from the Mypy
static Python type checker.
The written questions (below) will be graded manually.

## Written questions

Let's imagine you were trying to do this encryption, in bulk, from the
output of a paper-based ballot scanner. Assume that the ballots you're
encrypting have 20 contests, each of which has 5 selections, and voters
may select at most one candidate (so, 1-of-5). The performance
requirements for one of these would be roughly the same as encryption 20 `PlaintextBallot` 
objects with your code, assuming each has 5 candidates. _Write some kind of 
benchmark that generates 100 of these ballots and computes the time for
the encryption computation, including generation of the Chaum-Pedersen proofs,
to run._ Commit this file to your repository. (You may find [elgamal_benchmark.py](src/electionguard/elgamal_benchmark.py), which
just benchmarks the ElGamal encryption process itself, to be a useful template.)

- What is the name of the Python file which implements your benchmark? 
```
your_answer_here.py
```
- What command should we type to execute your benchmark? 
```
your_answer_here
```
- On your personal computer (or your partner's), how long does the encryption process take to run? 
```
your_answer_here seconds
```
- Now express this in terms of the throughput: 
```
your_answer_here ballots/second
```
- If you knew you needed to encrypt a million ballots in one hour, and assuming you could get
  perfect speedups from running in parallel, how many computers, of the same performance
  as your personal computer, would be necessary to hit the target performance? 
```
your_answer_here computers
```
- Amazon's AWS will rent you "spot instance" virtual CPUs at significant discounts.
  Assume you can get a virtual CPU of the same performance as your personal computer
  for USD 0.077 per hour (i.e., 7.7 cents per hour per virtual CPU). What will it cost, in dollars, 
  to run this computation?  
```
your_answer_here dollars
```

Wouldn't it be nice if we could test ElectionGuard without requiring all of this 4000-bit
arithmetic? Here's a set of parameters that satisfy all the same primality requirements as
the "real" ElectionGuard parameters:
```
p = 65267
q = 32633
r = 2
g = 3
```

- If you put these in, do all the unit tests still pass? If any of them
  failed, was it a bug in the ElectionGuard code or a bug in the unit test?
```
Your answer here. Just two or three sentences.
```
- Now how many ballots per second is your benchmark? 
```
your answer here ballots/second
```
- Obviously, with these small parameters, the system isn't secure any more.
  But how might these assist you in testing ElectionGuard and finding bugs?
```
Your answer here. Just two or three sentences.
```
Lastly, make sure that you don't accidentally commit these smaller parameters to
the GitHub repository. We want to test your code against the "real" ElectionGuard.