Machine Problem 4: Election Guard
=========================================
This is the fourth machine problem for ECE/CS 407 Cryptography at the University of Illinois at Urbana-Champaign. http://soc1024.ece.illinois.edu/teaching/ececs407/fa21

This assignment is a modified version of the course project in COMP 427 INTRO TO COMPUTER SECURITY of Rice University.

We include their original readme file `README.md`, slides `voting-crypto.pdf` and handout `handout-python.pdf` in directory `/handouts`.
Be sure to read these materials, which go into details of the election guard application, and include some of the math that you'll be converting to code.

The skeleton code includes regions clearly marked `#TODO` that you must fill out to complete the assignment.

Installation and setup
------------------------
Your project handout gives you additional details on how to configure
your computer with Python3.8 and the other necessary utilities.
After that, using **make**, you can do everything all at once:

```
make
```

The unit and integration tests can also be run with make:

```
make test
```

We would not use the github autograder. 
You only need to make sure that you could pass all the tests when running `make test`.

Submitting your solution
------------------------

To submit your solution:
- The due date is (**SEE THE COURSE WEBSITE**)
- You must upload your `mp4` folder as a zip file to Piazza. The file **must** be named `mp4`
- The upload must be marked "visible to Instructors"
- The `mp4` folder **must** contain a text file `report.txt`, which must include a short english-language narrative explaining:
    - your net id
    - what parts you finished, attempted, couldn't figure out
    - any parts you found interesting, challenging, questions you have
    - length can be one paragraph, or several... this is not an essay, but it may be used to justify partial credit
- **No partners are allowed for this machine problem.** You must do your own work on this MP
- You only need to finish the coding part and don't need to answer any written questions.
- We have removed `#TODO`s in `test_simple_elections_part1.py` and `test_simple_elections_part2.py`. 
    Only modify the `elgamal.py` and `simple_elections.py` files for part 1 and part 2.
- The decorator `weight()` before each test function denotes the points you will get if that test passes.
- We add part 3 on the basis of the original project, which requires you to perform the "How Not To Prove Yourself" attack on Election Guard.
Reach out to `/handouts/Bernhard2012_Chapter_HowNotToProveYourselfPitfallsO.pdf` section 3 CHUAN-PEDERSEN PROOFS for more details. 
You will modify `elgamal_malicious.py` file to finish this part. The main idea of the attack is that if the Chaum-Pedersen proofs 
instantiated with weak Fiat-Shamir transformation (challenge hashes only the commitment without statement), an adversary is able to create a 
fake proof which could pass the validation process but not correspond to the witness. You are required to create an honest proof along with the correct
partial decryption of the ElGamal encryption scheme. Correct partial decryptions lead to the success of the combination of those decryptions.
And then you need to create a fake proof that can also pass the validation process along with incorrect partial decryption.
This incorrect partial decryption will lead to the combination process running "forever" (if you uncomment line 289 in `test_simple_elections_part1.py`), 
as the corresponding plaintext is not stored in the table of the discrete log.