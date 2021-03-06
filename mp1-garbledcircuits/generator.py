"""
# Problem 2: Garbled Circuit Generator (20 points)
"""

from Crypto import Util
import circuit
from circuit import BooleanCircuit
import json
from util import specialDecryption, specialEncryption, generate_key, random_bytes
import os
import random

"""
## Problem 2.01: implement a random shuffling routine (5 points)
Hint: use knuth-fischer-yates shuffling

    Use util.random_bytes for randomness.

    http://www.i-programmer.info/programming/theory/2744-how-not-to-shuffle-the-kunth-fisher-yates-algorithm.html

    Note: random.shuffle() from python stdlib does not count!
"""
def shuffle(a):
    assert type(a) is list
    # TODO: sort a in place, and return None
    for i in range(len(a)-1, 0, -1):
        # print(i)
        rbytes = random_bytes(16)
        j = int(rbytes.hex(), 16) % (i+1)
        a[i], a[j] = a[j], a[i]
    return

"""
## Problem 2: Garbled Circuit Generator (15 points)
"""

class GarbledCircuitGenerator(BooleanCircuit):
    def __init__(self, from_json=None):
        # The superclass constructor initializes the gates and topological sorting
        super(GarbledCircuitGenerator,self).__init__(from_json=from_json)

    def garble(self):
        
        # Generate new wire labels
        self.wire_labels = {} # maps wire id to {"0":label0 ,"1": label1}

        # TODO: your code goes here
        for i in self.gates.keys():
            for wire in self.wires:
                key1, key2 = generate_key(), generate_key()
                self.wire_labels[wire] = [key1.hex(), key2.hex()]

        # Generate garble tables
        self.garble_table = {}              # dict of list of str

        # TODO: your code goes here
        for i in self.gates.keys():         # i = g3, g2, g1
            g_table = []
            gate = self.gates[i]
            # choose input and type
            for (idx, (in1, in2)) in enumerate([(0, 0), (0, 1), (1, 0), (1, 1)]):
                # print(idx, in1, in2)
                out = gate["table"][idx]
                out_label = self.wire_labels[gate["out"][0]][out]
                in1_label = self.wire_labels[gate["inp"][0]][in1]
                in2_label = self.wire_labels[gate["inp"][1]][in2]
                _tmp = specialEncryption(bytes.fromhex(in2_label), bytes.fromhex(out_label))
                ans = specialEncryption(bytes.fromhex(in1_label), _tmp)
                g_table.append(ans.hex())
                shuffle(g_table)
            self.garble_table[i] = g_table  

    def output(self, outfile, inputs=None, debug=True):
        # Save as a JSON file, with wire lables for debugging
        obj = {}
        gates = {}
        for gid,gate in self.gates.items():
            gates[gid] = gate.copy() # Copy the gate object directly
            gates[gid]["garble_table"] = self.garble_table[gid]
        obj["gates"] = gates

        # Output wire labels in debug mode
        if debug: 
            obj["wire_labels"] = self.wire_labels

        if inputs is not None:
            print('Input available')
            assert len(inputs) == len(self.input_wires)
            input_labels = {}
            for wid,v in inputs.items():
                assert v in (0,1)
                input_labels[wid] = self.wire_labels[wid][v]
                obj["inputs"] = input_labels

        with open(outfile,"w") as f:
            json.dump(obj, f, indent=4)
        print('Wrote garbled circuit', outfile)

if __name__ == '__main__':
    # a = [0, 1, 2, 3, 4, 5, 6]
    # shuffle(a)
    import sys
    if len(sys.argv) < 3:
        print("usage: python generator.py <circuit.json> <outfile.json>")
        sys.exit(1)

    filename = sys.argv[1]
    obj = json.load(open(filename))

    # Circuit
    c = GarbledCircuitGenerator(from_json=obj)
    print('Circuit loaded: %d gates, %d input wires, %d output_wires, %d total' \
        % (len(c.gates), len(c.input_wires), len(c.output_wires), len(c.wires)))
    
    # Generate the circuit
    c.garble()

    # Load the inputs
    inputs = obj["inputs"]

    # Write the output
    outfile = sys.argv[2]
    c.output(outfile, inputs)
