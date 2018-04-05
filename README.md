## Go Implementation of Bulletproofs

This project implements bulletproofs in Go http://web.stanford.edu/~buenz/pubs/bulletproofs.pdf 

Originally based on https://github.com/ wrv/bp-go. Research quality code.

Support has been added to be used in a UTXO based blockchain; including deterministic blinding factors 
based on ECDH.

Currently uses a different generator to the stanford example, so cannot be verified in the original java example from Stanford.

TODO
- Match generators
- Add more testing
- Turn research code into a library