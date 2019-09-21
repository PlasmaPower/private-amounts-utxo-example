# Private amounts UTXO example

An example of a UTXO ledger with optionally private amounts, using bulletproofs.
Commitments are done on the ristretto curve, but signatures are normal ed25519
for interop. Because of that, there's a separate blinding/commitment signature.

Of course, **don't use this code in anything serious**. I'm not cryptographer,
and I haven't reviewed this too carefully. It's just an example.
