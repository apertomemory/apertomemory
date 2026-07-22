# ApertoMemory (italiano)

Memoria AI portabile, cifrata lato client, di proprietà dell'utente.
La documentazione principale del progetto è in inglese: vedi
[README.md](README.md).

Installazione (richiede Python 3.10+): `pipx install apertomemory` —
comando `amem`, formato `.amem`. Su macOS con Homebrew un `pip install`
diretto viene rifiutato da PEP 668: usare pipx o un virtualenv.

Chi arriva dalla 0.1.x deve eseguire `amem migrate` dopo
l'aggiornamento: gli oggetti scritti prima del `format_version` 2 non
hanno il vincolo fra firma, autore e involucro, e si aprono come
`unverified` finché non vengono ri-sigillati. Vedi
[CHANGELOG.md](CHANGELOG.md).
