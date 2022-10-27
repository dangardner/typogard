# TypoGard
TypoGard is a client-side tool created to protect users from [package typosquatting attacks](https://snyk.io/blog/typosquatting-attacks/). TypoGard was originally implemented as a standalone tool for npm, but it can easily be extended to other languages and can even be embedded in package installation software.

# TypoGard-Crates
TypoGard-Crates is a fork of TypoGard with support for the [crates.io](https://crates.io/) registry. It implements the following additional features:
* Queries a local Postgres instance containing a nightly crates.io database dump
* Bit-flip detection - detects single bit-flip variations of popular crates
* Filtering based on similarity of package descriptions (using [spacy NLP](https://spacy.io/), falling back to Levenshtein distance)
* Uses crate authors instead of namespaces to identify common ownership
* Downloads tarballs of potentially typosquatting crates, to make investigation more convenient
* Ignores known non-malicious typosquatters with expected metadata signatures:
  * blallo - <https://troubles.noblogs.org/post/2021/03/29/why-so-much-ado-with-crates-io/>
  * skerkour - <https://kerkour.com/rust-crate-backdoor>

## How TypoGard Works
TypoGard works by applying a number of transformations to a given package name and comparing the results to a list of popular package names. These transformations are based on the same transformations made by malicious actors in past package typosquatting attacks. For more detailed information, read the [TypoGard paper on arXiv](https://arxiv.org/abs/2003.03471) (the tool was referred to as SpellBound at the time of publication).

## TypoGard-Crates Requirements
The version of TypoGard in this repository, which specifically targets crates.io, relies on the following:
* [Python3](https://www.python.org/downloads/) (tested with Python 3.7.10, but other versions may work too)
* [psycopg2](https://pypi.org/project/psycopg2/) for Postgres client functionality
* [spaCy](https://pypi.org/project/spacy/) for NLP-based crate description similarity scoring
* [semver](https://pypi.org/project/semver/) to compare semantic versions of crates
* [requests](https://pypi.org/project/requests/) to fetch crate tarballs from crates.io
* [blip](https://pypi.org/project/blip/) to calculate single bit-flip variations
* [rapidfuzz](https://pypi.org/project/rapidfuzz/) to calculate Levenshtein distance

## TypoGard-Crates Usage

```
usage: typogard_crates.py [-h] [--days CHECK_DAYS] [--top MOST_POPULAR]
                          [--similarity-threshold SIMILARITY_THRESHOLD]
                          [--lev-threshold LEVENSHTEIN_THRESHOLD]
                          [--download-dir CRATE_DOWNLOAD_DIR]
                          [--dbconf DB_CONFIG]

optional arguments:
  -h, --help            show this help message and exit
  --days CHECK_DAYS     Only check for crates with versions created/updated
                        within this number of days (default: 3)
  --top MOST_POPULAR    Number of most popular crates to consider as
                        typosquatting targets (default: 3000)
  --similarity-threshold SIMILARITY_THRESHOLD
                        Similarity threshold in the range 0-1, over which we
                        consider crate descriptions similar (default: 0.97)
  --lev-threshold LEVENSHTEIN_THRESHOLD
                        Levenshtein distance threshold under which we consider
                        crate descriptions similar (default: 10)
  --download-dir CRATE_DOWNLOAD_DIR
                        Directory into which discovered crates will be
                        downloaded, will be created if necessary (default:
                        /var/tmp/cratefiles)
  --dbconf DB_CONFIG    Database configuration file (default: db.conf)
```

TypoGard fundamentally relies on a list of packages considered to be popular. TypoGard-Crates uses the nightly database dump from crates.io, allowing the user to specify the number of most popular crates with which to populate this list, and how many days in the past to look for newly published crate versions that may be typosquatting the most popular crates.

The database configuration file specified with `--dbconf` is in the standard psycopg2 format. See the file `db.conf.example` for an example configuration.

### Example Usage:

If one would like to determine whether any crates with new versions published in the last 3 days are typosquatting any of the 3000 most popular packages, they could use:

`python3 typogard_crates.py`

This will notify the user and download the tarballs of any crates that appear to be typosquatting.
