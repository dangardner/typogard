#-------------------------------------------------------------------------
#   Name:
#       TypoGard-Crates
#
#   Description:
#       Applies a set of transformations to a given crate name and
#       the names of all (if any) of that crate's transitive
#       dependencies in an attempt to detect typosquatting attacks.
#
#   Usage:
#       py typogard_crates.py
#-------------------------------------------------------------------------

#-------------------------------------------------------------------------
#                               IMPORTS
#-------------------------------------------------------------------------
import re
import os
import sys
import argparse
import psycopg2
import psycopg2.extras
import spacy
import semver
import requests
from blip import blip
from typing import List
from itertools import permutations
from rapidfuzz.distance import Levenshtein
from functools import cmp_to_key

#-------------------------------------------------------------------------
#                              CONSTANTS
#-------------------------------------------------------------------------

# By default, only check for crates with versions created/updated within this number of days
DEFAULT_CHECK_DAYS = 3

# Default number of most popular crates to consider as typosquatting targets
DEFAULT_MOST_POPULAR = 3000

# Default similarity threshold over which we consider crate descriptions similar
DEFAULT_SIMILARITY_THRESHOLD = 0.97

# Default Levenshtein distance threshold under which we consider crate descriptions similar
DEFAULT_LEVENSHTEIN_THRESHOLD = 10

# Default crate download directory
DEFAULT_CRATE_DOWNLOAD_DIR = '/var/tmp/cratefiles'

# Default database configuration file
DEFAULT_DB_CONFIG = 'db.conf'

# Crate download URL
CRATE_DOWNLOAD_URL = 'https://crates.io/api/v1/crates/{}/{}/download'

# Regular expression for crate files
CRATE_FILE_REGEX = re.compile('^[A-Za-z0-9_-]+-(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?\.crate$')

# Delimiters allowed by crates.io
DELIMITER_REGEX = re.compile('[_-]')
DELIMITERS = ['', '-', '_']

# Basic regular expression for version numbers after a package name
VERSION_NUMBER_REGEX = re.compile('^(.*?)[_-]?\d+$')

# List of characters allowed in a package name
ALLOWED_CHARACTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-_'

# Regular expression for valid crate names
CRATE_NAME_REGEX = re.compile('^[A-Za-z0-9_-]+$')

# Dictionary containing reasonable typos for each of the allowed
# characters based on QWERTY keyboard locality and visual
# similarity
TYPOS = {
    '1': ['2', 'q', 'i', 'l'],
    '2': ['1', 'q', 'w', '3'],
    '3': ['2', 'w', 'e', '4'],
    '4': ['3', 'e', 'r', '5'],
    '5': ['4', 'r', 't', '6', 's'],
    '6': ['5', 't', 'y', '7'],
    '7': ['6', 'y', 'u', '8'],
    '8': ['7', 'u', 'i', '9'],
    '9': ['8', 'i', 'o', '0'],
    '0': ['9', 'o', 'p', '-'],
    '-': ['_', '0', 'p', '.', ''],
    '_': ['-', '0', 'p', '.', ''],
    'q': ['1', '2', 'w', 'a'],
    'w': ['2', '3', 'e', 's', 'a', 'q', 'vv'],
    'e': ['3', '4', 'r', 'd', 's', 'w'],
    'r': ['4', '5', 't', 'f', 'd', 'e'],
    't': ['5', '6', 'y', 'g', 'f', 'r'],
    'y': ['6', '7', 'u', 'h', 't', 'i'],
    'u': ['7', '8', 'i', 'j', 'y', 'v'],
    'i': ['1', '8', '9', 'o', 'l', 'k', 'j', 'u', 'y'],
    'o': ['9', '0', 'p', 'l', 'i'],
    'p': ['0', '-', 'o'],
    'a': ['q', 'w', 's', 'z'],
    's': ['w', 'd', 'x', 'z', 'a', '5'],
    'd': ['e', 'r', 'f', 'c', 'x', 's'],
    'f': ['r', 'g', 'v', 'c', 'd'],
    'g': ['t', 'h', 'b', 'v', 'f'],
    'h': ['y', 'j', 'n', 'b', 'g'],
    'j': ['u', 'i', 'k', 'm', 'n', 'h'],
    'k': ['i', 'o', 'l', 'm', 'j'],
    'l': ['i', 'o', 'p', 'k', '1'],
    'z': ['a', 's', 'x'],
    'x': ['z', 's', 'd', 'c'],
    'c': ['x', 'd', 'f', 'v'],
    'v': ['c', 'f', 'g', 'b', 'u'],
    'b': ['v', 'g', 'h', 'n'],
    'n': ['b', 'h', 'j', 'm'],
    'm': ['n', 'j', 'k', 'rn'],
    '.': ['-', '_', '']
}

#-------------------------------------------------------------------------
#                               GLOBALS
#-------------------------------------------------------------------------
popular_package_list = None
popular_package_set = None
popular_bitflips = None
crates = None
args = None

#-------------------------------------------------------------------------
#                              FUNCTIONS
#-------------------------------------------------------------------------

def get_most_popular_package(packages: List[str]) -> str:
    """
    Returns the most popular package in the given list 'packages'. The most popular
    package is whichever one comes first in the user-specified list of popular packages
    """

    # Convert packages to a set for faster lookups
    packages_set = set(packages)

    # Loop through all popular packages
    for popular_package in popular_package_list:

        # Check if the current popular_package is in the given package list
        if popular_package in packages_set:

            # If it is, return the popular package name
            return popular_package

    # If we couldn't find any of the given packages in the popular_package_list,
    # just return the first package in the list by default
    return packages[0]


# check if two crates have an author in common
def same_author(p1, p2):
    """
    Checks if two crates have an author in common
    """

    for author in crates[p1]['authors']:
        if author in crates[p2]['authors']:
            return True

    return False


def repeated_characters(package_name: str, return_all: bool=True) -> List[str]:
    """
    Removes any identical consecutive characters to check for typosquatting by repeated characters.
    For example, 'reeact' could be typosquatting 'react'. Returns a list of possible typosquatting
    targets from the given popular_package_set.

    Arguments:
        package_name: The name of the potential typosquatting package being analyzed.

        return_all: Whether or not to return all matches. If False, only return the most
            popular match.
    """

    # Initialize a list to hold results
    potential_typosquatting_targets = []

    # Loop through each character in the package name
    for i, c in enumerate(package_name):

        # If the next character in the given package_name is the same as the current one
        if i + 1 < len(package_name) and package_name[i + 1] == c:

            # Build a new package name by removing the duplicated character
            s = package_name[:i] + package_name[i + 1:]

            # If the new package name is in the list of popular packages, record it
            if s in popular_package_set and not same_author(package_name, s) and s != package_name:
                potential_typosquatting_targets.append(s)

    # If the user has requested to return all results or there were no results
    if return_all or len(potential_typosquatting_targets) == 0:

        # simply return whatever we have
        return potential_typosquatting_targets

    # If there is at least one package and the user only wants one
    else:

        # return the most popular package
        # return in a list to match other function return styles
        return [get_most_popular_package(potential_typosquatting_targets)]


def omitted_chars(package_name: str, return_all: bool=True) -> List[str]:
    """
    Inserts allowed characters into file name to check for typosquatting by omission. For example,
    'evnt-stream' could be typosquatting 'event-stream'. Returns a list of potential typosquatting
    targets from the given popular_package_set.

    Arguments:
        package_name: The name of the potential typosquatting package being analyzed.

        return_all: Whether or not to return all matches. If False, only return the most
            popular match.
    """

    # Initialize a list to hold results
    potential_typosquatting_targets = []

    # Do not apply this check to short package names.
    # This helps reduce the false positive rate
    if len(package_name) < 4:
        return potential_typosquatting_targets

    # Loop through every position in the given package_name
    for i in range(len(package_name) + 1):

        # Loop through every character in the list of allowed characters
        for c in ALLOWED_CHARACTERS:

            # Build a new package name by inserting the current character in the current position
            s = package_name[:i] + c + package_name[i:]

            # If the new package name is in the list of popular packages, record it
            if s in popular_package_set and not same_author(package_name, s) and s != package_name:
                potential_typosquatting_targets.append(s)


    # If the user has requested to return all results or there were no results
    if return_all or len(potential_typosquatting_targets) == 0:

        # simply return whatever we have
        return potential_typosquatting_targets

    # If there is at least one package and the user only wants one
    else:

        # return the most popular package
        # return in a list to match other function return styles
        return [get_most_popular_package(potential_typosquatting_targets)]


def swapped_characters(package_name: str, return_all: bool=True) -> List[str]:
    """
    Swaps consecutive characters in the given package_name to search for typosquatting.
    Returns a list of potential targets from the given popular_package_set. For
    example, 'loadsh' is typosquatting 'lodash'.

    Arguments:
        package_name: The name of the potential typosquatting package being analyzed.

        return_all: Whether or not to return all matches. If False, only return the most
            popular match.
    """

    # Initialize a list to hold results
    potential_typosquatting_targets = []

    # Loop through all pairs of consecutive characters in the given package_name
    for i in range(len(package_name) - 1):

        # Swap the two characters to create a new package name
        a = list(package_name)
        t = a[i]
        a[i] = a[i + 1]
        a[i + 1] = t
        s = ''.join(a)

        # If the new package name is in the list of popular packages, record it
        if s in popular_package_set and not same_author(package_name, s) and s != package_name:
            potential_typosquatting_targets.append(s)

    # If the user has requested to return all results or there were no results
    if return_all or len(potential_typosquatting_targets) == 0:

        # simply return whatever we have
        return potential_typosquatting_targets

    # If there is at least one package and the user only wants one
    else:

        # return the most popular package
        # return in a list to match other function return styles
        return [get_most_popular_package(potential_typosquatting_targets)]


def swapped_words(package_name: str, return_all: bool=True) -> List[str]:
    """
    Reorders package_name substrings separated by delimiters to look for typosquatting.
    Also check for delimiter substitution and omission. For example, 'stream-event' and
    'event.stream' are typosquatting 'event-stream'.

    Arguments:
        package_name: The name of the potential typosquatting package being analyzed.

        return_all: Whether or not to return all matches. If False, only return the most
            popular match.
    """

    # Initialize a list to hold results
    potential_typosquatting_targets = []

    # Return no targets for package names with no delimiters
    if DELIMITER_REGEX.search(package_name) is None:
        return potential_typosquatting_targets

    # Split package name on each delimiter, isolating each word
    tokens = DELIMITER_REGEX.sub(' ', package_name).split()

    # This function has factorial time complexity. To avoid
    # extremely long execution times, limit the number of tokens
    # allowed to be processed
    if len(tokens) > 8:
        return potential_typosquatting_targets

    # Get all possible permutations of the words in the package name
    for p in permutations(tokens):

        # Loop through all allowed delimiter characters
        for d in DELIMITERS:

            # Join the words using the current delimiter to create a new package name
            s = d.join(p)

            # If the new package name is in the list of popular packages, record it
            if s in popular_package_set and not same_author(package_name, s) and s != package_name:
                potential_typosquatting_targets.append(s)

    # If the user has requested to return all results or there were no results
    if return_all or len(potential_typosquatting_targets) == 0:

        # simply return whatever we have
        return potential_typosquatting_targets

    # If there is at least one package and the user only wants one
    else:

        # return the most popular package
        # return in a list to match other function return styles
        return [get_most_popular_package(potential_typosquatting_targets)]


def common_typos(package_name: str, return_all: bool=True) -> List[str]:
    """
    Applies each of the common typos to each of the characters in the given package_name.
    Checks if each result is in the list of popular package names and returns a list of
    any matches.

    Arguments:
        package_name: The name of the potential typosquatting package being analyzed.

        return_all: Whether or not to return all matches. If False, only return the most
            popular match.
    """

    # Initialize a list to hold results
    potential_typosquatting_targets = []

    # Loop through all characters in the given package_name
    for i, c in enumerate(package_name):

        # Ensure the character is in the common typo dict
        if c in TYPOS:

            # Loop through each common typo for the given character
            for t in TYPOS[c]:

                # Build a new package name, replacing the character with the current typo character
                typo_package_name = list(package_name)
                typo_package_name[i] = t
                typo_package_name = ''.join(typo_package_name)

                # Check if the new package name is in the list of popular packages
                if typo_package_name in popular_package_set and not same_author(package_name, typo_package_name) and typo_package_name != package_name:
                    potential_typosquatting_targets.append(typo_package_name)

    # If the user has requested to return all results or there were no results
    if return_all or len(potential_typosquatting_targets) == 0:

        # simply return whatever we have
        return potential_typosquatting_targets

    # If there is at least one package and the user only wants one
    else:

        # return the most popular package
        # return in a list to match other function return styles
        return [get_most_popular_package(potential_typosquatting_targets)]


def version_numbers(package_name: str) -> List[str]:
    """
    Checks if the given package_name adds a version number to the end of a
    popular package name. For example, 'react-2' and 'react2' could be typosquatting
    the popular package 'react'.

    Arguments:
        package_name: The name of the potential typosquatting package being analyzed.
    """

    # Match the given package name on the version number regular expression
    m = VERSION_NUMBER_REGEX.match(package_name)

    # If a match was found
    if m is not None:

        # Check if the match is in the list of popular packages
        s = m.group(1)
        if s in popular_package_set and not same_author(package_name, s) and s != package_name:

            # Return the result in a list to conform with other function return types
            return [s]

    # If no match was found, simply return an empty list, showing no possible targets were found
    return []


def bitflips(package_name: str) -> List[str]:
    """
    Checks if the given package_name is squatting a single bitflip of a popular package.

    Arguments:
        package_name: The name of the potential typosquatting package being analyzed.
    """
    # Check if the package name matches one of our pre-computed bitflips and return it
    if package_name in popular_bitflips:
        return popular_bitflips[package_name]

    # If no match was found, simply return an empty list, showing no possible targets were found
    return []


def allowlisted(package_name):
    # Ignore known non-malicious typosquatters with expected metadata signatures:
    # * blallo - https://troubles.noblogs.org/post/2021/03/29/why-so-much-ado-with-crates-io/
    # * skerkour - https://kerkour.com/rust-crate-backdoor
    c = crates[package_name]
    if set(c['authors']) == {'blallo'} and c['homepage'] == 'https://xkcd.com/386' and c['documentation'] == 'https://crates.io/policies' and c['repository'] == 'https://github.com/blallo/xkcd-386':
        return True
    if set(c['authors']) == {'skerkour'} and c['repository'] == 'https://github.com/skerkour/black-hat-rust':
        return True
    return False


def get_typosquatting_targets(package_name: str, nlp) -> List[str]:
    """
    Applies all typosquatting signals to the given package_name.
    Returns any potential typosquatting targets found in the given package_list.

    Arguments:
        package_name: The name of the potential typosquatting package being analyzed.
    """

    # If the given package_name is in the given package_list, return no suspected targets
    # By our definition, a popular package cannot be typosquatting
    if package_name in popular_package_set:
        return []

    # Ignore known non-malicious typosquatters
    if allowlisted(package_name):
        return []

    # Initialize a list used to hold possible typosquatting targets
    potential_typosquatting_targets = []

    # Check the given package name for typosquatting
    potential_typosquatting_targets += repeated_characters(package_name)
    potential_typosquatting_targets += omitted_chars(package_name)
    potential_typosquatting_targets += swapped_characters(package_name)
    potential_typosquatting_targets += swapped_words(package_name)
    potential_typosquatting_targets += common_typos(package_name)
    potential_typosquatting_targets += version_numbers(package_name)
    potential_typosquatting_targets += bitflips(package_name)

    # Remove any duplicate package names
    potential_typosquatting_targets = list(set(potential_typosquatting_targets))

    # Filter potential targets according to other metadata (description etc.)
    potential_typosquatting_targets = filter_targets(nlp, package_name, potential_typosquatting_targets)

    # Return possible targets
    return potential_typosquatting_targets


def blips(package_name: str) -> List[str]:
    """
    Uses blip to generate all valid crate names that are single bitflips away
    from the given package_name.

    Arguments:
        package_name: Package name to generate bitflips from
    """
    binary_blips = blip.get_blips(package_name)
    string_blips = blip.get_string_blips(binary_blips)
    return [ bf for bf in string_blips if CRATE_NAME_REGEX.search(bf) is not None ]


def get_database_cursor():
    with open (os.path.join(os.path.realpath(os.path.dirname(__file__)), args.db_config)) as configfile:
        connect_params = configfile.read()
    conn = psycopg2.connect(connect_params)
    return conn.cursor(cursor_factory = psycopg2.extras.RealDictCursor)


def get_top_crates(cur, limit):
    cur.execute("""
        SELECT
            crates.name AS name,
            COALESCE(users.gh_login, teams.login) AS login,
            crates.homepage AS homepage,
            crates.repository AS repository,
            crates.documentation AS documentation,
            crates.description AS description,
            crates.downloads AS downloads
        FROM (
            SELECT crates.*, recent_crate_downloads.downloads AS recent_downloads
            FROM crates
            LEFT JOIN recent_crate_downloads ON (crates.id = recent_crate_downloads.crate_id)
            ORDER BY recent_crate_downloads.downloads DESC
            LIMIT %s
        ) AS crates
        LEFT JOIN crate_owners ON (crates.id = crate_owners.crate_id)
        LEFT JOIN users ON (crate_owners.owner_id = users.id AND crate_owners.owner_kind = 0 AND NOT crate_owners.deleted)
        LEFT JOIN teams ON (crate_owners.owner_id = teams.id AND crate_owners.owner_kind = 1 AND NOT crate_owners.deleted)
        ORDER BY crates.recent_downloads DESC""", (limit,))
    return cur.fetchall()


def get_crates_to_check(cur, limit, days):
    cur.execute("""
        SELECT
            crates.name AS name,
            COALESCE(users.gh_login, teams.login) AS login,
            crates.homepage AS homepage,
            crates.repository AS repository,
            crates.documentation AS documentation,
            crates.description AS description,
            crates.downloads AS downloads
        FROM (
            SELECT crates.*, recent_crate_downloads.downloads AS recent_downloads
            FROM crates
            LEFT JOIN recent_crate_downloads ON (crates.id = recent_crate_downloads.crate_id)
            ORDER BY recent_crate_downloads.downloads DESC
            OFFSET %s
        ) AS crates
        LEFT JOIN crate_owners ON (crates.id = crate_owners.crate_id)
        LEFT JOIN users ON (crate_owners.owner_id = users.id AND crate_owners.owner_kind = 0 AND NOT crate_owners.deleted)
        LEFT JOIN teams ON (crate_owners.owner_id = teams.id AND crate_owners.owner_kind = 1 AND NOT crate_owners.deleted)
        LEFT JOIN versions ON (crates.id = versions.crate_id)
        WHERE
            NOT versions.yanked
            AND versions.updated_at > (CURRENT_DATE - INTERVAL '%s days')
        ORDER BY crates.recent_downloads DESC""", (limit, days))
    return cur.fetchall()


def get_latest_version(cur, package_name):
    cur.execute("""
        SELECT
            versions.num AS num
        FROM crates
        LEFT JOIN versions ON (crates.id = versions.crate_id AND NOT versions.yanked)
        WHERE crates.name = %s""", (package_name,))
    versions = sorted([ r['num'] for r in cur.fetchall() ], key=cmp_to_key(lambda x, y: semver.VersionInfo.parse(x).compare(y)))
    return versions[-1] if len(versions) else None


def download_latest(cur, package_name):
    if not os.path.exists(args.crate_download_dir):
        os.mkdir(args.crate_download_dir)
    ver = get_latest_version(cur, package_name)
    if ver is None:
        return None
    url = CRATE_DOWNLOAD_URL.format(package_name, ver)
    r = requests.get(url, allow_redirects=False)
    if r.status_code != 302:
        raise RuntimeError(f"Unexpected HTTP response {r.status_code} fetching {url}")
    if 'location' not in r.headers:
        raise RuntimeError(f"Found 302 redirect without Location header fetching {url}")
    loc = r.headers['location']
    crate_file = loc.split('/')[-1]
    if CRATE_FILE_REGEX.search(crate_file) is None:
        raise RuntimeError(f"Invalid crate filename {crate_file} from {url}")
    r = requests.get(loc, allow_redirects=False)
    if r.status_code != 200:
        raise RuntimeError(f"Unexpected HTTP response {r.status_code} fetching {loc}")
    local_file = os.path.join(args.crate_download_dir, crate_file)
    with open(local_file, 'wb') as out:
        out.write(r.content)
    return local_file


def populate_crate_lists(cur):
    # Read popular package list
    global crates
    crates = {}
    top_crates_with_authors = get_top_crates(cur, args.most_popular)
    for r in top_crates_with_authors:
        c = crates.setdefault(r['name'], {
            **{ k:r[k] for k in r.keys() if k != 'login' },
            **{ 'authors': [] }
        })
        c['authors'].append(r['login']) # needs Python 3.6+ to preserve order

    global popular_package_list
    popular_package_list = crates.keys()

    # Create a set containing all popular package names for faster lookups
    global popular_package_set
    popular_package_set = set(popular_package_list)
    if len(popular_package_set) != args.most_popular:
        print(f"Popular package set size mismatch ({len(popular_package_set)} != {args.most_popular})")
        sys.exit(1)

    # Get the rest of the crates to check
    other_crates_with_authors = get_crates_to_check(cur, args.most_popular, args.check_days)
    for r in other_crates_with_authors:
        c = crates.setdefault(r['name'], {
            **{ k:r[k] for k in r.keys() if k != 'login' },
            **{ 'authors': [] }
        })
        c['authors'].append(r['login']) # needs Python 3.6+ to preserve order

    # Generate bitflips for populate crates
    generate_bitflips()


def generate_bitflips():
    # Generate all variations with single-bit flips for the most popular crate names
    global popular_bitflips
    popular_bitflips = {}
    for crate_name in popular_package_set:
        for bf in blips(crate_name):
            popular_bitflips.setdefault(bf, []).append(crate_name)


def filter_targets(nlp, package, potential_targets):
    # Retain only potential typosquatters with similar descriptions
    if crates[package]['description'] is None or crates[package]['description'].strip() == '':
        return { t:100 for t in potential_targets if crates[t]['description'] is None or crates[t]['description'].strip() == '' }
    targets = {}
    refdoc = nlp(crates[package]['description'])
    # if spaCy can't help us, fall back to Levenshtein distance
    if not refdoc.vector_norm:
        for t in potential_targets:
            dist = Levenshtein.distance(crates[package]['description'], crates[t]['description'])
            if dist < args.levenshtein_threshold:
                targets[t] = dist
    else:
        for t in potential_targets:
            d = crates[t]['description']
            if d is not None and d.strip() != '':
                thisdoc = nlp(d)
                if not thisdoc.vector_norm:
                    raise ValueError(f"No vector_norm for potential target {t} ({d})")
                sim = refdoc.similarity(thisdoc)
                if sim > args.similarity_threshold:
                    targets[t] = sim
    return targets


def parse_arguments():
    global args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--days", type=int,
                        default=DEFAULT_CHECK_DAYS,
                        dest="check_days",
                        help="Only check for crates with versions created/updated within this number of days")
    parser.add_argument("--top", type=int,
                        default=DEFAULT_MOST_POPULAR,
                        dest="most_popular",
                        help="Number of most popular crates to consider as typosquatting targets")
    parser.add_argument("--similarity-threshold", type=float,
                        default=DEFAULT_SIMILARITY_THRESHOLD,
                        dest="similarity_threshold",
                        help="Similarity threshold in the range 0-1, over which we consider crate descriptions similar")
    parser.add_argument("--lev-threshold", type=int,
                        default=DEFAULT_LEVENSHTEIN_THRESHOLD,
                        dest="levenshtein_threshold",
                        help="Levenshtein distance threshold under which we consider crate descriptions similar")
    parser.add_argument("--download-dir", type=str,
                        default=DEFAULT_CRATE_DOWNLOAD_DIR,
                        dest="crate_download_dir",
                        help="Directory into which discovered crates will be downloaded, will be created if necessary")
    parser.add_argument("--dbconf", type=str,
                        default=DEFAULT_DB_CONFIG,
                        dest="db_config",
                        help="Database configuration file")
    args = parser.parse_args()


def main():
    """TypoGard entry point"""

    # Make warnings errors
    if not sys.warnoptions:
        import warnings
        warnings.simplefilter("error")

    # Parse command line arguments
    parse_arguments()

    # Connect to the database
    cur = get_database_cursor()

    # Populate the global crate lists
    populate_crate_lists(cur)

    # Load the spaCy model for comparing crate descriptions
    nlp = spacy.load('en_core_web_lg')

    print(f'Found {len(crates) - len(popular_package_set)} crates with new/updated versions in the past {args.check_days} days')

    # Loop through all crates to be checked
    potential_typosquatting_found = 0
    for crate_name in sorted(crates):
        # Check each crate for typosquatting
        targets = get_typosquatting_targets(crate_name, nlp)

        # Ignore crates with no potential typosquatting found
        if len(targets) == 0:
            continue

        # Alert the user if potential typosquatting was found
        potential_typosquatting_found += 1

        localfile = download_latest(cur, crate_name)
        if localfile is None:
            localfile = "no versions available"

        print(f"WARNING: {crate_name} ({localfile}) with {crates[crate_name]['downloads']} downloads could be typosquatting any of these crates: {targets}")


    if potential_typosquatting_found > 0:
        print(f'Typosquatting detection complete - {potential_typosquatting_found} potential typosquatting crates detected.')
        sys.exit(42)

    print('Typosquatting detection complete - no typosquatting detected.')


if __name__ == '__main__':
    main()
