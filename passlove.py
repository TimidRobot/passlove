#!/usr/bin/python

"""Usage: passlove [options]

Generates a passwords using an OS specific cryptographically secure
pseudo-random number generator (CSPRNG)."""

# Standard Library
import itertools
import math
import optparse
from os import path
import cPickle
import random
import re
from string import (ascii_letters, ascii_lowercase, ascii_uppercase, digits,
                    punctuation)
import sys

# Third-party
# ...

# Variables
script_path = path.normcase(path.realpath(path.abspath(__file__)))
script_file = path.basename(script_path)
script_dir = path.dirname(script_path)
words_file = path.join(script_dir, "words.pkl")
word_min = 2
word_max = 6
names = ("short", "medium", "long")
ranges = {names[0]: (word_min, 3), names[1]: (word_min, 5),
          names[2]: (word_min, word_max)}

words = {"len": dict(),  # length: common words
         "let": dict(),  # 1st letter: common words
         "pos": dict(),  # part of speach: common words
         "num_ranges": {"common": dict(),    # ranges: number of words
                        "egiost": dict(),    # ranges: number of words
                        "pairs": dict(),     # ranges: number of words
                        "swapped": dict()},  # ranges: number of words
         "num_common": dict(),   # length: number of words
         "num_egiost": dict(),   # length: number of words
         "num_swapped": dict()}  # length: number of words
for name in names:
    words["num_ranges"]["common"][name] = 0
    words["num_ranges"]["egiost"][name] = 0
    words["num_ranges"]["pairs"][name] = 0
    words["num_ranges"]["swapped"][name] = 0

pos_desc = {"!": "Interjection", "A": "Adjective", "C": "Conjunction",
            "D": "Definite Article", "N": "Noun", "p": "Plural",
            "V": "Verb (usu participle)", "h": "Noun Phrase",
            "i": "Verb (intransitive)", "P": "Preposition", "r": "Pronoun",
            "t": "Verb (transitive)", "v": "Adverb"}
re_nonalpha = re.compile(r"[^a-z]")
re_vowels = re.compile(r"[aeiouy]", re.IGNORECASE)
egiost_replace = {"e": "3", "g": "9", "i": "1", "o": "0", "s": "5", "t": "7"}
# determine all "egiost" replacement combinations
egiost_combos = set()
for x in xrange(1, len(egiost_replace.keys())):
    for combination in itertools.combinations(egiost_replace.keys(), x):
        egiost_combos.add(combination)
gen = dict()
strength = {3: 80.0, 2: 72.0, 1: 63.0, 0: 28.0}
# NIST Special Publication 800-63 Version 1.0.2
strength["nis"] = strength[3]   # nist
# Good Strength
strength["goo"] = strength[2]   # good
strength["hig"] = strength[2]   # high
strength["str"] = strength[2]   # strong
# Moderate Strength
strength["med"] = strength[1]   # medium
strength["mod"] = strength[1]   # moderate
# Weak Strength
strength["low"] = strength[0]   # low
strength["wea"] = strength[0]   # weak
# Separators -  do no require shift key, considered injection-safe
sep_list = [",", ".", "/", "]", "-", "=", " "]
separator = dict()
separator["count"] = len(sep_list)
separator["entropy"] = math.log(separator["count"], 2)
# random.SystemRandom - "Class that uses the os.urandom() function for
#   generating random numbers from sources provided by the operating
#   system. Not available on all systems. Does not rely on software state and
#   sequences are not reproducible."
# os.urandom - "This function returns random bytes from an OS-specific
#   randomness source. The returned data should be unpredictable enough
#   for cryptographic applications"
srand = random.SystemRandom()


def gen_characters(min_entropy, explain=False):
    """Generate passwords containing a sequence of symbols. The symbols consist
    of "readable" characters: digits (excluding 0 and 1), ASCII letters
    (excluding I, O, i, and l), and punctuation (excluding double quotation
    ["], single quotation ['], and backtick [`])."""
    parts = list()
    symbol = dict()
    symbols = '%s%s%s' % (digits, ascii_letters, punctuation)
    symbols = symbols.translate(None, "IOil01\"'`")
    symbol["count"] = len(symbols)
    symbol["bits"] = math.log(symbol["count"], 2)
    symbol["entropy"] = min_entropy
    symbol["length"] = int(math.ceil(symbol["entropy"] / symbol["bits"]))
    if explain:
        # explain entropy
        explain_entropy(min_entropy, symbol, False)
        password = None
    else:
        # generate password
        for x in xrange(0, symbol["length"]):
            parts.append(srand.choice(symbols))
        password = "".join(parts)
    return password
gen["characters"] = gen_characters


def gen_groups_lownum(min_entropy, explain=False):
    """Generates passwords containing groups of symbols demarcated by a
    random separator. The symbols consist of "readable" characters: digits
    (excluding 0 and 1) and lowercase ASCII letters (excluding i and l)."""
    symbols = "%s%s" % (ascii_lowercase, digits)
    symbols = symbols.translate(None, "IOil01\"'`")
    if explain:
        # explain entropy
        grouped_symbols(min_entropy, symbols, True)
        password = None
    else:
        # generate password
        password = grouped_symbols(min_entropy, symbols)
    return password
gen["groups_lownum"] = gen_groups_lownum


def gen_groups_lower(min_entropy, explain=False):
    """Generates passwords containing groups of symbols demarcated by a
    random separator. The symbols consist of "readable" lowercase ASCII letters
    (excluding i and l)."""
    symbols = ascii_lowercase
    symbols = symbols.translate(None, "IOil01\"'`")
    if explain:
        # explain entropy
        grouped_symbols(min_entropy, symbols, True)
        password = None
    else:
        # generate password
        password = grouped_symbols(min_entropy, symbols)
    return password
gen["groups_lower"] = gen_groups_lower


def gen_pairs_allit(min_entropy, explain=False):
    """Generates passwords containing short alliterative word pairs in which
    the words within the pair are demarcated by a random separator."""
    pairs = list()
    sep = srand.choice(sep_list)
    length = "long"
    word_type = "pairs"
    # symbols already consist of pairs--there is no need to ensure even length
    r1, r2, symbol = word_symbol_info(min_entropy, word_type, length)
    if explain:
        # explain entropy
        explain_entropy(min_entropy, symbol)
        password = None
    else:
        # generate password
        pair_count = symbol["length"]
        for x in xrange(0, pair_count):
            word1 = srand.sample(words["len"][srand.randint(r1, r2)], 1)[0]
            word2 = srand.sample(words["let"][word1[0]], 1)[0]
            while len(word2) > 4:
                word2 = srand.sample(words["let"][word1[0]], 1)[0]
            pairs.append("%s%s%s" % (word1, sep, word2))
        password = " ".join(pairs)
    return password
gen["pairs_allit"] = gen_pairs_allit


def gen_pairs_swap(min_entropy, explain=False):
    """Generate passwords consisting of medium length word pairs in which the
    1st letter has been swapped and the words within the pair are demarcated
    by a random separator."""
    pairs = list()
    sep = srand.choice(sep_list)
    length = "medium"
    word_type = "swapped"
    r1, r2, symbol = word_symbol_info(min_entropy, word_type, length, True)
    if explain:
        # explain entropy
        explain_entropy(min_entropy, symbol)
        password = None
    else:
        # generate password
        pair_count = symbol["length"] / 2
        for x in xrange(0, pair_count):
            word1 = srand.sample(words["len"][srand.randint(r1, r2)], 1)[0]
            word2 = srand.sample(words["len"][srand.randint(r1, r2)], 1)[0]
            pairs.append("%s%s%s%s%s" % (word2[0], word1[1:], sep, word1[0],
                         word2[1:]))
        password = " ".join(pairs)
    return password
gen["pairs_swap"] = gen_pairs_swap


def gen_words(min_entropy, explain=False):
    """Generate passwords consisting of long words demarcated by a random
    separator."""
    parts = list()
    symbol = dict()
    length = "long"
    word_type = "common"
    sep = srand.choice(sep_list)
    r1, r2, symbol = word_symbol_info(min_entropy, word_type, length)
    if explain:
        # explain entropy
        explain_entropy(min_entropy, symbol)
        password = None
    else:
        # generate password
        for x in xrange(0, symbol["length"]):
            parts.append(
                    srand.sample(words["len"][srand.randint(r1, r2)], 1)[0])
        password = sep.join(parts)
    return password
gen["words"] = gen_words


def gen_words_egiost(min_entropy, explain=False):
    """Generate passwords consisting of medium length 'egiost' words demarcated
    by a random separator. 'egoist' words consist of all unique combinations of
    the following substitutions: e to 3, g to 9, i to 1, o to 0, s to 5, t to 7
    """
    parts = list()
    length = "medium"
    word_type = "egiost"
    sep = srand.choice(sep_list)
    r1, r2, symbol = word_symbol_info(min_entropy, word_type, length)
    if explain:
        # explain entropy
        explain_entropy(min_entropy, symbol)
        password = None
    else:
        # generate password
        for x in xrange(0, symbol["length"]):
            word = srand.sample(words["len"][srand.randint(r1, r2)], 1)[0]
            for l in srand.sample(egiost_combos, 1)[0]:
                word = word.replace(l, egiost_replace[l])
            parts.append(word)
        password = sep.join(parts)
    return password
gen["words_egiost"] = gen_words_egiost


def grouped_symbols(min_entropy, symbols, explain=False):
    """Generates passwords split into groups demarcated by a random
    separator."""
    groups = list()
    parts = list()
    symbol = dict()
    sep = srand.choice(sep_list)
    # determine symbol entropy information
    symbol["count"] = len(symbols)
    symbol["bits"] = math.log(symbol["count"], 2)
    symbol["entropy"] = min_entropy - separator["entropy"]
    symbol["length"] = int(math.ceil(symbol["entropy"] / symbol["bits"]))
    # determine optimal number of groups
    if symbol["length"] < 8:
        group_count = 2
    elif symbol["length"] <= 14:
        group_count = 3
    else:
        group_count = symbol["length"] / 5
    group_remain = symbol["length"] % group_count
    # determine symbol count in each group
    for x in xrange(0, group_count):
        group_length = symbol["length"] / group_count
        if group_remain > 0:
            group_length += 1
            group_remain -= 1
        groups.append(group_length)
    srand.shuffle(groups)

    if explain:
        # explain entropy
        explain_entropy(min_entropy, symbol)
        password = None
    else:
        # generate password
        for length in groups:
            chunk = list()
            for y in xrange(0, length):
                chunk.append(srand.choice(symbols))
            parts.append("".join(chunk))
        password = sep.join(parts)
    return password


def word_symbol_info(min_entropy, word_type, length, pairs=False):
    """Determine symbol information: count, bits of entropy, minimum entropy
    from symbols, number of symbols required to meet minimum symbol entropy,
    and word length range."""
    symbol = dict()
    symbol["count"] = words["num_ranges"][word_type][length]
    symbol["bits"] = math.log(symbol["count"], 2)
    symbol["entropy"] = min_entropy - separator["entropy"]
    symbol["length"] = int(math.ceil(symbol["entropy"] / symbol["bits"]))
    # round up to even number if we're dealing with pairs
    if pairs and symbol["length"] % 2 != 0:
        symbol["length"] += 1
    # word length range
    r1, r2 = ranges[length]
    return r1, r2, symbol


def explain_entropy(min_entropy, symbol, with_sep=True):
    symbol["entropy"] = (symbol["bits"] * float(symbol["length"]))
    if with_sep:
        password_entropy = symbol["entropy"] + separator["entropy"]
    else:
        password_entropy = symbol["entropy"]
    print ("    Symbol entropy: %9.2f bits (%d * %.2f bits of entropy "
           "from %d symbols)") % (symbol["entropy"], symbol["length"],
                                   symbol["bits"], symbol["count"])
    if with_sep:
        print ("    Separator entropy: %6.2f bits (1 * %.2f bits of entropy "
               "from %d symbols)") % (separator["entropy"],
                                      separator["entropy"], separator["count"])
    print "    Password entropy: %7.2f bits (%.2f bits requested)" % (
            password_entropy, min_entropy)


def load_words_file(words_file):
    """Load words file"""
    global words
    word_fo = open(words_file, "rb")
    words = cPickle.load(word_fo)
    word_fo.close()


def create_words_file(source_file, words_file):
    """Create words file"""
    global words
    temp = {"len_egiost": dict(), "len_swapped": dict()}

    def binomial_coeff(n, k):
        """calculate C(n, k) - the binomial coefficient
        >>> binomial_coeff(3, 2)
        3
        >>> binomial_coeff(9,4)
        126
        >>> binomial_coeff(9,6)
        84
        >>> binomial_coeff(20,14)
        38760
        """
        result = 1
        for i in range(1, k + 1):
            result = result * (n - i + 1) / i
        return result

    # Load word lists
    for line in open(source_file, "r").readlines():
        word, pos = line.split("\t")
        word = word.strip()
        pos = pos.strip()
        i = len(word)
        # filters
        # - too short
        # - too long
        # - 2nd letter is uppercase
        # - contains characters that are not letters
        # - contains no vowels (including y)
        if (i < word_min or i > word_max or
            word[1] in ascii_uppercase or re_nonalpha.search(word) or
            not re_vowels.search(word)):
            continue
        word = word.lower()
        # by length
        if i not in words["len"].keys():
            words["len"][i] = set()
            temp["len_swapped"][i] = set()
            temp["len_egiost"][i] = set()
        words["len"][i].add(word)
        for x in ascii_lowercase:
            temp["len_swapped"][i].add("%s%s" % (x, word[1:]))
        temp["len_egiost"][i].add(word)
        for combo in egiost_combos:
            word_modified = word
            for l in combo:
                word_modified = word_modified.replace(l, egiost_replace[l])
            temp["len_egiost"][i].add(word_modified)
        # by 1st letter
        letter = word[0]
        if letter not in words["let"].keys():
            words["let"][letter] = set()
        words["let"][word[0]].add(word)
        # by part of speach
        if pos:
            pos = pos.strip()
            pos = pos.replace("|", "")
            for p in pos:
                if p not in words["pos"].keys():
                    words["pos"][p] = set()
                words["pos"][p].add(word)
    # number of words by length
    for i in words["len"]:
        words["num_common"][i] = len(words["len"][i])
    for i in temp["len_egiost"]:
        words["num_egiost"][i] = len(temp["len_egiost"][i])
    for i in temp["len_swapped"]:
        words["num_swapped"][i] = len(temp["len_swapped"][i])

    # number of words per range
    for i in words["len"]:
        for name in names:
            if ranges[name][0] <= i and ranges[name][1] >= i:
                words["num_ranges"]["common"][name] += len(words["len"][i])
                words["num_ranges"]["egiost"][name] += (
                        len(temp["len_egiost"][i]))
                words["num_ranges"]["swapped"][name] += (
                        len(temp["len_swapped"][i]))

    # letter and pair averages per range
    count = dict()
    pair = dict()
    for x in ascii_lowercase:
        count[x] = dict()
        pair[x] = dict()
        for name in names:
            count[x][name] = 0
            pair[x][name] = 0
        if x in words["let"]:
            for word in words["let"][x]:
                length = len(word)
                for name in names:
                    if ranges[name][0] <= length and ranges[name][1] >= length:
                        count[x][name] += 1
            for name in names:
                pair[x][name] = binomial_coeff(count[x][name], 2)
                words["num_ranges"]["pairs"][name] += pair[x][name]

    # write data to file
    words_fo = open(words_file, "wb")
    cPickle.dump(words, words_fo, -1)
    words_fo.close()


def word_list_info():
    """Display information based on loaded word list."""
    # header
    print "Words loaded from: %s" % words_file
    print "    Filters:"
    print "        * must be at least %d letters long" % word_min
    print "        * must be at most %d letters long" % word_max
    print "        * must contain only letters"
    print "        * must contain vowels (including y)"
    print
    print ("'common' words have been converted to all lowercase, but are "
           "otherwise\n    unmodified.")
    print
    print ("'egoist' words consist of all unique combinations of the "
            "following substitutions:")
    print "    e to 3, g to 9, i to 1, o to 0, s to 5, and t to 7."
    print
    print ("'swapped' words consist of all unique combinations in which the "
           "first letter has\n    been replaced with every ascii_lowercase "
           "letter.")
    print
    print

    # word information based on length
    for i in words["len"]:
        common = words["num_common"][i]
        egiost = words["num_egiost"][i]
        swapped = words["num_swapped"][i]
        print "%d %-17s" % (i, "Character Words"),
        print "%8d common words" % common
        print "%28d egiost words (multiplier: %.2f)" % (egiost,
                float(egiost) / float(common))
        print "%28d swapped words (multiplier: %.2f)" % (swapped,
                float(swapped) / float(common))
        print
    print

    # word information based on ranges
    for name in names:
        header = "%s (%d-%d) Words" % (name.title(), ranges[name][0],
                                 ranges[name][1])
        print "%-19s" % header,
        # common words
        print "%8d %s" % (words["num_ranges"]["common"][name],
                          "common words")
        # avg words per letter
        print "%40d %s" % ((words["num_ranges"]["common"][name] / 26),
                           "average words per letter")
        # avg pairs per letter
        print "%40d %s" % ((words["num_ranges"]["pairs"][name] / 26),
                           "average pairs per letter")
        # pairs (total 2 word combinations)
        print "%40d %s" % (words["num_ranges"]["pairs"][name],
                           "pairs (binomial coefficient, choose 2)")
        print "%28d egiost words" % (
                words["num_ranges"]["egiost"][name])
        print "%28d swapped words" % (
                words["num_ranges"]["swapped"][name])
        print
    print

    # word information based on part of speach
    print "Parts of speech (long common words)"
    print "Key     Part of Speach          Words       Examples"
    for pos in words["pos"]:
        count = len(words["pos"][pos])
        sample = 4
        if sample > count:
            sample = count
        samples = random.sample(words["pos"][pos], sample)
        print "%-8s%-24s%8d    %s" % (pos, pos_desc[pos], count,
                                      ", ".join(samples))


def parser_setup():
    """Instantiate, configure, and return an OptionParser instance."""
    p = optparse.OptionParser(usage=__doc__)
    p.add_option("-f", "--formula", default="groups_lower",
            help=('Password formula to use. Use "help" for a description of '
                  'each formula. Default formula: groups_lower.'))
    p.add_option("-e", "--entropy", dest="min_entropy",
                 default=strength[2],
                 help=("Minimum bits of entropy (int) or one of: Good (%s), "
                       "Moderate (%s), or Weak (%s)") % (strength[2],
                            strength[1], strength[0]))
    p.add_option("-n", "--number", type="int", default=1,
                 help="number of passwords to generate")
    p.add_option("--create-words-file", dest="source_file",
                 help="Create pickled word list from specified file")
    p.add_option("-w", "--word-list-info", action="store_true",
                 help="display information about word list")
    p.epilog = ('"Good" passwords can withstand an organized group attack. '
                '"Moderate" passwords can withstand a dedicated attacker. '
                '"Weak" passwords are only as secure as the system that '
                'stores them.')
    return p


def main(argv):
    # parse options
    p = parser_setup()
    opts, args = p.parse_args(argv)
    formula = opts.formula.lower()
    try:
        min_entropy = float(opts.min_entropy)
    except:
        min_entropy = str(opts.min_entropy)
        min_entropy = min_entropy.lower()[0:3]
        if min_entropy in strength:
            min_entropy = float(strength[min_entropy])
        else:
            p.error('invalid argument for --entropy: "%s"' %
                    str(opts.min_entropy))

    if opts.source_file:
        create_words_file(opts.source_file, words_file)
    elif opts.word_list_info:
        load_words_file(words_file)
        word_list_info()
    else:
        load_words_file(words_file)
        if formula in gen:
            for x in xrange(0, opts.number):
                print gen[formula](min_entropy)
        elif formula == "all":
            passwords = list()
            for method in gen.iterkeys():
                for x in xrange(0, opts.number):
                    passwords.append(gen[method](min_entropy))
            random.shuffle(passwords)
            for password in passwords:
                print password
        else:
            for method in sorted(gen.iterkeys()):
                print method
                print "    %s" % gen[method].__doc__
                print
                gen[method](min_entropy, True)
                print
                print "    %s  %s" % ("Examples:", gen[method](min_entropy))
                print "%s%s" % (" " * 15, gen[method](min_entropy))
                print "%s%s" % (" " * 15, gen[method](min_entropy))
                print
                print


if __name__ == "__main__":
    main(sys.argv[1:])
