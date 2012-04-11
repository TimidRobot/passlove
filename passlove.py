#!/usr/bin/python

"""Usage: passlove [options]

Generates a passwords using an OS specific cryptographically secure
pseudo-random number generator.
(CSPRNG)."""

# Standard Library
import itertools
import math
import optparse
import cPickle
import random
import re
from string import (ascii_letters, ascii_lowercase, ascii_uppercase, digits,
                    punctuation)
import sys

# Third-party
# ...

# Variables
words_file = "words.pkl"
word_min = 2
word_max = 6
names = ("short", "medium", "long", "total")
ranges = {"short": (2, 3), "medium": (3, 5), "long": (4, 6),
          "total": (word_min, word_max)}
words = dict()
egoist_3to6 = 59356
swapped_3to6 = 199680
pairs_3to4 = 180939
pos_desc = {"!": "Interjection", "A": "Adjective", "C": "Conjunction",
            "D": "Definite Article", "N": "Noun", "P": "Plural",
            "V": "Verb (usu participle)", "h": "Noun Phrase",
            "i": "Verb (intransitive)", "p": "Preposition", "r": "Pronoun",
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
# Separators -  do no require shift key, considered injection-safe
sep_list = [",", ".", "/", "]", "-", "=", " "]
# random.SystemRandom - "Class that uses the os.urandom() function for
#   generating random numbers from sources provided by the operating
#   system. Not available on all systems. Does not rely on software state and
#   sequences are not reproducible."
# os.urandom - "This function returns random bytes from an OS-specific
#   randomness source. The returned data should be unpredictable enough
#   for cryptographic applications"
srand = random.SystemRandom()


def gen_characters(level, explain=False):
    """Generate passwords containing a sequence of symbols. The symbols consist
    of "readable" characters: digits (excluding 0 and 1), ASCII letters
    (excluding I, O, i, and l), and punctuation (excluding double quotation
    ["], single quotation ['], and backtick [`])."""
    parts = list()
    readable = '%s%s%s' % (digits, ascii_letters, punctuation)
    readable = readable.translate(None, "IOil01\"'`")
    if level == 0:
        length = 5
    elif level == 1:
        length = 10
    else:
        length = 12

    if explain:
        symbol_count = len(readable)
        symbol_length = length
        explain_entropy(symbol_count, symbol_length, False)
        return

    for x in xrange(0, length):
        parts.append(srand.choice(readable))
    return "".join(parts)
gen["characters"] = gen_characters


def gen_groups_lownum(level, explain=False):
    """Generates passwords containing groups of symbols demarcated by a
    random separator. The symbols consist of digits and lowercase ASCII
    letters."""
    symbols = "%s%s" % (ascii_lowercase, digits)
    if level == 0:
        groups = [2, 3]
    elif level == 1:
        groups = [4, 4, 4]
    else:
        groups = [5, 5, 4]

    if explain:
        grouped_symbols(symbols, groups, True)
        return

    return grouped_symbols(symbols, groups)
gen["groups_lownum"] = gen_groups_lownum


def gen_groups_lower(level, explain=False):
    """Generates passwords containing groups of symbols demarcated by a
    random separator. The symbols consist of lowercase ASCI letters."""
    symbols = "%s" % (ascii_lowercase)
    if level == 0:
        groups = [3, 3]
    elif level == 1:
        groups = [5, 4, 4]
    else:
        groups = [5, 5, 5]

    if explain:
        grouped_symbols(symbols, groups, True)
        return

    return grouped_symbols(symbols, groups)
gen["groups_lower"] = gen_groups_lower


def gen_pairs_allit(level, explain=False):
    """Generates passwords containing short alliterative word pairs in which
    the words within the pair are demarcated by a random separator."""
    sep = srand.choice(sep_list)
    pairs = list()
    # 1st pair
    word1 = srand.sample(words["len"][srand.randint(3, 4)], 1)[0]
    word2 = srand.sample(words["let"][word1[0]], 1)[0]
    while len(word2) > 4:
        word2 = srand.sample(words["let"][word1[0]], 1)[0]
    pairs.append("%s%s%s" % (word1, sep, word2))
    # 2nd pair
    word1 = srand.sample(words["len"][srand.randint(3, 4)], 1)[0]
    word2 = srand.sample(words["let"][word1[0]], 1)[0]
    while len(word2) > 4:
        word2 = srand.sample(words["let"][word1[0]], 1)[0]
    pairs.append("%s%s%s" % (word1, sep, word2))
    if level > 0:
        # 3rd pair
        word1 = srand.sample(words["len"][srand.randint(3, 4)], 1)[0]
        word2 = srand.sample(words["let"][word1[0]], 1)[0]
        while len(word2) > 4:
            word2 = srand.sample(words["let"][word1[0]], 1)[0]
        pairs.append("%s%s%s" % (word1, sep, word2))
        # 4th pair
        word1 = srand.sample(words["len"][srand.randint(3, 4)], 1)[0]
        word2 = srand.sample(words["let"][word1[0]], 1)[0]
        while len(word2) > 4:
            word2 = srand.sample(words["let"][word1[0]], 1)[0]
        pairs.append("%s%s%s" % (word1, sep, word2))

    if explain:
        symbol_count = pairs_3to4
        symbol_length = len(pairs)
        explain_entropy(symbol_count, symbol_length)
        return

    return " ".join(pairs)
gen["pairs_allit"] = gen_pairs_allit


def gen_pairs_swap(level, explain=False):
    """Generate passwords consisting of medium length word pairs in which the
    1st letter has been swapped and the words within the pair are demarcated
    by a random separator."""
    sep = srand.choice(sep_list)
    pairs = list()
    length = "long"
    r1, r2 = ranges[length]

    # 1st pair
    word1 = srand.sample(words["len"][srand.randint(r1, r2)], 1)[0]
    word2 = srand.sample(words["len"][srand.randint(r1, r2)], 1)[0]
    pairs.append("%s%s%s%s%s" % (word2[0], word1[1:], sep, word1[0],
                 word2[1:]))
    if level != 0:
        # 2st pair
        word1 = srand.sample(words["len"][srand.randint(r1, r2)], 1)[0]
        word2 = srand.sample(words["len"][srand.randint(r1, r2)], 1)[0]
        pairs.append("%s%s%s%s%s" % (word2[0], word1[1:], sep, word1[0],
                                     word2[1:]))

    if explain:
        symbol_count = swapped_3to6
        symbol_length = len(pairs) * 2
        explain_entropy(symbol_count, symbol_length)
        return

    return " ".join(pairs)
gen["pairs_swap"] = gen_pairs_swap


def gen_words(level, explain=False):
    """Generate passwords consisting of words demarcated by a random
    separator."""
    parts = list()
    sep = srand.choice(sep_list)
    if level == 0:
        symbol_length = 2
    elif level == 1:
        symbol_length = 5
    else:
        symbol_length = 6

    if explain:
        symbol_count = (len(words["len"][3]) + len(words["len"][4]) +
                        len(words["len"][5]) + len(words["len"][6]))
        explain_entropy(symbol_count, symbol_length)
        return

    for x in xrange(0, symbol_length):
        parts.append(srand.sample(words["len"][srand.randint(3, 6)], 1)[0])
    return sep.join(parts)
gen["words"] = gen_words


def gen_words_egiost(level, explain=False):
    """Generate passwords consisting of short 'egiost' words demarcated by a
    random separator. 'egoist' words consist of all unique combinations of the
    following substitutions: e to 3, g to 9, i to 1, o to 0, s to 5, t to 7"""
    parts = list()
    sep = srand.choice(sep_list)
    if level == 0:
        symbol_length = 2
    elif level == 1:
        symbol_length = 4
    else:
        symbol_length = 5

    if explain:
        symbol_count = egoist_3to6
        explain_entropy(symbol_count, symbol_length)
        return

    for x in xrange(0, symbol_length):
        word = srand.sample(words["len"][srand.randint(3, 6)], 1)[0]
        for l in srand.sample(egiost_combos, 1)[0]:
            word = word.replace(l, egiost_replace[l])
        parts.append(word)
    return sep.join(parts)
gen["words_egiost"] = gen_words_egiost


def grouped_symbols(symbols, groups, explain=False):
    """Generates passwords split into groups demarcated by a random
    separator."""
    sep = srand.choice(sep_list)
    parts = list()
    srand.shuffle(groups)
    for length in groups:
        chunk = list()
        for y in xrange(0, length):
            chunk.append(srand.choice(symbols))
        parts.append("".join(chunk))

    if explain:
        symbol_count = len(symbols)
        symbol_length = 0
        for i in groups:
            symbol_length = symbol_length + i
        explain_entropy(symbol_count, symbol_length)
        return

    return sep.join(parts)


def explain_entropy(symbol_count, symbol_length, separator=True):
    symbol_bits = math.log(symbol_count, 2)
    symbol_entropy = (symbol_bits * float(symbol_length))
    if separator:
        sep_count = len(sep_list)
        sep_entropy = math.log(sep_count, 2)
        password_entropy = symbol_entropy + sep_entropy
    else:
        password_entropy = symbol_entropy
    print ("    Symbol entropy: %9.2f bits (%d * %.2f bits of entropy "
           "from %d symbols)") % (symbol_entropy, symbol_length,
                                   symbol_bits, symbol_count)
    if separator:
        print ("    Separator entropy: %6.2f bits (1 * %.2f bits of entropy "
               "from %d symbols)") % (sep_entropy, sep_entropy, sep_count)
    print "    Password entropy: %7.2f bits" % password_entropy


def load_words_file(words_file):
    """Load words file"""
    global words
    word_fo = open(words_file, "rb")
    words = cPickle.load(word_fo)
    word_fo.close()


def create_words_file(source_file, words_file):
    """Create words file"""
    global words
    temp = dict()
    words["len"] = dict()
    words["let"] = dict()
    words["pos"] = dict()
    words["num_ranges"] = dict()
    temp["len_egiost"] = dict()
    temp["len_swapped"] = dict()
    words["num_ranges"]["common"] = dict()
    words["num_ranges"]["egiost"] = dict()
    words["num_ranges"]["swapped"] = dict()
    words["num_egiost"] = dict()
    words["num_swapped"] = dict()
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
    # words length for egiost and swapped
    for i in temp["len_egiost"]:
        words["num_egiost"][i] = len(temp["len_egiost"][i])
    for i in temp["len_swapped"]:
        words["num_swapped"][i] = len(temp["len_swapped"][i])

    # words length for ranges
    for name in names:
        words["num_ranges"]["common"][name] = 0
        words["num_ranges"]["egiost"][name] = 0
        words["num_ranges"]["swapped"][name] = 0
    for i in words["len"]:
        for name in names:
            if ranges[name][0] <= i and ranges[name][1] >= i:
                words["num_ranges"]["common"][name] += len(words["len"][i])
                words["num_ranges"]["egiost"][name] += (
                        len(temp["len_egiost"][i]))
                words["num_ranges"]["swapped"][name] += (
                        len(temp["len_swapped"][i]))
    words_fo = open(words_file, "wb")
    cPickle.dump(words, words_fo, -1)
    words_fo.close()


def word_list_info():
    """Display information based on loaded word list."""
    global words

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

    # header
    print "Words loaded from: %s" % words_file
    print "    Filters:"
    print "        * must be at least %d letters long" % word_min
    print "        * must be at most %d letters long" % word_max
    print "        * must contain only letters"
    print "        * must contain vowels (including y)"
    print
    print

    # word information based on length
    print ("'egoist' words consist of all unique combinations of the "
            "following substitutions:")
    print "    e to 3, g to 9, i to 1, o to 0, s to 5, t to 7"
    print
    print ("'swapped' words consist of all unique combinations in which the "
           "first letter has\n    been replaced with every  ascii_lowercase "
           "letter")
    print
    words["swapped"] = dict()
    words["egiost"] = dict()
    for i in words["len"]:
        words["swapped"][i] = set()
        words["egiost"][i] = set()
        for word in words["len"][i]:
            for x in ascii_lowercase:
                words["swapped"][i].add("%s%s" % (x, word[1:]))
            words["egiost"][i].add(word)
            for combo in egiost_combos:
                word_modified = word
                for l in combo:
                    word_modified = word_modified.replace(l, egiost_replace[l])
                words["egiost"][i].add(word_modified)
    common_total = dict()
    egiost_total = dict()
    swapped_total = dict()
    for name in names:
        common_total[name] = 0
        egiost_total[name] = 0
        swapped_total[name] = 0
    for i in words["len"]:
        common = len(words["len"][i])
        egiost = len(words["egiost"][i])
        swapped = len(words["swapped"][i])
        for name in names:
            if ranges[name][0] <= i and ranges[name][1] >= i:
                common_total[name] += common
                egiost_total[name] += egiost
                swapped_total[name] += swapped
        print "%d %-17s" % (i, "Character Words"),
        print "%6d common words" % common
        print "%26d egiost words (multiplier: %.2f)" % (egiost,
                float(egiost) / float(common))
        print "%26d swapped words (multiplier: %.2f)" % (swapped,
                float(swapped) / float(common))
        print
    print "%-19s" % "Totals"
    for name in names:
        print "%26d common words, %s (%d-%d)" % (common_total[name],
                name, ranges[name][0], ranges[name][1])
    print
    for name in names:
        print "%26d egiost words, %s (%d-%d)" % (egiost_total[name],
                name, ranges[name][0], ranges[name][1])
    print
    for name in names:
        print "%26d swapped words, %s (%d-%d)" % (swapped_total[name],
                name, ranges[name][0], ranges[name][1])
    print
    print

    # word information based on 1st letter
    print ("1st letter distribution (common words) and pair combinations")
    print
    count = dict()
    pair = dict()
    count_total = dict()
    pair_total = dict()
    for name in names:
        count_total[name] = 0
        pair_total[name] = 0
        header = "%s (%d-%d)" % (name.title(), ranges[name][0],
                                 ranges[name][1])
        print "%-20s" % header,
    print
    print "Words     Pairs      " * 4
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
                count_total[name] += count[x][name]
                pair_total[name] += pair[x][name]
                print "%s:%6d%9d   " % (x, count[x][name], pair[x][name]),
            print
    print
    print "Averages"
    for name in names:
        print "  %6d%9d   " % ((count_total[name] / 26),
                (pair_total[name] / 26)),
    print
    print "Totals"
    for name in names:
        print "  %6d%9d   " % (count_total[name], pair_total[name]),
    print
    print
    print

    # word information based on part of speach
    print "Parts of speech (common words, %d-%d)" % (word_min, word_max)
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
    p.add_option("-n", "--number", type="int", default=1,
                 help="number of passwords to generate")
    p.add_option("--create-words-file", dest="source_file",
                 help="Create pickled word list from specified file")
    p.add_option("-w", "--word-list-info", action="store_true",
                 help="display information about word list")
    p.add_option("-l", "--level", type="int", default=2,
                 help="security level: 2 (good), 1 (moderate), or 0 (weak)")
    p.add_option("-f", "--formula", default="groups_lower",
                 help="choose from four columns of passwords")
    p.epilog = ('Security Levels: "Good" passwords contain a minimum of 72 '
                'bits of entropy. Good passwords can withstand an organized '
                'group attack. "Moderate" passwords contain a minimum of '
                '63 bits of entropy. Moderate passwords can withstand a '
                'dedicated attacker. "Weak" passwords contain a minimum of 28 '
                'bits of entropy. Weak passwords are only as secure as the '
                'system that stores them.')
    return p


def main(argv):
    # parse options
    p = parser_setup()
    opts, args = p.parse_args(argv)
    formula = opts.formula.lower()
    level = opts.level

    if opts.source_file:
        create_words_file(opts.source_file, words_file)
    elif opts.word_list_info:
        load_words_file(words_file)
        word_list_info()
    else:
        load_words_file(words_file)
        if formula in gen:
            for x in xrange(0, opts.number):
                print gen[formula](level)
        elif formula == "all":
            passwords = list()
            for method in gen.iterkeys():
                for x in xrange(0, opts.number):
                    passwords.append(gen[method](level))
            random.shuffle(passwords)
            for password in passwords:
                print password
        else:
            for method in sorted(gen.iterkeys()):
                print method
                print "    %s" % gen[method].__doc__
                print
                gen[method](level, True)
                print
                print "    %s  %s" % ("Examples:", gen[method](level))
                print "%s%s" % (" " * 15, gen[method](level))
                print "%s%s" % (" " * 15, gen[method](level))
                print
                print


if __name__ == "__main__":
    main(sys.argv[1:])
