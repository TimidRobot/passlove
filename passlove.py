#!/usr/bin/python

"""Usage: passlove [options]

Generates a passwords using an OS specific cryptographically secure
pseudo-random number generator.
(CSPRNG)."""

# Standard Library
import itertools
import math
import optparse
import random
import re
from string import ascii_letters, ascii_lowercase, digits, punctuation
import sys

# Third-party
# ...

# Variables
debug = 0
dic = "/usr/share/dict/american-english-huge"
egoist_lowercase_len_3_to_6 = 59356
swapped_lowercase_len_3_to_6 = 199680
words_let = dict()
words_len = dict()
word_min = 3
word_max = 6
re_nonalpha = re.compile(r"[^a-z]")
egiost = {'e': '3', 'g': '9', 'i': '1', 'o': '0', 's': '5', 't': '7'}
# determin all "egiost" replacement combinations
egiost_combos = set()
for x in xrange(1, len(egiost.keys())):
    for combination in itertools.combinations(egiost.keys(), x):
        egiost_combos.add(combination)
gen = dict()
# Separators -  do no require shift key, considered injection-safe
sep_list = [",", ".", "/", "]", "-", "=", " "]
# random.SystemRandom - "Class that uses the os.urandom() function for
#   generating random numbers from sources provided by the operating
#   system."
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
    separator. The symbols consist of digits and lowercase ASCII letters."""
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
    separator. The symbols consist of lowercase ASCI letters."""
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
    the words within the pair are demarcated by a separator."""
    sep = srand.choice(sep_list)
    pairs = list()
    # 1st pair
    word1 = srand.sample(words_len[srand.randint(3, 5)], 1)[0]
    word2 = srand.sample(words_let[word1[0]], 1)[0]
    pairs.append("%s%s%s" % (word1, sep, word2))
    # 2nd pair
    word1 = srand.sample(words_len[srand.randint(3, 5)], 1)[0]
    word2 = srand.sample(words_let[word1[0]], 1)[0]
    pairs.append("%s%s%s" % (word1, sep, word2))
    if level != 0:
        # 3nd pair
        word1 = srand.sample(words_len[srand.randint(3, 5)], 1)[0]
        word2 = srand.sample(words_let[word1[0]], 1)[0]
        pairs.append("%s%s%s" % (word1, sep, word2))

    if explain:
        symbol_count = (len(words_len[3]) + len(words_len[4]) +
                        len(words_len[5]))
        symbol_length = len(pairs) * 2
        explain_entropy(symbol_count, symbol_length)
        return

    return " ".join(pairs)
gen["pairs_allit"] = gen_pairs_allit


def gen_pairs_swap(level, explain=False):
    """Generate passwords consisting of medium length word pairs in which the
    1st letter has been swapped and the words within the pair are demarcated
    by a separator."""
    sep = srand.choice(sep_list)
    pairs = list()
    # 1st pair
    word1 = srand.sample(words_len[srand.randint(4, 6)], 1)[0]
    word2 = srand.sample(words_len[srand.randint(4, 6)], 1)[0]
    pairs.append("%s%s%s%s%s" % (word2[0], word1[1:], sep, word1[0],
                 word2[1:]))
    if level != 0:
        # 2st pair
        word1 = srand.sample(words_len[srand.randint(4, 6)], 1)[0]
        word2 = srand.sample(words_len[srand.randint(4, 6)], 1)[0]
        pairs.append("%s%s%s%s%s" % (word2[0], word1[1:], sep, word1[0],
                                     word2[1:]))

    if explain:
        symbol_count = swapped_lowercase_len_3_to_6
        symbol_length = len(pairs) * 2
        explain_entropy(symbol_count, symbol_length)
        return

    return " ".join(pairs)
gen["pairs_swap"] = gen_pairs_swap


def gen_words(level, explain=False):
    """Generate passwords consisting of words demarcated by a separator."""
    parts = list()
    sep = srand.choice(sep_list)
    if level == 0:
        symbol_length = 2
    elif level == 1:
        symbol_length = 5
    else:
        symbol_length = 6

    if explain:
        symbol_count = (len(words_len[3]) + len(words_len[4]) +
                        len(words_len[5]) + len(words_len[6]))
        explain_entropy(symbol_count, symbol_length)
        return

    for x in xrange(0, symbol_length):
        parts.append(srand.sample(words_len[srand.randint(3, 6)], 1)[0])
    return sep.join(parts)
gen["words"] = gen_words


def gen_words_egiost(level, explain=False):
    """Generate passwords consisting of short "egiost" words demarcated by a
    separator. The "egiost" words have random letter substitutions: e->3, g->9,
    i->1, o->0, s->5, t->7."""
    parts = list()
    sep = srand.choice(sep_list)
    if level == 0:
        symbol_length = 2
    elif level == 1:
        symbol_length = 4
    else:
        symbol_length = 5

    if explain:
        symbol_count = egoist_lowercase_len_3_to_6
        explain_entropy(symbol_count, symbol_length)
        return

    for x in xrange(0, symbol_length):
        word = srand.sample(words_len[srand.randint(3, 6)], 1)[0]
        for l in srand.sample(egiost_combos, 1)[0]:
            word = word.replace(l, egiost[l])
        parts.append(word)
    return sep.join(parts)
gen["words_egiost"] = gen_words_egiost


def grouped_symbols(symbols, groups, explain=False):
    """Generates passwords split into groups separated by a random symbol."""
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


def load_word_list(dic):
    """Load word list"""
    # Load word lists
    for line in open(dic, "r").readlines():
        line = line.lower()
        line = line.strip()
        length = len(line)
        if length < word_min or length > word_max or re_nonalpha.search(line):
            continue
        if length not in words_len.keys():
            words_len[length] = set()
        words_len[length].add(line)
        letter = line[0]
        if letter not in words_let.keys():
            words_let[letter] = set()
        words_let[line[0]].add(line)


def word_list_info():
    """Display information based on loaded word list."""

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

    words_swapped = dict()
    words_egiost = dict()
    for i in words_len:
        words_swapped[i] = set()
        words_egiost[i] = set()
        for word in words_len[i]:
            for x in ascii_lowercase:
                words_swapped[i].add("%s%s" % (x, word[1:]))
            words_egiost[i].add(word)
            for combo in egiost_combos:
                word_modified = word
                for l in combo:
                    word_modified = word_modified.replace(l, egiost[l])
                words_egiost[i].add(word_modified)

    print "Words loaded from: %s" % dic
    print "    Filters:"
    print "        * must only contain letters"
    print "        * must be at least %d characters long" % word_min
    print "        * must be at most %d characters long" % word_max
    print
    print ("'egoist' words consist of all unique combinations of the "
            "following substitutions:")
    print "    e to 3, g to 9, i to 1, o to 0, s to 5, t to 7"
    print
    print ("'swapped' words consist of all unique combinations in which the "
           "first letter has\n    been replaced with every  ascii_lowercase "
           "letter")
    print
    # word information based on length
    words_3to6 = 0
    egiost_3to6 = 0
    swapped_3to6 = 0
    for i in words_len:
        words_3to6 += len(words_len[i])
        egiost_3to6 += len(words_egiost[i])
        swapped_3to6 += len(words_swapped[i])
        print "%d %-17s" % (i, "character words"),
        print "%6d words" % len(words_len[i])
        print "%26d egiost words (multiplier: %.2f)" % (
                len(words_egiost[i]),
                float(len(words_egiost[i])) / float(len(words_len[i])))
        print "%26d swapped words (multiplier: %.2f)" % (
                len(words_swapped[i]),
                float(len(words_swapped[i])) / float(len(words_len[i])))
        print
    print "%-19s" % "totals",
    print "%6d words, 3 - 5 characters long" % (
            words_3to6 - len(words_len[6]))
    print "%26d words, 3 - 6 characters long" % words_3to6
    print "%26d egiost words, 3 - 5 characters long" % (
            egiost_3to6 - len(words_egiost[6]))
    print "%26d egiost words, 3 - 6 characters long" % egiost_3to6
    print "%26d swapped words, 3 - 5 characters long" % (
            swapped_3to6 - len(words_swapped[6]))
    print "%26d swapped words, 3 - 6 characters long" % swapped_3to6
    print
    # word information based on 1st letter
    print ("1st letter distribution and binomial coefficient (choose 2)")
    count_total = 0
    pairs_total = 0
    for x in words_let:
        count = len(words_let[x])
        count_total += count
        pairs = binomial_coeff(count, 2)
        pairs_total += pairs
        print "%5s:%5d%10s%8d" % (x, count, "pairs:", pairs)
    print "averages"
    print "%11d%18d" % ((count_total / 26), (pairs_total / 26))
    print "totals"
    print "%11d%18d" % (count_total, pairs_total)


def parser_setup():
    """Instantiate, configure, and return an OptionParser instance."""
    p = optparse.OptionParser(usage=__doc__)
    p.add_option("-n", "--number", type="int", default=1,
                 help="number of passwords to generate")
    p.add_option("--word-list-info", action="store_true",
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

    # load word lists
    load_word_list(dic)

    if opts.word_list_info:
        word_list_info()
    else:
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
                print "\n%36s  %s" % ("Examples:", gen[method](level))
                print "%s%s" % (" " * 38, gen[method](level))
                print "%s%s\n" % (" " * 38, gen[method](level))
                print


if __name__ == "__main__":
    main(sys.argv[1:])
