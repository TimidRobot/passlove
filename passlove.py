#!/usr/bin/python

"""Usage: passlove [options]

Generates a passwords using an OS specific cryptographically secure
pseudo-random number generator.
(CSPRNG)."""

# Standard Library
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
words_let = dict()
words_len = dict()
word_min = 3
word_max = 6
re_nonalpha = re.compile(r"[^a-z]", re.IGNORECASE)
gen = dict()
# Separators -  do no require shift key, considered injection-safe
sep_list = [",", ".", "/", "]", "-", "=", " "]


def gen_characters(srand, level, explain=None):
    """Generate password of random "readable" characters. "Readable characters
    includes digits, ASCII letters, and punctuation, but excludes li1O0"'`."""
    parts = list()
    readable = '%s%s%s' % (digits, ascii_letters, punctuation)
    readable = readable.translate(None, "li1O0\"'`")
    if level == 0:
        length = 5
    elif level == 1:
        length = 10
    else:
        length = 12

    if explain:
        count = len(readable)
        entropy = math.log(count,2)
        print "    Symbol Count: %d" % count
        print "    Entropy per symbol: %.3f" % entropy
        print "    Password Entropy: %.0f" % (entropy * length)
        return

    for x in xrange(0, length):
        parts.append(srand.choice(readable))
    return "".join(parts)
gen["characters"] = gen_characters


def gen_chunks_lownum(srand, level, explain=None):
    """Generates passwords consisting of lowercase ASCII letters and numbers
    that are separated by random symbol."""
    symbols = "%s%s" % (ascii_lowercase, digits)
    if level == 0:
        chunks = [2, 3]
    elif level == 1:
        chunks = [4, 4, 4]
    else:
        chunks = [5, 5, 4]

    if explain:
        chunked_symbols(srand, symbols, chunks, True)
        return

    return chunked_symbols(srand, symbols, chunks)
gen["chunks_lownum"] = gen_chunks_lownum


def gen_chunks_lower(srand, level, explain=None):
    """Generates passwords consisting of lowercase ASCII letters that are
    separated by random symbol."""
    symbols = "%s" % (ascii_lowercase)
    if level == 0:
        chunks = [3, 3]
    elif level == 1:
        chunks = [5, 4, 4]
    else:
        chunks = [5, 5, 5]

    if explain:
        chunked_symbols(srand, symbols, chunks, True)
        return

    return chunked_symbols(srand, symbols, chunks)
gen["lower_chunks"] = gen_chunks_lower


def gen_pairs_allit(srand, level, explain=None):
    """Generates passwords consisting of alliterative short word pairs."""
    pairs = list()
    # 1st pair
    word1 = srand.choice(words_len[srand.randint(3, 5)])
    word2 = srand.choice(words_let[word1[0]])
    pairs.append("%s.%s" % (word1, word2))
    # 2nd pair
    word1 = srand.choice(words_len[srand.randint(3, 5)])
    word2 = srand.choice(words_let[word1[0]])
    pairs.append("%s.%s" % (word1, word2))
    if level != 0:
        # 3nd pair
        word1 = srand.choice(words_len[srand.randint(3, 5)])
        word2 = srand.choice(words_let[word1[0]])
        pairs.append("%s.%s" % (word1, word2))

    if explain:
        return

    return " ".join(pairs)
gen["pairs_allit"] = gen_pairs_allit


def gen_pairs_swap(srand, level, explain=None):
    """Generate passwords consisting of medium length word pairs in which the
    1st letter has been swapped."""
    pairs = list()
    # 1st pair
    word1 = srand.choice(words_len[srand.randint(4, 6)])
    word2 = srand.choice(words_len[srand.randint(4, 6)])
    pairs.append("%s%s.%s%s" % (word2[0], word1[1:], word1[0], word2[1:]))
    if level != 0:
        # 2st pair
        word1 = srand.choice(words_len[srand.randint(4, 6)])
        word2 = srand.choice(words_len[srand.randint(4, 6)])
        pairs.append("%s%s.%s%s" % (word2[0], word1[1:], word1[0], word2[1:]))

    if explain:
        return

    return " ".join(pairs)
gen["pairs_swap"] = gen_pairs_swap


def chunked_symbols(srand, symbols, chunks, explain=None):
    """Generates passwords split into chunks separated by a random symbol."""
    sep = srand.choice(sep_list)
    parts = list()
    srand.shuffle(chunks)
    for length in chunks:
        chunk = list()
        for y in xrange(0, length):
            chunk.append(srand.choice(symbols))
        parts.append("".join(chunk))

    if explain:
        char_count = len(symbols)
        char_entropy = math.log(char_count,2)
        char_length = 0
        for i in chunks:
            char_length = char_length + i
        sep_count = len(sep_list)
        sep_entropy = math.log(sep_count,2)
        password_entropy = (char_entropy * char_length) + sep_entropy
        print "%36s %d" % ("Character count:", char_count)
        print "%36s %.3f" % ("Entropy per character:", char_entropy)
        print "%36s %d" % ("Separator count:", sep_count)
        print "%36s %.3f" % ("Entropy per separator:", sep_entropy)
        print "%36s %.0f" % ("Password information entropy:",
                              password_entropy)
        return

    return sep.join(parts)


def parserSetup():
    """Instantiate, configure, and return an OptionParser instance."""
    p = optparse.OptionParser(usage=__doc__)
    p.add_option("-n", "--number", type="int", default=1,
                 help="number of passwords to generate")
    p.add_option("-l", "--level", type="int", default=2,
                 help="security level: 2 (good), 1 (moderate), or 0 (weak)")
    p.add_option("-f", "--formula", default="lower_split",
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
    p = parserSetup()
    opts, args = p.parse_args(argv)
    formula = opts.formula
    level = opts.level

    # random.SystemRandom - "Class that uses the os.urandom() function for
    #   generating random numbers from sources provided by the operating
    #   system."
    # os.urandom - "This function returns random bytes from an OS-specific
    #   randomness source. The returned data should be unpredictable enough
    #   for cryptographic applications"
    srand = random.SystemRandom()
    #
    # Load word lists
    for line in open(dic, "r").readlines():
        line = line.lower()
        line = line.strip()
        length = len(line)
        if length < word_min or length > word_max or re_nonalpha.search(line):
            continue
        if length not in words_len.keys():
            words_len[length] = list()
        words_len[length].append(line)
        letter = line[0]
        if letter not in words_let.keys():
            words_let[letter] = list()
        words_let[line[0]].append(line)

    if formula in gen:
        for x in xrange(0, opts.number):
            print gen[formula](srand, level)
    elif formula == "help":
        for method in sorted(gen.iterkeys()):
            print method
            print "    %s" % gen[method].__doc__
            print
            gen[method](srand, level, True)
            print "\n%36s    %s" % ("Examples:", gen[method](srand, level))
            print "%s%s" % (" " * 40, gen[method](srand, level))
            print "%s%s\n" % (" " * 40, gen[method](srand, level))
            print

#            print "    Examples:
#            for x in xrange(0, 3):
#                print " " * 40, gen[method](srand, level)
##    for l in words_let.keys():
##        if len(words_let[l]) < 200:
##            del words_let[l]
##    for key in words_let.keys():
##        print key,'\t',len(words_let[key])
#
#    count = 0
#    while (count < opts.number):
#        if opts.columns:
#            print "%-40s%-40s\n" % (passGen(srand), passGen(srand), )
#        else:
#            print passGen(srand)
#        count = count + 1


if __name__ == "__main__":
    main(sys.argv[1:])
