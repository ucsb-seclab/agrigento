"""Compare config"""

GAP_BYTE = 256
GAPS_THRESHOLD = 0

WILDCARD = '(.*)?'
NETWORK = '<NETWORK>'
TIMESTAMP = '"<TIMESTAMP>"'  # workaround quotes
RANDOM_ID = '<RANDOM_ID>'

NUM_FLOWS_PER_APP = 15

DELIMITERS = ['\'', '=', ':', ',', ';', '-']

WHITELISTED_DOMAINS = ['googleads.g.doubleclick.net',
                       'pagead2.googlesyndication.com',
                       'pagead2.googleadservices.com',
                       'securepubads.g.doubleclick.net',
                       'www.google-analytics.com',
                       'cm.g.doubleclick.net',
                       'pubads.g.doubleclick.net',
                       'translate.google.com',
                       'www.google.com',
                       'ssl.google-analytics.com',
                       'csi.gstatic.com',
                       'www.gstatic.com',
                       'lh3.googleusercontent.com',
                       'fonts.googleapis.com',
                       'googleads4.g.doubleclick.net']
