import re

from mitmproxy.models import decoded


seed = 'var seed = 1;'
faketime = 'var faketime = 1465692604873;'

fake_math_random = 'function fakemathrand(){' + \
                   'var x = Math.sin(seed);' + \
                   'seed = seed + 1.1;' + \
                   'return Math.abs(x - 0.000001);}'

fake_get_random_values = 'function fakegetrandomval(array){' + \
                         'for(var i = 0; i < array.length; i++){' + \
                         'array[i]=Math.abs(Math.sin(seed))*9999999999;' + \
                         'seed=seed + 1.1;}' + \
                         'return array;}'

fake_get_time = 'function fakegettime(){' + \
                'faketime=faketime + 500;' + \
                'return faketime;}'

fake_performance_timing = '({connectEnd:1466645421380,' + \
                          'connectStart:1466645421380,' + \
                          'domComplete:1466645421420,' + \
                          'domContentLoadedEventEnd:1466645421419,' + \
                          'domContentLoadedEventStart:1466645421419,' + \
                          'domInteractive:1466645421417,' + \
                          'domLoading:1466645421384,' + \
                          'domainLookupEnd:1466645421380,' + \
                          'domainLookupStart:1466645421380,' + \
                          'fetchStart:1466645421380,' + \
                          'loadEventEnd:1466645421421,' + \
                          'loadEventStart:1466645421420,' + \
                          'navigationStart:1466645421380,' + \
                          'redirectEnd:0,' + \
                          'redirectStart:0,' + \
                          'requestStart:1466645421380,' + \
                          'responseEnd:1466645421381,' + \
                          'responseStart:1466645421380,' + \
                          'secureConnectionStart:0,' + \
                          'unloadEventEnd:0,' + \
                          'unloadEventStart:0})'


to_inject = seed + faketime + fake_math_random
to_inject += fake_get_random_values + fake_get_time


date_functions = ['getDate()', 'getDay()', 'getFullYear()', 'getHours()',
                  'getMilliseconds()', 'getMinutes()', 'getMonth()',
                  'getSeconds()', 'getTime()', 'getTimezoneOffset()',
                  'getUTCDate()', 'getUTCDay()', 'getUTCFullYear()',
                  'getUTCHours()', 'getUTCMilliseconds()', 'getUTCMinutes()',
                  'getUTCMonth()', 'getUTCSeconds()', 'getYear()',
                  'toDateString()', 'toGMTString()', 'toLocaleDateString()',
                  'toLocaleTimeString()', 'toTimeString()', 'toUTCString()']


def inject_js(f):
    with decoded(f.response):  # automatically decode gzipped responses
        f.response.content = get_injected_content(f.response.content)


def get_injected_content(content):
    content = inject_fake_functions(content)

    if 'Math.random()' in content:
        content = content.replace('Math.random()', 'fakemathrand()')

    if 'getRandomValues' in content:
        content = re.sub('([a-zA-Z0-9\.\-_]*?getRandomValues\()(.*?)(\))',
                         r'fakegetrandomval(\2)', content)

    if 'getRandomValues' in content:
        content = re.sub('[a-zA-Z0-9\.\-_]*?getRandomValues',
                         r'fakegetrandomval', content)

    content = content.replace('Date.now()', 'fakegettime()')

    content = re.sub('new Date(\([a-zA-Z0-9\-\_\.]*\))?',
                     'new Date(fakegettime())',
                     content)

    if '.timing' in content:
        content = re.sub('[a-zA-Z0-9\.\-_]*?.timing',
                         fake_performance_timing, content)

    for func in date_functions:
        escaped_func = func.replace('(', '\(').replace(')', '\)')
        content = re.sub('[a-zA-Z0-9\.\-_]*?.' + escaped_func,
                         '(new Date(fakegettime())).' + func, content)

    # FB sdk
    content = content.replace('la.frameName', 'f68f15c61d6f828')

    return content


def is_comment(line):
    if line[:2] == '/*' or line[:2] == '//':
        return True

    else:
        return False


def get_first_line(lines):
    for i, line in enumerate(lines):
        if not is_comment(line):
            return i
    return 0


def inject_fake_functions(content):
    lines = content.splitlines()

    line_num = get_first_line(lines)
    line = lines[line_num]

    index = line.find('{')
    line = line[:index + 1] + to_inject + line[index + 1:]

    new_lines = lines[:line_num]
    new_lines.append(line)
    new_lines.extend(lines[line_num + 1:])

    new_content = '\n'.join(new_lines)
    return new_content
