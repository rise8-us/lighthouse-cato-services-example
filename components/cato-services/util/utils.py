"""Provides utility functions for the ``tornado_shared_resources`` package."""

import sys
import re
from typing import Callable
import subprocess
import requests


class APIException(Exception):
    """Exception raised when an API request fails.

    This exception is designed for error handling logic depending on
    details like status code and the specific endpoint being called.

    Attributes:
        url: The URL of the API endpoint.
        endpoint: The specific endpoint being called.
        method: The HTTP method used.
        response: The server's response to the request.
        status_code: The HTTP status code of the response.
        data: (optional) The JSON data included in the request.
    """
    def __init__(self, message, url, method, response, data=None):
        super().__init__(message, url, response, response.text, data)
        self.url = url
        self.endpoint = url.split("/api")[-1]
        self.method = method
        self.response = response
        self.error_text = response.text
        self.status_code = response.status_code
        self.data = data


class Tracker:
    """A class that holds a single value."""
    def __init__(self, state=None):
        self.state = state

    def __iter__(self):
        return iter(self.state)

    def __repr__(self):
        return f"Tracker({repr(self.state)})"

    def __str__(self):
        return f"Tracker({str(self.state)})"

    def update(self, value):
        """Update the state with the given value."""
        self.state = value

    def get(self):
        """Return the current state."""
        return self.state


def put(url: str, headers: dict, json_data: dict = None, form_data: dict = None, verify=False, timeout=5):
    """Return the response from a ``PUT`` request to the specified URL."""
    response = requests.put(
        url,
        headers=headers,
        json=json_data,
        data=form_data,
        verify=verify,
        timeout=timeout
    )
    if 200 <= response.status_code < 300:
        return response
    raise APIException("Request failed", url, "PUT", response)

def get(url: str, headers: dict, verify=False, timeout=5):
    """Return the response from a ``GET`` request to the specified URL."""
    response = requests.get(
        url,
        headers=headers,
        verify=verify,
        timeout=timeout
    )
    if response.status_code == 200:
        return response.json()
    raise APIException("Request failed", url, "GET", response)

def post(url: str, headers: dict, json_data: dict = None, form_data: dict = None, verify=False, timeout=5):
    """Return the response from a ``POST`` request to the specified URL."""
    response = requests.post(
        url,
        headers=headers,
        data=form_data,
        json=json_data,
        verify=verify,
        timeout=timeout
    )
    if 200 <= response.status_code < 300:
        return response
    raise APIException("Request failed", url, "POST", response, data=json_data if json_data is not None else form_data)

def patch(url: str, headers: dict, json_data: dict = None, form_data: dict = None, verify=False, timeout=5):
    """Return the response from a ``PATCH`` request to the specified URL."""
    response = requests.patch(
        url,
        headers=headers,
        data=form_data,
        json=json_data,
        verify=verify,
        timeout=timeout
    )
    if 200 <= response.status_code < 300:
        return response.json()
    raise APIException("Request failed", url, "PATCH", response, data=json_data if json_data is not None else form_data)


def api_get(config: dict, path: str, timeout: int = 5):
    """Return the response from a ``GET`` request to the specified URL.

    :param config: A dictionary containing the configuration for the request.
                This should be provided by the ``get_client_config`` function
        and includes the ``base_url``, ``headers``, and ``verify`` parameters.
    :param path: The path of the API endpoint to append to the base_url.
    :param timeout: (optional) The number of seconds to wait for the server
                               to respond before giving up. Defaults to 5.
    :return: The server's response to the ``GET`` request.
    """
    return get(
        url=f'{config["base_url"]}{path}',
        headers=config["headers"],
        verify=config["verify"],
        timeout=timeout
    )

def api_post(config: dict, path: str, json_data: dict = None, form_data: dict = None, timeout: int = 5):
    """Return the response from a ``POST`` request to the specified URL.

    :param config: A dictionary containing the configuration for the request.
                This should be provided by the ``get_client_config`` function
        and includes the ``base_url``, ``headers``, and ``verify`` parameters.
    :param path: The path of the API endpoint to append to the base_url.
    :param data: The data to be sent in the ``POST`` request.
    :param timeout: (optional) The number of seconds to wait for the server
                               to respond before giving up. Defaults to 5.
    :return: The server's response to the ``POST`` request.
    """
    return post(
        url=f'{config["base_url"]}{path}',
        headers=config["headers"],
        json_data=json_data,
        form_data=form_data,
        verify=config["verify"],
        timeout=timeout
    )

def api_put(config: dict, path: str, json_data: dict = None, form_data: dict = None, timeout: int = 5):
    """Return the response from a ``PUT`` request to the specified URL.

    :param config: A dictionary containing the configuration for the request.
                This should be provided by the ``get_client_config`` function
        and includes the ``base_url``, ``headers``, and ``verify`` parameters.
    :param path: The path of the API endpoint to append to the base_url.
    :param data: The data to be sent in the ``PUT`` request.
    :param timeout: (optional) The number of seconds to wait for the server
                               to respond before giving up. Defaults to 5.
    :return: The server's response to the ``PUT`` request.
    """
    return put(
        url=f'{config["base_url"]}{path}',
        headers=config["headers"],
        json_data=json_data,
        form_data=form_data,
        verify=config["verify"],
        timeout=timeout
    )

def api_patch(config: dict, path: str, json_data: dict = None, form_data: dict = None, timeout: int = 5):
    """Return the response from a ``PATCH`` request to the specified URL.

    :param config: A dictionary containing the configuration for the request.
                This should be provided by the ``get_client_config`` function
        and includes the ``base_url``, ``headers``, and ``verify`` parameters.
    :param path: The path of the API endpoint to append to the base_url.
    :param data: The data to be sent in the ``PATCH`` request.
    :param timeout: (optional) The number of seconds to wait for the server
                               to respond before giving up. Defaults to 5.
    :return: The server's response to the ``PATCH`` request.
    """
    return patch(
        url=f'{config["base_url"]}{path}',
        headers=config["headers"],
        form_data=form_data,
        json_data=json_data,
        verify=config["verify"],
        timeout=timeout
    )


def get_client_config(base_url: str, headers: dict, ca_certs=False) -> dict:
    """Return a dictionary containing the configuration for the request.

    :param base_url: The base URL for the API endpoint.
    :param headers: The headers to be included in the request.
    :param ca_certs: (optional) The CA certificates to verify the
                     server's SSL certificate. Defaults to False.
    :return: A dictionary containing the configuration for the request.
    """
    return {
        "base_url": base_url,
        "headers": headers,
        "verify": ca_certs
    }


def _evaluate_conditions(result: str) -> str:
    """Evaluate conditional statements in the template string.

    :param result: The template string.
    :return: The resulting string with evaluated conditions.
    """
    while result.find("<if False>") != -1:
        false_if_conditions = re.findall(
            r'(<if False>((?!<if False>.*?<\/if False>).)*?<\/if False>)',
            result,
            flags=re.S
        )
        if not false_if_conditions:
            raise Exception("Unmatched <if False> tag")

        for condition in false_if_conditions:
            result = result.replace(condition[0], "")

    while result.find("<if True>") != -1:
        true_if_conditions = re.findall(
            r'(<if True>(((?!<if True>.*?<\/if True).)*?)<\/if True>)',
            result,
            flags=re.S
        )
        if not true_if_conditions:
            raise Exception("Unmatched <if True> tag")

        for condition in true_if_conditions:
            result = result.replace(condition[0], condition[1])

    return result


def _replace_for_loops(result: str, key: str, value: list) -> str:
    """Replace for loops in the template string.

    :param result: The template string.
    :param key: The key for the for loop.
    :param value: The list of replacements for each iteration of the loop.
    :return: The resulting string with replaced for loops.
    """
    for_match = re.findall(
        rf'(<for {key}>(.*?)<\/for {key}>)',
        result,
        flags=re.S
    )

    if not for_match:
        return result

    for_body = for_match[0][1]
    for_result = ""
    for list_element in value:
        for_item = for_body
        for replacements_key, replacements_value in list_element.items():
            for_item = for_item.replace(
                f"{{{{ {replacements_key} }}}}", str(replacements_value)
            )
        for_result += for_item

    return result.replace(for_match[0][0], for_result)


def build_string_from_template(template: str, replacements: dict) -> str:
    """Return a string from a template and a dictionary of replacements.
    
    Given a template string and a dictionary of replacements,
    replace all instances of the keys in the template with
    the values from the replacements dictionary.

    Basic example:
    ```python
    template = "My name is {{ name }}."
    replacements = {"name": "Bob"}
    result = build_string_from_template(template, replacements)
    print(result) # This will print "My name is Bob."
    ```

    Templates can also have if statements, indicated by
    ``<if {{ if_key }}> ... </if {{ if_key }}>``.
    
    If the value of ``if_key`` in the replacements dictionary is
    ``True``, then body between the if tags is included in the result.
    
    If it is ``False``, then the body is not included.
    
    If neither case is true, the body is unchanged,
    so be sure to put booleans for those replacements.

    Example:
    ```python
    template = "My name is {{ name }}. <if {{ show_age }}>{{ age }}</if {{ show_age }}>"
    replacements = {"name": "Bob", "show_age": True, "age": 42}
    result = build_string_from_template(template, replacements)
    print(result) # This will print "My name is Bob. 42"
    ```

    If the template has a for loop structure, indicated by
    ``<for key> ... </for key>``, then in the replacements
    dictionary, the value for ``key`` should be a list of
    dictionaries, each of which contains the replacements for
    each iteration of the loop.
    
    In the case of a nested for loop, the template should have
    unique keys for each internal loop, like so:
    ```python
    template = \"\"\"
    <for top_level>
    {{ title }}
    <for {{ for_key }}>
    Hi! My name is {{ name }}.
    </for {{ for_key }}>
    </for top_level>
    \"\"\"
    ```

    NOTE that in the case of nested for loops, the for loop
    entries in the replacements dictionary must be in order
    from outermost to innermost!
    
    
    Then, in the replacements dictionary, you treat this as
    follows (notice how the values for ``for_key`` match the
    keys in the other entries):
    
    ```python
    replacements = {
        "top_level": [
            {
                "for_key": "first_loop", "title": "First Set"
            },
            {
                "for_key": "second_loop", "title": "Second Set"
            }
        ],
        "first_loop": [{"name": "Bob"}, {"name": "Alice"}],
        "second_loop": [{"name": "Charlie"}, {"name": "Diane"}]
        }
    result = build_string_from_template(template, replacements)
    print(result)
    ```
    
    This will result in the following output:
    ```
    First Set
    Hi! My name is Bob.
    Hi! My name is Alice.
    Second Set
    Hi! My name is Charlie.
    Hi! My name is Diane.
    ```

    :param template: The template string.
    :param replacements: The dictionary of replacements.
    :return: The resulting string with replacements.
    """
    result = template

    # First, make any replacements that are outside of any for loops
    for key, value in replacements.items():
        if not isinstance(value, list):
            result = result.replace(f"{{{{ {key} }}}}", str(value))

    # Evaluate Conditional Statements that were created in the mods above
    result = _evaluate_conditions(result)

    # Now, make any replacements that are inside of for loops
    for key, value in replacements.items():
        if isinstance(value, list):
            result = _replace_for_loops(result, key, value)

    result = _evaluate_conditions(result)
    return result


def print_and_exit(message: str, code: int):
    """Print a message and exit with a specified exit code."""
    print(message)
    sys.exit(code)


def examine(test_cases: list, function_under_test: callable):
    """Test a function with input from each test case.
    
    Given a list of test cases, run the function under test with the input
    from each test case.

    :param test_cases: A list of test cases. Each test case is a dictionary 
                       with the following structure:
                       {
                           "name": str,
                           "input": list, (arguments to function_under_test)
                           "expected": any
                       }
    :param function_under_test: The function to be tested.
    """
    failed = False
    for test_case in test_cases:
        if not (result := function_under_test(*test_case["input"])) == test_case["expected"]:
            print(f"Test case: {test_case['name']}")
            print(f"Expected: {test_case['expected']}")
            print(f"Actual: {result}")
            failed = True
    assert not failed


def handle_repeat_exception(*alt, exception=Exception, predicate=lambda e: True):
    """Handle repeated exceptions.

    Given a series of functions of no arguments, call each.
    If the result is an exception that matches the provided type and satisfies
    the predicate, call the next function; otherwise, raise the exception,
    or return the value of the function.

    :param alt: A series of functions of no arguments.
    :param exception: The type of exception to handle. Defaults to Exception.
    :param predicate: A function that takes an exception and returns a boolean
                      Only exceptions for which this returns True are handled.
                      Defaults to a function that always returns ``True``.
    :return: The value of the first function that does not raise an exception,
              or ``None`` if all functions raise an exception.
    """
    if len(alt) == 0:
        return None

    try:
        return alt[0]()
    except exception as e:
        if predicate(e):
            return handle_repeat_exception(*alt[1:])
        raise


def handle404(*alt):
    """Handle an APIException 404 status code.

    Given a series of functions of no arguments, call each.
    If the result is an ``APIException`` with a status code of ``404``,
    call the next function; otherwise, raise the exception,
    or return the value of the function.

    :param alt: A series of functions of no arguments.
    :return: The value of the first function that does not raise an exception,
              or ``None`` if all functions raise an exception.
    """
    return handle_repeat_exception(
        *alt,
        exception=APIException,
        predicate=lambda e: e.status_code == 404
    )


def collect_pages(url_call: Callable[[int], list]) -> list:
    """Return all pages from a paginated API endpoint.

    :param url_call: A function that takes a page number and returns the
                     response from the API for that page, or ``None`` if
                     there are no more pages.
    :return: A list of all responses from the API.
    """
    page = 1
    final_response = []
    response = url_call(page)
    if response is not None and not isinstance(response, list):
        raise Exception(
            f"The function {url_call} does not return a list. "
            "Modify the function to do so."
        )

    while response is not None and len(response) > 0:
        final_response += response
        page += 1
        response = url_call(page)

    return final_response


def add_property(data_items: list[dict], property_name: str, get_property_value: Callable[[dict], any]) -> list[dict]:
    """Return a new list of data items with a new property added.
    
    This function adds a new property to each item in a given list of data items.

    :param data_items: A list of data items, each represented as a dictionary.
    :param property_name: The name of the new property to add.
    :param get_property_value: A function that takes a data item and returns
                               the value of the new property for that item.
    :return: A new list of data items, each with the new property added.
    """
    return [
        d | {property_name: get_property_value(d)} for d in data_items
    ]


def partition(sep, iterable=None):
    """Return a stateful transducer that partitions an iterable into sublists.

    Each sublist contains 'sep' number of elements from the iterable.
    If the iterable does not evenly divide by 'sep',
    the last sublist will contain the remaining elements.
    """
    def partitioner(iterable):
        i = 0
        result = []
        for item in iterable:
            if i < sep:
                result.append(item)
                i += 1
            if i == sep:
                i = 0
                yield result
                result = []
        if result:
            yield result

    if iterable is not None:
        return partitioner(iterable)

    return partitioner

def partition_by(fn, iterable=None):
    """Return a stateful transducer that partitions an iterable into sublists, based on the result of fn.
    """
    def partitioner(iterable):
        first = True
        result = []
        existing_fact = None
        for item in iterable:
            fact = fn(item)
            if first:
                existing_fact = fact
                first = False
            if fact == existing_fact:
                result.append(item)
            else:
                yield result
                result = [item]
            existing_fact = fact
        if result:
            yield result

    if iterable is not None:
        return partitioner(iterable)

    return partitioner

def set_with(get_value_to_compare, iterable):
    """Return a set of unique items from an iterable as a list, using a custom equality function.

    This function takes an iterable and a function that should return a value that can be compared with __eq__.
    It returns a list of unique items from the iterable, using the value from the function
    to determine whether two items are equal.
    """
    class HashableDict(dict):
        def __hash__(self):
            return get_value_to_compare(self).__hash__()
        def __eq__(self, __value: object) -> bool:
            return hash(self).__eq__(hash(__value))

    intermediate_set = set((HashableDict(item) for item in iterable))
    return [dict(item) for item in intermediate_set]

def group_by(fn, iterable):
    """Groups items in an iterable by a given function.

    This function takes an iterable and a function.
    It returns a dictionary where each item is assigned a key based on applying the function to the item.
    The values are lists of items that share the same key.
    """
    groups = {}
    for item in iterable:
        key = fn(item)
        if key not in groups:
            groups[key] = []
        groups[key].append(item)
    return groups

def compose(*fns):
    """Return a single function composed from a series of functions.

    This function takes in multiple function arguments and
    returns a single function that applies each input function
    in the order they were passed in.

    :param fns: Function arguments to be composed
    :return: A single function that applies each input function in order
    """
    def composed(arg):
        result = arg
        for fn in fns:
            result = fn(result)
        return result

    return composed

def reduce(fn, init, iterable=None):
    """Return a single value by applying a function to each
    item in an iterable and the current value.

    This function takes a function, an initial value, and an iterable.
    It applies the function to each item in the iterable
    and the current value, reducing the iterable to a single value.

    :param fn: The function to apply to each item and the current value
    :param init: The initial value
    :param iterable: The iterable to reduce. If not provided, returns a
    function that takes an iterable
    :return: The reduced value, or a function that takes an iterable
    and returns the reduced value
    """
    def reducer(iterable):
        result = init
        for item in iterable:
            result = fn(result, item)
        return result

    if iterable is not None:
        return reducer(iterable)

    return reducer

def _map(fn):
    """Return a transducer that applies a given function
    to each item in an iterable.

    The function 'fn' is applied to each item in the iterable.

    :param fn: The function to apply to each item in the iterable
    :return: A transducer that applies 'fn' to each item in an iterable
    """
    def mapper(iterable):
        return map(fn, iterable)

    return mapper

def mapcat(fn, iterable=None):
    """Return a transducer that applies a given function
    to each item in an iterable and flattens the result.

    The function 'fn' is applied to each item in the iterable.
    The result is then flattened.

    :param fn: The function to apply to each item in the iterable
    :param iterable: The iterable to apply the function to.
    If not provided, returns a function that takes an iterable
    :return: A transducer that applies 'fn' to each item in an
    iterable and flattens the result
    """
    def mapper(iterable):
        list_of_lists = map(fn, iterable)
        for l in list_of_lists:
            for subitem in l:
                yield subitem

    if iterable:
        return mapper(iterable)

    return mapper

def _filter(fn):
    """Return a transducer that filters an iterable based on a predicate."""
    def filterer(iterable):
        return filter(fn, iterable)

    return filterer

def take(n, iterable=None):
    """Return a transducer that takes the first ``n`` items from an ``iterable``."""
    def taker(iterable):
        i = 0
        for item in iterable:
            if i < n:
                yield item
                i += 1
            else:
                break

    if iterable is not None:
        return taker(iterable)

    return taker

def take_while(fn, iterable=None, inclusive=False):
    """Return a transducer that takes items from an ``iterable``
    while a predicate is ``True``.
    """
    def taker(iterable):
        for item in iterable:
            if fn(item):
                yield item
            else:
                if inclusive:
                    yield item
                break

    if iterable is not None:
        return taker(iterable)

    return taker

def drop(n, iterable=None):
    """Return a transducer that drops the first ``n`` items from an ``iterable``."""
    def dropper(iterable):
        i = 0
        for item in iterable:
            if i < n:
                i += 1
            else:
                yield item

    if iterable is not None:
        return dropper(iterable)

    return dropper

def drop_while(fn, iterable=None):
    """
    Return a transducer that drops items from an ``iterable``
    while a predicate is ``True``.
    """
    def dropper(iterable):
        dropping = True
        for item in iterable:
            if dropping and fn(item):
                continue
            dropping = False
            yield item

    if iterable is not None:
        return dropper(iterable)

    return dropper

def tee(iterable, n=2):
    """Return ``n`` iterable objects that each yield
    the same items from the original iterable.

    Caches the items from the original iterable so
    expensive operations are not duplicated.
    """
    cache = {f"cache_{i}": [] for i in range(n)}
    class TeeGenerator:
        """A generator class for teeing an iterable."""
        def __init__(self, i):
            self.cache_index = i
            self.index = 0

        def __iter__(self):
            return self

        def __next__(self):
            return self.next()

        def get_cache(self):
            """Return the cache dictionary."""
            return cache

        def next(self):
            """Return the next item from the cache or the iterable, and update the cache."""
            my_cache = cache[f"cache_{self.cache_index}"]

            if my_cache and self.index < len(my_cache):
                return my_cache.pop(0)

            next_item = next(iterable)
            for i in range(n):
                if i != self.cache_index:
                    cache[f"cache_{i}"].append(next_item)
            self.index += 1

            return next_item

    return (TeeGenerator(i) for i in range(n))

def track(fn, init=None, iterable=None):
    """Return a transducer that updates a Tracker by applying
    a function to its existing value, and the next item in an iterable.
    
    Use this whenever you need to calculate a value based on a series
    of items while transforming them for another purpose.
    
    Ex.
    Get the sum of a set of numbers while doing some transformation on them:
    ```
    sum_holder = Tracker(0)
    summing_function = track(lambda total, item: total + item, init=sum_holder)
    xform = compose(_map(lambda x: x + 1),
                    summing_function,
                    _map(lambda x: x * x))
    r = list(xform(range(10)))
    sum_holder.get() -> 55
    r -> [1, 4, 9, 16, 25, 36, 49, 64, 81, 100]
    ```
    """
    if iterable is None:
        state_holder: Tracker = init
    else:
        state_holder = Tracker(init)

    def tracker(iterable):
        for item in iterable:
            state_holder.update(fn(state_holder.get(), item))
            yield item

    if iterable is not None:
        return tracker(iterable), state_holder

    return tracker

def write_annotation(message: str, annotation_type: str = "error", args: dict = None):
    """Write a GitHub annotation to the current step in a GitHub Action workflow."""
    if args is None:
        args = {}
    with subprocess.Popen(
        [f'annotate "{message}" "{annotation_type}" "{str(args)}"'],
        shell=True,
        stdout=sys.stdout,
        stderr=sys.stderr
    ) as p:
        p.wait()
