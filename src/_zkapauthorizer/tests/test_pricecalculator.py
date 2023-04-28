# -*- coding: utf-8 -*-
# Copyright 2020 PrivateStorage.io, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Tests for ``_zkapauthorizer.pricecalculator``.
"""

from functools import partial

from hypothesis import assume, given
from hypothesis.strategies import integers, lists, tuples
from testtools import TestCase
from testtools.matchers import Equals, GreaterThan, IsInstance, MatchesAll

from ..pricecalculator import PriceCalculator
from ..storage_common import required_passes
from .matchers import greater_or_equal
from .strategies import encoding_parameters, sizes

file_sizes = lists(sizes(), min_size=1)


class PriceCalculatorTests(TestCase):
    """
    Tests for ``PriceCalculator``.
    """

    @given(
        integers(min_value=1),
        integers(min_value=1),
        file_sizes,
    )
    def test_pass_value(
        self, pass_value: int, more_value: int, file_sizes: list[int]
    ) -> None:
        """
        The result of ``PriceCalculator.calculate`` increases or remains the same
        as pass value decreases.
        """
        calculator = partial(PriceCalculator, shares_needed=1, shares_total=1)
        less_value_calc = calculator(pass_value=pass_value)
        more_value_calc = calculator(pass_value=pass_value + more_value)

        less_value_price = less_value_calc.calculate(file_sizes)
        more_value_price = more_value_calc.calculate(file_sizes)

        self.assertThat(
            less_value_price,
            greater_or_equal(more_value_price),
        )

    @given(
        integers(min_value=1, max_value=127),
        integers(min_value=1, max_value=127),
        file_sizes,
    )
    def test_shares_needed(
        self, shares_needed: int, more_needed: int, file_sizes: list[int]
    ) -> None:
        """
        The result of ``PriceCalculator.calculate`` never increases as
        ``shares_needed`` increases.
        """
        calculator = partial(PriceCalculator, pass_value=100, shares_total=255)
        fewer_needed_calc = calculator(shares_needed=shares_needed)
        more_needed_calc = calculator(shares_needed=shares_needed + more_needed)

        fewer_needed_price = fewer_needed_calc.calculate(file_sizes)
        more_needed_price = more_needed_calc.calculate(file_sizes)

        self.assertThat(
            fewer_needed_price,
            greater_or_equal(more_needed_price),
        )

    @given(
        integers(min_value=1, max_value=127),
        integers(min_value=1, max_value=127),
        file_sizes,
    )
    def test_shares_total(
        self, shares_total: int, more_total: int, file_sizes: list[int]
    ) -> None:
        """
        The result of ``PriceCalculator.calculate`` always increases as
        ``shares_total`` increases.
        """
        calculator = partial(PriceCalculator, pass_value=100, shares_needed=1)
        fewer_total_calc = calculator(shares_total=shares_total)
        more_total_calc = calculator(shares_total=shares_total + more_total)

        fewer_total_price = fewer_total_calc.calculate(file_sizes)
        more_total_price = more_total_calc.calculate(file_sizes)

        self.assertThat(
            more_total_price,
            greater_or_equal(fewer_total_price),
        )

    @given(
        integers(min_value=1, max_value=100).flatmap(
            lambda num_files: tuples(
                lists(sizes(), min_size=num_files, max_size=num_files),
                lists(sizes(), min_size=num_files, max_size=num_files),
            ),
        ),
        integers(min_value=1),
        encoding_parameters(),
    )
    def test_file_sizes(
        self,
        file_sizes: tuple[list[int], list[int]],
        pass_value: int,
        parameters: tuple[int, int, int],
    ) -> None:
        """
        The result of ``PriceCalculator.calculate`` never decreases as the values
        of ``file_sizes`` increase.
        """
        smaller_sizes, increases = file_sizes
        larger_sizes = list(a + b for (a, b) in zip(smaller_sizes, increases))
        k, happy, N = parameters

        calculator = PriceCalculator(
            pass_value=pass_value,
            shares_needed=k,
            shares_total=N,
        )

        smaller_sizes_price = calculator.calculate(smaller_sizes)
        larger_sizes_price = calculator.calculate(larger_sizes)

        self.assertThat(
            larger_sizes_price,
            greater_or_equal(smaller_sizes_price),
        )

    @given(
        integers(min_value=1),
        encoding_parameters(),
        file_sizes,
    )
    def test_positive_integer_price(
        self,
        pass_value: int,
        parameters: tuple[int, int, int],
        file_sizes: list[int],
    ) -> None:
        """
        The result of ``PriceCalculator.calculate`` for a non-empty size list is
        always a positive integer.
        """
        k, happy, N = parameters
        calculator = PriceCalculator(
            pass_value=pass_value,
            shares_needed=k,
            shares_total=N,
        )
        price = calculator.calculate(file_sizes)
        self.assertThat(
            price,
            MatchesAll(
                IsInstance(int),
                GreaterThan(0),
            ),
        )

    @given(
        integers(min_value=1),
        encoding_parameters(),
        file_sizes,
    )
    def test_linear_increase(
        self,
        pass_value: int,
        parameters: tuple[int, int, int],
        file_sizes: list[int],
    ) -> None:
        """
        The result of ``PriceCalculator.calculate`` doubles if the file size list
        is doubled.
        """
        k, happy, N = parameters
        calculator = PriceCalculator(
            pass_value=pass_value,
            shares_needed=k,
            shares_total=N,
        )
        smaller_price = calculator.calculate(file_sizes)
        larger_price = calculator.calculate(file_sizes + file_sizes)
        self.assertThat(
            larger_price,
            Equals(smaller_price * 2),
        )

    @given(
        integers(min_value=1),
    )
    def test_one_pass(self, pass_value: int) -> None:
        """
        The result of ``PriceCalculator.calculate`` is exactly ``1`` if the amount
        of data to be stored equals the value of a pass.
        """
        calculator = PriceCalculator(
            pass_value=pass_value,
            shares_needed=1,
            shares_total=1,
        )
        price = calculator.calculate([pass_value])
        self.assertThat(
            price,
            Equals(1),
        )

    @given(
        integers(min_value=2, max_value=255),
        integers(min_value=0, max_value=254),
    )
    def test_minimum_spending(self, needed: int, extra_shares: int) -> None:
        """
        The minimum amount of spending must be at least the number
        of 'required' shares
        """
        # ZFEC only allows up to 256 total shares
        assume(needed + extra_shares < 256)

        # "total" shares is encoded this way to give hypothesis a
        # break: we know "total" must be >= "needed" so we just add
        # some extra shares (possibly 0).
        calculator = PriceCalculator(
            pass_value=1000,
            shares_needed=needed,
            shares_total=needed + extra_shares,
        )
        price = calculator.calculate([1000])
        self.assertThat(price, greater_or_equal(needed))

    @given(
        integers(min_value=1, max_value=100).flatmap(
            lambda n_shares: lists(sizes(), min_size=n_shares, max_size=n_shares)
        ),
        integers(min_value=1),
    )
    def test_shuffled_shares(self, share_sizes: list[int], bytes_per_pass: int) -> None:
        """
        When computing how much a set of shares will cost, it
        doesn't matter how we order them (the result should be the
        same).
        """
        self.assertThat(
            required_passes(bytes_per_pass, share_sizes),
            Equals(
                sum(required_passes(bytes_per_pass, [size]) for size in share_sizes)
            ),
        )

    def test_simple(self) -> None:
        """
        An easy-to-inspect specific example we worked with when
        discovering bug 455
        """

        calculator = PriceCalculator(
            pass_value=1000000,  # one mega-byte
            shares_needed=3,
            shares_total=5,
        )

        # we store 1 megabyte -- but there's 5 shares so we must spend
        # 1 ZKAP at each server
        self.assertThat(calculator.calculate([1000000]), Equals(5))

        # we store _just_ enough to be more than the pass-value -- but
        # still 5 servers, so now we spend 2 at each one
        self.assertThat(calculator.calculate([1000000 * 3 + 1]), Equals(10))
