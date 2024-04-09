from collections import defaultdict
from tabulate import tabulate
import pandas as pd
import random

class DifferentialCryptanalysis:
    """
    Performs differential cryptanalysis on a given SP network.

    Attributes:
        sp_network (SP_Network): The SP network to be analyzed.
        difference_distribution (dict): A dictionary representing the difference distribution table for the S-box.
        data_size (int): Size of the data block used in the SP network.

    Methods:
        __init__(sp_network: SP_Network):
            Initializes the DifferentialCryptanalysis class with an SP network.
        calculate_difference_distribution():
            Calculates the difference distribution table for the S-box.
        print_difference_distribution():
            Prints the difference distribution table for the S-box.
        get_max_frequency_difference() -> tuple:
            Finds the input and output differences with the maximum frequency in the difference distribution table.
        get_max_delta_y(delta_x) -> int:
            Gets the output difference with the maximum frequency for a given input difference.
        get_active_sboxes(input_data: int) -> list:
            Finds the indices of active S-boxes for a given input data.
        get_output_difference(input_difference: int) -> int:
            Calculates the output difference for a given input difference.
        get_difference_pair_probability(u: int, v: int) -> float:
            Computes the probability of a difference pair (u, v) based on the difference distribution table.
        get_differential_characteristic(delta_p: int) -> tuple:
            Computes the output differential characteristic for a given input/output difference and target S-box.
        convert_to_block(active_sboxes: list, data: int) -> int:
            Converts data into a block based on the active S-boxes.
        perform_attack(ciphertext_pairs: list, diff_characteristic: int) -> list:
            Performs a differential cryptanalysis attack to extract the last subkey bits.
        check_expected_difference(partial_decryption_1: int, partial_decryption_2: int, diff_characteristic: int) -> bool:
            Checks if the XOR of two partial decryptions matches the specified differential characteristic.
        partial_decrypt(ciphertext: int, subkey_value: int) -> int:
            Partially decrypts the last round of the cipher with the given subkey value.
        extract_subkey_bits(subkey_value: int) -> list:
            Extracts the subkey bits from the given subkey value.
        generate_plaintext_and_ciphertext_pairs(delta_p: int, num_pairs: int) -> list:
            Generates plaintext pairs and their corresponding ciphertext pairs satisfying the differential characteristic.
    """

    def __init__(self, sp_network: SP_Network) -> None:
        """
        Initializes the DifferentialCryptanalysis class with an SP network.

        Args:
            sp_network (SP_Network): The SP network to be analyzed.
        """
        self.sp_network = sp_network
        self.difference_distribution = {}
        self.data_size = sp_network.data_size

    def calculate_difference_distribution(self) -> None:
        """
        Calculates the difference distribution table for the S-box.
        """
        for delta_x in range(self.data_size):
            self.difference_distribution[delta_x] = {}

            for delta_y in range(self.data_size):
                self.difference_distribution[delta_x][delta_y] = 0

                for x in range(self.data_size):
                    y = self.sp_network.sbox(x)
                    x2 = x ^ delta_x
                    y2 = self.sp_network.sbox(x2)
                    pred_delta_y = y ^ y2
                    if pred_delta_y == delta_y:
                        self.difference_distribution[delta_x][delta_y] += 1

    def print_difference_distribution(self) -> None:
        """
        Prints the difference distribution table for the S-box.
        """
        print("Difference Distribution Table ΔX and ΔY:\n")
        transposed_data = {col: {row: self.difference_distribution[row][col]
                                 for row in self.difference_distribution}
                           for col in self.difference_distribution[0]}
        df = pd.DataFrame(transposed_data)
        print(tabulate(df, headers='keys', tablefmt='psql'))

    def get_max_frequency_difference(self) -> tuple:
        """
        Finds the input and output differences with the maximum frequency in the difference distribution table.

        Returns:
            tuple: A tuple containing the input difference, output difference, and their frequency.
        """
        max_frequency = 0
        max_frequency_delta_x = None
        max_frequency_delta_y = None
        for delta_x, delta_y_counts in self.difference_distribution.items():
            for delta_y, count in delta_y_counts.items():
                if delta_x == 0 and delta_y == 0:
                    continue
                if count > max_frequency:
                    max_frequency = count
                    max_frequency_delta_x = delta_x
                    max_frequency_delta_y = delta_y

        return max_frequency_delta_x, max_frequency_delta_y, max_frequency

    def get_max_delta_y(self, delta_x) -> int:
        """
        Gets the output difference with the maximum frequency for a given input difference.

        Args:
            delta_x (int): Input difference.

        Returns:
            int: Output difference with maximum frequency.
        """
        delta_y_dict = self.difference_distribution[delta_x]
        max_delta_y = max(delta_y_dict, key=delta_y_dict.get)
        return max_delta_y

    def get_active_sboxes(self, input_data: int) -> list:
        """
        Finds the indices of active S-boxes for a given input data.

        Args:
            input_data (int): Input data.

        Returns:
            list: List of active S-box indices.
        """
        active_sboxes = []
        for i in range(4):
            if (input_data >> (i * 4)) & 0xF > 0:
                active_sboxes.append(4 - i)
        return active_sboxes

    def get_output_difference(self, input_difference: int) -> int:
        """
        Calculates the output difference for a given input difference.

        Args:
            input_difference (int): Input difference.

        Returns:
            int: Output difference.
        """
        output = 0
        active_sboxes = self.get_active_sboxes(input_difference)
        for i in active_sboxes:
            delta_x = (input_difference >> (self.data_size - i * 4)) & 0xF
            delta_y = self.get_max_delta_y(delta_x)
            output |= delta_y << (self.data_size - i * 4)
        return output

    def get_difference_pair_probability(self, u: int, v: int) -> float:
        """
        Computes the probability of a difference pair (u, v) based on the difference distribution table.

        Args:
            u (int): Input difference.
            v (int): Output difference.

        Returns:
            float: Probability of the difference pair.
        """
        probability = 1
        for i in range(4):
            delta_x = (u >> (i * 4)) & 0xF
            delta_y = (v >> (i * 4)) & 0xF
            if delta_x == 0 and delta_y == 0:
                continue
            probability *= self.difference_distribution[delta_x][delta_y] / \
                self.data_size
        return probability

    def get_delta_p(self, delta_x: int, target_sbox: int) -> int:
        """
        Calculates the delta_p value for a given delta_x and target S-box.

        Args:
            delta_x (int): The input difference value.
            target_sbox (int): The index of the target S-box.

        Returns:
            int: The delta_p value.
        """
        return delta_x << (self.data_size - target_sbox * 4)

    def get_differential_characteristic(self, delta_p: int) -> tuple:
        """
        Computes the output differential characteristic for a given input/output difference and target S-box.

        Args:
            delta_x (int): Input difference.
            delta_y (int): Output difference.
            target_sbox (int): Target S-box index.

        Returns:
            tuple: A tuple containing the output differential characteristic and its probability.
        """
        u = delta_p
        probability = 1
        for _ in range(self.sp_network.rounds - 1):
            v = self.get_output_difference(u)
            probability *= self.get_difference_pair_probability(u, v)
            u = self.sp_network.permute(v)
        return u, probability

    def convert_to_block(self, active_sboxes: list, data: int) -> int:
        """
        Converts data into a block based on the active S-boxes.

        Args:
            active_sboxes (list): List of active S-box indices.
            data (int): Input data.

        Returns:
            int: Data converted into a block.
        """
        groups = []
        for i in range(len(active_sboxes)):
            groups.insert(0, (data >> (4 * i)) & 0xF)

        output = 0
        for i in range(len(active_sboxes)):
            sbox_index = active_sboxes[i]
            group = groups[i]
            output |= group << (self.data_size - sbox_index * 4)

        return output

    def perform_attack(self, ciphertext_pairs: list, diff_characteristic: int) -> list:
        """
        Performs a differential cryptanalysis attack to extract the last subkey bits.

        Args:
            ciphertext_pairs (list): List of ciphertext pairs corresponding to plaintext pairs.

        Returns:
            None | list: Extracted last subkey bits.
        """
        subkey_counts = defaultdict(int)
        active_sboxes = self.get_active_sboxes(diff_characteristic)
        num_of_keys = (2 ** 4) ** len(active_sboxes)

        for i in range(1, num_of_keys):
            subkey = self.convert_to_block(active_sboxes, i)
            count = sum(
                self.check_expected_difference(
                    self.partial_decrypt(ciphertext_1, subkey),
                    self.partial_decrypt(ciphertext_2, subkey),
                    diff_characteristic
                )
                for ciphertext_1, ciphertext_2 in ciphertext_pairs
            )
            subkey_counts[subkey] = count

        if subkey_counts:
            return max(subkey_counts, key=subkey_counts.get)

    def check_expected_difference(self, partial_decryption_1: int, partial_decryption_2: int, diff_characteristic: int) -> bool:
        """
        Checks if the XOR of two partial decryptions matches the specified differential characteristic.

        Args:
            partial_decryption_1 (int): First partially decrypted ciphertext.
            partial_decryption_2 (int): Second partially decrypted ciphertext.
            diff_characteristic (int): Differential characteristic to check against.

        Returns:
            bool: True if the XOR of the partial decryptions matches the differential characteristic, False otherwise.
        """
        return (partial_decryption_1 ^ partial_decryption_2) == diff_characteristic

    def partial_decrypt(self, ciphertext: int, subkey_value: int) -> int:
        """
        Partially decrypts the last round of the cipher with the given subkey value.

        Args:
            ciphertext (int): Ciphertext to decrypt.
            subkey_value (int): Value of the target partial subkey.

        Returns:
            int: Partially decrypted ciphertext.
        """
        partially_decrypted_ciphertext = ciphertext ^ subkey_value
        return self.sp_network.substitute(partially_decrypted_ciphertext, True)

    def generate_plaintext_and_ciphertext_pairs(self, delta_p: int, num_pairs: int) -> list:
        """
        Generates plaintext pairs and their corresponding ciphertext pairs satisfying the differential characteristic.

        Args:
            delta_p (int): Input difference ∆P.
            num_pairs (int): Number of pairs to generate.

        Returns:
            list: List of tuples containing plaintext pairs and their corresponding ciphertext pairs.
        """
        ciphertext_pairs = []
        for _ in range(num_pairs):
            plaintext_1 = random.randint(0, 2 ** self.data_size - 1)
            plaintext_2 = plaintext_1 ^ delta_p
            ciphertext_1 = self.sp_network.encrypt(plaintext_1)
            ciphertext_2 = self.sp_network.encrypt(plaintext_2)
            ciphertext_pairs.append((ciphertext_1, ciphertext_2))

        return ciphertext_pairs

    def extract_subkey_bits(self, subkey_value: int) -> list:
        """
        Extracts the subkey bits from the given subkey value.

        Args:
            subkey_value (int): Value of the target partial subkey.

        Returns:
            list: Extracted subkey bits.
        """
        subkey_str = format(subkey_value, '016b')
        extracted_subkey_bits = []
        for i in range(0, self.data_size, 4):
            if subkey_str[i:i+4] != '0000':
                extracted_subkey_bits.append(int(subkey_str[i:i+4], 2))
        return extracted_subkey_bits

    def get_binary_rep_of_subkey(self, subkey_value: int, active_sboxes: list) -> str:
        """
        Gets the binary representation of the subkey from the given subkey value.

        Args:
            subkey_value (int): Value of the target partial subkey.

        Returns:
            str: Binary representation of the subkey.
        """
        subkey_str = ''
        for i in range(1, 5):
            sub_bits = (subkey_value >> (16 - i * 4)) & 0xF
            subkey_str += format(sub_bits, '04b') + \
                ' ' if i in active_sboxes else 'XXXX '
        return subkey_str